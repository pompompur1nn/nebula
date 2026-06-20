use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialWitnessDerivativeLatencyBankruptcyRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DERIVATIVE_LATENCY_BANKRUPTCY_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-fast-pq-confidential-witness-derivative-latency-bankruptcy-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DERIVATIVE_LATENCY_BANKRUPTCY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const PQ_BANKRUPTCY_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-latency-bankruptcy-resolution-root-v1";
pub const BANKRUPTCY_POSITION_SUITE: &str =
    "ml-kem-1024-sealed-defi-derivative-bankruptcy-position-root-v1";
pub const SOCIALIZED_LOSS_SUITE: &str =
    "roots-only-socialized-loss-resolution-derivative-bankruptcy-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_witnesses_addresses_keys_bankruptcy_terms_positions_or_losses";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-private-l2-fast-pq-confidential-derivative-latency-bankruptcy-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 8_240_000;
pub const DEVNET_EPOCH: u64 = 51_200;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BANKRUPTCY_CYCLE_MS: u64 = 30;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 180;
pub const DEFAULT_RESOLUTION_DELAY_SLOTS: u64 = 2;
pub const DEFAULT_LOW_FEE_CAP_BPS: u64 = 18;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 120;
pub const DEFAULT_BACKSTOP_FEE_BPS: u64 = 32;
pub const DEFAULT_BANKRUPTCY_DISCOUNT_BPS: u64 = 650;
pub const DEFAULT_SOCIALIZED_LOSS_CAP_BPS: u64 = 1_250;
pub const DEFAULT_INSURANCE_FIRST_LOSS_BPS: u64 = 5_000;
pub const DEFAULT_MIN_QUORUM_BPS: u64 = 7_000;
pub const DEFAULT_MIN_CREDITOR_APPROVAL_BPS: u64 = 6_700;
pub const DEFAULT_MAX_POOLS: usize = 65_536;
pub const DEFAULT_MAX_CLAIMS: usize = 1_048_576;
pub const DEFAULT_MAX_CASES: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_LOSS_EPOCHS: usize = 262_144;
pub const DEFAULT_MAX_BACKSTOP_DRAWS: usize = 262_144;
pub const DEFAULT_ROOT_BYTES: usize = 32;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:STATE";
const D_POOLS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:POOLS";
const D_CLAIMS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:CLAIMS";
const D_CASES: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:CASES";
const D_LOSS_EPOCHS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:SOCIALIZED-LOSS-EPOCHS";
const D_BACKSTOP_DRAWS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:BACKSTOP-DRAWS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:ATTESTATIONS";
const D_RECEIPTS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:RECEIPTS";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:NULLIFIERS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-WITNESS-DERIV-LAT-BANKRUPTCY:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BankruptcyMode {
    Continuous,
    BatchAuction,
    InsuranceFirst,
    SocializedLoss,
    EmergencyCourt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Open,
    Watch,
    Insolvent,
    Resolving,
    Paused,
    Sealed,
}

impl PoolStatus {
    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Open | Self::Watch | Self::Insolvent)
    }

    pub fn can_resolve(self) -> bool {
        matches!(self, Self::Insolvent | Self::Resolving)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeClass {
    LatencyFuture,
    WitnessDelaySwap,
    FeeRebateForward,
    CongestionOption,
    ReliabilityVariance,
    BankruptcyBackstop,
    SocializedLossNote,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSide {
    Creditor,
    Debtor,
    BackstopProvider,
    InsuranceFund,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Open,
    Nettable,
    Bankrupt,
    Resolved,
    Expired,
    Rejected,
}

impl ClaimStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Nettable | Self::Bankrupt)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Building,
    Attested,
    LossAllocated,
    Settled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LossEpochStatus {
    Open,
    Attested,
    Applied,
    Settled,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopDrawStatus {
    Requested,
    Attested,
    Applied,
    Repaid,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    QuorumSatisfied,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_bankruptcy_attestation_suite: String,
    pub bankruptcy_position_suite: String,
    pub socialized_loss_suite: String,
    pub roots_only_public_records: bool,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub bankruptcy_cycle_ms: u64,
    pub max_latency_ms: u64,
    pub resolution_delay_slots: u64,
    pub low_fee_cap_bps: u64,
    pub taker_fee_bps: u64,
    pub backstop_fee_bps: u64,
    pub bankruptcy_discount_bps: u64,
    pub socialized_loss_cap_bps: u64,
    pub insurance_first_loss_bps: u64,
    pub min_quorum_bps: u64,
    pub min_creditor_approval_bps: u64,
    pub max_pools: usize,
    pub max_claims: usize,
    pub max_cases: usize,
    pub max_attestations: usize,
    pub max_receipts: usize,
    pub max_loss_epochs: usize,
    pub max_backstop_draws: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_bankruptcy_attestation_suite: PQ_BANKRUPTCY_ATTESTATION_SUITE.to_string(),
            bankruptcy_position_suite: BANKRUPTCY_POSITION_SUITE.to_string(),
            socialized_loss_suite: SOCIALIZED_LOSS_SUITE.to_string(),
            roots_only_public_records: true,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            bankruptcy_cycle_ms: DEFAULT_BANKRUPTCY_CYCLE_MS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            resolution_delay_slots: DEFAULT_RESOLUTION_DELAY_SLOTS,
            low_fee_cap_bps: DEFAULT_LOW_FEE_CAP_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            backstop_fee_bps: DEFAULT_BACKSTOP_FEE_BPS,
            bankruptcy_discount_bps: DEFAULT_BANKRUPTCY_DISCOUNT_BPS,
            socialized_loss_cap_bps: DEFAULT_SOCIALIZED_LOSS_CAP_BPS,
            insurance_first_loss_bps: DEFAULT_INSURANCE_FIRST_LOSS_BPS,
            min_quorum_bps: DEFAULT_MIN_QUORUM_BPS,
            min_creditor_approval_bps: DEFAULT_MIN_CREDITOR_APPROVAL_BPS,
            max_pools: DEFAULT_MAX_POOLS,
            max_claims: DEFAULT_MAX_CLAIMS,
            max_cases: DEFAULT_MAX_CASES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_loss_epochs: DEFAULT_MAX_LOSS_EPOCHS,
            max_backstop_draws: DEFAULT_MAX_BACKSTOP_DRAWS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("l2_network", &self.l2_network)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_bps("low_fee_cap_bps", self.low_fee_cap_bps)?;
        ensure_bps("taker_fee_bps", self.taker_fee_bps)?;
        ensure_bps("backstop_fee_bps", self.backstop_fee_bps)?;
        ensure_bps("bankruptcy_discount_bps", self.bankruptcy_discount_bps)?;
        ensure_bps("socialized_loss_cap_bps", self.socialized_loss_cap_bps)?;
        ensure_bps("insurance_first_loss_bps", self.insurance_first_loss_bps)?;
        ensure_bps("min_quorum_bps", self.min_quorum_bps)?;
        ensure_bps("min_creditor_approval_bps", self.min_creditor_approval_bps)?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below PQ safety floor".to_string());
        }
        if self.min_privacy_set_size == 0 || self.target_privacy_set_size == 0 {
            return Err("privacy set sizes must be non-zero".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set below configured privacy floor".to_string());
        }
        if self.bankruptcy_cycle_ms == 0 || self.max_latency_ms == 0 {
            return Err("bankruptcy cycle and max latency must be non-zero".to_string());
        }
        if !self.roots_only_public_records {
            return Err("bankruptcy runtime requires roots-only public records".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_bankruptcy_attestation_suite": self.pq_bankruptcy_attestation_suite,
            "bankruptcy_position_suite": self.bankruptcy_position_suite,
            "socialized_loss_suite": self.socialized_loss_suite,
            "roots_only_public_records": self.roots_only_public_records,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "bankruptcy_cycle_ms": self.bankruptcy_cycle_ms,
            "max_latency_ms": self.max_latency_ms,
            "resolution_delay_slots": self.resolution_delay_slots,
            "low_fee_cap_bps": self.low_fee_cap_bps,
            "socialized_loss_cap_bps": self.socialized_loss_cap_bps,
            "insurance_first_loss_bps": self.insurance_first_loss_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub pools_registered: u64,
    pub claims_opened: u64,
    pub claims_bankrupt: u64,
    pub claims_resolved: u64,
    pub cases_opened: u64,
    pub cases_loss_allocated: u64,
    pub cases_settled: u64,
    pub loss_epochs_opened: u64,
    pub loss_epochs_applied: u64,
    pub backstop_draws_requested: u64,
    pub backstop_draws_applied: u64,
    pub attestations_recorded: u64,
    pub replay_receipts_recorded: u64,
    pub duplicate_replay_receipts: u64,
    pub total_claim_notional_micros: u128,
    pub total_deficit_micros: u128,
    pub total_insurance_paid_micros: u128,
    pub total_socialized_loss_micros: u128,
    pub total_backstop_draw_micros: u128,
    pub total_fee_micros: u128,
    pub total_fee_savings_micros: u128,
    pub peak_open_claims_micros: u128,
    pub last_height: u64,
    pub last_epoch: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub claims_root: String,
    pub bankruptcy_cases_root: String,
    pub socialized_loss_epochs_root: String,
    pub backstop_draws_root: String,
    pub pq_attestations_root: String,
    pub replay_receipts_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RegisterBankruptcyPoolInput {
    pub pool_id: String,
    pub derivative_class: DerivativeClass,
    pub bankruptcy_mode: BankruptcyMode,
    pub maker_commitment_root: String,
    pub insurance_vault_root: String,
    pub backstop_vault_root: String,
    pub encrypted_curve_root: String,
    pub loss_waterfall_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_latency_ms: u64,
    pub open_claim_limit_micros: u128,
    pub insurance_capacity_micros: u128,
    pub backstop_capacity_micros: u128,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BankruptcyPool {
    pub pool_id: String,
    pub derivative_class: DerivativeClass,
    pub bankruptcy_mode: BankruptcyMode,
    pub status: PoolStatus,
    pub maker_commitment_root: String,
    pub insurance_vault_root: String,
    pub backstop_vault_root: String,
    pub encrypted_curve_root: String,
    pub loss_waterfall_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_latency_ms: u64,
    pub open_claim_limit_micros: u128,
    pub insurance_capacity_micros: u128,
    pub insurance_remaining_micros: u128,
    pub backstop_capacity_micros: u128,
    pub backstop_remaining_micros: u128,
    pub open_claims_micros: u128,
    pub bankrupt_claims_micros: u128,
    pub socialized_loss_micros: u128,
    pub claim_count: u64,
    pub case_count: u64,
    pub loss_epoch_count: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl BankruptcyPool {
    pub fn from_input(input: RegisterBankruptcyPoolInput) -> Self {
        Self {
            pool_id: input.pool_id,
            derivative_class: input.derivative_class,
            bankruptcy_mode: input.bankruptcy_mode,
            status: PoolStatus::Open,
            maker_commitment_root: input.maker_commitment_root,
            insurance_vault_root: input.insurance_vault_root,
            backstop_vault_root: input.backstop_vault_root,
            encrypted_curve_root: input.encrypted_curve_root,
            loss_waterfall_root: input.loss_waterfall_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            max_latency_ms: input.max_latency_ms,
            open_claim_limit_micros: input.open_claim_limit_micros,
            insurance_capacity_micros: input.insurance_capacity_micros,
            insurance_remaining_micros: input.insurance_capacity_micros,
            backstop_capacity_micros: input.backstop_capacity_micros,
            backstop_remaining_micros: input.backstop_capacity_micros,
            open_claims_micros: 0,
            bankrupt_claims_micros: 0,
            socialized_loss_micros: 0,
            claim_count: 0,
            case_count: 0,
            loss_epoch_count: 0,
            created_at_height: input.created_at_height,
            updated_at_height: input.created_at_height,
        }
    }

    pub fn available_resolution_micros(&self) -> u128 {
        self.insurance_remaining_micros
            .saturating_add(self.backstop_remaining_micros)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "derivative_class": self.derivative_class,
            "bankruptcy_mode": self.bankruptcy_mode,
            "status": self.status,
            "maker_commitment_root": self.maker_commitment_root,
            "insurance_vault_root": self.insurance_vault_root,
            "backstop_vault_root": self.backstop_vault_root,
            "encrypted_curve_root": self.encrypted_curve_root,
            "loss_waterfall_root": self.loss_waterfall_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_latency_ms": self.max_latency_ms,
            "open_claims_micros": self.open_claims_micros,
            "bankrupt_claims_micros": self.bankrupt_claims_micros,
            "socialized_loss_micros": self.socialized_loss_micros,
            "case_count": self.case_count,
            "loss_epoch_count": self.loss_epoch_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenBankruptcyClaimInput {
    pub claim_id: String,
    pub pool_id: String,
    pub side: ClaimSide,
    pub claimant_commitment_root: String,
    pub sealed_terms_root: String,
    pub collateral_commitment_root: String,
    pub exposure_commitment_root: String,
    pub nullifier_root: String,
    pub claim_notional_micros: u64,
    pub collateral_value_micros: u64,
    pub max_fee_micros: u64,
    pub latency_bound_ms: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BankruptcyClaim {
    pub claim_id: String,
    pub pool_id: String,
    pub side: ClaimSide,
    pub status: ClaimStatus,
    pub claimant_commitment_root: String,
    pub sealed_terms_root: String,
    pub collateral_commitment_root: String,
    pub exposure_commitment_root: String,
    pub nullifier_root: String,
    pub claim_notional_micros: u64,
    pub collateral_value_micros: u64,
    pub deficit_micros: u64,
    pub max_fee_micros: u64,
    pub latency_bound_ms: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub created_at_height: u64,
    pub bankruptcy_case_id: Option<String>,
    pub loss_epoch_id: Option<String>,
}

impl BankruptcyClaim {
    pub fn from_input(input: OpenBankruptcyClaimInput) -> Self {
        let deficit_micros = input
            .claim_notional_micros
            .saturating_sub(input.collateral_value_micros);
        Self {
            claim_id: input.claim_id,
            pool_id: input.pool_id,
            side: input.side,
            status: ClaimStatus::Open,
            claimant_commitment_root: input.claimant_commitment_root,
            sealed_terms_root: input.sealed_terms_root,
            collateral_commitment_root: input.collateral_commitment_root,
            exposure_commitment_root: input.exposure_commitment_root,
            nullifier_root: input.nullifier_root,
            claim_notional_micros: input.claim_notional_micros,
            collateral_value_micros: input.collateral_value_micros,
            deficit_micros,
            max_fee_micros: input.max_fee_micros,
            latency_bound_ms: input.latency_bound_ms,
            opened_slot: input.opened_slot,
            expires_slot: input.expires_slot,
            created_at_height: input.created_at_height,
            bankruptcy_case_id: None,
            loss_epoch_id: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "pool_id": self.pool_id,
            "side": self.side,
            "status": self.status,
            "claimant_commitment_root": self.claimant_commitment_root,
            "sealed_terms_root": self.sealed_terms_root,
            "collateral_commitment_root": self.collateral_commitment_root,
            "exposure_commitment_root": self.exposure_commitment_root,
            "nullifier_root": self.nullifier_root,
            "claim_notional_micros": self.claim_notional_micros,
            "deficit_micros": self.deficit_micros,
            "latency_bound_ms": self.latency_bound_ms,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "bankruptcy_case_id": self.bankruptcy_case_id,
            "loss_epoch_id": self.loss_epoch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenBankruptcyCaseInput {
    pub case_id: String,
    pub pool_id: String,
    pub claim_ids: Vec<String>,
    pub insolvency_witness_root: String,
    pub creditor_set_root: String,
    pub debtor_set_root: String,
    pub collateral_snapshot_root: String,
    pub waterfall_commitment_root: String,
    pub observed_latency_ms: u64,
    pub creditor_approval_bps: u64,
    pub slot: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BankruptcyCase {
    pub case_id: String,
    pub pool_id: String,
    pub status: CaseStatus,
    pub claim_ids_root: String,
    pub insolvency_witness_root: String,
    pub creditor_set_root: String,
    pub debtor_set_root: String,
    pub collateral_snapshot_root: String,
    pub waterfall_commitment_root: String,
    pub gross_claim_micros: u128,
    pub collateral_value_micros: u128,
    pub deficit_micros: u128,
    pub insurance_paid_micros: u128,
    pub backstop_draw_micros: u128,
    pub socialized_loss_micros: u128,
    pub fee_micros: u64,
    pub fee_savings_micros: u64,
    pub observed_latency_ms: u64,
    pub creditor_approval_bps: u64,
    pub slot: u64,
    pub height: u64,
    pub attestation_count: u64,
    pub loss_epoch_id: Option<String>,
}

impl BankruptcyCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "pool_id": self.pool_id,
            "status": self.status,
            "claim_ids_root": self.claim_ids_root,
            "insolvency_witness_root": self.insolvency_witness_root,
            "creditor_set_root": self.creditor_set_root,
            "debtor_set_root": self.debtor_set_root,
            "collateral_snapshot_root": self.collateral_snapshot_root,
            "waterfall_commitment_root": self.waterfall_commitment_root,
            "gross_claim_micros": self.gross_claim_micros,
            "deficit_micros": self.deficit_micros,
            "insurance_paid_micros": self.insurance_paid_micros,
            "backstop_draw_micros": self.backstop_draw_micros,
            "socialized_loss_micros": self.socialized_loss_micros,
            "fee_micros": self.fee_micros,
            "fee_savings_micros": self.fee_savings_micros,
            "observed_latency_ms": self.observed_latency_ms,
            "creditor_approval_bps": self.creditor_approval_bps,
            "slot": self.slot,
            "height": self.height,
            "attestation_count": self.attestation_count,
            "loss_epoch_id": self.loss_epoch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AllocateSocializedLossInput {
    pub loss_epoch_id: String,
    pub pool_id: String,
    pub case_ids: Vec<String>,
    pub participant_set_root: String,
    pub loss_vector_root: String,
    pub fee_rebate_root: String,
    pub max_loss_bps: u64,
    pub slot: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SocializedLossEpoch {
    pub loss_epoch_id: String,
    pub pool_id: String,
    pub status: LossEpochStatus,
    pub case_ids_root: String,
    pub participant_set_root: String,
    pub loss_vector_root: String,
    pub fee_rebate_root: String,
    pub gross_deficit_micros: u128,
    pub socialized_loss_micros: u128,
    pub capped_loss_micros: u128,
    pub max_loss_bps: u64,
    pub slot: u64,
    pub height: u64,
    pub attestation_count: u64,
}

impl SocializedLossEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "loss_epoch_id": self.loss_epoch_id,
            "pool_id": self.pool_id,
            "status": self.status,
            "case_ids_root": self.case_ids_root,
            "participant_set_root": self.participant_set_root,
            "loss_vector_root": self.loss_vector_root,
            "fee_rebate_root": self.fee_rebate_root,
            "gross_deficit_micros": self.gross_deficit_micros,
            "socialized_loss_micros": self.socialized_loss_micros,
            "capped_loss_micros": self.capped_loss_micros,
            "max_loss_bps": self.max_loss_bps,
            "slot": self.slot,
            "height": self.height,
            "attestation_count": self.attestation_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RequestBackstopDrawInput {
    pub draw_id: String,
    pub pool_id: String,
    pub case_id: String,
    pub provider_set_root: String,
    pub draw_commitment_root: String,
    pub repayment_terms_root: String,
    pub requested_micros: u64,
    pub fee_micros: u64,
    pub slot: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BackstopDraw {
    pub draw_id: String,
    pub pool_id: String,
    pub case_id: String,
    pub status: BackstopDrawStatus,
    pub provider_set_root: String,
    pub draw_commitment_root: String,
    pub repayment_terms_root: String,
    pub requested_micros: u64,
    pub applied_micros: u64,
    pub fee_micros: u64,
    pub slot: u64,
    pub height: u64,
    pub attestation_count: u64,
}

impl BackstopDraw {
    pub fn public_record(&self) -> Value {
        json!({
            "draw_id": self.draw_id,
            "pool_id": self.pool_id,
            "case_id": self.case_id,
            "status": self.status,
            "provider_set_root": self.provider_set_root,
            "draw_commitment_root": self.draw_commitment_root,
            "repayment_terms_root": self.repayment_terms_root,
            "requested_micros": self.requested_micros,
            "applied_micros": self.applied_micros,
            "fee_micros": self.fee_micros,
            "slot": self.slot,
            "height": self.height,
            "attestation_count": self.attestation_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqBankruptcyAttestationInput {
    pub attestation_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub committee_root: String,
    pub pq_signature_root: String,
    pub quorum_bps: u64,
    pub security_bits: u16,
    pub valid_until_height: u64,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqBankruptcyAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub status: AttestationStatus,
    pub committee_root: String,
    pub pq_signature_root: String,
    pub quorum_bps: u64,
    pub security_bits: u16,
    pub valid_until_height: u64,
    pub recorded_at_height: u64,
}

impl PqBankruptcyAttestation {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayReceiptInput {
    pub receipt_id: String,
    pub nullifier_root: String,
    pub bound_subject_root: String,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayReceipt {
    pub receipt_id: String,
    pub nullifier_root: String,
    pub bound_subject_root: String,
    pub duplicate: bool,
    pub recorded_at_height: u64,
}

impl ReplayReceipt {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicRecord {
    pub protocol_version: String,
    pub scheme: String,
    pub privacy_boundary: String,
    pub height: u64,
    pub epoch: u64,
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub claims_root: String,
    pub bankruptcy_cases_root: String,
    pub socialized_loss_epochs_root: String,
    pub backstop_draws_root: String,
    pub pq_attestations_root: String,
    pub replay_receipts_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, BankruptcyPool>,
    pub claims: BTreeMap<String, BankruptcyClaim>,
    pub bankruptcy_cases: BTreeMap<String, BankruptcyCase>,
    pub socialized_loss_epochs: BTreeMap<String, SocializedLossEpoch>,
    pub backstop_draws: BTreeMap<String, BackstopDraw>,
    pub pq_attestations: BTreeMap<String, PqBankruptcyAttestation>,
    pub replay_receipts: BTreeMap<String, ReplayReceipt>,
    seen_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            claims: BTreeMap::new(),
            bankruptcy_cases: BTreeMap::new(),
            socialized_loss_epochs: BTreeMap::new(),
            backstop_draws: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            replay_receipts: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_pool(&mut self, input: RegisterBankruptcyPoolInput) -> Result<()> {
        self.config.validate()?;
        ensure_capacity(self.pools.len(), self.config.max_pools, "pools")?;
        ensure_unique(&self.pools, "pool", &input.pool_id)?;
        ensure_non_empty("maker_commitment_root", &input.maker_commitment_root)?;
        ensure_non_empty("insurance_vault_root", &input.insurance_vault_root)?;
        ensure_non_empty("backstop_vault_root", &input.backstop_vault_root)?;
        ensure_non_empty("loss_waterfall_root", &input.loss_waterfall_root)?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("pool privacy set below configured floor".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pool PQ security below configured floor".to_string());
        }
        if input.max_latency_ms > self.config.max_latency_ms {
            return Err("pool max latency exceeds configured runtime maximum".to_string());
        }
        let pool = BankruptcyPool::from_input(input);
        self.counters.pools_registered = self.counters.pools_registered.saturating_add(1);
        self.pools.insert(pool.pool_id.clone(), pool);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_claim(&mut self, input: OpenBankruptcyClaimInput) -> Result<()> {
        ensure_capacity(self.claims.len(), self.config.max_claims, "claims")?;
        ensure_unique(&self.claims, "claim", &input.claim_id)?;
        ensure_non_empty("claimant_commitment_root", &input.claimant_commitment_root)?;
        ensure_non_empty("sealed_terms_root", &input.sealed_terms_root)?;
        ensure_non_empty(
            "collateral_commitment_root",
            &input.collateral_commitment_root,
        )?;
        ensure_non_empty("exposure_commitment_root", &input.exposure_commitment_root)?;
        ensure_non_empty("nullifier_root", &input.nullifier_root)?;
        let pool = self
            .pools
            .get_mut(&input.pool_id)
            .ok_or_else(|| format!("pool `{}` not found", input.pool_id))?;
        if !pool.status.accepts_claims() {
            return Err("pool does not accept bankruptcy claims".to_string());
        }
        if input.expires_slot <= input.opened_slot {
            return Err("claim expires before it opens".to_string());
        }
        if input.latency_bound_ms > pool.max_latency_ms {
            return Err("claim latency bound exceeds pool maximum".to_string());
        }
        let next_claims = pool
            .open_claims_micros
            .saturating_add(u128::from(input.claim_notional_micros));
        if next_claims > pool.open_claim_limit_micros {
            return Err("pool open claim limit exceeded".to_string());
        }
        let claim = BankruptcyClaim::from_input(input);
        pool.open_claims_micros = next_claims;
        pool.claim_count = pool.claim_count.saturating_add(1);
        pool.updated_at_height = claim.created_at_height;
        if claim.deficit_micros > 0 {
            pool.status = PoolStatus::Watch;
        }
        self.counters.claims_opened = self.counters.claims_opened.saturating_add(1);
        self.counters.total_claim_notional_micros = self
            .counters
            .total_claim_notional_micros
            .saturating_add(u128::from(claim.claim_notional_micros));
        self.update_peak_open_claims();
        self.claims.insert(claim.claim_id.clone(), claim);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_bankruptcy_case(&mut self, input: OpenBankruptcyCaseInput) -> Result<()> {
        ensure_capacity(
            self.bankruptcy_cases.len(),
            self.config.max_cases,
            "bankruptcy cases",
        )?;
        ensure_unique(&self.bankruptcy_cases, "bankruptcy case", &input.case_id)?;
        ensure_bps("creditor_approval_bps", input.creditor_approval_bps)?;
        if input.creditor_approval_bps < self.config.min_creditor_approval_bps {
            return Err("creditor approval below configured bankruptcy floor".to_string());
        }
        let pool_snapshot = self
            .pools
            .get(&input.pool_id)
            .ok_or_else(|| format!("pool `{}` not found", input.pool_id))?
            .clone();
        if input.observed_latency_ms > pool_snapshot.max_latency_ms {
            return Err("bankruptcy case exceeds pool latency bound".to_string());
        }
        let mut gross_claim_micros = 0_u128;
        let mut collateral_value_micros = 0_u128;
        let mut deficit_micros = 0_u128;
        for claim_id in &input.claim_ids {
            let claim = self
                .claims
                .get(claim_id)
                .ok_or_else(|| format!("claim `{claim_id}` not found"))?;
            if claim.pool_id != input.pool_id || !claim.status.live() {
                return Err(format!("claim `{claim_id}` is not bankruptcy-nettable"));
            }
            gross_claim_micros =
                gross_claim_micros.saturating_add(u128::from(claim.claim_notional_micros));
            collateral_value_micros =
                collateral_value_micros.saturating_add(u128::from(claim.collateral_value_micros));
            deficit_micros = deficit_micros.saturating_add(u128::from(claim.deficit_micros));
        }
        if deficit_micros == 0 {
            return Err("bankruptcy case requires a positive confidential deficit".to_string());
        }
        let insurance_paid_micros =
            first_loss_payment(deficit_micros, pool_snapshot.insurance_remaining_micros);
        let deficit_after_insurance = deficit_micros.saturating_sub(insurance_paid_micros);
        let backstop_draw_micros =
            deficit_after_insurance.min(pool_snapshot.backstop_remaining_micros);
        let socialized_loss_micros = deficit_after_insurance.saturating_sub(backstop_draw_micros);
        let fee_micros = bankruptcy_fee(gross_claim_micros, deficit_micros, &self.config);
        let fee_savings_micros =
            fee_savings_for_resolution(deficit_micros, self.config.bankruptcy_discount_bps);
        let claim_ids_root = merkle_string_root(D_CLAIMS, &input.claim_ids);
        for claim_id in &input.claim_ids {
            if let Some(claim) = self.claims.get_mut(claim_id) {
                claim.status = ClaimStatus::Bankrupt;
                claim.bankruptcy_case_id = Some(input.case_id.clone());
            }
        }
        if let Some(pool) = self.pools.get_mut(&input.pool_id) {
            pool.status = PoolStatus::Insolvent;
            pool.bankrupt_claims_micros =
                pool.bankrupt_claims_micros.saturating_add(deficit_micros);
            pool.insurance_remaining_micros = pool
                .insurance_remaining_micros
                .saturating_sub(insurance_paid_micros);
            pool.backstop_remaining_micros = pool
                .backstop_remaining_micros
                .saturating_sub(backstop_draw_micros);
            pool.socialized_loss_micros = pool
                .socialized_loss_micros
                .saturating_add(socialized_loss_micros);
            pool.case_count = pool.case_count.saturating_add(1);
            pool.updated_at_height = input.height;
        }
        let case = BankruptcyCase {
            case_id: input.case_id,
            pool_id: input.pool_id,
            status: CaseStatus::Building,
            claim_ids_root,
            insolvency_witness_root: input.insolvency_witness_root,
            creditor_set_root: input.creditor_set_root,
            debtor_set_root: input.debtor_set_root,
            collateral_snapshot_root: input.collateral_snapshot_root,
            waterfall_commitment_root: input.waterfall_commitment_root,
            gross_claim_micros,
            collateral_value_micros,
            deficit_micros,
            insurance_paid_micros,
            backstop_draw_micros,
            socialized_loss_micros,
            fee_micros,
            fee_savings_micros,
            observed_latency_ms: input.observed_latency_ms,
            creditor_approval_bps: input.creditor_approval_bps,
            slot: input.slot,
            height: input.height,
            attestation_count: 0,
            loss_epoch_id: None,
        };
        self.counters.cases_opened = self.counters.cases_opened.saturating_add(1);
        self.counters.claims_bankrupt = self
            .counters
            .claims_bankrupt
            .saturating_add(input.claim_ids.len() as u64);
        self.counters.total_deficit_micros = self
            .counters
            .total_deficit_micros
            .saturating_add(deficit_micros);
        self.counters.total_insurance_paid_micros = self
            .counters
            .total_insurance_paid_micros
            .saturating_add(insurance_paid_micros);
        self.counters.total_backstop_draw_micros = self
            .counters
            .total_backstop_draw_micros
            .saturating_add(backstop_draw_micros);
        self.counters.total_socialized_loss_micros = self
            .counters
            .total_socialized_loss_micros
            .saturating_add(socialized_loss_micros);
        self.counters.total_fee_micros = self
            .counters
            .total_fee_micros
            .saturating_add(u128::from(fee_micros));
        self.counters.total_fee_savings_micros = self
            .counters
            .total_fee_savings_micros
            .saturating_add(u128::from(fee_savings_micros));
        self.bankruptcy_cases.insert(case.case_id.clone(), case);
        self.refresh_roots();
        Ok(())
    }

    pub fn request_backstop_draw(&mut self, input: RequestBackstopDrawInput) -> Result<()> {
        ensure_capacity(
            self.backstop_draws.len(),
            self.config.max_backstop_draws,
            "backstop draws",
        )?;
        ensure_unique(&self.backstop_draws, "backstop draw", &input.draw_id)?;
        let case = self
            .bankruptcy_cases
            .get(&input.case_id)
            .ok_or_else(|| format!("case `{}` not found", input.case_id))?;
        if case.pool_id != input.pool_id {
            return Err("backstop draw pool does not match bankruptcy case".to_string());
        }
        let pool = self
            .pools
            .get_mut(&input.pool_id)
            .ok_or_else(|| format!("pool `{}` not found", input.pool_id))?;
        let requested = u128::from(input.requested_micros);
        if requested > pool.backstop_remaining_micros {
            return Err("backstop draw exceeds remaining backstop capacity".to_string());
        }
        pool.backstop_remaining_micros = pool.backstop_remaining_micros.saturating_sub(requested);
        pool.updated_at_height = input.height;
        let draw = BackstopDraw {
            draw_id: input.draw_id,
            pool_id: input.pool_id,
            case_id: input.case_id,
            status: BackstopDrawStatus::Requested,
            provider_set_root: input.provider_set_root,
            draw_commitment_root: input.draw_commitment_root,
            repayment_terms_root: input.repayment_terms_root,
            requested_micros: input.requested_micros,
            applied_micros: 0,
            fee_micros: input.fee_micros,
            slot: input.slot,
            height: input.height,
            attestation_count: 0,
        };
        self.counters.backstop_draws_requested =
            self.counters.backstop_draws_requested.saturating_add(1);
        self.backstop_draws.insert(draw.draw_id.clone(), draw);
        self.refresh_roots();
        Ok(())
    }

    pub fn allocate_socialized_loss(&mut self, input: AllocateSocializedLossInput) -> Result<()> {
        ensure_capacity(
            self.socialized_loss_epochs.len(),
            self.config.max_loss_epochs,
            "socialized loss epochs",
        )?;
        ensure_unique(
            &self.socialized_loss_epochs,
            "socialized loss epoch",
            &input.loss_epoch_id,
        )?;
        ensure_bps("max_loss_bps", input.max_loss_bps)?;
        if input.max_loss_bps > self.config.socialized_loss_cap_bps {
            return Err("socialized loss cap exceeds configured maximum".to_string());
        }
        let pool = self
            .pools
            .get(&input.pool_id)
            .ok_or_else(|| format!("pool `{}` not found", input.pool_id))?;
        if !pool.status.can_resolve() {
            return Err("pool is not in a bankruptcy resolution state".to_string());
        }
        let mut gross_deficit_micros = 0_u128;
        let mut socialized_loss_micros = 0_u128;
        for case_id in &input.case_ids {
            let case = self
                .bankruptcy_cases
                .get(case_id)
                .ok_or_else(|| format!("case `{case_id}` not found"))?;
            if case.pool_id != input.pool_id {
                return Err(format!("case `{case_id}` belongs to another pool"));
            }
            gross_deficit_micros = gross_deficit_micros.saturating_add(case.deficit_micros);
            socialized_loss_micros =
                socialized_loss_micros.saturating_add(case.socialized_loss_micros);
        }
        let capped_loss_micros = gross_deficit_micros
            .saturating_mul(u128::from(input.max_loss_bps))
            .saturating_div(u128::from(MAX_BPS));
        if socialized_loss_micros > capped_loss_micros {
            return Err("socialized loss exceeds epoch cap".to_string());
        }
        let case_ids_root = merkle_string_root(D_CASES, &input.case_ids);
        for case_id in &input.case_ids {
            if let Some(case) = self.bankruptcy_cases.get_mut(case_id) {
                case.status = CaseStatus::LossAllocated;
                case.loss_epoch_id = Some(input.loss_epoch_id.clone());
            }
        }
        for claim in self.claims.values_mut() {
            if claim
                .bankruptcy_case_id
                .as_ref()
                .map(|case_id| input.case_ids.contains(case_id))
                .unwrap_or(false)
            {
                claim.loss_epoch_id = Some(input.loss_epoch_id.clone());
            }
        }
        if let Some(pool) = self.pools.get_mut(&input.pool_id) {
            pool.status = PoolStatus::Resolving;
            pool.loss_epoch_count = pool.loss_epoch_count.saturating_add(1);
            pool.updated_at_height = input.height;
        }
        let epoch = SocializedLossEpoch {
            loss_epoch_id: input.loss_epoch_id,
            pool_id: input.pool_id,
            status: LossEpochStatus::Open,
            case_ids_root,
            participant_set_root: input.participant_set_root,
            loss_vector_root: input.loss_vector_root,
            fee_rebate_root: input.fee_rebate_root,
            gross_deficit_micros,
            socialized_loss_micros,
            capped_loss_micros,
            max_loss_bps: input.max_loss_bps,
            slot: input.slot,
            height: input.height,
            attestation_count: 0,
        };
        self.counters.loss_epochs_opened = self.counters.loss_epochs_opened.saturating_add(1);
        self.counters.cases_loss_allocated = self
            .counters
            .cases_loss_allocated
            .saturating_add(input.case_ids.len() as u64);
        self.socialized_loss_epochs
            .insert(epoch.loss_epoch_id.clone(), epoch);
        self.refresh_roots();
        Ok(())
    }

    pub fn attest_bankruptcy(&mut self, input: PqBankruptcyAttestationInput) -> Result<()> {
        ensure_capacity(
            self.pq_attestations.len(),
            self.config.max_attestations,
            "PQ attestations",
        )?;
        ensure_unique(&self.pq_attestations, "attestation", &input.attestation_id)?;
        ensure_bps("quorum_bps", input.quorum_bps)?;
        ensure_non_empty("subject_root", &input.subject_root)?;
        let status = if input.security_bits >= self.config.min_pq_security_bits
            && input.quorum_bps >= self.config.min_quorum_bps
        {
            AttestationStatus::QuorumSatisfied
        } else {
            AttestationStatus::Pending
        };
        if status == AttestationStatus::QuorumSatisfied {
            self.mark_subject_attested(&input.subject_id);
        }
        let attestation = PqBankruptcyAttestation {
            attestation_id: input.attestation_id,
            subject_id: input.subject_id,
            subject_root: input.subject_root,
            status,
            committee_root: input.committee_root,
            pq_signature_root: input.pq_signature_root,
            quorum_bps: input.quorum_bps,
            security_bits: input.security_bits,
            valid_until_height: input.valid_until_height,
            recorded_at_height: input.recorded_at_height,
        };
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn apply_backstop_draw(&mut self, draw_id: &str, height: u64) -> Result<()> {
        let draw = self
            .backstop_draws
            .get_mut(draw_id)
            .ok_or_else(|| format!("backstop draw `{draw_id}` not found"))?;
        if draw.status != BackstopDrawStatus::Attested {
            return Err("backstop draw must be PQ-attested before application".to_string());
        }
        draw.status = BackstopDrawStatus::Applied;
        draw.applied_micros = draw.requested_micros;
        draw.height = height;
        self.counters.backstop_draws_applied =
            self.counters.backstop_draws_applied.saturating_add(1);
        self.counters.total_backstop_draw_micros = self
            .counters
            .total_backstop_draw_micros
            .saturating_add(u128::from(draw.applied_micros));
        self.refresh_roots();
        Ok(())
    }

    pub fn apply_socialized_loss(&mut self, loss_epoch_id: &str, height: u64) -> Result<()> {
        let epoch = self
            .socialized_loss_epochs
            .get_mut(loss_epoch_id)
            .ok_or_else(|| format!("socialized loss epoch `{loss_epoch_id}` not found"))?;
        if epoch.status != LossEpochStatus::Attested {
            return Err("socialized loss epoch must be PQ-attested before application".to_string());
        }
        epoch.status = LossEpochStatus::Applied;
        epoch.height = height;
        self.counters.loss_epochs_applied = self.counters.loss_epochs_applied.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_case(&mut self, case_id: &str, height: u64, epoch: u64) -> Result<()> {
        let case = self
            .bankruptcy_cases
            .get_mut(case_id)
            .ok_or_else(|| format!("case `{case_id}` not found"))?;
        if !matches!(
            case.status,
            CaseStatus::Attested | CaseStatus::LossAllocated
        ) {
            return Err("case must be attested or loss-allocated before settlement".to_string());
        }
        case.status = CaseStatus::Settled;
        for claim in self
            .claims
            .values_mut()
            .filter(|claim| claim.bankruptcy_case_id.as_deref() == Some(case_id))
        {
            claim.status = ClaimStatus::Resolved;
        }
        if let Some(pool) = self.pools.get_mut(&case.pool_id) {
            pool.updated_at_height = height;
            if pool.case_count == self.counters.cases_settled.saturating_add(1) {
                pool.status = PoolStatus::Open;
            }
        }
        self.counters.claims_resolved = self.counters.claims_resolved.saturating_add(1);
        self.counters.cases_settled = self.counters.cases_settled.saturating_add(1);
        self.counters.last_height = height;
        self.counters.last_epoch = epoch;
        self.refresh_roots();
        Ok(())
    }

    pub fn record_replay_receipt(&mut self, input: ReplayReceiptInput) -> Result<()> {
        ensure_capacity(
            self.replay_receipts.len(),
            self.config.max_receipts,
            "replay receipts",
        )?;
        ensure_unique(&self.replay_receipts, "receipt", &input.receipt_id)?;
        ensure_non_empty("nullifier_root", &input.nullifier_root)?;
        let duplicate = !self.seen_nullifiers.insert(input.nullifier_root.clone());
        let receipt = ReplayReceipt {
            receipt_id: input.receipt_id,
            nullifier_root: input.nullifier_root,
            bound_subject_root: input.bound_subject_root,
            duplicate,
            recorded_at_height: input.recorded_at_height,
        };
        self.counters.replay_receipts_recorded =
            self.counters.replay_receipts_recorded.saturating_add(1);
        if duplicate {
            self.counters.duplicate_replay_receipts =
                self.counters.duplicate_replay_receipts.saturating_add(1);
        }
        self.replay_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = canonical_root(D_CONFIG, &self.config.public_record());
        self.roots.counters_root = canonical_root(D_COUNTERS, &self.counters);
        self.roots.pools_root = map_root(D_POOLS, &self.pools);
        self.roots.claims_root = map_root(D_CLAIMS, &self.claims);
        self.roots.bankruptcy_cases_root = map_root(D_CASES, &self.bankruptcy_cases);
        self.roots.socialized_loss_epochs_root =
            map_root(D_LOSS_EPOCHS, &self.socialized_loss_epochs);
        self.roots.backstop_draws_root = map_root(D_BACKSTOP_DRAWS, &self.backstop_draws);
        self.roots.pq_attestations_root = map_root(D_ATTESTATIONS, &self.pq_attestations);
        self.roots.replay_receipts_root = map_root(D_RECEIPTS, &self.replay_receipts);
        self.roots.nullifier_root = set_root(D_NULLIFIERS, &self.seen_nullifiers);
        let public_seed = self.roots_only_record();
        self.roots.public_record_root = canonical_root(D_PUBLIC, &public_seed);
        self.roots.state_root = domain_hash(
            D_STATE,
            &[
                HashPart::Str(self.roots.config_root.as_str()),
                HashPart::Str(self.roots.counters_root.as_str()),
                HashPart::Str(self.roots.pools_root.as_str()),
                HashPart::Str(self.roots.claims_root.as_str()),
                HashPart::Str(self.roots.bankruptcy_cases_root.as_str()),
                HashPart::Str(self.roots.socialized_loss_epochs_root.as_str()),
                HashPart::Str(self.roots.backstop_draws_root.as_str()),
                HashPart::Str(self.roots.pq_attestations_root.as_str()),
                HashPart::Str(self.roots.replay_receipts_root.as_str()),
                HashPart::Str(self.roots.nullifier_root.as_str()),
                HashPart::Str(self.roots.public_record_root.as_str()),
            ],
            DEFAULT_ROOT_BYTES,
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&mut self, height: u64, epoch: u64) -> Result<PublicRecord> {
        self.config.validate()?;
        self.counters.last_height = height;
        self.counters.last_epoch = epoch;
        self.refresh_roots();
        Ok(self.roots_only_record())
    }

    pub fn roots_snapshot(&mut self) -> Roots {
        self.refresh_roots();
        self.roots.clone()
    }

    pub fn pool_root(&self, pool_id: &str) -> Result<String> {
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| format!("pool `{pool_id}` not found"))?;
        Ok(canonical_root(D_POOLS, &pool.public_record()))
    }

    pub fn claim_root(&self, claim_id: &str) -> Result<String> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| format!("claim `{claim_id}` not found"))?;
        Ok(canonical_root(D_CLAIMS, &claim.public_record()))
    }

    pub fn case_root(&self, case_id: &str) -> Result<String> {
        let case = self
            .bankruptcy_cases
            .get(case_id)
            .ok_or_else(|| format!("case `{case_id}` not found"))?;
        Ok(canonical_root(D_CASES, &case.public_record()))
    }

    pub fn loss_epoch_root(&self, loss_epoch_id: &str) -> Result<String> {
        let epoch = self
            .socialized_loss_epochs
            .get(loss_epoch_id)
            .ok_or_else(|| format!("socialized loss epoch `{loss_epoch_id}` not found"))?;
        Ok(canonical_root(D_LOSS_EPOCHS, &epoch.public_record()))
    }

    fn roots_only_record(&self) -> PublicRecord {
        PublicRecord {
            protocol_version: PROTOCOL_VERSION.to_string(),
            scheme: PUBLIC_RECORD_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            height: self.counters.last_height,
            epoch: self.counters.last_epoch,
            config_root: self.roots.config_root.clone(),
            counters_root: self.roots.counters_root.clone(),
            pools_root: self.roots.pools_root.clone(),
            claims_root: self.roots.claims_root.clone(),
            bankruptcy_cases_root: self.roots.bankruptcy_cases_root.clone(),
            socialized_loss_epochs_root: self.roots.socialized_loss_epochs_root.clone(),
            backstop_draws_root: self.roots.backstop_draws_root.clone(),
            pq_attestations_root: self.roots.pq_attestations_root.clone(),
            replay_receipts_root: self.roots.replay_receipts_root.clone(),
            nullifier_root: self.roots.nullifier_root.clone(),
            state_root: self.roots.state_root.clone(),
        }
    }

    fn mark_subject_attested(&mut self, subject_id: &str) {
        if let Some(case) = self.bankruptcy_cases.get_mut(subject_id) {
            case.status = CaseStatus::Attested;
            case.attestation_count = case.attestation_count.saturating_add(1);
        }
        if let Some(epoch) = self.socialized_loss_epochs.get_mut(subject_id) {
            epoch.status = LossEpochStatus::Attested;
            epoch.attestation_count = epoch.attestation_count.saturating_add(1);
        }
        if let Some(draw) = self.backstop_draws.get_mut(subject_id) {
            draw.status = BackstopDrawStatus::Attested;
            draw.attestation_count = draw.attestation_count.saturating_add(1);
        }
    }

    fn update_peak_open_claims(&mut self) {
        let open_claims = self
            .pools
            .values()
            .map(|pool| pool.open_claims_micros)
            .sum::<u128>();
        self.counters.peak_open_claims_micros =
            self.counters.peak_open_claims_micros.max(open_claims);
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let pool_id = "devnet-fast-pq-latency-bankruptcy-pool-0".to_string();
    state
        .register_pool(RegisterBankruptcyPoolInput {
            pool_id: pool_id.clone(),
            derivative_class: DerivativeClass::BankruptcyBackstop,
            bankruptcy_mode: BankruptcyMode::SocializedLoss,
            maker_commitment_root: devnet_commitment("maker", 0),
            insurance_vault_root: devnet_commitment("insurance-vault", 0),
            backstop_vault_root: devnet_commitment("backstop-vault", 0),
            encrypted_curve_root: devnet_commitment("encrypted-curve", 0),
            loss_waterfall_root: devnet_commitment("loss-waterfall", 0),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            open_claim_limit_micros: 5_000_000_000,
            insurance_capacity_micros: 1_000_000,
            backstop_capacity_micros: 500_000,
            created_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet bankruptcy pool must register");
    state
        .open_claim(OpenBankruptcyClaimInput {
            claim_id: "devnet-bankruptcy-claim-creditor-0".to_string(),
            pool_id: pool_id.clone(),
            side: ClaimSide::Creditor,
            claimant_commitment_root: devnet_commitment("creditor-claimant", 0),
            sealed_terms_root: devnet_commitment("creditor-terms", 0),
            collateral_commitment_root: devnet_commitment("creditor-collateral", 0),
            exposure_commitment_root: devnet_commitment("creditor-exposure", 0),
            nullifier_root: devnet_commitment("creditor-nullifier", 0),
            claim_notional_micros: 120_000,
            collateral_value_micros: 72_000,
            max_fee_micros: 18,
            latency_bound_ms: 120,
            opened_slot: DEVNET_EPOCH,
            expires_slot: DEVNET_EPOCH + 64,
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet creditor claim must open");
    state
        .open_claim(OpenBankruptcyClaimInput {
            claim_id: "devnet-bankruptcy-claim-debtor-0".to_string(),
            pool_id: pool_id.clone(),
            side: ClaimSide::Debtor,
            claimant_commitment_root: devnet_commitment("debtor-claimant", 0),
            sealed_terms_root: devnet_commitment("debtor-terms", 0),
            collateral_commitment_root: devnet_commitment("debtor-collateral", 0),
            exposure_commitment_root: devnet_commitment("debtor-exposure", 0),
            nullifier_root: devnet_commitment("debtor-nullifier", 0),
            claim_notional_micros: 96_000,
            collateral_value_micros: 64_000,
            max_fee_micros: 14,
            latency_bound_ms: 120,
            opened_slot: DEVNET_EPOCH,
            expires_slot: DEVNET_EPOCH + 64,
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet debtor claim must open");
    state
        .open_bankruptcy_case(OpenBankruptcyCaseInput {
            case_id: "devnet-bankruptcy-case-0".to_string(),
            pool_id: pool_id.clone(),
            claim_ids: vec![
                "devnet-bankruptcy-claim-creditor-0".to_string(),
                "devnet-bankruptcy-claim-debtor-0".to_string(),
            ],
            insolvency_witness_root: devnet_commitment("insolvency-witness", 0),
            creditor_set_root: devnet_commitment("creditor-set", 0),
            debtor_set_root: devnet_commitment("debtor-set", 0),
            collateral_snapshot_root: devnet_commitment("collateral-snapshot", 0),
            waterfall_commitment_root: devnet_commitment("waterfall", 0),
            observed_latency_ms: 24,
            creditor_approval_bps: DEFAULT_MIN_CREDITOR_APPROVAL_BPS,
            slot: DEVNET_EPOCH + 1,
            height: DEVNET_HEIGHT + 2,
        })
        .expect("devnet bankruptcy case must open");
    state
        .attest_bankruptcy(PqBankruptcyAttestationInput {
            attestation_id: "devnet-bankruptcy-case-attestation-0".to_string(),
            subject_id: "devnet-bankruptcy-case-0".to_string(),
            subject_root: devnet_commitment("case-root", 0),
            committee_root: devnet_commitment("committee", 0),
            pq_signature_root: devnet_commitment("pq-signature", 0),
            quorum_bps: DEFAULT_MIN_QUORUM_BPS,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_until_height: DEVNET_HEIGHT + 128,
            recorded_at_height: DEVNET_HEIGHT + 3,
        })
        .expect("devnet bankruptcy attestation must record");
    state
        .allocate_socialized_loss(AllocateSocializedLossInput {
            loss_epoch_id: "devnet-socialized-loss-epoch-0".to_string(),
            pool_id,
            case_ids: vec!["devnet-bankruptcy-case-0".to_string()],
            participant_set_root: devnet_commitment("participants", 0),
            loss_vector_root: devnet_commitment("loss-vector", 0),
            fee_rebate_root: devnet_commitment("fee-rebate", 0),
            max_loss_bps: DEFAULT_SOCIALIZED_LOSS_CAP_BPS,
            slot: DEVNET_EPOCH + 2,
            height: DEVNET_HEIGHT + 4,
        })
        .expect("devnet socialized loss epoch must open");
    state
        .attest_bankruptcy(PqBankruptcyAttestationInput {
            attestation_id: "devnet-bankruptcy-loss-attestation-0".to_string(),
            subject_id: "devnet-socialized-loss-epoch-0".to_string(),
            subject_root: devnet_commitment("loss-epoch-root", 0),
            committee_root: devnet_commitment("loss-committee", 0),
            pq_signature_root: devnet_commitment("loss-pq-signature", 0),
            quorum_bps: DEFAULT_MIN_QUORUM_BPS,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_until_height: DEVNET_HEIGHT + 128,
            recorded_at_height: DEVNET_HEIGHT + 5,
        })
        .expect("devnet loss attestation must record");
    state
        .apply_socialized_loss("devnet-socialized-loss-epoch-0", DEVNET_HEIGHT + 6)
        .expect("devnet socialized loss must apply");
    state
        .settle_case(
            "devnet-bankruptcy-case-0",
            DEVNET_HEIGHT + 7,
            DEVNET_EPOCH + 3,
        )
        .expect("devnet bankruptcy case must settle");
    state.refresh_roots();
    state
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &mut State, height: u64, epoch: u64) -> Result<PublicRecord> {
    state.public_record(height, epoch)
}

fn first_loss_payment(deficit: u128, available: u128) -> u128 {
    deficit.min(available)
}

fn bankruptcy_fee(gross: u128, deficit: u128, config: &Config) -> u64 {
    let fee_bps = config
        .taker_fee_bps
        .saturating_sub(config.bankruptcy_discount_bps.min(config.taker_fee_bps))
        .saturating_add(config.backstop_fee_bps)
        .min(config.low_fee_cap_bps);
    gross
        .saturating_add(deficit)
        .saturating_mul(u128::from(fee_bps))
        .saturating_div(u128::from(MAX_BPS))
        .min(u128::from(u64::MAX)) as u64
}

fn fee_savings_for_resolution(deficit: u128, discount_bps: u64) -> u64 {
    deficit
        .saturating_mul(u128::from(discount_bps.min(MAX_BPS)))
        .saturating_div(u128::from(MAX_BPS))
        .min(u128::from(u64::MAX)) as u64
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(len: usize, max: usize, label: &str) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_unique<T>(map: &BTreeMap<String, T>, label: &str, id: &str) -> Result<()> {
    if map.contains_key(id) {
        Err(format!("{label} `{id}` already exists"))
    } else {
        Ok(())
    }
}

fn canonical_root<T: Serialize>(domain: &'static str, value: &T) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    domain_hash(
        domain,
        &[HashPart::Str(encoded.as_str())],
        DEFAULT_ROOT_BYTES,
    )
}

fn map_root<T: Serialize>(domain: &'static str, map: &BTreeMap<String, T>) -> String {
    if map.is_empty() {
        return empty_root(domain);
    }
    let leaves = map
        .iter()
        .map(|(key, value)| {
            let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
            json!(domain_hash(
                domain,
                &[HashPart::Str(key.as_str()), HashPart::Str(encoded.as_str())],
                DEFAULT_ROOT_BYTES,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &'static str, set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        return empty_root(domain);
    }
    let leaves = set
        .iter()
        .map(|value| {
            json!(domain_hash(
                domain,
                &[HashPart::Str(value.as_str())],
                DEFAULT_ROOT_BYTES,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_string_root(domain: &'static str, values: &[String]) -> String {
    if values.is_empty() {
        return empty_root(domain);
    }
    let leaves = values
        .iter()
        .map(|value| json!(value))
        .collect::<Vec<Value>>();
    merkle_root(domain, &leaves)
}

fn empty_root(domain: &'static str) -> String {
    domain_hash(&format!("{domain}:empty"), &[], DEFAULT_ROOT_BYTES)
}

fn devnet_commitment(label: &str, index: u64) -> String {
    domain_hash(
        D_DEVNET,
        &[HashPart::Str(label), HashPart::U64(index)],
        DEFAULT_ROOT_BYTES,
    )
}
