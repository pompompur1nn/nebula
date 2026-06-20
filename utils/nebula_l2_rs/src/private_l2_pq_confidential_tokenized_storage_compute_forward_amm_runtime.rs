use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedStorageComputeForwardAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_STORAGE_COMPUTE_FORWARD_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-storage-compute-forward-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_STORAGE_COMPUTE_FORWARD_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const NOTE_SUITE: &str = "confidential-tokenized-storage-compute-forward-note-v1";
pub const AMM_SUITE: &str = "sealed-storage-compute-forward-cpamm-v1";
pub const ORACLE_SUITE: &str = "pq-provider-oracle-capacity-attestation-v1";
pub const CAPACITY_BUCKET_SUITE: &str = "epoch-storage-compute-capacity-bucket-root-v1";
pub const MATURITY_SUITE: &str = "confidential-storage-compute-maturity-settlement-v1";
pub const FEE_REBATE_SUITE: &str = "private-storage-compute-fee-credit-rebate-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-redacted-storage-compute-forward-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-storage-compute-forward-amm-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_612_000;
pub const DEVNET_EPOCH: u64 = 128;
pub const DEFAULT_EPOCH_SECONDS: u64 = 900;
pub const DEFAULT_MATURITY_EPOCHS: u64 = 64;
pub const DEFAULT_SETTLEMENT_GRACE_EPOCHS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_AMM_FEE_BPS: u64 = 20;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 4;
pub const DEFAULT_DEFAULT_HAIRCUT_BPS: u64 = 1_400;
pub const DEFAULT_UTILIZATION_HAIRCUT_BPS: u64 = 175;
pub const DEFAULT_REBATE_BPS: u64 = 9;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_SEALED_LIQUIDITY_TTL_EPOCHS: u64 = 12;
pub const DEFAULT_REBATE_BUDGET_MICRO_CREDITS: u64 = 900_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardNoteKind {
    StorageGibMonth,
    ComputeVcpuHour,
    BandwidthGib,
    GpuSecond,
    ProofComputeUnit,
    FeeCredit,
    LpShare,
    DefaultClaim,
}

impl ForwardNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StorageGibMonth => "storage_gib_month",
            Self::ComputeVcpuHour => "compute_vcpu_hour",
            Self::BandwidthGib => "bandwidth_gib",
            Self::GpuSecond => "gpu_second",
            Self::ProofComputeUnit => "proof_compute_unit",
            Self::FeeCredit => "fee_credit",
            Self::LpShare => "lp_share",
            Self::DefaultClaim => "default_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    ConstantProduct,
    StableCapacity,
    ForwardCurve,
    UtilizationWeighted,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::StableCapacity => "stable_capacity",
            Self::ForwardCurve => "forward_curve",
            Self::UtilizationWeighted => "utilization_weighted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ProviderCapacity,
    OraclePrice,
    ComputeCompletion,
    StorageAvailability,
    PoolSolvency,
    DefaultNotice,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderCapacity => "provider_capacity",
            Self::OraclePrice => "oracle_price",
            Self::ComputeCompletion => "compute_completion",
            Self::StorageAvailability => "storage_availability",
            Self::PoolSolvency => "pool_solvency",
            Self::DefaultNotice => "default_notice",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    OraclePending,
    Matured,
    HaircutApplied,
    Paid,
    Defaulted,
    Rebated,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::OraclePending => "oracle_pending",
            Self::Matured => "matured",
            Self::HaircutApplied => "haircut_applied",
            Self::Paid => "paid",
            Self::Defaulted => "defaulted",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub market_id: String,
    pub hash_suite: String,
    pub note_suite: String,
    pub amm_suite: String,
    pub oracle_suite: String,
    pub capacity_bucket_suite: String,
    pub maturity_suite: String,
    pub fee_rebate_suite: String,
    pub epoch_seconds: u64,
    pub maturity_epochs: u64,
    pub settlement_grace_epochs: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub amm_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub default_haircut_bps: u64,
    pub utilization_haircut_bps: u64,
    pub rebate_bps: u64,
    pub oracle_quorum: u16,
    pub sealed_liquidity_ttl_epochs: u64,
    pub rebate_budget_micro_credits: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            note_suite: NOTE_SUITE.to_string(),
            amm_suite: AMM_SUITE.to_string(),
            oracle_suite: ORACLE_SUITE.to_string(),
            capacity_bucket_suite: CAPACITY_BUCKET_SUITE.to_string(),
            maturity_suite: MATURITY_SUITE.to_string(),
            fee_rebate_suite: FEE_REBATE_SUITE.to_string(),
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            maturity_epochs: DEFAULT_MATURITY_EPOCHS,
            settlement_grace_epochs: DEFAULT_SETTLEMENT_GRACE_EPOCHS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            amm_fee_bps: DEFAULT_AMM_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            default_haircut_bps: DEFAULT_DEFAULT_HAIRCUT_BPS,
            utilization_haircut_bps: DEFAULT_UTILIZATION_HAIRCUT_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            sealed_liquidity_ttl_epochs: DEFAULT_SEALED_LIQUIDITY_TTL_EPOCHS,
            rebate_budget_micro_credits: DEFAULT_REBATE_BUDGET_MICRO_CREDITS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch",
        )?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(!self.market_id.trim().is_empty(), "market id required")?;
        require(self.epoch_seconds > 0, "epoch seconds required")?;
        require(self.maturity_epochs > 0, "maturity epochs required")?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(self.oracle_quorum > 0, "oracle quorum required")?;
        require(
            self.amm_fee_bps + self.protocol_fee_bps <= MAX_BPS
                && self.default_haircut_bps <= MAX_BPS
                && self.utilization_haircut_bps <= MAX_BPS
                && self.rebate_bps <= MAX_BPS,
            "invalid bps config",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub forward_notes: u64,
    pub amm_pools: u64,
    pub provider_attestations: u64,
    pub epoch_capacity_buckets: u64,
    pub sealed_liquidity: u64,
    pub maturity_settlements: u64,
    pub fee_credit_rebates: u64,
    pub privacy_redactions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub forward_note_root: String,
    pub amm_pool_root: String,
    pub provider_attestation_root: String,
    pub epoch_capacity_bucket_root: String,
    pub sealed_liquidity_root: String,
    pub maturity_settlement_root: String,
    pub fee_credit_rebate_root: String,
    pub privacy_redaction_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageComputeForwardNote {
    pub note_id: String,
    pub provider_commitment: String,
    pub buyer_commitment: String,
    pub pool_id: String,
    pub note_kind: ForwardNoteKind,
    pub capacity_bucket_id: String,
    pub capacity_units_commitment: String,
    pub price_quote_commitment: String,
    pub issue_epoch: u64,
    pub maturity_epoch: u64,
    pub default_haircut_bps: u64,
    pub encrypted_terms_root: String,
    pub nullifier_root: String,
}

impl StorageComputeForwardNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "provider_commitment": redacted_label(&self.provider_commitment),
            "buyer_commitment": redacted_label(&self.buyer_commitment),
            "pool_id": self.pool_id,
            "note_kind": self.note_kind.as_str(),
            "capacity_bucket_id": self.capacity_bucket_id,
            "capacity_units_commitment": self.capacity_units_commitment,
            "price_quote_commitment": self.price_quote_commitment,
            "issue_epoch": self.issue_epoch,
            "maturity_epoch": self.maturity_epoch,
            "default_haircut_bps": self.default_haircut_bps,
            "encrypted_terms_root": self.encrypted_terms_root,
            "nullifier_root": self.nullifier_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmmPool {
    pub pool_id: String,
    pub pool_kind: PoolKind,
    pub base_note_class: String,
    pub quote_token: String,
    pub sealed_base_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub lp_note_root: String,
    pub invariant_root: String,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub oracle_price_root: String,
    pub last_epoch: u64,
}

impl AmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "base_note_class": self.base_note_class,
            "quote_token": self.quote_token,
            "sealed_base_reserve_root": self.sealed_base_reserve_root,
            "sealed_quote_reserve_root": self.sealed_quote_reserve_root,
            "lp_note_root": self.lp_note_root,
            "invariant_root": self.invariant_root,
            "fee_bps": self.fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "oracle_price_root": self.oracle_price_root,
            "last_epoch": self.last_epoch
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderOracleAttestation {
    pub attestation_id: String,
    pub attestation_kind: AttestationKind,
    pub provider_commitment: String,
    pub oracle_committee_root: String,
    pub epoch: u64,
    pub capacity_bucket_id: String,
    pub attested_capacity_root: String,
    pub attested_price_root: String,
    pub pq_signature_root: String,
    pub status: SettlementStatus,
}

impl ProviderOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "provider_commitment": redacted_label(&self.provider_commitment),
            "oracle_committee_root": self.oracle_committee_root,
            "epoch": self.epoch,
            "capacity_bucket_id": self.capacity_bucket_id,
            "attested_capacity_root": self.attested_capacity_root,
            "attested_price_root": self.attested_price_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EpochCapacityBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub region_root: String,
    pub provider_set_root: String,
    pub storage_capacity_root: String,
    pub compute_capacity_root: String,
    pub utilization_root: String,
    pub haircut_bps: u64,
    pub net_capacity_root: String,
}

impl EpochCapacityBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedLiquidityPosition {
    pub position_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub sealed_base_units_root: String,
    pub sealed_quote_units_root: String,
    pub lp_note_root: String,
    pub locked_until_epoch: u64,
}

impl SealedLiquidityPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "pool_id": self.pool_id,
            "owner_commitment": redacted_label(&self.owner_commitment),
            "sealed_base_units_root": self.sealed_base_units_root,
            "sealed_quote_units_root": self.sealed_quote_units_root,
            "lp_note_root": self.lp_note_root,
            "locked_until_epoch": self.locked_until_epoch
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaturitySettlement {
    pub settlement_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub capacity_bucket_id: String,
    pub maturity_epoch: u64,
    pub delivered_capacity_root: String,
    pub due_quote_root: String,
    pub paid_quote_root: String,
    pub haircut_bps: u64,
    pub default_claim_root: String,
    pub status: SettlementStatus,
}

impl MaturitySettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "capacity_bucket_id": self.capacity_bucket_id,
            "maturity_epoch": self.maturity_epoch,
            "delivered_capacity_root": self.delivered_capacity_root,
            "due_quote_root": self.due_quote_root,
            "paid_quote_root": self.paid_quote_root,
            "haircut_bps": self.haircut_bps,
            "default_claim_root": self.default_claim_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub account_commitment: String,
    pub source_settlement_id: String,
    pub fee_credit_note_root: String,
    pub rebate_bps: u64,
    pub epoch: u64,
}

impl FeeCreditRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "account_commitment": redacted_label(&self.account_commitment),
            "source_settlement_id": self.source_settlement_id,
            "fee_credit_note_root": self.fee_credit_note_root,
            "rebate_bps": self.rebate_bps,
            "epoch": self.epoch
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub source_record_id: String,
    pub redacted_fields_root: String,
    pub disclosure_policy_root: String,
    pub public_hint_root: String,
}

impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_l2_height: u64,
    pub current_epoch: u64,
    pub rebate_budget_remaining_micro_credits: u64,
    pub forward_notes: BTreeMap<String, StorageComputeForwardNote>,
    pub amm_pools: BTreeMap<String, AmmPool>,
    pub provider_attestations: BTreeMap<String, ProviderOracleAttestation>,
    pub epoch_capacity_buckets: BTreeMap<String, EpochCapacityBucket>,
    pub sealed_liquidity: BTreeMap<String, SealedLiquidityPosition>,
    pub maturity_settlements: BTreeMap<String, MaturitySettlement>,
    pub fee_credit_rebates: BTreeMap<String, FeeCreditRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            rebate_budget_remaining_micro_credits: config.rebate_budget_micro_credits,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_l2_height,
            current_epoch,
            forward_notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            provider_attestations: BTreeMap::new(),
            epoch_capacity_buckets: BTreeMap::new(),
            sealed_liquidity: BTreeMap::new(),
            maturity_settlements: BTreeMap::new(),
            fee_credit_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::devnet(), DEVNET_L2_HEIGHT, DEVNET_EPOCH).expect("devnet");
        state.load_demo_fixtures();
        state
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn refresh_roots(&mut self) {
        self.counters = Counters {
            forward_notes: self.forward_notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            provider_attestations: self.provider_attestations.len() as u64,
            epoch_capacity_buckets: self.epoch_capacity_buckets.len() as u64,
            sealed_liquidity: self.sealed_liquidity.len() as u64,
            maturity_settlements: self.maturity_settlements.len() as u64,
            fee_credit_rebates: self.fee_credit_rebates.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
        };
        self.roots = Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            forward_note_root: map_root(
                "FORWARD-NOTES",
                self.forward_notes.values().map(|note| note.public_record()),
            ),
            amm_pool_root: map_root(
                "AMM-POOLS",
                self.amm_pools.values().map(|pool| pool.public_record()),
            ),
            provider_attestation_root: map_root(
                "PROVIDER-ATTESTATIONS",
                self.provider_attestations
                    .values()
                    .map(|attestation| attestation.public_record()),
            ),
            epoch_capacity_bucket_root: map_root(
                "EPOCH-CAPACITY-BUCKETS",
                self.epoch_capacity_buckets
                    .values()
                    .map(|bucket| bucket.public_record()),
            ),
            sealed_liquidity_root: map_root(
                "SEALED-LIQUIDITY",
                self.sealed_liquidity
                    .values()
                    .map(|position| position.public_record()),
            ),
            maturity_settlement_root: map_root(
                "MATURITY-SETTLEMENTS",
                self.maturity_settlements
                    .values()
                    .map(|settlement| settlement.public_record()),
            ),
            fee_credit_rebate_root: map_root(
                "FEE-CREDIT-REBATES",
                self.fee_credit_rebates
                    .values()
                    .map(|rebate| rebate.public_record()),
            ),
            privacy_redaction_root: map_root(
                "PRIVACY-REDACTIONS",
                self.privacy_redactions
                    .values()
                    .map(|redaction| redaction.public_record()),
            ),
        };
    }

    fn load_demo_fixtures(&mut self) {
        let config = self.config.clone();
        let pool = demo_pool(
            &config,
            "storage-compute-forward-pool-0",
            PoolKind::ConstantProduct,
        );
        let bucket = demo_bucket(&config, "capacity-bucket-128", DEVNET_EPOCH);
        let note = demo_note(&config, &pool.pool_id, &bucket.bucket_id, "forward-note-0");
        let attestation = demo_attestation(&config, &bucket.bucket_id, "provider-attestation-0");
        let liquidity = demo_liquidity(&pool.pool_id, "sealed-liquidity-0");
        let settlement = demo_settlement(&config, &note, &pool.pool_id, &bucket.bucket_id);
        let rebate = demo_rebate(&config, &settlement.settlement_id, "fee-credit-rebate-0");
        let redaction = demo_redaction(&note.note_id, "privacy-redaction-0");

        self.amm_pools.insert(pool.pool_id.clone(), pool);
        self.epoch_capacity_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.forward_notes.insert(note.note_id.clone(), note);
        self.provider_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.sealed_liquidity
            .insert(liquidity.position_id.clone(), liquidity);
        self.maturity_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.fee_credit_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.privacy_redactions
            .insert(redaction.redaction_id.clone(), redaction);
        self.refresh_roots();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": state.config.protocol_version,
        "schema_version": SCHEMA_VERSION,
        "public_record_suite": PUBLIC_RECORD_SUITE,
        "chain_id": state.config.chain_id,
        "l2_network": state.config.l2_network,
        "market_id": state.config.market_id,
        "current_l2_height": state.current_l2_height,
        "current_epoch": state.current_epoch,
        "config": {
            "hash_suite": state.config.hash_suite,
            "note_suite": state.config.note_suite,
            "amm_suite": state.config.amm_suite,
            "oracle_suite": state.config.oracle_suite,
            "capacity_bucket_suite": state.config.capacity_bucket_suite,
            "maturity_suite": state.config.maturity_suite,
            "fee_rebate_suite": state.config.fee_rebate_suite,
            "epoch_seconds": state.config.epoch_seconds,
            "maturity_epochs": state.config.maturity_epochs,
            "settlement_grace_epochs": state.config.settlement_grace_epochs,
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "target_privacy_set_size": state.config.target_privacy_set_size,
            "min_pq_security_bits": state.config.min_pq_security_bits,
            "amm_fee_bps": state.config.amm_fee_bps,
            "protocol_fee_bps": state.config.protocol_fee_bps,
            "default_haircut_bps": state.config.default_haircut_bps,
            "utilization_haircut_bps": state.config.utilization_haircut_bps,
            "rebate_bps": state.config.rebate_bps,
            "oracle_quorum": state.config.oracle_quorum,
            "sealed_liquidity_ttl_epochs": state.config.sealed_liquidity_ttl_epochs
        },
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "rebate_budget_remaining_micro_credits": state.rebate_budget_remaining_micro_credits
    })
}

pub fn state_root(state: &State) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-storage-compute-forward-amm-runtime/state-root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(&public_record(state)),
        ],
        32,
    )
}

fn demo_pool(config: &Config, pool_id: &str, pool_kind: PoolKind) -> AmmPool {
    AmmPool {
        pool_id: pool_id.to_string(),
        pool_kind,
        base_note_class: "storage-compute-capacity-forward".to_string(),
        quote_token: "dusd".to_string(),
        sealed_base_reserve_root: record_root("SEALED-BASE-RESERVE", &json!([pool_id, "base"])),
        sealed_quote_reserve_root: record_root("SEALED-QUOTE-RESERVE", &json!([pool_id, "quote"])),
        lp_note_root: record_root("LP-NOTE", &json!([pool_id, "lp"])),
        invariant_root: record_root("AMM-INVARIANT", &json!([pool_id, config.amm_suite])),
        fee_bps: config.amm_fee_bps,
        protocol_fee_bps: config.protocol_fee_bps,
        oracle_price_root: record_root("ORACLE-PRICE", &json!([pool_id, config.oracle_suite])),
        last_epoch: DEVNET_EPOCH,
    }
}

fn demo_bucket(config: &Config, bucket_id: &str, epoch: u64) -> EpochCapacityBucket {
    EpochCapacityBucket {
        bucket_id: bucket_id.to_string(),
        epoch,
        region_root: record_root("REGION", &json!(["devnet-us-east", "devnet-eu-west"])),
        provider_set_root: record_root("PROVIDER-SET", &json!(["provider-a", "provider-b"])),
        storage_capacity_root: record_root("STORAGE-CAPACITY", &json!([bucket_id, "gib-month"])),
        compute_capacity_root: record_root("COMPUTE-CAPACITY", &json!([bucket_id, "vcpu-hour"])),
        utilization_root: record_root("UTILIZATION", &json!([bucket_id, 7_250_u64])),
        haircut_bps: config.utilization_haircut_bps,
        net_capacity_root: record_root("NET-CAPACITY", &json!([bucket_id, "haircut-applied"])),
    }
}

fn demo_note(
    config: &Config,
    pool_id: &str,
    bucket_id: &str,
    note_id: &str,
) -> StorageComputeForwardNote {
    StorageComputeForwardNote {
        note_id: note_id.to_string(),
        provider_commitment: record_root("PROVIDER", &json!(["provider-a", note_id])),
        buyer_commitment: record_root("BUYER", &json!(["buyer-a", note_id])),
        pool_id: pool_id.to_string(),
        note_kind: ForwardNoteKind::ComputeVcpuHour,
        capacity_bucket_id: bucket_id.to_string(),
        capacity_units_commitment: record_root("CAPACITY-UNITS", &json!([note_id, 250_000_u64])),
        price_quote_commitment: record_root("PRICE-QUOTE", &json!([note_id, "dusd"])),
        issue_epoch: DEVNET_EPOCH,
        maturity_epoch: DEVNET_EPOCH + config.maturity_epochs,
        default_haircut_bps: config.default_haircut_bps,
        encrypted_terms_root: record_root("ENCRYPTED-TERMS", &json!([note_id, config.note_suite])),
        nullifier_root: record_root("NULLIFIER", &json!([note_id, "unspent"])),
    }
}

fn demo_attestation(
    config: &Config,
    bucket_id: &str,
    attestation_id: &str,
) -> ProviderOracleAttestation {
    ProviderOracleAttestation {
        attestation_id: attestation_id.to_string(),
        attestation_kind: AttestationKind::ProviderCapacity,
        provider_commitment: record_root("PROVIDER", &json!(["provider-a", bucket_id])),
        oracle_committee_root: record_root("ORACLE-COMMITTEE", &json!([config.oracle_quorum])),
        epoch: DEVNET_EPOCH,
        capacity_bucket_id: bucket_id.to_string(),
        attested_capacity_root: record_root("ATTESTED-CAPACITY", &json!([bucket_id])),
        attested_price_root: record_root("ATTESTED-PRICE", &json!([bucket_id, "dusd"])),
        pq_signature_root: record_root(
            "PQ-SIGNATURE",
            &json!([attestation_id, config.oracle_suite]),
        ),
        status: SettlementStatus::OraclePending,
    }
}

fn demo_liquidity(pool_id: &str, position_id: &str) -> SealedLiquidityPosition {
    SealedLiquidityPosition {
        position_id: position_id.to_string(),
        pool_id: pool_id.to_string(),
        owner_commitment: record_root("LP-OWNER", &json!([position_id])),
        sealed_base_units_root: record_root("SEALED-BASE-UNITS", &json!([position_id, "base"])),
        sealed_quote_units_root: record_root("SEALED-QUOTE-UNITS", &json!([position_id, "quote"])),
        lp_note_root: record_root("LP-NOTE", &json!([position_id])),
        locked_until_epoch: DEVNET_EPOCH + DEFAULT_SEALED_LIQUIDITY_TTL_EPOCHS,
    }
}

fn demo_settlement(
    config: &Config,
    note: &StorageComputeForwardNote,
    pool_id: &str,
    bucket_id: &str,
) -> MaturitySettlement {
    MaturitySettlement {
        settlement_id: format!("settlement-{}", note.note_id),
        note_id: note.note_id.clone(),
        pool_id: pool_id.to_string(),
        capacity_bucket_id: bucket_id.to_string(),
        maturity_epoch: note.maturity_epoch,
        delivered_capacity_root: record_root("DELIVERED-CAPACITY", &json!([note.note_id])),
        due_quote_root: record_root("DUE-QUOTE", &json!([note.note_id])),
        paid_quote_root: record_root("PAID-QUOTE", &json!([note.note_id, "pending"])),
        haircut_bps: config.default_haircut_bps,
        default_claim_root: record_root("DEFAULT-CLAIM", &json!([note.note_id, "none"])),
        status: SettlementStatus::HaircutApplied,
    }
}

fn demo_rebate(config: &Config, settlement_id: &str, rebate_id: &str) -> FeeCreditRebate {
    FeeCreditRebate {
        rebate_id: rebate_id.to_string(),
        account_commitment: record_root("REBATE-ACCOUNT", &json!([rebate_id])),
        source_settlement_id: settlement_id.to_string(),
        fee_credit_note_root: record_root("FEE-CREDIT-NOTE", &json!([rebate_id])),
        rebate_bps: config.rebate_bps,
        epoch: DEVNET_EPOCH,
    }
}

fn demo_redaction(source_record_id: &str, redaction_id: &str) -> PrivacyRedaction {
    PrivacyRedaction {
        redaction_id: redaction_id.to_string(),
        source_record_id: source_record_id.to_string(),
        redacted_fields_root: record_root(
            "REDACTED-FIELDS",
            &json!([
                "provider_commitment",
                "buyer_commitment",
                "owner_commitment"
            ]),
        ),
        disclosure_policy_root: record_root("DISCLOSURE-POLICY", &json!(["viewkey-required"])),
        public_hint_root: record_root("PUBLIC-HINT", &json!([source_record_id, "roots-only"])),
    }
}

fn map_root<I>(domain: &'static str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves: Vec<String> = records
        .into_iter()
        .map(|record| record_root(domain, &record))
        .collect();
    merkle_root(domain, leaves)
}

fn record_root(domain: &'static str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn redacted_label(value: &str) -> String {
    if value.len() <= 16 {
        "redacted".to_string()
    } else {
        format!("redacted:{}", &value[..16])
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
