use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedEnergySettlementAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_ENERGY_SETTLEMENT_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-energy-settlement-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_ENERGY_SETTLEMENT_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const NOTE_SUITE: &str = "tokenized-energy-settlement-note-commitments-v1";
pub const AMM_SUITE: &str = "sealed-confidential-energy-cpamm-v1";
pub const ORACLE_SUITE: &str = "pq-miner-energy-oracle-attestation-v1";
pub const PRODUCTION_BUCKET_SUITE: &str = "epoch-energy-production-bucket-root-v1";
pub const MATURITY_SUITE: &str = "confidential-energy-maturity-settlement-v1";
pub const FEE_REBATE_SUITE: &str = "private-fee-credit-rebate-note-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-redacted-energy-settlement-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_244_000;
pub const DEVNET_ENERGY_EPOCH: u64 = 48;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_SECONDS: u64 = 900;
pub const DEFAULT_MATURITY_EPOCHS: u64 = 96;
pub const DEFAULT_MAX_SETTLEMENT_DELAY_EPOCHS: u64 = 12;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_AMM_FEE_BPS: u64 = 18;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 4;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_PRODUCTION_HAIRCUT_BPS: u64 = 250;
pub const DEFAULT_PRICE_HAIRCUT_BPS: u64 = 75;
pub const DEFAULT_DEFAULT_HAIRCUT_BPS: u64 = 1_500;
pub const DEFAULT_REBATE_BPS: u64 = 8;
pub const DEFAULT_REBATE_BUDGET_MICRO_CREDITS: u64 = 750_000_000;
pub const DEFAULT_SEALED_LIQUIDITY_TTL_EPOCHS: u64 = 8;
pub const MAX_NOTES: usize = 1_048_576;
pub const MAX_POOLS: usize = 262_144;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_BUCKETS: usize = 524_288;
pub const MAX_SEALED_LIQUIDITY: usize = 1_048_576;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTIONS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnergyNoteKind {
    ProducedMwh,
    ForwardDelivery,
    RenewableCredit,
    GridBalancingCredit,
    MinerLoadOffset,
    FeeCredit,
    LpShare,
    DefaultClaim,
}

impl EnergyNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProducedMwh => "produced_mwh",
            Self::ForwardDelivery => "forward_delivery",
            Self::RenewableCredit => "renewable_credit",
            Self::GridBalancingCredit => "grid_balancing_credit",
            Self::MinerLoadOffset => "miner_load_offset",
            Self::FeeCredit => "fee_credit",
            Self::LpShare => "lp_share",
            Self::DefaultClaim => "default_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Committed,
    OraclePending,
    Bucketed,
    Sealed,
    Maturing,
    Settled,
    Defaulted,
    RebateIssued,
    Rejected,
    Expired,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::OraclePending => "oracle_pending",
            Self::Bucketed => "bucketed",
            Self::Sealed => "sealed",
            Self::Maturing => "maturing",
            Self::Settled => "settled",
            Self::Defaulted => "defaulted",
            Self::RebateIssued => "rebate_issued",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    ConstantProduct,
    StableEnergy,
    ForwardCurve,
    RenewableCreditCurve,
    LoadOffsetCurve,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::StableEnergy => "stable_energy",
            Self::ForwardCurve => "forward_curve",
            Self::RenewableCreditCurve => "renewable_credit_curve",
            Self::LoadOffsetCurve => "load_offset_curve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    MinerProduction,
    MeterReading,
    RenewableCertificate,
    GridPrice,
    OutageDefault,
    Curtailment,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinerProduction => "miner_production",
            Self::MeterReading => "meter_reading",
            Self::RenewableCertificate => "renewable_certificate",
            Self::GridPrice => "grid_price",
            Self::OutageDefault => "outage_default",
            Self::Curtailment => "curtailment",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub note_suite: String,
    pub amm_suite: String,
    pub oracle_suite: String,
    pub production_bucket_suite: String,
    pub maturity_suite: String,
    pub fee_rebate_suite: String,
    pub epoch_seconds: u64,
    pub maturity_epochs: u64,
    pub max_settlement_delay_epochs: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub amm_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub production_haircut_bps: u64,
    pub price_haircut_bps: u64,
    pub default_haircut_bps: u64,
    pub rebate_bps: u64,
    pub rebate_budget_micro_credits: u64,
    pub sealed_liquidity_ttl_epochs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            note_suite: NOTE_SUITE.to_string(),
            amm_suite: AMM_SUITE.to_string(),
            oracle_suite: ORACLE_SUITE.to_string(),
            production_bucket_suite: PRODUCTION_BUCKET_SUITE.to_string(),
            maturity_suite: MATURITY_SUITE.to_string(),
            fee_rebate_suite: FEE_REBATE_SUITE.to_string(),
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            maturity_epochs: DEFAULT_MATURITY_EPOCHS,
            max_settlement_delay_epochs: DEFAULT_MAX_SETTLEMENT_DELAY_EPOCHS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            amm_fee_bps: DEFAULT_AMM_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            production_haircut_bps: DEFAULT_PRODUCTION_HAIRCUT_BPS,
            price_haircut_bps: DEFAULT_PRICE_HAIRCUT_BPS,
            default_haircut_bps: DEFAULT_DEFAULT_HAIRCUT_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            rebate_budget_micro_credits: DEFAULT_REBATE_BUDGET_MICRO_CREDITS,
            sealed_liquidity_ttl_epochs: DEFAULT_SEALED_LIQUIDITY_TTL_EPOCHS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unexpected protocol version".to_string());
        }
        if self.amm_fee_bps + self.protocol_fee_bps > MAX_BPS {
            return Err("fee bps exceeds maximum".to_string());
        }
        if self.default_haircut_bps > MAX_BPS
            || self.production_haircut_bps > MAX_BPS
            || self.price_haircut_bps > MAX_BPS
        {
            return Err("haircut bps exceeds maximum".to_string());
        }
        if self.oracle_quorum == 0 {
            return Err("oracle quorum must be positive".to_string());
        }
        if self.min_privacy_set_size > self.target_privacy_set_size {
            return Err("minimum privacy set exceeds target".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub notes: u64,
    pub amm_pools: u64,
    pub oracle_attestations: u64,
    pub production_buckets: u64,
    pub sealed_liquidity: u64,
    pub maturity_settlements: u64,
    pub default_events: u64,
    pub fee_credit_rebates: u64,
    pub privacy_redactions: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub notes_root: String,
    pub amm_pools_root: String,
    pub oracle_attestations_root: String,
    pub production_buckets_root: String,
    pub sealed_liquidity_root: String,
    pub maturity_settlements_root: String,
    pub fee_credit_rebates_root: String,
    pub privacy_redactions_root: String,
    pub nullifier_root: String,
    pub runtime_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnergySettlementNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub energy_asset_root: String,
    pub note_kind: EnergyNoteKind,
    pub epoch: u64,
    pub maturity_epoch: u64,
    pub amount_mwh_commitment: String,
    pub price_micro_credits_commitment: String,
    pub status: SettlementStatus,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
}

impl EnergySettlementNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": self.owner_commitment,
            "energy_asset_root": self.energy_asset_root,
            "note_kind": self.note_kind.as_str(),
            "epoch": self.epoch,
            "maturity_epoch": self.maturity_epoch,
            "amount_mwh_commitment": self.amount_mwh_commitment,
            "price_micro_credits_commitment": self.price_micro_credits_commitment,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": self.nullifier_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmmPool {
    pub pool_id: String,
    pub pool_kind: PoolKind,
    pub base_energy_root: String,
    pub quote_credit_root: String,
    pub sealed_reserve_a_root: String,
    pub sealed_reserve_b_root: String,
    pub lp_note_root: String,
    pub fee_bps: u64,
    pub maturity_epoch: u64,
    pub active: bool,
}

impl AmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "base_energy_root": self.base_energy_root,
            "quote_credit_root": self.quote_credit_root,
            "sealed_reserve_a_root": self.sealed_reserve_a_root,
            "sealed_reserve_b_root": self.sealed_reserve_b_root,
            "lp_note_root": self.lp_note_root,
            "fee_bps": self.fee_bps,
            "maturity_epoch": self.maturity_epoch,
            "active": self.active
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestation {
    pub attestation_id: String,
    pub attestation_kind: AttestationKind,
    pub oracle_committee_root: String,
    pub miner_commitment: String,
    pub epoch: u64,
    pub production_bucket_id: String,
    pub attested_value_root: String,
    pub pq_signature_root: String,
    pub quorum_weight: u16,
}

impl OracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "oracle_committee_root": self.oracle_committee_root,
            "miner_commitment": self.miner_commitment,
            "epoch": self.epoch,
            "production_bucket_id": self.production_bucket_id,
            "attested_value_root": self.attested_value_root,
            "pq_signature_root": self.pq_signature_root,
            "quorum_weight": self.quorum_weight
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub region_root: String,
    pub miner_set_root: String,
    pub gross_mwh_root: String,
    pub haircut_bps: u64,
    pub net_mwh_root: String,
    pub attestation_root: String,
    pub sealed: bool,
}

impl ProductionBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "region_root": self.region_root,
            "miner_set_root": self.miner_set_root,
            "gross_mwh_root": self.gross_mwh_root,
            "haircut_bps": self.haircut_bps,
            "net_mwh_root": self.net_mwh_root,
            "attestation_root": self.attestation_root,
            "sealed": self.sealed
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedLiquidity {
    pub sealed_id: String,
    pub pool_id: String,
    pub provider_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub invariant_root: String,
    pub epoch: u64,
    pub expires_epoch: u64,
}

impl SealedLiquidity {
    pub fn public_record(&self) -> Value {
        json!({
            "sealed_id": self.sealed_id,
            "pool_id": self.pool_id,
            "provider_commitment": self.provider_commitment,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "invariant_root": self.invariant_root,
            "epoch": self.epoch,
            "expires_epoch": self.expires_epoch
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaturitySettlement {
    pub settlement_id: String,
    pub note_id: String,
    pub bucket_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub maturity_epoch: u64,
    pub haircut_bps: u64,
    pub settlement_amount_root: String,
    pub status: SettlementStatus,
}

impl MaturitySettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "note_id": self.note_id,
            "bucket_id": self.bucket_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "maturity_epoch": self.maturity_epoch,
            "haircut_bps": self.haircut_bps,
            "settlement_amount_root": self.settlement_amount_root,
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
            "account_commitment": self.account_commitment,
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
        json!({
            "redaction_id": self.redaction_id,
            "source_record_id": self.source_record_id,
            "redacted_fields_root": self.redacted_fields_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "public_hint_root": self.public_hint_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_l2_height: u64,
    pub current_energy_epoch: u64,
    pub rebate_budget_remaining_micro_credits: u64,
    pub notes: BTreeMap<String, EnergySettlementNote>,
    pub amm_pools: BTreeMap<String, AmmPool>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub production_buckets: BTreeMap<String, ProductionBucket>,
    pub sealed_liquidity: BTreeMap<String, SealedLiquidity>,
    pub maturity_settlements: BTreeMap<String, MaturitySettlement>,
    pub fee_credit_rebates: BTreeMap<String, FeeCreditRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub spent_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_energy_epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            rebate_budget_remaining_micro_credits: config.rebate_budget_micro_credits,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_l2_height,
            current_energy_epoch,
            notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            production_buckets: BTreeMap::new(),
            sealed_liquidity: BTreeMap::new(),
            maturity_settlements: BTreeMap::new(),
            fee_credit_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            spent_nullifier_roots: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::devnet(), DEVNET_L2_HEIGHT, DEVNET_ENERGY_EPOCH).expect("devnet");
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
            notes: self.notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            oracle_attestations: self.oracle_attestations.len() as u64,
            production_buckets: self.production_buckets.len() as u64,
            sealed_liquidity: self.sealed_liquidity.len() as u64,
            maturity_settlements: self.maturity_settlements.len() as u64,
            default_events: self
                .maturity_settlements
                .values()
                .filter(|settlement| settlement.status == SettlementStatus::Defaulted)
                .count() as u64,
            fee_credit_rebates: self.fee_credit_rebates.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
        };
        self.roots = self.derive_roots();
    }

    fn derive_roots(&self) -> Roots {
        let notes = public_values(self.notes.values().map(EnergySettlementNote::public_record));
        let amm_pools = public_values(self.amm_pools.values().map(AmmPool::public_record));
        let attestations = public_values(
            self.oracle_attestations
                .values()
                .map(OracleAttestation::public_record),
        );
        let buckets = public_values(
            self.production_buckets
                .values()
                .map(ProductionBucket::public_record),
        );
        let sealed = public_values(
            self.sealed_liquidity
                .values()
                .map(SealedLiquidity::public_record),
        );
        let settlements = public_values(
            self.maturity_settlements
                .values()
                .map(MaturitySettlement::public_record),
        );
        let rebates = public_values(
            self.fee_credit_rebates
                .values()
                .map(FeeCreditRebate::public_record),
        );
        let redactions = public_values(
            self.privacy_redactions
                .values()
                .map(PrivacyRedaction::public_record),
        );
        let nullifiers = self
            .spent_nullifier_roots
            .iter()
            .map(|root| json!(root))
            .collect::<Vec<_>>();

        let mut roots = Roots {
            notes_root: merkle_root("energy-settlement-notes", &notes),
            amm_pools_root: merkle_root("energy-settlement-amm-pools", &amm_pools),
            oracle_attestations_root: merkle_root(
                "energy-settlement-oracle-attestations",
                &attestations,
            ),
            production_buckets_root: merkle_root("energy-settlement-production-buckets", &buckets),
            sealed_liquidity_root: merkle_root("energy-settlement-sealed-liquidity", &sealed),
            maturity_settlements_root: merkle_root(
                "energy-settlement-maturity-settlements",
                &settlements,
            ),
            fee_credit_rebates_root: merkle_root("energy-settlement-fee-credit-rebates", &rebates),
            privacy_redactions_root: merkle_root(
                "energy-settlement-privacy-redactions",
                &redactions,
            ),
            nullifier_root: merkle_root("energy-settlement-nullifiers", &nullifiers),
            runtime_root: String::new(),
        };
        roots.runtime_root = runtime_root_from_parts(&roots, &self.counters, &self.config);
        roots
    }

    fn load_demo_fixtures(&mut self) {
        let pool_id = deterministic_id("pool", "mwh-usdc-forward");
        let bucket_id = deterministic_id("bucket", "epoch-48-north-grid");
        let note_id = deterministic_id("note", "miner-alpha-forward");
        let settlement_id = deterministic_id("settlement", "miner-alpha-forward");

        self.amm_pools.insert(
            pool_id.clone(),
            AmmPool {
                pool_id: pool_id.clone(),
                pool_kind: PoolKind::ForwardCurve,
                base_energy_root: deterministic_root("asset", "tokenized-mwh-nyiso"),
                quote_credit_root: deterministic_root("asset", "private-usdc-credit"),
                sealed_reserve_a_root: deterministic_root("reserve", "mwh"),
                sealed_reserve_b_root: deterministic_root("reserve", "credit"),
                lp_note_root: deterministic_root("lp", "mwh-usdc-forward"),
                fee_bps: self.config.amm_fee_bps,
                maturity_epoch: self.current_energy_epoch + self.config.maturity_epochs,
                active: true,
            },
        );
        self.production_buckets.insert(
            bucket_id.clone(),
            ProductionBucket {
                bucket_id: bucket_id.clone(),
                epoch: self.current_energy_epoch,
                region_root: deterministic_root("region", "north-grid"),
                miner_set_root: deterministic_root("miner-set", "alpha-beta"),
                gross_mwh_root: deterministic_root("gross-mwh", "11250"),
                haircut_bps: self.config.production_haircut_bps,
                net_mwh_root: deterministic_root("net-mwh", "10968"),
                attestation_root: deterministic_root("attestations", "epoch-48"),
                sealed: true,
            },
        );
        self.notes.insert(
            note_id.clone(),
            EnergySettlementNote {
                note_id: note_id.clone(),
                owner_commitment: deterministic_root("owner", "miner-alpha"),
                energy_asset_root: deterministic_root("asset", "tokenized-mwh-nyiso"),
                note_kind: EnergyNoteKind::ForwardDelivery,
                epoch: self.current_energy_epoch,
                maturity_epoch: self.current_energy_epoch + self.config.maturity_epochs,
                amount_mwh_commitment: deterministic_root("mwh", "420"),
                price_micro_credits_commitment: deterministic_root("price", "38600000"),
                status: SettlementStatus::Maturing,
                privacy_set_size: self.config.target_privacy_set_size,
                nullifier_root: deterministic_root("nullifier", "miner-alpha-forward"),
            },
        );
        self.oracle_attestations.insert(
            deterministic_id("attestation", "miner-alpha-meter"),
            OracleAttestation {
                attestation_id: deterministic_id("attestation", "miner-alpha-meter"),
                attestation_kind: AttestationKind::MeterReading,
                oracle_committee_root: deterministic_root("oracle", "energy-committee-a"),
                miner_commitment: deterministic_root("miner", "miner-alpha"),
                epoch: self.current_energy_epoch,
                production_bucket_id: bucket_id.clone(),
                attested_value_root: deterministic_root("meter", "miner-alpha-epoch-48"),
                pq_signature_root: deterministic_root("pq-signature", "meter-alpha"),
                quorum_weight: self.config.oracle_quorum,
            },
        );
        self.sealed_liquidity.insert(
            deterministic_id("sealed-liquidity", "provider-one"),
            SealedLiquidity {
                sealed_id: deterministic_id("sealed-liquidity", "provider-one"),
                pool_id: pool_id.clone(),
                provider_commitment: deterministic_root("provider", "lp-one"),
                input_note_root: deterministic_root("input-note", "lp-one-mwh"),
                output_note_root: deterministic_root("output-note", "lp-one-credit"),
                invariant_root: deterministic_root("invariant", "mwh-usdc-forward"),
                epoch: self.current_energy_epoch,
                expires_epoch: self.current_energy_epoch + self.config.sealed_liquidity_ttl_epochs,
            },
        );
        self.maturity_settlements.insert(
            settlement_id.clone(),
            MaturitySettlement {
                settlement_id: settlement_id.clone(),
                note_id: note_id.clone(),
                bucket_id,
                pool_id,
                epoch: self.current_energy_epoch,
                maturity_epoch: self.current_energy_epoch + self.config.maturity_epochs,
                haircut_bps: self.config.price_haircut_bps,
                settlement_amount_root: deterministic_root("settlement-amount", "miner-alpha"),
                status: SettlementStatus::Maturing,
            },
        );
        self.fee_credit_rebates.insert(
            deterministic_id("rebate", "miner-alpha"),
            FeeCreditRebate {
                rebate_id: deterministic_id("rebate", "miner-alpha"),
                account_commitment: deterministic_root("owner", "miner-alpha"),
                source_settlement_id: settlement_id.clone(),
                fee_credit_note_root: deterministic_root("fee-credit", "miner-alpha"),
                rebate_bps: self.config.rebate_bps,
                epoch: self.current_energy_epoch,
            },
        );
        self.privacy_redactions.insert(
            deterministic_id("redaction", "miner-alpha-note"),
            PrivacyRedaction {
                redaction_id: deterministic_id("redaction", "miner-alpha-note"),
                source_record_id: note_id,
                redacted_fields_root: deterministic_root("redacted-fields", "amount-price"),
                disclosure_policy_root: deterministic_root("policy", "roots-only-demo"),
                public_hint_root: deterministic_root("hint", "energy-forward"),
            },
        );
        self.spent_nullifier_roots
            .insert(deterministic_root("spent-nullifier", "demo-001"));
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
        "current_l2_height": state.current_l2_height,
        "current_energy_epoch": state.current_energy_epoch,
        "config": {
            "hash_suite": state.config.hash_suite,
            "note_suite": state.config.note_suite,
            "amm_suite": state.config.amm_suite,
            "oracle_suite": state.config.oracle_suite,
            "production_bucket_suite": state.config.production_bucket_suite,
            "maturity_suite": state.config.maturity_suite,
            "fee_rebate_suite": state.config.fee_rebate_suite,
            "epoch_seconds": state.config.epoch_seconds,
            "maturity_epochs": state.config.maturity_epochs,
            "max_settlement_delay_epochs": state.config.max_settlement_delay_epochs,
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "target_privacy_set_size": state.config.target_privacy_set_size,
            "min_pq_security_bits": state.config.min_pq_security_bits,
            "oracle_quorum": state.config.oracle_quorum,
            "amm_fee_bps": state.config.amm_fee_bps,
            "protocol_fee_bps": state.config.protocol_fee_bps,
            "production_haircut_bps": state.config.production_haircut_bps,
            "price_haircut_bps": state.config.price_haircut_bps,
            "default_haircut_bps": state.config.default_haircut_bps,
            "rebate_bps": state.config.rebate_bps,
            "sealed_liquidity_ttl_epochs": state.config.sealed_liquidity_ttl_epochs
        },
        "counters": state.counters,
        "roots": state.roots,
        "rebate_budget_remaining_micro_credits": state.rebate_budget_remaining_micro_credits
    })
}

pub fn state_root(state: &State) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-energy-settlement-amm-runtime/state-root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(&public_record(state)),
        ],
        32,
    )
}

fn runtime_root_from_parts(roots: &Roots, counters: &Counters, config: &Config) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-energy-settlement-amm-runtime/runtime-root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.chain_id),
            HashPart::Str(&roots.notes_root),
            HashPart::Str(&roots.amm_pools_root),
            HashPart::Str(&roots.oracle_attestations_root),
            HashPart::Str(&roots.production_buckets_root),
            HashPart::Str(&roots.sealed_liquidity_root),
            HashPart::Str(&roots.maturity_settlements_root),
            HashPart::Str(&roots.fee_credit_rebates_root),
            HashPart::Str(&roots.privacy_redactions_root),
            HashPart::Str(&roots.nullifier_root),
            HashPart::U64(counters.notes),
            HashPart::U64(counters.amm_pools),
            HashPart::U64(counters.oracle_attestations),
            HashPart::U64(counters.production_buckets),
            HashPart::U64(counters.sealed_liquidity),
            HashPart::U64(counters.maturity_settlements),
            HashPart::U64(counters.fee_credit_rebates),
            HashPart::U64(counters.privacy_redactions),
        ],
        32,
    )
}

fn deterministic_id(domain: &str, label: &str) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-energy-settlement-amm-runtime/id",
        &[HashPart::Str(domain), HashPart::Str(label)],
        16,
    )
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-energy-settlement-amm-runtime/root",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

fn public_values(values: impl Iterator<Item = Value>) -> Vec<Value> {
    values.collect()
}
