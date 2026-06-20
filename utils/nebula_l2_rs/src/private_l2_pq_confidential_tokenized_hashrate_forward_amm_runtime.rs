use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedHashrateForwardAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_HASHRATE_FORWARD_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-hashrate-forward-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_HASHRATE_FORWARD_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-hashrate-forward-v1";
pub const NOTE_COMMITMENT_SUITE: &str = "confidential-tokenized-hashrate-forward-note-v1";
pub const AMM_POOL_SUITE: &str = "sealed-constant-product-hashrate-forward-amm-v1";
pub const ORACLE_ATTESTATION_SUITE: &str = "miner-oracle-epoch-production-attestation-v1";
pub const SETTLEMENT_SUITE: &str = "maturity-settlement-default-haircut-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-hashrate-forward-amm-devnet";
pub const DEVNET_HEIGHT: u64 = 2_480_000;
pub const DEVNET_FEE_TOKEN: &str = "dxmr";
pub const DEVNET_QUOTE_TOKEN: &str = "dusd";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MATURITY_EPOCHS: u64 = 12;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POOL_FEE_BPS: u64 = 24;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 4;
pub const DEFAULT_REBATE_BPS: u64 = 10;
pub const DEFAULT_DEFAULT_HAIRCUT_BPS: u64 = 1_250;
pub const DEFAULT_ORACLE_DEVIATION_BPS: u64 = 500;
pub const DEFAULT_MIN_SEALED_LIQUIDITY_UNITS: u128 = 25_000_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardStatus {
    Draft,
    Listed,
    Funded,
    Matured,
    Settled,
    Defaulted,
    Cancelled,
}

impl ForwardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Listed => "listed",
            Self::Funded => "funded",
            Self::Matured => "matured",
            Self::Settled => "settled",
            Self::Defaulted => "defaulted",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    ConstantProduct,
    StableForward,
    WeightedHashrate,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::StableForward => "stable_forward",
            Self::WeightedHashrate => "weighted_hashrate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    MinerCapacity,
    OracleProduction,
    PoolSolvency,
    MaturitySettlement,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinerCapacity => "miner_capacity",
            Self::OracleProduction => "oracle_production",
            Self::PoolSolvency => "pool_solvency",
            Self::MaturitySettlement => "maturity_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    HaircutApplied,
    Paid,
    Rebated,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::HaircutApplied => "haircut_applied",
            Self::Paid => "paid",
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
    pub pq_attestation_suite: String,
    pub note_commitment_suite: String,
    pub amm_pool_suite: String,
    pub oracle_attestation_suite: String,
    pub settlement_suite: String,
    pub fee_token: String,
    pub quote_token: String,
    pub epoch_blocks: u64,
    pub maturity_epochs: u64,
    pub settlement_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub pool_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub rebate_bps: u64,
    pub default_haircut_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub min_sealed_liquidity_units: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            note_commitment_suite: NOTE_COMMITMENT_SUITE.to_string(),
            amm_pool_suite: AMM_POOL_SUITE.to_string(),
            oracle_attestation_suite: ORACLE_ATTESTATION_SUITE.to_string(),
            settlement_suite: SETTLEMENT_SUITE.to_string(),
            fee_token: DEVNET_FEE_TOKEN.to_string(),
            quote_token: DEVNET_QUOTE_TOKEN.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            maturity_epochs: DEFAULT_MATURITY_EPOCHS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            pool_fee_bps: DEFAULT_POOL_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            default_haircut_bps: DEFAULT_DEFAULT_HAIRCUT_BPS,
            max_oracle_deviation_bps: DEFAULT_ORACLE_DEVIATION_BPS,
            min_sealed_liquidity_units: DEFAULT_MIN_SEALED_LIQUIDITY_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch",
        )?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(!self.market_id.trim().is_empty(), "market id required")?;
        require(self.epoch_blocks > 0, "epoch blocks required")?;
        require(self.maturity_epochs > 0, "maturity epochs required")?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(
            self.pool_fee_bps + self.protocol_fee_bps <= MAX_BPS
                && self.rebate_bps <= MAX_BPS
                && self.default_haircut_bps <= MAX_BPS
                && self.max_oracle_deviation_bps <= MAX_BPS,
            "invalid bps config",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "market_id": self.market_id,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "note_commitment_suite": self.note_commitment_suite,
            "amm_pool_suite": self.amm_pool_suite,
            "oracle_attestation_suite": self.oracle_attestation_suite,
            "settlement_suite": self.settlement_suite,
            "fee_token": self.fee_token,
            "quote_token": self.quote_token,
            "epoch_blocks": self.epoch_blocks,
            "maturity_epochs": self.maturity_epochs,
            "settlement_window_blocks": self.settlement_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "pool_fee_bps": self.pool_fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "rebate_bps": self.rebate_bps,
            "default_haircut_bps": self.default_haircut_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "min_sealed_liquidity_units": self.min_sealed_liquidity_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub forward_notes: u64,
    pub amm_pools: u64,
    pub miner_attestations: u64,
    pub epoch_buckets: u64,
    pub sealed_liquidity: u64,
    pub maturity_settlements: u64,
    pub fee_credit_rebates: u64,
    pub privacy_redactions: u64,
    pub consumed_nullifiers: u64,
    pub total_hashrate_ths: u128,
    pub total_sealed_liquidity_units: u128,
    pub total_settled_quote_units: u128,
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
    pub miner_attestation_root: String,
    pub epoch_bucket_root: String,
    pub sealed_liquidity_root: String,
    pub maturity_settlement_root: String,
    pub fee_credit_rebate_root: String,
    pub privacy_redaction_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HashrateForwardNote {
    pub note_id: String,
    pub miner_id: String,
    pub pool_id: String,
    pub commitment_root: String,
    pub hashrate_ths: u128,
    pub strike_quote_units: u128,
    pub issue_epoch: u64,
    pub maturity_epoch: u64,
    pub status: ForwardStatus,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
}

impl HashrateForwardNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "miner_id": redacted_label(&self.miner_id),
            "pool_id": self.pool_id,
            "commitment_root": self.commitment_root,
            "hashrate_ths": self.hashrate_ths,
            "strike_quote_units": self.strike_quote_units,
            "issue_epoch": self.issue_epoch,
            "maturity_epoch": self.maturity_epoch,
            "status": self.status.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "nullifier_commitment": self.nullifier_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmmPool {
    pub pool_id: String,
    pub kind: PoolKind,
    pub base_note_class: String,
    pub quote_token: String,
    pub sealed_base_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub lp_commitment_root: String,
    pub fee_bps: u64,
    pub invariant_root: String,
    pub active: bool,
}

impl AmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "kind": self.kind.as_str(),
            "base_note_class": self.base_note_class,
            "quote_token": self.quote_token,
            "sealed_base_reserve_root": self.sealed_base_reserve_root,
            "sealed_quote_reserve_root": self.sealed_quote_reserve_root,
            "lp_commitment_root": self.lp_commitment_root,
            "fee_bps": self.fee_bps,
            "invariant_root": self.invariant_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinerOracleAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub miner_id: String,
    pub oracle_id: String,
    pub epoch: u64,
    pub production_bucket_id: String,
    pub committed_hashrate_ths: u128,
    pub observed_hashrate_ths: u128,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub issued_height: u64,
}

impl MinerOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "miner_id": redacted_label(&self.miner_id),
            "oracle_id": self.oracle_id,
            "epoch": self.epoch,
            "production_bucket_id": self.production_bucket_id,
            "committed_hashrate_ths": self.committed_hashrate_ths,
            "observed_hashrate_ths": self.observed_hashrate_ths,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EpochProductionBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub miner_set_root: String,
    pub production_commitment_root: String,
    pub expected_hashrate_ths: u128,
    pub observed_hashrate_ths: u128,
    pub oracle_aggregate_root: String,
}

impl EpochProductionBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedLiquidityPosition {
    pub position_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub sealed_base_units: u128,
    pub sealed_quote_units: u128,
    pub lp_note_root: String,
    pub locked_until_epoch: u64,
}

impl SealedLiquidityPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "pool_id": self.pool_id,
            "owner_commitment": self.owner_commitment,
            "sealed_base_units": self.sealed_base_units,
            "sealed_quote_units": self.sealed_quote_units,
            "lp_note_root": self.lp_note_root,
            "locked_until_epoch": self.locked_until_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaturitySettlement {
    pub settlement_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub maturity_epoch: u64,
    pub delivered_hashrate_ths: u128,
    pub due_quote_units: u128,
    pub paid_quote_units: u128,
    pub haircut_bps: u64,
    pub status: SettlementStatus,
    pub receipt_root: String,
}

impl MaturitySettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "maturity_epoch": self.maturity_epoch,
            "delivered_hashrate_ths": self.delivered_hashrate_ths,
            "due_quote_units": self.due_quote_units,
            "paid_quote_units": self.paid_quote_units,
            "haircut_bps": self.haircut_bps,
            "status": self.status.as_str(),
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub recipient_commitment: String,
    pub fee_credit_units: u128,
    pub rebate_bps: u64,
    pub expires_height: u64,
}

impl FeeCreditRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub record_kind: String,
    pub record_id: String,
    pub redacted_fields: Vec<String>,
    pub disclosure_root: String,
    pub privacy_set_size: u64,
}

impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub forward_notes: BTreeMap<String, HashrateForwardNote>,
    pub amm_pools: BTreeMap<String, AmmPool>,
    pub miner_attestations: BTreeMap<String, MinerOracleAttestation>,
    pub epoch_buckets: BTreeMap<String, EpochProductionBucket>,
    pub sealed_liquidity: BTreeMap<String, SealedLiquidityPosition>,
    pub maturity_settlements: BTreeMap<String, MaturitySettlement>,
    pub fee_credit_rebates: BTreeMap<String, FeeCreditRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            forward_notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            miner_attestations: BTreeMap::new(),
            epoch_buckets: BTreeMap::new(),
            sealed_liquidity: BTreeMap::new(),
            maturity_settlements: BTreeMap::new(),
            fee_credit_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone()).expect("valid devnet config");
        let pool = demo_pool(
            &config,
            "hashrate-forward-pool-0",
            PoolKind::ConstantProduct,
            "0",
        );
        let bucket = demo_bucket(42, "0");
        let note = demo_note(
            &pool.pool_id,
            "miner-alpha",
            42,
            config.maturity_epochs,
            "0",
        );
        let attestation = demo_attestation(&note, &bucket, DEVNET_HEIGHT + 1, "0");
        let liquidity = demo_liquidity(&pool, "lp-alpha", "0");
        let settlement = demo_settlement(&config, &note, &pool, "0");
        let rebate = demo_rebate(&config, &settlement, "0");
        let redaction = demo_redaction(
            "forward_note",
            &note.note_id,
            config.min_privacy_set_size,
            "0",
        );

        state.insert_amm_pool(pool).expect("devnet pool");
        state.insert_epoch_bucket(bucket).expect("devnet bucket");
        state.insert_forward_note(note).expect("devnet note");
        state
            .insert_miner_attestation(attestation)
            .expect("devnet attestation");
        state
            .insert_sealed_liquidity(liquidity)
            .expect("devnet sealed liquidity");
        state
            .insert_maturity_settlement(settlement)
            .expect("devnet settlement");
        state
            .insert_fee_credit_rebate(rebate)
            .expect("devnet rebate");
        state
            .insert_privacy_redaction(redaction)
            .expect("devnet redaction");
        state
    }

    pub fn insert_forward_note(&mut self, note: HashrateForwardNote) -> Result<()> {
        require(self.amm_pools.contains_key(&note.pool_id), "unknown pool")?;
        require(
            note.maturity_epoch > note.issue_epoch,
            "maturity must exceed issue epoch",
        )?;
        require(
            self.consumed_nullifiers
                .insert(note.nullifier_commitment.clone()),
            "duplicate nullifier commitment",
        )?;
        insert_unique(&mut self.forward_notes, note.note_id.clone(), note)
    }

    pub fn insert_amm_pool(&mut self, pool: AmmPool) -> Result<()> {
        require(pool.fee_bps <= MAX_BPS, "invalid pool fee bps")?;
        insert_unique(&mut self.amm_pools, pool.pool_id.clone(), pool)
    }

    pub fn insert_miner_attestation(&mut self, attestation: MinerOracleAttestation) -> Result<()> {
        require(
            attestation.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set below minimum",
        )?;
        insert_unique(
            &mut self.miner_attestations,
            attestation.attestation_id.clone(),
            attestation,
        )
    }

    pub fn insert_epoch_bucket(&mut self, bucket: EpochProductionBucket) -> Result<()> {
        insert_unique(&mut self.epoch_buckets, bucket.bucket_id.clone(), bucket)
    }

    pub fn insert_sealed_liquidity(&mut self, position: SealedLiquidityPosition) -> Result<()> {
        require(
            self.amm_pools.contains_key(&position.pool_id),
            "unknown liquidity pool",
        )?;
        require(
            position.sealed_quote_units >= self.config.min_sealed_liquidity_units,
            "sealed liquidity below minimum",
        )?;
        insert_unique(
            &mut self.sealed_liquidity,
            position.position_id.clone(),
            position,
        )
    }

    pub fn insert_maturity_settlement(&mut self, settlement: MaturitySettlement) -> Result<()> {
        require(
            self.forward_notes.contains_key(&settlement.note_id),
            "unknown forward note",
        )?;
        require(settlement.haircut_bps <= MAX_BPS, "invalid haircut bps")?;
        insert_unique(
            &mut self.maturity_settlements,
            settlement.settlement_id.clone(),
            settlement,
        )
    }

    pub fn insert_fee_credit_rebate(&mut self, rebate: FeeCreditRebate) -> Result<()> {
        require(rebate.rebate_bps <= MAX_BPS, "invalid rebate bps")?;
        insert_unique(
            &mut self.fee_credit_rebates,
            rebate.rebate_id.clone(),
            rebate,
        )
    }

    pub fn insert_privacy_redaction(&mut self, redaction: PrivacyRedaction) -> Result<()> {
        require(
            redaction.privacy_set_size >= self.config.min_privacy_set_size,
            "redaction privacy set below minimum",
        )?;
        insert_unique(
            &mut self.privacy_redactions,
            redaction.redaction_id.clone(),
            redaction,
        )
    }

    pub fn counters(&self) -> Counters {
        Counters {
            forward_notes: self.forward_notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            miner_attestations: self.miner_attestations.len() as u64,
            epoch_buckets: self.epoch_buckets.len() as u64,
            sealed_liquidity: self.sealed_liquidity.len() as u64,
            maturity_settlements: self.maturity_settlements.len() as u64,
            fee_credit_rebates: self.fee_credit_rebates.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            total_hashrate_ths: self
                .forward_notes
                .values()
                .map(|note| note.hashrate_ths)
                .sum(),
            total_sealed_liquidity_units: self
                .sealed_liquidity
                .values()
                .map(|position| position.sealed_quote_units)
                .sum(),
            total_settled_quote_units: self
                .maturity_settlements
                .values()
                .map(|settlement| settlement.paid_quote_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier_commitment": nullifier }));
        let mut roots = Roots {
            config_root: record_root("HASHRATE-FORWARD-AMM-CONFIG", &self.config.public_record()),
            forward_note_root: merkle_records(
                "HASHRATE-FORWARD-AMM-NOTES",
                self.forward_notes
                    .values()
                    .map(HashrateForwardNote::public_record),
            ),
            amm_pool_root: merkle_records(
                "HASHRATE-FORWARD-AMM-POOLS",
                self.amm_pools.values().map(AmmPool::public_record),
            ),
            miner_attestation_root: merkle_records(
                "HASHRATE-FORWARD-AMM-ATTESTATIONS",
                self.miner_attestations
                    .values()
                    .map(MinerOracleAttestation::public_record),
            ),
            epoch_bucket_root: merkle_records(
                "HASHRATE-FORWARD-AMM-EPOCH-BUCKETS",
                self.epoch_buckets
                    .values()
                    .map(EpochProductionBucket::public_record),
            ),
            sealed_liquidity_root: merkle_records(
                "HASHRATE-FORWARD-AMM-SEALED-LIQUIDITY",
                self.sealed_liquidity
                    .values()
                    .map(SealedLiquidityPosition::public_record),
            ),
            maturity_settlement_root: merkle_records(
                "HASHRATE-FORWARD-AMM-SETTLEMENTS",
                self.maturity_settlements
                    .values()
                    .map(MaturitySettlement::public_record),
            ),
            fee_credit_rebate_root: merkle_records(
                "HASHRATE-FORWARD-AMM-REBATES",
                self.fee_credit_rebates
                    .values()
                    .map(FeeCreditRebate::public_record),
            ),
            privacy_redaction_root: merkle_records(
                "HASHRATE-FORWARD-AMM-REDACTIONS",
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            nullifier_root: merkle_records("HASHRATE-FORWARD-AMM-NULLIFIERS", nullifier_records),
            counters_root: record_root("HASHRATE-FORWARD-AMM-COUNTERS", &counters.public_record()),
            state_root: String::new(),
        };
        roots.state_root = record_root("HASHRATE-FORWARD-AMM-ROOTS", &roots.public_record());
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    record_root("HASHRATE-FORWARD-AMM-STATE", record)
}

fn demo_pool(config: &Config, pool_id: &str, kind: PoolKind, salt: &str) -> AmmPool {
    AmmPool {
        pool_id: pool_id.to_string(),
        kind,
        base_note_class: "sha256-forward-ths-epoch-note".to_string(),
        quote_token: config.quote_token.clone(),
        sealed_base_reserve_root: demo_root("sealed-base-reserve", salt),
        sealed_quote_reserve_root: demo_root("sealed-quote-reserve", salt),
        lp_commitment_root: demo_root("lp-commitments", salt),
        fee_bps: config.pool_fee_bps,
        invariant_root: demo_root("constant-product-invariant", salt),
        active: true,
    }
}

fn demo_bucket(epoch: u64, salt: &str) -> EpochProductionBucket {
    EpochProductionBucket {
        bucket_id: format!("devnet-epoch-production-bucket-{epoch}-{salt}"),
        epoch,
        miner_set_root: demo_root("miner-set", salt),
        production_commitment_root: demo_root("production-commitment", salt),
        expected_hashrate_ths: 42_000,
        observed_hashrate_ths: 41_650,
        oracle_aggregate_root: demo_root("oracle-aggregate", salt),
    }
}

fn demo_note(
    pool_id: &str,
    miner_id: &str,
    issue_epoch: u64,
    maturity_epochs: u64,
    salt: &str,
) -> HashrateForwardNote {
    HashrateForwardNote {
        note_id: format!("devnet-hashrate-forward-note-{salt}"),
        miner_id: miner_id.to_string(),
        pool_id: pool_id.to_string(),
        commitment_root: demo_root("forward-note-commitment", salt),
        hashrate_ths: 12_500,
        strike_quote_units: 1_850_000_000,
        issue_epoch,
        maturity_epoch: issue_epoch + maturity_epochs,
        status: ForwardStatus::Funded,
        encrypted_terms_root: demo_root("encrypted-forward-terms", salt),
        nullifier_commitment: demo_root("forward-nullifier", salt),
    }
}

fn demo_attestation(
    note: &HashrateForwardNote,
    bucket: &EpochProductionBucket,
    issued_height: u64,
    salt: &str,
) -> MinerOracleAttestation {
    MinerOracleAttestation {
        attestation_id: format!("devnet-miner-oracle-attestation-{salt}"),
        kind: AttestationKind::OracleProduction,
        miner_id: note.miner_id.clone(),
        oracle_id: "devnet-oracle-committee-alpha".to_string(),
        epoch: bucket.epoch,
        production_bucket_id: bucket.bucket_id.clone(),
        committed_hashrate_ths: note.hashrate_ths,
        observed_hashrate_ths: 12_375,
        pq_signature_root: demo_root("pq-oracle-signature", salt),
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        issued_height,
    }
}

fn demo_liquidity(pool: &AmmPool, owner: &str, salt: &str) -> SealedLiquidityPosition {
    SealedLiquidityPosition {
        position_id: format!("devnet-sealed-liquidity-{salt}"),
        pool_id: pool.pool_id.clone(),
        owner_commitment: demo_root(owner, salt),
        sealed_base_units: 16_000,
        sealed_quote_units: DEFAULT_MIN_SEALED_LIQUIDITY_UNITS + 5_000_000_000,
        lp_note_root: demo_root("lp-note", salt),
        locked_until_epoch: 54,
    }
}

fn demo_settlement(
    config: &Config,
    note: &HashrateForwardNote,
    pool: &AmmPool,
    salt: &str,
) -> MaturitySettlement {
    let paid = haircut_amount(note.strike_quote_units, config.default_haircut_bps);
    MaturitySettlement {
        settlement_id: format!("devnet-maturity-settlement-{salt}"),
        note_id: note.note_id.clone(),
        pool_id: pool.pool_id.clone(),
        maturity_epoch: note.maturity_epoch,
        delivered_hashrate_ths: 12_050,
        due_quote_units: note.strike_quote_units,
        paid_quote_units: paid,
        haircut_bps: config.default_haircut_bps,
        status: SettlementStatus::HaircutApplied,
        receipt_root: demo_root("maturity-settlement-receipt", salt),
    }
}

fn demo_rebate(config: &Config, settlement: &MaturitySettlement, salt: &str) -> FeeCreditRebate {
    FeeCreditRebate {
        rebate_id: format!("devnet-fee-credit-rebate-{salt}"),
        settlement_id: settlement.settlement_id.clone(),
        recipient_commitment: demo_root("rebate-recipient", salt),
        fee_credit_units: settlement
            .paid_quote_units
            .saturating_mul(config.rebate_bps as u128)
            / MAX_BPS as u128,
        rebate_bps: config.rebate_bps,
        expires_height: DEVNET_HEIGHT + config.settlement_window_blocks,
    }
}

fn demo_redaction(
    record_kind: &str,
    record_id: &str,
    privacy_set_size: u64,
    salt: &str,
) -> PrivacyRedaction {
    PrivacyRedaction {
        redaction_id: format!("devnet-privacy-redaction-{record_kind}-{salt}"),
        record_kind: record_kind.to_string(),
        record_id: record_id.to_string(),
        redacted_fields: vec![
            "miner_id".to_string(),
            "owner_commitment".to_string(),
            "encrypted_terms_root".to_string(),
        ],
        disclosure_root: demo_root("selective-disclosure", salt),
        privacy_set_size,
    }
}

fn haircut_amount(amount: u128, haircut_bps: u64) -> u128 {
    amount.saturating_mul((MAX_BPS - haircut_bps) as u128) / MAX_BPS as u128
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    require(!key.trim().is_empty(), "id required")?;
    require(!map.contains_key(&key), "duplicate id")?;
    map.insert(key, value);
    Ok(())
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn redacted_label(value: &str) -> String {
    record_root(
        "HASHRATE-FORWARD-AMM-REDACTED-LABEL",
        &json!({ "value": value }),
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    record_root(
        "HASHRATE-FORWARD-AMM-DEMO-FIXTURE",
        &json!({ "label": label, "salt": salt }),
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::from(
            serde_json::to_string(record).expect("canonical json record"),
        )],
    )
}

fn merkle_records<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records
        .into_iter()
        .map(|record| record_root(domain, &record))
        .collect::<Vec<_>>();
    merkle_root(domain, leaves)
}
