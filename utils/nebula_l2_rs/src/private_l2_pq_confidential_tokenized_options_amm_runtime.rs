use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_OPTIONS_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-options-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_OPTIONS_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-options-amm-oracle-v1";
pub const CONFIDENTIAL_OPTION_SERIES_SUITE: &str =
    "tokenized-confidential-options-amm-series-root-v1";
pub const POOL_GREEKS_SUITE: &str = "confidential-options-amm-pool-greeks-root-v1";
pub const SEALED_EXERCISE_INTENT_SUITE: &str =
    "sealed-confidential-options-amm-exercise-intent-root-v1";
pub const PREMIUM_SETTLEMENT_SUITE: &str = "confidential-options-amm-premium-settlement-root-v1";
pub const LIQUIDITY_VAULT_SUITE: &str = "confidential-options-amm-liquidity-vault-root-v1";
pub const LOW_FEE_EXERCISE_REBATE_SUITE: &str =
    "low-fee-confidential-options-amm-exercise-rebate-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-tokenized-options-amm-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_412_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_026_000;
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-options-amm-devnet";
pub const DEVNET_AMM_ID: &str = "private-l2-pq-confidential-tokenized-options-amm-devnet";
pub const DEVNET_UNDERLYING_ASSET_ID: &str = "pxmr-private-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-private-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 3;
pub const DEFAULT_EXERCISE_QUORUM: u16 = 2;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_EXERCISE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_EXERCISE_FEE_BPS: u64 = 7;
pub const DEFAULT_REBATE_BPS: u64 = 2_500;
pub const DEFAULT_MIN_VAULT_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_MAX_POOL_DELTA_ABS_BPS: i64 = 6_500;
pub const DEFAULT_MAX_POOL_GAMMA_BPS: u64 = 1_200;
pub const DEFAULT_MAX_SERIES: usize = 1_024;
pub const DEFAULT_MAX_EXERCISE_INTENTS: usize = 8_192;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    Call,
    Put,
    BinaryCall,
    BinaryPut,
    BarrierCall,
    BarrierPut,
}

impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::BinaryCall => "binary_call",
            Self::BinaryPut => "binary_put",
            Self::BarrierCall => "barrier_call",
            Self::BarrierPut => "barrier_put",
        }
    }

    pub fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::BinaryCall | Self::BarrierCall)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStyle {
    European,
    American,
    Bermudan,
}

impl OptionStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::European => "european",
            Self::American => "american",
            Self::Bermudan => "bermudan",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesStatus {
    Draft,
    Open,
    Paused,
    Expired,
    Exercising,
    Settled,
    Retired,
}

impl SeriesStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Exercising => "exercising",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseIntentStatus {
    Sealed,
    OracleAttested,
    PremiumNetting,
    Queued,
    Exercised,
    Rebated,
    Rejected,
    Expired,
}

impl ExerciseIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::OracleAttested => "oracle_attested",
            Self::PremiumNetting => "premium_netting",
            Self::Queued => "queued",
            Self::Exercised => "exercised",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
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
    Open,
    Netting,
    Settled,
    PartiallySettled,
    Quarantined,
    Rejected,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Netting => "netting",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_oracle_attestation_suite: String,
    pub amm_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub underlying_asset_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub exercise_quorum: u16,
    pub attestation_ttl_blocks: u64,
    pub exercise_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_exercise_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_vault_coverage_bps: u64,
    pub max_pool_delta_abs_bps: i64,
    pub max_pool_gamma_bps: u64,
    pub max_series: usize,
    pub max_exercise_intents: usize,
    pub require_confidential_series: bool,
    pub require_pq_oracle_attestations: bool,
    pub allow_low_fee_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_oracle_attestation_suite: PQ_ORACLE_ATTESTATION_SUITE.to_string(),
            amm_id: DEVNET_AMM_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            underlying_asset_id: DEVNET_UNDERLYING_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            exercise_quorum: DEFAULT_EXERCISE_QUORUM,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            exercise_ttl_blocks: DEFAULT_EXERCISE_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_exercise_fee_bps: DEFAULT_TARGET_EXERCISE_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_vault_coverage_bps: DEFAULT_MIN_VAULT_COVERAGE_BPS,
            max_pool_delta_abs_bps: DEFAULT_MAX_POOL_DELTA_ABS_BPS,
            max_pool_gamma_bps: DEFAULT_MAX_POOL_GAMMA_BPS,
            max_series: DEFAULT_MAX_SERIES,
            max_exercise_intents: DEFAULT_MAX_EXERCISE_INTENTS,
            require_confidential_series: true,
            require_pq_oracle_attestations: true,
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

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_series_index: u64,
    pub next_greeks_index: u64,
    pub next_intent_index: u64,
    pub next_attestation_index: u64,
    pub next_settlement_index: u64,
    pub next_vault_index: u64,
    pub next_rebate_index: u64,
    pub next_public_record_index: u64,
    pub total_series: u64,
    pub open_series: u64,
    pub sealed_exercise_intents: u64,
    pub oracle_attestations: u64,
    pub premium_settlements: u64,
    pub exercised_intents: u64,
    pub liquidity_vaults: u64,
    pub rebates_issued: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_series_index: 1,
            next_greeks_index: 1,
            next_intent_index: 1,
            next_attestation_index: 1,
            next_settlement_index: 1,
            next_vault_index: 1,
            next_rebate_index: 1,
            next_public_record_index: 1,
            total_series: 0,
            open_series: 0,
            sealed_exercise_intents: 0,
            oracle_attestations: 0,
            premium_settlements: 0,
            exercised_intents: 0,
            liquidity_vaults: 0,
            rebates_issued: 0,
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
    pub option_series_root: String,
    pub pool_greeks_root: String,
    pub sealed_exercise_intents_root: String,
    pub pq_oracle_attestations_root: String,
    pub premium_settlements_root: String,
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
pub struct ConfidentialOptionSeries {
    pub series_id: String,
    pub pool_id: String,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub underlying_asset_id: String,
    pub quote_asset_id: String,
    pub strike_price_micro_units: u64,
    pub expiry_l2_height: u64,
    pub barrier_price_micro_units: Option<u64>,
    pub confidential_terms_root: String,
    pub token_supply_commitment: String,
    pub inventory_commitment: String,
    pub premium_curve_root: String,
    pub status: SeriesStatus,
}

impl ConfidentialOptionSeries {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PoolGreeks {
    pub greeks_id: String,
    pub pool_id: String,
    pub series_ids: Vec<String>,
    pub delta_bps: i64,
    pub gamma_bps: u64,
    pub vega_bps: u64,
    pub theta_bps: i64,
    pub rho_bps: i64,
    pub utilization_bps: u64,
    pub net_exposure_micro_units: i128,
    pub risk_proof_root: String,
    pub updated_at_l2_height: u64,
}

impl PoolGreeks {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedExerciseIntent {
    pub intent_id: String,
    pub series_id: String,
    pub owner_commitment: String,
    pub position_note_commitment: String,
    pub nullifier: String,
    pub encrypted_exercise_payload_root: String,
    pub max_fee_bps: u64,
    pub sealed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: ExerciseIntentStatus,
}

impl SealedExerciseIntent {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub series_id: String,
    pub intent_id: Option<String>,
    pub oracle_commitment: String,
    pub mark_price_micro_units: u64,
    pub implied_volatility_bps: u64,
    pub confidence_bps: u64,
    pub oracle_round: u64,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub verdict: AttestationVerdict,
    pub signature_root: String,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PremiumSettlement {
    pub settlement_id: String,
    pub series_id: String,
    pub intent_ids: Vec<String>,
    pub premium_asset_id: String,
    pub gross_premium_micro_units: u128,
    pub net_premium_micro_units: u128,
    pub fee_micro_units: u64,
    pub settlement_proof_root: String,
    pub status: SettlementStatus,
    pub settled_at_l2_height: u64,
}

impl PremiumSettlement {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityVault {
    pub vault_id: String,
    pub pool_id: String,
    pub operator_commitment: String,
    pub collateral_asset_id: String,
    pub collateral_commitment: String,
    pub coverage_bps: u64,
    pub fee_budget_micro_units: u64,
    pub inventory_root: String,
    pub active: bool,
}

impl LiquidityVault {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeExerciseRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub settlement_id: String,
    pub recipient_commitment: String,
    pub fee_asset_id: String,
    pub charged_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_micro_units: u64,
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
    pub public_payload: Value,
    pub payload_root: String,
    pub emitted_at_l2_height: u64,
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
    pub option_series: BTreeMap<String, ConfidentialOptionSeries>,
    pub pool_greeks: BTreeMap<String, PoolGreeks>,
    pub sealed_exercise_intents: BTreeMap<String, SealedExerciseIntent>,
    pub pq_oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub premium_settlements: BTreeMap<String, PremiumSettlement>,
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
            option_series: BTreeMap::new(),
            pool_greeks: BTreeMap::new(),
            sealed_exercise_intents: BTreeMap::new(),
            pq_oracle_attestations: BTreeMap::new(),
            premium_settlements: BTreeMap::new(),
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
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "amm_id": self.config.amm_id,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
            "hash_suite": HASH_SUITE,
            "pq_oracle_attestation_suite": PQ_ORACLE_ATTESTATION_SUITE,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "operator_safe_public_records": self
                .public_records
                .values()
                .map(DeterministicPublicRecord::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn insert_option_series(
        &mut self,
        mut series: ConfidentialOptionSeries,
    ) -> PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<String> {
        require(
            self.option_series.len() < self.config.max_series,
            "series limit reached",
        )?;
        require_non_empty("pool_id", &series.pool_id)?;
        require_root("confidential_terms_root", &series.confidential_terms_root)?;
        require_root("token_supply_commitment", &series.token_supply_commitment)?;
        require_root("inventory_commitment", &series.inventory_commitment)?;
        require_root("premium_curve_root", &series.premium_curve_root)?;
        if series.series_id.trim().is_empty() {
            series.series_id = deterministic_id(
                "option-series",
                &[
                    HashPart::Str(&series.pool_id),
                    HashPart::Str(series.option_kind.as_str()),
                    HashPart::U64(series.strike_price_micro_units),
                    HashPart::U64(series.expiry_l2_height),
                    HashPart::U64(self.counters.next_series_index),
                ],
            );
        }
        let series_id = series.series_id.clone();
        require(
            !self.option_series.contains_key(&series_id),
            "duplicate series",
        )?;
        if series.status == SeriesStatus::Open {
            self.counters.open_series = self.counters.open_series.saturating_add(1);
        }
        self.counters.total_series = self.counters.total_series.saturating_add(1);
        self.counters.next_series_index = self.counters.next_series_index.saturating_add(1);
        self.option_series.insert(series_id.clone(), series.clone());
        self.emit_public_record("option_series", &series_id, series.public_record());
        self.refresh_roots();
        Ok(series_id)
    }

    pub fn upsert_pool_greeks(
        &mut self,
        mut greeks: PoolGreeks,
    ) -> PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<String> {
        require_non_empty("pool_id", &greeks.pool_id)?;
        require(
            unique_strings(&greeks.series_ids),
            "series ids must be unique",
        )?;
        require(
            greeks.delta_bps.abs() <= self.config.max_pool_delta_abs_bps,
            "pool delta exceeds configured bound",
        )?;
        require(
            greeks.gamma_bps <= self.config.max_pool_gamma_bps,
            "pool gamma exceeds configured bound",
        )?;
        require(
            greeks.utilization_bps <= MAX_BPS,
            "utilization exceeds MAX_BPS",
        )?;
        require_root("risk_proof_root", &greeks.risk_proof_root)?;
        if greeks.greeks_id.trim().is_empty() {
            greeks.greeks_id = deterministic_id(
                "pool-greeks",
                &[
                    HashPart::Str(&greeks.pool_id),
                    HashPart::U64(greeks.updated_at_l2_height),
                    HashPart::U64(self.counters.next_greeks_index),
                ],
            );
        }
        let greeks_id = greeks.greeks_id.clone();
        self.pool_greeks.insert(greeks_id.clone(), greeks.clone());
        self.counters.next_greeks_index = self.counters.next_greeks_index.saturating_add(1);
        self.emit_public_record("pool_greeks", &greeks_id, greeks.public_record());
        self.refresh_roots();
        Ok(greeks_id)
    }

    pub fn seal_exercise_intent(
        &mut self,
        mut intent: SealedExerciseIntent,
    ) -> PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<String> {
        require(
            self.sealed_exercise_intents.len() < self.config.max_exercise_intents,
            "exercise intent limit reached",
        )?;
        require(
            self.option_series.contains_key(&intent.series_id),
            "unknown option series",
        )?;
        require_root("owner_commitment", &intent.owner_commitment)?;
        require_root("position_note_commitment", &intent.position_note_commitment)?;
        require_root("nullifier", &intent.nullifier)?;
        require(
            !self.consumed_nullifiers.contains(&intent.nullifier),
            "duplicate nullifier",
        )?;
        require_root(
            "encrypted_exercise_payload_root",
            &intent.encrypted_exercise_payload_root,
        )?;
        require(
            intent.max_fee_bps <= self.config.max_user_fee_bps,
            "fee too high",
        )?;
        require(
            intent.expires_at_l2_height > intent.sealed_at_l2_height,
            "intent expiry must be after seal height",
        )?;
        if intent.intent_id.trim().is_empty() {
            intent.intent_id = deterministic_id(
                "exercise-intent",
                &[
                    HashPart::Str(&intent.series_id),
                    HashPart::Str(&intent.nullifier),
                    HashPart::U64(self.counters.next_intent_index),
                ],
            );
        }
        let intent_id = intent.intent_id.clone();
        self.consumed_nullifiers.insert(intent.nullifier.clone());
        self.sealed_exercise_intents
            .insert(intent_id.clone(), intent.clone());
        self.counters.sealed_exercise_intents =
            self.counters.sealed_exercise_intents.saturating_add(1);
        self.counters.next_intent_index = self.counters.next_intent_index.saturating_add(1);
        self.emit_public_record("sealed_exercise_intent", &intent_id, intent.public_record());
        self.refresh_roots();
        Ok(intent_id)
    }

    pub fn record_oracle_attestation(
        &mut self,
        mut attestation: PqOracleAttestation,
    ) -> PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<String> {
        require(
            self.option_series.contains_key(&attestation.series_id),
            "unknown option series",
        )?;
        require_root("oracle_commitment", &attestation.oracle_commitment)?;
        require(
            attestation.confidence_bps <= MAX_BPS,
            "confidence exceeds MAX_BPS",
        )?;
        require_root("signature_root", &attestation.signature_root)?;
        require(
            attestation.expires_at_l2_height > attestation.attested_at_l2_height,
            "attestation expiry must be after attested height",
        )?;
        if let Some(intent_id) = &attestation.intent_id {
            require(
                self.sealed_exercise_intents.contains_key(intent_id),
                "unknown exercise intent",
            )?;
        }
        if attestation.attestation_id.trim().is_empty() {
            attestation.attestation_id = deterministic_id(
                "oracle-attestation",
                &[
                    HashPart::Str(&attestation.series_id),
                    HashPart::U64(attestation.oracle_round),
                    HashPart::U64(self.counters.next_attestation_index),
                ],
            );
        }
        let attestation_id = attestation.attestation_id.clone();
        self.pq_oracle_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.counters.oracle_attestations = self.counters.oracle_attestations.saturating_add(1);
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.emit_public_record(
            "pq_oracle_attestation",
            &attestation_id,
            attestation.public_record(),
        );
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_premium(
        &mut self,
        mut settlement: PremiumSettlement,
    ) -> PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<String> {
        require(
            self.option_series.contains_key(&settlement.series_id),
            "unknown option series",
        )?;
        require(
            !settlement.intent_ids.is_empty(),
            "settlement requires intents",
        )?;
        require(
            unique_strings(&settlement.intent_ids),
            "intent ids must be unique",
        )?;
        for intent_id in &settlement.intent_ids {
            require(
                self.sealed_exercise_intents.contains_key(intent_id),
                "unknown exercise intent in settlement",
            )?;
        }
        require_root("settlement_proof_root", &settlement.settlement_proof_root)?;
        require(
            settlement.net_premium_micro_units <= settlement.gross_premium_micro_units,
            "net premium exceeds gross premium",
        )?;
        if settlement.settlement_id.trim().is_empty() {
            settlement.settlement_id = deterministic_id(
                "premium-settlement",
                &[
                    HashPart::Str(&settlement.series_id),
                    HashPart::U64(settlement.settled_at_l2_height),
                    HashPart::U64(self.counters.next_settlement_index),
                ],
            );
        }
        let settlement_id = settlement.settlement_id.clone();
        if settlement.status == SettlementStatus::Settled {
            self.counters.exercised_intents = self
                .counters
                .exercised_intents
                .saturating_add(settlement.intent_ids.len() as u64);
        }
        self.premium_settlements
            .insert(settlement_id.clone(), settlement.clone());
        self.counters.premium_settlements = self.counters.premium_settlements.saturating_add(1);
        self.counters.next_settlement_index = self.counters.next_settlement_index.saturating_add(1);
        self.emit_public_record(
            "premium_settlement",
            &settlement_id,
            settlement.public_record(),
        );
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn upsert_liquidity_vault(
        &mut self,
        mut vault: LiquidityVault,
    ) -> PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<String> {
        require_non_empty("pool_id", &vault.pool_id)?;
        require_root("operator_commitment", &vault.operator_commitment)?;
        require_root("collateral_commitment", &vault.collateral_commitment)?;
        require_root("inventory_root", &vault.inventory_root)?;
        require(
            vault.coverage_bps >= self.config.min_vault_coverage_bps,
            "vault coverage below minimum",
        )?;
        if vault.vault_id.trim().is_empty() {
            vault.vault_id = deterministic_id(
                "liquidity-vault",
                &[
                    HashPart::Str(&vault.pool_id),
                    HashPart::Str(&vault.operator_commitment),
                    HashPart::U64(self.counters.next_vault_index),
                ],
            );
        }
        let vault_id = vault.vault_id.clone();
        let is_new = !self.liquidity_vaults.contains_key(&vault_id);
        self.liquidity_vaults
            .insert(vault_id.clone(), vault.clone());
        if is_new {
            self.counters.liquidity_vaults = self.counters.liquidity_vaults.saturating_add(1);
            self.counters.next_vault_index = self.counters.next_vault_index.saturating_add(1);
        }
        self.emit_public_record("liquidity_vault", &vault_id, vault.public_record());
        self.refresh_roots();
        Ok(vault_id)
    }

    pub fn issue_low_fee_rebate(
        &mut self,
        mut rebate: LowFeeExerciseRebate,
    ) -> PrivateL2PqConfidentialTokenizedOptionsAmmRuntimeResult<String> {
        require(self.config.allow_low_fee_rebates, "rebates disabled")?;
        require(
            self.sealed_exercise_intents.contains_key(&rebate.intent_id),
            "unknown exercise intent",
        )?;
        require(
            self.premium_settlements.contains_key(&rebate.settlement_id),
            "unknown premium settlement",
        )?;
        require_root("recipient_commitment", &rebate.recipient_commitment)?;
        require(
            rebate.charged_fee_bps <= self.config.max_user_fee_bps,
            "charged fee exceeds max",
        )?;
        require(
            rebate.target_fee_bps <= rebate.charged_fee_bps,
            "target fee exceeds charged fee",
        )?;
        if rebate.rebate_id.trim().is_empty() {
            rebate.rebate_id = deterministic_id(
                "exercise-rebate",
                &[
                    HashPart::Str(&rebate.intent_id),
                    HashPart::Str(&rebate.settlement_id),
                    HashPart::U64(self.counters.next_rebate_index),
                ],
            );
        }
        let rebate_id = rebate.rebate_id.clone();
        self.rebates.insert(rebate_id.clone(), rebate.clone());
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.counters.next_rebate_index = self.counters.next_rebate_index.saturating_add(1);
        self.emit_public_record(
            "low_fee_exercise_rebate",
            &rebate_id,
            rebate.public_record(),
        );
        self.refresh_roots();
        Ok(rebate_id)
    }

    fn emit_public_record(&mut self, record_kind: &str, subject_id: &str, public_payload: Value) {
        let record_id = deterministic_id(
            "public-record",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.counters.next_public_record_index),
            ],
        );
        let payload_root = payload_root("PUBLIC_RECORD_PAYLOAD", &public_payload);
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                record_kind: record_kind.to_string(),
                subject_id: subject_id.to_string(),
                public_payload,
                payload_root,
                emitted_at_l2_height: self.config.l2_height,
            },
        );
        self.counters.next_public_record_index =
            self.counters.next_public_record_index.saturating_add(1);
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.root();
        self.roots.counters_root = self.counters.root();
        self.roots.option_series_root = merkle_root(
            CONFIDENTIAL_OPTION_SERIES_SUITE,
            &self
                .option_series
                .values()
                .map(ConfidentialOptionSeries::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.pool_greeks_root = merkle_root(
            POOL_GREEKS_SUITE,
            &self
                .pool_greeks
                .values()
                .map(PoolGreeks::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.sealed_exercise_intents_root = merkle_root(
            SEALED_EXERCISE_INTENT_SUITE,
            &self
                .sealed_exercise_intents
                .values()
                .map(SealedExerciseIntent::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.pq_oracle_attestations_root = merkle_root(
            PQ_ORACLE_ATTESTATION_SUITE,
            &self
                .pq_oracle_attestations
                .values()
                .map(PqOracleAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.premium_settlements_root = merkle_root(
            PREMIUM_SETTLEMENT_SUITE,
            &self
                .premium_settlements
                .values()
                .map(PremiumSettlement::public_record)
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
            LOW_FEE_EXERCISE_REBATE_SUITE,
            &self
                .rebates
                .values()
                .map(LowFeeExerciseRebate::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = merkle_root(
            "confidential-options-amm-consumed-nullifier-root-v1",
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
            "nebula-private-l2-pq-confidential-tokenized-options-amm-state-root-v1",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.config.l2_height),
                HashPart::U64(self.config.monero_height),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.option_series_root),
                HashPart::Str(&self.roots.pool_greeks_root),
                HashPart::Str(&self.roots.sealed_exercise_intents_root),
                HashPart::Str(&self.roots.pq_oracle_attestations_root),
                HashPart::Str(&self.roots.premium_settlements_root),
                HashPart::Str(&self.roots.liquidity_vaults_root),
                HashPart::Str(&self.roots.rebates_root),
                HashPart::Str(&self.roots.nullifier_root),
                HashPart::Str(&self.roots.public_records_root),
            ],
            32,
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let pool_id = "options-amm-pxmr-dusd-30d-devnet".to_string();
    let series_id = state
        .insert_option_series(ConfidentialOptionSeries {
            series_id: String::new(),
            pool_id: pool_id.clone(),
            option_kind: OptionKind::Call,
            option_style: OptionStyle::European,
            underlying_asset_id: DEVNET_UNDERLYING_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            strike_price_micro_units: 175_000_000,
            expiry_l2_height: DEVNET_L2_HEIGHT + 21_600,
            barrier_price_micro_units: None,
            confidential_terms_root: hex_root("series-terms", 1),
            token_supply_commitment: hex_root("series-supply", 1),
            inventory_commitment: hex_root("series-inventory", 1),
            premium_curve_root: hex_root("series-premium-curve", 1),
            status: SeriesStatus::Open,
        })
        .expect("demo option series");
    state
        .upsert_liquidity_vault(LiquidityVault {
            vault_id: String::new(),
            pool_id: pool_id.clone(),
            operator_commitment: hex_root("vault-operator", 1),
            collateral_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            collateral_commitment: hex_root("vault-collateral", 1),
            coverage_bps: 11_250,
            fee_budget_micro_units: 250_000_000,
            inventory_root: hex_root("vault-inventory", 1),
            active: true,
        })
        .expect("demo liquidity vault");
    state
        .upsert_pool_greeks(PoolGreeks {
            greeks_id: String::new(),
            pool_id: pool_id.clone(),
            series_ids: vec![series_id.clone()],
            delta_bps: 3_100,
            gamma_bps: 420,
            vega_bps: 860,
            theta_bps: -74,
            rho_bps: 28,
            utilization_bps: 6_400,
            net_exposure_micro_units: 12_500_000_000,
            risk_proof_root: hex_root("pool-greeks-proof", 1),
            updated_at_l2_height: DEVNET_L2_HEIGHT,
        })
        .expect("demo pool greeks");
    let intent_id = state
        .seal_exercise_intent(SealedExerciseIntent {
            intent_id: String::new(),
            series_id: series_id.clone(),
            owner_commitment: hex_root("intent-owner", 1),
            position_note_commitment: hex_root("intent-position-note", 1),
            nullifier: hex_root("intent-nullifier", 1),
            encrypted_exercise_payload_root: hex_root("intent-payload", 1),
            max_fee_bps: 12,
            sealed_at_l2_height: DEVNET_L2_HEIGHT + 4,
            expires_at_l2_height: DEVNET_L2_HEIGHT + DEFAULT_EXERCISE_TTL_BLOCKS,
            status: ExerciseIntentStatus::Queued,
        })
        .expect("demo exercise intent");
    state
        .record_oracle_attestation(PqOracleAttestation {
            attestation_id: String::new(),
            series_id: series_id.clone(),
            intent_id: Some(intent_id.clone()),
            oracle_commitment: hex_root("oracle-committee", 1),
            mark_price_micro_units: 184_250_000,
            implied_volatility_bps: 6_850,
            confidence_bps: 9_850,
            oracle_round: 42,
            attested_at_l2_height: DEVNET_L2_HEIGHT + 5,
            expires_at_l2_height: DEVNET_L2_HEIGHT + 5 + DEFAULT_ATTESTATION_TTL_BLOCKS,
            verdict: AttestationVerdict::Accept,
            signature_root: hex_root("oracle-signature", 1),
        })
        .expect("demo oracle attestation");
    let settlement_id = state
        .settle_premium(PremiumSettlement {
            settlement_id: String::new(),
            series_id,
            intent_ids: vec![intent_id.clone()],
            premium_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            gross_premium_micro_units: 925_000_000,
            net_premium_micro_units: 923_890_000,
            fee_micro_units: 1_110_000,
            settlement_proof_root: hex_root("premium-settlement-proof", 1),
            status: SettlementStatus::Settled,
            settled_at_l2_height: DEVNET_L2_HEIGHT + 8,
        })
        .expect("demo premium settlement");
    state
        .issue_low_fee_rebate(LowFeeExerciseRebate {
            rebate_id: String::new(),
            intent_id,
            settlement_id,
            recipient_commitment: hex_root("rebate-recipient", 1),
            fee_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            charged_fee_bps: 12,
            target_fee_bps: DEFAULT_TARGET_EXERCISE_FEE_BPS,
            rebate_micro_units: 462_500,
            issued_at_l2_height: DEVNET_L2_HEIGHT + 9,
        })
        .expect("demo rebate");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{domain}:{}", domain_hash(domain, parts, 16))
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-options-amm-payload",
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
        "private-l2-pq-confidential-tokenized-options-amm-demo-root",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}
