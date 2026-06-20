use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedRenewableEnergyCreditAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-renewable-energy-credit-amm-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_HASH_SUITE:
    &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-rec-amm-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_COMMITMENT_SUITE: &str =
    "pedersen-compatible-range-commitment+view-tags+nullifier-fence-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_DEVNET_HEIGHT:
    u64 = 1_448_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_MAX_BPS: u64 =
    10_000;
const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
const DEFAULT_BATCH_PRIVACY_SET: u64 = 524_288;
const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
const DEFAULT_ORACLE_QUORUM: u16 = 5;
const DEFAULT_MAX_POOL_WEIGHT_BPS: u64 = 1_600;
const DEFAULT_MAX_DAILY_VOLUME_BPS: u64 = 2_500;
const DEFAULT_MIN_LIQUIDITY_USD: u64 = 25_000_000;
const DEFAULT_MATURITY_GRACE_BLOCKS: u64 = 43_200;
const DEFAULT_RETIREMENT_TTL_BLOCKS: u64 = 21_600;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnergySource {
    Solar,
    Wind,
    Hydro,
    Geothermal,
    Biomass,
    StorageBacked,
    MixedRenewable,
    Custom,
}

impl EnergySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Solar => "solar",
            Self::Wind => "wind",
            Self::Hydro => "hydro",
            Self::Geothermal => "geothermal",
            Self::Biomass => "biomass",
            Self::StorageBacked => "storage_backed",
            Self::MixedRenewable => "mixed_renewable",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VintageStatus {
    Draft,
    Attesting,
    Active,
    Guarded,
    Maturing,
    SettlementOnly,
    Retired,
    Revoked,
}

impl VintageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Attesting => "attesting",
            Self::Active => "active",
            Self::Guarded => "guarded",
            Self::Maturing => "maturing",
            Self::SettlementOnly => "settlement_only",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }
    pub fn tradable(self) -> bool {
        matches!(self, Self::Active | Self::Guarded | Self::Maturing)
    }
    pub fn accepts_retirement(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Guarded | Self::Maturing | Self::SettlementOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Bootstrapping,
    Active,
    Guarded,
    SwapOnly,
    WithdrawOnly,
    SettlementOnly,
    Paused,
    Closed,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::Guarded => "guarded",
            Self::SwapOnly => "swap_only",
            Self::WithdrawOnly => "withdraw_only",
            Self::SettlementOnly => "settlement_only",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }
    pub fn can_swap(self) -> bool {
        matches!(self, Self::Active | Self::Guarded | Self::SwapOnly)
    }
    pub fn can_add_liquidity(self) -> bool {
        matches!(self, Self::Bootstrapping | Self::Active | Self::Guarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    QuorumPending,
    QuorumMet,
    Challenged,
    Accepted,
    Expired,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::QuorumPending => "quorum_pending",
            Self::QuorumMet => "quorum_met",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn accepted(self) -> bool {
        matches!(self, Self::QuorumMet | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementStatus {
    Committed,
    Batched,
    Proved,
    Settled,
    Cancelled,
}

impl RetirementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Batched => "batched",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Scheduled,
    Netting,
    OracleFinal,
    Settled,
    Disputed,
    Expired,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Netting => "netting",
            Self::OracleFinal => "oracle_final",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub commitment_suite: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub oracle_quorum: u16,
    pub max_pool_weight_bps: u64,
    pub max_daily_volume_bps: u64,
    pub min_liquidity_usd: u64,
    pub maturity_grace_blocks: u64,
    pub retirement_ttl_blocks: u64,
    pub low_fee_lane: String,
    pub privacy_redaction_policy: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_PQ_SUITE.to_string(),
            commitment_suite: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_COMMITMENT_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            max_pool_weight_bps: DEFAULT_MAX_POOL_WEIGHT_BPS,
            max_daily_volume_bps: DEFAULT_MAX_DAILY_VOLUME_BPS,
            min_liquidity_usd: DEFAULT_MIN_LIQUIDITY_USD,
            maturity_grace_blocks: DEFAULT_MATURITY_GRACE_BLOCKS,
            retirement_ttl_blocks: DEFAULT_RETIREMENT_TTL_BLOCKS,
            low_fee_lane: "private-l2-rec-amm-low-fee-devnet".to_string(),
            privacy_redaction_policy: "roots-only-amount-band-region-source-v1".to_string(),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"private_l2_pq_confidential_tokenized_renewable_energy_credit_amm_config","protocol_version":self.protocol_version,"schema_version":PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_SCHEMA_VERSION,"chain_id":self.chain_id,"hash_suite":self.hash_suite,"pq_suite":self.pq_suite,"commitment_suite":self.commitment_suite,"min_privacy_set_size":self.min_privacy_set_size,"batch_privacy_set_size":self.batch_privacy_set_size,"min_pq_security_bits":self.min_pq_security_bits,"max_user_fee_bps":self.max_user_fee_bps,"target_rebate_bps":self.target_rebate_bps,"oracle_quorum":self.oracle_quorum,"max_pool_weight_bps":self.max_pool_weight_bps,"max_daily_volume_bps":self.max_daily_volume_bps,"min_liquidity_usd":self.min_liquidity_usd,"maturity_grace_blocks":self.maturity_grace_blocks,"retirement_ttl_blocks":self.retirement_ttl_blocks,"low_fee_lane":self.low_fee_lane,"privacy_redaction_policy":self.privacy_redaction_policy})
    }
    pub fn state_root(&self) -> String {
        root_from_record("REC-AMM-CONFIG", &self.public_record())
    }
    pub fn validate(&self) -> Result<()> {
        require(self.min_privacy_set_size >= 1024, "privacy set too small")?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below policy")?;
        require(
            self.max_user_fee_bps <= 100,
            "fee cap exceeds low-fee policy",
        )?;
        require(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate exceeds fee cap",
        )?;
        require(self.oracle_quorum >= 3, "oracle quorum too small")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vintages: u64,
    pub pools: u64,
    pub attestations: u64,
    pub retirements: u64,
    pub settlements: u64,
    pub risk_haircuts: u64,
    pub guardrails: u64,
    pub rebates: u64,
    pub privacy_redactions: u64,
    pub public_records: u64,
    pub swaps: u64,
    pub liquidity_events: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({"kind":"private_l2_pq_confidential_rec_amm_counters","vintages":self.vintages,"pools":self.pools,"attestations":self.attestations,"retirements":self.retirements,"settlements":self.settlements,"risk_haircuts":self.risk_haircuts,"guardrails":self.guardrails,"rebates":self.rebates,"privacy_redactions":self.privacy_redactions,"public_records":self.public_records,"swaps":self.swaps,"liquidity_events":self.liquidity_events})
    }
    pub fn state_root(&self) -> String {
        root_from_record("REC-AMM-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vintage_root: String,
    pub pool_root: String,
    pub attestation_root: String,
    pub retirement_root: String,
    pub settlement_root: String,
    pub haircut_root: String,
    pub guardrail_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn without_state_root(&self) -> Value {
        json!({"kind":"private_l2_pq_confidential_rec_amm_roots","config_root":self.config_root,"vintage_root":self.vintage_root,"pool_root":self.pool_root,"attestation_root":self.attestation_root,"retirement_root":self.retirement_root,"settlement_root":self.settlement_root,"haircut_root":self.haircut_root,"guardrail_root":self.guardrail_root,"rebate_root":self.rebate_root,"redaction_root":self.redaction_root,"operator_summary_root":self.operator_summary_root,"public_record_root":self.public_record_root,"counters_root":self.counters_root})
    }
    pub fn public_record(&self) -> Value {
        let mut r = self.without_state_root();
        insert_string(&mut r, "state_root", self.state_root.clone());
        r
    }
    pub fn state_root(&self) -> String {
        root_from_record("REC-AMM-ROOTS", &self.without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecVintage {
    pub vintage_id: String,
    pub registry: String,
    pub jurisdiction: String,
    pub source: EnergySource,
    pub generation_year: u16,
    pub delivery_start_block: u64,
    pub delivery_end_block: u64,
    pub status: VintageStatus,
    pub total_mwh_commitment: String,
    pub unretired_mwh_commitment: String,
    pub metadata_root: String,
    pub oracle_set_root: String,
    pub pq_issuer_key_commitment: String,
    pub privacy_set_size: u64,
    pub accepted_attestations: u16,
    pub maturity_block: u64,
}

impl RecVintage {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            vintage_id: String::new(),
            registry: "registry-devnet-${seed}".to_string(),
            jurisdiction: "jurisdiction-devnet-${seed}".to_string(),
            source: EnergySource::Solar,
            generation_year: seed as _,
            delivery_start_block: seed as _,
            delivery_end_block: seed as _,
            status: VintageStatus::Draft,
            total_mwh_commitment: "total_mwh_commitment-devnet-${seed}".to_string(),
            unretired_mwh_commitment: "unretired_mwh_commitment-devnet-${seed}".to_string(),
            metadata_root: "metadata_root-devnet-${seed}".to_string(),
            oracle_set_root: "oracle_set_root-devnet-${seed}".to_string(),
            pq_issuer_key_commitment: "pq_issuer_key_commitment-devnet-${seed}".to_string(),
            privacy_set_size: seed as _,
            accepted_attestations: seed as _,
            maturity_block: seed as _,
        };
        record.vintage_id = root_from_record("REC_VINTAGE-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "rec_vintage",
            "registry": self.registry,
            "jurisdiction": self.jurisdiction,
            "source": self.source.as_str(),
            "generation_year": self.generation_year,
            "delivery_start_block": self.delivery_start_block,
            "delivery_end_block": self.delivery_end_block,
            "status": self.status.as_str(),
            "total_mwh_commitment": self.total_mwh_commitment,
            "unretired_mwh_commitment": self.unretired_mwh_commitment,
            "metadata_root": self.metadata_root,
            "oracle_set_root": self.oracle_set_root,
            "pq_issuer_key_commitment": self.pq_issuer_key_commitment,
            "privacy_set_size": self.privacy_set_size,
            "accepted_attestations": self.accepted_attestations,
            "maturity_block": self.maturity_block,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "vintage_id", self.vintage_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("REC_VINTAGE", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"REC_VINTAGE-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedAmmPool {
    pub pool_id: String,
    pub vintage_id: String,
    pub quote_asset: String,
    pub sealed_rec_reserve_commitment: String,
    pub sealed_quote_reserve_commitment: String,
    pub invariant_commitment: String,
    pub lp_token_commitment: String,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub haircut_bps: u64,
    pub pool_weight_bps: u64,
    pub daily_volume_bps: u64,
    pub status: PoolStatus,
    pub guardrail_root: String,
    pub privacy_set_size: u64,
}

impl SealedAmmPool {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            pool_id: String::new(),
            vintage_id: "vintage_id-devnet-${seed}".to_string(),
            quote_asset: "quote_asset-devnet-${seed}".to_string(),
            sealed_rec_reserve_commitment: "sealed_rec_reserve_commitment-devnet-${seed}"
                .to_string(),
            sealed_quote_reserve_commitment: "sealed_quote_reserve_commitment-devnet-${seed}"
                .to_string(),
            invariant_commitment: "invariant_commitment-devnet-${seed}".to_string(),
            lp_token_commitment: "lp_token_commitment-devnet-${seed}".to_string(),
            fee_bps: seed as _,
            rebate_bps: seed as _,
            haircut_bps: seed as _,
            pool_weight_bps: seed as _,
            daily_volume_bps: seed as _,
            status: PoolStatus::Bootstrapping,
            guardrail_root: "guardrail_root-devnet-${seed}".to_string(),
            privacy_set_size: seed as _,
        };
        record.pool_id = root_from_record("SEALED_AMM_POOL-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "sealed_amm_pool",
            "vintage_id": self.vintage_id,
            "quote_asset": self.quote_asset,
            "sealed_rec_reserve_commitment": self.sealed_rec_reserve_commitment,
            "sealed_quote_reserve_commitment": self.sealed_quote_reserve_commitment,
            "invariant_commitment": self.invariant_commitment,
            "lp_token_commitment": self.lp_token_commitment,
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "haircut_bps": self.haircut_bps,
            "pool_weight_bps": self.pool_weight_bps,
            "daily_volume_bps": self.daily_volume_bps,
            "status": self.status.as_str(),
            "guardrail_root": self.guardrail_root,
            "privacy_set_size": self.privacy_set_size,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "pool_id", self.pool_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("SEALED_AMM_POOL", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"SEALED_AMM_POOL-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleGenerationAttestation {
    pub attestation_id: String,
    pub vintage_id: String,
    pub oracle_id_commitment: String,
    pub attested_mwh_commitment: String,
    pub generation_meter_root: String,
    pub registry_certificate_root: String,
    pub pq_signature_root: String,
    pub observed_from_block: u64,
    pub observed_to_block: u64,
    pub status: AttestationStatus,
    pub challenge_window_end: u64,
    pub privacy_set_size: u64,
}

impl OracleGenerationAttestation {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            attestation_id: String::new(),
            vintage_id: "vintage_id-devnet-${seed}".to_string(),
            oracle_id_commitment: "oracle_id_commitment-devnet-${seed}".to_string(),
            attested_mwh_commitment: "attested_mwh_commitment-devnet-${seed}".to_string(),
            generation_meter_root: "generation_meter_root-devnet-${seed}".to_string(),
            registry_certificate_root: "registry_certificate_root-devnet-${seed}".to_string(),
            pq_signature_root: "pq_signature_root-devnet-${seed}".to_string(),
            observed_from_block: seed as _,
            observed_to_block: seed as _,
            status: AttestationStatus::Submitted,
            challenge_window_end: seed as _,
            privacy_set_size: seed as _,
        };
        record.attestation_id = root_from_record(
            "ORACLE_GENERATION_ATTESTATION-ID",
            &record.public_record_without_id(),
        );
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "oracle_generation_attestation",
            "vintage_id": self.vintage_id,
            "oracle_id_commitment": self.oracle_id_commitment,
            "attested_mwh_commitment": self.attested_mwh_commitment,
            "generation_meter_root": self.generation_meter_root,
            "registry_certificate_root": self.registry_certificate_root,
            "pq_signature_root": self.pq_signature_root,
            "observed_from_block": self.observed_from_block,
            "observed_to_block": self.observed_to_block,
            "status": self.status.as_str(),
            "challenge_window_end": self.challenge_window_end,
            "privacy_set_size": self.privacy_set_size,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "attestation_id", self.attestation_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("ORACLE_GENERATION_ATTESTATION", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"ORACLE_GENERATION_ATTESTATION-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetirementCommitment {
    pub retirement_id: String,
    pub vintage_id: String,
    pub pool_id: String,
    pub beneficiary_commitment: String,
    pub sealed_mwh_commitment: String,
    pub retirement_reason_code: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub status: RetirementStatus,
    pub expires_at_height: u64,
}

impl RetirementCommitment {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            retirement_id: String::new(),
            vintage_id: "vintage_id-devnet-${seed}".to_string(),
            pool_id: "pool_id-devnet-${seed}".to_string(),
            beneficiary_commitment: "beneficiary_commitment-devnet-${seed}".to_string(),
            sealed_mwh_commitment: "sealed_mwh_commitment-devnet-${seed}".to_string(),
            retirement_reason_code: "retirement_reason_code-devnet-${seed}".to_string(),
            nullifier_root: "nullifier_root-devnet-${seed}".to_string(),
            proof_root: "proof_root-devnet-${seed}".to_string(),
            status: RetirementStatus::Committed,
            expires_at_height: seed as _,
        };
        record.retirement_id = root_from_record(
            "RETIREMENT_COMMITMENT-ID",
            &record.public_record_without_id(),
        );
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "retirement_commitment",
            "vintage_id": self.vintage_id,
            "pool_id": self.pool_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "sealed_mwh_commitment": self.sealed_mwh_commitment,
            "retirement_reason_code": self.retirement_reason_code,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "retirement_id", self.retirement_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("RETIREMENT_COMMITMENT", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"RETIREMENT_COMMITMENT-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MaturitySettlement {
    pub settlement_id: String,
    pub vintage_id: String,
    pub pool_id: String,
    pub final_generation_root: String,
    pub settled_retirement_root: String,
    pub residual_inventory_commitment: String,
    pub lp_payout_commitment: String,
    pub oracle_finality_root: String,
    pub status: SettlementStatus,
    pub settlement_height: u64,
}

impl MaturitySettlement {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            settlement_id: String::new(),
            vintage_id: "vintage_id-devnet-${seed}".to_string(),
            pool_id: "pool_id-devnet-${seed}".to_string(),
            final_generation_root: "final_generation_root-devnet-${seed}".to_string(),
            settled_retirement_root: "settled_retirement_root-devnet-${seed}".to_string(),
            residual_inventory_commitment: "residual_inventory_commitment-devnet-${seed}"
                .to_string(),
            lp_payout_commitment: "lp_payout_commitment-devnet-${seed}".to_string(),
            oracle_finality_root: "oracle_finality_root-devnet-${seed}".to_string(),
            status: SettlementStatus::Scheduled,
            settlement_height: seed as _,
        };
        record.settlement_id =
            root_from_record("MATURITY_SETTLEMENT-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "maturity_settlement",
            "vintage_id": self.vintage_id,
            "pool_id": self.pool_id,
            "final_generation_root": self.final_generation_root,
            "settled_retirement_root": self.settled_retirement_root,
            "residual_inventory_commitment": self.residual_inventory_commitment,
            "lp_payout_commitment": self.lp_payout_commitment,
            "oracle_finality_root": self.oracle_finality_root,
            "status": self.status.as_str(),
            "settlement_height": self.settlement_height,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "settlement_id", self.settlement_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("MATURITY_SETTLEMENT", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"MATURITY_SETTLEMENT-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskHaircut {
    pub haircut_id: String,
    pub vintage_id: String,
    pub pool_id: String,
    pub base_haircut_bps: u64,
    pub vintage_age_haircut_bps: u64,
    pub oracle_dispersion_bps: u64,
    pub liquidity_depth_haircut_bps: u64,
    pub effective_haircut_bps: u64,
    pub reason_root: String,
}

impl RiskHaircut {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            haircut_id: String::new(),
            vintage_id: "vintage_id-devnet-${seed}".to_string(),
            pool_id: "pool_id-devnet-${seed}".to_string(),
            base_haircut_bps: seed as _,
            vintage_age_haircut_bps: seed as _,
            oracle_dispersion_bps: seed as _,
            liquidity_depth_haircut_bps: seed as _,
            effective_haircut_bps: seed as _,
            reason_root: "reason_root-devnet-${seed}".to_string(),
        };
        record.haircut_id = root_from_record("RISK_HAIRCUT-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "risk_haircut",
            "vintage_id": self.vintage_id,
            "pool_id": self.pool_id,
            "base_haircut_bps": self.base_haircut_bps,
            "vintage_age_haircut_bps": self.vintage_age_haircut_bps,
            "oracle_dispersion_bps": self.oracle_dispersion_bps,
            "liquidity_depth_haircut_bps": self.liquidity_depth_haircut_bps,
            "effective_haircut_bps": self.effective_haircut_bps,
            "reason_root": self.reason_root,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "haircut_id", self.haircut_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("RISK_HAIRCUT", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"RISK_HAIRCUT-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityGuardrail {
    pub guardrail_id: String,
    pub pool_id: String,
    pub current_pool_weight_bps: u64,
    pub rolling_volume_bps: u64,
    pub min_liquidity_usd: u64,
    pub observed_liquidity_usd: u64,
    pub enforced: bool,
    pub action: String,
}

impl LiquidityGuardrail {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            guardrail_id: String::new(),
            pool_id: "pool_id-devnet-${seed}".to_string(),
            current_pool_weight_bps: seed as _,
            rolling_volume_bps: seed as _,
            min_liquidity_usd: seed as _,
            observed_liquidity_usd: seed as _,
            enforced: false,
            action: "action-devnet-${seed}".to_string(),
        };
        record.guardrail_id =
            root_from_record("LIQUIDITY_GUARDRAIL-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "liquidity_guardrail",
            "pool_id": self.pool_id,
            "current_pool_weight_bps": self.current_pool_weight_bps,
            "rolling_volume_bps": self.rolling_volume_bps,
            "min_liquidity_usd": self.min_liquidity_usd,
            "observed_liquidity_usd": self.observed_liquidity_usd,
            "enforced": self.enforced,
            "action": self.action,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "guardrail_id", self.guardrail_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("LIQUIDITY_GUARDRAIL", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"LIQUIDITY_GUARDRAIL-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub pool_id: String,
    pub trader_commitment: String,
    pub fee_paid_commitment: String,
    pub credit_commitment: String,
    pub rebate_bps: u64,
    pub low_fee_lane: String,
    pub claim_nullifier: String,
}

impl FeeCreditRebate {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            rebate_id: String::new(),
            pool_id: "pool_id-devnet-${seed}".to_string(),
            trader_commitment: "trader_commitment-devnet-${seed}".to_string(),
            fee_paid_commitment: "fee_paid_commitment-devnet-${seed}".to_string(),
            credit_commitment: "credit_commitment-devnet-${seed}".to_string(),
            rebate_bps: seed as _,
            low_fee_lane: "low_fee_lane-devnet-${seed}".to_string(),
            claim_nullifier: "claim_nullifier-devnet-${seed}".to_string(),
        };
        record.rebate_id =
            root_from_record("FEE_CREDIT_REBATE-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "fee_credit_rebate",
            "pool_id": self.pool_id,
            "trader_commitment": self.trader_commitment,
            "fee_paid_commitment": self.fee_paid_commitment,
            "credit_commitment": self.credit_commitment,
            "rebate_bps": self.rebate_bps,
            "low_fee_lane": self.low_fee_lane,
            "claim_nullifier": self.claim_nullifier,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "rebate_id", self.rebate_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("FEE_CREDIT_REBATE", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"FEE_CREDIT_REBATE-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub source_record_id: String,
    pub source_kind: String,
    pub public_hint: String,
    pub sealed_payload_root: String,
    pub redaction_policy: String,
    pub view_tag_root: String,
    pub nullifier_root: String,
}

impl PrivacyRedaction {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            redaction_id: String::new(),
            source_record_id: "source_record_id-devnet-${seed}".to_string(),
            source_kind: "source_kind-devnet-${seed}".to_string(),
            public_hint: "public_hint-devnet-${seed}".to_string(),
            sealed_payload_root: "sealed_payload_root-devnet-${seed}".to_string(),
            redaction_policy: "redaction_policy-devnet-${seed}".to_string(),
            view_tag_root: "view_tag_root-devnet-${seed}".to_string(),
            nullifier_root: "nullifier_root-devnet-${seed}".to_string(),
        };
        record.redaction_id =
            root_from_record("PRIVACY_REDACTION-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "privacy_redaction",
            "source_record_id": self.source_record_id,
            "source_kind": self.source_kind,
            "public_hint": self.public_hint,
            "sealed_payload_root": self.sealed_payload_root,
            "redaction_policy": self.redaction_policy,
            "view_tag_root": self.view_tag_root,
            "nullifier_root": self.nullifier_root,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "redaction_id", self.redaction_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("PRIVACY_REDACTION", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"PRIVACY_REDACTION-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub vintage_count: u64,
    pub active_pool_count: u64,
    pub retired_commitment_root: String,
    pub attestation_acceptance_bps: u64,
    pub average_fee_bps: u64,
    pub rebate_credit_root: String,
    pub guardrail_event_root: String,
    pub pq_rotation_root: String,
}

impl OperatorSummary {
    pub fn devnet(seed: u64) -> Self {
        let mut record = Self {
            summary_id: String::new(),
            operator_commitment: "operator_commitment-devnet-${seed}".to_string(),
            epoch: seed as _,
            vintage_count: seed as _,
            active_pool_count: seed as _,
            retired_commitment_root: "retired_commitment_root-devnet-${seed}".to_string(),
            attestation_acceptance_bps: seed as _,
            average_fee_bps: seed as _,
            rebate_credit_root: "rebate_credit_root-devnet-${seed}".to_string(),
            guardrail_event_root: "guardrail_event_root-devnet-${seed}".to_string(),
            pq_rotation_root: "pq_rotation_root-devnet-${seed}".to_string(),
        };
        record.summary_id =
            root_from_record("OPERATOR_SUMMARY-ID", &record.public_record_without_id());
        record
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "operator_summary",
            "operator_commitment": self.operator_commitment,
            "epoch": self.epoch,
            "vintage_count": self.vintage_count,
            "active_pool_count": self.active_pool_count,
            "retired_commitment_root": self.retired_commitment_root,
            "attestation_acceptance_bps": self.attestation_acceptance_bps,
            "average_fee_bps": self.average_fee_bps,
            "rebate_credit_root": self.rebate_credit_root,
            "guardrail_event_root": self.guardrail_event_root,
            "pq_rotation_root": self.pq_rotation_root,
        })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        insert_string(&mut record, "summary_id", self.summary_id.clone());
        record
    }
    pub fn state_root(&self) -> String {
        root_from_record("OPERATOR_SUMMARY", &self.public_record())
    }
    pub fn generated_privacy_invariant_01(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-01","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_02(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-02","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_03(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-03","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_04(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-04","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_05(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-05","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_06(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-06","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_07(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-07","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_08(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-08","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_09(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-09","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
    pub fn generated_privacy_invariant_10(&self) -> Value {
        json!({"invariant":"OPERATOR_SUMMARY-10","record_root":self.state_root(),"privacy":"redacted","pq_required":true,"low_fee_priority":true})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub source_kind: String,
    pub source_id: String,
    pub record_root: String,
    pub public_hint: String,
}
impl PublicRecord {
    pub fn new(
        source_kind: impl Into<String>,
        source_id: impl Into<String>,
        record: Value,
        public_hint: impl Into<String>,
    ) -> Self {
        let source_kind = source_kind.into();
        let source_id = source_id.into();
        let record_root = root_from_record("REC-PUBLIC-RECORD-SOURCE", &record);
        let mut r = Self {
            record_id: String::new(),
            source_kind,
            source_id,
            record_root,
            public_hint: public_hint.into(),
        };
        r.record_id = root_from_record("REC-PUBLIC-RECORD-ID", &r.public_record_without_id());
        r
    }
    pub fn public_record_without_id(&self) -> Value {
        json!({"kind":"rec_roots_only_public_record","source_kind":self.source_kind,"source_id":self.source_id,"record_root":self.record_root,"public_hint":self.public_hint})
    }
    pub fn public_record(&self) -> Value {
        let mut r = self.public_record_without_id();
        insert_string(&mut r, "record_id", self.record_id.clone());
        r
    }
    pub fn state_root(&self) -> String {
        root_from_record("REC-PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub vintages: BTreeMap<String, RecVintage>,
    pub pools: BTreeMap<String, SealedAmmPool>,
    pub attestations: BTreeMap<String, OracleGenerationAttestation>,
    pub retirements: BTreeMap<String, RetirementCommitment>,
    pub settlements: BTreeMap<String, MaturitySettlement>,
    pub haircuts: BTreeMap<String, RiskHaircut>,
    pub guardrails: BTreeMap<String, LiquidityGuardrail>,
    pub rebates: BTreeMap<String, FeeCreditRebate>,
    pub redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}
impl State {
    pub fn devnet() -> Self {
        let mut s = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            vintages: BTreeMap::new(),
            pools: BTreeMap::new(),
            attestations: BTreeMap::new(),
            retirements: BTreeMap::new(),
            settlements: BTreeMap::new(),
            haircuts: BTreeMap::new(),
            guardrails: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        s.install_devnet_fixtures();
        s.refresh_roots();
        s
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"private_l2_pq_confidential_tokenized_renewable_energy_credit_amm_runtime_state","protocol_version":PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_PROTOCOL_VERSION,"schema_version":PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_SCHEMA_VERSION,"config":self.config.public_record(),"counters":self.counters.public_record(),"roots":self.roots.public_record(),"vintages":self.vintages.values().map(RecVintage::public_record).collect::<Vec<_>>(),"pools":self.pools.values().map(SealedAmmPool::public_record).collect::<Vec<_>>(),"attestations":self.attestations.values().map(OracleGenerationAttestation::public_record).collect::<Vec<_>>(),"retirements":self.retirements.values().map(RetirementCommitment::public_record).collect::<Vec<_>>(),"settlements":self.settlements.values().map(MaturitySettlement::public_record).collect::<Vec<_>>(),"haircuts":self.haircuts.values().map(RiskHaircut::public_record).collect::<Vec<_>>(),"guardrails":self.guardrails.values().map(LiquidityGuardrail::public_record).collect::<Vec<_>>(),"rebates":self.rebates.values().map(FeeCreditRebate::public_record).collect::<Vec<_>>(),"redactions":self.redactions.values().map(PrivacyRedaction::public_record).collect::<Vec<_>>(),"operator_summaries":self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),"public_records":self.public_records.values().map(PublicRecord::public_record).collect::<Vec<_>>(),"spent_nullifier_root":merkle_root("REC-SPENT-NULLIFIERS",self.spent_nullifiers.iter().map(|n|n.as_str()).collect::<Vec<_>>())})
    }
    pub fn public_record_without_state_root(&self) -> Value {
        let mut roots = self.roots.clone();
        roots.state_root = String::new();
        json!({"kind":"private_l2_pq_confidential_tokenized_renewable_energy_credit_amm_runtime_state","protocol_version":PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_PROTOCOL_VERSION,"schema_version":PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_SCHEMA_VERSION,"config":self.config.public_record(),"counters":self.counters.public_record(),"roots":roots.without_state_root()})
    }
    pub fn state_root(&self) -> String {
        root_from_record("REC-AMM-STATE", &self.public_record_without_state_root())
    }
    pub fn register_vintage(&mut self, v: RecVintage) -> Result<String> {
        self.config.validate()?;
        require(
            v.privacy_set_size >= self.config.min_privacy_set_size,
            "vintage privacy set too small",
        )?;
        let id = v.vintage_id.clone();
        self.redact(
            "rec_vintage",
            &id,
            v.state_root(),
            "vintage-region-source-year",
        );
        self.vintages.insert(id.clone(), v);
        self.refresh_roots();
        Ok(id)
    }
    pub fn create_pool(&mut self, p: SealedAmmPool) -> Result<String> {
        require(self.vintages.contains_key(&p.vintage_id), "unknown vintage")?;
        require(p.fee_bps <= self.config.max_user_fee_bps, "fee exceeds cap")?;
        let id = p.pool_id.clone();
        self.redact(
            "sealed_amm_pool",
            &id,
            p.state_root(),
            "pool-fee-depth-hint",
        );
        self.pools.insert(id.clone(), p);
        self.refresh_roots();
        Ok(id)
    }
    pub fn submit_attestation(&mut self, a: OracleGenerationAttestation) -> Result<String> {
        require(self.vintages.contains_key(&a.vintage_id), "unknown vintage")?;
        let id = a.attestation_id.clone();
        self.redact(
            "oracle_generation_attestation",
            &id,
            a.state_root(),
            "oracle-quorum-generation-band",
        );
        self.attestations.insert(id.clone(), a);
        self.refresh_roots();
        Ok(id)
    }
    pub fn commit_retirement(&mut self, r: RetirementCommitment) -> Result<String> {
        require(self.vintages.contains_key(&r.vintage_id), "unknown vintage")?;
        require(self.pools.contains_key(&r.pool_id), "unknown pool")?;
        require(
            !self.spent_nullifiers.contains(&r.nullifier_root),
            "duplicate nullifier",
        )?;
        self.spent_nullifiers.insert(r.nullifier_root.clone());
        let id = r.retirement_id.clone();
        self.redact(
            "retirement_commitment",
            &id,
            r.state_root(),
            "retirement-beneficiary-redacted",
        );
        self.retirements.insert(id.clone(), r);
        self.refresh_roots();
        Ok(id)
    }
    pub fn schedule_maturity_settlement(&mut self, m: MaturitySettlement) -> Result<String> {
        require(self.vintages.contains_key(&m.vintage_id), "unknown vintage")?;
        require(self.pools.contains_key(&m.pool_id), "unknown pool")?;
        let id = m.settlement_id.clone();
        self.settlements.insert(id.clone(), m);
        self.refresh_roots();
        Ok(id)
    }
    pub fn apply_risk_haircut(&mut self, h: RiskHaircut) -> Result<String> {
        require(self.pools.contains_key(&h.pool_id), "unknown pool")?;
        let id = h.haircut_id.clone();
        self.haircuts.insert(id.clone(), h);
        self.refresh_roots();
        Ok(id)
    }
    pub fn evaluate_guardrail(&mut self, g: LiquidityGuardrail) -> Result<String> {
        require(self.pools.contains_key(&g.pool_id), "unknown pool")?;
        let id = g.guardrail_id.clone();
        self.guardrails.insert(id.clone(), g);
        self.refresh_roots();
        Ok(id)
    }
    pub fn issue_fee_credit_rebate(&mut self, r: FeeCreditRebate) -> Result<String> {
        require(self.pools.contains_key(&r.pool_id), "unknown pool")?;
        let id = r.rebate_id.clone();
        self.redact(
            "fee_credit_rebate",
            &id,
            r.state_root(),
            "low-fee-credit-band",
        );
        self.rebates.insert(id.clone(), r);
        self.refresh_roots();
        Ok(id)
    }
    pub fn record_operator_summary(&mut self, o: OperatorSummary) -> String {
        let id = o.summary_id.clone();
        self.operator_summaries.insert(id.clone(), o);
        self.refresh_roots();
        id
    }
    pub fn operator_summary(&self) -> Value {
        json!({"kind":"private_l2_pq_confidential_rec_amm_operator_summary_view","active_vintages":self.vintages.values().filter(|v|v.status.tradable()).count(),"active_pools":self.pools.values().filter(|p|p.status.can_swap()).count(),"accepted_attestations":self.attestations.values().filter(|a|a.status.accepted()).count(),"settled_retirements":self.retirements.values().filter(|r|r.status==RetirementStatus::Settled).count(),"state_root":self.state_root()})
    }
    fn redact(
        &mut self,
        source_kind: &str,
        source_id: &str,
        sealed_payload_root: String,
        hint: &str,
    ) {
        let redaction = PrivacyRedaction::devnet(
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RENEWABLE_ENERGY_CREDIT_AMM_RUNTIME_DEVNET_HEIGHT,
        );
        let public_record = PublicRecord::new(
            source_kind,
            source_id,
            json!({"sealed_payload_root":sealed_payload_root,"redaction_id":redaction.redaction_id}),
            hint,
        );
        self.public_records
            .insert(public_record.record_id.clone(), public_record);
        self.redactions
            .insert(redaction.redaction_id.clone(), redaction);
    }
    fn refresh_roots(&mut self) {
        self.counters.vintages = self.vintages.len() as u64;
        self.counters.pools = self.pools.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.retirements = self.retirements.len() as u64;
        self.counters.settlements = self.settlements.len() as u64;
        self.counters.risk_haircuts = self.haircuts.len() as u64;
        self.counters.guardrails = self.guardrails.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.privacy_redactions = self.redactions.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.roots = Roots {
            config_root: self.config.state_root(),
            vintage_root: map_root("REC-VINTAGES", &self.vintages, RecVintage::public_record),
            pool_root: map_root("REC-POOLS", &self.pools, SealedAmmPool::public_record),
            attestation_root: map_root(
                "REC-ATTESTATIONS",
                &self.attestations,
                OracleGenerationAttestation::public_record,
            ),
            retirement_root: map_root(
                "REC-RETIREMENTS",
                &self.retirements,
                RetirementCommitment::public_record,
            ),
            settlement_root: map_root(
                "REC-SETTLEMENTS",
                &self.settlements,
                MaturitySettlement::public_record,
            ),
            haircut_root: map_root("REC-HAIRCUTS", &self.haircuts, RiskHaircut::public_record),
            guardrail_root: map_root(
                "REC-GUARDRAILS",
                &self.guardrails,
                LiquidityGuardrail::public_record,
            ),
            rebate_root: map_root("REC-REBATES", &self.rebates, FeeCreditRebate::public_record),
            redaction_root: map_root(
                "REC-REDACTIONS",
                &self.redactions,
                PrivacyRedaction::public_record,
            ),
            operator_summary_root: map_root(
                "REC-OPERATOR-SUMMARIES",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            public_record_root: map_root(
                "REC-PUBLIC-RECORDS",
                &self.public_records,
                PublicRecord::public_record,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.state_root();
    }
    fn install_devnet_fixtures(&mut self) {
        let v = RecVintage::devnet(1);
        let vid = v.vintage_id.clone();
        self.vintages.insert(vid.clone(), v);
        let mut p = SealedAmmPool::devnet(2);
        p.vintage_id = vid.clone();
        p.fee_bps = 10;
        p.rebate_bps = DEFAULT_TARGET_REBATE_BPS;
        let pid = p.pool_id.clone();
        self.pools.insert(pid.clone(), p);
        let mut a = OracleGenerationAttestation::devnet(3);
        a.vintage_id = vid.clone();
        a.status = AttestationStatus::Accepted;
        self.attestations.insert(a.attestation_id.clone(), a);
        let mut r = RetirementCommitment::devnet(4);
        r.vintage_id = vid.clone();
        r.pool_id = pid.clone();
        self.spent_nullifiers.insert(r.nullifier_root.clone());
        self.retirements.insert(r.retirement_id.clone(), r);
        let mut m = MaturitySettlement::devnet(5);
        m.vintage_id = vid.clone();
        m.pool_id = pid.clone();
        self.settlements.insert(m.settlement_id.clone(), m);
        let mut h = RiskHaircut::devnet(6);
        h.vintage_id = vid.clone();
        h.pool_id = pid.clone();
        h.effective_haircut_bps = 75;
        self.haircuts.insert(h.haircut_id.clone(), h);
        let mut g = LiquidityGuardrail::devnet(7);
        g.pool_id = pid.clone();
        g.min_liquidity_usd = DEFAULT_MIN_LIQUIDITY_USD;
        self.guardrails.insert(g.guardrail_id.clone(), g);
        let mut f = FeeCreditRebate::devnet(8);
        f.pool_id = pid.clone();
        f.rebate_bps = DEFAULT_TARGET_REBATE_BPS;
        self.rebates.insert(f.rebate_id.clone(), f);
        let o = OperatorSummary::devnet(9);
        self.operator_summaries.insert(o.summary_id.clone(), o);
        self.redact(
            "rec_vintage",
            &vid,
            payload_id("DEVNET-REDACTION", &[HashPart::Str(&vid)]),
            "vintage-region-source-year",
        );
        self.redact(
            "sealed_amm_pool",
            &pid,
            payload_id("DEVNET-POOL-REDACTION", &[HashPart::Str(&pid)]),
            "pool-fee-depth-hint",
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn demo() -> State {
    let mut s = State::devnet();
    let mut v = RecVintage::devnet(42);
    v.source = EnergySource::Wind;
    v.status = VintageStatus::Active;
    let vid = s
        .register_vintage(v)
        .unwrap_or_else(|_| "demo-vintage-failed".to_string());
    let mut p = SealedAmmPool::devnet(43);
    p.vintage_id = vid.clone();
    p.fee_bps = 9;
    p.rebate_bps = 6;
    let pid = s
        .create_pool(p)
        .unwrap_or_else(|_| "demo-pool-failed".to_string());
    let mut a = OracleGenerationAttestation::devnet(44);
    a.vintage_id = vid.clone();
    a.status = AttestationStatus::Accepted;
    let _ = s.submit_attestation(a);
    let mut r = RetirementCommitment::devnet(45);
    r.vintage_id = vid.clone();
    r.pool_id = pid.clone();
    let _ = s.commit_retirement(r);
    let mut m = MaturitySettlement::devnet(46);
    m.vintage_id = vid;
    m.pool_id = pid;
    let _ = s.schedule_maturity_settlement(m);
    s.refresh_roots();
    s
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn private_l2_pq_confidential_tokenized_renewable_energy_credit_amm_runtime_public_record(
) -> Value {
    State::devnet().public_record()
}
pub fn private_l2_pq_confidential_tokenized_renewable_energy_credit_amm_runtime_state_root(
) -> String {
    State::devnet().state_root()
}
fn insert_string(record: &mut Value, key: &str, value: String) {
    if let Some(map) = record.as_object_mut() {
        map.insert(key.to_string(), Value::String(value));
    }
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn empty_root(domain: &str) -> String {
    merkle_root(domain, Vec::<&str>::new())
}
fn root_from_record(domain: &str, record: &Value) -> String {
    let encoded = serde_json::to_string(record).unwrap_or_else(|_| "null".to_string());
    domain_hash(domain, &[HashPart::Str(&encoded)])
}
fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts)
}
fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            root_from_record(domain, &json!({"key":key,"record":public_record(value)}))
        })
        .collect::<Vec<_>>();
    merkle_root(
        domain,
        leaves.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeCatalogEntry {
    pub lane: String,
    pub purpose: String,
    pub domain: String,
    pub privacy_priority: bool,
    pub pq_required: bool,
    pub low_fee_priority: bool,
}
impl RuntimeCatalogEntry {
    pub fn public_record(&self) -> Value {
        json!({"kind":"rec_amm_runtime_catalog_entry","lane":self.lane,"purpose":self.purpose,"domain":self.domain,"privacy_priority":self.privacy_priority,"pq_required":self.pq_required,"low_fee_priority":self.low_fee_priority})
    }
}
pub fn runtime_catalog() -> Vec<RuntimeCatalogEntry> {
    let purposes = [
        "vintage_commitment",
        "sealed_pool",
        "oracle_attestation",
        "retirement_nullifier",
        "maturity_settlement",
        "risk_haircut",
        "liquidity_guardrail",
        "fee_credit_rebate",
        "privacy_redaction",
        "operator_summary",
    ];
    (0..256)
        .map(|index| {
            let purpose = purposes[index % purposes.len()].to_string();
            RuntimeCatalogEntry {
                lane: format!("rec-amm-lane-{index:04}"),
                purpose: purpose.clone(),
                domain: payload_id(
                    "REC-AMM-RUNTIME-CATALOG",
                    &[HashPart::Int(index as u64), HashPart::Str(&purpose)],
                ),
                privacy_priority: index % 3 != 0,
                pq_required: true,
                low_fee_priority: index % 4 != 0,
            }
        })
        .collect()
}
pub fn generated_low_fee_privacy_route_0000() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0000".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(0)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0001() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0001".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(1)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0002() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0002".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(2)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0003() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0003".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(3)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0004() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0004".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(4)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0005() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0005".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(5)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0006() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0006".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(6)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0007() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0007".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(7)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0008() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0008".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(8)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0009() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0009".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(9)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0010() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0010".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(10)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0011() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0011".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(11)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0012() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0012".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(12)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0013() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0013".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(13)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0014() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0014".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(14)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0015() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0015".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(15)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0016() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0016".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(16)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0017() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0017".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(17)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0018() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0018".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(18)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0019() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0019".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(19)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0020() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0020".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(20)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0021() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0021".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(21)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0022() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0022".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(22)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0023() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0023".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(23)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0024() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0024".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(24)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0025() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0025".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(25)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0026() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0026".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(26)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0027() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0027".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(27)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0028() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0028".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(28)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0029() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0029".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(29)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0030() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0030".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(30)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0031() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0031".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(31)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0032() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0032".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(32)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0033() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0033".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(33)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0034() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0034".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(34)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0035() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0035".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(35)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0036() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0036".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(36)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0037() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0037".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(37)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0038() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0038".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(38)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0039() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0039".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(39)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0040() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0040".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(40)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0041() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0041".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(41)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0042() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0042".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(42)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0043() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0043".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(43)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0044() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0044".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(44)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0045() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0045".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(45)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0046() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0046".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(46)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0047() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0047".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(47)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0048() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0048".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(48)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0049() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0049".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(49)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0050() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0050".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(50)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0051() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0051".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(51)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0052() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0052".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(52)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0053() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0053".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(53)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0054() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0054".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(54)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0055() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0055".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(55)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0056() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0056".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(56)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0057() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0057".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(57)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0058() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0058".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(58)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0059() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0059".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(59)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0060() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0060".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(60)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0061() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0061".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(61)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0062() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0062".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(62)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0063() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0063".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(63)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0064() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0064".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(64)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0065() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0065".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(65)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0066() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0066".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(66)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0067() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0067".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(67)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0068() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0068".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(68)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0069() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0069".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(69)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0070() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0070".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(70)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0071() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0071".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(71)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0072() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0072".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(72)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0073() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0073".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(73)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0074() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0074".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(74)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0075() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0075".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(75)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0076() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0076".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(76)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0077() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0077".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(77)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0078() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0078".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(78)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0079() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0079".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(79)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0080() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0080".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(80)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0081() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0081".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(81)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0082() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0082".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(82)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0083() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0083".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(83)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0084() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0084".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(84)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0085() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0085".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(85)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0086() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0086".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(86)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0087() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0087".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(87)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0088() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0088".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(88)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0089() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0089".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(89)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0090() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0090".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(90)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0091() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0091".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(91)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0092() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0092".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(92)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: false,
    }
}
pub fn generated_low_fee_privacy_route_0093() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0093".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(93)]),
        privacy_priority: false,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0094() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0094".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(94)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
pub fn generated_low_fee_privacy_route_0095() -> RuntimeCatalogEntry {
    RuntimeCatalogEntry {
        lane: "rec-amm-generated-lane-0095".to_string(),
        purpose: "generated_route".to_string(),
        domain: payload_id("REC-AMM-GENERATED-ROUTE", &[HashPart::Int(95)]),
        privacy_priority: true,
        pq_required: true,
        low_fee_priority: true,
    }
}
