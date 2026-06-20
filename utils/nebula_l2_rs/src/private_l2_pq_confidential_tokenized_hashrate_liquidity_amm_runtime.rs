use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedHashrateLiquidityAmmRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenizedHashrateLiquidityAmmRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_HASHRATE_LIQUIDITY_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-hashrate-liquidity-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_HASHRATE_LIQUIDITY_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-hashrate-liquidity-amm-v1";
pub const PRIVACY_SCHEME: &str =
    "monero-viewtag-stealth-address-nullifier-fence-confidential-hashrate-amm-v1";
pub const ORACLE_SCHEME: &str = "pq-threshold-hashrate-liquidity-oracle-committee-v1";
pub const AMM_SCHEME: &str = "confidential-constant-product-hashrate-liquidity-amm-v1";
pub const REBATE_SCHEME: &str = "recursive-proof-low-fee-hashrate-swap-rebate-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-pq-confidential-tokenized-hashrate-liquidity-amm-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_884_320;
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_HASHRATE_UNIT_ASSET_ID: &str = "asset:tokenized-randomx-th-s-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_ORACLE_QUORUM: u16 = 7;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SWAP_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 3;
pub const DEFAULT_REBATE_BPS: u64 = 10;
pub const DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u64 = 1_500;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 250;
pub const DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 24;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashrateAlgorithm {
    RandomX,
    Sha256,
    Scrypt,
    Blake3Merged,
}

impl HashrateAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RandomX => "random_x",
            Self::Sha256 => "sha256",
            Self::Scrypt => "scrypt",
            Self::Blake3Merged => "blake3_merged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Active,
    SwapOnly,
    LiquidityOnly,
    OracleGated,
    Safeguarded,
    Paused,
    Retired,
}

impl PoolStatus {
    pub fn accepts_swaps(self) -> bool {
        matches!(self, Self::Active | Self::SwapOnly)
    }

    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Active | Self::LiquidityOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapDirection {
    FeeAssetForHashrate,
    HashrateForFeeAsset,
}

impl SwapDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeAssetForHashrate => "fee_asset_for_hashrate",
            Self::HashrateForFeeAsset => "hashrate_for_fee_asset",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    Quoted,
    Attested,
    Accepted,
    Settled,
    Rebated,
    Rejected,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Proposed,
    QuorumAccepted,
    Challenged,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hashrate_unit_asset_id: String,
    pub pq_auth_suite: String,
    pub privacy_scheme: String,
    pub oracle_scheme: String,
    pub amm_scheme: String,
    pub rebate_scheme: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub oracle_quorum: u16,
    pub min_pq_security_bits: u16,
    pub swap_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_liquidity_coverage_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub operator_view_redaction: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hashrate_unit_asset_id: DEVNET_HASHRATE_UNIT_ASSET_ID.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            privacy_scheme: PRIVACY_SCHEME.to_string(),
            oracle_scheme: ORACLE_SCHEME.to_string(),
            amm_scheme: AMM_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            swap_ttl_blocks: DEFAULT_SWAP_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_oracle_staleness_blocks: DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            operator_view_redaction: "operator-safe-roots-only-no-trader-or-miner-pii".to_string(),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub share_tokens: u64,
    pub oracle_reports: u64,
    pub pq_attestations: u64,
    pub confidential_swaps: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub accepted_flows: u64,
    pub rejected_flows: u64,
    pub total_liquidity_fee_asset: u64,
    pub total_liquidity_hashrate_th: u64,
    pub total_swap_notional_fee_asset: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pool_root: String,
    pub share_token_root: String,
    pub oracle_report_root: String,
    pub pq_attestation_root: String,
    pub swap_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AmmPool {
    pub pool_id: String,
    pub operator_commitment: String,
    pub algorithm: HashrateAlgorithm,
    pub status: PoolStatus,
    pub fee_asset_id: String,
    pub hashrate_asset_id: String,
    pub fee_reserve_commitment: String,
    pub hashrate_reserve_commitment: String,
    pub lp_supply_commitment: String,
    pub invariant_commitment: String,
    pub oracle_report_id: String,
    pub min_liquidity_coverage_bps: u64,
    pub max_price_impact_bps: u64,
    pub fee_bps: u64,
    pub liquidity_fee_asset: u64,
    pub liquidity_hashrate_th: u64,
    pub opened_at_height: u64,
}

impl AmmPool {
    pub fn new(request: CreatePoolRequest) -> Self {
        let mut record = Self {
            pool_id: String::new(),
            operator_commitment: request.operator_commitment,
            algorithm: request.algorithm,
            status: PoolStatus::Active,
            fee_asset_id: request.fee_asset_id,
            hashrate_asset_id: request.hashrate_asset_id,
            fee_reserve_commitment: request.fee_reserve_commitment,
            hashrate_reserve_commitment: request.hashrate_reserve_commitment,
            lp_supply_commitment: request.lp_supply_commitment,
            invariant_commitment: request.invariant_commitment,
            oracle_report_id: request.oracle_report_id,
            min_liquidity_coverage_bps: request.min_liquidity_coverage_bps,
            max_price_impact_bps: request.max_price_impact_bps,
            fee_bps: request.fee_bps,
            liquidity_fee_asset: request.liquidity_fee_asset,
            liquidity_hashrate_th: request.liquidity_hashrate_th,
            opened_at_height: request.opened_at_height,
        };
        record.pool_id = id_from_record("HASHRATE-AMM-POOL-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "pool_id", json!(self.pool_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "hashrate_liquidity_amm_pool",
            "protocol_version": PROTOCOL_VERSION,
            "operator_commitment": self.operator_commitment,
            "algorithm": self.algorithm.as_str(),
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "hashrate_asset_id": self.hashrate_asset_id,
            "fee_reserve_commitment": self.fee_reserve_commitment,
            "hashrate_reserve_commitment": self.hashrate_reserve_commitment,
            "lp_supply_commitment": self.lp_supply_commitment,
            "invariant_commitment": self.invariant_commitment,
            "oracle_report_id": self.oracle_report_id,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "fee_bps": self.fee_bps,
            "liquidity_fee_asset": self.liquidity_fee_asset,
            "liquidity_hashrate_th": self.liquidity_hashrate_th,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HashrateShareToken {
    pub token_id: String,
    pub pool_id: String,
    pub tranche_commitment: String,
    pub owner_commitment: String,
    pub algorithm: HashrateAlgorithm,
    pub committed_hashrate_th: u64,
    pub maturity_height: u64,
    pub redemption_commitment: String,
}

impl HashrateShareToken {
    pub fn new(request: MintShareTokenRequest) -> Self {
        let mut record = Self {
            token_id: String::new(),
            pool_id: request.pool_id,
            tranche_commitment: request.tranche_commitment,
            owner_commitment: request.owner_commitment,
            algorithm: request.algorithm,
            committed_hashrate_th: request.committed_hashrate_th,
            maturity_height: request.maturity_height,
            redemption_commitment: request.redemption_commitment,
        };
        record.token_id = id_from_record(
            "HASHRATE-SHARE-TOKEN-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "token_id", json!(self.token_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "hashrate_share_token",
            "protocol_version": PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "tranche_commitment": self.tranche_commitment,
            "owner_commitment": self.owner_commitment,
            "algorithm": self.algorithm.as_str(),
            "committed_hashrate_th": self.committed_hashrate_th,
            "maturity_height": self.maturity_height,
            "redemption_commitment": self.redemption_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleReport {
    pub report_id: String,
    pub pool_id: String,
    pub committee_root: String,
    pub status: OracleStatus,
    pub observed_hashrate_th: u64,
    pub difficulty_commitment: String,
    pub payout_index_commitment: String,
    pub price_commitment: String,
    pub quorum_weight: u16,
    pub pq_security_bits: u16,
    pub report_height: u64,
    pub expires_at_height: u64,
}

impl OracleReport {
    pub fn new(request: OracleReportRequest, config: &Config) -> Self {
        let mut record = Self {
            report_id: String::new(),
            pool_id: request.pool_id,
            committee_root: request.committee_root,
            status: OracleStatus::QuorumAccepted,
            observed_hashrate_th: request.observed_hashrate_th,
            difficulty_commitment: request.difficulty_commitment,
            payout_index_commitment: request.payout_index_commitment,
            price_commitment: request.price_commitment,
            quorum_weight: request.quorum_weight,
            pq_security_bits: request.pq_security_bits,
            report_height: request.report_height,
            expires_at_height: request
                .report_height
                .saturating_add(config.max_oracle_staleness_blocks),
        };
        record.report_id = id_from_record(
            "HASHRATE-ORACLE-REPORT-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "report_id", json!(self.report_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "hashrate_oracle_report",
            "protocol_version": PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "committee_root": self.committee_root,
            "status": self.status,
            "observed_hashrate_th": self.observed_hashrate_th,
            "difficulty_commitment": self.difficulty_commitment,
            "payout_index_commitment": self.payout_index_commitment,
            "price_commitment": self.price_commitment,
            "quorum_weight": self.quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "report_height": self.report_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub committee_root: String,
    pub attestation_root: String,
    pub security_bits: u16,
    pub quorum_weight: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl PqAttestation {
    pub fn new(request: PqAttestationRequest) -> Self {
        let mut record = Self {
            attestation_id: String::new(),
            subject_id: request.subject_id,
            committee_root: request.committee_root,
            attestation_root: request.attestation_root,
            security_bits: request.security_bits,
            quorum_weight: request.quorum_weight,
            valid_from_height: request.valid_from_height,
            valid_until_height: request.valid_until_height,
        };
        record.attestation_id = id_from_record(
            "HASHRATE-PQ-ATTESTATION-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "attestation_id", json!(self.attestation_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "pq_hashrate_liquidity_attestation",
            "protocol_version": PROTOCOL_VERSION,
            "subject_id": self.subject_id,
            "committee_root": self.committee_root,
            "attestation_root": self.attestation_root,
            "security_bits": self.security_bits,
            "quorum_weight": self.quorum_weight,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialSwap {
    pub swap_id: String,
    pub pool_id: String,
    pub direction: SwapDirection,
    pub status: FlowStatus,
    pub trader_commitment: String,
    pub input_commitment: String,
    pub output_commitment: String,
    pub fee_commitment: String,
    pub nullifier: String,
    pub oracle_report_id: String,
    pub max_price_impact_bps: u64,
    pub fee_bps: u64,
    pub notional_fee_asset: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ConfidentialSwap {
    pub fn new(request: ConfidentialSwapRequest, config: &Config, pool: &AmmPool) -> Self {
        let fee_bps = request
            .fee_bps
            .min(config.max_user_fee_bps)
            .max(pool.fee_bps);
        let mut record = Self {
            swap_id: String::new(),
            pool_id: request.pool_id,
            direction: request.direction,
            status: FlowStatus::Accepted,
            trader_commitment: request.trader_commitment,
            input_commitment: request.input_commitment,
            output_commitment: request.output_commitment,
            fee_commitment: request.fee_commitment,
            nullifier: request.nullifier,
            oracle_report_id: pool.oracle_report_id.clone(),
            max_price_impact_bps: request.max_price_impact_bps,
            fee_bps,
            notional_fee_asset: request.notional_fee_asset,
            created_at_height: request.created_at_height,
            expires_at_height: request
                .created_at_height
                .saturating_add(config.swap_ttl_blocks),
        };
        record.swap_id = id_from_record(
            "CONFIDENTIAL-HASHRATE-SWAP-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn qualifies_for_rebate(&self, config: &Config) -> bool {
        self.fee_bps <= config.low_fee_bps && self.status == FlowStatus::Settled
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "swap_id", json!(self.swap_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "confidential_hashrate_amm_swap",
            "protocol_version": PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "direction": self.direction.as_str(),
            "status": self.status,
            "trader_commitment": self.trader_commitment,
            "input_commitment": self.input_commitment,
            "output_commitment": self.output_commitment,
            "fee_commitment": self.fee_commitment,
            "nullifier": self.nullifier,
            "oracle_report_id": self.oracle_report_id,
            "max_price_impact_bps": self.max_price_impact_bps,
            "fee_bps": self.fee_bps,
            "notional_fee_asset": self.notional_fee_asset,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settlement {
    pub settlement_id: String,
    pub pool_id: String,
    pub swap_id: String,
    pub settlement_root: String,
    pub reserve_delta_root: String,
    pub fee_paid_commitment: String,
    pub status: FlowStatus,
    pub settled_at_height: u64,
}

impl Settlement {
    pub fn new(request: SettlementRequest) -> Self {
        let mut record = Self {
            settlement_id: String::new(),
            pool_id: request.pool_id,
            swap_id: request.swap_id,
            settlement_root: request.settlement_root,
            reserve_delta_root: request.reserve_delta_root,
            fee_paid_commitment: request.fee_paid_commitment,
            status: FlowStatus::Settled,
            settled_at_height: request.settled_at_height,
        };
        record.settlement_id = id_from_record(
            "HASHRATE-AMM-SETTLEMENT-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "settlement_id", json!(self.settlement_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "hashrate_amm_settlement",
            "protocol_version": PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "swap_id": self.swap_id,
            "settlement_root": self.settlement_root,
            "reserve_delta_root": self.reserve_delta_root,
            "fee_paid_commitment": self.fee_paid_commitment,
            "status": self.status,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub swap_id: String,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub proof_root: String,
    pub status: FlowStatus,
}

impl LowFeeRebate {
    pub fn new(request: RebateRequest, config: &Config) -> Self {
        let mut record = Self {
            rebate_id: String::new(),
            swap_id: request.swap_id,
            recipient_commitment: request.recipient_commitment,
            rebate_commitment: request.rebate_commitment,
            rebate_bps: config.rebate_bps,
            proof_root: request.proof_root,
            status: FlowStatus::Rebated,
        };
        record.rebate_id = id_from_record(
            "HASHRATE-LOW-FEE-REBATE-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "rebate_id", json!(self.rebate_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "hashrate_low_fee_rebate",
            "protocol_version": PROTOCOL_VERSION,
            "swap_id": self.swap_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_bps": self.rebate_bps,
            "proof_root": self.proof_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_commitment: String,
    pub pool_id: String,
    pub disclosure_root: String,
    pub max_records: u64,
    pub spent_records: u64,
    pub privacy_floor: u64,
}

impl RedactionBudget {
    pub fn new(request: RedactionBudgetRequest, config: &Config) -> Self {
        let mut record = Self {
            budget_id: String::new(),
            operator_commitment: request.operator_commitment,
            pool_id: request.pool_id,
            disclosure_root: request.disclosure_root,
            max_records: request.max_records,
            spent_records: 0,
            privacy_floor: config.min_privacy_set_size,
        };
        record.budget_id = id_from_record(
            "HASHRATE-REDACTION-BUDGET-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "budget_id", json!(self.budget_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "hashrate_operator_redaction_budget",
            "protocol_version": PROTOCOL_VERSION,
            "operator_commitment": self.operator_commitment,
            "pool_id": self.pool_id,
            "disclosure_root": self.disclosure_root,
            "max_records": self.max_records,
            "spent_records": self.spent_records,
            "privacy_floor": self.privacy_floor,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub pool_id: String,
    pub summary_height: u64,
    pub pool_status: PoolStatus,
    pub oracle_report_id: String,
    pub pool_root: String,
    pub liquidity_coverage_bps: u64,
    pub swap_count: u64,
    pub settled_count: u64,
    pub rebate_count: u64,
    pub safe_public_note: String,
}

impl OperatorSummary {
    pub fn new(request: OperatorSummaryRequest, pool: &AmmPool) -> Self {
        let mut record = Self {
            summary_id: String::new(),
            operator_commitment: pool.operator_commitment.clone(),
            pool_id: pool.pool_id.clone(),
            summary_height: request.summary_height,
            pool_status: pool.status,
            oracle_report_id: pool.oracle_report_id.clone(),
            pool_root: pool_root(pool),
            liquidity_coverage_bps: coverage_bps(
                pool.liquidity_fee_asset,
                pool.liquidity_hashrate_th,
            ),
            swap_count: request.swap_count,
            settled_count: request.settled_count,
            rebate_count: request.rebate_count,
            safe_public_note: request.safe_public_note,
        };
        record.summary_id = id_from_record(
            "HASHRATE-OPERATOR-SUMMARY-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "summary_id", json!(self.summary_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "operator_safe_hashrate_amm_summary",
            "protocol_version": PROTOCOL_VERSION,
            "operator_commitment": self.operator_commitment,
            "pool_id": self.pool_id,
            "summary_height": self.summary_height,
            "pool_status": self.pool_status,
            "oracle_report_id": self.oracle_report_id,
            "pool_root": self.pool_root,
            "liquidity_coverage_bps": self.liquidity_coverage_bps,
            "swap_count": self.swap_count,
            "settled_count": self.settled_count,
            "rebate_count": self.rebate_count,
            "safe_public_note": self.safe_public_note,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreatePoolRequest {
    pub operator_commitment: String,
    pub algorithm: HashrateAlgorithm,
    pub fee_asset_id: String,
    pub hashrate_asset_id: String,
    pub fee_reserve_commitment: String,
    pub hashrate_reserve_commitment: String,
    pub lp_supply_commitment: String,
    pub invariant_commitment: String,
    pub oracle_report_id: String,
    pub min_liquidity_coverage_bps: u64,
    pub max_price_impact_bps: u64,
    pub fee_bps: u64,
    pub liquidity_fee_asset: u64,
    pub liquidity_hashrate_th: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MintShareTokenRequest {
    pub pool_id: String,
    pub tranche_commitment: String,
    pub owner_commitment: String,
    pub algorithm: HashrateAlgorithm,
    pub committed_hashrate_th: u64,
    pub maturity_height: u64,
    pub redemption_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleReportRequest {
    pub pool_id: String,
    pub committee_root: String,
    pub observed_hashrate_th: u64,
    pub difficulty_commitment: String,
    pub payout_index_commitment: String,
    pub price_commitment: String,
    pub quorum_weight: u16,
    pub pq_security_bits: u16,
    pub report_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestationRequest {
    pub subject_id: String,
    pub committee_root: String,
    pub attestation_root: String,
    pub security_bits: u16,
    pub quorum_weight: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialSwapRequest {
    pub pool_id: String,
    pub direction: SwapDirection,
    pub trader_commitment: String,
    pub input_commitment: String,
    pub output_commitment: String,
    pub fee_commitment: String,
    pub nullifier: String,
    pub max_price_impact_bps: u64,
    pub fee_bps: u64,
    pub notional_fee_asset: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementRequest {
    pub pool_id: String,
    pub swap_id: String,
    pub settlement_root: String,
    pub reserve_delta_root: String,
    pub fee_paid_commitment: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateRequest {
    pub swap_id: String,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudgetRequest {
    pub operator_commitment: String,
    pub pool_id: String,
    pub disclosure_root: String,
    pub max_records: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummaryRequest {
    pub summary_height: u64,
    pub swap_count: u64,
    pub settled_count: u64,
    pub rebate_count: u64,
    pub safe_public_note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub pools: BTreeMap<String, AmmPool>,
    pub share_tokens: BTreeMap<String, HashrateShareToken>,
    pub oracle_reports: BTreeMap<String, OracleReport>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub confidential_swaps: BTreeMap<String, ConfidentialSwap>,
    pub settlements: BTreeMap<String, Settlement>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            pools: BTreeMap::new(),
            share_tokens: BTreeMap::new(),
            oracle_reports: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            confidential_swaps: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let oracle = state
            .publish_oracle_report(OracleReportRequest {
                pool_id: "bootstrap-randomx-pool".to_string(),
                committee_root: "devnet-pq-hashrate-oracle-committee-root".to_string(),
                observed_hashrate_th: 2_400_000,
                difficulty_commitment: "commitment:randomx-difficulty-devnet".to_string(),
                payout_index_commitment: "commitment:xmr-payout-index-devnet".to_string(),
                price_commitment: "commitment:hashrate-price-devnet".to_string(),
                quorum_weight: DEFAULT_ORACLE_QUORUM,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                report_height: DEVNET_HEIGHT,
            })
            .expect("devnet oracle report");
        let pool = state
            .create_pool(CreatePoolRequest {
                operator_commitment: "devnet-hashrate-amm-operator-root".to_string(),
                algorithm: HashrateAlgorithm::RandomX,
                fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                hashrate_asset_id: DEVNET_HASHRATE_UNIT_ASSET_ID.to_string(),
                fee_reserve_commitment: "commitment:fee-reserve-42-xmr".to_string(),
                hashrate_reserve_commitment: "commitment:hashrate-reserve-125000-th".to_string(),
                lp_supply_commitment: "commitment:lp-supply-private-devnet".to_string(),
                invariant_commitment: "commitment:constant-product-private-devnet".to_string(),
                oracle_report_id: oracle.report_id.clone(),
                min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
                max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
                fee_bps: DEFAULT_LOW_FEE_BPS,
                liquidity_fee_asset: 42_000_000_000_000,
                liquidity_hashrate_th: 125_000,
                opened_at_height: DEVNET_HEIGHT,
            })
            .expect("devnet pool");
        state
            .attest_pq_committee(PqAttestationRequest {
                subject_id: pool.pool_id.clone(),
                committee_root: "devnet-pq-hashrate-amm-committee-root".to_string(),
                attestation_root: "attestation:pool-operator-and-oracle-quorum".to_string(),
                security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                quorum_weight: DEFAULT_ORACLE_QUORUM,
                valid_from_height: DEVNET_HEIGHT,
                valid_until_height: DEVNET_HEIGHT + 720,
            })
            .expect("devnet pq attestation");
        state
            .mint_share_token(MintShareTokenRequest {
                pool_id: pool.pool_id.clone(),
                tranche_commitment: "commitment:weekly-randomx-tranche".to_string(),
                owner_commitment: "commitment:stealth-lp-owner".to_string(),
                algorithm: HashrateAlgorithm::RandomX,
                committed_hashrate_th: 12_500,
                maturity_height: DEVNET_HEIGHT + 720,
                redemption_commitment: "commitment:private-redemption-path".to_string(),
            })
            .expect("devnet share token");
        let swap = state
            .quote_confidential_swap(ConfidentialSwapRequest {
                pool_id: pool.pool_id.clone(),
                direction: SwapDirection::FeeAssetForHashrate,
                trader_commitment: "commitment:stealth-trader".to_string(),
                input_commitment: "commitment:swap-input-fee-asset".to_string(),
                output_commitment: "commitment:swap-output-hashrate-share".to_string(),
                fee_commitment: "commitment:low-fee-swap-fee".to_string(),
                nullifier: "nullifier:devnet-swap-001".to_string(),
                max_price_impact_bps: 80,
                fee_bps: DEFAULT_LOW_FEE_BPS,
                notional_fee_asset: 1_000_000_000_000,
                created_at_height: DEVNET_HEIGHT + 1,
            })
            .expect("devnet swap");
        state
            .settle_swap(SettlementRequest {
                pool_id: pool.pool_id.clone(),
                swap_id: swap.swap_id.clone(),
                settlement_root: "settlement:swap-001-root".to_string(),
                reserve_delta_root: "reserve-delta:swap-001-root".to_string(),
                fee_paid_commitment: "commitment:fee-paid-low-fee".to_string(),
                settled_at_height: DEVNET_HEIGHT + 2,
            })
            .expect("devnet settlement");
        state
            .publish_rebate(RebateRequest {
                swap_id: swap.swap_id.clone(),
                recipient_commitment: "commitment:stealth-trader-rebate".to_string(),
                rebate_commitment: "commitment:rebate-low-fee".to_string(),
                proof_root: "proof:recursive-low-fee-rebate".to_string(),
            })
            .expect("devnet rebate");
        state
            .open_redaction_budget(RedactionBudgetRequest {
                operator_commitment: pool.operator_commitment.clone(),
                pool_id: pool.pool_id.clone(),
                disclosure_root: "redaction:operator-safe-disclosure-root".to_string(),
                max_records: 64,
            })
            .expect("devnet redaction budget");
        state
            .publish_operator_summary(
                &pool.pool_id,
                OperatorSummaryRequest {
                    summary_height: DEVNET_HEIGHT + 3,
                    swap_count: 1,
                    settled_count: 1,
                    rebate_count: 1,
                    safe_public_note:
                        "roots-only liquidity healthy; no trader or miner identifiers".to_string(),
                },
            )
            .expect("devnet operator summary");
        state.refresh_public_records();
        state
    }

    pub fn create_pool(&mut self, request: CreatePoolRequest) -> Result<AmmPool> {
        ensure_non_empty("operator commitment", &request.operator_commitment)?;
        ensure_non_empty("fee reserve commitment", &request.fee_reserve_commitment)?;
        ensure_non_empty(
            "hashrate reserve commitment",
            &request.hashrate_reserve_commitment,
        )?;
        require(
            request.fee_bps <= self.config.max_user_fee_bps,
            "pool fee above max",
        )?;
        require(
            request.max_price_impact_bps <= self.config.max_price_impact_bps,
            "pool price impact guard too loose",
        )?;
        require(
            coverage_bps(request.liquidity_fee_asset, request.liquidity_hashrate_th)
                >= request.min_liquidity_coverage_bps,
            "liquidity coverage below safeguard",
        )?;
        let pool = AmmPool::new(request);
        self.counters.pools += 1;
        self.counters.total_liquidity_fee_asset = self
            .counters
            .total_liquidity_fee_asset
            .saturating_add(pool.liquidity_fee_asset);
        self.counters.total_liquidity_hashrate_th = self
            .counters
            .total_liquidity_hashrate_th
            .saturating_add(pool.liquidity_hashrate_th);
        self.public_records
            .insert(format!("pool:{}", pool.pool_id), pool.public_record());
        self.pools.insert(pool.pool_id.clone(), pool.clone());
        self.refresh_public_records();
        Ok(pool)
    }

    pub fn mint_share_token(
        &mut self,
        request: MintShareTokenRequest,
    ) -> Result<HashrateShareToken> {
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "pool missing for share token".to_string())?;
        require(
            pool.status.accepts_liquidity(),
            "pool not accepting liquidity",
        )?;
        require(
            request.committed_hashrate_th > 0,
            "committed hashrate is zero",
        )?;
        ensure_non_empty("owner commitment", &request.owner_commitment)?;
        let token = HashrateShareToken::new(request);
        self.counters.share_tokens += 1;
        self.public_records.insert(
            format!("share_token:{}", token.token_id),
            token.public_record(),
        );
        self.share_tokens
            .insert(token.token_id.clone(), token.clone());
        self.refresh_public_records();
        Ok(token)
    }

    pub fn publish_oracle_report(&mut self, request: OracleReportRequest) -> Result<OracleReport> {
        ensure_non_empty("committee root", &request.committee_root)?;
        require(
            request.quorum_weight >= self.config.oracle_quorum,
            "oracle quorum below threshold",
        )?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "oracle pq security below threshold",
        )?;
        let report = OracleReport::new(request, &self.config);
        self.counters.oracle_reports += 1;
        self.public_records.insert(
            format!("oracle:{}", report.report_id),
            report.public_record(),
        );
        self.oracle_reports
            .insert(report.report_id.clone(), report.clone());
        self.refresh_public_records();
        Ok(report)
    }

    pub fn attest_pq_committee(&mut self, request: PqAttestationRequest) -> Result<PqAttestation> {
        ensure_non_empty("attestation root", &request.attestation_root)?;
        require(
            request.security_bits >= self.config.min_pq_security_bits,
            "pq attestation below security floor",
        )?;
        require(
            request.quorum_weight >= self.config.oracle_quorum,
            "pq attestation quorum below threshold",
        )?;
        let attestation = PqAttestation::new(request);
        self.counters.pq_attestations += 1;
        self.public_records.insert(
            format!("pq_attestation:{}", attestation.attestation_id),
            attestation.public_record(),
        );
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.refresh_public_records();
        Ok(attestation)
    }

    pub fn quote_confidential_swap(
        &mut self,
        request: ConfidentialSwapRequest,
    ) -> Result<ConfidentialSwap> {
        ensure_non_empty("trader commitment", &request.trader_commitment)?;
        ensure_non_empty("swap nullifier", &request.nullifier)?;
        require(
            !self.nullifiers.contains(&request.nullifier),
            "swap nullifier reused",
        )?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "pool missing for swap".to_string())?;
        require(pool.status.accepts_swaps(), "pool not accepting swaps")?;
        require(
            request.max_price_impact_bps <= pool.max_price_impact_bps,
            "swap price impact exceeds pool safeguard",
        )?;
        require(
            request.fee_bps <= self.config.max_user_fee_bps,
            "swap fee above max",
        )?;
        let report = self
            .oracle_reports
            .get(&pool.oracle_report_id)
            .ok_or_else(|| "pool oracle report missing".to_string())?;
        require(
            request.created_at_height <= report.expires_at_height,
            "pool oracle report stale",
        )?;
        let swap = ConfidentialSwap::new(request, &self.config, pool);
        self.nullifiers.insert(swap.nullifier.clone());
        self.counters.confidential_swaps += 1;
        self.counters.accepted_flows += 1;
        self.counters.total_swap_notional_fee_asset = self
            .counters
            .total_swap_notional_fee_asset
            .saturating_add(swap.notional_fee_asset);
        self.public_records
            .insert(format!("swap:{}", swap.swap_id), swap.public_record());
        self.confidential_swaps
            .insert(swap.swap_id.clone(), swap.clone());
        self.refresh_public_records();
        Ok(swap)
    }

    pub fn settle_swap(&mut self, request: SettlementRequest) -> Result<Settlement> {
        let swap = self
            .confidential_swaps
            .get_mut(&request.swap_id)
            .ok_or_else(|| "swap missing for settlement".to_string())?;
        require(
            swap.status == FlowStatus::Accepted,
            "swap not settlement-ready",
        )?;
        require(
            request.settled_at_height <= swap.expires_at_height + self.config.settlement_ttl_blocks,
            "settlement expired",
        )?;
        swap.status = FlowStatus::Settled;
        let settlement = Settlement::new(request);
        self.counters.settlements += 1;
        self.public_records
            .insert(format!("swap:{}", swap.swap_id), swap.public_record());
        self.public_records.insert(
            format!("settlement:{}", settlement.settlement_id),
            settlement.public_record(),
        );
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        self.refresh_public_records();
        Ok(settlement)
    }

    pub fn publish_rebate(&mut self, request: RebateRequest) -> Result<LowFeeRebate> {
        let swap = self
            .confidential_swaps
            .get(&request.swap_id)
            .ok_or_else(|| "swap missing for rebate".to_string())?;
        require(
            swap.qualifies_for_rebate(&self.config),
            "swap does not qualify for rebate",
        )?;
        ensure_non_empty("rebate proof root", &request.proof_root)?;
        let rebate = LowFeeRebate::new(request, &self.config);
        self.counters.rebates += 1;
        self.public_records.insert(
            format!("rebate:{}", rebate.rebate_id),
            rebate.public_record(),
        );
        self.rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        self.refresh_public_records();
        Ok(rebate)
    }

    pub fn open_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        ensure_non_empty("operator commitment", &request.operator_commitment)?;
        require(request.max_records > 0, "redaction budget is zero")?;
        let budget = RedactionBudget::new(request, &self.config);
        self.counters.redaction_budgets += 1;
        self.public_records.insert(
            format!("redaction_budget:{}", budget.budget_id),
            budget.public_record(),
        );
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget.clone());
        self.refresh_public_records();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        pool_id: &str,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "pool missing for operator summary".to_string())?;
        ensure_non_empty("operator safe public note", &request.safe_public_note)?;
        let summary = OperatorSummary::new(request, pool);
        self.counters.operator_summaries += 1;
        self.public_records.insert(
            format!("operator_summary:{}", summary.summary_id),
            summary.public_record(),
        );
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary.clone());
        self.refresh_public_records();
        Ok(summary)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.state_root(),
            pool_root: map_root(
                "HASHRATE-AMM-POOL-ROOT",
                &self.pools,
                AmmPool::public_record,
            ),
            share_token_root: map_root(
                "HASHRATE-SHARE-TOKEN-ROOT",
                &self.share_tokens,
                HashrateShareToken::public_record,
            ),
            oracle_report_root: map_root(
                "HASHRATE-ORACLE-REPORT-ROOT",
                &self.oracle_reports,
                OracleReport::public_record,
            ),
            pq_attestation_root: map_root(
                "HASHRATE-PQ-ATTESTATION-ROOT",
                &self.pq_attestations,
                PqAttestation::public_record,
            ),
            swap_root: map_root(
                "CONFIDENTIAL-HASHRATE-SWAP-ROOT",
                &self.confidential_swaps,
                ConfidentialSwap::public_record,
            ),
            settlement_root: map_root(
                "HASHRATE-AMM-SETTLEMENT-ROOT",
                &self.settlements,
                Settlement::public_record,
            ),
            rebate_root: map_root(
                "HASHRATE-REBATE-ROOT",
                &self.rebates,
                LowFeeRebate::public_record,
            ),
            redaction_budget_root: map_root(
                "HASHRATE-REDACTION-BUDGET-ROOT",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summary_root: map_root(
                "HASHRATE-OPERATOR-SUMMARY-ROOT",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            nullifier_root: set_root("HASHRATE-AMM-NULLIFIER-ROOT", &self.nullifiers),
            public_record_root: value_map_root(
                "HASHRATE-AMM-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "kind": "private_l2_pq_confidential_tokenized_hashrate_liquidity_amm_state_roots",
            "protocol_version": PROTOCOL_VERSION,
            "config_root": roots.config_root,
            "pool_root": roots.pool_root,
            "share_token_root": roots.share_token_root,
            "oracle_report_root": roots.oracle_report_root,
            "pq_attestation_root": roots.pq_attestation_root,
            "swap_root": roots.swap_root,
            "settlement_root": roots.settlement_root,
            "rebate_root": roots.rebate_root,
            "redaction_budget_root": roots.redaction_budget_root,
            "operator_summary_root": roots.operator_summary_root,
            "nullifier_root": roots.nullifier_root,
            "public_record_root": roots.public_record_root,
            "counters_root": roots.counters_root,
        }));
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_tokenized_hashrate_liquidity_amm_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "privacy_scheme": PRIVACY_SCHEME,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn refresh_public_records(&mut self) {
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        self.counters.public_records = if self.public_records.contains_key("counters") {
            self.public_records.len() as u64
        } else {
            self.public_records.len().saturating_add(1) as u64
        };
        self.public_records
            .insert("counters".to_string(), self.counters.public_record());
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

pub fn private_l2_pq_confidential_tokenized_hashrate_liquidity_amm_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HASHRATE-LIQUIDITY-AMM-RUNTIME-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "nullifier": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn pool_root(pool: &AmmPool) -> String {
    state_root_from_record(&pool.public_record())
}

fn coverage_bps(fee_liquidity: u64, hashrate_liquidity: u64) -> u64 {
    if hashrate_liquidity == 0 {
        return 0;
    }
    fee_liquidity
        .saturating_div(hashrate_liquidity)
        .min(MAX_BPS.saturating_mul(100))
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    require(!value.trim().is_empty(), &format!("{label} empty"))
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(map) = record {
        map.insert(key.to_string(), value);
    }
}
