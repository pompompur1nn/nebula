use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedCarbonCreditForwardAmmRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenizedCarbonCreditForwardAmmRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CARBON_CREDIT_FORWARD_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-carbon-credit-forward-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CARBON_CREDIT_FORWARD_AMM_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CARBON_CREDIT_FORWARD_AMM_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CARBON_CREDIT_FORWARD_AMM_RUNTIME_SCHEMA_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-carbon-forward-amm-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_CARBON_REGISTRY: &str = "carbon-registry-devnet";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "asset:xusd-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero-devnet";
pub const CARBON_VINTAGE_SCHEME: &str = "confidential-tokenized-carbon-vintage-registry-root-v1";
pub const FORWARD_POOL_SCHEME: &str = "private-l2-pq-carbon-credit-forward-amm-pool-root-v1";
pub const ORACLE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-carbon-oracle-attestation-root-v1";
pub const SEALED_LIQUIDITY_SCHEME: &str = "ml-kem-1024-sealed-carbon-forward-liquidity-root-v1";
pub const MATURITY_SETTLEMENT_SCHEME: &str =
    "confidential-carbon-forward-maturity-settlement-root-v1";
pub const RISK_HAIRCUT_SCHEME: &str = "carbon-forward-risk-haircut-root-v1";
pub const FEE_REBATE_SCHEME: &str = "low-fee-carbon-forward-amm-fee-credit-rebate-root-v1";
pub const PRIVACY_REDACTION_SCHEME: &str = "view-key-safe-carbon-forward-amm-redaction-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-carbon-forward-amm-summary-root-v1";
pub const NULLIFIER_SCHEME: &str = "private-carbon-forward-amm-nullifier-root-v1";
pub const EVENT_SCHEME: &str = "roots-only-private-l2-pq-carbon-forward-amm-public-event-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_lp_identities_or_trade_sizes";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_PROTOCOL_FEE_BPS: u64 = 6;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ORACLE_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_VINTAGE_HAIRCUT_BPS: u64 = 4_500;
pub const DEFAULT_BASE_FORWARD_MARGIN_BPS: u64 = 1_200;
pub const DEFAULT_MAX_POOL_SKEW_BPS: u64 = 3_000;
pub const DEFAULT_MIN_LIQUIDITY_COMMITMENT: u64 = 25_000;
pub const DEFAULT_POOL_TTL_BLOCKS: u64 = 120_960;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_OPERATOR_BUCKET_SIZE: u64 = 64;
pub const MAX_CARBON_VINTAGES: usize = 524_288;
pub const MAX_FORWARD_POOLS: usize = 524_288;
pub const MAX_ORACLE_ATTESTATIONS: usize = 1_048_576;
pub const MAX_SEALED_LIQUIDITY: usize = 2_097_152;
pub const MAX_MATURITY_SETTLEMENTS: usize = 524_288;
pub const MAX_RISK_HAIRCUTS: usize = 1_048_576;
pub const MAX_FEE_REBATES: usize = 1_048_576;
pub const MAX_PRIVACY_REDACTIONS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const MAX_EVENTS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarbonStandard {
    VerraVcs,
    GoldStandard,
    ClimateActionReserve,
    AmericanCarbonRegistry,
    PlanVivo,
    Cdm,
    PuroEarth,
    InternalDevnet,
}

impl CarbonStandard {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerraVcs => "verra_vcs",
            Self::GoldStandard => "gold_standard",
            Self::ClimateActionReserve => "climate_action_reserve",
            Self::AmericanCarbonRegistry => "american_carbon_registry",
            Self::PlanVivo => "plan_vivo",
            Self::Cdm => "cdm",
            Self::PuroEarth => "puro_earth",
            Self::InternalDevnet => "internal_devnet",
        }
    }

    pub fn baseline_haircut_bps(self) -> u64 {
        match self {
            Self::GoldStandard => 650,
            Self::VerraVcs => 850,
            Self::ClimateActionReserve => 900,
            Self::AmericanCarbonRegistry => 950,
            Self::PuroEarth => 1_050,
            Self::PlanVivo => 1_250,
            Self::Cdm => 1_750,
            Self::InternalDevnet => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectType {
    AvoidedDeforestation,
    Reforestation,
    Biochar,
    DirectAirCapture,
    MethaneCapture,
    RenewableEnergy,
    SoilCarbon,
    BlueCarbon,
    IndustrialRemoval,
    Cookstoves,
}

impl ProjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AvoidedDeforestation => "avoided_deforestation",
            Self::Reforestation => "reforestation",
            Self::Biochar => "biochar",
            Self::DirectAirCapture => "direct_air_capture",
            Self::MethaneCapture => "methane_capture",
            Self::RenewableEnergy => "renewable_energy",
            Self::SoilCarbon => "soil_carbon",
            Self::BlueCarbon => "blue_carbon",
            Self::IndustrialRemoval => "industrial_removal",
            Self::Cookstoves => "cookstoves",
        }
    }

    pub fn delivery_risk_bps(self) -> u64 {
        match self {
            Self::DirectAirCapture => 350,
            Self::IndustrialRemoval => 500,
            Self::Biochar => 700,
            Self::BlueCarbon => 900,
            Self::MethaneCapture => 1_000,
            Self::Reforestation => 1_250,
            Self::SoilCarbon => 1_350,
            Self::AvoidedDeforestation => 1_500,
            Self::Cookstoves => 1_650,
            Self::RenewableEnergy => 1_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VintageStatus {
    Draft,
    RegistryPending,
    Tokenized,
    OracleAttested,
    ForwardEligible,
    DeliveryOnly,
    Retired,
    Suspended,
    Rejected,
}

impl VintageStatus {
    pub fn is_forward_eligible(self) -> bool {
        matches!(
            self,
            Self::OracleAttested | Self::ForwardEligible | Self::DeliveryOnly
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Retired | Self::Suspended | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Active,
    QuoteOnly,
    Matured,
    SettlementPending,
    Settled,
    Paused,
    Frozen,
    Retired,
}

impl PoolStatus {
    pub fn accepts_trades(self) -> bool {
        matches!(self, Self::Active | Self::QuoteOnly)
    }

    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Draft | Self::Active)
    }

    pub fn requires_settlement(self) -> bool {
        matches!(self, Self::Matured | Self::SettlementPending)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardSide {
    LongCarbon,
    ShortCarbon,
    LiquidityProvider,
    SettlementMaker,
}

impl ForwardSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongCarbon => "long_carbon",
            Self::ShortCarbon => "short_carbon",
            Self::LiquidityProvider => "liquidity_provider",
            Self::SettlementMaker => "settlement_maker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Superseded,
    Revoked,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityStatus {
    Committed,
    Opened,
    Active,
    Rebalanced,
    WithdrawPending,
    Settled,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Locked,
    Netting,
    DeliveryPosted,
    CashSettled,
    RetiredOnRegistry,
    Finalized,
    Disputed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Requested,
    Approved,
    Applied,
    Exhausted,
    Revoked,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAudience {
    Operator,
    Oracle,
    LiquidityProvider,
    MarketMaker,
    Compliance,
    Sponsor,
    Public,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    VintageRegistered,
    VintageAttested,
    PoolCreated,
    QuoteUpdated,
    LiquiditySealed,
    LiquidityOpened,
    TradeCommitted,
    HaircutUpdated,
    MaturityLocked,
    SettlementFinalized,
    RebateIssued,
    RedactionApplied,
    SummaryPublished,
    NullifierObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub carbon_registry: String,
    pub settlement_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub target_fee_rebate_bps: u64,
    pub oracle_quorum_bps: u64,
    pub strong_oracle_quorum_bps: u64,
    pub max_vintage_haircut_bps: u64,
    pub base_forward_margin_bps: u64,
    pub max_pool_skew_bps: u64,
    pub min_liquidity_commitment: u64,
    pub pool_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub operator_bucket_size: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            carbon_registry: DEVNET_CARBON_REGISTRY.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_protocol_fee_bps: DEFAULT_MAX_PROTOCOL_FEE_BPS,
            target_fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            oracle_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            strong_oracle_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            max_vintage_haircut_bps: DEFAULT_MAX_VINTAGE_HAIRCUT_BPS,
            base_forward_margin_bps: DEFAULT_BASE_FORWARD_MARGIN_BPS,
            max_pool_skew_bps: DEFAULT_MAX_POOL_SKEW_BPS,
            min_liquidity_commitment: DEFAULT_MIN_LIQUIDITY_COMMITMENT,
            pool_ttl_blocks: DEFAULT_POOL_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            operator_bucket_size: DEFAULT_OPERATOR_BUCKET_SIZE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain_id does not match runtime CHAIN_ID".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("config protocol_version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("config schema_version mismatch".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("config min_pq_security_bits below runtime floor".to_string());
        }
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("max_protocol_fee_bps", self.max_protocol_fee_bps)?;
        ensure_bps("target_fee_rebate_bps", self.target_fee_rebate_bps)?;
        ensure_bps("oracle_quorum_bps", self.oracle_quorum_bps)?;
        ensure_bps("strong_oracle_quorum_bps", self.strong_oracle_quorum_bps)?;
        ensure_bps("max_vintage_haircut_bps", self.max_vintage_haircut_bps)?;
        ensure_bps("base_forward_margin_bps", self.base_forward_margin_bps)?;
        ensure_bps("max_pool_skew_bps", self.max_pool_skew_bps)?;
        if self.oracle_quorum_bps > self.strong_oracle_quorum_bps {
            return Err("oracle quorum exceeds strong quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "carbon_registry": self.carbon_registry,
            "settlement_asset_id": self.settlement_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_protocol_fee_bps": self.max_protocol_fee_bps,
            "target_fee_rebate_bps": self.target_fee_rebate_bps,
            "oracle_quorum_bps": self.oracle_quorum_bps,
            "strong_oracle_quorum_bps": self.strong_oracle_quorum_bps,
            "max_vintage_haircut_bps": self.max_vintage_haircut_bps,
            "base_forward_margin_bps": self.base_forward_margin_bps,
            "max_pool_skew_bps": self.max_pool_skew_bps,
            "min_liquidity_commitment": self.min_liquidity_commitment,
            "pool_ttl_blocks": self.pool_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "oracle_ttl_blocks": self.oracle_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "operator_bucket_size": self.operator_bucket_size,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub carbon_vintages: u64,
    pub forward_pools: u64,
    pub oracle_attestations: u64,
    pub sealed_liquidity: u64,
    pub maturity_settlements: u64,
    pub risk_haircuts: u64,
    pub fee_rebates: u64,
    pub privacy_redactions: u64,
    pub operator_summaries: u64,
    pub nullifiers: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "carbon_vintages": self.carbon_vintages,
            "forward_pools": self.forward_pools,
            "oracle_attestations": self.oracle_attestations,
            "sealed_liquidity": self.sealed_liquidity,
            "maturity_settlements": self.maturity_settlements,
            "risk_haircuts": self.risk_haircuts,
            "fee_rebates": self.fee_rebates,
            "privacy_redactions": self.privacy_redactions,
            "operator_summaries": self.operator_summaries,
            "nullifiers": self.nullifiers,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub carbon_vintage_root: String,
    pub forward_pool_root: String,
    pub oracle_attestation_root: String,
    pub sealed_liquidity_root: String,
    pub maturity_settlement_root: String,
    pub risk_haircut_root: String,
    pub fee_rebate_root: String,
    pub privacy_redaction_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "carbon_vintage_root": self.carbon_vintage_root,
            "forward_pool_root": self.forward_pool_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "sealed_liquidity_root": self.sealed_liquidity_root,
            "maturity_settlement_root": self.maturity_settlement_root,
            "risk_haircut_root": self.risk_haircut_root,
            "fee_rebate_root": self.fee_rebate_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CarbonVintage {
    pub vintage_id: String,
    pub registry_project_id: String,
    pub token_asset_id: String,
    pub standard: CarbonStandard,
    pub project_type: ProjectType,
    pub country_code: String,
    pub vintage_year: u16,
    pub delivery_start_height: u64,
    pub delivery_deadline_height: u64,
    pub issued_tonnes_commitment: String,
    pub available_tonnes_commitment: String,
    pub retired_tonnes_commitment: String,
    pub permanence_buffer_bps: u64,
    pub baseline_haircut_bps: u64,
    pub oracle_price_commitment: String,
    pub registry_anchor: String,
    pub metadata_commitment: String,
    pub privacy_set_size: u64,
    pub status: VintageStatus,
}

impl CarbonVintage {
    pub fn devnet(
        label: &str,
        sequence: u64,
        standard: CarbonStandard,
        project_type: ProjectType,
    ) -> Self {
        let vintage_year = 2027 + sequence as u16;
        let baseline_haircut_bps =
            clamp_bps(standard.baseline_haircut_bps() + project_type.delivery_risk_bps() / 2);
        Self {
            vintage_id: format!("ccv:{label}:{sequence:04}"),
            registry_project_id: format!("devnet-carbon-project-{sequence:04}"),
            token_asset_id: format!("asset:carbon:{label}:{vintage_year}"),
            standard,
            project_type,
            country_code: "US".to_string(),
            vintage_year,
            delivery_start_height: 2_300_000 + sequence * 10_080,
            delivery_deadline_height: 2_420_960 + sequence * 10_080,
            issued_tonnes_commitment: commitment("issued-tonnes", label, sequence),
            available_tonnes_commitment: commitment("available-tonnes", label, sequence),
            retired_tonnes_commitment: commitment("retired-tonnes", label, sequence),
            permanence_buffer_bps: 1_000 + sequence * 25,
            baseline_haircut_bps,
            oracle_price_commitment: commitment("oracle-price", label, sequence),
            registry_anchor: root_hex(
                "registry-anchor",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            metadata_commitment: commitment("metadata", label, sequence),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE + sequence * 1_024,
            status: VintageStatus::ForwardEligible,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.vintage_id.is_empty() {
            return Err("carbon vintage missing vintage_id".to_string());
        }
        if self.delivery_start_height >= self.delivery_deadline_height {
            return Err(format!(
                "carbon vintage {} has invalid delivery window",
                self.vintage_id
            ));
        }
        ensure_bps("permanence_buffer_bps", self.permanence_buffer_bps)?;
        ensure_bps("baseline_haircut_bps", self.baseline_haircut_bps)?;
        if self.baseline_haircut_bps > config.max_vintage_haircut_bps {
            return Err(format!(
                "carbon vintage {} exceeds max haircut",
                self.vintage_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "carbon vintage {} below privacy set floor",
                self.vintage_id
            ));
        }
        Ok(())
    }

    pub fn effective_delivery_haircut_bps(&self) -> u64 {
        clamp_bps(self.baseline_haircut_bps + self.permanence_buffer_bps / 4)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vintage_id": self.vintage_id,
            "registry_project_id": self.registry_project_id,
            "token_asset_id": self.token_asset_id,
            "standard": self.standard.as_str(),
            "project_type": self.project_type.as_str(),
            "country_code": self.country_code,
            "vintage_year": self.vintage_year,
            "delivery_start_height": self.delivery_start_height,
            "delivery_deadline_height": self.delivery_deadline_height,
            "issued_tonnes_commitment": self.issued_tonnes_commitment,
            "available_tonnes_commitment": self.available_tonnes_commitment,
            "retired_tonnes_commitment": self.retired_tonnes_commitment,
            "permanence_buffer_bps": self.permanence_buffer_bps,
            "baseline_haircut_bps": self.baseline_haircut_bps,
            "effective_delivery_haircut_bps": self.effective_delivery_haircut_bps(),
            "oracle_price_commitment": self.oracle_price_commitment,
            "registry_anchor": self.registry_anchor,
            "metadata_commitment": self.metadata_commitment,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForwardAmmPool {
    pub pool_id: String,
    pub vintage_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub maturity_height: u64,
    pub oracle_price_commitment: String,
    pub invariant_commitment: String,
    pub base_reserve_commitment: String,
    pub quote_reserve_commitment: String,
    pub virtual_base_reserve_commitment: String,
    pub virtual_quote_reserve_commitment: String,
    pub lp_token_asset_id: String,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub rebate_bps: u64,
    pub risk_haircut_bps: u64,
    pub forward_margin_bps: u64,
    pub max_skew_bps: u64,
    pub privacy_set_size: u64,
    pub status: PoolStatus,
}

impl ForwardAmmPool {
    pub fn devnet(vintage: &CarbonVintage, sequence: u64, config: &Config) -> Self {
        let pool_id = format!("cfamm:{}:{sequence:04}", vintage.vintage_id);
        Self {
            pool_id: pool_id.clone(),
            vintage_id: vintage.vintage_id.clone(),
            base_asset_id: vintage.token_asset_id.clone(),
            quote_asset_id: config.settlement_asset_id.clone(),
            maturity_height: vintage.delivery_deadline_height,
            oracle_price_commitment: vintage.oracle_price_commitment.clone(),
            invariant_commitment: commitment("pool-invariant", &pool_id, sequence),
            base_reserve_commitment: commitment("base-reserve", &pool_id, sequence),
            quote_reserve_commitment: commitment("quote-reserve", &pool_id, sequence),
            virtual_base_reserve_commitment: commitment("virtual-base", &pool_id, sequence),
            virtual_quote_reserve_commitment: commitment("virtual-quote", &pool_id, sequence),
            lp_token_asset_id: format!("asset:lp:{pool_id}"),
            fee_bps: config.max_user_fee_bps.saturating_sub(2),
            protocol_fee_bps: config.max_protocol_fee_bps,
            rebate_bps: config.target_fee_rebate_bps,
            risk_haircut_bps: vintage.effective_delivery_haircut_bps(),
            forward_margin_bps: config.base_forward_margin_bps,
            max_skew_bps: config.max_pool_skew_bps,
            privacy_set_size: config.target_privacy_set_size + sequence * 2_048,
            status: PoolStatus::Active,
        }
    }

    pub fn validate(
        &self,
        config: &Config,
        vintages: &BTreeMap<String, CarbonVintage>,
    ) -> Result<()> {
        if self.pool_id.is_empty() {
            return Err("forward pool missing pool_id".to_string());
        }
        let vintage = vintages
            .get(&self.vintage_id)
            .ok_or_else(|| format!("forward pool {} references unknown vintage", self.pool_id))?;
        if !vintage.status.is_forward_eligible() {
            return Err(format!(
                "forward pool {} references ineligible vintage",
                self.pool_id
            ));
        }
        if self.maturity_height > vintage.delivery_deadline_height {
            return Err(format!(
                "forward pool {} matures after delivery deadline",
                self.pool_id
            ));
        }
        ensure_bps("fee_bps", self.fee_bps)?;
        ensure_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        ensure_bps("risk_haircut_bps", self.risk_haircut_bps)?;
        ensure_bps("forward_margin_bps", self.forward_margin_bps)?;
        ensure_bps("max_skew_bps", self.max_skew_bps)?;
        if self.fee_bps > config.max_user_fee_bps {
            return Err(format!(
                "forward pool {} fee exceeds user cap",
                self.pool_id
            ));
        }
        if self.protocol_fee_bps > config.max_protocol_fee_bps {
            return Err(format!(
                "forward pool {} protocol fee exceeds cap",
                self.pool_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "forward pool {} below privacy set floor",
                self.pool_id
            ));
        }
        Ok(())
    }

    pub fn net_user_fee_bps(&self) -> u64 {
        self.fee_bps.saturating_sub(self.rebate_bps)
    }

    pub fn settlement_margin_bps(&self) -> u64 {
        clamp_bps(self.risk_haircut_bps + self.forward_margin_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "vintage_id": self.vintage_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "maturity_height": self.maturity_height,
            "oracle_price_commitment": self.oracle_price_commitment,
            "invariant_commitment": self.invariant_commitment,
            "base_reserve_commitment": self.base_reserve_commitment,
            "quote_reserve_commitment": self.quote_reserve_commitment,
            "virtual_base_reserve_commitment": self.virtual_base_reserve_commitment,
            "virtual_quote_reserve_commitment": self.virtual_quote_reserve_commitment,
            "lp_token_asset_id": self.lp_token_asset_id,
            "fee_bps": self.fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "rebate_bps": self.rebate_bps,
            "net_user_fee_bps": self.net_user_fee_bps(),
            "risk_haircut_bps": self.risk_haircut_bps,
            "forward_margin_bps": self.forward_margin_bps,
            "settlement_margin_bps": self.settlement_margin_bps(),
            "max_skew_bps": self.max_skew_bps,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleVerificationAttestation {
    pub attestation_id: String,
    pub vintage_id: String,
    pub oracle_set_id: String,
    pub signer_commitment_root: String,
    pub signature_bundle_commitment: String,
    pub registry_anchor: String,
    pub price_commitment: String,
    pub delivery_probability_bps: u64,
    pub permanence_score_bps: u64,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub observed_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl OracleVerificationAttestation {
    pub fn devnet(vintage: &CarbonVintage, sequence: u64, config: &Config) -> Self {
        let attestation_id = format!("coa:{}:{sequence:04}", vintage.vintage_id);
        Self {
            attestation_id: attestation_id.clone(),
            vintage_id: vintage.vintage_id.clone(),
            oracle_set_id: "carbon-oracle-committee-devnet".to_string(),
            signer_commitment_root: root_hex("oracle-signers", &[HashPart::Str(&attestation_id)]),
            signature_bundle_commitment: commitment("oracle-signatures", &attestation_id, sequence),
            registry_anchor: vintage.registry_anchor.clone(),
            price_commitment: vintage.oracle_price_commitment.clone(),
            delivery_probability_bps: 8_800u64.saturating_sub(sequence * 50),
            permanence_score_bps: 8_500u64.saturating_sub(sequence * 35),
            quorum_weight_bps: config.strong_oracle_quorum_bps,
            pq_security_bits: config.min_pq_security_bits,
            observed_height: vintage.delivery_start_height.saturating_sub(14_400),
            expires_at_height: vintage.delivery_start_height.saturating_sub(14_400)
                + config.oracle_ttl_blocks,
            status: AttestationStatus::StrongQuorum,
        }
    }

    pub fn validate(
        &self,
        config: &Config,
        vintages: &BTreeMap<String, CarbonVintage>,
    ) -> Result<()> {
        if !vintages.contains_key(&self.vintage_id) {
            return Err(format!(
                "oracle attestation {} references unknown vintage",
                self.attestation_id
            ));
        }
        ensure_bps("delivery_probability_bps", self.delivery_probability_bps)?;
        ensure_bps("permanence_score_bps", self.permanence_score_bps)?;
        ensure_bps("quorum_weight_bps", self.quorum_weight_bps)?;
        if self.quorum_weight_bps < config.oracle_quorum_bps {
            return Err(format!(
                "oracle attestation {} below quorum",
                self.attestation_id
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "oracle attestation {} below PQ security floor",
                self.attestation_id
            ));
        }
        if self.observed_height >= self.expires_at_height {
            return Err(format!(
                "oracle attestation {} has invalid ttl",
                self.attestation_id
            ));
        }
        Ok(())
    }

    pub fn confidence_bps(&self) -> u64 {
        (self.delivery_probability_bps + self.permanence_score_bps + self.quorum_weight_bps) / 3
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "vintage_id": self.vintage_id,
            "oracle_set_id": self.oracle_set_id,
            "signer_commitment_root": self.signer_commitment_root,
            "signature_bundle_commitment": self.signature_bundle_commitment,
            "registry_anchor": self.registry_anchor,
            "price_commitment": self.price_commitment,
            "delivery_probability_bps": self.delivery_probability_bps,
            "permanence_score_bps": self.permanence_score_bps,
            "quorum_weight_bps": self.quorum_weight_bps,
            "confidence_bps": self.confidence_bps(),
            "pq_security_bits": self.pq_security_bits,
            "observed_height": self.observed_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedLiquidityPosition {
    pub position_id: String,
    pub pool_id: String,
    pub lp_commitment: String,
    pub sealed_amount_commitment: String,
    pub sealed_range_proof_root: String,
    pub encrypted_note_ciphertext_root: String,
    pub entry_price_commitment: String,
    pub side: ForwardSide,
    pub min_commitment: u64,
    pub fee_credit_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: LiquidityStatus,
}

impl SealedLiquidityPosition {
    pub fn devnet(pool: &ForwardAmmPool, sequence: u64, config: &Config) -> Self {
        let position_id = format!("slp:{}:{sequence:04}", pool.pool_id);
        Self {
            position_id: position_id.clone(),
            pool_id: pool.pool_id.clone(),
            lp_commitment: commitment("lp-identity", &position_id, sequence),
            sealed_amount_commitment: commitment("sealed-liquidity", &position_id, sequence),
            sealed_range_proof_root: root_hex(
                "liquidity-range-proof",
                &[HashPart::Str(&position_id)],
            ),
            encrypted_note_ciphertext_root: root_hex(
                "liquidity-ciphertexts",
                &[HashPart::Str(&position_id)],
            ),
            entry_price_commitment: pool.oracle_price_commitment.clone(),
            side: ForwardSide::LiquidityProvider,
            min_commitment: config.min_liquidity_commitment + sequence * 5_000,
            fee_credit_bps: config.target_fee_rebate_bps,
            privacy_set_size: config.target_privacy_set_size + sequence * 1_024,
            opened_at_height: pool.maturity_height.saturating_sub(86_400),
            expires_at_height: pool.maturity_height + config.settlement_ttl_blocks,
            status: LiquidityStatus::Active,
        }
    }

    pub fn validate(
        &self,
        config: &Config,
        pools: &BTreeMap<String, ForwardAmmPool>,
    ) -> Result<()> {
        if !pools.contains_key(&self.pool_id) {
            return Err(format!(
                "sealed liquidity {} references unknown pool",
                self.position_id
            ));
        }
        if self.min_commitment < config.min_liquidity_commitment {
            return Err(format!(
                "sealed liquidity {} below min commitment",
                self.position_id
            ));
        }
        ensure_bps("fee_credit_bps", self.fee_credit_bps)?;
        if self.fee_credit_bps > config.max_user_fee_bps {
            return Err(format!(
                "sealed liquidity {} fee credit too large",
                self.position_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "sealed liquidity {} below privacy set floor",
                self.position_id
            ));
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err(format!("sealed liquidity {} invalid ttl", self.position_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "pool_id": self.pool_id,
            "lp_commitment": self.lp_commitment,
            "sealed_amount_commitment": self.sealed_amount_commitment,
            "sealed_range_proof_root": self.sealed_range_proof_root,
            "encrypted_note_ciphertext_root": self.encrypted_note_ciphertext_root,
            "entry_price_commitment": self.entry_price_commitment,
            "side": self.side.as_str(),
            "min_commitment": self.min_commitment,
            "fee_credit_bps": self.fee_credit_bps,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaturitySettlement {
    pub settlement_id: String,
    pub pool_id: String,
    pub settlement_batch_root: String,
    pub delivered_tonnes_commitment: String,
    pub cash_settlement_commitment: String,
    pub registry_retirement_anchor: String,
    pub lp_payout_commitment_root: String,
    pub trader_payout_commitment_root: String,
    pub protocol_fee_commitment: String,
    pub rebate_commitment_root: String,
    pub settlement_price_commitment: String,
    pub settlement_height: u64,
    pub finality_height: u64,
    pub status: SettlementStatus,
}

impl MaturitySettlement {
    pub fn devnet(pool: &ForwardAmmPool, sequence: u64, config: &Config) -> Self {
        let settlement_id = format!("mst:{}:{sequence:04}", pool.pool_id);
        Self {
            settlement_id: settlement_id.clone(),
            pool_id: pool.pool_id.clone(),
            settlement_batch_root: root_hex("maturity-batch", &[HashPart::Str(&settlement_id)]),
            delivered_tonnes_commitment: commitment("delivered-tonnes", &settlement_id, sequence),
            cash_settlement_commitment: commitment("cash-settlement", &settlement_id, sequence),
            registry_retirement_anchor: root_hex(
                "registry-retirement",
                &[HashPart::Str(&settlement_id)],
            ),
            lp_payout_commitment_root: root_hex("lp-payouts", &[HashPart::Str(&settlement_id)]),
            trader_payout_commitment_root: root_hex(
                "trader-payouts",
                &[HashPart::Str(&settlement_id)],
            ),
            protocol_fee_commitment: commitment("protocol-fee", &settlement_id, sequence),
            rebate_commitment_root: root_hex(
                "settlement-rebates",
                &[HashPart::Str(&settlement_id)],
            ),
            settlement_price_commitment: pool.oracle_price_commitment.clone(),
            settlement_height: pool.maturity_height + sequence * 12,
            finality_height: pool.maturity_height
                + sequence * 12
                + config.settlement_ttl_blocks / 4,
            status: SettlementStatus::Finalized,
        }
    }

    pub fn validate(
        &self,
        config: &Config,
        pools: &BTreeMap<String, ForwardAmmPool>,
    ) -> Result<()> {
        let pool = pools.get(&self.pool_id).ok_or_else(|| {
            format!(
                "maturity settlement {} references unknown pool",
                self.settlement_id
            )
        })?;
        if self.settlement_height < pool.maturity_height {
            return Err(format!(
                "maturity settlement {} before maturity",
                self.settlement_id
            ));
        }
        if self.finality_height < self.settlement_height {
            return Err(format!(
                "maturity settlement {} invalid finality",
                self.settlement_id
            ));
        }
        if self.finality_height > self.settlement_height + config.settlement_ttl_blocks {
            return Err(format!(
                "maturity settlement {} exceeds settlement ttl",
                self.settlement_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "pool_id": self.pool_id,
            "settlement_batch_root": self.settlement_batch_root,
            "delivered_tonnes_commitment": self.delivered_tonnes_commitment,
            "cash_settlement_commitment": self.cash_settlement_commitment,
            "registry_retirement_anchor": self.registry_retirement_anchor,
            "lp_payout_commitment_root": self.lp_payout_commitment_root,
            "trader_payout_commitment_root": self.trader_payout_commitment_root,
            "protocol_fee_commitment": self.protocol_fee_commitment,
            "rebate_commitment_root": self.rebate_commitment_root,
            "settlement_price_commitment": self.settlement_price_commitment,
            "settlement_height": self.settlement_height,
            "finality_height": self.finality_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskHaircut {
    pub haircut_id: String,
    pub vintage_id: String,
    pub pool_id: String,
    pub oracle_attestation_id: String,
    pub standard_haircut_bps: u64,
    pub project_haircut_bps: u64,
    pub delivery_haircut_bps: u64,
    pub liquidity_haircut_bps: u64,
    pub forward_maturity_haircut_bps: u64,
    pub aggregate_haircut_bps: u64,
    pub stress_scenario_root: String,
    pub model_commitment: String,
    pub effective_at_height: u64,
}

impl RiskHaircut {
    pub fn devnet(
        vintage: &CarbonVintage,
        pool: &ForwardAmmPool,
        attestation: &OracleVerificationAttestation,
        sequence: u64,
    ) -> Self {
        let haircut_id = format!("rhc:{}:{sequence:04}", pool.pool_id);
        let standard_haircut_bps = vintage.standard.baseline_haircut_bps();
        let project_haircut_bps = vintage.project_type.delivery_risk_bps();
        let delivery_haircut_bps = MAX_BPS.saturating_sub(attestation.confidence_bps()) / 3;
        let liquidity_haircut_bps = pool.max_skew_bps / 5;
        let forward_maturity_haircut_bps = pool.forward_margin_bps / 2;
        let aggregate_haircut_bps = clamp_bps(
            standard_haircut_bps
                + project_haircut_bps
                + delivery_haircut_bps
                + liquidity_haircut_bps
                + forward_maturity_haircut_bps,
        );
        Self {
            haircut_id: haircut_id.clone(),
            vintage_id: vintage.vintage_id.clone(),
            pool_id: pool.pool_id.clone(),
            oracle_attestation_id: attestation.attestation_id.clone(),
            standard_haircut_bps,
            project_haircut_bps,
            delivery_haircut_bps,
            liquidity_haircut_bps,
            forward_maturity_haircut_bps,
            aggregate_haircut_bps,
            stress_scenario_root: root_hex(
                "carbon-stress-scenarios",
                &[HashPart::Str(&haircut_id)],
            ),
            model_commitment: commitment("risk-model", &haircut_id, sequence),
            effective_at_height: attestation.observed_height + 1,
        }
    }

    pub fn validate(
        &self,
        config: &Config,
        vintages: &BTreeMap<String, CarbonVintage>,
        pools: &BTreeMap<String, ForwardAmmPool>,
        attestations: &BTreeMap<String, OracleVerificationAttestation>,
    ) -> Result<()> {
        if !vintages.contains_key(&self.vintage_id) {
            return Err(format!(
                "risk haircut {} references unknown vintage",
                self.haircut_id
            ));
        }
        if !pools.contains_key(&self.pool_id) {
            return Err(format!(
                "risk haircut {} references unknown pool",
                self.haircut_id
            ));
        }
        if !attestations.contains_key(&self.oracle_attestation_id) {
            return Err(format!(
                "risk haircut {} references unknown oracle attestation",
                self.haircut_id
            ));
        }
        for (name, value) in [
            ("standard_haircut_bps", self.standard_haircut_bps),
            ("project_haircut_bps", self.project_haircut_bps),
            ("delivery_haircut_bps", self.delivery_haircut_bps),
            ("liquidity_haircut_bps", self.liquidity_haircut_bps),
            (
                "forward_maturity_haircut_bps",
                self.forward_maturity_haircut_bps,
            ),
            ("aggregate_haircut_bps", self.aggregate_haircut_bps),
        ] {
            ensure_bps(name, value)?;
        }
        if self.aggregate_haircut_bps > config.max_vintage_haircut_bps {
            return Err(format!(
                "risk haircut {} exceeds configured maximum",
                self.haircut_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "haircut_id": self.haircut_id,
            "vintage_id": self.vintage_id,
            "pool_id": self.pool_id,
            "oracle_attestation_id": self.oracle_attestation_id,
            "standard_haircut_bps": self.standard_haircut_bps,
            "project_haircut_bps": self.project_haircut_bps,
            "delivery_haircut_bps": self.delivery_haircut_bps,
            "liquidity_haircut_bps": self.liquidity_haircut_bps,
            "forward_maturity_haircut_bps": self.forward_maturity_haircut_bps,
            "aggregate_haircut_bps": self.aggregate_haircut_bps,
            "stress_scenario_root": self.stress_scenario_root,
            "model_commitment": self.model_commitment,
            "effective_at_height": self.effective_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub pool_id: String,
    pub beneficiary_commitment: String,
    pub fee_epoch: u64,
    pub gross_fee_commitment: String,
    pub rebate_commitment: String,
    pub sponsor_commitment: String,
    pub rebate_bps: u64,
    pub claim_nullifier: String,
    pub expires_at_height: u64,
}

impl FeeCreditRebate {
    pub fn devnet(pool: &ForwardAmmPool, sequence: u64, config: &Config) -> Self {
        let rebate_id = format!("fcr:{}:{sequence:04}", pool.pool_id);
        Self {
            rebate_id: rebate_id.clone(),
            pool_id: pool.pool_id.clone(),
            beneficiary_commitment: commitment("rebate-beneficiary", &rebate_id, sequence),
            fee_epoch: sequence,
            gross_fee_commitment: commitment("gross-fee", &rebate_id, sequence),
            rebate_commitment: commitment("rebate-amount", &rebate_id, sequence),
            sponsor_commitment: commitment("rebate-sponsor", &rebate_id, sequence),
            rebate_bps: pool.rebate_bps.min(config.target_fee_rebate_bps),
            claim_nullifier: nullifier("fee-rebate", &rebate_id, sequence),
            expires_at_height: pool.maturity_height + config.settlement_ttl_blocks,
        }
    }

    pub fn validate(
        &self,
        config: &Config,
        pools: &BTreeMap<String, ForwardAmmPool>,
    ) -> Result<()> {
        if !pools.contains_key(&self.pool_id) {
            return Err(format!(
                "fee rebate {} references unknown pool",
                self.rebate_id
            ));
        }
        ensure_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.max_user_fee_bps {
            return Err(format!(
                "fee rebate {} exceeds max user fee",
                self.rebate_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "pool_id": self.pool_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_epoch": self.fee_epoch,
            "gross_fee_commitment": self.gross_fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_bps": self.rebate_bps,
            "claim_nullifier": self.claim_nullifier,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub subject_root: String,
    pub redacted_record_root: String,
    pub view_key_commitment: String,
    pub policy_commitment: String,
    pub allowed_audience: SummaryAudience,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub status: RedactionStatus,
}

impl PrivacyRedaction {
    pub fn devnet(subject_root: &str, sequence: u64, config: &Config) -> Self {
        let redaction_id = format!("prd:carbon-forward:{sequence:04}");
        Self {
            redaction_id: redaction_id.clone(),
            subject_root: subject_root.to_string(),
            redacted_record_root: root_hex("redacted-record", &[HashPart::Str(subject_root)]),
            view_key_commitment: commitment("view-key", &redaction_id, sequence),
            policy_commitment: commitment("redaction-policy", &redaction_id, sequence),
            allowed_audience: SummaryAudience::Compliance,
            requested_at_height: 2_250_000 + sequence * config.redaction_epoch_blocks,
            expires_at_height: 2_250_000 + (sequence + 1) * config.redaction_epoch_blocks,
            status: RedactionStatus::Applied,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.requested_at_height >= self.expires_at_height {
            return Err(format!(
                "privacy redaction {} invalid ttl",
                self.redaction_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "subject_root": self.subject_root,
            "redacted_record_root": self.redacted_record_root,
            "view_key_commitment": self.view_key_commitment,
            "policy_commitment": self.policy_commitment,
            "allowed_audience": self.allowed_audience,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub audience: SummaryAudience,
    pub bucket_id: u64,
    pub pool_count: u64,
    pub active_pool_count: u64,
    pub matured_pool_count: u64,
    pub vintage_count: u64,
    pub sealed_liquidity_count: u64,
    pub oracle_quorum_count: u64,
    pub aggregate_liquidity_commitment_root: String,
    pub aggregate_fee_commitment_root: String,
    pub aggregate_rebate_commitment_root: String,
    pub aggregate_settlement_commitment_root: String,
    pub published_at_height: u64,
}

impl OperatorSummary {
    pub fn from_state_snapshot(state: &State, audience: SummaryAudience, bucket_id: u64) -> Self {
        let active_pool_count = state
            .forward_pools
            .values()
            .filter(|pool| pool.status.accepts_trades())
            .count() as u64;
        let matured_pool_count = state
            .forward_pools
            .values()
            .filter(|pool| pool.status.requires_settlement())
            .count() as u64;
        let oracle_quorum_count = state
            .oracle_attestations
            .values()
            .filter(|attestation| attestation.status.counts_for_quorum())
            .count() as u64;
        let summary_id = format!("ops:carbon-forward:{bucket_id:08}");
        Self {
            summary_id: summary_id.clone(),
            audience,
            bucket_id,
            pool_count: state.forward_pools.len() as u64,
            active_pool_count,
            matured_pool_count,
            vintage_count: state.carbon_vintages.len() as u64,
            sealed_liquidity_count: state.sealed_liquidity.len() as u64,
            oracle_quorum_count,
            aggregate_liquidity_commitment_root: collection_root(
                "summary-liquidity",
                state
                    .sealed_liquidity
                    .values()
                    .map(SealedLiquidityPosition::public_record),
            ),
            aggregate_fee_commitment_root: collection_root(
                "summary-fees",
                state
                    .fee_rebates
                    .values()
                    .map(FeeCreditRebate::public_record),
            ),
            aggregate_rebate_commitment_root: collection_root(
                "summary-rebates",
                state
                    .fee_rebates
                    .values()
                    .map(FeeCreditRebate::public_record),
            ),
            aggregate_settlement_commitment_root: collection_root(
                "summary-settlements",
                state
                    .maturity_settlements
                    .values()
                    .map(MaturitySettlement::public_record),
            ),
            published_at_height: 2_500_000 + bucket_id,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "audience": self.audience,
            "bucket_id": self.bucket_id,
            "pool_count": self.pool_count,
            "active_pool_count": self.active_pool_count,
            "matured_pool_count": self.matured_pool_count,
            "vintage_count": self.vintage_count,
            "sealed_liquidity_count": self.sealed_liquidity_count,
            "oracle_quorum_count": self.oracle_quorum_count,
            "aggregate_liquidity_commitment_root": self.aggregate_liquidity_commitment_root,
            "aggregate_fee_commitment_root": self.aggregate_fee_commitment_root,
            "aggregate_rebate_commitment_root": self.aggregate_rebate_commitment_root,
            "aggregate_settlement_commitment_root": self.aggregate_settlement_commitment_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: RuntimeEventKind,
    pub subject_id: String,
    pub public_commitment: String,
    pub nullifier: Option<String>,
    pub emitted_at_height: u64,
}

impl RuntimeEvent {
    pub fn new(kind: RuntimeEventKind, subject_id: &str, sequence: u64) -> Self {
        let event_id = format!("evt:carbon-forward:{sequence:08}");
        Self {
            event_id: event_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            public_commitment: commitment("runtime-event", &event_id, sequence),
            nullifier: None,
            emitted_at_height: 2_200_000 + sequence,
        }
    }

    pub fn with_nullifier(mut self, scope: &str) -> Self {
        self.nullifier = Some(nullifier(scope, &self.event_id, self.emitted_at_height));
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "public_commitment": self.public_commitment,
            "nullifier": self.nullifier,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub carbon_vintages: BTreeMap<String, CarbonVintage>,
    pub forward_pools: BTreeMap<String, ForwardAmmPool>,
    pub oracle_attestations: BTreeMap<String, OracleVerificationAttestation>,
    pub sealed_liquidity: BTreeMap<String, SealedLiquidityPosition>,
    pub maturity_settlements: BTreeMap<String, MaturitySettlement>,
    pub risk_haircuts: BTreeMap<String, RiskHaircut>,
    pub fee_rebates: BTreeMap<String, FeeCreditRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            carbon_vintages: BTreeMap::new(),
            forward_pools: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            sealed_liquidity: BTreeMap::new(),
            maturity_settlements: BTreeMap::new(),
            risk_haircuts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone());
        let vintage_specs = [
            ("biochar", CarbonStandard::PuroEarth, ProjectType::Biochar),
            (
                "forest",
                CarbonStandard::VerraVcs,
                ProjectType::Reforestation,
            ),
            (
                "dac",
                CarbonStandard::GoldStandard,
                ProjectType::DirectAirCapture,
            ),
        ];

        for (index, (label, standard, project_type)) in vintage_specs.into_iter().enumerate() {
            let sequence = index as u64 + 1;
            let vintage = CarbonVintage::devnet(label, sequence, standard, project_type);
            let pool = ForwardAmmPool::devnet(&vintage, sequence, &config);
            let attestation = OracleVerificationAttestation::devnet(&vintage, sequence, &config);
            let liquidity = SealedLiquidityPosition::devnet(&pool, sequence, &config);
            let settlement = MaturitySettlement::devnet(&pool, sequence, &config);
            let haircut = RiskHaircut::devnet(&vintage, &pool, &attestation, sequence);
            let rebate = FeeCreditRebate::devnet(&pool, sequence, &config);

            state
                .spent_nullifiers
                .insert(rebate.claim_nullifier.clone());
            state.events.push(RuntimeEvent::new(
                RuntimeEventKind::VintageRegistered,
                &vintage.vintage_id,
                sequence * 10,
            ));
            state.events.push(RuntimeEvent::new(
                RuntimeEventKind::PoolCreated,
                &pool.pool_id,
                sequence * 10 + 1,
            ));
            state.events.push(
                RuntimeEvent::new(
                    RuntimeEventKind::LiquiditySealed,
                    &liquidity.position_id,
                    sequence * 10 + 2,
                )
                .with_nullifier("sealed-liquidity"),
            );
            state.events.push(
                RuntimeEvent::new(
                    RuntimeEventKind::RebateIssued,
                    &rebate.rebate_id,
                    sequence * 10 + 3,
                )
                .with_nullifier("fee-rebate"),
            );

            state
                .carbon_vintages
                .insert(vintage.vintage_id.clone(), vintage);
            state.forward_pools.insert(pool.pool_id.clone(), pool);
            state
                .oracle_attestations
                .insert(attestation.attestation_id.clone(), attestation);
            state
                .sealed_liquidity
                .insert(liquidity.position_id.clone(), liquidity);
            state
                .maturity_settlements
                .insert(settlement.settlement_id.clone(), settlement);
            state
                .risk_haircuts
                .insert(haircut.haircut_id.clone(), haircut);
            state.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        }

        let preliminary_roots = state.compute_roots_without_state_root();
        let redaction = PrivacyRedaction::devnet(&preliminary_roots.forward_pool_root, 1, &config);
        state
            .privacy_redactions
            .insert(redaction.redaction_id.clone(), redaction);

        let operator_summary =
            OperatorSummary::from_state_snapshot(&state, SummaryAudience::Operator, 1);
        state
            .operator_summaries
            .insert(operator_summary.summary_id.clone(), operator_summary);
        state.events.push(RuntimeEvent::new(
            RuntimeEventKind::SummaryPublished,
            "ops:carbon-forward:00000001",
            99,
        ));
        state.refresh_accounting();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        enforce_limit(
            "carbon_vintages",
            self.carbon_vintages.len(),
            MAX_CARBON_VINTAGES,
        )?;
        enforce_limit("forward_pools", self.forward_pools.len(), MAX_FORWARD_POOLS)?;
        enforce_limit(
            "oracle_attestations",
            self.oracle_attestations.len(),
            MAX_ORACLE_ATTESTATIONS,
        )?;
        enforce_limit(
            "sealed_liquidity",
            self.sealed_liquidity.len(),
            MAX_SEALED_LIQUIDITY,
        )?;
        enforce_limit(
            "maturity_settlements",
            self.maturity_settlements.len(),
            MAX_MATURITY_SETTLEMENTS,
        )?;
        enforce_limit("risk_haircuts", self.risk_haircuts.len(), MAX_RISK_HAIRCUTS)?;
        enforce_limit("fee_rebates", self.fee_rebates.len(), MAX_FEE_REBATES)?;
        enforce_limit(
            "privacy_redactions",
            self.privacy_redactions.len(),
            MAX_PRIVACY_REDACTIONS,
        )?;
        enforce_limit(
            "operator_summaries",
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
        )?;
        enforce_limit("events", self.events.len(), MAX_EVENTS)?;

        for vintage in self.carbon_vintages.values() {
            vintage.validate(&self.config)?;
        }
        for pool in self.forward_pools.values() {
            pool.validate(&self.config, &self.carbon_vintages)?;
        }
        for attestation in self.oracle_attestations.values() {
            attestation.validate(&self.config, &self.carbon_vintages)?;
        }
        for liquidity in self.sealed_liquidity.values() {
            liquidity.validate(&self.config, &self.forward_pools)?;
        }
        for settlement in self.maturity_settlements.values() {
            settlement.validate(&self.config, &self.forward_pools)?;
        }
        for haircut in self.risk_haircuts.values() {
            haircut.validate(
                &self.config,
                &self.carbon_vintages,
                &self.forward_pools,
                &self.oracle_attestations,
            )?;
        }
        for rebate in self.fee_rebates.values() {
            rebate.validate(&self.config, &self.forward_pools)?;
        }
        for redaction in self.privacy_redactions.values() {
            redaction.validate()?;
        }
        Ok(())
    }

    pub fn refresh_accounting(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.compute_roots();
    }

    pub fn compute_counters(&self) -> Counters {
        Counters {
            carbon_vintages: self.carbon_vintages.len() as u64,
            forward_pools: self.forward_pools.len() as u64,
            oracle_attestations: self.oracle_attestations.len() as u64,
            sealed_liquidity: self.sealed_liquidity.len() as u64,
            maturity_settlements: self.maturity_settlements.len() as u64,
            risk_haircuts: self.risk_haircuts.len() as u64,
            fee_rebates: self.fee_rebates.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            nullifiers: self.spent_nullifiers.len() as u64,
            events: self.events.len() as u64,
        }
    }

    pub fn compute_roots_without_state_root(&self) -> Roots {
        let nullifier_values = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        Roots {
            carbon_vintage_root: collection_root(
                CARBON_VINTAGE_SCHEME,
                self.carbon_vintages
                    .values()
                    .map(CarbonVintage::public_record),
            ),
            forward_pool_root: collection_root(
                FORWARD_POOL_SCHEME,
                self.forward_pools
                    .values()
                    .map(ForwardAmmPool::public_record),
            ),
            oracle_attestation_root: collection_root(
                ORACLE_ATTESTATION_SCHEME,
                self.oracle_attestations
                    .values()
                    .map(OracleVerificationAttestation::public_record),
            ),
            sealed_liquidity_root: collection_root(
                SEALED_LIQUIDITY_SCHEME,
                self.sealed_liquidity
                    .values()
                    .map(SealedLiquidityPosition::public_record),
            ),
            maturity_settlement_root: collection_root(
                MATURITY_SETTLEMENT_SCHEME,
                self.maturity_settlements
                    .values()
                    .map(MaturitySettlement::public_record),
            ),
            risk_haircut_root: collection_root(
                RISK_HAIRCUT_SCHEME,
                self.risk_haircuts.values().map(RiskHaircut::public_record),
            ),
            fee_rebate_root: collection_root(
                FEE_REBATE_SCHEME,
                self.fee_rebates
                    .values()
                    .map(FeeCreditRebate::public_record),
            ),
            privacy_redaction_root: collection_root(
                PRIVACY_REDACTION_SCHEME,
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            operator_summary_root: collection_root(
                OPERATOR_SUMMARY_SCHEME,
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record),
            ),
            nullifier_root: merkle_root(NULLIFIER_SCHEME, &nullifier_values),
            event_root: collection_root(
                EVENT_SCHEME,
                self.events.iter().map(RuntimeEvent::public_record),
            ),
            state_root: String::new(),
        }
    }

    pub fn compute_roots(&self) -> Roots {
        let mut roots = self.compute_roots_without_state_root();
        roots.state_root = root_hex(
            "private-l2-pq-confidential-tokenized-carbon-credit-forward-amm-state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&roots.carbon_vintage_root),
                HashPart::Str(&roots.forward_pool_root),
                HashPart::Str(&roots.oracle_attestation_root),
                HashPart::Str(&roots.sealed_liquidity_root),
                HashPart::Str(&roots.maturity_settlement_root),
                HashPart::Str(&roots.risk_haircut_root),
                HashPart::Str(&roots.fee_rebate_root),
                HashPart::Str(&roots.privacy_redaction_root),
                HashPart::Str(&roots.operator_summary_root),
                HashPart::Str(&roots.nullifier_root),
                HashPart::Str(&roots.event_root),
                HashPart::U64(self.compute_counters().events),
            ],
        );
        roots
    }

    pub fn public_record(&self) -> Value {
        let counters = self.compute_counters();
        let roots = self.compute_roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
            "carbon_vintages": self.carbon_vintages.values().map(CarbonVintage::public_record).collect::<Vec<_>>(),
            "forward_pools": self.forward_pools.values().map(ForwardAmmPool::public_record).collect::<Vec<_>>(),
            "oracle_attestations": self.oracle_attestations.values().map(OracleVerificationAttestation::public_record).collect::<Vec<_>>(),
            "sealed_liquidity": self.sealed_liquidity.values().map(SealedLiquidityPosition::public_record).collect::<Vec<_>>(),
            "maturity_settlements": self.maturity_settlements.values().map(MaturitySettlement::public_record).collect::<Vec<_>>(),
            "risk_haircuts": self.risk_haircuts.values().map(RiskHaircut::public_record).collect::<Vec<_>>(),
            "fee_rebates": self.fee_rebates.values().map(FeeCreditRebate::public_record).collect::<Vec<_>>(),
            "privacy_redactions": self.privacy_redactions.values().map(PrivacyRedaction::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
            "spent_nullifier_root": roots.nullifier_root,
            "events": self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        self.compute_roots().state_root
    }

    pub fn register_vintage(&mut self, vintage: CarbonVintage) -> Result<()> {
        vintage.validate(&self.config)?;
        if self.carbon_vintages.contains_key(&vintage.vintage_id) {
            return Err(format!("duplicate carbon vintage {}", vintage.vintage_id));
        }
        self.events.push(RuntimeEvent::new(
            RuntimeEventKind::VintageRegistered,
            &vintage.vintage_id,
            self.events.len() as u64 + 1,
        ));
        self.carbon_vintages
            .insert(vintage.vintage_id.clone(), vintage);
        self.refresh_accounting();
        Ok(())
    }

    pub fn create_forward_pool(&mut self, pool: ForwardAmmPool) -> Result<()> {
        pool.validate(&self.config, &self.carbon_vintages)?;
        if self.forward_pools.contains_key(&pool.pool_id) {
            return Err(format!("duplicate forward pool {}", pool.pool_id));
        }
        self.events.push(RuntimeEvent::new(
            RuntimeEventKind::PoolCreated,
            &pool.pool_id,
            self.events.len() as u64 + 1,
        ));
        self.forward_pools.insert(pool.pool_id.clone(), pool);
        self.refresh_accounting();
        Ok(())
    }

    pub fn accept_oracle_attestation(
        &mut self,
        attestation: OracleVerificationAttestation,
    ) -> Result<()> {
        attestation.validate(&self.config, &self.carbon_vintages)?;
        self.events.push(RuntimeEvent::new(
            RuntimeEventKind::VintageAttested,
            &attestation.attestation_id,
            self.events.len() as u64 + 1,
        ));
        self.oracle_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_accounting();
        Ok(())
    }

    pub fn seal_liquidity(&mut self, liquidity: SealedLiquidityPosition) -> Result<()> {
        liquidity.validate(&self.config, &self.forward_pools)?;
        self.events.push(
            RuntimeEvent::new(
                RuntimeEventKind::LiquiditySealed,
                &liquidity.position_id,
                self.events.len() as u64 + 1,
            )
            .with_nullifier("sealed-liquidity"),
        );
        self.sealed_liquidity
            .insert(liquidity.position_id.clone(), liquidity);
        self.refresh_accounting();
        Ok(())
    }

    pub fn finalize_maturity(&mut self, settlement: MaturitySettlement) -> Result<()> {
        settlement.validate(&self.config, &self.forward_pools)?;
        self.events.push(RuntimeEvent::new(
            RuntimeEventKind::SettlementFinalized,
            &settlement.settlement_id,
            self.events.len() as u64 + 1,
        ));
        self.maturity_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.refresh_accounting();
        Ok(())
    }

    pub fn issue_fee_rebate(&mut self, rebate: FeeCreditRebate) -> Result<()> {
        rebate.validate(&self.config, &self.forward_pools)?;
        if !self.spent_nullifiers.insert(rebate.claim_nullifier.clone()) {
            return Err(format!(
                "duplicate rebate nullifier {}",
                rebate.claim_nullifier
            ));
        }
        self.events.push(
            RuntimeEvent::new(
                RuntimeEventKind::RebateIssued,
                &rebate.rebate_id,
                self.events.len() as u64 + 1,
            )
            .with_nullifier("fee-rebate"),
        );
        self.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        self.refresh_accounting();
        Ok(())
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

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{name} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn clamp_bps(value: u64) -> u64 {
    value.min(MAX_BPS)
}

fn enforce_limit(name: &str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        Err(format!("{name} exceeds runtime limit {max}"))
    } else {
        Ok(())
    }
}

fn collection_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &values.into_iter().collect::<Vec<_>>())
}

fn root_hex(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn commitment(scope: &str, label: &str, sequence: u64) -> String {
    root_hex(
        scope,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
    )
}

fn nullifier(scope: &str, label: &str, sequence: u64) -> String {
    root_hex(
        "private-carbon-forward-nullifier",
        &[
            HashPart::Str(scope),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
    )
}
