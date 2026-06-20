use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_LIQUIDITY_REBALANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-subaddress-liquidity-rebalance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SUBADDRESS_LIQUIDITY_REBALANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_RUNTIME_ID: &str = "monero-l2-pq-private-subaddress-liquidity-rebalance-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_356_800;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-subaddress-rebalance-v1";
pub const SUBADDRESS_BUCKET_SCHEME: &str = "monero-private-subaddress-liquidity-bucket-root-v1";
pub const REBALANCE_INTENT_SCHEME: &str = "monero-l2-private-liquidity-rebalance-intent-root-v1";
pub const VIEW_KEY_DISCLOSURE_SCHEME: &str = "monero-view-key-disclosure-limit-root-v1";
pub const DECOY_FLOOR_SCHEME: &str = "monero-decoy-floor-private-rebalance-root-v1";
pub const FEE_CREDIT_SCHEME: &str = "fee-capped-rebalancing-credit-root-v1";
pub const QUARANTINE_SCHEME: &str = "stale-subaddress-bucket-quarantine-root-v1";
pub const PRIVACY_REDACTION_SCHEME: &str = "privacy-redaction-budget-root-v1";
pub const DETERMINISTIC_ROOT_SCHEME: &str = "subaddress-liquidity-rebalance-deterministic-root-v1";
pub const REPLAY_DOMAIN: &str = "monero-l2-pq-private-subaddress-liquidity-rebalance-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_BUCKET_PRIVACY_SET: u64 = 32_768;
pub const DEFAULT_TARGET_BUCKET_PRIVACY_SET: u64 = 131_072;
pub const DEFAULT_MIN_DECOY_FLOOR: u16 = 32;
pub const DEFAULT_TARGET_DECOY_FLOOR: u16 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_VIEW_KEY_DISCLOSURE_LIMIT_PER_EPOCH: u32 = 3;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET_PER_EPOCH: u32 = 24;
pub const DEFAULT_BUCKET_STALE_AFTER_BLOCKS: u64 = 720;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 1_440;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 384;
pub const DEFAULT_FEE_CREDIT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_REBALANCE_FEE_BPS: u64 = 12;
pub const DEFAULT_OPERATOR_FEE_CAP_BPS: u64 = 16;
pub const DEFAULT_MAX_BUCKET_IMBALANCE_BPS: u64 = 2_000;
pub const DEFAULT_TARGET_BUCKET_FILL_BPS: u64 = 7_500;
pub const DEFAULT_MIN_REBALANCE_AMOUNT_PICONERO: u128 = 25_000_000_000;
pub const DEFAULT_MAX_REBALANCE_AMOUNT_PICONERO: u128 = 9_000_000_000_000;
pub const DEFAULT_MAX_SUBADDRESS_BUCKETS: usize = 4_096;
pub const DEFAULT_MAX_ACTIVE_INTENTS: usize = 16_384;
pub const DEFAULT_MAX_DISCLOSURE_LIMITS: usize = 65_536;
pub const DEFAULT_MAX_FEE_CREDITS: usize = 65_536;
pub const DEFAULT_MAX_QUARANTINES: usize = 16_384;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketClass {
    DepositIngress,
    WithdrawalEgress,
    MarketMaker,
    RouterFloat,
    ShieldedTreasury,
    EmergencyDrain,
}

impl BucketClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositIngress => "deposit_ingress",
            Self::WithdrawalEgress => "withdrawal_egress",
            Self::MarketMaker => "market_maker",
            Self::RouterFloat => "router_float",
            Self::ShieldedTreasury => "shielded_treasury",
            Self::EmergencyDrain => "emergency_drain",
        }
    }

    pub fn target_fill_bps(self, config: &Config) -> u64 {
        match self {
            Self::DepositIngress => config.target_bucket_fill_bps,
            Self::WithdrawalEgress => config.target_bucket_fill_bps.saturating_sub(800),
            Self::MarketMaker => config
                .target_bucket_fill_bps
                .saturating_add(900)
                .min(MAX_BPS),
            Self::RouterFloat => config
                .target_bucket_fill_bps
                .saturating_add(400)
                .min(MAX_BPS),
            Self::ShieldedTreasury => MAX_BPS,
            Self::EmergencyDrain => config.target_bucket_fill_bps / 2,
        }
    }
}

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $label:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }
        }
    };
}

status_enum!(BucketStatus {
    Open => "open",
    Saturated => "saturated",
    Draining => "draining",
    Quarantined => "quarantined",
    Retired => "retired",
    Slashed => "slashed",
});

impl BucketStatus {
    pub fn accepts_rebalance(self) -> bool {
        matches!(self, Self::Open | Self::Draining)
    }
}

status_enum!(IntentStatus {
    Draft => "draft",
    Committed => "committed",
    Matched => "matched",
    Executing => "executing",
    Settled => "settled",
    Expired => "expired",
    Cancelled => "cancelled",
    Quarantined => "quarantined",
});

impl IntentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Committed | Self::Matched | Self::Executing
        )
    }
}

status_enum!(DisclosureStatus {
    Available => "available",
    Reserved => "reserved",
    Consumed => "consumed",
    Exhausted => "exhausted",
    Revoked => "revoked",
});

impl DisclosureStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Available | Self::Reserved)
    }
}

status_enum!(AttestationRole {
    Wallet => "wallet",
    Operator => "operator",
    Watchtower => "watchtower",
    Auditor => "auditor",
});

status_enum!(AttestationStatus {
    Pending => "pending",
    Accepted => "accepted",
    Superseded => "superseded",
    Expired => "expired",
    Slashed => "slashed",
});

status_enum!(QuarantineReason {
    StaleBucket => "stale_bucket",
    DisclosureOverrun => "disclosure_overrun",
    DecoyFloorBreach => "decoy_floor_breach",
    FeeCapBreach => "fee_cap_breach",
    PqAttestationMissing => "pq_attestation_missing",
    RootMismatch => "root_mismatch",
});

status_enum!(CreditStatus {
    Minted => "minted",
    Reserved => "reserved",
    Redeemed => "redeemed",
    Expired => "expired",
    Revoked => "revoked",
});

impl CreditStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved)
    }
}

status_enum!(RedactionScope {
    BucketAggregate => "bucket_aggregate",
    ViewKeyWindow => "view_key_window",
    RebalanceIntent => "rebalance_intent",
    OperatorTelemetry => "operator_telemetry",
    FeeCredit => "fee_credit",
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub runtime_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub subaddress_bucket_scheme: String,
    pub rebalance_intent_scheme: String,
    pub view_key_disclosure_scheme: String,
    pub decoy_floor_scheme: String,
    pub fee_credit_scheme: String,
    pub quarantine_scheme: String,
    pub privacy_redaction_scheme: String,
    pub deterministic_root_scheme: String,
    pub replay_domain: String,
    pub min_bucket_privacy_set: u64,
    pub target_bucket_privacy_set: u64,
    pub min_decoy_floor: u16,
    pub target_decoy_floor: u16,
    pub min_pq_security_bits: u16,
    pub view_key_disclosure_limit_per_epoch: u32,
    pub privacy_redaction_budget_per_epoch: u32,
    pub bucket_stale_after_blocks: u64,
    pub quarantine_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fee_credit_ttl_blocks: u64,
    pub max_rebalance_fee_bps: u64,
    pub operator_fee_cap_bps: u64,
    pub max_bucket_imbalance_bps: u64,
    pub target_bucket_fill_bps: u64,
    pub min_rebalance_amount_piconero: u128,
    pub max_rebalance_amount_piconero: u128,
    pub max_subaddress_buckets: usize,
    pub max_active_intents: usize,
    pub max_disclosure_limits: usize,
    pub max_fee_credits: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            subaddress_bucket_scheme: SUBADDRESS_BUCKET_SCHEME.to_string(),
            rebalance_intent_scheme: REBALANCE_INTENT_SCHEME.to_string(),
            view_key_disclosure_scheme: VIEW_KEY_DISCLOSURE_SCHEME.to_string(),
            decoy_floor_scheme: DECOY_FLOOR_SCHEME.to_string(),
            fee_credit_scheme: FEE_CREDIT_SCHEME.to_string(),
            quarantine_scheme: QUARANTINE_SCHEME.to_string(),
            privacy_redaction_scheme: PRIVACY_REDACTION_SCHEME.to_string(),
            deterministic_root_scheme: DETERMINISTIC_ROOT_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            min_bucket_privacy_set: DEFAULT_MIN_BUCKET_PRIVACY_SET,
            target_bucket_privacy_set: DEFAULT_TARGET_BUCKET_PRIVACY_SET,
            min_decoy_floor: DEFAULT_MIN_DECOY_FLOOR,
            target_decoy_floor: DEFAULT_TARGET_DECOY_FLOOR,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            view_key_disclosure_limit_per_epoch: DEFAULT_VIEW_KEY_DISCLOSURE_LIMIT_PER_EPOCH,
            privacy_redaction_budget_per_epoch: DEFAULT_PRIVACY_REDACTION_BUDGET_PER_EPOCH,
            bucket_stale_after_blocks: DEFAULT_BUCKET_STALE_AFTER_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fee_credit_ttl_blocks: DEFAULT_FEE_CREDIT_TTL_BLOCKS,
            max_rebalance_fee_bps: DEFAULT_MAX_REBALANCE_FEE_BPS,
            operator_fee_cap_bps: DEFAULT_OPERATOR_FEE_CAP_BPS,
            max_bucket_imbalance_bps: DEFAULT_MAX_BUCKET_IMBALANCE_BPS,
            target_bucket_fill_bps: DEFAULT_TARGET_BUCKET_FILL_BPS,
            min_rebalance_amount_piconero: DEFAULT_MIN_REBALANCE_AMOUNT_PICONERO,
            max_rebalance_amount_piconero: DEFAULT_MAX_REBALANCE_AMOUNT_PICONERO,
            max_subaddress_buckets: DEFAULT_MAX_SUBADDRESS_BUCKETS,
            max_active_intents: DEFAULT_MAX_ACTIVE_INTENTS,
            max_disclosure_limits: DEFAULT_MAX_DISCLOSURE_LIMITS,
            max_fee_credits: DEFAULT_MAX_FEE_CREDITS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "runtime_id": self.runtime_id,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "subaddress_bucket_scheme": self.subaddress_bucket_scheme,
            "rebalance_intent_scheme": self.rebalance_intent_scheme,
            "view_key_disclosure_scheme": self.view_key_disclosure_scheme,
            "decoy_floor_scheme": self.decoy_floor_scheme,
            "fee_credit_scheme": self.fee_credit_scheme,
            "quarantine_scheme": self.quarantine_scheme,
            "privacy_redaction_scheme": self.privacy_redaction_scheme,
            "deterministic_root_scheme": self.deterministic_root_scheme,
            "replay_domain": self.replay_domain,
            "min_bucket_privacy_set": self.min_bucket_privacy_set,
            "target_bucket_privacy_set": self.target_bucket_privacy_set,
            "min_decoy_floor": self.min_decoy_floor,
            "target_decoy_floor": self.target_decoy_floor,
            "min_pq_security_bits": self.min_pq_security_bits,
            "view_key_disclosure_limit_per_epoch": self.view_key_disclosure_limit_per_epoch,
            "privacy_redaction_budget_per_epoch": self.privacy_redaction_budget_per_epoch,
            "bucket_stale_after_blocks": self.bucket_stale_after_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fee_credit_ttl_blocks": self.fee_credit_ttl_blocks,
            "max_rebalance_fee_bps": self.max_rebalance_fee_bps,
            "operator_fee_cap_bps": self.operator_fee_cap_bps,
            "max_bucket_imbalance_bps": self.max_bucket_imbalance_bps,
            "target_bucket_fill_bps": self.target_bucket_fill_bps,
            "min_rebalance_amount_piconero": self.min_rebalance_amount_piconero.to_string(),
            "max_rebalance_amount_piconero": self.max_rebalance_amount_piconero.to_string(),
            "max_subaddress_buckets": self.max_subaddress_buckets,
            "max_active_intents": self.max_active_intents,
            "max_disclosure_limits": self.max_disclosure_limits,
            "max_fee_credits": self.max_fee_credits,
            "max_quarantines": self.max_quarantines,
            "max_redaction_budgets": self.max_redaction_budgets,
        })
    }

    pub fn validate(&self) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unexpected protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unexpected schema version".to_string());
        }
        if self.min_bucket_privacy_set == 0
            || self.target_bucket_privacy_set < self.min_bucket_privacy_set
        {
            return Err("invalid bucket privacy set bounds".to_string());
        }
        if self.min_decoy_floor == 0 || self.target_decoy_floor < self.min_decoy_floor {
            return Err("invalid decoy floor bounds".to_string());
        }
        if self.max_rebalance_fee_bps > self.operator_fee_cap_bps
            || self.operator_fee_cap_bps > MAX_BPS
        {
            return Err("invalid fee cap bounds".to_string());
        }
        if self.target_bucket_fill_bps > MAX_BPS || self.max_bucket_imbalance_bps > MAX_BPS {
            return Err("invalid bucket bps bounds".to_string());
        }
        if self.min_rebalance_amount_piconero == 0
            || self.max_rebalance_amount_piconero < self.min_rebalance_amount_piconero
        {
            return Err("invalid rebalance amount bounds".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub buckets_open: u64,
    pub buckets_quarantined: u64,
    pub intents_committed: u64,
    pub intents_settled: u64,
    pub view_key_disclosures_consumed: u64,
    pub wallet_attestations_accepted: u64,
    pub operator_attestations_accepted: u64,
    pub decoy_floor_breaches: u64,
    pub fee_credits_minted: u64,
    pub fee_credits_redeemed: u64,
    pub stale_bucket_quarantines: u64,
    pub privacy_redactions_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "buckets_open": self.buckets_open,
            "buckets_quarantined": self.buckets_quarantined,
            "intents_committed": self.intents_committed,
            "intents_settled": self.intents_settled,
            "view_key_disclosures_consumed": self.view_key_disclosures_consumed,
            "wallet_attestations_accepted": self.wallet_attestations_accepted,
            "operator_attestations_accepted": self.operator_attestations_accepted,
            "decoy_floor_breaches": self.decoy_floor_breaches,
            "fee_credits_minted": self.fee_credits_minted,
            "fee_credits_redeemed": self.fee_credits_redeemed,
            "stale_bucket_quarantines": self.stale_bucket_quarantines,
            "privacy_redactions_consumed": self.privacy_redactions_consumed,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub bucket_root: String,
    pub intent_root: String,
    pub disclosure_root: String,
    pub attestation_root: String,
    pub decoy_floor_root: String,
    pub fee_credit_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub deterministic_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bucket_root": self.bucket_root,
            "intent_root": self.intent_root,
            "disclosure_root": self.disclosure_root,
            "attestation_root": self.attestation_root,
            "decoy_floor_root": self.decoy_floor_root,
            "fee_credit_root": self.fee_credit_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "deterministic_root": self.deterministic_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressBucket {
    pub bucket_id: String,
    pub bucket_class: BucketClass,
    pub status: BucketStatus,
    pub subaddress_account: u32,
    pub subaddress_major: u32,
    pub subaddress_minor_start: u32,
    pub subaddress_minor_end: u32,
    pub subaddress_view_tag_root: String,
    pub encrypted_bucket_label: String,
    pub bucket_commitment: String,
    pub balance_commitment: String,
    pub liquidity_piconero: u128,
    pub reserved_piconero: u128,
    pub target_liquidity_piconero: u128,
    pub inbound_intent_count: u64,
    pub outbound_intent_count: u64,
    pub privacy_set_size: u64,
    pub decoy_floor: u16,
    pub view_key_disclosure_epoch: u64,
    pub last_rebalanced_height: u64,
    pub last_observed_height: u64,
    pub created_height: u64,
    pub operator_id: String,
    pub wallet_attestation_id: String,
    pub operator_attestation_id: String,
}

impl SubaddressBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "bucket_class": self.bucket_class.as_str(),
            "status": self.status.as_str(),
            "subaddress_account": self.subaddress_account,
            "subaddress_range_width": self.subaddress_minor_end.saturating_sub(self.subaddress_minor_start).saturating_add(1),
            "subaddress_view_tag_root": self.subaddress_view_tag_root,
            "encrypted_bucket_label": self.encrypted_bucket_label,
            "bucket_commitment": self.bucket_commitment,
            "balance_commitment": self.balance_commitment,
            "liquidity_piconero": self.liquidity_piconero.to_string(),
            "reserved_piconero": self.reserved_piconero.to_string(),
            "target_liquidity_piconero": self.target_liquidity_piconero.to_string(),
            "inbound_intent_count": self.inbound_intent_count,
            "outbound_intent_count": self.outbound_intent_count,
            "privacy_set_size": self.privacy_set_size,
            "decoy_floor": self.decoy_floor,
            "view_key_disclosure_epoch": self.view_key_disclosure_epoch,
            "last_rebalanced_height": self.last_rebalanced_height,
            "last_observed_height": self.last_observed_height,
            "created_height": self.created_height,
            "operator_id": self.operator_id,
            "wallet_attestation_id": self.wallet_attestation_id,
            "operator_attestation_id": self.operator_attestation_id,
        })
    }

    pub fn root(&self) -> String {
        record_root("SUBADDRESS-BUCKET", &self.public_record())
    }

    pub fn is_stale(&self, config: &Config, current_height: u64) -> bool {
        current_height.saturating_sub(self.last_observed_height) > config.bucket_stale_after_blocks
    }

    pub fn available_piconero(&self) -> u128 {
        self.liquidity_piconero
            .saturating_sub(self.reserved_piconero)
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("bucket_id", &self.bucket_id)?;
        validate_hash("subaddress_view_tag_root", &self.subaddress_view_tag_root)?;
        validate_hash("bucket_commitment", &self.bucket_commitment)?;
        validate_hash("balance_commitment", &self.balance_commitment)?;
        validate_hash("operator_id", &self.operator_id)?;
        validate_hash("wallet_attestation_id", &self.wallet_attestation_id)?;
        validate_hash("operator_attestation_id", &self.operator_attestation_id)?;
        if self.subaddress_minor_end < self.subaddress_minor_start {
            return Err("bucket subaddress range is inverted".to_string());
        }
        if self.reserved_piconero > self.liquidity_piconero {
            return Err("bucket reserved liquidity exceeds balance".to_string());
        }
        if self.privacy_set_size < config.min_bucket_privacy_set {
            return Err("bucket privacy set below minimum".to_string());
        }
        if self.decoy_floor < config.min_decoy_floor {
            return Err("bucket decoy floor below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityRebalanceIntent {
    pub intent_id: String,
    pub status: IntentStatus,
    pub source_bucket_id: String,
    pub target_bucket_id: String,
    pub amount_commitment: String,
    pub amount_piconero: u128,
    pub max_fee_bps: u64,
    pub fee_credit_id: Option<String>,
    pub decoy_floor: u16,
    pub privacy_set_size: u64,
    pub view_key_disclosure_budget: u32,
    pub redaction_budget: u32,
    pub deterministic_route_root: String,
    pub wallet_attestation_id: String,
    pub operator_attestation_id: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub created_height: u64,
    pub expires_at_height: u64,
    pub settled_height: Option<u64>,
}

impl LiquidityRebalanceIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "source_bucket_id": self.source_bucket_id,
            "target_bucket_id": self.target_bucket_id,
            "amount_commitment": self.amount_commitment,
            "amount_piconero": self.amount_piconero.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "fee_credit_id": self.fee_credit_id,
            "decoy_floor": self.decoy_floor,
            "privacy_set_size": self.privacy_set_size,
            "view_key_disclosure_budget": self.view_key_disclosure_budget,
            "redaction_budget": self.redaction_budget,
            "deterministic_route_root": self.deterministic_route_root,
            "wallet_attestation_id": self.wallet_attestation_id,
            "operator_attestation_id": self.operator_attestation_id,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "created_height": self.created_height,
            "expires_at_height": self.expires_at_height,
            "settled_height": self.settled_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("LIQUIDITY-REBALANCE-INTENT", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("intent_id", &self.intent_id)?;
        validate_hash("source_bucket_id", &self.source_bucket_id)?;
        validate_hash("target_bucket_id", &self.target_bucket_id)?;
        validate_hash("amount_commitment", &self.amount_commitment)?;
        validate_hash("deterministic_route_root", &self.deterministic_route_root)?;
        validate_hash("wallet_attestation_id", &self.wallet_attestation_id)?;
        validate_hash("operator_attestation_id", &self.operator_attestation_id)?;
        validate_hash("nullifier_root", &self.nullifier_root)?;
        validate_hash("proof_root", &self.proof_root)?;
        if self.source_bucket_id == self.target_bucket_id {
            return Err("rebalance intent source and target are identical".to_string());
        }
        if self.amount_piconero < config.min_rebalance_amount_piconero
            || self.amount_piconero > config.max_rebalance_amount_piconero
        {
            return Err("rebalance intent amount outside configured bounds".to_string());
        }
        if self.max_fee_bps > config.max_rebalance_fee_bps {
            return Err("rebalance intent fee cap exceeds config".to_string());
        }
        if self.decoy_floor < config.min_decoy_floor {
            return Err("rebalance intent decoy floor below config".to_string());
        }
        if self.privacy_set_size < config.min_bucket_privacy_set {
            return Err("rebalance intent privacy set below config".to_string());
        }
        if self.view_key_disclosure_budget > config.view_key_disclosure_limit_per_epoch {
            return Err("rebalance intent disclosure budget exceeds limit".to_string());
        }
        validate_height_window(
            "rebalance intent",
            self.created_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyDisclosureLimit {
    pub disclosure_id: String,
    pub bucket_id: String,
    pub viewer_commitment: String,
    pub status: DisclosureStatus,
    pub epoch: u64,
    pub limit: u32,
    pub consumed: u32,
    pub disclosure_policy_root: String,
    pub encrypted_view_key_root: String,
    pub expires_at_height: u64,
}

impl ViewKeyDisclosureLimit {
    pub fn public_record(&self) -> Value {
        json!({
            "disclosure_id": self.disclosure_id,
            "bucket_id": self.bucket_id,
            "viewer_commitment": self.viewer_commitment,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "limit": self.limit,
            "consumed": self.consumed,
            "remaining": self.limit.saturating_sub(self.consumed),
            "disclosure_policy_root": self.disclosure_policy_root,
            "encrypted_view_key_root": self.encrypted_view_key_root,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("disclosure_id", &self.disclosure_id)?;
        validate_hash("bucket_id", &self.bucket_id)?;
        validate_hash("viewer_commitment", &self.viewer_commitment)?;
        validate_hash("disclosure_policy_root", &self.disclosure_policy_root)?;
        validate_hash("encrypted_view_key_root", &self.encrypted_view_key_root)?;
        if self.limit > config.view_key_disclosure_limit_per_epoch {
            return Err("view-key disclosure limit exceeds config".to_string());
        }
        if self.consumed > self.limit {
            return Err("view-key disclosure consumed exceeds limit".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub role: AttestationRole,
    pub status: AttestationStatus,
    pub pq_key_commitment: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub binds_bucket_ids: BTreeSet<String>,
    pub binds_intent_ids: BTreeSet<String>,
    pub security_bits: u16,
    pub issued_height: u64,
    pub expires_at_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "pq_key_commitment": self.pq_key_commitment,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "binds_bucket_ids": self.binds_bucket_ids,
            "binds_intent_ids": self.binds_intent_ids,
            "security_bits": self.security_bits,
            "issued_height": self.issued_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("attestation_id", &self.attestation_id)?;
        validate_hash("subject_id", &self.subject_id)?;
        validate_hash("pq_key_commitment", &self.pq_key_commitment)?;
        validate_hash("signature_root", &self.signature_root)?;
        validate_hash("transcript_root", &self.transcript_root)?;
        if self.security_bits < config.min_pq_security_bits {
            return Err("pq attestation security below config".to_string());
        }
        validate_height_window("pq attestation", self.issued_height, self.expires_at_height)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFloor {
    pub floor_id: String,
    pub bucket_class: BucketClass,
    pub min_decoys: u16,
    pub target_decoys: u16,
    pub privacy_set_floor: u64,
    pub sampling_policy_root: String,
    pub active_from_height: u64,
    pub expires_at_height: u64,
}

impl DecoyFloor {
    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "bucket_class": self.bucket_class.as_str(),
            "min_decoys": self.min_decoys,
            "target_decoys": self.target_decoys,
            "privacy_set_floor": self.privacy_set_floor,
            "sampling_policy_root": self.sampling_policy_root,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("floor_id", &self.floor_id)?;
        validate_hash("sampling_policy_root", &self.sampling_policy_root)?;
        if self.min_decoys < config.min_decoy_floor || self.target_decoys < self.min_decoys {
            return Err("invalid decoy floor".to_string());
        }
        if self.privacy_set_floor < config.min_bucket_privacy_set {
            return Err("decoy floor privacy set below config".to_string());
        }
        validate_height_window(
            "decoy floor",
            self.active_from_height,
            self.expires_at_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCappedRebalancingCredit {
    pub credit_id: String,
    pub owner_commitment: String,
    pub status: CreditStatus,
    pub amount_piconero: u128,
    pub fee_cap_bps: u64,
    pub redeemed_intent_id: Option<String>,
    pub coupon_nullifier_root: String,
    pub issued_height: u64,
    pub expires_at_height: u64,
}

impl FeeCappedRebalancingCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status.as_str(),
            "amount_piconero": self.amount_piconero.to_string(),
            "fee_cap_bps": self.fee_cap_bps,
            "redeemed_intent_id": self.redeemed_intent_id,
            "coupon_nullifier_root": self.coupon_nullifier_root,
            "issued_height": self.issued_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("credit_id", &self.credit_id)?;
        validate_hash("owner_commitment", &self.owner_commitment)?;
        validate_hash("coupon_nullifier_root", &self.coupon_nullifier_root)?;
        if self.amount_piconero == 0 {
            return Err("fee credit amount is zero".to_string());
        }
        if self.fee_cap_bps > config.max_rebalance_fee_bps {
            return Err("fee credit cap exceeds rebalance fee cap".to_string());
        }
        validate_height_window("fee credit", self.issued_height, self.expires_at_height)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleBucketQuarantine {
    pub quarantine_id: String,
    pub bucket_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub previous_bucket_root: String,
    pub release_policy_root: String,
    pub quarantined_height: u64,
    pub release_after_height: u64,
}

impl StaleBucketQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "bucket_id": self.bucket_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "previous_bucket_root": self.previous_bucket_root,
            "release_policy_root": self.release_policy_root,
            "quarantined_height": self.quarantined_height,
            "release_after_height": self.release_after_height,
        })
    }

    pub fn validate(&self) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("quarantine_id", &self.quarantine_id)?;
        validate_hash("bucket_id", &self.bucket_id)?;
        validate_hash("evidence_root", &self.evidence_root)?;
        validate_hash("previous_bucket_root", &self.previous_bucket_root)?;
        validate_hash("release_policy_root", &self.release_policy_root)?;
        validate_height_window(
            "stale bucket quarantine",
            self.quarantined_height,
            self.release_after_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub scope: RedactionScope,
    pub subject_commitment: String,
    pub epoch: u64,
    pub allowance: u32,
    pub consumed: u32,
    pub redaction_policy_root: String,
    pub audit_commitment_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "scope": self.scope.as_str(),
            "subject_commitment": self.subject_commitment,
            "epoch": self.epoch,
            "allowance": self.allowance,
            "consumed": self.consumed,
            "remaining": self.allowance.saturating_sub(self.consumed),
            "redaction_policy_root": self.redaction_policy_root,
            "audit_commitment_root": self.audit_commitment_root,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("budget_id", &self.budget_id)?;
        validate_hash("subject_commitment", &self.subject_commitment)?;
        validate_hash("redaction_policy_root", &self.redaction_policy_root)?;
        validate_hash("audit_commitment_root", &self.audit_commitment_root)?;
        if self.allowance > config.privacy_redaction_budget_per_epoch {
            return Err("redaction allowance exceeds config".to_string());
        }
        if self.consumed > self.allowance {
            return Err("redaction budget consumed exceeds allowance".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicRootCheckpoint {
    pub checkpoint_id: String,
    pub epoch: u64,
    pub bucket_root: String,
    pub intent_root: String,
    pub disclosure_root: String,
    pub attestation_root: String,
    pub decoy_floor_root: String,
    pub fee_credit_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub generated_at_height: u64,
}

impl DeterministicRootCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "epoch": self.epoch,
            "bucket_root": self.bucket_root,
            "intent_root": self.intent_root,
            "disclosure_root": self.disclosure_root,
            "attestation_root": self.attestation_root,
            "decoy_floor_root": self.decoy_floor_root,
            "fee_credit_root": self.fee_credit_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "generated_at_height": self.generated_at_height,
        })
    }

    pub fn validate(&self) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("bucket_root", &self.bucket_root)?;
        validate_hash("intent_root", &self.intent_root)?;
        validate_hash("disclosure_root", &self.disclosure_root)?;
        validate_hash("attestation_root", &self.attestation_root)?;
        validate_hash("decoy_floor_root", &self.decoy_floor_root)?;
        validate_hash("fee_credit_root", &self.fee_credit_root)?;
        validate_hash("quarantine_root", &self.quarantine_root)?;
        validate_hash("redaction_budget_root", &self.redaction_budget_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub buckets: BTreeMap<String, SubaddressBucket>,
    pub intents: BTreeMap<String, LiquidityRebalanceIntent>,
    pub disclosure_limits: BTreeMap<String, ViewKeyDisclosureLimit>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub decoy_floors: BTreeMap<String, DecoyFloor>,
    pub fee_credits: BTreeMap<String, FeeCappedRebalancingCredit>,
    pub quarantines: BTreeMap<String, StaleBucketQuarantine>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub deterministic_checkpoints: BTreeMap<String, DeterministicRootCheckpoint>,
    pub disclosed_bucket_ids: BTreeSet<String>,
    pub quarantined_bucket_ids: BTreeSet<String>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            current_height: DEVNET_HEIGHT,
            current_epoch: 188,
            buckets: BTreeMap::new(),
            intents: BTreeMap::new(),
            disclosure_limits: BTreeMap::new(),
            attestations: BTreeMap::new(),
            decoy_floors: BTreeMap::new(),
            fee_credits: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_checkpoints: BTreeMap::new(),
            disclosed_bucket_ids: BTreeSet::new(),
            quarantined_bucket_ids: BTreeSet::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let ingress_id = fixture_hash("bucket", "ingress-0");
        let egress_id = fixture_hash("bucket", "egress-0");
        let maker_id = fixture_hash("bucket", "maker-0");
        let wallet_attestation_id = fixture_hash("attestation", "wallet-0");
        let operator_attestation_id = fixture_hash("attestation", "operator-0");
        let intent_id = fixture_hash("intent", "rebalance-0");
        let credit_id = fixture_hash("credit", "fee-credit-0");

        let mut wallet_buckets = BTreeSet::new();
        wallet_buckets.insert(ingress_id.clone());
        wallet_buckets.insert(egress_id.clone());
        let mut operator_buckets = wallet_buckets.clone();
        operator_buckets.insert(maker_id.clone());
        let mut operator_intents = BTreeSet::new();
        operator_intents.insert(intent_id.clone());

        state.attestations.insert(
            wallet_attestation_id.clone(),
            PqAttestation {
                attestation_id: wallet_attestation_id.clone(),
                subject_id: fixture_hash("wallet", "treasury-wallet"),
                role: AttestationRole::Wallet,
                status: AttestationStatus::Accepted,
                pq_key_commitment: fixture_hash("pq-key", "wallet"),
                signature_root: fixture_hash("pq-sig", "wallet"),
                transcript_root: fixture_hash("pq-transcript", "wallet"),
                binds_bucket_ids: wallet_buckets,
                binds_intent_ids: BTreeSet::new(),
                security_bits: 256,
                issued_height: DEVNET_HEIGHT - 24,
                expires_at_height: DEVNET_HEIGHT + state.config.attestation_ttl_blocks,
            },
        );
        state.attestations.insert(
            operator_attestation_id.clone(),
            PqAttestation {
                attestation_id: operator_attestation_id.clone(),
                subject_id: fixture_hash("operator", "operator-0"),
                role: AttestationRole::Operator,
                status: AttestationStatus::Accepted,
                pq_key_commitment: fixture_hash("pq-key", "operator"),
                signature_root: fixture_hash("pq-sig", "operator"),
                transcript_root: fixture_hash("pq-transcript", "operator"),
                binds_bucket_ids: operator_buckets,
                binds_intent_ids: operator_intents,
                security_bits: 256,
                issued_height: DEVNET_HEIGHT - 18,
                expires_at_height: DEVNET_HEIGHT + state.config.attestation_ttl_blocks,
            },
        );

        state.buckets.insert(
            ingress_id.clone(),
            SubaddressBucket {
                bucket_id: ingress_id.clone(),
                bucket_class: BucketClass::DepositIngress,
                status: BucketStatus::Open,
                subaddress_account: 0,
                subaddress_major: 44,
                subaddress_minor_start: 0,
                subaddress_minor_end: 511,
                subaddress_view_tag_root: fixture_hash("view-tags", "ingress"),
                encrypted_bucket_label: "ml-kem:sealed:ingress-liquidity".to_string(),
                bucket_commitment: fixture_hash("bucket-commitment", "ingress"),
                balance_commitment: fixture_hash("balance", "ingress"),
                liquidity_piconero: 8_750_000_000_000,
                reserved_piconero: 600_000_000_000,
                target_liquidity_piconero: 6_500_000_000_000,
                inbound_intent_count: 42,
                outbound_intent_count: 11,
                privacy_set_size: 196_608,
                decoy_floor: 64,
                view_key_disclosure_epoch: state.current_epoch,
                last_rebalanced_height: DEVNET_HEIGHT - 9,
                last_observed_height: DEVNET_HEIGHT - 2,
                created_height: DEVNET_HEIGHT - 9_600,
                operator_id: fixture_hash("operator", "operator-0"),
                wallet_attestation_id: wallet_attestation_id.clone(),
                operator_attestation_id: operator_attestation_id.clone(),
            },
        );
        state.buckets.insert(
            egress_id.clone(),
            SubaddressBucket {
                bucket_id: egress_id.clone(),
                bucket_class: BucketClass::WithdrawalEgress,
                status: BucketStatus::Draining,
                subaddress_account: 0,
                subaddress_major: 45,
                subaddress_minor_start: 512,
                subaddress_minor_end: 1023,
                subaddress_view_tag_root: fixture_hash("view-tags", "egress"),
                encrypted_bucket_label: "ml-kem:sealed:egress-liquidity".to_string(),
                bucket_commitment: fixture_hash("bucket-commitment", "egress"),
                balance_commitment: fixture_hash("balance", "egress"),
                liquidity_piconero: 2_100_000_000_000,
                reserved_piconero: 450_000_000_000,
                target_liquidity_piconero: 4_250_000_000_000,
                inbound_intent_count: 8,
                outbound_intent_count: 37,
                privacy_set_size: 147_456,
                decoy_floor: 64,
                view_key_disclosure_epoch: state.current_epoch,
                last_rebalanced_height: DEVNET_HEIGHT - 9,
                last_observed_height: DEVNET_HEIGHT - 1,
                created_height: DEVNET_HEIGHT - 9_600,
                operator_id: fixture_hash("operator", "operator-0"),
                wallet_attestation_id: wallet_attestation_id.clone(),
                operator_attestation_id: operator_attestation_id.clone(),
            },
        );
        state.buckets.insert(
            maker_id.clone(),
            SubaddressBucket {
                bucket_id: maker_id.clone(),
                bucket_class: BucketClass::MarketMaker,
                status: BucketStatus::Open,
                subaddress_account: 1,
                subaddress_major: 7,
                subaddress_minor_start: 0,
                subaddress_minor_end: 255,
                subaddress_view_tag_root: fixture_hash("view-tags", "maker"),
                encrypted_bucket_label: "ml-kem:sealed:maker-float".to_string(),
                bucket_commitment: fixture_hash("bucket-commitment", "maker"),
                balance_commitment: fixture_hash("balance", "maker"),
                liquidity_piconero: 5_500_000_000_000,
                reserved_piconero: 900_000_000_000,
                target_liquidity_piconero: 5_000_000_000_000,
                inbound_intent_count: 15,
                outbound_intent_count: 13,
                privacy_set_size: 262_144,
                decoy_floor: 80,
                view_key_disclosure_epoch: state.current_epoch,
                last_rebalanced_height: DEVNET_HEIGHT - 4,
                last_observed_height: DEVNET_HEIGHT,
                created_height: DEVNET_HEIGHT - 7_200,
                operator_id: fixture_hash("operator", "operator-0"),
                wallet_attestation_id,
                operator_attestation_id: operator_attestation_id.clone(),
            },
        );

        state.intents.insert(
            intent_id.clone(),
            LiquidityRebalanceIntent {
                intent_id: intent_id.clone(),
                status: IntentStatus::Committed,
                source_bucket_id: ingress_id.clone(),
                target_bucket_id: egress_id.clone(),
                amount_commitment: fixture_hash("amount", "rebalance-0"),
                amount_piconero: 1_250_000_000_000,
                max_fee_bps: 8,
                fee_credit_id: Some(credit_id.clone()),
                decoy_floor: 64,
                privacy_set_size: 147_456,
                view_key_disclosure_budget: 1,
                redaction_budget: 4,
                deterministic_route_root: fixture_hash("route", "ingress-to-egress"),
                wallet_attestation_id: fixture_hash("attestation", "wallet-0"),
                operator_attestation_id: operator_attestation_id.clone(),
                nullifier_root: fixture_hash("nullifier", "rebalance-0"),
                proof_root: fixture_hash("proof", "rebalance-0"),
                created_height: DEVNET_HEIGHT - 6,
                expires_at_height: DEVNET_HEIGHT + state.config.intent_ttl_blocks,
                settled_height: None,
            },
        );

        state.disclosure_limits.insert(
            fixture_hash("disclosure", "egress-view-window"),
            ViewKeyDisclosureLimit {
                disclosure_id: fixture_hash("disclosure", "egress-view-window"),
                bucket_id: egress_id.clone(),
                viewer_commitment: fixture_hash("viewer", "watchtower-0"),
                status: DisclosureStatus::Reserved,
                epoch: state.current_epoch,
                limit: 2,
                consumed: 1,
                disclosure_policy_root: fixture_hash("disclosure-policy", "egress"),
                encrypted_view_key_root: fixture_hash("sealed-view-key", "egress"),
                expires_at_height: DEVNET_HEIGHT + 48,
            },
        );

        for class in [
            BucketClass::DepositIngress,
            BucketClass::WithdrawalEgress,
            BucketClass::MarketMaker,
        ] {
            state.decoy_floors.insert(
                fixture_hash("decoy-floor", class.as_str()),
                DecoyFloor {
                    floor_id: fixture_hash("decoy-floor", class.as_str()),
                    bucket_class: class,
                    min_decoys: 48,
                    target_decoys: class.target_fill_bps(&state.config) as u16 / 100,
                    privacy_set_floor: state.config.min_bucket_privacy_set,
                    sampling_policy_root: fixture_hash("decoy-sampling", class.as_str()),
                    active_from_height: DEVNET_HEIGHT - 1_000,
                    expires_at_height: DEVNET_HEIGHT + 10_000,
                },
            );
        }

        state.fee_credits.insert(
            credit_id.clone(),
            FeeCappedRebalancingCredit {
                credit_id,
                owner_commitment: fixture_hash("credit-owner", "operator-0"),
                status: CreditStatus::Reserved,
                amount_piconero: 15_000_000_000,
                fee_cap_bps: 8,
                redeemed_intent_id: Some(intent_id.clone()),
                coupon_nullifier_root: fixture_hash("credit-nullifier", "fee-credit-0"),
                issued_height: DEVNET_HEIGHT - 32,
                expires_at_height: DEVNET_HEIGHT + state.config.fee_credit_ttl_blocks,
            },
        );

        let quarantine_id = fixture_hash("quarantine", "stale-demo");
        state.quarantines.insert(
            quarantine_id.clone(),
            StaleBucketQuarantine {
                quarantine_id: quarantine_id.clone(),
                bucket_id: fixture_hash("bucket", "retired-stale-0"),
                reason: QuarantineReason::StaleBucket,
                evidence_root: fixture_hash("quarantine-evidence", "stale-demo"),
                previous_bucket_root: fixture_hash("previous-bucket", "stale-demo"),
                release_policy_root: fixture_hash("release-policy", "stale-demo"),
                quarantined_height: DEVNET_HEIGHT - 80,
                release_after_height: DEVNET_HEIGHT + state.config.quarantine_blocks,
            },
        );
        state
            .quarantined_bucket_ids
            .insert(fixture_hash("bucket", "retired-stale-0"));

        for (scope, label, consumed) in [
            (RedactionScope::BucketAggregate, "bucket-aggregate", 5),
            (RedactionScope::ViewKeyWindow, "view-key-window", 1),
            (RedactionScope::RebalanceIntent, "rebalance-intent", 3),
        ] {
            state.redaction_budgets.insert(
                fixture_hash("redaction-budget", label),
                PrivacyRedactionBudget {
                    budget_id: fixture_hash("redaction-budget", label),
                    scope,
                    subject_commitment: fixture_hash("redaction-subject", label),
                    epoch: state.current_epoch,
                    allowance: state.config.privacy_redaction_budget_per_epoch,
                    consumed,
                    redaction_policy_root: fixture_hash("redaction-policy", label),
                    audit_commitment_root: fixture_hash("redaction-audit", label),
                },
            );
        }

        state.disclosed_bucket_ids.insert(egress_id);
        state.counters = Counters {
            buckets_open: 2,
            buckets_quarantined: 1,
            intents_committed: 1,
            intents_settled: 0,
            view_key_disclosures_consumed: 1,
            wallet_attestations_accepted: 1,
            operator_attestations_accepted: 1,
            decoy_floor_breaches: 0,
            fee_credits_minted: 1,
            fee_credits_redeemed: 0,
            stale_bucket_quarantines: 1,
            privacy_redactions_consumed: 9,
        };
        state.recompute_roots();
        let checkpoint_id = fixture_hash("checkpoint", "demo-roots");
        state.deterministic_checkpoints.insert(
            checkpoint_id.clone(),
            DeterministicRootCheckpoint {
                checkpoint_id,
                epoch: state.current_epoch,
                bucket_root: state.roots.bucket_root.clone(),
                intent_root: state.roots.intent_root.clone(),
                disclosure_root: state.roots.disclosure_root.clone(),
                attestation_root: state.roots.attestation_root.clone(),
                decoy_floor_root: state.roots.decoy_floor_root.clone(),
                fee_credit_root: state.roots.fee_credit_root.clone(),
                quarantine_root: state.roots.quarantine_root.clone(),
                redaction_budget_root: state.roots.redaction_budget_root.clone(),
                generated_at_height: state.current_height,
            },
        );
        state.recompute_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "bucket_root": self.roots.bucket_root,
                "intent_root": self.roots.intent_root,
                "disclosure_root": self.roots.disclosure_root,
                "attestation_root": self.roots.attestation_root,
                "decoy_floor_root": self.roots.decoy_floor_root,
                "fee_credit_root": self.roots.fee_credit_root,
                "quarantine_root": self.roots.quarantine_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "deterministic_root": self.roots.deterministic_root,
                "counters_root": self.roots.counters_root,
            },
            "bucket_count": self.buckets.len(),
            "intent_count": self.intents.len(),
            "disclosure_limit_count": self.disclosure_limits.len(),
            "attestation_count": self.attestations.len(),
            "decoy_floor_count": self.decoy_floors.len(),
            "fee_credit_count": self.fee_credits.len(),
            "quarantine_count": self.quarantines.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "deterministic_checkpoint_count": self.deterministic_checkpoints.len(),
            "disclosed_bucket_ids": self.disclosed_bucket_ids,
            "quarantined_bucket_ids": self.quarantined_bucket_ids,
        })
    }

    pub fn recompute_roots(&mut self) {
        let config_root = record_root("SUBADDRESS-REBALANCE-CONFIG", &self.config.public_record());
        let bucket_root = map_root(
            "SUBADDRESS-REBALANCE-BUCKETS",
            self.buckets.values().map(SubaddressBucket::public_record),
        );
        let intent_root = map_root(
            "SUBADDRESS-REBALANCE-INTENTS",
            self.intents
                .values()
                .map(LiquidityRebalanceIntent::public_record),
        );
        let disclosure_root = map_root(
            "SUBADDRESS-REBALANCE-DISCLOSURES",
            self.disclosure_limits
                .values()
                .map(ViewKeyDisclosureLimit::public_record),
        );
        let attestation_root = map_root(
            "SUBADDRESS-REBALANCE-ATTESTATIONS",
            self.attestations.values().map(PqAttestation::public_record),
        );
        let decoy_floor_root = map_root(
            "SUBADDRESS-REBALANCE-DECOY-FLOORS",
            self.decoy_floors.values().map(DecoyFloor::public_record),
        );
        let fee_credit_root = map_root(
            "SUBADDRESS-REBALANCE-FEE-CREDITS",
            self.fee_credits
                .values()
                .map(FeeCappedRebalancingCredit::public_record),
        );
        let quarantine_root = map_root(
            "SUBADDRESS-REBALANCE-QUARANTINES",
            self.quarantines
                .values()
                .map(StaleBucketQuarantine::public_record),
        );
        let redaction_budget_root = map_root(
            "SUBADDRESS-REBALANCE-REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record),
        );
        let deterministic_root = map_root(
            "SUBADDRESS-REBALANCE-DETERMINISTIC-CHECKPOINTS",
            self.deterministic_checkpoints
                .values()
                .map(DeterministicRootCheckpoint::public_record),
        );
        let counters_root = record_root(
            "SUBADDRESS-REBALANCE-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots = Roots {
            config_root,
            bucket_root,
            intent_root,
            disclosure_root,
            attestation_root,
            decoy_floor_root,
            fee_credit_root,
            quarantine_root,
            redaction_budget_root,
            deterministic_root,
            counters_root,
            state_root: String::new(),
        };
        self.roots.state_root =
            state_root_from_public_record(&self.public_record_without_state_root());
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn validate(&self) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
        self.config.validate()?;
        if self.buckets.len() > self.config.max_subaddress_buckets {
            return Err("too many subaddress buckets".to_string());
        }
        if self.intents.len() > self.config.max_active_intents {
            return Err("too many rebalance intents".to_string());
        }
        if self.disclosure_limits.len() > self.config.max_disclosure_limits {
            return Err("too many disclosure limits".to_string());
        }
        if self.fee_credits.len() > self.config.max_fee_credits {
            return Err("too many fee credits".to_string());
        }
        if self.quarantines.len() > self.config.max_quarantines {
            return Err("too many quarantines".to_string());
        }
        if self.redaction_budgets.len() > self.config.max_redaction_budgets {
            return Err("too many redaction budgets".to_string());
        }
        for bucket in self.buckets.values() {
            bucket.validate(&self.config)?;
        }
        for intent in self.intents.values() {
            intent.validate(&self.config)?;
            if !self.buckets.contains_key(&intent.source_bucket_id) {
                return Err("rebalance intent references missing source bucket".to_string());
            }
            if !self.buckets.contains_key(&intent.target_bucket_id) {
                return Err("rebalance intent references missing target bucket".to_string());
            }
        }
        for disclosure in self.disclosure_limits.values() {
            disclosure.validate(&self.config)?;
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.config)?;
        }
        for floor in self.decoy_floors.values() {
            floor.validate(&self.config)?;
        }
        for credit in self.fee_credits.values() {
            credit.validate(&self.config)?;
        }
        for quarantine in self.quarantines.values() {
            quarantine.validate()?;
        }
        for budget in self.redaction_budgets.values() {
            budget.validate(&self.config)?;
        }
        for checkpoint in self.deterministic_checkpoints.values() {
            checkpoint.validate()?;
        }
        if self.state_root() != self.roots.state_root {
            return Err("state root mismatch".to_string());
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "SUBADDRESS-REBALANCE-PUBLIC-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn validate_height_window(
    label: &str,
    start: u64,
    end: u64,
) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
    if end <= start {
        return Err(format!("{label} height window is empty"));
    }
    Ok(())
}

fn validate_hash(
    label: &str,
    value: &str,
) -> MoneroL2PqPrivateSubaddressLiquidityRebalanceRuntimeResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 32-byte hex root"));
    }
    Ok(())
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn fixture_hash(domain: &str, label: &str) -> String {
    domain_hash(
        "SUBADDRESS-REBALANCE-FIXTURE",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_is_deterministic() {
        let a = State::devnet();
        let b = State::devnet();
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(devnet().state_root(), a.state_root());
    }

    #[test]
    fn demo_validates_and_has_private_public_roots() {
        let state = State::demo();
        state.validate().expect("demo fixture validates");
        let record = public_record(&state);
        assert_eq!(state_root(&state), record["state_root"]);
    }
}
