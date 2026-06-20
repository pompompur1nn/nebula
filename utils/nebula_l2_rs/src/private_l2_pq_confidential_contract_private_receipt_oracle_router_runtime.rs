use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateReceiptOracleRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_RECEIPT_ORACLE_ROUTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-private-receipt-oracle-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_RECEIPT_ORACLE_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_ROUTER_ID: &str =
    "private-l2-pq-confidential-contract-private-receipt-oracle-router-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RENT_ASSET_ID: &str = "private-l2-rent-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 1_940_800;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024-sealed-confidential-contract-private-receipt-v1";
pub const RECEIPT_COMMITMENT_SCHEME: &str =
    "private-l2-confidential-contract-receipt-commitment-root-v1";
pub const ORACLE_ROUTE_INTENT_SCHEME: &str =
    "private-l2-confidential-contract-oracle-route-intent-root-v1";
pub const SUBSCRIBER_FILTER_SCHEME: &str = "private-l2-private-receipt-subscriber-filter-root-v1";
pub const PQ_ORACLE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-private-oracle-attestation-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "private-l2-selective-disclosure-redaction-budget-root-v1";
pub const LOW_FEE_REWARD_SCHEME: &str = "private-l2-low-fee-oracle-routing-reward-root-v1";
pub const NAMESPACE_RENT_CREDIT_SCHEME: &str =
    "private-l2-confidential-contract-namespace-rent-credit-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "private-l2-pq-confidential-contract-oracle-operator-summary-root-v1";
pub const REPLAY_FENCE_SCHEME: &str =
    "private-l2-confidential-contract-private-receipt-oracle-router-replay-fence-v1";
pub const REPLAY_DOMAIN: &str =
    "private-l2-pq-confidential-contract-private-receipt-oracle-router-runtime-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FILTER_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_REWARD_EPOCH_BLOCKS: u64 = 360;
pub const DEFAULT_RENT_EPOCH_BLOCKS: u64 = 10_080;
pub const DEFAULT_LOW_FEE_BPS: u64 = 2;
pub const DEFAULT_STANDARD_FEE_BPS: u64 = 8;
pub const DEFAULT_FAST_FEE_BPS: u64 = 13;
pub const DEFAULT_EMERGENCY_FEE_BPS: u64 = 30;
pub const DEFAULT_REWARD_BPS: u64 = 5;
pub const DEFAULT_RENT_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_MIN_ORACLE_WEIGHT: u64 = 7;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRICT_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_BATCH_RECEIPTS: usize = 768;
pub const DEFAULT_MAX_FILTER_KEYS: usize = 64;
pub const MAX_ENCRYPTED_RECEIPTS: usize = 4_194_304;
pub const MAX_ORACLE_ROUTE_INTENTS: usize = 2_097_152;
pub const MAX_SUBSCRIBER_FILTERS: usize = 1_048_576;
pub const MAX_PQ_ORACLE_ATTESTATIONS: usize = 8_388_608;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_LOW_FEE_REWARDS: usize = 2_097_152;
pub const MAX_NAMESPACE_RENT_CREDITS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_REPLAY_FENCES: usize = 8_388_608;
pub const MAX_EVENTS: usize = 8_388_608;

macro_rules! snake_enum {
    ($name:ident { $($variant:ident => $text:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

snake_enum!(ContractDomain {
    Settlement => "settlement",
    Dex => "dex",
    Lending => "lending",
    Perps => "perps",
    Nft => "nft",
    Bridge => "bridge",
    Governance => "governance",
    Compliance => "compliance"
});

snake_enum!(ReceiptKind {
    Execution => "execution",
    EventLog => "event_log",
    Payment => "payment",
    OracleAnswer => "oracle_answer",
    Liquidation => "liquidation",
    Settlement => "settlement",
    Upgrade => "upgrade",
    Emergency => "emergency"
});

snake_enum!(ReceiptStatus {
    Sealed => "sealed",
    Routed => "routed",
    Filtered => "filtered",
    Attested => "attested",
    Delivered => "delivered",
    Redacted => "redacted",
    Settled => "settled",
    Expired => "expired",
    Revoked => "revoked",
    Disputed => "disputed"
});

impl ReceiptStatus {
    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Routed | Self::Filtered | Self::Attested | Self::Delivered
        )
    }
}

snake_enum!(RouteLane {
    LowFee => "low_fee",
    Standard => "standard",
    Fast => "fast",
    Bulk => "bulk",
    Compliance => "compliance",
    Emergency => "emergency"
});

impl RouteLane {
    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::Bulk => config.low_fee_bps,
            Self::Standard | Self::Compliance => config.standard_fee_bps,
            Self::Fast => config.fast_fee_bps,
            Self::Emergency => config.emergency_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::Compliance => 900,
            Self::Standard => 760,
            Self::LowFee => 700,
            Self::Bulk => 620,
        }
    }
}

snake_enum!(OracleIntentStatus {
    Drafted => "drafted",
    Active => "active",
    Matched => "matched",
    QuorumAttested => "quorum_attested",
    Delivering => "delivering",
    Settled => "settled",
    Expired => "expired",
    Cancelled => "cancelled",
    Slashed => "slashed"
});

impl OracleIntentStatus {
    pub fn routable(self) -> bool {
        matches!(self, Self::Active | Self::Matched | Self::QuorumAttested)
    }
}

snake_enum!(FilterMode {
    CommitmentPrefix => "commitment_prefix",
    Namespace => "namespace",
    ContractSelector => "contract_selector",
    EventTopic => "event_topic",
    ViewTagBucket => "view_tag_bucket",
    NullifierFence => "nullifier_fence",
    RedactionPolicy => "redaction_policy",
    EmergencyAudit => "emergency_audit"
});

snake_enum!(FilterStatus {
    Drafted => "drafted",
    Active => "active",
    Paused => "paused",
    Exhausted => "exhausted",
    Expired => "expired",
    Revoked => "revoked"
});

impl FilterStatus {
    pub fn accepts(self) -> bool {
        matches!(self, Self::Active)
    }
}

snake_enum!(AttestationKind {
    ReceiptAuthenticity => "receipt_authenticity",
    OracleAnswer => "oracle_answer",
    RouteCompleteness => "route_completeness",
    PrivacySet => "privacy_set",
    RedactionCorrectness => "redaction_correctness",
    FeeSponsorship => "fee_sponsorship",
    NamespaceRent => "namespace_rent",
    EmergencyOverride => "emergency_override"
});

snake_enum!(AttestationStatus {
    Submitted => "submitted",
    Accepted => "accepted",
    WeakQuorum => "weak_quorum",
    Superseded => "superseded",
    Expired => "expired",
    Rejected => "rejected",
    Slashed => "slashed"
});

impl AttestationStatus {
    pub fn trusted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

snake_enum!(RedactionScope {
    Amount => "amount",
    Address => "address",
    ContractCall => "contract_call",
    EventTopic => "event_topic",
    Payload => "payload",
    OracleAnswer => "oracle_answer",
    OperatorSet => "operator_set",
    Emergency => "emergency"
});

snake_enum!(BudgetStatus {
    Open => "open",
    Reserved => "reserved",
    Consumed => "consumed",
    Exhausted => "exhausted",
    Expired => "expired",
    Revoked => "revoked"
});

impl BudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

snake_enum!(RewardStatus {
    Accruing => "accruing",
    Claimable => "claimable",
    Claimed => "claimed",
    ClawedBack => "clawed_back",
    Expired => "expired"
});

snake_enum!(RentCreditStatus {
    Open => "open",
    Reserved => "reserved",
    Applied => "applied",
    Refunded => "refunded",
    Expired => "expired",
    Slashed => "slashed"
});

snake_enum!(OperatorStatus {
    Joining => "joining",
    Active => "active",
    Throttled => "throttled",
    Draining => "draining",
    Suspended => "suspended",
    Slashed => "slashed",
    Retired => "retired"
});

impl OperatorStatus {
    pub fn can_route(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Draining)
    }
}

snake_enum!(ReplayFenceKind {
    ReceiptNullifier => "receipt_nullifier",
    RouteNonce => "route_nonce",
    SubscriberNonce => "subscriber_nonce",
    AttestationNonce => "attestation_nonce",
    RedactionNonce => "redaction_nonce",
    RewardClaim => "reward_claim",
    RentEpoch => "rent_epoch"
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub router_id: String,
    pub fee_asset_id: String,
    pub rent_asset_id: String,
    pub hash_suite: String,
    pub receipt_encryption_scheme: String,
    pub receipt_commitment_scheme: String,
    pub oracle_route_intent_scheme: String,
    pub subscriber_filter_scheme: String,
    pub pq_oracle_attestation_scheme: String,
    pub redaction_budget_scheme: String,
    pub low_fee_reward_scheme: String,
    pub namespace_rent_credit_scheme: String,
    pub operator_summary_scheme: String,
    pub replay_fence_scheme: String,
    pub replay_domain: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub receipt_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub filter_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub reward_epoch_blocks: u64,
    pub rent_epoch_blocks: u64,
    pub low_fee_bps: u64,
    pub standard_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub reward_bps: u64,
    pub rent_rebate_bps: u64,
    pub min_oracle_weight: u64,
    pub quorum_bps: u64,
    pub strict_quorum_bps: u64,
    pub max_batch_receipts: usize,
    pub max_filter_keys: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rent_asset_id: DEVNET_RENT_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            receipt_encryption_scheme: RECEIPT_ENCRYPTION_SCHEME.to_string(),
            receipt_commitment_scheme: RECEIPT_COMMITMENT_SCHEME.to_string(),
            oracle_route_intent_scheme: ORACLE_ROUTE_INTENT_SCHEME.to_string(),
            subscriber_filter_scheme: SUBSCRIBER_FILTER_SCHEME.to_string(),
            pq_oracle_attestation_scheme: PQ_ORACLE_ATTESTATION_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            low_fee_reward_scheme: LOW_FEE_REWARD_SCHEME.to_string(),
            namespace_rent_credit_scheme: NAMESPACE_RENT_CREDIT_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            replay_fence_scheme: REPLAY_FENCE_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            filter_ttl_blocks: DEFAULT_FILTER_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            reward_epoch_blocks: DEFAULT_REWARD_EPOCH_BLOCKS,
            rent_epoch_blocks: DEFAULT_RENT_EPOCH_BLOCKS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            standard_fee_bps: DEFAULT_STANDARD_FEE_BPS,
            fast_fee_bps: DEFAULT_FAST_FEE_BPS,
            emergency_fee_bps: DEFAULT_EMERGENCY_FEE_BPS,
            reward_bps: DEFAULT_REWARD_BPS,
            rent_rebate_bps: DEFAULT_RENT_REBATE_BPS,
            min_oracle_weight: DEFAULT_MIN_ORACLE_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strict_quorum_bps: DEFAULT_STRICT_QUORUM_BPS,
            max_batch_receipts: DEFAULT_MAX_BATCH_RECEIPTS,
            max_filter_keys: DEFAULT_MAX_FILTER_KEYS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "router_id": self.router_id,
            "fee_asset_id": self.fee_asset_id,
            "rent_asset_id": self.rent_asset_id,
            "hash_suite": self.hash_suite,
            "receipt_encryption_scheme": self.receipt_encryption_scheme,
            "receipt_commitment_scheme": self.receipt_commitment_scheme,
            "oracle_route_intent_scheme": self.oracle_route_intent_scheme,
            "subscriber_filter_scheme": self.subscriber_filter_scheme,
            "pq_oracle_attestation_scheme": self.pq_oracle_attestation_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "low_fee_reward_scheme": self.low_fee_reward_scheme,
            "namespace_rent_credit_scheme": self.namespace_rent_credit_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "replay_fence_scheme": self.replay_fence_scheme,
            "replay_domain": self.replay_domain,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "filter_ttl_blocks": self.filter_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "reward_epoch_blocks": self.reward_epoch_blocks,
            "rent_epoch_blocks": self.rent_epoch_blocks,
            "low_fee_bps": self.low_fee_bps,
            "standard_fee_bps": self.standard_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "emergency_fee_bps": self.emergency_fee_bps,
            "reward_bps": self.reward_bps,
            "rent_rebate_bps": self.rent_rebate_bps,
            "min_oracle_weight": self.min_oracle_weight,
            "quorum_bps": self.quorum_bps,
            "strict_quorum_bps": self.strict_quorum_bps,
            "max_batch_receipts": self.max_batch_receipts,
            "max_filter_keys": self.max_filter_keys
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty(&self.router_id, "router_id")?;
        ensure_nonempty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_nonempty(&self.rent_asset_id, "rent_asset_id")?;
        ensure_bps(self.low_fee_bps, "low_fee_bps")?;
        ensure_bps(self.standard_fee_bps, "standard_fee_bps")?;
        ensure_bps(self.fast_fee_bps, "fast_fee_bps")?;
        ensure_bps(self.emergency_fee_bps, "emergency_fee_bps")?;
        ensure_bps(self.reward_bps, "reward_bps")?;
        ensure_bps(self.rent_rebate_bps, "rent_rebate_bps")?;
        ensure_bps(self.quorum_bps, "quorum_bps")?;
        ensure_bps(self.strict_quorum_bps, "strict_quorum_bps")?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below private L2 floor".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set size below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub height: u64,
    pub encrypted_receipts: u64,
    pub oracle_route_intents: u64,
    pub subscriber_filters: u64,
    pub pq_oracle_attestations: u64,
    pub redaction_budgets: u64,
    pub low_fee_rewards: u64,
    pub namespace_rent_credits: u64,
    pub operator_summaries: u64,
    pub replay_fences: u64,
    pub events: u64,
    pub delivered_receipts: u64,
    pub redacted_receipts: u64,
    pub settled_routes: u64,
    pub total_fee_units: u64,
    pub total_reward_units: u64,
    pub total_rent_credit_units: u64,
}

impl Counters {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "encrypted_receipts": self.encrypted_receipts,
            "oracle_route_intents": self.oracle_route_intents,
            "subscriber_filters": self.subscriber_filters,
            "pq_oracle_attestations": self.pq_oracle_attestations,
            "redaction_budgets": self.redaction_budgets,
            "low_fee_rewards": self.low_fee_rewards,
            "namespace_rent_credits": self.namespace_rent_credits,
            "operator_summaries": self.operator_summaries,
            "replay_fences": self.replay_fences,
            "events": self.events,
            "delivered_receipts": self.delivered_receipts,
            "redacted_receipts": self.redacted_receipts,
            "settled_routes": self.settled_routes,
            "total_fee_units": self.total_fee_units,
            "total_reward_units": self.total_reward_units,
            "total_rent_credit_units": self.total_rent_credit_units
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub encrypted_receipt_root: String,
    pub oracle_route_intent_root: String,
    pub subscriber_filter_root: String,
    pub pq_oracle_attestation_root: String,
    pub redaction_budget_root: String,
    pub low_fee_reward_root: String,
    pub namespace_rent_credit_root: String,
    pub operator_summary_root: String,
    pub replay_fence_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "oracle_route_intent_root": self.oracle_route_intent_root,
            "subscriber_filter_root": self.subscriber_filter_root,
            "pq_oracle_attestation_root": self.pq_oracle_attestation_root,
            "redaction_budget_root": self.redaction_budget_root,
            "low_fee_reward_root": self.low_fee_reward_root,
            "namespace_rent_credit_root": self.namespace_rent_credit_root,
            "operator_summary_root": self.operator_summary_root,
            "replay_fence_root": self.replay_fence_root,
            "event_root": self.event_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPrivateReceipt {
    pub receipt_id: String,
    pub contract_id: String,
    pub namespace_id: String,
    pub receipt_kind: ReceiptKind,
    pub domain: ContractDomain,
    pub status: ReceiptStatus,
    pub lane: RouteLane,
    pub owner_commitment: String,
    pub subscriber_commitment: String,
    pub receipt_commitment: String,
    pub payload_ciphertext_root: String,
    pub payload_key_commitment: String,
    pub event_topic_root: String,
    pub nullifier: String,
    pub privacy_set_root: String,
    pub privacy_set_size: u64,
    pub redaction_policy_root: String,
    pub fee_commitment: String,
    pub fee_bps: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl EncryptedPrivateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "contract_id": self.contract_id,
            "namespace_id": self.namespace_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "owner_commitment": self.owner_commitment,
            "subscriber_commitment": self.subscriber_commitment,
            "receipt_commitment": self.receipt_commitment,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "payload_key_commitment": self.payload_key_commitment,
            "event_topic_root": self.event_topic_root,
            "nullifier": self.nullifier,
            "privacy_set_root": self.privacy_set_root,
            "privacy_set_size": self.privacy_set_size,
            "redaction_policy_root": self.redaction_policy_root,
            "fee_commitment": self.fee_commitment,
            "fee_bps": self.fee_bps,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn expired(&self, height: u64) -> bool {
        height >= self.expires_height
    }

    pub fn privacy_floor_met(&self, config: &Config) -> bool {
        self.privacy_set_size >= config.min_privacy_set_size
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleRouteIntent {
    pub intent_id: String,
    pub receipt_id: String,
    pub namespace_id: String,
    pub subscriber_filter_id: String,
    pub requested_kind: AttestationKind,
    pub lane: RouteLane,
    pub status: OracleIntentStatus,
    pub payer_commitment: String,
    pub oracle_committee_id: String,
    pub answer_commitment_root: String,
    pub required_weight: u64,
    pub matched_weight: u64,
    pub fee_cap_bps: u64,
    pub max_fee_units: u64,
    pub priority: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl OracleRouteIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "namespace_id": self.namespace_id,
            "subscriber_filter_id": self.subscriber_filter_id,
            "requested_kind": self.requested_kind.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "payer_commitment": self.payer_commitment,
            "oracle_committee_id": self.oracle_committee_id,
            "answer_commitment_root": self.answer_commitment_root,
            "required_weight": self.required_weight,
            "matched_weight": self.matched_weight,
            "fee_cap_bps": self.fee_cap_bps,
            "max_fee_units": self.max_fee_units,
            "priority": self.priority,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn quorum_bps(&self) -> u64 {
        bps(self.matched_weight, self.required_weight)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriberFilter {
    pub filter_id: String,
    pub subscriber_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub mode: FilterMode,
    pub status: FilterStatus,
    pub key_commitments: BTreeSet<String>,
    pub min_privacy_set_size: u64,
    pub allowed_receipt_kinds: BTreeSet<ReceiptKind>,
    pub redaction_scope: BTreeSet<RedactionScope>,
    pub delivery_commitment: String,
    pub view_grant_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl SubscriberFilter {
    pub fn public_record(&self) -> Value {
        json!({
            "filter_id": self.filter_id,
            "subscriber_id": self.subscriber_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "mode": self.mode.as_str(),
            "status": self.status.as_str(),
            "key_commitments": self.key_commitments,
            "min_privacy_set_size": self.min_privacy_set_size,
            "allowed_receipt_kinds": self.allowed_receipt_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "redaction_scope": self.redaction_scope.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "delivery_commitment": self.delivery_commitment,
            "view_grant_root": self.view_grant_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn accepts_kind(&self, kind: ReceiptKind) -> bool {
        self.status.accepts() && self.allowed_receipt_kinds.contains(&kind)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub intent_id: String,
    pub receipt_id: String,
    pub oracle_id: String,
    pub committee_id: String,
    pub attestation_kind: AttestationKind,
    pub status: AttestationStatus,
    pub pq_scheme: String,
    pub aggregate_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub answer_commitment_root: String,
    pub redacted_payload_root: String,
    pub privacy_set_root: String,
    pub oracle_weight: u64,
    pub pq_security_bits: u16,
    pub signed_height: u64,
    pub expires_height: u64,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "oracle_id": self.oracle_id,
            "committee_id": self.committee_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "status": self.status.as_str(),
            "pq_scheme": self.pq_scheme,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "answer_commitment_root": self.answer_commitment_root,
            "redacted_payload_root": self.redacted_payload_root,
            "privacy_set_root": self.privacy_set_root,
            "oracle_weight": self.oracle_weight,
            "pq_security_bits": self.pq_security_bits,
            "signed_height": self.signed_height,
            "expires_height": self.expires_height
        })
    }

    pub fn acceptable_for(&self, config: &Config) -> bool {
        self.status.trusted()
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.oracle_weight >= config.min_oracle_weight
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub namespace_id: String,
    pub subscriber_id: String,
    pub scope: RedactionScope,
    pub status: BudgetStatus,
    pub epoch: u64,
    pub total_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub max_payload_bytes: u64,
    pub policy_root: String,
    pub audit_commitment_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "namespace_id": self.namespace_id,
            "subscriber_id": self.subscriber_id,
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "max_payload_bytes": self.max_payload_bytes,
            "policy_root": self.policy_root,
            "audit_commitment_root": self.audit_commitment_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRoutingReward {
    pub reward_id: String,
    pub intent_id: String,
    pub receipt_id: String,
    pub operator_id: String,
    pub lane: RouteLane,
    pub status: RewardStatus,
    pub fee_asset_id: String,
    pub fee_commitment: String,
    pub reward_commitment: String,
    pub fee_units: u64,
    pub reward_units: u64,
    pub sponsored_bps: u64,
    pub epoch: u64,
    pub created_height: u64,
    pub claimable_height: u64,
}

impl LowFeeRoutingReward {
    pub fn public_record(&self) -> Value {
        json!({
            "reward_id": self.reward_id,
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "operator_id": self.operator_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "fee_commitment": self.fee_commitment,
            "reward_commitment": self.reward_commitment,
            "fee_units": self.fee_units,
            "reward_units": self.reward_units,
            "sponsored_bps": self.sponsored_bps,
            "epoch": self.epoch,
            "created_height": self.created_height,
            "claimable_height": self.claimable_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceRentCredit {
    pub credit_id: String,
    pub namespace_id: String,
    pub sponsor_id: String,
    pub status: RentCreditStatus,
    pub rent_asset_id: String,
    pub credit_commitment: String,
    pub applied_to_receipt_root: String,
    pub credit_units: u64,
    pub rebate_bps: u64,
    pub epoch: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl NamespaceRentCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "namespace_id": self.namespace_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "rent_asset_id": self.rent_asset_id,
            "credit_commitment": self.credit_commitment,
            "applied_to_receipt_root": self.applied_to_receipt_root,
            "credit_units": self.credit_units,
            "rebate_bps": self.rebate_bps,
            "epoch": self.epoch,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub committee_id: String,
    pub status: OperatorStatus,
    pub pq_public_key_root: String,
    pub route_capacity: u64,
    pub active_routes: u64,
    pub delivered_receipts: u64,
    pub attested_receipts: u64,
    pub redaction_failures: u64,
    pub slash_points: u64,
    pub average_fee_bps: u64,
    pub uptime_bps: u64,
    pub last_seen_height: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "route_capacity": self.route_capacity,
            "active_routes": self.active_routes,
            "delivered_receipts": self.delivered_receipts,
            "attested_receipts": self.attested_receipts,
            "redaction_failures": self.redaction_failures,
            "slash_points": self.slash_points,
            "average_fee_bps": self.average_fee_bps,
            "uptime_bps": self.uptime_bps,
            "last_seen_height": self.last_seen_height,
            "summary_root": self.summary_root
        })
    }

    pub fn available_capacity(&self) -> u64 {
        self.route_capacity.saturating_sub(self.active_routes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub kind: ReplayFenceKind,
    pub subject_id: String,
    pub nullifier: String,
    pub namespace_id: String,
    pub height: u64,
    pub expires_height: u64,
}

impl ReplayFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "nullifier": self.nullifier,
            "namespace_id": self.namespace_id,
            "height": self.height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub record_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "record_root": self.record_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub encrypted_receipts: BTreeMap<String, EncryptedPrivateReceipt>,
    pub oracle_route_intents: BTreeMap<String, OracleRouteIntent>,
    pub subscriber_filters: BTreeMap<String, SubscriberFilter>,
    pub pq_oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub low_fee_rewards: BTreeMap<String, LowFeeRoutingReward>,
    pub namespace_rent_credits: BTreeMap<String, NamespaceRentCredit>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::new(height),
            encrypted_receipts: BTreeMap::new(),
            oracle_route_intents: BTreeMap::new(),
            subscriber_filters: BTreeMap::new(),
            pq_oracle_attestations: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            low_fee_rewards: BTreeMap::new(),
            namespace_rent_credits: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT).expect("valid devnet config");
        seed_devnet(&mut state).expect("valid devnet private receipt oracle router fixtures");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let height = state.counters.height + 12;
        let filter_id = state
            .register_subscriber_filter(SubscriberFilterInput {
                subscriber_id: "subscriber-confidential-indexer".to_string(),
                namespace_id: "namespace-private-dex".to_string(),
                contract_id: "contract-private-swap-vault".to_string(),
                mode: FilterMode::EventTopic,
                key_commitments: set_of(&[
                    deterministic_id("DEMO-FILTER-KEY", &["swap"]),
                    deterministic_id("DEMO-FILTER-KEY", &["fill"]),
                ]),
                allowed_receipt_kinds: enum_set(&[ReceiptKind::Execution, ReceiptKind::Payment]),
                redaction_scope: scope_set(&[
                    RedactionScope::Amount,
                    RedactionScope::Address,
                    RedactionScope::Payload,
                ]),
                min_privacy_set_size: state.config.min_privacy_set_size,
                delivery_commitment: deterministic_id("DEMO-DELIVERY", &["indexer"]),
                view_grant_root: deterministic_id("DEMO-VIEW-GRANT", &["indexer"]),
                created_height: height,
            })
            .expect("demo subscriber filter");
        let receipt_id = state
            .seal_private_receipt(EncryptedPrivateReceiptInput {
                contract_id: "contract-private-swap-vault".to_string(),
                namespace_id: "namespace-private-dex".to_string(),
                receipt_kind: ReceiptKind::Execution,
                domain: ContractDomain::Dex,
                lane: RouteLane::LowFee,
                owner_commitment: deterministic_id("DEMO-OWNER", &["swap-user"]),
                subscriber_commitment: deterministic_id("DEMO-SUBSCRIBER", &["indexer"]),
                receipt_commitment: deterministic_id("DEMO-RECEIPT-COMMITMENT", &["swap-fill"]),
                payload_ciphertext_root: deterministic_id("DEMO-CIPHERTEXT", &["swap-fill"]),
                payload_key_commitment: deterministic_id("DEMO-PAYLOAD-KEY", &["swap-fill"]),
                event_topic_root: deterministic_id("DEMO-TOPIC", &["swap-fill"]),
                nullifier: deterministic_id("DEMO-NULLIFIER", &["swap-fill"]),
                privacy_set_root: deterministic_id("DEMO-PRIVACY-SET", &["swap-fill"]),
                privacy_set_size: state.config.target_privacy_set_size,
                redaction_policy_root: deterministic_id("DEMO-REDACTION-POLICY", &["swap-fill"]),
                fee_commitment: deterministic_id("DEMO-FEE", &["swap-fill"]),
                created_height: height,
            })
            .expect("demo private receipt");
        let intent_id = state
            .open_oracle_route_intent(OracleRouteIntentInput {
                receipt_id: receipt_id.clone(),
                namespace_id: "namespace-private-dex".to_string(),
                subscriber_filter_id: filter_id,
                requested_kind: AttestationKind::RouteCompleteness,
                lane: RouteLane::LowFee,
                payer_commitment: deterministic_id("DEMO-PAYER", &["swap-fill"]),
                oracle_committee_id: "committee-devnet-private-receipts".to_string(),
                answer_commitment_root: deterministic_id("DEMO-ANSWER", &["swap-fill"]),
                required_weight: 10,
                fee_cap_bps: state.config.low_fee_bps,
                max_fee_units: 1_500,
                created_height: height,
            })
            .expect("demo route intent");
        state
            .submit_pq_oracle_attestation(PqOracleAttestationInput {
                intent_id,
                receipt_id,
                oracle_id: "operator-devnet-oracle-a".to_string(),
                committee_id: "committee-devnet-private-receipts".to_string(),
                attestation_kind: AttestationKind::RouteCompleteness,
                aggregate_public_key_root: deterministic_id("DEMO-PQ-KEYS", &["committee"]),
                signature_root: deterministic_id("DEMO-PQ-SIGNATURE", &["swap-fill"]),
                transcript_root: deterministic_id("DEMO-TRANSCRIPT", &["swap-fill"]),
                answer_commitment_root: deterministic_id("DEMO-ANSWER", &["swap-fill"]),
                redacted_payload_root: deterministic_id("DEMO-REDACTED", &["swap-fill"]),
                privacy_set_root: deterministic_id("DEMO-PRIVACY-SET", &["swap-fill"]),
                oracle_weight: 10,
                pq_security_bits: 256,
                signed_height: height + 1,
            })
            .expect("demo pq attestation");
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: record_root(
                "PRIVATE-L2-ORACLE-ROUTER-CONFIG",
                &self.config.public_record(),
            ),
            encrypted_receipt_root: merkle_from_records(
                "PRIVATE-L2-ENCRYPTED-RECEIPTS",
                values(
                    self.encrypted_receipts
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            oracle_route_intent_root: merkle_from_records(
                "PRIVATE-L2-ORACLE-ROUTE-INTENTS",
                values(
                    self.oracle_route_intents
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            subscriber_filter_root: merkle_from_records(
                "PRIVATE-L2-SUBSCRIBER-FILTERS",
                values(
                    self.subscriber_filters
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            pq_oracle_attestation_root: merkle_from_records(
                "PRIVATE-L2-PQ-ORACLE-ATTESTATIONS",
                values(
                    self.pq_oracle_attestations
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            redaction_budget_root: merkle_from_records(
                "PRIVATE-L2-REDACTION-BUDGETS",
                values(
                    self.redaction_budgets
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            low_fee_reward_root: merkle_from_records(
                "PRIVATE-L2-LOW-FEE-REWARDS",
                values(
                    self.low_fee_rewards
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            namespace_rent_credit_root: merkle_from_records(
                "PRIVATE-L2-NAMESPACE-RENT-CREDITS",
                values(
                    self.namespace_rent_credits
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            operator_summary_root: merkle_from_records(
                "PRIVATE-L2-OPERATOR-SUMMARIES",
                values(
                    self.operator_summaries
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            replay_fence_root: merkle_from_records(
                "PRIVATE-L2-REPLAY-FENCES",
                values(
                    self.replay_fences
                        .values()
                        .map(|record| record.public_record()),
                ),
            ),
            event_root: merkle_from_records(
                "PRIVATE-L2-ROUTER-EVENTS",
                values(self.events.values().map(|record| record.public_record())),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record()
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn seal_private_receipt(&mut self, input: EncryptedPrivateReceiptInput) -> Result<String> {
        ensure_capacity(
            self.encrypted_receipts.len(),
            MAX_ENCRYPTED_RECEIPTS,
            "encrypted receipts",
        )?;
        ensure_nonempty(&input.contract_id, "contract_id")?;
        ensure_nonempty(&input.namespace_id, "namespace_id")?;
        ensure_nonempty(&input.nullifier, "nullifier")?;
        ensure_bps(input.lane.fee_bps(&self.config), "receipt lane fee")?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("receipt privacy set below configured floor".to_string());
        }
        let receipt_id = receipt_id(
            &input.contract_id,
            &input.namespace_id,
            input.receipt_kind,
            &input.receipt_commitment,
            &input.nullifier,
        );
        let fence_id = replay_fence_id(
            ReplayFenceKind::ReceiptNullifier,
            &receipt_id,
            &input.nullifier,
            &input.namespace_id,
        );
        if self.replay_fences.contains_key(&fence_id) {
            return Err("receipt nullifier already fenced".to_string());
        }
        let record = EncryptedPrivateReceipt {
            receipt_id: receipt_id.clone(),
            contract_id: input.contract_id,
            namespace_id: input.namespace_id.clone(),
            receipt_kind: input.receipt_kind,
            domain: input.domain,
            status: ReceiptStatus::Sealed,
            lane: input.lane,
            owner_commitment: input.owner_commitment,
            subscriber_commitment: input.subscriber_commitment,
            receipt_commitment: input.receipt_commitment,
            payload_ciphertext_root: input.payload_ciphertext_root,
            payload_key_commitment: input.payload_key_commitment,
            event_topic_root: input.event_topic_root,
            nullifier: input.nullifier.clone(),
            privacy_set_root: input.privacy_set_root,
            privacy_set_size: input.privacy_set_size,
            redaction_policy_root: input.redaction_policy_root,
            fee_commitment: input.fee_commitment,
            fee_bps: input.lane.fee_bps(&self.config),
            created_height: input.created_height,
            expires_height: input.created_height + self.config.receipt_ttl_blocks,
        };
        let record_root_value =
            record_root("PRIVATE-L2-ENCRYPTED-RECEIPT", &record.public_record());
        self.encrypted_receipts.insert(receipt_id.clone(), record);
        self.counters.encrypted_receipts += 1;
        self.insert_replay_fence(ReplayFence {
            fence_id,
            kind: ReplayFenceKind::ReceiptNullifier,
            subject_id: receipt_id.clone(),
            nullifier: input.nullifier,
            namespace_id: input.namespace_id,
            height: input.created_height,
            expires_height: input.created_height + self.config.receipt_ttl_blocks,
        })?;
        self.push_event(
            input.created_height,
            "private_receipt_sealed",
            &receipt_id,
            &record_root_value,
        )?;
        Ok(receipt_id)
    }

    pub fn register_subscriber_filter(&mut self, input: SubscriberFilterInput) -> Result<String> {
        ensure_capacity(
            self.subscriber_filters.len(),
            MAX_SUBSCRIBER_FILTERS,
            "subscriber filters",
        )?;
        ensure_nonempty(&input.subscriber_id, "subscriber_id")?;
        ensure_nonempty(&input.namespace_id, "namespace_id")?;
        ensure_nonempty(&input.contract_id, "contract_id")?;
        if input.key_commitments.len() > self.config.max_filter_keys {
            return Err("subscriber filter key commitment capacity exceeded".to_string());
        }
        if input.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("subscriber filter privacy floor below runtime floor".to_string());
        }
        let filter_id = subscriber_filter_id(
            &input.subscriber_id,
            &input.namespace_id,
            &input.contract_id,
            input.mode,
            input.created_height,
        );
        let record = SubscriberFilter {
            filter_id: filter_id.clone(),
            subscriber_id: input.subscriber_id,
            namespace_id: input.namespace_id,
            contract_id: input.contract_id,
            mode: input.mode,
            status: FilterStatus::Active,
            key_commitments: input.key_commitments,
            min_privacy_set_size: input.min_privacy_set_size,
            allowed_receipt_kinds: input.allowed_receipt_kinds,
            redaction_scope: input.redaction_scope,
            delivery_commitment: input.delivery_commitment,
            view_grant_root: input.view_grant_root,
            created_height: input.created_height,
            expires_height: input.created_height + self.config.filter_ttl_blocks,
        };
        let record_root_value =
            record_root("PRIVATE-L2-SUBSCRIBER-FILTER", &record.public_record());
        self.subscriber_filters.insert(filter_id.clone(), record);
        self.counters.subscriber_filters += 1;
        self.push_event(
            input.created_height,
            "subscriber_filter_registered",
            &filter_id,
            &record_root_value,
        )?;
        Ok(filter_id)
    }

    pub fn open_oracle_route_intent(&mut self, input: OracleRouteIntentInput) -> Result<String> {
        ensure_capacity(
            self.oracle_route_intents.len(),
            MAX_ORACLE_ROUTE_INTENTS,
            "oracle route intents",
        )?;
        ensure_nonempty(&input.receipt_id, "receipt_id")?;
        ensure_nonempty(&input.subscriber_filter_id, "subscriber_filter_id")?;
        ensure_bps(input.fee_cap_bps, "fee_cap_bps")?;
        let receipt = self
            .encrypted_receipts
            .get(&input.receipt_id)
            .ok_or_else(|| "receipt missing for route intent".to_string())?;
        let filter = self
            .subscriber_filters
            .get(&input.subscriber_filter_id)
            .ok_or_else(|| "subscriber filter missing for route intent".to_string())?;
        if !receipt.status.open() {
            return Err("receipt is not routable".to_string());
        }
        if !filter.accepts_kind(receipt.receipt_kind) {
            return Err("subscriber filter does not accept receipt kind".to_string());
        }
        if input.fee_cap_bps < input.lane.fee_bps(&self.config) {
            return Err("route intent fee cap below lane fee".to_string());
        }
        let intent_id = oracle_route_intent_id(
            &input.receipt_id,
            &input.subscriber_filter_id,
            input.requested_kind,
            input.created_height,
        );
        let priority = input.lane.priority_weight() + input.required_weight;
        let record = OracleRouteIntent {
            intent_id: intent_id.clone(),
            receipt_id: input.receipt_id.clone(),
            namespace_id: input.namespace_id,
            subscriber_filter_id: input.subscriber_filter_id,
            requested_kind: input.requested_kind,
            lane: input.lane,
            status: OracleIntentStatus::Active,
            payer_commitment: input.payer_commitment,
            oracle_committee_id: input.oracle_committee_id,
            answer_commitment_root: input.answer_commitment_root,
            required_weight: input.required_weight.max(self.config.min_oracle_weight),
            matched_weight: 0,
            fee_cap_bps: input.fee_cap_bps,
            max_fee_units: input.max_fee_units,
            priority,
            created_height: input.created_height,
            expires_height: input.created_height + self.config.route_ttl_blocks,
        };
        let record_root_value =
            record_root("PRIVATE-L2-ORACLE-ROUTE-INTENT", &record.public_record());
        self.oracle_route_intents.insert(intent_id.clone(), record);
        if let Some(receipt) = self.encrypted_receipts.get_mut(&input.receipt_id) {
            receipt.status = ReceiptStatus::Routed;
        }
        self.counters.oracle_route_intents += 1;
        self.push_event(
            input.created_height,
            "oracle_route_intent_opened",
            &intent_id,
            &record_root_value,
        )?;
        Ok(intent_id)
    }

    pub fn submit_pq_oracle_attestation(
        &mut self,
        input: PqOracleAttestationInput,
    ) -> Result<String> {
        ensure_capacity(
            self.pq_oracle_attestations.len(),
            MAX_PQ_ORACLE_ATTESTATIONS,
            "pq oracle attestations",
        )?;
        ensure_nonempty(&input.intent_id, "intent_id")?;
        ensure_nonempty(&input.receipt_id, "receipt_id")?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq oracle attestation below security floor".to_string());
        }
        let intent = self
            .oracle_route_intents
            .get(&input.intent_id)
            .ok_or_else(|| "route intent missing for attestation".to_string())?;
        if !intent.status.routable() {
            return Err("route intent is not accepting attestations".to_string());
        }
        let attestation_id = pq_oracle_attestation_id(
            &input.intent_id,
            &input.receipt_id,
            &input.oracle_id,
            input.attestation_kind,
            input.signed_height,
        );
        let status = if input.oracle_weight >= self.config.min_oracle_weight {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::WeakQuorum
        };
        let record = PqOracleAttestation {
            attestation_id: attestation_id.clone(),
            intent_id: input.intent_id.clone(),
            receipt_id: input.receipt_id.clone(),
            oracle_id: input.oracle_id.clone(),
            committee_id: input.committee_id,
            attestation_kind: input.attestation_kind,
            status,
            pq_scheme: self.config.pq_oracle_attestation_scheme.clone(),
            aggregate_public_key_root: input.aggregate_public_key_root,
            signature_root: input.signature_root,
            transcript_root: input.transcript_root,
            answer_commitment_root: input.answer_commitment_root,
            redacted_payload_root: input.redacted_payload_root,
            privacy_set_root: input.privacy_set_root,
            oracle_weight: input.oracle_weight,
            pq_security_bits: input.pq_security_bits,
            signed_height: input.signed_height,
            expires_height: input.signed_height + self.config.attestation_ttl_blocks,
        };
        let record_root_value =
            record_root("PRIVATE-L2-PQ-ORACLE-ATTESTATION", &record.public_record());
        if record.acceptable_for(&self.config) {
            if let Some(intent) = self.oracle_route_intents.get_mut(&input.intent_id) {
                intent.matched_weight = intent.matched_weight.saturating_add(record.oracle_weight);
                if intent.quorum_bps() >= self.config.quorum_bps {
                    intent.status = OracleIntentStatus::QuorumAttested;
                } else {
                    intent.status = OracleIntentStatus::Matched;
                }
            }
            if let Some(receipt) = self.encrypted_receipts.get_mut(&input.receipt_id) {
                receipt.status = ReceiptStatus::Attested;
            }
        }
        self.pq_oracle_attestations
            .insert(attestation_id.clone(), record);
        self.counters.pq_oracle_attestations += 1;
        self.push_event(
            input.signed_height,
            "pq_oracle_attestation_submitted",
            &attestation_id,
            &record_root_value,
        )?;
        Ok(attestation_id)
    }

    pub fn reserve_redaction_budget(&mut self, input: RedactionBudgetInput) -> Result<String> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction budgets",
        )?;
        ensure_nonempty(&input.namespace_id, "namespace_id")?;
        ensure_nonempty(&input.subscriber_id, "subscriber_id")?;
        if input.reserved_units > input.total_units {
            return Err("reserved redaction units exceed total units".to_string());
        }
        let budget_id = redaction_budget_id(
            &input.namespace_id,
            &input.subscriber_id,
            input.scope,
            input.epoch,
        );
        let record = RedactionBudget {
            budget_id: budget_id.clone(),
            namespace_id: input.namespace_id,
            subscriber_id: input.subscriber_id,
            scope: input.scope,
            status: BudgetStatus::Reserved,
            epoch: input.epoch,
            total_units: input.total_units,
            reserved_units: input.reserved_units,
            consumed_units: 0,
            max_payload_bytes: input.max_payload_bytes,
            policy_root: input.policy_root,
            audit_commitment_root: input.audit_commitment_root,
            created_height: input.created_height,
            expires_height: input.created_height + self.config.redaction_epoch_blocks,
        };
        let record_root_value = record_root("PRIVATE-L2-REDACTION-BUDGET", &record.public_record());
        self.redaction_budgets.insert(budget_id.clone(), record);
        self.counters.redaction_budgets += 1;
        self.push_event(
            input.created_height,
            "redaction_budget_reserved",
            &budget_id,
            &record_root_value,
        )?;
        Ok(budget_id)
    }

    pub fn accrue_low_fee_reward(&mut self, input: LowFeeRoutingRewardInput) -> Result<String> {
        ensure_capacity(
            self.low_fee_rewards.len(),
            MAX_LOW_FEE_REWARDS,
            "low fee routing rewards",
        )?;
        ensure_bps(input.sponsored_bps, "sponsored_bps")?;
        let reward_id = low_fee_reward_id(
            &input.intent_id,
            &input.receipt_id,
            &input.operator_id,
            input.epoch,
        );
        let reward_units = input.fee_units.saturating_mul(self.config.reward_bps) / MAX_BPS;
        let record = LowFeeRoutingReward {
            reward_id: reward_id.clone(),
            intent_id: input.intent_id,
            receipt_id: input.receipt_id,
            operator_id: input.operator_id,
            lane: input.lane,
            status: RewardStatus::Claimable,
            fee_asset_id: self.config.fee_asset_id.clone(),
            fee_commitment: input.fee_commitment,
            reward_commitment: input.reward_commitment,
            fee_units: input.fee_units,
            reward_units,
            sponsored_bps: input.sponsored_bps,
            epoch: input.epoch,
            created_height: input.created_height,
            claimable_height: input.created_height + self.config.reward_epoch_blocks,
        };
        let record_root_value = record_root("PRIVATE-L2-LOW-FEE-REWARD", &record.public_record());
        self.counters.total_fee_units = self
            .counters
            .total_fee_units
            .saturating_add(record.fee_units);
        self.counters.total_reward_units = self
            .counters
            .total_reward_units
            .saturating_add(record.reward_units);
        self.low_fee_rewards.insert(reward_id.clone(), record);
        self.counters.low_fee_rewards += 1;
        self.push_event(
            input.created_height,
            "low_fee_reward_accrued",
            &reward_id,
            &record_root_value,
        )?;
        Ok(reward_id)
    }

    pub fn issue_namespace_rent_credit(
        &mut self,
        input: NamespaceRentCreditInput,
    ) -> Result<String> {
        ensure_capacity(
            self.namespace_rent_credits.len(),
            MAX_NAMESPACE_RENT_CREDITS,
            "namespace rent credits",
        )?;
        ensure_bps(input.rebate_bps, "rebate_bps")?;
        let credit_id = namespace_rent_credit_id(
            &input.namespace_id,
            &input.sponsor_id,
            input.epoch,
            &input.credit_commitment,
        );
        let record = NamespaceRentCredit {
            credit_id: credit_id.clone(),
            namespace_id: input.namespace_id,
            sponsor_id: input.sponsor_id,
            status: RentCreditStatus::Open,
            rent_asset_id: self.config.rent_asset_id.clone(),
            credit_commitment: input.credit_commitment,
            applied_to_receipt_root: input.applied_to_receipt_root,
            credit_units: input.credit_units,
            rebate_bps: input.rebate_bps,
            epoch: input.epoch,
            created_height: input.created_height,
            expires_height: input.created_height + self.config.rent_epoch_blocks,
        };
        let record_root_value =
            record_root("PRIVATE-L2-NAMESPACE-RENT-CREDIT", &record.public_record());
        self.counters.total_rent_credit_units = self
            .counters
            .total_rent_credit_units
            .saturating_add(record.credit_units);
        self.namespace_rent_credits
            .insert(credit_id.clone(), record);
        self.counters.namespace_rent_credits += 1;
        self.push_event(
            input.created_height,
            "namespace_rent_credit_issued",
            &credit_id,
            &record_root_value,
        )?;
        Ok(credit_id)
    }

    pub fn upsert_operator_summary(&mut self, input: OperatorSummaryInput) -> Result<String> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator summaries",
        )?;
        ensure_bps(input.average_fee_bps, "average_fee_bps")?;
        ensure_bps(input.uptime_bps, "uptime_bps")?;
        let summary_root_value =
            operator_summary_digest(&input.operator_id, input.last_seen_height);
        let record = OperatorSummary {
            operator_id: input.operator_id.clone(),
            committee_id: input.committee_id,
            status: input.status,
            pq_public_key_root: input.pq_public_key_root,
            route_capacity: input.route_capacity,
            active_routes: input.active_routes,
            delivered_receipts: input.delivered_receipts,
            attested_receipts: input.attested_receipts,
            redaction_failures: input.redaction_failures,
            slash_points: input.slash_points,
            average_fee_bps: input.average_fee_bps,
            uptime_bps: input.uptime_bps,
            last_seen_height: input.last_seen_height,
            summary_root: summary_root_value,
        };
        let record_root_value = record_root("PRIVATE-L2-OPERATOR-SUMMARY", &record.public_record());
        self.operator_summaries
            .insert(input.operator_id.clone(), record);
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.push_event(
            input.last_seen_height,
            "operator_summary_upserted",
            &input.operator_id,
            &record_root_value,
        )?;
        Ok(input.operator_id)
    }

    pub fn mark_receipt_delivered(&mut self, receipt_id: &str, height: u64) -> Result<()> {
        let record = self
            .encrypted_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| "receipt missing".to_string())?;
        if record.expired(height) {
            record.status = ReceiptStatus::Expired;
            return Err("receipt expired before delivery".to_string());
        }
        record.status = ReceiptStatus::Delivered;
        self.counters.delivered_receipts += 1;
        let record_root_value =
            record_root("PRIVATE-L2-ENCRYPTED-RECEIPT", &record.public_record());
        self.push_event(
            height,
            "private_receipt_delivered",
            receipt_id,
            &record_root_value,
        )
    }

    pub fn apply_redaction(
        &mut self,
        receipt_id: &str,
        budget_id: &str,
        units: u64,
        height: u64,
    ) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "redaction budget missing".to_string())?;
        if !budget.status.spendable() {
            return Err("redaction budget not spendable".to_string());
        }
        if budget.available_units() < units {
            budget.status = BudgetStatus::Exhausted;
            return Err("redaction budget exhausted".to_string());
        }
        budget.consumed_units = budget.consumed_units.saturating_add(units);
        if budget.available_units() == 0 {
            budget.status = BudgetStatus::Exhausted;
        }
        let receipt = self
            .encrypted_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| "receipt missing".to_string())?;
        receipt.status = ReceiptStatus::Redacted;
        self.counters.redacted_receipts += 1;
        let record_root_value = record_root("PRIVATE-L2-REDACTION-BUDGET", &budget.public_record());
        self.push_event(
            height,
            "private_receipt_redacted",
            receipt_id,
            &record_root_value,
        )
    }

    fn insert_replay_fence(&mut self, fence: ReplayFence) -> Result<()> {
        ensure_capacity(self.replay_fences.len(), MAX_REPLAY_FENCES, "replay fences")?;
        self.replay_fences.insert(fence.fence_id.clone(), fence);
        self.counters.replay_fences += 1;
        Ok(())
    }

    fn push_event(
        &mut self,
        height: u64,
        kind: &str,
        subject_id: &str,
        record_root_value: &str,
    ) -> Result<()> {
        ensure_capacity(self.events.len(), MAX_EVENTS, "events")?;
        let id = event_id(
            height,
            kind,
            subject_id,
            record_root_value,
            self.counters.events + 1,
        );
        self.events.insert(
            id.clone(),
            RuntimeEvent {
                event_id: id,
                height,
                kind: kind.to_string(),
                subject_id: subject_id.to_string(),
                record_root: record_root_value.to_string(),
            },
        );
        self.counters.events += 1;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPrivateReceiptInput {
    pub contract_id: String,
    pub namespace_id: String,
    pub receipt_kind: ReceiptKind,
    pub domain: ContractDomain,
    pub lane: RouteLane,
    pub owner_commitment: String,
    pub subscriber_commitment: String,
    pub receipt_commitment: String,
    pub payload_ciphertext_root: String,
    pub payload_key_commitment: String,
    pub event_topic_root: String,
    pub nullifier: String,
    pub privacy_set_root: String,
    pub privacy_set_size: u64,
    pub redaction_policy_root: String,
    pub fee_commitment: String,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleRouteIntentInput {
    pub receipt_id: String,
    pub namespace_id: String,
    pub subscriber_filter_id: String,
    pub requested_kind: AttestationKind,
    pub lane: RouteLane,
    pub payer_commitment: String,
    pub oracle_committee_id: String,
    pub answer_commitment_root: String,
    pub required_weight: u64,
    pub fee_cap_bps: u64,
    pub max_fee_units: u64,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriberFilterInput {
    pub subscriber_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub mode: FilterMode,
    pub key_commitments: BTreeSet<String>,
    pub min_privacy_set_size: u64,
    pub allowed_receipt_kinds: BTreeSet<ReceiptKind>,
    pub redaction_scope: BTreeSet<RedactionScope>,
    pub delivery_commitment: String,
    pub view_grant_root: String,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestationInput {
    pub intent_id: String,
    pub receipt_id: String,
    pub oracle_id: String,
    pub committee_id: String,
    pub attestation_kind: AttestationKind,
    pub aggregate_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub answer_commitment_root: String,
    pub redacted_payload_root: String,
    pub privacy_set_root: String,
    pub oracle_weight: u64,
    pub pq_security_bits: u16,
    pub signed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetInput {
    pub namespace_id: String,
    pub subscriber_id: String,
    pub scope: RedactionScope,
    pub epoch: u64,
    pub total_units: u64,
    pub reserved_units: u64,
    pub max_payload_bytes: u64,
    pub policy_root: String,
    pub audit_commitment_root: String,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRoutingRewardInput {
    pub intent_id: String,
    pub receipt_id: String,
    pub operator_id: String,
    pub lane: RouteLane,
    pub fee_commitment: String,
    pub reward_commitment: String,
    pub fee_units: u64,
    pub sponsored_bps: u64,
    pub epoch: u64,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceRentCreditInput {
    pub namespace_id: String,
    pub sponsor_id: String,
    pub credit_commitment: String,
    pub applied_to_receipt_root: String,
    pub credit_units: u64,
    pub rebate_bps: u64,
    pub epoch: u64,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryInput {
    pub operator_id: String,
    pub committee_id: String,
    pub status: OperatorStatus,
    pub pq_public_key_root: String,
    pub route_capacity: u64,
    pub active_routes: u64,
    pub delivered_receipts: u64,
    pub attested_receipts: u64,
    pub redaction_failures: u64,
    pub slash_points: u64,
    pub average_fee_bps: u64,
    pub uptime_bps: u64,
    pub last_seen_height: u64,
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

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-RECEIPT-ORACLE-ROUTER-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn receipt_id(
    contract_id: &str,
    namespace_id: &str,
    receipt_kind: ReceiptKind,
    receipt_commitment: &str,
    nullifier: &str,
) -> String {
    domain_hash(
        "PRIVATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(contract_id),
            HashPart::Str(namespace_id),
            HashPart::Str(receipt_kind.as_str()),
            HashPart::Str(receipt_commitment),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn oracle_route_intent_id(
    receipt_id: &str,
    subscriber_filter_id: &str,
    requested_kind: AttestationKind,
    created_height: u64,
) -> String {
    domain_hash(
        "ORACLE-ROUTE-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(subscriber_filter_id),
            HashPart::Str(requested_kind.as_str()),
            HashPart::Int(created_height as i128),
        ],
        32,
    )
}

pub fn subscriber_filter_id(
    subscriber_id: &str,
    namespace_id: &str,
    contract_id: &str,
    mode: FilterMode,
    created_height: u64,
) -> String {
    domain_hash(
        "SUBSCRIBER-FILTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subscriber_id),
            HashPart::Str(namespace_id),
            HashPart::Str(contract_id),
            HashPart::Str(mode.as_str()),
            HashPart::Int(created_height as i128),
        ],
        32,
    )
}

pub fn pq_oracle_attestation_id(
    intent_id: &str,
    receipt_id: &str,
    oracle_id: &str,
    attestation_kind: AttestationKind,
    signed_height: u64,
) -> String {
    domain_hash(
        "PQ-ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(intent_id),
            HashPart::Str(receipt_id),
            HashPart::Str(oracle_id),
            HashPart::Str(attestation_kind.as_str()),
            HashPart::Int(signed_height as i128),
        ],
        32,
    )
}

pub fn redaction_budget_id(
    namespace_id: &str,
    subscriber_id: &str,
    scope: RedactionScope,
    epoch: u64,
) -> String {
    domain_hash(
        "REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(namespace_id),
            HashPart::Str(subscriber_id),
            HashPart::Str(scope.as_str()),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn low_fee_reward_id(
    intent_id: &str,
    receipt_id: &str,
    operator_id: &str,
    epoch: u64,
) -> String {
    domain_hash(
        "LOW-FEE-ROUTING-REWARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(intent_id),
            HashPart::Str(receipt_id),
            HashPart::Str(operator_id),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn namespace_rent_credit_id(
    namespace_id: &str,
    sponsor_id: &str,
    epoch: u64,
    credit_commitment: &str,
) -> String {
    domain_hash(
        "NAMESPACE-RENT-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(namespace_id),
            HashPart::Str(sponsor_id),
            HashPart::Int(epoch as i128),
            HashPart::Str(credit_commitment),
        ],
        32,
    )
}

pub fn replay_fence_id(
    kind: ReplayFenceKind,
    subject_id: &str,
    nullifier: &str,
    namespace_id: &str,
) -> String {
    domain_hash(
        "PRIVATE-RECEIPT-ORACLE-ROUTER-REPLAY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier),
            HashPart::Str(namespace_id),
        ],
        32,
    )
}

pub fn event_id(
    height: u64,
    kind: &str,
    subject_id: &str,
    record_root_value: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-RECEIPT-ORACLE-ROUTER-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(height as i128),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Str(record_root_value),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn operator_summary_digest(operator_id: &str, last_seen_height: u64) -> String {
    domain_hash(
        "OPERATOR-SUMMARY-DIGEST",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Int(last_seen_height as i128),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn merkle_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{} capacity exceeded", label))
    } else {
        Ok(())
    }
}

fn ensure_nonempty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{} must not be empty", label))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{} exceeds maximum bps", label))
    } else {
        Ok(())
    }
}

fn values<I>(records: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    records.into_iter().collect()
}

fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

fn set_of(items: &[String]) -> BTreeSet<String> {
    items.iter().cloned().collect()
}

fn enum_set(items: &[ReceiptKind]) -> BTreeSet<ReceiptKind> {
    items.iter().copied().collect()
}

fn scope_set(items: &[RedactionScope]) -> BTreeSet<RedactionScope> {
    items.iter().copied().collect()
}

fn seed_devnet(state: &mut State) -> Result<()> {
    let height = state.counters.height;
    state.upsert_operator_summary(OperatorSummaryInput {
        operator_id: "operator-devnet-oracle-a".to_string(),
        committee_id: "committee-devnet-private-receipts".to_string(),
        status: OperatorStatus::Active,
        pq_public_key_root: deterministic_id("DEVNET-PQ-PUBLIC-KEY", &["operator-a"]),
        route_capacity: 4_096,
        active_routes: 128,
        delivered_receipts: 92_000,
        attested_receipts: 93_400,
        redaction_failures: 0,
        slash_points: 0,
        average_fee_bps: state.config.low_fee_bps,
        uptime_bps: 9_998,
        last_seen_height: height,
    })?;
    state.upsert_operator_summary(OperatorSummaryInput {
        operator_id: "operator-devnet-oracle-b".to_string(),
        committee_id: "committee-devnet-private-receipts".to_string(),
        status: OperatorStatus::Active,
        pq_public_key_root: deterministic_id("DEVNET-PQ-PUBLIC-KEY", &["operator-b"]),
        route_capacity: 3_584,
        active_routes: 96,
        delivered_receipts: 88_120,
        attested_receipts: 90_001,
        redaction_failures: 1,
        slash_points: 0,
        average_fee_bps: state.config.standard_fee_bps,
        uptime_bps: 9_991,
        last_seen_height: height,
    })?;
    let filter_id = state.register_subscriber_filter(SubscriberFilterInput {
        subscriber_id: "subscriber-devnet-settlement-vault".to_string(),
        namespace_id: "namespace-devnet-confidential-contracts".to_string(),
        contract_id: "contract-devnet-settlement-vault".to_string(),
        mode: FilterMode::ContractSelector,
        key_commitments: set_of(&[
            deterministic_id("DEVNET-FILTER-KEY", &["settlement"]),
            deterministic_id("DEVNET-FILTER-KEY", &["oracle-answer"]),
        ]),
        min_privacy_set_size: state.config.min_privacy_set_size,
        allowed_receipt_kinds: enum_set(&[
            ReceiptKind::Execution,
            ReceiptKind::OracleAnswer,
            ReceiptKind::Settlement,
        ]),
        redaction_scope: scope_set(&[
            RedactionScope::Amount,
            RedactionScope::ContractCall,
            RedactionScope::OracleAnswer,
        ]),
        delivery_commitment: deterministic_id("DEVNET-DELIVERY", &["settlement-vault"]),
        view_grant_root: deterministic_id("DEVNET-VIEW-GRANT", &["settlement-vault"]),
        created_height: height,
    })?;
    let receipt_id = state.seal_private_receipt(EncryptedPrivateReceiptInput {
        contract_id: "contract-devnet-settlement-vault".to_string(),
        namespace_id: "namespace-devnet-confidential-contracts".to_string(),
        receipt_kind: ReceiptKind::OracleAnswer,
        domain: ContractDomain::Settlement,
        lane: RouteLane::LowFee,
        owner_commitment: deterministic_id("DEVNET-OWNER", &["settlement-vault"]),
        subscriber_commitment: deterministic_id("DEVNET-SUBSCRIBER", &["settlement-vault"]),
        receipt_commitment: deterministic_id("DEVNET-RECEIPT-COMMITMENT", &["oracle-answer"]),
        payload_ciphertext_root: deterministic_id("DEVNET-CIPHERTEXT", &["oracle-answer"]),
        payload_key_commitment: deterministic_id("DEVNET-PAYLOAD-KEY", &["oracle-answer"]),
        event_topic_root: deterministic_id("DEVNET-EVENT-TOPIC", &["oracle-answer"]),
        nullifier: deterministic_id("DEVNET-NULLIFIER", &["oracle-answer"]),
        privacy_set_root: deterministic_id("DEVNET-PRIVACY-SET", &["oracle-answer"]),
        privacy_set_size: state.config.target_privacy_set_size,
        redaction_policy_root: deterministic_id("DEVNET-REDACTION-POLICY", &["oracle-answer"]),
        fee_commitment: deterministic_id("DEVNET-FEE", &["oracle-answer"]),
        created_height: height,
    })?;
    let intent_id = state.open_oracle_route_intent(OracleRouteIntentInput {
        receipt_id: receipt_id.clone(),
        namespace_id: "namespace-devnet-confidential-contracts".to_string(),
        subscriber_filter_id: filter_id,
        requested_kind: AttestationKind::OracleAnswer,
        lane: RouteLane::LowFee,
        payer_commitment: deterministic_id("DEVNET-PAYER", &["oracle-answer"]),
        oracle_committee_id: "committee-devnet-private-receipts".to_string(),
        answer_commitment_root: deterministic_id("DEVNET-ANSWER", &["oracle-answer"]),
        required_weight: 10,
        fee_cap_bps: state.config.low_fee_bps,
        max_fee_units: 1_000,
        created_height: height,
    })?;
    state.submit_pq_oracle_attestation(PqOracleAttestationInput {
        intent_id: intent_id.clone(),
        receipt_id: receipt_id.clone(),
        oracle_id: "operator-devnet-oracle-a".to_string(),
        committee_id: "committee-devnet-private-receipts".to_string(),
        attestation_kind: AttestationKind::OracleAnswer,
        aggregate_public_key_root: deterministic_id("DEVNET-PQ-KEYS", &["committee"]),
        signature_root: deterministic_id("DEVNET-SIGNATURE", &["oracle-answer", "a"]),
        transcript_root: deterministic_id("DEVNET-TRANSCRIPT", &["oracle-answer"]),
        answer_commitment_root: deterministic_id("DEVNET-ANSWER", &["oracle-answer"]),
        redacted_payload_root: deterministic_id("DEVNET-REDACTED", &["oracle-answer"]),
        privacy_set_root: deterministic_id("DEVNET-PRIVACY-SET", &["oracle-answer"]),
        oracle_weight: 10,
        pq_security_bits: 256,
        signed_height: height + 1,
    })?;
    state.reserve_redaction_budget(RedactionBudgetInput {
        namespace_id: "namespace-devnet-confidential-contracts".to_string(),
        subscriber_id: "subscriber-devnet-settlement-vault".to_string(),
        scope: RedactionScope::OracleAnswer,
        epoch: height / state.config.redaction_epoch_blocks,
        total_units: 10_000,
        reserved_units: 1_000,
        max_payload_bytes: 64 * 1024,
        policy_root: deterministic_id("DEVNET-REDACTION-BUDGET-POLICY", &["oracle-answer"]),
        audit_commitment_root: deterministic_id("DEVNET-REDACTION-AUDIT", &["oracle-answer"]),
        created_height: height,
    })?;
    state.accrue_low_fee_reward(LowFeeRoutingRewardInput {
        intent_id,
        receipt_id: receipt_id.clone(),
        operator_id: "operator-devnet-oracle-a".to_string(),
        lane: RouteLane::LowFee,
        fee_commitment: deterministic_id("DEVNET-FEE", &["oracle-answer"]),
        reward_commitment: deterministic_id("DEVNET-REWARD", &["oracle-answer"]),
        fee_units: 1_000,
        sponsored_bps: 9_500,
        epoch: height / state.config.reward_epoch_blocks,
        created_height: height + 1,
    })?;
    state.issue_namespace_rent_credit(NamespaceRentCreditInput {
        namespace_id: "namespace-devnet-confidential-contracts".to_string(),
        sponsor_id: "sponsor-devnet-low-fee-oracle-rent".to_string(),
        credit_commitment: deterministic_id("DEVNET-RENT-CREDIT", &["confidential-contracts"]),
        applied_to_receipt_root: deterministic_id(
            "DEVNET-RENT-RECEIPT-ROOT",
            &["confidential-contracts"],
        ),
        credit_units: 25_000,
        rebate_bps: state.config.rent_rebate_bps,
        epoch: height / state.config.rent_epoch_blocks,
        created_height: height,
    })?;
    state.mark_receipt_delivered(&receipt_id, height + 2)?;
    Ok(())
}
