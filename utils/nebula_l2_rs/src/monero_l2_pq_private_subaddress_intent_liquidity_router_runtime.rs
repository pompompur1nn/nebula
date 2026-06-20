use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SUBADDRESS_INTENT_LIQUIDITY_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-subaddress-intent-liquidity-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SUBADDRESS_INTENT_LIQUIDITY_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ROUTER_ID: &str = "monero-l2-pq-private-subaddress-intent-liquidity-router-devnet";
pub const DEVNET_BASE_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "private-usd-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_312_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROUTE_INTENT_SCHEME: &str =
    "ml-kem-1024-sealed-monero-subaddress-private-route-intent-root-v1";
pub const VIEW_TAG_HINT_SCHEME: &str = "monero-view-tag-private-scan-bucket-hint-root-v1";
pub const STEALTH_PROOF_SCHEME: &str = "monero-stealth-address-proof-commitment-redacted-root-v1";
pub const LIQUIDITY_QUOTE_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-private-liquidity-maker-quote-root-v1";
pub const FAST_EXIT_RESERVE_SCHEME: &str =
    "pq-private-fast-exit-subaddress-reserve-binding-root-v1";
pub const ATOMIC_SWAP_INTENT_SCHEME: &str = "pq-private-monero-atomic-swap-intent-adaptor-root-v1";
pub const RESERVE_ATTESTATION_SCHEME: &str = "monero-view-key-redacted-reserve-attestation-root-v1";
pub const FEE_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-subaddress-intent-sponsorship-nullifier-root-v1";
pub const NULLIFIER_FENCE_SCHEME: &str =
    "monero-subaddress-intent-liquidity-nullifier-fence-root-v1";
pub const REORG_PROTECTION_SCHEME: &str =
    "monero-private-route-reorg-protection-watchtower-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "private-subaddress-intent-router-slashing-evidence-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str =
    "monero-private-subaddress-intent-liquidity-settlement-batch-root-v1";
pub const REPLAY_DOMAIN: &str = "monero-l2-pq-private-subaddress-intent-liquidity-router-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_RESERVE_TTL_BLOCKS: u64 = 14;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REORG_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_FINALITY_BLOCKS: u64 = 20;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_VIEW_TAG_BUCKET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_VIEW_TAG_BUCKET_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_STANDARD_FEE_BPS: u64 = 8;
pub const DEFAULT_FAST_FEE_BPS: u64 = 15;
pub const DEFAULT_EMERGENCY_FEE_BPS: u64 = 24;
pub const DEFAULT_REORG_INSURANCE_BPS: u64 = 7;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 5;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_500;
pub const DEFAULT_MAX_ROUTE_HOPS: u8 = 8;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 768;
pub const MAX_ROUTE_INTENTS: usize = 4_194_304;
pub const MAX_VIEW_TAG_HINTS: usize = 4_194_304;
pub const MAX_STEALTH_PROOFS: usize = 4_194_304;
pub const MAX_LIQUIDITY_MAKERS: usize = 1_048_576;
pub const MAX_LIQUIDITY_QUOTES: usize = 4_194_304;
pub const MAX_FAST_EXIT_ROUTES: usize = 4_194_304;
pub const MAX_ATOMIC_SWAP_INTENTS: usize = 2_097_152;
pub const MAX_RESERVE_ATTESTATIONS: usize = 2_097_152;
pub const MAX_FEE_SPONSORSHIPS: usize = 2_097_152;
pub const MAX_NULLIFIER_FENCES: usize = 8_388_608;
pub const MAX_REORG_GUARDS: usize = 1_048_576;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_SETTLEMENT_BATCHES: usize = 1_048_576;
pub const MAX_EVENTS: usize = 8_388_608;

macro_rules! snake_enum {
    ($name:ident { $($variant:ident => $text:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
        }
    };
}

snake_enum!(RouteIntentKind {
    PrivateFastExit => "private_fast_exit",
    PrivateSwap => "private_swap",
    DefiLiquidityUnwind => "defi_liquidity_unwind",
    SubaddressRebalance => "subaddress_rebalance",
    MerchantSettlement => "merchant_settlement",
    EmergencyEscape => "emergency_escape",
});
snake_enum!(RouteLane {
    SponsoredLowFee => "sponsored_low_fee",
    Standard => "standard",
    Fast => "fast",
    Defi => "defi",
    AtomicSwap => "atomic_swap",
    Emergency => "emergency",
});
snake_enum!(IntentStatus {
    Submitted => "submitted",
    PrivacyChecked => "privacy_checked",
    Quoted => "quoted",
    Reserved => "reserved",
    SwapLocked => "swap_locked",
    Batched => "batched",
    Settling => "settling",
    Settled => "settled",
    Expired => "expired",
    Cancelled => "cancelled",
    Disputed => "disputed",
    Slashed => "slashed",
});
snake_enum!(MakerKind {
    RetailFastExit => "retail_fast_exit",
    InstitutionalPool => "institutional_pool",
    DefiVault => "defi_vault",
    BridgeOperator => "bridge_operator",
    AtomicSwapDesk => "atomic_swap_desk",
    EmergencyBackstop => "emergency_backstop",
});
snake_enum!(MakerStatus {
    Active => "active",
    Throttled => "throttled",
    Frozen => "frozen",
    Exited => "exited",
    Slashed => "slashed",
});
snake_enum!(QuoteStatus {
    Posted => "posted",
    Matched => "matched",
    Reserved => "reserved",
    Batched => "batched",
    Filled => "filled",
    Expired => "expired",
    Cancelled => "cancelled",
    Slashed => "slashed",
});
snake_enum!(FastExitStatus {
    Held => "held",
    Bound => "bound",
    Netted => "netted",
    Broadcast => "broadcast",
    Finalized => "finalized",
    Released => "released",
    Expired => "expired",
    Slashed => "slashed",
});
snake_enum!(AtomicSwapStatus {
    Proposed => "proposed",
    Locked => "locked",
    AdaptorPosted => "adaptor_posted",
    Redeemed => "redeemed",
    Refunded => "refunded",
    Expired => "expired",
    Disputed => "disputed",
});
snake_enum!(ReserveStatus {
    Submitted => "submitted",
    Accepted => "accepted",
    Degraded => "degraded",
    Superseded => "superseded",
    Rejected => "rejected",
    Slashed => "slashed",
});
snake_enum!(SponsorshipStatus {
    Minted => "minted",
    Reserved => "reserved",
    Applied => "applied",
    Refunded => "refunded",
    Expired => "expired",
    Slashed => "slashed",
});
snake_enum!(FenceKind {
    IntentNullifier => "intent_nullifier",
    ViewTagBucket => "view_tag_bucket",
    SubaddressReplay => "subaddress_replay",
    QuoteReplay => "quote_replay",
    ReserveReplay => "reserve_replay",
    SwapReplay => "swap_replay",
    SponsorNullifier => "sponsor_nullifier",
    BatchNullifier => "batch_nullifier",
});
snake_enum!(ReorgGuardStatus {
    Quoted => "quoted",
    Active => "active",
    Locked => "locked",
    Claimed => "claimed",
    Paid => "paid",
    Denied => "denied",
    Expired => "expired",
});
snake_enum!(SlashingKind {
    DoubleIntent => "double_intent",
    FalseReserve => "false_reserve",
    Misroute => "misroute",
    StaleBroadcast => "stale_broadcast",
    PrivacyLeak => "privacy_leak",
    InvalidPqAuth => "invalid_pq_auth",
});
snake_enum!(BatchStatus {
    Open => "open",
    Sealed => "sealed",
    Broadcast => "broadcast",
    Finalized => "finalized",
    Reorged => "reorged",
    Disputed => "disputed",
    Slashed => "slashed",
});
snake_enum!(EventKind {
    IntentSubmitted => "intent_submitted",
    QuoteRegistered => "quote_registered",
    RouteSelected => "route_selected",
    ReserveBound => "reserve_bound",
    SwapIntentSubmitted => "swap_intent_submitted",
    SponsorshipMinted => "sponsorship_minted",
    BatchSettled => "batch_settled",
    ReorgGuardOpened => "reorg_guard_opened",
    SlashingSubmitted => "slashing_submitted",
});

impl RouteLane {
    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::Standard => config.standard_fee_bps,
            Self::Fast | Self::AtomicSwap => config.fast_fee_bps,
            Self::Defi => config.standard_fee_bps.saturating_add(config.low_fee_bps),
            Self::Emergency => config.emergency_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::AtomicSwap => 920,
            Self::Defi => 880,
            Self::SponsoredLowFee => 820,
            Self::Standard => 720,
        }
    }
}

impl IntentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::PrivacyChecked
                | Self::Quoted
                | Self::Reserved
                | Self::SwapLocked
                | Self::Batched
                | Self::Settling
        )
    }
}

impl QuoteStatus {
    pub fn fillable(self) -> bool {
        matches!(self, Self::Posted | Self::Matched | Self::Reserved)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub router_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub route_intent_scheme: String,
    pub view_tag_hint_scheme: String,
    pub stealth_proof_scheme: String,
    pub liquidity_quote_scheme: String,
    pub fast_exit_reserve_scheme: String,
    pub atomic_swap_intent_scheme: String,
    pub reserve_attestation_scheme: String,
    pub fee_sponsorship_scheme: String,
    pub nullifier_fence_scheme: String,
    pub reorg_protection_scheme: String,
    pub slashing_evidence_scheme: String,
    pub settlement_batch_scheme: String,
    pub replay_domain: String,
    pub intent_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub reserve_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub reorg_ttl_blocks: u64,
    pub finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_view_tag_bucket_size: u64,
    pub target_view_tag_bucket_size: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub standard_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub reorg_insurance_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub max_route_hops: u8,
    pub max_batch_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            base_asset_id: DEVNET_BASE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            route_intent_scheme: ROUTE_INTENT_SCHEME.to_string(),
            view_tag_hint_scheme: VIEW_TAG_HINT_SCHEME.to_string(),
            stealth_proof_scheme: STEALTH_PROOF_SCHEME.to_string(),
            liquidity_quote_scheme: LIQUIDITY_QUOTE_SCHEME.to_string(),
            fast_exit_reserve_scheme: FAST_EXIT_RESERVE_SCHEME.to_string(),
            atomic_swap_intent_scheme: ATOMIC_SWAP_INTENT_SCHEME.to_string(),
            reserve_attestation_scheme: RESERVE_ATTESTATION_SCHEME.to_string(),
            fee_sponsorship_scheme: FEE_SPONSORSHIP_SCHEME.to_string(),
            nullifier_fence_scheme: NULLIFIER_FENCE_SCHEME.to_string(),
            reorg_protection_scheme: REORG_PROTECTION_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            settlement_batch_scheme: SETTLEMENT_BATCH_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            reserve_ttl_blocks: DEFAULT_RESERVE_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            reorg_ttl_blocks: DEFAULT_REORG_TTL_BLOCKS,
            finality_blocks: DEFAULT_FINALITY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_view_tag_bucket_size: DEFAULT_MIN_VIEW_TAG_BUCKET_SIZE,
            target_view_tag_bucket_size: DEFAULT_TARGET_VIEW_TAG_BUCKET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            standard_fee_bps: DEFAULT_STANDARD_FEE_BPS,
            fast_fee_bps: DEFAULT_FAST_FEE_BPS,
            emergency_fee_bps: DEFAULT_EMERGENCY_FEE_BPS,
            reorg_insurance_bps: DEFAULT_REORG_INSURANCE_BPS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            max_route_hops: DEFAULT_MAX_ROUTE_HOPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub intents_submitted: u64,
    pub view_tag_hints: u64,
    pub stealth_proofs: u64,
    pub makers_registered: u64,
    pub quotes_registered: u64,
    pub routes_selected: u64,
    pub fast_reserves_bound: u64,
    pub atomic_swaps_submitted: u64,
    pub reserve_attestations: u64,
    pub fee_sponsorships: u64,
    pub nullifier_fences: u64,
    pub reorg_guards: u64,
    pub slashing_evidence: u64,
    pub settlement_batches: u64,
    pub events: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_sequence: 1,
            intents_submitted: 0,
            view_tag_hints: 0,
            stealth_proofs: 0,
            makers_registered: 0,
            quotes_registered: 0,
            routes_selected: 0,
            fast_reserves_bound: 0,
            atomic_swaps_submitted: 0,
            reserve_attestations: 0,
            fee_sponsorships: 0,
            nullifier_fences: 0,
            reorg_guards: 0,
            slashing_evidence: 0,
            settlement_batches: 0,
            events: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub intent_root: String,
    pub view_tag_hint_root: String,
    pub stealth_proof_root: String,
    pub maker_root: String,
    pub quote_root: String,
    pub fast_exit_route_root: String,
    pub atomic_swap_root: String,
    pub reserve_attestation_root: String,
    pub fee_sponsorship_root: String,
    pub nullifier_fence_root: String,
    pub reorg_guard_root: String,
    pub slashing_evidence_root: String,
    pub settlement_batch_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-SUBADDRESS-INTENT-LIQUIDITY-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagHint {
    pub hint_id: String,
    pub intent_id: String,
    pub view_tag_bucket_commitment: String,
    pub scan_epoch: u64,
    pub bucket_size: u64,
    pub decoy_set_root: String,
    pub encrypted_hint_root: String,
    pub created_at_height: u64,
}

impl ViewTagHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "intent_id": self.intent_id,
            "view_tag_bucket_commitment": self.view_tag_bucket_commitment,
            "scan_epoch": self.scan_epoch,
            "bucket_size": self.bucket_size,
            "decoy_set_root": self.decoy_set_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthProofCommitment {
    pub proof_id: String,
    pub intent_id: String,
    pub one_time_address_commitment: String,
    pub tx_public_key_commitment: String,
    pub subaddress_spend_key_commitment: String,
    pub range_proof_root: String,
    pub membership_proof_root: String,
    pub pq_auth_root: String,
    pub min_privacy_set_size: u64,
    pub created_at_height: u64,
}

impl StealthProofCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "intent_id": self.intent_id,
            "one_time_address_commitment": self.one_time_address_commitment,
            "tx_public_key_commitment": self.tx_public_key_commitment,
            "subaddress_spend_key_commitment": self.subaddress_spend_key_commitment,
            "range_proof_root": self.range_proof_root,
            "membership_proof_root": self.membership_proof_root,
            "pq_auth_root": self.pq_auth_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteIntent {
    pub intent_id: String,
    pub kind: RouteIntentKind,
    pub lane: RouteLane,
    pub status: IntentStatus,
    pub owner_commitment: String,
    pub source_subaddress_commitment: String,
    pub destination_subaddress_commitment: String,
    pub amount_commitment: String,
    pub min_output_commitment: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub view_tag_hint_id: String,
    pub stealth_proof_id: String,
    pub nullifier: String,
    pub pq_bridge_auth_root: String,
    pub route_policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub selected_quote_id: Option<String>,
    pub fast_exit_route_id: Option<String>,
    pub atomic_swap_id: Option<String>,
    pub settlement_batch_id: Option<String>,
}

impl RouteIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "source_subaddress_commitment": self.source_subaddress_commitment,
            "destination_subaddress_commitment": self.destination_subaddress_commitment,
            "amount_commitment": self.amount_commitment,
            "min_output_commitment": self.min_output_commitment,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "view_tag_hint_id": self.view_tag_hint_id,
            "stealth_proof_id": self.stealth_proof_id,
            "nullifier": self.nullifier,
            "pq_bridge_auth_root": self.pq_bridge_auth_root,
            "route_policy_root": self.route_policy_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "selected_quote_id": self.selected_quote_id,
            "fast_exit_route_id": self.fast_exit_route_id,
            "atomic_swap_id": self.atomic_swap_id,
            "settlement_batch_id": self.settlement_batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityMaker {
    pub maker_id: String,
    pub kind: MakerKind,
    pub status: MakerStatus,
    pub operator_commitment: String,
    pub pq_identity_root: String,
    pub reserve_attestation_root: String,
    pub supported_lanes: BTreeSet<RouteLane>,
    pub supported_assets: BTreeSet<String>,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub available_capacity_commitment: String,
    pub bond_commitment: String,
    pub registered_at_height: u64,
    pub last_quote_height: u64,
}

impl LiquidityMaker {
    pub fn public_record(&self) -> Value {
        json!({
            "maker_id": self.maker_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "pq_identity_root": self.pq_identity_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "supported_lanes": self.supported_lanes.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            "supported_assets": self.supported_assets.iter().collect::<Vec<_>>(),
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "available_capacity_commitment": self.available_capacity_commitment,
            "bond_commitment": self.bond_commitment,
            "registered_at_height": self.registered_at_height,
            "last_quote_height": self.last_quote_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityQuote {
    pub quote_id: String,
    pub maker_id: String,
    pub status: QuoteStatus,
    pub lane: RouteLane,
    pub asset_id: String,
    pub input_amount_commitment: String,
    pub output_amount_commitment: String,
    pub fee_bps: u64,
    pub priority_fee_commitment: String,
    pub reserve_attestation_id: String,
    pub private_defi_pool_root: String,
    pub route_hop_commitments: Vec<String>,
    pub min_privacy_set_size: u64,
    pub pq_quote_auth_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidityQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "asset_id": self.asset_id,
            "input_amount_commitment": self.input_amount_commitment,
            "output_amount_commitment": self.output_amount_commitment,
            "fee_bps": self.fee_bps,
            "priority_fee_commitment": self.priority_fee_commitment,
            "reserve_attestation_id": self.reserve_attestation_id,
            "private_defi_pool_root": self.private_defi_pool_root,
            "route_hop_commitments": self.route_hop_commitments,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_quote_auth_root": self.pq_quote_auth_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn score(&self, lane: RouteLane) -> u128 {
        let fee_score = (MAX_BPS.saturating_sub(self.fee_bps)) as u128 * 10_000;
        let privacy_score = self.min_privacy_set_size as u128;
        let route_penalty = self.route_hop_commitments.len() as u128 * 50;
        fee_score
            .saturating_add(privacy_score)
            .saturating_add(lane.priority_weight() as u128)
            .saturating_sub(route_penalty)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastExitRoute {
    pub fast_exit_route_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub maker_id: String,
    pub status: FastExitStatus,
    pub reserve_commitment: String,
    pub reserve_attestation_id: String,
    pub payout_subaddress_commitment: String,
    pub watchtower_quorum_root: String,
    pub reorg_guard_id: Option<String>,
    pub bound_at_height: u64,
    pub expires_at_height: u64,
}

impl FastExitRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "fast_exit_route_id": self.fast_exit_route_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "reserve_attestation_id": self.reserve_attestation_id,
            "payout_subaddress_commitment": self.payout_subaddress_commitment,
            "watchtower_quorum_root": self.watchtower_quorum_root,
            "reorg_guard_id": self.reorg_guard_id,
            "bound_at_height": self.bound_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AtomicSwapIntent {
    pub swap_id: String,
    pub intent_id: String,
    pub maker_id: String,
    pub status: AtomicSwapStatus,
    pub monero_lock_commitment: String,
    pub l2_lock_commitment: String,
    pub adaptor_point_commitment: String,
    pub refund_key_commitment: String,
    pub pq_swap_auth_root: String,
    pub fee_sponsorship_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl AtomicSwapIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "swap_id": self.swap_id,
            "intent_id": self.intent_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "monero_lock_commitment": self.monero_lock_commitment,
            "l2_lock_commitment": self.l2_lock_commitment,
            "adaptor_point_commitment": self.adaptor_point_commitment,
            "refund_key_commitment": self.refund_key_commitment,
            "pq_swap_auth_root": self.pq_swap_auth_root,
            "fee_sponsorship_id": self.fee_sponsorship_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveAttestation {
    pub attestation_id: String,
    pub maker_id: String,
    pub status: ReserveStatus,
    pub reserve_commitment: String,
    pub liability_commitment: String,
    pub coverage_bps: u64,
    pub view_key_disclosure_root: String,
    pub monero_height: u64,
    pub pq_attestation_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "liability_commitment": self.liability_commitment,
            "coverage_bps": self.coverage_bps,
            "view_key_disclosure_root": self.view_key_disclosure_root,
            "monero_height": self.monero_height,
            "pq_attestation_root": self.pq_attestation_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub intent_id: Option<String>,
    pub status: SponsorshipStatus,
    pub fee_asset_id: String,
    pub fee_budget_commitment: String,
    pub rebate_bps: u64,
    pub nullifier: String,
    pub pq_sponsor_auth_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "fee_budget_commitment": self.fee_budget_commitment,
            "rebate_bps": self.rebate_bps,
            "nullifier": self.nullifier,
            "pq_sponsor_auth_root": self.pq_sponsor_auth_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub nullifier: String,
    pub domain: String,
    pub created_at_height: u64,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "nullifier": self.nullifier,
            "domain": self.domain,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgGuard {
    pub reorg_guard_id: String,
    pub intent_id: String,
    pub maker_id: String,
    pub status: ReorgGuardStatus,
    pub protected_height: u64,
    pub finality_blocks: u64,
    pub insurance_commitment: String,
    pub watchtower_quorum_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ReorgGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "reorg_guard_id": self.reorg_guard_id,
            "intent_id": self.intent_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "protected_height": self.protected_height,
            "finality_blocks": self.finality_blocks,
            "insurance_commitment": self.insurance_commitment,
            "watchtower_quorum_root": self.watchtower_quorum_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: SlashingKind,
    pub accused_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub penalty_bps: u64,
    pub pq_witness_root: String,
    pub created_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "accused_id": self.accused_id,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "penalty_bps": self.penalty_bps,
            "pq_witness_root": self.pq_witness_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub intent_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub fast_exit_route_ids: Vec<String>,
    pub atomic_swap_ids: Vec<String>,
    pub netted_amount_root: String,
    pub monero_tx_commitment: String,
    pub watchtower_receipt_root: String,
    pub batch_nullifier: String,
    pub created_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "intent_ids": self.intent_ids,
            "quote_ids": self.quote_ids,
            "fast_exit_route_ids": self.fast_exit_route_ids,
            "atomic_swap_ids": self.atomic_swap_ids,
            "netted_amount_root": self.netted_amount_root,
            "monero_tx_commitment": self.monero_tx_commitment,
            "watchtower_receipt_root": self.watchtower_receipt_root,
            "batch_nullifier": self.batch_nullifier,
            "created_at_height": self.created_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "root": self.root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub monero_height: u64,
    pub route_intents: BTreeMap<String, RouteIntent>,
    pub view_tag_hints: BTreeMap<String, ViewTagHint>,
    pub stealth_proofs: BTreeMap<String, StealthProofCommitment>,
    pub liquidity_makers: BTreeMap<String, LiquidityMaker>,
    pub liquidity_quotes: BTreeMap<String, LiquidityQuote>,
    pub fast_exit_routes: BTreeMap<String, FastExitRoute>,
    pub atomic_swap_intents: BTreeMap<String, AtomicSwapIntent>,
    pub reserve_attestations: BTreeMap<String, ReserveAttestation>,
    pub fee_sponsorships: BTreeMap<String, FeeSponsorship>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub reorg_guards: BTreeMap<String, ReorgGuard>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::devnet(),
            current_height: DEVNET_HEIGHT,
            monero_height: DEVNET_HEIGHT.saturating_sub(640),
            route_intents: BTreeMap::new(),
            view_tag_hints: BTreeMap::new(),
            stealth_proofs: BTreeMap::new(),
            liquidity_makers: BTreeMap::new(),
            liquidity_quotes: BTreeMap::new(),
            fast_exit_routes: BTreeMap::new(),
            atomic_swap_intents: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            fee_sponsorships: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            reorg_guards: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            events: BTreeMap::new(),
        };

        let maker_id = state
            .register_liquidity_maker(
                MakerKind::DefiVault,
                "devnet-maker-operator-commitment",
                "devnet-maker-pq-identity-root",
                "devnet-maker-reserve-root",
                [RouteLane::SponsoredLowFee, RouteLane::Fast, RouteLane::Defi]
                    .into_iter()
                    .collect(),
                [
                    DEVNET_BASE_ASSET_ID.to_string(),
                    DEVNET_QUOTE_ASSET_ID.to_string(),
                ]
                .into_iter()
                .collect(),
                DEFAULT_FAST_FEE_BPS,
                DEFAULT_MIN_PRIVACY_SET_SIZE,
                "devnet-maker-capacity-commitment",
                "devnet-maker-bond-commitment",
            )
            .unwrap_or_else(|err| deterministic_error_id("DEVNET-MAKER-ERROR", &err));
        let reserve_id = state
            .submit_reserve_attestation(
                &maker_id,
                "devnet-reserve-commitment",
                "devnet-liability-commitment",
                DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
                "devnet-view-key-disclosure-root",
                "devnet-pq-reserve-attestation-root",
            )
            .unwrap_or_else(|err| deterministic_error_id("DEVNET-RESERVE-ERROR", &err));
        let intent_id = state
            .submit_route_intent(RouteIntentRequest {
                kind: RouteIntentKind::PrivateFastExit,
                lane: RouteLane::Fast,
                owner_commitment: "devnet-owner-commitment".to_string(),
                source_subaddress_commitment: "devnet-source-subaddress-commitment".to_string(),
                destination_subaddress_commitment: "devnet-destination-subaddress-commitment"
                    .to_string(),
                amount_commitment: "devnet-amount-commitment".to_string(),
                min_output_commitment: "devnet-min-output-commitment".to_string(),
                asset_id: DEVNET_BASE_ASSET_ID.to_string(),
                fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                max_fee_bps: DEFAULT_FAST_FEE_BPS,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                view_tag_bucket_commitment: "devnet-view-tag-bucket".to_string(),
                scan_epoch: DEVNET_HEIGHT / 720,
                bucket_size: DEFAULT_TARGET_VIEW_TAG_BUCKET_SIZE,
                decoy_set_root: "devnet-decoy-set-root".to_string(),
                encrypted_hint_root: "devnet-encrypted-hint-root".to_string(),
                one_time_address_commitment: "devnet-one-time-address".to_string(),
                tx_public_key_commitment: "devnet-tx-public-key".to_string(),
                subaddress_spend_key_commitment: "devnet-subaddress-spend-key".to_string(),
                range_proof_root: "devnet-range-proof-root".to_string(),
                membership_proof_root: "devnet-membership-proof-root".to_string(),
                pq_auth_root: "devnet-pq-auth-root".to_string(),
                nullifier: "devnet-intent-nullifier".to_string(),
                pq_bridge_auth_root: "devnet-pq-bridge-auth-root".to_string(),
                route_policy_root: "devnet-route-policy-root".to_string(),
            })
            .unwrap_or_else(|err| deterministic_error_id("DEVNET-INTENT-ERROR", &err));
        let quote_id = state
            .register_liquidity_quote(LiquidityQuoteRequest {
                maker_id: maker_id.clone(),
                lane: RouteLane::Fast,
                asset_id: DEVNET_BASE_ASSET_ID.to_string(),
                input_amount_commitment: "devnet-quote-input".to_string(),
                output_amount_commitment: "devnet-quote-output".to_string(),
                fee_bps: DEFAULT_FAST_FEE_BPS,
                priority_fee_commitment: "devnet-priority-fee".to_string(),
                reserve_attestation_id: reserve_id.clone(),
                private_defi_pool_root: "devnet-private-defi-pool-root".to_string(),
                route_hop_commitments: vec![
                    "devnet-hop-0".to_string(),
                    "devnet-hop-1".to_string(),
                    "devnet-hop-2".to_string(),
                ],
                min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                pq_quote_auth_root: "devnet-pq-quote-auth-root".to_string(),
            })
            .unwrap_or_else(|err| deterministic_error_id("DEVNET-QUOTE-ERROR", &err));
        let _ = state.select_private_route(&intent_id);
        let _ = state.bind_fast_exit_reserve(
            &intent_id,
            &quote_id,
            "devnet-fast-reserve-commitment",
            "devnet-payout-subaddress-commitment",
            "devnet-watchtower-quorum-root",
        );
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: domain_hash(
                "MONERO-SUBADDRESS-INTENT-CONFIG",
                &[HashPart::Json(&self.config.public_record())],
                32,
            ),
            intent_root: map_root("MONERO-SUBADDRESS-INTENT", &self.route_intents),
            view_tag_hint_root: map_root("MONERO-SUBADDRESS-VIEW-TAG-HINT", &self.view_tag_hints),
            stealth_proof_root: map_root("MONERO-SUBADDRESS-STEALTH-PROOF", &self.stealth_proofs),
            maker_root: map_root("MONERO-SUBADDRESS-LIQUIDITY-MAKER", &self.liquidity_makers),
            quote_root: map_root("MONERO-SUBADDRESS-LIQUIDITY-QUOTE", &self.liquidity_quotes),
            fast_exit_route_root: map_root(
                "MONERO-SUBADDRESS-FAST-EXIT-ROUTE",
                &self.fast_exit_routes,
            ),
            atomic_swap_root: map_root("MONERO-SUBADDRESS-ATOMIC-SWAP", &self.atomic_swap_intents),
            reserve_attestation_root: map_root(
                "MONERO-SUBADDRESS-RESERVE-ATTESTATION",
                &self.reserve_attestations,
            ),
            fee_sponsorship_root: map_root(
                "MONERO-SUBADDRESS-FEE-SPONSORSHIP",
                &self.fee_sponsorships,
            ),
            nullifier_fence_root: map_root(
                "MONERO-SUBADDRESS-NULLIFIER-FENCE",
                &self.nullifier_fences,
            ),
            reorg_guard_root: map_root("MONERO-SUBADDRESS-REORG-GUARD", &self.reorg_guards),
            slashing_evidence_root: map_root(
                "MONERO-SUBADDRESS-SLASHING-EVIDENCE",
                &self.slashing_evidence,
            ),
            settlement_batch_root: map_root(
                "MONERO-SUBADDRESS-SETTLEMENT-BATCH",
                &self.settlement_batches,
            ),
            event_root: map_root("MONERO-SUBADDRESS-RUNTIME-EVENT", &self.events),
        }
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-SUBADDRESS-INTENT-LIQUIDITY-ROUTER-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "monero_height": self.monero_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn submit_route_intent(&mut self, request: RouteIntentRequest) -> Result<String> {
        self.ensure_len("route_intents", self.route_intents.len(), MAX_ROUTE_INTENTS)?;
        require_bps("max_fee_bps", request.max_fee_bps)?;
        if request.max_fee_bps > request.lane.fee_bps(&self.config) {
            return Err("route intent max fee is below lane fee".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("route intent privacy set is too small".to_string());
        }
        if request.bucket_size < self.config.min_view_tag_bucket_size {
            return Err("view tag bucket is too small".to_string());
        }
        self.ensure_fence_free(&request.nullifier)?;

        let sequence = self.next_sequence();
        let hint_id = route_id(
            "MONERO-SUBADDRESS-VIEW-TAG-HINT-ID",
            &[
                HashPart::Str(&request.view_tag_bucket_commitment),
                HashPart::U64(request.scan_epoch),
                HashPart::U64(sequence),
            ],
        );
        let proof_id = route_id(
            "MONERO-SUBADDRESS-STEALTH-PROOF-ID",
            &[
                HashPart::Str(&request.one_time_address_commitment),
                HashPart::Str(&request.tx_public_key_commitment),
                HashPart::U64(sequence),
            ],
        );
        let intent_id = route_id(
            "MONERO-SUBADDRESS-ROUTE-INTENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.source_subaddress_commitment),
                HashPart::Str(&request.destination_subaddress_commitment),
                HashPart::Str(&request.amount_commitment),
                HashPart::Str(&request.nullifier),
                HashPart::U64(sequence),
            ],
        );

        let hint = ViewTagHint {
            hint_id: hint_id.clone(),
            intent_id: intent_id.clone(),
            view_tag_bucket_commitment: request.view_tag_bucket_commitment,
            scan_epoch: request.scan_epoch,
            bucket_size: request.bucket_size,
            decoy_set_root: request.decoy_set_root,
            encrypted_hint_root: request.encrypted_hint_root,
            created_at_height: self.current_height,
        };
        let proof = StealthProofCommitment {
            proof_id: proof_id.clone(),
            intent_id: intent_id.clone(),
            one_time_address_commitment: request.one_time_address_commitment,
            tx_public_key_commitment: request.tx_public_key_commitment,
            subaddress_spend_key_commitment: request.subaddress_spend_key_commitment,
            range_proof_root: request.range_proof_root,
            membership_proof_root: request.membership_proof_root,
            pq_auth_root: request.pq_auth_root,
            min_privacy_set_size: request.privacy_set_size,
            created_at_height: self.current_height,
        };
        let intent = RouteIntent {
            intent_id: intent_id.clone(),
            kind: request.kind,
            lane: request.lane,
            status: IntentStatus::PrivacyChecked,
            owner_commitment: request.owner_commitment,
            source_subaddress_commitment: request.source_subaddress_commitment,
            destination_subaddress_commitment: request.destination_subaddress_commitment,
            amount_commitment: request.amount_commitment,
            min_output_commitment: request.min_output_commitment,
            asset_id: request.asset_id,
            fee_asset_id: request.fee_asset_id,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            view_tag_hint_id: hint_id.clone(),
            stealth_proof_id: proof_id.clone(),
            nullifier: request.nullifier.clone(),
            pq_bridge_auth_root: request.pq_bridge_auth_root,
            route_policy_root: request.route_policy_root,
            created_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.intent_ttl_blocks),
            selected_quote_id: None,
            fast_exit_route_id: None,
            atomic_swap_id: None,
            settlement_batch_id: None,
        };
        let fence = self.make_fence(
            FenceKind::IntentNullifier,
            &intent_id,
            &request.nullifier,
            "intent",
        );

        self.view_tag_hints.insert(hint_id, hint);
        self.stealth_proofs.insert(proof_id, proof);
        self.route_intents.insert(intent_id.clone(), intent);
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.counters.view_tag_hints = self.counters.view_tag_hints.saturating_add(1);
        self.counters.stealth_proofs = self.counters.stealth_proofs.saturating_add(1);
        self.counters.nullifier_fences = self.counters.nullifier_fences.saturating_add(1);
        self.push_event(EventKind::IntentSubmitted, &intent_id, "intent");
        Ok(intent_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_liquidity_maker(
        &mut self,
        kind: MakerKind,
        operator_commitment: &str,
        pq_identity_root: &str,
        reserve_attestation_root: &str,
        supported_lanes: BTreeSet<RouteLane>,
        supported_assets: BTreeSet<String>,
        max_fee_bps: u64,
        min_privacy_set_size: u64,
        available_capacity_commitment: &str,
        bond_commitment: &str,
    ) -> Result<String> {
        self.ensure_len(
            "liquidity_makers",
            self.liquidity_makers.len(),
            MAX_LIQUIDITY_MAKERS,
        )?;
        require_bps("max_fee_bps", max_fee_bps)?;
        if supported_lanes.is_empty() {
            return Err("maker must support at least one lane".to_string());
        }
        if supported_assets.is_empty() {
            return Err("maker must support at least one asset".to_string());
        }
        let sequence = self.next_sequence();
        let maker_id = route_id(
            "MONERO-SUBADDRESS-LIQUIDITY-MAKER-ID",
            &[
                HashPart::Str(operator_commitment),
                HashPart::Str(pq_identity_root),
                HashPart::U64(sequence),
            ],
        );
        let maker = LiquidityMaker {
            maker_id: maker_id.clone(),
            kind,
            status: MakerStatus::Active,
            operator_commitment: operator_commitment.to_string(),
            pq_identity_root: pq_identity_root.to_string(),
            reserve_attestation_root: reserve_attestation_root.to_string(),
            supported_lanes,
            supported_assets,
            max_fee_bps,
            min_privacy_set_size,
            available_capacity_commitment: available_capacity_commitment.to_string(),
            bond_commitment: bond_commitment.to_string(),
            registered_at_height: self.current_height,
            last_quote_height: self.current_height,
        };
        self.liquidity_makers.insert(maker_id.clone(), maker);
        self.counters.makers_registered = self.counters.makers_registered.saturating_add(1);
        self.push_event(EventKind::QuoteRegistered, &maker_id, "maker");
        Ok(maker_id)
    }

    pub fn submit_reserve_attestation(
        &mut self,
        maker_id: &str,
        reserve_commitment: &str,
        liability_commitment: &str,
        coverage_bps: u64,
        view_key_disclosure_root: &str,
        pq_attestation_root: &str,
    ) -> Result<String> {
        self.ensure_len(
            "reserve_attestations",
            self.reserve_attestations.len(),
            MAX_RESERVE_ATTESTATIONS,
        )?;
        if !self.liquidity_makers.contains_key(maker_id) {
            return Err("reserve attestation maker is unknown".to_string());
        }
        if coverage_bps < self.config.min_reserve_coverage_bps {
            return Err("reserve coverage is below minimum".to_string());
        }
        let sequence = self.next_sequence();
        let attestation_id = route_id(
            "MONERO-SUBADDRESS-RESERVE-ATTESTATION-ID",
            &[
                HashPart::Str(maker_id),
                HashPart::Str(reserve_commitment),
                HashPart::Str(liability_commitment),
                HashPart::U64(self.monero_height),
                HashPart::U64(sequence),
            ],
        );
        let attestation = ReserveAttestation {
            attestation_id: attestation_id.clone(),
            maker_id: maker_id.to_string(),
            status: ReserveStatus::Accepted,
            reserve_commitment: reserve_commitment.to_string(),
            liability_commitment: liability_commitment.to_string(),
            coverage_bps,
            view_key_disclosure_root: view_key_disclosure_root.to_string(),
            monero_height: self.monero_height,
            pq_attestation_root: pq_attestation_root.to_string(),
            created_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.reserve_ttl_blocks),
        };
        self.reserve_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.reserve_attestations = self.counters.reserve_attestations.saturating_add(1);
        Ok(attestation_id)
    }

    pub fn register_liquidity_quote(&mut self, request: LiquidityQuoteRequest) -> Result<String> {
        self.ensure_len(
            "liquidity_quotes",
            self.liquidity_quotes.len(),
            MAX_LIQUIDITY_QUOTES,
        )?;
        require_bps("fee_bps", request.fee_bps)?;
        let maker = self
            .liquidity_makers
            .get(&request.maker_id)
            .ok_or_else(|| "quote maker is unknown".to_string())?;
        if maker.status != MakerStatus::Active {
            return Err("quote maker is not active".to_string());
        }
        if !maker.supported_lanes.contains(&request.lane) {
            return Err("quote lane is not supported by maker".to_string());
        }
        if !maker.supported_assets.contains(&request.asset_id) {
            return Err("quote asset is not supported by maker".to_string());
        }
        if request.fee_bps > maker.max_fee_bps {
            return Err("quote fee exceeds maker maximum".to_string());
        }
        if request.route_hop_commitments.len() > self.config.max_route_hops as usize {
            return Err("quote route has too many hops".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("quote privacy set is too small".to_string());
        }
        let reserve = self
            .reserve_attestations
            .get(&request.reserve_attestation_id)
            .ok_or_else(|| "quote reserve attestation is unknown".to_string())?;
        if reserve.maker_id != request.maker_id || reserve.status != ReserveStatus::Accepted {
            return Err("quote reserve attestation is not accepted for maker".to_string());
        }
        if reserve.expires_at_height <= self.current_height {
            return Err("quote reserve attestation is expired".to_string());
        }
        let sequence = self.next_sequence();
        let quote_id = route_id(
            "MONERO-SUBADDRESS-LIQUIDITY-QUOTE-ID",
            &[
                HashPart::Str(&request.maker_id),
                HashPart::Str(request.lane.as_str()),
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.input_amount_commitment),
                HashPart::Str(&request.output_amount_commitment),
                HashPart::U64(sequence),
            ],
        );
        let quote = LiquidityQuote {
            quote_id: quote_id.clone(),
            maker_id: request.maker_id.clone(),
            status: QuoteStatus::Posted,
            lane: request.lane,
            asset_id: request.asset_id,
            input_amount_commitment: request.input_amount_commitment,
            output_amount_commitment: request.output_amount_commitment,
            fee_bps: request.fee_bps,
            priority_fee_commitment: request.priority_fee_commitment,
            reserve_attestation_id: request.reserve_attestation_id,
            private_defi_pool_root: request.private_defi_pool_root,
            route_hop_commitments: request.route_hop_commitments,
            min_privacy_set_size: request.min_privacy_set_size,
            pq_quote_auth_root: request.pq_quote_auth_root,
            created_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.quote_ttl_blocks),
        };
        self.liquidity_quotes.insert(quote_id.clone(), quote);
        if let Some(maker) = self.liquidity_makers.get_mut(&request.maker_id) {
            maker.last_quote_height = self.current_height;
        }
        self.counters.quotes_registered = self.counters.quotes_registered.saturating_add(1);
        self.push_event(EventKind::QuoteRegistered, &quote_id, "quote");
        Ok(quote_id)
    }

    pub fn select_private_route(&mut self, intent_id: &str) -> Result<String> {
        let intent = self
            .route_intents
            .get(intent_id)
            .ok_or_else(|| "route intent is unknown".to_string())?
            .clone();
        if !intent.status.live() {
            return Err("route intent is not live".to_string());
        }
        if intent.expires_at_height <= self.current_height {
            return Err("route intent is expired".to_string());
        }
        let mut best: Option<(u128, String)> = None;
        for quote in self.liquidity_quotes.values() {
            if !quote.status.fillable()
                || quote.expires_at_height <= self.current_height
                || quote.lane != intent.lane
                || quote.asset_id != intent.asset_id
                || quote.fee_bps > intent.max_fee_bps
                || quote.min_privacy_set_size > intent.privacy_set_size
            {
                continue;
            }
            let score = quote.score(intent.lane);
            match &best {
                Some((best_score, best_id))
                    if *best_score > score
                        || (*best_score == score
                            && best_id.as_str() <= quote.quote_id.as_str()) => {}
                _ => best = Some((score, quote.quote_id.clone())),
            }
        }
        let quote_id = best
            .map(|(_, quote_id)| quote_id)
            .ok_or_else(|| "no private route quote matched intent".to_string())?;
        if let Some(intent) = self.route_intents.get_mut(intent_id) {
            intent.status = IntentStatus::Quoted;
            intent.selected_quote_id = Some(quote_id.clone());
        }
        if let Some(quote) = self.liquidity_quotes.get_mut(&quote_id) {
            quote.status = QuoteStatus::Matched;
        }
        self.counters.routes_selected = self.counters.routes_selected.saturating_add(1);
        self.push_event(EventKind::RouteSelected, intent_id, &quote_id);
        Ok(quote_id)
    }

    pub fn bind_fast_exit_reserve(
        &mut self,
        intent_id: &str,
        quote_id: &str,
        reserve_commitment: &str,
        payout_subaddress_commitment: &str,
        watchtower_quorum_root: &str,
    ) -> Result<String> {
        self.ensure_len(
            "fast_exit_routes",
            self.fast_exit_routes.len(),
            MAX_FAST_EXIT_ROUTES,
        )?;
        let intent = self
            .route_intents
            .get(intent_id)
            .ok_or_else(|| "fast exit intent is unknown".to_string())?
            .clone();
        let quote = self
            .liquidity_quotes
            .get(quote_id)
            .ok_or_else(|| "fast exit quote is unknown".to_string())?
            .clone();
        if intent.selected_quote_id.as_deref() != Some(quote_id) {
            return Err("fast exit quote is not selected by intent".to_string());
        }
        if quote.status != QuoteStatus::Matched {
            return Err("fast exit quote is not matched".to_string());
        }
        let sequence = self.next_sequence();
        let fast_exit_route_id = route_id(
            "MONERO-SUBADDRESS-FAST-EXIT-ROUTE-ID",
            &[
                HashPart::Str(intent_id),
                HashPart::Str(quote_id),
                HashPart::Str(reserve_commitment),
                HashPart::U64(sequence),
            ],
        );
        let reorg_guard_id = self.open_reorg_guard(
            intent_id,
            &quote.maker_id,
            "fast-exit-reorg-insurance",
            watchtower_quorum_root,
        )?;
        let route = FastExitRoute {
            fast_exit_route_id: fast_exit_route_id.clone(),
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            maker_id: quote.maker_id.clone(),
            status: FastExitStatus::Bound,
            reserve_commitment: reserve_commitment.to_string(),
            reserve_attestation_id: quote.reserve_attestation_id.clone(),
            payout_subaddress_commitment: payout_subaddress_commitment.to_string(),
            watchtower_quorum_root: watchtower_quorum_root.to_string(),
            reorg_guard_id: Some(reorg_guard_id),
            bound_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.reserve_ttl_blocks),
        };
        self.fast_exit_routes
            .insert(fast_exit_route_id.clone(), route);
        if let Some(intent) = self.route_intents.get_mut(intent_id) {
            intent.status = IntentStatus::Reserved;
            intent.fast_exit_route_id = Some(fast_exit_route_id.clone());
        }
        if let Some(quote) = self.liquidity_quotes.get_mut(quote_id) {
            quote.status = QuoteStatus::Reserved;
        }
        self.counters.fast_reserves_bound = self.counters.fast_reserves_bound.saturating_add(1);
        self.push_event(EventKind::ReserveBound, &fast_exit_route_id, intent_id);
        Ok(fast_exit_route_id)
    }

    pub fn submit_atomic_swap_intent(
        &mut self,
        intent_id: &str,
        maker_id: &str,
        monero_lock_commitment: &str,
        l2_lock_commitment: &str,
        adaptor_point_commitment: &str,
        refund_key_commitment: &str,
        pq_swap_auth_root: &str,
        fee_sponsorship_id: Option<String>,
    ) -> Result<String> {
        self.ensure_len(
            "atomic_swap_intents",
            self.atomic_swap_intents.len(),
            MAX_ATOMIC_SWAP_INTENTS,
        )?;
        if !self.route_intents.contains_key(intent_id) {
            return Err("atomic swap intent route is unknown".to_string());
        }
        if !self.liquidity_makers.contains_key(maker_id) {
            return Err("atomic swap maker is unknown".to_string());
        }
        if let Some(sponsorship_id) = fee_sponsorship_id.as_deref() {
            if !self.fee_sponsorships.contains_key(sponsorship_id) {
                return Err("atomic swap fee sponsorship is unknown".to_string());
            }
        }
        let sequence = self.next_sequence();
        let swap_id = route_id(
            "MONERO-SUBADDRESS-ATOMIC-SWAP-ID",
            &[
                HashPart::Str(intent_id),
                HashPart::Str(maker_id),
                HashPart::Str(monero_lock_commitment),
                HashPart::Str(l2_lock_commitment),
                HashPart::U64(sequence),
            ],
        );
        let swap = AtomicSwapIntent {
            swap_id: swap_id.clone(),
            intent_id: intent_id.to_string(),
            maker_id: maker_id.to_string(),
            status: AtomicSwapStatus::Locked,
            monero_lock_commitment: monero_lock_commitment.to_string(),
            l2_lock_commitment: l2_lock_commitment.to_string(),
            adaptor_point_commitment: adaptor_point_commitment.to_string(),
            refund_key_commitment: refund_key_commitment.to_string(),
            pq_swap_auth_root: pq_swap_auth_root.to_string(),
            fee_sponsorship_id,
            created_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.intent_ttl_blocks),
        };
        self.atomic_swap_intents.insert(swap_id.clone(), swap);
        if let Some(intent) = self.route_intents.get_mut(intent_id) {
            intent.status = IntentStatus::SwapLocked;
            intent.atomic_swap_id = Some(swap_id.clone());
        }
        self.counters.atomic_swaps_submitted =
            self.counters.atomic_swaps_submitted.saturating_add(1);
        self.push_event(EventKind::SwapIntentSubmitted, &swap_id, intent_id);
        Ok(swap_id)
    }

    pub fn mint_fee_sponsorship(
        &mut self,
        sponsor_commitment: &str,
        intent_id: Option<String>,
        fee_budget_commitment: &str,
        nullifier: &str,
        pq_sponsor_auth_root: &str,
    ) -> Result<String> {
        self.ensure_len(
            "fee_sponsorships",
            self.fee_sponsorships.len(),
            MAX_FEE_SPONSORSHIPS,
        )?;
        self.ensure_fence_free(nullifier)?;
        let sequence = self.next_sequence();
        let sponsorship_id = route_id(
            "MONERO-SUBADDRESS-FEE-SPONSORSHIP-ID",
            &[
                HashPart::Str(sponsor_commitment),
                HashPart::Str(fee_budget_commitment),
                HashPart::Str(nullifier),
                HashPart::U64(sequence),
            ],
        );
        let sponsorship = FeeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            intent_id: intent_id.clone(),
            status: SponsorshipStatus::Minted,
            fee_asset_id: self.config.fee_asset_id.clone(),
            fee_budget_commitment: fee_budget_commitment.to_string(),
            rebate_bps: self.config.sponsor_rebate_bps,
            nullifier: nullifier.to_string(),
            pq_sponsor_auth_root: pq_sponsor_auth_root.to_string(),
            created_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.sponsor_ttl_blocks),
        };
        let fence = self.make_fence(
            FenceKind::SponsorNullifier,
            &sponsorship_id,
            nullifier,
            "fee_sponsorship",
        );
        self.fee_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);
        self.counters.fee_sponsorships = self.counters.fee_sponsorships.saturating_add(1);
        self.counters.nullifier_fences = self.counters.nullifier_fences.saturating_add(1);
        self.push_event(EventKind::SponsorshipMinted, &sponsorship_id, "sponsorship");
        Ok(sponsorship_id)
    }

    pub fn settle_route_batch(
        &mut self,
        intent_ids: Vec<String>,
        monero_tx_commitment: &str,
        watchtower_receipt_root: &str,
    ) -> Result<String> {
        self.ensure_len(
            "settlement_batches",
            self.settlement_batches.len(),
            MAX_SETTLEMENT_BATCHES,
        )?;
        if intent_ids.is_empty() {
            return Err("settlement batch must include at least one intent".to_string());
        }
        if intent_ids.len() > self.config.max_batch_items {
            return Err("settlement batch has too many intents".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut quote_ids = BTreeSet::new();
        let mut fast_exit_route_ids = BTreeSet::new();
        let mut atomic_swap_ids = BTreeSet::new();
        for intent_id in &intent_ids {
            if !seen.insert(intent_id.clone()) {
                return Err("settlement batch contains duplicate intent".to_string());
            }
            let intent = self
                .route_intents
                .get(intent_id)
                .ok_or_else(|| "settlement intent is unknown".to_string())?;
            if !intent.status.live() {
                return Err("settlement intent is not live".to_string());
            }
            if let Some(quote_id) = &intent.selected_quote_id {
                quote_ids.insert(quote_id.clone());
            }
            if let Some(route_id) = &intent.fast_exit_route_id {
                fast_exit_route_ids.insert(route_id.clone());
            }
            if let Some(swap_id) = &intent.atomic_swap_id {
                atomic_swap_ids.insert(swap_id.clone());
            }
        }
        let batch_nullifier = route_id(
            "MONERO-SUBADDRESS-SETTLEMENT-BATCH-NULLIFIER",
            &[
                HashPart::Json(&json!(intent_ids)),
                HashPart::Str(monero_tx_commitment),
                HashPart::U64(self.current_height),
            ],
        );
        self.ensure_fence_free(&batch_nullifier)?;
        let sequence = self.next_sequence();
        let batch_id = route_id(
            "MONERO-SUBADDRESS-SETTLEMENT-BATCH-ID",
            &[
                HashPart::Str(&batch_nullifier),
                HashPart::Str(monero_tx_commitment),
                HashPart::U64(sequence),
            ],
        );
        let amount_records = intent_ids
            .iter()
            .filter_map(|id| self.route_intents.get(id))
            .map(|intent| json!({"intent_id": intent.intent_id, "amount_commitment": intent.amount_commitment}))
            .collect::<Vec<_>>();
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Finalized,
            intent_ids: intent_ids.clone(),
            quote_ids: quote_ids.iter().cloned().collect(),
            fast_exit_route_ids: fast_exit_route_ids.iter().cloned().collect(),
            atomic_swap_ids: atomic_swap_ids.iter().cloned().collect(),
            netted_amount_root: merkle_root("MONERO-SUBADDRESS-BATCH-AMOUNTS", &amount_records),
            monero_tx_commitment: monero_tx_commitment.to_string(),
            watchtower_receipt_root: watchtower_receipt_root.to_string(),
            batch_nullifier: batch_nullifier.clone(),
            created_at_height: self.current_height,
            finalized_at_height: Some(
                self.current_height
                    .saturating_add(self.config.finality_blocks),
            ),
        };
        for intent_id in &intent_ids {
            if let Some(intent) = self.route_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
                intent.settlement_batch_id = Some(batch_id.clone());
            }
        }
        for quote_id in &quote_ids {
            if let Some(quote) = self.liquidity_quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Filled;
            }
        }
        for route_id in &fast_exit_route_ids {
            if let Some(route) = self.fast_exit_routes.get_mut(route_id) {
                route.status = FastExitStatus::Finalized;
            }
        }
        for swap_id in &atomic_swap_ids {
            if let Some(swap) = self.atomic_swap_intents.get_mut(swap_id) {
                swap.status = AtomicSwapStatus::Redeemed;
            }
        }
        let fence = self.make_fence(
            FenceKind::BatchNullifier,
            &batch_id,
            &batch_nullifier,
            "settlement_batch",
        );
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);
        self.counters.settlement_batches = self.counters.settlement_batches.saturating_add(1);
        self.counters.nullifier_fences = self.counters.nullifier_fences.saturating_add(1);
        self.push_event(EventKind::BatchSettled, &batch_id, monero_tx_commitment);
        Ok(batch_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        kind: SlashingKind,
        accused_id: &str,
        subject_id: &str,
        evidence_root: &str,
        penalty_bps: u64,
        pq_witness_root: &str,
    ) -> Result<String> {
        self.ensure_len(
            "slashing_evidence",
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
        )?;
        require_bps("penalty_bps", penalty_bps)?;
        let sequence = self.next_sequence();
        let evidence_id = route_id(
            "MONERO-SUBADDRESS-SLASHING-EVIDENCE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(accused_id),
                HashPart::Str(subject_id),
                HashPart::Str(evidence_root),
                HashPart::U64(sequence),
            ],
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            kind,
            accused_id: accused_id.to_string(),
            subject_id: subject_id.to_string(),
            evidence_root: evidence_root.to_string(),
            penalty_bps,
            pq_witness_root: pq_witness_root.to_string(),
            created_at_height: self.current_height,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        if let Some(maker) = self.liquidity_makers.get_mut(accused_id) {
            maker.status = MakerStatus::Slashed;
        }
        self.counters.slashing_evidence = self.counters.slashing_evidence.saturating_add(1);
        self.push_event(EventKind::SlashingSubmitted, &evidence_id, subject_id);
        Ok(evidence_id)
    }

    fn open_reorg_guard(
        &mut self,
        intent_id: &str,
        maker_id: &str,
        insurance_commitment: &str,
        watchtower_quorum_root: &str,
    ) -> Result<String> {
        self.ensure_len("reorg_guards", self.reorg_guards.len(), MAX_REORG_GUARDS)?;
        let sequence = self.next_sequence();
        let reorg_guard_id = route_id(
            "MONERO-SUBADDRESS-REORG-GUARD-ID",
            &[
                HashPart::Str(intent_id),
                HashPart::Str(maker_id),
                HashPart::Str(insurance_commitment),
                HashPart::U64(sequence),
            ],
        );
        let guard = ReorgGuard {
            reorg_guard_id: reorg_guard_id.clone(),
            intent_id: intent_id.to_string(),
            maker_id: maker_id.to_string(),
            status: ReorgGuardStatus::Active,
            protected_height: self.monero_height,
            finality_blocks: self.config.finality_blocks,
            insurance_commitment: insurance_commitment.to_string(),
            watchtower_quorum_root: watchtower_quorum_root.to_string(),
            created_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.reorg_ttl_blocks),
        };
        self.reorg_guards.insert(reorg_guard_id.clone(), guard);
        self.counters.reorg_guards = self.counters.reorg_guards.saturating_add(1);
        self.push_event(EventKind::ReorgGuardOpened, &reorg_guard_id, intent_id);
        Ok(reorg_guard_id)
    }

    fn ensure_len(&self, label: &str, len: usize, max: usize) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity exhausted"))
        } else {
            Ok(())
        }
    }

    fn ensure_fence_free(&self, nullifier: &str) -> Result<()> {
        if self
            .nullifier_fences
            .values()
            .any(|fence| fence.nullifier == nullifier)
        {
            Err("nullifier fence already exists".to_string())
        } else {
            Ok(())
        }
    }

    fn make_fence(
        &self,
        kind: FenceKind,
        subject_id: &str,
        nullifier: &str,
        domain: &str,
    ) -> NullifierFence {
        let fence_id = route_id(
            "MONERO-SUBADDRESS-NULLIFIER-FENCE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(nullifier),
                HashPart::Str(domain),
            ],
        );
        NullifierFence {
            fence_id,
            kind,
            subject_id: subject_id.to_string(),
            nullifier: nullifier.to_string(),
            domain: domain.to_string(),
            created_at_height: self.current_height,
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.counters.next_sequence;
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        sequence
    }

    fn push_event(&mut self, kind: EventKind, subject_id: &str, root: &str) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let sequence = self.next_sequence();
        let event_id = route_id(
            "MONERO-SUBADDRESS-RUNTIME-EVENT-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(root),
                HashPart::U64(sequence),
            ],
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            root: root.to_string(),
            height: self.current_height,
            sequence,
        };
        self.events.insert(event_id, event);
        self.counters.events = self.counters.events.saturating_add(1);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteIntentRequest {
    pub kind: RouteIntentKind,
    pub lane: RouteLane,
    pub owner_commitment: String,
    pub source_subaddress_commitment: String,
    pub destination_subaddress_commitment: String,
    pub amount_commitment: String,
    pub min_output_commitment: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub view_tag_bucket_commitment: String,
    pub scan_epoch: u64,
    pub bucket_size: u64,
    pub decoy_set_root: String,
    pub encrypted_hint_root: String,
    pub one_time_address_commitment: String,
    pub tx_public_key_commitment: String,
    pub subaddress_spend_key_commitment: String,
    pub range_proof_root: String,
    pub membership_proof_root: String,
    pub pq_auth_root: String,
    pub nullifier: String,
    pub pq_bridge_auth_root: String,
    pub route_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityQuoteRequest {
    pub maker_id: String,
    pub lane: RouteLane,
    pub asset_id: String,
    pub input_amount_commitment: String,
    pub output_amount_commitment: String,
    pub fee_bps: u64,
    pub priority_fee_commitment: String,
    pub reserve_attestation_id: String,
    pub private_defi_pool_root: String,
    pub route_hop_commitments: Vec<String>,
    pub min_privacy_set_size: u64,
    pub pq_quote_auth_root: String,
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "MONERO-SUBADDRESS-INTENT-LIQUIDITY-ROUTER-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_route_intent_id(request: &RouteIntentRequest, sequence: u64) -> String {
    route_id(
        "MONERO-SUBADDRESS-ROUTE-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.source_subaddress_commitment),
            HashPart::Str(&request.destination_subaddress_commitment),
            HashPart::Str(&request.amount_commitment),
            HashPart::Str(&request.nullifier),
            HashPart::U64(sequence),
        ],
    )
}

pub fn deterministic_quote_id(request: &LiquidityQuoteRequest, sequence: u64) -> String {
    route_id(
        "MONERO-SUBADDRESS-LIQUIDITY-QUOTE-ID",
        &[
            HashPart::Str(&request.maker_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.asset_id),
            HashPart::Str(&request.input_amount_commitment),
            HashPart::Str(&request.output_amount_commitment),
            HashPart::U64(sequence),
        ],
    )
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds maximum basis points"))
    } else {
        Ok(())
    }
}

fn route_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn deterministic_error_id(domain: &str, err: &str) -> String {
    domain_hash(domain, &[HashPart::Str(err)], 16)
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for RouteIntent {
    fn public_record(&self) -> Value {
        RouteIntent::public_record(self)
    }
}

impl PublicRecord for ViewTagHint {
    fn public_record(&self) -> Value {
        ViewTagHint::public_record(self)
    }
}

impl PublicRecord for StealthProofCommitment {
    fn public_record(&self) -> Value {
        StealthProofCommitment::public_record(self)
    }
}

impl PublicRecord for LiquidityMaker {
    fn public_record(&self) -> Value {
        LiquidityMaker::public_record(self)
    }
}

impl PublicRecord for LiquidityQuote {
    fn public_record(&self) -> Value {
        LiquidityQuote::public_record(self)
    }
}

impl PublicRecord for FastExitRoute {
    fn public_record(&self) -> Value {
        FastExitRoute::public_record(self)
    }
}

impl PublicRecord for AtomicSwapIntent {
    fn public_record(&self) -> Value {
        AtomicSwapIntent::public_record(self)
    }
}

impl PublicRecord for ReserveAttestation {
    fn public_record(&self) -> Value {
        ReserveAttestation::public_record(self)
    }
}

impl PublicRecord for FeeSponsorship {
    fn public_record(&self) -> Value {
        FeeSponsorship::public_record(self)
    }
}

impl PublicRecord for NullifierFence {
    fn public_record(&self) -> Value {
        NullifierFence::public_record(self)
    }
}

impl PublicRecord for ReorgGuard {
    fn public_record(&self) -> Value {
        ReorgGuard::public_record(self)
    }
}

impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

impl PublicRecord for SettlementBatch {
    fn public_record(&self) -> Value {
        SettlementBatch::public_record(self)
    }
}

impl PublicRecord for RuntimeEvent {
    fn public_record(&self) -> Value {
        RuntimeEvent::public_record(self)
    }
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let records = values
        .values()
        .map(PublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}
