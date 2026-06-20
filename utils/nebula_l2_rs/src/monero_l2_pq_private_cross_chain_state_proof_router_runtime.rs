use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_CROSS_CHAIN_STATE_PROOF_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-cross-chain-state-proof-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_CROSS_CHAIN_STATE_PROOF_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ROUTER_ID: &str = "monero-l2-pq-private-cross-chain-state-proof-router-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_536_240;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MONERO_HEADER_SCHEME: &str = "monero-compact-header-state-commitment-root-v1";
pub const MONERO_STATE_SCHEME: &str = "monero-private-state-witness-commitment-root-v1";
pub const PQ_COMMITTEE_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-cross-chain-state-proof-committee-root-v1";
pub const VIEWKEY_ROUTE_SCHEME: &str =
    "monero-selective-viewkey-cross-chain-disclosure-route-root-v1";
pub const STEALTH_PROOF_SCHEME: &str = "monero-stealth-address-state-proof-envelope-root-v1";
pub const RESERVE_QUEUE_SCHEME: &str = "monero-private-reserve-state-proof-queue-root-v1";
pub const EXIT_QUEUE_SCHEME: &str = "monero-private-fast-exit-state-proof-queue-root-v1";
pub const FAST_EXIT_LIQUIDITY_SCHEME: &str =
    "pq-private-cross-chain-fast-exit-liquidity-route-root-v1";
pub const REORG_FENCE_SCHEME: &str = "monero-cross-chain-reorg-fence-root-v1";
pub const LOW_FEE_AGGREGATION_SCHEME: &str = "low-fee-recursive-state-proof-aggregation-root-v1";
pub const PRIVACY_NULLIFIER_SCHEME: &str = "monero-private-cross-chain-nullifier-fence-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "robust-cross-chain-proof-settlement-receipt-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-private-cross-chain-state-proof-router-slashing-evidence-root-v1";
pub const REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-cross-chain-state-proof-router-runtime-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_FINALITY_DEPTH: u64 = 20;
pub const DEFAULT_REORG_FENCE_BLOCKS: u64 = 72;
pub const DEFAULT_HEADER_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_STATE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_RESERVE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_EXIT_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_AGGREGATION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_VIEWTAG_BUCKET_SIZE: u64 = 4_096;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 16;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 7;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRICT_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_FAST_EXIT_COVERAGE_BPS: u64 = 11_500;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_STANDARD_FEE_BPS: u64 = 8;
pub const DEFAULT_FAST_EXIT_FEE_BPS: u64 = 14;
pub const DEFAULT_EMERGENCY_FEE_BPS: u64 = 25;
pub const DEFAULT_AGGREGATION_REBATE_BPS: u64 = 4;
pub const DEFAULT_SLASH_INVALID_PROOF_BPS: u64 = 3_000;
pub const DEFAULT_SLASH_DOUBLE_ROUTE_BPS: u64 = 2_500;
pub const DEFAULT_SLASH_STALE_HEADER_BPS: u64 = 900;
pub const DEFAULT_SLASH_PRIVACY_LEAK_BPS: u64 = 4_000;
pub const DEFAULT_SLASH_LIQUIDITY_DEFAULT_BPS: u64 = 2_000;
pub const DEFAULT_MAX_AGGREGATION_ITEMS: usize = 768;
pub const MAX_HEADER_COMMITMENTS: usize = 4_194_304;
pub const MAX_STATE_COMMITMENTS: usize = 4_194_304;
pub const MAX_COMMITTEE_ATTESTATIONS: usize = 8_388_608;
pub const MAX_VIEWKEY_ROUTES: usize = 2_097_152;
pub const MAX_STEALTH_ENVELOPES: usize = 4_194_304;
pub const MAX_RESERVE_QUEUE_ITEMS: usize = 2_097_152;
pub const MAX_EXIT_QUEUE_ITEMS: usize = 4_194_304;
pub const MAX_LIQUIDITY_ROUTES: usize = 2_097_152;
pub const MAX_REORG_FENCES: usize = 1_048_576;
pub const MAX_AGGREGATION_BATCHES: usize = 1_048_576;
pub const MAX_NULLIFIER_FENCES: usize = 8_388_608;
pub const MAX_SETTLEMENT_RECEIPTS: usize = 4_194_304;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
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

snake_enum!(ChainKind {
    Monero => "monero",
    NebulaL2 => "nebula_l2",
    Bitcoin => "bitcoin",
    Ethereum => "ethereum",
    Appchain => "appchain",
    EmergencyMirror => "emergency_mirror"
});

snake_enum!(ProofDirection {
    MoneroToL2 => "monero_to_l2",
    L2ToMonero => "l2_to_monero",
    CrossRollup => "cross_rollup",
    ReserveMirror => "reserve_mirror",
    FastExit => "fast_exit",
    EmergencyEscape => "emergency_escape"
});

snake_enum!(DisclosureScope {
    ViewTagsOnly => "view_tags_only",
    OutputMembership => "output_membership",
    KeyImageSpentness => "key_image_spentness",
    ReserveBalance => "reserve_balance",
    SubaddressWindow => "subaddress_window",
    TxPrefixWindow => "tx_prefix_window",
    SettlementReceipt => "settlement_receipt",
    EmergencyAudit => "emergency_audit"
});

snake_enum!(RouteLane {
    LowFee => "low_fee",
    Standard => "standard",
    FastExit => "fast_exit",
    ReserveProof => "reserve_proof",
    Aggregated => "aggregated",
    Emergency => "emergency"
});

impl RouteLane {
    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::Aggregated => config.low_fee_bps,
            Self::Standard | Self::ReserveProof => config.standard_fee_bps,
            Self::FastExit => config.fast_exit_fee_bps,
            Self::Emergency => config.emergency_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::FastExit => 940,
            Self::ReserveProof => 900,
            Self::Aggregated => 820,
            Self::Standard => 760,
            Self::LowFee => 680,
        }
    }
}

snake_enum!(CommitmentStatus {
    Observed => "observed",
    QuorumAttested => "quorum_attested",
    Canonical => "canonical",
    Superseded => "superseded",
    ReorgFenced => "reorg_fenced",
    Rejected => "rejected"
});

impl CommitmentStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::QuorumAttested | Self::Canonical)
    }
}

snake_enum!(AttestationStatus {
    Submitted => "submitted",
    Accepted => "accepted",
    WeakQuorum => "weak_quorum",
    Superseded => "superseded",
    Rejected => "rejected",
    Slashed => "slashed"
});

snake_enum!(RouteStatus {
    Drafted => "drafted",
    Active => "active",
    Bound => "bound",
    Aggregated => "aggregated",
    Settling => "settling",
    Settled => "settled",
    Expired => "expired",
    Revoked => "revoked",
    Slashed => "slashed"
});

impl RouteStatus {
    pub fn routable(self) -> bool {
        matches!(self, Self::Active | Self::Bound | Self::Aggregated)
    }
}

snake_enum!(ProofEnvelopeStatus {
    Sealed => "sealed",
    Routed => "routed",
    ReserveQueued => "reserve_queued",
    ExitQueued => "exit_queued",
    Aggregated => "aggregated",
    Settling => "settling",
    Settled => "settled",
    ReorgFenced => "reorg_fenced",
    Rejected => "rejected",
    Slashed => "slashed"
});

impl ProofEnvelopeStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::Routed
                | Self::ReserveQueued
                | Self::ExitQueued
                | Self::Aggregated
                | Self::Settling
        )
    }
}

snake_enum!(QueueKind {
    Reserve => "reserve",
    Exit => "exit",
    FastExit => "fast_exit",
    LowFeeAggregate => "low_fee_aggregate",
    Emergency => "emergency"
});

snake_enum!(QueueStatus {
    Queued => "queued",
    Matched => "matched",
    Aggregated => "aggregated",
    Settling => "settling",
    Settled => "settled",
    Expired => "expired",
    Cancelled => "cancelled",
    Slashed => "slashed"
});

snake_enum!(LiquidityRouteStatus {
    Posted => "posted",
    Bound => "bound",
    Locked => "locked",
    Settling => "settling",
    Filled => "filled",
    Expired => "expired",
    Cancelled => "cancelled",
    Slashed => "slashed"
});

impl LiquidityRouteStatus {
    pub fn bindable(self) -> bool {
        matches!(self, Self::Posted | Self::Bound)
    }
}

snake_enum!(ReorgFenceStatus {
    Watching => "watching",
    Quarantined => "quarantined",
    Released => "released",
    Triggered => "triggered",
    Expired => "expired"
});

snake_enum!(AggregationStatus {
    Open => "open",
    Sealed => "sealed",
    Attested => "attested",
    Submitted => "submitted",
    Settled => "settled",
    Rejected => "rejected",
    Slashed => "slashed"
});

snake_enum!(NullifierFenceKind {
    OutputCommitment => "output_commitment",
    KeyImage => "key_image",
    ViewTagBucket => "view_tag_bucket",
    SubaddressRoute => "subaddress_route",
    StealthAddress => "stealth_address",
    ProofReplay => "proof_replay",
    SettlementReplay => "settlement_replay",
    LiquidityReservation => "liquidity_reservation"
});

snake_enum!(SettlementStatus {
    Submitted => "submitted",
    FastConfirmed => "fast_confirmed",
    Finalized => "finalized",
    Reorged => "reorged",
    Disputed => "disputed",
    Rejected => "rejected",
    Slashed => "slashed"
});

snake_enum!(SlashingReason {
    InvalidProof => "invalid_proof",
    DoubleRoute => "double_route",
    StaleHeader => "stale_header",
    PrivacyLeak => "privacy_leak",
    LiquidityDefault => "liquidity_default",
    FalseQuorum => "false_quorum",
    ReorgSuppression => "reorg_suppression"
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub router_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub finality_depth: u64,
    pub reorg_fence_blocks: u64,
    pub header_ttl_blocks: u64,
    pub state_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub reserve_ttl_blocks: u64,
    pub exit_ttl_blocks: u64,
    pub aggregation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_viewtag_bucket_size: u64,
    pub min_decoy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_committee_weight: u64,
    pub committee_quorum_bps: u64,
    pub strict_quorum_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub fast_exit_coverage_bps: u64,
    pub low_fee_bps: u64,
    pub standard_fee_bps: u64,
    pub fast_exit_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub aggregation_rebate_bps: u64,
    pub slash_invalid_proof_bps: u64,
    pub slash_double_route_bps: u64,
    pub slash_stale_header_bps: u64,
    pub slash_privacy_leak_bps: u64,
    pub slash_liquidity_default_bps: u64,
    pub max_aggregation_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            finality_depth: DEFAULT_FINALITY_DEPTH,
            reorg_fence_blocks: DEFAULT_REORG_FENCE_BLOCKS,
            header_ttl_blocks: DEFAULT_HEADER_TTL_BLOCKS,
            state_ttl_blocks: DEFAULT_STATE_TTL_BLOCKS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            reserve_ttl_blocks: DEFAULT_RESERVE_TTL_BLOCKS,
            exit_ttl_blocks: DEFAULT_EXIT_TTL_BLOCKS,
            aggregation_ttl_blocks: DEFAULT_AGGREGATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_viewtag_bucket_size: DEFAULT_MIN_VIEWTAG_BUCKET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_weight: DEFAULT_MIN_COMMITTEE_WEIGHT,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            strict_quorum_bps: DEFAULT_STRICT_QUORUM_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            fast_exit_coverage_bps: DEFAULT_FAST_EXIT_COVERAGE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            standard_fee_bps: DEFAULT_STANDARD_FEE_BPS,
            fast_exit_fee_bps: DEFAULT_FAST_EXIT_FEE_BPS,
            emergency_fee_bps: DEFAULT_EMERGENCY_FEE_BPS,
            aggregation_rebate_bps: DEFAULT_AGGREGATION_REBATE_BPS,
            slash_invalid_proof_bps: DEFAULT_SLASH_INVALID_PROOF_BPS,
            slash_double_route_bps: DEFAULT_SLASH_DOUBLE_ROUTE_BPS,
            slash_stale_header_bps: DEFAULT_SLASH_STALE_HEADER_BPS,
            slash_privacy_leak_bps: DEFAULT_SLASH_PRIVACY_LEAK_BPS,
            slash_liquidity_default_bps: DEFAULT_SLASH_LIQUIDITY_DEFAULT_BPS,
            max_aggregation_items: DEFAULT_MAX_AGGREGATION_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "router_id": self.router_id,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "finality_depth": self.finality_depth,
            "reorg_fence_blocks": self.reorg_fence_blocks,
            "header_ttl_blocks": self.header_ttl_blocks,
            "state_ttl_blocks": self.state_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "reserve_ttl_blocks": self.reserve_ttl_blocks,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "aggregation_ttl_blocks": self.aggregation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_viewtag_bucket_size": self.min_viewtag_bucket_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_committee_weight": self.min_committee_weight,
            "committee_quorum_bps": self.committee_quorum_bps,
            "strict_quorum_bps": self.strict_quorum_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "fast_exit_coverage_bps": self.fast_exit_coverage_bps,
            "low_fee_bps": self.low_fee_bps,
            "standard_fee_bps": self.standard_fee_bps,
            "fast_exit_fee_bps": self.fast_exit_fee_bps,
            "emergency_fee_bps": self.emergency_fee_bps,
            "aggregation_rebate_bps": self.aggregation_rebate_bps,
            "slash_invalid_proof_bps": self.slash_invalid_proof_bps,
            "slash_double_route_bps": self.slash_double_route_bps,
            "slash_stale_header_bps": self.slash_stale_header_bps,
            "slash_privacy_leak_bps": self.slash_privacy_leak_bps,
            "slash_liquidity_default_bps": self.slash_liquidity_default_bps,
            "max_aggregation_items": self.max_aggregation_items
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub header_commitments: u64,
    pub state_commitments: u64,
    pub committee_attestations: u64,
    pub viewkey_routes: u64,
    pub stealth_envelopes: u64,
    pub reserve_queue_items: u64,
    pub exit_queue_items: u64,
    pub liquidity_routes: u64,
    pub reorg_fences: u64,
    pub aggregation_batches: u64,
    pub nullifier_fences: u64,
    pub settlement_receipts: u64,
    pub slashing_evidence: u64,
    pub events: u64,
    pub last_height: u64,
}

impl Counters {
    pub fn new(height: u64) -> Self {
        Self {
            header_commitments: 0,
            state_commitments: 0,
            committee_attestations: 0,
            viewkey_routes: 0,
            stealth_envelopes: 0,
            reserve_queue_items: 0,
            exit_queue_items: 0,
            liquidity_routes: 0,
            reorg_fences: 0,
            aggregation_batches: 0,
            nullifier_fences: 0,
            settlement_receipts: 0,
            slashing_evidence: 0,
            events: 0,
            last_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "header_commitments": self.header_commitments,
            "state_commitments": self.state_commitments,
            "committee_attestations": self.committee_attestations,
            "viewkey_routes": self.viewkey_routes,
            "stealth_envelopes": self.stealth_envelopes,
            "reserve_queue_items": self.reserve_queue_items,
            "exit_queue_items": self.exit_queue_items,
            "liquidity_routes": self.liquidity_routes,
            "reorg_fences": self.reorg_fences,
            "aggregation_batches": self.aggregation_batches,
            "nullifier_fences": self.nullifier_fences,
            "settlement_receipts": self.settlement_receipts,
            "slashing_evidence": self.slashing_evidence,
            "events": self.events,
            "last_height": self.last_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub header_commitment_root: String,
    pub state_commitment_root: String,
    pub committee_attestation_root: String,
    pub viewkey_route_root: String,
    pub stealth_envelope_root: String,
    pub reserve_queue_root: String,
    pub exit_queue_root: String,
    pub liquidity_route_root: String,
    pub reorg_fence_root: String,
    pub aggregation_batch_root: String,
    pub nullifier_fence_root: String,
    pub settlement_receipt_root: String,
    pub slashing_evidence_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "header_commitment_root": self.header_commitment_root,
            "state_commitment_root": self.state_commitment_root,
            "committee_attestation_root": self.committee_attestation_root,
            "viewkey_route_root": self.viewkey_route_root,
            "stealth_envelope_root": self.stealth_envelope_root,
            "reserve_queue_root": self.reserve_queue_root,
            "exit_queue_root": self.exit_queue_root,
            "liquidity_route_root": self.liquidity_route_root,
            "reorg_fence_root": self.reorg_fence_root,
            "aggregation_batch_root": self.aggregation_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "event_root": self.event_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroHeaderCommitment {
    pub header_id: String,
    pub monero_network: String,
    pub height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub tx_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub view_tag_root: String,
    pub cumulative_difficulty_commitment: String,
    pub median_weight: u64,
    pub observed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: CommitmentStatus,
}

impl MoneroHeaderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "header_id": self.header_id,
            "monero_network": self.monero_network,
            "height": self.height,
            "block_hash": self.block_hash,
            "previous_block_hash": self.previous_block_hash,
            "tx_root": self.tx_root,
            "output_root": self.output_root,
            "key_image_root": self.key_image_root,
            "view_tag_root": self.view_tag_root,
            "cumulative_difficulty_commitment": self.cumulative_difficulty_commitment,
            "median_weight": self.median_weight,
            "observed_at_l2_height": self.observed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
            "scheme": MONERO_HEADER_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("MONERO-HEADER-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroStateCommitment {
    pub state_id: String,
    pub header_id: String,
    pub chain: ChainKind,
    pub height: u64,
    pub state_kind: DisclosureScope,
    pub commitment_root: String,
    pub witness_root: String,
    pub output_range_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub viewtag_bucket_size: u64,
    pub decoy_set_size: u64,
    pub observed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: CommitmentStatus,
}

impl MoneroStateCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "state_id": self.state_id,
            "header_id": self.header_id,
            "chain": self.chain.as_str(),
            "height": self.height,
            "state_kind": self.state_kind.as_str(),
            "commitment_root": self.commitment_root,
            "witness_root": self.witness_root,
            "output_range_root": self.output_range_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "viewtag_bucket_size": self.viewtag_bucket_size,
            "decoy_set_size": self.decoy_set_size,
            "observed_at_l2_height": self.observed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
            "scheme": MONERO_STATE_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("MONERO-STATE-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub committee_id: String,
    pub attestation_kind: DisclosureScope,
    pub pq_scheme: String,
    pub aggregate_public_key_root: String,
    pub signature_root: String,
    pub signer_bitmap_root: String,
    pub committee_weight: u64,
    pub signed_weight: u64,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: AttestationStatus,
}

impl PqCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "committee_id": self.committee_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "pq_scheme": self.pq_scheme,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "signature_root": self.signature_root,
            "signer_bitmap_root": self.signer_bitmap_root,
            "committee_weight": self.committee_weight,
            "signed_weight": self.signed_weight,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_l2_height": self.attested_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
            "scheme": PQ_COMMITTEE_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("PQ-COMMITTEE-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyDisclosureRoute {
    pub route_id: String,
    pub owner_commitment: String,
    pub auditor_committee_id: String,
    pub disclosure_scope: DisclosureScope,
    pub lane: RouteLane,
    pub encrypted_viewkey_share_root: String,
    pub selective_disclosure_policy_root: String,
    pub redaction_root: String,
    pub viewtag_bucket_root: String,
    pub allowed_chain_root: String,
    pub fee_bps: u64,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: RouteStatus,
}

impl ViewKeyDisclosureRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "owner_commitment": self.owner_commitment,
            "auditor_committee_id": self.auditor_committee_id,
            "disclosure_scope": self.disclosure_scope.as_str(),
            "lane": self.lane.as_str(),
            "encrypted_viewkey_share_root": self.encrypted_viewkey_share_root,
            "selective_disclosure_policy_root": self.selective_disclosure_policy_root,
            "redaction_root": self.redaction_root,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "allowed_chain_root": self.allowed_chain_root,
            "fee_bps": self.fee_bps,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
            "scheme": VIEWKEY_ROUTE_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("VIEWKEY-DISCLOSURE-ROUTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthAddressProofEnvelope {
    pub envelope_id: String,
    pub route_id: String,
    pub state_id: String,
    pub direction: ProofDirection,
    pub lane: RouteLane,
    pub stealth_address_commitment: String,
    pub one_time_key_root: String,
    pub tx_prefix_hash: String,
    pub output_membership_root: String,
    pub range_proof_commitment: String,
    pub encrypted_payload_root: String,
    pub nullifier: String,
    pub requested_amount_commitment: String,
    pub fee_commitment: String,
    pub privacy_set_size: u64,
    pub priority_score: u64,
    pub submitted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: ProofEnvelopeStatus,
}

impl StealthAddressProofEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "route_id": self.route_id,
            "state_id": self.state_id,
            "direction": self.direction.as_str(),
            "lane": self.lane.as_str(),
            "stealth_address_commitment": self.stealth_address_commitment,
            "one_time_key_root": self.one_time_key_root,
            "tx_prefix_hash": self.tx_prefix_hash,
            "output_membership_root": self.output_membership_root,
            "range_proof_commitment": self.range_proof_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier": self.nullifier,
            "requested_amount_commitment": self.requested_amount_commitment,
            "fee_commitment": self.fee_commitment,
            "privacy_set_size": self.privacy_set_size,
            "priority_score": self.priority_score,
            "submitted_at_l2_height": self.submitted_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
            "scheme": STEALTH_PROOF_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("STEALTH-ADDRESS-PROOF-ENVELOPE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofQueueItem {
    pub queue_id: String,
    pub envelope_id: String,
    pub queue_kind: QueueKind,
    pub route_id: String,
    pub target_chain: ChainKind,
    pub amount_commitment: String,
    pub reserve_requirement_commitment: String,
    pub fee_commitment: String,
    pub priority_score: u64,
    pub privacy_score: u64,
    pub queued_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub matched_liquidity_route_id: Option<String>,
    pub aggregation_batch_id: Option<String>,
    pub status: QueueStatus,
}

impl ProofQueueItem {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "envelope_id": self.envelope_id,
            "queue_kind": self.queue_kind.as_str(),
            "route_id": self.route_id,
            "target_chain": self.target_chain.as_str(),
            "amount_commitment": self.amount_commitment,
            "reserve_requirement_commitment": self.reserve_requirement_commitment,
            "fee_commitment": self.fee_commitment,
            "priority_score": self.priority_score,
            "privacy_score": self.privacy_score,
            "queued_at_l2_height": self.queued_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "matched_liquidity_route_id": self.matched_liquidity_route_id,
            "aggregation_batch_id": self.aggregation_batch_id,
            "status": self.status.as_str(),
            "reserve_scheme": RESERVE_QUEUE_SCHEME,
            "exit_scheme": EXIT_QUEUE_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("PROOF-QUEUE-ITEM", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastExitLiquidityRoute {
    pub liquidity_route_id: String,
    pub provider_id: String,
    pub source_chain: ChainKind,
    pub target_chain: ChainKind,
    pub reserve_commitment_root: String,
    pub capacity_commitment: String,
    pub filled_commitment: String,
    pub max_fee_bps: u64,
    pub coverage_bps: u64,
    pub pq_attestation_id: String,
    pub settlement_address_commitment: String,
    pub refund_address_commitment: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub bound_queue_ids: BTreeSet<String>,
    pub status: LiquidityRouteStatus,
}

impl FastExitLiquidityRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidity_route_id": self.liquidity_route_id,
            "provider_id": self.provider_id,
            "source_chain": self.source_chain.as_str(),
            "target_chain": self.target_chain.as_str(),
            "reserve_commitment_root": self.reserve_commitment_root,
            "capacity_commitment": self.capacity_commitment,
            "filled_commitment": self.filled_commitment,
            "max_fee_bps": self.max_fee_bps,
            "coverage_bps": self.coverage_bps,
            "pq_attestation_id": self.pq_attestation_id,
            "settlement_address_commitment": self.settlement_address_commitment,
            "refund_address_commitment": self.refund_address_commitment,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "bound_queue_ids": self.bound_queue_ids,
            "status": self.status.as_str(),
            "scheme": FAST_EXIT_LIQUIDITY_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("FAST-EXIT-LIQUIDITY-ROUTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgFence {
    pub fence_id: String,
    pub header_id: String,
    pub chain: ChainKind,
    pub watched_height: u64,
    pub canonical_block_hash: String,
    pub competing_block_hash_root: String,
    pub quarantine_root: String,
    pub protected_envelope_root: String,
    pub watcher_attestation_root: String,
    pub opened_at_l2_height: u64,
    pub release_after_l2_height: u64,
    pub status: ReorgFenceStatus,
}

impl ReorgFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "header_id": self.header_id,
            "chain": self.chain.as_str(),
            "watched_height": self.watched_height,
            "canonical_block_hash": self.canonical_block_hash,
            "competing_block_hash_root": self.competing_block_hash_root,
            "quarantine_root": self.quarantine_root,
            "protected_envelope_root": self.protected_envelope_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "opened_at_l2_height": self.opened_at_l2_height,
            "release_after_l2_height": self.release_after_l2_height,
            "status": self.status.as_str(),
            "scheme": REORG_FENCE_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("REORG-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAggregationBatch {
    pub batch_id: String,
    pub aggregator_id: String,
    pub lane: RouteLane,
    pub queue_ids: BTreeSet<String>,
    pub envelope_root: String,
    pub recursive_proof_root: String,
    pub fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub pq_attestation_id: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: AggregationStatus,
}

impl LowFeeAggregationBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "aggregator_id": self.aggregator_id,
            "lane": self.lane.as_str(),
            "queue_ids": self.queue_ids,
            "envelope_root": self.envelope_root,
            "recursive_proof_root": self.recursive_proof_root,
            "fee_commitment_root": self.fee_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "pq_attestation_id": self.pq_attestation_id,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
            "scheme": LOW_FEE_AGGREGATION_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("LOW-FEE-AGGREGATION-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub nullifier_id: String,
    pub nullifier: String,
    pub kind: NullifierFenceKind,
    pub route_id: String,
    pub envelope_id: Option<String>,
    pub chain: ChainKind,
    pub privacy_set_root: String,
    pub bound_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub active: bool,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "nullifier": self.nullifier,
            "kind": self.kind.as_str(),
            "route_id": self.route_id,
            "envelope_id": self.envelope_id,
            "chain": self.chain.as_str(),
            "privacy_set_root": self.privacy_set_root,
            "bound_at_l2_height": self.bound_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "active": self.active,
            "scheme": PRIVACY_NULLIFIER_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("PRIVACY-NULLIFIER-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub envelope_id: String,
    pub route_id: String,
    pub batch_id: Option<String>,
    pub liquidity_route_id: Option<String>,
    pub settled_chain: ChainKind,
    pub settlement_tx_commitment: String,
    pub finality_header_id: String,
    pub finality_height: u64,
    pub confirmation_depth: u64,
    pub settlement_proof_root: String,
    pub fee_paid_commitment: String,
    pub settled_at_l2_height: u64,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "envelope_id": self.envelope_id,
            "route_id": self.route_id,
            "batch_id": self.batch_id,
            "liquidity_route_id": self.liquidity_route_id,
            "settled_chain": self.settled_chain.as_str(),
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "finality_header_id": self.finality_header_id,
            "finality_height": self.finality_height,
            "confirmation_depth": self.confirmation_depth,
            "settlement_proof_root": self.settlement_proof_root,
            "fee_paid_commitment": self.fee_paid_commitment,
            "settled_at_l2_height": self.settled_at_l2_height,
            "status": self.status.as_str(),
            "scheme": SETTLEMENT_RECEIPT_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub subject_id: String,
    pub router_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub conflicting_record_root: String,
    pub protected_privacy_root: String,
    pub slash_bps: u64,
    pub reporter_id: String,
    pub reported_at_l2_height: u64,
    pub adjudication_root: String,
    pub applied: bool,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "subject_id": self.subject_id,
            "router_id": self.router_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "conflicting_record_root": self.conflicting_record_root,
            "protected_privacy_root": self.protected_privacy_root,
            "slash_bps": self.slash_bps,
            "reporter_id": self.reporter_id,
            "reported_at_l2_height": self.reported_at_l2_height,
            "adjudication_root": self.adjudication_root,
            "applied": self.applied,
            "scheme": SLASHING_EVIDENCE_SCHEME
        })
    }

    pub fn root(&self) -> String {
        record_root("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub record_root: String,
}

impl RouterEvent {
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
    pub header_commitments: BTreeMap<String, MoneroHeaderCommitment>,
    pub state_commitments: BTreeMap<String, MoneroStateCommitment>,
    pub committee_attestations: BTreeMap<String, PqCommitteeAttestation>,
    pub viewkey_routes: BTreeMap<String, ViewKeyDisclosureRoute>,
    pub stealth_envelopes: BTreeMap<String, StealthAddressProofEnvelope>,
    pub reserve_queue: BTreeMap<String, ProofQueueItem>,
    pub exit_queue: BTreeMap<String, ProofQueueItem>,
    pub liquidity_routes: BTreeMap<String, FastExitLiquidityRoute>,
    pub reorg_fences: BTreeMap<String, ReorgFence>,
    pub aggregation_batches: BTreeMap<String, LowFeeAggregationBatch>,
    pub nullifier_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RouterEvent>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        Self {
            config,
            counters: Counters::new(height),
            header_commitments: BTreeMap::new(),
            state_commitments: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            viewkey_routes: BTreeMap::new(),
            stealth_envelopes: BTreeMap::new(),
            reserve_queue: BTreeMap::new(),
            exit_queue: BTreeMap::new(),
            liquidity_routes: BTreeMap::new(),
            reorg_fences: BTreeMap::new(),
            aggregation_batches: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        let header_id = state
            .register_header_commitment(HeaderCommitmentInput {
                height: DEVNET_HEIGHT,
                block_hash: deterministic_id("DEVNET-MONERO-BLOCK", &["tip"]),
                previous_block_hash: deterministic_id("DEVNET-MONERO-BLOCK", &["parent"]),
                tx_root: deterministic_id("DEVNET-MONERO-TX-ROOT", &["tip"]),
                output_root: deterministic_id("DEVNET-MONERO-OUTPUT-ROOT", &["tip"]),
                key_image_root: deterministic_id("DEVNET-MONERO-KEY-IMAGE-ROOT", &["tip"]),
                view_tag_root: deterministic_id("DEVNET-MONERO-VIEW-TAG-ROOT", &["tip"]),
                cumulative_difficulty_commitment: deterministic_id(
                    "DEVNET-MONERO-DIFFICULTY",
                    &["tip"],
                ),
                median_weight: 300_000,
                observed_at_l2_height: DEVNET_HEIGHT,
            })
            .unwrap_or_else(|err| err);
        let state_id = state
            .register_state_commitment(StateCommitmentInput {
                header_id: header_id.clone(),
                chain: ChainKind::Monero,
                height: DEVNET_HEIGHT,
                state_kind: DisclosureScope::OutputMembership,
                commitment_root: deterministic_id("DEVNET-STATE-COMMITMENT", &["outputs"]),
                witness_root: deterministic_id("DEVNET-STATE-WITNESS", &["outputs"]),
                output_range_root: deterministic_id("DEVNET-OUTPUT-RANGE", &["outputs"]),
                nullifier_root: deterministic_id("DEVNET-NULLIFIER-ROOT", &["outputs"]),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
                viewtag_bucket_size: DEFAULT_MIN_VIEWTAG_BUCKET_SIZE.saturating_mul(2),
                decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE.saturating_mul(2),
                observed_at_l2_height: DEVNET_HEIGHT,
            })
            .unwrap_or_else(|err| err);
        let attestation_id = state
            .submit_committee_attestation(CommitteeAttestationInput {
                subject_id: state_id.clone(),
                committee_id: "devnet-pq-state-proof-committee".to_string(),
                attestation_kind: DisclosureScope::OutputMembership,
                aggregate_public_key_root: deterministic_id("DEVNET-PQ-COMMITTEE-KEY", &["state"]),
                signature_root: deterministic_id("DEVNET-PQ-COMMITTEE-SIGNATURE", &["state"]),
                signer_bitmap_root: deterministic_id("DEVNET-PQ-COMMITTEE-BITMAP", &["state"]),
                committee_weight: 10,
                signed_weight: 8,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                attested_at_l2_height: DEVNET_HEIGHT + 1,
            })
            .unwrap_or_else(|err| err);
        let route_id = state
            .open_viewkey_route(ViewKeyRouteInput {
                owner_commitment: deterministic_id("DEVNET-OWNER-COMMITMENT", &["alice"]),
                auditor_committee_id: "devnet-pq-state-proof-committee".to_string(),
                disclosure_scope: DisclosureScope::OutputMembership,
                lane: RouteLane::LowFee,
                encrypted_viewkey_share_root: deterministic_id("DEVNET-VIEWKEY-SHARE", &["alice"]),
                selective_disclosure_policy_root: deterministic_id(
                    "DEVNET-DISCLOSURE-POLICY",
                    &["outputs"],
                ),
                redaction_root: deterministic_id("DEVNET-REDACTION-ROOT", &["outputs"]),
                viewtag_bucket_root: deterministic_id("DEVNET-VIEWTAG-BUCKET", &["outputs"]),
                allowed_chain_root: deterministic_id("DEVNET-ALLOWED-CHAINS", &["monero", "l2"]),
                opened_at_l2_height: DEVNET_HEIGHT + 2,
            })
            .unwrap_or_else(|err| err);
        let envelope_id = state
            .route_proof_envelope(ProofEnvelopeInput {
                route_id: route_id.clone(),
                state_id: state_id.clone(),
                direction: ProofDirection::MoneroToL2,
                lane: RouteLane::FastExit,
                stealth_address_commitment: deterministic_id("DEVNET-STEALTH-ADDRESS", &["exit"]),
                one_time_key_root: deterministic_id("DEVNET-ONE-TIME-KEY", &["exit"]),
                tx_prefix_hash: deterministic_id("DEVNET-TX-PREFIX", &["exit"]),
                output_membership_root: deterministic_id("DEVNET-OUTPUT-MEMBERSHIP", &["exit"]),
                range_proof_commitment: deterministic_id("DEVNET-RANGE-PROOF", &["exit"]),
                encrypted_payload_root: deterministic_id("DEVNET-ENCRYPTED-PAYLOAD", &["exit"]),
                nullifier: deterministic_id("DEVNET-NULLIFIER", &["exit"]),
                requested_amount_commitment: deterministic_id("DEVNET-AMOUNT", &["exit"]),
                fee_commitment: deterministic_id("DEVNET-FEE", &["exit"]),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
                submitted_at_l2_height: DEVNET_HEIGHT + 3,
            })
            .unwrap_or_else(|err| err);
        let queue_id = state
            .enqueue_exit_proof(&envelope_id, ChainKind::NebulaL2, DEVNET_HEIGHT + 4)
            .unwrap_or_else(|err| err);
        let liquidity_route_id = state
            .post_fast_exit_liquidity(FastExitLiquidityInput {
                provider_id: "devnet-liquidity-maker-0".to_string(),
                source_chain: ChainKind::Monero,
                target_chain: ChainKind::NebulaL2,
                reserve_commitment_root: deterministic_id("DEVNET-LIQUIDITY-RESERVE", &["maker-0"]),
                capacity_commitment: deterministic_id("DEVNET-LIQUIDITY-CAPACITY", &["maker-0"]),
                max_fee_bps: DEFAULT_FAST_EXIT_FEE_BPS,
                coverage_bps: DEFAULT_FAST_EXIT_COVERAGE_BPS,
                pq_attestation_id: attestation_id.clone(),
                settlement_address_commitment: deterministic_id(
                    "DEVNET-SETTLEMENT-ADDRESS",
                    &["maker-0"],
                ),
                refund_address_commitment: deterministic_id("DEVNET-REFUND-ADDRESS", &["maker-0"]),
                opened_at_l2_height: DEVNET_HEIGHT + 4,
            })
            .unwrap_or_else(|err| err);
        let _ = state.bind_fast_exit_liquidity(&queue_id, &liquidity_route_id, DEVNET_HEIGHT + 5);
        let _ = state.open_low_fee_aggregation(
            "devnet-proof-aggregator-0",
            vec![queue_id.clone()],
            attestation_id.clone(),
            DEVNET_HEIGHT + 6,
        );
        let _ = state.settle_cross_chain_proof(SettlementInput {
            envelope_id,
            settlement_tx_commitment: deterministic_id("DEVNET-SETTLEMENT-TX", &["exit"]),
            finality_header_id: header_id,
            finality_height: DEVNET_HEIGHT + DEFAULT_FINALITY_DEPTH,
            confirmation_depth: DEFAULT_FINALITY_DEPTH,
            settlement_proof_root: deterministic_id("DEVNET-SETTLEMENT-PROOF", &["exit"]),
            fee_paid_commitment: deterministic_id("DEVNET-FEE-PAID", &["exit"]),
            settled_chain: ChainKind::NebulaL2,
            settled_at_l2_height: DEVNET_HEIGHT + 24,
        });
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            header_commitment_root: merkle_from_records(
                "HEADER-COMMITMENTS",
                self.header_commitments
                    .values()
                    .map(MoneroHeaderCommitment::public_record)
                    .collect(),
            ),
            state_commitment_root: merkle_from_records(
                "STATE-COMMITMENTS",
                self.state_commitments
                    .values()
                    .map(MoneroStateCommitment::public_record)
                    .collect(),
            ),
            committee_attestation_root: merkle_from_records(
                "COMMITTEE-ATTESTATIONS",
                self.committee_attestations
                    .values()
                    .map(PqCommitteeAttestation::public_record)
                    .collect(),
            ),
            viewkey_route_root: merkle_from_records(
                "VIEWKEY-ROUTES",
                self.viewkey_routes
                    .values()
                    .map(ViewKeyDisclosureRoute::public_record)
                    .collect(),
            ),
            stealth_envelope_root: merkle_from_records(
                "STEALTH-ENVELOPES",
                self.stealth_envelopes
                    .values()
                    .map(StealthAddressProofEnvelope::public_record)
                    .collect(),
            ),
            reserve_queue_root: merkle_from_records(
                "RESERVE-QUEUE",
                self.reserve_queue
                    .values()
                    .map(ProofQueueItem::public_record)
                    .collect(),
            ),
            exit_queue_root: merkle_from_records(
                "EXIT-QUEUE",
                self.exit_queue
                    .values()
                    .map(ProofQueueItem::public_record)
                    .collect(),
            ),
            liquidity_route_root: merkle_from_records(
                "LIQUIDITY-ROUTES",
                self.liquidity_routes
                    .values()
                    .map(FastExitLiquidityRoute::public_record)
                    .collect(),
            ),
            reorg_fence_root: merkle_from_records(
                "REORG-FENCES",
                self.reorg_fences
                    .values()
                    .map(ReorgFence::public_record)
                    .collect(),
            ),
            aggregation_batch_root: merkle_from_records(
                "AGGREGATION-BATCHES",
                self.aggregation_batches
                    .values()
                    .map(LowFeeAggregationBatch::public_record)
                    .collect(),
            ),
            nullifier_fence_root: merkle_from_records(
                "NULLIFIER-FENCES",
                self.nullifier_fences
                    .values()
                    .map(PrivacyNullifierFence::public_record)
                    .collect(),
            ),
            settlement_receipt_root: merkle_from_records(
                "SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            slashing_evidence_root: merkle_from_records(
                "SLASHING-EVIDENCE",
                self.slashing_evidence
                    .values()
                    .map(SlashingEvidence::public_record)
                    .collect(),
            ),
            event_root: merkle_from_records(
                "ROUTER-EVENTS",
                self.events
                    .values()
                    .map(RouterEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
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

    pub fn register_header_commitment(&mut self, input: HeaderCommitmentInput) -> Result<String> {
        ensure_capacity(
            self.header_commitments.len(),
            MAX_HEADER_COMMITMENTS,
            "header commitments",
        )?;
        ensure_nonempty(&input.block_hash, "block_hash")?;
        ensure_nonempty(&input.previous_block_hash, "previous_block_hash")?;
        let expires_at_l2_height = input
            .observed_at_l2_height
            .saturating_add(self.config.header_ttl_blocks);
        let header_id = header_commitment_id(
            input.height,
            &input.block_hash,
            &input.previous_block_hash,
            &input.tx_root,
        );
        let commitment = MoneroHeaderCommitment {
            header_id: header_id.clone(),
            monero_network: self.config.monero_network.clone(),
            height: input.height,
            block_hash: input.block_hash,
            previous_block_hash: input.previous_block_hash,
            tx_root: input.tx_root,
            output_root: input.output_root,
            key_image_root: input.key_image_root,
            view_tag_root: input.view_tag_root,
            cumulative_difficulty_commitment: input.cumulative_difficulty_commitment,
            median_weight: input.median_weight,
            observed_at_l2_height: input.observed_at_l2_height,
            expires_at_l2_height,
            status: CommitmentStatus::Observed,
        };
        self.header_commitments
            .insert(header_id.clone(), commitment.clone());
        self.counters.header_commitments = self.header_commitments.len() as u64;
        self.bump_height(input.observed_at_l2_height);
        self.record_event(
            input.observed_at_l2_height,
            "header_commitment_registered",
            &header_id,
            &commitment.root(),
        );
        Ok(header_id)
    }

    pub fn register_state_commitment(&mut self, input: StateCommitmentInput) -> Result<String> {
        ensure_capacity(
            self.state_commitments.len(),
            MAX_STATE_COMMITMENTS,
            "state commitments",
        )?;
        let header = self
            .header_commitments
            .get(&input.header_id)
            .ok_or_else(|| format!("missing header commitment {}", input.header_id))?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below router minimum".to_string());
        }
        if input.viewtag_bucket_size < self.config.min_viewtag_bucket_size {
            return Err("viewtag bucket below router minimum".to_string());
        }
        if input.decoy_set_size < self.config.min_decoy_set_size {
            return Err("decoy set below router minimum".to_string());
        }
        let state_id = state_commitment_id(
            &input.header_id,
            input.chain,
            input.state_kind,
            &input.commitment_root,
            &input.witness_root,
        );
        let commitment = MoneroStateCommitment {
            state_id: state_id.clone(),
            header_id: input.header_id,
            chain: input.chain,
            height: input.height,
            state_kind: input.state_kind,
            commitment_root: input.commitment_root,
            witness_root: input.witness_root,
            output_range_root: input.output_range_root,
            nullifier_root: input.nullifier_root,
            privacy_set_size: input.privacy_set_size,
            viewtag_bucket_size: input.viewtag_bucket_size,
            decoy_set_size: input.decoy_set_size,
            observed_at_l2_height: input.observed_at_l2_height,
            expires_at_l2_height: input
                .observed_at_l2_height
                .saturating_add(self.config.state_ttl_blocks),
            status: if header.status.usable() {
                CommitmentStatus::QuorumAttested
            } else {
                CommitmentStatus::Observed
            },
        };
        self.state_commitments
            .insert(state_id.clone(), commitment.clone());
        self.counters.state_commitments = self.state_commitments.len() as u64;
        self.bump_height(input.observed_at_l2_height);
        self.record_event(
            input.observed_at_l2_height,
            "state_commitment_registered",
            &state_id,
            &commitment.root(),
        );
        Ok(state_id)
    }

    pub fn submit_committee_attestation(
        &mut self,
        input: CommitteeAttestationInput,
    ) -> Result<String> {
        ensure_capacity(
            self.committee_attestations.len(),
            MAX_COMMITTEE_ATTESTATIONS,
            "committee attestations",
        )?;
        if input.committee_weight < self.config.min_committee_weight {
            return Err("committee weight below router minimum".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security below router minimum".to_string());
        }
        let quorum_bps = bps(input.signed_weight, input.committee_weight);
        let status = if quorum_bps >= self.config.committee_quorum_bps {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::WeakQuorum
        };
        let attestation_id = committee_attestation_id(
            &input.subject_id,
            &input.committee_id,
            &input.signature_root,
            input.attested_at_l2_height,
        );
        let attestation = PqCommitteeAttestation {
            attestation_id: attestation_id.clone(),
            subject_id: input.subject_id.clone(),
            committee_id: input.committee_id,
            attestation_kind: input.attestation_kind,
            pq_scheme: PQ_COMMITTEE_SCHEME.to_string(),
            aggregate_public_key_root: input.aggregate_public_key_root,
            signature_root: input.signature_root,
            signer_bitmap_root: input.signer_bitmap_root,
            committee_weight: input.committee_weight,
            signed_weight: input.signed_weight,
            quorum_bps,
            pq_security_bits: input.pq_security_bits,
            attested_at_l2_height: input.attested_at_l2_height,
            expires_at_l2_height: input
                .attested_at_l2_height
                .saturating_add(self.config.proof_ttl_blocks),
            status,
        };
        self.committee_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.mark_subject_attested(&input.subject_id, quorum_bps);
        self.counters.committee_attestations = self.committee_attestations.len() as u64;
        self.bump_height(input.attested_at_l2_height);
        self.record_event(
            input.attested_at_l2_height,
            "committee_attestation_submitted",
            &attestation_id,
            &attestation.root(),
        );
        Ok(attestation_id)
    }

    pub fn open_viewkey_route(&mut self, input: ViewKeyRouteInput) -> Result<String> {
        ensure_capacity(
            self.viewkey_routes.len(),
            MAX_VIEWKEY_ROUTES,
            "viewkey routes",
        )?;
        ensure_bps(input.lane.fee_bps(&self.config), "route fee")?;
        let route_id = viewkey_route_id(
            &input.owner_commitment,
            &input.auditor_committee_id,
            input.disclosure_scope,
            &input.selective_disclosure_policy_root,
            input.opened_at_l2_height,
        );
        let route = ViewKeyDisclosureRoute {
            route_id: route_id.clone(),
            owner_commitment: input.owner_commitment,
            auditor_committee_id: input.auditor_committee_id,
            disclosure_scope: input.disclosure_scope,
            lane: input.lane,
            encrypted_viewkey_share_root: input.encrypted_viewkey_share_root,
            selective_disclosure_policy_root: input.selective_disclosure_policy_root,
            redaction_root: input.redaction_root,
            viewtag_bucket_root: input.viewtag_bucket_root,
            allowed_chain_root: input.allowed_chain_root,
            fee_bps: input.lane.fee_bps(&self.config),
            opened_at_l2_height: input.opened_at_l2_height,
            expires_at_l2_height: input
                .opened_at_l2_height
                .saturating_add(self.config.route_ttl_blocks),
            status: RouteStatus::Active,
        };
        self.viewkey_routes.insert(route_id.clone(), route.clone());
        self.counters.viewkey_routes = self.viewkey_routes.len() as u64;
        self.bump_height(input.opened_at_l2_height);
        self.record_event(
            input.opened_at_l2_height,
            "viewkey_route_opened",
            &route_id,
            &route.root(),
        );
        Ok(route_id)
    }

    pub fn route_proof_envelope(&mut self, input: ProofEnvelopeInput) -> Result<String> {
        ensure_capacity(
            self.stealth_envelopes.len(),
            MAX_STEALTH_ENVELOPES,
            "stealth proof envelopes",
        )?;
        let route = self
            .viewkey_routes
            .get(&input.route_id)
            .ok_or_else(|| format!("missing viewkey route {}", input.route_id))?;
        if !route.status.routable() {
            return Err("viewkey route is not routable".to_string());
        }
        let commitment = self
            .state_commitments
            .get(&input.state_id)
            .ok_or_else(|| format!("missing state commitment {}", input.state_id))?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("envelope privacy set below router minimum".to_string());
        }
        if commitment.status == CommitmentStatus::ReorgFenced {
            return Err("state commitment is reorg fenced".to_string());
        }
        let privacy_set_root = commitment.output_range_root.clone();
        let replay_nullifier_id = nullifier_fence_id(
            input.direction,
            NullifierFenceKind::ProofReplay,
            &input.route_id,
            &input.nullifier,
        );
        if self.nullifier_fences.contains_key(&replay_nullifier_id) {
            return Err("proof nullifier already fenced".to_string());
        }
        let envelope_id = proof_envelope_id(
            &input.route_id,
            &input.state_id,
            input.direction,
            &input.stealth_address_commitment,
            &input.nullifier,
        );
        let envelope = StealthAddressProofEnvelope {
            envelope_id: envelope_id.clone(),
            route_id: input.route_id.clone(),
            state_id: input.state_id,
            direction: input.direction,
            lane: input.lane,
            stealth_address_commitment: input.stealth_address_commitment,
            one_time_key_root: input.one_time_key_root,
            tx_prefix_hash: input.tx_prefix_hash,
            output_membership_root: input.output_membership_root,
            range_proof_commitment: input.range_proof_commitment,
            encrypted_payload_root: input.encrypted_payload_root,
            nullifier: input.nullifier.clone(),
            requested_amount_commitment: input.requested_amount_commitment,
            fee_commitment: input.fee_commitment,
            privacy_set_size: input.privacy_set_size,
            priority_score: input
                .lane
                .priority_weight()
                .saturating_add(input.privacy_set_size / 1_024),
            submitted_at_l2_height: input.submitted_at_l2_height,
            expires_at_l2_height: input
                .submitted_at_l2_height
                .saturating_add(self.config.proof_ttl_blocks),
            status: ProofEnvelopeStatus::Routed,
        };
        self.stealth_envelopes
            .insert(envelope_id.clone(), envelope.clone());
        self.add_nullifier_fence(PrivacyNullifierFence {
            nullifier_id: replay_nullifier_id,
            nullifier: input.nullifier,
            kind: NullifierFenceKind::ProofReplay,
            route_id: input.route_id,
            envelope_id: Some(envelope_id.clone()),
            chain: ChainKind::Monero,
            privacy_set_root,
            bound_at_l2_height: input.submitted_at_l2_height,
            expires_at_l2_height: input
                .submitted_at_l2_height
                .saturating_add(self.config.settlement_ttl_blocks),
            active: true,
        })?;
        self.counters.stealth_envelopes = self.stealth_envelopes.len() as u64;
        self.bump_height(input.submitted_at_l2_height);
        self.record_event(
            input.submitted_at_l2_height,
            "proof_envelope_routed",
            &envelope_id,
            &envelope.root(),
        );
        Ok(envelope_id)
    }

    pub fn enqueue_reserve_proof(
        &mut self,
        envelope_id: &str,
        target_chain: ChainKind,
        height: u64,
    ) -> Result<String> {
        self.enqueue_proof(envelope_id, target_chain, QueueKind::Reserve, height)
    }

    pub fn enqueue_exit_proof(
        &mut self,
        envelope_id: &str,
        target_chain: ChainKind,
        height: u64,
    ) -> Result<String> {
        self.enqueue_proof(envelope_id, target_chain, QueueKind::FastExit, height)
    }

    pub fn post_fast_exit_liquidity(&mut self, input: FastExitLiquidityInput) -> Result<String> {
        ensure_capacity(
            self.liquidity_routes.len(),
            MAX_LIQUIDITY_ROUTES,
            "fast exit liquidity routes",
        )?;
        ensure_bps(input.max_fee_bps, "max fee")?;
        if input.coverage_bps < self.config.fast_exit_coverage_bps {
            return Err("fast exit coverage below router minimum".to_string());
        }
        if !self
            .committee_attestations
            .contains_key(&input.pq_attestation_id)
        {
            return Err(format!(
                "missing pq attestation {}",
                input.pq_attestation_id
            ));
        }
        let liquidity_route_id = liquidity_route_id(
            &input.provider_id,
            input.source_chain,
            input.target_chain,
            &input.reserve_commitment_root,
            input.opened_at_l2_height,
        );
        let route = FastExitLiquidityRoute {
            liquidity_route_id: liquidity_route_id.clone(),
            provider_id: input.provider_id,
            source_chain: input.source_chain,
            target_chain: input.target_chain,
            reserve_commitment_root: input.reserve_commitment_root,
            capacity_commitment: input.capacity_commitment,
            filled_commitment: empty_root("LIQUIDITY-FILLED"),
            max_fee_bps: input.max_fee_bps,
            coverage_bps: input.coverage_bps,
            pq_attestation_id: input.pq_attestation_id,
            settlement_address_commitment: input.settlement_address_commitment,
            refund_address_commitment: input.refund_address_commitment,
            opened_at_l2_height: input.opened_at_l2_height,
            expires_at_l2_height: input
                .opened_at_l2_height
                .saturating_add(self.config.exit_ttl_blocks),
            bound_queue_ids: BTreeSet::new(),
            status: LiquidityRouteStatus::Posted,
        };
        self.liquidity_routes
            .insert(liquidity_route_id.clone(), route.clone());
        self.counters.liquidity_routes = self.liquidity_routes.len() as u64;
        self.bump_height(input.opened_at_l2_height);
        self.record_event(
            input.opened_at_l2_height,
            "fast_exit_liquidity_posted",
            &liquidity_route_id,
            &route.root(),
        );
        Ok(liquidity_route_id)
    }

    pub fn bind_fast_exit_liquidity(
        &mut self,
        queue_id: &str,
        liquidity_route_id: &str,
        height: u64,
    ) -> Result<String> {
        let queue = self
            .exit_queue
            .get_mut(queue_id)
            .ok_or_else(|| format!("missing exit queue item {}", queue_id))?;
        if queue.status != QueueStatus::Queued && queue.status != QueueStatus::Matched {
            return Err("queue item is not bindable".to_string());
        }
        let route = self
            .liquidity_routes
            .get_mut(liquidity_route_id)
            .ok_or_else(|| format!("missing liquidity route {}", liquidity_route_id))?;
        if !route.status.bindable() {
            return Err("liquidity route is not bindable".to_string());
        }
        if route.target_chain != queue.target_chain {
            return Err("liquidity route target chain mismatch".to_string());
        }
        route.bound_queue_ids.insert(queue_id.to_string());
        route.status = LiquidityRouteStatus::Bound;
        queue.matched_liquidity_route_id = Some(liquidity_route_id.to_string());
        queue.status = QueueStatus::Matched;
        let record_root = route.root();
        self.bump_height(height);
        self.record_event(
            height,
            "fast_exit_liquidity_bound",
            liquidity_route_id,
            &record_root,
        );
        Ok(liquidity_route_id.to_string())
    }

    pub fn open_reorg_fence(&mut self, input: ReorgFenceInput) -> Result<String> {
        ensure_capacity(self.reorg_fences.len(), MAX_REORG_FENCES, "reorg fences")?;
        if !self.header_commitments.contains_key(&input.header_id) {
            return Err(format!("missing header commitment {}", input.header_id));
        }
        let fence_id = reorg_fence_id(
            &input.header_id,
            input.chain,
            input.watched_height,
            &input.canonical_block_hash,
        );
        let fence = ReorgFence {
            fence_id: fence_id.clone(),
            header_id: input.header_id,
            chain: input.chain,
            watched_height: input.watched_height,
            canonical_block_hash: input.canonical_block_hash,
            competing_block_hash_root: input.competing_block_hash_root,
            quarantine_root: input.quarantine_root,
            protected_envelope_root: input.protected_envelope_root,
            watcher_attestation_root: input.watcher_attestation_root,
            opened_at_l2_height: input.opened_at_l2_height,
            release_after_l2_height: input
                .opened_at_l2_height
                .saturating_add(self.config.reorg_fence_blocks),
            status: ReorgFenceStatus::Watching,
        };
        self.reorg_fences.insert(fence_id.clone(), fence.clone());
        self.counters.reorg_fences = self.reorg_fences.len() as u64;
        self.bump_height(input.opened_at_l2_height);
        self.record_event(
            input.opened_at_l2_height,
            "reorg_fence_opened",
            &fence_id,
            &fence.root(),
        );
        Ok(fence_id)
    }

    pub fn open_low_fee_aggregation(
        &mut self,
        aggregator_id: &str,
        queue_ids: Vec<String>,
        pq_attestation_id: String,
        height: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.aggregation_batches.len(),
            MAX_AGGREGATION_BATCHES,
            "aggregation batches",
        )?;
        if queue_ids.is_empty() {
            return Err("aggregation batch requires at least one queue item".to_string());
        }
        if queue_ids.len() > self.config.max_aggregation_items {
            return Err("aggregation batch exceeds configured item limit".to_string());
        }
        if !self.committee_attestations.contains_key(&pq_attestation_id) {
            return Err(format!("missing pq attestation {}", pq_attestation_id));
        }
        let mut sorted_queue_ids = BTreeSet::new();
        let mut envelope_records = Vec::new();
        for queue_id in queue_ids {
            let queue = self
                .exit_queue
                .get(&queue_id)
                .or_else(|| self.reserve_queue.get(&queue_id))
                .ok_or_else(|| format!("missing queue item {}", queue_id))?;
            sorted_queue_ids.insert(queue_id);
            envelope_records.push(queue.public_record());
        }
        let envelope_root = merkle_from_records("AGGREGATION-QUEUE-ITEMS", envelope_records);
        let batch_id = aggregation_batch_id(aggregator_id, &envelope_root, height);
        let batch = LowFeeAggregationBatch {
            batch_id: batch_id.clone(),
            aggregator_id: aggregator_id.to_string(),
            lane: RouteLane::Aggregated,
            queue_ids: sorted_queue_ids.clone(),
            envelope_root,
            recursive_proof_root: deterministic_id("AGGREGATION-RECURSIVE-PROOF", &[&batch_id]),
            fee_commitment_root: deterministic_id("AGGREGATION-FEE-COMMITMENT", &[&batch_id]),
            rebate_commitment_root: deterministic_id("AGGREGATION-REBATE-COMMITMENT", &[&batch_id]),
            pq_attestation_id,
            opened_at_l2_height: height,
            expires_at_l2_height: height.saturating_add(self.config.aggregation_ttl_blocks),
            status: AggregationStatus::Open,
        };
        for queue_id in &sorted_queue_ids {
            if let Some(queue) = self.exit_queue.get_mut(queue_id) {
                queue.aggregation_batch_id = Some(batch_id.clone());
                queue.status = QueueStatus::Aggregated;
            }
            if let Some(queue) = self.reserve_queue.get_mut(queue_id) {
                queue.aggregation_batch_id = Some(batch_id.clone());
                queue.status = QueueStatus::Aggregated;
            }
        }
        self.aggregation_batches
            .insert(batch_id.clone(), batch.clone());
        self.counters.aggregation_batches = self.aggregation_batches.len() as u64;
        self.bump_height(height);
        self.record_event(
            height,
            "low_fee_aggregation_opened",
            &batch_id,
            &batch.root(),
        );
        Ok(batch_id)
    }

    pub fn settle_cross_chain_proof(&mut self, input: SettlementInput) -> Result<String> {
        ensure_capacity(
            self.settlement_receipts.len(),
            MAX_SETTLEMENT_RECEIPTS,
            "settlement receipts",
        )?;
        let envelope = self
            .stealth_envelopes
            .get_mut(&input.envelope_id)
            .ok_or_else(|| format!("missing proof envelope {}", input.envelope_id))?;
        if !envelope.status.live() {
            return Err("proof envelope is not settleable".to_string());
        }
        if !self
            .header_commitments
            .contains_key(&input.finality_header_id)
        {
            return Err(format!(
                "missing finality header {}",
                input.finality_header_id
            ));
        }
        if input.confirmation_depth < self.config.finality_depth {
            return Err("settlement confirmation depth below finality requirement".to_string());
        }
        let mut batch_id = None;
        let mut liquidity_route_id = None;
        for queue in self.exit_queue.values_mut() {
            if queue.envelope_id == input.envelope_id {
                queue.status = QueueStatus::Settled;
                batch_id = queue.aggregation_batch_id.clone();
                liquidity_route_id = queue.matched_liquidity_route_id.clone();
            }
        }
        for queue in self.reserve_queue.values_mut() {
            if queue.envelope_id == input.envelope_id {
                queue.status = QueueStatus::Settled;
                batch_id = queue.aggregation_batch_id.clone();
            }
        }
        if let Some(route_id) = liquidity_route_id.as_ref() {
            if let Some(route) = self.liquidity_routes.get_mut(route_id) {
                route.status = LiquidityRouteStatus::Filled;
                route.filled_commitment = deterministic_id(
                    "LIQUIDITY-FILLED-COMMITMENT",
                    &[route_id, &input.settlement_tx_commitment],
                );
            }
        }
        if let Some(batch) = batch_id
            .as_ref()
            .and_then(|id| self.aggregation_batches.get_mut(id))
        {
            batch.status = AggregationStatus::Settled;
        }
        envelope.status = SettlementStatus::Finalized.into();
        let receipt_id = settlement_receipt_id(
            &input.envelope_id,
            &input.settlement_tx_commitment,
            input.settled_chain,
            input.finality_height,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            envelope_id: input.envelope_id,
            route_id: envelope.route_id.clone(),
            batch_id,
            liquidity_route_id,
            settled_chain: input.settled_chain,
            settlement_tx_commitment: input.settlement_tx_commitment,
            finality_header_id: input.finality_header_id,
            finality_height: input.finality_height,
            confirmation_depth: input.confirmation_depth,
            settlement_proof_root: input.settlement_proof_root,
            fee_paid_commitment: input.fee_paid_commitment,
            settled_at_l2_height: input.settled_at_l2_height,
            status: SettlementStatus::Finalized,
        };
        self.settlement_receipts
            .insert(receipt_id.clone(), receipt.clone());
        self.counters.settlement_receipts = self.settlement_receipts.len() as u64;
        self.bump_height(input.settled_at_l2_height);
        self.record_event(
            input.settled_at_l2_height,
            "cross_chain_proof_settled",
            &receipt_id,
            &receipt.root(),
        );
        Ok(receipt_id)
    }

    pub fn slash_bad_router(&mut self, input: SlashingInput) -> Result<String> {
        ensure_capacity(
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
            "slashing evidence",
        )?;
        ensure_bps(input.slash_bps, "slash")?;
        let cap = self.slash_cap_for(input.reason);
        if input.slash_bps > cap {
            return Err("slash exceeds reason cap".to_string());
        }
        let evidence_id = slashing_evidence_id(
            &input.subject_id,
            &input.router_id,
            input.reason,
            &input.evidence_root,
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            subject_id: input.subject_id.clone(),
            router_id: input.router_id,
            reason: input.reason,
            evidence_root: input.evidence_root,
            conflicting_record_root: input.conflicting_record_root,
            protected_privacy_root: input.protected_privacy_root,
            slash_bps: input.slash_bps,
            reporter_id: input.reporter_id,
            reported_at_l2_height: input.reported_at_l2_height,
            adjudication_root: input.adjudication_root,
            applied: true,
        };
        self.apply_slash_status(&input.subject_id);
        self.slashing_evidence
            .insert(evidence_id.clone(), evidence.clone());
        self.counters.slashing_evidence = self.slashing_evidence.len() as u64;
        self.bump_height(input.reported_at_l2_height);
        self.record_event(
            input.reported_at_l2_height,
            "router_slashed",
            &evidence_id,
            &evidence.root(),
        );
        Ok(evidence_id)
    }

    fn enqueue_proof(
        &mut self,
        envelope_id: &str,
        target_chain: ChainKind,
        queue_kind: QueueKind,
        height: u64,
    ) -> Result<String> {
        let is_exit = matches!(
            queue_kind,
            QueueKind::Exit | QueueKind::FastExit | QueueKind::Emergency
        );
        if is_exit {
            ensure_capacity(self.exit_queue.len(), MAX_EXIT_QUEUE_ITEMS, "exit queue")?;
        } else {
            ensure_capacity(
                self.reserve_queue.len(),
                MAX_RESERVE_QUEUE_ITEMS,
                "reserve queue",
            )?;
        }
        let envelope = self
            .stealth_envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| format!("missing proof envelope {}", envelope_id))?;
        if !envelope.status.live() {
            return Err("proof envelope is not queueable".to_string());
        }
        let queue_id = proof_queue_id(envelope_id, queue_kind, target_chain, height);
        let item = ProofQueueItem {
            queue_id: queue_id.clone(),
            envelope_id: envelope_id.to_string(),
            queue_kind,
            route_id: envelope.route_id.clone(),
            target_chain,
            amount_commitment: envelope.requested_amount_commitment.clone(),
            reserve_requirement_commitment: reserve_requirement_commitment(
                &envelope.requested_amount_commitment,
                self.config.min_reserve_coverage_bps,
            ),
            fee_commitment: envelope.fee_commitment.clone(),
            priority_score: envelope
                .priority_score
                .saturating_add(queue_kind_priority(queue_kind)),
            privacy_score: envelope.privacy_set_size / 1_024,
            queued_at_l2_height: height,
            expires_at_l2_height: height.saturating_add(if is_exit {
                self.config.exit_ttl_blocks
            } else {
                self.config.reserve_ttl_blocks
            }),
            matched_liquidity_route_id: None,
            aggregation_batch_id: None,
            status: QueueStatus::Queued,
        };
        if is_exit {
            envelope.status = ProofEnvelopeStatus::ExitQueued;
            self.exit_queue.insert(queue_id.clone(), item.clone());
            self.counters.exit_queue_items = self.exit_queue.len() as u64;
        } else {
            envelope.status = ProofEnvelopeStatus::ReserveQueued;
            self.reserve_queue.insert(queue_id.clone(), item.clone());
            self.counters.reserve_queue_items = self.reserve_queue.len() as u64;
        }
        self.bump_height(height);
        self.record_event(height, "proof_queued", &queue_id, &item.root());
        Ok(queue_id)
    }

    fn mark_subject_attested(&mut self, subject_id: &str, quorum_bps: u64) {
        if let Some(header) = self.header_commitments.get_mut(subject_id) {
            header.status = if quorum_bps >= self.config.strict_quorum_bps {
                CommitmentStatus::Canonical
            } else {
                CommitmentStatus::QuorumAttested
            };
        }
        if let Some(state) = self.state_commitments.get_mut(subject_id) {
            state.status = if quorum_bps >= self.config.strict_quorum_bps {
                CommitmentStatus::Canonical
            } else {
                CommitmentStatus::QuorumAttested
            };
        }
    }

    fn add_nullifier_fence(&mut self, fence: PrivacyNullifierFence) -> Result<()> {
        ensure_capacity(
            self.nullifier_fences.len(),
            MAX_NULLIFIER_FENCES,
            "privacy nullifier fences",
        )?;
        if self.nullifier_fences.contains_key(&fence.nullifier_id) {
            return Err("nullifier fence already exists".to_string());
        }
        self.nullifier_fences
            .insert(fence.nullifier_id.clone(), fence);
        self.counters.nullifier_fences = self.nullifier_fences.len() as u64;
        Ok(())
    }

    fn record_event(&mut self, height: u64, kind: &str, subject_id: &str, record_root_value: &str) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = event_id(
            height,
            kind,
            subject_id,
            record_root_value,
            self.events.len() as u64,
        );
        self.events.insert(
            event_id.clone(),
            RouterEvent {
                event_id,
                height,
                kind: kind.to_string(),
                subject_id: subject_id.to_string(),
                record_root: record_root_value.to_string(),
            },
        );
        self.counters.events = self.events.len() as u64;
    }

    fn bump_height(&mut self, height: u64) {
        if height > self.counters.last_height {
            self.counters.last_height = height;
        }
    }

    fn slash_cap_for(&self, reason: SlashingReason) -> u64 {
        match reason {
            SlashingReason::InvalidProof | SlashingReason::FalseQuorum => {
                self.config.slash_invalid_proof_bps
            }
            SlashingReason::DoubleRoute => self.config.slash_double_route_bps,
            SlashingReason::StaleHeader | SlashingReason::ReorgSuppression => {
                self.config.slash_stale_header_bps
            }
            SlashingReason::PrivacyLeak => self.config.slash_privacy_leak_bps,
            SlashingReason::LiquidityDefault => self.config.slash_liquidity_default_bps,
        }
    }

    fn apply_slash_status(&mut self, subject_id: &str) {
        if let Some(attestation) = self.committee_attestations.get_mut(subject_id) {
            attestation.status = AttestationStatus::Slashed;
        }
        if let Some(route) = self.viewkey_routes.get_mut(subject_id) {
            route.status = RouteStatus::Slashed;
        }
        if let Some(envelope) = self.stealth_envelopes.get_mut(subject_id) {
            envelope.status = ProofEnvelopeStatus::Slashed;
        }
        if let Some(route) = self.liquidity_routes.get_mut(subject_id) {
            route.status = LiquidityRouteStatus::Slashed;
        }
        if let Some(batch) = self.aggregation_batches.get_mut(subject_id) {
            batch.status = AggregationStatus::Slashed;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeaderCommitmentInput {
    pub height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub tx_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub view_tag_root: String,
    pub cumulative_difficulty_commitment: String,
    pub median_weight: u64,
    pub observed_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateCommitmentInput {
    pub header_id: String,
    pub chain: ChainKind,
    pub height: u64,
    pub state_kind: DisclosureScope,
    pub commitment_root: String,
    pub witness_root: String,
    pub output_range_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub viewtag_bucket_size: u64,
    pub decoy_set_size: u64,
    pub observed_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestationInput {
    pub subject_id: String,
    pub committee_id: String,
    pub attestation_kind: DisclosureScope,
    pub aggregate_public_key_root: String,
    pub signature_root: String,
    pub signer_bitmap_root: String,
    pub committee_weight: u64,
    pub signed_weight: u64,
    pub pq_security_bits: u16,
    pub attested_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyRouteInput {
    pub owner_commitment: String,
    pub auditor_committee_id: String,
    pub disclosure_scope: DisclosureScope,
    pub lane: RouteLane,
    pub encrypted_viewkey_share_root: String,
    pub selective_disclosure_policy_root: String,
    pub redaction_root: String,
    pub viewtag_bucket_root: String,
    pub allowed_chain_root: String,
    pub opened_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofEnvelopeInput {
    pub route_id: String,
    pub state_id: String,
    pub direction: ProofDirection,
    pub lane: RouteLane,
    pub stealth_address_commitment: String,
    pub one_time_key_root: String,
    pub tx_prefix_hash: String,
    pub output_membership_root: String,
    pub range_proof_commitment: String,
    pub encrypted_payload_root: String,
    pub nullifier: String,
    pub requested_amount_commitment: String,
    pub fee_commitment: String,
    pub privacy_set_size: u64,
    pub submitted_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastExitLiquidityInput {
    pub provider_id: String,
    pub source_chain: ChainKind,
    pub target_chain: ChainKind,
    pub reserve_commitment_root: String,
    pub capacity_commitment: String,
    pub max_fee_bps: u64,
    pub coverage_bps: u64,
    pub pq_attestation_id: String,
    pub settlement_address_commitment: String,
    pub refund_address_commitment: String,
    pub opened_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgFenceInput {
    pub header_id: String,
    pub chain: ChainKind,
    pub watched_height: u64,
    pub canonical_block_hash: String,
    pub competing_block_hash_root: String,
    pub quarantine_root: String,
    pub protected_envelope_root: String,
    pub watcher_attestation_root: String,
    pub opened_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementInput {
    pub envelope_id: String,
    pub settlement_tx_commitment: String,
    pub finality_header_id: String,
    pub finality_height: u64,
    pub confirmation_depth: u64,
    pub settlement_proof_root: String,
    pub fee_paid_commitment: String,
    pub settled_chain: ChainKind,
    pub settled_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingInput {
    pub subject_id: String,
    pub router_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub conflicting_record_root: String,
    pub protected_privacy_root: String,
    pub slash_bps: u64,
    pub reporter_id: String,
    pub reported_at_l2_height: u64,
    pub adjudication_root: String,
}

impl From<SettlementStatus> for ProofEnvelopeStatus {
    fn from(status: SettlementStatus) -> Self {
        match status {
            SettlementStatus::Submitted => Self::Settling,
            SettlementStatus::FastConfirmed => Self::Settling,
            SettlementStatus::Finalized => Self::Settled,
            SettlementStatus::Reorged => Self::ReorgFenced,
            SettlementStatus::Disputed => Self::Rejected,
            SettlementStatus::Rejected => Self::Rejected,
            SettlementStatus::Slashed => Self::Slashed,
        }
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-CROSS-CHAIN-STATE-PROOF-ROUTER-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

pub fn header_commitment_id(
    height: u64,
    block_hash: &str,
    previous_block_hash: &str,
    tx_root: &str,
) -> String {
    domain_hash(
        "MONERO-HEADER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(previous_block_hash),
            HashPart::Str(tx_root),
        ],
        32,
    )
}

pub fn state_commitment_id(
    header_id: &str,
    chain: ChainKind,
    state_kind: DisclosureScope,
    commitment_root: &str,
    witness_root: &str,
) -> String {
    domain_hash(
        "MONERO-STATE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(header_id),
            HashPart::Str(chain.as_str()),
            HashPart::Str(state_kind.as_str()),
            HashPart::Str(commitment_root),
            HashPart::Str(witness_root),
        ],
        32,
    )
}

pub fn committee_attestation_id(
    subject_id: &str,
    committee_id: &str,
    signature_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PQ-COMMITTEE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject_id),
            HashPart::Str(committee_id),
            HashPart::Str(signature_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn viewkey_route_id(
    owner_commitment: &str,
    committee_id: &str,
    disclosure_scope: DisclosureScope,
    policy_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "VIEWKEY-DISCLOSURE-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(owner_commitment),
            HashPart::Str(committee_id),
            HashPart::Str(disclosure_scope.as_str()),
            HashPart::Str(policy_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn proof_envelope_id(
    route_id: &str,
    state_id: &str,
    direction: ProofDirection,
    stealth_address_commitment: &str,
    nullifier: &str,
) -> String {
    domain_hash(
        "STEALTH-ADDRESS-PROOF-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(state_id),
            HashPart::Str(direction.as_str()),
            HashPart::Str(stealth_address_commitment),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn proof_queue_id(
    envelope_id: &str,
    queue_kind: QueueKind,
    target_chain: ChainKind,
    height: u64,
) -> String {
    domain_hash(
        "PROOF-QUEUE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(envelope_id),
            HashPart::Str(queue_kind.as_str()),
            HashPart::Str(target_chain.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn liquidity_route_id(
    provider_id: &str,
    source_chain: ChainKind,
    target_chain: ChainKind,
    reserve_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "FAST-EXIT-LIQUIDITY-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(provider_id),
            HashPart::Str(source_chain.as_str()),
            HashPart::Str(target_chain.as_str()),
            HashPart::Str(reserve_commitment_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn reorg_fence_id(
    header_id: &str,
    chain: ChainKind,
    watched_height: u64,
    canonical_block_hash: &str,
) -> String {
    domain_hash(
        "REORG-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(header_id),
            HashPart::Str(chain.as_str()),
            HashPart::Int(watched_height as i128),
            HashPart::Str(canonical_block_hash),
        ],
        32,
    )
}

pub fn aggregation_batch_id(aggregator_id: &str, envelope_root: &str, height: u64) -> String {
    domain_hash(
        "LOW-FEE-AGGREGATION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(aggregator_id),
            HashPart::Str(envelope_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn nullifier_fence_id(
    direction: ProofDirection,
    kind: NullifierFenceKind,
    route_id: &str,
    nullifier: &str,
) -> String {
    domain_hash(
        "PRIVACY-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(direction.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(route_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    envelope_id: &str,
    settlement_tx_commitment: &str,
    settled_chain: ChainKind,
    finality_height: u64,
) -> String {
    domain_hash(
        "SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(envelope_id),
            HashPart::Str(settlement_tx_commitment),
            HashPart::Str(settled_chain.as_str()),
            HashPart::Int(finality_height as i128),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    subject_id: &str,
    router_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
) -> String {
    domain_hash(
        "SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject_id),
            HashPart::Str(router_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
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
        "ROUTER-EVENT-ID",
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

pub fn reserve_requirement_commitment(amount_commitment: &str, coverage_bps: u64) -> String {
    domain_hash(
        "RESERVE-REQUIREMENT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(amount_commitment),
            HashPart::Int(coverage_bps as i128),
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

pub fn queue_kind_priority(kind: QueueKind) -> u64 {
    match kind {
        QueueKind::Emergency => 1_000,
        QueueKind::FastExit => 900,
        QueueKind::Exit => 820,
        QueueKind::Reserve => 760,
        QueueKind::LowFeeAggregate => 680,
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
        Err(format!("{} bps exceeds maximum", label))
    } else {
        Ok(())
    }
}
