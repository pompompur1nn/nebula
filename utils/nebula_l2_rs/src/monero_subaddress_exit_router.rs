use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type MoneroSubaddressExitRouterResult<T> = Result<T, String>;

pub const MONERO_SUBADDRESS_EXIT_ROUTER_PROTOCOL_VERSION: u32 = 1;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_PROTOCOL_LABEL: &str =
    "nebula-monero-subaddress-exit-router-v1";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEVNET_HEIGHT: u64 = 384;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_FEE_ASSET_ID: &str = "dxmr-devnet-fee";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_PQ_AUTH_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-subaddress-exit-auth";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_VIEW_TAG_SCHEME: &str =
    "monero-view-tag-indexed-subaddress-scan-v1";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_STEALTH_SCHEME: &str =
    "monero-stealth-subaddress-release-plan-v1";
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 48;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 8;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_FINALITY_DEPTH: u64 = 12;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_MAX_RELEASES_PER_BATCH: usize = 96;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_MAX_BATCH_UNITS: u64 = 1_500_000;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_BASE_FEE_BPS: u64 = 12;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_FAST_FEE_BPS: u64 = 42;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_750;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_SPONSOR_POOL_UNITS: u64 = 240_000;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_VIEW_TAG_QUORUM: u64 = 2;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubaddressExitPriority {
    LowFee,
    Standard,
    Fast,
    Emergency,
    ForcedInclusion,
}

impl SubaddressExitPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Emergency => "emergency",
            Self::ForcedInclusion => "forced_inclusion",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::LowFee => 40,
            Self::Standard => 70,
            Self::Fast => 88,
            Self::Emergency => 98,
            Self::ForcedInclusion => 100,
        }
    }

    pub fn fee_bps(self, config: &MoneroSubaddressExitRouterConfig) -> u64 {
        match self {
            Self::LowFee => config.base_fee_bps.saturating_div(2).max(1),
            Self::Standard => config.base_fee_bps,
            Self::Fast => config.fast_fee_bps,
            Self::Emergency => config.fast_fee_bps.saturating_add(8),
            Self::ForcedInclusion => config.fast_fee_bps.saturating_add(14),
        }
        .min(MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubaddressRouteStatus {
    Requested,
    Scanning,
    ViewTagMatched,
    Proving,
    ReleaseQueued,
    ChallengeOpen,
    FinalityHeld,
    Released,
    Cancelled,
    Expired,
}

impl SubaddressRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Scanning => "scanning",
            Self::ViewTagMatched => "view_tag_matched",
            Self::Proving => "proving",
            Self::ReleaseQueued => "release_queued",
            Self::ChallengeOpen => "challenge_open",
            Self::FinalityHeld => "finality_held",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Requested
                | Self::Scanning
                | Self::ViewTagMatched
                | Self::Proving
                | Self::ReleaseQueued
                | Self::ChallengeOpen
                | Self::FinalityHeld
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagScanStatus {
    Pending,
    Indexed,
    Matched,
    FalsePositive,
    QuorumCertified,
    Disputed,
    Expired,
}

impl ViewTagScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Indexed => "indexed",
            Self::Matched => "matched",
            Self::FalsePositive => "false_positive",
            Self::QuorumCertified => "quorum_certified",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Indexed | Self::Matched | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBatchStatus {
    Collecting,
    Sealed,
    Signed,
    Broadcast,
    Confirmed,
    ChallengeOpen,
    Final,
    ReorgHeld,
    Cancelled,
}

impl ReleaseBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Signed => "signed",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::ChallengeOpen => "challenge_open",
            Self::Final => "final",
            Self::ReorgHeld => "reorg_held",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Collecting
                | Self::Sealed
                | Self::Signed
                | Self::Broadcast
                | Self::Confirmed
                | Self::ChallengeOpen
                | Self::ReorgHeld
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteChallengeKind {
    WrongSubaddress,
    DuplicateKeyImage,
    InsufficientReserve,
    InvalidStealthProof,
    ViewTagEquivocation,
    FeeOvercharge,
    ReorgRisk,
}

impl RouteChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongSubaddress => "wrong_subaddress",
            Self::DuplicateKeyImage => "duplicate_key_image",
            Self::InsufficientReserve => "insufficient_reserve",
            Self::InvalidStealthProof => "invalid_stealth_proof",
            Self::ViewTagEquivocation => "view_tag_equivocation",
            Self::FeeOvercharge => "fee_overcharge",
            Self::ReorgRisk => "reorg_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidencePosted,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidencePosted => "evidence_posted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::EvidencePosted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSubaddressExitRouterConfig {
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub route_ttl_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub finality_depth: u64,
    pub max_releases_per_batch: usize,
    pub max_batch_units: u64,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub sponsor_pool_units: u64,
    pub view_tag_quorum: u64,
    pub watchtower_quorum: u64,
    pub pq_auth_suite: String,
    pub view_tag_scheme: String,
    pub stealth_scheme: String,
    pub hash_suite: String,
}

impl MoneroSubaddressExitRouterConfig {
    pub fn devnet() -> Self {
        Self {
            network: MONERO_SUBADDRESS_EXIT_ROUTER_MONERO_NETWORK.to_string(),
            asset_id: MONERO_SUBADDRESS_EXIT_ROUTER_ASSET_ID.to_string(),
            fee_asset_id: MONERO_SUBADDRESS_EXIT_ROUTER_FEE_ASSET_ID.to_string(),
            route_ttl_blocks: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS,
            reveal_delay_blocks: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_REVEAL_DELAY_BLOCKS,
            challenge_window_blocks: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_depth: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_FINALITY_DEPTH,
            max_releases_per_batch: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_MAX_RELEASES_PER_BATCH,
            max_batch_units: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_MAX_BATCH_UNITS,
            base_fee_bps: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_FAST_FEE_BPS,
            sponsor_rebate_bps: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_SPONSOR_REBATE_BPS,
            sponsor_pool_units: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_SPONSOR_POOL_UNITS,
            view_tag_quorum: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_VIEW_TAG_QUORUM,
            watchtower_quorum: MONERO_SUBADDRESS_EXIT_ROUTER_DEFAULT_WATCHTOWER_QUORUM,
            pq_auth_suite: MONERO_SUBADDRESS_EXIT_ROUTER_PQ_AUTH_SUITE.to_string(),
            view_tag_scheme: MONERO_SUBADDRESS_EXIT_ROUTER_VIEW_TAG_SCHEME.to_string(),
            stealth_scheme: MONERO_SUBADDRESS_EXIT_ROUTER_STEALTH_SCHEME.to_string(),
            hash_suite: MONERO_SUBADDRESS_EXIT_ROUTER_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "route_ttl_blocks": self.route_ttl_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_depth": self.finality_depth,
            "max_releases_per_batch": self.max_releases_per_batch,
            "max_batch_units": self.max_batch_units,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "sponsor_pool_units": self.sponsor_pool_units,
            "view_tag_quorum": self.view_tag_quorum,
            "watchtower_quorum": self.watchtower_quorum,
            "pq_auth_suite": self.pq_auth_suite,
            "view_tag_scheme": self.view_tag_scheme,
            "stealth_scheme": self.stealth_scheme,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        route_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> MoneroSubaddressExitRouterResult<()> {
        if self.network.is_empty() || self.asset_id.is_empty() || self.fee_asset_id.is_empty() {
            return Err("subaddress exit router config identifiers cannot be empty".to_string());
        }
        if self.route_ttl_blocks == 0
            || self.challenge_window_blocks == 0
            || self.finality_depth == 0
            || self.max_releases_per_batch == 0
            || self.max_batch_units == 0
            || self.view_tag_quorum == 0
            || self.watchtower_quorum == 0
        {
            return Err(
                "subaddress exit router config windows and limits must be positive".to_string(),
            );
        }
        if self.base_fee_bps > MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS
            || self.fast_fee_bps > MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS
            || self.sponsor_rebate_bps > MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS
        {
            return Err("subaddress exit router fee bps exceeds maximum".to_string());
        }
        if self.base_fee_bps > self.fast_fee_bps {
            return Err("subaddress exit router base fee cannot exceed fast fee".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressRouteRequest {
    pub route_id: String,
    pub account_commitment: String,
    pub subaddress_commitment: String,
    pub stealth_address_commitment: String,
    pub amount_bucket: u64,
    pub priority: SubaddressExitPriority,
    pub status: SubaddressRouteStatus,
    pub requested_height: u64,
    pub expires_height: u64,
    pub reveal_not_before_height: u64,
    pub view_tag_prefix: String,
    pub key_image_commitment: String,
    pub reserve_lock_id: String,
    pub pq_authorization_root: String,
    pub fee_quote_units: u64,
    pub sponsor_id: Option<String>,
    pub metadata_root: String,
}

impl SubaddressRouteRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        subaddress_label: &str,
        stealth_label: &str,
        amount_bucket: u64,
        priority: SubaddressExitPriority,
        requested_height: u64,
        config: &MoneroSubaddressExitRouterConfig,
        sponsor_id: Option<String>,
        metadata: &Value,
    ) -> Self {
        let account_commitment = route_hash("ACCOUNT", &[HashPart::Str(account_label)]);
        let subaddress_commitment = route_hash("SUBADDRESS", &[HashPart::Str(subaddress_label)]);
        let stealth_address_commitment = route_hash("STEALTH", &[HashPart::Str(stealth_label)]);
        let view_tag_prefix =
            route_hash("VIEW-TAG-PREFIX", &[HashPart::Str(stealth_label)])[0..8].to_string();
        let key_image_commitment = route_hash(
            "KEY-IMAGE",
            &[
                HashPart::Str(account_label),
                HashPart::Str(subaddress_label),
                HashPart::Int(amount_bucket as i128),
            ],
        );
        let reserve_lock_id = route_hash(
            "RESERVE-LOCK-ID",
            &[
                HashPart::Str(&key_image_commitment),
                HashPart::Int(requested_height as i128),
            ],
        );
        let pq_authorization_root = route_hash(
            "PQ-AUTH",
            &[
                HashPart::Str(account_label),
                HashPart::Str(subaddress_label),
                HashPart::Str(config.pq_auth_suite.as_str()),
            ],
        );
        let fee_quote_units = fee_quote_units(amount_bucket, priority, config);
        let metadata_root = route_hash("ROUTE-METADATA", &[HashPart::Json(metadata)]);
        let route_id = route_hash(
            "ROUTE-ID",
            &[
                HashPart::Str(&account_commitment),
                HashPart::Str(&subaddress_commitment),
                HashPart::Str(&stealth_address_commitment),
                HashPart::Int(amount_bucket as i128),
                HashPart::Int(priority.score() as i128),
                HashPart::Int(requested_height as i128),
                HashPart::Str(&metadata_root),
            ],
        );
        Self {
            route_id,
            account_commitment,
            subaddress_commitment,
            stealth_address_commitment,
            amount_bucket,
            priority,
            status: SubaddressRouteStatus::Requested,
            requested_height,
            expires_height: requested_height.saturating_add(config.route_ttl_blocks),
            reveal_not_before_height: requested_height.saturating_add(config.reveal_delay_blocks),
            view_tag_prefix,
            key_image_commitment,
            reserve_lock_id,
            pq_authorization_root,
            fee_quote_units,
            sponsor_id,
            metadata_root,
        }
    }

    pub fn with_status(mut self, status: SubaddressRouteStatus) -> Self {
        self.status = status;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "account_commitment": self.account_commitment,
            "subaddress_commitment": self.subaddress_commitment,
            "stealth_address_commitment": self.stealth_address_commitment,
            "amount_bucket": self.amount_bucket,
            "priority": self.priority.as_str(),
            "status": self.status.as_str(),
            "requested_height": self.requested_height,
            "expires_height": self.expires_height,
            "reveal_not_before_height": self.reveal_not_before_height,
            "view_tag_prefix": self.view_tag_prefix,
            "key_image_commitment": self.key_image_commitment,
            "reserve_lock_id": self.reserve_lock_id,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_quote_units": self.fee_quote_units,
            "sponsor_id": self.sponsor_id,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn record_root(&self) -> String {
        route_hash("ROUTE-REQUEST", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_live(&self) -> bool {
        self.status.is_live()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagScanReceipt {
    pub scan_id: String,
    pub route_id: String,
    pub scanner_commitment: String,
    pub view_tag_prefix: String,
    pub indexed_block_start: u64,
    pub indexed_block_end: u64,
    pub matched_output_count: u64,
    pub decoy_output_count: u64,
    pub status: ViewTagScanStatus,
    pub pq_signature_root: String,
    pub transcript_root: String,
}

impl ViewTagScanReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route: &SubaddressRouteRequest,
        scanner_label: &str,
        indexed_block_start: u64,
        indexed_block_end: u64,
        matched_output_count: u64,
        decoy_output_count: u64,
        status: ViewTagScanStatus,
    ) -> Self {
        let scanner_commitment = route_hash("SCANNER", &[HashPart::Str(scanner_label)]);
        let transcript_root = route_hash(
            "SCAN-TRANSCRIPT",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(scanner_label),
                HashPart::Str(&route.view_tag_prefix),
                HashPart::Int(indexed_block_start as i128),
                HashPart::Int(indexed_block_end as i128),
                HashPart::Int(matched_output_count as i128),
                HashPart::Int(decoy_output_count as i128),
                HashPart::Str(status.as_str()),
            ],
        );
        let pq_signature_root = route_hash(
            "SCAN-PQ-SIG",
            &[
                HashPart::Str(&scanner_commitment),
                HashPart::Str(&transcript_root),
            ],
        );
        let scan_id = route_hash(
            "SCAN-ID",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(&scanner_commitment),
            ],
        );
        Self {
            scan_id,
            route_id: route.route_id.clone(),
            scanner_commitment,
            view_tag_prefix: route.view_tag_prefix.clone(),
            indexed_block_start,
            indexed_block_end,
            matched_output_count,
            decoy_output_count,
            status,
            pq_signature_root,
            transcript_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scan_id": self.scan_id,
            "route_id": self.route_id,
            "scanner_commitment": self.scanner_commitment,
            "view_tag_prefix": self.view_tag_prefix,
            "indexed_block_start": self.indexed_block_start,
            "indexed_block_end": self.indexed_block_end,
            "matched_output_count": self.matched_output_count,
            "decoy_output_count": self.decoy_output_count,
            "status": self.status.as_str(),
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
        })
    }

    pub fn record_root(&self) -> String {
        route_hash("VIEW-TAG-SCAN", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthReleasePlan {
    pub plan_id: String,
    pub route_id: String,
    pub output_commitment_root: String,
    pub stealth_proof_root: String,
    pub range_bucket_root: String,
    pub decoy_set_root: String,
    pub encrypted_destination_root: String,
    pub unlock_height: u64,
    pub low_fee_eligible: bool,
    pub watchtower_quorum_root: String,
}

impl StealthReleasePlan {
    pub fn new(
        route: &SubaddressRouteRequest,
        output_labels: &[&str],
        unlock_height: u64,
        low_fee_eligible: bool,
    ) -> Self {
        let output_commitment_root = string_set_root("OUTPUT-COMMITMENT", output_labels);
        let stealth_proof_root = route_hash(
            "STEALTH-PROOF",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(&output_commitment_root),
            ],
        );
        let range_bucket_root = route_hash(
            "RANGE-BUCKET",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Int(route.amount_bucket as i128),
            ],
        );
        let decoy_set_root = string_set_root("DECOY-SET", output_labels);
        let encrypted_destination_root = route_hash(
            "ENCRYPTED-DESTINATION",
            &[
                HashPart::Str(&route.stealth_address_commitment),
                HashPart::Str(&route.pq_authorization_root),
            ],
        );
        let watchtower_quorum_root = route_hash(
            "WATCHTOWER-QUORUM",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Int(unlock_height as i128),
            ],
        );
        let plan_id = route_hash(
            "RELEASE-PLAN-ID",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(&output_commitment_root),
                HashPart::Int(unlock_height as i128),
                HashPart::Int(low_fee_eligible as i128),
            ],
        );
        Self {
            plan_id,
            route_id: route.route_id.clone(),
            output_commitment_root,
            stealth_proof_root,
            range_bucket_root,
            decoy_set_root,
            encrypted_destination_root,
            unlock_height,
            low_fee_eligible,
            watchtower_quorum_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "route_id": self.route_id,
            "output_commitment_root": self.output_commitment_root,
            "stealth_proof_root": self.stealth_proof_root,
            "range_bucket_root": self.range_bucket_root,
            "decoy_set_root": self.decoy_set_root,
            "encrypted_destination_root": self.encrypted_destination_root,
            "unlock_height": self.unlock_height,
            "low_fee_eligible": self.low_fee_eligible,
            "watchtower_quorum_root": self.watchtower_quorum_root,
        })
    }

    pub fn record_root(&self) -> String {
        route_hash(
            "STEALTH-RELEASE-PLAN",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExitSponsorship {
    pub sponsorship_id: String,
    pub route_id: String,
    pub sponsor_commitment: String,
    pub budget_units: u64,
    pub rebate_bps: u64,
    pub consumed_units: u64,
    pub expires_height: u64,
    pub policy_root: String,
}

impl LowFeeExitSponsorship {
    pub fn new(
        route: &SubaddressRouteRequest,
        sponsor_label: &str,
        budget_units: u64,
        rebate_bps: u64,
        expires_height: u64,
        policy: &Value,
    ) -> Self {
        let sponsor_commitment = route_hash("SPONSOR", &[HashPart::Str(sponsor_label)]);
        let policy_root = route_hash("SPONSOR-POLICY", &[HashPart::Json(policy)]);
        let sponsorship_id = route_hash(
            "SPONSORSHIP-ID",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(&sponsor_commitment),
                HashPart::Int(budget_units as i128),
                HashPart::Int(rebate_bps as i128),
            ],
        );
        Self {
            sponsorship_id,
            route_id: route.route_id.clone(),
            sponsor_commitment,
            budget_units,
            rebate_bps: rebate_bps.min(MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS),
            consumed_units: 0,
            expires_height,
            policy_root,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.consumed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "route_id": self.route_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_units": self.budget_units,
            "rebate_bps": self.rebate_bps,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "expires_height": self.expires_height,
            "policy_root": self.policy_root,
        })
    }

    pub fn record_root(&self) -> String {
        route_hash(
            "LOW-FEE-SPONSORSHIP",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBatch {
    pub batch_id: String,
    pub route_ids: Vec<String>,
    pub plan_ids: Vec<String>,
    pub amount_units: u64,
    pub fee_units: u64,
    pub status: ReleaseBatchStatus,
    pub sealed_height: u64,
    pub monero_tx_prefix_hash: String,
    pub pq_multisig_root: String,
    pub reserve_snapshot_root: String,
}

impl ReleaseBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        routes: &[SubaddressRouteRequest],
        plans: &[StealthReleasePlan],
        sealed_height: u64,
        status: ReleaseBatchStatus,
        monero_tx_label: &str,
        reserve_snapshot: &Value,
    ) -> Self {
        let route_ids = routes
            .iter()
            .map(|route| route.route_id.clone())
            .collect::<Vec<_>>();
        let plan_ids = plans
            .iter()
            .map(|plan| plan.plan_id.clone())
            .collect::<Vec<_>>();
        let amount_units = routes.iter().map(|route| route.amount_bucket).sum::<u64>();
        let fee_units = routes
            .iter()
            .map(|route| route.fee_quote_units)
            .sum::<u64>();
        let route_root = string_vec_root("BATCH-ROUTES", &route_ids);
        let plan_root = string_vec_root("BATCH-PLANS", &plan_ids);
        let monero_tx_prefix_hash =
            route_hash("MONERO-TX-PREFIX", &[HashPart::Str(monero_tx_label)]);
        let reserve_snapshot_root =
            route_hash("RESERVE-SNAPSHOT", &[HashPart::Json(reserve_snapshot)]);
        let pq_multisig_root = route_hash(
            "BATCH-PQ-MULTISIG",
            &[
                HashPart::Str(&route_root),
                HashPart::Str(&plan_root),
                HashPart::Str(&monero_tx_prefix_hash),
            ],
        );
        let batch_id = route_hash(
            "RELEASE-BATCH-ID",
            &[
                HashPart::Str(&route_root),
                HashPart::Str(&plan_root),
                HashPart::Int(sealed_height as i128),
                HashPart::Str(&reserve_snapshot_root),
            ],
        );
        Self {
            batch_id,
            route_ids,
            plan_ids,
            amount_units,
            fee_units,
            status,
            sealed_height,
            monero_tx_prefix_hash,
            pq_multisig_root,
            reserve_snapshot_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "route_ids": self.route_ids,
            "plan_ids": self.plan_ids,
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "status": self.status.as_str(),
            "sealed_height": self.sealed_height,
            "monero_tx_prefix_hash": self.monero_tx_prefix_hash,
            "pq_multisig_root": self.pq_multisig_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
        })
    }

    pub fn record_root(&self) -> String {
        route_hash("RELEASE-BATCH", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_live(&self) -> bool {
        self.status.is_live()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteChallenge {
    pub challenge_id: String,
    pub route_id: String,
    pub challenger_commitment: String,
    pub kind: RouteChallengeKind,
    pub status: ChallengeStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub evidence_root: String,
    pub bond_units: u64,
}

impl RouteChallenge {
    pub fn new(
        route: &SubaddressRouteRequest,
        challenger_label: &str,
        kind: RouteChallengeKind,
        opened_height: u64,
        challenge_window_blocks: u64,
        evidence: &Value,
        bond_units: u64,
    ) -> Self {
        let challenger_commitment = route_hash("CHALLENGER", &[HashPart::Str(challenger_label)]);
        let evidence_root = route_hash("CHALLENGE-EVIDENCE", &[HashPart::Json(evidence)]);
        let challenge_id = route_hash(
            "CHALLENGE-ID",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(&challenger_commitment),
                HashPart::Str(kind.as_str()),
                HashPart::Int(opened_height as i128),
                HashPart::Str(&evidence_root),
            ],
        );
        Self {
            challenge_id,
            route_id: route.route_id.clone(),
            challenger_commitment,
            kind,
            status: ChallengeStatus::Open,
            opened_height,
            expires_height: opened_height.saturating_add(challenge_window_blocks),
            evidence_root,
            bond_units,
        }
    }

    pub fn with_status(mut self, status: ChallengeStatus) -> Self {
        self.status = status;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "route_id": self.route_id,
            "challenger_commitment": self.challenger_commitment,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "evidence_root": self.evidence_root,
            "bond_units": self.bond_units,
        })
    }

    pub fn record_root(&self) -> String {
        route_hash("ROUTE-CHALLENGE", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerSubaddressAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub batch_id: Option<String>,
    pub watchtower_commitment: String,
    pub observed_height: u64,
    pub finality_depth: u64,
    pub view_tag_scan_root: String,
    pub reserve_snapshot_root: String,
    pub pq_signature_root: String,
}

impl WatchtowerSubaddressAttestation {
    pub fn new(
        route: &SubaddressRouteRequest,
        batch_id: Option<String>,
        watchtower_label: &str,
        observed_height: u64,
        finality_depth: u64,
        view_tag_scan_root: &str,
        reserve_snapshot: &Value,
    ) -> Self {
        let watchtower_commitment = route_hash("WATCHTOWER", &[HashPart::Str(watchtower_label)]);
        let reserve_snapshot_root =
            route_hash("WATCHTOWER-RESERVE", &[HashPart::Json(reserve_snapshot)]);
        let pq_signature_root = route_hash(
            "WATCHTOWER-PQ-SIG",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(batch_id.as_deref().unwrap_or("no-batch")),
                HashPart::Str(&watchtower_commitment),
                HashPart::Str(view_tag_scan_root),
                HashPart::Str(&reserve_snapshot_root),
            ],
        );
        let attestation_id = route_hash(
            "WATCHTOWER-ATTESTATION-ID",
            &[
                HashPart::Str(&route.route_id),
                HashPart::Str(&watchtower_commitment),
                HashPart::Int(observed_height as i128),
            ],
        );
        Self {
            attestation_id,
            route_id: route.route_id.clone(),
            batch_id,
            watchtower_commitment,
            observed_height,
            finality_depth,
            view_tag_scan_root: view_tag_scan_root.to_string(),
            reserve_snapshot_root,
            pq_signature_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "route_id": self.route_id,
            "batch_id": self.batch_id,
            "watchtower_commitment": self.watchtower_commitment,
            "observed_height": self.observed_height,
            "finality_depth": self.finality_depth,
            "view_tag_scan_root": self.view_tag_scan_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "pq_signature_root": self.pq_signature_root,
        })
    }

    pub fn record_root(&self) -> String {
        route_hash(
            "WATCHTOWER-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSubaddressExitRouterRoots {
    pub config_root: String,
    pub route_root: String,
    pub scan_root: String,
    pub release_plan_root: String,
    pub sponsorship_root: String,
    pub batch_root: String,
    pub challenge_root: String,
    pub watchtower_root: String,
}

impl MoneroSubaddressExitRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "route_root": self.route_root,
            "scan_root": self.scan_root,
            "release_plan_root": self.release_plan_root,
            "sponsorship_root": self.sponsorship_root,
            "batch_root": self.batch_root,
            "challenge_root": self.challenge_root,
            "watchtower_root": self.watchtower_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSubaddressExitRouterCounters {
    pub route_count: u64,
    pub live_route_count: u64,
    pub scan_count: u64,
    pub open_scan_count: u64,
    pub release_plan_count: u64,
    pub sponsorship_count: u64,
    pub live_batch_count: u64,
    pub open_challenge_count: u64,
    pub watchtower_attestation_count: u64,
    pub pending_amount_units: u64,
    pub sponsored_fee_units: u64,
    pub batch_fee_units: u64,
}

impl MoneroSubaddressExitRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "route_count": self.route_count,
            "live_route_count": self.live_route_count,
            "scan_count": self.scan_count,
            "open_scan_count": self.open_scan_count,
            "release_plan_count": self.release_plan_count,
            "sponsorship_count": self.sponsorship_count,
            "live_batch_count": self.live_batch_count,
            "open_challenge_count": self.open_challenge_count,
            "watchtower_attestation_count": self.watchtower_attestation_count,
            "pending_amount_units": self.pending_amount_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "batch_fee_units": self.batch_fee_units,
        })
    }

    pub fn state_root(&self) -> String {
        route_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSubaddressExitRouterState {
    pub height: u64,
    pub config: MoneroSubaddressExitRouterConfig,
    pub routes: BTreeMap<String, SubaddressRouteRequest>,
    pub scans: BTreeMap<String, ViewTagScanReceipt>,
    pub release_plans: BTreeMap<String, StealthReleasePlan>,
    pub sponsorships: BTreeMap<String, LowFeeExitSponsorship>,
    pub batches: BTreeMap<String, ReleaseBatch>,
    pub challenges: BTreeMap<String, RouteChallenge>,
    pub watchtower_attestations: BTreeMap<String, WatchtowerSubaddressAttestation>,
}

impl MoneroSubaddressExitRouterState {
    pub fn devnet() -> MoneroSubaddressExitRouterResult<Self> {
        let config = MoneroSubaddressExitRouterConfig::devnet();
        let height = MONERO_SUBADDRESS_EXIT_ROUTER_DEVNET_HEIGHT;
        let mut state = Self {
            height,
            config,
            routes: BTreeMap::new(),
            scans: BTreeMap::new(),
            release_plans: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            batches: BTreeMap::new(),
            challenges: BTreeMap::new(),
            watchtower_attestations: BTreeMap::new(),
        };

        let route_a = SubaddressRouteRequest::new(
            "devnet-account-alpha",
            "alpha-subaddress-0",
            "alpha-stealth-exit-0",
            125_000,
            SubaddressExitPriority::LowFee,
            height.saturating_sub(12),
            &state.config,
            Some("sponsor-alpha".to_string()),
            &json!({"lane": "low_fee", "intent": "shielded_wallet_exit"}),
        )
        .with_status(SubaddressRouteStatus::ReleaseQueued);
        let route_b = SubaddressRouteRequest::new(
            "devnet-account-beta",
            "beta-subaddress-4",
            "beta-stealth-exit-4",
            450_000,
            SubaddressExitPriority::Fast,
            height.saturating_sub(6),
            &state.config,
            None,
            &json!({"lane": "fast", "intent": "private_dex_settlement"}),
        )
        .with_status(SubaddressRouteStatus::ChallengeOpen);
        let route_c = SubaddressRouteRequest::new(
            "devnet-account-gamma",
            "gamma-subaddress-9",
            "gamma-stealth-forced-9",
            80_000,
            SubaddressExitPriority::ForcedInclusion,
            height.saturating_sub(1),
            &state.config,
            Some("sponsor-forced".to_string()),
            &json!({"lane": "forced_inclusion", "intent": "escape_hatch"}),
        )
        .with_status(SubaddressRouteStatus::Scanning);

        state.insert_route(route_a.clone())?;
        state.insert_route(route_b.clone())?;
        state.insert_route(route_c.clone())?;

        for (route, scanner, status) in [
            (
                &route_a,
                "viewtag-scanner-a",
                ViewTagScanStatus::QuorumCertified,
            ),
            (&route_a, "viewtag-scanner-b", ViewTagScanStatus::Matched),
            (&route_b, "viewtag-scanner-a", ViewTagScanStatus::Disputed),
            (&route_c, "viewtag-scanner-c", ViewTagScanStatus::Indexed),
        ] {
            let scan = ViewTagScanReceipt::new(
                route,
                scanner,
                height.saturating_sub(72),
                height.saturating_sub(2),
                if status == ViewTagScanStatus::Indexed {
                    0
                } else {
                    1
                },
                15,
                status,
            );
            state.insert_scan(scan)?;
        }

        let plan_a = StealthReleasePlan::new(
            &route_a,
            &[
                "alpha-output-0",
                "alpha-output-decoy-1",
                "alpha-output-decoy-2",
            ],
            height.saturating_add(2),
            true,
        );
        let plan_b = StealthReleasePlan::new(
            &route_b,
            &[
                "beta-output-4",
                "beta-output-decoy-3",
                "beta-output-decoy-7",
            ],
            height.saturating_add(4),
            false,
        );
        state.insert_release_plan(plan_a.clone())?;
        state.insert_release_plan(plan_b.clone())?;

        let sponsorship_a = LowFeeExitSponsorship::new(
            &route_a,
            "devnet-low-fee-sponsor",
            24_000,
            state.config.sponsor_rebate_bps,
            route_a.expires_height,
            &json!({"max_fee_units": 50, "lane": "low_fee"}),
        );
        let sponsorship_c = LowFeeExitSponsorship::new(
            &route_c,
            "devnet-forced-inclusion-sponsor",
            18_000,
            state.config.sponsor_rebate_bps,
            route_c.expires_height,
            &json!({"max_fee_units": 35, "lane": "forced_inclusion"}),
        );
        state.insert_sponsorship(sponsorship_a)?;
        state.insert_sponsorship(sponsorship_c)?;

        let batch = ReleaseBatch::new(
            &[route_a.clone(), route_b.clone()],
            &[plan_a.clone(), plan_b.clone()],
            height,
            ReleaseBatchStatus::Signed,
            "monero-devnet-exit-tx-42",
            &json!({"reserve_height": height, "reserve_units": 20_000_000}),
        );
        let batch_id = batch.batch_id.clone();
        state.insert_batch(batch)?;

        let challenge = RouteChallenge::new(
            &route_b,
            "watchtower-beta",
            RouteChallengeKind::ViewTagEquivocation,
            height,
            state.config.challenge_window_blocks,
            &json!({"scan_conflict": true, "scanner": "viewtag-scanner-a"}),
            7_500,
        )
        .with_status(ChallengeStatus::EvidencePosted);
        state.insert_challenge(challenge)?;

        let route_a_scan_root = state
            .scans
            .values()
            .find(|scan| scan.route_id == route_a.route_id)
            .map(ViewTagScanReceipt::record_root)
            .unwrap_or_else(|| route_hash("EMPTY-SCAN", &[HashPart::Str(&route_a.route_id)]));
        let attestation = WatchtowerSubaddressAttestation::new(
            &route_a,
            Some(batch_id),
            "watchtower-alpha",
            height,
            state.config.finality_depth,
            &route_a_scan_root,
            &json!({"reserve_height": height, "available_units": 20_000_000}),
        );
        state.insert_watchtower_attestation(attestation)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroSubaddressExitRouterResult<()> {
        if height < self.height {
            return Err("subaddress exit router height cannot decrease".to_string());
        }
        self.height = height;
        for route in self.routes.values_mut() {
            if route.status.is_live() && height > route.expires_height {
                route.status = SubaddressRouteStatus::Expired;
            }
        }
        for scan in self.scans.values_mut() {
            if scan.status.is_open()
                && height.saturating_sub(scan.indexed_block_end) > self.config.route_ttl_blocks
            {
                scan.status = ViewTagScanStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status.is_open() && height > challenge.expires_height {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        self.validate()?;
        Ok(())
    }

    pub fn insert_route(
        &mut self,
        route: SubaddressRouteRequest,
    ) -> MoneroSubaddressExitRouterResult<()> {
        if route.route_id.is_empty() {
            return Err("subaddress route id cannot be empty".to_string());
        }
        self.routes.insert(route.route_id.clone(), route);
        Ok(())
    }

    pub fn insert_scan(
        &mut self,
        scan: ViewTagScanReceipt,
    ) -> MoneroSubaddressExitRouterResult<()> {
        if !self.routes.contains_key(&scan.route_id) {
            return Err("subaddress scan references unknown route".to_string());
        }
        self.scans.insert(scan.scan_id.clone(), scan);
        Ok(())
    }

    pub fn insert_release_plan(
        &mut self,
        plan: StealthReleasePlan,
    ) -> MoneroSubaddressExitRouterResult<()> {
        if !self.routes.contains_key(&plan.route_id) {
            return Err("subaddress release plan references unknown route".to_string());
        }
        self.release_plans.insert(plan.plan_id.clone(), plan);
        Ok(())
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeExitSponsorship,
    ) -> MoneroSubaddressExitRouterResult<()> {
        if !self.routes.contains_key(&sponsorship.route_id) {
            return Err("subaddress sponsorship references unknown route".to_string());
        }
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_batch(&mut self, batch: ReleaseBatch) -> MoneroSubaddressExitRouterResult<()> {
        for route_id in &batch.route_ids {
            if !self.routes.contains_key(route_id) {
                return Err("subaddress release batch references unknown route".to_string());
            }
        }
        for plan_id in &batch.plan_ids {
            if !self.release_plans.contains_key(plan_id) {
                return Err("subaddress release batch references unknown plan".to_string());
            }
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: RouteChallenge,
    ) -> MoneroSubaddressExitRouterResult<()> {
        if !self.routes.contains_key(&challenge.route_id) {
            return Err("subaddress challenge references unknown route".to_string());
        }
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn insert_watchtower_attestation(
        &mut self,
        attestation: WatchtowerSubaddressAttestation,
    ) -> MoneroSubaddressExitRouterResult<()> {
        if !self.routes.contains_key(&attestation.route_id) {
            return Err("subaddress watchtower attestation references unknown route".to_string());
        }
        self.watchtower_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn roots(&self) -> MoneroSubaddressExitRouterRoots {
        MoneroSubaddressExitRouterRoots {
            config_root: self.config.config_root(),
            route_root: map_root(
                "ROUTES",
                self.routes
                    .values()
                    .map(SubaddressRouteRequest::public_record),
            ),
            scan_root: map_root(
                "SCANS",
                self.scans.values().map(ViewTagScanReceipt::public_record),
            ),
            release_plan_root: map_root(
                "RELEASE-PLANS",
                self.release_plans
                    .values()
                    .map(StealthReleasePlan::public_record),
            ),
            sponsorship_root: map_root(
                "SPONSORSHIPS",
                self.sponsorships
                    .values()
                    .map(LowFeeExitSponsorship::public_record),
            ),
            batch_root: map_root(
                "BATCHES",
                self.batches.values().map(ReleaseBatch::public_record),
            ),
            challenge_root: map_root(
                "CHALLENGES",
                self.challenges.values().map(RouteChallenge::public_record),
            ),
            watchtower_root: map_root(
                "WATCHTOWER-ATTESTATIONS",
                self.watchtower_attestations
                    .values()
                    .map(WatchtowerSubaddressAttestation::public_record),
            ),
        }
    }

    pub fn counters(&self) -> MoneroSubaddressExitRouterCounters {
        MoneroSubaddressExitRouterCounters {
            route_count: self.routes.len() as u64,
            live_route_count: self.routes.values().filter(|route| route.is_live()).count() as u64,
            scan_count: self.scans.len() as u64,
            open_scan_count: self.scans.values().filter(|scan| scan.is_open()).count() as u64,
            release_plan_count: self.release_plans.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            live_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.is_live())
                .count() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.is_open())
                .count() as u64,
            watchtower_attestation_count: self.watchtower_attestations.len() as u64,
            pending_amount_units: self
                .routes
                .values()
                .filter(|route| route.is_live())
                .map(|route| route.amount_bucket)
                .sum(),
            sponsored_fee_units: self
                .sponsorships
                .values()
                .map(LowFeeExitSponsorship::available_units)
                .sum(),
            batch_fee_units: self.batches.values().map(|batch| batch.fee_units).sum(),
        }
    }

    pub fn active_route_ids(&self) -> Vec<String> {
        self.routes
            .values()
            .filter(|route| route.is_live())
            .map(|route| route.route_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.is_open())
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_subaddress_exit_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_SUBADDRESS_EXIT_ROUTER_PROTOCOL_VERSION,
            "protocol_label": MONERO_SUBADDRESS_EXIT_ROUTER_PROTOCOL_LABEL,
            "schema_version": MONERO_SUBADDRESS_EXIT_ROUTER_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "routes": self.routes.values().map(SubaddressRouteRequest::public_record).collect::<Vec<_>>(),
            "scans": self.scans.values().map(ViewTagScanReceipt::public_record).collect::<Vec<_>>(),
            "release_plans": self.release_plans.values().map(StealthReleasePlan::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(LowFeeExitSponsorship::public_record).collect::<Vec<_>>(),
            "batches": self.batches.values().map(ReleaseBatch::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(RouteChallenge::public_record).collect::<Vec<_>>(),
            "watchtower_attestations": self.watchtower_attestations.values().map(WatchtowerSubaddressAttestation::public_record).collect::<Vec<_>>(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        monero_subaddress_exit_router_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> MoneroSubaddressExitRouterResult<String> {
        self.config.validate()?;
        let mut route_ids = BTreeSet::new();
        for route in self.routes.values() {
            if route.route_id.is_empty()
                || route.account_commitment.is_empty()
                || route.subaddress_commitment.is_empty()
                || route.stealth_address_commitment.is_empty()
                || route.key_image_commitment.is_empty()
                || route.reserve_lock_id.is_empty()
                || route.pq_authorization_root.is_empty()
            {
                return Err("subaddress route contains empty commitments".to_string());
            }
            if route.amount_bucket == 0 {
                return Err("subaddress route amount bucket must be positive".to_string());
            }
            if route.expires_height <= route.requested_height {
                return Err("subaddress route expiry must exceed request height".to_string());
            }
            if !route_ids.insert(route.route_id.clone()) {
                return Err("duplicate subaddress route id".to_string());
            }
        }
        for scan in self.scans.values() {
            if !self.routes.contains_key(&scan.route_id) {
                return Err("subaddress scan references missing route".to_string());
            }
            if scan.indexed_block_end < scan.indexed_block_start {
                return Err("subaddress scan block range is inverted".to_string());
            }
        }
        for plan in self.release_plans.values() {
            if !self.routes.contains_key(&plan.route_id) {
                return Err("subaddress release plan references missing route".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            if !self.routes.contains_key(&sponsorship.route_id) {
                return Err("subaddress sponsorship references missing route".to_string());
            }
            if sponsorship.rebate_bps > MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS {
                return Err("subaddress sponsorship rebate exceeds maximum".to_string());
            }
        }
        for batch in self.batches.values() {
            if batch.route_ids.is_empty() || batch.plan_ids.is_empty() {
                return Err("subaddress release batch cannot be empty".to_string());
            }
            if batch.route_ids.len() > self.config.max_releases_per_batch {
                return Err("subaddress release batch exceeds configured route limit".to_string());
            }
            if batch.amount_units > self.config.max_batch_units {
                return Err("subaddress release batch exceeds configured amount limit".to_string());
            }
            for route_id in &batch.route_ids {
                if !self.routes.contains_key(route_id) {
                    return Err("subaddress release batch references missing route".to_string());
                }
            }
            for plan_id in &batch.plan_ids {
                if !self.release_plans.contains_key(plan_id) {
                    return Err("subaddress release batch references missing plan".to_string());
                }
            }
        }
        for challenge in self.challenges.values() {
            if !self.routes.contains_key(&challenge.route_id) {
                return Err("subaddress challenge references missing route".to_string());
            }
            if challenge.expires_height <= challenge.opened_height {
                return Err("subaddress challenge expiry must exceed opening height".to_string());
            }
        }
        for attestation in self.watchtower_attestations.values() {
            if !self.routes.contains_key(&attestation.route_id) {
                return Err(
                    "subaddress watchtower attestation references missing route".to_string()
                );
            }
            if let Some(batch_id) = &attestation.batch_id {
                if !self.batches.contains_key(batch_id) {
                    return Err(
                        "subaddress watchtower attestation references missing batch".to_string()
                    );
                }
            }
        }
        Ok(self.state_root())
    }
}

pub fn monero_subaddress_exit_router_state_root_from_record(record: &Value) -> String {
    route_hash("STATE", &[HashPart::Json(record)])
}

fn route_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("MONERO-SUBADDRESS-EXIT-ROUTER-{domain}"),
        parts,
        32,
    )
}

fn fee_quote_units(
    amount_bucket: u64,
    priority: SubaddressExitPriority,
    config: &MoneroSubaddressExitRouterConfig,
) -> u64 {
    amount_bucket
        .saturating_mul(priority.fee_bps(config))
        .saturating_add(MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS - 1)
        / MONERO_SUBADDRESS_EXIT_ROUTER_MAX_BPS
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    route_hash(domain, &[HashPart::Json(&json!(values))])
}

fn string_set_root(domain: &str, labels: &[&str]) -> String {
    let mut labels = labels.iter().copied().collect::<Vec<_>>();
    labels.sort();
    route_hash(domain, &[HashPart::Json(&json!(labels))])
}

fn string_vec_root(domain: &str, values: &[String]) -> String {
    route_hash(domain, &[HashPart::Json(&json!(values))])
}
