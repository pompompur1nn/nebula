use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2ExitClaimQueueResult<T> = Result<T, String>;

pub const MONERO_L2_EXIT_CLAIM_QUEUE_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-exit-claim-queue-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_EXIT_CLAIM_QUEUE_PROTOCOL_VERSION;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_HEIGHT: u64 = 512;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_COMMITMENT_SCHEME: &str = "private-exit-claim-commitment-v1";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_SUBADDRESS_SCHEME: &str =
    "monero-subaddress-commitment-root-v1";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_WATCHER_CERT_SCHEME: &str =
    "pq-watchtower-exit-claim-certificate-root-v1";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_LIQUIDITY_SPONSOR_SCHEME: &str =
    "fast-exit-liquidity-sponsor-root-v1";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_FEE_SUBSIDY_SCHEME: &str =
    "privacy-preserving-fee-subsidy-root-v1";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_RECEIPT_SCHEME: &str = "private-exit-claim-receipt-root-v1";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_CHECKPOINT_SCHEME: &str =
    "monero-l2-exit-settlement-checkpoint-v1";
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_STANDARD_FINALITY_DEPTH: u64 = 12;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_FINALITY_DEPTH: u64 = 6;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_STANDARD_TTL_BLOCKS: u64 = 96;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_REPLAY_FENCE_TTL_BLOCKS: u64 = 192;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 2;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_MIN_WATCHER_WEIGHT: u64 = 3;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2_048;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MAX_OPEN_CLAIMS: usize = 262_144;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MAX_CHECKPOINT_CLAIMS: usize = 4_096;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_BASE_FEE_BPS: u64 = 16;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_FEE_BPS: u64 = 45;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_SPONSOR_REBATE_BPS: u64 = 7_500;
pub const MONERO_L2_EXIT_CLAIM_QUEUE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimLane {
    Standard,
    Fast,
}

impl ClaimLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Fast => "fast",
        }
    }

    pub fn finality_depth(self, config: &Config) -> u64 {
        match self {
            Self::Standard => config.standard_finality_depth,
            Self::Fast => config.fast_finality_depth,
        }
        .max(1)
    }

    pub fn ttl_blocks(self, config: &Config) -> u64 {
        match self {
            Self::Standard => config.standard_ttl_blocks,
            Self::Fast => config.fast_ttl_blocks,
        }
        .max(1)
    }

    pub fn watcher_weight(self, config: &Config) -> u64 {
        match self {
            Self::Standard => config.min_watcher_weight,
            Self::Fast => config.fast_min_watcher_weight,
        }
        .max(1)
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::Standard => config.base_fee_bps,
            Self::Fast => config.fast_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Open,
    WatcherCertified,
    SponsorLocked,
    SubsidyApplied,
    FinalityPending,
    ReadyToSettle,
    Settled,
    Expired,
    Rejected,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::WatcherCertified => "watcher_certified",
            Self::SponsorLocked => "sponsor_locked",
            Self::SubsidyApplied => "subsidy_applied",
            Self::FinalityPending => "finality_pending",
            Self::ReadyToSettle => "ready_to_settle",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAdvance {
    WatcherCertificate,
    LiquiditySponsor,
    FeeSubsidy,
    FinalityObservation,
    Ready,
    Expire,
    Reject,
}

impl ClaimAdvance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherCertificate => "watcher_certificate",
            Self::LiquiditySponsor => "liquidity_sponsor",
            Self::FeeSubsidy => "fee_subsidy",
            Self::FinalityObservation => "finality_observation",
            Self::Ready => "ready",
            Self::Expire => "expire",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub commitment_scheme: String,
    pub subaddress_scheme: String,
    pub watcher_cert_scheme: String,
    pub liquidity_sponsor_scheme: String,
    pub fee_subsidy_scheme: String,
    pub receipt_scheme: String,
    pub checkpoint_scheme: String,
    pub genesis_height: u64,
    pub standard_finality_depth: u64,
    pub fast_finality_depth: u64,
    pub standard_ttl_blocks: u64,
    pub fast_ttl_blocks: u64,
    pub replay_fence_ttl_blocks: u64,
    pub min_watcher_weight: u64,
    pub fast_min_watcher_weight: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_open_claims: usize,
    pub max_checkpoint_claims: usize,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_EXIT_CLAIM_QUEUE_SCHEMA_VERSION,
            monero_network: MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_L2_EXIT_CLAIM_QUEUE_HASH_SUITE.to_string(),
            commitment_scheme: MONERO_L2_EXIT_CLAIM_QUEUE_COMMITMENT_SCHEME.to_string(),
            subaddress_scheme: MONERO_L2_EXIT_CLAIM_QUEUE_SUBADDRESS_SCHEME.to_string(),
            watcher_cert_scheme: MONERO_L2_EXIT_CLAIM_QUEUE_WATCHER_CERT_SCHEME.to_string(),
            liquidity_sponsor_scheme: MONERO_L2_EXIT_CLAIM_QUEUE_LIQUIDITY_SPONSOR_SCHEME
                .to_string(),
            fee_subsidy_scheme: MONERO_L2_EXIT_CLAIM_QUEUE_FEE_SUBSIDY_SCHEME.to_string(),
            receipt_scheme: MONERO_L2_EXIT_CLAIM_QUEUE_RECEIPT_SCHEME.to_string(),
            checkpoint_scheme: MONERO_L2_EXIT_CLAIM_QUEUE_CHECKPOINT_SCHEME.to_string(),
            genesis_height: MONERO_L2_EXIT_CLAIM_QUEUE_DEVNET_HEIGHT,
            standard_finality_depth: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_STANDARD_FINALITY_DEPTH,
            fast_finality_depth: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_FINALITY_DEPTH,
            standard_ttl_blocks: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_STANDARD_TTL_BLOCKS,
            fast_ttl_blocks: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_TTL_BLOCKS,
            replay_fence_ttl_blocks: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_REPLAY_FENCE_TTL_BLOCKS,
            min_watcher_weight: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MIN_WATCHER_WEIGHT,
            fast_min_watcher_weight: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_MIN_WATCHER_WEIGHT,
            min_privacy_set_size: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_open_claims: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MAX_OPEN_CLAIMS,
            max_checkpoint_claims: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MAX_CHECKPOINT_CLAIMS,
            base_fee_bps: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_FEE_BPS,
            sponsor_rebate_bps: MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_SPONSOR_REBATE_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "commitment_scheme": self.commitment_scheme,
            "subaddress_scheme": self.subaddress_scheme,
            "watcher_cert_scheme": self.watcher_cert_scheme,
            "liquidity_sponsor_scheme": self.liquidity_sponsor_scheme,
            "fee_subsidy_scheme": self.fee_subsidy_scheme,
            "receipt_scheme": self.receipt_scheme,
            "checkpoint_scheme": self.checkpoint_scheme,
            "genesis_height": self.genesis_height,
            "standard_finality_depth": self.standard_finality_depth,
            "fast_finality_depth": self.fast_finality_depth,
            "standard_ttl_blocks": self.standard_ttl_blocks,
            "fast_ttl_blocks": self.fast_ttl_blocks,
            "replay_fence_ttl_blocks": self.replay_fence_ttl_blocks,
            "min_watcher_weight": self.min_watcher_weight,
            "fast_min_watcher_weight": self.fast_min_watcher_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_open_claims": self.max_open_claims,
            "max_checkpoint_claims": self.max_checkpoint_claims,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub opened_claims: u64,
    pub advanced_claims: u64,
    pub settled_claims: u64,
    pub expired_claims: u64,
    pub rejected_claims: u64,
    pub replay_rejections: u64,
    pub fast_lane_claims: u64,
    pub standard_lane_claims: u64,
    pub sponsored_claims: u64,
    pub subsidized_claims: u64,
    pub checkpoints: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "opened_claims": self.opened_claims,
            "advanced_claims": self.advanced_claims,
            "settled_claims": self.settled_claims,
            "expired_claims": self.expired_claims,
            "rejected_claims": self.rejected_claims,
            "replay_rejections": self.replay_rejections,
            "fast_lane_claims": self.fast_lane_claims,
            "standard_lane_claims": self.standard_lane_claims,
            "sponsored_claims": self.sponsored_claims,
            "subsidized_claims": self.subsidized_claims,
            "checkpoints": self.checkpoints,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenClaimRequest {
    pub exit_commitment: String,
    pub subaddress_commitment_root: String,
    pub amount_bucket_root: String,
    pub claimant_set_root: String,
    pub lane: ClaimLane,
    pub privacy_set_size: u64,
    pub l2_burn_height: u64,
    pub observed_monero_height: u64,
    pub nullifier: String,
    pub replay_fence: String,
    pub watcher_certificate_root: Option<String>,
    pub watcher_weight: u64,
    pub liquidity_sponsor_root: Option<String>,
    pub fee_subsidy_root: Option<String>,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvanceClaimRequest {
    pub claim_id: String,
    pub action: ClaimAdvance,
    pub watcher_certificate_root: Option<String>,
    pub watcher_weight: Option<u64>,
    pub liquidity_sponsor_root: Option<String>,
    pub fee_subsidy_root: Option<String>,
    pub observed_monero_height: Option<u64>,
    pub finality_depth: Option<u64>,
    pub note_root: Option<String>,
    pub advanced_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleClaimRequest {
    pub claim_id: String,
    pub settlement_tx_root: String,
    pub settlement_checkpoint_root: String,
    pub receipt_root: String,
    pub settled_monero_height: u64,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitClaim {
    pub claim_id: String,
    pub exit_commitment: String,
    pub subaddress_commitment_root: String,
    pub amount_bucket_root: String,
    pub claimant_set_root: String,
    pub lane: ClaimLane,
    pub status: ClaimStatus,
    pub privacy_set_size: u64,
    pub l2_burn_height: u64,
    pub observed_monero_height: u64,
    pub required_finality_depth: u64,
    pub watcher_certificate_root: String,
    pub watcher_weight: u64,
    pub liquidity_sponsor_root: String,
    pub fee_subsidy_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl ExitClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "exit_commitment": self.exit_commitment,
            "subaddress_commitment_root": self.subaddress_commitment_root,
            "amount_bucket_root": self.amount_bucket_root,
            "claimant_set_root": self.claimant_set_root,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "l2_burn_height": self.l2_burn_height,
            "observed_monero_height": self.observed_monero_height,
            "required_finality_depth": self.required_finality_depth,
            "watcher_certificate_root": self.watcher_certificate_root,
            "watcher_weight": self.watcher_weight,
            "liquidity_sponsor_root": self.liquidity_sponsor_root,
            "fee_subsidy_root": self.fee_subsidy_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn claim_root(&self) -> String {
        record_hash("MONERO-L2-EXIT-CLAIM", &self.public_record())
    }

    pub fn has_watcher_quorum(&self) -> bool {
        self.watcher_weight >= self.required_watcher_weight()
    }

    pub fn required_watcher_weight(&self) -> u64 {
        match self.lane {
            ClaimLane::Standard => MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_MIN_WATCHER_WEIGHT,
            ClaimLane::Fast => MONERO_L2_EXIT_CLAIM_QUEUE_DEFAULT_FAST_MIN_WATCHER_WEIGHT,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimReceipt {
    pub receipt_id: String,
    pub claim_id: String,
    pub lane: ClaimLane,
    pub exit_commitment: String,
    pub settlement_tx_root: String,
    pub settlement_checkpoint_root: String,
    pub receipt_root: String,
    pub watcher_certificate_root: String,
    pub liquidity_sponsor_root: String,
    pub fee_subsidy_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub settled_monero_height: u64,
    pub settled_at_height: u64,
    pub sequence: u64,
}

impl ClaimReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "lane": self.lane.as_str(),
            "exit_commitment": self.exit_commitment,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_checkpoint_root": self.settlement_checkpoint_root,
            "receipt_root": self.receipt_root,
            "watcher_certificate_root": self.watcher_certificate_root,
            "liquidity_sponsor_root": self.liquidity_sponsor_root,
            "fee_subsidy_root": self.fee_subsidy_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "settled_monero_height": self.settled_monero_height,
            "settled_at_height": self.settled_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub claim_id: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_at_height: Option<u64>,
}

impl ReplayFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "claim_id": self.claim_id,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed_at_height": self.consumed_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementCheckpoint {
    pub checkpoint_id: String,
    pub checkpoint_root: String,
    pub claim_receipt_root: String,
    pub settled_claim_count: u64,
    pub fast_claim_count: u64,
    pub standard_claim_count: u64,
    pub min_monero_height: u64,
    pub max_monero_height: u64,
    pub created_at_height: u64,
    pub state_root: String,
}

impl SettlementCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_root": self.checkpoint_root,
            "claim_receipt_root": self.claim_receipt_root,
            "settled_claim_count": self.settled_claim_count,
            "fast_claim_count": self.fast_claim_count,
            "standard_claim_count": self.standard_claim_count,
            "min_monero_height": self.min_monero_height,
            "max_monero_height": self.max_monero_height,
            "created_at_height": self.created_at_height,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueRoots {
    pub config_root: String,
    pub claim_root: String,
    pub open_claim_root: String,
    pub fast_lane_root: String,
    pub standard_lane_root: String,
    pub subaddress_commitment_root: String,
    pub watcher_certificate_root: String,
    pub liquidity_sponsor_root: String,
    pub fee_subsidy_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub receipt_root: String,
    pub settlement_checkpoint_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl QueueRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "claim_root": self.claim_root,
            "open_claim_root": self.open_claim_root,
            "fast_lane_root": self.fast_lane_root,
            "standard_lane_root": self.standard_lane_root,
            "subaddress_commitment_root": self.subaddress_commitment_root,
            "watcher_certificate_root": self.watcher_certificate_root,
            "liquidity_sponsor_root": self.liquidity_sponsor_root,
            "fee_subsidy_root": self.fee_subsidy_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "receipt_root": self.receipt_root,
            "settlement_checkpoint_root": self.settlement_checkpoint_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub claims: BTreeMap<String, ExitClaim>,
    pub receipts: BTreeMap<String, ClaimReceipt>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub settlement_checkpoints: BTreeMap<String, SettlementCheckpoint>,
    pub nullifier_index: BTreeSet<String>,
    pub replay_fence_index: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            claims: BTreeMap::new(),
            receipts: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            settlement_checkpoints: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            replay_fence_index: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    pub fn open_claim(
        &mut self,
        request: OpenClaimRequest,
    ) -> MoneroL2ExitClaimQueueResult<ExitClaim> {
        self.validate_open_request(&request)?;
        let nullifier_root = private_root("MONERO-L2-EXIT-NULLIFIER", &request.nullifier);
        let replay_fence_root = private_root("MONERO-L2-EXIT-REPLAY-FENCE", &request.replay_fence);

        if self.nullifier_index.contains(&nullifier_root)
            || self.replay_fence_index.contains(&replay_fence_root)
        {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("exit claim replay fence or nullifier already exists".to_string());
        }

        let sequence = self.counters.opened_claims.saturating_add(1);
        let required_finality_depth = request.lane.finality_depth(&self.config);
        let expires_at_height = request
            .opened_at_height
            .saturating_add(request.lane.ttl_blocks(&self.config));
        let watcher_certificate_root = request
            .watcher_certificate_root
            .unwrap_or_else(empty_watcher_certificate_root);
        let liquidity_sponsor_root = request
            .liquidity_sponsor_root
            .unwrap_or_else(empty_liquidity_sponsor_root);
        let fee_subsidy_root = request
            .fee_subsidy_root
            .unwrap_or_else(empty_fee_subsidy_root);
        let claim_id = claim_id(
            &request.exit_commitment,
            &request.subaddress_commitment_root,
            &nullifier_root,
            &replay_fence_root,
            request.lane,
            request.opened_at_height,
            sequence,
        );
        let status = if request.watcher_weight >= request.lane.watcher_weight(&self.config) {
            ClaimStatus::WatcherCertified
        } else {
            ClaimStatus::Open
        };

        let claim = ExitClaim {
            claim_id: claim_id.clone(),
            exit_commitment: request.exit_commitment,
            subaddress_commitment_root: request.subaddress_commitment_root,
            amount_bucket_root: request.amount_bucket_root,
            claimant_set_root: request.claimant_set_root,
            lane: request.lane,
            status,
            privacy_set_size: request.privacy_set_size,
            l2_burn_height: request.l2_burn_height,
            observed_monero_height: request.observed_monero_height,
            required_finality_depth,
            watcher_certificate_root,
            watcher_weight: request.watcher_weight,
            liquidity_sponsor_root,
            fee_subsidy_root,
            nullifier_root: nullifier_root.clone(),
            replay_fence_root: replay_fence_root.clone(),
            opened_at_height: request.opened_at_height,
            updated_at_height: request.opened_at_height,
            expires_at_height,
            sequence,
        };

        let fence = ReplayFence {
            fence_id: replay_fence_id(&claim_id, &nullifier_root, &replay_fence_root),
            claim_id: claim_id.clone(),
            nullifier_root: nullifier_root.clone(),
            replay_fence_root: replay_fence_root.clone(),
            opened_at_height: claim.opened_at_height,
            expires_at_height: claim
                .opened_at_height
                .saturating_add(self.config.replay_fence_ttl_blocks.max(1)),
            consumed_at_height: None,
        };

        self.nullifier_index.insert(nullifier_root);
        self.replay_fence_index.insert(replay_fence_root);
        self.replay_fences.insert(fence.fence_id.clone(), fence);
        self.claims.insert(claim_id.clone(), claim.clone());
        self.counters.opened_claims = sequence;
        match claim.lane {
            ClaimLane::Fast => {
                self.counters.fast_lane_claims = self.counters.fast_lane_claims.saturating_add(1)
            }
            ClaimLane::Standard => {
                self.counters.standard_lane_claims =
                    self.counters.standard_lane_claims.saturating_add(1)
            }
        }
        self.push_event(
            "claim_opened",
            claim.opened_at_height,
            json!({
                "claim_id": claim.claim_id,
                "lane": claim.lane.as_str(),
                "claim_root": claim.claim_root(),
                "status": claim.status.as_str(),
            }),
        );
        Ok(claim)
    }

    pub fn advance_claim(
        &mut self,
        request: AdvanceClaimRequest,
    ) -> MoneroL2ExitClaimQueueResult<ExitClaim> {
        let mut claim = self
            .claims
            .get(&request.claim_id)
            .cloned()
            .ok_or_else(|| format!("unknown exit claim {}", request.claim_id))?;
        if claim.status.is_terminal() {
            return Err(format!("exit claim {} is terminal", claim.claim_id));
        }
        if request.advanced_at_height > claim.expires_at_height
            && !matches!(request.action, ClaimAdvance::Expire | ClaimAdvance::Reject)
        {
            return Err(format!("exit claim {} has expired", claim.claim_id));
        }

        match request.action {
            ClaimAdvance::WatcherCertificate => {
                let root = required_root(
                    request.watcher_certificate_root,
                    "watcher certificate root is required",
                )?;
                claim.watcher_certificate_root = root;
                claim.watcher_weight = request
                    .watcher_weight
                    .ok_or_else(|| "watcher weight is required".to_string())?;
                if claim.watcher_weight < claim.lane.watcher_weight(&self.config) {
                    return Err("watcher certificate weight below lane threshold".to_string());
                }
                claim.status = ClaimStatus::WatcherCertified;
            }
            ClaimAdvance::LiquiditySponsor => {
                if claim.lane != ClaimLane::Fast {
                    return Err(
                        "liquidity sponsor can only be attached to fast lane claims".to_string()
                    );
                }
                claim.liquidity_sponsor_root = required_root(
                    request.liquidity_sponsor_root,
                    "liquidity sponsor root is required",
                )?;
                claim.status = ClaimStatus::SponsorLocked;
                self.counters.sponsored_claims = self.counters.sponsored_claims.saturating_add(1);
            }
            ClaimAdvance::FeeSubsidy => {
                claim.fee_subsidy_root =
                    required_root(request.fee_subsidy_root, "fee subsidy root is required")?;
                claim.status = ClaimStatus::SubsidyApplied;
                self.counters.subsidized_claims = self.counters.subsidized_claims.saturating_add(1);
            }
            ClaimAdvance::FinalityObservation => {
                let observed = request
                    .observed_monero_height
                    .ok_or_else(|| "observed monero height is required".to_string())?;
                claim.observed_monero_height = observed;
                if let Some(depth) = request.finality_depth {
                    claim.required_finality_depth = claim.required_finality_depth.max(depth.max(1));
                }
                claim.status = if observed.saturating_sub(claim.l2_burn_height)
                    >= claim.required_finality_depth
                {
                    ClaimStatus::ReadyToSettle
                } else {
                    ClaimStatus::FinalityPending
                };
            }
            ClaimAdvance::Ready => {
                if claim.watcher_weight < claim.lane.watcher_weight(&self.config) {
                    return Err("claim lacks watcher certificate quorum".to_string());
                }
                if claim
                    .observed_monero_height
                    .saturating_sub(claim.l2_burn_height)
                    < claim.required_finality_depth
                {
                    return Err("claim lacks required monero finality depth".to_string());
                }
                claim.status = ClaimStatus::ReadyToSettle;
            }
            ClaimAdvance::Expire => {
                claim.status = ClaimStatus::Expired;
                self.counters.expired_claims = self.counters.expired_claims.saturating_add(1);
            }
            ClaimAdvance::Reject => {
                claim.status = ClaimStatus::Rejected;
                self.counters.rejected_claims = self.counters.rejected_claims.saturating_add(1);
            }
        }

        claim.updated_at_height = request.advanced_at_height;
        if let Some(note_root) = request.note_root {
            self.push_event(
                "claim_advance_note",
                request.advanced_at_height,
                json!({
                    "claim_id": claim.claim_id,
                    "action": request.action.as_str(),
                    "note_root": note_root,
                }),
            );
        }
        self.claims.insert(claim.claim_id.clone(), claim.clone());
        self.counters.advanced_claims = self.counters.advanced_claims.saturating_add(1);
        self.push_event(
            "claim_advanced",
            request.advanced_at_height,
            json!({
                "claim_id": claim.claim_id,
                "action": request.action.as_str(),
                "status": claim.status.as_str(),
                "claim_root": claim.claim_root(),
            }),
        );
        Ok(claim)
    }

    pub fn settle_claim(
        &mut self,
        request: SettleClaimRequest,
    ) -> MoneroL2ExitClaimQueueResult<ClaimReceipt> {
        let mut claim = self
            .claims
            .get(&request.claim_id)
            .cloned()
            .ok_or_else(|| format!("unknown exit claim {}", request.claim_id))?;
        if claim.status != ClaimStatus::ReadyToSettle {
            return Err(format!(
                "exit claim {} is not ready to settle",
                request.claim_id
            ));
        }
        if request.settled_monero_height < claim.observed_monero_height {
            return Err("settled monero height cannot precede observed height".to_string());
        }

        let sequence = self.counters.settled_claims.saturating_add(1);
        let receipt_id = receipt_id(&claim.claim_id, &request.receipt_root, sequence);
        let receipt = ClaimReceipt {
            receipt_id: receipt_id.clone(),
            claim_id: claim.claim_id.clone(),
            lane: claim.lane,
            exit_commitment: claim.exit_commitment.clone(),
            settlement_tx_root: request.settlement_tx_root,
            settlement_checkpoint_root: request.settlement_checkpoint_root,
            receipt_root: request.receipt_root,
            watcher_certificate_root: claim.watcher_certificate_root.clone(),
            liquidity_sponsor_root: claim.liquidity_sponsor_root.clone(),
            fee_subsidy_root: claim.fee_subsidy_root.clone(),
            nullifier_root: claim.nullifier_root.clone(),
            replay_fence_root: claim.replay_fence_root.clone(),
            settled_monero_height: request.settled_monero_height,
            settled_at_height: request.settled_at_height,
            sequence,
        };

        claim.status = ClaimStatus::Settled;
        claim.updated_at_height = request.settled_at_height;
        self.claims.insert(claim.claim_id.clone(), claim.clone());
        self.receipts.insert(receipt_id.clone(), receipt.clone());
        for fence in self.replay_fences.values_mut() {
            if fence.claim_id == claim.claim_id {
                fence.consumed_at_height = Some(request.settled_at_height);
            }
        }
        self.counters.settled_claims = sequence;
        self.refresh_checkpoint(request.settled_at_height);
        self.push_event(
            "claim_settled",
            request.settled_at_height,
            json!({
                "claim_id": claim.claim_id,
                "receipt_id": receipt_id,
                "lane": claim.lane.as_str(),
                "receipt_root": receipt.receipt_root,
            }),
        );
        Ok(receipt)
    }

    pub fn roots(&self) -> QueueRoots {
        let config_root = record_hash(
            "MONERO-L2-EXIT-CLAIM-QUEUE-CONFIG",
            &self.config.public_record(),
        );
        let claim_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-CLAIMS",
            &map_records(&self.claims, ExitClaim::public_record),
        );
        let open_claim_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-OPEN-CLAIMS",
            &self
                .claims
                .values()
                .filter(|claim| !claim.status.is_terminal())
                .map(ExitClaim::public_record)
                .collect::<Vec<_>>(),
        );
        let fast_lane_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-FAST-LANE",
            &self
                .claims
                .values()
                .filter(|claim| claim.lane == ClaimLane::Fast)
                .map(ExitClaim::public_record)
                .collect::<Vec<_>>(),
        );
        let standard_lane_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-STANDARD-LANE",
            &self
                .claims
                .values()
                .filter(|claim| claim.lane == ClaimLane::Standard)
                .map(ExitClaim::public_record)
                .collect::<Vec<_>>(),
        );
        let subaddress_commitment_root = merkle_string_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-SUBADDRESS-ROOTS",
            self.claims
                .values()
                .map(|claim| claim.subaddress_commitment_root.clone())
                .collect(),
        );
        let watcher_certificate_root = merkle_string_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-WATCHER-CERT-ROOTS",
            self.claims
                .values()
                .map(|claim| claim.watcher_certificate_root.clone())
                .collect(),
        );
        let liquidity_sponsor_root = merkle_string_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-LIQUIDITY-SPONSOR-ROOTS",
            self.claims
                .values()
                .map(|claim| claim.liquidity_sponsor_root.clone())
                .collect(),
        );
        let fee_subsidy_root = merkle_string_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-FEE-SUBSIDY-ROOTS",
            self.claims
                .values()
                .map(|claim| claim.fee_subsidy_root.clone())
                .collect(),
        );
        let nullifier_root = merkle_string_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-NULLIFIERS",
            self.nullifier_index.iter().cloned().collect(),
        );
        let replay_fence_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-REPLAY-FENCES",
            &map_records(&self.replay_fences, ReplayFence::public_record),
        );
        let receipt_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-RECEIPTS",
            &map_records(&self.receipts, ClaimReceipt::public_record),
        );
        let settlement_checkpoint_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-CHECKPOINTS",
            &map_records(
                &self.settlement_checkpoints,
                SettlementCheckpoint::public_record,
            ),
        );
        let event_root = merkle_root("MONERO-L2-EXIT-CLAIM-QUEUE-EVENTS", &self.events);
        let state_record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": config_root,
            "claim_root": claim_root,
            "open_claim_root": open_claim_root,
            "fast_lane_root": fast_lane_root,
            "standard_lane_root": standard_lane_root,
            "subaddress_commitment_root": subaddress_commitment_root,
            "watcher_certificate_root": watcher_certificate_root,
            "liquidity_sponsor_root": liquidity_sponsor_root,
            "fee_subsidy_root": fee_subsidy_root,
            "nullifier_root": nullifier_root,
            "replay_fence_root": replay_fence_root,
            "receipt_root": receipt_root,
            "settlement_checkpoint_root": settlement_checkpoint_root,
            "event_root": event_root,
            "counters": self.counters.public_record(),
        });
        let state_root = record_hash("MONERO-L2-EXIT-CLAIM-QUEUE-STATE", &state_record);

        QueueRoots {
            config_root,
            claim_root,
            open_claim_root,
            fast_lane_root,
            standard_lane_root,
            subaddress_commitment_root,
            watcher_certificate_root,
            liquidity_sponsor_root,
            fee_subsidy_root,
            nullifier_root,
            replay_fence_root,
            receipt_root,
            settlement_checkpoint_root,
            event_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
            "claims": map_records(&self.claims, ExitClaim::public_record),
            "receipts": map_records(&self.receipts, ClaimReceipt::public_record),
            "replay_fences": map_records(&self.replay_fences, ReplayFence::public_record),
            "settlement_checkpoints": map_records(
                &self.settlement_checkpoints,
                SettlementCheckpoint::public_record,
            ),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn validate_open_request(
        &self,
        request: &OpenClaimRequest,
    ) -> MoneroL2ExitClaimQueueResult<()> {
        if request.exit_commitment.is_empty() {
            return Err("exit commitment is required".to_string());
        }
        if request.subaddress_commitment_root.is_empty() {
            return Err("subaddress commitment root is required".to_string());
        }
        if request.amount_bucket_root.is_empty() {
            return Err("amount bucket root is required".to_string());
        }
        if request.claimant_set_root.is_empty() {
            return Err("claimant set root is required".to_string());
        }
        if request.nullifier.is_empty() {
            return Err("nullifier is required".to_string());
        }
        if request.replay_fence.is_empty() {
            return Err("replay fence is required".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured floor".to_string());
        }
        if self
            .claims
            .values()
            .filter(|claim| !claim.status.is_terminal())
            .count()
            >= self.config.max_open_claims
        {
            return Err("open claim queue is full".to_string());
        }
        if request.lane == ClaimLane::Fast && request.liquidity_sponsor_root.is_none() {
            return Err("fast lane claims require a liquidity sponsor root".to_string());
        }
        if request.lane == ClaimLane::Fast
            && request.watcher_weight < request.lane.watcher_weight(&self.config)
        {
            return Err("fast lane claims require fast watcher certificate quorum".to_string());
        }
        Ok(())
    }

    fn refresh_checkpoint(&mut self, height: u64) {
        let recent_receipts = self
            .receipts
            .values()
            .rev()
            .take(self.config.max_checkpoint_claims)
            .cloned()
            .collect::<Vec<_>>();
        if recent_receipts.is_empty() {
            return;
        }
        let receipt_records = recent_receipts
            .iter()
            .map(ClaimReceipt::public_record)
            .collect::<Vec<_>>();
        let claim_receipt_root = merkle_root(
            "MONERO-L2-EXIT-CLAIM-QUEUE-CHECKPOINT-RECEIPTS",
            &receipt_records,
        );
        let fast_claim_count = recent_receipts
            .iter()
            .filter(|receipt| receipt.lane == ClaimLane::Fast)
            .count() as u64;
        let standard_claim_count = recent_receipts
            .iter()
            .filter(|receipt| receipt.lane == ClaimLane::Standard)
            .count() as u64;
        let min_monero_height = recent_receipts
            .iter()
            .map(|receipt| receipt.settled_monero_height)
            .min()
            .unwrap_or_default();
        let max_monero_height = recent_receipts
            .iter()
            .map(|receipt| receipt.settled_monero_height)
            .max()
            .unwrap_or_default();
        let checkpoint_sequence = self.counters.checkpoints.saturating_add(1);
        let checkpoint_root = domain_hash(
            "MONERO-L2-EXIT-CLAIM-QUEUE-CHECKPOINT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&claim_receipt_root),
                HashPart::Int(height as i128),
                HashPart::Int(checkpoint_sequence as i128),
            ],
            32,
        );
        let checkpoint_id = domain_hash(
            "MONERO-L2-EXIT-CLAIM-QUEUE-CHECKPOINT-ID",
            &[
                HashPart::Str(&checkpoint_root),
                HashPart::Int(checkpoint_sequence as i128),
            ],
            32,
        );
        let checkpoint = SettlementCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            checkpoint_root,
            claim_receipt_root,
            settled_claim_count: recent_receipts.len() as u64,
            fast_claim_count,
            standard_claim_count,
            min_monero_height,
            max_monero_height,
            created_at_height: height,
            state_root: self.state_root_without_checkpoints(),
        };
        self.settlement_checkpoints
            .insert(checkpoint_id, checkpoint);
        self.counters.checkpoints = checkpoint_sequence;
    }

    fn state_root_without_checkpoints(&self) -> String {
        let record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "claims": map_records(&self.claims, ExitClaim::public_record),
            "receipts": map_records(&self.receipts, ClaimReceipt::public_record),
            "replay_fences": map_records(&self.replay_fences, ReplayFence::public_record),
            "counters": self.counters.public_record(),
        });
        record_hash("MONERO-L2-EXIT-CLAIM-QUEUE-CHECKPOINT-STATE", &record)
    }

    fn push_event(&mut self, event_type: &str, height: u64, payload: Value) {
        let event_id = domain_hash(
            "MONERO-L2-EXIT-CLAIM-QUEUE-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(event_type),
                HashPart::Int(height as i128),
                HashPart::Int(self.counters.events.saturating_add(1) as i128),
                HashPart::Json(&payload),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "event_type": event_type,
            "height": height,
            "payload": payload,
        }));
        self.counters.events = self.counters.events.saturating_add(1);
    }
}

pub fn claim_id(
    exit_commitment: &str,
    subaddress_commitment_root: &str,
    nullifier_root: &str,
    replay_fence_root: &str,
    lane: ClaimLane,
    opened_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-EXIT-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(exit_commitment),
            HashPart::Str(subaddress_commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(replay_fence_root),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn receipt_id(claim_id: &str, receipt_root: &str, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-EXIT-CLAIM-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(claim_id),
            HashPart::Str(receipt_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn replay_fence_id(claim_id: &str, nullifier_root: &str, replay_fence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-EXIT-CLAIM-REPLAY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(claim_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(replay_fence_root),
        ],
        32,
    )
}

pub fn private_root(domain: &str, secret: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(secret),
        ],
        32,
    )
}

pub fn record_hash(domain: &str, record: &Value) -> String {
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

pub fn empty_watcher_certificate_root() -> String {
    merkle_root("MONERO-L2-EXIT-CLAIM-QUEUE-EMPTY-WATCHER-CERTS", &[])
}

pub fn empty_liquidity_sponsor_root() -> String {
    merkle_root("MONERO-L2-EXIT-CLAIM-QUEUE-EMPTY-LIQUIDITY-SPONSORS", &[])
}

pub fn empty_fee_subsidy_root() -> String {
    merkle_root("MONERO-L2-EXIT-CLAIM-QUEUE-EMPTY-FEE-SUBSIDIES", &[])
}

fn required_root(root: Option<String>, message: &str) -> MoneroL2ExitClaimQueueResult<String> {
    root.filter(|value| !value.is_empty())
        .ok_or_else(|| message.to_string())
}

fn merkle_string_root(domain: &str, values: Vec<String>) -> String {
    let leaves = values
        .into_iter()
        .map(Value::String)
        .collect::<Vec<Value>>();
    merkle_root(domain, &leaves)
}

fn map_records<T, F>(items: &BTreeMap<String, T>, record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    items.values().map(record).collect()
}
