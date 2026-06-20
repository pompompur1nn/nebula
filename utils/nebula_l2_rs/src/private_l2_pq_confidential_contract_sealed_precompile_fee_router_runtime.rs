use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedPrecompileFeeRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedPrecompileFeeRouterRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_PRECOMPILE_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-precompile-fee-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_PRECOMPILE_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_PRECOMPILE_FEE_ROUTER_SUITE: &str =
    "sealed-confidential-smart-contract-precompile-fee-router-v1";
pub const PRIVATE_PRECOMPILE_FEE_BID_SUITE: &str = "private-precompile-fee-bid-commitment-v1";
pub const PQ_PRECOMPILE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-precompile-commitment-attestation-v1";
pub const LOW_FEE_BATCHING_SUITE: &str = "low-fee-confidential-precompile-routing-batching-v1";
pub const REPLAY_RESISTANCE_SUITE: &str = "sealed-precompile-router-replay-nullifier-v1";
pub const PRIVACY_PRESERVING_STATE_SUITE: &str =
    "privacy-preserving-precompile-router-public-state-root-v1";
pub const ROUTE_EPOCH_SCHEME: &str = "sealed-precompile-router-route-epoch-root-v1";
pub const PRIVATE_FEE_BID_SCHEME: &str = "private-precompile-fee-bid-root-v1";
pub const PRECOMPILE_COMMITMENT_SCHEME: &str = "pq-attested-precompile-commitment-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-precompile-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "sealed-precompile-replay-nullifier-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-precompile-router-batch-root-v1";
pub const ROUTE_SETTLEMENT_SCHEME: &str = "sealed-precompile-router-settlement-root-v1";
pub const PUBLIC_STATE_SNAPSHOT_SCHEME: &str =
    "privacy-preserving-precompile-router-state-snapshot-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_337_728;
pub const DEVNET_EPOCH: u64 = 10_426;
pub const DEFAULT_ROUTE_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_BIDS_PER_ROUTE: usize = 12_288;
pub const DEFAULT_MAX_PRECOMPILE_CALLS_PER_BID: u64 = 8_192;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 6;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 10;
pub const DEFAULT_BASE_PRECOMPILE_MICRO_FEE: u64 = 5;
pub const DEFAULT_MIN_ROUTE_MICRO_FEE_PER_CALL: u64 = 1;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 24_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecompileFamily {
    EcRecover,
    Sha256,
    Ripemd160,
    Identity,
    ModExp,
    EcAdd,
    EcMul,
    Pairing,
    Blake2F,
    PqVerify,
    ConfidentialTransfer,
    SealedContractCall,
}

impl PrecompileFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcRecover => "ec_recover",
            Self::Sha256 => "sha256",
            Self::Ripemd160 => "ripemd160",
            Self::Identity => "identity",
            Self::ModExp => "modexp",
            Self::EcAdd => "ec_add",
            Self::EcMul => "ec_mul",
            Self::Pairing => "pairing",
            Self::Blake2F => "blake2f",
            Self::PqVerify => "pq_verify",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::SealedContractCall => "sealed_contract_call",
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::SealedContractCall => 10_000,
            Self::ConfidentialTransfer => 9_700,
            Self::PqVerify => 9_400,
            Self::Pairing => 8_800,
            Self::ModExp => 8_200,
            Self::EcMul => 7_600,
            Self::EcAdd => 7_200,
            Self::Blake2F => 6_700,
            Self::Sha256 => 6_300,
            Self::Ripemd160 => 5_900,
            Self::EcRecover => 5_500,
            Self::Identity => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteClass {
    Interactive,
    LowFeeBatch,
    OracleCallback,
    BridgeProof,
    Governance,
    Recovery,
    Emergency,
}

impl RouteClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::LowFeeBatch => "low_fee_batch",
            Self::OracleCallback => "oracle_callback",
            Self::BridgeProof => "bridge_proof",
            Self::Governance => "governance",
            Self::Recovery => "recovery",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Recovery => 9_600,
            Self::Governance => 9_000,
            Self::BridgeProof => 8_600,
            Self::OracleCallback => 8_100,
            Self::Interactive => 7_400,
            Self::LowFeeBatch => 6_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Announced,
    CommitOpen,
    PqAttested,
    BatchReady,
    Routing,
    Settled,
    Cancelled,
    Expired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::CommitOpen => "commit_open",
            Self::PqAttested => "pq_attested",
            Self::BatchReady => "batch_ready",
            Self::Routing => "routing",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    ReplayGuarded,
    PqCommitted,
    BatchQueued,
    Routed,
    Repriced,
    Outbid,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::ReplayGuarded => "replay_guarded",
            Self::PqCommitted => "pq_committed",
            Self::BatchQueued => "batch_queued",
            Self::Routed => "routed",
            Self::Repriced => "repriced",
            Self::Outbid => "outbid",
            Self::Refunded => "refunded",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Proposed,
    Authenticated,
    QuorumSigned,
    Applied,
    Challenged,
    Rejected,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authenticated => "authenticated",
            Self::QuorumSigned => "quorum_signed",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}

impl ReplayStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Armed => "armed",
            Self::Consumed => "consumed",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    PqAttested,
    Routed,
    Repriced,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::PqAttested => "pq_attested",
            Self::Routed => "routed",
            Self::Repriced => "repriced",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub route_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_bids_per_route: usize,
    pub max_precompile_calls_per_bid: u64,
    pub max_commitments_per_batch: usize,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub base_precompile_micro_fee: u64,
    pub min_route_micro_fee_per_call: u64,
    pub max_vm_steps_per_batch: u64,
    pub require_pq_attestation: bool,
    pub require_replay_nullifier: bool,
    pub privacy_preserving_public_apis: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            route_window_blocks: DEFAULT_ROUTE_WINDOW_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_bids_per_route: DEFAULT_MAX_BIDS_PER_ROUTE,
            max_precompile_calls_per_bid: DEFAULT_MAX_PRECOMPILE_CALLS_PER_BID,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            base_precompile_micro_fee: DEFAULT_BASE_PRECOMPILE_MICRO_FEE,
            min_route_micro_fee_per_call: DEFAULT_MIN_ROUTE_MICRO_FEE_PER_CALL,
            max_vm_steps_per_batch: DEFAULT_MAX_VM_STEPS_PER_BATCH,
            require_pq_attestation: true,
            require_replay_nullifier: true,
            privacy_preserving_public_apis: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol version: {}",
                self.protocol_version
            ));
        }
        if self.route_window_blocks == 0 {
            return Err("route window must be non-zero".to_string());
        }
        if self.replay_window_blocks < self.route_window_blocks {
            return Err("replay window must cover route window".to_string());
        }
        if self.batch_window_blocks == 0 {
            return Err("batch window must be non-zero".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime floor".to_string());
        }
        if self.min_privacy_set_size < 1_024 {
            return Err("privacy set size below anonymity floor".to_string());
        }
        if self.max_bids_per_route == 0 || self.max_commitments_per_batch == 0 {
            return Err("route and batch limits must be non-zero".to_string());
        }
        if self.max_user_fee_bps + self.operator_fee_bps > MAX_BPS {
            return Err("fee bps exceeds max basis points".to_string());
        }
        if self.base_precompile_micro_fee < self.min_route_micro_fee_per_call {
            return Err("base fee must not be below min route fee".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "route_window_blocks": self.route_window_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_bids_per_route": self.max_bids_per_route,
            "max_precompile_calls_per_bid": self.max_precompile_calls_per_bid,
            "max_commitments_per_batch": self.max_commitments_per_batch,
            "max_user_fee_bps": self.max_user_fee_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "congestion_surcharge_bps": self.congestion_surcharge_bps,
            "base_precompile_micro_fee": self.base_precompile_micro_fee,
            "min_route_micro_fee_per_call": self.min_route_micro_fee_per_call,
            "max_vm_steps_per_batch": self.max_vm_steps_per_batch,
            "require_pq_attestation": self.require_pq_attestation,
            "require_replay_nullifier": self.require_replay_nullifier,
            "privacy_preserving_public_apis": self.privacy_preserving_public_apis,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub route_epochs: u64,
    pub private_fee_bids: u64,
    pub precompile_commitments: u64,
    pub pq_attestations: u64,
    pub replay_nullifiers: u64,
    pub low_fee_batches: u64,
    pub route_settlements: u64,
    pub public_state_snapshots: u64,
    pub duplicate_replay_rejections: u64,
    pub repriced_bids: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "route_epochs": self.route_epochs,
            "private_fee_bids": self.private_fee_bids,
            "precompile_commitments": self.precompile_commitments,
            "pq_attestations": self.pq_attestations,
            "replay_nullifiers": self.replay_nullifiers,
            "low_fee_batches": self.low_fee_batches,
            "route_settlements": self.route_settlements,
            "public_state_snapshots": self.public_state_snapshots,
            "duplicate_replay_rejections": self.duplicate_replay_rejections,
            "repriced_bids": self.repriced_bids,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub route_epoch_root: String,
    pub private_fee_bid_root: String,
    pub precompile_commitment_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub low_fee_batch_root: String,
    pub route_settlement_root: String,
    pub public_state_snapshot_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "route_epoch_root": self.route_epoch_root,
            "private_fee_bid_root": self.private_fee_bid_root,
            "precompile_commitment_root": self.precompile_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "low_fee_batch_root": self.low_fee_batch_root,
            "route_settlement_root": self.route_settlement_root,
            "public_state_snapshot_root": self.public_state_snapshot_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteEpochInput {
    pub family: PrecompileFamily,
    pub route_class: RouteClass,
    pub contract_id: String,
    pub precompile_selector_commitment: String,
    pub epoch: u64,
    pub start_height: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivatePrecompileFeeBidInput {
    pub route_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub max_micro_fee_per_call: u64,
    pub call_count_commitment: String,
    pub submitted_height: u64,
    pub expiry_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPrecompileCommitmentInput {
    pub route_id: String,
    pub bid_id: String,
    pub precompile_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchInput {
    pub route_id: String,
    pub bid_ids: Vec<String>,
    pub opened_height: u64,
    pub congestion_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteSettlementInput {
    pub route_id: String,
    pub batch_id: String,
    pub accepted_bid_ids: Vec<String>,
    pub settlement_height: u64,
    pub state_transition_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteEpoch {
    pub route_id: String,
    pub family: PrecompileFamily,
    pub route_class: RouteClass,
    pub contract_id: String,
    pub precompile_selector_commitment: String,
    pub status: RouteStatus,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub privacy_set_size: u64,
    pub route_capacity_calls: u64,
    pub base_micro_fee_per_call: u64,
    pub priority_weight: u64,
    pub bid_commitment_root: String,
    pub replay_nullifier_root: String,
    pub pq_attestation_root: String,
    pub public_state_root: String,
}

impl RouteEpoch {
    pub fn from_input(config: &Config, input: RouteEpochInput) -> Result<Self> {
        if input.contract_id.is_empty() {
            return Err("contract id must be non-empty".to_string());
        }
        if input.precompile_selector_commitment.is_empty() {
            return Err("precompile selector commitment must be non-empty".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("route privacy set below configured floor".to_string());
        }
        let route_id = route_epoch_id(
            input.family,
            input.route_class,
            &input.contract_id,
            &input.precompile_selector_commitment,
            input.epoch,
            input.start_height,
        );
        let route_capacity_calls = config
            .max_precompile_calls_per_bid
            .saturating_mul(config.max_bids_per_route as u64);
        let priority_weight = input
            .family
            .base_weight()
            .saturating_add(input.route_class.priority_weight())
            .saturating_div(2);
        Ok(Self {
            route_id,
            family: input.family,
            route_class: input.route_class,
            contract_id: input.contract_id,
            precompile_selector_commitment: input.precompile_selector_commitment,
            status: RouteStatus::CommitOpen,
            epoch: input.epoch,
            start_height: input.start_height,
            end_height: input
                .start_height
                .saturating_add(config.route_window_blocks),
            privacy_set_size: input.privacy_set_size,
            route_capacity_calls,
            base_micro_fee_per_call: config.base_precompile_micro_fee,
            priority_weight,
            bid_commitment_root: record_root(PRIVATE_FEE_BID_SCHEME, &[]),
            replay_nullifier_root: record_root(REPLAY_NULLIFIER_SCHEME, &[]),
            pq_attestation_root: record_root(PQ_ATTESTATION_SCHEME, &[]),
            public_state_root: empty_root("route-public-state"),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "family": self.family.as_str(),
            "route_class": self.route_class.as_str(),
            "contract_id": self.contract_id,
            "precompile_selector_commitment": self.precompile_selector_commitment,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "privacy_set_size": self.privacy_set_size,
            "route_capacity_calls": self.route_capacity_calls,
            "base_micro_fee_per_call": self.base_micro_fee_per_call,
            "priority_weight": self.priority_weight,
            "bid_commitment_root": self.bid_commitment_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "public_state_root": self.public_state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivatePrecompileFeeBid {
    pub bid_id: String,
    pub route_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub call_count_commitment: String,
    pub status: BidStatus,
    pub max_micro_fee_per_call: u64,
    pub effective_micro_fee_cap: u64,
    pub submitted_height: u64,
    pub expiry_height: u64,
    pub replay_nullifier: String,
    pub pq_commitment_id: Option<String>,
    pub batch_id: Option<String>,
}

impl PrivatePrecompileFeeBid {
    pub fn from_input(config: &Config, input: PrivatePrecompileFeeBidInput) -> Result<Self> {
        if input.route_id.is_empty() {
            return Err("route id must be non-empty".to_string());
        }
        if input.bidder_commitment.is_empty() || input.sealed_fee_bid_root.is_empty() {
            return Err("bid commitments must be non-empty".to_string());
        }
        if input.max_micro_fee_per_call < config.min_route_micro_fee_per_call {
            return Err("bid fee cap below route minimum".to_string());
        }
        if input.expiry_height <= input.submitted_height {
            return Err("bid expiry must be after submission".to_string());
        }
        let bid_id = private_precompile_fee_bid_id(
            &input.route_id,
            &input.bidder_commitment,
            &input.sealed_fee_bid_root,
            input.submitted_height,
        );
        let replay_nullifier = replay_nullifier_id(
            &input.route_id,
            &bid_id,
            &input.bidder_commitment,
            &input.sealed_fee_bid_root,
        );
        Ok(Self {
            bid_id,
            route_id: input.route_id,
            bidder_commitment: input.bidder_commitment,
            sealed_fee_bid_root: input.sealed_fee_bid_root,
            call_count_commitment: input.call_count_commitment,
            status: BidStatus::ReplayGuarded,
            max_micro_fee_per_call: input.max_micro_fee_per_call,
            effective_micro_fee_cap: input.max_micro_fee_per_call,
            submitted_height: input.submitted_height,
            expiry_height: input.expiry_height,
            replay_nullifier,
            pq_commitment_id: None,
            batch_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "route_id": self.route_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_fee_bid_root": self.sealed_fee_bid_root,
            "call_count_commitment": self.call_count_commitment,
            "status": self.status.as_str(),
            "max_micro_fee_per_call": self.max_micro_fee_per_call,
            "effective_micro_fee_cap": self.effective_micro_fee_cap,
            "submitted_height": self.submitted_height,
            "expiry_height": self.expiry_height,
            "replay_nullifier": self.replay_nullifier,
            "pq_commitment_id": self.pq_commitment_id,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrecompileCommitment {
    pub commitment_id: String,
    pub route_id: String,
    pub bid_id: String,
    pub precompile_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_commitment: String,
    pub status: CommitmentStatus,
    pub pq_security_bits: u16,
    pub height: u64,
    pub attestation_id: String,
}

impl PrecompileCommitment {
    pub fn from_input(config: &Config, input: PqPrecompileCommitmentInput) -> Result<Self> {
        if input.route_id.is_empty() || input.bid_id.is_empty() {
            return Err("route id and bid id must be non-empty".to_string());
        }
        if input.precompile_commitment_root.is_empty()
            || input.transcript_root.is_empty()
            || input.pq_public_key_commitment.is_empty()
        {
            return Err("precompile commitment material must be non-empty".to_string());
        }
        let commitment_id = precompile_commitment_id(
            &input.route_id,
            &input.bid_id,
            &input.precompile_commitment_root,
            input.height,
        );
        let attestation_id = pq_precompile_attestation_id(
            &commitment_id,
            &input.route_id,
            &input.bid_id,
            input.height,
        );
        Ok(Self {
            commitment_id,
            route_id: input.route_id,
            bid_id: input.bid_id,
            precompile_commitment_root: input.precompile_commitment_root,
            transcript_root: input.transcript_root,
            pq_public_key_commitment: input.pq_public_key_commitment,
            status: CommitmentStatus::QuorumSigned,
            pq_security_bits: config.min_pq_security_bits,
            height: input.height,
            attestation_id,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "route_id": self.route_id,
            "bid_id": self.bid_id,
            "precompile_commitment_root": self.precompile_commitment_root,
            "transcript_root": self.transcript_root,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "height": self.height,
            "attestation_id": self.attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPrecompileAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub route_id: String,
    pub bid_id: String,
    pub attestor_set_root: String,
    pub signature_root: String,
    pub status: CommitmentStatus,
    pub pq_security_bits: u16,
    pub height: u64,
}

impl PqPrecompileAttestation {
    pub fn from_commitment(commitment: &PrecompileCommitment) -> Self {
        let attestor_set_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:ATTESTOR-SET",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&commitment.pq_public_key_commitment),
            ],
            32,
        );
        let signature_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:ATTESTATION-SIGNATURE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&commitment.transcript_root),
            ],
            32,
        );
        Self {
            attestation_id: commitment.attestation_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            route_id: commitment.route_id.clone(),
            bid_id: commitment.bid_id.clone(),
            attestor_set_root,
            signature_root,
            status: CommitmentStatus::Applied,
            pq_security_bits: commitment.pq_security_bits,
            height: commitment.height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "route_id": self.route_id,
            "bid_id": self.bid_id,
            "attestor_set_root": self.attestor_set_root,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_id: String,
    pub route_id: String,
    pub bid_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub status: ReplayStatus,
    pub reserved_height: u64,
    pub expiry_height: u64,
}

impl ReplayNullifier {
    pub fn from_bid(config: &Config, bid: &PrivatePrecompileFeeBid) -> Self {
        Self {
            nullifier_id: bid.replay_nullifier.clone(),
            route_id: bid.route_id.clone(),
            bid_id: bid.bid_id.clone(),
            bidder_commitment: bid.bidder_commitment.clone(),
            sealed_fee_bid_root: bid.sealed_fee_bid_root.clone(),
            status: ReplayStatus::Armed,
            reserved_height: bid.submitted_height,
            expiry_height: bid
                .submitted_height
                .saturating_add(config.replay_window_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "route_id": self.route_id,
            "bid_id": self.bid_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_fee_bid_root": self.sealed_fee_bid_root,
            "status": self.status.as_str(),
            "reserved_height": self.reserved_height,
            "expiry_height": self.expiry_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub route_id: String,
    pub bid_ids: Vec<String>,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub congestion_bps: u64,
    pub aggregate_micro_fee_cap: u64,
    pub batch_rebate_micro_fee: u64,
    pub bid_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
}

impl LowFeeBatch {
    pub fn from_input(
        config: &Config,
        input: LowFeeBatchInput,
        bids: &[PrivatePrecompileFeeBid],
    ) -> Result<Self> {
        if input.route_id.is_empty() {
            return Err("route id must be non-empty".to_string());
        }
        if input.bid_ids.is_empty() {
            return Err("batch requires at least one bid".to_string());
        }
        if input.bid_ids.len() > config.max_commitments_per_batch {
            return Err("batch exceeds commitment limit".to_string());
        }
        let bid_ids = input.bid_ids;
        let bid_set = bid_ids.iter().cloned().collect::<BTreeSet<_>>();
        let aggregate_micro_fee_cap = bids
            .iter()
            .filter(|bid| bid_set.contains(&bid.bid_id))
            .map(|bid| effective_micro_fee_cap(config, bid, input.congestion_bps))
            .sum::<u64>();
        let batch_id = low_fee_batch_id(&input.route_id, &bid_ids, input.opened_height);
        let bid_root = merkle_root(
            "sealed-precompile-fee-router-low-fee-batch-bid-id-root-v1",
            &bid_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let batch_rebate_micro_fee = aggregate_micro_fee_cap
            .saturating_mul(config.batch_rebate_bps)
            .saturating_div(MAX_BPS);
        Ok(Self {
            batch_id,
            route_id: input.route_id,
            bid_ids,
            status: BatchStatus::Sealed,
            opened_height: input.opened_height,
            sealed_height: input
                .opened_height
                .saturating_add(config.batch_window_blocks),
            congestion_bps: input.congestion_bps.min(config.congestion_surcharge_bps),
            aggregate_micro_fee_cap,
            batch_rebate_micro_fee,
            bid_root,
            pq_attestation_root: record_root(PQ_ATTESTATION_SCHEME, &[]),
            replay_nullifier_root: record_root(REPLAY_NULLIFIER_SCHEME, &[]),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "route_id": self.route_id,
            "bid_count": self.bid_ids.len(),
            "bid_root": self.bid_root,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "congestion_bps": self.congestion_bps,
            "aggregate_micro_fee_cap": self.aggregate_micro_fee_cap,
            "batch_rebate_micro_fee": self.batch_rebate_micro_fee,
            "pq_attestation_root": self.pq_attestation_root,
            "replay_nullifier_root": self.replay_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteSettlement {
    pub settlement_id: String,
    pub route_id: String,
    pub batch_id: String,
    pub accepted_bid_root: String,
    pub accepted_bid_count: usize,
    pub settlement_height: u64,
    pub state_transition_root: String,
    pub public_state_root: String,
    pub operator_fee_micro: u64,
    pub user_rebate_micro: u64,
}

impl RouteSettlement {
    pub fn from_input(
        config: &Config,
        input: RouteSettlementInput,
        batch: &LowFeeBatch,
    ) -> Result<Self> {
        if input.route_id != batch.route_id || input.batch_id != batch.batch_id {
            return Err("settlement input does not match batch".to_string());
        }
        if input.accepted_bid_ids.is_empty() {
            return Err("settlement requires accepted bids".to_string());
        }
        let settlement_id =
            route_settlement_id(&input.route_id, &input.batch_id, input.settlement_height);
        let accepted_bid_root = merkle_root(
            "sealed-precompile-fee-router-accepted-bid-id-root-v1",
            &input
                .accepted_bid_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let operator_fee_micro = batch
            .aggregate_micro_fee_cap
            .saturating_mul(config.operator_fee_bps)
            .saturating_div(MAX_BPS);
        let user_rebate_micro = batch.batch_rebate_micro_fee;
        let public_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:SETTLEMENT-PUBLIC-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&settlement_id),
                HashPart::Str(&accepted_bid_root),
                HashPart::Str(&input.state_transition_root),
            ],
            32,
        );
        Ok(Self {
            settlement_id,
            route_id: input.route_id,
            batch_id: input.batch_id,
            accepted_bid_root,
            accepted_bid_count: input.accepted_bid_ids.len(),
            settlement_height: input.settlement_height,
            state_transition_root: input.state_transition_root,
            public_state_root,
            operator_fee_micro,
            user_rebate_micro,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "route_id": self.route_id,
            "batch_id": self.batch_id,
            "accepted_bid_root": self.accepted_bid_root,
            "accepted_bid_count": self.accepted_bid_count,
            "settlement_height": self.settlement_height,
            "state_transition_root": self.state_transition_root,
            "public_state_root": self.public_state_root,
            "operator_fee_micro": self.operator_fee_micro,
            "user_rebate_micro": self.user_rebate_micro,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicStateSnapshot {
    pub snapshot_id: String,
    pub route_id: String,
    pub height: u64,
    pub route_status: RouteStatus,
    pub active_bid_count: usize,
    pub low_fee_batch_count: usize,
    pub public_state_root: String,
    pub privacy_budget_root: String,
}

impl PublicStateSnapshot {
    pub fn new(
        route: &RouteEpoch,
        active_bid_count: usize,
        low_fee_batch_count: usize,
        height: u64,
    ) -> Self {
        let snapshot_id = public_state_snapshot_id(&route.route_id, height);
        let privacy_budget_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:PRIVACY-BUDGET",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&route.route_id),
                HashPart::U64(route.privacy_set_size),
                HashPart::U64(active_bid_count as u64),
            ],
            32,
        );
        let public_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:SNAPSHOT-PUBLIC-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&snapshot_id),
                HashPart::Json(&route.public_record()),
                HashPart::U64(low_fee_batch_count as u64),
            ],
            32,
        );
        Self {
            snapshot_id,
            route_id: route.route_id.clone(),
            height,
            route_status: route.status,
            active_bid_count,
            low_fee_batch_count,
            public_state_root,
            privacy_budget_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "route_id": self.route_id,
            "height": self.height,
            "route_status": self.route_status.as_str(),
            "active_bid_count": self.active_bid_count,
            "low_fee_batch_count": self.low_fee_batch_count,
            "public_state_root": self.public_state_root,
            "privacy_budget_root": self.privacy_budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub route_epochs: Vec<RouteEpoch>,
    pub private_fee_bids: Vec<PrivatePrecompileFeeBid>,
    pub precompile_commitments: Vec<PrecompileCommitment>,
    pub pq_attestations: Vec<PqPrecompileAttestation>,
    pub replay_nullifiers: Vec<ReplayNullifier>,
    pub low_fee_batches: Vec<LowFeeBatch>,
    pub route_settlements: Vec<RouteSettlement>,
    pub public_state_snapshots: Vec<PublicStateSnapshot>,
}

impl State {
    pub fn devnet() -> Self {
        Self::demo()
    }

    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            route_epochs: Vec::new(),
            private_fee_bids: Vec::new(),
            precompile_commitments: Vec::new(),
            pq_attestations: Vec::new(),
            replay_nullifiers: Vec::new(),
            low_fee_batches: Vec::new(),
            route_settlements: Vec::new(),
            public_state_snapshots: Vec::new(),
        };
        state.refresh_roots_and_counters();
        Ok(state)
    }

    pub fn demo() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config).expect("devnet config is valid");
        let route = RouteEpoch::from_input(
            &state.config,
            RouteEpochInput {
                family: PrecompileFamily::PqVerify,
                route_class: RouteClass::LowFeeBatch,
                contract_id: demo_hash("router-demo-contract"),
                precompile_selector_commitment: demo_hash("pq-verify-selector"),
                epoch: DEVNET_EPOCH,
                start_height: DEVNET_HEIGHT,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            },
        )
        .expect("demo route is valid");
        state.route_epochs.push(route.clone());

        let bid_inputs = [
            ("alpha", 8, 0),
            ("bravo", 7, 1),
            ("charlie", 6, 2),
            ("delta", 5, 3),
        ];
        for (label, fee, offset) in bid_inputs {
            let bid = PrivatePrecompileFeeBid::from_input(
                &state.config,
                PrivatePrecompileFeeBidInput {
                    route_id: route.route_id.clone(),
                    bidder_commitment: demo_hash(&format!("{label}-bidder")),
                    sealed_fee_bid_root: demo_hash(&format!("{label}-sealed-fee")),
                    max_micro_fee_per_call: fee,
                    call_count_commitment: demo_hash(&format!("{label}-call-count")),
                    submitted_height: DEVNET_HEIGHT + offset,
                    expiry_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
                },
            )
            .expect("demo bid is valid");
            state
                .replay_nullifiers
                .push(ReplayNullifier::from_bid(&state.config, &bid));
            state.private_fee_bids.push(bid);
        }

        let first_bid = state.private_fee_bids[0].clone();
        let commitment = PrecompileCommitment::from_input(
            &state.config,
            PqPrecompileCommitmentInput {
                route_id: route.route_id.clone(),
                bid_id: first_bid.bid_id.clone(),
                precompile_commitment_root: demo_hash("precompile-commitment-root"),
                transcript_root: demo_hash("precompile-transcript-root"),
                pq_public_key_commitment: demo_hash("pq-public-key-commitment"),
                height: DEVNET_HEIGHT + 6,
            },
        )
        .expect("demo commitment is valid");
        state
            .pq_attestations
            .push(PqPrecompileAttestation::from_commitment(&commitment));
        state.precompile_commitments.push(commitment.clone());
        if let Some(bid) = state
            .private_fee_bids
            .iter_mut()
            .find(|bid| bid.bid_id == first_bid.bid_id)
        {
            bid.status = BidStatus::PqCommitted;
            bid.pq_commitment_id = Some(commitment.commitment_id.clone());
        }

        let bid_ids = state
            .private_fee_bids
            .iter()
            .map(|bid| bid.bid_id.clone())
            .collect::<Vec<_>>();
        let batch = LowFeeBatch::from_input(
            &state.config,
            LowFeeBatchInput {
                route_id: route.route_id.clone(),
                bid_ids: bid_ids.clone(),
                opened_height: DEVNET_HEIGHT + 8,
                congestion_bps: 4,
            },
            &state.private_fee_bids,
        )
        .expect("demo batch is valid");
        for bid in &mut state.private_fee_bids {
            if bid_ids.contains(&bid.bid_id) {
                bid.status = BidStatus::BatchQueued;
                bid.batch_id = Some(batch.batch_id.clone());
            }
        }
        state.low_fee_batches.push(batch.clone());

        let settlement = RouteSettlement::from_input(
            &state.config,
            RouteSettlementInput {
                route_id: route.route_id.clone(),
                batch_id: batch.batch_id.clone(),
                accepted_bid_ids: bid_ids,
                settlement_height: DEVNET_HEIGHT + 12,
                state_transition_root: demo_hash("precompile-router-transition-root"),
            },
            &batch,
        )
        .expect("demo settlement is valid");
        state.route_settlements.push(settlement);

        if let Some(route) = state.route_epochs.first_mut() {
            route.status = RouteStatus::Settled;
        }
        let snapshot = PublicStateSnapshot::new(
            state.route_epochs.first().expect("demo route exists"),
            0,
            state.low_fee_batches.len(),
            DEVNET_HEIGHT + 13,
        );
        state.public_state_snapshots.push(snapshot);
        state.refresh_roots_and_counters();
        state
    }

    pub fn refresh_roots_and_counters(&mut self) {
        self.counters = Counters {
            route_epochs: self.route_epochs.len() as u64,
            private_fee_bids: self.private_fee_bids.len() as u64,
            precompile_commitments: self.precompile_commitments.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            replay_nullifiers: self.replay_nullifiers.len() as u64,
            low_fee_batches: self.low_fee_batches.len() as u64,
            route_settlements: self.route_settlements.len() as u64,
            public_state_snapshots: self.public_state_snapshots.len() as u64,
            duplicate_replay_rejections: self.counters.duplicate_replay_rejections,
            repriced_bids: self
                .private_fee_bids
                .iter()
                .filter(|bid| bid.status == BidStatus::Repriced)
                .count() as u64,
        };
        self.roots = Roots {
            route_epoch_root: record_root(
                ROUTE_EPOCH_SCHEME,
                &self
                    .route_epochs
                    .iter()
                    .map(RouteEpoch::public_record)
                    .collect::<Vec<_>>(),
            ),
            private_fee_bid_root: record_root(
                PRIVATE_FEE_BID_SCHEME,
                &self
                    .private_fee_bids
                    .iter()
                    .map(PrivatePrecompileFeeBid::public_record)
                    .collect::<Vec<_>>(),
            ),
            precompile_commitment_root: record_root(
                PRECOMPILE_COMMITMENT_SCHEME,
                &self
                    .precompile_commitments
                    .iter()
                    .map(PrecompileCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                &self
                    .pq_attestations
                    .iter()
                    .map(PqPrecompileAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_nullifier_root: record_root(
                REPLAY_NULLIFIER_SCHEME,
                &self
                    .replay_nullifiers
                    .iter()
                    .map(ReplayNullifier::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_batch_root: record_root(
                LOW_FEE_BATCH_SCHEME,
                &self
                    .low_fee_batches
                    .iter()
                    .map(LowFeeBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            route_settlement_root: record_root(
                ROUTE_SETTLEMENT_SCHEME,
                &self
                    .route_settlements
                    .iter()
                    .map(RouteSettlement::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_state_snapshot_root: record_root(
                PUBLIC_STATE_SNAPSHOT_SCHEME,
                &self
                    .public_state_snapshots
                    .iter()
                    .map(PublicStateSnapshot::public_record)
                    .collect::<Vec<_>>(),
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "suite": SEALED_PRECOMPILE_FEE_ROUTER_SUITE,
            "private_precompile_fee_bid_suite": PRIVATE_PRECOMPILE_FEE_BID_SUITE,
            "pq_precompile_attestation_suite": PQ_PRECOMPILE_ATTESTATION_SUITE,
            "low_fee_batching_suite": LOW_FEE_BATCHING_SUITE,
            "replay_resistance_suite": REPLAY_RESISTANCE_SUITE,
            "privacy_preserving_state_suite": PRIVACY_PRESERVING_STATE_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

pub fn route_epoch_id(
    family: PrecompileFamily,
    route_class: RouteClass,
    contract_id: &str,
    precompile_selector_commitment: &str,
    epoch: u64,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:ROUTE-EPOCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(family.as_str()),
            HashPart::Str(route_class.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(precompile_selector_commitment),
            HashPart::U64(epoch),
            HashPart::U64(start_height),
        ],
        32,
    )
}

pub fn private_precompile_fee_bid_id(
    route_id: &str,
    bidder_commitment: &str,
    sealed_fee_bid_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:BID-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_bid_root),
            HashPart::U64(submitted_height),
        ],
        32,
    )
}

pub fn precompile_commitment_id(
    route_id: &str,
    bid_id: &str,
    precompile_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:COMMITMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(bid_id),
            HashPart::Str(precompile_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn pq_precompile_attestation_id(
    commitment_id: &str,
    route_id: &str,
    bid_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(commitment_id),
            HashPart::Str(route_id),
            HashPart::Str(bid_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn replay_nullifier_id(
    route_id: &str,
    bid_id: &str,
    bidder_commitment: &str,
    sealed_fee_bid_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:REPLAY-NULLIFIER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(bid_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_bid_root),
        ],
        32,
    )
}

pub fn low_fee_batch_id(route_id: &str, bid_ids: &[String], opened_height: u64) -> String {
    let bid_root = merkle_root(
        "sealed-precompile-fee-router-low-fee-batch-id-root-v1",
        &bid_ids.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:LOW-FEE-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(&bid_root),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn route_settlement_id(route_id: &str, batch_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:SETTLEMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(batch_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn public_state_snapshot_id(route_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:PUBLIC-STATE-SNAPSHOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn effective_micro_fee_cap(
    config: &Config,
    bid: &PrivatePrecompileFeeBid,
    congestion_bps: u64,
) -> u64 {
    let congestion = congestion_bps.min(config.congestion_surcharge_bps);
    let surcharge = bid
        .max_micro_fee_per_call
        .saturating_mul(congestion)
        .saturating_div(MAX_BPS);
    bid.max_micro_fee_per_call.saturating_add(surcharge)
}

pub fn privacy_preserving_public_state_root(
    route: &RouteEpoch,
    settlement: Option<&RouteSettlement>,
    snapshot: Option<&PublicStateSnapshot>,
) -> String {
    let settlement_record = settlement
        .map(RouteSettlement::public_record)
        .unwrap_or(Value::Null);
    let snapshot_record = snapshot
        .map(PublicStateSnapshot::public_record)
        .unwrap_or(Value::Null);
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:PUBLIC-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&route.public_record()),
            HashPart::Json(&settlement_record),
            HashPart::Json(&snapshot_record),
        ],
        32,
    )
}

pub fn record_root(scheme: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            domain_hash(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:RECORD-LEAF",
                &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
                32,
            )
        })
        .collect::<Vec<_>>();
    merkle_root(
        scheme,
        &leaves.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

pub fn empty_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:EMPTY-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
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

fn demo_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-PRECOMPILE-FEE-ROUTER:DEMO-HASH",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}
