use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqRecursiveProofRebateMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_RECURSIVE_PROOF_REBATE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-recursive-proof-rebate-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_RECURSIVE_PROOF_REBATE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-proof-rebate-market-v1";
pub const WORKLOAD_SCHEME: &str = "private-low-fee-pq-proof-workload-commitment-root-v1";
pub const PROVER_BID_SCHEME: &str = "sealed-pq-recursive-prover-bid-root-v1";
pub const AGGREGATION_WINDOW_SCHEME: &str = "low-fee-recursive-proof-aggregation-window-root-v1";
pub const DA_VOUCHER_SCHEME: &str = "confidential-da-compression-voucher-root-v1";
pub const SPONSOR_POOL_SCHEME: &str = "private-proof-rebate-sponsor-pool-root-v1";
pub const REBATE_COUPON_SCHEME: &str = "low-fee-recursive-proof-rebate-coupon-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str =
    "low-fee-pq-recursive-proof-rebate-settlement-receipt-root-v1";
pub const CHALLENGE_BOND_SCHEME: &str = "pq-recursive-proof-market-challenge-bond-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_WORKLOAD_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_WINDOW_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_WORKLOADS: usize = 4_194_304;
pub const DEFAULT_MAX_BIDS: usize = 4_194_304;
pub const DEFAULT_MAX_WINDOWS: usize = 1_048_576;
pub const DEFAULT_MAX_DA_VOUCHERS: usize = 2_097_152;
pub const DEFAULT_MAX_SPONSOR_POOLS: usize = 262_144;
pub const DEFAULT_MAX_REBATE_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_CHALLENGE_BONDS: usize = 1_048_576;
pub const DEFAULT_MAX_NULLIFIERS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWorkloadKind {
    TransferBatch,
    ContractExecution,
    DefiSettlement,
    TokenNetting,
    MoneroBridgeExit,
    OracleAttestation,
    GovernanceTally,
    StateDiff,
}

impl ProofWorkloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferBatch => "transfer_batch",
            Self::ContractExecution => "contract_execution",
            Self::DefiSettlement => "defi_settlement",
            Self::TokenNetting => "token_netting",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::OracleAttestation => "oracle_attestation",
            Self::GovernanceTally => "governance_tally",
            Self::StateDiff => "state_diff",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::DefiSettlement | Self::ContractExecution => 1_000,
            Self::MoneroBridgeExit => 920,
            Self::TokenNetting => 840,
            Self::StateDiff => 760,
            Self::OracleAttestation => 700,
            Self::TransferBatch => 620,
            Self::GovernanceTally => 540,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadStatus {
    Submitted,
    Bidding,
    Reserved,
    Aggregating,
    Proven,
    Settled,
    Expired,
    Challenged,
}

impl WorkloadStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Bidding => "bidding",
            Self::Reserved => "reserved",
            Self::Aggregating => "aggregating",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn accepts_bid(self) -> bool {
        matches!(self, Self::Submitted | Self::Bidding)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Accepted,
    Replaced,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::Replaced => "replaced",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Locked,
    Proving,
    Settled,
    Rejected,
    Expired,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Reserved,
    Applied,
    Released,
    Expired,
}

impl VoucherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
    Challenged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidProof,
    WithheldWitness,
    FeeOvercharge,
    BadAggregation,
    DaMismatch,
    PqSignatureFailure,
    PrivacyLeak,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProof => "invalid_proof",
            Self::WithheldWitness => "withheld_witness",
            Self::FeeOvercharge => "fee_overcharge",
            Self::BadAggregation => "bad_aggregation",
            Self::DaMismatch => "da_mismatch",
            Self::PqSignatureFailure => "pq_signature_failure",
            Self::PrivacyLeak => "privacy_leak",
        }
    }

    pub fn slash_bps(self) -> u64 {
        match self {
            Self::InvalidProof | Self::PrivacyLeak => 10_000,
            Self::BadAggregation | Self::PqSignatureFailure => 8_000,
            Self::DaMismatch => 6_000,
            Self::WithheldWitness => 4_500,
            Self::FeeOvercharge => 3_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub workload_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub window_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_workloads: usize,
    pub max_bids: usize,
    pub max_windows: usize,
    pub max_da_vouchers: usize,
    pub max_sponsor_pools: usize,
    pub max_rebate_coupons: usize,
    pub max_receipts: usize,
    pub max_challenge_bonds: usize,
    pub max_nullifiers: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            workload_ttl_blocks: DEFAULT_WORKLOAD_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            window_ttl_blocks: DEFAULT_WINDOW_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_workloads: DEFAULT_MAX_WORKLOADS,
            max_bids: DEFAULT_MAX_BIDS,
            max_windows: DEFAULT_MAX_WINDOWS,
            max_da_vouchers: DEFAULT_MAX_DA_VOUCHERS,
            max_sponsor_pools: DEFAULT_MAX_SPONSOR_POOLS,
            max_rebate_coupons: DEFAULT_MAX_REBATE_COUPONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_challenge_bonds: DEFAULT_MAX_CHALLENGE_BONDS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.min_privacy_set_size < 32_768 {
            return Err("min_privacy_set_size below low-fee proof floor".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below PQ floor".to_string());
        }
        if self.max_user_fee_bps > 100 {
            return Err("max_user_fee_bps exceeds low-fee envelope".to_string());
        }
        if self.target_rebate_bps > self.max_user_fee_bps {
            return Err("target_rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.sponsor_cover_bps > MAX_BPS {
            return Err("sponsor_cover_bps cannot exceed MAX_BPS".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_recursive_proof_rebate_market_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "workload_ttl_blocks": self.workload_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "window_ttl_blocks": self.window_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub next_workload: u64,
    pub next_bid: u64,
    pub next_window: u64,
    pub next_da_voucher: u64,
    pub next_sponsor_pool: u64,
    pub next_rebate_coupon: u64,
    pub next_receipt: u64,
    pub next_challenge_bond: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_recursive_proof_rebate_market_counters",
            "workload_count": self.next_workload,
            "bid_count": self.next_bid,
            "window_count": self.next_window,
            "da_voucher_count": self.next_da_voucher,
            "sponsor_pool_count": self.next_sponsor_pool,
            "rebate_coupon_count": self.next_rebate_coupon,
            "receipt_count": self.next_receipt,
            "challenge_bond_count": self.next_challenge_bond,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub workload_root: String,
    pub bid_root: String,
    pub window_root: String,
    pub da_voucher_root: String,
    pub sponsor_pool_root: String,
    pub rebate_coupon_root: String,
    pub receipt_root: String,
    pub challenge_bond_root: String,
    pub spent_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_recursive_proof_rebate_market_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "workload_root": self.workload_root,
            "bid_root": self.bid_root,
            "window_root": self.window_root,
            "da_voucher_root": self.da_voucher_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "rebate_coupon_root": self.rebate_coupon_root,
            "receipt_root": self.receipt_root,
            "challenge_bond_root": self.challenge_bond_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofWorkloadCommitmentRequest {
    pub owner_commitment: String,
    pub kind: ProofWorkloadKind,
    pub workload_root: String,
    pub private_witness_root: String,
    pub public_input_root: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub workload_nullifier: String,
    pub submitted_height: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofWorkloadCommitment {
    pub workload_id: String,
    pub owner_commitment: String,
    pub kind: ProofWorkloadKind,
    pub workload_root: String,
    pub private_witness_root: String,
    pub public_input_root: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub workload_nullifier: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: WorkloadStatus,
    pub priority_score: u64,
    pub metadata_root: String,
}

impl ProofWorkloadCommitment {
    pub fn from_request(config: &Config, request: ProofWorkloadCommitmentRequest) -> Result<Self> {
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        ensure_nonempty("workload_root", &request.workload_root)?;
        ensure_nonempty("private_witness_root", &request.private_witness_root)?;
        ensure_nonempty("public_input_root", &request.public_input_root)?;
        ensure_nonempty("pq_authorization_root", &request.pq_authorization_root)?;
        ensure_nonempty("workload_nullifier", &request.workload_nullifier)?;
        if request.fee_asset_id != config.fee_asset_id {
            return Err("workload fee_asset_id does not match runtime fee asset".to_string());
        }
        if request.privacy_set_size < config.min_privacy_set_size {
            return Err("workload privacy set below configured minimum".to_string());
        }
        let workload_id = workload_id(&request);
        Ok(Self {
            workload_id,
            owner_commitment: request.owner_commitment,
            kind: request.kind,
            workload_root: request.workload_root,
            private_witness_root: request.private_witness_root,
            public_input_root: request.public_input_root,
            fee_asset_id: request.fee_asset_id,
            max_fee_micro_units: request.max_fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            pq_authorization_root: request.pq_authorization_root,
            workload_nullifier: request.workload_nullifier,
            submitted_height: request.submitted_height,
            expires_height: request
                .submitted_height
                .saturating_add(config.workload_ttl_blocks),
            status: WorkloadStatus::Submitted,
            priority_score: workload_priority_score(
                request.kind,
                request.privacy_set_size,
                request.max_fee_micro_units,
            ),
            metadata_root: request.metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_proof_workload_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "workload_id": self.workload_id,
            "owner_commitment": self.owner_commitment,
            "workload_kind": self.kind.as_str(),
            "workload_root": self.workload_root,
            "private_witness_root": self.private_witness_root,
            "public_input_root": self.public_input_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "workload_nullifier": self.workload_nullifier,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "priority_score": self.priority_score,
            "scheme": WORKLOAD_SCHEME,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProverBidRequest {
    pub workload_id: String,
    pub prover_id: String,
    pub bid_commitment: String,
    pub proving_key_root: String,
    pub max_latency_ms: u64,
    pub bid_fee_micro_units: u64,
    pub pq_signature_root: String,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProverBid {
    pub bid_id: String,
    pub workload_id: String,
    pub prover_id: String,
    pub bid_commitment: String,
    pub proving_key_root: String,
    pub max_latency_ms: u64,
    pub bid_fee_micro_units: u64,
    pub pq_signature_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub score: u64,
    pub status: BidStatus,
}

impl ProverBid {
    pub fn from_request(config: &Config, request: ProverBidRequest) -> Result<Self> {
        ensure_nonempty("workload_id", &request.workload_id)?;
        ensure_nonempty("prover_id", &request.prover_id)?;
        ensure_nonempty("bid_commitment", &request.bid_commitment)?;
        ensure_nonempty("proving_key_root", &request.proving_key_root)?;
        ensure_nonempty("pq_signature_root", &request.pq_signature_root)?;
        if request.max_latency_ms == 0 {
            return Err("max_latency_ms must be positive".to_string());
        }
        let bid_id = prover_bid_id(&request);
        Ok(Self {
            bid_id,
            workload_id: request.workload_id,
            prover_id: request.prover_id,
            bid_commitment: request.bid_commitment,
            proving_key_root: request.proving_key_root,
            max_latency_ms: request.max_latency_ms,
            bid_fee_micro_units: request.bid_fee_micro_units,
            pq_signature_root: request.pq_signature_root,
            submitted_height: request.submitted_height,
            expires_height: request
                .submitted_height
                .saturating_add(config.bid_ttl_blocks),
            score: prover_bid_score(request.bid_fee_micro_units, request.max_latency_ms),
            status: BidStatus::Posted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_recursive_prover_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "workload_id": self.workload_id,
            "prover_id": self.prover_id,
            "bid_commitment": self.bid_commitment,
            "proving_key_root": self.proving_key_root,
            "max_latency_ms": self.max_latency_ms,
            "bid_fee_micro_units": self.bid_fee_micro_units,
            "pq_signature_root": self.pq_signature_root,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "score": self.score,
            "status": self.status.as_str(),
            "scheme": PROVER_BID_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregationWindowRequest {
    pub window_owner_id: String,
    pub workload_ids: Vec<String>,
    pub accepted_bid_ids: Vec<String>,
    pub batch_input_root: String,
    pub target_da_root: String,
    pub opened_height: u64,
    pub max_items: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregationWindow {
    pub window_id: String,
    pub window_owner_id: String,
    pub workload_ids: Vec<String>,
    pub accepted_bid_ids: Vec<String>,
    pub batch_input_root: String,
    pub target_da_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub max_items: u64,
    pub status: WindowStatus,
}

impl AggregationWindow {
    pub fn from_request(config: &Config, request: AggregationWindowRequest) -> Result<Self> {
        ensure_nonempty("window_owner_id", &request.window_owner_id)?;
        ensure_nonempty("batch_input_root", &request.batch_input_root)?;
        ensure_nonempty("target_da_root", &request.target_da_root)?;
        if request.workload_ids.is_empty() {
            return Err("aggregation window needs at least one workload".to_string());
        }
        if request.accepted_bid_ids.is_empty() {
            return Err("aggregation window needs at least one accepted bid".to_string());
        }
        let window_id = aggregation_window_id(&request);
        Ok(Self {
            window_id,
            window_owner_id: request.window_owner_id,
            workload_ids: request.workload_ids,
            accepted_bid_ids: request.accepted_bid_ids,
            batch_input_root: request.batch_input_root,
            target_da_root: request.target_da_root,
            opened_height: request.opened_height,
            expires_height: request
                .opened_height
                .saturating_add(config.window_ttl_blocks),
            max_items: request.max_items,
            status: WindowStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_recursive_proof_aggregation_window",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "window_id": self.window_id,
            "window_owner_id": self.window_owner_id,
            "workload_ids": self.workload_ids,
            "accepted_bid_ids": self.accepted_bid_ids,
            "batch_input_root": self.batch_input_root,
            "target_da_root": self.target_da_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "max_items": self.max_items,
            "status": self.status.as_str(),
            "scheme": AGGREGATION_WINDOW_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DaCompressionVoucherRequest {
    pub window_id: String,
    pub sponsor_id: String,
    pub compressed_da_root: String,
    pub voucher_nullifier: String,
    pub discount_bps: u64,
    pub reserved_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DaCompressionVoucher {
    pub voucher_id: String,
    pub window_id: String,
    pub sponsor_id: String,
    pub compressed_da_root: String,
    pub voucher_nullifier: String,
    pub discount_bps: u64,
    pub reserved_height: u64,
    pub status: VoucherStatus,
}

impl DaCompressionVoucher {
    pub fn from_request(request: DaCompressionVoucherRequest) -> Result<Self> {
        ensure_nonempty("window_id", &request.window_id)?;
        ensure_nonempty("sponsor_id", &request.sponsor_id)?;
        ensure_nonempty("compressed_da_root", &request.compressed_da_root)?;
        ensure_nonempty("voucher_nullifier", &request.voucher_nullifier)?;
        if request.discount_bps > MAX_BPS {
            return Err("discount_bps cannot exceed MAX_BPS".to_string());
        }
        let voucher_id = da_voucher_id(&request);
        Ok(Self {
            voucher_id,
            window_id: request.window_id,
            sponsor_id: request.sponsor_id,
            compressed_da_root: request.compressed_da_root,
            voucher_nullifier: request.voucher_nullifier,
            discount_bps: request.discount_bps,
            reserved_height: request.reserved_height,
            status: VoucherStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_da_compression_voucher",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "voucher_id": self.voucher_id,
            "window_id": self.window_id,
            "sponsor_id": self.sponsor_id,
            "compressed_da_root": self.compressed_da_root,
            "voucher_nullifier": self.voucher_nullifier,
            "discount_bps": self.discount_bps,
            "reserved_height": self.reserved_height,
            "status": self.status.as_str(),
            "scheme": DA_VOUCHER_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorPoolRequest {
    pub sponsor_id: String,
    pub pool_commitment: String,
    pub policy_root: String,
    pub liquidity_micro_units: u64,
    pub cover_bps: u64,
    pub opened_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub sponsor_id: String,
    pub pool_commitment: String,
    pub policy_root: String,
    pub liquidity_micro_units: u64,
    pub cover_bps: u64,
    pub opened_height: u64,
}

impl SponsorPool {
    pub fn from_request(config: &Config, request: SponsorPoolRequest) -> Result<Self> {
        ensure_nonempty("sponsor_id", &request.sponsor_id)?;
        ensure_nonempty("pool_commitment", &request.pool_commitment)?;
        ensure_nonempty("policy_root", &request.policy_root)?;
        if request.cover_bps > config.sponsor_cover_bps {
            return Err("sponsor pool cover exceeds runtime cover envelope".to_string());
        }
        let pool_id = sponsor_pool_id(&request);
        Ok(Self {
            pool_id,
            sponsor_id: request.sponsor_id,
            pool_commitment: request.pool_commitment,
            policy_root: request.policy_root,
            liquidity_micro_units: request.liquidity_micro_units,
            cover_bps: request.cover_bps,
            opened_height: request.opened_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_rebate_sponsor_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "sponsor_id": self.sponsor_id,
            "pool_commitment": self.pool_commitment,
            "policy_root": self.policy_root,
            "liquidity_micro_units": self.liquidity_micro_units,
            "cover_bps": self.cover_bps,
            "opened_height": self.opened_height,
            "scheme": SPONSOR_POOL_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateCouponRequest {
    pub workload_id: String,
    pub pool_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub coupon_nullifier: String,
    pub issued_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub workload_id: String,
    pub pool_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub coupon_nullifier: String,
    pub issued_height: u64,
}

impl RebateCoupon {
    pub fn from_request(config: &Config, request: RebateCouponRequest) -> Result<Self> {
        ensure_nonempty("workload_id", &request.workload_id)?;
        ensure_nonempty("pool_id", &request.pool_id)?;
        ensure_nonempty("beneficiary_commitment", &request.beneficiary_commitment)?;
        ensure_nonempty("coupon_nullifier", &request.coupon_nullifier)?;
        let rebate_micro_units = request
            .fee_paid_micro_units
            .saturating_mul(config.target_rebate_bps)
            / MAX_BPS;
        let coupon_id = rebate_coupon_id(&request, rebate_micro_units);
        Ok(Self {
            coupon_id,
            workload_id: request.workload_id,
            pool_id: request.pool_id,
            beneficiary_commitment: request.beneficiary_commitment,
            fee_paid_micro_units: request.fee_paid_micro_units,
            rebate_micro_units,
            coupon_nullifier: request.coupon_nullifier,
            issued_height: request.issued_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_recursive_proof_rebate_coupon",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "coupon_id": self.coupon_id,
            "workload_id": self.workload_id,
            "pool_id": self.pool_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "coupon_nullifier": self.coupon_nullifier,
            "issued_height": self.issued_height,
            "scheme": REBATE_COUPON_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofSettlementReceiptRequest {
    pub window_id: String,
    pub prover_id: String,
    pub recursive_proof_root: String,
    pub settlement_state_root: String,
    pub fee_paid_micro_units: u64,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofSettlementReceipt {
    pub receipt_id: String,
    pub window_id: String,
    pub prover_id: String,
    pub recursive_proof_root: String,
    pub settlement_state_root: String,
    pub fee_paid_micro_units: u64,
    pub settled_height: u64,
    pub finality_height: u64,
    pub status: ReceiptStatus,
}

impl ProofSettlementReceipt {
    pub fn from_request(config: &Config, request: ProofSettlementReceiptRequest) -> Result<Self> {
        ensure_nonempty("window_id", &request.window_id)?;
        ensure_nonempty("prover_id", &request.prover_id)?;
        ensure_nonempty("recursive_proof_root", &request.recursive_proof_root)?;
        ensure_nonempty("settlement_state_root", &request.settlement_state_root)?;
        let receipt_id = settlement_receipt_id(&request);
        Ok(Self {
            receipt_id,
            window_id: request.window_id,
            prover_id: request.prover_id,
            recursive_proof_root: request.recursive_proof_root,
            settlement_state_root: request.settlement_state_root,
            fee_paid_micro_units: request.fee_paid_micro_units,
            settled_height: request.settled_height,
            finality_height: request
                .settled_height
                .saturating_add(config.receipt_finality_blocks),
            status: ReceiptStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_proof_rebate_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "window_id": self.window_id,
            "prover_id": self.prover_id,
            "recursive_proof_root": self.recursive_proof_root,
            "settlement_state_root": self.settlement_state_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "settled_height": self.settled_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "scheme": SETTLEMENT_RECEIPT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeBondRequest {
    pub subject_id: String,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub bond_micro_units: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeBond {
    pub challenge_id: String,
    pub subject_id: String,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub bond_micro_units: u64,
    pub slash_bps: u64,
    pub height: u64,
    pub resolved: bool,
}

impl ChallengeBond {
    pub fn from_request(request: ChallengeBondRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("challenger_commitment", &request.challenger_commitment)?;
        ensure_nonempty("evidence_root", &request.evidence_root)?;
        let challenge_id = challenge_bond_id(&request);
        Ok(Self {
            challenge_id,
            subject_id: request.subject_id,
            challenger_commitment: request.challenger_commitment,
            kind: request.kind,
            evidence_root: request.evidence_root,
            bond_micro_units: request.bond_micro_units,
            slash_bps: request.kind.slash_bps(),
            height: request.height,
            resolved: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_proof_market_challenge_bond",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "subject_id": self.subject_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "bond_micro_units": self.bond_micro_units,
            "slash_bps": self.slash_bps,
            "height": self.height,
            "resolved": self.resolved,
            "scheme": CHALLENGE_BOND_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub workloads: BTreeMap<String, ProofWorkloadCommitment>,
    pub bids: BTreeMap<String, ProverBid>,
    pub windows: BTreeMap<String, AggregationWindow>,
    pub da_vouchers: BTreeMap<String, DaCompressionVoucher>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub receipts: BTreeMap<String, ProofSettlementReceipt>,
    pub challenge_bonds: BTreeMap<String, ChallengeBond>,
    spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            workloads: BTreeMap::new(),
            bids: BTreeMap::new(),
            windows: BTreeMap::new(),
            da_vouchers: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenge_bonds: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn with_config(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            ..Self::devnet()
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn submit_workload(
        &mut self,
        request: ProofWorkloadCommitmentRequest,
    ) -> Result<ProofWorkloadCommitment> {
        ensure_capacity("workloads", self.workloads.len(), self.config.max_workloads)?;
        if self.spent_nullifiers.contains(&request.workload_nullifier) {
            return Err("workload nullifier already spent".to_string());
        }
        let workload = ProofWorkloadCommitment::from_request(&self.config, request)?;
        ensure_absent("workload", &self.workloads, &workload.workload_id)?;
        self.spent_nullifiers
            .insert(workload.workload_nullifier.clone());
        self.counters.next_workload = self.counters.next_workload.saturating_add(1);
        self.workloads
            .insert(workload.workload_id.clone(), workload.clone());
        self.recompute_roots();
        Ok(workload)
    }

    pub fn post_bid(&mut self, request: ProverBidRequest) -> Result<ProverBid> {
        ensure_capacity("bids", self.bids.len(), self.config.max_bids)?;
        let bid = ProverBid::from_request(&self.config, request)?;
        let workload = self
            .workloads
            .get_mut(&bid.workload_id)
            .ok_or_else(|| format!("unknown workload_id {}", bid.workload_id))?;
        if !workload.status.accepts_bid() {
            return Err("workload is not accepting prover bids".to_string());
        }
        workload.status = WorkloadStatus::Bidding;
        ensure_absent("bid", &self.bids, &bid.bid_id)?;
        self.counters.next_bid = self.counters.next_bid.saturating_add(1);
        self.bids.insert(bid.bid_id.clone(), bid.clone());
        self.recompute_roots();
        Ok(bid)
    }

    pub fn open_window(&mut self, request: AggregationWindowRequest) -> Result<AggregationWindow> {
        ensure_capacity("windows", self.windows.len(), self.config.max_windows)?;
        for workload_id in &request.workload_ids {
            let workload = self
                .workloads
                .get_mut(workload_id)
                .ok_or_else(|| format!("unknown workload_id {}", workload_id))?;
            workload.status = WorkloadStatus::Reserved;
        }
        for bid_id in &request.accepted_bid_ids {
            let bid = self
                .bids
                .get_mut(bid_id)
                .ok_or_else(|| format!("unknown bid_id {}", bid_id))?;
            bid.status = BidStatus::Accepted;
        }
        let window = AggregationWindow::from_request(&self.config, request)?;
        ensure_absent("window", &self.windows, &window.window_id)?;
        self.counters.next_window = self.counters.next_window.saturating_add(1);
        self.windows
            .insert(window.window_id.clone(), window.clone());
        self.recompute_roots();
        Ok(window)
    }

    pub fn reserve_da_voucher(
        &mut self,
        request: DaCompressionVoucherRequest,
    ) -> Result<DaCompressionVoucher> {
        ensure_capacity(
            "da_vouchers",
            self.da_vouchers.len(),
            self.config.max_da_vouchers,
        )?;
        if self.spent_nullifiers.contains(&request.voucher_nullifier) {
            return Err("DA voucher nullifier already spent".to_string());
        }
        ensure_known("window", &self.windows, &request.window_id)?;
        let voucher = DaCompressionVoucher::from_request(request)?;
        ensure_absent("da_voucher", &self.da_vouchers, &voucher.voucher_id)?;
        self.spent_nullifiers
            .insert(voucher.voucher_nullifier.clone());
        self.counters.next_da_voucher = self.counters.next_da_voucher.saturating_add(1);
        self.da_vouchers
            .insert(voucher.voucher_id.clone(), voucher.clone());
        self.recompute_roots();
        Ok(voucher)
    }

    pub fn open_sponsor_pool(&mut self, request: SponsorPoolRequest) -> Result<SponsorPool> {
        ensure_capacity(
            "sponsor_pools",
            self.sponsor_pools.len(),
            self.config.max_sponsor_pools,
        )?;
        let pool = SponsorPool::from_request(&self.config, request)?;
        ensure_absent("sponsor_pool", &self.sponsor_pools, &pool.pool_id)?;
        self.counters.next_sponsor_pool = self.counters.next_sponsor_pool.saturating_add(1);
        self.sponsor_pools
            .insert(pool.pool_id.clone(), pool.clone());
        self.recompute_roots();
        Ok(pool)
    }

    pub fn issue_rebate_coupon(&mut self, request: RebateCouponRequest) -> Result<RebateCoupon> {
        ensure_capacity(
            "rebate_coupons",
            self.rebate_coupons.len(),
            self.config.max_rebate_coupons,
        )?;
        if self.spent_nullifiers.contains(&request.coupon_nullifier) {
            return Err("rebate coupon nullifier already spent".to_string());
        }
        ensure_known("workload", &self.workloads, &request.workload_id)?;
        ensure_known("sponsor_pool", &self.sponsor_pools, &request.pool_id)?;
        let coupon = RebateCoupon::from_request(&self.config, request)?;
        ensure_absent("rebate_coupon", &self.rebate_coupons, &coupon.coupon_id)?;
        self.spent_nullifiers
            .insert(coupon.coupon_nullifier.clone());
        self.counters.next_rebate_coupon = self.counters.next_rebate_coupon.saturating_add(1);
        self.rebate_coupons
            .insert(coupon.coupon_id.clone(), coupon.clone());
        self.recompute_roots();
        Ok(coupon)
    }

    pub fn publish_receipt(
        &mut self,
        request: ProofSettlementReceiptRequest,
    ) -> Result<ProofSettlementReceipt> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        let receipt = ProofSettlementReceipt::from_request(&self.config, request)?;
        let window = self
            .windows
            .get_mut(&receipt.window_id)
            .ok_or_else(|| format!("unknown window_id {}", receipt.window_id))?;
        window.status = WindowStatus::Settled;
        for workload_id in &window.workload_ids {
            if let Some(workload) = self.workloads.get_mut(workload_id) {
                workload.status = WorkloadStatus::Proven;
            }
        }
        ensure_absent("receipt", &self.receipts, &receipt.receipt_id)?;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn file_challenge(&mut self, request: ChallengeBondRequest) -> Result<ChallengeBond> {
        ensure_capacity(
            "challenge_bonds",
            self.challenge_bonds.len(),
            self.config.max_challenge_bonds,
        )?;
        let challenge = ChallengeBond::from_request(request)?;
        ensure_absent(
            "challenge_bond",
            &self.challenge_bonds,
            &challenge.challenge_id,
        )?;
        if let Some(workload) = self.workloads.get_mut(&challenge.subject_id) {
            workload.status = WorkloadStatus::Challenged;
        }
        if let Some(window) = self.windows.get_mut(&challenge.subject_id) {
            window.status = WindowStatus::Rejected;
        }
        if let Some(receipt) = self.receipts.get_mut(&challenge.subject_id) {
            receipt.status = ReceiptStatus::Challenged;
        }
        self.counters.next_challenge_bond = self.counters.next_challenge_bond.saturating_add(1);
        self.challenge_bonds
            .insert(challenge.challenge_id.clone(), challenge.clone());
        self.recompute_roots();
        Ok(challenge)
    }

    pub fn finalize_receipt(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt_id {}", receipt_id))?;
        receipt.status = ReceiptStatus::Finalized;
        if let Some(window) = self.windows.get(&receipt.window_id) {
            for workload_id in &window.workload_ids {
                if let Some(workload) = self.workloads.get_mut(workload_id) {
                    workload.status = WorkloadStatus::Settled;
                }
            }
        }
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: record_root(
                "LOW-FEE-PQ-PROOF-REBATE-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: record_root(
                "LOW-FEE-PQ-PROOF-REBATE-COUNTERS",
                &self.counters.public_record(),
            ),
            workload_root: map_root("LOW-FEE-PQ-PROOF-REBATE-WORKLOADS", &self.workloads),
            bid_root: map_root("LOW-FEE-PQ-PROOF-REBATE-BIDS", &self.bids),
            window_root: map_root("LOW-FEE-PQ-PROOF-REBATE-WINDOWS", &self.windows),
            da_voucher_root: map_root("LOW-FEE-PQ-PROOF-REBATE-DA-VOUCHERS", &self.da_vouchers),
            sponsor_pool_root: map_root(
                "LOW-FEE-PQ-PROOF-REBATE-SPONSOR-POOLS",
                &self.sponsor_pools,
            ),
            rebate_coupon_root: map_root("LOW-FEE-PQ-PROOF-REBATE-COUPONS", &self.rebate_coupons),
            receipt_root: map_root("LOW-FEE-PQ-PROOF-REBATE-RECEIPTS", &self.receipts),
            challenge_bond_root: map_root(
                "LOW-FEE-PQ-PROOF-REBATE-CHALLENGES",
                &self.challenge_bonds,
            ),
            spent_nullifier_root: set_root(
                "LOW-FEE-PQ-PROOF-REBATE-SPENT-NULLIFIERS",
                &self.spent_nullifiers,
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_recursive_proof_rebate_market_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "workload_count": self.workloads.len(),
            "bid_count": self.bids.len(),
            "window_count": self.windows.len(),
            "da_voucher_count": self.da_vouchers.len(),
            "sponsor_pool_count": self.sponsor_pools.len(),
            "rebate_coupon_count": self.rebate_coupons.len(),
            "receipt_count": self.receipts.len(),
            "challenge_bond_count": self.challenge_bonds.len(),
            "spent_nullifier_count": self.spent_nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_low_fee_pq_recursive_proof_rebate_market_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_recursive_proof_rebate_market_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn workload_id(request: &ProofWorkloadCommitmentRequest) -> String {
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-WORKLOAD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.workload_root),
            HashPart::Str(&request.private_witness_root),
            HashPart::Str(&request.workload_nullifier),
            HashPart::U64(request.submitted_height),
        ],
        32,
    )
}

pub fn prover_bid_id(request: &ProverBidRequest) -> String {
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.workload_id),
            HashPart::Str(&request.prover_id),
            HashPart::Str(&request.bid_commitment),
            HashPart::Str(&request.proving_key_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::U64(request.bid_fee_micro_units),
            HashPart::U64(request.submitted_height),
        ],
        32,
    )
}

pub fn aggregation_window_id(request: &AggregationWindowRequest) -> String {
    let workload_root = merkle_root(
        "LOW-FEE-PQ-PROOF-REBATE-WINDOW-WORKLOADS",
        &request
            .workload_ids
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    );
    let bid_root = merkle_root(
        "LOW-FEE-PQ-PROOF-REBATE-WINDOW-BIDS",
        &request
            .accepted_bid_ids
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    );
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.window_owner_id),
            HashPart::Str(&workload_root),
            HashPart::Str(&bid_root),
            HashPart::Str(&request.batch_input_root),
            HashPart::Str(&request.target_da_root),
            HashPart::U64(request.opened_height),
        ],
        32,
    )
}

pub fn da_voucher_id(request: &DaCompressionVoucherRequest) -> String {
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-DA-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.compressed_da_root),
            HashPart::Str(&request.voucher_nullifier),
            HashPart::U64(request.discount_bps),
            HashPart::U64(request.reserved_height),
        ],
        32,
    )
}

pub fn sponsor_pool_id(request: &SponsorPoolRequest) -> String {
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-SPONSOR-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.pool_commitment),
            HashPart::Str(&request.policy_root),
            HashPart::U64(request.liquidity_micro_units),
            HashPart::U64(request.opened_height),
        ],
        32,
    )
}

pub fn rebate_coupon_id(request: &RebateCouponRequest, rebate_micro_units: u64) -> String {
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.workload_id),
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.coupon_nullifier),
            HashPart::U64(request.fee_paid_micro_units),
            HashPart::U64(rebate_micro_units),
            HashPart::U64(request.issued_height),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &ProofSettlementReceiptRequest) -> String {
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.prover_id),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::Str(&request.settlement_state_root),
            HashPart::U64(request.fee_paid_micro_units),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}

pub fn challenge_bond_id(request: &ChallengeBondRequest) -> String {
    domain_hash(
        "LOW-FEE-PQ-PROOF-REBATE-CHALLENGE-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.bond_micro_units),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn workload_priority_score(
    kind: ProofWorkloadKind,
    privacy_set_size: u64,
    max_fee_micro_units: u64,
) -> u64 {
    kind.complexity_weight()
        .saturating_add(privacy_set_size.min(1_048_576) / 1_024)
        .saturating_add(max_fee_micro_units.min(10_000_000) / 10_000)
}

pub fn prover_bid_score(bid_fee_micro_units: u64, max_latency_ms: u64) -> u64 {
    20_000_u64.saturating_sub(
        bid_fee_micro_units
            .min(10_000_000)
            .saturating_div(1_000)
            .saturating_add(max_latency_ms.min(10_000)),
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("LOW-FEE-PQ-PROOF-REBATE-STATE-ROOT", record)
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"})),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

pub fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

pub fn ensure_known<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("unknown {label} {key}"))
    }
}
