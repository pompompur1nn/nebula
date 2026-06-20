use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPqFastExitSettlementRouterResult<T> = Result<T, String>;

pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-monero-pq-fast-exit-settlement-router-v1";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_QUOTE_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87-fast-exit-quote-v1";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_BACKUP_SIGNATURE_SCHEME: &str =
    "SLH-DSA-SHAKE-128s-fast-exit-dispute-v1";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MONERO_COMMITMENT_SCHEME: &str =
    "monero-stealth-payout-viewtag-commitment-v1";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_REPLAY_DOMAIN: &str =
    "monero-pq-fast-exit-router-devnet";
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_HEIGHT: u64 = 512;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_LOCK_TTL_BLOCKS: u64 = 48;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 96;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_MAX_FEE_BPS: u64 = 95;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_LOW_FEE_BPS: u64 = 12;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_URGENT_FEE_BPS: u64 = 80;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_DEFI_FEE_BPS: u64 = 55;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_FEE_FLOOR_PICONERO: u64 = 2_000;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_MIN_LIQUIDITY_PICONERO: u64 =
    250_000_000_000;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_BPS: u64 = 10_000;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_QUOTES: usize = 16_384;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_ROUTES: usize = 8_192;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_SIGNER_LANES: usize = 64;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_LIQUIDITY_LOCKS: usize = 16_384;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_PAYOUTS: usize = 16_384;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_RECEIPTS: usize = 16_384;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_CHALLENGES: usize = 4_096;
pub const MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_PUBLIC_RECORDS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClass {
    LowFee,
    Standard,
    Fast,
    Defi,
    TokenBridge,
    SmartContract,
    Emergency,
}

impl ExitClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::TokenBridge => "token_bridge",
            Self::SmartContract => "smart_contract",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Defi | Self::TokenBridge | Self::SmartContract => config.defi_fee_bps,
            Self::Emergency | Self::Fast => config.urgent_fee_bps,
            Self::Standard => config.max_fee_bps.min(config.urgent_fee_bps),
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::LowFee => 900,
            Self::SmartContract => 820,
            Self::TokenBridge => 780,
            Self::Defi => 700,
            Self::Fast => 640,
            Self::Standard => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Accepted,
    Locked,
    Settling,
    Settled,
    Challenged,
    Expired,
    Cancelled,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Locked => "locked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Accepted | Self::Locked | Self::Settling
        )
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Committed,
    Locked,
    PayoutQueued,
    Submitted,
    Confirmed,
    Disputed,
    Released,
    Expired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Locked => "locked",
            Self::PayoutQueued => "payout_queued",
            Self::Submitted => "submitted",
            Self::Confirmed => "confirmed",
            Self::Disputed => "disputed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerLaneStatus {
    Active,
    Degraded,
    Paused,
    Slashed,
    Rotating,
}

impl SignerLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Rotating => "rotating",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStatus {
    Reserved,
    Bound,
    Spent,
    Released,
    Challenged,
    Expired,
}

impl LockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Bound => "bound",
            Self::Spent => "spent",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    Prepared,
    Signed,
    Submitted,
    Confirmed,
    ReorgHold,
    Released,
    Failed,
}

impl PayoutStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Signed => "signed",
            Self::Submitted => "submitted",
            Self::Confirmed => "confirmed",
            Self::ReorgHold => "reorg_hold",
            Self::Released => "released",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Posted,
    Final,
    Challenged,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Posted => "posted",
            Self::Final => "final",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidencePosted,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidencePosted => "evidence_posted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub quote_scheme: String,
    pub backup_signature_scheme: String,
    pub monero_commitment_scheme: String,
    pub replay_domain: String,
    pub quote_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub low_fee_bps: u64,
    pub urgent_fee_bps: u64,
    pub defi_fee_bps: u64,
    pub fee_floor_piconero: u64,
    pub min_liquidity_piconero: u64,
    pub reserve_coverage_bps: u64,
    pub max_quotes: usize,
    pub max_routes: usize,
    pub max_signer_lanes: usize,
    pub max_liquidity_locks: usize,
    pub max_payouts: usize,
    pub max_receipts: usize,
    pub max_challenges: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            network: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_HASH_SUITE.to_string(),
            quote_scheme: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_QUOTE_SCHEME.to_string(),
            backup_signature_scheme: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            monero_commitment_scheme:
                MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MONERO_COMMITMENT_SCHEME.to_string(),
            replay_domain: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_REPLAY_DOMAIN.to_string(),
            quote_ttl_blocks: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS,
            lock_ttl_blocks: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_LOCK_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            challenge_window_blocks:
                MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_pq_security_bits:
                MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_MAX_FEE_BPS,
            low_fee_bps: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_LOW_FEE_BPS,
            urgent_fee_bps: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_URGENT_FEE_BPS,
            defi_fee_bps: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_DEFI_FEE_BPS,
            fee_floor_piconero: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_FEE_FLOOR_PICONERO,
            min_liquidity_piconero:
                MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_MIN_LIQUIDITY_PICONERO,
            reserve_coverage_bps:
                MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_RESERVE_COVERAGE_BPS,
            max_quotes: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_QUOTES,
            max_routes: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_ROUTES,
            max_signer_lanes: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_SIGNER_LANES,
            max_liquidity_locks: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_LIQUIDITY_LOCKS,
            max_payouts: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_PAYOUTS,
            max_receipts: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_RECEIPTS,
            max_challenges: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_CHALLENGES,
            max_public_records: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "quote_scheme": self.quote_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "monero_commitment_scheme": self.monero_commitment_scheme,
            "replay_domain": self.replay_domain,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "lock_ttl_blocks": self.lock_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "urgent_fee_bps": self.urgent_fee_bps,
            "defi_fee_bps": self.defi_fee_bps,
            "fee_floor_piconero": self.fee_floor_piconero,
            "min_liquidity_piconero": self.min_liquidity_piconero,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "max_quotes": self.max_quotes,
            "max_routes": self.max_routes,
            "max_signer_lanes": self.max_signer_lanes,
            "max_liquidity_locks": self.max_liquidity_locks,
            "max_payouts": self.max_payouts,
            "max_receipts": self.max_receipts,
            "max_challenges": self.max_challenges,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn validate(&self) -> MoneroPqFastExitSettlementRouterResult<()> {
        require(!self.network.is_empty(), "config network is empty")?;
        require(!self.asset_id.is_empty(), "config asset id is empty")?;
        require(
            !self.fee_asset_id.is_empty(),
            "config fee asset id is empty",
        )?;
        require(!self.hash_suite.is_empty(), "config hash suite is empty")?;
        require(
            !self.quote_scheme.is_empty(),
            "config quote scheme is empty",
        )?;
        require(
            !self.backup_signature_scheme.is_empty(),
            "config backup signature scheme is empty",
        )?;
        require(
            !self.monero_commitment_scheme.is_empty(),
            "config monero commitment scheme is empty",
        )?;
        require(
            !self.replay_domain.is_empty(),
            "config replay domain is empty",
        )?;
        require(self.quote_ttl_blocks > 0, "quote ttl must be positive")?;
        require(
            self.lock_ttl_blocks >= self.quote_ttl_blocks,
            "lock ttl too small",
        )?;
        require(
            self.settlement_ttl_blocks >= self.lock_ttl_blocks,
            "settlement ttl too small",
        )?;
        require(
            self.challenge_window_blocks > 0,
            "challenge window must be positive",
        )?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below devnet floor",
        )?;
        require(
            self.max_fee_bps <= MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_BPS,
            "fee cap too high",
        )?;
        require(self.low_fee_bps <= self.max_fee_bps, "low fee exceeds cap")?;
        require(
            self.urgent_fee_bps <= self.max_fee_bps,
            "urgent fee exceeds cap",
        )?;
        require(
            self.defi_fee_bps <= self.max_fee_bps,
            "defi fee exceeds cap",
        )?;
        require(self.fee_floor_piconero > 0, "fee floor must be positive")?;
        require(
            self.min_liquidity_piconero > self.fee_floor_piconero,
            "liquidity floor too small",
        )?;
        require(
            self.reserve_coverage_bps >= MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_BPS,
            "reserve coverage under one hundred percent",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitQuote {
    pub quote_id: String,
    pub exit_class: ExitClass,
    pub requester_commitment: String,
    pub route_commitment_id: String,
    pub signer_lane_id: String,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub min_payout_piconero: u64,
    pub fee_cap_bps: u64,
    pub issued_at_height: u64,
    pub valid_until_height: u64,
    pub replay_nullifier: String,
    pub pq_quote_signature: String,
    pub encrypted_route_hint: String,
    pub status: QuoteStatus,
}

impl ExitQuote {
    pub fn new(
        exit_class: ExitClass,
        label: &str,
        route_commitment_id: &str,
        signer_lane_id: &str,
        amount_piconero: u64,
        issued_at_height: u64,
        config: &Config,
    ) -> Self {
        let fee_cap_bps = exit_class.fee_bps(config);
        let fee_piconero = fee_for(amount_piconero, fee_cap_bps, config.fee_floor_piconero);
        let max_fee_piconero = fee_for(
            amount_piconero,
            config.max_fee_bps,
            config.fee_floor_piconero,
        );
        let min_payout_piconero = amount_piconero.saturating_sub(max_fee_piconero);
        let requester_commitment = labeled_hash("ROUTER-REQUESTER", label);
        let replay_nullifier =
            commitment_hash("ROUTER-REPLAY-NULLIFIER", &[label, route_commitment_id]);
        let encrypted_route_hint =
            commitment_hash("ROUTER-ENCRYPTED-HINT", &[label, signer_lane_id]);
        let valid_until_height = issued_at_height.saturating_add(config.quote_ttl_blocks);
        let mut quote = Self {
            quote_id: String::new(),
            exit_class,
            requester_commitment,
            route_commitment_id: route_commitment_id.to_string(),
            signer_lane_id: signer_lane_id.to_string(),
            amount_piconero,
            fee_piconero,
            max_fee_piconero,
            min_payout_piconero,
            fee_cap_bps,
            issued_at_height,
            valid_until_height,
            replay_nullifier,
            pq_quote_signature: String::new(),
            encrypted_route_hint,
            status: QuoteStatus::Open,
        };
        quote.quote_id = id_from_record("ROUTER-QUOTE-ID", &quote.public_record_without_id());
        quote.pq_quote_signature =
            signed_commitment("quote", signer_lane_id, &quote.quote_id, issued_at_height);
        quote
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "quote_id", json!(self.quote_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "exit_class": self.exit_class.as_str(),
            "requester_commitment": self.requester_commitment,
            "route_commitment_id": self.route_commitment_id,
            "signer_lane_id": self.signer_lane_id,
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "min_payout_piconero": self.min_payout_piconero,
            "fee_cap_bps": self.fee_cap_bps,
            "issued_at_height": self.issued_at_height,
            "valid_until_height": self.valid_until_height,
            "replay_nullifier": self.replay_nullifier,
            "pq_quote_signature": self.pq_quote_signature,
            "encrypted_route_hint": self.encrypted_route_hint,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteCommitment {
    pub route_id: String,
    pub quote_id: String,
    pub exit_class: ExitClass,
    pub route_root: String,
    pub solver_commitment: String,
    pub private_orderflow_root: String,
    pub token_context_root: String,
    pub smart_contract_call_root: String,
    pub monero_payout_commitment_id: String,
    pub fee_cap_commitment: String,
    pub replay_nullifier: String,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
    pub status: RouteStatus,
}

impl RouteCommitment {
    pub fn new(
        quote: &ExitQuote,
        label: &str,
        payout_id: &str,
        committed_at_height: u64,
        config: &Config,
    ) -> Self {
        let solver_commitment = labeled_hash("ROUTER-SOLVER", label);
        let private_orderflow_root = labeled_hash("ROUTER-PRIVATE-ORDERFLOW", label);
        let token_context_root = labeled_hash("ROUTER-TOKEN-CONTEXT", quote.exit_class.as_str());
        let smart_contract_call_root = labeled_hash("ROUTER-CONTRACT-CALL", label);
        let fee_cap_commitment = commitment_hash(
            "ROUTER-FEE-CAP",
            &[&quote.quote_id, &quote.max_fee_piconero.to_string()],
        );
        let route_root = merkle_root(
            "MONERO-PQ-FAST-EXIT-ROUTE-PLAN",
            &[
                json!(solver_commitment),
                json!(private_orderflow_root),
                json!(token_context_root),
                json!(smart_contract_call_root),
                json!(payout_id),
            ],
        );
        let mut route = Self {
            route_id: String::new(),
            quote_id: quote.quote_id.clone(),
            exit_class: quote.exit_class,
            route_root,
            solver_commitment,
            private_orderflow_root,
            token_context_root,
            smart_contract_call_root,
            monero_payout_commitment_id: payout_id.to_string(),
            fee_cap_commitment,
            replay_nullifier: quote.replay_nullifier.clone(),
            committed_at_height,
            expires_at_height: committed_at_height.saturating_add(config.settlement_ttl_blocks),
            status: RouteStatus::Committed,
        };
        route.route_id = id_from_record("ROUTER-ROUTE-ID", &route.public_record_without_id());
        route
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "route_id", json!(self.route_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "exit_class": self.exit_class.as_str(),
            "route_root": self.route_root,
            "solver_commitment": self.solver_commitment,
            "private_orderflow_root": self.private_orderflow_root,
            "token_context_root": self.token_context_root,
            "smart_contract_call_root": self.smart_contract_call_root,
            "monero_payout_commitment_id": self.monero_payout_commitment_id,
            "fee_cap_commitment": self.fee_cap_commitment,
            "replay_nullifier": self.replay_nullifier,
            "committed_at_height": self.committed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerLane {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_class: ExitClass,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub quorum_threshold: u64,
    pub quorum_weight: u64,
    pub min_security_bits: u16,
    pub latency_budget_ms: u64,
    pub fee_share_bps: u64,
    pub active_quote_count: u64,
    pub status: SignerLaneStatus,
}

impl PqSignerLane {
    pub fn new(label: &str, lane_class: ExitClass, quorum_weight: u64, fee_share_bps: u64) -> Self {
        let operator_commitment = labeled_hash("ROUTER-SIGNER-OPERATOR", label);
        let pq_public_key_commitment = labeled_hash("ROUTER-SIGNER-PQ-PUBKEY", label);
        let backup_public_key_commitment = labeled_hash("ROUTER-SIGNER-BACKUP-PUBKEY", label);
        let quorum_threshold = quorum_weight.saturating_sub(1).max(1);
        let mut lane = Self {
            lane_id: String::new(),
            operator_commitment,
            lane_class,
            pq_public_key_commitment,
            backup_public_key_commitment,
            quorum_threshold,
            quorum_weight,
            min_security_bits: MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            latency_budget_ms: if lane_class == ExitClass::LowFee {
                2_500
            } else {
                900
            },
            fee_share_bps,
            active_quote_count: 0,
            status: SignerLaneStatus::Active,
        };
        lane.lane_id = id_from_record("ROUTER-SIGNER-LANE-ID", &lane.public_record_without_id());
        lane
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "lane_id", json!(self.lane_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "lane_class": self.lane_class.as_str(),
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_public_key_commitment": self.backup_public_key_commitment,
            "quorum_threshold": self.quorum_threshold,
            "quorum_weight": self.quorum_weight,
            "min_security_bits": self.min_security_bits,
            "latency_budget_ms": self.latency_budget_ms,
            "fee_share_bps": self.fee_share_bps,
            "active_quote_count": self.active_quote_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityLock {
    pub lock_id: String,
    pub quote_id: String,
    pub route_id: String,
    pub provider_commitment: String,
    pub reserve_commitment: String,
    pub locked_amount_piconero: u64,
    pub fee_reserved_piconero: u64,
    pub locked_at_height: u64,
    pub unlock_height: u64,
    pub spend_authorization_root: String,
    pub status: LockStatus,
}

impl LiquidityLock {
    pub fn new(
        quote: &ExitQuote,
        route_id: &str,
        label: &str,
        locked_at_height: u64,
        config: &Config,
    ) -> Self {
        let provider_commitment = labeled_hash("ROUTER-LIQUIDITY-PROVIDER", label);
        let reserve_commitment = labeled_hash("ROUTER-LIQUIDITY-RESERVE", label);
        let spend_authorization_root = commitment_hash(
            "ROUTER-SPEND-AUTH",
            &[&quote.quote_id, route_id, &provider_commitment],
        );
        let mut lock = Self {
            lock_id: String::new(),
            quote_id: quote.quote_id.clone(),
            route_id: route_id.to_string(),
            provider_commitment,
            reserve_commitment,
            locked_amount_piconero: quote.amount_piconero,
            fee_reserved_piconero: quote.max_fee_piconero,
            locked_at_height,
            unlock_height: locked_at_height.saturating_add(config.lock_ttl_blocks),
            spend_authorization_root,
            status: LockStatus::Bound,
        };
        lock.lock_id = id_from_record("ROUTER-LIQUIDITY-LOCK-ID", &lock.public_record_without_id());
        lock
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "lock_id", json!(self.lock_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "route_id": self.route_id,
            "provider_commitment": self.provider_commitment,
            "reserve_commitment": self.reserve_commitment,
            "locked_amount_piconero": self.locked_amount_piconero,
            "fee_reserved_piconero": self.fee_reserved_piconero,
            "locked_at_height": self.locked_at_height,
            "unlock_height": self.unlock_height,
            "spend_authorization_root": self.spend_authorization_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPayoutCommitment {
    pub payout_id: String,
    pub quote_id: String,
    pub one_time_address_commitment: String,
    pub view_tag_commitment: String,
    pub amount_commitment: String,
    pub ring_decoy_set_root: String,
    pub tx_extra_commitment: String,
    pub payout_amount_piconero: u64,
    pub prepared_at_height: u64,
    pub submitted_monero_height: u64,
    pub status: PayoutStatus,
}

impl MoneroPayoutCommitment {
    pub fn new(
        quote: &ExitQuote,
        label: &str,
        prepared_at_height: u64,
        submitted_monero_height: u64,
    ) -> Self {
        let one_time_address_commitment = labeled_hash("ROUTER-MONERO-OTA", label);
        let view_tag_commitment = labeled_hash("ROUTER-MONERO-VIEW-TAG", label);
        let amount_commitment = commitment_hash(
            "ROUTER-MONERO-AMOUNT",
            &[&quote.quote_id, &quote.min_payout_piconero.to_string()],
        );
        let ring_decoy_set_root = labeled_hash("ROUTER-MONERO-DECOY-SET", label);
        let tx_extra_commitment = labeled_hash("ROUTER-MONERO-TX-EXTRA", label);
        let mut payout = Self {
            payout_id: String::new(),
            quote_id: quote.quote_id.clone(),
            one_time_address_commitment,
            view_tag_commitment,
            amount_commitment,
            ring_decoy_set_root,
            tx_extra_commitment,
            payout_amount_piconero: quote.min_payout_piconero,
            prepared_at_height,
            submitted_monero_height,
            status: PayoutStatus::Signed,
        };
        payout.payout_id = id_from_record("ROUTER-PAYOUT-ID", &payout.public_record_without_id());
        payout
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "payout_id", json!(self.payout_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "one_time_address_commitment": self.one_time_address_commitment,
            "view_tag_commitment": self.view_tag_commitment,
            "amount_commitment": self.amount_commitment,
            "ring_decoy_set_root": self.ring_decoy_set_root,
            "tx_extra_commitment": self.tx_extra_commitment,
            "payout_amount_piconero": self.payout_amount_piconero,
            "prepared_at_height": self.prepared_at_height,
            "submitted_monero_height": self.submitted_monero_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub route_id: String,
    pub payout_id: String,
    pub monero_txid_commitment: String,
    pub output_proof_root: String,
    pub key_image_guard_root: String,
    pub settled_amount_piconero: u64,
    pub fee_paid_piconero: u64,
    pub posted_at_height: u64,
    pub final_after_height: u64,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    pub fn new(
        route: &RouteCommitment,
        payout: &MoneroPayoutCommitment,
        quote: &ExitQuote,
        label: &str,
        posted_at_height: u64,
        config: &Config,
    ) -> Self {
        let monero_txid_commitment = labeled_hash("ROUTER-MONERO-TXID", label);
        let output_proof_root = commitment_hash(
            "ROUTER-OUTPUT-PROOF",
            &[&route.route_id, &payout.payout_id, &monero_txid_commitment],
        );
        let key_image_guard_root = commitment_hash(
            "ROUTER-KEY-IMAGE-GUARD",
            &[&quote.replay_nullifier, &monero_txid_commitment],
        );
        let mut receipt = Self {
            receipt_id: String::new(),
            route_id: route.route_id.clone(),
            payout_id: payout.payout_id.clone(),
            monero_txid_commitment,
            output_proof_root,
            key_image_guard_root,
            settled_amount_piconero: payout.payout_amount_piconero,
            fee_paid_piconero: quote.fee_piconero,
            posted_at_height,
            final_after_height: posted_at_height.saturating_add(config.challenge_window_blocks),
            status: ReceiptStatus::Posted,
        };
        receipt.receipt_id =
            id_from_record("ROUTER-RECEIPT-ID", &receipt.public_record_without_id());
        receipt
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "receipt_id", json!(self.receipt_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "payout_id": self.payout_id,
            "monero_txid_commitment": self.monero_txid_commitment,
            "output_proof_root": self.output_proof_root,
            "key_image_guard_root": self.key_image_guard_root,
            "settled_amount_piconero": self.settled_amount_piconero,
            "fee_paid_piconero": self.fee_paid_piconero,
            "posted_at_height": self.posted_at_height,
            "final_after_height": self.final_after_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeChallenge {
    pub challenge_id: String,
    pub receipt_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub challenged_at_height: u64,
    pub challenge_deadline_height: u64,
    pub bond_piconero: u64,
    pub status: ChallengeStatus,
}

impl DisputeChallenge {
    pub fn new(
        receipt_id: &str,
        label: &str,
        challenged_at_height: u64,
        bond_piconero: u64,
        config: &Config,
    ) -> Self {
        let challenger_commitment = labeled_hash("ROUTER-CHALLENGER", label);
        let evidence_root = commitment_hash("ROUTER-CHALLENGE-EVIDENCE", &[receipt_id, label]);
        let mut challenge = Self {
            challenge_id: String::new(),
            receipt_id: receipt_id.to_string(),
            challenger_commitment,
            evidence_root,
            challenged_at_height,
            challenge_deadline_height: challenged_at_height
                .saturating_add(config.challenge_window_blocks),
            bond_piconero,
            status: ChallengeStatus::EvidencePosted,
        };
        challenge.challenge_id =
            id_from_record("ROUTER-CHALLENGE-ID", &challenge.public_record_without_id());
        challenge
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "challenge_id", json!(self.challenge_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "challenged_at_height": self.challenged_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "bond_piconero": self.bond_piconero,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayProtectionRecord {
    pub nullifier: String,
    pub quote_id: String,
    pub route_id: String,
    pub first_seen_height: u64,
    pub replay_domain: String,
}

impl ReplayProtectionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "quote_id": self.quote_id,
            "route_id": self.route_id,
            "first_seen_height": self.first_seen_height,
            "replay_domain": self.replay_domain,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub disclosed_fields: BTreeSet<String>,
    pub hidden_field_root: String,
    pub emitted_at_height: u64,
}

impl PrivacyPublicRecord {
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_record: &Value,
        disclosed_fields: &[&str],
        emitted_at_height: u64,
    ) -> Self {
        let disclosed_fields = disclosed_fields
            .iter()
            .map(|field| (*field).to_string())
            .collect::<BTreeSet<_>>();
        let subject_root = root_from_record(subject_record);
        let hidden_field_root = commitment_hash(
            "ROUTER-HIDDEN-FIELDS",
            &[subject_kind, subject_id, &subject_root],
        );
        let mut record = Self {
            record_id: String::new(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            disclosed_fields,
            hidden_field_root,
            emitted_at_height,
        };
        record.record_id = id_from_record(
            "ROUTER-PUBLIC-RECORD-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        set_json_field(&mut record, "record_id", json!(self.record_id));
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "disclosed_fields": self.disclosed_fields.iter().cloned().collect::<Vec<_>>(),
            "hidden_field_root": self.hidden_field_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub quote_root: String,
    pub route_root: String,
    pub signer_lane_root: String,
    pub liquidity_lock_root: String,
    pub payout_commitment_root: String,
    pub fee_cap_root: String,
    pub replay_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "quote_root": self.quote_root,
            "route_root": self.route_root,
            "signer_lane_root": self.signer_lane_root,
            "liquidity_lock_root": self.liquidity_lock_root,
            "payout_commitment_root": self.payout_commitment_root,
            "fee_cap_root": self.fee_cap_root,
            "replay_root": self.replay_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub quote_count: u64,
    pub open_quote_count: u64,
    pub route_count: u64,
    pub signer_lane_count: u64,
    pub active_signer_lane_count: u64,
    pub liquidity_lock_count: u64,
    pub open_liquidity_lock_count: u64,
    pub payout_commitment_count: u64,
    pub receipt_count: u64,
    pub final_receipt_count: u64,
    pub challenge_count: u64,
    pub open_challenge_count: u64,
    pub replay_nullifier_count: u64,
    pub public_record_count: u64,
    pub locked_liquidity_piconero: u64,
    pub settled_payout_piconero: u64,
    pub reserved_fee_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_count": self.quote_count,
            "open_quote_count": self.open_quote_count,
            "route_count": self.route_count,
            "signer_lane_count": self.signer_lane_count,
            "active_signer_lane_count": self.active_signer_lane_count,
            "liquidity_lock_count": self.liquidity_lock_count,
            "open_liquidity_lock_count": self.open_liquidity_lock_count,
            "payout_commitment_count": self.payout_commitment_count,
            "receipt_count": self.receipt_count,
            "final_receipt_count": self.final_receipt_count,
            "challenge_count": self.challenge_count,
            "open_challenge_count": self.open_challenge_count,
            "replay_nullifier_count": self.replay_nullifier_count,
            "public_record_count": self.public_record_count,
            "locked_liquidity_piconero": self.locked_liquidity_piconero,
            "settled_payout_piconero": self.settled_payout_piconero,
            "reserved_fee_piconero": self.reserved_fee_piconero,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub quotes: BTreeMap<String, ExitQuote>,
    pub routes: BTreeMap<String, RouteCommitment>,
    pub signer_lanes: BTreeMap<String, PqSignerLane>,
    pub liquidity_locks: BTreeMap<String, LiquidityLock>,
    pub payout_commitments: BTreeMap<String, MoneroPayoutCommitment>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub challenges: BTreeMap<String, DisputeChallenge>,
    pub replay_index: BTreeMap<String, ReplayProtectionRecord>,
    pub public_records: BTreeMap<String, PrivacyPublicRecord>,
    pub paused: bool,
}

impl State {
    pub fn devnet() -> MoneroPqFastExitSettlementRouterResult<Self> {
        let config = Config::devnet();
        let height = MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_DEVNET_HEIGHT;

        let mut signer_lanes = BTreeMap::new();
        let low_fee_lane = PqSignerLane::new("low-fee-lane", ExitClass::LowFee, 5, 1_200);
        let fast_lane = PqSignerLane::new("fast-lane", ExitClass::Fast, 7, 1_800);
        let defi_lane = PqSignerLane::new("defi-lane", ExitClass::Defi, 6, 1_500);
        let contract_lane = PqSignerLane::new("contract-lane", ExitClass::SmartContract, 6, 1_500);
        insert_unique(
            &mut signer_lanes,
            low_fee_lane.lane_id.clone(),
            low_fee_lane,
            "signer lane",
        )?;
        insert_unique(
            &mut signer_lanes,
            fast_lane.lane_id.clone(),
            fast_lane,
            "signer lane",
        )?;
        insert_unique(
            &mut signer_lanes,
            defi_lane.lane_id.clone(),
            defi_lane,
            "signer lane",
        )?;
        insert_unique(
            &mut signer_lanes,
            contract_lane.lane_id.clone(),
            contract_lane,
            "signer lane",
        )?;

        let signer_ids = signer_lanes.keys().cloned().collect::<Vec<_>>();
        let low_fee_lane_id = string_at(&signer_ids, 0, "missing low fee lane")?;
        let fast_lane_id = string_at(&signer_ids, 1, "missing fast lane")?;
        let defi_lane_id = string_at(&signer_ids, 2, "missing defi lane")?;
        let contract_lane_id = string_at(&signer_ids, 3, "missing contract lane")?;

        let placeholder_route = labeled_hash("ROUTER-PLACEHOLDER-ROUTE", "devnet");
        let quote_specs = [
            (
                ExitClass::LowFee,
                "wallet-low-fee",
                low_fee_lane_id.as_str(),
                31_000_000_000_u64,
            ),
            (
                ExitClass::Fast,
                "merchant-fast",
                fast_lane_id.as_str(),
                92_000_000_000_u64,
            ),
            (
                ExitClass::Defi,
                "amm-arb",
                defi_lane_id.as_str(),
                144_000_000_000_u64,
            ),
            (
                ExitClass::SmartContract,
                "contract-escrow",
                contract_lane_id.as_str(),
                210_000_000_000_u64,
            ),
        ];

        let mut quotes = BTreeMap::new();
        let mut routes = BTreeMap::new();
        let mut locks = BTreeMap::new();
        let mut payouts = BTreeMap::new();
        let mut receipts = BTreeMap::new();
        let mut challenges = BTreeMap::new();
        let mut replay_index = BTreeMap::new();
        let mut public_records = BTreeMap::new();

        for (index, (exit_class, label, lane_id, amount)) in quote_specs.iter().enumerate() {
            let issued_at = height.saturating_sub(12).saturating_add(index as u64);
            let quote = ExitQuote::new(
                *exit_class,
                label,
                &placeholder_route,
                lane_id,
                *amount,
                issued_at,
                &config,
            );
            let payout = MoneroPayoutCommitment::new(
                &quote,
                label,
                issued_at.saturating_add(2),
                2_800_000_u64.saturating_add(index as u64),
            );
            let route = RouteCommitment::new(
                &quote,
                label,
                &payout.payout_id,
                issued_at.saturating_add(1),
                &config,
            );
            let lock = LiquidityLock::new(
                &quote,
                &route.route_id,
                label,
                issued_at.saturating_add(2),
                &config,
            );
            let receipt = SettlementReceipt::new(
                &route,
                &payout,
                &quote,
                label,
                issued_at.saturating_add(5),
                &config,
            );
            let replay = ReplayProtectionRecord {
                nullifier: quote.replay_nullifier.clone(),
                quote_id: quote.quote_id.clone(),
                route_id: route.route_id.clone(),
                first_seen_height: quote.issued_at_height,
                replay_domain: config.replay_domain.clone(),
            };

            if index == 2 {
                let challenge = DisputeChallenge::new(
                    &receipt.receipt_id,
                    "liquidity-watchtower",
                    receipt.posted_at_height.saturating_add(3),
                    config.fee_floor_piconero.saturating_mul(50),
                    &config,
                );
                insert_unique(
                    &mut challenges,
                    challenge.challenge_id.clone(),
                    challenge,
                    "challenge",
                )?;
            }

            let public_quote = PrivacyPublicRecord::new(
                "exit_quote",
                &quote.quote_id,
                &quote.public_record(),
                &[
                    "exit_class",
                    "amount_piconero",
                    "fee_piconero",
                    "valid_until_height",
                ],
                height,
            );
            let public_route = PrivacyPublicRecord::new(
                "route_commitment",
                &route.route_id,
                &route.public_record(),
                &["route_root", "fee_cap_commitment", "status"],
                height,
            );
            let public_receipt = PrivacyPublicRecord::new(
                "settlement_receipt",
                &receipt.receipt_id,
                &receipt.public_record(),
                &["output_proof_root", "final_after_height", "status"],
                height,
            );

            insert_unique(
                &mut replay_index,
                replay.nullifier.clone(),
                replay,
                "replay record",
            )?;
            insert_unique(
                &mut public_records,
                public_quote.record_id.clone(),
                public_quote,
                "public record",
            )?;
            insert_unique(
                &mut public_records,
                public_route.record_id.clone(),
                public_route,
                "public record",
            )?;
            insert_unique(
                &mut public_records,
                public_receipt.record_id.clone(),
                public_receipt,
                "public record",
            )?;
            insert_unique(&mut quotes, quote.quote_id.clone(), quote, "quote")?;
            insert_unique(&mut payouts, payout.payout_id.clone(), payout, "payout")?;
            insert_unique(&mut routes, route.route_id.clone(), route, "route")?;
            insert_unique(&mut locks, lock.lock_id.clone(), lock, "liquidity lock")?;
            insert_unique(
                &mut receipts,
                receipt.receipt_id.clone(),
                receipt,
                "receipt",
            )?;
        }

        for quote in quotes.values() {
            if let Some(lane) = signer_lanes.get_mut(&quote.signer_lane_id) {
                lane.active_quote_count = lane.active_quote_count.saturating_add(1);
            }
        }

        let state = Self {
            height,
            config,
            quotes,
            routes,
            signer_lanes,
            liquidity_locks: locks,
            payout_commitments: payouts,
            receipts,
            challenges,
            replay_index,
            public_records,
            paused: false,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroPqFastExitSettlementRouterResult<()> {
        self.config.validate()?;
        require(
            self.quotes.len() <= self.config.max_quotes,
            "too many quotes",
        )?;
        require(
            self.routes.len() <= self.config.max_routes,
            "too many routes",
        )?;
        require(
            self.signer_lanes.len() <= self.config.max_signer_lanes,
            "too many signer lanes",
        )?;
        require(
            self.liquidity_locks.len() <= self.config.max_liquidity_locks,
            "too many liquidity locks",
        )?;
        require(
            self.payout_commitments.len() <= self.config.max_payouts,
            "too many payout commitments",
        )?;
        require(
            self.receipts.len() <= self.config.max_receipts,
            "too many receipts",
        )?;
        require(
            self.challenges.len() <= self.config.max_challenges,
            "too many challenges",
        )?;
        require(
            self.public_records.len() <= self.config.max_public_records,
            "too many public records",
        )?;

        for (lane_id, lane) in &self.signer_lanes {
            require(lane_id == &lane.lane_id, "signer lane map key mismatch")?;
            require(!lane.lane_id.is_empty(), "signer lane id is empty")?;
            require(lane.quorum_threshold > 0, "signer quorum threshold is zero")?;
            require(
                lane.quorum_threshold <= lane.quorum_weight,
                "signer quorum threshold exceeds weight",
            )?;
            require(
                lane.min_security_bits >= self.config.min_pq_security_bits,
                "signer lane pq security below config",
            )?;
            require(
                lane.fee_share_bps <= MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_BPS,
                "signer fee share too high",
            )?;
        }

        let mut nullifiers = BTreeSet::new();
        for (quote_id, quote) in &self.quotes {
            require(quote_id == &quote.quote_id, "quote map key mismatch")?;
            require(!quote.quote_id.is_empty(), "quote id is empty")?;
            require(
                self.routes.contains_key(&quote.route_commitment_id)
                    || quote.route_commitment_id
                        == labeled_hash("ROUTER-PLACEHOLDER-ROUTE", "devnet"),
                "quote route missing",
            )?;
            require(
                self.signer_lanes.contains_key(&quote.signer_lane_id),
                "quote signer lane missing",
            )?;
            require(quote.amount_piconero > 0, "quote amount is zero")?;
            require(
                quote.fee_piconero <= quote.max_fee_piconero,
                "quote fee exceeds cap",
            )?;
            require(
                quote.fee_cap_bps <= self.config.max_fee_bps,
                "quote bps exceeds cap",
            )?;
            require(
                quote.valid_until_height >= quote.issued_at_height,
                "quote ttl reversed",
            )?;
            require(
                quote.valid_until_height
                    <= quote
                        .issued_at_height
                        .saturating_add(self.config.quote_ttl_blocks),
                "quote ttl exceeds config",
            )?;
            require(
                nullifiers.insert(quote.replay_nullifier.clone()),
                "duplicate quote nullifier",
            )?;
            require(
                self.replay_index.contains_key(&quote.replay_nullifier),
                "quote replay record missing",
            )?;
        }

        for (route_id, route) in &self.routes {
            require(route_id == &route.route_id, "route map key mismatch")?;
            require(
                self.quotes.contains_key(&route.quote_id),
                "route quote missing",
            )?;
            require(
                self.payout_commitments
                    .contains_key(&route.monero_payout_commitment_id),
                "route payout missing",
            )?;
            require(!route.route_root.is_empty(), "route root is empty")?;
            require(
                route.expires_at_height >= route.committed_at_height,
                "route ttl reversed",
            )?;
        }

        for (lock_id, lock) in &self.liquidity_locks {
            require(lock_id == &lock.lock_id, "lock map key mismatch")?;
            require(
                self.quotes.contains_key(&lock.quote_id),
                "lock quote missing",
            )?;
            require(
                self.routes.contains_key(&lock.route_id),
                "lock route missing",
            )?;
            require(
                lock.locked_amount_piconero >= self.config.fee_floor_piconero,
                "lock amount under fee floor",
            )?;
            require(
                lock.unlock_height >= lock.locked_at_height,
                "lock ttl reversed",
            )?;
        }

        for (payout_id, payout) in &self.payout_commitments {
            require(payout_id == &payout.payout_id, "payout map key mismatch")?;
            require(
                self.quotes.contains_key(&payout.quote_id),
                "payout quote missing",
            )?;
            require(
                payout.payout_amount_piconero > 0,
                "payout amount must be positive",
            )?;
            require(
                !payout.one_time_address_commitment.is_empty(),
                "payout address commitment empty",
            )?;
        }

        for (receipt_id, receipt) in &self.receipts {
            require(
                receipt_id == &receipt.receipt_id,
                "receipt map key mismatch",
            )?;
            require(
                self.routes.contains_key(&receipt.route_id),
                "receipt route missing",
            )?;
            require(
                self.payout_commitments.contains_key(&receipt.payout_id),
                "receipt payout missing",
            )?;
            require(
                receipt.final_after_height >= receipt.posted_at_height,
                "receipt finality reversed",
            )?;
        }

        for (challenge_id, challenge) in &self.challenges {
            require(
                challenge_id == &challenge.challenge_id,
                "challenge map key mismatch",
            )?;
            require(
                self.receipts.contains_key(&challenge.receipt_id),
                "challenge receipt missing",
            )?;
            require(
                challenge.challenge_deadline_height >= challenge.challenged_at_height,
                "challenge deadline reversed",
            )?;
            require(challenge.bond_piconero > 0, "challenge bond is zero")?;
        }

        for (nullifier, replay) in &self.replay_index {
            require(nullifier == &replay.nullifier, "replay map key mismatch")?;
            require(
                self.quotes.contains_key(&replay.quote_id),
                "replay quote missing",
            )?;
            require(
                self.routes.contains_key(&replay.route_id)
                    || replay.route_id == labeled_hash("ROUTER-PLACEHOLDER-ROUTE", "devnet"),
                "replay route missing",
            )?;
            require(
                replay.replay_domain == self.config.replay_domain,
                "replay domain mismatch",
            )?;
        }

        for (record_id, record) in &self.public_records {
            require(
                record_id == &record.record_id,
                "public record map key mismatch",
            )?;
            require(!record.subject_kind.is_empty(), "public record kind empty")?;
            require(!record.subject_id.is_empty(), "public record subject empty")?;
            require(!record.subject_root.is_empty(), "public record root empty")?;
        }

        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroPqFastExitSettlementRouterResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> MoneroPqFastExitSettlementRouterResult<()> {
        require(height >= self.height, "height cannot move backward")?;
        self.height = height;
        self.expire_records();
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        let quote_records = values_to_records(&self.quotes, ExitQuote::public_record);
        let route_records = values_to_records(&self.routes, RouteCommitment::public_record);
        let lane_records = values_to_records(&self.signer_lanes, PqSignerLane::public_record);
        let lock_records = values_to_records(&self.liquidity_locks, LiquidityLock::public_record);
        let payout_records = values_to_records(
            &self.payout_commitments,
            MoneroPayoutCommitment::public_record,
        );
        let receipt_records = values_to_records(&self.receipts, SettlementReceipt::public_record);
        let challenge_records =
            values_to_records(&self.challenges, DisputeChallenge::public_record);
        let replay_records =
            values_to_records(&self.replay_index, ReplayProtectionRecord::public_record);
        let public_records =
            values_to_records(&self.public_records, PrivacyPublicRecord::public_record);
        let fee_records = self
            .quotes
            .values()
            .map(|quote| {
                json!({
                    "quote_id": quote.quote_id,
                    "fee_piconero": quote.fee_piconero,
                    "max_fee_piconero": quote.max_fee_piconero,
                    "fee_cap_bps": quote.fee_cap_bps,
                })
            })
            .collect::<Vec<_>>();

        Roots {
            config_root: root_from_record(&self.config.public_record()),
            quote_root: merkle_root("MONERO-PQ-FAST-EXIT-QUOTE", &quote_records),
            route_root: merkle_root("MONERO-PQ-FAST-EXIT-ROUTE", &route_records),
            signer_lane_root: merkle_root("MONERO-PQ-FAST-EXIT-SIGNER-LANE", &lane_records),
            liquidity_lock_root: merkle_root("MONERO-PQ-FAST-EXIT-LIQUIDITY-LOCK", &lock_records),
            payout_commitment_root: merkle_root("MONERO-PQ-FAST-EXIT-PAYOUT", &payout_records),
            fee_cap_root: merkle_root("MONERO-PQ-FAST-EXIT-FEE-CAP", &fee_records),
            replay_root: merkle_root("MONERO-PQ-FAST-EXIT-REPLAY", &replay_records),
            receipt_root: merkle_root("MONERO-PQ-FAST-EXIT-RECEIPT", &receipt_records),
            challenge_root: merkle_root("MONERO-PQ-FAST-EXIT-CHALLENGE", &challenge_records),
            public_record_root: merkle_root("MONERO-PQ-FAST-EXIT-PUBLIC-RECORD", &public_records),
        }
    }

    pub fn counters(&self) -> Counters {
        let open_quote_count = self
            .quotes
            .values()
            .filter(|quote| quote.status.live())
            .count() as u64;
        let active_signer_lane_count = self
            .signer_lanes
            .values()
            .filter(|lane| lane.status.usable())
            .count() as u64;
        let open_liquidity_lock_count = self
            .liquidity_locks
            .values()
            .filter(|lock| matches!(lock.status, LockStatus::Reserved | LockStatus::Bound))
            .count() as u64;
        let final_receipt_count = self
            .receipts
            .values()
            .filter(|receipt| receipt.status == ReceiptStatus::Final)
            .count() as u64;
        let open_challenge_count = self
            .challenges
            .values()
            .filter(|challenge| {
                matches!(
                    challenge.status,
                    ChallengeStatus::Open | ChallengeStatus::EvidencePosted
                )
            })
            .count() as u64;
        let locked_liquidity_piconero = self
            .liquidity_locks
            .values()
            .filter(|lock| matches!(lock.status, LockStatus::Reserved | LockStatus::Bound))
            .map(|lock| lock.locked_amount_piconero)
            .fold(0_u64, u64::saturating_add);
        let settled_payout_piconero = self
            .receipts
            .values()
            .map(|receipt| receipt.settled_amount_piconero)
            .fold(0_u64, u64::saturating_add);
        let reserved_fee_piconero = self
            .liquidity_locks
            .values()
            .map(|lock| lock.fee_reserved_piconero)
            .fold(0_u64, u64::saturating_add);

        Counters {
            quote_count: self.quotes.len() as u64,
            open_quote_count,
            route_count: self.routes.len() as u64,
            signer_lane_count: self.signer_lanes.len() as u64,
            active_signer_lane_count,
            liquidity_lock_count: self.liquidity_locks.len() as u64,
            open_liquidity_lock_count,
            payout_commitment_count: self.payout_commitments.len() as u64,
            receipt_count: self.receipts.len() as u64,
            final_receipt_count,
            challenge_count: self.challenges.len() as u64,
            open_challenge_count,
            replay_nullifier_count: self.replay_index.len() as u64,
            public_record_count: self.public_records.len() as u64,
            locked_liquidity_piconero,
            settled_payout_piconero,
            reserved_fee_piconero,
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn expire_records(&mut self) {
        for quote in self.quotes.values_mut() {
            if quote.status.live() && self.height > quote.valid_until_height {
                quote.status = QuoteStatus::Expired;
            }
        }
        for route in self.routes.values_mut() {
            if matches!(route.status, RouteStatus::Committed | RouteStatus::Locked)
                && self.height > route.expires_at_height
            {
                route.status = RouteStatus::Expired;
            }
        }
        for lock in self.liquidity_locks.values_mut() {
            if matches!(lock.status, LockStatus::Reserved | LockStatus::Bound)
                && self.height > lock.unlock_height
            {
                lock.status = LockStatus::Expired;
            }
        }
        for receipt in self.receipts.values_mut() {
            if receipt.status == ReceiptStatus::Posted && self.height >= receipt.final_after_height
            {
                receipt.status = ReceiptStatus::Final;
            }
        }
        for challenge in self.challenges.values_mut() {
            if matches!(
                challenge.status,
                ChallengeStatus::Open | ChallengeStatus::EvidencePosted
            ) && self.height > challenge.challenge_deadline_height
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }
}

pub fn root_from_record(record: &serde_json::Value) -> String {
    domain_hash(
        "MONERO-PQ-FAST-EXIT-SETTLEMENT-ROUTER-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> MoneroPqFastExitSettlementRouterResult<State> {
    State::devnet()
}

fn values_to_records<T, F>(values: &BTreeMap<String, T>, f: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    values.values().map(f).collect()
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn labeled_hash(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn commitment_hash(domain: &str, values: &[&str]) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_PROTOCOL_VERSION,
        "values": values,
    });
    domain_hash(domain, &[HashPart::Json(&record)], 32)
}

fn signed_commitment(kind: &str, signer_lane_id: &str, subject_id: &str, height: u64) -> String {
    let record = json!({
        "kind": kind,
        "signer_lane_id": signer_lane_id,
        "subject_id": subject_id,
        "height": height,
        "scheme": MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_QUOTE_SCHEME,
    });
    domain_hash(
        "MONERO-PQ-FAST-EXIT-SIGNATURE-COMMITMENT",
        &[HashPart::Json(&record)],
        32,
    )
}

fn fee_for(amount_piconero: u64, fee_bps: u64, floor_piconero: u64) -> u64 {
    let proportional = amount_piconero
        .saturating_mul(fee_bps)
        .saturating_add(MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_BPS - 1)
        / MONERO_PQ_FAST_EXIT_SETTLEMENT_ROUTER_MAX_BPS;
    proportional.max(floor_piconero)
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}

fn require(condition: bool, message: &str) -> MoneroPqFastExitSettlementRouterResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroPqFastExitSettlementRouterResult<()> {
    if map.insert(key, value).is_some() {
        Err(format!("duplicate {label}"))
    } else {
        Ok(())
    }
}

fn string_at(
    values: &[String],
    index: usize,
    message: &str,
) -> MoneroPqFastExitSettlementRouterResult<String> {
    match values.get(index) {
        Some(value) => Ok(value.clone()),
        None => Err(message.to_string()),
    }
}
