use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-hash-time-lock-market-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_HASH_TIME_LOCK_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIMANT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-htlc-claimant-attestation-v1";
pub const HTLC_COMMITMENT_SUITE: &str =
    "confidential-preimage-hashlock+height-timelock+tokenized-claim-note-v1";
pub const SOLVER_QUOTE_SUITE: &str =
    "sealed-solver-quote+low-fee-cross-chain-confidential-settlement-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-tokenized-htlc-market-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_612_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_CLAIM_TOKEN_ASSET_ID: &str = "confidential-htlc-claim-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "dnr-low-fee-rebate-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POSITION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_EXPIRY_BUCKET_WIDTH_BLOCKS: u64 = 24;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_LANE_FEE_BPS: u64 = 24;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HtlcPositionKind {
    AtomicSwap,
    BridgeExit,
    BridgeEntry,
    SolverInventoryRebalance,
    MerchantInvoice,
    VaultMigration,
    ContractCallback,
}

impl HtlcPositionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AtomicSwap => "atomic_swap",
            Self::BridgeExit => "bridge_exit",
            Self::BridgeEntry => "bridge_entry",
            Self::SolverInventoryRebalance => "solver_inventory_rebalance",
            Self::MerchantInvoice => "merchant_invoice",
            Self::VaultMigration => "vault_migration",
            Self::ContractCallback => "contract_callback",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Committed,
    Tokenized,
    Quoted,
    ClaimAttested,
    SettlementLocked,
    Claimed,
    Refunded,
    Expired,
    Disputed,
}

impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Tokenized => "tokenized",
            Self::Quoted => "quoted",
            Self::ClaimAttested => "claim_attested",
            Self::SettlementLocked => "settlement_locked",
            Self::Claimed => "claimed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn accepts_quote(self) -> bool {
        matches!(self, Self::Committed | Self::Tokenized | Self::Quoted)
    }

    pub fn accepts_claim(self) -> bool {
        matches!(
            self,
            Self::Quoted | Self::ClaimAttested | Self::SettlementLocked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimTokenStatus {
    Minted,
    Listed,
    Escrowed,
    Exercised,
    Redeemed,
    Burned,
    Frozen,
}

impl ClaimTokenStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Listed => "listed",
            Self::Escrowed => "escrowed",
            Self::Exercised => "exercised",
            Self::Redeemed => "redeemed",
            Self::Burned => "burned",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapLaneKind {
    MoneroToL2,
    L2ToMonero,
    L2ToL2,
    L2ToEvm,
    EvmToL2,
    BitcoinToL2,
}

impl SwapLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToL2 => "monero_to_l2",
            Self::L2ToMonero => "l2_to_monero",
            Self::L2ToL2 => "l2_to_l2",
            Self::L2ToEvm => "l2_to_evm",
            Self::EvmToL2 => "evm_to_l2",
            Self::BitcoinToL2 => "bitcoin_to_l2",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    QuoteOnly,
    SettlementOnly,
    Congested,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::QuoteOnly => "quote_only",
            Self::SettlementOnly => "settlement_only",
            Self::Congested => "congested",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Open | Self::QuoteOnly | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Selected,
    Locked,
    Filled,
    Cancelled,
    Expired,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Selected => "selected",
            Self::Locked => "locked",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ClaimantPreimagePossession,
    RefundAuthority,
    SolverFill,
    WatchtowerTimeout,
    CrossChainFinality,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimantPreimagePossession => "claimant_preimage_possession",
            Self::RefundAuthority => "refund_authority",
            Self::SolverFill => "solver_fill",
            Self::WatchtowerTimeout => "watchtower_timeout",
            Self::CrossChainFinality => "cross_chain_finality",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub claim_token_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub htlc_commitment_suite: String,
    pub pq_claimant_attestation_suite: String,
    pub solver_quote_suite: String,
    pub public_record_suite: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub position_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub expiry_bucket_width_blocks: u64,
    pub default_low_fee_rebate_bps: u64,
    pub max_solver_fee_bps: u64,
    pub max_lane_fee_bps: u64,
    pub require_roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            claim_token_asset_id: DEFAULT_CLAIM_TOKEN_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            htlc_commitment_suite: HTLC_COMMITMENT_SUITE.to_string(),
            pq_claimant_attestation_suite: PQ_CLAIMANT_ATTESTATION_SUITE.to_string(),
            solver_quote_suite: SOLVER_QUOTE_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            position_ttl_blocks: DEFAULT_POSITION_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            expiry_bucket_width_blocks: DEFAULT_EXPIRY_BUCKET_WIDTH_BLOCKS,
            default_low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            max_lane_fee_bps: DEFAULT_MAX_LANE_FEE_BPS,
            require_roots_only_public_records: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "claim_token_asset_id": self.claim_token_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "htlc_commitment_suite": self.htlc_commitment_suite,
            "pq_claimant_attestation_suite": self.pq_claimant_attestation_suite,
            "solver_quote_suite": self.solver_quote_suite,
            "public_record_suite": self.public_record_suite,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "position_ttl_blocks": self.position_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "expiry_bucket_width_blocks": self.expiry_bucket_width_blocks,
            "default_low_fee_rebate_bps": self.default_low_fee_rebate_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "max_lane_fee_bps": self.max_lane_fee_bps,
            "require_roots_only_public_records": self.require_roots_only_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub positions: u64,
    pub claim_tokens: u64,
    pub solver_quotes: u64,
    pub expiry_buckets: u64,
    pub swap_lanes: u64,
    pub pq_claimant_attestations: u64,
    pub settlement_rebates: u64,
    pub consumed_nullifiers: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "positions": self.positions,
            "claim_tokens": self.claim_tokens,
            "solver_quotes": self.solver_quotes,
            "expiry_buckets": self.expiry_buckets,
            "swap_lanes": self.swap_lanes,
            "pq_claimant_attestations": self.pq_claimant_attestations,
            "settlement_rebates": self.settlement_rebates,
            "consumed_nullifiers": self.consumed_nullifiers,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub positions_root: String,
    pub claim_tokens_root: String,
    pub solver_quotes_root: String,
    pub expiry_buckets_root: String,
    pub swap_lanes_root: String,
    pub pq_claimant_attestations_root: String,
    pub settlement_rebates_root: String,
    pub consumed_nullifiers_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "positions_root": self.positions_root,
            "claim_tokens_root": self.claim_tokens_root,
            "solver_quotes_root": self.solver_quotes_root,
            "expiry_buckets_root": self.expiry_buckets_root,
            "swap_lanes_root": self.swap_lanes_root,
            "pq_claimant_attestations_root": self.pq_claimant_attestations_root,
            "settlement_rebates_root": self.settlement_rebates_root,
            "consumed_nullifiers_root": self.consumed_nullifiers_root,
            "public_records_root": self.public_records_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HtlcPosition {
    pub position_id: String,
    pub lane_id: String,
    pub kind: HtlcPositionKind,
    pub status: PositionStatus,
    pub maker_commitment: String,
    pub claimant_commitment: String,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub amount_commitment: String,
    pub hashlock_root: String,
    pub timelock_height: u64,
    pub refund_height: u64,
    pub privacy_set_size: u64,
    pub claim_token_id: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl HtlcPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "maker_commitment": self.maker_commitment,
            "claimant_commitment": self.claimant_commitment,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "amount_commitment": self.amount_commitment,
            "hashlock_root": self.hashlock_root,
            "timelock_height": self.timelock_height,
            "refund_height": self.refund_height,
            "privacy_set_size": self.privacy_set_size,
            "claim_token_id": self.claim_token_id,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimToken {
    pub claim_token_id: String,
    pub position_id: String,
    pub owner_commitment: String,
    pub status: ClaimTokenStatus,
    pub token_commitment_root: String,
    pub transfer_policy_root: String,
    pub claim_nullifier: String,
    pub minted_at_height: u64,
    pub expires_at_height: u64,
}

impl ClaimToken {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_token_id": self.claim_token_id,
            "position_id": self.position_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status.as_str(),
            "token_commitment_root": self.token_commitment_root,
            "transfer_policy_root": self.transfer_policy_root,
            "claim_nullifier": self.claim_nullifier,
            "minted_at_height": self.minted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverQuote {
    pub quote_id: String,
    pub position_id: String,
    pub lane_id: String,
    pub solver_commitment: String,
    pub status: QuoteStatus,
    pub fill_asset_id: String,
    pub sealed_price_root: String,
    pub solver_fee_bps: u64,
    pub bond_commitment: String,
    pub pq_quote_signature_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl SolverQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "position_id": self.position_id,
            "lane_id": self.lane_id,
            "solver_commitment": self.solver_commitment,
            "status": self.status.as_str(),
            "fill_asset_id": self.fill_asset_id,
            "sealed_price_root": self.sealed_price_root,
            "solver_fee_bps": self.solver_fee_bps,
            "bond_commitment": self.bond_commitment,
            "pq_quote_signature_root": self.pq_quote_signature_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpiryBucket {
    pub bucket_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub position_ids: Vec<String>,
    pub bucket_commitment_root: String,
    pub expired_position_count: u64,
}

impl ExpiryBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "position_count": self.position_ids.len(),
            "bucket_commitment_root": self.bucket_commitment_root,
            "expired_position_count": self.expired_position_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossChainSwapLane {
    pub lane_id: String,
    pub kind: SwapLaneKind,
    pub status: LaneStatus,
    pub source_network: String,
    pub target_network: String,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub allowed_solver_set_root: String,
    pub finality_policy_root: String,
    pub max_lane_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub opened_at_height: u64,
}

impl CrossChainSwapLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "source_network": self.source_network,
            "target_network": self.target_network,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "allowed_solver_set_root": self.allowed_solver_set_root,
            "finality_policy_root": self.finality_policy_root,
            "max_lane_fee_bps": self.max_lane_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimantAttestation {
    pub attestation_id: String,
    pub position_id: String,
    pub claim_token_id: String,
    pub kind: AttestationKind,
    pub claimant_commitment: String,
    pub attested_preimage_root: String,
    pub pq_signature_root: String,
    pub verifier_committee_root: String,
    pub accepted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqClaimantAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "position_id": self.position_id,
            "claim_token_id": self.claim_token_id,
            "kind": self.kind.as_str(),
            "claimant_commitment": self.claimant_commitment,
            "attested_preimage_root": self.attested_preimage_root,
            "pq_signature_root": self.pq_signature_root,
            "verifier_committee_root": self.verifier_committee_root,
            "accepted_at_height": self.accepted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRebate {
    pub rebate_id: String,
    pub position_id: String,
    pub quote_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_commitment: String,
    pub settlement_batch_root: String,
    pub issued_at_height: u64,
}

impl SettlementRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "position_id": self.position_id,
            "quote_id": self.quote_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_bps": self.rebate_bps,
            "rebate_commitment": self.rebate_commitment,
            "settlement_batch_root": self.settlement_batch_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub positions: BTreeMap<String, HtlcPosition>,
    pub claim_tokens: BTreeMap<String, ClaimToken>,
    pub solver_quotes: BTreeMap<String, SolverQuote>,
    pub expiry_buckets: BTreeMap<String, ExpiryBucket>,
    pub swap_lanes: BTreeMap<String, CrossChainSwapLane>,
    pub pq_claimant_attestations: BTreeMap<String, PqClaimantAttestation>,
    pub settlement_rebates: BTreeMap<String, SettlementRebate>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            counters: Counters::default(),
            roots: Roots::default(),
            positions: BTreeMap::new(),
            claim_tokens: BTreeMap::new(),
            solver_quotes: BTreeMap::new(),
            expiry_buckets: BTreeMap::new(),
            swap_lanes: BTreeMap::new(),
            pq_claimant_attestations: BTreeMap::new(),
            settlement_rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "latest_public_record": self.public_records.last(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HASH-TIME-LOCK-MARKET-STATE",
            &json!({
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "positions_root": self.roots.positions_root,
                "claim_tokens_root": self.roots.claim_tokens_root,
                "solver_quotes_root": self.roots.solver_quotes_root,
                "expiry_buckets_root": self.roots.expiry_buckets_root,
                "swap_lanes_root": self.roots.swap_lanes_root,
                "pq_claimant_attestations_root": self.roots.pq_claimant_attestations_root,
                "settlement_rebates_root": self.roots.settlement_rebates_root,
                "consumed_nullifiers_root": self.roots.consumed_nullifiers_root,
                "public_records_root": self.roots.public_records_root,
                "height": self.height,
            }),
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-CONFIG",
            &self.config.public_record(),
        );
        self.roots.counters_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots.positions_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-POSITIONS",
            &self.positions,
            HtlcPosition::public_record,
        );
        self.roots.claim_tokens_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-CLAIM-TOKENS",
            &self.claim_tokens,
            ClaimToken::public_record,
        );
        self.roots.solver_quotes_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-SOLVER-QUOTES",
            &self.solver_quotes,
            SolverQuote::public_record,
        );
        self.roots.expiry_buckets_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-EXPIRY-BUCKETS",
            &self.expiry_buckets,
            ExpiryBucket::public_record,
        );
        self.roots.swap_lanes_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-SWAP-LANES",
            &self.swap_lanes,
            CrossChainSwapLane::public_record,
        );
        self.roots.pq_claimant_attestations_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-PQ-ATTESTATIONS",
            &self.pq_claimant_attestations,
            PqClaimantAttestation::public_record,
        );
        self.roots.settlement_rebates_root = map_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-REBATES",
            &self.settlement_rebates,
            SettlementRebate::public_record,
        );
        self.roots.consumed_nullifiers_root = set_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-NULLIFIERS",
            &self.consumed_nullifiers,
        );
        self.roots.public_records_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-PUBLIC-RECORDS",
            &self.public_records,
        );
        self.roots.state_root = self.state_root();
    }

    pub fn register_swap_lane(
        &mut self,
        lane: CrossChainSwapLane,
    ) -> PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<Value> {
        require_non_empty("lane_id", &lane.lane_id)?;
        require_bps(
            lane.max_lane_fee_bps,
            self.config.max_lane_fee_bps,
            "lane fee",
        )?;
        require_bps(lane.low_fee_rebate_bps, MAX_BPS, "low fee rebate")?;
        if self.swap_lanes.contains_key(&lane.lane_id) {
            return Err("tokenized htlc market lane already exists".to_string());
        }
        let record = lane.public_record();
        self.swap_lanes.insert(lane.lane_id.clone(), lane);
        self.counters.swap_lanes = self.swap_lanes.len() as u64;
        self.public_records.push(json!({
            "event": "swap_lane_registered",
            "record": record,
        }));
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn commit_position(
        &mut self,
        mut position: HtlcPosition,
    ) -> PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<Value> {
        require_non_empty("position_id", &position.position_id)?;
        require_non_empty("lane_id", &position.lane_id)?;
        let lane = self
            .swap_lanes
            .get(&position.lane_id)
            .ok_or_else(|| "tokenized htlc market lane not found".to_string())?;
        if !lane.status.accepts_positions() {
            return Err("tokenized htlc market lane does not accept positions".to_string());
        }
        if position.privacy_set_size < self.config.min_privacy_set_size {
            return Err("tokenized htlc market privacy set below minimum".to_string());
        }
        if position.timelock_height <= self.height
            || position.refund_height <= position.timelock_height
        {
            return Err("tokenized htlc market invalid timelock window".to_string());
        }
        if self.positions.contains_key(&position.position_id) {
            return Err("tokenized htlc market position already exists".to_string());
        }
        if position.claim_token_id.trim().is_empty() {
            position.claim_token_id = derived_id("claim-token", &position.public_record());
        }
        let claim_token = ClaimToken {
            claim_token_id: position.claim_token_id.clone(),
            position_id: position.position_id.clone(),
            owner_commitment: position.claimant_commitment.clone(),
            status: ClaimTokenStatus::Minted,
            token_commitment_root: root_from_record(
                "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-CLAIM-TOKEN-COMMITMENT",
                &position.public_record(),
            ),
            transfer_policy_root: demo_root(
                "default-transfer-policy",
                self.counters.claim_tokens + 1,
            ),
            claim_nullifier: derived_id("claim-nullifier", &position.public_record()),
            minted_at_height: self.height,
            expires_at_height: position.refund_height,
        };
        let bucket_id = expiry_bucket_id(
            position.refund_height,
            self.config.expiry_bucket_width_blocks,
        );
        let bucket = self
            .expiry_buckets
            .entry(bucket_id.clone())
            .or_insert_with(|| ExpiryBucket {
                bucket_id: bucket_id.clone(),
                start_height: bucket_start(
                    position.refund_height,
                    self.config.expiry_bucket_width_blocks,
                ),
                end_height: bucket_start(
                    position.refund_height,
                    self.config.expiry_bucket_width_blocks,
                ) + self.config.expiry_bucket_width_blocks
                    - 1,
                position_ids: Vec::new(),
                bucket_commitment_root: String::new(),
                expired_position_count: 0,
            });
        bucket.position_ids.push(position.position_id.clone());
        bucket.bucket_commitment_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-EXPIRY-BUCKET-MEMBERS",
            &bucket
                .position_ids
                .iter()
                .map(|position_id| json!({ "position_id": position_id }))
                .collect::<Vec<_>>(),
        );

        let record = position.public_record();
        self.claim_tokens
            .insert(claim_token.claim_token_id.clone(), claim_token);
        self.positions
            .insert(position.position_id.clone(), position);
        self.counters.positions = self.positions.len() as u64;
        self.counters.claim_tokens = self.claim_tokens.len() as u64;
        self.counters.expiry_buckets = self.expiry_buckets.len() as u64;
        self.public_records.push(json!({
            "event": "htlc_position_committed",
            "record": record,
        }));
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn post_solver_quote(
        &mut self,
        quote: SolverQuote,
    ) -> PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<Value> {
        require_non_empty("quote_id", &quote.quote_id)?;
        require_bps(
            quote.solver_fee_bps,
            self.config.max_solver_fee_bps,
            "solver fee",
        )?;
        let position = self
            .positions
            .get_mut(&quote.position_id)
            .ok_or_else(|| "tokenized htlc market position not found".to_string())?;
        if !position.status.accepts_quote() {
            return Err("tokenized htlc market position does not accept quotes".to_string());
        }
        let lane = self
            .swap_lanes
            .get(&quote.lane_id)
            .ok_or_else(|| "tokenized htlc market quote lane not found".to_string())?;
        if !lane.status.accepts_quotes() {
            return Err("tokenized htlc market lane does not accept quotes".to_string());
        }
        if quote.expires_at_height <= self.height {
            return Err("tokenized htlc market quote already expired".to_string());
        }
        if self.solver_quotes.contains_key(&quote.quote_id) {
            return Err("tokenized htlc market quote already exists".to_string());
        }
        position.status = PositionStatus::Quoted;
        position.updated_at_height = self.height;
        let record = quote.public_record();
        self.solver_quotes.insert(quote.quote_id.clone(), quote);
        self.counters.solver_quotes = self.solver_quotes.len() as u64;
        self.public_records.push(json!({
            "event": "solver_quote_posted",
            "record": record,
        }));
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_pq_claimant_attestation(
        &mut self,
        attestation: PqClaimantAttestation,
    ) -> PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<Value> {
        require_non_empty("attestation_id", &attestation.attestation_id)?;
        let position = self
            .positions
            .get_mut(&attestation.position_id)
            .ok_or_else(|| "tokenized htlc market attestation position not found".to_string())?;
        if !position.status.accepts_claim() {
            return Err(
                "tokenized htlc market position does not accept claim attestation".to_string(),
            );
        }
        if attestation.claim_token_id != position.claim_token_id {
            return Err("tokenized htlc market attestation claim token mismatch".to_string());
        }
        if self
            .pq_claimant_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err("tokenized htlc market attestation already exists".to_string());
        }
        position.status = PositionStatus::ClaimAttested;
        position.updated_at_height = self.height;
        let record = attestation.public_record();
        self.pq_claimant_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.counters.pq_claimant_attestations = self.pq_claimant_attestations.len() as u64;
        self.public_records.push(json!({
            "event": "pq_claimant_attestation_recorded",
            "record": record,
        }));
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn issue_settlement_rebate(
        &mut self,
        rebate: SettlementRebate,
    ) -> PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<Value> {
        require_non_empty("rebate_id", &rebate.rebate_id)?;
        require_bps(rebate.rebate_bps, MAX_BPS, "settlement rebate")?;
        if !self.positions.contains_key(&rebate.position_id) {
            return Err("tokenized htlc market rebate position not found".to_string());
        }
        if !self.solver_quotes.contains_key(&rebate.quote_id) {
            return Err("tokenized htlc market rebate quote not found".to_string());
        }
        if self.settlement_rebates.contains_key(&rebate.rebate_id) {
            return Err("tokenized htlc market rebate already exists".to_string());
        }
        let record = rebate.public_record();
        self.settlement_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.counters.settlement_rebates = self.settlement_rebates.len() as u64;
        self.public_records.push(json!({
            "event": "low_fee_settlement_rebate_issued",
            "record": record,
        }));
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        Ok(record)
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let lane_id = "lane-monero-l2-confidential-htlc-devnet-001".to_string();
    let position_id = "htlc-position-xmr-to-private-dusd-devnet-001".to_string();
    let quote_id = "solver-quote-htlc-devnet-alpha-001".to_string();

    let _ = state.register_swap_lane(CrossChainSwapLane {
        lane_id: lane_id.clone(),
        kind: SwapLaneKind::MoneroToL2,
        status: LaneStatus::Open,
        source_network: DEVNET_MONERO_NETWORK.to_string(),
        target_network: DEVNET_L2_NETWORK.to_string(),
        source_asset_id: "xmr-main-commitment-devnet".to_string(),
        target_asset_id: "private-dusd-devnet".to_string(),
        allowed_solver_set_root: demo_root("allowed-solvers-monero-l2", 1),
        finality_policy_root: demo_root("ten-block-monero-finality-policy", 1),
        max_lane_fee_bps: 18,
        low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        opened_at_height: state.height,
    });
    let _ = state.commit_position(HtlcPosition {
        position_id: position_id.clone(),
        lane_id: lane_id.clone(),
        kind: HtlcPositionKind::AtomicSwap,
        status: PositionStatus::Tokenized,
        maker_commitment: demo_commitment("maker-stealth-output", 1),
        claimant_commitment: demo_commitment("claimant-pq-account", 1),
        source_asset_id: "xmr-main-commitment-devnet".to_string(),
        target_asset_id: "private-dusd-devnet".to_string(),
        amount_commitment: demo_commitment("sealed-amount-12-xmr", 1),
        hashlock_root: demo_root("sha256-preimage-bridged-to-shake-root", 1),
        timelock_height: state.height + 72,
        refund_height: state.height + 96,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        claim_token_id: "claim-token-htlc-devnet-alpha-001".to_string(),
        created_at_height: state.height,
        updated_at_height: state.height,
    });
    let _ = state.post_solver_quote(SolverQuote {
        quote_id: quote_id.clone(),
        position_id: position_id.clone(),
        lane_id: lane_id.clone(),
        solver_commitment: demo_commitment("solver-alpha", 1),
        status: QuoteStatus::Posted,
        fill_asset_id: "private-dusd-devnet".to_string(),
        sealed_price_root: demo_root("sealed-solver-price", 1),
        solver_fee_bps: 9,
        bond_commitment: demo_commitment("solver-bond", 1),
        pq_quote_signature_root: demo_root("pq-solver-quote-signature", 1),
        posted_at_height: state.height,
        expires_at_height: state.height + DEFAULT_QUOTE_TTL_BLOCKS,
    });
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.record_pq_claimant_attestation(PqClaimantAttestation {
        attestation_id: "pq-claimant-attestation-htlc-devnet-alpha-001".to_string(),
        position_id: "htlc-position-xmr-to-private-dusd-devnet-001".to_string(),
        claim_token_id: "claim-token-htlc-devnet-alpha-001".to_string(),
        kind: AttestationKind::ClaimantPreimagePossession,
        claimant_commitment: demo_commitment("claimant-pq-account", 1),
        attested_preimage_root: demo_root("attested-preimage-redacted", 1),
        pq_signature_root: demo_root("claimant-pq-signature", 1),
        verifier_committee_root: demo_root("pq-claim-verifier-committee", 1),
        accepted_at_height: state.height,
        expires_at_height: state.height + DEFAULT_ATTESTATION_TTL_BLOCKS,
    });
    let _ = state.issue_settlement_rebate(SettlementRebate {
        rebate_id: "low-fee-rebate-htlc-devnet-alpha-001".to_string(),
        position_id: "htlc-position-xmr-to-private-dusd-devnet-001".to_string(),
        quote_id: "solver-quote-htlc-devnet-alpha-001".to_string(),
        beneficiary_commitment: demo_commitment("claimant-pq-account", 1),
        rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
        rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        rebate_commitment: demo_commitment("rebate-amount", 1),
        settlement_batch_root: demo_root("settlement-batch", 1),
        issued_at_height: state.height,
    });
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

pub fn derived_id(label: &str, record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-DERIVED-ID",
        &json!({
            "label": label,
            "record": record,
        }),
    )
}

pub fn expiry_bucket_id(height: u64, width: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-EXPIRY-BUCKET-ID",
        &json!({
            "start_height": bucket_start(height, width),
            "width": width,
        }),
    )
}

pub fn bucket_start(height: u64, width: u64) -> u64 {
    let safe_width = width.max(1);
    height - (height % safe_width)
}

pub fn demo_root(label: &str, index: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-DEMO-ROOT",
        &json!({
            "label": label,
            "index": index,
        }),
    )
}

pub fn demo_commitment(label: &str, index: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-HTLC-MARKET-DEMO-COMMITMENT",
        &json!({
            "label": label,
            "index": index,
        }),
    )
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("tokenized htlc market {label} is required"));
    }
    Ok(())
}

fn require_bps(
    value: u64,
    max: u64,
    label: &str,
) -> PrivateL2PqConfidentialTokenizedHashTimeLockMarketRuntimeResult<()> {
    if value > max || value > MAX_BPS {
        return Err(format!("tokenized htlc market {label} exceeds fee cap"));
    }
    Ok(())
}
