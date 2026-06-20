use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialThresholdKeyInsuranceMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_THRESHOLD_KEY_INSURANCE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-threshold-key-insurance-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_THRESHOLD_KEY_INSURANCE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-threshold-key-insurance-market-v1";
pub const THRESHOLD_POOL_SCHEME: &str = "pq-confidential-threshold-key-insurance-pool-root-v1";
pub const UNDERWRITER_BOND_SCHEME: &str = "pq-signer-underwriter-bond-and-slashing-root-v1";
pub const PREMIUM_QUOTE_SCHEME: &str = "confidential-threshold-key-premium-quote-root-v1";
pub const KEY_LOSS_CLAIM_SCHEME: &str = "private-wallet-account-session-key-loss-claim-root-v1";
pub const BRIDGE_WATCHER_POLICY_SCHEME: &str = "bridge-watcher-key-compromise-policy-root-v1";
pub const CLAIM_BATCH_SCHEME: &str = "low-fee-threshold-key-claim-batch-settlement-root-v1";
pub const RECOVERY_COVENANT_SCHEME: &str = "contract-key-recovery-covenant-root-v1";
pub const PRIVACY_REDACTION_SCHEME: &str =
    "operator-safe-threshold-key-insurance-redaction-root-v1";
pub const PUBLIC_SUMMARY_SCHEME: &str =
    "operator-safe-threshold-key-insurance-public-summary-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_276_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MAX_PREMIUM_BPS: u64 = 180;
pub const DEFAULT_MIN_RESERVE_RATIO_BPS: u64 = 15_000;
pub const DEFAULT_LOW_FEE_CLAIM_BPS: u64 = 8;
pub const DEFAULT_UNDERWRITER_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_FULL_COMPROMISE_SLASH_BPS: u64 = 10_000;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 4_320;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_POOLS: usize = 262_144;
pub const DEFAULT_MAX_UNDERWRITERS: usize = 1_048_576;
pub const DEFAULT_MAX_QUOTES: usize = 2_097_152;
pub const DEFAULT_MAX_CLAIMS: usize = 2_097_152;
pub const DEFAULT_MAX_BRIDGE_POLICIES: usize = 524_288;
pub const DEFAULT_MAX_BATCHES: usize = 524_288;
pub const DEFAULT_MAX_COVENANTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageKind {
    WalletSpendKey,
    AccountGuardianSet,
    SessionKey,
    ContractAdminKey,
    BridgeWatcherKey,
    ThresholdSignerShard,
}

impl CoverageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSpendKey => "wallet_spend_key",
            Self::AccountGuardianSet => "account_guardian_set",
            Self::SessionKey => "session_key",
            Self::ContractAdminKey => "contract_admin_key",
            Self::BridgeWatcherKey => "bridge_watcher_key",
            Self::ThresholdSignerShard => "threshold_signer_shard",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::BridgeWatcherKey => 1_000,
            Self::ContractAdminKey => 930,
            Self::WalletSpendKey => 880,
            Self::ThresholdSignerShard => 820,
            Self::AccountGuardianSet => 740,
            Self::SessionKey => 560,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Active,
    QuoteOnly,
    ClaimOnly,
    Quarantined,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::QuoteOnly => "quote_only",
            Self::ClaimOnly => "claim_only",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Active | Self::QuoteOnly)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::ClaimOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnderwriterStatus {
    Bonded,
    Assigned,
    Quarantined,
    Slashed,
    Exited,
}

impl UnderwriterStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bonded => "bonded",
            Self::Assigned => "assigned",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Exited => "exited",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Sealed,
    Accepted,
    Bound,
    Expired,
    Cancelled,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Accepted => "accepted",
            Self::Bound => "bound",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    EvidenceLocked,
    Approved,
    Batched,
    Settled,
    Rejected,
    Quarantined,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::EvidenceLocked => "evidence_locked",
            Self::Approved => "approved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompromiseSignal {
    KeyLoss,
    ViewKeyDisclosure,
    WatcherShardCompromise,
    ThresholdSignerEquivocation,
    RecoveryCovenantTriggered,
    PrivacyLeak,
}

impl CompromiseSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyLoss => "key_loss",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::WatcherShardCompromise => "watcher_shard_compromise",
            Self::ThresholdSignerEquivocation => "threshold_signer_equivocation",
            Self::RecoveryCovenantTriggered => "recovery_covenant_triggered",
            Self::PrivacyLeak => "privacy_leak",
        }
    }

    pub fn slash_bps(self) -> u64 {
        match self {
            Self::PrivacyLeak | Self::ThresholdSignerEquivocation => {
                DEFAULT_FULL_COMPROMISE_SLASH_BPS
            }
            Self::WatcherShardCompromise => 7_500,
            Self::ViewKeyDisclosure => 5_000,
            Self::RecoveryCovenantTriggered => 2_000,
            Self::KeyLoss => DEFAULT_UNDERWRITER_SLASH_BPS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub activation_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_premium_bps: u64,
    pub min_reserve_ratio_bps: u64,
    pub low_fee_claim_bps: u64,
    pub underwriter_slash_bps: u64,
    pub full_compromise_slash_bps: u64,
    pub quarantine_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub max_pools: usize,
    pub max_underwriters: usize,
    pub max_quotes: usize,
    pub max_claims: usize,
    pub max_bridge_policies: usize,
    pub max_batches: usize,
    pub max_covenants: usize,
    pub allowed_coverage: BTreeSet<CoverageKind>,
    pub require_confidential_quotes: bool,
    pub require_operator_safe_summaries: bool,
    pub allow_low_fee_batch_settlement: bool,
    pub quantum_resistance_first: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            activation_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_premium_bps: DEFAULT_MAX_PREMIUM_BPS,
            min_reserve_ratio_bps: DEFAULT_MIN_RESERVE_RATIO_BPS,
            low_fee_claim_bps: DEFAULT_LOW_FEE_CLAIM_BPS,
            underwriter_slash_bps: DEFAULT_UNDERWRITER_SLASH_BPS,
            full_compromise_slash_bps: DEFAULT_FULL_COMPROMISE_SLASH_BPS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            max_pools: DEFAULT_MAX_POOLS,
            max_underwriters: DEFAULT_MAX_UNDERWRITERS,
            max_quotes: DEFAULT_MAX_QUOTES,
            max_claims: DEFAULT_MAX_CLAIMS,
            max_bridge_policies: DEFAULT_MAX_BRIDGE_POLICIES,
            max_batches: DEFAULT_MAX_BATCHES,
            max_covenants: DEFAULT_MAX_COVENANTS,
            allowed_coverage: BTreeSet::from([
                CoverageKind::WalletSpendKey,
                CoverageKind::AccountGuardianSet,
                CoverageKind::SessionKey,
                CoverageKind::ContractAdminKey,
                CoverageKind::BridgeWatcherKey,
                CoverageKind::ThresholdSignerShard,
            ]),
            require_confidential_quotes: true,
            require_operator_safe_summaries: true,
            allow_low_fee_batch_settlement: true,
            quantum_resistance_first: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "activation_height": self.activation_height,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_premium_bps": self.max_premium_bps,
            "min_reserve_ratio_bps": self.min_reserve_ratio_bps,
            "low_fee_claim_bps": self.low_fee_claim_bps,
            "quarantine_blocks": self.quarantine_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "allowed_coverage": self.allowed_coverage.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "operator_safe": self.require_operator_safe_summaries,
            "quantum_resistance_first": self.quantum_resistance_first,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub underwriters: u64,
    pub premium_quotes: u64,
    pub key_loss_claims: u64,
    pub bridge_policies: u64,
    pub claim_batches: u64,
    pub recovery_covenants: u64,
    pub quarantines: u64,
    pub slashes: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pools": self.pools,
            "underwriters": self.underwriters,
            "premium_quotes": self.premium_quotes,
            "key_loss_claims": self.key_loss_claims,
            "bridge_policies": self.bridge_policies,
            "claim_batches": self.claim_batches,
            "recovery_covenants": self.recovery_covenants,
            "quarantines": self.quarantines,
            "slashes": self.slashes,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub pools_root: String,
    pub underwriter_bonds_root: String,
    pub premium_quotes_root: String,
    pub key_loss_claims_root: String,
    pub bridge_policies_root: String,
    pub claim_batches_root: String,
    pub recovery_covenants_root: String,
    pub privacy_redaction_root: String,
    pub public_summaries_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            pools_root: merkle_root(THRESHOLD_POOL_SCHEME, &[]),
            underwriter_bonds_root: merkle_root(UNDERWRITER_BOND_SCHEME, &[]),
            premium_quotes_root: merkle_root(PREMIUM_QUOTE_SCHEME, &[]),
            key_loss_claims_root: merkle_root(KEY_LOSS_CLAIM_SCHEME, &[]),
            bridge_policies_root: merkle_root(BRIDGE_WATCHER_POLICY_SCHEME, &[]),
            claim_batches_root: merkle_root(CLAIM_BATCH_SCHEME, &[]),
            recovery_covenants_root: merkle_root(RECOVERY_COVENANT_SCHEME, &[]),
            privacy_redaction_root: merkle_root(PRIVACY_REDACTION_SCHEME, &[]),
            public_summaries_root: merkle_root(PUBLIC_SUMMARY_SCHEME, &[]),
            state_root: domain_hash(PROTOCOL_VERSION, &[HashPart::Str("empty")], 32),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pools_root": self.pools_root,
            "underwriter_bonds_root": self.underwriter_bonds_root,
            "premium_quotes_root": self.premium_quotes_root,
            "key_loss_claims_root": self.key_loss_claims_root,
            "bridge_policies_root": self.bridge_policies_root,
            "claim_batches_root": self.claim_batches_root,
            "recovery_covenants_root": self.recovery_covenants_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "public_summaries_root": self.public_summaries_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PoolRequest {
    pub pool_id: String,
    pub coverage_kind: CoverageKind,
    pub reserve_commitment: String,
    pub threshold: u16,
    pub signer_set_size: u16,
    pub reserve_ratio_bps: u64,
    pub premium_floor_bps: u64,
    pub max_claim_micronero: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThresholdKeyInsurancePool {
    pub pool_id: String,
    pub coverage_kind: CoverageKind,
    pub status: PoolStatus,
    pub reserve_commitment: String,
    pub threshold: u16,
    pub signer_set_size: u16,
    pub reserve_ratio_bps: u64,
    pub premium_floor_bps: u64,
    pub max_claim_micronero: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
}

impl ThresholdKeyInsurancePool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "coverage_kind": self.coverage_kind.as_str(),
            "status": self.status.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "threshold": self.threshold,
            "signer_set_size": self.signer_set_size,
            "reserve_ratio_bps": self.reserve_ratio_bps,
            "premium_floor_bps": self.premium_floor_bps,
            "max_claim_micronero": self.max_claim_micronero,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnderwriterBondRequest {
    pub underwriter_id: String,
    pub pool_id: String,
    pub pq_signer_commitment: String,
    pub bond_commitment: String,
    pub security_bits: u16,
    pub stake_micronero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignerUnderwriterBond {
    pub underwriter_id: String,
    pub pool_id: String,
    pub pq_signer_commitment: String,
    pub bond_commitment: String,
    pub security_bits: u16,
    pub stake_micronero: u64,
    pub status: UnderwriterStatus,
    pub quarantine_until_height: Option<u64>,
    pub slash_bps: u64,
}

impl PqSignerUnderwriterBond {
    pub fn public_record(&self) -> Value {
        json!({
            "underwriter_id": self.underwriter_id,
            "pool_id": self.pool_id,
            "pq_signer_commitment": self.pq_signer_commitment,
            "bond_commitment": self.bond_commitment,
            "security_bits": self.security_bits,
            "stake_micronero": self.stake_micronero,
            "status": self.status.as_str(),
            "quarantine_until_height": self.quarantine_until_height,
            "slash_bps": self.slash_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PremiumQuoteRequest {
    pub quote_id: String,
    pub pool_id: String,
    pub owner_nullifier: String,
    pub coverage_commitment: String,
    pub encrypted_quote_blob: String,
    pub requested_limit_micronero: u64,
    pub max_premium_bps: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialPremiumQuote {
    pub quote_id: String,
    pub pool_id: String,
    pub owner_nullifier: String,
    pub coverage_commitment: String,
    pub encrypted_quote_blob: String,
    pub requested_limit_micronero: u64,
    pub premium_bps_commitment: String,
    pub status: QuoteStatus,
    pub expires_height: u64,
}

impl ConfidentialPremiumQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "owner_nullifier": self.owner_nullifier,
            "coverage_commitment": self.coverage_commitment,
            "encrypted_quote_blob": self.encrypted_quote_blob,
            "requested_limit_micronero": self.requested_limit_micronero,
            "premium_bps_commitment": self.premium_bps_commitment,
            "status": self.status.as_str(),
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyLossClaimRequest {
    pub claim_id: String,
    pub pool_id: String,
    pub quote_id: String,
    pub claimant_nullifier: String,
    pub loss_signal: CompromiseSignal,
    pub evidence_commitment: String,
    pub recovery_address_commitment: String,
    pub claim_amount_micronero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyLossClaim {
    pub claim_id: String,
    pub pool_id: String,
    pub quote_id: String,
    pub claimant_nullifier: String,
    pub loss_signal: CompromiseSignal,
    pub evidence_commitment: String,
    pub recovery_address_commitment: String,
    pub claim_amount_micronero: u64,
    pub status: ClaimStatus,
    pub submitted_height: u64,
}

impl KeyLossClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "pool_id": self.pool_id,
            "quote_id": self.quote_id,
            "claimant_nullifier": self.claimant_nullifier,
            "loss_signal": self.loss_signal.as_str(),
            "evidence_commitment": self.evidence_commitment,
            "recovery_address_commitment": self.recovery_address_commitment,
            "claim_amount_micronero": self.claim_amount_micronero,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeWatcherPolicyRecord {
    pub policy_id: String,
    pub pool_id: String,
    pub watcher_set_commitment: String,
    pub compromise_signal_root: String,
    pub emergency_rotation_covenant: String,
    pub max_bridge_exposure_micronero: u64,
    pub quarantine_required: bool,
}

impl BridgeWatcherPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "pool_id": self.pool_id,
            "watcher_set_commitment": self.watcher_set_commitment,
            "compromise_signal_root": self.compromise_signal_root,
            "emergency_rotation_covenant": self.emergency_rotation_covenant,
            "max_bridge_exposure_micronero": self.max_bridge_exposure_micronero,
            "quarantine_required": self.quarantine_required,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimBatchSettlementRecord {
    pub batch_id: String,
    pub claim_ids: Vec<String>,
    pub settlement_commitment: String,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub settled_height: u64,
}

impl ClaimBatchSettlementRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "claim_ids": self.claim_ids,
            "settlement_commitment": self.settlement_commitment,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryCovenantRecord {
    pub covenant_id: String,
    pub contract_id: String,
    pub pool_id: String,
    pub covenant_commitment: String,
    pub recovery_threshold: u16,
    pub timelock_blocks: u64,
    pub active: bool,
}

impl RecoveryCovenantRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "covenant_id": self.covenant_id,
            "contract_id": self.contract_id,
            "pool_id": self.pool_id,
            "covenant_commitment": self.covenant_commitment,
            "recovery_threshold": self.recovery_threshold,
            "timelock_blocks": self.timelock_blocks,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub pools: BTreeMap<String, ThresholdKeyInsurancePool>,
    pub underwriter_bonds: BTreeMap<String, PqSignerUnderwriterBond>,
    pub premium_quotes: BTreeMap<String, ConfidentialPremiumQuote>,
    pub key_loss_claims: BTreeMap<String, KeyLossClaim>,
    pub bridge_policies: BTreeMap<String, BridgeWatcherPolicyRecord>,
    pub claim_batches: BTreeMap<String, ClaimBatchSettlementRecord>,
    pub recovery_covenants: BTreeMap<String, RecoveryCovenantRecord>,
    pub quarantined_underwriters: BTreeSet<String>,
    pub redaction_commitments: BTreeMap<String, String>,
    pub public_summaries: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            pools: BTreeMap::new(),
            underwriter_bonds: BTreeMap::new(),
            premium_quotes: BTreeMap::new(),
            key_loss_claims: BTreeMap::new(),
            bridge_policies: BTreeMap::new(),
            claim_batches: BTreeMap::new(),
            recovery_covenants: BTreeMap::new(),
            quarantined_underwriters: BTreeSet::new(),
            redaction_commitments: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state
            .open_pool(PoolRequest {
                pool_id: "pool-devnet-wallet-session-001".to_string(),
                coverage_kind: CoverageKind::WalletSpendKey,
                reserve_commitment: commitment("reserve", "wallet-session", 88_000_000_000),
                threshold: 5,
                signer_set_size: 9,
                reserve_ratio_bps: 18_500,
                premium_floor_bps: 38,
                max_claim_micronero: 25_000_000_000,
                privacy_set_size: 262_144,
            })
            .expect("devnet pool");
        state
            .open_pool(PoolRequest {
                pool_id: "pool-devnet-bridge-watcher-001".to_string(),
                coverage_kind: CoverageKind::BridgeWatcherKey,
                reserve_commitment: commitment("reserve", "bridge-watcher", 210_000_000_000),
                threshold: 7,
                signer_set_size: 11,
                reserve_ratio_bps: 22_000,
                premium_floor_bps: 66,
                max_claim_micronero: 95_000_000_000,
                privacy_set_size: 1_048_576,
            })
            .expect("devnet bridge pool");
        state
            .bond_underwriter(UnderwriterBondRequest {
                underwriter_id: "uw-devnet-ml-dsa-001".to_string(),
                pool_id: "pool-devnet-wallet-session-001".to_string(),
                pq_signer_commitment: commitment("pq-signer", "uw-001", 1),
                bond_commitment: commitment("bond", "uw-001", 12_500_000_000),
                security_bits: 256,
                stake_micronero: 12_500_000_000,
            })
            .expect("devnet underwriter");
        state
            .bond_underwriter(UnderwriterBondRequest {
                underwriter_id: "uw-devnet-slh-dsa-bridge-001".to_string(),
                pool_id: "pool-devnet-bridge-watcher-001".to_string(),
                pq_signer_commitment: commitment("pq-signer", "bridge-uw-001", 2),
                bond_commitment: commitment("bond", "bridge-uw-001", 44_000_000_000),
                security_bits: 256,
                stake_micronero: 44_000_000_000,
            })
            .expect("devnet bridge underwriter");
        state
            .quote_premium(PremiumQuoteRequest {
                quote_id: "quote-devnet-session-loss-001".to_string(),
                pool_id: "pool-devnet-wallet-session-001".to_string(),
                owner_nullifier: commitment("owner-nullifier", "alice", 1),
                coverage_commitment: commitment("coverage", "alice-session", 25_000_000_000),
                encrypted_quote_blob: commitment("ml-kem-quote", "alice-session", 38),
                requested_limit_micronero: 12_000_000_000,
                max_premium_bps: 52,
                ttl_blocks: 36,
            })
            .expect("devnet quote");
        state
            .submit_key_loss_claim(KeyLossClaimRequest {
                claim_id: "claim-devnet-session-loss-001".to_string(),
                pool_id: "pool-devnet-wallet-session-001".to_string(),
                quote_id: "quote-devnet-session-loss-001".to_string(),
                claimant_nullifier: commitment("claimant-nullifier", "alice", 1),
                loss_signal: CompromiseSignal::KeyLoss,
                evidence_commitment: commitment("evidence", "alice-lost-session-key", 1),
                recovery_address_commitment: commitment("recovery-address", "alice", 1),
                claim_amount_micronero: 7_500_000_000,
            })
            .expect("devnet claim");
        state
            .add_bridge_policy(BridgeWatcherPolicyRecord {
                policy_id: "bridge-policy-devnet-001".to_string(),
                pool_id: "pool-devnet-bridge-watcher-001".to_string(),
                watcher_set_commitment: commitment("watcher-set", "monero-bridge-a", 11),
                compromise_signal_root: commitment("compromise-signals", "monero-bridge-a", 6),
                emergency_rotation_covenant: commitment("rotation-covenant", "monero-bridge-a", 2),
                max_bridge_exposure_micronero: 95_000_000_000,
                quarantine_required: true,
            })
            .expect("devnet bridge policy");
        state
            .add_recovery_covenant(RecoveryCovenantRecord {
                covenant_id: "covenant-devnet-contract-admin-001".to_string(),
                contract_id: "confidential-vault-router-devnet".to_string(),
                pool_id: "pool-devnet-wallet-session-001".to_string(),
                covenant_commitment: commitment("contract-covenant", "vault-router", 1),
                recovery_threshold: 4,
                timelock_blocks: 48,
                active: true,
            })
            .expect("devnet covenant");
        state
            .settle_claim_batch(
                "batch-devnet-low-fee-001",
                vec!["claim-devnet-session-loss-001".to_string()],
                commitment("settlement", "batch-devnet-low-fee-001", 1),
            )
            .expect("devnet batch");
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn open_pool(&mut self, request: PoolRequest) -> Result<()> {
        if self.pools.len() >= self.config.max_pools {
            return Err("pool capacity exceeded".to_string());
        }
        if self.pools.contains_key(&request.pool_id) {
            return Err("pool already exists".to_string());
        }
        if !self
            .config
            .allowed_coverage
            .contains(&request.coverage_kind)
        {
            return Err("coverage kind disabled".to_string());
        }
        if request.reserve_ratio_bps < self.config.min_reserve_ratio_bps {
            return Err("reserve ratio below configured minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        if request.threshold == 0 || request.threshold > request.signer_set_size {
            return Err("invalid threshold signer geometry".to_string());
        }
        let record = ThresholdKeyInsurancePool {
            pool_id: request.pool_id.clone(),
            coverage_kind: request.coverage_kind,
            status: PoolStatus::Active,
            reserve_commitment: request.reserve_commitment,
            threshold: request.threshold,
            signer_set_size: request.signer_set_size,
            reserve_ratio_bps: request.reserve_ratio_bps,
            premium_floor_bps: request.premium_floor_bps,
            max_claim_micronero: request.max_claim_micronero,
            privacy_set_size: request.privacy_set_size,
            opened_height: self.height,
        };
        self.public_summaries
            .insert(record.pool_id.clone(), record.public_record());
        self.pools.insert(record.pool_id.clone(), record);
        self.counters.pools += 1;
        self.counters.public_records += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn bond_underwriter(&mut self, request: UnderwriterBondRequest) -> Result<()> {
        if self.underwriter_bonds.len() >= self.config.max_underwriters {
            return Err("underwriter capacity exceeded".to_string());
        }
        if self.underwriter_bonds.contains_key(&request.underwriter_id) {
            return Err("underwriter already bonded".to_string());
        }
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "unknown pool".to_string())?;
        if !pool.status.accepts_quotes() {
            return Err("pool does not accept underwriter assignment".to_string());
        }
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("post-quantum security bits below minimum".to_string());
        }
        let record = PqSignerUnderwriterBond {
            underwriter_id: request.underwriter_id.clone(),
            pool_id: request.pool_id,
            pq_signer_commitment: request.pq_signer_commitment,
            bond_commitment: request.bond_commitment,
            security_bits: request.security_bits,
            stake_micronero: request.stake_micronero,
            status: UnderwriterStatus::Bonded,
            quarantine_until_height: None,
            slash_bps: 0,
        };
        self.public_summaries
            .insert(record.underwriter_id.clone(), record.public_record());
        self.underwriter_bonds
            .insert(record.underwriter_id.clone(), record);
        self.counters.underwriters += 1;
        self.counters.public_records += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn quote_premium(&mut self, request: PremiumQuoteRequest) -> Result<()> {
        if self.premium_quotes.len() >= self.config.max_quotes {
            return Err("premium quote capacity exceeded".to_string());
        }
        if self.premium_quotes.contains_key(&request.quote_id) {
            return Err("premium quote already exists".to_string());
        }
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "unknown pool".to_string())?;
        if !pool.status.accepts_quotes() {
            return Err("pool does not accept premium quotes".to_string());
        }
        if request.max_premium_bps > self.config.max_premium_bps {
            return Err("premium exceeds market cap".to_string());
        }
        if request.requested_limit_micronero > pool.max_claim_micronero {
            return Err("requested limit exceeds pool cap".to_string());
        }
        let premium_bps_commitment = domain_hash(
            "threshold-key-insurance-premium-bps",
            &[
                HashPart::Str(&request.quote_id),
                HashPart::Str(&request.pool_id),
                HashPart::U64(request.max_premium_bps),
            ],
            32,
        );
        let record = ConfidentialPremiumQuote {
            quote_id: request.quote_id.clone(),
            pool_id: request.pool_id,
            owner_nullifier: request.owner_nullifier,
            coverage_commitment: request.coverage_commitment,
            encrypted_quote_blob: request.encrypted_quote_blob,
            requested_limit_micronero: request.requested_limit_micronero,
            premium_bps_commitment,
            status: QuoteStatus::Sealed,
            expires_height: self.height + request.ttl_blocks.min(self.config.quote_ttl_blocks),
        };
        self.redaction_commitments.insert(
            record.quote_id.clone(),
            domain_hash(
                "threshold-key-insurance-quote-redaction",
                &[HashPart::Json(&record.public_record())],
                32,
            ),
        );
        self.public_summaries
            .insert(record.quote_id.clone(), redact_quote(&record));
        self.premium_quotes.insert(record.quote_id.clone(), record);
        self.counters.premium_quotes += 1;
        self.counters.public_records += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_key_loss_claim(&mut self, request: KeyLossClaimRequest) -> Result<()> {
        if self.key_loss_claims.len() >= self.config.max_claims {
            return Err("claim capacity exceeded".to_string());
        }
        if self.key_loss_claims.contains_key(&request.claim_id) {
            return Err("claim already exists".to_string());
        }
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "unknown pool".to_string())?;
        if !pool.status.accepts_claims() {
            return Err("pool does not accept claims".to_string());
        }
        if !self.premium_quotes.contains_key(&request.quote_id) {
            return Err("unknown premium quote".to_string());
        }
        if request.claim_amount_micronero > pool.max_claim_micronero {
            return Err("claim exceeds pool cap".to_string());
        }
        let record = KeyLossClaim {
            claim_id: request.claim_id.clone(),
            pool_id: request.pool_id,
            quote_id: request.quote_id,
            claimant_nullifier: request.claimant_nullifier,
            loss_signal: request.loss_signal,
            evidence_commitment: request.evidence_commitment,
            recovery_address_commitment: request.recovery_address_commitment,
            claim_amount_micronero: request.claim_amount_micronero,
            status: ClaimStatus::Submitted,
            submitted_height: self.height,
        };
        self.redaction_commitments.insert(
            record.claim_id.clone(),
            domain_hash(
                "threshold-key-insurance-claim-redaction",
                &[HashPart::Json(&record.public_record())],
                32,
            ),
        );
        self.public_summaries
            .insert(record.claim_id.clone(), redact_claim(&record));
        self.key_loss_claims.insert(record.claim_id.clone(), record);
        self.counters.key_loss_claims += 1;
        self.counters.public_records += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_bridge_policy(&mut self, record: BridgeWatcherPolicyRecord) -> Result<()> {
        if self.bridge_policies.len() >= self.config.max_bridge_policies {
            return Err("bridge policy capacity exceeded".to_string());
        }
        if self.bridge_policies.contains_key(&record.policy_id) {
            return Err("bridge policy already exists".to_string());
        }
        if !self.pools.contains_key(&record.pool_id) {
            return Err("unknown pool".to_string());
        }
        self.public_summaries
            .insert(record.policy_id.clone(), record.public_record());
        self.bridge_policies
            .insert(record.policy_id.clone(), record);
        self.counters.bridge_policies += 1;
        self.counters.public_records += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_recovery_covenant(&mut self, record: RecoveryCovenantRecord) -> Result<()> {
        if self.recovery_covenants.len() >= self.config.max_covenants {
            return Err("recovery covenant capacity exceeded".to_string());
        }
        if self.recovery_covenants.contains_key(&record.covenant_id) {
            return Err("recovery covenant already exists".to_string());
        }
        if !self.pools.contains_key(&record.pool_id) {
            return Err("unknown pool".to_string());
        }
        self.public_summaries
            .insert(record.covenant_id.clone(), record.public_record());
        self.recovery_covenants
            .insert(record.covenant_id.clone(), record);
        self.counters.recovery_covenants += 1;
        self.counters.public_records += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_claim_batch(
        &mut self,
        batch_id: &str,
        claim_ids: Vec<String>,
        settlement_commitment: String,
    ) -> Result<()> {
        if self.claim_batches.len() >= self.config.max_batches {
            return Err("claim batch capacity exceeded".to_string());
        }
        if self.claim_batches.contains_key(batch_id) {
            return Err("claim batch already exists".to_string());
        }
        if claim_ids.is_empty() {
            return Err("claim batch is empty".to_string());
        }
        for claim_id in &claim_ids {
            let claim = self
                .key_loss_claims
                .get_mut(claim_id)
                .ok_or_else(|| format!("unknown claim: {claim_id}"))?;
            claim.status = ClaimStatus::Batched;
        }
        let record = ClaimBatchSettlementRecord {
            batch_id: batch_id.to_string(),
            claim_ids,
            settlement_commitment,
            fee_bps: self.config.low_fee_claim_bps,
            privacy_set_size: self.config.batch_privacy_set_size,
            settled_height: self.height + self.config.settlement_finality_blocks,
        };
        self.public_summaries
            .insert(record.batch_id.clone(), record.public_record());
        self.claim_batches.insert(record.batch_id.clone(), record);
        self.counters.claim_batches += 1;
        self.counters.public_records += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_underwriter(
        &mut self,
        underwriter_id: &str,
        signal: CompromiseSignal,
    ) -> Result<()> {
        let underwriter = self
            .underwriter_bonds
            .get_mut(underwriter_id)
            .ok_or_else(|| "unknown underwriter".to_string())?;
        underwriter.status = UnderwriterStatus::Quarantined;
        underwriter.quarantine_until_height = Some(self.height + self.config.quarantine_blocks);
        underwriter.slash_bps = signal.slash_bps();
        self.quarantined_underwriters
            .insert(underwriter_id.to_string());
        self.counters.quarantines += 1;
        if signal.slash_bps() > 0 {
            self.counters.slashes += 1;
        }
        self.public_summaries
            .insert(underwriter_id.to_string(), underwriter.public_record());
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        let pool_leaves = self
            .pools
            .values()
            .map(ThresholdKeyInsurancePool::public_record)
            .collect::<Vec<_>>();
        let underwriter_leaves = self
            .underwriter_bonds
            .values()
            .map(PqSignerUnderwriterBond::public_record)
            .collect::<Vec<_>>();
        let quote_leaves = self
            .premium_quotes
            .values()
            .map(ConfidentialPremiumQuote::public_record)
            .collect::<Vec<_>>();
        let claim_leaves = self
            .key_loss_claims
            .values()
            .map(KeyLossClaim::public_record)
            .collect::<Vec<_>>();
        let policy_leaves = self
            .bridge_policies
            .values()
            .map(BridgeWatcherPolicyRecord::public_record)
            .collect::<Vec<_>>();
        let batch_leaves = self
            .claim_batches
            .values()
            .map(ClaimBatchSettlementRecord::public_record)
            .collect::<Vec<_>>();
        let covenant_leaves = self
            .recovery_covenants
            .values()
            .map(RecoveryCovenantRecord::public_record)
            .collect::<Vec<_>>();
        let redaction_leaves = self
            .redaction_commitments
            .iter()
            .map(|(id, commitment)| json!({"id": id, "commitment": commitment}))
            .collect::<Vec<_>>();
        let public_leaves = self.public_summaries.values().cloned().collect::<Vec<_>>();

        self.roots.pools_root = merkle_root(THRESHOLD_POOL_SCHEME, &pool_leaves);
        self.roots.underwriter_bonds_root =
            merkle_root(UNDERWRITER_BOND_SCHEME, &underwriter_leaves);
        self.roots.premium_quotes_root = merkle_root(PREMIUM_QUOTE_SCHEME, &quote_leaves);
        self.roots.key_loss_claims_root = merkle_root(KEY_LOSS_CLAIM_SCHEME, &claim_leaves);
        self.roots.bridge_policies_root = merkle_root(BRIDGE_WATCHER_POLICY_SCHEME, &policy_leaves);
        self.roots.claim_batches_root = merkle_root(CLAIM_BATCH_SCHEME, &batch_leaves);
        self.roots.recovery_covenants_root =
            merkle_root(RECOVERY_COVENANT_SCHEME, &covenant_leaves);
        self.roots.privacy_redaction_root =
            merkle_root(PRIVACY_REDACTION_SCHEME, &redaction_leaves);
        self.roots.public_summaries_root = merkle_root(PUBLIC_SUMMARY_SCHEME, &public_leaves);
        self.roots.state_root = self.state_root();
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            PROTOCOL_VERSION,
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.height),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&self.roots.pools_root),
                HashPart::Str(&self.roots.underwriter_bonds_root),
                HashPart::Str(&self.roots.premium_quotes_root),
                HashPart::Str(&self.roots.key_loss_claims_root),
                HashPart::Str(&self.roots.bridge_policies_root),
                HashPart::Str(&self.roots.claim_batches_root),
                HashPart::Str(&self.roots.recovery_covenants_root),
                HashPart::Str(&self.roots.privacy_redaction_root),
                HashPart::Str(&self.roots.public_summaries_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "operator_safe_summary": {
                "active_pools": self.pools.values().filter(|pool| pool.status == PoolStatus::Active).count(),
                "bonded_underwriters": self.underwriter_bonds.values().filter(|bond| bond.status == UnderwriterStatus::Bonded).count(),
                "sealed_quotes": self.premium_quotes.values().filter(|quote| quote.status == QuoteStatus::Sealed).count(),
                "open_claims": self.key_loss_claims.values().filter(|claim| claim.status != ClaimStatus::Settled && claim.status != ClaimStatus::Rejected).count(),
                "quarantined_underwriters": self.quarantined_underwriters.len(),
                "low_fee_claim_batching": self.config.allow_low_fee_batch_settlement,
                "confidential_quotes": self.config.require_confidential_quotes,
                "quantum_resistance_first": self.config.quantum_resistance_first,
            }
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

fn commitment(domain: &str, label: &str, value: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(label),
            HashPart::U64(value),
            HashPart::Str(PROTOCOL_VERSION),
        ],
        32,
    )
}

fn redact_quote(quote: &ConfidentialPremiumQuote) -> Value {
    json!({
        "kind": "confidential_premium_quote",
        "quote_id": quote.quote_id,
        "pool_id": quote.pool_id,
        "owner_nullifier": quote.owner_nullifier,
        "coverage_commitment": quote.coverage_commitment,
        "requested_limit_micronero": quote.requested_limit_micronero,
        "premium_bps_commitment": quote.premium_bps_commitment,
        "status": quote.status.as_str(),
        "expires_height": quote.expires_height,
        "redacted_fields": ["encrypted_quote_blob"],
    })
}

fn redact_claim(claim: &KeyLossClaim) -> Value {
    json!({
        "kind": "key_loss_claim",
        "claim_id": claim.claim_id,
        "pool_id": claim.pool_id,
        "quote_id": claim.quote_id,
        "claimant_nullifier": claim.claimant_nullifier,
        "loss_signal": claim.loss_signal.as_str(),
        "evidence_commitment": claim.evidence_commitment,
        "recovery_address_commitment": claim.recovery_address_commitment,
        "claim_amount_micronero": claim.claim_amount_micronero,
        "status": claim.status.as_str(),
        "submitted_height": claim.submitted_height,
        "redacted_fields": ["private_wallet_metadata", "account_graph", "session_transcript"],
    })
}
