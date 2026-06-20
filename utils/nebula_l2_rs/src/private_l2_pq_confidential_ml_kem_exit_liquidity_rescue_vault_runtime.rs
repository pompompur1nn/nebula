use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlKemExitLiquidityRescueVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_EXIT_LIQUIDITY_RESCUE_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-kem-exit-liquidity-rescue-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_EXIT_LIQUIDITY_RESCUE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_KEM_RESCUE_SUITE: &str = "ML-KEM-1024-sealed-exit-liquidity-rescue-vault-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-rescue-vault-attestation-v1";
pub const CONFIDENTIAL_VOUCHER_SUITE: &str = "confidential-exit-liquidity-voucher-commitment-v1";
pub const LOW_FEE_BATCH_SETTLEMENT_SUITE: &str = "low-fee-private-exit-rescue-batch-settlement-v1";
pub const NULLIFIER_SUITE: &str = "private-l2-exit-rescue-anti-replay-nullifier-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-exit-liquidity-rescue-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RESCUE_ASSET_ID: &str = "xmr-exit-rescue-liquidity-devnet";
pub const DEVNET_VOUCHER_ASSET_ID: &str = "confidential-exit-rescue-voucher-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 4_982_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_944_000;
pub const DEVNET_EPOCH: u64 = 29_120;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_RESCUE_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_SLOW_EXIT_GRACE_BLOCKS: u64 = 72;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_BATCH_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_RESCUE_FEE_BPS: u64 = 24;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 36;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MIN_LIQUIDITY_BUFFER_BPS: u64 = 10_800;
pub const DEFAULT_PANIC_LIQUIDITY_BUFFER_BPS: u64 = 12_500;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 512;
pub const MAX_BPS: u64 = 10_000;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
    HybridX25519MlKem768,
    HybridX25519MlKem1024,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueLane {
    FailedMoneroExit,
    SlowMoneroExit,
    ContractWithdrawal,
    TokenBridgeExit,
    AmmLiquidityUnwind,
    LendingLiquidationEscape,
    PerpsMarginEscape,
    EmergencyEscapeHatch,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBucket {
    Green,
    Amber,
    Red,
    Critical,
    Quarantined,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Open,
    Rescuing,
    Throttled,
    Paused,
    Draining,
    Retired,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Sealed,
    Attested,
    VoucherIssued,
    Batched,
    Settled,
    Rejected,
    Quarantined,
    Expired,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Confidential,
    Reserved,
    Settling,
    Redeemed,
    Expired,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    MlKemCiphertextBound,
    ExitFailureObserved,
    SlowExitWindowElapsed,
    LiquidityCommitmentOpened,
    NullifierFresh,
    FeeCapObserved,
    PrivacySetObserved,
    ContractStateRootBound,
    MoneroWatcherQuorum,
    SettlementSafe,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    Approve,
    ApproveWithRebate,
    PartialFill,
    RetryLater,
    Reject,
    Quarantine,
    Expire,
}
impl MlKemParameterSet {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml_kem_512",
            Self::MlKem768 => "ml_kem_768",
            Self::MlKem1024 => "ml_kem_1024",
            Self::HybridX25519MlKem768 => "hybrid_x25519_ml_kem_768",
            Self::HybridX25519MlKem1024 => "hybrid_x25519_ml_kem_1024",
        }
    }
    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 | Self::HybridX25519MlKem768 => 192,
            Self::MlKem1024 | Self::HybridX25519MlKem1024 => 256,
        }
    }
}
impl RescueLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailedMoneroExit => "failed_monero_exit",
            Self::SlowMoneroExit => "slow_monero_exit",
            Self::ContractWithdrawal => "contract_withdrawal",
            Self::TokenBridgeExit => "token_bridge_exit",
            Self::AmmLiquidityUnwind => "amm_liquidity_unwind",
            Self::LendingLiquidationEscape => "lending_liquidation_escape",
            Self::PerpsMarginEscape => "perps_margin_escape",
            Self::EmergencyEscapeHatch => "emergency_escape_hatch",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscapeHatch => 10_000,
            Self::FailedMoneroExit => 9_600,
            Self::SlowMoneroExit => 8_900,
            Self::LendingLiquidationEscape => 8_500,
            Self::PerpsMarginEscape => 8_200,
            Self::TokenBridgeExit => 7_700,
            Self::ContractWithdrawal => 7_300,
            Self::AmmLiquidityUnwind => 6_800,
        }
    }
}
impl RiskBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Amber => "amber",
            Self::Red => "red",
            Self::Critical => "critical",
            Self::Quarantined => "quarantined",
        }
    }
    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Green => 8_000,
            Self::Amber => 10_000,
            Self::Red => 12_500,
            Self::Critical => 15_000,
            Self::Quarantined => 50_000,
        }
    }
}
impl VaultStatus {
    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Open | Self::Rescuing | Self::Throttled)
    }
}
impl ClaimStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Attested | Self::VoucherIssued | Self::Batched
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub ml_kem_rescue_suite: String,
    pub pq_attestation_suite: String,
    pub confidential_voucher_suite: String,
    pub low_fee_batch_settlement_suite: String,
    pub nullifier_suite: String,
    pub public_record_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rescue_asset_id: String,
    pub voucher_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub rescue_window_blocks: u64,
    pub slow_exit_grace_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub batch_finality_blocks: u64,
    pub max_rescue_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub min_liquidity_buffer_bps: u64,
    pub panic_liquidity_buffer_bps: u64,
    pub redaction_budget_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            ml_kem_rescue_suite: ML_KEM_RESCUE_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            confidential_voucher_suite: CONFIDENTIAL_VOUCHER_SUITE.to_string(),
            low_fee_batch_settlement_suite: LOW_FEE_BATCH_SETTLEMENT_SUITE.to_string(),
            nullifier_suite: NULLIFIER_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rescue_asset_id: DEVNET_RESCUE_ASSET_ID.to_string(),
            voucher_asset_id: DEVNET_VOUCHER_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            rescue_window_blocks: DEFAULT_RESCUE_WINDOW_BLOCKS,
            slow_exit_grace_blocks: DEFAULT_SLOW_EXIT_GRACE_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            batch_finality_blocks: DEFAULT_BATCH_FINALITY_BLOCKS,
            max_rescue_fee_bps: DEFAULT_MAX_RESCUE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            min_liquidity_buffer_bps: DEFAULT_MIN_LIQUIDITY_BUFFER_BPS,
            panic_liquidity_buffer_bps: DEFAULT_PANIC_LIQUIDITY_BUFFER_BPS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub sealed_claims: u64,
    pub attestations: u64,
    pub vouchers: u64,
    pub settlements: u64,
    pub batches: u64,
    pub rejected_claims: u64,
    pub quarantined_claims: u64,
    pub replay_attempts: u64,
    pub fee_rebates: u64,
    pub redaction_budget_spent: u64,
    pub total_rescue_liquidity_micro_units: u64,
    pub total_reserved_micro_units: u64,
    pub total_settled_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub sealed_claim_root: String,
    pub pq_attestation_root: String,
    pub voucher_root: String,
    pub settlement_root: String,
    pub batch_root: String,
    pub nullifier_root: String,
    pub risk_bucket_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RescueVault {
    pub vault_id: String,
    pub operator_commitment: String,
    pub reserve_commitment: String,
    pub status: VaultStatus,
    pub risk_bucket: RiskBucket,
    pub liquidity_micro_units: u64,
    pub reserved_micro_units: u64,
    pub settled_micro_units: u64,
    pub max_claim_micro_units: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_l2_height: u64,
    pub updated_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RescueVaultInput {
    pub vault_id: String,
    pub operator_commitment: String,
    pub reserve_commitment: String,
    pub liquidity_micro_units: u64,
    pub max_claim_micro_units: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub risk_bucket: RiskBucket,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedRescueClaim {
    pub claim_id: String,
    pub vault_id: String,
    pub exit_commitment: String,
    pub sealed_claim_commitment: String,
    pub claimant_view_tag_commitment: String,
    pub rescue_amount_commitment: String,
    pub requested_micro_units: u64,
    pub lane: RescueLane,
    pub risk_bucket: RiskBucket,
    pub ml_kem_parameter_set: MlKemParameterSet,
    pub ml_kem_ciphertext_root: String,
    pub encapsulation_attestation_root: String,
    pub nullifier: String,
    pub monero_height_hint: u64,
    pub l2_height_hint: u64,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub status: ClaimStatus,
    pub submitted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedRescueClaimInput {
    pub claim_id: String,
    pub vault_id: String,
    pub exit_commitment: String,
    pub sealed_claim_commitment: String,
    pub claimant_view_tag_commitment: String,
    pub rescue_amount_commitment: String,
    pub requested_micro_units: u64,
    pub lane: RescueLane,
    pub risk_bucket: RiskBucket,
    pub ml_kem_parameter_set: MlKemParameterSet,
    pub ml_kem_ciphertext_root: String,
    pub encapsulation_attestation_root: String,
    pub nullifier: String,
    pub monero_height_hint: u64,
    pub l2_height_hint: u64,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqEncapsulationAttestation {
    pub attestation_id: String,
    pub claim_id: String,
    pub vault_id: String,
    pub attestor_commitment: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub kinds: BTreeSet<AttestationKind>,
    pub quorum_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub observed_l2_height: u64,
    pub expires_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqEncapsulationAttestationInput {
    pub attestation_id: String,
    pub claim_id: String,
    pub attestor_commitment: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub kinds: BTreeSet<AttestationKind>,
    pub quorum_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub observed_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialLiquidityVoucher {
    pub voucher_id: String,
    pub claim_id: String,
    pub vault_id: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub recipient_commitment: String,
    pub voucher_nullifier: String,
    pub settlement_hint_root: String,
    pub risk_bucket: RiskBucket,
    pub lane: RescueLane,
    pub status: VoucherStatus,
    pub issued_micro_units: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub issued_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VoucherInput {
    pub voucher_id: String,
    pub claim_id: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub recipient_commitment: String,
    pub voucher_nullifier: String,
    pub settlement_hint_root: String,
    pub issued_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchSettlement {
    pub batch_id: String,
    pub vault_id: String,
    pub voucher_ids: Vec<String>,
    pub settlement_root: String,
    pub public_fee_root: String,
    pub decision: SettlementDecision,
    pub risk_bucket: RiskBucket,
    pub total_micro_units: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub settled_at_l2_height: u64,
    pub finalizes_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchSettlementInput {
    pub batch_id: String,
    pub vault_id: String,
    pub voucher_ids: Vec<String>,
    pub settlement_root: String,
    pub public_fee_root: String,
    pub decision: SettlementDecision,
    pub risk_bucket: RiskBucket,
    pub settled_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskBucketEntry {
    pub bucket_id: String,
    pub vault_id: String,
    pub bucket: RiskBucket,
    pub lane: RescueLane,
    pub liquidity_buffer_bps: u64,
    pub unresolved_claims: u64,
    pub reserved_micro_units: u64,
    pub latest_attestation_root: String,
    pub updated_at_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub roots: Roots,
    pub counters: Counters,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub vaults: BTreeMap<String, RescueVault>,
    pub sealed_claims: BTreeMap<String, SealedRescueClaim>,
    pub pq_attestations: BTreeMap<String, PqEncapsulationAttestation>,
    pub vouchers: BTreeMap<String, ConfidentialLiquidityVoucher>,
    pub settlements: BTreeMap<String, BatchSettlement>,
    pub risk_buckets: BTreeMap<String, RiskBucketEntry>,
    pub nullifiers: BTreeSet<String>,
    pub voucher_nullifiers: BTreeSet<String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            vaults: BTreeMap::new(),
            sealed_claims: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            vouchers: BTreeMap::new(),
            settlements: BTreeMap::new(),
            risk_buckets: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            voucher_nullifiers: BTreeSet::new(),
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let _ = state.register_vault(RescueVaultInput {
        vault_id: "devnet-primary-exit-rescue-vault".to_string(),
        operator_commitment: "operator:devnet:exit-rescue-primary".to_string(),
        reserve_commitment: "reserve:devnet:xmr-exit-liquidity:root".to_string(),
        liquidity_micro_units: 125_000_000_000,
        max_claim_micro_units: 5_000_000_000,
        fee_bps: 12,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        risk_bucket: RiskBucket::Green,
    });
    let _ = state.register_vault(RescueVaultInput {
        vault_id: "devnet-contract-exit-rescue-vault".to_string(),
        operator_commitment: "operator:devnet:contract-rescue".to_string(),
        reserve_commitment: "reserve:devnet:contract-exit-liquidity:root".to_string(),
        liquidity_micro_units: 80_000_000_000,
        max_claim_micro_units: 3_000_000_000,
        fee_bps: 16,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE / 2,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        risk_bucket: RiskBucket::Amber,
    });
    state
}
impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }
    pub fn set_heights(&mut self, l2_height: u64, monero_height: u64, epoch: u64) {
        self.l2_height = l2_height;
        self.monero_height = monero_height;
        self.epoch = epoch;
    }
    pub fn register_vault(&mut self, input: RescueVaultInput) -> Result<String> {
        ensure!(!input.vault_id.is_empty(), "vault_id is required");
        ensure!(
            !self.vaults.contains_key(&input.vault_id),
            "vault {} already exists",
            input.vault_id
        );
        ensure!(
            input.liquidity_micro_units > 0,
            "vault liquidity must be positive"
        );
        ensure!(
            input.max_claim_micro_units > 0,
            "max claim must be positive"
        );
        ensure!(
            input.max_claim_micro_units <= input.liquidity_micro_units,
            "max claim exceeds vault liquidity"
        );
        ensure!(
            input.fee_bps <= self.config.max_rescue_fee_bps,
            "fee {} exceeds cap {}",
            input.fee_bps,
            self.config.max_rescue_fee_bps
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set {} below minimum {}",
            input.privacy_set_size,
            self.config.min_privacy_set_size
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security {} below minimum {}",
            input.pq_security_bits,
            self.config.min_pq_security_bits
        );
        let vault = RescueVault {
            vault_id: input.vault_id.clone(),
            operator_commitment: input.operator_commitment,
            reserve_commitment: input.reserve_commitment,
            status: VaultStatus::Open,
            risk_bucket: input.risk_bucket,
            liquidity_micro_units: input.liquidity_micro_units,
            reserved_micro_units: 0,
            settled_micro_units: 0,
            max_claim_micro_units: input.max_claim_micro_units,
            fee_bps: input.fee_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            opened_at_l2_height: self.l2_height,
            updated_at_l2_height: self.l2_height,
        };
        let bucket = self.bucket_key(
            &vault.vault_id,
            vault.risk_bucket,
            RescueLane::FailedMoneroExit,
        );
        self.risk_buckets.insert(
            bucket.clone(),
            RiskBucketEntry {
                bucket_id: bucket,
                vault_id: vault.vault_id.clone(),
                bucket: vault.risk_bucket,
                lane: RescueLane::FailedMoneroExit,
                liquidity_buffer_bps: self.vault_liquidity_buffer_bps(&vault),
                unresolved_claims: 0,
                reserved_micro_units: 0,
                latest_attestation_root: self.empty_root("risk_bucket_attestation"),
                updated_at_l2_height: self.l2_height,
            },
        );
        self.counters.vaults += 1;
        self.counters.total_rescue_liquidity_micro_units = self
            .counters
            .total_rescue_liquidity_micro_units
            .saturating_add(vault.liquidity_micro_units);
        self.vaults.insert(vault.vault_id.clone(), vault);
        Ok(input.vault_id)
    }
    pub fn submit_sealed_claim(&mut self, input: SealedRescueClaimInput) -> Result<String> {
        ensure!(!input.claim_id.is_empty(), "claim_id is required");
        ensure!(
            !self.sealed_claims.contains_key(&input.claim_id),
            "claim {} already exists",
            input.claim_id
        );
        ensure!(
            !self.nullifiers.contains(&input.nullifier),
            "claim nullifier already used"
        );
        let vault = self
            .vaults
            .get(&input.vault_id)
            .ok_or_else(|| format!("vault {} not found", input.vault_id))?;
        ensure!(
            vault.status.accepts_claims(),
            "vault {} does not accept claims",
            input.vault_id
        );
        ensure!(
            input.requested_micro_units > 0,
            "requested amount must be positive"
        );
        ensure!(
            input.requested_micro_units <= vault.max_claim_micro_units,
            "requested amount exceeds vault max claim"
        );
        ensure!(
            input.max_fee_bps <= self.config.max_rescue_fee_bps,
            "claim max fee exceeds rescue cap"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "claim privacy set too small"
        );
        ensure!(
            input.ml_kem_parameter_set.pq_security_bits() >= self.config.min_pq_security_bits,
            "ML-KEM parameter set below configured security floor"
        );
        let available = vault
            .liquidity_micro_units
            .saturating_sub(vault.reserved_micro_units)
            .saturating_sub(vault.settled_micro_units);
        ensure!(
            available >= input.requested_micro_units,
            "vault {} has insufficient available liquidity",
            input.vault_id
        );
        let claim = SealedRescueClaim {
            claim_id: input.claim_id.clone(),
            vault_id: input.vault_id.clone(),
            exit_commitment: input.exit_commitment,
            sealed_claim_commitment: input.sealed_claim_commitment,
            claimant_view_tag_commitment: input.claimant_view_tag_commitment,
            rescue_amount_commitment: input.rescue_amount_commitment,
            requested_micro_units: input.requested_micro_units,
            lane: input.lane,
            risk_bucket: input.risk_bucket,
            ml_kem_parameter_set: input.ml_kem_parameter_set,
            ml_kem_ciphertext_root: input.ml_kem_ciphertext_root,
            encapsulation_attestation_root: input.encapsulation_attestation_root,
            nullifier: input.nullifier.clone(),
            monero_height_hint: input.monero_height_hint,
            l2_height_hint: input.l2_height_hint,
            privacy_set_size: input.privacy_set_size,
            max_fee_bps: input.max_fee_bps,
            status: ClaimStatus::Sealed,
            submitted_at_l2_height: self.l2_height,
            expires_at_l2_height: self
                .l2_height
                .saturating_add(self.config.rescue_window_blocks),
        };
        self.nullifiers.insert(input.nullifier);
        self.counters.sealed_claims += 1;
        self.sealed_claims.insert(claim.claim_id.clone(), claim);
        self.update_risk_bucket_for_claim(
            &input.vault_id,
            input.risk_bucket,
            input.lane,
            input.requested_micro_units,
            None,
        );
        Ok(input.claim_id)
    }
    pub fn attest_encapsulation(
        &mut self,
        input: PqEncapsulationAttestationInput,
    ) -> Result<String> {
        ensure!(
            !input.attestation_id.is_empty(),
            "attestation_id is required"
        );
        ensure!(
            !self.pq_attestations.contains_key(&input.attestation_id),
            "attestation {} already exists",
            input.attestation_id
        );
        let claim = self
            .sealed_claims
            .get_mut(&input.claim_id)
            .ok_or_else(|| format!("claim {} not found", input.claim_id))?;
        ensure!(
            claim.status == ClaimStatus::Sealed || claim.status == ClaimStatus::Attested,
            "claim {} is not attestable",
            input.claim_id
        );
        ensure!(
            input.quorum_bps >= self.config.min_attestation_quorum_bps,
            "attestation quorum below minimum"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set below minimum"
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security below minimum"
        );
        ensure!(
            input.kinds.contains(&AttestationKind::MlKemCiphertextBound),
            "ML-KEM ciphertext binding attestation is required"
        );
        ensure!(
            input.kinds.contains(&AttestationKind::NullifierFresh),
            "nullifier freshness attestation is required"
        );
        ensure!(
            input.kinds.contains(&AttestationKind::SettlementSafe),
            "settlement safety attestation is required"
        );
        let attestation = PqEncapsulationAttestation {
            attestation_id: input.attestation_id.clone(),
            claim_id: input.claim_id.clone(),
            vault_id: claim.vault_id.clone(),
            attestor_commitment: input.attestor_commitment,
            attestation_root: input.attestation_root.clone(),
            transcript_root: input.transcript_root,
            kinds: input.kinds,
            quorum_bps: input.quorum_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            observed_l2_height: input.observed_l2_height,
            expires_at_l2_height: input
                .observed_l2_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        claim.status = ClaimStatus::Attested;
        claim.encapsulation_attestation_root = input.attestation_root.clone();
        self.counters.attestations += 1;
        self.refresh_bucket_attestation(
            &attestation.vault_id,
            attestation.attestation_root.clone(),
        );
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(input.attestation_id)
    }
    pub fn issue_voucher(&mut self, input: VoucherInput) -> Result<String> {
        ensure!(!input.voucher_id.is_empty(), "voucher_id is required");
        ensure!(
            !self.vouchers.contains_key(&input.voucher_id),
            "voucher {} already exists",
            input.voucher_id
        );
        ensure!(
            !self.voucher_nullifiers.contains(&input.voucher_nullifier),
            "voucher nullifier already used"
        );
        let claim = self
            .sealed_claims
            .get_mut(&input.claim_id)
            .ok_or_else(|| format!("claim {} not found", input.claim_id))?;
        ensure!(
            claim.status == ClaimStatus::Attested,
            "claim {} must be attested before voucher issue",
            input.claim_id
        );
        ensure!(
            input.issued_micro_units > 0,
            "issued amount must be positive"
        );
        ensure!(
            input.issued_micro_units <= claim.requested_micro_units,
            "issued amount exceeds claim request"
        );
        let vault = self
            .vaults
            .get_mut(&claim.vault_id)
            .ok_or_else(|| format!("vault {} not found", claim.vault_id))?;
        let available = vault
            .liquidity_micro_units
            .saturating_sub(vault.reserved_micro_units)
            .saturating_sub(vault.settled_micro_units);
        ensure!(
            available >= input.issued_micro_units,
            "vault {} has insufficient liquidity for voucher",
            vault.vault_id
        );
        let fee_micro_units = fee_for(input.issued_micro_units, vault.fee_bps, claim.risk_bucket);
        let rebate_micro_units = rebate_for(
            fee_micro_units,
            self.config.target_rebate_bps,
            self.config.max_rebate_bps,
        );
        let voucher = ConfidentialLiquidityVoucher {
            voucher_id: input.voucher_id.clone(),
            claim_id: input.claim_id.clone(),
            vault_id: claim.vault_id.clone(),
            amount_commitment: input.amount_commitment,
            fee_commitment: input.fee_commitment,
            recipient_commitment: input.recipient_commitment,
            voucher_nullifier: input.voucher_nullifier.clone(),
            settlement_hint_root: input.settlement_hint_root,
            risk_bucket: claim.risk_bucket,
            lane: claim.lane,
            status: VoucherStatus::Confidential,
            issued_micro_units: input.issued_micro_units,
            fee_micro_units,
            rebate_micro_units,
            issued_at_l2_height: self.l2_height,
            expires_at_l2_height: self
                .l2_height
                .saturating_add(self.config.voucher_ttl_blocks),
        };
        vault.reserved_micro_units = vault
            .reserved_micro_units
            .saturating_add(input.issued_micro_units);
        vault.updated_at_l2_height = self.l2_height;
        claim.status = ClaimStatus::VoucherIssued;
        self.voucher_nullifiers.insert(input.voucher_nullifier);
        self.counters.vouchers += 1;
        self.counters.total_reserved_micro_units = self
            .counters
            .total_reserved_micro_units
            .saturating_add(input.issued_micro_units);
        self.vouchers.insert(input.voucher_id.clone(), voucher);
        Ok(input.voucher_id)
    }
    pub fn settle_batch(&mut self, input: BatchSettlementInput) -> Result<String> {
        ensure!(!input.batch_id.is_empty(), "batch_id is required");
        ensure!(
            !self.settlements.contains_key(&input.batch_id),
            "batch {} already exists",
            input.batch_id
        );
        ensure!(!input.voucher_ids.is_empty(), "batch must include vouchers");
        let mut total_micro_units = 0_u64;
        let mut total_fee_micro_units = 0_u64;
        let mut total_rebate_micro_units = 0_u64;
        for voucher_id in &input.voucher_ids {
            let voucher = self
                .vouchers
                .get(voucher_id)
                .ok_or_else(|| format!("voucher {} not found", voucher_id))?;
            ensure!(
                voucher.vault_id == input.vault_id,
                "voucher {} belongs to vault {}, not {}",
                voucher_id,
                voucher.vault_id,
                input.vault_id
            );
            ensure!(
                matches!(
                    voucher.status,
                    VoucherStatus::Confidential | VoucherStatus::Reserved
                ),
                "voucher {} is not settleable",
                voucher_id
            );
            total_micro_units = total_micro_units.saturating_add(voucher.issued_micro_units);
            total_fee_micro_units = total_fee_micro_units.saturating_add(voucher.fee_micro_units);
            total_rebate_micro_units =
                total_rebate_micro_units.saturating_add(voucher.rebate_micro_units);
        }
        let voucher_count = input.voucher_ids.len() as u64;
        let vault = self
            .vaults
            .get_mut(&input.vault_id)
            .ok_or_else(|| format!("vault {} not found", input.vault_id))?;
        ensure!(
            vault.reserved_micro_units >= total_micro_units,
            "vault reserved liquidity below batch total"
        );
        match input.decision {
            SettlementDecision::Approve
            | SettlementDecision::ApproveWithRebate
            | SettlementDecision::PartialFill => {
                vault.reserved_micro_units =
                    vault.reserved_micro_units.saturating_sub(total_micro_units);
                vault.settled_micro_units =
                    vault.settled_micro_units.saturating_add(total_micro_units);
                self.counters.total_settled_micro_units = self
                    .counters
                    .total_settled_micro_units
                    .saturating_add(total_micro_units);
                if matches!(input.decision, SettlementDecision::ApproveWithRebate) {
                    self.counters.fee_rebates =
                        self.counters.fee_rebates.saturating_add(voucher_count);
                }
            }
            SettlementDecision::Reject
            | SettlementDecision::Quarantine
            | SettlementDecision::Expire => {
                vault.reserved_micro_units =
                    vault.reserved_micro_units.saturating_sub(total_micro_units);
            }
            SettlementDecision::RetryLater => {}
        }
        vault.updated_at_l2_height = input.settled_at_l2_height;
        for voucher_id in &input.voucher_ids {
            if let Some(voucher) = self.vouchers.get_mut(voucher_id) {
                voucher.status = match input.decision {
                    SettlementDecision::Approve
                    | SettlementDecision::ApproveWithRebate
                    | SettlementDecision::PartialFill => VoucherStatus::Redeemed,
                    SettlementDecision::Reject | SettlementDecision::Quarantine => {
                        VoucherStatus::Slashed
                    }
                    SettlementDecision::Expire => VoucherStatus::Expired,
                    SettlementDecision::RetryLater => VoucherStatus::Reserved,
                };
                if let Some(claim) = self.sealed_claims.get_mut(&voucher.claim_id) {
                    claim.status = match input.decision {
                        SettlementDecision::Approve
                        | SettlementDecision::ApproveWithRebate
                        | SettlementDecision::PartialFill => ClaimStatus::Settled,
                        SettlementDecision::Reject => ClaimStatus::Rejected,
                        SettlementDecision::Quarantine => ClaimStatus::Quarantined,
                        SettlementDecision::Expire => ClaimStatus::Expired,
                        SettlementDecision::RetryLater => ClaimStatus::Batched,
                    };
                }
            }
        }
        let settlement = BatchSettlement {
            batch_id: input.batch_id.clone(),
            vault_id: input.vault_id,
            voucher_ids: input.voucher_ids,
            settlement_root: input.settlement_root,
            public_fee_root: input.public_fee_root,
            decision: input.decision,
            risk_bucket: input.risk_bucket,
            total_micro_units,
            total_fee_micro_units,
            total_rebate_micro_units,
            settled_at_l2_height: input.settled_at_l2_height,
            finalizes_at_l2_height: input
                .settled_at_l2_height
                .saturating_add(self.config.batch_finality_blocks),
        };
        self.counters.batches += 1;
        self.counters.settlements += voucher_count;
        self.settlements
            .insert(settlement.batch_id.clone(), settlement);
        Ok(input.batch_id)
    }
    pub fn reject_claim(&mut self, claim_id: &str, quarantine: bool) -> Result<()> {
        let claim = self
            .sealed_claims
            .get_mut(claim_id)
            .ok_or_else(|| format!("claim {} not found", claim_id))?;
        ensure!(claim.status.active(), "claim {} is not active", claim_id);
        claim.status = if quarantine {
            ClaimStatus::Quarantined
        } else {
            ClaimStatus::Rejected
        };
        if quarantine {
            self.counters.quarantined_claims += 1;
        } else {
            self.counters.rejected_claims += 1;
        }
        Ok(())
    }
    pub fn check_nullifier(&mut self, nullifier: &str) -> Result<()> {
        if self.nullifiers.contains(nullifier) || self.voucher_nullifiers.contains(nullifier) {
            self.counters.replay_attempts += 1;
            return Err(format!("nullifier {} has already been observed", nullifier));
        }
        Ok(())
    }
    pub fn roots(&self) -> Roots {
        let config_root = root_json("config", &self.config);
        let vault_root = map_root("vaults", &self.vaults);
        let sealed_claim_root = map_root("sealed_claims", &self.sealed_claims);
        let pq_attestation_root = map_root("pq_attestations", &self.pq_attestations);
        let voucher_root = map_root("vouchers", &self.vouchers);
        let settlement_root = map_root("settlements", &self.settlements);
        let batch_root = map_root("batches", &self.settlements);
        let nullifier_root = set_root("nullifiers", &self.nullifiers);
        let risk_bucket_root = map_root("risk_buckets", &self.risk_buckets);
        let counters_root = root_json("counters", &self.counters);
        let public_record_root = domain_hash(
            "private_l2_pq_confidential_ml_kem_exit_liquidity_rescue_vault:public_record",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&vault_root),
                HashPart::Str(&sealed_claim_root),
                HashPart::Str(&pq_attestation_root),
                HashPart::Str(&voucher_root),
                HashPart::Str(&settlement_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&risk_bucket_root),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
            ],
            32,
        );
        let state_root = domain_hash(
            "private_l2_pq_confidential_ml_kem_exit_liquidity_rescue_vault:state",
            &[
                HashPart::Str(&public_record_root),
                HashPart::Str(&batch_root),
                HashPart::Str(&counters_root),
                HashPart::U64(self.epoch),
            ],
            32,
        );
        Roots {
            config_root,
            vault_root,
            sealed_claim_root,
            pq_attestation_root,
            voucher_root,
            settlement_root,
            batch_root,
            nullifier_root,
            risk_bucket_root,
            counters_root,
            public_record_root,
            state_root,
        }
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    pub fn public_record(&self) -> PublicRecord {
        PublicRecord {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: self.config.chain_id.clone(),
            l2_network: self.config.l2_network.clone(),
            monero_network: self.config.monero_network.clone(),
            l2_height: self.l2_height,
            monero_height: self.monero_height,
            epoch: self.epoch,
            roots: self.roots(),
            counters: self.counters.clone(),
        }
    }
    pub fn public_record_json(&self) -> Value {
        json!(self.public_record())
    }
    fn vault_liquidity_buffer_bps(&self, vault: &RescueVault) -> u64 {
        if vault.liquidity_micro_units == 0 {
            return 0;
        }
        let free = vault
            .liquidity_micro_units
            .saturating_sub(vault.reserved_micro_units)
            .saturating_sub(vault.settled_micro_units);
        free.saturating_mul(MAX_BPS) / vault.liquidity_micro_units
    }
    fn bucket_key(&self, vault_id: &str, bucket: RiskBucket, lane: RescueLane) -> String {
        domain_hash(
            "exit_rescue_bucket_key",
            &[
                HashPart::Str(vault_id),
                HashPart::Str(bucket.as_str()),
                HashPart::Str(lane.as_str()),
            ],
            16,
        )
    }
    fn empty_root(&self, label: &str) -> String {
        domain_hash("exit_rescue_empty_root", &[HashPart::Str(label)], 32)
    }
    fn update_risk_bucket_for_claim(
        &mut self,
        vault_id: &str,
        bucket: RiskBucket,
        lane: RescueLane,
        amount: u64,
        attestation_root: Option<String>,
    ) {
        let key = self.bucket_key(vault_id, bucket, lane);
        let fallback_root = self.empty_root("risk_bucket_attestation");
        let entry = self
            .risk_buckets
            .entry(key.clone())
            .or_insert_with(|| RiskBucketEntry {
                bucket_id: key,
                vault_id: vault_id.to_string(),
                bucket,
                lane,
                liquidity_buffer_bps: 0,
                unresolved_claims: 0,
                reserved_micro_units: 0,
                latest_attestation_root: fallback_root,
                updated_at_l2_height: self.l2_height,
            });
        entry.unresolved_claims = entry.unresolved_claims.saturating_add(1);
        entry.reserved_micro_units = entry.reserved_micro_units.saturating_add(amount);
        if let Some(root) = attestation_root {
            entry.latest_attestation_root = root;
        }
        entry.updated_at_l2_height = self.l2_height;
    }
    fn refresh_bucket_attestation(&mut self, vault_id: &str, attestation_root: String) {
        for entry in self
            .risk_buckets
            .values_mut()
            .filter(|entry| entry.vault_id == vault_id)
        {
            entry.latest_attestation_root = attestation_root.clone();
            entry.updated_at_l2_height = self.l2_height;
        }
    }
    pub fn rescue_health_signal_00(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_00",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_01(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_01",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_02(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_02",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_03(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_03",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_04(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_04",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_05(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_05",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_06(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_06",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_07(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_07",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_08(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_08",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_09(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_09",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_10(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_10",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_11(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_11",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_12(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_12",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_13(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_13",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_14(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_14",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_15(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_15",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_16(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_16",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_17(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_17",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_18(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_18",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_19(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_19",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_20(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_20",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_21(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_21",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_22(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_22",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_23(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_23",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_24(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_24",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_25(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_25",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_26(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_26",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_27(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_27",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_28(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_28",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_29(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_29",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_30(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_30",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_31(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_31",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_32(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_32",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_33(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_33",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
    pub fn rescue_health_signal_34(&self) -> Value {
        let roots = self.roots();
        json!({
            "signal": "rescue_health_signal_34",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": roots.state_root,
            "vault_root": roots.vault_root,
            "claim_root": roots.sealed_claim_root,
            "voucher_root": roots.voucher_root,
            "risk_bucket_root": roots.risk_bucket_root,
            "vault_count": self.vaults.len(),
            "active_claims": self.active_claim_count(),
            "open_vouchers": self.open_voucher_count(),
            "settled_micro_units": self.counters.total_settled_micro_units,
            "reserved_micro_units": self.counters.total_reserved_micro_units,
            "fee_rebates": self.counters.fee_rebates,
        })
    }
}

impl State {
    pub fn active_claim_count(&self) -> usize {
        self.sealed_claims
            .values()
            .filter(|claim| claim.status.active())
            .count()
    }
    pub fn open_voucher_count(&self) -> usize {
        self.vouchers
            .values()
            .filter(|voucher| {
                matches!(
                    voucher.status,
                    VoucherStatus::Confidential | VoucherStatus::Reserved | VoucherStatus::Settling
                )
            })
            .count()
    }
    pub fn vault_available_liquidity(&self, vault_id: &str) -> Result<u64> {
        let vault = self
            .vaults
            .get(vault_id)
            .ok_or_else(|| format!("vault {} not found", vault_id))?;
        Ok(vault
            .liquidity_micro_units
            .saturating_sub(vault.reserved_micro_units)
            .saturating_sub(vault.settled_micro_units))
    }
    pub fn risk_bucket_summary(&self) -> Value {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut reserved: BTreeMap<String, u64> = BTreeMap::new();
        for entry in self.risk_buckets.values() {
            *counts.entry(entry.bucket.as_str().to_string()).or_default() +=
                entry.unresolved_claims;
            *reserved
                .entry(entry.bucket.as_str().to_string())
                .or_default() += entry.reserved_micro_units;
        }
        json!({"counts": counts, "reserved_micro_units": reserved, "risk_bucket_root": self.roots().risk_bucket_root})
    }
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn public_record(state: &State) -> PublicRecord {
    state.public_record()
}

fn fee_for(amount: u64, fee_bps: u64, bucket: RiskBucket) -> u64 {
    amount
        .saturating_mul(fee_bps)
        .saturating_mul(bucket.fee_multiplier_bps())
        / MAX_BPS
        / MAX_BPS
}
fn rebate_for(fee_micro_units: u64, target_rebate_bps: u64, max_rebate_bps: u64) -> u64 {
    let rebate_bps = target_rebate_bps.min(max_rebate_bps);
    fee_micro_units.saturating_mul(rebate_bps) / MAX_BPS
}
fn root_json<T: Serialize>(label: &str, value: &T) -> String {
    let value = serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"}));
    domain_hash(
        "private_l2_pq_confidential_ml_kem_exit_liquidity_rescue_vault:json_root",
        &[HashPart::Str(label), HashPart::Json(&value)],
        32,
    )
}
fn map_root<T: Serialize>(label: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_ml_kem_exit_liquidity_rescue_vault:{label}"),
        &leaves,
    )
}
fn set_root(label: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_ml_kem_exit_liquidity_rescue_vault:{label}"),
        &leaves,
    )
}
