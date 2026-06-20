use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedStakedXmrVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_STAKED_XMR_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-staked-xmr-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_STAKED_XMR_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_VAULT_COMMITTEE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-tokenized-staked-xmr-vault-committee-v1";
pub const CONFIDENTIAL_SHARE_NOTE_SCHEME: &str =
    "ml-kem-1024+xwing-confidential-staked-xmr-share-note-v1";
pub const STAKED_XMR_RESERVE_SCHEME: &str = "monero-l2-staked-xmr-reserve-accounting-root-v1";
pub const WITHDRAWAL_QUEUE_SCHEME: &str =
    "private-l2-confidential-staked-xmr-withdrawal-queue-root-v1";
pub const REWARD_NETTING_SCHEME: &str = "low-fee-staked-xmr-reward-netting-root-v1";
pub const LIQUIDITY_CONTROL_SCHEME: &str = "staked-xmr-vault-liquidity-control-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "operator-safe-staked-xmr-redaction-budget-root-v1";
pub const PUBLIC_SUMMARY_SCHEME: &str = "privacy-preserving-staked-xmr-vault-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "xmr-devnet";
pub const DEVNET_SHARE_ASSET_ID: &str = "sxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_812_000;
pub const DEVNET_EPOCH: u64 = 8_192;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_UNSTAKE_DELAY_BLOCKS: u64 = 2_880;
pub const DEFAULT_WITHDRAWAL_SETTLEMENT_BLOCKS: u64 = 144;
pub const DEFAULT_REWARD_REPORT_TTL_BLOCKS: u64 = 120;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 43_200;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 80;
pub const DEFAULT_REWARD_REBATE_BPS: u64 = 2;
pub const DEFAULT_LIQUID_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_WITHDRAWAL_BUFFER_BPS: u64 = 800;
pub const DEFAULT_MAX_SLIPPAGE_BPS: u64 = 20;
pub const DEFAULT_MAX_SHARE_PRICE_DRIFT_BPS: u64 = 75;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_667;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 512;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VAULTS: usize = 262_144;
pub const MAX_SHARE_TOKENS: usize = 262_144;
pub const MAX_STAKE_EPOCHS: usize = 1_048_576;
pub const MAX_REWARD_REPORTS: usize = 2_097_152;
pub const MAX_PQ_ATTESTATIONS: usize = 2_097_152;
pub const MAX_WITHDRAWAL_SETTLEMENTS: usize = 2_097_152;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    CommitteeAttested,
    Active,
    LiquidityLimited,
    WithdrawalOnly,
    Paused,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::CommitteeAttested => "committee_attested",
            Self::Active => "active",
            Self::LiquidityLimited => "liquidity_limited",
            Self::WithdrawalOnly => "withdrawal_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::CommitteeAttested | Self::Active)
    }

    pub fn permits_withdrawals(self) -> bool {
        matches!(
            self,
            Self::CommitteeAttested
                | Self::Active
                | Self::LiquidityLimited
                | Self::WithdrawalOnly
                | Self::Paused
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareTokenKind {
    ConfidentialStakedXmr,
    LiquidReceipt,
    LockedEpochShare,
    WithdrawalClaim,
    RewardCredit,
    OperatorCarry,
}

impl ShareTokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialStakedXmr => "confidential_staked_xmr",
            Self::LiquidReceipt => "liquid_receipt",
            Self::LockedEpochShare => "locked_epoch_share",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::RewardCredit => "reward_credit",
            Self::OperatorCarry => "operator_carry",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeEpochStatus {
    Open,
    Sealed,
    Staking,
    Rewarded,
    Unstaking,
    Settled,
    Disputed,
}

impl StakeEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Staking => "staking",
            Self::Rewarded => "rewarded",
            Self::Unstaking => "unstaking",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
        }
    }

    pub fn accepts_stake(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardReportStatus {
    Submitted,
    CommitteeAttested,
    Netted,
    Rebated,
    Expired,
    Disputed,
}

impl RewardReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::CommitteeAttested => "committee_attested",
            Self::Netted => "netted",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    VaultAdmission,
    ReserveCoverage,
    SharePrice,
    RewardReport,
    WithdrawalQueue,
    LiquidityControl,
    OperatorSummary,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultAdmission => "vault_admission",
            Self::ReserveCoverage => "reserve_coverage",
            Self::SharePrice => "share_price",
            Self::RewardReport => "reward_report",
            Self::WithdrawalQueue => "withdrawal_queue",
            Self::LiquidityControl => "liquidity_control",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalStatus {
    Queued,
    PrivacyFenced,
    LiquidityReserved,
    Batched,
    Settled,
    Cancelled,
    Expired,
}

impl WithdrawalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::PrivacyFenced => "privacy_fenced",
            Self::LiquidityReserved => "liquidity_reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::PrivacyFenced | Self::LiquidityReserved | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Netted,
    Claimed,
    Expired,
    Revoked,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Netted => "netted",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityMode {
    Normal,
    RewardNettingPreferred,
    WithdrawalBuffer,
    QueueThrottled,
    EmergencyPause,
}

impl LiquidityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::RewardNettingPreferred => "reward_netting_preferred",
            Self::WithdrawalBuffer => "withdrawal_buffer",
            Self::QueueThrottled => "queue_throttled",
            Self::EmergencyPause => "emergency_pause",
        }
    }

    pub fn allows_deposit(self) -> bool {
        matches!(self, Self::Normal | Self::RewardNettingPreferred)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub share_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_vault_committee_attestation_scheme: String,
    pub confidential_share_note_scheme: String,
    pub staked_xmr_reserve_scheme: String,
    pub withdrawal_queue_scheme: String,
    pub reward_netting_scheme: String,
    pub liquidity_control_scheme: String,
    pub redaction_budget_scheme: String,
    pub public_summary_scheme: String,
    pub epoch_blocks: u64,
    pub unstake_delay_blocks: u64,
    pub withdrawal_settlement_blocks: u64,
    pub reward_report_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub redaction_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub reward_rebate_bps: u64,
    pub liquid_reserve_bps: u64,
    pub withdrawal_buffer_bps: u64,
    pub max_slippage_bps: u64,
    pub max_share_price_drift_bps: u64,
    pub committee_quorum_bps: u64,
    pub redaction_budget_units: u64,
    pub max_vaults: usize,
    pub max_share_tokens: usize,
    pub max_stake_epochs: usize,
    pub max_reward_reports: usize,
    pub max_pq_attestations: usize,
    pub max_withdrawal_settlements: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            share_asset_id: DEVNET_SHARE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_vault_committee_attestation_scheme: PQ_VAULT_COMMITTEE_ATTESTATION_SCHEME
                .to_string(),
            confidential_share_note_scheme: CONFIDENTIAL_SHARE_NOTE_SCHEME.to_string(),
            staked_xmr_reserve_scheme: STAKED_XMR_RESERVE_SCHEME.to_string(),
            withdrawal_queue_scheme: WITHDRAWAL_QUEUE_SCHEME.to_string(),
            reward_netting_scheme: REWARD_NETTING_SCHEME.to_string(),
            liquidity_control_scheme: LIQUIDITY_CONTROL_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            public_summary_scheme: PUBLIC_SUMMARY_SCHEME.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            unstake_delay_blocks: DEFAULT_UNSTAKE_DELAY_BLOCKS,
            withdrawal_settlement_blocks: DEFAULT_WITHDRAWAL_SETTLEMENT_BLOCKS,
            reward_report_ttl_blocks: DEFAULT_REWARD_REPORT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            reward_rebate_bps: DEFAULT_REWARD_REBATE_BPS,
            liquid_reserve_bps: DEFAULT_LIQUID_RESERVE_BPS,
            withdrawal_buffer_bps: DEFAULT_WITHDRAWAL_BUFFER_BPS,
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            max_share_price_drift_bps: DEFAULT_MAX_SHARE_PRICE_DRIFT_BPS,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_vaults: MAX_VAULTS,
            max_share_tokens: MAX_SHARE_TOKENS,
            max_stake_epochs: MAX_STAKE_EPOCHS,
            max_reward_reports: MAX_REWARD_REPORTS,
            max_pq_attestations: MAX_PQ_ATTESTATIONS,
            max_withdrawal_settlements: MAX_WITHDRAWAL_SETTLEMENTS,
            max_rebates: MAX_REBATES,
            max_redaction_budgets: MAX_REDACTION_BUDGETS,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version"
        );
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("operator_fee_bps", self.operator_fee_bps)?;
        ensure_bps("reward_rebate_bps", self.reward_rebate_bps)?;
        ensure_bps("liquid_reserve_bps", self.liquid_reserve_bps)?;
        ensure_bps("max_slippage_bps", self.max_slippage_bps)?;
        ensure_bps("committee_quorum_bps", self.committee_quorum_bps)?;
        ensure!(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target user fee exceeds max user fee"
        );
        ensure!(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below runtime minimum"
        );
        ensure!(self.epoch_blocks > 0, "epoch blocks must be nonzero");
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub share_tokens: u64,
    pub stake_epochs: u64,
    pub reward_reports: u64,
    pub pq_attestations: u64,
    pub withdrawal_settlements: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub live_withdrawal_queue_items: u64,
    pub netted_reward_reports: u64,
    pub public_summary_updates: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub vaults_root: String,
    pub share_tokens_root: String,
    pub stake_epochs_root: String,
    pub reward_reports_root: String,
    pub pq_attestations_root: String,
    pub withdrawal_settlements_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRequest {
    pub operator_id: String,
    pub vault_label: String,
    pub reserve_commitment: String,
    pub share_price_commitment: String,
    pub committee_root: String,
    pub policy_root: String,
    pub liquidity_mode: LiquidityMode,
    pub target_liquid_reserve_bps: u64,
    pub max_slippage_bps: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Vault {
    pub vault_id: String,
    pub operator_id: String,
    pub vault_label: String,
    pub status: VaultStatus,
    pub liquidity_mode: LiquidityMode,
    pub reserve_commitment: String,
    pub share_price_commitment: String,
    pub committee_root: String,
    pub policy_root: String,
    pub target_liquid_reserve_bps: u64,
    pub max_slippage_bps: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl Vault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "operator_id": self.operator_id,
            "vault_label": self.vault_label,
            "status": self.status.as_str(),
            "liquidity_mode": self.liquidity_mode.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "share_price_commitment": self.share_price_commitment,
            "committee_root": self.committee_root,
            "policy_root": self.policy_root,
            "target_liquid_reserve_bps": self.target_liquid_reserve_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("vault", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareTokenRequest {
    pub vault_id: String,
    pub symbol: String,
    pub token_kind: ShareTokenKind,
    pub supply_commitment: String,
    pub share_note_root: String,
    pub redemption_policy_root: String,
    pub decimals: u8,
    pub transferable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShareToken {
    pub share_token_id: String,
    pub vault_id: String,
    pub symbol: String,
    pub token_kind: ShareTokenKind,
    pub supply_commitment: String,
    pub share_note_root: String,
    pub redemption_policy_root: String,
    pub decimals: u8,
    pub transferable: bool,
    pub issued_height: u64,
}

impl ShareToken {
    pub fn public_record(&self) -> Value {
        json!({
            "share_token_id": self.share_token_id,
            "vault_id": self.vault_id,
            "symbol": self.symbol,
            "token_kind": self.token_kind.as_str(),
            "supply_commitment": self.supply_commitment,
            "share_note_root": self.share_note_root,
            "redemption_policy_root": self.redemption_policy_root,
            "decimals": self.decimals,
            "transferable": self.transferable,
            "issued_height": self.issued_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("share_token", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StakeEpochRequest {
    pub vault_id: String,
    pub epoch_index: u64,
    pub stake_commitment: String,
    pub share_delta_commitment: String,
    pub reserve_proof_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StakeEpoch {
    pub stake_epoch_id: String,
    pub vault_id: String,
    pub epoch_index: u64,
    pub status: StakeEpochStatus,
    pub stake_commitment: String,
    pub share_delta_commitment: String,
    pub reserve_proof_root: String,
    pub privacy_set_size: u64,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub unlocks_at_height: u64,
}

impl StakeEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "stake_epoch_id": self.stake_epoch_id,
            "vault_id": self.vault_id,
            "epoch_index": self.epoch_index,
            "status": self.status.as_str(),
            "stake_commitment": self.stake_commitment,
            "share_delta_commitment": self.share_delta_commitment,
            "reserve_proof_root": self.reserve_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "unlocks_at_height": self.unlocks_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("stake_epoch", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RewardReportRequest {
    pub vault_id: String,
    pub stake_epoch_id: String,
    pub gross_reward_commitment: String,
    pub operator_fee_commitment: String,
    pub net_reward_commitment: String,
    pub share_price_commitment: String,
    pub proof_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RewardReport {
    pub reward_report_id: String,
    pub vault_id: String,
    pub stake_epoch_id: String,
    pub status: RewardReportStatus,
    pub gross_reward_commitment: String,
    pub operator_fee_commitment: String,
    pub net_reward_commitment: String,
    pub share_price_commitment: String,
    pub proof_root: String,
    pub privacy_set_size: u64,
    pub reported_height: u64,
    pub expires_at_height: u64,
}

impl RewardReport {
    pub fn public_record(&self) -> Value {
        json!({
            "reward_report_id": self.reward_report_id,
            "vault_id": self.vault_id,
            "stake_epoch_id": self.stake_epoch_id,
            "status": self.status.as_str(),
            "gross_reward_commitment": self.gross_reward_commitment,
            "operator_fee_commitment": self.operator_fee_commitment,
            "net_reward_commitment": self.net_reward_commitment,
            "share_price_commitment": self.share_price_commitment,
            "proof_root": self.proof_root,
            "privacy_set_size": self.privacy_set_size,
            "reported_height": self.reported_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("reward_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRequest {
    pub subject_id: String,
    pub kind: AttestationKind,
    pub committee_id: String,
    pub attested_root: String,
    pub signature_root: String,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub committee_id: String,
    pub attested_root: String,
    pub signature_root: String,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub expires_at_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "committee_id": self.committee_id,
            "attested_root": self.attested_root,
            "signature_root": self.signature_root,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "attested_height": self.attested_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("pq_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalSettlementRequest {
    pub vault_id: String,
    pub share_token_id: String,
    pub queue_nullifier: String,
    pub claim_commitment: String,
    pub settlement_root: String,
    pub xmr_payout_commitment: String,
    pub requested_share_amount: u128,
    pub min_payout_amount: u128,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalSettlement {
    pub withdrawal_settlement_id: String,
    pub vault_id: String,
    pub share_token_id: String,
    pub status: WithdrawalStatus,
    pub queue_nullifier: String,
    pub claim_commitment: String,
    pub settlement_root: String,
    pub xmr_payout_commitment: String,
    pub requested_share_amount: u128,
    pub min_payout_amount: u128,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub queued_height: u64,
    pub settle_after_height: u64,
    pub expires_at_height: u64,
}

impl WithdrawalSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_settlement_id": self.withdrawal_settlement_id,
            "vault_id": self.vault_id,
            "share_token_id": self.share_token_id,
            "status": self.status.as_str(),
            "queue_nullifier": self.queue_nullifier,
            "claim_commitment": self.claim_commitment,
            "settlement_root": self.settlement_root,
            "xmr_payout_commitment": self.xmr_payout_commitment,
            "requested_share_amount": self.requested_share_amount.to_string(),
            "min_payout_amount": self.min_payout_amount.to_string(),
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "queued_height": self.queued_height,
            "settle_after_height": self.settle_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("withdrawal_settlement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRequest {
    pub vault_id: String,
    pub reward_report_id: String,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub netting_root: String,
    pub rebate_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub vault_id: String,
    pub reward_report_id: String,
    pub status: RebateStatus,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub netting_root: String,
    pub rebate_bps: u64,
    pub accrued_height: u64,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "vault_id": self.vault_id,
            "reward_report_id": self.reward_report_id,
            "status": self.status.as_str(),
            "recipient_commitment": self.recipient_commitment,
            "rebate_commitment": self.rebate_commitment,
            "netting_root": self.netting_root,
            "rebate_bps": self.rebate_bps,
            "accrued_height": self.accrued_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("rebate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub vault_id: String,
    pub summary_epoch: u64,
    pub max_redactions: u64,
    pub spent_redactions: u64,
    pub redaction_commitment_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn remaining(&self) -> u64 {
        self.max_redactions.saturating_sub(self.spent_redactions)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_id": self.operator_id,
            "vault_id": self.vault_id,
            "summary_epoch": self.summary_epoch,
            "max_redactions": self.max_redactions,
            "spent_redactions": self.spent_redactions,
            "remaining_redactions": self.remaining(),
            "redaction_commitment_root": self.redaction_commitment_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("redaction_budget", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_summary_id: String,
    pub operator_id: String,
    pub vault_id: String,
    pub summary_epoch: u64,
    pub public_tvl_bucket: u64,
    pub public_share_price_bucket: u64,
    pub public_queue_depth_bucket: u64,
    pub reward_apr_bps_bucket: u64,
    pub liquidity_mode: LiquidityMode,
    pub attestation_root: String,
    pub redaction_budget_id: String,
    pub published_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_summary_id": self.operator_summary_id,
            "operator_id": self.operator_id,
            "vault_id": self.vault_id,
            "summary_epoch": self.summary_epoch,
            "public_tvl_bucket": self.public_tvl_bucket,
            "public_share_price_bucket": self.public_share_price_bucket,
            "public_queue_depth_bucket": self.public_queue_depth_bucket,
            "reward_apr_bps_bucket": self.reward_apr_bps_bucket,
            "liquidity_mode": self.liquidity_mode.as_str(),
            "attestation_root": self.attestation_root,
            "redaction_budget_id": self.redaction_budget_id,
            "published_height": self.published_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("operator_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub vaults: BTreeMap<String, Vault>,
    pub share_tokens: BTreeMap<String, ShareToken>,
    pub stake_epochs: BTreeMap<String, StakeEpoch>,
    pub reward_reports: BTreeMap<String, RewardReport>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub withdrawal_settlements: BTreeMap<String, WithdrawalSettlement>,
    pub rebates: BTreeMap<String, Rebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub used_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            roots: Roots::default(),
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            share_tokens: BTreeMap::new(),
            stake_epochs: BTreeMap::new(),
            reward_reports: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            withdrawal_settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet().expect("devnet state")
    }

    pub fn register_vault(&mut self, request: VaultRequest, status: VaultStatus) -> Result<String> {
        ensure_capacity("vaults", self.vaults.len(), self.config.max_vaults)?;
        ensure_nonempty("operator_id", &request.operator_id)?;
        ensure_nonempty("vault_label", &request.vault_label)?;
        ensure_hash_like("reserve_commitment", &request.reserve_commitment)?;
        ensure_hash_like("share_price_commitment", &request.share_price_commitment)?;
        ensure_hash_like("committee_root", &request.committee_root)?;
        ensure_hash_like("policy_root", &request.policy_root)?;
        ensure_bps(
            "target_liquid_reserve_bps",
            request.target_liquid_reserve_bps,
        )?;
        ensure_bps("max_slippage_bps", request.max_slippage_bps)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "vault privacy set below minimum"
        );
        ensure!(
            request.max_slippage_bps <= self.config.max_slippage_bps,
            "vault slippage exceeds config"
        );
        let vault_id = vault_id(&request);
        ensure!(
            !self.vaults.contains_key(&vault_id),
            "vault already registered: {vault_id}"
        );
        let vault = Vault {
            vault_id: vault_id.clone(),
            operator_id: request.operator_id,
            vault_label: request.vault_label,
            status,
            liquidity_mode: request.liquidity_mode,
            reserve_commitment: request.reserve_commitment,
            share_price_commitment: request.share_price_commitment,
            committee_root: request.committee_root,
            policy_root: request.policy_root,
            target_liquid_reserve_bps: request.target_liquid_reserve_bps,
            max_slippage_bps: request.max_slippage_bps,
            privacy_set_size: request.privacy_set_size,
            created_height: self.height,
            updated_height: self.height,
        };
        self.vaults.insert(vault_id.clone(), vault);
        self.refresh_roots();
        Ok(vault_id)
    }

    pub fn issue_share_token(&mut self, request: ShareTokenRequest) -> Result<String> {
        ensure_capacity(
            "share_tokens",
            self.share_tokens.len(),
            self.config.max_share_tokens,
        )?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| format!("unknown vault: {}", request.vault_id))?;
        ensure!(
            vault.status.accepts_deposits(),
            "vault does not accept share issuance"
        );
        ensure_nonempty("symbol", &request.symbol)?;
        ensure_hash_like("supply_commitment", &request.supply_commitment)?;
        ensure_hash_like("share_note_root", &request.share_note_root)?;
        ensure_hash_like("redemption_policy_root", &request.redemption_policy_root)?;
        ensure!(request.decimals <= 18, "share token decimals too large");
        let share_token_id = share_token_id(&request);
        ensure!(
            !self.share_tokens.contains_key(&share_token_id),
            "share token already issued: {share_token_id}"
        );
        let token = ShareToken {
            share_token_id: share_token_id.clone(),
            vault_id: request.vault_id,
            symbol: request.symbol,
            token_kind: request.token_kind,
            supply_commitment: request.supply_commitment,
            share_note_root: request.share_note_root,
            redemption_policy_root: request.redemption_policy_root,
            decimals: request.decimals,
            transferable: request.transferable,
            issued_height: self.height,
        };
        self.share_tokens.insert(share_token_id.clone(), token);
        self.refresh_roots();
        Ok(share_token_id)
    }

    pub fn open_stake_epoch(&mut self, request: StakeEpochRequest) -> Result<String> {
        ensure_capacity(
            "stake_epochs",
            self.stake_epochs.len(),
            self.config.max_stake_epochs,
        )?;
        ensure_known_vault(self, &request.vault_id)?;
        ensure_hash_like("stake_commitment", &request.stake_commitment)?;
        ensure_hash_like("share_delta_commitment", &request.share_delta_commitment)?;
        ensure_hash_like("reserve_proof_root", &request.reserve_proof_root)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "stake epoch privacy set below minimum"
        );
        let stake_epoch_id = stake_epoch_id(&request);
        ensure!(
            !self.stake_epochs.contains_key(&stake_epoch_id),
            "stake epoch already exists: {stake_epoch_id}"
        );
        let epoch = StakeEpoch {
            stake_epoch_id: stake_epoch_id.clone(),
            vault_id: request.vault_id,
            epoch_index: request.epoch_index,
            status: StakeEpochStatus::Open,
            stake_commitment: request.stake_commitment,
            share_delta_commitment: request.share_delta_commitment,
            reserve_proof_root: request.reserve_proof_root,
            privacy_set_size: request.privacy_set_size,
            opens_at_height: self.height,
            closes_at_height: self.height.saturating_add(self.config.epoch_blocks),
            unlocks_at_height: self
                .height
                .saturating_add(self.config.epoch_blocks)
                .saturating_add(self.config.unstake_delay_blocks),
        };
        self.stake_epochs.insert(stake_epoch_id.clone(), epoch);
        self.refresh_roots();
        Ok(stake_epoch_id)
    }

    pub fn submit_reward_report(&mut self, request: RewardReportRequest) -> Result<String> {
        ensure_capacity(
            "reward_reports",
            self.reward_reports.len(),
            self.config.max_reward_reports,
        )?;
        ensure_known_vault(self, &request.vault_id)?;
        ensure!(
            self.stake_epochs.contains_key(&request.stake_epoch_id),
            "unknown stake epoch"
        );
        ensure_hash_like("gross_reward_commitment", &request.gross_reward_commitment)?;
        ensure_hash_like("operator_fee_commitment", &request.operator_fee_commitment)?;
        ensure_hash_like("net_reward_commitment", &request.net_reward_commitment)?;
        ensure_hash_like("share_price_commitment", &request.share_price_commitment)?;
        ensure_hash_like("proof_root", &request.proof_root)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "reward report privacy set below minimum"
        );
        let reward_report_id = reward_report_id(&request);
        ensure!(
            !self.reward_reports.contains_key(&reward_report_id),
            "reward report already exists: {reward_report_id}"
        );
        let report = RewardReport {
            reward_report_id: reward_report_id.clone(),
            vault_id: request.vault_id,
            stake_epoch_id: request.stake_epoch_id,
            status: RewardReportStatus::Submitted,
            gross_reward_commitment: request.gross_reward_commitment,
            operator_fee_commitment: request.operator_fee_commitment,
            net_reward_commitment: request.net_reward_commitment,
            share_price_commitment: request.share_price_commitment,
            proof_root: request.proof_root,
            privacy_set_size: request.privacy_set_size,
            reported_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.reward_report_ttl_blocks),
        };
        self.reward_reports.insert(reward_report_id.clone(), report);
        self.refresh_roots();
        Ok(reward_report_id)
    }

    pub fn attest(&mut self, request: PqAttestationRequest) -> Result<String> {
        ensure_capacity(
            "pq_attestations",
            self.pq_attestations.len(),
            self.config.max_pq_attestations,
        )?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("committee_id", &request.committee_id)?;
        ensure_hash_like("attested_root", &request.attested_root)?;
        ensure_hash_like("signature_root", &request.signature_root)?;
        ensure_bps("quorum_bps", request.quorum_bps)?;
        ensure!(
            request.quorum_bps >= self.config.committee_quorum_bps,
            "attestation quorum below config"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security below config"
        );
        let attestation_id = pq_attestation_id(&request);
        let attestation = PqAttestation {
            attestation_id: attestation_id.clone(),
            subject_id: request.subject_id,
            kind: request.kind,
            committee_id: request.committee_id,
            attested_root: request.attested_root,
            signature_root: request.signature_root,
            quorum_bps: request.quorum_bps,
            pq_security_bits: request.pq_security_bits,
            attested_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn queue_withdrawal(&mut self, request: WithdrawalSettlementRequest) -> Result<String> {
        ensure_capacity(
            "withdrawal_settlements",
            self.withdrawal_settlements.len(),
            self.config.max_withdrawal_settlements,
        )?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| format!("unknown vault: {}", request.vault_id))?;
        ensure!(
            vault.status.permits_withdrawals(),
            "vault does not permit withdrawals"
        );
        ensure!(
            self.share_tokens.contains_key(&request.share_token_id),
            "unknown share token"
        );
        ensure_hash_like("queue_nullifier", &request.queue_nullifier)?;
        ensure_hash_like("claim_commitment", &request.claim_commitment)?;
        ensure_hash_like("settlement_root", &request.settlement_root)?;
        ensure_hash_like("xmr_payout_commitment", &request.xmr_payout_commitment)?;
        ensure!(
            !self.used_nullifiers.contains(&request.queue_nullifier),
            "withdrawal nullifier already used"
        );
        ensure!(
            request.requested_share_amount > 0,
            "requested share amount must be nonzero"
        );
        ensure_bps("fee_bps", request.fee_bps)?;
        ensure!(
            request.fee_bps <= self.config.max_user_fee_bps,
            "withdrawal fee exceeds config"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "withdrawal privacy set below minimum"
        );
        let withdrawal_settlement_id = withdrawal_settlement_id(&request);
        self.used_nullifiers.insert(request.queue_nullifier.clone());
        let settlement = WithdrawalSettlement {
            withdrawal_settlement_id: withdrawal_settlement_id.clone(),
            vault_id: request.vault_id,
            share_token_id: request.share_token_id,
            status: WithdrawalStatus::Queued,
            queue_nullifier: request.queue_nullifier,
            claim_commitment: request.claim_commitment,
            settlement_root: request.settlement_root,
            xmr_payout_commitment: request.xmr_payout_commitment,
            requested_share_amount: request.requested_share_amount,
            min_payout_amount: request.min_payout_amount,
            fee_bps: request.fee_bps,
            privacy_set_size: request.privacy_set_size,
            queued_height: self.height,
            settle_after_height: self
                .height
                .saturating_add(self.config.withdrawal_settlement_blocks),
            expires_at_height: self
                .height
                .saturating_add(self.config.withdrawal_settlement_blocks)
                .saturating_add(self.config.unstake_delay_blocks),
        };
        self.withdrawal_settlements
            .insert(withdrawal_settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(withdrawal_settlement_id)
    }

    pub fn accrue_rebate(&mut self, request: RebateRequest) -> Result<String> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        ensure_known_vault(self, &request.vault_id)?;
        ensure!(
            self.reward_reports.contains_key(&request.reward_report_id),
            "unknown reward report"
        );
        ensure_hash_like("recipient_commitment", &request.recipient_commitment)?;
        ensure_hash_like("rebate_commitment", &request.rebate_commitment)?;
        ensure_hash_like("netting_root", &request.netting_root)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        ensure!(
            request.rebate_bps <= self.config.reward_rebate_bps,
            "rebate exceeds config"
        );
        let rebate_id = rebate_id(&request);
        let rebate = Rebate {
            rebate_id: rebate_id.clone(),
            vault_id: request.vault_id,
            reward_report_id: request.reward_report_id,
            status: RebateStatus::Accrued,
            recipient_commitment: request.recipient_commitment,
            rebate_commitment: request.rebate_commitment,
            netting_root: request.netting_root,
            rebate_bps: request.rebate_bps,
            accrued_height: self.height,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn install_redaction_budget(
        &mut self,
        operator_id: String,
        vault_id: String,
        summary_epoch: u64,
        redaction_commitment_root: String,
    ) -> Result<String> {
        ensure_capacity(
            "redaction_budgets",
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        ensure_nonempty("operator_id", &operator_id)?;
        ensure_known_vault(self, &vault_id)?;
        ensure_hash_like("redaction_commitment_root", &redaction_commitment_root)?;
        let budget_id = redaction_budget_id(&operator_id, &vault_id, summary_epoch);
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            operator_id,
            vault_id,
            summary_epoch,
            max_redactions: self.config.redaction_budget_units,
            spent_redactions: 0,
            redaction_commitment_root,
            starts_at_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.redaction_window_blocks),
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        ensure_capacity(
            "operator_summaries",
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
        )?;
        ensure_known_vault(self, &summary.vault_id)?;
        ensure_nonempty("operator_id", &summary.operator_id)?;
        ensure_hash_like("attestation_root", &summary.attestation_root)?;
        ensure!(
            self.redaction_budgets
                .contains_key(&summary.redaction_budget_id),
            "unknown redaction budget"
        );
        let id = summary.operator_summary_id.clone();
        ensure_hash_like("operator_summary_id", &id)?;
        self.operator_summaries.insert(id.clone(), summary);
        self.refresh_roots();
        Ok(id)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let root = state_root_from_public_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(root));
        }
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "height": self.height,
            "epoch": self.epoch,
            "hash_suite": self.config.hash_suite,
            "schemes": {
                "pq_vault_committee_attestation": self.config.pq_vault_committee_attestation_scheme,
                "confidential_share_note": self.config.confidential_share_note_scheme,
                "staked_xmr_reserve": self.config.staked_xmr_reserve_scheme,
                "withdrawal_queue": self.config.withdrawal_queue_scheme,
                "reward_netting": self.config.reward_netting_scheme,
                "liquidity_control": self.config.liquidity_control_scheme,
                "redaction_budget": self.config.redaction_budget_scheme,
                "public_summary": self.config.public_summary_scheme,
            },
            "controls": {
                "target_user_fee_bps": self.config.target_user_fee_bps,
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "operator_fee_bps": self.config.operator_fee_bps,
                "reward_rebate_bps": self.config.reward_rebate_bps,
                "liquid_reserve_bps": self.config.liquid_reserve_bps,
                "withdrawal_buffer_bps": self.config.withdrawal_buffer_bps,
                "committee_quorum_bps": self.config.committee_quorum_bps,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
            },
            "counters": self.counters,
            "roots": self.roots,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    fn refresh_roots(&mut self) {
        let live_withdrawals = self
            .withdrawal_settlements
            .values()
            .filter(|settlement| settlement.status.live())
            .count() as u64;
        let netted_reports = self
            .reward_reports
            .values()
            .filter(|report| {
                matches!(
                    report.status,
                    RewardReportStatus::Netted | RewardReportStatus::Rebated
                )
            })
            .count() as u64;
        self.counters = Counters {
            vaults: self.vaults.len() as u64,
            share_tokens: self.share_tokens.len() as u64,
            stake_epochs: self.stake_epochs.len() as u64,
            reward_reports: self.reward_reports.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            withdrawal_settlements: self.withdrawal_settlements.len() as u64,
            rebates: self.rebates.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            live_withdrawal_queue_items: live_withdrawals,
            netted_reward_reports: netted_reports,
            public_summary_updates: self.operator_summaries.len() as u64,
        };
        self.roots = Roots {
            vaults_root: map_root("staked_xmr_vaults", &self.vaults, Vault::public_record),
            share_tokens_root: map_root(
                "staked_xmr_share_tokens",
                &self.share_tokens,
                ShareToken::public_record,
            ),
            stake_epochs_root: map_root(
                "staked_xmr_stake_epochs",
                &self.stake_epochs,
                StakeEpoch::public_record,
            ),
            reward_reports_root: map_root(
                "staked_xmr_reward_reports",
                &self.reward_reports,
                RewardReport::public_record,
            ),
            pq_attestations_root: map_root(
                "staked_xmr_pq_attestations",
                &self.pq_attestations,
                PqAttestation::public_record,
            ),
            withdrawal_settlements_root: map_root(
                "staked_xmr_withdrawal_settlements",
                &self.withdrawal_settlements,
                WithdrawalSettlement::public_record,
            ),
            rebates_root: map_root("staked_xmr_rebates", &self.rebates, Rebate::public_record),
            redaction_budgets_root: map_root(
                "staked_xmr_redaction_budgets",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summaries_root: map_root(
                "staked_xmr_operator_summaries",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            nullifier_root: set_root("staked_xmr_used_nullifiers", &self.used_nullifiers),
            public_record_root: record_root(
                "staked_xmr_public_record",
                &json!({
                    "vaults": self.vaults.len(),
                    "share_tokens": self.share_tokens.len(),
                    "stake_epochs": self.stake_epochs.len(),
                    "reward_reports": self.reward_reports.len(),
                    "withdrawal_settlements": self.withdrawal_settlements.len(),
                    "operator_summaries": self.operator_summaries.len(),
                }),
            ),
        };
    }
}

pub fn devnet() -> Result<State> {
    let mut state = State::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)?;
    let vault_id = state.register_vault(
        VaultRequest {
            operator_id: "devnet-staked-xmr-operator".to_string(),
            vault_label: "devnet confidential staked xmr vault".to_string(),
            reserve_commitment: sample_hash("vault-reserve"),
            share_price_commitment: sample_hash("initial-share-price"),
            committee_root: sample_hash("committee-root"),
            policy_root: sample_hash("policy-root"),
            liquidity_mode: LiquidityMode::RewardNettingPreferred,
            target_liquid_reserve_bps: DEFAULT_LIQUID_RESERVE_BPS,
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        },
        VaultStatus::CommitteeAttested,
    )?;
    let share_token_id = state.issue_share_token(ShareTokenRequest {
        vault_id: vault_id.clone(),
        symbol: "sXMRp".to_string(),
        token_kind: ShareTokenKind::ConfidentialStakedXmr,
        supply_commitment: sample_hash("share-supply"),
        share_note_root: sample_hash("share-note-root"),
        redemption_policy_root: sample_hash("redemption-policy"),
        decimals: 12,
        transferable: true,
    })?;
    let stake_epoch_id = state.open_stake_epoch(StakeEpochRequest {
        vault_id: vault_id.clone(),
        epoch_index: DEVNET_EPOCH,
        stake_commitment: sample_hash("epoch-stake"),
        share_delta_commitment: sample_hash("epoch-share-delta"),
        reserve_proof_root: sample_hash("reserve-proof"),
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
    })?;
    let reward_report_id = state.submit_reward_report(RewardReportRequest {
        vault_id: vault_id.clone(),
        stake_epoch_id: stake_epoch_id.clone(),
        gross_reward_commitment: sample_hash("gross-reward"),
        operator_fee_commitment: sample_hash("operator-fee"),
        net_reward_commitment: sample_hash("net-reward"),
        share_price_commitment: sample_hash("reward-share-price"),
        proof_root: sample_hash("reward-proof"),
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
    })?;
    state.attest(PqAttestationRequest {
        subject_id: vault_id.clone(),
        kind: AttestationKind::VaultAdmission,
        committee_id: "devnet-pq-vault-committee".to_string(),
        attested_root: state.vaults.get(&vault_id).expect("vault").root(),
        signature_root: sample_hash("vault-attestation-signature"),
        quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
    })?;
    state.attest(PqAttestationRequest {
        subject_id: reward_report_id.clone(),
        kind: AttestationKind::RewardReport,
        committee_id: "devnet-pq-vault-committee".to_string(),
        attested_root: state
            .reward_reports
            .get(&reward_report_id)
            .expect("reward report")
            .root(),
        signature_root: sample_hash("reward-attestation-signature"),
        quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
    })?;
    state.queue_withdrawal(WithdrawalSettlementRequest {
        vault_id: vault_id.clone(),
        share_token_id,
        queue_nullifier: sample_hash("withdrawal-nullifier"),
        claim_commitment: sample_hash("withdrawal-claim"),
        settlement_root: sample_hash("withdrawal-settlement"),
        xmr_payout_commitment: sample_hash("withdrawal-payout"),
        requested_share_amount: 25_000_000_000,
        min_payout_amount: 24_990_000_000,
        fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
    })?;
    state.accrue_rebate(RebateRequest {
        vault_id: vault_id.clone(),
        reward_report_id,
        recipient_commitment: sample_hash("rebate-recipient"),
        rebate_commitment: sample_hash("rebate-amount"),
        netting_root: sample_hash("rebate-netting"),
        rebate_bps: DEFAULT_REWARD_REBATE_BPS,
    })?;
    let budget_id = state.install_redaction_budget(
        "devnet-staked-xmr-operator".to_string(),
        vault_id.clone(),
        DEVNET_EPOCH,
        sample_hash("redaction-commitments"),
    )?;
    let summary_id = operator_summary_id("devnet-staked-xmr-operator", &vault_id, DEVNET_EPOCH);
    state.publish_operator_summary(OperatorSummary {
        operator_summary_id: summary_id,
        operator_id: "devnet-staked-xmr-operator".to_string(),
        vault_id,
        summary_epoch: DEVNET_EPOCH,
        public_tvl_bucket: 1_000_000,
        public_share_price_bucket: 1_000_004,
        public_queue_depth_bucket: 16,
        reward_apr_bps_bucket: 420,
        liquidity_mode: LiquidityMode::RewardNettingPreferred,
        attestation_root: sample_hash("summary-attestation"),
        redaction_budget_id: budget_id,
        published_height: DEVNET_HEIGHT,
    })?;
    Ok(state)
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:state_root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn vault_id(request: &VaultRequest) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:vault_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.operator_id),
            HashPart::Str(&request.vault_label),
            HashPart::Str(&request.reserve_commitment),
            HashPart::Str(&request.committee_root),
        ],
        32,
    )
}

pub fn share_token_id(request: &ShareTokenRequest) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:share_token_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.symbol),
            HashPart::Str(request.token_kind.as_str()),
            HashPart::Str(&request.supply_commitment),
        ],
        32,
    )
}

pub fn stake_epoch_id(request: &StakeEpochRequest) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:stake_epoch_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.vault_id),
            HashPart::U64(request.epoch_index),
            HashPart::Str(&request.stake_commitment),
            HashPart::Str(&request.reserve_proof_root),
        ],
        32,
    )
}

pub fn reward_report_id(request: &RewardReportRequest) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:reward_report_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.stake_epoch_id),
            HashPart::Str(&request.net_reward_commitment),
            HashPart::Str(&request.share_price_commitment),
        ],
        32,
    )
}

pub fn pq_attestation_id(request: &PqAttestationRequest) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:pq_attestation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.attested_root),
            HashPart::Str(&request.signature_root),
        ],
        32,
    )
}

pub fn withdrawal_settlement_id(request: &WithdrawalSettlementRequest) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:withdrawal_settlement_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.share_token_id),
            HashPart::Str(&request.queue_nullifier),
            HashPart::Str(&request.claim_commitment),
        ],
        32,
    )
}

pub fn rebate_id(request: &RebateRequest) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:rebate_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.reward_report_id),
            HashPart::Str(&request.recipient_commitment),
            HashPart::Str(&request.rebate_commitment),
        ],
        32,
    )
}

pub fn redaction_budget_id(operator_id: &str, vault_id: &str, summary_epoch: u64) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:redaction_budget_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(vault_id),
            HashPart::U64(summary_epoch),
        ],
        32,
    )
}

pub fn operator_summary_id(operator_id: &str, vault_id: &str, summary_epoch: u64) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:operator_summary_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(vault_id),
            HashPart::U64(summary_epoch),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:record_root",
        &[HashPart::Str(domain), HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_known_vault(state: &State, vault_id: &str) -> Result<()> {
    if state.vaults.contains_key(vault_id) {
        Ok(())
    } else {
        Err(format!("unknown vault: {vault_id}"))
    }
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be nonempty"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must be at least 16 characters"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(field: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        Err(format!("{field} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn sample_hash(label: &str) -> String {
    domain_hash(
        "private_l2_pq_confidential_tokenized_staked_xmr_vault:devnet_sample",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}
