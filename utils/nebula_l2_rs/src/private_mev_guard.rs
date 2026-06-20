use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateMevGuardResult<T> = Result<T, String>;

pub const PRIVATE_MEV_GUARD_PROTOCOL_VERSION: &str = "nebula-private-mev-guard-v1";
pub const PRIVATE_MEV_GUARD_THRESHOLD_ENCRYPTION_SCHEME: &str =
    "ML-KEM-1024+threshold-timelock-devnet";
pub const PRIVATE_MEV_GUARD_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PRIVATE_MEV_GUARD_COMMITMENT_SCHEME: &str = "SHAKE256-domain-v1";
pub const PRIVATE_MEV_GUARD_AUCTION_POLICY: &str =
    "encrypted-fair-batch-auction-uniform-clearing-v1";
pub const PRIVATE_MEV_GUARD_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_MEV_GUARD_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 1;
pub const PRIVATE_MEV_GUARD_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 3;
pub const PRIVATE_MEV_GUARD_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 12;
pub const PRIVATE_MEV_GUARD_DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_MEV_GUARD_DEFAULT_RECEIPT_DELAY_BLOCKS: u64 = 720;
pub const PRIVATE_MEV_GUARD_DEFAULT_LOW_FEE_TTL_BLOCKS: u64 = 144;
pub const PRIVATE_MEV_GUARD_DEFAULT_MAX_BUNDLE_BYTES: u64 = 192 * 1024;
pub const PRIVATE_MEV_GUARD_DEFAULT_MAX_BUNDLES_PER_EPOCH: u64 = 1_024;
pub const PRIVATE_MEV_GUARD_DEFAULT_MAX_SOLVERS_PER_EPOCH: u64 = 128;
pub const PRIVATE_MEV_GUARD_DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 100;
pub const PRIVATE_MEV_GUARD_DEFAULT_MIN_SURPLUS_REBATE_BPS: u64 = 7_000;
pub const PRIVATE_MEV_GUARD_DEFAULT_LOW_FEE_CEILING_MICRO_UNITS: u64 = 2_000;
pub const PRIVATE_MEV_GUARD_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_MEV_GUARD_MAX_BPS: u64 = 10_000;
pub const PRIVATE_MEV_GUARD_MAX_KEY_EPOCHS: usize = 64;
pub const PRIVATE_MEV_GUARD_MAX_BUNDLES: usize = 8_192;
pub const PRIVATE_MEV_GUARD_MAX_POLICIES: usize = 256;
pub const PRIVATE_MEV_GUARD_MAX_CONSTRAINTS: usize = 8_192;
pub const PRIVATE_MEV_GUARD_MAX_AUCTIONS: usize = 1_024;
pub const PRIVATE_MEV_GUARD_MAX_SOLVER_COMMITMENTS: usize = 4_096;
pub const PRIVATE_MEV_GUARD_MAX_REBATE_POOLS: usize = 256;
pub const PRIVATE_MEV_GUARD_MAX_REBATE_ENTRIES: usize = 8_192;
pub const PRIVATE_MEV_GUARD_MAX_LOW_FEE_LANES: usize = 128;
pub const PRIVATE_MEV_GUARD_MAX_FILLS: usize = 8_192;
pub const PRIVATE_MEV_GUARD_MAX_RECEIPTS: usize = 16_384;
pub const PRIVATE_MEV_GUARD_MAX_SLASHING_EVIDENCE: usize = 1_024;
pub const PRIVATE_MEV_GUARD_MAX_AUDIT_RECORDS: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateMevLaneKind {
    PrivateDex,
    ConfidentialLending,
    ConfidentialLiquidation,
    PrivateContract,
    LowFeeSwap,
    LowFeeLiquidation,
    BridgeProtection,
    Maintenance,
}

impl PrivateMevLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDex => "private_dex",
            Self::ConfidentialLending => "confidential_lending",
            Self::ConfidentialLiquidation => "confidential_liquidation",
            Self::PrivateContract => "private_contract",
            Self::LowFeeSwap => "low_fee_swap",
            Self::LowFeeLiquidation => "low_fee_liquidation",
            Self::BridgeProtection => "bridge_protection",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn fairness_priority(self) -> u64 {
        match self {
            Self::ConfidentialLiquidation => 0,
            Self::LowFeeLiquidation => 1,
            Self::BridgeProtection => 2,
            Self::LowFeeSwap => 3,
            Self::PrivateDex => 4,
            Self::ConfidentialLending => 5,
            Self::PrivateContract => 6,
            Self::Maintenance => 7,
        }
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::LowFeeSwap | Self::LowFeeLiquidation)
    }

    pub fn liquidation(self) -> bool {
        matches!(
            self,
            Self::ConfidentialLiquidation | Self::LowFeeLiquidation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateMevBundleKind {
    Swap,
    AddLiquidity,
    RemoveLiquidity,
    Borrow,
    Repay,
    Liquidation,
    ContractCall,
    BridgeExit,
}

impl PrivateMevBundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Liquidation => "liquidation",
            Self::ContractCall => "contract_call",
            Self::BridgeExit => "bridge_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateMevVenueKind {
    PrivateDex,
    ConfidentialAmm,
    ConfidentialLending,
    LiquidationAuction,
    PrivateContract,
    BridgeExit,
}

impl PrivateMevVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDex => "private_dex",
            Self::ConfidentialAmm => "confidential_amm",
            Self::ConfidentialLending => "confidential_lending",
            Self::LiquidationAuction => "liquidation_auction",
            Self::PrivateContract => "private_contract",
            Self::BridgeExit => "bridge_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdKeyEpochStatus {
    Pending,
    Active,
    Rotating,
    Retired,
    Slashed,
}

impl ThresholdKeyEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_bundles(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedBundleStatus {
    Submitted,
    Queued,
    Committed,
    Decrypting,
    Auctioned,
    Filled,
    Expired,
    Rejected,
}

impl EncryptedBundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Queued => "queued",
            Self::Committed => "committed",
            Self::Decrypting => "decrypting",
            Self::Auctioned => "auctioned",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Queued | Self::Committed | Self::Decrypting | Self::Auctioned
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiSandwichPolicyKind {
    UniformClearingPrice,
    BatchOnly,
    NoSameSolverBackrun,
    ProtectedLiquidation,
    LowFeeProtected,
}

impl AntiSandwichPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UniformClearingPrice => "uniform_clearing_price",
            Self::BatchOnly => "batch_only",
            Self::NoSameSolverBackrun => "no_same_solver_backrun",
            Self::ProtectedLiquidation => "protected_liquidation",
            Self::LowFeeProtected => "low_fee_protected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InclusionConstraintStatus {
    Pending,
    Bound,
    Satisfied,
    Expired,
    Challenged,
}

impl InclusionConstraintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Bound => "bound",
            Self::Satisfied => "satisfied",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairAuctionEpochStatus {
    Collecting,
    CommitLocked,
    Revealing,
    Solving,
    Sealed,
    Challenged,
    Finalized,
    Expired,
}

impl FairAuctionEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::CommitLocked => "commit_locked",
            Self::Revealing => "revealing",
            Self::Solving => "solving",
            Self::Sealed => "sealed",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Collecting | Self::CommitLocked | Self::Revealing | Self::Solving | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Committed,
    Opened,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl SolverCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Opened => "opened",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebatePoolStatus {
    Active,
    Draining,
    Exhausted,
    Paused,
    Closed,
}

impl RebatePoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }

    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateAccountingKind {
    Reserved,
    Paid,
    Released,
    Slashed,
    Sponsored,
}

impl RebateAccountingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Paid => "paid",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Sponsored => "sponsored",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeLaneStatus {
    Active,
    Saturated,
    Paused,
    Expired,
}

impl LowFeeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Paused => "paused",
            Self::Expired => "expired",
        }
    }

    pub fn accepts(self) -> bool {
        matches!(self, Self::Active | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillStatus {
    PendingProof,
    Proven,
    Settled,
    Disputed,
    Reverted,
}

impl FillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingProof => "pending_proof",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyReceiptAudience {
    Trader,
    Solver,
    Auditor,
    LiquidationKeeper,
    Protocol,
}

impl PrivacyReceiptAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trader => "trader",
            Self::Solver => "solver",
            Self::Auditor => "auditor",
            Self::LiquidationKeeper => "liquidation_keeper",
            Self::Protocol => "protocol",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyReceiptStatus {
    Committed,
    Releasable,
    Released,
    Revoked,
}

impl PrivacyReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Releasable => "releasable",
            Self::Released => "released",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    SolverEquivocation,
    SandwichViolation,
    InvalidOpening,
    WithheldReveal,
    RebateTheft,
    Censorship,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SolverEquivocation => "solver_equivocation",
            Self::SandwichViolation => "sandwich_violation",
            Self::InvalidOpening => "invalid_opening",
            Self::WithheldReveal => "withheld_reveal",
            Self::RebateTheft => "rebate_theft",
            Self::Censorship => "censorship",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Executed,
}

impl SlashingEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevGuardConfig {
    pub config_id: String,
    pub auction_window_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub reveal_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub receipt_delay_blocks: u64,
    pub low_fee_lane_ttl_blocks: u64,
    pub threshold_committee_size: u64,
    pub threshold_decryptions: u64,
    pub max_bundle_bytes: u64,
    pub max_bundles_per_epoch: u64,
    pub max_solvers_per_epoch: u64,
    pub max_price_impact_bps: u64,
    pub min_surplus_rebate_bps: u64,
    pub low_fee_ceiling_micro_units: u64,
    pub solver_slash_bps: u64,
    pub enable_private_dex: bool,
    pub enable_confidential_lending: bool,
    pub enable_private_liquidations: bool,
    pub enable_low_fee_lanes: bool,
    pub enable_delayed_receipts: bool,
}

impl Default for PrivateMevGuardConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            auction_window_blocks: PRIVATE_MEV_GUARD_DEFAULT_AUCTION_WINDOW_BLOCKS,
            reveal_delay_blocks: PRIVATE_MEV_GUARD_DEFAULT_REVEAL_DELAY_BLOCKS,
            reveal_window_blocks: PRIVATE_MEV_GUARD_DEFAULT_REVEAL_WINDOW_BLOCKS,
            challenge_window_blocks: PRIVATE_MEV_GUARD_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            bundle_ttl_blocks: PRIVATE_MEV_GUARD_DEFAULT_BUNDLE_TTL_BLOCKS,
            receipt_delay_blocks: PRIVATE_MEV_GUARD_DEFAULT_RECEIPT_DELAY_BLOCKS,
            low_fee_lane_ttl_blocks: PRIVATE_MEV_GUARD_DEFAULT_LOW_FEE_TTL_BLOCKS,
            threshold_committee_size: 4,
            threshold_decryptions: 3,
            max_bundle_bytes: PRIVATE_MEV_GUARD_DEFAULT_MAX_BUNDLE_BYTES,
            max_bundles_per_epoch: PRIVATE_MEV_GUARD_DEFAULT_MAX_BUNDLES_PER_EPOCH,
            max_solvers_per_epoch: PRIVATE_MEV_GUARD_DEFAULT_MAX_SOLVERS_PER_EPOCH,
            max_price_impact_bps: PRIVATE_MEV_GUARD_DEFAULT_MAX_PRICE_IMPACT_BPS,
            min_surplus_rebate_bps: PRIVATE_MEV_GUARD_DEFAULT_MIN_SURPLUS_REBATE_BPS,
            low_fee_ceiling_micro_units: PRIVATE_MEV_GUARD_DEFAULT_LOW_FEE_CEILING_MICRO_UNITS,
            solver_slash_bps: PRIVATE_MEV_GUARD_DEFAULT_SLASH_BPS,
            enable_private_dex: true,
            enable_confidential_lending: true,
            enable_private_liquidations: true,
            enable_low_fee_lanes: true,
            enable_delayed_receipts: true,
        };
        config.config_id = config.canonical_id();
        config
    }
}

impl PrivateMevGuardConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_config_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "auction_policy": PRIVATE_MEV_GUARD_AUCTION_POLICY,
            "auction_window_blocks": self.auction_window_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "receipt_delay_blocks": self.receipt_delay_blocks,
            "low_fee_lane_ttl_blocks": self.low_fee_lane_ttl_blocks,
            "threshold_committee_size": self.threshold_committee_size,
            "threshold_decryptions": self.threshold_decryptions,
            "max_bundle_bytes": self.max_bundle_bytes,
            "max_bundles_per_epoch": self.max_bundles_per_epoch,
            "max_solvers_per_epoch": self.max_solvers_per_epoch,
            "max_price_impact_bps": self.max_price_impact_bps,
            "min_surplus_rebate_bps": self.min_surplus_rebate_bps,
            "low_fee_ceiling_micro_units": self.low_fee_ceiling_micro_units,
            "solver_slash_bps": self.solver_slash_bps,
            "enable_private_dex": self.enable_private_dex,
            "enable_confidential_lending": self.enable_confidential_lending,
            "enable_private_liquidations": self.enable_private_liquidations,
            "enable_low_fee_lanes": self.enable_low_fee_lanes,
            "enable_delayed_receipts": self.enable_delayed_receipts,
        })
    }

    pub fn canonical_id(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-CONFIG-ID", &self.identity_record())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("private mev guard config record object")
            .insert(
                "config_id".to_string(),
                Value::String(self.config_id.clone()),
            );
        record
    }

    pub fn config_root(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.config_id, "private mev guard config id")?;
        if self.threshold_committee_size == 0 {
            return Err("private mev guard committee size cannot be zero".to_string());
        }
        if self.threshold_decryptions == 0 {
            return Err("private mev guard threshold decryptions cannot be zero".to_string());
        }
        if self.threshold_decryptions > self.threshold_committee_size {
            return Err(
                "private mev guard threshold decryptions exceed committee size".to_string(),
            );
        }
        if self.auction_window_blocks == 0 || self.reveal_window_blocks == 0 {
            return Err(
                "private mev guard auction and reveal windows must be positive".to_string(),
            );
        }
        if self.max_bundle_bytes == 0 {
            return Err("private mev guard max bundle bytes cannot be zero".to_string());
        }
        ensure_bps(
            self.max_price_impact_bps,
            "private mev guard max price impact bps",
        )?;
        ensure_bps(
            self.min_surplus_rebate_bps,
            "private mev guard min surplus rebate bps",
        )?;
        ensure_bps(self.solver_slash_bps, "private mev guard solver slash bps")?;
        if self.config_id != self.canonical_id() {
            return Err("private mev guard config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdEncryptionKeyEpoch {
    pub key_epoch_id: String,
    pub committee_id: String,
    pub aggregate_public_key_root: String,
    pub member_public_key_root: String,
    pub transcript_root: String,
    pub threshold: u64,
    pub committee_size: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub decrypt_delay_blocks: u64,
    pub status: ThresholdKeyEpochStatus,
}

impl ThresholdEncryptionKeyEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        committee_id: impl Into<String>,
        aggregate_public_key_root: impl Into<String>,
        member_labels: &[String],
        transcript: &Value,
        threshold: u64,
        starts_at_height: u64,
        expires_at_height: u64,
        decrypt_delay_blocks: u64,
    ) -> PrivateMevGuardResult<Self> {
        let committee_id = committee_id.into();
        let aggregate_public_key_root = aggregate_public_key_root.into();
        ensure_non_empty(&committee_id, "threshold key epoch committee id")?;
        ensure_non_empty(
            &aggregate_public_key_root,
            "threshold key epoch aggregate public key root",
        )?;
        if member_labels.is_empty() {
            return Err("threshold key epoch member labels cannot be empty".to_string());
        }
        if threshold == 0 || threshold > member_labels.len() as u64 {
            return Err("threshold key epoch threshold is invalid".to_string());
        }
        if expires_at_height <= starts_at_height {
            return Err("threshold key epoch expiry must be after start".to_string());
        }
        let member_public_key_root = private_mev_guard_string_list_root(
            "PRIVATE-MEV-GUARD-THRESHOLD-MEMBERS",
            member_labels,
        );
        let transcript_root =
            private_mev_guard_payload_root("threshold_key_transcript", transcript);
        let key_epoch_id = private_mev_guard_key_epoch_id(
            &committee_id,
            &aggregate_public_key_root,
            &member_public_key_root,
            threshold,
            starts_at_height,
        );
        let epoch = Self {
            key_epoch_id,
            committee_id,
            aggregate_public_key_root,
            member_public_key_root,
            transcript_root,
            threshold,
            committee_size: member_labels.len() as u64,
            starts_at_height,
            expires_at_height,
            decrypt_delay_blocks,
            status: ThresholdKeyEpochStatus::Active,
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepts_bundles()
            && height >= self.starts_at_height
            && height < self.expires_at_height
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_threshold_key_epoch_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "member_public_key_root": self.member_public_key_root,
            "transcript_root": self.transcript_root,
            "threshold": self.threshold,
            "committee_size": self.committee_size,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "decrypt_delay_blocks": self.decrypt_delay_blocks,
            "threshold_encryption_scheme": PRIVATE_MEV_GUARD_THRESHOLD_ENCRYPTION_SCHEME,
            "signature_scheme": PRIVATE_MEV_GUARD_SIGNATURE_SCHEME,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("threshold key epoch record object");
        object.insert(
            "key_epoch_id".to_string(),
            Value::String(self.key_epoch_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        record
    }

    pub fn epoch_root(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-KEY-EPOCH", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.key_epoch_id, "threshold key epoch id")?;
        ensure_non_empty(&self.committee_id, "threshold key epoch committee id")?;
        ensure_non_empty(
            &self.aggregate_public_key_root,
            "threshold key epoch aggregate public key root",
        )?;
        ensure_non_empty(
            &self.member_public_key_root,
            "threshold key epoch member public key root",
        )?;
        ensure_non_empty(&self.transcript_root, "threshold key epoch transcript root")?;
        if self.threshold == 0 || self.threshold > self.committee_size {
            return Err("threshold key epoch threshold is invalid".to_string());
        }
        if self.expires_at_height <= self.starts_at_height {
            return Err("threshold key epoch expiry must be after start".to_string());
        }
        let expected = private_mev_guard_key_epoch_id(
            &self.committee_id,
            &self.aggregate_public_key_root,
            &self.member_public_key_root,
            self.threshold,
            self.starts_at_height,
        );
        if self.key_epoch_id != expected {
            return Err("threshold key epoch id mismatch".to_string());
        }
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiSandwichPolicy {
    pub policy_id: String,
    pub policy_kind: AntiSandwichPolicyKind,
    pub protected_pair_commitment: String,
    pub min_batch_depth: u64,
    pub max_price_impact_bps: u64,
    pub max_solver_spread_bps: u64,
    pub min_surplus_rebate_bps: u64,
    pub require_uniform_clearing_price: bool,
    pub forbid_same_solver_pre_post: bool,
    pub forbid_backrun_profit_extraction: bool,
    pub require_solver_bond: bool,
    pub protected_lanes: Vec<PrivateMevLaneKind>,
    pub metadata_root: String,
}

impl AntiSandwichPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_kind: AntiSandwichPolicyKind,
        protected_pair_label: &str,
        min_batch_depth: u64,
        max_price_impact_bps: u64,
        max_solver_spread_bps: u64,
        min_surplus_rebate_bps: u64,
        protected_lanes: Vec<PrivateMevLaneKind>,
        metadata: &Value,
    ) -> PrivateMevGuardResult<Self> {
        ensure_non_empty(protected_pair_label, "anti sandwich protected pair label")?;
        if protected_lanes.is_empty() {
            return Err("anti sandwich policy must protect at least one lane".to_string());
        }
        ensure_bps(max_price_impact_bps, "anti sandwich max price impact bps")?;
        ensure_bps(max_solver_spread_bps, "anti sandwich max solver spread bps")?;
        ensure_bps(
            min_surplus_rebate_bps,
            "anti sandwich min surplus rebate bps",
        )?;
        let protected_pair_commitment =
            private_mev_guard_string_commitment("protected_pair", protected_pair_label);
        let metadata_root = private_mev_guard_payload_root("anti_sandwich_policy", metadata);
        let lane_root = private_mev_guard_lane_root(&protected_lanes);
        let policy_id = private_mev_guard_anti_sandwich_policy_id(
            policy_kind,
            &protected_pair_commitment,
            min_batch_depth,
            max_price_impact_bps,
            min_surplus_rebate_bps,
            &lane_root,
        );
        let policy = Self {
            policy_id,
            policy_kind,
            protected_pair_commitment,
            min_batch_depth,
            max_price_impact_bps,
            max_solver_spread_bps,
            min_surplus_rebate_bps,
            require_uniform_clearing_price: true,
            forbid_same_solver_pre_post: true,
            forbid_backrun_profit_extraction: true,
            require_solver_bond: true,
            protected_lanes,
            metadata_root,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn protects_lane(&self, lane: PrivateMevLaneKind) -> bool {
        self.protected_lanes
            .iter()
            .any(|protected| *protected == lane)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_anti_sandwich_policy_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "policy_kind": self.policy_kind.as_str(),
            "protected_pair_commitment": self.protected_pair_commitment,
            "min_batch_depth": self.min_batch_depth,
            "max_price_impact_bps": self.max_price_impact_bps,
            "max_solver_spread_bps": self.max_solver_spread_bps,
            "min_surplus_rebate_bps": self.min_surplus_rebate_bps,
            "require_uniform_clearing_price": self.require_uniform_clearing_price,
            "forbid_same_solver_pre_post": self.forbid_same_solver_pre_post,
            "forbid_backrun_profit_extraction": self.forbid_backrun_profit_extraction,
            "require_solver_bond": self.require_solver_bond,
            "protected_lane_root": private_mev_guard_lane_root(&self.protected_lanes),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("anti sandwich policy record object");
        object.insert(
            "policy_id".to_string(),
            Value::String(self.policy_id.clone()),
        );
        object.insert(
            "protected_lanes".to_string(),
            json!(self
                .protected_lanes
                .iter()
                .map(|lane| lane.as_str())
                .collect::<Vec<_>>()),
        );
        record
    }

    pub fn policy_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-ANTI-SANDWICH-POLICY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.policy_id, "anti sandwich policy id")?;
        ensure_non_empty(
            &self.protected_pair_commitment,
            "anti sandwich protected pair commitment",
        )?;
        if self.protected_lanes.is_empty() {
            return Err("anti sandwich policy protected lanes cannot be empty".to_string());
        }
        ensure_bps(
            self.max_price_impact_bps,
            "anti sandwich max price impact bps",
        )?;
        ensure_bps(
            self.max_solver_spread_bps,
            "anti sandwich solver spread bps",
        )?;
        ensure_bps(
            self.min_surplus_rebate_bps,
            "anti sandwich min surplus rebate bps",
        )?;
        let expected = private_mev_guard_anti_sandwich_policy_id(
            self.policy_kind,
            &self.protected_pair_commitment,
            self.min_batch_depth,
            self.max_price_impact_bps,
            self.min_surplus_rebate_bps,
            &private_mev_guard_lane_root(&self.protected_lanes),
        );
        if self.policy_id != expected {
            return Err("anti sandwich policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOrderBundle {
    pub bundle_id: String,
    pub bundle_kind: PrivateMevBundleKind,
    pub lane_kind: PrivateMevLaneKind,
    pub owner_commitment: String,
    pub strategy_commitment: String,
    pub market_pair_commitment: String,
    pub encrypted_payload_root: String,
    pub payload_size_bytes: u64,
    pub threshold_key_epoch_id: String,
    pub anti_sandwich_policy_id: String,
    pub inclusion_constraint_id: Option<String>,
    pub low_fee_lane_id: Option<String>,
    pub lending_position_commitment: Option<String>,
    pub liquidation_account_commitment: Option<String>,
    pub max_fee_micro_units: u64,
    pub max_price_impact_bps: u64,
    pub deadline_height: u64,
    pub submitted_at_height: u64,
    pub nonce: u64,
    pub replay_nullifier: String,
    pub status: EncryptedBundleStatus,
}

impl EncryptedOrderBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_kind: PrivateMevBundleKind,
        lane_kind: PrivateMevLaneKind,
        owner_label: &str,
        strategy_label: &str,
        market_pair_label: &str,
        encrypted_payload: &Value,
        payload_size_bytes: u64,
        threshold_key_epoch_id: impl Into<String>,
        anti_sandwich_policy_id: impl Into<String>,
        low_fee_lane_id: Option<String>,
        lending_position_label: Option<&str>,
        liquidation_account_label: Option<&str>,
        max_fee_micro_units: u64,
        max_price_impact_bps: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> PrivateMevGuardResult<Self> {
        ensure_non_empty(owner_label, "encrypted bundle owner label")?;
        ensure_non_empty(strategy_label, "encrypted bundle strategy label")?;
        ensure_non_empty(market_pair_label, "encrypted bundle market pair label")?;
        if payload_size_bytes == 0 {
            return Err("encrypted bundle payload size cannot be zero".to_string());
        }
        if ttl_blocks == 0 {
            return Err("encrypted bundle ttl cannot be zero".to_string());
        }
        ensure_bps(
            max_price_impact_bps,
            "encrypted bundle max price impact bps",
        )?;
        let threshold_key_epoch_id = threshold_key_epoch_id.into();
        let anti_sandwich_policy_id = anti_sandwich_policy_id.into();
        ensure_non_empty(
            &threshold_key_epoch_id,
            "encrypted bundle threshold key epoch id",
        )?;
        ensure_non_empty(
            &anti_sandwich_policy_id,
            "encrypted bundle anti sandwich policy id",
        )?;
        let owner_commitment = private_mev_guard_string_commitment("bundle_owner", owner_label);
        let strategy_commitment =
            private_mev_guard_string_commitment("bundle_strategy", strategy_label);
        let market_pair_commitment =
            private_mev_guard_string_commitment("market_pair", market_pair_label);
        let encrypted_payload_root =
            private_mev_guard_payload_root("encrypted_order_bundle", encrypted_payload);
        let lending_position_commitment = lending_position_label
            .map(|label| private_mev_guard_string_commitment("lending_position", label));
        let liquidation_account_commitment = liquidation_account_label
            .map(|label| private_mev_guard_string_commitment("liquidation_account", label));
        let deadline_height = submitted_at_height
            .checked_add(ttl_blocks)
            .ok_or_else(|| "encrypted bundle deadline overflow".to_string())?;
        let replay_nullifier = private_mev_guard_replay_nullifier(
            &owner_commitment,
            &strategy_commitment,
            submitted_at_height,
            nonce,
        );
        let bundle_id = private_mev_guard_bundle_id(
            bundle_kind,
            lane_kind,
            &owner_commitment,
            &market_pair_commitment,
            &encrypted_payload_root,
            deadline_height,
            nonce,
        );
        let bundle = Self {
            bundle_id,
            bundle_kind,
            lane_kind,
            owner_commitment,
            strategy_commitment,
            market_pair_commitment,
            encrypted_payload_root,
            payload_size_bytes,
            threshold_key_epoch_id,
            anti_sandwich_policy_id,
            inclusion_constraint_id: None,
            low_fee_lane_id,
            lending_position_commitment,
            liquidation_account_commitment,
            max_fee_micro_units,
            max_price_impact_bps,
            deadline_height,
            submitted_at_height,
            nonce,
            replay_nullifier,
            status: EncryptedBundleStatus::Submitted,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.deadline_height && self.status.active()
    }

    pub fn ordering_key(&self, seed: &str) -> String {
        domain_hash(
            "PRIVATE-MEV-GUARD-BUNDLE-ORDERING-KEY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(&self.bundle_id),
                HashPart::Int(self.lane_kind.fairness_priority() as i128),
                HashPart::Int(self.submitted_at_height as i128),
            ],
            32,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_encrypted_order_bundle_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "bundle_kind": self.bundle_kind.as_str(),
            "lane_kind": self.lane_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "strategy_commitment": self.strategy_commitment,
            "market_pair_commitment": self.market_pair_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "payload_size_bytes": self.payload_size_bytes,
            "threshold_key_epoch_id": self.threshold_key_epoch_id,
            "anti_sandwich_policy_id": self.anti_sandwich_policy_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "lending_position_commitment": self.lending_position_commitment,
            "liquidation_account_commitment": self.liquidation_account_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_price_impact_bps": self.max_price_impact_bps,
            "deadline_height": self.deadline_height,
            "submitted_at_height": self.submitted_at_height,
            "nonce": self.nonce,
            "replay_nullifier": self.replay_nullifier,
            "encryption_scheme": PRIVATE_MEV_GUARD_THRESHOLD_ENCRYPTION_SCHEME,
            "commitment_scheme": PRIVATE_MEV_GUARD_COMMITMENT_SCHEME,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("encrypted order bundle record object");
        object.insert(
            "bundle_id".to_string(),
            Value::String(self.bundle_id.clone()),
        );
        object.insert(
            "inclusion_constraint_id".to_string(),
            json!(self.inclusion_constraint_id),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        record
    }

    pub fn bundle_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-ENCRYPTED-ORDER-BUNDLE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.bundle_id, "encrypted bundle id")?;
        ensure_non_empty(&self.owner_commitment, "encrypted bundle owner commitment")?;
        ensure_non_empty(
            &self.strategy_commitment,
            "encrypted bundle strategy commitment",
        )?;
        ensure_non_empty(
            &self.market_pair_commitment,
            "encrypted bundle market pair commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "encrypted bundle payload root",
        )?;
        ensure_non_empty(
            &self.threshold_key_epoch_id,
            "encrypted bundle threshold key epoch id",
        )?;
        ensure_non_empty(
            &self.anti_sandwich_policy_id,
            "encrypted bundle anti sandwich policy id",
        )?;
        ensure_non_empty(&self.replay_nullifier, "encrypted bundle replay nullifier")?;
        if self.payload_size_bytes == 0 {
            return Err("encrypted bundle payload size cannot be zero".to_string());
        }
        if self.deadline_height <= self.submitted_at_height {
            return Err("encrypted bundle deadline must be after submission".to_string());
        }
        ensure_bps(
            self.max_price_impact_bps,
            "encrypted bundle max price impact bps",
        )?;
        let expected_id = private_mev_guard_bundle_id(
            self.bundle_kind,
            self.lane_kind,
            &self.owner_commitment,
            &self.market_pair_commitment,
            &self.encrypted_payload_root,
            self.deadline_height,
            self.nonce,
        );
        if self.bundle_id != expected_id {
            return Err("encrypted bundle id mismatch".to_string());
        }
        let expected_nullifier = private_mev_guard_replay_nullifier(
            &self.owner_commitment,
            &self.strategy_commitment,
            self.submitted_at_height,
            self.nonce,
        );
        if self.replay_nullifier != expected_nullifier {
            return Err("encrypted bundle replay nullifier mismatch".to_string());
        }
        Ok(self.bundle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionConstraint {
    pub constraint_id: String,
    pub bundle_id: String,
    pub lane_kind: PrivateMevLaneKind,
    pub min_inclusion_height: u64,
    pub max_inclusion_height: u64,
    pub fair_queue_position: u64,
    pub max_delay_blocks: u64,
    pub force_include_after_height: Option<u64>,
    pub censorship_ticket_hash: Option<String>,
    pub max_fee_micro_units: u64,
    pub privacy_budget_units: u64,
    pub allowed_solver_root: String,
    pub status: InclusionConstraintStatus,
}

impl InclusionConstraint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        lane_kind: PrivateMevLaneKind,
        min_inclusion_height: u64,
        max_inclusion_height: u64,
        fair_queue_position: u64,
        max_delay_blocks: u64,
        force_include_after_height: Option<u64>,
        censorship_ticket_hash: Option<String>,
        max_fee_micro_units: u64,
        privacy_budget_units: u64,
        allowed_solver_labels: &[String],
    ) -> PrivateMevGuardResult<Self> {
        let bundle_id = bundle_id.into();
        ensure_non_empty(&bundle_id, "inclusion constraint bundle id")?;
        if max_inclusion_height < min_inclusion_height {
            return Err("inclusion max height cannot be before min height".to_string());
        }
        if let Some(force_height) = force_include_after_height {
            if force_height > max_inclusion_height {
                return Err(
                    "inclusion force height cannot be after max inclusion height".to_string(),
                );
            }
        }
        let allowed_solver_root = private_mev_guard_string_list_root(
            "PRIVATE-MEV-GUARD-ALLOWED-SOLVERS",
            allowed_solver_labels,
        );
        let constraint_id = private_mev_guard_inclusion_constraint_id(
            &bundle_id,
            lane_kind,
            min_inclusion_height,
            max_inclusion_height,
            fair_queue_position,
        );
        let constraint = Self {
            constraint_id,
            bundle_id,
            lane_kind,
            min_inclusion_height,
            max_inclusion_height,
            fair_queue_position,
            max_delay_blocks,
            force_include_after_height,
            censorship_ticket_hash,
            max_fee_micro_units,
            privacy_budget_units,
            allowed_solver_root,
            status: InclusionConstraintStatus::Pending,
        };
        constraint.validate()?;
        Ok(constraint)
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.min_inclusion_height && height <= self.max_inclusion_height
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_inclusion_constraint_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "lane_kind": self.lane_kind.as_str(),
            "min_inclusion_height": self.min_inclusion_height,
            "max_inclusion_height": self.max_inclusion_height,
            "fair_queue_position": self.fair_queue_position,
            "max_delay_blocks": self.max_delay_blocks,
            "force_include_after_height": self.force_include_after_height,
            "censorship_ticket_hash": self.censorship_ticket_hash,
            "max_fee_micro_units": self.max_fee_micro_units,
            "privacy_budget_units": self.privacy_budget_units,
            "allowed_solver_root": self.allowed_solver_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("inclusion constraint record object");
        object.insert(
            "constraint_id".to_string(),
            Value::String(self.constraint_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        record
    }

    pub fn constraint_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-INCLUSION-CONSTRAINT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.constraint_id, "inclusion constraint id")?;
        ensure_non_empty(&self.bundle_id, "inclusion constraint bundle id")?;
        ensure_non_empty(
            &self.allowed_solver_root,
            "inclusion constraint allowed solver root",
        )?;
        if self.max_inclusion_height < self.min_inclusion_height {
            return Err("inclusion max height cannot be before min height".to_string());
        }
        if let Some(force_height) = self.force_include_after_height {
            if force_height > self.max_inclusion_height {
                return Err(
                    "inclusion force height cannot be after max inclusion height".to_string(),
                );
            }
        }
        let expected = private_mev_guard_inclusion_constraint_id(
            &self.bundle_id,
            self.lane_kind,
            self.min_inclusion_height,
            self.max_inclusion_height,
            self.fair_queue_position,
        );
        if self.constraint_id != expected {
            return Err("inclusion constraint id mismatch".to_string());
        }
        Ok(self.constraint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairBatchAuctionEpoch {
    pub epoch_id: String,
    pub sequence: u64,
    pub venue_kind: PrivateMevVenueKind,
    pub market_pair_commitment: String,
    pub bundle_root: String,
    pub anti_sandwich_policy_root: String,
    pub inclusion_constraint_root: String,
    pub solver_commitment_root: String,
    pub solver_opening_root: String,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_start_height: u64,
    pub reveal_end_height: u64,
    pub challenge_deadline_height: u64,
    pub min_batch_size: u64,
    pub max_batch_size: u64,
    pub ordering_seed: String,
    pub clearing_price_commitment: String,
    pub uniform_clearing_price: bool,
    pub status: FairAuctionEpochStatus,
}

impl FairBatchAuctionEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        venue_kind: PrivateMevVenueKind,
        market_pair_label: &str,
        bundle_root: impl Into<String>,
        anti_sandwich_policy_root: impl Into<String>,
        inclusion_constraint_root: impl Into<String>,
        commit_start_height: u64,
        auction_window_blocks: u64,
        reveal_delay_blocks: u64,
        reveal_window_blocks: u64,
        challenge_window_blocks: u64,
        min_batch_size: u64,
        max_batch_size: u64,
    ) -> PrivateMevGuardResult<Self> {
        ensure_non_empty(market_pair_label, "fair auction market pair label")?;
        if auction_window_blocks == 0 || reveal_window_blocks == 0 {
            return Err("fair auction windows must be positive".to_string());
        }
        if min_batch_size == 0 || max_batch_size < min_batch_size {
            return Err("fair auction batch bounds are invalid".to_string());
        }
        let market_pair_commitment =
            private_mev_guard_string_commitment("market_pair", market_pair_label);
        let bundle_root = bundle_root.into();
        let anti_sandwich_policy_root = anti_sandwich_policy_root.into();
        let inclusion_constraint_root = inclusion_constraint_root.into();
        ensure_non_empty(&bundle_root, "fair auction bundle root")?;
        ensure_non_empty(
            &anti_sandwich_policy_root,
            "fair auction anti sandwich policy root",
        )?;
        ensure_non_empty(
            &inclusion_constraint_root,
            "fair auction inclusion constraint root",
        )?;
        let commit_end_height = commit_start_height
            .checked_add(auction_window_blocks)
            .ok_or_else(|| "fair auction commit end overflow".to_string())?;
        let reveal_start_height = commit_end_height
            .checked_add(reveal_delay_blocks)
            .ok_or_else(|| "fair auction reveal start overflow".to_string())?;
        let reveal_end_height = reveal_start_height
            .checked_add(reveal_window_blocks)
            .ok_or_else(|| "fair auction reveal end overflow".to_string())?;
        let challenge_deadline_height = reveal_end_height
            .checked_add(challenge_window_blocks)
            .ok_or_else(|| "fair auction challenge deadline overflow".to_string())?;
        let ordering_seed = private_mev_guard_ordering_seed(
            venue_kind,
            &market_pair_commitment,
            sequence,
            &bundle_root,
        );
        let clearing_price_commitment =
            private_mev_guard_string_commitment("empty_clearing_price", &ordering_seed);
        let epoch_id = private_mev_guard_auction_epoch_id(
            sequence,
            venue_kind,
            &market_pair_commitment,
            &bundle_root,
            commit_start_height,
        );
        let epoch = Self {
            epoch_id,
            sequence,
            venue_kind,
            market_pair_commitment,
            bundle_root,
            anti_sandwich_policy_root,
            inclusion_constraint_root,
            solver_commitment_root: private_mev_guard_empty_root("solver_commitments"),
            solver_opening_root: private_mev_guard_empty_root("solver_openings"),
            commit_start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            challenge_deadline_height,
            min_batch_size,
            max_batch_size,
            ordering_seed,
            clearing_price_commitment,
            uniform_clearing_price: true,
            status: FairAuctionEpochStatus::Collecting,
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn commit_active_at(&self, height: u64) -> bool {
        height >= self.commit_start_height && height <= self.commit_end_height
    }

    pub fn reveal_active_at(&self, height: u64) -> bool {
        height >= self.reveal_start_height && height <= self.reveal_end_height
    }

    pub fn challenge_active_at(&self, height: u64) -> bool {
        height > self.reveal_end_height && height <= self.challenge_deadline_height
    }

    pub fn seal(
        &mut self,
        solver_commitment_root: impl Into<String>,
        solver_opening_root: impl Into<String>,
        clearing_price_commitment: impl Into<String>,
    ) -> PrivateMevGuardResult<String> {
        self.solver_commitment_root = solver_commitment_root.into();
        self.solver_opening_root = solver_opening_root.into();
        self.clearing_price_commitment = clearing_price_commitment.into();
        ensure_non_empty(
            &self.solver_commitment_root,
            "fair auction solver commitment root",
        )?;
        ensure_non_empty(
            &self.solver_opening_root,
            "fair auction solver opening root",
        )?;
        ensure_non_empty(
            &self.clearing_price_commitment,
            "fair auction clearing price commitment",
        )?;
        self.status = FairAuctionEpochStatus::Sealed;
        self.validate()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_fair_batch_auction_epoch_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "auction_policy": PRIVATE_MEV_GUARD_AUCTION_POLICY,
            "sequence": self.sequence,
            "venue_kind": self.venue_kind.as_str(),
            "market_pair_commitment": self.market_pair_commitment,
            "bundle_root": self.bundle_root,
            "anti_sandwich_policy_root": self.anti_sandwich_policy_root,
            "inclusion_constraint_root": self.inclusion_constraint_root,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_end_height": self.reveal_end_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "min_batch_size": self.min_batch_size,
            "max_batch_size": self.max_batch_size,
            "ordering_seed": self.ordering_seed,
            "uniform_clearing_price": self.uniform_clearing_price,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("fair batch auction epoch record object");
        object.insert("epoch_id".to_string(), Value::String(self.epoch_id.clone()));
        object.insert(
            "solver_commitment_root".to_string(),
            Value::String(self.solver_commitment_root.clone()),
        );
        object.insert(
            "solver_opening_root".to_string(),
            Value::String(self.solver_opening_root.clone()),
        );
        object.insert(
            "clearing_price_commitment".to_string(),
            Value::String(self.clearing_price_commitment.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        record
    }

    pub fn epoch_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-FAIR-BATCH-AUCTION-EPOCH",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.epoch_id, "fair auction epoch id")?;
        ensure_non_empty(
            &self.market_pair_commitment,
            "fair auction market pair commitment",
        )?;
        ensure_non_empty(&self.bundle_root, "fair auction bundle root")?;
        ensure_non_empty(
            &self.anti_sandwich_policy_root,
            "fair auction anti sandwich policy root",
        )?;
        ensure_non_empty(
            &self.inclusion_constraint_root,
            "fair auction inclusion constraint root",
        )?;
        ensure_non_empty(
            &self.solver_commitment_root,
            "fair auction solver commitment root",
        )?;
        ensure_non_empty(
            &self.solver_opening_root,
            "fair auction solver opening root",
        )?;
        ensure_non_empty(&self.ordering_seed, "fair auction ordering seed")?;
        ensure_non_empty(
            &self.clearing_price_commitment,
            "fair auction clearing price commitment",
        )?;
        if self.commit_end_height <= self.commit_start_height {
            return Err("fair auction commit end must be after start".to_string());
        }
        if self.reveal_start_height < self.commit_end_height {
            return Err("fair auction reveal start cannot be before commit end".to_string());
        }
        if self.reveal_end_height <= self.reveal_start_height {
            return Err("fair auction reveal end must be after reveal start".to_string());
        }
        if self.challenge_deadline_height <= self.reveal_end_height {
            return Err("fair auction challenge deadline must be after reveal end".to_string());
        }
        if self.min_batch_size == 0 || self.max_batch_size < self.min_batch_size {
            return Err("fair auction batch bounds are invalid".to_string());
        }
        let expected = private_mev_guard_auction_epoch_id(
            self.sequence,
            self.venue_kind,
            &self.market_pair_commitment,
            &self.bundle_root,
            self.commit_start_height,
        );
        if self.epoch_id != expected {
            return Err("fair auction epoch id mismatch".to_string());
        }
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSolverCommitment {
    pub commitment_id: String,
    pub epoch_id: String,
    pub solver_commitment: String,
    pub solver_public_key_root: String,
    pub encrypted_solution_root: String,
    pub route_commitment_root: String,
    pub bundle_set_root: String,
    pub price_vector_commitment: String,
    pub surplus_commitment: String,
    pub rebate_commitment: String,
    pub bond_units: u64,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub status: SolverCommitmentStatus,
}

impl PrivateSolverCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: impl Into<String>,
        solver_label: &str,
        solver_public_key: &str,
        encrypted_solution: &Value,
        route_commitments: &[String],
        bundle_ids: &[String],
        price_vector_label: &str,
        surplus_label: &str,
        rebate_label: &str,
        bond_units: u64,
        committed_at_height: u64,
        reveal_deadline_height: u64,
    ) -> PrivateMevGuardResult<Self> {
        let epoch_id = epoch_id.into();
        ensure_non_empty(&epoch_id, "solver commitment epoch id")?;
        ensure_non_empty(solver_label, "solver commitment solver label")?;
        ensure_non_empty(solver_public_key, "solver commitment public key")?;
        ensure_non_empty(price_vector_label, "solver commitment price vector label")?;
        ensure_non_empty(surplus_label, "solver commitment surplus label")?;
        ensure_non_empty(rebate_label, "solver commitment rebate label")?;
        if bond_units == 0 {
            return Err("solver commitment bond must be positive".to_string());
        }
        if reveal_deadline_height <= committed_at_height {
            return Err("solver commitment reveal deadline must be after commit".to_string());
        }
        let solver_commitment = private_mev_guard_string_commitment("solver", solver_label);
        let solver_public_key_root =
            private_mev_guard_string_commitment("solver_public_key", solver_public_key);
        let encrypted_solution_root =
            private_mev_guard_payload_root("solver_encrypted_solution", encrypted_solution);
        let route_commitment_root = private_mev_guard_string_list_root(
            "PRIVATE-MEV-GUARD-SOLVER-ROUTES",
            route_commitments,
        );
        let bundle_set_root =
            private_mev_guard_string_list_root("PRIVATE-MEV-GUARD-SOLVER-BUNDLES", bundle_ids);
        let price_vector_commitment =
            private_mev_guard_string_commitment("price_vector", price_vector_label);
        let surplus_commitment =
            private_mev_guard_string_commitment("solver_surplus", surplus_label);
        let rebate_commitment = private_mev_guard_string_commitment("solver_rebate", rebate_label);
        let commitment_id = private_mev_guard_solver_commitment_id(
            &epoch_id,
            &solver_commitment,
            &encrypted_solution_root,
            &bundle_set_root,
            committed_at_height,
        );
        let commitment = Self {
            commitment_id,
            epoch_id,
            solver_commitment,
            solver_public_key_root,
            encrypted_solution_root,
            route_commitment_root,
            bundle_set_root,
            price_vector_commitment,
            surplus_commitment,
            rebate_commitment,
            bond_units,
            committed_at_height,
            reveal_deadline_height,
            status: SolverCommitmentStatus::Committed,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_solver_commitment_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "solver_commitment": self.solver_commitment,
            "solver_public_key_root": self.solver_public_key_root,
            "encrypted_solution_root": self.encrypted_solution_root,
            "route_commitment_root": self.route_commitment_root,
            "bundle_set_root": self.bundle_set_root,
            "price_vector_commitment": self.price_vector_commitment,
            "surplus_commitment": self.surplus_commitment,
            "rebate_commitment": self.rebate_commitment,
            "bond_units": self.bond_units,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "signature_scheme": PRIVATE_MEV_GUARD_SIGNATURE_SCHEME,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("solver commitment record object");
        object.insert(
            "commitment_id".to_string(),
            Value::String(self.commitment_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        record
    }

    pub fn commitment_root(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-SOLVER-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.commitment_id, "solver commitment id")?;
        ensure_non_empty(&self.epoch_id, "solver commitment epoch id")?;
        ensure_non_empty(
            &self.solver_commitment,
            "solver commitment solver commitment",
        )?;
        ensure_non_empty(
            &self.solver_public_key_root,
            "solver commitment public key root",
        )?;
        ensure_non_empty(
            &self.encrypted_solution_root,
            "solver commitment encrypted solution root",
        )?;
        ensure_non_empty(&self.bundle_set_root, "solver commitment bundle set root")?;
        if self.bond_units == 0 {
            return Err("solver commitment bond must be positive".to_string());
        }
        if self.reveal_deadline_height <= self.committed_at_height {
            return Err("solver commitment reveal deadline must be after commit".to_string());
        }
        let expected = private_mev_guard_solver_commitment_id(
            &self.epoch_id,
            &self.solver_commitment,
            &self.encrypted_solution_root,
            &self.bundle_set_root,
            self.committed_at_height,
        );
        if self.commitment_id != expected {
            return Err("solver commitment id mismatch".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSolverOpening {
    pub opening_id: String,
    pub commitment_id: String,
    pub epoch_id: String,
    pub solver_commitment: String,
    pub execution_plan_root: String,
    pub constraint_satisfaction_root: String,
    pub clearing_price_root: String,
    pub surplus_root: String,
    pub rebate_root: String,
    pub opened_at_height: u64,
    pub accepted: bool,
}

impl PrivateSolverOpening {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment: &PrivateSolverCommitment,
        execution_plan: &Value,
        constraint_satisfaction: &Value,
        clearing_price: &Value,
        surplus: &Value,
        rebate: &Value,
        opened_at_height: u64,
        accepted: bool,
    ) -> PrivateMevGuardResult<Self> {
        commitment.validate()?;
        if opened_at_height > commitment.reveal_deadline_height {
            return Err("solver opening is after reveal deadline".to_string());
        }
        let execution_plan_root =
            private_mev_guard_payload_root("solver_execution_plan", execution_plan);
        let constraint_satisfaction_root = private_mev_guard_payload_root(
            "solver_constraint_satisfaction",
            constraint_satisfaction,
        );
        let clearing_price_root =
            private_mev_guard_payload_root("solver_clearing_price", clearing_price);
        let surplus_root = private_mev_guard_payload_root("solver_surplus_opening", surplus);
        let rebate_root = private_mev_guard_payload_root("solver_rebate_opening", rebate);
        let opening_id = private_mev_guard_solver_opening_id(
            &commitment.commitment_id,
            &commitment.epoch_id,
            &execution_plan_root,
            opened_at_height,
        );
        let opening = Self {
            opening_id,
            commitment_id: commitment.commitment_id.clone(),
            epoch_id: commitment.epoch_id.clone(),
            solver_commitment: commitment.solver_commitment.clone(),
            execution_plan_root,
            constraint_satisfaction_root,
            clearing_price_root,
            surplus_root,
            rebate_root,
            opened_at_height,
            accepted,
        };
        opening.validate()?;
        Ok(opening)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_solver_opening",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "opening_id": self.opening_id,
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "solver_commitment": self.solver_commitment,
            "execution_plan_root": self.execution_plan_root,
            "constraint_satisfaction_root": self.constraint_satisfaction_root,
            "clearing_price_root": self.clearing_price_root,
            "surplus_root": self.surplus_root,
            "rebate_root": self.rebate_root,
            "opened_at_height": self.opened_at_height,
            "accepted": self.accepted,
        })
    }

    pub fn opening_root(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-SOLVER-OPENING", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.opening_id, "solver opening id")?;
        ensure_non_empty(&self.commitment_id, "solver opening commitment id")?;
        ensure_non_empty(&self.epoch_id, "solver opening epoch id")?;
        ensure_non_empty(&self.solver_commitment, "solver opening solver commitment")?;
        ensure_non_empty(
            &self.execution_plan_root,
            "solver opening execution plan root",
        )?;
        ensure_non_empty(
            &self.constraint_satisfaction_root,
            "solver opening constraint satisfaction root",
        )?;
        let expected = private_mev_guard_solver_opening_id(
            &self.commitment_id,
            &self.epoch_id,
            &self.execution_plan_root,
            self.opened_at_height,
        );
        if self.opening_id != expected {
            return Err("solver opening id mismatch".to_string());
        }
        Ok(self.opening_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebatePool {
    pub pool_id: String,
    pub lane_kind: PrivateMevLaneKind,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub asset_commitment: String,
    pub opening_balance_units: u64,
    pub available_units: u64,
    pub reserved_units: u64,
    pub paid_units: u64,
    pub slashed_units: u64,
    pub max_rebate_bps: u64,
    pub max_per_bundle_units: u64,
    pub fee_floor_micro_units: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub status: RebatePoolStatus,
}

impl RebatePool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: PrivateMevLaneKind,
        sponsor_label: &str,
        asset_id: impl Into<String>,
        opening_balance_units: u64,
        max_rebate_bps: u64,
        max_per_bundle_units: u64,
        fee_floor_micro_units: u64,
        starts_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateMevGuardResult<Self> {
        ensure_non_empty(sponsor_label, "rebate pool sponsor label")?;
        let asset_id = asset_id.into();
        ensure_non_empty(&asset_id, "rebate pool asset id")?;
        if opening_balance_units == 0 {
            return Err("rebate pool opening balance must be positive".to_string());
        }
        if max_per_bundle_units == 0 {
            return Err("rebate pool max per bundle must be positive".to_string());
        }
        ensure_bps(max_rebate_bps, "rebate pool max rebate bps")?;
        let sponsor_commitment =
            private_mev_guard_string_commitment("rebate_sponsor", sponsor_label);
        let asset_commitment = private_mev_guard_string_commitment("rebate_asset", &asset_id);
        let expires_at_height = starts_at_height
            .checked_add(ttl_blocks)
            .ok_or_else(|| "rebate pool expiry overflow".to_string())?;
        let pool_id = private_mev_guard_rebate_pool_id(
            lane_kind,
            &sponsor_commitment,
            &asset_commitment,
            starts_at_height,
        );
        let pool = Self {
            pool_id,
            lane_kind,
            sponsor_commitment,
            asset_id,
            asset_commitment,
            opening_balance_units,
            available_units: opening_balance_units,
            reserved_units: 0,
            paid_units: 0,
            slashed_units: 0,
            max_rebate_bps,
            max_per_bundle_units,
            fee_floor_micro_units,
            starts_at_height,
            expires_at_height,
            status: RebatePoolStatus::Active,
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.can_reserve()
            && height >= self.starts_at_height
            && height < self.expires_at_height
    }

    pub fn reserve(&mut self, amount_units: u64) -> PrivateMevGuardResult<()> {
        if !self.status.can_reserve() {
            return Err("rebate pool is not accepting reservations".to_string());
        }
        if amount_units == 0 {
            return Err("rebate reservation amount must be positive".to_string());
        }
        if amount_units > self.max_per_bundle_units {
            return Err("rebate reservation exceeds per bundle cap".to_string());
        }
        if amount_units > self.available_units {
            return Err("rebate reservation exceeds available balance".to_string());
        }
        self.available_units -= amount_units;
        self.reserved_units = self
            .reserved_units
            .checked_add(amount_units)
            .ok_or_else(|| "rebate pool reserved balance overflow".to_string())?;
        Ok(())
    }

    pub fn pay(&mut self, amount_units: u64) -> PrivateMevGuardResult<()> {
        if amount_units == 0 {
            return Err("rebate payment amount must be positive".to_string());
        }
        if amount_units > self.reserved_units {
            return Err("rebate payment exceeds reserved balance".to_string());
        }
        self.reserved_units -= amount_units;
        self.paid_units = self
            .paid_units
            .checked_add(amount_units)
            .ok_or_else(|| "rebate pool paid balance overflow".to_string())?;
        if self.available_units == 0 && self.reserved_units == 0 {
            self.status = RebatePoolStatus::Exhausted;
        }
        Ok(())
    }

    pub fn release(&mut self, amount_units: u64) -> PrivateMevGuardResult<()> {
        if amount_units == 0 {
            return Err("rebate release amount must be positive".to_string());
        }
        if amount_units > self.reserved_units {
            return Err("rebate release exceeds reserved balance".to_string());
        }
        self.reserved_units -= amount_units;
        self.available_units = self
            .available_units
            .checked_add(amount_units)
            .ok_or_else(|| "rebate pool available balance overflow".to_string())?;
        Ok(())
    }

    pub fn slash(&mut self, amount_units: u64) -> PrivateMevGuardResult<()> {
        if amount_units == 0 {
            return Err("rebate slash amount must be positive".to_string());
        }
        if amount_units > self.reserved_units {
            return Err("rebate slash exceeds reserved balance".to_string());
        }
        self.reserved_units -= amount_units;
        self.slashed_units = self
            .slashed_units
            .checked_add(amount_units)
            .ok_or_else(|| "rebate pool slashed balance overflow".to_string())?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_rebate_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "lane_kind": self.lane_kind.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "asset_commitment": self.asset_commitment,
            "opening_balance_units": self.opening_balance_units,
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "paid_units": self.paid_units,
            "slashed_units": self.slashed_units,
            "max_rebate_bps": self.max_rebate_bps,
            "max_per_bundle_units": self.max_per_bundle_units,
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn pool_root(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-REBATE-POOL", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.pool_id, "rebate pool id")?;
        ensure_non_empty(&self.sponsor_commitment, "rebate pool sponsor commitment")?;
        ensure_non_empty(&self.asset_id, "rebate pool asset id")?;
        ensure_non_empty(&self.asset_commitment, "rebate pool asset commitment")?;
        if self.opening_balance_units == 0 {
            return Err("rebate pool opening balance must be positive".to_string());
        }
        if self.max_per_bundle_units == 0 {
            return Err("rebate pool max per bundle must be positive".to_string());
        }
        ensure_bps(self.max_rebate_bps, "rebate pool max rebate bps")?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("rebate pool expiry must be after start".to_string());
        }
        let accounted = self
            .available_units
            .checked_add(self.reserved_units)
            .and_then(|value| value.checked_add(self.paid_units))
            .and_then(|value| value.checked_add(self.slashed_units))
            .ok_or_else(|| "rebate pool accounting overflow".to_string())?;
        if accounted != self.opening_balance_units {
            return Err("rebate pool accounting does not balance".to_string());
        }
        let expected = private_mev_guard_rebate_pool_id(
            self.lane_kind,
            &self.sponsor_commitment,
            &self.asset_commitment,
            self.starts_at_height,
        );
        if self.pool_id != expected {
            return Err("rebate pool id mismatch".to_string());
        }
        Ok(self.pool_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevLowFeeLane {
    pub lane_id: String,
    pub lane_kind: PrivateMevLaneKind,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub min_privacy_budget_units: u64,
    pub rebate_pool_id: String,
    pub capacity_per_epoch: u64,
    pub used_capacity: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeLaneStatus,
}

impl PrivateMevLowFeeLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: PrivateMevLaneKind,
        fee_asset_id: impl Into<String>,
        max_fee_micro_units: u64,
        min_privacy_budget_units: u64,
        rebate_pool_id: impl Into<String>,
        capacity_per_epoch: u64,
        starts_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateMevGuardResult<Self> {
        let fee_asset_id = fee_asset_id.into();
        let rebate_pool_id = rebate_pool_id.into();
        ensure_non_empty(&fee_asset_id, "low fee lane fee asset id")?;
        ensure_non_empty(&rebate_pool_id, "low fee lane rebate pool id")?;
        if !lane_kind.low_fee() {
            return Err("low fee lane kind must be a low fee lane".to_string());
        }
        if capacity_per_epoch == 0 {
            return Err("low fee lane capacity must be positive".to_string());
        }
        let expires_at_height = starts_at_height
            .checked_add(ttl_blocks)
            .ok_or_else(|| "low fee lane expiry overflow".to_string())?;
        let lane_id = private_mev_guard_low_fee_lane_id(
            lane_kind,
            &fee_asset_id,
            &rebate_pool_id,
            starts_at_height,
        );
        let lane = Self {
            lane_id,
            lane_kind,
            fee_asset_id,
            max_fee_micro_units,
            min_privacy_budget_units,
            rebate_pool_id,
            capacity_per_epoch,
            used_capacity: 0,
            starts_at_height,
            expires_at_height,
            status: LowFeeLaneStatus::Active,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepts() && height >= self.starts_at_height && height < self.expires_at_height
    }

    pub fn reserve_capacity(&mut self, units: u64) -> PrivateMevGuardResult<()> {
        if units == 0 {
            return Err("low fee lane capacity reservation must be positive".to_string());
        }
        let next = self
            .used_capacity
            .checked_add(units)
            .ok_or_else(|| "low fee lane capacity overflow".to_string())?;
        if next > self.capacity_per_epoch {
            return Err("low fee lane capacity exceeded".to_string());
        }
        self.used_capacity = next;
        if self.used_capacity == self.capacity_per_epoch {
            self.status = LowFeeLaneStatus::Saturated;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_low_fee_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "min_privacy_budget_units": self.min_privacy_budget_units,
            "rebate_pool_id": self.rebate_pool_id,
            "capacity_per_epoch": self.capacity_per_epoch,
            "used_capacity": self.used_capacity,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn lane_root(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-LOW-FEE-LANE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.lane_id, "low fee lane id")?;
        ensure_non_empty(&self.fee_asset_id, "low fee lane fee asset id")?;
        ensure_non_empty(&self.rebate_pool_id, "low fee lane rebate pool id")?;
        if !self.lane_kind.low_fee() {
            return Err("low fee lane kind must be a low fee lane".to_string());
        }
        if self.capacity_per_epoch == 0 {
            return Err("low fee lane capacity must be positive".to_string());
        }
        if self.used_capacity > self.capacity_per_epoch {
            return Err("low fee lane used capacity exceeds capacity".to_string());
        }
        if self.expires_at_height <= self.starts_at_height {
            return Err("low fee lane expiry must be after start".to_string());
        }
        let expected = private_mev_guard_low_fee_lane_id(
            self.lane_kind,
            &self.fee_asset_id,
            &self.rebate_pool_id,
            self.starts_at_height,
        );
        if self.lane_id != expected {
            return Err("low fee lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateAccountingEntry {
    pub entry_id: String,
    pub pool_id: String,
    pub bundle_id: Option<String>,
    pub fill_id: Option<String>,
    pub solver_commitment_id: Option<String>,
    pub entry_kind: RebateAccountingKind,
    pub asset_id: String,
    pub amount_units: u64,
    pub pre_available_units: u64,
    pub post_available_units: u64,
    pub recorded_at_height: u64,
    pub note_root: String,
}

impl RebateAccountingEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: impl Into<String>,
        bundle_id: Option<String>,
        fill_id: Option<String>,
        solver_commitment_id: Option<String>,
        entry_kind: RebateAccountingKind,
        asset_id: impl Into<String>,
        amount_units: u64,
        pre_available_units: u64,
        post_available_units: u64,
        recorded_at_height: u64,
        note: &Value,
    ) -> PrivateMevGuardResult<Self> {
        let pool_id = pool_id.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&pool_id, "rebate accounting pool id")?;
        ensure_non_empty(&asset_id, "rebate accounting asset id")?;
        if amount_units == 0 {
            return Err("rebate accounting amount must be positive".to_string());
        }
        let note_root = private_mev_guard_payload_root("rebate_accounting_note", note);
        let entry_id = private_mev_guard_rebate_entry_id(
            &pool_id,
            bundle_id.as_deref(),
            fill_id.as_deref(),
            solver_commitment_id.as_deref(),
            entry_kind,
            amount_units,
            recorded_at_height,
        );
        let entry = Self {
            entry_id,
            pool_id,
            bundle_id,
            fill_id,
            solver_commitment_id,
            entry_kind,
            asset_id,
            amount_units,
            pre_available_units,
            post_available_units,
            recorded_at_height,
            note_root,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_rebate_accounting_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "pool_id": self.pool_id,
            "bundle_id": self.bundle_id,
            "fill_id": self.fill_id,
            "solver_commitment_id": self.solver_commitment_id,
            "entry_kind": self.entry_kind.as_str(),
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "pre_available_units": self.pre_available_units,
            "post_available_units": self.post_available_units,
            "recorded_at_height": self.recorded_at_height,
            "note_root": self.note_root,
        })
    }

    pub fn entry_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-REBATE-ACCOUNTING-ENTRY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.entry_id, "rebate accounting entry id")?;
        ensure_non_empty(&self.pool_id, "rebate accounting pool id")?;
        ensure_non_empty(&self.asset_id, "rebate accounting asset id")?;
        ensure_non_empty(&self.note_root, "rebate accounting note root")?;
        if self.amount_units == 0 {
            return Err("rebate accounting amount must be positive".to_string());
        }
        let expected = private_mev_guard_rebate_entry_id(
            &self.pool_id,
            self.bundle_id.as_deref(),
            self.fill_id.as_deref(),
            self.solver_commitment_id.as_deref(),
            self.entry_kind,
            self.amount_units,
            self.recorded_at_height,
        );
        if self.entry_id != expected {
            return Err("rebate accounting entry id mismatch".to_string());
        }
        Ok(self.entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPreservingFill {
    pub fill_id: String,
    pub bundle_id: String,
    pub epoch_id: String,
    pub solver_commitment_id: String,
    pub lane_kind: PrivateMevLaneKind,
    pub execution_trace_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub nullifier_root: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub surplus_commitment: String,
    pub price_commitment: String,
    pub proof_root: String,
    pub filled_at_height: u64,
    pub status: FillStatus,
}

impl PrivacyPreservingFill {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        epoch_id: impl Into<String>,
        solver_commitment_id: impl Into<String>,
        lane_kind: PrivateMevLaneKind,
        execution_trace: &Value,
        input_notes: &[String],
        output_notes: &[String],
        nullifiers: &[String],
        fee_label: &str,
        rebate_label: &str,
        surplus_label: &str,
        price_label: &str,
        proof: &Value,
        filled_at_height: u64,
    ) -> PrivateMevGuardResult<Self> {
        let bundle_id = bundle_id.into();
        let epoch_id = epoch_id.into();
        let solver_commitment_id = solver_commitment_id.into();
        ensure_non_empty(&bundle_id, "privacy fill bundle id")?;
        ensure_non_empty(&epoch_id, "privacy fill epoch id")?;
        ensure_non_empty(&solver_commitment_id, "privacy fill solver commitment id")?;
        ensure_non_empty(fee_label, "privacy fill fee label")?;
        ensure_non_empty(rebate_label, "privacy fill rebate label")?;
        ensure_non_empty(surplus_label, "privacy fill surplus label")?;
        ensure_non_empty(price_label, "privacy fill price label")?;
        let execution_trace_root =
            private_mev_guard_payload_root("fill_execution_trace", execution_trace);
        let input_note_root =
            private_mev_guard_string_list_root("PRIVATE-MEV-GUARD-FILL-INPUT-NOTES", input_notes);
        let output_note_root =
            private_mev_guard_string_list_root("PRIVATE-MEV-GUARD-FILL-OUTPUT-NOTES", output_notes);
        let nullifier_root =
            private_mev_guard_string_list_root("PRIVATE-MEV-GUARD-FILL-NULLIFIERS", nullifiers);
        let fee_commitment = private_mev_guard_string_commitment("fill_fee", fee_label);
        let rebate_commitment = private_mev_guard_string_commitment("fill_rebate", rebate_label);
        let surplus_commitment = private_mev_guard_string_commitment("fill_surplus", surplus_label);
        let price_commitment = private_mev_guard_string_commitment("fill_price", price_label);
        let proof_root = private_mev_guard_payload_root("fill_proof", proof);
        let fill_id = private_mev_guard_fill_id(
            &bundle_id,
            &epoch_id,
            &solver_commitment_id,
            &output_note_root,
            filled_at_height,
        );
        let fill = Self {
            fill_id,
            bundle_id,
            epoch_id,
            solver_commitment_id,
            lane_kind,
            execution_trace_root,
            input_note_root,
            output_note_root,
            nullifier_root,
            fee_commitment,
            rebate_commitment,
            surplus_commitment,
            price_commitment,
            proof_root,
            filled_at_height,
            status: FillStatus::Proven,
        };
        fill.validate()?;
        Ok(fill)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_privacy_preserving_fill",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "fill_id": self.fill_id,
            "bundle_id": self.bundle_id,
            "epoch_id": self.epoch_id,
            "solver_commitment_id": self.solver_commitment_id,
            "lane_kind": self.lane_kind.as_str(),
            "execution_trace_root": self.execution_trace_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "nullifier_root": self.nullifier_root,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "surplus_commitment": self.surplus_commitment,
            "price_commitment": self.price_commitment,
            "proof_root": self.proof_root,
            "filled_at_height": self.filled_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn fill_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-PRIVACY-PRESERVING-FILL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.fill_id, "privacy fill id")?;
        ensure_non_empty(&self.bundle_id, "privacy fill bundle id")?;
        ensure_non_empty(&self.epoch_id, "privacy fill epoch id")?;
        ensure_non_empty(
            &self.solver_commitment_id,
            "privacy fill solver commitment id",
        )?;
        ensure_non_empty(
            &self.execution_trace_root,
            "privacy fill execution trace root",
        )?;
        ensure_non_empty(&self.input_note_root, "privacy fill input note root")?;
        ensure_non_empty(&self.output_note_root, "privacy fill output note root")?;
        ensure_non_empty(&self.nullifier_root, "privacy fill nullifier root")?;
        ensure_non_empty(&self.proof_root, "privacy fill proof root")?;
        let expected = private_mev_guard_fill_id(
            &self.bundle_id,
            &self.epoch_id,
            &self.solver_commitment_id,
            &self.output_note_root,
            self.filled_at_height,
        );
        if self.fill_id != expected {
            return Err("privacy fill id mismatch".to_string());
        }
        Ok(self.fill_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostTradePrivacyReceipt {
    pub receipt_id: String,
    pub fill_id: String,
    pub bundle_id: String,
    pub audience: PrivacyReceiptAudience,
    pub recipient_commitment: String,
    pub encrypted_receipt_root: String,
    pub disclosure_policy_root: String,
    pub view_tag_root: String,
    pub release_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivacyReceiptStatus,
}

impl PostTradePrivacyReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_id: impl Into<String>,
        bundle_id: impl Into<String>,
        audience: PrivacyReceiptAudience,
        recipient_label: &str,
        encrypted_receipt: &Value,
        disclosure_policy: &Value,
        release_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateMevGuardResult<Self> {
        let fill_id = fill_id.into();
        let bundle_id = bundle_id.into();
        ensure_non_empty(&fill_id, "post trade receipt fill id")?;
        ensure_non_empty(&bundle_id, "post trade receipt bundle id")?;
        ensure_non_empty(recipient_label, "post trade receipt recipient label")?;
        if expires_at_height <= release_at_height {
            return Err("post trade receipt expiry must be after release".to_string());
        }
        let recipient_commitment =
            private_mev_guard_string_commitment("receipt_recipient", recipient_label);
        let encrypted_receipt_root =
            private_mev_guard_payload_root("post_trade_encrypted_receipt", encrypted_receipt);
        let disclosure_policy_root =
            private_mev_guard_payload_root("post_trade_disclosure_policy", disclosure_policy);
        let view_tag_root =
            private_mev_guard_string_commitment("receipt_view_tag", &recipient_commitment);
        let receipt_id = private_mev_guard_privacy_receipt_id(
            &fill_id,
            &bundle_id,
            audience,
            &recipient_commitment,
            release_at_height,
        );
        let receipt = Self {
            receipt_id,
            fill_id,
            bundle_id,
            audience,
            recipient_commitment,
            encrypted_receipt_root,
            disclosure_policy_root,
            view_tag_root,
            release_at_height,
            expires_at_height,
            status: PrivacyReceiptStatus::Committed,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_post_trade_privacy_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "fill_id": self.fill_id,
            "bundle_id": self.bundle_id,
            "audience": self.audience.as_str(),
            "recipient_commitment": self.recipient_commitment,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "view_tag_root": self.view_tag_root,
            "release_at_height": self.release_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-POST-TRADE-PRIVACY-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.receipt_id, "post trade receipt id")?;
        ensure_non_empty(&self.fill_id, "post trade receipt fill id")?;
        ensure_non_empty(&self.bundle_id, "post trade receipt bundle id")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "post trade receipt recipient commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_receipt_root,
            "post trade receipt encrypted root",
        )?;
        if self.expires_at_height <= self.release_at_height {
            return Err("post trade receipt expiry must be after release".to_string());
        }
        let expected = private_mev_guard_privacy_receipt_id(
            &self.fill_id,
            &self.bundle_id,
            self.audience,
            &self.recipient_commitment,
            self.release_at_height,
        );
        if self.receipt_id != expected {
            return Err("post trade receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedRevealReceipt {
    pub reveal_id: String,
    pub receipt_id: String,
    pub fill_id: String,
    pub delayed_payload_root: String,
    pub release_condition_root: String,
    pub release_at_height: u64,
    pub revealed_at_height: Option<u64>,
    pub status: PrivacyReceiptStatus,
}

impl DelayedRevealReceipt {
    pub fn new(
        receipt: &PostTradePrivacyReceipt,
        delayed_payload: &Value,
        release_condition: &Value,
    ) -> PrivateMevGuardResult<Self> {
        receipt.validate()?;
        let delayed_payload_root =
            private_mev_guard_payload_root("delayed_reveal_payload", delayed_payload);
        let release_condition_root =
            private_mev_guard_payload_root("delayed_reveal_condition", release_condition);
        let reveal_id = private_mev_guard_delayed_reveal_id(
            &receipt.receipt_id,
            &receipt.fill_id,
            &delayed_payload_root,
            receipt.release_at_height,
        );
        let delayed = Self {
            reveal_id,
            receipt_id: receipt.receipt_id.clone(),
            fill_id: receipt.fill_id.clone(),
            delayed_payload_root,
            release_condition_root,
            release_at_height: receipt.release_at_height,
            revealed_at_height: None,
            status: PrivacyReceiptStatus::Committed,
        };
        delayed.validate()?;
        Ok(delayed)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_delayed_reveal_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "reveal_id": self.reveal_id,
            "receipt_id": self.receipt_id,
            "fill_id": self.fill_id,
            "delayed_payload_root": self.delayed_payload_root,
            "release_condition_root": self.release_condition_root,
            "release_at_height": self.release_at_height,
            "revealed_at_height": self.revealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn reveal_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-DELAYED-REVEAL-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.reveal_id, "delayed reveal id")?;
        ensure_non_empty(&self.receipt_id, "delayed reveal receipt id")?;
        ensure_non_empty(&self.fill_id, "delayed reveal fill id")?;
        ensure_non_empty(&self.delayed_payload_root, "delayed reveal payload root")?;
        ensure_non_empty(
            &self.release_condition_root,
            "delayed reveal condition root",
        )?;
        let expected = private_mev_guard_delayed_reveal_id(
            &self.receipt_id,
            &self.fill_id,
            &self.delayed_payload_root,
            self.release_at_height,
        );
        if self.reveal_id != expected {
            return Err("delayed reveal id mismatch".to_string());
        }
        Ok(self.reveal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverSlashEvidence {
    pub evidence_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub accused_solver_commitment: String,
    pub epoch_id: String,
    pub commitment_id: Option<String>,
    pub bundle_id: Option<String>,
    pub pre_state_root: String,
    pub claimed_post_state_root: String,
    pub conflict_root: String,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub penalty_units: u64,
    pub discovered_at_height: u64,
    pub status: SlashingEvidenceStatus,
}

impl SolverSlashEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: SlashingEvidenceKind,
        accused_solver_label: &str,
        epoch_id: impl Into<String>,
        commitment_id: Option<String>,
        bundle_id: Option<String>,
        pre_state: &Value,
        claimed_post_state: &Value,
        conflict: &Value,
        evidence: &Value,
        reporter_label: &str,
        penalty_units: u64,
        discovered_at_height: u64,
    ) -> PrivateMevGuardResult<Self> {
        ensure_non_empty(accused_solver_label, "slashing accused solver label")?;
        ensure_non_empty(reporter_label, "slashing reporter label")?;
        let epoch_id = epoch_id.into();
        ensure_non_empty(&epoch_id, "slashing epoch id")?;
        if penalty_units == 0 {
            return Err("slashing penalty must be positive".to_string());
        }
        let accused_solver_commitment =
            private_mev_guard_string_commitment("solver", accused_solver_label);
        let pre_state_root = private_mev_guard_payload_root("slash_pre_state", pre_state);
        let claimed_post_state_root =
            private_mev_guard_payload_root("slash_claimed_post_state", claimed_post_state);
        let conflict_root = private_mev_guard_payload_root("slash_conflict", conflict);
        let evidence_root = private_mev_guard_payload_root("slash_evidence", evidence);
        let reporter_commitment =
            private_mev_guard_string_commitment("slash_reporter", reporter_label);
        let evidence_id = private_mev_guard_slashing_evidence_id(
            evidence_kind,
            &accused_solver_commitment,
            &epoch_id,
            commitment_id.as_deref(),
            bundle_id.as_deref(),
            &conflict_root,
            discovered_at_height,
        );
        let slash = Self {
            evidence_id,
            evidence_kind,
            accused_solver_commitment,
            epoch_id,
            commitment_id,
            bundle_id,
            pre_state_root,
            claimed_post_state_root,
            conflict_root,
            evidence_root,
            reporter_commitment,
            penalty_units,
            discovered_at_height,
            status: SlashingEvidenceStatus::Submitted,
        };
        slash.validate()?;
        Ok(slash)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_solver_slash_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "accused_solver_commitment": self.accused_solver_commitment,
            "epoch_id": self.epoch_id,
            "commitment_id": self.commitment_id,
            "bundle_id": self.bundle_id,
            "pre_state_root": self.pre_state_root,
            "claimed_post_state_root": self.claimed_post_state_root,
            "conflict_root": self.conflict_root,
            "evidence_root": self.evidence_root,
            "reporter_commitment": self.reporter_commitment,
            "penalty_units": self.penalty_units,
            "discovered_at_height": self.discovered_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn slash_root(&self) -> String {
        private_mev_guard_record_id(
            "PRIVATE-MEV-GUARD-SOLVER-SLASH-EVIDENCE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(
            &self.accused_solver_commitment,
            "slashing accused solver commitment",
        )?;
        ensure_non_empty(&self.epoch_id, "slashing epoch id")?;
        ensure_non_empty(&self.pre_state_root, "slashing pre state root")?;
        ensure_non_empty(
            &self.claimed_post_state_root,
            "slashing claimed post state root",
        )?;
        ensure_non_empty(&self.conflict_root, "slashing conflict root")?;
        ensure_non_empty(&self.evidence_root, "slashing evidence root")?;
        ensure_non_empty(&self.reporter_commitment, "slashing reporter commitment")?;
        if self.penalty_units == 0 {
            return Err("slashing penalty must be positive".to_string());
        }
        let expected = private_mev_guard_slashing_evidence_id(
            self.evidence_kind,
            &self.accused_solver_commitment,
            &self.epoch_id,
            self.commitment_id.as_deref(),
            self.bundle_id.as_deref(),
            &self.conflict_root,
            self.discovered_at_height,
        );
        if self.evidence_id != expected {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(self.slash_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevAuditRecord {
    pub audit_record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub severity: AuditSeverity,
    pub category: String,
    pub redacted_record_root: String,
    pub witness_root: String,
    pub state_root: String,
    pub recorded_at_height: u64,
    pub note_root: String,
}

impl PrivateMevAuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        severity: AuditSeverity,
        category: impl Into<String>,
        redacted_record: &Value,
        witness: &Value,
        state_root: impl Into<String>,
        recorded_at_height: u64,
        note: &Value,
    ) -> PrivateMevGuardResult<Self> {
        let object_kind = object_kind.into();
        let object_id = object_id.into();
        let category = category.into();
        let state_root = state_root.into();
        ensure_non_empty(&object_kind, "audit object kind")?;
        ensure_non_empty(&object_id, "audit object id")?;
        ensure_non_empty(&category, "audit category")?;
        ensure_non_empty(&state_root, "audit state root")?;
        let redacted_record_root =
            private_mev_guard_payload_root("audit_redacted_record", redacted_record);
        let witness_root = private_mev_guard_payload_root("audit_witness", witness);
        let note_root = private_mev_guard_payload_root("audit_note", note);
        let audit_record_id = private_mev_guard_audit_record_id(
            &object_kind,
            &object_id,
            severity,
            &category,
            &redacted_record_root,
            recorded_at_height,
        );
        let record = Self {
            audit_record_id,
            object_kind,
            object_id,
            severity,
            category,
            redacted_record_root,
            witness_root,
            state_root,
            recorded_at_height,
            note_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_audit_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "audit_record_id": self.audit_record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "severity": self.severity.as_str(),
            "category": self.category,
            "redacted_record_root": self.redacted_record_root,
            "witness_root": self.witness_root,
            "state_root": self.state_root,
            "recorded_at_height": self.recorded_at_height,
            "note_root": self.note_root,
        })
    }

    pub fn audit_root(&self) -> String {
        private_mev_guard_record_id("PRIVATE-MEV-GUARD-AUDIT-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.audit_record_id, "audit record id")?;
        ensure_non_empty(&self.object_kind, "audit object kind")?;
        ensure_non_empty(&self.object_id, "audit object id")?;
        ensure_non_empty(&self.category, "audit category")?;
        ensure_non_empty(&self.redacted_record_root, "audit redacted root")?;
        ensure_non_empty(&self.witness_root, "audit witness root")?;
        ensure_non_empty(&self.state_root, "audit state root")?;
        ensure_non_empty(&self.note_root, "audit note root")?;
        let expected = private_mev_guard_audit_record_id(
            &self.object_kind,
            &self.object_id,
            self.severity,
            &self.category,
            &self.redacted_record_root,
            self.recorded_at_height,
        );
        if self.audit_record_id != expected {
            return Err("audit record id mismatch".to_string());
        }
        Ok(self.audit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevGuardRoots {
    pub config_root: String,
    pub key_epoch_root: String,
    pub encrypted_bundle_root: String,
    pub anti_sandwich_policy_root: String,
    pub inclusion_constraint_root: String,
    pub auction_epoch_root: String,
    pub solver_commitment_root: String,
    pub solver_opening_root: String,
    pub rebate_pool_root: String,
    pub rebate_accounting_root: String,
    pub low_fee_lane_root: String,
    pub fill_root: String,
    pub post_trade_receipt_root: String,
    pub delayed_reveal_receipt_root: String,
    pub slashing_evidence_root: String,
    pub audit_record_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl PrivateMevGuardRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_mev_guard_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "key_epoch_root": self.key_epoch_root,
            "encrypted_bundle_root": self.encrypted_bundle_root,
            "anti_sandwich_policy_root": self.anti_sandwich_policy_root,
            "inclusion_constraint_root": self.inclusion_constraint_root,
            "auction_epoch_root": self.auction_epoch_root,
            "solver_commitment_root": self.solver_commitment_root,
            "solver_opening_root": self.solver_opening_root,
            "rebate_pool_root": self.rebate_pool_root,
            "rebate_accounting_root": self.rebate_accounting_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "fill_root": self.fill_root,
            "post_trade_receipt_root": self.post_trade_receipt_root,
            "delayed_reveal_receipt_root": self.delayed_reveal_receipt_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "audit_record_root": self.audit_record_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("private mev guard roots record object")
            .insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevGuardCounters {
    pub height: u64,
    pub key_epoch_count: u64,
    pub active_key_epoch_count: u64,
    pub encrypted_bundle_count: u64,
    pub active_bundle_count: u64,
    pub filled_bundle_count: u64,
    pub expired_bundle_count: u64,
    pub anti_sandwich_policy_count: u64,
    pub inclusion_constraint_count: u64,
    pub satisfied_constraint_count: u64,
    pub auction_epoch_count: u64,
    pub active_auction_epoch_count: u64,
    pub finalized_auction_epoch_count: u64,
    pub solver_commitment_count: u64,
    pub accepted_solver_commitment_count: u64,
    pub solver_opening_count: u64,
    pub accepted_solver_opening_count: u64,
    pub rebate_pool_count: u64,
    pub active_rebate_pool_count: u64,
    pub rebate_accounting_entry_count: u64,
    pub low_fee_lane_count: u64,
    pub active_low_fee_lane_count: u64,
    pub fill_count: u64,
    pub settled_fill_count: u64,
    pub post_trade_receipt_count: u64,
    pub delayed_reveal_receipt_count: u64,
    pub releasable_receipt_count: u64,
    pub slashing_evidence_count: u64,
    pub accepted_slashing_evidence_count: u64,
    pub audit_record_count: u64,
    pub public_record_count: u64,
    pub total_payload_bytes: u64,
    pub total_max_fee_micro_units: u64,
    pub rebate_available_units: u64,
    pub rebate_reserved_units: u64,
    pub rebate_paid_units: u64,
    pub rebate_slashed_units: u64,
}

impl PrivateMevGuardCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mev_guard_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "height": self.height,
            "key_epoch_count": self.key_epoch_count,
            "active_key_epoch_count": self.active_key_epoch_count,
            "encrypted_bundle_count": self.encrypted_bundle_count,
            "active_bundle_count": self.active_bundle_count,
            "filled_bundle_count": self.filled_bundle_count,
            "expired_bundle_count": self.expired_bundle_count,
            "anti_sandwich_policy_count": self.anti_sandwich_policy_count,
            "inclusion_constraint_count": self.inclusion_constraint_count,
            "satisfied_constraint_count": self.satisfied_constraint_count,
            "auction_epoch_count": self.auction_epoch_count,
            "active_auction_epoch_count": self.active_auction_epoch_count,
            "finalized_auction_epoch_count": self.finalized_auction_epoch_count,
            "solver_commitment_count": self.solver_commitment_count,
            "accepted_solver_commitment_count": self.accepted_solver_commitment_count,
            "solver_opening_count": self.solver_opening_count,
            "accepted_solver_opening_count": self.accepted_solver_opening_count,
            "rebate_pool_count": self.rebate_pool_count,
            "active_rebate_pool_count": self.active_rebate_pool_count,
            "rebate_accounting_entry_count": self.rebate_accounting_entry_count,
            "low_fee_lane_count": self.low_fee_lane_count,
            "active_low_fee_lane_count": self.active_low_fee_lane_count,
            "fill_count": self.fill_count,
            "settled_fill_count": self.settled_fill_count,
            "post_trade_receipt_count": self.post_trade_receipt_count,
            "delayed_reveal_receipt_count": self.delayed_reveal_receipt_count,
            "releasable_receipt_count": self.releasable_receipt_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "accepted_slashing_evidence_count": self.accepted_slashing_evidence_count,
            "audit_record_count": self.audit_record_count,
            "public_record_count": self.public_record_count,
            "total_payload_bytes": self.total_payload_bytes,
            "total_max_fee_micro_units": self.total_max_fee_micro_units,
            "rebate_available_units": self.rebate_available_units,
            "rebate_reserved_units": self.rebate_reserved_units,
            "rebate_paid_units": self.rebate_paid_units,
            "rebate_slashed_units": self.rebate_slashed_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevGuardState {
    pub height: u64,
    pub operator_label: String,
    pub next_epoch_sequence: u64,
    pub config: PrivateMevGuardConfig,
    pub key_epochs: BTreeMap<String, ThresholdEncryptionKeyEpoch>,
    pub encrypted_bundles: BTreeMap<String, EncryptedOrderBundle>,
    pub anti_sandwich_policies: BTreeMap<String, AntiSandwichPolicy>,
    pub inclusion_constraints: BTreeMap<String, InclusionConstraint>,
    pub auction_epochs: BTreeMap<String, FairBatchAuctionEpoch>,
    pub solver_commitments: BTreeMap<String, PrivateSolverCommitment>,
    pub solver_openings: BTreeMap<String, PrivateSolverOpening>,
    pub rebate_pools: BTreeMap<String, RebatePool>,
    pub rebate_accounting: BTreeMap<String, RebateAccountingEntry>,
    pub low_fee_lanes: BTreeMap<String, PrivateMevLowFeeLane>,
    pub fills: BTreeMap<String, PrivacyPreservingFill>,
    pub post_trade_receipts: BTreeMap<String, PostTradePrivacyReceipt>,
    pub delayed_reveal_receipts: BTreeMap<String, DelayedRevealReceipt>,
    pub slashing_evidence: BTreeMap<String, SolverSlashEvidence>,
    pub audit_records: BTreeMap<String, PrivateMevAuditRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for PrivateMevGuardState {
    fn default() -> Self {
        Self::new("private-mev-guard", PrivateMevGuardConfig::default())
            .expect("default private mev guard state")
    }
}

impl PrivateMevGuardState {
    pub fn new(
        operator_label: impl Into<String>,
        config: PrivateMevGuardConfig,
    ) -> PrivateMevGuardResult<Self> {
        config.validate()?;
        let operator_label = operator_label.into();
        ensure_non_empty(&operator_label, "private mev guard operator label")?;
        Ok(Self {
            height: 0,
            operator_label,
            next_epoch_sequence: 0,
            config,
            key_epochs: BTreeMap::new(),
            encrypted_bundles: BTreeMap::new(),
            anti_sandwich_policies: BTreeMap::new(),
            inclusion_constraints: BTreeMap::new(),
            auction_epochs: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            solver_openings: BTreeMap::new(),
            rebate_pools: BTreeMap::new(),
            rebate_accounting: BTreeMap::new(),
            low_fee_lanes: BTreeMap::new(),
            fills: BTreeMap::new(),
            post_trade_receipts: BTreeMap::new(),
            delayed_reveal_receipts: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            audit_records: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PrivateMevGuardResult<Self> {
        let mut state = Self::new("devnet-private-mev-guard", PrivateMevGuardConfig::default())?;
        state.set_height(32)?;

        let member_labels = [
            "devnet-mev-threshold-a",
            "devnet-mev-threshold-b",
            "devnet-mev-threshold-c",
            "devnet-mev-threshold-d",
        ]
        .iter()
        .map(|label| label.to_string())
        .collect::<Vec<_>>();
        let key_epoch = ThresholdEncryptionKeyEpoch::new(
            "devnet-private-mev-threshold-committee",
            "devnet-private-mev-aggregate-ml-kem-root",
            &member_labels,
            &json!({
                "ceremony": "devnet-private-mev-guard",
                "threshold": 3,
                "members": member_labels,
                "policy": "no-cleartext-before-batch-seal",
            }),
            state.config.threshold_decryptions,
            1,
            10_000,
            state.config.reveal_delay_blocks,
        )?;
        let key_epoch_id = key_epoch.key_epoch_id.clone();
        state.insert_key_epoch(key_epoch)?;

        let dex_policy = AntiSandwichPolicy::new(
            AntiSandwichPolicyKind::UniformClearingPrice,
            "wxmr-usdd",
            2,
            80,
            25,
            7_500,
            vec![
                PrivateMevLaneKind::PrivateDex,
                PrivateMevLaneKind::LowFeeSwap,
            ],
            &json!({
                "venue": "devnet-private-dex",
                "uniform_clearing": true,
                "forbid_same_solver_pre_post": true,
            }),
        )?;
        let dex_policy_id = dex_policy.policy_id.clone();
        state.insert_anti_sandwich_policy(dex_policy)?;

        let liquidation_policy = AntiSandwichPolicy::new(
            AntiSandwichPolicyKind::ProtectedLiquidation,
            "wxmr-usdd-lending",
            1,
            150,
            40,
            8_000,
            vec![
                PrivateMevLaneKind::ConfidentialLiquidation,
                PrivateMevLaneKind::LowFeeLiquidation,
            ],
            &json!({
                "venue": "devnet-confidential-lending",
                "protects": "liquidation-trigger-and-repay-path",
            }),
        )?;
        let liquidation_policy_id = liquidation_policy.policy_id.clone();
        state.insert_anti_sandwich_policy(liquidation_policy)?;

        let swap_rebate_pool = RebatePool::new(
            PrivateMevLaneKind::LowFeeSwap,
            "devnet-swap-sponsor",
            "wxmr-devnet",
            5_000_000,
            7_500,
            75_000,
            100,
            state.height,
            state.config.low_fee_lane_ttl_blocks,
        )?;
        let swap_pool_id = swap_rebate_pool.pool_id.clone();
        state.insert_rebate_pool(swap_rebate_pool)?;

        let liquidation_rebate_pool = RebatePool::new(
            PrivateMevLaneKind::LowFeeLiquidation,
            "devnet-liquidation-sponsor",
            "wxmr-devnet",
            8_000_000,
            8_000,
            120_000,
            50,
            state.height,
            state.config.low_fee_lane_ttl_blocks,
        )?;
        let liquidation_pool_id = liquidation_rebate_pool.pool_id.clone();
        state.insert_rebate_pool(liquidation_rebate_pool)?;

        let swap_lane = PrivateMevLowFeeLane::new(
            PrivateMevLaneKind::LowFeeSwap,
            "wxmr-devnet",
            state.config.low_fee_ceiling_micro_units,
            20_000,
            swap_pool_id.clone(),
            16,
            state.height,
            state.config.low_fee_lane_ttl_blocks,
        )?;
        let swap_lane_id = swap_lane.lane_id.clone();
        state.insert_low_fee_lane(swap_lane)?;

        let liquidation_lane = PrivateMevLowFeeLane::new(
            PrivateMevLaneKind::LowFeeLiquidation,
            "wxmr-devnet",
            state.config.low_fee_ceiling_micro_units,
            35_000,
            liquidation_pool_id.clone(),
            8,
            state.height,
            state.config.low_fee_lane_ttl_blocks,
        )?;
        let liquidation_lane_id = liquidation_lane.lane_id.clone();
        state.insert_low_fee_lane(liquidation_lane)?;

        let dex_bundle = EncryptedOrderBundle::new(
            PrivateMevBundleKind::Swap,
            PrivateMevLaneKind::PrivateDex,
            "devnet-alice",
            "split-wxmr-usdd-swap",
            "wxmr-usdd",
            &json!({
                "swap": "wxmr_to_usdd",
                "amount_bucket": "bucket-42",
                "limit_price_commitment": "devnet-alice-limit-price",
                "recipient_note": "devnet-alice-output-note",
            }),
            5_120,
            key_epoch_id.clone(),
            dex_policy_id.clone(),
            None,
            None,
            None,
            8_000,
            70,
            state.height,
            state.config.bundle_ttl_blocks,
            1,
        )?;
        let dex_bundle_id = state.insert_encrypted_bundle(dex_bundle)?;

        let low_fee_bundle = EncryptedOrderBundle::new(
            PrivateMevBundleKind::Swap,
            PrivateMevLaneKind::LowFeeSwap,
            "devnet-bob",
            "low-fee-wxmr-usdd-swap",
            "wxmr-usdd",
            &json!({
                "swap": "wxmr_to_usdd",
                "amount_bucket": "bucket-7",
                "rebate_credit": "devnet-bob-low-fee-credit",
            }),
            4_608,
            key_epoch_id.clone(),
            dex_policy_id.clone(),
            Some(swap_lane_id.clone()),
            None,
            None,
            1_500,
            60,
            state.height,
            state.config.bundle_ttl_blocks,
            2,
        )?;
        let low_fee_bundle_id = state.insert_encrypted_bundle(low_fee_bundle)?;

        let liquidation_bundle = EncryptedOrderBundle::new(
            PrivateMevBundleKind::Liquidation,
            PrivateMevLaneKind::LowFeeLiquidation,
            "devnet-keeper",
            "confidential-liquidation-wxmr-usdd",
            "wxmr-usdd-lending",
            &json!({
                "position": "encrypted-position-devnet-borrower-9",
                "health_bucket": "below-1.0",
                "repay_asset": "usdd",
                "seize_asset": "wxmr",
            }),
            6_144,
            key_epoch_id.clone(),
            liquidation_policy_id.clone(),
            Some(liquidation_lane_id.clone()),
            Some("devnet-position-borrower-9"),
            Some("devnet-borrower-9"),
            1_200,
            120,
            state.height,
            state.config.bundle_ttl_blocks,
            3,
        )?;
        let liquidation_bundle_id = state.insert_encrypted_bundle(liquidation_bundle)?;

        let solver_labels = vec![
            "devnet-solver-a".to_string(),
            "devnet-solver-b".to_string(),
            "devnet-liquidation-keeper".to_string(),
        ];
        for (index, bundle_id) in [
            dex_bundle_id.clone(),
            low_fee_bundle_id.clone(),
            liquidation_bundle_id.clone(),
        ]
        .iter()
        .enumerate()
        {
            let lane_kind = state
                .encrypted_bundles
                .get(bundle_id)
                .ok_or_else(|| "devnet bundle missing".to_string())?
                .lane_kind;
            let constraint = InclusionConstraint::new(
                bundle_id.clone(),
                lane_kind,
                state.height,
                state.height + state.config.bundle_ttl_blocks,
                index as u64,
                state.config.auction_window_blocks + state.config.reveal_window_blocks,
                Some(state.height + state.config.auction_window_blocks + 2),
                Some(format!("devnet-censorship-ticket-{index}")),
                state.encrypted_bundles[bundle_id].max_fee_micro_units,
                if lane_kind.low_fee() { 35_000 } else { 20_000 },
                &solver_labels,
            )?;
            let constraint_id = constraint.constraint_id.clone();
            state.insert_inclusion_constraint(constraint)?;
            if let Some(bundle) = state.encrypted_bundles.get_mut(bundle_id) {
                bundle.inclusion_constraint_id = Some(constraint_id);
                bundle.status = EncryptedBundleStatus::Queued;
            }
        }

        state.reserve_low_fee_capacity(&swap_lane_id, 1)?;
        state.reserve_low_fee_capacity(&liquidation_lane_id, 1)?;
        let swap_reservation = state.reserve_rebate(
            &swap_pool_id,
            &low_fee_bundle_id,
            50_000,
            &json!({"reason": "low_fee_private_swap", "lane": swap_lane_id}),
        )?;
        let liquidation_reservation = state.reserve_rebate(
            &liquidation_pool_id,
            &liquidation_bundle_id,
            90_000,
            &json!({"reason": "protected_liquidation", "lane": liquidation_lane_id}),
        )?;

        let sequence = state.next_epoch_sequence();
        let auction = FairBatchAuctionEpoch::new(
            sequence,
            PrivateMevVenueKind::PrivateDex,
            "wxmr-usdd",
            state.encrypted_bundle_root(),
            state.anti_sandwich_policy_root(),
            state.inclusion_constraint_root(),
            state.height,
            state.config.auction_window_blocks,
            state.config.reveal_delay_blocks,
            state.config.reveal_window_blocks,
            state.config.challenge_window_blocks,
            2,
            state.config.max_bundles_per_epoch,
        )?;
        let auction_id = auction.epoch_id.clone();
        state.insert_auction_epoch(auction)?;

        let solver_bundle_ids = vec![
            dex_bundle_id.clone(),
            low_fee_bundle_id.clone(),
            liquidation_bundle_id.clone(),
        ];
        let route_commitments = vec![
            private_mev_guard_string_commitment("route", "devnet-amm-direct"),
            private_mev_guard_string_commitment("route", "devnet-lending-liquidation"),
        ];
        let solver_commitment = PrivateSolverCommitment::new(
            auction_id.clone(),
            "devnet-solver-a",
            "devnet-solver-a-ml-dsa-public-key",
            &json!({
                "route": "encrypted-solution",
                "clearing": "uniform-price",
                "liquidation": "protected",
            }),
            &route_commitments,
            &solver_bundle_ids,
            "devnet-price-vector-001",
            "devnet-surplus-001",
            "devnet-rebate-001",
            2_000_000,
            state.height + 1,
            state.height
                + state.config.auction_window_blocks
                + state.config.reveal_delay_blocks
                + 1,
        )?;
        let solver_commitment_id = solver_commitment.commitment_id.clone();
        state.insert_solver_commitment(solver_commitment.clone())?;

        let solver_opening = PrivateSolverOpening::new(
            &solver_commitment,
            &json!({
                "batch_order": [
                    dex_bundle_id,
                    low_fee_bundle_id,
                    liquidation_bundle_id
                ],
                "no_same_solver_pre_post": true,
                "uniform_clearing_price": true,
            }),
            &json!({
                "anti_sandwich": "satisfied",
                "inclusion": "all_constraints_satisfied",
                "rebates": [swap_reservation.entry_id, liquidation_reservation.entry_id],
            }),
            &json!({"wxmr_usdd": "185000000/1"}),
            &json!({"surplus_bucket": "positive", "minimum_rebate_bps": 7500}),
            &json!({"low_fee_swap": 50_000, "liquidation": 90_000}),
            state.height + state.config.auction_window_blocks + state.config.reveal_delay_blocks,
            true,
        )?;
        state.insert_solver_opening(solver_opening)?;
        state.refresh_auction_roots(&auction_id)?;

        let low_fee_fill = PrivacyPreservingFill::new(
            low_fee_bundle_id.clone(),
            auction_id.clone(),
            solver_commitment_id.clone(),
            PrivateMevLaneKind::LowFeeSwap,
            &json!({"trace": "devnet-low-fee-fill", "venue": "private_dex"}),
            &["bob-input-note".to_string()],
            &["bob-output-note".to_string()],
            &["bob-nullifier".to_string()],
            "low-fee-swap-fee",
            "low-fee-swap-rebate",
            "low-fee-swap-surplus",
            "low-fee-swap-price",
            &json!({"proof": "devnet-low-fee-fill-proof"}),
            state.height + state.config.auction_window_blocks + 2,
        )?;
        let low_fee_fill_id = state.insert_fill(low_fee_fill)?;
        state.pay_rebate(
            &swap_pool_id,
            &low_fee_bundle_id,
            &low_fee_fill_id,
            &solver_commitment_id,
            50_000,
            &json!({"settlement": "paid-low-fee-swap-rebate"}),
        )?;

        let liquidation_fill = PrivacyPreservingFill::new(
            liquidation_bundle_id.clone(),
            auction_id.clone(),
            solver_commitment_id.clone(),
            PrivateMevLaneKind::LowFeeLiquidation,
            &json!({"trace": "devnet-liquidation-fill", "venue": "confidential_lending"}),
            &["keeper-repay-note".to_string()],
            &[
                "keeper-seize-note".to_string(),
                "borrower-change-note".to_string(),
            ],
            &["borrower-debt-nullifier".to_string()],
            "liquidation-fee",
            "liquidation-rebate",
            "liquidation-surplus",
            "liquidation-price",
            &json!({"proof": "devnet-liquidation-fill-proof"}),
            state.height + state.config.auction_window_blocks + 2,
        )?;
        let liquidation_fill_id = state.insert_fill(liquidation_fill)?;
        state.pay_rebate(
            &liquidation_pool_id,
            &liquidation_bundle_id,
            &liquidation_fill_id,
            &solver_commitment_id,
            90_000,
            &json!({"settlement": "paid-liquidation-protection-rebate"}),
        )?;

        let post_trade = PostTradePrivacyReceipt::new(
            low_fee_fill_id.clone(),
            low_fee_bundle_id.clone(),
            PrivacyReceiptAudience::Trader,
            "devnet-bob",
            &json!({
                "fill": low_fee_fill_id,
                "price_bucket": "uniform-clearing",
                "rebate": "paid",
            }),
            &json!({
                "release": "after_receipt_delay",
                "auditor_can_verify_roots": true,
            }),
            state.height + state.config.receipt_delay_blocks,
            state.height + state.config.receipt_delay_blocks + 10_000,
        )?;
        let receipt_id = state.insert_post_trade_receipt(post_trade.clone())?;
        let delayed = DelayedRevealReceipt::new(
            &post_trade,
            &json!({"delayed": "private-fill-view-key", "receipt": receipt_id}),
            &json!({"height": post_trade.release_at_height, "audience": "trader"}),
        )?;
        state.insert_delayed_reveal_receipt(delayed)?;

        let slash = SolverSlashEvidence::new(
            SlashingEvidenceKind::SandwichViolation,
            "devnet-solver-b",
            auction_id.clone(),
            Some(solver_commitment_id.clone()),
            Some(low_fee_bundle_id.clone()),
            &json!({"pre": "devnet-auction-pre-state"}),
            &json!({"claimed": "conflicting-clearing-price"}),
            &json!({
                "violation": "attempted-backrun",
                "bundle": low_fee_bundle_id,
                "policy": dex_policy_id,
            }),
            &json!({"watchtower": "devnet-watchtower-a", "proof": "price-time-conflict"}),
            "devnet-watchtower-a",
            500_000,
            state.height + state.config.auction_window_blocks + 3,
        )?;
        state.insert_slashing_evidence(slash)?;

        for (object_kind, object_id, record) in [
            (
                "threshold_key_epoch",
                key_epoch_id.as_str(),
                state.key_epochs[&key_epoch_id].public_record(),
            ),
            (
                "fair_batch_auction_epoch",
                auction_id.as_str(),
                state.auction_epochs[&auction_id].public_record(),
            ),
            (
                "solver_commitment",
                solver_commitment_id.as_str(),
                state.solver_commitments[&solver_commitment_id].public_record(),
            ),
        ] {
            state.publish_public_record(object_kind, object_id, &record)?;
        }

        let audit = PrivateMevAuditRecord::new(
            "fair_batch_auction_epoch",
            auction_id.clone(),
            AuditSeverity::Info,
            "devnet_fixture",
            &state.auction_epochs[&auction_id].public_record(),
            &json!({
                "checks": [
                    "uniform-clearing-price",
                    "no-same-solver-pre-post",
                    "rebate-paid",
                    "delayed-receipt-present"
                ],
            }),
            state.state_root(),
            state.height,
            &json!({"note": "private mev guard devnet fixture"}),
        )?;
        state.insert_audit_record(audit)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateMevGuardResult<String> {
        self.height = height;
        for bundle in self.encrypted_bundles.values_mut() {
            if bundle.expired_at(height) {
                bundle.status = EncryptedBundleStatus::Expired;
            }
        }
        for constraint in self.inclusion_constraints.values_mut() {
            if height > constraint.max_inclusion_height
                && matches!(
                    constraint.status,
                    InclusionConstraintStatus::Pending | InclusionConstraintStatus::Bound
                )
            {
                constraint.status = InclusionConstraintStatus::Expired;
            }
        }
        for epoch in self.auction_epochs.values_mut() {
            if epoch.status == FairAuctionEpochStatus::Collecting
                && height > epoch.commit_end_height
            {
                epoch.status = FairAuctionEpochStatus::CommitLocked;
            }
            if epoch.status == FairAuctionEpochStatus::CommitLocked
                && height >= epoch.reveal_start_height
            {
                epoch.status = FairAuctionEpochStatus::Revealing;
            }
            if epoch.status == FairAuctionEpochStatus::Revealing && height > epoch.reveal_end_height
            {
                epoch.status = FairAuctionEpochStatus::Solving;
            }
            if epoch.status == FairAuctionEpochStatus::Solving
                && height > epoch.challenge_deadline_height
            {
                epoch.status = FairAuctionEpochStatus::Finalized;
            }
        }
        for pool in self.rebate_pools.values_mut() {
            if height >= pool.expires_at_height && pool.status == RebatePoolStatus::Active {
                pool.status = RebatePoolStatus::Draining;
            }
        }
        for lane in self.low_fee_lanes.values_mut() {
            if height >= lane.expires_at_height {
                lane.status = LowFeeLaneStatus::Expired;
            }
        }
        for receipt in self.post_trade_receipts.values_mut() {
            if height >= receipt.release_at_height
                && receipt.status == PrivacyReceiptStatus::Committed
            {
                receipt.status = PrivacyReceiptStatus::Releasable;
            }
        }
        for receipt in self.delayed_reveal_receipts.values_mut() {
            if height >= receipt.release_at_height
                && receipt.status == PrivacyReceiptStatus::Committed
            {
                receipt.status = PrivacyReceiptStatus::Releasable;
            }
        }
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn next_epoch_sequence(&mut self) -> u64 {
        let sequence = self.next_epoch_sequence;
        self.next_epoch_sequence = self.next_epoch_sequence.saturating_add(1);
        sequence
    }

    pub fn insert_key_epoch(
        &mut self,
        epoch: ThresholdEncryptionKeyEpoch,
    ) -> PrivateMevGuardResult<String> {
        epoch.validate()?;
        let epoch_id = epoch.key_epoch_id.clone();
        self.key_epochs.insert(epoch_id.clone(), epoch);
        Ok(epoch_id)
    }

    pub fn insert_anti_sandwich_policy(
        &mut self,
        policy: AntiSandwichPolicy,
    ) -> PrivateMevGuardResult<String> {
        policy.validate()?;
        let policy_id = policy.policy_id.clone();
        self.anti_sandwich_policies
            .insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn insert_encrypted_bundle(
        &mut self,
        bundle: EncryptedOrderBundle,
    ) -> PrivateMevGuardResult<String> {
        bundle.validate()?;
        if bundle.payload_size_bytes > self.config.max_bundle_bytes {
            return Err("encrypted bundle exceeds configured max bytes".to_string());
        }
        if !self.key_epochs.contains_key(&bundle.threshold_key_epoch_id) {
            return Err("encrypted bundle references unknown threshold key epoch".to_string());
        }
        if !self
            .anti_sandwich_policies
            .contains_key(&bundle.anti_sandwich_policy_id)
        {
            return Err("encrypted bundle references unknown anti sandwich policy".to_string());
        }
        if let Some(lane_id) = &bundle.low_fee_lane_id {
            if !self.low_fee_lanes.contains_key(lane_id) {
                return Err("encrypted bundle references unknown low fee lane".to_string());
            }
        }
        let bundle_id = bundle.bundle_id.clone();
        self.encrypted_bundles.insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn insert_inclusion_constraint(
        &mut self,
        constraint: InclusionConstraint,
    ) -> PrivateMevGuardResult<String> {
        constraint.validate()?;
        if !self.encrypted_bundles.contains_key(&constraint.bundle_id) {
            return Err("inclusion constraint references unknown bundle".to_string());
        }
        let constraint_id = constraint.constraint_id.clone();
        self.inclusion_constraints
            .insert(constraint_id.clone(), constraint);
        Ok(constraint_id)
    }

    pub fn insert_auction_epoch(
        &mut self,
        epoch: FairBatchAuctionEpoch,
    ) -> PrivateMevGuardResult<String> {
        epoch.validate()?;
        let epoch_id = epoch.epoch_id.clone();
        self.auction_epochs.insert(epoch_id.clone(), epoch);
        Ok(epoch_id)
    }

    pub fn insert_solver_commitment(
        &mut self,
        commitment: PrivateSolverCommitment,
    ) -> PrivateMevGuardResult<String> {
        commitment.validate()?;
        if !self.auction_epochs.contains_key(&commitment.epoch_id) {
            return Err("solver commitment references unknown auction epoch".to_string());
        }
        let commitment_id = commitment.commitment_id.clone();
        self.solver_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn insert_solver_opening(
        &mut self,
        opening: PrivateSolverOpening,
    ) -> PrivateMevGuardResult<String> {
        opening.validate()?;
        if !self.solver_commitments.contains_key(&opening.commitment_id) {
            return Err("solver opening references unknown commitment".to_string());
        }
        let opening_id = opening.opening_id.clone();
        if let Some(commitment) = self.solver_commitments.get_mut(&opening.commitment_id) {
            commitment.status = if opening.accepted {
                SolverCommitmentStatus::Accepted
            } else {
                SolverCommitmentStatus::Opened
            };
        }
        self.solver_openings.insert(opening_id.clone(), opening);
        Ok(opening_id)
    }

    pub fn insert_rebate_pool(&mut self, pool: RebatePool) -> PrivateMevGuardResult<String> {
        pool.validate()?;
        let pool_id = pool.pool_id.clone();
        self.rebate_pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }

    pub fn insert_low_fee_lane(
        &mut self,
        lane: PrivateMevLowFeeLane,
    ) -> PrivateMevGuardResult<String> {
        lane.validate()?;
        if !self.config.enable_low_fee_lanes {
            return Err("private mev guard low fee lanes are disabled".to_string());
        }
        if !self.rebate_pools.contains_key(&lane.rebate_pool_id) {
            return Err("low fee lane references unknown rebate pool".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.low_fee_lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn reserve_low_fee_capacity(
        &mut self,
        lane_id: &str,
        units: u64,
    ) -> PrivateMevGuardResult<()> {
        let lane = self
            .low_fee_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown low fee lane".to_string())?;
        lane.reserve_capacity(units)
    }

    pub fn reserve_rebate(
        &mut self,
        pool_id: &str,
        bundle_id: &str,
        amount_units: u64,
        note: &Value,
    ) -> PrivateMevGuardResult<RebateAccountingEntry> {
        if !self.encrypted_bundles.contains_key(bundle_id) {
            return Err("rebate reservation references unknown bundle".to_string());
        }
        let pool = self
            .rebate_pools
            .get_mut(pool_id)
            .ok_or_else(|| "unknown rebate pool".to_string())?;
        let pre_available_units = pool.available_units;
        pool.reserve(amount_units)?;
        let entry = RebateAccountingEntry::new(
            pool_id,
            Some(bundle_id.to_string()),
            None,
            None,
            RebateAccountingKind::Reserved,
            pool.asset_id.clone(),
            amount_units,
            pre_available_units,
            pool.available_units,
            self.height,
            note,
        )?;
        let entry_id = entry.entry_id.clone();
        self.rebate_accounting.insert(entry_id, entry.clone());
        Ok(entry)
    }

    pub fn pay_rebate(
        &mut self,
        pool_id: &str,
        bundle_id: &str,
        fill_id: &str,
        solver_commitment_id: &str,
        amount_units: u64,
        note: &Value,
    ) -> PrivateMevGuardResult<RebateAccountingEntry> {
        if !self.encrypted_bundles.contains_key(bundle_id) {
            return Err("rebate payment references unknown bundle".to_string());
        }
        if !self.fills.contains_key(fill_id) {
            return Err("rebate payment references unknown fill".to_string());
        }
        if !self.solver_commitments.contains_key(solver_commitment_id) {
            return Err("rebate payment references unknown solver commitment".to_string());
        }
        let pool = self
            .rebate_pools
            .get_mut(pool_id)
            .ok_or_else(|| "unknown rebate pool".to_string())?;
        let pre_available_units = pool.available_units;
        pool.pay(amount_units)?;
        let entry = RebateAccountingEntry::new(
            pool_id,
            Some(bundle_id.to_string()),
            Some(fill_id.to_string()),
            Some(solver_commitment_id.to_string()),
            RebateAccountingKind::Paid,
            pool.asset_id.clone(),
            amount_units,
            pre_available_units,
            pool.available_units,
            self.height,
            note,
        )?;
        let entry_id = entry.entry_id.clone();
        self.rebate_accounting.insert(entry_id, entry.clone());
        Ok(entry)
    }

    pub fn insert_fill(&mut self, fill: PrivacyPreservingFill) -> PrivateMevGuardResult<String> {
        fill.validate()?;
        if !self.encrypted_bundles.contains_key(&fill.bundle_id) {
            return Err("fill references unknown bundle".to_string());
        }
        if !self.auction_epochs.contains_key(&fill.epoch_id) {
            return Err("fill references unknown auction epoch".to_string());
        }
        if !self
            .solver_commitments
            .contains_key(&fill.solver_commitment_id)
        {
            return Err("fill references unknown solver commitment".to_string());
        }
        let fill_id = fill.fill_id.clone();
        if let Some(bundle) = self.encrypted_bundles.get_mut(&fill.bundle_id) {
            bundle.status = EncryptedBundleStatus::Filled;
        }
        self.fills.insert(fill_id.clone(), fill);
        Ok(fill_id)
    }

    pub fn insert_post_trade_receipt(
        &mut self,
        receipt: PostTradePrivacyReceipt,
    ) -> PrivateMevGuardResult<String> {
        receipt.validate()?;
        if !self.fills.contains_key(&receipt.fill_id) {
            return Err("post trade receipt references unknown fill".to_string());
        }
        if !self.encrypted_bundles.contains_key(&receipt.bundle_id) {
            return Err("post trade receipt references unknown bundle".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.post_trade_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_delayed_reveal_receipt(
        &mut self,
        receipt: DelayedRevealReceipt,
    ) -> PrivateMevGuardResult<String> {
        receipt.validate()?;
        if !self.post_trade_receipts.contains_key(&receipt.receipt_id) {
            return Err("delayed reveal references unknown post trade receipt".to_string());
        }
        let reveal_id = receipt.reveal_id.clone();
        self.delayed_reveal_receipts
            .insert(reveal_id.clone(), receipt);
        Ok(reveal_id)
    }

    pub fn insert_slashing_evidence(
        &mut self,
        evidence: SolverSlashEvidence,
    ) -> PrivateMevGuardResult<String> {
        evidence.validate()?;
        if !self.auction_epochs.contains_key(&evidence.epoch_id) {
            return Err("slashing evidence references unknown auction epoch".to_string());
        }
        if let Some(commitment_id) = &evidence.commitment_id {
            if !self.solver_commitments.contains_key(commitment_id) {
                return Err("slashing evidence references unknown solver commitment".to_string());
            }
        }
        if let Some(bundle_id) = &evidence.bundle_id {
            if !self.encrypted_bundles.contains_key(bundle_id) {
                return Err("slashing evidence references unknown bundle".to_string());
            }
        }
        let evidence_id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn insert_audit_record(
        &mut self,
        record: PrivateMevAuditRecord,
    ) -> PrivateMevGuardResult<String> {
        record.validate()?;
        let record_id = record.audit_record_id.clone();
        self.audit_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        record: &Value,
    ) -> PrivateMevGuardResult<String> {
        ensure_non_empty(object_kind, "public record object kind")?;
        ensure_non_empty(object_id, "public record object id")?;
        let envelope = json!({
            "kind": "private_mev_guard_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "object_kind": object_kind,
            "object_id": object_id,
            "record_root": private_mev_guard_record_id("PRIVATE-MEV-GUARD-PUBLISHED-RECORD", record),
            "recorded_at_height": self.height,
        });
        let record_id =
            private_mev_guard_record_id("PRIVATE-MEV-GUARD-PUBLIC-RECORD-ID", &envelope);
        self.public_records.insert(record_id.clone(), envelope);
        Ok(record_id)
    }

    pub fn refresh_auction_roots(&mut self, epoch_id: &str) -> PrivateMevGuardResult<String> {
        let solver_commitment_root = self.solver_commitment_root();
        let solver_opening_root = self.solver_opening_root();
        let clearing_price_commitment =
            private_mev_guard_string_commitment("clearing_price", &solver_opening_root);
        let auction = self
            .auction_epochs
            .get_mut(epoch_id)
            .ok_or_else(|| "unknown auction epoch".to_string())?;
        auction.seal(
            solver_commitment_root,
            solver_opening_root,
            clearing_price_commitment,
        )
    }

    pub fn key_epoch_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-KEY-EPOCHS",
            self.key_epochs
                .values()
                .map(ThresholdEncryptionKeyEpoch::public_record)
                .collect(),
        )
    }

    pub fn encrypted_bundle_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-ENCRYPTED-BUNDLES",
            self.encrypted_bundles
                .values()
                .map(EncryptedOrderBundle::public_record)
                .collect(),
        )
    }

    pub fn anti_sandwich_policy_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-ANTI-SANDWICH-POLICIES",
            self.anti_sandwich_policies
                .values()
                .map(AntiSandwichPolicy::public_record)
                .collect(),
        )
    }

    pub fn inclusion_constraint_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-INCLUSION-CONSTRAINTS",
            self.inclusion_constraints
                .values()
                .map(InclusionConstraint::public_record)
                .collect(),
        )
    }

    pub fn auction_epoch_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-AUCTION-EPOCHS",
            self.auction_epochs
                .values()
                .map(FairBatchAuctionEpoch::public_record)
                .collect(),
        )
    }

    pub fn solver_commitment_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-SOLVER-COMMITMENTS",
            self.solver_commitments
                .values()
                .map(PrivateSolverCommitment::public_record)
                .collect(),
        )
    }

    pub fn solver_opening_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-SOLVER-OPENINGS",
            self.solver_openings
                .values()
                .map(PrivateSolverOpening::public_record)
                .collect(),
        )
    }

    pub fn rebate_pool_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-REBATE-POOLS",
            self.rebate_pools
                .values()
                .map(RebatePool::public_record)
                .collect(),
        )
    }

    pub fn rebate_accounting_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-REBATE-ACCOUNTING",
            self.rebate_accounting
                .values()
                .map(RebateAccountingEntry::public_record)
                .collect(),
        )
    }

    pub fn low_fee_lane_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-LOW-FEE-LANES",
            self.low_fee_lanes
                .values()
                .map(PrivateMevLowFeeLane::public_record)
                .collect(),
        )
    }

    pub fn fill_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-FILLS",
            self.fills
                .values()
                .map(PrivacyPreservingFill::public_record)
                .collect(),
        )
    }

    pub fn post_trade_receipt_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-POST-TRADE-RECEIPTS",
            self.post_trade_receipts
                .values()
                .map(PostTradePrivacyReceipt::public_record)
                .collect(),
        )
    }

    pub fn delayed_reveal_receipt_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-DELAYED-REVEAL-RECEIPTS",
            self.delayed_reveal_receipts
                .values()
                .map(DelayedRevealReceipt::public_record)
                .collect(),
        )
    }

    pub fn slashing_evidence_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SolverSlashEvidence::public_record)
                .collect(),
        )
    }

    pub fn audit_record_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-AUDIT-RECORDS",
            self.audit_records
                .values()
                .map(PrivateMevAuditRecord::public_record)
                .collect(),
        )
    }

    pub fn public_record_root(&self) -> String {
        private_mev_guard_map_root(
            "PRIVATE-MEV-GUARD-PUBLIC-RECORDS",
            self.public_records.values().cloned().collect(),
        )
    }

    pub fn roots(&self) -> PrivateMevGuardRoots {
        let config_root = self.config.config_root();
        let key_epoch_root = self.key_epoch_root();
        let encrypted_bundle_root = self.encrypted_bundle_root();
        let anti_sandwich_policy_root = self.anti_sandwich_policy_root();
        let inclusion_constraint_root = self.inclusion_constraint_root();
        let auction_epoch_root = self.auction_epoch_root();
        let solver_commitment_root = self.solver_commitment_root();
        let solver_opening_root = self.solver_opening_root();
        let rebate_pool_root = self.rebate_pool_root();
        let rebate_accounting_root = self.rebate_accounting_root();
        let low_fee_lane_root = self.low_fee_lane_root();
        let fill_root = self.fill_root();
        let post_trade_receipt_root = self.post_trade_receipt_root();
        let delayed_reveal_receipt_root = self.delayed_reveal_receipt_root();
        let slashing_evidence_root = self.slashing_evidence_root();
        let audit_record_root = self.audit_record_root();
        let public_record_root = self.public_record_root();
        let state_record = json!({
            "kind": "private_mev_guard_state_root_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "height": self.height,
            "operator_label_root": private_mev_guard_string_commitment("operator_label", &self.operator_label),
            "next_epoch_sequence": self.next_epoch_sequence,
            "config_root": config_root,
            "key_epoch_root": key_epoch_root,
            "encrypted_bundle_root": encrypted_bundle_root,
            "anti_sandwich_policy_root": anti_sandwich_policy_root,
            "inclusion_constraint_root": inclusion_constraint_root,
            "auction_epoch_root": auction_epoch_root,
            "solver_commitment_root": solver_commitment_root,
            "solver_opening_root": solver_opening_root,
            "rebate_pool_root": rebate_pool_root,
            "rebate_accounting_root": rebate_accounting_root,
            "low_fee_lane_root": low_fee_lane_root,
            "fill_root": fill_root,
            "post_trade_receipt_root": post_trade_receipt_root,
            "delayed_reveal_receipt_root": delayed_reveal_receipt_root,
            "slashing_evidence_root": slashing_evidence_root,
            "audit_record_root": audit_record_root,
            "public_record_root": public_record_root,
            "counters": self.counters().public_record(),
        });
        let state_root = private_mev_guard_state_root_from_record(&state_record);
        PrivateMevGuardRoots {
            config_root,
            key_epoch_root,
            encrypted_bundle_root,
            anti_sandwich_policy_root,
            inclusion_constraint_root,
            auction_epoch_root,
            solver_commitment_root,
            solver_opening_root,
            rebate_pool_root,
            rebate_accounting_root,
            low_fee_lane_root,
            fill_root,
            post_trade_receipt_root,
            delayed_reveal_receipt_root,
            slashing_evidence_root,
            audit_record_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateMevGuardCounters {
        let mut counters = PrivateMevGuardCounters {
            height: self.height,
            key_epoch_count: self.key_epochs.len() as u64,
            encrypted_bundle_count: self.encrypted_bundles.len() as u64,
            anti_sandwich_policy_count: self.anti_sandwich_policies.len() as u64,
            inclusion_constraint_count: self.inclusion_constraints.len() as u64,
            auction_epoch_count: self.auction_epochs.len() as u64,
            solver_commitment_count: self.solver_commitments.len() as u64,
            solver_opening_count: self.solver_openings.len() as u64,
            rebate_pool_count: self.rebate_pools.len() as u64,
            rebate_accounting_entry_count: self.rebate_accounting.len() as u64,
            low_fee_lane_count: self.low_fee_lanes.len() as u64,
            fill_count: self.fills.len() as u64,
            post_trade_receipt_count: self.post_trade_receipts.len() as u64,
            delayed_reveal_receipt_count: self.delayed_reveal_receipts.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            audit_record_count: self.audit_records.len() as u64,
            public_record_count: self.public_records.len() as u64,
            ..PrivateMevGuardCounters::default()
        };
        for epoch in self.key_epochs.values() {
            if epoch.active_at(self.height) {
                counters.active_key_epoch_count += 1;
            }
        }
        for bundle in self.encrypted_bundles.values() {
            if bundle.status.active() {
                counters.active_bundle_count += 1;
            }
            if bundle.status == EncryptedBundleStatus::Filled {
                counters.filled_bundle_count += 1;
            }
            if bundle.status == EncryptedBundleStatus::Expired {
                counters.expired_bundle_count += 1;
            }
            counters.total_payload_bytes = counters
                .total_payload_bytes
                .saturating_add(bundle.payload_size_bytes);
            counters.total_max_fee_micro_units = counters
                .total_max_fee_micro_units
                .saturating_add(bundle.max_fee_micro_units);
        }
        for constraint in self.inclusion_constraints.values() {
            if constraint.status == InclusionConstraintStatus::Satisfied {
                counters.satisfied_constraint_count += 1;
            }
        }
        for epoch in self.auction_epochs.values() {
            if epoch.status.active() {
                counters.active_auction_epoch_count += 1;
            }
            if epoch.status == FairAuctionEpochStatus::Finalized {
                counters.finalized_auction_epoch_count += 1;
            }
        }
        for commitment in self.solver_commitments.values() {
            if commitment.status == SolverCommitmentStatus::Accepted {
                counters.accepted_solver_commitment_count += 1;
            }
        }
        for opening in self.solver_openings.values() {
            if opening.accepted {
                counters.accepted_solver_opening_count += 1;
            }
        }
        for pool in self.rebate_pools.values() {
            if pool.active_at(self.height) {
                counters.active_rebate_pool_count += 1;
            }
            counters.rebate_available_units = counters
                .rebate_available_units
                .saturating_add(pool.available_units);
            counters.rebate_reserved_units = counters
                .rebate_reserved_units
                .saturating_add(pool.reserved_units);
            counters.rebate_paid_units = counters.rebate_paid_units.saturating_add(pool.paid_units);
            counters.rebate_slashed_units = counters
                .rebate_slashed_units
                .saturating_add(pool.slashed_units);
        }
        for lane in self.low_fee_lanes.values() {
            if lane.active_at(self.height) {
                counters.active_low_fee_lane_count += 1;
            }
        }
        for fill in self.fills.values() {
            if fill.status == FillStatus::Settled {
                counters.settled_fill_count += 1;
            }
        }
        for receipt in self.post_trade_receipts.values() {
            if receipt.status == PrivacyReceiptStatus::Releasable {
                counters.releasable_receipt_count += 1;
            }
        }
        for receipt in self.delayed_reveal_receipts.values() {
            if receipt.status == PrivacyReceiptStatus::Releasable {
                counters.releasable_receipt_count += 1;
            }
        }
        for evidence in self.slashing_evidence.values() {
            if evidence.status == SlashingEvidenceStatus::Accepted
                || evidence.status == SlashingEvidenceStatus::Executed
            {
                counters.accepted_slashing_evidence_count += 1;
            }
        }
        counters
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_mev_guard_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
            "height": self.height,
            "operator_label": self.operator_label,
            "next_epoch_sequence": self.next_epoch_sequence,
            "config": self.config.public_record(),
            "key_epochs": self.key_epochs.values().map(ThresholdEncryptionKeyEpoch::public_record).collect::<Vec<_>>(),
            "encrypted_bundles": self.encrypted_bundles.values().map(EncryptedOrderBundle::public_record).collect::<Vec<_>>(),
            "anti_sandwich_policies": self.anti_sandwich_policies.values().map(AntiSandwichPolicy::public_record).collect::<Vec<_>>(),
            "inclusion_constraints": self.inclusion_constraints.values().map(InclusionConstraint::public_record).collect::<Vec<_>>(),
            "auction_epochs": self.auction_epochs.values().map(FairBatchAuctionEpoch::public_record).collect::<Vec<_>>(),
            "solver_commitments": self.solver_commitments.values().map(PrivateSolverCommitment::public_record).collect::<Vec<_>>(),
            "solver_openings": self.solver_openings.values().map(PrivateSolverOpening::public_record).collect::<Vec<_>>(),
            "rebate_pools": self.rebate_pools.values().map(RebatePool::public_record).collect::<Vec<_>>(),
            "rebate_accounting": self.rebate_accounting.values().map(RebateAccountingEntry::public_record).collect::<Vec<_>>(),
            "low_fee_lanes": self.low_fee_lanes.values().map(PrivateMevLowFeeLane::public_record).collect::<Vec<_>>(),
            "fills": self.fills.values().map(PrivacyPreservingFill::public_record).collect::<Vec<_>>(),
            "post_trade_receipts": self.post_trade_receipts.values().map(PostTradePrivacyReceipt::public_record).collect::<Vec<_>>(),
            "delayed_reveal_receipts": self.delayed_reveal_receipts.values().map(DelayedRevealReceipt::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(SolverSlashEvidence::public_record).collect::<Vec<_>>(),
            "audit_records": self.audit_records.values().map(PrivateMevAuditRecord::public_record).collect::<Vec<_>>(),
            "public_record_count": self.public_records.len(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> PrivateMevGuardResult<String> {
        ensure_non_empty(&self.operator_label, "private mev guard operator label")?;
        self.config.validate()?;
        if self.key_epochs.len() > PRIVATE_MEV_GUARD_MAX_KEY_EPOCHS {
            return Err("private mev guard has too many key epochs".to_string());
        }
        if self.encrypted_bundles.len() > PRIVATE_MEV_GUARD_MAX_BUNDLES {
            return Err("private mev guard has too many encrypted bundles".to_string());
        }
        if self.anti_sandwich_policies.len() > PRIVATE_MEV_GUARD_MAX_POLICIES {
            return Err("private mev guard has too many anti sandwich policies".to_string());
        }
        if self.inclusion_constraints.len() > PRIVATE_MEV_GUARD_MAX_CONSTRAINTS {
            return Err("private mev guard has too many inclusion constraints".to_string());
        }
        if self.auction_epochs.len() > PRIVATE_MEV_GUARD_MAX_AUCTIONS {
            return Err("private mev guard has too many auction epochs".to_string());
        }
        if self.solver_commitments.len() > PRIVATE_MEV_GUARD_MAX_SOLVER_COMMITMENTS {
            return Err("private mev guard has too many solver commitments".to_string());
        }
        if self.rebate_pools.len() > PRIVATE_MEV_GUARD_MAX_REBATE_POOLS {
            return Err("private mev guard has too many rebate pools".to_string());
        }
        if self.rebate_accounting.len() > PRIVATE_MEV_GUARD_MAX_REBATE_ENTRIES {
            return Err("private mev guard has too many rebate accounting entries".to_string());
        }
        if self.low_fee_lanes.len() > PRIVATE_MEV_GUARD_MAX_LOW_FEE_LANES {
            return Err("private mev guard has too many low fee lanes".to_string());
        }
        if self.fills.len() > PRIVATE_MEV_GUARD_MAX_FILLS {
            return Err("private mev guard has too many fills".to_string());
        }
        if self.post_trade_receipts.len() + self.delayed_reveal_receipts.len()
            > PRIVATE_MEV_GUARD_MAX_RECEIPTS
        {
            return Err("private mev guard has too many privacy receipts".to_string());
        }
        if self.slashing_evidence.len() > PRIVATE_MEV_GUARD_MAX_SLASHING_EVIDENCE {
            return Err("private mev guard has too much slashing evidence".to_string());
        }
        if self.audit_records.len() > PRIVATE_MEV_GUARD_MAX_AUDIT_RECORDS {
            return Err("private mev guard has too many audit records".to_string());
        }
        for epoch in self.key_epochs.values() {
            epoch.validate()?;
        }
        for policy in self.anti_sandwich_policies.values() {
            policy.validate()?;
        }
        for lane in self.low_fee_lanes.values() {
            lane.validate()?;
            if !self.rebate_pools.contains_key(&lane.rebate_pool_id) {
                return Err("low fee lane references missing rebate pool".to_string());
            }
        }
        for bundle in self.encrypted_bundles.values() {
            bundle.validate()?;
            if bundle.payload_size_bytes > self.config.max_bundle_bytes {
                return Err("encrypted bundle exceeds configured max bytes".to_string());
            }
            if !self.key_epochs.contains_key(&bundle.threshold_key_epoch_id) {
                return Err("encrypted bundle references missing key epoch".to_string());
            }
            let policy = self
                .anti_sandwich_policies
                .get(&bundle.anti_sandwich_policy_id)
                .ok_or_else(|| "encrypted bundle references missing policy".to_string())?;
            if !policy.protects_lane(bundle.lane_kind) {
                return Err("encrypted bundle lane is not protected by policy".to_string());
            }
            if bundle.max_price_impact_bps > policy.max_price_impact_bps {
                return Err("encrypted bundle price impact exceeds policy".to_string());
            }
            if let Some(lane_id) = &bundle.low_fee_lane_id {
                let lane = self.low_fee_lanes.get(lane_id).ok_or_else(|| {
                    "encrypted bundle references missing low fee lane".to_string()
                })?;
                if lane.lane_kind != bundle.lane_kind {
                    return Err("encrypted bundle low fee lane kind mismatch".to_string());
                }
                if bundle.max_fee_micro_units > lane.max_fee_micro_units {
                    return Err("encrypted bundle exceeds low fee lane fee ceiling".to_string());
                }
            }
            if let Some(constraint_id) = &bundle.inclusion_constraint_id {
                if !self.inclusion_constraints.contains_key(constraint_id) {
                    return Err(
                        "encrypted bundle references missing inclusion constraint".to_string()
                    );
                }
            }
        }
        for constraint in self.inclusion_constraints.values() {
            constraint.validate()?;
            if !self.encrypted_bundles.contains_key(&constraint.bundle_id) {
                return Err("inclusion constraint references missing bundle".to_string());
            }
        }
        for epoch in self.auction_epochs.values() {
            epoch.validate()?;
        }
        for commitment in self.solver_commitments.values() {
            commitment.validate()?;
            if !self.auction_epochs.contains_key(&commitment.epoch_id) {
                return Err("solver commitment references missing auction".to_string());
            }
        }
        for opening in self.solver_openings.values() {
            opening.validate()?;
            if !self.solver_commitments.contains_key(&opening.commitment_id) {
                return Err("solver opening references missing commitment".to_string());
            }
        }
        for pool in self.rebate_pools.values() {
            pool.validate()?;
        }
        for entry in self.rebate_accounting.values() {
            entry.validate()?;
            if !self.rebate_pools.contains_key(&entry.pool_id) {
                return Err("rebate accounting references missing pool".to_string());
            }
            if let Some(bundle_id) = &entry.bundle_id {
                if !self.encrypted_bundles.contains_key(bundle_id) {
                    return Err("rebate accounting references missing bundle".to_string());
                }
            }
            if let Some(fill_id) = &entry.fill_id {
                if !self.fills.contains_key(fill_id) {
                    return Err("rebate accounting references missing fill".to_string());
                }
            }
            if let Some(commitment_id) = &entry.solver_commitment_id {
                if !self.solver_commitments.contains_key(commitment_id) {
                    return Err(
                        "rebate accounting references missing solver commitment".to_string()
                    );
                }
            }
        }
        for fill in self.fills.values() {
            fill.validate()?;
            if !self.encrypted_bundles.contains_key(&fill.bundle_id) {
                return Err("fill references missing bundle".to_string());
            }
            if !self.auction_epochs.contains_key(&fill.epoch_id) {
                return Err("fill references missing auction".to_string());
            }
            if !self
                .solver_commitments
                .contains_key(&fill.solver_commitment_id)
            {
                return Err("fill references missing solver commitment".to_string());
            }
        }
        for receipt in self.post_trade_receipts.values() {
            receipt.validate()?;
            if !self.fills.contains_key(&receipt.fill_id) {
                return Err("post trade receipt references missing fill".to_string());
            }
            if !self.encrypted_bundles.contains_key(&receipt.bundle_id) {
                return Err("post trade receipt references missing bundle".to_string());
            }
        }
        for receipt in self.delayed_reveal_receipts.values() {
            receipt.validate()?;
            if !self.post_trade_receipts.contains_key(&receipt.receipt_id) {
                return Err("delayed reveal receipt references missing receipt".to_string());
            }
            if !self.fills.contains_key(&receipt.fill_id) {
                return Err("delayed reveal receipt references missing fill".to_string());
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
            if !self.auction_epochs.contains_key(&evidence.epoch_id) {
                return Err("slashing evidence references missing auction".to_string());
            }
        }
        for record in self.audit_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn private_mev_guard_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_mev_guard_record_id(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_mev_guard_string_commitment(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-STRING-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_mev_guard_payload_root(kind: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_mev_guard_empty_root(label: &str) -> String {
    merkle_root(&format!("PRIVATE-MEV-GUARD-EMPTY-{label}"), &[])
}

pub fn private_mev_guard_map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn private_mev_guard_string_list_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| {
            json!({
                "kind": "private_mev_guard_string_leaf",
                "chain_id": CHAIN_ID,
                "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn private_mev_guard_lane_root(lanes: &[PrivateMevLaneKind]) -> String {
    let leaves = lanes
        .iter()
        .map(|lane| {
            json!({
                "kind": "private_mev_guard_lane_leaf",
                "chain_id": CHAIN_ID,
                "protocol_version": PRIVATE_MEV_GUARD_PROTOCOL_VERSION,
                "lane": lane.as_str(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-MEV-GUARD-LANE-ROOT", &leaves)
}

pub fn private_mev_guard_key_epoch_id(
    committee_id: &str,
    aggregate_public_key_root: &str,
    member_public_key_root: &str,
    threshold: u64,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-KEY-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(committee_id),
            HashPart::Str(aggregate_public_key_root),
            HashPart::Str(member_public_key_root),
            HashPart::Int(threshold as i128),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_anti_sandwich_policy_id(
    policy_kind: AntiSandwichPolicyKind,
    protected_pair_commitment: &str,
    min_batch_depth: u64,
    max_price_impact_bps: u64,
    min_surplus_rebate_bps: u64,
    lane_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-ANTI-SANDWICH-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(policy_kind.as_str()),
            HashPart::Str(protected_pair_commitment),
            HashPart::Int(min_batch_depth as i128),
            HashPart::Int(max_price_impact_bps as i128),
            HashPart::Int(min_surplus_rebate_bps as i128),
            HashPart::Str(lane_root),
        ],
        32,
    )
}

pub fn private_mev_guard_bundle_id(
    bundle_kind: PrivateMevBundleKind,
    lane_kind: PrivateMevLaneKind,
    owner_commitment: &str,
    market_pair_commitment: &str,
    encrypted_payload_root: &str,
    deadline_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(bundle_kind.as_str()),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(market_pair_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_replay_nullifier(
    owner_commitment: &str,
    strategy_commitment: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-REPLAY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(owner_commitment),
            HashPart::Str(strategy_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_inclusion_constraint_id(
    bundle_id: &str,
    lane_kind: PrivateMevLaneKind,
    min_inclusion_height: u64,
    max_inclusion_height: u64,
    fair_queue_position: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-INCLUSION-CONSTRAINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(bundle_id),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Int(min_inclusion_height as i128),
            HashPart::Int(max_inclusion_height as i128),
            HashPart::Int(fair_queue_position as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_ordering_seed(
    venue_kind: PrivateMevVenueKind,
    market_pair_commitment: &str,
    sequence: u64,
    bundle_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-ORDERING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(venue_kind.as_str()),
            HashPart::Str(market_pair_commitment),
            HashPart::Int(sequence as i128),
            HashPart::Str(bundle_root),
        ],
        32,
    )
}

pub fn private_mev_guard_auction_epoch_id(
    sequence: u64,
    venue_kind: PrivateMevVenueKind,
    market_pair_commitment: &str,
    bundle_root: &str,
    commit_start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-AUCTION-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(venue_kind.as_str()),
            HashPart::Str(market_pair_commitment),
            HashPart::Str(bundle_root),
            HashPart::Int(commit_start_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_solver_commitment_id(
    epoch_id: &str,
    solver_commitment: &str,
    encrypted_solution_root: &str,
    bundle_set_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(epoch_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(encrypted_solution_root),
            HashPart::Str(bundle_set_root),
            HashPart::Int(committed_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_solver_opening_id(
    commitment_id: &str,
    epoch_id: &str,
    execution_plan_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-SOLVER-OPENING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(commitment_id),
            HashPart::Str(epoch_id),
            HashPart::Str(execution_plan_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_rebate_pool_id(
    lane_kind: PrivateMevLaneKind,
    sponsor_commitment: &str,
    asset_commitment: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-REBATE-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(asset_commitment),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_low_fee_lane_id(
    lane_kind: PrivateMevLaneKind,
    fee_asset_id: &str,
    rebate_pool_id: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-LOW-FEE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Str(rebate_pool_id),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_rebate_entry_id(
    pool_id: &str,
    bundle_id: Option<&str>,
    fill_id: Option<&str>,
    solver_commitment_id: Option<&str>,
    entry_kind: RebateAccountingKind,
    amount_units: u64,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-REBATE-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(pool_id),
            HashPart::Str(bundle_id.unwrap_or("")),
            HashPart::Str(fill_id.unwrap_or("")),
            HashPart::Str(solver_commitment_id.unwrap_or("")),
            HashPart::Str(entry_kind.as_str()),
            HashPart::Int(amount_units as i128),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_fill_id(
    bundle_id: &str,
    epoch_id: &str,
    solver_commitment_id: &str,
    output_note_root: &str,
    filled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-FILL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(bundle_id),
            HashPart::Str(epoch_id),
            HashPart::Str(solver_commitment_id),
            HashPart::Str(output_note_root),
            HashPart::Int(filled_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_privacy_receipt_id(
    fill_id: &str,
    bundle_id: &str,
    audience: PrivacyReceiptAudience,
    recipient_commitment: &str,
    release_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-PRIVACY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(fill_id),
            HashPart::Str(bundle_id),
            HashPart::Str(audience.as_str()),
            HashPart::Str(recipient_commitment),
            HashPart::Int(release_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_delayed_reveal_id(
    receipt_id: &str,
    fill_id: &str,
    delayed_payload_root: &str,
    release_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-DELAYED-REVEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(fill_id),
            HashPart::Str(delayed_payload_root),
            HashPart::Int(release_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_slashing_evidence_id(
    evidence_kind: SlashingEvidenceKind,
    accused_solver_commitment: &str,
    epoch_id: &str,
    commitment_id: Option<&str>,
    bundle_id: Option<&str>,
    conflict_root: &str,
    discovered_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(accused_solver_commitment),
            HashPart::Str(epoch_id),
            HashPart::Str(commitment_id.unwrap_or("")),
            HashPart::Str(bundle_id.unwrap_or("")),
            HashPart::Str(conflict_root),
            HashPart::Int(discovered_at_height as i128),
        ],
        32,
    )
}

pub fn private_mev_guard_audit_record_id(
    object_kind: &str,
    object_id: &str,
    severity: AuditSeverity,
    category: &str,
    redacted_record_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-MEV-GUARD-AUDIT-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_MEV_GUARD_PROTOCOL_VERSION),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Str(severity.as_str()),
            HashPart::Str(category),
            HashPart::Str(redacted_record_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateMevGuardResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateMevGuardResult<()> {
    if value > PRIVATE_MEV_GUARD_MAX_BPS {
        return Err(format!("{label} exceeds {PRIVATE_MEV_GUARD_MAX_BPS} bps"));
    }
    Ok(())
}
