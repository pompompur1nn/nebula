use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeSponsorMarketResult<T> = Result<T, String>;

pub const LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION: &str = "nebula-low-fee-sponsor-market-v1";
pub const LOW_FEE_SPONSOR_PQ_AUTHORIZATION_SCHEME: &str =
    "ml-dsa-87-low-fee-sponsor-authorization-v1";
pub const LOW_FEE_SPONSOR_TREASURY_PROOF_SCHEME: &str = "monero-view-key-reserve-proof-shake256-v1";
pub const LOW_FEE_SPONSOR_REBATE_RECEIPT_SCHEME: &str = "zk-low-fee-rebate-receipt-range-proof-v1";
pub const LOW_FEE_SPONSOR_RESERVATION_SCHEME: &str = "anti-spam-reservation-nullifier-shake256-v1";
pub const LOW_FEE_SPONSOR_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const LOW_FEE_SPONSOR_DEVNET_MONERO_NETWORK: &str = "stagenet";
pub const LOW_FEE_SPONSOR_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const LOW_FEE_SPONSOR_DEFAULT_AUCTION_COMMIT_BLOCKS: u64 = 12;
pub const LOW_FEE_SPONSOR_DEFAULT_AUCTION_REVEAL_BLOCKS: u64 = 8;
pub const LOW_FEE_SPONSOR_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 18;
pub const LOW_FEE_SPONSOR_DEFAULT_PRESSURE_WINDOW_BLOCKS: u64 = 48;
pub const LOW_FEE_SPONSOR_DEFAULT_TREASURY_CONFIRMATIONS: u64 = 10;
pub const LOW_FEE_SPONSOR_DEFAULT_MIN_RESERVATION_BOND_UNITS: u64 = 2;
pub const LOW_FEE_SPONSOR_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const LOW_FEE_SPONSOR_DEFAULT_MAX_LANE_EXPOSURE_BPS: u64 = 6_000;
pub const LOW_FEE_SPONSOR_DEFAULT_TARGET_FAIRNESS_SCORE: u64 = 7_500;
pub const LOW_FEE_SPONSOR_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_SPONSOR_MAX_PRESSURE_BPS: u64 = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeSponsorLane {
    PrivateTransfer,
    MoneroBridge,
    SmallDefi,
    ContractCall,
    ProofJob,
    WalletRecovery,
    EmergencyExit,
}

impl LowFeeSponsorLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::SmallDefi => "small_defi",
            Self::ContractCall => "contract_call",
            Self::ProofJob => "proof_job",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_lane_key(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "wallet_private_transfer",
            Self::MoneroBridge => "monero_bridge_exit",
            Self::SmallDefi => "sealed_small_defi",
            Self::ContractCall => "private_contract_call",
            Self::ProofJob => "recursive_proof_job",
            Self::WalletRecovery => "pq_wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_display_name(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "Private transfers",
            Self::MoneroBridge => "Monero bridge exits",
            Self::SmallDefi => "Small private DeFi calls",
            Self::ContractCall => "Private contract calls",
            Self::ProofJob => "Proof jobs",
            Self::WalletRecovery => "Wallet recovery",
            Self::EmergencyExit => "Emergency exits",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::EmergencyExit => 400,
            Self::WalletRecovery => 650,
            Self::PrivateTransfer => 900,
            Self::MoneroBridge => 1_250,
            Self::SmallDefi => 1_650,
            Self::ContractCall => 2_250,
            Self::ProofJob => 2_800,
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::WalletRecovery => 90,
            Self::MoneroBridge => 85,
            Self::PrivateTransfer => 75,
            Self::SmallDefi => 65,
            Self::ContractCall => 60,
            Self::ProofJob => 55,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorAccountStatus {
    Active,
    Paused,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn can_allocate(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorBudgetStatus {
    Active,
    Replenishing,
    Exhausted,
    Paused,
    Expired,
    Closed,
}

impl SponsorBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Replenishing => "replenishing",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Closed => "closed",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Replenishing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneFeeCapStatus {
    Active,
    Superseded,
    Expired,
    Paused,
}

impl LaneFeeCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateLaneAuctionStatus {
    CommitOpen,
    RevealOpen,
    Settled,
    Cancelled,
    Expired,
}

impl PrivateLaneAuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_commit(self) -> bool {
        matches!(self, Self::CommitOpen)
    }

    pub fn accepts_reveal(self) -> bool {
        matches!(self, Self::RevealOpen)
    }

    pub fn is_final(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateLaneBidStatus {
    Committed,
    Revealed,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl PrivateLaneBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Committed | Self::Revealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Held,
    Released,
    Consumed,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Released => "released",
            Self::Consumed => "consumed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Held)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReceiptStatus {
    Pending,
    Settled,
    Disputed,
    Reversed,
}

impl RebateReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }

    pub fn final_for_accounting(self) -> bool {
        matches!(self, Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorAuthorizationStatus {
    Active,
    Revoked,
    Expired,
    Slashed,
}

impl SponsorAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipSlashingStatus {
    Open,
    Proven,
    Rejected,
    Appealed,
    Finalized,
}

impl SponsorshipSlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proven => "proven",
            Self::Rejected => "rejected",
            Self::Appealed => "appealed",
            Self::Finalized => "finalized",
        }
    }

    pub fn applies_penalty(self) -> bool {
        matches!(self, Self::Proven | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetReplenishmentStatus {
    Proposed,
    Proved,
    Applied,
    Rejected,
    Expired,
}

impl BudgetReplenishmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Proved => "proved",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Proposed | Self::Proved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryProofStatus {
    Observed,
    Confirmed,
    Challenged,
    Finalized,
    Rejected,
}

impl TreasuryProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Confirmed => "confirmed",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }

    pub fn final_for_replenishment(self) -> bool {
        matches!(self, Self::Confirmed | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePressureTrend {
    Cool,
    Normal,
    Hot,
    Congested,
}

impl FeePressureTrend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cool => "cool",
            Self::Normal => "normal",
            Self::Hot => "hot",
            Self::Congested => "congested",
        }
    }

    pub fn from_pressure_bps(pressure_bps: u64) -> Self {
        if pressure_bps >= 15_000 {
            Self::Congested
        } else if pressure_bps >= 10_000 {
            Self::Hot
        } else if pressure_bps <= 5_000 {
            Self::Cool
        } else {
            Self::Normal
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairnessScorecardStatus {
    Draft,
    Published,
    Challenged,
    Finalized,
}

impl FairnessScorecardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorMarketConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub auction_commit_blocks: u64,
    pub auction_reveal_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub pressure_window_blocks: u64,
    pub max_rebate_bps: u64,
    pub min_reservation_bond_units: u64,
    pub min_pq_security_bits: u16,
    pub min_treasury_confirmations: u64,
    pub max_lane_exposure_bps: u64,
    pub target_fairness_score: u64,
    pub pq_authorization_scheme: String,
    pub treasury_proof_scheme: String,
    pub rebate_receipt_scheme: String,
    pub reservation_scheme: String,
}

impl Default for LowFeeSponsorMarketConfig {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: LOW_FEE_SPONSOR_DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: LOW_FEE_SPONSOR_DEFAULT_EPOCH_BLOCKS,
            auction_commit_blocks: LOW_FEE_SPONSOR_DEFAULT_AUCTION_COMMIT_BLOCKS,
            auction_reveal_blocks: LOW_FEE_SPONSOR_DEFAULT_AUCTION_REVEAL_BLOCKS,
            reservation_ttl_blocks: LOW_FEE_SPONSOR_DEFAULT_RESERVATION_TTL_BLOCKS,
            pressure_window_blocks: LOW_FEE_SPONSOR_DEFAULT_PRESSURE_WINDOW_BLOCKS,
            max_rebate_bps: LOW_FEE_SPONSOR_MAX_BPS,
            min_reservation_bond_units: LOW_FEE_SPONSOR_DEFAULT_MIN_RESERVATION_BOND_UNITS,
            min_pq_security_bits: LOW_FEE_SPONSOR_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_treasury_confirmations: LOW_FEE_SPONSOR_DEFAULT_TREASURY_CONFIRMATIONS,
            max_lane_exposure_bps: LOW_FEE_SPONSOR_DEFAULT_MAX_LANE_EXPOSURE_BPS,
            target_fairness_score: LOW_FEE_SPONSOR_DEFAULT_TARGET_FAIRNESS_SCORE,
            pq_authorization_scheme: LOW_FEE_SPONSOR_PQ_AUTHORIZATION_SCHEME.to_string(),
            treasury_proof_scheme: LOW_FEE_SPONSOR_TREASURY_PROOF_SCHEME.to_string(),
            rebate_receipt_scheme: LOW_FEE_SPONSOR_REBATE_RECEIPT_SCHEME.to_string(),
            reservation_scheme: LOW_FEE_SPONSOR_RESERVATION_SCHEME.to_string(),
        }
    }
}

impl LowFeeSponsorMarketConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 240,
            auction_commit_blocks: 6,
            auction_reveal_blocks: 4,
            reservation_ttl_blocks: 12,
            pressure_window_blocks: 24,
            min_treasury_confirmations: 4,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_market_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "auction_commit_blocks": self.auction_commit_blocks,
            "auction_reveal_blocks": self.auction_reveal_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "pressure_window_blocks": self.pressure_window_blocks,
            "max_rebate_bps": self.max_rebate_bps,
            "min_reservation_bond_units": self.min_reservation_bond_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_treasury_confirmations": self.min_treasury_confirmations,
            "max_lane_exposure_bps": self.max_lane_exposure_bps,
            "target_fairness_score": self.target_fairness_score,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "treasury_proof_scheme": self.treasury_proof_scheme,
            "rebate_receipt_scheme": self.rebate_receipt_scheme,
            "reservation_scheme": self.reservation_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-MARKET-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_eq(
            "protocol version",
            &self.protocol_version,
            LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
        )?;
        ensure_eq("chain id", &self.chain_id, CHAIN_ID)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("epoch blocks", self.epoch_blocks)?;
        ensure_positive("auction commit blocks", self.auction_commit_blocks)?;
        ensure_positive("auction reveal blocks", self.auction_reveal_blocks)?;
        ensure_positive("reservation ttl blocks", self.reservation_ttl_blocks)?;
        ensure_positive("pressure window blocks", self.pressure_window_blocks)?;
        ensure_bps("max rebate bps", self.max_rebate_bps)?;
        ensure_positive(
            "minimum reservation bond units",
            self.min_reservation_bond_units,
        )?;
        if self.min_pq_security_bits < LOW_FEE_SPONSOR_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("minimum pq security bits below policy floor".to_string());
        }
        ensure_positive(
            "minimum treasury confirmations",
            self.min_treasury_confirmations,
        )?;
        ensure_bps("max lane exposure bps", self.max_lane_exposure_bps)?;
        ensure_bps("target fairness score", self.target_fairness_score)?;
        ensure_eq(
            "pq authorization scheme",
            &self.pq_authorization_scheme,
            LOW_FEE_SPONSOR_PQ_AUTHORIZATION_SCHEME,
        )?;
        ensure_eq(
            "treasury proof scheme",
            &self.treasury_proof_scheme,
            LOW_FEE_SPONSOR_TREASURY_PROOF_SCHEME,
        )?;
        ensure_eq(
            "rebate receipt scheme",
            &self.rebate_receipt_scheme,
            LOW_FEE_SPONSOR_REBATE_RECEIPT_SCHEME,
        )?;
        ensure_eq(
            "reservation scheme",
            &self.reservation_scheme,
            LOW_FEE_SPONSOR_RESERVATION_SCHEME,
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: String,
    pub sponsor_label: String,
    pub operator_commitment: String,
    pub settlement_address_commitment: String,
    pub fee_asset_id: String,
    pub total_budget_units: u64,
    pub replenished_budget_units: u64,
    pub allocated_budget_units: u64,
    pub slashed_units: u64,
    pub locked_bond_units: u64,
    pub max_lane_exposure_bps: u64,
    pub min_fairness_score: u64,
    pub pq_authorization_root: String,
    pub treasury_proof_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub account_nonce: u64,
    pub status: SponsorAccountStatus,
}

impl SponsorAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        operator_commitment: &str,
        settlement_address_commitment: &str,
        fee_asset_id: &str,
        total_budget_units: u64,
        max_lane_exposure_bps: u64,
        min_fairness_score: u64,
        opened_at_height: u64,
        account_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("sponsor label", sponsor_label)?;
        ensure_non_empty("operator commitment", operator_commitment)?;
        ensure_non_empty(
            "settlement address commitment",
            settlement_address_commitment,
        )?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("total budget units", total_budget_units)?;
        ensure_bps("max lane exposure bps", max_lane_exposure_bps)?;
        ensure_bps("minimum fairness score", min_fairness_score)?;
        let sponsor_id = low_fee_sponsor_account_id(
            sponsor_label,
            operator_commitment,
            settlement_address_commitment,
            fee_asset_id,
            account_nonce,
        );
        Ok(Self {
            sponsor_id,
            sponsor_label: sponsor_label.to_string(),
            operator_commitment: operator_commitment.to_string(),
            settlement_address_commitment: settlement_address_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            total_budget_units,
            replenished_budget_units: 0,
            allocated_budget_units: 0,
            slashed_units: 0,
            locked_bond_units: 0,
            max_lane_exposure_bps,
            min_fairness_score,
            pq_authorization_root: merkle_root("LOW-FEE-SPONSOR-PQ-AUTHORIZATION", &[]),
            treasury_proof_root: merkle_root("LOW-FEE-SPONSOR-TREASURY-PROOF", &[]),
            opened_at_height,
            updated_at_height: opened_at_height,
            account_nonce,
            status: SponsorAccountStatus::Active,
        })
    }

    pub fn capacity_units(&self) -> u64 {
        self.total_budget_units
            .saturating_add(self.replenished_budget_units)
    }

    pub fn available_budget_units(&self) -> u64 {
        self.capacity_units()
            .saturating_sub(self.allocated_budget_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn allocate_budget(&mut self, units: u64, height: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("allocated budget units", units)?;
        if !self.status.can_allocate() {
            return Err("sponsor account is not accepting budget allocation".to_string());
        }
        if self.available_budget_units() < units {
            return Err("sponsor account has insufficient unallocated budget".to_string());
        }
        self.allocated_budget_units = self.allocated_budget_units.saturating_add(units);
        self.updated_at_height = height;
        Ok(())
    }

    pub fn replenish(&mut self, units: u64, height: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("replenished budget units", units)?;
        self.replenished_budget_units = self.replenished_budget_units.saturating_add(units);
        self.updated_at_height = height;
        if matches!(self.status, SponsorAccountStatus::Exhausted) {
            self.status = SponsorAccountStatus::Active;
        }
        Ok(())
    }

    pub fn slash(&mut self, units: u64, height: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("sponsor slash units", units)?;
        self.slashed_units = self.slashed_units.saturating_add(units);
        self.updated_at_height = height;
        if self.available_budget_units() == 0 {
            self.status = SponsorAccountStatus::Slashed;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_account",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "sponsor_label": self.sponsor_label,
            "operator_commitment": self.operator_commitment,
            "settlement_address_commitment": self.settlement_address_commitment,
            "fee_asset_id": self.fee_asset_id,
            "total_budget_units": self.total_budget_units,
            "replenished_budget_units": self.replenished_budget_units,
            "allocated_budget_units": self.allocated_budget_units,
            "available_budget_units": self.available_budget_units(),
            "slashed_units": self.slashed_units,
            "locked_bond_units": self.locked_bond_units,
            "max_lane_exposure_bps": self.max_lane_exposure_bps,
            "min_fairness_score": self.min_fairness_score,
            "pq_authorization_root": self.pq_authorization_root,
            "treasury_proof_root": self.treasury_proof_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "account_nonce": self.account_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn account_root(&self) -> String {
        low_fee_sponsor_account_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("sponsor label", &self.sponsor_label)?;
        ensure_non_empty("operator commitment", &self.operator_commitment)?;
        ensure_non_empty(
            "settlement address commitment",
            &self.settlement_address_commitment,
        )?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("total budget units", self.total_budget_units)?;
        ensure_bps("max lane exposure bps", self.max_lane_exposure_bps)?;
        ensure_bps("minimum fairness score", self.min_fairness_score)?;
        ensure_non_empty("pq authorization root", &self.pq_authorization_root)?;
        ensure_non_empty("treasury proof root", &self.treasury_proof_root)?;
        if self.allocated_budget_units > self.capacity_units() {
            return Err("sponsor account allocation exceeds capacity".to_string());
        }
        if self.slashed_units > self.capacity_units() {
            return Err("sponsor account slashing exceeds capacity".to_string());
        }
        Ok(self.account_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorBudget {
    pub budget_id: String,
    pub sponsor_id: String,
    pub lane: LowFeeSponsorLane,
    pub lane_key: String,
    pub display_name: String,
    pub fee_asset_id: String,
    pub epoch_index: u64,
    pub total_budget_units: u64,
    pub replenished_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub slashed_units: u64,
    pub max_fee_cap_micro_units: u64,
    pub max_rebate_bps: u64,
    pub min_reservation_units: u64,
    pub priority_weight: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub policy_root: String,
    pub replenishment_root: String,
    pub status: SponsorBudgetStatus,
    pub budget_nonce: u64,
}

impl SponsorBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        lane: LowFeeSponsorLane,
        lane_key: &str,
        fee_asset_id: &str,
        epoch_index: u64,
        total_budget_units: u64,
        max_fee_cap_micro_units: u64,
        max_rebate_bps: u64,
        min_reservation_units: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        budget_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("lane key", lane_key)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("total budget units", total_budget_units)?;
        ensure_positive("max fee cap micro units", max_fee_cap_micro_units)?;
        ensure_bps("max rebate bps", max_rebate_bps)?;
        ensure_positive("minimum reservation units", min_reservation_units)?;
        ensure_height_order(
            "sponsor budget validity",
            valid_from_height,
            valid_until_height,
        )?;
        let budget_id = low_fee_sponsor_budget_id(
            sponsor_id,
            lane,
            lane_key,
            epoch_index,
            valid_from_height,
            budget_nonce,
        );
        let policy = json!({
            "sponsor_id": sponsor_id,
            "lane": lane.as_str(),
            "lane_key": lane_key,
            "fee_asset_id": fee_asset_id,
            "epoch_index": epoch_index,
            "total_budget_units": total_budget_units,
            "max_fee_cap_micro_units": max_fee_cap_micro_units,
            "max_rebate_bps": max_rebate_bps,
            "min_reservation_units": min_reservation_units,
            "priority_weight": lane.default_priority_weight(),
        });
        Ok(Self {
            budget_id,
            sponsor_id: sponsor_id.to_string(),
            lane,
            lane_key: lane_key.to_string(),
            display_name: lane.default_display_name().to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            epoch_index,
            total_budget_units,
            replenished_units: 0,
            reserved_units: 0,
            spent_units: 0,
            slashed_units: 0,
            max_fee_cap_micro_units,
            max_rebate_bps,
            min_reservation_units,
            priority_weight: lane.default_priority_weight(),
            valid_from_height,
            valid_until_height,
            policy_root: low_fee_sponsor_market_payload_root(
                "LOW-FEE-SPONSOR-BUDGET-POLICY",
                &policy,
            ),
            replenishment_root: merkle_root("LOW-FEE-SPONSOR-BUDGET-REPLENISHMENT", &[]),
            status: SponsorBudgetStatus::Active,
            budget_nonce,
        })
    }

    pub fn capacity_units(&self) -> u64 {
        self.total_budget_units
            .saturating_add(self.replenished_units)
    }

    pub fn available_units(&self) -> u64 {
        self.capacity_units()
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.spendable()
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn reserve_units(&mut self, units: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("budget reserve units", units)?;
        if !self.status.spendable() {
            return Err("sponsor budget is not spendable".to_string());
        }
        if self.available_units() < units {
            return Err("sponsor budget has insufficient available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn release_reserved_units(&mut self, units: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("budget release units", units)?;
        if units > self.reserved_units {
            return Err("cannot release more reserved budget than held".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        Ok(())
    }

    pub fn settle_reserved_units(
        &mut self,
        reserved_units: u64,
        spent_units: u64,
    ) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("reserved settlement units", reserved_units)?;
        if spent_units > reserved_units {
            return Err("spent units exceed reserved settlement".to_string());
        }
        if reserved_units > self.reserved_units {
            return Err("reserved settlement exceeds held budget".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(reserved_units);
        self.spent_units = self.spent_units.saturating_add(spent_units);
        if self.available_units() == 0 {
            self.status = SponsorBudgetStatus::Exhausted;
        }
        Ok(())
    }

    pub fn spend_available_units(&mut self, units: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("budget spend units", units)?;
        if self.available_units() < units {
            return Err("sponsor budget cannot cover spend".to_string());
        }
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = SponsorBudgetStatus::Exhausted;
        }
        Ok(())
    }

    pub fn replenish(&mut self, units: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("budget replenishment units", units)?;
        self.replenished_units = self.replenished_units.saturating_add(units);
        if matches!(
            self.status,
            SponsorBudgetStatus::Exhausted | SponsorBudgetStatus::Replenishing
        ) {
            self.status = SponsorBudgetStatus::Active;
        }
        Ok(())
    }

    pub fn slash(&mut self, units: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("budget slash units", units)?;
        if units > self.capacity_units() {
            return Err("budget slash exceeds capacity".to_string());
        }
        self.slashed_units = self.slashed_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = SponsorBudgetStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_budget",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "sponsor_id": self.sponsor_id,
            "lane": self.lane.as_str(),
            "lane_key": self.lane_key,
            "display_name": self.display_name,
            "fee_asset_id": self.fee_asset_id,
            "epoch_index": self.epoch_index,
            "total_budget_units": self.total_budget_units,
            "replenished_units": self.replenished_units,
            "capacity_units": self.capacity_units(),
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "slashed_units": self.slashed_units,
            "available_units": self.available_units(),
            "max_fee_cap_micro_units": self.max_fee_cap_micro_units,
            "max_rebate_bps": self.max_rebate_bps,
            "min_reservation_units": self.min_reservation_units,
            "priority_weight": self.priority_weight,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "policy_root": self.policy_root,
            "replenishment_root": self.replenishment_root,
            "status": self.status.as_str(),
            "budget_nonce": self.budget_nonce,
        })
    }

    pub fn budget_root(&self) -> String {
        low_fee_sponsor_budget_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("budget id", &self.budget_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("total budget units", self.total_budget_units)?;
        ensure_positive("max fee cap micro units", self.max_fee_cap_micro_units)?;
        ensure_bps("max rebate bps", self.max_rebate_bps)?;
        ensure_positive("minimum reservation units", self.min_reservation_units)?;
        ensure_height_order(
            "sponsor budget validity",
            self.valid_from_height,
            self.valid_until_height,
        )?;
        ensure_non_empty("budget policy root", &self.policy_root)?;
        ensure_non_empty("budget replenishment root", &self.replenishment_root)?;
        if self
            .reserved_units
            .saturating_add(self.spent_units)
            .saturating_add(self.slashed_units)
            > self.capacity_units()
        {
            return Err("budget accounting exceeds capacity".to_string());
        }
        Ok(self.budget_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneFeeCap {
    pub fee_cap_id: String,
    pub lane: LowFeeSponsorLane,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub target_fee_micro_units: u64,
    pub hard_cap_micro_units: u64,
    pub rebate_floor_bps: u64,
    pub pressure_ceiling_bps: u64,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
    pub source: String,
    pub status: LaneFeeCapStatus,
}

impl LaneFeeCap {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: LowFeeSponsorLane,
        lane_key: &str,
        fee_asset_id: &str,
        target_fee_micro_units: u64,
        hard_cap_micro_units: u64,
        rebate_floor_bps: u64,
        pressure_ceiling_bps: u64,
        effective_from_height: u64,
        expires_at_height: u64,
        source: &str,
        cap_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("lane key", lane_key)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("target fee micro units", target_fee_micro_units)?;
        ensure_positive("hard cap micro units", hard_cap_micro_units)?;
        ensure_bps("rebate floor bps", rebate_floor_bps)?;
        ensure_pressure_bps("pressure ceiling bps", pressure_ceiling_bps)?;
        ensure_height_order("fee cap validity", effective_from_height, expires_at_height)?;
        ensure_non_empty("fee cap source", source)?;
        if target_fee_micro_units > hard_cap_micro_units {
            return Err("target fee exceeds hard cap".to_string());
        }
        let fee_cap_id = low_fee_sponsor_fee_cap_id(
            lane,
            lane_key,
            fee_asset_id,
            effective_from_height,
            source,
            cap_nonce,
        );
        let policy = json!({
            "lane": lane.as_str(),
            "lane_key": lane_key,
            "fee_asset_id": fee_asset_id,
            "target_fee_micro_units": target_fee_micro_units,
            "hard_cap_micro_units": hard_cap_micro_units,
            "rebate_floor_bps": rebate_floor_bps,
            "pressure_ceiling_bps": pressure_ceiling_bps,
            "source": source,
        });
        Ok(Self {
            fee_cap_id,
            lane,
            lane_key: lane_key.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            target_fee_micro_units,
            hard_cap_micro_units,
            rebate_floor_bps,
            pressure_ceiling_bps,
            effective_from_height,
            expires_at_height,
            policy_root: low_fee_sponsor_market_payload_root(
                "LOW-FEE-SPONSOR-FEE-CAP-POLICY",
                &policy,
            ),
            source: source.to_string(),
            status: LaneFeeCapStatus::Active,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable()
            && height >= self.effective_from_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_lane_fee_cap",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "fee_cap_id": self.fee_cap_id,
            "lane": self.lane.as_str(),
            "lane_key": self.lane_key,
            "fee_asset_id": self.fee_asset_id,
            "target_fee_micro_units": self.target_fee_micro_units,
            "hard_cap_micro_units": self.hard_cap_micro_units,
            "rebate_floor_bps": self.rebate_floor_bps,
            "pressure_ceiling_bps": self.pressure_ceiling_bps,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
            "source": self.source,
            "status": self.status.as_str(),
        })
    }

    pub fn fee_cap_root(&self) -> String {
        low_fee_sponsor_fee_cap_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("fee cap id", &self.fee_cap_id)?;
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("target fee micro units", self.target_fee_micro_units)?;
        ensure_positive("hard cap micro units", self.hard_cap_micro_units)?;
        ensure_bps("rebate floor bps", self.rebate_floor_bps)?;
        ensure_pressure_bps("pressure ceiling bps", self.pressure_ceiling_bps)?;
        ensure_height_order(
            "fee cap validity",
            self.effective_from_height,
            self.expires_at_height,
        )?;
        ensure_non_empty("fee cap policy root", &self.policy_root)?;
        ensure_non_empty("fee cap source", &self.source)?;
        if self.target_fee_micro_units > self.hard_cap_micro_units {
            return Err("target fee exceeds hard cap".to_string());
        }
        Ok(self.fee_cap_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLaneAuction {
    pub auction_id: String,
    pub budget_id: String,
    pub sponsor_id: String,
    pub lane: LowFeeSponsorLane,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub epoch_index: u64,
    pub offered_rebate_units: u64,
    pub filled_rebate_units: u64,
    pub reserve_price_micro_units: u64,
    pub fee_cap_micro_units: u64,
    pub max_rebate_bps: u64,
    pub bid_count: u64,
    pub accepted_bid_count: u64,
    pub clearing_fee_micro_units: u64,
    pub start_height: u64,
    pub commit_end_height: u64,
    pub reveal_end_height: u64,
    pub privacy_set_root: String,
    pub sealed_policy_root: String,
    pub bid_commitment_root: String,
    pub bid_reveal_root: String,
    pub status: PrivateLaneAuctionStatus,
    pub auction_nonce: u64,
}

impl PrivateLaneAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        budget_id: &str,
        sponsor_id: &str,
        lane: LowFeeSponsorLane,
        lane_key: &str,
        fee_asset_id: &str,
        epoch_index: u64,
        offered_rebate_units: u64,
        reserve_price_micro_units: u64,
        fee_cap_micro_units: u64,
        max_rebate_bps: u64,
        start_height: u64,
        commit_end_height: u64,
        reveal_end_height: u64,
        privacy_set_root: &str,
        sealed_policy_root: &str,
        auction_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("budget id", budget_id)?;
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("lane key", lane_key)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("offered rebate units", offered_rebate_units)?;
        ensure_positive("reserve price micro units", reserve_price_micro_units)?;
        ensure_positive("fee cap micro units", fee_cap_micro_units)?;
        ensure_bps("max rebate bps", max_rebate_bps)?;
        ensure_height_order("auction commit range", start_height, commit_end_height)?;
        ensure_height_order(
            "auction reveal range",
            commit_end_height.saturating_add(1),
            reveal_end_height,
        )?;
        ensure_non_empty("privacy set root", privacy_set_root)?;
        ensure_non_empty("sealed policy root", sealed_policy_root)?;
        let auction_id = low_fee_sponsor_auction_id(
            budget_id,
            lane,
            lane_key,
            start_height,
            reveal_end_height,
            auction_nonce,
        );
        Ok(Self {
            auction_id,
            budget_id: budget_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            lane,
            lane_key: lane_key.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            epoch_index,
            offered_rebate_units,
            filled_rebate_units: 0,
            reserve_price_micro_units,
            fee_cap_micro_units,
            max_rebate_bps,
            bid_count: 0,
            accepted_bid_count: 0,
            clearing_fee_micro_units: 0,
            start_height,
            commit_end_height,
            reveal_end_height,
            privacy_set_root: privacy_set_root.to_string(),
            sealed_policy_root: sealed_policy_root.to_string(),
            bid_commitment_root: merkle_root("LOW-FEE-SPONSOR-AUCTION-BID-COMMITMENT", &[]),
            bid_reveal_root: merkle_root("LOW-FEE-SPONSOR-AUCTION-BID-REVEAL", &[]),
            status: PrivateLaneAuctionStatus::CommitOpen,
            auction_nonce,
        })
    }

    pub fn remaining_rebate_units(&self) -> u64 {
        self.offered_rebate_units
            .saturating_sub(self.filled_rebate_units)
    }

    pub fn accepts_commit_at(&self, height: u64) -> bool {
        self.status.accepts_commit()
            && height >= self.start_height
            && height <= self.commit_end_height
    }

    pub fn accepts_reveal_at(&self, height: u64) -> bool {
        self.status.accepts_reveal()
            && height > self.commit_end_height
            && height <= self.reveal_end_height
    }

    pub fn refresh_status_for_height(&mut self, height: u64) {
        if self.status.is_final() {
            return;
        }
        if height > self.reveal_end_height {
            self.status = PrivateLaneAuctionStatus::Expired;
        } else if height > self.commit_end_height {
            self.status = PrivateLaneAuctionStatus::RevealOpen;
        } else {
            self.status = PrivateLaneAuctionStatus::CommitOpen;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_private_lane_auction",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "auction_id": self.auction_id,
            "budget_id": self.budget_id,
            "sponsor_id": self.sponsor_id,
            "lane": self.lane.as_str(),
            "lane_key": self.lane_key,
            "fee_asset_id": self.fee_asset_id,
            "epoch_index": self.epoch_index,
            "offered_rebate_units": self.offered_rebate_units,
            "filled_rebate_units": self.filled_rebate_units,
            "remaining_rebate_units": self.remaining_rebate_units(),
            "reserve_price_micro_units": self.reserve_price_micro_units,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "max_rebate_bps": self.max_rebate_bps,
            "bid_count": self.bid_count,
            "accepted_bid_count": self.accepted_bid_count,
            "clearing_fee_micro_units": self.clearing_fee_micro_units,
            "start_height": self.start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_end_height": self.reveal_end_height,
            "privacy_set_root": self.privacy_set_root,
            "sealed_policy_root": self.sealed_policy_root,
            "bid_commitment_root": self.bid_commitment_root,
            "bid_reveal_root": self.bid_reveal_root,
            "status": self.status.as_str(),
            "auction_nonce": self.auction_nonce,
        })
    }

    pub fn auction_root(&self) -> String {
        low_fee_sponsor_auction_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("auction id", &self.auction_id)?;
        ensure_non_empty("budget id", &self.budget_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("offered rebate units", self.offered_rebate_units)?;
        ensure_positive("reserve price micro units", self.reserve_price_micro_units)?;
        ensure_positive("fee cap micro units", self.fee_cap_micro_units)?;
        ensure_bps("max rebate bps", self.max_rebate_bps)?;
        ensure_height_order(
            "auction commit range",
            self.start_height,
            self.commit_end_height,
        )?;
        ensure_height_order(
            "auction reveal range",
            self.commit_end_height.saturating_add(1),
            self.reveal_end_height,
        )?;
        ensure_non_empty("privacy set root", &self.privacy_set_root)?;
        ensure_non_empty("sealed policy root", &self.sealed_policy_root)?;
        ensure_non_empty("bid commitment root", &self.bid_commitment_root)?;
        ensure_non_empty("bid reveal root", &self.bid_reveal_root)?;
        if self.filled_rebate_units > self.offered_rebate_units {
            return Err("auction fill exceeds offered rebate".to_string());
        }
        if self.clearing_fee_micro_units > self.fee_cap_micro_units {
            return Err("auction clearing fee exceeds fee cap".to_string());
        }
        Ok(self.auction_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLaneBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub payer_nullifier: String,
    pub bid_commitment: String,
    pub requested_rebate_units: u64,
    pub max_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub revealed_fee_micro_units: u64,
    pub revealed_rebate_bps: u64,
    pub reveal_proof_root: String,
    pub reservation_id: String,
    pub pq_authorization_id: String,
    pub submitted_at_height: u64,
    pub revealed_at_height: u64,
    pub bid_nonce: u64,
    pub status: PrivateLaneBidStatus,
}

impl PrivateLaneBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        bidder_commitment: &str,
        payer_nullifier: &str,
        bid_commitment: &str,
        requested_rebate_units: u64,
        max_fee_micro_units: u64,
        rebate_bps: u64,
        reservation_id: &str,
        pq_authorization_id: &str,
        submitted_at_height: u64,
        bid_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("auction id", auction_id)?;
        ensure_non_empty("bidder commitment", bidder_commitment)?;
        ensure_non_empty("payer nullifier", payer_nullifier)?;
        ensure_non_empty("bid commitment", bid_commitment)?;
        ensure_positive("requested rebate units", requested_rebate_units)?;
        ensure_positive("max fee micro units", max_fee_micro_units)?;
        ensure_bps("rebate bps", rebate_bps)?;
        let bid_id = low_fee_sponsor_bid_id(
            auction_id,
            payer_nullifier,
            bid_commitment,
            submitted_at_height,
            bid_nonce,
        );
        Ok(Self {
            bid_id,
            auction_id: auction_id.to_string(),
            bidder_commitment: bidder_commitment.to_string(),
            payer_nullifier: payer_nullifier.to_string(),
            bid_commitment: bid_commitment.to_string(),
            requested_rebate_units,
            max_fee_micro_units,
            rebate_bps,
            revealed_fee_micro_units: 0,
            revealed_rebate_bps: 0,
            reveal_proof_root: merkle_root("LOW-FEE-SPONSOR-BID-REVEAL-PROOF", &[]),
            reservation_id: reservation_id.to_string(),
            pq_authorization_id: pq_authorization_id.to_string(),
            submitted_at_height,
            revealed_at_height: 0,
            bid_nonce,
            status: PrivateLaneBidStatus::Committed,
        })
    }

    pub fn reveal(
        &mut self,
        revealed_fee_micro_units: u64,
        revealed_rebate_bps: u64,
        reveal_proof_root: &str,
        height: u64,
    ) -> LowFeeSponsorMarketResult<()> {
        if !matches!(self.status, PrivateLaneBidStatus::Committed) {
            return Err("bid is not revealable".to_string());
        }
        ensure_positive("revealed fee micro units", revealed_fee_micro_units)?;
        ensure_bps("revealed rebate bps", revealed_rebate_bps)?;
        ensure_non_empty("reveal proof root", reveal_proof_root)?;
        if revealed_fee_micro_units > self.max_fee_micro_units {
            return Err("revealed fee exceeds committed maximum".to_string());
        }
        if revealed_rebate_bps > self.rebate_bps {
            return Err("revealed rebate exceeds committed maximum".to_string());
        }
        self.revealed_fee_micro_units = revealed_fee_micro_units;
        self.revealed_rebate_bps = revealed_rebate_bps;
        self.reveal_proof_root = reveal_proof_root.to_string();
        self.revealed_at_height = height;
        self.status = PrivateLaneBidStatus::Revealed;
        Ok(())
    }

    pub fn score_units(&self) -> u64 {
        let fee_savings = LOW_FEE_SPONSOR_MAX_BPS
            .saturating_sub(self.revealed_fee_micro_units.min(LOW_FEE_SPONSOR_MAX_BPS));
        self.requested_rebate_units
            .saturating_mul(self.revealed_rebate_bps.saturating_add(1))
            .saturating_add(fee_savings)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_private_lane_bid",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "payer_nullifier": self.payer_nullifier,
            "bid_commitment": self.bid_commitment,
            "requested_rebate_units": self.requested_rebate_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "revealed_fee_micro_units": self.revealed_fee_micro_units,
            "revealed_rebate_bps": self.revealed_rebate_bps,
            "reveal_proof_root": self.reveal_proof_root,
            "reservation_id": self.reservation_id,
            "pq_authorization_id": self.pq_authorization_id,
            "submitted_at_height": self.submitted_at_height,
            "revealed_at_height": self.revealed_at_height,
            "bid_nonce": self.bid_nonce,
            "score_units": self.score_units(),
            "status": self.status.as_str(),
        })
    }

    pub fn bid_root(&self) -> String {
        low_fee_sponsor_bid_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("bid id", &self.bid_id)?;
        ensure_non_empty("auction id", &self.auction_id)?;
        ensure_non_empty("bidder commitment", &self.bidder_commitment)?;
        ensure_non_empty("payer nullifier", &self.payer_nullifier)?;
        ensure_non_empty("bid commitment", &self.bid_commitment)?;
        ensure_positive("requested rebate units", self.requested_rebate_units)?;
        ensure_positive("max fee micro units", self.max_fee_micro_units)?;
        ensure_bps("rebate bps", self.rebate_bps)?;
        ensure_non_empty("reveal proof root", &self.reveal_proof_root)?;
        if self.status != PrivateLaneBidStatus::Committed {
            ensure_positive("revealed fee micro units", self.revealed_fee_micro_units)?;
            ensure_bps("revealed rebate bps", self.revealed_rebate_bps)?;
            if self.revealed_fee_micro_units > self.max_fee_micro_units {
                return Err("revealed fee exceeds committed maximum".to_string());
            }
            if self.revealed_rebate_bps > self.rebate_bps {
                return Err("revealed rebate exceeds committed maximum".to_string());
            }
        }
        Ok(self.bid_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiSpamReservation {
    pub reservation_id: String,
    pub owner_commitment: String,
    pub lane: LowFeeSponsorLane,
    pub lane_key: String,
    pub tx_intent_root: String,
    pub fee_asset_id: String,
    pub reserved_units: u64,
    pub bond_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub pq_authorization_id: String,
    pub reservation_nonce: u64,
    pub status: ReservationStatus,
}

impl AntiSpamReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        lane: LowFeeSponsorLane,
        lane_key: &str,
        tx_intent_root: &str,
        fee_asset_id: &str,
        reserved_units: u64,
        bond_units: u64,
        created_at_height: u64,
        expires_at_height: u64,
        pq_authorization_id: &str,
        reservation_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("owner commitment", owner_commitment)?;
        ensure_non_empty("lane key", lane_key)?;
        ensure_non_empty("transaction intent root", tx_intent_root)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("reserved units", reserved_units)?;
        ensure_positive("bond units", bond_units)?;
        ensure_height_order(
            "anti-spam reservation",
            created_at_height,
            expires_at_height,
        )?;
        let reservation_id = low_fee_sponsor_reservation_id(
            owner_commitment,
            lane,
            tx_intent_root,
            created_at_height,
            reservation_nonce,
        );
        Ok(Self {
            reservation_id,
            owner_commitment: owner_commitment.to_string(),
            lane,
            lane_key: lane_key.to_string(),
            tx_intent_root: tx_intent_root.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            reserved_units,
            bond_units,
            created_at_height,
            expires_at_height,
            pq_authorization_id: pq_authorization_id.to_string(),
            reservation_nonce,
            status: ReservationStatus::Held,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.active() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_anti_spam_reservation",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "reservation_id": self.reservation_id,
            "owner_commitment": self.owner_commitment,
            "lane": self.lane.as_str(),
            "lane_key": self.lane_key,
            "tx_intent_root": self.tx_intent_root,
            "fee_asset_id": self.fee_asset_id,
            "reserved_units": self.reserved_units,
            "bond_units": self.bond_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_authorization_id": self.pq_authorization_id,
            "reservation_nonce": self.reservation_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn reservation_root(&self) -> String {
        low_fee_sponsor_reservation_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("reservation id", &self.reservation_id)?;
        ensure_non_empty("owner commitment", &self.owner_commitment)?;
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_non_empty("transaction intent root", &self.tx_intent_root)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("reserved units", self.reserved_units)?;
        ensure_positive("bond units", self.bond_units)?;
        ensure_height_order(
            "anti-spam reservation",
            self.created_at_height,
            self.expires_at_height,
        )?;
        Ok(self.reservation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSponsorAuthorization {
    pub authorization_id: String,
    pub sponsor_id: String,
    pub delegate_commitment: String,
    pub permitted_lanes: Vec<LowFeeSponsorLane>,
    pub spending_limit_units: u64,
    pub used_units: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub pq_public_key_root: String,
    pub sponsor_policy_root: String,
    pub authorization_statement_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub threshold: u16,
    pub authorization_nonce: u64,
    pub status: SponsorAuthorizationStatus,
}

impl PqSponsorAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        delegate_commitment: &str,
        permitted_lanes: Vec<LowFeeSponsorLane>,
        spending_limit_units: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        pq_public_key_root: &str,
        sponsor_policy_root: &str,
        signature_root: &str,
        security_bits: u16,
        threshold: u16,
        authorization_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("delegate commitment", delegate_commitment)?;
        ensure_non_empty_lane_set(&permitted_lanes)?;
        ensure_positive("spending limit units", spending_limit_units)?;
        ensure_height_order(
            "pq sponsor authorization",
            valid_from_height,
            valid_until_height,
        )?;
        ensure_non_empty("pq public key root", pq_public_key_root)?;
        ensure_non_empty("sponsor policy root", sponsor_policy_root)?;
        ensure_non_empty("signature root", signature_root)?;
        if security_bits < LOW_FEE_SPONSOR_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq authorization security bits below floor".to_string());
        }
        if threshold == 0 {
            return Err("pq authorization threshold is required".to_string());
        }
        let authorization_statement = json!({
            "sponsor_id": sponsor_id,
            "delegate_commitment": delegate_commitment,
            "permitted_lane_root": low_fee_sponsor_lane_set_root(&permitted_lanes),
            "spending_limit_units": spending_limit_units,
            "valid_from_height": valid_from_height,
            "valid_until_height": valid_until_height,
            "pq_public_key_root": pq_public_key_root,
            "security_bits": security_bits,
            "threshold": threshold,
        });
        let authorization_statement_root = low_fee_sponsor_market_payload_root(
            "LOW-FEE-SPONSOR-PQ-AUTHORIZATION-STATEMENT",
            &authorization_statement,
        );
        let authorization_id = low_fee_sponsor_authorization_id(
            sponsor_id,
            delegate_commitment,
            &authorization_statement_root,
            valid_from_height,
            authorization_nonce,
        );
        Ok(Self {
            authorization_id,
            sponsor_id: sponsor_id.to_string(),
            delegate_commitment: delegate_commitment.to_string(),
            permitted_lanes,
            spending_limit_units,
            used_units: 0,
            valid_from_height,
            valid_until_height,
            pq_public_key_root: pq_public_key_root.to_string(),
            sponsor_policy_root: sponsor_policy_root.to_string(),
            authorization_statement_root,
            signature_root: signature_root.to_string(),
            security_bits,
            threshold,
            authorization_nonce,
            status: SponsorAuthorizationStatus::Active,
        })
    }

    pub fn remaining_units(&self) -> u64 {
        self.spending_limit_units.saturating_sub(self.used_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable()
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn permits_lane(&self, lane: LowFeeSponsorLane) -> bool {
        self.permitted_lanes
            .iter()
            .any(|permitted| *permitted == lane)
    }

    pub fn can_authorize(&self, lane: LowFeeSponsorLane, height: u64, units: u64) -> bool {
        self.active_at(height) && self.permits_lane(lane) && self.remaining_units() >= units
    }

    pub fn consume_units(&mut self, units: u64) -> LowFeeSponsorMarketResult<()> {
        ensure_positive("authorization consume units", units)?;
        if self.remaining_units() < units {
            return Err("pq authorization spending limit exhausted".to_string());
        }
        self.used_units = self.used_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_pq_authorization",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "scheme": LOW_FEE_SPONSOR_PQ_AUTHORIZATION_SCHEME,
            "authorization_id": self.authorization_id,
            "sponsor_id": self.sponsor_id,
            "delegate_commitment": self.delegate_commitment,
            "permitted_lanes": self.permitted_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "permitted_lane_root": low_fee_sponsor_lane_set_root(&self.permitted_lanes),
            "spending_limit_units": self.spending_limit_units,
            "used_units": self.used_units,
            "remaining_units": self.remaining_units(),
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "pq_public_key_root": self.pq_public_key_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "authorization_statement_root": self.authorization_statement_root,
            "signature_root": self.signature_root,
            "security_bits": self.security_bits,
            "threshold": self.threshold,
            "authorization_nonce": self.authorization_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn authorization_root(&self) -> String {
        low_fee_sponsor_authorization_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("authorization id", &self.authorization_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("delegate commitment", &self.delegate_commitment)?;
        ensure_non_empty_lane_set(&self.permitted_lanes)?;
        ensure_positive("spending limit units", self.spending_limit_units)?;
        ensure_height_order(
            "pq sponsor authorization",
            self.valid_from_height,
            self.valid_until_height,
        )?;
        ensure_non_empty("pq public key root", &self.pq_public_key_root)?;
        ensure_non_empty("sponsor policy root", &self.sponsor_policy_root)?;
        ensure_non_empty(
            "authorization statement root",
            &self.authorization_statement_root,
        )?;
        ensure_non_empty("signature root", &self.signature_root)?;
        if self.used_units > self.spending_limit_units {
            return Err("pq authorization used units exceed limit".to_string());
        }
        if self.security_bits < LOW_FEE_SPONSOR_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq authorization security bits below floor".to_string());
        }
        if self.threshold == 0 {
            return Err("pq authorization threshold is required".to_string());
        }
        Ok(self.authorization_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateReceipt {
    pub receipt_id: String,
    pub tx_nullifier: String,
    pub payer_commitment: String,
    pub recipient_commitment: String,
    pub sponsor_id: String,
    pub budget_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub reservation_id: String,
    pub fee_cap_id: String,
    pub pressure_window_id: String,
    pub lane: LowFeeSponsorLane,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub gross_fee_micro_units: u64,
    pub capped_fee_micro_units: u64,
    pub rebate_units: u64,
    pub sponsor_paid_units: u64,
    pub receipt_proof_root: String,
    pub settled_at_height: u64,
    pub receipt_nonce: u64,
    pub status: RebateReceiptStatus,
}

impl RebateReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_nullifier: &str,
        payer_commitment: &str,
        recipient_commitment: &str,
        sponsor_id: &str,
        budget_id: &str,
        lane: LowFeeSponsorLane,
        lane_key: &str,
        fee_asset_id: &str,
        gross_fee_micro_units: u64,
        capped_fee_micro_units: u64,
        rebate_units: u64,
        sponsor_paid_units: u64,
        auction_id: &str,
        bid_id: &str,
        reservation_id: &str,
        fee_cap_id: &str,
        pressure_window_id: &str,
        receipt_proof_root: &str,
        settled_at_height: u64,
        receipt_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("transaction nullifier", tx_nullifier)?;
        ensure_non_empty("payer commitment", payer_commitment)?;
        ensure_non_empty("recipient commitment", recipient_commitment)?;
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("budget id", budget_id)?;
        ensure_non_empty("lane key", lane_key)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("gross fee micro units", gross_fee_micro_units)?;
        ensure_positive("capped fee micro units", capped_fee_micro_units)?;
        ensure_non_empty("receipt proof root", receipt_proof_root)?;
        if capped_fee_micro_units > gross_fee_micro_units {
            return Err("capped fee exceeds gross fee".to_string());
        }
        if rebate_units > gross_fee_micro_units {
            return Err("rebate units exceed gross fee".to_string());
        }
        let receipt_id = low_fee_sponsor_rebate_receipt_id(
            tx_nullifier,
            sponsor_id,
            budget_id,
            lane,
            settled_at_height,
            receipt_nonce,
        );
        Ok(Self {
            receipt_id,
            tx_nullifier: tx_nullifier.to_string(),
            payer_commitment: payer_commitment.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            sponsor_id: sponsor_id.to_string(),
            budget_id: budget_id.to_string(),
            auction_id: auction_id.to_string(),
            bid_id: bid_id.to_string(),
            reservation_id: reservation_id.to_string(),
            fee_cap_id: fee_cap_id.to_string(),
            pressure_window_id: pressure_window_id.to_string(),
            lane,
            lane_key: lane_key.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_micro_units,
            capped_fee_micro_units,
            rebate_units,
            sponsor_paid_units,
            receipt_proof_root: receipt_proof_root.to_string(),
            settled_at_height,
            receipt_nonce,
            status: RebateReceiptStatus::Settled,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_rebate_receipt",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "scheme": LOW_FEE_SPONSOR_REBATE_RECEIPT_SCHEME,
            "receipt_id": self.receipt_id,
            "tx_nullifier": self.tx_nullifier,
            "payer_commitment": self.payer_commitment,
            "recipient_commitment": self.recipient_commitment,
            "sponsor_id": self.sponsor_id,
            "budget_id": self.budget_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "reservation_id": self.reservation_id,
            "fee_cap_id": self.fee_cap_id,
            "pressure_window_id": self.pressure_window_id,
            "lane": self.lane.as_str(),
            "lane_key": self.lane_key,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_micro_units": self.gross_fee_micro_units,
            "capped_fee_micro_units": self.capped_fee_micro_units,
            "rebate_units": self.rebate_units,
            "sponsor_paid_units": self.sponsor_paid_units,
            "receipt_proof_root": self.receipt_proof_root,
            "settled_at_height": self.settled_at_height,
            "receipt_nonce": self.receipt_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        low_fee_sponsor_rebate_receipt_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("transaction nullifier", &self.tx_nullifier)?;
        ensure_non_empty("payer commitment", &self.payer_commitment)?;
        ensure_non_empty("recipient commitment", &self.recipient_commitment)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("budget id", &self.budget_id)?;
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("gross fee micro units", self.gross_fee_micro_units)?;
        ensure_positive("capped fee micro units", self.capped_fee_micro_units)?;
        ensure_non_empty("receipt proof root", &self.receipt_proof_root)?;
        if self.capped_fee_micro_units > self.gross_fee_micro_units {
            return Err("capped fee exceeds gross fee".to_string());
        }
        if self.rebate_units > self.gross_fee_micro_units {
            return Err("rebate units exceed gross fee".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorshipSlashing {
    pub slashing_id: String,
    pub sponsor_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slashed_units: u64,
    pub challenger_reward_units: u64,
    pub opened_at_height: u64,
    pub resolved_at_height: u64,
    pub slashing_nonce: u64,
    pub status: SponsorshipSlashingStatus,
}

impl SponsorshipSlashing {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        target_kind: &str,
        target_id: &str,
        evidence_root: &str,
        challenger_commitment: &str,
        slashed_units: u64,
        challenger_reward_units: u64,
        opened_at_height: u64,
        slashing_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("slashing target kind", target_kind)?;
        ensure_non_empty("slashing target id", target_id)?;
        ensure_non_empty("slashing evidence root", evidence_root)?;
        ensure_non_empty("challenger commitment", challenger_commitment)?;
        ensure_positive("slashed units", slashed_units)?;
        if challenger_reward_units > slashed_units {
            return Err("slashing challenger reward exceeds slash".to_string());
        }
        let slashing_id = low_fee_sponsor_slashing_id(
            sponsor_id,
            target_kind,
            target_id,
            evidence_root,
            opened_at_height,
            slashing_nonce,
        );
        Ok(Self {
            slashing_id,
            sponsor_id: sponsor_id.to_string(),
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            evidence_root: evidence_root.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            slashed_units,
            challenger_reward_units,
            opened_at_height,
            resolved_at_height: 0,
            slashing_nonce,
            status: SponsorshipSlashingStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_slashing",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "slashing_id": self.slashing_id,
            "sponsor_id": self.sponsor_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "slashed_units": self.slashed_units,
            "challenger_reward_units": self.challenger_reward_units,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "slashing_nonce": self.slashing_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn slashing_root(&self) -> String {
        low_fee_sponsor_slashing_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("slashing id", &self.slashing_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("slashing target kind", &self.target_kind)?;
        ensure_non_empty("slashing target id", &self.target_id)?;
        ensure_non_empty("slashing evidence root", &self.evidence_root)?;
        ensure_non_empty("challenger commitment", &self.challenger_commitment)?;
        ensure_positive("slashed units", self.slashed_units)?;
        if self.challenger_reward_units > self.slashed_units {
            return Err("slashing challenger reward exceeds slash".to_string());
        }
        Ok(self.slashing_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReplenishmentIntent {
    pub intent_id: String,
    pub sponsor_id: String,
    pub budget_id: String,
    pub fee_asset_id: String,
    pub requested_units: u64,
    pub min_confirmations: u64,
    pub monero_txid: String,
    pub monero_output_commitment: String,
    pub treasury_proof_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub intent_nonce: u64,
    pub status: BudgetReplenishmentStatus,
}

impl BudgetReplenishmentIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        budget_id: &str,
        fee_asset_id: &str,
        requested_units: u64,
        min_confirmations: u64,
        monero_txid: &str,
        monero_output_commitment: &str,
        treasury_proof_id: &str,
        created_at_height: u64,
        expires_at_height: u64,
        intent_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("budget id", budget_id)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("requested units", requested_units)?;
        ensure_positive("minimum confirmations", min_confirmations)?;
        ensure_non_empty("monero txid", monero_txid)?;
        ensure_non_empty("monero output commitment", monero_output_commitment)?;
        ensure_height_order(
            "budget replenishment intent",
            created_at_height,
            expires_at_height,
        )?;
        let intent_id = low_fee_sponsor_replenishment_intent_id(
            sponsor_id,
            budget_id,
            monero_txid,
            monero_output_commitment,
            created_at_height,
            intent_nonce,
        );
        Ok(Self {
            intent_id,
            sponsor_id: sponsor_id.to_string(),
            budget_id: budget_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            requested_units,
            min_confirmations,
            monero_txid: monero_txid.to_string(),
            monero_output_commitment: monero_output_commitment.to_string(),
            treasury_proof_id: treasury_proof_id.to_string(),
            created_at_height,
            expires_at_height,
            intent_nonce,
            status: BudgetReplenishmentStatus::Proposed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_budget_replenishment_intent",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "intent_id": self.intent_id,
            "sponsor_id": self.sponsor_id,
            "budget_id": self.budget_id,
            "fee_asset_id": self.fee_asset_id,
            "requested_units": self.requested_units,
            "min_confirmations": self.min_confirmations,
            "monero_txid": self.monero_txid,
            "monero_output_commitment": self.monero_output_commitment,
            "treasury_proof_id": self.treasury_proof_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "intent_nonce": self.intent_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        low_fee_sponsor_replenishment_intent_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("replenishment intent id", &self.intent_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("budget id", &self.budget_id)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("requested units", self.requested_units)?;
        ensure_positive("minimum confirmations", self.min_confirmations)?;
        ensure_non_empty("monero txid", &self.monero_txid)?;
        ensure_non_empty("monero output commitment", &self.monero_output_commitment)?;
        ensure_height_order(
            "budget replenishment intent",
            self.created_at_height,
            self.expires_at_height,
        )?;
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessScorecard {
    pub scorecard_id: String,
    pub sponsor_id: String,
    pub epoch_index: u64,
    pub lane_count: u64,
    pub auction_count: u64,
    pub accepted_bid_count: u64,
    pub rejected_bid_count: u64,
    pub settled_receipt_count: u64,
    pub average_rebate_bps: u64,
    pub pressure_relief_bps: u64,
    pub privacy_set_size: u64,
    pub latency_penalty_bps: u64,
    pub slashing_penalty_bps: u64,
    pub fairness_score: u64,
    pub previous_score_root: String,
    pub published_at_height: u64,
    pub scorecard_nonce: u64,
    pub status: FairnessScorecardStatus,
}

impl FairnessScorecard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        epoch_index: u64,
        lane_count: u64,
        auction_count: u64,
        accepted_bid_count: u64,
        rejected_bid_count: u64,
        settled_receipt_count: u64,
        average_rebate_bps: u64,
        pressure_relief_bps: u64,
        privacy_set_size: u64,
        latency_penalty_bps: u64,
        slashing_penalty_bps: u64,
        previous_score_root: &str,
        published_at_height: u64,
        scorecard_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_positive("lane count", lane_count)?;
        ensure_bps("average rebate bps", average_rebate_bps)?;
        ensure_pressure_bps("pressure relief bps", pressure_relief_bps)?;
        ensure_bps("latency penalty bps", latency_penalty_bps)?;
        ensure_bps("slashing penalty bps", slashing_penalty_bps)?;
        ensure_non_empty("previous score root", previous_score_root)?;
        let fairness_score = low_fee_sponsor_fairness_score(
            accepted_bid_count,
            rejected_bid_count,
            average_rebate_bps,
            pressure_relief_bps,
            privacy_set_size,
            latency_penalty_bps,
            slashing_penalty_bps,
        );
        let scorecard_id = low_fee_sponsor_fairness_scorecard_id(
            sponsor_id,
            epoch_index,
            previous_score_root,
            published_at_height,
            scorecard_nonce,
        );
        Ok(Self {
            scorecard_id,
            sponsor_id: sponsor_id.to_string(),
            epoch_index,
            lane_count,
            auction_count,
            accepted_bid_count,
            rejected_bid_count,
            settled_receipt_count,
            average_rebate_bps,
            pressure_relief_bps,
            privacy_set_size,
            latency_penalty_bps,
            slashing_penalty_bps,
            fairness_score,
            previous_score_root: previous_score_root.to_string(),
            published_at_height,
            scorecard_nonce,
            status: FairnessScorecardStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_fairness_scorecard",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "scorecard_id": self.scorecard_id,
            "sponsor_id": self.sponsor_id,
            "epoch_index": self.epoch_index,
            "lane_count": self.lane_count,
            "auction_count": self.auction_count,
            "accepted_bid_count": self.accepted_bid_count,
            "rejected_bid_count": self.rejected_bid_count,
            "settled_receipt_count": self.settled_receipt_count,
            "average_rebate_bps": self.average_rebate_bps,
            "pressure_relief_bps": self.pressure_relief_bps,
            "privacy_set_size": self.privacy_set_size,
            "latency_penalty_bps": self.latency_penalty_bps,
            "slashing_penalty_bps": self.slashing_penalty_bps,
            "fairness_score": self.fairness_score,
            "previous_score_root": self.previous_score_root,
            "published_at_height": self.published_at_height,
            "scorecard_nonce": self.scorecard_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn scorecard_root(&self) -> String {
        low_fee_sponsor_fairness_scorecard_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("scorecard id", &self.scorecard_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_positive("lane count", self.lane_count)?;
        ensure_bps("average rebate bps", self.average_rebate_bps)?;
        ensure_pressure_bps("pressure relief bps", self.pressure_relief_bps)?;
        ensure_bps("latency penalty bps", self.latency_penalty_bps)?;
        ensure_bps("slashing penalty bps", self.slashing_penalty_bps)?;
        ensure_bps("fairness score", self.fairness_score)?;
        ensure_non_empty("previous score root", &self.previous_score_root)?;
        Ok(self.scorecard_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneFeePressureWindow {
    pub window_id: String,
    pub lane: LowFeeSponsorLane,
    pub lane_key: String,
    pub start_height: u64,
    pub end_height: u64,
    pub sample_count: u64,
    pub sample_root: String,
    pub observed_fee_micro_units_total: u64,
    pub target_fee_micro_units: u64,
    pub p50_fee_micro_units: u64,
    pub p95_fee_micro_units: u64,
    pub pressure_bps: u64,
    pub trend: FeePressureTrend,
    pub fee_cap_root: String,
    pub auction_root: String,
    pub status: LaneFeeCapStatus,
}

impl LaneFeePressureWindow {
    pub fn new(
        lane: LowFeeSponsorLane,
        lane_key: &str,
        start_height: u64,
        end_height: u64,
        fee_samples_micro_units: Vec<u64>,
        target_fee_micro_units: u64,
        fee_cap_root: &str,
        auction_root: &str,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("lane key", lane_key)?;
        ensure_height_order("lane fee pressure window", start_height, end_height)?;
        ensure_positive("target fee micro units", target_fee_micro_units)?;
        ensure_non_empty("fee cap root", fee_cap_root)?;
        ensure_non_empty("auction root", auction_root)?;
        if fee_samples_micro_units.is_empty() {
            return Err("fee pressure window requires samples".to_string());
        }
        let mut samples = fee_samples_micro_units;
        samples.sort();
        let sample_count = samples.len() as u64;
        let observed_fee_micro_units_total = samples
            .iter()
            .fold(0_u64, |total, sample| total.saturating_add(*sample));
        let p50_fee_micro_units = percentile_sample(&samples, 50);
        let p95_fee_micro_units = percentile_sample(&samples, 95);
        let pressure_bps = ratio_bps(p95_fee_micro_units, target_fee_micro_units)
            .min(LOW_FEE_SPONSOR_MAX_PRESSURE_BPS);
        let sample_root = merkle_root(
            "LOW-FEE-SPONSOR-FEE-PRESSURE-SAMPLE",
            &samples
                .iter()
                .map(|sample| json!({"fee_micro_units": sample}))
                .collect::<Vec<_>>(),
        );
        let window_id = low_fee_sponsor_pressure_window_id(
            lane,
            lane_key,
            start_height,
            end_height,
            &sample_root,
        );
        Ok(Self {
            window_id,
            lane,
            lane_key: lane_key.to_string(),
            start_height,
            end_height,
            sample_count,
            sample_root,
            observed_fee_micro_units_total,
            target_fee_micro_units,
            p50_fee_micro_units,
            p95_fee_micro_units,
            pressure_bps,
            trend: FeePressureTrend::from_pressure_bps(pressure_bps),
            fee_cap_root: fee_cap_root.to_string(),
            auction_root: auction_root.to_string(),
            status: LaneFeeCapStatus::Active,
        })
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_lane_fee_pressure_window",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "lane_key": self.lane_key,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "sample_count": self.sample_count,
            "sample_root": self.sample_root,
            "observed_fee_micro_units_total": self.observed_fee_micro_units_total,
            "target_fee_micro_units": self.target_fee_micro_units,
            "p50_fee_micro_units": self.p50_fee_micro_units,
            "p95_fee_micro_units": self.p95_fee_micro_units,
            "pressure_bps": self.pressure_bps,
            "trend": self.trend.as_str(),
            "fee_cap_root": self.fee_cap_root,
            "auction_root": self.auction_root,
            "status": self.status.as_str(),
        })
    }

    pub fn pressure_root(&self) -> String {
        low_fee_sponsor_pressure_window_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("pressure window id", &self.window_id)?;
        ensure_non_empty("lane key", &self.lane_key)?;
        ensure_height_order(
            "lane fee pressure window",
            self.start_height,
            self.end_height,
        )?;
        ensure_positive("fee pressure sample count", self.sample_count)?;
        ensure_non_empty("sample root", &self.sample_root)?;
        ensure_positive("target fee micro units", self.target_fee_micro_units)?;
        ensure_pressure_bps("pressure bps", self.pressure_bps)?;
        ensure_non_empty("fee cap root", &self.fee_cap_root)?;
        ensure_non_empty("auction root", &self.auction_root)?;
        Ok(self.pressure_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroTreasuryProof {
    pub proof_id: String,
    pub sponsor_id: String,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub monero_txid: String,
    pub output_index: u64,
    pub output_commitment: String,
    pub amount_commitment: String,
    pub confirmations: u64,
    pub min_confirmations: u64,
    pub view_tag: String,
    pub reserve_root: String,
    pub bridge_checkpoint_root: String,
    pub observed_at_height: u64,
    pub finalized_at_height: u64,
    pub proof_nonce: u64,
    pub status: TreasuryProofStatus,
}

impl MoneroTreasuryProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        fee_asset_id: &str,
        monero_network: &str,
        monero_txid: &str,
        output_index: u64,
        output_commitment: &str,
        amount_commitment: &str,
        confirmations: u64,
        min_confirmations: u64,
        view_tag: &str,
        reserve_root: &str,
        bridge_checkpoint_root: &str,
        observed_at_height: u64,
        proof_nonce: u64,
    ) -> LowFeeSponsorMarketResult<Self> {
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_non_empty("monero network", monero_network)?;
        ensure_non_empty("monero txid", monero_txid)?;
        ensure_non_empty("output commitment", output_commitment)?;
        ensure_non_empty("amount commitment", amount_commitment)?;
        ensure_positive("minimum confirmations", min_confirmations)?;
        ensure_non_empty("view tag", view_tag)?;
        ensure_non_empty("reserve root", reserve_root)?;
        ensure_non_empty("bridge checkpoint root", bridge_checkpoint_root)?;
        let proof_id = low_fee_sponsor_treasury_proof_id(
            sponsor_id,
            monero_txid,
            output_index,
            output_commitment,
            observed_at_height,
            proof_nonce,
        );
        let status = if confirmations >= min_confirmations {
            TreasuryProofStatus::Confirmed
        } else {
            TreasuryProofStatus::Observed
        };
        Ok(Self {
            proof_id,
            sponsor_id: sponsor_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            monero_network: monero_network.to_string(),
            monero_txid: monero_txid.to_string(),
            output_index,
            output_commitment: output_commitment.to_string(),
            amount_commitment: amount_commitment.to_string(),
            confirmations,
            min_confirmations,
            view_tag: view_tag.to_string(),
            reserve_root: reserve_root.to_string(),
            bridge_checkpoint_root: bridge_checkpoint_root.to_string(),
            observed_at_height,
            finalized_at_height: 0,
            proof_nonce,
            status,
        })
    }

    pub fn update_confirmations(&mut self, confirmations: u64, height: u64) {
        self.confirmations = confirmations;
        if self.confirmations >= self.min_confirmations
            && matches!(self.status, TreasuryProofStatus::Observed)
        {
            self.status = TreasuryProofStatus::Confirmed;
            self.finalized_at_height = height;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_monero_treasury_proof",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "scheme": LOW_FEE_SPONSOR_TREASURY_PROOF_SCHEME,
            "proof_id": self.proof_id,
            "sponsor_id": self.sponsor_id,
            "fee_asset_id": self.fee_asset_id,
            "monero_network": self.monero_network,
            "monero_txid": self.monero_txid,
            "output_index": self.output_index,
            "output_commitment": self.output_commitment,
            "amount_commitment": self.amount_commitment,
            "confirmations": self.confirmations,
            "min_confirmations": self.min_confirmations,
            "view_tag": self.view_tag,
            "reserve_root": self.reserve_root,
            "bridge_checkpoint_root": self.bridge_checkpoint_root,
            "observed_at_height": self.observed_at_height,
            "finalized_at_height": self.finalized_at_height,
            "proof_nonce": self.proof_nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn proof_root(&self) -> String {
        low_fee_sponsor_treasury_proof_root(self)
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        ensure_non_empty("treasury proof id", &self.proof_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_non_empty("monero network", &self.monero_network)?;
        ensure_non_empty("monero txid", &self.monero_txid)?;
        ensure_non_empty("output commitment", &self.output_commitment)?;
        ensure_non_empty("amount commitment", &self.amount_commitment)?;
        ensure_positive("minimum confirmations", self.min_confirmations)?;
        ensure_non_empty("view tag", &self.view_tag)?;
        ensure_non_empty("reserve root", &self.reserve_root)?;
        ensure_non_empty("bridge checkpoint root", &self.bridge_checkpoint_root)?;
        if self.status.final_for_replenishment() && self.confirmations < self.min_confirmations {
            return Err("final treasury proof lacks required confirmations".to_string());
        }
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorMarketRoots {
    pub config_root: String,
    pub sponsor_account_root: String,
    pub sponsor_budget_root: String,
    pub fee_cap_root: String,
    pub private_lane_auction_root: String,
    pub private_lane_bid_root: String,
    pub anti_spam_reservation_root: String,
    pub pq_authorization_root: String,
    pub rebate_receipt_root: String,
    pub slashing_root: String,
    pub replenishment_intent_root: String,
    pub fairness_scorecard_root: String,
    pub lane_pressure_window_root: String,
    pub treasury_proof_root: String,
    pub active_lane_root: String,
    pub nullifier_root: String,
}

impl LowFeeSponsorMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_market_roots",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "sponsor_account_root": self.sponsor_account_root,
            "sponsor_budget_root": self.sponsor_budget_root,
            "fee_cap_root": self.fee_cap_root,
            "private_lane_auction_root": self.private_lane_auction_root,
            "private_lane_bid_root": self.private_lane_bid_root,
            "anti_spam_reservation_root": self.anti_spam_reservation_root,
            "pq_authorization_root": self.pq_authorization_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "slashing_root": self.slashing_root,
            "replenishment_intent_root": self.replenishment_intent_root,
            "fairness_scorecard_root": self.fairness_scorecard_root,
            "lane_pressure_window_root": self.lane_pressure_window_root,
            "treasury_proof_root": self.treasury_proof_root,
            "active_lane_root": self.active_lane_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn roots_root(&self) -> String {
        low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-MARKET-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorMarketCounters {
    pub sponsor_count: u64,
    pub active_sponsor_count: u64,
    pub sponsor_budget_count: u64,
    pub active_budget_count: u64,
    pub fee_cap_count: u64,
    pub active_fee_cap_count: u64,
    pub auction_count: u64,
    pub open_auction_count: u64,
    pub settled_auction_count: u64,
    pub bid_count: u64,
    pub accepted_bid_count: u64,
    pub reservation_count: u64,
    pub active_reservation_count: u64,
    pub pq_authorization_count: u64,
    pub usable_pq_authorization_count: u64,
    pub rebate_receipt_count: u64,
    pub settled_rebate_receipt_count: u64,
    pub slashing_count: u64,
    pub pending_slashing_count: u64,
    pub replenishment_intent_count: u64,
    pub live_replenishment_intent_count: u64,
    pub fairness_scorecard_count: u64,
    pub pressure_window_count: u64,
    pub treasury_proof_count: u64,
    pub final_treasury_proof_count: u64,
    pub active_lane_count: u64,
    pub total_budget_units: u64,
    pub total_available_units: u64,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub total_slashed_units: u64,
    pub total_rebate_units: u64,
    pub aggregate_pressure_bps: u64,
    pub average_fairness_score: u64,
}

impl LowFeeSponsorMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_market_counters",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "sponsor_count": self.sponsor_count,
            "active_sponsor_count": self.active_sponsor_count,
            "sponsor_budget_count": self.sponsor_budget_count,
            "active_budget_count": self.active_budget_count,
            "fee_cap_count": self.fee_cap_count,
            "active_fee_cap_count": self.active_fee_cap_count,
            "auction_count": self.auction_count,
            "open_auction_count": self.open_auction_count,
            "settled_auction_count": self.settled_auction_count,
            "bid_count": self.bid_count,
            "accepted_bid_count": self.accepted_bid_count,
            "reservation_count": self.reservation_count,
            "active_reservation_count": self.active_reservation_count,
            "pq_authorization_count": self.pq_authorization_count,
            "usable_pq_authorization_count": self.usable_pq_authorization_count,
            "rebate_receipt_count": self.rebate_receipt_count,
            "settled_rebate_receipt_count": self.settled_rebate_receipt_count,
            "slashing_count": self.slashing_count,
            "pending_slashing_count": self.pending_slashing_count,
            "replenishment_intent_count": self.replenishment_intent_count,
            "live_replenishment_intent_count": self.live_replenishment_intent_count,
            "fairness_scorecard_count": self.fairness_scorecard_count,
            "pressure_window_count": self.pressure_window_count,
            "treasury_proof_count": self.treasury_proof_count,
            "final_treasury_proof_count": self.final_treasury_proof_count,
            "active_lane_count": self.active_lane_count,
            "total_budget_units": self.total_budget_units,
            "total_available_units": self.total_available_units,
            "total_reserved_units": self.total_reserved_units,
            "total_spent_units": self.total_spent_units,
            "total_slashed_units": self.total_slashed_units,
            "total_rebate_units": self.total_rebate_units,
            "aggregate_pressure_bps": self.aggregate_pressure_bps,
            "average_fairness_score": self.average_fairness_score,
        })
    }

    pub fn counters_root(&self) -> String {
        low_fee_sponsor_market_payload_root(
            "LOW-FEE-SPONSOR-MARKET-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorMarketState {
    pub height: u64,
    pub config: LowFeeSponsorMarketConfig,
    pub sponsor_accounts: BTreeMap<String, SponsorAccount>,
    pub sponsor_budgets: BTreeMap<String, SponsorBudget>,
    pub fee_caps: BTreeMap<String, LaneFeeCap>,
    pub private_lane_auctions: BTreeMap<String, PrivateLaneAuction>,
    pub private_lane_bids: BTreeMap<String, PrivateLaneBid>,
    pub anti_spam_reservations: BTreeMap<String, AntiSpamReservation>,
    pub pq_authorizations: BTreeMap<String, PqSponsorAuthorization>,
    pub rebate_receipts: BTreeMap<String, RebateReceipt>,
    pub slashings: BTreeMap<String, SponsorshipSlashing>,
    pub replenishment_intents: BTreeMap<String, BudgetReplenishmentIntent>,
    pub fairness_scorecards: BTreeMap<String, FairnessScorecard>,
    pub lane_pressure_windows: BTreeMap<String, LaneFeePressureWindow>,
    pub treasury_proofs: BTreeMap<String, MoneroTreasuryProof>,
}

impl Default for LowFeeSponsorMarketState {
    fn default() -> Self {
        Self::new()
    }
}

impl LowFeeSponsorMarketState {
    pub fn new() -> Self {
        Self {
            height: 0,
            config: LowFeeSponsorMarketConfig::default(),
            sponsor_accounts: BTreeMap::new(),
            sponsor_budgets: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            private_lane_auctions: BTreeMap::new(),
            private_lane_bids: BTreeMap::new(),
            anti_spam_reservations: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            rebate_receipts: BTreeMap::new(),
            slashings: BTreeMap::new(),
            replenishment_intents: BTreeMap::new(),
            fairness_scorecards: BTreeMap::new(),
            lane_pressure_windows: BTreeMap::new(),
            treasury_proofs: BTreeMap::new(),
        }
    }

    pub fn with_config(config: LowFeeSponsorMarketConfig) -> LowFeeSponsorMarketResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> LowFeeSponsorMarketResult<Self> {
        let mut state = Self::with_config(LowFeeSponsorMarketConfig::devnet())?;
        state.set_height(42)?;
        let fee_asset_id = state.config.fee_asset_id.clone();

        let foundation = SponsorAccount::new(
            "devnet-low-fee-foundation",
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-OPERATOR", "foundation"),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-SETTLEMENT", "foundation"),
            &fee_asset_id,
            5_000_000,
            state.config.max_lane_exposure_bps,
            state.config.target_fairness_score,
            state.height,
            1,
        )?;
        let bridge_guild = SponsorAccount::new(
            "devnet-bridge-guild",
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-OPERATOR", "bridge-guild"),
            &low_fee_sponsor_market_string_root(
                "LOW-FEE-SPONSOR-DEVNET-SETTLEMENT",
                "bridge-guild",
            ),
            &fee_asset_id,
            3_500_000,
            state.config.max_lane_exposure_bps,
            state.config.target_fairness_score,
            state.height,
            2,
        )?;
        let foundation_id = state.insert_sponsor_account(foundation)?;
        let bridge_guild_id = state.insert_sponsor_account(bridge_guild)?;

        let private_budget = SponsorBudget::new(
            &foundation_id,
            LowFeeSponsorLane::PrivateTransfer,
            LowFeeSponsorLane::PrivateTransfer.default_lane_key(),
            &fee_asset_id,
            0,
            1_500_000,
            950,
            8_500,
            4,
            state.height,
            state.height.saturating_add(state.config.epoch_blocks),
            10,
        )?;
        let bridge_budget = SponsorBudget::new(
            &bridge_guild_id,
            LowFeeSponsorLane::MoneroBridge,
            LowFeeSponsorLane::MoneroBridge.default_lane_key(),
            &fee_asset_id,
            0,
            2_000_000,
            1_250,
            9_000,
            6,
            state.height,
            state.height.saturating_add(state.config.epoch_blocks),
            11,
        )?;
        let proof_budget = SponsorBudget::new(
            &foundation_id,
            LowFeeSponsorLane::ProofJob,
            LowFeeSponsorLane::ProofJob.default_lane_key(),
            &fee_asset_id,
            0,
            800_000,
            2_500,
            7_500,
            5,
            state.height,
            state.height.saturating_add(state.config.epoch_blocks),
            12,
        )?;
        let private_budget_id = state.insert_sponsor_budget(private_budget)?;
        let bridge_budget_id = state.insert_sponsor_budget(bridge_budget)?;
        let proof_budget_id = state.insert_sponsor_budget(proof_budget)?;

        let private_cap = LaneFeeCap::new(
            LowFeeSponsorLane::PrivateTransfer,
            LowFeeSponsorLane::PrivateTransfer.default_lane_key(),
            &fee_asset_id,
            700,
            950,
            7_000,
            12_000,
            state.height,
            state.height.saturating_add(state.config.epoch_blocks),
            "devnet-controller",
            20,
        )?;
        let bridge_cap = LaneFeeCap::new(
            LowFeeSponsorLane::MoneroBridge,
            LowFeeSponsorLane::MoneroBridge.default_lane_key(),
            &fee_asset_id,
            900,
            1_250,
            7_500,
            12_000,
            state.height,
            state.height.saturating_add(state.config.epoch_blocks),
            "devnet-controller",
            21,
        )?;
        let private_cap_root = private_cap.fee_cap_root();
        let bridge_cap_root = bridge_cap.fee_cap_root();
        state.insert_fee_cap(private_cap)?;
        state.insert_fee_cap(bridge_cap)?;

        let pq_authorization = PqSponsorAuthorization::new(
            &foundation_id,
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-DELEGATE", "lane-solver"),
            vec![
                LowFeeSponsorLane::PrivateTransfer,
                LowFeeSponsorLane::ProofJob,
            ],
            400_000,
            state.height,
            state.height.saturating_add(120),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-PQ-KEY", "lane-solver"),
            &state
                .sponsor_budgets
                .get(&private_budget_id)
                .map(SponsorBudget::budget_root)
                .pipe_option_string_or_empty(),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-SIG", "lane-solver"),
            256,
            2,
            30,
        )?;
        let pq_authorization_id = state.insert_pq_authorization(pq_authorization)?;

        let reservation = AntiSpamReservation::new(
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-USER", "alice"),
            LowFeeSponsorLane::PrivateTransfer,
            LowFeeSponsorLane::PrivateTransfer.default_lane_key(),
            &low_fee_sponsor_market_metadata_root(&json!({
                "tx": "devnet-private-transfer-0",
                "lane": "private_transfer"
            })),
            &fee_asset_id,
            12,
            state.config.min_reservation_bond_units,
            state.height,
            state
                .height
                .saturating_add(state.config.reservation_ttl_blocks),
            &pq_authorization_id,
            40,
        )?;
        let reservation_id = state.insert_anti_spam_reservation(reservation)?;

        let auction = PrivateLaneAuction::new(
            &proof_budget_id,
            &foundation_id,
            LowFeeSponsorLane::ProofJob,
            LowFeeSponsorLane::ProofJob.default_lane_key(),
            &fee_asset_id,
            0,
            75_000,
            1_000,
            2_500,
            8_000,
            state.height,
            state
                .height
                .saturating_add(state.config.auction_commit_blocks),
            state
                .height
                .saturating_add(state.config.auction_commit_blocks)
                .saturating_add(state.config.auction_reveal_blocks),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-PRIVACY-SET", "proofs"),
            &low_fee_sponsor_market_metadata_root(&json!({"lane": "proof_job", "max_batch": 32})),
            50,
        )?;
        let auction_id = state.insert_private_lane_auction(auction)?;

        let mut bid = PrivateLaneBid::new(
            &auction_id,
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-BIDDER", "prover"),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-NULLIFIER", "proof-bid"),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-BID", "proof-bid"),
            24_000,
            2_000,
            7_000,
            "",
            &pq_authorization_id,
            state.height,
            51,
        )?;
        bid.reveal(
            1_700,
            6_500,
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-BID-REVEAL", "proof-bid"),
            state.height.saturating_add(7),
        )?;
        state.insert_private_lane_bid(bid)?;
        state.set_height(state.height.saturating_add(7))?;
        state.settle_private_lane_auction(&auction_id)?;

        let pressure = LaneFeePressureWindow::new(
            LowFeeSponsorLane::PrivateTransfer,
            LowFeeSponsorLane::PrivateTransfer.default_lane_key(),
            state.height.saturating_sub(12),
            state.height,
            vec![640, 690, 720, 730, 760, 800, 830],
            700,
            &private_cap_root,
            &state.private_lane_auction_root(),
        )?;
        let pressure_id = state.insert_fee_pressure_window(pressure)?;

        let receipt = RebateReceipt::new(
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-TX", "private-transfer-0"),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-PAYER", "alice"),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-RECIPIENT", "bob"),
            &foundation_id,
            &private_budget_id,
            LowFeeSponsorLane::PrivateTransfer,
            LowFeeSponsorLane::PrivateTransfer.default_lane_key(),
            &fee_asset_id,
            1_100,
            700,
            400,
            400,
            "",
            "",
            &reservation_id,
            &state
                .fee_caps
                .values()
                .find(|cap| cap.lane == LowFeeSponsorLane::PrivateTransfer)
                .map(|cap| cap.fee_cap_id.clone())
                .pipe_option_string_or_empty(),
            &pressure_id,
            &low_fee_sponsor_market_string_root(
                "LOW-FEE-SPONSOR-DEVNET-RECEIPT",
                "private-transfer-0",
            ),
            state.height,
            60,
        )?;
        state.insert_rebate_receipt(receipt)?;

        let treasury = MoneroTreasuryProof::new(
            &bridge_guild_id,
            &fee_asset_id,
            LOW_FEE_SPONSOR_DEVNET_MONERO_NETWORK,
            "devnet-monero-tx-bridge-replenish",
            0,
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-XMR-OUTPUT", "bridge"),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-XMR-AMOUNT", "bridge"),
            state.config.min_treasury_confirmations,
            state.config.min_treasury_confirmations,
            "42",
            &state.sponsor_budget_root(),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-CHECKPOINT", "bridge"),
            state.height,
            70,
        )?;
        let treasury_proof_id = state.insert_treasury_proof(treasury)?;
        let mut replenish = BudgetReplenishmentIntent::new(
            &bridge_guild_id,
            &bridge_budget_id,
            &fee_asset_id,
            250_000,
            state.config.min_treasury_confirmations,
            "devnet-monero-tx-bridge-replenish",
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-XMR-OUTPUT", "bridge"),
            &treasury_proof_id,
            state.height,
            state.height.saturating_add(120),
            80,
        )?;
        replenish.status = BudgetReplenishmentStatus::Proved;
        let replenish_id = state.insert_replenishment_intent(replenish)?;
        state.apply_replenishment_intent(&replenish_id)?;

        let scorecard = FairnessScorecard::new(
            &foundation_id,
            0,
            2,
            1,
            1,
            0,
            1,
            6_500,
            1_200,
            128,
            100,
            0,
            &merkle_root("LOW-FEE-SPONSOR-FAIRNESS-PREVIOUS", &[]),
            state.height,
            90,
        )?;
        state.insert_fairness_scorecard(scorecard)?;

        let mut slashing = SponsorshipSlashing::new(
            &foundation_id,
            "reservation",
            &reservation_id,
            &low_fee_sponsor_market_string_root(
                "LOW-FEE-SPONSOR-DEVNET-EVIDENCE",
                "reservation-ok",
            ),
            &low_fee_sponsor_market_string_root("LOW-FEE-SPONSOR-DEVNET-CHALLENGER", "watchtower"),
            10,
            2,
            state.height,
            100,
        )?;
        slashing.status = SponsorshipSlashingStatus::Rejected;
        slashing.resolved_at_height = state.height.saturating_add(1);
        state.insert_sponsorship_slashing(slashing)?;

        let bridge_pressure = LaneFeePressureWindow::new(
            LowFeeSponsorLane::MoneroBridge,
            LowFeeSponsorLane::MoneroBridge.default_lane_key(),
            state.height.saturating_sub(12),
            state.height,
            vec![850, 900, 920, 960, 1_000, 1_050, 1_100],
            900,
            &bridge_cap_root,
            &state.private_lane_auction_root(),
        )?;
        state.insert_fee_pressure_window(bridge_pressure)?;
        state.refresh_sponsor_roots();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeSponsorMarketResult<String> {
        self.height = height;
        for budget in self.sponsor_budgets.values_mut() {
            if budget.status.spendable() && height > budget.valid_until_height {
                budget.status = SponsorBudgetStatus::Expired;
            }
            if budget.available_units() == 0 && budget.status.spendable() {
                budget.status = SponsorBudgetStatus::Exhausted;
            }
        }
        for cap in self.fee_caps.values_mut() {
            if cap.status.usable() && height > cap.expires_at_height {
                cap.status = LaneFeeCapStatus::Expired;
            }
        }
        for auction in self.private_lane_auctions.values_mut() {
            auction.refresh_status_for_height(height);
        }
        for bid in self.private_lane_bids.values_mut() {
            let auction_status = self
                .private_lane_auctions
                .get(&bid.auction_id)
                .map(|auction| auction.status);
            if matches!(auction_status, Some(PrivateLaneAuctionStatus::Expired))
                && bid.status.live()
            {
                bid.status = PrivateLaneBidStatus::Expired;
            }
        }
        for reservation in self.anti_spam_reservations.values_mut() {
            if reservation.status.active() && height > reservation.expires_at_height {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for authorization in self.pq_authorizations.values_mut() {
            if authorization.status.usable() && height > authorization.valid_until_height {
                authorization.status = SponsorAuthorizationStatus::Expired;
            }
        }
        for intent in self.replenishment_intents.values_mut() {
            if intent.status.live() && height > intent.expires_at_height {
                intent.status = BudgetReplenishmentStatus::Expired;
            }
        }
        self.refresh_sponsor_roots();
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn insert_sponsor_account(
        &mut self,
        account: SponsorAccount,
    ) -> LowFeeSponsorMarketResult<String> {
        let sponsor_id = account.validate()?;
        if self.sponsor_accounts.contains_key(&sponsor_id) {
            return Err("duplicate sponsor account".to_string());
        }
        self.sponsor_accounts.insert(sponsor_id.clone(), account);
        Ok(sponsor_id)
    }

    pub fn insert_sponsor_budget(
        &mut self,
        budget: SponsorBudget,
    ) -> LowFeeSponsorMarketResult<String> {
        let budget_id = budget.validate()?;
        if self.sponsor_budgets.contains_key(&budget_id) {
            return Err("duplicate sponsor budget".to_string());
        }
        let sponsor = self
            .sponsor_accounts
            .get_mut(&budget.sponsor_id)
            .ok_or_else(|| "sponsor budget references missing sponsor".to_string())?;
        if sponsor.fee_asset_id != budget.fee_asset_id {
            return Err("sponsor budget fee asset mismatch".to_string());
        }
        sponsor.allocate_budget(budget.total_budget_units, self.height)?;
        self.sponsor_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_fee_cap(&mut self, cap: LaneFeeCap) -> LowFeeSponsorMarketResult<String> {
        let cap_id = cap.validate()?;
        if self.fee_caps.contains_key(&cap_id) {
            return Err("duplicate fee cap".to_string());
        }
        self.fee_caps.insert(cap_id.clone(), cap);
        Ok(cap_id)
    }

    pub fn insert_private_lane_auction(
        &mut self,
        auction: PrivateLaneAuction,
    ) -> LowFeeSponsorMarketResult<String> {
        let auction_id = auction.validate()?;
        if self.private_lane_auctions.contains_key(&auction_id) {
            return Err("duplicate private lane auction".to_string());
        }
        let budget = self
            .sponsor_budgets
            .get_mut(&auction.budget_id)
            .ok_or_else(|| "auction references missing sponsor budget".to_string())?;
        if budget.sponsor_id != auction.sponsor_id {
            return Err("auction sponsor does not match budget sponsor".to_string());
        }
        if budget.lane != auction.lane || budget.lane_key != auction.lane_key {
            return Err("auction lane does not match sponsor budget".to_string());
        }
        if budget.fee_asset_id != auction.fee_asset_id {
            return Err("auction fee asset does not match budget".to_string());
        }
        if !budget.active_at(self.height) {
            return Err("auction budget is not active at current height".to_string());
        }
        budget.reserve_units(auction.offered_rebate_units)?;
        self.private_lane_auctions
            .insert(auction_id.clone(), auction);
        self.refresh_auction_roots();
        Ok(auction_id)
    }

    pub fn insert_private_lane_bid(
        &mut self,
        bid: PrivateLaneBid,
    ) -> LowFeeSponsorMarketResult<String> {
        let bid_id = bid.validate()?;
        if self.private_lane_bids.contains_key(&bid_id) {
            return Err("duplicate private lane bid".to_string());
        }
        let auction = self
            .private_lane_auctions
            .get_mut(&bid.auction_id)
            .ok_or_else(|| "bid references missing auction".to_string())?;
        if !auction.accepts_commit_at(bid.submitted_at_height)
            && !matches!(bid.status, PrivateLaneBidStatus::Revealed)
        {
            return Err("auction is not accepting bid commits".to_string());
        }
        if bid.requested_rebate_units > auction.remaining_rebate_units() {
            return Err("bid requests more rebate than auction has remaining".to_string());
        }
        if bid.max_fee_micro_units > auction.fee_cap_micro_units {
            return Err("bid fee exceeds auction fee cap".to_string());
        }
        if bid.rebate_bps > auction.max_rebate_bps {
            return Err("bid rebate exceeds auction max rebate".to_string());
        }
        if !bid.reservation_id.is_empty() {
            let reservation = self
                .anti_spam_reservations
                .get(&bid.reservation_id)
                .ok_or_else(|| "bid references missing reservation".to_string())?;
            if !reservation.active_at(self.height) {
                return Err("bid reservation is not active".to_string());
            }
        }
        if !bid.pq_authorization_id.is_empty() {
            let authorization = self
                .pq_authorizations
                .get(&bid.pq_authorization_id)
                .ok_or_else(|| "bid references missing pq authorization".to_string())?;
            if !authorization.can_authorize(auction.lane, self.height, bid.requested_rebate_units) {
                return Err("pq authorization does not cover bid".to_string());
            }
        }
        auction.bid_count = auction.bid_count.saturating_add(1);
        self.private_lane_bids.insert(bid_id.clone(), bid);
        self.refresh_auction_roots();
        Ok(bid_id)
    }

    pub fn reveal_private_lane_bid(
        &mut self,
        bid_id: &str,
        revealed_fee_micro_units: u64,
        revealed_rebate_bps: u64,
        reveal_proof_root: &str,
    ) -> LowFeeSponsorMarketResult<String> {
        let bid = self
            .private_lane_bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown private lane bid".to_string())?;
        let auction = self
            .private_lane_auctions
            .get(&bid.auction_id)
            .ok_or_else(|| "bid references missing auction".to_string())?;
        if !auction.accepts_reveal_at(self.height) {
            return Err("auction is not accepting bid reveals".to_string());
        }
        bid.reveal(
            revealed_fee_micro_units,
            revealed_rebate_bps,
            reveal_proof_root,
            self.height,
        )?;
        let bid_root = bid.bid_root();
        self.refresh_auction_roots();
        Ok(bid_root)
    }

    pub fn settle_private_lane_auction(
        &mut self,
        auction_id: &str,
    ) -> LowFeeSponsorMarketResult<Vec<PrivateLaneBid>> {
        let auction = self
            .private_lane_auctions
            .get(auction_id)
            .ok_or_else(|| "unknown private lane auction".to_string())?
            .clone();
        let mut bid_order = self
            .private_lane_bids
            .iter()
            .filter(|(_, bid)| {
                bid.auction_id == auction_id && bid.status == PrivateLaneBidStatus::Revealed
            })
            .map(|(bid_id, bid)| {
                (
                    bid_id.clone(),
                    bid.score_units(),
                    bid.revealed_fee_micro_units,
                    bid.requested_rebate_units,
                )
            })
            .collect::<Vec<_>>();
        bid_order.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.3.cmp(&right.3))
                .then_with(|| left.0.cmp(&right.0))
        });

        let mut remaining = auction.offered_rebate_units;
        let mut accepted = Vec::new();
        let mut clearing_fee_micro_units = 0_u64;
        for (bid_id, _, fee_micro_units, requested_rebate_units) in bid_order {
            let bid = self
                .private_lane_bids
                .get_mut(&bid_id)
                .ok_or_else(|| "ordered bid disappeared during settlement".to_string())?;
            if requested_rebate_units <= remaining {
                remaining = remaining.saturating_sub(requested_rebate_units);
                clearing_fee_micro_units = clearing_fee_micro_units.max(fee_micro_units);
                bid.status = PrivateLaneBidStatus::Accepted;
                accepted.push(bid.clone());
                if !bid.pq_authorization_id.is_empty() {
                    if let Some(authorization) =
                        self.pq_authorizations.get_mut(&bid.pq_authorization_id)
                    {
                        authorization.consume_units(requested_rebate_units)?;
                    }
                }
            } else {
                bid.status = PrivateLaneBidStatus::Rejected;
            }
        }
        let filled = auction.offered_rebate_units.saturating_sub(remaining);
        if let Some(budget) = self.sponsor_budgets.get_mut(&auction.budget_id) {
            budget.settle_reserved_units(auction.offered_rebate_units, filled)?;
        }
        let settled_auction = self
            .private_lane_auctions
            .get_mut(auction_id)
            .ok_or_else(|| "auction missing during settlement".to_string())?;
        settled_auction.filled_rebate_units = filled;
        settled_auction.accepted_bid_count = accepted.len() as u64;
        settled_auction.clearing_fee_micro_units = clearing_fee_micro_units;
        settled_auction.status = PrivateLaneAuctionStatus::Settled;
        self.refresh_auction_roots();
        Ok(accepted)
    }

    pub fn insert_anti_spam_reservation(
        &mut self,
        reservation: AntiSpamReservation,
    ) -> LowFeeSponsorMarketResult<String> {
        let reservation_id = reservation.validate()?;
        if reservation.bond_units < self.config.min_reservation_bond_units {
            return Err("anti-spam reservation bond below configured minimum".to_string());
        }
        if self.anti_spam_reservations.contains_key(&reservation_id) {
            return Err("duplicate anti-spam reservation".to_string());
        }
        if !reservation.pq_authorization_id.is_empty() {
            let authorization = self
                .pq_authorizations
                .get(&reservation.pq_authorization_id)
                .ok_or_else(|| "reservation references missing pq authorization".to_string())?;
            if !authorization.can_authorize(
                reservation.lane,
                self.height,
                reservation.reserved_units,
            ) {
                return Err("pq authorization does not cover reservation".to_string());
            }
        }
        self.anti_spam_reservations
            .insert(reservation_id.clone(), reservation);
        Ok(reservation_id)
    }

    pub fn insert_pq_authorization(
        &mut self,
        authorization: PqSponsorAuthorization,
    ) -> LowFeeSponsorMarketResult<String> {
        let authorization_id = authorization.validate()?;
        if self.pq_authorizations.contains_key(&authorization_id) {
            return Err("duplicate pq sponsor authorization".to_string());
        }
        if !self
            .sponsor_accounts
            .contains_key(&authorization.sponsor_id)
        {
            return Err("pq authorization references missing sponsor".to_string());
        }
        self.pq_authorizations
            .insert(authorization_id.clone(), authorization);
        self.refresh_sponsor_roots();
        Ok(authorization_id)
    }

    pub fn insert_rebate_receipt(
        &mut self,
        receipt: RebateReceipt,
    ) -> LowFeeSponsorMarketResult<String> {
        let receipt_id = receipt.validate()?;
        if self.rebate_receipts.contains_key(&receipt_id) {
            return Err("duplicate rebate receipt".to_string());
        }
        let budget = self
            .sponsor_budgets
            .get_mut(&receipt.budget_id)
            .ok_or_else(|| "rebate receipt references missing budget".to_string())?;
        if budget.sponsor_id != receipt.sponsor_id {
            return Err("rebate receipt sponsor does not match budget".to_string());
        }
        if budget.lane != receipt.lane || budget.lane_key != receipt.lane_key {
            return Err("rebate receipt lane does not match budget".to_string());
        }
        if budget.fee_asset_id != receipt.fee_asset_id {
            return Err("rebate receipt fee asset does not match budget".to_string());
        }
        if receipt.status.final_for_accounting() && receipt.sponsor_paid_units > 0 {
            budget.spend_available_units(receipt.sponsor_paid_units)?;
        }
        if !receipt.reservation_id.is_empty() {
            let reservation = self
                .anti_spam_reservations
                .get_mut(&receipt.reservation_id)
                .ok_or_else(|| "rebate receipt references missing reservation".to_string())?;
            if reservation.status.active() {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        if !receipt.auction_id.is_empty()
            && !self.private_lane_auctions.contains_key(&receipt.auction_id)
        {
            return Err("rebate receipt references missing auction".to_string());
        }
        if !receipt.bid_id.is_empty() && !self.private_lane_bids.contains_key(&receipt.bid_id) {
            return Err("rebate receipt references missing bid".to_string());
        }
        if !receipt.fee_cap_id.is_empty() && !self.fee_caps.contains_key(&receipt.fee_cap_id) {
            return Err("rebate receipt references missing fee cap".to_string());
        }
        if !receipt.pressure_window_id.is_empty()
            && !self
                .lane_pressure_windows
                .contains_key(&receipt.pressure_window_id)
        {
            return Err("rebate receipt references missing pressure window".to_string());
        }
        self.rebate_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_sponsorship_slashing(
        &mut self,
        slashing: SponsorshipSlashing,
    ) -> LowFeeSponsorMarketResult<String> {
        let slashing_id = slashing.validate()?;
        if self.slashings.contains_key(&slashing_id) {
            return Err("duplicate sponsorship slashing".to_string());
        }
        if !self.sponsor_accounts.contains_key(&slashing.sponsor_id) {
            return Err("slashing references missing sponsor".to_string());
        }
        if !self.slashing_target_exists(&slashing.target_kind, &slashing.target_id) {
            return Err("slashing target is not present".to_string());
        }
        if slashing.status.applies_penalty() {
            self.apply_slashing_penalty(&slashing)?;
        }
        self.slashings.insert(slashing_id.clone(), slashing);
        Ok(slashing_id)
    }

    pub fn insert_replenishment_intent(
        &mut self,
        intent: BudgetReplenishmentIntent,
    ) -> LowFeeSponsorMarketResult<String> {
        let intent_id = intent.validate()?;
        if self.replenishment_intents.contains_key(&intent_id) {
            return Err("duplicate budget replenishment intent".to_string());
        }
        let budget = self
            .sponsor_budgets
            .get(&intent.budget_id)
            .ok_or_else(|| "replenishment intent references missing budget".to_string())?;
        if budget.sponsor_id != intent.sponsor_id {
            return Err("replenishment intent sponsor does not match budget".to_string());
        }
        if budget.fee_asset_id != intent.fee_asset_id {
            return Err("replenishment intent fee asset does not match budget".to_string());
        }
        if !intent.treasury_proof_id.is_empty()
            && !self.treasury_proofs.contains_key(&intent.treasury_proof_id)
        {
            return Err("replenishment intent references missing treasury proof".to_string());
        }
        self.replenishment_intents.insert(intent_id.clone(), intent);
        self.refresh_budget_replenishment_roots();
        Ok(intent_id)
    }

    pub fn apply_replenishment_intent(
        &mut self,
        intent_id: &str,
    ) -> LowFeeSponsorMarketResult<String> {
        let intent = self
            .replenishment_intents
            .get(intent_id)
            .ok_or_else(|| "unknown replenishment intent".to_string())?
            .clone();
        if !matches!(intent.status, BudgetReplenishmentStatus::Proved) {
            return Err("replenishment intent is not proved".to_string());
        }
        let proof = self
            .treasury_proofs
            .get(&intent.treasury_proof_id)
            .ok_or_else(|| "replenishment intent lacks treasury proof".to_string())?;
        if !proof.status.final_for_replenishment() {
            return Err("treasury proof is not final for replenishment".to_string());
        }
        if proof.confirmations < intent.min_confirmations {
            return Err("treasury proof confirmations below intent minimum".to_string());
        }
        let sponsor = self
            .sponsor_accounts
            .get_mut(&intent.sponsor_id)
            .ok_or_else(|| "replenishment sponsor missing".to_string())?;
        sponsor.replenish(intent.requested_units, self.height)?;
        sponsor.allocate_budget(intent.requested_units, self.height)?;
        let budget = self
            .sponsor_budgets
            .get_mut(&intent.budget_id)
            .ok_or_else(|| "replenishment budget missing".to_string())?;
        budget.replenish(intent.requested_units)?;
        if let Some(stored_intent) = self.replenishment_intents.get_mut(intent_id) {
            stored_intent.status = BudgetReplenishmentStatus::Applied;
        }
        self.refresh_budget_replenishment_roots();
        Ok(self.state_root())
    }

    pub fn insert_fairness_scorecard(
        &mut self,
        scorecard: FairnessScorecard,
    ) -> LowFeeSponsorMarketResult<String> {
        let scorecard_id = scorecard.validate()?;
        if self.fairness_scorecards.contains_key(&scorecard_id) {
            return Err("duplicate fairness scorecard".to_string());
        }
        if !self.sponsor_accounts.contains_key(&scorecard.sponsor_id) {
            return Err("fairness scorecard references missing sponsor".to_string());
        }
        self.fairness_scorecards
            .insert(scorecard_id.clone(), scorecard);
        Ok(scorecard_id)
    }

    pub fn insert_fee_pressure_window(
        &mut self,
        window: LaneFeePressureWindow,
    ) -> LowFeeSponsorMarketResult<String> {
        let window_id = window.validate()?;
        if self.lane_pressure_windows.contains_key(&window_id) {
            return Err("duplicate lane fee pressure window".to_string());
        }
        self.lane_pressure_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn insert_treasury_proof(
        &mut self,
        proof: MoneroTreasuryProof,
    ) -> LowFeeSponsorMarketResult<String> {
        let proof_id = proof.validate()?;
        if self.treasury_proofs.contains_key(&proof_id) {
            return Err("duplicate monero treasury proof".to_string());
        }
        if !self.sponsor_accounts.contains_key(&proof.sponsor_id) {
            return Err("treasury proof references missing sponsor".to_string());
        }
        self.treasury_proofs.insert(proof_id.clone(), proof);
        self.refresh_sponsor_roots();
        Ok(proof_id)
    }

    pub fn active_lane_keys(&self) -> Vec<String> {
        self.sponsor_budgets
            .values()
            .filter(|budget| budget.active_at(self.height))
            .map(|budget| budget.lane_key.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn active_lane_root(&self) -> String {
        merkle_root(
            "LOW-FEE-SPONSOR-ACTIVE-LANE",
            &self
                .active_lane_keys()
                .into_iter()
                .map(Value::String)
                .collect::<Vec<_>>(),
        )
    }

    pub fn nullifier_root(&self) -> String {
        let mut nullifiers = BTreeSet::<String>::new();
        for bid in self.private_lane_bids.values() {
            nullifiers.insert(bid.payer_nullifier.clone());
        }
        for receipt in self.rebate_receipts.values() {
            nullifiers.insert(receipt.tx_nullifier.clone());
        }
        merkle_root(
            "LOW-FEE-SPONSOR-NULLIFIER",
            &nullifiers
                .into_iter()
                .map(Value::String)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsor_account_root(&self) -> String {
        low_fee_sponsor_account_set_root(
            &self.sponsor_accounts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn sponsor_budget_root(&self) -> String {
        low_fee_sponsor_budget_set_root(&self.sponsor_budgets.values().cloned().collect::<Vec<_>>())
    }

    pub fn fee_cap_root(&self) -> String {
        low_fee_sponsor_fee_cap_set_root(&self.fee_caps.values().cloned().collect::<Vec<_>>())
    }

    pub fn private_lane_auction_root(&self) -> String {
        low_fee_sponsor_auction_set_root(
            &self
                .private_lane_auctions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_lane_bid_root(&self) -> String {
        low_fee_sponsor_bid_set_root(&self.private_lane_bids.values().cloned().collect::<Vec<_>>())
    }

    pub fn anti_spam_reservation_root(&self) -> String {
        low_fee_sponsor_reservation_set_root(
            &self
                .anti_spam_reservations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_authorization_root(&self) -> String {
        low_fee_sponsor_authorization_set_root(
            &self.pq_authorizations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn rebate_receipt_root(&self) -> String {
        low_fee_sponsor_rebate_receipt_set_root(
            &self.rebate_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn slashing_root(&self) -> String {
        low_fee_sponsor_slashing_set_root(&self.slashings.values().cloned().collect::<Vec<_>>())
    }

    pub fn replenishment_intent_root(&self) -> String {
        low_fee_sponsor_replenishment_intent_set_root(
            &self
                .replenishment_intents
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn fairness_scorecard_root(&self) -> String {
        low_fee_sponsor_fairness_scorecard_set_root(
            &self
                .fairness_scorecards
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn lane_pressure_window_root(&self) -> String {
        low_fee_sponsor_pressure_window_set_root(
            &self
                .lane_pressure_windows
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn treasury_proof_root(&self) -> String {
        low_fee_sponsor_treasury_proof_set_root(
            &self.treasury_proofs.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> LowFeeSponsorMarketRoots {
        LowFeeSponsorMarketRoots {
            config_root: self.config.config_root(),
            sponsor_account_root: self.sponsor_account_root(),
            sponsor_budget_root: self.sponsor_budget_root(),
            fee_cap_root: self.fee_cap_root(),
            private_lane_auction_root: self.private_lane_auction_root(),
            private_lane_bid_root: self.private_lane_bid_root(),
            anti_spam_reservation_root: self.anti_spam_reservation_root(),
            pq_authorization_root: self.pq_authorization_root(),
            rebate_receipt_root: self.rebate_receipt_root(),
            slashing_root: self.slashing_root(),
            replenishment_intent_root: self.replenishment_intent_root(),
            fairness_scorecard_root: self.fairness_scorecard_root(),
            lane_pressure_window_root: self.lane_pressure_window_root(),
            treasury_proof_root: self.treasury_proof_root(),
            active_lane_root: self.active_lane_root(),
            nullifier_root: self.nullifier_root(),
        }
    }

    pub fn counters(&self) -> LowFeeSponsorMarketCounters {
        let mut counters = LowFeeSponsorMarketCounters {
            sponsor_count: self.sponsor_accounts.len() as u64,
            sponsor_budget_count: self.sponsor_budgets.len() as u64,
            fee_cap_count: self.fee_caps.len() as u64,
            auction_count: self.private_lane_auctions.len() as u64,
            bid_count: self.private_lane_bids.len() as u64,
            reservation_count: self.anti_spam_reservations.len() as u64,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            rebate_receipt_count: self.rebate_receipts.len() as u64,
            slashing_count: self.slashings.len() as u64,
            replenishment_intent_count: self.replenishment_intents.len() as u64,
            fairness_scorecard_count: self.fairness_scorecards.len() as u64,
            pressure_window_count: self.lane_pressure_windows.len() as u64,
            treasury_proof_count: self.treasury_proofs.len() as u64,
            active_lane_count: self.active_lane_keys().len() as u64,
            ..LowFeeSponsorMarketCounters::default()
        };
        for sponsor in self.sponsor_accounts.values() {
            if matches!(sponsor.status, SponsorAccountStatus::Active) {
                counters.active_sponsor_count = counters.active_sponsor_count.saturating_add(1);
            }
        }
        for budget in self.sponsor_budgets.values() {
            if budget.active_at(self.height) {
                counters.active_budget_count = counters.active_budget_count.saturating_add(1);
            }
            counters.total_budget_units = counters
                .total_budget_units
                .saturating_add(budget.capacity_units());
            counters.total_available_units = counters
                .total_available_units
                .saturating_add(budget.available_units());
            counters.total_reserved_units = counters
                .total_reserved_units
                .saturating_add(budget.reserved_units);
            counters.total_spent_units = counters
                .total_spent_units
                .saturating_add(budget.spent_units);
            counters.total_slashed_units = counters
                .total_slashed_units
                .saturating_add(budget.slashed_units);
        }
        for cap in self.fee_caps.values() {
            if cap.active_at(self.height) {
                counters.active_fee_cap_count = counters.active_fee_cap_count.saturating_add(1);
            }
        }
        for auction in self.private_lane_auctions.values() {
            if matches!(
                auction.status,
                PrivateLaneAuctionStatus::CommitOpen | PrivateLaneAuctionStatus::RevealOpen
            ) {
                counters.open_auction_count = counters.open_auction_count.saturating_add(1);
            }
            if matches!(auction.status, PrivateLaneAuctionStatus::Settled) {
                counters.settled_auction_count = counters.settled_auction_count.saturating_add(1);
            }
        }
        for bid in self.private_lane_bids.values() {
            if matches!(bid.status, PrivateLaneBidStatus::Accepted) {
                counters.accepted_bid_count = counters.accepted_bid_count.saturating_add(1);
            }
        }
        for reservation in self.anti_spam_reservations.values() {
            if reservation.active_at(self.height) {
                counters.active_reservation_count =
                    counters.active_reservation_count.saturating_add(1);
            }
        }
        for authorization in self.pq_authorizations.values() {
            if authorization.active_at(self.height) {
                counters.usable_pq_authorization_count =
                    counters.usable_pq_authorization_count.saturating_add(1);
            }
        }
        for receipt in self.rebate_receipts.values() {
            counters.total_rebate_units = counters
                .total_rebate_units
                .saturating_add(receipt.rebate_units);
            if receipt.status.final_for_accounting() {
                counters.settled_rebate_receipt_count =
                    counters.settled_rebate_receipt_count.saturating_add(1);
            }
        }
        for slashing in self.slashings.values() {
            if matches!(
                slashing.status,
                SponsorshipSlashingStatus::Open | SponsorshipSlashingStatus::Appealed
            ) {
                counters.pending_slashing_count = counters.pending_slashing_count.saturating_add(1);
            }
        }
        for intent in self.replenishment_intents.values() {
            if intent.status.live() {
                counters.live_replenishment_intent_count =
                    counters.live_replenishment_intent_count.saturating_add(1);
            }
        }
        for proof in self.treasury_proofs.values() {
            if proof.status.final_for_replenishment() {
                counters.final_treasury_proof_count =
                    counters.final_treasury_proof_count.saturating_add(1);
            }
        }
        counters.aggregate_pressure_bps = average_u64(
            self.lane_pressure_windows
                .values()
                .map(|window| window.pressure_bps)
                .collect::<Vec<_>>(),
        );
        counters.average_fairness_score = average_u64(
            self.fairness_scorecards
                .values()
                .map(|scorecard| scorecard.fairness_score)
                .collect::<Vec<_>>(),
        );
        counters
    }

    pub fn state_root(&self) -> String {
        low_fee_sponsor_market_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> LowFeeSponsorMarketResult<String> {
        self.config.validate()?;
        let mut sponsor_allocations = BTreeMap::<String, u64>::new();
        for (id, sponsor) in &self.sponsor_accounts {
            if id != &sponsor.sponsor_id {
                return Err("sponsor account map key mismatch".to_string());
            }
            sponsor.validate()?;
            sponsor_allocations.insert(sponsor.sponsor_id.clone(), 0);
        }
        for (id, budget) in &self.sponsor_budgets {
            if id != &budget.budget_id {
                return Err("sponsor budget map key mismatch".to_string());
            }
            budget.validate()?;
            let sponsor = self
                .sponsor_accounts
                .get(&budget.sponsor_id)
                .ok_or_else(|| "budget references missing sponsor".to_string())?;
            if sponsor.fee_asset_id != budget.fee_asset_id {
                return Err("budget fee asset mismatches sponsor".to_string());
            }
            let allocation = sponsor_allocations
                .entry(budget.sponsor_id.clone())
                .or_default();
            *allocation = allocation
                .saturating_add(budget.total_budget_units)
                .saturating_add(budget.replenished_units);
        }
        for (sponsor_id, allocated_units) in sponsor_allocations {
            let sponsor = self
                .sponsor_accounts
                .get(&sponsor_id)
                .ok_or_else(|| "allocation references missing sponsor".to_string())?;
            if sponsor.allocated_budget_units != allocated_units {
                return Err("sponsor allocation total does not match budgets".to_string());
            }
        }
        for (id, cap) in &self.fee_caps {
            if id != &cap.fee_cap_id {
                return Err("fee cap map key mismatch".to_string());
            }
            cap.validate()?;
        }
        for (id, auction) in &self.private_lane_auctions {
            if id != &auction.auction_id {
                return Err("auction map key mismatch".to_string());
            }
            auction.validate()?;
            let budget = self
                .sponsor_budgets
                .get(&auction.budget_id)
                .ok_or_else(|| "auction references missing budget".to_string())?;
            if budget.sponsor_id != auction.sponsor_id {
                return Err("auction sponsor mismatch".to_string());
            }
            if budget.lane != auction.lane || budget.lane_key != auction.lane_key {
                return Err("auction lane mismatch".to_string());
            }
        }
        let mut bid_nullifiers = BTreeSet::<String>::new();
        for (id, bid) in &self.private_lane_bids {
            if id != &bid.bid_id {
                return Err("bid map key mismatch".to_string());
            }
            bid.validate()?;
            if !self.private_lane_auctions.contains_key(&bid.auction_id) {
                return Err("bid references missing auction".to_string());
            }
            if !bid_nullifiers.insert(bid.payer_nullifier.clone()) {
                return Err("duplicate private lane bid nullifier".to_string());
            }
            if !bid.reservation_id.is_empty()
                && !self
                    .anti_spam_reservations
                    .contains_key(&bid.reservation_id)
            {
                return Err("bid references missing reservation".to_string());
            }
            if !bid.pq_authorization_id.is_empty()
                && !self
                    .pq_authorizations
                    .contains_key(&bid.pq_authorization_id)
            {
                return Err("bid references missing pq authorization".to_string());
            }
        }
        for (id, reservation) in &self.anti_spam_reservations {
            if id != &reservation.reservation_id {
                return Err("reservation map key mismatch".to_string());
            }
            reservation.validate()?;
            if !reservation.pq_authorization_id.is_empty()
                && !self
                    .pq_authorizations
                    .contains_key(&reservation.pq_authorization_id)
            {
                return Err("reservation references missing pq authorization".to_string());
            }
        }
        for (id, authorization) in &self.pq_authorizations {
            if id != &authorization.authorization_id {
                return Err("pq authorization map key mismatch".to_string());
            }
            authorization.validate()?;
            if !self
                .sponsor_accounts
                .contains_key(&authorization.sponsor_id)
            {
                return Err("pq authorization references missing sponsor".to_string());
            }
        }
        let mut receipt_nullifiers = BTreeSet::<String>::new();
        for (id, receipt) in &self.rebate_receipts {
            if id != &receipt.receipt_id {
                return Err("rebate receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !receipt_nullifiers.insert(receipt.tx_nullifier.clone()) {
                return Err("duplicate rebate receipt nullifier".to_string());
            }
            let budget = self
                .sponsor_budgets
                .get(&receipt.budget_id)
                .ok_or_else(|| "rebate receipt references missing budget".to_string())?;
            if budget.sponsor_id != receipt.sponsor_id {
                return Err("rebate receipt sponsor mismatch".to_string());
            }
            if budget.lane != receipt.lane || budget.lane_key != receipt.lane_key {
                return Err("rebate receipt lane mismatch".to_string());
            }
        }
        for (id, slashing) in &self.slashings {
            if id != &slashing.slashing_id {
                return Err("slashing map key mismatch".to_string());
            }
            slashing.validate()?;
            if !self.sponsor_accounts.contains_key(&slashing.sponsor_id) {
                return Err("slashing references missing sponsor".to_string());
            }
            if !self.slashing_target_exists(&slashing.target_kind, &slashing.target_id) {
                return Err("slashing references missing target".to_string());
            }
        }
        for (id, intent) in &self.replenishment_intents {
            if id != &intent.intent_id {
                return Err("replenishment intent map key mismatch".to_string());
            }
            intent.validate()?;
            if !self.sponsor_accounts.contains_key(&intent.sponsor_id) {
                return Err("replenishment intent references missing sponsor".to_string());
            }
            if !self.sponsor_budgets.contains_key(&intent.budget_id) {
                return Err("replenishment intent references missing budget".to_string());
            }
            if !intent.treasury_proof_id.is_empty()
                && !self.treasury_proofs.contains_key(&intent.treasury_proof_id)
            {
                return Err("replenishment intent references missing treasury proof".to_string());
            }
        }
        for (id, scorecard) in &self.fairness_scorecards {
            if id != &scorecard.scorecard_id {
                return Err("fairness scorecard map key mismatch".to_string());
            }
            scorecard.validate()?;
            if !self.sponsor_accounts.contains_key(&scorecard.sponsor_id) {
                return Err("fairness scorecard references missing sponsor".to_string());
            }
        }
        for (id, window) in &self.lane_pressure_windows {
            if id != &window.window_id {
                return Err("pressure window map key mismatch".to_string());
            }
            window.validate()?;
        }
        for (id, proof) in &self.treasury_proofs {
            if id != &proof.proof_id {
                return Err("treasury proof map key mismatch".to_string());
            }
            proof.validate()?;
            if !self.sponsor_accounts.contains_key(&proof.sponsor_id) {
                return Err("treasury proof references missing sponsor".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "low_fee_sponsor_market_state",
            "protocol_version": LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "active_lane_keys": self.active_lane_keys(),
        })
    }

    fn refresh_auction_roots(&mut self) {
        let bid_commitment_root = merkle_root(
            "LOW-FEE-SPONSOR-AUCTION-BID-COMMITMENT",
            &self
                .private_lane_bids
                .values()
                .map(|bid| {
                    json!({
                        "auction_id": bid.auction_id,
                        "bid_commitment": bid.bid_commitment,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let bid_reveal_root = merkle_root(
            "LOW-FEE-SPONSOR-AUCTION-BID-REVEAL",
            &self
                .private_lane_bids
                .values()
                .filter(|bid| bid.status != PrivateLaneBidStatus::Committed)
                .map(PrivateLaneBid::public_record)
                .collect::<Vec<_>>(),
        );
        for auction in self.private_lane_auctions.values_mut() {
            auction.bid_commitment_root = bid_commitment_root.clone();
            auction.bid_reveal_root = bid_reveal_root.clone();
        }
    }

    fn refresh_sponsor_roots(&mut self) {
        let authorizations = self
            .pq_authorizations
            .values()
            .map(PqSponsorAuthorization::public_record)
            .collect::<Vec<_>>();
        let treasury_proofs = self
            .treasury_proofs
            .values()
            .map(MoneroTreasuryProof::public_record)
            .collect::<Vec<_>>();
        let authorization_root = merkle_root("LOW-FEE-SPONSOR-PQ-AUTHORIZATION", &authorizations);
        let treasury_root = merkle_root("LOW-FEE-SPONSOR-TREASURY-PROOF", &treasury_proofs);
        for sponsor in self.sponsor_accounts.values_mut() {
            sponsor.pq_authorization_root = authorization_root.clone();
            sponsor.treasury_proof_root = treasury_root.clone();
        }
    }

    fn refresh_budget_replenishment_roots(&mut self) {
        let mut roots_by_budget = BTreeMap::<String, Vec<Value>>::new();
        for intent in self.replenishment_intents.values() {
            roots_by_budget
                .entry(intent.budget_id.clone())
                .or_default()
                .push(intent.public_record());
        }
        for budget in self.sponsor_budgets.values_mut() {
            let records = roots_by_budget
                .get(&budget.budget_id)
                .cloned()
                .pipe_option_vec_or_empty();
            budget.replenishment_root =
                merkle_root("LOW-FEE-SPONSOR-BUDGET-REPLENISHMENT", &records);
        }
    }

    fn slashing_target_exists(&self, target_kind: &str, target_id: &str) -> bool {
        match target_kind {
            "sponsor" => self.sponsor_accounts.contains_key(target_id),
            "budget" => self.sponsor_budgets.contains_key(target_id),
            "auction" => self.private_lane_auctions.contains_key(target_id),
            "bid" => self.private_lane_bids.contains_key(target_id),
            "reservation" => self.anti_spam_reservations.contains_key(target_id),
            "authorization" => self.pq_authorizations.contains_key(target_id),
            "receipt" => self.rebate_receipts.contains_key(target_id),
            "treasury_proof" => self.treasury_proofs.contains_key(target_id),
            _ => false,
        }
    }

    fn apply_slashing_penalty(
        &mut self,
        slashing: &SponsorshipSlashing,
    ) -> LowFeeSponsorMarketResult<()> {
        if let Some(sponsor) = self.sponsor_accounts.get_mut(&slashing.sponsor_id) {
            sponsor.slash(slashing.slashed_units, self.height)?;
        }
        if slashing.target_kind == "budget" {
            if let Some(budget) = self.sponsor_budgets.get_mut(&slashing.target_id) {
                budget.slash(slashing.slashed_units)?;
            }
        }
        Ok(())
    }
}

pub fn low_fee_sponsor_market_state_root_from_record(record: &Value) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-MARKET-STATE", record)
}

pub fn low_fee_sponsor_market_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn low_fee_sponsor_market_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_SPONSOR_MARKET_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn low_fee_sponsor_market_metadata_root(metadata: &Value) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-MARKET-METADATA", metadata)
}

pub fn low_fee_sponsor_lane_set_root(lanes: &[LowFeeSponsorLane]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-LANE-SET",
        &lanes
            .iter()
            .map(|lane| Value::String(lane.as_str().to_string()))
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_account_id(
    sponsor_label: &str,
    operator_commitment: &str,
    settlement_address_commitment: &str,
    fee_asset_id: &str,
    account_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(operator_commitment),
            HashPart::Str(settlement_address_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(account_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_budget_id(
    sponsor_id: &str,
    lane: LowFeeSponsorLane,
    lane_key: &str,
    epoch_index: u64,
    valid_from_height: u64,
    budget_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(lane_key),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(budget_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_fee_cap_id(
    lane: LowFeeSponsorLane,
    lane_key: &str,
    fee_asset_id: &str,
    effective_from_height: u64,
    source: &str,
    cap_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-FEE-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(lane_key),
            HashPart::Str(fee_asset_id),
            HashPart::Int(effective_from_height as i128),
            HashPart::Str(source),
            HashPart::Int(cap_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_auction_id(
    budget_id: &str,
    lane: LowFeeSponsorLane,
    lane_key: &str,
    start_height: u64,
    reveal_end_height: u64,
    auction_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(budget_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(lane_key),
            HashPart::Int(start_height as i128),
            HashPart::Int(reveal_end_height as i128),
            HashPart::Int(auction_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_bid_id(
    auction_id: &str,
    payer_nullifier: &str,
    bid_commitment: &str,
    submitted_at_height: u64,
    bid_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(payer_nullifier),
            HashPart::Str(bid_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(bid_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_reservation_id(
    owner_commitment: &str,
    lane: LowFeeSponsorLane,
    tx_intent_root: &str,
    created_at_height: u64,
    reservation_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(tx_intent_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(reservation_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_authorization_id(
    sponsor_id: &str,
    delegate_commitment: &str,
    authorization_statement_root: &str,
    valid_from_height: u64,
    authorization_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(delegate_commitment),
            HashPart::Str(authorization_statement_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(authorization_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_rebate_receipt_id(
    tx_nullifier: &str,
    sponsor_id: &str,
    budget_id: &str,
    lane: LowFeeSponsorLane,
    settled_at_height: u64,
    receipt_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-REBATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_nullifier),
            HashPart::Str(sponsor_id),
            HashPart::Str(budget_id),
            HashPart::Str(lane.as_str()),
            HashPart::Int(settled_at_height as i128),
            HashPart::Int(receipt_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_slashing_id(
    sponsor_id: &str,
    target_kind: &str,
    target_id: &str,
    evidence_root: &str,
    opened_at_height: u64,
    slashing_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(slashing_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_replenishment_intent_id(
    sponsor_id: &str,
    budget_id: &str,
    monero_txid: &str,
    monero_output_commitment: &str,
    created_at_height: u64,
    intent_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-REPLENISHMENT-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(budget_id),
            HashPart::Str(monero_txid),
            HashPart::Str(monero_output_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(intent_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_fairness_scorecard_id(
    sponsor_id: &str,
    epoch_index: u64,
    previous_score_root: &str,
    published_at_height: u64,
    scorecard_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-FAIRNESS-SCORECARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Int(epoch_index as i128),
            HashPart::Str(previous_score_root),
            HashPart::Int(published_at_height as i128),
            HashPart::Int(scorecard_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_pressure_window_id(
    lane: LowFeeSponsorLane,
    lane_key: &str,
    start_height: u64,
    end_height: u64,
    sample_root: &str,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-PRESSURE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(lane_key),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(sample_root),
        ],
        20,
    )
}

pub fn low_fee_sponsor_treasury_proof_id(
    sponsor_id: &str,
    monero_txid: &str,
    output_index: u64,
    output_commitment: &str,
    observed_at_height: u64,
    proof_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-TREASURY-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(monero_txid),
            HashPart::Int(output_index as i128),
            HashPart::Str(output_commitment),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(proof_nonce as i128),
        ],
        20,
    )
}

pub fn low_fee_sponsor_account_root(account: &SponsorAccount) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-ACCOUNT", &account.public_record())
}

pub fn low_fee_sponsor_budget_root(budget: &SponsorBudget) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-BUDGET", &budget.public_record())
}

pub fn low_fee_sponsor_fee_cap_root(cap: &LaneFeeCap) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-FEE-CAP", &cap.public_record())
}

pub fn low_fee_sponsor_auction_root(auction: &PrivateLaneAuction) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-AUCTION", &auction.public_record())
}

pub fn low_fee_sponsor_bid_root(bid: &PrivateLaneBid) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-BID", &bid.public_record())
}

pub fn low_fee_sponsor_reservation_root(reservation: &AntiSpamReservation) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-RESERVATION", &reservation.public_record())
}

pub fn low_fee_sponsor_authorization_root(authorization: &PqSponsorAuthorization) -> String {
    low_fee_sponsor_market_payload_root(
        "LOW-FEE-SPONSOR-AUTHORIZATION",
        &authorization.public_record(),
    )
}

pub fn low_fee_sponsor_rebate_receipt_root(receipt: &RebateReceipt) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-REBATE-RECEIPT", &receipt.public_record())
}

pub fn low_fee_sponsor_slashing_root(slashing: &SponsorshipSlashing) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-SLASHING", &slashing.public_record())
}

pub fn low_fee_sponsor_replenishment_intent_root(intent: &BudgetReplenishmentIntent) -> String {
    low_fee_sponsor_market_payload_root(
        "LOW-FEE-SPONSOR-REPLENISHMENT-INTENT",
        &intent.public_record(),
    )
}

pub fn low_fee_sponsor_fairness_scorecard_root(scorecard: &FairnessScorecard) -> String {
    low_fee_sponsor_market_payload_root(
        "LOW-FEE-SPONSOR-FAIRNESS-SCORECARD",
        &scorecard.public_record(),
    )
}

pub fn low_fee_sponsor_pressure_window_root(window: &LaneFeePressureWindow) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-PRESSURE-WINDOW", &window.public_record())
}

pub fn low_fee_sponsor_treasury_proof_root(proof: &MoneroTreasuryProof) -> String {
    low_fee_sponsor_market_payload_root("LOW-FEE-SPONSOR-TREASURY-PROOF", &proof.public_record())
}

pub fn low_fee_sponsor_account_set_root(accounts: &[SponsorAccount]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-ACCOUNT-SET",
        &accounts
            .iter()
            .map(SponsorAccount::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_budget_set_root(budgets: &[SponsorBudget]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-BUDGET-SET",
        &budgets
            .iter()
            .map(SponsorBudget::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_fee_cap_set_root(caps: &[LaneFeeCap]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-FEE-CAP-SET",
        &caps
            .iter()
            .map(LaneFeeCap::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_auction_set_root(auctions: &[PrivateLaneAuction]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-AUCTION-SET",
        &auctions
            .iter()
            .map(PrivateLaneAuction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_bid_set_root(bids: &[PrivateLaneBid]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-BID-SET",
        &bids
            .iter()
            .map(PrivateLaneBid::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_reservation_set_root(reservations: &[AntiSpamReservation]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-RESERVATION-SET",
        &reservations
            .iter()
            .map(AntiSpamReservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_authorization_set_root(authorizations: &[PqSponsorAuthorization]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-AUTHORIZATION-SET",
        &authorizations
            .iter()
            .map(PqSponsorAuthorization::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_rebate_receipt_set_root(receipts: &[RebateReceipt]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-REBATE-RECEIPT-SET",
        &receipts
            .iter()
            .map(RebateReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_slashing_set_root(slashings: &[SponsorshipSlashing]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-SLASHING-SET",
        &slashings
            .iter()
            .map(SponsorshipSlashing::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_replenishment_intent_set_root(
    intents: &[BudgetReplenishmentIntent],
) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-REPLENISHMENT-INTENT-SET",
        &intents
            .iter()
            .map(BudgetReplenishmentIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_fairness_scorecard_set_root(scorecards: &[FairnessScorecard]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-FAIRNESS-SCORECARD-SET",
        &scorecards
            .iter()
            .map(FairnessScorecard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_pressure_window_set_root(windows: &[LaneFeePressureWindow]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-PRESSURE-WINDOW-SET",
        &windows
            .iter()
            .map(LaneFeePressureWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_treasury_proof_set_root(proofs: &[MoneroTreasuryProof]) -> String {
    merkle_root(
        "LOW-FEE-SPONSOR-TREASURY-PROOF-SET",
        &proofs
            .iter()
            .map(MoneroTreasuryProof::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_fairness_score(
    accepted_bid_count: u64,
    rejected_bid_count: u64,
    average_rebate_bps: u64,
    pressure_relief_bps: u64,
    privacy_set_size: u64,
    latency_penalty_bps: u64,
    slashing_penalty_bps: u64,
) -> u64 {
    let total_bids = accepted_bid_count.saturating_add(rejected_bid_count);
    let fill_rate_bps = if total_bids == 0 {
        LOW_FEE_SPONSOR_MAX_BPS
    } else {
        ratio_bps(accepted_bid_count, total_bids)
    };
    let privacy_bonus = privacy_set_size.min(256).saturating_mul(10);
    fill_rate_bps
        .saturating_div(2)
        .saturating_add(average_rebate_bps.saturating_div(4))
        .saturating_add(
            pressure_relief_bps
                .min(LOW_FEE_SPONSOR_MAX_BPS)
                .saturating_div(4),
        )
        .saturating_add(privacy_bonus.min(1_000))
        .saturating_sub(latency_penalty_bps)
        .saturating_sub(slashing_penalty_bps)
        .min(LOW_FEE_SPONSOR_MAX_BPS)
}

fn percentile_sample(samples: &[u64], percentile: u64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let capped = percentile.min(100);
    let index = ((samples.len().saturating_sub(1)) as u64)
        .saturating_mul(capped)
        .saturating_div(100) as usize;
    match samples.get(index) {
        Some(value) => *value,
        None => 0,
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(LOW_FEE_SPONSOR_MAX_BPS)
        .saturating_div(denominator)
}

fn average_u64(values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values
        .iter()
        .fold(0_u64, |total, value| total.saturating_add(*value))
        .saturating_div(values.len() as u64)
}

fn ensure_non_empty(label: &str, value: &str) -> LowFeeSponsorMarketResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

fn ensure_non_empty_lane_set(lanes: &[LowFeeSponsorLane]) -> LowFeeSponsorMarketResult<()> {
    if lanes.is_empty() {
        return Err("permitted lane set is required".to_string());
    }
    let unique = lanes.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != lanes.len() {
        return Err("permitted lane set contains duplicates".to_string());
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> LowFeeSponsorMarketResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> LowFeeSponsorMarketResult<()> {
    if value > LOW_FEE_SPONSOR_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_pressure_bps(label: &str, value: u64) -> LowFeeSponsorMarketResult<()> {
    if value > LOW_FEE_SPONSOR_MAX_PRESSURE_BPS {
        return Err(format!("{label} exceeds pressure ceiling"));
    }
    Ok(())
}

fn ensure_height_order(label: &str, start: u64, end: u64) -> LowFeeSponsorMarketResult<()> {
    if end < start {
        return Err(format!("{label} ends before it starts"));
    }
    Ok(())
}

fn ensure_eq(label: &str, actual: &str, required: &str) -> LowFeeSponsorMarketResult<()> {
    if actual != required {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

trait LowFeeSponsorOptionExt<T> {
    fn pipe_option_vec_or_empty(self) -> Vec<T>;
}

impl<T> LowFeeSponsorOptionExt<T> for Option<Vec<T>> {
    fn pipe_option_vec_or_empty(self) -> Vec<T> {
        match self {
            Some(value) => value,
            None => Vec::new(),
        }
    }
}

trait LowFeeSponsorOptionStringExt {
    fn pipe_option_string_or_empty(self) -> String;
}

impl LowFeeSponsorOptionStringExt for Option<String> {
    fn pipe_option_string_or_empty(self) -> String {
        match self {
            Some(value) => value,
            None => String::new(),
        }
    }
}
