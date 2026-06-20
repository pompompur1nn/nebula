use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedPrivateCreditVaultAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-private-credit-vault-auction-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_HASH_SUITE:
    &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_PQ_AUTH_SUITE:
    &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-credit-vault-auction-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_NOTE_SCHEME:
    &str = "confidential-private-credit-note+range-proof+nullifier-fence-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_TRANCHE_SCHEME:
    &str = "tokenized-private-credit-tranche-commitment+redacted-waterfall-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_ORACLE_SCHEME:
    &str = "pq-threshold-issuer-oracle-attestation+collateral-haircut-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_AUCTION_SCHEME:
    &str = "sealed-bid-low-fee-batch-private-credit-clearing-auction-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_SETTLEMENT_SCHEME:
    &str = "confidential-credit-vault-cashflow-settlement-batch+zk-receipt-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_REBATE_SCHEME:
    &str = "batch-density-low-fee-rebate+private-fee-sponsor-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_PRIVACY_SCHEME:
    &str = "redacted-compliance-view+operator-summary+note-nullifier-set-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_880_000;
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "asset:dusd-private-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:dnr-low-fee-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 7;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_REBATE_EPOCH_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_OPERATOR_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_MIN_ADVANCE_RATE_BPS: u64 = 4_000;
pub const DEFAULT_MAX_ADVANCE_RATE_BPS: u64 = 8_750;
pub const DEFAULT_MIN_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_MAX_LOAN_TO_VALUE_BPS: u64 = 8_500;
pub const DEFAULT_MAX_SETTLEMENT_BATCH_SIZE: usize = 512;
pub const DEFAULT_MAX_BIDS_PER_AUCTION: usize = 256;
pub const DEFAULT_MAX_NOTES_PER_VAULT: usize = 4_096;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VAULTS: usize = 262_144;
pub const MAX_NOTES: usize = 2_097_152;
pub const MAX_TRANCHES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_HAIRCUTS: usize = 1_048_576;
pub const MAX_AUCTIONS: usize = 524_288;
pub const MAX_BIDS: usize = 8_388_608;
pub const MAX_SETTLEMENT_BATCHES: usize = 1_048_576;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_COMPLIANCE_VIEWS: usize = 2_097_152;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;
pub const MAX_NULLIFIERS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditAssetKind {
    SeniorSecuredLoan,
    UnitrancheLoan,
    InvoiceReceivable,
    EquipmentFinance,
    TradeFinance,
    RevenueBasedFinance,
    RealEstateBridgeLoan,
    PrivateCreditFundInterest,
}

impl CreditAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SeniorSecuredLoan => "senior_secured_loan",
            Self::UnitrancheLoan => "unitranche_loan",
            Self::InvoiceReceivable => "invoice_receivable",
            Self::EquipmentFinance => "equipment_finance",
            Self::TradeFinance => "trade_finance",
            Self::RevenueBasedFinance => "revenue_based_finance",
            Self::RealEstateBridgeLoan => "real_estate_bridge_loan",
            Self::PrivateCreditFundInterest => "private_credit_fund_interest",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Funding,
    Active,
    DrawdownOnly,
    RepaymentOnly,
    AuctionOnly,
    Settling,
    Paused,
    Frozen,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Funding => "funding",
            Self::Active => "active",
            Self::DrawdownOnly => "drawdown_only",
            Self::RepaymentOnly => "repayment_only",
            Self::AuctionOnly => "auction_only",
            Self::Settling => "settling",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_notes(self) -> bool {
        matches!(self, Self::Funding | Self::Active | Self::DrawdownOnly)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(
            self,
            Self::Active | Self::RepaymentOnly | Self::AuctionOnly | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheSeniority {
    SuperSenior,
    Senior,
    Mezzanine,
    Junior,
    EquityFirstLoss,
    ServicerReserve,
}

impl TrancheSeniority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperSenior => "super_senior",
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::EquityFirstLoss => "equity_first_loss",
            Self::ServicerReserve => "servicer_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Minted,
    Funded,
    CashflowAccruing,
    AuctionCommitted,
    SettlementQueued,
    Settled,
    Nullified,
    Frozen,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Funded => "funded",
            Self::CashflowAccruing => "cashflow_accruing",
            Self::AuctionCommitted => "auction_committed",
            Self::SettlementQueued => "settlement_queued",
            Self::Settled => "settled",
            Self::Nullified => "nullified",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CashflowType {
    PrincipalDraw,
    PrincipalRepayment,
    InterestCoupon,
    OriginationFee,
    ServicerFee,
    RecoveryDistribution,
    DefaultLoss,
}

impl CashflowType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalDraw => "principal_draw",
            Self::PrincipalRepayment => "principal_repayment",
            Self::InterestCoupon => "interest_coupon",
            Self::OriginationFee => "origination_fee",
            Self::ServicerFee => "servicer_fee",
            Self::RecoveryDistribution => "recovery_distribution",
            Self::DefaultLoss => "default_loss",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleVerdict {
    Performing,
    Watchlist,
    CovenantBreach,
    Delinquent,
    Defaulted,
    RecoveryComplete,
}

impl OracleVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Performing => "performing",
            Self::Watchlist => "watchlist",
            Self::CovenantBreach => "covenant_breach",
            Self::Delinquent => "delinquent",
            Self::Defaulted => "defaulted",
            Self::RecoveryComplete => "recovery_complete",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralClass {
    CashReserve,
    ReceivablePool,
    EquipmentLien,
    RealEstateLien,
    InventoryLien,
    SponsorGuarantee,
    InsuranceWrap,
    TokenizedRwaReserve,
}

impl CollateralClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CashReserve => "cash_reserve",
            Self::ReceivablePool => "receivable_pool",
            Self::EquipmentLien => "equipment_lien",
            Self::RealEstateLien => "real_estate_lien",
            Self::InventoryLien => "inventory_lien",
            Self::SponsorGuarantee => "sponsor_guarantee",
            Self::InsuranceWrap => "insurance_wrap",
            Self::TokenizedRwaReserve => "tokenized_rwa_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Commit,
    Reveal,
    Clearing,
    SettlementQueued,
    Settled,
    Cancelled,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Reveal => "reveal",
            Self::Clearing => "clearing",
            Self::SettlementQueued => "settlement_queued",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidSide {
    BuyNote,
    SellNote,
    ProvideLiquidity,
    BackstopCredit,
}

impl BidSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuyNote => "buy_note",
            Self::SellNote => "sell_note",
            Self::ProvideLiquidity => "provide_liquidity",
            Self::BackstopCredit => "backstop_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceViewKind {
    KycEligibility,
    AccreditedInvestor,
    SanctionsScreen,
    ConcentrationLimit,
    ServicerAudit,
    TaxLot,
    TransferRestriction,
}

impl ComplianceViewKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KycEligibility => "kyc_eligibility",
            Self::AccreditedInvestor => "accredited_investor",
            Self::SanctionsScreen => "sanctions_screen",
            Self::ConcentrationLimit => "concentration_limit",
            Self::ServicerAudit => "servicer_audit",
            Self::TaxLot => "tax_lot",
            Self::TransferRestriction => "transfer_restriction",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub settlement_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub auction_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_operator_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_advance_rate_bps: u64,
    pub max_advance_rate_bps: u64,
    pub min_coverage_bps: u64,
    pub max_loan_to_value_bps: u64,
    pub max_settlement_batch_size: usize,
    pub max_bids_per_auction: usize,
    pub max_notes_per_vault: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_epoch_blocks: DEFAULT_REBATE_EPOCH_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_operator_fee_bps: DEFAULT_MAX_OPERATOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_advance_rate_bps: DEFAULT_MIN_ADVANCE_RATE_BPS,
            max_advance_rate_bps: DEFAULT_MAX_ADVANCE_RATE_BPS,
            min_coverage_bps: DEFAULT_MIN_COVERAGE_BPS,
            max_loan_to_value_bps: DEFAULT_MAX_LOAN_TO_VALUE_BPS,
            max_settlement_batch_size: DEFAULT_MAX_SETTLEMENT_BATCH_SIZE,
            max_bids_per_auction: DEFAULT_MAX_BIDS_PER_AUCTION,
            max_notes_per_vault: DEFAULT_MAX_NOTES_PER_VAULT,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "settlement_asset_id": self.settlement_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "oracle_quorum": self.oracle_quorum,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_operator_fee_bps": self.max_operator_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "min_advance_rate_bps": self.min_advance_rate_bps,
            "max_advance_rate_bps": self.max_advance_rate_bps,
            "min_coverage_bps": self.min_coverage_bps,
            "max_loan_to_value_bps": self.max_loan_to_value_bps,
            "max_settlement_batch_size": self.max_settlement_batch_size,
            "max_bids_per_auction": self.max_bids_per_auction,
            "max_notes_per_vault": self.max_notes_per_vault,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults_registered: u64,
    pub notes_minted: u64,
    pub tranches_committed: u64,
    pub issuer_attestations: u64,
    pub collateral_haircuts: u64,
    pub auctions_opened: u64,
    pub sealed_bids_committed: u64,
    pub sealed_bids_revealed: u64,
    pub settlement_batches: u64,
    pub fee_rebates: u64,
    pub compliance_views: u64,
    pub operator_summaries: u64,
    pub nullifiers_seen: u64,
    pub confidential_amount_redactions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vaults_root: String,
    pub notes_root: String,
    pub tranches_root: String,
    pub attestations_root: String,
    pub haircuts_root: String,
    pub auctions_root: String,
    pub sealed_bids_root: String,
    pub settlement_batches_root: String,
    pub fee_rebates_root: String,
    pub compliance_views_root: String,
    pub operator_summaries_root: String,
    pub nullifiers_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditVault {
    pub vault_id: String,
    pub issuer_commitment: String,
    pub servicer_commitment: String,
    pub asset_kind: CreditAssetKind,
    pub status: VaultStatus,
    pub borrower_pool_root: String,
    pub confidential_terms_root: String,
    pub collateral_pool_root: String,
    pub token_contract_commitment: String,
    pub target_notional: u64,
    pub outstanding_notional: u64,
    pub advance_rate_bps: u64,
    pub weighted_coupon_bps: u64,
    pub maturity_height: u64,
    pub min_privacy_set_size: u64,
    pub pq_issuer_key_commitment: String,
    pub pq_servicer_key_commitment: String,
    pub created_height: u64,
    pub updated_height: u64,
}

impl CreditVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "issuer_commitment": self.issuer_commitment,
            "servicer_commitment": self.servicer_commitment,
            "asset_kind": self.asset_kind.as_str(),
            "status": self.status.as_str(),
            "borrower_pool_root": self.borrower_pool_root,
            "confidential_terms_root": self.confidential_terms_root,
            "collateral_pool_root": self.collateral_pool_root,
            "token_contract_commitment": self.token_contract_commitment,
            "target_notional": self.target_notional,
            "outstanding_notional": self.outstanding_notional,
            "advance_rate_bps": self.advance_rate_bps,
            "weighted_coupon_bps": self.weighted_coupon_bps,
            "maturity_height": self.maturity_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_issuer_key_commitment": self.pq_issuer_key_commitment,
            "pq_servicer_key_commitment": self.pq_servicer_key_commitment,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateCreditVaultNote {
    pub note_id: String,
    pub vault_id: String,
    pub tranche_id: String,
    pub owner_commitment: String,
    pub status: NoteStatus,
    pub principal_commitment: String,
    pub coupon_commitment: String,
    pub maturity_commitment: String,
    pub note_token_commitment: String,
    pub cashflow_type: CashflowType,
    pub principal_amount: u64,
    pub coupon_due: u64,
    pub discounted_value: u64,
    pub privacy_set_size: u64,
    pub pq_owner_signature_commitment: String,
    pub note_nullifier: String,
    pub minted_height: u64,
    pub last_cashflow_height: u64,
}

impl PrivateCreditVaultNote {
    pub fn redacted_public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "vault_id": self.vault_id,
            "tranche_id": self.tranche_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status.as_str(),
            "principal_commitment": self.principal_commitment,
            "coupon_commitment": self.coupon_commitment,
            "maturity_commitment": self.maturity_commitment,
            "note_token_commitment": self.note_token_commitment,
            "cashflow_type": self.cashflow_type.as_str(),
            "principal_amount": "redacted",
            "coupon_due": "redacted",
            "discounted_value": "redacted",
            "privacy_set_size": self.privacy_set_size,
            "pq_owner_signature_commitment": self.pq_owner_signature_commitment,
            "note_nullifier_root": note_nullifier_commitment(&self.note_nullifier),
            "minted_height": self.minted_height,
            "last_cashflow_height": self.last_cashflow_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrancheCommitment {
    pub tranche_id: String,
    pub vault_id: String,
    pub seniority: TrancheSeniority,
    pub token_symbol_commitment: String,
    pub investor_set_root: String,
    pub waterfall_root: String,
    pub attachment_point_bps: u64,
    pub detachment_point_bps: u64,
    pub coupon_spread_bps: u64,
    pub max_supply: u64,
    pub minted_supply: u64,
    pub reserve_requirement_bps: u64,
    pub pq_tranche_admin_signature_commitment: String,
    pub created_height: u64,
}

impl TrancheCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "vault_id": self.vault_id,
            "seniority": self.seniority.as_str(),
            "token_symbol_commitment": self.token_symbol_commitment,
            "investor_set_root": self.investor_set_root,
            "waterfall_root": self.waterfall_root,
            "attachment_point_bps": self.attachment_point_bps,
            "detachment_point_bps": self.detachment_point_bps,
            "coupon_spread_bps": self.coupon_spread_bps,
            "max_supply": self.max_supply,
            "minted_supply": self.minted_supply,
            "reserve_requirement_bps": self.reserve_requirement_bps,
            "pq_tranche_admin_signature_commitment": self.pq_tranche_admin_signature_commitment,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuerOracleAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub oracle_committee_id: String,
    pub verdict: OracleVerdict,
    pub as_of_height: u64,
    pub net_asset_value_commitment: String,
    pub delinquency_ratio_bps: u64,
    pub coverage_ratio_bps: u64,
    pub default_probability_bps: u64,
    pub issuer_report_root: String,
    pub collateral_haircut_root: String,
    pub pq_oracle_signature_root: String,
    pub quorum: u16,
    pub expires_height: u64,
}

impl IssuerOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "oracle_committee_id": self.oracle_committee_id,
            "verdict": self.verdict.as_str(),
            "as_of_height": self.as_of_height,
            "net_asset_value_commitment": self.net_asset_value_commitment,
            "delinquency_ratio_bps": self.delinquency_ratio_bps,
            "coverage_ratio_bps": self.coverage_ratio_bps,
            "default_probability_bps": self.default_probability_bps,
            "issuer_report_root": self.issuer_report_root,
            "collateral_haircut_root": self.collateral_haircut_root,
            "pq_oracle_signature_root": self.pq_oracle_signature_root,
            "quorum": self.quorum,
            "expires_height": self.expires_height,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.as_of_height <= height && height <= self.expires_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralHaircut {
    pub haircut_id: String,
    pub vault_id: String,
    pub collateral_class: CollateralClass,
    pub collateral_commitment: String,
    pub valuation_root: String,
    pub gross_value: u64,
    pub haircut_bps: u64,
    pub net_value: u64,
    pub liquidity_score_bps: u64,
    pub oracle_attestation_id: String,
    pub applied_height: u64,
}

impl CollateralHaircut {
    pub fn public_record(&self) -> Value {
        json!({
            "haircut_id": self.haircut_id,
            "vault_id": self.vault_id,
            "collateral_class": self.collateral_class.as_str(),
            "collateral_commitment": self.collateral_commitment,
            "valuation_root": self.valuation_root,
            "gross_value": "redacted",
            "haircut_bps": self.haircut_bps,
            "net_value": "redacted",
            "liquidity_score_bps": self.liquidity_score_bps,
            "oracle_attestation_id": self.oracle_attestation_id,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultAuction {
    pub auction_id: String,
    pub vault_id: String,
    pub tranche_id: String,
    pub status: AuctionStatus,
    pub sealed_bid_book_root: String,
    pub eligible_note_set_root: String,
    pub oracle_attestation_id: String,
    pub clearing_price_commitment: String,
    pub target_notional: u64,
    pub committed_notional: u64,
    pub clearing_notional: u64,
    pub min_price_bps: u64,
    pub max_price_bps: u64,
    pub opened_height: u64,
    pub reveal_height: u64,
    pub settlement_height: u64,
}

impl VaultAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "vault_id": self.vault_id,
            "tranche_id": self.tranche_id,
            "status": self.status.as_str(),
            "sealed_bid_book_root": self.sealed_bid_book_root,
            "eligible_note_set_root": self.eligible_note_set_root,
            "oracle_attestation_id": self.oracle_attestation_id,
            "clearing_price_commitment": self.clearing_price_commitment,
            "target_notional": self.target_notional,
            "committed_notional": self.committed_notional,
            "clearing_notional": self.clearing_notional,
            "min_price_bps": self.min_price_bps,
            "max_price_bps": self.max_price_bps,
            "opened_height": self.opened_height,
            "reveal_height": self.reveal_height,
            "settlement_height": self.settlement_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedAuctionBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub side: BidSide,
    pub sealed_price_commitment: String,
    pub sealed_quantity_commitment: String,
    pub revealed_price_bps: Option<u64>,
    pub revealed_quantity: Option<u64>,
    pub bid_nullifier: String,
    pub pq_bid_signature_commitment: String,
    pub privacy_set_size: u64,
    pub committed_height: u64,
    pub revealed_height: Option<u64>,
}

impl SealedAuctionBid {
    pub fn redacted_public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "side": self.side.as_str(),
            "sealed_price_commitment": self.sealed_price_commitment,
            "sealed_quantity_commitment": self.sealed_quantity_commitment,
            "revealed_price_bps": self.revealed_price_bps,
            "revealed_quantity": self.revealed_quantity.map(|_| "redacted"),
            "bid_nullifier_root": note_nullifier_commitment(&self.bid_nullifier),
            "pq_bid_signature_commitment": self.pq_bid_signature_commitment,
            "privacy_set_size": self.privacy_set_size,
            "committed_height": self.committed_height,
            "revealed_height": self.revealed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub auction_id: String,
    pub vault_id: String,
    pub note_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub cashflow_root: String,
    pub settlement_proof_root: String,
    pub total_principal_settled: u64,
    pub total_coupon_settled: u64,
    pub total_recovery_settled: u64,
    pub user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub settled_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "auction_id": self.auction_id,
            "vault_id": self.vault_id,
            "note_ids": self.note_ids,
            "bid_ids": self.bid_ids,
            "cashflow_root": self.cashflow_root,
            "settlement_proof_root": self.settlement_proof_root,
            "total_principal_settled": "redacted",
            "total_coupon_settled": "redacted",
            "total_recovery_settled": "redacted",
            "user_fee_bps": self.user_fee_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_amount: u64,
    pub rebate_bps: u64,
    pub density_score_bps: u64,
    pub low_fee_lane_root: String,
    pub pq_rebate_signature_commitment: String,
    pub credited_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_amount": "redacted",
            "rebate_bps": self.rebate_bps,
            "density_score_bps": self.density_score_bps,
            "low_fee_lane_root": self.low_fee_lane_root,
            "pq_rebate_signature_commitment": self.pq_rebate_signature_commitment,
            "credited_height": self.credited_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedComplianceView {
    pub view_id: String,
    pub vault_id: String,
    pub subject_commitment: String,
    pub kind: ComplianceViewKind,
    pub allowed: bool,
    pub redaction_root: String,
    pub disclosed_fields: Vec<String>,
    pub withheld_fields: Vec<String>,
    pub jurisdiction_root: String,
    pub pq_compliance_signature_commitment: String,
    pub expires_height: u64,
}

impl RedactedComplianceView {
    pub fn public_record(&self) -> Value {
        json!({
            "view_id": self.view_id,
            "vault_id": self.vault_id,
            "subject_commitment": self.subject_commitment,
            "kind": self.kind.as_str(),
            "allowed": self.allowed,
            "redaction_root": self.redaction_root,
            "disclosed_fields": self.disclosed_fields,
            "withheld_fields": self.withheld_fields,
            "jurisdiction_root": self.jurisdiction_root,
            "pq_compliance_signature_commitment": self.pq_compliance_signature_commitment,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub height: u64,
    pub active_vaults: u64,
    pub active_tranches: u64,
    pub open_auctions: u64,
    pub confidential_notes: u64,
    pub sealed_bids: u64,
    pub settled_batches: u64,
    pub protected_notional: u64,
    pub settlement_volume: u64,
    pub average_user_fee_bps: u64,
    pub average_rebate_bps: u64,
    pub state_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "height": self.height,
            "active_vaults": self.active_vaults,
            "active_tranches": self.active_tranches,
            "open_auctions": self.open_auctions,
            "confidential_notes": self.confidential_notes,
            "sealed_bids": self.sealed_bids,
            "settled_batches": self.settled_batches,
            "protected_notional": "redacted",
            "settlement_volume": "redacted",
            "average_user_fee_bps": self.average_user_fee_bps,
            "average_rebate_bps": self.average_rebate_bps,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterVaultRequest {
    pub vault_id: String,
    pub issuer_commitment: String,
    pub servicer_commitment: String,
    pub asset_kind: CreditAssetKind,
    pub borrower_pool_root: String,
    pub confidential_terms_root: String,
    pub collateral_pool_root: String,
    pub token_contract_commitment: String,
    pub target_notional: u64,
    pub advance_rate_bps: u64,
    pub weighted_coupon_bps: u64,
    pub maturity_height: u64,
    pub pq_issuer_key_commitment: String,
    pub pq_servicer_key_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitTrancheRequest {
    pub tranche_id: String,
    pub vault_id: String,
    pub seniority: TrancheSeniority,
    pub token_symbol_commitment: String,
    pub investor_set_root: String,
    pub waterfall_root: String,
    pub attachment_point_bps: u64,
    pub detachment_point_bps: u64,
    pub coupon_spread_bps: u64,
    pub max_supply: u64,
    pub reserve_requirement_bps: u64,
    pub pq_tranche_admin_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MintNoteRequest {
    pub note_id: String,
    pub vault_id: String,
    pub tranche_id: String,
    pub owner_commitment: String,
    pub principal_commitment: String,
    pub coupon_commitment: String,
    pub maturity_commitment: String,
    pub note_token_commitment: String,
    pub cashflow_type: CashflowType,
    pub principal_amount: u64,
    pub coupon_due: u64,
    pub discounted_value: u64,
    pub pq_owner_signature_commitment: String,
    pub note_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestationRequest {
    pub attestation_id: String,
    pub vault_id: String,
    pub oracle_committee_id: String,
    pub verdict: OracleVerdict,
    pub as_of_height: u64,
    pub net_asset_value_commitment: String,
    pub delinquency_ratio_bps: u64,
    pub coverage_ratio_bps: u64,
    pub default_probability_bps: u64,
    pub issuer_report_root: String,
    pub collateral_haircut_root: String,
    pub pq_oracle_signature_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralHaircutRequest {
    pub haircut_id: String,
    pub vault_id: String,
    pub collateral_class: CollateralClass,
    pub collateral_commitment: String,
    pub valuation_root: String,
    pub gross_value: u64,
    pub haircut_bps: u64,
    pub liquidity_score_bps: u64,
    pub oracle_attestation_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenAuctionRequest {
    pub auction_id: String,
    pub vault_id: String,
    pub tranche_id: String,
    pub sealed_bid_book_root: String,
    pub eligible_note_set_root: String,
    pub oracle_attestation_id: String,
    pub target_notional: u64,
    pub min_price_bps: u64,
    pub max_price_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitSealedBidRequest {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub side: BidSide,
    pub sealed_price_commitment: String,
    pub sealed_quantity_commitment: String,
    pub bid_nullifier: String,
    pub pq_bid_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevealSealedBidRequest {
    pub bid_id: String,
    pub price_bps: u64,
    pub quantity: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatchRequest {
    pub batch_id: String,
    pub auction_id: String,
    pub vault_id: String,
    pub note_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub cashflow_root: String,
    pub settlement_proof_root: String,
    pub total_principal_settled: u64,
    pub total_coupon_settled: u64,
    pub total_recovery_settled: u64,
    pub user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRequest {
    pub rebate_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_amount: u64,
    pub rebate_bps: u64,
    pub density_score_bps: u64,
    pub low_fee_lane_root: String,
    pub pq_rebate_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceViewRequest {
    pub view_id: String,
    pub vault_id: String,
    pub subject_commitment: String,
    pub kind: ComplianceViewKind,
    pub allowed: bool,
    pub redaction_root: String,
    pub disclosed_fields: Vec<String>,
    pub withheld_fields: Vec<String>,
    pub jurisdiction_root: String,
    pub pq_compliance_signature_commitment: String,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, CreditVault>,
    pub notes: BTreeMap<String, PrivateCreditVaultNote>,
    pub tranches: BTreeMap<String, TrancheCommitment>,
    pub attestations: BTreeMap<String, IssuerOracleAttestation>,
    pub haircuts: BTreeMap<String, CollateralHaircut>,
    pub auctions: BTreeMap<String, VaultAuction>,
    pub sealed_bids: BTreeMap<String, SealedAuctionBid>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub compliance_views: BTreeMap<String, RedactedComplianceView>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub note_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            notes: BTreeMap::new(),
            tranches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            haircuts: BTreeMap::new(),
            auctions: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            compliance_views: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            note_nullifiers: BTreeSet::new(),
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
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn register_vault(&mut self, request: RegisterVaultRequest) -> Result<()> {
        self.ensure_capacity(self.vaults.len(), MAX_VAULTS, "vaults")?;
        self.ensure_new_key(&self.vaults, &request.vault_id, "vault")?;
        self.ensure_nonempty("vault_id", &request.vault_id)?;
        self.ensure_nonempty("issuer_commitment", &request.issuer_commitment)?;
        self.ensure_nonempty("servicer_commitment", &request.servicer_commitment)?;
        self.ensure_nonempty("borrower_pool_root", &request.borrower_pool_root)?;
        self.ensure_nonempty("confidential_terms_root", &request.confidential_terms_root)?;
        self.ensure_bps("advance_rate_bps", request.advance_rate_bps)?;
        self.ensure_bps("weighted_coupon_bps", request.weighted_coupon_bps)?;
        if request.advance_rate_bps < self.config.min_advance_rate_bps {
            return Err("advance_rate_bps below configured floor".to_string());
        }
        if request.advance_rate_bps > self.config.max_advance_rate_bps {
            return Err("advance_rate_bps above configured cap".to_string());
        }
        if request.maturity_height <= self.height {
            return Err("maturity_height must be in the future".to_string());
        }
        let vault = CreditVault {
            vault_id: request.vault_id.clone(),
            issuer_commitment: request.issuer_commitment,
            servicer_commitment: request.servicer_commitment,
            asset_kind: request.asset_kind,
            status: VaultStatus::Funding,
            borrower_pool_root: request.borrower_pool_root,
            confidential_terms_root: request.confidential_terms_root,
            collateral_pool_root: request.collateral_pool_root,
            token_contract_commitment: request.token_contract_commitment,
            target_notional: request.target_notional,
            outstanding_notional: 0,
            advance_rate_bps: request.advance_rate_bps,
            weighted_coupon_bps: request.weighted_coupon_bps,
            maturity_height: request.maturity_height,
            min_privacy_set_size: self.config.min_privacy_set_size,
            pq_issuer_key_commitment: request.pq_issuer_key_commitment,
            pq_servicer_key_commitment: request.pq_servicer_key_commitment,
            created_height: self.height,
            updated_height: self.height,
        };
        self.vaults.insert(request.vault_id, vault);
        self.counters.vaults_registered = self.counters.vaults_registered.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn commit_tranche(&mut self, request: CommitTrancheRequest) -> Result<()> {
        self.ensure_capacity(self.tranches.len(), MAX_TRANCHES, "tranches")?;
        self.ensure_new_key(&self.tranches, &request.tranche_id, "tranche")?;
        self.ensure_existing_key(&self.vaults, &request.vault_id, "vault")?;
        self.ensure_bps("attachment_point_bps", request.attachment_point_bps)?;
        self.ensure_bps("detachment_point_bps", request.detachment_point_bps)?;
        self.ensure_bps("coupon_spread_bps", request.coupon_spread_bps)?;
        self.ensure_bps("reserve_requirement_bps", request.reserve_requirement_bps)?;
        if request.attachment_point_bps >= request.detachment_point_bps {
            return Err("attachment_point_bps must be below detachment_point_bps".to_string());
        }
        let tranche = TrancheCommitment {
            tranche_id: request.tranche_id.clone(),
            vault_id: request.vault_id,
            seniority: request.seniority,
            token_symbol_commitment: request.token_symbol_commitment,
            investor_set_root: request.investor_set_root,
            waterfall_root: request.waterfall_root,
            attachment_point_bps: request.attachment_point_bps,
            detachment_point_bps: request.detachment_point_bps,
            coupon_spread_bps: request.coupon_spread_bps,
            max_supply: request.max_supply,
            minted_supply: 0,
            reserve_requirement_bps: request.reserve_requirement_bps,
            pq_tranche_admin_signature_commitment: request.pq_tranche_admin_signature_commitment,
            created_height: self.height,
        };
        self.tranches.insert(request.tranche_id, tranche);
        self.counters.tranches_committed = self.counters.tranches_committed.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn mint_note(&mut self, request: MintNoteRequest) -> Result<()> {
        self.ensure_capacity(self.notes.len(), MAX_NOTES, "notes")?;
        self.ensure_new_key(&self.notes, &request.note_id, "note")?;
        self.ensure_existing_key(&self.vaults, &request.vault_id, "vault")?;
        self.ensure_existing_key(&self.tranches, &request.tranche_id, "tranche")?;
        if self.note_nullifiers.contains(&request.note_nullifier) {
            return Err("note_nullifier already used".to_string());
        }
        let notes_in_vault = self
            .notes
            .values()
            .filter(|note| note.vault_id == request.vault_id)
            .count();
        self.ensure_capacity(
            notes_in_vault,
            self.config.max_notes_per_vault,
            "notes_per_vault",
        )?;
        let vault = self
            .vaults
            .get_mut(&request.vault_id)
            .ok_or_else(|| "vault missing".to_string())?;
        if !vault.status.accepts_notes() {
            return Err("vault does not accept notes".to_string());
        }
        let tranche = self
            .tranches
            .get_mut(&request.tranche_id)
            .ok_or_else(|| "tranche missing".to_string())?;
        if tranche.vault_id != request.vault_id {
            return Err("tranche does not belong to vault".to_string());
        }
        if tranche
            .minted_supply
            .saturating_add(request.principal_amount)
            > tranche.max_supply
        {
            return Err("tranche max_supply exceeded".to_string());
        }
        vault.outstanding_notional = vault
            .outstanding_notional
            .saturating_add(request.principal_amount);
        vault.updated_height = self.height;
        tranche.minted_supply = tranche
            .minted_supply
            .saturating_add(request.principal_amount);
        let note = PrivateCreditVaultNote {
            note_id: request.note_id.clone(),
            vault_id: request.vault_id,
            tranche_id: request.tranche_id,
            owner_commitment: request.owner_commitment,
            status: NoteStatus::Funded,
            principal_commitment: request.principal_commitment,
            coupon_commitment: request.coupon_commitment,
            maturity_commitment: request.maturity_commitment,
            note_token_commitment: request.note_token_commitment,
            cashflow_type: request.cashflow_type,
            principal_amount: request.principal_amount,
            coupon_due: request.coupon_due,
            discounted_value: request.discounted_value,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_owner_signature_commitment: request.pq_owner_signature_commitment,
            note_nullifier: request.note_nullifier.clone(),
            minted_height: self.height,
            last_cashflow_height: self.height,
        };
        self.note_nullifiers.insert(request.note_nullifier);
        self.notes.insert(request.note_id, note);
        self.counters.notes_minted = self.counters.notes_minted.saturating_add(1);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        self.counters.confidential_amount_redactions = self
            .counters
            .confidential_amount_redactions
            .saturating_add(3);
        self.refresh_roots();
        Ok(())
    }

    pub fn attest_issuer_oracle(&mut self, request: OracleAttestationRequest) -> Result<()> {
        self.ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        self.ensure_new_key(&self.attestations, &request.attestation_id, "attestation")?;
        self.ensure_existing_key(&self.vaults, &request.vault_id, "vault")?;
        self.ensure_bps("delinquency_ratio_bps", request.delinquency_ratio_bps)?;
        self.ensure_bps("coverage_ratio_bps", request.coverage_ratio_bps)?;
        self.ensure_bps("default_probability_bps", request.default_probability_bps)?;
        if request.coverage_ratio_bps < self.config.min_coverage_bps {
            return Err("coverage_ratio_bps below configured floor".to_string());
        }
        let attestation = IssuerOracleAttestation {
            attestation_id: request.attestation_id.clone(),
            vault_id: request.vault_id,
            oracle_committee_id: request.oracle_committee_id,
            verdict: request.verdict,
            as_of_height: request.as_of_height,
            net_asset_value_commitment: request.net_asset_value_commitment,
            delinquency_ratio_bps: request.delinquency_ratio_bps,
            coverage_ratio_bps: request.coverage_ratio_bps,
            default_probability_bps: request.default_probability_bps,
            issuer_report_root: request.issuer_report_root,
            collateral_haircut_root: request.collateral_haircut_root,
            pq_oracle_signature_root: request.pq_oracle_signature_root,
            quorum: self.config.oracle_quorum,
            expires_height: request
                .as_of_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.attestations
            .insert(request.attestation_id, attestation);
        self.counters.issuer_attestations = self.counters.issuer_attestations.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn apply_collateral_haircut(&mut self, request: CollateralHaircutRequest) -> Result<()> {
        self.ensure_capacity(self.haircuts.len(), MAX_HAIRCUTS, "haircuts")?;
        self.ensure_new_key(&self.haircuts, &request.haircut_id, "haircut")?;
        self.ensure_existing_key(&self.vaults, &request.vault_id, "vault")?;
        self.ensure_existing_key(
            &self.attestations,
            &request.oracle_attestation_id,
            "oracle_attestation",
        )?;
        self.ensure_bps("haircut_bps", request.haircut_bps)?;
        self.ensure_bps("liquidity_score_bps", request.liquidity_score_bps)?;
        let net_value = request
            .gross_value
            .saturating_mul(MAX_BPS.saturating_sub(request.haircut_bps))
            / MAX_BPS;
        let haircut = CollateralHaircut {
            haircut_id: request.haircut_id.clone(),
            vault_id: request.vault_id,
            collateral_class: request.collateral_class,
            collateral_commitment: request.collateral_commitment,
            valuation_root: request.valuation_root,
            gross_value: request.gross_value,
            haircut_bps: request.haircut_bps,
            net_value,
            liquidity_score_bps: request.liquidity_score_bps,
            oracle_attestation_id: request.oracle_attestation_id,
            applied_height: self.height,
        };
        self.haircuts.insert(request.haircut_id, haircut);
        self.counters.collateral_haircuts = self.counters.collateral_haircuts.saturating_add(1);
        self.counters.confidential_amount_redactions = self
            .counters
            .confidential_amount_redactions
            .saturating_add(2);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_auction(&mut self, request: OpenAuctionRequest) -> Result<()> {
        self.ensure_capacity(self.auctions.len(), MAX_AUCTIONS, "auctions")?;
        self.ensure_new_key(&self.auctions, &request.auction_id, "auction")?;
        self.ensure_existing_key(&self.vaults, &request.vault_id, "vault")?;
        self.ensure_existing_key(&self.tranches, &request.tranche_id, "tranche")?;
        self.ensure_existing_key(
            &self.attestations,
            &request.oracle_attestation_id,
            "oracle_attestation",
        )?;
        self.ensure_bps("min_price_bps", request.min_price_bps)?;
        self.ensure_bps("max_price_bps", request.max_price_bps)?;
        if request.min_price_bps > request.max_price_bps {
            return Err("min_price_bps must be <= max_price_bps".to_string());
        }
        let attestation = self
            .attestations
            .get(&request.oracle_attestation_id)
            .ok_or_else(|| "oracle_attestation missing".to_string())?;
        if attestation.vault_id != request.vault_id {
            return Err("oracle_attestation does not belong to vault".to_string());
        }
        if !attestation.is_live_at(self.height) {
            return Err("oracle_attestation is not live".to_string());
        }
        let vault = self
            .vaults
            .get_mut(&request.vault_id)
            .ok_or_else(|| "vault missing".to_string())?;
        vault.status = VaultStatus::AuctionOnly;
        vault.updated_height = self.height;
        let auction = VaultAuction {
            auction_id: request.auction_id.clone(),
            vault_id: request.vault_id,
            tranche_id: request.tranche_id,
            status: AuctionStatus::Commit,
            sealed_bid_book_root: request.sealed_bid_book_root,
            eligible_note_set_root: request.eligible_note_set_root,
            oracle_attestation_id: request.oracle_attestation_id,
            clearing_price_commitment: "pending".to_string(),
            target_notional: request.target_notional,
            committed_notional: 0,
            clearing_notional: 0,
            min_price_bps: request.min_price_bps,
            max_price_bps: request.max_price_bps,
            opened_height: self.height,
            reveal_height: self
                .height
                .saturating_add(self.config.auction_ttl_blocks / 2),
            settlement_height: self.height.saturating_add(self.config.auction_ttl_blocks),
        };
        self.auctions.insert(request.auction_id, auction);
        self.counters.auctions_opened = self.counters.auctions_opened.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn commit_sealed_bid(&mut self, request: CommitSealedBidRequest) -> Result<()> {
        self.ensure_capacity(self.sealed_bids.len(), MAX_BIDS, "sealed_bids")?;
        self.ensure_new_key(&self.sealed_bids, &request.bid_id, "sealed_bid")?;
        if self.note_nullifiers.contains(&request.bid_nullifier) {
            return Err("bid_nullifier already used".to_string());
        }
        let bid_count = self
            .sealed_bids
            .values()
            .filter(|bid| bid.auction_id == request.auction_id)
            .count();
        self.ensure_capacity(
            bid_count,
            self.config.max_bids_per_auction,
            "bids_per_auction",
        )?;
        let auction = self
            .auctions
            .get(&request.auction_id)
            .ok_or_else(|| "auction missing".to_string())?;
        if auction.status != AuctionStatus::Commit {
            return Err("auction is not in commit phase".to_string());
        }
        if self.height > auction.reveal_height {
            return Err("auction commit window closed".to_string());
        }
        let bid = SealedAuctionBid {
            bid_id: request.bid_id.clone(),
            auction_id: request.auction_id,
            bidder_commitment: request.bidder_commitment,
            side: request.side,
            sealed_price_commitment: request.sealed_price_commitment,
            sealed_quantity_commitment: request.sealed_quantity_commitment,
            revealed_price_bps: None,
            revealed_quantity: None,
            bid_nullifier: request.bid_nullifier.clone(),
            pq_bid_signature_commitment: request.pq_bid_signature_commitment,
            privacy_set_size: self.config.min_privacy_set_size,
            committed_height: self.height,
            revealed_height: None,
        };
        self.note_nullifiers.insert(request.bid_nullifier);
        self.sealed_bids.insert(request.bid_id, bid);
        self.counters.sealed_bids_committed = self.counters.sealed_bids_committed.saturating_add(1);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn reveal_sealed_bid(&mut self, request: RevealSealedBidRequest) -> Result<()> {
        self.ensure_bps("price_bps", request.price_bps)?;
        let bid = self
            .sealed_bids
            .get_mut(&request.bid_id)
            .ok_or_else(|| "sealed_bid missing".to_string())?;
        if bid.revealed_height.is_some() {
            return Err("sealed_bid already revealed".to_string());
        }
        let auction = self
            .auctions
            .get_mut(&bid.auction_id)
            .ok_or_else(|| "auction missing".to_string())?;
        if request.price_bps < auction.min_price_bps || request.price_bps > auction.max_price_bps {
            return Err("price_bps outside auction band".to_string());
        }
        if self.height < auction.reveal_height {
            auction.status = AuctionStatus::Reveal;
        }
        bid.revealed_price_bps = Some(request.price_bps);
        bid.revealed_quantity = Some(request.quantity);
        bid.revealed_height = Some(self.height);
        auction.committed_notional = auction.committed_notional.saturating_add(request.quantity);
        self.counters.sealed_bids_revealed = self.counters.sealed_bids_revealed.saturating_add(1);
        self.counters.confidential_amount_redactions = self
            .counters
            .confidential_amount_redactions
            .saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_batch(&mut self, request: SettlementBatchRequest) -> Result<()> {
        self.ensure_capacity(
            self.settlement_batches.len(),
            MAX_SETTLEMENT_BATCHES,
            "settlement_batches",
        )?;
        self.ensure_new_key(
            &self.settlement_batches,
            &request.batch_id,
            "settlement_batch",
        )?;
        self.ensure_existing_key(&self.auctions, &request.auction_id, "auction")?;
        self.ensure_existing_key(&self.vaults, &request.vault_id, "vault")?;
        self.ensure_bps("user_fee_bps", request.user_fee_bps)?;
        self.ensure_bps("operator_fee_bps", request.operator_fee_bps)?;
        self.ensure_bps("batch_rebate_bps", request.batch_rebate_bps)?;
        if request.user_fee_bps > self.config.max_user_fee_bps {
            return Err("user_fee_bps exceeds configured cap".to_string());
        }
        if request.operator_fee_bps > self.config.max_operator_fee_bps {
            return Err("operator_fee_bps exceeds configured cap".to_string());
        }
        if request.note_ids.len() > self.config.max_settlement_batch_size {
            return Err("settlement batch note limit exceeded".to_string());
        }
        for note_id in &request.note_ids {
            self.ensure_existing_key(&self.notes, note_id, "note")?;
        }
        for bid_id in &request.bid_ids {
            self.ensure_existing_key(&self.sealed_bids, bid_id, "sealed_bid")?;
        }
        let privacy_set_size = self.config.batch_privacy_set_size.max(
            (request.note_ids.len() as u64)
                .saturating_add(request.bid_ids.len() as u64)
                .saturating_mul(self.config.min_privacy_set_size),
        );
        let batch = SettlementBatch {
            batch_id: request.batch_id.clone(),
            auction_id: request.auction_id.clone(),
            vault_id: request.vault_id.clone(),
            note_ids: request.note_ids.clone(),
            bid_ids: request.bid_ids,
            cashflow_root: request.cashflow_root,
            settlement_proof_root: request.settlement_proof_root,
            total_principal_settled: request.total_principal_settled,
            total_coupon_settled: request.total_coupon_settled,
            total_recovery_settled: request.total_recovery_settled,
            user_fee_bps: request.user_fee_bps,
            operator_fee_bps: request.operator_fee_bps,
            batch_rebate_bps: request.batch_rebate_bps,
            privacy_set_size,
            settled_height: self.height,
        };
        for note_id in &request.note_ids {
            if let Some(note) = self.notes.get_mut(note_id) {
                note.status = NoteStatus::Settled;
                note.last_cashflow_height = self.height;
            }
        }
        if let Some(auction) = self.auctions.get_mut(&request.auction_id) {
            auction.status = AuctionStatus::Settled;
            auction.clearing_notional = request.total_principal_settled;
            auction.clearing_price_commitment = domain_hash(
                "private-credit-auction-clearing-price",
                &[
                    HashPart::Str(&request.auction_id),
                    HashPart::U64(request.total_principal_settled),
                    HashPart::U64(request.total_recovery_settled),
                ],
                32,
            );
        }
        if let Some(vault) = self.vaults.get_mut(&request.vault_id) {
            vault.status = VaultStatus::Settling;
            vault.updated_height = self.height;
        }
        self.settlement_batches.insert(request.batch_id, batch);
        self.counters.settlement_batches = self.counters.settlement_batches.saturating_add(1);
        self.counters.confidential_amount_redactions = self
            .counters
            .confidential_amount_redactions
            .saturating_add(3);
        self.refresh_roots();
        Ok(())
    }

    pub fn credit_fee_rebate(&mut self, request: FeeRebateRequest) -> Result<()> {
        self.ensure_capacity(self.fee_rebates.len(), MAX_REBATES, "fee_rebates")?;
        self.ensure_new_key(&self.fee_rebates, &request.rebate_id, "fee_rebate")?;
        self.ensure_existing_key(
            &self.settlement_batches,
            &request.batch_id,
            "settlement_batch",
        )?;
        self.ensure_bps("rebate_bps", request.rebate_bps)?;
        self.ensure_bps("density_score_bps", request.density_score_bps)?;
        let rebate = FeeRebate {
            rebate_id: request.rebate_id.clone(),
            batch_id: request.batch_id,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_asset_id: request.rebate_asset_id,
            rebate_amount: request.rebate_amount,
            rebate_bps: request.rebate_bps,
            density_score_bps: request.density_score_bps,
            low_fee_lane_root: request.low_fee_lane_root,
            pq_rebate_signature_commitment: request.pq_rebate_signature_commitment,
            credited_height: self.height,
        };
        self.fee_rebates.insert(request.rebate_id, rebate);
        self.counters.fee_rebates = self.counters.fee_rebates.saturating_add(1);
        self.counters.confidential_amount_redactions = self
            .counters
            .confidential_amount_redactions
            .saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_redacted_compliance_view(
        &mut self,
        request: ComplianceViewRequest,
    ) -> Result<()> {
        self.ensure_capacity(
            self.compliance_views.len(),
            MAX_COMPLIANCE_VIEWS,
            "compliance_views",
        )?;
        self.ensure_new_key(&self.compliance_views, &request.view_id, "compliance_view")?;
        self.ensure_existing_key(&self.vaults, &request.vault_id, "vault")?;
        let view = RedactedComplianceView {
            view_id: request.view_id.clone(),
            vault_id: request.vault_id,
            subject_commitment: request.subject_commitment,
            kind: request.kind,
            allowed: request.allowed,
            redaction_root: request.redaction_root,
            disclosed_fields: request.disclosed_fields,
            withheld_fields: request.withheld_fields,
            jurisdiction_root: request.jurisdiction_root,
            pq_compliance_signature_commitment: request.pq_compliance_signature_commitment,
            expires_height: self.height.saturating_add(request.ttl_blocks),
        };
        self.compliance_views.insert(request.view_id, view);
        self.counters.compliance_views = self.counters.compliance_views.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, summary_id: String) -> Result<()> {
        self.ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator_summaries",
        )?;
        self.ensure_new_key(&self.operator_summaries, &summary_id, "operator_summary")?;
        self.refresh_roots();
        let active_vaults = self
            .vaults
            .values()
            .filter(|vault| matches!(vault.status, VaultStatus::Funding | VaultStatus::Active))
            .count() as u64;
        let active_tranches = self.tranches.len() as u64;
        let open_auctions = self
            .auctions
            .values()
            .filter(|auction| {
                matches!(
                    auction.status,
                    AuctionStatus::Commit | AuctionStatus::Reveal | AuctionStatus::Clearing
                )
            })
            .count() as u64;
        let protected_notional = self
            .notes
            .values()
            .map(|note| note.principal_amount)
            .fold(0_u64, u64::saturating_add);
        let settlement_volume = self
            .settlement_batches
            .values()
            .map(|batch| batch.total_principal_settled)
            .fold(0_u64, u64::saturating_add);
        let average_user_fee_bps = average_bps(
            self.settlement_batches
                .values()
                .map(|batch| batch.user_fee_bps),
        );
        let average_rebate_bps =
            average_bps(self.fee_rebates.values().map(|rebate| rebate.rebate_bps));
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            height: self.height,
            active_vaults,
            active_tranches,
            open_auctions,
            confidential_notes: self.notes.len() as u64,
            sealed_bids: self.sealed_bids.len() as u64,
            settled_batches: self.settlement_batches.len() as u64,
            protected_notional,
            settlement_volume,
            average_user_fee_bps,
            average_rebate_bps,
            state_root: self.roots.state_root.clone(),
        };
        self.operator_summaries.insert(summary_id, summary);
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_PQ_AUTH_SUITE,
            "note_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_NOTE_SCHEME,
            "tranche_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_TRANCHE_SCHEME,
            "oracle_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_ORACLE_SCHEME,
            "auction_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_AUCTION_SCHEME,
            "settlement_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_SETTLEMENT_SCHEME,
            "rebate_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_REBATE_SCHEME,
            "privacy_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIVATE_CREDIT_VAULT_AUCTION_RUNTIME_PRIVACY_SCHEME,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "vaults_root": self.roots.vaults_root,
                "notes_root": self.roots.notes_root,
                "tranches_root": self.roots.tranches_root,
                "attestations_root": self.roots.attestations_root,
                "haircuts_root": self.roots.haircuts_root,
                "auctions_root": self.roots.auctions_root,
                "sealed_bids_root": self.roots.sealed_bids_root,
                "settlement_batches_root": self.roots.settlement_batches_root,
                "fee_rebates_root": self.roots.fee_rebates_root,
                "compliance_views_root": self.roots.compliance_views_root,
                "operator_summaries_root": self.roots.operator_summaries_root,
                "nullifiers_root": self.roots.nullifiers_root,
                "counters_root": self.roots.counters_root,
            },
            "vaults": public_map(&self.vaults, CreditVault::public_record),
            "notes": public_map(&self.notes, PrivateCreditVaultNote::redacted_public_record),
            "tranches": public_map(&self.tranches, TrancheCommitment::public_record),
            "attestations": public_map(&self.attestations, IssuerOracleAttestation::public_record),
            "haircuts": public_map(&self.haircuts, CollateralHaircut::public_record),
            "auctions": public_map(&self.auctions, VaultAuction::public_record),
            "sealed_bids": public_map(&self.sealed_bids, SealedAuctionBid::redacted_public_record),
            "settlement_batches": public_map(&self.settlement_batches, SettlementBatch::public_record),
            "fee_rebates": public_map(&self.fee_rebates, FeeRebate::public_record),
            "compliance_views": public_map(&self.compliance_views, RedactedComplianceView::public_record),
            "operator_summaries": public_map(&self.operator_summaries, OperatorSummary::public_record),
            "note_nullifier_root": set_root("private-credit-note-nullifiers", &self.note_nullifiers),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = domain_hash(
            "private-credit-vault-auction-config",
            &[HashPart::Json(&self.config.public_record())],
            32,
        );
        self.roots.vaults_root = public_value_map_root(
            "private-credit-vault-auction-vaults",
            &self.vaults,
            CreditVault::public_record,
        );
        self.roots.notes_root = public_value_map_root(
            "private-credit-vault-auction-notes",
            &self.notes,
            PrivateCreditVaultNote::redacted_public_record,
        );
        self.roots.tranches_root = public_value_map_root(
            "private-credit-vault-auction-tranches",
            &self.tranches,
            TrancheCommitment::public_record,
        );
        self.roots.attestations_root = public_value_map_root(
            "private-credit-vault-auction-attestations",
            &self.attestations,
            IssuerOracleAttestation::public_record,
        );
        self.roots.haircuts_root = public_value_map_root(
            "private-credit-vault-auction-haircuts",
            &self.haircuts,
            CollateralHaircut::public_record,
        );
        self.roots.auctions_root = public_value_map_root(
            "private-credit-vault-auction-auctions",
            &self.auctions,
            VaultAuction::public_record,
        );
        self.roots.sealed_bids_root = public_value_map_root(
            "private-credit-vault-auction-sealed-bids",
            &self.sealed_bids,
            SealedAuctionBid::redacted_public_record,
        );
        self.roots.settlement_batches_root = public_value_map_root(
            "private-credit-vault-auction-settlement-batches",
            &self.settlement_batches,
            SettlementBatch::public_record,
        );
        self.roots.fee_rebates_root = public_value_map_root(
            "private-credit-vault-auction-fee-rebates",
            &self.fee_rebates,
            FeeRebate::public_record,
        );
        self.roots.compliance_views_root = public_value_map_root(
            "private-credit-vault-auction-compliance-views",
            &self.compliance_views,
            RedactedComplianceView::public_record,
        );
        self.roots.operator_summaries_root = public_value_map_root(
            "private-credit-vault-auction-operator-summaries",
            &self.operator_summaries,
            OperatorSummary::public_record,
        );
        self.roots.nullifiers_root = set_root(
            "private-credit-vault-auction-nullifiers",
            &self.note_nullifiers,
        );
        self.roots.counters_root = domain_hash(
            "private-credit-vault-auction-counters",
            &[HashPart::Json(&self.counters.public_record())],
            32,
        );
        self.roots.state_root = state_root_from_public_record(&self.public_record_without_root());
    }

    fn ensure_nonempty(&self, label: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            return Err(format!("{} must not be empty", label));
        }
        Ok(())
    }

    fn ensure_bps(&self, label: &str, value: u64) -> Result<()> {
        if value > MAX_BPS {
            return Err(format!("{} exceeds max bps", label));
        }
        Ok(())
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            return Err(format!("{} capacity exceeded", label));
        }
        Ok(())
    }

    fn ensure_new_key<T>(&self, map: &BTreeMap<String, T>, key: &str, label: &str) -> Result<()> {
        self.ensure_nonempty(label, key)?;
        if map.contains_key(key) {
            return Err(format!("{} already exists", label));
        }
        Ok(())
    }

    fn ensure_existing_key<T>(
        &self,
        map: &BTreeMap<String, T>,
        key: &str,
        label: &str,
    ) -> Result<()> {
        self.ensure_nonempty(label, key)?;
        if !map.contains_key(key) {
            return Err(format!("{} missing", label));
        }
        Ok(())
    }
}

pub fn public_map<T, F>(values: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect()
}

pub fn public_value_map_root<T, F>(
    domain: &str,
    values: &BTreeMap<String, T>,
    public_record: F,
) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = public_map(values, public_record);
    merkle_root(domain, &leaves)
}

pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn note_nullifier_commitment(nullifier: &str) -> String {
    domain_hash(
        "private-credit-vault-auction-nullifier-commitment",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(nullifier)],
        32,
    )
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "private-credit-vault-auction-state-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn average_bps<I>(values: I) -> u64
where
    I: IntoIterator<Item = u64>,
{
    let mut count = 0_u64;
    let mut total = 0_u64;
    for value in values {
        count = count.saturating_add(1);
        total = total.saturating_add(value);
    }
    if count == 0 {
        0
    } else {
        total / count
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let _ = state.register_vault(RegisterVaultRequest {
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        issuer_commitment: "issuer-commitment-private-credit-alpha".to_string(),
        servicer_commitment: "servicer-commitment-private-credit-alpha".to_string(),
        asset_kind: CreditAssetKind::SeniorSecuredLoan,
        borrower_pool_root: domain_hash(
            "devnet-private-credit-borrower-pool",
            &[HashPart::Str("borrower-pool-alpha")],
            32,
        ),
        confidential_terms_root: domain_hash(
            "devnet-private-credit-confidential-terms",
            &[HashPart::Str("terms-alpha")],
            32,
        ),
        collateral_pool_root: domain_hash(
            "devnet-private-credit-collateral-pool",
            &[HashPart::Str("collateral-alpha")],
            32,
        ),
        token_contract_commitment: "token-contract-private-credit-alpha".to_string(),
        target_notional: 120_000_000_000,
        advance_rate_bps: 7_250,
        weighted_coupon_bps: 1_185,
        maturity_height: state.height + 129_600,
        pq_issuer_key_commitment: "pq-issuer-key-commitment-alpha".to_string(),
        pq_servicer_key_commitment: "pq-servicer-key-commitment-alpha".to_string(),
    });
    let _ = state.commit_tranche(CommitTrancheRequest {
        tranche_id: "private-credit-tranche-senior-alpha".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        seniority: TrancheSeniority::Senior,
        token_symbol_commitment: "token-symbol-commitment-pcv-senior-alpha".to_string(),
        investor_set_root: domain_hash(
            "devnet-private-credit-investor-set",
            &[HashPart::Str("senior-investors-alpha")],
            32,
        ),
        waterfall_root: domain_hash(
            "devnet-private-credit-waterfall",
            &[HashPart::Str("waterfall-senior-alpha")],
            32,
        ),
        attachment_point_bps: 1_500,
        detachment_point_bps: 8_500,
        coupon_spread_bps: 420,
        max_supply: 90_000_000_000,
        reserve_requirement_bps: 650,
        pq_tranche_admin_signature_commitment: "pq-tranche-admin-sig-alpha".to_string(),
    });
    let _ = state.commit_tranche(CommitTrancheRequest {
        tranche_id: "private-credit-tranche-junior-alpha".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        seniority: TrancheSeniority::Junior,
        token_symbol_commitment: "token-symbol-commitment-pcv-junior-alpha".to_string(),
        investor_set_root: domain_hash(
            "devnet-private-credit-investor-set",
            &[HashPart::Str("junior-investors-alpha")],
            32,
        ),
        waterfall_root: domain_hash(
            "devnet-private-credit-waterfall",
            &[HashPart::Str("waterfall-junior-alpha")],
            32,
        ),
        attachment_point_bps: 0,
        detachment_point_bps: 1_500,
        coupon_spread_bps: 1_050,
        max_supply: 30_000_000_000,
        reserve_requirement_bps: 1_250,
        pq_tranche_admin_signature_commitment: "pq-tranche-admin-sig-junior-alpha".to_string(),
    });
    let _ = state.mint_note(MintNoteRequest {
        note_id: "private-credit-note-alpha-0001".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        tranche_id: "private-credit-tranche-senior-alpha".to_string(),
        owner_commitment: "note-owner-stealth-commitment-alpha".to_string(),
        principal_commitment: "principal-commitment-note-alpha".to_string(),
        coupon_commitment: "coupon-commitment-note-alpha".to_string(),
        maturity_commitment: "maturity-commitment-note-alpha".to_string(),
        note_token_commitment: "note-token-commitment-alpha".to_string(),
        cashflow_type: CashflowType::InterestCoupon,
        principal_amount: 12_500_000_000,
        coupon_due: 148_125_000,
        discounted_value: 12_275_000_000,
        pq_owner_signature_commitment: "pq-note-owner-sig-alpha".to_string(),
        note_nullifier: "note-nullifier-private-credit-alpha-0001".to_string(),
    });
    let _ = state.attest_issuer_oracle(OracleAttestationRequest {
        attestation_id: "issuer-oracle-attestation-alpha".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        oracle_committee_id: "private-credit-oracle-committee-devnet".to_string(),
        verdict: OracleVerdict::Performing,
        as_of_height: state.height,
        net_asset_value_commitment: "nav-commitment-private-credit-alpha".to_string(),
        delinquency_ratio_bps: 180,
        coverage_ratio_bps: 11_250,
        default_probability_bps: 260,
        issuer_report_root: domain_hash(
            "devnet-private-credit-issuer-report",
            &[HashPart::Str("issuer-report-alpha")],
            32,
        ),
        collateral_haircut_root: domain_hash(
            "devnet-private-credit-haircut-root",
            &[HashPart::Str("haircut-alpha")],
            32,
        ),
        pq_oracle_signature_root: "pq-oracle-signature-root-alpha".to_string(),
    });
    let _ = state.apply_collateral_haircut(CollateralHaircutRequest {
        haircut_id: "haircut-private-credit-alpha".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        collateral_class: CollateralClass::ReceivablePool,
        collateral_commitment: "receivable-pool-collateral-commitment-alpha".to_string(),
        valuation_root: domain_hash(
            "devnet-private-credit-valuation",
            &[HashPart::Str("receivable-valuation-alpha")],
            32,
        ),
        gross_value: 132_500_000_000,
        haircut_bps: 1_600,
        liquidity_score_bps: 8_200,
        oracle_attestation_id: "issuer-oracle-attestation-alpha".to_string(),
    });
    let _ = state.publish_redacted_compliance_view(ComplianceViewRequest {
        view_id: "compliance-view-private-credit-alpha".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        subject_commitment: "note-owner-stealth-commitment-alpha".to_string(),
        kind: ComplianceViewKind::AccreditedInvestor,
        allowed: true,
        redaction_root: domain_hash(
            "devnet-private-credit-redaction",
            &[HashPart::Str("investor-redaction-alpha")],
            32,
        ),
        disclosed_fields: vec![
            "view_id".to_string(),
            "vault_id".to_string(),
            "allowed".to_string(),
            "jurisdiction_root".to_string(),
        ],
        withheld_fields: vec![
            "beneficial_owner".to_string(),
            "position_size".to_string(),
            "tax_identifier".to_string(),
        ],
        jurisdiction_root: "jurisdiction-root-us-qualified-purchaser-alpha".to_string(),
        pq_compliance_signature_commitment: "pq-compliance-sig-alpha".to_string(),
        ttl_blocks: 43_200,
    });
    let _ = state.publish_operator_summary("operator-summary-private-credit-devnet".to_string());
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.open_auction(OpenAuctionRequest {
        auction_id: "vault-auction-private-credit-alpha".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        tranche_id: "private-credit-tranche-senior-alpha".to_string(),
        sealed_bid_book_root: domain_hash(
            "devnet-private-credit-sealed-bid-book",
            &[HashPart::Str("auction-alpha")],
            32,
        ),
        eligible_note_set_root: domain_hash(
            "devnet-private-credit-eligible-notes",
            &[HashPart::Str("private-credit-note-alpha-0001")],
            32,
        ),
        oracle_attestation_id: "issuer-oracle-attestation-alpha".to_string(),
        target_notional: 12_500_000_000,
        min_price_bps: 8_900,
        max_price_bps: 10_200,
    });
    let _ = state.commit_sealed_bid(CommitSealedBidRequest {
        bid_id: "sealed-bid-private-credit-alpha-0001".to_string(),
        auction_id: "vault-auction-private-credit-alpha".to_string(),
        bidder_commitment: "liquidity-bidder-commitment-alpha".to_string(),
        side: BidSide::BuyNote,
        sealed_price_commitment: "sealed-price-commitment-alpha".to_string(),
        sealed_quantity_commitment: "sealed-quantity-commitment-alpha".to_string(),
        bid_nullifier: "bid-nullifier-private-credit-alpha-0001".to_string(),
        pq_bid_signature_commitment: "pq-bid-signature-alpha".to_string(),
    });
    let _ = state.reveal_sealed_bid(RevealSealedBidRequest {
        bid_id: "sealed-bid-private-credit-alpha-0001".to_string(),
        price_bps: 9_820,
        quantity: 12_500_000_000,
    });
    let _ = state.settle_batch(SettlementBatchRequest {
        batch_id: "settlement-batch-private-credit-alpha".to_string(),
        auction_id: "vault-auction-private-credit-alpha".to_string(),
        vault_id: "private-credit-vault-devnet-senior-001".to_string(),
        note_ids: vec!["private-credit-note-alpha-0001".to_string()],
        bid_ids: vec!["sealed-bid-private-credit-alpha-0001".to_string()],
        cashflow_root: domain_hash(
            "devnet-private-credit-cashflow-root",
            &[HashPart::Str("cashflow-alpha")],
            32,
        ),
        settlement_proof_root: "zk-settlement-proof-root-private-credit-alpha".to_string(),
        total_principal_settled: 12_500_000_000,
        total_coupon_settled: 148_125_000,
        total_recovery_settled: 0,
        user_fee_bps: 8,
        operator_fee_bps: 11,
        batch_rebate_bps: 6,
    });
    let _ = state.credit_fee_rebate(FeeRebateRequest {
        rebate_id: "fee-rebate-private-credit-alpha".to_string(),
        batch_id: "settlement-batch-private-credit-alpha".to_string(),
        beneficiary_commitment: "note-owner-stealth-commitment-alpha".to_string(),
        rebate_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
        rebate_amount: 7_500_000,
        rebate_bps: 6,
        density_score_bps: 9_400,
        low_fee_lane_root: domain_hash(
            "devnet-private-credit-low-fee-lane",
            &[HashPart::Str("batch-alpha")],
            32,
        ),
        pq_rebate_signature_commitment: "pq-rebate-signature-alpha".to_string(),
    });
    let _ = state.publish_operator_summary("operator-summary-private-credit-demo".to_string());
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    let mut record = state.public_record_without_root();
    if let Value::Object(ref mut object) = record {
        object.insert(
            "state_root".to_string(),
            Value::String(state.roots.state_root.clone()),
        );
    }
    record
}

pub fn state_root(state: &State) -> String {
    state_root_from_public_record(&state.public_record_without_root())
}

pub fn devnet_state_root() -> String {
    devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    devnet().public_record()
}

pub fn demo_state_root() -> String {
    demo().state_root()
}

pub fn demo_public_record() -> Value {
    demo().public_record()
}

pub const PRIVATE_CREDIT_CONTROL_DOMAIN_000: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-000";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_001: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-001";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_002: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-002";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_003: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-003";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_004: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-004";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_005: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-005";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_006: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-006";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_007: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-007";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_008: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-008";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_009: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-009";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_010: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-010";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_011: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-011";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_012: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-012";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_013: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-013";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_014: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-014";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_015: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-015";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_016: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-016";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_017: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-017";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_018: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-018";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_019: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-019";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_020: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-020";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_021: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-021";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_022: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-022";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_023: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-023";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_024: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-024";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_025: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-025";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_026: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-026";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_027: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-027";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_028: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-028";
pub const PRIVATE_CREDIT_CONTROL_DOMAIN_029: &str =
    "private-l2-pq-confidential-tokenized-private-credit-vault-auction-control-domain-029";

pub fn private_credit_control_root(domain: &str, subject: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_credit_control_root_000(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_000, subject, payload)
}

pub fn private_credit_control_root_001(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_001, subject, payload)
}

pub fn private_credit_control_root_002(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_002, subject, payload)
}

pub fn private_credit_control_root_003(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_003, subject, payload)
}

pub fn private_credit_control_root_004(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_004, subject, payload)
}

pub fn private_credit_control_root_005(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_005, subject, payload)
}

pub fn private_credit_control_root_006(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_006, subject, payload)
}

pub fn private_credit_control_root_007(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_007, subject, payload)
}

pub fn private_credit_control_root_008(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_008, subject, payload)
}

pub fn private_credit_control_root_009(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_009, subject, payload)
}

pub fn private_credit_control_root_010(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_010, subject, payload)
}

pub fn private_credit_control_root_011(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_011, subject, payload)
}

pub fn private_credit_control_root_012(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_012, subject, payload)
}

pub fn private_credit_control_root_013(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_013, subject, payload)
}

pub fn private_credit_control_root_014(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_014, subject, payload)
}

pub fn private_credit_control_root_015(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_015, subject, payload)
}

pub fn private_credit_control_root_016(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_016, subject, payload)
}

pub fn private_credit_control_root_017(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_017, subject, payload)
}

pub fn private_credit_control_root_018(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_018, subject, payload)
}

pub fn private_credit_control_root_019(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_019, subject, payload)
}

pub fn private_credit_control_root_020(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_020, subject, payload)
}

pub fn private_credit_control_root_021(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_021, subject, payload)
}

pub fn private_credit_control_root_022(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_022, subject, payload)
}

pub fn private_credit_control_root_023(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_023, subject, payload)
}

pub fn private_credit_control_root_024(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_024, subject, payload)
}

pub fn private_credit_control_root_025(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_025, subject, payload)
}

pub fn private_credit_control_root_026(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_026, subject, payload)
}

pub fn private_credit_control_root_027(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_027, subject, payload)
}

pub fn private_credit_control_root_028(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_028, subject, payload)
}

pub fn private_credit_control_root_029(subject: &str, payload: &Value) -> String {
    private_credit_control_root(PRIVATE_CREDIT_CONTROL_DOMAIN_029, subject, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_roots_are_stable() {
        let state = State::devnet();
        assert_eq!(state.state_root(), state.roots.state_root);
        assert_eq!(devnet_state_root(), State::devnet().state_root());
    }

    #[test]
    fn public_record_contains_state_root() {
        let record = devnet_public_record();
        assert!(record.get("state_root").is_some());
    }
}
