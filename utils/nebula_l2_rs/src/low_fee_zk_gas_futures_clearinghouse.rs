use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeZkGasFuturesClearinghouseResult<T> = Result<T, String>;

pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION: &str =
    "nebula-low-fee-zk-gas-futures-clearinghouse-v1";
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_SCHEMA_VERSION: &str =
    "low-fee-zk-gas-futures-clearinghouse-state-v1";
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_ZK_ELIGIBILITY_PROOF_SCHEME: &str =
    "zk-private-gas-eligibility-range-set-membership-shake256-v1";
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_SETTLEMENT_PROOF_SCHEME: &str =
    "zk-gas-mark-settlement-netting-shake256-v1";
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PQ_RISK_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-slh-dsa-shake-256f-risk-attestation-v1";
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_HEIGHT: u64 = 64;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_LOT_TTL_BLOCKS: u64 = 720;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MARK_INTERVAL_BLOCKS: u64 = 12;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_EXPIRY_GRACE_BLOCKS: u64 = 18;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_500;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 900;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_SPONSOR_RESERVE_BPS: u64 = 2_000;
pub const LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasLane {
    PrivateTransfer,
    MoneroBridge,
    PrivateDexSwap,
    Lending,
    Perps,
    TokenMintBurn,
    SmartContractCall,
    ProofAggregation,
    WalletRecovery,
    EmergencyExit,
}

impl GasLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateDexSwap => "private_dex_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::TokenMintBurn => "token_mint_burn",
            Self::SmartContractCall => "smart_contract_call",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_target_micro_price(self) -> u64 {
        match self {
            Self::EmergencyExit => 300,
            Self::WalletRecovery => 450,
            Self::PrivateTransfer => 700,
            Self::MoneroBridge => 1_050,
            Self::PrivateDexSwap => 1_250,
            Self::Lending => 1_450,
            Self::Perps => 1_650,
            Self::TokenMintBurn => 1_750,
            Self::SmartContractCall => 1_950,
            Self::ProofAggregation => 2_450,
        }
    }

    pub fn default_privacy_floor(self) -> u64 {
        match self {
            Self::EmergencyExit => 128,
            Self::WalletRecovery => 160,
            Self::PrivateTransfer => 256,
            Self::MoneroBridge => 192,
            Self::PrivateDexSwap => 160,
            Self::Lending => 144,
            Self::Perps => 144,
            Self::TokenMintBurn => 128,
            Self::SmartContractCall => 128,
            Self::ProofAggregation => 96,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LotSide {
    UserLongFee,
    SponsorShortFee,
    MakerNeutral,
}

impl LotSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserLongFee => "user_long_fee",
            Self::SponsorShortFee => "sponsor_short_fee",
            Self::MakerNeutral => "maker_neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Committed,
    Matched,
    Funded,
    Settling,
    Settled,
    Expired,
    Liquidated,
    Cancelled,
    Disputed,
}

impl LotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Matched => "matched",
            Self::Funded => "funded",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Liquidated => "liquidated",
            Self::Cancelled => "cancelled",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Matched | Self::Funded | Self::Settling
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Expired | Self::Liquidated | Self::Cancelled | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeStatus {
    Posted,
    Bound,
    Settling,
    Settled,
    Expired,
    Slashed,
    Cancelled,
}

impl HedgeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Bound => "bound",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Posted | Self::Bound | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCreditStatus {
    Active,
    Reserved,
    Settling,
    Exhausted,
    Expired,
    Revoked,
    Slashed,
}

impl SponsorCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Settling => "settling",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkStatus {
    Proposed,
    QuorumSigned,
    Accepted,
    Superseded,
    Disputed,
}

impl MarkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuorumSigned => "quorum_signed",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityStatus {
    Submitted,
    Verified,
    Rejected,
    Revoked,
    Expired,
}

impl EligibilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAttestationStatus {
    Draft,
    Active,
    Superseded,
    Challenged,
    Slashed,
    Expired,
}

impl RiskAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    CashSettled,
    PhysicalGasDelivery,
    ExpiredWorthless,
    MarginLiquidation,
    SponsorDefault,
    ProofFailure,
    GovernanceHalt,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CashSettled => "cash_settled",
            Self::PhysicalGasDelivery => "physical_gas_delivery",
            Self::ExpiredWorthless => "expired_worthless",
            Self::MarginLiquidation => "margin_liquidation",
            Self::SponsorDefault => "sponsor_default",
            Self::ProofFailure => "proof_failure",
            Self::GovernanceHalt => "governance_halt",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub chain_id: String,
    pub eligibility_proof_scheme: String,
    pub settlement_proof_scheme: String,
    pub pq_risk_attestation_scheme: String,
    pub epoch_blocks: u64,
    pub lot_ttl_blocks: u64,
    pub mark_interval_blocks: u64,
    pub expiry_grace_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub max_open_lots_per_account: u64,
    pub max_lane_open_interest_units: u64,
    pub low_fee_target_micro_price: u64,
    pub liquidation_penalty_bps: u64,
    pub mark_quorum_threshold: u64,
    pub supported_lanes: Vec<GasLane>,
}

impl Config {
    pub fn devnet() -> Self {
        let supported_lanes = vec![
            GasLane::PrivateTransfer,
            GasLane::MoneroBridge,
            GasLane::PrivateDexSwap,
            GasLane::Lending,
            GasLane::Perps,
            GasLane::TokenMintBurn,
            GasLane::SmartContractCall,
            GasLane::ProofAggregation,
            GasLane::WalletRecovery,
            GasLane::EmergencyExit,
        ];
        let config_id = domain_hash(
            "LOW-FEE-ZK-GAS-FUTURES-CLEARINGHOUSE-CONFIG-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION),
                HashPart::Str("devnet"),
            ],
            32,
        );
        Self {
            config_id,
            protocol_version: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION.to_string(),
            schema_version: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_SCHEMA_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            eligibility_proof_scheme:
                LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_ZK_ELIGIBILITY_PROOF_SCHEME.to_string(),
            settlement_proof_scheme: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_SETTLEMENT_PROOF_SCHEME
                .to_string(),
            pq_risk_attestation_scheme:
                LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PQ_RISK_ATTESTATION_SCHEME.to_string(),
            epoch_blocks: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_EPOCH_BLOCKS,
            lot_ttl_blocks: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_LOT_TTL_BLOCKS,
            mark_interval_blocks: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MARK_INTERVAL_BLOCKS,
            expiry_grace_blocks: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_EXPIRY_GRACE_BLOCKS,
            min_privacy_set_size: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS,
            initial_margin_bps: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps:
                LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_MAINTENANCE_MARGIN_BPS,
            sponsor_reserve_bps: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_SPONSOR_RESERVE_BPS,
            max_open_lots_per_account: 64,
            max_lane_open_interest_units: 25_000_000,
            low_fee_target_micro_price: 1_000,
            liquidation_penalty_bps: 350,
            mark_quorum_threshold: 3,
            supported_lanes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "config_id": self.config_id,
            "epoch_blocks": self.epoch_blocks,
            "eligibility_proof_scheme": self.eligibility_proof_scheme,
            "expiry_grace_blocks": self.expiry_grace_blocks,
            "initial_margin_bps": self.initial_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "lot_ttl_blocks": self.lot_ttl_blocks,
            "low_fee_target_micro_price": self.low_fee_target_micro_price,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "mark_interval_blocks": self.mark_interval_blocks,
            "mark_quorum_threshold": self.mark_quorum_threshold,
            "max_lane_open_interest_units": self.max_lane_open_interest_units,
            "max_open_lots_per_account": self.max_open_lots_per_account,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_risk_attestation_scheme": self.pq_risk_attestation_scheme,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "settlement_proof_scheme": self.settlement_proof_scheme,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "supported_lanes": self.supported_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateForwardGasLot {
    pub lot_id: String,
    pub lane: GasLane,
    pub side: LotSide,
    pub status: LotStatus,
    pub owner_commitment: String,
    pub counterparty_commitment: String,
    pub eligibility_id: String,
    pub sponsor_credit_id: String,
    pub notional_gas_units: u64,
    pub strike_micro_price: u64,
    pub max_fee_micro_price: u64,
    pub premium_piconero: u64,
    pub margin_commitment: String,
    pub confidential_terms_root: String,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub last_mark_id: String,
    pub settlement_id: String,
    pub nonce: u64,
}

impl PrivateForwardGasLot {
    pub fn public_record(&self) -> Value {
        json!({
            "confidential_terms_root": self.confidential_terms_root,
            "counterparty_commitment": self.counterparty_commitment,
            "eligibility_id": self.eligibility_id,
            "expiry_height": self.expiry_height,
            "lane": self.lane.as_str(),
            "last_mark_id": self.last_mark_id,
            "lot_id": self.lot_id,
            "margin_commitment": self.margin_commitment,
            "max_fee_micro_price": self.max_fee_micro_price,
            "nonce": self.nonce,
            "notional_gas_units": self.notional_gas_units,
            "opened_height": self.opened_height,
            "owner_commitment": self.owner_commitment,
            "premium_piconero": self.premium_piconero,
            "settlement_id": self.settlement_id,
            "side": self.side.as_str(),
            "sponsor_credit_id": self.sponsor_credit_id,
            "status": self.status.as_str(),
            "strike_micro_price": self.strike_micro_price,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expiry_height && self.status.live()
    }

    pub fn gross_notional_piconero(&self) -> u64 {
        self.notional_gas_units
            .saturating_mul(self.strike_micro_price)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeHedge {
    pub hedge_id: String,
    pub lot_id: String,
    pub lane: GasLane,
    pub side: LotSide,
    pub status: HedgeStatus,
    pub hedge_account_commitment: String,
    pub coverage_gas_units: u64,
    pub floor_micro_price: u64,
    pub cap_micro_price: u64,
    pub collateral_commitment: String,
    pub risk_attestation_id: String,
    pub posted_height: u64,
    pub expires_height: u64,
    pub nonce: u64,
}

impl FeeHedge {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_micro_price": self.cap_micro_price,
            "collateral_commitment": self.collateral_commitment,
            "coverage_gas_units": self.coverage_gas_units,
            "expires_height": self.expires_height,
            "floor_micro_price": self.floor_micro_price,
            "hedge_account_commitment": self.hedge_account_commitment,
            "hedge_id": self.hedge_id,
            "lane": self.lane.as_str(),
            "lot_id": self.lot_id,
            "nonce": self.nonce,
            "posted_height": self.posted_height,
            "risk_attestation_id": self.risk_attestation_id,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_height && self.status.live()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorVaultCredit {
    pub credit_id: String,
    pub sponsor_commitment: String,
    pub lane: GasLane,
    pub status: SponsorCreditStatus,
    pub credit_asset_id: String,
    pub total_credit_piconero: u64,
    pub reserved_credit_piconero: u64,
    pub spent_credit_piconero: u64,
    pub max_subsidy_micro_price: u64,
    pub eligible_lot_root: String,
    pub vault_commitment_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub nonce: u64,
}

impl SponsorVaultCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_asset_id": self.credit_asset_id,
            "credit_id": self.credit_id,
            "eligible_lot_root": self.eligible_lot_root,
            "expires_height": self.expires_height,
            "lane": self.lane.as_str(),
            "max_subsidy_micro_price": self.max_subsidy_micro_price,
            "nonce": self.nonce,
            "opened_height": self.opened_height,
            "reserved_credit_piconero": self.reserved_credit_piconero,
            "spent_credit_piconero": self.spent_credit_piconero,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "total_credit_piconero": self.total_credit_piconero,
            "vault_commitment_root": self.vault_commitment_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn available_credit_piconero(&self) -> u64 {
        self.total_credit_piconero
            .saturating_sub(self.reserved_credit_piconero)
            .saturating_sub(self.spent_credit_piconero)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementMark {
    pub mark_id: String,
    pub lane: GasLane,
    pub status: MarkStatus,
    pub epoch_index: u64,
    pub observed_height: u64,
    pub mark_micro_price: u64,
    pub twap_micro_price: u64,
    pub realized_vol_bps: u64,
    pub oracle_quorum_root: String,
    pub mark_proof_root: String,
    pub pq_signature_root: String,
    pub supersedes_mark_id: String,
}

impl SettlementMark {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_index": self.epoch_index,
            "lane": self.lane.as_str(),
            "mark_id": self.mark_id,
            "mark_micro_price": self.mark_micro_price,
            "mark_proof_root": self.mark_proof_root,
            "observed_height": self.observed_height,
            "oracle_quorum_root": self.oracle_quorum_root,
            "pq_signature_root": self.pq_signature_root,
            "realized_vol_bps": self.realized_vol_bps,
            "status": self.status.as_str(),
            "supersedes_mark_id": self.supersedes_mark_id,
            "twap_micro_price": self.twap_micro_price,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkEligibilityProof {
    pub proof_id: String,
    pub subject_commitment: String,
    pub lane: GasLane,
    pub status: EligibilityStatus,
    pub proof_system: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub nullifier: String,
    pub max_gas_units: u64,
    pub max_fee_micro_price: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub verifier_committee_root: String,
}

impl ZkEligibilityProof {
    pub fn public_record(&self) -> Value {
        json!({
            "expires_height": self.expires_height,
            "lane": self.lane.as_str(),
            "max_fee_micro_price": self.max_fee_micro_price,
            "max_gas_units": self.max_gas_units,
            "nullifier": self.nullifier,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "proof_id": self.proof_id,
            "proof_root": self.proof_root,
            "proof_system": self.proof_system,
            "public_input_root": self.public_input_root,
            "status": self.status.as_str(),
            "subject_commitment": self.subject_commitment,
            "submitted_height": self.submitted_height,
            "verifier_committee_root": self.verifier_committee_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqRiskAttestation {
    pub attestation_id: String,
    pub signer_commitment: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub status: RiskAttestationStatus,
    pub lane: GasLane,
    pub risk_score_bps: u64,
    pub exposure_limit_piconero: u64,
    pub margin_requirement_bps: u64,
    pub liquidity_haircut_bps: u64,
    pub model_root: String,
    pub evidence_root: String,
    pub signature_scheme: String,
    pub signature_root: String,
    pub signed_height: u64,
    pub expires_height: u64,
}

impl PqRiskAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "evidence_root": self.evidence_root,
            "expires_height": self.expires_height,
            "exposure_limit_piconero": self.exposure_limit_piconero,
            "lane": self.lane.as_str(),
            "liquidity_haircut_bps": self.liquidity_haircut_bps,
            "margin_requirement_bps": self.margin_requirement_bps,
            "model_root": self.model_root,
            "risk_score_bps": self.risk_score_bps,
            "signature_root": self.signature_root,
            "signature_scheme": self.signature_scheme,
            "signed_height": self.signed_height,
            "signer_commitment": self.signer_commitment,
            "status": self.status.as_str(),
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub lot_id: String,
    pub hedge_id: String,
    pub credit_id: String,
    pub mark_id: String,
    pub close_reason: CloseReason,
    pub settlement_proof_root: String,
    pub gas_units_settled: u64,
    pub strike_micro_price: u64,
    pub mark_micro_price: u64,
    pub payer_delta_piconero: i128,
    pub sponsor_delta_piconero: i128,
    pub maker_delta_piconero: i128,
    pub fee_rebate_piconero: u64,
    pub settled_height: u64,
    pub pq_signature_root: String,
}

impl SettlementRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "close_reason": self.close_reason.as_str(),
            "credit_id": self.credit_id,
            "fee_rebate_piconero": self.fee_rebate_piconero,
            "gas_units_settled": self.gas_units_settled,
            "hedge_id": self.hedge_id,
            "lot_id": self.lot_id,
            "maker_delta_piconero": self.maker_delta_piconero,
            "mark_id": self.mark_id,
            "mark_micro_price": self.mark_micro_price,
            "payer_delta_piconero": self.payer_delta_piconero,
            "pq_signature_root": self.pq_signature_root,
            "settled_height": self.settled_height,
            "settlement_id": self.settlement_id,
            "settlement_proof_root": self.settlement_proof_root,
            "sponsor_delta_piconero": self.sponsor_delta_piconero,
            "strike_micro_price": self.strike_micro_price,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidationRecord {
    pub liquidation_id: String,
    pub lot_id: String,
    pub hedge_id: String,
    pub liquidator_commitment: String,
    pub lane: GasLane,
    pub trigger_mark_id: String,
    pub close_reason: CloseReason,
    pub deficit_piconero: u64,
    pub penalty_piconero: u64,
    pub seized_margin_root: String,
    pub proof_root: String,
    pub liquidated_height: u64,
}

impl LiquidationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "close_reason": self.close_reason.as_str(),
            "deficit_piconero": self.deficit_piconero,
            "hedge_id": self.hedge_id,
            "lane": self.lane.as_str(),
            "liquidated_height": self.liquidated_height,
            "liquidation_id": self.liquidation_id,
            "liquidator_commitment": self.liquidator_commitment,
            "lot_id": self.lot_id,
            "penalty_piconero": self.penalty_piconero,
            "proof_root": self.proof_root,
            "seized_margin_root": self.seized_margin_root,
            "trigger_mark_id": self.trigger_mark_id,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpiryRecord {
    pub expiry_id: String,
    pub lot_id: String,
    pub hedge_id: String,
    pub credit_id: String,
    pub lane: GasLane,
    pub expiry_height: u64,
    pub processed_height: u64,
    pub close_reason: CloseReason,
    pub released_margin_root: String,
    pub expired_notional_gas_units: u64,
}

impl ExpiryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "close_reason": self.close_reason.as_str(),
            "credit_id": self.credit_id,
            "expired_notional_gas_units": self.expired_notional_gas_units,
            "expiry_height": self.expiry_height,
            "expiry_id": self.expiry_id,
            "hedge_id": self.hedge_id,
            "lane": self.lane.as_str(),
            "lot_id": self.lot_id,
            "processed_height": self.processed_height,
            "released_margin_root": self.released_margin_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub forward_lot_root: String,
    pub fee_hedge_root: String,
    pub sponsor_credit_root: String,
    pub settlement_mark_root: String,
    pub eligibility_proof_root: String,
    pub pq_risk_attestation_root: String,
    pub settlement_record_root: String,
    pub liquidation_record_root: String,
    pub expiry_record_root: String,
    pub lane_exposure_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "eligibility_proof_root": self.eligibility_proof_root,
            "expiry_record_root": self.expiry_record_root,
            "fee_hedge_root": self.fee_hedge_root,
            "forward_lot_root": self.forward_lot_root,
            "lane_exposure_root": self.lane_exposure_root,
            "liquidation_record_root": self.liquidation_record_root,
            "pq_risk_attestation_root": self.pq_risk_attestation_root,
            "public_record_root": self.public_record_root,
            "settlement_mark_root": self.settlement_mark_root,
            "settlement_record_root": self.settlement_record_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub forward_lots: u64,
    pub live_forward_lots: u64,
    pub fee_hedges: u64,
    pub live_fee_hedges: u64,
    pub sponsor_credits: u64,
    pub usable_sponsor_credits: u64,
    pub settlement_marks: u64,
    pub accepted_marks: u64,
    pub eligibility_proofs: u64,
    pub verified_eligibility_proofs: u64,
    pub pq_risk_attestations: u64,
    pub active_pq_risk_attestations: u64,
    pub settlement_records: u64,
    pub liquidation_records: u64,
    pub expiry_records: u64,
    pub total_open_interest_gas_units: u64,
    pub total_reserved_sponsor_credit_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "accepted_marks": self.accepted_marks,
            "active_pq_risk_attestations": self.active_pq_risk_attestations,
            "eligibility_proofs": self.eligibility_proofs,
            "expiry_records": self.expiry_records,
            "fee_hedges": self.fee_hedges,
            "forward_lots": self.forward_lots,
            "liquidation_records": self.liquidation_records,
            "live_fee_hedges": self.live_fee_hedges,
            "live_forward_lots": self.live_forward_lots,
            "pq_risk_attestations": self.pq_risk_attestations,
            "settlement_marks": self.settlement_marks,
            "settlement_records": self.settlement_records,
            "sponsor_credits": self.sponsor_credits,
            "total_open_interest_gas_units": self.total_open_interest_gas_units,
            "total_reserved_sponsor_credit_piconero": self.total_reserved_sponsor_credit_piconero,
            "usable_sponsor_credits": self.usable_sponsor_credits,
            "verified_eligibility_proofs": self.verified_eligibility_proofs,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch_index: u64,
    pub forward_lots: BTreeMap<String, PrivateForwardGasLot>,
    pub fee_hedges: BTreeMap<String, FeeHedge>,
    pub sponsor_credits: BTreeMap<String, SponsorVaultCredit>,
    pub settlement_marks: BTreeMap<String, SettlementMark>,
    pub eligibility_proofs: BTreeMap<String, ZkEligibilityProof>,
    pub pq_risk_attestations: BTreeMap<String, PqRiskAttestation>,
    pub settlement_records: BTreeMap<String, SettlementRecord>,
    pub liquidation_records: BTreeMap<String, LiquidationRecord>,
    pub expiry_records: BTreeMap<String, ExpiryRecord>,
}

impl State {
    pub fn devnet() -> LowFeeZkGasFuturesClearinghouseResult<Self> {
        let config = Config::devnet();
        let height = LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_DEFAULT_HEIGHT;
        let epoch_index = height / config.epoch_blocks;
        let mut state = Self {
            config,
            height,
            epoch_index,
            forward_lots: BTreeMap::new(),
            fee_hedges: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            settlement_marks: BTreeMap::new(),
            eligibility_proofs: BTreeMap::new(),
            pq_risk_attestations: BTreeMap::new(),
            settlement_records: BTreeMap::new(),
            liquidation_records: BTreeMap::new(),
            expiry_records: BTreeMap::new(),
        };
        state.seed_devnet();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        if self.config.protocol_version != LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION {
            return Err(
                "invalid low fee zk gas futures clearinghouse protocol version".to_string(),
            );
        }
        if self.config.chain_id != CHAIN_ID {
            return Err("state chain id does not match crate chain id".to_string());
        }
        if self.config.initial_margin_bps > LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_MAX_BPS
            || self.config.maintenance_margin_bps > LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_MAX_BPS
            || self.config.sponsor_reserve_bps > LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_MAX_BPS
        {
            return Err("margin or reserve basis points exceed max bps".to_string());
        }
        if self.config.maintenance_margin_bps > self.config.initial_margin_bps {
            return Err("maintenance margin exceeds initial margin".to_string());
        }
        if self.epoch_index != self.height / self.config.epoch_blocks {
            return Err("epoch index is inconsistent with height".to_string());
        }
        self.validate_unique_nullifiers()?;
        self.validate_lots()?;
        self.validate_hedges()?;
        self.validate_sponsor_credits()?;
        self.validate_marks()?;
        self.validate_eligibility()?;
        self.validate_risk_attestations()?;
        self.validate_closure_records()?;
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        self.height = height;
        self.epoch_index = self.height / self.config.epoch_blocks;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        if height < self.height {
            return Err("cannot update clearinghouse height backwards".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let forward_lot_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-FORWARD-LOT",
            &self.records_forward_lots(),
        );
        let fee_hedge_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-FEE-HEDGE",
            &self.records_fee_hedges(),
        );
        let sponsor_credit_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-SPONSOR-CREDIT",
            &self.records_sponsor_credits(),
        );
        let settlement_mark_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-SETTLEMENT-MARK",
            &self.records_settlement_marks(),
        );
        let eligibility_proof_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-ELIGIBILITY-PROOF",
            &self.records_eligibility_proofs(),
        );
        let pq_risk_attestation_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-PQ-RISK-ATTESTATION",
            &self.records_pq_risk_attestations(),
        );
        let settlement_record_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-SETTLEMENT-RECORD",
            &self.records_settlement_records(),
        );
        let liquidation_record_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-LIQUIDATION-RECORD",
            &self.records_liquidation_records(),
        );
        let expiry_record_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-EXPIRY-RECORD",
            &self.records_expiry_records(),
        );
        let lane_exposure_root = merkle_root(
            "LOW-FEE-ZK-GAS-FUTURES-LANE-EXPOSURE",
            &self.lane_exposure_records(),
        );
        let public_record_root = root_from_record(&self.public_record_without_roots());
        let state_root = domain_hash(
            "LOW-FEE-ZK-GAS-FUTURES-CLEARINGHOUSE-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.epoch_index as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&forward_lot_root),
                HashPart::Str(&fee_hedge_root),
                HashPart::Str(&sponsor_credit_root),
                HashPart::Str(&settlement_mark_root),
                HashPart::Str(&eligibility_proof_root),
                HashPart::Str(&pq_risk_attestation_root),
                HashPart::Str(&settlement_record_root),
                HashPart::Str(&liquidation_record_root),
                HashPart::Str(&expiry_record_root),
                HashPart::Str(&lane_exposure_root),
                HashPart::Str(&public_record_root),
            ],
            32,
        );
        Roots {
            config_root,
            forward_lot_root,
            fee_hedge_root,
            sponsor_credit_root,
            settlement_mark_root,
            eligibility_proof_root,
            pq_risk_attestation_root,
            settlement_record_root,
            liquidation_record_root,
            expiry_record_root,
            lane_exposure_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            forward_lots: self.forward_lots.len() as u64,
            live_forward_lots: self
                .forward_lots
                .values()
                .filter(|lot| lot.status.live())
                .count() as u64,
            fee_hedges: self.fee_hedges.len() as u64,
            live_fee_hedges: self
                .fee_hedges
                .values()
                .filter(|hedge| hedge.status.live())
                .count() as u64,
            sponsor_credits: self.sponsor_credits.len() as u64,
            usable_sponsor_credits: self
                .sponsor_credits
                .values()
                .filter(|credit| credit.status.usable())
                .count() as u64,
            settlement_marks: self.settlement_marks.len() as u64,
            accepted_marks: self
                .settlement_marks
                .values()
                .filter(|mark| mark.status == MarkStatus::Accepted)
                .count() as u64,
            eligibility_proofs: self.eligibility_proofs.len() as u64,
            verified_eligibility_proofs: self
                .eligibility_proofs
                .values()
                .filter(|proof| proof.status == EligibilityStatus::Verified)
                .count() as u64,
            pq_risk_attestations: self.pq_risk_attestations.len() as u64,
            active_pq_risk_attestations: self
                .pq_risk_attestations
                .values()
                .filter(|attestation| attestation.status == RiskAttestationStatus::Active)
                .count() as u64,
            settlement_records: self.settlement_records.len() as u64,
            liquidation_records: self.liquidation_records.len() as u64,
            expiry_records: self.expiry_records.len() as u64,
            total_open_interest_gas_units: self
                .forward_lots
                .values()
                .filter(|lot| lot.status.live())
                .fold(0_u64, |acc, lot| acc.saturating_add(lot.notional_gas_units)),
            total_reserved_sponsor_credit_piconero: self
                .sponsor_credits
                .values()
                .fold(0_u64, |acc, credit| {
                    acc.saturating_add(credit.reserved_credit_piconero)
                }),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "epoch_index": self.epoch_index,
            "height": self.height,
            "protocol_version": LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn public_record_without_roots(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "epoch_index": self.epoch_index,
            "height": self.height,
            "protocol_version": LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION,
        })
    }

    fn seed_devnet(&mut self) {
        let lanes = [
            GasLane::PrivateTransfer,
            GasLane::MoneroBridge,
            GasLane::PrivateDexSwap,
            GasLane::SmartContractCall,
            GasLane::ProofAggregation,
            GasLane::EmergencyExit,
        ];
        for (index, lane) in lanes.iter().copied().enumerate() {
            let account = commitment("devnet-account", lane.as_str(), index as u64);
            let sponsor = commitment("devnet-sponsor", lane.as_str(), index as u64);
            let maker = commitment("devnet-maker", lane.as_str(), index as u64);
            let eligibility_id = object_id("eligibility", lane.as_str(), index as u64);
            let credit_id = object_id("credit", lane.as_str(), index as u64);
            let lot_id = object_id("lot", lane.as_str(), index as u64);
            let hedge_id = object_id("hedge", lane.as_str(), index as u64);
            let mark_id = object_id("mark", lane.as_str(), index as u64);
            let attestation_id = object_id("risk", lane.as_str(), index as u64);
            let strike = lane.default_target_micro_price();
            let units = 50_000_u64.saturating_add((index as u64).saturating_mul(17_500));
            self.eligibility_proofs.insert(
                eligibility_id.clone(),
                ZkEligibilityProof {
                    proof_id: eligibility_id.clone(),
                    subject_commitment: account.clone(),
                    lane,
                    status: EligibilityStatus::Verified,
                    proof_system: LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_ZK_ELIGIBILITY_PROOF_SCHEME
                        .to_string(),
                    proof_root: commitment("zk-proof", lane.as_str(), index as u64),
                    public_input_root: commitment("zk-input", lane.as_str(), index as u64),
                    nullifier: commitment("zk-nullifier", lane.as_str(), index as u64),
                    max_gas_units: units.saturating_mul(4),
                    max_fee_micro_price: strike.saturating_mul(2),
                    privacy_set_size: lane.default_privacy_floor().saturating_add(32),
                    pq_security_bits: self.config.min_pq_security_bits,
                    submitted_height: self.height.saturating_sub(8),
                    expires_height: self.height.saturating_add(self.config.lot_ttl_blocks),
                    verifier_committee_root: commitment("verifier-committee", lane.as_str(), 0),
                },
            );
            self.sponsor_credits.insert(
                credit_id.clone(),
                SponsorVaultCredit {
                    credit_id: credit_id.clone(),
                    sponsor_commitment: sponsor.clone(),
                    lane,
                    status: SponsorCreditStatus::Reserved,
                    credit_asset_id: "piconero-gas-credit".to_string(),
                    total_credit_piconero: units.saturating_mul(strike).saturating_mul(3),
                    reserved_credit_piconero: units.saturating_mul(strike),
                    spent_credit_piconero: 0,
                    max_subsidy_micro_price: strike.saturating_mul(2),
                    eligible_lot_root: commitment("eligible-lot-set", lane.as_str(), index as u64),
                    vault_commitment_root: commitment("sponsor-vault", lane.as_str(), index as u64),
                    opened_height: self.height.saturating_sub(10),
                    expires_height: self.height.saturating_add(self.config.lot_ttl_blocks),
                    nonce: index as u64,
                },
            );
            self.settlement_marks.insert(
                mark_id.clone(),
                SettlementMark {
                    mark_id: mark_id.clone(),
                    lane,
                    status: MarkStatus::Accepted,
                    epoch_index: self.epoch_index,
                    observed_height: self.height,
                    mark_micro_price: strike.saturating_add(75),
                    twap_micro_price: strike.saturating_add(45),
                    realized_vol_bps: 300_u64.saturating_add((index as u64).saturating_mul(20)),
                    oracle_quorum_root: commitment("oracle-quorum", lane.as_str(), index as u64),
                    mark_proof_root: commitment("mark-proof", lane.as_str(), index as u64),
                    pq_signature_root: commitment("mark-pq-signature", lane.as_str(), index as u64),
                    supersedes_mark_id: String::new(),
                },
            );
            self.pq_risk_attestations.insert(
                attestation_id.clone(),
                PqRiskAttestation {
                    attestation_id: attestation_id.clone(),
                    signer_commitment: maker.clone(),
                    subject_kind: "fee_hedge".to_string(),
                    subject_id: hedge_id.clone(),
                    status: RiskAttestationStatus::Active,
                    lane,
                    risk_score_bps: 1_000_u64.saturating_add((index as u64).saturating_mul(80)),
                    exposure_limit_piconero: units.saturating_mul(strike).saturating_mul(5),
                    margin_requirement_bps: self.config.initial_margin_bps,
                    liquidity_haircut_bps: 250,
                    model_root: commitment("risk-model", lane.as_str(), index as u64),
                    evidence_root: commitment("risk-evidence", lane.as_str(), index as u64),
                    signature_scheme:
                        LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PQ_RISK_ATTESTATION_SCHEME.to_string(),
                    signature_root: commitment("risk-pq-signature", lane.as_str(), index as u64),
                    signed_height: self.height.saturating_sub(6),
                    expires_height: self.height.saturating_add(self.config.lot_ttl_blocks),
                },
            );
            self.forward_lots.insert(
                lot_id.clone(),
                PrivateForwardGasLot {
                    lot_id: lot_id.clone(),
                    lane,
                    side: LotSide::UserLongFee,
                    status: LotStatus::Funded,
                    owner_commitment: account,
                    counterparty_commitment: maker.clone(),
                    eligibility_id,
                    sponsor_credit_id: credit_id,
                    notional_gas_units: units,
                    strike_micro_price: strike,
                    max_fee_micro_price: strike.saturating_mul(2),
                    premium_piconero: units.saturating_mul(12),
                    margin_commitment: commitment("margin", lane.as_str(), index as u64),
                    confidential_terms_root: commitment("terms", lane.as_str(), index as u64),
                    opened_height: self.height.saturating_sub(5),
                    expiry_height: self.height.saturating_add(self.config.lot_ttl_blocks),
                    last_mark_id: mark_id,
                    settlement_id: String::new(),
                    nonce: index as u64,
                },
            );
            self.fee_hedges.insert(
                hedge_id.clone(),
                FeeHedge {
                    hedge_id,
                    lot_id,
                    lane,
                    side: LotSide::SponsorShortFee,
                    status: HedgeStatus::Bound,
                    hedge_account_commitment: maker,
                    coverage_gas_units: units,
                    floor_micro_price: strike.saturating_sub(strike / 5),
                    cap_micro_price: strike.saturating_mul(2),
                    collateral_commitment: commitment(
                        "hedge-collateral",
                        lane.as_str(),
                        index as u64,
                    ),
                    risk_attestation_id: attestation_id,
                    posted_height: self.height.saturating_sub(5),
                    expires_height: self.height.saturating_add(self.config.lot_ttl_blocks),
                    nonce: index as u64,
                },
            );
        }
        self.seed_closed_records();
    }

    fn seed_closed_records(&mut self) {
        let lane = GasLane::PrivateTransfer;
        let lot_id = object_id("closed-lot", lane.as_str(), 0);
        let hedge_id = object_id("closed-hedge", lane.as_str(), 0);
        let credit_id = object_id("closed-credit", lane.as_str(), 0);
        let mark_id = object_id("closed-mark", lane.as_str(), 0);
        let settlement_id = object_id("settlement", lane.as_str(), 0);
        self.settlement_records.insert(
            settlement_id.clone(),
            SettlementRecord {
                settlement_id,
                lot_id: lot_id.clone(),
                hedge_id: hedge_id.clone(),
                credit_id: credit_id.clone(),
                mark_id: mark_id.clone(),
                close_reason: CloseReason::CashSettled,
                settlement_proof_root: commitment("settlement-proof", lane.as_str(), 0),
                gas_units_settled: 40_000,
                strike_micro_price: lane.default_target_micro_price(),
                mark_micro_price: lane.default_target_micro_price().saturating_add(50),
                payer_delta_piconero: 2_000_000,
                sponsor_delta_piconero: -1_700_000,
                maker_delta_piconero: -300_000,
                fee_rebate_piconero: 600_000,
                settled_height: self.height.saturating_sub(2),
                pq_signature_root: commitment("settlement-pq-signature", lane.as_str(), 0),
            },
        );
        self.liquidation_records.insert(
            object_id("liquidation", lane.as_str(), 0),
            LiquidationRecord {
                liquidation_id: object_id("liquidation", lane.as_str(), 0),
                lot_id: object_id("liquidated-lot", lane.as_str(), 0),
                hedge_id: object_id("liquidated-hedge", lane.as_str(), 0),
                liquidator_commitment: commitment("liquidator", lane.as_str(), 0),
                lane,
                trigger_mark_id: mark_id.clone(),
                close_reason: CloseReason::MarginLiquidation,
                deficit_piconero: 1_250_000,
                penalty_piconero: 125_000,
                seized_margin_root: commitment("seized-margin", lane.as_str(), 0),
                proof_root: commitment("liquidation-proof", lane.as_str(), 0),
                liquidated_height: self.height.saturating_sub(1),
            },
        );
        self.expiry_records.insert(
            object_id("expiry", lane.as_str(), 0),
            ExpiryRecord {
                expiry_id: object_id("expiry", lane.as_str(), 0),
                lot_id,
                hedge_id,
                credit_id,
                lane,
                expiry_height: self.height.saturating_sub(4),
                processed_height: self.height.saturating_sub(3),
                close_reason: CloseReason::ExpiredWorthless,
                released_margin_root: commitment("released-margin", lane.as_str(), 0),
                expired_notional_gas_units: 25_000,
            },
        );
    }

    fn validate_unique_nullifiers(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        let mut seen = BTreeSet::new();
        for proof in self.eligibility_proofs.values() {
            if proof.nullifier.is_empty() {
                return Err(format!(
                    "eligibility proof {} has empty nullifier",
                    proof.proof_id
                ));
            }
            if !seen.insert(proof.nullifier.clone()) {
                return Err(format!(
                    "duplicate eligibility nullifier {}",
                    proof.nullifier
                ));
            }
        }
        Ok(())
    }

    fn validate_lots(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        for (lot_id, lot) in &self.forward_lots {
            if lot_id != &lot.lot_id {
                return Err(format!("forward lot key mismatch for {}", lot_id));
            }
            if !self.config.supported_lanes.contains(&lot.lane) {
                return Err(format!("unsupported lot lane for {}", lot.lot_id));
            }
            if lot.notional_gas_units == 0 {
                return Err(format!("forward lot {} has zero gas units", lot.lot_id));
            }
            if lot.strike_micro_price == 0 || lot.max_fee_micro_price < lot.strike_micro_price {
                return Err(format!(
                    "forward lot {} has invalid price bounds",
                    lot.lot_id
                ));
            }
            if lot.expiry_height <= lot.opened_height {
                return Err(format!("forward lot {} has invalid expiry", lot.lot_id));
            }
            if lot.status.live() {
                if !self.eligibility_proofs.contains_key(&lot.eligibility_id) {
                    return Err(format!(
                        "forward lot {} references missing eligibility",
                        lot.lot_id
                    ));
                }
                if !self.sponsor_credits.contains_key(&lot.sponsor_credit_id) {
                    return Err(format!(
                        "forward lot {} references missing sponsor credit",
                        lot.lot_id
                    ));
                }
                if !self.settlement_marks.contains_key(&lot.last_mark_id) {
                    return Err(format!(
                        "forward lot {} references missing settlement mark",
                        lot.lot_id
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_hedges(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        for (hedge_id, hedge) in &self.fee_hedges {
            if hedge_id != &hedge.hedge_id {
                return Err(format!("fee hedge key mismatch for {}", hedge_id));
            }
            if hedge.coverage_gas_units == 0 {
                return Err(format!("fee hedge {} has zero coverage", hedge.hedge_id));
            }
            if hedge.cap_micro_price < hedge.floor_micro_price {
                return Err(format!(
                    "fee hedge {} has inverted price band",
                    hedge.hedge_id
                ));
            }
            if hedge.status.live() {
                if !self.forward_lots.contains_key(&hedge.lot_id) {
                    return Err(format!(
                        "fee hedge {} references missing lot",
                        hedge.hedge_id
                    ));
                }
                if !self
                    .pq_risk_attestations
                    .contains_key(&hedge.risk_attestation_id)
                {
                    return Err(format!(
                        "fee hedge {} references missing risk attestation",
                        hedge.hedge_id
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_sponsor_credits(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        for (credit_id, credit) in &self.sponsor_credits {
            if credit_id != &credit.credit_id {
                return Err(format!("sponsor credit key mismatch for {}", credit_id));
            }
            let committed = credit
                .reserved_credit_piconero
                .saturating_add(credit.spent_credit_piconero);
            if committed > credit.total_credit_piconero {
                return Err(format!("sponsor credit {} overcommitted", credit.credit_id));
            }
            if credit.max_subsidy_micro_price == 0 {
                return Err(format!(
                    "sponsor credit {} has zero subsidy cap",
                    credit.credit_id
                ));
            }
        }
        Ok(())
    }

    fn validate_marks(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        for (mark_id, mark) in &self.settlement_marks {
            if mark_id != &mark.mark_id {
                return Err(format!("settlement mark key mismatch for {}", mark_id));
            }
            if mark.mark_micro_price == 0 || mark.twap_micro_price == 0 {
                return Err(format!("settlement mark {} has zero price", mark.mark_id));
            }
            if mark.status == MarkStatus::Accepted && mark.pq_signature_root.is_empty() {
                return Err(format!(
                    "accepted settlement mark {} lacks pq signatures",
                    mark.mark_id
                ));
            }
        }
        Ok(())
    }

    fn validate_eligibility(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        for (proof_id, proof) in &self.eligibility_proofs {
            if proof_id != &proof.proof_id {
                return Err(format!("eligibility proof key mismatch for {}", proof_id));
            }
            if proof.proof_system != self.config.eligibility_proof_scheme {
                return Err(format!(
                    "eligibility proof {} has unsupported proof system",
                    proof.proof_id
                ));
            }
            if proof.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "eligibility proof {} privacy set too small",
                    proof.proof_id
                ));
            }
            if proof.pq_security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "eligibility proof {} pq security too low",
                    proof.proof_id
                ));
            }
        }
        Ok(())
    }

    fn validate_risk_attestations(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        for (attestation_id, attestation) in &self.pq_risk_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err(format!(
                    "risk attestation key mismatch for {}",
                    attestation_id
                ));
            }
            if attestation.signature_scheme != self.config.pq_risk_attestation_scheme {
                return Err(format!(
                    "risk attestation {} has unsupported signature scheme",
                    attestation.attestation_id
                ));
            }
            if attestation.margin_requirement_bps > LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_MAX_BPS {
                return Err(format!(
                    "risk attestation {} margin exceeds max bps",
                    attestation.attestation_id
                ));
            }
            if attestation.status == RiskAttestationStatus::Active
                && attestation.signature_root.is_empty()
            {
                return Err(format!(
                    "active risk attestation {} lacks signature root",
                    attestation.attestation_id
                ));
            }
        }
        Ok(())
    }

    fn validate_closure_records(&self) -> LowFeeZkGasFuturesClearinghouseResult<()> {
        for (settlement_id, settlement) in &self.settlement_records {
            if settlement_id != &settlement.settlement_id {
                return Err(format!(
                    "settlement record key mismatch for {}",
                    settlement_id
                ));
            }
            if settlement.settlement_proof_root.is_empty() {
                return Err(format!(
                    "settlement record {} lacks proof root",
                    settlement_id
                ));
            }
        }
        for (liquidation_id, liquidation) in &self.liquidation_records {
            if liquidation_id != &liquidation.liquidation_id {
                return Err(format!(
                    "liquidation record key mismatch for {}",
                    liquidation_id
                ));
            }
            if liquidation.close_reason != CloseReason::MarginLiquidation
                && liquidation.close_reason != CloseReason::SponsorDefault
            {
                return Err(format!(
                    "liquidation record {} has invalid close reason",
                    liquidation_id
                ));
            }
        }
        for (expiry_id, expiry) in &self.expiry_records {
            if expiry_id != &expiry.expiry_id {
                return Err(format!("expiry record key mismatch for {}", expiry_id));
            }
            if expiry.processed_height < expiry.expiry_height {
                return Err(format!(
                    "expiry record {} processed before expiry",
                    expiry_id
                ));
            }
        }
        Ok(())
    }

    fn records_forward_lots(&self) -> Vec<Value> {
        self.forward_lots
            .values()
            .map(PrivateForwardGasLot::public_record)
            .collect()
    }

    fn records_fee_hedges(&self) -> Vec<Value> {
        self.fee_hedges
            .values()
            .map(FeeHedge::public_record)
            .collect()
    }

    fn records_sponsor_credits(&self) -> Vec<Value> {
        self.sponsor_credits
            .values()
            .map(SponsorVaultCredit::public_record)
            .collect()
    }

    fn records_settlement_marks(&self) -> Vec<Value> {
        self.settlement_marks
            .values()
            .map(SettlementMark::public_record)
            .collect()
    }

    fn records_eligibility_proofs(&self) -> Vec<Value> {
        self.eligibility_proofs
            .values()
            .map(ZkEligibilityProof::public_record)
            .collect()
    }

    fn records_pq_risk_attestations(&self) -> Vec<Value> {
        self.pq_risk_attestations
            .values()
            .map(PqRiskAttestation::public_record)
            .collect()
    }

    fn records_settlement_records(&self) -> Vec<Value> {
        self.settlement_records
            .values()
            .map(SettlementRecord::public_record)
            .collect()
    }

    fn records_liquidation_records(&self) -> Vec<Value> {
        self.liquidation_records
            .values()
            .map(LiquidationRecord::public_record)
            .collect()
    }

    fn records_expiry_records(&self) -> Vec<Value> {
        self.expiry_records
            .values()
            .map(ExpiryRecord::public_record)
            .collect()
    }

    fn lane_exposure_records(&self) -> Vec<Value> {
        self.config
            .supported_lanes
            .iter()
            .map(|lane| {
                let open_interest = self
                    .forward_lots
                    .values()
                    .filter(|lot| lot.lane == *lane && lot.status.live())
                    .fold(0_u64, |acc, lot| acc.saturating_add(lot.notional_gas_units));
                let hedged_units = self
                    .fee_hedges
                    .values()
                    .filter(|hedge| hedge.lane == *lane && hedge.status.live())
                    .fold(0_u64, |acc, hedge| {
                        acc.saturating_add(hedge.coverage_gas_units)
                    });
                let sponsor_available = self
                    .sponsor_credits
                    .values()
                    .filter(|credit| credit.lane == *lane && credit.status.usable())
                    .fold(0_u64, |acc, credit| {
                        acc.saturating_add(credit.available_credit_piconero())
                    });
                json!({
                    "hedged_units": hedged_units,
                    "lane": lane.as_str(),
                    "open_interest_gas_units": open_interest,
                    "sponsor_available_piconero": sponsor_available,
                    "target_micro_price": lane.default_target_micro_price(),
                })
            })
            .collect()
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "LOW-FEE-ZK-GAS-FUTURES-CLEARINGHOUSE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LOW_FEE_ZK_GAS_FUTURES_CLEARINGHOUSE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> LowFeeZkGasFuturesClearinghouseResult<State> {
    State::devnet()
}

pub fn private_forward_lot_id(lane: GasLane, owner_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "LOW-FEE-ZK-GAS-FUTURES-PRIVATE-FORWARD-LOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn fee_hedge_id(lane: GasLane, hedge_account_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "LOW-FEE-ZK-GAS-FUTURES-FEE-HEDGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(hedge_account_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn sponsor_credit_id(lane: GasLane, sponsor_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "LOW-FEE-ZK-GAS-FUTURES-SPONSOR-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sponsor_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn settlement_delta_piconero(
    gas_units: u64,
    strike_micro_price: u64,
    mark_micro_price: u64,
) -> i128 {
    let units = gas_units as i128;
    let strike = strike_micro_price as i128;
    let mark = mark_micro_price as i128;
    units.saturating_mul(mark.saturating_sub(strike))
}

fn object_id(kind: &str, lane: &str, nonce: u64) -> String {
    domain_hash(
        "LOW-FEE-ZK-GAS-FUTURES-OBJECT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(lane),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn commitment(kind: &str, lane: &str, nonce: u64) -> String {
    domain_hash(
        "LOW-FEE-ZK-GAS-FUTURES-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(lane),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRiskProfile {
    pub lane: GasLane,
    pub bucket: &'static str,
    pub target_micro_price: u64,
    pub stress_micro_price: u64,
    pub privacy_floor: u64,
    pub margin_bps: u64,
}

pub const LANE_RISK_PROFILES: &[LaneRiskProfile] = &[
    LaneRiskProfile {
        lane: GasLane::PrivateTransfer,
        bucket: "private_transfer_retail",
        target_micro_price: 700,
        stress_micro_price: 1_250,
        privacy_floor: 256,
        margin_bps: 1_200,
    },
    LaneRiskProfile {
        lane: GasLane::PrivateTransfer,
        bucket: "private_transfer_wholesale",
        target_micro_price: 650,
        stress_micro_price: 1_150,
        privacy_floor: 384,
        margin_bps: 1_100,
    },
    LaneRiskProfile {
        lane: GasLane::MoneroBridge,
        bucket: "monero_bridge_standard",
        target_micro_price: 1_050,
        stress_micro_price: 1_900,
        privacy_floor: 192,
        margin_bps: 1_500,
    },
    LaneRiskProfile {
        lane: GasLane::MoneroBridge,
        bucket: "monero_bridge_fast_exit",
        target_micro_price: 1_300,
        stress_micro_price: 2_300,
        privacy_floor: 160,
        margin_bps: 1_800,
    },
    LaneRiskProfile {
        lane: GasLane::PrivateDexSwap,
        bucket: "private_dex_swap_stable",
        target_micro_price: 1_250,
        stress_micro_price: 2_050,
        privacy_floor: 160,
        margin_bps: 1_500,
    },
    LaneRiskProfile {
        lane: GasLane::PrivateDexSwap,
        bucket: "private_dex_swap_volatile",
        target_micro_price: 1_500,
        stress_micro_price: 2_600,
        privacy_floor: 144,
        margin_bps: 1_900,
    },
    LaneRiskProfile {
        lane: GasLane::Lending,
        bucket: "lending_deposit_withdraw",
        target_micro_price: 1_450,
        stress_micro_price: 2_300,
        privacy_floor: 144,
        margin_bps: 1_550,
    },
    LaneRiskProfile {
        lane: GasLane::Lending,
        bucket: "lending_liquidation_sensitive",
        target_micro_price: 1_700,
        stress_micro_price: 2_900,
        privacy_floor: 128,
        margin_bps: 2_100,
    },
    LaneRiskProfile {
        lane: GasLane::Perps,
        bucket: "perps_funding",
        target_micro_price: 1_650,
        stress_micro_price: 2_800,
        privacy_floor: 144,
        margin_bps: 1_900,
    },
    LaneRiskProfile {
        lane: GasLane::Perps,
        bucket: "perps_liquidation",
        target_micro_price: 1_950,
        stress_micro_price: 3_250,
        privacy_floor: 128,
        margin_bps: 2_400,
    },
    LaneRiskProfile {
        lane: GasLane::TokenMintBurn,
        bucket: "token_mint_burn_standard",
        target_micro_price: 1_750,
        stress_micro_price: 2_650,
        privacy_floor: 128,
        margin_bps: 1_650,
    },
    LaneRiskProfile {
        lane: GasLane::SmartContractCall,
        bucket: "smart_contract_call_general",
        target_micro_price: 1_950,
        stress_micro_price: 3_100,
        privacy_floor: 128,
        margin_bps: 1_900,
    },
    LaneRiskProfile {
        lane: GasLane::SmartContractCall,
        bucket: "smart_contract_call_composable",
        target_micro_price: 2_150,
        stress_micro_price: 3_600,
        privacy_floor: 128,
        margin_bps: 2_200,
    },
    LaneRiskProfile {
        lane: GasLane::ProofAggregation,
        bucket: "proof_aggregation_batch",
        target_micro_price: 2_450,
        stress_micro_price: 3_900,
        privacy_floor: 96,
        margin_bps: 2_000,
    },
    LaneRiskProfile {
        lane: GasLane::WalletRecovery,
        bucket: "wallet_recovery_social",
        target_micro_price: 450,
        stress_micro_price: 850,
        privacy_floor: 160,
        margin_bps: 1_000,
    },
    LaneRiskProfile {
        lane: GasLane::EmergencyExit,
        bucket: "emergency_exit_censored",
        target_micro_price: 300,
        stress_micro_price: 700,
        privacy_floor: 128,
        margin_bps: 900,
    },
];
