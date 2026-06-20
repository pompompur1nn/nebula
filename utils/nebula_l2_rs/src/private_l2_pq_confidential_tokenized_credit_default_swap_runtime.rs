use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedCreditDefaultSwapRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-credit-default-swap-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_BUYER_SIGNATURE_SCHEME:
    &str = "ml-dsa-87+ml-kem-1024-confidential-cds-buyer-authorization-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_SELLER_SIGNATURE_SCHEME:
    &str = "ml-dsa-87+slh-dsa-shake-256f-confidential-cds-seller-margin-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_ORACLE_SCHEME: &str =
    "ml-dsa-87-threshold-default-attestation+private-reference-obligation-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_SETTLEMENT_SCHEME: &str =
    "sealed-bid-credit-event-auction+zk-confidential-cash-settlement-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_NETTING_SCHEME: &str =
    "low-fee-confidential-cds-premium-and-settlement-netting-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_PRIVACY_SCHEME: &str =
    "redacted-operator-summary+note-nullifier-privacy-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-private-l2-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEVNET_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_COLLATERAL_ASSET:
    &str = "dusd-private-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_FEE_ASSET: &str =
    "dnr-devnet-fee";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEVNET_HEIGHT: u64 =
    1_248_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MARGIN_BPS: u64 =
    1_850;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MAINTENANCE_BPS:
    u64 = 1_200;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS:
    u64 = 24;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_ORACLE_TTL_BLOCKS:
    u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_BATCH_LIMIT:
    usize = 512;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_TRANCHES: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_NOTES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_ATTESTATIONS: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_VAULTS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_AUCTIONS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_BATCHES: usize =
    524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceObligationKind {
    CorporateBond,
    SovereignBond,
    PrivateCreditLoan,
    TokenizedRwaDebt,
    StablecoinReserveClaim,
    BridgeReserveNote,
    LendingPoolDebt,
    MoneroL2FeeReceivable,
}

impl ReferenceObligationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CorporateBond => "corporate_bond",
            Self::SovereignBond => "sovereign_bond",
            Self::PrivateCreditLoan => "private_credit_loan",
            Self::TokenizedRwaDebt => "tokenized_rwa_debt",
            Self::StablecoinReserveClaim => "stablecoin_reserve_claim",
            Self::BridgeReserveNote => "bridge_reserve_note",
            Self::LendingPoolDebt => "lending_pool_debt",
            Self::MoneroL2FeeReceivable => "monero_l2_fee_receivable",
        }
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
}

impl TrancheSeniority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperSenior => "super_senior",
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::EquityFirstLoss => "equity_first_loss",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheStatus {
    Draft,
    Active,
    PremiumAccruing,
    DefaultAttested,
    AuctionOpen,
    Settling,
    Settled,
    Frozen,
    Retired,
}

impl TrancheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::PremiumAccruing => "premium_accruing",
            Self::DefaultAttested => "default_attested",
            Self::AuctionOpen => "auction_open",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_notes(self) -> bool {
        matches!(self, Self::Active | Self::PremiumAccruing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteSide {
    ProtectionBuyer,
    ProtectionSeller,
    PremiumReceiver,
    SettlementClaim,
}

impl NoteSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtectionBuyer => "protection_buyer",
            Self::ProtectionSeller => "protection_seller",
            Self::PremiumReceiver => "premium_receiver",
            Self::SettlementClaim => "settlement_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultEventKind {
    FailureToPay,
    Bankruptcy,
    Restructuring,
    ObligationAcceleration,
    ReserveImpairment,
    BridgeReserveShortfall,
    OracleCommitteeEmergency,
}

impl DefaultEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailureToPay => "failure_to_pay",
            Self::Bankruptcy => "bankruptcy",
            Self::Restructuring => "restructuring",
            Self::ObligationAcceleration => "obligation_acceleration",
            Self::ReserveImpairment => "reserve_impairment",
            Self::BridgeReserveShortfall => "bridge_reserve_shortfall",
            Self::OracleCommitteeEmergency => "oracle_committee_emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Commit,
    Reveal,
    Clearing,
    Settled,
    Cancelled,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Reveal => "reveal",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
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
    pub collateral_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub buyer_signature_scheme: String,
    pub seller_signature_scheme: String,
    pub oracle_scheme: String,
    pub settlement_scheme: String,
    pub netting_scheme: String,
    pub privacy_scheme: String,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub default_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub oracle_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub low_fee_batch_limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEVNET_L2_NETWORK
                    .to_string(),
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            collateral_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_COLLATERAL_ASSET
                    .to_string(),
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_FEE_ASSET
                    .to_string(),
            hash_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_HASH_SUITE
                    .to_string(),
            buyer_signature_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_BUYER_SIGNATURE_SCHEME
                    .to_string(),
            seller_signature_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_SELLER_SIGNATURE_SCHEME
                    .to_string(),
            oracle_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_ORACLE_SCHEME
                    .to_string(),
            settlement_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_SETTLEMENT_SCHEME
                    .to_string(),
            netting_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_NETTING_SCHEME
                    .to_string(),
            privacy_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_PRIVACY_SCHEME
                    .to_string(),
            min_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            default_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_MAINTENANCE_BPS,
            oracle_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_ORACLE_TTL_BLOCKS,
            auction_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS,
            low_fee_batch_limit:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEFAULT_BATCH_LIMIT,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub tranches_registered: u64,
    pub premium_notes_minted: u64,
    pub default_attestations_accepted: u64,
    pub seller_margin_locked: u64,
    pub settlement_auctions_opened: u64,
    pub low_fee_batches_cleared: u64,
    pub privacy_redactions_published: u64,
    pub public_summaries_published: u64,
    pub notional_protected: u64,
    pub premium_notional: u64,
    pub settlement_notional: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub tranche_root: String,
    pub note_root: String,
    pub reference_obligation_root: String,
    pub default_attestation_root: String,
    pub margin_vault_root: String,
    pub auction_root: String,
    pub batch_netting_root: String,
    pub privacy_redaction_root: String,
    pub nullifier_root: String,
    pub public_summary_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterTrancheRequest {
    pub tranche_id: String,
    pub reference_obligation_id: String,
    pub reference_kind: ReferenceObligationKind,
    pub seniority: TrancheSeniority,
    pub confidential_buyer_set_root: String,
    pub confidential_seller_set_root: String,
    pub attachment_point_bps: u64,
    pub detachment_point_bps: u64,
    pub premium_bps: u64,
    pub max_notional: u64,
    pub maturity_height: u64,
    pub pq_operator_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MintPremiumNoteRequest {
    pub note_id: String,
    pub tranche_id: String,
    pub owner_commitment: String,
    pub side: NoteSide,
    pub notional_commitment: String,
    pub premium_commitment: String,
    pub notional: u64,
    pub premium_due: u64,
    pub seller_margin_commitment: String,
    pub buyer_pq_signature_commitment: String,
    pub seller_pq_signature_commitment: String,
    pub note_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DefaultAttestationRequest {
    pub attestation_id: String,
    pub tranche_id: String,
    pub event_kind: DefaultEventKind,
    pub event_height: u64,
    pub reference_price_bps: u64,
    pub loss_bps: u64,
    pub oracle_committee_id: String,
    pub oracle_default_root: String,
    pub pq_attestation_signature_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarginVaultRequest {
    pub vault_id: String,
    pub tranche_id: String,
    pub seller_commitment: String,
    pub collateral_commitment: String,
    pub locked_amount: u64,
    pub maintenance_amount: u64,
    pub pq_seller_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementAuctionRequest {
    pub auction_id: String,
    pub tranche_id: String,
    pub attestation_id: String,
    pub sealed_bid_root: String,
    pub deliverable_obligation_root: String,
    pub recovery_price_bps: u64,
    pub clearing_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchNettingRequest {
    pub batch_id: String,
    pub height: u64,
    pub tranche_ids: Vec<String>,
    pub premium_note_ids: Vec<String>,
    pub net_premium_amount: u64,
    pub net_settlement_amount: u64,
    pub fee_rebate_bps: u64,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrancheRecord {
    pub tranche_id: String,
    pub reference_obligation_id: String,
    pub reference_kind: ReferenceObligationKind,
    pub seniority: TrancheSeniority,
    pub status: TrancheStatus,
    pub confidential_buyer_set_root: String,
    pub confidential_seller_set_root: String,
    pub reference_obligation_root: String,
    pub attachment_point_bps: u64,
    pub detachment_point_bps: u64,
    pub premium_bps: u64,
    pub max_notional: u64,
    pub open_notional: u64,
    pub protected_notional: u64,
    pub maturity_height: u64,
    pub created_height: u64,
    pub pq_operator_signature_commitment: String,
}

impl TrancheRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "reference_kind": self.reference_kind.as_str(),
            "seniority": self.seniority.as_str(),
            "status": self.status.as_str(),
            "reference_obligation_root": self.reference_obligation_root,
            "attachment_point_bps": self.attachment_point_bps,
            "detachment_point_bps": self.detachment_point_bps,
            "premium_bps": self.premium_bps,
            "max_notional": self.max_notional,
            "open_notional": self.open_notional,
            "protected_notional": self.protected_notional,
            "maturity_height": self.maturity_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PremiumNoteRecord {
    pub note_id: String,
    pub tranche_id: String,
    pub owner_commitment: String,
    pub side: NoteSide,
    pub notional_commitment: String,
    pub premium_commitment: String,
    pub notional: u64,
    pub premium_due: u64,
    pub seller_margin_commitment: String,
    pub buyer_pq_signature_commitment: String,
    pub seller_pq_signature_commitment: String,
    pub note_nullifier: String,
    pub minted_height: u64,
    pub settled: bool,
}

impl PremiumNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "tranche_id": self.tranche_id,
            "side": self.side.as_str(),
            "notional_commitment": self.notional_commitment,
            "premium_commitment": self.premium_commitment,
            "seller_margin_commitment": self.seller_margin_commitment,
            "minted_height": self.minted_height,
            "settled": self.settled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DefaultAttestationRecord {
    pub attestation_id: String,
    pub tranche_id: String,
    pub event_kind: DefaultEventKind,
    pub event_height: u64,
    pub reference_price_bps: u64,
    pub loss_bps: u64,
    pub oracle_committee_id: String,
    pub oracle_default_root: String,
    pub pq_attestation_signature_root: String,
    pub accepted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarginVaultRecord {
    pub vault_id: String,
    pub tranche_id: String,
    pub seller_commitment: String,
    pub collateral_commitment: String,
    pub locked_amount: u64,
    pub maintenance_amount: u64,
    pub pq_seller_signature_commitment: String,
    pub healthy: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementAuctionRecord {
    pub auction_id: String,
    pub tranche_id: String,
    pub attestation_id: String,
    pub sealed_bid_root: String,
    pub deliverable_obligation_root: String,
    pub recovery_price_bps: u64,
    pub clearing_height: u64,
    pub status: AuctionStatus,
    pub settled_notional: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchNettingRecord {
    pub batch_id: String,
    pub height: u64,
    pub tranche_ids: Vec<String>,
    pub premium_note_ids: Vec<String>,
    pub net_premium_amount: u64,
    pub net_settlement_amount: u64,
    pub fee_rebate_bps: u64,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionRecord {
    pub redaction_id: String,
    pub height: u64,
    pub domain: String,
    pub redacted_subject_root: String,
    pub retained_fields: Vec<String>,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicSummaryRecord {
    pub summary_id: String,
    pub height: u64,
    pub active_tranches: u64,
    pub protected_notional: u64,
    pub open_premium_notes: u64,
    pub default_attestations: u64,
    pub auctioned_settlement_notional: u64,
    pub low_fee_batches: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub tranches: BTreeMap<String, TrancheRecord>,
    pub premium_notes: BTreeMap<String, PremiumNoteRecord>,
    pub reference_obligations: BTreeMap<String, Value>,
    pub default_attestations: BTreeMap<String, DefaultAttestationRecord>,
    pub margin_vaults: BTreeMap<String, MarginVaultRecord>,
    pub settlement_auctions: BTreeMap<String, SettlementAuctionRecord>,
    pub batch_nettings: BTreeMap<String, BatchNettingRecord>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedactionRecord>,
    pub public_summaries: BTreeMap<String, PublicSummaryRecord>,
    pub seen_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            height: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_DEVNET_HEIGHT,
            tranches: BTreeMap::new(),
            premium_notes: BTreeMap::new(),
            reference_obligations: BTreeMap::new(),
            default_attestations: BTreeMap::new(),
            margin_vaults: BTreeMap::new(),
            settlement_auctions: BTreeMap::new(),
            batch_nettings: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn register_tranche(&mut self, request: RegisterTrancheRequest) -> Result<Value> {
        self.ensure_id("tranche_id", &request.tranche_id)?;
        self.ensure_id("reference_obligation_id", &request.reference_obligation_id)?;
        self.ensure_capacity(
            self.tranches.len(),
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_TRANCHES,
            "tranches",
        )?;
        self.ensure_bps("attachment_point_bps", request.attachment_point_bps)?;
        self.ensure_bps("detachment_point_bps", request.detachment_point_bps)?;
        self.ensure_bps("premium_bps", request.premium_bps)?;
        if request.attachment_point_bps >= request.detachment_point_bps {
            return Err("attachment point must be below detachment point".to_string());
        }
        if self.tranches.contains_key(&request.tranche_id) {
            return Err("tranche already exists".to_string());
        }
        let reference_record = json!({
            "reference_obligation_id": request.reference_obligation_id,
            "reference_kind": request.reference_kind.as_str(),
            "confidential_buyer_set_root": request.confidential_buyer_set_root,
            "confidential_seller_set_root": request.confidential_seller_set_root,
            "maturity_height": request.maturity_height,
        });
        let reference_obligation_root = domain_hash(
            "private-cds-reference-obligation",
            &[HashPart::Json(&reference_record)],
            32,
        );
        self.reference_obligations
            .insert(request.reference_obligation_id.clone(), reference_record);
        let record = TrancheRecord {
            tranche_id: request.tranche_id.clone(),
            reference_obligation_id: request.reference_obligation_id,
            reference_kind: request.reference_kind,
            seniority: request.seniority,
            status: TrancheStatus::Active,
            confidential_buyer_set_root: request.confidential_buyer_set_root,
            confidential_seller_set_root: request.confidential_seller_set_root,
            reference_obligation_root,
            attachment_point_bps: request.attachment_point_bps,
            detachment_point_bps: request.detachment_point_bps,
            premium_bps: request.premium_bps,
            max_notional: request.max_notional,
            open_notional: 0,
            protected_notional: 0,
            maturity_height: request.maturity_height,
            created_height: self.height,
            pq_operator_signature_commitment: request.pq_operator_signature_commitment,
        };
        let public = record.public_record();
        self.tranches.insert(request.tranche_id, record);
        self.counters.tranches_registered = self.counters.tranches_registered.saturating_add(1);
        self.refresh_roots();
        Ok(public)
    }

    pub fn mint_premium_note(&mut self, request: MintPremiumNoteRequest) -> Result<Value> {
        self.ensure_id("note_id", &request.note_id)?;
        self.ensure_id("tranche_id", &request.tranche_id)?;
        self.ensure_capacity(
            self.premium_notes.len(),
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_NOTES,
            "premium_notes",
        )?;
        if self.premium_notes.contains_key(&request.note_id) {
            return Err("premium note already exists".to_string());
        }
        if self.seen_nullifiers.contains(&request.note_nullifier) {
            return Err("note nullifier already spent".to_string());
        }
        let tranche = self
            .tranches
            .get_mut(&request.tranche_id)
            .ok_or_else(|| "unknown tranche".to_string())?;
        if !tranche.status.accepts_notes() {
            return Err("tranche does not accept new premium notes".to_string());
        }
        let new_open = tranche.open_notional.saturating_add(request.notional);
        if new_open > tranche.max_notional {
            return Err("tranche max notional exceeded".to_string());
        }
        tranche.open_notional = new_open;
        tranche.protected_notional = tranche.protected_notional.saturating_add(request.notional);
        tranche.status = TrancheStatus::PremiumAccruing;
        let record = PremiumNoteRecord {
            note_id: request.note_id.clone(),
            tranche_id: request.tranche_id,
            owner_commitment: request.owner_commitment,
            side: request.side,
            notional_commitment: request.notional_commitment,
            premium_commitment: request.premium_commitment,
            notional: request.notional,
            premium_due: request.premium_due,
            seller_margin_commitment: request.seller_margin_commitment,
            buyer_pq_signature_commitment: request.buyer_pq_signature_commitment,
            seller_pq_signature_commitment: request.seller_pq_signature_commitment,
            note_nullifier: request.note_nullifier.clone(),
            minted_height: self.height,
            settled: false,
        };
        let public = record.public_record();
        self.seen_nullifiers.insert(request.note_nullifier);
        self.counters.premium_notes_minted = self.counters.premium_notes_minted.saturating_add(1);
        self.counters.notional_protected = self
            .counters
            .notional_protected
            .saturating_add(request.notional);
        self.counters.premium_notional = self
            .counters
            .premium_notional
            .saturating_add(request.premium_due);
        self.premium_notes.insert(request.note_id, record);
        self.refresh_roots();
        Ok(public)
    }

    pub fn lock_margin_vault(&mut self, request: MarginVaultRequest) -> Result<Value> {
        self.ensure_id("vault_id", &request.vault_id)?;
        self.ensure_id("tranche_id", &request.tranche_id)?;
        self.ensure_capacity(
            self.margin_vaults.len(),
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_VAULTS,
            "margin_vaults",
        )?;
        if !self.tranches.contains_key(&request.tranche_id) {
            return Err("unknown tranche".to_string());
        }
        let healthy = request.locked_amount >= request.maintenance_amount;
        let record = MarginVaultRecord {
            vault_id: request.vault_id.clone(),
            tranche_id: request.tranche_id,
            seller_commitment: request.seller_commitment,
            collateral_commitment: request.collateral_commitment,
            locked_amount: request.locked_amount,
            maintenance_amount: request.maintenance_amount,
            pq_seller_signature_commitment: request.pq_seller_signature_commitment,
            healthy,
        };
        self.counters.seller_margin_locked = self
            .counters
            .seller_margin_locked
            .saturating_add(request.locked_amount);
        self.margin_vaults.insert(request.vault_id, record.clone());
        self.refresh_roots();
        Ok(
            json!({"vault_id": record.vault_id, "tranche_id": record.tranche_id, "healthy": healthy}),
        )
    }

    pub fn attest_default(&mut self, request: DefaultAttestationRequest) -> Result<Value> {
        self.ensure_id("attestation_id", &request.attestation_id)?;
        self.ensure_id("tranche_id", &request.tranche_id)?;
        self.ensure_capacity(
            self.default_attestations.len(),
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_ATTESTATIONS,
            "default_attestations",
        )?;
        self.ensure_bps("reference_price_bps", request.reference_price_bps)?;
        self.ensure_bps("loss_bps", request.loss_bps)?;
        let tranche = self
            .tranches
            .get_mut(&request.tranche_id)
            .ok_or_else(|| "unknown tranche".to_string())?;
        if self.height.saturating_sub(request.event_height) > self.config.oracle_ttl_blocks {
            return Err("default attestation is stale".to_string());
        }
        tranche.status = TrancheStatus::DefaultAttested;
        let record = DefaultAttestationRecord {
            attestation_id: request.attestation_id.clone(),
            tranche_id: request.tranche_id,
            event_kind: request.event_kind,
            event_height: request.event_height,
            reference_price_bps: request.reference_price_bps,
            loss_bps: request.loss_bps,
            oracle_committee_id: request.oracle_committee_id,
            oracle_default_root: request.oracle_default_root,
            pq_attestation_signature_root: request.pq_attestation_signature_root,
            accepted_height: self.height,
        };
        self.default_attestations
            .insert(request.attestation_id, record.clone());
        self.counters.default_attestations_accepted = self
            .counters
            .default_attestations_accepted
            .saturating_add(1);
        self.refresh_roots();
        Ok(json!({
            "attestation_id": record.attestation_id,
            "tranche_id": record.tranche_id,
            "event_kind": record.event_kind.as_str(),
            "loss_bps": record.loss_bps,
            "oracle_default_root": record.oracle_default_root,
        }))
    }

    pub fn open_settlement_auction(&mut self, request: SettlementAuctionRequest) -> Result<Value> {
        self.ensure_id("auction_id", &request.auction_id)?;
        self.ensure_id("tranche_id", &request.tranche_id)?;
        self.ensure_id("attestation_id", &request.attestation_id)?;
        self.ensure_capacity(
            self.settlement_auctions.len(),
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_AUCTIONS,
            "settlement_auctions",
        )?;
        self.ensure_bps("recovery_price_bps", request.recovery_price_bps)?;
        if !self
            .default_attestations
            .contains_key(&request.attestation_id)
        {
            return Err("unknown default attestation".to_string());
        }
        let tranche = self
            .tranches
            .get_mut(&request.tranche_id)
            .ok_or_else(|| "unknown tranche".to_string())?;
        tranche.status = TrancheStatus::AuctionOpen;
        let settled_notional = tranche.protected_notional.saturating_mul(
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_BPS
                .saturating_sub(request.recovery_price_bps),
        )
            / PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_BPS;
        let record = SettlementAuctionRecord {
            auction_id: request.auction_id.clone(),
            tranche_id: request.tranche_id,
            attestation_id: request.attestation_id,
            sealed_bid_root: request.sealed_bid_root,
            deliverable_obligation_root: request.deliverable_obligation_root,
            recovery_price_bps: request.recovery_price_bps,
            clearing_height: request.clearing_height,
            status: AuctionStatus::Commit,
            settled_notional,
        };
        self.counters.settlement_auctions_opened =
            self.counters.settlement_auctions_opened.saturating_add(1);
        self.counters.settlement_notional = self
            .counters
            .settlement_notional
            .saturating_add(settled_notional);
        self.settlement_auctions
            .insert(request.auction_id, record.clone());
        self.refresh_roots();
        Ok(json!({
            "auction_id": record.auction_id,
            "tranche_id": record.tranche_id,
            "status": record.status.as_str(),
            "recovery_price_bps": record.recovery_price_bps,
            "settled_notional": record.settled_notional,
        }))
    }

    pub fn clear_low_fee_batch(&mut self, request: BatchNettingRequest) -> Result<Value> {
        self.ensure_id("batch_id", &request.batch_id)?;
        self.ensure_capacity(
            self.batch_nettings.len(),
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_BATCHES,
            "batch_nettings",
        )?;
        self.ensure_bps("fee_rebate_bps", request.fee_rebate_bps)?;
        if request.premium_note_ids.len() > self.config.low_fee_batch_limit {
            return Err("low-fee batch limit exceeded".to_string());
        }
        for note_id in &request.premium_note_ids {
            if let Some(note) = self.premium_notes.get_mut(note_id) {
                note.settled = true;
            }
        }
        let record = BatchNettingRecord {
            batch_id: request.batch_id.clone(),
            height: request.height,
            tranche_ids: request.tranche_ids,
            premium_note_ids: request.premium_note_ids,
            net_premium_amount: request.net_premium_amount,
            net_settlement_amount: request.net_settlement_amount,
            fee_rebate_bps: request.fee_rebate_bps,
            proof_root: request.proof_root,
        };
        self.counters.low_fee_batches_cleared =
            self.counters.low_fee_batches_cleared.saturating_add(1);
        self.batch_nettings.insert(request.batch_id, record.clone());
        self.refresh_roots();
        Ok(json!({
            "batch_id": record.batch_id,
            "notes": record.premium_note_ids.len(),
            "net_premium_amount": record.net_premium_amount,
            "net_settlement_amount": record.net_settlement_amount,
            "fee_rebate_bps": record.fee_rebate_bps,
        }))
    }

    pub fn publish_privacy_redaction(
        &mut self,
        redaction_id: String,
        domain: String,
        redacted_subject_root: String,
        retained_fields: Vec<String>,
        privacy_set_size: u64,
    ) -> Result<Value> {
        self.ensure_id("redaction_id", &redaction_id)?;
        if privacy_set_size < self.config.min_privacy_set {
            return Err("privacy set below configured minimum".to_string());
        }
        let record = PrivacyRedactionRecord {
            redaction_id: redaction_id.clone(),
            height: self.height,
            domain,
            redacted_subject_root,
            retained_fields,
            privacy_set_size,
        };
        self.privacy_redactions.insert(redaction_id, record.clone());
        self.counters.privacy_redactions_published =
            self.counters.privacy_redactions_published.saturating_add(1);
        self.refresh_roots();
        Ok(json!({
            "redaction_id": record.redaction_id,
            "domain": record.domain,
            "redacted_subject_root": record.redacted_subject_root,
            "privacy_set_size": record.privacy_set_size,
        }))
    }

    pub fn publish_public_summary(&mut self, summary_id: String) -> Result<Value> {
        self.ensure_id("summary_id", &summary_id)?;
        let active_tranches = self
            .tranches
            .values()
            .filter(|tranche| tranche.status != TrancheStatus::Retired)
            .count() as u64;
        let open_premium_notes = self
            .premium_notes
            .values()
            .filter(|note| !note.settled)
            .count() as u64;
        let record = PublicSummaryRecord {
            summary_id: summary_id.clone(),
            height: self.height,
            active_tranches,
            protected_notional: self.counters.notional_protected,
            open_premium_notes,
            default_attestations: self.default_attestations.len() as u64,
            auctioned_settlement_notional: self.counters.settlement_notional,
            low_fee_batches: self.counters.low_fee_batches_cleared,
            state_root: self.state_root(),
        };
        self.public_summaries.insert(summary_id, record.clone());
        self.counters.public_summaries_published =
            self.counters.public_summaries_published.saturating_add(1);
        self.refresh_roots();
        Ok(public_record_from_summary(&record))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "collateral_asset_id": self.config.collateral_asset_id,
            "fee_asset_id": self.config.fee_asset_id,
            "height": self.height,
            "tranches": self.tranches.len(),
            "premium_notes": self.premium_notes.len(),
            "reference_obligations": self.reference_obligations.len(),
            "default_attestations": self.default_attestations.len(),
            "margin_vaults": self.margin_vaults.len(),
            "settlement_auctions": self.settlement_auctions.len(),
            "batch_nettings": self.batch_nettings.len(),
            "privacy_redactions": self.privacy_redactions.len(),
            "public_summaries": self.public_summaries.len(),
            "counters": self.counters,
            "roots": self.roots,
            "operator_safe_summary": self.operator_safe_summary(),
        })
    }

    pub fn state_root(&self) -> String {
        let parts = vec![
            HashPart::Str(&self.config.protocol_version),
            HashPart::U64(self.height),
            HashPart::Str(&self.roots.tranche_root),
            HashPart::Str(&self.roots.note_root),
            HashPart::Str(&self.roots.reference_obligation_root),
            HashPart::Str(&self.roots.default_attestation_root),
            HashPart::Str(&self.roots.margin_vault_root),
            HashPart::Str(&self.roots.auction_root),
            HashPart::Str(&self.roots.batch_netting_root),
            HashPart::Str(&self.roots.privacy_redaction_root),
            HashPart::Str(&self.roots.nullifier_root),
            HashPart::Str(&self.roots.public_summary_root),
        ];
        domain_hash("private-l2-pq-confidential-tokenized-cds-state", &parts, 32)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.tranche_root = map_root("cds_tranches", &self.tranches);
        self.roots.note_root = map_root("cds_premium_notes", &self.premium_notes);
        self.roots.reference_obligation_root =
            map_root("cds_reference_obligations", &self.reference_obligations);
        self.roots.default_attestation_root =
            map_root("cds_default_attestations", &self.default_attestations);
        self.roots.margin_vault_root = map_root("cds_margin_vaults", &self.margin_vaults);
        self.roots.auction_root = map_root("cds_settlement_auctions", &self.settlement_auctions);
        self.roots.batch_netting_root = map_root("cds_batch_nettings", &self.batch_nettings);
        self.roots.privacy_redaction_root =
            map_root("cds_privacy_redactions", &self.privacy_redactions);
        self.roots.nullifier_root = set_root("cds_note_nullifiers", &self.seen_nullifiers);
        self.roots.public_summary_root = map_root("cds_public_summaries", &self.public_summaries);
        self.roots.state_root = self.state_root();
    }

    pub fn operator_safe_summary(&self) -> Value {
        let open_notional = self.tranches.values().fold(0_u64, |acc, tranche| {
            acc.saturating_add(tranche.open_notional)
        });
        let unhealthy_vaults = self
            .margin_vaults
            .values()
            .filter(|vault| !vault.healthy)
            .count();
        json!({
            "active_tranches": self.tranches.len(),
            "open_notional": open_notional,
            "protected_notional": self.counters.notional_protected,
            "default_attestations": self.default_attestations.len(),
            "unhealthy_margin_vaults": unhealthy_vaults,
            "low_fee_batches": self.counters.low_fee_batches_cleared,
            "state_root": self.roots.state_root,
        })
    }

    fn ensure_id(&self, label: &str, value: &str) -> Result<()> {
        if value.trim().is_empty() {
            return Err(format!("{} must not be empty", label));
        }
        Ok(())
    }

    fn ensure_bps(&self, label: &str, value: u64) -> Result<()> {
        if value > PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CREDIT_DEFAULT_SWAP_RUNTIME_MAX_BPS {
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
}

pub fn public_record_from_summary(record: &PublicSummaryRecord) -> Value {
    json!({
        "summary_id": record.summary_id,
        "height": record.height,
        "active_tranches": record.active_tranches,
        "protected_notional": record.protected_notional,
        "open_premium_notes": record.open_premium_notes,
        "default_attestations": record.default_attestations,
        "auctioned_settlement_notional": record.auctioned_settlement_notional,
        "low_fee_batches": record.low_fee_batches,
        "state_root": record.state_root,
    })
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

pub fn devnet() -> State {
    let mut state = State::default();
    let _ = state.register_tranche(RegisterTrancheRequest {
        tranche_id: "cds-tranche-devnet-senior-xmr-credit-001".to_string(),
        reference_obligation_id: "ref-obligation-private-credit-xmr-001".to_string(),
        reference_kind: ReferenceObligationKind::PrivateCreditLoan,
        seniority: TrancheSeniority::Senior,
        confidential_buyer_set_root: domain_hash(
            "devnet-cds-buyer-set",
            &[HashPart::Str("buyers-alpha")],
            32,
        ),
        confidential_seller_set_root: domain_hash(
            "devnet-cds-seller-set",
            &[HashPart::Str("sellers-alpha")],
            32,
        ),
        attachment_point_bps: 1_000,
        detachment_point_bps: 3_500,
        premium_bps: 180,
        max_notional: 75_000_000_000,
        maturity_height: state.height + 43_200,
        pq_operator_signature_commitment: "pq-op-sig-cds-tranche-alpha".to_string(),
    });
    let _ = state.lock_margin_vault(MarginVaultRequest {
        vault_id: "margin-vault-cds-seller-alpha".to_string(),
        tranche_id: "cds-tranche-devnet-senior-xmr-credit-001".to_string(),
        seller_commitment: "seller-commitment-alpha-redacted".to_string(),
        collateral_commitment: "collateral-commitment-alpha-dusd".to_string(),
        locked_amount: 18_750_000_000,
        maintenance_amount: 12_000_000_000,
        pq_seller_signature_commitment: "pq-seller-margin-sig-alpha".to_string(),
    });
    let _ = state.mint_premium_note(MintPremiumNoteRequest {
        note_id: "premium-note-cds-alpha-0001".to_string(),
        tranche_id: "cds-tranche-devnet-senior-xmr-credit-001".to_string(),
        owner_commitment: "note-owner-stealth-commitment-alpha".to_string(),
        side: NoteSide::ProtectionBuyer,
        notional_commitment: "note-notional-commitment-alpha".to_string(),
        premium_commitment: "note-premium-commitment-alpha".to_string(),
        notional: 12_500_000_000,
        premium_due: 225_000_000,
        seller_margin_commitment: "seller-margin-note-alpha".to_string(),
        buyer_pq_signature_commitment: "pq-buyer-sig-alpha".to_string(),
        seller_pq_signature_commitment: "pq-seller-sig-alpha".to_string(),
        note_nullifier: "note-nullifier-alpha-0001".to_string(),
    });
    let _ = state.publish_privacy_redaction(
        "redaction-cds-devnet-alpha".to_string(),
        "premium_note_owner_and_amounts".to_string(),
        domain_hash(
            "devnet-cds-redacted-note",
            &[HashPart::Str("premium-note-cds-alpha-0001")],
            32,
        ),
        vec![
            "note_id".to_string(),
            "tranche_id".to_string(),
            "commitment_roots".to_string(),
        ],
        state.config.min_privacy_set,
    );
    let _ = state.publish_public_summary("summary-cds-devnet-genesis".to_string());
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.attest_default(DefaultAttestationRequest {
        attestation_id: "default-attestation-cds-alpha".to_string(),
        tranche_id: "cds-tranche-devnet-senior-xmr-credit-001".to_string(),
        event_kind: DefaultEventKind::FailureToPay,
        event_height: state.height.saturating_sub(3),
        reference_price_bps: 6_800,
        loss_bps: 3_200,
        oracle_committee_id: "private-cds-default-oracle-committee-devnet".to_string(),
        oracle_default_root: domain_hash(
            "devnet-cds-default-root",
            &[HashPart::Str("failure-to-pay-alpha")],
            32,
        ),
        pq_attestation_signature_root: "pq-default-attestation-root-alpha".to_string(),
    });
    let _ = state.open_settlement_auction(SettlementAuctionRequest {
        auction_id: "settlement-auction-cds-alpha".to_string(),
        tranche_id: "cds-tranche-devnet-senior-xmr-credit-001".to_string(),
        attestation_id: "default-attestation-cds-alpha".to_string(),
        sealed_bid_root: "sealed-bid-root-alpha".to_string(),
        deliverable_obligation_root: "deliverable-obligation-root-alpha".to_string(),
        recovery_price_bps: 6_750,
        clearing_height: state.height + state.config.auction_ttl_blocks,
    });
    let _ = state.clear_low_fee_batch(BatchNettingRequest {
        batch_id: "low-fee-netting-batch-cds-alpha".to_string(),
        height: state.height + 1,
        tranche_ids: vec!["cds-tranche-devnet-senior-xmr-credit-001".to_string()],
        premium_note_ids: vec!["premium-note-cds-alpha-0001".to_string()],
        net_premium_amount: 225_000_000,
        net_settlement_amount: 4_062_500_000,
        fee_rebate_bps: 12,
        proof_root: "low-fee-cds-batch-proof-root-alpha".to_string(),
    });
    let _ = state.publish_public_summary("summary-cds-demo-after-default".to_string());
    state.refresh_roots();
    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn state_root_of(state: &State) -> String {
    state.state_root()
}
