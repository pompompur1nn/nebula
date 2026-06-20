use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2ConfidentialCrossMarginNettingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_CONFIDENTIAL_CROSS_MARGIN_NETTING_RUNTIME_PROTOCOL_VERSION: &str =
    "private-l2-confidential-cross-margin-netting-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_CONFIDENTIAL_CROSS_MARGIN_NETTING_RUNTIME_PROTOCOL_VERSION;
pub const CHAIN_ID: &str = "nebula-l2-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const MAX_ACCOUNTS: usize = 512;
pub const MAX_POSITIONS: usize = 4096;
pub const MAX_INTENTS: usize = 8192;
pub const MAX_CYCLES: usize = 2048;
pub const MAX_EVENTS: usize = 8192;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MarginVenue {
    ConfidentialPerps,
    DarkpoolSpot,
    SyntheticVault,
    OptionsVault,
    LendingPool,
}

impl MarginVenue {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfidentialPerps => "confidential_perps",
            Self::DarkpoolSpot => "darkpool_spot",
            Self::SyntheticVault => "synthetic_vault",
            Self::OptionsVault => "options_vault",
            Self::LendingPool => "lending_pool",
        }
    }

    pub fn default_margin_bps(&self) -> u64 {
        match self {
            Self::ConfidentialPerps => 1250,
            Self::DarkpoolSpot => 700,
            Self::SyntheticVault => 1100,
            Self::OptionsVault => 1600,
            Self::LendingPool => 900,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountStatus {
    Opening,
    Active,
    NettingOnly,
    Frozen,
    Closed,
}

impl AccountStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::NettingOnly => "netting_only",
            Self::Frozen => "frozen",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PositionKind {
    Long,
    Short,
    Borrow,
    Lend,
    OptionWriter,
    OptionHolder,
}

impl PositionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
            Self::Borrow => "borrow",
            Self::Lend => "lend",
            Self::OptionWriter => "option_writer",
            Self::OptionHolder => "option_holder",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PositionStatus {
    Pending,
    Open,
    Netting,
    Offset,
    Settled,
    LiquidationOnly,
}

impl PositionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Netting => "netting",
            Self::Offset => "offset",
            Self::Settled => "settled",
            Self::LiquidationOnly => "liquidation_only",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntentStatus {
    Pending,
    Admitted,
    Batched,
    Matched,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Admitted => "admitted",
            Self::Batched => "batched",
            Self::Matched => "matched",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NettingCycleStatus {
    Building,
    RiskChecked,
    Settling,
    Settled,
    Challenged,
    Reverted,
}

impl NettingCycleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::RiskChecked => "risk_checked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Rejected,
    Disputed,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SponsorStatus {
    Reserved,
    Consumed,
    Released,
    Slashed,
}

impl SponsorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptKind {
    AccountOpened,
    PositionOpened,
    IntentMatched,
    CycleSettled,
    RebateIssued,
    ChallengeRecorded,
}

impl ReceiptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountOpened => "account_opened",
            Self::PositionOpened => "position_opened",
            Self::IntentMatched => "intent_matched",
            Self::CycleSettled => "cycle_settled",
            Self::RebateIssued => "rebate_issued",
            Self::ChallengeRecorded => "challenge_recorded",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FenceKind {
    AccountNullifier,
    PositionReplay,
    IntentReplay,
    CycleWitness,
    SponsorCoupon,
}

impl FenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountNullifier => "account_nullifier",
            Self::PositionReplay => "position_replay",
            Self::IntentReplay => "intent_replay",
            Self::CycleWitness => "cycle_witness",
            Self::SponsorCoupon => "sponsor_coupon",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingReason {
    InvalidRiskRoot,
    BadPqSignature,
    DoubleNetting,
    WithheldSettlement,
    SponsorOvercharge,
}

impl SlashingReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRiskRoot => "invalid_risk_root",
            Self::BadPqSignature => "bad_pq_signature",
            Self::DoubleNetting => "double_netting",
            Self::WithheldSettlement => "withheld_settlement",
            Self::SponsorOvercharge => "sponsor_overcharge",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub max_accounts: usize,
    pub max_positions: usize,
    pub max_intents: usize,
    pub max_positions_per_cycle: usize,
    pub min_privacy_set_size: u64,
    pub target_fee_bps: u64,
    pub max_fee_bps: u64,
    pub liquidation_margin_bps: u64,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub require_pq_attestation: bool,
    pub sponsor_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            max_accounts: MAX_ACCOUNTS,
            max_positions: MAX_POSITIONS,
            max_intents: MAX_INTENTS,
            max_positions_per_cycle: 96,
            min_privacy_set_size: 64,
            target_fee_bps: 18,
            max_fee_bps: 65,
            liquidation_margin_bps: 525,
            pq_signature_scheme: "ML-DSA-87/Falcon-1024 hybrid".to_string(),
            pq_kem_scheme: "ML-KEM-1024".to_string(),
            require_pq_attestation: true,
            sponsor_rebate_bps: 40,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        require_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        require_bps("target_fee_bps", self.target_fee_bps)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require_bps("liquidation_margin_bps", self.liquidation_margin_bps)?;
        require_bps("sponsor_rebate_bps", self.sponsor_rebate_bps)?;
        if self.target_fee_bps > self.max_fee_bps {
            return Err("target_fee_bps must be <= max_fee_bps".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "max_accounts": self.max_accounts,
            "max_positions": self.max_positions,
            "max_intents": self.max_intents,
            "max_positions_per_cycle": self.max_positions_per_cycle,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_fee_bps": self.target_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "liquidation_margin_bps": self.liquidation_margin_bps,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "require_pq_attestation": self.require_pq_attestation,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub accounts_opened: u64,
    pub positions_opened: u64,
    pub intents_submitted: u64,
    pub cycles_built: u64,
    pub attestations_recorded: u64,
    pub sponsor_reservations: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub privacy_fences_opened: u64,
    pub slashing_events: u64,
    pub runtime_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "accounts_opened": self.accounts_opened,
            "positions_opened": self.positions_opened,
            "intents_submitted": self.intents_submitted,
            "cycles_built": self.cycles_built,
            "attestations_recorded": self.attestations_recorded,
            "sponsor_reservations": self.sponsor_reservations,
            "receipts_published": self.receipts_published,
            "rebates_issued": self.rebates_issued,
            "privacy_fences_opened": self.privacy_fences_opened,
            "slashing_events": self.slashing_events,
            "runtime_events": self.runtime_events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub accounts_root: String,
    pub positions_root: String,
    pub intents_root: String,
    pub cycles_root: String,
    pub attestations_root: String,
    pub sponsors_root: String,
    pub receipts_root: String,
    pub rebates_root: String,
    pub fences_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            accounts_root: empty_root("accounts"),
            positions_root: empty_root("positions"),
            intents_root: empty_root("intents"),
            cycles_root: empty_root("cycles"),
            attestations_root: empty_root("attestations"),
            sponsors_root: empty_root("sponsors"),
            receipts_root: empty_root("receipts"),
            rebates_root: empty_root("rebates"),
            fences_root: empty_root("fences"),
            slashing_root: empty_root("slashing"),
            nullifier_root: empty_root("nullifiers"),
            events_root: empty_root("events"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accounts_root": self.accounts_root,
            "positions_root": self.positions_root,
            "intents_root": self.intents_root,
            "cycles_root": self.cycles_root,
            "attestations_root": self.attestations_root,
            "sponsors_root": self.sponsors_root,
            "receipts_root": self.receipts_root,
            "rebates_root": self.rebates_root,
            "fences_root": self.fences_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenMarginAccountRequest {
    pub owner_commitment: String,
    pub venue: MarginVenue,
    pub collateral_note_root: String,
    pub viewing_policy_root: String,
    pub pq_public_key_root: String,
    pub account_nullifier: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarginAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub venue: MarginVenue,
    pub status: AccountStatus,
    pub collateral_note_root: String,
    pub viewing_policy_root: String,
    pub pq_public_key_root: String,
    pub account_nullifier: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl MarginAccount {
    pub fn from_request(request: OpenMarginAccountRequest) -> Self {
        let account_id = margin_account_id(&request);
        Self {
            account_id,
            owner_commitment: request.owner_commitment,
            venue: request.venue,
            status: AccountStatus::Active,
            collateral_note_root: request.collateral_note_root,
            viewing_policy_root: request.viewing_policy_root,
            pq_public_key_root: request.pq_public_key_root,
            account_nullifier: request.account_nullifier,
            privacy_set_size: request.privacy_set_size,
            opened_at_height: request.opened_at_height,
            updated_at_height: request.opened_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "venue": self.venue.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "collateral_note_root": self.collateral_note_root,
            "viewing_policy_root": self.viewing_policy_root,
            "pq_public_key_root": self.pq_public_key_root,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenPositionRequest {
    pub account_id: String,
    pub venue: MarginVenue,
    pub position_kind: PositionKind,
    pub asset_commitment: String,
    pub notional_commitment: String,
    pub collateral_commitment: String,
    pub leverage_bps: u64,
    pub margin_bps: u64,
    pub entry_price_root: String,
    pub position_nullifier: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarginPosition {
    pub position_id: String,
    pub account_id: String,
    pub venue: MarginVenue,
    pub position_kind: PositionKind,
    pub status: PositionStatus,
    pub asset_commitment: String,
    pub notional_commitment: String,
    pub collateral_commitment: String,
    pub leverage_bps: u64,
    pub margin_bps: u64,
    pub entry_price_root: String,
    pub position_nullifier: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl MarginPosition {
    pub fn from_request(request: OpenPositionRequest) -> Self {
        let position_id = position_id(&request);
        Self {
            position_id,
            account_id: request.account_id,
            venue: request.venue,
            position_kind: request.position_kind,
            status: PositionStatus::Open,
            asset_commitment: request.asset_commitment,
            notional_commitment: request.notional_commitment,
            collateral_commitment: request.collateral_commitment,
            leverage_bps: request.leverage_bps,
            margin_bps: request.margin_bps,
            entry_price_root: request.entry_price_root,
            position_nullifier: request.position_nullifier,
            opened_at_height: request.opened_at_height,
            updated_at_height: request.opened_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "account_id": self.account_id,
            "venue": self.venue.as_str(),
            "position_kind": self.position_kind.as_str(),
            "status": self.status.as_str(),
            "asset_commitment": self.asset_commitment,
            "notional_commitment": self.notional_commitment,
            "collateral_commitment": self.collateral_commitment,
            "leverage_bps": self.leverage_bps,
            "margin_bps": self.margin_bps,
            "entry_price_root": self.entry_price_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitNettingIntentRequest {
    pub account_id: String,
    pub position_id: String,
    pub target_venue: MarginVenue,
    pub encrypted_intent_root: String,
    pub offset_note_root: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NettingIntent {
    pub intent_id: String,
    pub account_id: String,
    pub position_id: String,
    pub target_venue: MarginVenue,
    pub status: IntentStatus,
    pub encrypted_intent_root: String,
    pub offset_note_root: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_sequence: u64,
    pub expires_at_height: u64,
}

impl NettingIntent {
    pub fn from_request(request: SubmitNettingIntentRequest, sequence: u64) -> Self {
        let intent_id = netting_intent_id(&request, sequence);
        Self {
            intent_id,
            account_id: request.account_id,
            position_id: request.position_id,
            target_venue: request.target_venue,
            status: IntentStatus::Admitted,
            encrypted_intent_root: request.encrypted_intent_root,
            offset_note_root: request.offset_note_root,
            fee_note_root: request.fee_note_root,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            submitted_sequence: sequence,
            expires_at_height: request.expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "account_id": self.account_id,
            "position_id": self.position_id,
            "target_venue": self.target_venue.as_str(),
            "status": self.status.as_str(),
            "encrypted_intent_root": self.encrypted_intent_root,
            "offset_note_root": self.offset_note_root,
            "fee_note_root": self.fee_note_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "submitted_sequence": self.submitted_sequence,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildNettingCycleRequest {
    pub venue: MarginVenue,
    pub intent_ids: Vec<String>,
    pub netted_position_root: String,
    pub netted_collateral_root: String,
    pub residual_risk_root: String,
    pub batch_policy_root: String,
    pub sponsor_reservation_root: String,
    pub built_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NettingCycle {
    pub cycle_id: String,
    pub venue: MarginVenue,
    pub status: NettingCycleStatus,
    pub intent_ids: Vec<String>,
    pub intent_set_root: String,
    pub netted_position_root: String,
    pub netted_collateral_root: String,
    pub residual_risk_root: String,
    pub batch_policy_root: String,
    pub sponsor_reservation_root: String,
    pub built_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl NettingCycle {
    pub fn from_request(request: BuildNettingCycleRequest, sequence: u64) -> Self {
        let intent_set_root = id_list_root("cycle-intents", &request.intent_ids);
        let cycle_id = netting_cycle_id(&request, &intent_set_root, sequence);
        Self {
            cycle_id,
            venue: request.venue,
            status: NettingCycleStatus::Building,
            intent_ids: request.intent_ids,
            intent_set_root,
            netted_position_root: request.netted_position_root,
            netted_collateral_root: request.netted_collateral_root,
            residual_risk_root: request.residual_risk_root,
            batch_policy_root: request.batch_policy_root,
            sponsor_reservation_root: request.sponsor_reservation_root,
            built_at_height: request.built_at_height,
            settled_at_height: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cycle_id": self.cycle_id,
            "venue": self.venue.as_str(),
            "status": self.status.as_str(),
            "intent_set_root": self.intent_set_root,
            "netted_position_root": self.netted_position_root,
            "netted_collateral_root": self.netted_collateral_root,
            "residual_risk_root": self.residual_risk_root,
            "batch_policy_root": self.batch_policy_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "intent_count": self.intent_ids.len(),
            "built_at_height": self.built_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordRiskAttestationRequest {
    pub cycle_id: String,
    pub venue: MarginVenue,
    pub attester_commitment: String,
    pub pq_signature_root: String,
    pub solvency_root: String,
    pub liquidation_bound_root: String,
    pub verdict: AttestationStatus,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskAttestation {
    pub attestation_id: String,
    pub cycle_id: String,
    pub venue: MarginVenue,
    pub attester_commitment: String,
    pub pq_signature_root: String,
    pub solvency_root: String,
    pub liquidation_bound_root: String,
    pub verdict: AttestationStatus,
    pub attested_at_height: u64,
}

impl RiskAttestation {
    pub fn from_request(request: RecordRiskAttestationRequest, sequence: u64) -> Self {
        let attestation_id = risk_attestation_id(&request, sequence);
        Self {
            attestation_id,
            cycle_id: request.cycle_id,
            venue: request.venue,
            attester_commitment: request.attester_commitment,
            pq_signature_root: request.pq_signature_root,
            solvency_root: request.solvency_root,
            liquidation_bound_root: request.liquidation_bound_root,
            verdict: request.verdict,
            attested_at_height: request.attested_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "cycle_id": self.cycle_id,
            "venue": self.venue.as_str(),
            "attester_commitment": self.attester_commitment,
            "pq_signature_root": self.pq_signature_root,
            "solvency_root": self.solvency_root,
            "liquidation_bound_root": self.liquidation_bound_root,
            "verdict": self.verdict.as_str(),
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveSponsorRequest {
    pub cycle_id: String,
    pub sponsor_commitment: String,
    pub coupon_root: String,
    pub max_fee_bps: u64,
    pub reserved_fee_units: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub cycle_id: String,
    pub sponsor_commitment: String,
    pub coupon_root: String,
    pub status: SponsorStatus,
    pub max_fee_bps: u64,
    pub reserved_fee_units: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn from_request(request: ReserveSponsorRequest, sequence: u64) -> Self {
        let reservation_id = sponsor_reservation_id(&request, sequence);
        Self {
            reservation_id,
            cycle_id: request.cycle_id,
            sponsor_commitment: request.sponsor_commitment,
            coupon_root: request.coupon_root,
            status: SponsorStatus::Reserved,
            max_fee_bps: request.max_fee_bps,
            reserved_fee_units: request.reserved_fee_units,
            expires_at_height: request.expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "cycle_id": self.cycle_id,
            "sponsor_commitment": self.sponsor_commitment,
            "coupon_root": self.coupon_root,
            "status": self.status.as_str(),
            "max_fee_bps": self.max_fee_bps,
            "reserved_fee_units": self.reserved_fee_units,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishReceiptRequest {
    pub cycle_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub fee_root: String,
    pub residual_position_root: String,
    pub published_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub cycle_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub fee_root: String,
    pub residual_position_root: String,
    pub published_at_height: u64,
}

impl SettlementReceipt {
    pub fn from_request(request: PublishReceiptRequest, sequence: u64) -> Self {
        let receipt_id = settlement_receipt_id(&request, sequence);
        Self {
            receipt_id,
            cycle_id: request.cycle_id,
            receipt_kind: request.receipt_kind,
            settlement_root: request.settlement_root,
            fee_root: request.fee_root,
            residual_position_root: request.residual_position_root,
            published_at_height: request.published_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "cycle_id": self.cycle_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "settlement_root": self.settlement_root,
            "fee_root": self.fee_root,
            "residual_position_root": self.residual_position_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueRebateRequest {
    pub cycle_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub cycle_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub status: RebateStatus,
}

impl FeeRebate {
    pub fn from_request(request: IssueRebateRequest, sequence: u64) -> Self {
        let rebate_id = fee_rebate_id(&request, sequence);
        Self {
            rebate_id,
            cycle_id: request.cycle_id,
            receipt_id: request.receipt_id,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_note_root: request.rebate_note_root,
            rebate_bps: request.rebate_bps,
            status: RebateStatus::Claimable,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "cycle_id": self.cycle_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenPrivacyFenceRequest {
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub effective_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub effective_height: u64,
}

impl PrivacyFence {
    pub fn from_request(request: OpenPrivacyFenceRequest, sequence: u64) -> Self {
        let fence_id = privacy_fence_id(&request, sequence);
        Self {
            fence_id,
            fence_kind: request.fence_kind,
            subject_id: request.subject_id,
            commitment_root: request.commitment_root,
            nullifier_root: request.nullifier_root,
            replay_domain: request.replay_domain,
            effective_height: request.effective_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "replay_domain": self.replay_domain,
            "effective_height": self.effective_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordSlashingRequest {
    pub cycle_id: String,
    pub offender_commitment: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub penalty_bps: u64,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub slashing_id: String,
    pub cycle_id: String,
    pub offender_commitment: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub penalty_bps: u64,
    pub recorded_at_height: u64,
}

impl SlashingEvent {
    pub fn from_request(request: RecordSlashingRequest, sequence: u64) -> Self {
        let slashing_id = slashing_event_id(&request, sequence);
        Self {
            slashing_id,
            cycle_id: request.cycle_id,
            offender_commitment: request.offender_commitment,
            reason: request.reason,
            evidence_root: request.evidence_root,
            penalty_bps: request.penalty_bps,
            recorded_at_height: request.recorded_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "cycle_id": self.cycle_id,
            "offender_commitment": self.offender_commitment,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "penalty_bps": self.penalty_bps,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> Self {
        let payload_root = payload_root(event_kind, payload);
        let event_id = runtime_event_id(
            event_kind,
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub accounts: BTreeMap<String, MarginAccount>,
    pub positions: BTreeMap<String, MarginPosition>,
    pub intents: BTreeMap<String, NettingIntent>,
    pub cycles: BTreeMap<String, NettingCycle>,
    pub attestations: BTreeMap<String, RiskAttestation>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_events: BTreeMap<String, SlashingEvent>,
    pub spent_nullifiers: BTreeSet<String>,
    pub runtime_events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            accounts: BTreeMap::new(),
            positions: BTreeMap::new(),
            intents: BTreeMap::new(),
            cycles: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            runtime_events: Vec::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet())?;
        let account = state.open_margin_account(OpenMarginAccountRequest {
            owner_commitment: commitment("devnet-owner-a"),
            venue: MarginVenue::ConfidentialPerps,
            collateral_note_root: commitment("devnet-collateral-note-a"),
            viewing_policy_root: commitment("devnet-view-policy-a"),
            pq_public_key_root: commitment("devnet-pq-key-a"),
            account_nullifier: commitment("devnet-account-nullifier-a"),
            privacy_set_size: 256,
            opened_at_height: 1,
        })?;
        let position = state.open_position(OpenPositionRequest {
            account_id: account.account_id.clone(),
            venue: MarginVenue::ConfidentialPerps,
            position_kind: PositionKind::Long,
            asset_commitment: commitment("devnet-xmr-usd-perp"),
            notional_commitment: commitment("devnet-notional-a"),
            collateral_commitment: commitment("devnet-collateral-a"),
            leverage_bps: 2500,
            margin_bps: 1400,
            entry_price_root: commitment("devnet-entry-price-root"),
            position_nullifier: commitment("devnet-position-nullifier-a"),
            opened_at_height: 2,
        })?;
        let intent = state.submit_netting_intent(SubmitNettingIntentRequest {
            account_id: account.account_id.clone(),
            position_id: position.position_id.clone(),
            target_venue: MarginVenue::SyntheticVault,
            encrypted_intent_root: commitment("devnet-encrypted-intent-a"),
            offset_note_root: commitment("devnet-offset-note-a"),
            fee_note_root: commitment("devnet-fee-note-a"),
            max_fee_bps: 32,
            privacy_set_size: 256,
            expires_at_height: 32,
        })?;
        let cycle = state.build_netting_cycle(BuildNettingCycleRequest {
            venue: MarginVenue::ConfidentialPerps,
            intent_ids: vec![intent.intent_id.clone()],
            netted_position_root: commitment("devnet-netted-position-root"),
            netted_collateral_root: commitment("devnet-netted-collateral-root"),
            residual_risk_root: commitment("devnet-residual-risk-root"),
            batch_policy_root: commitment("devnet-batch-policy-root"),
            sponsor_reservation_root: commitment("devnet-sponsor-reservation-root"),
            built_at_height: 3,
        })?;
        state.record_risk_attestation(RecordRiskAttestationRequest {
            cycle_id: cycle.cycle_id.clone(),
            venue: MarginVenue::ConfidentialPerps,
            attester_commitment: commitment("devnet-risk-attester"),
            pq_signature_root: commitment("devnet-risk-pq-signature"),
            solvency_root: commitment("devnet-solvency-root"),
            liquidation_bound_root: commitment("devnet-liquidation-bound-root"),
            verdict: AttestationStatus::Accepted,
            attested_at_height: 4,
        })?;
        let receipt = state.publish_receipt(PublishReceiptRequest {
            cycle_id: cycle.cycle_id.clone(),
            receipt_kind: ReceiptKind::CycleSettled,
            settlement_root: commitment("devnet-settlement-root"),
            fee_root: commitment("devnet-fee-root"),
            residual_position_root: commitment("devnet-residual-position-root"),
            published_at_height: 5,
        })?;
        state.issue_rebate(IssueRebateRequest {
            cycle_id: cycle.cycle_id,
            receipt_id: receipt.receipt_id,
            beneficiary_commitment: commitment("devnet-beneficiary"),
            rebate_note_root: commitment("devnet-rebate-note-root"),
            rebate_bps: 8,
        })?;
        Ok(state)
    }

    pub fn open_margin_account(
        &mut self,
        request: OpenMarginAccountRequest,
    ) -> Result<MarginAccount> {
        ensure_capacity("accounts", self.accounts.len(), self.config.max_accounts)?;
        require_root("owner_commitment", &request.owner_commitment)?;
        require_root("collateral_note_root", &request.collateral_note_root)?;
        require_root("viewing_policy_root", &request.viewing_policy_root)?;
        require_root("pq_public_key_root", &request.pq_public_key_root)?;
        require_root("account_nullifier", &request.account_nullifier)?;
        require_min_privacy(request.privacy_set_size, self.config.min_privacy_set_size)?;
        if !self
            .spent_nullifiers
            .insert(request.account_nullifier.clone())
        {
            return Err("account_nullifier already spent".to_string());
        }
        let account = MarginAccount::from_request(request);
        self.accounts
            .insert(account.account_id.clone(), account.clone());
        self.counters.accounts_opened = self.counters.accounts_opened.saturating_add(1);
        self.emit_event(
            "account_opened",
            &account.account_id,
            &account.public_record(),
            account.opened_at_height,
        );
        self.refresh_roots();
        Ok(account)
    }

    pub fn open_position(&mut self, request: OpenPositionRequest) -> Result<MarginPosition> {
        ensure_capacity("positions", self.positions.len(), self.config.max_positions)?;
        let account = self
            .accounts
            .get(&request.account_id)
            .ok_or_else(|| format!("unknown account_id: {}", request.account_id))?;
        if account.status != AccountStatus::Active {
            return Err("account must be active".to_string());
        }
        require_eq("venue", request.venue.as_str(), account.venue.as_str())?;
        require_root("asset_commitment", &request.asset_commitment)?;
        require_root("notional_commitment", &request.notional_commitment)?;
        require_root("collateral_commitment", &request.collateral_commitment)?;
        require_root("entry_price_root", &request.entry_price_root)?;
        require_root("position_nullifier", &request.position_nullifier)?;
        require_bps("leverage_bps", request.leverage_bps)?;
        require_bps("margin_bps", request.margin_bps)?;
        if request.margin_bps < request.venue.default_margin_bps() {
            return Err("margin_bps below venue floor".to_string());
        }
        if !self
            .spent_nullifiers
            .insert(request.position_nullifier.clone())
        {
            return Err("position_nullifier already spent".to_string());
        }
        let position = MarginPosition::from_request(request);
        self.positions
            .insert(position.position_id.clone(), position.clone());
        self.counters.positions_opened = self.counters.positions_opened.saturating_add(1);
        self.emit_event(
            "position_opened",
            &position.position_id,
            &position.public_record(),
            position.opened_at_height,
        );
        self.refresh_roots();
        Ok(position)
    }

    pub fn submit_netting_intent(
        &mut self,
        request: SubmitNettingIntentRequest,
    ) -> Result<NettingIntent> {
        ensure_capacity("intents", self.intents.len(), self.config.max_intents)?;
        self.accounts
            .get(&request.account_id)
            .ok_or_else(|| format!("unknown account_id: {}", request.account_id))?;
        let position = self
            .positions
            .get(&request.position_id)
            .ok_or_else(|| format!("unknown position_id: {}", request.position_id))?;
        if position.account_id != request.account_id {
            return Err("position is not owned by account".to_string());
        }
        require_root("encrypted_intent_root", &request.encrypted_intent_root)?;
        require_root("offset_note_root", &request.offset_note_root)?;
        require_root("fee_note_root", &request.fee_note_root)?;
        require_bps("max_fee_bps", request.max_fee_bps)?;
        if request.max_fee_bps > self.config.max_fee_bps {
            return Err("max_fee_bps exceeds runtime cap".to_string());
        }
        require_min_privacy(request.privacy_set_size, self.config.min_privacy_set_size)?;
        let sequence = self.counters.intents_submitted.saturating_add(1);
        let intent = NettingIntent::from_request(request, sequence);
        self.intents
            .insert(intent.intent_id.clone(), intent.clone());
        self.counters.intents_submitted = sequence;
        self.emit_event(
            "netting_intent_submitted",
            &intent.intent_id,
            &intent.public_record(),
            intent.submitted_sequence,
        );
        self.refresh_roots();
        Ok(intent)
    }

    pub fn build_netting_cycle(
        &mut self,
        request: BuildNettingCycleRequest,
    ) -> Result<NettingCycle> {
        ensure_capacity("cycles", self.cycles.len(), MAX_CYCLES)?;
        if request.intent_ids.is_empty() {
            return Err("intent_ids must be non-empty".to_string());
        }
        if request.intent_ids.len() > self.config.max_positions_per_cycle {
            return Err("too many intents for cycle".to_string());
        }
        ensure_unique("intent_ids", &request.intent_ids)?;
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown intent_id: {intent_id}"))?;
            if intent.status != IntentStatus::Admitted {
                return Err(format!("intent {intent_id} is not admitted"));
            }
        }
        require_root("netted_position_root", &request.netted_position_root)?;
        require_root("netted_collateral_root", &request.netted_collateral_root)?;
        require_root("residual_risk_root", &request.residual_risk_root)?;
        require_root("batch_policy_root", &request.batch_policy_root)?;
        require_root(
            "sponsor_reservation_root",
            &request.sponsor_reservation_root,
        )?;
        let sequence = self.counters.cycles_built.saturating_add(1);
        let cycle = NettingCycle::from_request(request, sequence);
        for intent_id in &cycle.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Batched;
            }
        }
        self.cycles.insert(cycle.cycle_id.clone(), cycle.clone());
        self.counters.cycles_built = sequence;
        self.emit_event(
            "netting_cycle_built",
            &cycle.cycle_id,
            &cycle.public_record(),
            cycle.built_at_height,
        );
        self.refresh_roots();
        Ok(cycle)
    }

    pub fn record_risk_attestation(
        &mut self,
        request: RecordRiskAttestationRequest,
    ) -> Result<RiskAttestation> {
        let cycle = self
            .cycles
            .get_mut(&request.cycle_id)
            .ok_or_else(|| format!("unknown cycle_id: {}", request.cycle_id))?;
        require_eq("venue", request.venue.as_str(), cycle.venue.as_str())?;
        require_root("attester_commitment", &request.attester_commitment)?;
        require_root("pq_signature_root", &request.pq_signature_root)?;
        require_root("solvency_root", &request.solvency_root)?;
        require_root("liquidation_bound_root", &request.liquidation_bound_root)?;
        let sequence = self.counters.attestations_recorded.saturating_add(1);
        let attestation = RiskAttestation::from_request(request, sequence);
        if attestation.verdict == AttestationStatus::Accepted {
            cycle.status = NettingCycleStatus::RiskChecked;
        } else if attestation.verdict == AttestationStatus::Rejected {
            cycle.status = NettingCycleStatus::Challenged;
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.counters.attestations_recorded = sequence;
        self.emit_event(
            "risk_attestation_recorded",
            &attestation.attestation_id,
            &attestation.public_record(),
            attestation.attested_at_height,
        );
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveSponsorRequest,
    ) -> Result<SponsorReservation> {
        self.cycles
            .get(&request.cycle_id)
            .ok_or_else(|| format!("unknown cycle_id: {}", request.cycle_id))?;
        require_root("sponsor_commitment", &request.sponsor_commitment)?;
        require_root("coupon_root", &request.coupon_root)?;
        require_bps("max_fee_bps", request.max_fee_bps)?;
        if request.max_fee_bps > self.config.max_fee_bps {
            return Err("sponsor max_fee_bps exceeds runtime cap".to_string());
        }
        let sequence = self.counters.sponsor_reservations.saturating_add(1);
        let reservation = SponsorReservation::from_request(request, sequence);
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.counters.sponsor_reservations = sequence;
        self.emit_event(
            "sponsor_reserved",
            &reservation.reservation_id,
            &reservation.public_record(),
            reservation.expires_at_height,
        );
        self.refresh_roots();
        Ok(reservation)
    }

    pub fn publish_receipt(&mut self, request: PublishReceiptRequest) -> Result<SettlementReceipt> {
        let cycle = self
            .cycles
            .get_mut(&request.cycle_id)
            .ok_or_else(|| format!("unknown cycle_id: {}", request.cycle_id))?;
        require_root("settlement_root", &request.settlement_root)?;
        require_root("fee_root", &request.fee_root)?;
        require_root("residual_position_root", &request.residual_position_root)?;
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt = SettlementReceipt::from_request(request, sequence);
        cycle.status = NettingCycleStatus::Settled;
        cycle.settled_at_height = Some(receipt.published_at_height);
        for intent_id in &cycle.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Matched;
            }
        }
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.counters.receipts_published = sequence;
        self.emit_event(
            "receipt_published",
            &receipt.receipt_id,
            &receipt.public_record(),
            receipt.published_at_height,
        );
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<FeeRebate> {
        self.cycles
            .get(&request.cycle_id)
            .ok_or_else(|| format!("unknown cycle_id: {}", request.cycle_id))?;
        self.receipts
            .get(&request.receipt_id)
            .ok_or_else(|| format!("unknown receipt_id: {}", request.receipt_id))?;
        require_root("beneficiary_commitment", &request.beneficiary_commitment)?;
        require_root("rebate_note_root", &request.rebate_note_root)?;
        require_bps("rebate_bps", request.rebate_bps)?;
        let sequence = self.counters.rebates_issued.saturating_add(1);
        let rebate = FeeRebate::from_request(request, sequence);
        self.rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        self.counters.rebates_issued = sequence;
        self.emit_event(
            "rebate_issued",
            &rebate.rebate_id,
            &rebate.public_record(),
            sequence,
        );
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn open_privacy_fence(&mut self, request: OpenPrivacyFenceRequest) -> Result<PrivacyFence> {
        require_root("commitment_root", &request.commitment_root)?;
        require_root("nullifier_root", &request.nullifier_root)?;
        require_non_empty("replay_domain", &request.replay_domain)?;
        let sequence = self.counters.privacy_fences_opened.saturating_add(1);
        let fence = PrivacyFence::from_request(request, sequence);
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.counters.privacy_fences_opened = sequence;
        self.emit_event(
            "privacy_fence_opened",
            &fence.fence_id,
            &fence.public_record(),
            fence.effective_height,
        );
        self.refresh_roots();
        Ok(fence)
    }

    pub fn record_slashing(&mut self, request: RecordSlashingRequest) -> Result<SlashingEvent> {
        self.cycles
            .get(&request.cycle_id)
            .ok_or_else(|| format!("unknown cycle_id: {}", request.cycle_id))?;
        require_root("offender_commitment", &request.offender_commitment)?;
        require_root("evidence_root", &request.evidence_root)?;
        require_bps("penalty_bps", request.penalty_bps)?;
        let sequence = self.counters.slashing_events.saturating_add(1);
        let event = SlashingEvent::from_request(request, sequence);
        self.slashing_events
            .insert(event.slashing_id.clone(), event.clone());
        self.counters.slashing_events = sequence;
        self.emit_event(
            "slashing_recorded",
            &event.slashing_id,
            &event.public_record(),
            event.recorded_at_height,
        );
        self.refresh_roots();
        Ok(event)
    }

    pub fn public_record(&self) -> Value {
        let without_root = self.public_record_without_state_root();
        json!({
            "state_root": state_root_from_record(&without_root),
            "state": without_root,
        })
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_cross_margin_netting_runtime",
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "account_count": self.accounts.len(),
            "position_count": self.positions.len(),
            "intent_count": self.intents.len(),
            "cycle_count": self.cycles.len(),
            "attestation_count": self.attestations.len(),
            "sponsor_reservation_count": self.sponsor_reservations.len(),
            "receipt_count": self.receipts.len(),
            "rebate_count": self.rebates.len(),
            "privacy_fence_count": self.privacy_fences.len(),
            "slashing_event_count": self.slashing_events.len(),
            "spent_nullifier_count": self.spent_nullifiers.len(),
            "runtime_event_count": self.runtime_events.len(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn refresh_roots(&mut self) {
        self.roots = Roots {
            accounts_root: map_root(
                "accounts",
                self.accounts.values().map(MarginAccount::public_record),
            ),
            positions_root: map_root(
                "positions",
                self.positions.values().map(MarginPosition::public_record),
            ),
            intents_root: map_root(
                "intents",
                self.intents.values().map(NettingIntent::public_record),
            ),
            cycles_root: map_root(
                "cycles",
                self.cycles.values().map(NettingCycle::public_record),
            ),
            attestations_root: map_root(
                "attestations",
                self.attestations
                    .values()
                    .map(RiskAttestation::public_record),
            ),
            sponsors_root: map_root(
                "sponsors",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservation::public_record),
            ),
            receipts_root: map_root(
                "receipts",
                self.receipts.values().map(SettlementReceipt::public_record),
            ),
            rebates_root: map_root(
                "rebates",
                self.rebates.values().map(FeeRebate::public_record),
            ),
            fences_root: map_root(
                "fences",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            slashing_root: map_root(
                "slashing",
                self.slashing_events
                    .values()
                    .map(SlashingEvent::public_record),
            ),
            nullifier_root: id_list_root(
                "nullifiers",
                &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            events_root: map_root(
                "events",
                self.runtime_events.iter().map(RuntimeEvent::public_record),
            ),
        };
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str, payload: &Value, height: u64) {
        if self.runtime_events.len() >= MAX_EVENTS {
            return;
        }
        let sequence = self.counters.runtime_events.saturating_add(1);
        self.runtime_events.push(RuntimeEvent::new(
            kind, subject_id, payload, height, sequence,
        ));
        self.counters.runtime_events = sequence;
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn private_l2_confidential_cross_margin_netting_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_confidential_cross_margin_netting_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn margin_account_id(request: &OpenMarginAccountRequest) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.collateral_note_root),
            HashPart::Str(&request.account_nullifier),
            HashPart::U64(request.opened_at_height),
        ],
        32,
    )
}

pub fn position_id(request: &OpenPositionRequest) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.account_id),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(request.position_kind.as_str()),
            HashPart::Str(&request.asset_commitment),
            HashPart::Str(&request.position_nullifier),
            HashPart::U64(request.opened_at_height),
        ],
        32,
    )
}

pub fn netting_intent_id(request: &SubmitNettingIntentRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.account_id),
            HashPart::Str(&request.position_id),
            HashPart::Str(request.target_venue.as_str()),
            HashPart::Str(&request.encrypted_intent_root),
            HashPart::Str(&request.offset_note_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn netting_cycle_id(
    request: &BuildNettingCycleRequest,
    intent_set_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-CYCLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(intent_set_root),
            HashPart::Str(&request.netted_position_root),
            HashPart::Str(&request.residual_risk_root),
            HashPart::U64(request.built_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn risk_attestation_id(request: &RecordRiskAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cycle_id),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(request.verdict.as_str()),
            HashPart::U64(request.attested_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cycle_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.coupon_root),
            HashPart::U64(request.max_fee_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &PublishReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cycle_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.fee_root),
            HashPart::U64(request.published_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_rebate_id(request: &IssueRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cycle_id),
            HashPart::Str(&request.receipt_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_note_root),
            HashPart::U64(request.rebate_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &OpenPrivacyFenceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.commitment_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.replay_domain),
            HashPart::U64(request.effective_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_event_id(request: &RecordSlashingRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cycle_id),
            HashPart::Str(&request.offender_commitment),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.penalty_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(&format!("{domain}-ROOT"), record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-CONFIDENTIAL-CROSS-MARGIN-{domain}"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

pub fn id_list_root(domain: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records = records.into_iter().collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must equal {expected}"))
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        Err(format!("{field} must be a commitment root"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn require_min_privacy(actual: u64, minimum: u64) -> Result<()> {
    if actual < minimum {
        Err(format!(
            "privacy_set_size must be at least {minimum}, got {actual}"
        ))
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

fn ensure_unique(field: &str, values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value: {value}"));
        }
    }
    Ok(())
}
