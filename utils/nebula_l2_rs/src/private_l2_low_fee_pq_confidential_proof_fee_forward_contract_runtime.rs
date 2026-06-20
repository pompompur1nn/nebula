use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialProofFeeForwardContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_FORWARD_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-proof-fee-forward-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_FORWARD_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-proof-fee-forward-oracle-v1";
pub const CONFIDENTIAL_COLLATERAL_SUITE: &str =
    "pedersen+bulletproofs-plus-confidential-proof-fee-collateral-v1";
pub const FORWARD_BOOK_SCHEME: &str = "low-fee-proof-forward-book-root-v1";
pub const FEE_CURVE_SCHEME: &str = "predictable-proof-fee-curve-root-v1";
pub const SETTLEMENT_SCHEME: &str = "fast-proof-fee-forward-settlement-root-v1";
pub const REBATE_ROUTING_SCHEME: &str = "low-fee-rebate-forward-routing-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "operator-safe-proof-fee-forward-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "confidential-proof-fee-collateral-devnet";
pub const DEVNET_HEIGHT: u64 = 2_412_400;
pub const DEVNET_EPOCH: u64 = 3_350;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_FORWARD_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_BASE_FEE_PICONERO: u64 = 42_000;
pub const DEFAULT_MAX_SETTLEMENT_LATENCY_BLOCKS: u64 = 12;
pub const DEFAULT_SETTLEMENT_GRACE_BLOCKS: u64 = 6;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 18;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 6_500;
pub const DEFAULT_COLLATERAL_MARGIN_BPS: u64 = 1_250;
pub const DEFAULT_CURVE_DAMPING_BPS: u64 = 8_500;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_FORWARD_BOOKS: usize = 262_144;
pub const MAX_FEE_CURVES: usize = 524_288;
pub const MAX_COLLATERAL_COMMITMENTS: usize = 1_048_576;
pub const MAX_PQ_ATTESTATIONS: usize = 1_048_576;
pub const MAX_EXPIRIES: usize = 1_048_576;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardSide {
    BuyerLocksFee,
    ProverSellsCapacity,
    RouterHedgesBatch,
    SponsorSubsidizesProof,
}

impl ForwardSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuyerLocksFee => "buyer_locks_fee",
            Self::ProverSellsCapacity => "prover_sells_capacity",
            Self::RouterHedgesBatch => "router_hedges_batch",
            Self::SponsorSubsidizesProof => "sponsor_subsidizes_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BookStatus {
    Draft,
    Open,
    Quoting,
    Matched,
    Settling,
    Paused,
    Expired,
    Retired,
}

impl BookStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open | Self::Quoting | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurveStatus {
    Proposed,
    Active,
    Dampened,
    Frozen,
    Superseded,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurveKind {
    FlatCap,
    EpochTwap,
    CongestionBand,
    RecursiveProofDiscount,
    OracleMedian,
}

impl CurveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FlatCap => "flat_cap",
            Self::EpochTwap => "epoch_twap",
            Self::CongestionBand => "congestion_band",
            Self::RecursiveProofDiscount => "recursive_proof_discount",
            Self::OracleMedian => "oracle_median",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralStatus {
    Committed,
    Locked,
    PartiallyReserved,
    Reserved,
    Released,
    Slashed,
    Expired,
}

impl CollateralStatus {
    pub fn spendable(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Locked | Self::PartiallyReserved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ProverCostQuote,
    FeeCurveObservation,
    CollateralSufficiency,
    SettlementReadiness,
    RebateEligibility,
    OperatorSolvency,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProverCostQuote => "prover_cost_quote",
            Self::FeeCurveObservation => "fee_curve_observation",
            Self::CollateralSufficiency => "collateral_sufficiency",
            Self::SettlementReadiness => "settlement_readiness",
            Self::RebateEligibility => "rebate_eligibility",
            Self::OperatorSolvency => "operator_solvency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryKind {
    ForwardBook,
    FeeCurve,
    CollateralLock,
    PqAttestation,
    SettlementWindow,
    RebateClaim,
}

impl ExpiryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForwardBook => "forward_book",
            Self::FeeCurve => "fee_curve",
            Self::CollateralLock => "collateral_lock",
            Self::PqAttestation => "pq_attestation",
            Self::SettlementWindow => "settlement_window",
            Self::RebateClaim => "rebate_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    OracleAttested,
    CollateralReserved,
    Proving,
    Netting,
    Settled,
    Rebated,
    Failed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Proposed,
    Eligible,
    Routed,
    Claimed,
    DonatedToBook,
    Expired,
    Denied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_oracle_attestation_suite: String,
    pub confidential_collateral_suite: String,
    pub forward_book_scheme: String,
    pub fee_curve_scheme: String,
    pub settlement_scheme: String,
    pub rebate_routing_scheme: String,
    pub public_record_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub epoch: u64,
    pub epoch_blocks: u64,
    pub forward_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_base_fee_piconero: u64,
    pub max_settlement_latency_blocks: u64,
    pub settlement_grace_blocks: u64,
    pub operator_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub collateral_margin_bps: u64,
    pub curve_damping_bps: u64,
    pub max_forward_books: usize,
    pub max_fee_curves: usize,
    pub max_collateral_commitments: usize,
    pub max_pq_attestations: usize,
    pub max_expiries: usize,
    pub max_settlements: usize,
    pub max_rebates: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_oracle_attestation_suite: PQ_ORACLE_ATTESTATION_SUITE.to_string(),
            confidential_collateral_suite: CONFIDENTIAL_COLLATERAL_SUITE.to_string(),
            forward_book_scheme: FORWARD_BOOK_SCHEME.to_string(),
            fee_curve_scheme: FEE_CURVE_SCHEME.to_string(),
            settlement_scheme: SETTLEMENT_SCHEME.to_string(),
            rebate_routing_scheme: REBATE_ROUTING_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            epoch: DEVNET_EPOCH,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            forward_ttl_blocks: DEFAULT_FORWARD_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_base_fee_piconero: DEFAULT_MAX_BASE_FEE_PICONERO,
            max_settlement_latency_blocks: DEFAULT_MAX_SETTLEMENT_LATENCY_BLOCKS,
            settlement_grace_blocks: DEFAULT_SETTLEMENT_GRACE_BLOCKS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            collateral_margin_bps: DEFAULT_COLLATERAL_MARGIN_BPS,
            curve_damping_bps: DEFAULT_CURVE_DAMPING_BPS,
            max_forward_books: MAX_FORWARD_BOOKS,
            max_fee_curves: MAX_FEE_CURVES,
            max_collateral_commitments: MAX_COLLATERAL_COMMITMENTS,
            max_pq_attestations: MAX_PQ_ATTESTATIONS,
            max_expiries: MAX_EXPIRIES,
            max_settlements: MAX_SETTLEMENTS,
            max_rebates: MAX_REBATES,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("collateral_asset_id", &self.collateral_asset_id)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported protocol version".to_string());
        }
        if self.operator_fee_bps > MAX_BPS
            || self.rebate_share_bps > MAX_BPS
            || self.collateral_margin_bps > MAX_BPS
            || self.curve_damping_bps > MAX_BPS
        {
            return Err("basis point config exceeds max".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("PQ security below runtime floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub forward_books_opened: u64,
    pub fee_curves_published: u64,
    pub collateral_commitments_locked: u64,
    pub pq_attestations_accepted: u64,
    pub expiries_scheduled: u64,
    pub settlements_queued: u64,
    pub settlements_finalized: u64,
    pub rebates_routed: u64,
    pub operator_summaries_posted: u64,
    pub fee_units_forwarded: u64,
    pub fee_units_rebated: u64,
    pub settlement_latency_blocks_total: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub forward_book_root: String,
    pub fee_curve_root: String,
    pub collateral_commitment_root: String,
    pub pq_attestation_root: String,
    pub expiry_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub operator_summary_root: String,
    pub spent_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForwardBook {
    pub id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub side: ForwardSide,
    pub status: BookStatus,
    pub curve_id: String,
    pub collateral_commitment_id: String,
    pub notional_fee_units: u64,
    pub locked_fee_cap_piconero: u64,
    pub max_proof_units: u64,
    pub min_fill_units: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub metadata_root: String,
    pub order_commitment_root: String,
}

impl ForwardBook {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "operator_id": self.operator_id,
            "lane_id": self.lane_id,
            "side": self.side,
            "status": self.status,
            "curve_id": self.curve_id,
            "collateral_commitment_id": self.collateral_commitment_id,
            "notional_fee_units": self.notional_fee_units,
            "locked_fee_cap_piconero": self.locked_fee_cap_piconero,
            "max_proof_units": self.max_proof_units,
            "min_fill_units": self.min_fill_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "expiry_height": self.expiry_height,
            "metadata_root": self.metadata_root,
            "order_commitment_root": self.order_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCurve {
    pub id: String,
    pub operator_id: String,
    pub kind: CurveKind,
    pub status: CurveStatus,
    pub base_fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub congestion_multiplier_bps: u64,
    pub damping_bps: u64,
    pub rebate_floor_bps: u64,
    pub oracle_attestation_id: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub curve_commitment_root: String,
}

impl FeeCurve {
    pub fn quoted_fee(&self, proof_units: u64) -> u64 {
        let raw = self
            .base_fee_piconero
            .saturating_mul(proof_units)
            .saturating_mul(self.congestion_multiplier_bps)
            / MAX_BPS;
        let damped = raw.saturating_mul(self.damping_bps) / MAX_BPS;
        damped.min(self.max_fee_piconero.saturating_mul(proof_units))
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralCommitment {
    pub id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub status: CollateralStatus,
    pub amount_commitment: String,
    pub range_proof_root: String,
    pub blinding_root: String,
    pub reserved_fee_units: u64,
    pub margin_bps: u64,
    pub lock_height: u64,
    pub release_height: u64,
    pub nullifier: String,
}

impl CollateralCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "status": self.status,
            "amount_commitment": self.amount_commitment,
            "range_proof_root": self.range_proof_root,
            "reserved_fee_units": self.reserved_fee_units,
            "margin_bps": self.margin_bps,
            "lock_height": self.lock_height,
            "release_height": self.release_height,
            "nullifier": self.nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestation {
    pub id: String,
    pub oracle_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub subject_id: String,
    pub observed_fee_piconero: u64,
    pub observed_proof_units: u64,
    pub confidence_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub attested_height: u64,
    pub expiry_height: u64,
    pub payload_root: String,
    pub signature_root: String,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Expiry {
    pub id: String,
    pub kind: ExpiryKind,
    pub subject_id: String,
    pub due_height: u64,
    pub grace_height: u64,
    pub executed: bool,
    pub action_root: String,
}

impl Expiry {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Settlement {
    pub id: String,
    pub book_id: String,
    pub curve_id: String,
    pub attestation_id: String,
    pub collateral_commitment_id: String,
    pub status: SettlementStatus,
    pub proof_units: u64,
    pub quoted_fee_piconero: u64,
    pub executed_fee_piconero: u64,
    pub operator_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub queued_height: u64,
    pub settled_height: u64,
    pub settlement_payload_root: String,
    pub receipt_root: String,
}

impl Settlement {
    pub fn latency_blocks(&self) -> u64 {
        self.settled_height.saturating_sub(self.queued_height)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRoute {
    pub id: String,
    pub settlement_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub amount_piconero: u64,
    pub route_bps: u64,
    pub claim_nullifier: String,
    pub routed_height: u64,
    pub expiry_height: u64,
    pub routing_policy_root: String,
}

impl RebateRoute {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub open_books: u64,
    pub settled_forwards: u64,
    pub average_settlement_latency_blocks: u64,
    pub total_forwarded_fee_piconero: u64,
    pub total_rebated_fee_piconero: u64,
    pub collateral_coverage_bps: u64,
    pub public_risk_root: String,
    pub solvency_attestation_id: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub forward_books: BTreeMap<String, ForwardBook>,
    pub fee_curves: BTreeMap<String, FeeCurve>,
    pub collateral_commitments: BTreeMap<String, CollateralCommitment>,
    pub pq_attestations: BTreeMap<String, PqOracleAttestation>,
    pub expiries: BTreeMap<String, Expiry>,
    pub settlements: BTreeMap<String, Settlement>,
    pub rebates: BTreeMap<String, RebateRoute>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height,
            forward_books: BTreeMap::new(),
            fee_curves: BTreeMap::new(),
            collateral_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            expiries: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::devnet(), DEVNET_HEIGHT).expect("devnet config must validate");
        let collateral = CollateralCommitment {
            id: collateral_commitment_id(
                "commitment:prover-desk-a",
                DEVNET_COLLATERAL_ASSET_ID,
                "amount:proof-fee-collateral-a",
                "nullifier:proof-fee-collateral-a",
                DEVNET_HEIGHT,
            ),
            owner_commitment: "commitment:prover-desk-a".to_string(),
            asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            status: CollateralStatus::Locked,
            amount_commitment: "amount:proof-fee-collateral-a".to_string(),
            range_proof_root: sample_root("COLLATERAL-RANGE", "devnet-prover-desk-a"),
            blinding_root: sample_root("COLLATERAL-BLINDING", "devnet-prover-desk-a"),
            reserved_fee_units: 2_400,
            margin_bps: DEFAULT_COLLATERAL_MARGIN_BPS,
            lock_height: DEVNET_HEIGHT,
            release_height: DEVNET_HEIGHT + DEFAULT_FORWARD_TTL_BLOCKS,
            nullifier: "nullifier:proof-fee-collateral-a".to_string(),
        };
        state
            .lock_collateral(collateral)
            .expect("devnet collateral");

        let attestation = PqOracleAttestation {
            id: pq_attestation_id(
                "oracle:proof-fee-median-a",
                AttestationKind::FeeCurveObservation,
                "curve:private-defi-fast-proofs",
                DEVNET_HEIGHT,
            ),
            oracle_id: "oracle:proof-fee-median-a".to_string(),
            kind: AttestationKind::FeeCurveObservation,
            status: AttestationStatus::Accepted,
            subject_id: "curve:private-defi-fast-proofs".to_string(),
            observed_fee_piconero: 31_000,
            observed_proof_units: 1,
            confidence_bps: 9_650,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            attested_height: DEVNET_HEIGHT,
            expiry_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
            payload_root: sample_root("PQ-ORACLE-PAYLOAD", "devnet-fee-curve"),
            signature_root: sample_root("PQ-ORACLE-SIGNATURE", "devnet-fee-curve"),
        };
        let attestation_id = attestation.id.clone();
        state
            .accept_pq_attestation(attestation)
            .expect("devnet attestation");

        let curve = FeeCurve {
            id: fee_curve_id(
                "operator:low-fee-forward-a",
                CurveKind::OracleMedian,
                31_000,
                DEVNET_HEIGHT,
            ),
            operator_id: "operator:low-fee-forward-a".to_string(),
            kind: CurveKind::OracleMedian,
            status: CurveStatus::Active,
            base_fee_piconero: 31_000,
            max_fee_piconero: DEFAULT_MAX_BASE_FEE_PICONERO,
            congestion_multiplier_bps: 10_250,
            damping_bps: DEFAULT_CURVE_DAMPING_BPS,
            rebate_floor_bps: 2_000,
            oracle_attestation_id: attestation_id,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_FORWARD_TTL_BLOCKS,
            curve_commitment_root: sample_root("FEE-CURVE-COMMITMENT", "devnet-curve-a"),
        };
        let curve_id = curve.id.clone();
        state.publish_fee_curve(curve).expect("devnet curve");

        let collateral_id = state
            .collateral_commitments
            .keys()
            .next()
            .cloned()
            .expect("devnet collateral id");
        let book = ForwardBook {
            id: forward_book_id(
                "operator:low-fee-forward-a",
                "lane:defi-router-fast-proof",
                ForwardSide::BuyerLocksFee,
                DEVNET_HEIGHT,
            ),
            operator_id: "operator:low-fee-forward-a".to_string(),
            lane_id: "lane:defi-router-fast-proof".to_string(),
            side: ForwardSide::BuyerLocksFee,
            status: BookStatus::Open,
            curve_id,
            collateral_commitment_id: collateral_id,
            notional_fee_units: 2_400,
            locked_fee_cap_piconero: 42_000,
            max_proof_units: 2_400,
            min_fill_units: 8,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            opened_height: DEVNET_HEIGHT,
            expiry_height: DEVNET_HEIGHT + DEFAULT_FORWARD_TTL_BLOCKS,
            metadata_root: sample_root("BOOK-METADATA", "devnet-book-a"),
            order_commitment_root: sample_root("BOOK-ORDERS", "devnet-book-a"),
        };
        let book_id = book.id.clone();
        state.open_forward_book(book).expect("devnet book");

        let settlement_id = state
            .queue_settlement(&book_id, 64, DEVNET_HEIGHT + 4)
            .expect("devnet settlement");
        state
            .finalize_settlement(&settlement_id, 64, DEVNET_HEIGHT + 8)
            .expect("devnet final settlement");
        state
            .post_operator_summary("operator:low-fee-forward-a", DEVNET_EPOCH)
            .expect("devnet operator summary");
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            forward_book_root: map_public_record_root(
                "PROOF-FEE-FORWARD-BOOK-ROOT",
                &self.forward_books,
            ),
            fee_curve_root: map_public_record_root(
                "PROOF-FEE-FORWARD-CURVE-ROOT",
                &self.fee_curves,
            ),
            collateral_commitment_root: map_public_record_root(
                "PROOF-FEE-FORWARD-COLLATERAL-ROOT",
                &self.collateral_commitments,
            ),
            pq_attestation_root: map_public_record_root(
                "PROOF-FEE-FORWARD-ATTESTATION-ROOT",
                &self.pq_attestations,
            ),
            expiry_root: map_public_record_root("PROOF-FEE-FORWARD-EXPIRY-ROOT", &self.expiries),
            settlement_root: map_public_record_root(
                "PROOF-FEE-FORWARD-SETTLEMENT-ROOT",
                &self.settlements,
            ),
            rebate_root: map_public_record_root("PROOF-FEE-FORWARD-REBATE-ROOT", &self.rebates),
            operator_summary_root: map_public_record_root(
                "PROOF-FEE-FORWARD-OPERATOR-ROOT",
                &self.operator_summaries,
            ),
            spent_nullifier_root: set_root(
                "PROOF-FEE-FORWARD-NULLIFIER-ROOT",
                &self.spent_nullifiers,
            ),
        }
    }

    pub fn publish_fee_curve(&mut self, curve: FeeCurve) -> Result<()> {
        ensure_capacity(
            "fee curve",
            self.fee_curves.len(),
            self.config.max_fee_curves,
        )?;
        ensure_absent("fee curve", &self.fee_curves, &curve.id)?;
        ensure_nonempty("oracle_attestation_id", &curve.oracle_attestation_id)?;
        if curve.max_fee_piconero > self.config.max_base_fee_piconero {
            return Err("fee curve cap exceeds configured fee ceiling".to_string());
        }
        if curve.congestion_multiplier_bps > MAX_BPS * 4 || curve.damping_bps > MAX_BPS {
            return Err("fee curve multiplier outside policy bounds".to_string());
        }
        self.schedule_expiry(
            ExpiryKind::FeeCurve,
            &curve.id,
            curve.valid_until_height,
            curve.valid_until_height + self.config.settlement_grace_blocks,
        )?;
        self.counters.fee_curves_published += 1;
        self.fee_curves.insert(curve.id.clone(), curve);
        Ok(())
    }

    pub fn lock_collateral(&mut self, commitment: CollateralCommitment) -> Result<()> {
        ensure_capacity(
            "collateral commitment",
            self.collateral_commitments.len(),
            self.config.max_collateral_commitments,
        )?;
        ensure_absent(
            "collateral commitment",
            &self.collateral_commitments,
            &commitment.id,
        )?;
        ensure_nonempty("amount_commitment", &commitment.amount_commitment)?;
        ensure_nonempty("nullifier", &commitment.nullifier)?;
        if self.spent_nullifiers.contains(&commitment.nullifier) {
            return Err("collateral nullifier already spent".to_string());
        }
        if commitment.margin_bps < self.config.collateral_margin_bps {
            return Err("collateral margin below configured floor".to_string());
        }
        self.schedule_expiry(
            ExpiryKind::CollateralLock,
            &commitment.id,
            commitment.release_height,
            commitment.release_height + self.config.settlement_grace_blocks,
        )?;
        self.counters.collateral_commitments_locked += 1;
        self.collateral_commitments
            .insert(commitment.id.clone(), commitment);
        Ok(())
    }

    pub fn accept_pq_attestation(&mut self, attestation: PqOracleAttestation) -> Result<()> {
        ensure_capacity(
            "PQ attestation",
            self.pq_attestations.len(),
            self.config.max_pq_attestations,
        )?;
        ensure_absent("PQ attestation", &self.pq_attestations, &attestation.id)?;
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ attestation security below runtime floor".to_string());
        }
        if attestation.privacy_set_size < self.config.min_privacy_set_size {
            return Err("PQ attestation privacy set below runtime floor".to_string());
        }
        self.schedule_expiry(
            ExpiryKind::PqAttestation,
            &attestation.id,
            attestation.expiry_height,
            attestation.expiry_height + self.config.settlement_grace_blocks,
        )?;
        self.counters.pq_attestations_accepted += 1;
        self.pq_attestations
            .insert(attestation.id.clone(), attestation);
        Ok(())
    }

    pub fn open_forward_book(&mut self, book: ForwardBook) -> Result<()> {
        ensure_capacity(
            "forward book",
            self.forward_books.len(),
            self.config.max_forward_books,
        )?;
        ensure_absent("forward book", &self.forward_books, &book.id)?;
        ensure_known("fee curve", &self.fee_curves, &book.curve_id)?;
        ensure_known(
            "collateral commitment",
            &self.collateral_commitments,
            &book.collateral_commitment_id,
        )?;
        if !book.status.accepts_orders() {
            return Err("forward book is not orderable".to_string());
        }
        if book.privacy_set_size < self.config.min_privacy_set_size {
            return Err("forward book privacy set below runtime floor".to_string());
        }
        self.schedule_expiry(
            ExpiryKind::ForwardBook,
            &book.id,
            book.expiry_height,
            book.expiry_height + self.config.settlement_grace_blocks,
        )?;
        self.counters.forward_books_opened += 1;
        self.forward_books.insert(book.id.clone(), book);
        Ok(())
    }

    pub fn queue_settlement(
        &mut self,
        book_id: &str,
        proof_units: u64,
        queued_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "settlement",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        let book = self
            .forward_books
            .get(book_id)
            .ok_or_else(|| format!("unknown forward book {book_id}"))?;
        let curve_id = book.curve_id.clone();
        let collateral_commitment_id = book.collateral_commitment_id.clone();
        let max_proof_units = book.max_proof_units;
        let locked_fee_cap_piconero = book.locked_fee_cap_piconero;
        let curve = self
            .fee_curves
            .get(&curve_id)
            .ok_or_else(|| format!("unknown fee curve {curve_id}"))?;
        let attestation_id = curve.oracle_attestation_id.clone();
        ensure_known("PQ attestation", &self.pq_attestations, &attestation_id)?;
        if proof_units == 0 || proof_units > max_proof_units {
            return Err("settlement proof units outside forward bounds".to_string());
        }
        let quoted_fee = curve.quoted_fee(proof_units).min(
            locked_fee_cap_piconero
                .saturating_mul(proof_units)
                .saturating_div(max_proof_units.max(1)),
        );
        let operator_fee = quoted_fee.saturating_mul(self.config.operator_fee_bps) / MAX_BPS;
        let settlement_id = settlement_id(book_id, &curve_id, proof_units, queued_height);
        ensure_absent("settlement", &self.settlements, &settlement_id)?;
        let settlement = Settlement {
            id: settlement_id.clone(),
            book_id: book_id.to_string(),
            curve_id,
            attestation_id,
            collateral_commitment_id,
            status: SettlementStatus::Queued,
            proof_units,
            quoted_fee_piconero: quoted_fee,
            executed_fee_piconero: 0,
            operator_fee_piconero: operator_fee,
            rebate_piconero: 0,
            queued_height,
            settled_height: 0,
            settlement_payload_root: sample_root("SETTLEMENT-PAYLOAD", &settlement_id),
            receipt_root: sample_root("SETTLEMENT-RECEIPT-PENDING", &settlement_id),
        };
        self.schedule_expiry(
            ExpiryKind::SettlementWindow,
            &settlement_id,
            queued_height + self.config.settlement_ttl_blocks,
            queued_height + self.config.settlement_ttl_blocks + self.config.settlement_grace_blocks,
        )?;
        self.counters.settlements_queued += 1;
        self.counters.fee_units_forwarded += quoted_fee;
        self.settlements.insert(settlement_id.clone(), settlement);
        Ok(settlement_id)
    }

    pub fn finalize_settlement(
        &mut self,
        settlement_id: &str,
        executed_proof_units: u64,
        settled_height: u64,
    ) -> Result<()> {
        let settlement = self
            .settlements
            .get(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        if !matches!(
            settlement.status,
            SettlementStatus::Queued
                | SettlementStatus::OracleAttested
                | SettlementStatus::CollateralReserved
                | SettlementStatus::Proving
                | SettlementStatus::Netting
        ) {
            return Err("settlement status cannot be finalized".to_string());
        }
        let curve = self
            .fee_curves
            .get(&settlement.curve_id)
            .ok_or_else(|| format!("unknown fee curve {}", settlement.curve_id))?;
        let executed_fee = curve.quoted_fee(executed_proof_units);
        let rebate = settlement.quoted_fee_piconero.saturating_sub(executed_fee);
        let settlement = self
            .settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        settlement.executed_fee_piconero = executed_fee;
        settlement.rebate_piconero = rebate;
        settlement.settled_height = settled_height;
        settlement.status = if rebate > 0 {
            SettlementStatus::Rebated
        } else {
            SettlementStatus::Settled
        };
        settlement.receipt_root = sample_root("SETTLEMENT-RECEIPT", settlement_id);
        let latency_blocks = settlement.latency_blocks();
        self.counters.settlements_finalized += 1;
        self.counters.fee_units_rebated += rebate;
        self.counters.settlement_latency_blocks_total += latency_blocks;
        if rebate > 0 {
            self.route_rebate_for_settlement(settlement_id)?;
        }
        Ok(())
    }

    pub fn route_rebate_for_settlement(&mut self, settlement_id: &str) -> Result<String> {
        ensure_capacity("rebate", self.rebates.len(), self.config.max_rebates)?;
        let settlement = self
            .settlements
            .get(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        if settlement.rebate_piconero == 0 {
            return Err("settlement has no rebate to route".to_string());
        }
        let book_id = settlement.book_id.clone();
        let settled_height = settlement.settled_height;
        let amount = settlement
            .rebate_piconero
            .saturating_mul(self.config.rebate_share_bps)
            / MAX_BPS;
        let route_id = rebate_route_id(settlement_id, &book_id, amount, settled_height);
        ensure_absent("rebate", &self.rebates, &route_id)?;
        let nullifier = domain_hash(
            "PROOF-FEE-FORWARD-REBATE-NULLIFIER",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(settlement_id),
                HashPart::U64(amount),
            ],
            32,
        );
        let rebate = RebateRoute {
            id: route_id.clone(),
            settlement_id: settlement_id.to_string(),
            beneficiary_commitment: format!("beneficiary:{book_id}"),
            status: RebateStatus::Routed,
            amount_piconero: amount,
            route_bps: self.config.rebate_share_bps,
            claim_nullifier: nullifier,
            routed_height: settled_height,
            expiry_height: settled_height + self.config.rebate_ttl_blocks,
            routing_policy_root: sample_root("REBATE-ROUTING-POLICY", settlement_id),
        };
        self.schedule_expiry(
            ExpiryKind::RebateClaim,
            &route_id,
            rebate.expiry_height,
            rebate.expiry_height + self.config.settlement_grace_blocks,
        )?;
        self.counters.rebates_routed += 1;
        self.rebates.insert(route_id.clone(), rebate);
        Ok(route_id)
    }

    pub fn post_operator_summary(&mut self, operator_id: &str, epoch: u64) -> Result<String> {
        ensure_capacity(
            "operator summary",
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
        )?;
        let open_books = self
            .forward_books
            .values()
            .filter(|book| book.operator_id == operator_id && book.status.accepts_orders())
            .count() as u64;
        let settlements = self
            .settlements
            .values()
            .filter(|settlement| {
                self.forward_books
                    .get(&settlement.book_id)
                    .map(|book| book.operator_id == operator_id)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        let settled_forwards = settlements
            .iter()
            .filter(|settlement| {
                matches!(
                    settlement.status,
                    SettlementStatus::Settled | SettlementStatus::Rebated
                )
            })
            .count() as u64;
        let latency_total = settlements
            .iter()
            .map(|settlement| settlement.latency_blocks())
            .sum::<u64>();
        let total_forwarded = settlements
            .iter()
            .map(|settlement| settlement.quoted_fee_piconero)
            .sum::<u64>();
        let total_rebated = settlements
            .iter()
            .map(|settlement| settlement.rebate_piconero)
            .sum::<u64>();
        let summary_id = operator_summary_id(operator_id, epoch, self.current_height);
        ensure_absent("operator summary", &self.operator_summaries, &summary_id)?;
        let summary = OperatorSummary {
            id: summary_id.clone(),
            operator_id: operator_id.to_string(),
            epoch,
            open_books,
            settled_forwards,
            average_settlement_latency_blocks: if settled_forwards == 0 {
                0
            } else {
                latency_total / settled_forwards
            },
            total_forwarded_fee_piconero: total_forwarded,
            total_rebated_fee_piconero: total_rebated,
            collateral_coverage_bps: self.operator_collateral_coverage_bps(operator_id),
            public_risk_root: sample_root("OPERATOR-PUBLIC-RISK", operator_id),
            solvency_attestation_id: self
                .pq_attestations
                .values()
                .find(|attestation| {
                    attestation.oracle_id == operator_id
                        && attestation.kind == AttestationKind::OperatorSolvency
                })
                .map(|attestation| attestation.id.clone())
                .unwrap_or_else(|| "unattested-devnet-summary".to_string()),
        };
        self.counters.operator_summaries_posted += 1;
        self.operator_summaries.insert(summary_id.clone(), summary);
        Ok(summary_id)
    }

    pub fn operator_collateral_coverage_bps(&self, operator_id: &str) -> u64 {
        let reserved = self
            .forward_books
            .values()
            .filter(|book| book.operator_id == operator_id)
            .map(|book| book.notional_fee_units)
            .sum::<u64>();
        let locked = self
            .forward_books
            .values()
            .filter(|book| book.operator_id == operator_id)
            .filter_map(|book| {
                self.collateral_commitments
                    .get(&book.collateral_commitment_id)
            })
            .map(|commitment| commitment.reserved_fee_units)
            .sum::<u64>();
        if reserved == 0 {
            MAX_BPS
        } else {
            locked.saturating_mul(MAX_BPS) / reserved
        }
    }

    pub fn expire_due(&mut self, height: u64) -> Result<u64> {
        let due = self
            .expiries
            .iter()
            .filter(|(_, expiry)| !expiry.executed && expiry.due_height <= height)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in &due {
            if let Some(expiry) = self.expiries.get_mut(id) {
                expiry.executed = true;
            }
        }
        self.current_height = self.current_height.max(height);
        Ok(due.len() as u64)
    }

    fn schedule_expiry(
        &mut self,
        kind: ExpiryKind,
        subject_id: &str,
        due_height: u64,
        grace_height: u64,
    ) -> Result<String> {
        ensure_capacity("expiry", self.expiries.len(), self.config.max_expiries)?;
        let id = expiry_id(kind, subject_id, due_height);
        if self.expiries.contains_key(&id) {
            return Ok(id);
        }
        let expiry = Expiry {
            id: id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            due_height,
            grace_height,
            executed: false,
            action_root: sample_root("EXPIRY-ACTION", subject_id),
        };
        self.counters.expiries_scheduled += 1;
        self.expiries.insert(id.clone(), expiry);
        Ok(id)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": self.roots().public_record(),
            "counts": {
                "forward_books": self.forward_books.len(),
                "fee_curves": self.fee_curves.len(),
                "collateral_commitments": self.collateral_commitments.len(),
                "pq_attestations": self.pq_attestations.len(),
                "expiries": self.expiries.len(),
                "settlements": self.settlements.len(),
                "rebates": self.rebates.len(),
                "operator_summaries": self.operator_summaries.len(),
                "spent_nullifiers": self.spent_nullifiers.len(),
            },
            "operator_safe": self.operator_safe_summary(),
        })
    }

    pub fn operator_safe_summary(&self) -> Value {
        json!({
            "open_forward_books": self.forward_books.values().filter(|book| book.status.accepts_orders()).count(),
            "active_fee_curves": self.fee_curves.values().filter(|curve| curve.status == CurveStatus::Active).count(),
            "locked_collateral_commitments": self.collateral_commitments.values().filter(|commitment| commitment.status.spendable()).count(),
            "accepted_pq_attestations": self.pq_attestations.values().filter(|attestation| attestation.status == AttestationStatus::Accepted).count(),
            "pending_settlements": self.settlements.values().filter(|settlement| !matches!(settlement.status, SettlementStatus::Settled | SettlementStatus::Rebated | SettlementStatus::Failed | SettlementStatus::Expired)).count(),
            "routed_rebates": self.rebates.values().filter(|rebate| rebate.status == RebateStatus::Routed).count(),
            "average_settlement_latency_blocks": if self.counters.settlements_finalized == 0 { 0 } else { self.counters.settlement_latency_blocks_total / self.counters.settlements_finalized },
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}

pub fn devnet() -> State {
    State::devnet()
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

pub fn forward_book_id(
    operator_id: &str,
    lane_id: &str,
    side: ForwardSide,
    opened_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-BOOK-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(lane_id),
            HashPart::Str(side.as_str()),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn fee_curve_id(
    operator_id: &str,
    kind: CurveKind,
    base_fee_piconero: u64,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-CURVE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(base_fee_piconero),
            HashPart::U64(valid_from_height),
        ],
        32,
    )
}

pub fn collateral_commitment_id(
    owner_commitment: &str,
    asset_id: &str,
    amount_commitment: &str,
    nullifier: &str,
    lock_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-COLLATERAL-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(amount_commitment),
            HashPart::Str(nullifier),
            HashPart::U64(lock_height),
        ],
        32,
    )
}

pub fn pq_attestation_id(
    oracle_id: &str,
    kind: AttestationKind,
    subject_id: &str,
    attested_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(oracle_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(attested_height),
        ],
        32,
    )
}

pub fn expiry_id(kind: ExpiryKind, subject_id: &str, due_height: u64) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-EXPIRY-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(due_height),
        ],
        32,
    )
}

pub fn settlement_id(
    book_id: &str,
    curve_id: &str,
    proof_units: u64,
    queued_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-SETTLEMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(book_id),
            HashPart::Str(curve_id),
            HashPart::U64(proof_units),
            HashPart::U64(queued_height),
        ],
        32,
    )
}

pub fn rebate_route_id(
    settlement_id: &str,
    book_id: &str,
    amount_piconero: u64,
    routed_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-REBATE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(settlement_id),
            HashPart::Str(book_id),
            HashPart::U64(amount_piconero),
            HashPart::U64(routed_height),
        ],
        32,
    )
}

pub fn operator_summary_id(operator_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "PROOF-FEE-FORWARD-OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn sample_root(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    record_root("PROOF-FEE-FORWARD-STATE-ROOT", record)
}

pub fn map_public_record_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"})),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

pub fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

pub fn ensure_known<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("unknown {label} {key}"))
    }
}
