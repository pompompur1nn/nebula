use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-runtime-state-commitment-bus-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const CONFIDENTIALITY_SUITE: &str = "view-key-scoped-commitments+range-proof-budget-v1";
pub const DEFAULT_EPOCH: u64 = 1;
pub const DEFAULT_SLOT: u64 = 12_000_000;
pub const DEFAULT_L2_HEIGHT: u64 = 1_924_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_706_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_ENVELOPES_PER_BATCH: usize = 2_048;
pub const DEFAULT_MAX_BATCH_WEIGHT: u64 = 4_000_000;
pub const DEFAULT_MIN_DA_REPLICATION: u16 = 3;
pub const DEFAULT_MAX_CURSOR_GAP: u64 = 128;
pub const DEFAULT_BASE_FEE_UNITS: u64 = 2;
pub const DEFAULT_PROOF_FEE_UNITS: u64 = 3;
pub const DEFAULT_DA_FEE_UNITS: u64 = 2;
pub const DEFAULT_BRIDGE_FEE_UNITS: u64 = 4;
pub const DEFAULT_REBATE_BPS: u16 = 1_500;
pub const DEFAULT_PRIVACY_BUDGET_PER_EPOCH: u64 = 1_000_000;
pub const MAX_BPS: u16 = 10_000;

const D_CONFIG: &str = "PL2-PQ-XR-STATE-BUS-CONFIG";
const D_COUNTERS: &str = "PL2-PQ-XR-STATE-BUS-COUNTERS";
const D_ROOTS: &str = "PL2-PQ-XR-STATE-BUS-ROOTS";
const D_STATE: &str = "PL2-PQ-XR-STATE-BUS-STATE";
const D_ENVELOPES: &str = "PL2-PQ-XR-STATE-BUS-ENVELOPES";
const D_LANES: &str = "PL2-PQ-XR-STATE-BUS-LANES";
const D_PROOFS: &str = "PL2-PQ-XR-STATE-BUS-PROOFS";
const D_CONFLICTS: &str = "PL2-PQ-XR-STATE-BUS-CONFLICTS";
const D_BATCHES: &str = "PL2-PQ-XR-STATE-BUS-BATCHES";
const D_FEES: &str = "PL2-PQ-XR-STATE-BUS-FEES";
const D_PRIVACY: &str = "PL2-PQ-XR-STATE-BUS-PRIVACY";
const D_CONTRACTS: &str = "PL2-PQ-XR-STATE-BUS-CONTRACTS";
const D_TOKEN_BRIDGES: &str = "PL2-PQ-XR-STATE-BUS-TOKEN-BRIDGES";
const D_LIQUIDITY: &str = "PL2-PQ-XR-STATE-BUS-LIQUIDITY";
const D_MONERO: &str = "PL2-PQ-XR-STATE-BUS-MONERO";
const D_RECEIPTS: &str = "PL2-PQ-XR-STATE-BUS-RECEIPTS";
const D_WITNESSES: &str = "PL2-PQ-XR-STATE-BUS-WITNESSES";
const D_DA: &str = "PL2-PQ-XR-STATE-BUS-DA";
const D_GOVERNANCE: &str = "PL2-PQ-XR-STATE-BUS-GOVERNANCE";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDomain {
    Contract,
    TokenBridge,
    LiquidityLane,
    MoneroBridge,
    ExecutionReceipt,
    WitnessBundle,
    DataAvailability,
    Governance,
    FeeRouter,
    Watchtower,
}

impl RuntimeDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::TokenBridge => "token_bridge",
            Self::LiquidityLane => "liquidity_lane",
            Self::MoneroBridge => "monero_bridge",
            Self::ExecutionReceipt => "execution_receipt",
            Self::WitnessBundle => "witness_bundle",
            Self::DataAvailability => "data_availability",
            Self::Governance => "governance",
            Self::FeeRouter => "fee_router",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    ContractState,
    TokenBridgeRoot,
    LiquidityLaneRoot,
    MoneroBridgeRoot,
    ExecutionReceiptRoot,
    WitnessBundleRoot,
    DataAvailabilityVoucher,
    GovernanceUpgradeRoot,
    FeeAccountingRoot,
    PrivacyBudgetRoot,
}

impl EnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractState => "contract_state",
            Self::TokenBridgeRoot => "token_bridge_root",
            Self::LiquidityLaneRoot => "liquidity_lane_root",
            Self::MoneroBridgeRoot => "monero_bridge_root",
            Self::ExecutionReceiptRoot => "execution_receipt_root",
            Self::WitnessBundleRoot => "witness_bundle_root",
            Self::DataAvailabilityVoucher => "data_availability_voucher",
            Self::GovernanceUpgradeRoot => "governance_upgrade_root",
            Self::FeeAccountingRoot => "fee_accounting_root",
            Self::PrivacyBudgetRoot => "privacy_budget_root",
        }
    }

    pub fn fee_weight(self) -> u64 {
        match self {
            Self::ContractState => 5,
            Self::TokenBridgeRoot => 7,
            Self::LiquidityLaneRoot => 6,
            Self::MoneroBridgeRoot => 9,
            Self::ExecutionReceiptRoot => 4,
            Self::WitnessBundleRoot => 8,
            Self::DataAvailabilityVoucher => 3,
            Self::GovernanceUpgradeRoot => 10,
            Self::FeeAccountingRoot => 2,
            Self::PrivacyBudgetRoot => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Contract,
    TokenBridge,
    Liquidity,
    Monero,
    Receipt,
    Witness,
    DataAvailability,
    Governance,
    Mixed,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::TokenBridge => "token_bridge",
            Self::Liquidity => "liquidity",
            Self::Monero => "monero",
            Self::Receipt => "receipt",
            Self::Witness => "witness",
            Self::DataAvailability => "data_availability",
            Self::Governance => "governance",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Draft,
    Accepted,
    Proven,
    Batched,
    Committed,
    Conflicted,
    Superseded,
    Rejected,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Accepted => "accepted",
            Self::Proven => "proven",
            Self::Batched => "batched",
            Self::Committed => "committed",
            Self::Conflicted => "conflicted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Draft | Self::Accepted | Self::Proven)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    MerkleInclusion,
    SparseMerkleInclusion,
    RecursiveStark,
    LatticeAccumulator,
    HashBasedSignature,
    DaAvailability,
    MoneroReserve,
    GovernanceQuorum,
}

impl ProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MerkleInclusion => "merkle_inclusion",
            Self::SparseMerkleInclusion => "sparse_merkle_inclusion",
            Self::RecursiveStark => "recursive_stark",
            Self::LatticeAccumulator => "lattice_accumulator",
            Self::HashBasedSignature => "hash_based_signature",
            Self::DaAvailability => "da_availability",
            Self::MoneroReserve => "monero_reserve",
            Self::GovernanceQuorum => "governance_quorum",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    CursorGap,
    DuplicateNullifier,
    RootEquivocation,
    FeeOverclaim,
    PrivacyBudgetExceeded,
    DaVoucherMismatch,
    GovernanceFork,
    MoneroReorg,
}

impl ConflictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CursorGap => "cursor_gap",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::RootEquivocation => "root_equivocation",
            Self::FeeOverclaim => "fee_overclaim",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::DaVoucherMismatch => "da_voucher_mismatch",
            Self::GovernanceFork => "governance_fork",
            Self::MoneroReorg => "monero_reorg",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Open,
    AcceptedCanonical,
    SupersededByHigherSequence,
    Quarantined,
    Rejected,
}

impl ResolutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::AcceptedCanonical => "accepted_canonical",
            Self::SupersededByHigherSequence => "superseded_by_higher_sequence",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeKind {
    Base,
    Proof,
    DataAvailability,
    Bridge,
    Privacy,
    Governance,
    Rebate,
    Slash,
}

impl FeeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Proof => "proof",
            Self::DataAvailability => "data_availability",
            Self::Bridge => "bridge",
            Self::Privacy => "privacy",
            Self::Governance => "governance",
            Self::Rebate => "rebate",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub confidentiality_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_envelopes_per_batch: usize,
    pub max_batch_weight: u64,
    pub max_cursor_gap: u64,
    pub min_da_replication: u16,
    pub base_fee_units: u64,
    pub proof_fee_units: u64,
    pub da_fee_units: u64,
    pub bridge_fee_units: u64,
    pub rebate_bps: u16,
    pub privacy_budget_per_epoch: u64,
    pub require_inclusion_proofs: bool,
    pub require_da_vouchers: bool,
    pub require_monero_anchor: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            confidentiality_suite: CONFIDENTIALITY_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_envelopes_per_batch: DEFAULT_MAX_ENVELOPES_PER_BATCH,
            max_batch_weight: DEFAULT_MAX_BATCH_WEIGHT,
            max_cursor_gap: DEFAULT_MAX_CURSOR_GAP,
            min_da_replication: DEFAULT_MIN_DA_REPLICATION,
            base_fee_units: DEFAULT_BASE_FEE_UNITS,
            proof_fee_units: DEFAULT_PROOF_FEE_UNITS,
            da_fee_units: DEFAULT_DA_FEE_UNITS,
            bridge_fee_units: DEFAULT_BRIDGE_FEE_UNITS,
            rebate_bps: DEFAULT_REBATE_BPS,
            privacy_budget_per_epoch: DEFAULT_PRIVACY_BUDGET_PER_EPOCH,
            require_inclusion_proofs: true,
            require_da_vouchers: true,
            require_monero_anchor: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_nonempty("chain_id", &self.chain_id)?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require(self.hash_suite == HASH_SUITE, "hash suite mismatch")?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security bits below floor",
        )?;
        require(
            self.min_privacy_set_size >= 128,
            "privacy set size below floor",
        )?;
        require(
            self.max_envelopes_per_batch > 0,
            "batch envelope limit must be positive",
        )?;
        require(
            self.max_batch_weight > 0,
            "batch weight limit must be positive",
        )?;
        require(self.max_cursor_gap > 0, "cursor gap limit must be positive")?;
        require(
            self.min_da_replication > 0,
            "da replication must be positive",
        )?;
        require(self.rebate_bps <= MAX_BPS, "rebate exceeds max bps")?;
        require(
            self.privacy_budget_per_epoch > 0,
            "privacy budget must be positive",
        )
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_lane_index: u64,
    pub next_envelope_index: u64,
    pub next_proof_index: u64,
    pub next_conflict_index: u64,
    pub next_batch_index: u64,
    pub next_fee_index: u64,
    pub next_privacy_index: u64,
    pub next_component_index: u64,
    pub envelopes_accepted: u64,
    pub envelopes_committed: u64,
    pub proofs_attached: u64,
    pub conflicts_opened: u64,
    pub conflicts_resolved: u64,
    pub batches_built: u64,
    pub fee_charges: u64,
    pub privacy_charges: u64,
    pub total_fee_units: u128,
    pub total_rebate_units: u128,
    pub total_privacy_units: u128,
    pub total_weight: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_lane_index: 1,
            next_envelope_index: 1,
            next_proof_index: 1,
            next_conflict_index: 1,
            next_batch_index: 1,
            next_fee_index: 1,
            next_privacy_index: 1,
            next_component_index: 1,
            envelopes_accepted: 0,
            envelopes_committed: 0,
            proofs_attached: 0,
            conflicts_opened: 0,
            conflicts_resolved: 0,
            batches_built: 0,
            fee_charges: 0,
            privacy_charges: 0,
            total_fee_units: 0,
            total_rebate_units: 0,
            total_privacy_units: 0,
            total_weight: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lane_root: String,
    pub envelope_root: String,
    pub inclusion_proof_root: String,
    pub conflict_root: String,
    pub batch_root: String,
    pub fee_root: String,
    pub privacy_budget_root: String,
    pub contract_root: String,
    pub token_bridge_root: String,
    pub liquidity_lane_root: String,
    pub monero_bridge_root: String,
    pub execution_receipt_root: String,
    pub witness_bundle_root: String,
    pub da_voucher_root: String,
    pub governance_upgrade_root: String,
}

impl Roots {
    pub fn from_state(state: &State) -> Self {
        Self {
            config_root: state.config.root(),
            counters_root: state.counters.root(),
            lane_root: map_root(D_LANES, &state.lanes),
            envelope_root: map_root(D_ENVELOPES, &state.envelopes),
            inclusion_proof_root: map_root(D_PROOFS, &state.inclusion_proofs),
            conflict_root: map_root(D_CONFLICTS, &state.conflicts),
            batch_root: map_root(D_BATCHES, &state.batches),
            fee_root: map_root(D_FEES, &state.fee_charges),
            privacy_budget_root: map_root(D_PRIVACY, &state.privacy_budgets),
            contract_root: map_root(D_CONTRACTS, &state.contract_roots),
            token_bridge_root: map_root(D_TOKEN_BRIDGES, &state.token_bridge_roots),
            liquidity_lane_root: map_root(D_LIQUIDITY, &state.liquidity_lane_roots),
            monero_bridge_root: map_root(D_MONERO, &state.monero_bridge_roots),
            execution_receipt_root: map_root(D_RECEIPTS, &state.execution_receipts),
            witness_bundle_root: map_root(D_WITNESSES, &state.witness_bundles),
            da_voucher_root: map_root(D_DA, &state.da_vouchers),
            governance_upgrade_root: map_root(D_GOVERNANCE, &state.governance_upgrade_roots),
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneCursor {
    pub lane_id: String,
    pub lane_kind: LaneKind,
    pub runtime_domain: RuntimeDomain,
    pub operator_commitment: String,
    pub previous_cursor_root: String,
    pub latest_envelope_id: Option<String>,
    pub latest_state_root: String,
    pub sequence: u64,
    pub slot: u64,
    pub epoch: u64,
    pub pending_envelopes: BTreeSet<String>,
    pub committed_envelopes: BTreeSet<String>,
    pub nullifier_set_root: String,
    pub privacy_scope: String,
    pub max_weight: u64,
    pub active: bool,
}

impl LaneCursor {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("LANE-CURSOR", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateCommitmentEnvelope {
    pub envelope_id: String,
    pub lane_id: String,
    pub kind: EnvelopeKind,
    pub source_runtime: RuntimeDomain,
    pub target_runtime: RuntimeDomain,
    pub subject_id: String,
    pub previous_state_root: String,
    pub new_state_root: String,
    pub public_state_root: String,
    pub private_state_commitment: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub da_voucher_id: Option<String>,
    pub fee_payer_commitment: String,
    pub sponsor_commitment: Option<String>,
    pub sequence: u64,
    pub slot: u64,
    pub epoch: u64,
    pub weight: u64,
    pub privacy_cost: u64,
    pub pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub dependency_envelopes: BTreeSet<String>,
    pub tags: BTreeSet<String>,
    pub status: EnvelopeStatus,
}

impl StateCommitmentEnvelope {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("STATE-COMMITMENT-ENVELOPE", &self.public_record())
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.lane_id == other.lane_id
            && self.sequence == other.sequence
            && self.new_state_root != other.new_state_root
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InclusionProof {
    pub proof_id: String,
    pub envelope_id: String,
    pub proof_kind: ProofKind,
    pub leaf_id: String,
    pub leaf_root: String,
    pub expected_root: String,
    pub path_root: String,
    pub verifier_key_commitment: String,
    pub transcript_root: String,
    pub attester_commitments: BTreeSet<String>,
    pub weight: u64,
    pub verified: bool,
}

impl InclusionProof {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("INCLUSION-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConflictRecord {
    pub conflict_id: String,
    pub kind: ConflictKind,
    pub lane_id: String,
    pub envelope_ids: BTreeSet<String>,
    pub canonical_envelope_id: Option<String>,
    pub evidence_root: String,
    pub opened_slot: u64,
    pub resolved_slot: Option<u64>,
    pub status: ResolutionStatus,
    pub resolver_commitment: Option<String>,
}

impl ConflictRecord {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONFLICT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitmentBatch {
    pub batch_id: String,
    pub lane_ids: BTreeSet<String>,
    pub envelope_ids: BTreeSet<String>,
    pub envelope_root: String,
    pub proof_root: String,
    pub fee_root: String,
    pub privacy_budget_root: String,
    pub public_state_root: String,
    pub previous_global_root: String,
    pub new_global_root: String,
    pub builder_commitment: String,
    pub sequence: u64,
    pub epoch: u64,
    pub slot: u64,
    pub total_weight: u64,
    pub total_fee_units: u64,
    pub committed: bool,
}

impl CommitmentBatch {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("COMMITMENT-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCharge {
    pub fee_id: String,
    pub envelope_id: String,
    pub lane_id: String,
    pub kind: FeeKind,
    pub payer_commitment: String,
    pub sponsor_commitment: Option<String>,
    pub amount_units: u64,
    pub rebate_units: u64,
    pub settlement_root: String,
    pub paid: bool,
}

impl FeeCharge {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("FEE-CHARGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetAccount {
    pub privacy_id: String,
    pub scope: String,
    pub epoch: u64,
    pub budget_units: u64,
    pub spent_units: u64,
    pub reserved_units: u64,
    pub min_anonymity_set: u64,
    pub nullifier_root: String,
    pub sealed_counter_root: String,
}

impl PrivacyBudgetAccount {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVACY-BUDGET", &self.public_record())
    }

    pub fn remaining(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.spent_units + self.reserved_units)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractStateRoot {
    pub contract_id: String,
    pub class_tag: String,
    pub storage_root: String,
    pub event_root: String,
    pub token_root: String,
    pub policy_root: String,
    pub latest_envelope_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenBridgeRoot {
    pub bridge_id: String,
    pub asset_id: String,
    pub source_runtime: String,
    pub target_runtime: String,
    pub mint_burn_root: String,
    pub reserve_root: String,
    pub nullifier_root: String,
    pub latest_envelope_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityLaneRoot {
    pub lane_id: String,
    pub pool_root: String,
    pub position_root: String,
    pub clearing_root: String,
    pub slippage_guard_root: String,
    pub latest_envelope_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroBridgeRoot {
    pub bridge_id: String,
    pub monero_height: u64,
    pub output_root: String,
    pub key_image_root: String,
    pub reserve_commitment_root: String,
    pub latest_envelope_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptRoot {
    pub receipt_id: String,
    pub contract_id: String,
    pub call_root: String,
    pub state_diff_root: String,
    pub gas_root: String,
    pub event_root: String,
    pub latest_envelope_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessBundleRoot {
    pub bundle_id: String,
    pub envelope_ids: BTreeSet<String>,
    pub witness_root: String,
    pub recursive_proof_root: String,
    pub locality_zone_root: String,
    pub latest_envelope_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataAvailabilityVoucher {
    pub voucher_id: String,
    pub blob_root: String,
    pub erasure_root: String,
    pub provider_commitments: BTreeSet<String>,
    pub replication_factor: u16,
    pub fee_units: u64,
    pub expiry_slot: u64,
    pub redeemed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceUpgradeRoot {
    pub upgrade_id: String,
    pub proposal_root: String,
    pub vote_root: String,
    pub timelock_root: String,
    pub new_verifier_root: String,
    pub activation_epoch: u64,
    pub latest_envelope_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub epoch: u64,
    pub slot: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub global_state_root: String,
    pub lanes: BTreeMap<String, LaneCursor>,
    pub envelopes: BTreeMap<String, StateCommitmentEnvelope>,
    pub inclusion_proofs: BTreeMap<String, InclusionProof>,
    pub conflicts: BTreeMap<String, ConflictRecord>,
    pub batches: BTreeMap<String, CommitmentBatch>,
    pub fee_charges: BTreeMap<String, FeeCharge>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetAccount>,
    pub contract_roots: BTreeMap<String, ContractStateRoot>,
    pub token_bridge_roots: BTreeMap<String, TokenBridgeRoot>,
    pub liquidity_lane_roots: BTreeMap<String, LiquidityLaneRoot>,
    pub monero_bridge_roots: BTreeMap<String, MoneroBridgeRoot>,
    pub execution_receipts: BTreeMap<String, ExecutionReceiptRoot>,
    pub witness_bundles: BTreeMap<String, WitnessBundleRoot>,
    pub da_vouchers: BTreeMap<String, DataAvailabilityVoucher>,
    pub governance_upgrade_roots: BTreeMap<String, GovernanceUpgradeRoot>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::new(),
            epoch: DEFAULT_EPOCH,
            slot: DEFAULT_SLOT,
            l2_height: DEFAULT_L2_HEIGHT,
            monero_height: DEFAULT_MONERO_HEIGHT,
            global_state_root: empty_root("GENESIS-GLOBAL"),
            lanes: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            inclusion_proofs: BTreeMap::new(),
            conflicts: BTreeMap::new(),
            batches: BTreeMap::new(),
            fee_charges: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            contract_roots: BTreeMap::new(),
            token_bridge_roots: BTreeMap::new(),
            liquidity_lane_roots: BTreeMap::new(),
            monero_bridge_roots: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            witness_bundles: BTreeMap::new(),
            da_vouchers: BTreeMap::new(),
            governance_upgrade_roots: BTreeMap::new(),
        };
        let _ = state.open_lane(
            LaneKind::Contract,
            RuntimeDomain::Contract,
            "devnet-contract-operator",
            "devnet-contract-privacy",
            DEFAULT_MAX_BATCH_WEIGHT,
        );
        let _ = state.open_lane(
            LaneKind::TokenBridge,
            RuntimeDomain::TokenBridge,
            "devnet-token-bridge-operator",
            "devnet-token-bridge-privacy",
            DEFAULT_MAX_BATCH_WEIGHT,
        );
        let _ = state.open_lane(
            LaneKind::Liquidity,
            RuntimeDomain::LiquidityLane,
            "devnet-liquidity-operator",
            "devnet-liquidity-privacy",
            DEFAULT_MAX_BATCH_WEIGHT,
        );
        let _ = state.open_lane(
            LaneKind::Monero,
            RuntimeDomain::MoneroBridge,
            "devnet-monero-operator",
            "devnet-monero-privacy",
            DEFAULT_MAX_BATCH_WEIGHT,
        );
        state.global_state_root = state.roots().root();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(self.epoch > 0, "epoch must be positive")?;
        require(self.slot > 0, "slot must be positive")?;
        require(self.l2_height > 0, "l2 height must be positive")?;
        require(self.monero_height > 0, "monero height must be positive")?;
        require_nonempty("global_state_root", &self.global_state_root)
    }

    pub fn roots(&self) -> Roots {
        Roots::from_state(self)
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record_without_state_root())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "epoch": self.epoch,
            "slot": self.slot,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "global_state_root": self.global_state_root,
            "roots": self.roots().public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_state(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "epoch": self.epoch,
            "slot": self.slot,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "state_root": self.state_root(),
            "global_state_root": self.global_state_root,
            "roots": self.roots().public_record(),
            "open_conflicts": self.open_conflict_ids(),
            "lane_count": self.lanes.len(),
            "envelope_count": self.envelopes.len(),
            "batch_count": self.batches.len(),
        })
    }

    pub fn open_lane(
        &mut self,
        lane_kind: LaneKind,
        runtime_domain: RuntimeDomain,
        operator_commitment: &str,
        privacy_scope: &str,
        max_weight: u64,
    ) -> Result<String> {
        require_nonempty("operator_commitment", operator_commitment)?;
        require_nonempty("privacy_scope", privacy_scope)?;
        require(max_weight > 0, "lane max weight must be positive")?;
        let sequence = self.counters.next_lane_index;
        let lane_id = lane_id(lane_kind, runtime_domain, operator_commitment, sequence);
        require(!self.lanes.contains_key(&lane_id), "lane already exists")?;
        let cursor = LaneCursor {
            lane_id: lane_id.clone(),
            lane_kind,
            runtime_domain,
            operator_commitment: operator_commitment.to_string(),
            previous_cursor_root: empty_root("LANE-PREVIOUS-CURSOR"),
            latest_envelope_id: None,
            latest_state_root: empty_root("LANE-STATE"),
            sequence: 0,
            slot: self.slot,
            epoch: self.epoch,
            pending_envelopes: BTreeSet::new(),
            committed_envelopes: BTreeSet::new(),
            nullifier_set_root: empty_root("LANE-NULLIFIERS"),
            privacy_scope: privacy_scope.to_string(),
            max_weight,
            active: true,
        };
        self.lanes.insert(lane_id.clone(), cursor);
        self.ensure_privacy_account(privacy_scope, self.epoch)?;
        self.counters.next_lane_index += 1;
        Ok(lane_id)
    }

    pub fn submit_envelope(
        &mut self,
        lane_id: &str,
        kind: EnvelopeKind,
        target_runtime: RuntimeDomain,
        subject_id: &str,
        new_state_root: &str,
        public_state_root: &str,
        private_state_commitment: &str,
        nullifier_root: &str,
        witness_root: &str,
        fee_payer_commitment: &str,
        sponsor_commitment: Option<String>,
        weight: u64,
        privacy_cost: u64,
        dependency_envelopes: BTreeSet<String>,
        tags: BTreeSet<String>,
    ) -> Result<String> {
        require_nonempty("lane_id", lane_id)?;
        require_nonempty("subject_id", subject_id)?;
        require_nonempty("new_state_root", new_state_root)?;
        require_nonempty("public_state_root", public_state_root)?;
        require_nonempty("private_state_commitment", private_state_commitment)?;
        require_nonempty("nullifier_root", nullifier_root)?;
        require_nonempty("witness_root", witness_root)?;
        require_nonempty("fee_payer_commitment", fee_payer_commitment)?;
        require(weight > 0, "envelope weight must be positive")?;
        let lane_snapshot = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| unknown("lane", lane_id))?
            .clone();
        require(lane_snapshot.active, "lane is inactive")?;
        require(
            weight <= lane_snapshot.max_weight,
            "envelope exceeds lane max weight",
        )?;
        for dependency_id in &dependency_envelopes {
            require(
                self.envelopes.contains_key(dependency_id),
                "dependency envelope is unknown",
            )?;
        }
        self.reserve_privacy_units(&lane_snapshot.privacy_scope, privacy_cost)?;
        let next_sequence = lane_snapshot.sequence + 1;
        let envelope_id = envelope_id(lane_id, subject_id, kind, next_sequence);
        require(
            !self.envelopes.contains_key(&envelope_id),
            "envelope already exists",
        )?;
        let envelope = StateCommitmentEnvelope {
            envelope_id: envelope_id.clone(),
            lane_id: lane_id.to_string(),
            kind,
            source_runtime: lane_snapshot.runtime_domain,
            target_runtime,
            subject_id: subject_id.to_string(),
            previous_state_root: lane_snapshot.latest_state_root.clone(),
            new_state_root: new_state_root.to_string(),
            public_state_root: public_state_root.to_string(),
            private_state_commitment: private_state_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            witness_root: witness_root.to_string(),
            da_voucher_id: None,
            fee_payer_commitment: fee_payer_commitment.to_string(),
            sponsor_commitment,
            sequence: next_sequence,
            slot: self.slot,
            epoch: self.epoch,
            weight,
            privacy_cost,
            pq_security_bits: self.config.min_pq_security_bits,
            min_privacy_set_size: self.config.min_privacy_set_size,
            dependency_envelopes,
            tags,
            status: EnvelopeStatus::Accepted,
        };
        self.envelopes.insert(envelope_id.clone(), envelope);
        self.detect_envelope_conflicts(&envelope_id)?;
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.previous_cursor_root = lane.root();
            lane.sequence = next_sequence;
            lane.latest_envelope_id = Some(envelope_id.clone());
            lane.latest_state_root = new_state_root.to_string();
            lane.pending_envelopes.insert(envelope_id.clone());
            lane.nullifier_set_root = nullifier_root.to_string();
            lane.slot = self.slot;
            lane.epoch = self.epoch;
        }
        self.counters.next_envelope_index += 1;
        self.counters.envelopes_accepted += 1;
        self.counters.total_weight += weight as u128;
        self.charge_envelope_fees(&envelope_id)?;
        Ok(envelope_id)
    }

    pub fn attach_da_voucher(
        &mut self,
        envelope_id: &str,
        blob_root: &str,
        erasure_root: &str,
        provider_commitments: BTreeSet<String>,
        replication_factor: u16,
        fee_units: u64,
        expiry_slot: u64,
    ) -> Result<String> {
        require_nonempty("envelope_id", envelope_id)?;
        require_nonempty("blob_root", blob_root)?;
        require_nonempty("erasure_root", erasure_root)?;
        require(
            replication_factor >= self.config.min_da_replication,
            "da replication below configured floor",
        )?;
        require(
            expiry_slot > self.slot,
            "da voucher expiry must be in the future",
        )?;
        let voucher_sequence = self.counters.next_component_index;
        let voucher_id = da_voucher_id(envelope_id, blob_root, voucher_sequence);
        require(
            !self.da_vouchers.contains_key(&voucher_id),
            "da voucher already exists",
        )?;
        let voucher = DataAvailabilityVoucher {
            voucher_id: voucher_id.clone(),
            blob_root: blob_root.to_string(),
            erasure_root: erasure_root.to_string(),
            provider_commitments,
            replication_factor,
            fee_units,
            expiry_slot,
            redeemed: false,
        };
        self.da_vouchers.insert(voucher_id.clone(), voucher);
        let envelope = self
            .envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| unknown("envelope", envelope_id))?;
        envelope.da_voucher_id = Some(voucher_id.clone());
        self.counters.next_component_index += 1;
        Ok(voucher_id)
    }

    pub fn attach_inclusion_proof(
        &mut self,
        envelope_id: &str,
        proof_kind: ProofKind,
        leaf_id: &str,
        leaf_root: &str,
        expected_root: &str,
        path_root: &str,
        verifier_key_commitment: &str,
        transcript_root: &str,
        attester_commitments: BTreeSet<String>,
        weight: u64,
    ) -> Result<String> {
        require(
            self.envelopes.contains_key(envelope_id),
            "proof references unknown envelope",
        )?;
        require_nonempty("leaf_id", leaf_id)?;
        require_nonempty("leaf_root", leaf_root)?;
        require_nonempty("expected_root", expected_root)?;
        require_nonempty("path_root", path_root)?;
        require_nonempty("verifier_key_commitment", verifier_key_commitment)?;
        require_nonempty("transcript_root", transcript_root)?;
        require(weight > 0, "proof weight must be positive")?;
        let index = self.counters.next_proof_index;
        let proof_id = inclusion_proof_id(envelope_id, proof_kind, leaf_id, index);
        let verified = leaf_root == expected_root || !attester_commitments.is_empty();
        let proof = InclusionProof {
            proof_id: proof_id.clone(),
            envelope_id: envelope_id.to_string(),
            proof_kind,
            leaf_id: leaf_id.to_string(),
            leaf_root: leaf_root.to_string(),
            expected_root: expected_root.to_string(),
            path_root: path_root.to_string(),
            verifier_key_commitment: verifier_key_commitment.to_string(),
            transcript_root: transcript_root.to_string(),
            attester_commitments,
            weight,
            verified,
        };
        self.inclusion_proofs.insert(proof_id.clone(), proof);
        if verified {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                if envelope.status == EnvelopeStatus::Accepted {
                    envelope.status = EnvelopeStatus::Proven;
                }
            }
        }
        self.counters.next_proof_index += 1;
        self.counters.proofs_attached += 1;
        Ok(proof_id)
    }

    pub fn build_batch(
        &mut self,
        builder_commitment: &str,
        envelope_ids: BTreeSet<String>,
    ) -> Result<String> {
        require_nonempty("builder_commitment", builder_commitment)?;
        require(!envelope_ids.is_empty(), "batch requires envelopes")?;
        require(
            envelope_ids.len() <= self.config.max_envelopes_per_batch,
            "batch has too many envelopes",
        )?;
        let mut lane_ids = BTreeSet::new();
        let mut total_weight = 0u64;
        let mut total_fee_units = 0u64;
        for envelope_id in &envelope_ids {
            let envelope = self
                .envelopes
                .get(envelope_id)
                .ok_or_else(|| unknown("envelope", envelope_id))?;
            require(
                envelope.status == EnvelopeStatus::Proven,
                "batch envelope is not proven",
            )?;
            if self.config.require_da_vouchers {
                require(
                    envelope.da_voucher_id.is_some(),
                    "batch envelope lacks da voucher",
                )?;
            }
            total_weight = checked_add_u64(total_weight, envelope.weight)?;
            require(
                total_weight <= self.config.max_batch_weight,
                "batch exceeds max weight",
            )?;
            lane_ids.insert(envelope.lane_id.clone());
            total_fee_units =
                checked_add_u64(total_fee_units, self.envelope_fee_total(envelope_id))?;
        }
        let batch_index = self.counters.next_batch_index;
        let envelope_root = string_set_root("BATCH-ENVELOPES", &envelope_ids);
        let proof_root = filtered_map_root("BATCH-PROOFS", &self.inclusion_proofs, |proof| {
            envelope_ids.contains(&proof.envelope_id)
        });
        let fee_root = filtered_map_root("BATCH-FEES", &self.fee_charges, |fee| {
            envelope_ids.contains(&fee.envelope_id)
        });
        let privacy_budget_root = map_root(D_PRIVACY, &self.privacy_budgets);
        let public_state_root = envelope_public_state_root(&self.envelopes, &envelope_ids);
        let previous_global_root = self.global_state_root.clone();
        let new_global_root = batch_global_root(
            &previous_global_root,
            &envelope_root,
            &proof_root,
            &fee_root,
            &privacy_budget_root,
        );
        let batch_id = batch_id(&envelope_root, builder_commitment, batch_index);
        let batch = CommitmentBatch {
            batch_id: batch_id.clone(),
            lane_ids,
            envelope_ids: envelope_ids.clone(),
            envelope_root,
            proof_root,
            fee_root,
            privacy_budget_root,
            public_state_root,
            previous_global_root,
            new_global_root,
            builder_commitment: builder_commitment.to_string(),
            sequence: batch_index,
            epoch: self.epoch,
            slot: self.slot,
            total_weight,
            total_fee_units,
            committed: false,
        };
        for envelope_id in &envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Batched;
            }
        }
        self.batches.insert(batch_id.clone(), batch);
        self.counters.next_batch_index += 1;
        self.counters.batches_built += 1;
        Ok(batch_id)
    }

    pub fn commit_batch(&mut self, batch_id: &str) -> Result<String> {
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| unknown("batch", batch_id))?
            .clone();
        require(!batch.committed, "batch already committed")?;
        for envelope_id in &batch.envelope_ids {
            let envelope = self
                .envelopes
                .get(envelope_id)
                .ok_or_else(|| unknown("envelope", envelope_id))?
                .clone();
            require(
                envelope.status == EnvelopeStatus::Batched,
                "envelope is not batched",
            )?;
            self.apply_envelope_component(&envelope)?;
            self.finalize_privacy_units(&envelope.lane_id, envelope.privacy_cost)?;
            if let Some(lane) = self.lanes.get_mut(&envelope.lane_id) {
                lane.pending_envelopes.remove(envelope_id);
                lane.committed_envelopes.insert(envelope_id.clone());
            }
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Committed;
            }
            self.counters.envelopes_committed += 1;
        }
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.committed = true;
        }
        self.global_state_root = batch.new_global_root.clone();
        Ok(self.global_state_root.clone())
    }

    pub fn open_conflict(
        &mut self,
        kind: ConflictKind,
        lane_id: &str,
        envelope_ids: BTreeSet<String>,
        evidence_root: &str,
    ) -> Result<String> {
        require_nonempty("lane_id", lane_id)?;
        require_nonempty("evidence_root", evidence_root)?;
        require(
            self.lanes.contains_key(lane_id),
            "conflict references unknown lane",
        )?;
        require(
            envelope_ids.len() >= 2,
            "conflict requires at least two envelopes",
        )?;
        for envelope_id in &envelope_ids {
            require(
                self.envelopes.contains_key(envelope_id),
                "conflict references unknown envelope",
            )?;
        }
        let index = self.counters.next_conflict_index;
        let conflict_id = conflict_id(kind, lane_id, evidence_root, index);
        let record = ConflictRecord {
            conflict_id: conflict_id.clone(),
            kind,
            lane_id: lane_id.to_string(),
            envelope_ids: envelope_ids.clone(),
            canonical_envelope_id: None,
            evidence_root: evidence_root.to_string(),
            opened_slot: self.slot,
            resolved_slot: None,
            status: ResolutionStatus::Open,
            resolver_commitment: None,
        };
        for envelope_id in &envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                if envelope.status.open() {
                    envelope.status = EnvelopeStatus::Conflicted;
                }
            }
        }
        self.conflicts.insert(conflict_id.clone(), record);
        self.counters.next_conflict_index += 1;
        self.counters.conflicts_opened += 1;
        Ok(conflict_id)
    }

    pub fn resolve_conflict(
        &mut self,
        conflict_id: &str,
        canonical_envelope_id: &str,
        resolver_commitment: &str,
        status: ResolutionStatus,
    ) -> Result<()> {
        require_nonempty("resolver_commitment", resolver_commitment)?;
        require(
            matches!(
                status,
                ResolutionStatus::AcceptedCanonical
                    | ResolutionStatus::SupersededByHigherSequence
                    | ResolutionStatus::Quarantined
                    | ResolutionStatus::Rejected
            ),
            "resolution status must close the conflict",
        )?;
        let record = self
            .conflicts
            .get_mut(conflict_id)
            .ok_or_else(|| unknown("conflict", conflict_id))?;
        require(
            record.status == ResolutionStatus::Open,
            "conflict already resolved",
        )?;
        require(
            record.envelope_ids.contains(canonical_envelope_id),
            "canonical envelope is not in conflict set",
        )?;
        record.canonical_envelope_id = Some(canonical_envelope_id.to_string());
        record.resolved_slot = Some(self.slot);
        record.status = status;
        record.resolver_commitment = Some(resolver_commitment.to_string());
        for envelope_id in record.envelope_ids.clone() {
            if let Some(envelope) = self.envelopes.get_mut(&envelope_id) {
                if envelope_id == canonical_envelope_id {
                    envelope.status = EnvelopeStatus::Accepted;
                } else {
                    envelope.status = EnvelopeStatus::Superseded;
                }
            }
        }
        self.counters.conflicts_resolved += 1;
        Ok(())
    }

    pub fn advance_slot(&mut self, slots: u64) -> Result<u64> {
        require(slots > 0, "slot increment must be positive")?;
        self.slot = checked_add_u64(self.slot, slots)?;
        Ok(self.slot)
    }

    pub fn advance_epoch(&mut self) -> Result<u64> {
        self.epoch = checked_add_u64(self.epoch, 1)?;
        for budget in self.privacy_budgets.values_mut() {
            if budget.epoch < self.epoch {
                budget.reserved_units = 0;
            }
        }
        Ok(self.epoch)
    }

    pub fn register_contract_root(
        &mut self,
        contract_id: &str,
        class_tag: &str,
        storage_root: &str,
        event_root: &str,
        token_root: &str,
        policy_root: &str,
        envelope_id: &str,
    ) -> Result<()> {
        require(
            self.envelopes.contains_key(envelope_id),
            "contract root references unknown envelope",
        )?;
        let sequence = self
            .contract_roots
            .get(contract_id)
            .map(|root| root.sequence + 1)
            .unwrap_or(1);
        self.contract_roots.insert(
            contract_id.to_string(),
            ContractStateRoot {
                contract_id: contract_id.to_string(),
                class_tag: class_tag.to_string(),
                storage_root: storage_root.to_string(),
                event_root: event_root.to_string(),
                token_root: token_root.to_string(),
                policy_root: policy_root.to_string(),
                latest_envelope_id: envelope_id.to_string(),
                sequence,
            },
        );
        Ok(())
    }

    pub fn register_token_bridge_root(
        &mut self,
        bridge_id: &str,
        asset_id: &str,
        source_runtime: &str,
        target_runtime: &str,
        mint_burn_root: &str,
        reserve_root: &str,
        nullifier_root: &str,
        envelope_id: &str,
    ) -> Result<()> {
        require(
            self.envelopes.contains_key(envelope_id),
            "token bridge root references unknown envelope",
        )?;
        let sequence = self
            .token_bridge_roots
            .get(bridge_id)
            .map(|root| root.sequence + 1)
            .unwrap_or(1);
        self.token_bridge_roots.insert(
            bridge_id.to_string(),
            TokenBridgeRoot {
                bridge_id: bridge_id.to_string(),
                asset_id: asset_id.to_string(),
                source_runtime: source_runtime.to_string(),
                target_runtime: target_runtime.to_string(),
                mint_burn_root: mint_burn_root.to_string(),
                reserve_root: reserve_root.to_string(),
                nullifier_root: nullifier_root.to_string(),
                latest_envelope_id: envelope_id.to_string(),
                sequence,
            },
        );
        Ok(())
    }

    pub fn register_liquidity_lane_root(
        &mut self,
        lane_id: &str,
        pool_root: &str,
        position_root: &str,
        clearing_root: &str,
        slippage_guard_root: &str,
        envelope_id: &str,
    ) -> Result<()> {
        require(
            self.envelopes.contains_key(envelope_id),
            "liquidity root references unknown envelope",
        )?;
        let sequence = self
            .liquidity_lane_roots
            .get(lane_id)
            .map(|root| root.sequence + 1)
            .unwrap_or(1);
        self.liquidity_lane_roots.insert(
            lane_id.to_string(),
            LiquidityLaneRoot {
                lane_id: lane_id.to_string(),
                pool_root: pool_root.to_string(),
                position_root: position_root.to_string(),
                clearing_root: clearing_root.to_string(),
                slippage_guard_root: slippage_guard_root.to_string(),
                latest_envelope_id: envelope_id.to_string(),
                sequence,
            },
        );
        Ok(())
    }

    pub fn register_monero_bridge_root(
        &mut self,
        bridge_id: &str,
        monero_height: u64,
        output_root: &str,
        key_image_root: &str,
        reserve_commitment_root: &str,
        envelope_id: &str,
    ) -> Result<()> {
        require(
            self.envelopes.contains_key(envelope_id),
            "monero bridge root references unknown envelope",
        )?;
        require(
            monero_height >= self.monero_height,
            "monero height cannot move backward",
        )?;
        let sequence = self
            .monero_bridge_roots
            .get(bridge_id)
            .map(|root| root.sequence + 1)
            .unwrap_or(1);
        self.monero_bridge_roots.insert(
            bridge_id.to_string(),
            MoneroBridgeRoot {
                bridge_id: bridge_id.to_string(),
                monero_height,
                output_root: output_root.to_string(),
                key_image_root: key_image_root.to_string(),
                reserve_commitment_root: reserve_commitment_root.to_string(),
                latest_envelope_id: envelope_id.to_string(),
                sequence,
            },
        );
        self.monero_height = monero_height;
        Ok(())
    }

    pub fn register_execution_receipt_root(
        &mut self,
        receipt_id: &str,
        contract_id: &str,
        call_root: &str,
        state_diff_root: &str,
        gas_root: &str,
        event_root: &str,
        envelope_id: &str,
    ) -> Result<()> {
        require(
            self.envelopes.contains_key(envelope_id),
            "receipt root references unknown envelope",
        )?;
        let sequence = self
            .execution_receipts
            .get(receipt_id)
            .map(|root| root.sequence + 1)
            .unwrap_or(1);
        self.execution_receipts.insert(
            receipt_id.to_string(),
            ExecutionReceiptRoot {
                receipt_id: receipt_id.to_string(),
                contract_id: contract_id.to_string(),
                call_root: call_root.to_string(),
                state_diff_root: state_diff_root.to_string(),
                gas_root: gas_root.to_string(),
                event_root: event_root.to_string(),
                latest_envelope_id: envelope_id.to_string(),
                sequence,
            },
        );
        Ok(())
    }

    pub fn register_witness_bundle_root(
        &mut self,
        bundle_id: &str,
        envelope_ids: BTreeSet<String>,
        witness_root: &str,
        recursive_proof_root: &str,
        locality_zone_root: &str,
        envelope_id: &str,
    ) -> Result<()> {
        require(
            self.envelopes.contains_key(envelope_id),
            "witness bundle references unknown envelope",
        )?;
        for id in &envelope_ids {
            require(
                self.envelopes.contains_key(id),
                "witness bundle contains unknown envelope",
            )?;
        }
        let sequence = self
            .witness_bundles
            .get(bundle_id)
            .map(|root| root.sequence + 1)
            .unwrap_or(1);
        self.witness_bundles.insert(
            bundle_id.to_string(),
            WitnessBundleRoot {
                bundle_id: bundle_id.to_string(),
                envelope_ids,
                witness_root: witness_root.to_string(),
                recursive_proof_root: recursive_proof_root.to_string(),
                locality_zone_root: locality_zone_root.to_string(),
                latest_envelope_id: envelope_id.to_string(),
                sequence,
            },
        );
        Ok(())
    }

    pub fn register_governance_upgrade_root(
        &mut self,
        upgrade_id: &str,
        proposal_root: &str,
        vote_root: &str,
        timelock_root: &str,
        new_verifier_root: &str,
        activation_epoch: u64,
        envelope_id: &str,
    ) -> Result<()> {
        require(
            self.envelopes.contains_key(envelope_id),
            "governance root references unknown envelope",
        )?;
        require(
            activation_epoch >= self.epoch,
            "activation epoch cannot be in the past",
        )?;
        let sequence = self
            .governance_upgrade_roots
            .get(upgrade_id)
            .map(|root| root.sequence + 1)
            .unwrap_or(1);
        self.governance_upgrade_roots.insert(
            upgrade_id.to_string(),
            GovernanceUpgradeRoot {
                upgrade_id: upgrade_id.to_string(),
                proposal_root: proposal_root.to_string(),
                vote_root: vote_root.to_string(),
                timelock_root: timelock_root.to_string(),
                new_verifier_root: new_verifier_root.to_string(),
                activation_epoch,
                latest_envelope_id: envelope_id.to_string(),
                sequence,
            },
        );
        Ok(())
    }

    pub fn envelope_fee_total(&self, envelope_id: &str) -> u64 {
        self.fee_charges
            .values()
            .filter(|charge| charge.envelope_id == envelope_id)
            .map(|charge| charge.amount_units)
            .sum()
    }

    pub fn open_conflict_ids(&self) -> BTreeSet<String> {
        self.conflicts
            .iter()
            .filter(|(_, conflict)| conflict.status == ResolutionStatus::Open)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn ensure_privacy_account(&mut self, scope: &str, epoch: u64) -> Result<String> {
        require_nonempty("privacy scope", scope)?;
        let privacy_id = privacy_budget_id(scope, epoch);
        if !self.privacy_budgets.contains_key(&privacy_id) {
            let account = PrivacyBudgetAccount {
                privacy_id: privacy_id.clone(),
                scope: scope.to_string(),
                epoch,
                budget_units: self.config.privacy_budget_per_epoch,
                spent_units: 0,
                reserved_units: 0,
                min_anonymity_set: self.config.min_privacy_set_size,
                nullifier_root: empty_root("PRIVACY-NULLIFIERS"),
                sealed_counter_root: empty_root("PRIVACY-COUNTERS"),
            };
            self.privacy_budgets.insert(privacy_id.clone(), account);
            self.counters.next_privacy_index += 1;
        }
        Ok(privacy_id)
    }

    fn reserve_privacy_units(&mut self, scope: &str, units: u64) -> Result<()> {
        let privacy_id = self.ensure_privacy_account(scope, self.epoch)?;
        let account = self
            .privacy_budgets
            .get_mut(&privacy_id)
            .ok_or_else(|| unknown("privacy budget", &privacy_id))?;
        require(account.remaining() >= units, "privacy budget exceeded")?;
        account.reserved_units = checked_add_u64(account.reserved_units, units)?;
        self.counters.privacy_charges += 1;
        self.counters.total_privacy_units += units as u128;
        Ok(())
    }

    fn finalize_privacy_units(&mut self, lane_id: &str, units: u64) -> Result<()> {
        let scope = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| unknown("lane", lane_id))?
            .privacy_scope
            .clone();
        let privacy_id = privacy_budget_id(&scope, self.epoch);
        let account = self
            .privacy_budgets
            .get_mut(&privacy_id)
            .ok_or_else(|| unknown("privacy budget", &privacy_id))?;
        require(
            account.reserved_units >= units,
            "privacy reservation underflow",
        )?;
        account.reserved_units -= units;
        account.spent_units = checked_add_u64(account.spent_units, units)?;
        Ok(())
    }

    fn charge_envelope_fees(&mut self, envelope_id: &str) -> Result<()> {
        let envelope = self
            .envelopes
            .get(envelope_id)
            .ok_or_else(|| unknown("envelope", envelope_id))?
            .clone();
        let base_amount = checked_mul_u64(self.config.base_fee_units, envelope.kind.fee_weight())?;
        self.record_fee_charge(&envelope, FeeKind::Base, base_amount)?;
        self.record_fee_charge(&envelope, FeeKind::Proof, self.config.proof_fee_units)?;
        if matches!(
            envelope.kind,
            EnvelopeKind::TokenBridgeRoot | EnvelopeKind::MoneroBridgeRoot
        ) {
            self.record_fee_charge(&envelope, FeeKind::Bridge, self.config.bridge_fee_units)?;
        }
        if matches!(envelope.kind, EnvelopeKind::DataAvailabilityVoucher) {
            self.record_fee_charge(
                &envelope,
                FeeKind::DataAvailability,
                self.config.da_fee_units,
            )?;
        }
        if envelope.privacy_cost > 0 {
            self.record_fee_charge(&envelope, FeeKind::Privacy, envelope.privacy_cost)?;
        }
        Ok(())
    }

    fn record_fee_charge(
        &mut self,
        envelope: &StateCommitmentEnvelope,
        kind: FeeKind,
        amount_units: u64,
    ) -> Result<String> {
        let index = self.counters.next_fee_index;
        let fee_id = fee_charge_id(&envelope.envelope_id, kind, index);
        let rebate_units = if envelope.sponsor_commitment.is_some() {
            amount_units.saturating_mul(self.config.rebate_bps as u64) / MAX_BPS as u64
        } else {
            0
        };
        let settlement_root = payload_root(
            "FEE-SETTLEMENT",
            &json!({
                "envelope_id": envelope.envelope_id,
                "kind": kind.as_str(),
                "amount_units": amount_units,
                "rebate_units": rebate_units,
            }),
        );
        let charge = FeeCharge {
            fee_id: fee_id.clone(),
            envelope_id: envelope.envelope_id.clone(),
            lane_id: envelope.lane_id.clone(),
            kind,
            payer_commitment: envelope.fee_payer_commitment.clone(),
            sponsor_commitment: envelope.sponsor_commitment.clone(),
            amount_units,
            rebate_units,
            settlement_root,
            paid: false,
        };
        self.fee_charges.insert(fee_id.clone(), charge);
        self.counters.next_fee_index += 1;
        self.counters.fee_charges += 1;
        self.counters.total_fee_units += amount_units as u128;
        self.counters.total_rebate_units += rebate_units as u128;
        Ok(fee_id)
    }

    fn detect_envelope_conflicts(&mut self, envelope_id: &str) -> Result<()> {
        let envelope = self
            .envelopes
            .get(envelope_id)
            .ok_or_else(|| unknown("envelope", envelope_id))?
            .clone();
        let mut conflicting = BTreeSet::new();
        for existing in self.envelopes.values() {
            if existing.envelope_id == envelope.envelope_id {
                continue;
            }
            if envelope.conflicts_with(existing) {
                conflicting.insert(existing.envelope_id.clone());
            }
            if existing.nullifier_root == envelope.nullifier_root
                && existing.lane_id == envelope.lane_id
            {
                conflicting.insert(existing.envelope_id.clone());
            }
        }
        if !conflicting.is_empty() {
            conflicting.insert(envelope.envelope_id.clone());
            let evidence = string_set_root("CONFLICT-EVIDENCE", &conflicting);
            self.open_conflict(
                ConflictKind::RootEquivocation,
                &envelope.lane_id,
                conflicting,
                &evidence,
            )?;
        }
        Ok(())
    }

    fn apply_envelope_component(&mut self, envelope: &StateCommitmentEnvelope) -> Result<()> {
        match envelope.kind {
            EnvelopeKind::ContractState => self.register_contract_root(
                &envelope.subject_id,
                "confidential_contract",
                &envelope.new_state_root,
                &envelope.public_state_root,
                &envelope.private_state_commitment,
                &envelope.witness_root,
                &envelope.envelope_id,
            ),
            EnvelopeKind::TokenBridgeRoot => self.register_token_bridge_root(
                &envelope.subject_id,
                "confidential_asset",
                envelope.source_runtime.as_str(),
                envelope.target_runtime.as_str(),
                &envelope.public_state_root,
                &envelope.new_state_root,
                &envelope.nullifier_root,
                &envelope.envelope_id,
            ),
            EnvelopeKind::LiquidityLaneRoot => self.register_liquidity_lane_root(
                &envelope.subject_id,
                &envelope.new_state_root,
                &envelope.public_state_root,
                &envelope.private_state_commitment,
                &envelope.witness_root,
                &envelope.envelope_id,
            ),
            EnvelopeKind::MoneroBridgeRoot => self.register_monero_bridge_root(
                &envelope.subject_id,
                self.monero_height,
                &envelope.public_state_root,
                &envelope.nullifier_root,
                &envelope.new_state_root,
                &envelope.envelope_id,
            ),
            EnvelopeKind::ExecutionReceiptRoot => self.register_execution_receipt_root(
                &envelope.subject_id,
                &envelope.subject_id,
                &envelope.public_state_root,
                &envelope.new_state_root,
                &envelope.private_state_commitment,
                &envelope.witness_root,
                &envelope.envelope_id,
            ),
            EnvelopeKind::WitnessBundleRoot => self.register_witness_bundle_root(
                &envelope.subject_id,
                envelope.dependency_envelopes.clone(),
                &envelope.witness_root,
                &envelope.private_state_commitment,
                &envelope.public_state_root,
                &envelope.envelope_id,
            ),
            EnvelopeKind::DataAvailabilityVoucher
            | EnvelopeKind::GovernanceUpgradeRoot
            | EnvelopeKind::FeeAccountingRoot
            | EnvelopeKind::PrivacyBudgetRoot => {
                if envelope.kind == EnvelopeKind::GovernanceUpgradeRoot {
                    self.register_governance_upgrade_root(
                        &envelope.subject_id,
                        &envelope.public_state_root,
                        &envelope.private_state_commitment,
                        &envelope.witness_root,
                        &envelope.new_state_root,
                        self.epoch,
                        &envelope.envelope_id,
                    )?;
                }
                Ok(())
            }
        }
    }
}

pub fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

pub fn require_nonempty(label: &str, value: &str) -> Result<()> {
    require(!value.is_empty(), &format!("{label} cannot be empty"))
}

pub fn checked_add_u64(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| "u64 addition overflow".to_string())
}

pub fn checked_mul_u64(left: u64, right: u64) -> Result<u64> {
    left.checked_mul(right)
        .ok_or_else(|| "u64 multiplication overflow".to_string())
}

pub fn stable_record<T: Serialize>(value: &T) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => value,
        Err(error) => json!({ "serialization_error": error.to_string() }),
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut encoded = Vec::with_capacity(parts.len() + 2);
    encoded.push(HashPart::Str(CHAIN_ID));
    encoded.push(HashPart::Str(PROTOCOL_VERSION));
    for part in parts {
        encoded.push(copy_hash_part(part));
    }
    domain_hash(domain, &encoded, 32)
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": stable_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn filtered_map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, mut keep: F) -> String
where
    T: Serialize,
    F: FnMut(&T) -> bool,
{
    let leaves = values
        .iter()
        .filter(|(_, value)| keep(value))
        .map(|(key, value)| json!({ "key": key, "value": stable_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn envelope_public_state_root(
    envelopes: &BTreeMap<String, StateCommitmentEnvelope>,
    envelope_ids: &BTreeSet<String>,
) -> String {
    let leaves = envelope_ids
        .iter()
        .filter_map(|id| envelopes.get(id))
        .map(|envelope| {
            json!({
                "envelope_id": envelope.envelope_id,
                "lane_id": envelope.lane_id,
                "subject_id": envelope.subject_id,
                "public_state_root": envelope.public_state_root,
                "new_state_root": envelope.new_state_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("PL2-PQ-XR-STATE-BUS-PUBLIC-STATE", &leaves)
}

pub fn batch_global_root(
    previous_global_root: &str,
    envelope_root: &str,
    proof_root: &str,
    fee_root: &str,
    privacy_budget_root: &str,
) -> String {
    payload_root(
        "BATCH-GLOBAL-ROOT",
        &json!({
            "previous_global_root": previous_global_root,
            "envelope_root": envelope_root,
            "proof_root": proof_root,
            "fee_root": fee_root,
            "privacy_budget_root": privacy_budget_root,
        }),
    )
}

pub fn lane_id(
    lane_kind: LaneKind,
    runtime_domain: RuntimeDomain,
    operator_commitment: &str,
    sequence: u64,
) -> String {
    deterministic_id(
        "LANE-ID",
        &[
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(runtime_domain.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::U64(sequence),
        ],
    )
}

pub fn envelope_id(lane_id: &str, subject_id: &str, kind: EnvelopeKind, sequence: u64) -> String {
    deterministic_id(
        "ENVELOPE-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
        ],
    )
}

pub fn inclusion_proof_id(
    envelope_id: &str,
    proof_kind: ProofKind,
    leaf_id: &str,
    sequence: u64,
) -> String {
    deterministic_id(
        "INCLUSION-PROOF-ID",
        &[
            HashPart::Str(envelope_id),
            HashPart::Str(proof_kind.as_str()),
            HashPart::Str(leaf_id),
            HashPart::U64(sequence),
        ],
    )
}

pub fn conflict_id(
    kind: ConflictKind,
    lane_id: &str,
    evidence_root: &str,
    sequence: u64,
) -> String {
    deterministic_id(
        "CONFLICT-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane_id),
            HashPart::Str(evidence_root),
            HashPart::U64(sequence),
        ],
    )
}

pub fn batch_id(envelope_root: &str, builder_commitment: &str, sequence: u64) -> String {
    deterministic_id(
        "BATCH-ID",
        &[
            HashPart::Str(envelope_root),
            HashPart::Str(builder_commitment),
            HashPart::U64(sequence),
        ],
    )
}

pub fn fee_charge_id(envelope_id: &str, kind: FeeKind, sequence: u64) -> String {
    deterministic_id(
        "FEE-CHARGE-ID",
        &[
            HashPart::Str(envelope_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
        ],
    )
}

pub fn privacy_budget_id(scope: &str, epoch: u64) -> String {
    deterministic_id(
        "PRIVACY-BUDGET-ID",
        &[HashPart::Str(scope), HashPart::U64(epoch)],
    )
}

pub fn da_voucher_id(envelope_id: &str, blob_root: &str, sequence: u64) -> String {
    deterministic_id(
        "DA-VOUCHER-ID",
        &[
            HashPart::Str(envelope_id),
            HashPart::Str(blob_root),
            HashPart::U64(sequence),
        ],
    )
}

fn unknown(kind: &str, id: &str) -> String {
    format!("unknown {kind}: {id}")
}

fn copy_hash_part<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}
