use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-gas-meter-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-confidential-contract-gas-meter-v1";
pub const COMMITMENT_SCHEME: &str = "confidential-gas-escrow-pedersen-compatible-root-v1";
pub const NULLIFIER_SCHEME: &str = "monero-style-private-contract-gas-nullifier-v1";
pub const COUPON_SCHEME: &str = "proof-witness-gas-coupon-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-confidential-gas-rebate-coupon-v1";
pub const SLASHING_SCHEME: &str = "pq-contract-gas-meter-slashing-evidence-v1";
pub const DEVNET_HEIGHT: u64 = 742_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_GAS_UNIT: &str = "confidential-contract-gas";
pub const DEFAULT_MAX_LANES: usize = 32;
pub const DEFAULT_MAX_ESCROWS: usize = 1_048_576;
pub const DEFAULT_MAX_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_PRECOMPILES: usize = 262_144;
pub const DEFAULT_MAX_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 262_144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ESCROW_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BUDGET_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_CONGESTION_TARGET_GAS: u64 = 24_000_000;
pub const DEFAULT_CONGESTION_ELASTICITY_BPS: u64 = 1_250;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 2_000;
pub const DEFAULT_MAX_PRIORITY_FEE_BPS: u64 = 750;
pub const DEFAULT_SLASHING_BOND_FLOOR: u64 = 10_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GasLaneKind {
    Wallet,
    Dex,
    Lending,
    Perpetuals,
    Oracle,
    Bridge,
    Governance,
    BatchSettlement,
    Emergency,
}

impl GasLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::BatchSettlement => "batch_settlement",
            Self::Emergency => "emergency",
        }
    }

    pub fn defi(self) -> bool {
        matches!(self, Self::Dex | Self::Lending | Self::Perpetuals)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecompileKind {
    PoseidonHash,
    KeccakTranscript,
    RangeProofVerify,
    MembershipProofVerify,
    ConfidentialSwapMath,
    ConfidentialCreditMath,
    PqSignatureVerify,
    PqKemEnvelopeVerify,
    RecursiveProofVerify,
    MoneroKeyImageCheck,
    MoneroViewTagScan,
    BatchMerkleOpen,
}

impl PrecompileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoseidonHash => "poseidon_hash",
            Self::KeccakTranscript => "keccak_transcript",
            Self::RangeProofVerify => "range_proof_verify",
            Self::MembershipProofVerify => "membership_proof_verify",
            Self::ConfidentialSwapMath => "confidential_swap_math",
            Self::ConfidentialCreditMath => "confidential_credit_math",
            Self::PqSignatureVerify => "pq_signature_verify",
            Self::PqKemEnvelopeVerify => "pq_kem_envelope_verify",
            Self::RecursiveProofVerify => "recursive_proof_verify",
            Self::MoneroKeyImageCheck => "monero_key_image_check",
            Self::MoneroViewTagScan => "monero_view_tag_scan",
            Self::BatchMerkleOpen => "batch_merkle_open",
        }
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::RangeProofVerify
                | Self::MembershipProofVerify
                | Self::MoneroKeyImageCheck
                | Self::MoneroViewTagScan
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Open,
    Reserved,
    PartiallyConsumed,
    Consumed,
    Refunded,
    Expired,
    Fenced,
    Slashed,
}

impl EscrowStatus {
    pub fn reservable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::PartiallyConsumed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::PartiallyConsumed => "partially_consumed",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Fenced => "fenced",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Settled,
    Reverted,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Active,
    Throttled,
    Exhausted,
    Paused,
    Slashed,
}

impl BudgetStatus {
    pub fn metered(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Reserved,
    Redeemed,
    Expired,
    Revoked,
}

impl CouponStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Issued | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Issued,
    Claimed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Settled,
    PartiallySettled,
    Rejected,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    DoubleSpendNullifier,
    InvalidPqAuthorization,
    OverBudgetExecution,
    PrecompileMisMetering,
    CongestionOracleFault,
    CouponReplay,
    RebateFraud,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::InvalidPqAuthorization => "invalid_pq_authorization",
            Self::OverBudgetExecution => "over_budget_execution",
            Self::PrecompileMisMetering => "precompile_mis_metering",
            Self::CongestionOracleFault => "congestion_oracle_fault",
            Self::CouponReplay => "coupon_replay",
            Self::RebateFraud => "rebate_fraud",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub gas_unit: String,
    pub max_lanes: usize,
    pub max_escrows: usize,
    pub max_budgets: usize,
    pub max_precompiles: usize,
    pub max_coupons: usize,
    pub max_rebates: usize,
    pub max_reservations: usize,
    pub max_batch_items: usize,
    pub max_slashing_evidence: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub escrow_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub budget_window_blocks: u64,
    pub congestion_target_gas: u64,
    pub congestion_elasticity_bps: u64,
    pub max_rebate_bps: u64,
    pub max_priority_fee_bps: u64,
    pub slashing_bond_floor: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            gas_unit: DEFAULT_GAS_UNIT.to_string(),
            max_lanes: DEFAULT_MAX_LANES,
            max_escrows: DEFAULT_MAX_ESCROWS,
            max_budgets: DEFAULT_MAX_BUDGETS,
            max_precompiles: DEFAULT_MAX_PRECOMPILES,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            escrow_ttl_blocks: DEFAULT_ESCROW_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            budget_window_blocks: DEFAULT_BUDGET_WINDOW_BLOCKS,
            congestion_target_gas: DEFAULT_CONGESTION_TARGET_GAS,
            congestion_elasticity_bps: DEFAULT_CONGESTION_ELASTICITY_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            max_priority_fee_bps: DEFAULT_MAX_PRIORITY_FEE_BPS,
            slashing_bond_floor: DEFAULT_SLASHING_BOND_FLOOR,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_contract_gas_meter_config",
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "gas_unit": self.gas_unit,
            "max_lanes": self.max_lanes,
            "max_escrows": self.max_escrows,
            "max_budgets": self.max_budgets,
            "max_precompiles": self.max_precompiles,
            "max_coupons": self.max_coupons,
            "max_rebates": self.max_rebates,
            "max_reservations": self.max_reservations,
            "max_batch_items": self.max_batch_items,
            "max_slashing_evidence": self.max_slashing_evidence,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "escrow_ttl_blocks": self.escrow_ttl_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "budget_window_blocks": self.budget_window_blocks,
            "congestion_target_gas": self.congestion_target_gas,
            "congestion_elasticity_bps": self.congestion_elasticity_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "max_priority_fee_bps": self.max_priority_fee_bps,
            "slashing_bond_floor": self.slashing_bond_floor,
        })
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(!self.fee_asset_id.is_empty(), "fee asset id is empty")?;
        require(!self.gas_unit.is_empty(), "gas unit is empty")?;
        require(self.max_lanes > 0, "max lanes is zero")?;
        require(self.max_escrows > 0, "max escrows is zero")?;
        require(self.max_budgets > 0, "max budgets is zero")?;
        require(self.max_precompiles > 0, "max precompiles is zero")?;
        require(self.max_coupons > 0, "max coupons is zero")?;
        require(self.max_rebates > 0, "max rebates is zero")?;
        require(self.max_reservations > 0, "max reservations is zero")?;
        require(self.max_batch_items > 0, "max batch items is zero")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security bits below policy",
        )?;
        require(
            self.congestion_elasticity_bps <= MAX_BPS,
            "congestion elasticity exceeds bps",
        )?;
        require(self.max_rebate_bps <= MAX_BPS, "rebate bps exceeds max")?;
        require(
            self.max_priority_fee_bps <= MAX_BPS,
            "priority fee bps exceeds max",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GasPriceLane {
    pub lane_id: String,
    pub kind: GasLaneKind,
    pub base_price_micro: u64,
    pub priority_price_micro: u64,
    pub floor_price_micro: u64,
    pub ceiling_price_micro: u64,
    pub target_gas_per_block: u64,
    pub last_block_gas: u64,
    pub congestion_multiplier_bps: u64,
    pub privacy_floor: u64,
    pub pq_required: bool,
    pub accepts_rebates: bool,
    pub enabled: bool,
}

impl GasPriceLane {
    pub fn new(
        kind: GasLaneKind,
        base_price_micro: u64,
        priority_price_micro: u64,
        target_gas_per_block: u64,
        privacy_floor: u64,
        nonce: u64,
    ) -> Self {
        let lane_id = gas_meter_id(
            "GAS-LANE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Int(base_price_micro as i128),
                HashPart::Int(priority_price_micro as i128),
                HashPart::Int(nonce as i128),
            ],
        );
        let ceiling_price_micro = base_price_micro
            .saturating_mul(4)
            .saturating_add(priority_price_micro.saturating_mul(2));
        Self {
            lane_id,
            kind,
            base_price_micro,
            priority_price_micro,
            floor_price_micro: base_price_micro.saturating_div(2).max(1),
            ceiling_price_micro,
            target_gas_per_block,
            last_block_gas: 0,
            congestion_multiplier_bps: MAX_BPS,
            privacy_floor,
            pq_required: true,
            accepts_rebates: !matches!(kind, GasLaneKind::Emergency),
            enabled: true,
        }
    }

    pub fn quote_price_micro(&self) -> u64 {
        let base = self
            .base_price_micro
            .saturating_mul(self.congestion_multiplier_bps)
            .saturating_div(MAX_BPS);
        base.saturating_add(self.priority_price_micro)
            .clamp(self.floor_price_micro, self.ceiling_price_micro)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_price_lane",
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "lane_kind": self.kind.as_str(),
            "base_price_micro": self.base_price_micro,
            "priority_price_micro": self.priority_price_micro,
            "floor_price_micro": self.floor_price_micro,
            "ceiling_price_micro": self.ceiling_price_micro,
            "target_gas_per_block": self.target_gas_per_block,
            "last_block_gas": self.last_block_gas,
            "congestion_multiplier_bps": self.congestion_multiplier_bps,
            "privacy_floor": self.privacy_floor,
            "pq_required": self.pq_required,
            "accepts_rebates": self.accepts_rebates,
            "enabled": self.enabled,
            "quote_price_micro": self.quote_price_micro(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialGasEscrow {
    pub escrow_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub lane_id: String,
    pub amount_commitment: String,
    pub asset_id: String,
    pub nullifier: String,
    pub view_tag_root: String,
    pub encrypted_refund_hint_root: String,
    pub reserved_gas: u64,
    pub consumed_gas: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: EscrowStatus,
}

impl ConfidentialGasEscrow {
    pub fn new(
        owner_commitment: &str,
        contract_id: &str,
        lane_id: &str,
        amount_commitment: &str,
        asset_id: &str,
        view_tag_root: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> Self {
        let nullifier = gas_meter_id(
            "GAS-ESCROW-NULLIFIER",
            &[
                HashPart::Str(owner_commitment),
                HashPart::Str(contract_id),
                HashPart::Str(lane_id),
                HashPart::Str(amount_commitment),
                HashPart::Int(nonce as i128),
            ],
        );
        let escrow_id = gas_meter_id(
            "GAS-ESCROW-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&nullifier),
                HashPart::Str(asset_id),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Self {
            escrow_id,
            owner_commitment: owner_commitment.to_string(),
            contract_id: contract_id.to_string(),
            lane_id: lane_id.to_string(),
            amount_commitment: amount_commitment.to_string(),
            asset_id: asset_id.to_string(),
            nullifier,
            view_tag_root: view_tag_root.to_string(),
            encrypted_refund_hint_root: empty_root("GAS-ESCROW-REFUND-HINT"),
            reserved_gas: 0,
            consumed_gas: 0,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: EscrowStatus::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_gas_escrow",
            "chain_id": CHAIN_ID,
            "escrow_id": self.escrow_id,
            "owner_commitment": self.owner_commitment,
            "contract_id": self.contract_id,
            "lane_id": self.lane_id,
            "amount_commitment": self.amount_commitment,
            "asset_id": self.asset_id,
            "nullifier": self.nullifier,
            "view_tag_root": self.view_tag_root,
            "encrypted_refund_hint_root": self.encrypted_refund_hint_root,
            "reserved_gas": self.reserved_gas,
            "consumed_gas": self.consumed_gas,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractDomainGasBudget {
    pub budget_id: String,
    pub domain_id: String,
    pub contract_id: String,
    pub lane_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub private_state_read_limit: u64,
    pub private_state_reads: u64,
    pub proof_byte_limit: u64,
    pub proof_bytes: u64,
    pub allowed_precompile_root: String,
    pub fence_nullifier_root: String,
    pub status: BudgetStatus,
}

impl ContractDomainGasBudget {
    pub fn new(
        domain_id: &str,
        contract_id: &str,
        lane_id: &str,
        window_start_height: u64,
        window_blocks: u64,
        gas_limit: u64,
        allowed_precompile_ids: &[String],
        nonce: u64,
    ) -> Self {
        let allowed_records = allowed_precompile_ids
            .iter()
            .map(|id| json!({ "precompile_id": id }))
            .collect::<Vec<_>>();
        let allowed_precompile_root =
            gas_meter_merkle_root("BUDGET-ALLOWED-PRECOMPILES", allowed_records);
        let budget_id = gas_meter_id(
            "CONTRACT-DOMAIN-BUDGET-ID",
            &[
                HashPart::Str(domain_id),
                HashPart::Str(contract_id),
                HashPart::Str(lane_id),
                HashPart::Int(window_start_height as i128),
                HashPart::Int(gas_limit as i128),
                HashPart::Int(nonce as i128),
            ],
        );
        Self {
            budget_id,
            domain_id: domain_id.to_string(),
            contract_id: contract_id.to_string(),
            lane_id: lane_id.to_string(),
            window_start_height,
            window_end_height: window_start_height.saturating_add(window_blocks),
            gas_limit,
            gas_used: 0,
            private_state_read_limit: gas_limit.saturating_div(64).max(1),
            private_state_reads: 0,
            proof_byte_limit: gas_limit.saturating_mul(8),
            proof_bytes: 0,
            allowed_precompile_root,
            fence_nullifier_root: empty_root("BUDGET-FENCE-NULLIFIERS"),
            status: BudgetStatus::Active,
        }
    }

    pub fn available_gas(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_domain_gas_budget",
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "domain_id": self.domain_id,
            "contract_id": self.contract_id,
            "lane_id": self.lane_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "gas_limit": self.gas_limit,
            "gas_used": self.gas_used,
            "available_gas": self.available_gas(),
            "private_state_read_limit": self.private_state_read_limit,
            "private_state_reads": self.private_state_reads,
            "proof_byte_limit": self.proof_byte_limit,
            "proof_bytes": self.proof_bytes,
            "allowed_precompile_root": self.allowed_precompile_root,
            "fence_nullifier_root": self.fence_nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrecompileMeter {
    pub precompile_id: String,
    pub kind: PrecompileKind,
    pub base_gas: u64,
    pub gas_per_input_byte: u64,
    pub gas_per_proof_byte: u64,
    pub max_input_bytes: u64,
    pub max_proof_bytes: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub accelerator_committee_root: String,
    pub enabled: bool,
}

impl PrecompileMeter {
    pub fn new(
        kind: PrecompileKind,
        base_gas: u64,
        gas_per_input_byte: u64,
        gas_per_proof_byte: u64,
        max_input_bytes: u64,
        max_proof_bytes: u64,
        nonce: u64,
    ) -> Self {
        let precompile_id = gas_meter_id(
            "PRECOMPILE-METER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Int(base_gas as i128),
                HashPart::Int(nonce as i128),
            ],
        );
        Self {
            precompile_id,
            kind,
            base_gas,
            gas_per_input_byte,
            gas_per_proof_byte,
            max_input_bytes,
            max_proof_bytes,
            privacy_floor: if kind.privacy_critical() {
                16_384
            } else {
                8_192
            },
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            accelerator_committee_root: empty_root("PRECOMPILE-ACCELERATOR-COMMITTEE"),
            enabled: true,
        }
    }

    pub fn quote_gas(&self, input_bytes: u64, proof_bytes: u64) -> Result<u64> {
        require(self.enabled, "precompile disabled")?;
        require(
            input_bytes <= self.max_input_bytes,
            "input bytes exceed precompile cap",
        )?;
        require(
            proof_bytes <= self.max_proof_bytes,
            "proof bytes exceed precompile cap",
        )?;
        Ok(self
            .base_gas
            .saturating_add(input_bytes.saturating_mul(self.gas_per_input_byte))
            .saturating_add(proof_bytes.saturating_mul(self.gas_per_proof_byte)))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "precompile_meter",
            "chain_id": CHAIN_ID,
            "precompile_id": self.precompile_id,
            "precompile_kind": self.kind.as_str(),
            "base_gas": self.base_gas,
            "gas_per_input_byte": self.gas_per_input_byte,
            "gas_per_proof_byte": self.gas_per_proof_byte,
            "max_input_bytes": self.max_input_bytes,
            "max_proof_bytes": self.max_proof_bytes,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "accelerator_committee_root": self.accelerator_committee_root,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessProofGasCoupon {
    pub coupon_id: String,
    pub owner_commitment: String,
    pub lane_id: String,
    pub precompile_id: String,
    pub gas_units: u64,
    pub fee_credit_commitment: String,
    pub witness_root: String,
    pub proof_commitment_root: String,
    pub nullifier: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: CouponStatus,
}

impl WitnessProofGasCoupon {
    pub fn new(
        owner_commitment: &str,
        lane_id: &str,
        precompile_id: &str,
        gas_units: u64,
        fee_credit_commitment: &str,
        witness_root: &str,
        issued_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> Self {
        let nullifier = gas_meter_id(
            "PROOF-GAS-COUPON-NULLIFIER",
            &[
                HashPart::Str(owner_commitment),
                HashPart::Str(lane_id),
                HashPart::Str(precompile_id),
                HashPart::Str(witness_root),
                HashPart::Int(nonce as i128),
            ],
        );
        let coupon_id = gas_meter_id(
            "PROOF-GAS-COUPON-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&nullifier),
                HashPart::Int(gas_units as i128),
                HashPart::Int(issued_at_height as i128),
            ],
        );
        Self {
            coupon_id,
            owner_commitment: owner_commitment.to_string(),
            lane_id: lane_id.to_string(),
            precompile_id: precompile_id.to_string(),
            gas_units,
            fee_credit_commitment: fee_credit_commitment.to_string(),
            witness_root: witness_root.to_string(),
            proof_commitment_root: empty_root("COUPON-PROOF-COMMITMENT"),
            nullifier,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
            status: CouponStatus::Issued,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_proof_gas_coupon",
            "chain_id": CHAIN_ID,
            "coupon_id": self.coupon_id,
            "owner_commitment": self.owner_commitment,
            "lane_id": self.lane_id,
            "precompile_id": self.precompile_id,
            "gas_units": self.gas_units,
            "fee_credit_commitment": self.fee_credit_commitment,
            "witness_root": self.witness_root,
            "proof_commitment_root": self.proof_commitment_root,
            "nullifier": self.nullifier,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": format!("{:?}", self.status).to_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateCoupon {
    pub rebate_id: String,
    pub beneficiary_commitment: String,
    pub lane_id: String,
    pub reservation_id: String,
    pub rebate_bps: u64,
    pub gas_units: u64,
    pub rebate_commitment: String,
    pub claim_nullifier: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: RebateStatus,
}

impl FeeRebateCoupon {
    pub fn new(
        beneficiary_commitment: &str,
        lane_id: &str,
        reservation_id: &str,
        rebate_bps: u64,
        gas_units: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> Self {
        let claim_nullifier = gas_meter_id(
            "FEE-REBATE-CLAIM-NULLIFIER",
            &[
                HashPart::Str(beneficiary_commitment),
                HashPart::Str(lane_id),
                HashPart::Str(reservation_id),
                HashPart::Int(rebate_bps as i128),
                HashPart::Int(nonce as i128),
            ],
        );
        let rebate_commitment = gas_meter_id(
            "FEE-REBATE-COMMITMENT",
            &[
                HashPart::Str(&claim_nullifier),
                HashPart::Int(gas_units as i128),
                HashPart::Int(issued_at_height as i128),
            ],
        );
        let rebate_id = gas_meter_id(
            "FEE-REBATE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&rebate_commitment),
                HashPart::Str(reservation_id),
            ],
        );
        Self {
            rebate_id,
            beneficiary_commitment: beneficiary_commitment.to_string(),
            lane_id: lane_id.to_string(),
            reservation_id: reservation_id.to_string(),
            rebate_bps,
            gas_units,
            rebate_commitment,
            claim_nullifier,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
            status: RebateStatus::Issued,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_rebate_coupon",
            "chain_id": CHAIN_ID,
            "rebate_id": self.rebate_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "lane_id": self.lane_id,
            "reservation_id": self.reservation_id,
            "rebate_bps": self.rebate_bps,
            "gas_units": self.gas_units,
            "rebate_commitment": self.rebate_commitment,
            "claim_nullifier": self.claim_nullifier,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": format!("{:?}", self.status).to_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuthorizationReceipt {
    pub receipt_id: String,
    pub subject_commitment: String,
    pub contract_id: String,
    pub lane_id: String,
    pub authorized_action_root: String,
    pub pq_key_commitment: String,
    pub signature_transcript_root: String,
    pub kem_ciphertext_root: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl PqAuthorizationReceipt {
    pub fn new(
        subject_commitment: &str,
        contract_id: &str,
        lane_id: &str,
        authorized_action_root: &str,
        pq_key_commitment: &str,
        valid_from_height: u64,
        valid_until_height: u64,
        nonce: u64,
    ) -> Self {
        let receipt_id = gas_meter_id(
            "PQ-AUTH-RECEIPT-ID",
            &[
                HashPart::Str(subject_commitment),
                HashPart::Str(contract_id),
                HashPart::Str(lane_id),
                HashPart::Str(authorized_action_root),
                HashPart::Str(pq_key_commitment),
                HashPart::Int(nonce as i128),
            ],
        );
        Self {
            receipt_id,
            subject_commitment: subject_commitment.to_string(),
            contract_id: contract_id.to_string(),
            lane_id: lane_id.to_string(),
            authorized_action_root: authorized_action_root.to_string(),
            pq_key_commitment: pq_key_commitment.to_string(),
            signature_transcript_root: empty_root("PQ-AUTH-SIGNATURE-TRANSCRIPT"),
            kem_ciphertext_root: empty_root("PQ-AUTH-KEM-CIPHERTEXT"),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_from_height,
            valid_until_height,
        }
    }

    pub fn valid_at(&self, height: u64, min_security_bits: u16) -> bool {
        self.security_bits >= min_security_bits
            && self.valid_from_height <= height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_authorization_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "subject_commitment": self.subject_commitment,
            "contract_id": self.contract_id,
            "lane_id": self.lane_id,
            "authorized_action_root": self.authorized_action_root,
            "pq_key_commitment": self.pq_key_commitment,
            "signature_transcript_root": self.signature_transcript_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "pq_auth_suite": PQ_AUTH_SUITE,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionControl {
    pub lane_id: String,
    pub epoch: u64,
    pub target_gas: u64,
    pub observed_gas: u64,
    pub backlog_gas: u64,
    pub multiplier_bps: u64,
    pub rebate_bps: u64,
    pub privacy_queue_depth: u64,
    pub low_fee_mode: bool,
}

impl CongestionControl {
    pub fn new(lane_id: &str, epoch: u64, target_gas: u64) -> Self {
        Self {
            lane_id: lane_id.to_string(),
            epoch,
            target_gas,
            observed_gas: 0,
            backlog_gas: 0,
            multiplier_bps: MAX_BPS,
            rebate_bps: 0,
            privacy_queue_depth: 0,
            low_fee_mode: false,
        }
    }

    pub fn ingest(
        &mut self,
        observed_gas: u64,
        backlog_gas: u64,
        elasticity_bps: u64,
        max_rebate_bps: u64,
    ) {
        self.observed_gas = observed_gas;
        self.backlog_gas = backlog_gas;
        if observed_gas > self.target_gas {
            let excess = observed_gas.saturating_sub(self.target_gas);
            let pressure = excess
                .saturating_mul(elasticity_bps)
                .saturating_div(self.target_gas.max(1));
            self.multiplier_bps = MAX_BPS
                .saturating_add(pressure)
                .min(MAX_BPS.saturating_mul(4));
            self.rebate_bps = 0;
            self.low_fee_mode = false;
        } else {
            let spare = self.target_gas.saturating_sub(observed_gas);
            let discount = spare
                .saturating_mul(max_rebate_bps)
                .saturating_div(self.target_gas.max(1));
            self.multiplier_bps = MAX_BPS.saturating_sub(discount.min(max_rebate_bps));
            self.rebate_bps = discount.min(max_rebate_bps);
            self.low_fee_mode = true;
        }
        self.privacy_queue_depth = backlog_gas.saturating_div(1_000);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "congestion_control",
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "epoch": self.epoch,
            "target_gas": self.target_gas,
            "observed_gas": self.observed_gas,
            "backlog_gas": self.backlog_gas,
            "multiplier_bps": self.multiplier_bps,
            "rebate_bps": self.rebate_bps,
            "privacy_queue_depth": self.privacy_queue_depth,
            "low_fee_mode": self.low_fee_mode,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GasReservation {
    pub reservation_id: String,
    pub escrow_id: String,
    pub budget_id: String,
    pub lane_id: String,
    pub contract_id: String,
    pub auth_receipt_id: String,
    pub coupon_id: Option<String>,
    pub quoted_gas: u64,
    pub max_fee_micro: u64,
    pub price_micro: u64,
    pub reservation_nullifier: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}

impl GasReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_reservation",
            "chain_id": CHAIN_ID,
            "reservation_id": self.reservation_id,
            "escrow_id": self.escrow_id,
            "budget_id": self.budget_id,
            "lane_id": self.lane_id,
            "contract_id": self.contract_id,
            "auth_receipt_id": self.auth_receipt_id,
            "coupon_id": self.coupon_id,
            "quoted_gas": self.quoted_gas,
            "max_fee_micro": self.max_fee_micro,
            "price_micro": self.price_micro,
            "reservation_nullifier": self.reservation_nullifier,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MeteringBatchItem {
    pub reservation_id: String,
    pub gas_used: u64,
    pub private_state_reads: u64,
    pub proof_bytes: u64,
    pub output_commitment_root: String,
    pub success: bool,
}

impl MeteringBatchItem {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "gas_used": self.gas_used,
            "private_state_reads": self.private_state_reads,
            "proof_bytes": self.proof_bytes,
            "output_commitment_root": self.output_commitment_root,
            "success": self.success,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MeteringBatch {
    pub batch_id: String,
    pub sequencer_commitment: String,
    pub lane_id: String,
    pub item_root: String,
    pub batch_gas_used: u64,
    pub privacy_set_size: u64,
    pub proof_root: String,
    pub settlement_height: u64,
    pub status: BatchStatus,
}

impl MeteringBatch {
    pub fn new(
        sequencer_commitment: &str,
        lane_id: &str,
        items: &[MeteringBatchItem],
        privacy_set_size: u64,
        proof_root: &str,
        settlement_height: u64,
    ) -> Self {
        let item_records = items
            .iter()
            .map(MeteringBatchItem::public_record)
            .collect::<Vec<_>>();
        let item_root = gas_meter_merkle_root("METERING-BATCH-ITEMS", item_records);
        let batch_gas_used = items
            .iter()
            .fold(0_u64, |total, item| total.saturating_add(item.gas_used));
        let batch_id = gas_meter_id(
            "METERING-BATCH-ID",
            &[
                HashPart::Str(sequencer_commitment),
                HashPart::Str(lane_id),
                HashPart::Str(&item_root),
                HashPart::Int(settlement_height as i128),
            ],
        );
        Self {
            batch_id,
            sequencer_commitment: sequencer_commitment.to_string(),
            lane_id: lane_id.to_string(),
            item_root,
            batch_gas_used,
            privacy_set_size,
            proof_root: proof_root.to_string(),
            settlement_height,
            status: BatchStatus::Proposed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "metering_batch",
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "sequencer_commitment": self.sequencer_commitment,
            "lane_id": self.lane_id,
            "item_root": self.item_root,
            "batch_gas_used": self.batch_gas_used,
            "privacy_set_size": self.privacy_set_size,
            "proof_root": self.proof_root,
            "settlement_height": self.settlement_height,
            "status": format!("{:?}", self.status).to_lowercase(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub accused_commitment: String,
    pub reason: SlashingReason,
    pub linked_object_id: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub bond_commitment: String,
    pub slash_amount_commitment: String,
    pub detected_at_height: u64,
    pub finalized: bool,
}

impl SlashingEvidence {
    pub fn new(
        accused_commitment: &str,
        reason: SlashingReason,
        linked_object_id: &str,
        evidence_root: &str,
        challenger_commitment: &str,
        detected_at_height: u64,
        nonce: u64,
    ) -> Self {
        let evidence_id = gas_meter_id(
            "SLASHING-EVIDENCE-ID",
            &[
                HashPart::Str(accused_commitment),
                HashPart::Str(reason.as_str()),
                HashPart::Str(linked_object_id),
                HashPart::Str(evidence_root),
                HashPart::Int(nonce as i128),
            ],
        );
        Self {
            evidence_id,
            accused_commitment: accused_commitment.to_string(),
            reason,
            linked_object_id: linked_object_id.to_string(),
            evidence_root: evidence_root.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            bond_commitment: gas_meter_hash_str("SLASHING-BOND-COMMITMENT", linked_object_id),
            slash_amount_commitment: gas_meter_hash_str(
                "SLASHING-AMOUNT-COMMITMENT",
                evidence_root,
            ),
            detected_at_height,
            finalized: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "accused_commitment": self.accused_commitment,
            "reason": self.reason.as_str(),
            "linked_object_id": self.linked_object_id,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "bond_commitment": self.bond_commitment,
            "slash_amount_commitment": self.slash_amount_commitment,
            "detected_at_height": self.detected_at_height,
            "finalized": self.finalized,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub lane_root: String,
    pub escrow_root: String,
    pub budget_root: String,
    pub precompile_root: String,
    pub coupon_root: String,
    pub rebate_root: String,
    pub auth_receipt_root: String,
    pub congestion_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_contract_gas_meter_roots",
            "chain_id": CHAIN_ID,
            "lane_root": self.lane_root,
            "escrow_root": self.escrow_root,
            "budget_root": self.budget_root,
            "precompile_root": self.precompile_root,
            "coupon_root": self.coupon_root,
            "rebate_root": self.rebate_root,
            "auth_receipt_root": self.auth_receipt_root,
            "congestion_root": self.congestion_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn root(&self) -> String {
        gas_meter_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Counters {
    pub lanes: u64,
    pub escrows: u64,
    pub budgets: u64,
    pub precompiles: u64,
    pub coupons: u64,
    pub rebates: u64,
    pub auth_receipts: u64,
    pub congestion_controls: u64,
    pub reservations: u64,
    pub batches: u64,
    pub slashing_evidence: u64,
    pub spent_nullifiers: u64,
    pub gas_reserved: u64,
    pub gas_consumed: u64,
    pub fees_quoted_micro: u64,
    pub fees_settled_micro: u64,
    pub rebates_issued_micro: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_contract_gas_meter_counters",
            "chain_id": CHAIN_ID,
            "lanes": self.lanes,
            "escrows": self.escrows,
            "budgets": self.budgets,
            "precompiles": self.precompiles,
            "coupons": self.coupons,
            "rebates": self.rebates,
            "auth_receipts": self.auth_receipts,
            "congestion_controls": self.congestion_controls,
            "reservations": self.reservations,
            "batches": self.batches,
            "slashing_evidence": self.slashing_evidence,
            "spent_nullifiers": self.spent_nullifiers,
            "gas_reserved": self.gas_reserved,
            "gas_consumed": self.gas_consumed,
            "fees_quoted_micro": self.fees_quoted_micro,
            "fees_settled_micro": self.fees_settled_micro,
            "rebates_issued_micro": self.rebates_issued_micro,
        })
    }

    pub fn root(&self) -> String {
        gas_meter_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GasQuote {
    pub lane_id: String,
    pub budget_id: String,
    pub contract_id: String,
    pub estimated_gas: u64,
    pub price_micro: u64,
    pub max_fee_micro: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub quote_root: String,
}

impl GasQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_quote",
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "budget_id": self.budget_id,
            "contract_id": self.contract_id,
            "estimated_gas": self.estimated_gas,
            "price_micro": self.price_micro,
            "max_fee_micro": self.max_fee_micro,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "quote_root": self.quote_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub lanes: BTreeMap<String, GasPriceLane>,
    pub escrows: BTreeMap<String, ConfidentialGasEscrow>,
    pub budgets: BTreeMap<String, ContractDomainGasBudget>,
    pub precompiles: BTreeMap<String, PrecompileMeter>,
    pub coupons: BTreeMap<String, WitnessProofGasCoupon>,
    pub rebates: BTreeMap<String, FeeRebateCoupon>,
    pub auth_receipts: BTreeMap<String, PqAuthorizationReceipt>,
    pub congestion_controls: BTreeMap<String, CongestionControl>,
    pub reservations: BTreeMap<String, GasReservation>,
    pub batches: BTreeMap<String, MeteringBatch>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub height: u64,
    pub epoch: u64,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        Self {
            config,
            lanes: BTreeMap::new(),
            escrows: BTreeMap::new(),
            budgets: BTreeMap::new(),
            precompiles: BTreeMap::new(),
            coupons: BTreeMap::new(),
            rebates: BTreeMap::new(),
            auth_receipts: BTreeMap::new(),
            congestion_controls: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            height,
            epoch: 0,
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        let wallet = GasPriceLane::new(GasLaneKind::Wallet, 18, 1, 4_000_000, 8_192, 1);
        let dex = GasPriceLane::new(GasLaneKind::Dex, 24, 2, 8_000_000, 16_384, 2);
        let lending = GasPriceLane::new(GasLaneKind::Lending, 22, 2, 6_000_000, 16_384, 3);
        let oracle = GasPriceLane::new(GasLaneKind::Oracle, 16, 1, 2_000_000, 8_192, 4);
        let bridge = GasPriceLane::new(GasLaneKind::Bridge, 28, 3, 4_000_000, 65_536, 5);
        for lane in [wallet, dex, lending, oracle, bridge] {
            state.congestion_controls.insert(
                lane.lane_id.clone(),
                CongestionControl::new(&lane.lane_id, 0, lane.target_gas_per_block),
            );
            state.lanes.insert(lane.lane_id.clone(), lane);
        }

        let precompiles = [
            PrecompileMeter::new(
                PrecompileKind::RangeProofVerify,
                22_000,
                4,
                11,
                16_384,
                65_536,
                10,
            ),
            PrecompileMeter::new(
                PrecompileKind::MembershipProofVerify,
                18_000,
                3,
                8,
                16_384,
                65_536,
                11,
            ),
            PrecompileMeter::new(
                PrecompileKind::PqSignatureVerify,
                15_000,
                2,
                5,
                8_192,
                32_768,
                12,
            ),
            PrecompileMeter::new(
                PrecompileKind::RecursiveProofVerify,
                42_000,
                5,
                13,
                65_536,
                262_144,
                13,
            ),
            PrecompileMeter::new(
                PrecompileKind::ConfidentialSwapMath,
                9_000,
                2,
                2,
                8_192,
                16_384,
                14,
            ),
            PrecompileMeter::new(
                PrecompileKind::MoneroKeyImageCheck,
                30_000,
                3,
                9,
                16_384,
                65_536,
                15,
            ),
        ];
        let precompile_ids = precompiles
            .iter()
            .map(|precompile| precompile.precompile_id.clone())
            .collect::<Vec<_>>();
        for precompile in precompiles {
            state
                .precompiles
                .insert(precompile.precompile_id.clone(), precompile);
        }

        let dex_lane = state
            .lane_by_kind(GasLaneKind::Dex)
            .map(|lane| lane.lane_id.clone())
            .unwrap_or_else(|| gas_meter_hash_str("DEVNET-MISSING-LANE", "dex"));
        let wallet_lane = state
            .lane_by_kind(GasLaneKind::Wallet)
            .map(|lane| lane.lane_id.clone())
            .unwrap_or_else(|| gas_meter_hash_str("DEVNET-MISSING-LANE", "wallet"));

        let dex_budget = ContractDomainGasBudget::new(
            "devnet-defi-domain",
            "confidential-swap-router",
            &dex_lane,
            DEVNET_HEIGHT,
            DEFAULT_BUDGET_WINDOW_BLOCKS,
            90_000_000,
            &precompile_ids,
            21,
        );
        let wallet_budget = ContractDomainGasBudget::new(
            "devnet-wallet-domain",
            "shielded-account-router",
            &wallet_lane,
            DEVNET_HEIGHT,
            DEFAULT_BUDGET_WINDOW_BLOCKS,
            32_000_000,
            &precompile_ids,
            22,
        );
        state
            .budgets
            .insert(dex_budget.budget_id.clone(), dex_budget);
        state
            .budgets
            .insert(wallet_budget.budget_id.clone(), wallet_budget);

        let escrow = ConfidentialGasEscrow::new(
            "owner-commitment-devnet-alice",
            "confidential-swap-router",
            &dex_lane,
            "gas-amount-commitment-devnet-alice-0001",
            DEFAULT_FEE_ASSET_ID,
            &empty_root("DEVNET-VIEW-TAG-SET"),
            DEVNET_HEIGHT,
            DEFAULT_ESCROW_TTL_BLOCKS,
            31,
        );
        state.escrows.insert(escrow.escrow_id.clone(), escrow);

        let auth = PqAuthorizationReceipt::new(
            "owner-commitment-devnet-alice",
            "confidential-swap-router",
            &dex_lane,
            &gas_meter_hash_str("DEVNET-AUTH-ACTION", "swap-exact-private-input"),
            "ml-dsa-87-key-commitment-devnet-alice",
            DEVNET_HEIGHT,
            DEVNET_HEIGHT.saturating_add(128),
            41,
        );
        state.auth_receipts.insert(auth.receipt_id.clone(), auth);

        let coupon_precompile = precompile_ids
            .first()
            .cloned()
            .unwrap_or_else(|| gas_meter_hash_str("DEVNET-MISSING-PRECOMPILE", "range-proof"));
        let coupon = WitnessProofGasCoupon::new(
            "owner-commitment-devnet-alice",
            &dex_lane,
            &coupon_precompile,
            18_000,
            "fee-credit-commitment-devnet-alice-0001",
            &empty_root("DEVNET-WITNESS-ROOT"),
            DEVNET_HEIGHT,
            DEFAULT_COUPON_TTL_BLOCKS,
            51,
        );
        state.coupons.insert(coupon.coupon_id.clone(), coupon);
        state
    }

    pub fn validate_config(&self) -> Result<()> {
        self.config.validate()
    }

    pub fn lane_by_kind(&self, kind: GasLaneKind) -> Option<&GasPriceLane> {
        self.lanes.values().find(|lane| lane.kind == kind)
    }

    pub fn quote_call_gas(
        &self,
        lane_id: &str,
        budget_id: &str,
        precompile_ids: &[String],
        calldata_bytes: u64,
        witness_bytes: u64,
        proof_bytes: u64,
        private_state_reads: u64,
    ) -> Result<GasQuote> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "lane not found".to_string())?;
        require(lane.enabled, "lane disabled")?;
        let budget = self
            .budgets
            .get(budget_id)
            .ok_or_else(|| "budget not found".to_string())?;
        require(budget.status.metered(), "budget not metered")?;
        require(budget.lane_id == lane_id, "budget lane mismatch")?;
        require(
            private_state_reads <= budget.private_state_read_limit,
            "private state reads exceed budget fence",
        )?;

        let mut estimated_gas = calldata_bytes
            .saturating_mul(2)
            .saturating_add(witness_bytes.saturating_mul(3))
            .saturating_add(proof_bytes.saturating_mul(5))
            .saturating_add(private_state_reads.saturating_mul(128));
        for precompile_id in precompile_ids {
            let precompile = self
                .precompiles
                .get(precompile_id)
                .ok_or_else(|| format!("precompile not found: {precompile_id}"))?;
            estimated_gas =
                estimated_gas.saturating_add(precompile.quote_gas(calldata_bytes, proof_bytes)?);
        }
        estimated_gas = estimated_gas.max(lane.privacy_floor);
        require(
            estimated_gas <= budget.available_gas(),
            "estimated gas exceeds budget",
        )?;

        let congestion = self.congestion_controls.get(lane_id);
        let rebate_bps = congestion.map(|control| control.rebate_bps).unwrap_or(0);
        let price_micro = lane.quote_price_micro();
        let max_fee_micro = estimated_gas.saturating_mul(price_micro);
        let quote_root = gas_meter_payload_root(
            "GAS-QUOTE",
            &json!({
                "lane_id": lane_id,
                "budget_id": budget_id,
                "precompile_ids": precompile_ids,
                "calldata_bytes": calldata_bytes,
                "witness_bytes": witness_bytes,
                "proof_bytes": proof_bytes,
                "private_state_reads": private_state_reads,
                "estimated_gas": estimated_gas,
                "price_micro": price_micro,
                "rebate_bps": rebate_bps,
            }),
        );
        Ok(GasQuote {
            lane_id: lane_id.to_string(),
            budget_id: budget_id.to_string(),
            contract_id: budget.contract_id.clone(),
            estimated_gas,
            price_micro,
            max_fee_micro,
            rebate_bps,
            privacy_set_size: lane.privacy_floor.max(self.config.min_privacy_set_size),
            quote_root,
        })
    }

    pub fn reserve_gas(
        &mut self,
        escrow_id: &str,
        budget_id: &str,
        auth_receipt_id: &str,
        coupon_id: Option<&str>,
        quoted_gas: u64,
        max_fee_micro: u64,
        nonce: u64,
    ) -> Result<String> {
        self.validate_config()?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "reservation limit reached",
        )?;

        let escrow_view = self
            .escrows
            .get(escrow_id)
            .ok_or_else(|| "escrow not found".to_string())?;
        require(escrow_view.status.reservable(), "escrow is not reservable")?;
        require(
            !self.spent_nullifiers.contains(&escrow_view.nullifier),
            "escrow nullifier already spent",
        )?;

        let budget = self
            .budgets
            .get(budget_id)
            .ok_or_else(|| "budget not found".to_string())?;
        require(budget.status.metered(), "budget is not active")?;
        require(
            budget.contract_id == escrow_view.contract_id,
            "budget contract mismatch",
        )?;
        require(
            budget.lane_id == escrow_view.lane_id,
            "budget lane mismatch",
        )?;
        require(
            quoted_gas <= budget.available_gas(),
            "quoted gas exceeds budget",
        )?;

        let auth = self
            .auth_receipts
            .get(auth_receipt_id)
            .ok_or_else(|| "authorization receipt not found".to_string())?;
        require(
            auth.contract_id == budget.contract_id,
            "authorization contract mismatch",
        )?;
        require(
            auth.lane_id == budget.lane_id,
            "authorization lane mismatch",
        )?;
        require(
            auth.valid_at(self.height, self.config.min_pq_security_bits),
            "authorization receipt not valid at height",
        )?;

        if let Some(id) = coupon_id {
            let coupon = self
                .coupons
                .get(id)
                .ok_or_else(|| "coupon not found".to_string())?;
            require(coupon.status.spendable(), "coupon is not spendable")?;
            require(coupon.lane_id == budget.lane_id, "coupon lane mismatch")?;
            require(coupon.expires_at_height >= self.height, "coupon expired")?;
        }

        let lane = self
            .lanes
            .get(&budget.lane_id)
            .ok_or_else(|| "lane not found".to_string())?;
        let price_micro = lane.quote_price_micro();
        let minimum_fee = quoted_gas.saturating_mul(price_micro);
        require(
            max_fee_micro >= minimum_fee,
            "max fee below deterministic quote",
        )?;

        let reservation_nullifier = gas_meter_id(
            "GAS-RESERVATION-NULLIFIER",
            &[
                HashPart::Str(escrow_id),
                HashPart::Str(budget_id),
                HashPart::Str(auth_receipt_id),
                HashPart::Int(quoted_gas as i128),
                HashPart::Int(nonce as i128),
            ],
        );
        require(
            !self.spent_nullifiers.contains(&reservation_nullifier),
            "reservation nullifier already spent",
        )?;
        let reservation_id = gas_meter_id(
            "GAS-RESERVATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&reservation_nullifier),
                HashPart::Int(self.height as i128),
            ],
        );
        let reservation = GasReservation {
            reservation_id: reservation_id.clone(),
            escrow_id: escrow_id.to_string(),
            budget_id: budget_id.to_string(),
            lane_id: budget.lane_id.clone(),
            contract_id: budget.contract_id.clone(),
            auth_receipt_id: auth_receipt_id.to_string(),
            coupon_id: coupon_id.map(str::to_string),
            quoted_gas,
            max_fee_micro,
            price_micro,
            reservation_nullifier,
            opened_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.escrow_ttl_blocks),
            status: ReservationStatus::Reserved,
        };

        if let Some(escrow) = self.escrows.get_mut(escrow_id) {
            escrow.reserved_gas = escrow.reserved_gas.saturating_add(quoted_gas);
            escrow.status = EscrowStatus::Reserved;
        }
        if let Some(coupon_id) = coupon_id {
            if let Some(coupon) = self.coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Reserved;
            }
        }
        self.reservations
            .insert(reservation_id.clone(), reservation);
        Ok(reservation_id)
    }

    pub fn settle_metering_batch(
        &mut self,
        sequencer_commitment: &str,
        lane_id: &str,
        items: Vec<MeteringBatchItem>,
        proof_root: &str,
        privacy_set_size: u64,
    ) -> Result<String> {
        require(!items.is_empty(), "empty metering batch")?;
        require(
            items.len() <= self.config.max_batch_items,
            "batch item limit reached",
        )?;
        require(
            privacy_set_size >= self.config.batch_privacy_set_size,
            "batch privacy set too small",
        )?;
        require(self.lanes.contains_key(lane_id), "lane not found")?;

        let mut seen = BTreeSet::new();
        let mut batch_gas = 0_u64;
        for item in &items {
            require(
                seen.insert(item.reservation_id.clone()),
                "duplicate reservation in batch",
            )?;
            let reservation = self
                .reservations
                .get(&item.reservation_id)
                .ok_or_else(|| "reservation not found".to_string())?;
            require(
                reservation.status == ReservationStatus::Reserved,
                "reservation not open",
            )?;
            require(reservation.lane_id == lane_id, "reservation lane mismatch")?;
            require(
                item.gas_used <= reservation.quoted_gas,
                "gas used exceeds reservation",
            )?;
            let budget = self
                .budgets
                .get(&reservation.budget_id)
                .ok_or_else(|| "budget not found".to_string())?;
            require(
                item.private_state_reads <= budget.private_state_read_limit,
                "private reads exceed budget",
            )?;
            require(
                item.proof_bytes <= budget.proof_byte_limit,
                "proof bytes exceed budget",
            )?;
            batch_gas = batch_gas.saturating_add(item.gas_used);
        }

        let mut batch = MeteringBatch::new(
            sequencer_commitment,
            lane_id,
            &items,
            privacy_set_size,
            proof_root,
            self.height,
        );
        batch.status = BatchStatus::Settled;
        let batch_id = batch.batch_id.clone();

        for item in items {
            if let Some(reservation) = self.reservations.get_mut(&item.reservation_id) {
                reservation.status = if item.success {
                    ReservationStatus::Settled
                } else {
                    ReservationStatus::Reverted
                };
                self.spent_nullifiers
                    .insert(reservation.reservation_nullifier.clone());
                let settled_fee = item.gas_used.saturating_mul(reservation.price_micro);
                if let Some(budget) = self.budgets.get_mut(&reservation.budget_id) {
                    budget.gas_used = budget.gas_used.saturating_add(item.gas_used);
                    budget.private_state_reads = budget
                        .private_state_reads
                        .saturating_add(item.private_state_reads);
                    budget.proof_bytes = budget.proof_bytes.saturating_add(item.proof_bytes);
                    if budget.gas_used >= budget.gas_limit {
                        budget.status = BudgetStatus::Exhausted;
                    }
                }
                if let Some(escrow) = self.escrows.get_mut(&reservation.escrow_id) {
                    escrow.consumed_gas = escrow.consumed_gas.saturating_add(item.gas_used);
                    escrow.status = if escrow.consumed_gas >= escrow.reserved_gas {
                        EscrowStatus::Consumed
                    } else {
                        EscrowStatus::PartiallyConsumed
                    };
                }
                if let Some(coupon_id) = &reservation.coupon_id {
                    if let Some(coupon) = self.coupons.get_mut(coupon_id) {
                        coupon.status = CouponStatus::Redeemed;
                        self.spent_nullifiers.insert(coupon.nullifier.clone());
                    }
                }
                self.record_fee_settlement(settled_fee);
            }
        }

        if let Some(control) = self.congestion_controls.get_mut(lane_id) {
            control.ingest(
                batch_gas,
                control.backlog_gas.saturating_sub(batch_gas),
                self.config.congestion_elasticity_bps,
                self.config.max_rebate_bps,
            );
        }
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.last_block_gas = batch_gas;
            if let Some(control) = self.congestion_controls.get(lane_id) {
                lane.congestion_multiplier_bps = control.multiplier_bps;
            }
        }
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn issue_rebate_coupon(
        &mut self,
        beneficiary_commitment: &str,
        lane_id: &str,
        reservation_id: &str,
        rebate_bps: u64,
        gas_units: u64,
        nonce: u64,
    ) -> Result<String> {
        require(
            self.rebates.len() < self.config.max_rebates,
            "rebate limit reached",
        )?;
        require(
            rebate_bps <= self.config.max_rebate_bps,
            "rebate exceeds configured cap",
        )?;
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "lane not found".to_string())?;
        require(lane.accepts_rebates, "lane does not accept rebates")?;
        let reservation = self
            .reservations
            .get(reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?;
        require(reservation.lane_id == lane_id, "rebate lane mismatch")?;
        require(
            matches!(
                reservation.status,
                ReservationStatus::Settled | ReservationStatus::Reverted
            ),
            "reservation is not settled",
        )?;
        let rebate = FeeRebateCoupon::new(
            beneficiary_commitment,
            lane_id,
            reservation_id,
            rebate_bps,
            gas_units,
            self.height,
            self.config.coupon_ttl_blocks,
            nonce,
        );
        let rebate_id = rebate.rebate_id.clone();
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn enforce_budget_fence(
        &mut self,
        budget_id: &str,
        candidate_nullifier: &str,
        gas_delta: u64,
        private_state_read_delta: u64,
        proof_byte_delta: u64,
    ) -> Result<()> {
        require(
            !candidate_nullifier.is_empty(),
            "candidate nullifier is empty",
        )?;
        require(
            !self.spent_nullifiers.contains(candidate_nullifier),
            "candidate nullifier already spent",
        )?;
        let budget = self
            .budgets
            .get_mut(budget_id)
            .ok_or_else(|| "budget not found".to_string())?;
        require(budget.status.metered(), "budget is not active")?;
        require(
            gas_delta <= budget.available_gas(),
            "budget gas fence exceeded",
        )?;
        require(
            budget
                .private_state_reads
                .saturating_add(private_state_read_delta)
                <= budget.private_state_read_limit,
            "private state read fence exceeded",
        )?;
        require(
            budget.proof_bytes.saturating_add(proof_byte_delta) <= budget.proof_byte_limit,
            "proof byte fence exceeded",
        )?;
        budget.gas_used = budget.gas_used.saturating_add(gas_delta);
        budget.private_state_reads = budget
            .private_state_reads
            .saturating_add(private_state_read_delta);
        budget.proof_bytes = budget.proof_bytes.saturating_add(proof_byte_delta);
        let fence_root = gas_meter_merkle_root(
            "BUDGET-FENCE-NULLIFIERS",
            vec![
                json!({ "previous_root": budget.fence_nullifier_root }),
                json!({ "candidate_nullifier": candidate_nullifier }),
            ],
        );
        budget.fence_nullifier_root = fence_root;
        self.spent_nullifiers
            .insert(candidate_nullifier.to_string());
        if budget.gas_used >= budget.gas_limit {
            budget.status = BudgetStatus::Exhausted;
        }
        Ok(())
    }

    pub fn publish_slashing_evidence(
        &mut self,
        accused_commitment: &str,
        reason: SlashingReason,
        linked_object_id: &str,
        evidence_root: &str,
        challenger_commitment: &str,
        nonce: u64,
    ) -> Result<String> {
        require(
            self.slashing_evidence.len() < self.config.max_slashing_evidence,
            "slashing evidence limit reached",
        )?;
        let evidence = SlashingEvidence::new(
            accused_commitment,
            reason,
            linked_object_id,
            evidence_root,
            challenger_commitment,
            self.height,
            nonce,
        );
        let evidence_id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        if let Some(budget) = self.budgets.get_mut(linked_object_id) {
            budget.status = BudgetStatus::Slashed;
        }
        if let Some(escrow) = self.escrows.get_mut(linked_object_id) {
            escrow.status = EscrowStatus::Slashed;
        }
        if let Some(reservation) = self.reservations.get_mut(linked_object_id) {
            reservation.status = ReservationStatus::Slashed;
        }
        Ok(evidence_id)
    }

    pub fn update_congestion(
        &mut self,
        lane_id: &str,
        observed_gas: u64,
        backlog_gas: u64,
        epoch: u64,
    ) -> Result<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| "lane not found".to_string())?;
        let control = self
            .congestion_controls
            .entry(lane_id.to_string())
            .or_insert_with(|| CongestionControl::new(lane_id, epoch, lane.target_gas_per_block));
        control.epoch = epoch;
        control.ingest(
            observed_gas,
            backlog_gas,
            self.config.congestion_elasticity_bps,
            self.config.max_rebate_bps,
        );
        lane.last_block_gas = observed_gas;
        lane.congestion_multiplier_bps = control.multiplier_bps;
        self.epoch = epoch;
        Ok(())
    }

    pub fn expire_at_height(&mut self, height: u64) {
        self.height = height;
        for escrow in self.escrows.values_mut() {
            if escrow.expires_at_height < height && escrow.status.reservable() {
                escrow.status = EscrowStatus::Expired;
            }
        }
        for coupon in self.coupons.values_mut() {
            if coupon.expires_at_height < height && coupon.status.spendable() {
                coupon.status = CouponStatus::Expired;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.expires_at_height < height && rebate.status == RebateStatus::Issued {
                rebate.status = RebateStatus::Expired;
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.expires_at_height < height
                && reservation.status == ReservationStatus::Reserved
            {
                reservation.status = ReservationStatus::Expired;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            lane_root: self.lane_root(),
            escrow_root: self.escrow_root(),
            budget_root: self.budget_root(),
            precompile_root: self.precompile_root(),
            coupon_root: self.coupon_root(),
            rebate_root: self.rebate_root(),
            auth_receipt_root: self.auth_receipt_root(),
            congestion_root: self.congestion_root(),
            reservation_root: self.reservation_root(),
            batch_root: self.batch_root(),
            slashing_root: self.slashing_root(),
            nullifier_root: self.nullifier_root(),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lanes: self.lanes.len() as u64,
            escrows: self.escrows.len() as u64,
            budgets: self.budgets.len() as u64,
            precompiles: self.precompiles.len() as u64,
            coupons: self.coupons.len() as u64,
            rebates: self.rebates.len() as u64,
            auth_receipts: self.auth_receipts.len() as u64,
            congestion_controls: self.congestion_controls.len() as u64,
            reservations: self.reservations.len() as u64,
            batches: self.batches.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
            gas_reserved: self
                .reservations
                .values()
                .fold(0_u64, |total, item| total.saturating_add(item.quoted_gas)),
            gas_consumed: self.batches.values().fold(0_u64, |total, batch| {
                total.saturating_add(batch.batch_gas_used)
            }),
            fees_quoted_micro: self.reservations.values().fold(0_u64, |total, item| {
                total.saturating_add(item.max_fee_micro)
            }),
            fees_settled_micro: self
                .reservations
                .values()
                .filter(|item| item.status == ReservationStatus::Settled)
                .fold(0_u64, |total, item| {
                    total.saturating_add(item.quoted_gas.saturating_mul(item.price_micro))
                }),
            rebates_issued_micro: self.rebates.values().fold(0_u64, |total, rebate| {
                total.saturating_add(
                    rebate
                        .gas_units
                        .saturating_mul(rebate.rebate_bps)
                        .saturating_div(MAX_BPS),
                )
            }),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "pq_confidential_contract_gas_meter_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "commitment_scheme": COMMITMENT_SCHEME,
            "nullifier_scheme": NULLIFIER_SCHEME,
            "coupon_scheme": COUPON_SCHEME,
            "rebate_scheme": REBATE_SCHEME,
            "slashing_scheme": SLASHING_SCHEME,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn lane_root(&self) -> String {
        let leaves = self
            .lanes
            .values()
            .map(GasPriceLane::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("GAS-LANES", leaves)
    }

    fn escrow_root(&self) -> String {
        let leaves = self
            .escrows
            .values()
            .map(ConfidentialGasEscrow::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("CONFIDENTIAL-GAS-ESCROWS", leaves)
    }

    fn budget_root(&self) -> String {
        let leaves = self
            .budgets
            .values()
            .map(ContractDomainGasBudget::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("CONTRACT-DOMAIN-GAS-BUDGETS", leaves)
    }

    fn precompile_root(&self) -> String {
        let leaves = self
            .precompiles
            .values()
            .map(PrecompileMeter::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("PRECOMPILE-METERS", leaves)
    }

    fn coupon_root(&self) -> String {
        let leaves = self
            .coupons
            .values()
            .map(WitnessProofGasCoupon::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("WITNESS-PROOF-GAS-COUPONS", leaves)
    }

    fn rebate_root(&self) -> String {
        let leaves = self
            .rebates
            .values()
            .map(FeeRebateCoupon::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("FEE-REBATE-COUPONS", leaves)
    }

    fn auth_receipt_root(&self) -> String {
        let leaves = self
            .auth_receipts
            .values()
            .map(PqAuthorizationReceipt::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("PQ-AUTH-RECEIPTS", leaves)
    }

    fn congestion_root(&self) -> String {
        let leaves = self
            .congestion_controls
            .values()
            .map(CongestionControl::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("CONGESTION-CONTROLS", leaves)
    }

    fn reservation_root(&self) -> String {
        let leaves = self
            .reservations
            .values()
            .map(GasReservation::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("GAS-RESERVATIONS", leaves)
    }

    fn batch_root(&self) -> String {
        let leaves = self
            .batches
            .values()
            .map(MeteringBatch::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("METERING-BATCHES", leaves)
    }

    fn slashing_root(&self) -> String {
        let leaves = self
            .slashing_evidence
            .values()
            .map(SlashingEvidence::public_record)
            .collect::<Vec<_>>();
        gas_meter_merkle_root("SLASHING-EVIDENCE", leaves)
    }

    fn nullifier_root(&self) -> String {
        let leaves = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        gas_meter_merkle_root("SPENT-NULLIFIERS", leaves)
    }

    fn record_fee_settlement(&mut self, _settled_fee: u64) {}
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    let mut payload = record.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove("state_root");
    }
    gas_meter_payload_root("STATE", &payload)
}

pub fn deterministic_contract_id(
    domain_id: &str,
    contract_code_root: &str,
    deployer_commitment: &str,
    nonce: u64,
) -> String {
    gas_meter_id(
        "CONTRACT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(contract_code_root),
            HashPart::Str(deployer_commitment),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn deterministic_call_nullifier(
    contract_id: &str,
    caller_commitment: &str,
    call_salt_root: &str,
    nonce: u64,
) -> String {
    gas_meter_id(
        "CALL-NULLIFIER",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(caller_commitment),
            HashPart::Str(call_salt_root),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn privacy_set_root(members: &[String]) -> String {
    let leaves = members
        .iter()
        .map(|member| json!({ "member_commitment": member }))
        .collect::<Vec<_>>();
    gas_meter_merkle_root("PRIVACY-SET", leaves)
}

pub fn precompile_set_root(precompile_ids: &[String]) -> String {
    let leaves = precompile_ids
        .iter()
        .map(|precompile_id| json!({ "precompile_id": precompile_id }))
        .collect::<Vec<_>>();
    gas_meter_merkle_root("PRECOMPILE-SET", leaves)
}

pub fn pq_authorized_action_root(actions: &[String]) -> String {
    let leaves = actions
        .iter()
        .map(|action| json!({ "action": action }))
        .collect::<Vec<_>>();
    gas_meter_merkle_root("PQ-AUTHORIZED-ACTIONS", leaves)
}

pub fn confidential_fee_commitment(
    owner_commitment: &str,
    asset_id: &str,
    amount_blinding_root: &str,
    nonce: u64,
) -> String {
    gas_meter_id(
        "CONFIDENTIAL-FEE-COMMITMENT",
        &[
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(amount_blinding_root),
            HashPart::Int(nonce as i128),
        ],
    )
}

fn gas_meter_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PQ-CONFIDENTIAL-CONTRACT-GAS-METER-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

fn gas_meter_hash_str(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PQ-CONFIDENTIAL-CONTRACT-GAS-METER-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

fn gas_meter_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PQ-CONFIDENTIAL-CONTRACT-GAS-METER-{domain}"),
        parts,
        16,
    )
}

fn gas_meter_merkle_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(
        &format!("PQ-CONFIDENTIAL-CONTRACT-GAS-METER-{domain}"),
        &leaves,
    )
}

fn empty_root(domain: &str) -> String {
    gas_meter_merkle_root(domain, Vec::new())
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
