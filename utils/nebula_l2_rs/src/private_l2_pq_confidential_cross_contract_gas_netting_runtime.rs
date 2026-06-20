use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-contract-gas-netting-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_GAS_NETTING_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-cross-contract-gas-netting-v1";
pub const CALLGRAPH_COMMITMENT_SCHEME: &str =
    "pq-confidential-cross-contract-callgraph-merkle-commitment-v1";
pub const SEALED_GAS_ESCROW_SCHEME: &str =
    "ml-kem-1024-sealed-confidential-cross-contract-gas-escrow-v1";
pub const WITNESS_CREDIT_SCHEME: &str = "recursive-witness-proof-gas-credit-root-v1";
pub const REBATE_SETTLEMENT_SCHEME: &str = "low-fee-confidential-gas-rebate-settlement-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "monero-style-cross-contract-gas-nullifier-fence-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-confidential-cross-contract-gas-netting-slashing-evidence-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_GAS_UNIT: &str = "confidential-cross-contract-gas";
pub const DEVNET_HEIGHT: u64 = 1_980_240;
pub const DEVNET_EPOCH: u64 = 3_771;
pub const DEFAULT_CYCLE_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_ESCROW_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 7;
pub const DEFAULT_NETTING_DISCOUNT_BPS: u64 = 1_800;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_WITNESS_CREDIT_BPS: u64 = 2_500;
pub const DEFAULT_REBATE_BPS: u64 = 600;
pub const DEFAULT_SLASH_BPS: u64 = 3_000;
pub const DEFAULT_CONGESTION_TARGET_GAS: u64 = 32_000_000;
pub const DEFAULT_CONGESTION_ELASTICITY_BPS: u64 = 1_500;
pub const DEFAULT_MAX_CYCLES: usize = 1_048_576;
pub const DEFAULT_MAX_OBLIGATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_SPONSOR_CREDITS: usize = 4_194_304;
pub const DEFAULT_MAX_ESCROWS: usize = 4_194_304;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_EVIDENCE: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractLaneKind {
    Wallet,
    Dex,
    Lending,
    Perpetuals,
    Oracle,
    Bridge,
    Governance,
    Vault,
    BatchSettlement,
    Emergency,
}

impl ContractLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::Vault => "vault",
            Self::BatchSettlement => "batch_settlement",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionClass {
    Free,
    Low,
    Normal,
    Elevated,
    Critical,
    EmergencyOnly,
}

impl CongestionClass {
    pub fn multiplier_bps(self) -> u64 {
        match self {
            Self::Free => 0,
            Self::Low => 700,
            Self::Normal => 1_000,
            Self::Elevated => 1_350,
            Self::Critical => 2_000,
            Self::EmergencyOnly => 3_000,
        }
    }

    pub fn admits_private_flow(self) -> bool {
        matches!(self, Self::Free | Self::Low | Self::Normal | Self::Elevated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleStatus {
    Open,
    Netting,
    Settling,
    Settled,
    Expired,
    Disputed,
    Slashed,
}

impl CycleStatus {
    pub fn accepts_obligation(self) -> bool {
        matches!(self, Self::Open | Self::Netting)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    Submitted,
    Sponsored,
    Netted,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl ObligationStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Submitted | Self::Sponsored | Self::Netted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCreditStatus {
    Posted,
    Attached,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Sealed,
    Reserved,
    Netted,
    Released,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Issued,
    Settled,
    Claimed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Consumed,
    Quarantined,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    DuplicateNullifier,
    InvalidPqApproval,
    EscrowUnderfunded,
    SponsorCreditReplay,
    CallgraphMismatch,
    WitnessCreditFraud,
    RebateOverclaim,
    CongestionMisreport,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::InvalidPqApproval => "invalid_pq_approval",
            Self::EscrowUnderfunded => "escrow_underfunded",
            Self::SponsorCreditReplay => "sponsor_credit_replay",
            Self::CallgraphMismatch => "callgraph_mismatch",
            Self::WitnessCreditFraud => "witness_credit_fraud",
            Self::RebateOverclaim => "rebate_overclaim",
            Self::CongestionMisreport => "congestion_misreport",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub gas_unit: String,
    pub cycle_ttl_blocks: u64,
    pub escrow_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub netting_discount_bps: u64,
    pub sponsor_cover_bps: u64,
    pub witness_credit_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub congestion_target_gas: u64,
    pub congestion_elasticity_bps: u64,
    pub max_cycles: usize,
    pub max_obligations: usize,
    pub max_sponsor_credits: usize,
    pub max_escrows: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
    pub max_evidence: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            gas_unit: DEFAULT_GAS_UNIT.to_string(),
            cycle_ttl_blocks: DEFAULT_CYCLE_TTL_BLOCKS,
            escrow_ttl_blocks: DEFAULT_ESCROW_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            netting_discount_bps: DEFAULT_NETTING_DISCOUNT_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            witness_credit_bps: DEFAULT_WITNESS_CREDIT_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            congestion_target_gas: DEFAULT_CONGESTION_TARGET_GAS,
            congestion_elasticity_bps: DEFAULT_CONGESTION_ELASTICITY_BPS,
            max_cycles: DEFAULT_MAX_CYCLES,
            max_obligations: DEFAULT_MAX_OBLIGATIONS,
            max_sponsor_credits: DEFAULT_MAX_SPONSOR_CREDITS,
            max_escrows: DEFAULT_MAX_ESCROWS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_fences: DEFAULT_MAX_FENCES,
            max_evidence: DEFAULT_MAX_EVIDENCE,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "gas_unit": self.gas_unit,
            "cycle_ttl_blocks": self.cycle_ttl_blocks,
            "escrow_ttl_blocks": self.escrow_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_fee_micro_units": self.base_fee_micro_units,
            "netting_discount_bps": self.netting_discount_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "witness_credit_bps": self.witness_credit_bps,
            "rebate_bps": self.rebate_bps,
            "slash_bps": self.slash_bps,
            "congestion_target_gas": self.congestion_target_gas,
            "congestion_elasticity_bps": self.congestion_elasticity_bps,
            "max_cycles": self.max_cycles,
            "max_obligations": self.max_obligations,
            "max_sponsor_credits": self.max_sponsor_credits,
            "max_escrows": self.max_escrows,
            "max_rebates": self.max_rebates,
            "max_fences": self.max_fences,
            "max_evidence": self.max_evidence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub cycles: u64,
    pub obligations: u64,
    pub sponsor_credits: u64,
    pub escrows: u64,
    pub witness_credits: u64,
    pub rebates: u64,
    pub fences: u64,
    pub slashing_evidence: u64,
    pub settlements: u64,
    pub total_gas_submitted: u128,
    pub total_gas_netted: u128,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            cycles: 0,
            obligations: 0,
            sponsor_credits: 0,
            escrows: 0,
            witness_credits: 0,
            rebates: 0,
            fences: 0,
            slashing_evidence: 0,
            settlements: 0,
            total_gas_submitted: 0,
            total_gas_netted: 0,
            total_fee_micro_units: 0,
            total_rebate_micro_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cycles": self.cycles,
            "obligations": self.obligations,
            "sponsor_credits": self.sponsor_credits,
            "escrows": self.escrows,
            "witness_credits": self.witness_credits,
            "rebates": self.rebates,
            "fences": self.fences,
            "slashing_evidence": self.slashing_evidence,
            "settlements": self.settlements,
            "total_gas_submitted": self.total_gas_submitted.to_string(),
            "total_gas_netted": self.total_gas_netted.to_string(),
            "total_fee_micro_units": self.total_fee_micro_units.to_string(),
            "total_rebate_micro_units": self.total_rebate_micro_units.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub cycle_root: String,
    pub obligation_root: String,
    pub sponsor_credit_root: String,
    pub escrow_root: String,
    pub witness_credit_root: String,
    pub rebate_root: String,
    pub fence_root: String,
    pub slashing_root: String,
    pub congestion_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "cycle_root": self.cycle_root,
            "obligation_root": self.obligation_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "escrow_root": self.escrow_root,
            "witness_credit_root": self.witness_credit_root,
            "rebate_root": self.rebate_root,
            "fence_root": self.fence_root,
            "slashing_root": self.slashing_root,
            "congestion_root": self.congestion_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPayerApproval {
    pub approval_id: String,
    pub payer_commitment: String,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub kem_ciphertext_commitment: String,
    pub policy_root: String,
    pub nonce_nullifier: String,
    pub security_bits: u16,
    pub expires_at_height: u64,
}

impl PqPayerApproval {
    pub fn new(
        payer_commitment: impl Into<String>,
        public_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        kem_ciphertext_commitment: impl Into<String>,
        policy_root: impl Into<String>,
        nonce_nullifier: impl Into<String>,
        security_bits: u16,
        expires_at_height: u64,
    ) -> Self {
        let payer_commitment = payer_commitment.into();
        let public_key_commitment = public_key_commitment.into();
        let signature_commitment = signature_commitment.into();
        let kem_ciphertext_commitment = kem_ciphertext_commitment.into();
        let policy_root = policy_root.into();
        let nonce_nullifier = nonce_nullifier.into();
        let approval_id = deterministic_id(
            "PQ-PAYER-APPROVAL-ID",
            &[
                &payer_commitment,
                &public_key_commitment,
                &signature_commitment,
                &kem_ciphertext_commitment,
                &policy_root,
                &nonce_nullifier,
            ],
        );
        Self {
            approval_id,
            payer_commitment,
            public_key_commitment,
            signature_commitment,
            kem_ciphertext_commitment,
            policy_root,
            nonce_nullifier,
            security_bits,
            expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "payer_commitment": self.payer_commitment,
            "public_key_commitment": self.public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "kem_ciphertext_commitment": self.kem_ciphertext_commitment,
            "policy_root": self.policy_root,
            "nonce_nullifier": self.nonce_nullifier,
            "security_bits": self.security_bits,
            "expires_at_height": self.expires_at_height,
            "suite": PQ_AUTH_SUITE,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallgraphCommitment {
    pub callgraph_id: String,
    pub entry_contract: String,
    pub terminal_contracts: BTreeSet<String>,
    pub edge_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub privacy_budget_root: String,
    pub max_depth: u16,
    pub metered_nodes: u32,
}

impl CallgraphCommitment {
    pub fn new(
        entry_contract: impl Into<String>,
        terminal_contracts: BTreeSet<String>,
        edge_root: impl Into<String>,
        read_set_root: impl Into<String>,
        write_set_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        max_depth: u16,
        metered_nodes: u32,
    ) -> Self {
        let entry_contract = entry_contract.into();
        let edge_root = edge_root.into();
        let read_set_root = read_set_root.into();
        let write_set_root = write_set_root.into();
        let privacy_budget_root = privacy_budget_root.into();
        let terminals = terminal_contracts.iter().cloned().collect::<Vec<_>>();
        let terminal_root = merkle_root(
            "CROSS-CONTRACT-GAS-CALLGRAPH-TERMINALS",
            &terminals.iter().map(|v| json!(v)).collect::<Vec<_>>(),
        );
        let callgraph_id = deterministic_id(
            "CALLGRAPH-COMMITMENT-ID",
            &[
                &entry_contract,
                &edge_root,
                &read_set_root,
                &write_set_root,
                &privacy_budget_root,
                &terminal_root,
            ],
        );
        Self {
            callgraph_id,
            entry_contract,
            terminal_contracts,
            edge_root,
            read_set_root,
            write_set_root,
            privacy_budget_root,
            max_depth,
            metered_nodes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "callgraph_id": self.callgraph_id,
            "entry_contract": self.entry_contract,
            "terminal_contracts": self.terminal_contracts.iter().cloned().collect::<Vec<_>>(),
            "edge_root": self.edge_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "privacy_budget_root": self.privacy_budget_root,
            "max_depth": self.max_depth,
            "metered_nodes": self.metered_nodes,
            "scheme": CALLGRAPH_COMMITMENT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingCycle {
    pub cycle_id: String,
    pub lane: ContractLaneKind,
    pub status: CycleStatus,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub settlement_height: u64,
    pub congestion_class: CongestionClass,
    pub sponsor_pool_commitment: String,
    pub obligation_ids: BTreeSet<String>,
    pub callgraph_root: String,
    pub netted_gas: u128,
    pub gross_gas: u128,
    pub net_fee_micro_units: u128,
}

impl NettingCycle {
    pub fn public_record(&self) -> Value {
        json!({
            "cycle_id": self.cycle_id,
            "lane": self.lane,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "settlement_height": self.settlement_height,
            "congestion_class": self.congestion_class,
            "sponsor_pool_commitment": self.sponsor_pool_commitment,
            "obligation_ids": self.obligation_ids.iter().cloned().collect::<Vec<_>>(),
            "callgraph_root": self.callgraph_root,
            "netted_gas": self.netted_gas.to_string(),
            "gross_gas": self.gross_gas.to_string(),
            "net_fee_micro_units": self.net_fee_micro_units.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GasObligation {
    pub obligation_id: String,
    pub cycle_id: String,
    pub payer_approval_id: String,
    pub lane: ContractLaneKind,
    pub status: ObligationStatus,
    pub callgraph: CallgraphCommitment,
    pub sealed_escrow_id: String,
    pub gas_limit: u64,
    pub gas_used_commitment: String,
    pub max_fee_micro_units: u128,
    pub priority_fee_micro_units: u128,
    pub nullifier: String,
    pub witness_credit_ids: BTreeSet<String>,
    pub sponsor_credit_ids: BTreeSet<String>,
    pub submitted_at_height: u64,
}

impl GasObligation {
    pub fn public_record(&self) -> Value {
        json!({
            "obligation_id": self.obligation_id,
            "cycle_id": self.cycle_id,
            "payer_approval_id": self.payer_approval_id,
            "lane": self.lane,
            "status": self.status,
            "callgraph": self.callgraph.public_record(),
            "sealed_escrow_id": self.sealed_escrow_id,
            "gas_limit": self.gas_limit,
            "gas_used_commitment": self.gas_used_commitment,
            "max_fee_micro_units": self.max_fee_micro_units.to_string(),
            "priority_fee_micro_units": self.priority_fee_micro_units.to_string(),
            "nullifier": self.nullifier,
            "witness_credit_ids": self.witness_credit_ids.iter().cloned().collect::<Vec<_>>(),
            "sponsor_credit_ids": self.sponsor_credit_ids.iter().cloned().collect::<Vec<_>>(),
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCredit {
    pub sponsor_credit_id: String,
    pub sponsor_commitment: String,
    pub cycle_id: String,
    pub obligation_id: String,
    pub status: SponsorCreditStatus,
    pub credit_micro_units: u128,
    pub cover_bps: u64,
    pub authorization_root: String,
    pub nullifier: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_credit_id": self.sponsor_credit_id,
            "sponsor_commitment": self.sponsor_commitment,
            "cycle_id": self.cycle_id,
            "obligation_id": self.obligation_id,
            "status": self.status,
            "credit_micro_units": self.credit_micro_units.to_string(),
            "cover_bps": self.cover_bps,
            "authorization_root": self.authorization_root,
            "nullifier": self.nullifier,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedGasEscrow {
    pub escrow_id: String,
    pub owner_commitment: String,
    pub cycle_id: String,
    pub status: EscrowStatus,
    pub asset_id: String,
    pub sealed_amount_commitment: String,
    pub min_amount_micro_units: u128,
    pub refund_commitment: String,
    pub nullifier: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedGasEscrow {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "owner_commitment": self.owner_commitment,
            "cycle_id": self.cycle_id,
            "status": self.status,
            "asset_id": self.asset_id,
            "sealed_amount_commitment": self.sealed_amount_commitment,
            "min_amount_micro_units": self.min_amount_micro_units.to_string(),
            "refund_commitment": self.refund_commitment,
            "nullifier": self.nullifier,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": SEALED_GAS_ESCROW_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessGasCredit {
    pub witness_credit_id: String,
    pub obligation_id: String,
    pub prover_commitment: String,
    pub proof_root: String,
    pub recursive_receipt_root: String,
    pub gas_credit_micro_units: u128,
    pub credit_bps: u64,
    pub nullifier: String,
    pub issued_at_height: u64,
}

impl WitnessGasCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_credit_id": self.witness_credit_id,
            "obligation_id": self.obligation_id,
            "prover_commitment": self.prover_commitment,
            "proof_root": self.proof_root,
            "recursive_receipt_root": self.recursive_receipt_root,
            "gas_credit_micro_units": self.gas_credit_micro_units.to_string(),
            "credit_bps": self.credit_bps,
            "nullifier": self.nullifier,
            "issued_at_height": self.issued_at_height,
            "scheme": WITNESS_CREDIT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateSettlement {
    pub rebate_id: String,
    pub cycle_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub amount_micro_units: u128,
    pub settlement_root: String,
    pub claim_nullifier: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebateSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "cycle_id": self.cycle_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "status": self.status,
            "amount_micro_units": self.amount_micro_units.to_string(),
            "settlement_root": self.settlement_root,
            "claim_nullifier": self.claim_nullifier,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": REBATE_SETTLEMENT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub cycle_id: String,
    pub nullifier: String,
    pub status: FenceStatus,
    pub privacy_set_size: u64,
    pub anchor_root: String,
    pub created_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "cycle_id": self.cycle_id,
            "nullifier": self.nullifier,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "anchor_root": self.anchor_root,
            "created_at_height": self.created_at_height,
            "scheme": PRIVACY_FENCE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionSignal {
    pub signal_id: String,
    pub lane: ContractLaneKind,
    pub class: CongestionClass,
    pub observed_gas: u64,
    pub target_gas: u64,
    pub fee_multiplier_bps: u64,
    pub oracle_commitment: String,
    pub height: u64,
}

impl CongestionSignal {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "lane": self.lane,
            "class": self.class,
            "observed_gas": self.observed_gas,
            "target_gas": self.target_gas,
            "fee_multiplier_bps": self.fee_multiplier_bps,
            "oracle_commitment": self.oracle_commitment,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashingReason,
    pub accused_commitment: String,
    pub cycle_id: String,
    pub obligation_id: String,
    pub evidence_root: String,
    pub penalty_micro_units: u128,
    pub reporter_commitment: String,
    pub accepted: bool,
    pub height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "accused_commitment": self.accused_commitment,
            "cycle_id": self.cycle_id,
            "obligation_id": self.obligation_id,
            "evidence_root": self.evidence_root,
            "penalty_micro_units": self.penalty_micro_units.to_string(),
            "reporter_commitment": self.reporter_commitment,
            "accepted": self.accepted,
            "height": self.height,
            "scheme": SLASHING_EVIDENCE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub height: u64,
    pub epoch: u64,
    pub config: Config,
    pub cycles: BTreeMap<String, NettingCycle>,
    pub obligations: BTreeMap<String, GasObligation>,
    pub approvals: BTreeMap<String, PqPayerApproval>,
    pub sponsor_credits: BTreeMap<String, SponsorCredit>,
    pub escrows: BTreeMap<String, SealedGasEscrow>,
    pub witness_credits: BTreeMap<String, WitnessGasCredit>,
    pub rebates: BTreeMap<String, FeeRebateSettlement>,
    pub fences: BTreeMap<String, PrivacyFence>,
    pub congestion_signals: BTreeMap<String, CongestionSignal>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
}

impl State {
    pub fn empty(height: u64, epoch: u64, config: Config) -> Self {
        Self {
            height,
            epoch,
            config,
            cycles: BTreeMap::new(),
            obligations: BTreeMap::new(),
            approvals: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            escrows: BTreeMap::new(),
            witness_credits: BTreeMap::new(),
            rebates: BTreeMap::new(),
            fences: BTreeMap::new(),
            congestion_signals: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::empty(DEVNET_HEIGHT, DEVNET_EPOCH, Config::devnet());
        let cycle_id = state
            .open_netting_cycle(
                ContractLaneKind::Dex,
                CongestionClass::Low,
                "devnet-sponsor-pool-root",
            )
            .unwrap_or_else(|err| format!("devnet-cycle-error-{err}"));
        let approval = PqPayerApproval::new(
            "devnet-payer-commitment",
            "devnet-ml-dsa-public-key-commitment",
            "devnet-ml-dsa-signature-commitment",
            "devnet-ml-kem-ciphertext-commitment",
            "devnet-payer-policy-root",
            "devnet-payer-approval-nullifier",
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEVNET_HEIGHT + 72,
        );
        let callgraph = CallgraphCommitment::new(
            "confidential-dex-router",
            BTreeSet::from([
                "confidential-stable-swap".to_string(),
                "confidential-vault-fee-hook".to_string(),
            ]),
            "devnet-callgraph-edge-root",
            "devnet-callgraph-read-root",
            "devnet-callgraph-write-root",
            "devnet-callgraph-privacy-budget-root",
            5,
            9,
        );
        let escrow_id = state
            .seal_gas_escrow(
                &cycle_id,
                "devnet-payer-commitment",
                "devnet-sealed-amount-commitment",
                1_500_000,
                "devnet-refund-commitment",
                "devnet-escrow-nullifier",
            )
            .unwrap_or_else(|err| format!("devnet-escrow-error-{err}"));
        let obligation_id = state
            .submit_gas_obligation(
                &cycle_id,
                approval,
                callgraph,
                &escrow_id,
                180_000,
                "devnet-gas-used-commitment",
                1_260_000,
                10_000,
                "devnet-obligation-nullifier",
            )
            .unwrap_or_else(|err| format!("devnet-obligation-error-{err}"));
        let _ = state.attach_sponsor_credit(
            &cycle_id,
            &obligation_id,
            "devnet-sponsor-commitment",
            900_000,
            DEFAULT_SPONSOR_COVER_BPS,
            "devnet-sponsor-authorization-root",
            "devnet-sponsor-nullifier",
        );
        let _ = state.issue_witness_gas_credit(
            &obligation_id,
            "devnet-prover-commitment",
            "devnet-proof-root",
            "devnet-recursive-receipt-root",
            120_000,
            DEFAULT_WITNESS_CREDIT_BPS,
            "devnet-witness-credit-nullifier",
        );
        let _ = state.settle_netting_cycle(&cycle_id, DEVNET_HEIGHT + 8);
        let _ = state.issue_gas_rebate(
            &cycle_id,
            "devnet-payer-commitment",
            42_000,
            "devnet-rebate-settlement-root",
            "devnet-rebate-nullifier",
        );
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            cycles: self.cycles.len() as u64,
            obligations: self.obligations.len() as u64,
            sponsor_credits: self.sponsor_credits.len() as u64,
            escrows: self.escrows.len() as u64,
            witness_credits: self.witness_credits.len() as u64,
            rebates: self.rebates.len() as u64,
            fences: self.fences.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            settlements: self
                .cycles
                .values()
                .filter(|cycle| cycle.status == CycleStatus::Settled)
                .count() as u64,
            total_gas_submitted: self
                .obligations
                .values()
                .map(|obligation| obligation.gas_limit as u128)
                .sum(),
            total_gas_netted: self.cycles.values().map(|cycle| cycle.netted_gas).sum(),
            total_fee_micro_units: self
                .obligations
                .values()
                .map(|obligation| obligation.max_fee_micro_units)
                .sum(),
            total_rebate_micro_units: self
                .rebates
                .values()
                .map(|rebate| rebate.amount_micro_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root(
            "CROSS-CONTRACT-GAS-NETTING-CONFIG",
            &self.config.public_record(),
        );
        let cycle_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-CYCLES",
            self.cycles
                .values()
                .map(NettingCycle::public_record)
                .collect(),
        );
        let obligation_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-OBLIGATIONS",
            self.obligations
                .values()
                .map(GasObligation::public_record)
                .collect(),
        );
        let sponsor_credit_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-SPONSOR-CREDITS",
            self.sponsor_credits
                .values()
                .map(SponsorCredit::public_record)
                .collect(),
        );
        let escrow_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-ESCROWS",
            self.escrows
                .values()
                .map(SealedGasEscrow::public_record)
                .collect(),
        );
        let witness_credit_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-WITNESS-CREDITS",
            self.witness_credits
                .values()
                .map(WitnessGasCredit::public_record)
                .collect(),
        );
        let rebate_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-REBATES",
            self.rebates
                .values()
                .map(FeeRebateSettlement::public_record)
                .collect(),
        );
        let fence_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-FENCES",
            self.fences
                .values()
                .map(PrivacyFence::public_record)
                .collect(),
        );
        let slashing_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-SLASHING",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record)
                .collect(),
        );
        let congestion_root = records_root(
            "CROSS-CONTRACT-GAS-NETTING-CONGESTION",
            self.congestion_signals
                .values()
                .map(CongestionSignal::public_record)
                .collect(),
        );
        let counters = self.counters();
        let counters_root = payload_root(
            "CROSS-CONTRACT-GAS-NETTING-COUNTERS",
            &counters.public_record(),
        );
        let state_payload = json!({
            "kind": "private_l2_pq_confidential_cross_contract_gas_netting_runtime_roots",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config_root": config_root,
            "cycle_root": cycle_root,
            "obligation_root": obligation_root,
            "sponsor_credit_root": sponsor_credit_root,
            "escrow_root": escrow_root,
            "witness_credit_root": witness_credit_root,
            "rebate_root": rebate_root,
            "fence_root": fence_root,
            "slashing_root": slashing_root,
            "congestion_root": congestion_root,
            "counters_root": counters_root,
        });
        let state_root = state_root_from_public_record(&state_payload);
        Roots {
            config_root: root_value(&state_payload, "config_root"),
            cycle_root: root_value(&state_payload, "cycle_root"),
            obligation_root: root_value(&state_payload, "obligation_root"),
            sponsor_credit_root: root_value(&state_payload, "sponsor_credit_root"),
            escrow_root: root_value(&state_payload, "escrow_root"),
            witness_credit_root: root_value(&state_payload, "witness_credit_root"),
            rebate_root: root_value(&state_payload, "rebate_root"),
            fence_root: root_value(&state_payload, "fence_root"),
            slashing_root: root_value(&state_payload, "slashing_root"),
            congestion_root: root_value(&state_payload, "congestion_root"),
            counters_root: root_value(&state_payload, "counters_root"),
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(values) = record.as_object_mut() {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_cross_contract_gas_netting_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "cycles": values_record(&self.cycles, NettingCycle::public_record),
            "obligations": values_record(&self.obligations, GasObligation::public_record),
            "approvals": values_record(&self.approvals, PqPayerApproval::public_record),
            "sponsor_credits": values_record(&self.sponsor_credits, SponsorCredit::public_record),
            "escrows": values_record(&self.escrows, SealedGasEscrow::public_record),
            "witness_credits": values_record(&self.witness_credits, WitnessGasCredit::public_record),
            "rebates": values_record(&self.rebates, FeeRebateSettlement::public_record),
            "fences": values_record(&self.fences, PrivacyFence::public_record),
            "congestion_signals": values_record(&self.congestion_signals, CongestionSignal::public_record),
            "slashing_evidence": values_record(&self.slashing_evidence, SlashingEvidence::public_record),
        })
    }

    pub fn open_netting_cycle(
        &mut self,
        lane: ContractLaneKind,
        congestion_class: CongestionClass,
        sponsor_pool_commitment: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.cycles.len() < self.config.max_cycles,
            "cycle capacity exceeded"
        );
        ensure!(
            congestion_class.admits_private_flow(),
            "congestion class does not admit private flow"
        );
        let sponsor_pool_commitment = sponsor_pool_commitment.into();
        ensure_non_empty(&sponsor_pool_commitment, "sponsor pool commitment")?;
        let cycle_id = deterministic_id(
            "CROSS-CONTRACT-GAS-NETTING-CYCLE-ID",
            &[
                lane.as_str(),
                congestion_class_label(congestion_class),
                &sponsor_pool_commitment,
                &self.height.to_string(),
                &self.epoch.to_string(),
                &(self.cycles.len() as u64).to_string(),
            ],
        );
        let signal = self.observe_congestion(
            lane,
            congestion_class,
            self.config.congestion_target_gas / 2,
            "deterministic-cycle-open-congestion-oracle",
        )?;
        let cycle = NettingCycle {
            cycle_id: cycle_id.clone(),
            lane,
            status: CycleStatus::Open,
            opened_at_height: self.height,
            closes_at_height: self.height + self.config.cycle_ttl_blocks,
            settlement_height: 0,
            congestion_class,
            sponsor_pool_commitment,
            obligation_ids: BTreeSet::new(),
            callgraph_root: signal,
            netted_gas: 0,
            gross_gas: 0,
            net_fee_micro_units: 0,
        };
        self.cycles.insert(cycle_id.clone(), cycle);
        Ok(cycle_id)
    }

    pub fn seal_gas_escrow(
        &mut self,
        cycle_id: &str,
        owner_commitment: impl Into<String>,
        sealed_amount_commitment: impl Into<String>,
        min_amount_micro_units: u128,
        refund_commitment: impl Into<String>,
        nullifier: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.escrows.len() < self.config.max_escrows,
            "escrow capacity exceeded"
        );
        ensure!(
            self.cycles.contains_key(cycle_id),
            "unknown cycle {cycle_id}"
        );
        let owner_commitment = owner_commitment.into();
        let sealed_amount_commitment = sealed_amount_commitment.into();
        let refund_commitment = refund_commitment.into();
        let nullifier = nullifier.into();
        ensure_non_empty(&owner_commitment, "escrow owner commitment")?;
        ensure_non_empty(&sealed_amount_commitment, "sealed amount commitment")?;
        self.reserve_nullifier(cycle_id, &nullifier, self.config.min_privacy_set_size)?;
        let escrow_id = deterministic_id(
            "SEALED-CROSS-CONTRACT-GAS-ESCROW-ID",
            &[
                cycle_id,
                &owner_commitment,
                &sealed_amount_commitment,
                &refund_commitment,
                &nullifier,
            ],
        );
        ensure!(
            !self.escrows.contains_key(&escrow_id),
            "escrow already exists {escrow_id}"
        );
        let escrow = SealedGasEscrow {
            escrow_id: escrow_id.clone(),
            owner_commitment,
            cycle_id: cycle_id.to_string(),
            status: EscrowStatus::Sealed,
            asset_id: self.config.fee_asset_id.clone(),
            sealed_amount_commitment,
            min_amount_micro_units,
            refund_commitment,
            nullifier,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.escrow_ttl_blocks,
        };
        self.escrows.insert(escrow_id.clone(), escrow);
        Ok(escrow_id)
    }

    pub fn submit_gas_obligation(
        &mut self,
        cycle_id: &str,
        payer_approval: PqPayerApproval,
        callgraph: CallgraphCommitment,
        sealed_escrow_id: &str,
        gas_limit: u64,
        gas_used_commitment: impl Into<String>,
        max_fee_micro_units: u128,
        priority_fee_micro_units: u128,
        nullifier: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.obligations.len() < self.config.max_obligations,
            "obligation capacity exceeded"
        );
        ensure!(gas_limit > 0, "gas limit must be positive");
        ensure!(
            payer_approval.security_bits >= self.config.min_pq_security_bits,
            "payer approval below PQ security floor"
        );
        ensure!(
            payer_approval.expires_at_height >= self.height,
            "payer approval expired"
        );
        let cycle = self
            .cycles
            .get(cycle_id)
            .ok_or_else(|| format!("unknown cycle {cycle_id}"))?;
        ensure!(
            cycle.status.accepts_obligation(),
            "cycle does not accept obligations"
        );
        ensure!(
            cycle.lane == lane_for_callgraph(&callgraph),
            "lane mismatch"
        );
        let escrow = self
            .escrows
            .get_mut(sealed_escrow_id)
            .ok_or_else(|| format!("unknown escrow {sealed_escrow_id}"))?;
        ensure!(
            escrow.status == EscrowStatus::Sealed,
            "escrow is not sealed"
        );
        ensure!(escrow.cycle_id == cycle_id, "escrow cycle mismatch");
        let gas_used_commitment = gas_used_commitment.into();
        let nullifier = nullifier.into();
        ensure_non_empty(&gas_used_commitment, "gas used commitment")?;
        self.reserve_nullifier(cycle_id, &nullifier, self.config.min_privacy_set_size)?;
        let fee_floor = self.estimate_fee_micro_units(gas_limit, cycle.congestion_class);
        ensure!(
            max_fee_micro_units >= fee_floor,
            "max fee below deterministic fee floor"
        );
        let obligation_id = deterministic_id(
            "CROSS-CONTRACT-GAS-OBLIGATION-ID",
            &[
                cycle_id,
                &payer_approval.approval_id,
                &callgraph.callgraph_id,
                sealed_escrow_id,
                &gas_limit.to_string(),
                &gas_used_commitment,
                &nullifier,
            ],
        );
        ensure!(
            !self.obligations.contains_key(&obligation_id),
            "obligation already exists {obligation_id}"
        );
        escrow.status = EscrowStatus::Reserved;
        let obligation = GasObligation {
            obligation_id: obligation_id.clone(),
            cycle_id: cycle_id.to_string(),
            payer_approval_id: payer_approval.approval_id.clone(),
            lane: cycle.lane,
            status: ObligationStatus::Submitted,
            callgraph,
            sealed_escrow_id: sealed_escrow_id.to_string(),
            gas_limit,
            gas_used_commitment,
            max_fee_micro_units,
            priority_fee_micro_units,
            nullifier,
            witness_credit_ids: BTreeSet::new(),
            sponsor_credit_ids: BTreeSet::new(),
            submitted_at_height: self.height,
        };
        self.approvals
            .insert(payer_approval.approval_id.clone(), payer_approval);
        self.obligations.insert(obligation_id.clone(), obligation);
        if let Some(cycle) = self.cycles.get_mut(cycle_id) {
            cycle.obligation_ids.insert(obligation_id.clone());
            cycle.gross_gas += gas_limit as u128;
            cycle.callgraph_root = self.cycle_callgraph_root(cycle_id);
        }
        Ok(obligation_id)
    }

    pub fn attach_sponsor_credit(
        &mut self,
        cycle_id: &str,
        obligation_id: &str,
        sponsor_commitment: impl Into<String>,
        credit_micro_units: u128,
        cover_bps: u64,
        authorization_root: impl Into<String>,
        nullifier: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.sponsor_credits.len() < self.config.max_sponsor_credits,
            "sponsor credit capacity exceeded"
        );
        ensure!(cover_bps <= MAX_BPS, "cover bps exceeds max");
        let obligation = self
            .obligations
            .get_mut(obligation_id)
            .ok_or_else(|| format!("unknown obligation {obligation_id}"))?;
        ensure!(obligation.cycle_id == cycle_id, "obligation cycle mismatch");
        ensure!(obligation.status.active(), "obligation is not active");
        let sponsor_commitment = sponsor_commitment.into();
        let authorization_root = authorization_root.into();
        let nullifier = nullifier.into();
        ensure_non_empty(&sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&authorization_root, "sponsor authorization root")?;
        self.reserve_nullifier(cycle_id, &nullifier, self.config.min_privacy_set_size)?;
        let sponsor_credit_id = deterministic_id(
            "CROSS-CONTRACT-GAS-SPONSOR-CREDIT-ID",
            &[
                cycle_id,
                obligation_id,
                &sponsor_commitment,
                &authorization_root,
                &credit_micro_units.to_string(),
                &cover_bps.to_string(),
                &nullifier,
            ],
        );
        ensure!(
            !self.sponsor_credits.contains_key(&sponsor_credit_id),
            "sponsor credit already exists {sponsor_credit_id}"
        );
        let credit = SponsorCredit {
            sponsor_credit_id: sponsor_credit_id.clone(),
            sponsor_commitment,
            cycle_id: cycle_id.to_string(),
            obligation_id: obligation_id.to_string(),
            status: SponsorCreditStatus::Attached,
            credit_micro_units,
            cover_bps,
            authorization_root,
            nullifier,
            posted_at_height: self.height,
            expires_at_height: self.height + self.config.cycle_ttl_blocks,
        };
        obligation
            .sponsor_credit_ids
            .insert(sponsor_credit_id.clone());
        obligation.status = ObligationStatus::Sponsored;
        self.sponsor_credits
            .insert(sponsor_credit_id.clone(), credit);
        Ok(sponsor_credit_id)
    }

    pub fn issue_witness_gas_credit(
        &mut self,
        obligation_id: &str,
        prover_commitment: impl Into<String>,
        proof_root: impl Into<String>,
        recursive_receipt_root: impl Into<String>,
        gas_credit_micro_units: u128,
        credit_bps: u64,
        nullifier: impl Into<String>,
    ) -> Result<String> {
        ensure!(credit_bps <= MAX_BPS, "credit bps exceeds max");
        let cycle_id = self
            .obligations
            .get(obligation_id)
            .map(|obligation| obligation.cycle_id.clone())
            .ok_or_else(|| format!("unknown obligation {obligation_id}"))?;
        let prover_commitment = prover_commitment.into();
        let proof_root = proof_root.into();
        let recursive_receipt_root = recursive_receipt_root.into();
        let nullifier = nullifier.into();
        ensure_non_empty(&proof_root, "proof root")?;
        self.reserve_nullifier(&cycle_id, &nullifier, self.config.min_privacy_set_size)?;
        let witness_credit_id = deterministic_id(
            "CROSS-CONTRACT-GAS-WITNESS-CREDIT-ID",
            &[
                obligation_id,
                &prover_commitment,
                &proof_root,
                &recursive_receipt_root,
                &gas_credit_micro_units.to_string(),
                &credit_bps.to_string(),
                &nullifier,
            ],
        );
        let credit = WitnessGasCredit {
            witness_credit_id: witness_credit_id.clone(),
            obligation_id: obligation_id.to_string(),
            prover_commitment,
            proof_root,
            recursive_receipt_root,
            gas_credit_micro_units,
            credit_bps,
            nullifier,
            issued_at_height: self.height,
        };
        if let Some(obligation) = self.obligations.get_mut(obligation_id) {
            obligation
                .witness_credit_ids
                .insert(witness_credit_id.clone());
        }
        self.witness_credits
            .insert(witness_credit_id.clone(), credit);
        Ok(witness_credit_id)
    }

    pub fn settle_netting_cycle(
        &mut self,
        cycle_id: &str,
        settlement_height: u64,
    ) -> Result<String> {
        let obligation_ids = self
            .cycles
            .get(cycle_id)
            .map(|cycle| cycle.obligation_ids.iter().cloned().collect::<Vec<_>>())
            .ok_or_else(|| format!("unknown cycle {cycle_id}"))?;
        ensure!(!obligation_ids.is_empty(), "cannot settle empty cycle");
        let mut gross_gas = 0_u128;
        let mut fee_total = 0_u128;
        let mut witness_total = 0_u128;
        let mut sponsor_total = 0_u128;
        for obligation_id in &obligation_ids {
            if let Some(obligation) = self.obligations.get(obligation_id) {
                gross_gas += obligation.gas_limit as u128;
                fee_total += obligation.max_fee_micro_units + obligation.priority_fee_micro_units;
                for witness_credit_id in &obligation.witness_credit_ids {
                    if let Some(credit) = self.witness_credits.get(witness_credit_id) {
                        witness_total += credit.gas_credit_micro_units;
                    }
                }
                for sponsor_credit_id in &obligation.sponsor_credit_ids {
                    if let Some(credit) = self.sponsor_credits.get(sponsor_credit_id) {
                        sponsor_total += credit.credit_micro_units;
                    }
                }
            }
        }
        let discount =
            fee_total.saturating_mul(self.config.netting_discount_bps as u128) / MAX_BPS as u128;
        let net_fee = fee_total
            .saturating_sub(discount)
            .saturating_sub(witness_total)
            .saturating_sub(sponsor_total);
        for obligation_id in &obligation_ids {
            if let Some(obligation) = self.obligations.get_mut(obligation_id) {
                obligation.status = ObligationStatus::Settled;
                if let Some(escrow) = self.escrows.get_mut(&obligation.sealed_escrow_id) {
                    escrow.status = EscrowStatus::Netted;
                }
                for sponsor_credit_id in &obligation.sponsor_credit_ids {
                    if let Some(credit) = self.sponsor_credits.get_mut(sponsor_credit_id) {
                        credit.status = SponsorCreditStatus::Consumed;
                    }
                }
            }
        }
        let callgraph_root = self.cycle_callgraph_root(cycle_id);
        if let Some(cycle) = self.cycles.get_mut(cycle_id) {
            ensure!(
                cycle.status.accepts_obligation() || cycle.status == CycleStatus::Settling,
                "cycle is not settleable"
            );
            cycle.status = CycleStatus::Settled;
            cycle.settlement_height = settlement_height;
            cycle.gross_gas = gross_gas;
            cycle.netted_gas = gross_gas.saturating_sub(gross_gas / 5);
            cycle.net_fee_micro_units = net_fee;
            cycle.callgraph_root = callgraph_root;
        }
        Ok(self.state_root())
    }

    pub fn issue_gas_rebate(
        &mut self,
        cycle_id: &str,
        beneficiary_commitment: impl Into<String>,
        amount_micro_units: u128,
        settlement_root: impl Into<String>,
        claim_nullifier: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.rebates.len() < self.config.max_rebates,
            "rebate capacity exceeded"
        );
        let cycle = self
            .cycles
            .get(cycle_id)
            .ok_or_else(|| format!("unknown cycle {cycle_id}"))?;
        ensure!(
            cycle.status == CycleStatus::Settled,
            "cycle must be settled"
        );
        let beneficiary_commitment = beneficiary_commitment.into();
        let settlement_root = settlement_root.into();
        let claim_nullifier = claim_nullifier.into();
        ensure_non_empty(&beneficiary_commitment, "rebate beneficiary commitment")?;
        self.reserve_nullifier(cycle_id, &claim_nullifier, self.config.min_privacy_set_size)?;
        let rebate_cap = cycle
            .net_fee_micro_units
            .saturating_mul(self.config.rebate_bps as u128)
            / MAX_BPS as u128;
        ensure!(amount_micro_units <= rebate_cap, "rebate exceeds cycle cap");
        let rebate_id = deterministic_id(
            "CROSS-CONTRACT-GAS-REBATE-ID",
            &[
                cycle_id,
                &beneficiary_commitment,
                &amount_micro_units.to_string(),
                &settlement_root,
                &claim_nullifier,
            ],
        );
        let rebate = FeeRebateSettlement {
            rebate_id: rebate_id.clone(),
            cycle_id: cycle_id.to_string(),
            beneficiary_commitment,
            status: RebateStatus::Issued,
            amount_micro_units,
            settlement_root,
            claim_nullifier,
            issued_at_height: self.height,
            expires_at_height: self.height + self.config.rebate_ttl_blocks,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn record_slashing_evidence(
        &mut self,
        reason: SlashingReason,
        accused_commitment: impl Into<String>,
        cycle_id: &str,
        obligation_id: &str,
        evidence_root: impl Into<String>,
        reporter_commitment: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.slashing_evidence.len() < self.config.max_evidence,
            "slashing evidence capacity exceeded"
        );
        ensure!(
            self.cycles.contains_key(cycle_id),
            "unknown cycle {cycle_id}"
        );
        ensure!(
            self.obligations.contains_key(obligation_id),
            "unknown obligation {obligation_id}"
        );
        let accused_commitment = accused_commitment.into();
        let evidence_root = evidence_root.into();
        let reporter_commitment = reporter_commitment.into();
        ensure_non_empty(&evidence_root, "slashing evidence root")?;
        let penalty_micro_units = self
            .obligations
            .get(obligation_id)
            .map(|obligation| {
                obligation
                    .max_fee_micro_units
                    .saturating_mul(self.config.slash_bps as u128)
                    / MAX_BPS as u128
            })
            .unwrap_or(0);
        let evidence_id = deterministic_id(
            "CROSS-CONTRACT-GAS-SLASHING-EVIDENCE-ID",
            &[
                reason.as_str(),
                &accused_commitment,
                cycle_id,
                obligation_id,
                &evidence_root,
                &reporter_commitment,
            ],
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            reason,
            accused_commitment,
            cycle_id: cycle_id.to_string(),
            obligation_id: obligation_id.to_string(),
            evidence_root,
            penalty_micro_units,
            reporter_commitment,
            accepted: true,
            height: self.height,
        };
        if let Some(obligation) = self.obligations.get_mut(obligation_id) {
            obligation.status = ObligationStatus::Slashed;
        }
        if let Some(cycle) = self.cycles.get_mut(cycle_id) {
            cycle.status = CycleStatus::Slashed;
        }
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn observe_congestion(
        &mut self,
        lane: ContractLaneKind,
        class: CongestionClass,
        observed_gas: u64,
        oracle_commitment: impl Into<String>,
    ) -> Result<String> {
        let oracle_commitment = oracle_commitment.into();
        ensure_non_empty(&oracle_commitment, "congestion oracle commitment")?;
        let fee_multiplier_bps = class
            .multiplier_bps()
            .saturating_mul(self.config.congestion_elasticity_bps)
            / 1_000;
        let signal_id = deterministic_id(
            "CROSS-CONTRACT-GAS-CONGESTION-SIGNAL-ID",
            &[
                lane.as_str(),
                congestion_class_label(class),
                &observed_gas.to_string(),
                &oracle_commitment,
                &self.height.to_string(),
            ],
        );
        let signal = CongestionSignal {
            signal_id: signal_id.clone(),
            lane,
            class,
            observed_gas,
            target_gas: self.config.congestion_target_gas,
            fee_multiplier_bps,
            oracle_commitment,
            height: self.height,
        };
        self.congestion_signals.insert(signal_id.clone(), signal);
        Ok(signal_id)
    }

    pub fn advance_height(&mut self, height: u64) -> Result<String> {
        ensure!(height >= self.height, "height cannot move backward");
        self.height = height;
        self.expire_stale_items();
        Ok(self.state_root())
    }

    fn reserve_nullifier(
        &mut self,
        cycle_id: &str,
        nullifier: &str,
        privacy_set_size: u64,
    ) -> Result<String> {
        ensure_non_empty(nullifier, "privacy nullifier")?;
        ensure!(
            privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below configured floor"
        );
        ensure!(
            self.fences.len() < self.config.max_fences,
            "fence capacity exceeded"
        );
        ensure!(
            !self
                .fences
                .values()
                .any(|fence| fence.nullifier == nullifier && fence.status != FenceStatus::Slashed),
            "duplicate privacy nullifier"
        );
        let anchor_root = payload_root(
            "CROSS-CONTRACT-GAS-PRIVACY-FENCE-ANCHOR",
            &json!({
                "cycle_id": cycle_id,
                "nullifier": nullifier,
                "height": self.height,
                "privacy_set_size": privacy_set_size,
            }),
        );
        let fence_id = deterministic_id(
            "CROSS-CONTRACT-GAS-PRIVACY-FENCE-ID",
            &[cycle_id, nullifier, &anchor_root],
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            cycle_id: cycle_id.to_string(),
            nullifier: nullifier.to_string(),
            status: FenceStatus::Open,
            privacy_set_size,
            anchor_root,
            created_at_height: self.height,
        };
        self.fences.insert(fence_id.clone(), fence);
        Ok(fence_id)
    }

    fn estimate_fee_micro_units(&self, gas_limit: u64, congestion_class: CongestionClass) -> u128 {
        let multiplier = congestion_class.multiplier_bps().max(1_000) as u128;
        gas_limit as u128 * self.config.base_fee_micro_units as u128 * multiplier / MAX_BPS as u128
    }

    fn cycle_callgraph_root(&self, cycle_id: &str) -> String {
        let leaves = self
            .obligations
            .values()
            .filter(|obligation| obligation.cycle_id == cycle_id)
            .map(|obligation| obligation.callgraph.public_record())
            .collect::<Vec<_>>();
        records_root("CROSS-CONTRACT-GAS-CYCLE-CALLGRAPH", leaves)
    }

    fn expire_stale_items(&mut self) {
        for cycle in self.cycles.values_mut() {
            if cycle.status.accepts_obligation() && cycle.closes_at_height < self.height {
                cycle.status = CycleStatus::Expired;
            }
        }
        for escrow in self.escrows.values_mut() {
            if matches!(escrow.status, EscrowStatus::Sealed | EscrowStatus::Reserved)
                && escrow.expires_at_height < self.height
            {
                escrow.status = EscrowStatus::Expired;
            }
        }
        for credit in self.sponsor_credits.values_mut() {
            if matches!(
                credit.status,
                SponsorCreditStatus::Posted | SponsorCreditStatus::Attached
            ) && credit.expires_at_height < self.height
            {
                credit.status = SponsorCreditStatus::Expired;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.status == RebateStatus::Issued && rebate.expires_at_height < self.height {
                rebate.status = RebateStatus::Expired;
            }
        }
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-GAS-NETTING-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    let root = merkle_root(domain, &leaves);
    domain_hash(
        &format!("{domain}:id"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(&root)],
        20,
    )
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn values_record<T>(
    values: &BTreeMap<String, T>,
    projector: impl Fn(&T) -> Value,
) -> Vec<Value> {
    values.values().map(projector).collect()
}

pub fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    Ok(())
}

pub fn congestion_class_label(class: CongestionClass) -> &'static str {
    match class {
        CongestionClass::Free => "free",
        CongestionClass::Low => "low",
        CongestionClass::Normal => "normal",
        CongestionClass::Elevated => "elevated",
        CongestionClass::Critical => "critical",
        CongestionClass::EmergencyOnly => "emergency_only",
    }
}

pub fn lane_for_callgraph(callgraph: &CallgraphCommitment) -> ContractLaneKind {
    if callgraph.entry_contract.contains("dex") || callgraph.entry_contract.contains("swap") {
        ContractLaneKind::Dex
    } else if callgraph.entry_contract.contains("lend") {
        ContractLaneKind::Lending
    } else if callgraph.entry_contract.contains("perp") {
        ContractLaneKind::Perpetuals
    } else if callgraph.entry_contract.contains("oracle") {
        ContractLaneKind::Oracle
    } else if callgraph.entry_contract.contains("bridge") {
        ContractLaneKind::Bridge
    } else if callgraph.entry_contract.contains("governance") {
        ContractLaneKind::Governance
    } else if callgraph.entry_contract.contains("vault") {
        ContractLaneKind::Vault
    } else if callgraph.entry_contract.contains("batch") {
        ContractLaneKind::BatchSettlement
    } else {
        ContractLaneKind::Wallet
    }
}

fn root_value(record: &Value, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| payload_root("CROSS-CONTRACT-GAS-NETTING-MISSING-ROOT", &json!(key)))
}
