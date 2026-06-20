use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FeeSponsorSettlementResult<T> = Result<T, String>;

pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fee-sponsor-settlement-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEVNET_HEIGHT: u64 = 512;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_VAULT_SCHEME: &str =
    "private-sponsor-vault-commitment-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_OBLIGATION_SCHEME: &str =
    "private-flow-fee-obligation-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_REBATE_SCHEME: &str = "privacy-safe-rebate-root-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_PROOF_MARKET_SCHEME: &str =
    "sponsored-private-proof-market-payout-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_MONERO_EXIT_SUBSIDY_SCHEME: &str =
    "monero-exit-subsidy-root-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_RECEIPT_SCHEME: &str =
    "roots-only-sponsored-fee-settlement-receipt-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_SOLVENCY_SCHEME: &str =
    "sponsor-solvency-coverage-attestation-v1";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_REBATE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_EPOCH_BLOCKS: u64 = 96;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 4;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_RECEIPT_DELAY_BLOCKS: u64 = 12;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MIN_SPONSOR_DEPOSIT_UNITS: u64 = 100_000;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MIN_SOLVENCY_COVERAGE_BPS: u64 = 11_000;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_FEE_CAP_MICRO_UNITS: u64 = 2_500;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_DEFI_CAP_MICRO_UNITS: u64 = 1_600;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_CONTRACT_CAP_MICRO_UNITS: u64 = 1_900;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MONERO_EXIT_CAP_MICRO_UNITS: u64 = 2_200;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_PROOF_MARKET_CAP_MICRO_UNITS: u64 = 950;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_REBATE_BPS: u64 = 8_500;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_PROTOCOL_TAKE_BPS: u64 = 120;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_PROVER_PAYOUT_BPS: u64 = 7_000;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_EXIT_SUBSIDY_BPS: u64 = 2_500;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8_000;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_SPONSORS: usize = 2048;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_OPEN_OBLIGATIONS: usize = 131_072;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_RECEIPTS: usize = 262_144;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_SOLVENCY_NOTES: usize = 65_536;
pub const PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsoredFlowKind {
    PrivateTransfer,
    PrivateSwap,
    PrivateLending,
    PrivatePerps,
    PrivateOptions,
    PrivateVault,
    SmartContractCall,
    TokenMint,
    TokenBurn,
    MoneroExit,
    MoneroDeposit,
    RecursiveProofAggregation,
    StateChannelClose,
    EmergencyEscape,
}

impl SponsoredFlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerps => "private_perps",
            Self::PrivateOptions => "private_options",
            Self::PrivateVault => "private_vault",
            Self::SmartContractCall => "smart_contract_call",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::MoneroExit => "monero_exit",
            Self::MoneroDeposit => "monero_deposit",
            Self::RecursiveProofAggregation => "recursive_proof_aggregation",
            Self::StateChannelClose => "state_channel_close",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::PrivateTransfer => 900,
            Self::PrivateSwap => 1_300,
            Self::PrivateLending => 1_500,
            Self::PrivatePerps => 1_700,
            Self::PrivateOptions => 1_800,
            Self::PrivateVault => 1_400,
            Self::SmartContractCall => {
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_CONTRACT_CAP_MICRO_UNITS
            }
            Self::TokenMint | Self::TokenBurn => 1_100,
            Self::MoneroExit | Self::MoneroDeposit => {
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MONERO_EXIT_CAP_MICRO_UNITS
            }
            Self::RecursiveProofAggregation => {
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_PROOF_MARKET_CAP_MICRO_UNITS
            }
            Self::StateChannelClose => 800,
            Self::EmergencyEscape => {
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_FEE_CAP_MICRO_UNITS
            }
        }
    }

    pub fn settlement_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::MoneroExit | Self::MoneroDeposit => 9_100,
            Self::PrivatePerps | Self::PrivateOptions => 8_400,
            Self::SmartContractCall => 7_900,
            Self::PrivateSwap | Self::PrivateLending => 7_300,
            Self::PrivateVault => 6_700,
            Self::TokenMint | Self::TokenBurn => 6_100,
            Self::StateChannelClose => 5_800,
            Self::PrivateTransfer => 5_300,
            Self::RecursiveProofAggregation => 4_900,
        }
    }

    pub fn defi(self) -> bool {
        matches!(
            self,
            Self::PrivateSwap
                | Self::PrivateLending
                | Self::PrivatePerps
                | Self::PrivateOptions
                | Self::PrivateVault
        )
    }

    pub fn contract(self) -> bool {
        matches!(
            self,
            Self::SmartContractCall
                | Self::TokenMint
                | Self::TokenBurn
                | Self::PrivateSwap
                | Self::PrivateLending
                | Self::PrivatePerps
                | Self::PrivateOptions
                | Self::PrivateVault
        )
    }

    pub fn monero_exit(self) -> bool {
        matches!(self, Self::MoneroExit)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Throttled,
    Paused,
    Exhausted,
    Insolvent,
    Slashed,
    Retired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Insolvent => "insolvent",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_open_obligation(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    Open,
    Reserved,
    Proven,
    Settled,
    Expired,
    Cancelled,
    Challenged,
}

impl ObligationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Reserved | Self::Proven | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementOutcome {
    Settled,
    RebateOnly,
    ProofPayoutOnly,
    ExitSubsidyOnly,
    Capped,
    Slashed,
}

impl SettlementOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Settled => "settled",
            Self::RebateOnly => "rebate_only",
            Self::ProofPayoutOnly => "proof_payout_only",
            Self::ExitSubsidyOnly => "exit_subsidy_only",
            Self::Capped => "capped",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub epoch_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub receipt_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_sponsor_deposit_units: u64,
    pub min_solvency_coverage_bps: u64,
    pub default_max_fee_cap_micro_units: u64,
    pub defi_cap_micro_units: u64,
    pub contract_cap_micro_units: u64,
    pub monero_exit_cap_micro_units: u64,
    pub proof_market_cap_micro_units: u64,
    pub max_rebate_bps: u64,
    pub protocol_take_bps: u64,
    pub prover_payout_bps: u64,
    pub exit_subsidy_bps: u64,
    pub low_fee_target_bps: u64,
    pub max_sponsors: usize,
    pub max_open_obligations: usize,
    pub max_receipts: usize,
    pub max_solvency_notes: usize,
    pub hash_suite: String,
    pub pq_authorization_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_SCHEMA_VERSION,
            fee_asset_id: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_REBATE_ASSET_ID.to_string(),
            monero_network: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_L2_NETWORK.to_string(),
            epoch_blocks: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_EPOCH_BLOCKS,
            settlement_delay_blocks:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            receipt_delay_blocks: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_RECEIPT_DELAY_BLOCKS,
            challenge_window_blocks:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_sponsor_deposit_units:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MIN_SPONSOR_DEPOSIT_UNITS,
            min_solvency_coverage_bps:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MIN_SOLVENCY_COVERAGE_BPS,
            default_max_fee_cap_micro_units:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_FEE_CAP_MICRO_UNITS,
            defi_cap_micro_units: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_DEFI_CAP_MICRO_UNITS,
            contract_cap_micro_units:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_CONTRACT_CAP_MICRO_UNITS,
            monero_exit_cap_micro_units:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MONERO_EXIT_CAP_MICRO_UNITS,
            proof_market_cap_micro_units:
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_PROOF_MARKET_CAP_MICRO_UNITS,
            max_rebate_bps: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_REBATE_BPS,
            protocol_take_bps: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_PROTOCOL_TAKE_BPS,
            prover_payout_bps: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_PROVER_PAYOUT_BPS,
            exit_subsidy_bps: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_EXIT_SUBSIDY_BPS,
            low_fee_target_bps: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_LOW_FEE_TARGET_BPS,
            max_sponsors: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_SPONSORS,
            max_open_obligations: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_OPEN_OBLIGATIONS,
            max_receipts: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_RECEIPTS,
            max_solvency_notes: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEFAULT_MAX_SOLVENCY_NOTES,
            hash_suite: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_HASH_SUITE.to_string(),
            pq_authorization_suite: PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_PQ_AUTH_SUITE.to_string(),
        }
    }

    pub fn cap_for_flow(&self, flow_kind: SponsoredFlowKind) -> u64 {
        if flow_kind.defi() {
            self.defi_cap_micro_units
        } else if flow_kind.contract() {
            self.contract_cap_micro_units
        } else if flow_kind.monero_exit() {
            self.monero_exit_cap_micro_units
        } else if matches!(flow_kind, SponsoredFlowKind::RecursiveProofAggregation) {
            self.proof_market_cap_micro_units
        } else {
            self.default_max_fee_cap_micro_units
                .min(flow_kind.default_fee_cap_micro_units())
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": CHAIN_ID,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "epoch_blocks": self.epoch_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "receipt_delay_blocks": self.receipt_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_sponsor_deposit_units": self.min_sponsor_deposit_units,
            "min_solvency_coverage_bps": self.min_solvency_coverage_bps,
            "default_max_fee_cap_micro_units": self.default_max_fee_cap_micro_units,
            "defi_cap_micro_units": self.defi_cap_micro_units,
            "contract_cap_micro_units": self.contract_cap_micro_units,
            "monero_exit_cap_micro_units": self.monero_exit_cap_micro_units,
            "proof_market_cap_micro_units": self.proof_market_cap_micro_units,
            "max_rebate_bps": self.max_rebate_bps,
            "protocol_take_bps": self.protocol_take_bps,
            "prover_payout_bps": self.prover_payout_bps,
            "exit_subsidy_bps": self.exit_subsidy_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "max_sponsors": self.max_sponsors,
            "max_open_obligations": self.max_open_obligations,
            "max_receipts": self.max_receipts,
            "max_solvency_notes": self.max_solvency_notes,
            "hash_suite": self.hash_suite,
            "pq_authorization_suite": self.pq_authorization_suite,
            "vault_scheme": PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_VAULT_SCHEME,
            "obligation_scheme": PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_OBLIGATION_SCHEME,
            "rebate_scheme": PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_REBATE_SCHEME,
            "proof_market_scheme": PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_PROOF_MARKET_SCHEME,
            "monero_exit_subsidy_scheme": PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_MONERO_EXIT_SUBSIDY_SCHEME,
            "receipt_scheme": PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_RECEIPT_SCHEME,
            "solvency_scheme": PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_SOLVENCY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub sponsors_registered: u64,
    pub obligations_opened: u64,
    pub obligations_settled: u64,
    pub receipts_issued: u64,
    pub proof_market_payouts: u64,
    pub rebate_roots_recorded: u64,
    pub monero_exit_subsidies: u64,
    pub solvency_checks: u64,
    pub capped_obligations: u64,
    pub total_reserved_units: u64,
    pub total_settled_units: u64,
    pub total_rebate_units: u64,
    pub total_proof_payout_units: u64,
    pub total_exit_subsidy_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsors_registered": self.sponsors_registered,
            "obligations_opened": self.obligations_opened,
            "obligations_settled": self.obligations_settled,
            "receipts_issued": self.receipts_issued,
            "proof_market_payouts": self.proof_market_payouts,
            "rebate_roots_recorded": self.rebate_roots_recorded,
            "monero_exit_subsidies": self.monero_exit_subsidies,
            "solvency_checks": self.solvency_checks,
            "capped_obligations": self.capped_obligations,
            "total_reserved_units": self.total_reserved_units,
            "total_settled_units": self.total_settled_units,
            "total_rebate_units": self.total_rebate_units,
            "total_proof_payout_units": self.total_proof_payout_units,
            "total_exit_subsidy_units": self.total_exit_subsidy_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorVault {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub vault_commitment: String,
    pub reserve_root: String,
    pub policy_root: String,
    pub allowed_flow_root: String,
    pub payout_address_root: String,
    pub total_deposit_units: u64,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub min_balance_units: u64,
    pub daily_cap_units: u64,
    pub fee_cap_micro_units: u64,
    pub solvency_coverage_bps: u64,
    pub status: SponsorStatus,
    pub registered_at_height: u64,
    pub last_solvency_height: u64,
    pub nonce: u64,
}

impl SponsorVault {
    pub fn available_units(&self) -> u64 {
        self.total_deposit_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.settled_units)
            .saturating_sub(self.min_balance_units)
    }

    pub fn solvent(&self, required_coverage_bps: u64) -> bool {
        self.status.can_open_obligation()
            && self.solvency_coverage_bps >= required_coverage_bps
            && self.total_deposit_units >= self.min_balance_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "vault_commitment": self.vault_commitment,
            "reserve_root": self.reserve_root,
            "policy_root": self.policy_root,
            "allowed_flow_root": self.allowed_flow_root,
            "payout_address_root": self.payout_address_root,
            "total_deposit_units": self.total_deposit_units,
            "reserved_units": self.reserved_units,
            "settled_units": self.settled_units,
            "available_units": self.available_units(),
            "min_balance_units": self.min_balance_units,
            "daily_cap_units": self.daily_cap_units,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "solvency_coverage_bps": self.solvency_coverage_bps,
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
            "last_solvency_height": self.last_solvency_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fee_sponsor_hash("SPONSOR-VAULT", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeObligation {
    pub obligation_id: String,
    pub sponsor_id: String,
    pub flow_kind: SponsoredFlowKind,
    pub flow_commitment: String,
    pub user_nullifier_root: String,
    pub fee_quote_root: String,
    pub proof_request_root: String,
    pub rebate_commitment_root: String,
    pub monero_exit_commitment_root: String,
    pub max_fee_micro_units: u64,
    pub reserved_fee_units: u64,
    pub priority_weight: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ObligationStatus,
    pub settlement_receipt_id: Option<String>,
}

impl FeeObligation {
    pub fn public_record(&self) -> Value {
        json!({
            "obligation_id": self.obligation_id,
            "sponsor_id": self.sponsor_id,
            "flow_kind": self.flow_kind.as_str(),
            "flow_commitment": self.flow_commitment,
            "user_nullifier_root": self.user_nullifier_root,
            "fee_quote_root": self.fee_quote_root,
            "proof_request_root": self.proof_request_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "monero_exit_commitment_root": self.monero_exit_commitment_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "reserved_fee_units": self.reserved_fee_units,
            "priority_weight": self.priority_weight,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fee_sponsor_hash("FEE-OBLIGATION", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementInput {
    pub obligation_id: String,
    pub settled_fee_units: u64,
    pub prover_payout_units: u64,
    pub rebate_units: u64,
    pub monero_exit_subsidy_units: u64,
    pub proof_market_payout_root: String,
    pub rebate_root: String,
    pub monero_exit_subsidy_root: String,
    pub settlement_proof_root: String,
    pub solvency_attestation_root: String,
    pub settled_at_height: u64,
    pub outcome: SettlementOutcome,
}

impl SettlementInput {
    pub fn public_record(&self) -> Value {
        json!({
            "obligation_id": self.obligation_id,
            "settled_fee_units": self.settled_fee_units,
            "prover_payout_units": self.prover_payout_units,
            "rebate_units": self.rebate_units,
            "monero_exit_subsidy_units": self.monero_exit_subsidy_units,
            "proof_market_payout_root": self.proof_market_payout_root,
            "rebate_root": self.rebate_root,
            "monero_exit_subsidy_root": self.monero_exit_subsidy_root,
            "settlement_proof_root": self.settlement_proof_root,
            "solvency_attestation_root": self.solvency_attestation_root,
            "settled_at_height": self.settled_at_height,
            "outcome": self.outcome.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub obligation_id: String,
    pub sponsor_id: String,
    pub flow_kind: SponsoredFlowKind,
    pub obligation_root: String,
    pub settlement_input_root: String,
    pub proof_market_payout_root: String,
    pub rebate_root: String,
    pub monero_exit_subsidy_root: String,
    pub settlement_proof_root: String,
    pub solvency_attestation_root: String,
    pub settled_fee_units: u64,
    pub prover_payout_units: u64,
    pub rebate_units: u64,
    pub monero_exit_subsidy_units: u64,
    pub protocol_fee_units: u64,
    pub sponsor_remaining_available_units: u64,
    pub outcome: SettlementOutcome,
    pub settled_at_height: u64,
    pub releasable_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "obligation_id": self.obligation_id,
            "sponsor_id": self.sponsor_id,
            "flow_kind": self.flow_kind.as_str(),
            "obligation_root": self.obligation_root,
            "settlement_input_root": self.settlement_input_root,
            "proof_market_payout_root": self.proof_market_payout_root,
            "rebate_root": self.rebate_root,
            "monero_exit_subsidy_root": self.monero_exit_subsidy_root,
            "settlement_proof_root": self.settlement_proof_root,
            "solvency_attestation_root": self.solvency_attestation_root,
            "settled_fee_units": self.settled_fee_units,
            "prover_payout_units": self.prover_payout_units,
            "rebate_units": self.rebate_units,
            "monero_exit_subsidy_units": self.monero_exit_subsidy_units,
            "protocol_fee_units": self.protocol_fee_units,
            "sponsor_remaining_available_units": self.sponsor_remaining_available_units,
            "outcome": self.outcome.as_str(),
            "settled_at_height": self.settled_at_height,
            "releasable_at_height": self.releasable_at_height,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fee_sponsor_hash(
            "SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencyNote {
    pub note_id: String,
    pub sponsor_id: String,
    pub sponsor_vault_root: String,
    pub reserve_root: String,
    pub outstanding_obligation_root: String,
    pub coverage_bps: u64,
    pub checked_at_height: u64,
    pub solvent: bool,
}

impl SolvencyNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_vault_root": self.sponsor_vault_root,
            "reserve_root": self.reserve_root,
            "outstanding_obligation_root": self.outstanding_obligation_root,
            "coverage_bps": self.coverage_bps,
            "checked_at_height": self.checked_at_height,
            "solvent": self.solvent,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub sponsor_vault_root: String,
    pub obligation_root: String,
    pub open_obligation_root: String,
    pub rebate_root: String,
    pub proof_market_payout_root: String,
    pub monero_exit_subsidy_root: String,
    pub settlement_receipt_root: String,
    pub solvency_note_root: String,
    pub sponsor_solvency_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_vault_root": self.sponsor_vault_root,
            "obligation_root": self.obligation_root,
            "open_obligation_root": self.open_obligation_root,
            "rebate_root": self.rebate_root,
            "proof_market_payout_root": self.proof_market_payout_root,
            "monero_exit_subsidy_root": self.monero_exit_subsidy_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "solvency_note_root": self.solvency_note_root,
            "sponsor_solvency_root": self.sponsor_solvency_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub sponsors: BTreeMap<String, SponsorVault>,
    pub obligations: BTreeMap<String, FeeObligation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub solvency_notes: BTreeMap<String, SolvencyNote>,
    pub rebate_roots: BTreeSet<String>,
    pub proof_market_payout_roots: BTreeSet<String>,
    pub monero_exit_subsidy_roots: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            sponsors: BTreeMap::new(),
            obligations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            solvency_notes: BTreeMap::new(),
            rebate_roots: BTreeSet::new(),
            proof_market_payout_roots: BTreeSet::new(),
            monero_exit_subsidy_roots: BTreeSet::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_sponsor(
        &mut self,
        sponsor_commitment: impl Into<String>,
        vault_commitment: impl Into<String>,
        reserve_root: impl Into<String>,
        policy_root: impl Into<String>,
        allowed_flow_root: impl Into<String>,
        payout_address_root: impl Into<String>,
        total_deposit_units: u64,
        min_balance_units: u64,
        daily_cap_units: u64,
        fee_cap_micro_units: u64,
        solvency_coverage_bps: u64,
        registered_at_height: u64,
    ) -> PrivateL2FeeSponsorSettlementResult<String> {
        if self.sponsors.len() >= self.config.max_sponsors {
            return Err("sponsor registry capacity reached".to_string());
        }
        if total_deposit_units < self.config.min_sponsor_deposit_units {
            return Err("sponsor deposit below minimum".to_string());
        }
        if min_balance_units > total_deposit_units {
            return Err("sponsor minimum balance exceeds deposit".to_string());
        }
        if fee_cap_micro_units == 0
            || fee_cap_micro_units > self.config.default_max_fee_cap_micro_units
        {
            return Err("sponsor fee cap outside configured low-fee envelope".to_string());
        }

        let sponsor_commitment = sponsor_commitment.into();
        let vault_commitment = vault_commitment.into();
        let reserve_root = reserve_root.into();
        let policy_root = policy_root.into();
        let allowed_flow_root = allowed_flow_root.into();
        let payout_address_root = payout_address_root.into();
        ensure_non_empty(&sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&vault_commitment, "vault commitment")?;
        ensure_non_empty(&reserve_root, "reserve root")?;
        ensure_non_empty(&policy_root, "policy root")?;
        ensure_non_empty(&allowed_flow_root, "allowed flow root")?;
        ensure_non_empty(&payout_address_root, "payout address root")?;

        let sponsor_id = sponsor_id(
            &sponsor_commitment,
            &vault_commitment,
            &reserve_root,
            registered_at_height,
            self.counters.sponsors_registered,
        );
        if self.sponsors.contains_key(&sponsor_id) {
            return Err(format!("sponsor already registered: {sponsor_id}"));
        }

        let status = if solvency_coverage_bps >= self.config.min_solvency_coverage_bps {
            SponsorStatus::Active
        } else {
            SponsorStatus::Throttled
        };
        let sponsor = SponsorVault {
            sponsor_id: sponsor_id.clone(),
            sponsor_commitment,
            vault_commitment,
            reserve_root,
            policy_root,
            allowed_flow_root,
            payout_address_root,
            total_deposit_units,
            reserved_units: 0,
            settled_units: 0,
            min_balance_units,
            daily_cap_units,
            fee_cap_micro_units,
            solvency_coverage_bps,
            status,
            registered_at_height,
            last_solvency_height: registered_at_height,
            nonce: self.counters.sponsors_registered,
        };
        self.sponsors.insert(sponsor_id.clone(), sponsor);
        self.counters.sponsors_registered = self.counters.sponsors_registered.saturating_add(1);
        self.record_solvency_note(&sponsor_id, registered_at_height)?;
        Ok(sponsor_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_obligation(
        &mut self,
        sponsor_id: impl AsRef<str>,
        flow_kind: SponsoredFlowKind,
        flow_commitment: impl Into<String>,
        user_nullifier_root: impl Into<String>,
        fee_quote_root: impl Into<String>,
        proof_request_root: impl Into<String>,
        rebate_commitment_root: impl Into<String>,
        monero_exit_commitment_root: impl Into<String>,
        max_fee_micro_units: u64,
        reserved_fee_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateL2FeeSponsorSettlementResult<String> {
        let sponsor_id = sponsor_id.as_ref().to_string();
        let open_count = self
            .obligations
            .values()
            .filter(|obligation| obligation.status.is_live())
            .count();
        if open_count >= self.config.max_open_obligations {
            return Err("open obligation capacity reached".to_string());
        }
        if opened_at_height >= expires_at_height {
            return Err("obligation must expire after it opens".to_string());
        }
        if reserved_fee_units == 0 {
            return Err("reserved fee must be non-zero".to_string());
        }

        let configured_cap = self.config.cap_for_flow(flow_kind);
        if max_fee_micro_units == 0 || max_fee_micro_units > configured_cap {
            return Err("obligation exceeds configured low-fee cap".to_string());
        }

        let flow_commitment = flow_commitment.into();
        let user_nullifier_root = user_nullifier_root.into();
        let fee_quote_root = fee_quote_root.into();
        let proof_request_root = proof_request_root.into();
        let rebate_commitment_root = rebate_commitment_root.into();
        let monero_exit_commitment_root = monero_exit_commitment_root.into();
        ensure_non_empty(&flow_commitment, "flow commitment")?;
        ensure_non_empty(&user_nullifier_root, "user nullifier root")?;
        ensure_non_empty(&fee_quote_root, "fee quote root")?;
        ensure_non_empty(&proof_request_root, "proof request root")?;
        ensure_non_empty(&rebate_commitment_root, "rebate commitment root")?;
        ensure_non_empty(&monero_exit_commitment_root, "monero exit commitment root")?;

        let sponsor = self
            .sponsors
            .get_mut(&sponsor_id)
            .ok_or_else(|| format!("unknown sponsor: {sponsor_id}"))?;
        if !sponsor.status.can_open_obligation() {
            return Err(format!("sponsor cannot open obligations: {sponsor_id}"));
        }
        if !sponsor.solvent(self.config.min_solvency_coverage_bps) {
            sponsor.status = SponsorStatus::Insolvent;
            return Err(format!("sponsor is below solvency coverage: {sponsor_id}"));
        }
        if max_fee_micro_units > sponsor.fee_cap_micro_units {
            return Err("obligation exceeds sponsor fee cap".to_string());
        }
        if reserved_fee_units > sponsor.available_units() {
            sponsor.status = SponsorStatus::Exhausted;
            return Err("sponsor vault has insufficient available units".to_string());
        }

        let obligation_id = obligation_id(
            &sponsor_id,
            flow_kind,
            &flow_commitment,
            &user_nullifier_root,
            opened_at_height,
            self.counters.obligations_opened,
        );
        let obligation = FeeObligation {
            obligation_id: obligation_id.clone(),
            sponsor_id: sponsor_id.clone(),
            flow_kind,
            flow_commitment,
            user_nullifier_root,
            fee_quote_root,
            proof_request_root,
            rebate_commitment_root,
            monero_exit_commitment_root,
            max_fee_micro_units,
            reserved_fee_units,
            priority_weight: flow_kind.settlement_weight(),
            opened_at_height,
            expires_at_height,
            status: ObligationStatus::Reserved,
            settlement_receipt_id: None,
        };
        sponsor.reserved_units = sponsor.reserved_units.saturating_add(reserved_fee_units);
        self.obligations.insert(obligation_id.clone(), obligation);
        self.counters.obligations_opened = self.counters.obligations_opened.saturating_add(1);
        self.counters.total_reserved_units = self
            .counters
            .total_reserved_units
            .saturating_add(reserved_fee_units);
        Ok(obligation_id)
    }

    pub fn settle_obligation(
        &mut self,
        input: SettlementInput,
    ) -> PrivateL2FeeSponsorSettlementResult<String> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("settlement receipt capacity reached".to_string());
        }
        validate_settlement_input(&input)?;

        let obligation_snapshot = self
            .obligations
            .get(&input.obligation_id)
            .ok_or_else(|| format!("unknown obligation: {}", input.obligation_id))?
            .clone();
        if !obligation_snapshot.status.is_live() {
            return Err(format!(
                "obligation is not settleable: {}",
                obligation_snapshot.obligation_id
            ));
        }
        if input.settled_at_height < obligation_snapshot.opened_at_height {
            return Err("settlement height predates obligation".to_string());
        }
        if input.settled_fee_units > obligation_snapshot.reserved_fee_units {
            return Err("settled fee exceeds reserved fee".to_string());
        }
        let payout_total = input
            .settled_fee_units
            .saturating_add(input.prover_payout_units)
            .saturating_add(input.rebate_units)
            .saturating_add(input.monero_exit_subsidy_units);
        if payout_total > obligation_snapshot.reserved_fee_units {
            return Err("settlement payouts exceed reserved obligation".to_string());
        }
        if input.rebate_units > rebate_cap(input.settled_fee_units, self.config.max_rebate_bps) {
            return Err("rebate exceeds configured cap".to_string());
        }
        if input.monero_exit_subsidy_units > 0 && !obligation_snapshot.flow_kind.monero_exit() {
            return Err("monero exit subsidy requires a monero exit obligation".to_string());
        }

        let settlement_input_root = private_l2_fee_sponsor_hash(
            "SETTLEMENT-INPUT",
            &[HashPart::Json(&input.public_record())],
        );
        let protocol_fee_units = bps(input.settled_fee_units, self.config.protocol_take_bps);
        let obligation_root = obligation_snapshot.root();

        let sponsor = self
            .sponsors
            .get_mut(&obligation_snapshot.sponsor_id)
            .ok_or_else(|| format!("unknown sponsor: {}", obligation_snapshot.sponsor_id))?;
        sponsor.reserved_units = sponsor
            .reserved_units
            .saturating_sub(obligation_snapshot.reserved_fee_units);
        sponsor.settled_units = sponsor.settled_units.saturating_add(payout_total);
        sponsor.last_solvency_height = input.settled_at_height;

        let receipt_id = receipt_id(
            &obligation_snapshot.obligation_id,
            &obligation_snapshot.sponsor_id,
            &settlement_input_root,
            input.settled_at_height,
            self.counters.receipts_issued,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            obligation_id: obligation_snapshot.obligation_id.clone(),
            sponsor_id: obligation_snapshot.sponsor_id.clone(),
            flow_kind: obligation_snapshot.flow_kind,
            obligation_root,
            settlement_input_root,
            proof_market_payout_root: input.proof_market_payout_root.clone(),
            rebate_root: input.rebate_root.clone(),
            monero_exit_subsidy_root: input.monero_exit_subsidy_root.clone(),
            settlement_proof_root: input.settlement_proof_root.clone(),
            solvency_attestation_root: input.solvency_attestation_root.clone(),
            settled_fee_units: input.settled_fee_units,
            prover_payout_units: input.prover_payout_units,
            rebate_units: input.rebate_units,
            monero_exit_subsidy_units: input.monero_exit_subsidy_units,
            protocol_fee_units,
            sponsor_remaining_available_units: sponsor.available_units(),
            outcome: input.outcome,
            settled_at_height: input.settled_at_height,
            releasable_at_height: input
                .settled_at_height
                .saturating_add(self.config.receipt_delay_blocks),
        };

        if input.settled_fee_units == obligation_snapshot.reserved_fee_units {
            self.counters.capped_obligations = self.counters.capped_obligations.saturating_add(1);
        }
        self.rebate_roots.insert(input.rebate_root);
        self.proof_market_payout_roots
            .insert(input.proof_market_payout_root);
        self.monero_exit_subsidy_roots
            .insert(input.monero_exit_subsidy_root);
        self.receipts.insert(receipt_id.clone(), receipt);

        let obligation = self
            .obligations
            .get_mut(&obligation_snapshot.obligation_id)
            .expect("obligation exists after snapshot");
        obligation.status = ObligationStatus::Settled;
        obligation.settlement_receipt_id = Some(receipt_id.clone());

        self.counters.obligations_settled = self.counters.obligations_settled.saturating_add(1);
        self.counters.receipts_issued = self.counters.receipts_issued.saturating_add(1);
        self.counters.rebate_roots_recorded = self.counters.rebate_roots_recorded.saturating_add(1);
        if input.prover_payout_units > 0 {
            self.counters.proof_market_payouts =
                self.counters.proof_market_payouts.saturating_add(1);
        }
        if input.monero_exit_subsidy_units > 0 {
            self.counters.monero_exit_subsidies =
                self.counters.monero_exit_subsidies.saturating_add(1);
        }
        self.counters.total_settled_units = self
            .counters
            .total_settled_units
            .saturating_add(input.settled_fee_units);
        self.counters.total_rebate_units = self
            .counters
            .total_rebate_units
            .saturating_add(input.rebate_units);
        self.counters.total_proof_payout_units = self
            .counters
            .total_proof_payout_units
            .saturating_add(input.prover_payout_units);
        self.counters.total_exit_subsidy_units = self
            .counters
            .total_exit_subsidy_units
            .saturating_add(input.monero_exit_subsidy_units);
        self.record_solvency_note(&obligation_snapshot.sponsor_id, input.settled_at_height)?;
        Ok(receipt_id)
    }

    pub fn roots(&self) -> Roots {
        let sponsor_vaults = self
            .sponsors
            .values()
            .map(SponsorVault::public_record)
            .collect::<Vec<_>>();
        let obligations = self
            .obligations
            .values()
            .map(FeeObligation::public_record)
            .collect::<Vec<_>>();
        let open_obligations = self
            .obligations
            .values()
            .filter(|obligation| obligation.status.is_live())
            .map(FeeObligation::public_record)
            .collect::<Vec<_>>();
        let receipts = self
            .receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let solvency_notes = self
            .solvency_notes
            .values()
            .map(SolvencyNote::public_record)
            .collect::<Vec<_>>();
        let rebate_roots = self
            .rebate_roots
            .iter()
            .map(|root| json!(root))
            .collect::<Vec<_>>();
        let proof_market_payout_roots = self
            .proof_market_payout_roots
            .iter()
            .map(|root| json!(root))
            .collect::<Vec<_>>();
        let monero_exit_subsidy_roots = self
            .monero_exit_subsidy_roots
            .iter()
            .map(|root| json!(root))
            .collect::<Vec<_>>();
        let sponsor_solvency = self
            .sponsors
            .values()
            .map(|sponsor| {
                json!({
                    "sponsor_id": sponsor.sponsor_id,
                    "sponsor_vault_root": sponsor.root(),
                    "reserve_root": sponsor.reserve_root,
                    "available_units": sponsor.available_units(),
                    "reserved_units": sponsor.reserved_units,
                    "settled_units": sponsor.settled_units,
                    "solvency_coverage_bps": sponsor.solvency_coverage_bps,
                    "solvent": sponsor.solvent(self.config.min_solvency_coverage_bps),
                })
            })
            .collect::<Vec<_>>();

        Roots {
            sponsor_vault_root: merkle_root("PRIVATE-L2-FEE-SPONSOR-VAULT", &sponsor_vaults),
            obligation_root: merkle_root("PRIVATE-L2-FEE-OBLIGATION", &obligations),
            open_obligation_root: merkle_root("PRIVATE-L2-FEE-OPEN-OBLIGATION", &open_obligations),
            rebate_root: merkle_root("PRIVATE-L2-FEE-REBATE-ROOT", &rebate_roots),
            proof_market_payout_root: merkle_root(
                "PRIVATE-L2-FEE-PROOF-MARKET-PAYOUT-ROOT",
                &proof_market_payout_roots,
            ),
            monero_exit_subsidy_root: merkle_root(
                "PRIVATE-L2-FEE-MONERO-EXIT-SUBSIDY-ROOT",
                &monero_exit_subsidy_roots,
            ),
            settlement_receipt_root: merkle_root("PRIVATE-L2-FEE-SETTLEMENT-RECEIPT", &receipts),
            solvency_note_root: merkle_root("PRIVATE-L2-FEE-SOLVENCY-NOTE", &solvency_notes),
            sponsor_solvency_root: merkle_root(
                "PRIVATE-L2-FEE-SPONSOR-SOLVENCY",
                &sponsor_solvency,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_fee_sponsor_hash(
            "STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&self.roots().public_record()),
            ],
        )
    }

    fn record_solvency_note(
        &mut self,
        sponsor_id: &str,
        checked_at_height: u64,
    ) -> PrivateL2FeeSponsorSettlementResult<()> {
        if self.solvency_notes.len() >= self.config.max_solvency_notes {
            return Ok(());
        }
        let sponsor = self
            .sponsors
            .get(sponsor_id)
            .ok_or_else(|| format!("unknown sponsor: {sponsor_id}"))?;
        let outstanding = self
            .obligations
            .values()
            .filter(|obligation| obligation.sponsor_id == sponsor_id && obligation.status.is_live())
            .map(FeeObligation::public_record)
            .collect::<Vec<_>>();
        let outstanding_obligation_root =
            merkle_root("PRIVATE-L2-FEE-SPONSOR-OUTSTANDING", &outstanding);
        let sponsor_vault_root = sponsor.root();
        let solvent = sponsor.solvent(self.config.min_solvency_coverage_bps);
        let note_id = solvency_note_id(
            sponsor_id,
            &sponsor_vault_root,
            &outstanding_obligation_root,
            checked_at_height,
            self.counters.solvency_checks,
        );
        let note = SolvencyNote {
            note_id: note_id.clone(),
            sponsor_id: sponsor_id.to_string(),
            sponsor_vault_root,
            reserve_root: sponsor.reserve_root.clone(),
            outstanding_obligation_root,
            coverage_bps: sponsor.solvency_coverage_bps,
            checked_at_height,
            solvent,
        };
        self.solvency_notes.insert(note_id, note);
        self.counters.solvency_checks = self.counters.solvency_checks.saturating_add(1);
        Ok(())
    }
}

pub fn sponsor_id(
    sponsor_commitment: &str,
    vault_commitment: &str,
    reserve_root: &str,
    registered_at_height: u64,
    nonce: u64,
) -> String {
    private_l2_fee_sponsor_hash(
        "SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(vault_commitment),
            HashPart::Str(reserve_root),
            HashPart::Int(registered_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn obligation_id(
    sponsor_id: &str,
    flow_kind: SponsoredFlowKind,
    flow_commitment: &str,
    user_nullifier_root: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    private_l2_fee_sponsor_hash(
        "OBLIGATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(flow_kind.as_str()),
            HashPart::Str(flow_commitment),
            HashPart::Str(user_nullifier_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn receipt_id(
    obligation_id: &str,
    sponsor_id: &str,
    settlement_input_root: &str,
    settled_at_height: u64,
    nonce: u64,
) -> String {
    private_l2_fee_sponsor_hash(
        "RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(obligation_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(settlement_input_root),
            HashPart::Int(settled_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn solvency_note_id(
    sponsor_id: &str,
    sponsor_vault_root: &str,
    outstanding_obligation_root: &str,
    checked_at_height: u64,
    nonce: u64,
) -> String {
    private_l2_fee_sponsor_hash(
        "SOLVENCY-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(sponsor_vault_root),
            HashPart::Str(outstanding_obligation_root),
            HashPart::Int(checked_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn private_l2_fee_sponsor_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FEE-SPONSOR-SETTLEMENT-{domain}"),
        parts,
        32,
    )
}

fn validate_settlement_input(input: &SettlementInput) -> PrivateL2FeeSponsorSettlementResult<()> {
    ensure_non_empty(&input.obligation_id, "obligation id")?;
    ensure_non_empty(&input.proof_market_payout_root, "proof market payout root")?;
    ensure_non_empty(&input.rebate_root, "rebate root")?;
    ensure_non_empty(&input.monero_exit_subsidy_root, "monero exit subsidy root")?;
    ensure_non_empty(&input.settlement_proof_root, "settlement proof root")?;
    ensure_non_empty(
        &input.solvency_attestation_root,
        "solvency attestation root",
    )?;
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateL2FeeSponsorSettlementResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn bps(units: u64, bps: u64) -> u64 {
    units.saturating_mul(bps) / PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_MAX_BPS
}

fn rebate_cap(units: u64, rebate_bps: u64) -> u64 {
    bps(
        units,
        rebate_bps.min(PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_MAX_BPS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_register_open_and_settle_is_roots_only() {
        let mut state = State::devnet();
        let sponsor_id = state
            .register_sponsor(
                "sponsor-commitment",
                "vault-commitment",
                "reserve-root",
                "policy-root",
                "allowed-flow-root",
                "payout-address-root",
                1_000_000,
                100_000,
                250_000,
                1_500,
                11_500,
                PRIVATE_L2_FEE_SPONSOR_SETTLEMENT_DEVNET_HEIGHT,
            )
            .expect("register sponsor");
        let obligation_id = state
            .open_obligation(
                &sponsor_id,
                SponsoredFlowKind::PrivateSwap,
                "flow-commitment",
                "nullifier-root",
                "fee-quote-root",
                "proof-request-root",
                "rebate-commitment-root",
                "monero-exit-empty-root",
                1_300,
                1_000,
                520,
                620,
            )
            .expect("open obligation");
        let receipt_id = state
            .settle_obligation(SettlementInput {
                obligation_id,
                settled_fee_units: 700,
                prover_payout_units: 100,
                rebate_units: 50,
                monero_exit_subsidy_units: 0,
                proof_market_payout_root: "proof-market-payout-root".to_string(),
                rebate_root: "rebate-root".to_string(),
                monero_exit_subsidy_root: "monero-exit-subsidy-empty-root".to_string(),
                settlement_proof_root: "settlement-proof-root".to_string(),
                solvency_attestation_root: "solvency-attestation-root".to_string(),
                settled_at_height: 524,
                outcome: SettlementOutcome::Settled,
            })
            .expect("settle obligation");
        assert!(state.receipts.contains_key(&receipt_id));
        assert_eq!(state.counters.obligations_settled, 1);
        assert!(state.public_record().get("sponsors").is_none());
        assert!(!state.state_root().is_empty());
    }
}
