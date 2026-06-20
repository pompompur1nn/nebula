use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DefiSettlementHubResult<T> = Result<T, String>;

pub const DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION: &str = "nebula-defi-settlement-hub-v1";
pub const DEFI_SETTLEMENT_HUB_COMMITMENT_SCHEME: &str =
    "devnet-shake256-private-defi-settlement-v1";
pub const DEFI_SETTLEMENT_HUB_INTENT_ENCRYPTION_SCHEME: &str =
    "devnet-xwing-sealed-settlement-intent-v1";
pub const DEFI_SETTLEMENT_HUB_SOLVER_COMMITMENT_SCHEME: &str =
    "devnet-commit-reveal-solver-batch-v1";
pub const DEFI_SETTLEMENT_HUB_COLLATERAL_COMMITMENT_SCHEME: &str =
    "devnet-private-collateral-movement-root-v1";
pub const DEFI_SETTLEMENT_HUB_LP_RECEIPT_SCHEME: &str =
    "devnet-confidential-lp-vault-settlement-receipt-v1";
pub const DEFI_SETTLEMENT_HUB_SPONSOR_RECEIPT_SCHEME: &str =
    "devnet-low-fee-sponsor-debit-rebate-v1";
pub const DEFI_SETTLEMENT_HUB_PQ_APPROVAL_SCHEME: &str =
    "ml-dsa-87-defi-settlement-operator-approval-v1";
pub const DEFI_SETTLEMENT_HUB_FINALITY_ATTESTATION_SCHEME: &str =
    "devnet-threshold-finality-attestation-v1";
pub const DEFI_SETTLEMENT_HUB_DEVNET_HEIGHT: u64 = 288;
pub const DEFI_SETTLEMENT_HUB_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFI_SETTLEMENT_HUB_DEVNET_COLLATERAL_ASSET_ID: &str = "usdd-devnet";
pub const DEFI_SETTLEMENT_HUB_DEVNET_LOW_FEE_LANE: &str = "private-defi-settlement";
pub const DEFI_SETTLEMENT_HUB_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const DEFI_SETTLEMENT_HUB_MAX_BPS: u64 = 10_000;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_INTENT_TTL_BLOCKS: u64 = 64;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 6;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_MAX_BATCH_INTENTS: usize = 512;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_MAX_COLLATERAL_MOVEMENTS: usize = 768;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 250_000;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_MAX_REBATE_BPS: u64 = 8_500;
pub const DEFI_SETTLEMENT_HUB_DEFAULT_MIN_APPROVAL_WEIGHT_BPS: u64 = 6_700;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementVenue {
    Token,
    SmartContract,
    Swap,
    Lending,
    Options,
    Perps,
    LpVault,
    Sponsor,
}

impl SettlementVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::SmartContract => "smart_contract",
            Self::Swap => "swap",
            Self::Lending => "lending",
            Self::Options => "options",
            Self::Perps => "perps",
            Self::LpVault => "lp_vault",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementIntentKind {
    TokenTransfer,
    TokenMint,
    TokenBurn,
    ContractCall,
    ContractEscrowRelease,
    SwapExactIn,
    SwapExactOut,
    LendingSupply,
    LendingBorrow,
    LendingRepay,
    LendingWithdraw,
    OptionWrite,
    OptionExercise,
    OptionExpire,
    PerpOpen,
    PerpClose,
    PerpFunding,
    LpDeposit,
    LpWithdraw,
}

impl SettlementIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenTransfer => "token_transfer",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::ContractCall => "contract_call",
            Self::ContractEscrowRelease => "contract_escrow_release",
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::LendingWithdraw => "lending_withdraw",
            Self::OptionWrite => "option_write",
            Self::OptionExercise => "option_exercise",
            Self::OptionExpire => "option_expire",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::PerpFunding => "perp_funding",
            Self::LpDeposit => "lp_deposit",
            Self::LpWithdraw => "lp_withdraw",
        }
    }

    pub fn venue(self) -> SettlementVenue {
        match self {
            Self::TokenTransfer | Self::TokenMint | Self::TokenBurn => SettlementVenue::Token,
            Self::ContractCall | Self::ContractEscrowRelease => SettlementVenue::SmartContract,
            Self::SwapExactIn | Self::SwapExactOut => SettlementVenue::Swap,
            Self::LendingSupply
            | Self::LendingBorrow
            | Self::LendingRepay
            | Self::LendingWithdraw => SettlementVenue::Lending,
            Self::OptionWrite | Self::OptionExercise | Self::OptionExpire => {
                SettlementVenue::Options
            }
            Self::PerpOpen | Self::PerpClose | Self::PerpFunding => SettlementVenue::Perps,
            Self::LpDeposit | Self::LpWithdraw => SettlementVenue::LpVault,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Pending,
    Matched,
    Batched,
    Settled,
    Expired,
    Cancelled,
    Failed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Matched => "matched",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Pending | Self::Matched | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchKind {
    PrivateSwap,
    PrivateLending,
    PrivateOptions,
    PrivatePerps,
    MixedDefi,
    ContractToken,
}

impl SettlementBatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivateOptions => "private_options",
            Self::PrivatePerps => "private_perps",
            Self::MixedDefi => "mixed_defi",
            Self::ContractToken => "contract_token",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Collecting,
    Committed,
    Clearing,
    Cleared,
    Settling,
    Final,
    Failed,
    Challenged,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Committed => "committed",
            Self::Clearing => "clearing",
            Self::Cleared => "cleared",
            Self::Settling => "settling",
            Self::Final => "final",
            Self::Failed => "failed",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Collecting | Self::Committed | Self::Clearing | Self::Cleared | Self::Settling
        )
    }

    pub fn final_like(self) -> bool {
        matches!(self, Self::Final | Self::Failed | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Committed,
    Revealed,
    Selected,
    Settled,
    Slashed,
    Expired,
}

impl SolverCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn eligible(self) -> bool {
        matches!(self, Self::Revealed | Self::Selected | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingPriceStatus {
    Proposed,
    Accepted,
    Finalized,
    Disputed,
    Repriced,
}

impl ClearingPriceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Repriced => "repriced",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralMovementKind {
    Lock,
    Release,
    Transfer,
    Liquidation,
    MarginIncrease,
    MarginDecrease,
    VaultDeposit,
    VaultWithdraw,
}

impl CollateralMovementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Release => "release",
            Self::Transfer => "transfer",
            Self::Liquidation => "liquidation",
            Self::MarginIncrease => "margin_increase",
            Self::MarginDecrease => "margin_decrease",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementStatus {
    Committed,
    Applied,
    Reversed,
    Challenged,
    Expired,
}

impl MovementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Applied => "applied",
            Self::Reversed => "reversed",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorEntryStatus {
    Reserved,
    Debited,
    Rebated,
    Settled,
    ClawedBack,
    Expired,
}

impl SponsorEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Debited => "debited",
            Self::Rebated => "rebated",
            Self::Settled => "settled",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }

    pub fn pending(self) -> bool {
        matches!(self, Self::Reserved | Self::Debited | Self::Rebated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Superseded,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompensationStatus {
    Pending,
    Approved,
    Paid,
    Rejected,
    ClawedBack,
}

impl CompensationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::ClawedBack => "clawed_back",
        }
    }

    pub fn payable(self) -> bool {
        matches!(self, Self::Pending | Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    Pending,
    QuorumReached,
    Final,
    Reorged,
    Challenged,
    Expired,
}

impl FinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::QuorumReached => "quorum_reached",
            Self::Final => "final",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn finalizing(self) -> bool {
        matches!(self, Self::QuorumReached | Self::Final)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiSettlementHubConfig {
    pub protocol_version: String,
    pub commitment_scheme: String,
    pub intent_encryption_scheme: String,
    pub solver_commitment_scheme: String,
    pub collateral_commitment_scheme: String,
    pub lp_receipt_scheme: String,
    pub sponsor_receipt_scheme: String,
    pub pq_approval_scheme: String,
    pub finality_attestation_scheme: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub default_low_fee_lane: String,
    pub intent_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub finality_delay_blocks: u64,
    pub max_batch_intents: usize,
    pub max_collateral_movements: usize,
    pub min_solver_bond_units: u64,
    pub max_rebate_bps: u64,
    pub min_approval_weight_bps: u64,
    pub require_pq_approval: bool,
    pub require_finality_attestation: bool,
}

impl Default for DefiSettlementHubConfig {
    fn default() -> Self {
        Self {
            protocol_version: DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION.to_string(),
            commitment_scheme: DEFI_SETTLEMENT_HUB_COMMITMENT_SCHEME.to_string(),
            intent_encryption_scheme: DEFI_SETTLEMENT_HUB_INTENT_ENCRYPTION_SCHEME.to_string(),
            solver_commitment_scheme: DEFI_SETTLEMENT_HUB_SOLVER_COMMITMENT_SCHEME.to_string(),
            collateral_commitment_scheme: DEFI_SETTLEMENT_HUB_COLLATERAL_COMMITMENT_SCHEME
                .to_string(),
            lp_receipt_scheme: DEFI_SETTLEMENT_HUB_LP_RECEIPT_SCHEME.to_string(),
            sponsor_receipt_scheme: DEFI_SETTLEMENT_HUB_SPONSOR_RECEIPT_SCHEME.to_string(),
            pq_approval_scheme: DEFI_SETTLEMENT_HUB_PQ_APPROVAL_SCHEME.to_string(),
            finality_attestation_scheme: DEFI_SETTLEMENT_HUB_FINALITY_ATTESTATION_SCHEME
                .to_string(),
            fee_asset_id: DEFI_SETTLEMENT_HUB_DEVNET_FEE_ASSET_ID.to_string(),
            collateral_asset_id: DEFI_SETTLEMENT_HUB_DEVNET_COLLATERAL_ASSET_ID.to_string(),
            default_low_fee_lane: DEFI_SETTLEMENT_HUB_DEVNET_LOW_FEE_LANE.to_string(),
            intent_ttl_blocks: DEFI_SETTLEMENT_HUB_DEFAULT_INTENT_TTL_BLOCKS,
            batch_ttl_blocks: DEFI_SETTLEMENT_HUB_DEFAULT_BATCH_TTL_BLOCKS,
            challenge_window_blocks: DEFI_SETTLEMENT_HUB_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_delay_blocks: DEFI_SETTLEMENT_HUB_DEFAULT_FINALITY_DELAY_BLOCKS,
            max_batch_intents: DEFI_SETTLEMENT_HUB_DEFAULT_MAX_BATCH_INTENTS,
            max_collateral_movements: DEFI_SETTLEMENT_HUB_DEFAULT_MAX_COLLATERAL_MOVEMENTS,
            min_solver_bond_units: DEFI_SETTLEMENT_HUB_DEFAULT_MIN_SOLVER_BOND_UNITS,
            max_rebate_bps: DEFI_SETTLEMENT_HUB_DEFAULT_MAX_REBATE_BPS,
            min_approval_weight_bps: DEFI_SETTLEMENT_HUB_DEFAULT_MIN_APPROVAL_WEIGHT_BPS,
            require_pq_approval: true,
            require_finality_attestation: true,
        }
    }
}

impl DefiSettlementHubConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_settlement_hub_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "commitment_scheme": self.commitment_scheme,
            "intent_encryption_scheme": self.intent_encryption_scheme,
            "solver_commitment_scheme": self.solver_commitment_scheme,
            "collateral_commitment_scheme": self.collateral_commitment_scheme,
            "lp_receipt_scheme": self.lp_receipt_scheme,
            "sponsor_receipt_scheme": self.sponsor_receipt_scheme,
            "pq_approval_scheme": self.pq_approval_scheme,
            "finality_attestation_scheme": self.finality_attestation_scheme,
            "fee_asset_id": self.fee_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "default_low_fee_lane": self.default_low_fee_lane,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_delay_blocks": self.finality_delay_blocks,
            "max_batch_intents": self.max_batch_intents,
            "max_collateral_movements": self.max_collateral_movements,
            "min_solver_bond_units": self.min_solver_bond_units,
            "max_rebate_bps": self.max_rebate_bps,
            "min_approval_weight_bps": self.min_approval_weight_bps,
            "require_pq_approval": self.require_pq_approval,
            "require_finality_attestation": self.require_finality_attestation,
        })
    }

    pub fn config_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.protocol_version != DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION {
            return Err("defi settlement hub config protocol version mismatch".to_string());
        }
        if self.commitment_scheme.is_empty()
            || self.intent_encryption_scheme.is_empty()
            || self.solver_commitment_scheme.is_empty()
            || self.collateral_commitment_scheme.is_empty()
            || self.lp_receipt_scheme.is_empty()
            || self.sponsor_receipt_scheme.is_empty()
            || self.pq_approval_scheme.is_empty()
            || self.finality_attestation_scheme.is_empty()
        {
            return Err("defi settlement hub config schemes must be populated".to_string());
        }
        if self.fee_asset_id.is_empty()
            || self.collateral_asset_id.is_empty()
            || self.default_low_fee_lane.is_empty()
        {
            return Err("defi settlement hub config asset and lane ids are required".to_string());
        }
        if self.intent_ttl_blocks == 0
            || self.batch_ttl_blocks == 0
            || self.challenge_window_blocks == 0
            || self.finality_delay_blocks == 0
        {
            return Err("defi settlement hub config block windows must be non-zero".to_string());
        }
        if self.max_batch_intents == 0 || self.max_collateral_movements == 0 {
            return Err("defi settlement hub config capacities must be non-zero".to_string());
        }
        if self.max_rebate_bps > DEFI_SETTLEMENT_HUB_MAX_BPS {
            return Err("defi settlement hub config rebate cap exceeds bps scale".to_string());
        }
        if self.min_approval_weight_bps > DEFI_SETTLEMENT_HUB_MAX_BPS {
            return Err("defi settlement hub config approval weight exceeds bps scale".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub kind: SettlementIntentKind,
    pub venue: SettlementVenue,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub input_amount_commitment: String,
    pub min_output_amount_commitment: String,
    pub contract_id: String,
    pub call_selector: String,
    pub encrypted_payload: Value,
    pub privacy_nullifier: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub sponsor_lane: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: IntentStatus,
}

impl SettlementIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        kind: SettlementIntentKind,
        input_asset_id: &str,
        output_asset_id: &str,
        input_amount_commitment: &str,
        min_output_amount_commitment: &str,
        contract_id: &str,
        call_selector: &str,
        encrypted_payload: &Value,
        privacy_nullifier: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        sponsor_lane: &str,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let venue = kind.venue();
        let intent_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-INTENT-ID",
            &[
                HashPart::Str(owner_commitment),
                HashPart::Str(kind.as_str()),
                HashPart::Str(input_asset_id),
                HashPart::Str(output_asset_id),
                HashPart::Str(privacy_nullifier),
                HashPart::Int(nonce as i128),
            ],
        );
        let intent = Self {
            intent_id,
            owner_commitment: owner_commitment.to_string(),
            kind,
            venue,
            input_asset_id: input_asset_id.to_string(),
            output_asset_id: output_asset_id.to_string(),
            input_amount_commitment: input_amount_commitment.to_string(),
            min_output_amount_commitment: min_output_amount_commitment.to_string(),
            contract_id: contract_id.to_string(),
            call_selector: call_selector.to_string(),
            encrypted_payload: encrypted_payload.clone(),
            privacy_nullifier: privacy_nullifier.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            sponsor_lane: sponsor_lane.to_string(),
            created_at_height,
            expires_at_height,
            nonce,
            status: IntentStatus::Pending,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "intent_kind": self.kind.as_str(),
            "venue": self.venue.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "input_amount_commitment": self.input_amount_commitment,
            "min_output_amount_commitment": self.min_output_amount_commitment,
            "contract_id": self.contract_id,
            "call_selector": self.call_selector,
            "encrypted_payload": self.encrypted_payload,
            "privacy_nullifier": self.privacy_nullifier,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "sponsor_lane": self.sponsor_lane,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-INTENT", &self.public_record())
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.intent_id.is_empty()
            || self.owner_commitment.is_empty()
            || self.input_asset_id.is_empty()
            || self.output_asset_id.is_empty()
            || self.input_amount_commitment.is_empty()
            || self.min_output_amount_commitment.is_empty()
            || self.privacy_nullifier.is_empty()
            || self.fee_asset_id.is_empty()
            || self.sponsor_lane.is_empty()
        {
            return Err("settlement intent required fields are empty".to_string());
        }
        if self.venue != self.kind.venue() {
            return Err("settlement intent venue does not match kind".to_string());
        }
        if matches!(
            self.kind,
            SettlementIntentKind::ContractCall | SettlementIntentKind::ContractEscrowRelease
        ) && (self.contract_id.is_empty() || self.call_selector.is_empty())
        {
            return Err("contract settlement intent requires contract id and selector".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("settlement intent expiry must be after creation height".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub batch_kind: SettlementBatchKind,
    pub coordinator_id: String,
    pub intent_ids: Vec<String>,
    pub encrypted_intent_root: String,
    pub solver_commitment_root: String,
    pub clearing_price_root: String,
    pub collateral_movement_root: String,
    pub sponsor_entry_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub settlement_height: u64,
    pub nonce: u64,
    pub status: BatchStatus,
}

impl SettlementBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_kind: SettlementBatchKind,
        coordinator_id: &str,
        intent_ids: &[String],
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let encrypted_intent_root =
            defi_settlement_hub_string_set_root("DEFI-SETTLEMENT-HUB-BATCH-INTENTS", intent_ids);
        let batch_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-BATCH-ID",
            &[
                HashPart::Str(batch_kind.as_str()),
                HashPart::Str(coordinator_id),
                HashPart::Str(&encrypted_intent_root),
                HashPart::Int(nonce as i128),
            ],
        );
        let batch = Self {
            batch_id,
            batch_kind,
            coordinator_id: coordinator_id.to_string(),
            intent_ids: intent_ids.to_vec(),
            encrypted_intent_root,
            solver_commitment_root: empty_root("DEFI-SETTLEMENT-HUB-BATCH-SOLVERS"),
            clearing_price_root: empty_root("DEFI-SETTLEMENT-HUB-BATCH-PRICES"),
            collateral_movement_root: empty_root("DEFI-SETTLEMENT-HUB-BATCH-COLLATERAL"),
            sponsor_entry_root: empty_root("DEFI-SETTLEMENT-HUB-BATCH-SPONSORS"),
            opened_at_height,
            expires_at_height,
            settlement_height: 0,
            nonce,
            status: BatchStatus::Collecting,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "batch_kind": self.batch_kind.as_str(),
            "coordinator_id": self.coordinator_id,
            "intent_ids": self.intent_ids,
            "encrypted_intent_root": self.encrypted_intent_root,
            "solver_commitment_root": self.solver_commitment_root,
            "clearing_price_root": self.clearing_price_root,
            "collateral_movement_root": self.collateral_movement_root,
            "sponsor_entry_root": self.sponsor_entry_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "settlement_height": self.settlement_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.batch_id.is_empty()
            || self.coordinator_id.is_empty()
            || self.intent_ids.is_empty()
            || self.encrypted_intent_root.is_empty()
            || self.solver_commitment_root.is_empty()
            || self.clearing_price_root.is_empty()
            || self.collateral_movement_root.is_empty()
            || self.sponsor_entry_root.is_empty()
        {
            return Err("settlement batch required fields are empty".to_string());
        }
        if has_duplicates(&self.intent_ids) {
            return Err("settlement batch contains duplicate intent ids".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("settlement batch expiry must be after open height".to_string());
        }
        if self.status.final_like() && self.settlement_height == 0 {
            return Err("final settlement batch requires settlement height".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub batch_id: String,
    pub solver_id: String,
    pub commitment_root: String,
    pub reveal_root: String,
    pub claimed_surplus_commitment: String,
    pub bond_asset_id: String,
    pub bond_units: u64,
    pub pq_approval_id: String,
    pub submitted_at_height: u64,
    pub reveal_deadline_height: u64,
    pub nonce: u64,
    pub status: SolverCommitmentStatus,
}

impl SolverCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        solver_id: &str,
        commitment_root: &str,
        reveal_root: &str,
        claimed_surplus_commitment: &str,
        bond_asset_id: &str,
        bond_units: u64,
        pq_approval_id: &str,
        submitted_at_height: u64,
        reveal_deadline_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let commitment_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-SOLVER-COMMITMENT-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(solver_id),
                HashPart::Str(commitment_root),
                HashPart::Int(nonce as i128),
            ],
        );
        let commitment = Self {
            commitment_id,
            batch_id: batch_id.to_string(),
            solver_id: solver_id.to_string(),
            commitment_root: commitment_root.to_string(),
            reveal_root: reveal_root.to_string(),
            claimed_surplus_commitment: claimed_surplus_commitment.to_string(),
            bond_asset_id: bond_asset_id.to_string(),
            bond_units,
            pq_approval_id: pq_approval_id.to_string(),
            submitted_at_height,
            reveal_deadline_height,
            nonce,
            status: SolverCommitmentStatus::Committed,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "batch_id": self.batch_id,
            "solver_id": self.solver_id,
            "commitment_root": self.commitment_root,
            "reveal_root": self.reveal_root,
            "claimed_surplus_commitment": self.claimed_surplus_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bond_units": self.bond_units,
            "pq_approval_id": self.pq_approval_id,
            "submitted_at_height": self.submitted_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn commitment_record_root(&self) -> String {
        defi_settlement_hub_payload_root(
            "DEFI-SETTLEMENT-HUB-SOLVER-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.commitment_id.is_empty()
            || self.batch_id.is_empty()
            || self.solver_id.is_empty()
            || self.commitment_root.is_empty()
            || self.reveal_root.is_empty()
            || self.claimed_surplus_commitment.is_empty()
            || self.bond_asset_id.is_empty()
            || self.pq_approval_id.is_empty()
        {
            return Err("solver commitment required fields are empty".to_string());
        }
        if self.bond_units == 0 {
            return Err("solver commitment bond must be non-zero".to_string());
        }
        if self.reveal_deadline_height <= self.submitted_at_height {
            return Err("solver commitment reveal deadline must be after submission".to_string());
        }
        Ok(self.commitment_record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingPrice {
    pub clearing_price_id: String,
    pub batch_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub oracle_price_root: String,
    pub clearing_price_x12: u64,
    pub impact_bps: u64,
    pub notional_cleared_units: u64,
    pub solver_commitment_id: String,
    pub valid_at_height: u64,
    pub nonce: u64,
    pub status: ClearingPriceStatus,
}

impl ClearingPrice {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        base_asset_id: &str,
        quote_asset_id: &str,
        oracle_price_root: &str,
        clearing_price_x12: u64,
        impact_bps: u64,
        notional_cleared_units: u64,
        solver_commitment_id: &str,
        valid_at_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let clearing_price_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-CLEARING-PRICE-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(base_asset_id),
                HashPart::Str(quote_asset_id),
                HashPart::Int(clearing_price_x12 as i128),
                HashPart::Int(nonce as i128),
            ],
        );
        let price = Self {
            clearing_price_id,
            batch_id: batch_id.to_string(),
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            oracle_price_root: oracle_price_root.to_string(),
            clearing_price_x12,
            impact_bps,
            notional_cleared_units,
            solver_commitment_id: solver_commitment_id.to_string(),
            valid_at_height,
            nonce,
            status: ClearingPriceStatus::Proposed,
        };
        price.validate()?;
        Ok(price)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "clearing_price",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "clearing_price_id": self.clearing_price_id,
            "batch_id": self.batch_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "oracle_price_root": self.oracle_price_root,
            "clearing_price_x12": self.clearing_price_x12,
            "impact_bps": self.impact_bps,
            "notional_cleared_units": self.notional_cleared_units,
            "solver_commitment_id": self.solver_commitment_id,
            "valid_at_height": self.valid_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn price_root(&self) -> String {
        defi_settlement_hub_payload_root(
            "DEFI-SETTLEMENT-HUB-CLEARING-PRICE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.clearing_price_id.is_empty()
            || self.batch_id.is_empty()
            || self.base_asset_id.is_empty()
            || self.quote_asset_id.is_empty()
            || self.oracle_price_root.is_empty()
            || self.solver_commitment_id.is_empty()
        {
            return Err("clearing price required fields are empty".to_string());
        }
        if self.clearing_price_x12 == 0 || self.notional_cleared_units == 0 {
            return Err("clearing price and notional must be non-zero".to_string());
        }
        if self.impact_bps > DEFI_SETTLEMENT_HUB_MAX_BPS {
            return Err("clearing price impact exceeds bps scale".to_string());
        }
        Ok(self.price_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralMovementCommitment {
    pub movement_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub movement_kind: CollateralMovementKind,
    pub asset_id: String,
    pub amount_commitment: String,
    pub from_account_commitment: String,
    pub to_account_commitment: String,
    pub margin_account_id: String,
    pub movement_proof_root: String,
    pub applied_at_height: u64,
    pub nonce: u64,
    pub status: MovementStatus,
}

impl CollateralMovementCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        intent_id: &str,
        movement_kind: CollateralMovementKind,
        asset_id: &str,
        amount_commitment: &str,
        from_account_commitment: &str,
        to_account_commitment: &str,
        margin_account_id: &str,
        movement_proof_root: &str,
        applied_at_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let movement_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-COLLATERAL-MOVEMENT-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(intent_id),
                HashPart::Str(movement_kind.as_str()),
                HashPart::Str(asset_id),
                HashPart::Int(nonce as i128),
            ],
        );
        let movement = Self {
            movement_id,
            batch_id: batch_id.to_string(),
            intent_id: intent_id.to_string(),
            movement_kind,
            asset_id: asset_id.to_string(),
            amount_commitment: amount_commitment.to_string(),
            from_account_commitment: from_account_commitment.to_string(),
            to_account_commitment: to_account_commitment.to_string(),
            margin_account_id: margin_account_id.to_string(),
            movement_proof_root: movement_proof_root.to_string(),
            applied_at_height,
            nonce,
            status: MovementStatus::Committed,
        };
        movement.validate()?;
        Ok(movement)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "collateral_movement_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "movement_id": self.movement_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "movement_kind": self.movement_kind.as_str(),
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "from_account_commitment": self.from_account_commitment,
            "to_account_commitment": self.to_account_commitment,
            "margin_account_id": self.margin_account_id,
            "movement_proof_root": self.movement_proof_root,
            "applied_at_height": self.applied_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn movement_root(&self) -> String {
        defi_settlement_hub_payload_root(
            "DEFI-SETTLEMENT-HUB-COLLATERAL-MOVEMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.movement_id.is_empty()
            || self.batch_id.is_empty()
            || self.intent_id.is_empty()
            || self.asset_id.is_empty()
            || self.amount_commitment.is_empty()
            || self.from_account_commitment.is_empty()
            || self.to_account_commitment.is_empty()
            || self.margin_account_id.is_empty()
            || self.movement_proof_root.is_empty()
        {
            return Err("collateral movement required fields are empty".to_string());
        }
        Ok(self.movement_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LpVaultSettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub vault_id: String,
    pub lp_share_asset_id: String,
    pub asset_delta_commitment: String,
    pub share_delta_commitment: String,
    pub fee_accrual_commitment: String,
    pub vault_state_before_root: String,
    pub vault_state_after_root: String,
    pub solvency_proof_root: String,
    pub issued_at_height: u64,
    pub nonce: u64,
}

impl LpVaultSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        vault_id: &str,
        lp_share_asset_id: &str,
        asset_delta_commitment: &str,
        share_delta_commitment: &str,
        fee_accrual_commitment: &str,
        vault_state_before_root: &str,
        vault_state_after_root: &str,
        solvency_proof_root: &str,
        issued_at_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let receipt_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-LP-RECEIPT-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(vault_id),
                HashPart::Str(vault_state_after_root),
                HashPart::Int(nonce as i128),
            ],
        );
        let receipt = Self {
            receipt_id,
            batch_id: batch_id.to_string(),
            vault_id: vault_id.to_string(),
            lp_share_asset_id: lp_share_asset_id.to_string(),
            asset_delta_commitment: asset_delta_commitment.to_string(),
            share_delta_commitment: share_delta_commitment.to_string(),
            fee_accrual_commitment: fee_accrual_commitment.to_string(),
            vault_state_before_root: vault_state_before_root.to_string(),
            vault_state_after_root: vault_state_after_root.to_string(),
            solvency_proof_root: solvency_proof_root.to_string(),
            issued_at_height,
            nonce,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lp_vault_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "lp_share_asset_id": self.lp_share_asset_id,
            "asset_delta_commitment": self.asset_delta_commitment,
            "share_delta_commitment": self.share_delta_commitment,
            "fee_accrual_commitment": self.fee_accrual_commitment,
            "vault_state_before_root": self.vault_state_before_root,
            "vault_state_after_root": self.vault_state_after_root,
            "solvency_proof_root": self.solvency_proof_root,
            "issued_at_height": self.issued_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn receipt_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-LP-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.receipt_id.is_empty()
            || self.batch_id.is_empty()
            || self.vault_id.is_empty()
            || self.lp_share_asset_id.is_empty()
            || self.asset_delta_commitment.is_empty()
            || self.share_delta_commitment.is_empty()
            || self.fee_accrual_commitment.is_empty()
            || self.vault_state_before_root.is_empty()
            || self.vault_state_after_root.is_empty()
            || self.solvency_proof_root.is_empty()
        {
            return Err("lp vault settlement receipt required fields are empty".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorDebitRebate {
    pub entry_id: String,
    pub batch_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub debit_units: u64,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub recipient_commitment: String,
    pub reservation_nullifier: String,
    pub receipt_root: String,
    pub nonce: u64,
    pub status: SponsorEntryStatus,
}

impl SponsorDebitRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        sponsor_id: &str,
        lane_id: &str,
        fee_asset_id: &str,
        debit_units: u64,
        rebate_units: u64,
        rebate_bps: u64,
        recipient_commitment: &str,
        reservation_nullifier: &str,
        receipt_root: &str,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let entry_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-SPONSOR-ENTRY-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(sponsor_id),
                HashPart::Str(reservation_nullifier),
                HashPart::Int(nonce as i128),
            ],
        );
        let entry = Self {
            entry_id,
            batch_id: batch_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            debit_units,
            rebate_units,
            rebate_bps,
            recipient_commitment: recipient_commitment.to_string(),
            reservation_nullifier: reservation_nullifier.to_string(),
            receipt_root: receipt_root.to_string(),
            nonce,
            status: SponsorEntryStatus::Reserved,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_debit_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "batch_id": self.batch_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "debit_units": self.debit_units,
            "rebate_units": self.rebate_units,
            "rebate_bps": self.rebate_bps,
            "recipient_commitment": self.recipient_commitment,
            "reservation_nullifier": self.reservation_nullifier,
            "receipt_root": self.receipt_root,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn entry_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-SPONSOR-ENTRY", &self.public_record())
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.entry_id.is_empty()
            || self.batch_id.is_empty()
            || self.sponsor_id.is_empty()
            || self.lane_id.is_empty()
            || self.fee_asset_id.is_empty()
            || self.recipient_commitment.is_empty()
            || self.reservation_nullifier.is_empty()
            || self.receipt_root.is_empty()
        {
            return Err("sponsor debit rebate required fields are empty".to_string());
        }
        if self.debit_units == 0 {
            return Err("sponsor debit must be non-zero".to_string());
        }
        if self.rebate_units > self.debit_units {
            return Err("sponsor rebate cannot exceed debit".to_string());
        }
        if self.rebate_bps > DEFI_SETTLEMENT_HUB_MAX_BPS {
            return Err("sponsor rebate bps exceeds scale".to_string());
        }
        Ok(self.entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOperatorApproval {
    pub approval_id: String,
    pub operator_id: String,
    pub operator_role: String,
    pub approved_batch_kinds: Vec<SettlementBatchKind>,
    pub public_key_roots: Vec<String>,
    pub approval_weight_bps: u64,
    pub threshold_signature_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub nonce: u64,
    pub status: ApprovalStatus,
}

impl PqOperatorApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: &str,
        operator_role: &str,
        approved_batch_kinds: &[SettlementBatchKind],
        public_key_roots: &[String],
        approval_weight_bps: u64,
        threshold_signature_root: &str,
        valid_from_height: u64,
        valid_until_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let kind_names = approved_batch_kinds
            .iter()
            .map(|kind| kind.as_str().to_string())
            .collect::<Vec<_>>();
        let kind_root =
            defi_settlement_hub_string_set_root("DEFI-SETTLEMENT-HUB-PQ-KINDS", &kind_names);
        let key_root =
            defi_settlement_hub_string_set_root("DEFI-SETTLEMENT-HUB-PQ-KEYS", public_key_roots);
        let approval_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-PQ-APPROVAL-ID",
            &[
                HashPart::Str(operator_id),
                HashPart::Str(operator_role),
                HashPart::Str(&kind_root),
                HashPart::Str(&key_root),
                HashPart::Int(nonce as i128),
            ],
        );
        let approval = Self {
            approval_id,
            operator_id: operator_id.to_string(),
            operator_role: operator_role.to_string(),
            approved_batch_kinds: approved_batch_kinds.to_vec(),
            public_key_roots: public_key_roots.to_vec(),
            approval_weight_bps,
            threshold_signature_root: threshold_signature_root.to_string(),
            valid_from_height,
            valid_until_height,
            nonce,
            status: ApprovalStatus::Approved,
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn public_record(&self) -> Value {
        let approved_batch_kinds = self
            .approved_batch_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "pq_operator_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "operator_id": self.operator_id,
            "operator_role": self.operator_role,
            "approved_batch_kinds": approved_batch_kinds,
            "public_key_roots": self.public_key_roots,
            "approval_weight_bps": self.approval_weight_bps,
            "threshold_signature_root": self.threshold_signature_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn approval_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-PQ-APPROVAL", &self.public_record())
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.approval_id.is_empty()
            || self.operator_id.is_empty()
            || self.operator_role.is_empty()
            || self.approved_batch_kinds.is_empty()
            || self.public_key_roots.is_empty()
            || self.threshold_signature_root.is_empty()
        {
            return Err("pq operator approval required fields are empty".to_string());
        }
        if self.approval_weight_bps > DEFI_SETTLEMENT_HUB_MAX_BPS {
            return Err("pq operator approval weight exceeds bps scale".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("pq operator approval expiry must be after start".to_string());
        }
        if has_duplicates(&self.public_key_roots) {
            return Err("pq operator approval contains duplicate public key roots".to_string());
        }
        Ok(self.approval_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCompensation {
    pub compensation_id: String,
    pub batch_id: String,
    pub claimant_commitment: String,
    pub failure_code: String,
    pub evidence_root: String,
    pub compensation_asset_id: String,
    pub compensation_units: u64,
    pub solver_commitment_id: String,
    pub sponsor_entry_id: String,
    pub approved_at_height: u64,
    pub nonce: u64,
    pub status: CompensationStatus,
}

impl FailureCompensation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        claimant_commitment: &str,
        failure_code: &str,
        evidence_root: &str,
        compensation_asset_id: &str,
        compensation_units: u64,
        solver_commitment_id: &str,
        sponsor_entry_id: &str,
        approved_at_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let compensation_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-COMPENSATION-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(claimant_commitment),
                HashPart::Str(failure_code),
                HashPart::Int(nonce as i128),
            ],
        );
        let compensation = Self {
            compensation_id,
            batch_id: batch_id.to_string(),
            claimant_commitment: claimant_commitment.to_string(),
            failure_code: failure_code.to_string(),
            evidence_root: evidence_root.to_string(),
            compensation_asset_id: compensation_asset_id.to_string(),
            compensation_units,
            solver_commitment_id: solver_commitment_id.to_string(),
            sponsor_entry_id: sponsor_entry_id.to_string(),
            approved_at_height,
            nonce,
            status: CompensationStatus::Pending,
        };
        compensation.validate()?;
        Ok(compensation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "failure_compensation",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "compensation_id": self.compensation_id,
            "batch_id": self.batch_id,
            "claimant_commitment": self.claimant_commitment,
            "failure_code": self.failure_code,
            "evidence_root": self.evidence_root,
            "compensation_asset_id": self.compensation_asset_id,
            "compensation_units": self.compensation_units,
            "solver_commitment_id": self.solver_commitment_id,
            "sponsor_entry_id": self.sponsor_entry_id,
            "approved_at_height": self.approved_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn compensation_root(&self) -> String {
        defi_settlement_hub_payload_root(
            "DEFI-SETTLEMENT-HUB-FAILURE-COMPENSATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.compensation_id.is_empty()
            || self.batch_id.is_empty()
            || self.claimant_commitment.is_empty()
            || self.failure_code.is_empty()
            || self.evidence_root.is_empty()
            || self.compensation_asset_id.is_empty()
            || self.solver_commitment_id.is_empty()
            || self.sponsor_entry_id.is_empty()
        {
            return Err("failure compensation required fields are empty".to_string());
        }
        if self.compensation_units == 0 {
            return Err("failure compensation units must be non-zero".to_string());
        }
        Ok(self.compensation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub state_root: String,
    pub public_record_root: String,
    pub finalized_height: u64,
    pub attester_ids: Vec<String>,
    pub attestation_weight_bps: u64,
    pub aggregate_signature_root: String,
    pub monero_anchor_txid: String,
    pub nonce: u64,
    pub status: FinalityStatus,
}

impl FinalityAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        state_root: &str,
        public_record_root: &str,
        finalized_height: u64,
        attester_ids: &[String],
        attestation_weight_bps: u64,
        aggregate_signature_root: &str,
        monero_anchor_txid: &str,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let attester_root =
            defi_settlement_hub_string_set_root("DEFI-SETTLEMENT-HUB-ATTESTERS", attester_ids);
        let attestation_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-FINALITY-ATTESTATION-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(state_root),
                HashPart::Str(&attester_root),
                HashPart::Int(nonce as i128),
            ],
        );
        let attestation = Self {
            attestation_id,
            batch_id: batch_id.to_string(),
            state_root: state_root.to_string(),
            public_record_root: public_record_root.to_string(),
            finalized_height,
            attester_ids: attester_ids.to_vec(),
            attestation_weight_bps,
            aggregate_signature_root: aggregate_signature_root.to_string(),
            monero_anchor_txid: monero_anchor_txid.to_string(),
            nonce,
            status: FinalityStatus::Pending,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_finality_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "state_root": self.state_root,
            "public_record_root": self.public_record_root,
            "finalized_height": self.finalized_height,
            "attester_ids": self.attester_ids,
            "attestation_weight_bps": self.attestation_weight_bps,
            "aggregate_signature_root": self.aggregate_signature_root,
            "monero_anchor_txid": self.monero_anchor_txid,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        defi_settlement_hub_payload_root(
            "DEFI-SETTLEMENT-HUB-FINALITY-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.attestation_id.is_empty()
            || self.batch_id.is_empty()
            || self.state_root.is_empty()
            || self.public_record_root.is_empty()
            || self.attester_ids.is_empty()
            || self.aggregate_signature_root.is_empty()
            || self.monero_anchor_txid.is_empty()
        {
            return Err("finality attestation required fields are empty".to_string());
        }
        if self.attestation_weight_bps > DEFI_SETTLEMENT_HUB_MAX_BPS {
            return Err("finality attestation weight exceeds bps scale".to_string());
        }
        if has_duplicates(&self.attester_ids) {
            return Err("finality attestation contains duplicate attesters".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiSettlementPublicRecord {
    pub record_id: String,
    pub batch_id: String,
    pub state_root: String,
    pub roots_root: String,
    pub counters_root: String,
    pub public_payload: Value,
    pub published_at_height: u64,
    pub nonce: u64,
}

impl DefiSettlementPublicRecord {
    pub fn new(
        batch_id: &str,
        state_root: &str,
        roots_root: &str,
        counters_root: &str,
        public_payload: &Value,
        published_at_height: u64,
        nonce: u64,
    ) -> DefiSettlementHubResult<Self> {
        let record_id = defi_settlement_hub_id(
            "DEFI-SETTLEMENT-HUB-PUBLIC-RECORD-ID",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(state_root),
                HashPart::Str(roots_root),
                HashPart::Str(counters_root),
                HashPart::Int(nonce as i128),
            ],
        );
        let record = Self {
            record_id,
            batch_id: batch_id.to_string(),
            state_root: state_root.to_string(),
            roots_root: roots_root.to_string(),
            counters_root: counters_root.to_string(),
            public_payload: public_payload.clone(),
            published_at_height,
            nonce,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_settlement_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "batch_id": self.batch_id,
            "state_root": self.state_root,
            "roots_root": self.roots_root,
            "counters_root": self.counters_root,
            "public_payload": self.public_payload,
            "published_at_height": self.published_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn record_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        if self.record_id.is_empty()
            || self.batch_id.is_empty()
            || self.state_root.is_empty()
            || self.roots_root.is_empty()
            || self.counters_root.is_empty()
        {
            return Err("defi settlement public record required fields are empty".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiSettlementHubRoots {
    pub config_root: String,
    pub settlement_intent_root: String,
    pub settlement_batch_root: String,
    pub solver_commitment_root: String,
    pub clearing_price_root: String,
    pub collateral_movement_root: String,
    pub lp_vault_receipt_root: String,
    pub sponsor_debit_rebate_root: String,
    pub pq_operator_approval_root: String,
    pub failure_compensation_root: String,
    pub finality_attestation_root: String,
    pub public_record_root: String,
}

impl DefiSettlementHubRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_settlement_hub_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "settlement_intent_root": self.settlement_intent_root,
            "settlement_batch_root": self.settlement_batch_root,
            "solver_commitment_root": self.solver_commitment_root,
            "clearing_price_root": self.clearing_price_root,
            "collateral_movement_root": self.collateral_movement_root,
            "lp_vault_receipt_root": self.lp_vault_receipt_root,
            "sponsor_debit_rebate_root": self.sponsor_debit_rebate_root,
            "pq_operator_approval_root": self.pq_operator_approval_root,
            "failure_compensation_root": self.failure_compensation_root,
            "finality_attestation_root": self.finality_attestation_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiSettlementHubCounters {
    pub settlement_intent_count: u64,
    pub active_intent_count: u64,
    pub token_intent_count: u64,
    pub contract_intent_count: u64,
    pub swap_intent_count: u64,
    pub lending_intent_count: u64,
    pub options_intent_count: u64,
    pub perps_intent_count: u64,
    pub batch_count: u64,
    pub live_batch_count: u64,
    pub final_batch_count: u64,
    pub solver_commitment_count: u64,
    pub selected_solver_commitment_count: u64,
    pub clearing_price_count: u64,
    pub collateral_movement_count: u64,
    pub lp_vault_receipt_count: u64,
    pub sponsor_entry_count: u64,
    pub pending_sponsor_entry_count: u64,
    pub pq_operator_approval_count: u64,
    pub usable_pq_operator_approval_count: u64,
    pub failure_compensation_count: u64,
    pub payable_compensation_count: u64,
    pub finality_attestation_count: u64,
    pub finalizing_attestation_count: u64,
    pub public_record_count: u64,
    pub total_solver_bond_units: u64,
    pub total_notional_cleared_units: u64,
    pub total_sponsor_debit_units: u64,
    pub total_sponsor_rebate_units: u64,
    pub total_compensation_units: u64,
}

impl DefiSettlementHubCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_settlement_hub_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "settlement_intent_count": self.settlement_intent_count,
            "active_intent_count": self.active_intent_count,
            "token_intent_count": self.token_intent_count,
            "contract_intent_count": self.contract_intent_count,
            "swap_intent_count": self.swap_intent_count,
            "lending_intent_count": self.lending_intent_count,
            "options_intent_count": self.options_intent_count,
            "perps_intent_count": self.perps_intent_count,
            "batch_count": self.batch_count,
            "live_batch_count": self.live_batch_count,
            "final_batch_count": self.final_batch_count,
            "solver_commitment_count": self.solver_commitment_count,
            "selected_solver_commitment_count": self.selected_solver_commitment_count,
            "clearing_price_count": self.clearing_price_count,
            "collateral_movement_count": self.collateral_movement_count,
            "lp_vault_receipt_count": self.lp_vault_receipt_count,
            "sponsor_entry_count": self.sponsor_entry_count,
            "pending_sponsor_entry_count": self.pending_sponsor_entry_count,
            "pq_operator_approval_count": self.pq_operator_approval_count,
            "usable_pq_operator_approval_count": self.usable_pq_operator_approval_count,
            "failure_compensation_count": self.failure_compensation_count,
            "payable_compensation_count": self.payable_compensation_count,
            "finality_attestation_count": self.finality_attestation_count,
            "finalizing_attestation_count": self.finalizing_attestation_count,
            "public_record_count": self.public_record_count,
            "total_solver_bond_units": self.total_solver_bond_units,
            "total_notional_cleared_units": self.total_notional_cleared_units,
            "total_sponsor_debit_units": self.total_sponsor_debit_units,
            "total_sponsor_rebate_units": self.total_sponsor_rebate_units,
            "total_compensation_units": self.total_compensation_units,
        })
    }

    pub fn counters_root(&self) -> String {
        defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiSettlementHubState {
    pub height: u64,
    pub nonce: u64,
    pub config: DefiSettlementHubConfig,
    pub settlement_intents: BTreeMap<String, SettlementIntent>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub clearing_prices: BTreeMap<String, ClearingPrice>,
    pub collateral_movements: BTreeMap<String, CollateralMovementCommitment>,
    pub lp_vault_receipts: BTreeMap<String, LpVaultSettlementReceipt>,
    pub sponsor_entries: BTreeMap<String, SponsorDebitRebate>,
    pub pq_operator_approvals: BTreeMap<String, PqOperatorApproval>,
    pub failure_compensations: BTreeMap<String, FailureCompensation>,
    pub finality_attestations: BTreeMap<String, FinalityAttestation>,
    pub public_records: BTreeMap<String, DefiSettlementPublicRecord>,
}

impl Default for DefiSettlementHubState {
    fn default() -> Self {
        Self::new()
    }
}

impl DefiSettlementHubState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: DefiSettlementHubConfig::default(),
            settlement_intents: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            clearing_prices: BTreeMap::new(),
            collateral_movements: BTreeMap::new(),
            lp_vault_receipts: BTreeMap::new(),
            sponsor_entries: BTreeMap::new(),
            pq_operator_approvals: BTreeMap::new(),
            failure_compensations: BTreeMap::new(),
            finality_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(config: DefiSettlementHubConfig) -> DefiSettlementHubResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> DefiSettlementHubResult<Self> {
        let mut state = Self::with_config(DefiSettlementHubConfig::devnet())?;
        state.set_height(DEFI_SETTLEMENT_HUB_DEVNET_HEIGHT);

        let approval = PqOperatorApproval::new(
            "devnet-defi-solver-1",
            "settlement_solver",
            &[
                SettlementBatchKind::PrivateSwap,
                SettlementBatchKind::PrivateLending,
                SettlementBatchKind::PrivateOptions,
                SettlementBatchKind::PrivatePerps,
                SettlementBatchKind::MixedDefi,
            ],
            &[
                "ml-dsa-operator-key-root-1".to_string(),
                "slh-dsa-operator-key-root-2".to_string(),
            ],
            7_500,
            "devnet-pq-operator-threshold-signature-root",
            state.height.saturating_sub(12),
            state.height.saturating_add(7_200),
            state.next_nonce(),
        )?;
        let approval_id = approval.approval_id.clone();
        state.insert_pq_operator_approval(approval)?;

        let swap_intent = SettlementIntent::new(
            "devnet-alice-owner-commitment",
            SettlementIntentKind::SwapExactIn,
            "wxmr-devnet",
            "usdd-devnet",
            "commitment-42-wxmr",
            "commitment-min-7500-usdd",
            "",
            "",
            &json!({"route": "wxmr/usdd", "privacy": "sealed"}),
            "nullifier-devnet-swap-1",
            &state.config.fee_asset_id.clone(),
            1_250,
            &state.config.default_low_fee_lane.clone(),
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let swap_intent_id = swap_intent.intent_id.clone();
        state.insert_settlement_intent(swap_intent)?;

        let lend_intent = SettlementIntent::new(
            "devnet-bob-owner-commitment",
            SettlementIntentKind::LendingSupply,
            "usdd-devnet",
            "a-usdd-devnet",
            "commitment-5000-usdd",
            "commitment-min-ausdd",
            "",
            "",
            &json!({"market": "usdd", "action": "supply"}),
            "nullifier-devnet-lend-1",
            &state.config.fee_asset_id.clone(),
            900,
            &state.config.default_low_fee_lane.clone(),
            state.height,
            state.height.saturating_add(state.config.intent_ttl_blocks),
            state.next_nonce(),
        )?;
        let lend_intent_id = lend_intent.intent_id.clone();
        state.insert_settlement_intent(lend_intent)?;

        let intent_ids = vec![swap_intent_id.clone(), lend_intent_id.clone()];
        let mut batch = SettlementBatch::new(
            SettlementBatchKind::MixedDefi,
            "devnet-coordinator-1",
            &intent_ids,
            state.height,
            state.height.saturating_add(state.config.batch_ttl_blocks),
            state.next_nonce(),
        )?;
        let batch_id = batch.batch_id.clone();

        let solver = SolverCommitment::new(
            &batch_id,
            "devnet-defi-solver-1",
            "devnet-solver-commitment-root",
            "devnet-solver-reveal-root",
            "devnet-surplus-commitment",
            &state.config.fee_asset_id.clone(),
            state.config.min_solver_bond_units.saturating_add(50_000),
            &approval_id,
            state.height,
            state.height.saturating_add(4),
            state.next_nonce(),
        )?;
        let solver_id = solver.commitment_id.clone();
        state.insert_solver_commitment(solver)?;

        let price = ClearingPrice::new(
            &batch_id,
            "wxmr-devnet",
            "usdd-devnet",
            "devnet-wxmr-usdd-oracle-root",
            164 * DEFI_SETTLEMENT_HUB_PRICE_SCALE,
            18,
            7_500_000_000_000,
            &solver_id,
            state.height.saturating_add(1),
            state.next_nonce(),
        )?;
        let price_id = price.clearing_price_id.clone();
        state.insert_clearing_price(price)?;

        let movement = CollateralMovementCommitment::new(
            &batch_id,
            &lend_intent_id,
            CollateralMovementKind::Lock,
            &state.config.collateral_asset_id.clone(),
            "commitment-5000-usdd-collateral-lock",
            "devnet-bob-private-account",
            "devnet-lending-vault-account",
            "devnet-bob-margin-account",
            "devnet-collateral-movement-proof-root",
            state.height.saturating_add(2),
            state.next_nonce(),
        )?;
        state.insert_collateral_movement(movement)?;

        let lp_receipt = LpVaultSettlementReceipt::new(
            &batch_id,
            "devnet-private-lp-vault-1",
            "plp-wxmr-usdd-devnet",
            "commitment-vault-asset-delta",
            "commitment-vault-share-delta",
            "commitment-vault-fee-accrual",
            "devnet-vault-before-root",
            "devnet-vault-after-root",
            "devnet-vault-solvency-proof-root",
            state.height.saturating_add(2),
            state.next_nonce(),
        )?;
        state.insert_lp_vault_receipt(lp_receipt)?;

        let sponsor = SponsorDebitRebate::new(
            &batch_id,
            "devnet-low-fee-sponsor-1",
            &state.config.default_low_fee_lane.clone(),
            &state.config.fee_asset_id.clone(),
            1_500,
            1_050,
            7_000,
            "devnet-alice-rebate-commitment",
            "reservation-nullifier-devnet-1",
            "devnet-sponsor-receipt-root",
            state.next_nonce(),
        )?;
        let sponsor_id = sponsor.entry_id.clone();
        state.insert_sponsor_entry(sponsor)?;

        let compensation = FailureCompensation::new(
            &batch_id,
            "devnet-bob-owner-commitment",
            "partial_lending_fill_timeout",
            "devnet-failure-evidence-root",
            &state.config.fee_asset_id.clone(),
            350,
            &solver_id,
            &sponsor_id,
            state.height.saturating_add(4),
            state.next_nonce(),
        )?;
        state.insert_failure_compensation(compensation)?;

        batch.status = BatchStatus::Cleared;
        batch.solver_commitment_root = state.solver_commitment_root();
        batch.clearing_price_root = state.clearing_price_root();
        batch.collateral_movement_root = state.collateral_movement_root();
        batch.sponsor_entry_root = state.sponsor_debit_rebate_root();
        state.insert_settlement_batch(batch)?;

        let roots = state.roots();
        let counters = state.counters();
        let attestation = FinalityAttestation::new(
            &batch_id,
            &state.state_root(),
            &roots.public_record_root,
            state
                .height
                .saturating_add(state.config.finality_delay_blocks),
            &[
                "devnet-finality-attester-1".to_string(),
                "devnet-finality-attester-2".to_string(),
                "devnet-finality-attester-3".to_string(),
            ],
            7_500,
            "devnet-finality-aggregate-signature-root",
            "devnet-monero-anchor-txid",
            state.next_nonce(),
        )?;
        state.insert_finality_attestation(attestation)?;

        let public_record = DefiSettlementPublicRecord::new(
            &batch_id,
            &state.state_root(),
            &roots.roots_root(),
            &counters.counters_root(),
            &json!({
                "batch_id": batch_id,
                "price_id": price_id,
                "venue": "mixed_private_defi",
            }),
            state
                .height
                .saturating_add(state.config.finality_delay_blocks),
            state.next_nonce(),
        )?;
        state.insert_public_record(public_record)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_settlement_intent(
        &mut self,
        intent: SettlementIntent,
    ) -> DefiSettlementHubResult<String> {
        let root = intent.validate()?;
        self.settlement_intents
            .insert(intent.intent_id.clone(), intent);
        Ok(root)
    }

    pub fn insert_settlement_batch(
        &mut self,
        batch: SettlementBatch,
    ) -> DefiSettlementHubResult<String> {
        let root = batch.validate()?;
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch);
        Ok(root)
    }

    pub fn insert_solver_commitment(
        &mut self,
        commitment: SolverCommitment,
    ) -> DefiSettlementHubResult<String> {
        let root = commitment.validate()?;
        self.solver_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(root)
    }

    pub fn insert_clearing_price(
        &mut self,
        price: ClearingPrice,
    ) -> DefiSettlementHubResult<String> {
        let root = price.validate()?;
        self.clearing_prices
            .insert(price.clearing_price_id.clone(), price);
        Ok(root)
    }

    pub fn insert_collateral_movement(
        &mut self,
        movement: CollateralMovementCommitment,
    ) -> DefiSettlementHubResult<String> {
        let root = movement.validate()?;
        self.collateral_movements
            .insert(movement.movement_id.clone(), movement);
        Ok(root)
    }

    pub fn insert_lp_vault_receipt(
        &mut self,
        receipt: LpVaultSettlementReceipt,
    ) -> DefiSettlementHubResult<String> {
        let root = receipt.validate()?;
        self.lp_vault_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn insert_sponsor_entry(
        &mut self,
        entry: SponsorDebitRebate,
    ) -> DefiSettlementHubResult<String> {
        let root = entry.validate()?;
        self.sponsor_entries.insert(entry.entry_id.clone(), entry);
        Ok(root)
    }

    pub fn insert_pq_operator_approval(
        &mut self,
        approval: PqOperatorApproval,
    ) -> DefiSettlementHubResult<String> {
        let root = approval.validate()?;
        self.pq_operator_approvals
            .insert(approval.approval_id.clone(), approval);
        Ok(root)
    }

    pub fn insert_failure_compensation(
        &mut self,
        compensation: FailureCompensation,
    ) -> DefiSettlementHubResult<String> {
        let root = compensation.validate()?;
        self.failure_compensations
            .insert(compensation.compensation_id.clone(), compensation);
        Ok(root)
    }

    pub fn insert_finality_attestation(
        &mut self,
        attestation: FinalityAttestation,
    ) -> DefiSettlementHubResult<String> {
        let root = attestation.validate()?;
        self.finality_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(root)
    }

    pub fn insert_public_record(
        &mut self,
        record: DefiSettlementPublicRecord,
    ) -> DefiSettlementHubResult<String> {
        let root = record.validate()?;
        self.public_records.insert(record.record_id.clone(), record);
        Ok(root)
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn settlement_intent_root(&self) -> String {
        let items = self
            .settlement_intents
            .values()
            .cloned()
            .collect::<Vec<_>>();
        defi_settlement_hub_intent_root(&items)
    }

    pub fn settlement_batch_root(&self) -> String {
        let items = self
            .settlement_batches
            .values()
            .cloned()
            .collect::<Vec<_>>();
        defi_settlement_hub_batch_root(&items)
    }

    pub fn solver_commitment_root(&self) -> String {
        let items = self
            .solver_commitments
            .values()
            .cloned()
            .collect::<Vec<_>>();
        defi_settlement_hub_solver_commitment_root(&items)
    }

    pub fn clearing_price_root(&self) -> String {
        let items = self.clearing_prices.values().cloned().collect::<Vec<_>>();
        defi_settlement_hub_clearing_price_root(&items)
    }

    pub fn collateral_movement_root(&self) -> String {
        let items = self
            .collateral_movements
            .values()
            .cloned()
            .collect::<Vec<_>>();
        defi_settlement_hub_collateral_movement_root(&items)
    }

    pub fn lp_vault_receipt_root(&self) -> String {
        let items = self.lp_vault_receipts.values().cloned().collect::<Vec<_>>();
        defi_settlement_hub_lp_vault_receipt_root(&items)
    }

    pub fn sponsor_debit_rebate_root(&self) -> String {
        let items = self.sponsor_entries.values().cloned().collect::<Vec<_>>();
        defi_settlement_hub_sponsor_debit_rebate_root(&items)
    }

    pub fn pq_operator_approval_root(&self) -> String {
        let items = self
            .pq_operator_approvals
            .values()
            .cloned()
            .collect::<Vec<_>>();
        defi_settlement_hub_pq_operator_approval_root(&items)
    }

    pub fn failure_compensation_root(&self) -> String {
        let items = self
            .failure_compensations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        defi_settlement_hub_failure_compensation_root(&items)
    }

    pub fn finality_attestation_root(&self) -> String {
        let items = self
            .finality_attestations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        defi_settlement_hub_finality_attestation_root(&items)
    }

    pub fn public_record_root(&self) -> String {
        let items = self.public_records.values().cloned().collect::<Vec<_>>();
        defi_settlement_hub_public_record_root(&items)
    }

    pub fn roots(&self) -> DefiSettlementHubRoots {
        DefiSettlementHubRoots {
            config_root: self.config_root(),
            settlement_intent_root: self.settlement_intent_root(),
            settlement_batch_root: self.settlement_batch_root(),
            solver_commitment_root: self.solver_commitment_root(),
            clearing_price_root: self.clearing_price_root(),
            collateral_movement_root: self.collateral_movement_root(),
            lp_vault_receipt_root: self.lp_vault_receipt_root(),
            sponsor_debit_rebate_root: self.sponsor_debit_rebate_root(),
            pq_operator_approval_root: self.pq_operator_approval_root(),
            failure_compensation_root: self.failure_compensation_root(),
            finality_attestation_root: self.finality_attestation_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> DefiSettlementHubCounters {
        let settlement_intent_count = self.settlement_intents.len() as u64;
        let active_intent_count = self
            .settlement_intents
            .values()
            .filter(|intent| intent.status.active())
            .count() as u64;
        let token_intent_count = self
            .settlement_intents
            .values()
            .filter(|intent| intent.venue == SettlementVenue::Token)
            .count() as u64;
        let contract_intent_count = self
            .settlement_intents
            .values()
            .filter(|intent| intent.venue == SettlementVenue::SmartContract)
            .count() as u64;
        let swap_intent_count = self
            .settlement_intents
            .values()
            .filter(|intent| intent.venue == SettlementVenue::Swap)
            .count() as u64;
        let lending_intent_count = self
            .settlement_intents
            .values()
            .filter(|intent| intent.venue == SettlementVenue::Lending)
            .count() as u64;
        let options_intent_count = self
            .settlement_intents
            .values()
            .filter(|intent| intent.venue == SettlementVenue::Options)
            .count() as u64;
        let perps_intent_count = self
            .settlement_intents
            .values()
            .filter(|intent| intent.venue == SettlementVenue::Perps)
            .count() as u64;
        DefiSettlementHubCounters {
            settlement_intent_count,
            active_intent_count,
            token_intent_count,
            contract_intent_count,
            swap_intent_count,
            lending_intent_count,
            options_intent_count,
            perps_intent_count,
            batch_count: self.settlement_batches.len() as u64,
            live_batch_count: self
                .settlement_batches
                .values()
                .filter(|batch| batch.status.live())
                .count() as u64,
            final_batch_count: self
                .settlement_batches
                .values()
                .filter(|batch| batch.status.final_like())
                .count() as u64,
            solver_commitment_count: self.solver_commitments.len() as u64,
            selected_solver_commitment_count: self
                .solver_commitments
                .values()
                .filter(|commitment| commitment.status == SolverCommitmentStatus::Selected)
                .count() as u64,
            clearing_price_count: self.clearing_prices.len() as u64,
            collateral_movement_count: self.collateral_movements.len() as u64,
            lp_vault_receipt_count: self.lp_vault_receipts.len() as u64,
            sponsor_entry_count: self.sponsor_entries.len() as u64,
            pending_sponsor_entry_count: self
                .sponsor_entries
                .values()
                .filter(|entry| entry.status.pending())
                .count() as u64,
            pq_operator_approval_count: self.pq_operator_approvals.len() as u64,
            usable_pq_operator_approval_count: self
                .pq_operator_approvals
                .values()
                .filter(|approval| approval.status.usable())
                .count() as u64,
            failure_compensation_count: self.failure_compensations.len() as u64,
            payable_compensation_count: self
                .failure_compensations
                .values()
                .filter(|compensation| compensation.status.payable())
                .count() as u64,
            finality_attestation_count: self.finality_attestations.len() as u64,
            finalizing_attestation_count: self
                .finality_attestations
                .values()
                .filter(|attestation| attestation.status.finalizing())
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_solver_bond_units: self.total_solver_bond_units(),
            total_notional_cleared_units: self.total_notional_cleared_units(),
            total_sponsor_debit_units: self.total_sponsor_debit_units(),
            total_sponsor_rebate_units: self.total_sponsor_rebate_units(),
            total_compensation_units: self.total_compensation_units(),
        }
    }

    pub fn total_solver_bond_units(&self) -> u64 {
        self.solver_commitments
            .values()
            .fold(0_u64, |total, item| total.saturating_add(item.bond_units))
    }

    pub fn total_notional_cleared_units(&self) -> u64 {
        self.clearing_prices.values().fold(0_u64, |total, item| {
            total.saturating_add(item.notional_cleared_units)
        })
    }

    pub fn total_sponsor_debit_units(&self) -> u64 {
        self.sponsor_entries
            .values()
            .fold(0_u64, |total, item| total.saturating_add(item.debit_units))
    }

    pub fn total_sponsor_rebate_units(&self) -> u64 {
        self.sponsor_entries
            .values()
            .fold(0_u64, |total, item| total.saturating_add(item.rebate_units))
    }

    pub fn total_compensation_units(&self) -> u64 {
        self.failure_compensations
            .values()
            .fold(0_u64, |total, item| {
                total.saturating_add(item.compensation_units)
            })
    }

    pub fn state_root(&self) -> String {
        defi_settlement_hub_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> DefiSettlementHubResult<String> {
        self.config.validate()?;
        for (id, intent) in &self.settlement_intents {
            if id != &intent.intent_id {
                return Err("state intent key does not match intent id".to_string());
            }
            intent.validate()?;
        }
        for (id, approval) in &self.pq_operator_approvals {
            if id != &approval.approval_id {
                return Err("state pq approval key does not match approval id".to_string());
            }
            approval.validate()?;
            if approval.approval_weight_bps < self.config.min_approval_weight_bps
                && approval.status.usable()
            {
                return Err("state pq approval weight below configured threshold".to_string());
            }
        }
        for (id, batch) in &self.settlement_batches {
            if id != &batch.batch_id {
                return Err("state batch key does not match batch id".to_string());
            }
            batch.validate()?;
            if batch.intent_ids.len() > self.config.max_batch_intents {
                return Err("state batch exceeds max intent capacity".to_string());
            }
            for intent_id in &batch.intent_ids {
                if !self.settlement_intents.contains_key(intent_id) {
                    return Err("state batch references missing intent".to_string());
                }
            }
        }
        for (id, commitment) in &self.solver_commitments {
            if id != &commitment.commitment_id {
                return Err("state solver key does not match commitment id".to_string());
            }
            commitment.validate()?;
            if !self.settlement_batches.contains_key(&commitment.batch_id) {
                return Err("state solver commitment references missing batch".to_string());
            }
            if !self
                .pq_operator_approvals
                .contains_key(&commitment.pq_approval_id)
            {
                return Err("state solver commitment references missing pq approval".to_string());
            }
            if commitment.bond_units < self.config.min_solver_bond_units {
                return Err("state solver commitment bond below configured minimum".to_string());
            }
        }
        for (id, price) in &self.clearing_prices {
            if id != &price.clearing_price_id {
                return Err("state clearing price key does not match price id".to_string());
            }
            price.validate()?;
            if !self.settlement_batches.contains_key(&price.batch_id) {
                return Err("state clearing price references missing batch".to_string());
            }
            if !self
                .solver_commitments
                .contains_key(&price.solver_commitment_id)
            {
                return Err("state clearing price references missing solver commitment".to_string());
            }
        }
        for (id, movement) in &self.collateral_movements {
            if id != &movement.movement_id {
                return Err("state collateral movement key does not match movement id".to_string());
            }
            movement.validate()?;
            if !self.settlement_batches.contains_key(&movement.batch_id) {
                return Err("state collateral movement references missing batch".to_string());
            }
            if !self.settlement_intents.contains_key(&movement.intent_id) {
                return Err("state collateral movement references missing intent".to_string());
            }
        }
        if self.collateral_movements.len() > self.config.max_collateral_movements {
            return Err("state exceeds max collateral movement capacity".to_string());
        }
        for (id, receipt) in &self.lp_vault_receipts {
            if id != &receipt.receipt_id {
                return Err("state lp receipt key does not match receipt id".to_string());
            }
            receipt.validate()?;
            if !self.settlement_batches.contains_key(&receipt.batch_id) {
                return Err("state lp receipt references missing batch".to_string());
            }
        }
        for (id, entry) in &self.sponsor_entries {
            if id != &entry.entry_id {
                return Err("state sponsor entry key does not match entry id".to_string());
            }
            entry.validate()?;
            if !self.settlement_batches.contains_key(&entry.batch_id) {
                return Err("state sponsor entry references missing batch".to_string());
            }
            if entry.rebate_bps > self.config.max_rebate_bps {
                return Err("state sponsor entry rebate exceeds configured cap".to_string());
            }
        }
        for (id, compensation) in &self.failure_compensations {
            if id != &compensation.compensation_id {
                return Err("state compensation key does not match compensation id".to_string());
            }
            compensation.validate()?;
            if !self.settlement_batches.contains_key(&compensation.batch_id) {
                return Err("state compensation references missing batch".to_string());
            }
            if !self
                .solver_commitments
                .contains_key(&compensation.solver_commitment_id)
            {
                return Err("state compensation references missing solver commitment".to_string());
            }
            if !self
                .sponsor_entries
                .contains_key(&compensation.sponsor_entry_id)
            {
                return Err("state compensation references missing sponsor entry".to_string());
            }
        }
        for (id, attestation) in &self.finality_attestations {
            if id != &attestation.attestation_id {
                return Err("state finality key does not match attestation id".to_string());
            }
            attestation.validate()?;
            if !self.settlement_batches.contains_key(&attestation.batch_id) {
                return Err("state finality attestation references missing batch".to_string());
            }
            if self.config.require_finality_attestation
                && attestation.attestation_weight_bps < self.config.min_approval_weight_bps
            {
                return Err("state finality attestation weight below threshold".to_string());
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record key does not match record id".to_string());
            }
            record.validate()?;
            if !self.settlement_batches.contains_key(&record.batch_id) {
                return Err("state public record references missing batch".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "defi_settlement_hub_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_SETTLEMENT_HUB_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }
}

pub fn defi_settlement_hub_state_root_from_record(record: &Value) -> String {
    defi_settlement_hub_payload_root("DEFI-SETTLEMENT-HUB-STATE", record)
}

pub fn defi_settlement_hub_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn defi_settlement_hub_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn defi_settlement_hub_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    defi_settlement_hub_merkle_root(domain, leaves)
}

pub fn defi_settlement_hub_intent_root(items: &[SettlementIntent]) -> String {
    let leaves = items
        .iter()
        .map(SettlementIntent::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-INTENTS", leaves)
}

pub fn defi_settlement_hub_batch_root(items: &[SettlementBatch]) -> String {
    let leaves = items
        .iter()
        .map(SettlementBatch::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-BATCHES", leaves)
}

pub fn defi_settlement_hub_solver_commitment_root(items: &[SolverCommitment]) -> String {
    let leaves = items
        .iter()
        .map(SolverCommitment::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-SOLVER-COMMITMENTS", leaves)
}

pub fn defi_settlement_hub_clearing_price_root(items: &[ClearingPrice]) -> String {
    let leaves = items
        .iter()
        .map(ClearingPrice::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-CLEARING-PRICES", leaves)
}

pub fn defi_settlement_hub_collateral_movement_root(
    items: &[CollateralMovementCommitment],
) -> String {
    let leaves = items
        .iter()
        .map(CollateralMovementCommitment::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-COLLATERAL-MOVEMENTS", leaves)
}

pub fn defi_settlement_hub_lp_vault_receipt_root(items: &[LpVaultSettlementReceipt]) -> String {
    let leaves = items
        .iter()
        .map(LpVaultSettlementReceipt::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-LP-VAULT-RECEIPTS", leaves)
}

pub fn defi_settlement_hub_sponsor_debit_rebate_root(items: &[SponsorDebitRebate]) -> String {
    let leaves = items
        .iter()
        .map(SponsorDebitRebate::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-SPONSOR-DEBIT-REBATES", leaves)
}

pub fn defi_settlement_hub_pq_operator_approval_root(items: &[PqOperatorApproval]) -> String {
    let leaves = items
        .iter()
        .map(PqOperatorApproval::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-PQ-OPERATOR-APPROVALS", leaves)
}

pub fn defi_settlement_hub_failure_compensation_root(items: &[FailureCompensation]) -> String {
    let leaves = items
        .iter()
        .map(FailureCompensation::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-FAILURE-COMPENSATIONS", leaves)
}

pub fn defi_settlement_hub_finality_attestation_root(items: &[FinalityAttestation]) -> String {
    let leaves = items
        .iter()
        .map(FinalityAttestation::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-FINALITY-ATTESTATIONS", leaves)
}

pub fn defi_settlement_hub_public_record_root(items: &[DefiSettlementPublicRecord]) -> String {
    let leaves = items
        .iter()
        .map(DefiSettlementPublicRecord::public_record)
        .collect::<Vec<_>>();
    defi_settlement_hub_merkle_root("DEFI-SETTLEMENT-HUB-PUBLIC-RECORDS", leaves)
}

fn defi_settlement_hub_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 16)
}

fn defi_settlement_hub_merkle_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return true;
        }
    }
    false
}
