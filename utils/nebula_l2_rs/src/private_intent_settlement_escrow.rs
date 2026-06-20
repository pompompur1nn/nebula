use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateIntentSettlementEscrowResult<T> = Result<T, String>;

pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_PROTOCOL_VERSION: &str =
    "nebula-private-intent-settlement-escrow-v1";
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024-threshold-intent-escrow-v1";
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-solver-escrow-attestation-v1";
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_RECEIPT_SCHEME: &str =
    "zk-private-intent-settlement-receipt-v1";
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_FEE_SPONSOR_SCHEME: &str =
    "private-low-fee-escrow-sponsor-v1";
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_STABLE_ASSET_ID: &str = "dusd";
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEVNET_HEIGHT: u64 = 768;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_ESCROW_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_DECRYPTION_WINDOW_BLOCKS: u64 = 8;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 14;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 25_000;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 500;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_BPS: u64 = 10_000;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_ESCROWS: usize = 262_144;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_SOLVER_BONDS: usize = 65_536;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_DECRYPT_SHARES: usize = 524_288;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_SETTLEMENT_PATHS: usize = 262_144;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_SPONSORSHIPS: usize = 131_072;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_RECEIPTS: usize = 262_144;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_EVENTS: usize = 524_288;
pub const PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_PUBLIC_RECORDS: usize = 262_144;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateEscrowIntentKind {
    SwapExactIn,
    SwapExactOut,
    LendSupply,
    LendBorrow,
    LendRepay,
    LendWithdraw,
    PerpOpen,
    PerpClose,
    BridgeIn,
    BridgeOut,
    Composite,
    Custom(String),
}

impl PrivateEscrowIntentKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::SwapExactIn => "swap_exact_in".to_string(),
            Self::SwapExactOut => "swap_exact_out".to_string(),
            Self::LendSupply => "lend_supply".to_string(),
            Self::LendBorrow => "lend_borrow".to_string(),
            Self::LendRepay => "lend_repay".to_string(),
            Self::LendWithdraw => "lend_withdraw".to_string(),
            Self::PerpOpen => "perp_open".to_string(),
            Self::PerpClose => "perp_close".to_string(),
            Self::BridgeIn => "bridge_in".to_string(),
            Self::BridgeOut => "bridge_out".to_string(),
            Self::Composite => "composite".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn uses_bridge(&self) -> bool {
        matches!(self, Self::BridgeIn | Self::BridgeOut)
    }

    pub fn is_defi(&self) -> bool {
        matches!(
            self,
            Self::SwapExactIn
                | Self::SwapExactOut
                | Self::LendSupply
                | Self::LendBorrow
                | Self::LendRepay
                | Self::LendWithdraw
                | Self::PerpOpen
                | Self::PerpClose
                | Self::Composite
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowPrivacyClass {
    FullyShielded,
    AssetHinted,
    RouteHinted,
    SolverScoped,
    DisclosureScoped,
}

impl EscrowPrivacyClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::AssetHinted => "asset_hinted",
            Self::RouteHinted => "route_hinted",
            Self::SolverScoped => "solver_scoped",
            Self::DisclosureScoped => "disclosure_scoped",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Deposited,
    Locked,
    Matched,
    Decrypting,
    Settling,
    Settled,
    Refunded,
    Expired,
    Challenged,
}

impl EscrowStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deposited => "deposited",
            Self::Locked => "locked",
            Self::Matched => "matched",
            Self::Decrypting => "decrypting",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(&self) -> bool {
        matches!(
            self,
            Self::Deposited | Self::Locked | Self::Matched | Self::Decrypting | Self::Settling
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBondStatus {
    Pending,
    Active,
    Locked,
    Released,
    Slashed,
    Expired,
}

impl SolverBondStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptShareStatus {
    Submitted,
    Accepted,
    Superseded,
    Expired,
    Slashed,
}

impl DecryptShareStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementPathStatus {
    Proposed,
    Selected,
    Executing,
    Executed,
    Expired,
    Challenged,
}

impl SettlementPathStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Selected => "selected",
            Self::Executing => "executing",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(&self) -> bool {
        matches!(self, Self::Proposed | Self::Selected | Self::Executing)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Active,
    Reserved,
    Spent,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn available(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
    Resolved,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Resolved => "resolved",
        }
    }

    pub fn live(&self) -> bool {
        matches!(self, Self::Open | Self::Accepted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    Challenged,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentSettlementEscrowConfig {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub stable_asset_id: String,
    pub encryption_scheme: String,
    pub pq_auth_scheme: String,
    pub receipt_scheme: String,
    pub escrow_ttl_blocks: u64,
    pub decryption_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_solver_bond_units: u64,
    pub max_disclosure_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_escrows: usize,
    pub max_solver_bonds: usize,
    pub max_decrypt_shares: usize,
    pub max_settlement_paths: usize,
    pub max_sponsorships: usize,
    pub max_challenges: usize,
    pub max_receipts: usize,
    pub max_events: usize,
    pub max_public_records: usize,
}

impl Default for PrivateIntentSettlementEscrowConfig {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_FEE_ASSET_ID.to_string(),
            stable_asset_id: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_STABLE_ASSET_ID.to_string(),
            encryption_scheme: PRIVATE_INTENT_SETTLEMENT_ESCROW_ENCRYPTION_SCHEME.to_string(),
            pq_auth_scheme: PRIVATE_INTENT_SETTLEMENT_ESCROW_PQ_AUTH_SCHEME.to_string(),
            receipt_scheme: PRIVATE_INTENT_SETTLEMENT_ESCROW_RECEIPT_SCHEME.to_string(),
            escrow_ttl_blocks: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_ESCROW_TTL_BLOCKS,
            decryption_window_blocks:
                PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_DECRYPTION_WINDOW_BLOCKS,
            settlement_window_blocks:
                PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            challenge_window_blocks:
                PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            sponsor_ttl_blocks: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_solver_bond_units: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_MIN_SOLVER_BOND_UNITS,
            max_disclosure_bps: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_MAX_DISCLOSURE_BPS,
            low_fee_rebate_bps: PRIVATE_INTENT_SETTLEMENT_ESCROW_DEFAULT_LOW_FEE_REBATE_BPS,
            max_escrows: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_ESCROWS,
            max_solver_bonds: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_SOLVER_BONDS,
            max_decrypt_shares: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_DECRYPT_SHARES,
            max_settlement_paths: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_SETTLEMENT_PATHS,
            max_sponsorships: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_SPONSORSHIPS,
            max_challenges: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_CHALLENGES,
            max_receipts: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_RECEIPTS,
            max_events: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_EVENTS,
            max_public_records: PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_PUBLIC_RECORDS,
        }
    }
}

impl PrivateIntentSettlementEscrowConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<()> {
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.stable_asset_id", &self.stable_asset_id)?;
        ensure_non_empty("config.encryption_scheme", &self.encryption_scheme)?;
        ensure_non_empty("config.pq_auth_scheme", &self.pq_auth_scheme)?;
        ensure_non_empty("config.receipt_scheme", &self.receipt_scheme)?;
        ensure_positive("config.escrow_ttl_blocks", self.escrow_ttl_blocks)?;
        ensure_positive(
            "config.decryption_window_blocks",
            self.decryption_window_blocks,
        )?;
        ensure_positive(
            "config.settlement_window_blocks",
            self.settlement_window_blocks,
        )?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.sponsor_ttl_blocks", self.sponsor_ttl_blocks)?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("config.min_solver_bond_units", self.min_solver_bond_units)?;
        ensure_bps("config.max_disclosure_bps", self.max_disclosure_bps)?;
        ensure_bps("config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        ensure_capacity("config.max_escrows", self.max_escrows)?;
        ensure_capacity("config.max_solver_bonds", self.max_solver_bonds)?;
        ensure_capacity("config.max_decrypt_shares", self.max_decrypt_shares)?;
        ensure_capacity("config.max_settlement_paths", self.max_settlement_paths)?;
        ensure_capacity("config.max_sponsorships", self.max_sponsorships)?;
        ensure_capacity("config.max_challenges", self.max_challenges)?;
        ensure_capacity("config.max_receipts", self.max_receipts)?;
        ensure_capacity("config.max_events", self.max_events)?;
        ensure_capacity("config.max_public_records", self.max_public_records)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_settlement_escrow_config",
            "protocol_version": PRIVATE_INTENT_SETTLEMENT_ESCROW_PROTOCOL_VERSION,
            "schema_version": PRIVATE_INTENT_SETTLEMENT_ESCROW_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "encryption_scheme": self.encryption_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "receipt_scheme": self.receipt_scheme,
            "escrow_ttl_blocks": self.escrow_ttl_blocks,
            "decryption_window_blocks": self.decryption_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_solver_bond_units": self.min_solver_bond_units,
            "max_disclosure_bps": self.max_disclosure_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_escrows": self.max_escrows,
            "max_solver_bonds": self.max_solver_bonds,
            "max_decrypt_shares": self.max_decrypt_shares,
            "max_settlement_paths": self.max_settlement_paths,
            "max_sponsorships": self.max_sponsorships,
            "max_challenges": self.max_challenges,
            "max_receipts": self.max_receipts,
            "max_events": self.max_events,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn config_root(&self) -> String {
        private_intent_settlement_escrow_payload_root(
            "PRIVATE-INTENT-SETTLEMENT-ESCROW-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentEscrow {
    pub escrow_id: String,
    pub intent_commitment_root: String,
    pub owner_commitment_root: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub input_amount_commitment: String,
    pub min_output_commitment: String,
    pub nullifier_root: String,
    pub refund_commitment_root: String,
    pub intent_kind: PrivateEscrowIntentKind,
    pub privacy_class: EscrowPrivacyClass,
    pub privacy_set_size: u64,
    pub solver_id: Option<String>,
    pub matched_path_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub max_disclosure_bps: u64,
    pub low_fee_lane: bool,
    pub status: EscrowStatus,
}

impl PrivateIntentEscrow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_commitment_root: &str,
        owner_commitment_root: &str,
        input_asset_id: &str,
        output_asset_id: &str,
        input_amount_commitment: &str,
        min_output_commitment: &str,
        nullifier_root: &str,
        refund_commitment_root: &str,
        intent_kind: PrivateEscrowIntentKind,
        privacy_class: EscrowPrivacyClass,
        privacy_set_size: u64,
        created_at_height: u64,
        expires_at_height: u64,
        max_disclosure_bps: u64,
        low_fee_lane: bool,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_hex_root("escrow.intent_commitment_root", intent_commitment_root)?;
        ensure_hex_root("escrow.owner_commitment_root", owner_commitment_root)?;
        ensure_non_empty("escrow.input_asset_id", input_asset_id)?;
        ensure_non_empty("escrow.output_asset_id", output_asset_id)?;
        ensure_hex_root("escrow.input_amount_commitment", input_amount_commitment)?;
        ensure_hex_root("escrow.min_output_commitment", min_output_commitment)?;
        ensure_hex_root("escrow.nullifier_root", nullifier_root)?;
        ensure_hex_root("escrow.refund_commitment_root", refund_commitment_root)?;
        ensure_positive("escrow.privacy_set_size", privacy_set_size)?;
        ensure_height_order("escrow.created", created_at_height, expires_at_height)?;
        ensure_bps("escrow.max_disclosure_bps", max_disclosure_bps)?;
        let escrow_id = private_intent_settlement_escrow_id(
            intent_commitment_root,
            owner_commitment_root,
            input_asset_id,
            output_asset_id,
            created_at_height,
        );
        let item = Self {
            escrow_id,
            intent_commitment_root: intent_commitment_root.to_string(),
            owner_commitment_root: owner_commitment_root.to_string(),
            input_asset_id: input_asset_id.to_string(),
            output_asset_id: output_asset_id.to_string(),
            input_amount_commitment: input_amount_commitment.to_string(),
            min_output_commitment: min_output_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            refund_commitment_root: refund_commitment_root.to_string(),
            intent_kind,
            privacy_class,
            privacy_set_size,
            solver_id: None,
            matched_path_id: None,
            created_at_height,
            expires_at_height,
            max_disclosure_bps,
            low_fee_lane,
            status: EscrowStatus::Deposited,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "intent_commitment_root": self.intent_commitment_root,
            "owner_commitment_root": self.owner_commitment_root,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "input_amount_commitment": self.input_amount_commitment,
            "min_output_commitment": self.min_output_commitment,
            "nullifier_root": self.nullifier_root,
            "refund_commitment_root": self.refund_commitment_root,
            "intent_kind": self.intent_kind.as_str(),
            "privacy_class": self.privacy_class.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "solver_id": self.solver_id,
            "matched_path_id": self.matched_path_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "max_disclosure_bps": self.max_disclosure_bps,
            "low_fee_lane": self.low_fee_lane,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("escrow.escrow_id", &self.escrow_id)?;
        ensure_hex_root(
            "escrow.intent_commitment_root",
            &self.intent_commitment_root,
        )?;
        ensure_hex_root("escrow.owner_commitment_root", &self.owner_commitment_root)?;
        ensure_non_empty("escrow.input_asset_id", &self.input_asset_id)?;
        ensure_non_empty("escrow.output_asset_id", &self.output_asset_id)?;
        ensure_hex_root(
            "escrow.input_amount_commitment",
            &self.input_amount_commitment,
        )?;
        ensure_hex_root("escrow.min_output_commitment", &self.min_output_commitment)?;
        ensure_hex_root("escrow.nullifier_root", &self.nullifier_root)?;
        ensure_hex_root(
            "escrow.refund_commitment_root",
            &self.refund_commitment_root,
        )?;
        ensure_positive("escrow.privacy_set_size", self.privacy_set_size)?;
        ensure_height_order(
            "escrow.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        ensure_bps("escrow.max_disclosure_bps", self.max_disclosure_bps)?;
        let expected = private_intent_settlement_escrow_id(
            &self.intent_commitment_root,
            &self.owner_commitment_root,
            &self.input_asset_id,
            &self.output_asset_id,
            self.created_at_height,
        );
        if self.escrow_id != expected {
            return Err("escrow id mismatch".to_string());
        }
        Ok(self.escrow_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverEscrowBond {
    pub bond_id: String,
    pub solver_id: String,
    pub pq_public_key_commitment: String,
    pub bond_asset_id: String,
    pub bonded_units: u64,
    pub locked_units: u64,
    pub reputation_score_bps: u64,
    pub scope_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SolverBondStatus,
}

impl SolverEscrowBond {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        solver_id: &str,
        pq_public_key_commitment: &str,
        bond_asset_id: &str,
        bonded_units: u64,
        reputation_score_bps: u64,
        scopes: &[String],
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("bond.solver_id", solver_id)?;
        ensure_non_empty("bond.pq_public_key_commitment", pq_public_key_commitment)?;
        ensure_non_empty("bond.bond_asset_id", bond_asset_id)?;
        ensure_positive("bond.bonded_units", bonded_units)?;
        ensure_bps("bond.reputation_score_bps", reputation_score_bps)?;
        ensure_non_empty_list("bond.scopes", scopes)?;
        ensure_height_order("bond.created", created_at_height, expires_at_height)?;
        let scope_root = merkle_string_root("PRIVATE-INTENT-ESCROW-BOND-SCOPE", scopes);
        let bond_id = solver_escrow_bond_id(solver_id, &scope_root, created_at_height);
        let item = Self {
            bond_id,
            solver_id: solver_id.to_string(),
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            bond_asset_id: bond_asset_id.to_string(),
            bonded_units,
            locked_units: 0,
            reputation_score_bps,
            scope_root,
            created_at_height,
            expires_at_height,
            status: SolverBondStatus::Active,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn available_units(&self) -> u64 {
        self.bonded_units.saturating_sub(self.locked_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "solver_id": self.solver_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bonded_units": self.bonded_units,
            "locked_units": self.locked_units,
            "available_units": self.available_units(),
            "reputation_score_bps": self.reputation_score_bps,
            "scope_root": self.scope_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("bond.bond_id", &self.bond_id)?;
        ensure_non_empty("bond.solver_id", &self.solver_id)?;
        ensure_non_empty(
            "bond.pq_public_key_commitment",
            &self.pq_public_key_commitment,
        )?;
        ensure_non_empty("bond.bond_asset_id", &self.bond_asset_id)?;
        ensure_positive("bond.bonded_units", self.bonded_units)?;
        if self.locked_units > self.bonded_units {
            return Err("bond locked units exceed bonded units".to_string());
        }
        ensure_bps("bond.reputation_score_bps", self.reputation_score_bps)?;
        ensure_hex_root("bond.scope_root", &self.scope_root)?;
        ensure_height_order(
            "bond.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        let expected =
            solver_escrow_bond_id(&self.solver_id, &self.scope_root, self.created_at_height);
        if self.bond_id != expected {
            return Err("solver escrow bond id mismatch".to_string());
        }
        Ok(self.bond_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPath {
    pub path_id: String,
    pub escrow_id: String,
    pub solver_id: String,
    pub venue_commitment_root: String,
    pub route_commitment_root: String,
    pub clearing_price_commitment: String,
    pub expected_output_commitment: String,
    pub fee_commitment: String,
    pub sponsorship_id: Option<String>,
    pub proposed_at_height: u64,
    pub execute_by_height: u64,
    pub solver_surplus_bps: u64,
    pub status: SettlementPathStatus,
}

impl SettlementPath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        escrow_id: &str,
        solver_id: &str,
        venue_commitment_root: &str,
        route_commitment_root: &str,
        clearing_price_commitment: &str,
        expected_output_commitment: &str,
        fee_commitment: &str,
        sponsorship_id: Option<String>,
        proposed_at_height: u64,
        execute_by_height: u64,
        solver_surplus_bps: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("path.escrow_id", escrow_id)?;
        ensure_non_empty("path.solver_id", solver_id)?;
        ensure_hex_root("path.venue_commitment_root", venue_commitment_root)?;
        ensure_hex_root("path.route_commitment_root", route_commitment_root)?;
        ensure_hex_root("path.clearing_price_commitment", clearing_price_commitment)?;
        ensure_hex_root(
            "path.expected_output_commitment",
            expected_output_commitment,
        )?;
        ensure_hex_root("path.fee_commitment", fee_commitment)?;
        ensure_height_order("path.proposed", proposed_at_height, execute_by_height)?;
        ensure_bps("path.solver_surplus_bps", solver_surplus_bps)?;
        let path_id = settlement_path_id(
            escrow_id,
            solver_id,
            route_commitment_root,
            proposed_at_height,
        );
        let item = Self {
            path_id,
            escrow_id: escrow_id.to_string(),
            solver_id: solver_id.to_string(),
            venue_commitment_root: venue_commitment_root.to_string(),
            route_commitment_root: route_commitment_root.to_string(),
            clearing_price_commitment: clearing_price_commitment.to_string(),
            expected_output_commitment: expected_output_commitment.to_string(),
            fee_commitment: fee_commitment.to_string(),
            sponsorship_id,
            proposed_at_height,
            execute_by_height,
            solver_surplus_bps,
            status: SettlementPathStatus::Proposed,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "path_id": self.path_id,
            "escrow_id": self.escrow_id,
            "solver_id": self.solver_id,
            "venue_commitment_root": self.venue_commitment_root,
            "route_commitment_root": self.route_commitment_root,
            "clearing_price_commitment": self.clearing_price_commitment,
            "expected_output_commitment": self.expected_output_commitment,
            "fee_commitment": self.fee_commitment,
            "sponsorship_id": self.sponsorship_id,
            "proposed_at_height": self.proposed_at_height,
            "execute_by_height": self.execute_by_height,
            "solver_surplus_bps": self.solver_surplus_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("path.path_id", &self.path_id)?;
        ensure_non_empty("path.escrow_id", &self.escrow_id)?;
        ensure_non_empty("path.solver_id", &self.solver_id)?;
        ensure_hex_root("path.venue_commitment_root", &self.venue_commitment_root)?;
        ensure_hex_root("path.route_commitment_root", &self.route_commitment_root)?;
        ensure_hex_root(
            "path.clearing_price_commitment",
            &self.clearing_price_commitment,
        )?;
        ensure_hex_root(
            "path.expected_output_commitment",
            &self.expected_output_commitment,
        )?;
        ensure_hex_root("path.fee_commitment", &self.fee_commitment)?;
        ensure_height_order(
            "path.proposed",
            self.proposed_at_height,
            self.execute_by_height,
        )?;
        ensure_bps("path.solver_surplus_bps", self.solver_surplus_bps)?;
        let expected = settlement_path_id(
            &self.escrow_id,
            &self.solver_id,
            &self.route_commitment_root,
            self.proposed_at_height,
        );
        if self.path_id != expected {
            return Err("settlement path id mismatch".to_string());
        }
        Ok(self.path_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdDecryptShare {
    pub share_id: String,
    pub escrow_id: String,
    pub committee_member_id: String,
    pub share_commitment_root: String,
    pub pq_signature_commitment: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: DecryptShareStatus,
}

impl ThresholdDecryptShare {
    pub fn new(
        escrow_id: &str,
        committee_member_id: &str,
        share_commitment_root: &str,
        pq_signature_commitment: &str,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("share.escrow_id", escrow_id)?;
        ensure_non_empty("share.committee_member_id", committee_member_id)?;
        ensure_hex_root("share.share_commitment_root", share_commitment_root)?;
        ensure_hex_root("share.pq_signature_commitment", pq_signature_commitment)?;
        ensure_height_order("share.submitted", submitted_at_height, expires_at_height)?;
        let share_id = decrypt_share_id(escrow_id, committee_member_id, submitted_at_height);
        let item = Self {
            share_id,
            escrow_id: escrow_id.to_string(),
            committee_member_id: committee_member_id.to_string(),
            share_commitment_root: share_commitment_root.to_string(),
            pq_signature_commitment: pq_signature_commitment.to_string(),
            submitted_at_height,
            expires_at_height,
            status: DecryptShareStatus::Submitted,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "escrow_id": self.escrow_id,
            "committee_member_id": self.committee_member_id,
            "share_commitment_root": self.share_commitment_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("share.share_id", &self.share_id)?;
        ensure_non_empty("share.escrow_id", &self.escrow_id)?;
        ensure_non_empty("share.committee_member_id", &self.committee_member_id)?;
        ensure_hex_root("share.share_commitment_root", &self.share_commitment_root)?;
        ensure_hex_root(
            "share.pq_signature_commitment",
            &self.pq_signature_commitment,
        )?;
        ensure_height_order(
            "share.submitted",
            self.submitted_at_height,
            self.expires_at_height,
        )?;
        let expected = decrypt_share_id(
            &self.escrow_id,
            &self.committee_member_id,
            self.submitted_at_height,
        );
        if self.share_id != expected {
            return Err("decrypt share id mismatch".to_string());
        }
        Ok(self.share_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeEscrowSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub rebate_bps: u64,
    pub policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeEscrowSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        lane_id: &str,
        asset_id: &str,
        budget_units: u64,
        rebate_bps: u64,
        policy: &Value,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("sponsorship.sponsor_id", sponsor_id)?;
        ensure_non_empty("sponsorship.lane_id", lane_id)?;
        ensure_non_empty("sponsorship.asset_id", asset_id)?;
        ensure_positive("sponsorship.budget_units", budget_units)?;
        ensure_bps("sponsorship.rebate_bps", rebate_bps)?;
        ensure_height_order("sponsorship.created", created_at_height, expires_at_height)?;
        let policy_root =
            private_intent_settlement_escrow_payload_root("ESCROW-SPONSOR-POLICY", policy);
        let sponsorship_id =
            low_fee_escrow_sponsorship_id(sponsor_id, lane_id, &policy_root, created_at_height);
        let item = Self {
            sponsorship_id,
            sponsor_id: sponsor_id.to_string(),
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            rebate_bps,
            policy_root,
            created_at_height,
            expires_at_height,
            status: SponsorshipStatus::Active,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "rebate_bps": self.rebate_bps,
            "policy_root": self.policy_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("sponsorship.sponsorship_id", &self.sponsorship_id)?;
        ensure_non_empty("sponsorship.sponsor_id", &self.sponsor_id)?;
        ensure_non_empty("sponsorship.lane_id", &self.lane_id)?;
        ensure_non_empty("sponsorship.asset_id", &self.asset_id)?;
        ensure_positive("sponsorship.budget_units", self.budget_units)?;
        if self
            .reserved_units
            .saturating_add(self.spent_units)
            .gt(&self.budget_units)
        {
            return Err("sponsorship reserved plus spent exceeds budget".to_string());
        }
        ensure_bps("sponsorship.rebate_bps", self.rebate_bps)?;
        ensure_hex_root("sponsorship.policy_root", &self.policy_root)?;
        ensure_height_order(
            "sponsorship.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        let expected = low_fee_escrow_sponsorship_id(
            &self.sponsor_id,
            &self.lane_id,
            &self.policy_root,
            self.created_at_height,
        );
        if self.sponsorship_id != expected {
            return Err("low-fee escrow sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowChallengeWindow {
    pub challenge_id: String,
    pub escrow_id: String,
    pub challenger_commitment_root: String,
    pub reason_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub status: ChallengeStatus,
}

impl EscrowChallengeWindow {
    pub fn new(
        escrow_id: &str,
        challenger_commitment_root: &str,
        reason: &Value,
        bond_units: u64,
        opened_at_height: u64,
        deadline_height: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("challenge.escrow_id", escrow_id)?;
        ensure_hex_root(
            "challenge.challenger_commitment_root",
            challenger_commitment_root,
        )?;
        ensure_positive("challenge.bond_units", bond_units)?;
        ensure_height_order("challenge.opened", opened_at_height, deadline_height)?;
        let reason_root =
            private_intent_settlement_escrow_payload_root("ESCROW-CHALLENGE-REASON", reason);
        let challenge_id =
            escrow_challenge_id(escrow_id, challenger_commitment_root, opened_at_height);
        let item = Self {
            challenge_id,
            escrow_id: escrow_id.to_string(),
            challenger_commitment_root: challenger_commitment_root.to_string(),
            reason_root,
            bond_units,
            opened_at_height,
            deadline_height,
            status: ChallengeStatus::Open,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "escrow_id": self.escrow_id,
            "challenger_commitment_root": self.challenger_commitment_root,
            "reason_root": self.reason_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("challenge.challenge_id", &self.challenge_id)?;
        ensure_non_empty("challenge.escrow_id", &self.escrow_id)?;
        ensure_hex_root(
            "challenge.challenger_commitment_root",
            &self.challenger_commitment_root,
        )?;
        ensure_hex_root("challenge.reason_root", &self.reason_root)?;
        ensure_positive("challenge.bond_units", self.bond_units)?;
        ensure_height_order(
            "challenge.opened",
            self.opened_at_height,
            self.deadline_height,
        )?;
        let expected = escrow_challenge_id(
            &self.escrow_id,
            &self.challenger_commitment_root,
            self.opened_at_height,
        );
        if self.challenge_id != expected {
            return Err("escrow challenge id mismatch".to_string());
        }
        Ok(self.challenge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementReceipt {
    pub receipt_id: String,
    pub escrow_id: String,
    pub path_id: String,
    pub settlement_nullifier_root: String,
    pub output_note_root: String,
    pub fee_receipt_root: String,
    pub solver_id: String,
    pub finalized_at_height: u64,
    pub status: ReceiptStatus,
}

impl PrivateSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        escrow_id: &str,
        path_id: &str,
        settlement_nullifier_root: &str,
        output_note_root: &str,
        fee_receipt_root: &str,
        solver_id: &str,
        finalized_at_height: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("receipt.escrow_id", escrow_id)?;
        ensure_non_empty("receipt.path_id", path_id)?;
        ensure_hex_root(
            "receipt.settlement_nullifier_root",
            settlement_nullifier_root,
        )?;
        ensure_hex_root("receipt.output_note_root", output_note_root)?;
        ensure_hex_root("receipt.fee_receipt_root", fee_receipt_root)?;
        ensure_non_empty("receipt.solver_id", solver_id)?;
        let receipt_id =
            private_settlement_receipt_id(escrow_id, path_id, solver_id, finalized_at_height);
        let item = Self {
            receipt_id,
            escrow_id: escrow_id.to_string(),
            path_id: path_id.to_string(),
            settlement_nullifier_root: settlement_nullifier_root.to_string(),
            output_note_root: output_note_root.to_string(),
            fee_receipt_root: fee_receipt_root.to_string(),
            solver_id: solver_id.to_string(),
            finalized_at_height,
            status: ReceiptStatus::Finalized,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "escrow_id": self.escrow_id,
            "path_id": self.path_id,
            "settlement_nullifier_root": self.settlement_nullifier_root,
            "output_note_root": self.output_note_root,
            "fee_receipt_root": self.fee_receipt_root,
            "solver_id": self.solver_id,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("receipt.receipt_id", &self.receipt_id)?;
        ensure_non_empty("receipt.escrow_id", &self.escrow_id)?;
        ensure_non_empty("receipt.path_id", &self.path_id)?;
        ensure_hex_root(
            "receipt.settlement_nullifier_root",
            &self.settlement_nullifier_root,
        )?;
        ensure_hex_root("receipt.output_note_root", &self.output_note_root)?;
        ensure_hex_root("receipt.fee_receipt_root", &self.fee_receipt_root)?;
        ensure_non_empty("receipt.solver_id", &self.solver_id)?;
        let expected = private_settlement_receipt_id(
            &self.escrow_id,
            &self.path_id,
            &self.solver_id,
            self.finalized_at_height,
        );
        if self.receipt_id != expected {
            return Err("private settlement receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowLifecycleEvent {
    pub event_id: String,
    pub escrow_id: Option<String>,
    pub event_kind: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl EscrowLifecycleEvent {
    pub fn new(
        escrow_id: Option<String>,
        event_kind: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("event.event_kind", event_kind)?;
        let payload_root =
            private_intent_settlement_escrow_payload_root("ESCROW-LIFECYCLE-EVENT", payload);
        let event_id = escrow_lifecycle_event_id(
            escrow_id.as_deref(),
            event_kind,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let item = Self {
            event_id,
            escrow_id,
            event_kind: event_kind.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "escrow_id": self.escrow_id,
            "event_kind": self.event_kind,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("event.event_id", &self.event_id)?;
        ensure_non_empty("event.event_kind", &self.event_kind)?;
        ensure_hex_root("event.payload_root", &self.payload_root)?;
        let expected = escrow_lifecycle_event_id(
            self.escrow_id.as_deref(),
            &self.event_kind,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.event_id != expected {
            return Err("escrow lifecycle event id mismatch".to_string());
        }
        Ok(self.event_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl EscrowPublicRecord {
    pub fn new(
        record_kind: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PrivateIntentSettlementEscrowResult<Self> {
        ensure_non_empty("record.record_kind", record_kind)?;
        let payload_root =
            private_intent_settlement_escrow_payload_root("ESCROW-PUBLIC-RECORD-PAYLOAD", payload);
        let record_id =
            escrow_public_record_id(record_kind, &payload_root, emitted_at_height, sequence);
        let item = Self {
            record_id,
            record_kind: record_kind.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_non_empty("record.record_id", &self.record_id)?;
        ensure_non_empty("record.record_kind", &self.record_kind)?;
        ensure_hex_root("record.payload_root", &self.payload_root)?;
        let expected = escrow_public_record_id(
            &self.record_kind,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("escrow public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentSettlementEscrowRoots {
    pub config_root: String,
    pub escrow_root: String,
    pub solver_bond_root: String,
    pub decrypt_share_root: String,
    pub settlement_path_root: String,
    pub sponsorship_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl PrivateIntentSettlementEscrowRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_settlement_escrow_roots",
            "protocol_version": PRIVATE_INTENT_SETTLEMENT_ESCROW_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "escrow_root": self.escrow_root,
            "solver_bond_root": self.solver_bond_root,
            "decrypt_share_root": self.decrypt_share_root,
            "settlement_path_root": self.settlement_path_root,
            "sponsorship_root": self.sponsorship_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        private_intent_settlement_escrow_payload_root(
            "PRIVATE-INTENT-SETTLEMENT-ESCROW-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentSettlementEscrowCounters {
    pub escrow_count: u64,
    pub live_escrow_count: u64,
    pub settled_escrow_count: u64,
    pub challenged_escrow_count: u64,
    pub low_fee_escrow_count: u64,
    pub solver_bond_count: u64,
    pub active_solver_bond_count: u64,
    pub decrypt_share_count: u64,
    pub accepted_decrypt_share_count: u64,
    pub settlement_path_count: u64,
    pub live_settlement_path_count: u64,
    pub sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub challenge_count: u64,
    pub live_challenge_count: u64,
    pub receipt_count: u64,
    pub event_count: u64,
    pub public_record_count: u64,
    pub total_available_sponsor_units: u64,
    pub total_available_solver_bond_units: u64,
}

impl PrivateIntentSettlementEscrowCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_intent_settlement_escrow_counters",
            "protocol_version": PRIVATE_INTENT_SETTLEMENT_ESCROW_PROTOCOL_VERSION,
            "escrow_count": self.escrow_count,
            "live_escrow_count": self.live_escrow_count,
            "settled_escrow_count": self.settled_escrow_count,
            "challenged_escrow_count": self.challenged_escrow_count,
            "low_fee_escrow_count": self.low_fee_escrow_count,
            "solver_bond_count": self.solver_bond_count,
            "active_solver_bond_count": self.active_solver_bond_count,
            "decrypt_share_count": self.decrypt_share_count,
            "accepted_decrypt_share_count": self.accepted_decrypt_share_count,
            "settlement_path_count": self.settlement_path_count,
            "live_settlement_path_count": self.live_settlement_path_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "challenge_count": self.challenge_count,
            "live_challenge_count": self.live_challenge_count,
            "receipt_count": self.receipt_count,
            "event_count": self.event_count,
            "public_record_count": self.public_record_count,
            "total_available_sponsor_units": self.total_available_sponsor_units,
            "total_available_solver_bond_units": self.total_available_solver_bond_units,
        })
    }

    pub fn counters_root(&self) -> String {
        private_intent_settlement_escrow_payload_root(
            "PRIVATE-INTENT-SETTLEMENT-ESCROW-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentSettlementEscrowState {
    pub height: u64,
    pub config: PrivateIntentSettlementEscrowConfig,
    pub escrows: BTreeMap<String, PrivateIntentEscrow>,
    pub solver_bonds: BTreeMap<String, SolverEscrowBond>,
    pub decrypt_shares: BTreeMap<String, ThresholdDecryptShare>,
    pub settlement_paths: BTreeMap<String, SettlementPath>,
    pub sponsorships: BTreeMap<String, LowFeeEscrowSponsorship>,
    pub challenges: BTreeMap<String, EscrowChallengeWindow>,
    pub receipts: BTreeMap<String, PrivateSettlementReceipt>,
    pub events: BTreeMap<String, EscrowLifecycleEvent>,
    pub public_records: BTreeMap<String, EscrowPublicRecord>,
}

impl PrivateIntentSettlementEscrowState {
    pub fn new(config: PrivateIntentSettlementEscrowConfig, height: u64) -> Self {
        Self {
            height,
            config,
            escrows: BTreeMap::new(),
            solver_bonds: BTreeMap::new(),
            decrypt_shares: BTreeMap::new(),
            settlement_paths: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateIntentSettlementEscrowResult<Self> {
        let config = PrivateIntentSettlementEscrowConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            PRIVATE_INTENT_SETTLEMENT_ESCROW_DEVNET_HEIGHT,
        );
        let scopes = vec![
            "private-intent:solve".to_string(),
            "private-intent:decrypt".to_string(),
            "private-intent:low-fee".to_string(),
        ];
        let bond = SolverEscrowBond::new(
            "devnet-solver-a",
            "devnet-solver-a-ml-dsa-87-key",
            &config.fee_asset_id,
            config.min_solver_bond_units.saturating_mul(4),
            8_500,
            &scopes,
            state.height,
            state.height.saturating_add(config.sponsor_ttl_blocks),
        )?;
        let bond_id = state.insert_solver_bond(bond)?;
        let sponsorship = LowFeeEscrowSponsorship::new(
            "devnet-fee-sponsor-a",
            "private-intent-fast-lane",
            &config.fee_asset_id,
            500_000,
            config.low_fee_rebate_bps,
            &json!({
                "max_fee_units": 250,
                "min_privacy_set_size": config.min_privacy_set_size,
                "solver_bond_id": bond_id,
            }),
            state.height,
            state.height.saturating_add(config.sponsor_ttl_blocks),
        )?;
        let sponsorship_id = state.insert_sponsorship(sponsorship)?;
        let mut escrow = PrivateIntentEscrow::new(
            &private_intent_settlement_escrow_string_root("devnet-intent", "swap-1"),
            &private_intent_settlement_escrow_string_root("devnet-owner", "alice"),
            &config.stable_asset_id,
            "dxmr",
            &private_intent_settlement_escrow_string_root("devnet-input", "1000"),
            &private_intent_settlement_escrow_string_root("devnet-output", "980"),
            &private_intent_settlement_escrow_string_root("devnet-nullifier", "swap-1"),
            &private_intent_settlement_escrow_string_root("devnet-refund", "swap-1"),
            PrivateEscrowIntentKind::SwapExactIn,
            EscrowPrivacyClass::FullyShielded,
            config.min_privacy_set_size.saturating_mul(2),
            state.height,
            state.height.saturating_add(config.escrow_ttl_blocks),
            config.max_disclosure_bps,
            true,
        )?;
        escrow.status = EscrowStatus::Matched;
        let escrow_id = state.insert_escrow(escrow)?;
        let path = SettlementPath::new(
            &escrow_id,
            "devnet-solver-a",
            &private_intent_settlement_escrow_string_root("devnet-venue", "private-amm"),
            &private_intent_settlement_escrow_string_root("devnet-route", "dusd-dxmr"),
            &private_intent_settlement_escrow_string_root("devnet-clearing", "price-1"),
            &private_intent_settlement_escrow_string_root("devnet-expected-output", "swap-1"),
            &private_intent_settlement_escrow_string_root("devnet-fee", "sponsored"),
            Some(sponsorship_id),
            state.height,
            state.height.saturating_add(config.settlement_window_blocks),
            1_200,
        )?;
        let path_id = state.insert_settlement_path(path)?;
        state.link_escrow_to_path(&escrow_id, &path_id, "devnet-solver-a")?;
        for index in 0..3_u64 {
            let share = ThresholdDecryptShare::new(
                &escrow_id,
                &format!("devnet-threshold-member-{index}"),
                &private_intent_settlement_escrow_string_root(
                    "devnet-decrypt-share",
                    &format!("{escrow_id}:{index}"),
                ),
                &private_intent_settlement_escrow_string_root(
                    "devnet-pq-signature",
                    &format!("{escrow_id}:{index}"),
                ),
                state.height.saturating_add(index),
                state
                    .height
                    .saturating_add(config.decryption_window_blocks)
                    .saturating_add(index),
            )?;
            state.insert_decrypt_share(share)?;
        }
        let receipt = PrivateSettlementReceipt::new(
            &escrow_id,
            &path_id,
            &private_intent_settlement_escrow_string_root("devnet-settlement-nullifier", "swap-1"),
            &private_intent_settlement_escrow_string_root("devnet-output-note", "swap-1"),
            &private_intent_settlement_escrow_string_root("devnet-fee-receipt", "swap-1"),
            "devnet-solver-a",
            state.height.saturating_add(4),
        )?;
        state.insert_receipt(receipt)?;
        let challenge = EscrowChallengeWindow::new(
            &escrow_id,
            &private_intent_settlement_escrow_string_root("devnet-challenger", "watchtower-a"),
            &json!({"kind": "delayed_receipt_guard", "severity": "watch"}),
            10_000,
            state.height.saturating_add(5),
            state
                .height
                .saturating_add(config.challenge_window_blocks)
                .saturating_add(5),
        )?;
        state.insert_challenge(challenge)?;
        state.insert_event(EscrowLifecycleEvent::new(
            Some(escrow_id.clone()),
            "devnet_private_intent_escrow_seeded",
            &json!({"path_id": path_id, "low_fee": true}),
            state.height,
            1,
        )?)?;
        state.insert_public_record(EscrowPublicRecord::new(
            "devnet_private_intent_escrow_summary",
            &json!({
                "escrow_id": escrow_id,
                "solver_id": "devnet-solver-a",
                "scheme": PRIVATE_INTENT_SETTLEMENT_ESCROW_ENCRYPTION_SCHEME,
            }),
            state.height,
            1,
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_escrow(
        &mut self,
        escrow: PrivateIntentEscrow,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit("escrows", self.escrows.len(), self.config.max_escrows)?;
        if escrow.privacy_set_size < self.config.min_privacy_set_size {
            return Err("escrow privacy set below configured minimum".to_string());
        }
        if escrow.max_disclosure_bps > self.config.max_disclosure_bps {
            return Err("escrow disclosure exceeds configured maximum".to_string());
        }
        let id = escrow.validate()?;
        self.escrows.insert(id.clone(), escrow);
        Ok(id)
    }

    pub fn insert_solver_bond(
        &mut self,
        bond: SolverEscrowBond,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit(
            "solver_bonds",
            self.solver_bonds.len(),
            self.config.max_solver_bonds,
        )?;
        if bond.bonded_units < self.config.min_solver_bond_units {
            return Err("solver bond below configured minimum".to_string());
        }
        let id = bond.validate()?;
        self.solver_bonds.insert(id.clone(), bond);
        Ok(id)
    }

    pub fn insert_decrypt_share(
        &mut self,
        share: ThresholdDecryptShare,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit(
            "decrypt_shares",
            self.decrypt_shares.len(),
            self.config.max_decrypt_shares,
        )?;
        if !self.escrows.contains_key(&share.escrow_id) {
            return Err("decrypt share references unknown escrow".to_string());
        }
        let id = share.validate()?;
        self.decrypt_shares.insert(id.clone(), share);
        Ok(id)
    }

    pub fn insert_settlement_path(
        &mut self,
        path: SettlementPath,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit(
            "settlement_paths",
            self.settlement_paths.len(),
            self.config.max_settlement_paths,
        )?;
        if !self.escrows.contains_key(&path.escrow_id) {
            return Err("settlement path references unknown escrow".to_string());
        }
        if self
            .solver_bonds
            .values()
            .all(|bond| bond.solver_id != path.solver_id || !bond.status.usable())
        {
            return Err("settlement path solver has no active bond".to_string());
        }
        if let Some(sponsorship_id) = &path.sponsorship_id {
            if !self.sponsorships.contains_key(sponsorship_id) {
                return Err("settlement path references unknown sponsorship".to_string());
            }
        }
        let id = path.validate()?;
        self.settlement_paths.insert(id.clone(), path);
        Ok(id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeEscrowSponsorship,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit(
            "sponsorships",
            self.sponsorships.len(),
            self.config.max_sponsorships,
        )?;
        let id = sponsorship.validate()?;
        self.sponsorships.insert(id.clone(), sponsorship);
        Ok(id)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: EscrowChallengeWindow,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        if !self.escrows.contains_key(&challenge.escrow_id) {
            return Err("challenge references unknown escrow".to_string());
        }
        let id = challenge.validate()?;
        if let Some(escrow) = self.escrows.get_mut(&challenge.escrow_id) {
            if escrow.status.live() {
                escrow.status = EscrowStatus::Challenged;
            }
        }
        self.challenges.insert(id.clone(), challenge);
        Ok(id)
    }

    pub fn insert_receipt(
        &mut self,
        receipt: PrivateSettlementReceipt,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit("receipts", self.receipts.len(), self.config.max_receipts)?;
        if !self.escrows.contains_key(&receipt.escrow_id) {
            return Err("receipt references unknown escrow".to_string());
        }
        if !self.settlement_paths.contains_key(&receipt.path_id) {
            return Err("receipt references unknown settlement path".to_string());
        }
        let id = receipt.validate()?;
        if let Some(escrow) = self.escrows.get_mut(&receipt.escrow_id) {
            escrow.status = EscrowStatus::Settled;
        }
        if let Some(path) = self.settlement_paths.get_mut(&receipt.path_id) {
            path.status = SettlementPathStatus::Executed;
        }
        self.receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn insert_event(
        &mut self,
        event: EscrowLifecycleEvent,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit("events", self.events.len(), self.config.max_events)?;
        let id = event.validate()?;
        self.events.insert(id.clone(), event);
        Ok(id)
    }

    pub fn insert_public_record(
        &mut self,
        record: EscrowPublicRecord,
    ) -> PrivateIntentSettlementEscrowResult<String> {
        ensure_limit(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        let id = record.validate()?;
        self.public_records.insert(id.clone(), record);
        Ok(id)
    }

    pub fn link_escrow_to_path(
        &mut self,
        escrow_id: &str,
        path_id: &str,
        solver_id: &str,
    ) -> PrivateIntentSettlementEscrowResult<()> {
        if !self.settlement_paths.contains_key(path_id) {
            return Err("cannot link unknown settlement path".to_string());
        }
        let escrow = self
            .escrows
            .get_mut(escrow_id)
            .ok_or_else(|| "cannot link unknown escrow".to_string())?;
        escrow.matched_path_id = Some(path_id.to_string());
        escrow.solver_id = Some(solver_id.to_string());
        if escrow.status.live() {
            escrow.status = EscrowStatus::Matched;
        }
        if let Some(path) = self.settlement_paths.get_mut(path_id) {
            path.status = SettlementPathStatus::Selected;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateIntentSettlementEscrowResult<()> {
        if height < self.height {
            return Err(
                "private intent settlement escrow height cannot move backwards".to_string(),
            );
        }
        self.height = height;
        for escrow in self.escrows.values_mut() {
            if escrow.status.live() && escrow.expires_at_height <= height {
                escrow.status = EscrowStatus::Expired;
            } else if escrow.status == EscrowStatus::Matched {
                escrow.status = EscrowStatus::Decrypting;
            } else if escrow.status == EscrowStatus::Decrypting {
                escrow.status = EscrowStatus::Settling;
            }
        }
        for share in self.decrypt_shares.values_mut() {
            if matches!(share.status, DecryptShareStatus::Submitted)
                && share.expires_at_height <= height
            {
                share.status = DecryptShareStatus::Expired;
            } else if matches!(share.status, DecryptShareStatus::Submitted) {
                share.status = DecryptShareStatus::Accepted;
            }
        }
        for path in self.settlement_paths.values_mut() {
            if path.status.live() && path.execute_by_height <= height {
                path.status = SettlementPathStatus::Expired;
            } else if path.status == SettlementPathStatus::Selected {
                path.status = SettlementPathStatus::Executing;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status.available() && sponsorship.expires_at_height <= height {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status.live() && challenge.deadline_height <= height {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        for bond in self.solver_bonds.values_mut() {
            if matches!(bond.status, SolverBondStatus::Active) && bond.expires_at_height <= height {
                bond.status = SolverBondStatus::Expired;
            }
        }
        self.validate()?;
        Ok(())
    }

    pub fn live_escrow_ids(&self) -> Vec<String> {
        self.escrows
            .iter()
            .filter(|(_, escrow)| escrow.status.live())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn active_solver_ids(&self) -> Vec<String> {
        let mut ids = BTreeSet::new();
        for bond in self.solver_bonds.values() {
            if bond.status.usable() {
                ids.insert(bond.solver_id.clone());
            }
        }
        ids.into_iter().collect()
    }

    pub fn accepted_share_count_for_escrow(&self, escrow_id: &str) -> u64 {
        self.decrypt_shares
            .values()
            .filter(|share| {
                share.escrow_id == escrow_id && matches!(share.status, DecryptShareStatus::Accepted)
            })
            .count() as u64
    }

    pub fn total_available_sponsor_units(&self) -> u64 {
        self.sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status.available())
            .map(LowFeeEscrowSponsorship::available_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn total_available_solver_bond_units(&self) -> u64 {
        self.solver_bonds
            .values()
            .filter(|bond| bond.status.usable())
            .map(SolverEscrowBond::available_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn roots(&self) -> PrivateIntentSettlementEscrowRoots {
        PrivateIntentSettlementEscrowRoots {
            config_root: self.config.config_root(),
            escrow_root: private_intent_escrow_root(&self.escrows),
            solver_bond_root: solver_escrow_bond_root(&self.solver_bonds),
            decrypt_share_root: threshold_decrypt_share_root(&self.decrypt_shares),
            settlement_path_root: settlement_path_root(&self.settlement_paths),
            sponsorship_root: low_fee_escrow_sponsorship_root(&self.sponsorships),
            challenge_root: escrow_challenge_root(&self.challenges),
            receipt_root: private_settlement_receipt_root(&self.receipts),
            event_root: escrow_lifecycle_event_root(&self.events),
            public_record_root: escrow_public_record_root(&self.public_records),
        }
    }

    pub fn counters(&self) -> PrivateIntentSettlementEscrowCounters {
        PrivateIntentSettlementEscrowCounters {
            escrow_count: self.escrows.len() as u64,
            live_escrow_count: self
                .escrows
                .values()
                .filter(|escrow| escrow.status.live())
                .count() as u64,
            settled_escrow_count: self
                .escrows
                .values()
                .filter(|escrow| escrow.status == EscrowStatus::Settled)
                .count() as u64,
            challenged_escrow_count: self
                .escrows
                .values()
                .filter(|escrow| escrow.status == EscrowStatus::Challenged)
                .count() as u64,
            low_fee_escrow_count: self
                .escrows
                .values()
                .filter(|escrow| escrow.low_fee_lane)
                .count() as u64,
            solver_bond_count: self.solver_bonds.len() as u64,
            active_solver_bond_count: self
                .solver_bonds
                .values()
                .filter(|bond| bond.status.usable())
                .count() as u64,
            decrypt_share_count: self.decrypt_shares.len() as u64,
            accepted_decrypt_share_count: self
                .decrypt_shares
                .values()
                .filter(|share| share.status == DecryptShareStatus::Accepted)
                .count() as u64,
            settlement_path_count: self.settlement_paths.len() as u64,
            live_settlement_path_count: self
                .settlement_paths
                .values()
                .filter(|path| path.status.live())
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            active_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.available())
                .count() as u64,
            challenge_count: self.challenges.len() as u64,
            live_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.live())
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
            event_count: self.events.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_available_sponsor_units: self.total_available_sponsor_units(),
            total_available_solver_bond_units: self.total_available_solver_bond_units(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_intent_settlement_escrow_state",
            "protocol_version": PRIVATE_INTENT_SETTLEMENT_ESCROW_PROTOCOL_VERSION,
            "schema_version": PRIVATE_INTENT_SETTLEMENT_ESCROW_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        private_intent_settlement_escrow_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> PrivateIntentSettlementEscrowResult<String> {
        self.config.validate()?;
        ensure_count_at_most("escrows", self.escrows.len(), self.config.max_escrows)?;
        ensure_count_at_most(
            "solver_bonds",
            self.solver_bonds.len(),
            self.config.max_solver_bonds,
        )?;
        ensure_count_at_most(
            "decrypt_shares",
            self.decrypt_shares.len(),
            self.config.max_decrypt_shares,
        )?;
        ensure_count_at_most(
            "settlement_paths",
            self.settlement_paths.len(),
            self.config.max_settlement_paths,
        )?;
        ensure_count_at_most(
            "sponsorships",
            self.sponsorships.len(),
            self.config.max_sponsorships,
        )?;
        ensure_count_at_most(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        ensure_count_at_most("receipts", self.receipts.len(), self.config.max_receipts)?;
        ensure_count_at_most("events", self.events.len(), self.config.max_events)?;
        ensure_count_at_most(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        for (id, escrow) in &self.escrows {
            if id != &escrow.validate()? {
                return Err("escrow map key mismatch".to_string());
            }
            if escrow.privacy_set_size < self.config.min_privacy_set_size {
                return Err("escrow privacy set below configured minimum".to_string());
            }
        }
        for (id, bond) in &self.solver_bonds {
            if id != &bond.validate()? {
                return Err("solver bond map key mismatch".to_string());
            }
        }
        for (id, share) in &self.decrypt_shares {
            if id != &share.validate()? {
                return Err("decrypt share map key mismatch".to_string());
            }
            if !self.escrows.contains_key(&share.escrow_id) {
                return Err("decrypt share references unknown escrow".to_string());
            }
        }
        for (id, path) in &self.settlement_paths {
            if id != &path.validate()? {
                return Err("settlement path map key mismatch".to_string());
            }
            if !self.escrows.contains_key(&path.escrow_id) {
                return Err("settlement path references unknown escrow".to_string());
            }
            if self
                .solver_bonds
                .values()
                .all(|bond| bond.solver_id != path.solver_id)
            {
                return Err("settlement path references unknown solver".to_string());
            }
        }
        for (id, sponsorship) in &self.sponsorships {
            if id != &sponsorship.validate()? {
                return Err("sponsorship map key mismatch".to_string());
            }
        }
        for (id, challenge) in &self.challenges {
            if id != &challenge.validate()? {
                return Err("challenge map key mismatch".to_string());
            }
            if !self.escrows.contains_key(&challenge.escrow_id) {
                return Err("challenge references unknown escrow".to_string());
            }
        }
        for (id, receipt) in &self.receipts {
            if id != &receipt.validate()? {
                return Err("receipt map key mismatch".to_string());
            }
            if !self.escrows.contains_key(&receipt.escrow_id) {
                return Err("receipt references unknown escrow".to_string());
            }
            if !self.settlement_paths.contains_key(&receipt.path_id) {
                return Err("receipt references unknown settlement path".to_string());
            }
        }
        for (id, event) in &self.events {
            if id != &event.validate()? {
                return Err("event map key mismatch".to_string());
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.validate()? {
                return Err("public record map key mismatch".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_intent_settlement_escrow_state_root_from_record(record: &Value) -> String {
    private_intent_settlement_escrow_payload_root("PRIVATE-INTENT-SETTLEMENT-ESCROW-STATE", record)
}

pub fn private_intent_settlement_escrow_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_intent_settlement_escrow_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-STRING",
        &[HashPart::Str(domain), HashPart::Str(value)],
        32,
    )
}

pub fn private_intent_settlement_escrow_id(
    intent_commitment_root: &str,
    owner_commitment_root: &str,
    input_asset_id: &str,
    output_asset_id: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_commitment_root),
            HashPart::Str(owner_commitment_root),
            HashPart::Str(input_asset_id),
            HashPart::Str(output_asset_id),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn solver_escrow_bond_id(solver_id: &str, scope_root: &str, created_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-SOLVER-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_id),
            HashPart::Str(scope_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_path_id(
    escrow_id: &str,
    solver_id: &str,
    route_commitment_root: &str,
    proposed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-PATH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(escrow_id),
            HashPart::Str(solver_id),
            HashPart::Str(route_commitment_root),
            HashPart::Int(proposed_at_height as i128),
        ],
        32,
    )
}

pub fn decrypt_share_id(
    escrow_id: &str,
    committee_member_id: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-DECRYPT-SHARE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(escrow_id),
            HashPart::Str(committee_member_id),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_escrow_sponsorship_id(
    sponsor_id: &str,
    lane_id: &str,
    policy_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_id),
            HashPart::Str(policy_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn escrow_challenge_id(
    escrow_id: &str,
    challenger_commitment_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(escrow_id),
            HashPart::Str(challenger_commitment_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_settlement_receipt_id(
    escrow_id: &str,
    path_id: &str,
    solver_id: &str,
    finalized_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(escrow_id),
            HashPart::Str(path_id),
            HashPart::Str(solver_id),
            HashPart::Int(finalized_at_height as i128),
        ],
        32,
    )
}

pub fn escrow_lifecycle_event_id(
    escrow_id: Option<&str>,
    event_kind: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(match escrow_id {
                Some(value) => value,
                None => "global",
            }),
            HashPart::Str(event_kind),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn escrow_public_record_id(
    record_kind: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_intent_escrow_root(records: &BTreeMap<String, PrivateIntentEscrow>) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-ESCROW-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn solver_escrow_bond_root(records: &BTreeMap<String, SolverEscrowBond>) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-SOLVER-BOND-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn threshold_decrypt_share_root(records: &BTreeMap<String, ThresholdDecryptShare>) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-DECRYPT-SHARE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn settlement_path_root(records: &BTreeMap<String, SettlementPath>) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-PATH-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn low_fee_escrow_sponsorship_root(
    records: &BTreeMap<String, LowFeeEscrowSponsorship>,
) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-SPONSORSHIP-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn escrow_challenge_root(records: &BTreeMap<String, EscrowChallengeWindow>) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-CHALLENGE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn private_settlement_receipt_root(
    records: &BTreeMap<String, PrivateSettlementReceipt>,
) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-RECEIPT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn escrow_lifecycle_event_root(records: &BTreeMap<String, EscrowLifecycleEvent>) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-EVENT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn escrow_public_record_root(records: &BTreeMap<String, EscrowPublicRecord>) -> String {
    keyed_record_root(
        "PRIVATE-INTENT-SETTLEMENT-ESCROW-PUBLIC-RECORD-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

fn keyed_record_root<'a, I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = (&'a String, Value)>,
{
    let leaves = records
        .into_iter()
        .map(|(id, record)| json!({ "id": id, "record": record }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_string_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(field: &str, value: &str) -> PrivateIntentSettlementEscrowResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn ensure_non_empty_list(
    field: &str,
    values: &[String],
) -> PrivateIntentSettlementEscrowResult<()> {
    if values.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{field} contains an empty value"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{field} contains a duplicate value"));
        }
    }
    Ok(())
}

fn ensure_positive(field: &str, value: u64) -> PrivateIntentSettlementEscrowResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn ensure_capacity(field: &str, value: usize) -> PrivateIntentSettlementEscrowResult<()> {
    if value == 0 {
        return Err(format!("{field} capacity must be positive"));
    }
    Ok(())
}

fn ensure_limit(
    field: &str,
    current: usize,
    limit: usize,
) -> PrivateIntentSettlementEscrowResult<()> {
    if current >= limit {
        return Err(format!("{field} capacity exceeded"));
    }
    Ok(())
}

fn ensure_count_at_most(
    field: &str,
    current: usize,
    limit: usize,
) -> PrivateIntentSettlementEscrowResult<()> {
    if current > limit {
        return Err(format!("{field} capacity exceeded"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> PrivateIntentSettlementEscrowResult<()> {
    if value > PRIVATE_INTENT_SETTLEMENT_ESCROW_MAX_BPS {
        return Err(format!("{field} exceeds 100%"));
    }
    Ok(())
}

fn ensure_height_order(
    field: &str,
    start_height: u64,
    end_height: u64,
) -> PrivateIntentSettlementEscrowResult<()> {
    if end_height <= start_height {
        return Err(format!("{field} end height must be after start height"));
    }
    Ok(())
}

fn ensure_hex_root(field: &str, value: &str) -> PrivateIntentSettlementEscrowResult<()> {
    ensure_non_empty(field, value)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must be a 32-byte hex commitment"));
    }
    Ok(())
}
