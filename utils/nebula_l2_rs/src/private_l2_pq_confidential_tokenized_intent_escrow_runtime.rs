use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-intent-escrow-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-tokenized-intent-escrow-v1";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_SETTLEMENT_LANE: &str = "private-l2-confidential-tokenized-intent-escrow";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_INTENT_ASSET_ID: &str = "intent-note-devnet";
pub const DEFAULT_WRAPPED_XMR_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_STABLE_ASSET_ID: &str = "private-dusd-devnet";
pub const DEVNET_HEIGHT: u64 = 1_486_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u64 = 32;
pub const DEFAULT_MIN_SOLVER_BOND_PICONERO: u64 = 5_000_000_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 10;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 6;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_SOLVER_BOND_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 720;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VAULTS: usize = 262_144;
pub const MAX_SEALED_INTENTS: usize = 4_194_304;
pub const MAX_SOLVER_BONDS: usize = 1_048_576;
pub const MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENT_RECEIPTS: usize = 4_194_304;
pub const MAX_SPONSOR_CREDITS: usize = 2_097_152;
pub const MAX_ABUSE_QUARANTINES: usize = 1_048_576;
pub const MAX_PRIVACY_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_DEVNET_FIXTURES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowVaultKind {
    SpotSwap,
    Dca,
    LpExit,
    LendingRepay,
    CollateralRebalance,
    BridgeSettlement,
    TreasuryBatch,
}

impl EscrowVaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpotSwap => "spot_swap",
            Self::Dca => "dca",
            Self::LpExit => "lp_exit",
            Self::LendingRepay => "lending_repay",
            Self::CollateralRebalance => "collateral_rebalance",
            Self::BridgeSettlement => "bridge_settlement",
            Self::TreasuryBatch => "treasury_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    IntakePaused,
    SolverOnly,
    SettlementOnly,
    Quarantined,
    Closed,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::IntakePaused => "intake_paused",
            Self::SolverOnly => "solver_only",
            Self::SettlementOnly => "settlement_only",
            Self::Quarantined => "quarantined",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_bonds(self) -> bool {
        matches!(self, Self::Open | Self::SolverOnly)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(self, Self::Open | Self::SolverOnly | Self::SettlementOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    SwapExactIn,
    SwapExactOut,
    LimitOrder,
    DcaSlice,
    LpMint,
    LpBurn,
    CollateralMove,
    BridgeFill,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::LimitOrder => "limit_order",
            Self::DcaSlice => "dca_slice",
            Self::LpMint => "lp_mint",
            Self::LpBurn => "lp_burn",
            Self::CollateralMove => "collateral_move",
            Self::BridgeFill => "bridge_fill",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Bonded,
    PqAuthorized,
    Sponsored,
    Matched,
    Settled,
    Cancelled,
    Expired,
    Quarantined,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Bonded => "bonded",
            Self::PqAuthorized => "pq_authorized",
            Self::Sponsored => "sponsored",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Bonded | Self::PqAuthorized | Self::Sponsored | Self::Matched
        )
    }

    pub fn accepts_solver_bond(self) -> bool {
        matches!(self, Self::Sealed | Self::Bonded | Self::PqAuthorized)
    }

    pub fn accepts_authorization(self) -> bool {
        matches!(self, Self::Sealed | Self::Bonded | Self::PqAuthorized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Posted,
    Locked,
    Released,
    Slashed,
    Expired,
}

impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Posted | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationKind {
    UserIntent,
    SolverFill,
    SponsorCredit,
    WatchtowerReview,
    EmergencyCancel,
}

impl PqAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserIntent => "user_intent",
            Self::SolverFill => "solver_fill",
            Self::SponsorCredit => "sponsor_credit",
            Self::WatchtowerReview => "watchtower_review",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    Reconciled,
    Challenged,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Finalized => "finalized",
            Self::Reconciled => "reconciled",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    FeeCapViolation,
    ReusedNullifier,
    BadPqAuthorization,
    SolverBondMissing,
    RedactionBudgetExceeded,
    SettlementMismatch,
    WatchtowerAbuseReport,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeCapViolation => "fee_cap_violation",
            Self::ReusedNullifier => "reused_nullifier",
            Self::BadPqAuthorization => "bad_pq_authorization",
            Self::SolverBondMissing => "solver_bond_missing",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::SettlementMismatch => "settlement_mismatch",
            Self::WatchtowerAbuseReport => "watchtower_abuse_report",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub settlement_lane: String,
    pub fee_asset_id: String,
    pub intent_asset_id: String,
    pub wrapped_xmr_asset_id: String,
    pub stable_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub privacy_redaction_budget_per_epoch: u64,
    pub min_solver_bond_piconero: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub min_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub solver_bond_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub require_roots_only_public_records: bool,
    pub allow_demo_fixtures: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_SCHEMA_VERSION,
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            settlement_lane: DEFAULT_SETTLEMENT_LANE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            intent_asset_id: DEFAULT_INTENT_ASSET_ID.to_string(),
            wrapped_xmr_asset_id: DEFAULT_WRAPPED_XMR_ASSET_ID.to_string(),
            stable_asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            privacy_redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            min_solver_bond_piconero: DEFAULT_MIN_SOLVER_BOND_PICONERO,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            solver_bond_ttl_blocks: DEFAULT_SOLVER_BOND_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            require_roots_only_public_records: true,
            allow_demo_fixtures: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "settlement_lane": self.settlement_lane,
            "fee_asset_id": self.fee_asset_id,
            "intent_asset_id": self.intent_asset_id,
            "wrapped_xmr_asset_id": self.wrapped_xmr_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "privacy_redaction_budget_per_epoch": self.privacy_redaction_budget_per_epoch,
            "min_solver_bond_piconero": self.min_solver_bond_piconero,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "solver_bond_ttl_blocks": self.solver_bond_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "require_roots_only_public_records": self.require_roots_only_public_records,
            "allow_demo_fixtures": self.allow_demo_fixtures,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub sealed_intents: u64,
    pub solver_bonds: u64,
    pub pq_authorization_attestations: u64,
    pub settlement_receipts: u64,
    pub sponsor_credits: u64,
    pub abuse_quarantines: u64,
    pub privacy_redaction_budgets: u64,
    pub consumed_nullifiers: u64,
    pub public_records: u64,
    pub devnet_fixtures: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vaults": self.vaults,
            "sealed_intents": self.sealed_intents,
            "solver_bonds": self.solver_bonds,
            "pq_authorization_attestations": self.pq_authorization_attestations,
            "settlement_receipts": self.settlement_receipts,
            "sponsor_credits": self.sponsor_credits,
            "abuse_quarantines": self.abuse_quarantines,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "consumed_nullifiers": self.consumed_nullifiers,
            "public_records": self.public_records,
            "devnet_fixtures": self.devnet_fixtures,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenIntentEscrowVault {
    pub vault_id: String,
    pub kind: EscrowVaultKind,
    pub status: VaultStatus,
    pub operator_commitment: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub vault_commitment_root: String,
    pub token_inventory_root: String,
    pub allowed_solver_set_root: String,
    pub privacy_policy_root: String,
    pub fee_cap_bps: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl TokenIntentEscrowVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "vault_commitment_root": self.vault_commitment_root,
            "token_inventory_root": self.token_inventory_root,
            "allowed_solver_set_root": self.allowed_solver_set_root,
            "privacy_policy_root": self.privacy_policy_root,
            "fee_cap_bps": self.fee_cap_bps,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedIntent {
    pub intent_id: String,
    pub vault_id: String,
    pub kind: IntentKind,
    pub status: IntentStatus,
    pub maker_commitment: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub sealed_input_root: String,
    pub sealed_output_root: String,
    pub price_limit_commitment_root: String,
    pub route_constraint_root: String,
    pub nullifier_hash: String,
    pub privacy_set_size: u64,
    pub fee_cap_bps: u64,
    pub solver_fee_cap_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "vault_id": self.vault_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "maker_commitment": self.maker_commitment,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "sealed_input_root": self.sealed_input_root,
            "sealed_output_root": self.sealed_output_root,
            "price_limit_commitment_root": self.price_limit_commitment_root,
            "route_constraint_root": self.route_constraint_root,
            "nullifier_hash": self.nullifier_hash,
            "privacy_set_size": self.privacy_set_size,
            "fee_cap_bps": self.fee_cap_bps,
            "solver_fee_cap_bps": self.solver_fee_cap_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverBond {
    pub bond_id: String,
    pub intent_id: String,
    pub vault_id: String,
    pub solver_commitment: String,
    pub status: BondStatus,
    pub bond_asset_id: String,
    pub bond_amount_piconero: u64,
    pub fill_quote_root: String,
    pub slashing_condition_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl SolverBond {
    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "intent_id": self.intent_id,
            "vault_id": self.vault_id,
            "solver_commitment": self.solver_commitment,
            "status": self.status.as_str(),
            "bond_asset_id": self.bond_asset_id,
            "bond_amount_piconero": self.bond_amount_piconero,
            "fill_quote_root": self.fill_quote_root,
            "slashing_condition_root": self.slashing_condition_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorizationAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub kind: PqAttestationKind,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub authorization_scope_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub attested_at_height: u64,
}

impl PqAuthorizationAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "authorization_scope_root": self.authorization_scope_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossAssetSettlementReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub bond_id: String,
    pub vault_id: String,
    pub status: ReceiptStatus,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub settlement_asset_id: String,
    pub input_amount_commitment_root: String,
    pub output_amount_commitment_root: String,
    pub solver_fee_commitment_root: String,
    pub sponsor_credit_id: Option<String>,
    pub cross_asset_rate_root: String,
    pub monero_anchor_root: String,
    pub l2_settlement_root: String,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
}

impl CrossAssetSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "bond_id": self.bond_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "input_amount_commitment_root": self.input_amount_commitment_root,
            "output_amount_commitment_root": self.output_amount_commitment_root,
            "solver_fee_commitment_root": self.solver_fee_commitment_root,
            "sponsor_credit_id": self.sponsor_credit_id,
            "cross_asset_rate_root": self.cross_asset_rate_root,
            "monero_anchor_root": self.monero_anchor_root,
            "l2_settlement_root": self.l2_settlement_root,
            "settled_at_height": self.settled_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorCredit {
    pub sponsor_credit_id: String,
    pub intent_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub credit_commitment_root: String,
    pub max_sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub reservation_nullifier_hash: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSponsorCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_credit_id": self.sponsor_credit_id,
            "intent_id": self.intent_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "credit_commitment_root": self.credit_commitment_root,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "reservation_nullifier_hash": self.reservation_nullifier_hash,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseQuarantine {
    pub quarantine_id: String,
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub affected_nullifier_hashes: BTreeSet<String>,
    pub started_at_height: u64,
    pub expires_at_height: u64,
    pub released: bool,
}

impl AbuseQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "reason": self.reason.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "affected_nullifier_hashes": self.affected_nullifier_hashes,
            "started_at_height": self.started_at_height,
            "expires_at_height": self.expires_at_height,
            "released": self.released,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub epoch: u64,
    pub vault_id: String,
    pub viewer_commitment: String,
    pub allowed_redactions: u64,
    pub consumed_redactions: u64,
    pub redaction_policy_root: String,
    pub audit_transcript_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "epoch": self.epoch,
            "vault_id": self.vault_id,
            "viewer_commitment": self.viewer_commitment,
            "allowed_redactions": self.allowed_redactions,
            "consumed_redactions": self.consumed_redactions,
            "redaction_policy_root": self.redaction_policy_root,
            "audit_transcript_root": self.audit_transcript_root,
            "remaining_redactions": self.remaining_redactions(),
        })
    }

    pub fn remaining_redactions(&self) -> u64 {
        self.allowed_redactions
            .saturating_sub(self.consumed_redactions)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub vault_id: String,
    pub intent_ids: Vec<String>,
    pub settlement_receipt_ids: Vec<String>,
    pub fixture_root: String,
    pub created_at_height: u64,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "label": self.label,
            "vault_id": self.vault_id,
            "intent_ids": self.intent_ids,
            "settlement_receipt_ids": self.settlement_receipt_ids,
            "fixture_root": self.fixture_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub vault_root: String,
    pub sealed_intent_root: String,
    pub solver_bond_root: String,
    pub pq_authorization_attestation_root: String,
    pub settlement_receipt_root: String,
    pub sponsor_credit_root: String,
    pub abuse_quarantine_root: String,
    pub privacy_redaction_budget_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
    pub devnet_fixture_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_root": self.vault_root,
            "sealed_intent_root": self.sealed_intent_root,
            "solver_bond_root": self.solver_bond_root,
            "pq_authorization_attestation_root": self.pq_authorization_attestation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "abuse_quarantine_root": self.abuse_quarantine_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
            "devnet_fixture_root": self.devnet_fixture_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub vaults: BTreeMap<String, TokenIntentEscrowVault>,
    pub sealed_intents: BTreeMap<String, SealedIntent>,
    pub solver_bonds: BTreeMap<String, SolverBond>,
    pub pq_authorization_attestations: BTreeMap<String, PqAuthorizationAttestation>,
    pub settlement_receipts: BTreeMap<String, CrossAssetSettlementReceipt>,
    pub sponsor_credits: BTreeMap<String, LowFeeSponsorCredit>,
    pub abuse_quarantines: BTreeMap<String, AbuseQuarantine>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: Vec<Value>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            sealed_intents: BTreeMap::new(),
            solver_bonds: BTreeMap::new(),
            pq_authorization_attestations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            abuse_quarantines: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: Vec::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn register_vault(
        &mut self,
        request: RegisterVaultRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(self.vaults.len(), MAX_VAULTS, "vault")?;
        require_non_empty("operator_commitment", &request.operator_commitment)?;
        require_fee_bps(
            request.fee_cap_bps,
            self.config.max_user_fee_bps,
            "vault fee cap",
        )?;
        let vault_id = vault_id(&request, self.counters.vaults + 1);
        let record = TokenIntentEscrowVault {
            vault_id: vault_id.clone(),
            kind: request.kind,
            status: VaultStatus::Open,
            operator_commitment: request.operator_commitment,
            base_asset_id: request.base_asset_id,
            quote_asset_id: request.quote_asset_id,
            vault_commitment_root: request.vault_commitment_root,
            token_inventory_root: request.token_inventory_root,
            allowed_solver_set_root: request.allowed_solver_set_root,
            privacy_policy_root: request.privacy_policy_root,
            fee_cap_bps: request.fee_cap_bps,
            opened_at_height: request.opened_at_height,
            updated_at_height: request.opened_at_height,
        };
        self.vaults.insert(vault_id.clone(), record.clone());
        self.counters.vaults = self.vaults.len() as u64;
        self.record_public(record.public_record());
        Ok(vault_id)
    }

    pub fn submit_sealed_intent(
        &mut self,
        request: SubmitSealedIntentRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(
            self.sealed_intents.len(),
            MAX_SEALED_INTENTS,
            "sealed intent",
        )?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "intent escrow vault not found".to_string())?;
        if !vault.status.accepts_intents() {
            return Err("intent escrow vault is not accepting sealed intents".to_string());
        }
        self.require_privacy_set(request.privacy_set_size)?;
        require_fee_bps(
            request.fee_cap_bps,
            self.config.max_user_fee_bps,
            "intent fee cap",
        )?;
        require_fee_bps(
            request.solver_fee_cap_bps,
            self.config.max_solver_fee_bps,
            "solver fee cap",
        )?;
        if self.consumed_nullifiers.contains(&request.nullifier_hash) {
            return Err("sealed intent nullifier already consumed".to_string());
        }
        let intent_id = sealed_intent_id(&request, self.counters.sealed_intents + 1);
        let record = SealedIntent {
            intent_id: intent_id.clone(),
            vault_id: request.vault_id,
            kind: request.kind,
            status: IntentStatus::Sealed,
            maker_commitment: request.maker_commitment,
            input_asset_id: request.input_asset_id,
            output_asset_id: request.output_asset_id,
            sealed_input_root: request.sealed_input_root,
            sealed_output_root: request.sealed_output_root,
            price_limit_commitment_root: request.price_limit_commitment_root,
            route_constraint_root: request.route_constraint_root,
            nullifier_hash: request.nullifier_hash,
            privacy_set_size: request.privacy_set_size,
            fee_cap_bps: request.fee_cap_bps,
            solver_fee_cap_bps: request.solver_fee_cap_bps,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.intent_ttl_blocks),
        };
        self.sealed_intents
            .insert(intent_id.clone(), record.clone());
        self.counters.sealed_intents = self.sealed_intents.len() as u64;
        self.record_public(record.public_record());
        Ok(intent_id)
    }

    pub fn post_solver_bond(
        &mut self,
        request: PostSolverBondRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(self.solver_bonds.len(), MAX_SOLVER_BONDS, "solver bond")?;
        let intent = self
            .sealed_intents
            .get(&request.intent_id)
            .ok_or_else(|| "sealed intent not found for solver bond".to_string())?;
        if !intent.status.accepts_solver_bond() {
            return Err("sealed intent does not accept solver bond".to_string());
        }
        let vault = self
            .vaults
            .get(&intent.vault_id)
            .ok_or_else(|| "intent escrow vault not found for solver bond".to_string())?;
        if !vault.status.accepts_bonds() {
            return Err("intent escrow vault is not accepting solver bonds".to_string());
        }
        if request.bond_amount_piconero < self.config.min_solver_bond_piconero {
            return Err("solver bond is below configured minimum".to_string());
        }
        let bond_id = solver_bond_id(&request, self.counters.solver_bonds + 1);
        let record = SolverBond {
            bond_id: bond_id.clone(),
            intent_id: request.intent_id.clone(),
            vault_id: intent.vault_id.clone(),
            solver_commitment: request.solver_commitment,
            status: BondStatus::Posted,
            bond_asset_id: request.bond_asset_id,
            bond_amount_piconero: request.bond_amount_piconero,
            fill_quote_root: request.fill_quote_root,
            slashing_condition_root: request.slashing_condition_root,
            posted_at_height: request.posted_at_height,
            expires_at_height: request
                .posted_at_height
                .saturating_add(self.config.solver_bond_ttl_blocks),
        };
        self.solver_bonds.insert(bond_id.clone(), record.clone());
        if let Some(intent) = self.sealed_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Bonded;
        }
        self.counters.solver_bonds = self.solver_bonds.len() as u64;
        self.record_public(record.public_record());
        Ok(bond_id)
    }

    pub fn record_pq_authorization(
        &mut self,
        request: RecordPqAuthorizationRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(
            self.pq_authorization_attestations.len(),
            MAX_PQ_ATTESTATIONS,
            "PQ authorization attestation",
        )?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("PQ authorization is below configured security bits".to_string());
        }
        if !self.sealed_intents.contains_key(&request.subject_id)
            && !self.solver_bonds.contains_key(&request.subject_id)
            && !self.sponsor_credits.contains_key(&request.subject_id)
        {
            return Err("PQ authorization subject is unknown".to_string());
        }
        let attestation_id = pq_authorization_attestation_id(
            &request,
            self.counters.pq_authorization_attestations + 1,
        );
        let record = PqAuthorizationAttestation {
            attestation_id: attestation_id.clone(),
            subject_id: request.subject_id.clone(),
            kind: request.kind,
            signer_commitment: request.signer_commitment,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            authorization_scope_root: request.authorization_scope_root,
            transcript_root: request.transcript_root,
            security_bits: request.security_bits,
            attested_at_height: request.attested_at_height,
        };
        if let Some(intent) = self.sealed_intents.get_mut(&request.subject_id) {
            if intent.status.accepts_authorization() {
                intent.status = IntentStatus::PqAuthorized;
            }
        }
        self.pq_authorization_attestations
            .insert(attestation_id.clone(), record.clone());
        self.counters.pq_authorization_attestations =
            self.pq_authorization_attestations.len() as u64;
        self.record_public(record.public_record());
        Ok(attestation_id)
    }

    pub fn reserve_sponsor_credit(
        &mut self,
        request: ReserveSponsorCreditRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(
            self.sponsor_credits.len(),
            MAX_SPONSOR_CREDITS,
            "low-fee sponsor credit",
        )?;
        if !self.sealed_intents.contains_key(&request.intent_id) {
            return Err("sealed intent not found for sponsor credit".to_string());
        }
        self.require_privacy_set(request.privacy_set_size)?;
        require_fee_bps(
            request.max_sponsor_fee_bps,
            self.config.max_sponsor_fee_bps,
            "sponsor fee cap",
        )?;
        if self
            .consumed_nullifiers
            .contains(&request.reservation_nullifier_hash)
        {
            return Err("sponsor reservation nullifier already consumed".to_string());
        }
        let sponsor_credit_id = sponsor_credit_id(&request, self.counters.sponsor_credits + 1);
        let record = LowFeeSponsorCredit {
            sponsor_credit_id: sponsor_credit_id.clone(),
            intent_id: request.intent_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            fee_asset_id: request.fee_asset_id,
            credit_commitment_root: request.credit_commitment_root,
            max_sponsor_fee_bps: request.max_sponsor_fee_bps,
            privacy_set_size: request.privacy_set_size,
            reservation_nullifier_hash: request.reservation_nullifier_hash,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.intent_ttl_blocks),
        };
        self.sponsor_credits
            .insert(sponsor_credit_id.clone(), record.clone());
        if let Some(intent) = self.sealed_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Sponsored;
        }
        self.counters.sponsor_credits = self.sponsor_credits.len() as u64;
        self.record_public(record.public_record());
        Ok(sponsor_credit_id)
    }

    pub fn issue_settlement_receipt(
        &mut self,
        request: IssueSettlementReceiptRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(
            self.settlement_receipts.len(),
            MAX_SETTLEMENT_RECEIPTS,
            "settlement receipt",
        )?;
        let intent = self
            .sealed_intents
            .get(&request.intent_id)
            .ok_or_else(|| "sealed intent not found for settlement receipt".to_string())?;
        if !intent.status.is_live() {
            return Err("sealed intent is not live for settlement".to_string());
        }
        let bond = self
            .solver_bonds
            .get(&request.bond_id)
            .ok_or_else(|| "solver bond not found for settlement receipt".to_string())?;
        if bond.intent_id != request.intent_id || !bond.status.active() {
            return Err("solver bond does not cover settlement receipt".to_string());
        }
        let vault = self
            .vaults
            .get(&intent.vault_id)
            .ok_or_else(|| "intent escrow vault not found for settlement receipt".to_string())?;
        if !vault.status.accepts_settlement() {
            return Err("intent escrow vault is not accepting settlement".to_string());
        }
        if let Some(sponsor_credit_id) = &request.sponsor_credit_id {
            if !self.sponsor_credits.contains_key(sponsor_credit_id) {
                return Err("sponsor credit not found for settlement receipt".to_string());
            }
        }
        let receipt_id = settlement_receipt_id(&request, self.counters.settlement_receipts + 1);
        let record = CrossAssetSettlementReceipt {
            receipt_id: receipt_id.clone(),
            intent_id: request.intent_id.clone(),
            bond_id: request.bond_id.clone(),
            vault_id: intent.vault_id.clone(),
            status: ReceiptStatus::Finalized,
            input_asset_id: intent.input_asset_id.clone(),
            output_asset_id: intent.output_asset_id.clone(),
            settlement_asset_id: request.settlement_asset_id,
            input_amount_commitment_root: request.input_amount_commitment_root,
            output_amount_commitment_root: request.output_amount_commitment_root,
            solver_fee_commitment_root: request.solver_fee_commitment_root,
            sponsor_credit_id: request.sponsor_credit_id,
            cross_asset_rate_root: request.cross_asset_rate_root,
            monero_anchor_root: request.monero_anchor_root,
            l2_settlement_root: request.l2_settlement_root,
            settled_at_height: request.settled_at_height,
            expires_at_height: request
                .settled_at_height
                .saturating_add(self.config.receipt_ttl_blocks),
        };
        self.consumed_nullifiers
            .insert(intent.nullifier_hash.clone());
        if let Some(intent) = self.sealed_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Settled;
        }
        if let Some(bond) = self.solver_bonds.get_mut(&request.bond_id) {
            bond.status = BondStatus::Released;
        }
        self.settlement_receipts
            .insert(receipt_id.clone(), record.clone());
        self.counters.settlement_receipts = self.settlement_receipts.len() as u64;
        self.counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        self.record_public(record.public_record());
        Ok(receipt_id)
    }

    pub fn quarantine_subject(
        &mut self,
        request: QuarantineSubjectRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(
            self.abuse_quarantines.len(),
            MAX_ABUSE_QUARANTINES,
            "abuse quarantine",
        )?;
        let known_subject = self.sealed_intents.contains_key(&request.subject_id)
            || self.solver_bonds.contains_key(&request.subject_id)
            || self.settlement_receipts.contains_key(&request.subject_id)
            || self.vaults.contains_key(&request.subject_id);
        if !known_subject {
            return Err("quarantine subject is unknown".to_string());
        }
        let quarantine_id = abuse_quarantine_id(&request, self.counters.abuse_quarantines + 1);
        let record = AbuseQuarantine {
            quarantine_id: quarantine_id.clone(),
            subject_id: request.subject_id.clone(),
            reason: request.reason,
            reporter_commitment: request.reporter_commitment,
            evidence_root: request.evidence_root,
            affected_nullifier_hashes: request.affected_nullifier_hashes,
            started_at_height: request.started_at_height,
            expires_at_height: request
                .started_at_height
                .saturating_add(self.config.quarantine_ttl_blocks),
            released: false,
        };
        if let Some(intent) = self.sealed_intents.get_mut(&request.subject_id) {
            intent.status = IntentStatus::Quarantined;
        }
        if let Some(vault) = self.vaults.get_mut(&request.subject_id) {
            vault.status = VaultStatus::Quarantined;
            vault.updated_at_height = request.started_at_height;
        }
        self.abuse_quarantines
            .insert(quarantine_id.clone(), record.clone());
        self.counters.abuse_quarantines = self.abuse_quarantines.len() as u64;
        self.record_public(record.public_record());
        Ok(quarantine_id)
    }

    pub fn allocate_privacy_redaction_budget(
        &mut self,
        request: AllocatePrivacyRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<String> {
        self.ensure_capacity(
            self.privacy_redaction_budgets.len(),
            MAX_PRIVACY_REDACTION_BUDGETS,
            "privacy redaction budget",
        )?;
        if !self.vaults.contains_key(&request.vault_id) {
            return Err("vault not found for privacy redaction budget".to_string());
        }
        if request.allowed_redactions > self.config.privacy_redaction_budget_per_epoch {
            return Err("privacy redaction budget exceeds configured epoch limit".to_string());
        }
        let budget_id =
            privacy_redaction_budget_id(&request, self.counters.privacy_redaction_budgets + 1);
        let record = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            epoch: request.epoch,
            vault_id: request.vault_id,
            viewer_commitment: request.viewer_commitment,
            allowed_redactions: request.allowed_redactions,
            consumed_redactions: request.consumed_redactions,
            redaction_policy_root: request.redaction_policy_root,
            audit_transcript_root: request.audit_transcript_root,
        };
        self.privacy_redaction_budgets
            .insert(budget_id.clone(), record.clone());
        self.counters.privacy_redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        self.record_public(record.public_record());
        Ok(budget_id)
    }

    pub fn add_devnet_fixture(
        &mut self,
        fixture: DevnetFixture,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<()> {
        self.ensure_capacity(
            self.devnet_fixtures.len(),
            MAX_DEVNET_FIXTURES,
            "devnet fixture",
        )?;
        self.devnet_fixtures
            .insert(fixture.fixture_id.clone(), fixture.clone());
        self.counters.devnet_fixtures = self.devnet_fixtures.len() as u64;
        self.record_public(fixture.public_record());
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.vaults = self.vaults.len() as u64;
        counters.sealed_intents = self.sealed_intents.len() as u64;
        counters.solver_bonds = self.solver_bonds.len() as u64;
        counters.pq_authorization_attestations = self.pq_authorization_attestations.len() as u64;
        counters.settlement_receipts = self.settlement_receipts.len() as u64;
        counters.sponsor_credits = self.sponsor_credits.len() as u64;
        counters.abuse_quarantines = self.abuse_quarantines.len() as u64;
        counters.privacy_redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        counters.public_records = self.public_records.len() as u64;
        counters.devnet_fixtures = self.devnet_fixtures.len() as u64;
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            vault_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-VAULT-ROOT",
                &self.vaults,
                TokenIntentEscrowVault::public_record,
            ),
            sealed_intent_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-SEALED-INTENT-ROOT",
                &self.sealed_intents,
                SealedIntent::public_record,
            ),
            solver_bond_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-SOLVER-BOND-ROOT",
                &self.solver_bonds,
                SolverBond::public_record,
            ),
            pq_authorization_attestation_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-PQ-AUTHORIZATION-ATTESTATION-ROOT",
                &self.pq_authorization_attestations,
                PqAuthorizationAttestation::public_record,
            ),
            settlement_receipt_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-SETTLEMENT-RECEIPT-ROOT",
                &self.settlement_receipts,
                CrossAssetSettlementReceipt::public_record,
            ),
            sponsor_credit_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-SPONSOR-CREDIT-ROOT",
                &self.sponsor_credits,
                LowFeeSponsorCredit::public_record,
            ),
            abuse_quarantine_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-ABUSE-QUARANTINE-ROOT",
                &self.abuse_quarantines,
                AbuseQuarantine::public_record,
            ),
            privacy_redaction_budget_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-PRIVACY-REDACTION-BUDGET-ROOT",
                &self.privacy_redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            consumed_nullifier_root: set_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-CONSUMED-NULLIFIER-ROOT",
                &self.consumed_nullifiers,
            ),
            public_record_root: public_record_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
            devnet_fixture_root: map_root(
                "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-DEVNET-FIXTURE-ROOT",
                &self.devnet_fixtures,
                DevnetFixture::public_record,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_HASH_SUITE,
            "pq_authorization_suite": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_PQ_AUTH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "roots_state_root": roots.state_root(),
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
        private_l2_pq_confidential_tokenized_intent_escrow_runtime_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn ensure_capacity(
        &self,
        current_len: usize,
        max_len: usize,
        label: &str,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<()> {
        if current_len >= max_len {
            return Err(format!(
                "tokenized intent escrow {label} capacity exhausted"
            ));
        }
        Ok(())
    }

    fn require_privacy_set(
        &self,
        privacy_set_size: u64,
    ) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("tokenized intent escrow privacy set is below minimum".to_string());
        }
        Ok(())
    }

    fn record_public(&mut self, record: Value) {
        self.public_records.push(record);
        self.counters.public_records = self.public_records.len() as u64;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterVaultRequest {
    pub kind: EscrowVaultKind,
    pub operator_commitment: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub vault_commitment_root: String,
    pub token_inventory_root: String,
    pub allowed_solver_set_root: String,
    pub privacy_policy_root: String,
    pub fee_cap_bps: u64,
    pub opened_at_height: u64,
}

impl RegisterVaultRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "vault_commitment_root": self.vault_commitment_root,
            "token_inventory_root": self.token_inventory_root,
            "allowed_solver_set_root": self.allowed_solver_set_root,
            "privacy_policy_root": self.privacy_policy_root,
            "fee_cap_bps": self.fee_cap_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitSealedIntentRequest {
    pub vault_id: String,
    pub kind: IntentKind,
    pub maker_commitment: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub sealed_input_root: String,
    pub sealed_output_root: String,
    pub price_limit_commitment_root: String,
    pub route_constraint_root: String,
    pub nullifier_hash: String,
    pub privacy_set_size: u64,
    pub fee_cap_bps: u64,
    pub solver_fee_cap_bps: u64,
    pub submitted_at_height: u64,
}

impl SubmitSealedIntentRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "kind": self.kind.as_str(),
            "maker_commitment": self.maker_commitment,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "sealed_input_root": self.sealed_input_root,
            "sealed_output_root": self.sealed_output_root,
            "price_limit_commitment_root": self.price_limit_commitment_root,
            "route_constraint_root": self.route_constraint_root,
            "nullifier_hash": self.nullifier_hash,
            "privacy_set_size": self.privacy_set_size,
            "fee_cap_bps": self.fee_cap_bps,
            "solver_fee_cap_bps": self.solver_fee_cap_bps,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostSolverBondRequest {
    pub intent_id: String,
    pub solver_commitment: String,
    pub bond_asset_id: String,
    pub bond_amount_piconero: u64,
    pub fill_quote_root: String,
    pub slashing_condition_root: String,
    pub posted_at_height: u64,
}

impl PostSolverBondRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "solver_commitment": self.solver_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bond_amount_piconero": self.bond_amount_piconero,
            "fill_quote_root": self.fill_quote_root,
            "slashing_condition_root": self.slashing_condition_root,
            "posted_at_height": self.posted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordPqAuthorizationRequest {
    pub subject_id: String,
    pub kind: PqAttestationKind,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub authorization_scope_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub attested_at_height: u64,
}

impl RecordPqAuthorizationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "authorization_scope_root": self.authorization_scope_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveSponsorCreditRequest {
    pub intent_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub credit_commitment_root: String,
    pub max_sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub reservation_nullifier_hash: String,
    pub reserved_at_height: u64,
}

impl ReserveSponsorCreditRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "credit_commitment_root": self.credit_commitment_root,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "reservation_nullifier_hash": self.reservation_nullifier_hash,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueSettlementReceiptRequest {
    pub intent_id: String,
    pub bond_id: String,
    pub settlement_asset_id: String,
    pub input_amount_commitment_root: String,
    pub output_amount_commitment_root: String,
    pub solver_fee_commitment_root: String,
    pub sponsor_credit_id: Option<String>,
    pub cross_asset_rate_root: String,
    pub monero_anchor_root: String,
    pub l2_settlement_root: String,
    pub settled_at_height: u64,
}

impl IssueSettlementReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "bond_id": self.bond_id,
            "settlement_asset_id": self.settlement_asset_id,
            "input_amount_commitment_root": self.input_amount_commitment_root,
            "output_amount_commitment_root": self.output_amount_commitment_root,
            "solver_fee_commitment_root": self.solver_fee_commitment_root,
            "sponsor_credit_id": self.sponsor_credit_id,
            "cross_asset_rate_root": self.cross_asset_rate_root,
            "monero_anchor_root": self.monero_anchor_root,
            "l2_settlement_root": self.l2_settlement_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineSubjectRequest {
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub affected_nullifier_hashes: BTreeSet<String>,
    pub started_at_height: u64,
}

impl QuarantineSubjectRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "subject_id": self.subject_id,
            "reason": self.reason.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "affected_nullifier_hashes": self.affected_nullifier_hashes,
            "started_at_height": self.started_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllocatePrivacyRedactionBudgetRequest {
    pub epoch: u64,
    pub vault_id: String,
    pub viewer_commitment: String,
    pub allowed_redactions: u64,
    pub consumed_redactions: u64,
    pub redaction_policy_root: String,
    pub audit_transcript_root: String,
}

impl AllocatePrivacyRedactionBudgetRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "vault_id": self.vault_id,
            "viewer_commitment": self.viewer_commitment,
            "allowed_redactions": self.allowed_redactions,
            "consumed_redactions": self.consumed_redactions,
            "redaction_policy_root": self.redaction_policy_root,
            "audit_transcript_root": self.audit_transcript_root,
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let vault_id = state
        .register_vault(RegisterVaultRequest {
            kind: EscrowVaultKind::SpotSwap,
            operator_commitment: demo_commitment("operator", 1),
            base_asset_id: DEFAULT_WRAPPED_XMR_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
            vault_commitment_root: demo_root("vault-commitment", 1),
            token_inventory_root: demo_root("token-inventory", 1),
            allowed_solver_set_root: demo_root("solver-set", 1),
            privacy_policy_root: demo_root("privacy-policy", 1),
            fee_cap_bps: 10,
            opened_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet vault fixture is valid");
    let intent_id = state
        .submit_sealed_intent(SubmitSealedIntentRequest {
            vault_id: vault_id.clone(),
            kind: IntentKind::SwapExactIn,
            maker_commitment: demo_commitment("maker", 1),
            input_asset_id: DEFAULT_WRAPPED_XMR_ASSET_ID.to_string(),
            output_asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
            sealed_input_root: demo_root("sealed-input", 1),
            sealed_output_root: demo_root("sealed-output", 1),
            price_limit_commitment_root: demo_root("price-limit", 1),
            route_constraint_root: demo_root("route-constraint", 1),
            nullifier_hash: demo_root("intent-nullifier", 1),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            fee_cap_bps: 8,
            solver_fee_cap_bps: 6,
            submitted_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet sealed intent fixture is valid");
    let bond_id = state
        .post_solver_bond(PostSolverBondRequest {
            intent_id: intent_id.clone(),
            solver_commitment: demo_commitment("solver", 1),
            bond_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bond_amount_piconero: DEFAULT_MIN_SOLVER_BOND_PICONERO * 2,
            fill_quote_root: demo_root("fill-quote", 1),
            slashing_condition_root: demo_root("slashing-condition", 1),
            posted_at_height: DEVNET_HEIGHT + 2,
        })
        .expect("devnet solver bond fixture is valid");
    state
        .record_pq_authorization(RecordPqAuthorizationRequest {
            subject_id: intent_id.clone(),
            kind: PqAttestationKind::UserIntent,
            signer_commitment: demo_commitment("pq-signer", 1),
            pq_public_key_root: demo_root("pq-public-key", 1),
            pq_signature_root: demo_root("pq-signature", 1),
            authorization_scope_root: demo_root("auth-scope", 1),
            transcript_root: demo_root("auth-transcript", 1),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attested_at_height: DEVNET_HEIGHT + 3,
        })
        .expect("devnet PQ authorization fixture is valid");
    let sponsor_credit_id = state
        .reserve_sponsor_credit(ReserveSponsorCreditRequest {
            intent_id: intent_id.clone(),
            sponsor_commitment: demo_commitment("sponsor", 1),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            credit_commitment_root: demo_root("sponsor-credit", 1),
            max_sponsor_fee_bps: 4,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            reservation_nullifier_hash: demo_root("sponsor-nullifier", 1),
            reserved_at_height: DEVNET_HEIGHT + 4,
        })
        .expect("devnet sponsor credit fixture is valid");
    let receipt_id = state
        .issue_settlement_receipt(IssueSettlementReceiptRequest {
            intent_id: intent_id.clone(),
            bond_id: bond_id.clone(),
            settlement_asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
            input_amount_commitment_root: demo_root("input-amount", 1),
            output_amount_commitment_root: demo_root("output-amount", 1),
            solver_fee_commitment_root: demo_root("solver-fee", 1),
            sponsor_credit_id: Some(sponsor_credit_id),
            cross_asset_rate_root: demo_root("cross-asset-rate", 1),
            monero_anchor_root: demo_root("monero-anchor", 1),
            l2_settlement_root: demo_root("l2-settlement", 1),
            settled_at_height: DEVNET_HEIGHT + 5,
        })
        .expect("devnet settlement receipt fixture is valid");
    state
        .allocate_privacy_redaction_budget(AllocatePrivacyRedactionBudgetRequest {
            epoch: DEVNET_HEIGHT / 720,
            vault_id: vault_id.clone(),
            viewer_commitment: demo_commitment("viewing-auditor", 1),
            allowed_redactions: 8,
            consumed_redactions: 2,
            redaction_policy_root: demo_root("redaction-policy", 1),
            audit_transcript_root: demo_root("redaction-audit", 1),
        })
        .expect("devnet redaction budget fixture is valid");
    state
        .add_devnet_fixture(DevnetFixture {
            fixture_id: demo_root("fixture", 1),
            label: "devnet-wxmr-to-private-dusd-sponsored-fill".to_string(),
            vault_id,
            intent_ids: vec![intent_id],
            settlement_receipt_ids: vec![receipt_id],
            fixture_root: demo_root("fixture-root", 1),
            created_at_height: DEVNET_HEIGHT + 6,
        })
        .expect("devnet fixture record is valid");
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let vault_id = state
        .register_vault(RegisterVaultRequest {
            kind: EscrowVaultKind::CollateralRebalance,
            operator_commitment: demo_commitment("operator", 2),
            base_asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_WRAPPED_XMR_ASSET_ID.to_string(),
            vault_commitment_root: demo_root("vault-commitment", 2),
            token_inventory_root: demo_root("token-inventory", 2),
            allowed_solver_set_root: demo_root("solver-set", 2),
            privacy_policy_root: demo_root("privacy-policy", 2),
            fee_cap_bps: 12,
            opened_at_height: DEVNET_HEIGHT + 20,
        })
        .expect("demo vault fixture is valid");
    let intent_id = state
        .submit_sealed_intent(SubmitSealedIntentRequest {
            vault_id: vault_id.clone(),
            kind: IntentKind::CollateralMove,
            maker_commitment: demo_commitment("maker", 2),
            input_asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
            output_asset_id: DEFAULT_WRAPPED_XMR_ASSET_ID.to_string(),
            sealed_input_root: demo_root("sealed-input", 2),
            sealed_output_root: demo_root("sealed-output", 2),
            price_limit_commitment_root: demo_root("price-limit", 2),
            route_constraint_root: demo_root("route-constraint", 2),
            nullifier_hash: demo_root("intent-nullifier", 2),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            fee_cap_bps: 9,
            solver_fee_cap_bps: 6,
            submitted_at_height: DEVNET_HEIGHT + 21,
        })
        .expect("demo sealed intent fixture is valid");
    let mut affected_nullifiers = BTreeSet::new();
    affected_nullifiers.insert(demo_root("intent-nullifier", 2));
    state
        .quarantine_subject(QuarantineSubjectRequest {
            subject_id: intent_id.clone(),
            reason: QuarantineReason::WatchtowerAbuseReport,
            reporter_commitment: demo_commitment("watchtower", 1),
            evidence_root: demo_root("watchtower-evidence", 1),
            affected_nullifier_hashes: affected_nullifiers,
            started_at_height: DEVNET_HEIGHT + 22,
        })
        .expect("demo quarantine fixture is valid");
    state
        .add_devnet_fixture(DevnetFixture {
            fixture_id: demo_root("fixture", 2),
            label: "demo-quarantined-collateral-rebalance-intent".to_string(),
            vault_id,
            intent_ids: vec![intent_id],
            settlement_receipt_ids: Vec::new(),
            fixture_root: demo_root("fixture-root", 2),
            created_at_height: DEVNET_HEIGHT + 23,
        })
        .expect("demo fixture record is valid");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_confidential_tokenized_intent_escrow_runtime_state_root_from_record(
    record: &Value,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-INTENT-ESCROW-RUNTIME-STATE-ROOT",
        record,
    )
}

pub fn vault_id(request: &RegisterVaultRequest, counter: u64) -> String {
    id_from_record("VAULT-ID", counter, &request.public_record())
}

pub fn sealed_intent_id(request: &SubmitSealedIntentRequest, counter: u64) -> String {
    id_from_record("SEALED-INTENT-ID", counter, &request.public_record())
}

pub fn solver_bond_id(request: &PostSolverBondRequest, counter: u64) -> String {
    id_from_record("SOLVER-BOND-ID", counter, &request.public_record())
}

pub fn pq_authorization_attestation_id(
    request: &RecordPqAuthorizationRequest,
    counter: u64,
) -> String {
    id_from_record(
        "PQ-AUTHORIZATION-ATTESTATION-ID",
        counter,
        &request.public_record(),
    )
}

pub fn sponsor_credit_id(request: &ReserveSponsorCreditRequest, counter: u64) -> String {
    id_from_record("SPONSOR-CREDIT-ID", counter, &request.public_record())
}

pub fn settlement_receipt_id(request: &IssueSettlementReceiptRequest, counter: u64) -> String {
    id_from_record("SETTLEMENT-RECEIPT-ID", counter, &request.public_record())
}

pub fn abuse_quarantine_id(request: &QuarantineSubjectRequest, counter: u64) -> String {
    id_from_record("ABUSE-QUARANTINE-ID", counter, &request.public_record())
}

pub fn privacy_redaction_budget_id(
    request: &AllocatePrivacyRedactionBudgetRequest,
    counter: u64,
) -> String {
    id_from_record(
        "PRIVACY-REDACTION-BUDGET-ID",
        counter,
        &request.public_record(),
    )
}

pub fn id_from_record(label: &str, counter: u64, record: &Value) -> String {
    root_from_record(
        &format!("PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-{label}"),
        &json!({
            "counter": counter,
            "record": record,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INTENT_ESCROW_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(payload_root(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

pub fn demo_root(label: &str, index: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-DEMO-ROOT",
        &json!({
            "label": label,
            "index": index,
        }),
    )
}

pub fn demo_commitment(label: &str, index: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-TOKENIZED-INTENT-ESCROW-DEMO-COMMITMENT",
        &json!({
            "label": label,
            "index": index,
        }),
    )
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("tokenized intent escrow {label} is required"));
    }
    Ok(())
}

fn require_fee_bps(
    fee_bps: u64,
    max_bps: u64,
    label: &str,
) -> PrivateL2PqConfidentialTokenizedIntentEscrowRuntimeResult<()> {
    if fee_bps > max_bps || fee_bps > MAX_BPS {
        return Err(format!("tokenized intent escrow {label} exceeds fee cap"));
    }
    Ok(())
}
