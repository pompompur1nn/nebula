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
    "nebula-private-l2-confidential-token-batch-mint-burn-netting-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_246_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFIDENTIAL_PROOF_SUITE: &str = "confidential-token-batch-mint-burn-balance-proof-v1";
pub const PRIVACY_FENCE_SUITE: &str = "private-l2-token-nullifier-fence-and-note-commitment-set-v1";
pub const COMPLIANCE_ATTESTATION_SUITE: &str =
    "selective-disclosure-compliance-attestation-for-confidential-token-v1";
pub const SPONSOR_RESERVATION_SUITE: &str = "low-fee-token-batch-sponsor-reservation-v1";
pub const SETTLEMENT_RECEIPT_SUITE: &str =
    "confidential-token-netted-mint-burn-settlement-receipt-v1";
pub const FEE_REBATE_SUITE: &str = "low-fee-confidential-token-batch-rebate-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BRIDGE_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET: u64 = 262_144;
pub const DEFAULT_MIN_BATCH_ITEMS: u64 = 4;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_SPONSOR_DISCOUNT_BPS: u64 = 9;
pub const DEFAULT_REBATE_BPS: u64 = 7;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 28;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_NULLIFIER_GRACE_BLOCKS: u64 = 2_880;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_TOKEN_CLASSES: usize = 262_144;
pub const MAX_BATCHES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const MAX_SETTLEMENT_RECEIPTS: usize = 2_097_152;
pub const MAX_FEE_REBATES: usize = 2_097_152;
pub const MAX_PRIVACY_FENCES: usize = 4_194_304;
pub const MAX_NULLIFIERS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClassKind {
    ConfidentialIssuedToken,
    RedeemableReceipt,
    BridgedAsset,
    WrappedMonero,
    StableAsset,
    VaultShare,
    LpReceipt,
    RebateCredit,
    GovernanceNote,
    SyntheticClaim,
}

impl TokenClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialIssuedToken => "confidential_issued_token",
            Self::RedeemableReceipt => "redeemable_receipt",
            Self::BridgedAsset => "bridged_asset",
            Self::WrappedMonero => "wrapped_monero",
            Self::StableAsset => "stable_asset",
            Self::VaultShare => "vault_share",
            Self::LpReceipt => "lp_receipt",
            Self::RebateCredit => "rebate_credit",
            Self::GovernanceNote => "governance_note",
            Self::SyntheticClaim => "synthetic_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchOperationKind {
    Mint,
    Burn,
    MintAndBurnNet,
    BridgeMint,
    BridgeBurn,
    RedemptionBurn,
    IssuerRebalance,
    SponsorRebate,
}

impl BatchOperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::MintAndBurnNet => "mint_and_burn_net",
            Self::BridgeMint => "bridge_mint",
            Self::BridgeBurn => "bridge_burn",
            Self::RedemptionBurn => "redemption_burn",
            Self::IssuerRebalance => "issuer_rebalance",
            Self::SponsorRebate => "sponsor_rebate",
        }
    }

    pub fn requires_bridge(self) -> bool {
        matches!(self, Self::BridgeMint | Self::BridgeBurn)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchLane {
    SponsoredLowFee,
    RetailLowFee,
    DefiBulk,
    Bridge,
    Redemption,
    Emergency,
}

impl BatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::RetailLowFee => "retail_low_fee",
            Self::DefiBulk => "defi_bulk",
            Self::Bridge => "bridge",
            Self::Redemption => "redemption",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.target_user_fee_bps.saturating_sub(2),
            Self::RetailLowFee => config.target_user_fee_bps,
            Self::DefiBulk => config.target_user_fee_bps.saturating_add(2),
            Self::Bridge | Self::Redemption => config.max_user_fee_bps,
            Self::Emergency => config.max_user_fee_bps.saturating_mul(2).min(MAX_BPS),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClassStatus {
    Draft,
    Attested,
    Active,
    Paused,
    RedemptionOnly,
    Retired,
}

impl TokenClassStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::RedemptionOnly => "redemption_only",
            Self::Retired => "retired",
        }
    }

    pub fn permits_mint(self) -> bool {
        matches!(self, Self::Active | Self::Attested)
    }

    pub fn permits_burn(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Attested | Self::RedemptionOnly | Self::Paused
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    PrivacyFenced,
    ComplianceAttested,
    SponsorReserved,
    Netted,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PrivacyFenced => "privacy_fenced",
            Self::ComplianceAttested => "compliance_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::PrivacyFenced
                | Self::ComplianceAttested
                | Self::SponsorReserved
                | Self::Netted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    IssuerAuthorization,
    ReserveBacking,
    SanctionsScreen,
    JurisdictionPolicy,
    TravelRuleEnvelope,
    DefiRiskLimit,
    BridgeReserveLock,
    RedemptionWindow,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IssuerAuthorization => "issuer_authorization",
            Self::ReserveBacking => "reserve_backing",
            Self::SanctionsScreen => "sanctions_screen",
            Self::JurisdictionPolicy => "jurisdiction_policy",
            Self::TravelRuleEnvelope => "travel_rule_envelope",
            Self::DefiRiskLimit => "defi_risk_limit",
            Self::BridgeReserveLock => "bridge_reserve_lock",
            Self::RedemptionWindow => "redemption_window",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Allow,
    AllowWithDisclosure,
    Watch,
    Hold,
    Reject,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowWithDisclosure => "allow_with_disclosure",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }

    pub fn permits_settlement(self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithDisclosure)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Attached,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Attached => "attached",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Mint,
    Burn,
    NetSettlement,
    BridgeLock,
    BridgeRelease,
    Redemption,
    Rebate,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::NetSettlement => "net_settlement",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::Redemption => "redemption",
            Self::Rebate => "rebate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    SponsorSubsidy,
    BatchCompression,
    NettingSurplus,
    ProofReuse,
    BridgeAggregation,
    PrivacySetContribution,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorSubsidy => "sponsor_subsidy",
            Self::BatchCompression => "batch_compression",
            Self::NettingSurplus => "netting_surplus",
            Self::ProofReuse => "proof_reuse",
            Self::BridgeAggregation => "bridge_aggregation",
            Self::PrivacySetContribution => "privacy_set_contribution",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    InputNullifier,
    OutputCommitment,
    IssuerFence,
    BridgeFence,
    SponsorFence,
    ComplianceFence,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InputNullifier => "input_nullifier",
            Self::OutputCommitment => "output_commitment",
            Self::IssuerFence => "issuer_fence",
            Self::BridgeFence => "bridge_fence",
            Self::SponsorFence => "sponsor_fence",
            Self::ComplianceFence => "compliance_fence",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub bridge_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub confidential_proof_suite: String,
    pub privacy_fence_suite: String,
    pub compliance_attestation_suite: String,
    pub sponsor_reservation_suite: String,
    pub settlement_receipt_suite: String,
    pub fee_rebate_suite: String,
    pub min_privacy_set: u64,
    pub target_privacy_set: u64,
    pub min_batch_items: u64,
    pub max_batch_items: usize,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub sponsor_discount_bps: u64,
    pub rebate_bps: u64,
    pub reservation_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub nullifier_grace_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            bridge_network: DEFAULT_BRIDGE_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            confidential_proof_suite: CONFIDENTIAL_PROOF_SUITE.to_string(),
            privacy_fence_suite: PRIVACY_FENCE_SUITE.to_string(),
            compliance_attestation_suite: COMPLIANCE_ATTESTATION_SUITE.to_string(),
            sponsor_reservation_suite: SPONSOR_RESERVATION_SUITE.to_string(),
            settlement_receipt_suite: SETTLEMENT_RECEIPT_SUITE.to_string(),
            fee_rebate_suite: FEE_REBATE_SUITE.to_string(),
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set: DEFAULT_TARGET_PRIVACY_SET,
            min_batch_items: DEFAULT_MIN_BATCH_ITEMS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            sponsor_discount_bps: DEFAULT_SPONSOR_DISCOUNT_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            nullifier_grace_blocks: DEFAULT_NULLIFIER_GRACE_BLOCKS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("bridge_network", &self.bridge_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_user_fee_bps", self.target_user_fee_bps)?;
        ensure_bps("sponsor_discount_bps", self.sponsor_discount_bps)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target_user_fee_bps exceeds max_user_fee_bps".to_string());
        }
        if self.min_privacy_set == 0 || self.target_privacy_set < self.min_privacy_set {
            return Err("target_privacy_set must be at least min_privacy_set".to_string());
        }
        if self.min_batch_items == 0 || self.max_batch_items < self.min_batch_items as usize {
            return Err("max_batch_items must be at least min_batch_items".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_batch_mint_burn_netting_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "bridge_network": self.bridge_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "confidential_proof_suite": self.confidential_proof_suite,
            "privacy_fence_suite": self.privacy_fence_suite,
            "compliance_attestation_suite": self.compliance_attestation_suite,
            "sponsor_reservation_suite": self.sponsor_reservation_suite,
            "settlement_receipt_suite": self.settlement_receipt_suite,
            "fee_rebate_suite": self.fee_rebate_suite,
            "min_privacy_set": self.min_privacy_set,
            "target_privacy_set": self.target_privacy_set,
            "min_batch_items": self.min_batch_items,
            "max_batch_items": self.max_batch_items,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "sponsor_discount_bps": self.sponsor_discount_bps,
            "rebate_bps": self.rebate_bps,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "nullifier_grace_blocks": self.nullifier_grace_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub token_classes: u64,
    pub batches: u64,
    pub attestations: u64,
    pub sponsor_reservations: u64,
    pub settlement_receipts: u64,
    pub fee_rebates: u64,
    pub privacy_fences: u64,
    pub nullifiers: u64,
    pub public_records: u64,
    pub gross_mint_amount: u128,
    pub gross_burn_amount: u128,
    pub net_mint_amount: i128,
    pub sponsored_fee_amount: u128,
    pub rebated_fee_amount: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_batch_mint_burn_netting_counters",
            "token_classes": self.token_classes,
            "batches": self.batches,
            "attestations": self.attestations,
            "sponsor_reservations": self.sponsor_reservations,
            "settlement_receipts": self.settlement_receipts,
            "fee_rebates": self.fee_rebates,
            "privacy_fences": self.privacy_fences,
            "nullifiers": self.nullifiers,
            "public_records": self.public_records,
            "gross_mint_amount": self.gross_mint_amount.to_string(),
            "gross_burn_amount": self.gross_burn_amount.to_string(),
            "net_mint_amount": self.net_mint_amount.to_string(),
            "sponsored_fee_amount": self.sponsored_fee_amount.to_string(),
            "rebated_fee_amount": self.rebated_fee_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub token_class_root: String,
    pub batch_root: String,
    pub attestation_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub fee_rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_batch_mint_burn_netting_roots",
            "token_class_root": self.token_class_root,
            "batch_root": self.batch_root,
            "attestation_root": self.attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "fee_rebate_root": self.fee_rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenClassRequest {
    pub issuer_id: String,
    pub token_symbol: String,
    pub token_class_kind: TokenClassKind,
    pub reserve_asset_id: String,
    pub bridge_domain: String,
    pub supply_cap_commitment: String,
    pub policy_root: String,
    pub decimals: u8,
    pub low_fee_enabled: bool,
}

impl TokenClassRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("issuer_id", &self.issuer_id)?;
        ensure_nonempty("token_symbol", &self.token_symbol)?;
        ensure_nonempty("reserve_asset_id", &self.reserve_asset_id)?;
        ensure_nonempty("bridge_domain", &self.bridge_domain)?;
        ensure_hash_like("supply_cap_commitment", &self.supply_cap_commitment)?;
        ensure_hash_like("policy_root", &self.policy_root)?;
        if self.decimals > 18 {
            return Err("decimals must be <= 18".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "issuer_id": self.issuer_id,
            "token_symbol": self.token_symbol,
            "token_class_kind": self.token_class_kind.as_str(),
            "reserve_asset_id": self.reserve_asset_id,
            "bridge_domain": self.bridge_domain,
            "supply_cap_commitment": self.supply_cap_commitment,
            "policy_root": self.policy_root,
            "decimals": self.decimals,
            "low_fee_enabled": self.low_fee_enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenClassRecord {
    pub token_class_id: String,
    pub request: TokenClassRequest,
    pub status: TokenClassStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl TokenClassRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_class",
            "token_class_id": self.token_class_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchNettingRequest {
    pub token_class_id: String,
    pub operation: BatchOperationKind,
    pub lane: BatchLane,
    pub batch_salt: String,
    pub input_nullifiers: Vec<String>,
    pub output_commitments: Vec<String>,
    pub mint_amount_commitment: String,
    pub burn_amount_commitment: String,
    pub net_amount: i128,
    pub gross_mint_amount: u128,
    pub gross_burn_amount: u128,
    pub proof_commitment: String,
    pub bridge_lock_id: Option<String>,
    pub redemption_window_id: Option<String>,
    pub requested_fee_bps: u64,
    pub privacy_set_size: u64,
}

impl BatchNettingRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("token_class_id", &self.token_class_id)?;
        ensure_nonempty("batch_salt", &self.batch_salt)?;
        ensure_hash_like("mint_amount_commitment", &self.mint_amount_commitment)?;
        ensure_hash_like("burn_amount_commitment", &self.burn_amount_commitment)?;
        ensure_hash_like("proof_commitment", &self.proof_commitment)?;
        ensure_bps("requested_fee_bps", self.requested_fee_bps)?;
        if self.requested_fee_bps > config.max_user_fee_bps {
            return Err("requested_fee_bps exceeds max_user_fee_bps".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("privacy_set_size below configured minimum".to_string());
        }
        let items = self.input_nullifiers.len() + self.output_commitments.len();
        if items < config.min_batch_items as usize || items > config.max_batch_items {
            return Err("batch item count outside configured bounds".to_string());
        }
        ensure_unique("input_nullifiers", &self.input_nullifiers)?;
        ensure_unique("output_commitments", &self.output_commitments)?;
        for nullifier in &self.input_nullifiers {
            ensure_hash_like("input_nullifier", nullifier)?;
        }
        for commitment in &self.output_commitments {
            ensure_hash_like("output_commitment", commitment)?;
        }
        if self.operation.requires_bridge() && self.bridge_lock_id.is_none() {
            return Err("bridge operation requires bridge_lock_id".to_string());
        }
        let computed_net = self.gross_mint_amount as i128 - self.gross_burn_amount as i128;
        if computed_net != self.net_amount {
            return Err("net_amount must equal gross_mint_amount - gross_burn_amount".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "token_class_id": self.token_class_id,
            "operation": self.operation.as_str(),
            "lane": self.lane.as_str(),
            "batch_salt": self.batch_salt,
            "input_nullifiers": self.input_nullifiers,
            "output_commitments": self.output_commitments,
            "mint_amount_commitment": self.mint_amount_commitment,
            "burn_amount_commitment": self.burn_amount_commitment,
            "net_amount": self.net_amount.to_string(),
            "gross_mint_amount": self.gross_mint_amount.to_string(),
            "gross_burn_amount": self.gross_burn_amount.to_string(),
            "proof_commitment": self.proof_commitment,
            "bridge_lock_id": self.bridge_lock_id,
            "redemption_window_id": self.redemption_window_id,
            "requested_fee_bps": self.requested_fee_bps,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchRecord {
    pub batch_id: String,
    pub request: BatchNettingRequest,
    pub status: BatchStatus,
    pub fee_amount: u128,
    pub expires_height: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl BatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_batch",
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "fee_amount": self.fee_amount.to_string(),
            "expires_height": self.expires_height,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceAttestationRequest {
    pub batch_id: String,
    pub token_class_id: String,
    pub attestation_kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub attester_id: String,
    pub policy_root: String,
    pub disclosure_root: String,
    pub expires_height: u64,
}

impl ComplianceAttestationRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("token_class_id", &self.token_class_id)?;
        ensure_nonempty("attester_id", &self.attester_id)?;
        ensure_hash_like("policy_root", &self.policy_root)?;
        ensure_hash_like("disclosure_root", &self.disclosure_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "token_class_id": self.token_class_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "verdict": self.verdict.as_str(),
            "attester_id": self.attester_id,
            "policy_root": self.policy_root,
            "disclosure_root": self.disclosure_root,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceAttestationRecord {
    pub attestation_id: String,
    pub request: ComplianceAttestationRequest,
    pub created_height: u64,
}

impl ComplianceAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_compliance_attestation",
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservationRequest {
    pub sponsor_id: String,
    pub batch_id: String,
    pub token_class_id: String,
    pub max_fee_amount: u128,
    pub reserved_fee_commitment: String,
    pub discount_bps: u64,
    pub expires_height: u64,
}

impl SponsorReservationRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("sponsor_id", &self.sponsor_id)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("token_class_id", &self.token_class_id)?;
        ensure_hash_like("reserved_fee_commitment", &self.reserved_fee_commitment)?;
        ensure_bps("discount_bps", self.discount_bps)?;
        if self.max_fee_amount == 0 {
            return Err("max_fee_amount must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "batch_id": self.batch_id,
            "token_class_id": self.token_class_id,
            "max_fee_amount": self.max_fee_amount.to_string(),
            "reserved_fee_commitment": self.reserved_fee_commitment,
            "discount_bps": self.discount_bps,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub request: SponsorReservationRequest,
    pub status: ReservationStatus,
    pub created_height: u64,
    pub updated_height: u64,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptRequest {
    pub batch_id: String,
    pub token_class_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub reserve_delta_commitment: String,
    pub fee_paid_amount: u128,
    pub settled_height: u64,
}

impl SettlementReceiptRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("token_class_id", &self.token_class_id)?;
        ensure_hash_like("settlement_root", &self.settlement_root)?;
        ensure_hash_like("reserve_delta_commitment", &self.reserve_delta_commitment)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "token_class_id": self.token_class_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "settlement_root": self.settlement_root,
            "reserve_delta_commitment": self.reserve_delta_commitment,
            "fee_paid_amount": self.fee_paid_amount.to_string(),
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub request: SettlementReceiptRequest,
    pub created_height: u64,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_settlement_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateRequest {
    pub batch_id: String,
    pub token_class_id: String,
    pub recipient_commitment: String,
    pub rebate_reason: RebateReason,
    pub rebate_amount: u128,
    pub sponsor_id: Option<String>,
}

impl FeeRebateRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("token_class_id", &self.token_class_id)?;
        ensure_hash_like("recipient_commitment", &self.recipient_commitment)?;
        if self.rebate_amount == 0 {
            return Err("rebate_amount must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "token_class_id": self.token_class_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_reason": self.rebate_reason.as_str(),
            "rebate_amount": self.rebate_amount.to_string(),
            "sponsor_id": self.sponsor_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub request: FeeRebateRequest,
    pub created_height: u64,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_fee_rebate",
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRequest {
    pub batch_id: String,
    pub token_class_id: String,
    pub fence_kind: FenceKind,
    pub fence_commitment: String,
    pub privacy_set_root: String,
    pub effective_height: u64,
}

impl PrivacyFenceRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("token_class_id", &self.token_class_id)?;
        ensure_hash_like("fence_commitment", &self.fence_commitment)?;
        ensure_hash_like("privacy_set_root", &self.privacy_set_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "token_class_id": self.token_class_id,
            "fence_kind": self.fence_kind.as_str(),
            "fence_commitment": self.fence_commitment,
            "privacy_set_root": self.privacy_set_root,
            "effective_height": self.effective_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub request: PrivacyFenceRequest,
    pub created_height: u64,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_privacy_fence",
            "fence_id": self.fence_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRuntimeRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload: Value,
}

impl PublicRuntimeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_batch_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub token_classes: BTreeMap<String, TokenClassRecord>,
    pub batches: BTreeMap<String, BatchRecord>,
    pub attestations: BTreeMap<String, ComplianceAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub fee_rebates: BTreeMap<String, FeeRebateRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRuntimeRecord>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            token_classes: BTreeMap::new(),
            batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT)?;
        let token = TokenClassRequest {
            issuer_id: "issuer:devnet-low-fee-token-desk".to_string(),
            token_symbol: "pUSD".to_string(),
            token_class_kind: TokenClassKind::StableAsset,
            reserve_asset_id: "reserve:devnet-usdc-basket".to_string(),
            bridge_domain: DEFAULT_BRIDGE_NETWORK.to_string(),
            supply_cap_commitment: sample_hash("supply-cap"),
            policy_root: sample_hash("policy-root"),
            decimals: 6,
            low_fee_enabled: true,
        };
        let token_class_id = state.register_token_class(token, TokenClassStatus::Active)?;
        let batch = BatchNettingRequest {
            token_class_id: token_class_id.clone(),
            operation: BatchOperationKind::MintAndBurnNet,
            lane: BatchLane::SponsoredLowFee,
            batch_salt: "devnet-batch-0001".to_string(),
            input_nullifiers: vec![sample_hash("in-0"), sample_hash("in-1")],
            output_commitments: vec![sample_hash("out-0"), sample_hash("out-1")],
            mint_amount_commitment: sample_hash("mint-amount"),
            burn_amount_commitment: sample_hash("burn-amount"),
            net_amount: 750_000,
            gross_mint_amount: 1_000_000,
            gross_burn_amount: 250_000,
            proof_commitment: sample_hash("proof"),
            bridge_lock_id: None,
            redemption_window_id: Some("redemption-window:devnet:0".to_string()),
            requested_fee_bps: 3,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
        };
        let batch_id = state.propose_batch(batch)?;
        let attestation = ComplianceAttestationRequest {
            batch_id: batch_id.clone(),
            token_class_id: token_class_id.clone(),
            attestation_kind: AttestationKind::ReserveBacking,
            verdict: AttestationVerdict::Allow,
            attester_id: "attester:devnet-reserve-committee".to_string(),
            policy_root: sample_hash("attestation-policy"),
            disclosure_root: sample_hash("disclosure"),
            expires_height: state.height + DEFAULT_ATTESTATION_TTL_BLOCKS,
        };
        state.record_compliance_attestation(attestation)?;
        let reservation = SponsorReservationRequest {
            sponsor_id: "sponsor:devnet-low-fee-desk".to_string(),
            batch_id: batch_id.clone(),
            token_class_id: token_class_id.clone(),
            max_fee_amount: 100,
            reserved_fee_commitment: sample_hash("reserved-fee"),
            discount_bps: DEFAULT_SPONSOR_DISCOUNT_BPS,
            expires_height: state.height + DEFAULT_RESERVATION_TTL_BLOCKS,
        };
        state.reserve_sponsor_fee(reservation)?;
        state.install_privacy_fence(PrivacyFenceRequest {
            batch_id: batch_id.clone(),
            token_class_id: token_class_id.clone(),
            fence_kind: FenceKind::InputNullifier,
            fence_commitment: sample_hash("in-0"),
            privacy_set_root: sample_hash("privacy-set"),
            effective_height: state.height,
        })?;
        state.settle_batch(SettlementReceiptRequest {
            batch_id: batch_id.clone(),
            token_class_id,
            receipt_kind: ReceiptKind::NetSettlement,
            settlement_root: sample_hash("settlement"),
            reserve_delta_commitment: sample_hash("reserve-delta"),
            fee_paid_amount: 30,
            settled_height: state.height + 1,
        })?;
        Ok(state)
    }

    pub fn register_token_class(
        &mut self,
        request: TokenClassRequest,
        status: TokenClassStatus,
    ) -> Result<String> {
        request.validate()?;
        ensure_capacity("token_classes", self.token_classes.len(), MAX_TOKEN_CLASSES)?;
        let token_class_id = token_class_id(&request);
        if self.token_classes.contains_key(&token_class_id) {
            return Err(format!("token class already exists: {token_class_id}"));
        }
        let record = TokenClassRecord {
            token_class_id: token_class_id.clone(),
            request,
            status,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("token_class", &token_class_id, record.public_record())?;
        self.token_classes.insert(token_class_id.clone(), record);
        Ok(token_class_id)
    }

    pub fn propose_batch(&mut self, request: BatchNettingRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("batches", self.batches.len(), MAX_BATCHES)?;
        let token = self
            .token_classes
            .get(&request.token_class_id)
            .ok_or_else(|| format!("unknown token_class_id: {}", request.token_class_id))?;
        if request.gross_mint_amount > 0 && !token.status.permits_mint() {
            return Err("token class does not permit mint".to_string());
        }
        if request.gross_burn_amount > 0 && !token.status.permits_burn() {
            return Err("token class does not permit burn".to_string());
        }
        for nullifier in &request.input_nullifiers {
            if self.nullifiers.contains(nullifier) {
                return Err(format!("nullifier already spent: {nullifier}"));
            }
        }
        let batch_id = batch_id(&request);
        if self.batches.contains_key(&batch_id) {
            return Err(format!("batch already exists: {batch_id}"));
        }
        let fee_amount = fee_amount_for(&request, &self.config);
        let record = BatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: BatchStatus::Proposed,
            fee_amount,
            expires_height: self.height + self.config.batch_ttl_blocks,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish("batch", &batch_id, record.public_record())?;
        self.batches.insert(batch_id.clone(), record);
        Ok(batch_id)
    }

    pub fn record_compliance_attestation(
        &mut self,
        request: ComplianceAttestationRequest,
    ) -> Result<String> {
        request.validate()?;
        ensure_capacity("attestations", self.attestations.len(), MAX_ATTESTATIONS)?;
        let attestation_id = attestation_id(&request);
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation already exists: {attestation_id}"));
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("unknown batch_id: {}", request.batch_id))?;
        if batch.request.token_class_id != request.token_class_id {
            return Err("attestation token_class_id does not match batch".to_string());
        }
        if !request.verdict.permits_settlement() {
            batch.status = BatchStatus::Rejected;
        } else if batch.status == BatchStatus::Proposed
            || batch.status == BatchStatus::PrivacyFenced
        {
            batch.status = BatchStatus::ComplianceAttested;
        }
        batch.updated_height = self.height;
        let record = ComplianceAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("attestation", &attestation_id, record.public_record())?;
        self.attestations.insert(attestation_id.clone(), record);
        Ok(attestation_id)
    }

    pub fn reserve_sponsor_fee(&mut self, request: SponsorReservationRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            MAX_SPONSOR_RESERVATIONS,
        )?;
        let reservation_id = sponsor_reservation_id(&request);
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err(format!(
                "sponsor reservation already exists: {reservation_id}"
            ));
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("unknown batch_id: {}", request.batch_id))?;
        if batch.request.token_class_id != request.token_class_id {
            return Err("reservation token_class_id does not match batch".to_string());
        }
        if request.max_fee_amount < batch.fee_amount {
            return Err("max_fee_amount below batch fee amount".to_string());
        }
        batch.status = BatchStatus::SponsorReserved;
        batch.updated_height = self.height;
        let record = SponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Attached,
            created_height: self.height,
            updated_height: self.height,
        };
        self.publish(
            "sponsor_reservation",
            &reservation_id,
            record.public_record(),
        )?;
        self.sponsor_reservations
            .insert(reservation_id.clone(), record);
        Ok(reservation_id)
    }

    pub fn install_privacy_fence(&mut self, request: PrivacyFenceRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            MAX_PRIVACY_FENCES,
        )?;
        let fence_id = privacy_fence_id(&request);
        if self.privacy_fences.contains_key(&fence_id) {
            return Err(format!("privacy fence already exists: {fence_id}"));
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("unknown batch_id: {}", request.batch_id))?;
        if batch.request.token_class_id != request.token_class_id {
            return Err("privacy fence token_class_id does not match batch".to_string());
        }
        if matches!(request.fence_kind, FenceKind::InputNullifier) {
            ensure_capacity("nullifiers", self.nullifiers.len(), MAX_NULLIFIERS)?;
            if !batch
                .request
                .input_nullifiers
                .iter()
                .any(|nullifier| nullifier == &request.fence_commitment)
            {
                return Err("input nullifier fence is not part of batch".to_string());
            }
            if self.nullifiers.contains(&request.fence_commitment) {
                return Err("input nullifier already fenced".to_string());
            }
            self.nullifiers.insert(request.fence_commitment.clone());
        }
        if batch.status == BatchStatus::Proposed {
            batch.status = BatchStatus::PrivacyFenced;
        }
        batch.updated_height = self.height;
        let record = PrivacyFenceRecord {
            fence_id: fence_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("privacy_fence", &fence_id, record.public_record())?;
        self.privacy_fences.insert(fence_id.clone(), record);
        Ok(fence_id)
    }

    pub fn settle_batch(&mut self, request: SettlementReceiptRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity(
            "settlement_receipts",
            self.settlement_receipts.len(),
            MAX_SETTLEMENT_RECEIPTS,
        )?;
        let receipt_id = settlement_receipt_id(&request);
        if self.settlement_receipts.contains_key(&receipt_id) {
            return Err(format!("settlement receipt already exists: {receipt_id}"));
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("unknown batch_id: {}", request.batch_id))?;
        if batch.request.token_class_id != request.token_class_id {
            return Err("receipt token_class_id does not match batch".to_string());
        }
        if !batch.status.is_live() {
            return Err("batch is not live for settlement".to_string());
        }
        batch.status = BatchStatus::Settled;
        batch.updated_height = request.settled_height;
        self.height = self.height.max(request.settled_height);
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("settlement_receipt", &receipt_id, record.public_record())?;
        self.settlement_receipts.insert(receipt_id.clone(), record);
        Ok(receipt_id)
    }

    pub fn record_fee_rebate(&mut self, request: FeeRebateRequest) -> Result<String> {
        request.validate()?;
        ensure_capacity("fee_rebates", self.fee_rebates.len(), MAX_FEE_REBATES)?;
        let rebate_id = fee_rebate_id(&request);
        if self.fee_rebates.contains_key(&rebate_id) {
            return Err(format!("fee rebate already exists: {rebate_id}"));
        }
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| format!("unknown batch_id: {}", request.batch_id))?;
        if batch.request.token_class_id != request.token_class_id {
            return Err("rebate token_class_id does not match batch".to_string());
        }
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            created_height: self.height,
        };
        self.publish("fee_rebate", &rebate_id, record.public_record())?;
        self.fee_rebates.insert(rebate_id.clone(), record);
        Ok(rebate_id)
    }

    pub fn counters(&self) -> Counters {
        let mut counters = Counters {
            token_classes: self.token_classes.len() as u64,
            batches: self.batches.len() as u64,
            attestations: self.attestations.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            fee_rebates: self.fee_rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            public_records: self.public_records.len() as u64,
            ..Counters::default()
        };
        for batch in self.batches.values() {
            counters.gross_mint_amount = counters
                .gross_mint_amount
                .saturating_add(batch.request.gross_mint_amount);
            counters.gross_burn_amount = counters
                .gross_burn_amount
                .saturating_add(batch.request.gross_burn_amount);
            counters.net_mint_amount = counters
                .net_mint_amount
                .saturating_add(batch.request.net_amount);
            counters.sponsored_fee_amount = counters
                .sponsored_fee_amount
                .saturating_add(batch.fee_amount);
        }
        for rebate in self.fee_rebates.values() {
            counters.rebated_fee_amount = counters
                .rebated_fee_amount
                .saturating_add(rebate.request.rebate_amount);
        }
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            token_class_root: map_root(
                "private_l2_confidential_token_batch:token_classes",
                &self.token_classes,
                TokenClassRecord::public_record,
            ),
            batch_root: map_root(
                "private_l2_confidential_token_batch:batches",
                &self.batches,
                BatchRecord::public_record,
            ),
            attestation_root: map_root(
                "private_l2_confidential_token_batch:attestations",
                &self.attestations,
                ComplianceAttestationRecord::public_record,
            ),
            sponsor_reservation_root: map_root(
                "private_l2_confidential_token_batch:sponsor_reservations",
                &self.sponsor_reservations,
                SponsorReservationRecord::public_record,
            ),
            settlement_receipt_root: map_root(
                "private_l2_confidential_token_batch:settlement_receipts",
                &self.settlement_receipts,
                SettlementReceiptRecord::public_record,
            ),
            fee_rebate_root: map_root(
                "private_l2_confidential_token_batch:fee_rebates",
                &self.fee_rebates,
                FeeRebateRecord::public_record,
            ),
            privacy_fence_root: map_root(
                "private_l2_confidential_token_batch:privacy_fences",
                &self.privacy_fences,
                PrivacyFenceRecord::public_record,
            ),
            nullifier_root: set_root(
                "private_l2_confidential_token_batch:nullifiers",
                &self.nullifiers,
            ),
            public_record_root: map_root(
                "private_l2_confidential_token_batch:public_records",
                &self.public_records,
                PublicRuntimeRecord::public_record,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_batch_mint_burn_netting_state",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn publish(&mut self, record_kind: &str, subject_id: &str, payload: Value) -> Result<()> {
        let record_id = public_record_id(record_kind, subject_id, self.height, &payload);
        if self.public_records.contains_key(&record_id) {
            return Err(format!("public record already exists: {record_id}"));
        }
        let record = PublicRuntimeRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            payload,
        };
        self.public_records.insert(record_id, record);
        Ok(())
    }
}

pub fn private_l2_confidential_token_batch_mint_burn_netting_runtime_devnet() -> Result<State> {
    State::devnet()
}

pub fn private_l2_confidential_token_batch_mint_burn_netting_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_confidential_token_batch_mint_burn_netting_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn token_class_id(request: &TokenClassRequest) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:token_class_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.issuer_id.as_str()),
            HashPart::Str(request.token_symbol.as_str()),
            HashPart::Str(request.token_class_kind.as_str()),
            HashPart::Str(request.reserve_asset_id.as_str()),
            HashPart::Str(request.policy_root.as_str()),
        ],
        32,
    )
}

pub fn batch_id(request: &BatchNettingRequest) -> String {
    let record = request.public_record();
    domain_hash(
        "private_l2_confidential_token_batch:batch_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.token_class_id.as_str()),
            HashPart::Str(request.operation.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(request.batch_salt.as_str()),
            HashPart::Json(&record),
        ],
        32,
    )
}

pub fn attestation_id(request: &ComplianceAttestationRequest) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:attestation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.batch_id.as_str()),
            HashPart::Str(request.token_class_id.as_str()),
            HashPart::Str(request.attestation_kind.as_str()),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(request.attester_id.as_str()),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &SponsorReservationRequest) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:sponsor_reservation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.sponsor_id.as_str()),
            HashPart::Str(request.batch_id.as_str()),
            HashPart::Str(request.token_class_id.as_str()),
            HashPart::Str(request.reserved_fee_commitment.as_str()),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &SettlementReceiptRequest) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:settlement_receipt_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.batch_id.as_str()),
            HashPart::Str(request.token_class_id.as_str()),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(request.settlement_root.as_str()),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}

pub fn fee_rebate_id(request: &FeeRebateRequest) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:fee_rebate_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.batch_id.as_str()),
            HashPart::Str(request.token_class_id.as_str()),
            HashPart::Str(request.recipient_commitment.as_str()),
            HashPart::Str(request.rebate_reason.as_str()),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &PrivacyFenceRequest) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:privacy_fence_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.batch_id.as_str()),
            HashPart::Str(request.token_class_id.as_str()),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(request.fence_commitment.as_str()),
            HashPart::U64(request.effective_height),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:state_root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    subject_id: &str,
    height: u64,
    payload: &Value,
) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:public_record_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn fee_amount_for(request: &BatchNettingRequest, config: &Config) -> u128 {
    let volume = request
        .gross_mint_amount
        .saturating_add(request.gross_burn_amount);
    let bps = request.requested_fee_bps.min(request.lane.fee_bps(config));
    volume.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be nonempty"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must be at least 16 characters"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
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

fn sample_hash(label: &str) -> String {
    domain_hash(
        "private_l2_confidential_token_batch:devnet_sample",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_has_stable_public_root() {
        let state = State::devnet().expect("devnet");
        assert!(!state.state_root().is_empty());
        assert_eq!(state.counters().token_classes, 1);
        assert_eq!(state.counters().settlement_receipts, 1);
    }

    #[test]
    fn duplicate_nullifier_is_rejected() {
        let mut state = State::new(Config::devnet(), DEVNET_HEIGHT).expect("state");
        let token_id = state
            .register_token_class(
                TokenClassRequest {
                    issuer_id: "issuer".to_string(),
                    token_symbol: "TST".to_string(),
                    token_class_kind: TokenClassKind::ConfidentialIssuedToken,
                    reserve_asset_id: "reserve".to_string(),
                    bridge_domain: "bridge".to_string(),
                    supply_cap_commitment: sample_hash("cap"),
                    policy_root: sample_hash("policy"),
                    decimals: 6,
                    low_fee_enabled: true,
                },
                TokenClassStatus::Active,
            )
            .expect("token");
        let request = BatchNettingRequest {
            token_class_id: token_id,
            operation: BatchOperationKind::Burn,
            lane: BatchLane::RetailLowFee,
            batch_salt: "salt".to_string(),
            input_nullifiers: vec![sample_hash("same"), sample_hash("same")],
            output_commitments: vec![sample_hash("out"), sample_hash("out-2")],
            mint_amount_commitment: sample_hash("mint"),
            burn_amount_commitment: sample_hash("burn"),
            net_amount: -1,
            gross_mint_amount: 0,
            gross_burn_amount: 1,
            proof_commitment: sample_hash("proof"),
            bridge_lock_id: None,
            redemption_window_id: None,
            requested_fee_bps: 1,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
        };
        assert!(state.propose_batch(request).is_err());
    }
}
