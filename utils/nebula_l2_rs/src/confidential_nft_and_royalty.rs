use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialNftAndRoyaltyResult<T> = Result<T, String>;

pub const CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION: &str =
    "nebula-l2-confidential-nft-and-royalty-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_SCHEMA_VERSION: u64 = 1;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_METADATA_SCHEME: &str =
    "shake256-confidential-nft-metadata-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_OWNER_COMMITMENT_SCHEME: &str =
    "devnet-private-nft-owner-commitment-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_TRANSFER_PROOF_SCHEME: &str =
    "devnet-private-nft-transfer-proof-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_ROYALTY_SCHEME: &str = "devnet-private-royalty-stream-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_MARKETPLACE_SCHEME: &str =
    "devnet-confidential-nft-marketplace-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_LENDING_HOOK_SCHEME: &str =
    "devnet-private-nft-lending-collateral-hook-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_BRIDGE_WRAP_SCHEME: &str =
    "devnet-confidential-nft-bridge-wrap-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_LOW_FEE_SCHEME: &str =
    "devnet-low-fee-nft-mint-list-transfer-sponsor-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-nft-creator-operator-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DISCLOSURE_SCHEME: &str =
    "devnet-selective-nft-disclosure-receipt-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_NULLIFIER_SCHEME: &str =
    "devnet-confidential-nft-nullifier-set-v1";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_HEIGHT: u64 = 192;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_MAX_ROYALTY_BPS: u64 = 1_500;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_MARKETPLACE_FEE_BPS: u64 = 25;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_BID_TTL_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_LISTING_TTL_BLOCKS: u64 = 2_880;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_SPONSOR_EPOCH_BLOCKS: u64 = 1_440;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_LOW_FEE_UNIT_CAP: u64 = 40_000;
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_LOW_FEE_LANE: &str = "confidential-nft-small-market";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_FEE_ASSET_ID: &str = "dnr-devnet-fee";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_CREATOR_LABEL: &str =
    "devnet-confidential-nft-creator";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_OPERATOR_LABEL: &str =
    "devnet-confidential-nft-market-operator";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_LENDING_LABEL: &str =
    "devnet-private-nft-lending-vault";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_BRIDGE_LABEL: &str = "devnet-confidential-nft-bridge";
pub const CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_SPONSOR_LABEL: &str = "devnet-low-fee-nft-paymaster";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialNftClassKind {
    Art,
    Music,
    GameAsset,
    Identity,
    AccessPass,
    DeFiPosition,
    RealWorldAsset,
    BridgeWrapped,
    ContractReceipt,
    Custom(String),
}

impl ConfidentialNftClassKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::Art => "art".to_string(),
            Self::Music => "music".to_string(),
            Self::GameAsset => "game_asset".to_string(),
            Self::Identity => "identity".to_string(),
            Self::AccessPass => "access_pass".to_string(),
            Self::DeFiPosition => "defi_position".to_string(),
            Self::RealWorldAsset => "real_world_asset".to_string(),
            Self::BridgeWrapped => "bridge_wrapped".to_string(),
            Self::ContractReceipt => "contract_receipt".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn supports_marketplace(&self) -> bool {
        !matches!(self, Self::Identity | Self::ContractReceipt)
    }

    pub fn supports_lending_collateral(&self) -> bool {
        matches!(
            self,
            Self::Art
                | Self::GameAsset
                | Self::DeFiPosition
                | Self::RealWorldAsset
                | Self::BridgeWrapped
                | Self::Custom(_)
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_nft_class_kind",
            "chain_id": CHAIN_ID,
            "class_kind": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialNftSupplyMode {
    Unique,
    FixedEdition,
    OpenEdition,
    CreatorMintBurn,
    BridgeMintBurn,
    ContractControlled,
}

impl ConfidentialNftSupplyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unique => "unique",
            Self::FixedEdition => "fixed_edition",
            Self::OpenEdition => "open_edition",
            Self::CreatorMintBurn => "creator_mint_burn",
            Self::BridgeMintBurn => "bridge_mint_burn",
            Self::ContractControlled => "contract_controlled",
        }
    }

    pub fn allows_mint(&self) -> bool {
        !matches!(self, Self::Unique)
    }

    pub fn allows_burn(&self) -> bool {
        matches!(
            self,
            Self::CreatorMintBurn | Self::BridgeMintBurn | Self::ContractControlled
        )
    }

    pub fn requires_supply_cap(&self) -> bool {
        matches!(self, Self::Unique | Self::FixedEdition)
    }

    pub fn requires_bridge_reserve(&self) -> bool {
        matches!(self, Self::BridgeMintBurn)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialNftClassStatus {
    Draft,
    Active,
    MintPaused,
    TransferPaused,
    Frozen,
    BridgeOnly,
    Retired,
}

impl ConfidentialNftClassStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::MintPaused => "mint_paused",
            Self::TransferPaused => "transfer_paused",
            Self::Frozen => "frozen",
            Self::BridgeOnly => "bridge_only",
            Self::Retired => "retired",
        }
    }

    pub fn allows_mint(&self) -> bool {
        matches!(self, Self::Active | Self::TransferPaused | Self::BridgeOnly)
    }

    pub fn allows_transfer(&self) -> bool {
        matches!(self, Self::Active | Self::MintPaused | Self::BridgeOnly)
    }

    pub fn counts_as_active(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::MintPaused | Self::TransferPaused | Self::BridgeOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialNftItemStatus {
    PendingMint,
    Held,
    Listed,
    BidLocked,
    CollateralLocked,
    BridgedOut,
    Burned,
    Frozen,
}

impl ConfidentialNftItemStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PendingMint => "pending_mint",
            Self::Held => "held",
            Self::Listed => "listed",
            Self::BidLocked => "bid_locked",
            Self::CollateralLocked => "collateral_locked",
            Self::BridgedOut => "bridged_out",
            Self::Burned => "burned",
            Self::Frozen => "frozen",
        }
    }

    pub fn counts_as_live(&self) -> bool {
        matches!(
            self,
            Self::PendingMint
                | Self::Held
                | Self::Listed
                | Self::BidLocked
                | Self::CollateralLocked
                | Self::BridgedOut
                | Self::Frozen
        )
    }

    pub fn can_transfer(&self) -> bool {
        matches!(self, Self::Held | Self::Listed | Self::BidLocked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoyaltyStreamStatus {
    Proposed,
    Active,
    Accruing,
    Paused,
    Settled,
    Revoked,
    Expired,
}

impl RoyaltyStreamStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Accruing => "accruing",
            Self::Paused => "paused",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Active | Self::Accruing | Self::Paused)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceListingStatus {
    Draft,
    Open,
    Matched,
    Settled,
    Cancelled,
    Expired,
    Disputed,
}

impl MarketplaceListingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Disputed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBidStatus {
    Submitted,
    Escrowed,
    Matched,
    Settled,
    Withdrawn,
    Rejected,
    Expired,
}

impl PrivateBidStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Escrowed => "escrowed",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Withdrawn => "withdrawn",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Submitted | Self::Escrowed | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LendingCollateralHookStatus {
    Proposed,
    Active,
    Locked,
    Liquidating,
    Released,
    Disabled,
}

impl LendingCollateralHookStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Liquidating => "liquidating",
            Self::Released => "released",
            Self::Disabled => "disabled",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::Locked | Self::Liquidating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeWrapDirection {
    DepositToL2,
    WithdrawToL1,
    Rewrap,
}

impl BridgeWrapDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DepositToL2 => "deposit_to_l2",
            Self::WithdrawToL1 => "withdraw_to_l1",
            Self::Rewrap => "rewrap",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeWrapStatus {
    Requested,
    ReserveLocked,
    Minted,
    Burned,
    Released,
    Disputed,
    Expired,
}

impl BridgeWrapStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::ReserveLocked => "reserve_locked",
            Self::Minted => "minted",
            Self::Burned => "burned",
            Self::Released => "released",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Requested | Self::ReserveLocked | Self::Minted | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeNftAction {
    Mint,
    List,
    Transfer,
    Bid,
    RoyaltySettle,
    BridgeWrap,
}

impl LowFeeNftAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::List => "list",
            Self::Transfer => "transfer",
            Self::Bid => "bid",
            Self::RoyaltySettle => "royalty_settle",
            Self::BridgeWrap => "bridge_wrap",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqNftAuthorizationScope {
    CreateClass,
    MintItem,
    TransferItem,
    ManageRoyalty,
    OperateMarketplace,
    SponsorLowFee,
    BridgeWrap,
    LendingHook,
    DiscloseView,
    EmergencyPause,
    Custom(String),
}

impl PqNftAuthorizationScope {
    pub fn as_str(&self) -> String {
        match self {
            Self::CreateClass => "create_class".to_string(),
            Self::MintItem => "mint_item".to_string(),
            Self::TransferItem => "transfer_item".to_string(),
            Self::ManageRoyalty => "manage_royalty".to_string(),
            Self::OperateMarketplace => "operate_marketplace".to_string(),
            Self::SponsorLowFee => "sponsor_low_fee".to_string(),
            Self::BridgeWrap => "bridge_wrap".to_string(),
            Self::LendingHook => "lending_hook".to_string(),
            Self::DiscloseView => "disclose_view".to_string(),
            Self::EmergencyPause => "emergency_pause".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectiveDisclosureScope {
    MetadataPreview,
    OwnershipProof,
    RoyaltyAudit,
    MarketplaceCompliance,
    LendingValuation,
    BridgeReserve,
    CreatorPolicy,
}

impl SelectiveDisclosureScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MetadataPreview => "metadata_preview",
            Self::OwnershipProof => "ownership_proof",
            Self::RoyaltyAudit => "royalty_audit",
            Self::MarketplaceCompliance => "marketplace_compliance",
            Self::LendingValuation => "lending_valuation",
            Self::BridgeReserve => "bridge_reserve",
            Self::CreatorPolicy => "creator_policy",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftAndRoyaltyConfig {
    pub schema_version: u64,
    pub metadata_scheme: String,
    pub owner_commitment_scheme: String,
    pub transfer_proof_scheme: String,
    pub royalty_scheme: String,
    pub marketplace_scheme: String,
    pub lending_hook_scheme: String,
    pub bridge_wrap_scheme: String,
    pub low_fee_scheme: String,
    pub pq_authorization_scheme: String,
    pub disclosure_scheme: String,
    pub nullifier_scheme: String,
    pub default_low_fee_lane: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub max_royalty_bps: u64,
    pub marketplace_fee_bps: u64,
    pub default_bid_ttl_blocks: u64,
    pub default_listing_ttl_blocks: u64,
    pub default_sponsor_epoch_blocks: u64,
    pub default_disclosure_ttl_blocks: u64,
    pub low_fee_unit_cap: u64,
    pub allow_bridge_wrapped_classes: bool,
    pub allow_lending_collateral_hooks: bool,
    pub require_pq_creator_authorization: bool,
}

impl Default for ConfidentialNftAndRoyaltyConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIDENTIAL_NFT_AND_ROYALTY_SCHEMA_VERSION,
            metadata_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_METADATA_SCHEME.to_string(),
            owner_commitment_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_OWNER_COMMITMENT_SCHEME
                .to_string(),
            transfer_proof_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_TRANSFER_PROOF_SCHEME.to_string(),
            royalty_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_ROYALTY_SCHEME.to_string(),
            marketplace_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_MARKETPLACE_SCHEME.to_string(),
            lending_hook_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_LENDING_HOOK_SCHEME.to_string(),
            bridge_wrap_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_BRIDGE_WRAP_SCHEME.to_string(),
            low_fee_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_LOW_FEE_SCHEME.to_string(),
            pq_authorization_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_PQ_AUTH_SCHEME.to_string(),
            disclosure_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_DISCLOSURE_SCHEME.to_string(),
            nullifier_scheme: CONFIDENTIAL_NFT_AND_ROYALTY_NULLIFIER_SCHEME.to_string(),
            default_low_fee_lane: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_LOW_FEE_LANE.to_string(),
            fee_asset_id: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: CONFIDENTIAL_NFT_AND_ROYALTY_MIN_PQ_SECURITY_BITS,
            max_royalty_bps: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_MAX_ROYALTY_BPS,
            marketplace_fee_bps: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_MARKETPLACE_FEE_BPS,
            default_bid_ttl_blocks: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_BID_TTL_BLOCKS,
            default_listing_ttl_blocks: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_LISTING_TTL_BLOCKS,
            default_sponsor_epoch_blocks: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_SPONSOR_EPOCH_BLOCKS,
            default_disclosure_ttl_blocks:
                CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            low_fee_unit_cap: CONFIDENTIAL_NFT_AND_ROYALTY_DEFAULT_LOW_FEE_UNIT_CAP,
            allow_bridge_wrapped_classes: true,
            allow_lending_collateral_hooks: true,
            require_pq_creator_authorization: true,
        }
    }
}

impl ConfidentialNftAndRoyaltyConfig {
    pub fn devnet() -> Self {
        Self {
            max_royalty_bps: 1_200,
            marketplace_fee_bps: 20,
            default_bid_ttl_blocks: 360,
            default_listing_ttl_blocks: 1_440,
            default_sponsor_epoch_blocks: 720,
            low_fee_unit_cap: 25_000,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_nft_and_royalty_config",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "schema_version": self.schema_version,
            "metadata_scheme": self.metadata_scheme,
            "owner_commitment_scheme": self.owner_commitment_scheme,
            "transfer_proof_scheme": self.transfer_proof_scheme,
            "royalty_scheme": self.royalty_scheme,
            "marketplace_scheme": self.marketplace_scheme,
            "lending_hook_scheme": self.lending_hook_scheme,
            "bridge_wrap_scheme": self.bridge_wrap_scheme,
            "low_fee_scheme": self.low_fee_scheme,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "default_low_fee_lane": self.default_low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_royalty_bps": self.max_royalty_bps,
            "marketplace_fee_bps": self.marketplace_fee_bps,
            "default_bid_ttl_blocks": self.default_bid_ttl_blocks,
            "default_listing_ttl_blocks": self.default_listing_ttl_blocks,
            "default_sponsor_epoch_blocks": self.default_sponsor_epoch_blocks,
            "default_disclosure_ttl_blocks": self.default_disclosure_ttl_blocks,
            "low_fee_unit_cap": self.low_fee_unit_cap,
            "allow_bridge_wrapped_classes": self.allow_bridge_wrapped_classes,
            "allow_lending_collateral_hooks": self.allow_lending_collateral_hooks,
            "require_pq_creator_authorization": self.require_pq_creator_authorization,
        })
    }

    pub fn config_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-CONFIG",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<()> {
        if self.schema_version != CONFIDENTIAL_NFT_AND_ROYALTY_SCHEMA_VERSION {
            return Err("confidential nft schema version mismatch".to_string());
        }
        ensure_non_empty(&self.metadata_scheme, "config metadata_scheme")?;
        ensure_non_empty(
            &self.owner_commitment_scheme,
            "config owner_commitment_scheme",
        )?;
        ensure_non_empty(&self.transfer_proof_scheme, "config transfer_proof_scheme")?;
        ensure_non_empty(&self.royalty_scheme, "config royalty_scheme")?;
        ensure_non_empty(&self.marketplace_scheme, "config marketplace_scheme")?;
        ensure_non_empty(&self.lending_hook_scheme, "config lending_hook_scheme")?;
        ensure_non_empty(&self.bridge_wrap_scheme, "config bridge_wrap_scheme")?;
        ensure_non_empty(&self.low_fee_scheme, "config low_fee_scheme")?;
        ensure_non_empty(
            &self.pq_authorization_scheme,
            "config pq_authorization_scheme",
        )?;
        ensure_non_empty(&self.disclosure_scheme, "config disclosure_scheme")?;
        ensure_non_empty(&self.nullifier_scheme, "config nullifier_scheme")?;
        ensure_non_empty(&self.default_low_fee_lane, "config default_low_fee_lane")?;
        ensure_non_empty(&self.fee_asset_id, "config fee_asset_id")?;
        if self.min_pq_security_bits < CONFIDENTIAL_NFT_AND_ROYALTY_MIN_PQ_SECURITY_BITS {
            return Err("config min_pq_security_bits below confidential nft floor".to_string());
        }
        validate_bps("config max_royalty_bps", self.max_royalty_bps)?;
        validate_bps("config marketplace_fee_bps", self.marketplace_fee_bps)?;
        if self.low_fee_unit_cap == 0 {
            return Err("config low_fee_unit_cap must be non-zero".to_string());
        }
        if self.default_bid_ttl_blocks == 0
            || self.default_listing_ttl_blocks == 0
            || self.default_sponsor_epoch_blocks == 0
            || self.default_disclosure_ttl_blocks == 0
        {
            return Err("config default TTL windows must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftCreatorPolicy {
    pub policy_id: String,
    pub creator_commitment: String,
    pub creator_pq_key_root: String,
    pub operator_key_roots: BTreeSet<String>,
    pub royalty_bps: u64,
    pub min_sale_price_commitment: String,
    pub allowed_market_roots: BTreeSet<String>,
    pub denied_transfer_roots: BTreeSet<String>,
    pub disclosure_policy_root: String,
    pub pq_rotation_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub require_transfer_authorization: bool,
    pub allow_low_fee_sponsorship: bool,
}

impl ConfidentialNftCreatorPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        creator_label: &str,
        operator_labels: &[&str],
        royalty_bps: u64,
        min_sale_price_label: &str,
        allowed_market_labels: &[&str],
        denied_transfer_labels: &[&str],
        created_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        validate_bps("creator policy royalty_bps", royalty_bps)?;
        let creator_commitment = commitment("CONFIDENTIAL-NFT-CREATOR", creator_label);
        let creator_pq_key_root = commitment("CONFIDENTIAL-NFT-CREATOR-PQ", creator_label);
        let operator_key_roots = operator_labels
            .iter()
            .map(|label| commitment("CONFIDENTIAL-NFT-OPERATOR-PQ", label))
            .collect::<BTreeSet<_>>();
        let allowed_market_roots = allowed_market_labels
            .iter()
            .map(|label| commitment("CONFIDENTIAL-NFT-MARKET", label))
            .collect::<BTreeSet<_>>();
        let denied_transfer_roots = denied_transfer_labels
            .iter()
            .map(|label| commitment("CONFIDENTIAL-NFT-DENY", label))
            .collect::<BTreeSet<_>>();
        let min_sale_price_commitment =
            commitment("CONFIDENTIAL-NFT-MIN-SALE", min_sale_price_label);
        let disclosure_policy_root =
            commitment("CONFIDENTIAL-NFT-CREATOR-DISCLOSURE", creator_label);
        let pq_rotation_root = commitment("CONFIDENTIAL-NFT-CREATOR-PQ-ROTATION", creator_label);
        let policy_id = nft_hash(
            "CONFIDENTIAL-NFT-CREATOR-POLICY-ID",
            &[
                HashPart::Str(&creator_commitment),
                HashPart::Str(&creator_pq_key_root),
                HashPart::Int(royalty_bps as i128),
                HashPart::Int(created_at_height as i128),
                HashPart::Str(&disclosure_policy_root),
            ],
        );
        Ok(Self {
            policy_id,
            creator_commitment,
            creator_pq_key_root,
            operator_key_roots,
            royalty_bps,
            min_sale_price_commitment,
            allowed_market_roots,
            denied_transfer_roots,
            disclosure_policy_root,
            pq_rotation_root,
            created_at_height,
            expires_at_height,
            require_transfer_authorization: true,
            allow_low_fee_sponsorship: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_nft_creator_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "creator_commitment": self.creator_commitment,
            "creator_pq_key_root": self.creator_pq_key_root,
            "operator_key_roots": self.operator_key_roots,
            "royalty_bps": self.royalty_bps,
            "min_sale_price_commitment": self.min_sale_price_commitment,
            "allowed_market_roots": self.allowed_market_roots,
            "denied_transfer_roots": self.denied_transfer_roots,
            "disclosure_policy_root": self.disclosure_policy_root,
            "pq_rotation_root": self.pq_rotation_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "require_transfer_authorization": self.require_transfer_authorization,
            "allow_low_fee_sponsorship": self.allow_low_fee_sponsorship,
        })
    }

    pub fn policy_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-CREATOR-POLICY",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.created_at_height <= height && height < self.expires_at_height
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.policy_id, "creator policy id")?;
        ensure_non_empty(&self.creator_commitment, "creator policy creator")?;
        ensure_non_empty(&self.creator_pq_key_root, "creator policy pq root")?;
        ensure_non_empty(
            &self.min_sale_price_commitment,
            "creator policy min sale commitment",
        )?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "creator policy disclosure root",
        )?;
        ensure_non_empty(&self.pq_rotation_root, "creator policy pq rotation root")?;
        validate_bps("creator policy royalty_bps", self.royalty_bps)?;
        if self.operator_key_roots.is_empty() {
            return Err("creator policy must expose at least one operator key root".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("creator policy expiry must be after creation".to_string());
        }
        let expected = nft_hash(
            "CONFIDENTIAL-NFT-CREATOR-POLICY-ID",
            &[
                HashPart::Str(&self.creator_commitment),
                HashPart::Str(&self.creator_pq_key_root),
                HashPart::Int(self.royalty_bps as i128),
                HashPart::Int(self.created_at_height as i128),
                HashPart::Str(&self.disclosure_policy_root),
            ],
        );
        if self.policy_id != expected {
            return Err("creator policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftClass {
    pub class_id: String,
    pub symbol_commitment: String,
    pub display_name_commitment: String,
    pub metadata_root: String,
    pub class_kind: ConfidentialNftClassKind,
    pub supply_mode: ConfidentialNftSupplyMode,
    pub creator_policy_id: String,
    pub creator_policy_root: String,
    pub mint_authorization_root: String,
    pub transfer_policy_root: String,
    pub royalty_policy_root: String,
    pub marketplace_policy_root: String,
    pub lending_policy_root: String,
    pub bridge_policy_root: String,
    pub disclosure_policy_root: String,
    pub item_commitment_root: String,
    pub max_supply: u64,
    pub minted_count: u64,
    pub burned_count: u64,
    pub status: ConfidentialNftClassStatus,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ConfidentialNftClass {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol: &str,
        display_name: &str,
        class_kind: ConfidentialNftClassKind,
        supply_mode: ConfidentialNftSupplyMode,
        creator_policy: &ConfidentialNftCreatorPolicy,
        metadata: &Value,
        max_supply: u64,
        created_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(symbol, "nft class symbol")?;
        ensure_non_empty(display_name, "nft class display name")?;
        if supply_mode.requires_supply_cap() && max_supply == 0 {
            return Err("fixed nft class max_supply must be non-zero".to_string());
        }
        let symbol_commitment = commitment("CONFIDENTIAL-NFT-SYMBOL", symbol);
        let display_name_commitment = commitment("CONFIDENTIAL-NFT-DISPLAY", display_name);
        let metadata_root = json_root("CONFIDENTIAL-NFT-METADATA", metadata);
        let class_kind_label = class_kind.as_str();
        let class_id = nft_hash(
            "CONFIDENTIAL-NFT-CLASS-ID",
            &[
                HashPart::Str(&symbol_commitment),
                HashPart::Str(&display_name_commitment),
                HashPart::Str(&class_kind_label),
                HashPart::Str(supply_mode.as_str()),
                HashPart::Str(&creator_policy.policy_root()),
                HashPart::Str(&metadata_root),
                HashPart::Int(created_at_height as i128),
            ],
        );
        let mint_authorization_root = commitment(
            "CONFIDENTIAL-NFT-MINT-AUTH",
            &format!("{symbol}:{created_at_height}"),
        );
        let transfer_policy_root = commitment("CONFIDENTIAL-NFT-TRANSFER-POLICY", &class_id);
        let royalty_policy_root =
            commitment("CONFIDENTIAL-NFT-ROYALTY-POLICY", &creator_policy.policy_id);
        let marketplace_policy_root = commitment("CONFIDENTIAL-NFT-MARKETPLACE-POLICY", &class_id);
        let lending_policy_root = commitment("CONFIDENTIAL-NFT-LENDING-POLICY", &class_id);
        let bridge_policy_root = commitment("CONFIDENTIAL-NFT-BRIDGE-POLICY", &class_id);
        let disclosure_policy_root = commitment("CONFIDENTIAL-NFT-DISCLOSURE-POLICY", &class_id);
        let item_commitment_root = empty_root("CONFIDENTIAL-NFT-CLASS-ITEMS");
        Ok(Self {
            class_id,
            symbol_commitment,
            display_name_commitment,
            metadata_root,
            class_kind,
            supply_mode,
            creator_policy_id: creator_policy.policy_id.clone(),
            creator_policy_root: creator_policy.policy_root(),
            mint_authorization_root,
            transfer_policy_root,
            royalty_policy_root,
            marketplace_policy_root,
            lending_policy_root,
            bridge_policy_root,
            disclosure_policy_root,
            item_commitment_root,
            max_supply,
            minted_count: 0,
            burned_count: 0,
            status: ConfidentialNftClassStatus::Draft,
            created_at_height,
            updated_at_height: created_at_height,
        })
    }

    pub fn activate(&mut self, height: u64) {
        self.status = ConfidentialNftClassStatus::Active;
        self.updated_at_height = height;
    }

    pub fn update_item_root(&mut self, item_roots: &[String], height: u64) {
        self.item_commitment_root = merkle_from_strings("CONFIDENTIAL-NFT-CLASS-ITEMS", item_roots);
        self.updated_at_height = height;
    }

    pub fn available_supply(&self) -> u64 {
        if self.max_supply == 0 {
            u64::MAX
        } else {
            self.max_supply.saturating_sub(self.minted_count)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_nft_class",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "class_id": self.class_id,
            "symbol_commitment": self.symbol_commitment,
            "display_name_commitment": self.display_name_commitment,
            "metadata_root": self.metadata_root,
            "class_kind": self.class_kind.as_str(),
            "supply_mode": self.supply_mode.as_str(),
            "creator_policy_id": self.creator_policy_id,
            "creator_policy_root": self.creator_policy_root,
            "mint_authorization_root": self.mint_authorization_root,
            "transfer_policy_root": self.transfer_policy_root,
            "royalty_policy_root": self.royalty_policy_root,
            "marketplace_policy_root": self.marketplace_policy_root,
            "lending_policy_root": self.lending_policy_root,
            "bridge_policy_root": self.bridge_policy_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "item_commitment_root": self.item_commitment_root,
            "max_supply": self.max_supply,
            "minted_count": self.minted_count,
            "burned_count": self.burned_count,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn class_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-CLASS",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.class_id, "nft class id")?;
        ensure_non_empty(&self.symbol_commitment, "nft class symbol commitment")?;
        ensure_non_empty(
            &self.display_name_commitment,
            "nft class display commitment",
        )?;
        ensure_non_empty(&self.metadata_root, "nft class metadata root")?;
        ensure_non_empty(&self.creator_policy_id, "nft class creator policy id")?;
        ensure_non_empty(&self.creator_policy_root, "nft class creator policy root")?;
        ensure_non_empty(
            &self.mint_authorization_root,
            "nft class mint authorization root",
        )?;
        ensure_non_empty(&self.transfer_policy_root, "nft class transfer policy root")?;
        ensure_non_empty(&self.royalty_policy_root, "nft class royalty policy root")?;
        ensure_non_empty(
            &self.marketplace_policy_root,
            "nft class marketplace policy root",
        )?;
        ensure_non_empty(&self.disclosure_policy_root, "nft class disclosure root")?;
        if self.supply_mode.requires_supply_cap() && self.max_supply == 0 {
            return Err("nft class fixed supply mode requires max_supply".to_string());
        }
        if self.max_supply > 0 && self.minted_count > self.max_supply {
            return Err("nft class minted_count exceeds max_supply".to_string());
        }
        if self.burned_count > self.minted_count {
            return Err("nft class burned_count exceeds minted_count".to_string());
        }
        if self.updated_at_height < self.created_at_height {
            return Err("nft class updated height before creation".to_string());
        }
        Ok(self.class_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftItem {
    pub item_id: String,
    pub class_id: String,
    pub serial_commitment: String,
    pub metadata_commitment_root: String,
    pub owner_commitment: String,
    pub view_tag_root: String,
    pub encrypted_note_root: String,
    pub transfer_policy_root: String,
    pub royalty_stream_id: String,
    pub royalty_stream_root: String,
    pub current_nullifier_root: String,
    pub spend_root: String,
    pub collateral_hook_id: Option<String>,
    pub bridge_wrap_id: Option<String>,
    pub listing_id: Option<String>,
    pub status: ConfidentialNftItemStatus,
    pub minted_at_height: u64,
    pub last_updated_height: u64,
}

impl ConfidentialNftItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: &ConfidentialNftClass,
        serial_label: &str,
        owner_label: &str,
        metadata: &Value,
        royalty_stream_id: &str,
        royalty_stream_root: &str,
        minted_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(serial_label, "nft item serial")?;
        ensure_non_empty(owner_label, "nft item owner")?;
        let serial_commitment = commitment("CONFIDENTIAL-NFT-SERIAL", serial_label);
        let metadata_commitment_root = json_root("CONFIDENTIAL-NFT-ITEM-METADATA", metadata);
        let owner_commitment = commitment("CONFIDENTIAL-NFT-OWNER", owner_label);
        let view_tag_root = commitment("CONFIDENTIAL-NFT-VIEW-TAG", owner_label);
        let encrypted_note_root = commitment("CONFIDENTIAL-NFT-NOTE", serial_label);
        let transfer_policy_root = commitment("CONFIDENTIAL-NFT-ITEM-TRANSFER", serial_label);
        let current_nullifier_root = commitment(
            "CONFIDENTIAL-NFT-NULLIFIER",
            &format!("{owner_label}:{serial_label}"),
        );
        let spend_root = commitment("CONFIDENTIAL-NFT-SPEND", serial_label);
        let item_id = nft_hash(
            "CONFIDENTIAL-NFT-ITEM-ID",
            &[
                HashPart::Str(&class.class_id),
                HashPart::Str(&serial_commitment),
                HashPart::Str(&metadata_commitment_root),
                HashPart::Int(minted_at_height as i128),
            ],
        );
        Ok(Self {
            item_id,
            class_id: class.class_id.clone(),
            serial_commitment,
            metadata_commitment_root,
            owner_commitment,
            view_tag_root,
            encrypted_note_root,
            transfer_policy_root,
            royalty_stream_id: royalty_stream_id.to_string(),
            royalty_stream_root: royalty_stream_root.to_string(),
            current_nullifier_root,
            spend_root,
            collateral_hook_id: None,
            bridge_wrap_id: None,
            listing_id: None,
            status: ConfidentialNftItemStatus::PendingMint,
            minted_at_height,
            last_updated_height: minted_at_height,
        })
    }

    pub fn mark_held(&mut self, height: u64) {
        self.status = ConfidentialNftItemStatus::Held;
        self.last_updated_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_nft_item",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "item_id": self.item_id,
            "class_id": self.class_id,
            "serial_commitment": self.serial_commitment,
            "metadata_commitment_root": self.metadata_commitment_root,
            "owner_commitment": self.owner_commitment,
            "view_tag_root": self.view_tag_root,
            "encrypted_note_root": self.encrypted_note_root,
            "transfer_policy_root": self.transfer_policy_root,
            "royalty_stream_id": self.royalty_stream_id,
            "royalty_stream_root": self.royalty_stream_root,
            "current_nullifier_root": self.current_nullifier_root,
            "spend_root": self.spend_root,
            "collateral_hook_id": self.collateral_hook_id,
            "bridge_wrap_id": self.bridge_wrap_id,
            "listing_id": self.listing_id,
            "status": self.status.as_str(),
            "minted_at_height": self.minted_at_height,
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn item_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-ITEM",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.item_id, "nft item id")?;
        ensure_non_empty(&self.class_id, "nft item class id")?;
        ensure_non_empty(&self.serial_commitment, "nft item serial commitment")?;
        ensure_non_empty(
            &self.metadata_commitment_root,
            "nft item metadata commitment root",
        )?;
        ensure_non_empty(&self.owner_commitment, "nft item owner commitment")?;
        ensure_non_empty(&self.view_tag_root, "nft item view tag root")?;
        ensure_non_empty(&self.encrypted_note_root, "nft item encrypted note root")?;
        ensure_non_empty(&self.transfer_policy_root, "nft item transfer policy root")?;
        ensure_non_empty(&self.royalty_stream_id, "nft item royalty stream id")?;
        ensure_non_empty(&self.royalty_stream_root, "nft item royalty stream root")?;
        ensure_non_empty(&self.current_nullifier_root, "nft item nullifier root")?;
        ensure_non_empty(&self.spend_root, "nft item spend root")?;
        if self.last_updated_height < self.minted_at_height {
            return Err("nft item updated height before mint".to_string());
        }
        Ok(self.item_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoyaltyRecipientShare {
    pub recipient_commitment: String,
    pub share_bps: u64,
    pub view_key_root: String,
}

impl RoyaltyRecipientShare {
    pub fn new(label: &str, share_bps: u64) -> ConfidentialNftAndRoyaltyResult<Self> {
        validate_bps("royalty recipient share_bps", share_bps)?;
        Ok(Self {
            recipient_commitment: commitment("CONFIDENTIAL-NFT-ROYALTY-RECIPIENT", label),
            share_bps,
            view_key_root: commitment("CONFIDENTIAL-NFT-ROYALTY-VIEW-KEY", label),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "recipient_commitment": self.recipient_commitment,
            "share_bps": self.share_bps,
            "view_key_root": self.view_key_root,
        })
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<()> {
        ensure_non_empty(&self.recipient_commitment, "royalty recipient commitment")?;
        ensure_non_empty(&self.view_key_root, "royalty recipient view key root")?;
        validate_bps("royalty recipient share_bps", self.share_bps)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRoyaltyStream {
    pub stream_id: String,
    pub class_id: String,
    pub item_id: Option<String>,
    pub creator_policy_id: String,
    pub sale_price_commitment: String,
    pub royalty_bps: u64,
    pub recipient_shares: Vec<RoyaltyRecipientShare>,
    pub recipient_root: String,
    pub accrued_commitment: String,
    pub settled_commitment: String,
    pub next_settlement_height: u64,
    pub settlement_nullifier_root: String,
    pub disclosure_root: String,
    pub status: RoyaltyStreamStatus,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ConfidentialRoyaltyStream {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        item_id: Option<String>,
        creator_policy: &ConfidentialNftCreatorPolicy,
        sale_price_label: &str,
        recipient_shares: Vec<RoyaltyRecipientShare>,
        created_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(class_id, "royalty stream class id")?;
        ensure_non_empty(sale_price_label, "royalty stream sale price label")?;
        if recipient_shares.is_empty() {
            return Err("royalty stream must include recipients".to_string());
        }
        let total_bps = recipient_shares
            .iter()
            .fold(0_u64, |acc, share| acc.saturating_add(share.share_bps));
        if total_bps != CONFIDENTIAL_NFT_AND_ROYALTY_MAX_BPS {
            return Err("royalty stream recipient shares must sum to 10000 bps".to_string());
        }
        let sale_price_commitment = commitment("CONFIDENTIAL-NFT-SALE-PRICE", sale_price_label);
        let recipient_root = merkle_from_records(
            "CONFIDENTIAL-NFT-ROYALTY-RECIPIENTS",
            recipient_shares
                .iter()
                .map(RoyaltyRecipientShare::public_record)
                .collect::<Vec<_>>(),
        );
        let item_part = item_id.clone().unwrap_or_default();
        let stream_id = nft_hash(
            "CONFIDENTIAL-NFT-ROYALTY-STREAM-ID",
            &[
                HashPart::Str(class_id),
                HashPart::Str(&item_part),
                HashPart::Str(&creator_policy.policy_id),
                HashPart::Str(&sale_price_commitment),
                HashPart::Int(created_at_height as i128),
            ],
        );
        Ok(Self {
            stream_id,
            class_id: class_id.to_string(),
            item_id,
            creator_policy_id: creator_policy.policy_id.clone(),
            sale_price_commitment,
            royalty_bps: creator_policy.royalty_bps,
            recipient_shares,
            recipient_root,
            accrued_commitment: commitment("CONFIDENTIAL-NFT-ROYALTY-ACCRUED", "zero"),
            settled_commitment: commitment("CONFIDENTIAL-NFT-ROYALTY-SETTLED", "zero"),
            next_settlement_height: created_at_height.saturating_add(96),
            settlement_nullifier_root: commitment(
                "CONFIDENTIAL-NFT-ROYALTY-SETTLEMENT-NULLIFIER",
                class_id,
            ),
            disclosure_root: commitment("CONFIDENTIAL-NFT-ROYALTY-DISCLOSURE", class_id),
            status: RoyaltyStreamStatus::Proposed,
            created_at_height,
            updated_at_height: created_at_height,
        })
    }

    pub fn activate(&mut self, height: u64) {
        self.status = RoyaltyStreamStatus::Active;
        self.updated_at_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_royalty_stream",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "stream_id": self.stream_id,
            "class_id": self.class_id,
            "item_id": self.item_id,
            "creator_policy_id": self.creator_policy_id,
            "sale_price_commitment": self.sale_price_commitment,
            "royalty_bps": self.royalty_bps,
            "recipient_root": self.recipient_root,
            "recipient_shares": self.recipient_shares.iter().map(RoyaltyRecipientShare::public_record).collect::<Vec<_>>(),
            "accrued_commitment": self.accrued_commitment,
            "settled_commitment": self.settled_commitment,
            "next_settlement_height": self.next_settlement_height,
            "settlement_nullifier_root": self.settlement_nullifier_root,
            "disclosure_root": self.disclosure_root,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn stream_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-ROYALTY-STREAM",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.stream_id, "royalty stream id")?;
        ensure_non_empty(&self.class_id, "royalty stream class id")?;
        ensure_non_empty(&self.creator_policy_id, "royalty stream creator policy id")?;
        ensure_non_empty(
            &self.sale_price_commitment,
            "royalty stream sale price commitment",
        )?;
        ensure_non_empty(&self.recipient_root, "royalty stream recipient root")?;
        ensure_non_empty(
            &self.accrued_commitment,
            "royalty stream accrued commitment",
        )?;
        ensure_non_empty(
            &self.settled_commitment,
            "royalty stream settled commitment",
        )?;
        ensure_non_empty(
            &self.settlement_nullifier_root,
            "royalty stream settlement nullifier root",
        )?;
        ensure_non_empty(&self.disclosure_root, "royalty stream disclosure root")?;
        validate_bps("royalty stream royalty_bps", self.royalty_bps)?;
        if self.recipient_shares.is_empty() {
            return Err("royalty stream must include recipients".to_string());
        }
        let mut total_bps = 0_u64;
        for share in &self.recipient_shares {
            share.validate()?;
            total_bps = total_bps.saturating_add(share.share_bps);
        }
        if total_bps != CONFIDENTIAL_NFT_AND_ROYALTY_MAX_BPS {
            return Err("royalty stream recipient shares must sum to 10000 bps".to_string());
        }
        if self.updated_at_height < self.created_at_height {
            return Err("royalty stream updated height before creation".to_string());
        }
        Ok(self.stream_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialMarketplaceListing {
    pub listing_id: String,
    pub item_id: String,
    pub class_id: String,
    pub seller_commitment: String,
    pub price_commitment: String,
    pub payment_asset_id: String,
    pub marketplace_root: String,
    pub royalty_stream_id: String,
    pub seller_note_root: String,
    pub escrow_commitment: String,
    pub disclosure_root: String,
    pub low_fee_sponsorship_id: Option<String>,
    pub status: MarketplaceListingStatus,
    pub listed_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl ConfidentialMarketplaceListing {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        item: &ConfidentialNftItem,
        seller_label: &str,
        price_label: &str,
        payment_asset_id: &str,
        marketplace_label: &str,
        ttl_blocks: u64,
        listed_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(seller_label, "listing seller")?;
        ensure_non_empty(price_label, "listing price")?;
        ensure_non_empty(payment_asset_id, "listing payment asset")?;
        ensure_non_empty(marketplace_label, "listing marketplace")?;
        if ttl_blocks == 0 {
            return Err("listing ttl must be non-zero".to_string());
        }
        let seller_commitment = commitment("CONFIDENTIAL-NFT-LISTING-SELLER", seller_label);
        let price_commitment = commitment("CONFIDENTIAL-NFT-LISTING-PRICE", price_label);
        let marketplace_root = commitment("CONFIDENTIAL-NFT-LISTING-MARKET", marketplace_label);
        let listing_id = nft_hash(
            "CONFIDENTIAL-NFT-LISTING-ID",
            &[
                HashPart::Str(&item.item_id),
                HashPart::Str(&seller_commitment),
                HashPart::Str(&price_commitment),
                HashPart::Str(payment_asset_id),
                HashPart::Int(listed_at_height as i128),
            ],
        );
        Ok(Self {
            listing_id,
            item_id: item.item_id.clone(),
            class_id: item.class_id.clone(),
            seller_commitment,
            price_commitment,
            payment_asset_id: payment_asset_id.to_string(),
            marketplace_root,
            royalty_stream_id: item.royalty_stream_id.clone(),
            seller_note_root: commitment("CONFIDENTIAL-NFT-LISTING-SELLER-NOTE", seller_label),
            escrow_commitment: commitment("CONFIDENTIAL-NFT-LISTING-ESCROW", &item.item_id),
            disclosure_root: commitment("CONFIDENTIAL-NFT-LISTING-DISCLOSURE", &item.item_id),
            low_fee_sponsorship_id: None,
            status: MarketplaceListingStatus::Open,
            listed_at_height,
            expires_at_height: listed_at_height.saturating_add(ttl_blocks),
            settled_at_height: None,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_open() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_marketplace_listing",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "listing_id": self.listing_id,
            "item_id": self.item_id,
            "class_id": self.class_id,
            "seller_commitment": self.seller_commitment,
            "price_commitment": self.price_commitment,
            "payment_asset_id": self.payment_asset_id,
            "marketplace_root": self.marketplace_root,
            "royalty_stream_id": self.royalty_stream_id,
            "seller_note_root": self.seller_note_root,
            "escrow_commitment": self.escrow_commitment,
            "disclosure_root": self.disclosure_root,
            "low_fee_sponsorship_id": self.low_fee_sponsorship_id,
            "status": self.status.as_str(),
            "listed_at_height": self.listed_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn listing_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-LISTING",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.listing_id, "listing id")?;
        ensure_non_empty(&self.item_id, "listing item id")?;
        ensure_non_empty(&self.class_id, "listing class id")?;
        ensure_non_empty(&self.seller_commitment, "listing seller commitment")?;
        ensure_non_empty(&self.price_commitment, "listing price commitment")?;
        ensure_non_empty(&self.payment_asset_id, "listing payment asset")?;
        ensure_non_empty(&self.marketplace_root, "listing marketplace root")?;
        ensure_non_empty(&self.royalty_stream_id, "listing royalty stream id")?;
        ensure_non_empty(&self.seller_note_root, "listing seller note root")?;
        ensure_non_empty(&self.escrow_commitment, "listing escrow commitment")?;
        ensure_non_empty(&self.disclosure_root, "listing disclosure root")?;
        if self.expires_at_height <= self.listed_at_height {
            return Err("listing expiry must be after listed height".to_string());
        }
        if let Some(settled_at_height) = self.settled_at_height {
            if settled_at_height < self.listed_at_height {
                return Err("listing settled before listed".to_string());
            }
        }
        Ok(self.listing_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPrivateBid {
    pub bid_id: String,
    pub listing_id: String,
    pub item_id: String,
    pub bidder_commitment: String,
    pub bid_price_commitment: String,
    pub payment_asset_id: String,
    pub escrow_note_root: String,
    pub refund_note_root: String,
    pub bid_nullifier_root: String,
    pub disclosure_root: String,
    pub status: PrivateBidStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl ConfidentialPrivateBid {
    pub fn new(
        listing: &ConfidentialMarketplaceListing,
        bidder_label: &str,
        bid_price_label: &str,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(bidder_label, "private bid bidder")?;
        ensure_non_empty(bid_price_label, "private bid price")?;
        if ttl_blocks == 0 {
            return Err("private bid ttl must be non-zero".to_string());
        }
        let bidder_commitment = commitment("CONFIDENTIAL-NFT-BID-BIDDER", bidder_label);
        let bid_price_commitment = commitment("CONFIDENTIAL-NFT-BID-PRICE", bid_price_label);
        let bid_id = nft_hash(
            "CONFIDENTIAL-NFT-BID-ID",
            &[
                HashPart::Str(&listing.listing_id),
                HashPart::Str(&listing.item_id),
                HashPart::Str(&bidder_commitment),
                HashPart::Str(&bid_price_commitment),
                HashPart::Int(submitted_at_height as i128),
            ],
        );
        Ok(Self {
            bid_id,
            listing_id: listing.listing_id.clone(),
            item_id: listing.item_id.clone(),
            bidder_commitment,
            bid_price_commitment,
            payment_asset_id: listing.payment_asset_id.clone(),
            escrow_note_root: commitment("CONFIDENTIAL-NFT-BID-ESCROW", bidder_label),
            refund_note_root: commitment("CONFIDENTIAL-NFT-BID-REFUND", bidder_label),
            bid_nullifier_root: commitment("CONFIDENTIAL-NFT-BID-NULLIFIER", bidder_label),
            disclosure_root: commitment("CONFIDENTIAL-NFT-BID-DISCLOSURE", bidder_label),
            status: PrivateBidStatus::Submitted,
            submitted_at_height,
            expires_at_height: submitted_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_private_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "listing_id": self.listing_id,
            "item_id": self.item_id,
            "bidder_commitment": self.bidder_commitment,
            "bid_price_commitment": self.bid_price_commitment,
            "payment_asset_id": self.payment_asset_id,
            "escrow_note_root": self.escrow_note_root,
            "refund_note_root": self.refund_note_root,
            "bid_nullifier_root": self.bid_nullifier_root,
            "disclosure_root": self.disclosure_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn bid_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-BID",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.bid_id, "private bid id")?;
        ensure_non_empty(&self.listing_id, "private bid listing id")?;
        ensure_non_empty(&self.item_id, "private bid item id")?;
        ensure_non_empty(&self.bidder_commitment, "private bid bidder commitment")?;
        ensure_non_empty(&self.bid_price_commitment, "private bid price commitment")?;
        ensure_non_empty(&self.payment_asset_id, "private bid payment asset")?;
        ensure_non_empty(&self.escrow_note_root, "private bid escrow note root")?;
        ensure_non_empty(&self.refund_note_root, "private bid refund note root")?;
        ensure_non_empty(&self.bid_nullifier_root, "private bid nullifier root")?;
        ensure_non_empty(&self.disclosure_root, "private bid disclosure root")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("private bid expiry must be after submission".to_string());
        }
        Ok(self.bid_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingCollateralHook {
    pub hook_id: String,
    pub item_id: String,
    pub class_id: String,
    pub lending_market_id: String,
    pub collateral_owner_commitment: String,
    pub valuation_commitment: String,
    pub loan_commitment_root: String,
    pub liquidation_policy_root: String,
    pub oracle_attestation_root: String,
    pub release_nullifier_root: String,
    pub status: LendingCollateralHookStatus,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl ConfidentialLendingCollateralHook {
    pub fn new(
        item: &ConfidentialNftItem,
        market_id: &str,
        owner_label: &str,
        valuation_label: &str,
        opened_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(market_id, "lending hook market id")?;
        ensure_non_empty(owner_label, "lending hook owner")?;
        ensure_non_empty(valuation_label, "lending hook valuation")?;
        let collateral_owner_commitment = commitment("CONFIDENTIAL-NFT-LENDING-OWNER", owner_label);
        let valuation_commitment =
            commitment("CONFIDENTIAL-NFT-LENDING-VALUATION", valuation_label);
        let hook_id = nft_hash(
            "CONFIDENTIAL-NFT-LENDING-HOOK-ID",
            &[
                HashPart::Str(&item.item_id),
                HashPart::Str(market_id),
                HashPart::Str(&collateral_owner_commitment),
                HashPart::Str(&valuation_commitment),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Ok(Self {
            hook_id,
            item_id: item.item_id.clone(),
            class_id: item.class_id.clone(),
            lending_market_id: market_id.to_string(),
            collateral_owner_commitment,
            valuation_commitment,
            loan_commitment_root: commitment("CONFIDENTIAL-NFT-LENDING-LOAN", &item.item_id),
            liquidation_policy_root: commitment("CONFIDENTIAL-NFT-LENDING-LIQUIDATION", market_id),
            oracle_attestation_root: commitment("CONFIDENTIAL-NFT-LENDING-ORACLE", market_id),
            release_nullifier_root: commitment("CONFIDENTIAL-NFT-LENDING-RELEASE", &item.item_id),
            status: LendingCollateralHookStatus::Active,
            opened_at_height,
            updated_at_height: opened_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lending_collateral_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "hook_id": self.hook_id,
            "item_id": self.item_id,
            "class_id": self.class_id,
            "lending_market_id": self.lending_market_id,
            "collateral_owner_commitment": self.collateral_owner_commitment,
            "valuation_commitment": self.valuation_commitment,
            "loan_commitment_root": self.loan_commitment_root,
            "liquidation_policy_root": self.liquidation_policy_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "release_nullifier_root": self.release_nullifier_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn hook_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-LENDING-HOOK",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.hook_id, "lending hook id")?;
        ensure_non_empty(&self.item_id, "lending hook item id")?;
        ensure_non_empty(&self.class_id, "lending hook class id")?;
        ensure_non_empty(&self.lending_market_id, "lending hook market id")?;
        ensure_non_empty(
            &self.collateral_owner_commitment,
            "lending hook owner commitment",
        )?;
        ensure_non_empty(&self.valuation_commitment, "lending hook valuation")?;
        ensure_non_empty(&self.loan_commitment_root, "lending hook loan root")?;
        ensure_non_empty(
            &self.liquidation_policy_root,
            "lending hook liquidation policy root",
        )?;
        ensure_non_empty(
            &self.oracle_attestation_root,
            "lending hook oracle attestation root",
        )?;
        ensure_non_empty(
            &self.release_nullifier_root,
            "lending hook release nullifier root",
        )?;
        if self.updated_at_height < self.opened_at_height {
            return Err("lending hook updated height before opened".to_string());
        }
        Ok(self.hook_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialBridgeWrap {
    pub wrap_id: String,
    pub item_id: String,
    pub class_id: String,
    pub direction: BridgeWrapDirection,
    pub origin_chain: String,
    pub destination_chain: String,
    pub bridge_operator_commitment: String,
    pub reserve_commitment_root: String,
    pub remote_asset_commitment: String,
    pub reserve_proof_root: String,
    pub mint_burn_nullifier_root: String,
    pub disclosure_root: String,
    pub status: BridgeWrapStatus,
    pub requested_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl ConfidentialBridgeWrap {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        item: &ConfidentialNftItem,
        direction: BridgeWrapDirection,
        origin_chain: &str,
        destination_chain: &str,
        bridge_operator_label: &str,
        remote_asset_label: &str,
        requested_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(origin_chain, "bridge wrap origin chain")?;
        ensure_non_empty(destination_chain, "bridge wrap destination chain")?;
        ensure_non_empty(bridge_operator_label, "bridge wrap operator")?;
        ensure_non_empty(remote_asset_label, "bridge wrap remote asset")?;
        let bridge_operator_commitment =
            commitment("CONFIDENTIAL-NFT-BRIDGE-OPERATOR", bridge_operator_label);
        let remote_asset_commitment =
            commitment("CONFIDENTIAL-NFT-BRIDGE-REMOTE-ASSET", remote_asset_label);
        let wrap_id = nft_hash(
            "CONFIDENTIAL-NFT-BRIDGE-WRAP-ID",
            &[
                HashPart::Str(&item.item_id),
                HashPart::Str(direction.as_str()),
                HashPart::Str(origin_chain),
                HashPart::Str(destination_chain),
                HashPart::Str(&remote_asset_commitment),
                HashPart::Int(requested_at_height as i128),
            ],
        );
        Ok(Self {
            wrap_id,
            item_id: item.item_id.clone(),
            class_id: item.class_id.clone(),
            direction,
            origin_chain: origin_chain.to_string(),
            destination_chain: destination_chain.to_string(),
            bridge_operator_commitment,
            reserve_commitment_root: commitment(
                "CONFIDENTIAL-NFT-BRIDGE-RESERVE",
                remote_asset_label,
            ),
            remote_asset_commitment,
            reserve_proof_root: commitment("CONFIDENTIAL-NFT-BRIDGE-PROOF", remote_asset_label),
            mint_burn_nullifier_root: commitment(
                "CONFIDENTIAL-NFT-BRIDGE-MINT-BURN-NULLIFIER",
                &item.item_id,
            ),
            disclosure_root: commitment("CONFIDENTIAL-NFT-BRIDGE-DISCLOSURE", &item.item_id),
            status: BridgeWrapStatus::Requested,
            requested_at_height,
            finalized_at_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_bridge_wrap",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "wrap_id": self.wrap_id,
            "item_id": self.item_id,
            "class_id": self.class_id,
            "direction": self.direction.as_str(),
            "origin_chain": self.origin_chain,
            "destination_chain": self.destination_chain,
            "bridge_operator_commitment": self.bridge_operator_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "remote_asset_commitment": self.remote_asset_commitment,
            "reserve_proof_root": self.reserve_proof_root,
            "mint_burn_nullifier_root": self.mint_burn_nullifier_root,
            "disclosure_root": self.disclosure_root,
            "status": self.status.as_str(),
            "requested_at_height": self.requested_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn wrap_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-BRIDGE-WRAP",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.wrap_id, "bridge wrap id")?;
        ensure_non_empty(&self.item_id, "bridge wrap item id")?;
        ensure_non_empty(&self.class_id, "bridge wrap class id")?;
        ensure_non_empty(&self.origin_chain, "bridge wrap origin chain")?;
        ensure_non_empty(&self.destination_chain, "bridge wrap destination chain")?;
        ensure_non_empty(
            &self.bridge_operator_commitment,
            "bridge wrap operator commitment",
        )?;
        ensure_non_empty(
            &self.reserve_commitment_root,
            "bridge wrap reserve commitment root",
        )?;
        ensure_non_empty(
            &self.remote_asset_commitment,
            "bridge wrap remote asset commitment",
        )?;
        ensure_non_empty(&self.reserve_proof_root, "bridge wrap reserve proof root")?;
        ensure_non_empty(
            &self.mint_burn_nullifier_root,
            "bridge wrap mint burn nullifier root",
        )?;
        ensure_non_empty(&self.disclosure_root, "bridge wrap disclosure root")?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.requested_at_height {
                return Err("bridge wrap finalized before request".to_string());
            }
        }
        Ok(self.wrap_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeNftSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub action: LowFeeNftAction,
    pub class_id: Option<String>,
    pub item_id: Option<String>,
    pub budget_commitment: String,
    pub spent_commitment: String,
    pub max_units_per_action: u64,
    pub sponsor_authorization_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub revoked: bool,
}

impl LowFeeNftSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        lane_id: &str,
        fee_asset_id: &str,
        action: LowFeeNftAction,
        class_id: Option<String>,
        item_id: Option<String>,
        budget_label: &str,
        max_units_per_action: u64,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(sponsor_label, "low fee sponsor")?;
        ensure_non_empty(lane_id, "low fee lane")?;
        ensure_non_empty(fee_asset_id, "low fee fee asset")?;
        ensure_non_empty(budget_label, "low fee budget label")?;
        if max_units_per_action == 0 {
            return Err("low fee max_units_per_action must be non-zero".to_string());
        }
        if expires_at_height <= valid_from_height {
            return Err("low fee sponsorship expiry must be after valid-from".to_string());
        }
        let sponsor_commitment = commitment("CONFIDENTIAL-NFT-SPONSOR", sponsor_label);
        let budget_commitment = commitment("CONFIDENTIAL-NFT-SPONSOR-BUDGET", budget_label);
        let action_label = action.as_str();
        let class_part = class_id.clone().unwrap_or_default();
        let item_part = item_id.clone().unwrap_or_default();
        let sponsorship_id = nft_hash(
            "CONFIDENTIAL-NFT-SPONSORSHIP-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(lane_id),
                HashPart::Str(fee_asset_id),
                HashPart::Str(action_label),
                HashPart::Str(&class_part),
                HashPart::Str(&item_part),
                HashPart::Int(valid_from_height as i128),
            ],
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            action,
            class_id,
            item_id,
            budget_commitment,
            spent_commitment: commitment("CONFIDENTIAL-NFT-SPONSOR-SPENT", "zero"),
            max_units_per_action,
            sponsor_authorization_root: commitment("CONFIDENTIAL-NFT-SPONSOR-AUTH", sponsor_label),
            valid_from_height,
            expires_at_height,
            revoked: false,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        !self.revoked && self.valid_from_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_nft_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "action": self.action.as_str(),
            "class_id": self.class_id,
            "item_id": self.item_id,
            "budget_commitment": self.budget_commitment,
            "spent_commitment": self.spent_commitment,
            "max_units_per_action": self.max_units_per_action,
            "sponsor_authorization_root": self.sponsor_authorization_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "revoked": self.revoked,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-SPONSORSHIP",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.sponsorship_id, "low fee sponsorship id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "low fee sponsorship sponsor commitment",
        )?;
        ensure_non_empty(&self.lane_id, "low fee sponsorship lane id")?;
        ensure_non_empty(&self.fee_asset_id, "low fee sponsorship fee asset")?;
        ensure_non_empty(&self.budget_commitment, "low fee sponsorship budget")?;
        ensure_non_empty(&self.spent_commitment, "low fee sponsorship spent")?;
        ensure_non_empty(
            &self.sponsor_authorization_root,
            "low fee sponsorship authorization root",
        )?;
        if self.max_units_per_action == 0 {
            return Err("low fee sponsorship max units must be non-zero".to_string());
        }
        if self.expires_at_height <= self.valid_from_height {
            return Err("low fee sponsorship expiry must be after valid-from".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqNftAuthorization {
    pub authorization_id: String,
    pub scope: PqNftAuthorizationScope,
    pub subject_id: String,
    pub signer_commitment: String,
    pub pq_key_root: String,
    pub authorization_root: String,
    pub transcript_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub revoked: bool,
}

impl PqNftAuthorization {
    pub fn new(
        scope: PqNftAuthorizationScope,
        subject_id: &str,
        signer_label: &str,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(subject_id, "pq authorization subject")?;
        ensure_non_empty(signer_label, "pq authorization signer")?;
        if expires_at_height <= valid_from_height {
            return Err("pq authorization expiry must be after valid-from".to_string());
        }
        let signer_commitment = commitment("CONFIDENTIAL-NFT-PQ-SIGNER", signer_label);
        let pq_key_root = commitment("CONFIDENTIAL-NFT-PQ-KEY", signer_label);
        let scope_label = scope.as_str();
        let transcript_root = nft_hash(
            "CONFIDENTIAL-NFT-PQ-TRANSCRIPT",
            &[
                HashPart::Str(&scope_label),
                HashPart::Str(subject_id),
                HashPart::Str(&signer_commitment),
                HashPart::Int(valid_from_height as i128),
            ],
        );
        let authorization_root = nft_hash(
            "CONFIDENTIAL-NFT-PQ-AUTH-ROOT",
            &[
                HashPart::Str(&pq_key_root),
                HashPart::Str(&transcript_root),
                HashPart::Int(expires_at_height as i128),
            ],
        );
        let authorization_id = nft_hash(
            "CONFIDENTIAL-NFT-PQ-AUTH-ID",
            &[
                HashPart::Str(&scope_label),
                HashPart::Str(subject_id),
                HashPart::Str(&authorization_root),
            ],
        );
        Ok(Self {
            authorization_id,
            scope,
            subject_id: subject_id.to_string(),
            signer_commitment,
            pq_key_root,
            authorization_root,
            transcript_root,
            valid_from_height,
            expires_at_height,
            revoked: false,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        !self.revoked && self.valid_from_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_nft_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "signer_commitment": self.signer_commitment,
            "pq_key_root": self.pq_key_root,
            "authorization_root": self.authorization_root,
            "transcript_root": self.transcript_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "revoked": self.revoked,
        })
    }

    pub fn record_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-PQ-AUTHORIZATION",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.authorization_id, "pq authorization id")?;
        ensure_non_empty(&self.subject_id, "pq authorization subject")?;
        ensure_non_empty(&self.signer_commitment, "pq authorization signer")?;
        ensure_non_empty(&self.pq_key_root, "pq authorization key root")?;
        ensure_non_empty(&self.authorization_root, "pq authorization root")?;
        ensure_non_empty(&self.transcript_root, "pq authorization transcript root")?;
        if self.expires_at_height <= self.valid_from_height {
            return Err("pq authorization expiry must be after valid-from".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureReceipt {
    pub receipt_id: String,
    pub scope: SelectiveDisclosureScope,
    pub subject_id: String,
    pub viewer_commitment: String,
    pub disclosed_field_root: String,
    pub receipt_nullifier_root: String,
    pub audit_trail_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub revoked: bool,
}

impl SelectiveDisclosureReceipt {
    pub fn new(
        scope: SelectiveDisclosureScope,
        subject_id: &str,
        viewer_label: &str,
        fields: &[&str],
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        ensure_non_empty(subject_id, "disclosure subject")?;
        ensure_non_empty(viewer_label, "disclosure viewer")?;
        if fields.is_empty() {
            return Err("disclosure receipt must disclose at least one field root".to_string());
        }
        if ttl_blocks == 0 {
            return Err("disclosure ttl must be non-zero".to_string());
        }
        let viewer_commitment = commitment("CONFIDENTIAL-NFT-DISCLOSURE-VIEWER", viewer_label);
        let field_roots = fields
            .iter()
            .map(|field| commitment("CONFIDENTIAL-NFT-DISCLOSED-FIELD", field))
            .collect::<Vec<_>>();
        let disclosed_field_root =
            merkle_from_strings("CONFIDENTIAL-NFT-DISCLOSED-FIELDS", &field_roots);
        let scope_label = scope.as_str();
        let receipt_id = nft_hash(
            "CONFIDENTIAL-NFT-DISCLOSURE-RECEIPT-ID",
            &[
                HashPart::Str(scope_label),
                HashPart::Str(subject_id),
                HashPart::Str(&viewer_commitment),
                HashPart::Str(&disclosed_field_root),
                HashPart::Int(issued_at_height as i128),
            ],
        );
        Ok(Self {
            receipt_id,
            scope,
            subject_id: subject_id.to_string(),
            viewer_commitment,
            disclosed_field_root,
            receipt_nullifier_root: commitment("CONFIDENTIAL-NFT-DISCLOSURE-NULLIFIER", subject_id),
            audit_trail_root: commitment("CONFIDENTIAL-NFT-DISCLOSURE-AUDIT", subject_id),
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
            revoked: false,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        !self.revoked && self.issued_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "viewer_commitment": self.viewer_commitment,
            "disclosed_field_root": self.disclosed_field_root,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "audit_trail_root": self.audit_trail_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "revoked": self.revoked,
        })
    }

    pub fn receipt_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-DISCLOSURE-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        ensure_non_empty(&self.receipt_id, "disclosure receipt id")?;
        ensure_non_empty(&self.subject_id, "disclosure receipt subject")?;
        ensure_non_empty(&self.viewer_commitment, "disclosure viewer commitment")?;
        ensure_non_empty(&self.disclosed_field_root, "disclosure field root")?;
        ensure_non_empty(
            &self.receipt_nullifier_root,
            "disclosure receipt nullifier root",
        )?;
        ensure_non_empty(&self.audit_trail_root, "disclosure audit trail root")?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("disclosure receipt expiry must be after issue".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftAndRoyaltyRoots {
    pub config_root: String,
    pub creator_policy_root: String,
    pub class_root: String,
    pub item_root: String,
    pub royalty_stream_root: String,
    pub marketplace_listing_root: String,
    pub private_bid_root: String,
    pub lending_collateral_hook_root: String,
    pub bridge_wrap_root: String,
    pub low_fee_sponsorship_root: String,
    pub pq_authorization_root: String,
    pub disclosure_receipt_root: String,
    pub nullifier_root: String,
    pub spend_root: String,
}

impl ConfidentialNftAndRoyaltyRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_nft_and_royalty_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "creator_policy_root": self.creator_policy_root,
            "class_root": self.class_root,
            "item_root": self.item_root,
            "royalty_stream_root": self.royalty_stream_root,
            "marketplace_listing_root": self.marketplace_listing_root,
            "private_bid_root": self.private_bid_root,
            "lending_collateral_hook_root": self.lending_collateral_hook_root,
            "bridge_wrap_root": self.bridge_wrap_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "pq_authorization_root": self.pq_authorization_root,
            "disclosure_receipt_root": self.disclosure_receipt_root,
            "nullifier_root": self.nullifier_root,
            "spend_root": self.spend_root,
        })
    }

    pub fn state_root(&self) -> String {
        nft_hash(
            "CONFIDENTIAL-NFT-ROOTS",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftAndRoyaltyCounters {
    pub creator_policy_count: u64,
    pub active_creator_policy_count: u64,
    pub class_count: u64,
    pub active_class_count: u64,
    pub item_count: u64,
    pub live_item_count: u64,
    pub royalty_stream_count: u64,
    pub live_royalty_stream_count: u64,
    pub marketplace_listing_count: u64,
    pub open_listing_count: u64,
    pub private_bid_count: u64,
    pub live_private_bid_count: u64,
    pub lending_collateral_hook_count: u64,
    pub active_lending_collateral_hook_count: u64,
    pub bridge_wrap_count: u64,
    pub live_bridge_wrap_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub pq_authorization_count: u64,
    pub active_pq_authorization_count: u64,
    pub disclosure_receipt_count: u64,
    pub active_disclosure_receipt_count: u64,
    pub nullifier_count: u64,
    pub spend_root_count: u64,
    pub minted_item_count: u64,
    pub burned_item_count: u64,
    pub listed_item_count: u64,
    pub collateral_locked_item_count: u64,
    pub bridged_out_item_count: u64,
}

impl ConfidentialNftAndRoyaltyCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_nft_and_royalty_counters",
            "chain_id": CHAIN_ID,
            "creator_policy_count": self.creator_policy_count,
            "active_creator_policy_count": self.active_creator_policy_count,
            "class_count": self.class_count,
            "active_class_count": self.active_class_count,
            "item_count": self.item_count,
            "live_item_count": self.live_item_count,
            "royalty_stream_count": self.royalty_stream_count,
            "live_royalty_stream_count": self.live_royalty_stream_count,
            "marketplace_listing_count": self.marketplace_listing_count,
            "open_listing_count": self.open_listing_count,
            "private_bid_count": self.private_bid_count,
            "live_private_bid_count": self.live_private_bid_count,
            "lending_collateral_hook_count": self.lending_collateral_hook_count,
            "active_lending_collateral_hook_count": self.active_lending_collateral_hook_count,
            "bridge_wrap_count": self.bridge_wrap_count,
            "live_bridge_wrap_count": self.live_bridge_wrap_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "pq_authorization_count": self.pq_authorization_count,
            "active_pq_authorization_count": self.active_pq_authorization_count,
            "disclosure_receipt_count": self.disclosure_receipt_count,
            "active_disclosure_receipt_count": self.active_disclosure_receipt_count,
            "nullifier_count": self.nullifier_count,
            "spend_root_count": self.spend_root_count,
            "minted_item_count": self.minted_item_count,
            "burned_item_count": self.burned_item_count,
            "listed_item_count": self.listed_item_count,
            "collateral_locked_item_count": self.collateral_locked_item_count,
            "bridged_out_item_count": self.bridged_out_item_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialNftAndRoyaltyState {
    pub height: u64,
    pub config: ConfidentialNftAndRoyaltyConfig,
    pub creator_policies: BTreeMap<String, ConfidentialNftCreatorPolicy>,
    pub classes: BTreeMap<String, ConfidentialNftClass>,
    pub items: BTreeMap<String, ConfidentialNftItem>,
    pub royalty_streams: BTreeMap<String, ConfidentialRoyaltyStream>,
    pub marketplace_listings: BTreeMap<String, ConfidentialMarketplaceListing>,
    pub private_bids: BTreeMap<String, ConfidentialPrivateBid>,
    pub lending_collateral_hooks: BTreeMap<String, ConfidentialLendingCollateralHook>,
    pub bridge_wraps: BTreeMap<String, ConfidentialBridgeWrap>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeNftSponsorship>,
    pub pq_authorizations: BTreeMap<String, PqNftAuthorization>,
    pub disclosure_receipts: BTreeMap<String, SelectiveDisclosureReceipt>,
    pub spent_nullifiers: BTreeSet<String>,
    pub spend_roots: BTreeSet<String>,
    pub nonce: u64,
}

impl Default for ConfidentialNftAndRoyaltyState {
    fn default() -> Self {
        Self {
            height: 0,
            config: ConfidentialNftAndRoyaltyConfig::default(),
            creator_policies: BTreeMap::new(),
            classes: BTreeMap::new(),
            items: BTreeMap::new(),
            royalty_streams: BTreeMap::new(),
            marketplace_listings: BTreeMap::new(),
            private_bids: BTreeMap::new(),
            lending_collateral_hooks: BTreeMap::new(),
            bridge_wraps: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            disclosure_receipts: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            spend_roots: BTreeSet::new(),
            nonce: 0,
        }
    }
}

impl ConfidentialNftAndRoyaltyState {
    pub fn with_config(
        config: ConfidentialNftAndRoyaltyConfig,
    ) -> ConfidentialNftAndRoyaltyResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn set_height(&mut self, height: u64) -> ConfidentialNftAndRoyaltyResult<()> {
        if height < self.height {
            return Err("confidential nft height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn next_nonce(&mut self) -> u64 {
        let current = self.nonce;
        self.nonce = self.nonce.saturating_add(1);
        current
    }

    pub fn insert_creator_policy(
        &mut self,
        policy: ConfidentialNftCreatorPolicy,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let policy_id = policy.policy_id.clone();
        policy.validate()?;
        self.creator_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn insert_class(
        &mut self,
        class: ConfidentialNftClass,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let class_id = class.class_id.clone();
        class.validate()?;
        if !self.creator_policies.contains_key(&class.creator_policy_id) {
            return Err("nft class references unknown creator policy".to_string());
        }
        self.classes.insert(class_id.clone(), class);
        Ok(class_id)
    }

    pub fn insert_royalty_stream(
        &mut self,
        stream: ConfidentialRoyaltyStream,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let stream_id = stream.stream_id.clone();
        stream.validate()?;
        if !self.classes.contains_key(&stream.class_id) {
            return Err("royalty stream references unknown class".to_string());
        }
        if !self
            .creator_policies
            .contains_key(&stream.creator_policy_id)
        {
            return Err("royalty stream references unknown creator policy".to_string());
        }
        self.royalty_streams.insert(stream_id.clone(), stream);
        Ok(stream_id)
    }

    pub fn insert_item(
        &mut self,
        item: ConfidentialNftItem,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let item_id = item.item_id.clone();
        item.validate()?;
        if !self.classes.contains_key(&item.class_id) {
            return Err("nft item references unknown class".to_string());
        }
        if !self.royalty_streams.contains_key(&item.royalty_stream_id) {
            return Err("nft item references unknown royalty stream".to_string());
        }
        self.spent_nullifiers
            .insert(item.current_nullifier_root.clone());
        self.spend_roots.insert(item.spend_root.clone());
        self.items.insert(item_id.clone(), item);
        self.recompute_class_item_roots();
        Ok(item_id)
    }

    pub fn insert_listing(
        &mut self,
        listing: ConfidentialMarketplaceListing,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let listing_id = listing.listing_id.clone();
        listing.validate()?;
        if !self.items.contains_key(&listing.item_id) {
            return Err("listing references unknown item".to_string());
        }
        if !self
            .royalty_streams
            .contains_key(&listing.royalty_stream_id)
        {
            return Err("listing references unknown royalty stream".to_string());
        }
        if let Some(item) = self.items.get_mut(&listing.item_id) {
            item.listing_id = Some(listing_id.clone());
            item.status = ConfidentialNftItemStatus::Listed;
            item.last_updated_height = self.height;
        }
        self.marketplace_listings
            .insert(listing_id.clone(), listing);
        Ok(listing_id)
    }

    pub fn insert_private_bid(
        &mut self,
        bid: ConfidentialPrivateBid,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let bid_id = bid.bid_id.clone();
        bid.validate()?;
        if !self.marketplace_listings.contains_key(&bid.listing_id) {
            return Err("private bid references unknown listing".to_string());
        }
        self.spent_nullifiers.insert(bid.bid_nullifier_root.clone());
        self.private_bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn insert_lending_hook(
        &mut self,
        hook: ConfidentialLendingCollateralHook,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        if !self.config.allow_lending_collateral_hooks {
            return Err("lending collateral hooks are disabled".to_string());
        }
        let hook_id = hook.hook_id.clone();
        hook.validate()?;
        if !self.items.contains_key(&hook.item_id) {
            return Err("lending hook references unknown item".to_string());
        }
        if let Some(item) = self.items.get_mut(&hook.item_id) {
            item.collateral_hook_id = Some(hook_id.clone());
            item.status = ConfidentialNftItemStatus::CollateralLocked;
            item.last_updated_height = self.height;
        }
        self.spent_nullifiers
            .insert(hook.release_nullifier_root.clone());
        self.lending_collateral_hooks.insert(hook_id.clone(), hook);
        Ok(hook_id)
    }

    pub fn insert_bridge_wrap(
        &mut self,
        wrap: ConfidentialBridgeWrap,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        if !self.config.allow_bridge_wrapped_classes {
            return Err("bridge wrapped classes are disabled".to_string());
        }
        let wrap_id = wrap.wrap_id.clone();
        wrap.validate()?;
        if !self.items.contains_key(&wrap.item_id) {
            return Err("bridge wrap references unknown item".to_string());
        }
        if let Some(item) = self.items.get_mut(&wrap.item_id) {
            item.bridge_wrap_id = Some(wrap_id.clone());
            item.status = ConfidentialNftItemStatus::BridgedOut;
            item.last_updated_height = self.height;
        }
        self.spent_nullifiers
            .insert(wrap.mint_burn_nullifier_root.clone());
        self.bridge_wraps.insert(wrap_id.clone(), wrap);
        Ok(wrap_id)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeNftSponsorship,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        sponsorship.validate()?;
        if let Some(class_id) = &sponsorship.class_id {
            if !self.classes.contains_key(class_id) {
                return Err("low fee sponsorship references unknown class".to_string());
            }
        }
        if let Some(item_id) = &sponsorship.item_id {
            if !self.items.contains_key(item_id) {
                return Err("low fee sponsorship references unknown item".to_string());
            }
        }
        self.low_fee_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn insert_pq_authorization(
        &mut self,
        authorization: PqNftAuthorization,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let authorization_id = authorization.authorization_id.clone();
        authorization.validate()?;
        self.pq_authorizations
            .insert(authorization_id.clone(), authorization);
        Ok(authorization_id)
    }

    pub fn insert_disclosure_receipt(
        &mut self,
        receipt: SelectiveDisclosureReceipt,
    ) -> ConfidentialNftAndRoyaltyResult<String> {
        let receipt_id = receipt.receipt_id.clone();
        receipt.validate()?;
        self.spent_nullifiers
            .insert(receipt.receipt_nullifier_root.clone());
        self.disclosure_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn roots(&self) -> ConfidentialNftAndRoyaltyRoots {
        ConfidentialNftAndRoyaltyRoots {
            config_root: self.config.config_root(),
            creator_policy_root: merkle_from_map(
                "CONFIDENTIAL-NFT-CREATOR-POLICY-SET",
                &self.creator_policies,
                ConfidentialNftCreatorPolicy::public_record,
            ),
            class_root: merkle_from_map(
                "CONFIDENTIAL-NFT-CLASS-SET",
                &self.classes,
                ConfidentialNftClass::public_record,
            ),
            item_root: merkle_from_map(
                "CONFIDENTIAL-NFT-ITEM-SET",
                &self.items,
                ConfidentialNftItem::public_record,
            ),
            royalty_stream_root: merkle_from_map(
                "CONFIDENTIAL-NFT-ROYALTY-STREAM-SET",
                &self.royalty_streams,
                ConfidentialRoyaltyStream::public_record,
            ),
            marketplace_listing_root: merkle_from_map(
                "CONFIDENTIAL-NFT-LISTING-SET",
                &self.marketplace_listings,
                ConfidentialMarketplaceListing::public_record,
            ),
            private_bid_root: merkle_from_map(
                "CONFIDENTIAL-NFT-BID-SET",
                &self.private_bids,
                ConfidentialPrivateBid::public_record,
            ),
            lending_collateral_hook_root: merkle_from_map(
                "CONFIDENTIAL-NFT-LENDING-HOOK-SET",
                &self.lending_collateral_hooks,
                ConfidentialLendingCollateralHook::public_record,
            ),
            bridge_wrap_root: merkle_from_map(
                "CONFIDENTIAL-NFT-BRIDGE-WRAP-SET",
                &self.bridge_wraps,
                ConfidentialBridgeWrap::public_record,
            ),
            low_fee_sponsorship_root: merkle_from_map(
                "CONFIDENTIAL-NFT-SPONSORSHIP-SET",
                &self.low_fee_sponsorships,
                LowFeeNftSponsorship::public_record,
            ),
            pq_authorization_root: merkle_from_map(
                "CONFIDENTIAL-NFT-PQ-AUTHORIZATION-SET",
                &self.pq_authorizations,
                PqNftAuthorization::public_record,
            ),
            disclosure_receipt_root: merkle_from_map(
                "CONFIDENTIAL-NFT-DISCLOSURE-RECEIPT-SET",
                &self.disclosure_receipts,
                SelectiveDisclosureReceipt::public_record,
            ),
            nullifier_root: merkle_from_strings(
                "CONFIDENTIAL-NFT-NULLIFIER-SET",
                &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            spend_root: merkle_from_strings(
                "CONFIDENTIAL-NFT-SPEND-SET",
                &self.spend_roots.iter().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> ConfidentialNftAndRoyaltyCounters {
        ConfidentialNftAndRoyaltyCounters {
            creator_policy_count: self.creator_policies.len() as u64,
            active_creator_policy_count: self
                .creator_policies
                .values()
                .filter(|policy| policy.active_at(self.height))
                .count() as u64,
            class_count: self.classes.len() as u64,
            active_class_count: self
                .classes
                .values()
                .filter(|class| class.status.counts_as_active())
                .count() as u64,
            item_count: self.items.len() as u64,
            live_item_count: self
                .items
                .values()
                .filter(|item| item.status.counts_as_live())
                .count() as u64,
            royalty_stream_count: self.royalty_streams.len() as u64,
            live_royalty_stream_count: self
                .royalty_streams
                .values()
                .filter(|stream| stream.status.is_live())
                .count() as u64,
            marketplace_listing_count: self.marketplace_listings.len() as u64,
            open_listing_count: self
                .marketplace_listings
                .values()
                .filter(|listing| listing.is_live_at(self.height))
                .count() as u64,
            private_bid_count: self.private_bids.len() as u64,
            live_private_bid_count: self
                .private_bids
                .values()
                .filter(|bid| bid.is_live_at(self.height))
                .count() as u64,
            lending_collateral_hook_count: self.lending_collateral_hooks.len() as u64,
            active_lending_collateral_hook_count: self
                .lending_collateral_hooks
                .values()
                .filter(|hook| hook.status.is_active())
                .count() as u64,
            bridge_wrap_count: self.bridge_wraps.len() as u64,
            live_bridge_wrap_count: self
                .bridge_wraps
                .values()
                .filter(|wrap| wrap.status.is_live())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.active_at(self.height))
                .count() as u64,
            pq_authorization_count: self.pq_authorizations.len() as u64,
            active_pq_authorization_count: self
                .pq_authorizations
                .values()
                .filter(|authorization| authorization.active_at(self.height))
                .count() as u64,
            disclosure_receipt_count: self.disclosure_receipts.len() as u64,
            active_disclosure_receipt_count: self
                .disclosure_receipts
                .values()
                .filter(|receipt| receipt.active_at(self.height))
                .count() as u64,
            nullifier_count: self.spent_nullifiers.len() as u64,
            spend_root_count: self.spend_roots.len() as u64,
            minted_item_count: self
                .items
                .values()
                .filter(|item| item.status != ConfidentialNftItemStatus::PendingMint)
                .count() as u64,
            burned_item_count: self
                .items
                .values()
                .filter(|item| item.status == ConfidentialNftItemStatus::Burned)
                .count() as u64,
            listed_item_count: self
                .items
                .values()
                .filter(|item| item.status == ConfidentialNftItemStatus::Listed)
                .count() as u64,
            collateral_locked_item_count: self
                .items
                .values()
                .filter(|item| item.status == ConfidentialNftItemStatus::CollateralLocked)
                .count() as u64,
            bridged_out_item_count: self
                .items
                .values()
                .filter(|item| item.status == ConfidentialNftItemStatus::BridgedOut)
                .count() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        confidential_nft_and_royalty_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> ConfidentialNftAndRoyaltyResult<String> {
        self.config.validate()?;
        ensure_map_keys_match(
            &self.creator_policies,
            |value| &value.policy_id,
            "creator policy",
        )?;
        ensure_map_keys_match(&self.classes, |value| &value.class_id, "nft class")?;
        ensure_map_keys_match(&self.items, |value| &value.item_id, "nft item")?;
        ensure_map_keys_match(
            &self.royalty_streams,
            |value| &value.stream_id,
            "royalty stream",
        )?;
        ensure_map_keys_match(
            &self.marketplace_listings,
            |value| &value.listing_id,
            "marketplace listing",
        )?;
        ensure_map_keys_match(&self.private_bids, |value| &value.bid_id, "private bid")?;
        ensure_map_keys_match(
            &self.lending_collateral_hooks,
            |value| &value.hook_id,
            "lending collateral hook",
        )?;
        ensure_map_keys_match(&self.bridge_wraps, |value| &value.wrap_id, "bridge wrap")?;
        ensure_map_keys_match(
            &self.low_fee_sponsorships,
            |value| &value.sponsorship_id,
            "low fee sponsorship",
        )?;
        ensure_map_keys_match(
            &self.pq_authorizations,
            |value| &value.authorization_id,
            "pq authorization",
        )?;
        ensure_map_keys_match(
            &self.disclosure_receipts,
            |value| &value.receipt_id,
            "disclosure receipt",
        )?;
        for policy in self.creator_policies.values() {
            policy.validate()?;
            if policy.royalty_bps > self.config.max_royalty_bps {
                return Err("creator policy royalty exceeds configured maximum".to_string());
            }
        }
        for class in self.classes.values() {
            class.validate()?;
            if !self.creator_policies.contains_key(&class.creator_policy_id) {
                return Err("nft class references unknown creator policy".to_string());
            }
            if class.supply_mode.requires_bridge_reserve()
                && !self.config.allow_bridge_wrapped_classes
            {
                return Err(
                    "bridge mint burn class present while bridge wrapping disabled".to_string(),
                );
            }
        }
        for stream in self.royalty_streams.values() {
            stream.validate()?;
            if !self.classes.contains_key(&stream.class_id) {
                return Err("royalty stream references unknown class".to_string());
            }
            if !self
                .creator_policies
                .contains_key(&stream.creator_policy_id)
            {
                return Err("royalty stream references unknown creator policy".to_string());
            }
            if let Some(item_id) = &stream.item_id {
                if !self.items.contains_key(item_id) {
                    return Err("royalty stream item reference is unknown".to_string());
                }
            }
        }
        for item in self.items.values() {
            item.validate()?;
            if !self.classes.contains_key(&item.class_id) {
                return Err("nft item references unknown class".to_string());
            }
            if !self.royalty_streams.contains_key(&item.royalty_stream_id) {
                return Err("nft item references unknown royalty stream".to_string());
            }
            if let Some(listing_id) = &item.listing_id {
                if !self.marketplace_listings.contains_key(listing_id) {
                    return Err("nft item listing reference is unknown".to_string());
                }
            }
        }
        for listing in self.marketplace_listings.values() {
            listing.validate()?;
            if !self.items.contains_key(&listing.item_id) {
                return Err("listing references unknown item".to_string());
            }
            if !self
                .royalty_streams
                .contains_key(&listing.royalty_stream_id)
            {
                return Err("listing references unknown royalty stream".to_string());
            }
        }
        for bid in self.private_bids.values() {
            bid.validate()?;
            if !self.marketplace_listings.contains_key(&bid.listing_id) {
                return Err("private bid references unknown listing".to_string());
            }
            if !self.items.contains_key(&bid.item_id) {
                return Err("private bid references unknown item".to_string());
            }
        }
        for hook in self.lending_collateral_hooks.values() {
            hook.validate()?;
            if !self.config.allow_lending_collateral_hooks {
                return Err("lending hook present while hooks disabled".to_string());
            }
            if !self.items.contains_key(&hook.item_id) {
                return Err("lending hook references unknown item".to_string());
            }
        }
        for wrap in self.bridge_wraps.values() {
            wrap.validate()?;
            if !self.config.allow_bridge_wrapped_classes {
                return Err("bridge wrap present while bridge wrapping disabled".to_string());
            }
            if !self.items.contains_key(&wrap.item_id) {
                return Err("bridge wrap references unknown item".to_string());
            }
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
            if sponsorship.max_units_per_action > self.config.low_fee_unit_cap {
                return Err("low fee sponsorship exceeds configured unit cap".to_string());
            }
        }
        for authorization in self.pq_authorizations.values() {
            authorization.validate()?;
        }
        for receipt in self.disclosure_receipts.values() {
            receipt.validate()?;
        }
        Ok(self.state_root())
    }

    pub fn devnet() -> ConfidentialNftAndRoyaltyResult<Self> {
        let mut state = Self::with_config(ConfidentialNftAndRoyaltyConfig::devnet())?;
        state.set_height(CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_HEIGHT)?;

        let creator_policy = ConfidentialNftCreatorPolicy::new(
            CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_CREATOR_LABEL,
            &[
                CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_OPERATOR_LABEL,
                CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_SPONSOR_LABEL,
            ],
            750,
            "devnet-confidential-floor-1-xmr",
            &["devnet-private-marketplace"],
            &["sanctions-screened-deny-root"],
            state.height.saturating_sub(48),
            state.height.saturating_add(52_560),
        )?;
        let creator_policy_id = state.insert_creator_policy(creator_policy.clone())?;

        let mut art_class = ConfidentialNftClass::new(
            "DARKART",
            "Devnet Confidential Art",
            ConfidentialNftClassKind::Art,
            ConfidentialNftSupplyMode::FixedEdition,
            &creator_policy,
            &json!({
                "public_theme": "privacy-preserving creator royalties",
                "metadata_visibility": "thumbnail-only",
                "royalty": "shielded-recipient-split",
            }),
            128,
            state.height.saturating_sub(40),
        )?;
        art_class.activate(state.height.saturating_sub(39));
        let art_class_id = state.insert_class(art_class.clone())?;

        let mut royalty_stream = ConfidentialRoyaltyStream::new(
            &art_class_id,
            None,
            &creator_policy,
            "devnet-sale-price-hidden",
            vec![
                RoyaltyRecipientShare::new("devnet-artist-primary", 7_000)?,
                RoyaltyRecipientShare::new("devnet-studio-treasury", 2_000)?,
                RoyaltyRecipientShare::new("devnet-community-fund", 1_000)?,
            ],
            state.height.saturating_sub(38),
        )?;
        royalty_stream.activate(state.height.saturating_sub(37));
        let royalty_stream_id = state.insert_royalty_stream(royalty_stream.clone())?;

        let mut item = ConfidentialNftItem::new(
            &art_class,
            "devnet-confidential-art-0001",
            "devnet-private-owner",
            &json!({
                "preview": "commitment-only",
                "trait_root": "devnet-art-trait-root",
                "content_hash": "shielded-content-hash",
            }),
            &royalty_stream_id,
            &royalty_stream.stream_root(),
            state.height.saturating_sub(36),
        )?;
        item.mark_held(state.height.saturating_sub(35));
        let item_id = state.insert_item(item.clone())?;

        let listing = ConfidentialMarketplaceListing::new(
            &item,
            "devnet-private-owner",
            "devnet-listing-price-12-xmr",
            "pXMR",
            "devnet-private-marketplace",
            state.config.default_listing_ttl_blocks,
            state.height.saturating_sub(32),
        )?;
        let listing_id = state.insert_listing(listing.clone())?;

        let bid = ConfidentialPrivateBid::new(
            &listing,
            "devnet-private-bidder",
            "devnet-private-bid-11-xmr",
            state.height.saturating_sub(28),
            state.config.default_bid_ttl_blocks,
        )?;
        state.insert_private_bid(bid)?;

        let hook = ConfidentialLendingCollateralHook::new(
            &item,
            CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_LENDING_LABEL,
            "devnet-private-owner",
            "devnet-oracle-valuation-hidden",
            state.height.saturating_sub(24),
        )?;
        state.insert_lending_hook(hook)?;

        let bridge_wrap = ConfidentialBridgeWrap::new(
            &item,
            BridgeWrapDirection::DepositToL2,
            "monero-sidechain-devnet",
            "nebula-l2-devnet",
            CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_BRIDGE_LABEL,
            "remote-confidential-art-0001",
            state.height.saturating_sub(20),
        )?;
        state.insert_bridge_wrap(bridge_wrap)?;

        let sponsorship = LowFeeNftSponsorship::new(
            CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_SPONSOR_LABEL,
            &state.config.default_low_fee_lane,
            &state.config.fee_asset_id,
            LowFeeNftAction::Transfer,
            Some(art_class_id.clone()),
            Some(item_id.clone()),
            "devnet-low-fee-nft-budget",
            8_000,
            state.height.saturating_sub(16),
            state
                .height
                .saturating_add(state.config.default_sponsor_epoch_blocks),
        )?;
        state.insert_low_fee_sponsorship(sponsorship)?;

        let creator_auth = PqNftAuthorization::new(
            PqNftAuthorizationScope::CreateClass,
            &creator_policy_id,
            CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_CREATOR_LABEL,
            state.height.saturating_sub(64),
            state.height.saturating_add(52_560),
        )?;
        state.insert_pq_authorization(creator_auth)?;

        let operator_auth = PqNftAuthorization::new(
            PqNftAuthorizationScope::OperateMarketplace,
            &listing_id,
            CONFIDENTIAL_NFT_AND_ROYALTY_DEVNET_OPERATOR_LABEL,
            state.height.saturating_sub(32),
            state.height.saturating_add(2_880),
        )?;
        state.insert_pq_authorization(operator_auth)?;

        let disclosure = SelectiveDisclosureReceipt::new(
            SelectiveDisclosureScope::MarketplaceCompliance,
            &item_id,
            "devnet-market-auditor",
            &["class_id", "creator_policy_root", "royalty_bps"],
            state.height.saturating_sub(8),
            state.config.default_disclosure_ttl_blocks,
        )?;
        state.insert_disclosure_receipt(disclosure)?;

        state.validate()?;
        Ok(state)
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "confidential_nft_and_royalty_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_NFT_AND_ROYALTY_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "roots": roots.public_record(),
            "root_commitment": roots.state_root(),
            "counters": counters.public_record(),
            "active_class_ids": self.active_class_ids(),
            "open_listing_ids": self.open_listing_ids(),
            "live_bid_ids": self.live_bid_ids(),
        })
    }

    fn active_class_ids(&self) -> Vec<String> {
        self.classes
            .values()
            .filter(|class| class.status.counts_as_active())
            .map(|class| class.class_id.clone())
            .collect()
    }

    fn open_listing_ids(&self) -> Vec<String> {
        self.marketplace_listings
            .values()
            .filter(|listing| listing.is_live_at(self.height))
            .map(|listing| listing.listing_id.clone())
            .collect()
    }

    fn live_bid_ids(&self) -> Vec<String> {
        self.private_bids
            .values()
            .filter(|bid| bid.is_live_at(self.height))
            .map(|bid| bid.bid_id.clone())
            .collect()
    }

    fn recompute_class_item_roots(&mut self) {
        let mut class_items: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for item in self.items.values() {
            class_items
                .entry(item.class_id.clone())
                .or_default()
                .push(item.item_root());
        }
        for (class_id, roots) in class_items {
            if let Some(class) = self.classes.get_mut(&class_id) {
                class.minted_count = roots.len() as u64;
                class.update_item_root(&roots, self.height);
            }
        }
    }
}

pub fn confidential_nft_and_royalty_state_root_from_record(record: &Value) -> String {
    nft_hash("CONFIDENTIAL-NFT-STATE", &[HashPart::Json(record)])
}

fn ensure_non_empty(value: &str, label: &str) -> ConfidentialNftAndRoyaltyResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    Ok(())
}

fn validate_bps(label: &str, value: u64) -> ConfidentialNftAndRoyaltyResult<()> {
    if value > CONFIDENTIAL_NFT_AND_ROYALTY_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_map_keys_match<T, F>(
    map: &BTreeMap<String, T>,
    key_fn: F,
    label: &str,
) -> ConfidentialNftAndRoyaltyResult<()>
where
    F: Fn(&T) -> &String,
{
    for (key, value) in map {
        if key != key_fn(value) {
            return Err(format!("{label} map key mismatch"));
        }
    }
    Ok(())
}

fn nft_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn commitment(domain: &str, label: &str) -> String {
    nft_hash(domain, &[HashPart::Str(label)])
}

fn json_root(domain: &str, value: &Value) -> String {
    nft_hash(domain, &[HashPart::Json(value)])
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn merkle_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn merkle_from_strings(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_from_map<T, F>(domain: &str, map: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map.values().map(record_fn).collect::<Vec<_>>();
    merkle_root(domain, &records)
}
