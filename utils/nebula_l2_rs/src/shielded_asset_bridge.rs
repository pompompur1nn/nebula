use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ShieldedAssetBridgeResult<T> = Result<T, String>;

pub const SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION: u32 = 1;
pub const SHIELDED_ASSET_BRIDGE_PROTOCOL_LABEL: &str = "nebula-l2-shielded-asset-bridge-v1";
pub const SHIELDED_ASSET_BRIDGE_DEVNET_HEIGHT: u64 = 192;
pub const SHIELDED_ASSET_BRIDGE_MONERO_NETWORK: &str = "monero-devnet";
pub const SHIELDED_ASSET_BRIDGE_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const SHIELDED_ASSET_BRIDGE_PXMR_ASSET_ID: &str = "pxmr-confidential-devnet";
pub const SHIELDED_ASSET_BRIDGE_USDD_ASSET_ID: &str = "pusd-confidential-devnet";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_FEE_ASSET_ID: &str = "dnr-devnet-fee";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_PQ_SCHEME: &str =
    "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f-bridge-devnet";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_RESERVE_PROOF_SCHEME: &str =
    "view-key-attested-reserve-liability-proof-v1";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_MINT_PROOF_SCHEME: &str =
    "shielded-reserve-backed-mint-proof-v1";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_BURN_PROOF_SCHEME: &str = "shielded-burn-release-proof-v1";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_REPLAY_DOMAIN: &str =
    "nebula-shielded-asset-bridge-devnet-replay-v1";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_CONTRACT_HOOK_SCHEME: &str =
    "private-contract-asset-hook-v1";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_ANCHOR_SCHEME: &str =
    "monero-settlement-anchor-manifest-v1";
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_LOW_FEE_LANE: &str = "shielded-bridge-mint-sponsor";
pub const SHIELDED_ASSET_BRIDGE_MAX_BPS: u64 = 10_000;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_200;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_RISK_PAUSE_BPS: u64 = 8_500;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_PQ_SECURITY_BITS: u16 = 192;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 20;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_L2_FINALITY_DEPTH: u64 = 12;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_INTENT_TTL_BLOCKS: u64 = 144;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 720;
pub const SHIELDED_ASSET_BRIDGE_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 2_880;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrappedAssetKind {
    WrappedMonero,
    ConfidentialMonero,
    ConfidentialStable,
    BridgeReceipt,
    LiquidityShare,
}

impl WrappedAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedMonero => "wrapped_monero",
            Self::ConfidentialMonero => "confidential_monero",
            Self::ConfidentialStable => "confidential_stable",
            Self::BridgeReceipt => "bridge_receipt",
            Self::LiquidityShare => "liquidity_share",
        }
    }

    pub fn requires_reserve(self) -> bool {
        matches!(self, Self::WrappedMonero | Self::ConfidentialMonero)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLaneKind {
    PublicWrap,
    ConfidentialMint,
    ConfidentialBurn,
    LiquidityProvider,
    PrivateContract,
    EmergencyExit,
}

impl BridgeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicWrap => "public_wrap",
            Self::ConfidentialMint => "confidential_mint",
            Self::ConfidentialBurn => "confidential_burn",
            Self::LiquidityProvider => "liquidity_provider",
            Self::PrivateContract => "private_contract",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn mint_capable(self) -> bool {
        matches!(
            self,
            Self::PublicWrap
                | Self::ConfidentialMint
                | Self::LiquidityProvider
                | Self::PrivateContract
        )
    }

    pub fn burn_capable(self) -> bool {
        matches!(
            self,
            Self::ConfidentialBurn
                | Self::LiquidityProvider
                | Self::PrivateContract
                | Self::EmergencyExit
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLifecycleStatus {
    Draft,
    Active,
    Paused,
    RedemptionsOnly,
    Frozen,
    Retired,
}

impl BridgeLifecycleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::RedemptionsOnly => "redemptions_only",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn allows_mint(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn allows_burn(self) -> bool {
        matches!(self, Self::Active | Self::RedemptionsOnly)
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::Paused | Self::RedemptionsOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBridgeIntentKind {
    Mint,
    Burn,
    Rebalance,
    ContractDeposit,
    ContractWithdrawal,
}

impl PrivateBridgeIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Rebalance => "rebalance",
            Self::ContractDeposit => "contract_deposit",
            Self::ContractWithdrawal => "contract_withdrawal",
        }
    }

    pub fn needs_reserve_proof(self) -> bool {
        matches!(self, Self::Mint | Self::Rebalance | Self::ContractDeposit)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBridgeIntentStatus {
    Requested,
    ReserveProved,
    Approved,
    Sponsored,
    Executed,
    Rejected,
    Expired,
}

impl PrivateBridgeIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::ReserveProved => "reserve_proved",
            Self::Approved => "approved",
            Self::Sponsored => "sponsored",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::ReserveProved | Self::Approved | Self::Sponsored
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Executed | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalStatus {
    Proposed,
    ThresholdMet,
    Applied,
    Rejected,
    Expired,
}

impl PqApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ThresholdMet => "threshold_met",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Proposed | Self::ThresholdMet)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Draft,
    Attested,
    Accepted,
    Superseded,
    Disputed,
    Expired,
}

impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Attested => "attested",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBucketKind {
    Dust,
    Retail,
    MarketMaker,
    Whale,
    Contract,
    Emergency,
}

impl RiskBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dust => "dust",
            Self::Retail => "retail",
            Self::MarketMaker => "market_maker",
            Self::Whale => "whale",
            Self::Contract => "contract",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    Allow,
    SponsorOnly,
    RequirePqApproval,
    DelaySettlement,
    RedemptionsOnly,
    PauseLane,
}

impl RiskAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::SponsorOnly => "sponsor_only",
            Self::RequirePqApproval => "require_pq_approval",
            Self::DelaySettlement => "delay_settlement",
            Self::RedemptionsOnly => "redemptions_only",
            Self::PauseLane => "pause_lane",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractHookPhase {
    BeforeMint,
    AfterMint,
    BeforeBurn,
    AfterBurn,
    BeforeSettlement,
    AfterSettlement,
}

impl ContractHookPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeMint => "before_mint",
            Self::AfterMint => "after_mint",
            Self::BeforeBurn => "before_burn",
            Self::AfterBurn => "after_burn",
            Self::BeforeSettlement => "before_settlement",
            Self::AfterSettlement => "after_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAnchorStatus {
    Prepared,
    Published,
    Confirmed,
    ReorgHold,
    Reorged,
    Expired,
}

impl SettlementAnchorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Published => "published",
            Self::Confirmed => "confirmed",
            Self::ReorgHold => "reorg_hold",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Prepared | Self::Published | Self::ReorgHold)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAssetBridgeConfig {
    pub protocol_version: u32,
    pub protocol_label: String,
    pub monero_network: String,
    pub default_fee_asset_id: String,
    pub pq_approval_scheme: String,
    pub reserve_proof_scheme: String,
    pub mint_proof_scheme: String,
    pub burn_proof_scheme: String,
    pub replay_domain: String,
    pub contract_hook_scheme: String,
    pub settlement_anchor_scheme: String,
    pub low_fee_lane_label: String,
    pub min_pq_security_bits: u16,
    pub min_reserve_coverage_bps: u64,
    pub risk_pause_threshold_bps: u64,
    pub monero_finality_depth: u64,
    pub l2_finality_depth: u64,
    pub intent_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub replay_window_blocks: u64,
    pub max_open_intents: u64,
    pub max_active_contract_hooks: u64,
}

impl ShieldedAssetBridgeConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            protocol_label: SHIELDED_ASSET_BRIDGE_PROTOCOL_LABEL.to_string(),
            monero_network: SHIELDED_ASSET_BRIDGE_MONERO_NETWORK.to_string(),
            default_fee_asset_id: SHIELDED_ASSET_BRIDGE_DEFAULT_FEE_ASSET_ID.to_string(),
            pq_approval_scheme: SHIELDED_ASSET_BRIDGE_DEFAULT_PQ_SCHEME.to_string(),
            reserve_proof_scheme: SHIELDED_ASSET_BRIDGE_DEFAULT_RESERVE_PROOF_SCHEME.to_string(),
            mint_proof_scheme: SHIELDED_ASSET_BRIDGE_DEFAULT_MINT_PROOF_SCHEME.to_string(),
            burn_proof_scheme: SHIELDED_ASSET_BRIDGE_DEFAULT_BURN_PROOF_SCHEME.to_string(),
            replay_domain: SHIELDED_ASSET_BRIDGE_DEFAULT_REPLAY_DOMAIN.to_string(),
            contract_hook_scheme: SHIELDED_ASSET_BRIDGE_DEFAULT_CONTRACT_HOOK_SCHEME.to_string(),
            settlement_anchor_scheme: SHIELDED_ASSET_BRIDGE_DEFAULT_ANCHOR_SCHEME.to_string(),
            low_fee_lane_label: SHIELDED_ASSET_BRIDGE_DEFAULT_LOW_FEE_LANE.to_string(),
            min_pq_security_bits: SHIELDED_ASSET_BRIDGE_DEFAULT_PQ_SECURITY_BITS,
            min_reserve_coverage_bps: SHIELDED_ASSET_BRIDGE_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            risk_pause_threshold_bps: SHIELDED_ASSET_BRIDGE_DEFAULT_RISK_PAUSE_BPS,
            monero_finality_depth: SHIELDED_ASSET_BRIDGE_DEFAULT_MONERO_FINALITY_DEPTH,
            l2_finality_depth: SHIELDED_ASSET_BRIDGE_DEFAULT_L2_FINALITY_DEPTH,
            intent_ttl_blocks: SHIELDED_ASSET_BRIDGE_DEFAULT_INTENT_TTL_BLOCKS,
            sponsor_ttl_blocks: SHIELDED_ASSET_BRIDGE_DEFAULT_SPONSOR_TTL_BLOCKS,
            replay_window_blocks: SHIELDED_ASSET_BRIDGE_DEFAULT_REPLAY_WINDOW_BLOCKS,
            max_open_intents: 512,
            max_active_contract_hooks: 32,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "protocol_label": self.protocol_label,
            "monero_network": self.monero_network,
            "default_fee_asset_id": self.default_fee_asset_id,
            "pq_approval_scheme": self.pq_approval_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
            "mint_proof_scheme": self.mint_proof_scheme,
            "burn_proof_scheme": self.burn_proof_scheme,
            "replay_domain": self.replay_domain,
            "contract_hook_scheme": self.contract_hook_scheme,
            "settlement_anchor_scheme": self.settlement_anchor_scheme,
            "low_fee_lane_label": self.low_fee_lane_label,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "risk_pause_threshold_bps": self.risk_pause_threshold_bps,
            "monero_finality_depth": self.monero_finality_depth,
            "l2_finality_depth": self.l2_finality_depth,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "max_open_intents": self.max_open_intents,
            "max_active_contract_hooks": self.max_active_contract_hooks,
        })
    }

    pub fn config_root(&self) -> String {
        shielded_asset_bridge_payload_root("SHIELDED-ASSET-BRIDGE-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<()> {
        if self.protocol_version != SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION {
            return Err("shielded asset bridge protocol version mismatch".to_string());
        }
        ensure_non_empty(&self.protocol_label, "bridge protocol label")?;
        ensure_non_empty(&self.monero_network, "bridge monero network")?;
        ensure_non_empty(&self.default_fee_asset_id, "bridge fee asset")?;
        ensure_non_empty(&self.pq_approval_scheme, "bridge pq approval scheme")?;
        ensure_non_empty(&self.reserve_proof_scheme, "bridge reserve proof scheme")?;
        ensure_non_empty(&self.replay_domain, "bridge replay domain")?;
        ensure_bps(
            self.risk_pause_threshold_bps,
            "bridge risk pause threshold bps",
        )?;
        if self.min_reserve_coverage_bps < SHIELDED_ASSET_BRIDGE_MAX_BPS {
            return Err("bridge reserve coverage floor must be at least 100 percent".to_string());
        }
        if self.min_pq_security_bits < SHIELDED_ASSET_BRIDGE_DEFAULT_PQ_SECURITY_BITS {
            return Err("bridge PQ security floor is too low".to_string());
        }
        ensure_positive(self.monero_finality_depth, "bridge monero finality depth")?;
        ensure_positive(self.l2_finality_depth, "bridge l2 finality depth")?;
        ensure_positive(self.intent_ttl_blocks, "bridge intent ttl")?;
        ensure_positive(self.replay_window_blocks, "bridge replay window")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedAssetRecord {
    pub asset_id: String,
    pub symbol: String,
    pub display_name: String,
    pub decimals: u8,
    pub asset_kind: WrappedAssetKind,
    pub reserve_asset_id: String,
    pub reserve_network: String,
    pub metadata_root: String,
    pub issuer_commitment: String,
    pub supply_commitment: String,
    pub reserve_commitment_root: String,
    pub lane_policy_root: String,
    pub status: BridgeLifecycleStatus,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl WrappedAssetRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol: &str,
        display_name: &str,
        decimals: u8,
        asset_kind: WrappedAssetKind,
        reserve_asset_id: &str,
        reserve_network: &str,
        issuer_label: &str,
        height: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(symbol, "wrapped asset symbol")?;
        ensure_non_empty(display_name, "wrapped asset display name")?;
        ensure_non_empty(reserve_asset_id, "wrapped asset reserve asset")?;
        ensure_non_empty(reserve_network, "wrapped asset reserve network")?;
        ensure_non_empty(issuer_label, "wrapped asset issuer")?;
        let normalized_symbol = normalize_symbol(symbol);
        let metadata_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ASSET-METADATA",
            &format!("{normalized_symbol}:{display_name}:{decimals}"),
        );
        let issuer_commitment =
            shielded_asset_bridge_string_root("SHIELDED-ASSET-BRIDGE-ASSET-ISSUER", issuer_label);
        let reserve_commitment_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ASSET-RESERVE",
            &format!("{reserve_network}:{reserve_asset_id}:{normalized_symbol}"),
        );
        let supply_commitment = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ASSET-SUPPLY",
            &format!("{normalized_symbol}:{height}:0"),
        );
        let lane_policy_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ASSET-LANE-POLICY",
            &format!("{}:{}", normalized_symbol, asset_kind.as_str()),
        );
        let asset_id = wrapped_asset_id(
            &normalized_symbol,
            decimals,
            asset_kind,
            reserve_asset_id,
            &metadata_root,
        );
        let asset = Self {
            asset_id,
            symbol: normalized_symbol,
            display_name: display_name.trim().to_string(),
            decimals,
            asset_kind,
            reserve_asset_id: reserve_asset_id.to_string(),
            reserve_network: reserve_network.to_string(),
            metadata_root,
            issuer_commitment,
            supply_commitment,
            reserve_commitment_root,
            lane_policy_root,
            status: BridgeLifecycleStatus::Active,
            created_at_height: height,
            updated_at_height: height,
        };
        asset.validate()?;
        Ok(asset)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_wrapped_asset",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "asset_id": self.asset_id,
            "symbol": self.symbol,
            "display_name": self.display_name,
            "decimals": self.decimals,
            "asset_kind": self.asset_kind.as_str(),
            "reserve_asset_id": self.reserve_asset_id,
            "reserve_network": self.reserve_network,
            "metadata_root": self.metadata_root,
            "issuer_commitment": self.issuer_commitment,
            "supply_commitment": self.supply_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "lane_policy_root": self.lane_policy_root,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn asset_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-WRAPPED-ASSET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.asset_id, "wrapped asset id")?;
        ensure_non_empty(&self.symbol, "wrapped asset symbol")?;
        ensure_non_empty(&self.display_name, "wrapped asset display name")?;
        ensure_non_empty(&self.metadata_root, "wrapped asset metadata root")?;
        ensure_non_empty(&self.issuer_commitment, "wrapped asset issuer commitment")?;
        ensure_non_empty(&self.supply_commitment, "wrapped asset supply commitment")?;
        ensure_non_empty(
            &self.reserve_commitment_root,
            "wrapped asset reserve commitment root",
        )?;
        if self.asset_kind.requires_reserve() {
            ensure_non_empty(&self.reserve_asset_id, "reserve backed asset reserve id")?;
            ensure_non_empty(&self.reserve_network, "reserve backed asset network")?;
        }
        if self.updated_at_height < self.created_at_height {
            return Err("wrapped asset update height precedes creation".to_string());
        }
        let expected = wrapped_asset_id(
            &self.symbol,
            self.decimals,
            self.asset_kind,
            &self.reserve_asset_id,
            &self.metadata_root,
        );
        if expected != self.asset_id {
            return Err("wrapped asset id mismatch".to_string());
        }
        Ok(self.asset_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenLane {
    pub lane_id: String,
    pub label: String,
    pub lane_kind: BridgeLaneKind,
    pub asset_id: String,
    pub confidential_class_id: String,
    pub note_commitment_root: String,
    pub nullifier_set_root: String,
    pub mint_authority_root: String,
    pub burn_authority_root: String,
    pub max_mint_units_per_epoch: u64,
    pub max_burn_units_per_epoch: u64,
    pub epoch_blocks: u64,
    pub low_fee_eligible: bool,
    pub status: BridgeLifecycleStatus,
}

impl ConfidentialTokenLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        lane_kind: BridgeLaneKind,
        asset_id: &str,
        confidential_class_id: &str,
        epoch_blocks: u64,
        max_mint_units_per_epoch: u64,
        max_burn_units_per_epoch: u64,
        low_fee_eligible: bool,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(label, "confidential lane label")?;
        ensure_non_empty(asset_id, "confidential lane asset id")?;
        ensure_non_empty(
            confidential_class_id,
            "confidential lane confidential class id",
        )?;
        ensure_positive(epoch_blocks, "confidential lane epoch blocks")?;
        let normalized = normalize_label(label);
        let note_commitment_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-LANE-NOTE-COMMITMENT",
            &format!("{normalized}:{asset_id}"),
        );
        let nullifier_set_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-LANE-NULLIFIER",
            &format!("{normalized}:{confidential_class_id}"),
        );
        let mint_authority_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-LANE-MINT-AUTHORITY",
            &normalized,
        );
        let burn_authority_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-LANE-BURN-AUTHORITY",
            &normalized,
        );
        let lane_id = confidential_lane_id(&normalized, lane_kind, asset_id, confidential_class_id);
        let lane = Self {
            lane_id,
            label: normalized,
            lane_kind,
            asset_id: asset_id.to_string(),
            confidential_class_id: confidential_class_id.to_string(),
            note_commitment_root,
            nullifier_set_root,
            mint_authority_root,
            burn_authority_root,
            max_mint_units_per_epoch,
            max_burn_units_per_epoch,
            epoch_blocks,
            low_fee_eligible,
            status: BridgeLifecycleStatus::Active,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_confidential_token_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "label": self.label,
            "lane_kind": self.lane_kind.as_str(),
            "asset_id": self.asset_id,
            "confidential_class_id": self.confidential_class_id,
            "note_commitment_root": self.note_commitment_root,
            "nullifier_set_root": self.nullifier_set_root,
            "mint_authority_root": self.mint_authority_root,
            "burn_authority_root": self.burn_authority_root,
            "max_mint_units_per_epoch": self.max_mint_units_per_epoch,
            "max_burn_units_per_epoch": self.max_burn_units_per_epoch,
            "epoch_blocks": self.epoch_blocks,
            "low_fee_eligible": self.low_fee_eligible,
            "status": self.status.as_str(),
        })
    }

    pub fn lane_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-CONFIDENTIAL-TOKEN-LANE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.lane_id, "confidential lane id")?;
        ensure_non_empty(&self.label, "confidential lane label")?;
        ensure_non_empty(&self.asset_id, "confidential lane asset id")?;
        ensure_non_empty(&self.confidential_class_id, "confidential lane class id")?;
        ensure_non_empty(&self.note_commitment_root, "confidential lane note root")?;
        ensure_non_empty(&self.nullifier_set_root, "confidential lane nullifier root")?;
        ensure_positive(self.epoch_blocks, "confidential lane epoch blocks")?;
        if self.lane_kind.mint_capable() && self.max_mint_units_per_epoch == 0 {
            return Err("mint capable lane needs a mint cap".to_string());
        }
        if self.lane_kind.burn_capable() && self.max_burn_units_per_epoch == 0 {
            return Err("burn capable lane needs a burn cap".to_string());
        }
        let expected = confidential_lane_id(
            &self.label,
            self.lane_kind,
            &self.asset_id,
            &self.confidential_class_id,
        );
        if expected != self.lane_id {
            return Err("confidential lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMintBurnIntent {
    pub intent_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub kind: PrivateBridgeIntentKind,
    pub status: PrivateBridgeIntentStatus,
    pub owner_commitment: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub destination_commitment: String,
    pub source_nullifier_root: String,
    pub output_note_root: String,
    pub reserve_proof_id: String,
    pub pq_approval_id: String,
    pub sponsorship_id: String,
    pub replay_key: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateMintBurnIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        asset_id: &str,
        kind: PrivateBridgeIntentKind,
        owner_label: &str,
        amount_label: &str,
        destination_label: &str,
        requested_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(lane_id, "intent lane id")?;
        ensure_non_empty(asset_id, "intent asset id")?;
        ensure_non_empty(owner_label, "intent owner")?;
        ensure_non_empty(amount_label, "intent amount label")?;
        ensure_non_empty(destination_label, "intent destination")?;
        ensure_positive(ttl_blocks, "intent ttl")?;
        let owner_commitment =
            shielded_asset_bridge_string_root("SHIELDED-ASSET-BRIDGE-INTENT-OWNER", owner_label);
        let amount_commitment =
            shielded_asset_bridge_string_root("SHIELDED-ASSET-BRIDGE-INTENT-AMOUNT", amount_label);
        let fee_commitment = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-INTENT-FEE",
            &format!("{amount_label}:fee"),
        );
        let destination_commitment = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-INTENT-DESTINATION",
            destination_label,
        );
        let source_nullifier_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-INTENT-SOURCE-NULLIFIER",
            &format!("{lane_id}:{owner_label}:{nonce}"),
        );
        let output_note_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-INTENT-OUTPUT-NOTE",
            &format!("{asset_id}:{destination_label}:{nonce}"),
        );
        let replay_key = replay_key_for_intent(
            lane_id,
            asset_id,
            kind,
            &owner_commitment,
            &amount_commitment,
            nonce,
        );
        let intent_id =
            private_intent_id(lane_id, asset_id, kind, &replay_key, requested_at_height);
        let intent = Self {
            intent_id,
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            kind,
            status: PrivateBridgeIntentStatus::Requested,
            owner_commitment,
            amount_commitment,
            fee_commitment,
            destination_commitment,
            source_nullifier_root,
            output_note_root,
            reserve_proof_id: String::new(),
            pq_approval_id: String::new(),
            sponsorship_id: String::new(),
            replay_key,
            requested_at_height,
            expires_at_height: requested_at_height.saturating_add(ttl_blocks),
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_private_mint_burn_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "intent_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "destination_commitment": self.destination_commitment,
            "source_nullifier_root": self.source_nullifier_root,
            "output_note_root": self.output_note_root,
            "reserve_proof_id": self.reserve_proof_id,
            "pq_approval_id": self.pq_approval_id,
            "sponsorship_id": self.sponsorship_id,
            "replay_key": self.replay_key,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn intent_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-PRIVATE-MINT-BURN-INTENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.intent_id, "private intent id")?;
        ensure_non_empty(&self.lane_id, "private intent lane id")?;
        ensure_non_empty(&self.asset_id, "private intent asset id")?;
        ensure_non_empty(&self.owner_commitment, "private intent owner commitment")?;
        ensure_non_empty(&self.amount_commitment, "private intent amount commitment")?;
        ensure_non_empty(&self.fee_commitment, "private intent fee commitment")?;
        ensure_non_empty(
            &self.destination_commitment,
            "private intent destination commitment",
        )?;
        ensure_non_empty(
            &self.source_nullifier_root,
            "private intent source nullifier root",
        )?;
        ensure_non_empty(&self.output_note_root, "private intent output note root")?;
        ensure_non_empty(&self.replay_key, "private intent replay key")?;
        if self.expires_at_height <= self.requested_at_height {
            return Err("private intent expiry must be after request height".to_string());
        }
        if self.kind.needs_reserve_proof()
            && matches!(
                self.status,
                PrivateBridgeIntentStatus::ReserveProved
                    | PrivateBridgeIntentStatus::Approved
                    | PrivateBridgeIntentStatus::Sponsored
                    | PrivateBridgeIntentStatus::Executed
            )
            && self.reserve_proof_id.is_empty()
        {
            return Err("reserve-backed intent is missing reserve proof".to_string());
        }
        let expected = private_intent_id(
            &self.lane_id,
            &self.asset_id,
            self.kind,
            &self.replay_key,
            self.requested_at_height,
        );
        if expected != self.intent_id {
            return Err("private intent id mismatch".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveBackedIssuanceProof {
    pub proof_id: String,
    pub asset_id: String,
    pub lane_id: String,
    pub reserve_network: String,
    pub reserve_view_key_root: String,
    pub reserve_tx_root: String,
    pub liability_root: String,
    pub issued_supply_commitment: String,
    pub reserve_amount_bucket: String,
    pub liability_amount_bucket: String,
    pub coverage_bps: u64,
    pub observer_set_root: String,
    pub proof_transcript_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReserveProofStatus,
}

impl ReserveBackedIssuanceProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: &str,
        lane_id: &str,
        reserve_network: &str,
        observer_labels: &[String],
        coverage_bps: u64,
        attested_at_height: u64,
        expires_at_height: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(asset_id, "reserve proof asset id")?;
        ensure_non_empty(lane_id, "reserve proof lane id")?;
        ensure_non_empty(reserve_network, "reserve proof network")?;
        if coverage_bps < SHIELDED_ASSET_BRIDGE_MAX_BPS {
            return Err("reserve proof coverage below full reserve".to_string());
        }
        if expires_at_height <= attested_at_height {
            return Err("reserve proof expiry must be after attestation".to_string());
        }
        let observer_set_root = string_set_root(
            "SHIELDED-ASSET-BRIDGE-RESERVE-PROOF-OBSERVER",
            observer_labels,
        );
        let reserve_view_key_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-RESERVE-VIEW-KEY",
            &format!("{reserve_network}:{asset_id}"),
        );
        let reserve_tx_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-RESERVE-TX",
            &format!("{reserve_network}:{lane_id}:{attested_at_height}"),
        );
        let liability_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-RESERVE-LIABILITY",
            &format!("{asset_id}:{lane_id}:{coverage_bps}"),
        );
        let issued_supply_commitment = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-RESERVE-ISSUED-SUPPLY",
            &format!("{asset_id}:{attested_at_height}"),
        );
        let proof_transcript_root = shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-RESERVE-PROOF-TRANSCRIPT",
            &json!({
                "asset_id": asset_id,
                "lane_id": lane_id,
                "reserve_network": reserve_network,
                "coverage_bps": coverage_bps,
                "observer_set_root": observer_set_root,
            }),
        );
        let proof_id = reserve_proof_id(
            asset_id,
            lane_id,
            &reserve_tx_root,
            &liability_root,
            attested_at_height,
        );
        let proof = Self {
            proof_id,
            asset_id: asset_id.to_string(),
            lane_id: lane_id.to_string(),
            reserve_network: reserve_network.to_string(),
            reserve_view_key_root,
            reserve_tx_root,
            liability_root,
            issued_supply_commitment,
            reserve_amount_bucket: "reserve_overcollateralized".to_string(),
            liability_amount_bucket: "liability_private_supply".to_string(),
            coverage_bps,
            observer_set_root,
            proof_transcript_root,
            attested_at_height,
            expires_at_height,
            status: ReserveProofStatus::Accepted,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_reserve_backed_issuance_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "asset_id": self.asset_id,
            "lane_id": self.lane_id,
            "reserve_network": self.reserve_network,
            "reserve_view_key_root": self.reserve_view_key_root,
            "reserve_tx_root": self.reserve_tx_root,
            "liability_root": self.liability_root,
            "issued_supply_commitment": self.issued_supply_commitment,
            "reserve_amount_bucket": self.reserve_amount_bucket,
            "liability_amount_bucket": self.liability_amount_bucket,
            "coverage_bps": self.coverage_bps,
            "observer_set_root": self.observer_set_root,
            "proof_transcript_root": self.proof_transcript_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn proof_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-RESERVE-BACKED-ISSUANCE-PROOF",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.proof_id, "reserve proof id")?;
        ensure_non_empty(&self.asset_id, "reserve proof asset id")?;
        ensure_non_empty(&self.lane_id, "reserve proof lane id")?;
        ensure_non_empty(&self.reserve_network, "reserve proof network")?;
        ensure_non_empty(&self.reserve_view_key_root, "reserve proof view key root")?;
        ensure_non_empty(&self.reserve_tx_root, "reserve proof reserve tx root")?;
        ensure_non_empty(&self.liability_root, "reserve proof liability root")?;
        ensure_non_empty(
            &self.issued_supply_commitment,
            "reserve proof issued supply commitment",
        )?;
        ensure_non_empty(&self.observer_set_root, "reserve proof observer root")?;
        ensure_non_empty(&self.proof_transcript_root, "reserve proof transcript root")?;
        if self.coverage_bps < SHIELDED_ASSET_BRIDGE_MAX_BPS {
            return Err("reserve proof coverage is below full reserve".to_string());
        }
        if self.expires_at_height <= self.attested_at_height {
            return Err("reserve proof expiry precedes attestation".to_string());
        }
        let expected = reserve_proof_id(
            &self.asset_id,
            &self.lane_id,
            &self.reserve_tx_root,
            &self.liability_root,
            self.attested_at_height,
        );
        if expected != self.proof_id {
            return Err("reserve proof id mismatch".to_string());
        }
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeApproval {
    pub approval_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub action: String,
    pub approver_set_root: String,
    pub approval_transcript_root: String,
    pub threshold_weight: u64,
    pub observed_weight: u64,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: PqApprovalStatus,
}

impl PqBridgeApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        action: &str,
        approvers: &[String],
        threshold_weight: u64,
        observed_weight: u64,
        security_bits: u16,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(subject_kind, "pq approval subject kind")?;
        ensure_non_empty(subject_id, "pq approval subject id")?;
        ensure_non_empty(action, "pq approval action")?;
        ensure_positive(threshold_weight, "pq approval threshold")?;
        if expires_at_height <= valid_from_height {
            return Err("pq approval expiry must be after valid-from height".to_string());
        }
        let approver_set_root = string_set_root("SHIELDED-ASSET-BRIDGE-PQ-APPROVER", approvers);
        let approval_transcript_root = shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-PQ-APPROVAL-TRANSCRIPT",
            &json!({
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "action": action,
                "approver_set_root": approver_set_root,
                "threshold_weight": threshold_weight,
                "observed_weight": observed_weight,
            }),
        );
        let approval_id = pq_approval_id(
            subject_kind,
            subject_id,
            action,
            &approval_transcript_root,
            valid_from_height,
        );
        let status = if observed_weight >= threshold_weight {
            PqApprovalStatus::ThresholdMet
        } else {
            PqApprovalStatus::Proposed
        };
        let approval = Self {
            approval_id,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            action: action.to_string(),
            approver_set_root,
            approval_transcript_root,
            threshold_weight,
            observed_weight,
            security_bits,
            valid_from_height,
            expires_at_height,
            status,
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_pq_bridge_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "action": self.action,
            "approver_set_root": self.approver_set_root,
            "approval_transcript_root": self.approval_transcript_root,
            "threshold_weight": self.threshold_weight,
            "observed_weight": self.observed_weight,
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn approval_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-PQ-BRIDGE-APPROVAL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.approval_id, "pq approval id")?;
        ensure_non_empty(&self.subject_kind, "pq approval subject kind")?;
        ensure_non_empty(&self.subject_id, "pq approval subject id")?;
        ensure_non_empty(&self.action, "pq approval action")?;
        ensure_non_empty(&self.approver_set_root, "pq approval approver root")?;
        ensure_non_empty(
            &self.approval_transcript_root,
            "pq approval transcript root",
        )?;
        ensure_positive(self.threshold_weight, "pq approval threshold")?;
        if self.expires_at_height <= self.valid_from_height {
            return Err("pq approval expiry precedes valid-from height".to_string());
        }
        let expected = pq_approval_id(
            &self.subject_kind,
            &self.subject_id,
            &self.action,
            &self.approval_transcript_root,
            self.valid_from_height,
        );
        if expected != self.approval_id {
            return Err("pq approval id mismatch".to_string());
        }
        Ok(self.approval_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeMintSponsorship {
    pub sponsorship_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_mint_units: u64,
    pub per_intent_fee_cap_units: u64,
    pub rebate_bps: u64,
    pub budget_commitment: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

impl LowFeeMintSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        asset_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        max_mint_units: u64,
        per_intent_fee_cap_units: u64,
        rebate_bps: u64,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(lane_id, "mint sponsorship lane")?;
        ensure_non_empty(asset_id, "mint sponsorship asset")?;
        ensure_non_empty(sponsor_label, "mint sponsorship sponsor")?;
        ensure_non_empty(fee_asset_id, "mint sponsorship fee asset")?;
        ensure_positive(max_mint_units, "mint sponsorship max mint")?;
        ensure_positive(
            per_intent_fee_cap_units,
            "mint sponsorship per-intent fee cap",
        )?;
        ensure_bps(rebate_bps, "mint sponsorship rebate")?;
        if expires_at_height <= valid_from_height {
            return Err("mint sponsorship expiry must be after valid-from height".to_string());
        }
        let sponsor_commitment =
            shielded_asset_bridge_string_root("SHIELDED-ASSET-BRIDGE-MINT-SPONSOR", sponsor_label);
        let budget_commitment = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-MINT-SPONSOR-BUDGET",
            &format!("{lane_id}:{asset_id}:{max_mint_units}:{fee_asset_id}"),
        );
        let sponsorship_id = mint_sponsorship_id(
            lane_id,
            asset_id,
            &sponsor_commitment,
            &budget_commitment,
            valid_from_height,
        );
        let sponsorship = Self {
            sponsorship_id,
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            max_mint_units,
            per_intent_fee_cap_units,
            rebate_bps,
            budget_commitment,
            valid_from_height,
            expires_at_height,
            active: true,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_low_fee_mint_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_mint_units": self.max_mint_units,
            "per_intent_fee_cap_units": self.per_intent_fee_cap_units,
            "rebate_bps": self.rebate_bps,
            "budget_commitment": self.budget_commitment,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "active": self.active,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-LOW-FEE-MINT-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.sponsorship_id, "mint sponsorship id")?;
        ensure_non_empty(&self.lane_id, "mint sponsorship lane")?;
        ensure_non_empty(&self.asset_id, "mint sponsorship asset")?;
        ensure_non_empty(&self.sponsor_commitment, "mint sponsorship sponsor")?;
        ensure_non_empty(&self.fee_asset_id, "mint sponsorship fee asset")?;
        ensure_non_empty(&self.budget_commitment, "mint sponsorship budget")?;
        ensure_positive(self.max_mint_units, "mint sponsorship max mint")?;
        ensure_positive(
            self.per_intent_fee_cap_units,
            "mint sponsorship per-intent fee cap",
        )?;
        ensure_bps(self.rebate_bps, "mint sponsorship rebate")?;
        if self.expires_at_height <= self.valid_from_height {
            return Err("mint sponsorship expiry precedes valid-from height".to_string());
        }
        let expected = mint_sponsorship_id(
            &self.lane_id,
            &self.asset_id,
            &self.sponsor_commitment,
            &self.budget_commitment,
            self.valid_from_height,
        );
        if expected != self.sponsorship_id {
            return Err("mint sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRiskBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub bucket_kind: RiskBucketKind,
    pub min_amount_units: u64,
    pub max_amount_units: u64,
    pub action: RiskAction,
    pub delay_blocks: u64,
    pub daily_volume_cap_units: u64,
    pub open_intent_cap: u64,
    pub risk_score_bps: u64,
    pub guardian_policy_root: String,
    pub active: bool,
}

impl BridgeRiskBucket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        bucket_kind: RiskBucketKind,
        min_amount_units: u64,
        max_amount_units: u64,
        action: RiskAction,
        delay_blocks: u64,
        daily_volume_cap_units: u64,
        open_intent_cap: u64,
        risk_score_bps: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(lane_id, "risk bucket lane")?;
        ensure_bps(risk_score_bps, "risk bucket score")?;
        if max_amount_units != 0 && min_amount_units > max_amount_units {
            return Err("risk bucket min amount exceeds max amount".to_string());
        }
        let guardian_policy_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-RISK-GUARDIAN-POLICY",
            &format!("{lane_id}:{}", bucket_kind.as_str()),
        );
        let bucket_id = risk_bucket_id(lane_id, bucket_kind, min_amount_units, max_amount_units);
        let bucket = Self {
            bucket_id,
            lane_id: lane_id.to_string(),
            bucket_kind,
            min_amount_units,
            max_amount_units,
            action,
            delay_blocks,
            daily_volume_cap_units,
            open_intent_cap,
            risk_score_bps,
            guardian_policy_root,
            active: true,
        };
        bucket.validate()?;
        Ok(bucket)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_risk_bucket",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "min_amount_units": self.min_amount_units,
            "max_amount_units": self.max_amount_units,
            "action": self.action.as_str(),
            "delay_blocks": self.delay_blocks,
            "daily_volume_cap_units": self.daily_volume_cap_units,
            "open_intent_cap": self.open_intent_cap,
            "risk_score_bps": self.risk_score_bps,
            "guardian_policy_root": self.guardian_policy_root,
            "active": self.active,
        })
    }

    pub fn bucket_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-RISK-BUCKET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.bucket_id, "risk bucket id")?;
        ensure_non_empty(&self.lane_id, "risk bucket lane")?;
        ensure_non_empty(&self.guardian_policy_root, "risk bucket guardian policy")?;
        ensure_bps(self.risk_score_bps, "risk bucket score")?;
        if self.max_amount_units != 0 && self.min_amount_units > self.max_amount_units {
            return Err("risk bucket min amount exceeds max amount".to_string());
        }
        let expected = risk_bucket_id(
            &self.lane_id,
            self.bucket_kind,
            self.min_amount_units,
            self.max_amount_units,
        );
        if expected != self.bucket_id {
            return Err("risk bucket id mismatch".to_string());
        }
        Ok(self.bucket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractAssetHook {
    pub hook_id: String,
    pub contract_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub phases: BTreeSet<ContractHookPhase>,
    pub hook_commitment_root: String,
    pub call_policy_root: String,
    pub view_policy_root: String,
    pub max_hook_gas: u64,
    pub failure_action: RiskAction,
    pub active: bool,
}

impl PrivateContractAssetHook {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: &str,
        lane_id: &str,
        asset_id: &str,
        phases: BTreeSet<ContractHookPhase>,
        max_hook_gas: u64,
        failure_action: RiskAction,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(contract_id, "contract hook contract")?;
        ensure_non_empty(lane_id, "contract hook lane")?;
        ensure_non_empty(asset_id, "contract hook asset")?;
        ensure_positive(max_hook_gas, "contract hook gas")?;
        if phases.is_empty() {
            return Err("contract hook phases cannot be empty".to_string());
        }
        let phase_root = contract_hook_phase_root(&phases);
        let hook_commitment_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-CONTRACT-HOOK-COMMITMENT",
            &format!("{contract_id}:{lane_id}:{asset_id}:{phase_root}"),
        );
        let call_policy_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-CONTRACT-HOOK-CALL-POLICY",
            &format!("{contract_id}:{lane_id}"),
        );
        let view_policy_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-CONTRACT-HOOK-VIEW-POLICY",
            &format!("{contract_id}:{asset_id}"),
        );
        let hook_id = contract_hook_id(contract_id, lane_id, asset_id, &phase_root);
        let hook = Self {
            hook_id,
            contract_id: contract_id.to_string(),
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            phases,
            hook_commitment_root,
            call_policy_root,
            view_policy_root,
            max_hook_gas,
            failure_action,
            active: true,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_private_contract_asset_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "hook_id": self.hook_id,
            "contract_id": self.contract_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "phase_root": contract_hook_phase_root(&self.phases),
            "phases": self.phases.iter().map(|phase| phase.as_str()).collect::<Vec<_>>(),
            "hook_commitment_root": self.hook_commitment_root,
            "call_policy_root": self.call_policy_root,
            "view_policy_root": self.view_policy_root,
            "max_hook_gas": self.max_hook_gas,
            "failure_action": self.failure_action.as_str(),
            "active": self.active,
        })
    }

    pub fn hook_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-PRIVATE-CONTRACT-ASSET-HOOK",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.hook_id, "contract hook id")?;
        ensure_non_empty(&self.contract_id, "contract hook contract")?;
        ensure_non_empty(&self.lane_id, "contract hook lane")?;
        ensure_non_empty(&self.asset_id, "contract hook asset")?;
        ensure_non_empty(&self.hook_commitment_root, "contract hook commitment")?;
        ensure_non_empty(&self.call_policy_root, "contract hook call policy")?;
        ensure_non_empty(&self.view_policy_root, "contract hook view policy")?;
        ensure_positive(self.max_hook_gas, "contract hook gas")?;
        if self.phases.is_empty() {
            return Err("contract hook phases cannot be empty".to_string());
        }
        let phase_root = contract_hook_phase_root(&self.phases);
        let expected = contract_hook_id(
            &self.contract_id,
            &self.lane_id,
            &self.asset_id,
            &phase_root,
        );
        if expected != self.hook_id {
            return Err("contract hook id mismatch".to_string());
        }
        Ok(self.hook_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayProtectionEntry {
    pub replay_key: String,
    pub domain: String,
    pub subject_id: String,
    pub nullifier_root: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl ReplayProtectionEntry {
    pub fn new(
        domain: &str,
        subject_id: &str,
        nullifier_root: &str,
        first_seen_height: u64,
        expires_at_height: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(domain, "replay domain")?;
        ensure_non_empty(subject_id, "replay subject")?;
        ensure_non_empty(nullifier_root, "replay nullifier")?;
        if expires_at_height <= first_seen_height {
            return Err("replay entry expiry must be after first seen height".to_string());
        }
        let replay_key = replay_protection_key(domain, subject_id, nullifier_root);
        let entry = Self {
            replay_key,
            domain: domain.to_string(),
            subject_id: subject_id.to_string(),
            nullifier_root: nullifier_root.to_string(),
            first_seen_height,
            expires_at_height,
            consumed: true,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_replay_protection_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "replay_key": self.replay_key,
            "domain": self.domain,
            "subject_id": self.subject_id,
            "nullifier_root": self.nullifier_root,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed,
        })
    }

    pub fn entry_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-REPLAY-PROTECTION-ENTRY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.replay_key, "replay key")?;
        ensure_non_empty(&self.domain, "replay domain")?;
        ensure_non_empty(&self.subject_id, "replay subject")?;
        ensure_non_empty(&self.nullifier_root, "replay nullifier")?;
        if self.expires_at_height <= self.first_seen_height {
            return Err("replay entry expiry precedes first seen height".to_string());
        }
        let expected = replay_protection_key(&self.domain, &self.subject_id, &self.nullifier_root);
        if expected != self.replay_key {
            return Err("replay key mismatch".to_string());
        }
        Ok(self.entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSettlementAnchor {
    pub anchor_id: String,
    pub network: String,
    pub lane_id: String,
    pub asset_id: String,
    pub monero_block_height: u64,
    pub monero_block_hash_root: String,
    pub l2_state_root: String,
    pub deposit_root: String,
    pub withdrawal_root: String,
    pub reserve_spend_root: String,
    pub fee_plan_root: String,
    pub pq_approval_root: String,
    pub published_at_height: u64,
    pub finality_depth: u64,
    pub status: SettlementAnchorStatus,
}

impl MoneroSettlementAnchor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: &str,
        lane_id: &str,
        asset_id: &str,
        monero_block_height: u64,
        l2_state_root: &str,
        published_at_height: u64,
        finality_depth: u64,
    ) -> ShieldedAssetBridgeResult<Self> {
        ensure_non_empty(network, "settlement anchor network")?;
        ensure_non_empty(lane_id, "settlement anchor lane")?;
        ensure_non_empty(asset_id, "settlement anchor asset")?;
        ensure_non_empty(l2_state_root, "settlement anchor l2 state root")?;
        ensure_positive(monero_block_height, "settlement anchor monero block height")?;
        ensure_positive(finality_depth, "settlement anchor finality depth")?;
        let monero_block_hash_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-MONERO-BLOCK-HASH",
            &format!("{network}:{monero_block_height}"),
        );
        let deposit_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ANCHOR-DEPOSIT",
            &format!("{lane_id}:{asset_id}:{monero_block_height}"),
        );
        let withdrawal_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ANCHOR-WITHDRAWAL",
            &format!("{lane_id}:{asset_id}:{published_at_height}"),
        );
        let reserve_spend_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ANCHOR-RESERVE-SPEND",
            &format!("{network}:{asset_id}:{published_at_height}"),
        );
        let fee_plan_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ANCHOR-FEE-PLAN",
            &format!("{lane_id}:{published_at_height}"),
        );
        let pq_approval_root = shielded_asset_bridge_string_root(
            "SHIELDED-ASSET-BRIDGE-ANCHOR-PQ-APPROVAL",
            &format!("{lane_id}:{asset_id}:{l2_state_root}"),
        );
        let anchor_id = monero_anchor_id(
            network,
            lane_id,
            asset_id,
            &monero_block_hash_root,
            published_at_height,
        );
        let anchor = Self {
            anchor_id,
            network: network.to_string(),
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            monero_block_height,
            monero_block_hash_root,
            l2_state_root: l2_state_root.to_string(),
            deposit_root,
            withdrawal_root,
            reserve_spend_root,
            fee_plan_root,
            pq_approval_root,
            published_at_height,
            finality_depth,
            status: SettlementAnchorStatus::Published,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_monero_settlement_anchor",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "anchor_id": self.anchor_id,
            "network": self.network,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash_root": self.monero_block_hash_root,
            "l2_state_root": self.l2_state_root,
            "deposit_root": self.deposit_root,
            "withdrawal_root": self.withdrawal_root,
            "reserve_spend_root": self.reserve_spend_root,
            "fee_plan_root": self.fee_plan_root,
            "pq_approval_root": self.pq_approval_root,
            "published_at_height": self.published_at_height,
            "finality_depth": self.finality_depth,
            "status": self.status.as_str(),
        })
    }

    pub fn anchor_root(&self) -> String {
        shielded_asset_bridge_payload_root(
            "SHIELDED-ASSET-BRIDGE-MONERO-SETTLEMENT-ANCHOR",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        ensure_non_empty(&self.anchor_id, "settlement anchor id")?;
        ensure_non_empty(&self.network, "settlement anchor network")?;
        ensure_non_empty(&self.lane_id, "settlement anchor lane")?;
        ensure_non_empty(&self.asset_id, "settlement anchor asset")?;
        ensure_positive(self.monero_block_height, "settlement anchor monero height")?;
        ensure_non_empty(&self.monero_block_hash_root, "settlement anchor block root")?;
        ensure_non_empty(&self.l2_state_root, "settlement anchor l2 state root")?;
        ensure_non_empty(&self.deposit_root, "settlement anchor deposit root")?;
        ensure_non_empty(&self.withdrawal_root, "settlement anchor withdrawal root")?;
        ensure_non_empty(
            &self.reserve_spend_root,
            "settlement anchor reserve spend root",
        )?;
        ensure_non_empty(&self.fee_plan_root, "settlement anchor fee plan root")?;
        ensure_non_empty(&self.pq_approval_root, "settlement anchor pq approval root")?;
        ensure_positive(self.finality_depth, "settlement anchor finality depth")?;
        let expected = monero_anchor_id(
            &self.network,
            &self.lane_id,
            &self.asset_id,
            &self.monero_block_hash_root,
            self.published_at_height,
        );
        if expected != self.anchor_id {
            return Err("settlement anchor id mismatch".to_string());
        }
        Ok(self.anchor_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAssetBridgeRoots {
    pub config_root: String,
    pub wrapped_asset_root: String,
    pub confidential_lane_root: String,
    pub private_intent_root: String,
    pub reserve_proof_root: String,
    pub pq_approval_root: String,
    pub low_fee_sponsorship_root: String,
    pub risk_bucket_root: String,
    pub contract_hook_root: String,
    pub replay_protection_root: String,
    pub settlement_anchor_root: String,
}

impl ShieldedAssetBridgeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "wrapped_asset_root": self.wrapped_asset_root,
            "confidential_lane_root": self.confidential_lane_root,
            "private_intent_root": self.private_intent_root,
            "reserve_proof_root": self.reserve_proof_root,
            "pq_approval_root": self.pq_approval_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "risk_bucket_root": self.risk_bucket_root,
            "contract_hook_root": self.contract_hook_root,
            "replay_protection_root": self.replay_protection_root,
            "settlement_anchor_root": self.settlement_anchor_root,
        })
    }

    pub fn aggregate_root(&self) -> String {
        shielded_asset_bridge_payload_root("SHIELDED-ASSET-BRIDGE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAssetBridgeCounters {
    pub wrapped_asset_count: u64,
    pub active_wrapped_asset_count: u64,
    pub confidential_lane_count: u64,
    pub active_confidential_lane_count: u64,
    pub private_intent_count: u64,
    pub open_private_intent_count: u64,
    pub executed_private_intent_count: u64,
    pub reserve_proof_count: u64,
    pub pq_approval_count: u64,
    pub live_pq_approval_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub risk_bucket_count: u64,
    pub active_risk_bucket_count: u64,
    pub contract_hook_count: u64,
    pub active_contract_hook_count: u64,
    pub replay_entry_count: u64,
    pub consumed_replay_entry_count: u64,
    pub settlement_anchor_count: u64,
    pub live_settlement_anchor_count: u64,
}

impl ShieldedAssetBridgeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_bridge_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "wrapped_asset_count": self.wrapped_asset_count,
            "active_wrapped_asset_count": self.active_wrapped_asset_count,
            "confidential_lane_count": self.confidential_lane_count,
            "active_confidential_lane_count": self.active_confidential_lane_count,
            "private_intent_count": self.private_intent_count,
            "open_private_intent_count": self.open_private_intent_count,
            "executed_private_intent_count": self.executed_private_intent_count,
            "reserve_proof_count": self.reserve_proof_count,
            "pq_approval_count": self.pq_approval_count,
            "live_pq_approval_count": self.live_pq_approval_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "risk_bucket_count": self.risk_bucket_count,
            "active_risk_bucket_count": self.active_risk_bucket_count,
            "contract_hook_count": self.contract_hook_count,
            "active_contract_hook_count": self.active_contract_hook_count,
            "replay_entry_count": self.replay_entry_count,
            "consumed_replay_entry_count": self.consumed_replay_entry_count,
            "settlement_anchor_count": self.settlement_anchor_count,
            "live_settlement_anchor_count": self.live_settlement_anchor_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAssetBridgeState {
    pub height: u64,
    pub config: ShieldedAssetBridgeConfig,
    pub wrapped_assets: BTreeMap<String, WrappedAssetRecord>,
    pub confidential_lanes: BTreeMap<String, ConfidentialTokenLane>,
    pub private_intents: BTreeMap<String, PrivateMintBurnIntent>,
    pub reserve_proofs: BTreeMap<String, ReserveBackedIssuanceProof>,
    pub pq_approvals: BTreeMap<String, PqBridgeApproval>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeMintSponsorship>,
    pub risk_buckets: BTreeMap<String, BridgeRiskBucket>,
    pub contract_hooks: BTreeMap<String, PrivateContractAssetHook>,
    pub replay_protection: BTreeMap<String, ReplayProtectionEntry>,
    pub settlement_anchors: BTreeMap<String, MoneroSettlementAnchor>,
}

impl ShieldedAssetBridgeState {
    pub fn devnet() -> ShieldedAssetBridgeResult<Self> {
        let height = SHIELDED_ASSET_BRIDGE_DEVNET_HEIGHT;
        let config = ShieldedAssetBridgeConfig::devnet();
        let wxmr = WrappedAssetRecord::new(
            "WXMR",
            "Wrapped Monero",
            12,
            WrappedAssetKind::WrappedMonero,
            "xmr",
            SHIELDED_ASSET_BRIDGE_MONERO_NETWORK,
            "devnet-monero-bridge-issuer",
            height,
        )?;
        let pxmr = WrappedAssetRecord::new(
            "PXMR",
            "Private Wrapped Monero",
            12,
            WrappedAssetKind::ConfidentialMonero,
            "xmr",
            SHIELDED_ASSET_BRIDGE_MONERO_NETWORK,
            "devnet-confidential-bridge-issuer",
            height,
        )?;
        let pusd = WrappedAssetRecord::new(
            "PUSD",
            "Private Bridge Dollar",
            6,
            WrappedAssetKind::ConfidentialStable,
            "usdd-devnet",
            "nebula-devnet",
            "devnet-private-dollar-issuer",
            height,
        )?;

        let mint_lane = ConfidentialTokenLane::new(
            "devnet-pxmr-confidential-mint",
            BridgeLaneKind::ConfidentialMint,
            &pxmr.asset_id,
            SHIELDED_ASSET_BRIDGE_PXMR_ASSET_ID,
            720,
            25_000_000_000_000,
            0,
            true,
        )?;
        let burn_lane = ConfidentialTokenLane::new(
            "devnet-pxmr-confidential-burn",
            BridgeLaneKind::ConfidentialBurn,
            &pxmr.asset_id,
            SHIELDED_ASSET_BRIDGE_PXMR_ASSET_ID,
            720,
            0,
            20_000_000_000_000,
            true,
        )?;
        let contract_lane = ConfidentialTokenLane::new(
            "devnet-contract-asset-hook-lane",
            BridgeLaneKind::PrivateContract,
            &pusd.asset_id,
            SHIELDED_ASSET_BRIDGE_USDD_ASSET_ID,
            720,
            10_000_000_000,
            10_000_000_000,
            false,
        )?;

        let observers = vec![
            "devnet-monero-watchtower-0".to_string(),
            "devnet-monero-watchtower-1".to_string(),
            "devnet-reserve-auditor-0".to_string(),
        ];
        let reserve_proof = ReserveBackedIssuanceProof::new(
            &pxmr.asset_id,
            &mint_lane.lane_id,
            SHIELDED_ASSET_BRIDGE_MONERO_NETWORK,
            &observers,
            10_450,
            height,
            height.saturating_add(720),
        )?;

        let approvers = vec![
            "devnet-bridge-council-ml-dsa-0".to_string(),
            "devnet-bridge-council-ml-dsa-1".to_string(),
            "devnet-watchtower-slh-dsa-0".to_string(),
        ];
        let approval = PqBridgeApproval::new(
            "private_intent",
            "devnet-bootstrap-mint",
            "approve_reserve_backed_mint",
            &approvers,
            3,
            3,
            256,
            height,
            height.saturating_add(144),
        )?;

        let mut mint_intent = PrivateMintBurnIntent::new(
            &mint_lane.lane_id,
            &pxmr.asset_id,
            PrivateBridgeIntentKind::Mint,
            "devnet-alice-shielded-account",
            "mint-1250000000000-piconero",
            "devnet-alice-pxmr-note",
            height,
            config.intent_ttl_blocks,
            1,
        )?;
        mint_intent.reserve_proof_id = reserve_proof.proof_id.clone();
        mint_intent.pq_approval_id = approval.approval_id.clone();
        mint_intent.status = PrivateBridgeIntentStatus::Approved;
        mint_intent.validate()?;

        let mut burn_intent = PrivateMintBurnIntent::new(
            &burn_lane.lane_id,
            &pxmr.asset_id,
            PrivateBridgeIntentKind::Burn,
            "devnet-bob-shielded-account",
            "burn-420000000000-piconero",
            "monero-subaddress-bob-devnet",
            height.saturating_add(1),
            config.intent_ttl_blocks,
            2,
        )?;
        burn_intent.status = PrivateBridgeIntentStatus::Requested;
        burn_intent.validate()?;

        let sponsorship = LowFeeMintSponsorship::new(
            &mint_lane.lane_id,
            &pxmr.asset_id,
            "devnet-bridge-paymaster",
            &config.default_fee_asset_id,
            2_000_000_000_000,
            50_000,
            8_500,
            height,
            height.saturating_add(config.sponsor_ttl_blocks),
        )?;
        mint_intent.sponsorship_id = sponsorship.sponsorship_id.clone();
        mint_intent.status = PrivateBridgeIntentStatus::Sponsored;
        mint_intent.validate()?;

        let retail_bucket = BridgeRiskBucket::new(
            &mint_lane.lane_id,
            RiskBucketKind::Retail,
            1,
            2_000_000_000_000,
            RiskAction::SponsorOnly,
            0,
            12_000_000_000_000,
            128,
            2_500,
        )?;
        let whale_bucket = BridgeRiskBucket::new(
            &mint_lane.lane_id,
            RiskBucketKind::Whale,
            2_000_000_000_001,
            0,
            RiskAction::RequirePqApproval,
            12,
            50_000_000_000_000,
            16,
            7_500,
        )?;
        let emergency_bucket = BridgeRiskBucket::new(
            &burn_lane.lane_id,
            RiskBucketKind::Emergency,
            1,
            0,
            RiskAction::DelaySettlement,
            36,
            10_000_000_000_000,
            64,
            6_000,
        )?;

        let mut hook_phases = BTreeSet::new();
        hook_phases.insert(ContractHookPhase::BeforeMint);
        hook_phases.insert(ContractHookPhase::AfterBurn);
        hook_phases.insert(ContractHookPhase::BeforeSettlement);
        let contract_hook = PrivateContractAssetHook::new(
            "devnet-private-vault-contract",
            &contract_lane.lane_id,
            &pusd.asset_id,
            hook_phases,
            500_000,
            RiskAction::DelaySettlement,
        )?;

        let replay_entry = ReplayProtectionEntry::new(
            &config.replay_domain,
            &mint_intent.intent_id,
            &mint_intent.source_nullifier_root,
            height,
            height.saturating_add(config.replay_window_blocks),
        )?;

        let anchor = MoneroSettlementAnchor::new(
            SHIELDED_ASSET_BRIDGE_MONERO_NETWORK,
            &mint_lane.lane_id,
            &pxmr.asset_id,
            2_401_920,
            &reserve_proof.proof_root(),
            height,
            config.monero_finality_depth,
        )?;

        let mut state = Self {
            height,
            config,
            wrapped_assets: BTreeMap::new(),
            confidential_lanes: BTreeMap::new(),
            private_intents: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            risk_buckets: BTreeMap::new(),
            contract_hooks: BTreeMap::new(),
            replay_protection: BTreeMap::new(),
            settlement_anchors: BTreeMap::new(),
        };

        state.insert_wrapped_asset(wxmr)?;
        state.insert_wrapped_asset(pxmr)?;
        state.insert_wrapped_asset(pusd)?;
        state.insert_confidential_lane(mint_lane)?;
        state.insert_confidential_lane(burn_lane)?;
        state.insert_confidential_lane(contract_lane)?;
        state.insert_reserve_proof(reserve_proof)?;
        state.insert_pq_approval(approval)?;
        state.insert_low_fee_sponsorship(sponsorship)?;
        state.insert_private_intent(mint_intent)?;
        state.insert_private_intent(burn_intent)?;
        state.insert_risk_bucket(retail_bucket)?;
        state.insert_risk_bucket(whale_bucket)?;
        state.insert_risk_bucket(emergency_bucket)?;
        state.insert_contract_hook(contract_hook)?;
        state.insert_replay_entry(replay_entry)?;
        state.insert_settlement_anchor(anchor)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ShieldedAssetBridgeResult<()> {
        if height < self.height {
            return Err("shielded asset bridge height cannot move backward".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> ShieldedAssetBridgeRoots {
        ShieldedAssetBridgeRoots {
            config_root: self.config.config_root(),
            wrapped_asset_root: wrapped_asset_set_root(&self.wrapped_assets),
            confidential_lane_root: confidential_lane_set_root(&self.confidential_lanes),
            private_intent_root: private_intent_set_root(&self.private_intents),
            reserve_proof_root: reserve_proof_set_root(&self.reserve_proofs),
            pq_approval_root: pq_approval_set_root(&self.pq_approvals),
            low_fee_sponsorship_root: low_fee_sponsorship_set_root(&self.low_fee_sponsorships),
            risk_bucket_root: risk_bucket_set_root(&self.risk_buckets),
            contract_hook_root: contract_hook_set_root(&self.contract_hooks),
            replay_protection_root: replay_protection_set_root(&self.replay_protection),
            settlement_anchor_root: settlement_anchor_set_root(&self.settlement_anchors),
        }
    }

    pub fn counters(&self) -> ShieldedAssetBridgeCounters {
        ShieldedAssetBridgeCounters {
            wrapped_asset_count: self.wrapped_assets.len() as u64,
            active_wrapped_asset_count: self
                .wrapped_assets
                .values()
                .filter(|asset| asset.status.is_live())
                .count() as u64,
            confidential_lane_count: self.confidential_lanes.len() as u64,
            active_confidential_lane_count: self
                .confidential_lanes
                .values()
                .filter(|lane| lane.status.is_live())
                .count() as u64,
            private_intent_count: self.private_intents.len() as u64,
            open_private_intent_count: self
                .private_intents
                .values()
                .filter(|intent| intent.status.is_open())
                .count() as u64,
            executed_private_intent_count: self
                .private_intents
                .values()
                .filter(|intent| intent.status == PrivateBridgeIntentStatus::Executed)
                .count() as u64,
            reserve_proof_count: self.reserve_proofs.len() as u64,
            pq_approval_count: self.pq_approvals.len() as u64,
            live_pq_approval_count: self
                .pq_approvals
                .values()
                .filter(|approval| approval.status.is_live())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.active)
                .count() as u64,
            risk_bucket_count: self.risk_buckets.len() as u64,
            active_risk_bucket_count: self
                .risk_buckets
                .values()
                .filter(|bucket| bucket.active)
                .count() as u64,
            contract_hook_count: self.contract_hooks.len() as u64,
            active_contract_hook_count: self
                .contract_hooks
                .values()
                .filter(|hook| hook.active)
                .count() as u64,
            replay_entry_count: self.replay_protection.len() as u64,
            consumed_replay_entry_count: self
                .replay_protection
                .values()
                .filter(|entry| entry.consumed)
                .count() as u64,
            settlement_anchor_count: self.settlement_anchors.len() as u64,
            live_settlement_anchor_count: self
                .settlement_anchors
                .values()
                .filter(|anchor| anchor.status.is_live())
                .count() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        shielded_asset_bridge_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> ShieldedAssetBridgeResult<String> {
        self.config.validate()?;
        ensure_map_keys_match(
            &self.wrapped_assets,
            |asset| &asset.asset_id,
            "wrapped asset",
        )?;
        ensure_map_keys_match(
            &self.confidential_lanes,
            |lane| &lane.lane_id,
            "confidential lane",
        )?;
        ensure_map_keys_match(
            &self.private_intents,
            |intent| &intent.intent_id,
            "private intent",
        )?;
        ensure_map_keys_match(
            &self.reserve_proofs,
            |proof| &proof.proof_id,
            "reserve proof",
        )?;
        ensure_map_keys_match(
            &self.pq_approvals,
            |approval| &approval.approval_id,
            "pq approval",
        )?;
        ensure_map_keys_match(
            &self.low_fee_sponsorships,
            |sponsorship| &sponsorship.sponsorship_id,
            "low fee sponsorship",
        )?;
        ensure_map_keys_match(
            &self.risk_buckets,
            |bucket| &bucket.bucket_id,
            "risk bucket",
        )?;
        ensure_map_keys_match(&self.contract_hooks, |hook| &hook.hook_id, "contract hook")?;
        ensure_map_keys_match(
            &self.replay_protection,
            |entry| &entry.replay_key,
            "replay entry",
        )?;
        ensure_map_keys_match(
            &self.settlement_anchors,
            |anchor| &anchor.anchor_id,
            "settlement anchor",
        )?;

        for asset in self.wrapped_assets.values() {
            asset.validate()?;
        }
        for lane in self.confidential_lanes.values() {
            lane.validate()?;
            ensure_state_asset(&self.wrapped_assets, &lane.asset_id, "confidential lane")?;
        }
        for proof in self.reserve_proofs.values() {
            proof.validate()?;
            ensure_state_asset(&self.wrapped_assets, &proof.asset_id, "reserve proof")?;
            ensure_state_lane(&self.confidential_lanes, &proof.lane_id, "reserve proof")?;
            if proof.coverage_bps < self.config.min_reserve_coverage_bps {
                return Err("reserve proof coverage below configured minimum".to_string());
            }
        }
        for approval in self.pq_approvals.values() {
            approval.validate()?;
            if approval.security_bits < self.config.min_pq_security_bits {
                return Err("pq bridge approval below configured security floor".to_string());
            }
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
            ensure_state_asset(
                &self.wrapped_assets,
                &sponsorship.asset_id,
                "low fee sponsorship",
            )?;
            let lane = ensure_state_lane(
                &self.confidential_lanes,
                &sponsorship.lane_id,
                "low fee sponsorship",
            )?;
            if !lane.low_fee_eligible {
                return Err("low fee sponsorship references ineligible lane".to_string());
            }
        }
        for intent in self.private_intents.values() {
            intent.validate()?;
            ensure_state_asset(&self.wrapped_assets, &intent.asset_id, "private intent")?;
            let lane =
                ensure_state_lane(&self.confidential_lanes, &intent.lane_id, "private intent")?;
            if matches!(intent.kind, PrivateBridgeIntentKind::Mint)
                && !lane.lane_kind.mint_capable()
            {
                return Err("mint intent references non-mint lane".to_string());
            }
            if matches!(intent.kind, PrivateBridgeIntentKind::Burn)
                && !lane.lane_kind.burn_capable()
            {
                return Err("burn intent references non-burn lane".to_string());
            }
            if !intent.reserve_proof_id.is_empty()
                && !self.reserve_proofs.contains_key(&intent.reserve_proof_id)
            {
                return Err("private intent references missing reserve proof".to_string());
            }
            if !intent.pq_approval_id.is_empty()
                && !self.pq_approvals.contains_key(&intent.pq_approval_id)
            {
                return Err("private intent references missing pq approval".to_string());
            }
            if !intent.sponsorship_id.is_empty()
                && !self
                    .low_fee_sponsorships
                    .contains_key(&intent.sponsorship_id)
            {
                return Err("private intent references missing sponsorship".to_string());
            }
        }
        for bucket in self.risk_buckets.values() {
            bucket.validate()?;
            ensure_state_lane(&self.confidential_lanes, &bucket.lane_id, "risk bucket")?;
            if bucket.risk_score_bps >= self.config.risk_pause_threshold_bps
                && bucket.action == RiskAction::Allow
            {
                return Err("high risk bucket cannot be allow-only".to_string());
            }
        }
        for hook in self.contract_hooks.values() {
            hook.validate()?;
            ensure_state_asset(&self.wrapped_assets, &hook.asset_id, "contract hook")?;
            ensure_state_lane(&self.confidential_lanes, &hook.lane_id, "contract hook")?;
        }
        if self.counters().active_contract_hook_count > self.config.max_active_contract_hooks {
            return Err("active contract hook count exceeds configured maximum".to_string());
        }
        if self.counters().open_private_intent_count > self.config.max_open_intents {
            return Err("open private intent count exceeds configured maximum".to_string());
        }
        for entry in self.replay_protection.values() {
            entry.validate()?;
            if !self.private_intents.contains_key(&entry.subject_id) {
                return Err("replay entry references missing private intent".to_string());
            }
        }
        for anchor in self.settlement_anchors.values() {
            anchor.validate()?;
            ensure_state_asset(&self.wrapped_assets, &anchor.asset_id, "settlement anchor")?;
            ensure_state_lane(
                &self.confidential_lanes,
                &anchor.lane_id,
                "settlement anchor",
            )?;
            if anchor.finality_depth < self.config.monero_finality_depth {
                return Err("settlement anchor finality below configured depth".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn insert_wrapped_asset(&mut self, asset: WrappedAssetRecord) -> ShieldedAssetBridgeResult<()> {
        asset.validate()?;
        self.wrapped_assets.insert(asset.asset_id.clone(), asset);
        Ok(())
    }

    fn insert_confidential_lane(
        &mut self,
        lane: ConfidentialTokenLane,
    ) -> ShieldedAssetBridgeResult<()> {
        lane.validate()?;
        if !self.wrapped_assets.contains_key(&lane.asset_id) {
            return Err("confidential lane references missing asset".to_string());
        }
        self.confidential_lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    fn insert_private_intent(
        &mut self,
        intent: PrivateMintBurnIntent,
    ) -> ShieldedAssetBridgeResult<()> {
        intent.validate()?;
        self.private_intents
            .insert(intent.intent_id.clone(), intent);
        Ok(())
    }

    fn insert_reserve_proof(
        &mut self,
        proof: ReserveBackedIssuanceProof,
    ) -> ShieldedAssetBridgeResult<()> {
        proof.validate()?;
        self.reserve_proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    fn insert_pq_approval(&mut self, approval: PqBridgeApproval) -> ShieldedAssetBridgeResult<()> {
        approval.validate()?;
        self.pq_approvals
            .insert(approval.approval_id.clone(), approval);
        Ok(())
    }

    fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeMintSponsorship,
    ) -> ShieldedAssetBridgeResult<()> {
        sponsorship.validate()?;
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    fn insert_risk_bucket(&mut self, bucket: BridgeRiskBucket) -> ShieldedAssetBridgeResult<()> {
        bucket.validate()?;
        self.risk_buckets.insert(bucket.bucket_id.clone(), bucket);
        Ok(())
    }

    fn insert_contract_hook(
        &mut self,
        hook: PrivateContractAssetHook,
    ) -> ShieldedAssetBridgeResult<()> {
        hook.validate()?;
        self.contract_hooks.insert(hook.hook_id.clone(), hook);
        Ok(())
    }

    fn insert_replay_entry(
        &mut self,
        entry: ReplayProtectionEntry,
    ) -> ShieldedAssetBridgeResult<()> {
        entry.validate()?;
        self.replay_protection
            .insert(entry.replay_key.clone(), entry);
        Ok(())
    }

    fn insert_settlement_anchor(
        &mut self,
        anchor: MoneroSettlementAnchor,
    ) -> ShieldedAssetBridgeResult<()> {
        anchor.validate()?;
        self.settlement_anchors
            .insert(anchor.anchor_id.clone(), anchor);
        Ok(())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "shielded_asset_bridge_state",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_ASSET_BRIDGE_PROTOCOL_VERSION,
            "protocol_label": SHIELDED_ASSET_BRIDGE_PROTOCOL_LABEL,
            "height": self.height,
            "monero_network": self.config.monero_network,
            "default_fee_asset_id": self.config.default_fee_asset_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.aggregate_root(),
            "counters": counters.public_record(),
            "active_asset_ids": self.active_asset_ids(),
            "active_lane_ids": self.active_lane_ids(),
            "open_intent_ids": self.open_intent_ids(),
            "live_anchor_ids": self.live_anchor_ids(),
        })
    }

    fn active_asset_ids(&self) -> Vec<String> {
        self.wrapped_assets
            .values()
            .filter(|asset| asset.status.is_live())
            .map(|asset| asset.asset_id.clone())
            .collect()
    }

    fn active_lane_ids(&self) -> Vec<String> {
        self.confidential_lanes
            .values()
            .filter(|lane| lane.status.is_live())
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    fn open_intent_ids(&self) -> Vec<String> {
        self.private_intents
            .values()
            .filter(|intent| intent.status.is_open())
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    fn live_anchor_ids(&self) -> Vec<String> {
        self.settlement_anchors
            .values()
            .filter(|anchor| anchor.status.is_live())
            .map(|anchor| anchor.anchor_id.clone())
            .collect()
    }
}

pub fn shielded_asset_bridge_state_root_from_record(record: &Value) -> String {
    shielded_asset_bridge_payload_root("SHIELDED-ASSET-BRIDGE-STATE", record)
}

pub fn shielded_asset_bridge_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn shielded_asset_bridge_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn wrapped_asset_id(
    symbol: &str,
    decimals: u8,
    asset_kind: WrappedAssetKind,
    reserve_asset_id: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-WRAPPED-ASSET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(symbol),
            HashPart::Int(decimals as i128),
            HashPart::Str(asset_kind.as_str()),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_lane_id(
    label: &str,
    lane_kind: BridgeLaneKind,
    asset_id: &str,
    confidential_class_id: &str,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-CONFIDENTIAL-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Str(confidential_class_id),
        ],
        32,
    )
}

pub fn replay_key_for_intent(
    lane_id: &str,
    asset_id: &str,
    kind: PrivateBridgeIntentKind,
    owner_commitment: &str,
    amount_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-INTENT-REPLAY-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SHIELDED_ASSET_BRIDGE_DEFAULT_REPLAY_DOMAIN),
            HashPart::Str(lane_id),
            HashPart::Str(asset_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_intent_id(
    lane_id: &str,
    asset_id: &str,
    kind: PrivateBridgeIntentKind,
    replay_key: &str,
    requested_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-PRIVATE-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(asset_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(replay_key),
            HashPart::Int(requested_at_height as i128),
        ],
        32,
    )
}

pub fn reserve_proof_id(
    asset_id: &str,
    lane_id: &str,
    reserve_tx_root: &str,
    liability_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-RESERVE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_id),
            HashPart::Str(lane_id),
            HashPart::Str(reserve_tx_root),
            HashPart::Str(liability_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn pq_approval_id(
    subject_kind: &str,
    subject_id: &str,
    action: &str,
    approval_transcript_root: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-PQ-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(action),
            HashPart::Str(approval_transcript_root),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn mint_sponsorship_id(
    lane_id: &str,
    asset_id: &str,
    sponsor_commitment: &str,
    budget_commitment: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-MINT-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(asset_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(budget_commitment),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn risk_bucket_id(
    lane_id: &str,
    bucket_kind: RiskBucketKind,
    min_amount_units: u64,
    max_amount_units: u64,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-RISK-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_kind.as_str()),
            HashPart::Int(min_amount_units as i128),
            HashPart::Int(max_amount_units as i128),
        ],
        32,
    )
}

pub fn contract_hook_id(
    contract_id: &str,
    lane_id: &str,
    asset_id: &str,
    phase_root: &str,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-CONTRACT-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(lane_id),
            HashPart::Str(asset_id),
            HashPart::Str(phase_root),
        ],
        32,
    )
}

pub fn replay_protection_key(domain: &str, subject_id: &str, nullifier_root: &str) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-REPLAY-PROTECTION-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn monero_anchor_id(
    network: &str,
    lane_id: &str,
    asset_id: &str,
    monero_block_hash_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-ASSET-BRIDGE-MONERO-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(network),
            HashPart::Str(lane_id),
            HashPart::Str(asset_id),
            HashPart::Str(monero_block_hash_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn wrapped_asset_set_root(values: &BTreeMap<String, WrappedAssetRecord>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-WRAPPED-ASSET-SET",
        values
            .values()
            .map(|asset| (asset.asset_id.clone(), asset.public_record()))
            .collect(),
    )
}

pub fn confidential_lane_set_root(values: &BTreeMap<String, ConfidentialTokenLane>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-CONFIDENTIAL-LANE-SET",
        values
            .values()
            .map(|lane| (lane.lane_id.clone(), lane.public_record()))
            .collect(),
    )
}

pub fn private_intent_set_root(values: &BTreeMap<String, PrivateMintBurnIntent>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-PRIVATE-INTENT-SET",
        values
            .values()
            .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            .collect(),
    )
}

pub fn reserve_proof_set_root(values: &BTreeMap<String, ReserveBackedIssuanceProof>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-RESERVE-PROOF-SET",
        values
            .values()
            .map(|proof| (proof.proof_id.clone(), proof.public_record()))
            .collect(),
    )
}

pub fn pq_approval_set_root(values: &BTreeMap<String, PqBridgeApproval>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-PQ-APPROVAL-SET",
        values
            .values()
            .map(|approval| (approval.approval_id.clone(), approval.public_record()))
            .collect(),
    )
}

pub fn low_fee_sponsorship_set_root(values: &BTreeMap<String, LowFeeMintSponsorship>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-LOW-FEE-SPONSORSHIP-SET",
        values
            .values()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn risk_bucket_set_root(values: &BTreeMap<String, BridgeRiskBucket>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-RISK-BUCKET-SET",
        values
            .values()
            .map(|bucket| (bucket.bucket_id.clone(), bucket.public_record()))
            .collect(),
    )
}

pub fn contract_hook_set_root(values: &BTreeMap<String, PrivateContractAssetHook>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-CONTRACT-HOOK-SET",
        values
            .values()
            .map(|hook| (hook.hook_id.clone(), hook.public_record()))
            .collect(),
    )
}

pub fn replay_protection_set_root(values: &BTreeMap<String, ReplayProtectionEntry>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-REPLAY-PROTECTION-SET",
        values
            .values()
            .map(|entry| (entry.replay_key.clone(), entry.public_record()))
            .collect(),
    )
}

pub fn settlement_anchor_set_root(values: &BTreeMap<String, MoneroSettlementAnchor>) -> String {
    keyed_record_root(
        "SHIELDED-ASSET-BRIDGE-SETTLEMENT-ANCHOR-SET",
        values
            .values()
            .map(|anchor| (anchor.anchor_id.clone(), anchor.public_record()))
            .collect(),
    )
}

pub fn contract_hook_phase_root(phases: &BTreeSet<ContractHookPhase>) -> String {
    merkle_root(
        "SHIELDED-ASSET-BRIDGE-CONTRACT-HOOK-PHASE",
        &phases
            .iter()
            .map(|phase| {
                json!({
                    "kind": "shielded_asset_bridge_contract_hook_phase",
                    "chain_id": CHAIN_ID,
                    "phase": phase.as_str(),
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(key, record)| {
                json!({
                    "key": key,
                    "record": record,
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    merkle_root(
        domain,
        &sorted
            .iter()
            .map(|value| {
                json!({
                    "kind": "shielded_asset_bridge_string_member",
                    "chain_id": CHAIN_ID,
                    "value": value,
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(value: &str, label: &str) -> ShieldedAssetBridgeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ShieldedAssetBridgeResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ShieldedAssetBridgeResult<()> {
    if value > SHIELDED_ASSET_BRIDGE_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_map_keys_match<T, F>(
    values: &BTreeMap<String, T>,
    id: F,
    label: &str,
) -> ShieldedAssetBridgeResult<()>
where
    F: Fn(&T) -> &String,
{
    for (key, value) in values {
        if key != id(value) {
            return Err(format!("{label} map key mismatch"));
        }
    }
    Ok(())
}

fn ensure_state_asset<'a>(
    assets: &'a BTreeMap<String, WrappedAssetRecord>,
    asset_id: &str,
    label: &str,
) -> ShieldedAssetBridgeResult<&'a WrappedAssetRecord> {
    assets
        .get(asset_id)
        .ok_or_else(|| format!("{label} references unknown wrapped asset"))
}

fn ensure_state_lane<'a>(
    lanes: &'a BTreeMap<String, ConfidentialTokenLane>,
    lane_id: &str,
    label: &str,
) -> ShieldedAssetBridgeResult<&'a ConfidentialTokenLane> {
    lanes
        .get(lane_id)
        .ok_or_else(|| format!("{label} references unknown confidential lane"))
}

fn normalize_symbol(symbol: &str) -> String {
    symbol.trim().to_ascii_uppercase()
}

fn normalize_label(label: &str) -> String {
    label.trim().to_ascii_lowercase().replace([' ', '_'], "-")
}

#[allow(dead_code)]
fn object_with_state_root(mut record: Map<String, Value>, state_root: String) -> Value {
    record.insert("state_root".to_string(), Value::String(state_root));
    Value::Object(record)
}
