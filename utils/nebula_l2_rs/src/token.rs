use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type TokenResult<T> = Result<T, String>;

pub const TOKEN_PROTOCOL_VERSION: &str = "nebula-l2-token-v1";
pub const TOKEN_NATIVE_XMR_SYMBOL: &str = "XMR";
pub const TOKEN_NATIVE_XMR_DISPLAY_NAME: &str = "Bridged Monero";
pub const TOKEN_NATIVE_XMR_DECIMALS: u8 = 12;
pub const TOKEN_NATIVE_XMR_NETWORK: &str = "monero-mainnet";
pub const TOKEN_NATIVE_XMR_RESERVE_POLICY: &str = "full-reserve-monero-attested";
pub const TOKEN_NATIVE_XMR_METADATA_BLINDING: &str = "nebula-native-xmr-metadata";
pub const TOKEN_DEFAULT_GOVERNANCE_SCOPE: &str = "token_registry";
pub const TOKEN_DEFAULT_ISSUER_LABEL: &str = "nebula-bridge-governance";
pub const TOKEN_DEFAULT_TRANSFER_POLICY_LABEL: &str = "default-confidential-transfer";
pub const TOKEN_STATUS_ACTIVE: &str = "active";
pub const TOKEN_STATUS_SUSPENDED: &str = "suspended";
pub const TOKEN_STATUS_RETIRED: &str = "retired";
pub const TOKEN_STATUS_FROZEN: &str = "frozen";
pub const TOKEN_RESERVE_STATUS_VALID: &str = "valid";
pub const TOKEN_RESERVE_STATUS_INSUFFICIENT: &str = "insufficient";
pub const TOKEN_RESERVE_STATUS_STALE: &str = "stale";
pub const TOKEN_RESERVE_STATUS_REVOKED: &str = "revoked";
pub const TOKEN_MAX_SYMBOL_LEN: usize = 16;
pub const TOKEN_MAX_RISK_FLAGS: usize = 32;
pub const TOKEN_MAX_TRANSFER_POLICY_LIST_ITEMS: usize = 256;
pub const TOKEN_MAX_LOW_FEE_REBATE_BPS: u64 = 10_000;
pub const TOKEN_MIN_MONERO_FINALITY_DEPTH: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenKind {
    NativeBridgedXmr,
    WrappedMonero,
    Confidential,
    Governance,
    Utility,
    Liquidity,
    Custom(String),
}

impl TokenKind {
    pub fn as_str(&self) -> String {
        match self {
            TokenKind::NativeBridgedXmr => "native_bridged_xmr".to_string(),
            TokenKind::WrappedMonero => "wrapped_monero".to_string(),
            TokenKind::Confidential => "confidential".to_string(),
            TokenKind::Governance => "governance".to_string(),
            TokenKind::Utility => "utility".to_string(),
            TokenKind::Liquidity => "liquidity".to_string(),
            TokenKind::Custom(value) => value.clone(),
        }
    }

    pub fn requires_monero_reserve(&self) -> bool {
        matches!(self, Self::NativeBridgedXmr | Self::WrappedMonero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_kind",
            "chain_id": CHAIN_ID,
            "token_kind": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenSupplyPolicy {
    Fixed,
    MintBurn,
    CappedMintBurn,
    BridgeMintBurn,
    WrappedReserve,
    GovernanceControlled,
}

impl TokenSupplyPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenSupplyPolicy::Fixed => "fixed",
            TokenSupplyPolicy::MintBurn => "mint_burn",
            TokenSupplyPolicy::CappedMintBurn => "capped_mint_burn",
            TokenSupplyPolicy::BridgeMintBurn => "bridge_mint_burn",
            TokenSupplyPolicy::WrappedReserve => "wrapped_reserve",
            TokenSupplyPolicy::GovernanceControlled => "governance_controlled",
        }
    }

    pub fn allows_mint(&self) -> bool {
        matches!(
            self,
            Self::MintBurn
                | Self::CappedMintBurn
                | Self::BridgeMintBurn
                | Self::WrappedReserve
                | Self::GovernanceControlled
        )
    }

    pub fn allows_burn(&self) -> bool {
        matches!(
            self,
            Self::MintBurn
                | Self::CappedMintBurn
                | Self::BridgeMintBurn
                | Self::WrappedReserve
                | Self::GovernanceControlled
        )
    }

    pub fn requires_reserve_proof(&self) -> bool {
        matches!(self, Self::BridgeMintBurn | Self::WrappedReserve)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_supply_policy",
            "chain_id": CHAIN_ID,
            "supply_policy": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenRiskFlag {
    ReserveProofMissing,
    ReserveProofInsufficient,
    ReserveProofStale,
    IssuerCentralized,
    MintAuthorityActive,
    BurnAuthorityActive,
    TransferRestricted,
    FeeAssetVolatile,
    LowLiquidity,
    Frozen,
    GovernanceControlled,
    Experimental,
    Custom(String),
}

impl TokenRiskFlag {
    pub fn as_str(&self) -> String {
        match self {
            TokenRiskFlag::ReserveProofMissing => "reserve_proof_missing".to_string(),
            TokenRiskFlag::ReserveProofInsufficient => "reserve_proof_insufficient".to_string(),
            TokenRiskFlag::ReserveProofStale => "reserve_proof_stale".to_string(),
            TokenRiskFlag::IssuerCentralized => "issuer_centralized".to_string(),
            TokenRiskFlag::MintAuthorityActive => "mint_authority_active".to_string(),
            TokenRiskFlag::BurnAuthorityActive => "burn_authority_active".to_string(),
            TokenRiskFlag::TransferRestricted => "transfer_restricted".to_string(),
            TokenRiskFlag::FeeAssetVolatile => "fee_asset_volatile".to_string(),
            TokenRiskFlag::LowLiquidity => "low_liquidity".to_string(),
            TokenRiskFlag::Frozen => "frozen".to_string(),
            TokenRiskFlag::GovernanceControlled => "governance_controlled".to_string(),
            TokenRiskFlag::Experimental => "experimental".to_string(),
            TokenRiskFlag::Custom(value) => value.clone(),
        }
    }

    pub fn blocks_low_fee_eligibility(&self) -> bool {
        matches!(
            self,
            Self::ReserveProofMissing
                | Self::ReserveProofInsufficient
                | Self::ReserveProofStale
                | Self::FeeAssetVolatile
                | Self::Frozen
        )
    }

    pub fn public_record(&self, asset_id: &str) -> Value {
        json!({
            "kind": "token_risk_flag",
            "chain_id": CHAIN_ID,
            "asset_id": asset_id,
            "risk_flag": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMetadataCommitment {
    pub schema_version: String,
    pub metadata_root: String,
    pub display_name_commitment: String,
    pub symbol_commitment: String,
    pub uri_commitment: String,
    pub icon_commitment: String,
    pub audit_commitment: String,
    pub decimals: u8,
    pub confidentiality_level: String,
}

impl TokenMetadataCommitment {
    pub fn confidential(symbol: &str, decimals: u8, metadata: &Value, blinding: &str) -> Self {
        let display_name = metadata
            .get("display_name")
            .or_else(|| metadata.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let uri = metadata
            .get("uri")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let icon = metadata
            .get("icon")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let audit = metadata
            .get("audit")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Self {
            schema_version: TOKEN_PROTOCOL_VERSION.to_string(),
            metadata_root: token_metadata_root(metadata),
            display_name_commitment: token_metadata_field_commitment(
                "display_name",
                display_name,
                blinding,
            ),
            symbol_commitment: token_metadata_field_commitment(
                "symbol",
                &normalize_symbol(symbol),
                blinding,
            ),
            uri_commitment: token_metadata_field_commitment("uri", uri, blinding),
            icon_commitment: token_metadata_field_commitment("icon", icon, blinding),
            audit_commitment: token_metadata_field_commitment("audit", audit, blinding),
            decimals,
            confidentiality_level: "commitment_only".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_metadata_commitment",
            "chain_id": CHAIN_ID,
            "schema_version": self.schema_version,
            "metadata_root": self.metadata_root,
            "display_name_commitment": self.display_name_commitment,
            "symbol_commitment": self.symbol_commitment,
            "uri_commitment": self.uri_commitment,
            "icon_commitment": self.icon_commitment,
            "audit_commitment": self.audit_commitment,
            "decimals": self.decimals,
            "confidentiality_level": self.confidentiality_level,
        })
    }

    pub fn commitment_root(&self) -> String {
        token_metadata_commitment_root(self)
    }

    pub fn validate(&self) -> TokenResult<String> {
        validate_root_like(&self.metadata_root, "token metadata root")?;
        validate_root_like(
            &self.display_name_commitment,
            "token display name commitment",
        )?;
        validate_root_like(&self.symbol_commitment, "token symbol commitment")?;
        validate_root_like(&self.uri_commitment, "token uri commitment")?;
        validate_root_like(&self.icon_commitment, "token icon commitment")?;
        validate_root_like(&self.audit_commitment, "token audit commitment")?;
        if self.schema_version.trim().is_empty() {
            return Err("token metadata schema version cannot be empty".to_string());
        }
        if self.confidentiality_level.trim().is_empty() {
            return Err("token metadata confidentiality level cannot be empty".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintBurnCap {
    pub asset_id: String,
    pub max_supply_units: u64,
    pub lifetime_mint_cap_units: u64,
    pub lifetime_burn_cap_units: u64,
    pub epoch: u64,
    pub epoch_mint_cap_units: u64,
    pub epoch_burn_cap_units: u64,
    pub minted_units: u64,
    pub burned_units: u64,
    pub epoch_minted_units: u64,
    pub epoch_burned_units: u64,
    pub last_updated_height: u64,
}

impl MintBurnCap {
    pub fn uncapped(asset_id: &str, epoch: u64, height: u64) -> Self {
        Self {
            asset_id: asset_id.to_string(),
            max_supply_units: 0,
            lifetime_mint_cap_units: 0,
            lifetime_burn_cap_units: 0,
            epoch,
            epoch_mint_cap_units: 0,
            epoch_burn_cap_units: 0,
            minted_units: 0,
            burned_units: 0,
            epoch_minted_units: 0,
            epoch_burned_units: 0,
            last_updated_height: height,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn capped(
        asset_id: &str,
        max_supply_units: u64,
        lifetime_mint_cap_units: u64,
        lifetime_burn_cap_units: u64,
        epoch: u64,
        epoch_mint_cap_units: u64,
        epoch_burn_cap_units: u64,
        height: u64,
    ) -> Self {
        Self {
            asset_id: asset_id.to_string(),
            max_supply_units,
            lifetime_mint_cap_units,
            lifetime_burn_cap_units,
            epoch,
            epoch_mint_cap_units,
            epoch_burn_cap_units,
            minted_units: 0,
            burned_units: 0,
            epoch_minted_units: 0,
            epoch_burned_units: 0,
            last_updated_height: height,
        }
    }

    pub fn circulating_units(&self) -> u64 {
        self.minted_units.saturating_sub(self.burned_units)
    }

    pub fn remaining_mint_units(&self) -> u64 {
        let lifetime_remaining = cap_remaining(self.lifetime_mint_cap_units, self.minted_units);
        let epoch_remaining = cap_remaining(self.epoch_mint_cap_units, self.epoch_minted_units);
        if self.lifetime_mint_cap_units == 0 {
            epoch_remaining
        } else if self.epoch_mint_cap_units == 0 {
            lifetime_remaining
        } else {
            lifetime_remaining.min(epoch_remaining)
        }
    }

    pub fn remaining_burn_units(&self) -> u64 {
        let lifetime_remaining = cap_remaining(self.lifetime_burn_cap_units, self.burned_units);
        let epoch_remaining = cap_remaining(self.epoch_burn_cap_units, self.epoch_burned_units);
        if self.lifetime_burn_cap_units == 0 {
            epoch_remaining
        } else if self.epoch_burn_cap_units == 0 {
            lifetime_remaining
        } else {
            lifetime_remaining.min(epoch_remaining)
        }
    }

    pub fn can_mint(&self, amount: u64) -> bool {
        if amount == 0 {
            return false;
        }
        if self.lifetime_mint_cap_units != 0 && amount > self.remaining_mint_units() {
            return false;
        }
        if self.epoch_mint_cap_units != 0
            && amount
                > self
                    .epoch_mint_cap_units
                    .saturating_sub(self.epoch_minted_units)
        {
            return false;
        }
        if self.max_supply_units != 0 {
            self.circulating_units()
                .checked_add(amount)
                .is_some_and(|value| value <= self.max_supply_units)
        } else {
            self.minted_units.checked_add(amount).is_some()
        }
    }

    pub fn can_burn(&self, amount: u64) -> bool {
        if amount == 0 || amount > self.circulating_units() {
            return false;
        }
        if self.lifetime_burn_cap_units != 0 && amount > self.remaining_burn_units() {
            return false;
        }
        if self.epoch_burn_cap_units != 0
            && amount
                > self
                    .epoch_burn_cap_units
                    .saturating_sub(self.epoch_burned_units)
        {
            return false;
        }
        self.burned_units.checked_add(amount).is_some()
    }

    pub fn apply_mint(&mut self, amount: u64, height: u64) -> TokenResult<String> {
        if !self.can_mint(amount) {
            return Err("token mint exceeds cap or supply bounds".to_string());
        }
        self.minted_units = self
            .minted_units
            .checked_add(amount)
            .ok_or_else(|| "token minted supply overflow".to_string())?;
        self.epoch_minted_units = self
            .epoch_minted_units
            .checked_add(amount)
            .ok_or_else(|| "token epoch minted supply overflow".to_string())?;
        self.last_updated_height = height;
        Ok(self.cap_root())
    }

    pub fn apply_burn(&mut self, amount: u64, height: u64) -> TokenResult<String> {
        if !self.can_burn(amount) {
            return Err("token burn exceeds cap or circulating supply".to_string());
        }
        self.burned_units = self
            .burned_units
            .checked_add(amount)
            .ok_or_else(|| "token burned supply overflow".to_string())?;
        self.epoch_burned_units = self
            .epoch_burned_units
            .checked_add(amount)
            .ok_or_else(|| "token epoch burned supply overflow".to_string())?;
        self.last_updated_height = height;
        Ok(self.cap_root())
    }

    pub fn roll_epoch(&mut self, epoch: u64, height: u64) -> TokenResult<String> {
        if epoch < self.epoch {
            return Err("token cap epoch cannot move backward".to_string());
        }
        if epoch > self.epoch {
            self.epoch = epoch;
            self.epoch_minted_units = 0;
            self.epoch_burned_units = 0;
            self.last_updated_height = height;
        }
        Ok(self.cap_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_mint_burn_cap",
            "chain_id": CHAIN_ID,
            "asset_id": self.asset_id,
            "max_supply_units": self.max_supply_units,
            "lifetime_mint_cap_units": self.lifetime_mint_cap_units,
            "lifetime_burn_cap_units": self.lifetime_burn_cap_units,
            "epoch": self.epoch,
            "epoch_mint_cap_units": self.epoch_mint_cap_units,
            "epoch_burn_cap_units": self.epoch_burn_cap_units,
            "minted_units": self.minted_units,
            "burned_units": self.burned_units,
            "circulating_units": self.circulating_units(),
            "epoch_minted_units": self.epoch_minted_units,
            "epoch_burned_units": self.epoch_burned_units,
            "remaining_mint_units": self.remaining_mint_units(),
            "remaining_burn_units": self.remaining_burn_units(),
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn cap_root(&self) -> String {
        token_mint_burn_cap_root(self)
    }

    pub fn validate(&self) -> TokenResult<String> {
        validate_root_like(&self.asset_id, "token cap asset id")?;
        if self.burned_units > self.minted_units {
            return Err("token burned supply exceeds minted supply".to_string());
        }
        if self.max_supply_units != 0 && self.circulating_units() > self.max_supply_units {
            return Err("token circulating supply exceeds maximum".to_string());
        }
        if self.lifetime_mint_cap_units != 0 && self.minted_units > self.lifetime_mint_cap_units {
            return Err("token minted supply exceeds lifetime mint cap".to_string());
        }
        if self.lifetime_burn_cap_units != 0 && self.burned_units > self.lifetime_burn_cap_units {
            return Err("token burned supply exceeds lifetime burn cap".to_string());
        }
        if self.epoch_mint_cap_units != 0 && self.epoch_minted_units > self.epoch_mint_cap_units {
            return Err("token epoch minted supply exceeds epoch mint cap".to_string());
        }
        if self.epoch_burn_cap_units != 0 && self.epoch_burned_units > self.epoch_burn_cap_units {
            return Err("token epoch burned supply exceeds epoch burn cap".to_string());
        }
        Ok(self.cap_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenIssuer {
    pub issuer_id: String,
    pub issuer_label: String,
    pub governance_scope: String,
    pub controller_commitment: String,
    pub mint_authority_root: String,
    pub burn_authority_root: String,
    pub freeze_authority_root: String,
    pub reserve_authority_root: String,
    pub created_by_proposal_id: String,
    pub activated_at_height: u64,
    pub retired_at_height: u64,
    pub status: String,
}

impl TokenIssuer {
    #[allow(clippy::too_many_arguments)]
    pub fn governance_controlled(
        issuer_label: &str,
        governance_scope: &str,
        controller_label: &str,
        mint_authorities: &[String],
        burn_authorities: &[String],
        freeze_authorities: &[String],
        reserve_authorities: &[String],
        created_by_proposal_id: &str,
        activated_at_height: u64,
    ) -> Self {
        let controller_commitment = token_string_root("TOKEN-ISSUER-CONTROLLER", controller_label);
        let mint_authority_root =
            token_string_set_root("TOKEN-ISSUER-MINT-AUTHORITY", mint_authorities);
        let burn_authority_root =
            token_string_set_root("TOKEN-ISSUER-BURN-AUTHORITY", burn_authorities);
        let freeze_authority_root =
            token_string_set_root("TOKEN-ISSUER-FREEZE-AUTHORITY", freeze_authorities);
        let reserve_authority_root =
            token_string_set_root("TOKEN-ISSUER-RESERVE-AUTHORITY", reserve_authorities);
        let issuer_id = token_issuer_id(
            issuer_label,
            governance_scope,
            &controller_commitment,
            &mint_authority_root,
            &burn_authority_root,
            &reserve_authority_root,
        );
        Self {
            issuer_id,
            issuer_label: issuer_label.to_string(),
            governance_scope: governance_scope.to_string(),
            controller_commitment,
            mint_authority_root,
            burn_authority_root,
            freeze_authority_root,
            reserve_authority_root,
            created_by_proposal_id: created_by_proposal_id.to_string(),
            activated_at_height,
            retired_at_height: 0,
            status: TOKEN_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn native_bridge_governance(activated_at_height: u64) -> Self {
        let authorities = vec![TOKEN_DEFAULT_ISSUER_LABEL.to_string()];
        Self::governance_controlled(
            TOKEN_DEFAULT_ISSUER_LABEL,
            TOKEN_DEFAULT_GOVERNANCE_SCOPE,
            TOKEN_DEFAULT_ISSUER_LABEL,
            &authorities,
            &authorities,
            &authorities,
            &authorities,
            "genesis-native-xmr",
            activated_at_height,
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == TOKEN_STATUS_ACTIVE
            && height >= self.activated_at_height
            && (self.retired_at_height == 0 || height < self.retired_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_issuer",
            "chain_id": CHAIN_ID,
            "issuer_id": self.issuer_id,
            "issuer_label": self.issuer_label,
            "governance_scope": self.governance_scope,
            "controller_commitment": self.controller_commitment,
            "mint_authority_root": self.mint_authority_root,
            "burn_authority_root": self.burn_authority_root,
            "freeze_authority_root": self.freeze_authority_root,
            "reserve_authority_root": self.reserve_authority_root,
            "created_by_proposal_id": self.created_by_proposal_id,
            "activated_at_height": self.activated_at_height,
            "retired_at_height": self.retired_at_height,
            "status": self.status,
        })
    }

    pub fn issuer_root(&self) -> String {
        token_issuer_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> TokenResult<String> {
        if self.issuer_label.trim().is_empty() {
            return Err("token issuer label cannot be empty".to_string());
        }
        if self.governance_scope.trim().is_empty() {
            return Err("token issuer governance scope cannot be empty".to_string());
        }
        validate_root_like(
            &self.controller_commitment,
            "token issuer controller commitment",
        )?;
        validate_root_like(
            &self.mint_authority_root,
            "token issuer mint authority root",
        )?;
        validate_root_like(
            &self.burn_authority_root,
            "token issuer burn authority root",
        )?;
        validate_root_like(
            &self.freeze_authority_root,
            "token issuer freeze authority root",
        )?;
        validate_root_like(
            &self.reserve_authority_root,
            "token issuer reserve authority root",
        )?;
        validate_status(
            &self.status,
            &[
                TOKEN_STATUS_ACTIVE,
                TOKEN_STATUS_SUSPENDED,
                TOKEN_STATUS_RETIRED,
            ],
            "token issuer status",
        )?;
        if self.retired_at_height != 0 && self.retired_at_height < self.activated_at_height {
            return Err("token issuer retirement precedes activation".to_string());
        }
        let expected = token_issuer_id(
            &self.issuer_label,
            &self.governance_scope,
            &self.controller_commitment,
            &self.mint_authority_root,
            &self.burn_authority_root,
            &self.reserve_authority_root,
        );
        if self.issuer_id != expected {
            return Err("token issuer id mismatch".to_string());
        }
        Ok(self.issuer_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTransferPolicy {
    pub policy_id: String,
    pub asset_id: String,
    pub policy_label: String,
    pub version: u64,
    pub allow_confidential_transfers: bool,
    pub allow_public_transfers: bool,
    pub require_view_tag: bool,
    pub require_receiver_authorization: bool,
    pub allow_bridge_deposits: bool,
    pub allow_bridge_withdrawals: bool,
    pub max_transfer_units: u64,
    pub daily_transfer_cap_units: u64,
    pub cooldown_blocks: u64,
    pub sender_allowlist_root: String,
    pub recipient_allowlist_root: String,
    pub recipient_blocklist_root: String,
    pub policy_engine_root: String,
    pub memo_policy_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenTransferPolicy {
    pub fn default_confidential(asset_id: &str, height: u64) -> Self {
        let empty_sender_root = token_empty_root("TOKEN-SENDER-ALLOWLIST");
        let empty_recipient_root = token_empty_root("TOKEN-RECIPIENT-ALLOWLIST");
        let empty_blocklist_root = token_empty_root("TOKEN-RECIPIENT-BLOCKLIST");
        let policy_engine_root = token_string_root(
            "TOKEN-TRANSFER-POLICY-ENGINE",
            "confidential-note-transfer-v1",
        );
        let memo_policy_root = token_string_root("TOKEN-TRANSFER-MEMO-POLICY", "commitment-only");
        let policy_id =
            token_transfer_policy_id(asset_id, TOKEN_DEFAULT_TRANSFER_POLICY_LABEL, 1, height);
        Self {
            policy_id,
            asset_id: asset_id.to_string(),
            policy_label: TOKEN_DEFAULT_TRANSFER_POLICY_LABEL.to_string(),
            version: 1,
            allow_confidential_transfers: true,
            allow_public_transfers: false,
            require_view_tag: true,
            require_receiver_authorization: false,
            allow_bridge_deposits: true,
            allow_bridge_withdrawals: true,
            max_transfer_units: 0,
            daily_transfer_cap_units: 0,
            cooldown_blocks: 0,
            sender_allowlist_root: empty_sender_root,
            recipient_allowlist_root: empty_recipient_root,
            recipient_blocklist_root: empty_blocklist_root,
            policy_engine_root,
            memo_policy_root,
            created_at_height: height,
            updated_at_height: height,
            status: TOKEN_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_transfer_policy",
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "asset_id": self.asset_id,
            "policy_label": self.policy_label,
            "version": self.version,
            "allow_confidential_transfers": self.allow_confidential_transfers,
            "allow_public_transfers": self.allow_public_transfers,
            "require_view_tag": self.require_view_tag,
            "require_receiver_authorization": self.require_receiver_authorization,
            "allow_bridge_deposits": self.allow_bridge_deposits,
            "allow_bridge_withdrawals": self.allow_bridge_withdrawals,
            "max_transfer_units": self.max_transfer_units,
            "daily_transfer_cap_units": self.daily_transfer_cap_units,
            "cooldown_blocks": self.cooldown_blocks,
            "sender_allowlist_root": self.sender_allowlist_root,
            "recipient_allowlist_root": self.recipient_allowlist_root,
            "recipient_blocklist_root": self.recipient_blocklist_root,
            "policy_engine_root": self.policy_engine_root,
            "memo_policy_root": self.memo_policy_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn policy_root(&self) -> String {
        token_transfer_policy_root(self)
    }

    pub fn validate(&self) -> TokenResult<String> {
        validate_root_like(&self.asset_id, "token transfer policy asset id")?;
        if self.policy_label.trim().is_empty() {
            return Err("token transfer policy label cannot be empty".to_string());
        }
        if self.version == 0 {
            return Err("token transfer policy version cannot be zero".to_string());
        }
        if !self.allow_confidential_transfers && !self.allow_public_transfers {
            return Err("token transfer policy must allow at least one transfer mode".to_string());
        }
        validate_root_like(
            &self.sender_allowlist_root,
            "token transfer sender allowlist root",
        )?;
        validate_root_like(
            &self.recipient_allowlist_root,
            "token transfer recipient allowlist root",
        )?;
        validate_root_like(
            &self.recipient_blocklist_root,
            "token transfer recipient blocklist root",
        )?;
        validate_root_like(
            &self.policy_engine_root,
            "token transfer policy engine root",
        )?;
        validate_root_like(&self.memo_policy_root, "token transfer memo policy root")?;
        validate_status(
            &self.status,
            &[
                TOKEN_STATUS_ACTIVE,
                TOKEN_STATUS_SUSPENDED,
                TOKEN_STATUS_RETIRED,
            ],
            "token transfer policy status",
        )?;
        if self.updated_at_height < self.created_at_height {
            return Err("token transfer policy update precedes creation".to_string());
        }
        if self.policy_id
            != token_transfer_policy_id(
                &self.asset_id,
                &self.policy_label,
                self.version,
                self.created_at_height,
            )
        {
            return Err("token transfer policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedMoneroReserveProof {
    pub reserve_proof_id: String,
    pub asset_id: String,
    pub reserve_address_hash: String,
    pub reserve_view_key_commitment: String,
    pub monero_block_height: u64,
    pub monero_block_hash: String,
    pub monero_tx_root: String,
    pub reserve_amount_floor_units: u64,
    pub liabilities_amount_units: u64,
    pub liabilities_commitment_root: String,
    pub watcher_set_root: String,
    pub attestation_root: String,
    pub finality_depth: u64,
    pub observed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub prover_commitment: String,
    pub status: String,
}

impl WrappedMoneroReserveProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: &str,
        reserve_address_hash: &str,
        reserve_view_key_commitment: &str,
        monero_block_height: u64,
        monero_block_hash: &str,
        monero_tx_root: &str,
        reserve_amount_floor_units: u64,
        liabilities_amount_units: u64,
        liabilities_commitment_root: &str,
        watcher_set_root: &str,
        attestation_root: &str,
        finality_depth: u64,
        observed_at_l2_height: u64,
        expires_at_l2_height: u64,
        prover_commitment: &str,
    ) -> Self {
        let status = if reserve_amount_floor_units >= liabilities_amount_units {
            TOKEN_RESERVE_STATUS_VALID
        } else {
            TOKEN_RESERVE_STATUS_INSUFFICIENT
        }
        .to_string();
        let reserve_proof_id = token_reserve_proof_id(
            asset_id,
            reserve_address_hash,
            monero_block_height,
            monero_block_hash,
            monero_tx_root,
            reserve_amount_floor_units,
            liabilities_amount_units,
            attestation_root,
        );
        Self {
            reserve_proof_id,
            asset_id: asset_id.to_string(),
            reserve_address_hash: reserve_address_hash.to_string(),
            reserve_view_key_commitment: reserve_view_key_commitment.to_string(),
            monero_block_height,
            monero_block_hash: monero_block_hash.to_string(),
            monero_tx_root: monero_tx_root.to_string(),
            reserve_amount_floor_units,
            liabilities_amount_units,
            liabilities_commitment_root: liabilities_commitment_root.to_string(),
            watcher_set_root: watcher_set_root.to_string(),
            attestation_root: attestation_root.to_string(),
            finality_depth,
            observed_at_l2_height,
            expires_at_l2_height,
            prover_commitment: prover_commitment.to_string(),
            status,
        }
    }

    pub fn coverage_bps(&self) -> u64 {
        if self.liabilities_amount_units == 0 {
            return 10_000;
        }
        let coverage = (self.reserve_amount_floor_units as u128).saturating_mul(10_000)
            / self.liabilities_amount_units as u128;
        coverage.min(10_000) as u64
    }

    pub fn is_sufficient_at(&self, l2_height: u64) -> bool {
        self.status == TOKEN_RESERVE_STATUS_VALID
            && self.reserve_amount_floor_units >= self.liabilities_amount_units
            && self.finality_depth >= TOKEN_MIN_MONERO_FINALITY_DEPTH
            && self.expires_at_l2_height >= l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wrapped_monero_reserve_proof",
            "chain_id": CHAIN_ID,
            "reserve_proof_id": self.reserve_proof_id,
            "asset_id": self.asset_id,
            "reserve_address_hash": self.reserve_address_hash,
            "reserve_view_key_commitment": self.reserve_view_key_commitment,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
            "monero_tx_root": self.monero_tx_root,
            "reserve_amount_floor_units": self.reserve_amount_floor_units,
            "liabilities_amount_units": self.liabilities_amount_units,
            "liabilities_commitment_root": self.liabilities_commitment_root,
            "watcher_set_root": self.watcher_set_root,
            "attestation_root": self.attestation_root,
            "finality_depth": self.finality_depth,
            "coverage_bps": self.coverage_bps(),
            "observed_at_l2_height": self.observed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "prover_commitment": self.prover_commitment,
            "status": self.status,
        })
    }

    pub fn proof_root(&self) -> String {
        token_reserve_proof_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> TokenResult<String> {
        validate_root_like(&self.asset_id, "reserve proof asset id")?;
        validate_root_like(&self.reserve_address_hash, "reserve proof address hash")?;
        validate_root_like(
            &self.reserve_view_key_commitment,
            "reserve proof view key commitment",
        )?;
        validate_root_like(&self.monero_block_hash, "reserve proof Monero block hash")?;
        validate_root_like(&self.monero_tx_root, "reserve proof Monero tx root")?;
        validate_root_like(
            &self.liabilities_commitment_root,
            "reserve proof liabilities commitment root",
        )?;
        validate_root_like(&self.watcher_set_root, "reserve proof watcher set root")?;
        validate_root_like(&self.attestation_root, "reserve proof attestation root")?;
        validate_root_like(&self.prover_commitment, "reserve proof prover commitment")?;
        validate_status(
            &self.status,
            &[
                TOKEN_RESERVE_STATUS_VALID,
                TOKEN_RESERVE_STATUS_INSUFFICIENT,
                TOKEN_RESERVE_STATUS_STALE,
                TOKEN_RESERVE_STATUS_REVOKED,
            ],
            "reserve proof status",
        )?;
        if self.finality_depth < TOKEN_MIN_MONERO_FINALITY_DEPTH {
            return Err("reserve proof finality depth is below token minimum".to_string());
        }
        if self.expires_at_l2_height < self.observed_at_l2_height {
            return Err("reserve proof expiry precedes observation height".to_string());
        }
        if self.reserve_proof_id
            != token_reserve_proof_id(
                &self.asset_id,
                &self.reserve_address_hash,
                self.monero_block_height,
                &self.monero_block_hash,
                &self.monero_tx_root,
                self.reserve_amount_floor_units,
                self.liabilities_amount_units,
                &self.attestation_root,
            )
        {
            return Err("reserve proof id mismatch".to_string());
        }
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFeeAssetEntry {
    pub entry_id: String,
    pub asset_id: String,
    pub enabled: bool,
    pub low_fee_eligible: bool,
    pub min_fee_units: u64,
    pub max_rebate_bps: u64,
    pub fee_lane_root: String,
    pub oracle_price_feed_id: String,
    pub updated_by_proposal_id: String,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenFeeAssetEntry {
    pub fn enabled(
        asset_id: &str,
        low_fee_eligible: bool,
        min_fee_units: u64,
        max_rebate_bps: u64,
        fee_lane_root: &str,
        oracle_price_feed_id: &str,
        updated_by_proposal_id: &str,
        updated_at_height: u64,
    ) -> Self {
        let entry_id = token_fee_asset_entry_id(asset_id);
        Self {
            entry_id,
            asset_id: asset_id.to_string(),
            enabled: true,
            low_fee_eligible,
            min_fee_units,
            max_rebate_bps: max_rebate_bps.min(TOKEN_MAX_LOW_FEE_REBATE_BPS),
            fee_lane_root: fee_lane_root.to_string(),
            oracle_price_feed_id: oracle_price_feed_id.to_string(),
            updated_by_proposal_id: updated_by_proposal_id.to_string(),
            updated_at_height,
            status: TOKEN_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_fee_asset_entry",
            "chain_id": CHAIN_ID,
            "entry_id": self.entry_id,
            "asset_id": self.asset_id,
            "enabled": self.enabled,
            "low_fee_eligible": self.low_fee_eligible,
            "min_fee_units": self.min_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "fee_lane_root": self.fee_lane_root,
            "oracle_price_feed_id": self.oracle_price_feed_id,
            "updated_by_proposal_id": self.updated_by_proposal_id,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn entry_root(&self) -> String {
        token_fee_asset_entry_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> TokenResult<String> {
        validate_root_like(&self.asset_id, "fee asset entry asset id")?;
        validate_root_like(&self.fee_lane_root, "fee asset lane root")?;
        validate_bps(self.max_rebate_bps, "fee asset max rebate")?;
        validate_status(
            &self.status,
            &[
                TOKEN_STATUS_ACTIVE,
                TOKEN_STATUS_SUSPENDED,
                TOKEN_STATUS_RETIRED,
            ],
            "fee asset status",
        )?;
        if self.low_fee_eligible && !self.enabled {
            return Err("fee asset cannot be low-fee eligible while disabled".to_string());
        }
        if self.entry_id != token_fee_asset_entry_id(&self.asset_id) {
            return Err("fee asset entry id mismatch".to_string());
        }
        Ok(self.entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub asset_id: String,
    pub symbol: String,
    pub decimals: u8,
    pub token_kind: TokenKind,
    pub supply_policy: TokenSupplyPolicy,
    pub issuer_id: String,
    pub issuer_root: String,
    pub metadata: TokenMetadataCommitment,
    pub caps: MintBurnCap,
    pub transfer_policy_id: String,
    pub transfer_policy_root: String,
    pub reserve_proof_root: String,
    pub risk_flags: Vec<TokenRiskFlag>,
    pub risk_flag_root: String,
    pub fee_asset_enabled: bool,
    pub low_fee_eligible: bool,
    pub governance_proposal_id: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol: &str,
        decimals: u8,
        token_kind: TokenKind,
        supply_policy: TokenSupplyPolicy,
        issuer: &TokenIssuer,
        metadata: TokenMetadataCommitment,
        created_at_height: u64,
        governance_proposal_id: &str,
    ) -> Self {
        let normalized_symbol = normalize_symbol(symbol);
        let issuer_root = issuer.issuer_root();
        let token_kind_label = token_kind.as_str();
        let asset_id = token_asset_id(
            &normalized_symbol,
            decimals,
            &token_kind_label,
            supply_policy.as_str(),
            &issuer_root,
            &metadata.commitment_root(),
            created_at_height,
            governance_proposal_id,
        );
        let transfer_policy =
            TokenTransferPolicy::default_confidential(&asset_id, created_at_height);
        let caps = MintBurnCap::uncapped(&asset_id, 0, created_at_height);
        let mut risk_flags = Vec::new();
        if token_kind.requires_monero_reserve() || supply_policy.requires_reserve_proof() {
            risk_flags.push(TokenRiskFlag::ReserveProofMissing);
        }
        if matches!(supply_policy, TokenSupplyPolicy::GovernanceControlled) {
            risk_flags.push(TokenRiskFlag::GovernanceControlled);
        }
        let risk_flags = normalized_risk_flags(&risk_flags);
        let risk_flag_root = token_risk_flag_root(&asset_id, &risk_flags);
        Self {
            asset_id,
            symbol: normalized_symbol,
            decimals,
            token_kind,
            supply_policy,
            issuer_id: issuer.issuer_id.clone(),
            issuer_root,
            metadata,
            caps,
            transfer_policy_id: transfer_policy.policy_id.clone(),
            transfer_policy_root: transfer_policy.policy_root(),
            reserve_proof_root: token_empty_root("TOKEN-RESERVE-PROOF"),
            risk_flags,
            risk_flag_root,
            fee_asset_enabled: false,
            low_fee_eligible: false,
            governance_proposal_id: governance_proposal_id.to_string(),
            created_at_height,
            updated_at_height: created_at_height,
            status: TOKEN_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn expected_asset_id(&self) -> String {
        let token_kind_label = self.token_kind.as_str();
        token_asset_id(
            &self.symbol,
            self.decimals,
            &token_kind_label,
            self.supply_policy.as_str(),
            &self.issuer_root,
            &self.metadata.commitment_root(),
            self.created_at_height,
            &self.governance_proposal_id,
        )
    }

    pub fn circulating_units(&self) -> u64 {
        self.caps.circulating_units()
    }

    pub fn has_risk_flag(&self, flag: &TokenRiskFlag) -> bool {
        self.risk_flags.iter().any(|existing| existing == flag)
    }

    pub fn has_low_fee_blocking_risk(&self) -> bool {
        self.risk_flags
            .iter()
            .any(TokenRiskFlag::blocks_low_fee_eligibility)
    }

    pub fn can_use_low_fee_lane(&self) -> bool {
        self.status == TOKEN_STATUS_ACTIVE
            && self.fee_asset_enabled
            && self.low_fee_eligible
            && !self.has_low_fee_blocking_risk()
    }

    pub fn set_risk_flags(
        &mut self,
        flags: Vec<TokenRiskFlag>,
        height: u64,
    ) -> TokenResult<String> {
        if flags.len() > TOKEN_MAX_RISK_FLAGS {
            return Err("token has too many risk flags".to_string());
        }
        self.risk_flags = normalized_risk_flags(&flags);
        self.risk_flag_root = token_risk_flag_root(&self.asset_id, &self.risk_flags);
        if self.has_low_fee_blocking_risk() {
            self.low_fee_eligible = false;
        }
        self.updated_at_height = height;
        Ok(self.risk_flag_root.clone())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_record",
            "chain_id": CHAIN_ID,
            "protocol_version": TOKEN_PROTOCOL_VERSION,
            "asset_id": self.asset_id,
            "symbol": self.symbol,
            "decimals": self.decimals,
            "token_kind": self.token_kind.as_str(),
            "supply_policy": self.supply_policy.as_str(),
            "issuer_id": self.issuer_id,
            "issuer_root": self.issuer_root,
            "metadata": self.metadata.public_record(),
            "metadata_commitment_root": self.metadata.commitment_root(),
            "cap": self.caps.public_record(),
            "cap_root": self.caps.cap_root(),
            "transfer_policy_id": self.transfer_policy_id,
            "transfer_policy_root": self.transfer_policy_root,
            "reserve_proof_root": self.reserve_proof_root,
            "risk_flags": self.risk_flags.iter().map(TokenRiskFlag::as_str).collect::<Vec<_>>(),
            "risk_flag_root": self.risk_flag_root,
            "fee_asset_enabled": self.fee_asset_enabled,
            "low_fee_eligible": self.low_fee_eligible,
            "low_fee_lane_eligible": self.can_use_low_fee_lane(),
            "governance_proposal_id": self.governance_proposal_id,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn token_root(&self) -> String {
        token_record_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> TokenResult<String> {
        validate_symbol(&self.symbol)?;
        self.metadata.validate()?;
        self.caps.validate()?;
        validate_root_like(&self.issuer_id, "token issuer id")?;
        validate_root_like(&self.issuer_root, "token issuer root")?;
        validate_root_like(&self.transfer_policy_id, "token transfer policy id")?;
        validate_root_like(&self.transfer_policy_root, "token transfer policy root")?;
        validate_root_like(&self.reserve_proof_root, "token reserve proof root")?;
        validate_status(
            &self.status,
            &[
                TOKEN_STATUS_ACTIVE,
                TOKEN_STATUS_SUSPENDED,
                TOKEN_STATUS_RETIRED,
                TOKEN_STATUS_FROZEN,
            ],
            "token status",
        )?;
        if self.caps.asset_id != self.asset_id {
            return Err("token cap asset id mismatch".to_string());
        }
        if self.asset_id != self.expected_asset_id() {
            return Err("token asset id mismatch".to_string());
        }
        if self.risk_flags.len() > TOKEN_MAX_RISK_FLAGS {
            return Err("token has too many risk flags".to_string());
        }
        let normalized = normalized_risk_flags(&self.risk_flags);
        if normalized != self.risk_flags {
            return Err("token risk flags are not canonical".to_string());
        }
        if self.risk_flag_root != token_risk_flag_root(&self.asset_id, &self.risk_flags) {
            return Err("token risk flag root mismatch".to_string());
        }
        if self.low_fee_eligible && !self.fee_asset_enabled {
            return Err("token cannot be low-fee eligible without fee allowlist".to_string());
        }
        if self.low_fee_eligible && self.has_low_fee_blocking_risk() {
            return Err("token cannot be low-fee eligible with blocking risk flags".to_string());
        }
        if self.updated_at_height < self.created_at_height {
            return Err("token update height precedes creation".to_string());
        }
        if matches!(self.token_kind, TokenKind::NativeBridgedXmr) {
            if self.symbol != TOKEN_NATIVE_XMR_SYMBOL || self.decimals != TOKEN_NATIVE_XMR_DECIMALS
            {
                return Err("native bridged XMR token metadata mismatch".to_string());
            }
            if self.supply_policy != TokenSupplyPolicy::BridgeMintBurn {
                return Err("native bridged XMR must use bridge mint-burn supply".to_string());
            }
        }
        Ok(self.token_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSupplyOperation {
    pub operation_id: String,
    pub operation_kind: String,
    pub asset_id: String,
    pub issuer_id: String,
    pub amount: u64,
    pub cap_root_before: String,
    pub cap_root_after: String,
    pub reserve_proof_root: String,
    pub governance_proposal_id: String,
    pub applied_at_height: u64,
}

impl TokenSupplyOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_kind: &str,
        asset_id: &str,
        issuer_id: &str,
        amount: u64,
        cap_root_before: &str,
        cap_root_after: &str,
        reserve_proof_root: &str,
        governance_proposal_id: &str,
        applied_at_height: u64,
    ) -> Self {
        let operation_id = token_supply_operation_id(
            operation_kind,
            asset_id,
            issuer_id,
            amount,
            applied_at_height,
            cap_root_before,
            cap_root_after,
            reserve_proof_root,
            governance_proposal_id,
        );
        Self {
            operation_id,
            operation_kind: operation_kind.to_string(),
            asset_id: asset_id.to_string(),
            issuer_id: issuer_id.to_string(),
            amount,
            cap_root_before: cap_root_before.to_string(),
            cap_root_after: cap_root_after.to_string(),
            reserve_proof_root: reserve_proof_root.to_string(),
            governance_proposal_id: governance_proposal_id.to_string(),
            applied_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_supply_operation",
            "chain_id": CHAIN_ID,
            "operation_id": self.operation_id,
            "operation_kind": self.operation_kind,
            "asset_id": self.asset_id,
            "issuer_id": self.issuer_id,
            "amount": self.amount,
            "cap_root_before": self.cap_root_before,
            "cap_root_after": self.cap_root_after,
            "reserve_proof_root": self.reserve_proof_root,
            "governance_proposal_id": self.governance_proposal_id,
            "applied_at_height": self.applied_at_height,
        })
    }

    pub fn operation_root(&self) -> String {
        token_supply_operation_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> TokenResult<String> {
        if !matches!(self.operation_kind.as_str(), "mint" | "burn") {
            return Err("token supply operation kind is unsupported".to_string());
        }
        validate_root_like(&self.asset_id, "token supply operation asset id")?;
        validate_root_like(&self.issuer_id, "token supply operation issuer id")?;
        validate_root_like(&self.cap_root_before, "token supply cap root before")?;
        validate_root_like(&self.cap_root_after, "token supply cap root after")?;
        validate_root_like(&self.reserve_proof_root, "token supply reserve proof root")?;
        if self.amount == 0 {
            return Err("token supply operation amount cannot be zero".to_string());
        }
        if self.operation_id
            != token_supply_operation_id(
                &self.operation_kind,
                &self.asset_id,
                &self.issuer_id,
                self.amount,
                self.applied_at_height,
                &self.cap_root_before,
                &self.cap_root_after,
                &self.reserve_proof_root,
                &self.governance_proposal_id,
            )
        {
            return Err("token supply operation id mismatch".to_string());
        }
        Ok(self.operation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBridgedXmrAsset {
    pub issuer: TokenIssuer,
    pub transfer_policy: TokenTransferPolicy,
    pub token: TokenRecord,
    pub fee_asset_entry: TokenFeeAssetEntry,
}

impl NativeBridgedXmrAsset {
    pub fn new(created_at_height: u64) -> Self {
        let issuer = TokenIssuer::native_bridge_governance(created_at_height);
        let metadata = json!({
            "display_name": TOKEN_NATIVE_XMR_DISPLAY_NAME,
            "symbol": TOKEN_NATIVE_XMR_SYMBOL,
            "decimals": TOKEN_NATIVE_XMR_DECIMALS,
            "network": TOKEN_NATIVE_XMR_NETWORK,
            "reserve_policy": TOKEN_NATIVE_XMR_RESERVE_POLICY,
        });
        let metadata_commitment = TokenMetadataCommitment::confidential(
            TOKEN_NATIVE_XMR_SYMBOL,
            TOKEN_NATIVE_XMR_DECIMALS,
            &metadata,
            TOKEN_NATIVE_XMR_METADATA_BLINDING,
        );
        let mut token = TokenRecord::new(
            TOKEN_NATIVE_XMR_SYMBOL,
            TOKEN_NATIVE_XMR_DECIMALS,
            TokenKind::NativeBridgedXmr,
            TokenSupplyPolicy::BridgeMintBurn,
            &issuer,
            metadata_commitment,
            created_at_height,
            "genesis-native-xmr",
        );
        token.risk_flags = normalized_risk_flags(&[
            TokenRiskFlag::ReserveProofMissing,
            TokenRiskFlag::GovernanceControlled,
            TokenRiskFlag::MintAuthorityActive,
            TokenRiskFlag::BurnAuthorityActive,
        ]);
        token.risk_flag_root = token_risk_flag_root(&token.asset_id, &token.risk_flags);
        token.fee_asset_enabled = true;
        token.low_fee_eligible = false;
        let transfer_policy =
            TokenTransferPolicy::default_confidential(&token.asset_id, created_at_height);
        token.transfer_policy_id = transfer_policy.policy_id.clone();
        token.transfer_policy_root = transfer_policy.policy_root();
        let fee_asset_entry = TokenFeeAssetEntry::enabled(
            &token.asset_id,
            false,
            0,
            TOKEN_MAX_LOW_FEE_REBATE_BPS,
            &token_string_root("TOKEN-FEE-LANE", "native-xmr"),
            "",
            "genesis-native-xmr",
            created_at_height,
        );
        Self {
            issuer,
            transfer_policy,
            token,
            fee_asset_entry,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "native_bridged_xmr_asset",
            "chain_id": CHAIN_ID,
            "issuer": self.issuer.public_record(),
            "transfer_policy": self.transfer_policy.public_record(),
            "token": self.token.public_record(),
            "fee_asset_entry": self.fee_asset_entry.public_record(),
        })
    }

    pub fn root(&self) -> String {
        token_payload_root("TOKEN-NATIVE-BRIDGED-XMR", &self.public_record())
    }

    pub fn validate(&self) -> TokenResult<String> {
        self.issuer.validate()?;
        self.transfer_policy.validate()?;
        self.token.validate()?;
        self.fee_asset_entry.validate()?;
        if self.token.issuer_id != self.issuer.issuer_id {
            return Err("native bridged XMR issuer mismatch".to_string());
        }
        if self.token.transfer_policy_id != self.transfer_policy.policy_id {
            return Err("native bridged XMR transfer policy mismatch".to_string());
        }
        if self.fee_asset_entry.asset_id != self.token.asset_id {
            return Err("native bridged XMR fee asset mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRegistryState {
    pub issuers: BTreeMap<String, TokenIssuer>,
    pub tokens: BTreeMap<String, TokenRecord>,
    pub transfer_policies: BTreeMap<String, TokenTransferPolicy>,
    pub reserve_proofs: BTreeMap<String, WrappedMoneroReserveProof>,
    pub fee_asset_allowlist: BTreeMap<String, TokenFeeAssetEntry>,
    pub supply_operations: BTreeMap<String, TokenSupplyOperation>,
    pub height: u64,
}

impl TokenRegistryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_native_bridged_xmr(height: u64) -> TokenResult<Self> {
        let mut state = Self {
            height,
            ..Self::default()
        };
        state.register_native_bridged_xmr()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> TokenResult<String> {
        if height < self.height {
            return Err("token registry height cannot move backward".to_string());
        }
        self.height = height;
        Ok(self.state_root())
    }

    pub fn register_native_bridged_xmr(&mut self) -> TokenResult<String> {
        let bundle = NativeBridgedXmrAsset::new(self.height);
        bundle.validate()?;
        self.register_issuer(bundle.issuer)?;
        self.register_transfer_policy(bundle.transfer_policy)?;
        let asset_id = self.register_token(bundle.token)?;
        self.apply_fee_asset_allowlist(bundle.fee_asset_entry)?;
        Ok(asset_id)
    }

    pub fn register_issuer(&mut self, issuer: TokenIssuer) -> TokenResult<String> {
        issuer.validate()?;
        if self.issuers.contains_key(&issuer.issuer_id) {
            return Err("token issuer already exists".to_string());
        }
        let issuer_id = issuer.issuer_id.clone();
        self.issuers.insert(issuer_id.clone(), issuer);
        Ok(issuer_id)
    }

    pub fn apply_issuer_status(
        &mut self,
        issuer_id: &str,
        status: &str,
        governance_proposal_id: &str,
    ) -> TokenResult<String> {
        validate_status(
            status,
            &[
                TOKEN_STATUS_ACTIVE,
                TOKEN_STATUS_SUSPENDED,
                TOKEN_STATUS_RETIRED,
            ],
            "token issuer status",
        )?;
        if governance_proposal_id.trim().is_empty() {
            return Err("token issuer status update requires governance proposal id".to_string());
        }
        let mut issuer = self
            .issuers
            .get(issuer_id)
            .cloned()
            .ok_or_else(|| "unknown token issuer".to_string())?;
        issuer.status = status.to_string();
        if status == TOKEN_STATUS_RETIRED && issuer.retired_at_height == 0 {
            issuer.retired_at_height = self.height;
        }
        let issuer_root = issuer.validate()?;
        self.issuers.insert(issuer_id.to_string(), issuer);
        Ok(issuer_root)
    }

    pub fn register_transfer_policy(&mut self, policy: TokenTransferPolicy) -> TokenResult<String> {
        policy.validate()?;
        if self.transfer_policies.contains_key(&policy.policy_id) {
            return Err("token transfer policy already exists".to_string());
        }
        let policy_id = policy.policy_id.clone();
        self.transfer_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn apply_transfer_policy(
        &mut self,
        mut policy: TokenTransferPolicy,
        governance_proposal_id: &str,
    ) -> TokenResult<String> {
        if governance_proposal_id.trim().is_empty() {
            return Err("token transfer policy update requires governance proposal id".to_string());
        }
        policy.updated_at_height = self.height;
        policy.validate()?;
        let token = self
            .tokens
            .get_mut(&policy.asset_id)
            .ok_or_else(|| "unknown token for transfer policy".to_string())?;
        let policy_id = policy.policy_id.clone();
        let policy_root = policy.policy_root();
        token.transfer_policy_id = policy_id.clone();
        token.transfer_policy_root = policy_root.clone();
        token.updated_at_height = self.height;
        self.transfer_policies.insert(policy_id, policy);
        Ok(policy_root)
    }

    pub fn register_token(&mut self, token: TokenRecord) -> TokenResult<String> {
        token.validate()?;
        if self.tokens.contains_key(&token.asset_id) {
            return Err("token asset already exists".to_string());
        }
        let issuer = self
            .issuers
            .get(&token.issuer_id)
            .ok_or_else(|| "unknown token issuer".to_string())?;
        if issuer.issuer_root() != token.issuer_root {
            return Err("token issuer root mismatch".to_string());
        }
        if !issuer.is_active_at(self.height) {
            return Err("token issuer is not active".to_string());
        }
        let transfer_policy = self
            .transfer_policies
            .get(&token.transfer_policy_id)
            .ok_or_else(|| "unknown token transfer policy".to_string())?;
        if transfer_policy.asset_id != token.asset_id
            || transfer_policy.policy_root() != token.transfer_policy_root
        {
            return Err("token transfer policy root mismatch".to_string());
        }
        let asset_id = token.asset_id.clone();
        self.tokens.insert(asset_id.clone(), token);
        Ok(asset_id)
    }

    pub fn apply_fee_asset_allowlist(&mut self, entry: TokenFeeAssetEntry) -> TokenResult<String> {
        entry.validate()?;
        let token = self
            .tokens
            .get_mut(&entry.asset_id)
            .ok_or_else(|| "unknown token for fee allowlist".to_string())?;
        if entry.low_fee_eligible && token.has_low_fee_blocking_risk() {
            return Err(
                "fee asset cannot be low-fee eligible with blocking risk flags".to_string(),
            );
        }
        token.fee_asset_enabled = entry.enabled && entry.status == TOKEN_STATUS_ACTIVE;
        token.low_fee_eligible = entry.low_fee_eligible && token.fee_asset_enabled;
        token.updated_at_height = self.height;
        let entry_id = entry.entry_id.clone();
        let entry_root = entry.entry_root();
        self.fee_asset_allowlist.insert(entry_id, entry);
        Ok(entry_root)
    }

    pub fn apply_reserve_proof(&mut self, proof: WrappedMoneroReserveProof) -> TokenResult<String> {
        proof.validate()?;
        let mut token = self
            .tokens
            .get(&proof.asset_id)
            .cloned()
            .ok_or_else(|| "unknown token for reserve proof".to_string())?;
        if !token.token_kind.requires_monero_reserve()
            && !token.supply_policy.requires_reserve_proof()
        {
            return Err("token does not require wrapped Monero reserve proof".to_string());
        }
        if proof.liabilities_amount_units < token.circulating_units() {
            return Err("reserve proof liabilities are below token circulation".to_string());
        }
        let proof_root = proof.proof_root();
        let proof_id = proof.reserve_proof_id.clone();
        let mut flags = token.risk_flags.clone();
        remove_risk_flag(&mut flags, &TokenRiskFlag::ReserveProofMissing);
        remove_risk_flag(&mut flags, &TokenRiskFlag::ReserveProofInsufficient);
        remove_risk_flag(&mut flags, &TokenRiskFlag::ReserveProofStale);
        if proof.status == TOKEN_RESERVE_STATUS_STALE {
            flags.push(TokenRiskFlag::ReserveProofStale);
        } else if !proof.is_sufficient_at(self.height) {
            flags.push(TokenRiskFlag::ReserveProofInsufficient);
        }
        token.reserve_proof_root = proof_root;
        token.set_risk_flags(flags, self.height)?;
        self.tokens.insert(proof.asset_id.clone(), token);
        self.reserve_proofs.insert(proof_id.clone(), proof);
        Ok(proof_id)
    }

    pub fn apply_risk_flags(
        &mut self,
        asset_id: &str,
        flags: Vec<TokenRiskFlag>,
        governance_proposal_id: &str,
    ) -> TokenResult<String> {
        if governance_proposal_id.trim().is_empty() {
            return Err("token risk flag update requires governance proposal id".to_string());
        }
        let token = self
            .tokens
            .get_mut(asset_id)
            .ok_or_else(|| "unknown token for risk flag update".to_string())?;
        token.set_risk_flags(flags, self.height)
    }

    pub fn apply_low_fee_eligibility(
        &mut self,
        asset_id: &str,
        low_fee_eligible: bool,
        governance_proposal_id: &str,
    ) -> TokenResult<String> {
        if governance_proposal_id.trim().is_empty() {
            return Err("token low-fee update requires governance proposal id".to_string());
        }
        let token = self
            .tokens
            .get_mut(asset_id)
            .ok_or_else(|| "unknown token for low-fee update".to_string())?;
        let entry = self
            .fee_asset_allowlist
            .get_mut(&token_fee_asset_entry_id(asset_id))
            .ok_or_else(|| "token is not fee-asset allowlisted".to_string())?;
        if low_fee_eligible && (!entry.enabled || entry.status != TOKEN_STATUS_ACTIVE) {
            return Err("token fee asset is not active".to_string());
        }
        if low_fee_eligible && token.has_low_fee_blocking_risk() {
            return Err("token has risk flags that block low-fee eligibility".to_string());
        }
        token.low_fee_eligible = low_fee_eligible;
        token.fee_asset_enabled = entry.enabled && entry.status == TOKEN_STATUS_ACTIVE;
        token.updated_at_height = self.height;
        entry.low_fee_eligible = low_fee_eligible;
        entry.updated_by_proposal_id = governance_proposal_id.to_string();
        entry.updated_at_height = self.height;
        Ok(token.token_root())
    }

    pub fn apply_mint(
        &mut self,
        asset_id: &str,
        issuer_id: &str,
        amount: u64,
        reserve_proof_id: Option<&str>,
        governance_proposal_id: &str,
    ) -> TokenResult<String> {
        self.apply_supply_change(
            "mint",
            asset_id,
            issuer_id,
            amount,
            reserve_proof_id,
            governance_proposal_id,
        )
    }

    pub fn apply_burn(
        &mut self,
        asset_id: &str,
        issuer_id: &str,
        amount: u64,
        reserve_proof_id: Option<&str>,
        governance_proposal_id: &str,
    ) -> TokenResult<String> {
        self.apply_supply_change(
            "burn",
            asset_id,
            issuer_id,
            amount,
            reserve_proof_id,
            governance_proposal_id,
        )
    }

    fn apply_supply_change(
        &mut self,
        operation_kind: &str,
        asset_id: &str,
        issuer_id: &str,
        amount: u64,
        reserve_proof_id: Option<&str>,
        governance_proposal_id: &str,
    ) -> TokenResult<String> {
        if governance_proposal_id.trim().is_empty() {
            return Err("token supply change requires governance proposal id".to_string());
        }
        let issuer = self
            .issuers
            .get(issuer_id)
            .ok_or_else(|| "unknown token issuer".to_string())?;
        if !issuer.is_active_at(self.height) {
            return Err("token issuer is not active".to_string());
        }
        let token_snapshot = self
            .tokens
            .get(asset_id)
            .cloned()
            .ok_or_else(|| "unknown token asset".to_string())?;
        if token_snapshot.issuer_id != issuer_id {
            return Err("token supply issuer mismatch".to_string());
        }
        if operation_kind == "mint" && !token_snapshot.supply_policy.allows_mint() {
            return Err("token supply policy does not allow mint".to_string());
        }
        if operation_kind == "burn" && !token_snapshot.supply_policy.allows_burn() {
            return Err("token supply policy does not allow burn".to_string());
        }
        let reserve_proof = reserve_proof_id
            .map(|proof_id| {
                self.reserve_proofs
                    .get(proof_id)
                    .cloned()
                    .ok_or_else(|| "unknown reserve proof".to_string())
            })
            .transpose()?;
        if token_snapshot.supply_policy.requires_reserve_proof()
            || token_snapshot.token_kind.requires_monero_reserve()
        {
            let proof = reserve_proof
                .as_ref()
                .ok_or_else(|| "token supply change requires reserve proof".to_string())?;
            if proof.asset_id != asset_id {
                return Err("reserve proof asset mismatch".to_string());
            }
            if !proof.is_sufficient_at(self.height) {
                return Err("reserve proof is not sufficient at registry height".to_string());
            }
        }
        let mut updated_token = token_snapshot;
        let cap_root_before = updated_token.caps.cap_root();
        match operation_kind {
            "mint" => {
                updated_token.caps.apply_mint(amount, self.height)?;
            }
            "burn" => {
                updated_token.caps.apply_burn(amount, self.height)?;
            }
            _ => return Err("unsupported token supply operation".to_string()),
        }
        if let Some(proof) = reserve_proof.as_ref() {
            if proof.liabilities_amount_units < updated_token.caps.circulating_units() {
                return Err(
                    "reserve proof liabilities are below post-operation circulation".to_string(),
                );
            }
            if proof.reserve_amount_floor_units < updated_token.caps.circulating_units() {
                return Err("reserve proof is below post-operation circulating supply".to_string());
            }
            updated_token.reserve_proof_root = proof.proof_root();
        }
        updated_token.updated_at_height = self.height;
        let cap_root_after = updated_token.caps.cap_root();
        let reserve_proof_root = updated_token.reserve_proof_root.clone();
        let operation = TokenSupplyOperation::new(
            operation_kind,
            asset_id,
            issuer_id,
            amount,
            &cap_root_before,
            &cap_root_after,
            &reserve_proof_root,
            governance_proposal_id,
            self.height,
        );
        operation.validate()?;
        let operation_id = operation.operation_id.clone();
        self.tokens.insert(asset_id.to_string(), updated_token);
        self.supply_operations
            .insert(operation_id.clone(), operation);
        Ok(operation_id)
    }

    pub fn token_root(&self) -> String {
        token_record_set_root(&self.tokens.values().cloned().collect::<Vec<_>>())
    }

    pub fn issuer_root(&self) -> String {
        token_issuer_set_root(&self.issuers.values().cloned().collect::<Vec<_>>())
    }

    pub fn transfer_policy_root(&self) -> String {
        token_transfer_policy_set_root(
            &self.transfer_policies.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reserve_proof_root(&self) -> String {
        token_reserve_proof_set_root(&self.reserve_proofs.values().cloned().collect::<Vec<_>>())
    }

    pub fn fee_asset_allowlist_root(&self) -> String {
        token_fee_asset_allowlist_root(
            &self
                .fee_asset_allowlist
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn supply_operation_root(&self) -> String {
        token_supply_operation_set_root(
            &self.supply_operations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_asset_ids(&self) -> Vec<String> {
        self.tokens
            .values()
            .filter(|token| token.can_use_low_fee_lane())
            .map(|token| token.asset_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        token_registry_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("token registry state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "token_registry_state",
            "chain_id": CHAIN_ID,
            "protocol_version": TOKEN_PROTOCOL_VERSION,
            "height": self.height,
            "issuer_count": self.issuers.len() as u64,
            "token_count": self.tokens.len() as u64,
            "transfer_policy_count": self.transfer_policies.len() as u64,
            "reserve_proof_count": self.reserve_proofs.len() as u64,
            "fee_asset_count": self.fee_asset_allowlist.len() as u64,
            "supply_operation_count": self.supply_operations.len() as u64,
            "issuer_root": self.issuer_root(),
            "token_root": self.token_root(),
            "transfer_policy_root": self.transfer_policy_root(),
            "reserve_proof_root": self.reserve_proof_root(),
            "fee_asset_allowlist_root": self.fee_asset_allowlist_root(),
            "supply_operation_root": self.supply_operation_root(),
            "low_fee_asset_ids": self.low_fee_asset_ids(),
        })
    }

    pub fn validate(&self) -> TokenResult<String> {
        for issuer in self.issuers.values() {
            issuer.validate()?;
        }
        for policy in self.transfer_policies.values() {
            policy.validate()?;
        }
        for token in self.tokens.values() {
            token.validate()?;
            let issuer = self
                .issuers
                .get(&token.issuer_id)
                .ok_or_else(|| "token references unknown issuer".to_string())?;
            if issuer.issuer_root() != token.issuer_root {
                return Err("token references stale issuer root".to_string());
            }
            let transfer_policy = self
                .transfer_policies
                .get(&token.transfer_policy_id)
                .ok_or_else(|| "token references unknown transfer policy".to_string())?;
            if transfer_policy.policy_root() != token.transfer_policy_root {
                return Err("token references stale transfer policy root".to_string());
            }
        }
        for proof in self.reserve_proofs.values() {
            proof.validate()?;
            if !self.tokens.contains_key(&proof.asset_id) {
                return Err("reserve proof references unknown token".to_string());
            }
        }
        for entry in self.fee_asset_allowlist.values() {
            entry.validate()?;
            if !self.tokens.contains_key(&entry.asset_id) {
                return Err("fee asset entry references unknown token".to_string());
            }
        }
        for operation in self.supply_operations.values() {
            operation.validate()?;
            if !self.tokens.contains_key(&operation.asset_id) {
                return Err("supply operation references unknown token".to_string());
            }
            if !self.issuers.contains_key(&operation.issuer_id) {
                return Err("supply operation references unknown issuer".to_string());
            }
        }
        Ok(self.state_root())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn token_asset_id(
    symbol: &str,
    decimals: u8,
    token_kind: &str,
    supply_policy: &str,
    issuer_root: &str,
    metadata_commitment_root: &str,
    created_at_height: u64,
    governance_proposal_id: &str,
) -> String {
    domain_hash(
        "TOKEN-ASSET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&normalize_symbol(symbol)),
            HashPart::Int(decimals as i128),
            HashPart::Str(token_kind),
            HashPart::Str(supply_policy),
            HashPart::Str(issuer_root),
            HashPart::Str(metadata_commitment_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(governance_proposal_id),
        ],
        32,
    )
}

pub fn native_bridged_xmr_asset_id(created_at_height: u64) -> String {
    NativeBridgedXmrAsset::new(created_at_height).token.asset_id
}

pub fn token_issuer_id(
    issuer_label: &str,
    governance_scope: &str,
    controller_commitment: &str,
    mint_authority_root: &str,
    burn_authority_root: &str,
    reserve_authority_root: &str,
) -> String {
    domain_hash(
        "TOKEN-ISSUER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(issuer_label),
            HashPart::Str(governance_scope),
            HashPart::Str(controller_commitment),
            HashPart::Str(mint_authority_root),
            HashPart::Str(burn_authority_root),
            HashPart::Str(reserve_authority_root),
        ],
        32,
    )
}

pub fn token_transfer_policy_id(
    asset_id: &str,
    policy_label: &str,
    version: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "TOKEN-TRANSFER-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_id),
            HashPart::Str(policy_label),
            HashPart::Int(version as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn token_reserve_proof_id(
    asset_id: &str,
    reserve_address_hash: &str,
    monero_block_height: u64,
    monero_block_hash: &str,
    monero_tx_root: &str,
    reserve_amount_floor_units: u64,
    liabilities_amount_units: u64,
    attestation_root: &str,
) -> String {
    domain_hash(
        "TOKEN-RESERVE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_id),
            HashPart::Str(reserve_address_hash),
            HashPart::Int(monero_block_height as i128),
            HashPart::Str(monero_block_hash),
            HashPart::Str(monero_tx_root),
            HashPart::Int(reserve_amount_floor_units as i128),
            HashPart::Int(liabilities_amount_units as i128),
            HashPart::Str(attestation_root),
        ],
        32,
    )
}

pub fn token_fee_asset_entry_id(asset_id: &str) -> String {
    domain_hash(
        "TOKEN-FEE-ASSET-ENTRY-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn token_supply_operation_id(
    operation_kind: &str,
    asset_id: &str,
    issuer_id: &str,
    amount: u64,
    applied_at_height: u64,
    cap_root_before: &str,
    cap_root_after: &str,
    reserve_proof_root: &str,
    governance_proposal_id: &str,
) -> String {
    domain_hash(
        "TOKEN-SUPPLY-OPERATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operation_kind),
            HashPart::Str(asset_id),
            HashPart::Str(issuer_id),
            HashPart::Int(amount as i128),
            HashPart::Int(applied_at_height as i128),
            HashPart::Str(cap_root_before),
            HashPart::Str(cap_root_after),
            HashPart::Str(reserve_proof_root),
            HashPart::Str(governance_proposal_id),
        ],
        32,
    )
}

pub fn token_metadata_field_commitment(label: &str, value: &str, blinding: &str) -> String {
    domain_hash(
        "TOKEN-METADATA-FIELD-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn token_metadata_root(metadata: &Value) -> String {
    token_payload_root("TOKEN-METADATA", metadata)
}

pub fn token_metadata_commitment_root(metadata: &TokenMetadataCommitment) -> String {
    token_payload_root("TOKEN-METADATA-COMMITMENT", &metadata.public_record())
}

pub fn token_mint_burn_cap_root(cap: &MintBurnCap) -> String {
    token_payload_root("TOKEN-MINT-BURN-CAP", &cap.public_record())
}

pub fn token_transfer_policy_root(policy: &TokenTransferPolicy) -> String {
    token_payload_root("TOKEN-TRANSFER-POLICY", &policy.public_record())
}

pub fn token_risk_flag_root(asset_id: &str, flags: &[TokenRiskFlag]) -> String {
    let records = normalized_risk_flags(flags)
        .iter()
        .map(|flag| flag.public_record(asset_id))
        .collect::<Vec<_>>();
    merkle_root("TOKEN-RISK-FLAG", &records)
}

pub fn token_issuer_root_from_record(record: &Value) -> String {
    token_payload_root("TOKEN-ISSUER", record)
}

pub fn token_record_root_from_record(record: &Value) -> String {
    token_payload_root("TOKEN-RECORD", record)
}

pub fn token_reserve_proof_root_from_record(record: &Value) -> String {
    token_payload_root("TOKEN-RESERVE-PROOF", record)
}

pub fn token_fee_asset_entry_root_from_record(record: &Value) -> String {
    token_payload_root("TOKEN-FEE-ASSET-ENTRY", record)
}

pub fn token_supply_operation_root_from_record(record: &Value) -> String {
    token_payload_root("TOKEN-SUPPLY-OPERATION", record)
}

pub fn token_record_set_root(tokens: &[TokenRecord]) -> String {
    let mut records = tokens
        .iter()
        .map(|token| (token.asset_id.clone(), token.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "TOKEN-RECORD-SET",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn token_issuer_set_root(issuers: &[TokenIssuer]) -> String {
    let mut records = issuers
        .iter()
        .map(|issuer| (issuer.issuer_id.clone(), issuer.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "TOKEN-ISSUER-SET",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn token_transfer_policy_set_root(policies: &[TokenTransferPolicy]) -> String {
    let mut records = policies
        .iter()
        .map(|policy| (policy.policy_id.clone(), policy.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "TOKEN-TRANSFER-POLICY-SET",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn token_reserve_proof_set_root(proofs: &[WrappedMoneroReserveProof]) -> String {
    let mut records = proofs
        .iter()
        .map(|proof| (proof.reserve_proof_id.clone(), proof.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "TOKEN-RESERVE-PROOF-SET",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn token_fee_asset_allowlist_root(entries: &[TokenFeeAssetEntry]) -> String {
    let mut records = entries
        .iter()
        .map(|entry| (entry.entry_id.clone(), entry.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "TOKEN-FEE-ASSET-ALLOWLIST",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn token_supply_operation_set_root(operations: &[TokenSupplyOperation]) -> String {
    let mut records = operations
        .iter()
        .map(|operation| (operation.operation_id.clone(), operation.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "TOKEN-SUPPLY-OPERATION-SET",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn token_registry_state_root_from_record(record: &Value) -> String {
    token_payload_root("TOKEN-REGISTRY-STATE", record)
}

pub fn token_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn token_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn token_string_set_root(domain: &str, values: &[String]) -> String {
    let records = normalized_strings(values)
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn token_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn cap_remaining(cap: u64, used: u64) -> u64 {
    if cap == 0 {
        u64::MAX
    } else {
        cap.saturating_sub(used)
    }
}

fn validate_bps(value: u64, label: &str) -> TokenResult<()> {
    if value > 10_000 {
        Err(format!("{label} basis points exceed 100 percent"))
    } else {
        Ok(())
    }
}

fn validate_root_like(value: &str, label: &str) -> TokenResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_status(value: &str, allowed: &[&str], label: &str) -> TokenResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{label} is unsupported"))
    }
}

fn validate_symbol(symbol: &str) -> TokenResult<()> {
    if symbol.trim().is_empty() {
        return Err("token symbol cannot be empty".to_string());
    }
    if symbol.len() > TOKEN_MAX_SYMBOL_LEN {
        return Err("token symbol is too long".to_string());
    }
    if symbol != normalize_symbol(symbol) {
        return Err("token symbol must be normalized uppercase ASCII".to_string());
    }
    if !symbol
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
    {
        return Err("token symbol contains unsupported characters".to_string());
    }
    Ok(())
}

fn normalize_symbol(symbol: &str) -> String {
    symbol.trim().to_ascii_uppercase()
}

fn normalized_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_risk_flags(flags: &[TokenRiskFlag]) -> Vec<TokenRiskFlag> {
    flags
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn remove_risk_flag(flags: &mut Vec<TokenRiskFlag>, flag: &TokenRiskFlag) {
    flags.retain(|existing| existing != flag);
}
