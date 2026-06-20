use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FeeAbstractionResult<T> = Result<T, String>;

pub const FEE_ABSTRACTION_PROTOCOL_VERSION: &str = "nebula-fee-abstraction-v1";
pub const FEE_ABSTRACTION_MAX_BPS: u64 = 10_000;
pub const FEE_ABSTRACTION_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const FEE_ABSTRACTION_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const FEE_ABSTRACTION_DEFAULT_REBATE_EPOCH_BLOCKS: u64 = 64;
pub const FEE_ABSTRACTION_DEFAULT_SPONSOR_POOL_UNITS: u64 = 1_000_000;
pub const FEE_ABSTRACTION_DEFAULT_MAX_FEE_UNITS: u64 = 250_000;
pub const FEE_ABSTRACTION_PQ_AUTH_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const FEE_ABSTRACTION_KEM_SCHEME: &str = "ML-KEM-768";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneKind {
    PrivateTransfer,
    MoneroBridge,
    SmallDefi,
    ContractCall,
    ProofJob,
    EmergencyExit,
}

impl FeeLaneKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::SmallDefi => "small_defi",
            Self::ContractCall => "contract_call",
            Self::ProofJob => "proof_job",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_floor_units(&self) -> u64 {
        match self {
            Self::PrivateTransfer => 350,
            Self::MoneroBridge => 1_200,
            Self::SmallDefi => 650,
            Self::ContractCall => 900,
            Self::ProofJob => 1_800,
            Self::EmergencyExit => 2_500,
        }
    }

    pub fn default_priority_bps(&self) -> u64 {
        match self {
            Self::PrivateTransfer => 2_000,
            Self::MoneroBridge => 3_000,
            Self::SmallDefi => 2_500,
            Self::ContractCall => 2_600,
            Self::ProofJob => 2_900,
            Self::EmergencyExit => 5_000,
        }
    }

    pub fn privacy_weight_bps(&self) -> u64 {
        match self {
            Self::PrivateTransfer => 5_000,
            Self::MoneroBridge => 4_000,
            Self::SmallDefi => 3_000,
            Self::ContractCall => 3_500,
            Self::ProofJob => 2_000,
            Self::EmergencyExit => 4_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePaymentMode {
    Native,
    SponsorPool,
    PrivatePaymaster,
    RebateCredit,
    ProofSubsidy,
    BridgeExitNetting,
}

impl FeePaymentMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::SponsorPool => "sponsor_pool",
            Self::PrivatePaymaster => "private_paymaster",
            Self::RebateCredit => "rebate_credit",
            Self::ProofSubsidy => "proof_subsidy",
            Self::BridgeExitNetting => "bridge_exit_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeIntentStatus {
    Quoted,
    Reserved,
    Authorized,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl FeeIntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Authorized => "authorized",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Quoted | Self::Reserved | Self::Authorized)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rejected | Self::Expired | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Active,
    Draining,
    Paused,
    Exhausted,
    Expired,
}

impl SponsorPoolStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_reservations(&self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateWindowStatus {
    Open,
    Closing,
    Settled,
    Expired,
}

impl RebateWindowStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closing => "closing",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSlashingKind {
    DuplicateSpend,
    InvalidAuthorization,
    SponsorEquivocation,
    PaymasterPolicyBreach,
    RebateOverclaim,
}

impl FeeSlashingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DuplicateSpend => "duplicate_spend",
            Self::InvalidAuthorization => "invalid_authorization",
            Self::SponsorEquivocation => "sponsor_equivocation",
            Self::PaymasterPolicyBreach => "paymaster_policy_breach",
            Self::RebateOverclaim => "rebate_overclaim",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAbstractionConfig {
    pub quote_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub max_fee_units: u64,
    pub max_payload_bytes: u64,
    pub min_sponsor_reserve_units: u64,
    pub default_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub max_pending_intents: usize,
    pub require_pq_authorization: bool,
    pub require_private_metadata: bool,
}

impl Default for FeeAbstractionConfig {
    fn default() -> Self {
        Self {
            quote_ttl_blocks: FEE_ABSTRACTION_DEFAULT_QUOTE_TTL_BLOCKS,
            intent_ttl_blocks: FEE_ABSTRACTION_DEFAULT_INTENT_TTL_BLOCKS,
            rebate_epoch_blocks: FEE_ABSTRACTION_DEFAULT_REBATE_EPOCH_BLOCKS,
            max_fee_units: FEE_ABSTRACTION_DEFAULT_MAX_FEE_UNITS,
            max_payload_bytes: 16_384,
            min_sponsor_reserve_units: 10_000,
            default_rebate_bps: 2_000,
            max_rebate_bps: 7_500,
            max_pending_intents: 1_024,
            require_pq_authorization: true,
            require_private_metadata: true,
        }
    }
}

impl FeeAbstractionConfig {
    pub fn devnet() -> Self {
        Self {
            quote_ttl_blocks: 8,
            intent_ttl_blocks: 16,
            rebate_epoch_blocks: 16,
            max_fee_units: 500_000,
            max_payload_bytes: 32_768,
            min_sponsor_reserve_units: 1_000,
            default_rebate_bps: 3_500,
            max_rebate_bps: 8_500,
            max_pending_intents: 256,
            require_pq_authorization: true,
            require_private_metadata: true,
        }
    }

    pub fn validate(&self) -> FeeAbstractionResult<()> {
        ensure_positive(self.quote_ttl_blocks, "quote_ttl_blocks")?;
        ensure_positive(self.intent_ttl_blocks, "intent_ttl_blocks")?;
        ensure_positive(self.rebate_epoch_blocks, "rebate_epoch_blocks")?;
        ensure_positive(self.max_fee_units, "max_fee_units")?;
        ensure_positive(self.max_payload_bytes, "max_payload_bytes")?;
        ensure_positive(self.min_sponsor_reserve_units, "min_sponsor_reserve_units")?;
        ensure_bps(self.default_rebate_bps, "default_rebate_bps")?;
        ensure_bps(self.max_rebate_bps, "max_rebate_bps")?;
        if self.default_rebate_bps > self.max_rebate_bps {
            return Err("default rebate exceeds max rebate".to_string());
        }
        if self.max_pending_intents == 0 {
            return Err("max_pending_intents must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_abstraction_config",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_ABSTRACTION_PROTOCOL_VERSION,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
            "max_fee_units": self.max_fee_units,
            "max_payload_bytes": self.max_payload_bytes,
            "min_sponsor_reserve_units": self.min_sponsor_reserve_units,
            "default_rebate_bps": self.default_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "max_pending_intents": self.max_pending_intents as u64,
            "require_pq_authorization": self.require_pq_authorization,
            "require_private_metadata": self.require_private_metadata,
        })
    }

    pub fn config_root(&self) -> String {
        fee_abstraction_payload_root("FEE-ABSTRACTION-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAbstractionQuote {
    pub quote_id: String,
    pub lane: FeeLaneKind,
    pub payment_mode: FeePaymentMode,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub base_fee_units: u64,
    pub sponsor_rebate_units: u64,
    pub net_fee_units: u64,
    pub congestion_bps: u64,
    pub privacy_surcharge_bps: u64,
    pub priority_bps: u64,
    pub private_metadata_root: String,
    pub route_hint_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeAbstractionQuote {
    pub fn new(
        lane: FeeLaneKind,
        payment_mode: FeePaymentMode,
        fee_asset_id: impl Into<String>,
        base_fee_units: u64,
        congestion_bps: u64,
        privacy_surcharge_bps: u64,
        private_metadata: &Value,
        route_hint: &Value,
        height: u64,
        ttl_blocks: u64,
        max_rebate_bps: u64,
    ) -> FeeAbstractionResult<Self> {
        ensure_positive(base_fee_units, "base_fee_units")?;
        ensure_bps(congestion_bps, "congestion_bps")?;
        ensure_bps(privacy_surcharge_bps, "privacy_surcharge_bps")?;
        ensure_bps(max_rebate_bps, "max_rebate_bps")?;
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&fee_asset_id, "fee_asset_id")?;
        let congestion_fee = mul_bps_ceil(base_fee_units, congestion_bps);
        let privacy_fee = mul_bps_ceil(base_fee_units, privacy_surcharge_bps);
        let gross_fee_units = base_fee_units
            .saturating_add(congestion_fee)
            .saturating_add(privacy_fee);
        let rebate_units = match payment_mode {
            FeePaymentMode::Native => 0,
            FeePaymentMode::SponsorPool | FeePaymentMode::PrivatePaymaster => {
                mul_bps_floor(gross_fee_units, max_rebate_bps)
            }
            FeePaymentMode::RebateCredit => mul_bps_floor(gross_fee_units, max_rebate_bps / 2),
            FeePaymentMode::ProofSubsidy => mul_bps_floor(gross_fee_units, max_rebate_bps),
            FeePaymentMode::BridgeExitNetting => mul_bps_floor(gross_fee_units, max_rebate_bps / 3),
        };
        let net_fee_units = gross_fee_units.saturating_sub(rebate_units);
        let private_metadata_root =
            fee_abstraction_payload_root("FEE-PRIVATE-METADATA", private_metadata);
        let route_hint_root = fee_abstraction_payload_root("FEE-ROUTE-HINT", route_hint);
        let quote_payload = json!({
            "lane": lane.as_str(),
            "payment_mode": payment_mode.as_str(),
            "fee_asset_id": fee_asset_id,
            "base_fee_units": base_fee_units,
            "gross_fee_units": gross_fee_units,
            "net_fee_units": net_fee_units,
            "private_metadata_root": private_metadata_root,
            "route_hint_root": route_hint_root,
            "height": height,
        });
        let quote_id = fee_abstraction_id("FEE-QUOTE-ID", &quote_payload);
        Ok(Self {
            quote_id,
            lane,
            payment_mode,
            fee_asset_id,
            max_fee_units: gross_fee_units,
            base_fee_units,
            sponsor_rebate_units: rebate_units,
            net_fee_units,
            congestion_bps,
            privacy_surcharge_bps,
            priority_bps: lane.default_priority_bps(),
            private_metadata_root,
            route_hint_root,
            created_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks.max(1)),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_abstraction_quote",
            "chain_id": CHAIN_ID,
            "quote_id": self.quote_id,
            "lane": self.lane.as_str(),
            "payment_mode": self.payment_mode.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "base_fee_units": self.base_fee_units,
            "sponsor_rebate_units": self.sponsor_rebate_units,
            "net_fee_units": self.net_fee_units,
            "congestion_bps": self.congestion_bps,
            "privacy_surcharge_bps": self.privacy_surcharge_bps,
            "priority_bps": self.priority_bps,
            "private_metadata_root": self.private_metadata_root,
            "route_hint_root": self.route_hint_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn quote_root(&self) -> String {
        fee_abstraction_payload_root("FEE-QUOTE", &self.public_record())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub label: String,
    pub allowed_lanes: BTreeSet<FeeLaneKind>,
    pub asset_id: String,
    pub total_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_rebate_bps: u64,
    pub per_intent_cap_units: u64,
    pub status: SponsorPoolStatus,
    pub pq_admin_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorPool {
    pub fn new(
        label: impl Into<String>,
        sponsor_label: &str,
        allowed_lanes: impl IntoIterator<Item = FeeLaneKind>,
        asset_id: impl Into<String>,
        total_units: u64,
        max_rebate_bps: u64,
        per_intent_cap_units: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> FeeAbstractionResult<Self> {
        let label = label.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&label, "pool label")?;
        ensure_non_empty(sponsor_label, "sponsor label")?;
        ensure_non_empty(&asset_id, "asset_id")?;
        ensure_positive(total_units, "total_units")?;
        ensure_positive(per_intent_cap_units, "per_intent_cap_units")?;
        ensure_bps(max_rebate_bps, "max_rebate_bps")?;
        let allowed_lanes = allowed_lanes.into_iter().collect::<BTreeSet<_>>();
        if allowed_lanes.is_empty() {
            return Err("sponsor pool must allow at least one lane".to_string());
        }
        let sponsor_commitment = fee_abstraction_string_root("FEE-SPONSOR", sponsor_label);
        let pq_admin_root = fee_abstraction_string_root(
            "FEE-SPONSOR-PQ-ADMIN",
            &format!("{sponsor_label}:{FEE_ABSTRACTION_PQ_AUTH_SCHEME}"),
        );
        let pool_payload = json!({
            "label": label,
            "sponsor_commitment": sponsor_commitment,
            "asset_id": asset_id,
            "total_units": total_units,
            "height": height,
        });
        let pool_id = fee_abstraction_id("FEE-SPONSOR-POOL-ID", &pool_payload);
        Ok(Self {
            pool_id,
            sponsor_commitment,
            label,
            allowed_lanes,
            asset_id,
            total_units,
            reserved_units: 0,
            spent_units: 0,
            max_rebate_bps,
            per_intent_cap_units,
            status: SponsorPoolStatus::Active,
            pq_admin_root,
            created_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks.max(1)),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn can_cover(&self, lane: FeeLaneKind, amount_units: u64, height: u64) -> bool {
        self.status.accepts_reservations()
            && self.allowed_lanes.contains(&lane)
            && height <= self.expires_at_height
            && amount_units <= self.per_intent_cap_units
            && self.available_units() >= amount_units
    }

    pub fn reserve(
        &mut self,
        lane: FeeLaneKind,
        amount_units: u64,
        height: u64,
    ) -> FeeAbstractionResult<()> {
        ensure_positive(amount_units, "reserve amount")?;
        if !self.can_cover(lane, amount_units, height) {
            return Err("sponsor pool cannot cover fee reservation".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(amount_units);
        if self.available_units() == 0 {
            self.status = SponsorPoolStatus::Exhausted;
        }
        Ok(())
    }

    pub fn spend(&mut self, amount_units: u64) {
        let spend_units = amount_units.min(self.reserved_units);
        self.reserved_units = self.reserved_units.saturating_sub(spend_units);
        self.spent_units = self.spent_units.saturating_add(spend_units);
        if self.available_units() == 0 {
            self.status = SponsorPoolStatus::Exhausted;
        }
    }

    pub fn release(&mut self, amount_units: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(amount_units);
        if self.status == SponsorPoolStatus::Exhausted && self.available_units() > 0 {
            self.status = SponsorPoolStatus::Draining;
        }
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height > self.expires_at_height {
            self.status = SponsorPoolStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_pool",
            "chain_id": CHAIN_ID,
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "label": self.label,
            "allowed_lanes": self.allowed_lanes.iter().map(FeeLaneKind::as_str).collect::<Vec<_>>(),
            "asset_id": self.asset_id,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_rebate_bps": self.max_rebate_bps,
            "per_intent_cap_units": self.per_intent_cap_units,
            "status": self.status.as_str(),
            "pq_admin_root": self.pq_admin_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn pool_root(&self) -> String {
        fee_abstraction_payload_root("FEE-SPONSOR-POOL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterPolicy {
    pub policy_id: String,
    pub paymaster_commitment: String,
    pub allowed_contract_root: String,
    pub allowed_asset_root: String,
    pub max_fee_units: u64,
    pub max_user_rebate_bps: u64,
    pub private_condition_root: String,
    pub pq_policy_root: String,
    pub active: bool,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PaymasterPolicy {
    pub fn new(
        paymaster_label: &str,
        allowed_contracts: &[String],
        allowed_assets: &[String],
        max_fee_units: u64,
        max_user_rebate_bps: u64,
        private_condition: &Value,
        height: u64,
        ttl_blocks: u64,
    ) -> FeeAbstractionResult<Self> {
        ensure_non_empty(paymaster_label, "paymaster label")?;
        ensure_positive(max_fee_units, "max_fee_units")?;
        ensure_bps(max_user_rebate_bps, "max_user_rebate_bps")?;
        let paymaster_commitment = fee_abstraction_string_root("FEE-PAYMASTER", paymaster_label);
        let allowed_contract_root = fee_abstraction_string_set_root(
            "FEE-PAYMASTER-CONTRACTS",
            allowed_contracts.iter().map(String::as_str),
        );
        let allowed_asset_root = fee_abstraction_string_set_root(
            "FEE-PAYMASTER-ASSETS",
            allowed_assets.iter().map(String::as_str),
        );
        let private_condition_root =
            fee_abstraction_payload_root("FEE-PAYMASTER-PRIVATE-CONDITION", private_condition);
        let pq_policy_root = fee_abstraction_string_root(
            "FEE-PAYMASTER-PQ-POLICY",
            &format!("{paymaster_label}:{FEE_ABSTRACTION_PQ_AUTH_SCHEME}"),
        );
        let policy_payload = json!({
            "paymaster_commitment": paymaster_commitment,
            "allowed_contract_root": allowed_contract_root,
            "allowed_asset_root": allowed_asset_root,
            "height": height,
        });
        let policy_id = fee_abstraction_id("FEE-PAYMASTER-POLICY-ID", &policy_payload);
        Ok(Self {
            policy_id,
            paymaster_commitment,
            allowed_contract_root,
            allowed_asset_root,
            max_fee_units,
            max_user_rebate_bps,
            private_condition_root,
            pq_policy_root,
            active: true,
            created_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks.max(1)),
        })
    }

    pub fn allows_fee(&self, fee_units: u64, height: u64) -> bool {
        self.active && fee_units <= self.max_fee_units && height <= self.expires_at_height
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height > self.expires_at_height {
            self.active = false;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "paymaster_policy",
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "paymaster_commitment": self.paymaster_commitment,
            "allowed_contract_root": self.allowed_contract_root,
            "allowed_asset_root": self.allowed_asset_root,
            "max_fee_units": self.max_fee_units,
            "max_user_rebate_bps": self.max_user_rebate_bps,
            "private_condition_root": self.private_condition_root,
            "pq_policy_root": self.pq_policy_root,
            "active": self.active,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn policy_root(&self) -> String {
        fee_abstraction_payload_root("FEE-PAYMASTER-POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeIntent {
    pub intent_id: String,
    pub quote_id: String,
    pub payer_commitment: String,
    pub target_domain: String,
    pub lane: FeeLaneKind,
    pub payment_mode: FeePaymentMode,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub reserved_fee_units: u64,
    pub net_fee_units: u64,
    pub sponsor_pool_id: Option<String>,
    pub paymaster_policy_id: Option<String>,
    pub authorization_id: Option<String>,
    pub private_call_root: String,
    pub replay_nullifier: String,
    pub status: FeeIntentStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl FeeIntent {
    pub fn from_quote(
        quote: &FeeAbstractionQuote,
        payer_label: &str,
        target_domain: impl Into<String>,
        private_call: &Value,
        height: u64,
        ttl_blocks: u64,
    ) -> FeeAbstractionResult<Self> {
        ensure_non_empty(payer_label, "payer label")?;
        let target_domain = target_domain.into();
        ensure_non_empty(&target_domain, "target domain")?;
        if !quote.is_live_at(height) {
            return Err("fee quote expired".to_string());
        }
        let payer_commitment = fee_abstraction_string_root("FEE-PAYER", payer_label);
        let private_call_root = fee_abstraction_payload_root("FEE-PRIVATE-CALL", private_call);
        let replay_nullifier = fee_abstraction_id(
            "FEE-INTENT-REPLAY-NULLIFIER",
            &json!({
                "quote_id": quote.quote_id,
                "payer_commitment": payer_commitment,
                "private_call_root": private_call_root,
            }),
        );
        let intent_id = fee_abstraction_id(
            "FEE-INTENT-ID",
            &json!({
                "quote_id": quote.quote_id,
                "payer_commitment": payer_commitment,
                "target_domain": target_domain,
                "height": height,
            }),
        );
        Ok(Self {
            intent_id,
            quote_id: quote.quote_id.clone(),
            payer_commitment,
            target_domain,
            lane: quote.lane,
            payment_mode: quote.payment_mode,
            fee_asset_id: quote.fee_asset_id.clone(),
            gross_fee_units: quote.max_fee_units,
            reserved_fee_units: 0,
            net_fee_units: quote.net_fee_units,
            sponsor_pool_id: None,
            paymaster_policy_id: None,
            authorization_id: None,
            private_call_root,
            replay_nullifier,
            status: FeeIntentStatus::Quoted,
            created_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks.max(1)),
            settled_at_height: None,
        })
    }

    pub fn reserve_with_pool(
        &mut self,
        pool_id: impl Into<String>,
        reserved_units: u64,
    ) -> FeeAbstractionResult<()> {
        ensure_positive(reserved_units, "reserved_units")?;
        if !self.status.is_live() {
            return Err("fee intent is not reservable".to_string());
        }
        self.sponsor_pool_id = Some(pool_id.into());
        self.reserved_fee_units = reserved_units;
        self.status = FeeIntentStatus::Reserved;
        Ok(())
    }

    pub fn bind_paymaster(&mut self, policy_id: impl Into<String>) -> FeeAbstractionResult<()> {
        if !self.status.is_live() {
            return Err("fee intent is not paymaster bindable".to_string());
        }
        self.paymaster_policy_id = Some(policy_id.into());
        self.status = FeeIntentStatus::Reserved;
        Ok(())
    }

    pub fn authorize(&mut self, authorization_id: impl Into<String>) -> FeeAbstractionResult<()> {
        if !matches!(
            self.status,
            FeeIntentStatus::Quoted | FeeIntentStatus::Reserved
        ) {
            return Err("fee intent cannot be authorized in current status".to_string());
        }
        self.authorization_id = Some(authorization_id.into());
        self.status = FeeIntentStatus::Authorized;
        Ok(())
    }

    pub fn settle(&mut self, height: u64) -> FeeAbstractionResult<()> {
        if self.status != FeeIntentStatus::Authorized {
            return Err("fee intent must be authorized before settlement".to_string());
        }
        self.status = FeeIntentStatus::Settled;
        self.settled_at_height = Some(height);
        Ok(())
    }

    pub fn reject(&mut self) {
        if !self.status.is_terminal() {
            self.status = FeeIntentStatus::Rejected;
        }
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if self.status.is_live() && height > self.expires_at_height {
            self.status = FeeIntentStatus::Expired;
        }
    }

    pub fn slash(&mut self) {
        if !self.status.is_terminal() {
            self.status = FeeIntentStatus::Slashed;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_intent",
            "chain_id": CHAIN_ID,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "payer_commitment": self.payer_commitment,
            "target_domain": self.target_domain,
            "lane": self.lane.as_str(),
            "payment_mode": self.payment_mode.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "net_fee_units": self.net_fee_units,
            "sponsor_pool_id": self.sponsor_pool_id,
            "paymaster_policy_id": self.paymaster_policy_id,
            "authorization_id": self.authorization_id,
            "private_call_root": self.private_call_root,
            "replay_nullifier": self.replay_nullifier,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn intent_root(&self) -> String {
        fee_abstraction_payload_root("FEE-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAuthorization {
    pub authorization_id: String,
    pub intent_id: String,
    pub authorizer_commitment: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub kem_ciphertext_root: String,
    pub spending_limit_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeAuthorization {
    pub fn new(
        intent: &FeeIntent,
        authorizer_label: &str,
        spending_limit: &Value,
        height: u64,
        ttl_blocks: u64,
    ) -> FeeAbstractionResult<Self> {
        ensure_non_empty(authorizer_label, "authorizer label")?;
        let authorizer_commitment = fee_abstraction_string_root("FEE-AUTHORIZER", authorizer_label);
        let pq_public_key_root = fee_abstraction_string_root(
            "FEE-AUTH-PQ-PUBLIC-KEY",
            &format!("{authorizer_label}:{FEE_ABSTRACTION_PQ_AUTH_SCHEME}"),
        );
        let spending_limit_root =
            fee_abstraction_payload_root("FEE-AUTH-SPENDING-LIMIT", spending_limit);
        let kem_ciphertext_root = fee_abstraction_string_root(
            "FEE-AUTH-KEM-CIPHERTEXT",
            &format!("{}:{FEE_ABSTRACTION_KEM_SCHEME}", intent.intent_id),
        );
        let signature_payload = json!({
            "intent_id": intent.intent_id,
            "intent_root": intent.intent_root(),
            "authorizer_commitment": authorizer_commitment,
            "spending_limit_root": spending_limit_root,
            "issued_at_height": height,
        });
        let pq_signature_root =
            fee_abstraction_payload_root("FEE-AUTH-PQ-SIGNATURE", &signature_payload);
        let authorization_id = fee_abstraction_id("FEE-AUTHORIZATION-ID", &signature_payload);
        Ok(Self {
            authorization_id,
            intent_id: intent.intent_id.clone(),
            authorizer_commitment,
            pq_public_key_root,
            pq_signature_root,
            kem_ciphertext_root,
            spending_limit_root,
            issued_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks.max(1)),
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_authorization",
            "chain_id": CHAIN_ID,
            "authorization_id": self.authorization_id,
            "intent_id": self.intent_id,
            "authorizer_commitment": self.authorizer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "spending_limit_root": self.spending_limit_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn authorization_root(&self) -> String {
        fee_abstraction_payload_root("FEE-AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateWindow {
    pub window_id: String,
    pub lane: FeeLaneKind,
    pub fee_asset_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub rebate_bps: u64,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub participant_root: String,
    pub status: RebateWindowStatus,
}

impl RebateWindow {
    pub fn new(
        lane: FeeLaneKind,
        fee_asset_id: impl Into<String>,
        start_height: u64,
        epoch_blocks: u64,
        rebate_bps: u64,
        budget_units: u64,
        participants: &[String],
    ) -> FeeAbstractionResult<Self> {
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&fee_asset_id, "fee_asset_id")?;
        ensure_positive(epoch_blocks, "epoch_blocks")?;
        ensure_bps(rebate_bps, "rebate_bps")?;
        ensure_positive(budget_units, "budget_units")?;
        let participant_root = fee_abstraction_string_set_root(
            "FEE-REBATE-PARTICIPANTS",
            participants.iter().map(String::as_str),
        );
        let end_height = start_height.saturating_add(epoch_blocks);
        let window_id = fee_abstraction_id(
            "FEE-REBATE-WINDOW-ID",
            &json!({
                "lane": lane.as_str(),
                "fee_asset_id": fee_asset_id,
                "start_height": start_height,
                "end_height": end_height,
            }),
        );
        Ok(Self {
            window_id,
            lane,
            fee_asset_id,
            start_height,
            end_height,
            rebate_bps,
            budget_units,
            reserved_units: 0,
            settled_units: 0,
            participant_root,
            status: RebateWindowStatus::Open,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.settled_units)
    }

    pub fn reserve_for_quote(&mut self, quote: &FeeAbstractionQuote) -> u64 {
        if self.status != RebateWindowStatus::Open
            || self.lane != quote.lane
            || self.fee_asset_id != quote.fee_asset_id
        {
            return 0;
        }
        let rebate_units = mul_bps_floor(quote.max_fee_units, self.rebate_bps)
            .min(self.available_units())
            .min(quote.sponsor_rebate_units);
        self.reserved_units = self.reserved_units.saturating_add(rebate_units);
        rebate_units
    }

    pub fn settle(&mut self, amount_units: u64) {
        let amount_units = amount_units.min(self.reserved_units);
        self.reserved_units = self.reserved_units.saturating_sub(amount_units);
        self.settled_units = self.settled_units.saturating_add(amount_units);
    }

    pub fn tick(&mut self, height: u64) {
        if self.status == RebateWindowStatus::Open && height >= self.end_height {
            self.status = RebateWindowStatus::Closing;
        }
        if self.status == RebateWindowStatus::Closing && self.reserved_units == 0 {
            self.status = RebateWindowStatus::Settled;
        }
        if height > self.end_height.saturating_add(32) && self.status != RebateWindowStatus::Settled
        {
            self.status = RebateWindowStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_window",
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "rebate_bps": self.rebate_bps,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "settled_units": self.settled_units,
            "available_units": self.available_units(),
            "participant_root": self.participant_root,
            "status": self.status.as_str(),
        })
    }

    pub fn window_root(&self) -> String {
        fee_abstraction_payload_root("FEE-REBATE-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSettlementReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub fee_asset_id: String,
    pub charged_units: u64,
    pub sponsor_paid_units: u64,
    pub payer_paid_units: u64,
    pub rebate_units: u64,
    pub state_transition_root: String,
    pub emitted_event_root: String,
    pub settled_at_height: u64,
}

impl FeeSettlementReceipt {
    pub fn new(
        intent: &FeeIntent,
        state_transition: &Value,
        emitted_event: &Value,
        settled_at_height: u64,
    ) -> Self {
        let state_transition_root =
            fee_abstraction_payload_root("FEE-SETTLEMENT-STATE", state_transition);
        let emitted_event_root =
            fee_abstraction_payload_root("FEE-SETTLEMENT-EVENT", emitted_event);
        let sponsor_paid_units = intent.reserved_fee_units.min(intent.gross_fee_units);
        let payer_paid_units = intent.net_fee_units.saturating_sub(sponsor_paid_units);
        let rebate_units = intent.gross_fee_units.saturating_sub(intent.net_fee_units);
        let receipt_id = fee_abstraction_id(
            "FEE-SETTLEMENT-RECEIPT-ID",
            &json!({
                "intent_id": intent.intent_id,
                "quote_id": intent.quote_id,
                "state_transition_root": state_transition_root,
                "settled_at_height": settled_at_height,
            }),
        );
        Self {
            receipt_id,
            intent_id: intent.intent_id.clone(),
            quote_id: intent.quote_id.clone(),
            fee_asset_id: intent.fee_asset_id.clone(),
            charged_units: intent.net_fee_units,
            sponsor_paid_units,
            payer_paid_units,
            rebate_units,
            state_transition_root,
            emitted_event_root,
            settled_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_settlement_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "fee_asset_id": self.fee_asset_id,
            "charged_units": self.charged_units,
            "sponsor_paid_units": self.sponsor_paid_units,
            "payer_paid_units": self.payer_paid_units,
            "rebate_units": self.rebate_units,
            "state_transition_root": self.state_transition_root,
            "emitted_event_root": self.emitted_event_root,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        fee_abstraction_payload_root("FEE-SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSlashingEvidence {
    pub evidence_id: String,
    pub kind: FeeSlashingKind,
    pub subject_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub penalty_units: u64,
    pub created_at_height: u64,
}

impl FeeSlashingEvidence {
    pub fn new(
        kind: FeeSlashingKind,
        subject_id: &str,
        reporter_label: &str,
        evidence: &Value,
        penalty_units: u64,
        height: u64,
    ) -> FeeAbstractionResult<Self> {
        ensure_non_empty(subject_id, "subject_id")?;
        ensure_non_empty(reporter_label, "reporter_label")?;
        ensure_positive(penalty_units, "penalty_units")?;
        let reporter_commitment = fee_abstraction_string_root("FEE-SLASH-REPORTER", reporter_label);
        let evidence_root = fee_abstraction_payload_root("FEE-SLASH-EVIDENCE", evidence);
        let evidence_id = fee_abstraction_id(
            "FEE-SLASH-EVIDENCE-ID",
            &json!({
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "reporter_commitment": reporter_commitment,
                "evidence_root": evidence_root,
                "height": height,
            }),
        );
        Ok(Self {
            evidence_id,
            kind,
            subject_id: subject_id.to_string(),
            reporter_commitment,
            evidence_root,
            penalty_units,
            created_at_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_slashing_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "slash_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "penalty_units": self.penalty_units,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn evidence_root(&self) -> String {
        fee_abstraction_payload_root("FEE-SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAbstractionRoots {
    pub quote_root: String,
    pub intent_root: String,
    pub sponsor_pool_root: String,
    pub paymaster_policy_root: String,
    pub authorization_root: String,
    pub rebate_window_root: String,
    pub settlement_receipt_root: String,
    pub slashing_evidence_root: String,
    pub replay_registry_root: String,
}

impl FeeAbstractionRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_abstraction_roots",
            "chain_id": CHAIN_ID,
            "quote_root": self.quote_root,
            "intent_root": self.intent_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "paymaster_policy_root": self.paymaster_policy_root,
            "authorization_root": self.authorization_root,
            "rebate_window_root": self.rebate_window_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "replay_registry_root": self.replay_registry_root,
        })
    }

    pub fn roots_root(&self) -> String {
        fee_abstraction_payload_root("FEE-ABSTRACTION-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAbstractionState {
    pub config: FeeAbstractionConfig,
    pub height: u64,
    pub quotes: BTreeMap<String, FeeAbstractionQuote>,
    pub intents: BTreeMap<String, FeeIntent>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub paymaster_policies: BTreeMap<String, PaymasterPolicy>,
    pub authorizations: BTreeMap<String, FeeAuthorization>,
    pub rebate_windows: BTreeMap<String, RebateWindow>,
    pub settlement_receipts: BTreeMap<String, FeeSettlementReceipt>,
    pub slashing_evidence: BTreeMap<String, FeeSlashingEvidence>,
    pub replay_registry: BTreeSet<String>,
}

impl FeeAbstractionState {
    pub fn new(config: FeeAbstractionConfig) -> FeeAbstractionResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            quotes: BTreeMap::new(),
            intents: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            paymaster_policies: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            rebate_windows: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            replay_registry: BTreeSet::new(),
        })
    }

    pub fn devnet(operator_label: &str) -> FeeAbstractionResult<Self> {
        let mut state = Self::new(FeeAbstractionConfig::devnet())?;
        state.set_height(8);
        let pool_private = SponsorPool::new(
            "devnet-private-fee-pool",
            operator_label,
            [FeeLaneKind::PrivateTransfer, FeeLaneKind::ContractCall],
            "wrapped-xmr",
            FEE_ABSTRACTION_DEFAULT_SPONSOR_POOL_UNITS,
            7_500,
            50_000,
            state.height,
            512,
        )?;
        let pool_bridge = SponsorPool::new(
            "devnet-bridge-exit-pool",
            "devnet-bridge-sponsor",
            [FeeLaneKind::MoneroBridge, FeeLaneKind::EmergencyExit],
            "wrapped-xmr",
            750_000,
            6_000,
            90_000,
            state.height,
            512,
        )?;
        let pool_proofs = SponsorPool::new(
            "devnet-proof-subsidy-pool",
            "devnet-prover-sponsor",
            [FeeLaneKind::ProofJob, FeeLaneKind::SmallDefi],
            "wrapped-xmr",
            500_000,
            8_500,
            120_000,
            state.height,
            512,
        )?;
        let private_pool_id = pool_private.pool_id.clone();
        let bridge_pool_id = pool_bridge.pool_id.clone();
        let proof_pool_id = pool_proofs.pool_id.clone();
        state.insert_sponsor_pool(pool_private)?;
        state.insert_sponsor_pool(pool_bridge)?;
        state.insert_sponsor_pool(pool_proofs)?;

        let policy = PaymasterPolicy::new(
            "devnet-private-contract-paymaster",
            &[
                "private-swap-router".to_string(),
                "private-lending-market".to_string(),
                "shielded-token-vault".to_string(),
            ],
            &["wrapped-xmr".to_string(), "dxusd".to_string()],
            80_000,
            7_000,
            &json!({
                "privacy": "commitment_only",
                "max_view_tag_bits": 16,
                "requires_pq_session": true,
            }),
            state.height,
            256,
        )?;
        let policy_id = policy.policy_id.clone();
        state.insert_paymaster_policy(policy)?;

        let rebate_private = RebateWindow::new(
            FeeLaneKind::PrivateTransfer,
            "wrapped-xmr",
            state.height,
            state.config.rebate_epoch_blocks,
            state.config.default_rebate_bps,
            250_000,
            &["devnet-private-fee-pool".to_string()],
        )?;
        let rebate_proofs = RebateWindow::new(
            FeeLaneKind::ProofJob,
            "wrapped-xmr",
            state.height,
            state.config.rebate_epoch_blocks,
            6_000,
            180_000,
            &["devnet-proof-subsidy-pool".to_string()],
        )?;
        state.insert_rebate_window(rebate_private)?;
        state.insert_rebate_window(rebate_proofs)?;

        let private_quote_id = state.create_quote(
            FeeLaneKind::PrivateTransfer,
            FeePaymentMode::SponsorPool,
            "wrapped-xmr",
            2_000,
            800,
            FeeLaneKind::PrivateTransfer.privacy_weight_bps(),
            &json!({"note": "shielded-transfer", "view": "root-only"}),
            &json!({"route": "private-mempool", "qos": "low-fee"}),
        )?;
        let private_intent_id = state.submit_intent(
            &private_quote_id,
            "devnet-shielded-user-0",
            "privacy_pool",
            &json!({"action": "shielded_transfer", "amount_bucket": "small"}),
        )?;
        state.reserve_intent_from_pool(&private_intent_id, &private_pool_id)?;
        state.authorize_intent(
            &private_intent_id,
            "devnet-shielded-user-0",
            &json!({"max_fee_units": 2_000, "scope": "privacy_pool"}),
        )?;
        state.settle_intent(
            &private_intent_id,
            &json!({"nullifier": "devnet-fee-nullifier-0"}),
            &json!({"event": "fee_settled", "lane": "private_transfer"}),
        )?;

        let bridge_quote_id = state.create_quote(
            FeeLaneKind::MoneroBridge,
            FeePaymentMode::BridgeExitNetting,
            "wrapped-xmr",
            8_000,
            1_200,
            FeeLaneKind::MoneroBridge.privacy_weight_bps(),
            &json!({"exit": "batched-monero", "address": "hidden"}),
            &json!({"route": "monero-exit-circuit", "batch": "fast"}),
        )?;
        let bridge_intent_id = state.submit_intent(
            &bridge_quote_id,
            "devnet-bridge-user-0",
            "monero_exit_circuit",
            &json!({"action": "exit", "amount_bucket": "medium"}),
        )?;
        state.reserve_intent_from_pool(&bridge_intent_id, &bridge_pool_id)?;
        state.authorize_intent(
            &bridge_intent_id,
            "devnet-bridge-user-0",
            &json!({"max_fee_units": 10_000, "scope": "monero_exit"}),
        )?;

        let contract_quote_id = state.create_quote(
            FeeLaneKind::ContractCall,
            FeePaymentMode::PrivatePaymaster,
            "dxusd",
            4_000,
            1_000,
            FeeLaneKind::ContractCall.privacy_weight_bps(),
            &json!({"contract": "private-swap-router", "selector": "hidden"}),
            &json!({"route": "contract-vm", "gas": "sponsored"}),
        )?;
        let contract_intent_id = state.submit_intent(
            &contract_quote_id,
            "devnet-contract-user-0",
            "private_contracts",
            &json!({"action": "swap", "input": "encrypted"}),
        )?;
        state.bind_intent_to_paymaster(&contract_intent_id, &policy_id)?;
        state.authorize_intent(
            &contract_intent_id,
            "devnet-contract-user-0",
            &json!({"max_fee_units": 5_000, "scope": "private_contract"}),
        )?;

        let proof_quote_id = state.create_quote(
            FeeLaneKind::ProofJob,
            FeePaymentMode::ProofSubsidy,
            "wrapped-xmr",
            14_000,
            1_500,
            FeeLaneKind::ProofJob.privacy_weight_bps(),
            &json!({"proof": "recursive-batch", "witness": "private"}),
            &json!({"route": "prover-market", "compression": true}),
        )?;
        let proof_intent_id = state.submit_intent(
            &proof_quote_id,
            "devnet-prover-client-0",
            "proof_compression",
            &json!({"proof_job": "recursive-private-batch"}),
        )?;
        state.reserve_intent_from_pool(&proof_intent_id, &proof_pool_id)?;
        state.authorize_intent(
            &proof_intent_id,
            "devnet-prover-client-0",
            &json!({"max_fee_units": 15_000, "scope": "proof_job"}),
        )?;

        let slash = FeeSlashingEvidence::new(
            FeeSlashingKind::SponsorEquivocation,
            &proof_pool_id,
            "devnet-watchtower-fees",
            &json!({"duplicate_rebate_window": false, "severity": "watch"}),
            500,
            state.height,
        )?;
        state.insert_slashing_evidence(slash)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for pool in self.sponsor_pools.values_mut() {
            pool.expire_if_due(height);
        }
        for policy in self.paymaster_policies.values_mut() {
            policy.expire_if_due(height);
        }
        for intent in self.intents.values_mut() {
            intent.expire_if_due(height);
        }
        for window in self.rebate_windows.values_mut() {
            window.tick(height);
        }
    }

    pub fn insert_sponsor_pool(&mut self, pool: SponsorPool) -> FeeAbstractionResult<()> {
        if self.sponsor_pools.contains_key(&pool.pool_id) {
            return Err("duplicate sponsor pool".to_string());
        }
        self.sponsor_pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }

    pub fn insert_paymaster_policy(&mut self, policy: PaymasterPolicy) -> FeeAbstractionResult<()> {
        if self.paymaster_policies.contains_key(&policy.policy_id) {
            return Err("duplicate paymaster policy".to_string());
        }
        self.paymaster_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn insert_rebate_window(&mut self, window: RebateWindow) -> FeeAbstractionResult<()> {
        if self.rebate_windows.contains_key(&window.window_id) {
            return Err("duplicate rebate window".to_string());
        }
        self.rebate_windows.insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn insert_slashing_evidence(
        &mut self,
        evidence: FeeSlashingEvidence,
    ) -> FeeAbstractionResult<()> {
        if self.slashing_evidence.contains_key(&evidence.evidence_id) {
            return Err("duplicate fee slashing evidence".to_string());
        }
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn create_quote(
        &mut self,
        lane: FeeLaneKind,
        payment_mode: FeePaymentMode,
        fee_asset_id: impl Into<String>,
        base_fee_units: u64,
        congestion_bps: u64,
        privacy_surcharge_bps: u64,
        private_metadata: &Value,
        route_hint: &Value,
    ) -> FeeAbstractionResult<String> {
        let quote = FeeAbstractionQuote::new(
            lane,
            payment_mode,
            fee_asset_id,
            base_fee_units.max(lane.default_floor_units()),
            congestion_bps,
            privacy_surcharge_bps,
            private_metadata,
            route_hint,
            self.height,
            self.config.quote_ttl_blocks,
            self.config.max_rebate_bps,
        )?;
        if quote.max_fee_units > self.config.max_fee_units {
            return Err("fee quote exceeds configured max fee".to_string());
        }
        let quote_id = quote.quote_id.clone();
        for window in self.rebate_windows.values_mut() {
            window.reserve_for_quote(&quote);
        }
        self.quotes.insert(quote_id.clone(), quote);
        Ok(quote_id)
    }

    pub fn submit_intent(
        &mut self,
        quote_id: &str,
        payer_label: &str,
        target_domain: impl Into<String>,
        private_call: &Value,
    ) -> FeeAbstractionResult<String> {
        if self.live_intent_count() as usize >= self.config.max_pending_intents {
            return Err("fee abstraction pending intent capacity reached".to_string());
        }
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| format!("fee quote not found: {quote_id}"))?;
        let intent = FeeIntent::from_quote(
            quote,
            payer_label,
            target_domain,
            private_call,
            self.height,
            self.config.intent_ttl_blocks,
        )?;
        if self.replay_registry.contains(&intent.replay_nullifier) {
            return Err("fee intent replay nullifier already used".to_string());
        }
        let intent_id = intent.intent_id.clone();
        self.replay_registry.insert(intent.replay_nullifier.clone());
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn reserve_intent_from_pool(
        &mut self,
        intent_id: &str,
        pool_id: &str,
    ) -> FeeAbstractionResult<()> {
        let (lane, rebate_units) = {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("fee intent not found: {intent_id}"))?;
            let quote = self
                .quotes
                .get(&intent.quote_id)
                .ok_or_else(|| format!("fee quote not found: {}", intent.quote_id))?;
            (intent.lane, quote.sponsor_rebate_units)
        };
        let pool = self
            .sponsor_pools
            .get_mut(pool_id)
            .ok_or_else(|| format!("sponsor pool not found: {pool_id}"))?;
        pool.reserve(lane, rebate_units.max(1), self.height)?;
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("fee intent not found: {intent_id}"))?;
        intent.reserve_with_pool(pool_id, rebate_units.max(1))?;
        Ok(())
    }

    pub fn bind_intent_to_paymaster(
        &mut self,
        intent_id: &str,
        policy_id: &str,
    ) -> FeeAbstractionResult<()> {
        let net_fee_units = self
            .intents
            .get(intent_id)
            .ok_or_else(|| format!("fee intent not found: {intent_id}"))?
            .net_fee_units;
        let policy = self
            .paymaster_policies
            .get(policy_id)
            .ok_or_else(|| format!("paymaster policy not found: {policy_id}"))?;
        if !policy.allows_fee(net_fee_units, self.height) {
            return Err("paymaster policy does not allow fee".to_string());
        }
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("fee intent not found: {intent_id}"))?;
        intent.bind_paymaster(policy_id)?;
        Ok(())
    }

    pub fn authorize_intent(
        &mut self,
        intent_id: &str,
        authorizer_label: &str,
        spending_limit: &Value,
    ) -> FeeAbstractionResult<String> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| format!("fee intent not found: {intent_id}"))?
            .clone();
        let authorization = FeeAuthorization::new(
            &intent,
            authorizer_label,
            spending_limit,
            self.height,
            self.config.intent_ttl_blocks,
        )?;
        let authorization_id = authorization.authorization_id.clone();
        self.authorizations
            .insert(authorization_id.clone(), authorization);
        self.intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("fee intent not found: {intent_id}"))?
            .authorize(&authorization_id)?;
        Ok(authorization_id)
    }

    pub fn settle_intent(
        &mut self,
        intent_id: &str,
        state_transition: &Value,
        emitted_event: &Value,
    ) -> FeeAbstractionResult<String> {
        let intent_snapshot = {
            let intent = self
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| format!("fee intent not found: {intent_id}"))?;
            if let Some(authorization_id) = &intent.authorization_id {
                let authorization = self
                    .authorizations
                    .get(authorization_id)
                    .ok_or_else(|| format!("fee authorization not found: {authorization_id}"))?;
                if !authorization.is_live_at(self.height) {
                    return Err("fee authorization expired".to_string());
                }
            }
            intent.settle(self.height)?;
            intent.clone()
        };
        if let Some(pool_id) = &intent_snapshot.sponsor_pool_id {
            if let Some(pool) = self.sponsor_pools.get_mut(pool_id) {
                pool.spend(intent_snapshot.reserved_fee_units);
            }
        }
        for window in self.rebate_windows.values_mut() {
            if window.lane == intent_snapshot.lane
                && window.fee_asset_id == intent_snapshot.fee_asset_id
            {
                window.settle(
                    intent_snapshot
                        .gross_fee_units
                        .saturating_sub(intent_snapshot.net_fee_units),
                );
            }
        }
        let receipt = FeeSettlementReceipt::new(
            &intent_snapshot,
            state_transition,
            emitted_event,
            self.height,
        );
        let receipt_id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn reject_intent(&mut self, intent_id: &str) -> FeeAbstractionResult<()> {
        let (pool_id, reserved_units) = {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("fee intent not found: {intent_id}"))?;
            (intent.sponsor_pool_id.clone(), intent.reserved_fee_units)
        };
        if let Some(pool_id) = pool_id {
            if let Some(pool) = self.sponsor_pools.get_mut(&pool_id) {
                pool.release(reserved_units);
            }
        }
        self.intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("fee intent not found: {intent_id}"))?
            .reject();
        Ok(())
    }

    pub fn roots(&self) -> FeeAbstractionRoots {
        let quote_records = self
            .quotes
            .values()
            .map(FeeAbstractionQuote::public_record)
            .collect::<Vec<_>>();
        let intent_records = self
            .intents
            .values()
            .map(FeeIntent::public_record)
            .collect::<Vec<_>>();
        let pool_records = self
            .sponsor_pools
            .values()
            .map(SponsorPool::public_record)
            .collect::<Vec<_>>();
        let policy_records = self
            .paymaster_policies
            .values()
            .map(PaymasterPolicy::public_record)
            .collect::<Vec<_>>();
        let authorization_records = self
            .authorizations
            .values()
            .map(FeeAuthorization::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebate_windows
            .values()
            .map(RebateWindow::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .settlement_receipts
            .values()
            .map(FeeSettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let slash_records = self
            .slashing_evidence
            .values()
            .map(FeeSlashingEvidence::public_record)
            .collect::<Vec<_>>();
        let replay_records = self
            .replay_registry
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        FeeAbstractionRoots {
            quote_root: merkle_root("FEE-QUOTE", &quote_records),
            intent_root: merkle_root("FEE-INTENT", &intent_records),
            sponsor_pool_root: merkle_root("FEE-SPONSOR-POOL", &pool_records),
            paymaster_policy_root: merkle_root("FEE-PAYMASTER-POLICY", &policy_records),
            authorization_root: merkle_root("FEE-AUTHORIZATION", &authorization_records),
            rebate_window_root: merkle_root("FEE-REBATE-WINDOW", &rebate_records),
            settlement_receipt_root: merkle_root("FEE-SETTLEMENT-RECEIPT", &receipt_records),
            slashing_evidence_root: merkle_root("FEE-SLASHING-EVIDENCE", &slash_records),
            replay_registry_root: merkle_root("FEE-REPLAY-REGISTRY", &replay_records),
        }
    }

    pub fn live_intent_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status.is_live())
            .count() as u64
    }

    pub fn settled_intent_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status == FeeIntentStatus::Settled)
            .count() as u64
    }

    pub fn active_sponsor_pool_count(&self) -> u64 {
        self.sponsor_pools
            .values()
            .filter(|pool| pool.status.accepts_reservations())
            .count() as u64
    }

    pub fn total_available_sponsor_units(&self) -> u64 {
        self.sponsor_pools
            .values()
            .map(SponsorPool::available_units)
            .sum()
    }

    pub fn total_reserved_units(&self) -> u64 {
        self.sponsor_pools
            .values()
            .map(|pool| pool.reserved_units)
            .sum()
    }

    pub fn total_spent_units(&self) -> u64 {
        self.sponsor_pools
            .values()
            .map(|pool| pool.spent_units)
            .sum()
    }

    pub fn active_quote_ids(&self) -> Vec<String> {
        self.quotes
            .values()
            .filter(|quote| quote.is_live_at(self.height))
            .map(|quote| quote.quote_id.clone())
            .collect()
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "fee_abstraction_state",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_ABSTRACTION_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "quote_count": self.quotes.len() as u64,
            "intent_count": self.intents.len() as u64,
            "live_intent_count": self.live_intent_count(),
            "settled_intent_count": self.settled_intent_count(),
            "sponsor_pool_count": self.sponsor_pools.len() as u64,
            "active_sponsor_pool_count": self.active_sponsor_pool_count(),
            "paymaster_policy_count": self.paymaster_policies.len() as u64,
            "authorization_count": self.authorizations.len() as u64,
            "rebate_window_count": self.rebate_windows.len() as u64,
            "settlement_receipt_count": self.settlement_receipts.len() as u64,
            "slashing_evidence_count": self.slashing_evidence.len() as u64,
            "replay_registry_count": self.replay_registry.len() as u64,
            "total_available_sponsor_units": self.total_available_sponsor_units(),
            "total_reserved_units": self.total_reserved_units(),
            "total_spent_units": self.total_spent_units(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_root();
        let state_root = fee_abstraction_state_root_from_record(&record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        fee_abstraction_state_root_from_record(&self.public_record_without_root())
    }

    pub fn validate(&self) -> FeeAbstractionResult<()> {
        self.config.validate()?;
        for intent in self.intents.values() {
            if !self.quotes.contains_key(&intent.quote_id) {
                return Err(format!(
                    "fee intent references missing quote: {}",
                    intent.quote_id
                ));
            }
            if let Some(pool_id) = &intent.sponsor_pool_id {
                if !self.sponsor_pools.contains_key(pool_id) {
                    return Err(format!(
                        "fee intent references missing sponsor pool: {pool_id}"
                    ));
                }
            }
            if let Some(policy_id) = &intent.paymaster_policy_id {
                if !self.paymaster_policies.contains_key(policy_id) {
                    return Err(format!(
                        "fee intent references missing paymaster policy: {policy_id}"
                    ));
                }
            }
            if let Some(authorization_id) = &intent.authorization_id {
                if !self.authorizations.contains_key(authorization_id) {
                    return Err(format!(
                        "fee intent references missing authorization: {authorization_id}"
                    ));
                }
            }
        }
        Ok(())
    }
}

pub fn fee_abstraction_state_root_from_record(record: &Value) -> String {
    fee_abstraction_payload_root("FEE-ABSTRACTION-STATE", record)
}

pub fn fee_abstraction_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn fee_abstraction_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn fee_abstraction_string_set_root<'a>(
    domain: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> String {
    let records = values
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn fee_abstraction_id(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 20)
}

pub fn ensure_non_empty(value: &str, label: &str) -> FeeAbstractionResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_positive(value: u64, label: &str) -> FeeAbstractionResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

pub fn ensure_bps(value: u64, label: &str) -> FeeAbstractionResult<()> {
    if value > FEE_ABSTRACTION_MAX_BPS {
        Err(format!("{label} exceeds {FEE_ABSTRACTION_MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

pub fn mul_bps_floor(value: u64, bps: u64) -> u64 {
    value.saturating_mul(bps) / FEE_ABSTRACTION_MAX_BPS
}

pub fn mul_bps_ceil(value: u64, bps: u64) -> u64 {
    if value == 0 || bps == 0 {
        0
    } else {
        value
            .saturating_mul(bps)
            .saturating_add(FEE_ABSTRACTION_MAX_BPS - 1)
            / FEE_ABSTRACTION_MAX_BPS
    }
}
