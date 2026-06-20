use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateTokenConfidentialAmmHooksResult<T> = Result<T, String>;

pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_PROTOCOL_VERSION: &str =
    "nebula-private-token-confidential-amm-hooks-v1";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_SWAP_PROOF_SYSTEM: &str =
    "zk-confidential-amm-hook-swap-devnet-v1";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_LP_PROOF_SYSTEM: &str =
    "zk-confidential-lp-envelope-devnet-v1";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-confidential-amm-hook-v1";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_COMMITMENT_SCHEME: &str =
    "anti-sandwich-sealed-route-commitment-v1";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_RECEIPT_SCHEME: &str =
    "confidential-amm-settlement-receipt-v1";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_SPONSOR_SCHEME: &str =
    "low-fee-private-token-hook-sponsor-v1";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_HEIGHT: u64 = 2_720;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_EPOCH_BLOCKS: u64 = 16;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_HOOK_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 2;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 32;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_SPONSOR_BOND_UNITS: u128 = 15_000_000;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_POOL_FEE_BPS: u64 = 100;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_PROTOCOL_FEE_SHARE_BPS: u64 = 750;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 600;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 500;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_HOOKS_PER_POOL: usize = 128;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_PENDING_SWAPS: usize = 65_536;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_BPS: u64 = 10_000;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_POOLS: usize = 16_384;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_TOKENS: usize = 65_536;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_HOOKS: usize = 262_144;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_SWAPS: usize = 1_048_576;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_LP_ENVELOPES: usize = 1_048_576;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_ATTESTATIONS: usize = 1_048_576;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_SPONSORSHIPS: usize = 1_048_576;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_CHALLENGES: usize = 1_048_576;
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_FEE_TOKEN: &str = "dxmr";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_STABLE_TOKEN: &str = "dusd";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_GOV_TOKEN: &str = "dnr";
pub const PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_RWA_TOKEN: &str = "drwa";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialAmmPoolKind {
    ConstantProduct,
    Stable,
    Concentrated,
    Weighted,
    Rwa,
}

impl ConfidentialAmmPoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::Stable => "stable",
            Self::Concentrated => "concentrated",
            Self::Weighted => "weighted",
            Self::Rwa => "rwa",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialTokenClass {
    Native,
    Stable,
    Governance,
    BridgeWrapped,
    Synthetic,
    Rwa,
}

impl ConfidentialTokenClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Stable => "stable",
            Self::Governance => "governance",
            Self::BridgeWrapped => "bridge_wrapped",
            Self::Synthetic => "synthetic",
            Self::Rwa => "rwa",
        }
    }

    pub fn default_risk_weight_bps(self) -> u64 {
        match self {
            Self::Stable => 150,
            Self::Native => 300,
            Self::BridgeWrapped => 550,
            Self::Governance => 700,
            Self::Synthetic => 950,
            Self::Rwa => 1_250,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialAmmHookKind {
    PreSwap,
    PostSwap,
    LiquidityDeposit,
    LiquidityWithdraw,
    FeeSponsor,
    OracleGuard,
    AntiSandwich,
    Settlement,
}

impl ConfidentialAmmHookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreSwap => "pre_swap",
            Self::PostSwap => "post_swap",
            Self::LiquidityDeposit => "liquidity_deposit",
            Self::LiquidityWithdraw => "liquidity_withdraw",
            Self::FeeSponsor => "fee_sponsor",
            Self::OracleGuard => "oracle_guard",
            Self::AntiSandwich => "anti_sandwich",
            Self::Settlement => "settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialAmmHookStatus {
    Draft,
    Active,
    Throttled,
    Paused,
    Retired,
    Slashed,
}

impl ConfidentialAmmHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_private_flow(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialSwapSide {
    ExactInput,
    ExactOutput,
    PrivateRoute,
    BatchIntent,
}

impl ConfidentialSwapSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactInput => "exact_input",
            Self::ExactOutput => "exact_output",
            Self::PrivateRoute => "private_route",
            Self::BatchIntent => "batch_intent",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialSwapStatus {
    Committed,
    Hooked,
    Attested,
    Sponsored,
    Settled,
    Challenged,
    Rejected,
    Expired,
}

impl ConfidentialSwapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Hooked => "hooked",
            Self::Attested => "attested",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LpEnvelopeKind {
    Mint,
    Burn,
    RangeShift,
    FeeClaim,
    Rebalance,
}

impl LpEnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::RangeShift => "range_shift",
            Self::FeeClaim => "fee_claim",
            Self::Rebalance => "rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LpEnvelopeStatus {
    Sealed,
    Admitted,
    Applied,
    Challenged,
    Rejected,
    Expired,
}

impl LpEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAttestationStatus {
    Pending,
    Valid,
    Superseded,
    Disputed,
    Revoked,
}

impl HookAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reimbursed,
    Challenged,
    Slashed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reimbursed => "reimbursed",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Proposed,
    Finalized,
    Challenged,
    Reverted,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookChallengeKind {
    InvalidPqAttestation,
    AllowlistBypass,
    SandwichRevealMismatch,
    FeeOvercharge,
    InvalidLpEnvelope,
    SettlementMismatch,
    LateSettlement,
}

impl HookChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::AllowlistBypass => "allowlist_bypass",
            Self::SandwichRevealMismatch => "sandwich_reveal_mismatch",
            Self::FeeOvercharge => "fee_overcharge",
            Self::InvalidLpEnvelope => "invalid_lp_envelope",
            Self::SettlementMismatch => "settlement_mismatch",
            Self::LateSettlement => "late_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookChallengeStatus {
    Open,
    EvidencePosted,
    Upheld,
    Rejected,
    Expired,
}

impl HookChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidencePosted => "evidence_posted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Pending,
    Applied,
    Reversed,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenConfidentialAmmHooksConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub epoch_blocks: u64,
    pub hook_ttl_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub settlement_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_sponsor_bond_units: u128,
    pub max_pool_fee_bps: u64,
    pub low_fee_bps: u64,
    pub protocol_fee_share_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub slash_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub max_hooks_per_pool: usize,
    pub max_pending_swaps: usize,
    pub hash_suite: String,
    pub swap_proof_system: String,
    pub lp_proof_system: String,
    pub pq_attestation_scheme: String,
    pub commitment_scheme: String,
    pub receipt_scheme: String,
    pub sponsor_scheme: String,
}

impl PrivateTokenConfidentialAmmHooksConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_SCHEMA_VERSION,
            epoch_blocks: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_EPOCH_BLOCKS,
            hook_ttl_blocks: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_HOOK_TTL_BLOCKS,
            reveal_delay_blocks: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_REVEAL_DELAY_BLOCKS,
            settlement_window_blocks:
                PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            challenge_window_blocks:
                PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_sponsor_bond_units:
                PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_SPONSOR_BOND_UNITS,
            max_pool_fee_bps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_POOL_FEE_BPS,
            low_fee_bps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_LOW_FEE_BPS,
            protocol_fee_share_bps:
                PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_PROTOCOL_FEE_SHARE_BPS,
            sponsor_rebate_bps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_SPONSOR_REBATE_BPS,
            slash_bps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_SLASH_BPS,
            max_price_impact_bps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_oracle_deviation_bps:
                PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            max_hooks_per_pool: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_HOOKS_PER_POOL,
            max_pending_swaps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_PENDING_SWAPS,
            hash_suite: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_HASH_SUITE.to_string(),
            swap_proof_system: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_SWAP_PROOF_SYSTEM.to_string(),
            lp_proof_system: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_LP_PROOF_SYSTEM.to_string(),
            pq_attestation_scheme: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_PQ_ATTESTATION_SCHEME
                .to_string(),
            commitment_scheme: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_COMMITMENT_SCHEME.to_string(),
            receipt_scheme: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_RECEIPT_SCHEME.to_string(),
            sponsor_scheme: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_SPONSOR_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("config.protocol_version", &self.protocol_version)?;
        ensure_positive("config.schema_version", self.schema_version)?;
        ensure_positive("config.epoch_blocks", self.epoch_blocks)?;
        ensure_positive("config.hook_ttl_blocks", self.hook_ttl_blocks)?;
        ensure_positive(
            "config.settlement_window_blocks",
            self.settlement_window_blocks,
        )?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("config.min_sponsor_bond_units", self.min_sponsor_bond_units)?;
        ensure_bps("config.max_pool_fee_bps", self.max_pool_fee_bps)?;
        ensure_bps("config.low_fee_bps", self.low_fee_bps)?;
        ensure_bps("config.protocol_fee_share_bps", self.protocol_fee_share_bps)?;
        ensure_bps("config.sponsor_rebate_bps", self.sponsor_rebate_bps)?;
        ensure_bps("config.slash_bps", self.slash_bps)?;
        ensure_bps("config.max_price_impact_bps", self.max_price_impact_bps)?;
        ensure_bps(
            "config.max_oracle_deviation_bps",
            self.max_oracle_deviation_bps,
        )?;
        ensure_nonzero_usize("config.max_hooks_per_pool", self.max_hooks_per_pool)?;
        ensure_nonzero_usize("config.max_pending_swaps", self.max_pending_swaps)?;
        ensure_nonempty("config.hash_suite", &self.hash_suite)?;
        ensure_nonempty("config.swap_proof_system", &self.swap_proof_system)?;
        ensure_nonempty("config.lp_proof_system", &self.lp_proof_system)?;
        ensure_nonempty("config.pq_attestation_scheme", &self.pq_attestation_scheme)?;
        ensure_nonempty("config.commitment_scheme", &self.commitment_scheme)?;
        ensure_nonempty("config.receipt_scheme", &self.receipt_scheme)?;
        ensure_nonempty("config.sponsor_scheme", &self.sponsor_scheme)?;
        if self.min_pq_security_bits
            < PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("config.min_pq_security_bits below devnet floor".to_string());
        }
        if self.low_fee_bps > self.max_pool_fee_bps {
            return Err("config.low_fee_bps cannot exceed config.max_pool_fee_bps".to_string());
        }
        Ok(())
    }
}

impl Default for PrivateTokenConfidentialAmmHooksConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenAllowlistEntry {
    pub token_id: String,
    pub token_class: ConfidentialTokenClass,
    pub issuer_commitment: String,
    pub policy_root: String,
    pub view_tag_root: String,
    pub bridge_origin_root: String,
    pub min_privacy_set_size: u64,
    pub risk_weight_bps: u64,
    pub pq_security_bits: u16,
    pub active: bool,
    pub listed_at_height: u64,
}

impl ConfidentialTokenAllowlistEntry {
    pub fn devnet(
        token_id: &str,
        token_class: ConfidentialTokenClass,
        listed_at_height: u64,
    ) -> Self {
        let policy_root = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ALLOWLIST-POLICY",
            &json!({
                "token_id": token_id,
                "token_class": token_class.as_str(),
                "devnet": true,
            }),
        );
        Self {
            token_id: token_id.to_string(),
            token_class,
            issuer_commitment: private_token_confidential_amm_hooks_string_root(
                "allowlist-issuer",
                token_id,
            ),
            policy_root,
            view_tag_root: private_token_confidential_amm_hooks_string_root(
                "allowlist-view-tag",
                token_id,
            ),
            bridge_origin_root: private_token_confidential_amm_hooks_string_root(
                "allowlist-bridge-origin",
                token_id,
            ),
            min_privacy_set_size: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_PRIVACY_SET_SIZE,
            risk_weight_bps: token_class.default_risk_weight_bps(),
            pq_security_bits: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MIN_PQ_SECURITY_BITS,
            active: true,
            listed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active": self.active,
            "bridge_origin_root": self.bridge_origin_root,
            "chain_id": CHAIN_ID,
            "issuer_commitment": self.issuer_commitment,
            "listed_at_height": self.listed_at_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "policy_root": self.policy_root,
            "pq_security_bits": self.pq_security_bits,
            "risk_weight_bps": self.risk_weight_bps,
            "token_class": self.token_class.as_str(),
            "token_id": self.token_id,
            "view_tag_root": self.view_tag_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ALLOWLIST-ENTRY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("allowlist.token_id", &self.token_id)?;
        ensure_nonempty("allowlist.issuer_commitment", &self.issuer_commitment)?;
        ensure_nonempty("allowlist.policy_root", &self.policy_root)?;
        ensure_nonempty("allowlist.view_tag_root", &self.view_tag_root)?;
        ensure_nonempty("allowlist.bridge_origin_root", &self.bridge_origin_root)?;
        ensure_positive("allowlist.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_bps("allowlist.risk_weight_bps", self.risk_weight_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "allowlist {} privacy set below config floor",
                self.token_id
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "allowlist {} pq security below config floor",
                self.token_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAmmPool {
    pub pool_id: String,
    pub pool_kind: ConfidentialAmmPoolKind,
    pub token_a: String,
    pub token_b: String,
    pub lp_token_id: String,
    pub pool_commitment: String,
    pub invariant_commitment: String,
    pub fee_bps: u64,
    pub protocol_fee_share_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub hook_set_root: String,
    pub oracle_commitment_root: String,
    pub active: bool,
    pub created_at_height: u64,
    pub last_updated_height: u64,
}

impl ConfidentialAmmPool {
    pub fn devnet(
        pool_id: &str,
        pool_kind: ConfidentialAmmPoolKind,
        token_a: &str,
        token_b: &str,
        height: u64,
    ) -> Self {
        let lp_token_id = format!("{pool_id}-lp");
        Self {
            pool_id: pool_id.to_string(),
            pool_kind,
            token_a: token_a.to_string(),
            token_b: token_b.to_string(),
            lp_token_id,
            pool_commitment: private_token_confidential_amm_hooks_pool_id(
                pool_kind, token_a, token_b, height,
            ),
            invariant_commitment: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-INVARIANT",
                &json!({
                    "pool_id": pool_id,
                    "pool_kind": pool_kind.as_str(),
                    "token_a": token_a,
                    "token_b": token_b,
                }),
            ),
            fee_bps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_LOW_FEE_BPS,
            protocol_fee_share_bps:
                PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_PROTOCOL_FEE_SHARE_BPS,
            max_price_impact_bps: PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_oracle_deviation_bps:
                PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            hook_set_root: private_token_confidential_amm_hooks_string_set_root(
                "pool-hook-set",
                &[pool_id],
            ),
            oracle_commitment_root: private_token_confidential_amm_hooks_string_root(
                "pool-oracle",
                pool_id,
            ),
            active: true,
            created_at_height: height,
            last_updated_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active": self.active,
            "chain_id": CHAIN_ID,
            "created_at_height": self.created_at_height,
            "fee_bps": self.fee_bps,
            "hook_set_root": self.hook_set_root,
            "invariant_commitment": self.invariant_commitment,
            "last_updated_height": self.last_updated_height,
            "lp_token_id": self.lp_token_id,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "oracle_commitment_root": self.oracle_commitment_root,
            "pool_commitment": self.pool_commitment,
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "protocol_fee_share_bps": self.protocol_fee_share_bps,
            "token_a": self.token_a,
            "token_b": self.token_b,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-POOL",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn contains_token(&self, token_id: &str) -> bool {
        self.token_a == token_id || self.token_b == token_id
    }

    pub fn validate(
        &self,
        config: &PrivateTokenConfidentialAmmHooksConfig,
        allowlist: &BTreeMap<String, ConfidentialTokenAllowlistEntry>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("pool.pool_id", &self.pool_id)?;
        ensure_nonempty("pool.token_a", &self.token_a)?;
        ensure_nonempty("pool.token_b", &self.token_b)?;
        ensure_nonempty("pool.lp_token_id", &self.lp_token_id)?;
        ensure_nonempty("pool.pool_commitment", &self.pool_commitment)?;
        ensure_nonempty("pool.invariant_commitment", &self.invariant_commitment)?;
        ensure_nonempty("pool.hook_set_root", &self.hook_set_root)?;
        ensure_nonempty("pool.oracle_commitment_root", &self.oracle_commitment_root)?;
        ensure_bps("pool.fee_bps", self.fee_bps)?;
        ensure_bps("pool.protocol_fee_share_bps", self.protocol_fee_share_bps)?;
        ensure_bps("pool.max_price_impact_bps", self.max_price_impact_bps)?;
        ensure_bps(
            "pool.max_oracle_deviation_bps",
            self.max_oracle_deviation_bps,
        )?;
        if self.token_a == self.token_b {
            return Err(format!("pool {} uses identical tokens", self.pool_id));
        }
        if self.fee_bps > config.max_pool_fee_bps {
            return Err(format!("pool {} fee exceeds config max", self.pool_id));
        }
        ensure_allowlisted(&self.token_a, allowlist)?;
        ensure_allowlisted(&self.token_b, allowlist)?;
        if self.last_updated_height < self.created_at_height {
            return Err(format!("pool {} height moved backwards", self.pool_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAmmHook {
    pub hook_id: String,
    pub pool_id: String,
    pub hook_kind: ConfidentialAmmHookKind,
    pub status: ConfidentialAmmHookStatus,
    pub operator_commitment: String,
    pub circuit_root: String,
    pub policy_root: String,
    pub pq_verifier_root: String,
    pub supported_token_root: String,
    pub max_fee_bps: u64,
    pub sponsor_bond_units: u128,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub last_attested_height: u64,
}

impl ConfidentialAmmHook {
    pub fn devnet(
        pool_id: &str,
        hook_kind: ConfidentialAmmHookKind,
        operator_commitment: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let hook_id = private_token_confidential_amm_hooks_hook_id(
            pool_id,
            hook_kind,
            operator_commitment,
            height,
        );
        Self {
            hook_id,
            pool_id: pool_id.to_string(),
            hook_kind,
            status: ConfidentialAmmHookStatus::Active,
            operator_commitment: operator_commitment.to_string(),
            circuit_root: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-CIRCUIT",
                &json!({
                    "pool_id": pool_id,
                    "hook_kind": hook_kind.as_str(),
                    "proof_system": config.swap_proof_system,
                }),
            ),
            policy_root: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-POLICY",
                &json!({
                    "pool_id": pool_id,
                    "hook_kind": hook_kind.as_str(),
                    "low_fee_bps": config.low_fee_bps,
                }),
            ),
            pq_verifier_root: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-PQ-VERIFIER",
                &json!({
                    "scheme": config.pq_attestation_scheme,
                    "security_bits": config.min_pq_security_bits,
                }),
            ),
            supported_token_root: private_token_confidential_amm_hooks_string_set_root(
                "hook-supported-token",
                &[pool_id],
            ),
            max_fee_bps: config.max_pool_fee_bps,
            sponsor_bond_units: config.min_sponsor_bond_units,
            activated_at_height: height,
            expires_at_height: height.saturating_add(config.hook_ttl_blocks),
            last_attested_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "activated_at_height": self.activated_at_height,
            "chain_id": CHAIN_ID,
            "circuit_root": self.circuit_root,
            "expires_at_height": self.expires_at_height,
            "hook_id": self.hook_id,
            "hook_kind": self.hook_kind.as_str(),
            "last_attested_height": self.last_attested_height,
            "max_fee_bps": self.max_fee_bps,
            "operator_commitment": self.operator_commitment,
            "policy_root": self.policy_root,
            "pool_id": self.pool_id,
            "pq_verifier_root": self.pq_verifier_root,
            "sponsor_bond_units": self.sponsor_bond_units,
            "status": self.status.as_str(),
            "supported_token_root": self.supported_token_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-HOOK",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        config: &PrivateTokenConfidentialAmmHooksConfig,
        pools: &BTreeMap<String, ConfidentialAmmPool>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("hook.hook_id", &self.hook_id)?;
        ensure_nonempty("hook.pool_id", &self.pool_id)?;
        ensure_nonempty("hook.operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("hook.circuit_root", &self.circuit_root)?;
        ensure_nonempty("hook.policy_root", &self.policy_root)?;
        ensure_nonempty("hook.pq_verifier_root", &self.pq_verifier_root)?;
        ensure_nonempty("hook.supported_token_root", &self.supported_token_root)?;
        ensure_bps("hook.max_fee_bps", self.max_fee_bps)?;
        ensure_positive("hook.sponsor_bond_units", self.sponsor_bond_units)?;
        if !pools.contains_key(&self.pool_id) {
            return Err(format!("hook {} references unknown pool", self.hook_id));
        }
        if self.max_fee_bps > config.max_pool_fee_bps {
            return Err(format!("hook {} max fee exceeds config", self.hook_id));
        }
        if self.sponsor_bond_units < config.min_sponsor_bond_units {
            return Err(format!("hook {} sponsor bond below config", self.hook_id));
        }
        if self.expires_at_height <= self.activated_at_height {
            return Err(format!(
                "hook {} expiry is not after activation",
                self.hook_id
            ));
        }
        if self.last_attested_height < self.activated_at_height {
            return Err(format!(
                "hook {} attestation height before activation",
                self.hook_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiSandwichCommitment {
    pub commitment_id: String,
    pub pool_id: String,
    pub route_commitment: String,
    pub sealed_order_root: String,
    pub batch_entropy_root: String,
    pub pre_state_root: String,
    pub max_price_impact_bps: u64,
    pub reveal_after_height: u64,
    pub expires_at_height: u64,
}

impl AntiSandwichCommitment {
    pub fn new(
        pool_id: &str,
        route_commitment: &str,
        sealed_order_root: &str,
        pre_state_root: &str,
        max_price_impact_bps: u64,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let batch_entropy_root = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-BATCH-ENTROPY",
            &json!({
                "height": height,
                "pool_id": pool_id,
                "route_commitment": route_commitment,
                "sealed_order_root": sealed_order_root,
            }),
        );
        let commitment_id = private_token_confidential_amm_hooks_commitment_id(
            pool_id,
            route_commitment,
            sealed_order_root,
            height,
        );
        Self {
            commitment_id,
            pool_id: pool_id.to_string(),
            route_commitment: route_commitment.to_string(),
            sealed_order_root: sealed_order_root.to_string(),
            batch_entropy_root,
            pre_state_root: pre_state_root.to_string(),
            max_price_impact_bps,
            reveal_after_height: height.saturating_add(config.reveal_delay_blocks),
            expires_at_height: height.saturating_add(config.hook_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_entropy_root": self.batch_entropy_root,
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "expires_at_height": self.expires_at_height,
            "max_price_impact_bps": self.max_price_impact_bps,
            "pool_id": self.pool_id,
            "pre_state_root": self.pre_state_root,
            "reveal_after_height": self.reveal_after_height,
            "route_commitment": self.route_commitment,
            "sealed_order_root": self.sealed_order_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ANTI-SANDWICH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        config: &PrivateTokenConfidentialAmmHooksConfig,
        pools: &BTreeMap<String, ConfidentialAmmPool>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("anti_sandwich.commitment_id", &self.commitment_id)?;
        ensure_nonempty("anti_sandwich.pool_id", &self.pool_id)?;
        ensure_nonempty("anti_sandwich.route_commitment", &self.route_commitment)?;
        ensure_nonempty("anti_sandwich.sealed_order_root", &self.sealed_order_root)?;
        ensure_nonempty("anti_sandwich.batch_entropy_root", &self.batch_entropy_root)?;
        ensure_nonempty("anti_sandwich.pre_state_root", &self.pre_state_root)?;
        ensure_bps(
            "anti_sandwich.max_price_impact_bps",
            self.max_price_impact_bps,
        )?;
        if !pools.contains_key(&self.pool_id) {
            return Err(format!(
                "anti-sandwich commitment {} references unknown pool",
                self.commitment_id
            ));
        }
        if self.max_price_impact_bps > config.max_price_impact_bps {
            return Err(format!(
                "anti-sandwich commitment {} exceeds price impact limit",
                self.commitment_id
            ));
        }
        if self.expires_at_height <= self.reveal_after_height {
            return Err(format!(
                "anti-sandwich commitment {} expires before reveal",
                self.commitment_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialSwapHookIntent {
    pub swap_id: String,
    pub pool_id: String,
    pub hook_id: String,
    pub swap_side: ConfidentialSwapSide,
    pub trader_commitment: String,
    pub input_token: String,
    pub output_token: String,
    pub amount_commitment: String,
    pub min_output_commitment: String,
    pub route_commitment: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub anti_sandwich_commitment_id: String,
    pub max_fee_bps: u64,
    pub status: ConfidentialSwapStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl ConfidentialSwapHookIntent {
    pub fn new(
        pool_id: &str,
        hook_id: &str,
        swap_side: ConfidentialSwapSide,
        trader_commitment: &str,
        input_token: &str,
        output_token: &str,
        amount_commitment: &str,
        min_output_commitment: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let route_commitment = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ROUTE",
            &json!({
                "pool_id": pool_id,
                "hook_id": hook_id,
                "swap_side": swap_side.as_str(),
                "input_token": input_token,
                "output_token": output_token,
                "amount_commitment": amount_commitment,
                "min_output_commitment": min_output_commitment,
            }),
        );
        let sealed_order_root = private_token_confidential_amm_hooks_string_root(
            "swap-sealed-order",
            &route_commitment,
        );
        let pre_state_root =
            private_token_confidential_amm_hooks_string_root("swap-pre-state", pool_id);
        let anti_sandwich = AntiSandwichCommitment::new(
            pool_id,
            &route_commitment,
            &sealed_order_root,
            &pre_state_root,
            config.max_price_impact_bps,
            height,
            config,
        );
        let swap_id = private_token_confidential_amm_hooks_swap_id(
            pool_id,
            hook_id,
            trader_commitment,
            &route_commitment,
            height,
        );
        Self {
            swap_id,
            pool_id: pool_id.to_string(),
            hook_id: hook_id.to_string(),
            swap_side,
            trader_commitment: trader_commitment.to_string(),
            input_token: input_token.to_string(),
            output_token: output_token.to_string(),
            amount_commitment: amount_commitment.to_string(),
            min_output_commitment: min_output_commitment.to_string(),
            route_commitment,
            nullifier_root: private_token_confidential_amm_hooks_string_root(
                "swap-nullifier",
                trader_commitment,
            ),
            witness_root: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SWAP-WITNESS",
                &json!({
                    "pool_id": pool_id,
                    "hook_id": hook_id,
                    "trader_commitment": trader_commitment,
                    "height": height,
                }),
            ),
            anti_sandwich_commitment_id: anti_sandwich.commitment_id,
            max_fee_bps: config.max_pool_fee_bps,
            status: ConfidentialSwapStatus::Committed,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(config.hook_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "amount_commitment": self.amount_commitment,
            "anti_sandwich_commitment_id": self.anti_sandwich_commitment_id,
            "chain_id": CHAIN_ID,
            "expires_at_height": self.expires_at_height,
            "hook_id": self.hook_id,
            "input_token": self.input_token,
            "max_fee_bps": self.max_fee_bps,
            "min_output_commitment": self.min_output_commitment,
            "nullifier_root": self.nullifier_root,
            "output_token": self.output_token,
            "pool_id": self.pool_id,
            "route_commitment": self.route_commitment,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "swap_id": self.swap_id,
            "swap_side": self.swap_side.as_str(),
            "trader_commitment": self.trader_commitment,
            "witness_root": self.witness_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SWAP",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        config: &PrivateTokenConfidentialAmmHooksConfig,
        pools: &BTreeMap<String, ConfidentialAmmPool>,
        hooks: &BTreeMap<String, ConfidentialAmmHook>,
        allowlist: &BTreeMap<String, ConfidentialTokenAllowlistEntry>,
        commitments: &BTreeMap<String, AntiSandwichCommitment>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("swap.swap_id", &self.swap_id)?;
        ensure_nonempty("swap.pool_id", &self.pool_id)?;
        ensure_nonempty("swap.hook_id", &self.hook_id)?;
        ensure_nonempty("swap.trader_commitment", &self.trader_commitment)?;
        ensure_nonempty("swap.input_token", &self.input_token)?;
        ensure_nonempty("swap.output_token", &self.output_token)?;
        ensure_nonempty("swap.amount_commitment", &self.amount_commitment)?;
        ensure_nonempty("swap.min_output_commitment", &self.min_output_commitment)?;
        ensure_nonempty("swap.route_commitment", &self.route_commitment)?;
        ensure_nonempty("swap.nullifier_root", &self.nullifier_root)?;
        ensure_nonempty("swap.witness_root", &self.witness_root)?;
        ensure_nonempty(
            "swap.anti_sandwich_commitment_id",
            &self.anti_sandwich_commitment_id,
        )?;
        ensure_bps("swap.max_fee_bps", self.max_fee_bps)?;
        let pool = pools
            .get(&self.pool_id)
            .ok_or_else(|| format!("swap {} references unknown pool", self.swap_id))?;
        let hook = hooks
            .get(&self.hook_id)
            .ok_or_else(|| format!("swap {} references unknown hook", self.swap_id))?;
        if hook.pool_id != self.pool_id {
            return Err(format!("swap {} hook/pool mismatch", self.swap_id));
        }
        if !hook.status.accepts_private_flow() {
            return Err(format!("swap {} hook does not accept flow", self.swap_id));
        }
        if !pool.contains_token(&self.input_token) || !pool.contains_token(&self.output_token) {
            return Err(format!("swap {} token not in pool", self.swap_id));
        }
        if self.input_token == self.output_token {
            return Err(format!(
                "swap {} input and output tokens match",
                self.swap_id
            ));
        }
        ensure_allowlisted(&self.input_token, allowlist)?;
        ensure_allowlisted(&self.output_token, allowlist)?;
        if !commitments.contains_key(&self.anti_sandwich_commitment_id) {
            return Err(format!(
                "swap {} missing anti-sandwich commitment",
                self.swap_id
            ));
        }
        if self.max_fee_bps > config.max_pool_fee_bps {
            return Err(format!("swap {} fee exceeds config", self.swap_id));
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err(format!("swap {} expiry before submission", self.swap_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LpPrivacyEnvelope {
    pub envelope_id: String,
    pub pool_id: String,
    pub hook_id: String,
    pub owner_commitment: String,
    pub envelope_kind: LpEnvelopeKind,
    pub status: LpEnvelopeStatus,
    pub liquidity_commitment: String,
    pub range_commitment: String,
    pub fee_claim_commitment: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl LpPrivacyEnvelope {
    pub fn new(
        pool_id: &str,
        hook_id: &str,
        owner_commitment: &str,
        envelope_kind: LpEnvelopeKind,
        liquidity_commitment: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let envelope_id = private_token_confidential_amm_hooks_lp_envelope_id(
            pool_id,
            hook_id,
            owner_commitment,
            envelope_kind,
            height,
        );
        Self {
            envelope_id,
            pool_id: pool_id.to_string(),
            hook_id: hook_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            envelope_kind,
            status: LpEnvelopeStatus::Sealed,
            liquidity_commitment: liquidity_commitment.to_string(),
            range_commitment: private_token_confidential_amm_hooks_string_root(
                "lp-range",
                owner_commitment,
            ),
            fee_claim_commitment: private_token_confidential_amm_hooks_string_root(
                "lp-fee-claim",
                owner_commitment,
            ),
            nullifier_root: private_token_confidential_amm_hooks_string_root(
                "lp-nullifier",
                owner_commitment,
            ),
            witness_root: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-LP-WITNESS",
                &json!({
                    "pool_id": pool_id,
                    "hook_id": hook_id,
                    "owner_commitment": owner_commitment,
                    "envelope_kind": envelope_kind.as_str(),
                    "height": height,
                }),
            ),
            proof_root: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-LP-PROOF",
                &json!({
                    "proof_system": config.lp_proof_system,
                    "liquidity_commitment": liquidity_commitment,
                }),
            ),
            submitted_at_height: height,
            expires_at_height: height.saturating_add(config.hook_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "envelope_id": self.envelope_id,
            "envelope_kind": self.envelope_kind.as_str(),
            "expires_at_height": self.expires_at_height,
            "fee_claim_commitment": self.fee_claim_commitment,
            "hook_id": self.hook_id,
            "liquidity_commitment": self.liquidity_commitment,
            "nullifier_root": self.nullifier_root,
            "owner_commitment": self.owner_commitment,
            "pool_id": self.pool_id,
            "proof_root": self.proof_root,
            "range_commitment": self.range_commitment,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "witness_root": self.witness_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-LP-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        pools: &BTreeMap<String, ConfidentialAmmPool>,
        hooks: &BTreeMap<String, ConfidentialAmmHook>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("lp.envelope_id", &self.envelope_id)?;
        ensure_nonempty("lp.pool_id", &self.pool_id)?;
        ensure_nonempty("lp.hook_id", &self.hook_id)?;
        ensure_nonempty("lp.owner_commitment", &self.owner_commitment)?;
        ensure_nonempty("lp.liquidity_commitment", &self.liquidity_commitment)?;
        ensure_nonempty("lp.range_commitment", &self.range_commitment)?;
        ensure_nonempty("lp.fee_claim_commitment", &self.fee_claim_commitment)?;
        ensure_nonempty("lp.nullifier_root", &self.nullifier_root)?;
        ensure_nonempty("lp.witness_root", &self.witness_root)?;
        ensure_nonempty("lp.proof_root", &self.proof_root)?;
        if !pools.contains_key(&self.pool_id) {
            return Err(format!(
                "lp envelope {} references unknown pool",
                self.envelope_id
            ));
        }
        let hook = hooks
            .get(&self.hook_id)
            .ok_or_else(|| format!("lp envelope {} references unknown hook", self.envelope_id))?;
        if hook.pool_id != self.pool_id {
            return Err(format!(
                "lp envelope {} hook/pool mismatch",
                self.envelope_id
            ));
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err(format!(
                "lp envelope {} expiry before submission",
                self.envelope_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqHookAttestation {
    pub attestation_id: String,
    pub hook_id: String,
    pub subject_root: String,
    pub attester_commitment: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub status: HookAttestationStatus,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqHookAttestation {
    pub fn new(
        hook_id: &str,
        subject_root: &str,
        attester_commitment: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let transcript_root = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-PQ-TRANSCRIPT",
            &json!({
                "hook_id": hook_id,
                "subject_root": subject_root,
                "attester_commitment": attester_commitment,
                "scheme": config.pq_attestation_scheme,
            }),
        );
        let signature_root = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-PQ-SIGNATURE",
            &json!({
                "transcript_root": transcript_root,
                "attester_commitment": attester_commitment,
            }),
        );
        let attestation_id = private_token_confidential_amm_hooks_attestation_id(
            hook_id,
            subject_root,
            attester_commitment,
            height,
        );
        Self {
            attestation_id,
            hook_id: hook_id.to_string(),
            subject_root: subject_root.to_string(),
            attester_commitment: attester_commitment.to_string(),
            signature_root,
            transcript_root,
            status: HookAttestationStatus::Valid,
            pq_security_bits: config.min_pq_security_bits,
            attested_at_height: height,
            expires_at_height: height.saturating_add(config.hook_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attested_at_height": self.attested_at_height,
            "attester_commitment": self.attester_commitment,
            "chain_id": CHAIN_ID,
            "expires_at_height": self.expires_at_height,
            "hook_id": self.hook_id,
            "pq_security_bits": self.pq_security_bits,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "subject_root": self.subject_root,
            "transcript_root": self.transcript_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-PQ-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        config: &PrivateTokenConfidentialAmmHooksConfig,
        hooks: &BTreeMap<String, ConfidentialAmmHook>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("attestation.attestation_id", &self.attestation_id)?;
        ensure_nonempty("attestation.hook_id", &self.hook_id)?;
        ensure_nonempty("attestation.subject_root", &self.subject_root)?;
        ensure_nonempty("attestation.attester_commitment", &self.attester_commitment)?;
        ensure_nonempty("attestation.signature_root", &self.signature_root)?;
        ensure_nonempty("attestation.transcript_root", &self.transcript_root)?;
        if !hooks.contains_key(&self.hook_id) {
            return Err(format!(
                "attestation {} references unknown hook",
                self.attestation_id
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below pq security floor",
                self.attestation_id
            ));
        }
        if self.expires_at_height <= self.attested_at_height {
            return Err(format!(
                "attestation {} expiry before attestation",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeHookSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub hook_id: String,
    pub swap_id: String,
    pub fee_token: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub sponsor_bond_units: u128,
    pub status: SponsorshipStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeHookSponsorship {
    pub fn new(
        sponsor_commitment: &str,
        hook_id: &str,
        swap_id: &str,
        fee_token: &str,
        fee_commitment: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let sponsorship_id = private_token_confidential_amm_hooks_sponsorship_id(
            sponsor_commitment,
            hook_id,
            swap_id,
            height,
        );
        Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            hook_id: hook_id.to_string(),
            swap_id: swap_id.to_string(),
            fee_token: fee_token.to_string(),
            fee_commitment: fee_commitment.to_string(),
            rebate_commitment: private_token_confidential_amm_hooks_payload_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SPONSOR-REBATE",
                &json!({
                    "sponsor_commitment": sponsor_commitment,
                    "hook_id": hook_id,
                    "swap_id": swap_id,
                    "rebate_bps": config.sponsor_rebate_bps,
                }),
            ),
            sponsor_bond_units: config.min_sponsor_bond_units,
            status: SponsorshipStatus::Reserved,
            reserved_at_height: height,
            expires_at_height: height.saturating_add(config.hook_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "expires_at_height": self.expires_at_height,
            "fee_commitment": self.fee_commitment,
            "fee_token": self.fee_token,
            "hook_id": self.hook_id,
            "rebate_commitment": self.rebate_commitment,
            "reserved_at_height": self.reserved_at_height,
            "sponsor_bond_units": self.sponsor_bond_units,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsorship_id": self.sponsorship_id,
            "status": self.status.as_str(),
            "swap_id": self.swap_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SPONSORSHIP",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        config: &PrivateTokenConfidentialAmmHooksConfig,
        swaps: &BTreeMap<String, ConfidentialSwapHookIntent>,
        hooks: &BTreeMap<String, ConfidentialAmmHook>,
        allowlist: &BTreeMap<String, ConfidentialTokenAllowlistEntry>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("sponsorship.sponsorship_id", &self.sponsorship_id)?;
        ensure_nonempty("sponsorship.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_nonempty("sponsorship.hook_id", &self.hook_id)?;
        ensure_nonempty("sponsorship.swap_id", &self.swap_id)?;
        ensure_nonempty("sponsorship.fee_token", &self.fee_token)?;
        ensure_nonempty("sponsorship.fee_commitment", &self.fee_commitment)?;
        ensure_nonempty("sponsorship.rebate_commitment", &self.rebate_commitment)?;
        ensure_positive("sponsorship.sponsor_bond_units", self.sponsor_bond_units)?;
        ensure_allowlisted(&self.fee_token, allowlist)?;
        if !swaps.contains_key(&self.swap_id) {
            return Err(format!(
                "sponsorship {} references unknown swap",
                self.sponsorship_id
            ));
        }
        if !hooks.contains_key(&self.hook_id) {
            return Err(format!(
                "sponsorship {} references unknown hook",
                self.sponsorship_id
            ));
        }
        if self.sponsor_bond_units < config.min_sponsor_bond_units {
            return Err(format!(
                "sponsorship {} bond below config",
                self.sponsorship_id
            ));
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err(format!(
                "sponsorship {} expiry before reservation",
                self.sponsorship_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub pool_id: String,
    pub hook_id: String,
    pub swap_id: String,
    pub attestation_id: String,
    pub sponsorship_id: Option<String>,
    pub post_state_root: String,
    pub output_commitment: String,
    pub fee_commitment: String,
    pub protocol_fee_commitment: String,
    pub receipt_root: String,
    pub status: SettlementReceiptStatus,
    pub settled_at_height: u64,
    pub challenge_deadline_height: u64,
}

impl SettlementReceipt {
    pub fn new(
        swap: &ConfidentialSwapHookIntent,
        attestation_id: &str,
        sponsorship_id: Option<String>,
        output_commitment: &str,
        fee_commitment: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let protocol_fee_commitment = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-PROTOCOL-FEE",
            &json!({
                "swap_id": swap.swap_id,
                "fee_commitment": fee_commitment,
                "protocol_fee_share_bps": config.protocol_fee_share_bps,
            }),
        );
        let post_state_root = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-POST-STATE",
            &json!({
                "pool_id": swap.pool_id,
                "swap_id": swap.swap_id,
                "output_commitment": output_commitment,
                "height": height,
            }),
        );
        let receipt_id = private_token_confidential_amm_hooks_receipt_id(
            &swap.swap_id,
            attestation_id,
            &post_state_root,
            height,
        );
        let receipt_root = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-RECEIPT",
            &json!({
                "receipt_id": receipt_id,
                "swap_id": swap.swap_id,
                "attestation_id": attestation_id,
                "post_state_root": post_state_root,
            }),
        );
        Self {
            receipt_id,
            pool_id: swap.pool_id.clone(),
            hook_id: swap.hook_id.clone(),
            swap_id: swap.swap_id.clone(),
            attestation_id: attestation_id.to_string(),
            sponsorship_id,
            post_state_root,
            output_commitment: output_commitment.to_string(),
            fee_commitment: fee_commitment.to_string(),
            protocol_fee_commitment,
            receipt_root,
            status: SettlementReceiptStatus::Proposed,
            settled_at_height: height,
            challenge_deadline_height: height.saturating_add(config.challenge_window_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "chain_id": CHAIN_ID,
            "challenge_deadline_height": self.challenge_deadline_height,
            "fee_commitment": self.fee_commitment,
            "hook_id": self.hook_id,
            "output_commitment": self.output_commitment,
            "pool_id": self.pool_id,
            "post_state_root": self.post_state_root,
            "protocol_fee_commitment": self.protocol_fee_commitment,
            "receipt_id": self.receipt_id,
            "receipt_root": self.receipt_root,
            "settled_at_height": self.settled_at_height,
            "sponsorship_id": self.sponsorship_id,
            "status": self.status.as_str(),
            "swap_id": self.swap_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        swaps: &BTreeMap<String, ConfidentialSwapHookIntent>,
        attestations: &BTreeMap<String, PqHookAttestation>,
        sponsorships: &BTreeMap<String, LowFeeHookSponsorship>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("receipt.receipt_id", &self.receipt_id)?;
        ensure_nonempty("receipt.pool_id", &self.pool_id)?;
        ensure_nonempty("receipt.hook_id", &self.hook_id)?;
        ensure_nonempty("receipt.swap_id", &self.swap_id)?;
        ensure_nonempty("receipt.attestation_id", &self.attestation_id)?;
        ensure_nonempty("receipt.post_state_root", &self.post_state_root)?;
        ensure_nonempty("receipt.output_commitment", &self.output_commitment)?;
        ensure_nonempty("receipt.fee_commitment", &self.fee_commitment)?;
        ensure_nonempty(
            "receipt.protocol_fee_commitment",
            &self.protocol_fee_commitment,
        )?;
        ensure_nonempty("receipt.receipt_root", &self.receipt_root)?;
        let swap = swaps
            .get(&self.swap_id)
            .ok_or_else(|| format!("receipt {} references unknown swap", self.receipt_id))?;
        if swap.pool_id != self.pool_id || swap.hook_id != self.hook_id {
            return Err(format!("receipt {} swap linkage mismatch", self.receipt_id));
        }
        if !attestations.contains_key(&self.attestation_id) {
            return Err(format!(
                "receipt {} references unknown attestation",
                self.receipt_id
            ));
        }
        if let Some(sponsorship_id) = &self.sponsorship_id {
            if !sponsorships.contains_key(sponsorship_id) {
                return Err(format!(
                    "receipt {} references unknown sponsorship",
                    self.receipt_id
                ));
            }
        }
        if self.challenge_deadline_height <= self.settled_at_height {
            return Err(format!(
                "receipt {} invalid challenge deadline",
                self.receipt_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookChallenge {
    pub challenge_id: String,
    pub kind: HookChallengeKind,
    pub status: HookChallengeStatus,
    pub claimant_commitment: String,
    pub hook_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl HookChallenge {
    pub fn new(
        kind: HookChallengeKind,
        claimant_commitment: &str,
        hook_id: &str,
        subject_id: &str,
        expected_root: &str,
        observed_root: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let evidence_root = private_token_confidential_amm_hooks_payload_root(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-CHALLENGE-EVIDENCE",
            &json!({
                "kind": kind.as_str(),
                "claimant_commitment": claimant_commitment,
                "hook_id": hook_id,
                "subject_id": subject_id,
                "expected_root": expected_root,
                "observed_root": observed_root,
            }),
        );
        let challenge_id = private_token_confidential_amm_hooks_challenge_id(
            kind,
            claimant_commitment,
            hook_id,
            subject_id,
            height,
        );
        Self {
            challenge_id,
            kind,
            status: HookChallengeStatus::Open,
            claimant_commitment: claimant_commitment.to_string(),
            hook_id: hook_id.to_string(),
            subject_id: subject_id.to_string(),
            evidence_root,
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            opened_at_height: height,
            expires_at_height: height.saturating_add(config.challenge_window_blocks),
            resolved_at_height: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "claimant_commitment": self.claimant_commitment,
            "evidence_root": self.evidence_root,
            "expected_root": self.expected_root,
            "expires_at_height": self.expires_at_height,
            "hook_id": self.hook_id,
            "kind": self.kind.as_str(),
            "observed_root": self.observed_root,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status.as_str(),
            "subject_id": self.subject_id,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-CHALLENGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        hooks: &BTreeMap<String, ConfidentialAmmHook>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("challenge.challenge_id", &self.challenge_id)?;
        ensure_nonempty("challenge.claimant_commitment", &self.claimant_commitment)?;
        ensure_nonempty("challenge.hook_id", &self.hook_id)?;
        ensure_nonempty("challenge.subject_id", &self.subject_id)?;
        ensure_nonempty("challenge.evidence_root", &self.evidence_root)?;
        ensure_nonempty("challenge.expected_root", &self.expected_root)?;
        ensure_nonempty("challenge.observed_root", &self.observed_root)?;
        if !hooks.contains_key(&self.hook_id) {
            return Err(format!(
                "challenge {} references unknown hook",
                self.challenge_id
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!("challenge {} invalid expiry", self.challenge_id));
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err(format!(
                    "challenge {} resolved before opening",
                    self.challenge_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSlashingRecord {
    pub slashing_id: String,
    pub hook_id: String,
    pub challenge_id: String,
    pub operator_commitment: String,
    pub amount_units: u128,
    pub slash_bps: u64,
    pub beneficiary_root: String,
    pub status: SlashingStatus,
    pub applied_at_height: u64,
}

impl HookSlashingRecord {
    pub fn new(
        hook: &ConfidentialAmmHook,
        challenge_id: &str,
        beneficiary_root: &str,
        height: u64,
        config: &PrivateTokenConfidentialAmmHooksConfig,
    ) -> Self {
        let amount_units = bps_mul_u128(hook.sponsor_bond_units, config.slash_bps);
        let slashing_id = private_token_confidential_amm_hooks_slashing_id(
            &hook.hook_id,
            challenge_id,
            &hook.operator_commitment,
            height,
        );
        Self {
            slashing_id,
            hook_id: hook.hook_id.clone(),
            challenge_id: challenge_id.to_string(),
            operator_commitment: hook.operator_commitment.clone(),
            amount_units,
            slash_bps: config.slash_bps,
            beneficiary_root: beneficiary_root.to_string(),
            status: SlashingStatus::Applied,
            applied_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "amount_units": self.amount_units,
            "applied_at_height": self.applied_at_height,
            "beneficiary_root": self.beneficiary_root,
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "hook_id": self.hook_id,
            "operator_commitment": self.operator_commitment,
            "slash_bps": self.slash_bps,
            "slashing_id": self.slashing_id,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SLASHING",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(
        &self,
        hooks: &BTreeMap<String, ConfidentialAmmHook>,
        challenges: &BTreeMap<String, HookChallenge>,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        ensure_nonempty("slashing.slashing_id", &self.slashing_id)?;
        ensure_nonempty("slashing.hook_id", &self.hook_id)?;
        ensure_nonempty("slashing.challenge_id", &self.challenge_id)?;
        ensure_nonempty("slashing.operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("slashing.beneficiary_root", &self.beneficiary_root)?;
        ensure_positive("slashing.amount_units", self.amount_units)?;
        ensure_bps("slashing.slash_bps", self.slash_bps)?;
        let hook = hooks
            .get(&self.hook_id)
            .ok_or_else(|| format!("slashing {} references unknown hook", self.slashing_id))?;
        if hook.operator_commitment != self.operator_commitment {
            return Err(format!("slashing {} operator mismatch", self.slashing_id));
        }
        let challenge = challenges
            .get(&self.challenge_id)
            .ok_or_else(|| format!("slashing {} references unknown challenge", self.slashing_id))?;
        if challenge.status != HookChallengeStatus::Upheld {
            return Err(format!(
                "slashing {} requires upheld challenge",
                self.slashing_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenConfidentialAmmHooksCounters {
    pub allowlisted_tokens: usize,
    pub pools: usize,
    pub hooks: usize,
    pub active_hooks: usize,
    pub swaps: usize,
    pub pending_swaps: usize,
    pub settled_swaps: usize,
    pub lp_envelopes: usize,
    pub attestations: usize,
    pub sponsorships: usize,
    pub receipts: usize,
    pub challenges: usize,
    pub upheld_challenges: usize,
    pub slashings: usize,
}

impl PrivateTokenConfidentialAmmHooksCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "active_hooks": self.active_hooks,
            "allowlisted_tokens": self.allowlisted_tokens,
            "attestations": self.attestations,
            "chain_id": CHAIN_ID,
            "challenges": self.challenges,
            "hooks": self.hooks,
            "lp_envelopes": self.lp_envelopes,
            "pending_swaps": self.pending_swaps,
            "pools": self.pools,
            "receipts": self.receipts,
            "settled_swaps": self.settled_swaps,
            "slashings": self.slashings,
            "sponsorships": self.sponsorships,
            "swaps": self.swaps,
            "upheld_challenges": self.upheld_challenges,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenConfidentialAmmHooksRoots {
    pub allowlist_root: String,
    pub pool_root: String,
    pub hook_root: String,
    pub anti_sandwich_root: String,
    pub swap_root: String,
    pub lp_envelope_root: String,
    pub attestation_root: String,
    pub sponsorship_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub counter_root: String,
}

impl PrivateTokenConfidentialAmmHooksRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "allowlist_root": self.allowlist_root,
            "anti_sandwich_root": self.anti_sandwich_root,
            "attestation_root": self.attestation_root,
            "chain_id": CHAIN_ID,
            "challenge_root": self.challenge_root,
            "counter_root": self.counter_root,
            "hook_root": self.hook_root,
            "lp_envelope_root": self.lp_envelope_root,
            "pool_root": self.pool_root,
            "receipt_root": self.receipt_root,
            "slashing_root": self.slashing_root,
            "sponsorship_root": self.sponsorship_root,
            "swap_root": self.swap_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenConfidentialAmmHooksState {
    pub config: PrivateTokenConfidentialAmmHooksConfig,
    pub height: u64,
    pub allowlist: BTreeMap<String, ConfidentialTokenAllowlistEntry>,
    pub pools: BTreeMap<String, ConfidentialAmmPool>,
    pub hooks: BTreeMap<String, ConfidentialAmmHook>,
    pub anti_sandwich_commitments: BTreeMap<String, AntiSandwichCommitment>,
    pub swaps: BTreeMap<String, ConfidentialSwapHookIntent>,
    pub lp_envelopes: BTreeMap<String, LpPrivacyEnvelope>,
    pub attestations: BTreeMap<String, PqHookAttestation>,
    pub sponsorships: BTreeMap<String, LowFeeHookSponsorship>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub challenges: BTreeMap<String, HookChallenge>,
    pub slashings: BTreeMap<String, HookSlashingRecord>,
    pub seen_nullifiers: BTreeSet<String>,
}

impl PrivateTokenConfidentialAmmHooksState {
    pub fn new(config: PrivateTokenConfidentialAmmHooksConfig, height: u64) -> Self {
        Self {
            config,
            height,
            allowlist: BTreeMap::new(),
            pools: BTreeMap::new(),
            hooks: BTreeMap::new(),
            anti_sandwich_commitments: BTreeMap::new(),
            swaps: BTreeMap::new(),
            lp_envelopes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashings: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> PrivateTokenConfidentialAmmHooksResult<Self> {
        let config = PrivateTokenConfidentialAmmHooksConfig::devnet();
        let height = PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_HEIGHT;
        let mut state = Self::new(config, height);

        state.add_allowlist_entry(ConfidentialTokenAllowlistEntry::devnet(
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_FEE_TOKEN,
            ConfidentialTokenClass::Native,
            height.saturating_sub(48),
        ))?;
        state.add_allowlist_entry(ConfidentialTokenAllowlistEntry::devnet(
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_STABLE_TOKEN,
            ConfidentialTokenClass::Stable,
            height.saturating_sub(47),
        ))?;
        state.add_allowlist_entry(ConfidentialTokenAllowlistEntry::devnet(
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_GOV_TOKEN,
            ConfidentialTokenClass::Governance,
            height.saturating_sub(46),
        ))?;
        state.add_allowlist_entry(ConfidentialTokenAllowlistEntry::devnet(
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_RWA_TOKEN,
            ConfidentialTokenClass::Rwa,
            height.saturating_sub(45),
        ))?;

        let pool = ConfidentialAmmPool::devnet(
            "dxmr-dusd-confidential-amm",
            ConfidentialAmmPoolKind::Stable,
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_FEE_TOKEN,
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_STABLE_TOKEN,
            height.saturating_sub(40),
        );
        state.add_pool(pool)?;

        let hook = ConfidentialAmmHook::devnet(
            "dxmr-dusd-confidential-amm",
            ConfidentialAmmHookKind::PreSwap,
            "operator:confidential-amm-hook-committee:0",
            height.saturating_sub(32),
            &state.config,
        );
        let hook_id = hook.hook_id.clone();
        state.add_hook(hook)?;

        let swap = ConfidentialSwapHookIntent::new(
            "dxmr-dusd-confidential-amm",
            &hook_id,
            ConfidentialSwapSide::ExactInput,
            "trader:stealth-commitment:0",
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_FEE_TOKEN,
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_STABLE_TOKEN,
            "amount:pedersen:dxmr:42",
            "min-output:pedersen:dusd:41",
            height.saturating_sub(12),
            &state.config,
        );
        let anti_sandwich = AntiSandwichCommitment::new(
            &swap.pool_id,
            &swap.route_commitment,
            &private_token_confidential_amm_hooks_string_root(
                "swap-sealed-order",
                &swap.route_commitment,
            ),
            &private_token_confidential_amm_hooks_string_root("swap-pre-state", &swap.pool_id),
            state.config.max_price_impact_bps,
            swap.submitted_at_height,
            &state.config,
        );
        state.add_anti_sandwich_commitment(anti_sandwich)?;
        let swap_id = state.submit_swap(swap)?;

        let subject_root = state
            .swaps
            .get(&swap_id)
            .map(ConfidentialSwapHookIntent::state_root)
            .ok_or_else(|| "devnet swap missing after submission".to_string())?;
        let attestation = PqHookAttestation::new(
            &hook_id,
            &subject_root,
            "attester:pq-hook-quorum:0",
            height.saturating_sub(10),
            &state.config,
        );
        let attestation_id = state.add_attestation(attestation)?;

        let sponsorship = LowFeeHookSponsorship::new(
            "sponsor:low-fee-relay:0",
            &hook_id,
            &swap_id,
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_DEVNET_FEE_TOKEN,
            "fee:pedersen:dxmr:4bps",
            height.saturating_sub(9),
            &state.config,
        );
        let sponsorship_id = state.reserve_sponsorship(sponsorship)?;

        state.settle_swap(
            &swap_id,
            &attestation_id,
            Some(sponsorship_id),
            "output:pedersen:dusd:net",
            "fee:pedersen:dxmr:low",
            height.saturating_sub(8),
        )?;

        let envelope = LpPrivacyEnvelope::new(
            "dxmr-dusd-confidential-amm",
            &hook_id,
            "lp:stealth-owner:0",
            LpEnvelopeKind::Mint,
            "liquidity:pedersen:range:0",
            height.saturating_sub(7),
            &state.config,
        );
        state.add_lp_envelope(envelope)?;

        let challenge = HookChallenge::new(
            HookChallengeKind::SandwichRevealMismatch,
            "challenger:watchtower:0",
            &hook_id,
            &swap_id,
            "expected:post-state:root",
            "observed:post-state:root",
            height.saturating_sub(6),
            &state.config,
        );
        let challenge_id = state.open_challenge(challenge)?;
        state.resolve_challenge(&challenge_id, false, height.saturating_sub(4))?;

        state.validate()?;
        Ok(state)
    }

    pub fn update_height(
        &mut self,
        next_height: u64,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        if next_height < self.height {
            return Err(format!(
                "height cannot move backwards from {} to {}",
                self.height, next_height
            ));
        }
        self.height = next_height;
        self.expire_stale_records();
        Ok(())
    }

    pub fn add_allowlist_entry(
        &mut self,
        entry: ConfidentialTokenAllowlistEntry,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        self.config.validate()?;
        if self.allowlist.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_TOKENS {
            return Err("allowlist capacity exceeded".to_string());
        }
        entry.validate(&self.config)?;
        if self.allowlist.contains_key(&entry.token_id) {
            return Err(format!("allowlist entry {} already exists", entry.token_id));
        }
        let token_id = entry.token_id.clone();
        self.allowlist.insert(token_id.clone(), entry);
        Ok(token_id)
    }

    pub fn add_pool(
        &mut self,
        pool: ConfidentialAmmPool,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        self.config.validate()?;
        if self.pools.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_POOLS {
            return Err("pool capacity exceeded".to_string());
        }
        pool.validate(&self.config, &self.allowlist)?;
        if self.pools.contains_key(&pool.pool_id) {
            return Err(format!("pool {} already exists", pool.pool_id));
        }
        let pool_id = pool.pool_id.clone();
        self.pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }

    pub fn add_hook(
        &mut self,
        hook: ConfidentialAmmHook,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        self.config.validate()?;
        if self.hooks.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_HOOKS {
            return Err("hook capacity exceeded".to_string());
        }
        hook.validate(&self.config, &self.pools)?;
        if self.hooks.contains_key(&hook.hook_id) {
            return Err(format!("hook {} already exists", hook.hook_id));
        }
        let hooks_for_pool = self
            .hooks
            .values()
            .filter(|candidate| candidate.pool_id == hook.pool_id)
            .count();
        if hooks_for_pool >= self.config.max_hooks_per_pool {
            return Err(format!("pool {} hook limit exceeded", hook.pool_id));
        }
        let hook_id = hook.hook_id.clone();
        self.hooks.insert(hook_id.clone(), hook);
        Ok(hook_id)
    }

    pub fn add_anti_sandwich_commitment(
        &mut self,
        commitment: AntiSandwichCommitment,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        commitment.validate(&self.config, &self.pools)?;
        if self
            .anti_sandwich_commitments
            .contains_key(&commitment.commitment_id)
        {
            return Err(format!(
                "anti-sandwich commitment {} already exists",
                commitment.commitment_id
            ));
        }
        let commitment_id = commitment.commitment_id.clone();
        self.anti_sandwich_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn submit_swap(
        &mut self,
        mut swap: ConfidentialSwapHookIntent,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        self.config.validate()?;
        if self.swaps.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_SWAPS {
            return Err("swap capacity exceeded".to_string());
        }
        if self.pending_swap_count() >= self.config.max_pending_swaps {
            return Err("pending swap capacity exceeded".to_string());
        }
        if self.seen_nullifiers.contains(&swap.nullifier_root) {
            return Err(format!("swap {} nullifier already used", swap.swap_id));
        }
        swap.validate(
            &self.config,
            &self.pools,
            &self.hooks,
            &self.allowlist,
            &self.anti_sandwich_commitments,
        )?;
        if self.swaps.contains_key(&swap.swap_id) {
            return Err(format!("swap {} already exists", swap.swap_id));
        }
        swap.status = ConfidentialSwapStatus::Hooked;
        let swap_id = swap.swap_id.clone();
        self.seen_nullifiers.insert(swap.nullifier_root.clone());
        self.swaps.insert(swap_id.clone(), swap);
        Ok(swap_id)
    }

    pub fn add_lp_envelope(
        &mut self,
        envelope: LpPrivacyEnvelope,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        if self.lp_envelopes.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_LP_ENVELOPES {
            return Err("lp envelope capacity exceeded".to_string());
        }
        if self.seen_nullifiers.contains(&envelope.nullifier_root) {
            return Err(format!(
                "lp envelope {} nullifier already used",
                envelope.envelope_id
            ));
        }
        envelope.validate(&self.pools, &self.hooks)?;
        if self.lp_envelopes.contains_key(&envelope.envelope_id) {
            return Err(format!(
                "lp envelope {} already exists",
                envelope.envelope_id
            ));
        }
        let envelope_id = envelope.envelope_id.clone();
        self.seen_nullifiers.insert(envelope.nullifier_root.clone());
        self.lp_envelopes.insert(envelope_id.clone(), envelope);
        Ok(envelope_id)
    }

    pub fn add_attestation(
        &mut self,
        attestation: PqHookAttestation,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        if self.attestations.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_ATTESTATIONS {
            return Err("attestation capacity exceeded".to_string());
        }
        attestation.validate(&self.config, &self.hooks)?;
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err(format!(
                "attestation {} already exists",
                attestation.attestation_id
            ));
        }
        if let Some(hook) = self.hooks.get_mut(&attestation.hook_id) {
            hook.last_attested_height = monotonic_height(
                "hook.last_attested_height",
                hook.last_attested_height,
                attestation.attested_at_height,
            )?;
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn reserve_sponsorship(
        &mut self,
        sponsorship: LowFeeHookSponsorship,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        if self.sponsorships.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_SPONSORSHIPS {
            return Err("sponsorship capacity exceeded".to_string());
        }
        sponsorship.validate(&self.config, &self.swaps, &self.hooks, &self.allowlist)?;
        if self.sponsorships.contains_key(&sponsorship.sponsorship_id) {
            return Err(format!(
                "sponsorship {} already exists",
                sponsorship.sponsorship_id
            ));
        }
        if let Some(swap) = self.swaps.get_mut(&sponsorship.swap_id) {
            if swap.status != ConfidentialSwapStatus::Hooked {
                return Err(format!("swap {} is not sponsorable", swap.swap_id));
            }
            swap.status = ConfidentialSwapStatus::Sponsored;
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn settle_swap(
        &mut self,
        swap_id: &str,
        attestation_id: &str,
        sponsorship_id: Option<String>,
        output_commitment: &str,
        fee_commitment: &str,
        height: u64,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        if self.settlement_receipts.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_RECEIPTS {
            return Err("settlement receipt capacity exceeded".to_string());
        }
        let swap = self
            .swaps
            .get(swap_id)
            .cloned()
            .ok_or_else(|| format!("settlement references unknown swap {swap_id}"))?;
        if swap.status.terminal() {
            return Err(format!("swap {swap_id} is already terminal"));
        }
        if height < swap.submitted_at_height {
            return Err(format!(
                "settlement height before swap {swap_id} submission"
            ));
        }
        let attestation = self
            .attestations
            .get(attestation_id)
            .ok_or_else(|| format!("settlement references unknown attestation {attestation_id}"))?;
        if attestation.hook_id != swap.hook_id || attestation.status != HookAttestationStatus::Valid
        {
            return Err(format!(
                "attestation {attestation_id} cannot settle swap {swap_id}"
            ));
        }
        if let Some(existing_sponsorship_id) = &sponsorship_id {
            let sponsorship = self
                .sponsorships
                .get(existing_sponsorship_id)
                .ok_or_else(|| {
                    format!("settlement references unknown sponsorship {existing_sponsorship_id}")
                })?;
            if sponsorship.swap_id != swap_id || sponsorship.hook_id != swap.hook_id {
                return Err(format!(
                    "sponsorship {existing_sponsorship_id} does not match swap {swap_id}"
                ));
            }
        }
        let receipt = SettlementReceipt::new(
            &swap,
            attestation_id,
            sponsorship_id.clone(),
            output_commitment,
            fee_commitment,
            height,
            &self.config,
        );
        receipt.validate(&self.swaps, &self.attestations, &self.sponsorships)?;
        let receipt_id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        if let Some(swap) = self.swaps.get_mut(swap_id) {
            swap.status = ConfidentialSwapStatus::Settled;
        }
        if let Some(existing_sponsorship_id) = sponsorship_id {
            if let Some(sponsorship) = self.sponsorships.get_mut(&existing_sponsorship_id) {
                sponsorship.status = SponsorshipStatus::Applied;
            }
        }
        Ok(receipt_id)
    }

    pub fn open_challenge(
        &mut self,
        challenge: HookChallenge,
    ) -> PrivateTokenConfidentialAmmHooksResult<String> {
        if self.challenges.len() >= PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_CHALLENGES {
            return Err("challenge capacity exceeded".to_string());
        }
        challenge.validate(&self.hooks)?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err(format!(
                "challenge {} already exists",
                challenge.challenge_id
            ));
        }
        let challenge_id = challenge.challenge_id.clone();
        self.mark_subject_challenged(&challenge);
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        uphold: bool,
        height: u64,
    ) -> PrivateTokenConfidentialAmmHooksResult<Option<String>> {
        let (hook_id, claimant_commitment) = {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| format!("unknown challenge {challenge_id}"))?;
            if height < challenge.opened_at_height {
                return Err(format!(
                    "challenge {challenge_id} resolution before opening"
                ));
            }
            challenge.resolved_at_height = Some(height);
            challenge.status = if uphold {
                HookChallengeStatus::Upheld
            } else {
                HookChallengeStatus::Rejected
            };
            (
                challenge.hook_id.clone(),
                challenge.claimant_commitment.clone(),
            )
        };
        if !uphold {
            return Ok(None);
        }
        let hook = self
            .hooks
            .get(&hook_id)
            .cloned()
            .ok_or_else(|| format!("challenge {challenge_id} has unknown hook"))?;
        let beneficiary_root = private_token_confidential_amm_hooks_string_root(
            "slashing-beneficiary",
            &claimant_commitment,
        );
        let slashing =
            HookSlashingRecord::new(&hook, challenge_id, &beneficiary_root, height, &self.config);
        slashing.validate(&self.hooks, &self.challenges)?;
        let slashing_id = slashing.slashing_id.clone();
        self.slashings.insert(slashing_id.clone(), slashing);
        if let Some(hook) = self.hooks.get_mut(&hook_id) {
            hook.status = ConfidentialAmmHookStatus::Slashed;
        }
        Ok(Some(slashing_id))
    }

    pub fn finalize_receipt(
        &mut self,
        receipt_id: &str,
        height: u64,
    ) -> PrivateTokenConfidentialAmmHooksResult<()> {
        let receipt = self
            .settlement_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?;
        if height < receipt.challenge_deadline_height {
            return Err(format!(
                "receipt {receipt_id} cannot finalize before challenge deadline"
            ));
        }
        if receipt.status == SettlementReceiptStatus::Challenged {
            return Err(format!("receipt {receipt_id} is challenged"));
        }
        receipt.status = SettlementReceiptStatus::Finalized;
        Ok(())
    }

    pub fn roots(&self) -> PrivateTokenConfidentialAmmHooksRoots {
        let allowlist_records = self
            .allowlist
            .values()
            .map(ConfidentialTokenAllowlistEntry::public_record)
            .collect::<Vec<_>>();
        let pool_records = self
            .pools
            .values()
            .map(ConfidentialAmmPool::public_record)
            .collect::<Vec<_>>();
        let hook_records = self
            .hooks
            .values()
            .map(ConfidentialAmmHook::public_record)
            .collect::<Vec<_>>();
        let anti_sandwich_records = self
            .anti_sandwich_commitments
            .values()
            .map(AntiSandwichCommitment::public_record)
            .collect::<Vec<_>>();
        let swap_records = self
            .swaps
            .values()
            .map(ConfidentialSwapHookIntent::public_record)
            .collect::<Vec<_>>();
        let lp_envelope_records = self
            .lp_envelopes
            .values()
            .map(LpPrivacyEnvelope::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(PqHookAttestation::public_record)
            .collect::<Vec<_>>();
        let sponsorship_records = self
            .sponsorships
            .values()
            .map(LowFeeHookSponsorship::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .settlement_receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(HookChallenge::public_record)
            .collect::<Vec<_>>();
        let slashing_records = self
            .slashings
            .values()
            .map(HookSlashingRecord::public_record)
            .collect::<Vec<_>>();
        PrivateTokenConfidentialAmmHooksRoots {
            allowlist_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ALLOWLIST-ROOT",
                &allowlist_records,
            ),
            pool_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-POOL-ROOT",
                &pool_records,
            ),
            hook_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-HOOK-ROOT",
                &hook_records,
            ),
            anti_sandwich_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ANTI-SANDWICH-ROOT",
                &anti_sandwich_records,
            ),
            swap_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SWAP-ROOT",
                &swap_records,
            ),
            lp_envelope_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-LP-ENVELOPE-ROOT",
                &lp_envelope_records,
            ),
            attestation_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ATTESTATION-ROOT",
                &attestation_records,
            ),
            sponsorship_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SPONSORSHIP-ROOT",
                &sponsorship_records,
            ),
            receipt_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-RECEIPT-ROOT",
                &receipt_records,
            ),
            challenge_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-CHALLENGE-ROOT",
                &challenge_records,
            ),
            slashing_root: merkle_root(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SLASHING-ROOT",
                &slashing_records,
            ),
            counter_root: domain_hash(
                "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-COUNTERS",
                &[HashPart::Json(&self.counters().public_record())],
                32,
            ),
        }
    }

    pub fn counters(&self) -> PrivateTokenConfidentialAmmHooksCounters {
        PrivateTokenConfidentialAmmHooksCounters {
            allowlisted_tokens: self.allowlist.len(),
            pools: self.pools.len(),
            hooks: self.hooks.len(),
            active_hooks: self
                .hooks
                .values()
                .filter(|hook| hook.status.accepts_private_flow())
                .count(),
            swaps: self.swaps.len(),
            pending_swaps: self.pending_swap_count(),
            settled_swaps: self
                .swaps
                .values()
                .filter(|swap| swap.status == ConfidentialSwapStatus::Settled)
                .count(),
            lp_envelopes: self.lp_envelopes.len(),
            attestations: self.attestations.len(),
            sponsorships: self.sponsorships.len(),
            receipts: self.settlement_receipts.len(),
            challenges: self.challenges.len(),
            upheld_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == HookChallengeStatus::Upheld)
                .count(),
            slashings: self.slashings.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config,
            "counters": self.counters().public_record(),
            "height": self.height,
            "protocol_version": PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_PROTOCOL_VERSION,
            "roots": roots.public_record(),
            "schema_version": PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_SCHEMA_VERSION,
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_token_confidential_amm_hooks_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateTokenConfidentialAmmHooksResult<()> {
        self.config.validate()?;
        ensure_capacity(
            "allowlist",
            self.allowlist.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_TOKENS,
        )?;
        ensure_capacity(
            "pools",
            self.pools.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_POOLS,
        )?;
        ensure_capacity(
            "hooks",
            self.hooks.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_HOOKS,
        )?;
        ensure_capacity(
            "swaps",
            self.swaps.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_SWAPS,
        )?;
        ensure_capacity(
            "lp_envelopes",
            self.lp_envelopes.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_LP_ENVELOPES,
        )?;
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_ATTESTATIONS,
        )?;
        ensure_capacity(
            "sponsorships",
            self.sponsorships.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_SPONSORSHIPS,
        )?;
        ensure_capacity(
            "receipts",
            self.settlement_receipts.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_RECEIPTS,
        )?;
        ensure_capacity(
            "challenges",
            self.challenges.len(),
            PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_CHALLENGES,
        )?;
        for entry in self.allowlist.values() {
            entry.validate(&self.config)?;
        }
        for pool in self.pools.values() {
            pool.validate(&self.config, &self.allowlist)?;
        }
        for hook in self.hooks.values() {
            hook.validate(&self.config, &self.pools)?;
        }
        for commitment in self.anti_sandwich_commitments.values() {
            commitment.validate(&self.config, &self.pools)?;
        }
        for swap in self.swaps.values() {
            swap.validate(
                &self.config,
                &self.pools,
                &self.hooks,
                &self.allowlist,
                &self.anti_sandwich_commitments,
            )?;
        }
        for envelope in self.lp_envelopes.values() {
            envelope.validate(&self.pools, &self.hooks)?;
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.config, &self.hooks)?;
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate(&self.config, &self.swaps, &self.hooks, &self.allowlist)?;
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate(&self.swaps, &self.attestations, &self.sponsorships)?;
        }
        for challenge in self.challenges.values() {
            challenge.validate(&self.hooks)?;
        }
        for slashing in self.slashings.values() {
            slashing.validate(&self.hooks, &self.challenges)?;
        }
        self.validate_nullifier_set()?;
        Ok(())
    }

    fn pending_swap_count(&self) -> usize {
        self.swaps
            .values()
            .filter(|swap| !swap.status.terminal())
            .count()
    }

    fn validate_nullifier_set(&self) -> PrivateTokenConfidentialAmmHooksResult<()> {
        let mut observed = BTreeSet::new();
        for swap in self.swaps.values() {
            if !observed.insert(swap.nullifier_root.clone()) {
                return Err(format!("duplicate swap nullifier {}", swap.nullifier_root));
            }
        }
        for envelope in self.lp_envelopes.values() {
            if !observed.insert(envelope.nullifier_root.clone()) {
                return Err(format!(
                    "duplicate lp envelope nullifier {}",
                    envelope.nullifier_root
                ));
            }
        }
        if observed != self.seen_nullifiers {
            return Err("seen nullifier set does not match records".to_string());
        }
        Ok(())
    }

    fn mark_subject_challenged(&mut self, challenge: &HookChallenge) {
        match challenge.kind {
            HookChallengeKind::InvalidPqAttestation => {
                if let Some(attestation) = self.attestations.get_mut(&challenge.subject_id) {
                    attestation.status = HookAttestationStatus::Disputed;
                }
            }
            HookChallengeKind::AllowlistBypass
            | HookChallengeKind::SandwichRevealMismatch
            | HookChallengeKind::FeeOvercharge
            | HookChallengeKind::SettlementMismatch
            | HookChallengeKind::LateSettlement => {
                if let Some(swap) = self.swaps.get_mut(&challenge.subject_id) {
                    swap.status = ConfidentialSwapStatus::Challenged;
                }
                if let Some(receipt) = self.settlement_receipts.get_mut(&challenge.subject_id) {
                    receipt.status = SettlementReceiptStatus::Challenged;
                }
                if let Some(sponsorship) = self.sponsorships.get_mut(&challenge.subject_id) {
                    sponsorship.status = SponsorshipStatus::Challenged;
                }
            }
            HookChallengeKind::InvalidLpEnvelope => {
                if let Some(envelope) = self.lp_envelopes.get_mut(&challenge.subject_id) {
                    envelope.status = LpEnvelopeStatus::Challenged;
                }
            }
        }
    }

    fn expire_stale_records(&mut self) {
        for swap in self.swaps.values_mut() {
            if !swap.status.terminal() && self.height > swap.expires_at_height {
                swap.status = ConfidentialSwapStatus::Expired;
            }
        }
        for envelope in self.lp_envelopes.values_mut() {
            if matches!(
                envelope.status,
                LpEnvelopeStatus::Sealed | LpEnvelopeStatus::Admitted
            ) && self.height > envelope.expires_at_height
            {
                envelope.status = LpEnvelopeStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status == SponsorshipStatus::Reserved
                && self.height > sponsorship.expires_at_height
            {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if matches!(
                challenge.status,
                HookChallengeStatus::Open | HookChallengeStatus::EvidencePosted
            ) && self.height > challenge.expires_at_height
            {
                challenge.status = HookChallengeStatus::Expired;
            }
        }
    }
}

pub fn private_token_confidential_amm_hooks_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn private_token_confidential_amm_hooks_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_token_confidential_amm_hooks_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_token_confidential_amm_hooks_string_set_root(
    label: &str,
    values: &[&str],
) -> String {
    let records = values
        .iter()
        .map(|value| json!({"label": label, "value": value}))
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-STRING-SET", &records)
}

pub fn private_token_confidential_amm_hooks_pool_id(
    pool_kind: ConfidentialAmmPoolKind,
    token_a: &str,
    token_b: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_kind.as_str()),
            HashPart::Str(token_a),
            HashPart::Str(token_b),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_hook_id(
    pool_id: &str,
    hook_kind: ConfidentialAmmHookKind,
    operator_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(hook_kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_commitment_id(
    pool_id: &str,
    route_commitment: &str,
    sealed_order_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(route_commitment),
            HashPart::Str(sealed_order_root),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_swap_id(
    pool_id: &str,
    hook_id: &str,
    trader_commitment: &str,
    route_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SWAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(hook_id),
            HashPart::Str(trader_commitment),
            HashPart::Str(route_commitment),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_lp_envelope_id(
    pool_id: &str,
    hook_id: &str,
    owner_commitment: &str,
    envelope_kind: LpEnvelopeKind,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-LP-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(hook_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(envelope_kind.as_str()),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_attestation_id(
    hook_id: &str,
    subject_root: &str,
    attester_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(hook_id),
            HashPart::Str(subject_root),
            HashPart::Str(attester_commitment),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_sponsorship_id(
    sponsor_commitment: &str,
    hook_id: &str,
    swap_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(hook_id),
            HashPart::Str(swap_id),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_receipt_id(
    swap_id: &str,
    attestation_id: &str,
    post_state_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(swap_id),
            HashPart::Str(attestation_id),
            HashPart::Str(post_state_root),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_challenge_id(
    kind: HookChallengeKind,
    claimant_commitment: &str,
    hook_id: &str,
    subject_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(claimant_commitment),
            HashPart::Str(hook_id),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn private_token_confidential_amm_hooks_slashing_id(
    hook_id: &str,
    challenge_id: &str,
    operator_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONFIDENTIAL-AMM-HOOKS-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(hook_id),
            HashPart::Str(challenge_id),
            HashPart::Str(operator_commitment),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

fn ensure_nonempty(name: &str, value: &str) -> PrivateTokenConfidentialAmmHooksResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive<T>(name: &str, value: T) -> PrivateTokenConfidentialAmmHooksResult<()>
where
    T: PartialEq + Default,
{
    if value == T::default() {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn ensure_nonzero_usize(name: &str, value: usize) -> PrivateTokenConfidentialAmmHooksResult<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> PrivateTokenConfidentialAmmHooksResult<()> {
    if value > PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_BPS {
        return Err(format!("{name} exceeds max bps"));
    }
    Ok(())
}

fn ensure_capacity(
    label: &str,
    observed: usize,
    max: usize,
) -> PrivateTokenConfidentialAmmHooksResult<()> {
    if observed > max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_allowlisted(
    token_id: &str,
    allowlist: &BTreeMap<String, ConfidentialTokenAllowlistEntry>,
) -> PrivateTokenConfidentialAmmHooksResult<()> {
    let entry = allowlist
        .get(token_id)
        .ok_or_else(|| format!("token {token_id} is not allowlisted"))?;
    if !entry.active {
        return Err(format!("token {token_id} is not active"));
    }
    Ok(())
}

fn monotonic_height(
    name: &str,
    current: u64,
    next: u64,
) -> PrivateTokenConfidentialAmmHooksResult<u64> {
    if next < current {
        return Err(format!("{name} cannot move backwards"));
    }
    Ok(next)
}

fn bps_mul_u128(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / PRIVATE_TOKEN_CONFIDENTIAL_AMM_HOOKS_MAX_BPS as u128
}
