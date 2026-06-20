use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialTokenBridgeMintBurnAuditorResult<T> = Result<T, String>;

pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_PROTOCOL_VERSION: &str =
    "nebula-confidential-token-bridge-mint-burn-auditor-v1";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_HEIGHT: u64 = 192;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_WRAPPED_XMR_ASSET_ID: &str =
    "wxmr-devnet";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_AUDIT_TOKEN_ID: &str =
    "confidential-token-devnet";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_COMMITMENT_SCHEME: &str =
    "pedersen-compatible-supply-commitment-v1";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_RANGE_PROOF_SCHEME: &str =
    "zk-range-proof-64-confidential-token-v1";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_RESERVE_PROOF_SCHEME: &str =
    "monero-view-key-reserve-liability-proof-v1";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_BATCH_PROOF_SCHEME: &str =
    "confidential-mint-burn-batch-balance-proof-v1";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-auditor-v1";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_REPLAY_DOMAIN: &str =
    "nebula-confidential-token-bridge-replay-v1";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 =
    10_100;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_WARNING_COVERAGE_BPS: u64 = 10_000;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_HALT_COVERAGE_BPS: u64 = 9_800;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 7;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MINT_TTL_BLOCKS: u64 = 144;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_BURN_TTL_BLOCKS: u64 = 288;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_RESERVE_TTL_BLOCKS: u64 = 72;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MAX_BATCH_ITEMS: usize = 8_192;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_ASSETS: usize = 65_536;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_ISSUERS: usize = 65_536;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_RESERVE_PROOFS: usize = 262_144;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_BATCHES: usize = 262_144;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_NULLIFIERS: usize = 1_048_576;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_REBATES: usize = 524_288;
pub const CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTokenKind {
    WrappedXmr,
    ConfidentialWrappedXmr,
    ConfidentialToken,
    ReserveReceipt,
    FeeCredit,
}

impl BridgeTokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedXmr => "wrapped_xmr",
            Self::ConfidentialWrappedXmr => "confidential_wrapped_xmr",
            Self::ConfidentialToken => "confidential_token",
            Self::ReserveReceipt => "reserve_receipt",
            Self::FeeCredit => "fee_credit",
        }
    }

    pub fn requires_reserve(self) -> bool {
        matches!(
            self,
            Self::WrappedXmr | Self::ConfidentialWrappedXmr | Self::ReserveReceipt
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerStatus {
    Candidate,
    Active,
    Constrained,
    Paused,
    Slashed,
    Retired,
}

impl IssuerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Constrained => "constrained",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_mint(self) -> bool {
        matches!(self, Self::Active | Self::Constrained)
    }

    pub fn can_burn(self) -> bool {
        matches!(self, Self::Active | Self::Constrained | Self::Paused)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchKind {
    ShieldedMint,
    ShieldedBurn,
    NetMintBurn,
    ReserveSync,
    EmergencyBurn,
}

impl BatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedMint => "shielded_mint",
            Self::ShieldedBurn => "shielded_burn",
            Self::NetMintBurn => "net_mint_burn",
            Self::ReserveSync => "reserve_sync",
            Self::EmergencyBurn => "emergency_burn",
        }
    }

    pub fn includes_mint(self) -> bool {
        matches!(
            self,
            Self::ShieldedMint | Self::NetMintBurn | Self::ReserveSync
        )
    }

    pub fn includes_burn(self) -> bool {
        matches!(
            self,
            Self::ShieldedBurn | Self::NetMintBurn | Self::EmergencyBurn
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    ReserveChecked,
    CommitteeApproved,
    Applied,
    Challenged,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ReserveChecked => "reserve_checked",
            Self::CommitteeApproved => "committee_approved",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_final(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Posted,
    Verified,
    Stale,
    Challenged,
    Revoked,
}

impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Verified => "verified",
            Self::Stale => "stale",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Posted | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeMemberStatus {
    Active,
    Paused,
    Slashed,
    Retired,
}

impl CommitteeMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn counts(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayFindingStatus {
    Observed,
    Quarantined,
    ConfirmedReplay,
    Cleared,
}

impl ReplayFindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Quarantined => "quarantined",
            Self::ConfirmedReplay => "confirmed_replay",
            Self::Cleared => "cleared",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRebateStatus {
    Accruing,
    Eligible,
    Claimed,
    Settled,
    Rejected,
    Expired,
}

impl FeeRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Eligible => "eligible",
            Self::Claimed => "claimed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub wrapped_xmr_asset_id: String,
    pub default_rebate_asset_id: String,
    pub hash_suite: String,
    pub commitment_scheme: String,
    pub range_proof_scheme: String,
    pub reserve_proof_scheme: String,
    pub batch_proof_scheme: String,
    pub pq_auth_suite: String,
    pub replay_domain: String,
    pub min_reserve_coverage_bps: u64,
    pub warning_reserve_coverage_bps: u64,
    pub halt_reserve_coverage_bps: u64,
    pub min_committee_weight: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub mint_ttl_blocks: u64,
    pub burn_ttl_blocks: u64,
    pub reserve_proof_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_batch_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_PROTOCOL_VERSION
                .to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_MONERO_NETWORK
                .to_string(),
            wrapped_xmr_asset_id:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_WRAPPED_XMR_ASSET_ID.to_string(),
            default_rebate_asset_id:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_REBATE_ASSET_ID.to_string(),
            hash_suite: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_HASH_SUITE.to_string(),
            commitment_scheme:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_COMMITMENT_SCHEME.to_string(),
            range_proof_scheme:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_RANGE_PROOF_SCHEME.to_string(),
            reserve_proof_scheme:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_RESERVE_PROOF_SCHEME.to_string(),
            batch_proof_scheme:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_BATCH_PROOF_SCHEME.to_string(),
            pq_auth_suite: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_PQ_AUTH_SUITE
                .to_string(),
            replay_domain: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_REPLAY_DOMAIN
                .to_string(),
            min_reserve_coverage_bps:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warning_reserve_coverage_bps:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_WARNING_COVERAGE_BPS,
            halt_reserve_coverage_bps:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_HALT_COVERAGE_BPS,
            min_committee_weight:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_COMMITTEE_WEIGHT,
            min_privacy_set_size:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MIN_PQ_SECURITY_BITS,
            mint_ttl_blocks: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MINT_TTL_BLOCKS,
            burn_ttl_blocks: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_BURN_TTL_BLOCKS,
            reserve_proof_ttl_blocks:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_RESERVE_TTL_BLOCKS,
            rebate_ttl_blocks:
                CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_REBATE_TTL_BLOCKS,
            max_batch_items: CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEFAULT_MAX_BATCH_ITEMS,
        }
    }

    pub fn validate(&self) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("wrapped_xmr_asset_id", &self.wrapped_xmr_asset_id)?;
        require_non_empty("default_rebate_asset_id", &self.default_rebate_asset_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("commitment_scheme", &self.commitment_scheme)?;
        require_non_empty("range_proof_scheme", &self.range_proof_scheme)?;
        require_non_empty("reserve_proof_scheme", &self.reserve_proof_scheme)?;
        require_non_empty("batch_proof_scheme", &self.batch_proof_scheme)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_non_empty("replay_domain", &self.replay_domain)?;
        require_bps("min_reserve_coverage_bps", self.min_reserve_coverage_bps)?;
        require_bps(
            "warning_reserve_coverage_bps",
            self.warning_reserve_coverage_bps,
        )?;
        require_bps("halt_reserve_coverage_bps", self.halt_reserve_coverage_bps)?;
        if self.halt_reserve_coverage_bps > self.warning_reserve_coverage_bps {
            return Err("halt reserve coverage must not exceed warning coverage".to_string());
        }
        if self.warning_reserve_coverage_bps > self.min_reserve_coverage_bps {
            return Err("warning reserve coverage must not exceed minimum coverage".to_string());
        }
        if self.min_committee_weight == 0 {
            return Err("min_committee_weight must be non-zero".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        if self.min_pq_security_bits == 0 {
            return Err("min_pq_security_bits must be non-zero".to_string());
        }
        if self.mint_ttl_blocks == 0 || self.burn_ttl_blocks == 0 {
            return Err("mint and burn ttl blocks must be non-zero".to_string());
        }
        if self.reserve_proof_ttl_blocks == 0 || self.rebate_ttl_blocks == 0 {
            return Err("reserve proof and rebate ttl blocks must be non-zero".to_string());
        }
        if self.max_batch_items == 0 {
            return Err("max_batch_items must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "wrapped_xmr_asset_id": self.wrapped_xmr_asset_id,
            "default_rebate_asset_id": self.default_rebate_asset_id,
            "hash_suite": self.hash_suite,
            "commitment_scheme": self.commitment_scheme,
            "range_proof_scheme": self.range_proof_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
            "batch_proof_scheme": self.batch_proof_scheme,
            "pq_auth_suite": self.pq_auth_suite,
            "replay_domain": self.replay_domain,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warning_reserve_coverage_bps": self.warning_reserve_coverage_bps,
            "halt_reserve_coverage_bps": self.halt_reserve_coverage_bps,
            "min_committee_weight": self.min_committee_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "mint_ttl_blocks": self.mint_ttl_blocks,
            "burn_ttl_blocks": self.burn_ttl_blocks,
            "reserve_proof_ttl_blocks": self.reserve_proof_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "max_batch_items": self.max_batch_items,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyCommitment {
    pub asset_id: String,
    pub token_kind: BridgeTokenKind,
    pub issuer_id: String,
    pub total_minted_commitment: String,
    pub total_burned_commitment: String,
    pub circulating_supply_commitment: String,
    pub reserve_liability_commitment: String,
    pub confidential_supply_root: String,
    pub range_proof_root: String,
    pub opening_policy_root: String,
    pub last_updated_height: u64,
}

impl SupplyCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "token_kind": self.token_kind.as_str(),
            "issuer_id": self.issuer_id,
            "total_minted_commitment": self.total_minted_commitment,
            "total_burned_commitment": self.total_burned_commitment,
            "circulating_supply_commitment": self.circulating_supply_commitment,
            "reserve_liability_commitment": self.reserve_liability_commitment,
            "confidential_supply_root": self.confidential_supply_root,
            "range_proof_root": self.range_proof_root,
            "opening_policy_root": self.opening_policy_root,
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn commitment_id(&self) -> String {
        domain_hash(
            "CONFIDENTIAL-TOKEN-BRIDGE-SUPPLY-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.asset_id),
                HashPart::Str(self.token_kind.as_str()),
                HashPart::Str(&self.issuer_id),
                HashPart::Str(&self.circulating_supply_commitment),
                HashPart::Int(self.last_updated_height as i128),
            ],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("issuer_id", &self.issuer_id)?;
        require_hash_like("total_minted_commitment", &self.total_minted_commitment)?;
        require_hash_like("total_burned_commitment", &self.total_burned_commitment)?;
        require_hash_like(
            "circulating_supply_commitment",
            &self.circulating_supply_commitment,
        )?;
        require_hash_like(
            "reserve_liability_commitment",
            &self.reserve_liability_commitment,
        )?;
        require_hash_like("confidential_supply_root", &self.confidential_supply_root)?;
        require_hash_like("range_proof_root", &self.range_proof_root)?;
        require_hash_like("opening_policy_root", &self.opening_policy_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerConstraint {
    pub issuer_id: String,
    pub issuer_commitment: String,
    pub status: IssuerStatus,
    pub allowed_asset_ids: BTreeSet<String>,
    pub mint_cap_commitment: String,
    pub burn_limit_commitment: String,
    pub reserve_account_root: String,
    pub policy_root: String,
    pub committee_root: String,
    pub pq_security_bits: u16,
    pub active_from_height: u64,
    pub expires_at_height: u64,
}

impl IssuerConstraint {
    pub fn public_record(&self) -> Value {
        json!({
            "issuer_id": self.issuer_id,
            "issuer_commitment": self.issuer_commitment,
            "status": self.status.as_str(),
            "allowed_asset_ids": self.allowed_asset_ids.iter().cloned().collect::<Vec<_>>(),
            "mint_cap_commitment": self.mint_cap_commitment,
            "burn_limit_commitment": self.burn_limit_commitment,
            "reserve_account_root": self.reserve_account_root,
            "policy_root": self.policy_root,
            "committee_root": self.committee_root,
            "pq_security_bits": self.pq_security_bits,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn constraint_id(&self) -> String {
        domain_hash(
            "CONFIDENTIAL-TOKEN-BRIDGE-ISSUER-CONSTRAINT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.issuer_id),
                HashPart::Str(&self.issuer_commitment),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(&self.policy_root),
                HashPart::Int(self.active_from_height as i128),
                HashPart::Int(self.expires_at_height as i128),
            ],
            32,
        )
    }

    pub fn validate(&self, config: &Config) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_non_empty("issuer_id", &self.issuer_id)?;
        require_hash_like("issuer_commitment", &self.issuer_commitment)?;
        if self.allowed_asset_ids.is_empty() {
            return Err(format!("issuer {} has no allowed assets", self.issuer_id));
        }
        for asset_id in &self.allowed_asset_ids {
            require_non_empty("issuer allowed asset id", asset_id)?;
        }
        require_hash_like("mint_cap_commitment", &self.mint_cap_commitment)?;
        require_hash_like("burn_limit_commitment", &self.burn_limit_commitment)?;
        require_hash_like("reserve_account_root", &self.reserve_account_root)?;
        require_hash_like("policy_root", &self.policy_root)?;
        require_hash_like("committee_root", &self.committee_root)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "issuer {} pq security below minimum",
                self.issuer_id
            ));
        }
        if self.expires_at_height <= self.active_from_height {
            return Err(format!(
                "issuer {} expiry is not after activation",
                self.issuer_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeReserveProof {
    pub proof_id: String,
    pub asset_id: String,
    pub issuer_id: String,
    pub monero_network: String,
    pub reserve_view_key_commitment: String,
    pub reserve_output_root: String,
    pub liability_commitment_root: String,
    pub reserve_commitment: String,
    pub liability_commitment: String,
    pub surplus_commitment: String,
    pub coverage_bps: u64,
    pub proof_scheme: String,
    pub status: ReserveProofStatus,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl BridgeReserveProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "asset_id": self.asset_id,
            "issuer_id": self.issuer_id,
            "monero_network": self.monero_network,
            "reserve_view_key_commitment": self.reserve_view_key_commitment,
            "reserve_output_root": self.reserve_output_root,
            "liability_commitment_root": self.liability_commitment_root,
            "reserve_commitment": self.reserve_commitment,
            "liability_commitment": self.liability_commitment,
            "surplus_commitment": self.surplus_commitment,
            "coverage_bps": self.coverage_bps,
            "proof_scheme": self.proof_scheme,
            "status": self.status.as_str(),
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self, config: &Config) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_id("proof_id", &self.proof_id)?;
        require_non_empty("reserve proof asset_id", &self.asset_id)?;
        require_non_empty("reserve proof issuer_id", &self.issuer_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_hash_like(
            "reserve_view_key_commitment",
            &self.reserve_view_key_commitment,
        )?;
        require_hash_like("reserve_output_root", &self.reserve_output_root)?;
        require_hash_like("liability_commitment_root", &self.liability_commitment_root)?;
        require_hash_like("reserve_commitment", &self.reserve_commitment)?;
        require_hash_like("liability_commitment", &self.liability_commitment)?;
        require_hash_like("surplus_commitment", &self.surplus_commitment)?;
        require_bps("reserve proof coverage_bps", self.coverage_bps)?;
        require_non_empty("proof_scheme", &self.proof_scheme)?;
        if self.coverage_bps < config.halt_reserve_coverage_bps {
            return Err(format!(
                "reserve proof {} below halt coverage",
                self.proof_id
            ));
        }
        if self.expires_at_height <= self.observed_at_height {
            return Err(format!("reserve proof {} expiry is invalid", self.proof_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintBurnBatch {
    pub batch_id: String,
    pub batch_kind: BatchKind,
    pub status: BatchStatus,
    pub issuer_id: String,
    pub asset_id: String,
    pub reserve_proof_id: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub mint_commitment_root: String,
    pub burn_commitment_root: String,
    pub nullifier_root: String,
    pub fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub balance_proof_root: String,
    pub audit_transcript_root: String,
    pub item_count: usize,
    pub privacy_set_size: u64,
    pub proposed_at_height: u64,
    pub expires_at_height: u64,
}

impl MintBurnBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "batch_kind": self.batch_kind.as_str(),
            "status": self.status.as_str(),
            "issuer_id": self.issuer_id,
            "asset_id": self.asset_id,
            "reserve_proof_id": self.reserve_proof_id,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "mint_commitment_root": self.mint_commitment_root,
            "burn_commitment_root": self.burn_commitment_root,
            "nullifier_root": self.nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "balance_proof_root": self.balance_proof_root,
            "audit_transcript_root": self.audit_transcript_root,
            "item_count": self.item_count,
            "privacy_set_size": self.privacy_set_size,
            "proposed_at_height": self.proposed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self, config: &Config) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_id("batch_id", &self.batch_id)?;
        require_non_empty("batch issuer_id", &self.issuer_id)?;
        require_non_empty("batch asset_id", &self.asset_id)?;
        require_id("reserve_proof_id", &self.reserve_proof_id)?;
        require_hash_like("input_note_root", &self.input_note_root)?;
        require_hash_like("output_note_root", &self.output_note_root)?;
        require_hash_like("mint_commitment_root", &self.mint_commitment_root)?;
        require_hash_like("burn_commitment_root", &self.burn_commitment_root)?;
        require_hash_like("nullifier_root", &self.nullifier_root)?;
        require_hash_like("fee_commitment_root", &self.fee_commitment_root)?;
        require_hash_like("rebate_commitment_root", &self.rebate_commitment_root)?;
        require_hash_like("balance_proof_root", &self.balance_proof_root)?;
        require_hash_like("audit_transcript_root", &self.audit_transcript_root)?;
        if self.item_count == 0 {
            return Err(format!("batch {} has no items", self.batch_id));
        }
        if self.item_count > config.max_batch_items {
            return Err(format!("batch {} exceeds max items", self.batch_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("batch {} privacy set below minimum", self.batch_id));
        }
        if self.expires_at_height <= self.proposed_at_height {
            return Err(format!("batch {} expiry is invalid", self.batch_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditorCommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub status: CommitteeMemberStatus,
    pub weight: u64,
    pub pq_public_key_root: String,
    pub jurisdiction_commitment: String,
    pub active_from_height: u64,
}

impl AuditorCommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "weight": self.weight,
            "pq_public_key_root": self.pq_public_key_root,
            "jurisdiction_commitment": self.jurisdiction_commitment,
            "active_from_height": self.active_from_height,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_id("member_id", &self.member_id)?;
        require_hash_like("operator_commitment", &self.operator_commitment)?;
        if self.weight == 0 {
            return Err(format!(
                "committee member {} has zero weight",
                self.member_id
            ));
        }
        require_hash_like("pq_public_key_root", &self.pq_public_key_root)?;
        require_hash_like("jurisdiction_commitment", &self.jurisdiction_commitment)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub member_id: String,
    pub attested_root: String,
    pub decision: String,
    pub signature_root: String,
    pub attested_at_height: u64,
}

impl BatchAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "member_id": self.member_id,
            "attested_root": self.attested_root,
            "decision": self.decision,
            "signature_root": self.signature_root,
            "attested_at_height": self.attested_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_id("attestation_id", &self.attestation_id)?;
        require_id("batch_id", &self.batch_id)?;
        require_id("member_id", &self.member_id)?;
        require_hash_like("attested_root", &self.attested_root)?;
        require_non_empty("decision", &self.decision)?;
        require_hash_like("signature_root", &self.signature_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierReplayFinding {
    pub finding_id: String,
    pub nullifier: String,
    pub first_batch_id: String,
    pub repeated_batch_id: String,
    pub asset_id: String,
    pub issuer_id: String,
    pub evidence_root: String,
    pub status: ReplayFindingStatus,
    pub observed_at_height: u64,
}

impl NullifierReplayFinding {
    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "nullifier": self.nullifier,
            "first_batch_id": self.first_batch_id,
            "repeated_batch_id": self.repeated_batch_id,
            "asset_id": self.asset_id,
            "issuer_id": self.issuer_id,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_id("finding_id", &self.finding_id)?;
        require_hash_like("nullifier", &self.nullifier)?;
        require_id("first_batch_id", &self.first_batch_id)?;
        require_id("repeated_batch_id", &self.repeated_batch_id)?;
        if self.first_batch_id == self.repeated_batch_id {
            return Err(format!(
                "replay finding {} references one batch",
                self.finding_id
            ));
        }
        require_non_empty("replay asset_id", &self.asset_id)?;
        require_non_empty("replay issuer_id", &self.issuer_id)?;
        require_hash_like("evidence_root", &self.evidence_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateLedgerEntry {
    pub rebate_id: String,
    pub batch_id: String,
    pub claimant_commitment: String,
    pub asset_id: String,
    pub rebate_asset_id: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub eligibility_root: String,
    pub nullifier: String,
    pub status: FeeRebateStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebateLedgerEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "claimant_commitment": self.claimant_commitment,
            "asset_id": self.asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "eligibility_root": self.eligibility_root,
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        require_id("rebate_id", &self.rebate_id)?;
        require_id("batch_id", &self.batch_id)?;
        require_hash_like("claimant_commitment", &self.claimant_commitment)?;
        require_non_empty("rebate asset_id", &self.asset_id)?;
        require_non_empty("rebate_asset_id", &self.rebate_asset_id)?;
        require_hash_like("fee_commitment", &self.fee_commitment)?;
        require_hash_like("rebate_commitment", &self.rebate_commitment)?;
        require_hash_like("eligibility_root", &self.eligibility_root)?;
        require_hash_like("rebate nullifier", &self.nullifier)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!("rebate {} expiry is invalid", self.rebate_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub supply_commitment_root: String,
    pub issuer_constraint_root: String,
    pub reserve_proof_root: String,
    pub mint_burn_batch_root: String,
    pub committee_member_root: String,
    pub batch_attestation_root: String,
    pub nullifier_root: String,
    pub replay_finding_root: String,
    pub fee_rebate_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "supply_commitment_root": self.supply_commitment_root,
            "issuer_constraint_root": self.issuer_constraint_root,
            "reserve_proof_root": self.reserve_proof_root,
            "mint_burn_batch_root": self.mint_burn_batch_root,
            "committee_member_root": self.committee_member_root,
            "batch_attestation_root": self.batch_attestation_root,
            "nullifier_root": self.nullifier_root,
            "replay_finding_root": self.replay_finding_root,
            "fee_rebate_root": self.fee_rebate_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub supply_commitments: usize,
    pub issuer_constraints: usize,
    pub reserve_proofs: usize,
    pub mint_burn_batches: usize,
    pub committee_members: usize,
    pub batch_attestations: usize,
    pub observed_nullifiers: usize,
    pub replay_findings: usize,
    pub fee_rebates: usize,
    pub events: usize,
    pub active_issuers: usize,
    pub applied_batches: usize,
    pub challenged_batches: usize,
    pub confirmed_replays: usize,
    pub settled_rebates: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "supply_commitments": self.supply_commitments,
            "issuer_constraints": self.issuer_constraints,
            "reserve_proofs": self.reserve_proofs,
            "mint_burn_batches": self.mint_burn_batches,
            "committee_members": self.committee_members,
            "batch_attestations": self.batch_attestations,
            "observed_nullifiers": self.observed_nullifiers,
            "replay_findings": self.replay_findings,
            "fee_rebates": self.fee_rebates,
            "events": self.events,
            "active_issuers": self.active_issuers,
            "applied_batches": self.applied_batches,
            "challenged_batches": self.challenged_batches,
            "confirmed_replays": self.confirmed_replays,
            "settled_rebates": self.settled_rebates,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub supply_commitments: BTreeMap<String, SupplyCommitment>,
    pub issuer_constraints: BTreeMap<String, IssuerConstraint>,
    pub reserve_proofs: BTreeMap<String, BridgeReserveProof>,
    pub mint_burn_batches: BTreeMap<String, MintBurnBatch>,
    pub committee_members: BTreeMap<String, AuditorCommitteeMember>,
    pub batch_attestations: BTreeMap<String, BatchAttestation>,
    pub observed_nullifiers: BTreeMap<String, String>,
    pub replay_findings: BTreeMap<String, NullifierReplayFinding>,
    pub fee_rebates: BTreeMap<String, FeeRebateLedgerEntry>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> ConfidentialTokenBridgeMintBurnAuditorResult<State> {
        let config = Config::devnet();
        config.validate()?;
        let height = CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_HEIGHT;
        let issuer_id = deterministic_id("ISSUER", "devnet-issuer", height);
        let asset_id =
            CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_AUDIT_TOKEN_ID.to_string();
        let wxmr_asset_id =
            CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_DEVNET_WRAPPED_XMR_ASSET_ID.to_string();
        let reserve_proof_id = deterministic_id("RESERVE-PROOF", "devnet-reserve", height);
        let batch_id = deterministic_id("MINT-BURN-BATCH", "devnet-net-batch", height);

        let mut supply_commitments = BTreeMap::new();
        let supply = SupplyCommitment {
            asset_id: asset_id.clone(),
            token_kind: BridgeTokenKind::ConfidentialToken,
            issuer_id: issuer_id.clone(),
            total_minted_commitment: deterministic_commitment("total-minted", &asset_id, height),
            total_burned_commitment: deterministic_commitment("total-burned", &asset_id, height),
            circulating_supply_commitment: deterministic_commitment(
                "circulating",
                &asset_id,
                height,
            ),
            reserve_liability_commitment: deterministic_commitment("liability", &asset_id, height),
            confidential_supply_root: deterministic_root("supply-tree", &asset_id, height),
            range_proof_root: deterministic_root("range-proofs", &asset_id, height),
            opening_policy_root: deterministic_root("opening-policy", &asset_id, height),
            last_updated_height: height,
        };
        supply_commitments.insert(supply.asset_id.clone(), supply);

        let mut wxmr_supply = SupplyCommitment {
            asset_id: wxmr_asset_id.clone(),
            token_kind: BridgeTokenKind::WrappedXmr,
            issuer_id: issuer_id.clone(),
            total_minted_commitment: deterministic_commitment(
                "wxmr-total-minted",
                &wxmr_asset_id,
                height,
            ),
            total_burned_commitment: deterministic_commitment(
                "wxmr-total-burned",
                &wxmr_asset_id,
                height,
            ),
            circulating_supply_commitment: deterministic_commitment(
                "wxmr-circulating",
                &wxmr_asset_id,
                height,
            ),
            reserve_liability_commitment: deterministic_commitment(
                "wxmr-liability",
                &wxmr_asset_id,
                height,
            ),
            confidential_supply_root: deterministic_root(
                "wxmr-supply-tree",
                &wxmr_asset_id,
                height,
            ),
            range_proof_root: deterministic_root("wxmr-range-proofs", &wxmr_asset_id, height),
            opening_policy_root: deterministic_root("wxmr-opening-policy", &wxmr_asset_id, height),
            last_updated_height: height,
        };
        wxmr_supply.last_updated_height = height;
        supply_commitments.insert(wxmr_supply.asset_id.clone(), wxmr_supply);

        let mut allowed_asset_ids = BTreeSet::new();
        allowed_asset_ids.insert(asset_id.clone());
        allowed_asset_ids.insert(wxmr_asset_id.clone());

        let issuer = IssuerConstraint {
            issuer_id: issuer_id.clone(),
            issuer_commitment: deterministic_commitment("issuer", &issuer_id, height),
            status: IssuerStatus::Active,
            allowed_asset_ids,
            mint_cap_commitment: deterministic_commitment("mint-cap", &issuer_id, height),
            burn_limit_commitment: deterministic_commitment("burn-limit", &issuer_id, height),
            reserve_account_root: deterministic_root("reserve-account", &issuer_id, height),
            policy_root: deterministic_root("issuer-policy", &issuer_id, height),
            committee_root: deterministic_root("issuer-committee", &issuer_id, height),
            pq_security_bits: config.min_pq_security_bits,
            active_from_height: height.saturating_sub(24),
            expires_at_height: height + 10_080,
        };
        let mut issuer_constraints = BTreeMap::new();
        issuer_constraints.insert(issuer.issuer_id.clone(), issuer);

        let reserve_proof = BridgeReserveProof {
            proof_id: reserve_proof_id.clone(),
            asset_id: wxmr_asset_id.clone(),
            issuer_id: issuer_id.clone(),
            monero_network: config.monero_network.clone(),
            reserve_view_key_commitment: deterministic_commitment(
                "reserve-view-key",
                &issuer_id,
                height,
            ),
            reserve_output_root: deterministic_root("reserve-outputs", &issuer_id, height),
            liability_commitment_root: deterministic_root(
                "liability-commitments",
                &issuer_id,
                height,
            ),
            reserve_commitment: deterministic_commitment("reserve-total", &issuer_id, height),
            liability_commitment: deterministic_commitment("reserve-liability", &issuer_id, height),
            surplus_commitment: deterministic_commitment("reserve-surplus", &issuer_id, height),
            coverage_bps: config.min_reserve_coverage_bps + 25,
            proof_scheme: config.reserve_proof_scheme.clone(),
            status: ReserveProofStatus::Verified,
            observed_at_height: height,
            expires_at_height: height + config.reserve_proof_ttl_blocks,
        };
        let mut reserve_proofs = BTreeMap::new();
        reserve_proofs.insert(reserve_proof.proof_id.clone(), reserve_proof);

        let batch = MintBurnBatch {
            batch_id: batch_id.clone(),
            batch_kind: BatchKind::NetMintBurn,
            status: BatchStatus::CommitteeApproved,
            issuer_id: issuer_id.clone(),
            asset_id: wxmr_asset_id.clone(),
            reserve_proof_id: reserve_proof_id.clone(),
            input_note_root: deterministic_root("input-notes", &batch_id, height),
            output_note_root: deterministic_root("output-notes", &batch_id, height),
            mint_commitment_root: deterministic_root("mint-commitments", &batch_id, height),
            burn_commitment_root: deterministic_root("burn-commitments", &batch_id, height),
            nullifier_root: deterministic_root("batch-nullifiers", &batch_id, height),
            fee_commitment_root: deterministic_root("fee-commitments", &batch_id, height),
            rebate_commitment_root: deterministic_root("rebate-commitments", &batch_id, height),
            balance_proof_root: deterministic_root("balance-proof", &batch_id, height),
            audit_transcript_root: deterministic_root("audit-transcript", &batch_id, height),
            item_count: 512,
            privacy_set_size: config.min_privacy_set_size + 512,
            proposed_at_height: height,
            expires_at_height: height + config.mint_ttl_blocks,
        };
        let mut mint_burn_batches = BTreeMap::new();
        mint_burn_batches.insert(batch.batch_id.clone(), batch);

        let mut committee_members = BTreeMap::new();
        for index in 0..4_u64 {
            let member_id = deterministic_id("AUDITOR-MEMBER", &format!("devnet-{index}"), height);
            committee_members.insert(
                member_id.clone(),
                AuditorCommitteeMember {
                    member_id: member_id.clone(),
                    operator_commitment: deterministic_commitment("operator", &member_id, height),
                    status: CommitteeMemberStatus::Active,
                    weight: 2 + index,
                    pq_public_key_root: deterministic_root("pq-key", &member_id, height),
                    jurisdiction_commitment: deterministic_commitment(
                        "jurisdiction",
                        &member_id,
                        height,
                    ),
                    active_from_height: height.saturating_sub(12),
                },
            );
        }

        let mut batch_attestations = BTreeMap::new();
        for (index, member_id) in committee_members.keys().enumerate() {
            let attestation_id = deterministic_id(
                "BATCH-ATTESTATION",
                &format!("{batch_id}-{member_id}-{index}"),
                height,
            );
            batch_attestations.insert(
                attestation_id.clone(),
                BatchAttestation {
                    attestation_id,
                    batch_id: batch_id.clone(),
                    member_id: member_id.clone(),
                    attested_root: deterministic_root("attested-batch", &batch_id, height),
                    decision: "approve".to_string(),
                    signature_root: deterministic_root("attestation-signature", member_id, height),
                    attested_at_height: height + 1,
                },
            );
        }

        let nullifier = deterministic_commitment("spent-nullifier", &batch_id, height);
        let mut observed_nullifiers = BTreeMap::new();
        observed_nullifiers.insert(nullifier.clone(), batch_id.clone());

        let rebate_id = deterministic_id("FEE-REBATE", &batch_id, height);
        let mut fee_rebates = BTreeMap::new();
        fee_rebates.insert(
            rebate_id.clone(),
            FeeRebateLedgerEntry {
                rebate_id,
                batch_id: batch_id.clone(),
                claimant_commitment: deterministic_commitment("rebate-claimant", &batch_id, height),
                asset_id: wxmr_asset_id.clone(),
                rebate_asset_id: config.default_rebate_asset_id.clone(),
                fee_commitment: deterministic_commitment("fee", &batch_id, height),
                rebate_commitment: deterministic_commitment("rebate", &batch_id, height),
                eligibility_root: deterministic_root("rebate-eligibility", &batch_id, height),
                nullifier: deterministic_commitment("rebate-nullifier", &batch_id, height),
                status: FeeRebateStatus::Eligible,
                opened_at_height: height,
                expires_at_height: height + config.rebate_ttl_blocks,
            },
        );

        let events = vec![
            json!({
                "event_id": deterministic_id("EVENT", "devnet-reserve-verified", height),
                "kind": "reserve_proof_verified",
                "height": height,
                "reserve_proof_id": reserve_proof_id,
            }),
            json!({
                "event_id": deterministic_id("EVENT", "devnet-batch-approved", height),
                "kind": "mint_burn_batch_committee_approved",
                "height": height + 1,
                "batch_id": batch_id,
            }),
        ];

        let state = State {
            config,
            height,
            supply_commitments,
            issuer_constraints,
            reserve_proofs,
            mint_burn_batches,
            committee_members,
            batch_attestations,
            observed_nullifiers,
            replay_findings: BTreeMap::new(),
            fee_rebates,
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        self.config.validate()?;
        if self.supply_commitments.len() > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_ASSETS {
            return Err("too many supply commitments".to_string());
        }
        if self.issuer_constraints.len() > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_ISSUERS {
            return Err("too many issuer constraints".to_string());
        }
        if self.reserve_proofs.len()
            > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_RESERVE_PROOFS
        {
            return Err("too many reserve proofs".to_string());
        }
        if self.mint_burn_batches.len() > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_BATCHES {
            return Err("too many mint burn batches".to_string());
        }
        if self.observed_nullifiers.len()
            > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_NULLIFIERS
        {
            return Err("too many observed nullifiers".to_string());
        }
        if self.fee_rebates.len() > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_REBATES {
            return Err("too many fee rebates".to_string());
        }
        if self.events.len() > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_EVENTS {
            return Err("too many events".to_string());
        }

        for (asset_id, commitment) in &self.supply_commitments {
            if asset_id != &commitment.asset_id {
                return Err(format!("supply commitment key mismatch for {asset_id}"));
            }
            commitment.validate()?;
            if !self.issuer_constraints.contains_key(&commitment.issuer_id) {
                return Err(format!(
                    "supply commitment {} references missing issuer {}",
                    commitment.asset_id, commitment.issuer_id
                ));
            }
        }

        for (issuer_id, issuer) in &self.issuer_constraints {
            if issuer_id != &issuer.issuer_id {
                return Err(format!("issuer key mismatch for {issuer_id}"));
            }
            issuer.validate(&self.config)?;
        }

        for (proof_id, proof) in &self.reserve_proofs {
            if proof_id != &proof.proof_id {
                return Err(format!("reserve proof key mismatch for {proof_id}"));
            }
            proof.validate(&self.config)?;
            let issuer = self
                .issuer_constraints
                .get(&proof.issuer_id)
                .ok_or_else(|| {
                    format!(
                        "reserve proof {} references missing issuer {}",
                        proof.proof_id, proof.issuer_id
                    )
                })?;
            if !issuer.allowed_asset_ids.contains(&proof.asset_id) {
                return Err(format!(
                    "reserve proof {} asset {} not allowed for issuer",
                    proof.proof_id, proof.asset_id
                ));
            }
        }

        for (batch_id, batch) in &self.mint_burn_batches {
            if batch_id != &batch.batch_id {
                return Err(format!("batch key mismatch for {batch_id}"));
            }
            batch.validate(&self.config)?;
            let issuer = self
                .issuer_constraints
                .get(&batch.issuer_id)
                .ok_or_else(|| {
                    format!(
                        "batch {} references missing issuer {}",
                        batch.batch_id, batch.issuer_id
                    )
                })?;
            if batch.batch_kind.includes_mint() && !issuer.status.can_mint() {
                return Err(format!("batch {} issuer cannot mint", batch.batch_id));
            }
            if batch.batch_kind.includes_burn() && !issuer.status.can_burn() {
                return Err(format!("batch {} issuer cannot burn", batch.batch_id));
            }
            if !issuer.allowed_asset_ids.contains(&batch.asset_id) {
                return Err(format!(
                    "batch {} asset not allowed for issuer",
                    batch.batch_id
                ));
            }
            let reserve_proof = self
                .reserve_proofs
                .get(&batch.reserve_proof_id)
                .ok_or_else(|| {
                    format!(
                        "batch {} references missing reserve proof {}",
                        batch.batch_id, batch.reserve_proof_id
                    )
                })?;
            if !reserve_proof.status.usable() {
                return Err(format!(
                    "batch {} reserve proof is not usable",
                    batch.batch_id
                ));
            }
            if reserve_proof.expires_at_height < batch.proposed_at_height {
                return Err(format!(
                    "batch {} reserve proof expired first",
                    batch.batch_id
                ));
            }
        }

        let mut active_committee_weight = 0_u64;
        for (member_id, member) in &self.committee_members {
            if member_id != &member.member_id {
                return Err(format!("committee member key mismatch for {member_id}"));
            }
            member.validate()?;
            if member.status.counts() {
                active_committee_weight = active_committee_weight.saturating_add(member.weight);
            }
        }
        if active_committee_weight < self.config.min_committee_weight {
            return Err("active auditor committee weight below minimum".to_string());
        }

        let mut attested_weight_by_batch: BTreeMap<String, u64> = BTreeMap::new();
        let mut seen_member_batch = BTreeSet::new();
        for (attestation_id, attestation) in &self.batch_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err(format!("attestation key mismatch for {attestation_id}"));
            }
            attestation.validate()?;
            if !self.mint_burn_batches.contains_key(&attestation.batch_id) {
                return Err(format!(
                    "attestation {} references missing batch {}",
                    attestation.attestation_id, attestation.batch_id
                ));
            }
            let member = self
                .committee_members
                .get(&attestation.member_id)
                .ok_or_else(|| {
                    format!(
                        "attestation {} references missing member {}",
                        attestation.attestation_id, attestation.member_id
                    )
                })?;
            let member_batch_key = format!("{}:{}", attestation.batch_id, attestation.member_id);
            if !seen_member_batch.insert(member_batch_key) {
                return Err(format!(
                    "duplicate member attestation for batch {}",
                    attestation.batch_id
                ));
            }
            if member.status.counts() && attestation.decision == "approve" {
                let entry = attested_weight_by_batch
                    .entry(attestation.batch_id.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(member.weight);
            }
        }

        for batch in self.mint_burn_batches.values() {
            if matches!(
                batch.status,
                BatchStatus::CommitteeApproved | BatchStatus::Applied
            ) {
                let weight = match attested_weight_by_batch.get(&batch.batch_id) {
                    Some(weight) => *weight,
                    None => 0,
                };
                if weight < self.config.min_committee_weight {
                    return Err(format!(
                        "batch {} lacks committee approval weight",
                        batch.batch_id
                    ));
                }
            }
        }

        let mut nullifier_to_batch = BTreeMap::new();
        for (nullifier, batch_id) in &self.observed_nullifiers {
            require_hash_like("observed nullifier", nullifier)?;
            require_id("observed nullifier batch_id", batch_id)?;
            if !self.mint_burn_batches.contains_key(batch_id) {
                return Err(format!(
                    "observed nullifier references missing batch {batch_id}"
                ));
            }
            nullifier_to_batch.insert(nullifier.clone(), batch_id.clone());
        }

        for (finding_id, finding) in &self.replay_findings {
            if finding_id != &finding.finding_id {
                return Err(format!("replay finding key mismatch for {finding_id}"));
            }
            finding.validate()?;
            let first = nullifier_to_batch.get(&finding.nullifier).ok_or_else(|| {
                format!(
                    "replay finding {} nullifier was not observed",
                    finding.finding_id
                )
            })?;
            if first != &finding.first_batch_id && first != &finding.repeated_batch_id {
                return Err(format!(
                    "replay finding {} does not match observed nullifier batch",
                    finding.finding_id
                ));
            }
        }

        for (rebate_id, rebate) in &self.fee_rebates {
            if rebate_id != &rebate.rebate_id {
                return Err(format!("rebate key mismatch for {rebate_id}"));
            }
            rebate.validate()?;
            if !self.mint_burn_batches.contains_key(&rebate.batch_id) {
                return Err(format!(
                    "rebate {} references missing batch {}",
                    rebate.rebate_id, rebate.batch_id
                ));
            }
        }

        for event in &self.events {
            require_event(event)?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        if height < self.height {
            return Err(format!(
                "height regression from {} to {}",
                self.height, height
            ));
        }
        self.height = height;
        self.mark_stale_records();
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            supply_commitment_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-SUPPLY-COMMITMENTS",
                self.supply_commitments
                    .values()
                    .map(SupplyCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            issuer_constraint_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-ISSUER-CONSTRAINTS",
                self.issuer_constraints
                    .values()
                    .map(IssuerConstraint::public_record)
                    .collect::<Vec<_>>(),
            ),
            reserve_proof_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-RESERVE-PROOFS",
                self.reserve_proofs
                    .values()
                    .map(BridgeReserveProof::public_record)
                    .collect::<Vec<_>>(),
            ),
            mint_burn_batch_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-MINT-BURN-BATCHES",
                self.mint_burn_batches
                    .values()
                    .map(MintBurnBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            committee_member_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-COMMITTEE-MEMBERS",
                self.committee_members
                    .values()
                    .map(AuditorCommitteeMember::public_record)
                    .collect::<Vec<_>>(),
            ),
            batch_attestation_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-BATCH-ATTESTATIONS",
                self.batch_attestations
                    .values()
                    .map(BatchAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-OBSERVED-NULLIFIERS",
                self.observed_nullifiers
                    .iter()
                    .map(|(nullifier, batch_id)| {
                        json!({
                            "nullifier": nullifier,
                            "batch_id": batch_id,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            replay_finding_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-REPLAY-FINDINGS",
                self.replay_findings
                    .values()
                    .map(NullifierReplayFinding::public_record)
                    .collect::<Vec<_>>(),
            ),
            fee_rebate_root: root_from_values(
                "CONFIDENTIAL-TOKEN-BRIDGE-FEE-REBATES",
                self.fee_rebates
                    .values()
                    .map(FeeRebateLedgerEntry::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_root: root_from_values("CONFIDENTIAL-TOKEN-BRIDGE-EVENTS", self.events.clone()),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            supply_commitments: self.supply_commitments.len(),
            issuer_constraints: self.issuer_constraints.len(),
            reserve_proofs: self.reserve_proofs.len(),
            mint_burn_batches: self.mint_burn_batches.len(),
            committee_members: self.committee_members.len(),
            batch_attestations: self.batch_attestations.len(),
            observed_nullifiers: self.observed_nullifiers.len(),
            replay_findings: self.replay_findings.len(),
            fee_rebates: self.fee_rebates.len(),
            events: self.events.len(),
            active_issuers: self
                .issuer_constraints
                .values()
                .filter(|issuer| issuer.status.can_mint() || issuer.status.can_burn())
                .count(),
            applied_batches: self
                .mint_burn_batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Applied)
                .count(),
            challenged_batches: self
                .mint_burn_batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Challenged)
                .count(),
            confirmed_replays: self
                .replay_findings
                .values()
                .filter(|finding| finding.status == ReplayFindingStatus::ConfirmedReplay)
                .count(),
            settled_rebates: self
                .fee_rebates
                .values()
                .filter(|rebate| rebate.status == FeeRebateStatus::Settled)
                .count(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "supply_commitments": self.supply_commitments.values().map(SupplyCommitment::public_record).collect::<Vec<_>>(),
            "issuer_constraints": self.issuer_constraints.values().map(IssuerConstraint::public_record).collect::<Vec<_>>(),
            "reserve_proofs": self.reserve_proofs.values().map(BridgeReserveProof::public_record).collect::<Vec<_>>(),
            "mint_burn_batches": self.mint_burn_batches.values().map(MintBurnBatch::public_record).collect::<Vec<_>>(),
            "committee_members": self.committee_members.values().map(AuditorCommitteeMember::public_record).collect::<Vec<_>>(),
            "batch_attestations": self.batch_attestations.values().map(BatchAttestation::public_record).collect::<Vec<_>>(),
            "observed_nullifiers": self.observed_nullifiers.iter().map(|(nullifier, batch_id)| json!({"nullifier": nullifier, "batch_id": batch_id})).collect::<Vec<_>>(),
            "replay_findings": self.replay_findings.values().map(NullifierReplayFinding::public_record).collect::<Vec<_>>(),
            "fee_rebates": self.fee_rebates.values().map(FeeRebateLedgerEntry::public_record).collect::<Vec<_>>(),
            "events": self.events,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let record = json!({
            "protocol_version": CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        });
        root_from_record(&record)
    }

    fn mark_stale_records(&mut self) {
        for proof in self.reserve_proofs.values_mut() {
            if proof.status.usable() && proof.expires_at_height < self.height {
                proof.status = ReserveProofStatus::Stale;
            }
        }
        for batch in self.mint_burn_batches.values_mut() {
            if !batch.status.is_final() && batch.expires_at_height < self.height {
                batch.status = BatchStatus::Expired;
            }
        }
        for rebate in self.fee_rebates.values_mut() {
            if matches!(
                rebate.status,
                FeeRebateStatus::Accruing | FeeRebateStatus::Eligible
            ) && rebate.expires_at_height < self.height
            {
                rebate.status = FeeRebateStatus::Expired;
            }
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-BRIDGE-MINT-BURN-AUDITOR-RECORD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> ConfidentialTokenBridgeMintBurnAuditorResult<State> {
    State::devnet()
}

pub fn supply_commitment_id(commitment: &SupplyCommitment) -> String {
    commitment.commitment_id()
}

pub fn issuer_constraint_id(constraint: &IssuerConstraint) -> String {
    constraint.constraint_id()
}

pub fn mint_burn_batch_id(
    issuer_id: &str,
    asset_id: &str,
    batch_kind: BatchKind,
    nullifier_root: &str,
    proposed_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-BRIDGE-MINT-BURN-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(issuer_id),
            HashPart::Str(asset_id),
            HashPart::Str(batch_kind.as_str()),
            HashPart::Str(nullifier_root),
            HashPart::Int(proposed_at_height as i128),
        ],
        32,
    )
}

pub fn reserve_proof_id(
    issuer_id: &str,
    asset_id: &str,
    reserve_output_root: &str,
    liability_commitment_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-BRIDGE-RESERVE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(issuer_id),
            HashPart::Str(asset_id),
            HashPart::Str(reserve_output_root),
            HashPart::Str(liability_commitment_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn replay_finding_id(nullifier: &str, first_batch_id: &str, repeated_batch_id: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-BRIDGE-NULLIFIER-REPLAY-FINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier),
            HashPart::Str(first_batch_id),
            HashPart::Str(repeated_batch_id),
        ],
        32,
    )
}

pub fn fee_rebate_id(batch_id: &str, claimant_commitment: &str, nullifier: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-BRIDGE-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(claimant_commitment),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

fn root_from_values(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn deterministic_id(domain: &str, label: &str, height: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn deterministic_root(domain: &str, label: &str, height: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Str("root"),
        ],
        32,
    )
}

fn deterministic_commitment(domain: &str, label: &str, height: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Str("commitment"),
        ],
        32,
    )
}

fn require_non_empty(field: &str, value: &str) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_id(field: &str, value: &str) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must be a deterministic id"));
    }
    Ok(())
}

fn require_hash_like(field: &str, value: &str) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 32 {
        return Err(format!("{field} must be hash-like"));
    }
    if !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(format!("{field} must be hex encoded"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
    if value > CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_MAX_BPS + 1_000 {
        Err(format!(
            "{field} exceeds supported reserve coverage bps range"
        ))
    } else {
        Ok(())
    }
}

fn require_event(event: &Value) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
    let object = event
        .as_object()
        .ok_or_else(|| "event must be a JSON object".to_string())?;
    let event_id = object
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "event_id must be present".to_string())?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "event kind must be present".to_string())?;
    let height = object
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| "event height must be present".to_string())?;
    require_id("event_id", event_id)?;
    require_non_empty("event kind", kind)?;
    if height == 0 {
        return Err("event height must be non-zero".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_roots_are_deterministic(
    ) -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        let state = State::devnet()?;
        let root = state.state_root();
        assert_eq!(root, state.state_root());
        assert_eq!(
            root,
            root_from_record(&json!({
                "protocol_version": CONFIDENTIAL_TOKEN_BRIDGE_MINT_BURN_AUDITOR_PROTOCOL_VERSION,
                "chain_id": CHAIN_ID,
                "height": state.height,
                "config": state.config.public_record(),
                "roots": state.roots().public_record(),
                "counters": state.counters().public_record(),
            }))
        );
        Ok(())
    }

    #[test]
    fn height_updates_mark_stale_records() -> ConfidentialTokenBridgeMintBurnAuditorResult<()> {
        let mut state = State::devnet()?;
        let next_height = state.height + state.config.reserve_proof_ttl_blocks + 1;
        state.update_height(next_height)?;
        assert!(state
            .reserve_proofs
            .values()
            .any(|proof| proof.status == ReserveProofStatus::Stale));
        Ok(())
    }
}
