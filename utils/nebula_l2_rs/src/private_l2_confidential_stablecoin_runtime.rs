use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialStablecoinRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-stablecoin-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-stablecoin-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_RESERVE_SCHEME: &str =
    "private-l2-confidential-stablecoin-reserve-proof-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_NOTE_SCHEME: &str =
    "private-l2-confidential-stablecoin-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_FEE_BUCKET_SCHEME: &str =
    "private-l2-confidential-stability-fee-bucket-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_SPONSOR_RECEIPT_SCHEME: &str =
    "roots-only-low-fee-sponsor-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_BATCH_SCHEME: &str =
    "private-l2-confidential-stablecoin-batched-settlement-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEVNET_HEIGHT: u64 = 196_000;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_STABLE_ASSET_ID: &str =
    "asset:private-dusd";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_RESERVE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_MINTS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_REDEEMS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_RESERVE_ATTESTATIONS: usize =
    131_072;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_FEE_BUCKETS: usize = 256;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 32_768;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_STABILITY_FEE_BPS: u64 = 250;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 20;
pub const PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StablecoinFlowKind {
    PrivateMint,
    PrivateRedeem,
}

impl StablecoinFlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateMint => "private_mint",
            Self::PrivateRedeem => "private_redeem",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    Pending,
    ReserveAttested,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl FlowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ReserveAttested => "reserve_attested",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Pending | Self::ReserveAttested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveVerdict {
    Covered,
    Overcollateralized,
    Watch,
    Undercovered,
    Rejected,
}

impl ReserveVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Overcollateralized => "overcollateralized",
            Self::Watch => "watch",
            Self::Undercovered => "undercovered",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_settlement(self) -> bool {
        matches!(self, Self::Covered | Self::Overcollateralized | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBucketKind {
    Mint,
    Redeem,
    DefiComposability,
    EmergencyLiquidity,
    SponsorRebate,
}

impl FeeBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Redeem => "redeem",
            Self::DefiComposability => "defi_composability",
            Self::EmergencyLiquidity => "emergency_liquidity",
            Self::SponsorRebate => "sponsor_rebate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub stable_asset_id: String,
    pub reserve_asset_id: String,
    pub hash_suite: String,
    pub pq_authorization_scheme: String,
    pub reserve_scheme: String,
    pub note_scheme: String,
    pub fee_bucket_scheme: String,
    pub sponsor_receipt_scheme: String,
    pub batch_scheme: String,
    pub max_mints: usize,
    pub max_redeems: usize,
    pub max_reserve_attestations: usize,
    pub max_batch_items: usize,
    pub max_fee_buckets: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_stability_fee_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_defi_hook_root: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_L2_NETWORK.to_string(),
            stable_asset_id: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_STABLE_ASSET_ID
                .to_string(),
            reserve_asset_id: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_RESERVE_ASSET_ID
                .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_scheme: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_PQ_AUTH_SCHEME
                .to_string(),
            reserve_scheme: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_RESERVE_SCHEME.to_string(),
            note_scheme: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_NOTE_SCHEME.to_string(),
            fee_bucket_scheme: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_FEE_BUCKET_SCHEME
                .to_string(),
            sponsor_receipt_scheme:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_SPONSOR_RECEIPT_SCHEME.to_string(),
            batch_scheme: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_BATCH_SCHEME.to_string(),
            max_mints: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_MINTS,
            max_redeems: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_REDEEMS,
            max_reserve_attestations:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_RESERVE_ATTESTATIONS,
            max_batch_items: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_fee_buckets: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_FEE_BUCKETS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_stability_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MAX_STABILITY_FEE_BPS,
            min_reserve_coverage_bps:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_defi_hook_root: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("chain id", &self.chain_id)?;
        require_non_empty("monero network", &self.monero_network)?;
        require_non_empty("l2 network", &self.l2_network)?;
        require_non_empty("stable asset id", &self.stable_asset_id)?;
        require_non_empty("reserve asset id", &self.reserve_asset_id)?;
        require_non_empty("hash suite", &self.hash_suite)?;
        require_non_empty("PQ authorization scheme", &self.pq_authorization_scheme)?;
        require_non_empty("reserve scheme", &self.reserve_scheme)?;
        require_non_empty("note scheme", &self.note_scheme)?;
        require_non_empty("fee bucket scheme", &self.fee_bucket_scheme)?;
        require_non_empty("sponsor receipt scheme", &self.sponsor_receipt_scheme)?;
        require_non_empty("batch scheme", &self.batch_scheme)?;
        if self.stable_asset_id == self.reserve_asset_id {
            return Err("stable and reserve assets must differ".to_string());
        }
        if self.max_mints == 0
            || self.max_redeems == 0
            || self.max_reserve_attestations == 0
            || self.max_batch_items == 0
            || self.max_fee_buckets == 0
            || self.settlement_ttl_blocks == 0
        {
            return Err("confidential stablecoin capacities must be positive".to_string());
        }
        if self.min_batch_privacy_set_size < self.min_privacy_set_size {
            return Err(
                "batch privacy set must cover individual stablecoin privacy set".to_string(),
            );
        }
        if self.min_pq_security_bits < 192 {
            return Err("stablecoin PQ authorization security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_MAX_BPS
            || self.max_stability_fee_bps > PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_MAX_BPS
        {
            return Err("stablecoin fee bps exceeds range".to_string());
        }
        if self.min_reserve_coverage_bps < PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_MAX_BPS {
            return Err("reserve coverage must be at least full backing".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "stable_asset_id": self.stable_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "hash_suite": self.hash_suite,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "reserve_scheme": self.reserve_scheme,
            "note_scheme": self.note_scheme,
            "fee_bucket_scheme": self.fee_bucket_scheme,
            "sponsor_receipt_scheme": self.sponsor_receipt_scheme,
            "batch_scheme": self.batch_scheme,
            "max_mints": self.max_mints,
            "max_redeems": self.max_redeems,
            "max_reserve_attestations": self.max_reserve_attestations,
            "max_batch_items": self.max_batch_items,
            "max_fee_buckets": self.max_fee_buckets,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_stability_fee_bps": self.max_stability_fee_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_defi_hook_root": self.require_defi_hook_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub mint_counter: u64,
    pub redeem_counter: u64,
    pub reserve_attestation_counter: u64,
    pub fee_bucket_counter: u64,
    pub sponsor_receipt_counter: u64,
    pub batch_counter: u64,
    pub settlement_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "mint_counter": self.mint_counter,
            "redeem_counter": self.redeem_counter,
            "reserve_attestation_counter": self.reserve_attestation_counter,
            "fee_bucket_counter": self.fee_bucket_counter,
            "sponsor_receipt_counter": self.sponsor_receipt_counter,
            "batch_counter": self.batch_counter,
            "settlement_counter": self.settlement_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMintRequest {
    pub minter_commitment: String,
    pub reserve_lock_root: String,
    pub stable_note_root: String,
    pub amount_commitment_root: String,
    pub reserve_proof_root: String,
    pub stability_fee_bucket_id: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub sponsor_receipt_root: String,
    pub defi_hook_root: String,
    pub mint_nullifier: String,
    pub reserve_coverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateMintRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        require_non_empty("minter commitment", &self.minter_commitment)?;
        require_non_empty("reserve lock root", &self.reserve_lock_root)?;
        require_non_empty("stable note root", &self.stable_note_root)?;
        require_non_empty("amount commitment root", &self.amount_commitment_root)?;
        require_non_empty("reserve proof root", &self.reserve_proof_root)?;
        require_non_empty("stability fee bucket id", &self.stability_fee_bucket_id)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("mint nullifier", &self.mint_nullifier)?;
        if config.require_low_fee_sponsor {
            require_non_empty("sponsor receipt root", &self.sponsor_receipt_root)?;
        }
        if config.require_defi_hook_root {
            require_non_empty("DeFi hook root", &self.defi_hook_root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.reserve_coverage_bps < config.min_reserve_coverage_bps {
            return Err("mint reserve coverage below configured minimum".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("mint fee exceeds configured maximum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("mint expiry must be after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "minter_commitment": self.minter_commitment,
            "reserve_lock_root": self.reserve_lock_root,
            "stable_note_root": self.stable_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "reserve_proof_root": self.reserve_proof_root,
            "stability_fee_bucket_id": self.stability_fee_bucket_id,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "defi_hook_root": self.defi_hook_root,
            "mint_nullifier": self.mint_nullifier,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRedeemRequest {
    pub redeemer_commitment: String,
    pub stable_burn_root: String,
    pub reserve_release_root: String,
    pub amount_commitment_root: String,
    pub reserve_proof_root: String,
    pub stability_fee_bucket_id: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub sponsor_receipt_root: String,
    pub defi_hook_root: String,
    pub redeem_nullifier: String,
    pub reserve_coverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateRedeemRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        require_non_empty("redeemer commitment", &self.redeemer_commitment)?;
        require_non_empty("stable burn root", &self.stable_burn_root)?;
        require_non_empty("reserve release root", &self.reserve_release_root)?;
        require_non_empty("amount commitment root", &self.amount_commitment_root)?;
        require_non_empty("reserve proof root", &self.reserve_proof_root)?;
        require_non_empty("stability fee bucket id", &self.stability_fee_bucket_id)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("redeem nullifier", &self.redeem_nullifier)?;
        if config.require_low_fee_sponsor {
            require_non_empty("sponsor receipt root", &self.sponsor_receipt_root)?;
        }
        if config.require_defi_hook_root {
            require_non_empty("DeFi hook root", &self.defi_hook_root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.reserve_coverage_bps < config.min_reserve_coverage_bps {
            return Err("redeem reserve coverage below configured minimum".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("redeem fee exceeds configured maximum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("redeem expiry must be after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redeemer_commitment": self.redeemer_commitment,
            "stable_burn_root": self.stable_burn_root,
            "reserve_release_root": self.reserve_release_root,
            "amount_commitment_root": self.amount_commitment_root,
            "reserve_proof_root": self.reserve_proof_root,
            "stability_fee_bucket_id": self.stability_fee_bucket_id,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "defi_hook_root": self.defi_hook_root,
            "redeem_nullifier": self.redeem_nullifier,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestationRequest {
    pub flow_kind: StablecoinFlowKind,
    pub flow_id: String,
    pub attestor_commitment: String,
    pub reserve_asset_root: String,
    pub liability_commitment_root: String,
    pub oracle_price_root: String,
    pub coverage_proof_root: String,
    pub pq_attestation_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub verdict: ReserveVerdict,
    pub reserve_coverage_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl ReserveAttestationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        require_non_empty("flow id", &self.flow_id)?;
        require_non_empty("attestor commitment", &self.attestor_commitment)?;
        require_non_empty("reserve asset root", &self.reserve_asset_root)?;
        require_non_empty("liability commitment root", &self.liability_commitment_root)?;
        require_non_empty("oracle price root", &self.oracle_price_root)?;
        require_non_empty("coverage proof root", &self.coverage_proof_root)?;
        require_non_empty("PQ attestation root", &self.pq_attestation_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("attestation nullifier", &self.attestation_nullifier)?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.verdict.allows_settlement()
            && self.reserve_coverage_bps < config.min_reserve_coverage_bps
        {
            return Err("covered reserve attestation is below configured minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "flow_kind": self.flow_kind.as_str(),
            "flow_id": self.flow_id,
            "attestor_commitment": self.attestor_commitment,
            "reserve_asset_root": self.reserve_asset_root,
            "liability_commitment_root": self.liability_commitment_root,
            "oracle_price_root": self.oracle_price_root,
            "coverage_proof_root": self.coverage_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "verdict": self.verdict.as_str(),
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFeeBucketRequest {
    pub bucket_kind: FeeBucketKind,
    pub bucket_owner_commitment: String,
    pub fee_policy_root: String,
    pub rate_commitment_root: String,
    pub reserve_sink_root: String,
    pub sponsor_rebate_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub max_stability_fee_bps: u64,
    pub opened_at_height: u64,
}

impl OpenFeeBucketRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        require_non_empty("bucket owner commitment", &self.bucket_owner_commitment)?;
        require_non_empty("fee policy root", &self.fee_policy_root)?;
        require_non_empty("rate commitment root", &self.rate_commitment_root)?;
        require_non_empty("reserve sink root", &self.reserve_sink_root)?;
        require_non_empty("PQ authority root", &self.pq_authority_root)?;
        require_non_empty("privacy policy root", &self.privacy_policy_root)?;
        if self.max_stability_fee_bps > config.max_stability_fee_bps {
            return Err("fee bucket exceeds configured stability fee maximum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_kind": self.bucket_kind.as_str(),
            "bucket_owner_commitment": self.bucket_owner_commitment,
            "fee_policy_root": self.fee_policy_root,
            "rate_commitment_root": self.rate_commitment_root,
            "reserve_sink_root": self.reserve_sink_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "max_stability_fee_bps": self.max_stability_fee_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSponsorReceiptRequest {
    pub sponsor_commitment: String,
    pub flow_kind: StablecoinFlowKind,
    pub flow_id: String,
    pub fee_quote_root: String,
    pub rebate_commitment_root: String,
    pub sponsor_vault_root: String,
    pub pq_receipt_root: String,
    pub max_fee_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PublishSponsorReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty("flow id", &self.flow_id)?;
        require_non_empty("fee quote root", &self.fee_quote_root)?;
        require_non_empty("rebate commitment root", &self.rebate_commitment_root)?;
        require_non_empty("sponsor vault root", &self.sponsor_vault_root)?;
        require_non_empty("PQ receipt root", &self.pq_receipt_root)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("sponsor receipt fee exceeds configured maximum".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("sponsor receipt expiry must be after issue height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_commitment": self.sponsor_commitment,
            "flow_kind": self.flow_kind.as_str(),
            "flow_id": self.flow_id,
            "fee_quote_root": self.fee_quote_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "sponsor_vault_root": self.sponsor_vault_root,
            "pq_receipt_root": self.pq_receipt_root,
            "max_fee_bps": self.max_fee_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSettlementBatchRequest {
    pub mint_ids: Vec<String>,
    pub redeem_ids: Vec<String>,
    pub builder_commitment: String,
    pub reserve_delta_root: String,
    pub stable_supply_delta_root: String,
    pub fee_bucket_delta_root: String,
    pub defi_composability_root: String,
    pub recursive_proof_root: String,
    pub sponsor_receipt_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildSettlementBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        if self.mint_ids.is_empty() && self.redeem_ids.is_empty() {
            return Err("stablecoin batch requires at least one flow".to_string());
        }
        if self.mint_ids.len().saturating_add(self.redeem_ids.len()) > config.max_batch_items {
            return Err("stablecoin batch exceeds configured item limit".to_string());
        }
        require_non_empty("builder commitment", &self.builder_commitment)?;
        require_non_empty("reserve delta root", &self.reserve_delta_root)?;
        require_non_empty("stable supply delta root", &self.stable_supply_delta_root)?;
        require_non_empty("fee bucket delta root", &self.fee_bucket_delta_root)?;
        require_non_empty("recursive proof root", &self.recursive_proof_root)?;
        require_non_empty(
            "PQ batch authorization root",
            &self.pq_batch_authorization_root,
        )?;
        if config.require_low_fee_sponsor {
            require_non_empty("sponsor receipt root", &self.sponsor_receipt_root)?;
        }
        if config.require_defi_hook_root {
            require_non_empty("DeFi composability root", &self.defi_composability_root)?;
        }
        if self.privacy_set_size < config.min_batch_privacy_set_size {
            return Err("stablecoin batch privacy set below configured minimum".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("stablecoin batch fee exceeds configured maximum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mint_ids": self.mint_ids,
            "redeem_ids": self.redeem_ids,
            "builder_commitment": self.builder_commitment,
            "reserve_delta_root": self.reserve_delta_root,
            "stable_supply_delta_root": self.stable_supply_delta_root,
            "fee_bucket_delta_root": self.fee_bucket_delta_root,
            "defi_composability_root": self.defi_composability_root,
            "recursive_proof_root": self.recursive_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub reserve_root_after: String,
    pub stable_note_root_after: String,
    pub fee_bucket_root_after: String,
    pub account_delta_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub sponsor_settlement_root: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_non_empty("settlement tx root", &self.settlement_tx_root)?;
        require_non_empty("settlement proof root", &self.settlement_proof_root)?;
        require_non_empty("reserve root after", &self.reserve_root_after)?;
        require_non_empty("stable note root after", &self.stable_note_root_after)?;
        require_non_empty("fee bucket root after", &self.fee_bucket_root_after)?;
        require_non_empty("account delta root", &self.account_delta_root)?;
        require_non_empty("nullifier root", &self.nullifier_root)?;
        require_non_empty("output note root", &self.output_note_root)?;
        require_non_empty("PQ settlement root", &self.pq_settlement_root)?;
        if config.require_low_fee_sponsor {
            require_non_empty("sponsor settlement root", &self.sponsor_settlement_root)?;
        }
        if self.settled_fee_bps > config.max_user_fee_bps {
            return Err("settled stablecoin fee exceeds configured maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StablecoinFlowRecord {
    pub flow_id: String,
    pub flow_kind: StablecoinFlowKind,
    pub owner_commitment: String,
    pub input_root: String,
    pub output_root: String,
    pub amount_commitment_root: String,
    pub reserve_proof_root: String,
    pub stability_fee_bucket_id: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub sponsor_receipt_root: String,
    pub defi_hook_root: String,
    pub nullifier: String,
    pub reserve_coverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: FlowStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl StablecoinFlowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "flow_id": self.flow_id,
            "flow_kind": self.flow_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "amount_commitment_root": self.amount_commitment_root,
            "reserve_proof_root": self.reserve_proof_root,
            "stability_fee_bucket_id": self.stability_fee_bucket_id,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "defi_hook_root": self.defi_hook_root,
            "nullifier": self.nullifier,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestationRecord {
    pub attestation_id: String,
    pub flow_kind: StablecoinFlowKind,
    pub flow_id: String,
    pub attestor_commitment: String,
    pub reserve_asset_root: String,
    pub liability_commitment_root: String,
    pub oracle_price_root: String,
    pub coverage_proof_root: String,
    pub pq_attestation_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub verdict: ReserveVerdict,
    pub reserve_coverage_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl ReserveAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "flow_kind": self.flow_kind.as_str(),
            "flow_id": self.flow_id,
            "attestor_commitment": self.attestor_commitment,
            "reserve_asset_root": self.reserve_asset_root,
            "liability_commitment_root": self.liability_commitment_root,
            "oracle_price_root": self.oracle_price_root,
            "coverage_proof_root": self.coverage_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "verdict": self.verdict.as_str(),
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabilityFeeBucket {
    pub bucket_id: String,
    pub bucket_kind: FeeBucketKind,
    pub bucket_owner_commitment: String,
    pub fee_policy_root: String,
    pub rate_commitment_root: String,
    pub reserve_sink_root: String,
    pub sponsor_rebate_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub max_stability_fee_bps: u64,
    pub opened_at_height: u64,
    pub flow_ids: Vec<String>,
}

impl StabilityFeeBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "bucket_owner_commitment": self.bucket_owner_commitment,
            "fee_policy_root": self.fee_policy_root,
            "rate_commitment_root": self.rate_commitment_root,
            "reserve_sink_root": self.reserve_sink_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "max_stability_fee_bps": self.max_stability_fee_bps,
            "opened_at_height": self.opened_at_height,
            "flow_ids": self.flow_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReceipt {
    pub receipt_id: String,
    pub sponsor_commitment: String,
    pub flow_kind: StablecoinFlowKind,
    pub flow_id: String,
    pub fee_quote_root: String,
    pub rebate_commitment_root: String,
    pub sponsor_vault_root: String,
    pub pq_receipt_root: String,
    pub max_fee_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "flow_kind": self.flow_kind.as_str(),
            "flow_id": self.flow_id,
            "fee_quote_root": self.fee_quote_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "sponsor_vault_root": self.sponsor_vault_root,
            "pq_receipt_root": self.pq_receipt_root,
            "max_fee_bps": self.max_fee_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub mint_ids: Vec<String>,
    pub redeem_ids: Vec<String>,
    pub builder_commitment: String,
    pub reserve_delta_root: String,
    pub stable_supply_delta_root: String,
    pub fee_bucket_delta_root: String,
    pub defi_composability_root: String,
    pub recursive_proof_root: String,
    pub sponsor_receipt_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub status: BatchStatus,
    pub built_at_height: u64,
    pub settlement_deadline_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "mint_ids": self.mint_ids,
            "redeem_ids": self.redeem_ids,
            "builder_commitment": self.builder_commitment,
            "reserve_delta_root": self.reserve_delta_root,
            "stable_supply_delta_root": self.stable_supply_delta_root,
            "fee_bucket_delta_root": self.fee_bucket_delta_root,
            "defi_composability_root": self.defi_composability_root,
            "recursive_proof_root": self.recursive_proof_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub reserve_root_after: String,
    pub stable_note_root_after: String,
    pub fee_bucket_root_after: String,
    pub account_delta_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub sponsor_settlement_root: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "reserve_root_after": self.reserve_root_after,
            "stable_note_root_after": self.stable_note_root_after,
            "fee_bucket_root_after": self.fee_bucket_root_after,
            "account_delta_root": self.account_delta_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub mint_root: String,
    pub redeem_root: String,
    pub reserve_attestation_root: String,
    pub fee_bucket_root: String,
    pub sponsor_receipt_root: String,
    pub batch_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "mint_root": self.mint_root,
            "redeem_root": self.redeem_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "fee_bucket_root": self.fee_bucket_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "batch_root": self.batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub mints: BTreeMap<String, StablecoinFlowRecord>,
    pub redeems: BTreeMap<String, StablecoinFlowRecord>,
    pub reserve_attestations: BTreeMap<String, ReserveAttestationRecord>,
    pub fee_buckets: BTreeMap<String, StabilityFeeBucket>,
    pub sponsor_receipts: BTreeMap<String, SponsorReceipt>,
    pub batches: BTreeMap<String, SettlementBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_DEVNET_HEIGHT,
            mints: BTreeMap::new(),
            redeems: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            fee_buckets: BTreeMap::new(),
            sponsor_receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn new(
        config: Config,
        current_height: u64,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height,
            mints: BTreeMap::new(),
            redeems: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            fee_buckets: BTreeMap::new(),
            sponsor_receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_fee_bucket(
        &mut self,
        request: OpenFeeBucketRequest,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<StabilityFeeBucket> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.fee_buckets.len() >= self.config.max_fee_buckets {
            return Err("stablecoin fee bucket capacity exhausted".to_string());
        }
        self.counters.fee_bucket_counter = self.counters.fee_bucket_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let bucket_id = fee_bucket_id(&request, self.counters.fee_bucket_counter);
        let bucket = StabilityFeeBucket {
            bucket_id: bucket_id.clone(),
            bucket_kind: request.bucket_kind,
            bucket_owner_commitment: request.bucket_owner_commitment,
            fee_policy_root: request.fee_policy_root,
            rate_commitment_root: request.rate_commitment_root,
            reserve_sink_root: request.reserve_sink_root,
            sponsor_rebate_root: request.sponsor_rebate_root,
            pq_authority_root: request.pq_authority_root,
            privacy_policy_root: request.privacy_policy_root,
            max_stability_fee_bps: request.max_stability_fee_bps,
            opened_at_height: request.opened_at_height,
            flow_ids: Vec::new(),
        };
        self.fee_buckets.insert(bucket_id, bucket.clone());
        Ok(bucket)
    }

    pub fn private_mint(
        &mut self,
        request: PrivateMintRequest,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<StablecoinFlowRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.mints.len() >= self.config.max_mints {
            return Err("private mint capacity exhausted".to_string());
        }
        self.ensure_fee_bucket(&request.stability_fee_bucket_id, request.max_fee_bps)?;
        self.consume_nullifier(&request.mint_nullifier)?;
        self.counters.mint_counter = self.counters.mint_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let flow_id = private_mint_id(&request, self.counters.mint_counter);
        let record = StablecoinFlowRecord {
            flow_id: flow_id.clone(),
            flow_kind: StablecoinFlowKind::PrivateMint,
            owner_commitment: request.minter_commitment,
            input_root: request.reserve_lock_root,
            output_root: request.stable_note_root,
            amount_commitment_root: request.amount_commitment_root,
            reserve_proof_root: request.reserve_proof_root,
            stability_fee_bucket_id: request.stability_fee_bucket_id,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            defi_hook_root: request.defi_hook_root,
            nullifier: request.mint_nullifier,
            reserve_coverage_bps: request.reserve_coverage_bps,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: FlowStatus::Pending,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(bucket) = self.fee_buckets.get_mut(&record.stability_fee_bucket_id) {
            bucket.flow_ids.push(flow_id.clone());
        }
        self.mints.insert(flow_id, record.clone());
        Ok(record)
    }

    pub fn private_redeem(
        &mut self,
        request: PrivateRedeemRequest,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<StablecoinFlowRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.redeems.len() >= self.config.max_redeems {
            return Err("private redeem capacity exhausted".to_string());
        }
        self.ensure_fee_bucket(&request.stability_fee_bucket_id, request.max_fee_bps)?;
        self.consume_nullifier(&request.redeem_nullifier)?;
        self.counters.redeem_counter = self.counters.redeem_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let flow_id = private_redeem_id(&request, self.counters.redeem_counter);
        let record = StablecoinFlowRecord {
            flow_id: flow_id.clone(),
            flow_kind: StablecoinFlowKind::PrivateRedeem,
            owner_commitment: request.redeemer_commitment,
            input_root: request.stable_burn_root,
            output_root: request.reserve_release_root,
            amount_commitment_root: request.amount_commitment_root,
            reserve_proof_root: request.reserve_proof_root,
            stability_fee_bucket_id: request.stability_fee_bucket_id,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            defi_hook_root: request.defi_hook_root,
            nullifier: request.redeem_nullifier,
            reserve_coverage_bps: request.reserve_coverage_bps,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: FlowStatus::Pending,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(bucket) = self.fee_buckets.get_mut(&record.stability_fee_bucket_id) {
            bucket.flow_ids.push(flow_id.clone());
        }
        self.redeems.insert(flow_id, record.clone());
        Ok(record)
    }

    pub fn attest_reserves(
        &mut self,
        request: ReserveAttestationRequest,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<ReserveAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.reserve_attestations.len() >= self.config.max_reserve_attestations {
            return Err("reserve attestation capacity exhausted".to_string());
        }
        self.consume_nullifier(&request.attestation_nullifier)?;
        let flow = self
            .flow_mut(request.flow_kind, &request.flow_id)
            .ok_or_else(|| "reserve attestation references unknown stablecoin flow".to_string())?;
        if !flow.status.batchable() {
            return Err("reserve attestation cannot target non-live flow".to_string());
        }
        if flow.expires_at_height <= request.attested_at_height {
            flow.status = FlowStatus::Expired;
            return Err("reserve attestation cannot target expired flow".to_string());
        }
        flow.status = if request.verdict.allows_settlement() {
            FlowStatus::ReserveAttested
        } else {
            FlowStatus::Rejected
        };
        self.counters.reserve_attestation_counter =
            self.counters.reserve_attestation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let attestation_id =
            reserve_attestation_id(&request, self.counters.reserve_attestation_counter);
        let record = ReserveAttestationRecord {
            attestation_id: attestation_id.clone(),
            flow_kind: request.flow_kind,
            flow_id: request.flow_id,
            attestor_commitment: request.attestor_commitment,
            reserve_asset_root: request.reserve_asset_root,
            liability_commitment_root: request.liability_commitment_root,
            oracle_price_root: request.oracle_price_root,
            coverage_proof_root: request.coverage_proof_root,
            pq_attestation_root: request.pq_attestation_root,
            privacy_proof_root: request.privacy_proof_root,
            attestation_nullifier: request.attestation_nullifier,
            verdict: request.verdict,
            reserve_coverage_bps: request.reserve_coverage_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };
        self.reserve_attestations
            .insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn publish_sponsor_receipt(
        &mut self,
        request: PublishSponsorReceiptRequest,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<SponsorReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let flow = self
            .flow(request.flow_kind, &request.flow_id)
            .ok_or_else(|| "sponsor receipt references unknown stablecoin flow".to_string())?;
        if request.max_fee_bps > flow.max_fee_bps {
            return Err("sponsor receipt exceeds flow fee cap".to_string());
        }
        if request.expires_at_height <= flow.submitted_at_height {
            return Err("sponsor receipt expires before flow can settle".to_string());
        }
        self.counters.sponsor_receipt_counter =
            self.counters.sponsor_receipt_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.issued_at_height);
        let receipt_id = sponsor_receipt_id(&request, self.counters.sponsor_receipt_counter);
        let receipt = SponsorReceipt {
            receipt_id: receipt_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            flow_kind: request.flow_kind,
            flow_id: request.flow_id,
            fee_quote_root: request.fee_quote_root,
            rebate_commitment_root: request.rebate_commitment_root,
            sponsor_vault_root: request.sponsor_vault_root,
            pq_receipt_root: request.pq_receipt_root,
            max_fee_bps: request.max_fee_bps,
            issued_at_height: request.issued_at_height,
            expires_at_height: request.expires_at_height,
        };
        self.sponsor_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildSettlementBatchRequest,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<SettlementBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let mut seen = BTreeSet::new();
        for mint_id in &request.mint_ids {
            if !seen.insert(format!("mint:{mint_id}")) {
                return Err("duplicate mint in settlement batch".to_string());
            }
            let flow = self
                .mints
                .get(mint_id)
                .ok_or_else(|| format!("unknown mint flow {mint_id}"))?;
            validate_flow_for_batch(flow, request.built_at_height, request.max_fee_bps)?;
        }
        for redeem_id in &request.redeem_ids {
            if !seen.insert(format!("redeem:{redeem_id}")) {
                return Err("duplicate redeem in settlement batch".to_string());
            }
            let flow = self
                .redeems
                .get(redeem_id)
                .ok_or_else(|| format!("unknown redeem flow {redeem_id}"))?;
            validate_flow_for_batch(flow, request.built_at_height, request.max_fee_bps)?;
        }
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let batch_id = settlement_batch_id(&request, self.counters.batch_counter);
        for mint_id in &request.mint_ids {
            if let Some(flow) = self.mints.get_mut(mint_id) {
                flow.status = FlowStatus::Batched;
            }
        }
        for redeem_id in &request.redeem_ids {
            if let Some(flow) = self.redeems.get_mut(redeem_id) {
                flow.status = FlowStatus::Batched;
            }
        }
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            mint_ids: request.mint_ids,
            redeem_ids: request.redeem_ids,
            builder_commitment: request.builder_commitment,
            reserve_delta_root: request.reserve_delta_root,
            stable_supply_delta_root: request.stable_supply_delta_root,
            fee_bucket_delta_root: request.fee_bucket_delta_root,
            defi_composability_root: request.defi_composability_root,
            recursive_proof_root: request.recursive_proof_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            pq_batch_authorization_root: request.pq_batch_authorization_root,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            status: BatchStatus::SettlementReady,
            built_at_height: request.built_at_height,
            settlement_deadline_height: request
                .built_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
        };
        self.batches.insert(batch_id, batch.clone());
        Ok(batch)
    }

    pub fn settle_batch(
        &mut self,
        request: SettleBatchRequest,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<SettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "stablecoin batch not found for settlement".to_string())?
            .clone();
        if !batch.status.can_settle() {
            return Err("stablecoin batch cannot settle from current status".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("stablecoin batch settlement deadline elapsed".to_string());
        }
        if request.settled_fee_bps > batch.max_fee_bps {
            return Err("stablecoin settled fee exceeds batch maximum".to_string());
        }
        self.counters.settlement_counter = self.counters.settlement_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, self.counters.settlement_counter);
        for mint_id in &batch.mint_ids {
            if let Some(flow) = self.mints.get_mut(mint_id) {
                flow.status = FlowStatus::Settled;
            }
        }
        for redeem_id in &batch.redeem_ids {
            if let Some(flow) = self.redeems.get_mut(redeem_id) {
                flow.status = FlowStatus::Settled;
            }
        }
        if let Some(stored_batch) = self.batches.get_mut(&request.batch_id) {
            stored_batch.status = BatchStatus::Settled;
        }
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            reserve_root_after: request.reserve_root_after,
            stable_note_root_after: request.stable_note_root_after,
            fee_bucket_root_after: request.fee_bucket_root_after,
            account_delta_root: request.account_delta_root,
            nullifier_root: request.nullifier_root,
            output_note_root: request.output_note_root,
            sponsor_settlement_root: request.sponsor_settlement_root,
            pq_settlement_root: request.pq_settlement_root,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        self.settlement_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let mint_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-MINTS",
            &self
                .mints
                .values()
                .map(StablecoinFlowRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let redeem_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-REDEEMS",
            &self
                .redeems
                .values()
                .map(StablecoinFlowRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reserve_attestation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-RESERVE-ATTESTATIONS",
            &self
                .reserve_attestations
                .values()
                .map(ReserveAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_bucket_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-FEE-BUCKETS",
            &self
                .fee_buckets
                .values()
                .map(StabilityFeeBucket::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-SPONSOR-RECEIPTS",
            &self
                .sponsor_receipts
                .values()
                .map(SponsorReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-BATCHES",
            &self
                .batches
                .values()
                .map(SettlementBatch::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-SETTLEMENT-RECEIPTS",
            &self
                .settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-STATE",
            &json!({
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "current_height": self.current_height,
                "mint_root": mint_root,
                "redeem_root": redeem_root,
                "reserve_attestation_root": reserve_attestation_root,
                "fee_bucket_root": fee_bucket_root,
                "sponsor_receipt_root": sponsor_receipt_root,
                "batch_root": batch_root,
                "settlement_receipt_root": settlement_receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            mint_root,
            redeem_root,
            reserve_attestation_root,
            fee_bucket_root,
            sponsor_receipt_root,
            batch_root,
            settlement_receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "mint_ids": self.mints.keys().cloned().collect::<Vec<_>>(),
            "redeem_ids": self.redeems.keys().cloned().collect::<Vec<_>>(),
            "reserve_attestation_ids": self.reserve_attestations.keys().cloned().collect::<Vec<_>>(),
            "fee_bucket_ids": self.fee_buckets.keys().cloned().collect::<Vec<_>>(),
            "sponsor_receipt_ids": self.sponsor_receipts.keys().cloned().collect::<Vec<_>>(),
            "batch_ids": self.batches.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn ensure_fee_bucket(
        &self,
        bucket_id: &str,
        max_fee_bps: u64,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        let bucket = self
            .fee_buckets
            .get(bucket_id)
            .ok_or_else(|| "stablecoin flow references unknown fee bucket".to_string())?;
        if max_fee_bps > bucket.max_stability_fee_bps {
            return Err("flow fee exceeds stability fee bucket maximum".to_string());
        }
        Ok(())
    }

    fn flow(&self, flow_kind: StablecoinFlowKind, flow_id: &str) -> Option<&StablecoinFlowRecord> {
        match flow_kind {
            StablecoinFlowKind::PrivateMint => self.mints.get(flow_id),
            StablecoinFlowKind::PrivateRedeem => self.redeems.get(flow_id),
        }
    }

    fn flow_mut(
        &mut self,
        flow_kind: StablecoinFlowKind,
        flow_id: &str,
    ) -> Option<&mut StablecoinFlowRecord> {
        match flow_kind {
            StablecoinFlowKind::PrivateMint => self.mints.get_mut(flow_id),
            StablecoinFlowKind::PrivateRedeem => self.redeems.get_mut(flow_id),
        }
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("confidential stablecoin nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn private_mint_id(request: &PrivateMintRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-MINT-ID",
        &json!({
            "counter": counter,
            "minter_commitment": request.minter_commitment,
            "reserve_lock_root": request.reserve_lock_root,
            "stable_note_root": request.stable_note_root,
            "amount_commitment_root": request.amount_commitment_root,
            "mint_nullifier": request.mint_nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn private_redeem_id(request: &PrivateRedeemRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-REDEEM-ID",
        &json!({
            "counter": counter,
            "redeemer_commitment": request.redeemer_commitment,
            "stable_burn_root": request.stable_burn_root,
            "reserve_release_root": request.reserve_release_root,
            "amount_commitment_root": request.amount_commitment_root,
            "redeem_nullifier": request.redeem_nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn reserve_attestation_id(request: &ReserveAttestationRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-RESERVE-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "flow_kind": request.flow_kind.as_str(),
            "flow_id": request.flow_id,
            "attestor_commitment": request.attestor_commitment,
            "coverage_proof_root": request.coverage_proof_root,
            "verdict": request.verdict.as_str(),
            "attestation_nullifier": request.attestation_nullifier,
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn fee_bucket_id(request: &OpenFeeBucketRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-FEE-BUCKET-ID",
        &json!({
            "counter": counter,
            "bucket_kind": request.bucket_kind.as_str(),
            "bucket_owner_commitment": request.bucket_owner_commitment,
            "fee_policy_root": request.fee_policy_root,
            "rate_commitment_root": request.rate_commitment_root,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn sponsor_receipt_id(request: &PublishSponsorReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-SPONSOR-RECEIPT-ID",
        &json!({
            "counter": counter,
            "sponsor_commitment": request.sponsor_commitment,
            "flow_kind": request.flow_kind.as_str(),
            "flow_id": request.flow_id,
            "fee_quote_root": request.fee_quote_root,
            "sponsor_vault_root": request.sponsor_vault_root,
            "issued_at_height": request.issued_at_height,
        }),
    )
}

pub fn settlement_batch_id(request: &BuildSettlementBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-BATCH-ID",
        &json!({
            "counter": counter,
            "mint_ids": request.mint_ids,
            "redeem_ids": request.redeem_ids,
            "reserve_delta_root": request.reserve_delta_root,
            "stable_supply_delta_root": request.stable_supply_delta_root,
            "recursive_proof_root": request.recursive_proof_root,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn settlement_receipt_id(request: &SettleBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-STABLECOIN-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "batch_id": request.batch_id,
            "settlement_tx_root": request.settlement_tx_root,
            "settlement_proof_root": request.settlement_proof_root,
            "reserve_root_after": request.reserve_root_after,
            "stable_note_root_after": request.stable_note_root_after,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_PROTOCOL_VERSION),
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
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_STABLECOIN_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

fn validate_flow_for_batch(
    flow: &StablecoinFlowRecord,
    built_at_height: u64,
    max_fee_bps: u64,
) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
    if !flow.status.batchable() {
        return Err("stablecoin flow is not batchable".to_string());
    }
    if flow.expires_at_height <= built_at_height {
        return Err("stablecoin flow expired before batch".to_string());
    }
    if max_fee_bps > flow.max_fee_bps {
        return Err("batch fee exceeds flow fee cap".to_string());
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialStablecoinRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("stablecoin privacy set is below configured anonymity threshold".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err(
            "stablecoin PQ authorization security bits below configured minimum".to_string(),
        );
    }
    Ok(())
}
