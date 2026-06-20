use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisJamtisSpendlinkDecoyRefreshRebateVaultRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_SPENDLINK_DECOY_REFRESH_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-jamtis-spendlink-decoy-refresh-rebate-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_SPENDLINK_DECOY_REFRESH_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STATE_ROOT_DOMAIN: &str =
    "MONERO-L2-PQ-PRIVATE-SERAPHIS-JAMTIS-SPENDLINK-DECOY-REFRESH-REBATE-VAULT";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "refresh-rebate-vault-credit-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_248_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_896_000;
pub const DEVNET_EPOCH: u64 = 19_136;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_DECOY_POOL_OUTPUTS: u64 = 196_608;
pub const DEFAULT_TARGET_DECOY_POOL_OUTPUTS: u64 = 1_572_864;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 9_050;
pub const DEFAULT_MIN_SPENDLINK_SHIELD_BPS: u64 = 9_000;
pub const DEFAULT_MIN_REFRESH_UTILITY_BPS: u64 = 8_700;
pub const DEFAULT_MIN_REBATE_VAULT_ACCOUNTING_BPS: u64 = 9_150;
pub const DEFAULT_MIN_LIQUIDITY_DEPTH_BPS: u64 = 8_850;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_REFRESH_FEE_BPS: u64 = 3;
pub const DEFAULT_TARGET_REBATE_COVER_BPS: u64 = 9_700;
pub const DEFAULT_MIN_REBATE_SOLVENCY_BPS: u64 = 9_350;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_BATCH: u64 = 24_576;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_EPOCH: u64 = 393_216;
pub const DEFAULT_MIN_SOLVER_DIVERSITY_BPS: u64 = 7_750;
pub const DEFAULT_VAULT_REFRESH_INTENT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_VAULT_QUOTE_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_VAULT_EPOCH_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_REBATE_DRAW_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const VAULT_REFRESH_INTENT_SCHEME: &str =
    "seraphis-jamtis-spendlink-decoy-refresh-rebate-intent-root-v1";
pub const VAULT_QUOTE_SCHEME: &str =
    "pq-private-seraphis-jamtis-decoy-refresh-rebate-quote-root-v1";
pub const VAULT_EPOCH_SCHEME: &str = "defi-style-private-refresh-rebate-vault-batch-root-v1";
pub const REBATE_DRAW_SCHEME: &str = "jamtis-seraphis-private-refresh-rebate-draw-root-v1";
pub const SHIELDED_ACCOUNTING_VAULT_SCHEME: &str =
    "shielded-refresh-rebate-liquidity-vault-commitment-root-v1";
pub const PQ_VAULT_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-seraphis-jamtis-refresh-rebate-vault-attestation-v1";
pub const LOW_FEE_VAULT_AUDIT_SCHEME: &str =
    "low-fee-seraphis-jamtis-refresh-rebate-vault-audit-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-seraphis-jamtis-spendlink-decoy-refresh-rebate-vault-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_viewtags_spendlinks_ring_members_decoy_graphs_solver_identities_quote_prices_draw_witnesses_or_liquidity_owner_ids";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultLane {
    WalletScan,
    DexFlow,
    BridgeExit,
    MerchantReceive,
    WatchtowerRepair,
    ReorgRecovery,
    Migration,
    EmergencyPrivacy,
}

impl VaultLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::DexFlow => "dex_flow",
            Self::BridgeExit => "bridge_exit",
            Self::MerchantReceive => "merchant_receive",
            Self::WatchtowerRepair => "watchtower_repair",
            Self::ReorgRecovery => "reorg_recovery",
            Self::Migration => "migration",
            Self::EmergencyPrivacy => "emergency_privacy",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPrivacy => 1_000,
            Self::ReorgRecovery => 975,
            Self::BridgeExit => 945,
            Self::Migration => 915,
            Self::DexFlow => 890,
            Self::WatchtowerRepair => 855,
            Self::MerchantReceive => 825,
            Self::WalletScan => 800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRefreshIntentStatus {
    Open,
    EntropyChecked,
    ShieldChecked,
    Quoted,
    Batched,
    Drawn,
    Attested,
    Audited,
    Sealed,
    Quarantined,
    Rejected,
    Expired,
}

impl VaultRefreshIntentStatus {
    pub fn eligible_for_quote(self) -> bool {
        matches!(
            self,
            Self::Open | Self::EntropyChecked | Self::ShieldChecked | Self::Quoted
        )
    }

    pub fn counts_as_private_success(self) -> bool {
        matches!(
            self,
            Self::Batched | Self::Drawn | Self::Attested | Self::Audited | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultQuoteStatus {
    Committed,
    Revealed,
    Eligible,
    Allocating,
    Filled,
    Refunded,
    Slashed,
    Rejected,
    Expired,
}

impl VaultQuoteStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Revealed | Self::Eligible | Self::Allocating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultEpochStatus {
    Draft,
    Matching,
    Cleared,
    Netted,
    Drawing,
    Final,
    Challenged,
    Quarantined,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrawStatus {
    Created,
    Reserved,
    Proved,
    Paid,
    RolledForward,
    Slashed,
    Challenged,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingVaultStatus {
    Open,
    Reserving,
    Netting,
    Rebalanced,
    Exhausted,
    Slashed,
    Frozen,
    Closed,
}

impl AccountingVaultStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Reserving | Self::Netting | Self::Rebalanced
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultAttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Rotating,
    Expired,
    Revoked,
    Rejected,
}

impl VaultAttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultAuditStatus {
    Draft,
    Sampling,
    Published,
    Disputed,
    Accepted,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultPublicAudience {
    Wallets,
    Solvers,
    LiquidityProviders,
    Watchtowers,
    Governance,
    Public,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub vault_refresh_intent_scheme: String,
    pub vault_quote_scheme: String,
    pub vault_epoch_scheme: String,
    pub rebate_draw_scheme: String,
    pub accounting_vault_scheme: String,
    pub pq_vault_attestation_scheme: String,
    pub low_fee_vault_audit_scheme: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub public_bucket_size: u64,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_decoy_pool_outputs: u64,
    pub target_decoy_pool_outputs: u64,
    pub min_decoy_entropy_bps: u64,
    pub min_spendlink_shield_bps: u64,
    pub min_refresh_utility_bps: u64,
    pub min_vault_accounting_bps: u64,
    pub min_liquidity_depth_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_refresh_fee_bps: u64,
    pub target_rebate_cover_bps: u64,
    pub min_rebate_solvency_bps: u64,
    pub max_refresh_units_per_batch: u64,
    pub max_refresh_units_per_epoch: u64,
    pub min_solver_diversity_bps: u64,
    pub vault_refresh_intent_ttl_blocks: u64,
    pub vault_quote_ttl_blocks: u64,
    pub vault_epoch_ttl_blocks: u64,
    pub draw_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            vault_refresh_intent_scheme: VAULT_REFRESH_INTENT_SCHEME.to_string(),
            vault_quote_scheme: VAULT_QUOTE_SCHEME.to_string(),
            vault_epoch_scheme: VAULT_EPOCH_SCHEME.to_string(),
            rebate_draw_scheme: REBATE_DRAW_SCHEME.to_string(),
            accounting_vault_scheme: SHIELDED_ACCOUNTING_VAULT_SCHEME.to_string(),
            pq_vault_attestation_scheme: PQ_VAULT_ATTESTATION_SCHEME.to_string(),
            low_fee_vault_audit_scheme: LOW_FEE_VAULT_AUDIT_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_decoy_pool_outputs: DEFAULT_MIN_DECOY_POOL_OUTPUTS,
            target_decoy_pool_outputs: DEFAULT_TARGET_DECOY_POOL_OUTPUTS,
            min_decoy_entropy_bps: DEFAULT_MIN_DECOY_ENTROPY_BPS,
            min_spendlink_shield_bps: DEFAULT_MIN_SPENDLINK_SHIELD_BPS,
            min_refresh_utility_bps: DEFAULT_MIN_REFRESH_UTILITY_BPS,
            min_vault_accounting_bps: DEFAULT_MIN_REBATE_VAULT_ACCOUNTING_BPS,
            min_liquidity_depth_bps: DEFAULT_MIN_LIQUIDITY_DEPTH_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_refresh_fee_bps: DEFAULT_MAX_USER_REFRESH_FEE_BPS,
            target_rebate_cover_bps: DEFAULT_TARGET_REBATE_COVER_BPS,
            min_rebate_solvency_bps: DEFAULT_MIN_REBATE_SOLVENCY_BPS,
            max_refresh_units_per_batch: DEFAULT_MAX_REFRESH_UNITS_PER_BATCH,
            max_refresh_units_per_epoch: DEFAULT_MAX_REFRESH_UNITS_PER_EPOCH,
            min_solver_diversity_bps: DEFAULT_MIN_SOLVER_DIVERSITY_BPS,
            vault_refresh_intent_ttl_blocks: DEFAULT_VAULT_REFRESH_INTENT_TTL_BLOCKS,
            vault_quote_ttl_blocks: DEFAULT_VAULT_QUOTE_TTL_BLOCKS,
            vault_epoch_ttl_blocks: DEFAULT_VAULT_EPOCH_TTL_BLOCKS,
            draw_ttl_blocks: DEFAULT_REBATE_DRAW_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "vault_refresh_intent_scheme": self.vault_refresh_intent_scheme,
            "vault_quote_scheme": self.vault_quote_scheme,
            "vault_epoch_scheme": self.vault_epoch_scheme,
            "rebate_draw_scheme": self.rebate_draw_scheme,
            "accounting_vault_scheme": self.accounting_vault_scheme,
            "pq_vault_attestation_scheme": self.pq_vault_attestation_scheme,
            "low_fee_vault_audit_scheme": self.low_fee_vault_audit_scheme,
            "public_record_scheme": self.public_record_scheme,
            "privacy_boundary": self.privacy_boundary,
            "public_bucket_size": self.public_bucket_size,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_decoy_pool_outputs": self.min_decoy_pool_outputs,
            "target_decoy_pool_outputs": self.target_decoy_pool_outputs,
            "min_decoy_entropy_bps": self.min_decoy_entropy_bps,
            "min_spendlink_shield_bps": self.min_spendlink_shield_bps,
            "min_refresh_utility_bps": self.min_refresh_utility_bps,
            "min_vault_accounting_bps": self.min_vault_accounting_bps,
            "min_liquidity_depth_bps": self.min_liquidity_depth_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_refresh_fee_bps": self.max_user_refresh_fee_bps,
            "target_rebate_cover_bps": self.target_rebate_cover_bps,
            "min_rebate_solvency_bps": self.min_rebate_solvency_bps,
            "max_refresh_units_per_batch": self.max_refresh_units_per_batch,
            "max_refresh_units_per_epoch": self.max_refresh_units_per_epoch,
            "min_solver_diversity_bps": self.min_solver_diversity_bps,
            "vault_refresh_intent_ttl_blocks": self.vault_refresh_intent_ttl_blocks,
            "vault_quote_ttl_blocks": self.vault_quote_ttl_blocks,
            "vault_epoch_ttl_blocks": self.vault_epoch_ttl_blocks,
            "draw_ttl_blocks": self.draw_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vault_refresh_intents: u64,
    pub vault_quotes: u64,
    pub vault_epochs: u64,
    pub rebate_draws: u64,
    pub accounting_vaults: u64,
    pub pq_attestations: u64,
    pub vault_fee_audits: u64,
    pub roots_only_public_records: u64,
    pub quarantined_intents: u64,
    pub rejected_intents: u64,
    pub slashed_quotes: u64,
    pub frozen_vaults: u64,
    pub total_refresh_units_bucket: u64,
    pub total_rebate_units_bucket: u64,
    pub total_drawn_rebate_bucket: u64,
    pub max_observed_user_fee_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_refresh_intents": self.vault_refresh_intents,
            "vault_quotes": self.vault_quotes,
            "vault_epochs": self.vault_epochs,
            "rebate_draws": self.rebate_draws,
            "accounting_vaults": self.accounting_vaults,
            "pq_attestations": self.pq_attestations,
            "vault_fee_audits": self.vault_fee_audits,
            "roots_only_public_records": self.roots_only_public_records,
            "quarantined_intents": self.quarantined_intents,
            "rejected_intents": self.rejected_intents,
            "slashed_quotes": self.slashed_quotes,
            "frozen_vaults": self.frozen_vaults,
            "total_refresh_units_bucket": self.total_refresh_units_bucket,
            "total_rebate_units_bucket": self.total_rebate_units_bucket,
            "total_drawn_rebate_bucket": self.total_drawn_rebate_bucket,
            "max_observed_user_fee_bps": self.max_observed_user_fee_bps,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub vault_refresh_intent_root: String,
    pub vault_quote_root: String,
    pub vault_epoch_root: String,
    pub rebate_draw_root: String,
    pub accounting_vault_root: String,
    pub pq_attestation_root: String,
    pub low_fee_vault_audit_root: String,
    pub quarantined_intent_root: String,
    pub used_vault_quote_nullifier_root: String,
    pub used_draw_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        Self {
            config_root: config.state_root(),
            counters_root: counters.state_root(),
            vault_refresh_intent_root: empty_root(VAULT_REFRESH_INTENT_SCHEME),
            vault_quote_root: empty_root(VAULT_QUOTE_SCHEME),
            vault_epoch_root: empty_root(VAULT_EPOCH_SCHEME),
            rebate_draw_root: empty_root(REBATE_DRAW_SCHEME),
            accounting_vault_root: empty_root(SHIELDED_ACCOUNTING_VAULT_SCHEME),
            pq_attestation_root: empty_root(PQ_VAULT_ATTESTATION_SCHEME),
            low_fee_vault_audit_root: empty_root(LOW_FEE_VAULT_AUDIT_SCHEME),
            quarantined_intent_root: empty_root("quarantined-intent"),
            used_vault_quote_nullifier_root: empty_root("used-quote-nullifier"),
            used_draw_nullifier_root: empty_root("used-draw-nullifier"),
            public_record_root: empty_root(PUBLIC_RECORD_SCHEME),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "vault_refresh_intent_root": self.vault_refresh_intent_root,
            "vault_quote_root": self.vault_quote_root,
            "vault_epoch_root": self.vault_epoch_root,
            "rebate_draw_root": self.rebate_draw_root,
            "accounting_vault_root": self.accounting_vault_root,
            "pq_attestation_root": self.pq_attestation_root,
            "low_fee_vault_audit_root": self.low_fee_vault_audit_root,
            "quarantined_intent_root": self.quarantined_intent_root,
            "used_vault_quote_nullifier_root": self.used_vault_quote_nullifier_root,
            "used_draw_nullifier_root": self.used_draw_nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRefreshIntentInput {
    pub vault_intent_id: String,
    pub lane: VaultLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub ring_size: u16,
    pub refresh_unit_bucket: u64,
    pub max_user_fee_bps: u64,
    pub decoy_entropy_bps: u64,
    pub spendlink_shield_bps: u64,
    pub refresh_utility_bps: u64,
    pub decoy_pool_root: String,
    pub spendlink_shield_root: String,
    pub refresh_plan_root: String,
    pub rebate_hint_root: String,
    pub expires_at_height: u64,
    pub status: VaultRefreshIntentStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRefreshIntentEntry {
    pub vault_intent_id: String,
    pub lane: VaultLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub ring_size: u16,
    pub refresh_unit_bucket: u64,
    pub max_user_fee_bps: u64,
    pub priority_score: u64,
    pub decoy_entropy_bps: u64,
    pub spendlink_shield_bps: u64,
    pub refresh_utility_bps: u64,
    pub decoy_pool_root: String,
    pub spendlink_shield_root: String,
    pub refresh_plan_root: String,
    pub rebate_hint_root: String,
    pub expires_at_height: u64,
    pub status: VaultRefreshIntentStatus,
}

impl VaultRefreshIntentEntry {
    pub fn from_input(input: VaultRefreshIntentInput) -> Self {
        let priority_score = input
            .lane
            .priority_weight()
            .saturating_mul(input.refresh_unit_bucket.max(1));
        Self {
            vault_intent_id: input.vault_intent_id,
            lane: input.lane,
            epoch: input.epoch,
            monero_height_bucket: input.monero_height_bucket,
            output_count_bucket: input.output_count_bucket,
            ring_size: input.ring_size,
            refresh_unit_bucket: input.refresh_unit_bucket,
            max_user_fee_bps: input.max_user_fee_bps,
            priority_score,
            decoy_entropy_bps: input.decoy_entropy_bps,
            spendlink_shield_bps: input.spendlink_shield_bps,
            refresh_utility_bps: input.refresh_utility_bps,
            decoy_pool_root: input.decoy_pool_root,
            spendlink_shield_root: input.spendlink_shield_root,
            refresh_plan_root: input.refresh_plan_root,
            rebate_hint_root: input.rebate_hint_root,
            expires_at_height: input.expires_at_height,
            status: input.status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_intent_id": self.vault_intent_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "output_count_bucket": self.output_count_bucket,
            "ring_size": self.ring_size,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "max_user_fee_bps": self.max_user_fee_bps,
            "priority_score": self.priority_score,
            "decoy_entropy_bps": self.decoy_entropy_bps,
            "spendlink_shield_bps": self.spendlink_shield_bps,
            "refresh_utility_bps": self.refresh_utility_bps,
            "decoy_pool_root": self.decoy_pool_root,
            "spendlink_shield_root": self.spendlink_shield_root,
            "refresh_plan_root": self.refresh_plan_root,
            "rebate_hint_root": self.rebate_hint_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("refresh-intent", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultQuoteInput {
    pub vault_quote_id: String,
    pub solver_bucket: String,
    pub vault_quote_nullifier: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub max_user_fee_bps: u64,
    pub rebate_cover_bps: u64,
    pub solvency_bps: u64,
    pub liquidity_depth_bps: u64,
    pub refresh_unit_budget_bucket: u64,
    pub rebate_budget_bucket: u64,
    pub quote_commitment_root: String,
    pub solver_policy_root: String,
    pub liquidity_reservation_root: String,
    pub expires_at_height: u64,
    pub status: VaultQuoteStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultQuoteEntry {
    pub vault_quote_id: String,
    pub solver_bucket: String,
    pub vault_quote_nullifier: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub max_user_fee_bps: u64,
    pub rebate_cover_bps: u64,
    pub solvency_bps: u64,
    pub liquidity_depth_bps: u64,
    pub refresh_unit_budget_bucket: u64,
    pub rebate_budget_bucket: u64,
    pub quote_commitment_root: String,
    pub solver_policy_root: String,
    pub liquidity_reservation_root: String,
    pub expires_at_height: u64,
    pub status: VaultQuoteStatus,
}

impl VaultQuoteEntry {
    pub fn from_input(input: VaultQuoteInput) -> Self {
        Self {
            vault_quote_id: input.vault_quote_id,
            solver_bucket: input.solver_bucket,
            vault_quote_nullifier: input.vault_quote_nullifier,
            fee_asset_id: input.fee_asset_id,
            rebate_asset_id: input.rebate_asset_id,
            max_user_fee_bps: input.max_user_fee_bps,
            rebate_cover_bps: input.rebate_cover_bps,
            solvency_bps: input.solvency_bps,
            liquidity_depth_bps: input.liquidity_depth_bps,
            refresh_unit_budget_bucket: input.refresh_unit_budget_bucket,
            rebate_budget_bucket: input.rebate_budget_bucket,
            quote_commitment_root: input.quote_commitment_root,
            solver_policy_root: input.solver_policy_root,
            liquidity_reservation_root: input.liquidity_reservation_root,
            expires_at_height: input.expires_at_height,
            status: input.status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_quote_id": self.vault_quote_id,
            "solver_bucket": self.solver_bucket,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_cover_bps": self.rebate_cover_bps,
            "solvency_bps": self.solvency_bps,
            "liquidity_depth_bps": self.liquidity_depth_bps,
            "refresh_unit_budget_bucket": self.refresh_unit_budget_bucket,
            "rebate_budget_bucket": self.rebate_budget_bucket,
            "quote_commitment_root": self.quote_commitment_root,
            "solver_policy_root": self.solver_policy_root,
            "liquidity_reservation_root": self.liquidity_reservation_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_parts(
            "rebate-quote",
            &[
                HashPart::Json(&self.public_record()),
                HashPart::Str(&self.vault_quote_nullifier),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultEpochEntry {
    pub batch_id: String,
    pub epoch: u64,
    pub lane: VaultLane,
    pub intent_root: String,
    pub quote_root: String,
    pub solver_diversity_bps: u64,
    pub vault_accounting_efficiency_bps: u64,
    pub liquidity_depth_bps: u64,
    pub matched_refresh_units_bucket: u64,
    pub gross_fee_bucket: u64,
    pub rebate_bucket: u64,
    pub net_user_fee_bps: u64,
    pub vault_accounting_price_root: String,
    pub private_netting_root: String,
    pub mev_resistance_root: String,
    pub expires_at_height: u64,
    pub status: VaultEpochStatus,
}

impl VaultEpochEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "intent_root": self.intent_root,
            "quote_root": self.quote_root,
            "solver_diversity_bps": self.solver_diversity_bps,
            "vault_accounting_efficiency_bps": self.vault_accounting_efficiency_bps,
            "liquidity_depth_bps": self.liquidity_depth_bps,
            "matched_refresh_units_bucket": self.matched_refresh_units_bucket,
            "gross_fee_bucket": self.gross_fee_bucket,
            "rebate_bucket": self.rebate_bucket,
            "net_user_fee_bps": self.net_user_fee_bps,
            "vault_accounting_price_root": self.vault_accounting_price_root,
            "private_netting_root": self.private_netting_root,
            "mev_resistance_root": self.mev_resistance_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("vault-epoch", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateDrawEntry {
    pub draw_id: String,
    pub batch_id: String,
    pub vault_intent_id: String,
    pub vault_quote_id: String,
    pub draw_nullifier: String,
    pub refresh_unit_bucket: u64,
    pub rebate_bucket: u64,
    pub user_fee_bps: u64,
    pub rebate_cover_bps: u64,
    pub draw_commitment_root: String,
    pub payout_receipt_root: String,
    pub roll_forward_root: String,
    pub expires_at_height: u64,
    pub status: DrawStatus,
}

impl RebateDrawEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "draw_id": self.draw_id,
            "batch_id": self.batch_id,
            "vault_intent_id": self.vault_intent_id,
            "vault_quote_id": self.vault_quote_id,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "rebate_bucket": self.rebate_bucket,
            "user_fee_bps": self.user_fee_bps,
            "rebate_cover_bps": self.rebate_cover_bps,
            "draw_commitment_root": self.draw_commitment_root,
            "payout_receipt_root": self.payout_receipt_root,
            "roll_forward_root": self.roll_forward_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_parts(
            "rebate-draw",
            &[
                HashPart::Json(&self.public_record()),
                HashPart::Str(&self.draw_nullifier),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedAccountingVaultEntry {
    pub vault_id: String,
    pub provider_bucket: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub available_rebate_bucket: u64,
    pub reserved_rebate_bucket: u64,
    pub solvency_bps: u64,
    pub liquidity_depth_bps: u64,
    pub accounting_vault_commitment_root: String,
    pub withdrawal_policy_root: String,
    pub rebalance_proof_root: String,
    pub status: AccountingVaultStatus,
}

impl ShieldedAccountingVaultEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "provider_bucket": self.provider_bucket,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "available_rebate_bucket": self.available_rebate_bucket,
            "reserved_rebate_bucket": self.reserved_rebate_bucket,
            "solvency_bps": self.solvency_bps,
            "liquidity_depth_bps": self.liquidity_depth_bps,
            "accounting_vault_commitment_root": self.accounting_vault_commitment_root,
            "withdrawal_policy_root": self.withdrawal_policy_root,
            "rebalance_proof_root": self.rebalance_proof_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("liquidity-vault", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqVaultAttestationEntry {
    pub attestation_id: String,
    pub batch_id: String,
    pub signer_set_root: String,
    pub pq_transcript_root: String,
    pub vault_accounting_verdict_root: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: VaultAttestationStatus,
}

impl PqVaultAttestationEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "signer_set_root": self.signer_set_root,
            "pq_transcript_root": self.pq_transcript_root,
            "vault_accounting_verdict_root": self.vault_accounting_verdict_root,
            "pq_security_bits": self.pq_security_bits,
            "classical_fallback_disabled": self.classical_fallback_disabled,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("pq-vault-attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeVaultAuditEntry {
    pub audit_id: String,
    pub batch_id: String,
    pub measured_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub vault_accounting_bps: u64,
    pub liquidity_efficiency_bps: u64,
    pub refresh_latency_blocks: u64,
    pub fee_sample_root: String,
    pub rebate_sample_root: String,
    pub privacy_regression_root: String,
    pub accounting_evidence_root: String,
    pub status: VaultAuditStatus,
}

impl LowFeeVaultAuditEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "batch_id": self.batch_id,
            "measured_user_fee_bps": self.measured_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "vault_accounting_bps": self.vault_accounting_bps,
            "liquidity_efficiency_bps": self.liquidity_efficiency_bps,
            "refresh_latency_blocks": self.refresh_latency_blocks,
            "fee_sample_root": self.fee_sample_root,
            "rebate_sample_root": self.rebate_sample_root,
            "privacy_regression_root": self.privacy_regression_root,
            "accounting_evidence_root": self.accounting_evidence_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("low-fee-rebate-audit", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub audience: VaultPublicAudience,
    pub protocol_version: String,
    pub epoch: u64,
    pub l2_height: u64,
    pub monero_height_bucket: u64,
    pub privacy_boundary: String,
    pub roots: Roots,
    pub counters_root: String,
}

impl RootsOnlyPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "audience": self.audience,
            "protocol_version": self.protocol_version,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": self.monero_height_bucket,
            "privacy_boundary": self.privacy_boundary,
            "roots": self.roots.public_record(),
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots-only-public-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub chain_id: String,
    pub epoch: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub vault_refresh_intents: BTreeMap<String, VaultRefreshIntentEntry>,
    pub vault_quotes: BTreeMap<String, VaultQuoteEntry>,
    pub vault_epochs: BTreeMap<String, VaultEpochEntry>,
    pub rebate_draws: BTreeMap<String, RebateDrawEntry>,
    pub accounting_vaults: BTreeMap<String, ShieldedAccountingVaultEntry>,
    pub pq_attestations: BTreeMap<String, PqVaultAttestationEntry>,
    pub low_fee_vault_audits: BTreeMap<String, LowFeeVaultAuditEntry>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub quarantined_vault_intent_ids: BTreeSet<String>,
    pub used_vault_quote_nullifiers: BTreeSet<String>,
    pub used_draw_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(
            Config::devnet(),
            DEVNET_EPOCH,
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
        )
    }
}

impl State {
    pub fn new(config: Config, epoch: u64, l2_height: u64, monero_height: u64) -> Self {
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            protocol_version: config.protocol_version.clone(),
            chain_id: config.chain_id.clone(),
            epoch,
            l2_height,
            monero_height,
            config,
            counters,
            roots,
            vault_refresh_intents: BTreeMap::new(),
            vault_quotes: BTreeMap::new(),
            vault_epochs: BTreeMap::new(),
            rebate_draws: BTreeMap::new(),
            accounting_vaults: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            low_fee_vault_audits: BTreeMap::new(),
            public_records: BTreeMap::new(),
            quarantined_vault_intent_ids: BTreeSet::new(),
            used_vault_quote_nullifiers: BTreeSet::new(),
            used_draw_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.seed_devnet();
        state
    }

    pub fn insert_vault_refresh_intent(&mut self, input: VaultRefreshIntentInput) -> Result<()> {
        ensure(!input.vault_intent_id.is_empty(), "intent id is required")?;
        ensure(
            !self
                .vault_refresh_intents
                .contains_key(&input.vault_intent_id),
            "refresh intent already exists",
        )?;
        ensure(
            input.ring_size >= self.config.min_ring_size,
            "ring size below minimum",
        )?;
        ensure(
            input.output_count_bucket >= self.config.min_decoy_pool_outputs,
            "decoy pool below minimum",
        )?;
        ensure(
            input.refresh_unit_bucket <= self.config.max_refresh_units_per_batch,
            "refresh units exceed batch cap",
        )?;
        ensure(
            input.max_user_fee_bps <= self.config.max_user_refresh_fee_bps,
            "user refresh fee above cap",
        )?;
        ensure(
            input.decoy_entropy_bps >= self.config.min_decoy_entropy_bps,
            "decoy entropy below minimum",
        )?;
        ensure(
            input.spendlink_shield_bps >= self.config.min_spendlink_shield_bps,
            "spendlink shield below minimum",
        )?;
        ensure(
            input.refresh_utility_bps >= self.config.min_refresh_utility_bps,
            "refresh utility below minimum",
        )?;
        ensure(
            input.expires_at_height > self.monero_height,
            "refresh intent already expired",
        )?;
        if matches!(input.status, VaultRefreshIntentStatus::Quarantined) {
            self.quarantined_vault_intent_ids
                .insert(input.vault_intent_id.clone());
        }
        let entry = VaultRefreshIntentEntry::from_input(input);
        self.vault_refresh_intents
            .insert(entry.vault_intent_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_vault_quote(&mut self, input: VaultQuoteInput) -> Result<()> {
        ensure(!input.vault_quote_id.is_empty(), "quote id is required")?;
        ensure(
            !self.vault_quotes.contains_key(&input.vault_quote_id),
            "rebate quote already exists",
        )?;
        ensure(
            !input.vault_quote_nullifier.is_empty(),
            "quote nullifier is required",
        )?;
        ensure(
            !self
                .used_vault_quote_nullifiers
                .contains(&input.vault_quote_nullifier),
            "quote nullifier already used",
        )?;
        ensure(
            input.fee_asset_id == self.config.fee_asset_id,
            "unexpected fee asset",
        )?;
        ensure(
            input.rebate_asset_id == self.config.rebate_asset_id,
            "unexpected rebate asset",
        )?;
        ensure(
            input.max_user_fee_bps <= self.config.max_user_refresh_fee_bps,
            "quote user fee above cap",
        )?;
        ensure(
            input.rebate_cover_bps >= self.config.target_rebate_cover_bps,
            "rebate cover below target",
        )?;
        ensure(
            input.solvency_bps >= self.config.min_rebate_solvency_bps,
            "rebate solvency below minimum",
        )?;
        ensure(
            input.liquidity_depth_bps >= self.config.min_liquidity_depth_bps,
            "liquidity depth below minimum",
        )?;
        ensure(
            input.expires_at_height > self.monero_height,
            "rebate quote already expired",
        )?;
        self.used_vault_quote_nullifiers
            .insert(input.vault_quote_nullifier.clone());
        let entry = VaultQuoteEntry::from_input(input);
        self.vault_quotes
            .insert(entry.vault_quote_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_vault_epoch(&mut self, entry: VaultEpochEntry) -> Result<()> {
        ensure(!entry.batch_id.is_empty(), "batch id is required")?;
        ensure(
            !self.vault_epochs.contains_key(&entry.batch_id),
            "vault epoch already exists",
        )?;
        ensure(
            entry.matched_refresh_units_bucket <= self.config.max_refresh_units_per_epoch,
            "matched refresh units exceed epoch cap",
        )?;
        ensure(
            entry.net_user_fee_bps <= self.config.max_user_refresh_fee_bps,
            "vault fee above user cap",
        )?;
        ensure(
            entry.vault_accounting_efficiency_bps >= self.config.min_vault_accounting_bps,
            "rebate vault accounting efficiency below minimum",
        )?;
        ensure(
            entry.liquidity_depth_bps >= self.config.min_liquidity_depth_bps,
            "batch liquidity depth below minimum",
        )?;
        ensure(
            entry.solver_diversity_bps >= self.config.min_solver_diversity_bps,
            "solver diversity below minimum",
        )?;
        ensure(
            entry.expires_at_height > self.monero_height,
            "vault epoch already expired",
        )?;
        self.vault_epochs.insert(entry.batch_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_rebate_draw(&mut self, entry: RebateDrawEntry) -> Result<()> {
        ensure(!entry.draw_id.is_empty(), "draw id is required")?;
        ensure(
            !self.rebate_draws.contains_key(&entry.draw_id),
            "rebate draw already exists",
        )?;
        ensure(
            self.vault_epochs.contains_key(&entry.batch_id),
            "draw references unknown vault epoch",
        )?;
        ensure(
            self.vault_refresh_intents
                .contains_key(&entry.vault_intent_id),
            "draw references unknown refresh intent",
        )?;
        ensure(
            self.vault_quotes.contains_key(&entry.vault_quote_id),
            "draw references unknown rebate quote",
        )?;
        ensure(
            !entry.draw_nullifier.is_empty(),
            "draw nullifier is required",
        )?;
        ensure(
            !self.used_draw_nullifiers.contains(&entry.draw_nullifier),
            "draw nullifier already used",
        )?;
        ensure(
            entry.user_fee_bps <= self.config.max_user_refresh_fee_bps,
            "draw fee above cap",
        )?;
        ensure(
            entry.rebate_cover_bps >= self.config.target_rebate_cover_bps,
            "draw rebate cover below target",
        )?;
        ensure(
            entry.expires_at_height > self.monero_height,
            "rebate draw already expired",
        )?;
        self.used_draw_nullifiers
            .insert(entry.draw_nullifier.clone());
        self.rebate_draws.insert(entry.draw_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_accounting_vault(&mut self, entry: ShieldedAccountingVaultEntry) -> Result<()> {
        ensure(!entry.vault_id.is_empty(), "vault id is required")?;
        ensure(
            !self.accounting_vaults.contains_key(&entry.vault_id),
            "accounting vault already exists",
        )?;
        ensure(
            entry.fee_asset_id == self.config.fee_asset_id,
            "unexpected vault fee asset",
        )?;
        ensure(
            entry.rebate_asset_id == self.config.rebate_asset_id,
            "unexpected vault rebate asset",
        )?;
        ensure(
            entry.solvency_bps >= self.config.min_rebate_solvency_bps,
            "vault solvency below minimum",
        )?;
        ensure(
            entry.liquidity_depth_bps >= self.config.min_liquidity_depth_bps,
            "vault liquidity depth below minimum",
        )?;
        self.accounting_vaults.insert(entry.vault_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, entry: PqVaultAttestationEntry) -> Result<()> {
        ensure(
            !entry.attestation_id.is_empty(),
            "attestation id is required",
        )?;
        ensure(
            !self.pq_attestations.contains_key(&entry.attestation_id),
            "attestation already exists",
        )?;
        ensure(
            self.vault_epochs.contains_key(&entry.batch_id),
            "attestation references unknown vault epoch",
        )?;
        ensure(
            entry.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ security below minimum",
        )?;
        ensure(
            entry.classical_fallback_disabled,
            "classical fallback must be disabled",
        )?;
        ensure(
            entry.expires_at_height > self.monero_height,
            "attestation already expired",
        )?;
        self.pq_attestations
            .insert(entry.attestation_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_rebate_audit(&mut self, entry: LowFeeVaultAuditEntry) -> Result<()> {
        ensure(!entry.audit_id.is_empty(), "audit id is required")?;
        ensure(
            !self.low_fee_vault_audits.contains_key(&entry.audit_id),
            "audit already exists",
        )?;
        ensure(
            self.vault_epochs.contains_key(&entry.batch_id),
            "audit references unknown vault epoch",
        )?;
        ensure(
            entry.measured_user_fee_bps <= entry.target_user_fee_bps,
            "measured fee exceeds target",
        )?;
        ensure(
            entry.target_user_fee_bps <= self.config.max_user_refresh_fee_bps,
            "audit fee target above config cap",
        )?;
        ensure(
            entry.vault_accounting_bps >= self.config.min_vault_accounting_bps,
            "audit vault accounting score below minimum",
        )?;
        self.low_fee_vault_audits
            .insert(entry.audit_id.clone(), entry);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_roots_only_record(
        &mut self,
        record_id: &str,
        audience: VaultPublicAudience,
    ) -> Result<()> {
        ensure(!record_id.is_empty(), "record id is required")?;
        ensure(
            !self.public_records.contains_key(record_id),
            "public record already exists",
        )?;
        let record = RootsOnlyPublicRecord {
            record_id: record_id.to_string(),
            audience,
            protocol_version: self.protocol_version.clone(),
            epoch: self.epoch,
            l2_height: self.l2_height,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            privacy_boundary: self.config.privacy_boundary.clone(),
            roots: self.roots.clone(),
            counters_root: self.counters.state_root(),
        };
        self.public_records.insert(record_id.to_string(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn rebate_coverage_bps(&self) -> u64 {
        ratio_bps(
            self.counters.total_rebate_units_bucket,
            self.counters.total_refresh_units_bucket,
        )
    }

    pub fn drawn_rebate_bps(&self) -> u64 {
        ratio_bps(
            self.counters.total_drawn_rebate_bucket,
            self.counters.total_rebate_units_bucket,
        )
    }

    pub fn attested_vault_accounting_bps(&self) -> u64 {
        ratio_bps(
            self.pq_attestations
                .values()
                .filter(|entry| entry.status.counts_for_quorum())
                .count() as u64,
            self.vault_epochs.len() as u64,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": bucket(self.monero_height, self.config.public_bucket_size),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "rebate_coverage_bps": self.rebate_coverage_bps(),
            "drawn_rebate_bps": self.drawn_rebate_bps(),
            "attested_vault_accounting_bps": self.attested_vault_accounting_bps(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_parts(
            "state",
            &[
                HashPart::Json(&self.public_record()),
                HashPart::Str(&self.roots.state_root()),
            ],
        )
    }

    pub fn refresh_roots(&mut self) {
        self.counters.vault_refresh_intents = self.vault_refresh_intents.len() as u64;
        self.counters.vault_quotes = self.vault_quotes.len() as u64;
        self.counters.vault_epochs = self.vault_epochs.len() as u64;
        self.counters.rebate_draws = self.rebate_draws.len() as u64;
        self.counters.accounting_vaults = self.accounting_vaults.len() as u64;
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.counters.vault_fee_audits = self.low_fee_vault_audits.len() as u64;
        self.counters.roots_only_public_records = self.public_records.len() as u64;
        self.counters.quarantined_intents = self.quarantined_vault_intent_ids.len() as u64;
        self.counters.rejected_intents = self
            .vault_refresh_intents
            .values()
            .filter(|entry| entry.status == VaultRefreshIntentStatus::Rejected)
            .count() as u64;
        self.counters.slashed_quotes = self
            .vault_quotes
            .values()
            .filter(|entry| entry.status == VaultQuoteStatus::Slashed)
            .count() as u64;
        self.counters.frozen_vaults = self
            .accounting_vaults
            .values()
            .filter(|entry| entry.status == AccountingVaultStatus::Frozen)
            .count() as u64;
        self.counters.total_refresh_units_bucket = self
            .vault_epochs
            .values()
            .map(|entry| entry.matched_refresh_units_bucket)
            .sum();
        self.counters.total_rebate_units_bucket = self
            .vault_epochs
            .values()
            .map(|entry| entry.rebate_bucket)
            .sum();
        self.counters.total_drawn_rebate_bucket = self
            .rebate_draws
            .values()
            .filter(|entry| matches!(entry.status, DrawStatus::Paid | DrawStatus::RolledForward))
            .map(|entry| entry.rebate_bucket)
            .sum();
        self.counters.max_observed_user_fee_bps = self
            .vault_epochs
            .values()
            .map(|entry| entry.net_user_fee_bps)
            .chain(self.rebate_draws.values().map(|entry| entry.user_fee_bps))
            .max()
            .unwrap_or(0);
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            vault_refresh_intent_root: map_root(
                VAULT_REFRESH_INTENT_SCHEME,
                self.vault_refresh_intents
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            vault_quote_root: map_root(
                VAULT_QUOTE_SCHEME,
                self.vault_quotes
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            vault_epoch_root: map_root(
                VAULT_EPOCH_SCHEME,
                self.vault_epochs
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            rebate_draw_root: map_root(
                REBATE_DRAW_SCHEME,
                self.rebate_draws
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            accounting_vault_root: map_root(
                SHIELDED_ACCOUNTING_VAULT_SCHEME,
                self.accounting_vaults
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            pq_attestation_root: map_root(
                PQ_VAULT_ATTESTATION_SCHEME,
                self.pq_attestations
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            low_fee_vault_audit_root: map_root(
                LOW_FEE_VAULT_AUDIT_SCHEME,
                self.low_fee_vault_audits
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            quarantined_intent_root: set_root(
                "quarantined-intent",
                &self.quarantined_vault_intent_ids,
            ),
            used_vault_quote_nullifier_root: set_root(
                "used-quote-nullifier",
                &self.used_vault_quote_nullifiers,
            ),
            used_draw_nullifier_root: set_root("used-draw-nullifier", &self.used_draw_nullifiers),
            public_record_root: map_root(
                PUBLIC_RECORD_SCHEME,
                self.public_records
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
        };
    }

    fn seed_devnet(&mut self) {
        let vault_intent_id = "rebate-refresh-intent-devnet-0".to_string();
        let vault_quote_id = "rebate-vault-quote-devnet-0".to_string();
        let batch_id = "rebate-vault-epoch-devnet-0".to_string();
        let draw_id = "rebate-draw-devnet-0".to_string();
        self.insert_vault_refresh_intent(VaultRefreshIntentInput {
            vault_intent_id: vault_intent_id.clone(),
            lane: VaultLane::DexFlow,
            epoch: self.epoch,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            output_count_bucket: self.config.target_decoy_pool_outputs,
            ring_size: self.config.target_ring_size,
            refresh_unit_bucket: 8_192,
            max_user_fee_bps: 2,
            decoy_entropy_bps: 9_420,
            spendlink_shield_bps: 9_310,
            refresh_utility_bps: 9_050,
            decoy_pool_root: root_from_parts(
                "devnet-decoy-pool",
                &[HashPart::Str(&vault_intent_id)],
            ),
            spendlink_shield_root: root_from_parts(
                "devnet-spendlink-shield",
                &[HashPart::Str(&vault_intent_id)],
            ),
            refresh_plan_root: root_from_parts(
                "devnet-refresh-plan",
                &[HashPart::Str(&vault_intent_id)],
            ),
            rebate_hint_root: root_from_parts(
                "devnet-rebate-hint",
                &[HashPart::Str(&vault_intent_id)],
            ),
            expires_at_height: self.monero_height + self.config.vault_refresh_intent_ttl_blocks,
            status: VaultRefreshIntentStatus::Batched,
        })
        .expect("devnet refresh intent inserts");
        self.insert_vault_quote(VaultQuoteInput {
            vault_quote_id: vault_quote_id.clone(),
            solver_bucket: "devnet-solver-bucket-0".to_string(),
            vault_quote_nullifier: "devnet-private-quote-nullifier-0".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            max_user_fee_bps: 2,
            rebate_cover_bps: 9_850,
            solvency_bps: 9_900,
            liquidity_depth_bps: 9_620,
            refresh_unit_budget_bucket: 98_304,
            rebate_budget_bucket: 384,
            quote_commitment_root: root_from_parts(
                "devnet-quote-commitment",
                &[HashPart::Str(&vault_quote_id)],
            ),
            solver_policy_root: root_from_parts(
                "devnet-solver-policy",
                &[HashPart::Str(&vault_quote_id)],
            ),
            liquidity_reservation_root: root_from_parts(
                "devnet-liquidity-reservation",
                &[HashPart::Str(&vault_quote_id)],
            ),
            expires_at_height: self.monero_height + self.config.vault_quote_ttl_blocks,
            status: VaultQuoteStatus::Filled,
        })
        .expect("devnet rebate quote inserts");
        self.insert_accounting_vault(ShieldedAccountingVaultEntry {
            vault_id: "rebate-liquidity-vault-devnet-0".to_string(),
            provider_bucket: "devnet-provider-bucket-0".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            available_rebate_bucket: 16_384,
            reserved_rebate_bucket: 384,
            solvency_bps: 9_910,
            liquidity_depth_bps: 9_700,
            accounting_vault_commitment_root: root_from_parts(
                "devnet-vault",
                &[HashPart::Str("0")],
            ),
            withdrawal_policy_root: root_from_parts(
                "devnet-withdrawal-policy",
                &[HashPart::Str("0")],
            ),
            rebalance_proof_root: root_from_parts("devnet-rebalance", &[HashPart::Str("0")]),
            status: AccountingVaultStatus::Rebalanced,
        })
        .expect("devnet accounting vault inserts");
        self.insert_vault_epoch(VaultEpochEntry {
            batch_id: batch_id.clone(),
            epoch: self.epoch,
            lane: VaultLane::DexFlow,
            intent_root: map_root(
                "devnet-batch-intents",
                std::iter::once((
                    vault_intent_id.as_str(),
                    self.vault_refresh_intents
                        .get(&vault_intent_id)
                        .expect("intent exists")
                        .state_root(),
                )),
            ),
            quote_root: map_root(
                "devnet-batch-quotes",
                std::iter::once((
                    vault_quote_id.as_str(),
                    self.vault_quotes
                        .get(&vault_quote_id)
                        .expect("quote exists")
                        .state_root(),
                )),
            ),
            solver_diversity_bps: 8_200,
            vault_accounting_efficiency_bps: 9_360,
            liquidity_depth_bps: 9_620,
            matched_refresh_units_bucket: 8_192,
            gross_fee_bucket: 24,
            rebate_bucket: 8,
            net_user_fee_bps: 2,
            vault_accounting_price_root: root_from_parts(
                "devnet-vault-accounting-price",
                &[HashPart::Str(&batch_id)],
            ),
            private_netting_root: root_from_parts(
                "devnet-private-netting",
                &[HashPart::Str(&batch_id)],
            ),
            mev_resistance_root: root_from_parts(
                "devnet-mev-resistance",
                &[HashPart::Str(&batch_id)],
            ),
            expires_at_height: self.monero_height + self.config.vault_epoch_ttl_blocks,
            status: VaultEpochStatus::Final,
        })
        .expect("devnet vault epoch inserts");
        self.insert_rebate_draw(RebateDrawEntry {
            draw_id: draw_id.clone(),
            batch_id: batch_id.clone(),
            vault_intent_id: vault_intent_id.clone(),
            vault_quote_id: vault_quote_id.clone(),
            draw_nullifier: "devnet-private-draw-nullifier-0".to_string(),
            refresh_unit_bucket: 8_192,
            rebate_bucket: 8,
            user_fee_bps: 2,
            rebate_cover_bps: 9_850,
            draw_commitment_root: root_from_parts(
                "devnet-draw-commitment",
                &[HashPart::Str(&draw_id)],
            ),
            payout_receipt_root: root_from_parts("devnet-payout", &[HashPart::Str(&draw_id)]),
            roll_forward_root: root_from_parts("devnet-roll-forward", &[HashPart::Str(&draw_id)]),
            expires_at_height: self.monero_height + self.config.draw_ttl_blocks,
            status: DrawStatus::Paid,
        })
        .expect("devnet rebate draw inserts");
        self.insert_pq_attestation(PqVaultAttestationEntry {
            attestation_id: "pq-rebate-vault-attestation-devnet-0".to_string(),
            batch_id: batch_id.clone(),
            signer_set_root: root_from_parts("devnet-pq-signers", &[HashPart::Str("0")]),
            pq_transcript_root: root_from_parts(
                "devnet-pq-transcript",
                &[HashPart::Str(&batch_id)],
            ),
            vault_accounting_verdict_root: root_from_parts(
                "devnet-vault-accounting-verdict",
                &[HashPart::Str(&batch_id)],
            ),
            pq_security_bits: self.config.target_pq_security_bits,
            classical_fallback_disabled: true,
            attested_at_height: self.monero_height,
            expires_at_height: self.monero_height + self.config.attestation_ttl_blocks,
            status: VaultAttestationStatus::StrongQuorum,
        })
        .expect("devnet PQ attestation inserts");
        self.insert_low_fee_rebate_audit(LowFeeVaultAuditEntry {
            audit_id: "refresh-rebate-vault-audit-devnet-0".to_string(),
            batch_id,
            measured_user_fee_bps: 2,
            target_user_fee_bps: self.config.max_user_refresh_fee_bps,
            vault_accounting_bps: 9_360,
            liquidity_efficiency_bps: 9_280,
            refresh_latency_blocks: 7,
            fee_sample_root: root_from_parts("devnet-fee-samples", &[HashPart::Str("0")]),
            rebate_sample_root: root_from_parts("devnet-rebate-samples", &[HashPart::Str("0")]),
            privacy_regression_root: root_from_parts(
                "devnet-privacy-regression",
                &[HashPart::Str("0")],
            ),
            accounting_evidence_root: root_from_parts(
                "devnet-accounting-evidence",
                &[HashPart::Str("0")],
            ),
            status: VaultAuditStatus::Accepted,
        })
        .expect("devnet audit inserts");
        self.publish_roots_only_record(
            "roots-only-refresh-rebate-vault-public-record-devnet-0",
            VaultPublicAudience::Public,
        )
        .expect("devnet roots-only public record publishes");
        self.refresh_roots();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bucket(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        (value / bucket_size) * bucket_size
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{STATE_ROOT_DOMAIN}-{domain}"), parts, 32)
}

fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| json!({ "id": id, "root": root }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{STATE_ROOT_DOMAIN}-{domain}"), &leaves)
}

fn set_root(domain: &str, entries: &BTreeSet<String>) -> String {
    let leaves = entries
        .iter()
        .map(|id| json!({ "id": id }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{STATE_ROOT_DOMAIN}-{domain}"), &leaves)
}
