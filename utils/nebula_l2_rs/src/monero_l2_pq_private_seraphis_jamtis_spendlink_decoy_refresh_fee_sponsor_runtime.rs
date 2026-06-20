use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisJamtisSpendlinkDecoyRefreshFeeSponsorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_SPENDLINK_DECOY_REFRESH_FEE_SPONSOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-jamtis-spendlink-decoy-refresh-fee-sponsor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_SPENDLINK_DECOY_REFRESH_FEE_SPONSOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STATE_ROOT_DOMAIN: &str =
    "MONERO-L2-PQ-PRIVATE-SERAPHIS-JAMTIS-SPENDLINK-DECOY-REFRESH-FEE-SPONSOR";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_196_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_846_000;
pub const DEVNET_EPOCH: u64 = 18_240;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_DECOY_POOL_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_DECOY_POOL_OUTPUTS: u64 = 786_432;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 8_850;
pub const DEFAULT_MIN_SPENDLINK_SHIELD_BPS: u64 = 8_800;
pub const DEFAULT_MIN_REFRESH_UTILITY_BPS: u64 = 8_400;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_REFRESH_FEE_BPS: u64 = 5;
pub const DEFAULT_TARGET_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_MIN_SPONSOR_SOLVENCY_BPS: u64 = 9_200;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_EPOCH: u64 = 131_072;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_TICKET: u64 = 8_192;
pub const DEFAULT_REFRESH_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const DECOY_REFRESH_QUEUE_SCHEME: &str =
    "seraphis-jamtis-spendlink-decoy-refresh-queue-root-v1";
pub const REFRESH_SPONSOR_ACCOUNT_SCHEME: &str =
    "seraphis-jamtis-refresh-fee-sponsor-account-root-v1";
pub const SPONSOR_SETTLEMENT_SCHEME: &str = "defi-style-private-refresh-sponsor-settlement-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-seraphis-jamtis-refresh-sponsor-attestation-v1";
pub const LOW_FEE_AUDIT_SCHEME: &str =
    "low-fee-seraphis-jamtis-decoy-refresh-sponsor-audit-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-seraphis-jamtis-spendlink-decoy-refresh-fee-sponsor-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_viewtags_spendlinks_ring_members_decoy_graphs_or_sponsor_identities";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshLane {
    WalletScan,
    DexSettlement,
    BridgeExit,
    MerchantReceive,
    WatchtowerRepair,
    ReorgRecovery,
    Migration,
    EmergencyPrivacy,
}

impl RefreshLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::DexSettlement => "dex_settlement",
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
            Self::ReorgRecovery => 970,
            Self::BridgeExit => 930,
            Self::Migration => 900,
            Self::DexSettlement => 870,
            Self::WatchtowerRepair => 840,
            Self::MerchantReceive => 810,
            Self::WalletScan => 780,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshStatus {
    Open,
    EntropyChecked,
    ShieldChecked,
    Sponsored,
    Queued,
    Attested,
    Settled,
    Audited,
    Sealed,
    Quarantined,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Open,
    Reserved,
    Netting,
    Settled,
    Refunded,
    Slashed,
    Exhausted,
    Rejected,
}

impl SponsorStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Reserved | Self::Netting | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Netting,
    Cleared,
    Rebalanced,
    Slashed,
    Challenged,
    Final,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAudience {
    Wallets,
    Sponsors,
    Solvers,
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
    pub hash_suite: String,
    pub decoy_refresh_queue_scheme: String,
    pub refresh_sponsor_account_scheme: String,
    pub sponsor_settlement_scheme: String,
    pub pq_attestation_scheme: String,
    pub low_fee_audit_scheme: String,
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
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_refresh_fee_bps: u64,
    pub target_sponsor_cover_bps: u64,
    pub min_sponsor_solvency_bps: u64,
    pub max_refresh_units_per_epoch: u64,
    pub max_refresh_units_per_ticket: u64,
    pub refresh_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
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
            hash_suite: HASH_SUITE.to_string(),
            decoy_refresh_queue_scheme: DECOY_REFRESH_QUEUE_SCHEME.to_string(),
            refresh_sponsor_account_scheme: REFRESH_SPONSOR_ACCOUNT_SCHEME.to_string(),
            sponsor_settlement_scheme: SPONSOR_SETTLEMENT_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            low_fee_audit_scheme: LOW_FEE_AUDIT_SCHEME.to_string(),
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
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_refresh_fee_bps: DEFAULT_MAX_USER_REFRESH_FEE_BPS,
            target_sponsor_cover_bps: DEFAULT_TARGET_SPONSOR_COVER_BPS,
            min_sponsor_solvency_bps: DEFAULT_MIN_SPONSOR_SOLVENCY_BPS,
            max_refresh_units_per_epoch: DEFAULT_MAX_REFRESH_UNITS_PER_EPOCH,
            max_refresh_units_per_ticket: DEFAULT_MAX_REFRESH_UNITS_PER_TICKET,
            refresh_ttl_blocks: DEFAULT_REFRESH_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch",
        )?;
        ensure(self.schema_version == SCHEMA_VERSION, "schema mismatch")?;
        ensure(
            self.public_bucket_size > 0,
            "public bucket size must be nonzero",
        )?;
        ensure(self.min_ring_size >= 16, "ring size floor is too low")?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size below floor",
        )?;
        ensure(
            self.target_decoy_pool_outputs >= self.min_decoy_pool_outputs,
            "target decoy pool below floor",
        )?;
        ensure(
            self.min_decoy_entropy_bps <= MAX_BPS
                && self.min_spendlink_shield_bps <= MAX_BPS
                && self.min_refresh_utility_bps <= MAX_BPS
                && self.max_user_refresh_fee_bps <= MAX_BPS
                && self.target_sponsor_cover_bps <= MAX_BPS
                && self.min_sponsor_solvency_bps <= MAX_BPS,
            "basis point config exceeds max",
        )?;
        ensure(
            self.min_pq_security_bits >= 128
                && self.target_pq_security_bits >= self.min_pq_security_bits,
            "PQ security config is below floor",
        )?;
        ensure(
            self.max_refresh_units_per_ticket <= self.max_refresh_units_per_epoch,
            "ticket refresh unit cap exceeds epoch cap",
        )?;
        ensure(
            self.refresh_ttl_blocks > 0
                && self.sponsor_ttl_blocks > 0
                && self.attestation_ttl_blocks > 0,
            "ttl config must be nonzero",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "schemes": {
                "decoy_refresh_queue": self.decoy_refresh_queue_scheme,
                "refresh_sponsor_account": self.refresh_sponsor_account_scheme,
                "sponsor_settlement": self.sponsor_settlement_scheme,
                "pq_attestation": self.pq_attestation_scheme,
                "low_fee_audit": self.low_fee_audit_scheme,
                "public_record": self.public_record_scheme,
            },
            "privacy_boundary": self.privacy_boundary,
            "public_bucket_size": self.public_bucket_size,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_decoy_pool_outputs": self.min_decoy_pool_outputs,
            "target_decoy_pool_outputs": self.target_decoy_pool_outputs,
            "min_decoy_entropy_bps": self.min_decoy_entropy_bps,
            "min_spendlink_shield_bps": self.min_spendlink_shield_bps,
            "min_refresh_utility_bps": self.min_refresh_utility_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_refresh_fee_bps": self.max_user_refresh_fee_bps,
            "target_sponsor_cover_bps": self.target_sponsor_cover_bps,
            "min_sponsor_solvency_bps": self.min_sponsor_solvency_bps,
            "max_refresh_units_per_epoch": self.max_refresh_units_per_epoch,
            "max_refresh_units_per_ticket": self.max_refresh_units_per_ticket,
            "refresh_ttl_blocks": self.refresh_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub refresh_tickets: u64,
    pub sponsor_accounts: u64,
    pub settlement_batches: u64,
    pub pq_attestations: u64,
    pub fee_audits: u64,
    pub public_records: u64,
    pub quarantined_tickets: u64,
    pub rejected_tickets: u64,
    pub slashed_sponsors: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub decoy_refresh_queue_root: String,
    pub refresh_sponsor_account_root: String,
    pub sponsor_settlement_root: String,
    pub pq_attestation_root: String,
    pub low_fee_audit_root: String,
    pub quarantined_ticket_root: String,
    pub used_sponsor_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            decoy_refresh_queue_root: empty_root("decoy-refresh-queue"),
            refresh_sponsor_account_root: empty_root("refresh-sponsor-account"),
            sponsor_settlement_root: empty_root("sponsor-settlement"),
            pq_attestation_root: empty_root("pq-attestation"),
            low_fee_audit_root: empty_root("low-fee-audit"),
            quarantined_ticket_root: empty_root("quarantined-ticket"),
            used_sponsor_nullifier_root: empty_root("used-sponsor-nullifier"),
            public_record_root: empty_root("public-record"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyRefreshTicketInput {
    pub ticket_id: String,
    pub lane: RefreshLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub ring_size: u16,
    pub refresh_unit_bucket: u64,
    pub decoy_entropy_bps: u64,
    pub spendlink_shield_bps: u64,
    pub refresh_utility_bps: u64,
    pub decoy_pool_root: String,
    pub spendlink_shield_root: String,
    pub refresh_plan_root: String,
    pub expires_at_height: u64,
    pub status: RefreshStatus,
}

impl DecoyRefreshTicketInput {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(!self.ticket_id.is_empty(), "ticket id is required")?;
        ensure(
            self.ring_size >= config.min_ring_size,
            "ticket ring size below floor",
        )?;
        ensure(
            self.output_count_bucket >= config.min_decoy_pool_outputs,
            "ticket decoy pool below floor",
        )?;
        ensure(
            self.refresh_unit_bucket <= config.max_refresh_units_per_ticket,
            "ticket refresh units exceed cap",
        )?;
        ensure(
            self.decoy_entropy_bps >= config.min_decoy_entropy_bps,
            "ticket decoy entropy below floor",
        )?;
        ensure(
            self.spendlink_shield_bps >= config.min_spendlink_shield_bps,
            "ticket spendlink shield below floor",
        )?;
        ensure(
            self.refresh_utility_bps >= config.min_refresh_utility_bps,
            "ticket utility below floor",
        )?;
        ensure(
            self.expires_at_height >= monero_height,
            "ticket is already expired",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "output_count_bucket": self.output_count_bucket,
            "ring_size": self.ring_size,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "decoy_entropy_bps": self.decoy_entropy_bps,
            "spendlink_shield_bps": self.spendlink_shield_bps,
            "refresh_utility_bps": self.refresh_utility_bps,
            "decoy_pool_root": self.decoy_pool_root,
            "spendlink_shield_root": self.spendlink_shield_root,
            "refresh_plan_root": self.refresh_plan_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("decoy-refresh-ticket", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorAccountInput {
    pub account_id: String,
    pub sponsor_bucket: String,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub solvency_bps: u64,
    pub refresh_unit_budget_bucket: u64,
    pub reserved_fee_bucket: u64,
    pub sponsor_commitment_root: String,
    pub policy_root: String,
    pub settlement_vault_root: String,
    pub expires_at_height: u64,
    pub status: SponsorStatus,
}

impl SponsorAccountInput {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(
            !self.account_id.is_empty(),
            "sponsor account id is required",
        )?;
        ensure(
            self.fee_asset_id == config.fee_asset_id,
            "sponsor uses unsupported fee asset",
        )?;
        ensure(
            self.max_user_fee_bps <= config.max_user_refresh_fee_bps,
            "sponsor user fee cap is too high",
        )?;
        ensure(
            self.sponsor_cover_bps >= config.target_sponsor_cover_bps,
            "sponsor cover below target",
        )?;
        ensure(
            self.solvency_bps >= config.min_sponsor_solvency_bps,
            "sponsor solvency below floor",
        )?;
        ensure(
            self.refresh_unit_budget_bucket <= config.max_refresh_units_per_epoch,
            "sponsor budget exceeds epoch cap",
        )?;
        ensure(
            self.expires_at_height >= monero_height,
            "sponsor account is expired",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "sponsor_bucket": self.sponsor_bucket,
            "fee_asset_id": self.fee_asset_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "solvency_bps": self.solvency_bps,
            "refresh_unit_budget_bucket": self.refresh_unit_budget_bucket,
            "reserved_fee_bucket": self.reserved_fee_bucket,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "policy_root": self.policy_root,
            "settlement_vault_root": self.settlement_vault_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-account", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorSettlementEntry {
    pub settlement_id: String,
    pub ticket_id: String,
    pub sponsor_account_id: String,
    pub sponsor_nullifier: String,
    pub refresh_unit_bucket: u64,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub netted_fee_bucket: u64,
    pub rebate_bucket: u64,
    pub settlement_receipt_root: String,
    pub defi_accounting_root: String,
    pub status: SettlementStatus,
}

impl SponsorSettlementEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.settlement_id.is_empty(), "settlement id is required")?;
        ensure(
            !self.sponsor_nullifier.is_empty(),
            "sponsor nullifier is required",
        )?;
        ensure(
            self.refresh_unit_bucket <= config.max_refresh_units_per_ticket,
            "settlement refresh units exceed ticket cap",
        )?;
        ensure(
            self.user_fee_bps <= config.max_user_refresh_fee_bps,
            "settlement user fee exceeds cap",
        )?;
        ensure(
            self.sponsor_cover_bps >= config.target_sponsor_cover_bps,
            "settlement sponsor cover below target",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "ticket_id": self.ticket_id,
            "sponsor_account_id": self.sponsor_account_id,
            "sponsor_nullifier_root": root_from_parts(
                "public-sponsor-nullifier",
                &[HashPart::Str(&self.sponsor_nullifier)]
            ),
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "netted_fee_bucket": self.netted_fee_bucket,
            "rebate_bucket": self.rebate_bucket,
            "settlement_receipt_root": self.settlement_receipt_root,
            "defi_accounting_root": self.defi_accounting_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-settlement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestationEntry {
    pub attestation_id: String,
    pub ticket_id: String,
    pub sponsor_account_id: String,
    pub signer_set_root: String,
    pub pq_transcript_root: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl PqSponsorAttestationEntry {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(
            !self.attestation_id.is_empty(),
            "attestation id is required",
        )?;
        ensure(
            self.pq_security_bits >= config.min_pq_security_bits,
            "attestation PQ security below floor",
        )?;
        ensure(
            self.classical_fallback_disabled,
            "attestation must disable classical fallback",
        )?;
        ensure(
            self.expires_at_height >= monero_height,
            "attestation is expired",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "ticket_id": self.ticket_id,
            "sponsor_account_id": self.sponsor_account_id,
            "signer_set_root": self.signer_set_root,
            "pq_transcript_root": self.pq_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "classical_fallback_disabled": self.classical_fallback_disabled,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("pq-sponsor-attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAuditEntry {
    pub audit_id: String,
    pub settlement_id: String,
    pub measured_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub sponsor_efficiency_bps: u64,
    pub refresh_latency_blocks: u64,
    pub fee_sample_root: String,
    pub privacy_regression_root: String,
    pub accounting_evidence_root: String,
    pub status: SettlementStatus,
}

impl LowFeeAuditEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.audit_id.is_empty(), "audit id is required")?;
        ensure(
            self.measured_user_fee_bps <= self.target_user_fee_bps
                && self.target_user_fee_bps <= config.max_user_refresh_fee_bps,
            "audit fee measurement exceeds target",
        )?;
        ensure(
            self.sponsor_efficiency_bps <= MAX_BPS,
            "audit efficiency exceeds max",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "settlement_id": self.settlement_id,
            "measured_user_fee_bps": self.measured_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "sponsor_efficiency_bps": self.sponsor_efficiency_bps,
            "refresh_latency_blocks": self.refresh_latency_blocks,
            "fee_sample_root": self.fee_sample_root,
            "privacy_regression_root": self.privacy_regression_root,
            "accounting_evidence_root": self.accounting_evidence_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("low-fee-audit", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub audience: PublicAudience,
    pub epoch: u64,
    pub l2_height: u64,
    pub monero_height_bucket: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub sponsor_coverage_bps: u64,
    pub attested_refresh_bps: u64,
    pub privacy_boundary: String,
}

impl RootsOnlyPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "audience": self.audience,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": self.monero_height_bucket,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "attested_refresh_bps": self.attested_refresh_bps,
            "privacy_boundary": self.privacy_boundary,
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
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub decoy_refresh_tickets: BTreeMap<String, DecoyRefreshTicketInput>,
    pub sponsor_accounts: BTreeMap<String, SponsorAccountInput>,
    pub sponsor_settlements: BTreeMap<String, SponsorSettlementEntry>,
    pub pq_attestations: BTreeMap<String, PqSponsorAttestationEntry>,
    pub low_fee_audits: BTreeMap<String, LowFeeAuditEntry>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub quarantined_ticket_ids: BTreeSet<String>,
    pub used_sponsor_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_height,
            monero_height,
            epoch,
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            decoy_refresh_tickets: BTreeMap::new(),
            sponsor_accounts: BTreeMap::new(),
            sponsor_settlements: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            low_fee_audits: BTreeMap::new(),
            public_records: BTreeMap::new(),
            quarantined_ticket_ids: BTreeSet::new(),
            used_sponsor_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet config is valid");
        state.seed_devnet();
        state
    }

    pub fn insert_decoy_refresh_ticket(&mut self, ticket: DecoyRefreshTicketInput) -> Result<()> {
        ticket.validate(&self.config, self.monero_height)?;
        ensure(
            !self.decoy_refresh_tickets.contains_key(&ticket.ticket_id),
            "duplicate decoy refresh ticket",
        )?;
        self.decoy_refresh_tickets
            .insert(ticket.ticket_id.clone(), ticket);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_sponsor_account(&mut self, account: SponsorAccountInput) -> Result<()> {
        account.validate(&self.config, self.monero_height)?;
        ensure(
            !self.sponsor_accounts.contains_key(&account.account_id),
            "duplicate sponsor account",
        )?;
        self.sponsor_accounts
            .insert(account.account_id.clone(), account);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_sponsor_settlement(&mut self, settlement: SponsorSettlementEntry) -> Result<()> {
        settlement.validate(&self.config)?;
        ensure(
            self.decoy_refresh_tickets
                .contains_key(&settlement.ticket_id),
            "settlement references unknown refresh ticket",
        )?;
        ensure(
            self.sponsor_accounts
                .contains_key(&settlement.sponsor_account_id),
            "settlement references unknown sponsor account",
        )?;
        ensure(
            !self
                .used_sponsor_nullifiers
                .contains(&settlement.sponsor_nullifier),
            "sponsor nullifier already used",
        )?;
        ensure(
            !self
                .sponsor_settlements
                .contains_key(&settlement.settlement_id),
            "duplicate sponsor settlement",
        )?;
        self.used_sponsor_nullifiers
            .insert(settlement.sponsor_nullifier.clone());
        self.sponsor_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqSponsorAttestationEntry) -> Result<()> {
        attestation.validate(&self.config, self.monero_height)?;
        ensure(
            self.decoy_refresh_tickets
                .contains_key(&attestation.ticket_id),
            "attestation references unknown refresh ticket",
        )?;
        ensure(
            self.sponsor_accounts
                .contains_key(&attestation.sponsor_account_id),
            "attestation references unknown sponsor account",
        )?;
        ensure(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate PQ sponsor attestation",
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_audit(&mut self, audit: LowFeeAuditEntry) -> Result<()> {
        audit.validate(&self.config)?;
        ensure(
            self.sponsor_settlements.contains_key(&audit.settlement_id),
            "audit references unknown settlement",
        )?;
        ensure(
            !self.low_fee_audits.contains_key(&audit.audit_id),
            "duplicate low fee audit",
        )?;
        self.low_fee_audits.insert(audit.audit_id.clone(), audit);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_ticket(&mut self, ticket_id: &str) -> Result<()> {
        ensure(
            self.decoy_refresh_tickets.contains_key(ticket_id),
            "cannot quarantine unknown ticket",
        )?;
        if self.quarantined_ticket_ids.insert(ticket_id.to_string()) {
            self.counters.quarantined_tickets += 1;
        }
        if let Some(ticket) = self.decoy_refresh_tickets.get_mut(ticket_id) {
            ticket.status = RefreshStatus::Quarantined;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_roots_only_record(
        &mut self,
        record_id: impl Into<String>,
        audience: PublicAudience,
    ) -> Result<String> {
        self.refresh_roots();
        let record_id = record_id.into();
        ensure(!record_id.is_empty(), "public record id is required")?;
        ensure(
            !self.public_records.contains_key(&record_id),
            "duplicate public record",
        )?;
        let record = RootsOnlyPublicRecord {
            record_id: record_id.clone(),
            audience,
            epoch: self.epoch,
            l2_height: self.l2_height,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            roots: self.roots.clone(),
            counters: self.counters.clone(),
            sponsor_coverage_bps: self.sponsor_coverage_bps(),
            attested_refresh_bps: self.attested_refresh_bps(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        };
        let root = record.state_root();
        self.public_records.insert(record_id, record);
        self.refresh_roots();
        Ok(root)
    }

    pub fn sponsor_coverage_bps(&self) -> u64 {
        if self.decoy_refresh_tickets.is_empty() {
            return 0;
        }
        let sponsored = self
            .sponsor_settlements
            .values()
            .filter(|entry| {
                matches!(
                    entry.status,
                    SettlementStatus::Cleared
                        | SettlementStatus::Rebalanced
                        | SettlementStatus::Final
                )
            })
            .map(|entry| entry.ticket_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        sponsored
            .saturating_mul(MAX_BPS)
            .saturating_div(self.decoy_refresh_tickets.len() as u64)
            .min(MAX_BPS)
    }

    pub fn attested_refresh_bps(&self) -> u64 {
        if self.decoy_refresh_tickets.is_empty() {
            return 0;
        }
        let attested = self
            .pq_attestations
            .values()
            .filter(|entry| entry.status.counts_for_quorum())
            .map(|entry| entry.ticket_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        attested
            .saturating_mul(MAX_BPS)
            .saturating_div(self.decoy_refresh_tickets.len() as u64)
            .min(MAX_BPS)
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
            "sponsor_coverage_bps": self.sponsor_coverage_bps(),
            "attested_refresh_bps": self.attested_refresh_bps(),
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
        self.counters.refresh_tickets = self.decoy_refresh_tickets.len() as u64;
        self.counters.sponsor_accounts = self.sponsor_accounts.len() as u64;
        self.counters.settlement_batches = self.sponsor_settlements.len() as u64;
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.counters.fee_audits = self.low_fee_audits.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.quarantined_tickets = self.quarantined_ticket_ids.len() as u64;
        self.counters.rejected_tickets = self
            .decoy_refresh_tickets
            .values()
            .filter(|ticket| ticket.status == RefreshStatus::Rejected)
            .count() as u64;
        self.counters.slashed_sponsors = self
            .sponsor_accounts
            .values()
            .filter(|account| account.status == SponsorStatus::Slashed)
            .count() as u64;
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            decoy_refresh_queue_root: map_root(
                DECOY_REFRESH_QUEUE_SCHEME,
                self.decoy_refresh_tickets
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            refresh_sponsor_account_root: map_root(
                REFRESH_SPONSOR_ACCOUNT_SCHEME,
                self.sponsor_accounts
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            sponsor_settlement_root: map_root(
                SPONSOR_SETTLEMENT_SCHEME,
                self.sponsor_settlements
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            pq_attestation_root: map_root(
                PQ_ATTESTATION_SCHEME,
                self.pq_attestations
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            low_fee_audit_root: map_root(
                LOW_FEE_AUDIT_SCHEME,
                self.low_fee_audits
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            quarantined_ticket_root: set_root("quarantined-ticket", &self.quarantined_ticket_ids),
            used_sponsor_nullifier_root: set_root(
                "used-sponsor-nullifier",
                &self.used_sponsor_nullifiers,
            ),
            public_record_root: map_root(
                PUBLIC_RECORD_SCHEME,
                self.public_records
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
        };
    }

    fn seed_devnet(&mut self) {
        let ticket_id = "seraphis-jamtis-refresh-ticket-devnet-0".to_string();
        let account_id = "refresh-fee-sponsor-account-devnet-0".to_string();
        let settlement_id = "refresh-fee-sponsor-settlement-devnet-0".to_string();
        self.insert_decoy_refresh_ticket(DecoyRefreshTicketInput {
            ticket_id: ticket_id.clone(),
            lane: RefreshLane::DexSettlement,
            epoch: self.epoch,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            output_count_bucket: self.config.target_decoy_pool_outputs,
            ring_size: self.config.target_ring_size,
            refresh_unit_bucket: 4_096,
            decoy_entropy_bps: 9_260,
            spendlink_shield_bps: 9_120,
            refresh_utility_bps: 8_950,
            decoy_pool_root: root_from_parts("devnet-decoy-pool", &[HashPart::Str(&ticket_id)]),
            spendlink_shield_root: root_from_parts(
                "devnet-spendlink-shield",
                &[HashPart::Str(&ticket_id)],
            ),
            refresh_plan_root: root_from_parts("devnet-refresh-plan", &[HashPart::Str(&ticket_id)]),
            expires_at_height: self.monero_height + self.config.refresh_ttl_blocks,
            status: RefreshStatus::Sponsored,
        })
        .expect("devnet refresh ticket inserts");
        self.insert_sponsor_account(SponsorAccountInput {
            account_id: account_id.clone(),
            sponsor_bucket: "devnet-sponsor-bucket-0".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            max_user_fee_bps: 4,
            sponsor_cover_bps: self.config.target_sponsor_cover_bps,
            solvency_bps: 9_820,
            refresh_unit_budget_bucket: 65_536,
            reserved_fee_bucket: 48,
            sponsor_commitment_root: root_from_parts(
                "devnet-sponsor-commitment",
                &[HashPart::Str(&account_id)],
            ),
            policy_root: root_from_parts("devnet-sponsor-policy", &[HashPart::Str(&account_id)]),
            settlement_vault_root: root_from_parts(
                "devnet-settlement-vault",
                &[HashPart::Str(&account_id)],
            ),
            expires_at_height: self.monero_height + self.config.sponsor_ttl_blocks,
            status: SponsorStatus::Settled,
        })
        .expect("devnet sponsor account inserts");
        self.insert_sponsor_settlement(SponsorSettlementEntry {
            settlement_id: settlement_id.clone(),
            ticket_id: ticket_id.clone(),
            sponsor_account_id: account_id.clone(),
            sponsor_nullifier: "devnet-private-sponsor-nullifier-0".to_string(),
            refresh_unit_bucket: 4_096,
            user_fee_bps: 3,
            sponsor_cover_bps: self.config.target_sponsor_cover_bps,
            netted_fee_bucket: 28,
            rebate_bucket: 6,
            settlement_receipt_root: root_from_parts(
                "devnet-settlement-receipt",
                &[HashPart::Str(&settlement_id)],
            ),
            defi_accounting_root: root_from_parts(
                "devnet-defi-accounting",
                &[HashPart::Str(&settlement_id)],
            ),
            status: SettlementStatus::Final,
        })
        .expect("devnet sponsor settlement inserts");
        self.insert_pq_attestation(PqSponsorAttestationEntry {
            attestation_id: "pq-refresh-sponsor-attestation-devnet-0".to_string(),
            ticket_id: ticket_id.clone(),
            sponsor_account_id: account_id,
            signer_set_root: root_from_parts("devnet-pq-signers", &[HashPart::Str("0")]),
            pq_transcript_root: root_from_parts(
                "devnet-pq-transcript",
                &[HashPart::Str(&ticket_id)],
            ),
            pq_security_bits: self.config.target_pq_security_bits,
            classical_fallback_disabled: true,
            attested_at_height: self.monero_height,
            expires_at_height: self.monero_height + self.config.attestation_ttl_blocks,
            status: AttestationStatus::StrongQuorum,
        })
        .expect("devnet PQ attestation inserts");
        self.insert_low_fee_audit(LowFeeAuditEntry {
            audit_id: "refresh-fee-sponsor-audit-devnet-0".to_string(),
            settlement_id,
            measured_user_fee_bps: 3,
            target_user_fee_bps: self.config.max_user_refresh_fee_bps,
            sponsor_efficiency_bps: 9_340,
            refresh_latency_blocks: 8,
            fee_sample_root: root_from_parts("devnet-fee-samples", &[HashPart::Str("0")]),
            privacy_regression_root: root_from_parts(
                "devnet-privacy-regression",
                &[HashPart::Str("0")],
            ),
            accounting_evidence_root: root_from_parts(
                "devnet-accounting-evidence",
                &[HashPart::Str("0")],
            ),
            status: SettlementStatus::Final,
        })
        .expect("devnet audit inserts");
        self.publish_roots_only_record(
            "roots-only-refresh-sponsor-public-record-devnet-0",
            PublicAudience::Public,
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
