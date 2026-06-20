use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateJamtisAddressRotationRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = MoneroL2PqPrivateJamtisAddressRotationRuntimeResult<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_ADDRESS_ROTATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-address-rotation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_ADDRESS_ROTATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-l2-pq-private-jamtis-address-rotation-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_094_400;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_WALLET_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-jamtis-wallet-rotation-v1";
pub const JAMTIS_ROTATION_SCHEME: &str = "monero-jamtis-address-rotation-commitment-root-v1";
pub const VIEW_TAG_MIGRATION_SCHEME: &str = "monero-jamtis-view-tag-migration-root-v1";
pub const PQ_WALLET_ATTESTATION_SCHEME: &str = "pq-jamtis-wallet-attestation-root-v1";
pub const SUBADDRESS_COMPATIBILITY_SCHEME: &str =
    "monero-jamtis-subaddress-compatibility-lane-root-v1";
pub const LOW_FEE_SPONSORSHIP_SCHEME: &str = "low-fee-jamtis-address-rotation-sponsorship-root-v1";
pub const LINKABILITY_GUARD_SCHEME: &str = "jamtis-linkability-guard-counter-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "jamtis-address-rotation-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "jamtis-address-rotation-public-record-root-v1";
pub const STATE_ROOT_DOMAIN: &str = "MONERO-L2-PQ-PRIVATE-JAMTIS-ADDRESS-ROTATION-STATE";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const DEFAULT_EPOCH_GRACE_BLOCKS: u64 = 144;
pub const DEFAULT_VIEW_TAG_MIGRATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SUBADDRESS_COMPATIBILITY_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 216;
pub const DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 = 18_000;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_ROTATION_BATCH_SIZE: u32 = 128;
pub const DEFAULT_LINKABILITY_ALARM_THRESHOLD: u64 = 3;
pub const DEFAULT_DAILY_REDACTION_BUDGET: u64 = 96;
pub const DEFAULT_DAILY_VIEW_TAG_BUDGET: u64 = 262_144;
pub const DEFAULT_DAILY_ROTATION_BUDGET: u64 = 512;
pub const MAX_ROTATION_EPOCHS: usize = 262_144;
pub const MAX_VIEW_TAG_MIGRATIONS: usize = 2_097_152;
pub const MAX_WALLET_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SUBADDRESS_LANES: usize = 1_048_576;
pub const MAX_SPONSORSHIPS: usize = 1_048_576;
pub const MAX_LINKABILITY_GUARDS: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationLane {
    LowFee,
    Fast,
    Merchant,
    Defi,
    Token,
    WalletRecovery,
    BridgeAudit,
    Emergency,
}

impl RotationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Fast => "fast",
            Self::Merchant => "merchant",
            Self::Defi => "defi",
            Self::Token => "token",
            Self::WalletRecovery => "wallet_recovery",
            Self::BridgeAudit => "bridge_audit",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::BridgeAudit => 960,
            Self::WalletRecovery => 940,
            Self::Fast => 920,
            Self::Defi => 860,
            Self::Token => 820,
            Self::Merchant => 780,
            Self::LowFee => 700,
        }
    }

    pub fn fee_cap(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_target_micro_units,
            Self::Fast | Self::Emergency => config.max_user_fee_micro_units,
            Self::Merchant
            | Self::Defi
            | Self::Token
            | Self::WalletRecovery
            | Self::BridgeAudit => config.max_user_fee_micro_units.saturating_mul(8) / 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Drafted,
    Open,
    ViewTagsCommitted,
    Attested,
    Compatible,
    Sponsored,
    Guarded,
    Redacted,
    Anchored,
    Finalized,
    Cancelled,
    Rejected,
    Expired,
    Slashed,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Open => "open",
            Self::ViewTagsCommitted => "view_tags_committed",
            Self::Attested => "attested",
            Self::Compatible => "compatible",
            Self::Sponsored => "sponsored",
            Self::Guarded => "guarded",
            Self::Redacted => "redacted",
            Self::Anchored => "anchored",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::ViewTagsCommitted
                | Self::Attested
                | Self::Compatible
                | Self::Sponsored
                | Self::Guarded
                | Self::Redacted
                | Self::Anchored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagMigrationStatus {
    Committed,
    WalletBound,
    CompatibilityChecked,
    Published,
    Superseded,
    Expired,
    Rejected,
}

impl ViewTagMigrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::WalletBound => "wallet_bound",
            Self::CompatibilityChecked => "compatibility_checked",
            Self::Published => "published",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakPqEvidence,
    Superseded,
    Revoked,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakPqEvidence => "weak_pq_evidence",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityMode {
    NativeJamtis,
    LegacySubaddress,
    DualReceive,
    MerchantStatic,
    AuditOnly,
    RecoveryOnly,
}

impl CompatibilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeJamtis => "native_jamtis",
            Self::LegacySubaddress => "legacy_subaddress",
            Self::DualReceive => "dual_receive",
            Self::MerchantStatic => "merchant_static",
            Self::AuditOnly => "audit_only",
            Self::RecoveryOnly => "recovery_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    ViewTags,
    AddressMap,
    WalletAttestation,
    SubaddressLane,
    SponsorReceipt,
    GuardCounter,
    PublicRecord,
    BridgeAudit,
}

impl BudgetScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTags => "view_tags",
            Self::AddressMap => "address_map",
            Self::WalletAttestation => "wallet_attestation",
            Self::SubaddressLane => "subaddress_lane",
            Self::SponsorReceipt => "sponsor_receipt",
            Self::GuardCounter => "guard_counter",
            Self::PublicRecord => "public_record",
            Self::BridgeAudit => "bridge_audit",
        }
    }

    pub fn cost(self) -> u64 {
        match self {
            Self::ViewTags => 1,
            Self::AddressMap => 8,
            Self::WalletAttestation => 10,
            Self::SubaddressLane => 6,
            Self::SponsorReceipt => 4,
            Self::GuardCounter => 3,
            Self::PublicRecord => 2,
            Self::BridgeAudit => 12,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub bridge_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub activation_height: u64,
    pub epoch_length_blocks: u64,
    pub epoch_grace_blocks: u64,
    pub view_tag_migration_ttl_blocks: u64,
    pub subaddress_compatibility_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_micro_units: u64,
    pub low_fee_target_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub rotation_batch_size: u32,
    pub linkability_alarm_threshold: u64,
    pub daily_redaction_budget: u64,
    pub daily_view_tag_budget: u64,
    pub daily_rotation_budget: u64,
    pub hash_suite: String,
    pub pq_wallet_attestation_suite: String,
    pub jamtis_rotation_scheme: String,
    pub view_tag_migration_scheme: String,
    pub pq_wallet_attestation_scheme: String,
    pub subaddress_compatibility_scheme: String,
    pub low_fee_sponsorship_scheme: String,
    pub linkability_guard_scheme: String,
    pub redaction_budget_scheme: String,
    pub public_record_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            activation_height: DEVNET_HEIGHT,
            epoch_length_blocks: DEFAULT_EPOCH_LENGTH_BLOCKS,
            epoch_grace_blocks: DEFAULT_EPOCH_GRACE_BLOCKS,
            view_tag_migration_ttl_blocks: DEFAULT_VIEW_TAG_MIGRATION_TTL_BLOCKS,
            subaddress_compatibility_ttl_blocks: DEFAULT_SUBADDRESS_COMPATIBILITY_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            sponsorship_ttl_blocks: DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rotation_batch_size: DEFAULT_ROTATION_BATCH_SIZE,
            linkability_alarm_threshold: DEFAULT_LINKABILITY_ALARM_THRESHOLD,
            daily_redaction_budget: DEFAULT_DAILY_REDACTION_BUDGET,
            daily_view_tag_budget: DEFAULT_DAILY_VIEW_TAG_BUDGET,
            daily_rotation_budget: DEFAULT_DAILY_ROTATION_BUDGET,
            hash_suite: HASH_SUITE.to_string(),
            pq_wallet_attestation_suite: PQ_WALLET_ATTESTATION_SUITE.to_string(),
            jamtis_rotation_scheme: JAMTIS_ROTATION_SCHEME.to_string(),
            view_tag_migration_scheme: VIEW_TAG_MIGRATION_SCHEME.to_string(),
            pq_wallet_attestation_scheme: PQ_WALLET_ATTESTATION_SCHEME.to_string(),
            subaddress_compatibility_scheme: SUBADDRESS_COMPATIBILITY_SCHEME.to_string(),
            low_fee_sponsorship_scheme: LOW_FEE_SPONSORSHIP_SCHEME.to_string(),
            linkability_guard_scheme: LINKABILITY_GUARD_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "activation_height": self.activation_height,
            "asset_id": self.asset_id,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "bridge_id": self.bridge_id,
            "chain_id": self.chain_id,
            "daily_redaction_budget": self.daily_redaction_budget,
            "daily_rotation_budget": self.daily_rotation_budget,
            "daily_view_tag_budget": self.daily_view_tag_budget,
            "epoch_grace_blocks": self.epoch_grace_blocks,
            "epoch_length_blocks": self.epoch_length_blocks,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "jamtis_rotation_scheme": self.jamtis_rotation_scheme,
            "l2_network": self.l2_network,
            "linkability_alarm_threshold": self.linkability_alarm_threshold,
            "linkability_guard_scheme": self.linkability_guard_scheme,
            "low_fee_sponsorship_scheme": self.low_fee_sponsorship_scheme,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "monero_network": self.monero_network,
            "pq_wallet_attestation_scheme": self.pq_wallet_attestation_scheme,
            "pq_wallet_attestation_suite": self.pq_wallet_attestation_suite,
            "protocol_version": self.protocol_version,
            "public_record_scheme": self.public_record_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "rotation_batch_size": self.rotation_batch_size,
            "schema_version": self.schema_version,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "subaddress_compatibility_scheme": self.subaddress_compatibility_scheme,
            "subaddress_compatibility_ttl_blocks": self.subaddress_compatibility_ttl_blocks,
            "view_tag_migration_scheme": self.view_tag_migration_scheme,
            "view_tag_migration_ttl_blocks": self.view_tag_migration_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub rotation_epochs: u64,
    pub live_rotation_epochs: u64,
    pub finalized_rotation_epochs: u64,
    pub view_tag_migrations: u64,
    pub wallet_attestations: u64,
    pub accepted_wallet_attestations: u64,
    pub subaddress_compatibility_lanes: u64,
    pub low_fee_sponsorships: u64,
    pub active_sponsorships: u64,
    pub linkability_guards: u64,
    pub linkability_alarms: u64,
    pub redaction_budgets: u64,
    pub redaction_units_reserved: u64,
    pub redaction_units_spent: u64,
    pub public_records: u64,
    pub deterministic_roots: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "accepted_wallet_attestations": self.accepted_wallet_attestations,
            "active_sponsorships": self.active_sponsorships,
            "deterministic_roots": self.deterministic_roots,
            "finalized_rotation_epochs": self.finalized_rotation_epochs,
            "linkability_alarms": self.linkability_alarms,
            "linkability_guards": self.linkability_guards,
            "live_rotation_epochs": self.live_rotation_epochs,
            "low_fee_sponsorships": self.low_fee_sponsorships,
            "public_records": self.public_records,
            "redaction_budgets": self.redaction_budgets,
            "redaction_units_reserved": self.redaction_units_reserved,
            "redaction_units_spent": self.redaction_units_spent,
            "rotation_epochs": self.rotation_epochs,
            "subaddress_compatibility_lanes": self.subaddress_compatibility_lanes,
            "view_tag_migrations": self.view_tag_migrations,
            "wallet_attestations": self.wallet_attestations,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub rotation_epoch_root: String,
    pub view_tag_migration_root: String,
    pub pq_wallet_attestation_root: String,
    pub subaddress_compatibility_root: String,
    pub low_fee_sponsorship_root: String,
    pub linkability_guard_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "linkability_guard_root": self.linkability_guard_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "pq_wallet_attestation_root": self.pq_wallet_attestation_root,
            "public_record_root": self.public_record_root,
            "redaction_budget_root": self.redaction_budget_root,
            "rotation_epoch_root": self.rotation_epoch_root,
            "state_root": self.state_root,
            "subaddress_compatibility_root": self.subaddress_compatibility_root,
            "view_tag_migration_root": self.view_tag_migration_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RotationEpoch {
    pub epoch_id: String,
    pub lane: RotationLane,
    pub status: RotationStatus,
    pub start_height: u64,
    pub close_height: u64,
    pub grace_close_height: u64,
    pub wallet_set_commitment: String,
    pub old_jamtis_root: String,
    pub new_jamtis_root: String,
    pub view_tag_migration_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_cap_micro_units: u64,
    pub sponsor_id: Option<String>,
    pub guard_counter_id: Option<String>,
    pub public_record_id: String,
}

impl RotationEpoch {
    pub fn new(
        config: &Config,
        epoch_id: impl Into<String>,
        lane: RotationLane,
        start_height: u64,
        wallet_set_commitment: impl Into<String>,
    ) -> Self {
        let epoch_id = epoch_id.into();
        let close_height = start_height.saturating_add(config.epoch_length_blocks);
        let grace_close_height = close_height.saturating_add(config.epoch_grace_blocks);
        let wallet_set_commitment = wallet_set_commitment.into();
        let old_jamtis_root = root_from_parts(
            "JAMTIS-ROTATION-OLD-ROOT",
            &[&epoch_id, &wallet_set_commitment, lane.as_str()],
        );
        let new_jamtis_root = root_from_parts(
            "JAMTIS-ROTATION-NEW-ROOT",
            &[&epoch_id, &wallet_set_commitment, lane.as_str()],
        );
        let view_tag_migration_root = root_from_parts(
            "JAMTIS-ROTATION-VIEW-TAG-ROOT",
            &[&epoch_id, &wallet_set_commitment],
        );
        let public_record_id = root_from_parts("JAMTIS-ROTATION-PUBLIC-ID", &[&epoch_id]);
        Self {
            epoch_id,
            lane,
            status: RotationStatus::Open,
            start_height,
            close_height,
            grace_close_height,
            wallet_set_commitment,
            old_jamtis_root,
            new_jamtis_root,
            view_tag_migration_root,
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            fee_cap_micro_units: lane.fee_cap(config),
            sponsor_id: None,
            guard_counter_id: None,
            public_record_id,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "close_height": self.close_height,
            "epoch_id": self.epoch_id,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "grace_close_height": self.grace_close_height,
            "guard_counter_id": self.guard_counter_id,
            "lane": self.lane.as_str(),
            "new_jamtis_root": self.new_jamtis_root,
            "old_jamtis_root": self.old_jamtis_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "public_record_id": self.public_record_id,
            "sponsor_id": self.sponsor_id,
            "start_height": self.start_height,
            "status": self.status.as_str(),
            "view_tag_migration_root": self.view_tag_migration_root,
            "wallet_set_commitment": self.wallet_set_commitment,
        })
    }

    pub fn commitment(&self) -> String {
        root_from_record("JAMTIS-ROTATION-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ViewTagMigrationCommitment {
    pub migration_id: String,
    pub epoch_id: String,
    pub status: ViewTagMigrationStatus,
    pub source_view_tag_root: String,
    pub target_view_tag_root: String,
    pub migration_commitment: String,
    pub wallet_batch_root: String,
    pub compatibility_lane_id: Option<String>,
    pub expires_at_height: u64,
    pub redaction_units_reserved: u64,
}

impl ViewTagMigrationCommitment {
    pub fn new(
        config: &Config,
        migration_id: impl Into<String>,
        epoch: &RotationEpoch,
        wallet_batch_root: impl Into<String>,
    ) -> Self {
        let migration_id = migration_id.into();
        let wallet_batch_root = wallet_batch_root.into();
        let source_view_tag_root =
            root_from_parts("JAMTIS-SOURCE-VIEW-TAGS", &[&epoch.epoch_id, &migration_id]);
        let target_view_tag_root =
            root_from_parts("JAMTIS-TARGET-VIEW-TAGS", &[&epoch.epoch_id, &migration_id]);
        let migration_commitment = root_from_parts(
            "JAMTIS-VIEW-TAG-MIGRATION-COMMITMENT",
            &[
                &source_view_tag_root,
                &target_view_tag_root,
                &wallet_batch_root,
            ],
        );
        Self {
            migration_id,
            epoch_id: epoch.epoch_id.clone(),
            status: ViewTagMigrationStatus::Committed,
            source_view_tag_root,
            target_view_tag_root,
            migration_commitment,
            wallet_batch_root,
            compatibility_lane_id: None,
            expires_at_height: epoch
                .start_height
                .saturating_add(config.view_tag_migration_ttl_blocks),
            redaction_units_reserved: BudgetScope::ViewTags.cost(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "compatibility_lane_id": self.compatibility_lane_id,
            "epoch_id": self.epoch_id,
            "expires_at_height": self.expires_at_height,
            "migration_commitment": self.migration_commitment,
            "migration_id": self.migration_id,
            "redaction_units_reserved": self.redaction_units_reserved,
            "source_view_tag_root": self.source_view_tag_root,
            "status": self.status.as_str(),
            "target_view_tag_root": self.target_view_tag_root,
            "wallet_batch_root": self.wallet_batch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqWalletAttestation {
    pub attestation_id: String,
    pub epoch_id: String,
    pub wallet_commitment: String,
    pub pq_public_key_root: String,
    pub hybrid_signature_root: String,
    pub attestation_status: AttestationStatus,
    pub security_bits: u16,
    pub watcher_weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqWalletAttestation {
    pub fn new(
        config: &Config,
        attestation_id: impl Into<String>,
        epoch: &RotationEpoch,
        wallet_commitment: impl Into<String>,
        watcher_weight: u64,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let wallet_commitment = wallet_commitment.into();
        let pq_public_key_root = root_from_parts(
            "JAMTIS-PQ-PUBLIC-KEYS",
            &[&attestation_id, &wallet_commitment],
        );
        let hybrid_signature_root = root_from_parts(
            "JAMTIS-HYBRID-SIGNATURES",
            &[&attestation_id, &epoch.epoch_id],
        );
        Self {
            attestation_id,
            epoch_id: epoch.epoch_id.clone(),
            wallet_commitment,
            pq_public_key_root,
            hybrid_signature_root,
            attestation_status: AttestationStatus::Accepted,
            security_bits: config.min_pq_security_bits,
            watcher_weight,
            issued_at_height: epoch.start_height,
            expires_at_height: epoch
                .start_height
                .saturating_add(config.attestation_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_status": self.attestation_status.as_str(),
            "epoch_id": self.epoch_id,
            "expires_at_height": self.expires_at_height,
            "hybrid_signature_root": self.hybrid_signature_root,
            "issued_at_height": self.issued_at_height,
            "pq_public_key_root": self.pq_public_key_root,
            "security_bits": self.security_bits,
            "wallet_commitment": self.wallet_commitment,
            "watcher_weight": self.watcher_weight,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubaddressCompatibilityLane {
    pub lane_id: String,
    pub epoch_id: String,
    pub mode: CompatibilityMode,
    pub legacy_subaddress_root: String,
    pub jamtis_receive_root: String,
    pub payment_id_commitment_root: String,
    pub wallet_scan_hint_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

impl SubaddressCompatibilityLane {
    pub fn new(
        config: &Config,
        lane_id: impl Into<String>,
        epoch: &RotationEpoch,
        mode: CompatibilityMode,
    ) -> Self {
        let lane_id = lane_id.into();
        Self {
            legacy_subaddress_root: root_from_parts(
                "JAMTIS-LEGACY-SUBADDRESS-ROOT",
                &[&lane_id, &epoch.epoch_id],
            ),
            jamtis_receive_root: root_from_parts(
                "JAMTIS-COMPAT-RECEIVE-ROOT",
                &[&lane_id, &epoch.epoch_id],
            ),
            payment_id_commitment_root: root_from_parts(
                "JAMTIS-PAYMENT-ID-COMMITMENT-ROOT",
                &[&lane_id],
            ),
            wallet_scan_hint_root: root_from_parts("JAMTIS-SCAN-HINT-ROOT", &[&lane_id]),
            lane_id,
            epoch_id: epoch.epoch_id.clone(),
            mode,
            opened_at_height: epoch.start_height,
            expires_at_height: epoch
                .start_height
                .saturating_add(config.subaddress_compatibility_ttl_blocks),
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active": self.active,
            "epoch_id": self.epoch_id,
            "expires_at_height": self.expires_at_height,
            "jamtis_receive_root": self.jamtis_receive_root,
            "lane_id": self.lane_id,
            "legacy_subaddress_root": self.legacy_subaddress_root,
            "mode": self.mode.as_str(),
            "opened_at_height": self.opened_at_height,
            "payment_id_commitment_root": self.payment_id_commitment_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeRotationSponsorship {
    pub sponsorship_id: String,
    pub epoch_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub covered_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub cover_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

impl LowFeeRotationSponsorship {
    pub fn new(
        config: &Config,
        sponsorship_id: impl Into<String>,
        epoch: &RotationEpoch,
        sponsor_commitment: impl Into<String>,
    ) -> Self {
        let sponsorship_id = sponsorship_id.into();
        let user_fee_micro_units = epoch.lane.fee_cap(config);
        let covered_fee_micro_units =
            user_fee_micro_units.saturating_mul(config.sponsor_cover_bps) / MAX_BPS;
        Self {
            sponsorship_id,
            epoch_id: epoch.epoch_id.clone(),
            sponsor_commitment: sponsor_commitment.into(),
            fee_asset_id: config.fee_asset_id.clone(),
            covered_fee_micro_units,
            user_fee_micro_units,
            cover_bps: config.sponsor_cover_bps,
            opened_at_height: epoch.start_height,
            expires_at_height: epoch
                .start_height
                .saturating_add(config.sponsorship_ttl_blocks),
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active": self.active,
            "cover_bps": self.cover_bps,
            "covered_fee_micro_units": self.covered_fee_micro_units,
            "epoch_id": self.epoch_id,
            "expires_at_height": self.expires_at_height,
            "fee_asset_id": self.fee_asset_id,
            "opened_at_height": self.opened_at_height,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsorship_id": self.sponsorship_id,
            "user_fee_micro_units": self.user_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LinkabilityGuardCounter {
    pub guard_id: String,
    pub epoch_id: String,
    pub wallet_cluster_commitment: String,
    pub observed_reuse_count: u64,
    pub view_tag_overlap_count: u64,
    pub subaddress_overlap_count: u64,
    pub alarm_threshold: u64,
    pub alarmed: bool,
    pub last_observed_height: u64,
}

impl LinkabilityGuardCounter {
    pub fn new(
        config: &Config,
        guard_id: impl Into<String>,
        epoch: &RotationEpoch,
        wallet_cluster_commitment: impl Into<String>,
    ) -> Self {
        Self {
            guard_id: guard_id.into(),
            epoch_id: epoch.epoch_id.clone(),
            wallet_cluster_commitment: wallet_cluster_commitment.into(),
            observed_reuse_count: 0,
            view_tag_overlap_count: 0,
            subaddress_overlap_count: 0,
            alarm_threshold: config.linkability_alarm_threshold,
            alarmed: false,
            last_observed_height: epoch.start_height,
        }
    }

    pub fn observe(&mut self, view_tag_overlap: u64, subaddress_overlap: u64, height: u64) {
        self.observed_reuse_count = self.observed_reuse_count.saturating_add(1);
        self.view_tag_overlap_count = self.view_tag_overlap_count.saturating_add(view_tag_overlap);
        self.subaddress_overlap_count = self
            .subaddress_overlap_count
            .saturating_add(subaddress_overlap);
        self.last_observed_height = height;
        self.alarmed = self.observed_reuse_count >= self.alarm_threshold
            || self.view_tag_overlap_count >= self.alarm_threshold
            || self.subaddress_overlap_count >= self.alarm_threshold;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "alarmed": self.alarmed,
            "alarm_threshold": self.alarm_threshold,
            "epoch_id": self.epoch_id,
            "guard_id": self.guard_id,
            "last_observed_height": self.last_observed_height,
            "observed_reuse_count": self.observed_reuse_count,
            "subaddress_overlap_count": self.subaddress_overlap_count,
            "view_tag_overlap_count": self.view_tag_overlap_count,
            "wallet_cluster_commitment": self.wallet_cluster_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub epoch_id: String,
    pub scope: BudgetScope,
    pub wallet_group_commitment: String,
    pub daily_limit: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub reset_height: u64,
}

impl RedactionBudget {
    pub fn new(
        config: &Config,
        budget_id: impl Into<String>,
        epoch: &RotationEpoch,
        scope: BudgetScope,
        wallet_group_commitment: impl Into<String>,
    ) -> Self {
        let daily_limit = match scope {
            BudgetScope::ViewTags => config.daily_view_tag_budget,
            BudgetScope::PublicRecord | BudgetScope::AddressMap | BudgetScope::BridgeAudit => {
                config.daily_redaction_budget
            }
            _ => config.daily_rotation_budget,
        };
        Self {
            budget_id: budget_id.into(),
            epoch_id: epoch.epoch_id.clone(),
            scope,
            wallet_group_commitment: wallet_group_commitment.into(),
            daily_limit,
            reserved_units: scope.cost(),
            spent_units: 0,
            remaining_units: daily_limit.saturating_sub(scope.cost()),
            reset_height: epoch
                .start_height
                .saturating_add(config.epoch_length_blocks),
        }
    }

    pub fn spend(&mut self, units: u64) -> Result<()> {
        if units > self.remaining_units {
            return Err(format!(
                "redaction budget {} exhausted: requested {}, remaining {}",
                self.budget_id, units, self.remaining_units
            ));
        }
        self.spent_units = self.spent_units.saturating_add(units);
        self.remaining_units = self.remaining_units.saturating_sub(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "daily_limit": self.daily_limit,
            "epoch_id": self.epoch_id,
            "remaining_units": self.remaining_units,
            "reserved_units": self.reserved_units,
            "reset_height": self.reset_height,
            "scope": self.scope.as_str(),
            "spent_units": self.spent_units,
            "wallet_group_commitment": self.wallet_group_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicRecordEntry {
    pub record_id: String,
    pub category: String,
    pub object_id: String,
    pub object_root: String,
    pub sequence: u64,
}

impl PublicRecordEntry {
    pub fn new(
        category: impl Into<String>,
        object_id: impl Into<String>,
        object_root: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let category = category.into();
        let object_id = object_id.into();
        let object_root = object_root.into();
        let record_id = root_from_parts(
            "JAMTIS-PUBLIC-RECORD-ID",
            &[&category, &object_id, &object_root, &sequence.to_string()],
        );
        Self {
            record_id,
            category,
            object_id,
            object_root,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "category": self.category,
            "object_id": self.object_id,
            "object_root": self.object_root,
            "record_id": self.record_id,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub rotation_epochs: BTreeMap<String, RotationEpoch>,
    pub view_tag_migrations: BTreeMap<String, ViewTagMigrationCommitment>,
    pub wallet_attestations: BTreeMap<String, PqWalletAttestation>,
    pub subaddress_lanes: BTreeMap<String, SubaddressCompatibilityLane>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeRotationSponsorship>,
    pub linkability_guards: BTreeMap<String, LinkabilityGuardCounter>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, PublicRecordEntry>,
    pub finalized_epochs: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            rotation_epochs: BTreeMap::new(),
            view_tag_migrations: BTreeMap::new(),
            wallet_attestations: BTreeMap::new(),
            subaddress_lanes: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            linkability_guards: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            finalized_epochs: BTreeSet::new(),
        };
        state.refresh();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let epoch = RotationEpoch::new(
            &state.config,
            "jamtis-rotation-epoch-0001",
            RotationLane::LowFee,
            state.config.activation_height,
            "wallet-set-commitment-devnet-0001",
        );
        let migration = ViewTagMigrationCommitment::new(
            &state.config,
            "view-tag-migration-0001",
            &epoch,
            "wallet-batch-root-devnet-0001",
        );
        let attestation = PqWalletAttestation::new(
            &state.config,
            "pq-wallet-attestation-0001",
            &epoch,
            "wallet-commitment-devnet-0001",
            7,
        );
        let lane = SubaddressCompatibilityLane::new(
            &state.config,
            "subaddress-compat-lane-0001",
            &epoch,
            CompatibilityMode::DualReceive,
        );
        let sponsorship = LowFeeRotationSponsorship::new(
            &state.config,
            "low-fee-sponsorship-0001",
            &epoch,
            "sponsor-commitment-devnet-0001",
        );
        let mut guard = LinkabilityGuardCounter::new(
            &state.config,
            "linkability-guard-0001",
            &epoch,
            "wallet-cluster-commitment-devnet-0001",
        );
        guard.observe(1, 0, state.config.activation_height.saturating_add(12));
        let mut budget = RedactionBudget::new(
            &state.config,
            "redaction-budget-0001",
            &epoch,
            BudgetScope::PublicRecord,
            "wallet-group-commitment-devnet-0001",
        );
        let _ = budget.spend(BudgetScope::PublicRecord.cost());

        state
            .insert_rotation_epoch(epoch)
            .expect("demo rotation epoch");
        state
            .insert_view_tag_migration(migration)
            .expect("demo view tag migration");
        state
            .insert_wallet_attestation(attestation)
            .expect("demo wallet attestation");
        state
            .insert_subaddress_lane(lane)
            .expect("demo subaddress lane");
        state
            .insert_low_fee_sponsorship(sponsorship)
            .expect("demo low fee sponsorship");
        state
            .insert_linkability_guard(guard)
            .expect("demo linkability guard");
        state
            .insert_redaction_budget(budget)
            .expect("demo redaction budget");
        state
            .finalize_epoch("jamtis-rotation-epoch-0001")
            .expect("demo finalization");
        state
    }

    pub fn insert_rotation_epoch(&mut self, epoch: RotationEpoch) -> Result<()> {
        ensure_capacity(
            self.rotation_epochs.len(),
            MAX_ROTATION_EPOCHS,
            "rotation epochs",
        )?;
        if epoch.pq_security_bits < self.config.min_pq_security_bits {
            return Err(format!("epoch {} below pq security floor", epoch.epoch_id));
        }
        if epoch.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!("epoch {} below privacy set floor", epoch.epoch_id));
        }
        let id = epoch.epoch_id.clone();
        self.rotation_epochs.insert(id.clone(), epoch);
        self.publish_record("rotation_epoch", &id)?;
        self.refresh();
        Ok(())
    }

    pub fn insert_view_tag_migration(
        &mut self,
        migration: ViewTagMigrationCommitment,
    ) -> Result<()> {
        ensure_capacity(
            self.view_tag_migrations.len(),
            MAX_VIEW_TAG_MIGRATIONS,
            "view tag migrations",
        )?;
        self.require_epoch(&migration.epoch_id)?;
        let id = migration.migration_id.clone();
        self.view_tag_migrations.insert(id.clone(), migration);
        self.publish_record("view_tag_migration", &id)?;
        self.refresh();
        Ok(())
    }

    pub fn insert_wallet_attestation(&mut self, attestation: PqWalletAttestation) -> Result<()> {
        ensure_capacity(
            self.wallet_attestations.len(),
            MAX_WALLET_ATTESTATIONS,
            "wallet attestations",
        )?;
        self.require_epoch(&attestation.epoch_id)?;
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "wallet attestation {} below pq security floor",
                attestation.attestation_id
            ));
        }
        let id = attestation.attestation_id.clone();
        self.wallet_attestations.insert(id.clone(), attestation);
        self.publish_record("pq_wallet_attestation", &id)?;
        self.refresh();
        Ok(())
    }

    pub fn insert_subaddress_lane(&mut self, lane: SubaddressCompatibilityLane) -> Result<()> {
        ensure_capacity(
            self.subaddress_lanes.len(),
            MAX_SUBADDRESS_LANES,
            "subaddress compatibility lanes",
        )?;
        self.require_epoch(&lane.epoch_id)?;
        let id = lane.lane_id.clone();
        self.subaddress_lanes.insert(id.clone(), lane);
        self.publish_record("subaddress_compatibility_lane", &id)?;
        self.refresh();
        Ok(())
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeRotationSponsorship,
    ) -> Result<()> {
        ensure_capacity(
            self.low_fee_sponsorships.len(),
            MAX_SPONSORSHIPS,
            "low fee sponsorships",
        )?;
        self.require_epoch(&sponsorship.epoch_id)?;
        if sponsorship.cover_bps > MAX_BPS {
            return Err(format!(
                "sponsorship {} cover bps exceeds max",
                sponsorship.sponsorship_id
            ));
        }
        let id = sponsorship.sponsorship_id.clone();
        self.low_fee_sponsorships.insert(id.clone(), sponsorship);
        self.publish_record("low_fee_sponsorship", &id)?;
        self.refresh();
        Ok(())
    }

    pub fn insert_linkability_guard(&mut self, guard: LinkabilityGuardCounter) -> Result<()> {
        ensure_capacity(
            self.linkability_guards.len(),
            MAX_LINKABILITY_GUARDS,
            "linkability guards",
        )?;
        self.require_epoch(&guard.epoch_id)?;
        let id = guard.guard_id.clone();
        self.linkability_guards.insert(id.clone(), guard);
        self.publish_record("linkability_guard", &id)?;
        self.refresh();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction budgets",
        )?;
        self.require_epoch(&budget.epoch_id)?;
        let id = budget.budget_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        self.publish_record("redaction_budget", &id)?;
        self.refresh();
        Ok(())
    }

    pub fn finalize_epoch(&mut self, epoch_id: &str) -> Result<()> {
        let epoch = self
            .rotation_epochs
            .get_mut(epoch_id)
            .ok_or_else(|| format!("unknown rotation epoch {epoch_id}"))?;
        epoch.status = RotationStatus::Finalized;
        self.finalized_epochs.insert(epoch_id.to_string());
        self.publish_record("finalized_epoch", epoch_id)?;
        self.refresh();
        Ok(())
    }

    pub fn roots_without_state_root(&self) -> Roots {
        let mut roots = self.roots.clone();
        roots.config_root =
            root_from_record("JAMTIS-ROTATION-CONFIG", &self.config.public_record());
        roots.counters_root =
            root_from_record("JAMTIS-ROTATION-COUNTERS", &self.counters.public_record());
        roots.rotation_epoch_root = map_root(
            "JAMTIS-ROTATION-EPOCHS",
            self.rotation_epochs
                .values()
                .map(RotationEpoch::public_record)
                .collect(),
        );
        roots.view_tag_migration_root = map_root(
            "JAMTIS-VIEW-TAG-MIGRATIONS",
            self.view_tag_migrations
                .values()
                .map(ViewTagMigrationCommitment::public_record)
                .collect(),
        );
        roots.pq_wallet_attestation_root = map_root(
            "JAMTIS-PQ-WALLET-ATTESTATIONS",
            self.wallet_attestations
                .values()
                .map(PqWalletAttestation::public_record)
                .collect(),
        );
        roots.subaddress_compatibility_root = map_root(
            "JAMTIS-SUBADDRESS-COMPATIBILITY-LANES",
            self.subaddress_lanes
                .values()
                .map(SubaddressCompatibilityLane::public_record)
                .collect(),
        );
        roots.low_fee_sponsorship_root = map_root(
            "JAMTIS-LOW-FEE-SPONSORSHIPS",
            self.low_fee_sponsorships
                .values()
                .map(LowFeeRotationSponsorship::public_record)
                .collect(),
        );
        roots.linkability_guard_root = map_root(
            "JAMTIS-LINKABILITY-GUARDS",
            self.linkability_guards
                .values()
                .map(LinkabilityGuardCounter::public_record)
                .collect(),
        );
        roots.redaction_budget_root = map_root(
            "JAMTIS-REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect(),
        );
        roots.public_record_root = map_root(
            "JAMTIS-PUBLIC-RECORDS",
            self.public_records
                .values()
                .map(PublicRecordEntry::public_record)
                .collect(),
        );
        roots.state_root.clear();
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "finalized_epochs": self.finalized_epochs.iter().cloned().collect::<Vec<_>>(),
            "linkability_guards": values_as_records(&self.linkability_guards),
            "low_fee_sponsorships": values_as_records(&self.low_fee_sponsorships),
            "protocol_version": PROTOCOL_VERSION,
            "public_records": values_as_records(&self.public_records),
            "redaction_budgets": values_as_records(&self.redaction_budgets),
            "roots": self.roots_without_state_root().public_record(),
            "rotation_epochs": values_as_records(&self.rotation_epochs),
            "subaddress_lanes": values_as_records(&self.subaddress_lanes),
            "view_tag_migrations": values_as_records(&self.view_tag_migrations),
            "wallet_attestations": values_as_records(&self.wallet_attestations),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn refresh(&mut self) {
        self.recount();
        self.roots = self.roots_without_state_root();
        self.roots.state_root = self.state_root();
    }

    fn recount(&mut self) {
        self.counters.rotation_epochs = self.rotation_epochs.len() as u64;
        self.counters.live_rotation_epochs = self
            .rotation_epochs
            .values()
            .filter(|epoch| epoch.status.live())
            .count() as u64;
        self.counters.finalized_rotation_epochs = self.finalized_epochs.len() as u64;
        self.counters.view_tag_migrations = self.view_tag_migrations.len() as u64;
        self.counters.wallet_attestations = self.wallet_attestations.len() as u64;
        self.counters.accepted_wallet_attestations = self
            .wallet_attestations
            .values()
            .filter(|attestation| attestation.attestation_status == AttestationStatus::Accepted)
            .count() as u64;
        self.counters.subaddress_compatibility_lanes = self.subaddress_lanes.len() as u64;
        self.counters.low_fee_sponsorships = self.low_fee_sponsorships.len() as u64;
        self.counters.active_sponsorships = self
            .low_fee_sponsorships
            .values()
            .filter(|sponsorship| sponsorship.active)
            .count() as u64;
        self.counters.linkability_guards = self.linkability_guards.len() as u64;
        self.counters.linkability_alarms = self
            .linkability_guards
            .values()
            .filter(|guard| guard.alarmed)
            .count() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.redaction_units_reserved = self
            .redaction_budgets
            .values()
            .map(|budget| budget.reserved_units)
            .sum();
        self.counters.redaction_units_spent = self
            .redaction_budgets
            .values()
            .map(|budget| budget.spent_units)
            .sum();
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.deterministic_roots = 10;
    }

    fn publish_record(&mut self, category: &str, object_id: &str) -> Result<()> {
        ensure_capacity(
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
            "public records",
        )?;
        let object_root = self
            .object_root(category, object_id)
            .ok_or_else(|| format!("cannot publish missing {category}:{object_id}"))?;
        let sequence = self.public_records.len() as u64;
        let entry = PublicRecordEntry::new(category, object_id, object_root, sequence);
        self.public_records.insert(entry.record_id.clone(), entry);
        Ok(())
    }

    fn object_root(&self, category: &str, object_id: &str) -> Option<String> {
        match category {
            "rotation_epoch" | "finalized_epoch" => self
                .rotation_epochs
                .get(object_id)
                .map(|record| root_from_record("JAMTIS-ROTATION-EPOCH", &record.public_record())),
            "view_tag_migration" => self.view_tag_migrations.get(object_id).map(|record| {
                root_from_record("JAMTIS-VIEW-TAG-MIGRATION", &record.public_record())
            }),
            "pq_wallet_attestation" => self.wallet_attestations.get(object_id).map(|record| {
                root_from_record("JAMTIS-PQ-WALLET-ATTESTATION", &record.public_record())
            }),
            "subaddress_compatibility_lane" => self.subaddress_lanes.get(object_id).map(|record| {
                root_from_record("JAMTIS-SUBADDRESS-COMPATIBILITY", &record.public_record())
            }),
            "low_fee_sponsorship" => self.low_fee_sponsorships.get(object_id).map(|record| {
                root_from_record("JAMTIS-LOW-FEE-SPONSORSHIP", &record.public_record())
            }),
            "linkability_guard" => self.linkability_guards.get(object_id).map(|record| {
                root_from_record("JAMTIS-LINKABILITY-GUARD", &record.public_record())
            }),
            "redaction_budget" => self
                .redaction_budgets
                .get(object_id)
                .map(|record| root_from_record("JAMTIS-REDACTION-BUDGET", &record.public_record())),
            _ => None,
        }
    }

    fn require_epoch(&self, epoch_id: &str) -> Result<()> {
        if self.rotation_epochs.contains_key(epoch_id) {
            Ok(())
        } else {
            Err(format!("unknown rotation epoch {epoch_id}"))
        }
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for RotationEpoch {
    fn public_record(&self) -> Value {
        RotationEpoch::public_record(self)
    }
}

impl PublicRecord for ViewTagMigrationCommitment {
    fn public_record(&self) -> Value {
        ViewTagMigrationCommitment::public_record(self)
    }
}

impl PublicRecord for PqWalletAttestation {
    fn public_record(&self) -> Value {
        PqWalletAttestation::public_record(self)
    }
}

impl PublicRecord for SubaddressCompatibilityLane {
    fn public_record(&self) -> Value {
        SubaddressCompatibilityLane::public_record(self)
    }
}

impl PublicRecord for LowFeeRotationSponsorship {
    fn public_record(&self) -> Value {
        LowFeeRotationSponsorship::public_record(self)
    }
}

impl PublicRecord for LinkabilityGuardCounter {
    fn public_record(&self) -> Value {
        LinkabilityGuardCounter::public_record(self)
    }
}

impl PublicRecord for RedactionBudget {
    fn public_record(&self) -> Value {
        RedactionBudget::public_record(self)
    }
}

impl PublicRecord for PublicRecordEntry {
    fn public_record(&self) -> Value {
        PublicRecordEntry::public_record(self)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(STATE_ROOT_DOMAIN, record)
}

fn root_from_parts(domain: &str, parts: &[&str]) -> String {
    let values = parts
        .iter()
        .map(|part| Value::String((*part).to_string()))
        .collect::<Vec<_>>();
    domain_hash(domain, &[HashPart::Json(&Value::Array(values))], 32)
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted: {current}/{max}"))
    } else {
        Ok(())
    }
}

fn values_as_records<T: PublicRecord>(records: &BTreeMap<String, T>) -> Value {
    Value::Array(records.values().map(PublicRecord::public_record).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_roots_are_stable() {
        let state = demo();
        assert_eq!(state.roots.state_root, state.state_root());
        assert_eq!(state.public_record()["state_root"], state.state_root());
        assert!(!state.roots.rotation_epoch_root.is_empty());
    }
}
