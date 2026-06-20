use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PqLightClientFallbackResult<T> = Result<T, String>;

pub const PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION: u32 = 1;
pub const PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_ID: &str = "nebula-pq-light-client-fallback-v1";
pub const PQ_LIGHT_CLIENT_FALLBACK_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PQ_LIGHT_CLIENT_FALLBACK_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_LIGHT_CLIENT_FALLBACK_KEM_SCHEME: &str = "ML-KEM-768";
pub const PQ_LIGHT_CLIENT_FALLBACK_CHECKPOINT_SCHEME: &str = "shake256-pq-checkpoint-mirror-v1";
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_HEIGHT: u64 = 384;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_WEAK_SUBJECTIVITY_WINDOW: u64 = 10_080;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_HEADER_SYNC_WINDOW: u64 = 144;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_MIGRATION_NOTICE_WINDOW: u64 = 720;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_MIN_VERIFIER_WEIGHT_BPS: u64 = 6_700;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_EMERGENCY_WEIGHT_BPS: u64 = 7_500;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_MAX_RECOVERY_PACKET_BYTES: u64 = 64 * 1024;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_LOW_FEE_BUDGET_UNITS: u64 = 25_000;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_SPONSORED_FEE_UNITS: u64 = 4;
pub const PQ_LIGHT_CLIENT_FALLBACK_MAX_BPS: u64 = 10_000;
pub const PQ_LIGHT_CLIENT_FALLBACK_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_LIGHT_CLIENT_FALLBACK_DEVNET_MONERO_NETWORK: &str = "monero-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFallbackMode {
    NormalMirror,
    DegradedNetwork,
    VerifierKeyMigration,
    EmergencyHeaderSync,
    RecoveryOnly,
}

impl PqFallbackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NormalMirror => "normal_mirror",
            Self::DegradedNetwork => "degraded_network",
            Self::VerifierKeyMigration => "verifier_key_migration",
            Self::EmergencyHeaderSync => "emergency_header_sync",
            Self::RecoveryOnly => "recovery_only",
        }
    }

    pub fn accepts_recovery_packets(self) -> bool {
        matches!(
            self,
            Self::DegradedNetwork
                | Self::VerifierKeyMigration
                | Self::EmergencyHeaderSync
                | Self::RecoveryOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFallbackRecordStatus {
    Pending,
    Active,
    Mirrored,
    Verified,
    Sponsored,
    Expired,
    Rejected,
    Superseded,
}

impl PqFallbackRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Mirrored => "mirrored",
            Self::Verified => "verified",
            Self::Sponsored => "sponsored",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Active | Self::Mirrored | Self::Verified | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFallbackAttestationKind {
    CheckpointMirror,
    VerifierSet,
    HeaderSync,
    MoneroAnchor,
    DaAvailability,
    RecoveryPacket,
    LowFeeSponsor,
}

impl PqFallbackAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CheckpointMirror => "checkpoint_mirror",
            Self::VerifierSet => "verifier_set",
            Self::HeaderSync => "header_sync",
            Self::MoneroAnchor => "monero_anchor",
            Self::DaAvailability => "da_availability",
            Self::RecoveryPacket => "recovery_packet",
            Self::LowFeeSponsor => "low_fee_sponsor",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFallbackConfig {
    pub protocol_version: u32,
    pub protocol_id: String,
    pub signature_scheme: String,
    pub backup_signature_scheme: String,
    pub kem_scheme: String,
    pub checkpoint_scheme: String,
    pub weak_subjectivity_window_blocks: u64,
    pub emergency_header_sync_window_blocks: u64,
    pub verifier_migration_notice_blocks: u64,
    pub min_verifier_weight_bps: u64,
    pub emergency_weight_bps: u64,
    pub max_recovery_packet_bytes: u64,
    pub low_fee_budget_units: u64,
    pub sponsored_fee_units: u64,
    pub fee_asset_id: String,
    pub monero_network: String,
}

impl Default for PqLightClientFallbackConfig {
    fn default() -> Self {
        Self {
            protocol_version: PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            protocol_id: PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_ID.to_string(),
            signature_scheme: PQ_LIGHT_CLIENT_FALLBACK_SIGNATURE_SCHEME.to_string(),
            backup_signature_scheme: PQ_LIGHT_CLIENT_FALLBACK_BACKUP_SIGNATURE_SCHEME.to_string(),
            kem_scheme: PQ_LIGHT_CLIENT_FALLBACK_KEM_SCHEME.to_string(),
            checkpoint_scheme: PQ_LIGHT_CLIENT_FALLBACK_CHECKPOINT_SCHEME.to_string(),
            weak_subjectivity_window_blocks:
                PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_WEAK_SUBJECTIVITY_WINDOW,
            emergency_header_sync_window_blocks:
                PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_HEADER_SYNC_WINDOW,
            verifier_migration_notice_blocks:
                PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_MIGRATION_NOTICE_WINDOW,
            min_verifier_weight_bps: PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_MIN_VERIFIER_WEIGHT_BPS,
            emergency_weight_bps: PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_EMERGENCY_WEIGHT_BPS,
            max_recovery_packet_bytes: PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_MAX_RECOVERY_PACKET_BYTES,
            low_fee_budget_units: PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_LOW_FEE_BUDGET_UNITS,
            sponsored_fee_units: PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_SPONSORED_FEE_UNITS,
            fee_asset_id: PQ_LIGHT_CLIENT_FALLBACK_DEVNET_FEE_ASSET_ID.to_string(),
            monero_network: PQ_LIGHT_CLIENT_FALLBACK_DEVNET_MONERO_NETWORK.to_string(),
        }
    }
}

impl PqLightClientFallbackConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_light_client_fallback_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "signature_scheme": self.signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "kem_scheme": self.kem_scheme,
            "checkpoint_scheme": self.checkpoint_scheme,
            "weak_subjectivity_window_blocks": self.weak_subjectivity_window_blocks,
            "emergency_header_sync_window_blocks": self.emergency_header_sync_window_blocks,
            "verifier_migration_notice_blocks": self.verifier_migration_notice_blocks,
            "min_verifier_weight_bps": self.min_verifier_weight_bps,
            "emergency_weight_bps": self.emergency_weight_bps,
            "max_recovery_packet_bytes": self.max_recovery_packet_bytes,
            "low_fee_budget_units": self.low_fee_budget_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "fee_asset_id": self.fee_asset_id,
            "monero_network": self.monero_network,
        })
    }

    pub fn config_root(&self) -> String {
        pq_light_client_fallback_payload_root(
            "PQ-LIGHT-CLIENT-FALLBACK-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.protocol_id, "fallback protocol id")?;
        ensure_non_empty(&self.signature_scheme, "fallback signature scheme")?;
        ensure_non_empty(
            &self.backup_signature_scheme,
            "fallback backup signature scheme",
        )?;
        ensure_non_empty(&self.kem_scheme, "fallback kem scheme")?;
        ensure_non_empty(&self.checkpoint_scheme, "fallback checkpoint scheme")?;
        ensure_non_empty(&self.fee_asset_id, "fallback fee asset id")?;
        ensure_non_empty(&self.monero_network, "fallback monero network")?;
        ensure_positive(
            self.weak_subjectivity_window_blocks,
            "fallback weak subjectivity window",
        )?;
        ensure_positive(
            self.emergency_header_sync_window_blocks,
            "fallback header sync window",
        )?;
        ensure_positive(
            self.verifier_migration_notice_blocks,
            "fallback migration notice window",
        )?;
        ensure_positive(
            self.max_recovery_packet_bytes,
            "fallback recovery packet limit",
        )?;
        ensure_bps(self.min_verifier_weight_bps, "fallback verifier quorum")?;
        ensure_bps(self.emergency_weight_bps, "fallback emergency quorum")?;
        if self.protocol_version != PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION {
            return Err("fallback protocol version mismatch".to_string());
        }
        if self.emergency_weight_bps < self.min_verifier_weight_bps {
            return Err("fallback emergency quorum cannot be below verifier quorum".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCheckpointMirror {
    pub mirror_id: String,
    pub source_checkpoint_root: String,
    pub l2_block_root: String,
    pub post_state_root: String,
    pub privacy_state_root: String,
    pub contract_state_root: String,
    pub mirrored_height: u64,
    pub finalized_height: u64,
    pub status: PqFallbackRecordStatus,
}

impl PqCheckpointMirror {
    pub fn devnet(height: u64) -> Self {
        let source_checkpoint_root = devnet_root("fallback-checkpoint-source", &height.to_string());
        let l2_block_root = devnet_root("fallback-l2-block", &height.to_string());
        let post_state_root = devnet_root("fallback-post-state", &height.to_string());
        let privacy_state_root = devnet_root("fallback-privacy-state", &height.to_string());
        let contract_state_root = devnet_root("fallback-contract-state", &height.to_string());
        let mirror_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-CHECKPOINT-MIRROR-ID",
            &json!({
                "source_checkpoint_root": source_checkpoint_root,
                "l2_block_root": l2_block_root,
                "post_state_root": post_state_root,
                "mirrored_height": height,
            }),
        );
        Self {
            mirror_id,
            source_checkpoint_root,
            l2_block_root,
            post_state_root,
            privacy_state_root,
            contract_state_root,
            mirrored_height: height,
            finalized_height: height.saturating_sub(12),
            status: PqFallbackRecordStatus::Mirrored,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_checkpoint_mirror",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "mirror_id": self.mirror_id,
            "source_checkpoint_root": self.source_checkpoint_root,
            "l2_block_root": self.l2_block_root,
            "post_state_root": self.post_state_root,
            "privacy_state_root": self.privacy_state_root,
            "contract_state_root": self.contract_state_root,
            "mirrored_height": self.mirrored_height,
            "finalized_height": self.finalized_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.mirror_id, "checkpoint mirror id")?;
        ensure_non_empty(
            &self.source_checkpoint_root,
            "checkpoint source checkpoint root",
        )?;
        ensure_non_empty(&self.l2_block_root, "checkpoint l2 block root")?;
        ensure_non_empty(&self.post_state_root, "checkpoint post state root")?;
        ensure_non_empty(&self.privacy_state_root, "checkpoint privacy state root")?;
        ensure_non_empty(&self.contract_state_root, "checkpoint contract state root")?;
        if self.finalized_height > self.mirrored_height {
            return Err("checkpoint mirror finalized height exceeds mirrored height".to_string());
        }
        Ok(self.mirror_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackVerifierSet {
    pub verifier_set_id: String,
    pub previous_verifier_set_id: Option<String>,
    pub pq_public_key_root: String,
    pub backup_public_key_root: String,
    pub encrypted_contact_root: String,
    pub verifier_weight_bps: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub migration_notice_root: String,
    pub status: PqFallbackRecordStatus,
}

impl FallbackVerifierSet {
    pub fn devnet(label: &str, start_height: u64) -> Self {
        let pq_public_key_root = devnet_root("fallback-verifier-pq-key", label);
        let backup_public_key_root = devnet_root("fallback-verifier-backup-key", label);
        let encrypted_contact_root = devnet_root("fallback-verifier-contact", label);
        let migration_notice_root = devnet_root("fallback-verifier-migration", label);
        let verifier_set_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-VERIFIER-SET-ID",
            &json!({
                "label": label,
                "pq_public_key_root": pq_public_key_root,
                "backup_public_key_root": backup_public_key_root,
                "active_from_height": start_height,
            }),
        );
        Self {
            verifier_set_id,
            previous_verifier_set_id: None,
            pq_public_key_root,
            backup_public_key_root,
            encrypted_contact_root,
            verifier_weight_bps: 8_000,
            active_from_height: start_height,
            active_until_height: start_height.saturating_add(10_080),
            migration_notice_root,
            status: PqFallbackRecordStatus::Active,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.live()
            && height >= self.active_from_height
            && height <= self.active_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fallback_verifier_set",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "verifier_set_id": self.verifier_set_id,
            "previous_verifier_set_id": self.previous_verifier_set_id,
            "pq_public_key_root": self.pq_public_key_root,
            "backup_public_key_root": self.backup_public_key_root,
            "encrypted_contact_root": self.encrypted_contact_root,
            "verifier_weight_bps": self.verifier_weight_bps,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "migration_notice_root": self.migration_notice_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.verifier_set_id, "fallback verifier set id")?;
        ensure_non_empty(&self.pq_public_key_root, "fallback verifier pq key")?;
        ensure_non_empty(&self.backup_public_key_root, "fallback verifier backup key")?;
        ensure_non_empty(
            &self.encrypted_contact_root,
            "fallback verifier contact root",
        )?;
        ensure_non_empty(
            &self.migration_notice_root,
            "fallback verifier migration notice",
        )?;
        ensure_bps(self.verifier_weight_bps, "fallback verifier weight")?;
        if self.active_until_height <= self.active_from_height {
            return Err("fallback verifier set ends before start".to_string());
        }
        Ok(self.verifier_set_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyHeaderSync {
    pub header_sync_id: String,
    pub verifier_set_id: String,
    pub from_height: u64,
    pub to_height: u64,
    pub header_root: String,
    pub skip_list_root: String,
    pub accumulated_work_root: String,
    pub pq_signature_root: String,
    pub status: PqFallbackRecordStatus,
}

impl EmergencyHeaderSync {
    pub fn devnet(verifier_set_id: &str, from_height: u64, to_height: u64) -> Self {
        let header_root = devnet_root("fallback-header-root", &to_height.to_string());
        let skip_list_root = devnet_root("fallback-header-skip-list", &from_height.to_string());
        let accumulated_work_root = devnet_root("fallback-header-work", &to_height.to_string());
        let pq_signature_root = fallback_signature_root(verifier_set_id, &header_root);
        let header_sync_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-HEADER-SYNC-ID",
            &json!({
                "verifier_set_id": verifier_set_id,
                "from_height": from_height,
                "to_height": to_height,
                "header_root": header_root,
            }),
        );
        Self {
            header_sync_id,
            verifier_set_id: verifier_set_id.to_string(),
            from_height,
            to_height,
            header_root,
            skip_list_root,
            accumulated_work_root,
            pq_signature_root,
            status: PqFallbackRecordStatus::Verified,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_header_sync",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "header_sync_id": self.header_sync_id,
            "verifier_set_id": self.verifier_set_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "header_root": self.header_root,
            "skip_list_root": self.skip_list_root,
            "accumulated_work_root": self.accumulated_work_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.header_sync_id, "header sync id")?;
        ensure_non_empty(&self.verifier_set_id, "header sync verifier set")?;
        ensure_non_empty(&self.header_root, "header sync root")?;
        ensure_non_empty(&self.skip_list_root, "header sync skip list")?;
        ensure_non_empty(&self.accumulated_work_root, "header sync work root")?;
        ensure_non_empty(&self.pq_signature_root, "header sync signature root")?;
        if self.to_height < self.from_height {
            return Err("header sync ends before start".to_string());
        }
        Ok(self.header_sync_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAnchorMirror {
    pub anchor_id: String,
    pub monero_network: String,
    pub monero_height: u64,
    pub monero_block_hash_root: String,
    pub key_image_set_root: String,
    pub reserve_view_root: String,
    pub l2_bridge_event_root: String,
    pub observed_at_height: u64,
    pub status: PqFallbackRecordStatus,
}

impl MoneroAnchorMirror {
    pub fn devnet(observed_at_height: u64) -> Self {
        let monero_network = PQ_LIGHT_CLIENT_FALLBACK_DEVNET_MONERO_NETWORK.to_string();
        let monero_height = observed_at_height.saturating_mul(2);
        let monero_block_hash_root =
            devnet_root("fallback-monero-block", &monero_height.to_string());
        let key_image_set_root = devnet_root("fallback-monero-key-images", "devnet");
        let reserve_view_root = devnet_root("fallback-monero-reserve-view", "devnet");
        let l2_bridge_event_root = devnet_root("fallback-l2-bridge-events", "devnet");
        let anchor_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-MONERO-ANCHOR-ID",
            &json!({
                "monero_network": monero_network,
                "monero_height": monero_height,
                "monero_block_hash_root": monero_block_hash_root,
                "observed_at_height": observed_at_height,
            }),
        );
        Self {
            anchor_id,
            monero_network,
            monero_height,
            monero_block_hash_root,
            key_image_set_root,
            reserve_view_root,
            l2_bridge_event_root,
            observed_at_height,
            status: PqFallbackRecordStatus::Mirrored,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_anchor_mirror",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "anchor_id": self.anchor_id,
            "monero_network": self.monero_network,
            "monero_height": self.monero_height,
            "monero_block_hash_root": self.monero_block_hash_root,
            "key_image_set_root": self.key_image_set_root,
            "reserve_view_root": self.reserve_view_root,
            "l2_bridge_event_root": self.l2_bridge_event_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.anchor_id, "monero anchor id")?;
        ensure_non_empty(&self.monero_network, "monero anchor network")?;
        ensure_non_empty(&self.monero_block_hash_root, "monero anchor block hash")?;
        ensure_non_empty(&self.key_image_set_root, "monero anchor key image root")?;
        ensure_non_empty(&self.reserve_view_root, "monero anchor reserve view root")?;
        ensure_non_empty(
            &self.l2_bridge_event_root,
            "monero anchor bridge event root",
        )?;
        Ok(self.anchor_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaAvailabilityCheckpoint {
    pub da_checkpoint_id: String,
    pub l2_height: u64,
    pub namespace_root: String,
    pub erasure_commitment_root: String,
    pub sample_receipt_root: String,
    pub retained_blob_root: String,
    pub available_weight_bps: u64,
    pub status: PqFallbackRecordStatus,
}

impl DaAvailabilityCheckpoint {
    pub fn devnet(l2_height: u64) -> Self {
        let namespace_root = devnet_root("fallback-da-namespace", &l2_height.to_string());
        let erasure_commitment_root = devnet_root("fallback-da-erasure", &l2_height.to_string());
        let sample_receipt_root = devnet_root("fallback-da-samples", &l2_height.to_string());
        let retained_blob_root = devnet_root("fallback-da-retained", &l2_height.to_string());
        let da_checkpoint_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-DA-CHECKPOINT-ID",
            &json!({
                "l2_height": l2_height,
                "namespace_root": namespace_root,
                "erasure_commitment_root": erasure_commitment_root,
            }),
        );
        Self {
            da_checkpoint_id,
            l2_height,
            namespace_root,
            erasure_commitment_root,
            sample_receipt_root,
            retained_blob_root,
            available_weight_bps: 8_500,
            status: PqFallbackRecordStatus::Verified,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_availability_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "da_checkpoint_id": self.da_checkpoint_id,
            "l2_height": self.l2_height,
            "namespace_root": self.namespace_root,
            "erasure_commitment_root": self.erasure_commitment_root,
            "sample_receipt_root": self.sample_receipt_root,
            "retained_blob_root": self.retained_blob_root,
            "available_weight_bps": self.available_weight_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.da_checkpoint_id, "da checkpoint id")?;
        ensure_non_empty(&self.namespace_root, "da namespace root")?;
        ensure_non_empty(&self.erasure_commitment_root, "da erasure root")?;
        ensure_non_empty(&self.sample_receipt_root, "da sample root")?;
        ensure_non_empty(&self.retained_blob_root, "da retained blob root")?;
        ensure_bps(self.available_weight_bps, "da available weight")?;
        Ok(self.da_checkpoint_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeakSubjectivityWindow {
    pub window_id: String,
    pub anchor_height: u64,
    pub expires_at_height: u64,
    pub checkpoint_mirror_id: String,
    pub verifier_set_id: String,
    pub client_pin_root: String,
    pub status: PqFallbackRecordStatus,
}

impl WeakSubjectivityWindow {
    pub fn devnet(anchor_height: u64, checkpoint_mirror_id: &str, verifier_set_id: &str) -> Self {
        let expires_at_height =
            anchor_height.saturating_add(PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_WEAK_SUBJECTIVITY_WINDOW);
        let client_pin_root = devnet_root("fallback-ws-client-pin", checkpoint_mirror_id);
        let window_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-WS-WINDOW-ID",
            &json!({
                "anchor_height": anchor_height,
                "expires_at_height": expires_at_height,
                "checkpoint_mirror_id": checkpoint_mirror_id,
                "verifier_set_id": verifier_set_id,
            }),
        );
        Self {
            window_id,
            anchor_height,
            expires_at_height,
            checkpoint_mirror_id: checkpoint_mirror_id.to_string(),
            verifier_set_id: verifier_set_id.to_string(),
            client_pin_root,
            status: PqFallbackRecordStatus::Active,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.live() && height >= self.anchor_height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "weak_subjectivity_window",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "anchor_height": self.anchor_height,
            "expires_at_height": self.expires_at_height,
            "checkpoint_mirror_id": self.checkpoint_mirror_id,
            "verifier_set_id": self.verifier_set_id,
            "client_pin_root": self.client_pin_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.window_id, "weak subjectivity window id")?;
        ensure_non_empty(&self.checkpoint_mirror_id, "weak subjectivity checkpoint")?;
        ensure_non_empty(&self.verifier_set_id, "weak subjectivity verifier")?;
        ensure_non_empty(&self.client_pin_root, "weak subjectivity client pin")?;
        if self.expires_at_height <= self.anchor_height {
            return Err("weak subjectivity window expires before anchor".to_string());
        }
        Ok(self.window_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelaySponsorship {
    pub sponsorship_id: String,
    pub lane_id: String,
    pub sponsor_commitment_root: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub sponsored_fee_units: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub privacy_preserving: bool,
    pub status: PqFallbackRecordStatus,
}

impl LowFeeRelaySponsorship {
    pub fn devnet(height: u64) -> Self {
        let lane_id = "fallback-private-relay".to_string();
        let sponsor_commitment_root = devnet_root("fallback-sponsor", &lane_id);
        let fee_asset_id = PQ_LIGHT_CLIENT_FALLBACK_DEVNET_FEE_ASSET_ID.to_string();
        let sponsorship_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-SPONSORSHIP-ID",
            &json!({
                "lane_id": lane_id,
                "sponsor_commitment_root": sponsor_commitment_root,
                "valid_from_height": height,
            }),
        );
        Self {
            sponsorship_id,
            lane_id,
            sponsor_commitment_root,
            fee_asset_id,
            budget_units: PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_LOW_FEE_BUDGET_UNITS,
            sponsored_fee_units: PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_SPONSORED_FEE_UNITS,
            valid_from_height: height,
            valid_until_height: height.saturating_add(720),
            privacy_preserving: true,
            status: PqFallbackRecordStatus::Sponsored,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.live() && height >= self.valid_from_height && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_relay_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "lane_id": self.lane_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "privacy_preserving": self.privacy_preserving,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.sponsorship_id, "relay sponsorship id")?;
        ensure_non_empty(&self.lane_id, "relay sponsorship lane")?;
        ensure_non_empty(&self.sponsor_commitment_root, "relay sponsorship sponsor")?;
        ensure_non_empty(&self.fee_asset_id, "relay sponsorship fee asset")?;
        if self.budget_units == 0 {
            return Err("relay sponsorship budget cannot be zero".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("relay sponsorship ends before start".to_string());
        }
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPacket {
    pub packet_id: String,
    pub checkpoint_mirror_id: String,
    pub header_sync_id: String,
    pub da_checkpoint_id: String,
    pub encrypted_payload_root: String,
    pub payload_size_bytes: u64,
    pub repair_hint_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqFallbackRecordStatus,
}

impl RecoveryPacket {
    pub fn devnet(
        checkpoint_mirror_id: &str,
        header_sync_id: &str,
        da_checkpoint_id: &str,
        height: u64,
    ) -> Self {
        let encrypted_payload_root = devnet_root("fallback-recovery-payload", checkpoint_mirror_id);
        let repair_hint_root = devnet_root("fallback-recovery-hint", header_sync_id);
        let packet_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-RECOVERY-PACKET-ID",
            &json!({
                "checkpoint_mirror_id": checkpoint_mirror_id,
                "header_sync_id": header_sync_id,
                "da_checkpoint_id": da_checkpoint_id,
                "encrypted_payload_root": encrypted_payload_root,
                "issued_at_height": height,
            }),
        );
        Self {
            packet_id,
            checkpoint_mirror_id: checkpoint_mirror_id.to_string(),
            header_sync_id: header_sync_id.to_string(),
            da_checkpoint_id: da_checkpoint_id.to_string(),
            encrypted_payload_root,
            payload_size_bytes: 16 * 1024,
            repair_hint_root,
            issued_at_height: height,
            expires_at_height: height.saturating_add(144),
            status: PqFallbackRecordStatus::Active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recovery_packet",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "checkpoint_mirror_id": self.checkpoint_mirror_id,
            "header_sync_id": self.header_sync_id,
            "da_checkpoint_id": self.da_checkpoint_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "payload_size_bytes": self.payload_size_bytes,
            "repair_hint_root": self.repair_hint_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self, max_packet_bytes: u64) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.packet_id, "recovery packet id")?;
        ensure_non_empty(&self.checkpoint_mirror_id, "recovery packet checkpoint")?;
        ensure_non_empty(&self.header_sync_id, "recovery packet header sync")?;
        ensure_non_empty(&self.da_checkpoint_id, "recovery packet da checkpoint")?;
        ensure_non_empty(&self.encrypted_payload_root, "recovery packet payload")?;
        ensure_non_empty(&self.repair_hint_root, "recovery packet repair hint")?;
        if self.payload_size_bytes == 0 || self.payload_size_bytes > max_packet_bytes {
            return Err("recovery packet payload size outside limit".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("recovery packet expires before issue height".to_string());
        }
        Ok(self.packet_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorFallbackAttestation {
    pub attestation_id: String,
    pub validator_id: String,
    pub kind: PqFallbackAttestationKind,
    pub subject_id: String,
    pub signed_root: String,
    pub signature_root: String,
    pub weight_bps: u64,
    pub signed_at_height: u64,
    pub status: PqFallbackRecordStatus,
}

impl ValidatorFallbackAttestation {
    pub fn devnet(
        validator_id: &str,
        kind: PqFallbackAttestationKind,
        subject_id: &str,
        signed_at_height: u64,
    ) -> Self {
        let signed_root = devnet_root("fallback-attested-subject", subject_id);
        let signature_root = fallback_signature_root(validator_id, &signed_root);
        let attestation_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-ATTESTATION-ID",
            &json!({
                "validator_id": validator_id,
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "signed_root": signed_root,
                "signed_at_height": signed_at_height,
            }),
        );
        Self {
            attestation_id,
            validator_id: validator_id.to_string(),
            kind,
            subject_id: subject_id.to_string(),
            signed_root,
            signature_root,
            weight_bps: 3_400,
            signed_at_height,
            status: PqFallbackRecordStatus::Verified,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_fallback_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "validator_id": self.validator_id,
            "attestation_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "signed_root": self.signed_root,
            "signature_root": self.signature_root,
            "weight_bps": self.weight_bps,
            "signed_at_height": self.signed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.attestation_id, "validator attestation id")?;
        ensure_non_empty(&self.validator_id, "validator attestation validator")?;
        ensure_non_empty(&self.subject_id, "validator attestation subject")?;
        ensure_non_empty(&self.signed_root, "validator attestation signed root")?;
        ensure_non_empty(&self.signature_root, "validator attestation signature")?;
        ensure_bps(self.weight_bps, "validator attestation weight")?;
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFallbackPublicRecord {
    pub record_id: String,
    pub subject_id: String,
    pub record_root: String,
    pub published_at_height: u64,
    pub status: PqFallbackRecordStatus,
}

impl PqFallbackPublicRecord {
    pub fn devnet(subject_id: &str, height: u64) -> Self {
        let record_root = devnet_root("fallback-public-record", subject_id);
        let record_id = pq_light_client_fallback_id(
            "PQ-LIGHT-CLIENT-FALLBACK-PUBLIC-RECORD-ID",
            &json!({
                "subject_id": subject_id,
                "record_root": record_root,
                "published_at_height": height,
            }),
        );
        Self {
            record_id,
            subject_id: subject_id.to_string(),
            record_root,
            published_at_height: height,
            status: PqFallbackRecordStatus::Verified,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fallback_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "record_root": self.record_root,
            "published_at_height": self.published_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        ensure_non_empty(&self.record_id, "fallback public record id")?;
        ensure_non_empty(&self.subject_id, "fallback public record subject")?;
        ensure_non_empty(&self.record_root, "fallback public record root")?;
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFallbackRoots {
    pub config_root: String,
    pub checkpoint_mirror_root: String,
    pub verifier_set_root: String,
    pub emergency_header_sync_root: String,
    pub monero_anchor_root: String,
    pub da_availability_root: String,
    pub weak_subjectivity_root: String,
    pub low_fee_sponsorship_root: String,
    pub recovery_packet_root: String,
    pub validator_attestation_root: String,
    pub public_record_root: String,
}

impl PqLightClientFallbackRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_light_client_fallback_roots",
            "config_root": self.config_root,
            "checkpoint_mirror_root": self.checkpoint_mirror_root,
            "verifier_set_root": self.verifier_set_root,
            "emergency_header_sync_root": self.emergency_header_sync_root,
            "monero_anchor_root": self.monero_anchor_root,
            "da_availability_root": self.da_availability_root,
            "weak_subjectivity_root": self.weak_subjectivity_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "recovery_packet_root": self.recovery_packet_root,
            "validator_attestation_root": self.validator_attestation_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        pq_light_client_fallback_payload_root(
            "PQ-LIGHT-CLIENT-FALLBACK-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFallbackCounters {
    pub checkpoint_mirror_count: u64,
    pub verifier_set_count: u64,
    pub active_verifier_set_count: u64,
    pub emergency_header_sync_count: u64,
    pub monero_anchor_count: u64,
    pub da_availability_count: u64,
    pub weak_subjectivity_window_count: u64,
    pub active_weak_subjectivity_window_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub recovery_packet_count: u64,
    pub live_recovery_packet_count: u64,
    pub validator_attestation_count: u64,
    pub verified_validator_attestation_count: u64,
    pub public_record_count: u64,
}

impl PqLightClientFallbackCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_light_client_fallback_counters",
            "checkpoint_mirror_count": self.checkpoint_mirror_count,
            "verifier_set_count": self.verifier_set_count,
            "active_verifier_set_count": self.active_verifier_set_count,
            "emergency_header_sync_count": self.emergency_header_sync_count,
            "monero_anchor_count": self.monero_anchor_count,
            "da_availability_count": self.da_availability_count,
            "weak_subjectivity_window_count": self.weak_subjectivity_window_count,
            "active_weak_subjectivity_window_count": self.active_weak_subjectivity_window_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "recovery_packet_count": self.recovery_packet_count,
            "live_recovery_packet_count": self.live_recovery_packet_count,
            "validator_attestation_count": self.validator_attestation_count,
            "verified_validator_attestation_count": self.verified_validator_attestation_count,
            "public_record_count": self.public_record_count,
        })
    }

    pub fn counters_root(&self) -> String {
        pq_light_client_fallback_payload_root(
            "PQ-LIGHT-CLIENT-FALLBACK-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFallbackState {
    pub height: u64,
    pub mode: PqFallbackMode,
    pub config: PqLightClientFallbackConfig,
    pub checkpoint_mirrors: BTreeMap<String, PqCheckpointMirror>,
    pub verifier_sets: BTreeMap<String, FallbackVerifierSet>,
    pub emergency_header_syncs: BTreeMap<String, EmergencyHeaderSync>,
    pub monero_anchor_mirrors: BTreeMap<String, MoneroAnchorMirror>,
    pub da_availability_checkpoints: BTreeMap<String, DaAvailabilityCheckpoint>,
    pub weak_subjectivity_windows: BTreeMap<String, WeakSubjectivityWindow>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeRelaySponsorship>,
    pub recovery_packets: BTreeMap<String, RecoveryPacket>,
    pub validator_attestations: BTreeMap<String, ValidatorFallbackAttestation>,
    pub public_records: BTreeMap<String, PqFallbackPublicRecord>,
}

impl PqLightClientFallbackState {
    pub fn devnet() -> PqLightClientFallbackResult<Self> {
        let height = PQ_LIGHT_CLIENT_FALLBACK_DEFAULT_HEIGHT;
        let config = PqLightClientFallbackConfig::default();
        let checkpoint = PqCheckpointMirror::devnet(height);
        let verifier = FallbackVerifierSet::devnet("fallback-devnet-verifier-set", height);
        let header_sync = EmergencyHeaderSync::devnet(
            &verifier.verifier_set_id,
            height.saturating_sub(32),
            height,
        );
        let monero_anchor = MoneroAnchorMirror::devnet(height);
        let da_checkpoint = DaAvailabilityCheckpoint::devnet(height);
        let ws_window = WeakSubjectivityWindow::devnet(
            height,
            &checkpoint.mirror_id,
            &verifier.verifier_set_id,
        );
        let sponsorship = LowFeeRelaySponsorship::devnet(height);
        let recovery_packet = RecoveryPacket::devnet(
            &checkpoint.mirror_id,
            &header_sync.header_sync_id,
            &da_checkpoint.da_checkpoint_id,
            height,
        );
        let checkpoint_attestation = ValidatorFallbackAttestation::devnet(
            "fallback-devnet-validator-a",
            PqFallbackAttestationKind::CheckpointMirror,
            &checkpoint.mirror_id,
            height,
        );
        let header_attestation = ValidatorFallbackAttestation::devnet(
            "fallback-devnet-validator-b",
            PqFallbackAttestationKind::HeaderSync,
            &header_sync.header_sync_id,
            height,
        );
        let public_record = PqFallbackPublicRecord::devnet(&checkpoint.mirror_id, height);

        let mut state = Self {
            height,
            mode: PqFallbackMode::DegradedNetwork,
            config,
            checkpoint_mirrors: BTreeMap::new(),
            verifier_sets: BTreeMap::new(),
            emergency_header_syncs: BTreeMap::new(),
            monero_anchor_mirrors: BTreeMap::new(),
            da_availability_checkpoints: BTreeMap::new(),
            weak_subjectivity_windows: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            recovery_packets: BTreeMap::new(),
            validator_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state
            .checkpoint_mirrors
            .insert(checkpoint.mirror_id.clone(), checkpoint);
        state
            .verifier_sets
            .insert(verifier.verifier_set_id.clone(), verifier);
        state
            .emergency_header_syncs
            .insert(header_sync.header_sync_id.clone(), header_sync);
        state
            .monero_anchor_mirrors
            .insert(monero_anchor.anchor_id.clone(), monero_anchor);
        state
            .da_availability_checkpoints
            .insert(da_checkpoint.da_checkpoint_id.clone(), da_checkpoint);
        state
            .weak_subjectivity_windows
            .insert(ws_window.window_id.clone(), ws_window);
        state
            .low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        state
            .recovery_packets
            .insert(recovery_packet.packet_id.clone(), recovery_packet);
        state.validator_attestations.insert(
            checkpoint_attestation.attestation_id.clone(),
            checkpoint_attestation,
        );
        state.validator_attestations.insert(
            header_attestation.attestation_id.clone(),
            header_attestation,
        );
        state
            .public_records
            .insert(public_record.record_id.clone(), public_record);
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqLightClientFallbackResult<()> {
        self.height = height;
        for window in self.weak_subjectivity_windows.values_mut() {
            if !window.active_at(height) && window.status.live() {
                window.status = PqFallbackRecordStatus::Expired;
            }
        }
        for sponsorship in self.low_fee_sponsorships.values_mut() {
            if !sponsorship.active_at(height) && sponsorship.status.live() {
                sponsorship.status = PqFallbackRecordStatus::Expired;
            }
        }
        for packet in self.recovery_packets.values_mut() {
            if height > packet.expires_at_height && packet.status.live() {
                packet.status = PqFallbackRecordStatus::Expired;
            }
        }
        self.validate().map(|_| ())
    }

    pub fn roots(&self) -> PqLightClientFallbackRoots {
        PqLightClientFallbackRoots {
            config_root: self.config.config_root(),
            checkpoint_mirror_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-CHECKPOINT-MIRRORS",
                self.checkpoint_mirrors
                    .values()
                    .map(PqCheckpointMirror::public_record)
                    .collect(),
            ),
            verifier_set_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-VERIFIER-SETS",
                self.verifier_sets
                    .values()
                    .map(FallbackVerifierSet::public_record)
                    .collect(),
            ),
            emergency_header_sync_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-HEADER-SYNCS",
                self.emergency_header_syncs
                    .values()
                    .map(EmergencyHeaderSync::public_record)
                    .collect(),
            ),
            monero_anchor_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-MONERO-ANCHORS",
                self.monero_anchor_mirrors
                    .values()
                    .map(MoneroAnchorMirror::public_record)
                    .collect(),
            ),
            da_availability_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-DA-CHECKPOINTS",
                self.da_availability_checkpoints
                    .values()
                    .map(DaAvailabilityCheckpoint::public_record)
                    .collect(),
            ),
            weak_subjectivity_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-WS-WINDOWS",
                self.weak_subjectivity_windows
                    .values()
                    .map(WeakSubjectivityWindow::public_record)
                    .collect(),
            ),
            low_fee_sponsorship_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-SPONSORSHIPS",
                self.low_fee_sponsorships
                    .values()
                    .map(LowFeeRelaySponsorship::public_record)
                    .collect(),
            ),
            recovery_packet_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-RECOVERY-PACKETS",
                self.recovery_packets
                    .values()
                    .map(RecoveryPacket::public_record)
                    .collect(),
            ),
            validator_attestation_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-VALIDATOR-ATTESTATIONS",
                self.validator_attestations
                    .values()
                    .map(ValidatorFallbackAttestation::public_record)
                    .collect(),
            ),
            public_record_root: value_collection_root(
                "PQ-LIGHT-CLIENT-FALLBACK-PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(PqFallbackPublicRecord::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PqLightClientFallbackCounters {
        PqLightClientFallbackCounters {
            checkpoint_mirror_count: self.checkpoint_mirrors.len() as u64,
            verifier_set_count: self.verifier_sets.len() as u64,
            active_verifier_set_count: self
                .verifier_sets
                .values()
                .filter(|set| set.active_at(self.height))
                .count() as u64,
            emergency_header_sync_count: self.emergency_header_syncs.len() as u64,
            monero_anchor_count: self.monero_anchor_mirrors.len() as u64,
            da_availability_count: self.da_availability_checkpoints.len() as u64,
            weak_subjectivity_window_count: self.weak_subjectivity_windows.len() as u64,
            active_weak_subjectivity_window_count: self
                .weak_subjectivity_windows
                .values()
                .filter(|window| window.active_at(self.height))
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.active_at(self.height))
                .count() as u64,
            recovery_packet_count: self.recovery_packets.len() as u64,
            live_recovery_packet_count: self
                .recovery_packets
                .values()
                .filter(|packet| packet.status.live() && self.height <= packet.expires_at_height)
                .count() as u64,
            validator_attestation_count: self.validator_attestations.len() as u64,
            verified_validator_attestation_count: self
                .validator_attestations
                .values()
                .filter(|attestation| attestation.status == PqFallbackRecordStatus::Verified)
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_root();
        json!({
            "kind": "pq_light_client_fallback_state_record",
            "record": record,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_light_client_fallback_state_root_from_record(&self.public_record_without_root())
    }

    pub fn validate(&self) -> PqLightClientFallbackResult<String> {
        self.config.validate()?;
        if !self.mode.accepts_recovery_packets() && !self.recovery_packets.is_empty() {
            return Err("fallback mode does not accept recovery packets".to_string());
        }
        for (id, checkpoint) in &self.checkpoint_mirrors {
            let validated = checkpoint.validate()?;
            if id != &validated {
                return Err("checkpoint mirror map key mismatch".to_string());
            }
        }
        for (id, verifier) in &self.verifier_sets {
            let validated = verifier.validate()?;
            if id != &validated {
                return Err("verifier set map key mismatch".to_string());
            }
            if verifier.verifier_weight_bps < self.config.min_verifier_weight_bps {
                return Err("verifier set is below configured quorum".to_string());
            }
        }
        for (id, sync) in &self.emergency_header_syncs {
            let validated = sync.validate()?;
            if id != &validated {
                return Err("header sync map key mismatch".to_string());
            }
            if !self.verifier_sets.contains_key(&sync.verifier_set_id) {
                return Err("header sync references unknown verifier set".to_string());
            }
        }
        for (id, anchor) in &self.monero_anchor_mirrors {
            let validated = anchor.validate()?;
            if id != &validated {
                return Err("monero anchor map key mismatch".to_string());
            }
        }
        for (id, checkpoint) in &self.da_availability_checkpoints {
            let validated = checkpoint.validate()?;
            if id != &validated {
                return Err("da availability map key mismatch".to_string());
            }
        }
        for (id, window) in &self.weak_subjectivity_windows {
            let validated = window.validate()?;
            if id != &validated {
                return Err("weak subjectivity map key mismatch".to_string());
            }
            if !self
                .checkpoint_mirrors
                .contains_key(&window.checkpoint_mirror_id)
            {
                return Err("weak subjectivity references unknown checkpoint".to_string());
            }
            if !self.verifier_sets.contains_key(&window.verifier_set_id) {
                return Err("weak subjectivity references unknown verifier set".to_string());
            }
        }
        for (id, sponsorship) in &self.low_fee_sponsorships {
            let validated = sponsorship.validate()?;
            if id != &validated {
                return Err("sponsorship map key mismatch".to_string());
            }
            if sponsorship.sponsored_fee_units > self.config.low_fee_budget_units {
                return Err("sponsored fee exceeds fallback budget".to_string());
            }
        }
        for (id, packet) in &self.recovery_packets {
            let validated = packet.validate(self.config.max_recovery_packet_bytes)?;
            if id != &validated {
                return Err("recovery packet map key mismatch".to_string());
            }
            if !self
                .checkpoint_mirrors
                .contains_key(&packet.checkpoint_mirror_id)
            {
                return Err("recovery packet references unknown checkpoint".to_string());
            }
            if !self
                .emergency_header_syncs
                .contains_key(&packet.header_sync_id)
            {
                return Err("recovery packet references unknown header sync".to_string());
            }
            if !self
                .da_availability_checkpoints
                .contains_key(&packet.da_checkpoint_id)
            {
                return Err("recovery packet references unknown da checkpoint".to_string());
            }
        }
        self.validate_attestations()?;
        for (id, record) in &self.public_records {
            let validated = record.validate()?;
            if id != &validated {
                return Err("public record map key mismatch".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_light_client_fallback_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_VERSION,
            "protocol_id": PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_ID,
            "height": self.height,
            "mode": self.mode.as_str(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "signature_scheme": self.config.signature_scheme,
            "backup_signature_scheme": self.config.backup_signature_scheme,
            "kem_scheme": self.config.kem_scheme,
            "checkpoint_scheme": self.config.checkpoint_scheme,
        })
    }

    fn validate_attestations(&self) -> PqLightClientFallbackResult<()> {
        let known_subjects = self.known_subject_ids();
        let mut weight_by_subject = BTreeMap::<String, u64>::new();
        for (id, attestation) in &self.validator_attestations {
            let validated = attestation.validate()?;
            if id != &validated {
                return Err("validator attestation map key mismatch".to_string());
            }
            if !known_subjects.contains(&attestation.subject_id) {
                return Err("validator attestation references unknown subject".to_string());
            }
            let entry = weight_by_subject
                .entry(attestation.subject_id.clone())
                .or_insert(0);
            *entry = entry.saturating_add(attestation.weight_bps);
        }
        for weight in weight_by_subject.values() {
            if *weight > PQ_LIGHT_CLIENT_FALLBACK_MAX_BPS {
                return Err("validator attestation weight exceeds max bps".to_string());
            }
        }
        Ok(())
    }

    fn known_subject_ids(&self) -> BTreeSet<String> {
        self.checkpoint_mirrors
            .keys()
            .chain(self.verifier_sets.keys())
            .chain(self.emergency_header_syncs.keys())
            .chain(self.monero_anchor_mirrors.keys())
            .chain(self.da_availability_checkpoints.keys())
            .chain(self.weak_subjectivity_windows.keys())
            .chain(self.low_fee_sponsorships.keys())
            .chain(self.recovery_packets.keys())
            .cloned()
            .collect()
    }
}

pub fn pq_light_client_fallback_state_root_from_record(record: &Value) -> String {
    pq_light_client_fallback_payload_root("PQ-LIGHT-CLIENT-FALLBACK-STATE", record)
}

pub fn pq_light_client_fallback_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn pq_light_client_fallback_id(domain: &str, payload: &Value) -> String {
    pq_light_client_fallback_payload_root(domain, payload)
}

pub fn fallback_signature_root(signer_id: &str, signed_root: &str) -> String {
    domain_hash(
        "PQ-LIGHT-CLIENT-FALLBACK-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_LIGHT_CLIENT_FALLBACK_SIGNATURE_SCHEME),
            HashPart::Str(signer_id),
            HashPart::Str(signed_root),
        ],
        32,
    )
}

fn value_collection_root(domain: &str, records: Vec<Value>) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_LIGHT_CLIENT_FALLBACK_PROTOCOL_ID),
            HashPart::Json(&json!({ "records": records })),
        ],
        32,
    )
}

fn devnet_root(scope: &str, label: &str) -> String {
    domain_hash(
        "PQ-LIGHT-CLIENT-FALLBACK-DEVNET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(label),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PqLightClientFallbackResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> PqLightClientFallbackResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> PqLightClientFallbackResult<()> {
    if value > PQ_LIGHT_CLIENT_FALLBACK_MAX_BPS {
        Err(format!("{label} exceeds max bps"))
    } else {
        Ok(())
    }
}
