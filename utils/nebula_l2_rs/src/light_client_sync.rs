use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LightClientSyncResult<T> = Result<T, String>;

pub const LIGHT_CLIENT_SYNC_PROTOCOL_VERSION: &str = "nebula-light-client-sync-v1";
pub const LIGHT_CLIENT_SYNC_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const LIGHT_CLIENT_SYNC_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const LIGHT_CLIENT_SYNC_FILTER_SCHEME: &str = "compact-note-filter-shake256-v1";
pub const LIGHT_CLIENT_SYNC_DEFAULT_EPOCH_BLOCKS: u64 = 64;
pub const LIGHT_CLIENT_SYNC_DEFAULT_FILTER_BITS: u64 = 2_048;
pub const LIGHT_CLIENT_SYNC_DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 128;
pub const LIGHT_CLIENT_SYNC_DEFAULT_UPDATE_TTL_BLOCKS: u64 = 32;
pub const LIGHT_CLIENT_SYNC_DEFAULT_MAX_BUNDLE_CHECKPOINTS: usize = 64;
pub const LIGHT_CLIENT_SYNC_DEFAULT_MAX_WALLET_DELTAS: usize = 512;
pub const LIGHT_CLIENT_SYNC_DEFAULT_LOW_FEE_HINT_UNITS: u64 = 1_250;
pub const LIGHT_CLIENT_SYNC_STATUS_ACTIVE: &str = "active";
pub const LIGHT_CLIENT_SYNC_STATUS_PENDING: &str = "pending";
pub const LIGHT_CLIENT_SYNC_STATUS_DELIVERED: &str = "delivered";
pub const LIGHT_CLIENT_SYNC_STATUS_VERIFIED: &str = "verified";
pub const LIGHT_CLIENT_SYNC_STATUS_EXPIRED: &str = "expired";
pub const LIGHT_CLIENT_SYNC_STATUS_REJECTED: &str = "rejected";
pub const LIGHT_CLIENT_SYNC_STATUS_STALE: &str = "stale";
pub const LIGHT_CLIENT_SYNC_DEVNET_SYNCER_ID: &str = "devnet-light-syncer";
pub const LIGHT_CLIENT_SYNC_DEVNET_WALLET_ID: &str = "devnet-mobile-wallet";
pub const LIGHT_CLIENT_SYNC_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightClientSyncMode {
    FullCheckpoint,
    HeaderOnly,
    WalletDelta,
    NullifierScan,
    BridgeWatch,
    FeeHint,
    Emergency,
}

impl LightClientSyncMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FullCheckpoint => "full_checkpoint",
            Self::HeaderOnly => "header_only",
            Self::WalletDelta => "wallet_delta",
            Self::NullifierScan => "nullifier_scan",
            Self::BridgeWatch => "bridge_watch",
            Self::FeeHint => "fee_hint",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(&self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::BridgeWatch => 8_000,
            Self::NullifierScan => 7_000,
            Self::WalletDelta => 6_500,
            Self::FullCheckpoint => 6_000,
            Self::HeaderOnly => 4_500,
            Self::FeeHint => 3_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightClientPrivacyTier {
    Public,
    ViewTagOnly,
    EncryptedDeltas,
    NullifierOnly,
    FullShielded,
}

impl LightClientPrivacyTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::ViewTagOnly => "view_tag_only",
            Self::EncryptedDeltas => "encrypted_deltas",
            Self::NullifierOnly => "nullifier_only",
            Self::FullShielded => "full_shielded",
        }
    }

    pub fn hides_amounts(&self) -> bool {
        !matches!(self, Self::Public)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientSyncConfig {
    pub protocol_version: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub filter_scheme: String,
    pub epoch_blocks: u64,
    pub filter_bits: u64,
    pub scan_window_blocks: u64,
    pub update_ttl_blocks: u64,
    pub max_bundle_checkpoints: usize,
    pub max_wallet_deltas: usize,
    pub default_low_fee_hint_units: u64,
    pub fee_asset_id: String,
    pub metadata_root: String,
}

impl Default for LightClientSyncConfig {
    fn default() -> Self {
        Self {
            protocol_version: LIGHT_CLIENT_SYNC_PROTOCOL_VERSION.to_string(),
            pq_signature_scheme: LIGHT_CLIENT_SYNC_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: LIGHT_CLIENT_SYNC_PQ_KEM_SCHEME.to_string(),
            filter_scheme: LIGHT_CLIENT_SYNC_FILTER_SCHEME.to_string(),
            epoch_blocks: LIGHT_CLIENT_SYNC_DEFAULT_EPOCH_BLOCKS,
            filter_bits: LIGHT_CLIENT_SYNC_DEFAULT_FILTER_BITS,
            scan_window_blocks: LIGHT_CLIENT_SYNC_DEFAULT_SCAN_WINDOW_BLOCKS,
            update_ttl_blocks: LIGHT_CLIENT_SYNC_DEFAULT_UPDATE_TTL_BLOCKS,
            max_bundle_checkpoints: LIGHT_CLIENT_SYNC_DEFAULT_MAX_BUNDLE_CHECKPOINTS,
            max_wallet_deltas: LIGHT_CLIENT_SYNC_DEFAULT_MAX_WALLET_DELTAS,
            default_low_fee_hint_units: LIGHT_CLIENT_SYNC_DEFAULT_LOW_FEE_HINT_UNITS,
            fee_asset_id: LIGHT_CLIENT_SYNC_DEVNET_FEE_ASSET_ID.to_string(),
            metadata_root: light_client_payload_root(
                "LIGHT-CLIENT-SYNC-CONFIG-METADATA",
                &json!({
                    "mode": "devnet",
                    "goal": "fast private low-bandwidth wallet sync"
                }),
            ),
        }
    }
}

impl LightClientSyncConfig {
    pub fn validate(&self) -> LightClientSyncResult<()> {
        ensure_non_empty(&self.protocol_version, "light client protocol version")?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "light client PQ signature scheme",
        )?;
        ensure_non_empty(&self.pq_kem_scheme, "light client PQ KEM scheme")?;
        ensure_non_empty(&self.filter_scheme, "light client filter scheme")?;
        ensure_non_empty(&self.fee_asset_id, "light client fee asset")?;
        ensure_non_empty(&self.metadata_root, "light client metadata root")?;
        if self.epoch_blocks == 0 {
            return Err("light client epoch blocks cannot be zero".to_string());
        }
        if self.filter_bits == 0 {
            return Err("light client filter bits cannot be zero".to_string());
        }
        if self.scan_window_blocks == 0 {
            return Err("light client scan window cannot be zero".to_string());
        }
        if self.update_ttl_blocks == 0 {
            return Err("light client update ttl cannot be zero".to_string());
        }
        if self.max_bundle_checkpoints == 0 || self.max_wallet_deltas == 0 {
            return Err("light client bundle limits cannot be zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "light_client_sync_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "filter_scheme": self.filter_scheme,
            "epoch_blocks": self.epoch_blocks,
            "filter_bits": self.filter_bits,
            "scan_window_blocks": self.scan_window_blocks,
            "update_ttl_blocks": self.update_ttl_blocks,
            "max_bundle_checkpoints": self.max_bundle_checkpoints,
            "max_wallet_deltas": self.max_wallet_deltas,
            "default_low_fee_hint_units": self.default_low_fee_hint_units,
            "fee_asset_id": self.fee_asset_id,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-SYNC-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeMember {
    pub member_id: String,
    pub operator_label: String,
    pub pq_public_key_root: String,
    pub endpoint_commitment: String,
    pub stake_units: u64,
    pub reliability_bps: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub status: String,
}

impl SyncCommitteeMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_label: &str,
        pq_public_key_root: &str,
        endpoint_commitment: &str,
        stake_units: u64,
        reliability_bps: u64,
        active_from_height: u64,
        active_until_height: u64,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(operator_label, "sync committee operator")?;
        ensure_non_empty(pq_public_key_root, "sync committee PQ key")?;
        ensure_non_empty(endpoint_commitment, "sync committee endpoint")?;
        validate_bps(reliability_bps, "sync committee reliability")?;
        if active_until_height <= active_from_height {
            return Err("sync committee member ends before start".to_string());
        }
        let member_id = light_client_committee_member_id(
            operator_label,
            pq_public_key_root,
            endpoint_commitment,
            active_from_height,
        );
        Ok(Self {
            member_id,
            operator_label: operator_label.to_string(),
            pq_public_key_root: pq_public_key_root.to_string(),
            endpoint_commitment: endpoint_commitment.to_string(),
            stake_units,
            reliability_bps,
            active_from_height,
            active_until_height,
            status: LIGHT_CLIENT_SYNC_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn devnet(label: &str, height: u64) -> LightClientSyncResult<Self> {
        Self::new(
            label,
            &light_client_string_root("LIGHT-CLIENT-DEVNET-PQ-KEY", label),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-ENDPOINT", label),
            100_000,
            9_900,
            height,
            height.saturating_add(1_000),
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == LIGHT_CLIENT_SYNC_STATUS_ACTIVE
            && height >= self.active_from_height
            && height <= self.active_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sync_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "pq_public_key_root": self.pq_public_key_root,
            "endpoint_commitment": self.endpoint_commitment,
            "stake_units": self.stake_units,
            "reliability_bps": self.reliability_bps,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "status": self.status,
        })
    }

    pub fn member_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-COMMITTEE-MEMBER", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.member_id, "sync committee member id")?;
        ensure_non_empty(&self.operator_label, "sync committee operator")?;
        ensure_non_empty(&self.pq_public_key_root, "sync committee PQ key")?;
        ensure_non_empty(&self.endpoint_commitment, "sync committee endpoint")?;
        validate_bps(self.reliability_bps, "sync committee reliability")?;
        if self.active_until_height <= self.active_from_height {
            return Err("sync committee member invalid active range".to_string());
        }
        let expected = light_client_committee_member_id(
            &self.operator_label,
            &self.pq_public_key_root,
            &self.endpoint_commitment,
            self.active_from_height,
        );
        if self.member_id != expected {
            return Err("sync committee member id mismatch".to_string());
        }
        Ok(self.member_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactStateCheckpoint {
    pub checkpoint_id: String,
    pub height: u64,
    pub block_root: String,
    pub state_root: String,
    pub da_root: String,
    pub nullifier_root: String,
    pub note_commitment_root: String,
    pub bridge_root: String,
    pub contract_root: String,
    pub fee_root: String,
    pub committee_root: String,
    pub pq_signature_root: String,
    pub status: String,
}

impl CompactStateCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        block_root: &str,
        state_root: &str,
        da_root: &str,
        nullifier_root: &str,
        note_commitment_root: &str,
        bridge_root: &str,
        contract_root: &str,
        fee_root: &str,
        committee_root: &str,
        signer_id: &str,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(block_root, "light checkpoint block root")?;
        ensure_non_empty(state_root, "light checkpoint state root")?;
        ensure_non_empty(da_root, "light checkpoint DA root")?;
        ensure_non_empty(nullifier_root, "light checkpoint nullifier root")?;
        ensure_non_empty(note_commitment_root, "light checkpoint note root")?;
        ensure_non_empty(bridge_root, "light checkpoint bridge root")?;
        ensure_non_empty(contract_root, "light checkpoint contract root")?;
        ensure_non_empty(fee_root, "light checkpoint fee root")?;
        ensure_non_empty(committee_root, "light checkpoint committee root")?;
        ensure_non_empty(signer_id, "light checkpoint signer")?;
        let checkpoint_id = light_client_checkpoint_id(
            height,
            block_root,
            state_root,
            da_root,
            nullifier_root,
            note_commitment_root,
        );
        let pq_signature_root = light_client_signature_root(signer_id, &checkpoint_id);
        Ok(Self {
            checkpoint_id,
            height,
            block_root: block_root.to_string(),
            state_root: state_root.to_string(),
            da_root: da_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            note_commitment_root: note_commitment_root.to_string(),
            bridge_root: bridge_root.to_string(),
            contract_root: contract_root.to_string(),
            fee_root: fee_root.to_string(),
            committee_root: committee_root.to_string(),
            pq_signature_root,
            status: LIGHT_CLIENT_SYNC_STATUS_VERIFIED.to_string(),
        })
    }

    pub fn devnet(
        height: u64,
        committee_root: &str,
        signer_id: &str,
    ) -> LightClientSyncResult<Self> {
        Self::new(
            height,
            &light_client_string_root("LIGHT-CLIENT-DEVNET-BLOCK", &height.to_string()),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-STATE", &height.to_string()),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-DA", &height.to_string()),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-NULLIFIER", &height.to_string()),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-NOTE", &height.to_string()),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-BRIDGE", &height.to_string()),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-CONTRACT", &height.to_string()),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-FEE", &height.to_string()),
            committee_root,
            signer_id,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compact_state_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "block_root": self.block_root,
            "state_root": self.state_root,
            "da_root": self.da_root,
            "nullifier_root": self.nullifier_root,
            "note_commitment_root": self.note_commitment_root,
            "bridge_root": self.bridge_root,
            "contract_root": self.contract_root,
            "fee_root": self.fee_root,
            "committee_root": self.committee_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status,
        })
    }

    pub fn checkpoint_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-CHECKPOINT", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.checkpoint_id, "light checkpoint id")?;
        ensure_non_empty(&self.block_root, "light checkpoint block")?;
        ensure_non_empty(&self.state_root, "light checkpoint state")?;
        ensure_non_empty(&self.da_root, "light checkpoint DA")?;
        ensure_non_empty(&self.nullifier_root, "light checkpoint nullifier")?;
        ensure_non_empty(&self.note_commitment_root, "light checkpoint note")?;
        ensure_non_empty(&self.bridge_root, "light checkpoint bridge")?;
        ensure_non_empty(&self.contract_root, "light checkpoint contract")?;
        ensure_non_empty(&self.fee_root, "light checkpoint fee")?;
        ensure_non_empty(&self.committee_root, "light checkpoint committee")?;
        ensure_non_empty(&self.pq_signature_root, "light checkpoint signature")?;
        let expected = light_client_checkpoint_id(
            self.height,
            &self.block_root,
            &self.state_root,
            &self.da_root,
            &self.nullifier_root,
            &self.note_commitment_root,
        );
        if self.checkpoint_id != expected {
            return Err("light checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactBlockFilter {
    pub filter_id: String,
    pub checkpoint_id: String,
    pub height: u64,
    pub filter_bits: u64,
    pub note_filter_root: String,
    pub nullifier_filter_root: String,
    pub view_tag_root: String,
    pub bridge_event_filter_root: String,
    pub false_positive_bps: u64,
    pub status: String,
}

impl CompactBlockFilter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_id: &str,
        height: u64,
        filter_bits: u64,
        note_filter_root: &str,
        nullifier_filter_root: &str,
        view_tag_root: &str,
        bridge_event_filter_root: &str,
        false_positive_bps: u64,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(checkpoint_id, "light filter checkpoint")?;
        ensure_non_empty(note_filter_root, "light filter note root")?;
        ensure_non_empty(nullifier_filter_root, "light filter nullifier root")?;
        ensure_non_empty(view_tag_root, "light filter view tag root")?;
        ensure_non_empty(bridge_event_filter_root, "light filter bridge root")?;
        validate_bps(false_positive_bps, "light filter false positive bps")?;
        if filter_bits == 0 {
            return Err("light filter bits cannot be zero".to_string());
        }
        let filter_id = light_client_filter_id(
            checkpoint_id,
            height,
            note_filter_root,
            nullifier_filter_root,
            view_tag_root,
        );
        Ok(Self {
            filter_id,
            checkpoint_id: checkpoint_id.to_string(),
            height,
            filter_bits,
            note_filter_root: note_filter_root.to_string(),
            nullifier_filter_root: nullifier_filter_root.to_string(),
            view_tag_root: view_tag_root.to_string(),
            bridge_event_filter_root: bridge_event_filter_root.to_string(),
            false_positive_bps,
            status: LIGHT_CLIENT_SYNC_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn devnet(
        checkpoint: &CompactStateCheckpoint,
        filter_bits: u64,
    ) -> LightClientSyncResult<Self> {
        Self::new(
            &checkpoint.checkpoint_id,
            checkpoint.height,
            filter_bits,
            &light_client_string_root("LIGHT-CLIENT-DEVNET-NOTE-FILTER", &checkpoint.checkpoint_id),
            &light_client_string_root(
                "LIGHT-CLIENT-DEVNET-NULLIFIER-FILTER",
                &checkpoint.checkpoint_id,
            ),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-VIEW-TAG", &checkpoint.checkpoint_id),
            &light_client_string_root(
                "LIGHT-CLIENT-DEVNET-BRIDGE-FILTER",
                &checkpoint.checkpoint_id,
            ),
            25,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compact_block_filter",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "filter_id": self.filter_id,
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "filter_bits": self.filter_bits,
            "note_filter_root": self.note_filter_root,
            "nullifier_filter_root": self.nullifier_filter_root,
            "view_tag_root": self.view_tag_root,
            "bridge_event_filter_root": self.bridge_event_filter_root,
            "false_positive_bps": self.false_positive_bps,
            "status": self.status,
        })
    }

    pub fn filter_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-BLOCK-FILTER", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.filter_id, "light filter id")?;
        ensure_non_empty(&self.checkpoint_id, "light filter checkpoint")?;
        ensure_non_empty(&self.note_filter_root, "light filter note")?;
        ensure_non_empty(&self.nullifier_filter_root, "light filter nullifier")?;
        ensure_non_empty(&self.view_tag_root, "light filter view tag")?;
        ensure_non_empty(&self.bridge_event_filter_root, "light filter bridge")?;
        validate_bps(self.false_positive_bps, "light filter false positive")?;
        if self.filter_bits == 0 {
            return Err("light filter bits cannot be zero".to_string());
        }
        let expected = light_client_filter_id(
            &self.checkpoint_id,
            self.height,
            &self.note_filter_root,
            &self.nullifier_filter_root,
            &self.view_tag_root,
        );
        if self.filter_id != expected {
            return Err("light filter id mismatch".to_string());
        }
        Ok(self.filter_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletDeltaBundle {
    pub bundle_id: String,
    pub wallet_id: String,
    pub checkpoint_id: String,
    pub filter_id: String,
    pub privacy_tier: LightClientPrivacyTier,
    pub encrypted_note_root: String,
    pub encrypted_spend_root: String,
    pub view_tag_root: String,
    pub delta_count: u64,
    pub scan_from_height: u64,
    pub scan_to_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl WalletDeltaBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        checkpoint_id: &str,
        filter_id: &str,
        privacy_tier: LightClientPrivacyTier,
        encrypted_note_root: &str,
        encrypted_spend_root: &str,
        view_tag_root: &str,
        delta_count: u64,
        scan_from_height: u64,
        scan_to_height: u64,
        expires_at_height: u64,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(wallet_id, "wallet delta wallet")?;
        ensure_non_empty(checkpoint_id, "wallet delta checkpoint")?;
        ensure_non_empty(filter_id, "wallet delta filter")?;
        ensure_non_empty(encrypted_note_root, "wallet delta encrypted notes")?;
        ensure_non_empty(encrypted_spend_root, "wallet delta encrypted spends")?;
        ensure_non_empty(view_tag_root, "wallet delta view tags")?;
        if scan_to_height < scan_from_height {
            return Err("wallet delta scan range invalid".to_string());
        }
        if expires_at_height <= scan_to_height {
            return Err("wallet delta expires before scan end".to_string());
        }
        let bundle_id = light_client_wallet_delta_id(
            wallet_id,
            checkpoint_id,
            filter_id,
            encrypted_note_root,
            scan_to_height,
        );
        Ok(Self {
            bundle_id,
            wallet_id: wallet_id.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
            filter_id: filter_id.to_string(),
            privacy_tier,
            encrypted_note_root: encrypted_note_root.to_string(),
            encrypted_spend_root: encrypted_spend_root.to_string(),
            view_tag_root: view_tag_root.to_string(),
            delta_count,
            scan_from_height,
            scan_to_height,
            expires_at_height,
            status: LIGHT_CLIENT_SYNC_STATUS_PENDING.to_string(),
        })
    }

    pub fn devnet(
        wallet_id: &str,
        checkpoint: &CompactStateCheckpoint,
        filter: &CompactBlockFilter,
        expires_at_height: u64,
    ) -> LightClientSyncResult<Self> {
        Self::new(
            wallet_id,
            &checkpoint.checkpoint_id,
            &filter.filter_id,
            LightClientPrivacyTier::EncryptedDeltas,
            &light_client_string_root("LIGHT-CLIENT-DEVNET-ENCRYPTED-NOTES", wallet_id),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-ENCRYPTED-SPENDS", wallet_id),
            &filter.view_tag_root,
            3,
            checkpoint.height.saturating_sub(8),
            checkpoint.height,
            expires_at_height,
        )
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_delta_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "wallet_id": self.wallet_id,
            "checkpoint_id": self.checkpoint_id,
            "filter_id": self.filter_id,
            "privacy_tier": self.privacy_tier.as_str(),
            "hides_amounts": self.privacy_tier.hides_amounts(),
            "encrypted_note_root": self.encrypted_note_root,
            "encrypted_spend_root": self.encrypted_spend_root,
            "view_tag_root": self.view_tag_root,
            "delta_count": self.delta_count,
            "scan_from_height": self.scan_from_height,
            "scan_to_height": self.scan_to_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn delta_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-WALLET-DELTA", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.bundle_id, "wallet delta bundle id")?;
        ensure_non_empty(&self.wallet_id, "wallet delta wallet")?;
        ensure_non_empty(&self.checkpoint_id, "wallet delta checkpoint")?;
        ensure_non_empty(&self.filter_id, "wallet delta filter")?;
        ensure_non_empty(&self.encrypted_note_root, "wallet delta note root")?;
        ensure_non_empty(&self.encrypted_spend_root, "wallet delta spend root")?;
        ensure_non_empty(&self.view_tag_root, "wallet delta view tag")?;
        if self.scan_to_height < self.scan_from_height {
            return Err("wallet delta scan range invalid".to_string());
        }
        if self.expires_at_height <= self.scan_to_height {
            return Err("wallet delta expires before scan end".to_string());
        }
        let expected = light_client_wallet_delta_id(
            &self.wallet_id,
            &self.checkpoint_id,
            &self.filter_id,
            &self.encrypted_note_root,
            self.scan_to_height,
        );
        if self.bundle_id != expected {
            return Err("wallet delta bundle id mismatch".to_string());
        }
        Ok(self.delta_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierScanRequest {
    pub request_id: String,
    pub wallet_id: String,
    pub scan_tag_root: String,
    pub nullifier_prefix_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub max_false_positive_bps: u64,
    pub privacy_tier: LightClientPrivacyTier,
    pub status: String,
}

impl NullifierScanRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        scan_tag_root: &str,
        nullifier_prefix_root: &str,
        start_height: u64,
        end_height: u64,
        max_false_positive_bps: u64,
        privacy_tier: LightClientPrivacyTier,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(wallet_id, "nullifier scan wallet")?;
        ensure_non_empty(scan_tag_root, "nullifier scan tag")?;
        ensure_non_empty(nullifier_prefix_root, "nullifier scan prefix")?;
        validate_bps(max_false_positive_bps, "nullifier scan false positive")?;
        if end_height < start_height {
            return Err("nullifier scan end before start".to_string());
        }
        let request_id = light_client_nullifier_scan_id(
            wallet_id,
            scan_tag_root,
            nullifier_prefix_root,
            start_height,
            end_height,
        );
        Ok(Self {
            request_id,
            wallet_id: wallet_id.to_string(),
            scan_tag_root: scan_tag_root.to_string(),
            nullifier_prefix_root: nullifier_prefix_root.to_string(),
            start_height,
            end_height,
            max_false_positive_bps,
            privacy_tier,
            status: LIGHT_CLIENT_SYNC_STATUS_PENDING.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nullifier_scan_request",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "wallet_id": self.wallet_id,
            "scan_tag_root": self.scan_tag_root,
            "nullifier_prefix_root": self.nullifier_prefix_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "max_false_positive_bps": self.max_false_positive_bps,
            "privacy_tier": self.privacy_tier.as_str(),
            "status": self.status,
        })
    }

    pub fn request_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-NULLIFIER-SCAN", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.request_id, "nullifier scan id")?;
        ensure_non_empty(&self.wallet_id, "nullifier scan wallet")?;
        ensure_non_empty(&self.scan_tag_root, "nullifier scan tag")?;
        ensure_non_empty(&self.nullifier_prefix_root, "nullifier scan prefix")?;
        validate_bps(self.max_false_positive_bps, "nullifier scan false positive")?;
        if self.end_height < self.start_height {
            return Err("nullifier scan end before start".to_string());
        }
        let expected = light_client_nullifier_scan_id(
            &self.wallet_id,
            &self.scan_tag_root,
            &self.nullifier_prefix_root,
            self.start_height,
            self.end_height,
        );
        if self.request_id != expected {
            return Err("nullifier scan id mismatch".to_string());
        }
        Ok(self.request_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSyncHint {
    pub hint_id: String,
    pub wallet_id: String,
    pub monero_network: String,
    pub bridge_event_root: String,
    pub key_image_root: String,
    pub output_commitment_root: String,
    pub observed_height: u64,
    pub finality_depth: u64,
    pub status: String,
}

impl BridgeSyncHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        monero_network: &str,
        bridge_event_root: &str,
        key_image_root: &str,
        output_commitment_root: &str,
        observed_height: u64,
        finality_depth: u64,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(wallet_id, "bridge sync wallet")?;
        ensure_non_empty(monero_network, "bridge sync network")?;
        ensure_non_empty(bridge_event_root, "bridge sync event")?;
        ensure_non_empty(key_image_root, "bridge sync key image")?;
        ensure_non_empty(output_commitment_root, "bridge sync output commitment")?;
        if finality_depth == 0 {
            return Err("bridge sync finality depth cannot be zero".to_string());
        }
        let hint_id = light_client_bridge_hint_id(
            wallet_id,
            monero_network,
            bridge_event_root,
            output_commitment_root,
            observed_height,
        );
        Ok(Self {
            hint_id,
            wallet_id: wallet_id.to_string(),
            monero_network: monero_network.to_string(),
            bridge_event_root: bridge_event_root.to_string(),
            key_image_root: key_image_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            observed_height,
            finality_depth,
            status: LIGHT_CLIENT_SYNC_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_sync_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "hint_id": self.hint_id,
            "wallet_id": self.wallet_id,
            "monero_network": self.monero_network,
            "bridge_event_root": self.bridge_event_root,
            "key_image_root": self.key_image_root,
            "output_commitment_root": self.output_commitment_root,
            "observed_height": self.observed_height,
            "finality_depth": self.finality_depth,
            "status": self.status,
        })
    }

    pub fn hint_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-BRIDGE-HINT", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.hint_id, "bridge sync hint id")?;
        ensure_non_empty(&self.wallet_id, "bridge sync wallet")?;
        ensure_non_empty(&self.monero_network, "bridge sync network")?;
        ensure_non_empty(&self.bridge_event_root, "bridge sync event")?;
        ensure_non_empty(&self.key_image_root, "bridge sync key image")?;
        ensure_non_empty(&self.output_commitment_root, "bridge sync output")?;
        if self.finality_depth == 0 {
            return Err("bridge sync finality depth cannot be zero".to_string());
        }
        let expected = light_client_bridge_hint_id(
            &self.wallet_id,
            &self.monero_network,
            &self.bridge_event_root,
            &self.output_commitment_root,
            self.observed_height,
        );
        if self.hint_id != expected {
            return Err("bridge sync hint id mismatch".to_string());
        }
        Ok(self.hint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientFeeHint {
    pub hint_id: String,
    pub mode: LightClientSyncMode,
    pub fee_asset_id: String,
    pub suggested_fee_units: u64,
    pub low_fee_credit_units: u64,
    pub priority_weight: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub status: String,
}

impl LightClientFeeHint {
    pub fn new(
        mode: LightClientSyncMode,
        fee_asset_id: &str,
        suggested_fee_units: u64,
        low_fee_credit_units: u64,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(fee_asset_id, "light fee hint asset")?;
        if valid_until_height <= valid_from_height {
            return Err("light fee hint validity range invalid".to_string());
        }
        let hint_id = light_client_fee_hint_id(
            mode,
            fee_asset_id,
            suggested_fee_units,
            low_fee_credit_units,
            valid_from_height,
        );
        Ok(Self {
            hint_id,
            mode,
            fee_asset_id: fee_asset_id.to_string(),
            suggested_fee_units,
            low_fee_credit_units,
            priority_weight: mode.priority_weight(),
            valid_from_height,
            valid_until_height,
            status: LIGHT_CLIENT_SYNC_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == LIGHT_CLIENT_SYNC_STATUS_ACTIVE
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "light_client_fee_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "hint_id": self.hint_id,
            "mode": self.mode.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "suggested_fee_units": self.suggested_fee_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "priority_weight": self.priority_weight,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "status": self.status,
        })
    }

    pub fn hint_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-FEE-HINT", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.hint_id, "light fee hint id")?;
        ensure_non_empty(&self.fee_asset_id, "light fee hint asset")?;
        if self.valid_until_height <= self.valid_from_height {
            return Err("light fee hint validity range invalid".to_string());
        }
        let expected = light_client_fee_hint_id(
            self.mode,
            &self.fee_asset_id,
            self.suggested_fee_units,
            self.low_fee_credit_units,
            self.valid_from_height,
        );
        if self.hint_id != expected {
            return Err("light fee hint id mismatch".to_string());
        }
        Ok(self.hint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncUpdateBundle {
    pub update_id: String,
    pub wallet_id: String,
    pub checkpoint_ids: Vec<String>,
    pub delta_bundle_ids: Vec<String>,
    pub bridge_hint_ids: Vec<String>,
    pub fee_hint_ids: Vec<String>,
    pub checkpoint_root: String,
    pub delta_root: String,
    pub bridge_hint_root: String,
    pub fee_hint_root: String,
    pub syncer_id: String,
    pub pq_signature_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl SyncUpdateBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        checkpoints: &[CompactStateCheckpoint],
        deltas: &[WalletDeltaBundle],
        bridge_hints: &[BridgeSyncHint],
        fee_hints: &[LightClientFeeHint],
        syncer_id: &str,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(wallet_id, "sync update wallet")?;
        ensure_non_empty(syncer_id, "sync update syncer")?;
        if checkpoints.is_empty() {
            return Err("sync update needs at least one checkpoint".to_string());
        }
        let mut checkpoint_ids = Vec::new();
        let mut delta_bundle_ids = Vec::new();
        let mut bridge_hint_ids = Vec::new();
        let mut fee_hint_ids = Vec::new();
        for checkpoint in checkpoints {
            checkpoint.validate()?;
            checkpoint_ids.push(checkpoint.checkpoint_id.clone());
        }
        for delta in deltas {
            delta.validate()?;
            delta_bundle_ids.push(delta.bundle_id.clone());
        }
        for hint in bridge_hints {
            hint.validate()?;
            bridge_hint_ids.push(hint.hint_id.clone());
        }
        for hint in fee_hints {
            hint.validate()?;
            fee_hint_ids.push(hint.hint_id.clone());
        }
        checkpoint_ids.sort();
        delta_bundle_ids.sort();
        bridge_hint_ids.sort();
        fee_hint_ids.sort();
        let checkpoint_root =
            light_client_string_set_root("LIGHT-CLIENT-UPDATE-CHECKPOINT-ID", &checkpoint_ids);
        let delta_root =
            light_client_string_set_root("LIGHT-CLIENT-UPDATE-DELTA-ID", &delta_bundle_ids);
        let bridge_hint_root =
            light_client_string_set_root("LIGHT-CLIENT-UPDATE-BRIDGE-HINT-ID", &bridge_hint_ids);
        let fee_hint_root =
            light_client_string_set_root("LIGHT-CLIENT-UPDATE-FEE-HINT-ID", &fee_hint_ids);
        let expires_at_height = issued_at_height.saturating_add(ttl_blocks.max(1));
        let update_id = light_client_update_bundle_id(
            wallet_id,
            &checkpoint_root,
            &delta_root,
            syncer_id,
            issued_at_height,
        );
        let pq_signature_root = light_client_signature_root(syncer_id, &update_id);
        Ok(Self {
            update_id,
            wallet_id: wallet_id.to_string(),
            checkpoint_ids,
            delta_bundle_ids,
            bridge_hint_ids,
            fee_hint_ids,
            checkpoint_root,
            delta_root,
            bridge_hint_root,
            fee_hint_root,
            syncer_id: syncer_id.to_string(),
            pq_signature_root,
            issued_at_height,
            expires_at_height,
            status: LIGHT_CLIENT_SYNC_STATUS_DELIVERED.to_string(),
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sync_update_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "update_id": self.update_id,
            "wallet_id": self.wallet_id,
            "checkpoint_ids": self.checkpoint_ids,
            "delta_bundle_ids": self.delta_bundle_ids,
            "bridge_hint_ids": self.bridge_hint_ids,
            "fee_hint_ids": self.fee_hint_ids,
            "checkpoint_root": self.checkpoint_root,
            "delta_root": self.delta_root,
            "bridge_hint_root": self.bridge_hint_root,
            "fee_hint_root": self.fee_hint_root,
            "syncer_id": self.syncer_id,
            "pq_signature_root": self.pq_signature_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn update_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-UPDATE-BUNDLE", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.update_id, "sync update id")?;
        ensure_non_empty(&self.wallet_id, "sync update wallet")?;
        ensure_non_empty(&self.checkpoint_root, "sync update checkpoint root")?;
        ensure_non_empty(&self.delta_root, "sync update delta root")?;
        ensure_non_empty(&self.bridge_hint_root, "sync update bridge root")?;
        ensure_non_empty(&self.fee_hint_root, "sync update fee root")?;
        ensure_non_empty(&self.syncer_id, "sync update syncer")?;
        ensure_non_empty(&self.pq_signature_root, "sync update signature")?;
        if self.checkpoint_ids.is_empty() {
            return Err("sync update has no checkpoints".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("sync update expires before issue".to_string());
        }
        let expected = light_client_update_bundle_id(
            &self.wallet_id,
            &self.checkpoint_root,
            &self.delta_root,
            &self.syncer_id,
            self.issued_at_height,
        );
        if self.update_id != expected {
            return Err("sync update id mismatch".to_string());
        }
        Ok(self.update_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDeliveryReceipt {
    pub receipt_id: String,
    pub update_id: String,
    pub wallet_id: String,
    pub delivered_at_height: u64,
    pub verified_at_height: u64,
    pub latency_ms: u64,
    pub client_ack_root: String,
    pub status: String,
}

impl SyncDeliveryReceipt {
    pub fn new(
        update_id: &str,
        wallet_id: &str,
        delivered_at_height: u64,
        verified_at_height: u64,
        latency_ms: u64,
        client_ack_root: &str,
    ) -> LightClientSyncResult<Self> {
        ensure_non_empty(update_id, "sync receipt update")?;
        ensure_non_empty(wallet_id, "sync receipt wallet")?;
        ensure_non_empty(client_ack_root, "sync receipt ack")?;
        if verified_at_height < delivered_at_height {
            return Err("sync receipt verified before delivery".to_string());
        }
        let receipt_id = light_client_delivery_receipt_id(
            update_id,
            wallet_id,
            client_ack_root,
            delivered_at_height,
        );
        Ok(Self {
            receipt_id,
            update_id: update_id.to_string(),
            wallet_id: wallet_id.to_string(),
            delivered_at_height,
            verified_at_height,
            latency_ms,
            client_ack_root: client_ack_root.to_string(),
            status: LIGHT_CLIENT_SYNC_STATUS_VERIFIED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sync_delivery_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "update_id": self.update_id,
            "wallet_id": self.wallet_id,
            "delivered_at_height": self.delivered_at_height,
            "verified_at_height": self.verified_at_height,
            "latency_ms": self.latency_ms,
            "client_ack_root": self.client_ack_root,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-DELIVERY-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        ensure_non_empty(&self.receipt_id, "sync receipt id")?;
        ensure_non_empty(&self.update_id, "sync receipt update")?;
        ensure_non_empty(&self.wallet_id, "sync receipt wallet")?;
        ensure_non_empty(&self.client_ack_root, "sync receipt ack")?;
        if self.verified_at_height < self.delivered_at_height {
            return Err("sync receipt verified before delivery".to_string());
        }
        let expected = light_client_delivery_receipt_id(
            &self.update_id,
            &self.wallet_id,
            &self.client_ack_root,
            self.delivered_at_height,
        );
        if self.receipt_id != expected {
            return Err("sync receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientSyncRoots {
    pub config_root: String,
    pub committee_root: String,
    pub checkpoint_root: String,
    pub filter_root: String,
    pub wallet_delta_root: String,
    pub nullifier_scan_root: String,
    pub bridge_hint_root: String,
    pub fee_hint_root: String,
    pub update_bundle_root: String,
    pub delivery_receipt_root: String,
}

impl LightClientSyncRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "light_client_sync_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "committee_root": self.committee_root,
            "checkpoint_root": self.checkpoint_root,
            "filter_root": self.filter_root,
            "wallet_delta_root": self.wallet_delta_root,
            "nullifier_scan_root": self.nullifier_scan_root,
            "bridge_hint_root": self.bridge_hint_root,
            "fee_hint_root": self.fee_hint_root,
            "update_bundle_root": self.update_bundle_root,
            "delivery_receipt_root": self.delivery_receipt_root,
        })
    }

    pub fn roots_root(&self) -> String {
        light_client_payload_root("LIGHT-CLIENT-SYNC-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientSyncState {
    pub config: LightClientSyncConfig,
    pub committee_members: BTreeMap<String, SyncCommitteeMember>,
    pub checkpoints: BTreeMap<String, CompactStateCheckpoint>,
    pub filters: BTreeMap<String, CompactBlockFilter>,
    pub wallet_deltas: BTreeMap<String, WalletDeltaBundle>,
    pub nullifier_scans: BTreeMap<String, NullifierScanRequest>,
    pub bridge_hints: BTreeMap<String, BridgeSyncHint>,
    pub fee_hints: BTreeMap<String, LightClientFeeHint>,
    pub update_bundles: BTreeMap<String, SyncUpdateBundle>,
    pub delivery_receipts: BTreeMap<String, SyncDeliveryReceipt>,
    pub height: u64,
}

impl Default for LightClientSyncState {
    fn default() -> Self {
        Self {
            config: LightClientSyncConfig::default(),
            committee_members: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            filters: BTreeMap::new(),
            wallet_deltas: BTreeMap::new(),
            nullifier_scans: BTreeMap::new(),
            bridge_hints: BTreeMap::new(),
            fee_hints: BTreeMap::new(),
            update_bundles: BTreeMap::new(),
            delivery_receipts: BTreeMap::new(),
            height: 0,
        }
    }
}

impl LightClientSyncState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet(operator_label: &str) -> LightClientSyncResult<Self> {
        let mut state = Self::new();
        state.set_height(32);
        for label in [
            operator_label,
            LIGHT_CLIENT_SYNC_DEVNET_SYNCER_ID,
            "devnet-light-sync-backup",
        ] {
            let member = SyncCommitteeMember::devnet(label, 0)?;
            state.insert_committee_member(member)?;
        }
        let committee_root = state.committee_root();
        let mut checkpoints = Vec::new();
        let mut filters = Vec::new();
        for height in [16_u64, 24, 32] {
            let checkpoint = CompactStateCheckpoint::devnet(
                height,
                &committee_root,
                LIGHT_CLIENT_SYNC_DEVNET_SYNCER_ID,
            )?;
            let filter = CompactBlockFilter::devnet(&checkpoint, state.config.filter_bits)?;
            state.insert_checkpoint(checkpoint.clone())?;
            state.insert_filter(filter.clone())?;
            checkpoints.push(checkpoint);
            filters.push(filter);
        }
        let latest_checkpoint = checkpoints
            .last()
            .cloned()
            .ok_or_else(|| "devnet light client missing checkpoint".to_string())?;
        let latest_filter = filters
            .last()
            .cloned()
            .ok_or_else(|| "devnet light client missing filter".to_string())?;
        let delta = WalletDeltaBundle::devnet(
            LIGHT_CLIENT_SYNC_DEVNET_WALLET_ID,
            &latest_checkpoint,
            &latest_filter,
            state.height.saturating_add(state.config.update_ttl_blocks),
        )?;
        state.insert_wallet_delta(delta.clone())?;
        let scan = NullifierScanRequest::new(
            LIGHT_CLIENT_SYNC_DEVNET_WALLET_ID,
            &light_client_string_root("LIGHT-CLIENT-DEVNET-SCAN-TAG", "wallet"),
            &latest_checkpoint.nullifier_root,
            state.height.saturating_sub(16),
            state.height,
            25,
            LightClientPrivacyTier::NullifierOnly,
        )?;
        state.insert_nullifier_scan(scan)?;
        let bridge_hint = BridgeSyncHint::new(
            LIGHT_CLIENT_SYNC_DEVNET_WALLET_ID,
            "monero-devnet",
            &latest_checkpoint.bridge_root,
            &light_client_string_root("LIGHT-CLIENT-DEVNET-KEY-IMAGE", "wallet"),
            &light_client_string_root("LIGHT-CLIENT-DEVNET-OUTPUT", "wallet"),
            state.height,
            10,
        )?;
        state.insert_bridge_hint(bridge_hint.clone())?;
        let fee_hint = LightClientFeeHint::new(
            LightClientSyncMode::WalletDelta,
            &state.config.fee_asset_id,
            state.config.default_low_fee_hint_units,
            state.config.default_low_fee_hint_units / 2,
            state.height,
            state.height.saturating_add(32),
        )?;
        state.insert_fee_hint(fee_hint.clone())?;
        let update = SyncUpdateBundle::new(
            LIGHT_CLIENT_SYNC_DEVNET_WALLET_ID,
            &checkpoints,
            &[delta],
            &[bridge_hint],
            &[fee_hint],
            LIGHT_CLIENT_SYNC_DEVNET_SYNCER_ID,
            state.height,
            state.config.update_ttl_blocks,
        )?;
        let update_id = update.update_id.clone();
        state.insert_update_bundle(update)?;
        let receipt = SyncDeliveryReceipt::new(
            &update_id,
            LIGHT_CLIENT_SYNC_DEVNET_WALLET_ID,
            state.height.saturating_add(1),
            state.height.saturating_add(1),
            85,
            &light_client_string_root("LIGHT-CLIENT-DEVNET-ACK", &update_id),
        )?;
        state.insert_delivery_receipt(receipt)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for delta in self.wallet_deltas.values_mut() {
            if delta.is_expired_at(height) && delta.status != LIGHT_CLIENT_SYNC_STATUS_VERIFIED {
                delta.status = LIGHT_CLIENT_SYNC_STATUS_EXPIRED.to_string();
            }
        }
        for update in self.update_bundles.values_mut() {
            if update.is_expired_at(height) && update.status != LIGHT_CLIENT_SYNC_STATUS_VERIFIED {
                update.status = LIGHT_CLIENT_SYNC_STATUS_EXPIRED.to_string();
            }
        }
        for fee_hint in self.fee_hints.values_mut() {
            if !fee_hint.is_active_at(height) && fee_hint.status == LIGHT_CLIENT_SYNC_STATUS_ACTIVE
            {
                fee_hint.status = LIGHT_CLIENT_SYNC_STATUS_STALE.to_string();
            }
        }
    }

    pub fn insert_committee_member(
        &mut self,
        member: SyncCommitteeMember,
    ) -> LightClientSyncResult<String> {
        let root = member.validate()?;
        self.committee_members
            .insert(member.member_id.clone(), member);
        Ok(root)
    }

    pub fn insert_checkpoint(
        &mut self,
        checkpoint: CompactStateCheckpoint,
    ) -> LightClientSyncResult<String> {
        let root = checkpoint.validate()?;
        self.checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint);
        Ok(root)
    }

    pub fn insert_filter(&mut self, filter: CompactBlockFilter) -> LightClientSyncResult<String> {
        let root = filter.validate()?;
        if !self.checkpoints.contains_key(&filter.checkpoint_id) {
            return Err("light filter references missing checkpoint".to_string());
        }
        self.filters.insert(filter.filter_id.clone(), filter);
        Ok(root)
    }

    pub fn insert_wallet_delta(
        &mut self,
        delta: WalletDeltaBundle,
    ) -> LightClientSyncResult<String> {
        let root = delta.validate()?;
        if !self.checkpoints.contains_key(&delta.checkpoint_id) {
            return Err("wallet delta references missing checkpoint".to_string());
        }
        if !self.filters.contains_key(&delta.filter_id) {
            return Err("wallet delta references missing filter".to_string());
        }
        self.wallet_deltas.insert(delta.bundle_id.clone(), delta);
        Ok(root)
    }

    pub fn insert_nullifier_scan(
        &mut self,
        scan: NullifierScanRequest,
    ) -> LightClientSyncResult<String> {
        let root = scan.validate()?;
        self.nullifier_scans.insert(scan.request_id.clone(), scan);
        Ok(root)
    }

    pub fn insert_bridge_hint(&mut self, hint: BridgeSyncHint) -> LightClientSyncResult<String> {
        let root = hint.validate()?;
        self.bridge_hints.insert(hint.hint_id.clone(), hint);
        Ok(root)
    }

    pub fn insert_fee_hint(&mut self, hint: LightClientFeeHint) -> LightClientSyncResult<String> {
        let root = hint.validate()?;
        self.fee_hints.insert(hint.hint_id.clone(), hint);
        Ok(root)
    }

    pub fn insert_update_bundle(
        &mut self,
        update: SyncUpdateBundle,
    ) -> LightClientSyncResult<String> {
        let root = update.validate()?;
        for checkpoint_id in &update.checkpoint_ids {
            if !self.checkpoints.contains_key(checkpoint_id) {
                return Err("sync update references missing checkpoint".to_string());
            }
        }
        for delta_id in &update.delta_bundle_ids {
            if !self.wallet_deltas.contains_key(delta_id) {
                return Err("sync update references missing delta".to_string());
            }
        }
        self.update_bundles.insert(update.update_id.clone(), update);
        Ok(root)
    }

    pub fn insert_delivery_receipt(
        &mut self,
        receipt: SyncDeliveryReceipt,
    ) -> LightClientSyncResult<String> {
        let root = receipt.validate()?;
        let update = self
            .update_bundles
            .get_mut(&receipt.update_id)
            .ok_or_else(|| "sync receipt references missing update".to_string())?;
        update.status = LIGHT_CLIENT_SYNC_STATUS_VERIFIED.to_string();
        self.delivery_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn roots(&self) -> LightClientSyncRoots {
        LightClientSyncRoots {
            config_root: self.config.config_root(),
            committee_root: self.committee_root(),
            checkpoint_root: self.checkpoint_root(),
            filter_root: self.filter_root(),
            wallet_delta_root: self.wallet_delta_root(),
            nullifier_scan_root: self.nullifier_scan_root(),
            bridge_hint_root: self.bridge_hint_root(),
            fee_hint_root: self.fee_hint_root(),
            update_bundle_root: self.update_bundle_root(),
            delivery_receipt_root: self.delivery_receipt_root(),
        }
    }

    pub fn committee_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-COMMITTEE-SET",
            &self
                .committee_members
                .values()
                .map(SyncCommitteeMember::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn checkpoint_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-CHECKPOINT-SET",
            &self
                .checkpoints
                .values()
                .map(CompactStateCheckpoint::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn filter_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-FILTER-SET",
            &self
                .filters
                .values()
                .map(CompactBlockFilter::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn wallet_delta_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-WALLET-DELTA-SET",
            &self
                .wallet_deltas
                .values()
                .map(WalletDeltaBundle::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn nullifier_scan_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-NULLIFIER-SCAN-SET",
            &self
                .nullifier_scans
                .values()
                .map(NullifierScanRequest::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bridge_hint_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-BRIDGE-HINT-SET",
            &self
                .bridge_hints
                .values()
                .map(BridgeSyncHint::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn fee_hint_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-FEE-HINT-SET",
            &self
                .fee_hints
                .values()
                .map(LightClientFeeHint::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn update_bundle_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-UPDATE-BUNDLE-SET",
            &self
                .update_bundles
                .values()
                .map(SyncUpdateBundle::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn delivery_receipt_root(&self) -> String {
        merkle_root(
            "LIGHT-CLIENT-DELIVERY-RECEIPT-SET",
            &self
                .delivery_receipts
                .values()
                .map(SyncDeliveryReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_fee_hint_count(&self) -> u64 {
        self.fee_hints
            .values()
            .filter(|hint| hint.is_active_at(self.height))
            .count() as u64
    }

    pub fn active_committee_count(&self) -> u64 {
        self.committee_members
            .values()
            .filter(|member| member.is_active_at(self.height))
            .count() as u64
    }

    pub fn state_root(&self) -> String {
        light_client_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("light client state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "light_client_sync_state",
            "chain_id": CHAIN_ID,
            "protocol_version": LIGHT_CLIENT_SYNC_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "committee_member_count": self.committee_members.len() as u64,
            "active_committee_count": self.active_committee_count(),
            "checkpoint_count": self.checkpoints.len() as u64,
            "filter_count": self.filters.len() as u64,
            "wallet_delta_count": self.wallet_deltas.len() as u64,
            "nullifier_scan_count": self.nullifier_scans.len() as u64,
            "bridge_hint_count": self.bridge_hints.len() as u64,
            "fee_hint_count": self.fee_hints.len() as u64,
            "active_fee_hint_count": self.active_fee_hint_count(),
            "update_bundle_count": self.update_bundles.len() as u64,
            "delivery_receipt_count": self.delivery_receipts.len() as u64,
            "pq_signature_scheme": self.config.pq_signature_scheme,
            "pq_kem_scheme": self.config.pq_kem_scheme,
            "filter_scheme": self.config.filter_scheme,
        })
    }

    pub fn validate(&self) -> LightClientSyncResult<String> {
        self.config.validate()?;
        let mut checkpoint_ids = BTreeSet::new();
        for member in self.committee_members.values() {
            member.validate()?;
        }
        for checkpoint in self.checkpoints.values() {
            checkpoint.validate()?;
            checkpoint_ids.insert(checkpoint.checkpoint_id.clone());
        }
        for filter in self.filters.values() {
            filter.validate()?;
            if !checkpoint_ids.contains(&filter.checkpoint_id) {
                return Err("light filter references missing checkpoint".to_string());
            }
        }
        for delta in self.wallet_deltas.values() {
            delta.validate()?;
            if !checkpoint_ids.contains(&delta.checkpoint_id) {
                return Err("wallet delta references missing checkpoint".to_string());
            }
            if !self.filters.contains_key(&delta.filter_id) {
                return Err("wallet delta references missing filter".to_string());
            }
        }
        for scan in self.nullifier_scans.values() {
            scan.validate()?;
        }
        for hint in self.bridge_hints.values() {
            hint.validate()?;
        }
        for hint in self.fee_hints.values() {
            hint.validate()?;
        }
        for update in self.update_bundles.values() {
            update.validate()?;
        }
        for receipt in self.delivery_receipts.values() {
            receipt.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn light_client_committee_member_id(
    operator_label: &str,
    pq_public_key_root: &str,
    endpoint_commitment: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(endpoint_commitment),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn light_client_checkpoint_id(
    height: u64,
    block_root: &str,
    state_root: &str,
    da_root: &str,
    nullifier_root: &str,
    note_commitment_root: &str,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(block_root),
            HashPart::Str(state_root),
            HashPart::Str(da_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(note_commitment_root),
        ],
        32,
    )
}

pub fn light_client_filter_id(
    checkpoint_id: &str,
    height: u64,
    note_filter_root: &str,
    nullifier_filter_root: &str,
    view_tag_root: &str,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-FILTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Int(height as i128),
            HashPart::Str(note_filter_root),
            HashPart::Str(nullifier_filter_root),
            HashPart::Str(view_tag_root),
        ],
        32,
    )
}

pub fn light_client_wallet_delta_id(
    wallet_id: &str,
    checkpoint_id: &str,
    filter_id: &str,
    encrypted_note_root: &str,
    scan_to_height: u64,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-WALLET-DELTA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(checkpoint_id),
            HashPart::Str(filter_id),
            HashPart::Str(encrypted_note_root),
            HashPart::Int(scan_to_height as i128),
        ],
        32,
    )
}

pub fn light_client_nullifier_scan_id(
    wallet_id: &str,
    scan_tag_root: &str,
    nullifier_prefix_root: &str,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-NULLIFIER-SCAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(scan_tag_root),
            HashPart::Str(nullifier_prefix_root),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

pub fn light_client_bridge_hint_id(
    wallet_id: &str,
    monero_network: &str,
    bridge_event_root: &str,
    output_commitment_root: &str,
    observed_height: u64,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-BRIDGE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(monero_network),
            HashPart::Str(bridge_event_root),
            HashPart::Str(output_commitment_root),
            HashPart::Int(observed_height as i128),
        ],
        32,
    )
}

pub fn light_client_fee_hint_id(
    mode: LightClientSyncMode,
    fee_asset_id: &str,
    suggested_fee_units: u64,
    low_fee_credit_units: u64,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-FEE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(mode.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(suggested_fee_units as i128),
            HashPart::Int(low_fee_credit_units as i128),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn light_client_update_bundle_id(
    wallet_id: &str,
    checkpoint_root: &str,
    delta_root: &str,
    syncer_id: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-UPDATE-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(checkpoint_root),
            HashPart::Str(delta_root),
            HashPart::Str(syncer_id),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn light_client_delivery_receipt_id(
    update_id: &str,
    wallet_id: &str,
    client_ack_root: &str,
    delivered_at_height: u64,
) -> String {
    domain_hash(
        "LIGHT-CLIENT-DELIVERY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(update_id),
            HashPart::Str(wallet_id),
            HashPart::Str(client_ack_root),
            HashPart::Int(delivered_at_height as i128),
        ],
        32,
    )
}

pub fn light_client_signature_root(signer_id: &str, message_root: &str) -> String {
    domain_hash(
        "LIGHT-CLIENT-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LIGHT_CLIENT_SYNC_PQ_SIGNATURE_SCHEME),
            HashPart::Str(signer_id),
            HashPart::Str(message_root),
        ],
        32,
    )
}

pub fn light_client_state_root_from_record(record: &Value) -> String {
    light_client_payload_root("LIGHT-CLIENT-SYNC-STATE", record)
}

pub fn light_client_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn light_client_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn light_client_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn validate_bps(value: u64, label: &str) -> LightClientSyncResult<()> {
    if value > 10_000 {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

pub fn ensure_non_empty(value: &str, label: &str) -> LightClientSyncResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}
