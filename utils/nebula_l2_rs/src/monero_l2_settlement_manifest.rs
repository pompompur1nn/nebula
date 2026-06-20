use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2SettlementManifestResult<T> = Result<T, String>;

pub const MONERO_L2_SETTLEMENT_MANIFEST_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-settlement-manifest-v1";
pub const MONERO_L2_SETTLEMENT_MANIFEST_PUBLIC_RECORD_SCHEMA: &str =
    "monero-l2-settlement-manifest-public-record-v1";
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_SETTLEMENT_MANIFEST_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 20;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_L2_FINALITY_DEPTH: u64 = 12;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_REORG_HOLD_BLOCKS: u64 = 48;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_BATCH_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_DA_RETENTION_BLOCKS: u64 = 7_200;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MAX_ENTRIES: u64 = 512;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MAX_BATCH_BYTES: u64 = 4_000_000;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_WATCHER_QUORUM_WEIGHT: u64 = 3;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_LOW_FEE_TARGET_BPS: u64 = 9_500;
pub const MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const MONERO_L2_SETTLEMENT_MANIFEST_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Open,
    Sealed,
    Published,
    Confirming,
    Finalized,
    ReorgHold,
    Reorged,
    Expired,
    Cancelled,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Published => "published",
            Self::Confirming => "confirming",
            Self::Finalized => "finalized",
            Self::ReorgHold => "reorg_hold",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_entries(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Reorged | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    Standard,
    FastExit,
    LowFee,
    PrivateDefi,
    TokenContract,
    Emergency,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::FastExit => "fast_exit",
            Self::LowFee => "low_fee",
            Self::PrivateDefi => "private_defi",
            Self::TokenContract => "token_contract",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 0,
            Self::FastExit => 1,
            Self::LowFee => 2,
            Self::PrivateDefi => 3,
            Self::TokenContract => 4,
            Self::Standard => 5,
        }
    }

    pub fn sponsor_eligible(self) -> bool {
        matches!(
            self,
            Self::FastExit | Self::LowFee | Self::PrivateDefi | Self::Emergency
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    PrivateExecutionReceipt,
    ExitCommitment,
    WatcherCertificate,
    DaPublication,
    FeeSponsor,
    ReplayFence,
    NullifierFence,
    PrivateContractCall,
    ConfidentialTokenTransfer,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateExecutionReceipt => "private_execution_receipt",
            Self::ExitCommitment => "exit_commitment",
            Self::WatcherCertificate => "watcher_certificate",
            Self::DaPublication => "da_publication",
            Self::FeeSponsor => "fee_sponsor",
            Self::ReplayFence => "replay_fence",
            Self::NullifierFence => "nullifier_fence",
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    Planned,
    Submitted,
    Confirming,
    Mature,
    ReorgHold,
    Reorged,
    Failed,
}

impl AnchorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Submitted => "submitted",
            Self::Confirming => "confirming",
            Self::Mature => "mature",
            Self::ReorgHold => "reorg_hold",
            Self::Reorged => "reorged",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub public_record_schema: String,
    pub monero_network: String,
    pub l2_network: String,
    pub settlement_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub monero_finality_depth: u64,
    pub l2_finality_depth: u64,
    pub reorg_hold_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub da_retention_blocks: u64,
    pub max_entries_per_manifest: u64,
    pub max_batch_bytes: u64,
    pub watcher_quorum_weight: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_target_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub roots_only: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_L2_SETTLEMENT_MANIFEST_PROTOCOL_VERSION.to_string(),
            public_record_schema: MONERO_L2_SETTLEMENT_MANIFEST_PUBLIC_RECORD_SCHEMA.to_string(),
            monero_network: MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_NETWORK.to_string(),
            l2_network: MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_L2_NETWORK.to_string(),
            settlement_asset_id: MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_SETTLEMENT_MANIFEST_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_L2_SETTLEMENT_MANIFEST_HASH_SUITE.to_string(),
            monero_finality_depth: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MONERO_FINALITY_DEPTH,
            l2_finality_depth: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_L2_FINALITY_DEPTH,
            reorg_hold_blocks: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_REORG_HOLD_BLOCKS,
            batch_ttl_blocks: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_BATCH_TTL_BLOCKS,
            da_retention_blocks: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_DA_RETENTION_BLOCKS,
            max_entries_per_manifest: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MAX_ENTRIES,
            max_batch_bytes: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MAX_BATCH_BYTES,
            watcher_quorum_weight: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_WATCHER_QUORUM_WEIGHT,
            min_pq_security_bits: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_target_bps: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_LOW_FEE_TARGET_BPS,
            sponsor_rebate_bps: MONERO_L2_SETTLEMENT_MANIFEST_DEFAULT_SPONSOR_REBATE_BPS,
            roots_only: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "public_record_schema": self.public_record_schema,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "settlement_asset_id": self.settlement_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "monero_finality_depth": self.monero_finality_depth,
            "l2_finality_depth": self.l2_finality_depth,
            "reorg_hold_blocks": self.reorg_hold_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "da_retention_blocks": self.da_retention_blocks,
            "max_entries_per_manifest": self.max_entries_per_manifest,
            "max_batch_bytes": self.max_batch_bytes,
            "watcher_quorum_weight": self.watcher_quorum_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_target_bps": self.low_fee_target_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "roots_only": self.roots_only,
        })
    }

    pub fn validate(&self) -> MoneroL2SettlementManifestResult<()> {
        if self.protocol_version != MONERO_L2_SETTLEMENT_MANIFEST_PROTOCOL_VERSION {
            return Err("unsupported settlement manifest protocol version".to_string());
        }
        if !self.roots_only {
            return Err("settlement manifest must remain roots-only".to_string());
        }
        if self.monero_finality_depth == 0 || self.l2_finality_depth == 0 {
            return Err("finality depths must be non-zero".to_string());
        }
        if self.reorg_hold_blocks < self.monero_finality_depth {
            return Err("reorg hold must cover the Monero finality depth".to_string());
        }
        if self.max_entries_per_manifest == 0 {
            return Err("max entries per manifest must be non-zero".to_string());
        }
        if self.low_fee_target_bps > MONERO_L2_SETTLEMENT_MANIFEST_MAX_BPS {
            return Err("low fee target exceeds bps limit".to_string());
        }
        if self.sponsor_rebate_bps > MONERO_L2_SETTLEMENT_MANIFEST_MAX_BPS {
            return Err("sponsor rebate exceeds bps limit".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityWindow {
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub monero_anchor_height: u64,
    pub monero_unlock_height: u64,
    pub challenge_deadline_height: u64,
    pub reorg_hold_until_height: u64,
}

impl FinalityWindow {
    pub fn new(
        l2_start_height: u64,
        l2_end_height: u64,
        monero_anchor_height: u64,
        config: &Config,
    ) -> MoneroL2SettlementManifestResult<Self> {
        if l2_end_height < l2_start_height {
            return Err("l2 finality window ends before it starts".to_string());
        }
        Ok(Self {
            l2_start_height,
            l2_end_height,
            monero_anchor_height,
            monero_unlock_height: monero_anchor_height + config.monero_finality_depth,
            challenge_deadline_height: l2_end_height + config.l2_finality_depth,
            reorg_hold_until_height: monero_anchor_height + config.reorg_hold_blocks,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "monero_anchor_height": self.monero_anchor_height,
            "monero_unlock_height": self.monero_unlock_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "reorg_hold_until_height": self.reorg_hold_until_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAnchor {
    pub anchor_id: String,
    pub txid_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub view_tag_root: String,
    pub subaddress_root: String,
    pub fee_commitment_root: String,
    pub status: AnchorStatus,
}

impl MoneroAnchor {
    pub fn planned(anchor_id: impl Into<String>) -> Self {
        Self {
            anchor_id: anchor_id.into(),
            txid_root: empty_root("MONERO-ANCHOR-TXID"),
            output_commitment_root: empty_root("MONERO-ANCHOR-OUTPUT-COMMITMENT"),
            key_image_root: empty_root("MONERO-ANCHOR-KEY-IMAGE"),
            view_tag_root: empty_root("MONERO-ANCHOR-VIEW-TAG"),
            subaddress_root: empty_root("MONERO-ANCHOR-SUBADDRESS"),
            fee_commitment_root: empty_root("MONERO-ANCHOR-FEE-COMMITMENT"),
            status: AnchorStatus::Planned,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "txid_root": self.txid_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "view_tag_root": self.view_tag_root,
            "subaddress_root": self.subaddress_root,
            "fee_commitment_root": self.fee_commitment_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementEntry {
    pub entry_id: String,
    pub manifest_id: String,
    pub sequence: u64,
    pub kind: EntryKind,
    pub lane: SettlementLane,
    pub private_receipt_root: String,
    pub private_contract_root: String,
    pub confidential_token_root: String,
    pub exit_commitment_root: String,
    pub watcher_certificate_root: String,
    pub da_publication_root: String,
    pub fee_sponsor_root: String,
    pub replay_root: String,
    pub nullifier_root: String,
    pub pq_attestation_root: String,
    pub monero_anchor_hint_root: String,
    pub byte_size: u64,
    pub fee_piconero: u64,
}

impl SettlementEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_id: impl Into<String>,
        sequence: u64,
        kind: EntryKind,
        lane: SettlementLane,
        private_receipt_root: impl Into<String>,
        exit_commitment_root: impl Into<String>,
        watcher_certificate_root: impl Into<String>,
        da_publication_root: impl Into<String>,
        fee_sponsor_root: impl Into<String>,
        replay_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        byte_size: u64,
        fee_piconero: u64,
    ) -> Self {
        let manifest_id = manifest_id.into();
        let entry_id = settlement_entry_id(&manifest_id, sequence, kind, lane);
        Self {
            entry_id,
            manifest_id,
            sequence,
            kind,
            lane,
            private_receipt_root: private_receipt_root.into(),
            private_contract_root: empty_root("PRIVATE-CONTRACT"),
            confidential_token_root: empty_root("CONFIDENTIAL-TOKEN"),
            exit_commitment_root: exit_commitment_root.into(),
            watcher_certificate_root: watcher_certificate_root.into(),
            da_publication_root: da_publication_root.into(),
            fee_sponsor_root: fee_sponsor_root.into(),
            replay_root: replay_root.into(),
            nullifier_root: nullifier_root.into(),
            pq_attestation_root: empty_root("PQ-ATTESTATION"),
            monero_anchor_hint_root: empty_root("MONERO-ANCHOR-HINT"),
            byte_size,
            fee_piconero,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "manifest_id": self.manifest_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "lane_priority": self.lane.priority(),
            "sponsor_eligible": self.lane.sponsor_eligible(),
            "private_receipt_root": self.private_receipt_root,
            "private_contract_root": self.private_contract_root,
            "confidential_token_root": self.confidential_token_root,
            "exit_commitment_root": self.exit_commitment_root,
            "watcher_certificate_root": self.watcher_certificate_root,
            "da_publication_root": self.da_publication_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "replay_root": self.replay_root,
            "nullifier_root": self.nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "monero_anchor_hint_root": self.monero_anchor_hint_root,
            "byte_size": self.byte_size,
            "fee_piconero": self.fee_piconero,
        })
    }

    pub fn entry_root(&self) -> String {
        record_root("SETTLEMENT-ENTRY", &self.public_record())
    }

    pub fn validate(&self) -> MoneroL2SettlementManifestResult<()> {
        if self.entry_id.is_empty() || self.manifest_id.is_empty() {
            return Err("settlement entry identifiers must be non-empty".to_string());
        }
        if self.byte_size == 0 {
            return Err("settlement entry byte size must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementManifest {
    pub manifest_id: String,
    pub batch_id: String,
    pub epoch: u64,
    pub status: ManifestStatus,
    pub opened_l2_height: u64,
    pub sealed_l2_height: Option<u64>,
    pub finality_window: FinalityWindow,
    pub monero_anchor: MoneroAnchor,
    pub entry_root: String,
    pub receipt_root: String,
    pub exit_root: String,
    pub watcher_certificate_root: String,
    pub da_publication_root: String,
    pub fee_sponsor_root: String,
    pub replay_root: String,
    pub nullifier_root: String,
    pub pq_attestation_root: String,
    pub private_contract_root: String,
    pub confidential_token_root: String,
    pub total_bytes: u64,
    pub total_fee_piconero: u64,
    pub entry_count: u64,
}

impl SettlementManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "batch_id": self.batch_id,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "opened_l2_height": self.opened_l2_height,
            "sealed_l2_height": self.sealed_l2_height,
            "finality_window": self.finality_window.public_record(),
            "monero_anchor": self.monero_anchor.public_record(),
            "entry_root": self.entry_root,
            "receipt_root": self.receipt_root,
            "exit_root": self.exit_root,
            "watcher_certificate_root": self.watcher_certificate_root,
            "da_publication_root": self.da_publication_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "replay_root": self.replay_root,
            "nullifier_root": self.nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "private_contract_root": self.private_contract_root,
            "confidential_token_root": self.confidential_token_root,
            "total_bytes": self.total_bytes,
            "total_fee_piconero": self.total_fee_piconero,
            "entry_count": self.entry_count,
        })
    }

    pub fn manifest_root(&self) -> String {
        record_root("SETTLEMENT-MANIFEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub manifests_opened: u64,
    pub manifests_sealed: u64,
    pub entries_appended: u64,
    pub private_receipts_linked: u64,
    pub exits_linked: u64,
    pub watcher_certificates_linked: u64,
    pub da_publications_linked: u64,
    pub fee_sponsors_linked: u64,
    pub replay_fences_linked: u64,
    pub nullifier_fences_linked: u64,
    pub total_bytes: u64,
    pub total_fee_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "manifests_opened": self.manifests_opened,
            "manifests_sealed": self.manifests_sealed,
            "entries_appended": self.entries_appended,
            "private_receipts_linked": self.private_receipts_linked,
            "exits_linked": self.exits_linked,
            "watcher_certificates_linked": self.watcher_certificates_linked,
            "da_publications_linked": self.da_publications_linked,
            "fee_sponsors_linked": self.fee_sponsors_linked,
            "replay_fences_linked": self.replay_fences_linked,
            "nullifier_fences_linked": self.nullifier_fences_linked,
            "total_bytes": self.total_bytes,
            "total_fee_piconero": self.total_fee_piconero,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub manifest_root: String,
    pub open_manifest_root: String,
    pub sealed_manifest_root: String,
    pub entry_root: String,
    pub receipt_root: String,
    pub exit_root: String,
    pub watcher_certificate_root: String,
    pub da_publication_root: String,
    pub fee_sponsor_root: String,
    pub replay_root: String,
    pub nullifier_root: String,
    pub monero_anchor_root: String,
    pub finality_window_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_root": self.manifest_root,
            "open_manifest_root": self.open_manifest_root,
            "sealed_manifest_root": self.sealed_manifest_root,
            "entry_root": self.entry_root,
            "receipt_root": self.receipt_root,
            "exit_root": self.exit_root,
            "watcher_certificate_root": self.watcher_certificate_root,
            "da_publication_root": self.da_publication_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "replay_root": self.replay_root,
            "nullifier_root": self.nullifier_root,
            "monero_anchor_root": self.monero_anchor_root,
            "finality_window_root": self.finality_window_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub manifests: BTreeMap<String, SettlementManifest>,
    pub entries: BTreeMap<String, SettlementEntry>,
    pub manifest_entries: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            manifests: BTreeMap::new(),
            entries: BTreeMap::new(),
            manifest_entries: BTreeMap::new(),
        }
    }

    pub fn open_manifest(
        &mut self,
        batch_id: impl Into<String>,
        epoch: u64,
        opened_l2_height: u64,
        l2_end_height: u64,
        monero_anchor_height: u64,
    ) -> MoneroL2SettlementManifestResult<SettlementManifest> {
        self.config.validate()?;
        let batch_id = batch_id.into();
        if batch_id.is_empty() {
            return Err("batch id must be non-empty".to_string());
        }
        let manifest_id = settlement_manifest_id(&batch_id, epoch, opened_l2_height);
        if self.manifests.contains_key(&manifest_id) {
            return Err("settlement manifest already exists".to_string());
        }
        let finality_window = FinalityWindow::new(
            opened_l2_height,
            l2_end_height,
            monero_anchor_height,
            &self.config,
        )?;
        let manifest = SettlementManifest {
            manifest_id: manifest_id.clone(),
            batch_id,
            epoch,
            status: ManifestStatus::Open,
            opened_l2_height,
            sealed_l2_height: None,
            finality_window,
            monero_anchor: MoneroAnchor::planned(settlement_anchor_id(&manifest_id)),
            entry_root: empty_root("MANIFEST-ENTRY"),
            receipt_root: empty_root("MANIFEST-RECEIPT"),
            exit_root: empty_root("MANIFEST-EXIT"),
            watcher_certificate_root: empty_root("MANIFEST-WATCHER-CERTIFICATE"),
            da_publication_root: empty_root("MANIFEST-DA-PUBLICATION"),
            fee_sponsor_root: empty_root("MANIFEST-FEE-SPONSOR"),
            replay_root: empty_root("MANIFEST-REPLAY"),
            nullifier_root: empty_root("MANIFEST-NULLIFIER"),
            pq_attestation_root: empty_root("MANIFEST-PQ-ATTESTATION"),
            private_contract_root: empty_root("MANIFEST-PRIVATE-CONTRACT"),
            confidential_token_root: empty_root("MANIFEST-CONFIDENTIAL-TOKEN"),
            total_bytes: 0,
            total_fee_piconero: 0,
            entry_count: 0,
        };
        self.manifests.insert(manifest_id.clone(), manifest.clone());
        self.manifest_entries.insert(manifest_id, BTreeSet::new());
        self.counters.manifests_opened += 1;
        Ok(manifest)
    }

    pub fn append_entry(
        &mut self,
        manifest_id: &str,
        mut entry: SettlementEntry,
    ) -> MoneroL2SettlementManifestResult<SettlementEntry> {
        self.config.validate()?;
        entry.validate()?;
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or_else(|| "settlement manifest not found".to_string())?;
        if !manifest.status.accepts_entries() {
            return Err("settlement manifest no longer accepts entries".to_string());
        }
        if entry.manifest_id != manifest_id {
            return Err("settlement entry manifest id mismatch".to_string());
        }
        if manifest.entry_count >= self.config.max_entries_per_manifest {
            return Err("settlement manifest entry limit reached".to_string());
        }
        if manifest.total_bytes + entry.byte_size > self.config.max_batch_bytes {
            return Err("settlement manifest byte limit reached".to_string());
        }
        let expected_sequence = manifest.entry_count;
        if entry.sequence != expected_sequence {
            return Err("settlement entry sequence is not contiguous".to_string());
        }
        entry.entry_id = settlement_entry_id(manifest_id, entry.sequence, entry.kind, entry.lane);
        if self.entries.contains_key(&entry.entry_id) {
            return Err("settlement entry already exists".to_string());
        }

        self.entries.insert(entry.entry_id.clone(), entry.clone());
        self.manifest_entries
            .entry(manifest_id.to_string())
            .or_default()
            .insert(entry.entry_id.clone());
        self.counters.entries_appended += 1;
        self.counters.total_bytes += entry.byte_size;
        self.counters.total_fee_piconero += entry.fee_piconero;
        self.increment_kind_counter(entry.kind);
        self.refresh_manifest_roots(manifest_id)?;
        Ok(entry)
    }

    pub fn seal_manifest(
        &mut self,
        manifest_id: &str,
        sealed_l2_height: u64,
    ) -> MoneroL2SettlementManifestResult<SettlementManifest> {
        self.config.validate()?;
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or_else(|| "settlement manifest not found".to_string())?;
        if !manifest.status.accepts_entries() {
            return Err("settlement manifest is not open".to_string());
        }
        if manifest.entry_count == 0 {
            return Err("cannot seal an empty settlement manifest".to_string());
        }
        if sealed_l2_height < manifest.opened_l2_height {
            return Err("sealed height precedes manifest open height".to_string());
        }

        self.refresh_manifest_roots(manifest_id)?;
        let manifest = self
            .manifests
            .get_mut(manifest_id)
            .ok_or_else(|| "settlement manifest not found".to_string())?;
        manifest.status = ManifestStatus::Sealed;
        manifest.sealed_l2_height = Some(sealed_l2_height);
        self.counters.manifests_sealed += 1;
        Ok(manifest.clone())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_SETTLEMENT_MANIFEST_PROTOCOL_VERSION,
            "schema": MONERO_L2_SETTLEMENT_MANIFEST_PUBLIC_RECORD_SCHEMA,
            "privacy_boundary": "roots_only_no_plaintext_receipts_no_user_addresses_no_amounts",
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "SETTLEMENT-MANIFEST-STATE",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": MONERO_L2_SETTLEMENT_MANIFEST_PROTOCOL_VERSION,
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "roots": self.roots().public_record(),
            }),
        )
    }

    pub fn roots(&self) -> Roots {
        let manifest_records = self
            .manifests
            .values()
            .map(SettlementManifest::public_record)
            .collect::<Vec<_>>();
        let open_manifest_records = self
            .manifests
            .values()
            .filter(|manifest| manifest.status == ManifestStatus::Open)
            .map(SettlementManifest::public_record)
            .collect::<Vec<_>>();
        let sealed_manifest_records = self
            .manifests
            .values()
            .filter(|manifest| manifest.status == ManifestStatus::Sealed)
            .map(SettlementManifest::public_record)
            .collect::<Vec<_>>();
        let entry_records = self
            .entries
            .values()
            .map(SettlementEntry::public_record)
            .collect::<Vec<_>>();

        Roots {
            manifest_root: merkle_root("MONERO-L2-SETTLEMENT-MANIFEST", &manifest_records),
            open_manifest_root: merkle_root(
                "MONERO-L2-SETTLEMENT-OPEN-MANIFEST",
                &open_manifest_records,
            ),
            sealed_manifest_root: merkle_root(
                "MONERO-L2-SETTLEMENT-SEALED-MANIFEST",
                &sealed_manifest_records,
            ),
            entry_root: merkle_root("MONERO-L2-SETTLEMENT-ENTRY", &entry_records),
            receipt_root: root_from_entries(
                self.entries.values(),
                "MONERO-L2-SETTLEMENT-RECEIPT",
                |entry| &entry.private_receipt_root,
            ),
            exit_root: root_from_entries(
                self.entries.values(),
                "MONERO-L2-SETTLEMENT-EXIT",
                |entry| &entry.exit_commitment_root,
            ),
            watcher_certificate_root: root_from_entries(
                self.entries.values(),
                "MONERO-L2-SETTLEMENT-WATCHER-CERTIFICATE",
                |entry| &entry.watcher_certificate_root,
            ),
            da_publication_root: root_from_entries(
                self.entries.values(),
                "MONERO-L2-SETTLEMENT-DA-PUBLICATION",
                |entry| &entry.da_publication_root,
            ),
            fee_sponsor_root: root_from_entries(
                self.entries.values(),
                "MONERO-L2-SETTLEMENT-FEE-SPONSOR",
                |entry| &entry.fee_sponsor_root,
            ),
            replay_root: root_from_entries(
                self.entries.values(),
                "MONERO-L2-SETTLEMENT-REPLAY",
                |entry| &entry.replay_root,
            ),
            nullifier_root: root_from_entries(
                self.entries.values(),
                "MONERO-L2-SETTLEMENT-NULLIFIER",
                |entry| &entry.nullifier_root,
            ),
            monero_anchor_root: merkle_root(
                "MONERO-L2-SETTLEMENT-ANCHOR",
                &self
                    .manifests
                    .values()
                    .map(|manifest| manifest.monero_anchor.public_record())
                    .collect::<Vec<_>>(),
            ),
            finality_window_root: merkle_root(
                "MONERO-L2-SETTLEMENT-FINALITY-WINDOW",
                &self
                    .manifests
                    .values()
                    .map(|manifest| manifest.finality_window.public_record())
                    .collect::<Vec<_>>(),
            ),
        }
    }

    fn increment_kind_counter(&mut self, kind: EntryKind) {
        match kind {
            EntryKind::PrivateExecutionReceipt
            | EntryKind::PrivateContractCall
            | EntryKind::ConfidentialTokenTransfer => self.counters.private_receipts_linked += 1,
            EntryKind::ExitCommitment => self.counters.exits_linked += 1,
            EntryKind::WatcherCertificate => self.counters.watcher_certificates_linked += 1,
            EntryKind::DaPublication => self.counters.da_publications_linked += 1,
            EntryKind::FeeSponsor => self.counters.fee_sponsors_linked += 1,
            EntryKind::ReplayFence => self.counters.replay_fences_linked += 1,
            EntryKind::NullifierFence => self.counters.nullifier_fences_linked += 1,
        }
    }

    fn refresh_manifest_roots(
        &mut self,
        manifest_id: &str,
    ) -> MoneroL2SettlementManifestResult<()> {
        let entry_ids = self
            .manifest_entries
            .get(manifest_id)
            .cloned()
            .unwrap_or_default();
        let mut entries = Vec::with_capacity(entry_ids.len());
        for entry_id in entry_ids {
            let entry = self
                .entries
                .get(&entry_id)
                .ok_or_else(|| "manifest entry index points at missing entry".to_string())?;
            entries.push(entry.clone());
        }
        let manifest = self
            .manifests
            .get_mut(manifest_id)
            .ok_or_else(|| "settlement manifest not found".to_string())?;
        manifest.entry_count = entries.len() as u64;
        manifest.total_bytes = entries.iter().map(|entry| entry.byte_size).sum();
        manifest.total_fee_piconero = entries.iter().map(|entry| entry.fee_piconero).sum();
        manifest.entry_root = merkle_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-ENTRY",
            &entries
                .iter()
                .map(SettlementEntry::public_record)
                .collect::<Vec<_>>(),
        );
        manifest.receipt_root =
            entry_field_root("MONERO-L2-SETTLEMENT-MANIFEST-RECEIPT", &entries, |entry| {
                &entry.private_receipt_root
            });
        manifest.exit_root =
            entry_field_root("MONERO-L2-SETTLEMENT-MANIFEST-EXIT", &entries, |entry| {
                &entry.exit_commitment_root
            });
        manifest.watcher_certificate_root = entry_field_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-WATCHER-CERTIFICATE",
            &entries,
            |entry| &entry.watcher_certificate_root,
        );
        manifest.da_publication_root = entry_field_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-DA-PUBLICATION",
            &entries,
            |entry| &entry.da_publication_root,
        );
        manifest.fee_sponsor_root = entry_field_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-FEE-SPONSOR",
            &entries,
            |entry| &entry.fee_sponsor_root,
        );
        manifest.replay_root =
            entry_field_root("MONERO-L2-SETTLEMENT-MANIFEST-REPLAY", &entries, |entry| {
                &entry.replay_root
            });
        manifest.nullifier_root = entry_field_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-NULLIFIER",
            &entries,
            |entry| &entry.nullifier_root,
        );
        manifest.pq_attestation_root = entry_field_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-PQ-ATTESTATION",
            &entries,
            |entry| &entry.pq_attestation_root,
        );
        manifest.private_contract_root = entry_field_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-PRIVATE-CONTRACT",
            &entries,
            |entry| &entry.private_contract_root,
        );
        manifest.confidential_token_root = entry_field_root(
            "MONERO-L2-SETTLEMENT-MANIFEST-CONFIDENTIAL-TOKEN",
            &entries,
            |entry| &entry.confidential_token_root,
        );
        Ok(())
    }
}

fn settlement_manifest_id(batch_id: &str, epoch: u64, opened_l2_height: u64) -> String {
    domain_hash(
        "MONERO-L2-SETTLEMENT-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_L2_SETTLEMENT_MANIFEST_PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(opened_l2_height as i128),
        ],
        32,
    )
}

fn settlement_anchor_id(manifest_id: &str) -> String {
    domain_hash(
        "MONERO-L2-SETTLEMENT-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_L2_SETTLEMENT_MANIFEST_PROTOCOL_VERSION),
            HashPart::Str(manifest_id),
        ],
        32,
    )
}

fn settlement_entry_id(
    manifest_id: &str,
    sequence: u64,
    kind: EntryKind,
    lane: SettlementLane,
) -> String {
    domain_hash(
        "MONERO-L2-SETTLEMENT-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(&format!("MONERO-L2-SETTLEMENT-{domain}"), &[])
}

fn entry_field_root<F>(domain: &str, entries: &[SettlementEntry], field: F) -> String
where
    F: Fn(&SettlementEntry) -> &String,
{
    merkle_root(
        domain,
        &entries
            .iter()
            .map(|entry| {
                json!({
                    "entry_id": entry.entry_id,
                    "sequence": entry.sequence,
                    "root": field(entry),
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn root_from_entries<'a, I, F>(entries: I, domain: &str, field: F) -> String
where
    I: Iterator<Item = &'a SettlementEntry>,
    F: Fn(&'a SettlementEntry) -> &'a String,
{
    merkle_root(
        domain,
        &entries
            .map(|entry| {
                json!({
                    "entry_id": entry.entry_id,
                    "manifest_id": entry.manifest_id,
                    "sequence": entry.sequence,
                    "root": field(entry),
                })
            })
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_lifecycle_is_roots_only_and_deterministic() {
        let mut state = State::devnet();
        let manifest = state
            .open_manifest("batch-0", 7, 100, 112, 1_000)
            .expect("open manifest");
        let entry = SettlementEntry::new(
            manifest.manifest_id.clone(),
            0,
            EntryKind::PrivateExecutionReceipt,
            SettlementLane::LowFee,
            "receipt-root",
            "exit-root",
            "watcher-root",
            "da-root",
            "sponsor-root",
            "replay-root",
            "nullifier-root",
            1_024,
            10,
        );
        state
            .append_entry(&manifest.manifest_id, entry)
            .expect("append entry");
        let sealed = state
            .seal_manifest(&manifest.manifest_id, 112)
            .expect("seal manifest");
        assert_eq!(sealed.status, ManifestStatus::Sealed);
        assert_eq!(sealed.entry_count, 1);
        assert_eq!(
            state.public_record()["privacy_boundary"],
            "roots_only_no_plaintext_receipts_no_user_addresses_no_amounts"
        );
        assert_eq!(state.state_root(), state.state_root());
    }
}
