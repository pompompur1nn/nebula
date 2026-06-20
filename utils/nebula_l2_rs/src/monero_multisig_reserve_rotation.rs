use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroMultisigReserveRotationResult<T> = Result<T, String>;

pub const MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION: u32 = 1;
pub const MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_NAME: &str =
    "nebula-monero-multisig-reserve-rotation-v1";
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_HEIGHT: u64 = 432;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_MULTISIG_RESERVE_ROTATION_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const MONERO_MULTISIG_RESERVE_ROTATION_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const MONERO_MULTISIG_RESERVE_ROTATION_CLASSIC_MULTISIG_SCHEME: &str =
    "monero-multisig-2-of-3-devnet";
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_NOTICE_BLOCKS: u64 = 144;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_OVERLAP_BLOCKS: u64 = 72;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_FREEZE_BLOCKS: u64 = 48;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_RELEASE_BLOCKS: u64 = 96;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_REORG_DEPTH_BLOCKS: u64 = 12;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_MIN_CONFIRMATIONS: u64 = 12;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_WATCHTOWER_QUORUM_WEIGHT: u64 = 3;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_GUARDIAN_QUORUM_WEIGHT: u64 = 2;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_LOW_FEE_BUDGET_PICONERO: u64 = 900_000_000;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_MIN_COVERAGE_BPS: u64 = 10_250;
pub const MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_TARGET_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_MULTISIG_RESERVE_ROTATION_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveWalletEpochStatus {
    Planned,
    Active,
    Rotating,
    Draining,
    Retired,
    Frozen,
}

impl ReserveWalletEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Draining => "draining",
            Self::Retired => "retired",
            Self::Frozen => "frozen",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveWalletRole {
    ColdReserve,
    RotationStaging,
    DrainOnly,
    AuditMirror,
    EmergencyRecovery,
}

impl ReserveWalletRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ColdReserve => "cold_reserve",
            Self::RotationStaging => "rotation_staging",
            Self::DrainOnly => "drain_only",
            Self::AuditMirror => "audit_mirror",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRotationCeremonyStatus {
    Draft,
    Announced,
    ShareSealed,
    WatchtowerAttested,
    Activated,
    Challenged,
    Cancelled,
    Complete,
}

impl PqRotationCeremonyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Announced => "announced",
            Self::ShareSealed => "share_sealed",
            Self::WatchtowerAttested => "watchtower_attested",
            Self::Activated => "activated",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Complete => "complete",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Announced | Self::ShareSealed | Self::WatchtowerAttested
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerShardRole {
    PrimarySigner,
    BackupSigner,
    ViewOnlyAuditor,
    CeremonyCoordinator,
    EmergencyGuardian,
}

impl SignerShardRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrimarySigner => "primary_signer",
            Self::BackupSigner => "backup_signer",
            Self::ViewOnlyAuditor => "view_only_auditor",
            Self::CeremonyCoordinator => "ceremony_coordinator",
            Self::EmergencyGuardian => "emergency_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerShardStatus {
    Pending,
    Sealed,
    Active,
    Rotating,
    Quarantined,
    Retired,
}

impl SignerShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sealed => "sealed",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn can_sign(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerRotationAttestationStatus {
    Submitted,
    Accepted,
    Disputed,
    Slashed,
    Expired,
}

impl WatchtowerRotationAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyWindowKind {
    Freeze,
    Release,
    ViewKeyQuarantine,
    SignerJail,
    FullReservePause,
}

impl EmergencyWindowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Freeze => "freeze",
            Self::Release => "release",
            Self::ViewKeyQuarantine => "view_key_quarantine",
            Self::SignerJail => "signer_jail",
            Self::FullReservePause => "full_reserve_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyWindowStatus {
    Scheduled,
    Active,
    EvidenceReview,
    Released,
    Expired,
    Cancelled,
}

impl EmergencyWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::EvidenceReview => "evidence_review",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active | Self::EvidenceReview)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubaddressMigrationStatus {
    Planned,
    Scanning,
    Sweeping,
    Sponsored,
    Complete,
    Challenged,
    Reorged,
}

impl SubaddressMigrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Scanning => "scanning",
            Self::Sweeping => "sweeping",
            Self::Sponsored => "sponsored",
            Self::Complete => "complete",
            Self::Challenged => "challenged",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Scanning | Self::Sweeping | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCommitmentStatus {
    Draft,
    Posted,
    WatchtowerAccepted,
    Disputed,
    Finalized,
    Reorged,
}

impl AuditCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::WatchtowerAccepted => "watchtower_accepted",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
        }
    }

    pub fn usable_for_solvency(self) -> bool {
        matches!(self, Self::WatchtowerAccepted | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencySnapshotStatus {
    Draft,
    Observed,
    Attested,
    UnderCovered,
    Finalized,
    Superseded,
}

impl SolvencySnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Observed => "observed",
            Self::Attested => "attested",
            Self::UnderCovered => "under_covered",
            Self::Finalized => "finalized",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Attested | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationSponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Exhausted,
    Expired,
    Slashed,
}

impl RotationSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackSafeguardStatus {
    Armed,
    Observing,
    Triggered,
    Resolved,
    Expired,
}

impl RollbackSafeguardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Observing => "observing",
            Self::Triggered => "triggered",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_activation(self) -> bool {
        matches!(self, Self::Triggered)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroMultisigReserveRotationConfig {
    pub config_id: String,
    pub network: String,
    pub reserve_asset_id: String,
    pub fee_asset_id: String,
    pub classic_multisig_scheme: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub epoch_blocks: u64,
    pub notice_blocks: u64,
    pub overlap_blocks: u64,
    pub emergency_freeze_blocks: u64,
    pub emergency_release_blocks: u64,
    pub min_confirmations: u64,
    pub reorg_depth_blocks: u64,
    pub watchtower_quorum_weight: u64,
    pub guardian_quorum_weight: u64,
    pub low_fee_budget_piconero: u64,
    pub min_coverage_bps: u64,
    pub target_coverage_bps: u64,
}

impl Default for MoneroMultisigReserveRotationConfig {
    fn default() -> Self {
        let payload = json!({
            "network": MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_NETWORK,
            "reserve_asset_id": MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_ASSET_ID,
            "fee_asset_id": MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_FEE_ASSET_ID,
            "classic_multisig_scheme": MONERO_MULTISIG_RESERVE_ROTATION_CLASSIC_MULTISIG_SCHEME,
            "pq_signature_scheme": MONERO_MULTISIG_RESERVE_ROTATION_PQ_SIGNATURE_SCHEME,
            "pq_kem_scheme": MONERO_MULTISIG_RESERVE_ROTATION_PQ_KEM_SCHEME,
            "epoch_blocks": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_EPOCH_BLOCKS,
            "notice_blocks": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_NOTICE_BLOCKS,
            "overlap_blocks": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_OVERLAP_BLOCKS,
            "emergency_freeze_blocks": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_FREEZE_BLOCKS,
            "emergency_release_blocks": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_RELEASE_BLOCKS,
            "min_confirmations": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_MIN_CONFIRMATIONS,
            "reorg_depth_blocks": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_REORG_DEPTH_BLOCKS,
            "watchtower_quorum_weight": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_WATCHTOWER_QUORUM_WEIGHT,
            "guardian_quorum_weight": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_GUARDIAN_QUORUM_WEIGHT,
            "low_fee_budget_piconero": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_LOW_FEE_BUDGET_PICONERO,
            "min_coverage_bps": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_MIN_COVERAGE_BPS,
            "target_coverage_bps": MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_TARGET_COVERAGE_BPS,
        });
        Self {
            config_id: monero_multisig_reserve_rotation_config_id(&payload),
            network: MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_NETWORK.to_string(),
            reserve_asset_id: MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_FEE_ASSET_ID.to_string(),
            classic_multisig_scheme: MONERO_MULTISIG_RESERVE_ROTATION_CLASSIC_MULTISIG_SCHEME
                .to_string(),
            pq_signature_scheme: MONERO_MULTISIG_RESERVE_ROTATION_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: MONERO_MULTISIG_RESERVE_ROTATION_PQ_KEM_SCHEME.to_string(),
            epoch_blocks: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_EPOCH_BLOCKS,
            notice_blocks: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_NOTICE_BLOCKS,
            overlap_blocks: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_OVERLAP_BLOCKS,
            emergency_freeze_blocks: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_FREEZE_BLOCKS,
            emergency_release_blocks: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_RELEASE_BLOCKS,
            min_confirmations: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_MIN_CONFIRMATIONS,
            reorg_depth_blocks: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_REORG_DEPTH_BLOCKS,
            watchtower_quorum_weight:
                MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_WATCHTOWER_QUORUM_WEIGHT,
            guardian_quorum_weight: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_GUARDIAN_QUORUM_WEIGHT,
            low_fee_budget_piconero:
                MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_LOW_FEE_BUDGET_PICONERO,
            min_coverage_bps: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_MIN_COVERAGE_BPS,
            target_coverage_bps: MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_TARGET_COVERAGE_BPS,
        }
    }
}

impl MoneroMultisigReserveRotationConfig {
    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.config_id, "monero reserve rotation config id")?;
        ensure_non_empty(&self.network, "monero reserve rotation network")?;
        ensure_non_empty(
            &self.reserve_asset_id,
            "monero reserve rotation reserve asset",
        )?;
        ensure_non_empty(&self.fee_asset_id, "monero reserve rotation fee asset")?;
        ensure_non_empty(
            &self.classic_multisig_scheme,
            "monero reserve rotation multisig scheme",
        )?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "monero reserve rotation pq signature scheme",
        )?;
        ensure_non_empty(&self.pq_kem_scheme, "monero reserve rotation pq kem scheme")?;
        ensure_positive(self.epoch_blocks, "monero reserve rotation epoch blocks")?;
        ensure_positive(self.notice_blocks, "monero reserve rotation notice blocks")?;
        ensure_positive(
            self.overlap_blocks,
            "monero reserve rotation overlap blocks",
        )?;
        ensure_positive(
            self.emergency_freeze_blocks,
            "monero reserve rotation freeze blocks",
        )?;
        ensure_positive(
            self.emergency_release_blocks,
            "monero reserve rotation release blocks",
        )?;
        ensure_positive(
            self.min_confirmations,
            "monero reserve rotation min confirmations",
        )?;
        ensure_positive(
            self.reorg_depth_blocks,
            "monero reserve rotation reorg depth",
        )?;
        ensure_positive(
            self.watchtower_quorum_weight,
            "monero reserve rotation watchtower quorum",
        )?;
        ensure_positive(
            self.guardian_quorum_weight,
            "monero reserve rotation guardian quorum",
        )?;
        ensure_bps(
            self.min_coverage_bps,
            "monero reserve rotation minimum coverage bps",
        )?;
        ensure_bps(
            self.target_coverage_bps,
            "monero reserve rotation target coverage bps",
        )?;
        if self.notice_blocks >= self.epoch_blocks {
            return Err("monero reserve rotation notice must fit inside epoch".to_string());
        }
        if self.overlap_blocks >= self.epoch_blocks {
            return Err("monero reserve rotation overlap must fit inside epoch".to_string());
        }
        Ok(self.config_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_multisig_reserve_rotation_config",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "protocol_name": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_NAME,
            "config_id": self.config_id,
            "network": self.network,
            "reserve_asset_id": self.reserve_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "classic_multisig_scheme": self.classic_multisig_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "epoch_blocks": self.epoch_blocks,
            "notice_blocks": self.notice_blocks,
            "overlap_blocks": self.overlap_blocks,
            "emergency_freeze_blocks": self.emergency_freeze_blocks,
            "emergency_release_blocks": self.emergency_release_blocks,
            "min_confirmations": self.min_confirmations,
            "reorg_depth_blocks": self.reorg_depth_blocks,
            "watchtower_quorum_weight": self.watchtower_quorum_weight,
            "guardian_quorum_weight": self.guardian_quorum_weight,
            "low_fee_budget_piconero": self.low_fee_budget_piconero,
            "min_coverage_bps": self.min_coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
        })
    }

    pub fn config_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveWalletEpoch {
    pub epoch_id: String,
    pub epoch: u64,
    pub role: ReserveWalletRole,
    pub status: ReserveWalletEpochStatus,
    pub wallet_label: String,
    pub reserve_address_hash: String,
    pub view_key_commitment: String,
    pub previous_epoch_id: Option<String>,
    pub signer_set_root: String,
    pub multisig_threshold: u64,
    pub signer_count: u64,
    pub starts_at_height: u64,
    pub activates_at_height: u64,
    pub retires_at_height: Option<u64>,
    pub expected_balance_piconero: u64,
}

impl ReserveWalletEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        role: ReserveWalletRole,
        status: ReserveWalletEpochStatus,
        wallet_label: impl Into<String>,
        reserve_address_hash: impl Into<String>,
        view_key_commitment: impl Into<String>,
        previous_epoch_id: Option<String>,
        signer_set_root: impl Into<String>,
        multisig_threshold: u64,
        signer_count: u64,
        starts_at_height: u64,
        activates_at_height: u64,
        retires_at_height: Option<u64>,
        expected_balance_piconero: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let wallet_label = wallet_label.into();
        let reserve_address_hash = reserve_address_hash.into();
        let view_key_commitment = view_key_commitment.into();
        let signer_set_root = signer_set_root.into();
        ensure_non_empty(&wallet_label, "monero reserve rotation wallet label")?;
        ensure_non_empty(
            &reserve_address_hash,
            "monero reserve rotation address hash",
        )?;
        ensure_non_empty(
            &view_key_commitment,
            "monero reserve rotation view key commitment",
        )?;
        ensure_non_empty(&signer_set_root, "monero reserve rotation signer root")?;
        ensure_threshold(multisig_threshold, signer_count)?;
        if activates_at_height < starts_at_height {
            return Err("monero reserve rotation activation precedes start".to_string());
        }
        if let Some(retire_height) = retires_at_height {
            if retire_height <= activates_at_height {
                return Err("monero reserve rotation retirement precedes activation".to_string());
            }
        }
        let payload = json!({
            "epoch": epoch,
            "role": role.as_str(),
            "wallet_label": wallet_label,
            "reserve_address_hash": reserve_address_hash,
            "view_key_commitment": view_key_commitment,
            "previous_epoch_id": previous_epoch_id,
            "signer_set_root": signer_set_root,
            "multisig_threshold": multisig_threshold,
            "signer_count": signer_count,
            "starts_at_height": starts_at_height,
            "activates_at_height": activates_at_height,
        });
        Ok(Self {
            epoch_id: monero_multisig_reserve_rotation_wallet_epoch_id(&payload),
            epoch,
            role,
            status,
            wallet_label,
            reserve_address_hash,
            view_key_commitment,
            previous_epoch_id,
            signer_set_root,
            multisig_threshold,
            signer_count,
            starts_at_height,
            activates_at_height,
            retires_at_height,
            expected_balance_piconero,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.epoch_id, "monero reserve rotation wallet epoch id")?;
        ensure_non_empty(&self.wallet_label, "monero reserve rotation wallet label")?;
        ensure_non_empty(
            &self.reserve_address_hash,
            "monero reserve rotation address hash",
        )?;
        ensure_non_empty(
            &self.view_key_commitment,
            "monero reserve rotation view key commitment",
        )?;
        ensure_non_empty(&self.signer_set_root, "monero reserve rotation signer root")?;
        ensure_threshold(self.multisig_threshold, self.signer_count)?;
        if self.activates_at_height < self.starts_at_height {
            return Err("monero reserve rotation activation precedes start".to_string());
        }
        if let Some(retire_height) = self.retires_at_height {
            if retire_height <= self.activates_at_height {
                return Err("monero reserve rotation retirement precedes activation".to_string());
            }
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_wallet_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch": self.epoch,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "wallet_label": self.wallet_label,
            "reserve_address_hash": self.reserve_address_hash,
            "view_key_commitment": self.view_key_commitment,
            "previous_epoch_id": self.previous_epoch_id,
            "signer_set_root": self.signer_set_root,
            "multisig_threshold": self.multisig_threshold,
            "signer_count": self.signer_count,
            "starts_at_height": self.starts_at_height,
            "activates_at_height": self.activates_at_height,
            "retires_at_height": self.retires_at_height,
            "expected_balance_piconero": self.expected_balance_piconero,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-WALLET-EPOCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRotationCeremony {
    pub ceremony_id: String,
    pub from_epoch_id: String,
    pub to_epoch_id: String,
    pub status: PqRotationCeremonyStatus,
    pub coordinator_commitment: String,
    pub pq_manifest_root: String,
    pub classic_multisig_transcript_root: String,
    pub sealed_share_root: String,
    pub watchtower_attestation_root: String,
    pub announced_at_height: u64,
    pub activates_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRotationCeremony {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_epoch_id: impl Into<String>,
        to_epoch_id: impl Into<String>,
        status: PqRotationCeremonyStatus,
        coordinator_commitment: impl Into<String>,
        pq_manifest_root: impl Into<String>,
        classic_multisig_transcript_root: impl Into<String>,
        sealed_share_root: impl Into<String>,
        watchtower_attestation_root: impl Into<String>,
        announced_at_height: u64,
        activates_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let from_epoch_id = from_epoch_id.into();
        let to_epoch_id = to_epoch_id.into();
        let coordinator_commitment = coordinator_commitment.into();
        let pq_manifest_root = pq_manifest_root.into();
        let classic_multisig_transcript_root = classic_multisig_transcript_root.into();
        let sealed_share_root = sealed_share_root.into();
        let watchtower_attestation_root = watchtower_attestation_root.into();
        ensure_non_empty(&from_epoch_id, "monero reserve rotation source epoch")?;
        ensure_non_empty(&to_epoch_id, "monero reserve rotation target epoch")?;
        ensure_non_empty(
            &coordinator_commitment,
            "monero reserve rotation coordinator",
        )?;
        ensure_non_empty(&pq_manifest_root, "monero reserve rotation pq manifest")?;
        ensure_non_empty(
            &classic_multisig_transcript_root,
            "monero reserve rotation transcript root",
        )?;
        ensure_non_empty(
            &sealed_share_root,
            "monero reserve rotation sealed share root",
        )?;
        ensure_non_empty(
            &watchtower_attestation_root,
            "monero reserve rotation watchtower attestation root",
        )?;
        if activates_at_height <= announced_at_height {
            return Err(
                "monero reserve rotation ceremony activation must follow announcement".to_string(),
            );
        }
        if expires_at_height <= activates_at_height {
            return Err(
                "monero reserve rotation ceremony expiry must follow activation".to_string(),
            );
        }
        let payload = json!({
            "from_epoch_id": from_epoch_id,
            "to_epoch_id": to_epoch_id,
            "coordinator_commitment": coordinator_commitment,
            "pq_manifest_root": pq_manifest_root,
            "classic_multisig_transcript_root": classic_multisig_transcript_root,
            "sealed_share_root": sealed_share_root,
            "announced_at_height": announced_at_height,
            "activates_at_height": activates_at_height,
        });
        Ok(Self {
            ceremony_id: monero_multisig_reserve_rotation_ceremony_id(&payload),
            from_epoch_id,
            to_epoch_id,
            status,
            coordinator_commitment,
            pq_manifest_root,
            classic_multisig_transcript_root,
            sealed_share_root,
            watchtower_attestation_root,
            announced_at_height,
            activates_at_height,
            expires_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.ceremony_id, "monero reserve rotation ceremony id")?;
        ensure_non_empty(&self.from_epoch_id, "monero reserve rotation source epoch")?;
        ensure_non_empty(&self.to_epoch_id, "monero reserve rotation target epoch")?;
        ensure_non_empty(
            &self.coordinator_commitment,
            "monero reserve rotation coordinator",
        )?;
        ensure_non_empty(
            &self.pq_manifest_root,
            "monero reserve rotation pq manifest",
        )?;
        ensure_non_empty(
            &self.classic_multisig_transcript_root,
            "monero reserve rotation transcript root",
        )?;
        ensure_non_empty(
            &self.sealed_share_root,
            "monero reserve rotation sealed shares",
        )?;
        ensure_non_empty(
            &self.watchtower_attestation_root,
            "monero reserve rotation watchtower root",
        )?;
        if self.activates_at_height <= self.announced_at_height {
            return Err(
                "monero reserve rotation ceremony activation must follow announcement".to_string(),
            );
        }
        if self.expires_at_height <= self.activates_at_height {
            return Err(
                "monero reserve rotation ceremony expiry must follow activation".to_string(),
            );
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_rotation_ceremony",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "ceremony_id": self.ceremony_id,
            "from_epoch_id": self.from_epoch_id,
            "to_epoch_id": self.to_epoch_id,
            "status": self.status.as_str(),
            "coordinator_commitment": self.coordinator_commitment,
            "pq_manifest_root": self.pq_manifest_root,
            "classic_multisig_transcript_root": self.classic_multisig_transcript_root,
            "sealed_share_root": self.sealed_share_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "announced_at_height": self.announced_at_height,
            "activates_at_height": self.activates_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-CEREMONY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerShard {
    pub shard_id: String,
    pub signer_commitment: String,
    pub role: SignerShardRole,
    pub status: SignerShardStatus,
    pub epoch_id: String,
    pub pq_public_key_commitment: String,
    pub encrypted_share_root: String,
    pub recovery_commitment: String,
    pub weight: u64,
    pub sealed_at_height: u64,
}

impl SignerShard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer_commitment: impl Into<String>,
        role: SignerShardRole,
        status: SignerShardStatus,
        epoch_id: impl Into<String>,
        pq_public_key_commitment: impl Into<String>,
        encrypted_share_root: impl Into<String>,
        recovery_commitment: impl Into<String>,
        weight: u64,
        sealed_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let signer_commitment = signer_commitment.into();
        let epoch_id = epoch_id.into();
        let pq_public_key_commitment = pq_public_key_commitment.into();
        let encrypted_share_root = encrypted_share_root.into();
        let recovery_commitment = recovery_commitment.into();
        ensure_non_empty(&signer_commitment, "monero reserve rotation signer")?;
        ensure_non_empty(&epoch_id, "monero reserve rotation signer epoch")?;
        ensure_non_empty(
            &pq_public_key_commitment,
            "monero reserve rotation signer pq key",
        )?;
        ensure_non_empty(
            &encrypted_share_root,
            "monero reserve rotation encrypted share",
        )?;
        ensure_non_empty(
            &recovery_commitment,
            "monero reserve rotation recovery commitment",
        )?;
        ensure_positive(weight, "monero reserve rotation signer weight")?;
        let payload = json!({
            "signer_commitment": signer_commitment,
            "role": role.as_str(),
            "epoch_id": epoch_id,
            "pq_public_key_commitment": pq_public_key_commitment,
            "encrypted_share_root": encrypted_share_root,
            "sealed_at_height": sealed_at_height,
        });
        Ok(Self {
            shard_id: monero_multisig_reserve_rotation_signer_shard_id(&payload),
            signer_commitment,
            role,
            status,
            epoch_id,
            pq_public_key_commitment,
            encrypted_share_root,
            recovery_commitment,
            weight,
            sealed_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.shard_id, "monero reserve rotation shard id")?;
        ensure_non_empty(&self.signer_commitment, "monero reserve rotation signer")?;
        ensure_non_empty(&self.epoch_id, "monero reserve rotation signer epoch")?;
        ensure_non_empty(
            &self.pq_public_key_commitment,
            "monero reserve rotation signer pq key",
        )?;
        ensure_non_empty(
            &self.encrypted_share_root,
            "monero reserve rotation encrypted share",
        )?;
        ensure_non_empty(
            &self.recovery_commitment,
            "monero reserve rotation recovery commitment",
        )?;
        ensure_positive(self.weight, "monero reserve rotation signer weight")?;
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "signer_shard",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "shard_id": self.shard_id,
            "signer_commitment": self.signer_commitment,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "epoch_id": self.epoch_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "encrypted_share_root": self.encrypted_share_root,
            "recovery_commitment": self.recovery_commitment,
            "weight": self.weight,
            "sealed_at_height": self.sealed_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-SIGNER-SHARD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerRotationAttestation {
    pub attestation_id: String,
    pub watchtower_commitment: String,
    pub ceremony_id: String,
    pub subject_root: String,
    pub signature_root: String,
    pub status: WatchtowerRotationAttestationStatus,
    pub weight: u64,
    pub observed_height: u64,
    pub expires_at_height: u64,
}

impl WatchtowerRotationAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watchtower_commitment: impl Into<String>,
        ceremony_id: impl Into<String>,
        subject_root: impl Into<String>,
        signature_material: impl Into<String>,
        status: WatchtowerRotationAttestationStatus,
        weight: u64,
        observed_height: u64,
        expires_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let watchtower_commitment = watchtower_commitment.into();
        let ceremony_id = ceremony_id.into();
        let subject_root = subject_root.into();
        let signature_material = signature_material.into();
        ensure_non_empty(&watchtower_commitment, "monero reserve rotation watchtower")?;
        ensure_non_empty(&ceremony_id, "monero reserve rotation ceremony")?;
        ensure_non_empty(&subject_root, "monero reserve rotation subject root")?;
        ensure_non_empty(
            &signature_material,
            "monero reserve rotation signature material",
        )?;
        ensure_positive(weight, "monero reserve rotation watchtower weight")?;
        if expires_at_height <= observed_height {
            return Err(
                "monero reserve rotation attestation expiry must follow observation".to_string(),
            );
        }
        let signature_root = monero_multisig_reserve_rotation_signature_root(
            &watchtower_commitment,
            "pq_rotation_ceremony",
            &ceremony_id,
            &subject_root,
            &signature_material,
        );
        let payload = json!({
            "watchtower_commitment": watchtower_commitment,
            "ceremony_id": ceremony_id,
            "subject_root": subject_root,
            "signature_root": signature_root,
            "observed_height": observed_height,
        });
        Ok(Self {
            attestation_id: monero_multisig_reserve_rotation_watchtower_attestation_id(&payload),
            watchtower_commitment,
            ceremony_id,
            subject_root,
            signature_root,
            status,
            weight,
            observed_height,
            expires_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(
            &self.attestation_id,
            "monero reserve rotation attestation id",
        )?;
        ensure_non_empty(
            &self.watchtower_commitment,
            "monero reserve rotation watchtower",
        )?;
        ensure_non_empty(&self.ceremony_id, "monero reserve rotation ceremony")?;
        ensure_non_empty(&self.subject_root, "monero reserve rotation subject root")?;
        ensure_non_empty(
            &self.signature_root,
            "monero reserve rotation signature root",
        )?;
        ensure_positive(self.weight, "monero reserve rotation watchtower weight")?;
        if self.expires_at_height <= self.observed_height {
            return Err(
                "monero reserve rotation attestation expiry must follow observation".to_string(),
            );
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "watchtower_rotation_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "watchtower_commitment": self.watchtower_commitment,
            "ceremony_id": self.ceremony_id,
            "subject_root": self.subject_root,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "weight": self.weight,
            "observed_height": self.observed_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-WATCHTOWER-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyFreezeReleaseWindow {
    pub window_id: String,
    pub kind: EmergencyWindowKind,
    pub status: EmergencyWindowStatus,
    pub epoch_id: String,
    pub reason_code: String,
    pub evidence_root: String,
    pub guardian_attestation_root: String,
    pub starts_at_height: u64,
    pub releases_at_height: u64,
}

impl EmergencyFreezeReleaseWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: EmergencyWindowKind,
        status: EmergencyWindowStatus,
        epoch_id: impl Into<String>,
        reason_code: impl Into<String>,
        evidence_root: impl Into<String>,
        guardian_attestation_root: impl Into<String>,
        starts_at_height: u64,
        releases_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let epoch_id = epoch_id.into();
        let reason_code = reason_code.into();
        let evidence_root = evidence_root.into();
        let guardian_attestation_root = guardian_attestation_root.into();
        ensure_non_empty(&epoch_id, "monero reserve rotation emergency epoch")?;
        ensure_non_empty(&reason_code, "monero reserve rotation emergency reason")?;
        ensure_non_empty(&evidence_root, "monero reserve rotation emergency evidence")?;
        ensure_non_empty(
            &guardian_attestation_root,
            "monero reserve rotation guardian attestation",
        )?;
        if releases_at_height <= starts_at_height {
            return Err("monero reserve rotation emergency release must follow start".to_string());
        }
        let payload = json!({
            "kind": kind.as_str(),
            "epoch_id": epoch_id,
            "reason_code": reason_code,
            "evidence_root": evidence_root,
            "starts_at_height": starts_at_height,
        });
        Ok(Self {
            window_id: monero_multisig_reserve_rotation_emergency_window_id(&payload),
            kind,
            status,
            epoch_id,
            reason_code,
            evidence_root,
            guardian_attestation_root,
            starts_at_height,
            releases_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.window_id, "monero reserve rotation emergency window")?;
        ensure_non_empty(&self.epoch_id, "monero reserve rotation emergency epoch")?;
        ensure_non_empty(
            &self.reason_code,
            "monero reserve rotation emergency reason",
        )?;
        ensure_non_empty(
            &self.evidence_root,
            "monero reserve rotation emergency evidence",
        )?;
        ensure_non_empty(
            &self.guardian_attestation_root,
            "monero reserve rotation guardian attestation",
        )?;
        if self.releases_at_height <= self.starts_at_height {
            return Err("monero reserve rotation emergency release must follow start".to_string());
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_freeze_release_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "window_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "epoch_id": self.epoch_id,
            "reason_code": self.reason_code,
            "evidence_root": self.evidence_root,
            "guardian_attestation_root": self.guardian_attestation_root,
            "starts_at_height": self.starts_at_height,
            "releases_at_height": self.releases_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-EMERGENCY-WINDOW",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressMigrationBatch {
    pub batch_id: String,
    pub from_epoch_id: String,
    pub to_epoch_id: String,
    pub status: SubaddressMigrationStatus,
    pub subaddress_index_start: u64,
    pub subaddress_index_end: u64,
    pub output_commitment_root: String,
    pub sweep_tx_root: String,
    pub fee_sponsorship_id: Option<String>,
    pub expected_output_count: u64,
    pub migrated_piconero: u64,
    pub starts_at_height: u64,
    pub completes_at_height: u64,
}

impl SubaddressMigrationBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_epoch_id: impl Into<String>,
        to_epoch_id: impl Into<String>,
        status: SubaddressMigrationStatus,
        subaddress_index_start: u64,
        subaddress_index_end: u64,
        output_commitment_root: impl Into<String>,
        sweep_tx_root: impl Into<String>,
        fee_sponsorship_id: Option<String>,
        expected_output_count: u64,
        migrated_piconero: u64,
        starts_at_height: u64,
        completes_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let from_epoch_id = from_epoch_id.into();
        let to_epoch_id = to_epoch_id.into();
        let output_commitment_root = output_commitment_root.into();
        let sweep_tx_root = sweep_tx_root.into();
        ensure_non_empty(&from_epoch_id, "monero reserve rotation migration source")?;
        ensure_non_empty(&to_epoch_id, "monero reserve rotation migration target")?;
        ensure_non_empty(
            &output_commitment_root,
            "monero reserve rotation output commitment",
        )?;
        ensure_non_empty(&sweep_tx_root, "monero reserve rotation sweep tx root")?;
        ensure_positive(
            expected_output_count,
            "monero reserve rotation expected outputs",
        )?;
        if subaddress_index_end < subaddress_index_start {
            return Err("monero reserve rotation subaddress range is inverted".to_string());
        }
        if completes_at_height <= starts_at_height {
            return Err(
                "monero reserve rotation migration completion must follow start".to_string(),
            );
        }
        let payload = json!({
            "from_epoch_id": from_epoch_id,
            "to_epoch_id": to_epoch_id,
            "subaddress_index_start": subaddress_index_start,
            "subaddress_index_end": subaddress_index_end,
            "output_commitment_root": output_commitment_root,
            "sweep_tx_root": sweep_tx_root,
            "starts_at_height": starts_at_height,
        });
        Ok(Self {
            batch_id: monero_multisig_reserve_rotation_subaddress_batch_id(&payload),
            from_epoch_id,
            to_epoch_id,
            status,
            subaddress_index_start,
            subaddress_index_end,
            output_commitment_root,
            sweep_tx_root,
            fee_sponsorship_id,
            expected_output_count,
            migrated_piconero,
            starts_at_height,
            completes_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.batch_id, "monero reserve rotation migration batch")?;
        ensure_non_empty(
            &self.from_epoch_id,
            "monero reserve rotation migration source",
        )?;
        ensure_non_empty(
            &self.to_epoch_id,
            "monero reserve rotation migration target",
        )?;
        ensure_non_empty(
            &self.output_commitment_root,
            "monero reserve rotation output commitment",
        )?;
        ensure_non_empty(&self.sweep_tx_root, "monero reserve rotation sweep tx root")?;
        ensure_positive(
            self.expected_output_count,
            "monero reserve rotation expected outputs",
        )?;
        if self.subaddress_index_end < self.subaddress_index_start {
            return Err("monero reserve rotation subaddress range is inverted".to_string());
        }
        if self.completes_at_height <= self.starts_at_height {
            return Err(
                "monero reserve rotation migration completion must follow start".to_string(),
            );
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "subaddress_migration_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "from_epoch_id": self.from_epoch_id,
            "to_epoch_id": self.to_epoch_id,
            "status": self.status.as_str(),
            "subaddress_index_start": self.subaddress_index_start,
            "subaddress_index_end": self.subaddress_index_end,
            "output_commitment_root": self.output_commitment_root,
            "sweep_tx_root": self.sweep_tx_root,
            "fee_sponsorship_id": self.fee_sponsorship_id,
            "expected_output_count": self.expected_output_count,
            "migrated_piconero": self.migrated_piconero,
            "starts_at_height": self.starts_at_height,
            "completes_at_height": self.completes_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-SUBADDRESS-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyImageAuditCommitment {
    pub audit_id: String,
    pub epoch_id: String,
    pub status: AuditCommitmentStatus,
    pub daemon_block_height: u64,
    pub daemon_block_hash: String,
    pub key_image_absence_root: String,
    pub spent_key_image_root: String,
    pub output_commitment_root: String,
    pub auditor_commitment: String,
    pub posted_at_height: u64,
}

impl KeyImageAuditCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: impl Into<String>,
        status: AuditCommitmentStatus,
        daemon_block_height: u64,
        daemon_block_hash: impl Into<String>,
        key_image_absence_root: impl Into<String>,
        spent_key_image_root: impl Into<String>,
        output_commitment_root: impl Into<String>,
        auditor_commitment: impl Into<String>,
        posted_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let epoch_id = epoch_id.into();
        let daemon_block_hash = daemon_block_hash.into();
        let key_image_absence_root = key_image_absence_root.into();
        let spent_key_image_root = spent_key_image_root.into();
        let output_commitment_root = output_commitment_root.into();
        let auditor_commitment = auditor_commitment.into();
        ensure_non_empty(&epoch_id, "monero reserve rotation audit epoch")?;
        ensure_non_empty(&daemon_block_hash, "monero reserve rotation daemon block")?;
        ensure_non_empty(
            &key_image_absence_root,
            "monero reserve rotation absent key images",
        )?;
        ensure_non_empty(
            &spent_key_image_root,
            "monero reserve rotation spent key images",
        )?;
        ensure_non_empty(
            &output_commitment_root,
            "monero reserve rotation output commitments",
        )?;
        ensure_non_empty(&auditor_commitment, "monero reserve rotation auditor")?;
        let payload = json!({
            "epoch_id": epoch_id,
            "daemon_block_height": daemon_block_height,
            "daemon_block_hash": daemon_block_hash,
            "key_image_absence_root": key_image_absence_root,
            "spent_key_image_root": spent_key_image_root,
            "output_commitment_root": output_commitment_root,
        });
        Ok(Self {
            audit_id: monero_multisig_reserve_rotation_key_image_audit_id(&payload),
            epoch_id,
            status,
            daemon_block_height,
            daemon_block_hash,
            key_image_absence_root,
            spent_key_image_root,
            output_commitment_root,
            auditor_commitment,
            posted_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.audit_id, "monero reserve rotation audit id")?;
        ensure_non_empty(&self.epoch_id, "monero reserve rotation audit epoch")?;
        ensure_non_empty(
            &self.daemon_block_hash,
            "monero reserve rotation daemon block",
        )?;
        ensure_non_empty(
            &self.key_image_absence_root,
            "monero reserve rotation absent key images",
        )?;
        ensure_non_empty(
            &self.spent_key_image_root,
            "monero reserve rotation spent key images",
        )?;
        ensure_non_empty(
            &self.output_commitment_root,
            "monero reserve rotation output commitments",
        )?;
        ensure_non_empty(&self.auditor_commitment, "monero reserve rotation auditor")?;
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "key_image_audit_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "audit_id": self.audit_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "daemon_block_height": self.daemon_block_height,
            "daemon_block_hash": self.daemon_block_hash,
            "key_image_absence_root": self.key_image_absence_root,
            "spent_key_image_root": self.spent_key_image_root,
            "output_commitment_root": self.output_commitment_root,
            "auditor_commitment": self.auditor_commitment,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-KEY-IMAGE-AUDIT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencySnapshot {
    pub snapshot_id: String,
    pub epoch_id: String,
    pub audit_id: String,
    pub status: SolvencySnapshotStatus,
    pub reserve_piconero: u64,
    pub liability_piconero: u64,
    pub pending_rotation_piconero: u64,
    pub coverage_bps: u64,
    pub watchtower_weight: u64,
    pub observed_at_height: u64,
}

impl SolvencySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: impl Into<String>,
        audit_id: impl Into<String>,
        status: SolvencySnapshotStatus,
        reserve_piconero: u64,
        liability_piconero: u64,
        pending_rotation_piconero: u64,
        watchtower_weight: u64,
        observed_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let epoch_id = epoch_id.into();
        let audit_id = audit_id.into();
        ensure_non_empty(&epoch_id, "monero reserve rotation solvency epoch")?;
        ensure_non_empty(&audit_id, "monero reserve rotation solvency audit")?;
        ensure_positive(reserve_piconero, "monero reserve rotation reserve value")?;
        ensure_positive(
            liability_piconero,
            "monero reserve rotation liability value",
        )?;
        ensure_positive(
            watchtower_weight,
            "monero reserve rotation solvency watchtower weight",
        )?;
        let coverage_bps = reserve_coverage_bps(reserve_piconero, liability_piconero);
        let payload = json!({
            "epoch_id": epoch_id,
            "audit_id": audit_id,
            "reserve_piconero": reserve_piconero,
            "liability_piconero": liability_piconero,
            "pending_rotation_piconero": pending_rotation_piconero,
            "observed_at_height": observed_at_height,
        });
        Ok(Self {
            snapshot_id: monero_multisig_reserve_rotation_solvency_snapshot_id(&payload),
            epoch_id,
            audit_id,
            status,
            reserve_piconero,
            liability_piconero,
            pending_rotation_piconero,
            coverage_bps,
            watchtower_weight,
            observed_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(&self.snapshot_id, "monero reserve rotation solvency id")?;
        ensure_non_empty(&self.epoch_id, "monero reserve rotation solvency epoch")?;
        ensure_non_empty(&self.audit_id, "monero reserve rotation solvency audit")?;
        ensure_positive(
            self.reserve_piconero,
            "monero reserve rotation reserve value",
        )?;
        ensure_positive(
            self.liability_piconero,
            "monero reserve rotation liability value",
        )?;
        ensure_positive(
            self.watchtower_weight,
            "monero reserve rotation solvency watchtower weight",
        )?;
        if self.coverage_bps != reserve_coverage_bps(self.reserve_piconero, self.liability_piconero)
        {
            return Err("monero reserve rotation solvency coverage mismatch".to_string());
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solvency_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "epoch_id": self.epoch_id,
            "audit_id": self.audit_id,
            "status": self.status.as_str(),
            "reserve_piconero": self.reserve_piconero,
            "liability_piconero": self.liability_piconero,
            "pending_rotation_piconero": self.pending_rotation_piconero,
            "coverage_bps": self.coverage_bps,
            "watchtower_weight": self.watchtower_weight,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-SOLVENCY-SNAPSHOT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRotationSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub status: RotationSponsorshipStatus,
    pub fee_asset_id: String,
    pub budget_piconero: u64,
    pub spent_piconero: u64,
    pub max_fee_per_tx_piconero: u64,
    pub covered_batch_ids: Vec<String>,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRotationSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        status: RotationSponsorshipStatus,
        fee_asset_id: impl Into<String>,
        budget_piconero: u64,
        spent_piconero: u64,
        max_fee_per_tx_piconero: u64,
        covered_batch_ids: Vec<String>,
        starts_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&sponsor_commitment, "monero reserve rotation sponsor")?;
        ensure_non_empty(
            &fee_asset_id,
            "monero reserve rotation sponsorship fee asset",
        )?;
        ensure_positive(
            budget_piconero,
            "monero reserve rotation sponsorship budget",
        )?;
        ensure_positive(
            max_fee_per_tx_piconero,
            "monero reserve rotation sponsorship max fee",
        )?;
        ensure_string_list(
            &covered_batch_ids,
            "monero reserve rotation sponsored batches",
        )?;
        if spent_piconero > budget_piconero {
            return Err("monero reserve rotation sponsorship overspent".to_string());
        }
        if expires_at_height <= starts_at_height {
            return Err("monero reserve rotation sponsorship expiry must follow start".to_string());
        }
        let payload = json!({
            "sponsor_commitment": sponsor_commitment,
            "fee_asset_id": fee_asset_id,
            "budget_piconero": budget_piconero,
            "covered_batch_root": string_set_root("MONERO-MULTISIG-RESERVE-ROTATION-SPONSORED-BATCHES", &covered_batch_ids),
            "starts_at_height": starts_at_height,
        });
        Ok(Self {
            sponsorship_id: monero_multisig_reserve_rotation_sponsorship_id(&payload),
            sponsor_commitment,
            status,
            fee_asset_id,
            budget_piconero,
            spent_piconero,
            max_fee_per_tx_piconero,
            covered_batch_ids,
            starts_at_height,
            expires_at_height,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(
            &self.sponsorship_id,
            "monero reserve rotation sponsorship id",
        )?;
        ensure_non_empty(&self.sponsor_commitment, "monero reserve rotation sponsor")?;
        ensure_non_empty(
            &self.fee_asset_id,
            "monero reserve rotation sponsorship fee asset",
        )?;
        ensure_positive(
            self.budget_piconero,
            "monero reserve rotation sponsorship budget",
        )?;
        ensure_positive(
            self.max_fee_per_tx_piconero,
            "monero reserve rotation sponsorship max fee",
        )?;
        ensure_string_list(
            &self.covered_batch_ids,
            "monero reserve rotation sponsored batches",
        )?;
        if self.spent_piconero > self.budget_piconero {
            return Err("monero reserve rotation sponsorship overspent".to_string());
        }
        if self.expires_at_height <= self.starts_at_height {
            return Err("monero reserve rotation sponsorship expiry must follow start".to_string());
        }
        Ok(self.record_root())
    }

    pub fn remaining_budget_piconero(&self) -> u64 {
        self.budget_piconero.saturating_sub(self.spent_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rotation_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_piconero": self.budget_piconero,
            "spent_piconero": self.spent_piconero,
            "remaining_budget_piconero": self.remaining_budget_piconero(),
            "max_fee_per_tx_piconero": self.max_fee_per_tx_piconero,
            "covered_batch_root": string_set_root("MONERO-MULTISIG-RESERVE-ROTATION-SPONSORED-BATCHES", &self.covered_batch_ids),
            "covered_batch_ids": self.covered_batch_ids,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-LOW-FEE-SPONSORSHIP",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReorgSafeguard {
    pub safeguard_id: String,
    pub epoch_id: String,
    pub status: RollbackSafeguardStatus,
    pub anchor_block_height: u64,
    pub anchor_block_hash: String,
    pub finalized_height: u64,
    pub reorg_depth_blocks: u64,
    pub rollback_plan_root: String,
    pub affected_record_root: String,
}

impl RollbackReorgSafeguard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: impl Into<String>,
        status: RollbackSafeguardStatus,
        anchor_block_height: u64,
        anchor_block_hash: impl Into<String>,
        finalized_height: u64,
        reorg_depth_blocks: u64,
        rollback_plan_root: impl Into<String>,
        affected_record_root: impl Into<String>,
    ) -> MoneroMultisigReserveRotationResult<Self> {
        let epoch_id = epoch_id.into();
        let anchor_block_hash = anchor_block_hash.into();
        let rollback_plan_root = rollback_plan_root.into();
        let affected_record_root = affected_record_root.into();
        ensure_non_empty(&epoch_id, "monero reserve rotation rollback epoch")?;
        ensure_non_empty(&anchor_block_hash, "monero reserve rotation anchor block")?;
        ensure_positive(reorg_depth_blocks, "monero reserve rotation reorg depth")?;
        ensure_non_empty(&rollback_plan_root, "monero reserve rotation rollback plan")?;
        ensure_non_empty(
            &affected_record_root,
            "monero reserve rotation affected record root",
        )?;
        if finalized_height < anchor_block_height {
            return Err("monero reserve rotation finalized height precedes anchor".to_string());
        }
        let payload = json!({
            "epoch_id": epoch_id,
            "anchor_block_height": anchor_block_height,
            "anchor_block_hash": anchor_block_hash,
            "finalized_height": finalized_height,
            "rollback_plan_root": rollback_plan_root,
        });
        Ok(Self {
            safeguard_id: monero_multisig_reserve_rotation_rollback_safeguard_id(&payload),
            epoch_id,
            status,
            anchor_block_height,
            anchor_block_hash,
            finalized_height,
            reorg_depth_blocks,
            rollback_plan_root,
            affected_record_root,
        })
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        ensure_non_empty(
            &self.safeguard_id,
            "monero reserve rotation rollback safeguard",
        )?;
        ensure_non_empty(&self.epoch_id, "monero reserve rotation rollback epoch")?;
        ensure_non_empty(
            &self.anchor_block_hash,
            "monero reserve rotation anchor block",
        )?;
        ensure_positive(
            self.reorg_depth_blocks,
            "monero reserve rotation reorg depth",
        )?;
        ensure_non_empty(
            &self.rollback_plan_root,
            "monero reserve rotation rollback plan",
        )?;
        ensure_non_empty(
            &self.affected_record_root,
            "monero reserve rotation affected record root",
        )?;
        if self.finalized_height < self.anchor_block_height {
            return Err("monero reserve rotation finalized height precedes anchor".to_string());
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollback_reorg_safeguard",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "safeguard_id": self.safeguard_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "anchor_block_height": self.anchor_block_height,
            "anchor_block_hash": self.anchor_block_hash,
            "finalized_height": self.finalized_height,
            "reorg_depth_blocks": self.reorg_depth_blocks,
            "rollback_plan_root": self.rollback_plan_root,
            "affected_record_root": self.affected_record_root,
        })
    }

    pub fn record_root(&self) -> String {
        monero_multisig_reserve_rotation_payload_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-ROLLBACK-SAFEGUARD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroMultisigReserveRotationRoots {
    pub config_root: String,
    pub wallet_epoch_root: String,
    pub ceremony_root: String,
    pub signer_shard_root: String,
    pub watchtower_attestation_root: String,
    pub emergency_window_root: String,
    pub subaddress_migration_root: String,
    pub key_image_audit_root: String,
    pub solvency_snapshot_root: String,
    pub low_fee_sponsorship_root: String,
    pub rollback_safeguard_root: String,
    pub state_root: String,
}

impl MoneroMultisigReserveRotationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_multisig_reserve_rotation_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "wallet_epoch_root": self.wallet_epoch_root,
            "ceremony_root": self.ceremony_root,
            "signer_shard_root": self.signer_shard_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "emergency_window_root": self.emergency_window_root,
            "subaddress_migration_root": self.subaddress_migration_root,
            "key_image_audit_root": self.key_image_audit_root,
            "solvency_snapshot_root": self.solvency_snapshot_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "rollback_safeguard_root": self.rollback_safeguard_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroMultisigReserveRotationCounters {
    pub wallet_epoch_count: u64,
    pub live_wallet_epoch_count: u64,
    pub ceremony_count: u64,
    pub open_ceremony_count: u64,
    pub signer_shard_count: u64,
    pub active_signer_shard_count: u64,
    pub watchtower_attestation_count: u64,
    pub accepted_watchtower_weight: u64,
    pub emergency_window_count: u64,
    pub open_emergency_window_count: u64,
    pub subaddress_migration_count: u64,
    pub open_subaddress_migration_count: u64,
    pub key_image_audit_count: u64,
    pub usable_key_image_audit_count: u64,
    pub solvency_snapshot_count: u64,
    pub usable_solvency_snapshot_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub live_low_fee_sponsorship_count: u64,
    pub rollback_safeguard_count: u64,
    pub triggered_rollback_safeguard_count: u64,
    pub total_reserve_piconero: u64,
    pub total_liability_piconero: u64,
    pub total_pending_rotation_piconero: u64,
    pub reserve_coverage_bps: u64,
    pub sponsored_fee_remaining_piconero: u64,
}

impl MoneroMultisigReserveRotationCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_multisig_reserve_rotation_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "wallet_epoch_count": self.wallet_epoch_count,
            "live_wallet_epoch_count": self.live_wallet_epoch_count,
            "ceremony_count": self.ceremony_count,
            "open_ceremony_count": self.open_ceremony_count,
            "signer_shard_count": self.signer_shard_count,
            "active_signer_shard_count": self.active_signer_shard_count,
            "watchtower_attestation_count": self.watchtower_attestation_count,
            "accepted_watchtower_weight": self.accepted_watchtower_weight,
            "emergency_window_count": self.emergency_window_count,
            "open_emergency_window_count": self.open_emergency_window_count,
            "subaddress_migration_count": self.subaddress_migration_count,
            "open_subaddress_migration_count": self.open_subaddress_migration_count,
            "key_image_audit_count": self.key_image_audit_count,
            "usable_key_image_audit_count": self.usable_key_image_audit_count,
            "solvency_snapshot_count": self.solvency_snapshot_count,
            "usable_solvency_snapshot_count": self.usable_solvency_snapshot_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "live_low_fee_sponsorship_count": self.live_low_fee_sponsorship_count,
            "rollback_safeguard_count": self.rollback_safeguard_count,
            "triggered_rollback_safeguard_count": self.triggered_rollback_safeguard_count,
            "total_reserve_piconero": self.total_reserve_piconero,
            "total_liability_piconero": self.total_liability_piconero,
            "total_pending_rotation_piconero": self.total_pending_rotation_piconero,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "sponsored_fee_remaining_piconero": self.sponsored_fee_remaining_piconero,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroMultisigReserveRotationState {
    pub height: u64,
    pub config: MoneroMultisigReserveRotationConfig,
    pub wallet_epochs: BTreeMap<String, ReserveWalletEpoch>,
    pub pq_rotation_ceremonies: BTreeMap<String, PqRotationCeremony>,
    pub signer_shards: BTreeMap<String, SignerShard>,
    pub watchtower_attestations: BTreeMap<String, WatchtowerRotationAttestation>,
    pub emergency_windows: BTreeMap<String, EmergencyFreezeReleaseWindow>,
    pub subaddress_migration_batches: BTreeMap<String, SubaddressMigrationBatch>,
    pub key_image_audit_commitments: BTreeMap<String, KeyImageAuditCommitment>,
    pub solvency_snapshots: BTreeMap<String, SolvencySnapshot>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeRotationSponsorship>,
    pub rollback_safeguards: BTreeMap<String, RollbackReorgSafeguard>,
}

impl Default for MoneroMultisigReserveRotationState {
    fn default() -> Self {
        Self::new(
            MoneroMultisigReserveRotationConfig::default(),
            MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_HEIGHT,
        )
    }
}

impl MoneroMultisigReserveRotationState {
    pub fn new(config: MoneroMultisigReserveRotationConfig, height: u64) -> Self {
        Self {
            height,
            config,
            wallet_epochs: BTreeMap::new(),
            pq_rotation_ceremonies: BTreeMap::new(),
            signer_shards: BTreeMap::new(),
            watchtower_attestations: BTreeMap::new(),
            emergency_windows: BTreeMap::new(),
            subaddress_migration_batches: BTreeMap::new(),
            key_image_audit_commitments: BTreeMap::new(),
            solvency_snapshots: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            rollback_safeguards: BTreeMap::new(),
        }
    }

    pub fn devnet() -> MoneroMultisigReserveRotationResult<Self> {
        let mut state = Self::new(
            MoneroMultisigReserveRotationConfig::default(),
            MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_HEIGHT,
        );

        let signer_set_a = string_set_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-DEVNET-SIGNER-SET-A",
            &[
                "devnet-reserve-signer-a".to_string(),
                "devnet-reserve-signer-b".to_string(),
                "devnet-reserve-signer-c".to_string(),
            ],
        );
        let signer_set_b = string_set_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-DEVNET-SIGNER-SET-B",
            &[
                "devnet-reserve-signer-b".to_string(),
                "devnet-reserve-signer-c".to_string(),
                "devnet-reserve-signer-d".to_string(),
            ],
        );

        let epoch_a = ReserveWalletEpoch::new(
            7,
            ReserveWalletRole::ColdReserve,
            ReserveWalletEpochStatus::Rotating,
            "devnet-cold-reserve-epoch-7",
            "devnet-reserve-address-hash-epoch-7",
            "devnet-view-key-commitment-epoch-7",
            None,
            signer_set_a,
            2,
            3,
            0,
            96,
            Some(576),
            12_800_000_000_000,
        )?;
        state.insert_wallet_epoch(epoch_a.clone())?;

        let epoch_b = ReserveWalletEpoch::new(
            8,
            ReserveWalletRole::RotationStaging,
            ReserveWalletEpochStatus::Active,
            "devnet-cold-reserve-epoch-8",
            "devnet-reserve-address-hash-epoch-8",
            "devnet-view-key-commitment-epoch-8",
            Some(epoch_a.epoch_id.clone()),
            signer_set_b,
            2,
            3,
            360,
            432,
            None,
            13_150_000_000_000,
        )?;
        state.insert_wallet_epoch(epoch_b.clone())?;

        for signer in [
            ("devnet-reserve-signer-b", SignerShardRole::PrimarySigner, 2),
            ("devnet-reserve-signer-c", SignerShardRole::PrimarySigner, 2),
            ("devnet-reserve-signer-d", SignerShardRole::BackupSigner, 1),
            (
                "devnet-emergency-guardian-a",
                SignerShardRole::EmergencyGuardian,
                1,
            ),
        ] {
            let shard = SignerShard::new(
                signer.0,
                signer.1,
                SignerShardStatus::Active,
                &epoch_b.epoch_id,
                format!("{}-pq-public-key-commitment", signer.0),
                format!("{}-encrypted-share-root", signer.0),
                format!("{}-recovery-commitment", signer.0),
                signer.2,
                384,
            )?;
            state.insert_signer_shard(shard)?;
        }

        let sealed_share_root = collection_root(
            "MONERO-MULTISIG-RESERVE-ROTATION-DEVNET-SEALED-SHARES",
            state
                .signer_shards
                .values()
                .map(|record| (record.shard_id.clone(), record.public_record()))
                .collect(),
        );
        let ceremony = PqRotationCeremony::new(
            &epoch_a.epoch_id,
            &epoch_b.epoch_id,
            PqRotationCeremonyStatus::WatchtowerAttested,
            "devnet-rotation-coordinator-a",
            "devnet-pq-rotation-manifest-root-8",
            "devnet-classic-multisig-transcript-root-8",
            sealed_share_root,
            "devnet-watchtower-attestation-aggregate-root",
            360,
            432,
            576,
        )?;
        state.insert_pq_rotation_ceremony(ceremony.clone())?;

        for watchtower in [
            (
                "devnet-watchtower-a",
                2,
                WatchtowerRotationAttestationStatus::Accepted,
            ),
            (
                "devnet-watchtower-b",
                1,
                WatchtowerRotationAttestationStatus::Accepted,
            ),
            (
                "devnet-watchtower-c",
                1,
                WatchtowerRotationAttestationStatus::Submitted,
            ),
        ] {
            let attestation = WatchtowerRotationAttestation::new(
                watchtower.0,
                &ceremony.ceremony_id,
                ceremony.record_root(),
                format!("{}-rotation-signature-material", watchtower.0),
                watchtower.2,
                watchtower.1,
                420,
                492,
            )?;
            state.insert_watchtower_attestation(attestation)?;
        }

        let sponsorship_placeholder_batch = "devnet-subaddress-batch-placeholder".to_string();
        let sponsorship = LowFeeRotationSponsorship::new(
            "devnet-low-fee-rotation-sponsor",
            RotationSponsorshipStatus::Applied,
            MONERO_MULTISIG_RESERVE_ROTATION_DEVNET_FEE_ASSET_ID,
            MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_LOW_FEE_BUDGET_PICONERO,
            275_000_000,
            75_000_000,
            vec![sponsorship_placeholder_batch],
            360,
            576,
        )?;
        state.insert_low_fee_sponsorship(sponsorship.clone())?;

        let batch = SubaddressMigrationBatch::new(
            &epoch_a.epoch_id,
            &epoch_b.epoch_id,
            SubaddressMigrationStatus::Sponsored,
            0,
            511,
            "devnet-subaddress-output-commitment-root-0-511",
            "devnet-subaddress-sweep-tx-root-0-511",
            Some(sponsorship.sponsorship_id.clone()),
            42,
            3_250_000_000_000,
            432,
            540,
        )?;
        state.insert_subaddress_migration_batch(batch)?;

        let audit = KeyImageAuditCommitment::new(
            &epoch_b.epoch_id,
            AuditCommitmentStatus::WatchtowerAccepted,
            1_536,
            "devnet-monero-block-hash-1536",
            "devnet-key-image-absence-root-1536",
            "devnet-spent-key-image-root-1536",
            "devnet-output-commitment-root-1536",
            "devnet-auditor-a",
            432,
        )?;
        state.insert_key_image_audit_commitment(audit.clone())?;

        let solvency = SolvencySnapshot::new(
            &epoch_b.epoch_id,
            &audit.audit_id,
            SolvencySnapshotStatus::Attested,
            13_150_000_000_000,
            11_900_000_000_000,
            3_250_000_000_000,
            3,
            432,
        )?;
        state.insert_solvency_snapshot(solvency)?;

        let freeze = EmergencyFreezeReleaseWindow::new(
            EmergencyWindowKind::Freeze,
            EmergencyWindowStatus::EvidenceReview,
            &epoch_a.epoch_id,
            "rotation-overlap-key-image-review",
            "devnet-freeze-evidence-root",
            "devnet-guardian-attestation-root",
            432,
            480,
        )?;
        state.insert_emergency_window(freeze)?;

        let rollback = RollbackReorgSafeguard::new(
            &epoch_b.epoch_id,
            RollbackSafeguardStatus::Observing,
            1_536,
            "devnet-monero-block-hash-1536",
            1_548,
            MONERO_MULTISIG_RESERVE_ROTATION_DEFAULT_REORG_DEPTH_BLOCKS,
            "devnet-rotation-rollback-plan-root",
            state.roots_without_state_root().public_record().to_string(),
        )?;
        state.insert_rollback_safeguard(rollback)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroMultisigReserveRotationResult<()> {
        if height < self.height {
            return Err("monero reserve rotation height cannot move backward".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> MoneroMultisigReserveRotationRoots {
        let mut roots = self.roots_without_state_root();
        let record = self.public_record_without_state_root(&roots);
        roots.state_root = monero_multisig_reserve_rotation_state_root_from_record(&record);
        roots
    }

    pub fn counters(&self) -> MoneroMultisigReserveRotationCounters {
        let total_reserve_piconero = self
            .solvency_snapshots
            .values()
            .filter(|snapshot| snapshot.status.usable())
            .map(|snapshot| snapshot.reserve_piconero)
            .fold(0_u64, u64::max);
        let total_liability_piconero = self
            .solvency_snapshots
            .values()
            .filter(|snapshot| snapshot.status.usable())
            .map(|snapshot| snapshot.liability_piconero)
            .fold(0_u64, u64::max);
        let total_pending_rotation_piconero = self
            .solvency_snapshots
            .values()
            .filter(|snapshot| snapshot.status.usable())
            .map(|snapshot| snapshot.pending_rotation_piconero)
            .fold(0_u64, u64::max);
        let sponsored_fee_remaining_piconero = self
            .low_fee_sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status.is_live())
            .map(LowFeeRotationSponsorship::remaining_budget_piconero)
            .fold(0_u64, u64::saturating_add);
        MoneroMultisigReserveRotationCounters {
            wallet_epoch_count: self.wallet_epochs.len() as u64,
            live_wallet_epoch_count: self
                .wallet_epochs
                .values()
                .filter(|epoch| epoch.status.is_live())
                .count() as u64,
            ceremony_count: self.pq_rotation_ceremonies.len() as u64,
            open_ceremony_count: self
                .pq_rotation_ceremonies
                .values()
                .filter(|ceremony| ceremony.status.is_open())
                .count() as u64,
            signer_shard_count: self.signer_shards.len() as u64,
            active_signer_shard_count: self
                .signer_shards
                .values()
                .filter(|shard| shard.status.can_sign())
                .count() as u64,
            watchtower_attestation_count: self.watchtower_attestations.len() as u64,
            accepted_watchtower_weight: self
                .watchtower_attestations
                .values()
                .filter(|attestation| attestation.status.counts_for_quorum())
                .map(|attestation| attestation.weight)
                .fold(0_u64, u64::saturating_add),
            emergency_window_count: self.emergency_windows.len() as u64,
            open_emergency_window_count: self
                .emergency_windows
                .values()
                .filter(|window| window.status.is_open())
                .count() as u64,
            subaddress_migration_count: self.subaddress_migration_batches.len() as u64,
            open_subaddress_migration_count: self
                .subaddress_migration_batches
                .values()
                .filter(|batch| batch.status.is_open())
                .count() as u64,
            key_image_audit_count: self.key_image_audit_commitments.len() as u64,
            usable_key_image_audit_count: self
                .key_image_audit_commitments
                .values()
                .filter(|audit| audit.status.usable_for_solvency())
                .count() as u64,
            solvency_snapshot_count: self.solvency_snapshots.len() as u64,
            usable_solvency_snapshot_count: self
                .solvency_snapshots
                .values()
                .filter(|snapshot| snapshot.status.usable())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            live_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_live())
                .count() as u64,
            rollback_safeguard_count: self.rollback_safeguards.len() as u64,
            triggered_rollback_safeguard_count: self
                .rollback_safeguards
                .values()
                .filter(|safeguard| safeguard.status.blocks_activation())
                .count() as u64,
            total_reserve_piconero,
            total_liability_piconero,
            total_pending_rotation_piconero,
            reserve_coverage_bps: reserve_coverage_bps(
                total_reserve_piconero,
                total_liability_piconero,
            ),
            sponsored_fee_remaining_piconero,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root(&roots);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(roots.state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> MoneroMultisigReserveRotationResult<String> {
        self.config.validate()?;
        for record in self.wallet_epochs.values() {
            record.validate()?;
        }
        for record in self.pq_rotation_ceremonies.values() {
            record.validate()?;
            if !self.wallet_epochs.contains_key(&record.from_epoch_id) {
                return Err(
                    "monero reserve rotation ceremony references unknown source epoch".to_string(),
                );
            }
            if !self.wallet_epochs.contains_key(&record.to_epoch_id) {
                return Err(
                    "monero reserve rotation ceremony references unknown target epoch".to_string(),
                );
            }
        }
        for record in self.signer_shards.values() {
            record.validate()?;
            if !self.wallet_epochs.contains_key(&record.epoch_id) {
                return Err("monero reserve rotation shard references unknown epoch".to_string());
            }
        }
        for record in self.watchtower_attestations.values() {
            record.validate()?;
            if !self
                .pq_rotation_ceremonies
                .contains_key(&record.ceremony_id)
            {
                return Err(
                    "monero reserve rotation watchtower references unknown ceremony".to_string(),
                );
            }
        }
        for record in self.emergency_windows.values() {
            record.validate()?;
            if !self.wallet_epochs.contains_key(&record.epoch_id) {
                return Err(
                    "monero reserve rotation emergency references unknown epoch".to_string()
                );
            }
        }
        for record in self.subaddress_migration_batches.values() {
            record.validate()?;
            if !self.wallet_epochs.contains_key(&record.from_epoch_id) {
                return Err(
                    "monero reserve rotation migration references unknown source epoch".to_string(),
                );
            }
            if !self.wallet_epochs.contains_key(&record.to_epoch_id) {
                return Err(
                    "monero reserve rotation migration references unknown target epoch".to_string(),
                );
            }
            if let Some(sponsorship_id) = &record.fee_sponsorship_id {
                if !self.low_fee_sponsorships.contains_key(sponsorship_id) {
                    return Err(
                        "monero reserve rotation migration references unknown sponsorship"
                            .to_string(),
                    );
                }
            }
        }
        for record in self.key_image_audit_commitments.values() {
            record.validate()?;
            if !self.wallet_epochs.contains_key(&record.epoch_id) {
                return Err("monero reserve rotation audit references unknown epoch".to_string());
            }
        }
        for record in self.solvency_snapshots.values() {
            record.validate()?;
            if !self.wallet_epochs.contains_key(&record.epoch_id) {
                return Err("monero reserve rotation solvency references unknown epoch".to_string());
            }
            if !self
                .key_image_audit_commitments
                .contains_key(&record.audit_id)
            {
                return Err("monero reserve rotation solvency references unknown audit".to_string());
            }
            if record.coverage_bps < self.config.min_coverage_bps && record.status.usable() {
                return Err(
                    "monero reserve rotation usable solvency snapshot is under covered".to_string(),
                );
            }
        }
        for record in self.low_fee_sponsorships.values() {
            record.validate()?;
        }
        for record in self.rollback_safeguards.values() {
            record.validate()?;
            if !self.wallet_epochs.contains_key(&record.epoch_id) {
                return Err("monero reserve rotation rollback references unknown epoch".to_string());
            }
        }
        let counters = self.counters();
        if counters.accepted_watchtower_weight < self.config.watchtower_quorum_weight {
            return Err("monero reserve rotation watchtower quorum is below threshold".to_string());
        }
        Ok(self.state_root())
    }

    fn roots_without_state_root(&self) -> MoneroMultisigReserveRotationRoots {
        MoneroMultisigReserveRotationRoots {
            config_root: self.config.config_root(),
            wallet_epoch_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-WALLET-EPOCH-COLLECTION",
                self.wallet_epochs
                    .values()
                    .map(|record| (record.epoch_id.clone(), record.public_record()))
                    .collect(),
            ),
            ceremony_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-CEREMONY-COLLECTION",
                self.pq_rotation_ceremonies
                    .values()
                    .map(|record| (record.ceremony_id.clone(), record.public_record()))
                    .collect(),
            ),
            signer_shard_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-SIGNER-SHARD-COLLECTION",
                self.signer_shards
                    .values()
                    .map(|record| (record.shard_id.clone(), record.public_record()))
                    .collect(),
            ),
            watchtower_attestation_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-WATCHTOWER-ATTESTATION-COLLECTION",
                self.watchtower_attestations
                    .values()
                    .map(|record| (record.attestation_id.clone(), record.public_record()))
                    .collect(),
            ),
            emergency_window_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-EMERGENCY-WINDOW-COLLECTION",
                self.emergency_windows
                    .values()
                    .map(|record| (record.window_id.clone(), record.public_record()))
                    .collect(),
            ),
            subaddress_migration_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-SUBADDRESS-MIGRATION-COLLECTION",
                self.subaddress_migration_batches
                    .values()
                    .map(|record| (record.batch_id.clone(), record.public_record()))
                    .collect(),
            ),
            key_image_audit_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-KEY-IMAGE-AUDIT-COLLECTION",
                self.key_image_audit_commitments
                    .values()
                    .map(|record| (record.audit_id.clone(), record.public_record()))
                    .collect(),
            ),
            solvency_snapshot_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-SOLVENCY-SNAPSHOT-COLLECTION",
                self.solvency_snapshots
                    .values()
                    .map(|record| (record.snapshot_id.clone(), record.public_record()))
                    .collect(),
            ),
            low_fee_sponsorship_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-LOW-FEE-SPONSORSHIP-COLLECTION",
                self.low_fee_sponsorships
                    .values()
                    .map(|record| (record.sponsorship_id.clone(), record.public_record()))
                    .collect(),
            ),
            rollback_safeguard_root: collection_root(
                "MONERO-MULTISIG-RESERVE-ROTATION-ROLLBACK-SAFEGUARD-COLLECTION",
                self.rollback_safeguards
                    .values()
                    .map(|record| (record.safeguard_id.clone(), record.public_record()))
                    .collect(),
            ),
            state_root: String::new(),
        }
    }

    fn public_record_without_state_root(
        &self,
        roots: &MoneroMultisigReserveRotationRoots,
    ) -> Value {
        json!({
            "kind": "monero_multisig_reserve_rotation_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION,
            "protocol_name": MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_NAME,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn insert_wallet_epoch(
        &mut self,
        record: ReserveWalletEpoch,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.wallet_epochs,
            record.epoch_id.clone(),
            record,
            "wallet epoch",
        )
    }

    fn insert_pq_rotation_ceremony(
        &mut self,
        record: PqRotationCeremony,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.pq_rotation_ceremonies,
            record.ceremony_id.clone(),
            record,
            "pq rotation ceremony",
        )
    }

    fn insert_signer_shard(
        &mut self,
        record: SignerShard,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.signer_shards,
            record.shard_id.clone(),
            record,
            "signer shard",
        )
    }

    fn insert_watchtower_attestation(
        &mut self,
        record: WatchtowerRotationAttestation,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.watchtower_attestations,
            record.attestation_id.clone(),
            record,
            "watchtower attestation",
        )
    }

    fn insert_emergency_window(
        &mut self,
        record: EmergencyFreezeReleaseWindow,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.emergency_windows,
            record.window_id.clone(),
            record,
            "emergency window",
        )
    }

    fn insert_subaddress_migration_batch(
        &mut self,
        record: SubaddressMigrationBatch,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.subaddress_migration_batches,
            record.batch_id.clone(),
            record,
            "subaddress migration batch",
        )
    }

    fn insert_key_image_audit_commitment(
        &mut self,
        record: KeyImageAuditCommitment,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.key_image_audit_commitments,
            record.audit_id.clone(),
            record,
            "key image audit commitment",
        )
    }

    fn insert_solvency_snapshot(
        &mut self,
        record: SolvencySnapshot,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.solvency_snapshots,
            record.snapshot_id.clone(),
            record,
            "solvency snapshot",
        )
    }

    fn insert_low_fee_sponsorship(
        &mut self,
        record: LowFeeRotationSponsorship,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.low_fee_sponsorships,
            record.sponsorship_id.clone(),
            record,
            "low fee sponsorship",
        )
    }

    fn insert_rollback_safeguard(
        &mut self,
        record: RollbackReorgSafeguard,
    ) -> MoneroMultisigReserveRotationResult<()> {
        record.validate()?;
        insert_unique_record(
            &mut self.rollback_safeguards,
            record.safeguard_id.clone(),
            record,
            "rollback safeguard",
        )
    }
}

pub fn monero_multisig_reserve_rotation_state_root_from_record(record: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root("MONERO-MULTISIG-RESERVE-ROTATION-STATE", record)
}

pub fn reserve_coverage_bps(reserve_units: u64, liability_units: u64) -> u64 {
    if liability_units == 0 {
        return MONERO_MULTISIG_RESERVE_ROTATION_MAX_BPS;
    }
    let result = (reserve_units as u128)
        .saturating_mul(MONERO_MULTISIG_RESERVE_ROTATION_MAX_BPS as u128)
        / liability_units as u128;
    result
        .min(MONERO_MULTISIG_RESERVE_ROTATION_MAX_BPS as u128)
        .min(u64::MAX as u128) as u64
}

fn monero_multisig_reserve_rotation_config_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-CONFIG-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_wallet_epoch_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-WALLET-EPOCH-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_ceremony_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-CEREMONY-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_signer_shard_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-SIGNER-SHARD-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_watchtower_attestation_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-WATCHTOWER-ATTESTATION-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_emergency_window_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-EMERGENCY-WINDOW-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_subaddress_batch_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-SUBADDRESS-BATCH-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_key_image_audit_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-KEY-IMAGE-AUDIT-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_solvency_snapshot_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-SOLVENCY-SNAPSHOT-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_sponsorship_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-SPONSORSHIP-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_rollback_safeguard_id(payload: &Value) -> String {
    monero_multisig_reserve_rotation_payload_root(
        "MONERO-MULTISIG-RESERVE-ROTATION-ROLLBACK-SAFEGUARD-ID",
        payload,
    )
}

fn monero_multisig_reserve_rotation_signature_root(
    signer_commitment: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    signature_material: &str,
) -> String {
    domain_hash(
        "MONERO-MULTISIG-RESERVE-ROTATION-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION as i128),
            HashPart::Str(signer_commitment),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signature_material),
        ],
        32,
    )
}

fn monero_multisig_reserve_rotation_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(MONERO_MULTISIG_RESERVE_ROTATION_PROTOCOL_VERSION as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn collection_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, record)| json!({ "key": key, "record": record }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroMultisigReserveRotationResult<()> {
    if records.contains_key(&key) {
        return Err(format!("monero reserve rotation {label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroMultisigReserveRotationResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroMultisigReserveRotationResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroMultisigReserveRotationResult<()> {
    if value > MONERO_MULTISIG_RESERVE_ROTATION_MAX_BPS.saturating_mul(2) {
        Err(format!("{label} is outside supported bps range"))
    } else {
        Ok(())
    }
}

fn ensure_threshold(threshold: u64, signer_count: u64) -> MoneroMultisigReserveRotationResult<()> {
    if threshold == 0 {
        return Err("monero reserve rotation threshold must be positive".to_string());
    }
    if signer_count == 0 {
        return Err("monero reserve rotation signer count must be positive".to_string());
    }
    if threshold > signer_count {
        return Err("monero reserve rotation threshold exceeds signer count".to_string());
    }
    Ok(())
}

fn ensure_string_list(values: &[String], label: &str) -> MoneroMultisigReserveRotationResult<()> {
    if values.is_empty() {
        return Err(format!("{label} list is required"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} list contains duplicates"));
        }
    }
    Ok(())
}
