use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroWalletSyncResult<T> = Result<T, String>;

pub const MONERO_WALLET_SYNC_PROTOCOL_VERSION: &str = "nebula-monero-wallet-sync-v1";
pub const MONERO_WALLET_SYNC_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_WALLET_SYNC_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_WALLET_SYNC_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_WALLET_SYNC_VIEW_TAG_BYTES: u64 = 1;
pub const MONERO_WALLET_SYNC_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const MONERO_WALLET_SYNC_DEFAULT_CHECKPOINT_INTERVAL_BLOCKS: u64 = 8;
pub const MONERO_WALLET_SYNC_DEFAULT_MAX_REORG_DEPTH: u64 = 24;
pub const MONERO_WALLET_SYNC_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 72;
pub const MONERO_WALLET_SYNC_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 96;
pub const MONERO_WALLET_SYNC_DEFAULT_CLIENT_SESSION_TTL_BLOCKS: u64 = 720;
pub const MONERO_WALLET_SYNC_DEFAULT_LOW_FEE_SCAN_UNIT_CAP: u64 = 128;
pub const MONERO_WALLET_SYNC_DEFAULT_MAX_VIEW_TAGS_PER_CHECKPOINT: u64 = 4_096;
pub const MONERO_WALLET_SYNC_DEFAULT_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_WALLET_SYNC_DEFAULT_WITHDRAWAL_ALERT_BLOCKS: u64 = 18;
pub const MONERO_WALLET_SYNC_DEFAULT_SCAN_REBATE_MICRO_UNITS: u64 = 25_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletSyncClientKind {
    Wallet,
    WatchOnly,
    BridgeOperator,
    Auditor,
    Sponsor,
}

impl WalletSyncClientKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::WatchOnly => "watch_only",
            Self::BridgeOperator => "bridge_operator",
            Self::Auditor => "auditor",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagMatchStatus {
    Candidate,
    Matched,
    FalsePositive,
    Spent,
    Cleared,
    Reorged,
}

impl ViewTagMatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Matched => "matched",
            Self::FalsePositive => "false_positive",
            Self::Spent => "spent",
            Self::Cleared => "cleared",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_live_match(self) -> bool {
        matches!(self, Self::Candidate | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanCheckpointStatus {
    Open,
    Sealed,
    Reorged,
    Superseded,
}

impl ScanCheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Reorged => "reorged",
            Self::Superseded => "superseded",
        }
    }

    pub fn is_current(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgSyncStatus {
    Detected,
    Rewound,
    Rescanned,
    Finalized,
}

impl ReorgSyncStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Rewound => "rewound",
            Self::Rescanned => "rescanned",
            Self::Finalized => "finalized",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Detected | Self::Rewound | Self::Rescanned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureTicketScope {
    ViewTagHit,
    OutputAmountBucket,
    IncomingTransfer,
    WithdrawalStatus,
    ReorgProof,
    SponsorReceipt,
}

impl DisclosureTicketScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagHit => "view_tag_hit",
            Self::OutputAmountBucket => "output_amount_bucket",
            Self::IncomingTransfer => "incoming_transfer",
            Self::WithdrawalStatus => "withdrawal_status",
            Self::ReorgProof => "reorg_proof",
            Self::SponsorReceipt => "sponsor_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureTicketStatus {
    Requested,
    Approved,
    Revealed,
    Revoked,
    Expired,
}

impl DisclosureTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Revealed => "revealed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Requested | Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSponsorshipStatus {
    Offered,
    Reserved,
    Settled,
    Slashed,
    Expired,
}

impl ScanSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchClientStatus {
    Pending,
    Active,
    Rotating,
    Suspended,
    Revoked,
    Expired,
}

impl WatchClientStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn can_scan(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalMonitorStatus {
    Queued,
    Observed,
    Confirming,
    Finalized,
    Reorged,
    Stuck,
    Recovered,
}

impl WithdrawalMonitorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Observed => "observed",
            Self::Confirming => "confirming",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Stuck => "stuck",
            Self::Recovered => "recovered",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Observed | Self::Confirming | Self::Stuck
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWalletSyncConfig {
    pub config_id: String,
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub finality_depth: u64,
    pub checkpoint_interval_blocks: u64,
    pub max_reorg_depth: u64,
    pub disclosure_ticket_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub client_session_ttl_blocks: u64,
    pub low_fee_scan_unit_cap: u64,
    pub max_view_tags_per_checkpoint: u64,
    pub min_watch_client_pq_security_bits: u16,
    pub withdrawal_alert_blocks: u64,
    pub require_pq_client_auth: bool,
}

impl Default for MoneroWalletSyncConfig {
    fn default() -> Self {
        Self::new(
            MONERO_WALLET_SYNC_DEVNET_NETWORK,
            MONERO_WALLET_SYNC_DEVNET_ASSET_ID,
            MONERO_WALLET_SYNC_DEVNET_FEE_ASSET_ID,
        )
    }
}

impl MoneroWalletSyncConfig {
    pub fn new(
        network: impl Into<String>,
        asset_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
    ) -> Self {
        let network = network.into();
        let asset_id = asset_id.into();
        let fee_asset_id = fee_asset_id.into();
        let config_id = monero_wallet_sync_config_id_from_fields(
            &network,
            &asset_id,
            &fee_asset_id,
            MONERO_WALLET_SYNC_DEFAULT_FINALITY_DEPTH,
            MONERO_WALLET_SYNC_DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            MONERO_WALLET_SYNC_DEFAULT_MAX_REORG_DEPTH,
            true,
        );
        Self {
            config_id,
            network,
            asset_id,
            fee_asset_id,
            finality_depth: MONERO_WALLET_SYNC_DEFAULT_FINALITY_DEPTH,
            checkpoint_interval_blocks: MONERO_WALLET_SYNC_DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            max_reorg_depth: MONERO_WALLET_SYNC_DEFAULT_MAX_REORG_DEPTH,
            disclosure_ticket_ttl_blocks: MONERO_WALLET_SYNC_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            sponsorship_ttl_blocks: MONERO_WALLET_SYNC_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            client_session_ttl_blocks: MONERO_WALLET_SYNC_DEFAULT_CLIENT_SESSION_TTL_BLOCKS,
            low_fee_scan_unit_cap: MONERO_WALLET_SYNC_DEFAULT_LOW_FEE_SCAN_UNIT_CAP,
            max_view_tags_per_checkpoint: MONERO_WALLET_SYNC_DEFAULT_MAX_VIEW_TAGS_PER_CHECKPOINT,
            min_watch_client_pq_security_bits: MONERO_WALLET_SYNC_DEFAULT_PQ_SECURITY_BITS,
            withdrawal_alert_blocks: MONERO_WALLET_SYNC_DEFAULT_WITHDRAWAL_ALERT_BLOCKS,
            require_pq_client_auth: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_wallet_sync_config",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "config_id": self.config_id,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "finality_depth": self.finality_depth,
            "checkpoint_interval_blocks": self.checkpoint_interval_blocks,
            "max_reorg_depth": self.max_reorg_depth,
            "disclosure_ticket_ttl_blocks": self.disclosure_ticket_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "client_session_ttl_blocks": self.client_session_ttl_blocks,
            "low_fee_scan_unit_cap": self.low_fee_scan_unit_cap,
            "max_view_tags_per_checkpoint": self.max_view_tags_per_checkpoint,
            "min_watch_client_pq_security_bits": self.min_watch_client_pq_security_bits,
            "withdrawal_alert_blocks": self.withdrawal_alert_blocks,
            "view_tag_bytes": MONERO_WALLET_SYNC_VIEW_TAG_BYTES,
            "require_pq_client_auth": self.require_pq_client_auth,
        })
    }

    pub fn config_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.network, "monero wallet sync network")?;
        ensure_non_empty(&self.asset_id, "monero wallet sync asset id")?;
        ensure_non_empty(&self.fee_asset_id, "monero wallet sync fee asset id")?;
        ensure_positive(self.finality_depth, "monero wallet sync finality depth")?;
        ensure_positive(
            self.checkpoint_interval_blocks,
            "monero wallet sync checkpoint interval",
        )?;
        ensure_positive(self.max_reorg_depth, "monero wallet sync max reorg depth")?;
        ensure_positive(
            self.disclosure_ticket_ttl_blocks,
            "monero wallet sync disclosure ticket ttl",
        )?;
        ensure_positive(
            self.sponsorship_ttl_blocks,
            "monero wallet sync sponsorship ttl",
        )?;
        ensure_positive(
            self.client_session_ttl_blocks,
            "monero wallet sync client session ttl",
        )?;
        ensure_positive(
            self.low_fee_scan_unit_cap,
            "monero wallet sync low fee scan unit cap",
        )?;
        ensure_positive(
            self.max_view_tags_per_checkpoint,
            "monero wallet sync max view tags per checkpoint",
        )?;
        if self.min_watch_client_pq_security_bits < 128 {
            return Err("monero wallet sync pq security floor is too low".to_string());
        }
        let expected = monero_wallet_sync_config_id_from_fields(
            &self.network,
            &self.asset_id,
            &self.fee_asset_id,
            self.finality_depth,
            self.checkpoint_interval_blocks,
            self.max_reorg_depth,
            self.require_pq_client_auth,
        );
        if self.config_id != expected {
            return Err("monero wallet sync config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroViewKeyProfile {
    pub profile_id: String,
    pub account_label: String,
    pub view_key_commitment: String,
    pub wallet_address_tag: String,
    pub restore_height: u64,
    pub scan_from_height: u64,
    pub privacy_set_root: String,
    pub view_tag_domain: String,
    pub created_at_height: u64,
    pub active: bool,
}

impl MoneroViewKeyProfile {
    pub fn new(
        account_label: impl Into<String>,
        view_key_label: impl Into<String>,
        wallet_address_tag: impl Into<String>,
        restore_height: u64,
        scan_from_height: u64,
        privacy_labels: &[String],
        created_at_height: u64,
    ) -> MoneroWalletSyncResult<Self> {
        let account_label = account_label.into();
        let view_key_label = view_key_label.into();
        let wallet_address_tag = wallet_address_tag.into();
        ensure_non_empty(&account_label, "monero wallet sync account label")?;
        ensure_non_empty(&view_key_label, "monero wallet sync view key label")?;
        ensure_non_empty(&wallet_address_tag, "monero wallet sync wallet address tag")?;
        let view_key_commitment =
            monero_wallet_sync_string_root("MONERO-WALLET-SYNC-VIEW-KEY", &view_key_label);
        let privacy_set_root =
            monero_wallet_sync_string_set_root("MONERO-WALLET-SYNC-PRIVACY-SET", privacy_labels);
        let view_tag_domain = monero_wallet_sync_payload_root(
            "MONERO-WALLET-SYNC-VIEW-TAG-DOMAIN",
            &json!({
                "account_label": account_label,
                "wallet_address_tag": wallet_address_tag,
                "view_key_commitment": view_key_commitment,
                "restore_height": restore_height,
            }),
        );
        let profile_id = monero_wallet_sync_profile_id(
            &account_label,
            &view_key_commitment,
            &wallet_address_tag,
            restore_height,
        );
        let profile = Self {
            profile_id,
            account_label,
            view_key_commitment,
            wallet_address_tag,
            restore_height,
            scan_from_height,
            privacy_set_root,
            view_tag_domain,
            created_at_height,
            active: true,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_view_key_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "profile_id": self.profile_id,
            "account_label": self.account_label,
            "view_key_commitment": self.view_key_commitment,
            "wallet_address_tag": self.wallet_address_tag,
            "restore_height": self.restore_height,
            "scan_from_height": self.scan_from_height,
            "privacy_set_root": self.privacy_set_root,
            "view_tag_domain": self.view_tag_domain,
            "created_at_height": self.created_at_height,
            "active": self.active,
        })
    }

    pub fn profile_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-PROFILE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.profile_id, "monero wallet sync profile id")?;
        ensure_non_empty(&self.account_label, "monero wallet sync account label")?;
        ensure_non_empty(
            &self.view_key_commitment,
            "monero wallet sync view key commitment",
        )?;
        ensure_non_empty(
            &self.wallet_address_tag,
            "monero wallet sync wallet address tag",
        )?;
        ensure_non_empty(
            &self.privacy_set_root,
            "monero wallet sync privacy set root",
        )?;
        ensure_non_empty(&self.view_tag_domain, "monero wallet sync view tag domain")?;
        let expected = monero_wallet_sync_profile_id(
            &self.account_label,
            &self.view_key_commitment,
            &self.wallet_address_tag,
            self.restore_height,
        );
        if self.profile_id != expected {
            return Err("monero wallet sync profile id mismatch".to_string());
        }
        if self.scan_from_height < self.restore_height {
            return Err("monero wallet sync scan start precedes restore height".to_string());
        }
        Ok(self.profile_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatchOnlyClient {
    pub client_id: String,
    pub client_label: String,
    pub client_kind: WalletSyncClientKind,
    pub pq_auth_scheme: String,
    pub pq_public_key_root: String,
    pub view_key_commitment: String,
    pub scan_policy_root: String,
    pub allowed_scope_root: String,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub last_seen_height: u64,
    pub security_bits: u16,
    pub status: WatchClientStatus,
}

impl PqWatchOnlyClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_label: impl Into<String>,
        client_kind: WalletSyncClientKind,
        pq_auth_scheme: impl Into<String>,
        pq_public_key_material: impl Into<String>,
        view_key_label: impl Into<String>,
        allowed_scopes: &[String],
        registered_at_height: u64,
        ttl_blocks: u64,
        security_bits: u16,
    ) -> MoneroWalletSyncResult<Self> {
        let client_label = client_label.into();
        let pq_auth_scheme = pq_auth_scheme.into();
        let pq_public_key_material = pq_public_key_material.into();
        let view_key_label = view_key_label.into();
        ensure_non_empty(&client_label, "monero wallet sync client label")?;
        ensure_non_empty(&pq_auth_scheme, "monero wallet sync pq auth scheme")?;
        ensure_non_empty(
            &pq_public_key_material,
            "monero wallet sync pq public key material",
        )?;
        ensure_non_empty(&view_key_label, "monero wallet sync client view key label")?;
        ensure_positive(ttl_blocks, "monero wallet sync client ttl")?;
        let pq_public_key_root = monero_wallet_sync_string_root(
            "MONERO-WALLET-SYNC-PQ-PUBLIC-KEY",
            &pq_public_key_material,
        );
        let view_key_commitment =
            monero_wallet_sync_string_root("MONERO-WALLET-SYNC-CLIENT-VIEW-KEY", &view_key_label);
        let scan_policy_root = monero_wallet_sync_payload_root(
            "MONERO-WALLET-SYNC-SCAN-POLICY",
            &json!({
                "client_label": client_label,
                "client_kind": client_kind.as_str(),
                "view_key_commitment": view_key_commitment,
                "allowed_scope_root": monero_wallet_sync_string_set_root(
                    "MONERO-WALLET-SYNC-CLIENT-SCOPES",
                    allowed_scopes,
                ),
            }),
        );
        let allowed_scope_root =
            monero_wallet_sync_string_set_root("MONERO-WALLET-SYNC-CLIENT-SCOPES", allowed_scopes);
        let expires_at_height = registered_at_height.saturating_add(ttl_blocks);
        let client_id = monero_wallet_sync_client_id(
            &client_label,
            client_kind,
            &pq_auth_scheme,
            &pq_public_key_root,
            &view_key_commitment,
            registered_at_height,
        );
        let client = Self {
            client_id,
            client_label,
            client_kind,
            pq_auth_scheme,
            pq_public_key_root,
            view_key_commitment,
            scan_policy_root,
            allowed_scope_root,
            registered_at_height,
            expires_at_height,
            last_seen_height: registered_at_height,
            security_bits,
            status: WatchClientStatus::Active,
        };
        client.validate()?;
        Ok(client)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_watch_only_client",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "client_id": self.client_id,
            "client_label": self.client_label,
            "client_kind": self.client_kind.as_str(),
            "pq_auth_scheme": self.pq_auth_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "view_key_commitment": self.view_key_commitment,
            "scan_policy_root": self.scan_policy_root,
            "allowed_scope_root": self.allowed_scope_root,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "last_seen_height": self.last_seen_height,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
        })
    }

    pub fn client_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-CLIENT", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.client_id, "monero wallet sync client id")?;
        ensure_non_empty(&self.client_label, "monero wallet sync client label")?;
        ensure_non_empty(&self.pq_auth_scheme, "monero wallet sync pq auth scheme")?;
        ensure_non_empty(
            &self.pq_public_key_root,
            "monero wallet sync pq public key root",
        )?;
        ensure_non_empty(
            &self.view_key_commitment,
            "monero wallet sync client view key commitment",
        )?;
        ensure_non_empty(
            &self.scan_policy_root,
            "monero wallet sync scan policy root",
        )?;
        ensure_non_empty(
            &self.allowed_scope_root,
            "monero wallet sync allowed scope root",
        )?;
        if self.expires_at_height <= self.registered_at_height {
            return Err("monero wallet sync client expiry must follow registration".to_string());
        }
        if self.last_seen_height < self.registered_at_height {
            return Err("monero wallet sync client last seen precedes registration".to_string());
        }
        let expected = monero_wallet_sync_client_id(
            &self.client_label,
            self.client_kind,
            &self.pq_auth_scheme,
            &self.pq_public_key_root,
            &self.view_key_commitment,
            self.registered_at_height,
        );
        if self.client_id != expected {
            return Err("monero wallet sync client id mismatch".to_string());
        }
        Ok(self.client_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqClientAttestation {
    pub attestation_id: String,
    pub client_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub pq_signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: WatchClientStatus,
}

impl PqClientAttestation {
    pub fn new(
        client_id: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        signature_material: impl Into<String>,
        signed_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWalletSyncResult<Self> {
        let client_id = client_id.into();
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let signature_material = signature_material.into();
        ensure_non_empty(&client_id, "monero wallet sync attestation client id")?;
        ensure_non_empty(&subject_kind, "monero wallet sync attestation subject kind")?;
        ensure_non_empty(&subject_id, "monero wallet sync attestation subject id")?;
        ensure_non_empty(&subject_root, "monero wallet sync attestation subject root")?;
        ensure_non_empty(
            &signature_material,
            "monero wallet sync attestation signature material",
        )?;
        ensure_positive(ttl_blocks, "monero wallet sync attestation ttl")?;
        let pq_signature_root =
            monero_wallet_sync_signature_root(&client_id, &subject_root, &signature_material);
        let expires_at_height = signed_at_height.saturating_add(ttl_blocks);
        let attestation_id = monero_wallet_sync_attestation_id(
            &client_id,
            &subject_kind,
            &subject_id,
            &subject_root,
            signed_at_height,
        );
        let attestation = Self {
            attestation_id,
            client_id,
            subject_kind,
            subject_id,
            subject_root,
            pq_signature_root,
            signed_at_height,
            expires_at_height,
            status: WatchClientStatus::Active,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_client_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "client_id": self.client_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "pq_signature_root": self.pq_signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.attestation_id, "monero wallet sync attestation id")?;
        ensure_non_empty(&self.client_id, "monero wallet sync attestation client id")?;
        ensure_non_empty(
            &self.subject_kind,
            "monero wallet sync attestation subject kind",
        )?;
        ensure_non_empty(
            &self.subject_id,
            "monero wallet sync attestation subject id",
        )?;
        ensure_non_empty(
            &self.subject_root,
            "monero wallet sync attestation subject root",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "monero wallet sync attestation signature root",
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("monero wallet sync attestation expiry must follow signature".to_string());
        }
        let expected = monero_wallet_sync_attestation_id(
            &self.client_id,
            &self.subject_kind,
            &self.subject_id,
            &self.subject_root,
            self.signed_at_height,
        );
        if self.attestation_id != expected {
            return Err("monero wallet sync attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagObservation {
    pub observation_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub txid_hash: String,
    pub output_index: u64,
    pub view_tag: String,
    pub encrypted_amount_bucket: String,
    pub output_commitment: String,
    pub one_time_address_commitment: String,
    pub key_image_hint_root: Option<String>,
    pub scan_nonce: String,
    pub observed_at_height: u64,
    pub confirmations: u64,
    pub status: ViewTagMatchStatus,
}

impl ViewTagObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: impl Into<String>,
        client_id: impl Into<String>,
        block_height: u64,
        block_hash: impl Into<String>,
        txid_label: impl Into<String>,
        output_index: u64,
        view_tag: impl Into<String>,
        encrypted_amount_bucket: impl Into<String>,
        output_material: impl Into<String>,
        one_time_address_label: impl Into<String>,
        key_image_hint_label: Option<String>,
        scan_nonce: impl Into<String>,
        observed_at_height: u64,
        status: ViewTagMatchStatus,
    ) -> MoneroWalletSyncResult<Self> {
        let profile_id = profile_id.into();
        let client_id = client_id.into();
        let block_hash = block_hash.into();
        let txid_label = txid_label.into();
        let view_tag = view_tag.into();
        let encrypted_amount_bucket = encrypted_amount_bucket.into();
        let output_material = output_material.into();
        let one_time_address_label = one_time_address_label.into();
        let scan_nonce = scan_nonce.into();
        ensure_non_empty(&profile_id, "monero wallet sync observation profile id")?;
        ensure_non_empty(&client_id, "monero wallet sync observation client id")?;
        ensure_non_empty(&block_hash, "monero wallet sync observation block hash")?;
        ensure_non_empty(&txid_label, "monero wallet sync observation txid")?;
        ensure_non_empty(&view_tag, "monero wallet sync view tag")?;
        ensure_non_empty(
            &encrypted_amount_bucket,
            "monero wallet sync encrypted amount bucket",
        )?;
        ensure_non_empty(&output_material, "monero wallet sync output material")?;
        ensure_non_empty(
            &one_time_address_label,
            "monero wallet sync one-time address label",
        )?;
        ensure_non_empty(&scan_nonce, "monero wallet sync scan nonce")?;
        let txid_hash = monero_wallet_sync_string_root("MONERO-WALLET-SYNC-TXID", &txid_label);
        let output_commitment =
            monero_wallet_sync_string_root("MONERO-WALLET-SYNC-OUTPUT", &output_material);
        let one_time_address_commitment = monero_wallet_sync_string_root(
            "MONERO-WALLET-SYNC-ONE-TIME-ADDRESS",
            &one_time_address_label,
        );
        let key_image_hint_root = key_image_hint_label
            .as_deref()
            .filter(|label| !label.trim().is_empty())
            .map(|label| {
                monero_wallet_sync_string_root("MONERO-WALLET-SYNC-KEY-IMAGE-HINT", label)
            });
        let confirmations = confirmations(observed_at_height, block_height);
        let observation_id = monero_wallet_sync_observation_id(
            &profile_id,
            &client_id,
            block_height,
            &block_hash,
            &txid_hash,
            output_index,
        );
        let observation = Self {
            observation_id,
            profile_id,
            client_id,
            block_height,
            block_hash,
            txid_hash,
            output_index,
            view_tag,
            encrypted_amount_bucket,
            output_commitment,
            one_time_address_commitment,
            key_image_hint_root,
            scan_nonce,
            observed_at_height,
            confirmations,
            status,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_tag_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "profile_id": self.profile_id,
            "client_id": self.client_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "txid_hash": self.txid_hash,
            "output_index": self.output_index,
            "view_tag": self.view_tag,
            "encrypted_amount_bucket": self.encrypted_amount_bucket,
            "output_commitment": self.output_commitment,
            "one_time_address_commitment": self.one_time_address_commitment,
            "key_image_hint_root": self.key_image_hint_root,
            "scan_nonce": self.scan_nonce,
            "observed_at_height": self.observed_at_height,
            "confirmations": self.confirmations,
            "status": self.status.as_str(),
        })
    }

    pub fn observation_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-OBSERVATION", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.observation_id, "monero wallet sync observation id")?;
        ensure_non_empty(
            &self.profile_id,
            "monero wallet sync observation profile id",
        )?;
        ensure_non_empty(&self.client_id, "monero wallet sync observation client id")?;
        ensure_non_empty(
            &self.block_hash,
            "monero wallet sync observation block hash",
        )?;
        ensure_non_empty(&self.txid_hash, "monero wallet sync observation txid hash")?;
        ensure_non_empty(&self.view_tag, "monero wallet sync observation view tag")?;
        ensure_non_empty(
            &self.encrypted_amount_bucket,
            "monero wallet sync observation amount bucket",
        )?;
        ensure_non_empty(
            &self.output_commitment,
            "monero wallet sync observation output commitment",
        )?;
        ensure_non_empty(
            &self.one_time_address_commitment,
            "monero wallet sync observation address commitment",
        )?;
        ensure_non_empty(&self.scan_nonce, "monero wallet sync observation nonce")?;
        let expected = monero_wallet_sync_observation_id(
            &self.profile_id,
            &self.client_id,
            self.block_height,
            &self.block_hash,
            &self.txid_hash,
            self.output_index,
        );
        if self.observation_id != expected {
            return Err("monero wallet sync observation id mismatch".to_string());
        }
        if self.observed_at_height < self.block_height {
            return Err("monero wallet sync observation precedes block height".to_string());
        }
        Ok(self.observation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub checkpoint_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub from_monero_height: u64,
    pub to_monero_height: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub scanned_block_count: u64,
    pub view_tag_root: String,
    pub candidate_output_root: String,
    pub matched_output_count: u64,
    pub false_positive_count: u64,
    pub checkpoint_commitment: String,
    pub parent_checkpoint_id: Option<String>,
    pub status: ScanCheckpointStatus,
}

impl ScanCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: impl Into<String>,
        client_id: impl Into<String>,
        from_monero_height: u64,
        to_monero_height: u64,
        opened_at_height: u64,
        sealed_at_height: u64,
        observations: &[ViewTagObservation],
        parent_checkpoint_id: Option<String>,
        status: ScanCheckpointStatus,
    ) -> MoneroWalletSyncResult<Self> {
        let profile_id = profile_id.into();
        let client_id = client_id.into();
        ensure_non_empty(&profile_id, "monero wallet sync checkpoint profile id")?;
        ensure_non_empty(&client_id, "monero wallet sync checkpoint client id")?;
        if to_monero_height < from_monero_height {
            return Err("monero wallet sync checkpoint height range is inverted".to_string());
        }
        let scoped_observations = observations
            .iter()
            .filter(|observation| {
                observation.profile_id == profile_id
                    && observation.client_id == client_id
                    && observation.block_height >= from_monero_height
                    && observation.block_height <= to_monero_height
            })
            .cloned()
            .collect::<Vec<_>>();
        let view_tag_root =
            monero_wallet_sync_view_tag_observation_collection_root(&scoped_observations);
        let candidate_output_root = monero_wallet_sync_candidate_output_root(&scoped_observations);
        let matched_output_count = scoped_observations
            .iter()
            .filter(|observation| observation.status == ViewTagMatchStatus::Matched)
            .count() as u64;
        let false_positive_count = scoped_observations
            .iter()
            .filter(|observation| observation.status == ViewTagMatchStatus::FalsePositive)
            .count() as u64;
        let scanned_block_count = to_monero_height
            .saturating_sub(from_monero_height)
            .saturating_add(1);
        let checkpoint_commitment = monero_wallet_sync_payload_root(
            "MONERO-WALLET-SYNC-CHECKPOINT-COMMITMENT",
            &json!({
                "profile_id": profile_id,
                "client_id": client_id,
                "from_monero_height": from_monero_height,
                "to_monero_height": to_monero_height,
                "view_tag_root": view_tag_root,
                "candidate_output_root": candidate_output_root,
                "matched_output_count": matched_output_count,
                "false_positive_count": false_positive_count,
                "parent_checkpoint_id": parent_checkpoint_id,
            }),
        );
        let checkpoint_id = monero_wallet_sync_checkpoint_id(
            &profile_id,
            &client_id,
            from_monero_height,
            to_monero_height,
            &view_tag_root,
            &candidate_output_root,
        );
        let checkpoint = Self {
            checkpoint_id,
            profile_id,
            client_id,
            from_monero_height,
            to_monero_height,
            opened_at_height,
            sealed_at_height,
            scanned_block_count,
            view_tag_root,
            candidate_output_root,
            matched_output_count,
            false_positive_count,
            checkpoint_commitment,
            parent_checkpoint_id,
            status,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "scan_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "profile_id": self.profile_id,
            "client_id": self.client_id,
            "from_monero_height": self.from_monero_height,
            "to_monero_height": self.to_monero_height,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "scanned_block_count": self.scanned_block_count,
            "view_tag_root": self.view_tag_root,
            "candidate_output_root": self.candidate_output_root,
            "matched_output_count": self.matched_output_count,
            "false_positive_count": self.false_positive_count,
            "checkpoint_commitment": self.checkpoint_commitment,
            "parent_checkpoint_id": self.parent_checkpoint_id,
            "status": self.status.as_str(),
        })
    }

    pub fn checkpoint_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-CHECKPOINT", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.checkpoint_id, "monero wallet sync checkpoint id")?;
        ensure_non_empty(&self.profile_id, "monero wallet sync checkpoint profile id")?;
        ensure_non_empty(&self.client_id, "monero wallet sync checkpoint client id")?;
        ensure_non_empty(
            &self.view_tag_root,
            "monero wallet sync checkpoint view tag root",
        )?;
        ensure_non_empty(
            &self.candidate_output_root,
            "monero wallet sync checkpoint candidate output root",
        )?;
        ensure_non_empty(
            &self.checkpoint_commitment,
            "monero wallet sync checkpoint commitment",
        )?;
        if self.to_monero_height < self.from_monero_height {
            return Err("monero wallet sync checkpoint height range is inverted".to_string());
        }
        let expected_count = self
            .to_monero_height
            .saturating_sub(self.from_monero_height)
            .saturating_add(1);
        if self.scanned_block_count != expected_count {
            return Err("monero wallet sync checkpoint scanned block count mismatch".to_string());
        }
        if self.sealed_at_height < self.opened_at_height {
            return Err(
                "monero wallet sync checkpoint seal height precedes open height".to_string(),
            );
        }
        let expected = monero_wallet_sync_checkpoint_id(
            &self.profile_id,
            &self.client_id,
            self.from_monero_height,
            self.to_monero_height,
            &self.view_tag_root,
            &self.candidate_output_root,
        );
        if self.checkpoint_id != expected {
            return Err("monero wallet sync checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgSafeSyncWindow {
    pub reorg_id: String,
    pub profile_id: String,
    pub old_tip_height: u64,
    pub old_tip_hash: String,
    pub new_tip_height: u64,
    pub new_tip_hash: String,
    pub rollback_to_height: u64,
    pub affected_checkpoint_root: String,
    pub affected_observation_root: String,
    pub detected_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub status: ReorgSyncStatus,
}

impl ReorgSafeSyncWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: impl Into<String>,
        old_tip_height: u64,
        old_tip_hash: impl Into<String>,
        new_tip_height: u64,
        new_tip_hash: impl Into<String>,
        rollback_to_height: u64,
        affected_checkpoint_ids: &[String],
        affected_observation_ids: &[String],
        detected_at_height: u64,
    ) -> MoneroWalletSyncResult<Self> {
        let profile_id = profile_id.into();
        let old_tip_hash = old_tip_hash.into();
        let new_tip_hash = new_tip_hash.into();
        ensure_non_empty(&profile_id, "monero wallet sync reorg profile id")?;
        ensure_non_empty(&old_tip_hash, "monero wallet sync old tip hash")?;
        ensure_non_empty(&new_tip_hash, "monero wallet sync new tip hash")?;
        if rollback_to_height > old_tip_height {
            return Err("monero wallet sync rollback height exceeds old tip".to_string());
        }
        let affected_checkpoint_root = monero_wallet_sync_string_set_root(
            "MONERO-WALLET-SYNC-REORG-CHECKPOINTS",
            affected_checkpoint_ids,
        );
        let affected_observation_root = monero_wallet_sync_string_set_root(
            "MONERO-WALLET-SYNC-REORG-OBSERVATIONS",
            affected_observation_ids,
        );
        let reorg_id = monero_wallet_sync_reorg_id(
            &profile_id,
            old_tip_height,
            &old_tip_hash,
            new_tip_height,
            &new_tip_hash,
            rollback_to_height,
        );
        let window = Self {
            reorg_id,
            profile_id,
            old_tip_height,
            old_tip_hash,
            new_tip_height,
            new_tip_hash,
            rollback_to_height,
            affected_checkpoint_root,
            affected_observation_root,
            detected_at_height,
            resolved_at_height: None,
            status: ReorgSyncStatus::Detected,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reorg_safe_sync_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "reorg_id": self.reorg_id,
            "profile_id": self.profile_id,
            "old_tip_height": self.old_tip_height,
            "old_tip_hash": self.old_tip_hash,
            "new_tip_height": self.new_tip_height,
            "new_tip_hash": self.new_tip_hash,
            "rollback_to_height": self.rollback_to_height,
            "affected_checkpoint_root": self.affected_checkpoint_root,
            "affected_observation_root": self.affected_observation_root,
            "detected_at_height": self.detected_at_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn reorg_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-REORG", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.reorg_id, "monero wallet sync reorg id")?;
        ensure_non_empty(&self.profile_id, "monero wallet sync reorg profile id")?;
        ensure_non_empty(&self.old_tip_hash, "monero wallet sync old tip hash")?;
        ensure_non_empty(&self.new_tip_hash, "monero wallet sync new tip hash")?;
        ensure_non_empty(
            &self.affected_checkpoint_root,
            "monero wallet sync affected checkpoint root",
        )?;
        ensure_non_empty(
            &self.affected_observation_root,
            "monero wallet sync affected observation root",
        )?;
        if self.rollback_to_height > self.old_tip_height {
            return Err("monero wallet sync rollback height exceeds old tip".to_string());
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.detected_at_height {
                return Err("monero wallet sync reorg resolution precedes detection".to_string());
            }
        }
        let expected = monero_wallet_sync_reorg_id(
            &self.profile_id,
            self.old_tip_height,
            &self.old_tip_hash,
            self.new_tip_height,
            &self.new_tip_hash,
            self.rollback_to_height,
        );
        if self.reorg_id != expected {
            return Err("monero wallet sync reorg id mismatch".to_string());
        }
        Ok(self.reorg_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitedDisclosureTicket {
    pub ticket_id: String,
    pub scope: DisclosureTicketScope,
    pub requester_label: String,
    pub profile_id: Option<String>,
    pub subject_id: String,
    pub subject_root: String,
    pub disclosed_field_root: String,
    pub policy_root: String,
    pub min_consumer_pq_security_bits: u16,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub revealed_at_height: Option<u64>,
    pub status: DisclosureTicketStatus,
}

impl LimitedDisclosureTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DisclosureTicketScope,
        requester_label: impl Into<String>,
        profile_id: Option<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        disclosed_fields: &[String],
        policy_label: impl Into<String>,
        min_consumer_pq_security_bits: u16,
        requested_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWalletSyncResult<Self> {
        let requester_label = requester_label.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let policy_label = policy_label.into();
        ensure_non_empty(&requester_label, "monero wallet sync disclosure requester")?;
        ensure_non_empty(&subject_id, "monero wallet sync disclosure subject id")?;
        ensure_non_empty(&subject_root, "monero wallet sync disclosure subject root")?;
        ensure_non_empty(&policy_label, "monero wallet sync disclosure policy")?;
        ensure_positive(ttl_blocks, "monero wallet sync disclosure ttl")?;
        let disclosed_field_root = monero_wallet_sync_string_set_root(
            "MONERO-WALLET-SYNC-DISCLOSED-FIELDS",
            disclosed_fields,
        );
        let policy_root =
            monero_wallet_sync_string_root("MONERO-WALLET-SYNC-DISCLOSURE-POLICY", &policy_label);
        let expires_at_height = requested_at_height.saturating_add(ttl_blocks);
        let ticket_id = monero_wallet_sync_disclosure_ticket_id(
            scope,
            &requester_label,
            profile_id.as_deref(),
            &subject_id,
            &subject_root,
            &disclosed_field_root,
            requested_at_height,
        );
        let ticket = Self {
            ticket_id,
            scope,
            requester_label,
            profile_id,
            subject_id,
            subject_root,
            disclosed_field_root,
            policy_root,
            min_consumer_pq_security_bits,
            requested_at_height,
            expires_at_height,
            revealed_at_height: None,
            status: DisclosureTicketStatus::Requested,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "limited_disclosure_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "scope": self.scope.as_str(),
            "requester_label": self.requester_label,
            "profile_id": self.profile_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "disclosed_field_root": self.disclosed_field_root,
            "policy_root": self.policy_root,
            "min_consumer_pq_security_bits": self.min_consumer_pq_security_bits,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "revealed_at_height": self.revealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn ticket_root(&self) -> String {
        monero_wallet_sync_payload_root(
            "MONERO-WALLET-SYNC-DISCLOSURE-TICKET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.ticket_id, "monero wallet sync disclosure ticket id")?;
        ensure_non_empty(
            &self.requester_label,
            "monero wallet sync disclosure requester",
        )?;
        ensure_non_empty(&self.subject_id, "monero wallet sync disclosure subject id")?;
        ensure_non_empty(
            &self.subject_root,
            "monero wallet sync disclosure subject root",
        )?;
        ensure_non_empty(
            &self.disclosed_field_root,
            "monero wallet sync disclosed field root",
        )?;
        ensure_non_empty(
            &self.policy_root,
            "monero wallet sync disclosure policy root",
        )?;
        if self.expires_at_height <= self.requested_at_height {
            return Err("monero wallet sync disclosure expiry must follow request".to_string());
        }
        if let Some(revealed_at_height) = self.revealed_at_height {
            if revealed_at_height < self.requested_at_height {
                return Err("monero wallet sync disclosure reveal precedes request".to_string());
            }
        }
        let expected = monero_wallet_sync_disclosure_ticket_id(
            self.scope,
            &self.requester_label,
            self.profile_id.as_deref(),
            &self.subject_id,
            &self.subject_root,
            &self.disclosed_field_root,
            self.requested_at_height,
        );
        if self.ticket_id != expected {
            return Err("monero wallet sync disclosure ticket id mismatch".to_string());
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeScanSponsorship {
    pub sponsorship_id: String,
    pub sponsor_label: String,
    pub profile_id: Option<String>,
    pub client_id: Option<String>,
    pub fee_asset_id: String,
    pub max_scan_units: u64,
    pub reserved_scan_units: u64,
    pub settled_scan_units: u64,
    pub rebate_rate_micro_units: u64,
    pub budget_micro_units: u64,
    pub spent_micro_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub settlement_root: String,
    pub status: ScanSponsorshipStatus,
}

impl LowFeeScanSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: impl Into<String>,
        profile_id: Option<String>,
        client_id: Option<String>,
        fee_asset_id: impl Into<String>,
        max_scan_units: u64,
        rebate_rate_micro_units: u64,
        budget_micro_units: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWalletSyncResult<Self> {
        let sponsor_label = sponsor_label.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&sponsor_label, "monero wallet sync sponsor label")?;
        ensure_non_empty(&fee_asset_id, "monero wallet sync sponsorship fee asset id")?;
        ensure_positive(max_scan_units, "monero wallet sync sponsorship scan units")?;
        ensure_positive(
            rebate_rate_micro_units,
            "monero wallet sync sponsorship rebate rate",
        )?;
        ensure_positive(ttl_blocks, "monero wallet sync sponsorship ttl")?;
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let settlement_root =
            monero_wallet_sync_empty_root("MONERO-WALLET-SYNC-SPONSOR-SETTLEMENT");
        let sponsorship_id = monero_wallet_sync_sponsorship_id(
            &sponsor_label,
            profile_id.as_deref(),
            client_id.as_deref(),
            &fee_asset_id,
            max_scan_units,
            created_at_height,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_label,
            profile_id,
            client_id,
            fee_asset_id,
            max_scan_units,
            reserved_scan_units: 0,
            settled_scan_units: 0,
            rebate_rate_micro_units,
            budget_micro_units,
            spent_micro_units: 0,
            created_at_height,
            expires_at_height,
            settlement_root,
            status: ScanSponsorshipStatus::Offered,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn reserve(&mut self, scan_units: u64) -> MoneroWalletSyncResult<()> {
        ensure_positive(scan_units, "monero wallet sync sponsored scan units")?;
        let next = self.reserved_scan_units.saturating_add(scan_units);
        if next > self.max_scan_units {
            return Err("monero wallet sync sponsorship capacity exceeded".to_string());
        }
        self.reserved_scan_units = next;
        self.status = ScanSponsorshipStatus::Reserved;
        self.validate()?;
        Ok(())
    }

    pub fn settle(
        &mut self,
        scan_units: u64,
        receipt_root: impl Into<String>,
    ) -> MoneroWalletSyncResult<()> {
        ensure_positive(scan_units, "monero wallet sync settled scan units")?;
        let receipt_root = receipt_root.into();
        ensure_non_empty(&receipt_root, "monero wallet sync settlement receipt root")?;
        let next = self.settled_scan_units.saturating_add(scan_units);
        if next > self.reserved_scan_units || next > self.max_scan_units {
            return Err(
                "monero wallet sync sponsorship settlement exceeds reservation".to_string(),
            );
        }
        self.settled_scan_units = next;
        self.spent_micro_units = self
            .spent_micro_units
            .saturating_add(scan_units.saturating_mul(self.rebate_rate_micro_units));
        if self.budget_micro_units > 0 && self.spent_micro_units > self.budget_micro_units {
            return Err("monero wallet sync sponsorship budget exceeded".to_string());
        }
        self.settlement_root = monero_wallet_sync_payload_root(
            "MONERO-WALLET-SYNC-SPONSOR-SETTLEMENT",
            &json!({
                "previous_settlement_root": self.settlement_root,
                "receipt_root": receipt_root,
                "settled_scan_units": self.settled_scan_units,
                "spent_micro_units": self.spent_micro_units,
            }),
        );
        self.status = ScanSponsorshipStatus::Settled;
        self.validate()?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_scan_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_label": self.sponsor_label,
            "profile_id": self.profile_id,
            "client_id": self.client_id,
            "fee_asset_id": self.fee_asset_id,
            "max_scan_units": self.max_scan_units,
            "reserved_scan_units": self.reserved_scan_units,
            "settled_scan_units": self.settled_scan_units,
            "rebate_rate_micro_units": self.rebate_rate_micro_units,
            "budget_micro_units": self.budget_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "settlement_root": self.settlement_root,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.sponsorship_id, "monero wallet sync sponsorship id")?;
        ensure_non_empty(&self.sponsor_label, "monero wallet sync sponsor label")?;
        ensure_non_empty(
            &self.fee_asset_id,
            "monero wallet sync sponsorship fee asset id",
        )?;
        ensure_positive(
            self.max_scan_units,
            "monero wallet sync sponsorship max units",
        )?;
        ensure_positive(
            self.rebate_rate_micro_units,
            "monero wallet sync sponsorship rebate rate",
        )?;
        ensure_non_empty(&self.settlement_root, "monero wallet sync settlement root")?;
        if self.reserved_scan_units > self.max_scan_units {
            return Err("monero wallet sync sponsorship reserved units exceed cap".to_string());
        }
        if self.settled_scan_units > self.max_scan_units {
            return Err("monero wallet sync sponsorship settled units exceed cap".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("monero wallet sync sponsorship expiry must follow creation".to_string());
        }
        if self.budget_micro_units > 0 && self.spent_micro_units > self.budget_micro_units {
            return Err("monero wallet sync sponsorship spent budget exceeded".to_string());
        }
        let expected = monero_wallet_sync_sponsorship_id(
            &self.sponsor_label,
            self.profile_id.as_deref(),
            self.client_id.as_deref(),
            &self.fee_asset_id,
            self.max_scan_units,
            self.created_at_height,
        );
        if self.sponsorship_id != expected {
            return Err("monero wallet sync sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalMonitor {
    pub monitor_id: String,
    pub withdrawal_id: String,
    pub profile_id: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub destination_address_commitment: String,
    pub amount_bucket: u64,
    pub expected_monero_height: u64,
    pub observed_txid_hash: Option<String>,
    pub observed_height: Option<u64>,
    pub confirmations: u64,
    pub last_checked_height: u64,
    pub stuck_after_height: u64,
    pub disclosure_ticket_id: Option<String>,
    pub status: WithdrawalMonitorStatus,
}

impl BridgeWithdrawalMonitor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        profile_id: impl Into<String>,
        nullifier_label: impl Into<String>,
        key_image_label: impl Into<String>,
        destination_address_label: impl Into<String>,
        amount_bucket: u64,
        expected_monero_height: u64,
        opened_at_height: u64,
        alert_after_blocks: u64,
        disclosure_ticket_id: Option<String>,
    ) -> MoneroWalletSyncResult<Self> {
        let withdrawal_id = withdrawal_id.into();
        let profile_id = profile_id.into();
        let nullifier_label = nullifier_label.into();
        let key_image_label = key_image_label.into();
        let destination_address_label = destination_address_label.into();
        ensure_non_empty(&withdrawal_id, "monero wallet sync withdrawal id")?;
        ensure_non_empty(&profile_id, "monero wallet sync withdrawal profile id")?;
        ensure_non_empty(&nullifier_label, "monero wallet sync withdrawal nullifier")?;
        ensure_non_empty(&key_image_label, "monero wallet sync withdrawal key image")?;
        ensure_non_empty(
            &destination_address_label,
            "monero wallet sync withdrawal destination",
        )?;
        ensure_positive(
            alert_after_blocks,
            "monero wallet sync withdrawal alert window",
        )?;
        let nullifier_root = monero_wallet_sync_string_root(
            "MONERO-WALLET-SYNC-WITHDRAWAL-NULLIFIER",
            &nullifier_label,
        );
        let key_image_root = monero_wallet_sync_string_root(
            "MONERO-WALLET-SYNC-WITHDRAWAL-KEY-IMAGE",
            &key_image_label,
        );
        let destination_address_commitment = monero_wallet_sync_string_root(
            "MONERO-WALLET-SYNC-WITHDRAWAL-DESTINATION",
            &destination_address_label,
        );
        let stuck_after_height = expected_monero_height.saturating_add(alert_after_blocks);
        let monitor_id = monero_wallet_sync_withdrawal_monitor_id(
            &withdrawal_id,
            &profile_id,
            &nullifier_root,
            &key_image_root,
            expected_monero_height,
        );
        let monitor = Self {
            monitor_id,
            withdrawal_id,
            profile_id,
            nullifier_root,
            key_image_root,
            destination_address_commitment,
            amount_bucket,
            expected_monero_height,
            observed_txid_hash: None,
            observed_height: None,
            confirmations: 0,
            last_checked_height: opened_at_height,
            stuck_after_height,
            disclosure_ticket_id,
            status: WithdrawalMonitorStatus::Queued,
        };
        monitor.validate()?;
        Ok(monitor)
    }

    pub fn observe(
        &mut self,
        txid_label: impl Into<String>,
        observed_height: u64,
        current_height: u64,
        finality_depth: u64,
    ) -> MoneroWalletSyncResult<()> {
        let txid_label = txid_label.into();
        ensure_non_empty(&txid_label, "monero wallet sync withdrawal txid")?;
        self.observed_txid_hash = Some(monero_wallet_sync_string_root(
            "MONERO-WALLET-SYNC-WITHDRAWAL-TXID",
            &txid_label,
        ));
        self.observed_height = Some(observed_height);
        self.confirmations = confirmations(current_height, observed_height);
        self.last_checked_height = current_height;
        self.status = if self.confirmations >= finality_depth {
            WithdrawalMonitorStatus::Finalized
        } else if self.confirmations == 0 {
            WithdrawalMonitorStatus::Observed
        } else {
            WithdrawalMonitorStatus::Confirming
        };
        self.validate()?;
        Ok(())
    }

    pub fn refresh(&mut self, current_height: u64, finality_depth: u64) {
        self.last_checked_height = current_height;
        if let Some(observed_height) = self.observed_height {
            self.confirmations = confirmations(current_height, observed_height);
            if self.status.is_open() && self.confirmations >= finality_depth {
                self.status = WithdrawalMonitorStatus::Finalized;
            } else if self.status == WithdrawalMonitorStatus::Observed && self.confirmations > 0 {
                self.status = WithdrawalMonitorStatus::Confirming;
            }
        } else if self.status == WithdrawalMonitorStatus::Queued
            && current_height >= self.stuck_after_height
        {
            self.status = WithdrawalMonitorStatus::Stuck;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_withdrawal_monitor",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "monitor_id": self.monitor_id,
            "withdrawal_id": self.withdrawal_id,
            "profile_id": self.profile_id,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "destination_address_commitment": self.destination_address_commitment,
            "amount_bucket": self.amount_bucket,
            "expected_monero_height": self.expected_monero_height,
            "observed_txid_hash": self.observed_txid_hash,
            "observed_height": self.observed_height,
            "confirmations": self.confirmations,
            "last_checked_height": self.last_checked_height,
            "stuck_after_height": self.stuck_after_height,
            "disclosure_ticket_id": self.disclosure_ticket_id,
            "status": self.status.as_str(),
        })
    }

    pub fn monitor_root(&self) -> String {
        monero_wallet_sync_payload_root(
            "MONERO-WALLET-SYNC-WITHDRAWAL-MONITOR",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        ensure_non_empty(&self.monitor_id, "monero wallet sync withdrawal monitor id")?;
        ensure_non_empty(&self.withdrawal_id, "monero wallet sync withdrawal id")?;
        ensure_non_empty(&self.profile_id, "monero wallet sync withdrawal profile id")?;
        ensure_non_empty(
            &self.nullifier_root,
            "monero wallet sync withdrawal nullifier root",
        )?;
        ensure_non_empty(
            &self.key_image_root,
            "monero wallet sync withdrawal key image root",
        )?;
        ensure_non_empty(
            &self.destination_address_commitment,
            "monero wallet sync withdrawal destination commitment",
        )?;
        if let Some(observed_height) = self.observed_height {
            if observed_height > self.last_checked_height {
                return Err(
                    "monero wallet sync withdrawal observed height exceeds last check".to_string(),
                );
            }
        }
        let expected = monero_wallet_sync_withdrawal_monitor_id(
            &self.withdrawal_id,
            &self.profile_id,
            &self.nullifier_root,
            &self.key_image_root,
            self.expected_monero_height,
        );
        if self.monitor_id != expected {
            return Err("monero wallet sync withdrawal monitor id mismatch".to_string());
        }
        Ok(self.monitor_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWalletSyncRoots {
    pub config_root: String,
    pub profile_root: String,
    pub watch_client_root: String,
    pub client_attestation_root: String,
    pub view_tag_observation_root: String,
    pub scan_checkpoint_root: String,
    pub reorg_window_root: String,
    pub disclosure_ticket_root: String,
    pub scan_sponsorship_root: String,
    pub withdrawal_monitor_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl MoneroWalletSyncRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_wallet_sync_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "profile_root": self.profile_root,
            "watch_client_root": self.watch_client_root,
            "client_attestation_root": self.client_attestation_root,
            "view_tag_observation_root": self.view_tag_observation_root,
            "scan_checkpoint_root": self.scan_checkpoint_root,
            "reorg_window_root": self.reorg_window_root,
            "disclosure_ticket_root": self.disclosure_ticket_root,
            "scan_sponsorship_root": self.scan_sponsorship_root,
            "withdrawal_monitor_root": self.withdrawal_monitor_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWalletSyncCounters {
    pub height: u64,
    pub profile_count: u64,
    pub active_profile_count: u64,
    pub watch_client_count: u64,
    pub active_watch_client_count: u64,
    pub client_attestation_count: u64,
    pub active_client_attestation_count: u64,
    pub view_tag_observation_count: u64,
    pub live_view_tag_count: u64,
    pub matched_view_tag_count: u64,
    pub scan_checkpoint_count: u64,
    pub current_checkpoint_count: u64,
    pub reorg_window_count: u64,
    pub open_reorg_window_count: u64,
    pub disclosure_ticket_count: u64,
    pub active_disclosure_ticket_count: u64,
    pub scan_sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub withdrawal_monitor_count: u64,
    pub finalized_withdrawal_count: u64,
    pub stuck_withdrawal_count: u64,
    pub sponsored_scan_units: u64,
    pub settled_scan_units: u64,
    pub public_record_count: u64,
}

impl MoneroWalletSyncCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_wallet_sync_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "height": self.height,
            "profile_count": self.profile_count,
            "active_profile_count": self.active_profile_count,
            "watch_client_count": self.watch_client_count,
            "active_watch_client_count": self.active_watch_client_count,
            "client_attestation_count": self.client_attestation_count,
            "active_client_attestation_count": self.active_client_attestation_count,
            "view_tag_observation_count": self.view_tag_observation_count,
            "live_view_tag_count": self.live_view_tag_count,
            "matched_view_tag_count": self.matched_view_tag_count,
            "scan_checkpoint_count": self.scan_checkpoint_count,
            "current_checkpoint_count": self.current_checkpoint_count,
            "reorg_window_count": self.reorg_window_count,
            "open_reorg_window_count": self.open_reorg_window_count,
            "disclosure_ticket_count": self.disclosure_ticket_count,
            "active_disclosure_ticket_count": self.active_disclosure_ticket_count,
            "scan_sponsorship_count": self.scan_sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "withdrawal_monitor_count": self.withdrawal_monitor_count,
            "finalized_withdrawal_count": self.finalized_withdrawal_count,
            "stuck_withdrawal_count": self.stuck_withdrawal_count,
            "sponsored_scan_units": self.sponsored_scan_units,
            "settled_scan_units": self.settled_scan_units,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWalletSyncState {
    pub height: u64,
    pub operator_label: String,
    pub network: String,
    pub config: MoneroWalletSyncConfig,
    pub view_profiles: BTreeMap<String, MoneroViewKeyProfile>,
    pub watch_clients: BTreeMap<String, PqWatchOnlyClient>,
    pub client_attestations: BTreeMap<String, PqClientAttestation>,
    pub view_tag_observations: BTreeMap<String, ViewTagObservation>,
    pub scan_checkpoints: BTreeMap<String, ScanCheckpoint>,
    pub reorg_windows: BTreeMap<String, ReorgSafeSyncWindow>,
    pub disclosure_tickets: BTreeMap<String, LimitedDisclosureTicket>,
    pub scan_sponsorships: BTreeMap<String, LowFeeScanSponsorship>,
    pub withdrawal_monitors: BTreeMap<String, BridgeWithdrawalMonitor>,
}

impl MoneroWalletSyncState {
    pub fn new(
        operator_label: impl Into<String>,
        config: MoneroWalletSyncConfig,
    ) -> MoneroWalletSyncResult<Self> {
        config.validate()?;
        let operator_label = operator_label.into();
        ensure_non_empty(&operator_label, "monero wallet sync operator label")?;
        Ok(Self {
            height: 0,
            operator_label,
            network: config.network.clone(),
            config,
            view_profiles: BTreeMap::new(),
            watch_clients: BTreeMap::new(),
            client_attestations: BTreeMap::new(),
            view_tag_observations: BTreeMap::new(),
            scan_checkpoints: BTreeMap::new(),
            reorg_windows: BTreeMap::new(),
            disclosure_tickets: BTreeMap::new(),
            scan_sponsorships: BTreeMap::new(),
            withdrawal_monitors: BTreeMap::new(),
        })
    }

    pub fn devnet() -> MoneroWalletSyncResult<Self> {
        let mut state = Self::new(
            "devnet-monero-wallet-sync",
            MoneroWalletSyncConfig::default(),
        )?;
        state.set_height(12)?;

        let privacy_labels = vec![
            "bridge-deposits".to_string(),
            "bridge-withdrawals".to_string(),
            "wallet-view-tags".to_string(),
            "low-fee-scan".to_string(),
        ];
        let alice_profile = state.register_view_profile(
            "devnet-alice",
            "devnet-alice-private-view-key",
            "devnet-alice-wallet-tag",
            1,
            1,
            &privacy_labels,
        )?;
        let bridge_profile = state.register_view_profile(
            "devnet-bridge-watch",
            "devnet-bridge-view-key",
            "devnet-bridge-wallet-tag",
            1,
            1,
            &privacy_labels,
        )?;

        let scopes = vec![
            "view_tag_hits".to_string(),
            "withdrawal_status".to_string(),
            "sponsor_receipts".to_string(),
        ];
        let alice_client = state.register_watch_client(
            "devnet-alice-watch-client",
            WalletSyncClientKind::WatchOnly,
            "ML-DSA-65+SLH-DSA-SHAKE-128s",
            "devnet-alice-watch-pq-key",
            "devnet-alice-private-view-key",
            &scopes,
            MONERO_WALLET_SYNC_DEFAULT_PQ_SECURITY_BITS,
        )?;
        let operator_client = state.register_watch_client(
            "devnet-bridge-operator-client",
            WalletSyncClientKind::BridgeOperator,
            "ML-DSA-87+SLH-DSA-SHAKE-192s",
            "devnet-bridge-operator-pq-key",
            "devnet-bridge-view-key",
            &scopes,
            256,
        )?;

        state.attest_client_subject(
            &alice_client.client_id,
            "monero_view_key_profile",
            &alice_profile.profile_id,
            &alice_profile.profile_root(),
            "devnet-alice-client-signature",
        )?;
        state.attest_client_subject(
            &operator_client.client_id,
            "monero_view_key_profile",
            &bridge_profile.profile_id,
            &bridge_profile.profile_root(),
            "devnet-operator-client-signature",
        )?;

        let first_hit = state.observe_view_tag(
            &alice_profile.profile_id,
            &alice_client.client_id,
            8,
            "devnet-monero-block-8",
            "devnet-monero-tx-alice-deposit-0",
            0,
            "7f",
            "bucket-10",
            "devnet-alice-output-0",
            "devnet-alice-one-time-address-0",
            Some("devnet-alice-key-image-hint-0".to_string()),
            "scan-0001",
            ViewTagMatchStatus::Matched,
        )?;
        state.observe_view_tag(
            &alice_profile.profile_id,
            &alice_client.client_id,
            9,
            "devnet-monero-block-9",
            "devnet-monero-tx-alice-change-0",
            1,
            "7f",
            "bucket-0",
            "devnet-alice-output-1",
            "devnet-alice-one-time-address-1",
            None,
            "scan-0002",
            ViewTagMatchStatus::FalsePositive,
        )?;
        let checkpoint = state.seal_scan_checkpoint(
            &alice_profile.profile_id,
            &alice_client.client_id,
            1,
            12,
            None,
        )?;

        let ticket = state.open_disclosure_ticket(
            DisclosureTicketScope::IncomingTransfer,
            "devnet-risk-auditor",
            Some(alice_profile.profile_id.clone()),
            &first_hit.observation_id,
            &first_hit.observation_root(),
            &["amount_bucket".to_string(), "confirmations".to_string()],
            "view-tag-hit-limited-disclosure",
            MONERO_WALLET_SYNC_DEFAULT_PQ_SECURITY_BITS,
        )?;
        state.approve_disclosure_ticket(&ticket.ticket_id)?;

        let sponsorship = state.open_scan_sponsorship(
            "devnet-scan-sponsor",
            Some(alice_profile.profile_id.clone()),
            Some(alice_client.client_id.clone()),
            MONERO_WALLET_SYNC_DEVNET_FEE_ASSET_ID,
            16,
            MONERO_WALLET_SYNC_DEFAULT_SCAN_REBATE_MICRO_UNITS,
            800_000,
        )?;
        state.reserve_sponsored_scan_units(&sponsorship.sponsorship_id, 4)?;
        state.settle_sponsorship(
            &sponsorship.sponsorship_id,
            4,
            &checkpoint.checkpoint_root(),
        )?;

        let withdrawal = state.monitor_withdrawal(
            "devnet-withdrawal-0",
            &bridge_profile.profile_id,
            "devnet-withdrawal-nullifier-0",
            "devnet-withdrawal-key-image-0",
            "devnet-withdrawal-destination-0",
            10_000,
            10,
            Some(ticket.ticket_id.clone()),
        )?;
        state.observe_withdrawal(&withdrawal.monitor_id, "devnet-monero-withdrawal-tx-0", 10)?;

        state.record_reorg_window(
            &alice_profile.profile_id,
            12,
            "devnet-old-tip-12",
            13,
            "devnet-new-tip-13",
            11,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroWalletSyncResult<String> {
        self.height = height;
        for client in self.watch_clients.values_mut() {
            if matches!(
                client.status,
                WatchClientStatus::Active | WatchClientStatus::Rotating
            ) && height >= client.expires_at_height
            {
                client.status = WatchClientStatus::Expired;
            }
            client.last_seen_height = client
                .last_seen_height
                .min(height)
                .max(client.registered_at_height);
        }
        for attestation in self.client_attestations.values_mut() {
            if attestation.status.can_scan() && height >= attestation.expires_at_height {
                attestation.status = WatchClientStatus::Expired;
            }
        }
        for ticket in self.disclosure_tickets.values_mut() {
            if ticket.status.is_active() && height >= ticket.expires_at_height {
                ticket.status = DisclosureTicketStatus::Expired;
            }
        }
        for sponsorship in self.scan_sponsorships.values_mut() {
            if sponsorship.status.is_active() && height >= sponsorship.expires_at_height {
                sponsorship.status = ScanSponsorshipStatus::Expired;
            }
        }
        for withdrawal in self.withdrawal_monitors.values_mut() {
            withdrawal.refresh(height, self.config.finality_depth);
        }
        self.validate()
    }

    pub fn register_view_profile(
        &mut self,
        account_label: &str,
        view_key_label: &str,
        wallet_address_tag: &str,
        restore_height: u64,
        scan_from_height: u64,
        privacy_labels: &[String],
    ) -> MoneroWalletSyncResult<MoneroViewKeyProfile> {
        let profile = MoneroViewKeyProfile::new(
            account_label,
            view_key_label,
            wallet_address_tag,
            restore_height,
            scan_from_height,
            privacy_labels,
            self.height,
        )?;
        insert_unique_record(
            &mut self.view_profiles,
            profile.profile_id.clone(),
            profile.clone(),
            "monero wallet sync profile",
        )?;
        Ok(profile)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_watch_client(
        &mut self,
        client_label: &str,
        client_kind: WalletSyncClientKind,
        pq_auth_scheme: &str,
        pq_public_key_material: &str,
        view_key_label: &str,
        allowed_scopes: &[String],
        security_bits: u16,
    ) -> MoneroWalletSyncResult<PqWatchOnlyClient> {
        if self.config.require_pq_client_auth
            && security_bits < self.config.min_watch_client_pq_security_bits
        {
            return Err("monero wallet sync watch client pq security below policy".to_string());
        }
        let client = PqWatchOnlyClient::new(
            client_label,
            client_kind,
            pq_auth_scheme,
            pq_public_key_material,
            view_key_label,
            allowed_scopes,
            self.height,
            self.config.client_session_ttl_blocks,
            security_bits,
        )?;
        insert_unique_record(
            &mut self.watch_clients,
            client.client_id.clone(),
            client.clone(),
            "monero wallet sync watch client",
        )?;
        Ok(client)
    }

    pub fn attest_client_subject(
        &mut self,
        client_id: &str,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        signature_material: &str,
    ) -> MoneroWalletSyncResult<PqClientAttestation> {
        self.require_client(client_id)?;
        let attestation = PqClientAttestation::new(
            client_id,
            subject_kind,
            subject_id,
            subject_root,
            signature_material,
            self.height,
            self.config.client_session_ttl_blocks,
        )?;
        insert_unique_record(
            &mut self.client_attestations,
            attestation.attestation_id.clone(),
            attestation.clone(),
            "monero wallet sync client attestation",
        )?;
        Ok(attestation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_view_tag(
        &mut self,
        profile_id: &str,
        client_id: &str,
        block_height: u64,
        block_hash: &str,
        txid_label: &str,
        output_index: u64,
        view_tag: &str,
        encrypted_amount_bucket: &str,
        output_material: &str,
        one_time_address_label: &str,
        key_image_hint_label: Option<String>,
        scan_nonce: &str,
        status: ViewTagMatchStatus,
    ) -> MoneroWalletSyncResult<ViewTagObservation> {
        self.require_profile(profile_id)?;
        self.require_scanning_client(client_id)?;
        let observation = ViewTagObservation::new(
            profile_id,
            client_id,
            block_height,
            block_hash,
            txid_label,
            output_index,
            view_tag,
            encrypted_amount_bucket,
            output_material,
            one_time_address_label,
            key_image_hint_label,
            scan_nonce,
            self.height,
            status,
        )?;
        insert_unique_record(
            &mut self.view_tag_observations,
            observation.observation_id.clone(),
            observation.clone(),
            "monero wallet sync view tag observation",
        )?;
        Ok(observation)
    }

    pub fn seal_scan_checkpoint(
        &mut self,
        profile_id: &str,
        client_id: &str,
        from_monero_height: u64,
        to_monero_height: u64,
        parent_checkpoint_id: Option<String>,
    ) -> MoneroWalletSyncResult<ScanCheckpoint> {
        self.require_profile(profile_id)?;
        self.require_scanning_client(client_id)?;
        if to_monero_height
            .saturating_sub(from_monero_height)
            .saturating_add(1)
            > self.config.max_view_tags_per_checkpoint
        {
            return Err("monero wallet sync checkpoint exceeds configured scan span".to_string());
        }
        if let Some(parent) = parent_checkpoint_id.as_deref() {
            if !self.scan_checkpoints.contains_key(parent) {
                return Err("monero wallet sync parent checkpoint is unknown".to_string());
            }
        }
        let observations = self
            .view_tag_observations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let checkpoint = ScanCheckpoint::new(
            profile_id,
            client_id,
            from_monero_height,
            to_monero_height,
            self.height,
            self.height,
            &observations,
            parent_checkpoint_id,
            ScanCheckpointStatus::Sealed,
        )?;
        insert_unique_record(
            &mut self.scan_checkpoints,
            checkpoint.checkpoint_id.clone(),
            checkpoint.clone(),
            "monero wallet sync checkpoint",
        )?;
        Ok(checkpoint)
    }

    pub fn record_reorg_window(
        &mut self,
        profile_id: &str,
        old_tip_height: u64,
        old_tip_hash: &str,
        new_tip_height: u64,
        new_tip_hash: &str,
        rollback_to_height: u64,
    ) -> MoneroWalletSyncResult<ReorgSafeSyncWindow> {
        self.require_profile(profile_id)?;
        let affected_checkpoint_ids = self
            .scan_checkpoints
            .values()
            .filter(|checkpoint| {
                checkpoint.profile_id == profile_id
                    && checkpoint.to_monero_height >= rollback_to_height
            })
            .map(|checkpoint| checkpoint.checkpoint_id.clone())
            .collect::<Vec<_>>();
        let affected_observation_ids = self
            .view_tag_observations
            .values()
            .filter(|observation| {
                observation.profile_id == profile_id
                    && observation.block_height >= rollback_to_height
            })
            .map(|observation| observation.observation_id.clone())
            .collect::<Vec<_>>();
        for checkpoint_id in &affected_checkpoint_ids {
            if let Some(checkpoint) = self.scan_checkpoints.get_mut(checkpoint_id) {
                checkpoint.status = ScanCheckpointStatus::Reorged;
            }
        }
        for observation_id in &affected_observation_ids {
            if let Some(observation) = self.view_tag_observations.get_mut(observation_id) {
                observation.status = ViewTagMatchStatus::Reorged;
            }
        }
        let reorg = ReorgSafeSyncWindow::new(
            profile_id,
            old_tip_height,
            old_tip_hash,
            new_tip_height,
            new_tip_hash,
            rollback_to_height,
            &affected_checkpoint_ids,
            &affected_observation_ids,
            self.height,
        )?;
        insert_unique_record(
            &mut self.reorg_windows,
            reorg.reorg_id.clone(),
            reorg.clone(),
            "monero wallet sync reorg window",
        )?;
        Ok(reorg)
    }

    pub fn resolve_reorg_window(
        &mut self,
        reorg_id: &str,
        status: ReorgSyncStatus,
    ) -> MoneroWalletSyncResult<ReorgSafeSyncWindow> {
        if status.is_open() {
            return Err("monero wallet sync reorg resolution requires final status".to_string());
        }
        let reorg = self
            .reorg_windows
            .get_mut(reorg_id)
            .ok_or_else(|| "unknown monero wallet sync reorg window".to_string())?;
        reorg.status = status;
        reorg.resolved_at_height = Some(self.height);
        reorg.validate()?;
        Ok(reorg.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_disclosure_ticket(
        &mut self,
        scope: DisclosureTicketScope,
        requester_label: &str,
        profile_id: Option<String>,
        subject_id: &str,
        subject_root: &str,
        disclosed_fields: &[String],
        policy_label: &str,
        min_consumer_pq_security_bits: u16,
    ) -> MoneroWalletSyncResult<LimitedDisclosureTicket> {
        if let Some(profile_id) = profile_id.as_deref() {
            self.require_profile(profile_id)?;
        }
        let ticket = LimitedDisclosureTicket::new(
            scope,
            requester_label,
            profile_id,
            subject_id,
            subject_root,
            disclosed_fields,
            policy_label,
            min_consumer_pq_security_bits,
            self.height,
            self.config.disclosure_ticket_ttl_blocks,
        )?;
        insert_unique_record(
            &mut self.disclosure_tickets,
            ticket.ticket_id.clone(),
            ticket.clone(),
            "monero wallet sync disclosure ticket",
        )?;
        Ok(ticket)
    }

    pub fn approve_disclosure_ticket(
        &mut self,
        ticket_id: &str,
    ) -> MoneroWalletSyncResult<LimitedDisclosureTicket> {
        let ticket = self
            .disclosure_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown monero wallet sync disclosure ticket".to_string())?;
        if !ticket.status.is_active() {
            return Err("monero wallet sync disclosure ticket is not active".to_string());
        }
        ticket.status = DisclosureTicketStatus::Approved;
        ticket.validate()?;
        Ok(ticket.clone())
    }

    pub fn reveal_disclosure_ticket(
        &mut self,
        ticket_id: &str,
    ) -> MoneroWalletSyncResult<LimitedDisclosureTicket> {
        let ticket = self
            .disclosure_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown monero wallet sync disclosure ticket".to_string())?;
        if ticket.status != DisclosureTicketStatus::Approved {
            return Err("monero wallet sync disclosure ticket must be approved".to_string());
        }
        ticket.revealed_at_height = Some(self.height);
        ticket.status = DisclosureTicketStatus::Revealed;
        ticket.validate()?;
        Ok(ticket.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_scan_sponsorship(
        &mut self,
        sponsor_label: &str,
        profile_id: Option<String>,
        client_id: Option<String>,
        fee_asset_id: &str,
        max_scan_units: u64,
        rebate_rate_micro_units: u64,
        budget_micro_units: u64,
    ) -> MoneroWalletSyncResult<LowFeeScanSponsorship> {
        if let Some(profile_id) = profile_id.as_deref() {
            self.require_profile(profile_id)?;
        }
        if let Some(client_id) = client_id.as_deref() {
            self.require_client(client_id)?;
        }
        if max_scan_units > self.config.low_fee_scan_unit_cap {
            return Err("monero wallet sync sponsorship exceeds low fee scan cap".to_string());
        }
        let sponsorship = LowFeeScanSponsorship::new(
            sponsor_label,
            profile_id,
            client_id,
            fee_asset_id,
            max_scan_units,
            rebate_rate_micro_units,
            budget_micro_units,
            self.height,
            self.config.sponsorship_ttl_blocks,
        )?;
        insert_unique_record(
            &mut self.scan_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship.clone(),
            "monero wallet sync sponsorship",
        )?;
        Ok(sponsorship)
    }

    pub fn reserve_sponsored_scan_units(
        &mut self,
        sponsorship_id: &str,
        scan_units: u64,
    ) -> MoneroWalletSyncResult<LowFeeScanSponsorship> {
        let sponsorship = self
            .scan_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown monero wallet sync sponsorship".to_string())?;
        sponsorship.reserve(scan_units)?;
        Ok(sponsorship.clone())
    }

    pub fn settle_sponsorship(
        &mut self,
        sponsorship_id: &str,
        scan_units: u64,
        receipt_root: &str,
    ) -> MoneroWalletSyncResult<LowFeeScanSponsorship> {
        let sponsorship = self
            .scan_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown monero wallet sync sponsorship".to_string())?;
        sponsorship.settle(scan_units, receipt_root)?;
        Ok(sponsorship.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn monitor_withdrawal(
        &mut self,
        withdrawal_id: &str,
        profile_id: &str,
        nullifier_label: &str,
        key_image_label: &str,
        destination_address_label: &str,
        amount_bucket: u64,
        expected_monero_height: u64,
        disclosure_ticket_id: Option<String>,
    ) -> MoneroWalletSyncResult<BridgeWithdrawalMonitor> {
        self.require_profile(profile_id)?;
        if let Some(ticket_id) = disclosure_ticket_id.as_deref() {
            if !self.disclosure_tickets.contains_key(ticket_id) {
                return Err(
                    "monero wallet sync withdrawal disclosure ticket is unknown".to_string()
                );
            }
        }
        let monitor = BridgeWithdrawalMonitor::new(
            withdrawal_id,
            profile_id,
            nullifier_label,
            key_image_label,
            destination_address_label,
            amount_bucket,
            expected_monero_height,
            self.height,
            self.config.withdrawal_alert_blocks,
            disclosure_ticket_id,
        )?;
        insert_unique_record(
            &mut self.withdrawal_monitors,
            monitor.monitor_id.clone(),
            monitor.clone(),
            "monero wallet sync withdrawal monitor",
        )?;
        Ok(monitor)
    }

    pub fn observe_withdrawal(
        &mut self,
        monitor_id: &str,
        txid_label: &str,
        observed_height: u64,
    ) -> MoneroWalletSyncResult<BridgeWithdrawalMonitor> {
        let monitor = self
            .withdrawal_monitors
            .get_mut(monitor_id)
            .ok_or_else(|| "unknown monero wallet sync withdrawal monitor".to_string())?;
        monitor.observe(
            txid_label,
            observed_height,
            self.height,
            self.config.finality_depth,
        )?;
        Ok(monitor.clone())
    }

    pub fn profile_root(&self) -> String {
        monero_wallet_sync_profile_collection_root(
            &self.view_profiles.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn watch_client_root(&self) -> String {
        monero_wallet_sync_watch_client_collection_root(
            &self.watch_clients.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn client_attestation_root(&self) -> String {
        monero_wallet_sync_attestation_collection_root(
            &self
                .client_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn view_tag_observation_root(&self) -> String {
        monero_wallet_sync_view_tag_observation_collection_root(
            &self
                .view_tag_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn scan_checkpoint_root(&self) -> String {
        monero_wallet_sync_checkpoint_collection_root(
            &self.scan_checkpoints.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reorg_window_root(&self) -> String {
        monero_wallet_sync_reorg_collection_root(
            &self.reorg_windows.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn disclosure_ticket_root(&self) -> String {
        monero_wallet_sync_disclosure_ticket_collection_root(
            &self
                .disclosure_tickets
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn scan_sponsorship_root(&self) -> String {
        monero_wallet_sync_sponsorship_collection_root(
            &self.scan_sponsorships.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn withdrawal_monitor_root(&self) -> String {
        monero_wallet_sync_withdrawal_monitor_collection_root(
            &self
                .withdrawal_monitors
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        keyed_value_root(
            "MONERO-WALLET-SYNC-PUBLIC-RECORDS",
            self.public_records_for_root(),
        )
    }

    pub fn counters(&self) -> MoneroWalletSyncCounters {
        MoneroWalletSyncCounters {
            height: self.height,
            profile_count: self.view_profiles.len() as u64,
            active_profile_count: self
                .view_profiles
                .values()
                .filter(|profile| profile.active)
                .count() as u64,
            watch_client_count: self.watch_clients.len() as u64,
            active_watch_client_count: self
                .watch_clients
                .values()
                .filter(|client| client.status.can_scan())
                .count() as u64,
            client_attestation_count: self.client_attestations.len() as u64,
            active_client_attestation_count: self
                .client_attestations
                .values()
                .filter(|attestation| attestation.status.can_scan())
                .count() as u64,
            view_tag_observation_count: self.view_tag_observations.len() as u64,
            live_view_tag_count: self
                .view_tag_observations
                .values()
                .filter(|observation| observation.status.is_live_match())
                .count() as u64,
            matched_view_tag_count: self
                .view_tag_observations
                .values()
                .filter(|observation| observation.status == ViewTagMatchStatus::Matched)
                .count() as u64,
            scan_checkpoint_count: self.scan_checkpoints.len() as u64,
            current_checkpoint_count: self
                .scan_checkpoints
                .values()
                .filter(|checkpoint| checkpoint.status.is_current())
                .count() as u64,
            reorg_window_count: self.reorg_windows.len() as u64,
            open_reorg_window_count: self
                .reorg_windows
                .values()
                .filter(|reorg| reorg.status.is_open())
                .count() as u64,
            disclosure_ticket_count: self.disclosure_tickets.len() as u64,
            active_disclosure_ticket_count: self
                .disclosure_tickets
                .values()
                .filter(|ticket| ticket.status.is_active())
                .count() as u64,
            scan_sponsorship_count: self.scan_sponsorships.len() as u64,
            active_sponsorship_count: self
                .scan_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_active())
                .count() as u64,
            withdrawal_monitor_count: self.withdrawal_monitors.len() as u64,
            finalized_withdrawal_count: self
                .withdrawal_monitors
                .values()
                .filter(|withdrawal| withdrawal.status == WithdrawalMonitorStatus::Finalized)
                .count() as u64,
            stuck_withdrawal_count: self
                .withdrawal_monitors
                .values()
                .filter(|withdrawal| withdrawal.status == WithdrawalMonitorStatus::Stuck)
                .count() as u64,
            sponsored_scan_units: self
                .scan_sponsorships
                .values()
                .map(|sponsorship| sponsorship.reserved_scan_units)
                .sum(),
            settled_scan_units: self
                .scan_sponsorships
                .values()
                .map(|sponsorship| sponsorship.settled_scan_units)
                .sum(),
            public_record_count: self.public_records_for_root().len() as u64,
        }
    }

    pub fn roots(&self) -> MoneroWalletSyncRoots {
        let mut roots = MoneroWalletSyncRoots {
            config_root: self.config.config_root(),
            profile_root: self.profile_root(),
            watch_client_root: self.watch_client_root(),
            client_attestation_root: self.client_attestation_root(),
            view_tag_observation_root: self.view_tag_observation_root(),
            scan_checkpoint_root: self.scan_checkpoint_root(),
            reorg_window_root: self.reorg_window_root(),
            disclosure_ticket_root: self.disclosure_ticket_root(),
            scan_sponsorship_root: self.scan_sponsorship_root(),
            withdrawal_monitor_root: self.withdrawal_monitor_root(),
            public_record_root: self.public_record_root(),
            state_root: String::new(),
        };
        let record = self.public_record_without_state_root(&roots);
        roots.state_root = monero_wallet_sync_state_root_from_record(&record);
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root(&roots);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(roots.state_root));
        }
        record
    }

    pub fn validate(&self) -> MoneroWalletSyncResult<String> {
        self.config.validate()?;
        ensure_non_empty(&self.operator_label, "monero wallet sync operator label")?;
        ensure_non_empty(&self.network, "monero wallet sync network")?;
        if self.network != self.config.network {
            return Err("monero wallet sync state network mismatch".to_string());
        }
        for (profile_id, profile) in &self.view_profiles {
            if profile_id != &profile.profile_id {
                return Err("monero wallet sync profile map key mismatch".to_string());
            }
            profile.validate()?;
        }
        for (client_id, client) in &self.watch_clients {
            if client_id != &client.client_id {
                return Err("monero wallet sync client map key mismatch".to_string());
            }
            client.validate()?;
        }
        for (attestation_id, attestation) in &self.client_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("monero wallet sync attestation map key mismatch".to_string());
            }
            if !self.watch_clients.contains_key(&attestation.client_id) {
                return Err("monero wallet sync attestation references unknown client".to_string());
            }
            attestation.validate()?;
        }
        for (observation_id, observation) in &self.view_tag_observations {
            if observation_id != &observation.observation_id {
                return Err("monero wallet sync observation map key mismatch".to_string());
            }
            if !self.view_profiles.contains_key(&observation.profile_id) {
                return Err("monero wallet sync observation references unknown profile".to_string());
            }
            if !self.watch_clients.contains_key(&observation.client_id) {
                return Err("monero wallet sync observation references unknown client".to_string());
            }
            observation.validate()?;
        }
        for (checkpoint_id, checkpoint) in &self.scan_checkpoints {
            if checkpoint_id != &checkpoint.checkpoint_id {
                return Err("monero wallet sync checkpoint map key mismatch".to_string());
            }
            if !self.view_profiles.contains_key(&checkpoint.profile_id) {
                return Err("monero wallet sync checkpoint references unknown profile".to_string());
            }
            if !self.watch_clients.contains_key(&checkpoint.client_id) {
                return Err("monero wallet sync checkpoint references unknown client".to_string());
            }
            if let Some(parent) = checkpoint.parent_checkpoint_id.as_deref() {
                if !self.scan_checkpoints.contains_key(parent) {
                    return Err(
                        "monero wallet sync checkpoint references unknown parent".to_string()
                    );
                }
            }
            checkpoint.validate()?;
        }
        for (reorg_id, reorg) in &self.reorg_windows {
            if reorg_id != &reorg.reorg_id {
                return Err("monero wallet sync reorg map key mismatch".to_string());
            }
            if !self.view_profiles.contains_key(&reorg.profile_id) {
                return Err("monero wallet sync reorg references unknown profile".to_string());
            }
            reorg.validate()?;
        }
        for (ticket_id, ticket) in &self.disclosure_tickets {
            if ticket_id != &ticket.ticket_id {
                return Err("monero wallet sync disclosure ticket map key mismatch".to_string());
            }
            if let Some(profile_id) = ticket.profile_id.as_deref() {
                if !self.view_profiles.contains_key(profile_id) {
                    return Err(
                        "monero wallet sync disclosure references unknown profile".to_string()
                    );
                }
            }
            ticket.validate()?;
        }
        for (sponsorship_id, sponsorship) in &self.scan_sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("monero wallet sync sponsorship map key mismatch".to_string());
            }
            if let Some(profile_id) = sponsorship.profile_id.as_deref() {
                if !self.view_profiles.contains_key(profile_id) {
                    return Err(
                        "monero wallet sync sponsorship references unknown profile".to_string()
                    );
                }
            }
            if let Some(client_id) = sponsorship.client_id.as_deref() {
                if !self.watch_clients.contains_key(client_id) {
                    return Err(
                        "monero wallet sync sponsorship references unknown client".to_string()
                    );
                }
            }
            sponsorship.validate()?;
        }
        for (monitor_id, monitor) in &self.withdrawal_monitors {
            if monitor_id != &monitor.monitor_id {
                return Err("monero wallet sync withdrawal monitor map key mismatch".to_string());
            }
            if !self.view_profiles.contains_key(&monitor.profile_id) {
                return Err(
                    "monero wallet sync withdrawal monitor references unknown profile".to_string(),
                );
            }
            if let Some(ticket_id) = monitor.disclosure_ticket_id.as_deref() {
                if !self.disclosure_tickets.contains_key(ticket_id) {
                    return Err(
                        "monero wallet sync withdrawal monitor references unknown ticket"
                            .to_string(),
                    );
                }
            }
            monitor.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self, roots: &MoneroWalletSyncRoots) -> Value {
        json!({
            "kind": "monero_wallet_sync_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WALLET_SYNC_PROTOCOL_VERSION,
            "height": self.height,
            "operator_label": self.operator_label,
            "network": self.network,
            "config_id": self.config.config_id,
            "roots": roots.public_record_without_state_root(),
            "counters": self.counters().public_record(),
        })
    }

    fn require_profile(&self, profile_id: &str) -> MoneroWalletSyncResult<()> {
        if self.view_profiles.contains_key(profile_id) {
            Ok(())
        } else {
            Err("unknown monero wallet sync profile".to_string())
        }
    }

    fn require_client(&self, client_id: &str) -> MoneroWalletSyncResult<()> {
        if self.watch_clients.contains_key(client_id) {
            Ok(())
        } else {
            Err("unknown monero wallet sync client".to_string())
        }
    }

    fn require_scanning_client(&self, client_id: &str) -> MoneroWalletSyncResult<()> {
        let client = self
            .watch_clients
            .get(client_id)
            .ok_or_else(|| "unknown monero wallet sync client".to_string())?;
        if client.status.can_scan() {
            Ok(())
        } else {
            Err("monero wallet sync client is not scan-capable".to_string())
        }
    }

    fn public_records_for_root(&self) -> Vec<(String, Value)> {
        let mut records = Vec::new();
        records.push(("config".to_string(), self.config.public_record()));
        for profile in self.view_profiles.values() {
            records.push((
                format!("profile:{}", profile.profile_id),
                profile.public_record(),
            ));
        }
        for client in self.watch_clients.values() {
            records.push((
                format!("client:{}", client.client_id),
                client.public_record(),
            ));
        }
        for attestation in self.client_attestations.values() {
            records.push((
                format!("attestation:{}", attestation.attestation_id),
                attestation.public_record(),
            ));
        }
        for observation in self.view_tag_observations.values() {
            records.push((
                format!("observation:{}", observation.observation_id),
                observation.public_record(),
            ));
        }
        for checkpoint in self.scan_checkpoints.values() {
            records.push((
                format!("checkpoint:{}", checkpoint.checkpoint_id),
                checkpoint.public_record(),
            ));
        }
        for reorg in self.reorg_windows.values() {
            records.push((format!("reorg:{}", reorg.reorg_id), reorg.public_record()));
        }
        for ticket in self.disclosure_tickets.values() {
            records.push((
                format!("ticket:{}", ticket.ticket_id),
                ticket.public_record(),
            ));
        }
        for sponsorship in self.scan_sponsorships.values() {
            records.push((
                format!("sponsorship:{}", sponsorship.sponsorship_id),
                sponsorship.public_record(),
            ));
        }
        for monitor in self.withdrawal_monitors.values() {
            records.push((
                format!("withdrawal:{}", monitor.monitor_id),
                monitor.public_record(),
            ));
        }
        records
    }
}

pub fn monero_wallet_sync_state_root_from_record(record: &Value) -> String {
    monero_wallet_sync_payload_root("MONERO-WALLET-SYNC-STATE", record)
}

pub fn monero_wallet_sync_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn monero_wallet_sync_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn monero_wallet_sync_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn monero_wallet_sync_string_set_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &ordered_strings(values)
            .iter()
            .map(|value| json!({"value": value}))
            .collect::<Vec<_>>(),
    )
}

pub fn monero_wallet_sync_config_id_from_fields(
    network: &str,
    asset_id: &str,
    fee_asset_id: &str,
    finality_depth: u64,
    checkpoint_interval_blocks: u64,
    max_reorg_depth: u64,
    require_pq_client_auth: bool,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-CONFIG-ID",
        &json!({
            "network": network,
            "asset_id": asset_id,
            "fee_asset_id": fee_asset_id,
            "finality_depth": finality_depth,
            "checkpoint_interval_blocks": checkpoint_interval_blocks,
            "max_reorg_depth": max_reorg_depth,
            "require_pq_client_auth": require_pq_client_auth,
        }),
    )
}

pub fn monero_wallet_sync_profile_id(
    account_label: &str,
    view_key_commitment: &str,
    wallet_address_tag: &str,
    restore_height: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-PROFILE-ID",
        &json!({
            "account_label": account_label,
            "view_key_commitment": view_key_commitment,
            "wallet_address_tag": wallet_address_tag,
            "restore_height": restore_height,
        }),
    )
}

pub fn monero_wallet_sync_client_id(
    client_label: &str,
    client_kind: WalletSyncClientKind,
    pq_auth_scheme: &str,
    pq_public_key_root: &str,
    view_key_commitment: &str,
    registered_at_height: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-CLIENT-ID",
        &json!({
            "client_label": client_label,
            "client_kind": client_kind.as_str(),
            "pq_auth_scheme": pq_auth_scheme,
            "pq_public_key_root": pq_public_key_root,
            "view_key_commitment": view_key_commitment,
            "registered_at_height": registered_at_height,
        }),
    )
}

pub fn monero_wallet_sync_attestation_id(
    client_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-ATTESTATION-ID",
        &json!({
            "client_id": client_id,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "signed_at_height": signed_at_height,
        }),
    )
}

pub fn monero_wallet_sync_signature_root(
    signer_id: &str,
    subject_root: &str,
    signature_material: &str,
) -> String {
    domain_hash(
        "MONERO-WALLET-SYNC-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WALLET_SYNC_PROTOCOL_VERSION),
            HashPart::Str(signer_id),
            HashPart::Str(subject_root),
            HashPart::Str(signature_material),
        ],
        32,
    )
}

pub fn monero_wallet_sync_observation_id(
    profile_id: &str,
    client_id: &str,
    block_height: u64,
    block_hash: &str,
    txid_hash: &str,
    output_index: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-OBSERVATION-ID",
        &json!({
            "profile_id": profile_id,
            "client_id": client_id,
            "block_height": block_height,
            "block_hash": block_hash,
            "txid_hash": txid_hash,
            "output_index": output_index,
        }),
    )
}

pub fn monero_wallet_sync_checkpoint_id(
    profile_id: &str,
    client_id: &str,
    from_monero_height: u64,
    to_monero_height: u64,
    view_tag_root: &str,
    candidate_output_root: &str,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-CHECKPOINT-ID",
        &json!({
            "profile_id": profile_id,
            "client_id": client_id,
            "from_monero_height": from_monero_height,
            "to_monero_height": to_monero_height,
            "view_tag_root": view_tag_root,
            "candidate_output_root": candidate_output_root,
        }),
    )
}

pub fn monero_wallet_sync_reorg_id(
    profile_id: &str,
    old_tip_height: u64,
    old_tip_hash: &str,
    new_tip_height: u64,
    new_tip_hash: &str,
    rollback_to_height: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-REORG-ID",
        &json!({
            "profile_id": profile_id,
            "old_tip_height": old_tip_height,
            "old_tip_hash": old_tip_hash,
            "new_tip_height": new_tip_height,
            "new_tip_hash": new_tip_hash,
            "rollback_to_height": rollback_to_height,
        }),
    )
}

pub fn monero_wallet_sync_disclosure_ticket_id(
    scope: DisclosureTicketScope,
    requester_label: &str,
    profile_id: Option<&str>,
    subject_id: &str,
    subject_root: &str,
    disclosed_field_root: &str,
    requested_at_height: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-DISCLOSURE-TICKET-ID",
        &json!({
            "scope": scope.as_str(),
            "requester_label": requester_label,
            "profile_id": profile_id,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "disclosed_field_root": disclosed_field_root,
            "requested_at_height": requested_at_height,
        }),
    )
}

pub fn monero_wallet_sync_sponsorship_id(
    sponsor_label: &str,
    profile_id: Option<&str>,
    client_id: Option<&str>,
    fee_asset_id: &str,
    max_scan_units: u64,
    created_at_height: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-SPONSORSHIP-ID",
        &json!({
            "sponsor_label": sponsor_label,
            "profile_id": profile_id,
            "client_id": client_id,
            "fee_asset_id": fee_asset_id,
            "max_scan_units": max_scan_units,
            "created_at_height": created_at_height,
        }),
    )
}

pub fn monero_wallet_sync_withdrawal_monitor_id(
    withdrawal_id: &str,
    profile_id: &str,
    nullifier_root: &str,
    key_image_root: &str,
    expected_monero_height: u64,
) -> String {
    monero_wallet_sync_payload_root(
        "MONERO-WALLET-SYNC-WITHDRAWAL-MONITOR-ID",
        &json!({
            "withdrawal_id": withdrawal_id,
            "profile_id": profile_id,
            "nullifier_root": nullifier_root,
            "key_image_root": key_image_root,
            "expected_monero_height": expected_monero_height,
        }),
    )
}

pub fn monero_wallet_sync_profile_collection_root(profiles: &[MoneroViewKeyProfile]) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-PROFILE-COLLECTION",
        profiles
            .iter()
            .map(|profile| (profile.profile_id.clone(), profile.public_record()))
            .collect(),
    )
}

pub fn monero_wallet_sync_watch_client_collection_root(clients: &[PqWatchOnlyClient]) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-CLIENT-COLLECTION",
        clients
            .iter()
            .map(|client| (client.client_id.clone(), client.public_record()))
            .collect(),
    )
}

pub fn monero_wallet_sync_attestation_collection_root(
    attestations: &[PqClientAttestation],
) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-ATTESTATION-COLLECTION",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_wallet_sync_view_tag_observation_collection_root(
    observations: &[ViewTagObservation],
) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-OBSERVATION-COLLECTION",
        observations
            .iter()
            .map(|observation| {
                (
                    observation.observation_id.clone(),
                    observation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_wallet_sync_candidate_output_root(observations: &[ViewTagObservation]) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-CANDIDATE-OUTPUTS",
        observations
            .iter()
            .filter(|observation| observation.status.is_live_match())
            .map(|observation| {
                (
                    observation.observation_id.clone(),
                    json!({
                        "observation_id": observation.observation_id,
                        "output_commitment": observation.output_commitment,
                        "one_time_address_commitment": observation.one_time_address_commitment,
                        "encrypted_amount_bucket": observation.encrypted_amount_bucket,
                        "status": observation.status.as_str(),
                    }),
                )
            })
            .collect(),
    )
}

pub fn monero_wallet_sync_checkpoint_collection_root(checkpoints: &[ScanCheckpoint]) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-CHECKPOINT-COLLECTION",
        checkpoints
            .iter()
            .map(|checkpoint| (checkpoint.checkpoint_id.clone(), checkpoint.public_record()))
            .collect(),
    )
}

pub fn monero_wallet_sync_reorg_collection_root(reorgs: &[ReorgSafeSyncWindow]) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-REORG-COLLECTION",
        reorgs
            .iter()
            .map(|reorg| (reorg.reorg_id.clone(), reorg.public_record()))
            .collect(),
    )
}

pub fn monero_wallet_sync_disclosure_ticket_collection_root(
    tickets: &[LimitedDisclosureTicket],
) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-DISCLOSURE-TICKET-COLLECTION",
        tickets
            .iter()
            .map(|ticket| (ticket.ticket_id.clone(), ticket.public_record()))
            .collect(),
    )
}

pub fn monero_wallet_sync_sponsorship_collection_root(
    sponsorships: &[LowFeeScanSponsorship],
) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-SPONSORSHIP-COLLECTION",
        sponsorships
            .iter()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_wallet_sync_withdrawal_monitor_collection_root(
    monitors: &[BridgeWithdrawalMonitor],
) -> String {
    keyed_record_root(
        "MONERO-WALLET-SYNC-WITHDRAWAL-MONITOR-COLLECTION",
        monitors
            .iter()
            .map(|monitor| (monitor.monitor_id.clone(), monitor.public_record()))
            .collect(),
    )
}

fn keyed_record_root(domain: &str, records: Vec<(String, Value)>) -> String {
    keyed_value_root(domain, records)
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(key, record)| json!({"key": key, "record": record}))
            .collect::<Vec<_>>(),
    )
}

fn confirmations(current_height: u64, observed_height: u64) -> u64 {
    if current_height >= observed_height {
        current_height
            .saturating_sub(observed_height)
            .saturating_add(1)
    } else {
        0
    }
}

fn ordered_strings(values: &[String]) -> Vec<String> {
    ordered_string_set(values).into_iter().collect()
}

fn ordered_string_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect()
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroWalletSyncResult<()> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroWalletSyncResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroWalletSyncResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_wallet_sync_state_validates() -> MoneroWalletSyncResult<()> {
        let state = MoneroWalletSyncState::devnet()?;
        let root = state.validate()?;
        assert_eq!(root, state.state_root());
        assert!(state.counters().matched_view_tag_count > 0);
        assert_eq!(state.counters().scan_sponsorship_count, 1);
        Ok(())
    }

    #[test]
    fn roots_are_deterministic_for_same_fixture() -> MoneroWalletSyncResult<()> {
        let left = MoneroWalletSyncState::devnet()?;
        let right = MoneroWalletSyncState::devnet()?;
        assert_eq!(left.state_root(), right.state_root());
        assert_eq!(left.public_record_root(), right.public_record_root());
        Ok(())
    }

    #[test]
    fn reorg_marks_affected_scan_material() -> MoneroWalletSyncResult<()> {
        let mut state = MoneroWalletSyncState::devnet()?;
        let profile_id = state
            .view_profiles
            .values()
            .next()
            .map(|profile| profile.profile_id.clone())
            .ok_or_else(|| "missing devnet profile".to_string())?;
        let reorg = state.record_reorg_window(&profile_id, 20, "old-tip", 21, "new-tip", 1)?;
        assert!(state.reorg_windows.contains_key(&reorg.reorg_id));
        assert!(state
            .scan_checkpoints
            .values()
            .any(|checkpoint| checkpoint.status == ScanCheckpointStatus::Reorged));
        Ok(())
    }
}
