use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPrivateLightWalletRelayResult<T> = Result<T, String>;

pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_PROTOCOL_VERSION: &str =
    "nebula-monero-private-light-wallet-relay-v1";
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_VIEW_TAG_BITS: u16 = 8;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_FILTER_BITS: u16 = 2048;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_REORG_WINDOW_BLOCKS: u64 = 32;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CHECKPOINT_INTERVAL_BLOCKS: u64 = 8;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_EPOCH_BLOCKS: u64 = 16;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CLIENT_TTL_BLOCKS: u64 = 720;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_DELTA_TTL_BLOCKS: u64 = 144;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 288;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_LOW_FEE_SCAN_UNIT_PRICE: u64 = 225;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_TAGS_PER_REQUEST: u64 = 512;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_FILTERS_PER_CLIENT: u64 = 16;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_REQUESTS_PER_EPOCH: u64 = 64;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_DELTAS_PER_EPOCH: u64 = 96;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_EXIT_HINTS_PER_EPOCH: u64 = 24;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MIN_SCANNER_WEIGHT: u64 = 3;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_FILTER_SCHEME: &str =
    "monero-view-tag-compact-filter-shake256-v1";
pub const MONERO_PRIVATE_LIGHT_WALLET_RELAY_DELTA_ENCRYPTION: &str =
    "ml-kem-768-xchacha20poly1305-devnet-envelope-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayClientKind {
    WatchOnlyWallet,
    MobileWallet,
    BridgeOperator,
    Auditor,
    Sponsor,
    RecoveryAgent,
}

impl RelayClientKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatchOnlyWallet => "watch_only_wallet",
            Self::MobileWallet => "mobile_wallet",
            Self::BridgeOperator => "bridge_operator",
            Self::Auditor => "auditor",
            Self::Sponsor => "sponsor",
            Self::RecoveryAgent => "recovery_agent",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayClientStatus {
    Pending,
    Active,
    Rotating,
    RateLimited,
    Suspended,
    Revoked,
    Expired,
}

impl RelayClientStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::RateLimited => "rate_limited",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn can_request(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayScannerRole {
    ViewTagScanner,
    SubaddressRouter,
    BridgeWatcher,
    FilterBuilder,
    ReceiptSigner,
    ReorgReplay,
}

impl RelayScannerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagScanner => "view_tag_scanner",
            Self::SubaddressRouter => "subaddress_router",
            Self::BridgeWatcher => "bridge_watcher",
            Self::FilterBuilder => "filter_builder",
            Self::ReceiptSigner => "receipt_signer",
            Self::ReorgReplay => "reorg_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterScope {
    ViewTagBucket,
    SubaddressRoute,
    BridgeDeposit,
    BridgeExit,
    ReserveOutput,
    ReorgReplay,
}

impl FilterScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagBucket => "view_tag_bucket",
            Self::SubaddressRoute => "subaddress_route",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeExit => "bridge_exit",
            Self::ReserveOutput => "reserve_output",
            Self::ReorgReplay => "reorg_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanRequestStatus {
    Queued,
    Sponsored,
    Leased,
    Fulfilled,
    Settled,
    RateLimited,
    Expired,
    Reorged,
}

impl ScanRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sponsored => "sponsored",
            Self::Leased => "leased",
            Self::Fulfilled => "fulfilled",
            Self::Settled => "settled",
            Self::RateLimited => "rate_limited",
            Self::Expired => "expired",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Queued | Self::Sponsored | Self::Leased)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Consumed,
    Refunded,
    Slashed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_spendable(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletDeltaStatus {
    Prepared,
    Delivered,
    Acknowledged,
    Superseded,
    Expired,
    Reorged,
}

impl WalletDeltaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Prepared | Self::Delivered)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStatus {
    Open,
    Sealed,
    Finalized,
    Reorged,
    Superseded,
}

impl CheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Superseded => "superseded",
        }
    }

    pub fn is_canonical(self) -> bool {
        matches!(self, Self::Open | Self::Sealed | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    FilterBuilt,
    ScanProved,
    DeltaDelivered,
    SponsorCharged,
    ReorgReplay,
    ExitHintPublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilterBuilt => "filter_built",
            Self::ScanProved => "scan_proved",
            Self::DeltaDelivered => "delta_delivered",
            Self::SponsorCharged => "sponsor_charged",
            Self::ReorgReplay => "reorg_replay",
            Self::ExitHintPublished => "exit_hint_published",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeExitHintStatus {
    Proposed,
    Routed,
    Included,
    Finalized,
    Reorged,
    Expired,
}

impl BridgeExitHintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Routed => "routed",
            Self::Included => "included",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayParameters {
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub view_tag_bits: u16,
    pub filter_bits: u16,
    pub finality_depth: u64,
    pub reorg_window_blocks: u64,
    pub checkpoint_interval_blocks: u64,
    pub epoch_blocks: u64,
    pub client_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub delta_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub low_fee_scan_unit_price: u64,
    pub max_tags_per_request: u64,
    pub max_filters_per_client: u64,
    pub max_requests_per_epoch: u64,
    pub max_deltas_per_epoch: u64,
    pub max_exit_hints_per_epoch: u64,
    pub min_scanner_weight: u64,
    pub pq_security_bits: u16,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub filter_scheme: String,
    pub delta_encryption: String,
}

impl Default for RelayParameters {
    fn default() -> Self {
        Self {
            network: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEVNET_FEE_ASSET_ID.to_string(),
            view_tag_bits: MONERO_PRIVATE_LIGHT_WALLET_RELAY_VIEW_TAG_BITS,
            filter_bits: MONERO_PRIVATE_LIGHT_WALLET_RELAY_FILTER_BITS,
            finality_depth: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_FINALITY_DEPTH,
            reorg_window_blocks: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_REORG_WINDOW_BLOCKS,
            checkpoint_interval_blocks:
                MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            epoch_blocks: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_EPOCH_BLOCKS,
            client_ttl_blocks: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CLIENT_TTL_BLOCKS,
            sponsor_ttl_blocks: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_SPONSOR_TTL_BLOCKS,
            delta_ttl_blocks: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_DELTA_TTL_BLOCKS,
            receipt_ttl_blocks: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_RECEIPT_TTL_BLOCKS,
            low_fee_scan_unit_price:
                MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_LOW_FEE_SCAN_UNIT_PRICE,
            max_tags_per_request: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_TAGS_PER_REQUEST,
            max_filters_per_client:
                MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_FILTERS_PER_CLIENT,
            max_requests_per_epoch:
                MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_REQUESTS_PER_EPOCH,
            max_deltas_per_epoch: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_DELTAS_PER_EPOCH,
            max_exit_hints_per_epoch:
                MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MAX_EXIT_HINTS_PER_EPOCH,
            min_scanner_weight: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_MIN_SCANNER_WEIGHT,
            pq_security_bits: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_PQ_SECURITY_BITS,
            pq_signature_scheme: MONERO_PRIVATE_LIGHT_WALLET_RELAY_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: MONERO_PRIVATE_LIGHT_WALLET_RELAY_PQ_KEM_SCHEME.to_string(),
            filter_scheme: MONERO_PRIVATE_LIGHT_WALLET_RELAY_FILTER_SCHEME.to_string(),
            delta_encryption: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DELTA_ENCRYPTION.to_string(),
        }
    }
}

impl RelayParameters {
    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.network, "relay network")?;
        ensure_non_empty(&self.asset_id, "relay asset id")?;
        ensure_non_empty(&self.fee_asset_id, "relay fee asset id")?;
        ensure_non_empty(&self.pq_signature_scheme, "relay pq signature scheme")?;
        ensure_non_empty(&self.pq_kem_scheme, "relay pq kem scheme")?;
        ensure_non_empty(&self.filter_scheme, "relay filter scheme")?;
        ensure_non_empty(&self.delta_encryption, "relay delta encryption")?;
        if self.view_tag_bits == 0 || self.view_tag_bits > 16 {
            return Err("relay view tag bits must be in 1..=16".to_string());
        }
        if self.filter_bits < 256 {
            return Err("relay compact filter must have at least 256 bits".to_string());
        }
        if self.finality_depth == 0 {
            return Err("relay finality depth must be positive".to_string());
        }
        if self.reorg_window_blocks < self.finality_depth {
            return Err("relay reorg window must cover finality depth".to_string());
        }
        if self.checkpoint_interval_blocks == 0 || self.epoch_blocks == 0 {
            return Err("relay checkpoint and epoch intervals must be positive".to_string());
        }
        if self.max_tags_per_request == 0
            || self.max_filters_per_client == 0
            || self.max_requests_per_epoch == 0
            || self.max_deltas_per_epoch == 0
            || self.max_exit_hints_per_epoch == 0
        {
            return Err("relay rate limit ceilings must be positive".to_string());
        }
        if self.min_scanner_weight == 0 {
            return Err("relay scanner quorum weight must be positive".to_string());
        }
        if self.pq_security_bits < 128 {
            return Err("relay pq security bits must be at least 128".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_parameters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PRIVATE_LIGHT_WALLET_RELAY_PROTOCOL_VERSION,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "view_tag_bits": self.view_tag_bits,
            "filter_bits": self.filter_bits,
            "finality_depth": self.finality_depth,
            "reorg_window_blocks": self.reorg_window_blocks,
            "checkpoint_interval_blocks": self.checkpoint_interval_blocks,
            "epoch_blocks": self.epoch_blocks,
            "client_ttl_blocks": self.client_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "delta_ttl_blocks": self.delta_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "low_fee_scan_unit_price": self.low_fee_scan_unit_price,
            "max_tags_per_request": self.max_tags_per_request,
            "max_filters_per_client": self.max_filters_per_client,
            "max_requests_per_epoch": self.max_requests_per_epoch,
            "max_deltas_per_epoch": self.max_deltas_per_epoch,
            "max_exit_hints_per_epoch": self.max_exit_hints_per_epoch,
            "min_scanner_weight": self.min_scanner_weight,
            "pq_security_bits": self.pq_security_bits,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "filter_scheme": self.filter_scheme,
            "delta_encryption": self.delta_encryption,
        })
    }

    pub fn parameters_root(&self) -> String {
        relay_payload_root(
            "MONERO-PRIVATE-LIGHT-WALLET-RELAY-PARAMETERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthEnvelope {
    pub auth_id: String,
    pub subject_id: String,
    pub scheme: String,
    pub public_key_commitment: String,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub security_bits: u16,
}

impl PqAuthEnvelope {
    pub fn new(
        subject_id: &str,
        public_key_label: &str,
        transcript_label: &str,
        signature_label: &str,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(subject_id, "pq auth subject id")?;
        ensure_non_empty(public_key_label, "pq auth public key label")?;
        ensure_non_empty(transcript_label, "pq auth transcript label")?;
        ensure_non_empty(signature_label, "pq auth signature label")?;
        if ttl_blocks == 0 {
            return Err("pq auth ttl must be positive".to_string());
        }
        let public_key_commitment = relay_string_root("PQ-AUTH-PUBLIC-KEY", public_key_label);
        let transcript_hash = relay_string_root("PQ-AUTH-TRANSCRIPT", transcript_label);
        let signature_commitment = relay_string_root("PQ-AUTH-SIGNATURE", signature_label);
        let auth_id = relay_id(
            "PQ-AUTH-ID",
            &json!({
                "subject_id": subject_id,
                "public_key_commitment": public_key_commitment,
                "transcript_hash": transcript_hash,
                "issued_at_height": issued_at_height,
            }),
        );
        Ok(Self {
            auth_id,
            subject_id: subject_id.to_string(),
            scheme: MONERO_PRIVATE_LIGHT_WALLET_RELAY_PQ_SIGNATURE_SCHEME.to_string(),
            public_key_commitment,
            transcript_hash,
            signature_commitment,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
            security_bits: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_PQ_SECURITY_BITS,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height >= self.issued_at_height && height <= self.expires_at_height
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.auth_id, "pq auth id")?;
        ensure_non_empty(&self.subject_id, "pq auth subject")?;
        ensure_non_empty(&self.scheme, "pq auth scheme")?;
        ensure_non_empty(&self.public_key_commitment, "pq auth public key commitment")?;
        ensure_non_empty(&self.transcript_hash, "pq auth transcript hash")?;
        ensure_non_empty(&self.signature_commitment, "pq auth signature commitment")?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("pq auth expiry must be after issue height".to_string());
        }
        if self.security_bits < 128 {
            return Err("pq auth security bits must be at least 128".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_auth_envelope",
            "auth_id": self.auth_id,
            "subject_id": self.subject_id,
            "scheme": self.scheme,
            "public_key_commitment": self.public_key_commitment,
            "transcript_hash": self.transcript_hash,
            "signature_commitment": self.signature_commitment,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "security_bits": self.security_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayClient {
    pub client_id: String,
    pub owner_commitment: String,
    pub kind: RelayClientKind,
    pub status: RelayClientStatus,
    pub watch_key_commitment: String,
    pub subaddress_account_root: String,
    pub delivery_key_commitment: String,
    pub auth: PqAuthEnvelope,
    pub allowed_scopes: BTreeSet<FilterScope>,
    pub created_at_height: u64,
    pub last_seen_height: u64,
    pub expires_at_height: u64,
    pub request_count: u64,
    pub delta_count: u64,
    pub filter_count: u64,
}

impl RelayClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        kind: RelayClientKind,
        watch_key_label: &str,
        subaddress_labels: &[String],
        delivery_key_label: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(owner_label, "relay client owner label")?;
        ensure_non_empty(watch_key_label, "relay client watch key label")?;
        ensure_non_empty(delivery_key_label, "relay client delivery key label")?;
        if ttl_blocks == 0 {
            return Err("relay client ttl must be positive".to_string());
        }
        let owner_commitment = relay_string_root("RELAY-CLIENT-OWNER", owner_label);
        let watch_key_commitment = relay_string_root("RELAY-CLIENT-WATCH-KEY", watch_key_label);
        let delivery_key_commitment =
            relay_string_root("RELAY-CLIENT-DELIVERY-KEY", delivery_key_label);
        let subaddress_account_root = relay_string_set_root(
            "RELAY-CLIENT-SUBADDRESS-ACCOUNT",
            subaddress_labels
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let client_id = relay_id(
            "RELAY-CLIENT-ID",
            &json!({
                "owner_commitment": owner_commitment,
                "kind": kind.as_str(),
                "watch_key_commitment": watch_key_commitment,
                "subaddress_account_root": subaddress_account_root,
            }),
        );
        let auth = PqAuthEnvelope::new(
            &client_id,
            delivery_key_label,
            "watch-only-client-enrollment",
            owner_label,
            created_at_height,
            ttl_blocks,
        )?;
        let allowed_scopes = [
            FilterScope::ViewTagBucket,
            FilterScope::SubaddressRoute,
            FilterScope::BridgeDeposit,
            FilterScope::BridgeExit,
        ]
        .into_iter()
        .collect();
        Ok(Self {
            client_id,
            owner_commitment,
            kind,
            status: RelayClientStatus::Active,
            watch_key_commitment,
            subaddress_account_root,
            delivery_key_commitment,
            auth,
            allowed_scopes,
            created_at_height,
            last_seen_height: created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            request_count: 0,
            delta_count: 0,
            filter_count: 0,
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.client_id, "relay client id")?;
        ensure_non_empty(&self.owner_commitment, "relay client owner commitment")?;
        ensure_non_empty(
            &self.watch_key_commitment,
            "relay client watch key commitment",
        )?;
        ensure_non_empty(
            &self.subaddress_account_root,
            "relay client subaddress account root",
        )?;
        ensure_non_empty(
            &self.delivery_key_commitment,
            "relay client delivery key commitment",
        )?;
        self.auth.validate()?;
        if self.auth.subject_id != self.client_id {
            return Err("relay client pq auth subject mismatch".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("relay client expiry must be after creation".to_string());
        }
        if self.last_seen_height < self.created_at_height {
            return Err("relay client last seen cannot precede creation".to_string());
        }
        if self.allowed_scopes.is_empty() {
            return Err("relay client must have at least one allowed scope".to_string());
        }
        Ok(())
    }

    pub fn can_request_at(&self, height: u64) -> bool {
        self.status.can_request()
            && height <= self.expires_at_height
            && self.auth.is_live_at(height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_client",
            "client_id": self.client_id,
            "owner_commitment": self.owner_commitment,
            "client_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "watch_key_commitment": self.watch_key_commitment,
            "subaddress_account_root": self.subaddress_account_root,
            "delivery_key_commitment": self.delivery_key_commitment,
            "auth": self.auth.public_record(),
            "allowed_scopes": self.allowed_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "created_at_height": self.created_at_height,
            "last_seen_height": self.last_seen_height,
            "expires_at_height": self.expires_at_height,
            "request_count": self.request_count,
            "delta_count": self.delta_count,
            "filter_count": self.filter_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerNode {
    pub scanner_id: String,
    pub operator_commitment: String,
    pub roles: BTreeSet<RelayScannerRole>,
    pub auth: PqAuthEnvelope,
    pub stake_commitment: String,
    pub weight: u64,
    pub served_requests: u64,
    pub failed_requests: u64,
    pub last_heartbeat_height: u64,
    pub suspended: bool,
}

impl ScannerNode {
    pub fn new(
        operator_label: &str,
        roles: BTreeSet<RelayScannerRole>,
        stake_label: &str,
        weight: u64,
        height: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(operator_label, "scanner operator label")?;
        ensure_non_empty(stake_label, "scanner stake label")?;
        if roles.is_empty() {
            return Err("scanner must advertise at least one role".to_string());
        }
        if weight == 0 {
            return Err("scanner weight must be positive".to_string());
        }
        let operator_commitment = relay_string_root("SCANNER-OPERATOR", operator_label);
        let stake_commitment = relay_string_root("SCANNER-STAKE", stake_label);
        let scanner_id = relay_id(
            "SCANNER-ID",
            &json!({
                "operator_commitment": operator_commitment,
                "roles": roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
                "stake_commitment": stake_commitment,
            }),
        );
        let auth = PqAuthEnvelope::new(
            &scanner_id,
            operator_label,
            "relay-scanner-enrollment",
            stake_label,
            height,
            MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CLIENT_TTL_BLOCKS,
        )?;
        Ok(Self {
            scanner_id,
            operator_commitment,
            roles,
            auth,
            stake_commitment,
            weight,
            served_requests: 0,
            failed_requests: 0,
            last_heartbeat_height: height,
            suspended: false,
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.scanner_id, "scanner id")?;
        ensure_non_empty(&self.operator_commitment, "scanner operator commitment")?;
        ensure_non_empty(&self.stake_commitment, "scanner stake commitment")?;
        if self.roles.is_empty() {
            return Err("scanner roles cannot be empty".to_string());
        }
        if self.weight == 0 {
            return Err("scanner weight must be positive".to_string());
        }
        self.auth.validate()?;
        if self.auth.subject_id != self.scanner_id {
            return Err("scanner pq auth subject mismatch".to_string());
        }
        Ok(())
    }

    pub fn has_role(&self, role: RelayScannerRole) -> bool {
        self.roles.contains(&role) && !self.suspended
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "scanner_node",
            "scanner_id": self.scanner_id,
            "operator_commitment": self.operator_commitment,
            "roles": self.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "auth": self.auth.public_record(),
            "stake_commitment": self.stake_commitment,
            "weight": self.weight,
            "served_requests": self.served_requests,
            "failed_requests": self.failed_requests,
            "last_heartbeat_height": self.last_heartbeat_height,
            "suspended": self.suspended,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagObservation {
    pub observation_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub tx_hash: String,
    pub output_index: u32,
    pub view_tag: u16,
    pub encrypted_amount_bucket: String,
    pub stealth_key_commitment: String,
    pub subaddress_hint_commitment: String,
    pub scanner_id: String,
    pub observed_at_height: u64,
}

impl ViewTagObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_height: u64,
        block_hash: &str,
        tx_hash: &str,
        output_index: u32,
        view_tag: u16,
        amount_bucket_label: &str,
        stealth_key_label: &str,
        subaddress_hint_label: &str,
        scanner_id: &str,
        observed_at_height: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(block_hash, "view tag block hash")?;
        ensure_non_empty(tx_hash, "view tag tx hash")?;
        ensure_non_empty(amount_bucket_label, "view tag amount bucket")?;
        ensure_non_empty(stealth_key_label, "view tag stealth key")?;
        ensure_non_empty(subaddress_hint_label, "view tag subaddress hint")?;
        ensure_non_empty(scanner_id, "view tag scanner id")?;
        let encrypted_amount_bucket =
            relay_string_root("VIEW-TAG-AMOUNT-BUCKET", amount_bucket_label);
        let stealth_key_commitment = relay_string_root("VIEW-TAG-STEALTH-KEY", stealth_key_label);
        let subaddress_hint_commitment =
            relay_string_root("VIEW-TAG-SUBADDRESS-HINT", subaddress_hint_label);
        let observation_id = relay_id(
            "VIEW-TAG-OBSERVATION-ID",
            &json!({
                "block_height": block_height,
                "block_hash": block_hash,
                "tx_hash": tx_hash,
                "output_index": output_index,
                "view_tag": view_tag,
                "stealth_key_commitment": stealth_key_commitment,
            }),
        );
        Ok(Self {
            observation_id,
            block_height,
            block_hash: block_hash.to_string(),
            tx_hash: tx_hash.to_string(),
            output_index,
            view_tag,
            encrypted_amount_bucket,
            stealth_key_commitment,
            subaddress_hint_commitment,
            scanner_id: scanner_id.to_string(),
            observed_at_height,
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.observation_id, "view tag observation id")?;
        ensure_non_empty(&self.block_hash, "view tag block hash")?;
        ensure_non_empty(&self.tx_hash, "view tag tx hash")?;
        ensure_non_empty(
            &self.encrypted_amount_bucket,
            "view tag encrypted amount bucket",
        )?;
        ensure_non_empty(
            &self.stealth_key_commitment,
            "view tag stealth key commitment",
        )?;
        ensure_non_empty(
            &self.subaddress_hint_commitment,
            "view tag subaddress hint commitment",
        )?;
        ensure_non_empty(&self.scanner_id, "view tag scanner id")?;
        if self.view_tag >= (1_u16 << MONERO_PRIVATE_LIGHT_WALLET_RELAY_VIEW_TAG_BITS) {
            return Err("view tag exceeds configured tag space".to_string());
        }
        if self.observed_at_height < self.block_height {
            return Err("view tag observation cannot precede source block".to_string());
        }
        Ok(())
    }

    pub fn route_key(&self) -> String {
        relay_id(
            "VIEW-TAG-ROUTE-KEY",
            &json!({
                "view_tag": self.view_tag,
                "subaddress_hint_commitment": self.subaddress_hint_commitment,
            }),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_tag_observation",
            "observation_id": self.observation_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "tx_hash": self.tx_hash,
            "output_index": self.output_index,
            "view_tag": self.view_tag,
            "encrypted_amount_bucket": self.encrypted_amount_bucket,
            "stealth_key_commitment": self.stealth_key_commitment,
            "subaddress_hint_commitment": self.subaddress_hint_commitment,
            "scanner_id": self.scanner_id,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressRoute {
    pub route_id: String,
    pub client_id: String,
    pub account_index_commitment: String,
    pub subaddress_index_commitment: String,
    pub route_key: String,
    pub view_tag_set_root: String,
    pub spend_authority_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

impl SubaddressRoute {
    pub fn new(
        client_id: &str,
        account_label: &str,
        subaddress_label: &str,
        view_tags: &[u16],
        spend_authority_label: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(client_id, "subaddress route client id")?;
        ensure_non_empty(account_label, "subaddress account label")?;
        ensure_non_empty(subaddress_label, "subaddress label")?;
        ensure_non_empty(spend_authority_label, "subaddress spend authority")?;
        if view_tags.is_empty() {
            return Err("subaddress route needs at least one view tag".to_string());
        }
        if ttl_blocks == 0 {
            return Err("subaddress route ttl must be positive".to_string());
        }
        let account_index_commitment = relay_string_root("SUBADDRESS-ACCOUNT", account_label);
        let subaddress_index_commitment = relay_string_root("SUBADDRESS-INDEX", subaddress_label);
        let view_tag_set_root = relay_u16_set_root("SUBADDRESS-VIEW-TAGS", view_tags);
        let spend_authority_commitment =
            relay_string_root("SUBADDRESS-SPEND-AUTHORITY", spend_authority_label);
        let route_key = relay_id(
            "SUBADDRESS-ROUTE-KEY",
            &json!({
                "client_id": client_id,
                "account_index_commitment": account_index_commitment,
                "subaddress_index_commitment": subaddress_index_commitment,
                "view_tag_set_root": view_tag_set_root,
            }),
        );
        let route_id = relay_id(
            "SUBADDRESS-ROUTE-ID",
            &json!({
                "client_id": client_id,
                "route_key": route_key,
                "created_at_height": created_at_height,
            }),
        );
        Ok(Self {
            route_id,
            client_id: client_id.to_string(),
            account_index_commitment,
            subaddress_index_commitment,
            route_key,
            view_tag_set_root,
            spend_authority_commitment,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            active: true,
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.route_id, "subaddress route id")?;
        ensure_non_empty(&self.client_id, "subaddress route client id")?;
        ensure_non_empty(
            &self.account_index_commitment,
            "subaddress account index commitment",
        )?;
        ensure_non_empty(
            &self.subaddress_index_commitment,
            "subaddress index commitment",
        )?;
        ensure_non_empty(&self.route_key, "subaddress route key")?;
        ensure_non_empty(&self.view_tag_set_root, "subaddress route view tag root")?;
        ensure_non_empty(
            &self.spend_authority_commitment,
            "subaddress spend authority commitment",
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("subaddress route expiry must be after creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "subaddress_route",
            "route_id": self.route_id,
            "client_id": self.client_id,
            "account_index_commitment": self.account_index_commitment,
            "subaddress_index_commitment": self.subaddress_index_commitment,
            "route_key": self.route_key,
            "view_tag_set_root": self.view_tag_set_root,
            "spend_authority_commitment": self.spend_authority_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactFilter {
    pub filter_id: String,
    pub scope: FilterScope,
    pub client_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub view_tag_root: String,
    pub output_commitment_root: String,
    pub filter_commitment: String,
    pub false_positive_rate_bps: u64,
    pub built_by: BTreeSet<String>,
    pub built_at_height: u64,
}

impl CompactFilter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: FilterScope,
        client_id: &str,
        start_height: u64,
        end_height: u64,
        view_tags: &[u16],
        output_commitments: &[String],
        builders: BTreeSet<String>,
        built_at_height: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(client_id, "compact filter client id")?;
        if end_height < start_height {
            return Err("compact filter end height cannot precede start height".to_string());
        }
        if builders.is_empty() {
            return Err("compact filter needs at least one builder".to_string());
        }
        let view_tag_root = relay_u16_set_root("COMPACT-FILTER-VIEW-TAGS", view_tags);
        let output_commitment_root = relay_string_set_root(
            "COMPACT-FILTER-OUTPUTS",
            output_commitments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let filter_commitment = relay_id(
            "COMPACT-FILTER-BITSET",
            &json!({
                "scope": scope.as_str(),
                "client_id": client_id,
                "start_height": start_height,
                "end_height": end_height,
                "view_tag_root": view_tag_root,
                "output_commitment_root": output_commitment_root,
            }),
        );
        let filter_id = relay_id(
            "COMPACT-FILTER-ID",
            &json!({
                "scope": scope.as_str(),
                "client_id": client_id,
                "filter_commitment": filter_commitment,
                "built_at_height": built_at_height,
            }),
        );
        Ok(Self {
            filter_id,
            scope,
            client_id: client_id.to_string(),
            start_height,
            end_height,
            view_tag_root,
            output_commitment_root,
            filter_commitment,
            false_positive_rate_bps: 50,
            built_by: builders,
            built_at_height,
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.filter_id, "compact filter id")?;
        ensure_non_empty(&self.client_id, "compact filter client id")?;
        ensure_non_empty(&self.view_tag_root, "compact filter view tag root")?;
        ensure_non_empty(
            &self.output_commitment_root,
            "compact filter output commitment root",
        )?;
        ensure_non_empty(&self.filter_commitment, "compact filter commitment")?;
        if self.end_height < self.start_height {
            return Err("compact filter end height cannot precede start height".to_string());
        }
        if self.false_positive_rate_bps > 10_000 {
            return Err("compact filter false positive rate exceeds 100%".to_string());
        }
        if self.built_by.is_empty() {
            return Err("compact filter builders cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compact_filter",
            "filter_id": self.filter_id,
            "scope": self.scope.as_str(),
            "client_id": self.client_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "view_tag_root": self.view_tag_root,
            "output_commitment_root": self.output_commitment_root,
            "filter_commitment": self.filter_commitment,
            "false_positive_rate_bps": self.false_positive_rate_bps,
            "built_by": self.built_by.iter().cloned().collect::<Vec<_>>(),
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub client_id: String,
    pub status: SponsorshipStatus,
    pub scan_unit_budget: u64,
    pub scan_unit_price: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub privacy_pool_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ScanSponsorship {
    pub fn new(
        sponsor_id: &str,
        client_id: &str,
        scan_unit_budget: u64,
        scan_unit_price: u64,
        privacy_pool_label: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(sponsor_id, "scan sponsorship sponsor id")?;
        ensure_non_empty(client_id, "scan sponsorship client id")?;
        ensure_non_empty(privacy_pool_label, "scan sponsorship privacy pool")?;
        if scan_unit_budget == 0 || scan_unit_price == 0 {
            return Err("scan sponsorship budget and price must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("scan sponsorship ttl must be positive".to_string());
        }
        let privacy_pool_commitment =
            relay_string_root("SCAN-SPONSORSHIP-PRIVACY-POOL", privacy_pool_label);
        let sponsorship_id = relay_id(
            "SCAN-SPONSORSHIP-ID",
            &json!({
                "sponsor_id": sponsor_id,
                "client_id": client_id,
                "privacy_pool_commitment": privacy_pool_commitment,
                "created_at_height": created_at_height,
            }),
        );
        Ok(Self {
            sponsorship_id,
            sponsor_id: sponsor_id.to_string(),
            client_id: client_id.to_string(),
            status: SponsorshipStatus::Offered,
            scan_unit_budget,
            scan_unit_price,
            reserved_units: 0,
            consumed_units: 0,
            privacy_pool_commitment,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn reserve(&mut self, units: u64) -> MoneroPrivateLightWalletRelayResult<()> {
        if !self.status.is_spendable() {
            return Err("scan sponsorship is not spendable".to_string());
        }
        if self.available_units() < units {
            return Err("scan sponsorship has insufficient units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.status = SponsorshipStatus::Reserved;
        Ok(())
    }

    pub fn consume(&mut self, units: u64) -> MoneroPrivateLightWalletRelayResult<()> {
        if self.reserved_units < units {
            return Err("cannot consume more scan units than reserved".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.consumed_units = self.consumed_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = SponsorshipStatus::Consumed;
        }
        Ok(())
    }

    pub fn available_units(&self) -> u64 {
        self.scan_unit_budget
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.sponsorship_id, "scan sponsorship id")?;
        ensure_non_empty(&self.sponsor_id, "scan sponsorship sponsor id")?;
        ensure_non_empty(&self.client_id, "scan sponsorship client id")?;
        ensure_non_empty(
            &self.privacy_pool_commitment,
            "scan sponsorship privacy pool commitment",
        )?;
        if self.scan_unit_budget == 0 || self.scan_unit_price == 0 {
            return Err("scan sponsorship budget and price must be positive".to_string());
        }
        if self.reserved_units.saturating_add(self.consumed_units) > self.scan_unit_budget {
            return Err("scan sponsorship over-reserved budget".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("scan sponsorship expiry must be after creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "scan_sponsorship",
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "client_id": self.client_id,
            "status": self.status.as_str(),
            "scan_unit_budget": self.scan_unit_budget,
            "scan_unit_price": self.scan_unit_price,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "privacy_pool_commitment": self.privacy_pool_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub request_id: String,
    pub client_id: String,
    pub status: ScanRequestStatus,
    pub requested_scopes: BTreeSet<FilterScope>,
    pub view_tag_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub max_scan_units: u64,
    pub sponsorship_id: Option<String>,
    pub assigned_scanner_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ScanRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: &str,
        requested_scopes: BTreeSet<FilterScope>,
        view_tags: &[u16],
        start_height: u64,
        end_height: u64,
        max_scan_units: u64,
        sponsorship_id: Option<String>,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(client_id, "scan request client id")?;
        if requested_scopes.is_empty() {
            return Err("scan request must include at least one scope".to_string());
        }
        if view_tags.is_empty() {
            return Err("scan request must include at least one view tag".to_string());
        }
        if end_height < start_height {
            return Err("scan request end height cannot precede start".to_string());
        }
        if max_scan_units == 0 {
            return Err("scan request unit cap must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("scan request ttl must be positive".to_string());
        }
        let view_tag_root = relay_u16_set_root("SCAN-REQUEST-VIEW-TAGS", view_tags);
        let request_id = relay_id(
            "SCAN-REQUEST-ID",
            &json!({
                "client_id": client_id,
                "scopes": requested_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
                "view_tag_root": view_tag_root,
                "start_height": start_height,
                "end_height": end_height,
                "created_at_height": created_at_height,
            }),
        );
        Ok(Self {
            request_id,
            client_id: client_id.to_string(),
            status: if sponsorship_id.is_some() {
                ScanRequestStatus::Sponsored
            } else {
                ScanRequestStatus::Queued
            },
            requested_scopes,
            view_tag_root,
            start_height,
            end_height,
            max_scan_units,
            sponsorship_id,
            assigned_scanner_id: None,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn assign(&mut self, scanner_id: &str) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(scanner_id, "scan request scanner id")?;
        if !self.status.is_open() {
            return Err("scan request is not open".to_string());
        }
        self.assigned_scanner_id = Some(scanner_id.to_string());
        self.status = ScanRequestStatus::Leased;
        Ok(())
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.request_id, "scan request id")?;
        ensure_non_empty(&self.client_id, "scan request client id")?;
        ensure_non_empty(&self.view_tag_root, "scan request view tag root")?;
        if self.requested_scopes.is_empty() {
            return Err("scan request scopes cannot be empty".to_string());
        }
        if self.end_height < self.start_height {
            return Err("scan request end height cannot precede start".to_string());
        }
        if self.max_scan_units == 0 {
            return Err("scan request max scan units must be positive".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("scan request expiry must be after creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "scan_request",
            "request_id": self.request_id,
            "client_id": self.client_id,
            "status": self.status.as_str(),
            "requested_scopes": self.requested_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "view_tag_root": self.view_tag_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "max_scan_units": self.max_scan_units,
            "sponsorship_id": self.sponsorship_id,
            "assigned_scanner_id": self.assigned_scanner_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedWalletDelta {
    pub delta_id: String,
    pub client_id: String,
    pub request_id: String,
    pub checkpoint_id: String,
    pub filter_root: String,
    pub matched_output_root: String,
    pub nullifier_hint_root: String,
    pub bridge_exit_hint_root: String,
    pub envelope_commitment: String,
    pub encryption_scheme: String,
    pub status: WalletDeltaStatus,
    pub sequence: u64,
    pub prepared_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedWalletDelta {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: &str,
        request_id: &str,
        checkpoint_id: &str,
        filters: &[String],
        matched_outputs: &[String],
        nullifier_hints: &[String],
        bridge_exit_hints: &[String],
        envelope_label: &str,
        sequence: u64,
        prepared_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(client_id, "wallet delta client id")?;
        ensure_non_empty(request_id, "wallet delta request id")?;
        ensure_non_empty(checkpoint_id, "wallet delta checkpoint id")?;
        ensure_non_empty(envelope_label, "wallet delta envelope")?;
        if ttl_blocks == 0 {
            return Err("wallet delta ttl must be positive".to_string());
        }
        let filter_root = relay_string_set_root(
            "WALLET-DELTA-FILTER",
            filters
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let matched_output_root = relay_string_set_root(
            "WALLET-DELTA-MATCHED-OUTPUT",
            matched_outputs
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let nullifier_hint_root = relay_string_set_root(
            "WALLET-DELTA-NULLIFIER-HINT",
            nullifier_hints
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let bridge_exit_hint_root = relay_string_set_root(
            "WALLET-DELTA-BRIDGE-EXIT-HINT",
            bridge_exit_hints
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let envelope_commitment = relay_string_root("WALLET-DELTA-ENVELOPE", envelope_label);
        let delta_id = relay_id(
            "WALLET-DELTA-ID",
            &json!({
                "client_id": client_id,
                "request_id": request_id,
                "checkpoint_id": checkpoint_id,
                "sequence": sequence,
                "envelope_commitment": envelope_commitment,
            }),
        );
        Ok(Self {
            delta_id,
            client_id: client_id.to_string(),
            request_id: request_id.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
            filter_root,
            matched_output_root,
            nullifier_hint_root,
            bridge_exit_hint_root,
            envelope_commitment,
            encryption_scheme: MONERO_PRIVATE_LIGHT_WALLET_RELAY_DELTA_ENCRYPTION.to_string(),
            status: WalletDeltaStatus::Prepared,
            sequence,
            prepared_at_height,
            expires_at_height: prepared_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.delta_id, "wallet delta id")?;
        ensure_non_empty(&self.client_id, "wallet delta client id")?;
        ensure_non_empty(&self.request_id, "wallet delta request id")?;
        ensure_non_empty(&self.checkpoint_id, "wallet delta checkpoint id")?;
        ensure_non_empty(&self.filter_root, "wallet delta filter root")?;
        ensure_non_empty(
            &self.matched_output_root,
            "wallet delta matched output root",
        )?;
        ensure_non_empty(
            &self.nullifier_hint_root,
            "wallet delta nullifier hint root",
        )?;
        ensure_non_empty(
            &self.bridge_exit_hint_root,
            "wallet delta bridge exit hint root",
        )?;
        ensure_non_empty(
            &self.envelope_commitment,
            "wallet delta envelope commitment",
        )?;
        ensure_non_empty(&self.encryption_scheme, "wallet delta encryption scheme")?;
        if self.expires_at_height <= self.prepared_at_height {
            return Err("wallet delta expiry must be after preparation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_wallet_delta",
            "delta_id": self.delta_id,
            "client_id": self.client_id,
            "request_id": self.request_id,
            "checkpoint_id": self.checkpoint_id,
            "filter_root": self.filter_root,
            "matched_output_root": self.matched_output_root,
            "nullifier_hint_root": self.nullifier_hint_root,
            "bridge_exit_hint_root": self.bridge_exit_hint_root,
            "envelope_commitment": self.envelope_commitment,
            "encryption_scheme": self.encryption_scheme,
            "status": self.status.as_str(),
            "sequence": self.sequence,
            "prepared_at_height": self.prepared_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgSafeCheckpoint {
    pub checkpoint_id: String,
    pub status: CheckpointStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub block_hash_root: String,
    pub observation_root: String,
    pub filter_root: String,
    pub delta_root: String,
    pub receipt_root: String,
    pub parent_checkpoint_id: Option<String>,
    pub sealed_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl ReorgSafeCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        start_height: u64,
        end_height: u64,
        block_hashes: &[String],
        observations: &[String],
        filters: &[String],
        deltas: &[String],
        receipts: &[String],
        parent_checkpoint_id: Option<String>,
        sealed_at_height: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        if end_height < start_height {
            return Err("checkpoint end height cannot precede start".to_string());
        }
        let block_hash_root = relay_string_set_root(
            "CHECKPOINT-BLOCK-HASH",
            block_hashes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let observation_root = relay_string_set_root(
            "CHECKPOINT-OBSERVATION",
            observations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let filter_root = relay_string_set_root(
            "CHECKPOINT-FILTER",
            filters
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let delta_root = relay_string_set_root(
            "CHECKPOINT-DELTA",
            deltas
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let receipt_root = relay_string_set_root(
            "CHECKPOINT-RECEIPT",
            receipts
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let checkpoint_id = relay_id(
            "REORG-SAFE-CHECKPOINT-ID",
            &json!({
                "start_height": start_height,
                "end_height": end_height,
                "block_hash_root": block_hash_root,
                "observation_root": observation_root,
                "parent_checkpoint_id": parent_checkpoint_id,
            }),
        );
        Ok(Self {
            checkpoint_id,
            status: CheckpointStatus::Sealed,
            start_height,
            end_height,
            block_hash_root,
            observation_root,
            filter_root,
            delta_root,
            receipt_root,
            parent_checkpoint_id,
            sealed_at_height,
            finalized_at_height: None,
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.checkpoint_id, "checkpoint id")?;
        ensure_non_empty(&self.block_hash_root, "checkpoint block hash root")?;
        ensure_non_empty(&self.observation_root, "checkpoint observation root")?;
        ensure_non_empty(&self.filter_root, "checkpoint filter root")?;
        ensure_non_empty(&self.delta_root, "checkpoint delta root")?;
        ensure_non_empty(&self.receipt_root, "checkpoint receipt root")?;
        if self.end_height < self.start_height {
            return Err("checkpoint end height cannot precede start".to_string());
        }
        if self.sealed_at_height < self.end_height {
            return Err("checkpoint cannot seal before its end height".to_string());
        }
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.sealed_at_height {
                return Err("checkpoint finality cannot precede seal height".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reorg_safe_checkpoint",
            "checkpoint_id": self.checkpoint_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "block_hash_root": self.block_hash_root,
            "observation_root": self.observation_root,
            "filter_root": self.filter_root,
            "delta_root": self.delta_root,
            "receipt_root": self.receipt_root,
            "parent_checkpoint_id": self.parent_checkpoint_id,
            "sealed_at_height": self.sealed_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRateLimitBucket {
    pub bucket_id: String,
    pub subject_id: String,
    pub epoch: u64,
    pub request_count: u64,
    pub delta_count: u64,
    pub exit_hint_count: u64,
    pub max_requests: u64,
    pub max_deltas: u64,
    pub max_exit_hints: u64,
}

impl RelayRateLimitBucket {
    pub fn new(subject_id: &str, epoch: u64, parameters: &RelayParameters) -> Self {
        let bucket_id = relay_id(
            "RATE-LIMIT-BUCKET-ID",
            &json!({
                "subject_id": subject_id,
                "epoch": epoch,
            }),
        );
        Self {
            bucket_id,
            subject_id: subject_id.to_string(),
            epoch,
            request_count: 0,
            delta_count: 0,
            exit_hint_count: 0,
            max_requests: parameters.max_requests_per_epoch,
            max_deltas: parameters.max_deltas_per_epoch,
            max_exit_hints: parameters.max_exit_hints_per_epoch,
        }
    }

    pub fn charge_request(&mut self) -> MoneroPrivateLightWalletRelayResult<()> {
        if self.request_count >= self.max_requests {
            return Err("relay request rate limit exceeded".to_string());
        }
        self.request_count = self.request_count.saturating_add(1);
        Ok(())
    }

    pub fn charge_delta(&mut self) -> MoneroPrivateLightWalletRelayResult<()> {
        if self.delta_count >= self.max_deltas {
            return Err("relay delta rate limit exceeded".to_string());
        }
        self.delta_count = self.delta_count.saturating_add(1);
        Ok(())
    }

    pub fn charge_exit_hint(&mut self) -> MoneroPrivateLightWalletRelayResult<()> {
        if self.exit_hint_count >= self.max_exit_hints {
            return Err("relay exit hint rate limit exceeded".to_string());
        }
        self.exit_hint_count = self.exit_hint_count.saturating_add(1);
        Ok(())
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.bucket_id, "rate limit bucket id")?;
        ensure_non_empty(&self.subject_id, "rate limit subject id")?;
        if self.request_count > self.max_requests {
            return Err("rate limit request count exceeds max".to_string());
        }
        if self.delta_count > self.max_deltas {
            return Err("rate limit delta count exceeds max".to_string());
        }
        if self.exit_hint_count > self.max_exit_hints {
            return Err("rate limit exit hint count exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_rate_limit_bucket",
            "bucket_id": self.bucket_id,
            "subject_id": self.subject_id,
            "epoch": self.epoch,
            "request_count": self.request_count,
            "delta_count": self.delta_count,
            "exit_hint_count": self.exit_hint_count,
            "max_requests": self.max_requests,
            "max_deltas": self.max_deltas,
            "max_exit_hints": self.max_exit_hints,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayProofReceipt {
    pub receipt_id: String,
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub checkpoint_id: String,
    pub proof_commitment: String,
    pub signer_root: String,
    pub scanner_weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl RelayProofReceipt {
    pub fn new(
        kind: ReceiptKind,
        subject_id: &str,
        checkpoint_id: &str,
        proof_label: &str,
        signers: &BTreeSet<String>,
        scanner_weight: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(subject_id, "receipt subject id")?;
        ensure_non_empty(checkpoint_id, "receipt checkpoint id")?;
        ensure_non_empty(proof_label, "receipt proof label")?;
        if signers.is_empty() {
            return Err("receipt signer set cannot be empty".to_string());
        }
        if scanner_weight == 0 || ttl_blocks == 0 {
            return Err("receipt scanner weight and ttl must be positive".to_string());
        }
        let proof_commitment = relay_string_root("RELAY-RECEIPT-PROOF", proof_label);
        let signer_root = relay_string_set_root(
            "RELAY-RECEIPT-SIGNER",
            signers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let receipt_id = relay_id(
            "RELAY-PROOF-RECEIPT-ID",
            &json!({
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "checkpoint_id": checkpoint_id,
                "proof_commitment": proof_commitment,
                "signer_root": signer_root,
            }),
        );
        Ok(Self {
            receipt_id,
            kind,
            subject_id: subject_id.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
            proof_commitment,
            signer_root,
            scanner_weight,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.subject_id, "receipt subject id")?;
        ensure_non_empty(&self.checkpoint_id, "receipt checkpoint id")?;
        ensure_non_empty(&self.proof_commitment, "receipt proof commitment")?;
        ensure_non_empty(&self.signer_root, "receipt signer root")?;
        if self.scanner_weight == 0 {
            return Err("receipt scanner weight must be positive".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("receipt expiry must be after issue height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_proof_receipt",
            "receipt_id": self.receipt_id,
            "receipt_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "checkpoint_id": self.checkpoint_id,
            "proof_commitment": self.proof_commitment,
            "signer_root": self.signer_root,
            "scanner_weight": self.scanner_weight,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeExitHint {
    pub hint_id: String,
    pub client_id: String,
    pub status: BridgeExitHintStatus,
    pub exit_intent_commitment: String,
    pub subaddress_route_id: String,
    pub amount_bucket_commitment: String,
    pub preferred_unlock_height: u64,
    pub fee_bid_piconero: u64,
    pub bridge_lane_commitment: String,
    pub proof_receipt_id: Option<String>,
    pub created_at_height: u64,
}

impl BridgeExitHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: &str,
        exit_intent_label: &str,
        subaddress_route_id: &str,
        amount_bucket_label: &str,
        preferred_unlock_height: u64,
        fee_bid_piconero: u64,
        bridge_lane_label: &str,
        created_at_height: u64,
    ) -> MoneroPrivateLightWalletRelayResult<Self> {
        ensure_non_empty(client_id, "bridge exit hint client id")?;
        ensure_non_empty(exit_intent_label, "bridge exit intent label")?;
        ensure_non_empty(subaddress_route_id, "bridge exit subaddress route id")?;
        ensure_non_empty(amount_bucket_label, "bridge exit amount bucket")?;
        ensure_non_empty(bridge_lane_label, "bridge exit lane")?;
        if preferred_unlock_height < created_at_height {
            return Err("bridge exit preferred unlock cannot precede creation".to_string());
        }
        let exit_intent_commitment = relay_string_root("BRIDGE-EXIT-INTENT", exit_intent_label);
        let amount_bucket_commitment =
            relay_string_root("BRIDGE-EXIT-AMOUNT-BUCKET", amount_bucket_label);
        let bridge_lane_commitment = relay_string_root("BRIDGE-EXIT-LANE", bridge_lane_label);
        let hint_id = relay_id(
            "BRIDGE-EXIT-HINT-ID",
            &json!({
                "client_id": client_id,
                "exit_intent_commitment": exit_intent_commitment,
                "subaddress_route_id": subaddress_route_id,
                "preferred_unlock_height": preferred_unlock_height,
                "bridge_lane_commitment": bridge_lane_commitment,
            }),
        );
        Ok(Self {
            hint_id,
            client_id: client_id.to_string(),
            status: BridgeExitHintStatus::Proposed,
            exit_intent_commitment,
            subaddress_route_id: subaddress_route_id.to_string(),
            amount_bucket_commitment,
            preferred_unlock_height,
            fee_bid_piconero,
            bridge_lane_commitment,
            proof_receipt_id: None,
            created_at_height,
        })
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<()> {
        ensure_non_empty(&self.hint_id, "bridge exit hint id")?;
        ensure_non_empty(&self.client_id, "bridge exit hint client id")?;
        ensure_non_empty(
            &self.exit_intent_commitment,
            "bridge exit intent commitment",
        )?;
        ensure_non_empty(&self.subaddress_route_id, "bridge exit subaddress route id")?;
        ensure_non_empty(
            &self.amount_bucket_commitment,
            "bridge exit amount bucket commitment",
        )?;
        ensure_non_empty(&self.bridge_lane_commitment, "bridge exit lane commitment")?;
        if self.preferred_unlock_height < self.created_at_height {
            return Err("bridge exit preferred unlock cannot precede creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_exit_hint",
            "hint_id": self.hint_id,
            "client_id": self.client_id,
            "status": self.status.as_str(),
            "exit_intent_commitment": self.exit_intent_commitment,
            "subaddress_route_id": self.subaddress_route_id,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "preferred_unlock_height": self.preferred_unlock_height,
            "fee_bid_piconero": self.fee_bid_piconero,
            "bridge_lane_commitment": self.bridge_lane_commitment,
            "proof_receipt_id": self.proof_receipt_id,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCounters {
    pub clients: u64,
    pub scanners: u64,
    pub subaddress_routes: u64,
    pub observations: u64,
    pub filters: u64,
    pub sponsorships: u64,
    pub scan_requests: u64,
    pub wallet_deltas: u64,
    pub checkpoints: u64,
    pub rate_limit_buckets: u64,
    pub proof_receipts: u64,
    pub bridge_exit_hints: u64,
    pub active_clients: u64,
    pub open_requests: u64,
    pub live_deltas: u64,
    pub finalized_checkpoints: u64,
}

impl RelayCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_counters",
            "clients": self.clients,
            "scanners": self.scanners,
            "subaddress_routes": self.subaddress_routes,
            "observations": self.observations,
            "filters": self.filters,
            "sponsorships": self.sponsorships,
            "scan_requests": self.scan_requests,
            "wallet_deltas": self.wallet_deltas,
            "checkpoints": self.checkpoints,
            "rate_limit_buckets": self.rate_limit_buckets,
            "proof_receipts": self.proof_receipts,
            "bridge_exit_hints": self.bridge_exit_hints,
            "active_clients": self.active_clients,
            "open_requests": self.open_requests,
            "live_deltas": self.live_deltas,
            "finalized_checkpoints": self.finalized_checkpoints,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRoots {
    pub parameters_root: String,
    pub client_root: String,
    pub scanner_root: String,
    pub subaddress_route_root: String,
    pub observation_root: String,
    pub compact_filter_root: String,
    pub sponsorship_root: String,
    pub scan_request_root: String,
    pub wallet_delta_root: String,
    pub checkpoint_root: String,
    pub rate_limit_root: String,
    pub proof_receipt_root: String,
    pub bridge_exit_hint_root: String,
    pub counters_root: String,
}

impl RelayRoots {
    pub fn state_root(&self) -> String {
        relay_payload_root(
            "MONERO-PRIVATE-LIGHT-WALLET-RELAY-ROOTS",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_roots",
            "parameters_root": self.parameters_root,
            "client_root": self.client_root,
            "scanner_root": self.scanner_root,
            "subaddress_route_root": self.subaddress_route_root,
            "observation_root": self.observation_root,
            "compact_filter_root": self.compact_filter_root,
            "sponsorship_root": self.sponsorship_root,
            "scan_request_root": self.scan_request_root,
            "wallet_delta_root": self.wallet_delta_root,
            "checkpoint_root": self.checkpoint_root,
            "rate_limit_root": self.rate_limit_root,
            "proof_receipt_root": self.proof_receipt_root,
            "bridge_exit_hint_root": self.bridge_exit_hint_root,
            "counters_root": self.counters_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPrivateLightWalletRelayState {
    pub parameters: RelayParameters,
    pub current_height: u64,
    pub clients: BTreeMap<String, RelayClient>,
    pub scanners: BTreeMap<String, ScannerNode>,
    pub subaddress_routes: BTreeMap<String, SubaddressRoute>,
    pub observations: BTreeMap<String, ViewTagObservation>,
    pub compact_filters: BTreeMap<String, CompactFilter>,
    pub sponsorships: BTreeMap<String, ScanSponsorship>,
    pub scan_requests: BTreeMap<String, ScanRequest>,
    pub wallet_deltas: BTreeMap<String, EncryptedWalletDelta>,
    pub checkpoints: BTreeMap<String, ReorgSafeCheckpoint>,
    pub rate_limits: BTreeMap<String, RelayRateLimitBucket>,
    pub proof_receipts: BTreeMap<String, RelayProofReceipt>,
    pub bridge_exit_hints: BTreeMap<String, BridgeExitHint>,
    pub view_tag_index: BTreeMap<u16, BTreeSet<String>>,
    pub client_routes: BTreeMap<String, BTreeSet<String>>,
    pub client_requests: BTreeMap<String, BTreeSet<String>>,
    pub client_deltas: BTreeMap<String, BTreeSet<String>>,
}

impl Default for MoneroPrivateLightWalletRelayState {
    fn default() -> Self {
        Self {
            parameters: RelayParameters::default(),
            current_height: 0,
            clients: BTreeMap::new(),
            scanners: BTreeMap::new(),
            subaddress_routes: BTreeMap::new(),
            observations: BTreeMap::new(),
            compact_filters: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            scan_requests: BTreeMap::new(),
            wallet_deltas: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            rate_limits: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            bridge_exit_hints: BTreeMap::new(),
            view_tag_index: BTreeMap::new(),
            client_routes: BTreeMap::new(),
            client_requests: BTreeMap::new(),
            client_deltas: BTreeMap::new(),
        }
    }
}

impl MoneroPrivateLightWalletRelayState {
    pub fn new(parameters: RelayParameters, current_height: u64) -> Self {
        Self {
            parameters,
            current_height,
            ..Self::default()
        }
    }

    pub fn set_height(&mut self, height: u64) -> MoneroPrivateLightWalletRelayResult<()> {
        if height < self.current_height {
            return Err(format!(
                "monero private light wallet relay height cannot move backward from {} to {}",
                self.current_height, height
            ));
        }
        self.current_height = height;
        Ok(())
    }

    pub fn devnet() -> MoneroPrivateLightWalletRelayResult<Self> {
        let parameters = RelayParameters::default();
        parameters.validate()?;
        let mut state = Self::new(parameters, 240);

        let client = RelayClient::new(
            "devnet-watch-only-wallet",
            RelayClientKind::WatchOnlyWallet,
            "devnet-primary-view-key",
            &["account-0".to_string(), "account-1".to_string()],
            "devnet-wallet-delivery-key",
            200,
            MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CLIENT_TTL_BLOCKS,
        )?;
        let client_id = client.client_id.clone();
        state.register_client(client)?;

        let sponsor = RelayClient::new(
            "devnet-scan-sponsor",
            RelayClientKind::Sponsor,
            "devnet-sponsor-watch-key",
            &["sponsor-account".to_string()],
            "devnet-sponsor-delivery-key",
            201,
            MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CLIENT_TTL_BLOCKS,
        )?;
        let sponsor_id = sponsor.client_id.clone();
        state.register_client(sponsor)?;

        let scanner_roles = [
            RelayScannerRole::ViewTagScanner,
            RelayScannerRole::SubaddressRouter,
            RelayScannerRole::FilterBuilder,
            RelayScannerRole::ReceiptSigner,
            RelayScannerRole::BridgeWatcher,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let scanner = ScannerNode::new(
            "devnet-relay-scanner-a",
            scanner_roles,
            "scanner-stake-a",
            3,
            202,
        )?;
        let scanner_id = scanner.scanner_id.clone();
        state.register_scanner(scanner)?;

        let route = SubaddressRoute::new(
            &client_id,
            "account-0",
            "subaddress-7",
            &[3, 9, 42],
            "watch-only-spend-authority-commitment",
            203,
            MONERO_PRIVATE_LIGHT_WALLET_RELAY_DEFAULT_CLIENT_TTL_BLOCKS,
        )?;
        let route_id = route.route_id.clone();
        state.register_subaddress_route(route)?;

        let observation = ViewTagObservation::new(
            228,
            "devnet-monero-block-228",
            "devnet-monero-tx-a",
            0,
            42,
            "amount-bucket-small",
            "stealth-output-key-a",
            "subaddress-hint-a",
            &scanner_id,
            229,
        )?;
        let observation_id = observation.observation_id.clone();
        state.record_view_tag_observation(observation)?;

        let sponsorship = ScanSponsorship::new(
            &sponsor_id,
            &client_id,
            256,
            state.parameters.low_fee_scan_unit_price,
            "privacy-sponsor-pool-a",
            230,
            state.parameters.sponsor_ttl_blocks,
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.register_sponsorship(sponsorship)?;

        let request_scopes = [FilterScope::ViewTagBucket, FilterScope::SubaddressRoute]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let request = ScanRequest::new(
            &client_id,
            request_scopes,
            &[42],
            224,
            232,
            8,
            Some(sponsorship_id),
            231,
            32,
        )?;
        let request_id = request.request_id.clone();
        state.submit_scan_request(request)?;
        state.assign_scan_request(&request_id, &scanner_id)?;

        let filter = CompactFilter::new(
            FilterScope::ViewTagBucket,
            &client_id,
            224,
            232,
            &[42],
            std::slice::from_ref(&observation_id),
            [scanner_id.clone()].into_iter().collect(),
            233,
        )?;
        let filter_id = filter.filter_id.clone();
        state.record_compact_filter(filter)?;

        let checkpoint = ReorgSafeCheckpoint::new(
            224,
            232,
            &[
                "devnet-monero-block-224".to_string(),
                "devnet-monero-block-232".to_string(),
            ],
            std::slice::from_ref(&observation_id),
            std::slice::from_ref(&filter_id),
            &[],
            &[],
            None,
            234,
        )?;
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        state.record_checkpoint(checkpoint)?;

        let delta = EncryptedWalletDelta::new(
            &client_id,
            &request_id,
            &checkpoint_id,
            std::slice::from_ref(&filter_id),
            std::slice::from_ref(&observation_id),
            &["nullifier-hint-a".to_string()],
            &[],
            "encrypted-wallet-delta-a",
            0,
            235,
            state.parameters.delta_ttl_blocks,
        )?;
        let delta_id = delta.delta_id.clone();
        state.record_wallet_delta(delta)?;

        let signers = [scanner_id.clone()].into_iter().collect::<BTreeSet<_>>();
        let receipt = RelayProofReceipt::new(
            ReceiptKind::DeltaDelivered,
            &delta_id,
            &checkpoint_id,
            "delta-delivery-proof-a",
            &signers,
            3,
            236,
            state.parameters.receipt_ttl_blocks,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.record_proof_receipt(receipt)?;

        let mut exit_hint = BridgeExitHint::new(
            &client_id,
            "bridge-exit-intent-a",
            &route_id,
            "amount-bucket-small",
            250,
            1_250,
            "fast-private-exit-lane",
            237,
        )?;
        exit_hint.proof_receipt_id = Some(receipt_id);
        state.record_bridge_exit_hint(exit_hint)?;

        state.validate()?;
        Ok(state)
    }

    pub fn register_client(
        &mut self,
        client: RelayClient,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        client.validate()?;
        if self.clients.contains_key(&client.client_id) {
            return Err("relay client already registered".to_string());
        }
        let client_id = client.client_id.clone();
        self.clients.insert(client_id.clone(), client);
        Ok(client_id)
    }

    pub fn register_scanner(
        &mut self,
        scanner: ScannerNode,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        scanner.validate()?;
        if self.scanners.contains_key(&scanner.scanner_id) {
            return Err("relay scanner already registered".to_string());
        }
        let scanner_id = scanner.scanner_id.clone();
        self.scanners.insert(scanner_id.clone(), scanner);
        Ok(scanner_id)
    }

    pub fn register_subaddress_route(
        &mut self,
        route: SubaddressRoute,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        route.validate()?;
        if !self.clients.contains_key(&route.client_id) {
            return Err("subaddress route references unknown client".to_string());
        }
        let route_id = route.route_id.clone();
        self.client_routes
            .entry(route.client_id.clone())
            .or_default()
            .insert(route_id.clone());
        self.subaddress_routes.insert(route_id.clone(), route);
        Ok(route_id)
    }

    pub fn record_view_tag_observation(
        &mut self,
        observation: ViewTagObservation,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        observation.validate()?;
        let scanner = self
            .scanners
            .get(&observation.scanner_id)
            .ok_or_else(|| "view tag observation references unknown scanner".to_string())?;
        if !scanner.has_role(RelayScannerRole::ViewTagScanner) {
            return Err("view tag observation scanner lacks view tag role".to_string());
        }
        let observation_id = observation.observation_id.clone();
        self.view_tag_index
            .entry(observation.view_tag)
            .or_default()
            .insert(observation_id.clone());
        self.observations
            .insert(observation_id.clone(), observation);
        Ok(observation_id)
    }

    pub fn record_compact_filter(
        &mut self,
        filter: CompactFilter,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        filter.validate()?;
        let client = self
            .clients
            .get(&filter.client_id)
            .ok_or_else(|| "compact filter references unknown client".to_string())?;
        if !client.allowed_scopes.contains(&filter.scope) {
            return Err("compact filter scope not allowed for client".to_string());
        }
        for builder in &filter.built_by {
            let scanner = self
                .scanners
                .get(builder)
                .ok_or_else(|| "compact filter references unknown builder".to_string())?;
            if !scanner.has_role(RelayScannerRole::FilterBuilder) {
                return Err("compact filter builder lacks filter role".to_string());
            }
        }
        let filter_id = filter.filter_id.clone();
        self.compact_filters.insert(filter_id.clone(), filter);
        Ok(filter_id)
    }

    pub fn register_sponsorship(
        &mut self,
        sponsorship: ScanSponsorship,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        sponsorship.validate()?;
        if !self.clients.contains_key(&sponsorship.sponsor_id) {
            return Err("scan sponsorship references unknown sponsor".to_string());
        }
        if !self.clients.contains_key(&sponsorship.client_id) {
            return Err("scan sponsorship references unknown client".to_string());
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn submit_scan_request(
        &mut self,
        request: ScanRequest,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        request.validate()?;
        let client = self
            .clients
            .get(&request.client_id)
            .ok_or_else(|| "scan request references unknown client".to_string())?;
        if !client.can_request_at(request.created_at_height) {
            return Err("scan request client cannot request at height".to_string());
        }
        for scope in &request.requested_scopes {
            if !client.allowed_scopes.contains(scope) {
                return Err("scan request scope not allowed for client".to_string());
            }
        }
        if let Some(sponsorship_id) = &request.sponsorship_id {
            let sponsorship = self
                .sponsorships
                .get_mut(sponsorship_id)
                .ok_or_else(|| "scan request references unknown sponsorship".to_string())?;
            if sponsorship.client_id != request.client_id {
                return Err("scan request sponsorship client mismatch".to_string());
            }
            sponsorship.reserve(request.max_scan_units)?;
        }
        let epoch = self.epoch_for_height(request.created_at_height);
        let bucket = self.rate_bucket_mut(&request.client_id, epoch);
        bucket.charge_request()?;
        let request_id = request.request_id.clone();
        self.client_requests
            .entry(request.client_id.clone())
            .or_default()
            .insert(request_id.clone());
        self.scan_requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    pub fn assign_scan_request(
        &mut self,
        request_id: &str,
        scanner_id: &str,
    ) -> MoneroPrivateLightWalletRelayResult<()> {
        let scanner = self
            .scanners
            .get(scanner_id)
            .ok_or_else(|| "scan assignment references unknown scanner".to_string())?;
        if !scanner.has_role(RelayScannerRole::ViewTagScanner) {
            return Err("scan assignment scanner lacks scan role".to_string());
        }
        let request = self
            .scan_requests
            .get_mut(request_id)
            .ok_or_else(|| "scan request not found".to_string())?;
        request.assign(scanner_id)
    }

    pub fn record_wallet_delta(
        &mut self,
        delta: EncryptedWalletDelta,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        delta.validate()?;
        if !self.clients.contains_key(&delta.client_id) {
            return Err("wallet delta references unknown client".to_string());
        }
        if !self.scan_requests.contains_key(&delta.request_id) {
            return Err("wallet delta references unknown scan request".to_string());
        }
        if !self.checkpoints.contains_key(&delta.checkpoint_id) {
            return Err("wallet delta references unknown checkpoint".to_string());
        }
        let epoch = self.epoch_for_height(delta.prepared_at_height);
        let bucket = self.rate_bucket_mut(&delta.client_id, epoch);
        bucket.charge_delta()?;
        let delta_id = delta.delta_id.clone();
        self.client_deltas
            .entry(delta.client_id.clone())
            .or_default()
            .insert(delta_id.clone());
        self.wallet_deltas.insert(delta_id.clone(), delta);
        Ok(delta_id)
    }

    pub fn record_checkpoint(
        &mut self,
        checkpoint: ReorgSafeCheckpoint,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        checkpoint.validate()?;
        if let Some(parent) = &checkpoint.parent_checkpoint_id {
            if !self.checkpoints.contains_key(parent) {
                return Err("checkpoint references unknown parent".to_string());
            }
        }
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);
        Ok(checkpoint_id)
    }

    pub fn record_proof_receipt(
        &mut self,
        receipt: RelayProofReceipt,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        receipt.validate()?;
        if receipt.scanner_weight < self.parameters.min_scanner_weight {
            return Err("proof receipt scanner weight below quorum".to_string());
        }
        if !self.checkpoints.contains_key(&receipt.checkpoint_id) {
            return Err("proof receipt references unknown checkpoint".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.proof_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn record_bridge_exit_hint(
        &mut self,
        hint: BridgeExitHint,
    ) -> MoneroPrivateLightWalletRelayResult<String> {
        hint.validate()?;
        if !self.clients.contains_key(&hint.client_id) {
            return Err("bridge exit hint references unknown client".to_string());
        }
        if !self
            .subaddress_routes
            .contains_key(&hint.subaddress_route_id)
        {
            return Err("bridge exit hint references unknown subaddress route".to_string());
        }
        if let Some(receipt_id) = &hint.proof_receipt_id {
            if !self.proof_receipts.contains_key(receipt_id) {
                return Err("bridge exit hint references unknown proof receipt".to_string());
            }
        }
        let epoch = self.epoch_for_height(hint.created_at_height);
        let bucket = self.rate_bucket_mut(&hint.client_id, epoch);
        bucket.charge_exit_hint()?;
        let hint_id = hint.hint_id.clone();
        self.bridge_exit_hints.insert(hint_id.clone(), hint);
        Ok(hint_id)
    }

    pub fn mark_reorg_from_height(
        &mut self,
        reorg_height: u64,
    ) -> MoneroPrivateLightWalletRelayResult<()> {
        let mut changed = false;
        for observation in self.observations.values() {
            if observation.block_height >= reorg_height {
                changed = true;
            }
        }
        for checkpoint in self.checkpoints.values_mut() {
            if checkpoint.end_height >= reorg_height && checkpoint.status.is_canonical() {
                checkpoint.status = CheckpointStatus::Reorged;
                changed = true;
            }
        }
        for request in self.scan_requests.values_mut() {
            if request.end_height >= reorg_height && request.status.is_open() {
                request.status = ScanRequestStatus::Reorged;
                changed = true;
            }
        }
        for delta in self.wallet_deltas.values_mut() {
            if delta.prepared_at_height >= reorg_height && delta.status.is_live() {
                delta.status = WalletDeltaStatus::Reorged;
                changed = true;
            }
        }
        for hint in self.bridge_exit_hints.values_mut() {
            if hint.created_at_height >= reorg_height {
                hint.status = BridgeExitHintStatus::Reorged;
                changed = true;
            }
        }
        if !changed {
            return Err("reorg did not affect relay state".to_string());
        }
        Ok(())
    }

    pub fn expire_at_height(&mut self, height: u64) {
        for client in self.clients.values_mut() {
            if height > client.expires_at_height && client.status.can_request() {
                client.status = RelayClientStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if height > sponsorship.expires_at_height && sponsorship.status.is_spendable() {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for request in self.scan_requests.values_mut() {
            if height > request.expires_at_height && request.status.is_open() {
                request.status = ScanRequestStatus::Expired;
            }
        }
        for delta in self.wallet_deltas.values_mut() {
            if height > delta.expires_at_height && delta.status.is_live() {
                delta.status = WalletDeltaStatus::Expired;
            }
        }
        for hint in self.bridge_exit_hints.values_mut() {
            if height > hint.preferred_unlock_height
                && matches!(
                    hint.status,
                    BridgeExitHintStatus::Proposed | BridgeExitHintStatus::Routed
                )
            {
                hint.status = BridgeExitHintStatus::Expired;
            }
        }
        self.current_height = height;
    }

    pub fn counters(&self) -> RelayCounters {
        RelayCounters {
            clients: self.clients.len() as u64,
            scanners: self.scanners.len() as u64,
            subaddress_routes: self.subaddress_routes.len() as u64,
            observations: self.observations.len() as u64,
            filters: self.compact_filters.len() as u64,
            sponsorships: self.sponsorships.len() as u64,
            scan_requests: self.scan_requests.len() as u64,
            wallet_deltas: self.wallet_deltas.len() as u64,
            checkpoints: self.checkpoints.len() as u64,
            rate_limit_buckets: self.rate_limits.len() as u64,
            proof_receipts: self.proof_receipts.len() as u64,
            bridge_exit_hints: self.bridge_exit_hints.len() as u64,
            active_clients: self
                .clients
                .values()
                .filter(|client| client.status.can_request())
                .count() as u64,
            open_requests: self
                .scan_requests
                .values()
                .filter(|request| request.status.is_open())
                .count() as u64,
            live_deltas: self
                .wallet_deltas
                .values()
                .filter(|delta| delta.status.is_live())
                .count() as u64,
            finalized_checkpoints: self
                .checkpoints
                .values()
                .filter(|checkpoint| checkpoint.status == CheckpointStatus::Finalized)
                .count() as u64,
        }
    }

    pub fn roots(&self) -> RelayRoots {
        let counters = self.counters();
        RelayRoots {
            parameters_root: self.parameters.parameters_root(),
            client_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-CLIENT",
                self.clients
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            scanner_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-SCANNER",
                self.scanners
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            subaddress_route_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-SUBADDRESS-ROUTE",
                self.subaddress_routes
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            observation_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-OBSERVATION",
                self.observations
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            compact_filter_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-COMPACT-FILTER",
                self.compact_filters
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            sponsorship_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-SPONSORSHIP",
                self.sponsorships
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            scan_request_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-SCAN-REQUEST",
                self.scan_requests
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            wallet_delta_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-WALLET-DELTA",
                self.wallet_deltas
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            checkpoint_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-CHECKPOINT",
                self.checkpoints
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            rate_limit_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-RATE-LIMIT",
                self.rate_limits
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            proof_receipt_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-PROOF-RECEIPT",
                self.proof_receipts
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            bridge_exit_hint_root: map_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-BRIDGE-EXIT-HINT",
                self.bridge_exit_hints
                    .iter()
                    .map(|(id, item)| (id.clone(), item.public_record())),
            ),
            counters_root: relay_payload_root(
                "MONERO-PRIVATE-LIGHT-WALLET-RELAY-COUNTERS",
                &counters.public_record(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        monero_private_light_wallet_relay_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_private_light_wallet_relay_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PRIVATE_LIGHT_WALLET_RELAY_PROTOCOL_VERSION,
            "current_height": self.current_height,
            "roots": roots.public_record(),
            "root_commitment": roots.state_root(),
            "counters": self.counters().public_record(),
            "parameters": self.parameters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        json_with_root(
            self.public_record_without_root(),
            "monero_private_light_wallet_relay_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> MoneroPrivateLightWalletRelayResult<String> {
        self.parameters.validate()?;
        for client in self.clients.values() {
            client.validate()?;
        }
        for scanner in self.scanners.values() {
            scanner.validate()?;
        }
        for route in self.subaddress_routes.values() {
            route.validate()?;
            if !self.clients.contains_key(&route.client_id) {
                return Err("state contains route for unknown client".to_string());
            }
        }
        for observation in self.observations.values() {
            observation.validate()?;
            if !self.scanners.contains_key(&observation.scanner_id) {
                return Err("state contains observation for unknown scanner".to_string());
            }
        }
        for filter in self.compact_filters.values() {
            filter.validate()?;
            if !self.clients.contains_key(&filter.client_id) {
                return Err("state contains filter for unknown client".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
        }
        for request in self.scan_requests.values() {
            request.validate()?;
            if !self.clients.contains_key(&request.client_id) {
                return Err("state contains request for unknown client".to_string());
            }
        }
        for delta in self.wallet_deltas.values() {
            delta.validate()?;
        }
        for checkpoint in self.checkpoints.values() {
            checkpoint.validate()?;
        }
        for bucket in self.rate_limits.values() {
            bucket.validate()?;
        }
        for receipt in self.proof_receipts.values() {
            receipt.validate()?;
        }
        for hint in self.bridge_exit_hints.values() {
            hint.validate()?;
        }
        Ok(self.state_root())
    }

    fn epoch_for_height(&self, height: u64) -> u64 {
        if self.parameters.epoch_blocks == 0 {
            0
        } else {
            height / self.parameters.epoch_blocks
        }
    }

    fn rate_bucket_mut(&mut self, subject_id: &str, epoch: u64) -> &mut RelayRateLimitBucket {
        let bucket_id = relay_id(
            "RATE-LIMIT-BUCKET-ID",
            &json!({
                "subject_id": subject_id,
                "epoch": epoch,
            }),
        );
        let parameters = self.parameters.clone();
        self.rate_limits
            .entry(bucket_id)
            .or_insert_with(|| RelayRateLimitBucket::new(subject_id, epoch, &parameters))
    }
}

pub fn monero_private_light_wallet_relay_state_root_from_record(record: &Value) -> String {
    relay_payload_root("MONERO-PRIVATE-LIGHT-WALLET-RELAY-STATE", record)
}

fn relay_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn relay_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn relay_id(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn relay_string_set_root(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn relay_u16_set_root(domain: &str, values: &[u16]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    let leaves = sorted
        .into_iter()
        .map(|value| json!({ "view_tag": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_root<I>(domain: &str, entries: I) -> String
where
    I: IntoIterator<Item = (String, Value)>,
{
    let leaves = entries
        .into_iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn json_with_root(mut record: Value, root_key: &str, root: String) -> Value {
    if let Value::Object(ref mut object) = record {
        object.insert(root_key.to_string(), Value::String(root));
    }
    record
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroPrivateLightWalletRelayResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_deterministic_root() {
        let state = match MoneroPrivateLightWalletRelayState::devnet() {
            Ok(state) => state,
            Err(error) => {
                assert!(false, "devnet relay state should build: {error}");
                return;
            }
        };
        let root = match state.validate() {
            Ok(root) => root,
            Err(error) => {
                assert!(false, "devnet relay state should validate: {error}");
                return;
            }
        };
        assert_eq!(root, state.state_root());
        assert_eq!(state.counters().clients, 2);
        assert_eq!(state.counters().scanners, 1);
        assert_eq!(state.counters().bridge_exit_hints, 1);
    }

    #[test]
    fn sponsorship_cannot_over_reserve() {
        let mut sponsorship = match ScanSponsorship::new("sponsor", "client", 4, 1, "pool", 1, 10) {
            Ok(sponsorship) => sponsorship,
            Err(error) => {
                assert!(false, "sponsorship should build: {error}");
                return;
            }
        };
        assert!(sponsorship.reserve(4).is_ok());
        assert!(sponsorship.reserve(1).is_err());
    }
}
