use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroRpcBridgeResult<T> = Result<T, String>;

pub const MONERO_RPC_BRIDGE_PROTOCOL_VERSION: &str = "nebula-monero-rpc-bridge-v1";
pub const MONERO_RPC_BRIDGE_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_RPC_BRIDGE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_RPC_BRIDGE_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_RPC_BRIDGE_DEFAULT_ENDPOINT_QUORUM: u64 = 2;
pub const MONERO_RPC_BRIDGE_DEFAULT_WALLET_QUORUM: u64 = 1;
pub const MONERO_RPC_BRIDGE_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const MONERO_RPC_BRIDGE_DEFAULT_MAX_ENDPOINT_LAG_BLOCKS: u64 = 4;
pub const MONERO_RPC_BRIDGE_DEFAULT_HEALTH_STALE_BLOCKS: u64 = 3;
pub const MONERO_RPC_BRIDGE_DEFAULT_SCAN_REQUEST_TTL_BLOCKS: u64 = 72;
pub const MONERO_RPC_BRIDGE_DEFAULT_IMPORT_REQUEST_TTL_BLOCKS: u64 = 36;
pub const MONERO_RPC_BRIDGE_DEFAULT_VIEW_SYNC_JOB_TTL_BLOCKS: u64 = 48;
pub const MONERO_RPC_BRIDGE_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 96;
pub const MONERO_RPC_BRIDGE_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 144;
pub const MONERO_RPC_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_RPC_BRIDGE_DEFAULT_MAX_SCAN_WINDOW_BLOCKS: u64 = 2_048;
pub const MONERO_RPC_BRIDGE_DEFAULT_MAX_SCAN_OUTPUTS_PER_JOB: u64 = 8_192;
pub const MONERO_RPC_BRIDGE_DEFAULT_SCAN_UNIT_MICRO_FEE: u64 = 25_000;
pub const MONERO_RPC_BRIDGE_AMOUNT_BUCKET: u64 = 10_000;
pub const MONERO_RPC_BRIDGE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcEndpointKind {
    Daemon,
    Wallet,
    WalletRpcProxy,
    ViewOnlyWallet,
    FailoverRelay,
}

impl RpcEndpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Wallet => "wallet",
            Self::WalletRpcProxy => "wallet_rpc_proxy",
            Self::ViewOnlyWallet => "view_only_wallet",
            Self::FailoverRelay => "failover_relay",
        }
    }

    pub fn is_wallet_capable(self) -> bool {
        matches!(
            self,
            Self::Wallet | Self::WalletRpcProxy | Self::ViewOnlyWallet
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcEndpointStatus {
    Active,
    Degraded,
    Quarantined,
    Offline,
    Retired,
}

impl RpcEndpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Quarantined => "quarantined",
            Self::Offline => "offline",
            Self::Retired => "retired",
        }
    }

    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcMethodFamily {
    DaemonHeight,
    DaemonBlocks,
    DaemonTxPool,
    WalletRefresh,
    WalletScan,
    WalletImport,
    WalletTransfer,
    WalletProof,
    ViewOnlySync,
    Health,
    Attestation,
}

impl RpcMethodFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonHeight => "daemon_height",
            Self::DaemonBlocks => "daemon_blocks",
            Self::DaemonTxPool => "daemon_tx_pool",
            Self::WalletRefresh => "wallet_refresh",
            Self::WalletScan => "wallet_scan",
            Self::WalletImport => "wallet_import",
            Self::WalletTransfer => "wallet_transfer",
            Self::WalletProof => "wallet_proof",
            Self::ViewOnlySync => "view_only_sync",
            Self::Health => "health",
            Self::Attestation => "attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletRequestKind {
    ScanOutputs,
    ImportOutputs,
    ImportKeyImages,
    ExportOutputs,
    Refresh,
    RescanSpent,
    Sweep,
    ProofOnly,
}

impl WalletRequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanOutputs => "scan_outputs",
            Self::ImportOutputs => "import_outputs",
            Self::ImportKeyImages => "import_key_images",
            Self::ExportOutputs => "export_outputs",
            Self::Refresh => "refresh",
            Self::RescanSpent => "rescan_spent",
            Self::Sweep => "sweep",
            Self::ProofOnly => "proof_only",
        }
    }

    pub fn is_import(self) -> bool {
        matches!(self, Self::ImportOutputs | Self::ImportKeyImages)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletRequestStatus {
    Queued,
    Assigned,
    Running,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

impl WalletRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Assigned => "assigned",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Queued | Self::Assigned | Self::Running)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewOnlySyncStatus {
    Queued,
    Running,
    Sealed,
    Reorged,
    Expired,
    Paused,
}

impl ViewOnlySyncStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Sealed => "sealed",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::Paused)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTicketKind {
    Deposit,
    Withdrawal,
    ReserveSweep,
    FeeTopUp,
}

impl BridgeTicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::ReserveSweep => "reserve_sweep",
            Self::FeeTopUp => "fee_top_up",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTicketStatus {
    Observed,
    PendingFinality,
    Matched,
    Released,
    Reorged,
    Rejected,
    Expired,
}

impl BridgeTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::PendingFinality => "pending_finality",
            Self::Matched => "matched",
            Self::Released => "released",
            Self::Reorged => "reorged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Observed | Self::PendingFinality | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgEvidenceKind {
    BlockHashConflict,
    HeightRollback,
    TxDropped,
    WalletScanMismatch,
    EndpointEquivocation,
}

impl ReorgEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockHashConflict => "block_hash_conflict",
            Self::HeightRollback => "height_rollback",
            Self::TxDropped => "tx_dropped",
            Self::WalletScanMismatch => "wallet_scan_mismatch",
            Self::EndpointEquivocation => "endpoint_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverDecisionKind {
    PreferEndpoint,
    QuarantineEndpoint,
    RotateWalletRpc,
    ReduceQuorum,
    RestoreEndpoint,
}

impl FailoverDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreferEndpoint => "prefer_endpoint",
            Self::QuarantineEndpoint => "quarantine_endpoint",
            Self::RotateWalletRpc => "rotate_wallet_rpc",
            Self::ReduceQuorum => "reduce_quorum",
            Self::RestoreEndpoint => "restore_endpoint",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Consumed,
    Settled,
    Slashed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Consumed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    EndpointHealth,
    HeightRange,
    ScanWindow,
    BridgeTicket,
    ReorgEvidence,
    SponsorUse,
    PqAttestation,
}

impl DisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EndpointHealth => "endpoint_health",
            Self::HeightRange => "height_range",
            Self::ScanWindow => "scan_window",
            Self::BridgeTicket => "bridge_ticket",
            Self::ReorgEvidence => "reorg_evidence",
            Self::SponsorUse => "sponsor_use",
            Self::PqAttestation => "pq_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Prepared,
    Shared,
    Revoked,
    Expired,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Shared => "shared",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Prepared | Self::Shared)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationSubject {
    Endpoint,
    Operator,
    WalletJob,
    BridgeTicket,
    FailoverDecision,
    DisclosureSummary,
    ReorgEvidence,
}

impl PqAttestationSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Operator => "operator",
            Self::WalletJob => "wallet_job",
            Self::BridgeTicket => "bridge_ticket",
            Self::FailoverDecision => "failover_decision",
            Self::DisclosureSummary => "disclosure_summary",
            Self::ReorgEvidence => "reorg_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Pending,
    Accepted,
    ThresholdMet,
    Superseded,
    Rejected,
    Expired,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::ThresholdMet => "threshold_met",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Accepted | Self::ThresholdMet)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcBridgeConfig {
    pub config_id: String,
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub endpoint_quorum: u64,
    pub wallet_quorum: u64,
    pub finality_depth: u64,
    pub max_endpoint_lag_blocks: u64,
    pub health_stale_blocks: u64,
    pub scan_request_ttl_blocks: u64,
    pub import_request_ttl_blocks: u64,
    pub view_sync_job_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub max_scan_window_blocks: u64,
    pub max_scan_outputs_per_job: u64,
    pub require_pq_endpoint_attestations: bool,
    pub require_operator_attestations: bool,
    pub privacy_mode: String,
}

impl Default for MoneroRpcBridgeConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            network: MONERO_RPC_BRIDGE_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_RPC_BRIDGE_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_RPC_BRIDGE_DEVNET_FEE_ASSET_ID.to_string(),
            endpoint_quorum: MONERO_RPC_BRIDGE_DEFAULT_ENDPOINT_QUORUM,
            wallet_quorum: MONERO_RPC_BRIDGE_DEFAULT_WALLET_QUORUM,
            finality_depth: MONERO_RPC_BRIDGE_DEFAULT_FINALITY_DEPTH,
            max_endpoint_lag_blocks: MONERO_RPC_BRIDGE_DEFAULT_MAX_ENDPOINT_LAG_BLOCKS,
            health_stale_blocks: MONERO_RPC_BRIDGE_DEFAULT_HEALTH_STALE_BLOCKS,
            scan_request_ttl_blocks: MONERO_RPC_BRIDGE_DEFAULT_SCAN_REQUEST_TTL_BLOCKS,
            import_request_ttl_blocks: MONERO_RPC_BRIDGE_DEFAULT_IMPORT_REQUEST_TTL_BLOCKS,
            view_sync_job_ttl_blocks: MONERO_RPC_BRIDGE_DEFAULT_VIEW_SYNC_JOB_TTL_BLOCKS,
            disclosure_ttl_blocks: MONERO_RPC_BRIDGE_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            sponsorship_ttl_blocks: MONERO_RPC_BRIDGE_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            min_pq_security_bits: MONERO_RPC_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_scan_window_blocks: MONERO_RPC_BRIDGE_DEFAULT_MAX_SCAN_WINDOW_BLOCKS,
            max_scan_outputs_per_job: MONERO_RPC_BRIDGE_DEFAULT_MAX_SCAN_OUTPUTS_PER_JOB,
            require_pq_endpoint_attestations: true,
            require_operator_attestations: true,
            privacy_mode: "commitments_only_limited_disclosure".to_string(),
        };
        config.config_id = monero_rpc_bridge_config_id(&config.identity_record());
        config
    }
}

impl MoneroRpcBridgeConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_bridge_config_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "endpoint_quorum": self.endpoint_quorum,
            "wallet_quorum": self.wallet_quorum,
            "finality_depth": self.finality_depth,
            "max_endpoint_lag_blocks": self.max_endpoint_lag_blocks,
            "health_stale_blocks": self.health_stale_blocks,
            "scan_request_ttl_blocks": self.scan_request_ttl_blocks,
            "import_request_ttl_blocks": self.import_request_ttl_blocks,
            "view_sync_job_ttl_blocks": self.view_sync_job_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_scan_window_blocks": self.max_scan_window_blocks,
            "max_scan_outputs_per_job": self.max_scan_outputs_per_job,
            "require_pq_endpoint_attestations": self.require_pq_endpoint_attestations,
            "require_operator_attestations": self.require_operator_attestations,
            "privacy_mode": self.privacy_mode,
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            with_string_field(
                with_string_field(
                    self.identity_record(),
                    "kind",
                    "monero_rpc_bridge_config".to_string(),
                ),
                "config_id",
                self.config_id.clone(),
            ),
            "config_root",
            self.config_root(),
        )
    }

    pub fn config_root(&self) -> String {
        monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.config_id, "monero rpc bridge config id")?;
        ensure_non_empty(&self.network, "monero rpc bridge network")?;
        ensure_non_empty(&self.asset_id, "monero rpc bridge asset id")?;
        ensure_non_empty(&self.fee_asset_id, "monero rpc bridge fee asset id")?;
        ensure_non_empty(&self.privacy_mode, "monero rpc bridge privacy mode")?;
        ensure_positive(self.endpoint_quorum, "monero rpc bridge endpoint quorum")?;
        ensure_positive(self.wallet_quorum, "monero rpc bridge wallet quorum")?;
        ensure_positive(self.finality_depth, "monero rpc bridge finality depth")?;
        ensure_positive(
            self.health_stale_blocks,
            "monero rpc bridge health stale blocks",
        )?;
        ensure_positive(
            self.scan_request_ttl_blocks,
            "monero rpc bridge scan request ttl",
        )?;
        ensure_positive(
            self.import_request_ttl_blocks,
            "monero rpc bridge import request ttl",
        )?;
        ensure_positive(
            self.view_sync_job_ttl_blocks,
            "monero rpc bridge sync job ttl",
        )?;
        ensure_positive(
            self.disclosure_ttl_blocks,
            "monero rpc bridge disclosure ttl",
        )?;
        ensure_positive(
            self.sponsorship_ttl_blocks,
            "monero rpc bridge sponsorship ttl",
        )?;
        ensure_positive(
            self.max_scan_window_blocks,
            "monero rpc bridge max scan window",
        )?;
        ensure_positive(
            self.max_scan_outputs_per_job,
            "monero rpc bridge max scan outputs",
        )?;
        if self.min_pq_security_bits < 128 {
            return Err("monero rpc bridge pq security floor is too low".to_string());
        }
        let computed = monero_rpc_bridge_config_id(&self.identity_record());
        if self.config_id != computed {
            return Err("monero rpc bridge config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcEndpoint {
    pub endpoint_id: String,
    pub label: String,
    pub endpoint_kind: RpcEndpointKind,
    pub network: String,
    pub operator_commitment: String,
    pub route_commitment: String,
    pub auth_policy_root: String,
    pub tls_policy_root: String,
    pub supported_method_root: String,
    pub priority: u64,
    pub advertised_height: u64,
    pub last_observed_height: u64,
    pub last_health_height: u64,
    pub latency_ms: u64,
    pub error_count: u64,
    pub reliability_bps: u64,
    pub pq_key_root: String,
    pub status: RpcEndpointStatus,
}

impl MoneroRpcEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        endpoint_kind: RpcEndpointKind,
        network: impl Into<String>,
        operator_label: impl Into<String>,
        route_label: impl Into<String>,
        auth_policy: &Value,
        tls_policy: &Value,
        supported_methods: &[RpcMethodFamily],
        priority: u64,
        advertised_height: u64,
        pq_key_material: impl Into<String>,
    ) -> MoneroRpcBridgeResult<Self> {
        let label = label.into();
        let network = network.into();
        let operator_label = operator_label.into();
        let route_label = route_label.into();
        let pq_key_material = pq_key_material.into();
        ensure_non_empty(&label, "monero rpc endpoint label")?;
        ensure_non_empty(&network, "monero rpc endpoint network")?;
        ensure_non_empty(&operator_label, "monero rpc endpoint operator")?;
        ensure_non_empty(&route_label, "monero rpc endpoint route")?;
        ensure_non_empty(&pq_key_material, "monero rpc endpoint pq key")?;
        ensure_method_set(supported_methods, "monero rpc endpoint methods")?;
        let operator_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-ENDPOINT-OPERATOR", &operator_label);
        let route_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-ENDPOINT-ROUTE", &route_label);
        let auth_policy_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-AUTH-POLICY", auth_policy);
        let tls_policy_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-TLS-POLICY", tls_policy);
        let method_labels = supported_methods
            .iter()
            .map(|method| method.as_str().to_string())
            .collect::<Vec<_>>();
        let supported_method_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-ENDPOINT-METHOD", &method_labels);
        let pq_key_root =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-ENDPOINT-PQ-KEY", &pq_key_material);
        let mut endpoint = Self {
            endpoint_id: String::new(),
            label,
            endpoint_kind,
            network,
            operator_commitment,
            route_commitment,
            auth_policy_root,
            tls_policy_root,
            supported_method_root,
            priority,
            advertised_height,
            last_observed_height: advertised_height,
            last_health_height: 0,
            latency_ms: 0,
            error_count: 0,
            reliability_bps: MONERO_RPC_BRIDGE_MAX_BPS,
            pq_key_root,
            status: RpcEndpointStatus::Active,
        };
        endpoint.endpoint_id = monero_rpc_bridge_endpoint_id(&endpoint.identity_record());
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_endpoint_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "label": self.label,
            "endpoint_kind": self.endpoint_kind.as_str(),
            "network": self.network,
            "operator_commitment": self.operator_commitment,
            "route_commitment": self.route_commitment,
            "auth_policy_root": self.auth_policy_root,
            "tls_policy_root": self.tls_policy_root,
            "supported_method_root": self.supported_method_root,
            "priority": self.priority,
            "pq_key_root": self.pq_key_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_endpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "label": self.label,
            "endpoint_kind": self.endpoint_kind.as_str(),
            "network": self.network,
            "operator_commitment": self.operator_commitment,
            "route_commitment": self.route_commitment,
            "auth_policy_root": self.auth_policy_root,
            "tls_policy_root": self.tls_policy_root,
            "supported_method_root": self.supported_method_root,
            "priority": self.priority,
            "advertised_height": self.advertised_height,
            "last_observed_height": self.last_observed_height,
            "last_health_height": self.last_health_height,
            "latency_ms": self.latency_ms,
            "error_count": self.error_count,
            "reliability_bps": self.reliability_bps,
            "pq_key_root": self.pq_key_root,
            "status": self.status.as_str(),
        })
    }

    pub fn endpoint_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-ENDPOINT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "endpoint_root",
            self.endpoint_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.endpoint_id, "monero rpc endpoint id")?;
        ensure_non_empty(&self.label, "monero rpc endpoint label")?;
        ensure_non_empty(&self.network, "monero rpc endpoint network")?;
        ensure_non_empty(
            &self.operator_commitment,
            "monero rpc endpoint operator commitment",
        )?;
        ensure_non_empty(
            &self.route_commitment,
            "monero rpc endpoint route commitment",
        )?;
        ensure_non_empty(&self.auth_policy_root, "monero rpc endpoint auth root")?;
        ensure_non_empty(&self.tls_policy_root, "monero rpc endpoint tls root")?;
        ensure_non_empty(
            &self.supported_method_root,
            "monero rpc endpoint method root",
        )?;
        ensure_non_empty(&self.pq_key_root, "monero rpc endpoint pq key root")?;
        ensure_bps(self.reliability_bps, "monero rpc endpoint reliability")?;
        let computed = monero_rpc_bridge_endpoint_id(&self.identity_record());
        if self.endpoint_id != computed {
            return Err("monero rpc endpoint id mismatch".to_string());
        }
        Ok(self.endpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcEndpointHealth {
    pub health_id: String,
    pub endpoint_id: String,
    pub observed_at_height: u64,
    pub daemon_height: u64,
    pub wallet_height: u64,
    pub txpool_size: u64,
    pub latency_ms: u64,
    pub error_count: u64,
    pub lag_blocks: u64,
    pub supported_method_root: String,
    pub response_root: String,
    pub status: RpcEndpointStatus,
}

impl RpcEndpointHealth {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint_id: impl Into<String>,
        observed_at_height: u64,
        daemon_height: u64,
        wallet_height: u64,
        txpool_size: u64,
        latency_ms: u64,
        error_count: u64,
        chain_tip_height: u64,
        supported_methods: &[RpcMethodFamily],
        response_payload: &Value,
    ) -> MoneroRpcBridgeResult<Self> {
        let endpoint_id = endpoint_id.into();
        ensure_non_empty(&endpoint_id, "monero rpc health endpoint id")?;
        ensure_method_set(supported_methods, "monero rpc health methods")?;
        let method_labels = supported_methods
            .iter()
            .map(|method| method.as_str().to_string())
            .collect::<Vec<_>>();
        let supported_method_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-HEALTH-METHOD", &method_labels);
        let response_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-HEALTH-RESPONSE", response_payload);
        let lag_blocks = chain_tip_height.saturating_sub(daemon_height);
        let status = if error_count > 2 {
            RpcEndpointStatus::Quarantined
        } else if error_count > 0 || lag_blocks > MONERO_RPC_BRIDGE_DEFAULT_MAX_ENDPOINT_LAG_BLOCKS
        {
            RpcEndpointStatus::Degraded
        } else {
            RpcEndpointStatus::Active
        };
        let mut health = Self {
            health_id: String::new(),
            endpoint_id,
            observed_at_height,
            daemon_height,
            wallet_height,
            txpool_size,
            latency_ms,
            error_count,
            lag_blocks,
            supported_method_root,
            response_root,
            status,
        };
        health.health_id = monero_rpc_bridge_endpoint_health_id(&health.identity_record());
        health.validate()?;
        Ok(health)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_endpoint_health_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "observed_at_height": self.observed_at_height,
            "daemon_height": self.daemon_height,
            "wallet_height": self.wallet_height,
            "txpool_size": self.txpool_size,
            "latency_ms": self.latency_ms,
            "error_count": self.error_count,
            "supported_method_root": self.supported_method_root,
            "response_root": self.response_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_endpoint_health",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "health_id": self.health_id,
            "endpoint_id": self.endpoint_id,
            "observed_at_height": self.observed_at_height,
            "daemon_height": self.daemon_height,
            "wallet_height": self.wallet_height,
            "txpool_size": self.txpool_size,
            "latency_ms": self.latency_ms,
            "error_count": self.error_count,
            "lag_blocks": self.lag_blocks,
            "supported_method_root": self.supported_method_root,
            "response_root": self.response_root,
            "status": self.status.as_str(),
        })
    }

    pub fn health_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-ENDPOINT-HEALTH",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "health_root",
            self.health_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.health_id, "monero rpc health id")?;
        ensure_non_empty(&self.endpoint_id, "monero rpc health endpoint id")?;
        ensure_non_empty(
            &self.supported_method_root,
            "monero rpc health methods root",
        )?;
        ensure_non_empty(&self.response_root, "monero rpc health response root")?;
        let computed = monero_rpc_bridge_endpoint_health_id(&self.identity_record());
        if self.health_id != computed {
            return Err("monero rpc health id mismatch".to_string());
        }
        Ok(self.health_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcQuorumHealth {
    pub quorum_id: String,
    pub network: String,
    pub height: u64,
    pub endpoint_root: String,
    pub health_root: String,
    pub active_endpoint_count: u64,
    pub daemon_endpoint_count: u64,
    pub wallet_endpoint_count: u64,
    pub quorum_required: u64,
    pub wallet_quorum_required: u64,
    pub min_daemon_height: u64,
    pub median_daemon_height: u64,
    pub max_lag_blocks: u64,
    pub degraded_endpoint_count: u64,
    pub active_endpoint_id: Option<String>,
    pub status: String,
}

impl RpcQuorumHealth {
    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_quorum_health",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "quorum_id": self.quorum_id,
            "network": self.network,
            "height": self.height,
            "endpoint_root": self.endpoint_root,
            "health_root": self.health_root,
            "active_endpoint_count": self.active_endpoint_count,
            "daemon_endpoint_count": self.daemon_endpoint_count,
            "wallet_endpoint_count": self.wallet_endpoint_count,
            "quorum_required": self.quorum_required,
            "wallet_quorum_required": self.wallet_quorum_required,
            "min_daemon_height": self.min_daemon_height,
            "median_daemon_height": self.median_daemon_height,
            "max_lag_blocks": self.max_lag_blocks,
            "degraded_endpoint_count": self.degraded_endpoint_count,
            "active_endpoint_id": self.active_endpoint_id,
            "status": self.status,
        })
    }

    pub fn quorum_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-QUORUM-HEALTH",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "quorum_root",
            self.quorum_root(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonHeightObservation {
    pub observation_id: String,
    pub endpoint_id: String,
    pub observed_at_l2_height: u64,
    pub daemon_height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub cumulative_difficulty_root: String,
    pub txpool_size: u64,
    pub pruning_seed: u64,
    pub response_root: String,
    pub status: RpcEndpointStatus,
}

impl DaemonHeightObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint_id: impl Into<String>,
        observed_at_l2_height: u64,
        daemon_height: u64,
        block_hash: impl Into<String>,
        previous_block_hash: impl Into<String>,
        cumulative_difficulty: &Value,
        txpool_size: u64,
        pruning_seed: u64,
        response_payload: &Value,
        status: RpcEndpointStatus,
    ) -> MoneroRpcBridgeResult<Self> {
        let endpoint_id = endpoint_id.into();
        let block_hash = block_hash.into();
        let previous_block_hash = previous_block_hash.into();
        ensure_non_empty(&endpoint_id, "monero rpc height endpoint id")?;
        ensure_non_empty(&block_hash, "monero rpc height block hash")?;
        ensure_non_empty(
            &previous_block_hash,
            "monero rpc height previous block hash",
        )?;
        let cumulative_difficulty_root = monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-CUMULATIVE-DIFFICULTY",
            cumulative_difficulty,
        );
        let response_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-HEIGHT-RESPONSE", response_payload);
        let mut observation = Self {
            observation_id: String::new(),
            endpoint_id,
            observed_at_l2_height,
            daemon_height,
            block_hash,
            previous_block_hash,
            cumulative_difficulty_root,
            txpool_size,
            pruning_seed,
            response_root,
            status,
        };
        observation.observation_id =
            monero_rpc_bridge_height_observation_id(&observation.identity_record());
        observation.validate()?;
        Ok(observation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_daemon_height_observation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "observed_at_l2_height": self.observed_at_l2_height,
            "daemon_height": self.daemon_height,
            "block_hash": self.block_hash,
            "previous_block_hash": self.previous_block_hash,
            "cumulative_difficulty_root": self.cumulative_difficulty_root,
            "txpool_size": self.txpool_size,
            "pruning_seed": self.pruning_seed,
            "response_root": self.response_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_daemon_height_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "endpoint_id": self.endpoint_id,
            "observed_at_l2_height": self.observed_at_l2_height,
            "daemon_height": self.daemon_height,
            "block_hash": self.block_hash,
            "previous_block_hash": self.previous_block_hash,
            "cumulative_difficulty_root": self.cumulative_difficulty_root,
            "txpool_size": self.txpool_size,
            "pruning_seed": self.pruning_seed,
            "response_root": self.response_root,
            "status": self.status.as_str(),
        })
    }

    pub fn observation_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-HEIGHT-OBSERVATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "observation_root",
            self.observation_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.observation_id, "monero rpc height observation id")?;
        ensure_non_empty(&self.endpoint_id, "monero rpc height observation endpoint")?;
        ensure_non_empty(&self.block_hash, "monero rpc height block hash")?;
        ensure_non_empty(
            &self.previous_block_hash,
            "monero rpc height previous block hash",
        )?;
        ensure_non_empty(
            &self.cumulative_difficulty_root,
            "monero rpc height difficulty root",
        )?;
        ensure_non_empty(&self.response_root, "monero rpc height response root")?;
        let computed = monero_rpc_bridge_height_observation_id(&self.identity_record());
        if self.observation_id != computed {
            return Err("monero rpc height observation id mismatch".to_string());
        }
        Ok(self.observation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRpcRequest {
    pub request_id: String,
    pub request_kind: WalletRequestKind,
    pub requester_commitment: String,
    pub profile_commitment: String,
    pub view_key_commitment: String,
    pub address_set_root: String,
    pub key_image_root: String,
    pub output_root: String,
    pub from_monero_height: u64,
    pub to_monero_height: u64,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub sponsorship_id: Option<String>,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub status: WalletRequestStatus,
}

impl WalletRpcRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_kind: WalletRequestKind,
        requester_label: impl Into<String>,
        profile_label: impl Into<String>,
        view_key_label: impl Into<String>,
        addresses: &[String],
        key_images: &[String],
        output_labels: &[String],
        from_monero_height: u64,
        to_monero_height: u64,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        sponsorship_id: Option<String>,
        requested_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroRpcBridgeResult<Self> {
        let requester_label = requester_label.into();
        let profile_label = profile_label.into();
        let view_key_label = view_key_label.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&requester_label, "monero rpc wallet requester")?;
        ensure_non_empty(&profile_label, "monero rpc wallet profile")?;
        ensure_non_empty(&view_key_label, "monero rpc wallet view key")?;
        ensure_non_empty(&fee_asset_id, "monero rpc wallet fee asset")?;
        ensure_positive(ttl_blocks, "monero rpc wallet request ttl")?;
        ensure_ordered_window(
            from_monero_height,
            to_monero_height,
            "monero rpc wallet request scan range",
        )?;
        let requester_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-WALLET-REQUESTER", &requester_label);
        let profile_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-WALLET-PROFILE", &profile_label);
        let view_key_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-WALLET-VIEW-KEY", &view_key_label);
        let address_set_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-WALLET-ADDRESS", addresses);
        let key_image_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-WALLET-KEY-IMAGE", key_images);
        let output_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-WALLET-OUTPUT", output_labels);
        let mut request = Self {
            request_id: String::new(),
            request_kind,
            requester_commitment,
            profile_commitment,
            view_key_commitment,
            address_set_root,
            key_image_root,
            output_root,
            from_monero_height,
            to_monero_height,
            fee_asset_id,
            max_fee_units,
            sponsorship_id,
            requested_at_height,
            expires_at_height: requested_at_height.saturating_add(ttl_blocks),
            status: WalletRequestStatus::Queued,
        };
        request.request_id = monero_rpc_bridge_wallet_request_id(&request.identity_record());
        request.validate()?;
        Ok(request)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_wallet_rpc_request_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "request_kind": self.request_kind.as_str(),
            "requester_commitment": self.requester_commitment,
            "profile_commitment": self.profile_commitment,
            "view_key_commitment": self.view_key_commitment,
            "address_set_root": self.address_set_root,
            "key_image_root": self.key_image_root,
            "output_root": self.output_root,
            "from_monero_height": self.from_monero_height,
            "to_monero_height": self.to_monero_height,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "sponsorship_id": self.sponsorship_id,
            "requested_at_height": self.requested_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_wallet_rpc_request",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "request_kind": self.request_kind.as_str(),
            "requester_commitment": self.requester_commitment,
            "profile_commitment": self.profile_commitment,
            "view_key_commitment": self.view_key_commitment,
            "address_set_root": self.address_set_root,
            "key_image_root": self.key_image_root,
            "output_root": self.output_root,
            "from_monero_height": self.from_monero_height,
            "to_monero_height": self.to_monero_height,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "sponsorship_id": self.sponsorship_id,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn request_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-WALLET-REQUEST",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "request_root",
            self.request_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.request_id, "monero rpc wallet request id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "monero rpc wallet requester commitment",
        )?;
        ensure_non_empty(
            &self.profile_commitment,
            "monero rpc wallet profile commitment",
        )?;
        ensure_non_empty(
            &self.view_key_commitment,
            "monero rpc wallet view key commitment",
        )?;
        ensure_non_empty(&self.address_set_root, "monero rpc wallet address root")?;
        ensure_non_empty(&self.key_image_root, "monero rpc wallet key image root")?;
        ensure_non_empty(&self.output_root, "monero rpc wallet output root")?;
        ensure_non_empty(&self.fee_asset_id, "monero rpc wallet fee asset")?;
        ensure_ordered_window(
            self.from_monero_height,
            self.to_monero_height,
            "monero rpc wallet request range",
        )?;
        if self.expires_at_height <= self.requested_at_height {
            return Err("monero rpc wallet request expiry must be after request".to_string());
        }
        let computed = monero_rpc_bridge_wallet_request_id(&self.identity_record());
        if self.request_id != computed {
            return Err("monero rpc wallet request id mismatch".to_string());
        }
        Ok(self.request_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewOnlyWalletSyncJob {
    pub job_id: String,
    pub request_id: String,
    pub profile_commitment: String,
    pub client_commitment: String,
    pub endpoint_quorum_root: String,
    pub from_monero_height: u64,
    pub to_monero_height: u64,
    pub checkpoint_root: String,
    pub candidate_output_root: String,
    pub scan_unit_count: u64,
    pub priority: u64,
    pub assigned_at_height: u64,
    pub expires_at_height: u64,
    pub result_root: String,
    pub status: ViewOnlySyncStatus,
}

impl ViewOnlyWalletSyncJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &WalletRpcRequest,
        client_label: impl Into<String>,
        endpoint_ids: &[String],
        checkpoint_payload: &Value,
        candidate_outputs: &[String],
        scan_unit_count: u64,
        priority: u64,
        assigned_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroRpcBridgeResult<Self> {
        let client_label = client_label.into();
        ensure_non_empty(&client_label, "monero rpc sync client")?;
        ensure_positive(scan_unit_count, "monero rpc sync scan units")?;
        ensure_positive(ttl_blocks, "monero rpc sync ttl")?;
        ensure_string_set(endpoint_ids, "monero rpc sync endpoint quorum")?;
        let client_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-SYNC-CLIENT", &client_label);
        let endpoint_quorum_root = monero_rpc_bridge_string_set_root(
            "MONERO-RPC-BRIDGE-SYNC-ENDPOINT-QUORUM",
            endpoint_ids,
        );
        let checkpoint_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-SYNC-CHECKPOINT", checkpoint_payload);
        let candidate_output_root = monero_rpc_bridge_string_set_root(
            "MONERO-RPC-BRIDGE-SYNC-CANDIDATE-OUTPUT",
            candidate_outputs,
        );
        let mut job = Self {
            job_id: String::new(),
            request_id: request.request_id.clone(),
            profile_commitment: request.profile_commitment.clone(),
            client_commitment,
            endpoint_quorum_root,
            from_monero_height: request.from_monero_height,
            to_monero_height: request.to_monero_height,
            checkpoint_root,
            candidate_output_root,
            scan_unit_count,
            priority,
            assigned_at_height,
            expires_at_height: assigned_at_height.saturating_add(ttl_blocks),
            result_root: monero_rpc_bridge_payload_root(
                "MONERO-RPC-BRIDGE-SYNC-EMPTY-RESULT",
                &json!({"status": "pending"}),
            ),
            status: ViewOnlySyncStatus::Queued,
        };
        job.job_id = monero_rpc_bridge_view_sync_job_id(&job.identity_record());
        job.validate()?;
        Ok(job)
    }

    pub fn seal(&mut self, result_payload: &Value) -> MoneroRpcBridgeResult<String> {
        self.result_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-SYNC-RESULT", result_payload);
        self.status = ViewOnlySyncStatus::Sealed;
        self.validate()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_view_only_wallet_sync_job_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "profile_commitment": self.profile_commitment,
            "client_commitment": self.client_commitment,
            "endpoint_quorum_root": self.endpoint_quorum_root,
            "from_monero_height": self.from_monero_height,
            "to_monero_height": self.to_monero_height,
            "checkpoint_root": self.checkpoint_root,
            "candidate_output_root": self.candidate_output_root,
            "scan_unit_count": self.scan_unit_count,
            "priority": self.priority,
            "assigned_at_height": self.assigned_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_view_only_wallet_sync_job",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "job_id": self.job_id,
            "request_id": self.request_id,
            "profile_commitment": self.profile_commitment,
            "client_commitment": self.client_commitment,
            "endpoint_quorum_root": self.endpoint_quorum_root,
            "from_monero_height": self.from_monero_height,
            "to_monero_height": self.to_monero_height,
            "checkpoint_root": self.checkpoint_root,
            "candidate_output_root": self.candidate_output_root,
            "scan_unit_count": self.scan_unit_count,
            "priority": self.priority,
            "assigned_at_height": self.assigned_at_height,
            "expires_at_height": self.expires_at_height,
            "result_root": self.result_root,
            "status": self.status.as_str(),
        })
    }

    pub fn job_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-VIEW-SYNC-JOB",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "job_root",
            self.job_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.job_id, "monero rpc sync job id")?;
        ensure_non_empty(&self.request_id, "monero rpc sync request id")?;
        ensure_non_empty(&self.profile_commitment, "monero rpc sync profile")?;
        ensure_non_empty(&self.client_commitment, "monero rpc sync client")?;
        ensure_non_empty(
            &self.endpoint_quorum_root,
            "monero rpc sync endpoint quorum",
        )?;
        ensure_non_empty(&self.checkpoint_root, "monero rpc sync checkpoint")?;
        ensure_non_empty(
            &self.candidate_output_root,
            "monero rpc sync candidate root",
        )?;
        ensure_non_empty(&self.result_root, "monero rpc sync result root")?;
        ensure_positive(self.scan_unit_count, "monero rpc sync scan units")?;
        ensure_ordered_window(
            self.from_monero_height,
            self.to_monero_height,
            "monero rpc sync range",
        )?;
        if self.expires_at_height <= self.assigned_at_height {
            return Err("monero rpc sync expiry must be after assignment".to_string());
        }
        let computed = monero_rpc_bridge_view_sync_job_id(&self.identity_record());
        if self.job_id != computed {
            return Err("monero rpc sync job id mismatch".to_string());
        }
        Ok(self.job_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeObservationTicket {
    pub ticket_id: String,
    pub ticket_kind: BridgeTicketKind,
    pub account_commitment: String,
    pub monero_txid_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub amount_bucket: u64,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub nullifier_root: String,
    pub wallet_request_id: Option<String>,
    pub observed_endpoint_root: String,
    pub confirmations: u64,
    pub finality_height: u64,
    pub created_at_height: u64,
    pub status: BridgeTicketStatus,
}

impl BridgeObservationTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_kind: BridgeTicketKind,
        account_label: impl Into<String>,
        monero_txid: impl Into<String>,
        block_height: u64,
        block_hash: impl Into<String>,
        amount_units: u64,
        output_labels: &[String],
        key_images: &[String],
        nullifier_label: impl Into<String>,
        wallet_request_id: Option<String>,
        endpoint_ids: &[String],
        observed_tip_height: u64,
        finality_depth: u64,
        created_at_height: u64,
    ) -> MoneroRpcBridgeResult<Self> {
        let account_label = account_label.into();
        let monero_txid = monero_txid.into();
        let block_hash = block_hash.into();
        let nullifier_label = nullifier_label.into();
        ensure_non_empty(&account_label, "monero rpc bridge ticket account")?;
        ensure_non_empty(&monero_txid, "monero rpc bridge ticket txid")?;
        ensure_non_empty(&block_hash, "monero rpc bridge ticket block hash")?;
        ensure_non_empty(&nullifier_label, "monero rpc bridge ticket nullifier")?;
        ensure_positive(finality_depth, "monero rpc bridge ticket finality")?;
        ensure_string_set(endpoint_ids, "monero rpc bridge ticket endpoints")?;
        let account_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-TICKET-ACCOUNT", &account_label);
        let monero_txid_hash =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-TICKET-TXID", &monero_txid);
        let output_commitment_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-TICKET-OUTPUT", output_labels);
        let key_image_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-TICKET-KEY-IMAGE", key_images);
        let nullifier_root =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-TICKET-NULLIFIER", &nullifier_label);
        let observed_endpoint_root =
            monero_rpc_bridge_string_set_root("MONERO-RPC-BRIDGE-TICKET-ENDPOINT", endpoint_ids);
        let confirmations = confirmations(observed_tip_height, block_height);
        let finality_height = block_height.saturating_add(finality_depth.saturating_sub(1));
        let status = if confirmations >= finality_depth {
            BridgeTicketStatus::Matched
        } else {
            BridgeTicketStatus::PendingFinality
        };
        let mut ticket = Self {
            ticket_id: String::new(),
            ticket_kind,
            account_commitment,
            monero_txid_hash,
            block_height,
            block_hash,
            amount_bucket: monero_rpc_bridge_amount_bucket(amount_units),
            output_commitment_root,
            key_image_root,
            nullifier_root,
            wallet_request_id,
            observed_endpoint_root,
            confirmations,
            finality_height,
            created_at_height,
            status,
        };
        ticket.ticket_id = monero_rpc_bridge_bridge_ticket_id(&ticket.identity_record());
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn set_tip_height(&mut self, tip_height: u64) {
        self.confirmations = confirmations(tip_height, self.block_height);
        if self.status == BridgeTicketStatus::PendingFinality && tip_height >= self.finality_height
        {
            self.status = BridgeTicketStatus::Matched;
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_observation_ticket_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "ticket_kind": self.ticket_kind.as_str(),
            "account_commitment": self.account_commitment,
            "monero_txid_hash": self.monero_txid_hash,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "amount_bucket": self.amount_bucket,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "nullifier_root": self.nullifier_root,
            "wallet_request_id": self.wallet_request_id,
            "observed_endpoint_root": self.observed_endpoint_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_observation_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "ticket_kind": self.ticket_kind.as_str(),
            "account_commitment": self.account_commitment,
            "monero_txid_hash": self.monero_txid_hash,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "amount_bucket": self.amount_bucket,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "nullifier_root": self.nullifier_root,
            "wallet_request_id": self.wallet_request_id,
            "observed_endpoint_root": self.observed_endpoint_root,
            "confirmations": self.confirmations,
            "finality_height": self.finality_height,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn ticket_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-BRIDGE-TICKET",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "ticket_root",
            self.ticket_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.ticket_id, "monero rpc bridge ticket id")?;
        ensure_non_empty(&self.account_commitment, "monero rpc bridge ticket account")?;
        ensure_non_empty(&self.monero_txid_hash, "monero rpc bridge ticket txid")?;
        ensure_non_empty(&self.block_hash, "monero rpc bridge ticket block hash")?;
        ensure_non_empty(
            &self.output_commitment_root,
            "monero rpc bridge ticket output root",
        )?;
        ensure_non_empty(
            &self.key_image_root,
            "monero rpc bridge ticket key image root",
        )?;
        ensure_non_empty(
            &self.nullifier_root,
            "monero rpc bridge ticket nullifier root",
        )?;
        ensure_non_empty(
            &self.observed_endpoint_root,
            "monero rpc bridge ticket endpoint root",
        )?;
        if self.finality_height < self.block_height {
            return Err("monero rpc bridge ticket finality precedes block".to_string());
        }
        let computed = monero_rpc_bridge_bridge_ticket_id(&self.identity_record());
        if self.ticket_id != computed {
            return Err("monero rpc bridge ticket id mismatch".to_string());
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgEvidence {
    pub evidence_id: String,
    pub evidence_kind: ReorgEvidenceKind,
    pub endpoint_id: String,
    pub old_height: u64,
    pub old_block_hash: String,
    pub new_height: u64,
    pub new_block_hash: String,
    pub affected_ticket_root: String,
    pub affected_request_root: String,
    pub proof_root: String,
    pub reporter_commitment: String,
    pub reported_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ReorgEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: ReorgEvidenceKind,
        endpoint_id: impl Into<String>,
        old_height: u64,
        old_block_hash: impl Into<String>,
        new_height: u64,
        new_block_hash: impl Into<String>,
        affected_ticket_ids: &[String],
        affected_request_ids: &[String],
        proof_payload: &Value,
        reporter_label: impl Into<String>,
        reported_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroRpcBridgeResult<Self> {
        let endpoint_id = endpoint_id.into();
        let old_block_hash = old_block_hash.into();
        let new_block_hash = new_block_hash.into();
        let reporter_label = reporter_label.into();
        ensure_non_empty(&endpoint_id, "monero rpc reorg endpoint")?;
        ensure_non_empty(&old_block_hash, "monero rpc reorg old block hash")?;
        ensure_non_empty(&new_block_hash, "monero rpc reorg new block hash")?;
        ensure_non_empty(&reporter_label, "monero rpc reorg reporter")?;
        ensure_positive(ttl_blocks, "monero rpc reorg ttl")?;
        let affected_ticket_root = monero_rpc_bridge_string_set_root(
            "MONERO-RPC-BRIDGE-REORG-AFFECTED-TICKET",
            affected_ticket_ids,
        );
        let affected_request_root = monero_rpc_bridge_string_set_root(
            "MONERO-RPC-BRIDGE-REORG-AFFECTED-REQUEST",
            affected_request_ids,
        );
        let proof_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-REORG-PROOF", proof_payload);
        let reporter_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-REORG-REPORTER", &reporter_label);
        let mut evidence = Self {
            evidence_id: String::new(),
            evidence_kind,
            endpoint_id,
            old_height,
            old_block_hash,
            new_height,
            new_block_hash,
            affected_ticket_root,
            affected_request_root,
            proof_root,
            reporter_commitment,
            reported_at_height,
            expires_at_height: reported_at_height.saturating_add(ttl_blocks),
            status: "reported".to_string(),
        };
        evidence.evidence_id = monero_rpc_bridge_reorg_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_reorg_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "evidence_kind": self.evidence_kind.as_str(),
            "endpoint_id": self.endpoint_id,
            "old_height": self.old_height,
            "old_block_hash": self.old_block_hash,
            "new_height": self.new_height,
            "new_block_hash": self.new_block_hash,
            "affected_ticket_root": self.affected_ticket_root,
            "affected_request_root": self.affected_request_root,
            "proof_root": self.proof_root,
            "reporter_commitment": self.reporter_commitment,
            "reported_at_height": self.reported_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_reorg_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "endpoint_id": self.endpoint_id,
            "old_height": self.old_height,
            "old_block_hash": self.old_block_hash,
            "new_height": self.new_height,
            "new_block_hash": self.new_block_hash,
            "affected_ticket_root": self.affected_ticket_root,
            "affected_request_root": self.affected_request_root,
            "proof_root": self.proof_root,
            "reporter_commitment": self.reporter_commitment,
            "reported_at_height": self.reported_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn evidence_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-REORG-EVIDENCE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "evidence_root",
            self.evidence_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.evidence_id, "monero rpc reorg evidence id")?;
        ensure_non_empty(&self.endpoint_id, "monero rpc reorg endpoint")?;
        ensure_non_empty(&self.old_block_hash, "monero rpc reorg old block hash")?;
        ensure_non_empty(&self.new_block_hash, "monero rpc reorg new block hash")?;
        ensure_non_empty(&self.affected_ticket_root, "monero rpc reorg ticket root")?;
        ensure_non_empty(&self.affected_request_root, "monero rpc reorg request root")?;
        ensure_non_empty(&self.proof_root, "monero rpc reorg proof root")?;
        ensure_non_empty(&self.reporter_commitment, "monero rpc reorg reporter")?;
        if self.old_height == self.new_height && self.old_block_hash == self.new_block_hash {
            return Err("monero rpc reorg evidence does not describe a conflict".to_string());
        }
        if self.expires_at_height <= self.reported_at_height {
            return Err("monero rpc reorg evidence expiry must be after report".to_string());
        }
        let computed = monero_rpc_bridge_reorg_evidence_id(&self.identity_record());
        if self.evidence_id != computed {
            return Err("monero rpc reorg evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointFailoverEvent {
    pub failover_id: String,
    pub decision_kind: FailoverDecisionKind,
    pub from_endpoint_id: Option<String>,
    pub to_endpoint_id: Option<String>,
    pub reason_root: String,
    pub quorum_root: String,
    pub health_root: String,
    pub decided_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl EndpointFailoverEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        decision_kind: FailoverDecisionKind,
        from_endpoint_id: Option<String>,
        to_endpoint_id: Option<String>,
        reason_payload: &Value,
        quorum_root: impl Into<String>,
        health_root: impl Into<String>,
        decided_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroRpcBridgeResult<Self> {
        let quorum_root = quorum_root.into();
        let health_root = health_root.into();
        ensure_non_empty(&quorum_root, "monero rpc failover quorum root")?;
        ensure_non_empty(&health_root, "monero rpc failover health root")?;
        ensure_positive(ttl_blocks, "monero rpc failover ttl")?;
        let reason_root =
            monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-FAILOVER-REASON", reason_payload);
        let mut event = Self {
            failover_id: String::new(),
            decision_kind,
            from_endpoint_id,
            to_endpoint_id,
            reason_root,
            quorum_root,
            health_root,
            decided_at_height,
            expires_at_height: decided_at_height.saturating_add(ttl_blocks),
            status: "applied".to_string(),
        };
        event.failover_id = monero_rpc_bridge_failover_event_id(&event.identity_record());
        event.validate()?;
        Ok(event)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_failover_event_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "decision_kind": self.decision_kind.as_str(),
            "from_endpoint_id": self.from_endpoint_id,
            "to_endpoint_id": self.to_endpoint_id,
            "reason_root": self.reason_root,
            "quorum_root": self.quorum_root,
            "health_root": self.health_root,
            "decided_at_height": self.decided_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_failover_event",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "failover_id": self.failover_id,
            "decision_kind": self.decision_kind.as_str(),
            "from_endpoint_id": self.from_endpoint_id,
            "to_endpoint_id": self.to_endpoint_id,
            "reason_root": self.reason_root,
            "quorum_root": self.quorum_root,
            "health_root": self.health_root,
            "decided_at_height": self.decided_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn failover_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-FAILOVER-EVENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "failover_root",
            self.failover_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.failover_id, "monero rpc failover id")?;
        ensure_non_empty(&self.reason_root, "monero rpc failover reason root")?;
        ensure_non_empty(&self.quorum_root, "monero rpc failover quorum root")?;
        ensure_non_empty(&self.health_root, "monero rpc failover health root")?;
        if self.expires_at_height <= self.decided_at_height {
            return Err("monero rpc failover expiry must be after decision".to_string());
        }
        let computed = monero_rpc_bridge_failover_event_id(&self.identity_record());
        if self.failover_id != computed {
            return Err("monero rpc failover id mismatch".to_string());
        }
        Ok(self.failover_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeScanSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: Option<String>,
    pub fee_asset_id: String,
    pub max_scan_units: u64,
    pub reserved_scan_units: u64,
    pub consumed_scan_units: u64,
    pub max_fee_units: u64,
    pub fee_rate_micro_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub settlement_root: String,
    pub status: SponsorshipStatus,
}

impl LowFeeScanSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: impl Into<String>,
        beneficiary_label: Option<String>,
        fee_asset_id: impl Into<String>,
        max_scan_units: u64,
        max_fee_units: u64,
        fee_rate_micro_units: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroRpcBridgeResult<Self> {
        let sponsor_label = sponsor_label.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&sponsor_label, "monero rpc sponsorship sponsor")?;
        ensure_non_empty(&fee_asset_id, "monero rpc sponsorship fee asset")?;
        ensure_positive(max_scan_units, "monero rpc sponsorship scan units")?;
        ensure_positive(max_fee_units, "monero rpc sponsorship fee units")?;
        ensure_positive(fee_rate_micro_units, "monero rpc sponsorship fee rate")?;
        ensure_positive(ttl_blocks, "monero rpc sponsorship ttl")?;
        let sponsor_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-SPONSOR", &sponsor_label);
        let beneficiary_commitment = match beneficiary_label {
            Some(label) => {
                ensure_non_empty(&label, "monero rpc sponsorship beneficiary")?;
                Some(monero_rpc_bridge_string_root(
                    "MONERO-RPC-BRIDGE-SPONSOR-BENEFICIARY",
                    &label,
                ))
            }
            None => None,
        };
        let mut sponsorship = Self {
            sponsorship_id: String::new(),
            sponsor_commitment,
            beneficiary_commitment,
            fee_asset_id,
            max_scan_units,
            reserved_scan_units: 0,
            consumed_scan_units: 0,
            max_fee_units,
            fee_rate_micro_units,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            settlement_root: monero_rpc_bridge_payload_root(
                "MONERO-RPC-BRIDGE-SPONSORSHIP-EMPTY-SETTLEMENT",
                &json!({"status": "open"}),
            ),
            status: SponsorshipStatus::Offered,
        };
        sponsorship.sponsorship_id =
            monero_rpc_bridge_scan_sponsorship_id(&sponsorship.identity_record());
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn remaining_scan_units(&self) -> u64 {
        self.max_scan_units.saturating_sub(self.reserved_scan_units)
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(
            self.consumed_scan_units
                .saturating_mul(self.fee_rate_micro_units),
        )
    }

    pub fn reserve_units(&mut self, units: u64) -> MoneroRpcBridgeResult<String> {
        ensure_positive(units, "monero rpc sponsorship reserve units")?;
        if units > self.remaining_scan_units() {
            return Err("monero rpc sponsorship reserve exceeds available units".to_string());
        }
        self.reserved_scan_units = self.reserved_scan_units.saturating_add(units);
        self.status = SponsorshipStatus::Reserved;
        self.validate()
    }

    pub fn consume_units(
        &mut self,
        units: u64,
        settlement_payload: &Value,
    ) -> MoneroRpcBridgeResult<String> {
        ensure_positive(units, "monero rpc sponsorship consume units")?;
        let next = self.consumed_scan_units.saturating_add(units);
        if next > self.reserved_scan_units {
            return Err("monero rpc sponsorship consumed units exceed reserved units".to_string());
        }
        let fee_units = next.saturating_mul(self.fee_rate_micro_units);
        if fee_units > self.max_fee_units {
            return Err("monero rpc sponsorship consumed fee exceeds max".to_string());
        }
        self.consumed_scan_units = next;
        self.settlement_root = monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-SPONSORSHIP-SETTLEMENT",
            settlement_payload,
        );
        self.status = if self.consumed_scan_units == self.max_scan_units {
            SponsorshipStatus::Settled
        } else {
            SponsorshipStatus::Consumed
        };
        self.validate()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_low_fee_scan_sponsorship_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_scan_units": self.max_scan_units,
            "max_fee_units": self.max_fee_units,
            "fee_rate_micro_units": self.fee_rate_micro_units,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_low_fee_scan_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_scan_units": self.max_scan_units,
            "reserved_scan_units": self.reserved_scan_units,
            "consumed_scan_units": self.consumed_scan_units,
            "remaining_scan_units": self.remaining_scan_units(),
            "max_fee_units": self.max_fee_units,
            "fee_rate_micro_units": self.fee_rate_micro_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "settlement_root": self.settlement_root,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-SCAN-SPONSORSHIP",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "sponsorship_root",
            self.sponsorship_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.sponsorship_id, "monero rpc sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "monero rpc sponsorship sponsor")?;
        ensure_non_empty(&self.fee_asset_id, "monero rpc sponsorship fee asset")?;
        ensure_non_empty(&self.settlement_root, "monero rpc sponsorship settlement")?;
        ensure_positive(self.max_scan_units, "monero rpc sponsorship max scan units")?;
        ensure_positive(self.max_fee_units, "monero rpc sponsorship max fee units")?;
        ensure_positive(self.fee_rate_micro_units, "monero rpc sponsorship fee rate")?;
        if self.reserved_scan_units > self.max_scan_units {
            return Err("monero rpc sponsorship reserved units exceed max".to_string());
        }
        if self.consumed_scan_units > self.reserved_scan_units {
            return Err("monero rpc sponsorship consumed units exceed reserved".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("monero rpc sponsorship expiry must be after creation".to_string());
        }
        let computed = monero_rpc_bridge_scan_sponsorship_id(&self.identity_record());
        if self.sponsorship_id != computed {
            return Err("monero rpc sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureSummary {
    pub summary_id: String,
    pub scope: DisclosureScope,
    pub subject_id: String,
    pub subject_root: String,
    pub disclosed_field_root: String,
    pub redaction_root: String,
    pub recipient_commitment: String,
    pub prepared_at_height: u64,
    pub expires_at_height: u64,
    pub min_anonymity_set: u64,
    pub status: DisclosureStatus,
}

impl DisclosureSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DisclosureScope,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        disclosed_fields: &[String],
        redaction_payload: &Value,
        recipient_label: impl Into<String>,
        prepared_at_height: u64,
        ttl_blocks: u64,
        min_anonymity_set: u64,
    ) -> MoneroRpcBridgeResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let recipient_label = recipient_label.into();
        ensure_non_empty(&subject_id, "monero rpc disclosure subject id")?;
        ensure_non_empty(&subject_root, "monero rpc disclosure subject root")?;
        ensure_non_empty(&recipient_label, "monero rpc disclosure recipient")?;
        ensure_positive(ttl_blocks, "monero rpc disclosure ttl")?;
        ensure_positive(min_anonymity_set, "monero rpc disclosure anonymity set")?;
        let disclosed_field_root = monero_rpc_bridge_string_set_root(
            "MONERO-RPC-BRIDGE-DISCLOSURE-FIELD",
            disclosed_fields,
        );
        let redaction_root = monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-DISCLOSURE-REDACTION",
            redaction_payload,
        );
        let recipient_commitment = monero_rpc_bridge_string_root(
            "MONERO-RPC-BRIDGE-DISCLOSURE-RECIPIENT",
            &recipient_label,
        );
        let mut summary = Self {
            summary_id: String::new(),
            scope,
            subject_id,
            subject_root,
            disclosed_field_root,
            redaction_root,
            recipient_commitment,
            prepared_at_height,
            expires_at_height: prepared_at_height.saturating_add(ttl_blocks),
            min_anonymity_set,
            status: DisclosureStatus::Prepared,
        };
        summary.summary_id = monero_rpc_bridge_disclosure_summary_id(&summary.identity_record());
        summary.validate()?;
        Ok(summary)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_disclosure_summary_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "disclosed_field_root": self.disclosed_field_root,
            "redaction_root": self.redaction_root,
            "recipient_commitment": self.recipient_commitment,
            "prepared_at_height": self.prepared_at_height,
            "min_anonymity_set": self.min_anonymity_set,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_disclosure_summary",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "summary_id": self.summary_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "disclosed_field_root": self.disclosed_field_root,
            "redaction_root": self.redaction_root,
            "recipient_commitment": self.recipient_commitment,
            "prepared_at_height": self.prepared_at_height,
            "expires_at_height": self.expires_at_height,
            "min_anonymity_set": self.min_anonymity_set,
            "status": self.status.as_str(),
        })
    }

    pub fn summary_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-DISCLOSURE-SUMMARY",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "summary_root",
            self.summary_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.summary_id, "monero rpc disclosure summary id")?;
        ensure_non_empty(&self.subject_id, "monero rpc disclosure subject id")?;
        ensure_non_empty(&self.subject_root, "monero rpc disclosure subject root")?;
        ensure_non_empty(
            &self.disclosed_field_root,
            "monero rpc disclosure field root",
        )?;
        ensure_non_empty(&self.redaction_root, "monero rpc disclosure redaction root")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "monero rpc disclosure recipient",
        )?;
        ensure_positive(
            self.min_anonymity_set,
            "monero rpc disclosure anonymity set",
        )?;
        if self.expires_at_height <= self.prepared_at_height {
            return Err("monero rpc disclosure expiry must be after preparation".to_string());
        }
        let computed = monero_rpc_bridge_disclosure_summary_id(&self.identity_record());
        if self.summary_id != computed {
            return Err("monero rpc disclosure summary id mismatch".to_string());
        }
        Ok(self.summary_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRpcAttestation {
    pub attestation_id: String,
    pub subject_kind: PqAttestationSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_commitment: String,
    pub operator_commitment: String,
    pub pq_scheme: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub security_bits: u16,
    pub status: PqAttestationStatus,
}

impl PqRpcAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: PqAttestationSubject,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        signer_label: impl Into<String>,
        operator_label: impl Into<String>,
        pq_scheme: impl Into<String>,
        pq_public_key_material: impl Into<String>,
        signature_material: impl Into<String>,
        signed_at_height: u64,
        ttl_blocks: u64,
        security_bits: u16,
        threshold_met: bool,
    ) -> MoneroRpcBridgeResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let signer_label = signer_label.into();
        let operator_label = operator_label.into();
        let pq_scheme = pq_scheme.into();
        let pq_public_key_material = pq_public_key_material.into();
        let signature_material = signature_material.into();
        ensure_non_empty(&subject_id, "monero rpc pq attestation subject id")?;
        ensure_non_empty(&subject_root, "monero rpc pq attestation subject root")?;
        ensure_non_empty(&signer_label, "monero rpc pq attestation signer")?;
        ensure_non_empty(&operator_label, "monero rpc pq attestation operator")?;
        ensure_non_empty(&pq_scheme, "monero rpc pq attestation scheme")?;
        ensure_non_empty(
            &pq_public_key_material,
            "monero rpc pq attestation public key",
        )?;
        ensure_non_empty(&signature_material, "monero rpc pq attestation signature")?;
        ensure_positive(ttl_blocks, "monero rpc pq attestation ttl")?;
        let signer_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-PQ-SIGNER", &signer_label);
        let operator_commitment =
            monero_rpc_bridge_string_root("MONERO-RPC-BRIDGE-PQ-OPERATOR", &operator_label);
        let pq_public_key_root = monero_rpc_bridge_string_root(
            "MONERO-RPC-BRIDGE-PQ-PUBLIC-KEY",
            &pq_public_key_material,
        );
        let signature_root = monero_rpc_bridge_pq_signature_root(
            subject_kind,
            &subject_id,
            &subject_root,
            &signer_commitment,
            &pq_scheme,
            &signature_material,
        );
        let mut attestation = Self {
            attestation_id: String::new(),
            subject_kind,
            subject_id,
            subject_root,
            signer_commitment,
            operator_commitment,
            pq_scheme,
            pq_public_key_root,
            signature_root,
            signed_at_height,
            expires_at_height: signed_at_height.saturating_add(ttl_blocks),
            security_bits,
            status: if threshold_met {
                PqAttestationStatus::ThresholdMet
            } else {
                PqAttestationStatus::Accepted
            },
        };
        attestation.attestation_id =
            monero_rpc_bridge_pq_attestation_id(&attestation.identity_record());
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_pq_attestation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "operator_commitment": self.operator_commitment,
            "pq_scheme": self.pq_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "security_bits": self.security_bits,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_pq_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "operator_commitment": self.operator_commitment,
            "pq_scheme": self.pq_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-PQ-ATTESTATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "attestation_root",
            self.attestation_root(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        ensure_non_empty(&self.attestation_id, "monero rpc pq attestation id")?;
        ensure_non_empty(&self.subject_id, "monero rpc pq attestation subject id")?;
        ensure_non_empty(&self.subject_root, "monero rpc pq attestation subject root")?;
        ensure_non_empty(&self.signer_commitment, "monero rpc pq attestation signer")?;
        ensure_non_empty(
            &self.operator_commitment,
            "monero rpc pq attestation operator",
        )?;
        ensure_non_empty(&self.pq_scheme, "monero rpc pq attestation scheme")?;
        ensure_non_empty(&self.pq_public_key_root, "monero rpc pq attestation key")?;
        ensure_non_empty(&self.signature_root, "monero rpc pq attestation signature")?;
        if self.security_bits < 128 {
            return Err("monero rpc pq attestation security bits too low".to_string());
        }
        if self.expires_at_height <= self.signed_at_height {
            return Err("monero rpc pq attestation expiry must be after signature".to_string());
        }
        let computed = monero_rpc_bridge_pq_attestation_id(&self.identity_record());
        if self.attestation_id != computed {
            return Err("monero rpc pq attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcBridgeCounters {
    pub height: u64,
    pub endpoint_count: u64,
    pub active_endpoint_count: u64,
    pub daemon_endpoint_count: u64,
    pub wallet_endpoint_count: u64,
    pub health_observation_count: u64,
    pub daemon_height_observation_count: u64,
    pub quorum_health_count: u64,
    pub wallet_request_count: u64,
    pub open_wallet_request_count: u64,
    pub sync_job_count: u64,
    pub active_sync_job_count: u64,
    pub bridge_ticket_count: u64,
    pub open_bridge_ticket_count: u64,
    pub reorg_evidence_count: u64,
    pub active_reorg_evidence_count: u64,
    pub failover_event_count: u64,
    pub scan_sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub sponsored_scan_units: u64,
    pub consumed_scan_units: u64,
    pub disclosure_summary_count: u64,
    pub active_disclosure_summary_count: u64,
    pub pq_attestation_count: u64,
    pub usable_pq_attestation_count: u64,
}

impl MoneroRpcBridgeCounters {
    pub fn counters_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-COUNTERS",
            &json!({
                "height": self.height,
                "endpoint_count": self.endpoint_count,
                "active_endpoint_count": self.active_endpoint_count,
                "daemon_endpoint_count": self.daemon_endpoint_count,
                "wallet_endpoint_count": self.wallet_endpoint_count,
                "health_observation_count": self.health_observation_count,
                "daemon_height_observation_count": self.daemon_height_observation_count,
                "quorum_health_count": self.quorum_health_count,
                "wallet_request_count": self.wallet_request_count,
                "open_wallet_request_count": self.open_wallet_request_count,
                "sync_job_count": self.sync_job_count,
                "active_sync_job_count": self.active_sync_job_count,
                "bridge_ticket_count": self.bridge_ticket_count,
                "open_bridge_ticket_count": self.open_bridge_ticket_count,
                "reorg_evidence_count": self.reorg_evidence_count,
                "active_reorg_evidence_count": self.active_reorg_evidence_count,
                "failover_event_count": self.failover_event_count,
                "scan_sponsorship_count": self.scan_sponsorship_count,
                "active_sponsorship_count": self.active_sponsorship_count,
                "sponsored_scan_units": self.sponsored_scan_units,
                "consumed_scan_units": self.consumed_scan_units,
                "disclosure_summary_count": self.disclosure_summary_count,
                "active_disclosure_summary_count": self.active_disclosure_summary_count,
                "pq_attestation_count": self.pq_attestation_count,
                "usable_pq_attestation_count": self.usable_pq_attestation_count,
            }),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            json!({
                "kind": "monero_rpc_bridge_counters",
                "chain_id": CHAIN_ID,
                "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
                "height": self.height,
                "endpoint_count": self.endpoint_count,
                "active_endpoint_count": self.active_endpoint_count,
                "daemon_endpoint_count": self.daemon_endpoint_count,
                "wallet_endpoint_count": self.wallet_endpoint_count,
                "health_observation_count": self.health_observation_count,
                "daemon_height_observation_count": self.daemon_height_observation_count,
                "quorum_health_count": self.quorum_health_count,
                "wallet_request_count": self.wallet_request_count,
                "open_wallet_request_count": self.open_wallet_request_count,
                "sync_job_count": self.sync_job_count,
                "active_sync_job_count": self.active_sync_job_count,
                "bridge_ticket_count": self.bridge_ticket_count,
                "open_bridge_ticket_count": self.open_bridge_ticket_count,
                "reorg_evidence_count": self.reorg_evidence_count,
                "active_reorg_evidence_count": self.active_reorg_evidence_count,
                "failover_event_count": self.failover_event_count,
                "scan_sponsorship_count": self.scan_sponsorship_count,
                "active_sponsorship_count": self.active_sponsorship_count,
                "sponsored_scan_units": self.sponsored_scan_units,
                "consumed_scan_units": self.consumed_scan_units,
                "disclosure_summary_count": self.disclosure_summary_count,
                "active_disclosure_summary_count": self.active_disclosure_summary_count,
                "pq_attestation_count": self.pq_attestation_count,
                "usable_pq_attestation_count": self.usable_pq_attestation_count,
            }),
            "counters_root",
            self.counters_root(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcBridgeRoots {
    pub config_root: String,
    pub endpoint_root: String,
    pub endpoint_health_root: String,
    pub quorum_health_root: String,
    pub daemon_height_observation_root: String,
    pub wallet_request_root: String,
    pub view_sync_job_root: String,
    pub bridge_ticket_root: String,
    pub reorg_evidence_root: String,
    pub failover_event_root: String,
    pub scan_sponsorship_root: String,
    pub disclosure_summary_root: String,
    pub pq_attestation_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl MoneroRpcBridgeRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_rpc_bridge_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "endpoint_root": self.endpoint_root,
            "endpoint_health_root": self.endpoint_health_root,
            "quorum_health_root": self.quorum_health_root,
            "daemon_height_observation_root": self.daemon_height_observation_root,
            "wallet_request_root": self.wallet_request_root,
            "view_sync_job_root": self.view_sync_job_root,
            "bridge_ticket_root": self.bridge_ticket_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "failover_event_root": self.failover_event_root,
            "scan_sponsorship_root": self.scan_sponsorship_root,
            "disclosure_summary_root": self.disclosure_summary_root,
            "pq_attestation_root": self.pq_attestation_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        monero_rpc_bridge_payload_root(
            "MONERO-RPC-BRIDGE-ROOTS",
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            with_root_field(
                self.public_record_without_state_root(),
                "roots_root",
                self.roots_root(),
            ),
            "state_root",
            self.state_root.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcBridgeState {
    pub height: u64,
    pub operator_label: String,
    pub network: String,
    pub config: MoneroRpcBridgeConfig,
    pub active_endpoint_id: Option<String>,
    pub endpoints: BTreeMap<String, MoneroRpcEndpoint>,
    pub endpoint_health: BTreeMap<String, RpcEndpointHealth>,
    pub quorum_health: BTreeMap<String, RpcQuorumHealth>,
    pub height_observations: BTreeMap<String, DaemonHeightObservation>,
    pub wallet_requests: BTreeMap<String, WalletRpcRequest>,
    pub view_sync_jobs: BTreeMap<String, ViewOnlyWalletSyncJob>,
    pub bridge_tickets: BTreeMap<String, BridgeObservationTicket>,
    pub reorg_evidence: BTreeMap<String, ReorgEvidence>,
    pub failover_events: BTreeMap<String, EndpointFailoverEvent>,
    pub scan_sponsorships: BTreeMap<String, LowFeeScanSponsorship>,
    pub disclosure_summaries: BTreeMap<String, DisclosureSummary>,
    pub pq_attestations: BTreeMap<String, PqRpcAttestation>,
}

impl MoneroRpcBridgeState {
    pub fn new(
        operator_label: impl Into<String>,
        config: MoneroRpcBridgeConfig,
    ) -> MoneroRpcBridgeResult<Self> {
        config.validate()?;
        let operator_label = operator_label.into();
        ensure_non_empty(&operator_label, "monero rpc bridge operator label")?;
        Ok(Self {
            height: 0,
            operator_label,
            network: config.network.clone(),
            config,
            active_endpoint_id: None,
            endpoints: BTreeMap::new(),
            endpoint_health: BTreeMap::new(),
            quorum_health: BTreeMap::new(),
            height_observations: BTreeMap::new(),
            wallet_requests: BTreeMap::new(),
            view_sync_jobs: BTreeMap::new(),
            bridge_tickets: BTreeMap::new(),
            reorg_evidence: BTreeMap::new(),
            failover_events: BTreeMap::new(),
            scan_sponsorships: BTreeMap::new(),
            disclosure_summaries: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
        })
    }

    pub fn devnet() -> MoneroRpcBridgeResult<Self> {
        let mut state = Self::new("devnet-monero-rpc-bridge", MoneroRpcBridgeConfig::default())?;
        state.set_height(64)?;

        let daemon_methods = vec![
            RpcMethodFamily::DaemonHeight,
            RpcMethodFamily::DaemonBlocks,
            RpcMethodFamily::DaemonTxPool,
            RpcMethodFamily::Health,
            RpcMethodFamily::Attestation,
        ];
        let wallet_methods = vec![
            RpcMethodFamily::WalletRefresh,
            RpcMethodFamily::WalletScan,
            RpcMethodFamily::WalletImport,
            RpcMethodFamily::WalletProof,
            RpcMethodFamily::ViewOnlySync,
            RpcMethodFamily::Health,
            RpcMethodFamily::Attestation,
        ];
        let daemon_a = state.insert_endpoint(MoneroRpcEndpoint::new(
            "devnet-daemon-a",
            RpcEndpointKind::Daemon,
            state.config.network.clone(),
            "operator-alpha",
            "http://monero-daemon-a.invalid:18081",
            &json!({"auth": "mutual_pq_token", "network_calls": false}),
            &json!({"tls": "pinned_commitment", "pq_hybrid": true}),
            &daemon_methods,
            0,
            2_904_064,
            "ml-dsa-87-daemon-a",
        )?)?;
        let daemon_b = state.insert_endpoint(MoneroRpcEndpoint::new(
            "devnet-daemon-b",
            RpcEndpointKind::Daemon,
            state.config.network.clone(),
            "operator-beta",
            "http://monero-daemon-b.invalid:18081",
            &json!({"auth": "mutual_pq_token", "network_calls": false}),
            &json!({"tls": "pinned_commitment", "pq_hybrid": true}),
            &daemon_methods,
            1,
            2_904_063,
            "ml-dsa-87-daemon-b",
        )?)?;
        let daemon_c = state.insert_endpoint(MoneroRpcEndpoint::new(
            "devnet-daemon-c",
            RpcEndpointKind::FailoverRelay,
            state.config.network.clone(),
            "operator-gamma",
            "http://monero-daemon-c.invalid:18081",
            &json!({"auth": "relay_pq_token", "network_calls": false}),
            &json!({"tls": "pinned_commitment", "pq_hybrid": true}),
            &daemon_methods,
            2,
            2_904_060,
            "ml-dsa-65-daemon-c",
        )?)?;
        let wallet_a = state.insert_endpoint(MoneroRpcEndpoint::new(
            "devnet-wallet-rpc-a",
            RpcEndpointKind::ViewOnlyWallet,
            state.config.network.clone(),
            "operator-alpha",
            "http://wallet-rpc-a.invalid:18083",
            &json!({"auth": "view_only_wallet_token", "network_calls": false}),
            &json!({"tls": "pinned_commitment", "pq_hybrid": true}),
            &wallet_methods,
            0,
            2_904_064,
            "ml-dsa-87-wallet-a",
        )?)?;
        let wallet_b = state.insert_endpoint(MoneroRpcEndpoint::new(
            "devnet-wallet-rpc-b",
            RpcEndpointKind::WalletRpcProxy,
            state.config.network.clone(),
            "operator-beta",
            "http://wallet-rpc-b.invalid:18083",
            &json!({"auth": "view_only_wallet_token", "network_calls": false}),
            &json!({"tls": "pinned_commitment", "pq_hybrid": true}),
            &wallet_methods,
            1,
            2_904_063,
            "ml-dsa-65-wallet-b",
        )?)?;

        for (endpoint_id, daemon_height, wallet_height, txpool_size, latency_ms, errors) in [
            (daemon_a.clone(), 2_904_064_u64, 0_u64, 4_u64, 38_u64, 0_u64),
            (daemon_b.clone(), 2_904_063_u64, 0_u64, 6_u64, 44_u64, 0_u64),
            (daemon_c.clone(), 2_904_060_u64, 0_u64, 9_u64, 91_u64, 1_u64),
            (
                wallet_a.clone(),
                2_904_064_u64,
                2_904_064_u64,
                0_u64,
                52_u64,
                0_u64,
            ),
            (
                wallet_b.clone(),
                2_904_063_u64,
                2_904_063_u64,
                0_u64,
                65_u64,
                0_u64,
            ),
        ] {
            let methods = if endpoint_id == wallet_a || endpoint_id == wallet_b {
                wallet_methods.clone()
            } else {
                daemon_methods.clone()
            };
            state.record_endpoint_health(
                &endpoint_id,
                daemon_height,
                wallet_height,
                txpool_size,
                latency_ms,
                errors,
                2_904_064,
                &methods,
                &json!({
                    "fixture": "devnet-health",
                    "height": daemon_height,
                    "wallet_height": wallet_height,
                    "no_network_call": true,
                }),
            )?;
        }

        state.observe_daemon_height(
            &daemon_a,
            2_904_064,
            "devnet-block-2904064-a",
            "devnet-block-2904063",
            &json!({"wide_difficulty": "00000000000000000000000000f0d00d"}),
            4,
            0,
            &json!({"method": "get_info", "fixture": true}),
            RpcEndpointStatus::Active,
        )?;
        state.observe_daemon_height(
            &daemon_b,
            2_904_063,
            "devnet-block-2904063",
            "devnet-block-2904062",
            &json!({"wide_difficulty": "00000000000000000000000000f0cf00"}),
            6,
            0,
            &json!({"method": "get_info", "fixture": true}),
            RpcEndpointStatus::Active,
        )?;

        let sponsorship_id = state.open_scan_sponsorship(
            "devnet-low-fee-pool",
            Some("devnet-alice".to_string()),
            MONERO_RPC_BRIDGE_DEVNET_FEE_ASSET_ID,
            64,
            2_000_000,
            MONERO_RPC_BRIDGE_DEFAULT_SCAN_UNIT_MICRO_FEE,
        )?;
        state.reserve_sponsored_scan_units(&sponsorship_id, 8)?;

        let scan_request_id = state.open_wallet_request(WalletRpcRequest::new(
            WalletRequestKind::ScanOutputs,
            "devnet-alice",
            "alice-view-profile",
            "alice-view-key",
            &["alice-address-0".to_string()],
            &[],
            &["scan-window-outputs".to_string()],
            2_904_040,
            2_904_064,
            MONERO_RPC_BRIDGE_DEVNET_FEE_ASSET_ID,
            200_000,
            Some(sponsorship_id.clone()),
            state.height,
            state.config.scan_request_ttl_blocks,
        )?)?;
        let import_request_id = state.open_wallet_request(WalletRpcRequest::new(
            WalletRequestKind::ImportKeyImages,
            "devnet-bridge-operator",
            "bridge-view-profile",
            "bridge-view-key",
            &["bridge-reserve-address-0".to_string()],
            &["withdrawal-key-image-0".to_string()],
            &["withdrawal-output-0".to_string()],
            2_904_050,
            2_904_064,
            MONERO_RPC_BRIDGE_DEVNET_FEE_ASSET_ID,
            120_000,
            None,
            state.height,
            state.config.import_request_ttl_blocks,
        )?)?;

        let sync_job_id = state.schedule_view_only_sync_job(
            &scan_request_id,
            "devnet-alice-view-client",
            &[wallet_a.clone(), wallet_b.clone()],
            &json!({
                "checkpoint": "alice-scan-2904040-2904064",
                "privacy": "view_tag_commitments_only",
            }),
            &[
                "candidate-output-a".to_string(),
                "candidate-output-b".to_string(),
            ],
            8,
            0,
        )?;
        state.seal_view_only_sync_job(
            &sync_job_id,
            &json!({
                "matched_outputs": 1,
                "candidate_root_only": true,
                "sponsorship_id": sponsorship_id,
            }),
        )?;
        state.consume_sponsored_scan_units(
            &sponsorship_id,
            8,
            &json!({"job_id": sync_job_id, "settlement": "devnet-low-fee-scan"}),
        )?;

        let deposit_ticket_id = state.open_bridge_ticket(BridgeObservationTicket::new(
            BridgeTicketKind::Deposit,
            "devnet-alice",
            "monero-deposit-tx-0",
            2_904_058,
            "devnet-block-2904058",
            85_000,
            &["deposit-output-0".to_string()],
            &[],
            "deposit-nullifier-0",
            Some(scan_request_id.clone()),
            &[daemon_a.clone(), daemon_b.clone()],
            2_904_064,
            state.config.finality_depth,
            state.height,
        )?)?;
        let withdrawal_ticket_id = state.open_bridge_ticket(BridgeObservationTicket::new(
            BridgeTicketKind::Withdrawal,
            "devnet-bob",
            "monero-withdrawal-tx-0",
            2_904_060,
            "devnet-block-2904060",
            42_000,
            &["withdrawal-output-0".to_string()],
            &["withdrawal-key-image-0".to_string()],
            "withdrawal-nullifier-0",
            Some(import_request_id.clone()),
            &[daemon_a.clone(), daemon_b.clone()],
            2_904_064,
            state.config.finality_depth,
            state.height,
        )?)?;

        let reorg_id = state.record_reorg_evidence(ReorgEvidence::new(
            ReorgEvidenceKind::BlockHashConflict,
            daemon_c.clone(),
            2_904_060,
            "devnet-block-2904060-alt",
            2_904_061,
            "devnet-block-2904061-main",
            &[withdrawal_ticket_id.clone()],
            &[import_request_id.clone()],
            &json!({
                "window": "two-block-soft-reorg",
                "redacted_headers": true,
                "preserves_tx_privacy": true,
            }),
            "devnet-watchtower-alpha",
            state.height,
            state.config.disclosure_ttl_blocks,
        )?)?;

        let latest_quorum_root = state.latest_quorum_root();
        let latest_health_root = monero_rpc_bridge_endpoint_health_collection_root(
            &state.endpoint_health.values().cloned().collect::<Vec<_>>(),
        );
        let failover_id = state.record_failover_event(EndpointFailoverEvent::new(
            FailoverDecisionKind::QuarantineEndpoint,
            Some(daemon_c.clone()),
            Some(daemon_a.clone()),
            &json!({
                "reason": "lag-and-reorg-conflict",
                "low_fee_scans_keep_wallet_quorum": true,
            }),
            latest_quorum_root,
            latest_health_root,
            state.height,
            state.config.health_stale_blocks,
        )?)?;

        let disclosure_id = state.prepare_disclosure_summary(DisclosureSummary::new(
            DisclosureScope::BridgeTicket,
            deposit_ticket_id.clone(),
            state
                .bridge_tickets
                .get(&deposit_ticket_id)
                .map(BridgeObservationTicket::ticket_root)
                .ok_or_else(|| "missing devnet deposit ticket".to_string())?,
            &[
                "amount_bucket".to_string(),
                "confirmations".to_string(),
                "endpoint_quorum_root".to_string(),
            ],
            &json!({
                "hide_txid": true,
                "hide_address": true,
                "show_bucket_only": true,
            }),
            "devnet-risk-dashboard",
            state.height,
            state.config.disclosure_ttl_blocks,
            64,
        )?)?;

        for (subject_kind, subject_id, subject_root, signer, scheme, key, threshold) in [
            (
                PqAttestationSubject::Endpoint,
                daemon_a.clone(),
                state
                    .endpoints
                    .get(&daemon_a)
                    .map(MoneroRpcEndpoint::endpoint_root)
                    .ok_or_else(|| "missing devnet daemon a".to_string())?,
                "operator-alpha",
                "ML-DSA-87+SLH-DSA-SHAKE-192s",
                "alpha-pq-key",
                true,
            ),
            (
                PqAttestationSubject::Endpoint,
                wallet_a.clone(),
                state
                    .endpoints
                    .get(&wallet_a)
                    .map(MoneroRpcEndpoint::endpoint_root)
                    .ok_or_else(|| "missing devnet wallet a".to_string())?,
                "operator-alpha",
                "ML-DSA-87+SLH-DSA-SHAKE-192s",
                "wallet-alpha-pq-key",
                true,
            ),
            (
                PqAttestationSubject::Operator,
                state.operator_label.clone(),
                monero_rpc_bridge_string_root(
                    "MONERO-RPC-BRIDGE-OPERATOR-SUBJECT",
                    &state.operator_label,
                ),
                "bridge-operator-threshold",
                "ML-DSA-87+Falcon-1024-threshold",
                "bridge-threshold-pq-key",
                true,
            ),
            (
                PqAttestationSubject::FailoverDecision,
                failover_id.clone(),
                state
                    .failover_events
                    .get(&failover_id)
                    .map(EndpointFailoverEvent::failover_root)
                    .ok_or_else(|| "missing devnet failover".to_string())?,
                "operator-beta",
                "ML-DSA-65+SLH-DSA-SHAKE-128s",
                "beta-pq-key",
                false,
            ),
            (
                PqAttestationSubject::DisclosureSummary,
                disclosure_id.clone(),
                state
                    .disclosure_summaries
                    .get(&disclosure_id)
                    .map(DisclosureSummary::summary_root)
                    .ok_or_else(|| "missing devnet disclosure".to_string())?,
                "privacy-auditor",
                "ML-DSA-65+SLH-DSA-SHAKE-128s",
                "auditor-pq-key",
                false,
            ),
            (
                PqAttestationSubject::ReorgEvidence,
                reorg_id.clone(),
                state
                    .reorg_evidence
                    .get(&reorg_id)
                    .map(ReorgEvidence::evidence_root)
                    .ok_or_else(|| "missing devnet reorg evidence".to_string())?,
                "watchtower-alpha",
                "ML-DSA-87+SLH-DSA-SHAKE-192s",
                "watchtower-alpha-pq-key",
                true,
            ),
        ] {
            state.attest_subject(PqRpcAttestation::new(
                subject_kind,
                subject_id,
                subject_root,
                signer,
                state.operator_label.clone(),
                scheme,
                key,
                "devnet-deterministic-signature-root",
                state.height,
                state.config.disclosure_ttl_blocks,
                state.config.min_pq_security_bits,
                threshold,
            )?)?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroRpcBridgeResult<String> {
        self.height = height;
        let stale_blocks = self.config.health_stale_blocks;
        for endpoint in self.endpoints.values_mut() {
            if endpoint.status != RpcEndpointStatus::Retired
                && endpoint.status != RpcEndpointStatus::Quarantined
            {
                let stale_by = height.saturating_sub(endpoint.last_health_height);
                endpoint.status = if endpoint.last_health_height == 0 {
                    RpcEndpointStatus::Degraded
                } else if stale_by > stale_blocks.saturating_mul(2) {
                    RpcEndpointStatus::Offline
                } else if stale_by > stale_blocks {
                    RpcEndpointStatus::Degraded
                } else {
                    endpoint.status
                };
            }
        }
        for request in self.wallet_requests.values_mut() {
            if request.status.is_open() && height >= request.expires_at_height {
                request.status = WalletRequestStatus::Expired;
            }
        }
        for job in self.view_sync_jobs.values_mut() {
            if job.status.is_active() && height >= job.expires_at_height {
                job.status = ViewOnlySyncStatus::Expired;
            }
        }
        let tip_height = self.latest_daemon_height();
        for ticket in self.bridge_tickets.values_mut() {
            ticket.set_tip_height(tip_height);
        }
        for evidence in self.reorg_evidence.values_mut() {
            if evidence.status == "reported" && height >= evidence.expires_at_height {
                evidence.status = "expired".to_string();
            }
        }
        for event in self.failover_events.values_mut() {
            if event.status == "applied" && height >= event.expires_at_height {
                event.status = "expired".to_string();
            }
        }
        for sponsorship in self.scan_sponsorships.values_mut() {
            if sponsorship.status.is_active() && height >= sponsorship.expires_at_height {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for disclosure in self.disclosure_summaries.values_mut() {
            if disclosure.status.is_active() && height >= disclosure.expires_at_height {
                disclosure.status = DisclosureStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if attestation.status.is_usable() && height >= attestation.expires_at_height {
                attestation.status = PqAttestationStatus::Expired;
            }
        }
        self.recompute_quorum_health()?;
        self.validate()
    }

    pub fn insert_endpoint(
        &mut self,
        endpoint: MoneroRpcEndpoint,
    ) -> MoneroRpcBridgeResult<String> {
        endpoint.validate()?;
        let endpoint_id = endpoint.endpoint_id.clone();
        if self.endpoints.contains_key(&endpoint_id) {
            return Err("monero rpc endpoint already exists".to_string());
        }
        if self.active_endpoint_id.is_none() && endpoint.status.contributes_to_quorum() {
            self.active_endpoint_id = Some(endpoint_id.clone());
        }
        self.endpoints.insert(endpoint_id.clone(), endpoint);
        self.recompute_quorum_health()?;
        Ok(endpoint_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_endpoint_health(
        &mut self,
        endpoint_id: &str,
        daemon_height: u64,
        wallet_height: u64,
        txpool_size: u64,
        latency_ms: u64,
        error_count: u64,
        chain_tip_height: u64,
        supported_methods: &[RpcMethodFamily],
        response_payload: &Value,
    ) -> MoneroRpcBridgeResult<String> {
        if !self.endpoints.contains_key(endpoint_id) {
            return Err("monero rpc health references unknown endpoint".to_string());
        }
        let health = RpcEndpointHealth::new(
            endpoint_id,
            self.height,
            daemon_height,
            wallet_height,
            txpool_size,
            latency_ms,
            error_count,
            chain_tip_height,
            supported_methods,
            response_payload,
        )?;
        let health_id = health.health_id.clone();
        let health_status = health.status;
        if let Some(endpoint) = self.endpoints.get_mut(endpoint_id) {
            endpoint.advertised_height = chain_tip_height;
            endpoint.last_observed_height = daemon_height;
            endpoint.last_health_height = self.height;
            endpoint.latency_ms = latency_ms;
            endpoint.error_count = error_count;
            endpoint.status = health_status;
            endpoint.reliability_bps = reliability_bps(error_count, latency_ms);
        }
        self.endpoint_health.insert(health_id.clone(), health);
        self.recompute_quorum_health()?;
        Ok(health_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_daemon_height(
        &mut self,
        endpoint_id: &str,
        daemon_height: u64,
        block_hash: impl Into<String>,
        previous_block_hash: impl Into<String>,
        cumulative_difficulty: &Value,
        txpool_size: u64,
        pruning_seed: u64,
        response_payload: &Value,
        status: RpcEndpointStatus,
    ) -> MoneroRpcBridgeResult<String> {
        if !self.endpoints.contains_key(endpoint_id) {
            return Err("monero rpc height observation references unknown endpoint".to_string());
        }
        let observation = DaemonHeightObservation::new(
            endpoint_id,
            self.height,
            daemon_height,
            block_hash,
            previous_block_hash,
            cumulative_difficulty,
            txpool_size,
            pruning_seed,
            response_payload,
            status,
        )?;
        let observation_id = observation.observation_id.clone();
        self.height_observations
            .insert(observation_id.clone(), observation);
        if let Some(endpoint) = self.endpoints.get_mut(endpoint_id) {
            endpoint.last_observed_height = daemon_height;
            endpoint.advertised_height = endpoint.advertised_height.max(daemon_height);
        }
        self.recompute_quorum_health()?;
        Ok(observation_id)
    }

    pub fn open_wallet_request(
        &mut self,
        request: WalletRpcRequest,
    ) -> MoneroRpcBridgeResult<String> {
        request.validate()?;
        if let Some(sponsorship_id) = &request.sponsorship_id {
            if !self.scan_sponsorships.contains_key(sponsorship_id) {
                return Err("monero rpc wallet request references unknown sponsorship".to_string());
            }
        }
        let request_id = request.request_id.clone();
        if self.wallet_requests.contains_key(&request_id) {
            return Err("monero rpc wallet request already exists".to_string());
        }
        self.wallet_requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    pub fn schedule_view_only_sync_job(
        &mut self,
        request_id: &str,
        client_label: impl Into<String>,
        endpoint_ids: &[String],
        checkpoint_payload: &Value,
        candidate_outputs: &[String],
        scan_unit_count: u64,
        priority: u64,
    ) -> MoneroRpcBridgeResult<String> {
        for endpoint_id in endpoint_ids {
            let endpoint = self
                .endpoints
                .get(endpoint_id)
                .ok_or_else(|| "monero rpc sync job references unknown endpoint".to_string())?;
            if !endpoint.endpoint_kind.is_wallet_capable() {
                return Err("monero rpc sync job endpoint is not wallet capable".to_string());
            }
        }
        let request = self
            .wallet_requests
            .get_mut(request_id)
            .ok_or_else(|| "monero rpc sync job references unknown request".to_string())?;
        if !request.status.is_open() {
            return Err("monero rpc sync job request is closed".to_string());
        }
        request.status = WalletRequestStatus::Assigned;
        let job = ViewOnlyWalletSyncJob::new(
            request,
            client_label,
            endpoint_ids,
            checkpoint_payload,
            candidate_outputs,
            scan_unit_count,
            priority,
            self.height,
            self.config.view_sync_job_ttl_blocks,
        )?;
        let job_id = job.job_id.clone();
        self.view_sync_jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn seal_view_only_sync_job(
        &mut self,
        job_id: &str,
        result_payload: &Value,
    ) -> MoneroRpcBridgeResult<String> {
        let request_id = {
            let job = self
                .view_sync_jobs
                .get_mut(job_id)
                .ok_or_else(|| "unknown monero rpc sync job".to_string())?;
            job.seal(result_payload)?;
            job.request_id.clone()
        };
        if let Some(request) = self.wallet_requests.get_mut(&request_id) {
            request.status = WalletRequestStatus::Completed;
        }
        Ok(job_id.to_string())
    }

    pub fn open_bridge_ticket(
        &mut self,
        ticket: BridgeObservationTicket,
    ) -> MoneroRpcBridgeResult<String> {
        ticket.validate()?;
        if let Some(request_id) = &ticket.wallet_request_id {
            if !self.wallet_requests.contains_key(request_id) {
                return Err("monero rpc bridge ticket references unknown request".to_string());
            }
        }
        let ticket_id = ticket.ticket_id.clone();
        if self.bridge_tickets.contains_key(&ticket_id) {
            return Err("monero rpc bridge ticket already exists".to_string());
        }
        self.bridge_tickets.insert(ticket_id.clone(), ticket);
        Ok(ticket_id)
    }

    pub fn record_reorg_evidence(
        &mut self,
        evidence: ReorgEvidence,
    ) -> MoneroRpcBridgeResult<String> {
        evidence.validate()?;
        if !self.endpoints.contains_key(&evidence.endpoint_id) {
            return Err("monero rpc reorg evidence references unknown endpoint".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        if self.reorg_evidence.contains_key(&evidence_id) {
            return Err("monero rpc reorg evidence already exists".to_string());
        }
        self.reorg_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn record_failover_event(
        &mut self,
        event: EndpointFailoverEvent,
    ) -> MoneroRpcBridgeResult<String> {
        event.validate()?;
        if let Some(endpoint_id) = &event.from_endpoint_id {
            if !self.endpoints.contains_key(endpoint_id) {
                return Err("monero rpc failover from endpoint is unknown".to_string());
            }
        }
        if let Some(endpoint_id) = &event.to_endpoint_id {
            if !self.endpoints.contains_key(endpoint_id) {
                return Err("monero rpc failover to endpoint is unknown".to_string());
            }
            self.active_endpoint_id = Some(endpoint_id.clone());
        }
        if event.decision_kind == FailoverDecisionKind::QuarantineEndpoint {
            if let Some(endpoint_id) = &event.from_endpoint_id {
                if let Some(endpoint) = self.endpoints.get_mut(endpoint_id) {
                    endpoint.status = RpcEndpointStatus::Quarantined;
                }
            }
        }
        if event.decision_kind == FailoverDecisionKind::RestoreEndpoint {
            if let Some(endpoint_id) = &event.to_endpoint_id {
                if let Some(endpoint) = self.endpoints.get_mut(endpoint_id) {
                    endpoint.status = RpcEndpointStatus::Active;
                }
            }
        }
        let failover_id = event.failover_id.clone();
        if self.failover_events.contains_key(&failover_id) {
            return Err("monero rpc failover event already exists".to_string());
        }
        self.failover_events.insert(failover_id.clone(), event);
        self.recompute_quorum_health()?;
        Ok(failover_id)
    }

    pub fn open_scan_sponsorship(
        &mut self,
        sponsor_label: impl Into<String>,
        beneficiary_label: Option<String>,
        fee_asset_id: impl Into<String>,
        max_scan_units: u64,
        max_fee_units: u64,
        fee_rate_micro_units: u64,
    ) -> MoneroRpcBridgeResult<String> {
        let sponsorship = LowFeeScanSponsorship::new(
            sponsor_label,
            beneficiary_label,
            fee_asset_id,
            max_scan_units,
            max_fee_units,
            fee_rate_micro_units,
            self.height,
            self.config.sponsorship_ttl_blocks,
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.scan_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn reserve_sponsored_scan_units(
        &mut self,
        sponsorship_id: &str,
        units: u64,
    ) -> MoneroRpcBridgeResult<String> {
        let sponsorship = self
            .scan_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown monero rpc scan sponsorship".to_string())?;
        sponsorship.reserve_units(units)
    }

    pub fn consume_sponsored_scan_units(
        &mut self,
        sponsorship_id: &str,
        units: u64,
        settlement_payload: &Value,
    ) -> MoneroRpcBridgeResult<String> {
        let sponsorship = self
            .scan_sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "unknown monero rpc scan sponsorship".to_string())?;
        sponsorship.consume_units(units, settlement_payload)
    }

    pub fn prepare_disclosure_summary(
        &mut self,
        summary: DisclosureSummary,
    ) -> MoneroRpcBridgeResult<String> {
        summary.validate()?;
        let summary_id = summary.summary_id.clone();
        if self.disclosure_summaries.contains_key(&summary_id) {
            return Err("monero rpc disclosure summary already exists".to_string());
        }
        self.disclosure_summaries
            .insert(summary_id.clone(), summary);
        Ok(summary_id)
    }

    pub fn attest_subject(
        &mut self,
        attestation: PqRpcAttestation,
    ) -> MoneroRpcBridgeResult<String> {
        attestation.validate()?;
        self.validate_attestation_subject(&attestation)?;
        let attestation_id = attestation.attestation_id.clone();
        if self.pq_attestations.contains_key(&attestation_id) {
            return Err("monero rpc pq attestation already exists".to_string());
        }
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn counters(&self) -> MoneroRpcBridgeCounters {
        MoneroRpcBridgeCounters {
            height: self.height,
            endpoint_count: self.endpoints.len() as u64,
            active_endpoint_count: self
                .endpoints
                .values()
                .filter(|endpoint| endpoint.status.contributes_to_quorum())
                .count() as u64,
            daemon_endpoint_count: self
                .endpoints
                .values()
                .filter(|endpoint| {
                    matches!(
                        endpoint.endpoint_kind,
                        RpcEndpointKind::Daemon | RpcEndpointKind::FailoverRelay
                    )
                })
                .count() as u64,
            wallet_endpoint_count: self
                .endpoints
                .values()
                .filter(|endpoint| endpoint.endpoint_kind.is_wallet_capable())
                .count() as u64,
            health_observation_count: self.endpoint_health.len() as u64,
            daemon_height_observation_count: self.height_observations.len() as u64,
            quorum_health_count: self.quorum_health.len() as u64,
            wallet_request_count: self.wallet_requests.len() as u64,
            open_wallet_request_count: self
                .wallet_requests
                .values()
                .filter(|request| request.status.is_open())
                .count() as u64,
            sync_job_count: self.view_sync_jobs.len() as u64,
            active_sync_job_count: self
                .view_sync_jobs
                .values()
                .filter(|job| job.status.is_active())
                .count() as u64,
            bridge_ticket_count: self.bridge_tickets.len() as u64,
            open_bridge_ticket_count: self
                .bridge_tickets
                .values()
                .filter(|ticket| ticket.status.is_open())
                .count() as u64,
            reorg_evidence_count: self.reorg_evidence.len() as u64,
            active_reorg_evidence_count: self
                .reorg_evidence
                .values()
                .filter(|evidence| evidence.status == "reported")
                .count() as u64,
            failover_event_count: self.failover_events.len() as u64,
            scan_sponsorship_count: self.scan_sponsorships.len() as u64,
            active_sponsorship_count: self
                .scan_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_active())
                .count() as u64,
            sponsored_scan_units: self
                .scan_sponsorships
                .values()
                .map(|sponsorship| sponsorship.reserved_scan_units)
                .sum(),
            consumed_scan_units: self
                .scan_sponsorships
                .values()
                .map(|sponsorship| sponsorship.consumed_scan_units)
                .sum(),
            disclosure_summary_count: self.disclosure_summaries.len() as u64,
            active_disclosure_summary_count: self
                .disclosure_summaries
                .values()
                .filter(|summary| summary.status.is_active())
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            usable_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.is_usable())
                .count() as u64,
        }
    }

    pub fn roots(&self) -> MoneroRpcBridgeRoots {
        let counters = self.counters();
        let mut roots = MoneroRpcBridgeRoots {
            config_root: self.config.config_root(),
            endpoint_root: monero_rpc_bridge_endpoint_collection_root(
                &self.endpoints.values().cloned().collect::<Vec<_>>(),
            ),
            endpoint_health_root: monero_rpc_bridge_endpoint_health_collection_root(
                &self.endpoint_health.values().cloned().collect::<Vec<_>>(),
            ),
            quorum_health_root: monero_rpc_bridge_quorum_health_collection_root(
                &self.quorum_health.values().cloned().collect::<Vec<_>>(),
            ),
            daemon_height_observation_root: monero_rpc_bridge_height_observation_collection_root(
                &self
                    .height_observations
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            wallet_request_root: monero_rpc_bridge_wallet_request_collection_root(
                &self.wallet_requests.values().cloned().collect::<Vec<_>>(),
            ),
            view_sync_job_root: monero_rpc_bridge_view_sync_job_collection_root(
                &self.view_sync_jobs.values().cloned().collect::<Vec<_>>(),
            ),
            bridge_ticket_root: monero_rpc_bridge_bridge_ticket_collection_root(
                &self.bridge_tickets.values().cloned().collect::<Vec<_>>(),
            ),
            reorg_evidence_root: monero_rpc_bridge_reorg_evidence_collection_root(
                &self.reorg_evidence.values().cloned().collect::<Vec<_>>(),
            ),
            failover_event_root: monero_rpc_bridge_failover_event_collection_root(
                &self.failover_events.values().cloned().collect::<Vec<_>>(),
            ),
            scan_sponsorship_root: monero_rpc_bridge_scan_sponsorship_collection_root(
                &self.scan_sponsorships.values().cloned().collect::<Vec<_>>(),
            ),
            disclosure_summary_root: monero_rpc_bridge_disclosure_summary_collection_root(
                &self
                    .disclosure_summaries
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: monero_rpc_bridge_pq_attestation_collection_root(
                &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
            ),
            counters_root: counters.counters_root(),
            public_record_root: monero_rpc_bridge_payload_root(
                "MONERO-RPC-BRIDGE-PUBLIC-RECORD-SUMMARY",
                &json!({
                    "kind": "monero_rpc_bridge_public_summary",
                    "chain_id": CHAIN_ID,
                    "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
                    "height": self.height,
                    "operator_label": self.operator_label,
                    "network": self.network,
                    "active_endpoint_id": self.active_endpoint_id,
                    "config_root": self.config.config_root(),
                    "counters_root": counters.counters_root(),
                }),
            ),
            state_root: String::new(),
        };
        let record = self.public_record_without_state_root(&roots, &counters);
        roots.state_root = monero_rpc_bridge_state_root_from_record(&record);
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        with_root_field(
            self.public_record_without_state_root(&roots, &counters),
            "state_root",
            roots.state_root.clone(),
        )
    }

    pub fn validate(&self) -> MoneroRpcBridgeResult<String> {
        self.config.validate()?;
        ensure_non_empty(&self.operator_label, "monero rpc bridge operator label")?;
        ensure_non_empty(&self.network, "monero rpc bridge network")?;
        if self.network != self.config.network {
            return Err("monero rpc bridge state network differs from config".to_string());
        }
        if let Some(endpoint_id) = &self.active_endpoint_id {
            if !self.endpoints.contains_key(endpoint_id) {
                return Err("monero rpc bridge active endpoint is unknown".to_string());
            }
        }
        for (endpoint_id, endpoint) in &self.endpoints {
            if endpoint_id != &endpoint.endpoint_id {
                return Err("monero rpc endpoint map key mismatch".to_string());
            }
            if endpoint.network != self.network {
                return Err("monero rpc endpoint network mismatch".to_string());
            }
            endpoint.validate()?;
        }
        for (health_id, health) in &self.endpoint_health {
            if health_id != &health.health_id {
                return Err("monero rpc health map key mismatch".to_string());
            }
            if !self.endpoints.contains_key(&health.endpoint_id) {
                return Err("monero rpc health references unknown endpoint".to_string());
            }
            health.validate()?;
        }
        for (quorum_id, quorum) in &self.quorum_health {
            if quorum_id != &quorum.quorum_id {
                return Err("monero rpc quorum map key mismatch".to_string());
            }
            ensure_non_empty(&quorum.network, "monero rpc quorum network")?;
            ensure_non_empty(&quorum.endpoint_root, "monero rpc quorum endpoint root")?;
            ensure_non_empty(&quorum.health_root, "monero rpc quorum health root")?;
        }
        for (observation_id, observation) in &self.height_observations {
            if observation_id != &observation.observation_id {
                return Err("monero rpc height observation map key mismatch".to_string());
            }
            if !self.endpoints.contains_key(&observation.endpoint_id) {
                return Err("monero rpc height observation references unknown endpoint".to_string());
            }
            observation.validate()?;
        }
        for (request_id, request) in &self.wallet_requests {
            if request_id != &request.request_id {
                return Err("monero rpc wallet request map key mismatch".to_string());
            }
            if let Some(sponsorship_id) = &request.sponsorship_id {
                if !self.scan_sponsorships.contains_key(sponsorship_id) {
                    return Err(
                        "monero rpc wallet request references unknown sponsorship".to_string()
                    );
                }
            }
            request.validate()?;
        }
        for (job_id, job) in &self.view_sync_jobs {
            if job_id != &job.job_id {
                return Err("monero rpc sync job map key mismatch".to_string());
            }
            if !self.wallet_requests.contains_key(&job.request_id) {
                return Err("monero rpc sync job references unknown wallet request".to_string());
            }
            if job.scan_unit_count > self.config.max_scan_outputs_per_job {
                return Err("monero rpc sync job exceeds scan output cap".to_string());
            }
            job.validate()?;
        }
        for (ticket_id, ticket) in &self.bridge_tickets {
            if ticket_id != &ticket.ticket_id {
                return Err("monero rpc bridge ticket map key mismatch".to_string());
            }
            if let Some(request_id) = &ticket.wallet_request_id {
                if !self.wallet_requests.contains_key(request_id) {
                    return Err("monero rpc bridge ticket references unknown request".to_string());
                }
            }
            ticket.validate()?;
        }
        for (evidence_id, evidence) in &self.reorg_evidence {
            if evidence_id != &evidence.evidence_id {
                return Err("monero rpc reorg evidence map key mismatch".to_string());
            }
            if !self.endpoints.contains_key(&evidence.endpoint_id) {
                return Err("monero rpc reorg evidence references unknown endpoint".to_string());
            }
            evidence.validate()?;
        }
        for (failover_id, event) in &self.failover_events {
            if failover_id != &event.failover_id {
                return Err("monero rpc failover event map key mismatch".to_string());
            }
            if let Some(endpoint_id) = &event.from_endpoint_id {
                if !self.endpoints.contains_key(endpoint_id) {
                    return Err("monero rpc failover source endpoint unknown".to_string());
                }
            }
            if let Some(endpoint_id) = &event.to_endpoint_id {
                if !self.endpoints.contains_key(endpoint_id) {
                    return Err("monero rpc failover target endpoint unknown".to_string());
                }
            }
            event.validate()?;
        }
        for (sponsorship_id, sponsorship) in &self.scan_sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("monero rpc scan sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
        }
        for (summary_id, summary) in &self.disclosure_summaries {
            if summary_id != &summary.summary_id {
                return Err("monero rpc disclosure summary map key mismatch".to_string());
            }
            summary.validate()?;
        }
        for (attestation_id, attestation) in &self.pq_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("monero rpc pq attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            self.validate_attestation_subject(attestation)?;
            if attestation.security_bits < self.config.min_pq_security_bits {
                return Err("monero rpc pq attestation below configured security floor".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(
        &self,
        roots: &MoneroRpcBridgeRoots,
        counters: &MoneroRpcBridgeCounters,
    ) -> Value {
        json!({
            "kind": "monero_rpc_bridge_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RPC_BRIDGE_PROTOCOL_VERSION,
            "height": self.height,
            "operator_label": self.operator_label,
            "network": self.network,
            "active_endpoint_id": self.active_endpoint_id,
            "config": self.config.public_record(),
            "roots": roots.public_record_without_state_root(),
            "counters": counters.public_record(),
        })
    }

    fn recompute_quorum_health(&mut self) -> MoneroRpcBridgeResult<()> {
        let active_endpoints = self
            .endpoints
            .values()
            .filter(|endpoint| endpoint.status.contributes_to_quorum())
            .cloned()
            .collect::<Vec<_>>();
        let daemon_heights = active_endpoints
            .iter()
            .filter(|endpoint| {
                matches!(
                    endpoint.endpoint_kind,
                    RpcEndpointKind::Daemon | RpcEndpointKind::FailoverRelay
                )
            })
            .map(|endpoint| endpoint.last_observed_height)
            .collect::<Vec<_>>();
        let wallet_endpoint_count = active_endpoints
            .iter()
            .filter(|endpoint| endpoint.endpoint_kind.is_wallet_capable())
            .count() as u64;
        let daemon_endpoint_count = daemon_heights.len() as u64;
        let active_endpoint_count = active_endpoints.len() as u64;
        let median_daemon_height = median_u64(daemon_heights.clone());
        let min_daemon_height = min_u64(&daemon_heights);
        let latest_height = max_u64(&daemon_heights);
        let max_lag_blocks = latest_height.saturating_sub(min_daemon_height);
        let degraded_endpoint_count = self
            .endpoints
            .values()
            .filter(|endpoint| endpoint.status == RpcEndpointStatus::Degraded)
            .count() as u64;
        let endpoint_root = monero_rpc_bridge_endpoint_collection_root(
            &self.endpoints.values().cloned().collect::<Vec<_>>(),
        );
        let health_root = monero_rpc_bridge_endpoint_health_collection_root(
            &self.endpoint_health.values().cloned().collect::<Vec<_>>(),
        );
        let status = if daemon_endpoint_count < self.config.endpoint_quorum {
            "insufficient_daemon_quorum"
        } else if wallet_endpoint_count < self.config.wallet_quorum {
            "insufficient_wallet_quorum"
        } else if max_lag_blocks > self.config.max_endpoint_lag_blocks {
            "degraded_lag"
        } else if degraded_endpoint_count > 0 {
            "degraded"
        } else {
            "healthy"
        }
        .to_string();
        let active_endpoint_id = self.choose_active_endpoint();
        self.active_endpoint_id = active_endpoint_id.clone();
        let identity = json!({
            "network": self.network,
            "height": self.height,
            "endpoint_root": endpoint_root,
            "health_root": health_root,
            "quorum_required": self.config.endpoint_quorum,
            "wallet_quorum_required": self.config.wallet_quorum,
            "median_daemon_height": median_daemon_height,
            "max_lag_blocks": max_lag_blocks,
            "active_endpoint_id": active_endpoint_id,
            "status": status,
        });
        let quorum_id = monero_rpc_bridge_quorum_health_id(&identity);
        let quorum = RpcQuorumHealth {
            quorum_id: quorum_id.clone(),
            network: self.network.clone(),
            height: self.height,
            endpoint_root,
            health_root,
            active_endpoint_count,
            daemon_endpoint_count,
            wallet_endpoint_count,
            quorum_required: self.config.endpoint_quorum,
            wallet_quorum_required: self.config.wallet_quorum,
            min_daemon_height,
            median_daemon_height,
            max_lag_blocks,
            degraded_endpoint_count,
            active_endpoint_id,
            status,
        };
        self.quorum_health.insert(quorum_id, quorum);
        Ok(())
    }

    fn choose_active_endpoint(&self) -> Option<String> {
        self.endpoints
            .values()
            .filter(|endpoint| endpoint.status == RpcEndpointStatus::Active)
            .min_by(|left, right| {
                left.priority
                    .cmp(&right.priority)
                    .then(left.latency_ms.cmp(&right.latency_ms))
                    .then(right.reliability_bps.cmp(&left.reliability_bps))
                    .then(left.endpoint_id.cmp(&right.endpoint_id))
            })
            .map(|endpoint| endpoint.endpoint_id.clone())
    }

    fn latest_daemon_height(&self) -> u64 {
        match self
            .endpoints
            .values()
            .map(|endpoint| endpoint.last_observed_height)
            .max()
        {
            Some(height) => height,
            None => 0,
        }
    }

    fn latest_quorum_root(&self) -> String {
        match self
            .quorum_health
            .values()
            .max_by_key(|quorum| quorum.height)
            .map(RpcQuorumHealth::quorum_root)
        {
            Some(root) => root,
            None => monero_rpc_bridge_empty_root("MONERO-RPC-BRIDGE-QUORUM-HEALTH"),
        }
    }

    fn validate_attestation_subject(
        &self,
        attestation: &PqRpcAttestation,
    ) -> MoneroRpcBridgeResult<()> {
        match attestation.subject_kind {
            PqAttestationSubject::Endpoint => {
                if !self.endpoints.contains_key(&attestation.subject_id) {
                    return Err("monero rpc pq endpoint attestation subject unknown".to_string());
                }
            }
            PqAttestationSubject::Operator => {
                if attestation.subject_id != self.operator_label {
                    return Err("monero rpc pq operator attestation subject mismatch".to_string());
                }
            }
            PqAttestationSubject::WalletJob => {
                if !self.view_sync_jobs.contains_key(&attestation.subject_id) {
                    return Err("monero rpc pq wallet job attestation subject unknown".to_string());
                }
            }
            PqAttestationSubject::BridgeTicket => {
                if !self.bridge_tickets.contains_key(&attestation.subject_id) {
                    return Err(
                        "monero rpc pq bridge ticket attestation subject unknown".to_string()
                    );
                }
            }
            PqAttestationSubject::FailoverDecision => {
                if !self.failover_events.contains_key(&attestation.subject_id) {
                    return Err("monero rpc pq failover attestation subject unknown".to_string());
                }
            }
            PqAttestationSubject::DisclosureSummary => {
                if !self
                    .disclosure_summaries
                    .contains_key(&attestation.subject_id)
                {
                    return Err("monero rpc pq disclosure attestation subject unknown".to_string());
                }
            }
            PqAttestationSubject::ReorgEvidence => {
                if !self.reorg_evidence.contains_key(&attestation.subject_id) {
                    return Err("monero rpc pq reorg attestation subject unknown".to_string());
                }
            }
        }
        Ok(())
    }
}

pub fn monero_rpc_bridge_state_root_from_record(record: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-STATE", record)
}

pub fn monero_rpc_bridge_config_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-CONFIG-ID", payload)
}

pub fn monero_rpc_bridge_endpoint_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-ENDPOINT-ID", payload)
}

pub fn monero_rpc_bridge_endpoint_health_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-ENDPOINT-HEALTH-ID", payload)
}

pub fn monero_rpc_bridge_quorum_health_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-QUORUM-HEALTH-ID", payload)
}

pub fn monero_rpc_bridge_height_observation_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-HEIGHT-OBSERVATION-ID", payload)
}

pub fn monero_rpc_bridge_wallet_request_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-WALLET-REQUEST-ID", payload)
}

pub fn monero_rpc_bridge_view_sync_job_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-VIEW-SYNC-JOB-ID", payload)
}

pub fn monero_rpc_bridge_bridge_ticket_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-BRIDGE-TICKET-ID", payload)
}

pub fn monero_rpc_bridge_reorg_evidence_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-REORG-EVIDENCE-ID", payload)
}

pub fn monero_rpc_bridge_failover_event_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-FAILOVER-EVENT-ID", payload)
}

pub fn monero_rpc_bridge_scan_sponsorship_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-SCAN-SPONSORSHIP-ID", payload)
}

pub fn monero_rpc_bridge_disclosure_summary_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-DISCLOSURE-SUMMARY-ID", payload)
}

pub fn monero_rpc_bridge_pq_attestation_id(payload: &Value) -> String {
    monero_rpc_bridge_payload_root("MONERO-RPC-BRIDGE-PQ-ATTESTATION-ID", payload)
}

pub fn monero_rpc_bridge_pq_signature_root(
    subject_kind: PqAttestationSubject,
    subject_id: &str,
    subject_root: &str,
    signer_commitment: &str,
    pq_scheme: &str,
    signature_material: &str,
) -> String {
    domain_hash(
        "MONERO-RPC-BRIDGE-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_RPC_BRIDGE_PROTOCOL_VERSION),
            HashPart::Str(subject_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Str(pq_scheme),
            HashPart::Str(signature_material),
        ],
        32,
    )
}

pub fn monero_rpc_bridge_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_RPC_BRIDGE_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_rpc_bridge_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_RPC_BRIDGE_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_rpc_bridge_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn monero_rpc_bridge_string_set_root(domain: &str, values: &[String]) -> String {
    let ordered = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect::<BTreeSet<_>>();
    merkle_root(
        domain,
        &ordered
            .into_iter()
            .map(|value| json!({"value": monero_rpc_bridge_string_root(domain, &value)}))
            .collect::<Vec<_>>(),
    )
}

pub fn monero_rpc_bridge_endpoint_collection_root(records: &[MoneroRpcEndpoint]) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-ENDPOINT-COLLECTION",
        records
            .iter()
            .map(|record| (record.endpoint_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_endpoint_health_collection_root(records: &[RpcEndpointHealth]) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-ENDPOINT-HEALTH-COLLECTION",
        records
            .iter()
            .map(|record| (record.health_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_quorum_health_collection_root(records: &[RpcQuorumHealth]) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-QUORUM-HEALTH-COLLECTION",
        records
            .iter()
            .map(|record| (record.quorum_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_height_observation_collection_root(
    records: &[DaemonHeightObservation],
) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-HEIGHT-OBSERVATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.observation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_wallet_request_collection_root(records: &[WalletRpcRequest]) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-WALLET-REQUEST-COLLECTION",
        records
            .iter()
            .map(|record| (record.request_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_view_sync_job_collection_root(
    records: &[ViewOnlyWalletSyncJob],
) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-VIEW-SYNC-JOB-COLLECTION",
        records
            .iter()
            .map(|record| (record.job_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_bridge_ticket_collection_root(
    records: &[BridgeObservationTicket],
) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-BRIDGE-TICKET-COLLECTION",
        records
            .iter()
            .map(|record| (record.ticket_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_reorg_evidence_collection_root(records: &[ReorgEvidence]) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-REORG-EVIDENCE-COLLECTION",
        records
            .iter()
            .map(|record| (record.evidence_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_failover_event_collection_root(
    records: &[EndpointFailoverEvent],
) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-FAILOVER-EVENT-COLLECTION",
        records
            .iter()
            .map(|record| (record.failover_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_scan_sponsorship_collection_root(
    records: &[LowFeeScanSponsorship],
) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-SCAN-SPONSORSHIP-COLLECTION",
        records
            .iter()
            .map(|record| (record.sponsorship_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_disclosure_summary_collection_root(
    records: &[DisclosureSummary],
) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-DISCLOSURE-SUMMARY-COLLECTION",
        records
            .iter()
            .map(|record| (record.summary_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_pq_attestation_collection_root(records: &[PqRpcAttestation]) -> String {
    keyed_value_root(
        "MONERO-RPC-BRIDGE-PQ-ATTESTATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.attestation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_rpc_bridge_amount_bucket(amount_units: u64) -> u64 {
    if amount_units == 0 {
        0
    } else {
        amount_units.div_ceil(MONERO_RPC_BRIDGE_AMOUNT_BUCKET) * MONERO_RPC_BRIDGE_AMOUNT_BUCKET
    }
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(key, value)| json!({"key": key, "value": value}))
            .collect::<Vec<_>>(),
    )
}

fn with_root_field(mut record: Value, field_name: &str, root: String) -> Value {
    if let Some(object) = record.as_object_mut() {
        object.insert(field_name.to_string(), Value::String(root));
    }
    record
}

fn with_string_field(mut record: Value, field_name: &str, value: String) -> Value {
    if let Some(object) = record.as_object_mut() {
        object.insert(field_name.to_string(), Value::String(value));
    }
    record
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroRpcBridgeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroRpcBridgeResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroRpcBridgeResult<()> {
    if value > MONERO_RPC_BRIDGE_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_window(start: u64, end: u64, label: &str) -> MoneroRpcBridgeResult<()> {
    if end < start {
        Err(format!("{label} end is before start"))
    } else {
        Ok(())
    }
}

fn ensure_string_set(values: &[String], label: &str) -> MoneroRpcBridgeResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}

fn ensure_method_set(values: &[RpcMethodFamily], label: &str) -> MoneroRpcBridgeResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}

fn confirmations(tip_height: u64, block_height: u64) -> u64 {
    if tip_height >= block_height {
        tip_height.saturating_sub(block_height).saturating_add(1)
    } else {
        0
    }
}

fn reliability_bps(error_count: u64, latency_ms: u64) -> u64 {
    let error_penalty = error_count.saturating_mul(2_000);
    let latency_penalty = latency_ms.saturating_sub(50).saturating_mul(10);
    MONERO_RPC_BRIDGE_MAX_BPS.saturating_sub(error_penalty.saturating_add(latency_penalty))
}

fn median_u64(mut values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort();
    values[values.len() / 2]
}

fn min_u64(values: &[u64]) -> u64 {
    match values.iter().min() {
        Some(value) => *value,
        None => 0,
    }
}

fn max_u64(values: &[u64]) -> u64 {
    match values.iter().max() {
        Some(value) => *value,
        None => 0,
    }
}
