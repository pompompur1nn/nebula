use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqTrustMinimizedBridgeExitSpineRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_TRUST_MINIMIZED_BRIDGE_EXIT_SPINE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-trust-minimized-bridge-exit-spine-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_TRUST_MINIMIZED_BRIDGE_EXIT_SPINE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CONTROL_PLANE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-exit-control-v1";
pub const WATCHER_CERTIFICATE_SUITE: &str = "threshold-pq-watchers-monero-lock-exit-quorum-root-v1";
pub const PRIVATE_NOTE_SUITE: &str =
    "monero-l2-private-note-state-root-with-roots-only-disclosure-v1";
pub const ALWAYS_AVAILABLE_EXIT_SUITE: &str =
    "forced-exit-escape-path-with-challenge-window-and-liquidity-backstop-v1";
pub const RECEIPT_SUITE: &str = "deposit-action-withdrawal-settlement-receipt-spine-root-v1";
pub const THREAT_MODEL_SUITE: &str =
    "monero-private-l2-bridge-exit-threat-model-and-mitigations-v1";
pub const DEVNET_HEIGHT: u64 = 620_000;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const DEFAULT_EMERGENCY_WATCHER_WEIGHT: u64 = 7;
pub const DEFAULT_MONERO_FINALITY_DEPTH: u64 = 18;
pub const DEFAULT_FAST_FINALITY_DEPTH: u64 = 8;
pub const DEFAULT_FORCED_EXIT_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_EXIT_LIVENESS_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_EXIT_RESERVE_BPS: u64 = 11_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_LIVE_PATHS: usize = 262_144;
pub const DEFAULT_MAX_CHALLENGES: usize = 131_072;
pub const DEFAULT_MAX_EVENTS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSurface {
    MoneroReorg,
    WatcherCollusion,
    SequencerCensorship,
    LiquidityExhaustion,
    MetadataLinkage,
    UpgradeKeyCompromise,
    PqMigrationFailure,
}

impl ThreatSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroReorg => "monero_reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::SequencerCensorship => "sequencer_censorship",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLinkage => "metadata_linkage",
            Self::UpgradeKeyCompromise => "upgrade_key_compromise",
            Self::PqMigrationFailure => "pq_migration_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLane {
    LowFee,
    Standard,
    Fast,
    Emergency,
}

impl BridgeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Emergency => "emergency",
        }
    }

    pub fn finality_depth(self, config: &Config) -> u64 {
        match self {
            Self::Fast => config.fast_finality_depth,
            Self::Emergency => config.fast_finality_depth.max(1),
            Self::LowFee | Self::Standard => config.monero_finality_depth,
        }
    }

    pub fn user_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::Fast | Self::Emergency => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitMode {
    Cooperative,
    FastLiquidity,
    Forced,
    Emergency,
}

impl ExitMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cooperative => "cooperative",
            Self::FastLiquidity => "fast_liquidity",
            Self::Forced => "forced",
            Self::Emergency => "emergency",
        }
    }

    pub fn needs_forced_exit_delay(self) -> bool {
        matches!(self, Self::Forced | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpineStage {
    DepositLocked,
    WatcherCertified,
    PrivateNoteMinted,
    PrivateActionRecorded,
    ReceiptAnchored,
    WithdrawalRequested,
    ForcedExitArmed,
    ExitSettled,
    Challenged,
    Quarantined,
    Expired,
}

impl SpineStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLocked => "deposit_locked",
            Self::WatcherCertified => "watcher_certified",
            Self::PrivateNoteMinted => "private_note_minted",
            Self::PrivateActionRecorded => "private_action_recorded",
            Self::ReceiptAnchored => "receipt_anchored",
            Self::WithdrawalRequested => "withdrawal_requested",
            Self::ForcedExitArmed => "forced_exit_armed",
            Self::ExitSettled => "exit_settled",
            Self::Challenged => "challenged",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::ExitSettled | Self::Quarantined | Self::Expired)
    }

    pub fn can_request_exit(self) -> bool {
        matches!(
            self,
            Self::PrivateNoteMinted | Self::PrivateActionRecorded | Self::ReceiptAnchored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateActionKind {
    Transfer,
    ContractCall,
    TokenMintBurn,
    AmmSwap,
    LendingPosition,
    SettlementOnly,
}

impl PrivateActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::ContractCall => "contract_call",
            Self::TokenMintBurn => "token_mint_burn",
            Self::AmmSwap => "amm_swap",
            Self::LendingPosition => "lending_position",
            Self::SettlementOnly => "settlement_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidDepositLock,
    WatcherEquivocation,
    SequencerCensorship,
    LiquidityShortfall,
    ReceiptMismatch,
    MetadataLeakage,
    ReplayNullifier,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidDepositLock => "invalid_deposit_lock",
            Self::WatcherEquivocation => "watcher_equivocation",
            Self::SequencerCensorship => "sequencer_censorship",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::MetadataLeakage => "metadata_leakage",
            Self::ReplayNullifier => "replay_nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceComplete,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceComplete => "evidence_complete",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceComplete)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyStatus {
    Green,
    Watch,
    Degraded,
    HaltDeposits,
    ExitOnly,
}

impl SafetyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Watch => "watch",
            Self::Degraded => "degraded",
            Self::HaltDeposits => "halt_deposits",
            Self::ExitOnly => "exit_only",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Green | Self::Watch)
    }

    pub fn permits_exits(self) -> bool {
        !matches!(self, Self::HaltDeposits)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_control_plane_suite: String,
    pub watcher_certificate_suite: String,
    pub private_note_suite: String,
    pub always_available_exit_suite: String,
    pub receipt_suite: String,
    pub threat_model_suite: String,
    pub genesis_height: u64,
    pub min_pq_security_bits: u16,
    pub min_watcher_weight: u64,
    pub emergency_watcher_weight: u64,
    pub monero_finality_depth: u64,
    pub fast_finality_depth: u64,
    pub forced_exit_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub exit_liveness_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub exit_reserve_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub max_live_paths: usize,
    pub max_challenges: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_control_plane_suite: PQ_CONTROL_PLANE_SUITE.to_string(),
            watcher_certificate_suite: WATCHER_CERTIFICATE_SUITE.to_string(),
            private_note_suite: PRIVATE_NOTE_SUITE.to_string(),
            always_available_exit_suite: ALWAYS_AVAILABLE_EXIT_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            threat_model_suite: THREAT_MODEL_SUITE.to_string(),
            genesis_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            emergency_watcher_weight: DEFAULT_EMERGENCY_WATCHER_WEIGHT,
            monero_finality_depth: DEFAULT_MONERO_FINALITY_DEPTH,
            fast_finality_depth: DEFAULT_FAST_FINALITY_DEPTH,
            forced_exit_delay_blocks: DEFAULT_FORCED_EXIT_DELAY_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            exit_liveness_window_blocks: DEFAULT_EXIT_LIVENESS_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            exit_reserve_bps: DEFAULT_EXIT_RESERVE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_live_paths: DEFAULT_MAX_LIVE_PATHS,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_control_plane_suite": self.pq_control_plane_suite,
            "watcher_certificate_suite": self.watcher_certificate_suite,
            "private_note_suite": self.private_note_suite,
            "always_available_exit_suite": self.always_available_exit_suite,
            "receipt_suite": self.receipt_suite,
            "threat_model_suite": self.threat_model_suite,
            "genesis_height": self.genesis_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watcher_weight": self.min_watcher_weight,
            "emergency_watcher_weight": self.emergency_watcher_weight,
            "monero_finality_depth": self.monero_finality_depth,
            "fast_finality_depth": self.fast_finality_depth,
            "forced_exit_delay_blocks": self.forced_exit_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "exit_liveness_window_blocks": self.exit_liveness_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "exit_reserve_bps": self.exit_reserve_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "max_live_paths": self.max_live_paths,
            "max_challenges": self.max_challenges,
            "max_events": self.max_events,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThreatModelEntry {
    pub surface: ThreatSurface,
    pub assumption: String,
    pub mitigation: String,
    pub required_evidence: String,
    pub residual_risk: String,
}

impl ThreatModelEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "surface": self.surface.as_str(),
            "assumption": self.assumption,
            "mitigation": self.mitigation,
            "required_evidence": self.required_evidence,
            "residual_risk": self.residual_risk,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgePolicy {
    pub policy_id: String,
    pub safety_status: SafetyStatus,
    pub custody_model: String,
    pub reserve_root: String,
    pub watcher_set_root: String,
    pub upgrade_authority_root: String,
    pub deposits_enabled: bool,
    pub withdrawals_enabled: bool,
    pub forced_exits_enabled: bool,
    pub max_single_exit_amount: u128,
    pub daily_exit_cap: u128,
    pub fee_cap_bps: u64,
}

impl BridgePolicy {
    pub fn devnet(config: &Config) -> Self {
        let reserve_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-RESERVE",
            &[
                HashPart::Str(config.asset_id.as_str()),
                HashPart::U64(11_000),
            ],
            32,
        );
        let watcher_set_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-WATCHERS",
            &[HashPart::Str("devnet-pq-watchers"), HashPart::U64(7)],
            32,
        );
        let upgrade_authority_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-UPGRADE-AUTHORITY",
            &[HashPart::Str("exit-only-safe-mode-pq-council")],
            32,
        );

        Self {
            policy_id: bridge_policy_id(&reserve_root, &watcher_set_root, config.genesis_height),
            safety_status: SafetyStatus::Watch,
            custody_model: "watcher-certified-monero-locks-with-roots-only-l2-mint-and-forced-exit"
                .to_string(),
            reserve_root,
            watcher_set_root,
            upgrade_authority_root,
            deposits_enabled: true,
            withdrawals_enabled: true,
            forced_exits_enabled: true,
            max_single_exit_amount: 25_000_000_000_000,
            daily_exit_cap: 250_000_000_000_000,
            fee_cap_bps: config.max_user_fee_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "safety_status": self.safety_status.as_str(),
            "custody_model": self.custody_model,
            "reserve_root": self.reserve_root,
            "watcher_set_root": self.watcher_set_root,
            "upgrade_authority_root": self.upgrade_authority_root,
            "deposits_enabled": self.deposits_enabled,
            "withdrawals_enabled": self.withdrawals_enabled,
            "forced_exits_enabled": self.forced_exits_enabled,
            "max_single_exit_amount": self.max_single_exit_amount.to_string(),
            "daily_exit_cap": self.daily_exit_cap.to_string(),
            "fee_cap_bps": self.fee_cap_bps,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherQuorum {
    pub quorum_id: String,
    pub watcher_set_root: String,
    pub pq_committee_root: String,
    pub threshold_weight: u64,
    pub observed_weight: u64,
    pub min_pq_security_bits: u16,
    pub monero_finality_depth: u64,
    pub last_certified_height: u64,
    pub certificate_root: String,
}

impl WatcherQuorum {
    pub fn public_record(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "watcher_set_root": self.watcher_set_root,
            "pq_committee_root": self.pq_committee_root,
            "threshold_weight": self.threshold_weight,
            "observed_weight": self.observed_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "monero_finality_depth": self.monero_finality_depth,
            "last_certified_height": self.last_certified_height,
            "certificate_root": self.certificate_root,
        })
    }

    pub fn usable(&self, config: &Config, emergency: bool) -> bool {
        let required_weight = if emergency {
            config.emergency_watcher_weight
        } else {
            config.min_watcher_weight
        };
        self.observed_weight >= self.threshold_weight.max(required_weight)
            && self.min_pq_security_bits >= config.min_pq_security_bits
            && self.monero_finality_depth >= config.fast_finality_depth
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockRequest {
    pub monero_lock_txid: String,
    pub deposit_commitment: String,
    pub amount: u128,
    pub sender_viewtag_commitment: String,
    pub deposit_subaddress_commitment: String,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub watcher_quorum_id: String,
    pub observed_monero_height: u64,
    pub lane: BridgeLane,
    pub user_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositCertificateRequest {
    pub path_id: String,
    pub watcher_quorum_id: String,
    pub certificate_root: String,
    pub monero_finality_depth: u64,
    pub certified_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MintPrivateNoteRequest {
    pub path_id: String,
    pub private_note_commitment: String,
    pub note_membership_root: String,
    pub wallet_scan_hint_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateActionRequest {
    pub path_id: String,
    pub action_kind: PrivateActionKind,
    pub action_commitment: String,
    pub private_state_root: String,
    pub contract_call_root: String,
    pub token_transfer_root: String,
    pub fee_sponsor_root: String,
    pub sequencer_pq_root: String,
    pub receipt_root: String,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AnchorReceiptRequest {
    pub path_id: String,
    pub receipt_root: String,
    pub settlement_state_root: String,
    pub bridge_checkpoint_root: String,
    pub anchor_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalRequest {
    pub path_id: String,
    pub withdrawal_commitment: String,
    pub burn_nullifier: String,
    pub payout_subaddress_commitment: String,
    pub requested_amount: u128,
    pub exit_mode: ExitMode,
    pub watcher_quorum_id: String,
    pub liquidity_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub requested_height: u64,
    pub user_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitRequest {
    pub path_id: String,
    pub censorship_evidence_root: String,
    pub liveness_failure_root: String,
    pub watcher_quorum_id: String,
    pub armed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeRequest {
    pub path_id: String,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub opened_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeResolutionRequest {
    pub challenge_id: String,
    pub status: ChallengeStatus,
    pub resolution_root: String,
    pub resolved_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitSettlementRequest {
    pub path_id: String,
    pub settlement_tx_root: String,
    pub release_certificate_root: String,
    pub final_private_state_root: String,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgePath {
    pub path_id: String,
    pub stage: SpineStage,
    pub lane: BridgeLane,
    pub deposit_commitment: String,
    pub monero_lock_txid: String,
    pub amount: u128,
    pub sender_viewtag_commitment: String,
    pub deposit_subaddress_commitment: String,
    pub watcher_quorum_id: String,
    pub deposit_certificate_root: Option<String>,
    pub private_note_commitment: Option<String>,
    pub private_state_root: Option<String>,
    pub action_receipt_id: Option<String>,
    pub receipt_root: Option<String>,
    pub bridge_checkpoint_root: Option<String>,
    pub withdrawal_commitment: Option<String>,
    pub burn_nullifier: Option<String>,
    pub payout_subaddress_commitment: Option<String>,
    pub exit_mode: Option<ExitMode>,
    pub forced_exit_evidence_root: Option<String>,
    pub settlement_id: Option<String>,
    pub settlement_tx_root: Option<String>,
    pub created_height: u64,
    pub updated_height: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub max_user_fee_bps: u64,
}

impl BridgePath {
    pub fn public_record(&self) -> Value {
        json!({
            "path_id": self.path_id,
            "stage": self.stage.as_str(),
            "lane": self.lane.as_str(),
            "deposit_commitment": self.deposit_commitment,
            "monero_lock_txid": self.monero_lock_txid,
            "amount": self.amount.to_string(),
            "sender_viewtag_commitment": self.sender_viewtag_commitment,
            "deposit_subaddress_commitment": self.deposit_subaddress_commitment,
            "watcher_quorum_id": self.watcher_quorum_id,
            "deposit_certificate_root": self.deposit_certificate_root,
            "private_note_commitment": self.private_note_commitment,
            "private_state_root": self.private_state_root,
            "action_receipt_id": self.action_receipt_id,
            "receipt_root": self.receipt_root,
            "bridge_checkpoint_root": self.bridge_checkpoint_root,
            "withdrawal_commitment": self.withdrawal_commitment,
            "burn_nullifier": self.burn_nullifier,
            "payout_subaddress_commitment": self.payout_subaddress_commitment,
            "exit_mode": self.exit_mode.map(ExitMode::as_str),
            "forced_exit_evidence_root": self.forced_exit_evidence_root,
            "settlement_id": self.settlement_id,
            "settlement_tx_root": self.settlement_tx_root,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "max_user_fee_bps": self.max_user_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SpineReceipt {
    pub receipt_id: String,
    pub path_id: String,
    pub action_kind: PrivateActionKind,
    pub action_commitment: String,
    pub private_state_root: String,
    pub contract_call_root: String,
    pub token_transfer_root: String,
    pub fee_sponsor_root: String,
    pub sequencer_pq_root: String,
    pub receipt_root: String,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
}

impl SpineReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "path_id": self.path_id,
            "action_kind": self.action_kind.as_str(),
            "action_commitment": self.action_commitment,
            "private_state_root": self.private_state_root,
            "contract_call_root": self.contract_call_root,
            "token_transfer_root": self.token_transfer_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "sequencer_pq_root": self.sequencer_pq_root,
            "receipt_root": self.receipt_root,
            "privacy_set_size": self.privacy_set_size,
            "user_fee_bps": self.user_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitChallenge {
    pub challenge_id: String,
    pub path_id: String,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub evidence_root: String,
    pub resolution_root: Option<String>,
    pub opened_height: u64,
    pub expires_height: u64,
    pub resolved_height: Option<u64>,
}

impl ExitChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "path_id": self.path_id,
            "challenger_commitment": self.challenger_commitment,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "resolution_root": self.resolution_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "resolved_height": self.resolved_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub kind: String,
    pub path_id: Option<String>,
    pub height: u64,
    pub record_root: String,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "path_id": self.path_id,
            "height": self.height,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub watcher_quorums_registered: u64,
    pub deposit_paths_opened: u64,
    pub deposits_certified: u64,
    pub private_notes_minted: u64,
    pub private_actions_recorded: u64,
    pub receipts_anchored: u64,
    pub withdrawals_requested: u64,
    pub forced_exits_armed: u64,
    pub challenges_opened: u64,
    pub challenges_upheld: u64,
    pub exits_settled: u64,
    pub replay_attempts_rejected: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_quorums_registered": self.watcher_quorums_registered,
            "deposit_paths_opened": self.deposit_paths_opened,
            "deposits_certified": self.deposits_certified,
            "private_notes_minted": self.private_notes_minted,
            "private_actions_recorded": self.private_actions_recorded,
            "receipts_anchored": self.receipts_anchored,
            "withdrawals_requested": self.withdrawals_requested,
            "forced_exits_armed": self.forced_exits_armed,
            "challenges_opened": self.challenges_opened,
            "challenges_upheld": self.challenges_upheld,
            "exits_settled": self.exits_settled,
            "replay_attempts_rejected": self.replay_attempts_rejected,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-COUNTERS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub policy_root: String,
    pub threat_model_root: String,
    pub watcher_quorum_root: String,
    pub bridge_path_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub spent_nullifier_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, policy: &BridgePolicy, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            policy_root: policy.state_root(),
            threat_model_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-THREATS", &[]),
            watcher_quorum_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-WATCHERS", &[]),
            bridge_path_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-PATHS", &[]),
            receipt_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-RECEIPTS", &[]),
            challenge_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-CHALLENGES", &[]),
            spent_nullifier_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-SPENT-NULLIFIERS",
                &[],
            ),
            event_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-EVENTS", &[]),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "policy_root": self.policy_root,
            "threat_model_root": self.threat_model_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "bridge_path_root": self.bridge_path_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.policy_root),
                HashPart::Str(&self.threat_model_root),
                HashPart::Str(&self.watcher_quorum_root),
                HashPart::Str(&self.bridge_path_root),
                HashPart::Str(&self.receipt_root),
                HashPart::Str(&self.challenge_root),
                HashPart::Str(&self.spent_nullifier_root),
                HashPart::Str(&self.event_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub policy: BridgePolicy,
    pub threat_model: BTreeMap<String, ThreatModelEntry>,
    pub watcher_quorums: BTreeMap<String, WatcherQuorum>,
    pub bridge_paths: BTreeMap<String, BridgePath>,
    pub receipts: BTreeMap<String, SpineReceipt>,
    pub challenges: BTreeMap<String, ExitChallenge>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: Vec<PublicEvent>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let policy = BridgePolicy::devnet(&config);
        let counters = Counters::default();
        let mut state = Self {
            roots: Roots::empty(&config, &policy, &counters),
            config,
            policy,
            threat_model: default_threat_model(),
            watcher_quorums: BTreeMap::new(),
            bridge_paths: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: Vec::new(),
            counters,
        };

        let watcher_root = state.policy.watcher_set_root.clone();
        let pq_committee_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-PQ-COMMITTEE",
            &[HashPart::Str("ml-dsa-slh-dsa-devnet-committee")],
            32,
        );
        let quorum = WatcherQuorum {
            quorum_id: watcher_quorum_id(&watcher_root, &pq_committee_root, DEVNET_HEIGHT),
            watcher_set_root: watcher_root,
            pq_committee_root,
            threshold_weight: state.config.min_watcher_weight,
            observed_weight: state.config.emergency_watcher_weight,
            min_pq_security_bits: state.config.min_pq_security_bits,
            monero_finality_depth: state.config.monero_finality_depth,
            last_certified_height: DEVNET_HEIGHT + state.config.monero_finality_depth,
            certificate_root: domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-CERT",
                &[HashPart::Str("watcher-devnet-cert")],
                32,
            ),
        };
        let quorum_id = state
            .register_watcher_quorum(quorum)
            .expect("devnet watcher quorum registers");

        let path_id = state
            .open_deposit_path(DepositLockRequest {
                monero_lock_txid: "devnet-monero-lock-txid-0001".to_string(),
                deposit_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-DEPOSIT-COMMITMENT",
                    &[HashPart::Str("deposit-commitment")],
                    32,
                ),
                amount: 1_000_000_000_000,
                sender_viewtag_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-VIEWTAG",
                    &[HashPart::Str("viewtag")],
                    32,
                ),
                deposit_subaddress_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-SUBADDRESS",
                    &[HashPart::Str("subaddress")],
                    32,
                ),
                privacy_set_size: state.config.target_privacy_set_size,
                pq_authorization_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-DEPOSIT-PQ-AUTH",
                    &[HashPart::Str("deposit-pq-auth")],
                    32,
                ),
                watcher_quorum_id: quorum_id.clone(),
                observed_monero_height: DEVNET_HEIGHT + state.config.monero_finality_depth,
                lane: BridgeLane::Standard,
                user_fee_bps: state.config.low_fee_bps,
            })
            .expect("devnet deposit path opens");

        state
            .certify_deposit_lock(DepositCertificateRequest {
                path_id: path_id.clone(),
                watcher_quorum_id: quorum_id.clone(),
                certificate_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-DEPOSIT-CERT",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                monero_finality_depth: state.config.monero_finality_depth,
                certified_height: DEVNET_HEIGHT + state.config.monero_finality_depth,
            })
            .expect("devnet deposit certifies");

        state
            .mint_private_note(MintPrivateNoteRequest {
                path_id: path_id.clone(),
                private_note_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-NOTE",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                note_membership_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-NOTE-MEMBERSHIP",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                wallet_scan_hint_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-SCAN-HINT",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                privacy_set_size: state.config.target_privacy_set_size,
            })
            .expect("devnet private note mints");

        state
            .record_private_action(PrivateActionRequest {
                path_id: path_id.clone(),
                action_kind: PrivateActionKind::Transfer,
                action_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-ACTION",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                private_state_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-PRIVATE-STATE",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                contract_call_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-CONTRACT-CALL",
                    &[HashPart::Str("none")],
                    32,
                ),
                token_transfer_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-TOKEN-TRANSFER",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                fee_sponsor_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-FEE-SPONSOR",
                    &[HashPart::Str("low-fee-sponsor")],
                    32,
                ),
                sequencer_pq_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-SEQUENCER-PQ",
                    &[HashPart::Str("sequencer-pq-root")],
                    32,
                ),
                receipt_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-RECEIPT",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                privacy_set_size: state.config.target_privacy_set_size,
                user_fee_bps: state.config.low_fee_bps,
            })
            .expect("devnet private action records");

        state
            .request_exit(WithdrawalRequest {
                path_id: path_id.clone(),
                withdrawal_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-WITHDRAWAL",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                burn_nullifier: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-BURN-NULLIFIER",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                payout_subaddress_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-PAYOUT",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                requested_amount: 999_999_950_000,
                exit_mode: ExitMode::Forced,
                watcher_quorum_id: quorum_id.clone(),
                liquidity_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-LIQUIDITY",
                    &[HashPart::Str("reserve-covered")],
                    32,
                ),
                pq_authorization_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-EXIT-PQ-AUTH",
                    &[HashPart::Str(&path_id)],
                    32,
                ),
                privacy_set_size: state.config.target_privacy_set_size,
                requested_height: DEVNET_HEIGHT + 64,
                user_fee_bps: state.config.low_fee_bps,
            })
            .expect("devnet exit requests");

        state
            .arm_forced_exit(ForcedExitRequest {
                path_id: path_id.clone(),
                censorship_evidence_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-CENSORSHIP",
                    &[HashPart::Str("simulated-liveness-failure")],
                    32,
                ),
                liveness_failure_root: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-DEVNET-LIVENESS",
                    &[HashPart::Str("sequencer-timeout")],
                    32,
                ),
                watcher_quorum_id: quorum_id,
                armed_height: DEVNET_HEIGHT + 96,
            })
            .expect("devnet forced exit arms");

        state
    }

    pub fn register_watcher_quorum(&mut self, quorum: WatcherQuorum) -> Result<String> {
        required("quorum_id", &quorum.quorum_id)?;
        required("watcher_set_root", &quorum.watcher_set_root)?;
        required("pq_committee_root", &quorum.pq_committee_root)?;
        required("certificate_root", &quorum.certificate_root)?;
        require(
            quorum.threshold_weight >= self.config.min_watcher_weight,
            "watcher quorum threshold below minimum",
        )?;
        require(
            quorum.observed_weight >= quorum.threshold_weight,
            "watcher quorum observed weight below threshold",
        )?;
        require(
            quorum.min_pq_security_bits >= self.config.min_pq_security_bits,
            "watcher quorum PQ security below runtime minimum",
        )?;
        require(
            !self.watcher_quorums.contains_key(&quorum.quorum_id),
            "watcher quorum already registered",
        )?;

        let quorum_id = quorum.quorum_id.clone();
        let record_root = record_root("watcher_quorum", &quorum.public_record());
        self.watcher_quorums.insert(quorum_id.clone(), quorum);
        self.counters.watcher_quorums_registered += 1;
        self.push_event(
            "watcher_quorum_registered",
            None,
            self.config.genesis_height,
            record_root,
        );
        self.refresh_roots();
        Ok(quorum_id)
    }

    pub fn open_deposit_path(&mut self, request: DepositLockRequest) -> Result<String> {
        require(
            self.policy.safety_status.accepts_deposits()
                && self.policy.deposits_enabled
                && self.policy.forced_exits_enabled,
            "bridge policy does not accept new deposits with forced exit coverage",
        )?;
        require(
            self.bridge_paths.len() < self.config.max_live_paths,
            "bridge path capacity reached",
        )?;
        required("monero_lock_txid", &request.monero_lock_txid)?;
        required("deposit_commitment", &request.deposit_commitment)?;
        required(
            "sender_viewtag_commitment",
            &request.sender_viewtag_commitment,
        )?;
        required(
            "deposit_subaddress_commitment",
            &request.deposit_subaddress_commitment,
        )?;
        required("pq_authorization_root", &request.pq_authorization_root)?;
        required("watcher_quorum_id", &request.watcher_quorum_id)?;
        require(request.amount > 0, "deposit amount must be positive")?;
        require(
            request.amount <= self.policy.max_single_exit_amount,
            "deposit exceeds single-exit policy cap",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "deposit privacy set below minimum",
        )?;
        require(
            request.user_fee_bps <= request.lane.user_fee_bps(&self.config),
            "deposit fee exceeds selected lane cap",
        )?;
        let quorum = self
            .watcher_quorums
            .get(&request.watcher_quorum_id)
            .ok_or_else(|| "watcher quorum not found".to_string())?;
        require(
            quorum.usable(&self.config, matches!(request.lane, BridgeLane::Emergency)),
            "watcher quorum is not usable for deposit lane",
        )?;
        require(
            quorum.last_certified_height >= request.observed_monero_height.saturating_sub(1),
            "watcher quorum does not cover observed deposit height",
        )?;
        require(
            request.observed_monero_height
                >= self
                    .config
                    .genesis_height
                    .saturating_add(request.lane.finality_depth(&self.config)),
            "deposit lock lacks required Monero finality depth",
        )?;

        let path_id = bridge_path_id(
            &request.monero_lock_txid,
            &request.deposit_commitment,
            request.amount,
        );
        require(
            !self.bridge_paths.contains_key(&path_id),
            "bridge deposit path already exists",
        )?;

        let path = BridgePath {
            path_id: path_id.clone(),
            stage: SpineStage::DepositLocked,
            lane: request.lane,
            deposit_commitment: request.deposit_commitment,
            monero_lock_txid: request.monero_lock_txid,
            amount: request.amount,
            sender_viewtag_commitment: request.sender_viewtag_commitment,
            deposit_subaddress_commitment: request.deposit_subaddress_commitment,
            watcher_quorum_id: request.watcher_quorum_id,
            deposit_certificate_root: None,
            private_note_commitment: None,
            private_state_root: None,
            action_receipt_id: None,
            receipt_root: None,
            bridge_checkpoint_root: None,
            withdrawal_commitment: None,
            burn_nullifier: None,
            payout_subaddress_commitment: None,
            exit_mode: None,
            forced_exit_evidence_root: None,
            settlement_id: None,
            settlement_tx_root: None,
            created_height: request.observed_monero_height,
            updated_height: request.observed_monero_height,
            privacy_set_size: request.privacy_set_size,
            pq_authorization_root: request.pq_authorization_root,
            max_user_fee_bps: request.user_fee_bps,
        };
        let record_root = record_root("deposit_path", &path.public_record());
        self.bridge_paths.insert(path_id.clone(), path);
        self.counters.deposit_paths_opened += 1;
        self.push_event(
            "deposit_path_opened",
            Some(path_id.clone()),
            request.observed_monero_height,
            record_root,
        );
        self.refresh_roots();
        Ok(path_id)
    }

    pub fn certify_deposit_lock(&mut self, request: DepositCertificateRequest) -> Result<()> {
        required("path_id", &request.path_id)?;
        required("watcher_quorum_id", &request.watcher_quorum_id)?;
        required("certificate_root", &request.certificate_root)?;
        let quorum = self
            .watcher_quorums
            .get(&request.watcher_quorum_id)
            .ok_or_else(|| "watcher quorum not found".to_string())?;
        require(
            quorum.usable(&self.config, false),
            "watcher quorum is not usable for deposit certificate",
        )?;
        require(
            request.monero_finality_depth >= self.config.fast_finality_depth,
            "deposit certificate finality depth below fast minimum",
        )?;
        let record_root = {
            let path = self
                .bridge_paths
                .get_mut(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                path.stage == SpineStage::DepositLocked,
                "bridge path is not waiting for deposit certification",
            )?;
            require(
                path.watcher_quorum_id == request.watcher_quorum_id,
                "deposit certificate uses wrong watcher quorum",
            )?;

            path.stage = SpineStage::WatcherCertified;
            path.deposit_certificate_root = Some(request.certificate_root);
            path.updated_height = request.certified_height;
            record_root("deposit_certified", &path.public_record())
        };
        self.counters.deposits_certified += 1;
        self.push_event(
            "deposit_lock_certified",
            Some(request.path_id),
            request.certified_height,
            record_root,
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn mint_private_note(&mut self, request: MintPrivateNoteRequest) -> Result<()> {
        required("path_id", &request.path_id)?;
        required("private_note_commitment", &request.private_note_commitment)?;
        required("note_membership_root", &request.note_membership_root)?;
        required("wallet_scan_hint_root", &request.wallet_scan_hint_root)?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "private note privacy set below minimum",
        )?;

        let (event_path_id, event_height, record_root) = {
            let path = self
                .bridge_paths
                .get_mut(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                path.stage == SpineStage::WatcherCertified,
                "bridge path is not ready for private note mint",
            )?;
            require(
                path.private_note_commitment.is_none(),
                "private note already minted for path",
            )?;

            let note_state = json!({
                "private_note_commitment": request.private_note_commitment,
                "note_membership_root": request.note_membership_root,
                "wallet_scan_hint_root": request.wallet_scan_hint_root,
                "path_id": request.path_id,
                "amount": path.amount.to_string(),
            });
            path.private_note_commitment = Some(
                note_state
                    .get("private_note_commitment")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            path.private_state_root = Some(record_root("private_note_state", &note_state));
            path.privacy_set_size = path.privacy_set_size.max(request.privacy_set_size);
            path.stage = SpineStage::PrivateNoteMinted;
            (
                path.path_id.clone(),
                path.updated_height,
                record_root("private_note_minted", &path.public_record()),
            )
        };
        self.counters.private_notes_minted += 1;
        self.push_event(
            "private_note_minted",
            Some(event_path_id),
            event_height,
            record_root,
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn record_private_action(&mut self, request: PrivateActionRequest) -> Result<String> {
        required("path_id", &request.path_id)?;
        required("action_commitment", &request.action_commitment)?;
        required("private_state_root", &request.private_state_root)?;
        required("contract_call_root", &request.contract_call_root)?;
        required("token_transfer_root", &request.token_transfer_root)?;
        required("fee_sponsor_root", &request.fee_sponsor_root)?;
        required("sequencer_pq_root", &request.sequencer_pq_root)?;
        required("receipt_root", &request.receipt_root)?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "private action privacy set below minimum",
        )?;
        require(
            request.user_fee_bps <= self.policy.fee_cap_bps,
            "private action fee exceeds bridge policy cap",
        )?;

        let receipt_id = private_action_receipt_id(
            &request.path_id,
            request.action_kind,
            &request.action_commitment,
            &request.receipt_root,
        );
        require(
            !self.receipts.contains_key(&receipt_id),
            "private action receipt already exists",
        )?;
        let event_path_id = request.path_id.clone();
        let receipt = SpineReceipt {
            receipt_id: receipt_id.clone(),
            path_id: request.path_id.clone(),
            action_kind: request.action_kind,
            action_commitment: request.action_commitment,
            private_state_root: request.private_state_root,
            contract_call_root: request.contract_call_root,
            token_transfer_root: request.token_transfer_root,
            fee_sponsor_root: request.fee_sponsor_root,
            sequencer_pq_root: request.sequencer_pq_root,
            receipt_root: request.receipt_root,
            privacy_set_size: request.privacy_set_size,
            user_fee_bps: request.user_fee_bps,
        };

        let (event_height, path_record_root) = {
            let path = self
                .bridge_paths
                .get_mut(&event_path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                matches!(
                    path.stage,
                    SpineStage::PrivateNoteMinted
                        | SpineStage::PrivateActionRecorded
                        | SpineStage::ReceiptAnchored
                ),
                "bridge path is not ready for private action",
            )?;
            path.stage = SpineStage::PrivateActionRecorded;
            path.private_state_root = Some(receipt.private_state_root.clone());
            path.action_receipt_id = Some(receipt_id.clone());
            path.receipt_root = Some(receipt.receipt_root.clone());
            path.privacy_set_size = path.privacy_set_size.max(receipt.privacy_set_size);
            (
                path.updated_height,
                record_root("private_action_path", &path.public_record()),
            )
        };
        let record_root = record_root("private_action_recorded", &receipt.public_record());
        self.receipts.insert(receipt_id.clone(), receipt);
        self.counters.private_actions_recorded += 1;
        self.push_event(
            "private_action_path_updated",
            Some(event_path_id.clone()),
            event_height,
            path_record_root,
        );
        self.push_event(
            "private_action_recorded",
            Some(event_path_id),
            event_height,
            record_root,
        );
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn anchor_settlement_receipt(&mut self, request: AnchorReceiptRequest) -> Result<()> {
        required("path_id", &request.path_id)?;
        required("receipt_root", &request.receipt_root)?;
        required("settlement_state_root", &request.settlement_state_root)?;
        required("bridge_checkpoint_root", &request.bridge_checkpoint_root)?;
        let record_root = {
            let path = self
                .bridge_paths
                .get_mut(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                matches!(
                    path.stage,
                    SpineStage::PrivateActionRecorded | SpineStage::ReceiptAnchored
                ),
                "bridge path has no private action receipt to anchor",
            )?;
            require(
                path.receipt_root.as_ref() == Some(&request.receipt_root),
                "anchored receipt root does not match latest private action",
            )?;
            path.stage = SpineStage::ReceiptAnchored;
            path.private_state_root = Some(request.settlement_state_root);
            path.bridge_checkpoint_root = Some(request.bridge_checkpoint_root);
            path.updated_height = request.anchor_height;
            record_root("receipt_anchored", &path.public_record())
        };
        self.counters.receipts_anchored += 1;
        self.push_event(
            "settlement_receipt_anchored",
            Some(request.path_id),
            request.anchor_height,
            record_root,
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn request_exit(&mut self, request: WithdrawalRequest) -> Result<String> {
        require(
            self.policy.safety_status.permits_exits()
                && self.policy.withdrawals_enabled
                && self.policy.forced_exits_enabled,
            "bridge policy does not permit exits",
        )?;
        required("path_id", &request.path_id)?;
        required("withdrawal_commitment", &request.withdrawal_commitment)?;
        required("burn_nullifier", &request.burn_nullifier)?;
        required(
            "payout_subaddress_commitment",
            &request.payout_subaddress_commitment,
        )?;
        required("watcher_quorum_id", &request.watcher_quorum_id)?;
        required("liquidity_root", &request.liquidity_root)?;
        required("pq_authorization_root", &request.pq_authorization_root)?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "exit privacy set below minimum",
        )?;
        require(
            request.user_fee_bps <= self.policy.fee_cap_bps,
            "exit fee exceeds bridge policy cap",
        )?;
        if self.spent_nullifiers.contains(&request.burn_nullifier) {
            self.counters.replay_attempts_rejected += 1;
            self.refresh_roots();
            return Err("exit burn nullifier already spent".to_string());
        }
        let quorum = self
            .watcher_quorums
            .get(&request.watcher_quorum_id)
            .ok_or_else(|| "watcher quorum not found".to_string())?;
        require(
            quorum.usable(
                &self.config,
                matches!(request.exit_mode, ExitMode::Emergency),
            ),
            "watcher quorum is not usable for exit mode",
        )?;

        let exit_id = exit_settlement_id(&request.path_id, &request.withdrawal_commitment);
        let forced_exit = request.exit_mode.needs_forced_exit_delay();
        let burn_nullifier = request.burn_nullifier.clone();
        let (event_path_id, event_height, record_root) = {
            let path = self
                .bridge_paths
                .get_mut(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                path.stage.can_request_exit(),
                "bridge path cannot request exit",
            )?;
            require(
                request.requested_amount <= path.amount,
                "exit amount exceeds path amount",
            )?;
            require(
                request.requested_amount <= self.policy.max_single_exit_amount,
                "exit amount exceeds policy cap",
            )?;
            require(
                path.watcher_quorum_id == request.watcher_quorum_id,
                "exit uses wrong watcher quorum",
            )?;

            path.stage = if forced_exit {
                SpineStage::ForcedExitArmed
            } else {
                SpineStage::WithdrawalRequested
            };
            path.withdrawal_commitment = Some(request.withdrawal_commitment);
            path.burn_nullifier = Some(request.burn_nullifier);
            path.payout_subaddress_commitment = Some(request.payout_subaddress_commitment);
            path.exit_mode = Some(request.exit_mode);
            path.privacy_set_size = path.privacy_set_size.max(request.privacy_set_size);
            path.updated_height = request.requested_height;
            path.pq_authorization_root = request.pq_authorization_root;
            path.max_user_fee_bps = path.max_user_fee_bps.max(request.user_fee_bps);
            (
                path.path_id.clone(),
                path.updated_height,
                record_root("exit_requested", &path.public_record()),
            )
        };
        self.spent_nullifiers.insert(burn_nullifier);
        self.counters.withdrawals_requested += 1;
        if forced_exit {
            self.counters.forced_exits_armed += 1;
        }
        self.push_event(
            "exit_requested",
            Some(event_path_id),
            event_height,
            record_root,
        );
        self.refresh_roots();
        Ok(exit_id)
    }

    pub fn arm_forced_exit(&mut self, request: ForcedExitRequest) -> Result<()> {
        required("path_id", &request.path_id)?;
        required(
            "censorship_evidence_root",
            &request.censorship_evidence_root,
        )?;
        required("liveness_failure_root", &request.liveness_failure_root)?;
        required("watcher_quorum_id", &request.watcher_quorum_id)?;
        let quorum = self
            .watcher_quorums
            .get(&request.watcher_quorum_id)
            .ok_or_else(|| "watcher quorum not found".to_string())?;
        require(
            quorum.usable(&self.config, true),
            "emergency watcher quorum is not usable for forced exit",
        )?;
        let evidence_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-FORCED-EXIT-EVIDENCE",
            &[
                HashPart::Str(&request.censorship_evidence_root),
                HashPart::Str(&request.liveness_failure_root),
            ],
            32,
        );
        let record_root = {
            let path = self
                .bridge_paths
                .get_mut(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                matches!(
                    path.stage,
                    SpineStage::WithdrawalRequested | SpineStage::ForcedExitArmed
                ),
                "bridge path is not ready to arm forced exit",
            )?;
            require(
                path.watcher_quorum_id == request.watcher_quorum_id,
                "forced exit uses wrong watcher quorum",
            )?;

            path.stage = SpineStage::ForcedExitArmed;
            path.forced_exit_evidence_root = Some(evidence_root);
            path.updated_height = request.armed_height;
            record_root("forced_exit_armed", &path.public_record())
        };
        self.counters.forced_exits_armed += 1;
        self.push_event(
            "forced_exit_armed",
            Some(request.path_id),
            request.armed_height,
            record_root,
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn challenge_path(&mut self, request: ChallengeRequest) -> Result<String> {
        require(
            self.challenges.len() < self.config.max_challenges,
            "challenge capacity reached",
        )?;
        required("path_id", &request.path_id)?;
        required("challenger_commitment", &request.challenger_commitment)?;
        required("evidence_root", &request.evidence_root)?;
        let challenge_id = exit_challenge_id(
            &request.path_id,
            request.kind,
            &request.challenger_commitment,
            &request.evidence_root,
        );
        require(
            !self.challenges.contains_key(&challenge_id),
            "exit challenge already exists",
        )?;
        {
            let path = self
                .bridge_paths
                .get(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                !path.stage.terminal(),
                "cannot challenge terminal bridge path",
            )?;
        }

        let challenge = ExitChallenge {
            challenge_id: challenge_id.clone(),
            path_id: request.path_id.clone(),
            challenger_commitment: request.challenger_commitment,
            kind: request.kind,
            status: ChallengeStatus::Open,
            evidence_root: request.evidence_root,
            resolution_root: None,
            opened_height: request.opened_height,
            expires_height: request
                .opened_height
                .saturating_add(self.config.challenge_window_blocks),
            resolved_height: None,
        };
        {
            let path = self
                .bridge_paths
                .get_mut(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            path.stage = SpineStage::Challenged;
            path.updated_height = request.opened_height;
        }
        let record_root = record_root("exit_challenge_opened", &challenge.public_record());
        self.challenges.insert(challenge_id.clone(), challenge);
        self.counters.challenges_opened += 1;
        self.push_event(
            "exit_challenge_opened",
            Some(request.path_id),
            request.opened_height,
            record_root,
        );
        self.refresh_roots();
        Ok(challenge_id)
    }

    pub fn resolve_challenge(&mut self, request: ChallengeResolutionRequest) -> Result<()> {
        required("challenge_id", &request.challenge_id)?;
        required("resolution_root", &request.resolution_root)?;
        require(
            !matches!(request.status, ChallengeStatus::Open),
            "challenge resolution cannot remain open",
        )?;
        let challenge_path_id = {
            let challenge = self
                .challenges
                .get(&request.challenge_id)
                .ok_or_else(|| "exit challenge not found".to_string())?;
            require(challenge.status.open(), "exit challenge already resolved")?;
            challenge.path_id.clone()
        };
        let record_root = {
            let challenge = self
                .challenges
                .get_mut(&request.challenge_id)
                .ok_or_else(|| "exit challenge not found".to_string())?;
            challenge.status = request.status;
            challenge.resolution_root = Some(request.resolution_root);
            challenge.resolved_height = Some(request.resolved_height);
            record_root("exit_challenge_resolved", &challenge.public_record())
        };
        {
            let path = self
                .bridge_paths
                .get_mut(&challenge_path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            path.updated_height = request.resolved_height;
            path.stage = match request.status {
                ChallengeStatus::Upheld => SpineStage::Quarantined,
                ChallengeStatus::Rejected
                | ChallengeStatus::Expired
                | ChallengeStatus::EvidenceComplete => {
                    if path
                        .exit_mode
                        .map(ExitMode::needs_forced_exit_delay)
                        .unwrap_or(false)
                    {
                        SpineStage::ForcedExitArmed
                    } else {
                        SpineStage::WithdrawalRequested
                    }
                }
                ChallengeStatus::Open => SpineStage::Challenged,
            };
        }
        if request.status == ChallengeStatus::Upheld {
            self.counters.challenges_upheld += 1;
        }
        self.push_event(
            "exit_challenge_resolved",
            Some(challenge_path_id),
            request.resolved_height,
            record_root,
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_exit(&mut self, request: ExitSettlementRequest) -> Result<String> {
        required("path_id", &request.path_id)?;
        required("settlement_tx_root", &request.settlement_tx_root)?;
        required(
            "release_certificate_root",
            &request.release_certificate_root,
        )?;
        required(
            "final_private_state_root",
            &request.final_private_state_root,
        )?;
        require(
            !self.has_open_challenge(&request.path_id),
            "bridge path has open exit challenge",
        )?;
        let settlement_id = exit_settlement_id(&request.path_id, &request.settlement_tx_root);
        let record_root = {
            let path = self
                .bridge_paths
                .get_mut(&request.path_id)
                .ok_or_else(|| "bridge path not found".to_string())?;
            require(
                matches!(
                    path.stage,
                    SpineStage::WithdrawalRequested | SpineStage::ForcedExitArmed
                ),
                "bridge path is not ready to settle exit",
            )?;
            if path
                .exit_mode
                .map(ExitMode::needs_forced_exit_delay)
                .unwrap_or(false)
            {
                require(
                    request.settled_height
                        >= path
                            .updated_height
                            .saturating_add(self.config.forced_exit_delay_blocks),
                    "forced exit delay has not elapsed",
                )?;
            }

            path.stage = SpineStage::ExitSettled;
            path.settlement_id = Some(settlement_id.clone());
            path.settlement_tx_root = Some(request.settlement_tx_root);
            path.private_state_root = Some(request.final_private_state_root);
            path.receipt_root = Some(request.release_certificate_root);
            path.updated_height = request.settled_height;
            record_root("exit_settled", &path.public_record())
        };
        self.counters.exits_settled += 1;
        self.push_event(
            "exit_settled",
            Some(request.path_id),
            request.settled_height,
            record_root,
        );
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn forced_exit_available(&self, path_id: &str, current_height: u64) -> bool {
        self.bridge_paths.get(path_id).is_some_and(|path| {
            matches!(
                path.stage,
                SpineStage::PrivateNoteMinted
                    | SpineStage::PrivateActionRecorded
                    | SpineStage::ReceiptAnchored
                    | SpineStage::WithdrawalRequested
                    | SpineStage::ForcedExitArmed
            ) && current_height
                >= path
                    .updated_height
                    .saturating_add(self.config.exit_liveness_window_blocks)
                && self.policy.forced_exits_enabled
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "policy": self.policy.public_record(),
            "safety_status": self.policy.safety_status.as_str(),
            "threat_model_root": self.roots.threat_model_root,
            "watcher_quorum_root": self.roots.watcher_quorum_root,
            "bridge_path_root": self.roots.bridge_path_root,
            "receipt_root": self.roots.receipt_root,
            "challenge_root": self.roots.challenge_root,
            "spent_nullifier_root": self.roots.spent_nullifier_root,
            "event_root": self.roots.event_root,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "live_paths": self.bridge_paths.values().filter(|path| !path.stage.terminal()).count(),
            "open_challenges": self.challenges.values().filter(|challenge| challenge.status.open()).count(),
            "forced_exit_enabled": self.policy.forced_exits_enabled,
            "deposits_enabled": self.policy.deposits_enabled,
            "withdrawals_enabled": self.policy.withdrawals_enabled,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn has_open_challenge(&self, path_id: &str) -> bool {
        self.challenges
            .values()
            .any(|challenge| challenge.path_id == path_id && challenge.status.open())
    }

    fn push_event(
        &mut self,
        kind: &str,
        path_id: Option<String>,
        height: u64,
        record_root: String,
    ) {
        if self.events.len() >= self.config.max_events {
            self.events.remove(0);
        }
        let event_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-EVENT-ID",
            &[
                HashPart::Str(kind),
                HashPart::Str(path_id.as_deref().unwrap_or("none")),
                HashPart::U64(height),
                HashPart::Str(&record_root),
            ],
            32,
        );
        self.events.push(PublicEvent {
            event_id,
            kind: kind.to_string(),
            path_id,
            height,
            record_root,
        });
    }

    fn refresh_roots(&mut self) {
        let threat_records = self
            .threat_model
            .values()
            .map(ThreatModelEntry::public_record)
            .collect::<Vec<_>>();
        let quorum_records = self
            .watcher_quorums
            .values()
            .map(WatcherQuorum::public_record)
            .collect::<Vec<_>>();
        let path_records = self
            .bridge_paths
            .values()
            .map(BridgePath::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(SpineReceipt::public_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(ExitChallenge::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();
        let event_records = self
            .events
            .iter()
            .map(PublicEvent::public_record)
            .collect::<Vec<_>>();

        self.roots = Roots {
            config_root: self.config.state_root(),
            policy_root: self.policy.state_root(),
            threat_model_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-THREATS",
                &threat_records,
            ),
            watcher_quorum_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-WATCHERS",
                &quorum_records,
            ),
            bridge_path_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-PATHS", &path_records),
            receipt_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-RECEIPTS", &receipt_records),
            challenge_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-CHALLENGES",
                &challenge_records,
            ),
            spent_nullifier_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-SPENT-NULLIFIERS",
                &nullifier_records,
            ),
            event_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-EVENTS", &event_records),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn bridge_policy_id(reserve_root: &str, watcher_set_root: &str, height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-POLICY-ID",
        &[
            HashPart::Str(reserve_root),
            HashPart::Str(watcher_set_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn watcher_quorum_id(watcher_set_root: &str, pq_committee_root: &str, height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-WATCHER-QUORUM-ID",
        &[
            HashPart::Str(watcher_set_root),
            HashPart::Str(pq_committee_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn bridge_path_id(monero_lock_txid: &str, deposit_commitment: &str, amount: u128) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-PATH-ID",
        &[
            HashPart::Str(monero_lock_txid),
            HashPart::Str(deposit_commitment),
            HashPart::Str(&amount.to_string()),
        ],
        32,
    )
}

pub fn private_action_receipt_id(
    path_id: &str,
    action_kind: PrivateActionKind,
    action_commitment: &str,
    receipt_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-PRIVATE-ACTION-RECEIPT-ID",
        &[
            HashPart::Str(path_id),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(action_commitment),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

pub fn exit_challenge_id(
    path_id: &str,
    kind: ChallengeKind,
    challenger_commitment: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-CHALLENGE-ID",
        &[
            HashPart::Str(path_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn exit_settlement_id(path_id: &str, settlement_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SPINE-SETTLEMENT-ID",
        &[HashPart::Str(path_id), HashPart::Str(settlement_root)],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-SPINE-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn default_threat_model() -> BTreeMap<String, ThreatModelEntry> {
    let entries = [
        ThreatModelEntry {
            surface: ThreatSurface::MoneroReorg,
            assumption: "Monero lock transactions can reorg before sufficient depth".to_string(),
            mitigation: "watcher certificates require lane-specific finality depth and reserve roots"
                .to_string(),
            required_evidence: "monero header depth, lock tx commitment, watcher certificate root"
                .to_string(),
            residual_risk: "deep Monero reorgs require exit-only mode and delayed settlement"
                .to_string(),
        },
        ThreatModelEntry {
            surface: ThreatSurface::WatcherCollusion,
            assumption: "a minority watcher set can equivocate or certify stale roots".to_string(),
            mitigation: "PQ threshold roots, emergency higher weight, challenge records, slashing evidence roots"
                .to_string(),
            required_evidence: "watcher quorum root, PQ committee root, certificate root, challenge root"
                .to_string(),
            residual_risk: "threshold capture remains a governance and staking design dependency".to_string(),
        },
        ThreatModelEntry {
            surface: ThreatSurface::SequencerCensorship,
            assumption: "sequencer can delay private receipts or refuse withdrawals".to_string(),
            mitigation: "always-available forced exit path with liveness failure evidence and watcher arming"
                .to_string(),
            required_evidence: "private note root, latest receipt root, censorship evidence root".to_string(),
            residual_risk: "forced exits trade speed for liveness and may reveal coarse timing".to_string(),
        },
        ThreatModelEntry {
            surface: ThreatSurface::LiquidityExhaustion,
            assumption: "fast exit liquidity can dry up under stress".to_string(),
            mitigation: "policy reserve bps, single-exit caps, daily caps, cooperative and forced exit fallback"
                .to_string(),
            required_evidence: "liquidity root, reserve root, settlement release certificate".to_string(),
            residual_risk: "large exits may settle slowly during reserve recovery".to_string(),
        },
        ThreatModelEntry {
            surface: ThreatSurface::MetadataLinkage,
            assumption: "deposit, action, and exit timing can link users".to_string(),
            mitigation: "roots-only public records, privacy-set floors, viewtag/subaddress commitments"
                .to_string(),
            required_evidence: "privacy-set size, redacted receipt root, wallet scan hint root".to_string(),
            residual_risk: "traffic analysis remains possible without batching and wallet discipline".to_string(),
        },
        ThreatModelEntry {
            surface: ThreatSurface::UpgradeKeyCompromise,
            assumption: "upgrade or emergency authority can attempt unsafe policy changes".to_string(),
            mitigation: "PQ upgrade authority roots and exit-only safety mode before risky changes".to_string(),
            required_evidence: "upgrade authority root, policy root, public safety-status event".to_string(),
            residual_risk: "social recovery and operator governance still need separate audits".to_string(),
        },
        ThreatModelEntry {
            surface: ThreatSurface::PqMigrationFailure,
            assumption: "hybrid or post-quantum key rollover can strand bridge controls".to_string(),
            mitigation: "PQ security bit floors on watcher, deposit, exit, and sequencer roots".to_string(),
            required_evidence: "PQ committee root, authorization roots, signer migration records".to_string(),
            residual_risk: "cryptographic implementation review remains required before production".to_string(),
        },
    ];

    entries
        .into_iter()
        .map(|entry| (entry.surface.as_str().to_string(), entry))
        .collect()
}

fn required(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

pub fn state_root_from_record(record: &Value) -> String {
    record_root("state-root-from-record", record)
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
