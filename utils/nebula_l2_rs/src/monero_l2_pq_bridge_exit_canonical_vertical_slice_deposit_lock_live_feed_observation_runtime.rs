use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceDepositLockLiveFeedObservationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_LOCK_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-lock-live-feed-observation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_LOCK_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const OBSERVATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-deposit-lock-live-feed-observation-v1";
pub const FINALITY_SUITE: &str = "monero-header-depth-and-live-reorg-fence-v1";
pub const WALLET_SCAN_SUITE: &str = "monero-view-key-scan-hints-roots-only-v1";
pub const OUTPUT_COMMITMENT_SUITE: &str = "monero-output-key-commitment-hints-v1";
pub const RESERVE_HANDOFF_SUITE: &str = "forced-exit-reserve-handoff-hints-v1";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-lock-live-feed-observation-runtime";
const DEFAULT_BRIDGE_SESSION_LABEL: &str = "canonical-vertical-slice-devnet";
const DEFAULT_FEED_ID: &str = "devnet-monero-deposit-lock-live-feed";
const DEFAULT_OBSERVER_ID: &str = "pq-watcher-quorum-devnet-a";
const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
const DEFAULT_REFERENCE_MONERO_HEIGHT: u64 = 912_704;
const DEFAULT_REFERENCE_L2_HEIGHT: u64 = 4_220_144;
const DEFAULT_MIN_CONFIRMATIONS: u64 = 60;
const DEFAULT_REORG_FENCE_BLOCKS: u64 = 12;
const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 720;
const DEFAULT_MAX_FEED_LAG_BLOCKS: u64 = 4;
const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u64 = 6_700;
const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Accepted,
    PendingFinality,
    HeldForRelease,
    FailedClosed,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::PendingFinality => "pending_finality",
            Self::HeldForRelease => "held_for_release",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    Mature,
    Pending,
    ReorgRisk,
    ConflictingHeader,
}

impl FinalityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mature => "mature",
            Self::Pending => "pending",
            Self::ReorgRisk => "reorg_risk",
            Self::ConflictingHeader => "conflicting_header",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    AmountCommitment,
    ReserveAsset,
    OutputKey,
    WalletScan,
    FinalityLink,
    DuplicateOutput,
    FeedLag,
}

impl MismatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmountCommitment => "amount_commitment",
            Self::ReserveAsset => "reserve_asset",
            Self::OutputKey => "output_key",
            Self::WalletScan => "wallet_scan",
            Self::FinalityLink => "finality_link",
            Self::DuplicateOutput => "duplicate_output",
            Self::FeedLag => "feed_lag",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub observation_suite: String,
    pub finality_suite: String,
    pub wallet_scan_suite: String,
    pub output_commitment_suite: String,
    pub reserve_handoff_suite: String,
    pub bridge_session_label: String,
    pub feed_id: String,
    pub observer_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub reference_monero_height: u64,
    pub reference_l2_height: u64,
    pub min_confirmations: u64,
    pub reorg_fence_blocks: u64,
    pub release_hold_blocks: u64,
    pub max_feed_lag_blocks: u64,
    pub min_watcher_weight_bps: u64,
    pub min_privacy_set_size: u64,
    pub require_amount_commitment_match: bool,
    pub require_reserve_hint_match: bool,
    pub require_wallet_scan_match: bool,
    pub fail_closed_on_any_mismatch: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            observation_suite: OBSERVATION_SUITE.to_string(),
            finality_suite: FINALITY_SUITE.to_string(),
            wallet_scan_suite: WALLET_SCAN_SUITE.to_string(),
            output_commitment_suite: OUTPUT_COMMITMENT_SUITE.to_string(),
            reserve_handoff_suite: RESERVE_HANDOFF_SUITE.to_string(),
            bridge_session_label: DEFAULT_BRIDGE_SESSION_LABEL.to_string(),
            feed_id: DEFAULT_FEED_ID.to_string(),
            observer_id: DEFAULT_OBSERVER_ID.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            reference_monero_height: DEFAULT_REFERENCE_MONERO_HEIGHT,
            reference_l2_height: DEFAULT_REFERENCE_L2_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_fence_blocks: DEFAULT_REORG_FENCE_BLOCKS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            max_feed_lag_blocks: DEFAULT_MAX_FEED_LAG_BLOCKS,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            require_amount_commitment_match: true,
            require_reserve_hint_match: true,
            require_wallet_scan_match: true,
            fail_closed_on_any_mismatch: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "observation_suite": self.observation_suite,
            "finality_suite": self.finality_suite,
            "wallet_scan_suite": self.wallet_scan_suite,
            "output_commitment_suite": self.output_commitment_suite,
            "reserve_handoff_suite": self.reserve_handoff_suite,
            "bridge_session_label": self.bridge_session_label,
            "feed_id": self.feed_id,
            "observer_id": self.observer_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "reference_monero_height": self.reference_monero_height,
            "reference_l2_height": self.reference_l2_height,
            "min_confirmations": self.min_confirmations,
            "reorg_fence_blocks": self.reorg_fence_blocks,
            "release_hold_blocks": self.release_hold_blocks,
            "max_feed_lag_blocks": self.max_feed_lag_blocks,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "require_amount_commitment_match": self.require_amount_commitment_match,
            "require_reserve_hint_match": self.require_reserve_hint_match,
            "require_wallet_scan_match": self.require_wallet_scan_match,
            "fail_closed_on_any_mismatch": self.fail_closed_on_any_mismatch,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DepositOutputReference {
    pub lock_txid: String,
    pub output_index: u64,
    pub one_time_public_key: String,
    pub key_image_hint_root: String,
    pub commitment_mask_hint_root: String,
    pub output_reference_root: String,
}

impl DepositOutputReference {
    pub fn new(
        lock_txid: impl Into<String>,
        output_index: u64,
        one_time_public_key: impl Into<String>,
        key_image_hint_root: impl Into<String>,
        commitment_mask_hint_root: impl Into<String>,
    ) -> Self {
        let lock_txid = lock_txid.into();
        let one_time_public_key = one_time_public_key.into();
        let key_image_hint_root = key_image_hint_root.into();
        let commitment_mask_hint_root = commitment_mask_hint_root.into();
        let output_reference_root = domain_hash(
            &format!("{DOMAIN}:output-reference"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&lock_txid),
                HashPart::Int(output_index as i128),
                HashPart::Str(&one_time_public_key),
                HashPart::Str(&key_image_hint_root),
                HashPart::Str(&commitment_mask_hint_root),
            ],
            32,
        );

        Self {
            lock_txid,
            output_index,
            one_time_public_key,
            key_image_hint_root,
            commitment_mask_hint_root,
            output_reference_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lock_txid": self.lock_txid,
            "output_index": self.output_index,
            "one_time_public_key": self.one_time_public_key,
            "key_image_hint_root": self.key_image_hint_root,
            "commitment_mask_hint_root": self.commitment_mask_hint_root,
            "output_reference_root": self.output_reference_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FinalityLinkage {
    pub lock_height: u64,
    pub observed_height: u64,
    pub confirmations: u64,
    pub min_confirmations: u64,
    pub block_hash: String,
    pub checkpoint_header_root: String,
    pub competing_header_root: String,
    pub status: FinalityStatus,
    pub finality_link_root: String,
}

impl FinalityLinkage {
    pub fn new(
        lock_height: u64,
        observed_height: u64,
        min_confirmations: u64,
        block_hash: impl Into<String>,
        checkpoint_header_root: impl Into<String>,
        competing_header_root: impl Into<String>,
    ) -> Self {
        let confirmations = observed_height.saturating_sub(lock_height);
        let block_hash = block_hash.into();
        let checkpoint_header_root = checkpoint_header_root.into();
        let competing_header_root = competing_header_root.into();
        let status = if !competing_header_root.is_empty() {
            FinalityStatus::ConflictingHeader
        } else if confirmations >= min_confirmations {
            FinalityStatus::Mature
        } else {
            FinalityStatus::Pending
        };
        let finality_link_root = domain_hash(
            &format!("{DOMAIN}:finality-linkage"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(lock_height as i128),
                HashPart::Int(observed_height as i128),
                HashPart::Int(confirmations as i128),
                HashPart::Int(min_confirmations as i128),
                HashPart::Str(&block_hash),
                HashPart::Str(&checkpoint_header_root),
                HashPart::Str(&competing_header_root),
                HashPart::Str(status.as_str()),
            ],
            32,
        );

        Self {
            lock_height,
            observed_height,
            confirmations,
            min_confirmations,
            block_hash,
            checkpoint_header_root,
            competing_header_root,
            status,
            finality_link_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lock_height": self.lock_height,
            "observed_height": self.observed_height,
            "confirmations": self.confirmations,
            "min_confirmations": self.min_confirmations,
            "block_hash": self.block_hash,
            "checkpoint_header_root": self.checkpoint_header_root,
            "competing_header_root": self.competing_header_root,
            "status": self.status.as_str(),
            "finality_link_root": self.finality_link_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmountReserveCommitmentHint {
    pub asset_id: String,
    pub amount_commitment_root: String,
    pub reserve_account_hint_root: String,
    pub reserve_epoch: u64,
    pub reserve_handoff_root: String,
    pub commitment_hint_root: String,
}

impl AmountReserveCommitmentHint {
    pub fn new(
        asset_id: impl Into<String>,
        amount_commitment_root: impl Into<String>,
        reserve_account_hint_root: impl Into<String>,
        reserve_epoch: u64,
        reserve_handoff_root: impl Into<String>,
    ) -> Self {
        let asset_id = asset_id.into();
        let amount_commitment_root = amount_commitment_root.into();
        let reserve_account_hint_root = reserve_account_hint_root.into();
        let reserve_handoff_root = reserve_handoff_root.into();
        let commitment_hint_root = domain_hash(
            &format!("{DOMAIN}:amount-reserve-hint"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&asset_id),
                HashPart::Str(&amount_commitment_root),
                HashPart::Str(&reserve_account_hint_root),
                HashPart::Int(reserve_epoch as i128),
                HashPart::Str(&reserve_handoff_root),
            ],
            32,
        );

        Self {
            asset_id,
            amount_commitment_root,
            reserve_account_hint_root,
            reserve_epoch,
            reserve_handoff_root,
            commitment_hint_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "amount_commitment_root": self.amount_commitment_root,
            "reserve_account_hint_root": self.reserve_account_hint_root,
            "reserve_epoch": self.reserve_epoch,
            "reserve_handoff_root": self.reserve_handoff_root,
            "commitment_hint_root": self.commitment_hint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub scan_hint_id: String,
    pub view_tag_root: String,
    pub subaddress_hint_root: String,
    pub encrypted_memo_root: String,
    pub privacy_set_size: u64,
    pub scan_window_start_height: u64,
    pub scan_window_end_height: u64,
    pub wallet_scan_root: String,
}

impl WalletScanHint {
    pub fn new(
        scan_hint_id: impl Into<String>,
        view_tag_root: impl Into<String>,
        subaddress_hint_root: impl Into<String>,
        encrypted_memo_root: impl Into<String>,
        privacy_set_size: u64,
        scan_window_start_height: u64,
        scan_window_end_height: u64,
    ) -> Self {
        let scan_hint_id = scan_hint_id.into();
        let view_tag_root = view_tag_root.into();
        let subaddress_hint_root = subaddress_hint_root.into();
        let encrypted_memo_root = encrypted_memo_root.into();
        let wallet_scan_root = domain_hash(
            &format!("{DOMAIN}:wallet-scan-hint"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&scan_hint_id),
                HashPart::Str(&view_tag_root),
                HashPart::Str(&subaddress_hint_root),
                HashPart::Str(&encrypted_memo_root),
                HashPart::Int(privacy_set_size as i128),
                HashPart::Int(scan_window_start_height as i128),
                HashPart::Int(scan_window_end_height as i128),
            ],
            32,
        );

        Self {
            scan_hint_id,
            view_tag_root,
            subaddress_hint_root,
            encrypted_memo_root,
            privacy_set_size,
            scan_window_start_height,
            scan_window_end_height,
            wallet_scan_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scan_hint_id": self.scan_hint_id,
            "view_tag_root": self.view_tag_root,
            "subaddress_hint_root": self.subaddress_hint_root,
            "encrypted_memo_root": self.encrypted_memo_root,
            "privacy_set_size": self.privacy_set_size,
            "scan_window_start_height": self.scan_window_start_height,
            "scan_window_end_height": self.scan_window_end_height,
            "wallet_scan_root": self.wallet_scan_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub kind: MismatchKind,
    pub subject_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub fail_closed: bool,
    pub detected_at_monero_height: u64,
    pub mismatch_root: String,
}

impl MismatchRecord {
    pub fn new(
        kind: MismatchKind,
        subject_root: impl Into<String>,
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        fail_closed: bool,
        detected_at_monero_height: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let expected_root = expected_root.into();
        let observed_root = observed_root.into();
        let fail_closed_marker = bool_marker(fail_closed);
        let mismatch_root = domain_hash(
            &format!("{DOMAIN}:mismatch-record"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_root),
                HashPart::Str(&expected_root),
                HashPart::Str(&observed_root),
                HashPart::Str(fail_closed_marker),
                HashPart::Int(detected_at_monero_height as i128),
            ],
            32,
        );
        let mismatch_id = domain_hash(
            &format!("{DOMAIN}:mismatch-id"),
            &[HashPart::Str(kind.as_str()), HashPart::Str(&mismatch_root)],
            16,
        );

        Self {
            mismatch_id,
            kind,
            subject_root,
            expected_root,
            observed_root,
            fail_closed,
            detected_at_monero_height,
            mismatch_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "kind": self.kind.as_str(),
            "subject_root": self.subject_root,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "fail_closed": self.fail_closed,
            "detected_at_monero_height": self.detected_at_monero_height,
            "mismatch_root": self.mismatch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub observation_id: String,
    pub reason: String,
    pub hold_until_monero_height: u64,
    pub release_allowed: bool,
    pub release_hold_root: String,
}

impl ReleaseHold {
    pub fn new(
        observation_id: impl Into<String>,
        reason: impl Into<String>,
        hold_until_monero_height: u64,
        release_allowed: bool,
    ) -> Self {
        let observation_id = observation_id.into();
        let reason = reason.into();
        let release_allowed_marker = bool_marker(release_allowed);
        let release_hold_root = domain_hash(
            &format!("{DOMAIN}:release-hold"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&observation_id),
                HashPart::Str(&reason),
                HashPart::Int(hold_until_monero_height as i128),
                HashPart::Str(release_allowed_marker),
            ],
            32,
        );
        let hold_id = domain_hash(
            &format!("{DOMAIN}:release-hold-id"),
            &[
                HashPart::Str(&observation_id),
                HashPart::Str(&release_hold_root),
            ],
            16,
        );

        Self {
            hold_id,
            observation_id,
            reason,
            hold_until_monero_height,
            release_allowed,
            release_hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "observation_id": self.observation_id,
            "reason": self.reason,
            "hold_until_monero_height": self.hold_until_monero_height,
            "release_allowed": self.release_allowed,
            "release_hold_root": self.release_hold_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DepositLockObservation {
    pub observation_id: String,
    pub feed_sequence: u64,
    pub feed_received_height: u64,
    pub output_reference: DepositOutputReference,
    pub finality: FinalityLinkage,
    pub amount_reserve_hint: AmountReserveCommitmentHint,
    pub wallet_scan_hint: WalletScanHint,
    pub watcher_weight_bps: u64,
    pub status: ObservationStatus,
    pub observation_root: String,
}

impl DepositLockObservation {
    pub fn new(
        feed_sequence: u64,
        feed_received_height: u64,
        output_reference: DepositOutputReference,
        finality: FinalityLinkage,
        amount_reserve_hint: AmountReserveCommitmentHint,
        wallet_scan_hint: WalletScanHint,
        watcher_weight_bps: u64,
        status: ObservationStatus,
    ) -> Self {
        let observation_root = domain_hash(
            &format!("{DOMAIN}:deposit-lock-observation"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(feed_sequence as i128),
                HashPart::Int(feed_received_height as i128),
                HashPart::Str(&output_reference.output_reference_root),
                HashPart::Str(&finality.finality_link_root),
                HashPart::Str(&amount_reserve_hint.commitment_hint_root),
                HashPart::Str(&wallet_scan_hint.wallet_scan_root),
                HashPart::Int(watcher_weight_bps as i128),
                HashPart::Str(status.as_str()),
            ],
            32,
        );
        let observation_id = domain_hash(
            &format!("{DOMAIN}:observation-id"),
            &[
                HashPart::Str(&output_reference.lock_txid),
                HashPart::Int(output_reference.output_index as i128),
                HashPart::Str(&observation_root),
            ],
            16,
        );

        Self {
            observation_id,
            feed_sequence,
            feed_received_height,
            output_reference,
            finality,
            amount_reserve_hint,
            wallet_scan_hint,
            watcher_weight_bps,
            status,
            observation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "feed_sequence": self.feed_sequence,
            "feed_received_height": self.feed_received_height,
            "output_reference": self.output_reference.public_record(),
            "finality": self.finality.public_record(),
            "amount_reserve_hint": self.amount_reserve_hint.public_record(),
            "wallet_scan_hint": self.wallet_scan_hint.public_record(),
            "watcher_weight_bps": self.watcher_weight_bps,
            "status": self.status.as_str(),
            "observation_root": self.observation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub observations: Vec<DepositLockObservation>,
    pub output_key_commitments: BTreeMap<String, String>,
    pub reserve_handoff_hints: BTreeMap<String, String>,
    pub lock_proof_roots: BTreeMap<String, String>,
    pub mismatches: Vec<MismatchRecord>,
    pub release_holds: Vec<ReleaseHold>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            observations: Vec::new(),
            output_key_commitments: BTreeMap::new(),
            reserve_handoff_hints: BTreeMap::new(),
            lock_proof_roots: BTreeMap::new(),
            mismatches: Vec::new(),
            release_holds: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone());

        let output_reference = DepositOutputReference::new(
            "0f3d-devnet-lock-txid-canonical-0001",
            2,
            label_root("one_time_public_key", "deposit-output-0001"),
            label_root("key_image_hint", "spend-hidden-until-release-0001"),
            label_root("commitment_mask_hint", "mask-hidden-until-wallet-scan-0001"),
        );
        let finality = FinalityLinkage::new(
            912_640,
            config.reference_monero_height,
            config.min_confirmations,
            label_root("monero_block_hash", "devnet-lock-block-912640"),
            label_root("checkpoint_header", "canonical-header-window-912640-912704"),
            String::new(),
        );
        let amount_reserve_hint = AmountReserveCommitmentHint::new(
            "xmr",
            label_root("amount_commitment", "deposit-amount-hidden-0001"),
            label_root("reserve_account", "reserve-bucket-devnet-xmr-a"),
            42,
            label_root("reserve_handoff", "reserve-handoff-devnet-epoch-42"),
        );
        let wallet_scan_hint = WalletScanHint::new(
            "wallet-scan-devnet-0001",
            label_root("view_tag", "view-tag-bucket-0001"),
            label_root("subaddress_hint", "subaddress-lane-bridge-deposits"),
            label_root("encrypted_memo", "deposit-note-memo-0001"),
            65_536,
            912_600,
            912_720,
        );
        let accepted = DepositLockObservation::new(
            1,
            912_705,
            output_reference,
            finality,
            amount_reserve_hint,
            wallet_scan_hint,
            7_500,
            ObservationStatus::Accepted,
        );

        let mismatch = MismatchRecord::new(
            MismatchKind::AmountCommitment,
            accepted.observation_root.clone(),
            accepted.amount_reserve_hint.amount_commitment_root.clone(),
            label_root("amount_commitment", "unexpected-live-feed-amount-root"),
            config.fail_closed_on_any_mismatch,
            config.reference_monero_height,
        );
        let hold = ReleaseHold::new(
            accepted.observation_id.clone(),
            "release_window_not_elapsed",
            accepted.finality.lock_height + config.release_hold_blocks,
            false,
        );

        state.output_key_commitments.insert(
            accepted.output_reference.output_reference_root.clone(),
            accepted.output_reference.one_time_public_key.clone(),
        );
        state.reserve_handoff_hints.insert(
            accepted.amount_reserve_hint.reserve_handoff_root.clone(),
            accepted
                .amount_reserve_hint
                .reserve_account_hint_root
                .clone(),
        );
        state.lock_proof_roots.insert(
            accepted.observation_id.clone(),
            lock_proof_root(&accepted, &config),
        );
        state.observations.push(accepted);
        state.mismatches.push(mismatch);
        state.release_holds.push(hold);
        state
    }

    pub fn public_record(&self) -> Value {
        let observation_records = self
            .observations
            .iter()
            .map(DepositLockObservation::public_record)
            .collect::<Vec<_>>();
        let mismatch_records = self
            .mismatches
            .iter()
            .map(MismatchRecord::public_record)
            .collect::<Vec<_>>();
        let release_hold_records = self
            .release_holds
            .iter()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>();

        let deposit_observation_root = merkle_root(
            &format!("{DOMAIN}:deposit-observations"),
            &observation_records,
        );
        let lock_proof_root = map_root("lock_proof_roots", &self.lock_proof_roots);
        let wallet_scan_surface_root = merkle_root(
            &format!("{DOMAIN}:wallet-scan-surfaces"),
            &self
                .observations
                .iter()
                .map(|observation| observation.wallet_scan_hint.public_record())
                .collect::<Vec<_>>(),
        );
        let output_key_commitment_root =
            map_root("output_key_commitments", &self.output_key_commitments);
        let reserve_handoff_hint_root =
            map_root("reserve_handoff_hints", &self.reserve_handoff_hints);
        let mismatch_record_root = merkle_root(&format!("{DOMAIN}:mismatches"), &mismatch_records);
        let release_hold_root =
            merkle_root(&format!("{DOMAIN}:release-holds"), &release_hold_records);

        json!({
            "config": self.config.public_record(),
            "observation_count": self.observations.len(),
            "mismatch_count": self.mismatches.len(),
            "release_hold_count": self.release_holds.len(),
            "deposit_observation_root": deposit_observation_root,
            "lock_proof_root": lock_proof_root,
            "wallet_scan_surface_root": wallet_scan_surface_root,
            "output_key_commitment_root": output_key_commitment_root,
            "reserve_handoff_hint_root": reserve_handoff_hint_root,
            "mismatch_record_root": mismatch_record_root,
            "release_hold_root": release_hold_root,
            "observations": observation_records,
            "output_key_commitments": self.output_key_commitments,
            "reserve_handoff_hints": self.reserve_handoff_hints,
            "lock_proof_roots": self.lock_proof_roots,
            "mismatches": mismatch_records,
            "release_holds": release_hold_records,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn record_root(label: &str, payload: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn label_root(label: &str, value: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:label-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn lock_proof_root(observation: &DepositLockObservation, config: &Config) -> String {
    domain_hash(
        &format!("{DOMAIN}:lock-proof-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.feed_id),
            HashPart::Str(&config.observer_id),
            HashPart::Str(&observation.observation_id),
            HashPart::Str(&observation.observation_root),
            HashPart::Str(&observation.output_reference.output_reference_root),
            HashPart::Str(&observation.finality.finality_link_root),
            HashPart::Str(&observation.amount_reserve_hint.commitment_hint_root),
            HashPart::Str(&observation.wallet_scan_hint.wallet_scan_root),
            HashPart::Int(observation.feed_sequence as i128),
            HashPart::Int(observation.feed_received_height as i128),
        ],
        32,
    )
}

fn map_root(label: &str, map: &BTreeMap<String, String>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

fn bool_marker(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
