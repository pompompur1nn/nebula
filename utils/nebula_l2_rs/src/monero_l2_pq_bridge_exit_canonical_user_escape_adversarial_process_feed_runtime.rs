use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAdversarialProcessFeedRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-process-feed-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub lane_id: String,
    pub process_feed_lane: String,
    pub reconciliation_lane: String,
    pub adversarial_policy: String,
    pub min_probe_count: u64,
    pub min_watcher_weight: u64,
    pub min_pq_epoch: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_leak_score: u64,
    pub hold_release_on_any_probe: u64,
    pub require_fail_closed_runtime_output: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lane_id: "canonical_user_escape_adversarial_process_feed".to_string(),
            process_feed_lane: "process_fed_adversarial_bridge_exit_outputs".to_string(),
            reconciliation_lane:
                "canonical_user_escape_adversarial_gap_runtime_output_reconciliation".to_string(),
            adversarial_policy: "fail_closed_hold_release_on_hostile_runtime_output".to_string(),
            min_probe_count: 9,
            min_watcher_weight: 67,
            min_pq_epoch: 7,
            min_reserve_coverage_bps: 12_500,
            max_metadata_leak_score: 0,
            hold_release_on_any_probe: 1,
            require_fail_closed_runtime_output: 1,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "process_feed_lane": self.process_feed_lane,
            "reconciliation_lane": self.reconciliation_lane,
            "adversarial_policy": self.adversarial_policy,
            "min_probe_count": self.min_probe_count,
            "min_watcher_weight": self.min_watcher_weight,
            "min_pq_epoch": self.min_pq_epoch,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_metadata_leak_score": self.max_metadata_leak_score,
            "hold_release_on_any_probe": self.hold_release_on_any_probe,
            "require_fail_closed_runtime_output": self.require_fail_closed_runtime_output,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialProbe {
    ReorgDepth,
    WatcherCollusion,
    SequencerHalt,
    ForgedReceipt,
    StalePqEpoch,
    LiquidityShortfall,
    MetadataLeak,
    ReplayNullifier,
    WalletMismatch,
}

impl AdversarialProbe {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReorgDepth => "reorg_depth",
            Self::WatcherCollusion => "watcher_collusion",
            Self::SequencerHalt => "sequencer_halt",
            Self::ForgedReceipt => "forged_receipt",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::MetadataLeak => "metadata_leak",
            Self::ReplayNullifier => "replay_nullifier",
            Self::WalletMismatch => "wallet_mismatch",
        }
    }

    pub fn feed_source(self) -> &'static str {
        match self {
            Self::ReorgDepth => "monero_watcher_process",
            Self::WatcherCollusion => "watcher_quorum_monitor",
            Self::SequencerHalt => "sequencer_liveness_process",
            Self::ForgedReceipt => "receipt_replay_detector",
            Self::StalePqEpoch => "pq_authority_process",
            Self::LiquidityShortfall => "reserve_process",
            Self::MetadataLeak => "wallet_scanner_privacy_monitor",
            Self::ReplayNullifier => "nullifier_replay_process",
            Self::WalletMismatch => "wallet_scanner_process",
        }
    }

    pub fn blocker_kind(self) -> &'static str {
        match self {
            Self::ReorgDepth => "monero_reorg_depth_exceeds_release_window",
            Self::WatcherCollusion => "watcher_quorum_collusion_detected",
            Self::SequencerHalt => "sequencer_halt_requires_escape_mode",
            Self::ForgedReceipt => "forged_or_unbound_receipt_detected",
            Self::StalePqEpoch => "stale_pq_authority_epoch",
            Self::LiquidityShortfall => "reserve_coverage_below_exit_floor",
            Self::MetadataLeak => "metadata_leak_exceeds_privacy_budget",
            Self::ReplayNullifier => "nullifier_replay_detected",
            Self::WalletMismatch => "wallet_visible_output_mismatch",
        }
    }

    pub fn wallet_notice(self) -> &'static str {
        match self {
            Self::ReorgDepth => "wait_for_monero_finality_refresh",
            Self::WatcherCollusion => "switch_to_emergency_watcher_set",
            Self::SequencerHalt => "prepare_forced_exit_bundle",
            Self::ForgedReceipt => "reject_receipt_and_request_transcript",
            Self::StalePqEpoch => "wait_for_pq_epoch_rotation",
            Self::LiquidityShortfall => "queue_exit_until_reserve_refresh",
            Self::MetadataLeak => "rotate_scan_window_and_mask_timing",
            Self::ReplayNullifier => "freeze_replayed_nullifier_claim",
            Self::WalletMismatch => "rescan_wallet_evidence_before_release",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedAdversarialProcessOutput {
    pub probe: AdversarialProbe,
    pub ordinal: u64,
    pub process_id: String,
    pub feed_source: String,
    pub observed_height: u64,
    pub input_evidence_root: String,
    pub runtime_output_root: String,
    pub watcher_weight: u64,
    pub pq_epoch: u64,
    pub reserve_coverage_bps: u64,
    pub metadata_leak_score: u64,
    pub nullifier_replay_count: u64,
    pub wallet_mismatch_count: u64,
    pub release_instruction_count: u64,
    pub runtime_decision: String,
    pub release_allowed: u64,
    pub quarantine_required: u64,
    pub output_digest: String,
}

impl ObservedAdversarialProcessOutput {
    pub fn devnet(config: &Config, probe: AdversarialProbe, ordinal: u64) -> Self {
        let process_id = label_root("process", probe.as_str(), ordinal);
        let feed_source = probe.feed_source().to_string();
        let observed_height = 220_000 + ordinal;
        let watcher_weight = match probe {
            AdversarialProbe::WatcherCollusion => config.min_watcher_weight.saturating_sub(8),
            AdversarialProbe::ReorgDepth => config.min_watcher_weight,
            _ => config.min_watcher_weight.saturating_add(5),
        };
        let pq_epoch = match probe {
            AdversarialProbe::StalePqEpoch => config.min_pq_epoch.saturating_sub(1),
            _ => config.min_pq_epoch.saturating_add(2),
        };
        let reserve_coverage_bps = match probe {
            AdversarialProbe::LiquidityShortfall => {
                config.min_reserve_coverage_bps.saturating_sub(1_000)
            }
            _ => config.min_reserve_coverage_bps.saturating_add(500),
        };
        let metadata_leak_score = match probe {
            AdversarialProbe::MetadataLeak => config.max_metadata_leak_score.saturating_add(7),
            _ => config.max_metadata_leak_score,
        };
        let nullifier_replay_count = match probe {
            AdversarialProbe::ReplayNullifier => 2,
            _ => 0,
        };
        let wallet_mismatch_count = match probe {
            AdversarialProbe::WalletMismatch => 1,
            _ => 0,
        };
        let release_instruction_count = match probe {
            AdversarialProbe::ForgedReceipt => 1,
            _ => 0,
        };
        let input_evidence_root = evidence_root(
            "adversarial-input",
            probe,
            ordinal,
            watcher_weight,
            pq_epoch,
            reserve_coverage_bps,
        );
        let runtime_output_root = evidence_root(
            "adversarial-runtime-output",
            probe,
            ordinal,
            metadata_leak_score,
            nullifier_replay_count,
            wallet_mismatch_count,
        );
        let runtime_decision = "hold_release".to_string();
        let release_allowed = 0;
        let quarantine_required = 1;
        let output_digest = domain_hash(
            "canonical-user-escape-adversarial-process-feed:output-digest",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(probe.as_str()),
                HashPart::Str(&process_id),
                HashPart::Str(&input_evidence_root),
                HashPart::Str(&runtime_output_root),
                HashPart::U64(watcher_weight),
                HashPart::U64(pq_epoch),
                HashPart::U64(reserve_coverage_bps),
                HashPart::U64(metadata_leak_score),
                HashPart::U64(nullifier_replay_count),
                HashPart::U64(wallet_mismatch_count),
                HashPart::U64(release_instruction_count),
                HashPart::Str(&runtime_decision),
                HashPart::U64(release_allowed),
                HashPart::U64(quarantine_required),
            ],
            32,
        );
        Self {
            probe,
            ordinal,
            process_id,
            feed_source,
            observed_height,
            input_evidence_root,
            runtime_output_root,
            watcher_weight,
            pq_epoch,
            reserve_coverage_bps,
            metadata_leak_score,
            nullifier_replay_count,
            wallet_mismatch_count,
            release_instruction_count,
            runtime_decision,
            release_allowed,
            quarantine_required,
            output_digest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "probe": self.probe,
            "ordinal": self.ordinal,
            "process_id": self.process_id,
            "feed_source": self.feed_source,
            "observed_height": self.observed_height,
            "input_evidence_root": self.input_evidence_root,
            "runtime_output_root": self.runtime_output_root,
            "watcher_weight": self.watcher_weight,
            "pq_epoch": self.pq_epoch,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "metadata_leak_score": self.metadata_leak_score,
            "nullifier_replay_count": self.nullifier_replay_count,
            "wallet_mismatch_count": self.wallet_mismatch_count,
            "release_instruction_count": self.release_instruction_count,
            "runtime_decision": self.runtime_decision,
            "release_allowed": self.release_allowed,
            "quarantine_required": self.quarantine_required,
            "output_digest": self.output_digest,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed_adversarial_process_output", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBlocker {
    pub probe: AdversarialProbe,
    pub blocker_kind: String,
    pub process_id: String,
    pub runtime_output_root: String,
    pub reason: String,
    pub wallet_notice: String,
    pub severity: String,
    pub blocks_release: u64,
    pub blocker_root: String,
}

impl ReleaseBlocker {
    pub fn from_output(config: &Config, output: &ObservedAdversarialProcessOutput) -> Self {
        let reason = blocker_reason(config, output);
        let blocker_kind = output.probe.blocker_kind().to_string();
        let wallet_notice = output.probe.wallet_notice().to_string();
        let severity = "critical".to_string();
        let blocks_release = config.hold_release_on_any_probe;
        let blocker_root = domain_hash(
            "canonical-user-escape-adversarial-process-feed:blocker",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(output.probe.as_str()),
                HashPart::Str(&blocker_kind),
                HashPart::Str(&output.process_id),
                HashPart::Str(&output.runtime_output_root),
                HashPart::Str(&reason),
                HashPart::Str(&wallet_notice),
                HashPart::Str(&severity),
                HashPart::U64(blocks_release),
            ],
            32,
        );
        Self {
            probe: output.probe,
            blocker_kind,
            process_id: output.process_id.clone(),
            runtime_output_root: output.runtime_output_root.clone(),
            reason,
            wallet_notice,
            severity,
            blocks_release,
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "probe": self.probe,
            "blocker_kind": self.blocker_kind,
            "process_id": self.process_id,
            "runtime_output_root": self.runtime_output_root,
            "reason": self.reason,
            "wallet_notice": self.wallet_notice,
            "severity": self.severity,
            "blocks_release": self.blocks_release,
            "blocker_root": self.blocker_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletVisibleNotice {
    pub probe: AdversarialProbe,
    pub notice_id: String,
    pub wallet_action: String,
    pub public_safe_summary_root: String,
    pub hides_counterparty_metadata: u64,
    pub hides_exact_amount: u64,
    pub hides_scan_timing: u64,
    pub notice_root: String,
}

impl WalletVisibleNotice {
    pub fn from_blocker(blocker: &ReleaseBlocker, ordinal: u64) -> Self {
        let notice_id = label_root("wallet-notice", blocker.probe.as_str(), ordinal);
        let wallet_action = blocker.wallet_notice.clone();
        let public_safe_summary_root = domain_hash(
            "canonical-user-escape-adversarial-process-feed:public-safe-summary",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(blocker.probe.as_str()),
                HashPart::Str(&blocker.blocker_kind),
                HashPart::Str(&wallet_action),
                HashPart::Str(&blocker.blocker_root),
            ],
            32,
        );
        let hides_counterparty_metadata = 1;
        let hides_exact_amount = 1;
        let hides_scan_timing = 1;
        let notice_root = domain_hash(
            "canonical-user-escape-adversarial-process-feed:wallet-notice",
            &[
                HashPart::Str(&notice_id),
                HashPart::Str(&wallet_action),
                HashPart::Str(&public_safe_summary_root),
                HashPart::U64(hides_counterparty_metadata),
                HashPart::U64(hides_exact_amount),
                HashPart::U64(hides_scan_timing),
            ],
            32,
        );
        Self {
            probe: blocker.probe,
            notice_id,
            wallet_action,
            public_safe_summary_root,
            hides_counterparty_metadata,
            hides_exact_amount,
            hides_scan_timing,
            notice_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "probe": self.probe,
            "notice_id": self.notice_id,
            "wallet_action": self.wallet_action,
            "public_safe_summary_root": self.public_safe_summary_root,
            "hides_counterparty_metadata": self.hides_counterparty_metadata,
            "hides_exact_amount": self.hides_exact_amount,
            "hides_scan_timing": self.hides_scan_timing,
            "notice_root": self.notice_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedIntegrityVerdict {
    pub observed_output_count: u64,
    pub blocker_count: u64,
    pub wallet_notice_count: u64,
    pub all_outputs_fail_closed: u64,
    pub all_releases_held: u64,
    pub privacy_safe_wallet_notices: u64,
    pub release_allowed: u64,
    pub verdict: String,
    pub verdict_root: String,
}

impl FeedIntegrityVerdict {
    pub fn from_state(
        config: &Config,
        outputs: &[ObservedAdversarialProcessOutput],
        blockers: &[ReleaseBlocker],
        notices: &[WalletVisibleNotice],
    ) -> Self {
        let all_outputs_fail_closed = all_outputs_fail_closed(outputs);
        let all_releases_held = all_releases_held(outputs);
        let privacy_safe_wallet_notices = privacy_safe_wallet_notices(notices);
        let release_allowed = 0;
        let verdict = if outputs.len() as u64 >= config.min_probe_count
            && blockers.len() == outputs.len()
            && notices.len() == blockers.len()
            && all_outputs_fail_closed == 1
            && all_releases_held == 1
            && privacy_safe_wallet_notices == 1
        {
            "adversarial_process_feed_fail_closed_ready".to_string()
        } else {
            "adversarial_process_feed_incomplete_hold_release".to_string()
        };
        let observed_output_count = outputs.len() as u64;
        let blocker_count = blockers.len() as u64;
        let wallet_notice_count = notices.len() as u64;
        let verdict_root = domain_hash(
            "canonical-user-escape-adversarial-process-feed:verdict",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.lane_id),
                HashPart::U64(observed_output_count),
                HashPart::U64(blocker_count),
                HashPart::U64(wallet_notice_count),
                HashPart::U64(all_outputs_fail_closed),
                HashPart::U64(all_releases_held),
                HashPart::U64(privacy_safe_wallet_notices),
                HashPart::U64(release_allowed),
                HashPart::Str(&verdict),
            ],
            32,
        );
        Self {
            observed_output_count,
            blocker_count,
            wallet_notice_count,
            all_outputs_fail_closed,
            all_releases_held,
            privacy_safe_wallet_notices,
            release_allowed,
            verdict,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observed_output_count": self.observed_output_count,
            "blocker_count": self.blocker_count,
            "wallet_notice_count": self.wallet_notice_count,
            "all_outputs_fail_closed": self.all_outputs_fail_closed,
            "all_releases_held": self.all_releases_held,
            "privacy_safe_wallet_notices": self.privacy_safe_wallet_notices,
            "release_allowed": self.release_allowed,
            "verdict": self.verdict,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub observed_outputs: Vec<ObservedAdversarialProcessOutput>,
    pub release_blockers: Vec<ReleaseBlocker>,
    pub wallet_notices: Vec<WalletVisibleNotice>,
    pub verdict: FeedIntegrityVerdict,
    pub observed_output_root: String,
    pub blocker_root: String,
    pub wallet_notice_root: String,
    pub release_hold_root: String,
    pub feed_integrity_root: String,
}

impl State {
    pub fn new(
        config: Config,
        observed_outputs: Vec<ObservedAdversarialProcessOutput>,
    ) -> Result<Self> {
        if observed_outputs.len() as u64 != config.min_probe_count {
            return Err("adversarial process feed probe count mismatch".to_string());
        }
        let release_blockers = observed_outputs
            .iter()
            .map(|output| ReleaseBlocker::from_output(&config, output))
            .collect::<Vec<_>>();
        let wallet_notices = release_blockers
            .iter()
            .enumerate()
            .map(|(index, blocker)| WalletVisibleNotice::from_blocker(blocker, index as u64))
            .collect::<Vec<_>>();
        let verdict = FeedIntegrityVerdict::from_state(
            &config,
            &observed_outputs,
            &release_blockers,
            &wallet_notices,
        );
        let observed_output_root = merkle_root(
            "canonical-user-escape-adversarial-process-feed:observed-outputs",
            &observed_outputs
                .iter()
                .map(ObservedAdversarialProcessOutput::public_record)
                .collect::<Vec<_>>(),
        );
        let blocker_root = merkle_root(
            "canonical-user-escape-adversarial-process-feed:blockers",
            &release_blockers
                .iter()
                .map(ReleaseBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let wallet_notice_root = merkle_root(
            "canonical-user-escape-adversarial-process-feed:wallet-notices",
            &wallet_notices
                .iter()
                .map(WalletVisibleNotice::public_record)
                .collect::<Vec<_>>(),
        );
        let release_hold_root = release_hold_root(&config, &release_blockers, &verdict);
        let feed_integrity_root = domain_hash(
            "canonical-user-escape-adversarial-process-feed:integrity",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.state_root()),
                HashPart::Str(&observed_output_root),
                HashPart::Str(&blocker_root),
                HashPart::Str(&wallet_notice_root),
                HashPart::Str(&release_hold_root),
                HashPart::Str(&verdict.verdict_root),
            ],
            32,
        );
        Ok(Self {
            config,
            observed_outputs,
            release_blockers,
            wallet_notices,
            verdict,
            observed_output_root,
            blocker_root,
            wallet_notice_root,
            release_hold_root,
            feed_integrity_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::default();
        let observed_outputs = devnet_observed_outputs(&config);
        match Self::new(config, observed_outputs) {
            Ok(state) => state,
            Err(error) => Self::invalid(error),
        }
    }

    pub fn invalid(error: String) -> Self {
        let config = Config::default();
        let release_hold_root = domain_hash(
            "canonical-user-escape-adversarial-process-feed:invalid-release-hold",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.lane_id),
                HashPart::Str(&error),
            ],
            32,
        );
        let verdict = FeedIntegrityVerdict {
            observed_output_count: 0,
            blocker_count: 0,
            wallet_notice_count: 0,
            all_outputs_fail_closed: 0,
            all_releases_held: 1,
            privacy_safe_wallet_notices: 0,
            release_allowed: 0,
            verdict: "adversarial_process_feed_invalid_hold_release".to_string(),
            verdict_root: release_hold_root.clone(),
        };
        let feed_integrity_root = domain_hash(
            "canonical-user-escape-adversarial-process-feed:invalid-integrity",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&error),
                HashPart::Str(&release_hold_root),
            ],
            32,
        );
        Self {
            config,
            observed_outputs: Vec::new(),
            release_blockers: Vec::new(),
            wallet_notices: Vec::new(),
            verdict,
            observed_output_root: merkle_root(
                "canonical-user-escape-adversarial-process-feed:observed-outputs",
                &[],
            ),
            blocker_root: merkle_root(
                "canonical-user-escape-adversarial-process-feed:blockers",
                &[],
            ),
            wallet_notice_root: merkle_root(
                "canonical-user-escape-adversarial-process-feed:wallet-notices",
                &[],
            ),
            release_hold_root,
            feed_integrity_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "observed_output_root": self.observed_output_root,
            "blocker_root": self.blocker_root,
            "wallet_notice_root": self.wallet_notice_root,
            "release_hold_root": self.release_hold_root,
            "feed_integrity_root": self.feed_integrity_root,
            "verdict": self.verdict.public_record(),
            "observed_outputs": self
                .observed_outputs
                .iter()
                .map(ObservedAdversarialProcessOutput::public_record)
                .collect::<Vec<_>>(),
            "release_blockers": self
                .release_blockers
                .iter()
                .map(ReleaseBlocker::public_record)
                .collect::<Vec<_>>(),
            "wallet_notices": self
                .wallet_notices
                .iter()
                .map(WalletVisibleNotice::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "observed_output_root": self.observed_output_root,
                "blocker_root": self.blocker_root,
                "wallet_notice_root": self.wallet_notice_root,
                "release_hold_root": self.release_hold_root,
                "feed_integrity_root": self.feed_integrity_root,
                "verdict_root": self.verdict.verdict_root,
            }),
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

fn devnet_observed_outputs(config: &Config) -> Vec<ObservedAdversarialProcessOutput> {
    [
        AdversarialProbe::ReorgDepth,
        AdversarialProbe::WatcherCollusion,
        AdversarialProbe::SequencerHalt,
        AdversarialProbe::ForgedReceipt,
        AdversarialProbe::StalePqEpoch,
        AdversarialProbe::LiquidityShortfall,
        AdversarialProbe::MetadataLeak,
        AdversarialProbe::ReplayNullifier,
        AdversarialProbe::WalletMismatch,
    ]
    .iter()
    .enumerate()
    .map(|(index, probe)| ObservedAdversarialProcessOutput::devnet(config, *probe, index as u64))
    .collect()
}

fn blocker_reason(config: &Config, output: &ObservedAdversarialProcessOutput) -> String {
    match output.probe {
        AdversarialProbe::ReorgDepth => format!(
            "monero watcher reports release-risk reorg at height {}",
            output.observed_height
        ),
        AdversarialProbe::WatcherCollusion => format!(
            "watcher weight {} below emergency quorum {} after collusion evidence",
            output.watcher_weight, config.min_watcher_weight
        ),
        AdversarialProbe::SequencerHalt => {
            "sequencer liveness process requires forced-exit mode before release".to_string()
        }
        AdversarialProbe::ForgedReceipt => format!(
            "receipt process saw {} forged release instruction",
            output.release_instruction_count
        ),
        AdversarialProbe::StalePqEpoch => format!(
            "pq authority epoch {} below required epoch {}",
            output.pq_epoch, config.min_pq_epoch
        ),
        AdversarialProbe::LiquidityShortfall => format!(
            "reserve coverage {} bps below required {} bps",
            output.reserve_coverage_bps, config.min_reserve_coverage_bps
        ),
        AdversarialProbe::MetadataLeak => format!(
            "wallet scanner privacy monitor leak score {} exceeds budget {}",
            output.metadata_leak_score, config.max_metadata_leak_score
        ),
        AdversarialProbe::ReplayNullifier => format!(
            "nullifier replay process reports {} replayed claims",
            output.nullifier_replay_count
        ),
        AdversarialProbe::WalletMismatch => format!(
            "wallet scanner reports {} wallet-visible output mismatch",
            output.wallet_mismatch_count
        ),
    }
}

fn all_outputs_fail_closed(outputs: &[ObservedAdversarialProcessOutput]) -> u64 {
    if outputs
        .iter()
        .all(|output| output.runtime_decision == "hold_release" && output.quarantine_required == 1)
    {
        1
    } else {
        0
    }
}

fn all_releases_held(outputs: &[ObservedAdversarialProcessOutput]) -> u64 {
    if outputs.iter().all(|output| output.release_allowed == 0) {
        1
    } else {
        0
    }
}

fn privacy_safe_wallet_notices(notices: &[WalletVisibleNotice]) -> u64 {
    if notices.iter().all(|notice| {
        notice.hides_counterparty_metadata == 1
            && notice.hides_exact_amount == 1
            && notice.hides_scan_timing == 1
    }) {
        1
    } else {
        0
    }
}

fn release_hold_root(
    config: &Config,
    blockers: &[ReleaseBlocker],
    verdict: &FeedIntegrityVerdict,
) -> String {
    let blocker_roots = blockers
        .iter()
        .map(|blocker| json!(blocker.blocker_root))
        .collect::<Vec<_>>();
    domain_hash(
        "canonical-user-escape-adversarial-process-feed:release-hold",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.lane_id),
            HashPart::Str(&merkle_root(
                "canonical-user-escape-adversarial-process-feed:release-hold:blockers",
                &blocker_roots,
            )),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(config.hold_release_on_any_probe),
        ],
        32,
    )
}

fn evidence_root(
    domain: &str,
    probe: AdversarialProbe,
    ordinal: u64,
    first_metric: u64,
    second_metric: u64,
    third_metric: u64,
) -> String {
    domain_hash(
        &format!("canonical-user-escape-adversarial-process-feed:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(probe.as_str()),
            HashPart::U64(ordinal),
            HashPart::U64(first_metric),
            HashPart::U64(second_metric),
            HashPart::U64(third_metric),
        ],
        32,
    )
}

fn label_root(label: &str, value: &str, ordinal: u64) -> String {
    domain_hash(
        "canonical-user-escape-adversarial-process-feed:label",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "canonical-user-escape-adversarial-process-feed:record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
