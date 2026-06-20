use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeWalletRecoveryBindingManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_WALLET_RECOVERY_BINDING_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-wallet-recovery-binding-manifest-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_WALLET_RECOVERY_BINDING_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "wallet-recovery-binding-manifest/1";
pub const HASH_SUITE: &str = "nebula-domain-hash+json-merkle-v1";
pub const BINDING_SUITE: &str = "wallet-recovery+forced-exit-binding+fail-closed-v1";
pub const DEFAULT_RUNTIME_GATE: &str = "cargo-runtime-heavy-gate-deferred";
pub const DEFAULT_RELEASE_CANDIDATE: &str = "bridge-exit-wallet-recovery-binding-rc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryBindingLane {
    WalletScanExport,
    PrivateNoteRecovery,
    ForcedExitClaim,
    PqWithdrawalAuthority,
    ObservedReceiptLink,
    LiveFeedLink,
    AdversarialRecovery,
    ReleaseBlocker,
}

impl RecoveryBindingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanExport => "wallet_scan_export",
            Self::PrivateNoteRecovery => "private_note_recovery",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::PqWithdrawalAuthority => "pq_withdrawal_authority",
            Self::ObservedReceiptLink => "observed_receipt_link",
            Self::LiveFeedLink => "live_feed_link",
            Self::AdversarialRecovery => "adversarial_recovery",
            Self::ReleaseBlocker => "release_blocker",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::WalletScanExport => "wallet scan export binding",
            Self::PrivateNoteRecovery => "private note recovery binding",
            Self::ForcedExitClaim => "forced-exit claim binding",
            Self::PqWithdrawalAuthority => "PQ withdrawal authority binding",
            Self::ObservedReceiptLink => "observed receipt link binding",
            Self::LiveFeedLink => "live feed link binding",
            Self::AdversarialRecovery => "adversarial wallet recovery binding",
            Self::ReleaseBlocker => "release blocker wallet recovery binding",
        }
    }

    pub fn requires_wallet_visibility(self) -> bool {
        matches!(
            self,
            Self::WalletScanExport | Self::PrivateNoteRecovery | Self::ForcedExitClaim
        )
    }

    pub fn requires_pq_authority(self) -> bool {
        matches!(
            self,
            Self::ForcedExitClaim | Self::PqWithdrawalAuthority | Self::ReleaseBlocker
        )
    }

    pub fn requires_fail_closed(self) -> bool {
        matches!(self, Self::AdversarialRecovery | Self::ReleaseBlocker)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryBindingStatus {
    DeferredUntilRuntime,
    BoundAndReady,
    MissingWalletExport,
    MissingObservedReceipt,
    MissingLiveFeed,
    PqAuthorityMismatch,
    PrivacySurfaceMismatch,
    ReleaseBlocked,
}

impl RecoveryBindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeferredUntilRuntime => "deferred_until_runtime",
            Self::BoundAndReady => "bound_and_ready",
            Self::MissingWalletExport => "missing_wallet_export",
            Self::MissingObservedReceipt => "missing_observed_receipt",
            Self::MissingLiveFeed => "missing_live_feed",
            Self::PqAuthorityMismatch => "pq_authority_mismatch",
            Self::PrivacySurfaceMismatch => "privacy_surface_mismatch",
            Self::ReleaseBlocked => "release_blocked",
        }
    }

    pub fn blocks_release(self) -> bool {
        !matches!(self, Self::BoundAndReady)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestVerdict {
    WalletRecoveryBindingRequired,
    ReleaseBlockedUntilWalletCanRecover,
    HeavyGateReadyWhenCargoAllowed,
}

impl ManifestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecoveryBindingRequired => "wallet_recovery_binding_required",
            Self::ReleaseBlockedUntilWalletCanRecover => "release_blocked_until_wallet_can_recover",
            Self::HeavyGateReadyWhenCargoAllowed => "heavy_gate_ready_when_cargo_allowed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub binding_suite: String,
    pub runtime_gate: String,
    pub release_candidate: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub min_wallet_scan_windows: u64,
    pub max_metadata_bytes: u64,
    pub min_pq_authority_signers: u64,
    pub min_recovery_source_links: u64,
    pub mismatch_policy: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            binding_suite: BINDING_SUITE.to_string(),
            runtime_gate: DEFAULT_RUNTIME_GATE.to_string(),
            release_candidate: DEFAULT_RELEASE_CANDIDATE.to_string(),
            l2_reference_height: 75_000,
            monero_reference_height: 3_261_120,
            min_wallet_scan_windows: 3,
            max_metadata_bytes: 384,
            min_pq_authority_signers: 5,
            min_recovery_source_links: 4,
            mismatch_policy: "block release and preserve user-forced-exit evidence".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "binding_suite": self.binding_suite,
            "runtime_gate": self.runtime_gate,
            "release_candidate": self.release_candidate,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "min_wallet_scan_windows": self.min_wallet_scan_windows,
            "max_metadata_bytes": self.max_metadata_bytes,
            "min_pq_authority_signers": self.min_pq_authority_signers,
            "min_recovery_source_links": self.min_recovery_source_links,
            "mismatch_policy": self.mismatch_policy,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-wallet-recovery-binding-config",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBindingRequirement {
    pub lane: RecoveryBindingLane,
    pub lane_label: String,
    pub wallet_export_required: bool,
    pub observed_receipt_required: bool,
    pub live_feed_required: bool,
    pub pq_authority_required: bool,
    pub fail_closed_required: bool,
    pub min_wallet_scan_windows: u64,
    pub max_metadata_bytes: u64,
    pub min_pq_authority_signers: u64,
    pub requirement_root: String,
    pub expected_binding_root: String,
}

impl RecoveryBindingRequirement {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane_label,
            "wallet_export_required": self.wallet_export_required,
            "observed_receipt_required": self.observed_receipt_required,
            "live_feed_required": self.live_feed_required,
            "pq_authority_required": self.pq_authority_required,
            "fail_closed_required": self.fail_closed_required,
            "min_wallet_scan_windows": self.min_wallet_scan_windows,
            "max_metadata_bytes": self.max_metadata_bytes,
            "min_pq_authority_signers": self.min_pq_authority_signers,
            "requirement_root": self.requirement_root,
            "expected_binding_root": self.expected_binding_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-wallet-recovery-binding-requirement",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBindingRecord {
    pub lane: RecoveryBindingLane,
    pub wallet_export_root: String,
    pub private_note_root: String,
    pub forced_exit_claim_root: String,
    pub pq_authority_root: String,
    pub observed_receipt_root: String,
    pub live_feed_root: String,
    pub privacy_surface_root: String,
    pub metadata_budget_bytes: u64,
    pub wallet_scan_windows: u64,
    pub pq_authority_signers: u64,
    pub recovery_source_links: u64,
    pub wallet_export_bound: bool,
    pub private_note_bound: bool,
    pub forced_exit_claim_bound: bool,
    pub pq_authority_bound: bool,
    pub observed_receipt_bound: bool,
    pub live_feed_bound: bool,
    pub privacy_surface_satisfied: bool,
    pub release_blockers: u64,
    pub status: RecoveryBindingStatus,
}

impl RecoveryBindingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "wallet_export_root": self.wallet_export_root,
            "private_note_root": self.private_note_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "pq_authority_root": self.pq_authority_root,
            "observed_receipt_root": self.observed_receipt_root,
            "live_feed_root": self.live_feed_root,
            "privacy_surface_root": self.privacy_surface_root,
            "metadata_budget_bytes": self.metadata_budget_bytes,
            "wallet_scan_windows": self.wallet_scan_windows,
            "pq_authority_signers": self.pq_authority_signers,
            "recovery_source_links": self.recovery_source_links,
            "wallet_export_bound": self.wallet_export_bound,
            "private_note_bound": self.private_note_bound,
            "forced_exit_claim_bound": self.forced_exit_claim_bound,
            "pq_authority_bound": self.pq_authority_bound,
            "observed_receipt_bound": self.observed_receipt_bound,
            "live_feed_bound": self.live_feed_bound,
            "privacy_surface_satisfied": self.privacy_surface_satisfied,
            "release_blockers": self.release_blockers,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-wallet-recovery-binding-record",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.wallet_export_root),
                HashPart::Str(&self.forced_exit_claim_root),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBindingMismatch {
    pub lane: RecoveryBindingLane,
    pub mismatch_code: String,
    pub expected_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub severity: String,
    pub release_effect: String,
}

impl RecoveryBindingMismatch {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "mismatch_code": self.mismatch_code,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "severity": self.severity,
            "release_effect": self.release_effect,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-wallet-recovery-binding-mismatch",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.mismatch_code),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBindingCounters {
    pub total_lanes: u64,
    pub bound_lanes: u64,
    pub release_blocked_lanes: u64,
    pub missing_wallet_exports: u64,
    pub missing_observed_receipts: u64,
    pub missing_live_feeds: u64,
    pub pq_authority_mismatches: u64,
    pub privacy_surface_mismatches: u64,
}

impl RecoveryBindingCounters {
    pub fn from_records(records: &[RecoveryBindingRecord]) -> Self {
        let mut counters = Self {
            total_lanes: records.len() as u64,
            bound_lanes: 0,
            release_blocked_lanes: 0,
            missing_wallet_exports: 0,
            missing_observed_receipts: 0,
            missing_live_feeds: 0,
            pq_authority_mismatches: 0,
            privacy_surface_mismatches: 0,
        };

        for record in records {
            if record.status.blocks_release() {
                counters.release_blocked_lanes += 1;
            } else {
                counters.bound_lanes += 1;
            }
            match record.status {
                RecoveryBindingStatus::MissingWalletExport
                | RecoveryBindingStatus::DeferredUntilRuntime => {
                    counters.missing_wallet_exports += 1;
                }
                RecoveryBindingStatus::MissingObservedReceipt => {
                    counters.missing_observed_receipts += 1;
                }
                RecoveryBindingStatus::MissingLiveFeed => counters.missing_live_feeds += 1,
                RecoveryBindingStatus::PqAuthorityMismatch => {
                    counters.pq_authority_mismatches += 1;
                }
                RecoveryBindingStatus::PrivacySurfaceMismatch => {
                    counters.privacy_surface_mismatches += 1;
                }
                RecoveryBindingStatus::ReleaseBlocked => counters.release_blocked_lanes += 1,
                RecoveryBindingStatus::BoundAndReady => {}
            }
        }

        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_lanes": self.total_lanes,
            "bound_lanes": self.bound_lanes,
            "release_blocked_lanes": self.release_blocked_lanes,
            "missing_wallet_exports": self.missing_wallet_exports,
            "missing_observed_receipts": self.missing_observed_receipts,
            "missing_live_feeds": self.missing_live_feeds,
            "pq_authority_mismatches": self.pq_authority_mismatches,
            "privacy_surface_mismatches": self.privacy_surface_mismatches,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-wallet-recovery-binding-counters",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBindingRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub record_root: String,
    pub wallet_export_root: String,
    pub private_note_root: String,
    pub forced_exit_claim_root: String,
    pub pq_authority_root: String,
    pub observed_receipt_root: String,
    pub live_feed_root: String,
    pub privacy_surface_root: String,
    pub mismatch_root: String,
    pub release_hold_root: String,
    pub counter_root: String,
}

impl RecoveryBindingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "record_root": self.record_root,
            "wallet_export_root": self.wallet_export_root,
            "private_note_root": self.private_note_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "pq_authority_root": self.pq_authority_root,
            "observed_receipt_root": self.observed_receipt_root,
            "live_feed_root": self.live_feed_root,
            "privacy_surface_root": self.privacy_surface_root,
            "mismatch_root": self.mismatch_root,
            "release_hold_root": self.release_hold_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-wallet-recovery-binding-roots",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBindingManifest {
    pub manifest_id: String,
    pub config: Config,
    pub requirements: Vec<RecoveryBindingRequirement>,
    pub records: Vec<RecoveryBindingRecord>,
    pub mismatches: Vec<RecoveryBindingMismatch>,
    pub counters: RecoveryBindingCounters,
    pub roots: RecoveryBindingRoots,
    pub release_holds: BTreeMap<String, String>,
    pub verdict: ManifestVerdict,
}

impl RecoveryBindingManifest {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = binding_requirements(&config);
        let records = binding_records(&config, &requirements);
        let mismatches = mismatch_records(&requirements, &records);
        let counters = RecoveryBindingCounters::from_records(&records);
        let release_holds = release_hold_reasons(&records);
        let roots = RecoveryBindingRoots {
            config_root: config.state_root(),
            requirement_root: requirement_merkle(&requirements),
            record_root: record_merkle(&records),
            wallet_export_root: lane_merkle(&records, "wallet_export"),
            private_note_root: lane_merkle(&records, "private_note"),
            forced_exit_claim_root: lane_merkle(&records, "forced_exit_claim"),
            pq_authority_root: lane_merkle(&records, "pq_authority"),
            observed_receipt_root: lane_merkle(&records, "observed_receipt"),
            live_feed_root: lane_merkle(&records, "live_feed"),
            privacy_surface_root: lane_merkle(&records, "privacy_surface"),
            mismatch_root: mismatch_merkle(&mismatches),
            release_hold_root: hold_root(&release_holds),
            counter_root: counters.state_root(),
        };
        let manifest_id = manifest_id(&config, &roots);
        let verdict = if counters.release_blocked_lanes == 0 {
            ManifestVerdict::HeavyGateReadyWhenCargoAllowed
        } else {
            ManifestVerdict::ReleaseBlockedUntilWalletCanRecover
        };

        Self {
            manifest_id,
            config,
            requirements,
            records,
            mismatches,
            counters,
            roots,
            release_holds,
            verdict,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(RecoveryBindingRequirement::public_record).collect::<Vec<_>>(),
            "records": self.records.iter().map(RecoveryBindingRecord::public_record).collect::<Vec<_>>(),
            "mismatches": self.mismatches.iter().map(RecoveryBindingMismatch::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "release_holds": self.release_holds,
            "verdict": self.verdict.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-wallet-recovery-binding-manifest-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.manifest_id),
                HashPart::Str(&self.roots.state_root()),
                HashPart::Json(&self.counters.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub manifest: RecoveryBindingManifest,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let manifest = RecoveryBindingManifest::devnet();
        let state_root = manifest.state_root();
        Self {
            manifest,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root,
            "manifest": self.manifest.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
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

fn binding_requirements(config: &Config) -> Vec<RecoveryBindingRequirement> {
    [
        RecoveryBindingLane::WalletScanExport,
        RecoveryBindingLane::PrivateNoteRecovery,
        RecoveryBindingLane::ForcedExitClaim,
        RecoveryBindingLane::PqWithdrawalAuthority,
        RecoveryBindingLane::ObservedReceiptLink,
        RecoveryBindingLane::LiveFeedLink,
        RecoveryBindingLane::AdversarialRecovery,
        RecoveryBindingLane::ReleaseBlocker,
    ]
    .into_iter()
    .map(|lane| RecoveryBindingRequirement {
        lane,
        lane_label: lane.label().to_string(),
        wallet_export_required: lane.requires_wallet_visibility(),
        observed_receipt_required: true,
        live_feed_required: true,
        pq_authority_required: lane.requires_pq_authority(),
        fail_closed_required: lane.requires_fail_closed(),
        min_wallet_scan_windows: config.min_wallet_scan_windows,
        max_metadata_bytes: config.max_metadata_bytes,
        min_pq_authority_signers: config.min_pq_authority_signers,
        requirement_root: requirement_root(lane),
        expected_binding_root: expected_binding_root(lane),
    })
    .collect()
}

fn binding_records(
    config: &Config,
    requirements: &[RecoveryBindingRequirement],
) -> Vec<RecoveryBindingRecord> {
    requirements
        .iter()
        .map(|requirement| {
            let wallet_export_bound = false;
            let private_note_bound = false;
            let forced_exit_claim_bound = false;
            let pq_authority_bound = false;
            let observed_receipt_bound = false;
            let live_feed_bound = false;
            let privacy_surface_satisfied = false;
            let wallet_scan_windows = 0;
            let pq_authority_signers = 0;
            let recovery_source_links = 0;
            let status = status_for(
                requirement,
                wallet_export_bound,
                observed_receipt_bound,
                live_feed_bound,
                pq_authority_bound,
                privacy_surface_satisfied,
            );
            let release_blockers = release_blocker_count(
                requirement,
                wallet_export_bound,
                observed_receipt_bound,
                live_feed_bound,
                pq_authority_bound,
                privacy_surface_satisfied,
                wallet_scan_windows,
                pq_authority_signers,
                recovery_source_links,
                config,
            );

            RecoveryBindingRecord {
                lane: requirement.lane,
                wallet_export_root: wallet_export_root(requirement.lane),
                private_note_root: private_note_root(requirement.lane),
                forced_exit_claim_root: forced_exit_claim_root(requirement.lane),
                pq_authority_root: pq_authority_root(requirement.lane),
                observed_receipt_root: observed_receipt_root(requirement.lane),
                live_feed_root: live_feed_root(requirement.lane),
                privacy_surface_root: privacy_surface_root(requirement.lane),
                metadata_budget_bytes: config.max_metadata_bytes + 1,
                wallet_scan_windows,
                pq_authority_signers,
                recovery_source_links,
                wallet_export_bound,
                private_note_bound,
                forced_exit_claim_bound,
                pq_authority_bound,
                observed_receipt_bound,
                live_feed_bound,
                privacy_surface_satisfied,
                release_blockers,
                status,
            }
        })
        .collect()
}

fn status_for(
    requirement: &RecoveryBindingRequirement,
    wallet_export_bound: bool,
    observed_receipt_bound: bool,
    live_feed_bound: bool,
    pq_authority_bound: bool,
    privacy_surface_satisfied: bool,
) -> RecoveryBindingStatus {
    if requirement.wallet_export_required && !wallet_export_bound {
        return RecoveryBindingStatus::MissingWalletExport;
    }
    if !observed_receipt_bound {
        return RecoveryBindingStatus::MissingObservedReceipt;
    }
    if !live_feed_bound {
        return RecoveryBindingStatus::MissingLiveFeed;
    }
    if requirement.pq_authority_required && !pq_authority_bound {
        return RecoveryBindingStatus::PqAuthorityMismatch;
    }
    if !privacy_surface_satisfied {
        return RecoveryBindingStatus::PrivacySurfaceMismatch;
    }
    RecoveryBindingStatus::BoundAndReady
}

fn release_blocker_count(
    requirement: &RecoveryBindingRequirement,
    wallet_export_bound: bool,
    observed_receipt_bound: bool,
    live_feed_bound: bool,
    pq_authority_bound: bool,
    privacy_surface_satisfied: bool,
    wallet_scan_windows: u64,
    pq_authority_signers: u64,
    recovery_source_links: u64,
    config: &Config,
) -> u64 {
    let mut blockers = 0;
    if requirement.wallet_export_required && !wallet_export_bound {
        blockers += 1;
    }
    if !observed_receipt_bound {
        blockers += 1;
    }
    if !live_feed_bound {
        blockers += 1;
    }
    if requirement.pq_authority_required && !pq_authority_bound {
        blockers += 1;
    }
    if !privacy_surface_satisfied {
        blockers += 1;
    }
    if wallet_scan_windows < config.min_wallet_scan_windows {
        blockers += 1;
    }
    if pq_authority_signers < config.min_pq_authority_signers {
        blockers += 1;
    }
    if recovery_source_links < config.min_recovery_source_links {
        blockers += 1;
    }
    if requirement.fail_closed_required {
        blockers += 1;
    }
    blockers
}

fn requirement_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-requirement-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("required-user-recovery-evidence"),
        ],
        32,
    )
}

fn expected_binding_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-expected-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("expected-wallet-recovery-binding"),
        ],
        32,
    )
}

fn wallet_export_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-wallet-export-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("wallet-scan-export"),
        ],
        32,
    )
}

fn private_note_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-private-note-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("private-note-recovery"),
        ],
        32,
    )
}

fn forced_exit_claim_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-forced-exit-claim-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("forced-exit-claim"),
        ],
        32,
    )
}

fn pq_authority_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-pq-authority-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("pq-withdrawal-authority"),
        ],
        32,
    )
}

fn observed_receipt_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-observed-receipt-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("observed-receipt-ingest-link"),
        ],
        32,
    )
}

fn live_feed_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-live-feed-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("live-feed-observation-link"),
        ],
        32,
    )
}

fn privacy_surface_root(lane: RecoveryBindingLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-privacy-surface-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("wallet-recovery-privacy-surface"),
        ],
        32,
    )
}

fn mismatch_records(
    requirements: &[RecoveryBindingRequirement],
    records: &[RecoveryBindingRecord],
) -> Vec<RecoveryBindingMismatch> {
    records
        .iter()
        .filter(|record| record.status.blocks_release())
        .map(|record| {
            let expected_root = requirements
                .iter()
                .find(|requirement| requirement.lane == record.lane)
                .map(|requirement| requirement.expected_binding_root.clone())
                .unwrap_or_else(|| expected_binding_root(record.lane));
            RecoveryBindingMismatch {
                lane: record.lane,
                mismatch_code: mismatch_code(record).to_string(),
                expected_root,
                observed_root: record.state_root(),
                evidence_root: mismatch_evidence_root(record),
                severity: "release_blocking".to_string(),
                release_effect: "retain forced-exit hold until wallet recovery can prove claim"
                    .to_string(),
            }
        })
        .collect()
}

fn mismatch_code(record: &RecoveryBindingRecord) -> &'static str {
    if !record.wallet_export_bound {
        "wallet_export_missing"
    } else if !record.private_note_bound {
        "private_note_recovery_missing"
    } else if !record.forced_exit_claim_bound {
        "forced_exit_claim_missing"
    } else if !record.observed_receipt_bound {
        "observed_receipt_link_missing"
    } else if !record.live_feed_bound {
        "live_feed_link_missing"
    } else if !record.pq_authority_bound {
        "pq_authority_mismatch"
    } else if !record.privacy_surface_satisfied {
        "privacy_surface_mismatch"
    } else {
        "release_hold"
    }
}

fn mismatch_evidence_root(record: &RecoveryBindingRecord) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-mismatch-evidence",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record.lane.as_str()),
            HashPart::Str(record.status.as_str()),
            HashPart::Str(&record.wallet_export_root),
            HashPart::Str(&record.forced_exit_claim_root),
        ],
        32,
    )
}

fn requirement_merkle(requirements: &[RecoveryBindingRequirement]) -> String {
    let leaves = requirements
        .iter()
        .map(|requirement| {
            json!({
                "requirement_root": requirement.state_root(),
                "record": requirement.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-requirements",
        &leaves,
    )
}

fn record_merkle(records: &[RecoveryBindingRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "record_root": record.state_root(),
                "record": record.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-records",
        &leaves,
    )
}

fn lane_merkle(records: &[RecoveryBindingRecord], lane_root: &str) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            let root = match lane_root {
                "wallet_export" => &record.wallet_export_root,
                "private_note" => &record.private_note_root,
                "forced_exit_claim" => &record.forced_exit_claim_root,
                "pq_authority" => &record.pq_authority_root,
                "observed_receipt" => &record.observed_receipt_root,
                "live_feed" => &record.live_feed_root,
                "privacy_surface" => &record.privacy_surface_root,
                _ => &record.wallet_export_root,
            };
            json!({
                "lane": record.lane.as_str(),
                "lane_root": lane_root,
                "root": root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-lane-roots",
        &leaves,
    )
}

fn mismatch_merkle(mismatches: &[RecoveryBindingMismatch]) -> String {
    let leaves = mismatches
        .iter()
        .map(|mismatch| {
            json!({
                "mismatch_root": mismatch.state_root(),
                "record": mismatch.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-mismatches",
        &leaves,
    )
}

fn release_hold_reasons(records: &[RecoveryBindingRecord]) -> BTreeMap<String, String> {
    let mut reasons = BTreeMap::new();
    reasons.insert(
        "wallet_scan_export".to_string(),
        "wallet scan export roots must bind recovered notes without exposing linkable metadata"
            .to_string(),
    );
    reasons.insert(
        "observed_receipts".to_string(),
        "observed receipt roots must bind to the wallet recovery claim".to_string(),
    );
    reasons.insert(
        "live_feed_roots".to_string(),
        "live-feed observation roots must bind to the wallet recovery claim".to_string(),
    );
    reasons.insert(
        "pq_withdrawal_authority".to_string(),
        "PQ withdrawal authority and watcher quorum roots must authorize the recovered claim"
            .to_string(),
    );
    reasons.insert(
        "privacy_surface".to_string(),
        "wallet recovery payloads must respect metadata and scan-window privacy budgets"
            .to_string(),
    );
    for record in records {
        if record.status.blocks_release() {
            reasons.insert(
                format!("lane_{}", record.lane.as_str()),
                format!(
                    "{} remains {} with {} blockers",
                    record.lane.label(),
                    record.status.as_str(),
                    record.release_blockers
                ),
            );
        }
    }
    reasons
}

fn hold_root(reasons: &BTreeMap<String, String>) -> String {
    let leaves = reasons
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-release-holds",
        &leaves,
    )
}

fn manifest_id(config: &Config, roots: &RecoveryBindingRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-wallet-recovery-binding-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.requirement_root),
            HashPart::Str(&roots.record_root),
            HashPart::Str(&roots.forced_exit_claim_root),
            HashPart::Str(&roots.observed_receipt_root),
            HashPart::Str(&roots.live_feed_root),
            HashPart::Str(&roots.release_hold_root),
        ],
        16,
    )
}
