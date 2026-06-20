use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialWalletRecoveryBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_WALLET_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-wallet-recovery-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_WALLET_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const WALLET_RECOVERY_BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-adversarial-wallet-recovery-binding-v1";
pub const DEFAULT_L2_TIP_HEIGHT: u64 = 92_418;
pub const DEFAULT_MONERO_TIP_HEIGHT: u64 = 3_460_112;
pub const DEFAULT_FORCED_EXIT_EPOCH: u64 = 47;
pub const DEFAULT_WALLET_HINT_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_LIVE_FEED_TTL_BLOCKS: u64 = 4;
pub const DEFAULT_RECEIPT_DRIFT_TOLERANCE_BLOCKS: u64 = 1;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 24;
pub const DEFAULT_MAX_METADATA_BITS: u16 = 6;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialCaseKind {
    MissingWalletHint,
    StaleLiveFeed,
    ObservedReceiptMismatch,
    BadNullifierFence,
    PqAuthorityMismatch,
    MetadataLeakage,
    PrematureSettlementAttempt,
}

impl AdversarialCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWalletHint => "missing_wallet_hint",
            Self::StaleLiveFeed => "stale_live_feed",
            Self::ObservedReceiptMismatch => "observed_receipt_mismatch",
            Self::BadNullifierFence => "bad_nullifier_fence",
            Self::PqAuthorityMismatch => "pq_authority_mismatch",
            Self::MetadataLeakage => "metadata_leakage",
            Self::PrematureSettlementAttempt => "premature_settlement_attempt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityLane {
    FailClosed,
    CriticalHold,
}

impl SeverityLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::CriticalHold => "critical_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingVerdict {
    RejectedFailClosed,
    Quarantined,
    ReleaseHold,
}

impl BindingVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RejectedFailClosed => "rejected_fail_closed",
            Self::Quarantined => "quarantined",
            Self::ReleaseHold => "release_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Present,
    Missing,
    Stale,
    Mismatched,
    Leaking,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::Mismatched => "mismatched",
            Self::Leaking => "leaking",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub binding_suite: String,
    pub wallet_hint_ttl_blocks: u64,
    pub live_feed_ttl_blocks: u64,
    pub receipt_drift_tolerance_blocks: u64,
    pub min_privacy_set_size: u64,
    pub release_hold_blocks: u64,
    pub max_metadata_bits: u16,
    pub fail_closed_required: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            binding_suite: WALLET_RECOVERY_BINDING_SUITE.to_string(),
            wallet_hint_ttl_blocks: DEFAULT_WALLET_HINT_TTL_BLOCKS,
            live_feed_ttl_blocks: DEFAULT_LIVE_FEED_TTL_BLOCKS,
            receipt_drift_tolerance_blocks: DEFAULT_RECEIPT_DRIFT_TOLERANCE_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            max_metadata_bits: DEFAULT_MAX_METADATA_BITS,
            fail_closed_required: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "binding_suite": self.binding_suite,
            "wallet_hint_ttl_blocks": self.wallet_hint_ttl_blocks,
            "live_feed_ttl_blocks": self.live_feed_ttl_blocks,
            "receipt_drift_tolerance_blocks": self.receipt_drift_tolerance_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "release_hold_blocks": self.release_hold_blocks,
            "max_metadata_bits": self.max_metadata_bits,
            "fail_closed_required": self.fail_closed_required,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletRecoveryBinding {
    pub binding_id: String,
    pub wallet_id: String,
    pub recovery_claim_id: String,
    pub forced_exit_id: String,
    pub account_commitment: String,
    pub recovery_hint_commitment: String,
    pub expected_receipt_commitment: String,
    pub nullifier_fence_root: String,
    pub pq_authority_epoch_root: String,
    pub privacy_set_size: u64,
    pub created_l2_height: u64,
}

impl WalletRecoveryBinding {
    pub fn new(
        wallet_id: impl Into<String>,
        recovery_claim_id: impl Into<String>,
        forced_exit_id: impl Into<String>,
        privacy_set_size: u64,
        created_l2_height: u64,
    ) -> Self {
        let wallet_id = wallet_id.into();
        let recovery_claim_id = recovery_claim_id.into();
        let forced_exit_id = forced_exit_id.into();
        let account_commitment = label_root("account-commitment", &wallet_id);
        let recovery_hint_commitment = label_root("recovery-hint", &recovery_claim_id);
        let expected_receipt_commitment = label_root("expected-receipt", &forced_exit_id);
        let nullifier_fence_root = label_root("nullifier-fence", &recovery_claim_id);
        let pq_authority_epoch_root = label_root("pq-authority-epoch", &forced_exit_id);
        let binding_id = domain_hash(
            "monero-l2-pq-wallet-recovery-binding:id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&wallet_id),
                HashPart::Str(&recovery_claim_id),
                HashPart::Str(&forced_exit_id),
            ],
            32,
        );
        Self {
            binding_id,
            wallet_id,
            recovery_claim_id,
            forced_exit_id,
            account_commitment,
            recovery_hint_commitment,
            expected_receipt_commitment,
            nullifier_fence_root,
            pq_authority_epoch_root,
            privacy_set_size,
            created_l2_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "wallet_id": self.wallet_id,
            "recovery_claim_id": self.recovery_claim_id,
            "forced_exit_id": self.forced_exit_id,
            "account_commitment": self.account_commitment,
            "recovery_hint_commitment": self.recovery_hint_commitment,
            "expected_receipt_commitment": self.expected_receipt_commitment,
            "nullifier_fence_root": self.nullifier_fence_root,
            "pq_authority_epoch_root": self.pq_authority_epoch_root,
            "privacy_set_size": self.privacy_set_size,
            "created_l2_height": self.created_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletEvidenceSnapshot {
    pub evidence_id: String,
    pub case_kind: AdversarialCaseKind,
    pub wallet_hint_status: EvidenceStatus,
    pub live_feed_status: EvidenceStatus,
    pub receipt_status: EvidenceStatus,
    pub nullifier_fence_status: EvidenceStatus,
    pub pq_authority_status: EvidenceStatus,
    pub metadata_status: EvidenceStatus,
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
}

impl WalletEvidenceSnapshot {
    pub fn new(
        evidence_id: impl Into<String>,
        case_kind: AdversarialCaseKind,
        statuses: EvidenceStatuses,
        observed_l2_height: u64,
        observed_monero_height: u64,
    ) -> Self {
        let evidence_id = evidence_id.into();
        Self {
            evidence_id,
            case_kind,
            wallet_hint_status: statuses.wallet_hint,
            live_feed_status: statuses.live_feed,
            receipt_status: statuses.receipt,
            nullifier_fence_status: statuses.nullifier_fence,
            pq_authority_status: statuses.pq_authority,
            metadata_status: statuses.metadata,
            observed_l2_height,
            observed_monero_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "case_kind": self.case_kind.as_str(),
            "wallet_hint_status": self.wallet_hint_status.as_str(),
            "live_feed_status": self.live_feed_status.as_str(),
            "receipt_status": self.receipt_status.as_str(),
            "nullifier_fence_status": self.nullifier_fence_status.as_str(),
            "pq_authority_status": self.pq_authority_status.as_str(),
            "metadata_status": self.metadata_status.as_str(),
            "observed_l2_height": self.observed_l2_height,
            "observed_monero_height": self.observed_monero_height,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct EvidenceStatuses {
    pub wallet_hint: EvidenceStatus,
    pub live_feed: EvidenceStatus,
    pub receipt: EvidenceStatus,
    pub nullifier_fence: EvidenceStatus,
    pub pq_authority: EvidenceStatus,
    pub metadata: EvidenceStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptMismatch {
    pub mismatch_id: String,
    pub binding_id: String,
    pub expected_receipt_commitment: String,
    pub observed_receipt_commitment: String,
    pub mismatch_field: String,
    pub expected_value_commitment: String,
    pub observed_value_commitment: String,
    pub fail_closed_reason: String,
}

impl ReceiptMismatch {
    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "binding_id": self.binding_id,
            "expected_receipt_commitment": self.expected_receipt_commitment,
            "observed_receipt_commitment": self.observed_receipt_commitment,
            "mismatch_field": self.mismatch_field,
            "expected_value_commitment": self.expected_value_commitment,
            "observed_value_commitment": self.observed_value_commitment,
            "fail_closed_reason": self.fail_closed_reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveFeedMismatch {
    pub mismatch_id: String,
    pub feed_lane: String,
    pub expected_height: u64,
    pub observed_height: u64,
    pub expected_root: String,
    pub observed_root: String,
    pub stale_by_blocks: u64,
    pub release_blocked: bool,
}

impl LiveFeedMismatch {
    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "feed_lane": self.feed_lane,
            "expected_height": self.expected_height,
            "observed_height": self.observed_height,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "stale_by_blocks": self.stale_by_blocks,
            "release_blocked": self.release_blocked,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyLeak {
    pub leak_id: String,
    pub binding_id: String,
    pub leaked_surface: String,
    pub leaked_bits: u16,
    pub max_allowed_bits: u16,
    pub privacy_set_before: u64,
    pub privacy_set_after: u64,
    pub mitigation: String,
}

impl PrivacyLeak {
    pub fn public_record(&self) -> Value {
        json!({
            "leak_id": self.leak_id,
            "binding_id": self.binding_id,
            "leaked_surface": self.leaked_surface,
            "leaked_bits": self.leaked_bits,
            "max_allowed_bits": self.max_allowed_bits,
            "privacy_set_before": self.privacy_set_before,
            "privacy_set_after": self.privacy_set_after,
            "mitigation": self.mitigation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdversarialBindingCase {
    pub case_id: String,
    pub kind: AdversarialCaseKind,
    pub binding_id: String,
    pub evidence_id: String,
    pub severity: SeverityLane,
    pub verdict: BindingVerdict,
    pub expected_fail_closed_result: String,
    pub blocked_hazard: String,
    pub recovery_action: String,
    pub release_hold_id: String,
}

impl AdversarialBindingCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "binding_id": self.binding_id,
            "evidence_id": self.evidence_id,
            "severity": self.severity.as_str(),
            "verdict": self.verdict.as_str(),
            "expected_fail_closed_result": self.expected_fail_closed_result,
            "blocked_hazard": self.blocked_hazard,
            "recovery_action": self.recovery_action,
            "release_hold_id": self.release_hold_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub case_id: String,
    pub severity: SeverityLane,
    pub hold_reason: String,
    pub earliest_release_l2_height: u64,
    pub required_clearance_root: String,
    pub blocks_settlement: bool,
}

impl ReleaseHold {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "case_id": self.case_id,
            "severity": self.severity.as_str(),
            "hold_reason": self.hold_reason,
            "earliest_release_l2_height": self.earliest_release_l2_height,
            "required_clearance_root": self.required_clearance_root,
            "blocks_settlement": self.blocks_settlement,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub forced_exit_epoch: u64,
    pub bindings: Vec<WalletRecoveryBinding>,
    pub evidence: Vec<WalletEvidenceSnapshot>,
    pub receipt_mismatches: Vec<ReceiptMismatch>,
    pub live_feed_mismatches: Vec<LiveFeedMismatch>,
    pub privacy_leaks: Vec<PrivacyLeak>,
    pub adversarial_cases: Vec<AdversarialBindingCase>,
    pub release_holds: Vec<ReleaseHold>,
    pub severity_lanes: BTreeMap<String, Vec<String>>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let bindings = devnet_bindings();
        let evidence = devnet_evidence();
        let receipt_mismatches = devnet_receipt_mismatches(&bindings);
        let live_feed_mismatches = devnet_live_feed_mismatches();
        let privacy_leaks = devnet_privacy_leaks(&bindings, config.max_metadata_bits);
        let adversarial_cases = devnet_adversarial_cases(&bindings, &evidence);
        let release_holds = devnet_release_holds(&adversarial_cases, config.release_hold_blocks);
        let severity_lanes = severity_lanes(&adversarial_cases);
        Self {
            config,
            runtime_id: runtime_id(),
            l2_tip_height: DEFAULT_L2_TIP_HEIGHT,
            monero_tip_height: DEFAULT_MONERO_TIP_HEIGHT,
            forced_exit_epoch: DEFAULT_FORCED_EXIT_EPOCH,
            bindings,
            evidence,
            receipt_mismatches,
            live_feed_mismatches,
            privacy_leaks,
            adversarial_cases,
            release_holds,
            severity_lanes,
        }
    }

    pub fn public_record(&self) -> Value {
        let binding_records = self
            .bindings
            .iter()
            .map(WalletRecoveryBinding::public_record)
            .collect::<Vec<_>>();
        let evidence_records = self
            .evidence
            .iter()
            .map(WalletEvidenceSnapshot::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipt_mismatches
            .iter()
            .map(ReceiptMismatch::public_record)
            .collect::<Vec<_>>();
        let feed_records = self
            .live_feed_mismatches
            .iter()
            .map(LiveFeedMismatch::public_record)
            .collect::<Vec<_>>();
        let leak_records = self
            .privacy_leaks
            .iter()
            .map(PrivacyLeak::public_record)
            .collect::<Vec<_>>();
        let case_records = self
            .adversarial_cases
            .iter()
            .map(AdversarialBindingCase::public_record)
            .collect::<Vec<_>>();
        let hold_records = self
            .release_holds
            .iter()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>();
        let roots = self.roots_from_records(
            &binding_records,
            &evidence_records,
            &receipt_records,
            &feed_records,
            &leak_records,
            &case_records,
            &hold_records,
        );

        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_wallet_recovery_binding_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "forced_exit_epoch": self.forced_exit_epoch,
            "config": self.config.public_record(),
            "bindings": binding_records,
            "evidence": evidence_records,
            "receipt_mismatches": receipt_records,
            "live_feed_mismatches": feed_records,
            "privacy_leaks": leak_records,
            "adversarial_cases": case_records,
            "release_holds": hold_records,
            "severity_lanes": self.severity_lanes,
            "roots": roots,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "runtime_id": self.runtime_id,
            "config_root": self.config.state_root(),
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "forced_exit_epoch": self.forced_exit_epoch,
            "bindings": self.bindings,
            "evidence": self.evidence,
            "receipt_mismatches": self.receipt_mismatches,
            "live_feed_mismatches": self.live_feed_mismatches,
            "privacy_leaks": self.privacy_leaks,
            "adversarial_cases": self.adversarial_cases,
            "release_holds": self.release_holds,
            "severity_lanes": self.severity_lanes,
        });
        domain_hash(
            "wallet-recovery-binding:state-root",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&record)],
            32,
        )
    }

    fn roots_from_records(
        &self,
        binding_records: &[Value],
        evidence_records: &[Value],
        receipt_records: &[Value],
        feed_records: &[Value],
        leak_records: &[Value],
        case_records: &[Value],
        hold_records: &[Value],
    ) -> Value {
        json!({
            "config_root": self.config.state_root(),
            "binding_root": merkle_root("wallet-recovery-binding:bindings", binding_records),
            "evidence_root": merkle_root("wallet-recovery-binding:evidence", evidence_records),
            "receipt_mismatch_root": merkle_root("wallet-recovery-binding:receipt-mismatches", receipt_records),
            "live_feed_mismatch_root": merkle_root("wallet-recovery-binding:live-feed-mismatches", feed_records),
            "privacy_leak_root": merkle_root("wallet-recovery-binding:privacy-leaks", leak_records),
            "adversarial_case_root": merkle_root("wallet-recovery-binding:adversarial-cases", case_records),
            "release_hold_root": merkle_root("wallet-recovery-binding:release-holds", hold_records),
        })
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

fn devnet_bindings() -> Vec<WalletRecoveryBinding> {
    [
        (
            "wallet-alpha",
            "claim-missing-hint",
            "exit-001",
            128,
            92_384,
        ),
        ("wallet-beta", "claim-stale-feed", "exit-002", 112, 92_388),
        (
            "wallet-gamma",
            "claim-receipt-drift",
            "exit-003",
            96,
            92_392,
        ),
        (
            "wallet-delta",
            "claim-nullifier-fence",
            "exit-004",
            144,
            92_396,
        ),
        (
            "wallet-epsilon",
            "claim-pq-mismatch",
            "exit-005",
            160,
            92_400,
        ),
        ("wallet-zeta", "claim-metadata-leak", "exit-006", 72, 92_404),
        (
            "wallet-eta",
            "claim-premature-settle",
            "exit-007",
            104,
            92_408,
        ),
    ]
    .into_iter()
    .map(|(wallet, claim, exit, privacy, height)| {
        WalletRecoveryBinding::new(wallet, claim, exit, privacy, height)
    })
    .collect()
}

fn devnet_evidence() -> Vec<WalletEvidenceSnapshot> {
    vec![
        WalletEvidenceSnapshot::new(
            "evidence-missing-wallet-hint",
            AdversarialCaseKind::MissingWalletHint,
            EvidenceStatuses {
                wallet_hint: EvidenceStatus::Missing,
                live_feed: EvidenceStatus::Present,
                receipt: EvidenceStatus::Present,
                nullifier_fence: EvidenceStatus::Present,
                pq_authority: EvidenceStatus::Present,
                metadata: EvidenceStatus::Present,
            },
            92_418,
            3_460_112,
        ),
        WalletEvidenceSnapshot::new(
            "evidence-stale-live-feed",
            AdversarialCaseKind::StaleLiveFeed,
            EvidenceStatuses {
                wallet_hint: EvidenceStatus::Present,
                live_feed: EvidenceStatus::Stale,
                receipt: EvidenceStatus::Present,
                nullifier_fence: EvidenceStatus::Present,
                pq_authority: EvidenceStatus::Present,
                metadata: EvidenceStatus::Present,
            },
            92_410,
            3_460_097,
        ),
        WalletEvidenceSnapshot::new(
            "evidence-receipt-mismatch",
            AdversarialCaseKind::ObservedReceiptMismatch,
            EvidenceStatuses {
                wallet_hint: EvidenceStatus::Present,
                live_feed: EvidenceStatus::Present,
                receipt: EvidenceStatus::Mismatched,
                nullifier_fence: EvidenceStatus::Present,
                pq_authority: EvidenceStatus::Present,
                metadata: EvidenceStatus::Present,
            },
            92_417,
            3_460_112,
        ),
        WalletEvidenceSnapshot::new(
            "evidence-bad-nullifier-fence",
            AdversarialCaseKind::BadNullifierFence,
            EvidenceStatuses {
                wallet_hint: EvidenceStatus::Present,
                live_feed: EvidenceStatus::Present,
                receipt: EvidenceStatus::Present,
                nullifier_fence: EvidenceStatus::Mismatched,
                pq_authority: EvidenceStatus::Present,
                metadata: EvidenceStatus::Present,
            },
            92_418,
            3_460_112,
        ),
        WalletEvidenceSnapshot::new(
            "evidence-pq-authority-mismatch",
            AdversarialCaseKind::PqAuthorityMismatch,
            EvidenceStatuses {
                wallet_hint: EvidenceStatus::Present,
                live_feed: EvidenceStatus::Present,
                receipt: EvidenceStatus::Present,
                nullifier_fence: EvidenceStatus::Present,
                pq_authority: EvidenceStatus::Mismatched,
                metadata: EvidenceStatus::Present,
            },
            92_418,
            3_460_112,
        ),
        WalletEvidenceSnapshot::new(
            "evidence-metadata-leakage",
            AdversarialCaseKind::MetadataLeakage,
            EvidenceStatuses {
                wallet_hint: EvidenceStatus::Present,
                live_feed: EvidenceStatus::Present,
                receipt: EvidenceStatus::Present,
                nullifier_fence: EvidenceStatus::Present,
                pq_authority: EvidenceStatus::Present,
                metadata: EvidenceStatus::Leaking,
            },
            92_418,
            3_460_112,
        ),
        WalletEvidenceSnapshot::new(
            "evidence-premature-settlement",
            AdversarialCaseKind::PrematureSettlementAttempt,
            EvidenceStatuses {
                wallet_hint: EvidenceStatus::Present,
                live_feed: EvidenceStatus::Present,
                receipt: EvidenceStatus::Present,
                nullifier_fence: EvidenceStatus::Present,
                pq_authority: EvidenceStatus::Present,
                metadata: EvidenceStatus::Present,
            },
            92_409,
            3_460_101,
        ),
    ]
}

fn devnet_receipt_mismatches(bindings: &[WalletRecoveryBinding]) -> Vec<ReceiptMismatch> {
    bindings
        .iter()
        .filter(|binding| binding.wallet_id == "wallet-gamma")
        .map(|binding| ReceiptMismatch {
            mismatch_id: label_root("receipt-mismatch", &binding.binding_id),
            binding_id: binding.binding_id.clone(),
            expected_receipt_commitment: binding.expected_receipt_commitment.clone(),
            observed_receipt_commitment: label_root("observed-receipt", "wallet-gamma-drift"),
            mismatch_field: "recovery_claim_id".to_string(),
            expected_value_commitment: label_root("expected-value", &binding.recovery_claim_id),
            observed_value_commitment: label_root("observed-value", "recovery-claim-shadow"),
            fail_closed_reason:
                "observed settlement receipt is not bound to the wallet recovery claim".to_string(),
        })
        .collect()
}

fn devnet_live_feed_mismatches() -> Vec<LiveFeedMismatch> {
    vec![LiveFeedMismatch {
        mismatch_id: label_root("live-feed-mismatch", "monero-header-feed-stale"),
        feed_lane: "monero_header_feed".to_string(),
        expected_height: DEFAULT_MONERO_TIP_HEIGHT,
        observed_height: DEFAULT_MONERO_TIP_HEIGHT - 15,
        expected_root: label_root("expected-feed-root", "monero-header-feed"),
        observed_root: label_root("observed-feed-root", "monero-header-feed-stale"),
        stale_by_blocks: 15,
        release_blocked: true,
    }]
}

fn devnet_privacy_leaks(
    bindings: &[WalletRecoveryBinding],
    max_allowed_bits: u16,
) -> Vec<PrivacyLeak> {
    bindings
        .iter()
        .filter(|binding| binding.wallet_id == "wallet-zeta")
        .map(|binding| PrivacyLeak {
            leak_id: label_root("privacy-leak", &binding.binding_id),
            binding_id: binding.binding_id.clone(),
            leaked_surface: "receipt_timing_and_wallet_hint_bucket".to_string(),
            leaked_bits: 11,
            max_allowed_bits,
            privacy_set_before: binding.privacy_set_size,
            privacy_set_after: 41,
            mitigation: "drop receipt envelope, rotate hint bucket, and require widened anonymity set before replay".to_string(),
        })
        .collect()
}

fn devnet_adversarial_cases(
    bindings: &[WalletRecoveryBinding],
    evidence: &[WalletEvidenceSnapshot],
) -> Vec<AdversarialBindingCase> {
    let mut cases = Vec::new();
    for (index, binding) in bindings.iter().enumerate() {
        let case_kind = match binding.wallet_id.as_str() {
            "wallet-alpha" => AdversarialCaseKind::MissingWalletHint,
            "wallet-beta" => AdversarialCaseKind::StaleLiveFeed,
            "wallet-gamma" => AdversarialCaseKind::ObservedReceiptMismatch,
            "wallet-delta" => AdversarialCaseKind::BadNullifierFence,
            "wallet-epsilon" => AdversarialCaseKind::PqAuthorityMismatch,
            "wallet-zeta" => AdversarialCaseKind::MetadataLeakage,
            _ => AdversarialCaseKind::PrematureSettlementAttempt,
        };
        let evidence_id = evidence
            .iter()
            .find(|snapshot| snapshot.case_kind == case_kind)
            .map(|snapshot| snapshot.evidence_id.clone())
            .unwrap_or_else(|| label_root("missing-evidence", case_kind.as_str()));
        let severity = severity_for(case_kind);
        let verdict = verdict_for(case_kind);
        let case_id = label_root(
            "adversarial-binding-case",
            &format!("{}-{index}", case_kind.as_str()),
        );
        cases.push(AdversarialBindingCase {
            release_hold_id: label_root("release-hold", &case_id),
            case_id,
            kind: case_kind,
            binding_id: binding.binding_id.clone(),
            evidence_id,
            severity,
            verdict,
            expected_fail_closed_result: fail_closed_result(case_kind).to_string(),
            blocked_hazard: blocked_hazard(case_kind).to_string(),
            recovery_action: recovery_action(case_kind).to_string(),
        });
    }
    cases
}

fn devnet_release_holds(cases: &[AdversarialBindingCase], hold_blocks: u64) -> Vec<ReleaseHold> {
    cases
        .iter()
        .filter(|case| {
            matches!(
                case.severity,
                SeverityLane::FailClosed | SeverityLane::CriticalHold
            )
        })
        .map(|case| ReleaseHold {
            hold_id: case.release_hold_id.clone(),
            case_id: case.case_id.clone(),
            severity: case.severity,
            hold_reason: case.expected_fail_closed_result.clone(),
            earliest_release_l2_height: DEFAULT_L2_TIP_HEIGHT + hold_blocks,
            required_clearance_root: label_root("clearance-root", &case.case_id),
            blocks_settlement: true,
        })
        .collect()
}

fn severity_lanes(cases: &[AdversarialBindingCase]) -> BTreeMap<String, Vec<String>> {
    let mut lanes = BTreeMap::new();
    for lane in [SeverityLane::FailClosed, SeverityLane::CriticalHold] {
        let ids = cases
            .iter()
            .filter(|case| case.severity == lane)
            .map(|case| case.case_id.clone())
            .collect::<Vec<_>>();
        lanes.insert(lane.as_str().to_string(), ids);
    }
    lanes
}

fn severity_for(kind: AdversarialCaseKind) -> SeverityLane {
    match kind {
        AdversarialCaseKind::MissingWalletHint => SeverityLane::FailClosed,
        AdversarialCaseKind::StaleLiveFeed => SeverityLane::FailClosed,
        AdversarialCaseKind::ObservedReceiptMismatch => SeverityLane::CriticalHold,
        AdversarialCaseKind::BadNullifierFence => SeverityLane::CriticalHold,
        AdversarialCaseKind::PqAuthorityMismatch => SeverityLane::CriticalHold,
        AdversarialCaseKind::MetadataLeakage => SeverityLane::FailClosed,
        AdversarialCaseKind::PrematureSettlementAttempt => SeverityLane::FailClosed,
    }
}

fn verdict_for(kind: AdversarialCaseKind) -> BindingVerdict {
    match kind {
        AdversarialCaseKind::MissingWalletHint => BindingVerdict::RejectedFailClosed,
        AdversarialCaseKind::StaleLiveFeed => BindingVerdict::ReleaseHold,
        AdversarialCaseKind::ObservedReceiptMismatch => BindingVerdict::Quarantined,
        AdversarialCaseKind::BadNullifierFence => BindingVerdict::Quarantined,
        AdversarialCaseKind::PqAuthorityMismatch => BindingVerdict::ReleaseHold,
        AdversarialCaseKind::MetadataLeakage => BindingVerdict::RejectedFailClosed,
        AdversarialCaseKind::PrematureSettlementAttempt => BindingVerdict::RejectedFailClosed,
    }
}

fn fail_closed_result(kind: AdversarialCaseKind) -> &'static str {
    match kind {
        AdversarialCaseKind::MissingWalletHint => {
            "reject recovery binding until wallet hint commitment is present"
        }
        AdversarialCaseKind::StaleLiveFeed => "hold release until live feeds advance inside ttl",
        AdversarialCaseKind::ObservedReceiptMismatch => {
            "quarantine binding and require receipt replay from canonical root"
        }
        AdversarialCaseKind::BadNullifierFence => {
            "block settlement and rotate nullifier fence witness"
        }
        AdversarialCaseKind::PqAuthorityMismatch => {
            "hold release until authority epoch and signature domain agree"
        }
        AdversarialCaseKind::MetadataLeakage => {
            "drop leaked envelope and widen privacy set before retry"
        }
        AdversarialCaseKind::PrematureSettlementAttempt => {
            "reject call before challenge window and release hold clear"
        }
    }
}

fn blocked_hazard(kind: AdversarialCaseKind) -> &'static str {
    match kind {
        AdversarialCaseKind::MissingWalletHint => {
            "wallet recovery could bind to an unowned or ambiguous account commitment"
        }
        AdversarialCaseKind::StaleLiveFeed => {
            "settlement could rely on reorged or superseded bridge evidence"
        }
        AdversarialCaseKind::ObservedReceiptMismatch => {
            "operator receipt could settle a different recovery claim"
        }
        AdversarialCaseKind::BadNullifierFence => {
            "double recovery or replay through a broken nullifier exclusion set"
        }
        AdversarialCaseKind::PqAuthorityMismatch => {
            "release could be signed by an authority outside the active pq epoch"
        }
        AdversarialCaseKind::MetadataLeakage => {
            "receipt timing and hint bucket could deanonymize the recovering wallet"
        }
        AdversarialCaseKind::PrematureSettlementAttempt => {
            "forced exit could settle before challenge and watcher lanes close"
        }
    }
}

fn recovery_action(kind: AdversarialCaseKind) -> &'static str {
    match kind {
        AdversarialCaseKind::MissingWalletHint => {
            "require wallet hint witness and recompute binding root"
        }
        AdversarialCaseKind::StaleLiveFeed => "refresh monero header and settlement receipt feeds",
        AdversarialCaseKind::ObservedReceiptMismatch => {
            "replay receipt against canonical claim transcript"
        }
        AdversarialCaseKind::BadNullifierFence => {
            "rebuild nullifier fence from finalized spent set"
        }
        AdversarialCaseKind::PqAuthorityMismatch => {
            "reload pq authority epoch and verify domain-separated signature"
        }
        AdversarialCaseKind::MetadataLeakage => {
            "rotate metadata envelope and batch with larger privacy cohort"
        }
        AdversarialCaseKind::PrematureSettlementAttempt => {
            "defer settlement until release clock and challenge window clear"
        }
    }
}

fn runtime_id() -> String {
    domain_hash(
        "wallet-recovery-binding:runtime-id",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "wallet-recovery-binding:record-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn label_root(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}
