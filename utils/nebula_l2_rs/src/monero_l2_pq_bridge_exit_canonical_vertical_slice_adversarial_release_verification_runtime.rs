use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialReleaseVerificationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-release-verification-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.vertical-slice.adversarial-release-verification.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";
pub const RELEASE_DECISION: &str = "block_release";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-release-verification-runtime";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub release_decision: String,
    pub forced_exit_epoch: u64,
    pub required_wallet_receipt_nonce: u64,
    pub required_monero_broadcast_height: u64,
    pub pq_epoch_floor: u64,
    pub liquidity_floor_piconero: u64,
    pub privacy_budget_bits: u64,
    pub watcher_quorum: u64,
    pub watcher_fault_limit: u64,
    pub monero_reorg_hold_blocks: u64,
    pub challenge_window_blocks: u64,
    pub manifest_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let manifest_seed = json!({
            "suite": "forced-exit-release-evidence",
            "epoch": 42_u64,
            "case_count": 9_u64,
        });

        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            release_decision: RELEASE_DECISION.to_string(),
            forced_exit_epoch: 42,
            required_wallet_receipt_nonce: 700_001,
            required_monero_broadcast_height: 3_020_000,
            pq_epoch_floor: 42,
            liquidity_floor_piconero: 9_000_000_000_000,
            privacy_budget_bits: 6,
            watcher_quorum: 5,
            watcher_fault_limit: 1,
            monero_reorg_hold_blocks: 20,
            challenge_window_blocks: 96,
            manifest_root: hash_json("manifest-root", &manifest_seed),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_decision": self.release_decision,
            "forced_exit_epoch": self.forced_exit_epoch,
            "required_wallet_receipt_nonce": self.required_wallet_receipt_nonce,
            "required_monero_broadcast_height": self.required_monero_broadcast_height,
            "pq_epoch_floor": self.pq_epoch_floor,
            "liquidity_floor_piconero": self.liquidity_floor_piconero,
            "privacy_budget_bits": self.privacy_budget_bits,
            "watcher_quorum": self.watcher_quorum,
            "watcher_fault_limit": self.watcher_fault_limit,
            "monero_reorg_hold_blocks": self.monero_reorg_hold_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "manifest_root": self.manifest_root,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialReleaseCase {
    ReplayedWalletReceipt,
    MismatchedMoneroBroadcast,
    StalePqEpoch,
    LiquidityShortfall,
    PrivacyBudgetBreach,
    WatcherQuorumCollusion,
    ReorgAfterRelease,
    ChallengeWindowBypass,
    ForgedManifestRoot,
}

impl AdversarialReleaseCase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayedWalletReceipt => "replayed_wallet_receipt",
            Self::MismatchedMoneroBroadcast => "mismatched_monero_broadcast",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::PrivacyBudgetBreach => "privacy_budget_breach",
            Self::WatcherQuorumCollusion => "watcher_quorum_collusion",
            Self::ReorgAfterRelease => "reorg_after_release",
            Self::ChallengeWindowBypass => "challenge_window_bypass",
            Self::ForgedManifestRoot => "forged_manifest_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDisposition {
    FailClosed,
    Quarantine,
}

impl ReleaseDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseEvidence {
    pub wallet_receipt_nonce: u64,
    pub wallet_receipt_seen_before: bool,
    pub expected_monero_txid: String,
    pub observed_monero_txid: String,
    pub observed_monero_height: u64,
    pub pq_epoch: u64,
    pub available_liquidity_piconero: u64,
    pub privacy_cost_bits: u64,
    pub watcher_signatures: u64,
    pub colluding_watchers: u64,
    pub reorg_depth_blocks: u64,
    pub challenge_elapsed_blocks: u64,
    pub submitted_manifest_root: String,
}

impl ReleaseEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "wallet_receipt_nonce": self.wallet_receipt_nonce,
            "wallet_receipt_seen_before": self.wallet_receipt_seen_before,
            "expected_monero_txid": self.expected_monero_txid,
            "observed_monero_txid": self.observed_monero_txid,
            "observed_monero_height": self.observed_monero_height,
            "pq_epoch": self.pq_epoch,
            "available_liquidity_piconero": self.available_liquidity_piconero,
            "privacy_cost_bits": self.privacy_cost_bits,
            "watcher_signatures": self.watcher_signatures,
            "colluding_watchers": self.colluding_watchers,
            "reorg_depth_blocks": self.reorg_depth_blocks,
            "challenge_elapsed_blocks": self.challenge_elapsed_blocks,
            "submitted_manifest_root": self.submitted_manifest_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerificationCase {
    pub case_id: String,
    pub case_kind: AdversarialReleaseCase,
    pub evidence: ReleaseEvidence,
    pub disposition: ReleaseDisposition,
    pub blocked_release: bool,
    pub reason: String,
    pub evidence_root: String,
    pub verdict_root: String,
}

impl VerificationCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "case_kind": self.case_kind.as_str(),
            "evidence": self.evidence.public_record(),
            "disposition": self.disposition.as_str(),
            "blocked_release": self.blocked_release,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Scorecard {
    pub total_cases: u64,
    pub fail_closed_cases: u64,
    pub quarantine_cases: u64,
    pub blocked_release_cases: u64,
    pub release_allowed_cases: u64,
    pub all_negative_cases_block_release: bool,
    pub verdict_merkle_root: String,
    pub scorecard_root: String,
}

impl Scorecard {
    pub fn public_record(&self) -> Value {
        json!({
            "total_cases": self.total_cases,
            "fail_closed_cases": self.fail_closed_cases,
            "quarantine_cases": self.quarantine_cases,
            "blocked_release_cases": self.blocked_release_cases,
            "release_allowed_cases": self.release_allowed_cases,
            "all_negative_cases_block_release": self.all_negative_cases_block_release,
            "verdict_merkle_root": self.verdict_merkle_root,
            "scorecard_root": self.scorecard_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub cases: Vec<VerificationCase>,
    pub scorecard: Scorecard,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let cases = adversarial_cases(&config);
        let scorecard = build_scorecard(&cases);
        let state_record = json!({
            "config": config.public_record(),
            "cases": cases
                .iter()
                .map(VerificationCase::public_record)
                .collect::<Vec<_>>(),
            "scorecard": scorecard.public_record(),
        });
        let state_root = hash_json("state-root", &state_record);

        Self {
            config,
            cases,
            scorecard,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "cases": self
                .cases
                .iter()
                .map(VerificationCase::public_record)
                .collect::<Vec<_>>(),
            "scorecard": self.scorecard.public_record(),
            "state_root": self.state_root,
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

fn adversarial_cases(config: &Config) -> Vec<VerificationCase> {
    vec![
        evaluate_case(
            config,
            AdversarialReleaseCase::ReplayedWalletReceipt,
            ReleaseDisposition::FailClosed,
            "wallet receipt nonce was already consumed",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce - 1,
                wallet_receipt_seen_before: true,
                expected_monero_txid: stable_id("expected-monero-txid", "replayed-wallet-receipt"),
                observed_monero_txid: stable_id("expected-monero-txid", "replayed-wallet-receipt"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::MismatchedMoneroBroadcast,
            ReleaseDisposition::FailClosed,
            "observed Monero txid does not match release evidence",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "mismatched-broadcast"),
                observed_monero_txid: stable_id("observed-monero-txid", "mismatched-broadcast"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::StalePqEpoch,
            ReleaseDisposition::FailClosed,
            "post-quantum authorization epoch is stale",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "stale-pq-epoch"),
                observed_monero_txid: stable_id("expected-monero-txid", "stale-pq-epoch"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor - 1,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::LiquidityShortfall,
            ReleaseDisposition::FailClosed,
            "available liquidity is below release floor",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "liquidity-shortfall"),
                observed_monero_txid: stable_id("expected-monero-txid", "liquidity-shortfall"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero - 1,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::PrivacyBudgetBreach,
            ReleaseDisposition::Quarantine,
            "release evidence exceeds metadata privacy budget",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "privacy-budget-breach"),
                observed_monero_txid: stable_id("expected-monero-txid", "privacy-budget-breach"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits + 1,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::WatcherQuorumCollusion,
            ReleaseDisposition::Quarantine,
            "watcher fault bound is exceeded inside quorum",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "watcher-collusion"),
                observed_monero_txid: stable_id("expected-monero-txid", "watcher-collusion"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: config.watcher_fault_limit + 1,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::ReorgAfterRelease,
            ReleaseDisposition::Quarantine,
            "Monero reorg hold was violated after release evidence formed",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "reorg-after-release"),
                observed_monero_txid: stable_id("expected-monero-txid", "reorg-after-release"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: config.monero_reorg_hold_blocks + 1,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::ChallengeWindowBypass,
            ReleaseDisposition::FailClosed,
            "release was attempted before challenge window elapsed",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "challenge-window-bypass"),
                observed_monero_txid: stable_id("expected-monero-txid", "challenge-window-bypass"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks - 1,
                submitted_manifest_root: config.manifest_root.clone(),
            },
        ),
        evaluate_case(
            config,
            AdversarialReleaseCase::ForgedManifestRoot,
            ReleaseDisposition::FailClosed,
            "submitted manifest root does not match canonical release manifest",
            ReleaseEvidence {
                wallet_receipt_nonce: config.required_wallet_receipt_nonce,
                wallet_receipt_seen_before: false,
                expected_monero_txid: stable_id("expected-monero-txid", "forged-manifest-root"),
                observed_monero_txid: stable_id("expected-monero-txid", "forged-manifest-root"),
                observed_monero_height: config.required_monero_broadcast_height,
                pq_epoch: config.pq_epoch_floor,
                available_liquidity_piconero: config.liquidity_floor_piconero,
                privacy_cost_bits: config.privacy_budget_bits,
                watcher_signatures: config.watcher_quorum,
                colluding_watchers: 0,
                reorg_depth_blocks: 0,
                challenge_elapsed_blocks: config.challenge_window_blocks,
                submitted_manifest_root: stable_id("forged-manifest-root", "release"),
            },
        ),
    ]
}

fn evaluate_case(
    config: &Config,
    case_kind: AdversarialReleaseCase,
    disposition: ReleaseDisposition,
    reason: &str,
    evidence: ReleaseEvidence,
) -> VerificationCase {
    let case_id = stable_id("case-id", case_kind.as_str());
    let evidence_record = evidence.public_record();
    let evidence_root = hash_json("evidence-root", &evidence_record);
    let blocked_release = release_is_blocked(config, &evidence, disposition);
    let verdict_record = json!({
        "case_id": case_id,
        "case_kind": case_kind.as_str(),
        "disposition": disposition.as_str(),
        "blocked_release": blocked_release,
        "reason": reason,
        "evidence_root": evidence_root,
    });
    let verdict_root = hash_json("verdict-root", &verdict_record);

    VerificationCase {
        case_id,
        case_kind,
        evidence,
        disposition,
        blocked_release,
        reason: reason.to_string(),
        evidence_root,
        verdict_root,
    }
}

fn release_is_blocked(
    config: &Config,
    evidence: &ReleaseEvidence,
    disposition: ReleaseDisposition,
) -> bool {
    let disposition_blocks = matches!(
        disposition,
        ReleaseDisposition::FailClosed | ReleaseDisposition::Quarantine
    );
    let receipt_replayed = evidence.wallet_receipt_seen_before
        || evidence.wallet_receipt_nonce < config.required_wallet_receipt_nonce;
    let monero_mismatch = evidence.expected_monero_txid != evidence.observed_monero_txid
        || evidence.observed_monero_height < config.required_monero_broadcast_height;
    let stale_pq_epoch = evidence.pq_epoch < config.pq_epoch_floor;
    let liquidity_shortfall =
        evidence.available_liquidity_piconero < config.liquidity_floor_piconero;
    let privacy_breach = evidence.privacy_cost_bits > config.privacy_budget_bits;
    let watcher_collusion = evidence.watcher_signatures >= config.watcher_quorum
        && evidence.colluding_watchers > config.watcher_fault_limit;
    let reorg_after_release = evidence.reorg_depth_blocks > config.monero_reorg_hold_blocks;
    let challenge_bypass = evidence.challenge_elapsed_blocks < config.challenge_window_blocks;
    let forged_manifest = evidence.submitted_manifest_root != config.manifest_root;

    disposition_blocks
        && (receipt_replayed
            || monero_mismatch
            || stale_pq_epoch
            || liquidity_shortfall
            || privacy_breach
            || watcher_collusion
            || reorg_after_release
            || challenge_bypass
            || forged_manifest)
}

fn build_scorecard(cases: &[VerificationCase]) -> Scorecard {
    let total_cases = cases.len() as u64;
    let fail_closed_cases = cases
        .iter()
        .filter(|case| case.disposition == ReleaseDisposition::FailClosed)
        .count() as u64;
    let quarantine_cases = cases
        .iter()
        .filter(|case| case.disposition == ReleaseDisposition::Quarantine)
        .count() as u64;
    let blocked_release_cases = cases.iter().filter(|case| case.blocked_release).count() as u64;
    let release_allowed_cases = total_cases - blocked_release_cases;
    let all_negative_cases_block_release =
        total_cases > 0 && blocked_release_cases == total_cases && release_allowed_cases == 0;
    let verdict_records = cases
        .iter()
        .map(VerificationCase::public_record)
        .collect::<Vec<_>>();
    let verdict_merkle_root = merkle_root(
        &format!("{DOMAIN}:verdict-merkle-root"),
        verdict_records.as_slice(),
    );
    let scorecard_seed = json!({
        "total_cases": total_cases,
        "fail_closed_cases": fail_closed_cases,
        "quarantine_cases": quarantine_cases,
        "blocked_release_cases": blocked_release_cases,
        "release_allowed_cases": release_allowed_cases,
        "all_negative_cases_block_release": all_negative_cases_block_release,
        "verdict_merkle_root": verdict_merkle_root,
        "case_roots": cases
            .iter()
            .map(|case| case.verdict_root.clone())
            .collect::<Vec<_>>(),
    });
    let scorecard_root = hash_json("scorecard-root", &scorecard_seed);

    Scorecard {
        total_cases,
        fail_closed_cases,
        quarantine_cases,
        blocked_release_cases,
        release_allowed_cases,
        all_negative_cases_block_release,
        verdict_merkle_root,
        scorecard_root,
    }
}

fn hash_json(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn stable_id(label: &str, seed: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}
