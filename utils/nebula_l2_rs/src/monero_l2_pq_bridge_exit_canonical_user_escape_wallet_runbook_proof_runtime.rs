use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeWalletRunbookProofRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_PROOF_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-wallet-runbook-proof-runtime-v1";

const PROTOCOL_LABEL: &str = "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_proof";
const RUNBOOK_ID: &str = "devnet-user-escape-package-001";
const WALLET_SCAN_STEP_ID: &str = "wallet_scan";
const PROOF_COLLECTION_STEP_ID: &str = "proof_collection";
const FORCED_EXIT_CLAIM_BUILD_STEP_ID: &str = "forced_exit_claim_build";
const PQ_AUTHORIZATION_STEP_ID: &str = "pq_authorization";
const LIVE_FEED_CROSSCHECK_STEP_ID: &str = "live_feed_crosscheck";
const CHALLENGE_DISPUTE_WAIT_STEP_ID: &str = "challenge_dispute_wait";
const RELEASE_VERIFICATION_STEP_ID: &str = "release_verification";
const OPERATOR_FAILURE_FALLBACK_STEP_ID: &str = "operator_failure_fallback";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub bridge_asset_id: String,
    pub runbook_id: String,
    pub challenge_window_blocks: u64,
    pub dispute_wait_blocks: u64,
    pub release_finality_blocks: u64,
    pub required_live_feed_confirmations: u64,
    pub required_wallet_scan_confirmations: u64,
    pub pq_authorization_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            bridge_asset_id: "wxmr-devnet".to_string(),
            runbook_id: RUNBOOK_ID.to_string(),
            challenge_window_blocks: 36,
            dispute_wait_blocks: 18,
            release_finality_blocks: 10,
            required_live_feed_confirmations: 3,
            required_wallet_scan_confirmations: 12,
            pq_authorization_scheme: "ML-DSA-65+SLH-DSA-SHAKE-128s-user-escape".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "bridge_asset_id": self.bridge_asset_id,
            "runbook_id": self.runbook_id,
            "challenge_window_blocks": self.challenge_window_blocks,
            "dispute_wait_blocks": self.dispute_wait_blocks,
            "release_finality_blocks": self.release_finality_blocks,
            "required_live_feed_confirmations": self.required_live_feed_confirmations,
            "required_wallet_scan_confirmations": self.required_wallet_scan_confirmations,
            "pq_authorization_scheme": self.pq_authorization_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        runtime_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Ready,
    Waiting,
    Blocked,
    OperatorFallback,
    ReleaseVerified,
}

impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Waiting => "waiting",
            Self::Blocked => "blocked",
            Self::OperatorFallback => "operator_fallback",
            Self::ReleaseVerified => "release_verified",
        }
    }

    pub fn fail_closed(self) -> bool {
        matches!(self, Self::Blocked | Self::OperatorFallback)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookStep {
    pub step_id: String,
    pub title: String,
    pub readiness_status: ReadinessStatus,
    pub user_instructions: Vec<String>,
    pub evidence_roots: Vec<String>,
    pub fail_closed_blockers: Vec<String>,
}

impl RunbookStep {
    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "title": self.title,
            "readiness_status": self.readiness_status.as_str(),
            "user_instructions": self.user_instructions,
            "evidence_roots": self.evidence_roots,
            "fail_closed_blockers": self.fail_closed_blockers,
            "fail_closed": self.readiness_status.fail_closed() || !self.fail_closed_blockers.is_empty(),
        })
    }

    pub fn step_root(&self) -> String {
        runtime_hash("RUNBOOK-STEP", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub wallet_account_commitment: String,
    pub bridge_exit_commitment: String,
    pub forced_exit_claim_root: String,
    pub pq_authorization_root: String,
    pub live_feed_checkpoint_root: String,
    pub release_receipt_root: String,
    pub steps: Vec<RunbookStep>,
}

impl State {
    pub fn devnet() -> Self {
        let wallet_account_commitment = seed_root("wallet-account", "escape-wallet-alpha");
        let bridge_exit_commitment = seed_root("bridge-exit", "canonical-exit-devnet-17");
        let forced_exit_claim_root = seed_root("forced-exit-claim", "claim-package-v1");
        let pq_authorization_root = seed_root("pq-authorization", "wallet-pq-auth-v1");
        let live_feed_checkpoint_root =
            seed_root("live-feed", "operator-and-watchtower-crosscheck");
        let release_receipt_root = seed_root("release-receipt", "monero-release-proof-v1");

        Self {
            config: Config::devnet(),
            wallet_account_commitment: wallet_account_commitment.clone(),
            bridge_exit_commitment: bridge_exit_commitment.clone(),
            forced_exit_claim_root: forced_exit_claim_root.clone(),
            pq_authorization_root: pq_authorization_root.clone(),
            live_feed_checkpoint_root: live_feed_checkpoint_root.clone(),
            release_receipt_root: release_receipt_root.clone(),
            steps: vec![
                RunbookStep {
                    step_id: WALLET_SCAN_STEP_ID.to_string(),
                    title: "Wallet scan".to_string(),
                    readiness_status: ReadinessStatus::Ready,
                    user_instructions: vec![
                        "Scan wallet notes through the required confirmation depth".to_string(),
                        "Export the spendable output commitment set and local height".to_string(),
                        "Stop if the wallet view key or scan height cannot be verified".to_string(),
                    ],
                    evidence_roots: vec![wallet_account_commitment.clone()],
                    fail_closed_blockers: Vec::new(),
                },
                RunbookStep {
                    step_id: PROOF_COLLECTION_STEP_ID.to_string(),
                    title: "Proof collection".to_string(),
                    readiness_status: ReadinessStatus::Ready,
                    user_instructions: vec![
                        "Collect inclusion, nullifier, and bridge custody witnesses".to_string(),
                        "Bind all witnesses to the canonical exit commitment".to_string(),
                        "Reject partial packages missing any witness root".to_string(),
                    ],
                    evidence_roots: vec![
                        wallet_account_commitment.clone(),
                        bridge_exit_commitment.clone(),
                    ],
                    fail_closed_blockers: Vec::new(),
                },
                RunbookStep {
                    step_id: FORCED_EXIT_CLAIM_BUILD_STEP_ID.to_string(),
                    title: "Forced-exit claim build".to_string(),
                    readiness_status: ReadinessStatus::Ready,
                    user_instructions: vec![
                        "Build the forced-exit claim from wallet scan and bridge proof roots"
                            .to_string(),
                        "Attach payout address commitment and fee ceiling commitment".to_string(),
                        "Do not broadcast if claim root differs from wallet preview".to_string(),
                    ],
                    evidence_roots: vec![
                        forced_exit_claim_root.clone(),
                        bridge_exit_commitment.clone(),
                    ],
                    fail_closed_blockers: Vec::new(),
                },
                RunbookStep {
                    step_id: PQ_AUTHORIZATION_STEP_ID.to_string(),
                    title: "PQ authorization".to_string(),
                    readiness_status: ReadinessStatus::Ready,
                    user_instructions: vec![
                        "Authorize the claim transcript with the wallet PQ key".to_string(),
                        "Record key identifier, signature root, and transcript root".to_string(),
                        "Abort if classical-only authorization is the only available signature"
                            .to_string(),
                    ],
                    evidence_roots: vec![
                        pq_authorization_root.clone(),
                        forced_exit_claim_root.clone(),
                    ],
                    fail_closed_blockers: Vec::new(),
                },
                RunbookStep {
                    step_id: LIVE_FEED_CROSSCHECK_STEP_ID.to_string(),
                    title: "Live feed crosscheck".to_string(),
                    readiness_status: ReadinessStatus::Waiting,
                    user_instructions: vec![
                        "Compare operator feed, watchtower feed, and local wallet height"
                            .to_string(),
                        "Require matching exit id, claim root, and challenge deadline".to_string(),
                        "Pause if any feed is stale or disagrees on finality".to_string(),
                    ],
                    evidence_roots: vec![
                        live_feed_checkpoint_root.clone(),
                        forced_exit_claim_root.clone(),
                    ],
                    fail_closed_blockers: vec![
                        "live_feed_requires_three_matching_confirmations".to_string()
                    ],
                },
                RunbookStep {
                    step_id: CHALLENGE_DISPUTE_WAIT_STEP_ID.to_string(),
                    title: "Challenge and dispute wait".to_string(),
                    readiness_status: ReadinessStatus::Waiting,
                    user_instructions: vec![
                        "Wait through the configured challenge and dispute windows".to_string(),
                        "Monitor for fraud proof, duplicate claim, or reorg dispute notices"
                            .to_string(),
                        "Keep the package sealed until the dispute window root is finalized"
                            .to_string(),
                    ],
                    evidence_roots: vec![live_feed_checkpoint_root.clone()],
                    fail_closed_blockers: vec!["challenge_window_not_elapsed".to_string()],
                },
                RunbookStep {
                    step_id: RELEASE_VERIFICATION_STEP_ID.to_string(),
                    title: "Release verification".to_string(),
                    readiness_status: ReadinessStatus::ReleaseVerified,
                    user_instructions: vec![
                        "Verify release receipt against payout commitment and finality depth"
                            .to_string(),
                        "Archive wallet scan, claim, authorization, and release roots together"
                            .to_string(),
                        "Mark escape complete only after the release receipt root matches"
                            .to_string(),
                    ],
                    evidence_roots: vec![
                        release_receipt_root.clone(),
                        forced_exit_claim_root.clone(),
                    ],
                    fail_closed_blockers: Vec::new(),
                },
                RunbookStep {
                    step_id: OPERATOR_FAILURE_FALLBACK_STEP_ID.to_string(),
                    title: "Operator failure fallback".to_string(),
                    readiness_status: ReadinessStatus::OperatorFallback,
                    user_instructions: vec![
                        "Switch to watchtower relay when operator feed stalls or withholds release"
                            .to_string(),
                        "Submit the sealed package and operator-failure evidence root".to_string(),
                        "Fail closed if neither operator nor watchtower can prove live custody"
                            .to_string(),
                    ],
                    evidence_roots: vec![live_feed_checkpoint_root, release_receipt_root],
                    fail_closed_blockers: vec![
                        "operator_or_watchtower_custody_not_proven".to_string()
                    ],
                },
            ],
        }
    }

    pub fn step_roots(&self) -> Vec<String> {
        self.steps.iter().map(RunbookStep::step_root).collect()
    }

    pub fn fail_closed_blockers(&self) -> Vec<String> {
        self.steps
            .iter()
            .flat_map(|step| step.fail_closed_blockers.iter().cloned())
            .collect()
    }

    pub fn roots_record(&self) -> Value {
        let step_root_leaves = self
            .step_roots()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();

        json!({
            "config_root": self.config.config_root(),
            "step_root": merkle_root("USER-ESCAPE-RUNBOOK-STEPS", &step_root_leaves),
            "wallet_account_commitment": self.wallet_account_commitment,
            "bridge_exit_commitment": self.bridge_exit_commitment,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "pq_authorization_root": self.pq_authorization_root,
            "live_feed_checkpoint_root": self.live_feed_checkpoint_root,
            "release_receipt_root": self.release_receipt_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_PROOF_RUNTIME_PROTOCOL_VERSION,
            "protocol_label": PROTOCOL_LABEL,
            "config": self.config.public_record(),
            "roots": self.roots_record(),
            "readiness_statuses": self.steps.iter().map(|step| json!({
                "step_id": step.step_id,
                "readiness_status": step.readiness_status.as_str(),
            })).collect::<Vec<_>>(),
            "steps": self.steps.iter().map(RunbookStep::public_record).collect::<Vec<_>>(),
            "fail_closed_blockers": self.fail_closed_blockers(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        runtime_hash(
            "STATE",
            &[HashPart::Json(&self.public_record_without_root())],
        )
    }

    pub fn verify_release(&self, receipt_root: &str) -> Result<String> {
        if receipt_root == self.release_receipt_root {
            Ok(self.state_root())
        } else {
            Err("release_receipt_root_mismatch".to_string())
        }
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

fn seed_root(label: &str, value: &str) -> String {
    runtime_hash("SEED", &[HashPart::Str(label), HashPart::Str(value)])
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let part_record = parts.iter().map(hash_part_record).collect::<Vec<_>>();

    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_LABEL),
            HashPart::Str(MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_PROOF_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(&json!(part_record)),
        ],
        32,
    )
}

fn hash_part_record(part: &HashPart<'_>) -> Value {
    match part {
        HashPart::Bytes(value) => json!({
            "kind": "bytes",
            "value": hex::encode(value),
        }),
        HashPart::Str(value) => json!({
            "kind": "str",
            "value": value,
        }),
        HashPart::U64(value) => json!({
            "kind": "u64",
            "value": value,
        }),
        HashPart::Int(value) => json!({
            "kind": "int",
            "value": value.to_string(),
        }),
        HashPart::Json(value) => json!({
            "kind": "json",
            "value": value,
        }),
    }
}
