use serde_json::{Map, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReleaseVerificationProofRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_PROOF_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-proof-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_PROOF_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_VERIFICATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-proof-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub network: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub escape_package_id: String,
    pub release_verification_manifest_root: String,
    pub wallet_verifier_root: String,
    pub monero_broadcast_verifier_root: String,
    pub pq_custody_verifier_root: String,
    pub liquidity_verifier_root: String,
    pub release_blocker_verifier_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let release_verification_manifest_root = fixed_root(
            "release-verification-manifest",
            "canonical-user-escape-devnet",
        );
        let wallet_verifier_root = fixed_root("wallet-verifier", "view-key-and-address-match");
        let monero_broadcast_verifier_root =
            fixed_root("monero-broadcast-verifier", "tx-relay-ready-with-fee-bound");
        let pq_custody_verifier_root =
            fixed_root("pq-custody-verifier", "custody-share-threshold-verified");
        let liquidity_verifier_root = fixed_root("liquidity-verifier", "reserve-coverage-ready");
        let release_blocker_verifier_root =
            fixed_root("release-blocker-verifier", "fail-closed-blockers-enforced");
        let escape_package_id = escape_package_id(
            &release_verification_manifest_root,
            &wallet_verifier_root,
            &monero_broadcast_verifier_root,
            &pq_custody_verifier_root,
            &liquidity_verifier_root,
            &release_blocker_verifier_root,
        );

        Self {
            network: "devnet".to_string(),
            l2_reference_height: 4_240_000,
            monero_reference_height: 3_520_000,
            escape_package_id,
            release_verification_manifest_root,
            wallet_verifier_root,
            monero_broadcast_verifier_root,
            pq_custody_verifier_root,
            liquidity_verifier_root,
            release_blocker_verifier_root,
        }
    }

    pub fn public_record(&self) -> Value {
        object([
            ("network", string_value(&self.network)),
            (
                "l2_reference_height",
                number_value(self.l2_reference_height),
            ),
            (
                "monero_reference_height",
                number_value(self.monero_reference_height),
            ),
            ("escape_package_id", string_value(&self.escape_package_id)),
            (
                "release_verification_manifest_root",
                string_value(&self.release_verification_manifest_root),
            ),
            (
                "wallet_verifier_root",
                string_value(&self.wallet_verifier_root),
            ),
            (
                "monero_broadcast_verifier_root",
                string_value(&self.monero_broadcast_verifier_root),
            ),
            (
                "pq_custody_verifier_root",
                string_value(&self.pq_custody_verifier_root),
            ),
            (
                "liquidity_verifier_root",
                string_value(&self.liquidity_verifier_root),
            ),
            (
                "release_blocker_verifier_root",
                string_value(&self.release_blocker_verifier_root),
            ),
        ])
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseEvidence {
    pub name: String,
    pub verifier_root: String,
    pub accepted: bool,
    pub evidence_root: String,
    pub note: String,
}

impl ReleaseEvidence {
    pub fn new(name: &str, verifier_root: &str, accepted: bool, note: &str) -> Self {
        let evidence_root = release_evidence_root(name, verifier_root, accepted, note);

        Self {
            name: name.to_string(),
            verifier_root: verifier_root.to_string(),
            accepted,
            evidence_root,
            note: note.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        object([
            ("name", string_value(&self.name)),
            ("verifier_root", string_value(&self.verifier_root)),
            ("accepted", Value::Bool(self.accepted)),
            ("evidence_root", string_value(&self.evidence_root)),
            ("note", string_value(&self.note)),
        ])
    }

    pub fn state_root(&self) -> String {
        record_root("release-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailClosedGap {
    pub gap: String,
    pub blocks_release: bool,
    pub evidence_root: String,
}

impl FailClosedGap {
    pub fn new(gap: &str, blocks_release: bool) -> Self {
        let evidence_root = fixed_root("fail-closed-gap", gap);

        Self {
            gap: gap.to_string(),
            blocks_release,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        object([
            ("gap", string_value(&self.gap)),
            ("blocks_release", Value::Bool(self.blocks_release)),
            ("evidence_root", string_value(&self.evidence_root)),
        ])
    }

    pub fn state_root(&self) -> String {
        record_root("fail-closed-gap", &self.public_record())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserExitVerdict {
    pub verdict: String,
    pub user_exit_verdict_root: String,
    pub ready_evidence_root: String,
    pub blocked_evidence_root: String,
    pub fail_closed_gap_root: String,
    pub release_ready: bool,
}

impl UserExitVerdict {
    pub fn from_roots(ready_root: String, blocked_root: String, gap_root: String) -> Self {
        let release_ready = blocked_root == empty_set_root("blocked-evidence")
            && gap_root == empty_set_root("fail-closed-gaps");
        let verdict = if release_ready {
            "user_escape_release_ready"
        } else {
            "user_escape_release_blocked_fail_closed"
        }
        .to_string();
        let user_exit_verdict_root = domain_hash(
            "monero-l2-pq-bridge-user-escape-release-verdict",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&ready_root),
                HashPart::Str(&blocked_root),
                HashPart::Str(&gap_root),
                HashPart::Str(&verdict),
            ],
            32,
        );

        Self {
            verdict,
            user_exit_verdict_root,
            ready_evidence_root: ready_root,
            blocked_evidence_root: blocked_root,
            fail_closed_gap_root: gap_root,
            release_ready,
        }
    }

    pub fn public_record(&self) -> Value {
        object([
            ("verdict", string_value(&self.verdict)),
            (
                "user_exit_verdict_root",
                string_value(&self.user_exit_verdict_root),
            ),
            (
                "ready_evidence_root",
                string_value(&self.ready_evidence_root),
            ),
            (
                "blocked_evidence_root",
                string_value(&self.blocked_evidence_root),
            ),
            (
                "fail_closed_gap_root",
                string_value(&self.fail_closed_gap_root),
            ),
            ("release_ready", Value::Bool(self.release_ready)),
        ])
    }

    pub fn state_root(&self) -> String {
        record_root("user-exit-verdict", &self.public_record())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub config: Config,
    pub ready_evidence: Vec<ReleaseEvidence>,
    pub blocked_evidence: Vec<ReleaseEvidence>,
    pub fail_closed_gaps: Vec<FailClosedGap>,
    pub verdict: UserExitVerdict,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let ready_evidence = Vec::from([
            ReleaseEvidence::new(
                "wallet_verifier",
                &config.wallet_verifier_root,
                true,
                "escape wallet proof binds view key, spend authorization, and destination address",
            ),
            ReleaseEvidence::new(
                "monero_broadcast_verifier",
                &config.monero_broadcast_verifier_root,
                true,
                "broadcast plan has canonical transaction envelope and fee ceiling evidence",
            ),
            ReleaseEvidence::new(
                "pq_custody_verifier",
                &config.pq_custody_verifier_root,
                true,
                "post-quantum custody threshold evidence is present for user release",
            ),
            ReleaseEvidence::new(
                "liquidity_verifier",
                &config.liquidity_verifier_root,
                true,
                "reserve coverage and exit liquidity evidence are bound into package",
            ),
        ]);
        let blocked_evidence = Vec::new();
        let fail_closed_gaps = Vec::new();
        let verdict = UserExitVerdict::from_roots(
            evidence_root("ready-evidence", &ready_evidence),
            evidence_root("blocked-evidence", &blocked_evidence),
            gap_root(&fail_closed_gaps),
        );

        Self {
            config,
            ready_evidence,
            blocked_evidence,
            fail_closed_gaps,
            verdict,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        object([
            ("chain_id", string_value(CHAIN_ID)),
            ("protocol_version", string_value(PROTOCOL_VERSION)),
            ("schema_version", number_value(SCHEMA_VERSION)),
            ("hash_suite", string_value(HASH_SUITE)),
            (
                "release_verification_suite",
                string_value(RELEASE_VERIFICATION_SUITE),
            ),
            ("config", self.config.public_record()),
            (
                "release_verification_manifest_root",
                string_value(&self.config.release_verification_manifest_root),
            ),
            (
                "wallet_verifier_root",
                string_value(&self.config.wallet_verifier_root),
            ),
            (
                "monero_broadcast_verifier_root",
                string_value(&self.config.monero_broadcast_verifier_root),
            ),
            (
                "pq_custody_verifier_root",
                string_value(&self.config.pq_custody_verifier_root),
            ),
            (
                "liquidity_verifier_root",
                string_value(&self.config.liquidity_verifier_root),
            ),
            (
                "release_blocker_verifier_root",
                string_value(&self.config.release_blocker_verifier_root),
            ),
            (
                "ready_evidence",
                Value::Array(
                    self.ready_evidence
                        .iter()
                        .map(ReleaseEvidence::public_record)
                        .collect(),
                ),
            ),
            (
                "blocked_evidence",
                Value::Array(
                    self.blocked_evidence
                        .iter()
                        .map(ReleaseEvidence::public_record)
                        .collect(),
                ),
            ),
            (
                "fail_closed_gaps",
                Value::Array(
                    self.fail_closed_gaps
                        .iter()
                        .map(FailClosedGap::public_record)
                        .collect(),
                ),
            ),
            (
                "ready_evidence_root",
                string_value(&self.verdict.ready_evidence_root),
            ),
            (
                "blocked_evidence_root",
                string_value(&self.verdict.blocked_evidence_root),
            ),
            (
                "fail_closed_gap_root",
                string_value(&self.verdict.fail_closed_gap_root),
            ),
            (
                "user_exit_verdict_root",
                string_value(&self.verdict.user_exit_verdict_root),
            ),
            ("verdict", self.verdict.public_record()),
        ])
    }

    pub fn public_record(&self) -> Value {
        let mut record = match self.public_record_without_state_root() {
            Value::Object(record) => record,
            _ => Map::new(),
        };
        record.insert("state_root".to_string(), string_value(&self.state_root()));
        Value::Object(record)
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_state_root())
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

fn escape_package_id(
    manifest_root: &str,
    wallet_root: &str,
    broadcast_root: &str,
    pq_custody_root: &str,
    liquidity_root: &str,
    blocker_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-package-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(manifest_root),
            HashPart::Str(wallet_root),
            HashPart::Str(broadcast_root),
            HashPart::Str(pq_custody_root),
            HashPart::Str(liquidity_root),
            HashPart::Str(blocker_root),
        ],
        16,
    )
}

fn release_evidence_root(name: &str, verifier_root: &str, accepted: bool, note: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-evidence",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(name),
            HashPart::Str(verifier_root),
            HashPart::Str(bool_label(accepted)),
            HashPart::Str(note),
        ],
        32,
    )
}

fn evidence_root(kind: &str, evidence: &[ReleaseEvidence]) -> String {
    if evidence.is_empty() {
        return empty_set_root(kind);
    }

    let records = evidence
        .iter()
        .map(ReleaseEvidence::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-user-escape-release-evidence-root",
        &records,
    )
}

fn gap_root(gaps: &[FailClosedGap]) -> String {
    if gaps.is_empty() {
        return empty_set_root("fail-closed-gaps");
    }

    let records = gaps
        .iter()
        .map(FailClosedGap::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-user-escape-fail-closed-gap-root",
        &records,
    )
}

fn empty_set_root(kind: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-empty-set",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
        ],
        32,
    )
}

fn fixed_root(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-fixed-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-release-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

fn string_value(value: &str) -> Value {
    Value::String(value.to_string())
}

fn number_value(value: u64) -> Value {
    Value::Number(value.into())
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
