use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceFixtureBundleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FIXTURE_BUNDLE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-fixture-bundle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FIXTURE_BUNDLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BUNDLE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-fixtures-v1";
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_240_512;
pub const DEFAULT_MONERO_REFERENCE_HEIGHT: u64 = 3_540_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureKind {
    DepositLock,
    PrivateNote,
    PrivateTransferReceipt,
    ContractActionReceipt,
    WithdrawalClaim,
    AdversarialRecovery,
    EvidenceAcceptance,
}

impl FixtureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateNote => "private_note",
            Self::PrivateTransferReceipt => "private_transfer_receipt",
            Self::ContractActionReceipt => "contract_action_receipt",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::AdversarialRecovery => "adversarial_recovery",
            Self::EvidenceAcceptance => "evidence_acceptance",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub bundle_suite: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub fixture_count: u64,
    pub forced_exit_only: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            bundle_suite: BUNDLE_SUITE.to_string(),
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            monero_reference_height: DEFAULT_MONERO_REFERENCE_HEIGHT,
            fixture_count: 7,
            forced_exit_only: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "bundle_suite": self.bundle_suite,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "fixture_count": self.fixture_count,
            "forced_exit_only": self.forced_exit_only,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureRecord {
    pub fixture_id: String,
    pub kind: FixtureKind,
    pub sequence: u64,
    pub summary: String,
    pub committed_root: String,
    pub public_root: String,
    pub encrypted_root: String,
    pub fixture_root: String,
}

impl FixtureRecord {
    pub fn new(kind: FixtureKind, sequence: u64, summary: &str, public_terms: &[&str]) -> Self {
        let fixture_id = fixture_id(kind, sequence);
        let committed_root = fixture_surface_root("committed", &fixture_id, kind, public_terms);
        let public_root = fixture_surface_root("public", &fixture_id, kind, public_terms);
        let encrypted_root = fixture_surface_root("encrypted", &fixture_id, kind, public_terms);
        let fixture_root = fixture_record_root(
            &fixture_id,
            kind,
            sequence,
            &committed_root,
            &public_root,
            &encrypted_root,
        );

        Self {
            fixture_id,
            kind,
            sequence,
            summary: summary.to_string(),
            committed_root,
            public_root,
            encrypted_root,
            fixture_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "kind": self.kind.as_str(),
            "sequence": self.sequence,
            "summary": self.summary,
            "committed_root": self.committed_root,
            "public_root": self.public_root,
            "encrypted_root": self.encrypted_root,
            "fixture_root": self.fixture_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub fixtures: Vec<FixtureRecord>,
    pub fixture_root: String,
    pub committed_root: String,
    pub public_root: String,
    pub encrypted_root: String,
    pub bundle_id: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let fixtures = canonical_fixtures();
        let fixture_records = fixtures
            .iter()
            .map(FixtureRecord::public_record)
            .collect::<Vec<_>>();
        let committed_records = fixtures
            .iter()
            .map(|fixture| {
                json!({
                    "fixture_id": fixture.fixture_id,
                    "kind": fixture.kind.as_str(),
                    "committed_root": fixture.committed_root,
                })
            })
            .collect::<Vec<_>>();
        let public_records = fixtures
            .iter()
            .map(|fixture| {
                json!({
                    "fixture_id": fixture.fixture_id,
                    "kind": fixture.kind.as_str(),
                    "public_root": fixture.public_root,
                })
            })
            .collect::<Vec<_>>();
        let encrypted_records = fixtures
            .iter()
            .map(|fixture| {
                json!({
                    "fixture_id": fixture.fixture_id,
                    "kind": fixture.kind.as_str(),
                    "encrypted_root": fixture.encrypted_root,
                })
            })
            .collect::<Vec<_>>();

        let fixture_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-FIXTURES",
            &fixture_records,
        );
        let committed_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-COMMITTED-ROOTS",
            &committed_records,
        );
        let public_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-PUBLIC-ROOTS",
            &public_records,
        );
        let encrypted_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-ENCRYPTED-ROOTS",
            &encrypted_records,
        );
        let bundle_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-BUNDLE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&fixture_root),
                HashPart::Str(&committed_root),
                HashPart::Str(&public_root),
                HashPart::Str(&encrypted_root),
            ],
            32,
        );
        let state_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-STATE",
            &[
                HashPart::Json(&config.public_record()),
                HashPart::Str(&bundle_id),
                HashPart::Str(&fixture_root),
                HashPart::Str(&committed_root),
                HashPart::Str(&public_root),
                HashPart::Str(&encrypted_root),
            ],
            32,
        );

        Self {
            config,
            fixtures,
            fixture_root,
            committed_root,
            public_root,
            encrypted_root,
            bundle_id,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "bundle_id": self.bundle_id,
            "fixture_root": self.fixture_root,
            "committed_root": self.committed_root,
            "public_root": self.public_root,
            "encrypted_root": self.encrypted_root,
            "state_root": self.state_root,
            "fixtures": self.fixtures.iter().map(FixtureRecord::public_record).collect::<Vec<_>>(),
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

fn canonical_fixtures() -> Vec<FixtureRecord> {
    vec![
        FixtureRecord::new(
            FixtureKind::DepositLock,
            0,
            "canonical Monero deposit lock with pq watcher quorum and redacted wallet metadata",
            &[
                "monero_tx_lock",
                "burn_output",
                "watcher_quorum",
                "redacted_amount",
            ],
        ),
        FixtureRecord::new(
            FixtureKind::PrivateNote,
            1,
            "deposit lock minted into a private note with unlinkable wallet-local opening data",
            &[
                "note_commitment",
                "view_tag",
                "nullifier_seed",
                "encrypted_opening",
            ],
        ),
        FixtureRecord::new(
            FixtureKind::PrivateTransferReceipt,
            2,
            "private transfer receipt preserving note continuity without public sender linkage",
            &[
                "input_note",
                "output_note",
                "receipt_commitment",
                "privacy_budget",
            ],
        ),
        FixtureRecord::new(
            FixtureKind::ContractActionReceipt,
            3,
            "forced-exit contract action receipt binding claim intent to canonical replay inputs",
            &[
                "contract_call",
                "action_nonce",
                "replay_fence",
                "policy_root",
            ],
        ),
        FixtureRecord::new(
            FixtureKind::WithdrawalClaim,
            4,
            "withdrawal claim carrying subaddress commitment, nullifier, and fee cap evidence",
            &[
                "claim_commitment",
                "subaddress_root",
                "fee_cap",
                "exit_nullifier",
            ],
        ),
        FixtureRecord::new(
            FixtureKind::AdversarialRecovery,
            5,
            "adversarial recovery fixture for operator silence, reorg risk, and delayed release",
            &[
                "recovery_path",
                "challenge_window",
                "reserve_release",
                "fail_closed_gate",
            ],
        ),
        FixtureRecord::new(
            FixtureKind::EvidenceAcceptance,
            6,
            "runtime evidence acceptance receipt with public anchors and encrypted audit material",
            &[
                "evidence_packet",
                "acceptance_receipt",
                "audit_anchor",
                "release_blocker",
            ],
        ),
    ]
}

fn fixture_id(kind: FixtureKind, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-FIXTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn fixture_surface_root(
    surface: &str,
    fixture_id: &str,
    kind: FixtureKind,
    public_terms: &[&str],
) -> String {
    let leaves = public_terms
        .iter()
        .enumerate()
        .map(|(index, term)| {
            json!({
                "surface": surface,
                "fixture_id": fixture_id,
                "kind": kind.as_str(),
                "index": index as u64,
                "term": term,
                "commitment": labeled_commitment(surface, fixture_id, term),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-SURFACE",
        &leaves,
    )
}

fn fixture_record_root(
    fixture_id: &str,
    kind: FixtureKind,
    sequence: u64,
    committed_root: &str,
    public_root: &str,
    encrypted_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-FIXTURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(fixture_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
            HashPart::Str(committed_root),
            HashPart::Str(public_root),
            HashPart::Str(encrypted_root),
        ],
        32,
    )
}

fn labeled_commitment(surface: &str, fixture_id: &str, term: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-LABELED-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(surface),
            HashPart::Str(fixture_id),
            HashPart::Str(term),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
