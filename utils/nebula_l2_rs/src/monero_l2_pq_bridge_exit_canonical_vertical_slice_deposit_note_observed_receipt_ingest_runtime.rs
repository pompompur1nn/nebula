use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceDepositNoteObservedReceiptIngestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-observed-receipt-ingest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-observed-receipt-ingest-runtime";
const DEFAULT_BRIDGE_SESSION_LABEL: &str = "canonical-vertical-slice-devnet";
const DEFAULT_RECEIPT_ID: &str = "devnet-deposit-note-observed-receipt-ingest-0001";
const DEFAULT_MONERO_LOCK_HEIGHT: u64 = 912_640;
const DEFAULT_MONERO_OBSERVED_HEIGHT: u64 = 912_704;
const DEFAULT_MIN_MONERO_FINALITY_DEPTH: u64 = 60;
const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u64 = 6_700;
const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 720;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub bridge_session_label: String,
    pub receipt_id: String,
    pub min_monero_finality_depth: u64,
    pub min_watcher_weight_bps: u64,
    pub release_hold_blocks: u64,
    pub require_wallet_visible_metadata_match: bool,
    pub require_note_commitment_match: bool,
    pub runtime_execution_allowed: bool,
    pub cargo_execution_allowed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            bridge_session_label: DEFAULT_BRIDGE_SESSION_LABEL.to_string(),
            receipt_id: DEFAULT_RECEIPT_ID.to_string(),
            min_monero_finality_depth: DEFAULT_MIN_MONERO_FINALITY_DEPTH,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            require_wallet_visible_metadata_match: true,
            require_note_commitment_match: true,
            runtime_execution_allowed: false,
            cargo_execution_allowed: false,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "bridge_session_label": self.bridge_session_label,
            "receipt_id": self.receipt_id,
            "min_monero_finality_depth": self.min_monero_finality_depth,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "release_hold_blocks": self.release_hold_blocks,
            "require_wallet_visible_metadata_match": self.require_wallet_visible_metadata_match,
            "require_note_commitment_match": self.require_note_commitment_match,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "cargo_execution_allowed": self.cargo_execution_allowed,
            "production_release_allowed": self.production_release_allowed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlaceholderRoot {
    pub lane: String,
    pub placeholder_root: String,
    pub conformance_root: String,
}

impl PlaceholderRoot {
    pub fn new(lane: &str, payload: Value) -> Self {
        let placeholder_root = record_root(&format!("{lane}_placeholder"), &payload);
        let conformance_root = domain_hash(
            &format!("{DOMAIN}:conformance-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane),
                HashPart::Str(&placeholder_root),
            ],
            32,
        );

        Self {
            lane: lane.to_string(),
            placeholder_root,
            conformance_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "placeholder_root": self.placeholder_root,
            "conformance_root": self.conformance_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceiptRecord {
    pub lane: String,
    pub observed_root: String,
    pub expected_placeholder_root: String,
    pub expected_conformance_root: String,
    pub replacement_record_root: String,
    pub observed_at_monero_height: u64,
}

impl ObservedReceiptRecord {
    pub fn from_placeholder(
        placeholder: &PlaceholderRoot,
        observed_payload: Value,
        observed_at_monero_height: u64,
    ) -> Self {
        let observed_root =
            record_root(&format!("{}_observed", placeholder.lane), &observed_payload);
        let replacement_record_root = domain_hash(
            &format!("{DOMAIN}:observed-receipt-replacement"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&placeholder.lane),
                HashPart::Str(&placeholder.placeholder_root),
                HashPart::Str(&placeholder.conformance_root),
                HashPart::Str(&observed_root),
                HashPart::Int(observed_at_monero_height as i128),
            ],
            32,
        );

        Self {
            lane: placeholder.lane.clone(),
            observed_root,
            expected_placeholder_root: placeholder.placeholder_root.clone(),
            expected_conformance_root: placeholder.conformance_root.clone(),
            replacement_record_root,
            observed_at_monero_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "observed_root": self.observed_root,
            "expected_placeholder_root": self.expected_placeholder_root,
            "expected_conformance_root": self.expected_conformance_root,
            "replacement_record_root": self.replacement_record_root,
            "observed_at_monero_height": self.observed_at_monero_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherEvidence {
    pub watcher_set_root: String,
    pub signature_scheme: String,
    pub attested_weight_bps: u64,
    pub min_weight_bps: u64,
    pub attestation_transcript_root: String,
    pub evidence_root: String,
}

impl PqWatcherEvidence {
    pub fn devnet(config: &Config) -> Self {
        let watcher_set_root = label_root("watcher_set", "devnet-pq-observed-receipt-watchers");
        let attestation_transcript_root =
            label_root("watcher_transcript", "deposit-note-observed-receipt-ingest");
        let attested_weight_bps = 7_500;
        let evidence_root = record_root(
            "pq_watcher_evidence",
            &json!({
                "watcher_set_root": watcher_set_root,
                "signature_scheme": "ml-dsa-falcon-hybrid",
                "attested_weight_bps": attested_weight_bps,
                "min_weight_bps": config.min_watcher_weight_bps,
                "attestation_transcript_root": attestation_transcript_root,
            }),
        );

        Self {
            watcher_set_root,
            signature_scheme: "ml-dsa-falcon-hybrid".to_string(),
            attested_weight_bps,
            min_weight_bps: config.min_watcher_weight_bps,
            attestation_transcript_root,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watcher_set_root": self.watcher_set_root,
            "signature_scheme": self.signature_scheme,
            "attested_weight_bps": self.attested_weight_bps,
            "min_weight_bps": self.min_weight_bps,
            "attestation_transcript_root": self.attestation_transcript_root,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroFinalityEvidence {
    pub lock_height: u64,
    pub observed_height: u64,
    pub finality_depth: u64,
    pub min_finality_depth: u64,
    pub reorg_probe_root: String,
    pub evidence_root: String,
}

impl MoneroFinalityEvidence {
    pub fn devnet(config: &Config) -> Self {
        let lock_height = DEFAULT_MONERO_LOCK_HEIGHT;
        let observed_height = DEFAULT_MONERO_OBSERVED_HEIGHT;
        let finality_depth = observed_height.saturating_sub(lock_height);
        let reorg_probe_root = label_root(
            "monero_reorg_probe",
            "canonical-branch-window-912640-912704",
        );
        let evidence_root = record_root(
            "monero_finality_evidence",
            &json!({
                "lock_height": lock_height,
                "observed_height": observed_height,
                "finality_depth": finality_depth,
                "min_finality_depth": config.min_monero_finality_depth,
                "reorg_probe_root": reorg_probe_root,
            }),
        );

        Self {
            lock_height,
            observed_height,
            finality_depth,
            min_finality_depth: config.min_monero_finality_depth,
            reorg_probe_root,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lock_height": self.lock_height,
            "observed_height": self.observed_height,
            "finality_depth": self.finality_depth,
            "min_finality_depth": self.min_finality_depth,
            "reorg_probe_root": self.reorg_probe_root,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub wallet_hint_root: String,
    pub expected_metadata_root: String,
    pub observed_metadata_root: String,
    pub scan_from_height: u64,
    pub scan_to_height: u64,
    pub metadata_drift: bool,
    pub hint_root: String,
}

impl WalletScanHint {
    pub fn devnet() -> Self {
        let expected_metadata_root = label_root("wallet_metadata", "wallet-visible-redacted-v1");
        let observed_metadata_root = expected_metadata_root.clone();
        let wallet_hint_root = label_root("wallet_scan_hint", "scan-window-912640-912704");
        let hint_root = record_root(
            "wallet_scan_hint",
            &json!({
                "wallet_hint_root": wallet_hint_root,
                "expected_metadata_root": expected_metadata_root,
                "observed_metadata_root": observed_metadata_root,
                "scan_from_height": DEFAULT_MONERO_LOCK_HEIGHT,
                "scan_to_height": DEFAULT_MONERO_OBSERVED_HEIGHT,
                "metadata_drift": false,
            }),
        );

        Self {
            wallet_hint_root,
            expected_metadata_root,
            observed_metadata_root,
            scan_from_height: DEFAULT_MONERO_LOCK_HEIGHT,
            scan_to_height: DEFAULT_MONERO_OBSERVED_HEIGHT,
            metadata_drift: false,
            hint_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_hint_root": self.wallet_hint_root,
            "expected_metadata_root": self.expected_metadata_root,
            "observed_metadata_root": self.observed_metadata_root,
            "scan_from_height": self.scan_from_height,
            "scan_to_height": self.scan_to_height,
            "metadata_drift": self.metadata_drift,
            "hint_root": self.hint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NoteCommitmentEvidence {
    pub expected_note_commitment_root: String,
    pub observed_note_commitment_root: String,
    pub amount_commitment_root: String,
    pub recipient_commitment_root: String,
    pub nullifier_domain_root: String,
    pub commitment_mismatch: bool,
    pub evidence_root: String,
}

impl NoteCommitmentEvidence {
    pub fn devnet() -> Self {
        let amount_commitment_root = label_root("amount_commitment", "locked-atomic-units");
        let recipient_commitment_root = label_root("recipient_commitment", "pq-wallet-recipient");
        let nullifier_domain_root = label_root("nullifier_domain", "forced-exit-spine");
        let expected_note_commitment_root = domain_hash(
            &format!("{DOMAIN}:note-commitment"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&amount_commitment_root),
                HashPart::Str(&recipient_commitment_root),
                HashPart::Str(&nullifier_domain_root),
            ],
            32,
        );
        let observed_note_commitment_root = expected_note_commitment_root.clone();
        let evidence_root = record_root(
            "note_commitment_evidence",
            &json!({
                "expected_note_commitment_root": expected_note_commitment_root,
                "observed_note_commitment_root": observed_note_commitment_root,
                "amount_commitment_root": amount_commitment_root,
                "recipient_commitment_root": recipient_commitment_root,
                "nullifier_domain_root": nullifier_domain_root,
                "commitment_mismatch": false,
            }),
        );

        Self {
            expected_note_commitment_root,
            observed_note_commitment_root,
            amount_commitment_root,
            recipient_commitment_root,
            nullifier_domain_root,
            commitment_mismatch: false,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "expected_note_commitment_root": self.expected_note_commitment_root,
            "observed_note_commitment_root": self.observed_note_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "nullifier_domain_root": self.nullifier_domain_root,
            "commitment_mismatch": self.commitment_mismatch,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MismatchRecord {
    pub lane: String,
    pub expected_root: String,
    pub observed_root: String,
    pub reason: String,
    pub release_blocking: bool,
    pub mismatch_root: String,
}

impl MismatchRecord {
    pub fn new(lane: &str, expected_root: &str, observed_root: &str, reason: &str) -> Self {
        let mismatch_root = record_root(
            &format!("{lane}_mismatch"),
            &json!({
                "lane": lane,
                "expected_root": expected_root,
                "observed_root": observed_root,
                "reason": reason,
                "release_blocking": true,
            }),
        );

        Self {
            lane: lane.to_string(),
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            reason: reason.to_string(),
            release_blocking: true,
            mismatch_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "reason": self.reason,
            "release_blocking": self.release_blocking,
            "mismatch_root": self.mismatch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub reason: String,
    pub release_not_before_monero_height: u64,
    pub release_blocking: bool,
    pub hold_root: String,
}

impl ReleaseHold {
    pub fn new(reason: &str, observed_height: u64, hold_blocks: u64) -> Self {
        let release_not_before_monero_height = observed_height.saturating_add(hold_blocks);
        let hold_id = label_root("release_hold", reason);
        let hold_root = record_root(
            "release_hold",
            &json!({
                "hold_id": hold_id,
                "reason": reason,
                "release_not_before_monero_height": release_not_before_monero_height,
                "release_blocking": true,
            }),
        );

        Self {
            hold_id,
            reason: reason.to_string(),
            release_not_before_monero_height,
            release_blocking: true,
            hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "reason": self.reason,
            "release_not_before_monero_height": self.release_not_before_monero_height,
            "release_blocking": self.release_blocking,
            "hold_root": self.hold_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub bridge_session_id: String,
    pub receipt_id: String,
    pub placeholder_roots: BTreeMap<String, PlaceholderRoot>,
    pub observed_receipts: BTreeMap<String, ObservedReceiptRecord>,
    pub pq_watcher_evidence: PqWatcherEvidence,
    pub monero_finality_evidence: MoneroFinalityEvidence,
    pub wallet_scan_hint: WalletScanHint,
    pub note_commitment_evidence: NoteCommitmentEvidence,
    pub mismatch_records: BTreeMap<String, MismatchRecord>,
    pub release_holds: BTreeMap<String, ReleaseHold>,
    pub observed_receipt_root: String,
    pub mismatch_root: String,
    pub wallet_scan_hint_root: String,
    pub pq_watcher_evidence_root: String,
    pub finality_evidence_root: String,
    pub note_commitment_root: String,
    pub release_hold_root: String,
    pub fail_closed_root: String,
    pub production_release_allowed: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let bridge_session_id = label_root("bridge_session", &config.bridge_session_label);
        let receipt_id = config.receipt_id.clone();
        let monero_finality_evidence = MoneroFinalityEvidence::devnet(&config);
        let pq_watcher_evidence = PqWatcherEvidence::devnet(&config);
        let wallet_scan_hint = WalletScanHint::devnet();
        let note_commitment_evidence = NoteCommitmentEvidence::devnet();

        let mut placeholder_roots = BTreeMap::new();
        insert_placeholder(
            &mut placeholder_roots,
            PlaceholderRoot::new(
                "deposit_note_receipt",
                json!({
                    "receipt_id": receipt_id,
                    "bridge_session_id": bridge_session_id,
                    "status": "placeholder_conformance_root",
                }),
            ),
        );
        insert_placeholder(
            &mut placeholder_roots,
            PlaceholderRoot::new(
                "wallet_visible_receipt",
                json!({
                    "wallet_hint_root": wallet_scan_hint.hint_root,
                    "metadata_root": wallet_scan_hint.expected_metadata_root,
                    "status": "placeholder_conformance_root",
                }),
            ),
        );
        insert_placeholder(
            &mut placeholder_roots,
            PlaceholderRoot::new(
                "note_commitment_receipt",
                json!({
                    "expected_note_commitment_root": note_commitment_evidence.expected_note_commitment_root,
                    "status": "placeholder_conformance_root",
                }),
            ),
        );

        let mut observed_receipts = BTreeMap::new();
        for placeholder in placeholder_roots.values() {
            let observed_payload = observed_payload_for_lane(
                placeholder,
                &monero_finality_evidence,
                &pq_watcher_evidence,
                &wallet_scan_hint,
                &note_commitment_evidence,
            );
            insert_observed(
                &mut observed_receipts,
                ObservedReceiptRecord::from_placeholder(
                    placeholder,
                    observed_payload,
                    monero_finality_evidence.observed_height,
                ),
            );
        }

        let mut mismatch_records = BTreeMap::new();
        collect_mismatches(
            &config,
            &placeholder_roots,
            &observed_receipts,
            &monero_finality_evidence,
            &pq_watcher_evidence,
            &wallet_scan_hint,
            &note_commitment_evidence,
            &mut mismatch_records,
        );

        let mut release_holds = BTreeMap::new();
        insert_release_hold(
            &mut release_holds,
            ReleaseHold::new(
                "cargo_and_runtime_gates_not_enabled_for_observed_receipt_ingest",
                monero_finality_evidence.observed_height,
                config.release_hold_blocks,
            ),
        );
        let observed_receipt_root = map_root("observed_receipts", &observed_receipts);
        let mismatch_root = mismatch_map_root("mismatch_records", &mismatch_records);
        let wallet_scan_hint_root =
            record_root("wallet_scan_hint_root", &wallet_scan_hint.public_record());
        let pq_watcher_evidence_root = record_root(
            "pq_watcher_evidence_root",
            &pq_watcher_evidence.public_record(),
        );
        let finality_evidence_root = record_root(
            "finality_evidence_root",
            &monero_finality_evidence.public_record(),
        );
        let note_commitment_root = record_root(
            "note_commitment_root",
            &note_commitment_evidence.public_record(),
        );
        let release_hold_root = release_hold_map_root("release_holds", &release_holds);
        let fail_closed_root = fail_closed_root(&mismatch_records, &release_holds);

        Self {
            config,
            bridge_session_id,
            receipt_id,
            placeholder_roots,
            observed_receipts,
            pq_watcher_evidence,
            monero_finality_evidence,
            wallet_scan_hint,
            note_commitment_evidence,
            mismatch_records,
            release_holds,
            observed_receipt_root,
            mismatch_root,
            wallet_scan_hint_root,
            pq_watcher_evidence_root,
            finality_evidence_root,
            note_commitment_root,
            release_hold_root,
            fail_closed_root,
            production_release_allowed: false,
        }
    }

    pub fn validate_fail_closed(&self) -> Result<()> {
        if self.observed_receipts.is_empty() {
            return Err("missing observed receipt roots".to_string());
        }
        if self.monero_finality_evidence.finality_depth
            < self.monero_finality_evidence.min_finality_depth
        {
            return Err("stale Monero finality evidence".to_string());
        }
        if self.pq_watcher_evidence.attested_weight_bps < self.pq_watcher_evidence.min_weight_bps {
            return Err("weak PQ watcher quorum".to_string());
        }
        if self.wallet_scan_hint.metadata_drift
            || self.wallet_scan_hint.expected_metadata_root
                != self.wallet_scan_hint.observed_metadata_root
        {
            return Err("wallet-visible metadata drift".to_string());
        }
        if self.note_commitment_evidence.commitment_mismatch
            || self.note_commitment_evidence.expected_note_commitment_root
                != self.note_commitment_evidence.observed_note_commitment_root
        {
            return Err("note-commitment mismatch".to_string());
        }
        for placeholder in self.placeholder_roots.values() {
            let observed = match self.observed_receipts.get(&placeholder.lane) {
                Some(record) => record,
                None => {
                    return Err(format!(
                        "missing observed root for lane {}",
                        placeholder.lane
                    ))
                }
            };
            if observed.expected_placeholder_root != placeholder.placeholder_root {
                return Err(format!(
                    "placeholder root mismatch for lane {}",
                    placeholder.lane
                ));
            }
            if observed.expected_conformance_root != placeholder.conformance_root {
                return Err(format!(
                    "conformance root mismatch for lane {}",
                    placeholder.lane
                ));
            }
        }
        if !self.mismatch_records.is_empty() {
            return Err("observed receipt ingest has mismatch records".to_string());
        }
        if !self.release_holds.is_empty() {
            return Err("observed receipt ingest is under release hold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "bridge_session_id": self.bridge_session_id,
            "receipt_id": self.receipt_id,
            "placeholder_roots": self.placeholder_roots.values().map(PlaceholderRoot::public_record).collect::<Vec<_>>(),
            "observed_receipts": self.observed_receipts.values().map(ObservedReceiptRecord::public_record).collect::<Vec<_>>(),
            "pq_watcher_evidence": self.pq_watcher_evidence.public_record(),
            "monero_finality_evidence": self.monero_finality_evidence.public_record(),
            "wallet_scan_hint": self.wallet_scan_hint.public_record(),
            "note_commitment_evidence": self.note_commitment_evidence.public_record(),
            "mismatch_records": self.mismatch_records.values().map(MismatchRecord::public_record).collect::<Vec<_>>(),
            "release_holds": self.release_holds.values().map(ReleaseHold::public_record).collect::<Vec<_>>(),
            "observed_receipt_root": self.observed_receipt_root,
            "mismatch_root": self.mismatch_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "pq_watcher_evidence_root": self.pq_watcher_evidence_root,
            "finality_evidence_root": self.finality_evidence_root,
            "note_commitment_root": self.note_commitment_root,
            "release_hold_root": self.release_hold_root,
            "fail_closed_root": self.fail_closed_root,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(&record_root("config", &self.config.public_record())),
                HashPart::Str(&self.bridge_session_id),
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.observed_receipt_root),
                HashPart::Str(&self.mismatch_root),
                HashPart::Str(&self.wallet_scan_hint_root),
                HashPart::Str(&self.pq_watcher_evidence_root),
                HashPart::Str(&self.finality_evidence_root),
                HashPart::Str(&self.note_commitment_root),
                HashPart::Str(&self.release_hold_root),
                HashPart::Str(&self.fail_closed_root),
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

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn label_root(kind: &str, label: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:label"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn observed_payload_for_lane(
    placeholder: &PlaceholderRoot,
    finality: &MoneroFinalityEvidence,
    watcher: &PqWatcherEvidence,
    wallet: &WalletScanHint,
    note: &NoteCommitmentEvidence,
) -> Value {
    json!({
        "lane": placeholder.lane,
        "replaces_placeholder_root": placeholder.placeholder_root,
        "replaces_conformance_root": placeholder.conformance_root,
        "monero_finality_evidence_root": finality.evidence_root,
        "pq_watcher_evidence_root": watcher.evidence_root,
        "wallet_scan_hint_root": wallet.hint_root,
        "note_commitment_evidence_root": note.evidence_root,
        "observed_height": finality.observed_height,
        "status": "runtime_observed_deposit_note_receipt_root",
    })
}

fn collect_mismatches(
    config: &Config,
    placeholder_roots: &BTreeMap<String, PlaceholderRoot>,
    observed_receipts: &BTreeMap<String, ObservedReceiptRecord>,
    finality: &MoneroFinalityEvidence,
    watcher: &PqWatcherEvidence,
    wallet: &WalletScanHint,
    note: &NoteCommitmentEvidence,
    mismatch_records: &mut BTreeMap<String, MismatchRecord>,
) {
    for placeholder in placeholder_roots.values() {
        match observed_receipts.get(&placeholder.lane) {
            Some(observed) => {
                if observed.expected_placeholder_root != placeholder.placeholder_root {
                    insert_mismatch(
                        mismatch_records,
                        MismatchRecord::new(
                            &placeholder.lane,
                            &placeholder.placeholder_root,
                            &observed.expected_placeholder_root,
                            "observed receipt references a different placeholder root",
                        ),
                    );
                }
                if observed.expected_conformance_root != placeholder.conformance_root {
                    insert_mismatch(
                        mismatch_records,
                        MismatchRecord::new(
                            &placeholder.lane,
                            &placeholder.conformance_root,
                            &observed.expected_conformance_root,
                            "observed receipt references a different conformance root",
                        ),
                    );
                }
            }
            None => insert_mismatch(
                mismatch_records,
                MismatchRecord::new(
                    &placeholder.lane,
                    &placeholder.placeholder_root,
                    "missing",
                    "missing observed receipt root",
                ),
            ),
        }
    }
    if finality.finality_depth < config.min_monero_finality_depth {
        insert_mismatch(
            mismatch_records,
            MismatchRecord::new(
                "monero_finality",
                &config.min_monero_finality_depth.to_string(),
                &finality.finality_depth.to_string(),
                "stale Monero finality evidence",
            ),
        );
    }
    if watcher.attested_weight_bps < config.min_watcher_weight_bps {
        insert_mismatch(
            mismatch_records,
            MismatchRecord::new(
                "pq_watcher_quorum",
                &config.min_watcher_weight_bps.to_string(),
                &watcher.attested_weight_bps.to_string(),
                "weak PQ watcher quorum",
            ),
        );
    }
    if wallet.expected_metadata_root != wallet.observed_metadata_root || wallet.metadata_drift {
        insert_mismatch(
            mismatch_records,
            MismatchRecord::new(
                "wallet_visible_metadata",
                &wallet.expected_metadata_root,
                &wallet.observed_metadata_root,
                "wallet-visible metadata drift",
            ),
        );
    }
    if note.expected_note_commitment_root != note.observed_note_commitment_root
        || note.commitment_mismatch
    {
        insert_mismatch(
            mismatch_records,
            MismatchRecord::new(
                "note_commitment",
                &note.expected_note_commitment_root,
                &note.observed_note_commitment_root,
                "note-commitment mismatch",
            ),
        );
    }
}

fn insert_placeholder(
    placeholder_roots: &mut BTreeMap<String, PlaceholderRoot>,
    placeholder: PlaceholderRoot,
) {
    placeholder_roots.insert(placeholder.lane.clone(), placeholder);
}

fn insert_observed(
    observed_receipts: &mut BTreeMap<String, ObservedReceiptRecord>,
    observed: ObservedReceiptRecord,
) {
    observed_receipts.insert(observed.lane.clone(), observed);
}

fn insert_mismatch(
    mismatch_records: &mut BTreeMap<String, MismatchRecord>,
    mismatch: MismatchRecord,
) {
    mismatch_records.insert(mismatch.lane.clone(), mismatch);
}

fn insert_release_hold(release_holds: &mut BTreeMap<String, ReleaseHold>, hold: ReleaseHold) {
    release_holds.insert(hold.hold_id.clone(), hold);
}

fn map_root(label: &str, records: &BTreeMap<String, ObservedReceiptRecord>) -> String {
    let leaves = records
        .values()
        .map(ObservedReceiptRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

fn mismatch_map_root(label: &str, records: &BTreeMap<String, MismatchRecord>) -> String {
    let leaves = records
        .values()
        .map(MismatchRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

fn release_hold_map_root(label: &str, records: &BTreeMap<String, ReleaseHold>) -> String {
    let leaves = records
        .values()
        .map(ReleaseHold::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

fn fail_closed_root(
    mismatch_records: &BTreeMap<String, MismatchRecord>,
    release_holds: &BTreeMap<String, ReleaseHold>,
) -> String {
    let mut leaves = mismatch_records
        .values()
        .map(MismatchRecord::public_record)
        .collect::<Vec<_>>();
    leaves.extend(
        release_holds
            .values()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>(),
    );
    merkle_root(&format!("{DOMAIN}:fail-closed"), &leaves)
}
