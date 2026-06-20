use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapePrivateNoteRuntimeOutputReconciliationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-private-note-runtime-output-reconciliation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECONCILIATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-private-note-runtime-output-reconciliation-v1";
pub const PRIVACY_BOUNDARY: &str = "handler-bound-roots-and-wallet-scan-evidence-only";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 744_193;
pub const DEFAULT_RECONCILIATION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REQUIRED_RUNTIME_FEEDS: u64 = 3;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub reconciliation_suite: String,
    pub privacy_boundary: String,
    pub reconciliation_height: u64,
    pub reconciliation_window_blocks: u64,
    pub required_runtime_feeds: u64,
    pub metadata_budget_units: u64,
    pub production_release_allowed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            reconciliation_suite: RECONCILIATION_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            reconciliation_height: DEFAULT_DEVNET_HEIGHT,
            reconciliation_window_blocks: DEFAULT_RECONCILIATION_WINDOW_BLOCKS,
            required_runtime_feeds: DEFAULT_REQUIRED_RUNTIME_FEEDS,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "reconciliation_suite": self.reconciliation_suite,
            "privacy_boundary": self.privacy_boundary,
            "reconciliation_height": self.reconciliation_height,
            "reconciliation_window_blocks": self.reconciliation_window_blocks,
            "required_runtime_feeds": self.required_runtime_feeds,
            "metadata_budget_units": self.metadata_budget_units,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpectedRuntimeRoots {
    pub expectation_id: String,
    pub handler_execution_id: String,
    pub handler_verdict_root: String,
    pub expected_commitment_root: String,
    pub expected_nullifier_root: String,
    pub expected_encrypted_payload_root: String,
    pub expected_receipt_root: String,
    pub expected_metadata_root: String,
    pub expected_output_root: String,
}

impl ExpectedRuntimeRoots {
    pub fn devnet(config: &Config) -> Self {
        let expectation_id = "devnet-private-note-runtime-output-expectation-0001".to_string();
        let handler_execution_id = "devnet-private-note-handler-bound-execution-0001".to_string();
        let handler_verdict_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-HANDLER-VERDICT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&handler_execution_id),
                HashPart::Str("handler_bound_execution_accepted"),
                HashPart::Str("private_note_escape_lane_executable"),
            ],
            32,
        );
        let expected_commitment_root = root_from_leaves(
            "EXPECTED-COMMITMENT",
            &expectation_id,
            &[
                "commitment_frontier_matches_handler_input",
                "note_commitment_not_plaintext",
                "canonical_exit_commitment_lane",
            ],
        );
        let expected_nullifier_root = root_from_leaves(
            "EXPECTED-NULLIFIER",
            &expectation_id,
            &[
                "nullifier_frontier_matches_handler_input",
                "key_image_domain_separated",
                "spend_linkage_not_revealed",
            ],
        );
        let expected_encrypted_payload_root = root_from_leaves(
            "EXPECTED-ENCRYPTED-PAYLOAD",
            &expectation_id,
            &[
                "payload_ciphertext_root_matches_handler_input",
                "wallet_scan_hints_capped",
                "recipient_amount_route_redacted",
            ],
        );
        let expected_receipt_root = root_from_leaves(
            "EXPECTED-RECEIPT",
            &expectation_id,
            &[
                "forced_exit_receipt_commitment",
                "runtime_output_receipt_redacted",
                "release_claim_bound_to_reconciliation",
            ],
        );
        let expected_metadata_root = root_from_leaves(
            "EXPECTED-METADATA",
            &expectation_id,
            &[
                "metadata_budget_enforced",
                "runtime_feed_count_threshold",
                "no_wallet_plaintext_disclosure",
            ],
        );
        let expected_output_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-EXPECTED-OUTPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&expectation_id),
                HashPart::Str(&handler_execution_id),
                HashPart::Str(&handler_verdict_root),
                HashPart::Str(&expected_commitment_root),
                HashPart::Str(&expected_nullifier_root),
                HashPart::Str(&expected_encrypted_payload_root),
                HashPart::Str(&expected_receipt_root),
                HashPart::Str(&expected_metadata_root),
                HashPart::U64(config.reconciliation_height),
            ],
            32,
        );

        Self {
            expectation_id,
            handler_execution_id,
            handler_verdict_root,
            expected_commitment_root,
            expected_nullifier_root,
            expected_encrypted_payload_root,
            expected_receipt_root,
            expected_metadata_root,
            expected_output_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "expectation_id": self.expectation_id,
            "handler_execution_id": self.handler_execution_id,
            "handler_verdict_root": self.handler_verdict_root,
            "expected_commitment_root": self.expected_commitment_root,
            "expected_nullifier_root": self.expected_nullifier_root,
            "expected_encrypted_payload_root": self.expected_encrypted_payload_root,
            "expected_receipt_root": self.expected_receipt_root,
            "expected_metadata_root": self.expected_metadata_root,
            "expected_output_root": self.expected_output_root,
        })
    }

    pub fn expectation_root(&self) -> String {
        record_root("expected_runtime_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedRuntimeRoots {
    pub observation_id: String,
    pub runtime_feed_root: String,
    pub observed_commitment_root: String,
    pub observed_nullifier_root: String,
    pub observed_encrypted_payload_root: String,
    pub observed_receipt_root: String,
    pub observed_metadata_root: String,
    pub observed_output_root: String,
}

impl ObservedRuntimeRoots {
    pub fn from_expected(config: &Config, expected: &ExpectedRuntimeRoots) -> Self {
        let observation_id = "devnet-private-note-runtime-output-observation-0001".to_string();
        let runtime_feed_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-RUNTIME-FEED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&observation_id),
                HashPart::Str(&expected.expectation_id),
                HashPart::U64(config.required_runtime_feeds),
                HashPart::Str("future_process_fed_outputs_quorum_stub"),
            ],
            32,
        );
        let observed_output_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-OBSERVED-OUTPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&observation_id),
                HashPart::Str(&runtime_feed_root),
                HashPart::Str(&expected.expected_commitment_root),
                HashPart::Str(&expected.expected_nullifier_root),
                HashPart::Str(&expected.expected_encrypted_payload_root),
                HashPart::Str(&expected.expected_receipt_root),
                HashPart::Str(&expected.expected_metadata_root),
            ],
            32,
        );

        Self {
            observation_id,
            runtime_feed_root,
            observed_commitment_root: expected.expected_commitment_root.clone(),
            observed_nullifier_root: expected.expected_nullifier_root.clone(),
            observed_encrypted_payload_root: expected.expected_encrypted_payload_root.clone(),
            observed_receipt_root: expected.expected_receipt_root.clone(),
            observed_metadata_root: expected.expected_metadata_root.clone(),
            observed_output_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "runtime_feed_root": self.runtime_feed_root,
            "observed_commitment_root": self.observed_commitment_root,
            "observed_nullifier_root": self.observed_nullifier_root,
            "observed_encrypted_payload_root": self.observed_encrypted_payload_root,
            "observed_receipt_root": self.observed_receipt_root,
            "observed_metadata_root": self.observed_metadata_root,
            "observed_output_root": self.observed_output_root,
        })
    }

    pub fn observation_root(&self) -> String {
        record_root("observed_runtime_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanEvidence {
    pub evidence_id: String,
    pub wallet_scan_root: String,
    pub view_tag_scan_root: String,
    pub recipient_match_root: String,
    pub plaintext_disclosure_root: String,
    pub metadata_budget_root: String,
    pub evidence_root: String,
}

impl WalletScanEvidence {
    pub fn devnet(config: &Config, expected: &ExpectedRuntimeRoots) -> Self {
        let evidence_id = "devnet-private-note-wallet-scan-evidence-0001".to_string();
        let wallet_scan_root = root_from_leaves(
            "WALLET-SCAN",
            &evidence_id,
            &[
                "wallet_scan_completed_against_encrypted_payload_root",
                "view_key_material_not_exported",
                "scan_result_bound_to_expected_output_root",
            ],
        );
        let view_tag_scan_root = root_from_leaves(
            "VIEW-TAG-SCAN",
            &evidence_id,
            &[
                "view_tag_match_count_redacted",
                "false_positive_window_committed",
                "subaddress_label_not_disclosed",
            ],
        );
        let recipient_match_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-RECIPIENT-MATCH",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&evidence_id),
                HashPart::Str(&expected.expected_encrypted_payload_root),
                HashPart::Str("recipient_membership_private_match_committed"),
            ],
            32,
        );
        let plaintext_disclosure_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-PLAINTEXT-DISCLOSURE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&evidence_id),
                HashPart::Str("no_amount_address_memo_or_route_plaintext"),
                HashPart::Str(PRIVACY_BOUNDARY),
            ],
            32,
        );
        let metadata_budget_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-METADATA-BUDGET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&evidence_id),
                HashPart::Str(&expected.expected_metadata_root),
                HashPart::U64(config.metadata_budget_units),
            ],
            32,
        );
        let evidence_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-WALLET-SCAN-EVIDENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&evidence_id),
                HashPart::Str(&wallet_scan_root),
                HashPart::Str(&view_tag_scan_root),
                HashPart::Str(&recipient_match_root),
                HashPart::Str(&plaintext_disclosure_root),
                HashPart::Str(&metadata_budget_root),
            ],
            32,
        );

        Self {
            evidence_id,
            wallet_scan_root,
            view_tag_scan_root,
            recipient_match_root,
            plaintext_disclosure_root,
            metadata_budget_root,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "wallet_scan_root": self.wallet_scan_root,
            "view_tag_scan_root": self.view_tag_scan_root,
            "recipient_match_root": self.recipient_match_root,
            "plaintext_disclosure_root": self.plaintext_disclosure_root,
            "metadata_budget_root": self.metadata_budget_root,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PrivacyLeakageClass {
    NoneObserved,
    PlaintextAmount,
    PlaintextAddress,
    PlaintextMemo,
    RouteLinkage,
    MetadataBudgetExceeded,
    UnknownRuntimeDisclosure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyLeakageRecord {
    pub leakage_id: String,
    pub class: PrivacyLeakageClass,
    pub affected_root: String,
    pub severity: String,
    pub fail_closed: bool,
    pub leakage_root: String,
}

impl PrivacyLeakageRecord {
    pub fn none(evidence: &WalletScanEvidence) -> Self {
        let leakage_id = "devnet-private-note-privacy-leakage-none-0001".to_string();
        let class = PrivacyLeakageClass::NoneObserved;
        let severity = "none".to_string();
        let leakage_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-PRIVACY-LEAKAGE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&leakage_id),
                HashPart::Str("none_observed"),
                HashPart::Str(&evidence.evidence_root),
                HashPart::Str(&severity),
            ],
            32,
        );

        Self {
            leakage_id,
            class,
            affected_root: evidence.evidence_root.clone(),
            severity,
            fail_closed: false,
            leakage_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "leakage_id": self.leakage_id,
            "class": self.class,
            "affected_root": self.affected_root,
            "severity": self.severity,
            "fail_closed": self.fail_closed,
            "leakage_root": self.leakage_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RuntimeMismatchClass {
    NoneObserved,
    CommitmentRoot,
    NullifierRoot,
    EncryptedPayloadRoot,
    ReceiptRoot,
    MetadataRoot,
    RuntimeFeedQuorum,
    UnknownRuntimeOutput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeMismatchRecord {
    pub mismatch_id: String,
    pub class: RuntimeMismatchClass,
    pub expected_root: String,
    pub observed_root: String,
    pub fail_closed: bool,
    pub mismatch_root: String,
}

impl RuntimeMismatchRecord {
    pub fn none(expected: &ExpectedRuntimeRoots, observed: &ObservedRuntimeRoots) -> Self {
        let mismatch_id = "devnet-private-note-runtime-mismatch-none-0001".to_string();
        let mismatch_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-MISMATCH",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&mismatch_id),
                HashPart::Str("none_observed"),
                HashPart::Str(&expected.expected_output_root),
                HashPart::Str(&observed.observed_output_root),
            ],
            32,
        );

        Self {
            mismatch_id,
            class: RuntimeMismatchClass::NoneObserved,
            expected_root: expected.expected_output_root.clone(),
            observed_root: observed.observed_output_root.clone(),
            fail_closed: false,
            mismatch_root,
        }
    }

    pub fn first_mismatch(
        expected: &ExpectedRuntimeRoots,
        observed: &ObservedRuntimeRoots,
    ) -> Option<Self> {
        let checks = [
            (
                RuntimeMismatchClass::CommitmentRoot,
                expected.expected_commitment_root.as_str(),
                observed.observed_commitment_root.as_str(),
            ),
            (
                RuntimeMismatchClass::NullifierRoot,
                expected.expected_nullifier_root.as_str(),
                observed.observed_nullifier_root.as_str(),
            ),
            (
                RuntimeMismatchClass::EncryptedPayloadRoot,
                expected.expected_encrypted_payload_root.as_str(),
                observed.observed_encrypted_payload_root.as_str(),
            ),
            (
                RuntimeMismatchClass::ReceiptRoot,
                expected.expected_receipt_root.as_str(),
                observed.observed_receipt_root.as_str(),
            ),
            (
                RuntimeMismatchClass::MetadataRoot,
                expected.expected_metadata_root.as_str(),
                observed.observed_metadata_root.as_str(),
            ),
        ];

        checks
            .iter()
            .find(|(_, expected_root, observed_root)| expected_root != observed_root)
            .map(|(class, expected_root, observed_root)| {
                let mismatch_id =
                    "runtime-output-reconciliation-first-mismatch".to_string();
                let mismatch_root = domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-MISMATCH",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(&mismatch_id),
                        HashPart::Str("fail_closed_runtime_root_mismatch"),
                        HashPart::Str(*expected_root),
                        HashPart::Str(*observed_root),
                    ],
                    32,
                );

                Self {
                    mismatch_id,
                    class: class.clone(),
                    expected_root: (*expected_root).to_string(),
                    observed_root: (*observed_root).to_string(),
                    fail_closed: true,
                    mismatch_root,
                }
            })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "class": self.class,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "fail_closed": self.fail_closed,
            "mismatch_root": self.mismatch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReconciliationStatus {
    Matched,
    Held,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconciliationVerdict {
    pub verdict_id: String,
    pub status: ReconciliationStatus,
    pub release_allowed: bool,
    pub fail_closed: bool,
    pub reason: String,
    pub matched_root: String,
    pub rejected_root: String,
    pub verdict_root: String,
}

impl ReconciliationVerdict {
    pub fn reconcile(
        config: &Config,
        expected: &ExpectedRuntimeRoots,
        observed: &ObservedRuntimeRoots,
        evidence: &WalletScanEvidence,
        leakage: &PrivacyLeakageRecord,
        mismatch: &RuntimeMismatchRecord,
    ) -> Result<Self> {
        if config.chain_id != CHAIN_ID {
            return Err("chain_id_mismatch".to_string());
        }
        if config.protocol_version != PROTOCOL_VERSION {
            return Err("protocol_version_mismatch".to_string());
        }
        if config.required_runtime_feeds == 0 {
            return Err("runtime_feed_quorum_required".to_string());
        }

        let roots_match = expected.expected_commitment_root == observed.observed_commitment_root
            && expected.expected_nullifier_root == observed.observed_nullifier_root
            && expected.expected_encrypted_payload_root == observed.observed_encrypted_payload_root
            && expected.expected_receipt_root == observed.observed_receipt_root
            && expected.expected_metadata_root == observed.observed_metadata_root;
        let private = leakage.class == PrivacyLeakageClass::NoneObserved && !leakage.fail_closed;
        let no_mismatch =
            mismatch.class == RuntimeMismatchClass::NoneObserved && !mismatch.fail_closed;
        let release_allowed =
            roots_match && private && no_mismatch && config.production_release_allowed;
        let status = if roots_match && private && no_mismatch {
            ReconciliationStatus::Matched
        } else {
            ReconciliationStatus::Held
        };
        let fail_closed = !roots_match || !private || !no_mismatch;
        let reason = if release_allowed {
            "runtime_outputs_reconciled_release_allowed".to_string()
        } else if roots_match && private && no_mismatch {
            "runtime_outputs_reconciled_devnet_release_hold".to_string()
        } else {
            "runtime_outputs_not_reconciled_release_held".to_string()
        };
        let verdict_id =
            "devnet-private-note-runtime-output-reconciliation-verdict-0001".to_string();
        let matched_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-MATCHED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&expected.expected_output_root),
                HashPart::Str(&observed.observed_output_root),
                HashPart::Str(&evidence.evidence_root),
                HashPart::Str(&leakage.leakage_root),
                HashPart::Str(&mismatch.mismatch_root),
                HashPart::Str(&reason),
            ],
            32,
        );
        let rejected_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-REJECTED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&verdict_id),
                HashPart::Str(&reason),
                HashPart::Str(&leakage.leakage_root),
                HashPart::Str(&mismatch.mismatch_root),
                HashPart::Str(if fail_closed {
                    "fail_closed"
                } else {
                    "release_policy_hold"
                }),
            ],
            32,
        );
        let verdict_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-VERDICT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&verdict_id),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&status_label(&status)),
                HashPart::Str(&matched_root),
                HashPart::Str(&rejected_root),
                HashPart::Str(&reason),
            ],
            32,
        );

        Ok(Self {
            verdict_id,
            status,
            release_allowed,
            fail_closed,
            reason,
            matched_root,
            rejected_root,
            verdict_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "status": self.status,
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
            "reason": self.reason,
            "matched_root": self.matched_root,
            "rejected_root": self.rejected_root,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub active: bool,
    pub hold_reason: String,
    pub release_policy: String,
    pub hold_root: String,
}

impl ReleaseHold {
    pub fn from_verdict(verdict: &ReconciliationVerdict) -> Self {
        let hold_id = "devnet-private-note-runtime-output-release-hold-0001".to_string();
        let active = !verdict.release_allowed;
        let hold_reason = if active {
            verdict.reason.clone()
        } else {
            "release_allowed".to_string()
        };
        let release_policy = if verdict.release_allowed {
            "process_fed_runtime_outputs_reconciled".to_string()
        } else {
            "hold_until_process_fed_runtime_outputs_and_privacy_evidence_match".to_string()
        };
        let hold_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-RELEASE-HOLD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&hold_id),
                HashPart::Str(&verdict.verdict_root),
                HashPart::Str(&hold_reason),
                HashPart::Str(&release_policy),
                HashPart::Str(if active { "active" } else { "inactive" }),
            ],
            32,
        );

        Self {
            hold_id,
            active,
            hold_reason,
            release_policy,
            hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "active": self.active,
            "hold_reason": self.hold_reason,
            "release_policy": self.release_policy,
            "hold_root": self.hold_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub expected: ExpectedRuntimeRoots,
    pub observed: ObservedRuntimeRoots,
    pub wallet_scan_evidence: WalletScanEvidence,
    pub privacy_leakage: PrivacyLeakageRecord,
    pub runtime_mismatch: RuntimeMismatchRecord,
    pub verdict: ReconciliationVerdict,
    pub release_hold: ReleaseHold,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        match Self::try_devnet() {
            Ok(state) => state,
            Err(_) => Self::held_devnet(),
        }
    }

    pub fn try_devnet() -> Result<Self> {
        let config = Config::devnet();
        let expected = ExpectedRuntimeRoots::devnet(&config);
        let observed = ObservedRuntimeRoots::from_expected(&config, &expected);
        let wallet_scan_evidence = WalletScanEvidence::devnet(&config, &expected);
        let privacy_leakage = PrivacyLeakageRecord::none(&wallet_scan_evidence);
        let runtime_mismatch = match RuntimeMismatchRecord::first_mismatch(&expected, &observed) {
            Some(mismatch) => mismatch,
            None => RuntimeMismatchRecord::none(&expected, &observed),
        };
        let verdict = ReconciliationVerdict::reconcile(
            &config,
            &expected,
            &observed,
            &wallet_scan_evidence,
            &privacy_leakage,
            &runtime_mismatch,
        )?;
        let release_hold = ReleaseHold::from_verdict(&verdict);
        Ok(Self::from_parts(
            config,
            expected,
            observed,
            wallet_scan_evidence,
            privacy_leakage,
            runtime_mismatch,
            verdict,
            release_hold,
        ))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "expected": self.expected.public_record(),
            "observed": self.observed.public_record(),
            "wallet_scan_evidence": self.wallet_scan_evidence.public_record(),
            "privacy_leakage": self.privacy_leakage.public_record(),
            "runtime_mismatch": self.runtime_mismatch.public_record(),
            "verdict": self.verdict.public_record(),
            "release_hold": self.release_hold.public_record(),
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    fn from_parts(
        config: Config,
        expected: ExpectedRuntimeRoots,
        observed: ObservedRuntimeRoots,
        wallet_scan_evidence: WalletScanEvidence,
        privacy_leakage: PrivacyLeakageRecord,
        runtime_mismatch: RuntimeMismatchRecord,
        verdict: ReconciliationVerdict,
        release_hold: ReleaseHold,
    ) -> Self {
        let public_record_root = record_root(
            "public_record",
            &json!({
                "config": config.public_record(),
                "expected": expected.public_record(),
                "observed": observed.public_record(),
                "wallet_scan_evidence": wallet_scan_evidence.public_record(),
                "privacy_leakage": privacy_leakage.public_record(),
                "runtime_mismatch": runtime_mismatch.public_record(),
                "verdict": verdict.public_record(),
                "release_hold": release_hold.public_record(),
            }),
        );
        let state_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.state_root()),
                HashPart::Str(&expected.expectation_root()),
                HashPart::Str(&observed.observation_root()),
                HashPart::Str(&wallet_scan_evidence.evidence_root),
                HashPart::Str(&privacy_leakage.leakage_root),
                HashPart::Str(&runtime_mismatch.mismatch_root),
                HashPart::Str(&verdict.verdict_root),
                HashPart::Str(&release_hold.hold_root),
                HashPart::Str(&public_record_root),
            ],
            32,
        );

        Self {
            config,
            expected,
            observed,
            wallet_scan_evidence,
            privacy_leakage,
            runtime_mismatch,
            verdict,
            release_hold,
            public_record_root,
            state_root,
        }
    }

    fn held_devnet() -> Self {
        let config = Config::devnet();
        let expected = ExpectedRuntimeRoots::devnet(&config);
        let observed = ObservedRuntimeRoots::from_expected(&config, &expected);
        let wallet_scan_evidence = WalletScanEvidence::devnet(&config, &expected);
        let privacy_leakage = PrivacyLeakageRecord::none(&wallet_scan_evidence);
        let runtime_mismatch = RuntimeMismatchRecord {
            mismatch_id: "devnet-private-note-runtime-mismatch-fail-closed-0001".to_string(),
            class: RuntimeMismatchClass::UnknownRuntimeOutput,
            expected_root: expected.expected_output_root.clone(),
            observed_root: observed.observed_output_root.clone(),
            fail_closed: true,
            mismatch_root: domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-MISMATCH",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str("devnet-private-note-runtime-mismatch-fail-closed-0001"),
                    HashPart::Str("fallback_hold"),
                    HashPart::Str(&expected.expected_output_root),
                    HashPart::Str(&observed.observed_output_root),
                ],
                32,
            ),
        };
        let verdict = ReconciliationVerdict {
            verdict_id: "devnet-private-note-runtime-output-reconciliation-verdict-held-0001"
                .to_string(),
            status: ReconciliationStatus::Held,
            release_allowed: false,
            fail_closed: true,
            reason: "runtime_outputs_not_reconciled_release_held".to_string(),
            matched_root: domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-MATCHED",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(&expected.expected_output_root),
                    HashPart::Str(&observed.observed_output_root),
                    HashPart::Str("fallback_no_match"),
                ],
                32,
            ),
            rejected_root: domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-REJECTED",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str("devnet-private-note-runtime-output-reconciliation-verdict-held-0001"),
                    HashPart::Str("runtime_outputs_not_reconciled_release_held"),
                    HashPart::Str(&runtime_mismatch.mismatch_root),
                ],
                32,
            ),
            verdict_root: domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-VERDICT",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str("devnet-private-note-runtime-output-reconciliation-verdict-held-0001"),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str("held"),
                    HashPart::Str(&runtime_mismatch.mismatch_root),
                ],
                32,
            ),
        };
        let release_hold = ReleaseHold::from_verdict(&verdict);

        Self::from_parts(
            config,
            expected,
            observed,
            wallet_scan_evidence,
            privacy_leakage,
            runtime_mismatch,
            verdict,
            release_hold,
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

fn root_from_leaves(label: &str, root_id: &str, leaves: &[&str]) -> String {
    let leaf_roots = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-LEAF",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(label),
                    HashPart::Str(root_id),
                    HashPart::U64(index as u64),
                    HashPart::Str(leaf),
                ],
                32,
            )
        })
        .map(Value::String)
        .collect::<Vec<_>>();

    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-MERKLE-ROOT",
        leaf_roots.as_slice(),
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-RUNTIME-OUTPUT-RECONCILIATION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn status_label(status: &ReconciliationStatus) -> String {
    match status {
        ReconciliationStatus::Matched => "matched".to_string(),
        ReconciliationStatus::Held => "held".to_string(),
        ReconciliationStatus::Rejected => "rejected".to_string(),
    }
}
