use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSettlementReceiptRuntimeOutputReconciliationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-settlement-receipt-runtime-output-reconciliation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SETTLEMENT_RECEIPT_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECONCILIATION_SUITE: &str =
    "handler-bound-settlement-receipt-runtime-output-reconciliation-v1";
pub const DEFAULT_MIN_OPERATOR_EVIDENCE: u64 = 3;
pub const DEFAULT_MAX_RUNTIME_LAG_BLOCKS: u64 = 12;
pub const DEFAULT_REQUIRED_WALLET_FIELDS: u64 = 6;

const DOMAIN: &str =
    "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-SETTLEMENT-RECEIPT-RUNTIME-OUTPUT-RECONCILIATION-RUNTIME";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub reconciliation_suite: String,
    pub min_operator_evidence: u64,
    pub max_runtime_lag_blocks: u64,
    pub required_wallet_fields: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            reconciliation_suite: RECONCILIATION_SUITE.to_string(),
            min_operator_evidence: DEFAULT_MIN_OPERATOR_EVIDENCE,
            max_runtime_lag_blocks: DEFAULT_MAX_RUNTIME_LAG_BLOCKS,
            required_wallet_fields: DEFAULT_REQUIRED_WALLET_FIELDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "reconciliation_suite": self.reconciliation_suite,
            "min_operator_evidence": self.min_operator_evidence,
            "max_runtime_lag_blocks": self.max_runtime_lag_blocks,
            "required_wallet_fields": self.required_wallet_fields,
        })
    }

    pub fn root(&self) -> String {
        record_hash("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpectedReceiptRoots {
    pub handler_execution_root: String,
    pub handler_receipt_root: String,
    pub settlement_receipt_root: String,
    pub release_receipt_root: String,
    pub wallet_receipt_root: String,
    pub expected_output_root: String,
}

impl ExpectedReceiptRoots {
    pub fn devnet() -> Self {
        let handler_execution_root =
            short_hash("HANDLER-EXECUTION", "devnet-handler-bound-execution-record");
        let settlement_receipt_root =
            short_hash("EXPECTED-SETTLEMENT-RECEIPT", &handler_execution_root);
        let release_receipt_root = short_hash("EXPECTED-RELEASE-RECEIPT", &settlement_receipt_root);
        let wallet_receipt_root = short_hash("EXPECTED-WALLET-RECEIPT", &release_receipt_root);
        let handler_receipt_root = short_hash("EXPECTED-HANDLER-RECEIPT", &handler_execution_root);
        let expected_output_root = leaf_root(
            "EXPECTED-RUNTIME-OUTPUT",
            &[
                handler_execution_root.as_str(),
                handler_receipt_root.as_str(),
                settlement_receipt_root.as_str(),
                release_receipt_root.as_str(),
                wallet_receipt_root.as_str(),
            ],
        );

        Self {
            handler_execution_root,
            handler_receipt_root,
            settlement_receipt_root,
            release_receipt_root,
            wallet_receipt_root,
            expected_output_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handler_execution_root": self.handler_execution_root,
            "handler_receipt_root": self.handler_receipt_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "release_receipt_root": self.release_receipt_root,
            "wallet_receipt_root": self.wallet_receipt_root,
            "expected_output_root": self.expected_output_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("EXPECTED-RECEIPT-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedRuntimeReceiptRoots {
    pub process_id: String,
    pub process_output_root: String,
    pub observed_handler_receipt_root: String,
    pub observed_settlement_receipt_root: String,
    pub observed_release_receipt_root: String,
    pub observed_wallet_receipt_root: String,
    pub observed_at_l2_height: u64,
    pub expected_at_l2_height: u64,
}

impl ObservedRuntimeReceiptRoots {
    pub fn devnet(expected: &ExpectedReceiptRoots) -> Self {
        Self {
            process_id: short_hash("PROCESS-ID", &expected.expected_output_root),
            process_output_root: expected.expected_output_root.clone(),
            observed_handler_receipt_root: expected.handler_receipt_root.clone(),
            observed_settlement_receipt_root: expected.settlement_receipt_root.clone(),
            observed_release_receipt_root: expected.release_receipt_root.clone(),
            observed_wallet_receipt_root: expected.wallet_receipt_root.clone(),
            expected_at_l2_height: 4_260_780,
            observed_at_l2_height: 4_260_786,
        }
    }

    pub fn runtime_lag_blocks(&self) -> u64 {
        self.observed_at_l2_height
            .saturating_sub(self.expected_at_l2_height)
    }

    pub fn within_lag(&self, config: &Config) -> bool {
        self.observed_at_l2_height >= self.expected_at_l2_height
            && self.runtime_lag_blocks() <= config.max_runtime_lag_blocks
    }

    pub fn roots_match(&self, expected: &ExpectedReceiptRoots) -> bool {
        self.process_output_root == expected.expected_output_root
            && self.observed_handler_receipt_root == expected.handler_receipt_root
            && self.observed_settlement_receipt_root == expected.settlement_receipt_root
            && self.observed_release_receipt_root == expected.release_receipt_root
            && self.observed_wallet_receipt_root == expected.wallet_receipt_root
    }

    pub fn public_record(&self, config: &Config, expected: &ExpectedReceiptRoots) -> Value {
        json!({
            "process_id": self.process_id,
            "process_output_root": self.process_output_root,
            "observed_handler_receipt_root": self.observed_handler_receipt_root,
            "observed_settlement_receipt_root": self.observed_settlement_receipt_root,
            "observed_release_receipt_root": self.observed_release_receipt_root,
            "observed_wallet_receipt_root": self.observed_wallet_receipt_root,
            "expected_at_l2_height": self.expected_at_l2_height,
            "observed_at_l2_height": self.observed_at_l2_height,
            "runtime_lag_blocks": self.runtime_lag_blocks(),
            "within_lag": self.within_lag(config),
            "roots_match": self.roots_match(expected),
        })
    }

    pub fn root(&self, config: &Config, expected: &ExpectedReceiptRoots) -> String {
        record_hash(
            "OBSERVED-RUNTIME-RECEIPT-ROOTS",
            &self.public_record(config, expected),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorEvidence {
    pub evidence_set_root: String,
    pub operator_quorum_root: String,
    pub signed_output_root: String,
    pub evidence_count: u64,
    pub conflicting_evidence_count: u64,
}

impl OperatorEvidence {
    pub fn devnet(observed: &ObservedRuntimeReceiptRoots) -> Self {
        Self {
            evidence_set_root: leaf_root(
                "OPERATOR-EVIDENCE-SET",
                &[
                    observed.process_id.as_str(),
                    observed.process_output_root.as_str(),
                    observed.observed_settlement_receipt_root.as_str(),
                ],
            ),
            operator_quorum_root: short_hash("OPERATOR-QUORUM", &observed.process_id),
            signed_output_root: short_hash("SIGNED-RUNTIME-OUTPUT", &observed.process_output_root),
            evidence_count: DEFAULT_MIN_OPERATOR_EVIDENCE,
            conflicting_evidence_count: 0,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.evidence_count >= config.min_operator_evidence && self.conflicting_evidence_count == 0
    }

    pub fn public_record(&self, config: &Config) -> Value {
        json!({
            "evidence_set_root": self.evidence_set_root,
            "operator_quorum_root": self.operator_quorum_root,
            "signed_output_root": self.signed_output_root,
            "evidence_count": self.evidence_count,
            "min_operator_evidence": config.min_operator_evidence,
            "conflicting_evidence_count": self.conflicting_evidence_count,
            "accepted": self.accepted(config),
        })
    }

    pub fn root(&self, config: &Config) -> String {
        record_hash("OPERATOR-EVIDENCE", &self.public_record(config))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletVisibleReceiptFields {
    pub wallet_view_root: String,
    pub claim_id_commitment: String,
    pub release_nullifier: String,
    pub settlement_tx_commitment: String,
    pub fee_commitment: String,
    pub recipient_address_commitment: String,
    pub fields_present: u64,
}

impl WalletVisibleReceiptFields {
    pub fn devnet(expected: &ExpectedReceiptRoots) -> Self {
        Self {
            wallet_view_root: expected.wallet_receipt_root.clone(),
            claim_id_commitment: short_hash("WALLET-CLAIM-ID", &expected.wallet_receipt_root),
            release_nullifier: short_hash(
                "WALLET-RELEASE-NULLIFIER",
                &expected.release_receipt_root,
            ),
            settlement_tx_commitment: short_hash(
                "WALLET-SETTLEMENT-TX",
                &expected.settlement_receipt_root,
            ),
            fee_commitment: short_hash("WALLET-FEE", &expected.settlement_receipt_root),
            recipient_address_commitment: short_hash(
                "WALLET-RECIPIENT-ADDRESS",
                &expected.wallet_receipt_root,
            ),
            fields_present: DEFAULT_REQUIRED_WALLET_FIELDS,
        }
    }

    pub fn complete(&self, config: &Config, expected: &ExpectedReceiptRoots) -> bool {
        self.wallet_view_root == expected.wallet_receipt_root
            && self.fields_present >= config.required_wallet_fields
            && self.claim_id_commitment != self.release_nullifier
            && self.settlement_tx_commitment != self.recipient_address_commitment
    }

    pub fn public_record(&self, config: &Config, expected: &ExpectedReceiptRoots) -> Value {
        json!({
            "wallet_view_root": self.wallet_view_root,
            "claim_id_commitment": self.claim_id_commitment,
            "release_nullifier": self.release_nullifier,
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "fee_commitment": self.fee_commitment,
            "recipient_address_commitment": self.recipient_address_commitment,
            "fields_present": self.fields_present,
            "required_wallet_fields": config.required_wallet_fields,
            "complete": self.complete(config, expected),
        })
    }

    pub fn root(&self, config: &Config, expected: &ExpectedReceiptRoots) -> String {
        record_hash(
            "WALLET-VISIBLE-RECEIPT-FIELDS",
            &self.public_record(config, expected),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MismatchClassification {
    None,
    MissingRuntimeOutput,
    HandlerReceiptRootMismatch,
    SettlementReceiptRootMismatch,
    ReleaseReceiptRootMismatch,
    WalletReceiptRootMismatch,
    RuntimeLagExceeded,
    OperatorEvidenceRejected,
    WalletFieldsIncomplete,
}

impl MismatchClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MissingRuntimeOutput => "missing_runtime_output",
            Self::HandlerReceiptRootMismatch => "handler_receipt_root_mismatch",
            Self::SettlementReceiptRootMismatch => "settlement_receipt_root_mismatch",
            Self::ReleaseReceiptRootMismatch => "release_receipt_root_mismatch",
            Self::WalletReceiptRootMismatch => "wallet_receipt_root_mismatch",
            Self::RuntimeLagExceeded => "runtime_lag_exceeded",
            Self::OperatorEvidenceRejected => "operator_evidence_rejected",
            Self::WalletFieldsIncomplete => "wallet_fields_incomplete",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReconciliationStatus {
    Accepted,
    Held,
    Rejected,
}

impl ReconciliationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconciliationVerdict {
    pub status: ReconciliationStatus,
    pub mismatch: MismatchClassification,
    pub release_allowed: bool,
    pub expected_observed_match: bool,
    pub operator_evidence_accepted: bool,
    pub wallet_fields_complete: bool,
    pub runtime_lag_acceptable: bool,
    pub verdict_root: String,
}

impl ReconciliationVerdict {
    pub fn evaluate(
        config: &Config,
        expected: &ExpectedReceiptRoots,
        observed: &ObservedRuntimeReceiptRoots,
        operator_evidence: &OperatorEvidence,
        wallet_fields: &WalletVisibleReceiptFields,
    ) -> Self {
        let operator_evidence_accepted = operator_evidence.accepted(config);
        let wallet_fields_complete = wallet_fields.complete(config, expected);
        let runtime_lag_acceptable = observed.within_lag(config);
        let expected_observed_match = observed.roots_match(expected);
        let mismatch = classify_mismatch(
            expected,
            observed,
            operator_evidence_accepted,
            wallet_fields_complete,
            runtime_lag_acceptable,
        );
        let release_allowed = mismatch == MismatchClassification::None;
        let status = if release_allowed {
            ReconciliationStatus::Accepted
        } else if expected_observed_match && operator_evidence_accepted {
            ReconciliationStatus::Held
        } else {
            ReconciliationStatus::Rejected
        };
        let verdict_root = verdict_digest(
            status.as_str(),
            mismatch.as_str(),
            release_allowed,
            expected_observed_match,
            operator_evidence_accepted,
            wallet_fields_complete,
            runtime_lag_acceptable,
        );

        Self {
            status,
            mismatch,
            release_allowed,
            expected_observed_match,
            operator_evidence_accepted,
            wallet_fields_complete,
            runtime_lag_acceptable,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "mismatch": self.mismatch.as_str(),
            "release_allowed": self.release_allowed,
            "expected_observed_match": self.expected_observed_match,
            "operator_evidence_accepted": self.operator_evidence_accepted,
            "wallet_fields_complete": self.wallet_fields_complete,
            "runtime_lag_acceptable": self.runtime_lag_acceptable,
            "verdict_root": self.verdict_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("RECONCILIATION-VERDICT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_required: bool,
    pub hold_reason: String,
    pub hold_root: String,
}

impl ReleaseHold {
    pub fn from_verdict(verdict: &ReconciliationVerdict) -> Self {
        let hold_required = !verdict.release_allowed;
        let hold_reason = if hold_required {
            verdict.mismatch.as_str()
        } else {
            "release_allowed"
        }
        .to_string();
        let hold_root = domain_hash(
            &format!("{DOMAIN}:RELEASE-HOLD-DIGEST"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(bool_label(hold_required)),
                HashPart::Str(&hold_reason),
                HashPart::Str(verdict.verdict_root.as_str()),
            ],
            32,
        );

        Self {
            hold_required,
            hold_reason,
            hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_required": self.hold_required,
            "hold_reason": self.hold_reason,
            "hold_root": self.hold_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("RELEASE-HOLD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub expected_receipt_roots: ExpectedReceiptRoots,
    pub observed_runtime_receipt_roots: ObservedRuntimeReceiptRoots,
    pub operator_evidence: OperatorEvidence,
    pub wallet_visible_receipt_fields: WalletVisibleReceiptFields,
    pub reconciliation_verdict: ReconciliationVerdict,
    pub release_hold: ReleaseHold,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let expected_receipt_roots = ExpectedReceiptRoots::devnet();
        let observed_runtime_receipt_roots =
            ObservedRuntimeReceiptRoots::devnet(&expected_receipt_roots);
        let operator_evidence = OperatorEvidence::devnet(&observed_runtime_receipt_roots);
        let wallet_visible_receipt_fields =
            WalletVisibleReceiptFields::devnet(&expected_receipt_roots);
        let reconciliation_verdict = ReconciliationVerdict::evaluate(
            &config,
            &expected_receipt_roots,
            &observed_runtime_receipt_roots,
            &operator_evidence,
            &wallet_visible_receipt_fields,
        );
        let release_hold = ReleaseHold::from_verdict(&reconciliation_verdict);

        Self {
            config,
            expected_receipt_roots,
            observed_runtime_receipt_roots,
            operator_evidence,
            wallet_visible_receipt_fields,
            reconciliation_verdict,
            release_hold,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_runtime_output_reconciliation_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "expected_receipt_roots": self.expected_receipt_roots.public_record(),
            "observed_runtime_receipt_roots": self.observed_runtime_receipt_roots.public_record(&self.config, &self.expected_receipt_roots),
            "operator_evidence": self.operator_evidence.public_record(&self.config),
            "wallet_visible_receipt_fields": self.wallet_visible_receipt_fields.public_record(&self.config, &self.expected_receipt_roots),
            "reconciliation_verdict": self.reconciliation_verdict.public_record(),
            "release_hold": self.release_hold.public_record(),
            "component_roots": self.component_roots(),
            "state_root": self.state_root(),
        })
    }

    pub fn component_roots(&self) -> Value {
        json!({
            "config_root": self.config.root(),
            "expected_receipt_roots_root": self.expected_receipt_roots.root(),
            "observed_runtime_receipt_roots_root": self.observed_runtime_receipt_roots.root(&self.config, &self.expected_receipt_roots),
            "operator_evidence_root": self.operator_evidence.root(&self.config),
            "wallet_visible_receipt_fields_root": self.wallet_visible_receipt_fields.root(&self.config, &self.expected_receipt_roots),
            "reconciliation_verdict_root": self.reconciliation_verdict.root(),
            "release_hold_root": self.release_hold.root(),
        })
    }

    pub fn state_root(&self) -> String {
        let component_roots = self.component_roots();
        domain_hash(
            &format!("{DOMAIN}:STATE-ROOT"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&component_roots),
            ],
            32,
        )
    }

    pub fn root(&self) -> String {
        self.state_root()
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

fn classify_mismatch(
    expected: &ExpectedReceiptRoots,
    observed: &ObservedRuntimeReceiptRoots,
    operator_evidence_accepted: bool,
    wallet_fields_complete: bool,
    runtime_lag_acceptable: bool,
) -> MismatchClassification {
    if observed.process_output_root.is_empty() {
        MismatchClassification::MissingRuntimeOutput
    } else if observed.observed_handler_receipt_root != expected.handler_receipt_root {
        MismatchClassification::HandlerReceiptRootMismatch
    } else if observed.observed_settlement_receipt_root != expected.settlement_receipt_root {
        MismatchClassification::SettlementReceiptRootMismatch
    } else if observed.observed_release_receipt_root != expected.release_receipt_root {
        MismatchClassification::ReleaseReceiptRootMismatch
    } else if observed.observed_wallet_receipt_root != expected.wallet_receipt_root {
        MismatchClassification::WalletReceiptRootMismatch
    } else if observed.process_output_root != expected.expected_output_root {
        MismatchClassification::MissingRuntimeOutput
    } else if !runtime_lag_acceptable {
        MismatchClassification::RuntimeLagExceeded
    } else if !operator_evidence_accepted {
        MismatchClassification::OperatorEvidenceRejected
    } else if !wallet_fields_complete {
        MismatchClassification::WalletFieldsIncomplete
    } else {
        MismatchClassification::None
    }
}

fn record_hash(label: &str, record: &Value) -> String {
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

fn short_hash(label: &str, value: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn leaf_root(label: &str, leaves: &[&str]) -> String {
    let records = leaves
        .iter()
        .map(|leaf| {
            json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "leaf": leaf,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &records)
}

fn verdict_digest(
    status: &str,
    mismatch: &str,
    release_allowed: bool,
    expected_observed_match: bool,
    operator_evidence_accepted: bool,
    wallet_fields_complete: bool,
    runtime_lag_acceptable: bool,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:VERDICT-DIGEST"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(status),
            HashPart::Str(mismatch),
            HashPart::Str(bool_label(release_allowed)),
            HashPart::Str(bool_label(expected_observed_match)),
            HashPart::Str(bool_label(operator_evidence_accepted)),
            HashPart::Str(bool_label(wallet_fields_complete)),
            HashPart::Str(bool_label(runtime_lag_acceptable)),
        ],
        32,
    )
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
