use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWithdrawalClaimGateInvocationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-withdrawal-claim-gate-invocation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const INVOCATION_SUITE: &str =
    "canonical-vertical-slice-wallet-owned-withdrawal-claim-gate-invocation-v1";
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_FEE_CAP_ATOMIC: u128 = 35_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub invocation_suite: String,
    pub challenge_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub fee_cap_atomic: u128,
    pub wallet_owned_claim_required: bool,
    pub operator_independent_submission_required: bool,
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
            invocation_suite: INVOCATION_SUITE.to_string(),
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            fee_cap_atomic: DEFAULT_FEE_CAP_ATOMIC,
            wallet_owned_claim_required: true,
            operator_independent_submission_required: true,
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
            "invocation_suite": self.invocation_suite,
            "challenge_window_blocks": self.challenge_window_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "fee_cap_atomic": self.fee_cap_atomic.to_string(),
            "wallet_owned_claim_required": self.wallet_owned_claim_required,
            "operator_independent_submission_required": self.operator_independent_submission_required,
            "fail_closed_required": self.fail_closed_required,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "withdrawal-claim-gate-invocation-config",
            &self.public_record(),
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationRecord {
    pub record_id: String,
    pub label: String,
    pub root: String,
    pub required: bool,
    pub satisfied: bool,
    pub fail_closed: bool,
    pub note: String,
}

impl InvocationRecord {
    pub fn new(
        label: impl Into<String>,
        root: impl Into<String>,
        required: bool,
        satisfied: bool,
        fail_closed: bool,
        note: impl Into<String>,
    ) -> Self {
        let label = label.into();
        let root = root.into();
        let note = note.into();
        let record_id = domain_hash(
            "WITHDRAWAL-CLAIM-GATE-INVOCATION-RECORD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&label),
                HashPart::Str(&root),
                HashPart::Str(if required { "required" } else { "optional" }),
                HashPart::Str(if satisfied {
                    "satisfied"
                } else {
                    "unsatisfied"
                }),
                HashPart::Str(if fail_closed {
                    "fail_closed"
                } else {
                    "non_fail_closed"
                }),
            ],
            32,
        );

        Self {
            record_id,
            label,
            root,
            required,
            satisfied,
            fail_closed,
            note,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "label": self.label,
            "root": self.root,
            "required": self.required,
            "satisfied": self.satisfied,
            "fail_closed": self.fail_closed,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "withdrawal-claim-gate-invocation-record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationRoots {
    pub wallet_claim_payload_root: String,
    pub note_nullifier_proof_root: String,
    pub settlement_receipt_root: String,
    pub challenge_window_root: String,
    pub pq_withdrawal_authorization_root: String,
    pub reserve_coverage_root: String,
    pub fee_cap_root: String,
    pub operator_independent_submission_root: String,
    pub expected_output_root: String,
    pub fail_closed_roots: Vec<String>,
}

impl InvocationRoots {
    pub fn devnet(config: &Config) -> Self {
        let claim_id = short_hash(
            "WITHDRAWAL-CLAIM-ID",
            "devnet-wallet-owned-claim-invocation",
        );
        let wallet_claim_payload_root = record_root(
            "withdrawal-claim-wallet-payload",
            &json!({
                "claim_id": claim_id,
                "account_commitment": short_hash("ACCOUNT-COMMITMENT", &claim_id),
                "withdrawal_address_commitment": short_hash("WITHDRAWAL-ADDRESS-COMMITMENT", &claim_id),
                "amount_atomic": "12500000000",
                "asset_id": "xmr",
                "forced_exit": true,
                "wallet_owned": true,
            }),
        );
        let note_nullifier_proof_root = record_root(
            "withdrawal-claim-note-nullifier-proof",
            &json!({
                "note_commitment_root": leaf_root("WITHDRAWAL-NOTE-COMMITMENTS", &[&claim_id, "bridge-lock-note", "claim-change-note"]),
                "nullifier_root": leaf_root("WITHDRAWAL-NULLIFIERS", &["spent-prior-nullifier", "claim-nullifier"]),
                "inclusion_proof_root": short_hash("WITHDRAWAL-NOTE-INCLUSION-PROOF", &claim_id),
                "non_membership_proof_root": short_hash("WITHDRAWAL-NULLIFIER-NON-MEMBERSHIP-PROOF", &claim_id),
                "privacy_set_size": config.min_privacy_set_size,
            }),
        );
        let settlement_receipt_root = record_root(
            "withdrawal-claim-settlement-receipt",
            &json!({
                "public_receipt_root": short_hash("WITHDRAWAL-PUBLIC-RECEIPT", &claim_id),
                "encrypted_receipt_root": short_hash("WITHDRAWAL-ENCRYPTED-RECEIPT", &claim_id),
                "reserve_debit_receipt_root": short_hash("WITHDRAWAL-RESERVE-DEBIT-RECEIPT", &claim_id),
                "execution_receipt_root": short_hash("WITHDRAWAL-EXECUTION-RECEIPT", &claim_id),
            }),
        );
        let challenge_window_root = record_root(
            "withdrawal-claim-challenge-window",
            &json!({
                "opened_at_l2_height": 4260000_u64,
                "closes_at_l2_height": 4260000_u64 + config.challenge_window_blocks,
                "release_after_l2_height": 4260000_u64 + config.challenge_window_blocks + config.release_delay_blocks,
                "current_l2_height": 4260000_u64 + config.challenge_window_blocks + config.release_delay_blocks + 12,
                "unresolved_challenges": 0_u64,
            }),
        );
        let pq_withdrawal_authorization_root = record_root(
            "withdrawal-claim-pq-authorization",
            &json!({
                "wallet_pq_public_key_root": short_hash("WALLET-PQ-PUBLIC-KEY", &claim_id),
                "authorization_transcript_root": short_hash("WITHDRAWAL-PQ-AUTHORIZATION-TRANSCRIPT", &claim_id),
                "signature_bundle_root": short_hash("WITHDRAWAL-PQ-SIGNATURE-BUNDLE", &claim_id),
                "min_security_bits": config.min_pq_security_bits,
                "wallet_authorized": true,
            }),
        );
        let reserve_coverage_root = record_root(
            "withdrawal-claim-reserve-coverage",
            &json!({
                "reserve_snapshot_root": short_hash("WITHDRAWAL-RESERVE-SNAPSHOT", &claim_id),
                "claim_liability_root": short_hash("WITHDRAWAL-CLAIM-LIABILITY", &claim_id),
                "coverage_bps": config.min_reserve_coverage_bps,
                "coverage_floor_bps": config.min_reserve_coverage_bps,
                "covered": true,
            }),
        );
        let fee_cap_root = record_root(
            "withdrawal-claim-fee-cap",
            &json!({
                "fee_quote_root": short_hash("WITHDRAWAL-FEE-QUOTE", &claim_id),
                "quoted_fee_atomic": config.fee_cap_atomic.to_string(),
                "fee_cap_atomic": config.fee_cap_atomic.to_string(),
                "within_cap": true,
            }),
        );
        let operator_independent_submission_root = record_root(
            "withdrawal-claim-operator-independent-submission",
            &json!({
                "submission_channel_root": short_hash("WITHDRAWAL-CLAIM-SUBMISSION-CHANNEL", &claim_id),
                "wallet_replay_bundle_root": short_hash("WITHDRAWAL-WALLET-REPLAY-BUNDLE", &claim_id),
                "operator_signature_required": false,
                "wallet_can_submit_directly": true,
            }),
        );
        let expected_output_root = record_root(
            "withdrawal-claim-expected-output",
            &json!({
                "claim_id": claim_id,
                "settlement_action": "release_withdrawal_to_wallet_owned_address",
                "receipt_required": true,
                "state_transition_expected": true,
                "fail_closed_on_ambiguity": true,
            }),
        );
        let fail_closed_roots = vec![
            fail_closed_root("missing_wallet_claim_payload", &claim_id),
            fail_closed_root("invalid_note_or_nullifier_proof", &claim_id),
            fail_closed_root("unelapsed_or_contested_challenge_window", &claim_id),
            fail_closed_root("missing_pq_withdrawal_authorization", &claim_id),
            fail_closed_root("reserve_coverage_below_floor", &claim_id),
            fail_closed_root("fee_above_cap", &claim_id),
            fail_closed_root("operator_dependent_submission_only", &claim_id),
            fail_closed_root("ambiguous_expected_output", &claim_id),
        ];

        Self {
            wallet_claim_payload_root,
            note_nullifier_proof_root,
            settlement_receipt_root,
            challenge_window_root,
            pq_withdrawal_authorization_root,
            reserve_coverage_root,
            fee_cap_root,
            operator_independent_submission_root,
            expected_output_root,
            fail_closed_roots,
        }
    }

    pub fn records(&self) -> Vec<InvocationRecord> {
        let mut records = vec![
            InvocationRecord::new(
                "wallet_claim_payload_root",
                &self.wallet_claim_payload_root,
                true,
                true,
                true,
                "wallet-owned withdrawal claim payload is bound before gate invocation",
            ),
            InvocationRecord::new(
                "note_nullifier_proof_root",
                &self.note_nullifier_proof_root,
                true,
                true,
                true,
                "note inclusion and nullifier non-membership proofs are bound",
            ),
            InvocationRecord::new(
                "settlement_receipt_root",
                &self.settlement_receipt_root,
                true,
                true,
                true,
                "settlement receipt roots are committed for replay and audit",
            ),
            InvocationRecord::new(
                "challenge_window_root",
                &self.challenge_window_root,
                true,
                true,
                true,
                "challenge window has elapsed with no unresolved challenges",
            ),
            InvocationRecord::new(
                "pq_withdrawal_authorization_root",
                &self.pq_withdrawal_authorization_root,
                true,
                true,
                true,
                "post-quantum wallet authorization transcript is bound",
            ),
            InvocationRecord::new(
                "reserve_coverage_root",
                &self.reserve_coverage_root,
                true,
                true,
                true,
                "reserve coverage meets the forced-exit floor",
            ),
            InvocationRecord::new(
                "fee_cap_root",
                &self.fee_cap_root,
                true,
                true,
                true,
                "withdrawal fee quote is capped before submission",
            ),
            InvocationRecord::new(
                "operator_independent_submission_root",
                &self.operator_independent_submission_root,
                true,
                true,
                true,
                "wallet can invoke the claim gate without operator custody or signature",
            ),
            InvocationRecord::new(
                "expected_output_root",
                &self.expected_output_root,
                true,
                true,
                true,
                "expected settlement output is deterministic and auditable",
            ),
        ];

        records.extend(
            self.fail_closed_roots
                .iter()
                .enumerate()
                .map(|(index, root)| {
                    InvocationRecord::new(
                format!("fail_closed_root_{index}"),
                root,
                true,
                true,
                true,
                "negative-path commitment rejects ambiguous or incomplete invocation inputs",
            )
                }),
        );

        records
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_claim_payload_root": self.wallet_claim_payload_root,
            "note_nullifier_proof_root": self.note_nullifier_proof_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "challenge_window_root": self.challenge_window_root,
            "pq_withdrawal_authorization_root": self.pq_withdrawal_authorization_root,
            "reserve_coverage_root": self.reserve_coverage_root,
            "fee_cap_root": self.fee_cap_root,
            "operator_independent_submission_root": self.operator_independent_submission_root,
            "expected_output_root": self.expected_output_root,
            "fail_closed_roots": self.fail_closed_roots,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "withdrawal-claim-gate-invocation-roots",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub invocation_roots: InvocationRoots,
    pub invocation_records: Vec<InvocationRecord>,
    pub invocation_record_root: String,
    pub fail_closed_root: String,
    pub accepted_for_invocation: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let invocation_roots = InvocationRoots::devnet(&config);
        let invocation_records = invocation_roots.records();
        let invocation_record_root = merkle_root(
            "WITHDRAWAL-CLAIM-GATE-INVOCATION-RECORDS",
            &invocation_records
                .iter()
                .map(InvocationRecord::state_root)
                .collect::<Vec<_>>(),
        );
        let fail_closed_root = merkle_root(
            "WITHDRAWAL-CLAIM-GATE-FAIL-CLOSED-ROOTS",
            &invocation_roots.fail_closed_roots,
        );
        let accepted_for_invocation = config.wallet_owned_claim_required
            && config.operator_independent_submission_required
            && config.fail_closed_required
            && !config.production_release_allowed
            && invocation_records
                .iter()
                .all(|record| !record.required || record.satisfied);

        Self {
            config,
            invocation_roots,
            invocation_records,
            invocation_record_root,
            fail_closed_root,
            accepted_for_invocation,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "invocation_roots": self.invocation_roots.public_record(),
            "invocation_records": self.invocation_records.iter().map(InvocationRecord::public_record).collect::<Vec<_>>(),
            "invocation_record_root": self.invocation_record_root,
            "fail_closed_root": self.fail_closed_root,
            "accepted_for_invocation": self.accepted_for_invocation,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "WITHDRAWAL-CLAIM-GATE-INVOCATION-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.invocation_roots.state_root()),
                HashPart::Str(&self.invocation_record_root),
                HashPart::Str(&self.fail_closed_root),
                HashPart::Str(if self.accepted_for_invocation {
                    "accepted"
                } else {
                    "rejected"
                }),
            ],
            32,
        )
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

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "WITHDRAWAL-CLAIM-GATE-INVOCATION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn leaf_root(label: &str, leaves: &[&str]) -> String {
    merkle_root(
        label,
        &leaves
            .iter()
            .map(|leaf| short_hash(label, leaf))
            .collect::<Vec<_>>(),
    )
}

fn short_hash(label: &str, seed: &str) -> String {
    domain_hash(
        label,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn fail_closed_root(reason: &str, claim_id: &str) -> String {
    record_root(
        "withdrawal-claim-gate-fail-closed",
        &json!({
            "reason": reason,
            "claim_id": claim_id,
            "action": "reject_invocation",
            "release_allowed": false,
        }),
    )
}
