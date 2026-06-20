use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWithdrawalClaimObservedReceiptIngestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-withdrawal-claim-observed-receipt-ingest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const INGEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-withdrawal-claim-observed-receipt-ingest-v1";
pub const DEFAULT_REFERENCE_HEIGHT: u64 = 4_260_768;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_RESERVE_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_MIN_WALLET_RECOVERY_SHARES: u64 = 3;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;

const DOMAIN: &str = "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-OBSERVED-RECEIPT-INGEST";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub ingest_suite: String,
    pub reference_height: u64,
    pub challenge_window_blocks: u64,
    pub release_hold_blocks: u64,
    pub min_reserve_confirmations: u64,
    pub min_reserve_coverage_bps: u64,
    pub min_wallet_recovery_shares: u64,
    pub min_pq_security_bits: u16,
    pub observed_runtime_inputs_allowed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            ingest_suite: INGEST_SUITE.to_string(),
            reference_height: DEFAULT_REFERENCE_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            min_reserve_confirmations: DEFAULT_MIN_RESERVE_CONFIRMATIONS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_wallet_recovery_shares: DEFAULT_MIN_WALLET_RECOVERY_SHARES,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_runtime_inputs_allowed: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "ingest_suite": self.ingest_suite,
            "reference_height": self.reference_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "release_hold_blocks": self.release_hold_blocks,
            "min_reserve_confirmations": self.min_reserve_confirmations,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_wallet_recovery_shares": self.min_wallet_recovery_shares,
            "min_pq_security_bits": self.min_pq_security_bits,
            "observed_runtime_inputs_allowed": self.observed_runtime_inputs_allowed,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpectedReceiptRoot {
    pub lane: String,
    pub expected_root: String,
    pub source: String,
    pub invariant: String,
    pub release_blocking: bool,
}

impl ExpectedReceiptRoot {
    pub fn new(
        lane: impl Into<String>,
        source: impl Into<String>,
        invariant: impl Into<String>,
        release_blocking: bool,
        seed_record: &Value,
    ) -> Self {
        let lane = lane.into();
        let source = source.into();
        let invariant = invariant.into();
        let expected_root = domain_hash(
            &domain("expected-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&lane),
                HashPart::Str(&source),
                HashPart::Str(&invariant),
                HashPart::Str(bool_str(release_blocking)),
                HashPart::Json(seed_record),
            ],
            32,
        );

        Self {
            lane,
            expected_root,
            source,
            invariant,
            release_blocking,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "expected_root": self.expected_root,
            "source": self.source,
            "invariant": self.invariant,
            "release_blocking": self.release_blocking,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("expected_receipt_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceipt {
    pub receipt_id: String,
    pub lane: String,
    pub source_runtime: String,
    pub observed_at_height: u64,
    pub observed_root: String,
    pub evidence_root: String,
    pub ingestion_root: String,
}

impl ObservedReceipt {
    pub fn new(
        lane: impl Into<String>,
        source_runtime: impl Into<String>,
        observed_at_height: u64,
        payload: &Value,
    ) -> Self {
        let lane = lane.into();
        let source_runtime = source_runtime.into();
        let evidence_root = payload_root("observed-evidence", payload);
        let observed_root = domain_hash(
            &domain("observed-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&lane),
                HashPart::Str(&source_runtime),
                HashPart::U64(observed_at_height),
                HashPart::Str(&evidence_root),
                HashPart::Json(payload),
            ],
            32,
        );
        let ingestion_root = domain_hash(
            &domain("ingestion-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&lane),
                HashPart::Str(&observed_root),
                HashPart::Str(&evidence_root),
            ],
            32,
        );
        let receipt_id = domain_hash(
            &domain("receipt-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&lane),
                HashPart::Str(&source_runtime),
                HashPart::Str(&ingestion_root),
            ],
            32,
        );

        Self {
            receipt_id,
            lane,
            source_runtime,
            observed_at_height,
            observed_root,
            evidence_root,
            ingestion_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane": self.lane,
            "source_runtime": self.source_runtime,
            "observed_at_height": self.observed_at_height,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "ingestion_root": self.ingestion_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptComparison {
    pub lane: String,
    pub expected_root: String,
    pub observed_root: String,
    pub matches_expected: bool,
    pub release_blocking: bool,
    pub comparison_root: String,
}

impl ReceiptComparison {
    pub fn compare(expected: &ExpectedReceiptRoot, observed: &ObservedReceipt) -> Self {
        let matches_expected = expected.expected_root == observed.observed_root;
        let release_blocking = expected.release_blocking && !matches_expected;
        let comparison_root = domain_hash(
            &domain("comparison-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&expected.lane),
                HashPart::Str(&expected.expected_root),
                HashPart::Str(&observed.observed_root),
                HashPart::Str(bool_str(matches_expected)),
                HashPart::Str(bool_str(release_blocking)),
            ],
            32,
        );

        Self {
            lane: expected.lane.clone(),
            expected_root: expected.expected_root.clone(),
            observed_root: observed.observed_root.clone(),
            matches_expected,
            release_blocking,
            comparison_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "matches_expected": self.matches_expected,
            "release_blocking": self.release_blocking,
            "comparison_root": self.comparison_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_comparison", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptMismatch {
    pub mismatch_id: String,
    pub lane: String,
    pub expected_root: String,
    pub observed_root: String,
    pub reason: String,
    pub evidence_root: String,
}

impl ReceiptMismatch {
    pub fn from_comparison(comparison: &ReceiptComparison) -> Option<Self> {
        if comparison.matches_expected {
            return None;
        }

        let reason = "observed_receipt_root_differs_from_expected_conformance_root".to_string();
        let evidence = json!({
            "lane": comparison.lane,
            "expected_root": comparison.expected_root,
            "observed_root": comparison.observed_root,
            "comparison_root": comparison.comparison_root,
            "reason": reason,
        });
        let evidence_root = payload_root("mismatch-evidence", &evidence);
        let mismatch_id = domain_hash(
            &domain("mismatch-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&comparison.lane),
                HashPart::Str(&comparison.expected_root),
                HashPart::Str(&comparison.observed_root),
                HashPart::Str(&evidence_root),
            ],
            32,
        );

        Some(Self {
            mismatch_id,
            lane: comparison.lane.clone(),
            expected_root: comparison.expected_root.clone(),
            observed_root: comparison.observed_root.clone(),
            reason,
            evidence_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "lane": self.lane,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub lane: String,
    pub release_after_height: u64,
    pub reason: String,
    pub mismatch_id: String,
    pub hold_root: String,
}

impl ReleaseHold {
    pub fn from_mismatch(config: &Config, mismatch: &ReceiptMismatch) -> Self {
        let release_after_height = config.reference_height + config.release_hold_blocks;
        let reason = "forced_exit_release_held_until_observed_receipt_conforms".to_string();
        let hold_root = domain_hash(
            &domain("release-hold-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&mismatch.lane),
                HashPart::Str(&mismatch.mismatch_id),
                HashPart::U64(release_after_height),
                HashPart::Str(&reason),
            ],
            32,
        );
        let hold_id = domain_hash(
            &domain("release-hold-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&mismatch.lane),
                HashPart::Str(&hold_root),
            ],
            32,
        );

        Self {
            hold_id,
            lane: mismatch.lane.clone(),
            release_after_height,
            reason,
            mismatch_id: mismatch.mismatch_id.clone(),
            hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "lane": self.lane,
            "release_after_height": self.release_after_height,
            "reason": self.reason,
            "mismatch_id": self.mismatch_id,
            "hold_root": self.hold_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub expected_roots: Vec<ExpectedReceiptRoot>,
    pub observed_receipts: Vec<ObservedReceipt>,
    pub comparisons: Vec<ReceiptComparison>,
    pub mismatches: Vec<ReceiptMismatch>,
    pub release_holds: Vec<ReleaseHold>,
    pub expected_root_by_lane: BTreeMap<String, String>,
    pub observed_root_by_lane: BTreeMap<String, String>,
}

impl State {
    pub fn new(
        config: Config,
        expected_roots: Vec<ExpectedReceiptRoot>,
        observed_receipts: Vec<ObservedReceipt>,
    ) -> Self {
        let observed_by_lane = observed_receipt_by_lane(&observed_receipts);
        let comparisons = expected_roots
            .iter()
            .filter_map(|expected| {
                observed_by_lane
                    .get(&expected.lane)
                    .map(|observed| ReceiptComparison::compare(expected, observed))
            })
            .collect::<Vec<_>>();
        let mismatches = comparisons
            .iter()
            .filter_map(ReceiptMismatch::from_comparison)
            .collect::<Vec<_>>();
        let release_holds = mismatches
            .iter()
            .map(|mismatch| ReleaseHold::from_mismatch(&config, mismatch))
            .collect::<Vec<_>>();
        let expected_root_by_lane = expected_roots
            .iter()
            .map(|record| (record.lane.clone(), record.expected_root.clone()))
            .collect::<BTreeMap<_, _>>();
        let observed_root_by_lane = observed_receipts
            .iter()
            .map(|record| (record.lane.clone(), record.observed_root.clone()))
            .collect::<BTreeMap<_, _>>();

        Self {
            config,
            expected_roots,
            observed_receipts,
            comparisons,
            mismatches,
            release_holds,
            expected_root_by_lane,
            observed_root_by_lane,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let expected_roots = devnet_expected_roots(&config);
        let observed_receipts = devnet_observed_receipts(&config);
        Self::new(config, expected_roots, observed_receipts)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "ingest_suite": INGEST_SUITE,
            "config": self.config.public_record(),
            "expected_count": self.expected_roots.len() as u64,
            "observed_count": self.observed_receipts.len() as u64,
            "comparison_count": self.comparisons.len() as u64,
            "mismatch_count": self.mismatches.len() as u64,
            "release_hold_count": self.release_holds.len() as u64,
            "all_roots_conform": self.all_roots_conform(),
            "release_blocking": self.release_blocking(),
            "expected_root": self.expected_receipt_root(),
            "observed_root": self.observed_receipt_root(),
            "comparison_root": self.comparison_root(),
            "mismatch_root": self.mismatch_root(),
            "release_hold_root": self.release_hold_root(),
            "claim_authorization_root": self.lane_root("claim_authorization"),
            "challenge_window_root": self.lane_root("challenge_window"),
            "reserve_proof_root": self.lane_root("reserve_proof"),
            "pq_withdrawal_authorization_root": self.lane_root("pq_withdrawal_authorization"),
            "wallet_recovery_payload_root": self.lane_root("wallet_recovery_payloads"),
            "settlement_receipt_root": self.lane_root("settlement_receipts"),
            "expected_root_by_lane": self.expected_root_by_lane,
            "observed_root_by_lane": self.observed_root_by_lane,
            "expected_roots": self.expected_roots.iter().map(ExpectedReceiptRoot::public_record).collect::<Vec<_>>(),
            "observed_receipts": self.observed_receipts.iter().map(ObservedReceipt::public_record).collect::<Vec<_>>(),
            "comparisons": self.comparisons.iter().map(ReceiptComparison::public_record).collect::<Vec<_>>(),
            "mismatches": self.mismatches.iter().map(ReceiptMismatch::public_record).collect::<Vec<_>>(),
            "release_holds": self.release_holds.iter().map(ReleaseHold::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &domain("state"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.expected_receipt_root()),
                HashPart::Str(&self.observed_receipt_root()),
                HashPart::Str(&self.comparison_root()),
                HashPart::Str(&self.mismatch_root()),
                HashPart::Str(&self.release_hold_root()),
            ],
            32,
        )
    }

    pub fn expected_receipt_root(&self) -> String {
        merkle_root(
            &domain("expected-receipts"),
            &self
                .expected_roots
                .iter()
                .map(ExpectedReceiptRoot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn observed_receipt_root(&self) -> String {
        merkle_root(
            &domain("observed-receipts"),
            &self
                .observed_receipts
                .iter()
                .map(ObservedReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn comparison_root(&self) -> String {
        merkle_root(
            &domain("comparisons"),
            &self
                .comparisons
                .iter()
                .map(ReceiptComparison::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn mismatch_root(&self) -> String {
        merkle_root(
            &domain("mismatches"),
            &self
                .mismatches
                .iter()
                .map(ReceiptMismatch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn release_hold_root(&self) -> String {
        merkle_root(
            &domain("release-holds"),
            &self
                .release_holds
                .iter()
                .map(ReleaseHold::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lane_root(&self, lane: &str) -> String {
        match self.observed_root_by_lane.get(lane) {
            Some(root) => root.clone(),
            None => domain_hash(
                &domain("missing-lane-root"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(lane),
                ],
                32,
            ),
        }
    }

    pub fn all_roots_conform(&self) -> bool {
        self.comparisons
            .iter()
            .all(|comparison| comparison.matches_expected)
    }

    pub fn release_blocking(&self) -> bool {
        self.comparisons
            .iter()
            .any(|comparison| comparison.release_blocking)
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

pub fn ingest_observed_receipts(
    config: Config,
    expected_roots: Vec<ExpectedReceiptRoot>,
    observed_receipts: Vec<ObservedReceipt>,
) -> Result<State> {
    if config.chain_id != CHAIN_ID {
        return Err("config_chain_id_does_not_match_runtime_chain_id".to_string());
    }
    if config.protocol_version != PROTOCOL_VERSION {
        return Err("config_protocol_version_does_not_match_runtime_protocol".to_string());
    }
    if expected_roots.is_empty() {
        return Err("expected_receipt_roots_required".to_string());
    }
    if observed_receipts.is_empty() {
        return Err("observed_receipts_required".to_string());
    }

    Ok(State::new(config, expected_roots, observed_receipts))
}

fn devnet_expected_roots(config: &Config) -> Vec<ExpectedReceiptRoot> {
    vec![
        expected_lane(
            config,
            "claim_authorization",
            "withdrawal-claim-gate-execution-receipt",
            "claim authorization quorum must accept canonical forced-exit claim",
            true,
        ),
        expected_lane(
            config,
            "challenge_window",
            "withdrawal-claim-gate-execution-receipt",
            "challenge window must be closed before release",
            true,
        ),
        expected_lane(
            config,
            "reserve_proof",
            "withdrawal-claim-gate-execution-receipt",
            "reserve proof must cover requested piconero amount plus hold margin",
            true,
        ),
        expected_lane(
            config,
            "pq_withdrawal_authorization",
            "forced-withdrawal-authorization-runtime",
            "post-quantum authorization must meet configured security bits",
            true,
        ),
        expected_lane(
            config,
            "wallet_recovery_payloads",
            "wallet-claim-export-manifest-runtime",
            "wallet recovery payloads must be redacted and share-threshold complete",
            false,
        ),
        expected_lane(
            config,
            "settlement_receipts",
            "settlement-receipt-verifier-runtime",
            "settlement receipts must bind release transaction and canonical exit root",
            true,
        ),
    ]
}

fn expected_lane(
    config: &Config,
    lane: &str,
    source: &str,
    invariant: &str,
    release_blocking: bool,
) -> ExpectedReceiptRoot {
    let seed = json!({
        "reference_height": config.reference_height,
        "challenge_window_blocks": config.challenge_window_blocks,
        "release_hold_blocks": config.release_hold_blocks,
        "min_reserve_confirmations": config.min_reserve_confirmations,
        "min_reserve_coverage_bps": config.min_reserve_coverage_bps,
        "min_wallet_recovery_shares": config.min_wallet_recovery_shares,
        "min_pq_security_bits": config.min_pq_security_bits,
        "lane": lane,
    });
    ExpectedReceiptRoot::new(lane, source, invariant, release_blocking, &seed)
}

fn devnet_observed_receipts(config: &Config) -> Vec<ObservedReceipt> {
    vec![
        observed_claim_authorization(config),
        observed_challenge_window(config),
        observed_reserve_proof(config),
        observed_pq_withdrawal_authorization(config),
        observed_wallet_recovery_payloads(config),
        observed_settlement_receipts(config),
    ]
}

fn observed_claim_authorization(config: &Config) -> ObservedReceipt {
    ObservedReceipt::new(
        "claim_authorization",
        "monero-l2-pq-bridge-exit-canonical-withdrawal-claim-execution-runtime",
        config.reference_height,
        &json!({
            "claim_id": label_root("claim", "devnet-forced-exit-withdrawal-claim-0001"),
            "claimant_commitment": label_root("claimant", "wallet-claimant"),
            "forced_exit_spine_root": label_root("forced-exit-spine", "canonical-withdrawal-claim"),
            "authorization_quorum_root": label_root("pq-quorum", "ml-dsa-falcon-slh-dsa"),
            "accepted": true,
        }),
    )
}

fn observed_challenge_window(config: &Config) -> ObservedReceipt {
    ObservedReceipt::new(
        "challenge_window",
        "monero-l2-pq-bridge-exit-canonical-withdrawal-claim-execution-runtime",
        config.reference_height,
        &json!({
            "opened_at_height": config.reference_height - config.challenge_window_blocks - config.release_hold_blocks,
            "closed_at_height": config.reference_height - config.release_hold_blocks,
            "observed_at_height": config.reference_height,
            "challenge_window_blocks": config.challenge_window_blocks,
            "release_hold_blocks": config.release_hold_blocks,
            "challenge_status": "closed_without_successful_challenge",
        }),
    )
}

fn observed_reserve_proof(config: &Config) -> ObservedReceipt {
    ObservedReceipt::new(
        "reserve_proof",
        "monero-l2-pq-bridge-exit-settlement-receipt-verifier-runtime",
        config.reference_height,
        &json!({
            "reserve_proof_id": label_root("reserve-proof", "devnet-reserve-proof-0001"),
            "asset": "xmr",
            "requested_piconero": 1_700_000_000_000_u64,
            "reserved_piconero": 1_805_000_000_000_u64,
            "coverage_bps": config.min_reserve_coverage_bps,
            "confirmations": config.min_reserve_confirmations,
        }),
    )
}

fn observed_pq_withdrawal_authorization(config: &Config) -> ObservedReceipt {
    ObservedReceipt::new(
        "pq_withdrawal_authorization",
        "monero-l2-pq-bridge-exit-forced-withdrawal-authorization-runtime",
        config.reference_height,
        &json!({
            "authorization_id": label_root("pq-withdrawal-authorization", "devnet-auth-0001"),
            "signature_scheme_roots": [
                label_root("pq-scheme", "ml-dsa-87"),
                label_root("pq-scheme", "falcon-1024"),
                label_root("pq-scheme", "slh-dsa-shake-256f")
            ],
            "threshold": 2_u64,
            "security_bits": config.min_pq_security_bits,
            "nonce_root": label_root("nonce", "withdrawal-claim-auth-nonce"),
        }),
    )
}

fn observed_wallet_recovery_payloads(config: &Config) -> ObservedReceipt {
    ObservedReceipt::new(
        "wallet_recovery_payloads",
        "monero-l2-pq-bridge-exit-canonical-wallet-claim-export-manifest-runtime",
        config.reference_height,
        &json!({
            "payload_bundle_id": label_root("wallet-recovery", "devnet-recovery-bundle-0001"),
            "share_count": config.min_wallet_recovery_shares,
            "redaction_root": label_root("redaction", "wallet-visible-recovery-payload"),
            "view_key_export_root": label_root("view-key-export", "redacted-view-key-envelope"),
            "operator_blind_root": label_root("operator-blind", "operator-cannot-link-wallet-payload"),
        }),
    )
}

fn observed_settlement_receipts(config: &Config) -> ObservedReceipt {
    ObservedReceipt::new(
        "settlement_receipts",
        "monero-l2-pq-bridge-exit-settlement-receipt-verifier-runtime",
        config.reference_height,
        &json!({
            "settlement_id": label_root("settlement", "devnet-settlement-0001"),
            "release_monero_txid_hash": label_root("monero-txid", "release-transaction"),
            "canonical_exit_root": label_root("canonical-exit", "forced-exit-spine"),
            "claim_receipt_root": label_root("claim-receipt", "withdrawal-claim-receipt"),
            "settled": true,
        }),
    )
}

fn observed_receipt_by_lane(receipts: &[ObservedReceipt]) -> BTreeMap<String, ObservedReceipt> {
    receipts
        .iter()
        .map(|receipt| (receipt.lane.clone(), receipt.clone()))
        .collect()
}

fn label_root(label: &str, value: &str) -> String {
    domain_hash(
        &domain("label-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        &domain(label),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        &domain(label),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn domain(label: &str) -> String {
    format!("{DOMAIN}-{label}")
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
