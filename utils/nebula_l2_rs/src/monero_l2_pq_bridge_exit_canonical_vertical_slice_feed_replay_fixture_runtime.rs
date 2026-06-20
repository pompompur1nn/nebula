use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceFeedReplayFixtureRuntimeResult<T> = Result<T>;

pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FEED_REPLAY_FIXTURE_RUNTIME_PROTOCOL_VERSION: u64 =
    1;
pub const PROTOCOL_VERSION: u64 =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FEED_REPLAY_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-32/domain-separated-json-merkle-v1";

const DOMAIN_PREFIX: &str = "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-FEED-REPLAY-FIXTURE";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub fixture_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub bridge_id: String,
    pub forced_exit_circuit_id: String,
    pub replay_start_height: u64,
    pub replay_end_height: u64,
    pub required_monero_confirmations: u64,
    pub challenge_window_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            fixture_id: "monero-l2-pq-forced-exit-feed-replay-fixture-devnet-001".to_string(),
            monero_network: "monero-devnet-regtest".to_string(),
            l2_network: "nebula-l2-devnet".to_string(),
            bridge_id: "xmr-pq-canonical-forced-exit-bridge".to_string(),
            forced_exit_circuit_id: "forced-exit-vertical-slice-v1".to_string(),
            replay_start_height: 2_410_000,
            replay_end_height: 2_410_096,
            required_monero_confirmations: 18,
            challenge_window_blocks: 64,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bridge_id": self.bridge_id,
            "chain_id": CHAIN_ID,
            "challenge_window_blocks": self.challenge_window_blocks,
            "fixture_id": self.fixture_id,
            "forced_exit_circuit_id": self.forced_exit_circuit_id,
            "hash_suite": HASH_SUITE,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "protocol_version": PROTOCOL_VERSION,
            "replay_end_height": self.replay_end_height,
            "replay_start_height": self.replay_start_height,
            "required_monero_confirmations": self.required_monero_confirmations,
            "schema_version": SCHEMA_VERSION,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub monero_headers: Vec<Value>,
    pub deposit_observations: Vec<Value>,
    pub reorg_notices: Vec<Value>,
    pub settlement_receipts: Vec<Value>,
    pub reserve_proofs: Vec<Value>,
    pub pq_authority_epochs: Vec<Value>,
    pub privacy_budget_summaries: Vec<Value>,
    pub challenge_windows: Vec<Value>,
    pub stale_fail_closed_records: Vec<Value>,
    pub reorg_fail_closed_records: Vec<Value>,
}

impl State {
    pub fn devnet() -> MoneroL2PqBridgeExitCanonicalVerticalSliceFeedReplayFixtureRuntimeResult<Self>
    {
        let config = Config::devnet();
        Ok(Self {
            config,
            monero_headers: monero_header_records(),
            deposit_observations: deposit_observation_records(),
            reorg_notices: reorg_notice_records(),
            settlement_receipts: settlement_receipt_records(),
            reserve_proofs: reserve_proof_records(),
            pq_authority_epochs: pq_authority_epoch_records(),
            privacy_budget_summaries: privacy_budget_summary_records(),
            challenge_windows: challenge_window_records(),
            stale_fail_closed_records: stale_fail_closed_records(),
            reorg_fail_closed_records: reorg_fail_closed_records(),
        })
    }

    pub fn monero_header_root(&self) -> String {
        fixture_merkle_root("MONERO-HEADER", &self.monero_headers)
    }

    pub fn deposit_observation_root(&self) -> String {
        fixture_merkle_root("DEPOSIT-OBSERVATION", &self.deposit_observations)
    }

    pub fn reorg_notice_root(&self) -> String {
        fixture_merkle_root("REORG-NOTICE", &self.reorg_notices)
    }

    pub fn settlement_receipt_root(&self) -> String {
        fixture_merkle_root("SETTLEMENT-RECEIPT", &self.settlement_receipts)
    }

    pub fn reserve_proof_root(&self) -> String {
        fixture_merkle_root("RESERVE-PROOF", &self.reserve_proofs)
    }

    pub fn pq_authority_epoch_root(&self) -> String {
        fixture_merkle_root("PQ-AUTHORITY-EPOCH", &self.pq_authority_epochs)
    }

    pub fn privacy_budget_summary_root(&self) -> String {
        fixture_merkle_root("PRIVACY-BUDGET-SUMMARY", &self.privacy_budget_summaries)
    }

    pub fn challenge_window_root(&self) -> String {
        fixture_merkle_root("CHALLENGE-WINDOW", &self.challenge_windows)
    }

    pub fn stale_fail_closed_root(&self) -> String {
        fixture_merkle_root("STALE-FAIL-CLOSED", &self.stale_fail_closed_records)
    }

    pub fn reorg_fail_closed_root(&self) -> String {
        fixture_merkle_root("REORG-FAIL-CLOSED", &self.reorg_fail_closed_records)
    }

    pub fn replay_manifest_record(&self) -> Value {
        json!({
            "challenge_window_root": self.challenge_window_root(),
            "deposit_observation_root": self.deposit_observation_root(),
            "monero_header_root": self.monero_header_root(),
            "pq_authority_epoch_root": self.pq_authority_epoch_root(),
            "privacy_budget_summary_root": self.privacy_budget_summary_root(),
            "reorg_fail_closed_root": self.reorg_fail_closed_root(),
            "reorg_notice_root": self.reorg_notice_root(),
            "reserve_proof_root": self.reserve_proof_root(),
            "settlement_receipt_root": self.settlement_receipt_root(),
            "stale_fail_closed_root": self.stale_fail_closed_root(),
        })
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "hash_suite": HASH_SUITE,
            "protocol_version": PROTOCOL_VERSION,
            "replay_manifest": self.replay_manifest_record(),
            "schema_version": SCHEMA_VERSION,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &fixture_domain("STATE-ROOT"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.public_record_without_state_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }
}

pub fn devnet() -> State {
    match State::devnet() {
        Ok(state) => state,
        Err(_) => State {
            config: Config::devnet(),
            monero_headers: Vec::new(),
            deposit_observations: Vec::new(),
            reorg_notices: Vec::new(),
            settlement_receipts: Vec::new(),
            reserve_proofs: Vec::new(),
            pq_authority_epochs: Vec::new(),
            privacy_budget_summaries: Vec::new(),
            challenge_windows: Vec::new(),
            stale_fail_closed_records: Vec::new(),
            reorg_fail_closed_records: Vec::new(),
        },
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn fixture_domain(suffix: &str) -> String {
    format!("{DOMAIN_PREFIX}:{suffix}")
}

fn fixture_merkle_root(suffix: &str, records: &[Value]) -> String {
    merkle_root(&fixture_domain(suffix), records)
}

fn leaf_id(domain: &str, record: &Value) -> String {
    domain_hash(&fixture_domain(domain), &[HashPart::Json(record)], 32)
}

fn record_with_id(domain: &str, mut record: Value) -> Value {
    let id = leaf_id(domain, &record);
    if let Some(object) = record.as_object_mut() {
        object.insert("id".to_string(), json!(id));
    }
    record
}

fn monero_header_records() -> Vec<Value> {
    [
        json!({
            "canonical": true,
            "cumulative_difficulty": "335982401881440000",
            "feed_kind": "monero_header",
            "height": 2410000,
            "major_version": 16,
            "minor_version": 16,
            "nonce": 392771,
            "parent_hash": "8f5474aa3f2a3e7db3b56f27a4b1c4d4a7c7569f3a55f2a552fb8c9a2d210001",
            "pow_hash": "d3d6f08da8479c7d011ec90745c23cd44edfc96f7a1456c60a19be1124100000",
            "timestamp": 1759300800,
            "tx_root": "45b01c38f35aa7a6a14d9f96490ae7bb81c83a6513a58d8a83b28d4824100000",
        }),
        json!({
            "canonical": true,
            "cumulative_difficulty": "335982401881640000",
            "feed_kind": "monero_header",
            "height": 2410018,
            "major_version": 16,
            "minor_version": 16,
            "nonce": 392903,
            "parent_hash": "a5e5348ee641e3a447a1471147bfc54fbdcd9f355f0a8f2d66f1d04f2410017",
            "pow_hash": "5e91f5c474414f024f780a0c9f2410018e8328a98fc5c6a9517c4ddcbb76a6e7",
            "timestamp": 1759302960,
            "tx_root": "f39a6125013f6cf232a7ac1744547f647c51ce90e59c05a3e9f21a5e2410018",
        }),
        json!({
            "canonical": true,
            "cumulative_difficulty": "335982401882400000",
            "feed_kind": "monero_header",
            "height": 2410096,
            "major_version": 16,
            "minor_version": 16,
            "nonce": 393511,
            "parent_hash": "69df7d19d0cf7c9653c20b9c97241009557e160c775a93da5c4c7329a",
            "pow_hash": "aa64bc04741fe18d2a77425f0ffedc7d2410096e59b3904e23dbba9625cf0",
            "timestamp": 1759312320,
            "tx_root": "9f049615d8ad3c4ba73b02d4c1dfb550465217d9b9ac2410096ea0c3185",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("MONERO-HEADER-ID", record))
    .collect()
}

fn deposit_observation_records() -> Vec<Value> {
    [
        json!({
            "amount_piconero": "750000000000",
            "canonical_height": 2410000,
            "deposit_commitment": "depcom_xmr_pq_exit_0001",
            "feed_kind": "deposit_observation",
            "key_image_commitment": "ki_blinded_6ec7a0c7d66f2410000",
            "mined_tx_hash": "4be12dba991cc034ae089c66f8c5bd812410000",
            "observed_by": ["watcher-a", "watcher-b", "watcher-c"],
            "required_confirmations": 18,
            "status": "mature",
        }),
        json!({
            "amount_piconero": "1250000000000",
            "canonical_height": 2410018,
            "deposit_commitment": "depcom_xmr_pq_exit_0002",
            "feed_kind": "deposit_observation",
            "key_image_commitment": "ki_blinded_6ec7a0c7d66f2410018",
            "mined_tx_hash": "bb7e8cd9008c568c44507ee64de2410018",
            "observed_by": ["watcher-a", "watcher-c", "watcher-d"],
            "required_confirmations": 18,
            "status": "mature",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("DEPOSIT-OBSERVATION-ID", record))
    .collect()
}

fn reorg_notice_records() -> Vec<Value> {
    [
        json!({
            "action": "quarantine_old_branch",
            "depth": 3,
            "feed_kind": "reorg_notice",
            "first_divergent_height": 2410032,
            "losing_tip_hash": "stale_tip_f8170f5c8c4d2410034",
            "new_canonical_tip_hash": "canon_tip_b1d9a2050f642410035",
            "notice_height": 2410035,
            "status": "contained",
        }),
        json!({
            "action": "fail_closed_pending_exit",
            "depth": 7,
            "feed_kind": "reorg_notice",
            "first_divergent_height": 2410061,
            "losing_tip_hash": "stale_tip_59c30cc67b242410067",
            "new_canonical_tip_hash": "canon_tip_71abcb643c712410068",
            "notice_height": 2410068,
            "status": "forced_exit_paused",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("REORG-NOTICE-ID", record))
    .collect()
}

fn settlement_receipt_records() -> Vec<Value> {
    [
        json!({
            "feed_kind": "settlement_receipt",
            "forced_exit_id": "forced_exit_0001",
            "l2_batch": 91821,
            "l2_receipt_root": "receipt_root_9b1b6232b99c91821",
            "settled_amount_piconero": "750000000000",
            "settlement_status": "accepted",
            "source_deposit_commitment": "depcom_xmr_pq_exit_0001",
        }),
        json!({
            "feed_kind": "settlement_receipt",
            "forced_exit_id": "forced_exit_0002",
            "l2_batch": 91834,
            "l2_receipt_root": "receipt_root_30ec8fdd5b0991834",
            "settled_amount_piconero": "1250000000000",
            "settlement_status": "accepted",
            "source_deposit_commitment": "depcom_xmr_pq_exit_0002",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("SETTLEMENT-RECEIPT-ID", record))
    .collect()
}

fn reserve_proof_records() -> Vec<Value> {
    [
        json!({
            "attested_liabilities_piconero": "2000000000000",
            "feed_kind": "reserve_proof",
            "proof_height": 2410018,
            "reserve_commitment": "reserve_commitment_exit_fixture_0001",
            "reserve_margin_bps": 1800,
            "reserve_proof_root": "reserve_proof_root_19217eca2410018",
            "signer_threshold": "3-of-4",
        }),
        json!({
            "attested_liabilities_piconero": "2000000000000",
            "feed_kind": "reserve_proof",
            "proof_height": 2410096,
            "reserve_commitment": "reserve_commitment_exit_fixture_0002",
            "reserve_margin_bps": 1750,
            "reserve_proof_root": "reserve_proof_root_63228b102410096",
            "signer_threshold": "3-of-4",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("RESERVE-PROOF-ID", record))
    .collect()
}

fn pq_authority_epoch_records() -> Vec<Value> {
    [
        json!({
            "authority_root": "pq_authority_root_epoch_77",
            "epoch": 77,
            "feed_kind": "pq_authority_epoch",
            "key_suite": "ml-dsa-87+sphincs-shake-256f",
            "quorum": "4-of-6",
            "valid_from_l2_batch": 91800,
            "valid_to_l2_batch": 91863,
        }),
        json!({
            "authority_root": "pq_authority_root_epoch_78",
            "epoch": 78,
            "feed_kind": "pq_authority_epoch",
            "key_suite": "ml-dsa-87+sphincs-shake-256f",
            "quorum": "4-of-6",
            "valid_from_l2_batch": 91864,
            "valid_to_l2_batch": 91927,
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("PQ-AUTHORITY-EPOCH-ID", record))
    .collect()
}

fn privacy_budget_summary_records() -> Vec<Value> {
    [
        json!({
            "budget_epoch": 77,
            "feed_kind": "privacy_budget_summary",
            "linkability_budget_bps": 10000,
            "observed_spendlink_events": 2,
            "remaining_budget_bps": 9830,
            "summary_root": "privacy_budget_summary_epoch_77",
        }),
        json!({
            "budget_epoch": 78,
            "feed_kind": "privacy_budget_summary",
            "linkability_budget_bps": 10000,
            "observed_spendlink_events": 1,
            "remaining_budget_bps": 9915,
            "summary_root": "privacy_budget_summary_epoch_78",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("PRIVACY-BUDGET-SUMMARY-ID", record))
    .collect()
}

fn challenge_window_records() -> Vec<Value> {
    [
        json!({
            "challenge_deadline_l2_batch": 91885,
            "challenge_window_blocks": 64,
            "feed_kind": "challenge_window",
            "forced_exit_id": "forced_exit_0001",
            "opened_at_l2_batch": 91821,
            "status": "closed_uncontested",
        }),
        json!({
            "challenge_deadline_l2_batch": 91898,
            "challenge_window_blocks": 64,
            "feed_kind": "challenge_window",
            "forced_exit_id": "forced_exit_0002",
            "opened_at_l2_batch": 91834,
            "status": "closed_uncontested",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("CHALLENGE-WINDOW-ID", record))
    .collect()
}

fn stale_fail_closed_records() -> Vec<Value> {
    [
        json!({
            "deposit_commitment": "depcom_xmr_pq_exit_stale_0003",
            "fail_closed_reason": "stale_header_below_required_confirmations",
            "feed_kind": "stale_fail_closed",
            "latest_safe_height": 2410096,
            "observed_height": 2410084,
            "required_confirmations": 18,
            "resolution": "reject_replay_leaf",
        }),
        json!({
            "deposit_commitment": "depcom_xmr_pq_exit_stale_0004",
            "fail_closed_reason": "expired_privacy_budget_summary",
            "feed_kind": "stale_fail_closed",
            "latest_safe_height": 2410096,
            "observed_height": 2410018,
            "required_confirmations": 18,
            "resolution": "require_fresh_feed_bundle",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("STALE-FAIL-CLOSED-ID", record))
    .collect()
}

fn reorg_fail_closed_records() -> Vec<Value> {
    [
        json!({
            "deposit_commitment": "depcom_xmr_pq_exit_reorg_0005",
            "fail_closed_reason": "deposit_mined_on_losing_branch",
            "feed_kind": "reorg_fail_closed",
            "first_divergent_height": 2410061,
            "losing_branch_depth": 7,
            "resolution": "pause_forced_exit_and_emit_challenge",
        }),
        json!({
            "deposit_commitment": "depcom_xmr_pq_exit_reorg_0006",
            "fail_closed_reason": "settlement_receipt_references_reorged_header",
            "feed_kind": "reorg_fail_closed",
            "first_divergent_height": 2410032,
            "losing_branch_depth": 3,
            "resolution": "invalidate_receipt_before_release",
        }),
    ]
    .into_iter()
    .map(|record| record_with_id("REORG-FAIL-CLOSED-ID", record))
    .collect()
}
