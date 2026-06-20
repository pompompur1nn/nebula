use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalWithdrawalClaimExecutionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WITHDRAWAL_CLAIM_EXECUTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-withdrawal-claim-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WITHDRAWAL_CLAIM_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTION_SUITE: &str = "canonical-withdrawal-forced-exit-claim-execution-v1";
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
    pub execution_suite: String,
    pub challenge_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub fee_cap_atomic: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            execution_suite: EXECUTION_SUITE.to_string(),
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            fee_cap_atomic: DEFAULT_FEE_CAP_ATOMIC,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "execution_suite": self.execution_suite,
            "challenge_window_blocks": self.challenge_window_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "fee_cap_atomic": self.fee_cap_atomic.to_string(),
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-CLAIM-EXECUTION-CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletOwnedClaimPayload {
    pub claim_id: String,
    pub wallet_view_tag: String,
    pub account_commitment: String,
    pub withdrawal_address_commitment: String,
    pub amount_atomic: u128,
    pub asset_id: String,
    pub forced_exit: bool,
}

impl WalletOwnedClaimPayload {
    pub fn devnet() -> Self {
        let seed = "devnet-wallet-owned-withdrawal-claim";
        Self {
            claim_id: short_hash("WITHDRAWAL-CLAIM-ID", seed),
            wallet_view_tag: short_hash("WALLET-VIEW-TAG", seed),
            account_commitment: short_hash("ACCOUNT-COMMITMENT", seed),
            withdrawal_address_commitment: short_hash("WITHDRAWAL-ADDRESS-COMMITMENT", seed),
            amount_atomic: 12_500_000_000,
            asset_id: "xmr".to_string(),
            forced_exit: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "wallet_view_tag": self.wallet_view_tag,
            "account_commitment": self.account_commitment,
            "withdrawal_address_commitment": self.withdrawal_address_commitment,
            "amount_atomic": self.amount_atomic.to_string(),
            "asset_id": self.asset_id,
            "forced_exit": self.forced_exit,
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-CLAIM-PAYLOAD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NoteNullifierProofRoots {
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub inclusion_proof_root: String,
    pub non_membership_proof_root: String,
    pub privacy_set_size: u64,
}

impl NoteNullifierProofRoots {
    pub fn devnet(payload: &WalletOwnedClaimPayload) -> Self {
        Self {
            note_commitment_root: leaf_root(
                "WITHDRAWAL-NOTE-COMMITMENTS",
                &[
                    payload.account_commitment.as_str(),
                    "note:devnet:bridge-lock:0001",
                    "note:devnet:change:0001",
                ],
            ),
            nullifier_root: leaf_root(
                "WITHDRAWAL-NULLIFIERS",
                &[
                    "nullifier:devnet:spent-prior:0001",
                    "nullifier:devnet:withdrawal-claim:0001",
                ],
            ),
            inclusion_proof_root: short_hash("WITHDRAWAL-NOTE-INCLUSION-PROOF", &payload.claim_id),
            non_membership_proof_root: short_hash(
                "WITHDRAWAL-NULLIFIER-NON-MEMBERSHIP-PROOF",
                &payload.claim_id,
            ),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_commitment_root": self.note_commitment_root,
            "nullifier_root": self.nullifier_root,
            "inclusion_proof_root": self.inclusion_proof_root,
            "non_membership_proof_root": self.non_membership_proof_root,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn root(&self) -> String {
        record_hash(
            "WITHDRAWAL-NOTE-NULLIFIER-PROOF-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceiptRoots {
    pub public_receipt_root: String,
    pub encrypted_receipt_root: String,
    pub reserve_debit_receipt_root: String,
    pub execution_receipt_root: String,
}

impl SettlementReceiptRoots {
    pub fn devnet(payload: &WalletOwnedClaimPayload) -> Self {
        Self {
            public_receipt_root: short_hash("WITHDRAWAL-PUBLIC-RECEIPT", &payload.claim_id),
            encrypted_receipt_root: short_hash("WITHDRAWAL-ENCRYPTED-RECEIPT", &payload.claim_id),
            reserve_debit_receipt_root: short_hash(
                "WITHDRAWAL-RESERVE-DEBIT-RECEIPT",
                &payload.claim_id,
            ),
            execution_receipt_root: short_hash("WITHDRAWAL-EXECUTION-RECEIPT", &payload.claim_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "public_receipt_root": self.public_receipt_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "reserve_debit_receipt_root": self.reserve_debit_receipt_root,
            "execution_receipt_root": self.execution_receipt_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-SETTLEMENT-RECEIPT-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindow {
    pub opened_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub release_after_l2_height: u64,
    pub current_l2_height: u64,
    pub unresolved_challenges: u64,
}

impl ChallengeWindow {
    pub fn devnet(config: &Config) -> Self {
        let opened_at_l2_height = 4_260_000;
        let closes_at_l2_height = opened_at_l2_height + config.challenge_window_blocks;
        Self {
            opened_at_l2_height,
            closes_at_l2_height,
            release_after_l2_height: closes_at_l2_height + config.release_delay_blocks,
            current_l2_height: closes_at_l2_height + config.release_delay_blocks + 12,
            unresolved_challenges: 0,
        }
    }

    pub fn elapsed(&self) -> bool {
        self.current_l2_height >= self.release_after_l2_height && self.unresolved_challenges == 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "opened_at_l2_height": self.opened_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height,
            "release_after_l2_height": self.release_after_l2_height,
            "current_l2_height": self.current_l2_height,
            "unresolved_challenges": self.unresolved_challenges,
            "elapsed": self.elapsed(),
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-CHALLENGE-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWithdrawalAuthorization {
    pub authorization_id: String,
    pub scheme: String,
    pub authority_set_root: String,
    pub wallet_signature_root: String,
    pub watcher_attestation_root: String,
    pub security_bits: u16,
    pub threshold_met: bool,
}

impl PqWithdrawalAuthorization {
    pub fn devnet(payload: &WalletOwnedClaimPayload) -> Self {
        Self {
            authorization_id: short_hash("WITHDRAWAL-PQ-AUTHORIZATION-ID", &payload.claim_id),
            scheme: "ml-dsa-87+slh-dsa-shake-256f".to_string(),
            authority_set_root: leaf_root(
                "WITHDRAWAL-PQ-AUTHORITY-SET",
                &[
                    "pq-authority:alpha",
                    "pq-authority:bravo",
                    "pq-authority:charlie",
                ],
            ),
            wallet_signature_root: short_hash("WITHDRAWAL-WALLET-PQ-SIGNATURE", &payload.claim_id),
            watcher_attestation_root: leaf_root(
                "WITHDRAWAL-PQ-WATCHER-ATTESTATIONS",
                &[
                    "watcher:alpha:accept",
                    "watcher:bravo:accept",
                    "watcher:charlie:accept",
                ],
            ),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            threshold_met: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "scheme": self.scheme,
            "authority_set_root": self.authority_set_root,
            "wallet_signature_root": self.wallet_signature_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "security_bits": self.security_bits,
            "threshold_met": self.threshold_met,
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-PQ-AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveCoverage {
    pub reserve_epoch: u64,
    pub required_atomic: u128,
    pub available_atomic: u128,
    pub coverage_bps: u64,
    pub coverage_proof_root: String,
}

impl ReserveCoverage {
    pub fn devnet(payload: &WalletOwnedClaimPayload) -> Self {
        let required_atomic = payload.amount_atomic;
        let available_atomic = 15_250_000_000;
        Self {
            reserve_epoch: 77,
            required_atomic,
            available_atomic,
            coverage_bps: ((available_atomic * 10_000) / required_atomic) as u64,
            coverage_proof_root: short_hash("WITHDRAWAL-RESERVE-COVERAGE", &payload.claim_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reserve_epoch": self.reserve_epoch,
            "required_atomic": self.required_atomic.to_string(),
            "available_atomic": self.available_atomic.to_string(),
            "coverage_bps": self.coverage_bps,
            "coverage_proof_root": self.coverage_proof_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-RESERVE-COVERAGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCap {
    pub max_fee_atomic: u128,
    pub quoted_fee_atomic: u128,
    pub fee_market_epoch: u64,
    pub fee_receipt_root: String,
}

impl FeeCap {
    pub fn devnet(payload: &WalletOwnedClaimPayload) -> Self {
        Self {
            max_fee_atomic: DEFAULT_FEE_CAP_ATOMIC,
            quoted_fee_atomic: 18_000_000,
            fee_market_epoch: 211,
            fee_receipt_root: short_hash("WITHDRAWAL-FEE-RECEIPT", &payload.claim_id),
        }
    }

    pub fn within_cap(&self) -> bool {
        self.quoted_fee_atomic <= self.max_fee_atomic
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_fee_atomic": self.max_fee_atomic.to_string(),
            "quoted_fee_atomic": self.quoted_fee_atomic.to_string(),
            "fee_market_epoch": self.fee_market_epoch,
            "fee_receipt_root": self.fee_receipt_root,
            "within_cap": self.within_cap(),
        })
    }

    pub fn root(&self) -> String {
        record_hash("WITHDRAWAL-FEE-CAP", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorIndependentSubmission {
    pub submission_id: String,
    pub submitted_by_wallet: bool,
    pub operator_signature_required: bool,
    pub relay_path_root: String,
    pub censorship_bypass_root: String,
}

impl OperatorIndependentSubmission {
    pub fn devnet(payload: &WalletOwnedClaimPayload) -> Self {
        Self {
            submission_id: short_hash(
                "WITHDRAWAL-OPERATOR-INDEPENDENT-SUBMISSION",
                &payload.claim_id,
            ),
            submitted_by_wallet: true,
            operator_signature_required: false,
            relay_path_root: leaf_root(
                "WITHDRAWAL-OPERATOR-INDEPENDENT-RELAYS",
                &[
                    "wallet-direct-mempool",
                    "watcher-bonded-relay",
                    "escape-hatch-calldata",
                ],
            ),
            censorship_bypass_root: short_hash("WITHDRAWAL-CENSORSHIP-BYPASS", &payload.claim_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "submission_id": self.submission_id,
            "submitted_by_wallet": self.submitted_by_wallet,
            "operator_signature_required": self.operator_signature_required,
            "relay_path_root": self.relay_path_root,
            "censorship_bypass_root": self.censorship_bypass_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash(
            "WITHDRAWAL-OPERATOR-INDEPENDENT-SUBMISSION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub claim_payload: WalletOwnedClaimPayload,
    pub note_nullifier_roots: NoteNullifierProofRoots,
    pub settlement_receipt_roots: SettlementReceiptRoots,
    pub challenge_window: ChallengeWindow,
    pub pq_authorization: PqWithdrawalAuthorization,
    pub reserve_coverage: ReserveCoverage,
    pub fee_cap: FeeCap,
    pub submission: OperatorIndependentSubmission,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let claim_payload = WalletOwnedClaimPayload::devnet();
        Self {
            note_nullifier_roots: NoteNullifierProofRoots::devnet(&claim_payload),
            settlement_receipt_roots: SettlementReceiptRoots::devnet(&claim_payload),
            challenge_window: ChallengeWindow::devnet(&config),
            pq_authorization: PqWithdrawalAuthorization::devnet(&claim_payload),
            reserve_coverage: ReserveCoverage::devnet(&claim_payload),
            fee_cap: FeeCap::devnet(&claim_payload),
            submission: OperatorIndependentSubmission::devnet(&claim_payload),
            config,
            claim_payload,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_withdrawal_claim_execution_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "claim_payload": self.claim_payload.public_record(),
            "note_nullifier_roots": self.note_nullifier_roots.public_record(),
            "settlement_receipt_roots": self.settlement_receipt_roots.public_record(),
            "challenge_window": self.challenge_window.public_record(),
            "pq_authorization": self.pq_authorization.public_record(),
            "reserve_coverage": self.reserve_coverage.public_record(),
            "fee_cap": self.fee_cap.public_record(),
            "submission": self.submission.public_record(),
            "roots": self.component_roots(),
            "state_root": self.root(),
        })
    }

    pub fn component_roots(&self) -> Value {
        json!({
            "config_root": self.config.root(),
            "claim_payload_root": self.claim_payload.root(),
            "note_nullifier_root": self.note_nullifier_roots.root(),
            "settlement_receipt_root": self.settlement_receipt_roots.root(),
            "challenge_window_root": self.challenge_window.root(),
            "pq_authorization_root": self.pq_authorization.root(),
            "reserve_coverage_root": self.reserve_coverage.root(),
            "fee_cap_root": self.fee_cap.root(),
            "submission_root": self.submission.root(),
        })
    }

    pub fn root(&self) -> String {
        let roots = self.component_roots();
        domain_hash(
            "WITHDRAWAL-CLAIM-EXECUTION-STATE",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&roots)],
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
    devnet().root()
}

fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn short_hash(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

fn leaf_root(domain: &str, labels: &[&str]) -> String {
    let leaves = labels
        .iter()
        .map(|label| json!({ "chain_id": CHAIN_ID, "label": label }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
