use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceForcedExitReleaseAcceptanceRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FORCED_EXIT_RELEASE_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-forced-exit-release-acceptance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FORCED_EXIT_RELEASE_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_ACCEPTANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-forced-exit-release-acceptance-v1";
pub const DEFAULT_REFERENCE_L2_HEIGHT: u64 = 4_265_600;
pub const DEFAULT_REFERENCE_MONERO_HEIGHT: u64 = 3_525_920;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_FINALITY_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_WALLET_RECOVERY_SHARDS: u16 = 3;
pub const DEFAULT_MIN_OBSERVED_RECEIPTS: u16 = 3;
pub const DEFAULT_MIN_SETTLEMENT_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_RELEASE_FEE_ATOMIC: u64 = 40_000_000;

const DOMAIN: &str = "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-RELEASE-ACCEPTANCE";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceStage {
    WalletRecoveryEvidence,
    ObservedReceipts,
    ChallengeWindowClosure,
    SettlementOrdering,
    ReserveSufficiency,
    MismatchScreening,
    ReleaseAcceptance,
}

impl AcceptanceStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecoveryEvidence => "wallet_recovery_evidence",
            Self::ObservedReceipts => "observed_receipts",
            Self::ChallengeWindowClosure => "challenge_window_closure",
            Self::SettlementOrdering => "settlement_ordering",
            Self::ReserveSufficiency => "reserve_sufficiency",
            Self::MismatchScreening => "mismatch_screening",
            Self::ReleaseAcceptance => "release_acceptance",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::WalletRecoveryEvidence => 0,
            Self::ObservedReceipts => 1,
            Self::ChallengeWindowClosure => 2,
            Self::SettlementOrdering => 3,
            Self::ReserveSufficiency => 4,
            Self::MismatchScreening => 5,
            Self::ReleaseAcceptance => 6,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::WalletRecoveryEvidence,
            Self::ObservedReceipts,
            Self::ChallengeWindowClosure,
            Self::SettlementOrdering,
            Self::ReserveSufficiency,
            Self::MismatchScreening,
            Self::ReleaseAcceptance,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    WalletRecoveryMissing,
    WalletRecoveryInsufficient,
    WalletRecoveryMismatched,
    ReceiptQuorumMissing,
    ReceiptAmountMismatch,
    ReceiptDestinationMismatch,
    ChallengeWindowOpen,
    ActiveChallengeRecorded,
    SettlementOutOfOrder,
    SettlementReceiptUnconfirmed,
    ReserveCoverageInsufficient,
    FeeCapExceeded,
    ReleaseNullifierMismatch,
    ReleaseCommitmentMismatch,
    PolicyHold,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecoveryMissing => "wallet_recovery_missing",
            Self::WalletRecoveryInsufficient => "wallet_recovery_insufficient",
            Self::WalletRecoveryMismatched => "wallet_recovery_mismatched",
            Self::ReceiptQuorumMissing => "receipt_quorum_missing",
            Self::ReceiptAmountMismatch => "receipt_amount_mismatch",
            Self::ReceiptDestinationMismatch => "receipt_destination_mismatch",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ActiveChallengeRecorded => "active_challenge_recorded",
            Self::SettlementOutOfOrder => "settlement_out_of_order",
            Self::SettlementReceiptUnconfirmed => "settlement_receipt_unconfirmed",
            Self::ReserveCoverageInsufficient => "reserve_coverage_insufficient",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::ReleaseNullifierMismatch => "release_nullifier_mismatch",
            Self::ReleaseCommitmentMismatch => "release_commitment_mismatch",
            Self::PolicyHold => "policy_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceVerdict {
    AcceptedForRelease,
    Deferred,
    Rejected,
}

impl AcceptanceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedForRelease => "accepted_for_release",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDirection {
    DepositReturn,
    PrivateExitRelease,
    OperatorCompensation,
}

impl SettlementDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositReturn => "deposit_return",
            Self::PrivateExitRelease => "private_exit_release",
            Self::OperatorCompensation => "operator_compensation",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_acceptance_suite: String,
    pub reference_l2_height: u64,
    pub reference_monero_height: u64,
    pub challenge_window_blocks: u64,
    pub release_finality_blocks: u64,
    pub min_wallet_recovery_shards: u16,
    pub min_observed_receipts: u16,
    pub min_settlement_confirmations: u64,
    pub min_reserve_coverage_bps: u64,
    pub min_pq_security_bits: u16,
    pub max_release_fee_atomic: u64,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_acceptance_suite: RELEASE_ACCEPTANCE_SUITE.to_string(),
            reference_l2_height: DEFAULT_REFERENCE_L2_HEIGHT,
            reference_monero_height: DEFAULT_REFERENCE_MONERO_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_finality_blocks: DEFAULT_RELEASE_FINALITY_BLOCKS,
            min_wallet_recovery_shards: DEFAULT_MIN_WALLET_RECOVERY_SHARDS,
            min_observed_receipts: DEFAULT_MIN_OBSERVED_RECEIPTS,
            min_settlement_confirmations: DEFAULT_MIN_SETTLEMENT_CONFIRMATIONS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_release_fee_atomic: DEFAULT_MAX_RELEASE_FEE_ATOMIC,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_acceptance_suite": self.release_acceptance_suite,
            "reference_l2_height": self.reference_l2_height,
            "reference_monero_height": self.reference_monero_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "release_finality_blocks": self.release_finality_blocks,
            "min_wallet_recovery_shards": self.min_wallet_recovery_shards,
            "min_observed_receipts": self.min_observed_receipts,
            "min_settlement_confirmations": self.min_settlement_confirmations,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_release_fee_atomic": self.max_release_fee_atomic,
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
pub struct WalletRecoveryEvidence {
    pub claim_id: String,
    pub recovered_wallet_root: String,
    pub recovered_note_root: String,
    pub recovery_transcript_root: String,
    pub recovery_view_tag_root: String,
    pub expected_wallet_root: String,
    pub expected_note_root: String,
    pub shard_count: u16,
    pub attestor_count: u16,
    pub pq_security_bits: u16,
    pub evidence_height: u64,
}

impl WalletRecoveryEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "recovered_wallet_root": self.recovered_wallet_root,
            "recovered_note_root": self.recovered_note_root,
            "recovery_transcript_root": self.recovery_transcript_root,
            "recovery_view_tag_root": self.recovery_view_tag_root,
            "expected_wallet_root": self.expected_wallet_root,
            "expected_note_root": self.expected_note_root,
            "shard_count": self.shard_count,
            "attestor_count": self.attestor_count,
            "pq_security_bits": self.pq_security_bits,
            "evidence_height": self.evidence_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("wallet-recovery-evidence", &self.public_record())
    }

    pub fn matches_expected(&self) -> bool {
        self.recovered_wallet_root == self.expected_wallet_root
            && self.recovered_note_root == self.expected_note_root
    }

    pub fn sufficient_for(&self, config: &Config) -> bool {
        self.shard_count >= config.min_wallet_recovery_shards
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.matches_expected()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceipt {
    pub receipt_id: String,
    pub claim_id: String,
    pub observer_id: String,
    pub receipt_root: String,
    pub amount_atomic: u64,
    pub release_fee_atomic: u64,
    pub destination_commitment: String,
    pub exit_nullifier: String,
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
    pub pq_security_bits: u16,
}

impl ObservedReceipt {
    pub fn new(
        claim_id: impl Into<String>,
        observer_id: impl Into<String>,
        receipt_root: impl Into<String>,
        amount_atomic: u64,
        release_fee_atomic: u64,
        destination_commitment: impl Into<String>,
        exit_nullifier: impl Into<String>,
        observed_l2_height: u64,
        observed_monero_height: u64,
        pq_security_bits: u16,
    ) -> Self {
        let claim_id = claim_id.into();
        let observer_id = observer_id.into();
        let receipt_root = receipt_root.into();
        let destination_commitment = destination_commitment.into();
        let exit_nullifier = exit_nullifier.into();
        let receipt_id = domain_hash(
            &domain("observed-receipt-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&claim_id),
                HashPart::Str(&observer_id),
                HashPart::Str(&receipt_root),
                HashPart::U64(amount_atomic),
                HashPart::U64(release_fee_atomic),
                HashPart::Str(&destination_commitment),
                HashPart::Str(&exit_nullifier),
            ],
            32,
        );

        Self {
            receipt_id,
            claim_id,
            observer_id,
            receipt_root,
            amount_atomic,
            release_fee_atomic,
            destination_commitment,
            exit_nullifier,
            observed_l2_height,
            observed_monero_height,
            pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "observer_id": self.observer_id,
            "receipt_root": self.receipt_root,
            "amount_atomic": self.amount_atomic,
            "release_fee_atomic": self.release_fee_atomic,
            "destination_commitment": self.destination_commitment,
            "exit_nullifier": self.exit_nullifier,
            "observed_l2_height": self.observed_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn root(&self) -> String {
        record_root("observed-receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptSet {
    pub claim_id: String,
    pub expected_amount_atomic: u64,
    pub expected_destination_commitment: String,
    pub expected_exit_nullifier: String,
    pub receipts: BTreeMap<String, ObservedReceipt>,
}

impl ReceiptSet {
    pub fn new(
        claim_id: impl Into<String>,
        expected_amount_atomic: u64,
        expected_destination_commitment: impl Into<String>,
        expected_exit_nullifier: impl Into<String>,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            expected_amount_atomic,
            expected_destination_commitment: expected_destination_commitment.into(),
            expected_exit_nullifier: expected_exit_nullifier.into(),
            receipts: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, receipt: ObservedReceipt) -> Result<()> {
        if receipt.claim_id != self.claim_id {
            return Err("receipt claim id does not match receipt set".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn observed_count(&self) -> u16 {
        bounded_u16(self.receipts.len())
    }

    pub fn max_release_fee_atomic(&self) -> u64 {
        self.receipts
            .values()
            .map(|receipt| receipt.release_fee_atomic)
            .max()
            .map_or(0, identity_u64)
    }

    pub fn has_amount_mismatch(&self) -> bool {
        self.receipts
            .values()
            .any(|receipt| receipt.amount_atomic != self.expected_amount_atomic)
    }

    pub fn has_destination_mismatch(&self) -> bool {
        self.receipts
            .values()
            .any(|receipt| receipt.destination_commitment != self.expected_destination_commitment)
    }

    pub fn has_nullifier_mismatch(&self) -> bool {
        self.receipts
            .values()
            .any(|receipt| receipt.exit_nullifier != self.expected_exit_nullifier)
    }

    pub fn min_pq_security_bits(&self) -> u16 {
        self.receipts
            .values()
            .map(|receipt| receipt.pq_security_bits)
            .min()
            .map_or(0, identity_u16)
    }

    pub fn public_record(&self) -> Value {
        let receipts: Vec<Value> = self
            .receipts
            .values()
            .map(ObservedReceipt::public_record)
            .collect();
        json!({
            "claim_id": self.claim_id,
            "expected_amount_atomic": self.expected_amount_atomic,
            "expected_destination_commitment": self.expected_destination_commitment,
            "expected_exit_nullifier": self.expected_exit_nullifier,
            "observed_count": self.observed_count(),
            "receipts": receipts,
        })
    }

    pub fn root(&self) -> String {
        let receipt_roots: Vec<String> =
            self.receipts.values().map(ObservedReceipt::root).collect();
        domain_hash(
            &domain("receipt-set"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.claim_id),
                HashPart::U64(self.expected_amount_atomic),
                HashPart::Str(&self.expected_destination_commitment),
                HashPart::Str(&self.expected_exit_nullifier),
                HashPart::Str(&merkle_root(receipt_roots)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindow {
    pub claim_id: String,
    pub opened_l2_height: u64,
    pub closed_l2_height: u64,
    pub current_l2_height: u64,
    pub active_challenge_root: String,
    pub resolved_challenge_root: String,
    pub challenge_count: u16,
    pub resolved_challenge_count: u16,
}

impl ChallengeWindow {
    pub fn is_closed(&self) -> bool {
        self.current_l2_height >= self.closed_l2_height
            && self.challenge_count == self.resolved_challenge_count
    }

    pub fn remaining_blocks(&self) -> u64 {
        self.closed_l2_height.saturating_sub(self.current_l2_height)
    }

    pub fn has_active_challenge(&self) -> bool {
        self.challenge_count != self.resolved_challenge_count
            || self.active_challenge_root != self.resolved_challenge_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "opened_l2_height": self.opened_l2_height,
            "closed_l2_height": self.closed_l2_height,
            "current_l2_height": self.current_l2_height,
            "remaining_blocks": self.remaining_blocks(),
            "active_challenge_root": self.active_challenge_root,
            "resolved_challenge_root": self.resolved_challenge_root,
            "challenge_count": self.challenge_count,
            "resolved_challenge_count": self.resolved_challenge_count,
            "closed": self.is_closed(),
            "active_challenge": self.has_active_challenge(),
        })
    }

    pub fn root(&self) -> String {
        record_root("challenge-window", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementStep {
    pub order_index: u64,
    pub settlement_id: String,
    pub claim_id: String,
    pub direction: SettlementDirection,
    pub settlement_root: String,
    pub amount_atomic: u64,
    pub confirmation_height: u64,
    pub confirmations: u64,
    pub predecessor_root: String,
}

impl SettlementStep {
    pub fn new(
        order_index: u64,
        claim_id: impl Into<String>,
        direction: SettlementDirection,
        settlement_root: impl Into<String>,
        amount_atomic: u64,
        confirmation_height: u64,
        confirmations: u64,
        predecessor_root: impl Into<String>,
    ) -> Self {
        let claim_id = claim_id.into();
        let settlement_root = settlement_root.into();
        let predecessor_root = predecessor_root.into();
        let settlement_id = domain_hash(
            &domain("settlement-step-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(order_index),
                HashPart::Str(&claim_id),
                HashPart::Str(direction.as_str()),
                HashPart::Str(&settlement_root),
                HashPart::U64(amount_atomic),
                HashPart::Str(&predecessor_root),
            ],
            32,
        );

        Self {
            order_index,
            settlement_id,
            claim_id,
            direction,
            settlement_root,
            amount_atomic,
            confirmation_height,
            confirmations,
            predecessor_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_index": self.order_index,
            "settlement_id": self.settlement_id,
            "claim_id": self.claim_id,
            "direction": self.direction.as_str(),
            "settlement_root": self.settlement_root,
            "amount_atomic": self.amount_atomic,
            "confirmation_height": self.confirmation_height,
            "confirmations": self.confirmations,
            "predecessor_root": self.predecessor_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("settlement-step", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementOrdering {
    pub claim_id: String,
    pub expected_first_root: String,
    pub steps: BTreeMap<u64, SettlementStep>,
}

impl SettlementOrdering {
    pub fn new(claim_id: impl Into<String>, expected_first_root: impl Into<String>) -> Self {
        Self {
            claim_id: claim_id.into(),
            expected_first_root: expected_first_root.into(),
            steps: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, step: SettlementStep) -> Result<()> {
        if step.claim_id != self.claim_id {
            return Err("settlement step claim id does not match ordering".to_string());
        }
        self.steps.insert(step.order_index, step);
        Ok(())
    }

    pub fn first_root(&self) -> String {
        self.steps
            .values()
            .next()
            .map(SettlementStep::root)
            .map_or_else(empty_root, identity_string)
    }

    pub fn final_root(&self) -> String {
        self.steps
            .values()
            .last()
            .map(SettlementStep::root)
            .map_or_else(empty_root, identity_string)
    }

    pub fn in_order(&self) -> bool {
        let mut expected_index = 0_u64;
        let mut previous_root = self.expected_first_root.clone();
        for (index, step) in &self.steps {
            if *index != expected_index || step.predecessor_root != previous_root {
                return false;
            }
            previous_root = step.root();
            expected_index = expected_index.saturating_add(1);
        }
        true
    }

    pub fn min_confirmations(&self) -> u64 {
        self.steps
            .values()
            .map(|step| step.confirmations)
            .min()
            .map_or(0, identity_u64)
    }

    pub fn release_amount_atomic(&self) -> u64 {
        self.steps
            .values()
            .filter(|step| step.direction == SettlementDirection::PrivateExitRelease)
            .map(|step| step.amount_atomic)
            .sum()
    }

    pub fn public_record(&self) -> Value {
        let steps: Vec<Value> = self
            .steps
            .values()
            .map(SettlementStep::public_record)
            .collect();
        json!({
            "claim_id": self.claim_id,
            "expected_first_root": self.expected_first_root,
            "first_root": self.first_root(),
            "final_root": self.final_root(),
            "in_order": self.in_order(),
            "min_confirmations": self.min_confirmations(),
            "release_amount_atomic": self.release_amount_atomic(),
            "steps": steps,
        })
    }

    pub fn root(&self) -> String {
        let step_roots: Vec<String> = self.steps.values().map(SettlementStep::root).collect();
        domain_hash(
            &domain("settlement-ordering"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.expected_first_root),
                HashPart::Str(&merkle_root(step_roots)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLedger {
    pub claim_id: String,
    pub reserve_root: String,
    pub available_atomic: u64,
    pub pending_release_atomic: u64,
    pub required_release_atomic: u64,
    pub fee_budget_atomic: u64,
    pub reserved_after_release_atomic: u64,
}

impl ReserveLedger {
    pub fn coverage_bps(&self) -> u64 {
        if self.required_release_atomic == 0 {
            return 0;
        }
        self.available_atomic
            .saturating_mul(10_000)
            .saturating_div(self.required_release_atomic)
    }

    pub fn sufficient_for(&self, config: &Config) -> bool {
        self.coverage_bps() >= config.min_reserve_coverage_bps
            && self.available_atomic
                >= self
                    .required_release_atomic
                    .saturating_add(self.pending_release_atomic)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "reserve_root": self.reserve_root,
            "available_atomic": self.available_atomic,
            "pending_release_atomic": self.pending_release_atomic,
            "required_release_atomic": self.required_release_atomic,
            "fee_budget_atomic": self.fee_budget_atomic,
            "reserved_after_release_atomic": self.reserved_after_release_atomic,
            "coverage_bps": self.coverage_bps(),
        })
    }

    pub fn root(&self) -> String {
        record_root("reserve-ledger", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseMismatch {
    pub mismatch_id: String,
    pub claim_id: String,
    pub kind: BlockerKind,
    pub expected_root: String,
    pub observed_root: String,
    pub blocking: bool,
    pub note: String,
}

impl ReleaseMismatch {
    pub fn new(
        claim_id: impl Into<String>,
        kind: BlockerKind,
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        blocking: bool,
        note: impl Into<String>,
    ) -> Self {
        let claim_id = claim_id.into();
        let expected_root = expected_root.into();
        let observed_root = observed_root.into();
        let note = note.into();
        let mismatch_id = domain_hash(
            &domain("release-mismatch-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&claim_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&expected_root),
                HashPart::Str(&observed_root),
                HashPart::Json(&json!({ "blocking": blocking })),
            ],
            32,
        );

        Self {
            mismatch_id,
            claim_id,
            kind,
            expected_root,
            observed_root,
            blocking,
            note,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "claim_id": self.claim_id,
            "kind": self.kind.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "blocking": self.blocking,
            "note": self.note,
        })
    }

    pub fn root(&self) -> String {
        record_root("release-mismatch", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseBlocker {
    pub blocker_id: String,
    pub claim_id: String,
    pub stage: AcceptanceStage,
    pub kind: BlockerKind,
    pub severity: u8,
    pub observed_root: String,
    pub detail: String,
}

impl ReleaseBlocker {
    pub fn new(
        claim_id: impl Into<String>,
        stage: AcceptanceStage,
        kind: BlockerKind,
        severity: u8,
        observed_root: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let claim_id = claim_id.into();
        let observed_root = observed_root.into();
        let detail = detail.into();
        let blocker_id = domain_hash(
            &domain("release-blocker-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&claim_id),
                HashPart::Str(stage.as_str()),
                HashPart::Str(kind.as_str()),
                HashPart::U64(u64::from(severity)),
                HashPart::Str(&observed_root),
            ],
            32,
        );

        Self {
            blocker_id,
            claim_id,
            stage,
            kind,
            severity,
            observed_root,
            detail,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "claim_id": self.claim_id,
            "stage": self.stage.as_str(),
            "kind": self.kind.as_str(),
            "severity": self.severity,
            "observed_root": self.observed_root,
            "detail": self.detail,
        })
    }

    pub fn root(&self) -> String {
        record_root("release-blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptanceGate {
    pub stage: AcceptanceStage,
    pub accepted: bool,
    pub blocker_count: u16,
    pub evidence_root: String,
}

impl AcceptanceGate {
    pub fn public_record(&self) -> Value {
        json!({
            "stage": self.stage.as_str(),
            "stage_ordinal": self.stage.ordinal(),
            "accepted": self.accepted,
            "blocker_count": self.blocker_count,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("acceptance-gate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseAcceptanceRecord {
    pub claim_id: String,
    pub verdict: AcceptanceVerdict,
    pub accepted_release_amount_atomic: u64,
    pub release_fee_atomic: u64,
    pub wallet_recovery_root: String,
    pub receipt_set_root: String,
    pub challenge_window_root: String,
    pub settlement_ordering_root: String,
    pub reserve_ledger_root: String,
    pub mismatch_root: String,
    pub blocker_root: String,
    pub gate_root: String,
    pub acceptance_root: String,
}

impl ReleaseAcceptanceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "verdict": self.verdict.as_str(),
            "accepted_release_amount_atomic": self.accepted_release_amount_atomic,
            "release_fee_atomic": self.release_fee_atomic,
            "wallet_recovery_root": self.wallet_recovery_root,
            "receipt_set_root": self.receipt_set_root,
            "challenge_window_root": self.challenge_window_root,
            "settlement_ordering_root": self.settlement_ordering_root,
            "reserve_ledger_root": self.reserve_ledger_root,
            "mismatch_root": self.mismatch_root,
            "blocker_root": self.blocker_root,
            "gate_root": self.gate_root,
            "acceptance_root": self.acceptance_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("release-acceptance-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseCase {
    pub claim_id: String,
    pub wallet_recovery: WalletRecoveryEvidence,
    pub receipt_set: ReceiptSet,
    pub challenge_window: ChallengeWindow,
    pub settlement_ordering: SettlementOrdering,
    pub reserve_ledger: ReserveLedger,
    pub mismatches: BTreeMap<String, ReleaseMismatch>,
    pub policy_hold: bool,
}

impl ReleaseCase {
    pub fn evaluate(&self, config: &Config) -> ReleaseAcceptanceRecord {
        let blockers = self.blockers(config);
        let gates = self.gates(config, &blockers);
        let verdict = if blockers.is_empty() {
            AcceptanceVerdict::AcceptedForRelease
        } else if blockers.values().any(|blocker| blocker.severity >= 9) {
            AcceptanceVerdict::Rejected
        } else {
            AcceptanceVerdict::Deferred
        };
        let mismatch_roots: Vec<String> = self
            .mismatches
            .values()
            .map(ReleaseMismatch::root)
            .collect();
        let blocker_roots: Vec<String> = blockers.values().map(ReleaseBlocker::root).collect();
        let gate_roots: Vec<String> = gates.values().map(AcceptanceGate::root).collect();
        let wallet_recovery_root = self.wallet_recovery.root();
        let receipt_set_root = self.receipt_set.root();
        let challenge_window_root = self.challenge_window.root();
        let settlement_ordering_root = self.settlement_ordering.root();
        let reserve_ledger_root = self.reserve_ledger.root();
        let mismatch_root = merkle_root(mismatch_roots);
        let blocker_root = merkle_root(blocker_roots);
        let gate_root = merkle_root(gate_roots);
        let accepted_release_amount_atomic = if verdict == AcceptanceVerdict::AcceptedForRelease {
            self.settlement_ordering.release_amount_atomic()
        } else {
            0
        };
        let release_fee_atomic = if verdict == AcceptanceVerdict::AcceptedForRelease {
            self.receipt_set.max_release_fee_atomic()
        } else {
            0
        };
        let acceptance_root = domain_hash(
            &domain("release-acceptance-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.claim_id),
                HashPart::Str(verdict.as_str()),
                HashPart::U64(accepted_release_amount_atomic),
                HashPart::U64(release_fee_atomic),
                HashPart::Str(&wallet_recovery_root),
                HashPart::Str(&receipt_set_root),
                HashPart::Str(&challenge_window_root),
                HashPart::Str(&settlement_ordering_root),
                HashPart::Str(&reserve_ledger_root),
                HashPart::Str(&mismatch_root),
                HashPart::Str(&blocker_root),
                HashPart::Str(&gate_root),
            ],
            32,
        );

        ReleaseAcceptanceRecord {
            claim_id: self.claim_id.clone(),
            verdict,
            accepted_release_amount_atomic,
            release_fee_atomic,
            wallet_recovery_root,
            receipt_set_root,
            challenge_window_root,
            settlement_ordering_root,
            reserve_ledger_root,
            mismatch_root,
            blocker_root,
            gate_root,
            acceptance_root,
        }
    }

    pub fn blockers(&self, config: &Config) -> BTreeMap<String, ReleaseBlocker> {
        let mut blockers = BTreeMap::new();
        self.push_wallet_blockers(config, &mut blockers);
        self.push_receipt_blockers(config, &mut blockers);
        self.push_challenge_blockers(&mut blockers);
        self.push_settlement_blockers(config, &mut blockers);
        self.push_reserve_blockers(config, &mut blockers);
        self.push_mismatch_blockers(&mut blockers);
        if self.policy_hold || !config.production_release_allowed {
            insert_blocker(
                &mut blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ReleaseAcceptance,
                    BlockerKind::PolicyHold,
                    4,
                    self.reserve_ledger.root(),
                    "release remains in deterministic devnet hold",
                ),
            );
        }
        blockers
    }

    pub fn gates(
        &self,
        config: &Config,
        blockers: &BTreeMap<String, ReleaseBlocker>,
    ) -> BTreeMap<AcceptanceStage, AcceptanceGate> {
        let mut gates = BTreeMap::new();
        for stage in AcceptanceStage::all() {
            let blocker_count = bounded_u16(
                blockers
                    .values()
                    .filter(|blocker| blocker.stage == stage)
                    .count(),
            );
            let evidence_root = match stage {
                AcceptanceStage::WalletRecoveryEvidence => self.wallet_recovery.root(),
                AcceptanceStage::ObservedReceipts => self.receipt_set.root(),
                AcceptanceStage::ChallengeWindowClosure => self.challenge_window.root(),
                AcceptanceStage::SettlementOrdering => self.settlement_ordering.root(),
                AcceptanceStage::ReserveSufficiency => self.reserve_ledger.root(),
                AcceptanceStage::MismatchScreening => merkle_root(
                    self.mismatches
                        .values()
                        .map(ReleaseMismatch::root)
                        .collect(),
                ),
                AcceptanceStage::ReleaseAcceptance => domain_hash(
                    &domain("release-gate-policy"),
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&self.claim_id),
                        HashPart::Json(&json!({
                            "policy_hold": self.policy_hold,
                            "production_release_allowed": config.production_release_allowed,
                        })),
                    ],
                    32,
                ),
            };
            gates.insert(
                stage,
                AcceptanceGate {
                    stage,
                    accepted: blocker_count == 0,
                    blocker_count,
                    evidence_root,
                },
            );
        }
        gates
    }

    pub fn public_record(&self) -> Value {
        let mismatches: Vec<Value> = self
            .mismatches
            .values()
            .map(ReleaseMismatch::public_record)
            .collect();
        json!({
            "claim_id": self.claim_id,
            "wallet_recovery": self.wallet_recovery.public_record(),
            "receipt_set": self.receipt_set.public_record(),
            "challenge_window": self.challenge_window.public_record(),
            "settlement_ordering": self.settlement_ordering.public_record(),
            "reserve_ledger": self.reserve_ledger.public_record(),
            "mismatches": mismatches,
            "policy_hold": self.policy_hold,
        })
    }

    pub fn root(&self) -> String {
        record_root("release-case", &self.public_record())
    }

    fn push_wallet_blockers(
        &self,
        config: &Config,
        blockers: &mut BTreeMap<String, ReleaseBlocker>,
    ) {
        if self.wallet_recovery.shard_count == 0 {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::WalletRecoveryEvidence,
                    BlockerKind::WalletRecoveryMissing,
                    10,
                    self.wallet_recovery.root(),
                    "no wallet recovery shards were admitted",
                ),
            );
        }
        if self.wallet_recovery.shard_count < config.min_wallet_recovery_shards
            || self.wallet_recovery.pq_security_bits < config.min_pq_security_bits
        {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::WalletRecoveryEvidence,
                    BlockerKind::WalletRecoveryInsufficient,
                    8,
                    self.wallet_recovery.root(),
                    "wallet recovery evidence does not meet shard or pq thresholds",
                ),
            );
        }
        if !self.wallet_recovery.matches_expected() {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::WalletRecoveryEvidence,
                    BlockerKind::WalletRecoveryMismatched,
                    10,
                    self.wallet_recovery.root(),
                    "recovered wallet or note root diverges from the claim binding",
                ),
            );
        }
    }

    fn push_receipt_blockers(
        &self,
        config: &Config,
        blockers: &mut BTreeMap<String, ReleaseBlocker>,
    ) {
        if self.receipt_set.observed_count() < config.min_observed_receipts {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ObservedReceipts,
                    BlockerKind::ReceiptQuorumMissing,
                    8,
                    self.receipt_set.root(),
                    "observed receipt quorum has not been reached",
                ),
            );
        }
        if self.receipt_set.has_amount_mismatch() {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ObservedReceipts,
                    BlockerKind::ReceiptAmountMismatch,
                    10,
                    self.receipt_set.root(),
                    "at least one observed receipt reports a different amount",
                ),
            );
        }
        if self.receipt_set.has_destination_mismatch() {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ObservedReceipts,
                    BlockerKind::ReceiptDestinationMismatch,
                    10,
                    self.receipt_set.root(),
                    "at least one observed receipt reports a different destination",
                ),
            );
        }
        if self.receipt_set.has_nullifier_mismatch() {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::MismatchScreening,
                    BlockerKind::ReleaseNullifierMismatch,
                    10,
                    self.receipt_set.root(),
                    "at least one observed receipt reports a different exit nullifier",
                ),
            );
        }
        if self.receipt_set.min_pq_security_bits() < config.min_pq_security_bits {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ObservedReceipts,
                    BlockerKind::ReceiptQuorumMissing,
                    8,
                    self.receipt_set.root(),
                    "receipt quorum does not meet pq security threshold",
                ),
            );
        }
        if self.receipt_set.max_release_fee_atomic() > config.max_release_fee_atomic {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ReserveSufficiency,
                    BlockerKind::FeeCapExceeded,
                    8,
                    self.receipt_set.root(),
                    "observed release fee exceeds configured cap",
                ),
            );
        }
    }

    fn push_challenge_blockers(&self, blockers: &mut BTreeMap<String, ReleaseBlocker>) {
        if !self.challenge_window.is_closed() {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ChallengeWindowClosure,
                    BlockerKind::ChallengeWindowOpen,
                    7,
                    self.challenge_window.root(),
                    "challenge window has not fully closed",
                ),
            );
        }
        if self.challenge_window.has_active_challenge() {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ChallengeWindowClosure,
                    BlockerKind::ActiveChallengeRecorded,
                    10,
                    self.challenge_window.root(),
                    "active challenge root differs from resolved challenge root",
                ),
            );
        }
    }

    fn push_settlement_blockers(
        &self,
        config: &Config,
        blockers: &mut BTreeMap<String, ReleaseBlocker>,
    ) {
        if !self.settlement_ordering.in_order() {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::SettlementOrdering,
                    BlockerKind::SettlementOutOfOrder,
                    10,
                    self.settlement_ordering.root(),
                    "settlement chain does not match expected predecessor ordering",
                ),
            );
        }
        if self.settlement_ordering.min_confirmations() < config.min_settlement_confirmations {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::SettlementOrdering,
                    BlockerKind::SettlementReceiptUnconfirmed,
                    7,
                    self.settlement_ordering.root(),
                    "settlement receipt confirmation threshold has not been reached",
                ),
            );
        }
    }

    fn push_reserve_blockers(
        &self,
        config: &Config,
        blockers: &mut BTreeMap<String, ReleaseBlocker>,
    ) {
        if !self.reserve_ledger.sufficient_for(config) {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::ReserveSufficiency,
                    BlockerKind::ReserveCoverageInsufficient,
                    9,
                    self.reserve_ledger.root(),
                    "reserve ledger cannot cover required and pending releases",
                ),
            );
        }
    }

    fn push_mismatch_blockers(&self, blockers: &mut BTreeMap<String, ReleaseBlocker>) {
        for mismatch in self
            .mismatches
            .values()
            .filter(|mismatch| mismatch.blocking)
        {
            insert_blocker(
                blockers,
                ReleaseBlocker::new(
                    self.claim_id.clone(),
                    AcceptanceStage::MismatchScreening,
                    mismatch.kind,
                    10,
                    mismatch.root(),
                    mismatch.note.clone(),
                ),
            );
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: BTreeMap<String, ReleaseCase>,
    pub acceptance_records: BTreeMap<String, ReleaseAcceptanceRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut cases = BTreeMap::new();
        let accepted = sample_release_case("accepted-alpha", false, true, &config);
        let deferred = sample_release_case("deferred-policy", true, false, &config);
        cases.insert(accepted.claim_id.clone(), accepted);
        cases.insert(deferred.claim_id.clone(), deferred);
        let mut state = Self {
            config,
            cases,
            acceptance_records: BTreeMap::new(),
        };
        state.recompute_acceptance_records();
        state
    }

    pub fn recompute_acceptance_records(&mut self) {
        self.acceptance_records.clear();
        for case in self.cases.values() {
            let record = case.evaluate(&self.config);
            self.acceptance_records
                .insert(record.claim_id.clone(), record);
        }
    }

    pub fn public_record(&self) -> Value {
        let cases: Vec<Value> = self
            .cases
            .values()
            .map(ReleaseCase::public_record)
            .collect();
        let acceptance_records: Vec<Value> = self
            .acceptance_records
            .values()
            .map(ReleaseAcceptanceRecord::public_record)
            .collect();
        json!({
            "config": self.config.public_record(),
            "case_count": self.cases.len(),
            "acceptance_record_count": self.acceptance_records.len(),
            "cases": cases,
            "acceptance_records": acceptance_records,
        })
    }

    pub fn state_root(&self) -> String {
        let case_roots: Vec<String> = self.cases.values().map(ReleaseCase::root).collect();
        let acceptance_roots: Vec<String> = self
            .acceptance_records
            .values()
            .map(ReleaseAcceptanceRecord::root)
            .collect();
        domain_hash(
            &domain("state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&merkle_root(case_roots)),
                HashPart::Str(&merkle_root(acceptance_roots)),
            ],
            32,
        )
    }

    pub fn acceptance_for(&self, claim_id: &str) -> Result<&ReleaseAcceptanceRecord> {
        self.acceptance_records
            .get(claim_id)
            .ok_or_else(|| "acceptance record not found".to_string())
    }

    pub fn insert_case(&mut self, case: ReleaseCase) -> Result<()> {
        if case.claim_id != case.wallet_recovery.claim_id
            || case.claim_id != case.receipt_set.claim_id
            || case.claim_id != case.challenge_window.claim_id
            || case.claim_id != case.settlement_ordering.claim_id
            || case.claim_id != case.reserve_ledger.claim_id
        {
            return Err("release case components must share claim id".to_string());
        }
        let record = case.evaluate(&self.config);
        self.acceptance_records
            .insert(record.claim_id.clone(), record);
        self.cases.insert(case.claim_id.clone(), case);
        Ok(())
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

fn sample_release_case(
    label: &str,
    policy_hold: bool,
    clean: bool,
    config: &Config,
) -> ReleaseCase {
    let claim_id = labeled_root("claim", label);
    let wallet_root = labeled_root("wallet", label);
    let note_root = labeled_root("note", label);
    let destination = labeled_root("destination", label);
    let nullifier = labeled_root("nullifier", label);
    let amount = 7_500_000_000_000_u64;
    let wallet_recovery = WalletRecoveryEvidence {
        claim_id: claim_id.clone(),
        recovered_wallet_root: wallet_root.clone(),
        recovered_note_root: note_root.clone(),
        recovery_transcript_root: labeled_root("recovery-transcript", label),
        recovery_view_tag_root: labeled_root("recovery-view-tags", label),
        expected_wallet_root: wallet_root.clone(),
        expected_note_root: if clean {
            note_root.clone()
        } else {
            labeled_root("different-note", label)
        },
        shard_count: config.min_wallet_recovery_shards,
        attestor_count: 4,
        pq_security_bits: config.min_pq_security_bits,
        evidence_height: config.reference_l2_height.saturating_sub(80),
    };
    let mut receipt_set = ReceiptSet::new(
        claim_id.clone(),
        amount,
        destination.clone(),
        nullifier.clone(),
    );
    let receipt_total = config.min_observed_receipts;
    for index in 0..receipt_total {
        let observed_destination = if clean || index != receipt_total.saturating_sub(1) {
            destination.clone()
        } else {
            labeled_root("different-destination", label)
        };
        let receipt = ObservedReceipt::new(
            claim_id.clone(),
            format!("observer-{}", index),
            labeled_root("receipt", &format!("{}-{}", label, index)),
            amount,
            12_500_000,
            observed_destination,
            nullifier.clone(),
            config
                .reference_l2_height
                .saturating_sub(24 + u64::from(index)),
            config
                .reference_monero_height
                .saturating_sub(18 + u64::from(index)),
            config.min_pq_security_bits,
        );
        let _ = receipt_set.insert(receipt);
    }
    let challenge_window = ChallengeWindow {
        claim_id: claim_id.clone(),
        opened_l2_height: config
            .reference_l2_height
            .saturating_sub(config.challenge_window_blocks)
            .saturating_sub(config.release_finality_blocks),
        closed_l2_height: config
            .reference_l2_height
            .saturating_sub(config.release_finality_blocks),
        current_l2_height: config.reference_l2_height,
        active_challenge_root: empty_root(),
        resolved_challenge_root: empty_root(),
        challenge_count: 0,
        resolved_challenge_count: 0,
    };
    let mut settlement_ordering = SettlementOrdering::new(claim_id.clone(), empty_root());
    let first = SettlementStep::new(
        0,
        claim_id.clone(),
        SettlementDirection::DepositReturn,
        labeled_root("settlement-deposit", label),
        300_000_000_000,
        config.reference_monero_height.saturating_sub(24),
        config.min_settlement_confirmations,
        empty_root(),
    );
    let first_root = first.root();
    let _ = settlement_ordering.insert(first);
    let release = SettlementStep::new(
        1,
        claim_id.clone(),
        SettlementDirection::PrivateExitRelease,
        labeled_root("settlement-release", label),
        amount,
        config.reference_monero_height.saturating_sub(23),
        config.min_settlement_confirmations.saturating_add(2),
        first_root,
    );
    let _ = settlement_ordering.insert(release);
    let reserve_ledger = ReserveLedger {
        claim_id: claim_id.clone(),
        reserve_root: labeled_root("reserve-ledger", label),
        available_atomic: amount.saturating_mul(2),
        pending_release_atomic: 0,
        required_release_atomic: amount,
        fee_budget_atomic: config.max_release_fee_atomic,
        reserved_after_release_atomic: amount,
    };
    let mut mismatches = BTreeMap::new();
    if !clean {
        let mismatch = ReleaseMismatch::new(
            claim_id.clone(),
            BlockerKind::ReleaseCommitmentMismatch,
            destination,
            labeled_root("different-destination", label),
            true,
            "release destination commitment differs from recovered wallet evidence",
        );
        mismatches.insert(mismatch.mismatch_id.clone(), mismatch);
    }

    ReleaseCase {
        claim_id,
        wallet_recovery,
        receipt_set,
        challenge_window,
        settlement_ordering,
        reserve_ledger,
        mismatches,
        policy_hold,
    }
}

fn insert_blocker(blockers: &mut BTreeMap<String, ReleaseBlocker>, blocker: ReleaseBlocker) {
    blockers.insert(blocker.blocker_id.clone(), blocker);
}

fn bounded_u16(value: usize) -> u16 {
    if value > usize::from(u16::MAX) {
        u16::MAX
    } else {
        value as u16
    }
}

fn identity_u16(value: u16) -> u16 {
    value
}

fn identity_u64(value: u64) -> u64 {
    value
}

fn identity_string(value: String) -> String {
    value
}

fn empty_root() -> String {
    domain_hash(
        &domain("empty-root"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn labeled_root(kind: &str, label: &str) -> String {
    domain_hash(
        &domain(kind),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn record_root(kind: &str, value: &Value) -> String {
    domain_hash(
        &domain(kind),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn domain(label: &str) -> String {
    format!("{}:{}", DOMAIN, label)
}
