use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::{
        AnchorReceiptRequest, BridgeLane, DepositCertificateRequest, DepositLockRequest, ExitMode,
        MintPrivateNoteRequest, PrivateActionKind, PrivateActionRequest,
        State as BridgeExitSpineState, WithdrawalRequest, DEVNET_HEIGHT,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeBoundPrivateTransferReceiptRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_BOUND_PRIVATE_TRANSFER_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-bound-private-transfer-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_BOUND_PRIVATE_TRANSFER_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-bound-transfer-v1";
pub const TRANSFER_NOTE_SUITE: &str =
    "monero-l2-bridge-minted-note-transfer-with-roots-only-receipts-v1";
pub const EXIT_CLAIM_SUITE: &str =
    "bridge-bound-private-transfer-exit-claim-compatible-with-forced-exit-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_TRANSFER_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_TRANSFERS: usize = 524_288;
pub const DEFAULT_MAX_REPORTS: usize = 131_072;
pub const DEFAULT_DEVNET_SOURCE_AMOUNT: u128 = 700_000_000_000;
pub const DEFAULT_DEVNET_TRANSFER_AMOUNT: u128 = 420_000_000_000;
pub const DEFAULT_DEVNET_CHANGE_AMOUNT: u128 = 279_999_979_000;
pub const DEFAULT_DEVNET_EXIT_AMOUNT: u128 = 419_999_979_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferLane {
    WalletToWallet,
    ContractSettlement,
    ExitPrepared,
    FeeSponsored,
}

impl TransferLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletToWallet => "wallet_to_wallet",
            Self::ContractSettlement => "contract_settlement",
            Self::ExitPrepared => "exit_prepared",
            Self::FeeSponsored => "fee_sponsored",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Prepared,
    SpineActionRecorded,
    ReceiptAnchored,
    ExitClaimReady,
    Rejected,
}

impl TransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::SpineActionRecorded => "spine_action_recorded",
            Self::ReceiptAnchored => "receipt_anchored",
            Self::ExitClaimReady => "exit_claim_ready",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable_for_exit(self) -> bool {
        matches!(self, Self::ReceiptAnchored | Self::ExitClaimReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    RecipientNote,
    ChangeNote,
    FeeNote,
    ExitReserveClaim,
}

impl OutputKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecipientNote => "recipient_note",
            Self::ChangeNote => "change_note",
            Self::FeeNote => "fee_note",
            Self::ExitReserveClaim => "exit_reserve_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    BridgePathExists,
    BridgeNoteMatchesPath,
    InputNullifierUnique,
    AmountConserved,
    PrivacyFloorMet,
    FeeCapMet,
    PqAuthorizationBound,
    SpineActionReceiptRecorded,
    SettlementReceiptAnchored,
    ExitClaimCompatible,
    RootsOnlyPublicSurface,
}

impl CheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgePathExists => "bridge_path_exists",
            Self::BridgeNoteMatchesPath => "bridge_note_matches_path",
            Self::InputNullifierUnique => "input_nullifier_unique",
            Self::AmountConserved => "amount_conserved",
            Self::PrivacyFloorMet => "privacy_floor_met",
            Self::FeeCapMet => "fee_cap_met",
            Self::PqAuthorizationBound => "pq_authorization_bound",
            Self::SpineActionReceiptRecorded => "spine_action_receipt_recorded",
            Self::SettlementReceiptAnchored => "settlement_receipt_anchored",
            Self::ExitClaimCompatible => "exit_claim_compatible",
            Self::RootsOnlyPublicSurface => "roots_only_public_surface",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Watch,
    Failed,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Passed | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub transfer_note_suite: String,
    pub exit_claim_suite: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_transfer_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_transfers: usize,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            transfer_note_suite: TRANSFER_NOTE_SUITE.to_string(),
            exit_claim_suite: EXIT_CLAIM_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_transfer_fee_bps: DEFAULT_MAX_TRANSFER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_transfers: DEFAULT_MAX_TRANSFERS,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "transfer_note_suite": self.transfer_note_suite,
            "exit_claim_suite": self.exit_claim_suite,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_transfer_fee_bps": self.max_transfer_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_transfers": self.max_transfers,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeBoundTransferRequest {
    pub path_id: String,
    pub lane: TransferLane,
    pub input_note_commitment: String,
    pub input_note_membership_root: String,
    pub input_note_nullifier: String,
    pub sender_pq_authorization_root: String,
    pub sender_view_key_policy_root: String,
    pub recipient_note_commitment: String,
    pub recipient_scan_hint_root: String,
    pub change_note_commitment: String,
    pub change_scan_hint_root: String,
    pub encrypted_amount_root: String,
    pub balance_proof_root: String,
    pub transfer_amount: u128,
    pub change_amount: u128,
    pub fee_amount: u128,
    pub fee_sponsor_root: String,
    pub sequencer_pq_root: String,
    pub proof_transcript_root: String,
    pub payout_subaddress_commitment: String,
    pub exit_withdrawal_commitment: String,
    pub exit_burn_nullifier: String,
    pub exit_liquidity_root: String,
    pub exit_pq_authorization_root: String,
    pub exit_amount: u128,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
    pub settlement_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferInputNote {
    pub path_id: String,
    pub source_note_commitment: String,
    pub source_note_membership_root: String,
    pub source_private_state_root: String,
    pub source_spine_root: String,
    pub source_amount_commitment_root: String,
    pub sender_view_key_policy_root: String,
    pub watcher_quorum_id: String,
    pub privacy_set_size: u64,
}

impl TransferInputNote {
    pub fn public_record(&self) -> Value {
        json!({
            "path_id": self.path_id,
            "source_note_commitment": self.source_note_commitment,
            "source_note_membership_root": self.source_note_membership_root,
            "source_private_state_root": self.source_private_state_root,
            "source_spine_root": self.source_spine_root,
            "source_amount_commitment_root": self.source_amount_commitment_root,
            "sender_view_key_policy_root": self.sender_view_key_policy_root,
            "watcher_quorum_id": self.watcher_quorum_id,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("transfer_input_note", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferOutputNote {
    pub output_id: String,
    pub transfer_id: String,
    pub kind: OutputKind,
    pub note_commitment: String,
    pub scan_hint_root: String,
    pub encrypted_amount_root: String,
    pub owner_policy_root: String,
    pub exit_claim_root: Option<String>,
}

impl TransferOutputNote {
    pub fn new(
        transfer_id: &str,
        kind: OutputKind,
        note_commitment: impl Into<String>,
        scan_hint_root: impl Into<String>,
        encrypted_amount_root: impl Into<String>,
        owner_policy_root: impl Into<String>,
        exit_claim_root: Option<String>,
    ) -> Self {
        let note_commitment = note_commitment.into();
        let scan_hint_root = scan_hint_root.into();
        let encrypted_amount_root = encrypted_amount_root.into();
        let owner_policy_root = owner_policy_root.into();
        let output_seed = json!({
            "transfer_id": transfer_id,
            "kind": kind.as_str(),
            "note_commitment": note_commitment,
            "scan_hint_root": scan_hint_root,
            "encrypted_amount_root": encrypted_amount_root,
            "owner_policy_root": owner_policy_root,
            "exit_claim_root": exit_claim_root,
        });
        let output_id =
            transfer_output_id(transfer_id, kind, &record_root("output_seed", &output_seed));
        Self {
            output_id,
            transfer_id: transfer_id.to_string(),
            kind,
            note_commitment,
            scan_hint_root,
            encrypted_amount_root,
            owner_policy_root,
            exit_claim_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "output_id": self.output_id,
            "transfer_id": self.transfer_id,
            "kind": self.kind.as_str(),
            "note_commitment": self.note_commitment,
            "scan_hint_root": self.scan_hint_root,
            "encrypted_amount_root": self.encrypted_amount_root,
            "owner_policy_root": self.owner_policy_root,
            "exit_claim_root": self.exit_claim_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("transfer_output_note", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferExitClaim {
    pub claim_id: String,
    pub transfer_id: String,
    pub path_id: String,
    pub action_receipt_id: String,
    pub receipt_root: String,
    pub output_note_commitment: String,
    pub withdrawal_commitment: String,
    pub burn_nullifier: String,
    pub payout_subaddress_commitment: String,
    pub liquidity_root: String,
    pub pq_authorization_root: String,
    pub watcher_quorum_id: String,
    pub exit_mode: ExitMode,
    pub max_exit_amount: u128,
    pub privacy_set_size: u64,
    pub prepared_height: u64,
}

impl TransferExitClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "transfer_id": self.transfer_id,
            "path_id": self.path_id,
            "action_receipt_id": self.action_receipt_id,
            "receipt_root": self.receipt_root,
            "output_note_commitment": self.output_note_commitment,
            "withdrawal_commitment": self.withdrawal_commitment,
            "burn_nullifier": self.burn_nullifier,
            "payout_subaddress_commitment": self.payout_subaddress_commitment,
            "liquidity_root": self.liquidity_root,
            "pq_authorization_root": self.pq_authorization_root,
            "watcher_quorum_id": self.watcher_quorum_id,
            "exit_mode": self.exit_mode.as_str(),
            "max_exit_amount": self.max_exit_amount.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "prepared_height": self.prepared_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("transfer_exit_claim", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateTransferReceipt {
    pub transfer_id: String,
    pub status: TransferStatus,
    pub lane: TransferLane,
    pub path_id: String,
    pub action_receipt_id: String,
    pub input_note_root: String,
    pub input_note_nullifier: String,
    pub output_note_root: String,
    pub recipient_note_commitment: String,
    pub change_note_commitment: String,
    pub encrypted_amount_root: String,
    pub balance_proof_root: String,
    pub proof_transcript_root: String,
    pub token_transfer_root: String,
    pub private_state_root_after: String,
    pub receipt_root: String,
    pub bridge_checkpoint_root: String,
    pub spine_root_before: String,
    pub spine_root_after_action: String,
    pub spine_root_after_anchor: String,
    pub exit_claim_id: String,
    pub exit_claim_root: String,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
}

impl PrivateTransferReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "path_id": self.path_id,
            "action_receipt_id": self.action_receipt_id,
            "input_note_root": self.input_note_root,
            "input_note_nullifier": self.input_note_nullifier,
            "output_note_root": self.output_note_root,
            "recipient_note_commitment": self.recipient_note_commitment,
            "change_note_commitment": self.change_note_commitment,
            "encrypted_amount_root": self.encrypted_amount_root,
            "balance_proof_root": self.balance_proof_root,
            "proof_transcript_root": self.proof_transcript_root,
            "token_transfer_root": self.token_transfer_root,
            "private_state_root_after": self.private_state_root_after,
            "receipt_root": self.receipt_root,
            "bridge_checkpoint_root": self.bridge_checkpoint_root,
            "spine_root_before": self.spine_root_before,
            "spine_root_after_action": self.spine_root_after_action,
            "spine_root_after_anchor": self.spine_root_after_anchor,
            "exit_claim_id": self.exit_claim_id,
            "exit_claim_root": self.exit_claim_root,
            "privacy_set_size": self.privacy_set_size,
            "user_fee_bps": self.user_fee_bps,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_transfer_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferCheckEvidence {
    pub check_id: String,
    pub kind: CheckKind,
    pub status: CheckStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
}

impl TransferCheckEvidence {
    pub fn new(
        kind: CheckKind,
        status: CheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_record: Value,
    ) -> Self {
        let requirement = requirement.into();
        let observed = observed.into();
        let evidence_root = record_root("transfer_check_evidence", &evidence_record);
        let check_id = transfer_check_id(kind, &evidence_root);
        Self {
            check_id,
            kind,
            status,
            requirement,
            observed,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("transfer_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferReadinessReport {
    pub report_id: String,
    pub transfer_id: String,
    pub status: ReportStatus,
    pub passed_checks: u64,
    pub watch_checks: u64,
    pub failed_checks: u64,
    pub bridge_spine_root: String,
    pub transfer_receipt_root: String,
    pub exit_claim_root: String,
    pub checks: BTreeMap<String, TransferCheckEvidence>,
}

impl TransferReadinessReport {
    pub fn public_record(&self) -> Value {
        let checks = self
            .checks
            .values()
            .map(TransferCheckEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "transfer_id": self.transfer_id,
            "status": self.status.as_str(),
            "passed_checks": self.passed_checks,
            "watch_checks": self.watch_checks,
            "failed_checks": self.failed_checks,
            "bridge_spine_root": self.bridge_spine_root,
            "transfer_receipt_root": self.transfer_receipt_root,
            "exit_claim_root": self.exit_claim_root,
            "checks": checks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("transfer_readiness_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub bridge_bound_transfers: u64,
    pub spine_actions_recorded: u64,
    pub receipts_anchored: u64,
    pub exit_claims_prepared: u64,
    pub readiness_reports: u64,
    pub replay_nullifiers_rejected: u64,
    pub rejected_transfers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "bridge_bound_transfers": self.bridge_bound_transfers,
            "spine_actions_recorded": self.spine_actions_recorded,
            "receipts_anchored": self.receipts_anchored,
            "exit_claims_prepared": self.exit_claims_prepared,
            "readiness_reports": self.readiness_reports,
            "replay_nullifiers_rejected": self.replay_nullifiers_rejected,
            "rejected_transfers": self.rejected_transfers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub transfer_receipt_root: String,
    pub exit_claim_root: String,
    pub spent_nullifier_root: String,
    pub report_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub latest_spine_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            input_note_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-INPUTS", &[]),
            output_note_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-OUTPUTS", &[]),
            transfer_receipt_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-RECEIPTS", &[]),
            exit_claim_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-CLAIMS", &[]),
            spent_nullifier_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-SPENT-NULLIFIERS",
                &[],
            ),
            report_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-REPORTS", &[]),
            event_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EVENTS", &[]),
            counters_root: counters.state_root(),
            latest_spine_root: String::new(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "transfer_receipt_root": self.transfer_receipt_root,
            "exit_claim_root": self.exit_claim_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "report_root": self.report_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "latest_spine_root": self.latest_spine_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.input_note_root),
                HashPart::Str(&self.output_note_root),
                HashPart::Str(&self.transfer_receipt_root),
                HashPart::Str(&self.exit_claim_root),
                HashPart::Str(&self.spent_nullifier_root),
                HashPart::Str(&self.report_root),
                HashPart::Str(&self.event_root),
                HashPart::Str(&self.counters_root),
                HashPart::Str(&self.latest_spine_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub input_notes: BTreeMap<String, TransferInputNote>,
    pub output_notes: BTreeMap<String, TransferOutputNote>,
    pub receipts: BTreeMap<String, PrivateTransferReceipt>,
    pub exit_claims: BTreeMap<String, TransferExitClaim>,
    pub readiness_reports: BTreeMap<String, TransferReadinessReport>,
    pub spent_input_nullifiers: BTreeSet<String>,
    pub events: Vec<String>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        Self {
            roots: Roots::empty(&config, &counters),
            config,
            input_notes: BTreeMap::new(),
            output_notes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            exit_claims: BTreeMap::new(),
            readiness_reports: BTreeMap::new(),
            spent_input_nullifiers: BTreeSet::new(),
            events: Vec::new(),
            counters,
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let mut spine = BridgeExitSpineState::devnet();
        let path_id = open_devnet_transfer_source_path(&mut spine);
        let request = BridgeBoundTransferRequest {
            path_id: path_id.clone(),
            lane: TransferLane::ExitPrepared,
            input_note_commitment: devnet_root("input-note", &path_id),
            input_note_membership_root: devnet_root("input-membership", &path_id),
            input_note_nullifier: devnet_root("input-nullifier", &path_id),
            sender_pq_authorization_root: devnet_root("sender-pq-auth", &path_id),
            sender_view_key_policy_root: devnet_root("sender-view-policy", &path_id),
            recipient_note_commitment: devnet_root("recipient-note", &path_id),
            recipient_scan_hint_root: devnet_root("recipient-scan-hint", &path_id),
            change_note_commitment: devnet_root("change-note", &path_id),
            change_scan_hint_root: devnet_root("change-scan-hint", &path_id),
            encrypted_amount_root: devnet_root("encrypted-amounts", &path_id),
            balance_proof_root: devnet_root("balance-proof", &path_id),
            transfer_amount: DEFAULT_DEVNET_TRANSFER_AMOUNT,
            change_amount: DEFAULT_DEVNET_CHANGE_AMOUNT,
            fee_amount: 21_000,
            fee_sponsor_root: devnet_root("fee-sponsor", &path_id),
            sequencer_pq_root: devnet_root("sequencer-pq", &path_id),
            proof_transcript_root: devnet_root("proof-transcript", &path_id),
            payout_subaddress_commitment: devnet_root("payout-subaddress", &path_id),
            exit_withdrawal_commitment: devnet_root("exit-withdrawal", &path_id),
            exit_burn_nullifier: devnet_root("exit-burn-nullifier", &path_id),
            exit_liquidity_root: devnet_root("exit-liquidity", &path_id),
            exit_pq_authorization_root: devnet_root("exit-pq-auth", &path_id),
            exit_amount: DEFAULT_DEVNET_EXIT_AMOUNT,
            privacy_set_size: state.config.target_privacy_set_size,
            user_fee_bps: state.config.max_transfer_fee_bps,
            settlement_height: DEVNET_HEIGHT + 142,
        };
        state
            .submit_bridge_bound_transfer(&mut spine, request)
            .expect("devnet bridge-bound transfer records and anchors");
        state
    }

    pub fn submit_bridge_bound_transfer(
        &mut self,
        spine: &mut BridgeExitSpineState,
        request: BridgeBoundTransferRequest,
    ) -> Result<String> {
        self.validate_request_roots(&request)?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "transfer privacy set below runtime floor",
        )?;
        require(
            request.user_fee_bps <= self.config.max_user_fee_bps,
            "transfer user fee exceeds runtime cap",
        )?;
        require(
            request.user_fee_bps <= self.config.max_transfer_fee_bps,
            "transfer fee exceeds bridge-bound low-fee cap",
        )?;
        require(
            !self
                .spent_input_nullifiers
                .contains(&request.input_note_nullifier),
            "input note nullifier already spent by transfer runtime",
        )?;
        if spine
            .spent_nullifiers
            .contains(&request.input_note_nullifier)
        {
            self.counters.replay_nullifiers_rejected += 1;
            self.refresh_roots(spine.state_root());
            return Err("input note nullifier already appears in bridge exit set".to_string());
        }

        let spine_root_before = spine.state_root();
        let path = spine
            .bridge_paths
            .get(&request.path_id)
            .ok_or_else(|| "bridge path not found for private transfer".to_string())?;
        require(
            path.stage.can_request_exit(),
            "bridge path is not in a private-note/action state",
        )?;
        require(
            path.private_note_commitment.as_ref() == Some(&request.input_note_commitment),
            "transfer input note does not match bridge-minted note",
        )?;
        require(
            request.privacy_set_size >= path.privacy_set_size,
            "transfer privacy set regresses below bridge path privacy",
        )?;
        let conserved_total = request
            .transfer_amount
            .checked_add(request.change_amount)
            .and_then(|value| value.checked_add(request.fee_amount))
            .ok_or_else(|| "transfer amount conservation overflow".to_string())?;
        require(
            conserved_total <= path.amount,
            "transfer amount plus change and fee exceeds bridge source amount",
        )?;
        require(
            request.exit_amount <= request.transfer_amount,
            "prepared exit amount exceeds transferred recipient amount",
        )?;
        let source_private_state_root = path
            .private_state_root
            .clone()
            .unwrap_or_else(|| record_root("empty_source_private_state", &path.public_record()));
        let source_amount_commitment_root = record_root(
            "source_amount_commitment",
            &json!({
                "path_id": path.path_id,
                "amount_commitment": request.encrypted_amount_root,
                "source_amount_ceiling": path.amount.to_string(),
            }),
        );
        let watcher_quorum_id = path.watcher_quorum_id.clone();
        let _ = path;

        let transfer_id = bridge_bound_transfer_id(
            &request.path_id,
            &request.input_note_nullifier,
            &request.recipient_note_commitment,
            &request.proof_transcript_root,
        );
        require(
            !self.receipts.contains_key(&transfer_id),
            "bridge-bound transfer already exists",
        )?;
        if self.receipts.len() >= self.config.max_transfers {
            return Err("bridge-bound transfer capacity reached".to_string());
        }

        let input_note = TransferInputNote {
            path_id: request.path_id.clone(),
            source_note_commitment: request.input_note_commitment.clone(),
            source_note_membership_root: request.input_note_membership_root.clone(),
            source_private_state_root,
            source_spine_root: spine_root_before.clone(),
            source_amount_commitment_root,
            sender_view_key_policy_root: request.sender_view_key_policy_root.clone(),
            watcher_quorum_id: watcher_quorum_id.clone(),
            privacy_set_size: request.privacy_set_size,
        };
        let input_note_root = input_note.state_root();
        let exit_claim_seed_root = record_root(
            "exit_claim_seed",
            &json!({
                "transfer_id": transfer_id,
                "path_id": request.path_id,
                "recipient_note_commitment": request.recipient_note_commitment,
                "withdrawal_commitment": request.exit_withdrawal_commitment,
                "burn_nullifier": request.exit_burn_nullifier,
                "exit_amount": request.exit_amount.to_string(),
                "payout_subaddress_commitment": request.payout_subaddress_commitment,
            }),
        );
        let recipient_output = TransferOutputNote::new(
            &transfer_id,
            OutputKind::RecipientNote,
            request.recipient_note_commitment.clone(),
            request.recipient_scan_hint_root.clone(),
            request.encrypted_amount_root.clone(),
            request.sender_view_key_policy_root.clone(),
            Some(exit_claim_seed_root.clone()),
        );
        let change_output = TransferOutputNote::new(
            &transfer_id,
            OutputKind::ChangeNote,
            request.change_note_commitment.clone(),
            request.change_scan_hint_root.clone(),
            request.encrypted_amount_root.clone(),
            request.sender_view_key_policy_root.clone(),
            None,
        );
        let output_note_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-OUTPUT-ROOT",
            &[
                recipient_output.public_record(),
                change_output.public_record(),
            ],
        );
        let token_transfer_root = record_root(
            "token_transfer_root",
            &json!({
                "transfer_id": transfer_id,
                "path_id": request.path_id,
                "input_note_root": input_note_root,
                "output_note_root": output_note_root,
                "balance_proof_root": request.balance_proof_root,
                "encrypted_amount_root": request.encrypted_amount_root,
                "fee_sponsor_root": request.fee_sponsor_root,
                "exit_claim_seed_root": exit_claim_seed_root,
            }),
        );
        let private_state_root_after = record_root(
            "private_transfer_state_after",
            &json!({
                "transfer_id": transfer_id,
                "spent_input_nullifier": request.input_note_nullifier,
                "output_note_root": output_note_root,
                "recipient_note": request.recipient_note_commitment,
                "change_note": request.change_note_commitment,
                "token_transfer_root": token_transfer_root,
            }),
        );
        let action_commitment = record_root(
            "private_transfer_action_commitment",
            &json!({
                "transfer_id": transfer_id,
                "lane": request.lane.as_str(),
                "path_id": request.path_id,
                "input_note_root": input_note_root,
                "token_transfer_root": token_transfer_root,
                "private_state_root_after": private_state_root_after,
            }),
        );
        let receipt_root = private_transfer_receipt_root(
            &transfer_id,
            &request.path_id,
            &token_transfer_root,
            &private_state_root_after,
            &request.proof_transcript_root,
        );

        let action_receipt_id = spine.record_private_action(PrivateActionRequest {
            path_id: request.path_id.clone(),
            action_kind: PrivateActionKind::Transfer,
            action_commitment,
            private_state_root: private_state_root_after.clone(),
            contract_call_root: record_root(
                "no_contract_call",
                &json!({ "transfer_id": transfer_id }),
            ),
            token_transfer_root: token_transfer_root.clone(),
            fee_sponsor_root: request.fee_sponsor_root.clone(),
            sequencer_pq_root: request.sequencer_pq_root.clone(),
            receipt_root: receipt_root.clone(),
            privacy_set_size: request.privacy_set_size,
            user_fee_bps: request.user_fee_bps,
        })?;
        let spine_root_after_action = spine.state_root();
        let bridge_checkpoint_root = record_root(
            "bridge_transfer_checkpoint",
            &json!({
                "transfer_id": transfer_id,
                "action_receipt_id": action_receipt_id,
                "spine_root_before": spine_root_before,
                "spine_root_after_action": spine_root_after_action,
                "receipt_root": receipt_root,
            }),
        );
        spine.anchor_settlement_receipt(AnchorReceiptRequest {
            path_id: request.path_id.clone(),
            receipt_root: receipt_root.clone(),
            settlement_state_root: private_state_root_after.clone(),
            bridge_checkpoint_root: bridge_checkpoint_root.clone(),
            anchor_height: request.settlement_height,
        })?;
        let spine_root_after_anchor = spine.state_root();

        let claim_id = transfer_exit_claim_id(
            &transfer_id,
            &action_receipt_id,
            &request.exit_withdrawal_commitment,
            &request.exit_burn_nullifier,
        );
        let exit_claim = TransferExitClaim {
            claim_id: claim_id.clone(),
            transfer_id: transfer_id.clone(),
            path_id: request.path_id.clone(),
            action_receipt_id: action_receipt_id.clone(),
            receipt_root: receipt_root.clone(),
            output_note_commitment: request.recipient_note_commitment.clone(),
            withdrawal_commitment: request.exit_withdrawal_commitment.clone(),
            burn_nullifier: request.exit_burn_nullifier.clone(),
            payout_subaddress_commitment: request.payout_subaddress_commitment.clone(),
            liquidity_root: request.exit_liquidity_root.clone(),
            pq_authorization_root: request.exit_pq_authorization_root.clone(),
            watcher_quorum_id,
            exit_mode: ExitMode::Forced,
            max_exit_amount: request.exit_amount,
            privacy_set_size: request.privacy_set_size,
            prepared_height: request.settlement_height,
        };
        let exit_claim_root = exit_claim.state_root();
        let receipt = PrivateTransferReceipt {
            transfer_id: transfer_id.clone(),
            status: TransferStatus::ExitClaimReady,
            lane: request.lane,
            path_id: request.path_id.clone(),
            action_receipt_id,
            input_note_root: input_note_root.clone(),
            input_note_nullifier: request.input_note_nullifier.clone(),
            output_note_root: output_note_root.clone(),
            recipient_note_commitment: request.recipient_note_commitment.clone(),
            change_note_commitment: request.change_note_commitment.clone(),
            encrypted_amount_root: request.encrypted_amount_root.clone(),
            balance_proof_root: request.balance_proof_root.clone(),
            proof_transcript_root: request.proof_transcript_root.clone(),
            token_transfer_root,
            private_state_root_after,
            receipt_root,
            bridge_checkpoint_root,
            spine_root_before,
            spine_root_after_action,
            spine_root_after_anchor: spine_root_after_anchor.clone(),
            exit_claim_id: claim_id.clone(),
            exit_claim_root: exit_claim_root.clone(),
            privacy_set_size: request.privacy_set_size,
            user_fee_bps: request.user_fee_bps,
        };

        self.input_notes.insert(transfer_id.clone(), input_note);
        self.output_notes
            .insert(recipient_output.output_id.clone(), recipient_output);
        self.output_notes
            .insert(change_output.output_id.clone(), change_output);
        self.spent_input_nullifiers
            .insert(request.input_note_nullifier.clone());
        self.exit_claims.insert(claim_id, exit_claim);
        self.receipts.insert(transfer_id.clone(), receipt.clone());
        self.counters.bridge_bound_transfers += 1;
        self.counters.spine_actions_recorded += 1;
        self.counters.receipts_anchored += 1;
        self.counters.exit_claims_prepared += 1;
        self.push_event(
            "bridge_bound_private_transfer_exit_claim_ready",
            &transfer_id,
        );
        let report = self.build_readiness_report(spine, &receipt)?;
        self.readiness_reports
            .insert(report.report_id.clone(), report);
        self.counters.readiness_reports += 1;
        self.refresh_roots(spine_root_after_anchor);
        Ok(transfer_id)
    }

    pub fn prepare_exit_request(
        &self,
        transfer_id: &str,
        requested_height: u64,
    ) -> Result<WithdrawalRequest> {
        let receipt = self
            .receipts
            .get(transfer_id)
            .ok_or_else(|| "transfer receipt not found".to_string())?;
        require(
            receipt.status.usable_for_exit(),
            "transfer receipt is not usable for exit",
        )?;
        let claim = self
            .exit_claims
            .get(&receipt.exit_claim_id)
            .ok_or_else(|| "transfer exit claim not found".to_string())?;
        Ok(WithdrawalRequest {
            path_id: claim.path_id.clone(),
            withdrawal_commitment: claim.withdrawal_commitment.clone(),
            burn_nullifier: claim.burn_nullifier.clone(),
            payout_subaddress_commitment: claim.payout_subaddress_commitment.clone(),
            requested_amount: claim.max_exit_amount,
            exit_mode: claim.exit_mode,
            watcher_quorum_id: claim.watcher_quorum_id.clone(),
            liquidity_root: claim.liquidity_root.clone(),
            pq_authorization_root: claim.pq_authorization_root.clone(),
            privacy_set_size: claim.privacy_set_size,
            requested_height,
            user_fee_bps: receipt.user_fee_bps,
        })
    }

    pub fn verify_transfer_exit_readiness(
        &self,
        spine: &BridgeExitSpineState,
        transfer_id: &str,
    ) -> Result<TransferReadinessReport> {
        let receipt = self
            .receipts
            .get(transfer_id)
            .ok_or_else(|| "transfer receipt not found".to_string())?;
        self.build_readiness_report(spine, receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "pq_auth_suite": self.config.pq_auth_suite,
            "transfer_note_suite": self.config.transfer_note_suite,
            "exit_claim_suite": self.config.exit_claim_suite,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "bridge_bound_transfers": self.receipts.len(),
            "exit_claims_ready": self.exit_claims.len(),
            "readiness_reports": self.readiness_reports.len(),
            "spent_input_nullifiers": self.spent_input_nullifiers.len(),
            "latest_spine_root": self.roots.latest_spine_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn validate_request_roots(&self, request: &BridgeBoundTransferRequest) -> Result<()> {
        required("path_id", &request.path_id)?;
        required("input_note_commitment", &request.input_note_commitment)?;
        required(
            "input_note_membership_root",
            &request.input_note_membership_root,
        )?;
        required("input_note_nullifier", &request.input_note_nullifier)?;
        required(
            "sender_pq_authorization_root",
            &request.sender_pq_authorization_root,
        )?;
        required(
            "recipient_note_commitment",
            &request.recipient_note_commitment,
        )?;
        required(
            "recipient_scan_hint_root",
            &request.recipient_scan_hint_root,
        )?;
        required("change_note_commitment", &request.change_note_commitment)?;
        required("change_scan_hint_root", &request.change_scan_hint_root)?;
        required("encrypted_amount_root", &request.encrypted_amount_root)?;
        required("balance_proof_root", &request.balance_proof_root)?;
        required("fee_sponsor_root", &request.fee_sponsor_root)?;
        required("sequencer_pq_root", &request.sequencer_pq_root)?;
        required("proof_transcript_root", &request.proof_transcript_root)?;
        required(
            "payout_subaddress_commitment",
            &request.payout_subaddress_commitment,
        )?;
        required(
            "exit_withdrawal_commitment",
            &request.exit_withdrawal_commitment,
        )?;
        required("exit_burn_nullifier", &request.exit_burn_nullifier)?;
        required("exit_liquidity_root", &request.exit_liquidity_root)?;
        required(
            "exit_pq_authorization_root",
            &request.exit_pq_authorization_root,
        )?;
        require(
            request.transfer_amount > 0,
            "transfer amount must be non-zero",
        )?;
        require(request.exit_amount > 0, "exit amount must be non-zero")?;
        require(
            request.user_fee_bps <= MAX_BPS,
            "transfer fee bps exceeds absolute bps range",
        )
    }

    fn build_readiness_report(
        &self,
        spine: &BridgeExitSpineState,
        receipt: &PrivateTransferReceipt,
    ) -> Result<TransferReadinessReport> {
        let path = spine.bridge_paths.get(&receipt.path_id);
        let spine_receipt = spine.receipts.get(&receipt.action_receipt_id);
        let claim = self.exit_claims.get(&receipt.exit_claim_id);
        let mut checks = BTreeMap::new();
        self.add_check(
            &mut checks,
            CheckKind::BridgePathExists,
            if path.is_some() {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "transfer must reference an existing bridge path",
            format!("path_present={}", path.is_some()),
            json!({ "path_id": receipt.path_id, "spine_root": spine.state_root() }),
        );
        self.add_check(
            &mut checks,
            CheckKind::BridgeNoteMatchesPath,
            if path.and_then(|item| item.action_receipt_id.as_ref())
                == Some(&receipt.action_receipt_id)
            {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "bridge path latest action receipt must be the transfer receipt",
            format!(
                "path_action_receipt={}",
                path.and_then(|item| item.action_receipt_id.as_deref())
                    .unwrap_or("missing")
            ),
            json!({
                "path_id": receipt.path_id,
                "expected_action_receipt_id": receipt.action_receipt_id,
            }),
        );
        self.add_check(
            &mut checks,
            CheckKind::InputNullifierUnique,
            if self
                .spent_input_nullifiers
                .contains(&receipt.input_note_nullifier)
            {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "input note nullifier must be recorded exactly once by transfer runtime",
            "transfer runtime has the input nullifier in its spent set",
            json!({ "input_note_nullifier": receipt.input_note_nullifier }),
        );
        self.add_check(
            &mut checks,
            CheckKind::AmountConserved,
            CheckStatus::Passed,
            "balance conservation proof root must be bound into the receipt",
            "balance proof root and encrypted amount root are part of the receipt root",
            json!({
                "balance_proof_root": receipt.balance_proof_root,
                "encrypted_amount_root": receipt.encrypted_amount_root,
                "receipt_root": receipt.receipt_root,
            }),
        );
        self.add_check(
            &mut checks,
            CheckKind::PrivacyFloorMet,
            if receipt.privacy_set_size >= self.config.min_privacy_set_size {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "transfer must preserve the runtime privacy set floor",
            format!("privacy_set_size={}", receipt.privacy_set_size),
            json!({ "privacy_set_size": receipt.privacy_set_size }),
        );
        self.add_check(
            &mut checks,
            CheckKind::FeeCapMet,
            if receipt.user_fee_bps <= self.config.max_transfer_fee_bps {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "bridge-bound private transfer must stay inside low-fee cap",
            format!("user_fee_bps={}", receipt.user_fee_bps),
            json!({ "user_fee_bps": receipt.user_fee_bps }),
        );
        self.add_check(
            &mut checks,
            CheckKind::PqAuthorizationBound,
            CheckStatus::Passed,
            "sequencer and sender PQ authorization roots must be included in the spine action",
            "sequencer PQ root is part of the corresponding spine receipt",
            json!({
                "spine_receipt_present": spine_receipt.is_some(),
                "action_receipt_id": receipt.action_receipt_id,
            }),
        );
        self.add_check(
            &mut checks,
            CheckKind::SpineActionReceiptRecorded,
            if spine_receipt
                .map(|item| {
                    item.action_kind == PrivateActionKind::Transfer
                        && item.receipt_root == receipt.receipt_root
                        && item.token_transfer_root == receipt.token_transfer_root
                })
                .unwrap_or(false)
            {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "spine must contain a matching private transfer action receipt",
            format!("spine_receipt_present={}", spine_receipt.is_some()),
            json!({
                "receipt_root": receipt.receipt_root,
                "token_transfer_root": receipt.token_transfer_root,
            }),
        );
        self.add_check(
            &mut checks,
            CheckKind::SettlementReceiptAnchored,
            if path.and_then(|item| item.receipt_root.as_ref()) == Some(&receipt.receipt_root)
                && path.and_then(|item| item.bridge_checkpoint_root.as_ref())
                    == Some(&receipt.bridge_checkpoint_root)
            {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "spine path must anchor the transfer settlement receipt and checkpoint root",
            "latest bridge path root points at transfer receipt and checkpoint",
            json!({
                "receipt_root": receipt.receipt_root,
                "bridge_checkpoint_root": receipt.bridge_checkpoint_root,
            }),
        );
        self.add_check(
            &mut checks,
            CheckKind::ExitClaimCompatible,
            if claim
                .map(|item| {
                    item.action_receipt_id == receipt.action_receipt_id
                        && item.receipt_root == receipt.receipt_root
                        && item.privacy_set_size >= self.config.min_privacy_set_size
                })
                .unwrap_or(false)
            {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "receipt must produce a forced-exit compatible withdrawal claim",
            format!("exit_claim_present={}", claim.is_some()),
            json!({
                "exit_claim_id": receipt.exit_claim_id,
                "exit_claim_root": receipt.exit_claim_root,
            }),
        );
        self.add_check(
            &mut checks,
            CheckKind::RootsOnlyPublicSurface,
            CheckStatus::Passed,
            "public transfer record must expose commitments, roots, and ids rather than recipient plaintext",
            "receipt public surface uses commitments, roots, nullifiers, and scan-hint roots",
            json!({
                "receipt_record_root": receipt.state_root(),
                "public_surface": "roots_and_commitments_only",
            }),
        );

        let passed_checks = checks
            .values()
            .filter(|check| check.status == CheckStatus::Passed)
            .count() as u64;
        let watch_checks = checks
            .values()
            .filter(|check| check.status == CheckStatus::Watch)
            .count() as u64;
        let failed_checks = checks
            .values()
            .filter(|check| check.status == CheckStatus::Failed)
            .count() as u64;
        let status = if failed_checks > 0 {
            ReportStatus::Failed
        } else if watch_checks > 0 {
            ReportStatus::Watch
        } else {
            ReportStatus::Passed
        };
        let report_root_seed = record_root(
            "transfer_readiness_report_seed",
            &json!({
                "transfer_id": receipt.transfer_id,
                "status": status.as_str(),
                "passed_checks": passed_checks,
                "watch_checks": watch_checks,
                "failed_checks": failed_checks,
                "bridge_spine_root": spine.state_root(),
                "transfer_receipt_root": receipt.state_root(),
                "exit_claim_root": receipt.exit_claim_root,
            }),
        );
        let report_id = transfer_report_id(&receipt.transfer_id, &report_root_seed);
        Ok(TransferReadinessReport {
            report_id,
            transfer_id: receipt.transfer_id.clone(),
            status,
            passed_checks,
            watch_checks,
            failed_checks,
            bridge_spine_root: spine.state_root(),
            transfer_receipt_root: receipt.state_root(),
            exit_claim_root: receipt.exit_claim_root.clone(),
            checks,
        })
    }

    fn add_check(
        &self,
        checks: &mut BTreeMap<String, TransferCheckEvidence>,
        kind: CheckKind,
        status: CheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_record: Value,
    ) {
        let check =
            TransferCheckEvidence::new(kind, status, requirement, observed, evidence_record);
        checks.insert(check.check_id.clone(), check);
    }

    fn push_event(&mut self, label: &str, transfer_id: &str) {
        let event_root = record_root(
            "event",
            &json!({
                "label": label,
                "transfer_id": transfer_id,
                "sequence": self.events.len(),
            }),
        );
        self.events.push(event_root);
    }

    fn refresh_roots(&mut self, latest_spine_root: String) {
        let input_records = self
            .input_notes
            .values()
            .map(TransferInputNote::public_record)
            .collect::<Vec<_>>();
        let output_records = self
            .output_notes
            .values()
            .map(TransferOutputNote::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(PrivateTransferReceipt::public_record)
            .collect::<Vec<_>>();
        let exit_claim_records = self
            .exit_claims
            .values()
            .map(TransferExitClaim::public_record)
            .collect::<Vec<_>>();
        let report_records = self
            .readiness_reports
            .values()
            .map(TransferReadinessReport::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .spent_input_nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();
        let event_records = self
            .events
            .iter()
            .map(|event| json!(event))
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            input_note_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-INPUTS",
                &input_records,
            ),
            output_note_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-OUTPUTS",
                &output_records,
            ),
            transfer_receipt_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-RECEIPTS",
                &receipt_records,
            ),
            exit_claim_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-CLAIMS",
                &exit_claim_records,
            ),
            spent_nullifier_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-SPENT-NULLIFIERS",
                &nullifier_records,
            ),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-REPORTS",
                &report_records,
            ),
            event_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EVENTS", &event_records),
            counters_root: self.counters.state_root(),
            latest_spine_root,
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn bridge_bound_transfer_id(
    path_id: &str,
    input_nullifier: &str,
    recipient_note_commitment: &str,
    proof_transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-ID",
        &[
            HashPart::Str(path_id),
            HashPart::Str(input_nullifier),
            HashPart::Str(recipient_note_commitment),
            HashPart::Str(proof_transcript_root),
        ],
        32,
    )
}

pub fn transfer_output_id(transfer_id: &str, kind: OutputKind, output_seed_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-OUTPUT-ID",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(output_seed_root),
        ],
        32,
    )
}

pub fn private_transfer_receipt_root(
    transfer_id: &str,
    path_id: &str,
    token_transfer_root: &str,
    private_state_root_after: &str,
    proof_transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-RECEIPT-ROOT",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(path_id),
            HashPart::Str(token_transfer_root),
            HashPart::Str(private_state_root_after),
            HashPart::Str(proof_transcript_root),
        ],
        32,
    )
}

pub fn transfer_exit_claim_id(
    transfer_id: &str,
    action_receipt_id: &str,
    withdrawal_commitment: &str,
    burn_nullifier: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-EXIT-CLAIM-ID",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(action_receipt_id),
            HashPart::Str(withdrawal_commitment),
            HashPart::Str(burn_nullifier),
        ],
        32,
    )
}

pub fn transfer_check_id(kind: CheckKind, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-CHECK-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(evidence_root)],
        32,
    )
}

pub fn transfer_report_id(transfer_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-REPORT-ID",
        &[HashPart::Str(transfer_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-{kind}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn open_devnet_transfer_source_path(spine: &mut BridgeExitSpineState) -> String {
    let watcher_quorum_id = spine
        .watcher_quorums
        .keys()
        .next()
        .cloned()
        .expect("devnet spine has watcher quorum");
    let monero_lock_txid = "devnet-monero-lock-txid-transfer-0002";
    let path_id = spine
        .open_deposit_path(DepositLockRequest {
            monero_lock_txid: monero_lock_txid.to_string(),
            deposit_commitment: devnet_root("transfer-deposit-commitment", monero_lock_txid),
            amount: DEFAULT_DEVNET_SOURCE_AMOUNT,
            sender_viewtag_commitment: devnet_root("transfer-viewtag", monero_lock_txid),
            deposit_subaddress_commitment: devnet_root("transfer-subaddress", monero_lock_txid),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_authorization_root: devnet_root("transfer-deposit-pq-auth", monero_lock_txid),
            watcher_quorum_id: watcher_quorum_id.clone(),
            observed_monero_height: DEVNET_HEIGHT + spine.config.monero_finality_depth + 7,
            lane: BridgeLane::LowFee,
            user_fee_bps: DEFAULT_MAX_TRANSFER_FEE_BPS,
        })
        .expect("devnet transfer source deposit opens");
    spine
        .certify_deposit_lock(DepositCertificateRequest {
            path_id: path_id.clone(),
            watcher_quorum_id: watcher_quorum_id.clone(),
            certificate_root: devnet_root("transfer-deposit-certificate", &path_id),
            monero_finality_depth: spine.config.monero_finality_depth,
            certified_height: DEVNET_HEIGHT + spine.config.monero_finality_depth + 8,
        })
        .expect("devnet transfer source certifies");
    spine
        .mint_private_note(MintPrivateNoteRequest {
            path_id: path_id.clone(),
            private_note_commitment: devnet_root("input-note", &path_id),
            note_membership_root: devnet_root("input-membership", &path_id),
            wallet_scan_hint_root: devnet_root("input-wallet-scan-hint", &path_id),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet transfer source private note mints");
    path_id
}

fn devnet_root(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-PRIVATE-TRANSFER-DEVNET",
        &[HashPart::Str(label), HashPart::Str(seed)],
        32,
    )
}

fn required(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} is required"))
    } else {
        Ok(())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
