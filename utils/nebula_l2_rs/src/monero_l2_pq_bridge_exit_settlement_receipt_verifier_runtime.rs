use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitSettlementReceiptVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_SETTLEMENT_RECEIPT_VERIFIER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-settlement-receipt-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_SETTLEMENT_RECEIPT_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_BINDING_SUITE: &str =
    "monero-private-l2-bridge-exit-settlement-receipt-binding-v1";
pub const WALLET_RECEIPT_SUITE: &str =
    "ml-kem-wallet-visible-encrypted-settlement-receipts-roots-only-v1";
pub const RELEASE_AUTHORIZATION_SUITE: &str =
    "pq-release-authorization-root-with-dispute-window-gating-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_260_000;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MAX_FEE_BPS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MAX_RECEIPTS: usize = 512;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    PrivateTransfer,
    ContractAction,
    ForcedExit,
    LiquidityBackstop,
    EmergencyEscape,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractAction => "contract_action",
            Self::ForcedExit => "forced_exit",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Submitted,
    Bound,
    DisputeWindowOpen,
    ReleaseAuthorized,
    Denied,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Bound => "bound",
            Self::DisputeWindowOpen => "dispute_window_open",
            Self::ReleaseAuthorized => "release_authorized",
            Self::Denied => "denied",
        }
    }

    pub fn releases(self) -> bool {
        matches!(self, Self::ReleaseAuthorized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputBindingKind {
    PrivateTransferOutput,
    PrivateActionOutput,
    BurnNullifier,
    ExitClaimCommitment,
    WalletVisibleCiphertext,
}

impl OutputBindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransferOutput => "private_transfer_output",
            Self::PrivateActionOutput => "private_action_output",
            Self::BurnNullifier => "burn_nullifier",
            Self::ExitClaimCommitment => "exit_claim_commitment",
            Self::WalletVisibleCiphertext => "wallet_visible_ciphertext",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    None,
    MissingTransferOutput,
    MissingActionOutput,
    ExitClaimMismatch,
    FeeAboveLowFeeCap,
    DisputeWindowActive,
    WalletReceiptNotDecryptable,
    ReleaseAuthorizationMissing,
    PrivacyFloorNotMet,
    WatcherQuorumMissing,
    MetadataLeakageExceeded,
    DuplicateNullifier,
}

impl DenialReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MissingTransferOutput => "missing_transfer_output",
            Self::MissingActionOutput => "missing_action_output",
            Self::ExitClaimMismatch => "exit_claim_mismatch",
            Self::FeeAboveLowFeeCap => "fee_above_low_fee_cap",
            Self::DisputeWindowActive => "dispute_window_active",
            Self::WalletReceiptNotDecryptable => "wallet_receipt_not_decryptable",
            Self::ReleaseAuthorizationMissing => "release_authorization_missing",
            Self::PrivacyFloorNotMet => "privacy_floor_not_met",
            Self::WatcherQuorumMissing => "watcher_quorum_missing",
            Self::MetadataLeakageExceeded => "metadata_leakage_exceeded",
            Self::DuplicateNullifier => "duplicate_nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierCheckKind {
    TransferOutputBound,
    ActionOutputBound,
    ExitClaimBound,
    LowFeeReceipt,
    WalletReceiptEncrypted,
    WalletReceiptVisible,
    ReleaseAuthorizationRootPresent,
    DisputeWindowElapsed,
    PrivacyFloorMet,
    WatcherQuorumMet,
    NullifierUnique,
    MetadataBudgetMet,
}

impl VerifierCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferOutputBound => "transfer_output_bound",
            Self::ActionOutputBound => "action_output_bound",
            Self::ExitClaimBound => "exit_claim_bound",
            Self::LowFeeReceipt => "low_fee_receipt",
            Self::WalletReceiptEncrypted => "wallet_receipt_encrypted",
            Self::WalletReceiptVisible => "wallet_receipt_visible",
            Self::ReleaseAuthorizationRootPresent => "release_authorization_root_present",
            Self::DisputeWindowElapsed => "dispute_window_elapsed",
            Self::PrivacyFloorMet => "privacy_floor_met",
            Self::WatcherQuorumMet => "watcher_quorum_met",
            Self::NullifierUnique => "nullifier_unique",
            Self::MetadataBudgetMet => "metadata_budget_met",
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

    pub fn accepts(self) -> bool {
        matches!(self, Self::Passed | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierReportStatus {
    Passed,
    Watch,
    Failed,
}

impl VerifierReportStatus {
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
    pub receipt_binding_suite: String,
    pub wallet_receipt_suite: String,
    pub release_authorization_suite: String,
    pub current_height: u64,
    pub dispute_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub low_fee_cap_atomic: u128,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub max_metadata_leakage_units: u64,
    pub min_watcher_quorum: u64,
    pub require_transfer_output_binding: bool,
    pub require_action_output_binding: bool,
    pub require_wallet_visible_receipt: bool,
    pub require_release_authorization_root: bool,
    pub deny_duplicate_nullifiers: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_receipts: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_binding_suite: RECEIPT_BINDING_SUITE.to_string(),
            wallet_receipt_suite: WALLET_RECEIPT_SUITE.to_string(),
            release_authorization_suite: RELEASE_AUTHORIZATION_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            require_transfer_output_binding: true,
            require_action_output_binding: true,
            require_wallet_visible_receipt: true,
            require_release_authorization_root: true,
            deny_duplicate_nullifiers: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_receipts: DEFAULT_MAX_RECEIPTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_binding_suite": self.receipt_binding_suite,
            "wallet_receipt_suite": self.wallet_receipt_suite,
            "release_authorization_suite": self.release_authorization_suite,
            "current_height": self.current_height,
            "dispute_window_blocks": self.dispute_window_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "low_fee_cap_atomic": self.low_fee_cap_atomic.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "min_watcher_quorum": self.min_watcher_quorum,
            "require_transfer_output_binding": self.require_transfer_output_binding,
            "require_action_output_binding": self.require_action_output_binding,
            "require_wallet_visible_receipt": self.require_wallet_visible_receipt,
            "require_release_authorization_root": self.require_release_authorization_root,
            "deny_duplicate_nullifiers": self.deny_duplicate_nullifiers,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_receipts": self.max_receipts,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptRequest {
    pub receipt_id: String,
    pub exit_claim_id: String,
    pub settlement_lane: SettlementLane,
    pub private_transfer_output_root: String,
    pub private_action_output_root: String,
    pub burn_nullifier_root: String,
    pub exit_claim_root: String,
    pub requested_release_root: String,
    pub encrypted_wallet_receipt_root: String,
    pub wallet_view_key_commitment_root: String,
    pub release_authorization_root: String,
    pub watcher_attestation_root: String,
    pub dispute_evidence_root: String,
    pub metadata_budget_root: String,
    pub amount_atomic: u128,
    pub fee_atomic: u128,
    pub privacy_set_size: u64,
    pub watcher_quorum: u64,
    pub metadata_leakage_units: u64,
    pub submitted_height: u64,
    pub duplicate_nullifier_seen: bool,
}

impl SettlementReceiptRequest {
    pub fn devnet(
        receipt_id: &str,
        exit_claim_id: &str,
        settlement_lane: SettlementLane,
        ordinal: u64,
    ) -> Self {
        let private_transfer_output_root = binding_root(
            OutputBindingKind::PrivateTransferOutput,
            receipt_id,
            exit_claim_id,
            ordinal,
        );
        let private_action_output_root = binding_root(
            OutputBindingKind::PrivateActionOutput,
            receipt_id,
            exit_claim_id,
            ordinal,
        );
        let burn_nullifier_root = binding_root(
            OutputBindingKind::BurnNullifier,
            receipt_id,
            exit_claim_id,
            ordinal,
        );
        let exit_claim_root = binding_root(
            OutputBindingKind::ExitClaimCommitment,
            receipt_id,
            exit_claim_id,
            ordinal,
        );
        let requested_release_root = release_request_root(
            receipt_id,
            exit_claim_id,
            &exit_claim_root,
            &burn_nullifier_root,
        );
        let encrypted_wallet_receipt_root = binding_root(
            OutputBindingKind::WalletVisibleCiphertext,
            receipt_id,
            exit_claim_id,
            ordinal,
        );
        let wallet_view_key_commitment_root = wallet_view_key_commitment_root(
            receipt_id,
            exit_claim_id,
            &encrypted_wallet_receipt_root,
        );
        let watcher_attestation_root =
            watcher_attestation_root(receipt_id, exit_claim_id, DEFAULT_MIN_WATCHER_QUORUM + 1);
        let dispute_evidence_root = dispute_evidence_root(receipt_id, exit_claim_id, "none");
        let metadata_budget_root = metadata_budget_root(receipt_id, exit_claim_id, 1);
        let release_authorization_root = release_authorization_root(
            receipt_id,
            exit_claim_id,
            &requested_release_root,
            &watcher_attestation_root,
        );

        Self {
            receipt_id: receipt_id.to_string(),
            exit_claim_id: exit_claim_id.to_string(),
            settlement_lane,
            private_transfer_output_root,
            private_action_output_root,
            burn_nullifier_root,
            exit_claim_root,
            requested_release_root,
            encrypted_wallet_receipt_root,
            wallet_view_key_commitment_root,
            release_authorization_root,
            watcher_attestation_root,
            dispute_evidence_root,
            metadata_budget_root,
            amount_atomic: 420_000_000_000 + u128::from(ordinal) * 10_000_000,
            fee_atomic: 21_000_000 + u128::from(ordinal) * 1_000_000,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE + ordinal * 512,
            watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM + 1,
            metadata_leakage_units: 1,
            submitted_height: DEFAULT_CURRENT_HEIGHT - DEFAULT_DISPUTE_WINDOW_BLOCKS - 48 + ordinal,
            duplicate_nullifier_seen: false,
        }
    }

    pub fn denied_fee_fixture(receipt_id: &str, exit_claim_id: &str) -> Self {
        let mut request = Self::devnet(
            receipt_id,
            exit_claim_id,
            SettlementLane::PrivateTransfer,
            9,
        );
        request.fee_atomic = DEFAULT_LOW_FEE_CAP_ATOMIC + 9_000_000;
        request
    }

    pub fn active_dispute_fixture(receipt_id: &str, exit_claim_id: &str) -> Self {
        let mut request = Self::devnet(receipt_id, exit_claim_id, SettlementLane::ForcedExit, 17);
        request.submitted_height = DEFAULT_CURRENT_HEIGHT - 24;
        request.dispute_evidence_root = dispute_evidence_root(receipt_id, exit_claim_id, "open");
        request
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "exit_claim_id": self.exit_claim_id,
            "settlement_lane": self.settlement_lane.as_str(),
            "private_transfer_output_root": self.private_transfer_output_root,
            "private_action_output_root": self.private_action_output_root,
            "burn_nullifier_root": self.burn_nullifier_root,
            "exit_claim_root": self.exit_claim_root,
            "requested_release_root": self.requested_release_root,
            "encrypted_wallet_receipt_root": self.encrypted_wallet_receipt_root,
            "wallet_view_key_commitment_root": self.wallet_view_key_commitment_root,
            "release_authorization_root": self.release_authorization_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "dispute_evidence_root": self.dispute_evidence_root,
            "metadata_budget_root": self.metadata_budget_root,
            "amount_atomic": self.amount_atomic.to_string(),
            "fee_atomic": self.fee_atomic.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "watcher_quorum": self.watcher_quorum,
            "metadata_leakage_units": self.metadata_leakage_units,
            "submitted_height": self.submitted_height,
            "duplicate_nullifier_seen": self.duplicate_nullifier_seen,
        })
    }

    pub fn request_root(&self) -> String {
        record_root("settlement_receipt_request", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifierCheck {
    pub kind: VerifierCheckKind,
    pub status: CheckStatus,
    pub denial_reason: DenialReason,
    pub evidence_root: String,
    pub check_root: String,
}

impl VerifierCheck {
    pub fn new(
        kind: VerifierCheckKind,
        status: CheckStatus,
        denial_reason: DenialReason,
        evidence_root: String,
    ) -> Self {
        let check_root = verifier_check_root(kind, status, denial_reason, &evidence_root);
        Self {
            kind,
            status,
            denial_reason,
            evidence_root,
            check_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "denial_reason": self.denial_reason.as_str(),
            "evidence_root": self.evidence_root,
            "check_root": self.check_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptVerification {
    pub receipt_id: String,
    pub exit_claim_id: String,
    pub status: ReceiptStatus,
    pub denial_reason: DenialReason,
    pub request_root: String,
    pub binding_root: String,
    pub low_fee_receipt_root: String,
    pub encrypted_wallet_receipt_root: String,
    pub wallet_visible_receipt_root: String,
    pub dispute_window_root: String,
    pub release_authorization_root: String,
    pub release_decision_root: String,
    pub checks_root: String,
    pub verification_root: String,
    pub release_height: u64,
    pub dispute_window_end: u64,
    pub checks: Vec<VerifierCheck>,
}

impl SettlementReceiptVerification {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "exit_claim_id": self.exit_claim_id,
            "status": self.status.as_str(),
            "denial_reason": self.denial_reason.as_str(),
            "request_root": self.request_root,
            "binding_root": self.binding_root,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "encrypted_wallet_receipt_root": self.encrypted_wallet_receipt_root,
            "wallet_visible_receipt_root": self.wallet_visible_receipt_root,
            "dispute_window_root": self.dispute_window_root,
            "release_authorization_root": self.release_authorization_root,
            "release_decision_root": self.release_decision_root,
            "checks_root": self.checks_root,
            "verification_root": self.verification_root,
            "release_height": self.release_height,
            "dispute_window_end": self.dispute_window_end,
            "checks": self.checks.iter().map(VerifierCheck::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifierReport {
    pub status: VerifierReportStatus,
    pub receipts_verified: u64,
    pub release_authorized_count: u64,
    pub denied_count: u64,
    pub open_dispute_count: u64,
    pub low_fee_receipt_count: u64,
    pub encrypted_wallet_receipt_count: u64,
    pub denial_roots: BTreeMap<String, String>,
    pub receipt_root: String,
    pub release_authorization_root: String,
    pub denial_root: String,
    pub report_root: String,
}

impl VerifierReport {
    pub fn public_record(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "receipts_verified": self.receipts_verified,
            "release_authorized_count": self.release_authorized_count,
            "denied_count": self.denied_count,
            "open_dispute_count": self.open_dispute_count,
            "low_fee_receipt_count": self.low_fee_receipt_count,
            "encrypted_wallet_receipt_count": self.encrypted_wallet_receipt_count,
            "denial_roots": self.denial_roots,
            "receipt_root": self.receipt_root,
            "release_authorization_root": self.release_authorization_root,
            "denial_root": self.denial_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub receipts: BTreeMap<String, SettlementReceiptVerification>,
    pub report: VerifierReport,
    pub config_root: String,
    pub receipt_root: String,
    pub report_root: String,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config) -> Self {
        let config_root = config.state_root();
        let report = empty_report();
        let report_root = report.report_root.clone();
        let receipt_root = merkle_root("settlement_receipt_verifier:empty_receipts", &[]);
        let state_root = runtime_state_root(&config_root, &receipt_root, &report_root);
        Self {
            config,
            receipts: BTreeMap::new(),
            report,
            config_root,
            receipt_root,
            report_root,
            state_root,
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let fixtures = vec![
            SettlementReceiptRequest::devnet(
                "settlement-receipt-devnet-001",
                "exit-claim-devnet-001",
                SettlementLane::PrivateTransfer,
                1,
            ),
            SettlementReceiptRequest::devnet(
                "settlement-receipt-devnet-002",
                "exit-claim-devnet-002",
                SettlementLane::ContractAction,
                2,
            ),
            SettlementReceiptRequest::denied_fee_fixture(
                "settlement-receipt-devnet-003",
                "exit-claim-devnet-003",
            ),
            SettlementReceiptRequest::active_dispute_fixture(
                "settlement-receipt-devnet-004",
                "exit-claim-devnet-004",
            ),
        ];
        for request in fixtures {
            let _ = state.verify_receipt(request);
        }
        state
    }

    pub fn verify_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> Result<SettlementReceiptVerification> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("settlement receipt verifier capacity exceeded".to_string());
        }
        if self.receipts.contains_key(&request.receipt_id) {
            return Err(format!("duplicate receipt id {}", request.receipt_id));
        }

        let verification = self.build_verification(&request);
        self.receipts
            .insert(request.receipt_id.clone(), verification.clone());
        self.recompute_roots();
        Ok(verification)
    }

    pub fn get_receipt(&self, receipt_id: &str) -> Option<&SettlementReceiptVerification> {
        self.receipts.get(receipt_id)
    }

    pub fn authorized_release_roots(&self) -> Vec<String> {
        self.receipts
            .values()
            .filter(|receipt| receipt.status.releases())
            .map(|receipt| receipt.release_authorization_root.clone())
            .collect()
    }

    pub fn denial_reasons(&self) -> BTreeMap<String, String> {
        self.receipts
            .iter()
            .filter(|(_, receipt)| receipt.denial_reason != DenialReason::None)
            .map(|(receipt_id, receipt)| {
                (
                    receipt_id.clone(),
                    receipt.denial_reason.as_str().to_string(),
                )
            })
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "receipts": self.receipts.values().map(SettlementReceiptVerification::public_record).collect::<Vec<_>>(),
            "report": self.report.public_record(),
            "config_root": self.config_root,
            "receipt_root": self.receipt_root,
            "report_root": self.report_root,
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn report(&self) -> &VerifierReport {
        &self.report
    }

    fn build_verification(
        &self,
        request: &SettlementReceiptRequest,
    ) -> SettlementReceiptVerification {
        let request_root = request.request_root();
        let dispute_window_end = request
            .submitted_height
            .saturating_add(self.config.dispute_window_blocks);
        let release_height = dispute_window_end.saturating_add(self.config.release_delay_blocks);
        let fee_bps = fee_bps(request.fee_atomic, request.amount_atomic);
        let binding_root = settlement_binding_root(request, &request_root);
        let low_fee_receipt_root = low_fee_receipt_root(
            &request.receipt_id,
            request.fee_atomic,
            self.config.low_fee_cap_atomic,
            fee_bps,
        );
        let wallet_visible_receipt_root = wallet_visible_receipt_root(
            &request.receipt_id,
            &request.encrypted_wallet_receipt_root,
            &request.wallet_view_key_commitment_root,
        );
        let dispute_window_root = dispute_window_root(
            &request.receipt_id,
            request.submitted_height,
            dispute_window_end,
            self.config.current_height,
            &request.dispute_evidence_root,
        );
        let release_authorization_root = release_authorization_decision_root(
            &request.receipt_id,
            &request.release_authorization_root,
            &request.requested_release_root,
            release_height,
        );

        let checks = vec![
            self.check_transfer_output(request),
            self.check_action_output(request),
            self.check_exit_claim(request),
            self.check_low_fee(request, &low_fee_receipt_root),
            self.check_wallet_encryption(request),
            self.check_wallet_visibility(request, &wallet_visible_receipt_root),
            self.check_release_authorization(request, &release_authorization_root),
            self.check_dispute_window(request, &dispute_window_root, dispute_window_end),
            self.check_privacy_floor(request),
            self.check_watcher_quorum(request),
            self.check_nullifier(request),
            self.check_metadata_budget(request),
        ];
        let denial_reason = checks
            .iter()
            .find(|check| !check.status.accepts())
            .map(|check| check.denial_reason)
            .unwrap_or(DenialReason::None);
        let status = receipt_status(
            denial_reason,
            self.config.current_height,
            dispute_window_end,
        );
        let checks_root = merkle_root(
            "settlement_receipt_verifier:checks",
            &checks
                .iter()
                .map(VerifierCheck::public_record)
                .collect::<Vec<_>>(),
        );
        let release_decision_root = release_decision_root(
            status,
            denial_reason,
            &binding_root,
            &release_authorization_root,
            &checks_root,
        );
        let verification_root = verification_root(
            status,
            denial_reason,
            &request.receipt_id,
            &request.exit_claim_id,
            &request_root,
            &release_decision_root,
        );

        SettlementReceiptVerification {
            receipt_id: request.receipt_id.clone(),
            exit_claim_id: request.exit_claim_id.clone(),
            status,
            denial_reason,
            request_root,
            binding_root,
            low_fee_receipt_root,
            encrypted_wallet_receipt_root: request.encrypted_wallet_receipt_root.clone(),
            wallet_visible_receipt_root,
            dispute_window_root,
            release_authorization_root,
            release_decision_root,
            checks_root,
            verification_root,
            release_height,
            dispute_window_end,
            checks,
        }
    }

    fn check_transfer_output(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        let present = !request.private_transfer_output_root.is_empty();
        check_from_bool(
            VerifierCheckKind::TransferOutputBound,
            present || !self.config.require_transfer_output_binding,
            DenialReason::MissingTransferOutput,
            request.private_transfer_output_root.clone(),
        )
    }

    fn check_action_output(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        let present = !request.private_action_output_root.is_empty();
        check_from_bool(
            VerifierCheckKind::ActionOutputBound,
            present || !self.config.require_action_output_binding,
            DenialReason::MissingActionOutput,
            request.private_action_output_root.clone(),
        )
    }

    fn check_exit_claim(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        let expected = release_request_root(
            &request.receipt_id,
            &request.exit_claim_id,
            &request.exit_claim_root,
            &request.burn_nullifier_root,
        );
        check_from_bool(
            VerifierCheckKind::ExitClaimBound,
            request.requested_release_root == expected,
            DenialReason::ExitClaimMismatch,
            expected,
        )
    }

    fn check_low_fee(
        &self,
        request: &SettlementReceiptRequest,
        low_fee_receipt_root: &str,
    ) -> VerifierCheck {
        let fee_bps = fee_bps(request.fee_atomic, request.amount_atomic);
        let accepted = request.fee_atomic <= self.config.low_fee_cap_atomic
            && fee_bps <= u128::from(self.config.max_fee_bps);
        check_from_bool(
            VerifierCheckKind::LowFeeReceipt,
            accepted,
            DenialReason::FeeAboveLowFeeCap,
            low_fee_receipt_root.to_string(),
        )
    }

    fn check_wallet_encryption(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        check_from_bool(
            VerifierCheckKind::WalletReceiptEncrypted,
            !request.encrypted_wallet_receipt_root.is_empty(),
            DenialReason::WalletReceiptNotDecryptable,
            request.encrypted_wallet_receipt_root.clone(),
        )
    }

    fn check_wallet_visibility(
        &self,
        request: &SettlementReceiptRequest,
        wallet_visible_receipt_root: &str,
    ) -> VerifierCheck {
        let visible = !request.wallet_view_key_commitment_root.is_empty()
            && !request.encrypted_wallet_receipt_root.is_empty();
        check_from_bool(
            VerifierCheckKind::WalletReceiptVisible,
            visible || !self.config.require_wallet_visible_receipt,
            DenialReason::WalletReceiptNotDecryptable,
            wallet_visible_receipt_root.to_string(),
        )
    }

    fn check_release_authorization(
        &self,
        request: &SettlementReceiptRequest,
        release_authorization_root: &str,
    ) -> VerifierCheck {
        let present = !request.release_authorization_root.is_empty()
            && request.release_authorization_root != empty_root();
        check_from_bool(
            VerifierCheckKind::ReleaseAuthorizationRootPresent,
            present || !self.config.require_release_authorization_root,
            DenialReason::ReleaseAuthorizationMissing,
            release_authorization_root.to_string(),
        )
    }

    fn check_dispute_window(
        &self,
        _request: &SettlementReceiptRequest,
        dispute_window_root: &str,
        dispute_window_end: u64,
    ) -> VerifierCheck {
        check_from_bool(
            VerifierCheckKind::DisputeWindowElapsed,
            self.config.current_height >= dispute_window_end,
            DenialReason::DisputeWindowActive,
            dispute_window_root.to_string(),
        )
    }

    fn check_privacy_floor(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        check_from_bool(
            VerifierCheckKind::PrivacyFloorMet,
            request.privacy_set_size >= self.config.min_privacy_set_size,
            DenialReason::PrivacyFloorNotMet,
            privacy_floor_root(request.privacy_set_size, self.config.min_privacy_set_size),
        )
    }

    fn check_watcher_quorum(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        check_from_bool(
            VerifierCheckKind::WatcherQuorumMet,
            request.watcher_quorum >= self.config.min_watcher_quorum,
            DenialReason::WatcherQuorumMissing,
            request.watcher_attestation_root.clone(),
        )
    }

    fn check_nullifier(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        check_from_bool(
            VerifierCheckKind::NullifierUnique,
            !self.config.deny_duplicate_nullifiers || !request.duplicate_nullifier_seen,
            DenialReason::DuplicateNullifier,
            request.burn_nullifier_root.clone(),
        )
    }

    fn check_metadata_budget(&self, request: &SettlementReceiptRequest) -> VerifierCheck {
        check_from_bool(
            VerifierCheckKind::MetadataBudgetMet,
            request.metadata_leakage_units <= self.config.max_metadata_leakage_units,
            DenialReason::MetadataLeakageExceeded,
            request.metadata_budget_root.clone(),
        )
    }

    fn recompute_roots(&mut self) {
        self.config_root = self.config.state_root();
        self.receipt_root = merkle_root(
            "settlement_receipt_verifier:receipts",
            &self
                .receipts
                .values()
                .map(SettlementReceiptVerification::public_record)
                .collect::<Vec<_>>(),
        );
        self.report = self.build_report();
        self.report_root = self.report.report_root.clone();
        self.state_root =
            runtime_state_root(&self.config_root, &self.receipt_root, &self.report_root);
    }

    fn build_report(&self) -> VerifierReport {
        let receipts_verified = self.receipts.len() as u64;
        let release_authorized_count = self
            .receipts
            .values()
            .filter(|receipt| receipt.status == ReceiptStatus::ReleaseAuthorized)
            .count() as u64;
        let denied_count = self
            .receipts
            .values()
            .filter(|receipt| receipt.status == ReceiptStatus::Denied)
            .count() as u64;
        let open_dispute_count = self
            .receipts
            .values()
            .filter(|receipt| receipt.status == ReceiptStatus::DisputeWindowOpen)
            .count() as u64;
        let low_fee_receipt_count = self
            .receipts
            .values()
            .filter(|receipt| {
                receipt.checks.iter().any(|check| {
                    check.kind == VerifierCheckKind::LowFeeReceipt
                        && check.status == CheckStatus::Passed
                })
            })
            .count() as u64;
        let encrypted_wallet_receipt_count = self
            .receipts
            .values()
            .filter(|receipt| !receipt.encrypted_wallet_receipt_root.is_empty())
            .count() as u64;
        let denial_roots = self
            .receipts
            .iter()
            .filter(|(_, receipt)| receipt.denial_reason != DenialReason::None)
            .map(|(receipt_id, receipt)| {
                (
                    receipt_id.clone(),
                    denial_root(receipt.denial_reason, &receipt.verification_root),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let release_authorization_root = merkle_root(
            "settlement_receipt_verifier:authorized_release_roots",
            &self
                .receipts
                .values()
                .filter(|receipt| receipt.status == ReceiptStatus::ReleaseAuthorized)
                .map(|receipt| json!({ "release_authorization_root": receipt.release_authorization_root }))
                .collect::<Vec<_>>(),
        );
        let denial_root = merkle_root(
            "settlement_receipt_verifier:denials",
            &denial_roots
                .iter()
                .map(|(receipt_id, root)| json!({ "receipt_id": receipt_id, "denial_root": root }))
                .collect::<Vec<_>>(),
        );
        let status = report_status(receipts_verified, denied_count, open_dispute_count);
        let report_root = verifier_report_root(
            status,
            receipts_verified,
            release_authorized_count,
            denied_count,
            open_dispute_count,
            &self.receipt_root,
            &release_authorization_root,
            &denial_root,
        );

        VerifierReport {
            status,
            receipts_verified,
            release_authorized_count,
            denied_count,
            open_dispute_count,
            low_fee_receipt_count,
            encrypted_wallet_receipt_count,
            denial_roots,
            receipt_root: self.receipt_root.clone(),
            release_authorization_root,
            denial_root,
            report_root,
        }
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

fn empty_report() -> VerifierReport {
    let receipt_root = merkle_root("settlement_receipt_verifier:empty_receipts", &[]);
    let release_authorization_root = merkle_root(
        "settlement_receipt_verifier:empty_authorized_release_roots",
        &[],
    );
    let denial_root = merkle_root("settlement_receipt_verifier:empty_denials", &[]);
    let report_root = verifier_report_root(
        VerifierReportStatus::Passed,
        0,
        0,
        0,
        0,
        &receipt_root,
        &release_authorization_root,
        &denial_root,
    );
    VerifierReport {
        status: VerifierReportStatus::Passed,
        receipts_verified: 0,
        release_authorized_count: 0,
        denied_count: 0,
        open_dispute_count: 0,
        low_fee_receipt_count: 0,
        encrypted_wallet_receipt_count: 0,
        denial_roots: BTreeMap::new(),
        receipt_root,
        release_authorization_root,
        denial_root,
        report_root,
    }
}

fn check_from_bool(
    kind: VerifierCheckKind,
    accepted: bool,
    denial_reason: DenialReason,
    evidence_root: String,
) -> VerifierCheck {
    if accepted {
        VerifierCheck::new(kind, CheckStatus::Passed, DenialReason::None, evidence_root)
    } else {
        VerifierCheck::new(kind, CheckStatus::Failed, denial_reason, evidence_root)
    }
}

fn receipt_status(
    denial_reason: DenialReason,
    current_height: u64,
    dispute_window_end: u64,
) -> ReceiptStatus {
    if denial_reason != DenialReason::None {
        if denial_reason == DenialReason::DisputeWindowActive {
            ReceiptStatus::DisputeWindowOpen
        } else {
            ReceiptStatus::Denied
        }
    } else if current_height >= dispute_window_end {
        ReceiptStatus::ReleaseAuthorized
    } else {
        ReceiptStatus::DisputeWindowOpen
    }
}

fn report_status(
    receipts_verified: u64,
    denied_count: u64,
    open_dispute_count: u64,
) -> VerifierReportStatus {
    if denied_count > 0 {
        VerifierReportStatus::Failed
    } else if open_dispute_count > 0 || receipts_verified == 0 {
        VerifierReportStatus::Watch
    } else {
        VerifierReportStatus::Passed
    }
}

fn fee_bps(fee_atomic: u128, amount_atomic: u128) -> u128 {
    if amount_atomic == 0 {
        return u128::from(MAX_BPS);
    }
    fee_atomic.saturating_mul(u128::from(MAX_BPS)) / amount_atomic
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn empty_root() -> String {
    domain_hash("settlement_receipt_verifier:empty", &[], 32)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "settlement_receipt_verifier:record",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn binding_root(
    kind: OutputBindingKind,
    receipt_id: &str,
    exit_claim_id: &str,
    ordinal: u64,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:binding",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn release_request_root(
    receipt_id: &str,
    exit_claim_id: &str,
    exit_claim_root: &str,
    burn_nullifier_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:release_request",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(exit_claim_root),
            HashPart::Str(burn_nullifier_root),
        ],
        32,
    )
}

fn wallet_view_key_commitment_root(
    receipt_id: &str,
    exit_claim_id: &str,
    encrypted_wallet_receipt_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:wallet_view_key_commitment",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(encrypted_wallet_receipt_root),
        ],
        32,
    )
}

fn watcher_attestation_root(receipt_id: &str, exit_claim_id: &str, watcher_quorum: u64) -> String {
    domain_hash(
        "settlement_receipt_verifier:watcher_attestation",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::U64(watcher_quorum),
        ],
        32,
    )
}

fn dispute_evidence_root(receipt_id: &str, exit_claim_id: &str, dispute_state: &str) -> String {
    domain_hash(
        "settlement_receipt_verifier:dispute_evidence",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(dispute_state),
        ],
        32,
    )
}

fn metadata_budget_root(receipt_id: &str, exit_claim_id: &str, leakage_units: u64) -> String {
    domain_hash(
        "settlement_receipt_verifier:metadata_budget",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::U64(leakage_units),
        ],
        32,
    )
}

fn release_authorization_root(
    receipt_id: &str,
    exit_claim_id: &str,
    requested_release_root: &str,
    watcher_attestation_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:release_authorization",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(requested_release_root),
            HashPart::Str(watcher_attestation_root),
        ],
        32,
    )
}

fn settlement_binding_root(request: &SettlementReceiptRequest, request_root: &str) -> String {
    domain_hash(
        "settlement_receipt_verifier:settlement_binding",
        &[
            HashPart::Str(request.settlement_lane.as_str()),
            HashPart::Str(&request.private_transfer_output_root),
            HashPart::Str(&request.private_action_output_root),
            HashPart::Str(&request.exit_claim_root),
            HashPart::Str(&request.requested_release_root),
            HashPart::Str(request_root),
        ],
        32,
    )
}

fn low_fee_receipt_root(
    receipt_id: &str,
    fee_atomic: u128,
    low_fee_cap_atomic: u128,
    fee_bps: u128,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:low_fee_receipt",
        &[
            HashPart::Str(receipt_id),
            HashPart::Int(fee_atomic as i128),
            HashPart::Int(low_fee_cap_atomic as i128),
            HashPart::Int(fee_bps as i128),
        ],
        32,
    )
}

fn wallet_visible_receipt_root(
    receipt_id: &str,
    encrypted_wallet_receipt_root: &str,
    wallet_view_key_commitment_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:wallet_visible_receipt",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(encrypted_wallet_receipt_root),
            HashPart::Str(wallet_view_key_commitment_root),
        ],
        32,
    )
}

fn dispute_window_root(
    receipt_id: &str,
    submitted_height: u64,
    dispute_window_end: u64,
    current_height: u64,
    dispute_evidence_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:dispute_window",
        &[
            HashPart::Str(receipt_id),
            HashPart::U64(submitted_height),
            HashPart::U64(dispute_window_end),
            HashPart::U64(current_height),
            HashPart::Str(dispute_evidence_root),
        ],
        32,
    )
}

fn release_authorization_decision_root(
    receipt_id: &str,
    release_authorization_root: &str,
    requested_release_root: &str,
    release_height: u64,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:release_authorization_decision",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(release_authorization_root),
            HashPart::Str(requested_release_root),
            HashPart::U64(release_height),
        ],
        32,
    )
}

fn privacy_floor_root(privacy_set_size: u64, min_privacy_set_size: u64) -> String {
    domain_hash(
        "settlement_receipt_verifier:privacy_floor",
        &[
            HashPart::U64(privacy_set_size),
            HashPart::U64(min_privacy_set_size),
        ],
        32,
    )
}

fn verifier_check_root(
    kind: VerifierCheckKind,
    status: CheckStatus,
    denial_reason: DenialReason,
    evidence_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:check",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(denial_reason.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn release_decision_root(
    status: ReceiptStatus,
    denial_reason: DenialReason,
    binding_root: &str,
    release_authorization_root: &str,
    checks_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:release_decision",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(denial_reason.as_str()),
            HashPart::Str(binding_root),
            HashPart::Str(release_authorization_root),
            HashPart::Str(checks_root),
            HashPart::Str(bool_str(status.releases())),
        ],
        32,
    )
}

fn verification_root(
    status: ReceiptStatus,
    denial_reason: DenialReason,
    receipt_id: &str,
    exit_claim_id: &str,
    request_root: &str,
    release_decision_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:verification",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(denial_reason.as_str()),
            HashPart::Str(receipt_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(request_root),
            HashPart::Str(release_decision_root),
        ],
        32,
    )
}

fn denial_root(denial_reason: DenialReason, verification_root: &str) -> String {
    domain_hash(
        "settlement_receipt_verifier:denial",
        &[
            HashPart::Str(denial_reason.as_str()),
            HashPart::Str(verification_root),
        ],
        32,
    )
}

fn verifier_report_root(
    status: VerifierReportStatus,
    receipts_verified: u64,
    release_authorized_count: u64,
    denied_count: u64,
    open_dispute_count: u64,
    receipt_root: &str,
    release_authorization_root: &str,
    denial_root: &str,
) -> String {
    domain_hash(
        "settlement_receipt_verifier:report",
        &[
            HashPart::Str(status.as_str()),
            HashPart::U64(receipts_verified),
            HashPart::U64(release_authorized_count),
            HashPart::U64(denied_count),
            HashPart::U64(open_dispute_count),
            HashPart::Str(receipt_root),
            HashPart::Str(release_authorization_root),
            HashPart::Str(denial_root),
        ],
        32,
    )
}

fn runtime_state_root(config_root: &str, receipt_root: &str, report_root: &str) -> String {
    domain_hash(
        "settlement_receipt_verifier:state",
        &[
            HashPart::Str(config_root),
            HashPart::Str(receipt_root),
            HashPart::Str(report_root),
        ],
        32,
    )
}
