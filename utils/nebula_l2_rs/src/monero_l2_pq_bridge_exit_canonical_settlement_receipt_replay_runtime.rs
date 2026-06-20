use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalSettlementReceiptReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_SETTLEMENT_RECEIPT_REPLAY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-settlement-receipt-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_SETTLEMENT_RECEIPT_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const REPLAY_SUITE: &str = "canonical-settlement-receipt-forced-exit-replay-fail-closed-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_260_512;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_LOW_FEE_BATCH_CAP_ATOMIC: u128 = 140_000_000;
pub const DEFAULT_MAX_REPLAY_ITEMS: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLane {
    PrivateTransfer,
    ForcedExit,
    LiquidityBackstop,
    EmergencyEscape,
}

impl ReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ForcedExit => "forced_exit",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    AcceptedForForcedExit,
    WatchDisputeWindow,
    RejectedFailClosed,
}

impl ReplayStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedForForcedExit => "accepted_for_forced_exit",
            Self::WatchDisputeWindow => "watch_dispute_window",
            Self::RejectedFailClosed => "rejected_fail_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCheckKind {
    SettlementReceiptRootBound,
    ExitClaimRootBound,
    ReleaseAuthorizationLinked,
    ReserveRootSufficient,
    EncryptedWalletReceiptMaterialBound,
    LowFeeCapRespected,
    PrivacyFloorMet,
    WatcherQuorumMet,
    DisputeWindowElapsed,
    NullifierUnique,
}

impl ReplayCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementReceiptRootBound => "settlement_receipt_root_bound",
            Self::ExitClaimRootBound => "exit_claim_root_bound",
            Self::ReleaseAuthorizationLinked => "release_authorization_linked",
            Self::ReserveRootSufficient => "reserve_root_sufficient",
            Self::EncryptedWalletReceiptMaterialBound => "encrypted_wallet_receipt_material_bound",
            Self::LowFeeCapRespected => "low_fee_cap_respected",
            Self::PrivacyFloorMet => "privacy_floor_met",
            Self::WatcherQuorumMet => "watcher_quorum_met",
            Self::DisputeWindowElapsed => "dispute_window_elapsed",
            Self::NullifierUnique => "nullifier_unique",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Accepted,
    Watch,
    Rejected,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    None,
    SettlementReceiptRootMissing,
    ExitClaimRootMissing,
    ReleaseAuthorizationMismatch,
    ReserveRootInsufficient,
    EncryptedWalletReceiptMaterialMissing,
    FeeAboveLowFeeCap,
    PrivacyFloorNotMet,
    WatcherQuorumMissing,
    DisputeWindowOpen,
    DuplicateNullifier,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SettlementReceiptRootMissing => "settlement_receipt_root_missing",
            Self::ExitClaimRootMissing => "exit_claim_root_missing",
            Self::ReleaseAuthorizationMismatch => "release_authorization_mismatch",
            Self::ReserveRootInsufficient => "reserve_root_insufficient",
            Self::EncryptedWalletReceiptMaterialMissing => {
                "encrypted_wallet_receipt_material_missing"
            }
            Self::FeeAboveLowFeeCap => "fee_above_low_fee_cap",
            Self::PrivacyFloorNotMet => "privacy_floor_not_met",
            Self::WatcherQuorumMissing => "watcher_quorum_missing",
            Self::DisputeWindowOpen => "dispute_window_open",
            Self::DuplicateNullifier => "duplicate_nullifier",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub replay_suite: String,
    pub current_height: u64,
    pub dispute_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub min_reserve_coverage_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_watcher_quorum: u64,
    pub max_metadata_leakage_units: u64,
    pub low_fee_cap_atomic: u128,
    pub low_fee_batch_cap_atomic: u128,
    pub require_release_authorization_linkage: bool,
    pub require_encrypted_wallet_receipt_material: bool,
    pub fail_closed_on_any_rejection: bool,
    pub production_release_allowed: bool,
    pub max_replay_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            replay_suite: REPLAY_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            low_fee_batch_cap_atomic: DEFAULT_LOW_FEE_BATCH_CAP_ATOMIC,
            require_release_authorization_linkage: true,
            require_encrypted_wallet_receipt_material: true,
            fail_closed_on_any_rejection: true,
            production_release_allowed: false,
            max_replay_items: DEFAULT_MAX_REPLAY_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "replay_suite": self.replay_suite,
            "current_height": self.current_height,
            "dispute_window_blocks": self.dispute_window_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "low_fee_cap_atomic": self.low_fee_cap_atomic.to_string(),
            "low_fee_batch_cap_atomic": self.low_fee_batch_cap_atomic.to_string(),
            "require_release_authorization_linkage": self.require_release_authorization_linkage,
            "require_encrypted_wallet_receipt_material": self.require_encrypted_wallet_receipt_material,
            "fail_closed_on_any_rejection": self.fail_closed_on_any_rejection,
            "production_release_allowed": self.production_release_allowed,
            "max_replay_items": self.max_replay_items,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub lane: ReceiptLane,
    pub settlement_receipt_root: String,
    pub settlement_batch_root: String,
    pub receipt_nullifier_root: String,
    pub public_receipt_material_root: String,
    pub encrypted_wallet_receipt_material_root: String,
    pub wallet_view_key_commitment_root: String,
    pub amount_atomic: u128,
    pub fee_atomic: u128,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
    pub watcher_quorum: u64,
    pub pq_security_bits: u16,
    pub settled_at_height: u64,
    pub duplicate_nullifier_seen: bool,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "settlement_receipt_root": self.settlement_receipt_root,
            "settlement_batch_root": self.settlement_batch_root,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "public_receipt_material_root": self.public_receipt_material_root,
            "encrypted_wallet_receipt_material_root": self.encrypted_wallet_receipt_material_root,
            "wallet_view_key_commitment_root": self.wallet_view_key_commitment_root,
            "amount_atomic": self.amount_atomic.to_string(),
            "fee_atomic": self.fee_atomic.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "watcher_quorum": self.watcher_quorum,
            "pq_security_bits": self.pq_security_bits,
            "settled_at_height": self.settled_at_height,
            "duplicate_nullifier_seen": self.duplicate_nullifier_seen,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("settlement-receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaim {
    pub claim_id: String,
    pub receipt_id: String,
    pub exit_claim_root: String,
    pub recipient_commitment_root: String,
    pub forced_exit_gate_root: String,
    pub claim_amount_atomic: u128,
    pub claim_fee_atomic: u128,
    pub claim_created_at_height: u64,
    pub release_not_before_height: u64,
}

impl ExitClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "receipt_id": self.receipt_id,
            "exit_claim_root": self.exit_claim_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "forced_exit_gate_root": self.forced_exit_gate_root,
            "claim_amount_atomic": self.claim_amount_atomic.to_string(),
            "claim_fee_atomic": self.claim_fee_atomic.to_string(),
            "claim_created_at_height": self.claim_created_at_height,
            "release_not_before_height": self.release_not_before_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("exit-claim", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseAuthorizationLinkage {
    pub linkage_id: String,
    pub receipt_id: String,
    pub claim_id: String,
    pub release_authorization_root: String,
    pub pq_authority_root: String,
    pub withdrawal_authorization_root: String,
    pub dispute_window_root: String,
    pub reserve_release_root: String,
    pub linked_at_height: u64,
}

impl ReleaseAuthorizationLinkage {
    pub fn linked(&self, receipt: &SettlementReceipt, claim: &ExitClaim) -> bool {
        self.receipt_id == receipt.receipt_id && self.claim_id == claim.claim_id
    }

    pub fn public_record(&self) -> Value {
        json!({
            "linkage_id": self.linkage_id,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "release_authorization_root": self.release_authorization_root,
            "pq_authority_root": self.pq_authority_root,
            "withdrawal_authorization_root": self.withdrawal_authorization_root,
            "dispute_window_root": self.dispute_window_root,
            "reserve_release_root": self.reserve_release_root,
            "linked_at_height": self.linked_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-authorization-linkage", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveSnapshot {
    pub reserve_id: String,
    pub reserve_root: String,
    pub liquidity_bucket_root: String,
    pub committed_atomic: u128,
    pub pending_liability_atomic: u128,
    pub unlocked_liquidity_atomic: u128,
    pub reserve_coverage_bps: u64,
    pub measured_at_height: u64,
}

impl ReserveSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "reserve_root": self.reserve_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "committed_atomic": self.committed_atomic.to_string(),
            "pending_liability_atomic": self.pending_liability_atomic.to_string(),
            "unlocked_liquidity_atomic": self.unlocked_liquidity_atomic.to_string(),
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "measured_at_height": self.measured_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve-snapshot", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayCheck {
    pub check_id: String,
    pub receipt_id: String,
    pub claim_id: String,
    pub kind: ReplayCheckKind,
    pub status: CheckStatus,
    pub rejection_reason: RejectionReason,
    pub evidence_root: String,
    pub observed: String,
}

impl ReplayCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "rejection_reason": self.rejection_reason.as_str(),
            "evidence_root": self.evidence_root,
            "observed": self.observed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replay-check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptReplay {
    pub replay_id: String,
    pub receipt_id: String,
    pub claim_id: String,
    pub status: ReplayStatus,
    pub rejection_reason: RejectionReason,
    pub settlement_receipt_root: String,
    pub exit_claim_root: String,
    pub release_authorization_root: String,
    pub reserve_root: String,
    pub encrypted_wallet_receipt_material_root: String,
    pub low_fee_root: String,
    pub check_root: String,
    pub release_height: u64,
    pub sufficient_to_drive_forced_exit: bool,
}

impl ReceiptReplay {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_id": self.replay_id,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "status": self.status.as_str(),
            "rejection_reason": self.rejection_reason.as_str(),
            "settlement_receipt_root": self.settlement_receipt_root,
            "exit_claim_root": self.exit_claim_root,
            "release_authorization_root": self.release_authorization_root,
            "reserve_root": self.reserve_root,
            "encrypted_wallet_receipt_material_root": self.encrypted_wallet_receipt_material_root,
            "low_fee_root": self.low_fee_root,
            "check_root": self.check_root,
            "release_height": self.release_height,
            "sufficient_to_drive_forced_exit": self.sufficient_to_drive_forced_exit,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-replay", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayReport {
    pub report_id: String,
    pub status: ReplayStatus,
    pub sufficient_receipt_count: u64,
    pub watched_receipt_count: u64,
    pub rejected_receipt_count: u64,
    pub settlement_receipt_root: String,
    pub exit_claim_root: String,
    pub release_authorization_root: String,
    pub reserve_root: String,
    pub encrypted_wallet_receipt_material_root: String,
    pub low_fee_root: String,
    pub replay_root: String,
    pub rejection_root: String,
    pub answer: String,
}

impl ReplayReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "sufficient_receipt_count": self.sufficient_receipt_count,
            "watched_receipt_count": self.watched_receipt_count,
            "rejected_receipt_count": self.rejected_receipt_count,
            "settlement_receipt_root": self.settlement_receipt_root,
            "exit_claim_root": self.exit_claim_root,
            "release_authorization_root": self.release_authorization_root,
            "reserve_root": self.reserve_root,
            "encrypted_wallet_receipt_material_root": self.encrypted_wallet_receipt_material_root,
            "low_fee_root": self.low_fee_root,
            "replay_root": self.replay_root,
            "rejection_root": self.rejection_root,
            "answer": self.answer,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replay-report", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub receipts: u64,
    pub claims: u64,
    pub release_authorizations: u64,
    pub reserves: u64,
    pub checks: u64,
    pub replays: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "receipts": self.receipts,
            "claims": self.claims,
            "release_authorizations": self.release_authorizations,
            "reserves": self.reserves,
            "checks": self.checks,
            "replays": self.replays,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub settlement_receipts: Vec<SettlementReceipt>,
    pub exit_claims: Vec<ExitClaim>,
    pub release_authorizations: Vec<ReleaseAuthorizationLinkage>,
    pub reserves: Vec<ReserveSnapshot>,
    pub checks: Vec<ReplayCheck>,
    pub replays: Vec<ReceiptReplay>,
    pub latest_report: ReplayReport,
    pub counters: Counters,
    pub metadata: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            settlement_receipts: Vec::new(),
            exit_claims: Vec::new(),
            release_authorizations: Vec::new(),
            reserves: Vec::new(),
            checks: Vec::new(),
            replays: Vec::new(),
            latest_report: empty_report(),
            counters: Counters::default(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.metadata.insert(
            "fixture".to_string(),
            "canonical settlement receipt replay for forced-exit sufficiency".to_string(),
        );
        state.metadata.insert(
            "forced_exit_question".to_string(),
            "is the settlement receipt sufficient to drive a forced exit".to_string(),
        );

        let receipt_a = devnet_receipt(
            "receipt-a",
            ReceiptLane::ForcedExit,
            40_000_000_000,
            24_000_000,
            DEFAULT_CURRENT_HEIGHT - DEFAULT_DISPUTE_WINDOW_BLOCKS - 72,
            false,
        );
        let claim_a = devnet_claim(
            "claim-a",
            &receipt_a.receipt_id,
            receipt_a.amount_atomic - receipt_a.fee_atomic,
            receipt_a.fee_atomic,
            DEFAULT_CURRENT_HEIGHT - DEFAULT_DISPUTE_WINDOW_BLOCKS - 60,
            DEFAULT_CURRENT_HEIGHT - 12,
        );
        let authorization_a =
            devnet_authorization("auth-a", &receipt_a.receipt_id, &claim_a.claim_id);
        let reserve_a = devnet_reserve("reserve-a", claim_a.claim_amount_atomic, true);
        state.add_replay(receipt_a, claim_a, authorization_a, reserve_a);

        let mut receipt_b = devnet_receipt(
            "receipt-b",
            ReceiptLane::PrivateTransfer,
            12_500_000_000,
            DEFAULT_LOW_FEE_CAP_ATOMIC + 4_000_000,
            DEFAULT_CURRENT_HEIGHT - 48,
            false,
        );
        receipt_b.encrypted_wallet_receipt_material_root = String::new();
        let claim_b = devnet_claim(
            "claim-b",
            &receipt_b.receipt_id,
            receipt_b.amount_atomic - receipt_b.fee_atomic,
            receipt_b.fee_atomic,
            DEFAULT_CURRENT_HEIGHT - 40,
            DEFAULT_CURRENT_HEIGHT + DEFAULT_DISPUTE_WINDOW_BLOCKS,
        );
        let authorization_b =
            devnet_authorization("auth-b", &receipt_b.receipt_id, &claim_b.claim_id);
        let reserve_b = devnet_reserve("reserve-b", claim_b.claim_amount_atomic, false);
        state.add_replay(receipt_b, claim_b, authorization_b, reserve_b);

        state.recompute();
        state
    }

    pub fn add_replay(
        &mut self,
        receipt: SettlementReceipt,
        claim: ExitClaim,
        authorization: ReleaseAuthorizationLinkage,
        reserve: ReserveSnapshot,
    ) {
        let checks = build_checks(&self.config, &receipt, &claim, &authorization, &reserve);
        let replay = build_replay(
            &self.config,
            &receipt,
            &claim,
            &authorization,
            &reserve,
            &checks,
        );
        self.settlement_receipts.push(receipt);
        self.exit_claims.push(claim);
        self.release_authorizations.push(authorization);
        self.reserves.push(reserve);
        self.checks.extend(checks);
        self.replays.push(replay);
        self.recompute();
    }

    pub fn recompute(&mut self) {
        self.counters = Counters {
            receipts: self.settlement_receipts.len() as u64,
            claims: self.exit_claims.len() as u64,
            release_authorizations: self.release_authorizations.len() as u64,
            reserves: self.reserves.len() as u64,
            checks: self.checks.len() as u64,
            replays: self.replays.len() as u64,
        };
        self.latest_report = build_report(self);
    }

    pub fn settlement_receipt_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-SETTLEMENT-RECEIPTS",
            &self
                .settlement_receipts
                .iter()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn exit_claim_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-EXIT-CLAIMS",
            &self
                .exit_claims
                .iter()
                .map(ExitClaim::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn release_authorization_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-RELEASE-AUTHORIZATIONS",
            &self
                .release_authorizations
                .iter()
                .map(ReleaseAuthorizationLinkage::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn reserve_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-RESERVES",
            &self
                .reserves
                .iter()
                .map(ReserveSnapshot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn encrypted_wallet_receipt_material_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-ENCRYPTED-WALLET-MATERIAL",
            &self
                .settlement_receipts
                .iter()
                .map(|receipt| {
                    json!({
                        "receipt_id": receipt.receipt_id,
                        "encrypted_wallet_receipt_material_root": receipt.encrypted_wallet_receipt_material_root,
                        "wallet_view_key_commitment_root": receipt.wallet_view_key_commitment_root,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-LOW-FEE-CAPS",
            &self
                .settlement_receipts
                .iter()
                .map(|receipt| {
                    json!({
                        "receipt_id": receipt.receipt_id,
                        "fee_atomic": receipt.fee_atomic.to_string(),
                        "low_fee_cap_atomic": self.config.low_fee_cap_atomic.to_string(),
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn check_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-CHECKS",
            &self
                .checks
                .iter()
                .map(ReplayCheck::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn replay_root(&self) -> String {
        merkle_root(
            "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-REPLAYS",
            &self
                .replays
                .iter()
                .map(ReceiptReplay::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "settlement_receipt_root": self.settlement_receipt_root(),
            "exit_claim_root": self.exit_claim_root(),
            "release_authorization_root": self.release_authorization_root(),
            "reserve_root": self.reserve_root(),
            "encrypted_wallet_receipt_material_root": self.encrypted_wallet_receipt_material_root(),
            "low_fee_root": self.low_fee_root(),
            "check_root": self.check_root(),
            "replay_root": self.replay_root(),
            "settlement_receipts": self.settlement_receipts.iter().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "exit_claims": self.exit_claims.iter().map(ExitClaim::public_record).collect::<Vec<_>>(),
            "release_authorizations": self.release_authorizations.iter().map(ReleaseAuthorizationLinkage::public_record).collect::<Vec<_>>(),
            "reserves": self.reserves.iter().map(ReserveSnapshot::public_record).collect::<Vec<_>>(),
            "checks": self.checks.iter().map(ReplayCheck::public_record).collect::<Vec<_>>(),
            "replays": self.replays.iter().map(ReceiptReplay::public_record).collect::<Vec<_>>(),
            "latest_report": self.latest_report.public_record(),
            "counters": self.counters.public_record(),
            "metadata": self.metadata,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-SETTLEMENT-RECEIPT-REPLAY-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.settlement_receipt_root()),
                HashPart::Str(&self.exit_claim_root()),
                HashPart::Str(&self.release_authorization_root()),
                HashPart::Str(&self.reserve_root()),
                HashPart::Str(&self.check_root()),
                HashPart::Str(&self.replay_root()),
                HashPart::Str(&self.latest_report.state_root()),
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

fn build_checks(
    config: &Config,
    receipt: &SettlementReceipt,
    claim: &ExitClaim,
    authorization: &ReleaseAuthorizationLinkage,
    reserve: &ReserveSnapshot,
) -> Vec<ReplayCheck> {
    vec![
        make_check(
            receipt,
            claim,
            ReplayCheckKind::SettlementReceiptRootBound,
            !receipt.settlement_receipt_root.is_empty(),
            receipt.state_root(),
            RejectionReason::SettlementReceiptRootMissing,
            "settlement receipt root is bound",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::ExitClaimRootBound,
            !claim.exit_claim_root.is_empty() && claim.receipt_id == receipt.receipt_id,
            claim.state_root(),
            RejectionReason::ExitClaimRootMissing,
            "exit claim root binds the receipt",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::ReleaseAuthorizationLinked,
            !config.require_release_authorization_linkage || authorization.linked(receipt, claim),
            authorization.state_root(),
            RejectionReason::ReleaseAuthorizationMismatch,
            "release authorization links receipt, claim, dispute, and reserve release roots",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::ReserveRootSufficient,
            reserve.reserve_coverage_bps >= config.min_reserve_coverage_bps
                && reserve.unlocked_liquidity_atomic >= claim.claim_amount_atomic,
            reserve.state_root(),
            RejectionReason::ReserveRootInsufficient,
            "reserve root has sufficient unlocked liquidity for the claim",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::EncryptedWalletReceiptMaterialBound,
            !config.require_encrypted_wallet_receipt_material
                || (!receipt.encrypted_wallet_receipt_material_root.is_empty()
                    && !receipt.wallet_view_key_commitment_root.is_empty()),
            wallet_material_root(receipt),
            RejectionReason::EncryptedWalletReceiptMaterialMissing,
            "encrypted wallet receipt material and view-key commitment are bound",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::LowFeeCapRespected,
            receipt.fee_atomic <= config.low_fee_cap_atomic
                && claim.claim_fee_atomic <= config.low_fee_cap_atomic,
            low_fee_receipt_root(receipt, config),
            RejectionReason::FeeAboveLowFeeCap,
            "receipt and claim fees remain inside the low-fee cap",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::PrivacyFloorMet,
            receipt.privacy_set_size >= config.min_privacy_set_size
                && receipt.metadata_leakage_units <= config.max_metadata_leakage_units,
            privacy_root(receipt, config),
            RejectionReason::PrivacyFloorNotMet,
            "privacy set and metadata leakage satisfy policy",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::WatcherQuorumMet,
            receipt.watcher_quorum >= config.min_watcher_quorum
                && receipt.pq_security_bits >= config.min_pq_security_bits,
            watcher_root(receipt),
            RejectionReason::WatcherQuorumMissing,
            "watcher quorum and PQ security floor are met",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::DisputeWindowElapsed,
            config.current_height >= claim.release_not_before_height,
            authorization.dispute_window_root.clone(),
            RejectionReason::DisputeWindowOpen,
            "release height is reachable after dispute window",
        ),
        make_check(
            receipt,
            claim,
            ReplayCheckKind::NullifierUnique,
            !receipt.duplicate_nullifier_seen,
            receipt.receipt_nullifier_root.clone(),
            RejectionReason::DuplicateNullifier,
            "receipt nullifier is unique for replay",
        ),
    ]
}

fn build_replay(
    config: &Config,
    receipt: &SettlementReceipt,
    claim: &ExitClaim,
    authorization: &ReleaseAuthorizationLinkage,
    reserve: &ReserveSnapshot,
    checks: &[ReplayCheck],
) -> ReceiptReplay {
    let rejection_reason = checks
        .iter()
        .find(|check| check.status == CheckStatus::Rejected)
        .map(|check| check.rejection_reason)
        .unwrap_or(RejectionReason::None);
    let watched = checks
        .iter()
        .any(|check| check.status == CheckStatus::Watch);
    let status = if rejection_reason != RejectionReason::None && config.fail_closed_on_any_rejection
    {
        ReplayStatus::RejectedFailClosed
    } else if watched {
        ReplayStatus::WatchDisputeWindow
    } else {
        ReplayStatus::AcceptedForForcedExit
    };
    let check_root = merkle_root(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-CHECKS-FOR-RECEIPT",
        &checks
            .iter()
            .map(ReplayCheck::public_record)
            .collect::<Vec<_>>(),
    );
    let sufficient_to_drive_forced_exit = status == ReplayStatus::AcceptedForForcedExit;
    let replay_id = stable_id("receipt-replay", &receipt.receipt_id);

    ReceiptReplay {
        replay_id,
        receipt_id: receipt.receipt_id.clone(),
        claim_id: claim.claim_id.clone(),
        status,
        rejection_reason,
        settlement_receipt_root: receipt.settlement_receipt_root.clone(),
        exit_claim_root: claim.exit_claim_root.clone(),
        release_authorization_root: authorization.release_authorization_root.clone(),
        reserve_root: reserve.reserve_root.clone(),
        encrypted_wallet_receipt_material_root: receipt
            .encrypted_wallet_receipt_material_root
            .clone(),
        low_fee_root: low_fee_receipt_root(receipt, config),
        check_root,
        release_height: claim.release_not_before_height,
        sufficient_to_drive_forced_exit,
    }
}

fn build_report(state: &State) -> ReplayReport {
    let sufficient_receipt_count = state
        .replays
        .iter()
        .filter(|replay| replay.sufficient_to_drive_forced_exit)
        .count() as u64;
    let watched_receipt_count = state
        .replays
        .iter()
        .filter(|replay| replay.status == ReplayStatus::WatchDisputeWindow)
        .count() as u64;
    let rejected_receipt_count = state
        .replays
        .iter()
        .filter(|replay| replay.status == ReplayStatus::RejectedFailClosed)
        .count() as u64;
    let status = if sufficient_receipt_count > 0 {
        ReplayStatus::AcceptedForForcedExit
    } else if watched_receipt_count > 0 {
        ReplayStatus::WatchDisputeWindow
    } else {
        ReplayStatus::RejectedFailClosed
    };
    let replay_root = state.replay_root();
    let rejection_root = merkle_root(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-FAIL-CLOSED-REJECTIONS",
        &state
            .replays
            .iter()
            .filter(|replay| replay.rejection_reason != RejectionReason::None)
            .map(|replay| {
                json!({
                    "receipt_id": replay.receipt_id,
                    "claim_id": replay.claim_id,
                    "rejection_reason": replay.rejection_reason.as_str(),
                    "replay_root": replay.state_root(),
                })
            })
            .collect::<Vec<_>>(),
    );
    let answer = if sufficient_receipt_count > 0 {
        "yes: at least one canonical settlement receipt is sufficient to drive a forced exit"
            .to_string()
    } else if watched_receipt_count > 0 {
        "not yet: replay is bound but waiting for the dispute window".to_string()
    } else {
        "no: all settlement receipt replays are rejected fail-closed".to_string()
    };
    let body = json!({
        "status": status.as_str(),
        "sufficient_receipt_count": sufficient_receipt_count,
        "watched_receipt_count": watched_receipt_count,
        "rejected_receipt_count": rejected_receipt_count,
        "replay_root": replay_root,
        "rejection_root": rejection_root,
        "answer": answer,
    });
    let report_id = stable_id("replay-report", &record_root("replay-report-body", &body));

    ReplayReport {
        report_id,
        status,
        sufficient_receipt_count,
        watched_receipt_count,
        rejected_receipt_count,
        settlement_receipt_root: state.settlement_receipt_root(),
        exit_claim_root: state.exit_claim_root(),
        release_authorization_root: state.release_authorization_root(),
        reserve_root: state.reserve_root(),
        encrypted_wallet_receipt_material_root: state.encrypted_wallet_receipt_material_root(),
        low_fee_root: state.low_fee_root(),
        replay_root,
        rejection_root,
        answer,
    }
}

fn empty_report() -> ReplayReport {
    let empty = merkle_root("CANONICAL-SETTLEMENT-RECEIPT-REPLAY-EMPTY", &[]);
    ReplayReport {
        report_id: stable_id("empty-report", &empty),
        status: ReplayStatus::RejectedFailClosed,
        sufficient_receipt_count: 0,
        watched_receipt_count: 0,
        rejected_receipt_count: 0,
        settlement_receipt_root: empty.clone(),
        exit_claim_root: empty.clone(),
        release_authorization_root: empty.clone(),
        reserve_root: empty.clone(),
        encrypted_wallet_receipt_material_root: empty.clone(),
        low_fee_root: empty.clone(),
        replay_root: empty.clone(),
        rejection_root: empty,
        answer: "no: no settlement receipt replay has been loaded".to_string(),
    }
}

fn make_check(
    receipt: &SettlementReceipt,
    claim: &ExitClaim,
    kind: ReplayCheckKind,
    accepted: bool,
    evidence_root: String,
    reason: RejectionReason,
    observed: &str,
) -> ReplayCheck {
    let release_pending = kind == ReplayCheckKind::DisputeWindowElapsed
        && reason == RejectionReason::DisputeWindowOpen;
    let status = if accepted {
        CheckStatus::Accepted
    } else if release_pending {
        CheckStatus::Watch
    } else {
        CheckStatus::Rejected
    };
    let rejection_reason = if status == CheckStatus::Accepted || status == CheckStatus::Watch {
        RejectionReason::None
    } else {
        reason
    };
    let check_id = replay_check_id(&receipt.receipt_id, &claim.claim_id, kind, &evidence_root);
    ReplayCheck {
        check_id,
        receipt_id: receipt.receipt_id.clone(),
        claim_id: claim.claim_id.clone(),
        kind,
        status,
        rejection_reason,
        evidence_root,
        observed: observed.to_string(),
    }
}

fn devnet_receipt(
    suffix: &str,
    lane: ReceiptLane,
    amount_atomic: u128,
    fee_atomic: u128,
    settled_at_height: u64,
    duplicate_nullifier_seen: bool,
) -> SettlementReceipt {
    let receipt_id = stable_id("devnet-receipt", suffix);
    SettlementReceipt {
        settlement_receipt_root: stable_id("settlement-receipt-root", &receipt_id),
        settlement_batch_root: stable_id("settlement-batch-root", &receipt_id),
        receipt_nullifier_root: stable_id("receipt-nullifier-root", &receipt_id),
        public_receipt_material_root: stable_id("public-receipt-material", &receipt_id),
        encrypted_wallet_receipt_material_root: stable_id(
            "encrypted-wallet-receipt-material",
            &receipt_id,
        ),
        wallet_view_key_commitment_root: stable_id("wallet-view-key-commitment", &receipt_id),
        receipt_id,
        lane,
        amount_atomic,
        fee_atomic,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        metadata_leakage_units: 1,
        watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM + 2,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        settled_at_height,
        duplicate_nullifier_seen,
    }
}

fn devnet_claim(
    suffix: &str,
    receipt_id: &str,
    claim_amount_atomic: u128,
    claim_fee_atomic: u128,
    claim_created_at_height: u64,
    release_not_before_height: u64,
) -> ExitClaim {
    let claim_id = stable_id("devnet-claim", suffix);
    ExitClaim {
        exit_claim_root: stable_id("exit-claim-root", &claim_id),
        recipient_commitment_root: stable_id("recipient-commitment-root", &claim_id),
        forced_exit_gate_root: stable_id("forced-exit-gate-root", &claim_id),
        claim_id,
        receipt_id: receipt_id.to_string(),
        claim_amount_atomic,
        claim_fee_atomic,
        claim_created_at_height,
        release_not_before_height,
    }
}

fn devnet_authorization(
    suffix: &str,
    receipt_id: &str,
    claim_id: &str,
) -> ReleaseAuthorizationLinkage {
    ReleaseAuthorizationLinkage {
        linkage_id: stable_id("release-linkage", suffix),
        receipt_id: receipt_id.to_string(),
        claim_id: claim_id.to_string(),
        release_authorization_root: stable_id("release-authorization-root", claim_id),
        pq_authority_root: stable_id("pq-authority-root", claim_id),
        withdrawal_authorization_root: stable_id("withdrawal-authorization-root", claim_id),
        dispute_window_root: stable_id("dispute-window-root", claim_id),
        reserve_release_root: stable_id("reserve-release-root", claim_id),
        linked_at_height: DEFAULT_CURRENT_HEIGHT - DEFAULT_RELEASE_DELAY_BLOCKS,
    }
}

fn devnet_reserve(suffix: &str, claim_amount_atomic: u128, sufficient: bool) -> ReserveSnapshot {
    let reserve_id = stable_id("reserve-snapshot", suffix);
    let unlocked_liquidity_atomic = if sufficient {
        claim_amount_atomic + DEFAULT_LOW_FEE_CAP_ATOMIC
    } else {
        claim_amount_atomic.saturating_sub(DEFAULT_LOW_FEE_CAP_ATOMIC)
    };
    let committed_atomic = claim_amount_atomic.saturating_mul(2);
    ReserveSnapshot {
        reserve_root: stable_id("reserve-root", &reserve_id),
        liquidity_bucket_root: stable_id("liquidity-bucket-root", &reserve_id),
        reserve_id,
        committed_atomic,
        pending_liability_atomic: claim_amount_atomic,
        unlocked_liquidity_atomic,
        reserve_coverage_bps: bps(committed_atomic, claim_amount_atomic),
        measured_at_height: DEFAULT_CURRENT_HEIGHT,
    }
}

fn low_fee_receipt_root(receipt: &SettlementReceipt, config: &Config) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-LOW-FEE-ROOT",
        &[
            HashPart::Str(&receipt.receipt_id),
            HashPart::Str(&receipt.fee_atomic.to_string()),
            HashPart::Str(&config.low_fee_cap_atomic.to_string()),
            HashPart::Str(&config.low_fee_batch_cap_atomic.to_string()),
        ],
        32,
    )
}

fn wallet_material_root(receipt: &SettlementReceipt) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-WALLET-MATERIAL",
        &[
            HashPart::Str(&receipt.receipt_id),
            HashPart::Str(&receipt.encrypted_wallet_receipt_material_root),
            HashPart::Str(&receipt.wallet_view_key_commitment_root),
        ],
        32,
    )
}

fn privacy_root(receipt: &SettlementReceipt, config: &Config) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-PRIVACY",
        &[
            HashPart::Str(&receipt.receipt_id),
            HashPart::U64(receipt.privacy_set_size),
            HashPart::U64(config.min_privacy_set_size),
            HashPart::U64(receipt.metadata_leakage_units),
            HashPart::U64(config.max_metadata_leakage_units),
        ],
        32,
    )
}

fn watcher_root(receipt: &SettlementReceipt) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-WATCHER",
        &[
            HashPart::Str(&receipt.receipt_id),
            HashPart::U64(receipt.watcher_quorum),
            HashPart::U64(u64::from(receipt.pq_security_bits)),
        ],
        32,
    )
}

fn replay_check_id(
    receipt_id: &str,
    claim_id: &str,
    kind: ReplayCheckKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-CHECK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(claim_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn stable_id(domain: &str, value: &str) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-STABLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "CANONICAL-SETTLEMENT-RECEIPT-REPLAY-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(MAX_BPS as u128)
        .checked_div(denominator)
        .unwrap_or(0)
        .min(u64::MAX as u128) as u64
}
