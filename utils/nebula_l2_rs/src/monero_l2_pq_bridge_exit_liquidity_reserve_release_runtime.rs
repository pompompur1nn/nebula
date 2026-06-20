use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::{
        State as TransferRuntimeState, TransferExitClaim, TransferReadinessReport,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::{
        ScenarioTranscript, State as ForcedExitScenarioState,
    },
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferReportStatus, State as AuthorityTransferState,
    },
    monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::{
        SafetyCaseReport, SafetyCaseVerdict, SafetyRequirement, State as BridgeExitSafetyCaseState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitLiquidityReserveReleaseRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_LIQUIDITY_RESERVE_RELEASE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-liquidity-reserve-release-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_LIQUIDITY_RESERVE_RELEASE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RESERVE_RELEASE_SUITE: &str = "monero-l2-pq-bridge-exit-liquidity-reserve-release-v1";
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_000;
pub const DEFAULT_EMERGENCY_RESERVE_BPS: u64 = 2_000;
pub const DEFAULT_MAX_RELEASE_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_UTILIZATION_BPS: u64 = 8_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_RELEASE_DECISIONS: u64 = 7;
pub const DEFAULT_MAX_REPORTS: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveLane {
    ForcedExitPrimary,
    EmergencyExitBuffer,
    WatcherBackstop,
    ChallengeSettlement,
    LowFeeSponsor,
    RebalanceAuction,
}

impl ReserveLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForcedExitPrimary => "forced_exit_primary",
            Self::EmergencyExitBuffer => "emergency_exit_buffer",
            Self::WatcherBackstop => "watcher_backstop",
            Self::ChallengeSettlement => "challenge_settlement",
            Self::LowFeeSponsor => "low_fee_sponsor",
            Self::RebalanceAuction => "rebalance_auction",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAccountStatus {
    Funded,
    Watch,
    Exhausted,
}

impl ReserveAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funded => "funded",
            Self::Watch => "watch",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecisionKind {
    PrimaryReserveReservation,
    EmergencyReserveBuffer,
    WatcherBackstopEscrow,
    ChallengeSettlementHoldback,
    LowFeeSponsorCap,
    LiquidityExhaustionDrill,
    AuthorityReleaseContinuity,
    SafetyCaseProductionBlocker,
}

impl ReleaseDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrimaryReserveReservation => "primary_reserve_reservation",
            Self::EmergencyReserveBuffer => "emergency_reserve_buffer",
            Self::WatcherBackstopEscrow => "watcher_backstop_escrow",
            Self::ChallengeSettlementHoldback => "challenge_settlement_holdback",
            Self::LowFeeSponsorCap => "low_fee_sponsor_cap",
            Self::LiquidityExhaustionDrill => "liquidity_exhaustion_drill",
            Self::AuthorityReleaseContinuity => "authority_release_continuity",
            Self::SafetyCaseProductionBlocker => "safety_case_production_blocker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecisionStatus {
    Reserved,
    Watch,
    Blocked,
}

impl ReleaseDecisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityReleaseReportStatus {
    Passed,
    Watch,
    Failed,
}

impl LiquidityReleaseReportStatus {
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
    pub reserve_release_suite: String,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub emergency_reserve_bps: u64,
    pub max_release_fee_bps: u64,
    pub max_utilization_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_release_decisions: u64,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub reserve_adapter_deferred: bool,
    pub security_audit_deferred: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            reserve_release_suite: RESERVE_RELEASE_SUITE.to_string(),
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            emergency_reserve_bps: DEFAULT_EMERGENCY_RESERVE_BPS,
            max_release_fee_bps: DEFAULT_MAX_RELEASE_FEE_BPS,
            max_utilization_bps: DEFAULT_MAX_UTILIZATION_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_release_decisions: DEFAULT_MIN_RELEASE_DECISIONS,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            reserve_adapter_deferred: true,
            security_audit_deferred: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "reserve_release_suite": self.reserve_release_suite,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "emergency_reserve_bps": self.emergency_reserve_bps,
            "max_release_fee_bps": self.max_release_fee_bps,
            "max_utilization_bps": self.max_utilization_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_release_decisions": self.min_release_decisions,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "reserve_adapter_deferred": self.reserve_adapter_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveAccount {
    pub account_id: String,
    pub lane: ReserveLane,
    pub status: ReserveAccountStatus,
    pub committed_liquidity: u128,
    pub reserved_liquidity: u128,
    pub released_liquidity: u128,
    pub emergency_liquidity: u128,
    pub coverage_bps: u64,
    pub max_utilization_bps: u64,
    pub reserve_attestation_root: String,
    pub pq_signer_root: String,
    pub privacy_bucket_root: String,
}

impl ReserveAccount {
    pub fn new(
        lane: ReserveLane,
        status: ReserveAccountStatus,
        committed_liquidity: u128,
        emergency_liquidity: u128,
        requested_amount: u128,
        max_utilization_bps: u64,
        seed: &str,
    ) -> Self {
        let coverage_bps = bps(committed_liquidity, requested_amount);
        let reserve_attestation_root = labeled_root("reserve-attestation", lane, seed);
        let pq_signer_root = labeled_root("reserve-pq-signer", lane, seed);
        let privacy_bucket_root = labeled_root("reserve-privacy-bucket", lane, seed);
        let account_id = reserve_account_id(
            lane,
            &reserve_attestation_root,
            &pq_signer_root,
            committed_liquidity,
        );
        Self {
            account_id,
            lane,
            status,
            committed_liquidity,
            reserved_liquidity: 0,
            released_liquidity: 0,
            emergency_liquidity,
            coverage_bps,
            max_utilization_bps,
            reserve_attestation_root,
            pq_signer_root,
            privacy_bucket_root,
        }
    }

    pub fn available_liquidity(&self) -> u128 {
        self.committed_liquidity
            .saturating_sub(self.reserved_liquidity)
            .saturating_sub(self.released_liquidity)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "committed_liquidity": self.committed_liquidity.to_string(),
            "reserved_liquidity": self.reserved_liquidity.to_string(),
            "released_liquidity": self.released_liquidity.to_string(),
            "emergency_liquidity": self.emergency_liquidity.to_string(),
            "coverage_bps": self.coverage_bps,
            "max_utilization_bps": self.max_utilization_bps,
            "reserve_attestation_root": self.reserve_attestation_root,
            "pq_signer_root": self.pq_signer_root,
            "privacy_bucket_root": self.privacy_bucket_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve_account", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitReleaseClaim {
    pub release_claim_id: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub path_id: String,
    pub settlement_id: String,
    pub transcript_root: String,
    pub transfer_report_root: String,
    pub exit_claim_id: String,
    pub exit_claim_root: String,
    pub receipt_root: String,
    pub withdrawal_commitment: String,
    pub payout_subaddress_commitment: String,
    pub burn_nullifier: String,
    pub liquidity_root: String,
    pub requested_amount: u128,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub watcher_quorum_id: String,
    pub claim_root: String,
}

impl ForcedExitReleaseClaim {
    pub fn from_transfer_claim(
        config: &Config,
        transcript: &ScenarioTranscript,
        transfer_report: &TransferReadinessReport,
        claim: &TransferExitClaim,
    ) -> Self {
        let claim_root = release_claim_root(
            &transcript.scenario_id,
            &claim.claim_id,
            &transfer_report.exit_claim_root,
            claim.max_exit_amount,
        );
        let release_claim_id = release_claim_id(
            &transcript.scenario_id,
            &claim.transfer_id,
            &claim.claim_id,
            &claim_root,
        );
        Self {
            release_claim_id,
            scenario_id: transcript.scenario_id.clone(),
            transfer_id: claim.transfer_id.clone(),
            path_id: claim.path_id.clone(),
            settlement_id: transcript.settlement_id.clone(),
            transcript_root: transcript.transcript_root.clone(),
            transfer_report_root: transfer_report.state_root(),
            exit_claim_id: claim.claim_id.clone(),
            exit_claim_root: transfer_report.exit_claim_root.clone(),
            receipt_root: claim.receipt_root.clone(),
            withdrawal_commitment: claim.withdrawal_commitment.clone(),
            payout_subaddress_commitment: claim.payout_subaddress_commitment.clone(),
            burn_nullifier: claim.burn_nullifier.clone(),
            liquidity_root: claim.liquidity_root.clone(),
            requested_amount: claim.max_exit_amount,
            max_fee_bps: config.max_release_fee_bps,
            privacy_set_size: claim.privacy_set_size,
            pq_authorization_root: claim.pq_authorization_root.clone(),
            watcher_quorum_id: claim.watcher_quorum_id.clone(),
            claim_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "release_claim_id": self.release_claim_id,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "path_id": self.path_id,
            "settlement_id": self.settlement_id,
            "transcript_root": self.transcript_root,
            "transfer_report_root": self.transfer_report_root,
            "exit_claim_id": self.exit_claim_id,
            "exit_claim_root": self.exit_claim_root,
            "receipt_root": self.receipt_root,
            "withdrawal_commitment": self.withdrawal_commitment,
            "payout_subaddress_commitment": self.payout_subaddress_commitment,
            "burn_nullifier": self.burn_nullifier,
            "liquidity_root": self.liquidity_root,
            "requested_amount": self.requested_amount.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "watcher_quorum_id": self.watcher_quorum_id,
            "claim_root": self.claim_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("forced_exit_release_claim", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveReleaseDecision {
    pub decision_id: String,
    pub kind: ReleaseDecisionKind,
    pub status: ReleaseDecisionStatus,
    pub release_claim_id: String,
    pub lane: ReserveLane,
    pub account_id: String,
    pub requested_amount: u128,
    pub allocated_amount: u128,
    pub reserve_after_release: u128,
    pub coverage_bps: u64,
    pub utilization_bps: u64,
    pub fee_bps: u64,
    pub release_certificate_root: String,
    pub evidence_root: String,
    pub observed: String,
    pub remediation: String,
    pub blocks_release: bool,
    pub blocks_production: bool,
}

impl ReserveReleaseDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ReleaseDecisionKind,
        status: ReleaseDecisionStatus,
        claim: &ForcedExitReleaseClaim,
        account: &ReserveAccount,
        allocated_amount: u128,
        fee_bps: u64,
        observed: impl Into<String>,
        remediation: impl Into<String>,
        blocks_release: bool,
        blocks_production: bool,
    ) -> Self {
        let reserve_after_release = account
            .available_liquidity()
            .saturating_sub(allocated_amount);
        let utilization_bps = bps(allocated_amount, account.committed_liquidity.max(1));
        let observed = observed.into();
        let remediation = remediation.into();
        let release_certificate_root = release_certificate_root(
            kind,
            &claim.release_claim_id,
            &account.account_id,
            allocated_amount,
            reserve_after_release,
        );
        let evidence_root = release_decision_evidence_root(
            kind,
            status,
            claim,
            account,
            allocated_amount,
            reserve_after_release,
            fee_bps,
            &observed,
        );
        let decision_id = release_decision_id(
            kind,
            &claim.release_claim_id,
            &account.account_id,
            &evidence_root,
        );
        Self {
            decision_id,
            kind,
            status,
            release_claim_id: claim.release_claim_id.clone(),
            lane: account.lane,
            account_id: account.account_id.clone(),
            requested_amount: claim.requested_amount,
            allocated_amount,
            reserve_after_release,
            coverage_bps: account.coverage_bps,
            utilization_bps,
            fee_bps,
            release_certificate_root,
            evidence_root,
            observed,
            remediation,
            blocks_release,
            blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "lane": self.lane.as_str(),
            "account_id": self.account_id,
            "requested_amount": self.requested_amount.to_string(),
            "allocated_amount": self.allocated_amount.to_string(),
            "reserve_after_release": self.reserve_after_release.to_string(),
            "coverage_bps": self.coverage_bps,
            "utilization_bps": self.utilization_bps,
            "fee_bps": self.fee_bps,
            "release_certificate_root": self.release_certificate_root,
            "evidence_root": self.evidence_root,
            "observed": self.observed,
            "remediation": self.remediation,
            "blocks_release": self.blocks_release,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve_release_decision", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityReleaseReport {
    pub report_id: String,
    pub status: LiquidityReleaseReportStatus,
    pub readiness_label: String,
    pub safety_case_state_root: String,
    pub safety_case_report_root: String,
    pub scenario_state_root: String,
    pub transfer_runtime_state_root: String,
    pub authority_transfer_state_root: String,
    pub authority_transfer_report_root: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub requested_amount: u128,
    pub total_committed_liquidity: u128,
    pub total_reserved_liquidity: u128,
    pub total_emergency_liquidity: u128,
    pub effective_coverage_bps: u64,
    pub decisions_reserved: u64,
    pub decisions_watch: u64,
    pub decisions_blocked: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub reserve_accounts: BTreeMap<String, ReserveAccount>,
    pub release_claim: ForcedExitReleaseClaim,
    pub decisions: BTreeMap<String, ReserveReleaseDecision>,
    pub roots: LiquidityReleaseReportRoots,
}

impl LiquidityReleaseReport {
    pub fn public_record(&self) -> Value {
        let reserve_accounts = self
            .reserve_accounts
            .values()
            .map(ReserveAccount::public_record)
            .collect::<Vec<_>>();
        let decisions = self
            .decisions
            .values()
            .map(ReserveReleaseDecision::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "safety_case_state_root": self.safety_case_state_root,
            "safety_case_report_root": self.safety_case_report_root,
            "scenario_state_root": self.scenario_state_root,
            "transfer_runtime_state_root": self.transfer_runtime_state_root,
            "authority_transfer_state_root": self.authority_transfer_state_root,
            "authority_transfer_report_root": self.authority_transfer_report_root,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "requested_amount": self.requested_amount.to_string(),
            "total_committed_liquidity": self.total_committed_liquidity.to_string(),
            "total_reserved_liquidity": self.total_reserved_liquidity.to_string(),
            "total_emergency_liquidity": self.total_emergency_liquidity.to_string(),
            "effective_coverage_bps": self.effective_coverage_bps,
            "decisions_reserved": self.decisions_reserved,
            "decisions_watch": self.decisions_watch,
            "decisions_blocked": self.decisions_blocked,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "reserve_accounts": reserve_accounts,
            "release_claim": self.release_claim.public_record(),
            "decisions": decisions,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityReleaseReportRoots {
    pub reserve_account_root: String,
    pub release_claim_root: String,
    pub decision_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub report_root: String,
}

impl LiquidityReleaseReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_account_root": self.reserve_account_root,
            "release_claim_root": self.release_claim_root,
            "decision_root": self.decision_root,
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub reports_passed: u64,
    pub reports_watch: u64,
    pub reports_failed: u64,
    pub reserve_accounts_seen: u64,
    pub release_claims_seen: u64,
    pub decisions_reserved: u64,
    pub decisions_watch: u64,
    pub decisions_blocked: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "reserve_accounts_seen": self.reserve_accounts_seen,
            "release_claims_seen": self.release_claims_seen,
            "decisions_reserved": self.decisions_reserved,
            "decisions_watch": self.decisions_watch,
            "decisions_blocked": self.decisions_blocked,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub report_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-EMPTY-REPORTS",
                &[],
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "report_root": self.report_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.report_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_report: Option<LiquidityReleaseReport>,
    pub report_history: Vec<LiquidityReleaseReport>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            latest_report: None,
            report_history: Vec::new(),
            counters,
            roots,
        };
        let transfer_runtime =
            crate::monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::devnet();
        let scenario =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::devnet();
        let safety_case = crate::monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::devnet();
        let authority_transfer =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        state
            .evaluate_liquidity_release(
                &transfer_runtime,
                &scenario,
                &safety_case,
                &authority_transfer,
            )
            .expect("devnet bridge exit liquidity reserve release");
        state
    }

    pub fn evaluate_liquidity_release(
        &mut self,
        transfer_runtime: &TransferRuntimeState,
        scenario: &ForcedExitScenarioState,
        safety_case: &BridgeExitSafetyCaseState,
        authority_transfer: &AuthorityTransferState,
    ) -> Result<String> {
        let transcript = latest_transcript(scenario)?;
        let transfer_report = latest_transfer_report(&scenario.transfer_runtime)?;
        let transfer_claim =
            latest_transfer_claim(&scenario.transfer_runtime, &transcript.transfer_id)?;
        let safety_report = latest_safety_report(safety_case)?;
        let authority_report = authority_transfer
            .latest_report
            .as_ref()
            .ok_or_else(|| "authority transfer state has no latest report".to_string())?;
        let release_claim = ForcedExitReleaseClaim::from_transfer_claim(
            &self.config,
            transcript,
            transfer_report,
            transfer_claim,
        );
        ensure(
            release_claim.privacy_set_size >= self.config.min_privacy_set_size,
            "forced-exit release claim is below privacy floor",
        )?;

        let reserve_accounts = build_reserve_accounts(&self.config, &release_claim, safety_report);
        let decisions = build_release_decisions(
            &self.config,
            &release_claim,
            &reserve_accounts,
            safety_report,
            authority_report.status,
        )?;
        ensure(
            decisions.len() as u64 >= self.config.min_release_decisions,
            "liquidity release report omitted required reserve decisions",
        )?;

        let total_committed_liquidity = reserve_accounts
            .values()
            .map(|account| account.committed_liquidity)
            .sum::<u128>();
        let total_reserved_liquidity = decisions
            .values()
            .map(|decision| decision.allocated_amount)
            .sum::<u128>();
        let total_emergency_liquidity = reserve_accounts
            .values()
            .map(|account| account.emergency_liquidity)
            .sum::<u128>();
        let effective_coverage_bps = bps(total_committed_liquidity, release_claim.requested_amount);
        let decisions_reserved = decisions
            .values()
            .filter(|decision| decision.status == ReleaseDecisionStatus::Reserved)
            .count() as u64;
        let decisions_watch = decisions
            .values()
            .filter(|decision| decision.status == ReleaseDecisionStatus::Watch)
            .count() as u64;
        let decisions_blocked = decisions
            .values()
            .filter(|decision| decision.status == ReleaseDecisionStatus::Blocked)
            .count() as u64;
        let release_blockers = decisions
            .values()
            .filter(|decision| decision.blocks_release)
            .count() as u64;
        let production_blockers = decisions
            .values()
            .filter(|decision| decision.blocks_production)
            .count() as u64;
        let status = aggregate_report_status(
            &self.config,
            effective_coverage_bps,
            decisions_watch,
            decisions_blocked,
            release_blockers,
            safety_report,
        );
        let readiness_label =
            readiness_label(status, &self.config, production_blockers).to_string();

        let reserve_records = reserve_accounts
            .values()
            .map(ReserveAccount::public_record)
            .collect::<Vec<_>>();
        let decision_records = decisions
            .values()
            .map(ReserveReleaseDecision::public_record)
            .collect::<Vec<_>>();
        let blocker_records = decisions
            .values()
            .filter(|decision| decision.blocks_release || decision.blocks_production)
            .map(ReserveReleaseDecision::public_record)
            .collect::<Vec<_>>();
        let reserve_account_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-ACCOUNTS",
            &reserve_records,
        );
        let release_claim_root = release_claim.state_root();
        let decision_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-DECISIONS",
            &decision_records,
        );
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-BLOCKERS",
            &blocker_records,
        );
        let source_root = source_root(
            &transfer_runtime.state_root(),
            &scenario.state_root(),
            &scenario.transfer_runtime.state_root(),
            &safety_case.state_root(),
            &safety_report.state_root(),
            &authority_transfer.state_root(),
            &authority_report.state_root(),
            &transfer_report.state_root(),
            &transcript.transcript_root,
            &release_claim.claim_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &reserve_account_root,
            &release_claim_root,
            &decision_root,
            &blocker_root,
            &release_claim.release_claim_id,
        );
        let report_id = liquidity_release_report_id(&release_claim.release_claim_id, &report_root);
        let report = LiquidityReleaseReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            safety_case_state_root: safety_case.state_root(),
            safety_case_report_root: safety_report.state_root(),
            scenario_state_root: scenario.state_root(),
            transfer_runtime_state_root: transfer_runtime.state_root(),
            authority_transfer_state_root: authority_transfer.state_root(),
            authority_transfer_report_root: authority_report.state_root(),
            scenario_id: release_claim.scenario_id.clone(),
            transfer_id: release_claim.transfer_id.clone(),
            release_claim_id: release_claim.release_claim_id.clone(),
            transcript_root: release_claim.transcript_root.clone(),
            requested_amount: release_claim.requested_amount,
            total_committed_liquidity,
            total_reserved_liquidity,
            total_emergency_liquidity,
            effective_coverage_bps,
            decisions_reserved,
            decisions_watch,
            decisions_blocked,
            release_blockers,
            production_blockers,
            reserve_accounts,
            release_claim,
            decisions,
            roots: LiquidityReleaseReportRoots {
                reserve_account_root,
                release_claim_root,
                decision_root,
                source_root,
                blocker_root,
                report_root,
            },
        };
        self.record_report(report);
        Ok(report_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "reserve_release_suite": self.config.reserve_release_suite,
            "latest_report": self.latest_report.as_ref().map(LiquidityReleaseReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: LiquidityReleaseReport) {
        self.counters.reports_run += 1;
        self.counters.reserve_accounts_seen += report.reserve_accounts.len() as u64;
        self.counters.release_claims_seen += 1;
        self.counters.decisions_reserved += report.decisions_reserved;
        self.counters.decisions_watch += report.decisions_watch;
        self.counters.decisions_blocked += report.decisions_blocked;
        self.counters.release_blockers += report.release_blockers;
        self.counters.production_blockers += report.production_blockers;
        match report.status {
            LiquidityReleaseReportStatus::Passed => self.counters.reports_passed += 1,
            LiquidityReleaseReportStatus::Watch => self.counters.reports_watch += 1,
            LiquidityReleaseReportStatus::Failed => self.counters.reports_failed += 1,
        }
        self.latest_report = Some(report.clone());
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_reports {
            self.report_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let report_records = self
            .report_history
            .iter()
            .map(LiquidityReleaseReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn latest_transcript(state: &ForcedExitScenarioState) -> Result<&ScenarioTranscript> {
    state
        .transcripts
        .values()
        .next_back()
        .ok_or_else(|| "forced-exit scenario has no sealed transcript".to_string())
}

fn latest_transfer_report(state: &TransferRuntimeState) -> Result<&TransferReadinessReport> {
    state
        .readiness_reports
        .values()
        .next_back()
        .ok_or_else(|| "transfer runtime has no readiness report".to_string())
}

fn latest_transfer_claim<'a>(
    state: &'a TransferRuntimeState,
    transfer_id: &str,
) -> Result<&'a TransferExitClaim> {
    state
        .exit_claims
        .values()
        .find(|claim| claim.transfer_id == transfer_id)
        .or_else(|| state.exit_claims.values().next_back())
        .ok_or_else(|| "transfer runtime has no exit claim".to_string())
}

fn latest_safety_report(state: &BridgeExitSafetyCaseState) -> Result<&SafetyCaseReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "bridge exit safety case has no latest report".to_string())
}

fn build_reserve_accounts(
    config: &Config,
    claim: &ForcedExitReleaseClaim,
    safety_report: &SafetyCaseReport,
) -> BTreeMap<String, ReserveAccount> {
    let amount = claim.requested_amount.max(1);
    let primary = scale_amount(amount, config.target_reserve_coverage_bps);
    let emergency = scale_amount(amount, config.emergency_reserve_bps);
    let watcher = scale_amount(amount, 3_000);
    let challenge = scale_amount(amount, 1_500);
    let sponsor = scale_amount(amount, 250);
    let rebalance = if safety_report.production_blockers > 0 {
        scale_amount(amount, 1_000)
    } else {
        scale_amount(amount, 500)
    };
    let seed = format!(
        "{}:{}:{}",
        claim.release_claim_id, claim.transcript_root, safety_report.report_id
    );
    [
        ReserveAccount::new(
            ReserveLane::ForcedExitPrimary,
            ReserveAccountStatus::Funded,
            primary,
            emergency,
            amount,
            config.max_utilization_bps,
            &seed,
        ),
        ReserveAccount::new(
            ReserveLane::EmergencyExitBuffer,
            ReserveAccountStatus::Funded,
            emergency,
            emergency,
            amount,
            config.max_utilization_bps,
            &seed,
        ),
        ReserveAccount::new(
            ReserveLane::WatcherBackstop,
            ReserveAccountStatus::Funded,
            watcher,
            emergency / 2,
            amount,
            config.max_utilization_bps,
            &seed,
        ),
        ReserveAccount::new(
            ReserveLane::ChallengeSettlement,
            ReserveAccountStatus::Funded,
            challenge,
            emergency / 2,
            amount,
            config.max_utilization_bps,
            &seed,
        ),
        ReserveAccount::new(
            ReserveLane::LowFeeSponsor,
            ReserveAccountStatus::Watch,
            sponsor,
            0,
            amount,
            config.max_utilization_bps,
            &seed,
        ),
        ReserveAccount::new(
            ReserveLane::RebalanceAuction,
            ReserveAccountStatus::Watch,
            rebalance,
            emergency,
            amount,
            config.max_utilization_bps,
            &seed,
        ),
    ]
    .into_iter()
    .map(|account| (account.account_id.clone(), account))
    .collect()
}

fn build_release_decisions(
    config: &Config,
    claim: &ForcedExitReleaseClaim,
    accounts: &BTreeMap<String, ReserveAccount>,
    safety_report: &SafetyCaseReport,
    authority_status: AuthorityTransferReportStatus,
) -> Result<BTreeMap<String, ReserveReleaseDecision>> {
    let primary = account_for_lane(accounts, ReserveLane::ForcedExitPrimary)?;
    let emergency = account_for_lane(accounts, ReserveLane::EmergencyExitBuffer)?;
    let watcher = account_for_lane(accounts, ReserveLane::WatcherBackstop)?;
    let challenge = account_for_lane(accounts, ReserveLane::ChallengeSettlement)?;
    let sponsor = account_for_lane(accounts, ReserveLane::LowFeeSponsor)?;
    let rebalance = account_for_lane(accounts, ReserveLane::RebalanceAuction)?;
    let primary_covers = primary.available_liquidity() >= claim.requested_amount
        && primary.coverage_bps >= config.min_reserve_coverage_bps;
    let emergency_covers = emergency.available_liquidity()
        >= scale_amount(claim.requested_amount, config.emergency_reserve_bps);
    let safety_mentions_liquidity = safety_report
        .evidence
        .values()
        .any(|item| item.requirement == SafetyRequirement::LiquidityExhaustionVisible);
    let mut decisions = BTreeMap::new();
    let mut push = |decision: ReserveReleaseDecision| {
        decisions.insert(decision.decision_id.clone(), decision);
    };

    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::PrimaryReserveReservation,
        if primary_covers {
            ReleaseDecisionStatus::Reserved
        } else {
            ReleaseDecisionStatus::Blocked
        },
        claim,
        primary,
        claim.requested_amount,
        config.max_release_fee_bps,
        format!(
            "primary_available={} requested={} coverage_bps={}",
            primary.available_liquidity(),
            claim.requested_amount,
            primary.coverage_bps
        ),
        "top up the forced-exit primary reserve before accepting more bridge-bound transfers",
        !primary_covers,
        !primary_covers,
    ));
    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::EmergencyReserveBuffer,
        if emergency_covers {
            ReleaseDecisionStatus::Reserved
        } else {
            ReleaseDecisionStatus::Watch
        },
        claim,
        emergency,
        scale_amount(claim.requested_amount, config.emergency_reserve_bps),
        0,
        format!(
            "emergency_available={} emergency_target_bps={}",
            emergency.available_liquidity(),
            config.emergency_reserve_bps
        ),
        "keep emergency reserve above the configured forced-exit buffer",
        !emergency_covers,
        !emergency_covers,
    ));
    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::WatcherBackstopEscrow,
        if watcher.available_liquidity() > 0 && !claim.watcher_quorum_id.is_empty() {
            ReleaseDecisionStatus::Reserved
        } else {
            ReleaseDecisionStatus::Blocked
        },
        claim,
        watcher,
        scale_amount(claim.requested_amount, 1_000),
        0,
        format!(
            "watcher_backstop_available={} watcher_quorum_present={}",
            watcher.available_liquidity(),
            !claim.watcher_quorum_id.is_empty()
        ),
        "bind watcher liquidity escrow to the forced-exit watcher quorum",
        claim.watcher_quorum_id.is_empty(),
        true,
    ));
    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::ChallengeSettlementHoldback,
        if challenge.available_liquidity() > 0 && !claim.settlement_id.is_empty() {
            ReleaseDecisionStatus::Reserved
        } else {
            ReleaseDecisionStatus::Blocked
        },
        claim,
        challenge,
        scale_amount(claim.requested_amount, 750),
        0,
        format!(
            "challenge_holdback_available={} settlement_id_present={}",
            challenge.available_liquidity(),
            !claim.settlement_id.is_empty()
        ),
        "hold challenge-settlement liquidity until the transcript settlement root is final",
        claim.settlement_id.is_empty(),
        true,
    ));
    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::LowFeeSponsorCap,
        if claim.max_fee_bps <= config.max_release_fee_bps && sponsor.coverage_bps > 0 {
            ReleaseDecisionStatus::Reserved
        } else {
            ReleaseDecisionStatus::Watch
        },
        claim,
        sponsor,
        scale_amount(claim.requested_amount, config.max_release_fee_bps),
        config.max_release_fee_bps,
        format!(
            "max_fee_bps={} configured_max_release_fee_bps={} sponsor_coverage_bps={}",
            claim.max_fee_bps, config.max_release_fee_bps, sponsor.coverage_bps
        ),
        "wire fee sponsor accounting to live settlement fees before production",
        false,
        config.reserve_adapter_deferred,
    ));
    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::LiquidityExhaustionDrill,
        if safety_mentions_liquidity {
            ReleaseDecisionStatus::Watch
        } else {
            ReleaseDecisionStatus::Blocked
        },
        claim,
        rebalance,
        scale_amount(claim.requested_amount, 500),
        0,
        format!(
            "safety_case_mentions_liquidity={} production_blockers={}",
            safety_mentions_liquidity, safety_report.production_blockers
        ),
        "turn the liquidity exhaustion safety-case item into an executable reserve depletion drill",
        !safety_mentions_liquidity,
        true,
    ));
    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::AuthorityReleaseContinuity,
        if authority_status == AuthorityTransferReportStatus::Failed {
            ReleaseDecisionStatus::Blocked
        } else if authority_status == AuthorityTransferReportStatus::Watch {
            ReleaseDecisionStatus::Watch
        } else {
            ReleaseDecisionStatus::Reserved
        },
        claim,
        primary,
        0,
        0,
        format!("authority_transfer_status={}", authority_status.as_str()),
        "promote authority transfer release gate from watch to audited enforcement",
        authority_status == AuthorityTransferReportStatus::Failed,
        authority_status != AuthorityTransferReportStatus::Passed,
    ));
    push(ReserveReleaseDecision::new(
        ReleaseDecisionKind::SafetyCaseProductionBlocker,
        if safety_report.verdict == SafetyCaseVerdict::Failed {
            ReleaseDecisionStatus::Blocked
        } else if safety_report.verdict == SafetyCaseVerdict::Watch {
            ReleaseDecisionStatus::Watch
        } else {
            ReleaseDecisionStatus::Reserved
        },
        claim,
        rebalance,
        0,
        0,
        format!(
            "safety_case_verdict={} production_blockers={} deferred_gates={}",
            safety_report.verdict.as_str(),
            safety_report.production_blockers,
            safety_report.deferred_gates
        ),
        "clear safety-case deferred gates, cargo/runtime checks, and audits before production release",
        safety_report.verdict == SafetyCaseVerdict::Failed,
        safety_report.verdict != SafetyCaseVerdict::Proven,
    ));

    Ok(decisions)
}

fn account_for_lane(
    accounts: &BTreeMap<String, ReserveAccount>,
    lane: ReserveLane,
) -> Result<&ReserveAccount> {
    accounts
        .values()
        .find(|account| account.lane == lane)
        .ok_or_else(|| format!("missing reserve account for lane {}", lane.as_str()))
}

fn aggregate_report_status(
    config: &Config,
    coverage_bps: u64,
    decisions_watch: u64,
    decisions_blocked: u64,
    release_blockers: u64,
    safety_report: &SafetyCaseReport,
) -> LiquidityReleaseReportStatus {
    if decisions_blocked > 0
        || release_blockers > 0
        || coverage_bps < config.min_reserve_coverage_bps
    {
        LiquidityReleaseReportStatus::Failed
    } else if decisions_watch > 0
        || safety_report.verdict == SafetyCaseVerdict::Watch
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || config.reserve_adapter_deferred
        || config.security_audit_deferred
    {
        LiquidityReleaseReportStatus::Watch
    } else {
        LiquidityReleaseReportStatus::Passed
    }
}

fn readiness_label(
    status: LiquidityReleaseReportStatus,
    config: &Config,
    production_blockers: u64,
) -> &'static str {
    match status {
        LiquidityReleaseReportStatus::Failed => "liquidity_reserve_release_blocked",
        LiquidityReleaseReportStatus::Watch
            if config.reserve_adapter_deferred || production_blockers > 0 =>
        {
            "liquidity_reserve_release_reserved_with_deferred_adapter"
        }
        LiquidityReleaseReportStatus::Watch => "liquidity_reserve_release_watch",
        LiquidityReleaseReportStatus::Passed => "liquidity_reserve_release_ready",
    }
}

fn scale_amount(amount: u128, bps_value: u64) -> u128 {
    amount
        .saturating_mul(bps_value as u128)
        .saturating_add((MAX_BPS - 1) as u128)
        / MAX_BPS as u128
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

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn reserve_account_id(
    lane: ReserveLane,
    reserve_attestation_root: &str,
    pq_signer_root: &str,
    committed_liquidity: u128,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-ACCOUNT-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(reserve_attestation_root),
            HashPart::Str(pq_signer_root),
            HashPart::U64((committed_liquidity & u64::MAX as u128) as u64),
        ],
        32,
    )
}

pub fn release_claim_id(
    scenario_id: &str,
    transfer_id: &str,
    exit_claim_id: &str,
    claim_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-CLAIM-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(transfer_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(claim_root),
        ],
        32,
    )
}

pub fn release_decision_id(
    kind: ReleaseDecisionKind,
    release_claim_id: &str,
    account_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-DECISION-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(account_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn liquidity_release_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn release_claim_root(
    scenario_id: &str,
    exit_claim_id: &str,
    exit_claim_root: &str,
    requested_amount: u128,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-CLAIM-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(exit_claim_root),
            HashPart::U64((requested_amount & u64::MAX as u128) as u64),
        ],
        32,
    )
}

pub fn release_certificate_root(
    kind: ReleaseDecisionKind,
    release_claim_id: &str,
    account_id: &str,
    allocated_amount: u128,
    reserve_after_release: u128,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-CERTIFICATE-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(account_id),
            HashPart::U64((allocated_amount & u64::MAX as u128) as u64),
            HashPart::U64((reserve_after_release & u64::MAX as u128) as u64),
        ],
        32,
    )
}

pub fn release_decision_evidence_root(
    kind: ReleaseDecisionKind,
    status: ReleaseDecisionStatus,
    claim: &ForcedExitReleaseClaim,
    account: &ReserveAccount,
    allocated_amount: u128,
    reserve_after_release: u128,
    fee_bps: u64,
    observed: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-DECISION-EVIDENCE-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&claim.release_claim_id),
            HashPart::Str(&account.account_id),
            HashPart::Str(account.lane.as_str()),
            HashPart::U64((allocated_amount & u64::MAX as u128) as u64),
            HashPart::U64((reserve_after_release & u64::MAX as u128) as u64),
            HashPart::U64(fee_bps),
            HashPart::Str(observed),
        ],
        32,
    )
}

pub fn labeled_root(label: &str, lane: ReserveLane, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-LABELED-ROOT",
        &[
            HashPart::Str(label),
            HashPart::Str(lane.as_str()),
            HashPart::Str(seed),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    transfer_runtime_state_root: &str,
    scenario_state_root: &str,
    scenario_transfer_runtime_root: &str,
    safety_case_state_root: &str,
    safety_case_report_root: &str,
    authority_transfer_state_root: &str,
    authority_transfer_report_root: &str,
    transfer_report_root: &str,
    transcript_root: &str,
    release_claim_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-SOURCE-ROOT",
        &[
            HashPart::Str(transfer_runtime_state_root),
            HashPart::Str(scenario_state_root),
            HashPart::Str(scenario_transfer_runtime_root),
            HashPart::Str(safety_case_state_root),
            HashPart::Str(safety_case_report_root),
            HashPart::Str(authority_transfer_state_root),
            HashPart::Str(authority_transfer_report_root),
            HashPart::Str(transfer_report_root),
            HashPart::Str(transcript_root),
            HashPart::Str(release_claim_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: LiquidityReleaseReportStatus,
    readiness_label: &str,
    source_root: &str,
    reserve_account_root: &str,
    release_claim_root: &str,
    decision_root: &str,
    blocker_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(reserve_account_root),
            HashPart::Str(release_claim_root),
            HashPart::Str(decision_root),
            HashPart::Str(blocker_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIQUIDITY-RESERVE-RELEASE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
