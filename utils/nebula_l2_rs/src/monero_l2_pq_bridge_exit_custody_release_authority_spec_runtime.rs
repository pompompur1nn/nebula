use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::State as BridgeExitSpineState,
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCustodyReleaseAuthoritySpecRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CUSTODY_RELEASE_AUTHORITY_SPEC_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-custody-release-authority-spec-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CUSTODY_RELEASE_AUTHORITY_SPEC_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const AUTHORITY_SUITE: &str =
    "monero-l2-pq-bridge-custody-release-authority-and-fail-closed-controls-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_UPGRADE_TIMELOCK_BLOCKS: u64 = 10_080;
pub const DEFAULT_EMERGENCY_REVIEW_BLOCKS: u64 = 144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityDomain {
    MoneroLockObservation,
    DepositMint,
    PrivateStateTransition,
    SettlementReceipt,
    WithdrawalRelease,
    ForcedExit,
    ChallengeResolution,
    ReserveBackstop,
    WatcherRotation,
    UpgradeAuthority,
    EmergencyPause,
    PqKeyMigration,
}

impl AuthorityDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroLockObservation => "monero_lock_observation",
            Self::DepositMint => "deposit_mint",
            Self::PrivateStateTransition => "private_state_transition",
            Self::SettlementReceipt => "settlement_receipt",
            Self::WithdrawalRelease => "withdrawal_release",
            Self::ForcedExit => "forced_exit",
            Self::ChallengeResolution => "challenge_resolution",
            Self::ReserveBackstop => "reserve_backstop",
            Self::WatcherRotation => "watcher_rotation",
            Self::UpgradeAuthority => "upgrade_authority",
            Self::EmergencyPause => "emergency_pause",
            Self::PqKeyMigration => "pq_key_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleKind {
    UserWallet,
    WatcherQuorum,
    EmergencyWatcherQuorum,
    Sequencer,
    SettlementAdapter,
    ChallengeArbiter,
    ReserveCouncil,
    UpgradeCouncil,
    PqKeyCouncil,
    Auditor,
}

impl RoleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserWallet => "user_wallet",
            Self::WatcherQuorum => "watcher_quorum",
            Self::EmergencyWatcherQuorum => "emergency_watcher_quorum",
            Self::Sequencer => "sequencer",
            Self::SettlementAdapter => "settlement_adapter",
            Self::ChallengeArbiter => "challenge_arbiter",
            Self::ReserveCouncil => "reserve_council",
            Self::UpgradeCouncil => "upgrade_council",
            Self::PqKeyCouncil => "pq_key_council",
            Self::Auditor => "auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MoneroLockTxRoot,
    WatcherCertificateRoot,
    PqQuorumSignatureRoot,
    PrivateNoteCommitment,
    PrivateStateRoot,
    ReceiptRoot,
    BurnNullifier,
    WithdrawalCommitment,
    CensorshipEvidenceRoot,
    LivenessFailureRoot,
    ChallengeEvidenceRoot,
    ChallengeResolutionRoot,
    ReserveProofRoot,
    ReleaseCertificateRoot,
    UpgradeTimelockRoot,
    EmergencyActionRoot,
    PqRotationRoot,
    PrivacyBudgetRoot,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroLockTxRoot => "monero_lock_tx_root",
            Self::WatcherCertificateRoot => "watcher_certificate_root",
            Self::PqQuorumSignatureRoot => "pq_quorum_signature_root",
            Self::PrivateNoteCommitment => "private_note_commitment",
            Self::PrivateStateRoot => "private_state_root",
            Self::ReceiptRoot => "receipt_root",
            Self::BurnNullifier => "burn_nullifier",
            Self::WithdrawalCommitment => "withdrawal_commitment",
            Self::CensorshipEvidenceRoot => "censorship_evidence_root",
            Self::LivenessFailureRoot => "liveness_failure_root",
            Self::ChallengeEvidenceRoot => "challenge_evidence_root",
            Self::ChallengeResolutionRoot => "challenge_resolution_root",
            Self::ReserveProofRoot => "reserve_proof_root",
            Self::ReleaseCertificateRoot => "release_certificate_root",
            Self::UpgradeTimelockRoot => "upgrade_timelock_root",
            Self::EmergencyActionRoot => "emergency_action_root",
            Self::PqRotationRoot => "pq_rotation_root",
            Self::PrivacyBudgetRoot => "privacy_budget_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedAction {
    Reject,
    ExitOnly,
    QuarantinePath,
    DelayRelease,
    SlashAndRotate,
    PauseDepositsKeepExits,
}

impl FailClosedAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::ExitOnly => "exit_only",
            Self::QuarantinePath => "quarantine_path",
            Self::DelayRelease => "delay_release",
            Self::SlashAndRotate => "slash_and_rotate",
            Self::PauseDepositsKeepExits => "pause_deposits_keep_exits",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCheckKind {
    NoUnilateralRelease,
    ForcedExitBypassesSequencer,
    UpgradeTimelocked,
    EmergencyCannotHaltExits,
    PqControlPlane,
    PrivacyRootsOnly,
    ReserveRequiredForRelease,
    ChallengeBlocksRelease,
}

impl AuthorityCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoUnilateralRelease => "no_unilateral_release",
            Self::ForcedExitBypassesSequencer => "forced_exit_bypasses_sequencer",
            Self::UpgradeTimelocked => "upgrade_timelocked",
            Self::EmergencyCannotHaltExits => "emergency_cannot_halt_exits",
            Self::PqControlPlane => "pq_control_plane",
            Self::PrivacyRootsOnly => "privacy_roots_only",
            Self::ReserveRequiredForRelease => "reserve_required_for_release",
            Self::ChallengeBlocksRelease => "challenge_blocks_release",
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub authority_suite: String,
    pub min_pq_security_bits: u16,
    pub release_delay_blocks: u64,
    pub upgrade_timelock_blocks: u64,
    pub emergency_review_blocks: u64,
}

impl Config {
    pub fn devnet(spine: &BridgeExitSpineState) -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            authority_suite: AUTHORITY_SUITE.to_string(),
            min_pq_security_bits: spine
                .config
                .min_pq_security_bits
                .max(DEFAULT_MIN_PQ_SECURITY_BITS),
            release_delay_blocks: spine
                .config
                .forced_exit_delay_blocks
                .max(DEFAULT_RELEASE_DELAY_BLOCKS),
            upgrade_timelock_blocks: DEFAULT_UPGRADE_TIMELOCK_BLOCKS,
            emergency_review_blocks: spine
                .config
                .exit_liveness_window_blocks
                .max(DEFAULT_EMERGENCY_REVIEW_BLOCKS),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "authority_suite": self.authority_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "release_delay_blocks": self.release_delay_blocks,
            "upgrade_timelock_blocks": self.upgrade_timelock_blocks,
            "emergency_review_blocks": self.emergency_review_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoleRecord {
    pub role_id: String,
    pub role: RoleKind,
    pub authority_root: String,
    pub pq_suite: String,
    pub threshold_weight: u64,
    pub can_custody_value: bool,
    pub can_unilaterally_release: bool,
    pub can_halt_deposits: bool,
    pub can_halt_exits: bool,
    pub evidence_scope: Vec<EvidenceKind>,
    pub rotation_root: String,
}

impl RoleRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "role_id": self.role_id,
            "role": self.role.as_str(),
            "authority_root": self.authority_root,
            "pq_suite": self.pq_suite,
            "threshold_weight": self.threshold_weight,
            "can_custody_value": self.can_custody_value,
            "can_unilaterally_release": self.can_unilaterally_release,
            "can_halt_deposits": self.can_halt_deposits,
            "can_halt_exits": self.can_halt_exits,
            "evidence_scope": self.evidence_scope.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "rotation_root": self.rotation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_role", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapabilityRule {
    pub capability_id: String,
    pub domain: AuthorityDomain,
    pub primary_role: RoleKind,
    pub co_signers: Vec<RoleKind>,
    pub required_evidence: Vec<EvidenceKind>,
    pub forbidden_without: Vec<EvidenceKind>,
    pub fail_closed_action: FailClosedAction,
    pub min_threshold_weight: u64,
    pub min_pq_security_bits: u16,
    pub delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_amount: Option<u128>,
    pub public_disclosure: String,
}

impl CapabilityRule {
    pub fn public_record(&self) -> Value {
        json!({
            "capability_id": self.capability_id,
            "domain": self.domain.as_str(),
            "primary_role": self.primary_role.as_str(),
            "co_signers": self.co_signers.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "required_evidence": self.required_evidence.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "forbidden_without": self.forbidden_without.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "fail_closed_action": self.fail_closed_action.as_str(),
            "min_threshold_weight": self.min_threshold_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "delay_blocks": self.delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_amount": self.max_amount.map(|value| value.to_string()),
            "public_disclosure": self.public_disclosure,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_capability", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseRule {
    pub release_id: String,
    pub release_path: String,
    pub normal_release_roles: Vec<RoleKind>,
    pub forced_release_roles: Vec<RoleKind>,
    pub blocks_if_open_challenge: bool,
    pub blocks_if_reserve_missing: bool,
    pub burns_nullifier_before_release: bool,
    pub sequencer_can_block: bool,
    pub release_certificate_evidence: Vec<EvidenceKind>,
    pub fail_closed_action: FailClosedAction,
}

impl ReleaseRule {
    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "release_path": self.release_path,
            "normal_release_roles": self.normal_release_roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "forced_release_roles": self.forced_release_roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "blocks_if_open_challenge": self.blocks_if_open_challenge,
            "blocks_if_reserve_missing": self.blocks_if_reserve_missing,
            "burns_nullifier_before_release": self.burns_nullifier_before_release,
            "sequencer_can_block": self.sequencer_can_block,
            "release_certificate_evidence": self.release_certificate_evidence.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "fail_closed_action": self.fail_closed_action.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_release_rule", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityCheck {
    pub check_id: String,
    pub kind: AuthorityCheckKind,
    pub status: CheckStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub remediation: String,
}

impl AuthorityCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub roles_registered: u64,
    pub capabilities_registered: u64,
    pub release_rules_registered: u64,
    pub checks_run: u64,
    pub checks_passed: u64,
    pub checks_watch: u64,
    pub checks_failed: u64,
    pub unilateral_release_roles: u64,
    pub exit_halt_roles: u64,
    pub sequencer_blocking_paths: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "roles_registered": self.roles_registered,
            "capabilities_registered": self.capabilities_registered,
            "release_rules_registered": self.release_rules_registered,
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "checks_watch": self.checks_watch,
            "checks_failed": self.checks_failed,
            "unilateral_release_roles": self.unilateral_release_roles,
            "exit_halt_roles": self.exit_halt_roles,
            "sequencer_blocking_paths": self.sequencer_blocking_paths,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub source_spine_root: String,
    pub source_policy_root: String,
    pub role_root: String,
    pub capability_root: String,
    pub release_rule_root: String,
    pub check_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, spine: &BridgeExitSpineState, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            source_spine_root: spine.state_root(),
            source_policy_root: spine.policy.state_root(),
            role_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-EMPTY-ROLES", &[]),
            capability_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-EMPTY-CAPABILITIES",
                &[],
            ),
            release_rule_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-EMPTY-RELEASE-RULES",
                &[],
            ),
            check_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-EMPTY-CHECKS", &[]),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "source_spine_root": self.source_spine_root,
            "source_policy_root": self.source_policy_root,
            "role_root": self.role_root,
            "capability_root": self.capability_root,
            "release_rule_root": self.release_rule_root,
            "check_root": self.check_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-ROOTS",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.source_spine_root),
                HashPart::Str(&self.source_policy_root),
                HashPart::Str(&self.role_root),
                HashPart::Str(&self.capability_root),
                HashPart::Str(&self.release_rule_root),
                HashPart::Str(&self.check_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub source_spine_root: String,
    pub source_policy_root: String,
    pub roles: BTreeMap<String, RoleRecord>,
    pub capabilities: BTreeMap<String, CapabilityRule>,
    pub release_rules: BTreeMap<String, ReleaseRule>,
    pub checks: BTreeMap<String, AuthorityCheck>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let spine = BridgeExitSpineState::devnet();
        let config = Config::devnet(&spine);
        let counters = Counters::default();
        let roots = Roots::empty(&config, &spine, &counters);
        let mut state = Self {
            config,
            source_spine_root: spine.state_root(),
            source_policy_root: spine.policy.state_root(),
            roles: BTreeMap::new(),
            capabilities: BTreeMap::new(),
            release_rules: BTreeMap::new(),
            checks: BTreeMap::new(),
            counters,
            roots,
        };
        state.install_devnet_authority_model(&spine);
        state
    }

    fn install_devnet_authority_model(&mut self, spine: &BridgeExitSpineState) {
        for role in devnet_roles(self, spine) {
            self.insert_role(role);
        }
        for capability in devnet_capabilities(self, spine) {
            self.insert_capability(capability);
        }
        for release_rule in devnet_release_rules(self) {
            self.insert_release_rule(release_rule);
        }
        for check in evaluate_authority_checks(self, spine) {
            self.insert_check(check);
        }
        self.refresh_roots(spine);
    }

    fn insert_role(&mut self, role: RoleRecord) {
        self.roles.insert(role.role_id.clone(), role);
        self.counters.roles_registered += 1;
    }

    fn insert_capability(&mut self, capability: CapabilityRule) {
        self.capabilities
            .insert(capability.capability_id.clone(), capability);
        self.counters.capabilities_registered += 1;
    }

    fn insert_release_rule(&mut self, release_rule: ReleaseRule) {
        self.release_rules
            .insert(release_rule.release_id.clone(), release_rule);
        self.counters.release_rules_registered += 1;
    }

    fn insert_check(&mut self, check: AuthorityCheck) {
        self.counters.checks_run += 1;
        match check.status {
            CheckStatus::Passed => self.counters.checks_passed += 1,
            CheckStatus::Watch => self.counters.checks_watch += 1,
            CheckStatus::Failed => self.counters.checks_failed += 1,
        }
        self.checks.insert(check.check_id.clone(), check);
    }

    fn refresh_roots(&mut self, spine: &BridgeExitSpineState) {
        let role_records = self
            .roles
            .values()
            .map(RoleRecord::public_record)
            .collect::<Vec<_>>();
        let capability_records = self
            .capabilities
            .values()
            .map(CapabilityRule::public_record)
            .collect::<Vec<_>>();
        let release_records = self
            .release_rules
            .values()
            .map(ReleaseRule::public_record)
            .collect::<Vec<_>>();
        let check_records = self
            .checks
            .values()
            .map(AuthorityCheck::public_record)
            .collect::<Vec<_>>();
        self.counters.unilateral_release_roles = self
            .roles
            .values()
            .filter(|role| role.can_unilaterally_release)
            .count() as u64;
        self.counters.exit_halt_roles = self
            .roles
            .values()
            .filter(|role| role.can_halt_exits)
            .count() as u64;
        self.counters.sequencer_blocking_paths = self
            .release_rules
            .values()
            .filter(|rule| rule.sequencer_can_block)
            .count() as u64;
        self.source_spine_root = spine.state_root();
        self.source_policy_root = spine.policy.state_root();
        self.roots = Roots {
            config_root: self.config.state_root(),
            source_spine_root: self.source_spine_root.clone(),
            source_policy_root: self.source_policy_root.clone(),
            role_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-ROLES", &role_records),
            capability_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CAPABILITIES",
                &capability_records,
            ),
            release_rule_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-RELEASE-RULES",
                &release_records,
            ),
            check_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CHECKS", &check_records),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "authority_suite": self.config.authority_suite,
            "source_spine_root": self.source_spine_root,
            "source_policy_root": self.source_policy_root,
            "role_count": self.roles.len(),
            "capability_count": self.capabilities.len(),
            "release_rule_count": self.release_rules.len(),
            "check_count": self.checks.len(),
            "checks": self.checks.values().map(AuthorityCheck::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

fn devnet_roles(state: &State, spine: &BridgeExitSpineState) -> Vec<RoleRecord> {
    vec![
        role(
            RoleKind::UserWallet,
            "user-wallet-withdrawal-authority",
            state.config.min_pq_security_bits,
            1,
            false,
            false,
            false,
            false,
            vec![
                EvidenceKind::BurnNullifier,
                EvidenceKind::WithdrawalCommitment,
                EvidenceKind::PrivacyBudgetRoot,
            ],
        ),
        role(
            RoleKind::WatcherQuorum,
            &spine.policy.watcher_set_root,
            state.config.min_pq_security_bits,
            spine.config.min_watcher_weight,
            false,
            false,
            false,
            false,
            vec![
                EvidenceKind::MoneroLockTxRoot,
                EvidenceKind::WatcherCertificateRoot,
                EvidenceKind::PqQuorumSignatureRoot,
            ],
        ),
        role(
            RoleKind::EmergencyWatcherQuorum,
            "emergency-forced-exit-watchers",
            state.config.min_pq_security_bits,
            spine.config.emergency_watcher_weight,
            false,
            false,
            true,
            false,
            vec![
                EvidenceKind::CensorshipEvidenceRoot,
                EvidenceKind::LivenessFailureRoot,
                EvidenceKind::PqQuorumSignatureRoot,
            ],
        ),
        role(
            RoleKind::Sequencer,
            "pq-sequencer-receipt-authority",
            state.config.min_pq_security_bits,
            1,
            false,
            false,
            false,
            false,
            vec![
                EvidenceKind::PrivateStateRoot,
                EvidenceKind::ReceiptRoot,
                EvidenceKind::PqQuorumSignatureRoot,
            ],
        ),
        role(
            RoleKind::SettlementAdapter,
            "monero-release-settlement-adapter",
            state.config.min_pq_security_bits,
            spine.config.min_watcher_weight,
            false,
            false,
            false,
            false,
            vec![
                EvidenceKind::ReserveProofRoot,
                EvidenceKind::ReleaseCertificateRoot,
                EvidenceKind::BurnNullifier,
            ],
        ),
        role(
            RoleKind::ChallengeArbiter,
            "challenge-arbiter-quorum",
            state.config.min_pq_security_bits,
            spine.config.min_watcher_weight,
            false,
            false,
            false,
            false,
            vec![
                EvidenceKind::ChallengeEvidenceRoot,
                EvidenceKind::ChallengeResolutionRoot,
            ],
        ),
        role(
            RoleKind::ReserveCouncil,
            &spine.policy.reserve_root,
            state.config.min_pq_security_bits,
            spine.config.min_watcher_weight,
            true,
            false,
            false,
            false,
            vec![EvidenceKind::ReserveProofRoot],
        ),
        role(
            RoleKind::UpgradeCouncil,
            &spine.policy.upgrade_authority_root,
            state.config.min_pq_security_bits,
            spine.config.emergency_watcher_weight,
            false,
            false,
            true,
            false,
            vec![
                EvidenceKind::UpgradeTimelockRoot,
                EvidenceKind::EmergencyActionRoot,
            ],
        ),
        role(
            RoleKind::PqKeyCouncil,
            "pq-key-migration-council",
            state.config.min_pq_security_bits,
            spine.config.emergency_watcher_weight,
            false,
            false,
            true,
            false,
            vec![EvidenceKind::PqRotationRoot],
        ),
        role(
            RoleKind::Auditor,
            "roots-only-auditor",
            state.config.min_pq_security_bits,
            1,
            false,
            false,
            false,
            false,
            vec![
                EvidenceKind::ReceiptRoot,
                EvidenceKind::PrivacyBudgetRoot,
                EvidenceKind::ChallengeEvidenceRoot,
            ],
        ),
    ]
}

fn role(
    role: RoleKind,
    authority_seed: &str,
    min_pq_security_bits: u16,
    threshold_weight: u64,
    can_custody_value: bool,
    can_unilaterally_release: bool,
    can_halt_deposits: bool,
    can_halt_exits: bool,
    evidence_scope: Vec<EvidenceKind>,
) -> RoleRecord {
    let authority_root = root("role-authority", authority_seed);
    let rotation_root = root("role-rotation", role.as_str());
    let role_id = authority_id("role", role.as_str(), &authority_root);
    RoleRecord {
        role_id,
        role,
        authority_root,
        pq_suite: "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f".to_string(),
        threshold_weight,
        can_custody_value,
        can_unilaterally_release,
        can_halt_deposits,
        can_halt_exits,
        evidence_scope,
        rotation_root,
    }
}

fn devnet_capabilities(state: &State, spine: &BridgeExitSpineState) -> Vec<CapabilityRule> {
    vec![
        capability(
            state,
            spine,
            AuthorityDomain::MoneroLockObservation,
            RoleKind::WatcherQuorum,
            vec![RoleKind::Auditor],
            vec![
                EvidenceKind::MoneroLockTxRoot,
                EvidenceKind::WatcherCertificateRoot,
                EvidenceKind::PqQuorumSignatureRoot,
            ],
            FailClosedAction::Reject,
            0,
            "lock txid, deposit commitment, subaddress/viewtag commitments only",
        ),
        capability(
            state,
            spine,
            AuthorityDomain::DepositMint,
            RoleKind::WatcherQuorum,
            vec![RoleKind::Sequencer],
            vec![
                EvidenceKind::WatcherCertificateRoot,
                EvidenceKind::PrivateNoteCommitment,
                EvidenceKind::PrivacyBudgetRoot,
            ],
            FailClosedAction::QuarantinePath,
            0,
            "private note commitment and membership root only",
        ),
        capability(
            state,
            spine,
            AuthorityDomain::PrivateStateTransition,
            RoleKind::Sequencer,
            vec![RoleKind::UserWallet],
            vec![
                EvidenceKind::PrivateStateRoot,
                EvidenceKind::ReceiptRoot,
                EvidenceKind::PrivacyBudgetRoot,
            ],
            FailClosedAction::Reject,
            0,
            "receipt and private state roots only",
        ),
        capability(
            state,
            spine,
            AuthorityDomain::WithdrawalRelease,
            RoleKind::SettlementAdapter,
            vec![
                RoleKind::UserWallet,
                RoleKind::WatcherQuorum,
                RoleKind::ReserveCouncil,
            ],
            vec![
                EvidenceKind::BurnNullifier,
                EvidenceKind::WithdrawalCommitment,
                EvidenceKind::ReserveProofRoot,
                EvidenceKind::ReleaseCertificateRoot,
            ],
            FailClosedAction::DelayRelease,
            state.config.release_delay_blocks,
            "release certificate, nullifier, reserve root, payout commitment",
        ),
        capability(
            state,
            spine,
            AuthorityDomain::ForcedExit,
            RoleKind::EmergencyWatcherQuorum,
            vec![RoleKind::UserWallet],
            vec![
                EvidenceKind::CensorshipEvidenceRoot,
                EvidenceKind::LivenessFailureRoot,
                EvidenceKind::BurnNullifier,
                EvidenceKind::WithdrawalCommitment,
            ],
            FailClosedAction::ExitOnly,
            state.config.release_delay_blocks,
            "forced-exit evidence roots and burn nullifier only",
        ),
        capability(
            state,
            spine,
            AuthorityDomain::ChallengeResolution,
            RoleKind::ChallengeArbiter,
            vec![RoleKind::Auditor],
            vec![
                EvidenceKind::ChallengeEvidenceRoot,
                EvidenceKind::ChallengeResolutionRoot,
            ],
            FailClosedAction::DelayRelease,
            spine.config.challenge_window_blocks,
            "challenge evidence and resolution roots only",
        ),
        capability(
            state,
            spine,
            AuthorityDomain::UpgradeAuthority,
            RoleKind::UpgradeCouncil,
            vec![RoleKind::Auditor, RoleKind::PqKeyCouncil],
            vec![
                EvidenceKind::UpgradeTimelockRoot,
                EvidenceKind::PqRotationRoot,
            ],
            FailClosedAction::PauseDepositsKeepExits,
            state.config.upgrade_timelock_blocks,
            "upgrade timelock and migration roots only",
        ),
        capability(
            state,
            spine,
            AuthorityDomain::EmergencyPause,
            RoleKind::EmergencyWatcherQuorum,
            vec![RoleKind::UpgradeCouncil, RoleKind::Auditor],
            vec![
                EvidenceKind::EmergencyActionRoot,
                EvidenceKind::CensorshipEvidenceRoot,
            ],
            FailClosedAction::PauseDepositsKeepExits,
            state.config.emergency_review_blocks,
            "emergency root with exits preserved",
        ),
    ]
}

fn capability(
    state: &State,
    spine: &BridgeExitSpineState,
    domain: AuthorityDomain,
    primary_role: RoleKind,
    co_signers: Vec<RoleKind>,
    required_evidence: Vec<EvidenceKind>,
    fail_closed_action: FailClosedAction,
    delay_blocks: u64,
    public_disclosure: &str,
) -> CapabilityRule {
    let capability_id = authority_id("capability", domain.as_str(), primary_role.as_str());
    CapabilityRule {
        capability_id,
        domain,
        primary_role,
        co_signers,
        forbidden_without: required_evidence.clone(),
        required_evidence,
        fail_closed_action,
        min_threshold_weight: spine.config.min_watcher_weight,
        min_pq_security_bits: state.config.min_pq_security_bits,
        delay_blocks,
        challenge_window_blocks: spine.config.challenge_window_blocks,
        max_amount: Some(spine.policy.max_single_exit_amount),
        public_disclosure: public_disclosure.to_string(),
    }
}

fn devnet_release_rules(state: &State) -> Vec<ReleaseRule> {
    vec![
        ReleaseRule {
            release_id: authority_id("release", "cooperative", "withdrawal"),
            release_path: "cooperative-withdrawal-release".to_string(),
            normal_release_roles: vec![
                RoleKind::UserWallet,
                RoleKind::WatcherQuorum,
                RoleKind::SettlementAdapter,
                RoleKind::ReserveCouncil,
            ],
            forced_release_roles: Vec::new(),
            blocks_if_open_challenge: true,
            blocks_if_reserve_missing: true,
            burns_nullifier_before_release: true,
            sequencer_can_block: false,
            release_certificate_evidence: vec![
                EvidenceKind::BurnNullifier,
                EvidenceKind::ReserveProofRoot,
                EvidenceKind::ReleaseCertificateRoot,
            ],
            fail_closed_action: FailClosedAction::DelayRelease,
        },
        ReleaseRule {
            release_id: authority_id("release", "forced", "escape"),
            release_path: "always-available-forced-exit-release".to_string(),
            normal_release_roles: Vec::new(),
            forced_release_roles: vec![
                RoleKind::UserWallet,
                RoleKind::EmergencyWatcherQuorum,
                RoleKind::SettlementAdapter,
            ],
            blocks_if_open_challenge: true,
            blocks_if_reserve_missing: true,
            burns_nullifier_before_release: true,
            sequencer_can_block: false,
            release_certificate_evidence: vec![
                EvidenceKind::BurnNullifier,
                EvidenceKind::CensorshipEvidenceRoot,
                EvidenceKind::LivenessFailureRoot,
                EvidenceKind::ReleaseCertificateRoot,
            ],
            fail_closed_action: FailClosedAction::ExitOnly,
        },
        ReleaseRule {
            release_id: authority_id("release", "emergency", "pause"),
            release_path: "emergency-pause-keeps-exits-open".to_string(),
            normal_release_roles: vec![RoleKind::EmergencyWatcherQuorum, RoleKind::UpgradeCouncil],
            forced_release_roles: vec![RoleKind::UserWallet, RoleKind::EmergencyWatcherQuorum],
            blocks_if_open_challenge: true,
            blocks_if_reserve_missing: true,
            burns_nullifier_before_release: true,
            sequencer_can_block: false,
            release_certificate_evidence: vec![
                EvidenceKind::EmergencyActionRoot,
                EvidenceKind::ReleaseCertificateRoot,
            ],
            fail_closed_action: FailClosedAction::PauseDepositsKeepExits,
        },
    ]
    .into_iter()
    .map(|mut rule| {
        if rule.release_path.contains("forced") {
            rule.release_certificate_evidence
                .push(EvidenceKind::ChallengeResolutionRoot);
        }
        if rule.release_path.contains("emergency") {
            rule.release_certificate_evidence
                .push(EvidenceKind::UpgradeTimelockRoot);
        }
        let _ = state.config.schema_version;
        rule
    })
    .collect()
}

fn evaluate_authority_checks(state: &State, spine: &BridgeExitSpineState) -> Vec<AuthorityCheck> {
    vec![
        check(
            AuthorityCheckKind::NoUnilateralRelease,
            state
                .roles
                .values()
                .all(|role| !role.can_unilaterally_release),
            "no role can unilaterally release locked Monero value",
            format!(
                "unilateral_release_roles={}",
                state
                    .roles
                    .values()
                    .filter(|role| role.can_unilaterally_release)
                    .count()
            ),
            "remove unilateral release permission and require wallet+watcher+reserve evidence",
        ),
        check(
            AuthorityCheckKind::ForcedExitBypassesSequencer,
            state
                .release_rules
                .values()
                .filter(|rule| rule.release_path.contains("forced"))
                .all(|rule| !rule.sequencer_can_block),
            "forced exit release must not depend on sequencer cooperation",
            format!(
                "sequencer_blocking_forced_paths={}",
                state
                    .release_rules
                    .values()
                    .filter(|rule| rule.release_path.contains("forced") && rule.sequencer_can_block)
                    .count()
            ),
            "remove sequencer as a blocking role from forced-exit release rules",
        ),
        check(
            AuthorityCheckKind::UpgradeTimelocked,
            state.capabilities.values().any(|capability| {
                capability.domain == AuthorityDomain::UpgradeAuthority
                    && capability.delay_blocks >= state.config.upgrade_timelock_blocks
                    && capability
                        .required_evidence
                        .contains(&EvidenceKind::UpgradeTimelockRoot)
            }),
            "upgrade authority requires PQ approval plus long timelock evidence",
            format!("upgrade_timelock_blocks={}", state.config.upgrade_timelock_blocks),
            "reject upgrades without timelock root and PQ key migration evidence",
        ),
        check(
            AuthorityCheckKind::EmergencyCannotHaltExits,
            state.roles.values().all(|role| !role.can_halt_exits)
                && state.release_rules.values().all(|rule| {
                    rule.fail_closed_action != FailClosedAction::Reject || !rule.release_path.contains("emergency")
                }),
            "emergency powers may pause deposits but must preserve exits",
            format!(
                "exit_halt_roles={}, forced_exits_enabled={}",
                state.roles.values().filter(|role| role.can_halt_exits).count(),
                spine.policy.forced_exits_enabled
            ),
            "convert emergency pause to pause-deposits-keep-exits mode",
        ),
        check(
            AuthorityCheckKind::PqControlPlane,
            state
                .roles
                .values()
                .all(|role| role.pq_suite.contains("ML-DSA") && role.threshold_weight > 0),
            "all bridge control-plane roles require PQ signing suites and positive threshold weight",
            format!("role_count={}", state.roles.len()),
            "rotate non-PQ role roots before admitting deposits or exits",
        ),
        check(
            AuthorityCheckKind::PrivacyRootsOnly,
            state
                .capabilities
                .values()
                .all(|capability| capability.public_disclosure.contains("root")
                    || capability.public_disclosure.contains("commitment")),
            "public authority records must expose roots and commitments, not wallet plaintext",
            format!("capability_count={}", state.capabilities.len()),
            "redact authority records to roots, commitments, and aggregate counters",
        ),
        check(
            AuthorityCheckKind::ReserveRequiredForRelease,
            state.release_rules.values().all(|rule| {
                !rule.release_path.contains("release")
                    || (rule.blocks_if_reserve_missing
                        && rule
                            .release_certificate_evidence
                            .contains(&EvidenceKind::ReleaseCertificateRoot))
            }),
            "release rules require reserve proof or release certificate before value leaves custody",
            format!("reserve_root_present={}", !spine.policy.reserve_root.is_empty()),
            "delay release and refresh reserve proof before settlement adapter signs",
        ),
        check(
            AuthorityCheckKind::ChallengeBlocksRelease,
            state
                .release_rules
                .values()
                .all(|rule| rule.blocks_if_open_challenge),
            "open challenges must block release until resolved or expired",
            format!("release_rule_count={}", state.release_rules.len()),
            "set every release path to block when challenge state is open",
        ),
    ]
}

fn check(
    kind: AuthorityCheckKind,
    passed: bool,
    requirement: &str,
    observed: String,
    remediation: &str,
) -> AuthorityCheck {
    let status = if passed {
        CheckStatus::Passed
    } else {
        CheckStatus::Failed
    };
    let evidence = json!({
        "kind": kind.as_str(),
        "status": status.as_str(),
        "requirement": requirement,
        "observed": observed,
    });
    let evidence_root = record_root("authority_check_evidence", &evidence);
    AuthorityCheck {
        check_id: authority_id("check", kind.as_str(), &evidence_root),
        kind,
        status,
        requirement: requirement.to_string(),
        observed,
        evidence_root,
        remediation: remediation.to_string(),
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

pub fn authority_id(kind: &str, label: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-ID",
        &[
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::Str(root),
        ],
        32,
    )
}

pub fn root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-ROOT",
        &[HashPart::Str(kind), HashPart::Str(label)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}
