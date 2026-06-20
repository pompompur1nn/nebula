use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalExecutionReplayBundleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_EXECUTION_REPLAY_BUNDLE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-execution-replay-bundle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_EXECUTION_REPLAY_BUNDLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BUNDLE_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-execution-replay-bundle-v1";
pub const DEFAULT_MIN_REQUIRED_DOMAINS: u64 = 10;
pub const DEFAULT_MIN_WALLET_SAFE_DOMAINS: u64 = 9;
pub const DEFAULT_MAX_WATCH_DOMAINS: u64 = 2;
pub const DEFAULT_MAX_DEFERRED_DOMAINS: u64 = 4;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_LEAK_UNITS: u64 = 2;
pub const DEFAULT_MAX_USER_FEE_ATOMIC: u64 = 35_000_000;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_BUNDLE_ITEMS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleDomain {
    DepositLock,
    DepositToNoteLinkage,
    PrivateStateTransition,
    SettlementReceipt,
    ForcedExitClaim,
    ChallengeDispute,
    PqReleaseAuthority,
    PrivacyBudget,
    ReserveSufficiency,
    WalletLocalRecovery,
    OperatorFailureInjection,
    EscapeHatchScorecard,
    ProductionBlockerBurnDown,
}

impl BundleDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::DepositToNoteLinkage => "deposit_to_note_linkage",
            Self::PrivateStateTransition => "private_state_transition",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::ChallengeDispute => "challenge_dispute",
            Self::PqReleaseAuthority => "pq_release_authority",
            Self::PrivacyBudget => "privacy_budget",
            Self::ReserveSufficiency => "reserve_sufficiency",
            Self::WalletLocalRecovery => "wallet_local_recovery",
            Self::OperatorFailureInjection => "operator_failure_injection",
            Self::EscapeHatchScorecard => "escape_hatch_scorecard",
            Self::ProductionBlockerBurnDown => "production_blocker_burn_down",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::DepositLock => 0,
            Self::DepositToNoteLinkage => 1,
            Self::PrivateStateTransition => 2,
            Self::SettlementReceipt => 3,
            Self::ForcedExitClaim => 4,
            Self::ChallengeDispute => 5,
            Self::PqReleaseAuthority => 6,
            Self::PrivacyBudget => 7,
            Self::ReserveSufficiency => 8,
            Self::WalletLocalRecovery => 9,
            Self::OperatorFailureInjection => 10,
            Self::EscapeHatchScorecard => 11,
            Self::ProductionBlockerBurnDown => 12,
        }
    }

    pub fn wallet_critical(self) -> bool {
        matches!(
            self,
            Self::DepositLock
                | Self::DepositToNoteLinkage
                | Self::PrivateStateTransition
                | Self::SettlementReceipt
                | Self::ForcedExitClaim
                | Self::ChallengeDispute
                | Self::PqReleaseAuthority
                | Self::PrivacyBudget
                | Self::ReserveSufficiency
                | Self::WalletLocalRecovery
                | Self::OperatorFailureInjection
                | Self::EscapeHatchScorecard
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVisibility {
    PublicAnchor,
    Commitment,
    EncryptedReceipt,
    WalletLocal,
}

impl EvidenceVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicAnchor => "public_anchor",
            Self::Commitment => "commitment",
            Self::EncryptedReceipt => "encrypted_receipt",
            Self::WalletLocal => "wallet_local",
        }
    }

    pub fn hides_wallet_metadata(self) -> bool {
        matches!(
            self,
            Self::Commitment | Self::EncryptedReceipt | Self::WalletLocal
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleItemStatus {
    Passed,
    Watch,
    Deferred,
    Blocked,
    Rejected,
}

impl BundleItemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_wallet(self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected)
    }

    pub fn blocks_production(self) -> bool {
        matches!(
            self,
            Self::Watch | Self::Deferred | Self::Blocked | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleBlocker {
    MissingReplayRoot,
    NonCanonicalOrder,
    OperatorCooperationRequired,
    PrivacyBudgetExceeded,
    FeeCapExceeded,
    PqReleaseWeightTooLow,
    ReserveCoverageTooLow,
    ChallengeWindowOpen,
    WalletRecoveryMissing,
    RuntimeGateDeferred,
    SecurityAuditDeferred,
    ProductionReleaseBlocked,
    PublicWalletMetadataLeak,
}

impl BundleBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingReplayRoot => "missing_replay_root",
            Self::NonCanonicalOrder => "non_canonical_order",
            Self::OperatorCooperationRequired => "operator_cooperation_required",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::PqReleaseWeightTooLow => "pq_release_weight_too_low",
            Self::ReserveCoverageTooLow => "reserve_coverage_too_low",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::WalletRecoveryMissing => "wallet_recovery_missing",
            Self::RuntimeGateDeferred => "runtime_gate_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::ProductionReleaseBlocked => "production_release_blocked",
            Self::PublicWalletMetadataLeak => "public_wallet_metadata_leak",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::MissingReplayRoot => "execution_replay_bundle",
            Self::NonCanonicalOrder => "canonical_transcript",
            Self::OperatorCooperationRequired => "forced_exit_contract",
            Self::PrivacyBudgetExceeded => "privacy_budget_regression",
            Self::FeeCapExceeded => "fee_policy",
            Self::PqReleaseWeightTooLow => "pq_release_authority",
            Self::ReserveCoverageTooLow => "liquidity_reserve",
            Self::ChallengeWindowOpen => "challenge_dispute",
            Self::WalletRecoveryMissing => "wallet_local_recovery",
            Self::RuntimeGateDeferred => "runtime_harness",
            Self::SecurityAuditDeferred => "security_audit",
            Self::ProductionReleaseBlocked => "release_management",
            Self::PublicWalletMetadataLeak => "wallet_privacy",
        }
    }

    pub fn blocks_wallet(self) -> bool {
        matches!(
            self,
            Self::MissingReplayRoot
                | Self::NonCanonicalOrder
                | Self::OperatorCooperationRequired
                | Self::PrivacyBudgetExceeded
                | Self::FeeCapExceeded
                | Self::PqReleaseWeightTooLow
                | Self::ReserveCoverageTooLow
                | Self::WalletRecoveryMissing
                | Self::PublicWalletMetadataLeak
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleVerdict {
    WalletEscapeReplayable,
    WalletEscapeReplayableButDeferred,
    Watch,
    Blocked,
    Rejected,
}

impl BundleVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletEscapeReplayable => "wallet_escape_replayable",
            Self::WalletEscapeReplayableButDeferred => "wallet_escape_replayable_but_deferred",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn user_answer(self) -> &'static str {
        match self {
            Self::WalletEscapeReplayable | Self::WalletEscapeReplayableButDeferred => {
                "user_can_get_in_move_privately_and_force_out_from_replay_bundle"
            }
            Self::Watch => "user_escape_needs_challenge_window_or_watcher_followup",
            Self::Blocked => "user_escape_blocked_until_wallet_critical_blockers_clear",
            Self::Rejected => "user_escape_rejected_by_bundle_replay",
        }
    }

    pub fn release_answer(self) -> &'static str {
        match self {
            Self::WalletEscapeReplayable => "design_replayable_but_release_still_needs_heavy_gates",
            Self::WalletEscapeReplayableButDeferred => {
                "release_blocked_by_deferred_runtime_or_audit_evidence"
            }
            Self::Watch => "release_requires_watch_items_to_clear",
            Self::Blocked => "release_blocked",
            Self::Rejected => "release_rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub min_required_domains: u64,
    pub min_wallet_safe_domains: u64,
    pub max_watch_domains: u64,
    pub max_deferred_domains: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_leak_units: u64,
    pub max_user_fee_atomic: u64,
    pub challenge_window_blocks: u64,
    pub max_bundle_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_required_domains: DEFAULT_MIN_REQUIRED_DOMAINS,
            min_wallet_safe_domains: DEFAULT_MIN_WALLET_SAFE_DOMAINS,
            max_watch_domains: DEFAULT_MAX_WATCH_DOMAINS,
            max_deferred_domains: DEFAULT_MAX_DEFERRED_DOMAINS,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_metadata_leak_units: DEFAULT_MAX_METADATA_LEAK_UNITS,
            max_user_fee_atomic: DEFAULT_MAX_USER_FEE_ATOMIC,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_bundle_items: DEFAULT_MAX_BUNDLE_ITEMS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleInput {
    pub domain: BundleDomain,
    pub required: bool,
    pub visibility: EvidenceVisibility,
    pub replay_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub operator_independent: bool,
    pub wallet_reconstructable: bool,
    pub challenge_elapsed_blocks: u64,
    pub pq_weight_bps: u64,
    pub reserve_coverage_bps: u64,
    pub metadata_leak_units: u64,
    pub fee_atomic: u64,
    pub runtime_executed: bool,
    pub security_audit_signed: bool,
    pub production_release_blocked: bool,
}

impl BundleInput {
    pub fn leaf(&self) -> Value {
        json!({
            "domain": self.domain.as_str(),
            "domain_ordinal": self.domain.ordinal(),
            "required": self.required,
            "visibility": self.visibility.as_str(),
            "replay_root": self.replay_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "operator_independent": self.operator_independent,
            "wallet_reconstructable": self.wallet_reconstructable,
            "challenge_elapsed_blocks": self.challenge_elapsed_blocks,
            "pq_weight_bps": self.pq_weight_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "metadata_leak_units": self.metadata_leak_units,
            "fee_atomic": self.fee_atomic,
            "runtime_executed": self.runtime_executed,
            "security_audit_signed": self.security_audit_signed,
            "production_release_blocked": self.production_release_blocked,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleItem {
    pub index: u64,
    pub domain: BundleDomain,
    pub required: bool,
    pub visibility: EvidenceVisibility,
    pub status: BundleItemStatus,
    pub blocker: Option<BundleBlocker>,
    pub owner_lane: Option<String>,
    pub replay_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub item_root: String,
    pub wallet_safe: bool,
    pub production_safe: bool,
}

impl BundleItem {
    pub fn from_input(index: u64, input: BundleInput, config: &Config) -> Self {
        let blocker = derive_blocker(index, &input, config);
        let status = derive_status(blocker, &input);
        let wallet_safe = input.domain.wallet_critical()
            && !status.blocks_wallet()
            && input.operator_independent
            && input.wallet_reconstructable;
        let production_safe = !status.blocks_production()
            && input.runtime_executed
            && input.security_audit_signed
            && !input.production_release_blocked;
        let owner_lane = blocker.map(|value| value.owner_lane().to_string());
        let item_leaf = json!({
            "index": index,
            "domain": input.domain.as_str(),
            "required": input.required,
            "visibility": input.visibility.as_str(),
            "status": status.as_str(),
            "blocker": blocker.map(BundleBlocker::as_str),
            "owner_lane": owner_lane,
            "replay_root": input.replay_root,
            "public_root": input.public_root,
            "committed_root": input.committed_root,
            "encrypted_root": input.encrypted_root,
            "wallet_recovery_root": input.wallet_recovery_root,
            "wallet_safe": wallet_safe,
            "production_safe": production_safe,
        });
        let item_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-replay-bundle-item",
            &[HashPart::Json(&item_leaf)],
            32,
        );
        Self {
            index,
            domain: input.domain,
            required: input.required,
            visibility: input.visibility,
            status,
            blocker,
            owner_lane,
            replay_root: input.replay_root,
            public_root: input.public_root,
            committed_root: input.committed_root,
            encrypted_root: input.encrypted_root,
            wallet_recovery_root: input.wallet_recovery_root,
            item_root,
            wallet_safe,
            production_safe,
        }
    }

    pub fn leaf(&self) -> Value {
        json!({
            "index": self.index,
            "domain": self.domain.as_str(),
            "required": self.required,
            "visibility": self.visibility.as_str(),
            "status": self.status.as_str(),
            "blocker": self.blocker.map(BundleBlocker::as_str),
            "owner_lane": self.owner_lane,
            "replay_root": self.replay_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "item_root": self.item_root,
            "wallet_safe": self.wallet_safe,
            "production_safe": self.production_safe,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleCounters {
    pub passed: u64,
    pub watch: u64,
    pub deferred: u64,
    pub blocked: u64,
    pub rejected: u64,
    pub required: u64,
    pub wallet_critical: u64,
    pub wallet_safe: u64,
    pub production_safe: u64,
}

impl BundleCounters {
    pub fn ingest(&mut self, item: &BundleItem) {
        match item.status {
            BundleItemStatus::Passed => self.passed += 1,
            BundleItemStatus::Watch => self.watch += 1,
            BundleItemStatus::Deferred => self.deferred += 1,
            BundleItemStatus::Blocked => self.blocked += 1,
            BundleItemStatus::Rejected => self.rejected += 1,
        }
        if item.required {
            self.required += 1;
        }
        if item.domain.wallet_critical() {
            self.wallet_critical += 1;
        }
        if item.wallet_safe {
            self.wallet_safe += 1;
        }
        if item.production_safe {
            self.production_safe += 1;
        }
    }

    pub fn total(&self) -> u64 {
        self.passed + self.watch + self.deferred + self.blocked + self.rejected
    }

    pub fn has_wallet_blocker(&self) -> bool {
        self.blocked > 0 || self.rejected > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayBundle {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub bundle_suite: String,
    pub verdict: BundleVerdict,
    pub user_answer: String,
    pub release_answer: String,
    pub bundle_root: String,
    pub item_root: String,
    pub replay_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub blocker_root: String,
    pub counters: BundleCounters,
    pub blocker_counts: BTreeMap<String, u64>,
    pub items: Vec<BundleItem>,
}

impl ReplayBundle {
    pub fn from_items(config: &Config, items: Vec<BundleItem>) -> Self {
        let mut counters = BundleCounters::default();
        let mut blocker_counts = BTreeMap::new();
        for item in &items {
            counters.ingest(item);
            if let Some(blocker) = item.blocker {
                *blocker_counts
                    .entry(blocker.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }

        let item_leaves = items.iter().map(BundleItem::leaf).collect::<Vec<_>>();
        let replay_leaves = items
            .iter()
            .map(|item| json!({ "domain": item.domain.as_str(), "root": item.replay_root }))
            .collect::<Vec<_>>();
        let public_leaves = items
            .iter()
            .map(|item| json!({ "domain": item.domain.as_str(), "root": item.public_root }))
            .collect::<Vec<_>>();
        let committed_leaves = items
            .iter()
            .map(|item| json!({ "domain": item.domain.as_str(), "root": item.committed_root }))
            .collect::<Vec<_>>();
        let encrypted_leaves = items
            .iter()
            .map(|item| json!({ "domain": item.domain.as_str(), "root": item.encrypted_root }))
            .collect::<Vec<_>>();
        let wallet_leaves = items
            .iter()
            .map(
                |item| json!({ "domain": item.domain.as_str(), "root": item.wallet_recovery_root }),
            )
            .collect::<Vec<_>>();
        let blocker_leaves = blocker_counts
            .iter()
            .map(|(blocker, count)| json!({ "blocker": blocker, "count": count }))
            .collect::<Vec<_>>();

        let item_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-items",
            &item_leaves,
        );
        let replay_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-replay",
            &replay_leaves,
        );
        let public_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-public",
            &public_leaves,
        );
        let committed_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-committed",
            &committed_leaves,
        );
        let encrypted_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-encrypted",
            &encrypted_leaves,
        );
        let wallet_recovery_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-wallet",
            &wallet_leaves,
        );
        let blocker_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-blockers",
            &blocker_leaves,
        );

        let verdict = derive_verdict(config, &counters);
        let bundle_payload = json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": config.chain_id,
            "bundle_suite": BUNDLE_SUITE,
            "verdict": verdict.as_str(),
            "user_answer": verdict.user_answer(),
            "release_answer": verdict.release_answer(),
            "item_root": item_root,
            "replay_root": replay_root,
            "public_root": public_root,
            "committed_root": committed_root,
            "encrypted_root": encrypted_root,
            "wallet_recovery_root": wallet_recovery_root,
            "blocker_root": blocker_root,
            "counters": counters,
        });
        let bundle_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-replay-bundle",
            &[HashPart::Json(&bundle_payload)],
            32,
        );

        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: config.chain_id.clone(),
            bundle_suite: BUNDLE_SUITE.to_string(),
            verdict,
            user_answer: verdict.user_answer().to_string(),
            release_answer: verdict.release_answer().to_string(),
            bundle_root,
            item_root,
            replay_root,
            public_root,
            committed_root,
            encrypted_root,
            wallet_recovery_root,
            blocker_root,
            counters,
            blocker_counts,
            items,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "bundle_suite": self.bundle_suite,
            "verdict": self.verdict.as_str(),
            "user_answer": self.user_answer,
            "release_answer": self.release_answer,
            "bundle_root": self.bundle_root,
            "item_root": self.item_root,
            "replay_root": self.replay_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "blocker_root": self.blocker_root,
            "counters": self.counters,
            "blocker_counts": self.blocker_counts,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub bundle: ReplayBundle,
}

impl State {
    pub fn new() -> Self {
        Self::from_inputs(Config::default(), default_inputs())
    }

    pub fn from_inputs(config: Config, inputs: Vec<BundleInput>) -> Self {
        let items = inputs
            .into_iter()
            .enumerate()
            .map(|(index, input)| BundleItem::from_input(index as u64, input, &config))
            .collect::<Vec<_>>();
        let bundle = ReplayBundle::from_items(&config, items);
        Self { config, bundle }
    }

    pub fn ingest(&mut self, input: BundleInput) -> Result<()> {
        if self.bundle.items.len() >= self.config.max_bundle_items {
            return Err("canonical execution replay bundle item limit reached".to_string());
        }
        let mut inputs = self
            .bundle
            .items
            .iter()
            .map(bundle_item_to_input)
            .collect::<Vec<_>>();
        inputs.push(input);
        *self = Self::from_inputs(self.config.clone(), inputs);
        Ok(())
    }

    pub fn user_escape_replayable(&self) -> bool {
        matches!(
            self.bundle.verdict,
            BundleVerdict::WalletEscapeReplayable
                | BundleVerdict::WalletEscapeReplayableButDeferred
        )
    }

    pub fn production_blocked(&self) -> bool {
        !matches!(self.bundle.verdict, BundleVerdict::WalletEscapeReplayable)
            || self.bundle.counters.deferred > 0
            || self.bundle.counters.watch > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": {
                "chain_id": self.config.chain_id,
                "min_required_domains": self.config.min_required_domains,
                "min_wallet_safe_domains": self.config.min_wallet_safe_domains,
                "max_watch_domains": self.config.max_watch_domains,
                "max_deferred_domains": self.config.max_deferred_domains,
                "min_pq_weight_bps": self.config.min_pq_weight_bps,
                "min_reserve_coverage_bps": self.config.min_reserve_coverage_bps,
                "max_metadata_leak_units": self.config.max_metadata_leak_units,
                "max_user_fee_atomic": self.config.max_user_fee_atomic,
                "challenge_window_blocks": self.config.challenge_window_blocks,
                "max_bundle_items": self.config.max_bundle_items,
            },
            "bundle": self.bundle.public_record(),
            "user_escape_replayable": self.user_escape_replayable(),
            "production_blocked": self.production_blocked(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_value(&self.public_record())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

pub fn devnet() -> State {
    State::new()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn state_root_from_value(value: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-execution-replay-bundle-state",
        &[HashPart::Json(value)],
        32,
    )
}

fn derive_blocker(index: u64, input: &BundleInput, config: &Config) -> Option<BundleBlocker> {
    if input.replay_root.is_empty()
        || input.public_root.is_empty()
        || input.committed_root.is_empty()
        || input.encrypted_root.is_empty()
    {
        return Some(BundleBlocker::MissingReplayRoot);
    }
    if index != input.domain.ordinal() {
        return Some(BundleBlocker::NonCanonicalOrder);
    }
    if input.visibility == EvidenceVisibility::PublicAnchor && input.domain.wallet_critical() {
        return Some(BundleBlocker::PublicWalletMetadataLeak);
    }
    if !input.operator_independent {
        return Some(BundleBlocker::OperatorCooperationRequired);
    }
    if input.metadata_leak_units > config.max_metadata_leak_units {
        return Some(BundleBlocker::PrivacyBudgetExceeded);
    }
    if input.fee_atomic > config.max_user_fee_atomic {
        return Some(BundleBlocker::FeeCapExceeded);
    }
    if input.pq_weight_bps < config.min_pq_weight_bps
        && input.domain.ordinal() >= BundleDomain::PqReleaseAuthority.ordinal()
    {
        return Some(BundleBlocker::PqReleaseWeightTooLow);
    }
    if input.reserve_coverage_bps < config.min_reserve_coverage_bps
        && input.domain.ordinal() >= BundleDomain::ReserveSufficiency.ordinal()
    {
        return Some(BundleBlocker::ReserveCoverageTooLow);
    }
    if input.challenge_elapsed_blocks < config.challenge_window_blocks
        && input.domain.ordinal() >= BundleDomain::ChallengeDispute.ordinal()
    {
        return Some(BundleBlocker::ChallengeWindowOpen);
    }
    if !input.wallet_reconstructable && input.domain.wallet_critical() {
        return Some(BundleBlocker::WalletRecoveryMissing);
    }
    if !input.runtime_executed {
        return Some(BundleBlocker::RuntimeGateDeferred);
    }
    if !input.security_audit_signed {
        return Some(BundleBlocker::SecurityAuditDeferred);
    }
    if input.production_release_blocked {
        return Some(BundleBlocker::ProductionReleaseBlocked);
    }
    None
}

fn derive_status(blocker: Option<BundleBlocker>, input: &BundleInput) -> BundleItemStatus {
    match blocker {
        None => BundleItemStatus::Passed,
        Some(BundleBlocker::RuntimeGateDeferred)
        | Some(BundleBlocker::SecurityAuditDeferred)
        | Some(BundleBlocker::ProductionReleaseBlocked) => BundleItemStatus::Deferred,
        Some(BundleBlocker::ChallengeWindowOpen) => BundleItemStatus::Watch,
        Some(blocker) if blocker.blocks_wallet() => BundleItemStatus::Blocked,
        Some(_) if input.required => BundleItemStatus::Blocked,
        Some(_) => BundleItemStatus::Rejected,
    }
}

fn derive_verdict(config: &Config, counters: &BundleCounters) -> BundleVerdict {
    if counters.rejected > 0 {
        return BundleVerdict::Rejected;
    }
    if counters.has_wallet_blocker() {
        return BundleVerdict::Blocked;
    }
    if counters.watch > config.max_watch_domains {
        return BundleVerdict::Watch;
    }
    if counters.required < config.min_required_domains {
        return BundleVerdict::Blocked;
    }
    if counters.wallet_safe < config.min_wallet_safe_domains {
        return BundleVerdict::Blocked;
    }
    if counters.deferred > config.max_deferred_domains {
        return BundleVerdict::Blocked;
    }
    if counters.watch > 0 {
        return BundleVerdict::Watch;
    }
    if counters.deferred > 0 {
        BundleVerdict::WalletEscapeReplayableButDeferred
    } else {
        BundleVerdict::WalletEscapeReplayable
    }
}

fn bundle_item_to_input(item: &BundleItem) -> BundleInput {
    BundleInput {
        domain: item.domain,
        required: item.required,
        visibility: item.visibility,
        replay_root: item.replay_root.clone(),
        public_root: item.public_root.clone(),
        committed_root: item.committed_root.clone(),
        encrypted_root: item.encrypted_root.clone(),
        wallet_recovery_root: item.wallet_recovery_root.clone(),
        operator_independent: item.wallet_safe,
        wallet_reconstructable: item.wallet_safe,
        challenge_elapsed_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
        metadata_leak_units: 1,
        fee_atomic: DEFAULT_MAX_USER_FEE_ATOMIC / 2,
        runtime_executed: false,
        security_audit_signed: false,
        production_release_blocked: true,
    }
}

fn default_inputs() -> Vec<BundleInput> {
    [
        BundleDomain::DepositLock,
        BundleDomain::DepositToNoteLinkage,
        BundleDomain::PrivateStateTransition,
        BundleDomain::SettlementReceipt,
        BundleDomain::ForcedExitClaim,
        BundleDomain::ChallengeDispute,
        BundleDomain::PqReleaseAuthority,
        BundleDomain::PrivacyBudget,
        BundleDomain::ReserveSufficiency,
        BundleDomain::WalletLocalRecovery,
        BundleDomain::OperatorFailureInjection,
        BundleDomain::EscapeHatchScorecard,
        BundleDomain::ProductionBlockerBurnDown,
    ]
    .iter()
    .map(|domain| default_input(*domain))
    .collect()
}

fn default_input(domain: BundleDomain) -> BundleInput {
    let domain_name = domain.as_str();
    let replay_payload = json!({
        "domain": domain_name,
        "purpose": "canonical-bridge-exit-replay-root",
        "wallet_metadata": "redacted",
    });
    let public_payload = json!({
        "domain": domain_name,
        "public_anchor": "canonical-redacted-anchor",
    });
    let committed_payload = json!({
        "domain": domain_name,
        "commitment": "canonical-private-l2-commitment",
    });
    let encrypted_payload = json!({
        "domain": domain_name,
        "encrypted_receipt": "wallet-recoverable-shard",
    });
    let wallet_payload = json!({
        "domain": domain_name,
        "wallet_local": "reconstruction-hint-root",
    });
    BundleInput {
        domain,
        required: domain != BundleDomain::ProductionBlockerBurnDown,
        visibility: match domain {
            BundleDomain::DepositLock => EvidenceVisibility::Commitment,
            BundleDomain::DepositToNoteLinkage => EvidenceVisibility::Commitment,
            BundleDomain::PrivateStateTransition => EvidenceVisibility::EncryptedReceipt,
            BundleDomain::SettlementReceipt => EvidenceVisibility::Commitment,
            BundleDomain::ForcedExitClaim => EvidenceVisibility::Commitment,
            BundleDomain::ChallengeDispute => EvidenceVisibility::Commitment,
            BundleDomain::PqReleaseAuthority => EvidenceVisibility::Commitment,
            BundleDomain::PrivacyBudget => EvidenceVisibility::Commitment,
            BundleDomain::ReserveSufficiency => EvidenceVisibility::PublicAnchor,
            BundleDomain::WalletLocalRecovery => EvidenceVisibility::WalletLocal,
            BundleDomain::OperatorFailureInjection => EvidenceVisibility::Commitment,
            BundleDomain::EscapeHatchScorecard => EvidenceVisibility::Commitment,
            BundleDomain::ProductionBlockerBurnDown => EvidenceVisibility::PublicAnchor,
        },
        replay_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-replay-root",
            &[HashPart::Json(&replay_payload)],
            32,
        ),
        public_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-public-root",
            &[HashPart::Json(&public_payload)],
            32,
        ),
        committed_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-committed-root",
            &[HashPart::Json(&committed_payload)],
            32,
        ),
        encrypted_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-encrypted-root",
            &[HashPart::Json(&encrypted_payload)],
            32,
        ),
        wallet_recovery_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-replay-bundle-wallet-root",
            &[HashPart::Json(&wallet_payload)],
            32,
        ),
        operator_independent: true,
        wallet_reconstructable: true,
        challenge_elapsed_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS + 900,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS + 1_500,
        metadata_leak_units: 1,
        fee_atomic: DEFAULT_MAX_USER_FEE_ATOMIC / 2,
        runtime_executed: false,
        security_audit_signed: false,
        production_release_blocked: true,
    }
}
