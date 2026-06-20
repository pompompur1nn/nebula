use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAdversarialMismatchFixtureRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_MISMATCH_FIXTURE_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-mismatch-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_MISMATCH_FIXTURE_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-mismatch-fixture";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub lane_id: String,
    pub fixture_suite: String,
    pub binding_module: String,
    pub min_fixture_count: u64,
    pub required_release_hold_count: u64,
    pub expected_release_allowed: u64,
    pub require_wallet_notice: u64,
    pub require_privacy_boundary: u64,
    pub require_binding_handoff: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lane_id: "canonical_user_escape_adversarial_mismatch_fixture".to_string(),
            fixture_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-mismatch-fixtures-v1"
                    .to_string(),
            binding_module:
                "monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime"
                    .to_string(),
            min_fixture_count: 7,
            required_release_hold_count: 7,
            expected_release_allowed: 0,
            require_wallet_notice: 1,
            require_privacy_boundary: 1,
            require_binding_handoff: 1,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "fixture_suite": self.fixture_suite,
            "binding_module": self.binding_module,
            "min_fixture_count": self.min_fixture_count,
            "required_release_hold_count": self.required_release_hold_count,
            "expected_release_allowed": self.expected_release_allowed,
            "require_wallet_notice": self.require_wallet_notice,
            "require_privacy_boundary": self.require_privacy_boundary,
            "require_binding_handoff": self.require_binding_handoff,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchScenario {
    MoneroReorg,
    WatcherCollusion,
    StalePqEpoch,
    LiquidityShortfall,
    ForgedReceipt,
    WalletMismatch,
    MetadataLeak,
}

impl MismatchScenario {
    pub fn all() -> [Self; 7] {
        [
            Self::MoneroReorg,
            Self::WatcherCollusion,
            Self::StalePqEpoch,
            Self::LiquidityShortfall,
            Self::ForgedReceipt,
            Self::WalletMismatch,
            Self::MetadataLeak,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroReorg => "monero_reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::ForgedReceipt => "forged_receipt",
            Self::WalletMismatch => "wallet_mismatch",
            Self::MetadataLeak => "metadata_leak",
        }
    }

    pub fn process_feed_lane(self) -> &'static str {
        match self {
            Self::MoneroReorg => "monero_watcher",
            Self::WatcherCollusion => "adversarial",
            Self::StalePqEpoch => "pq_authority",
            Self::LiquidityShortfall => "reserve",
            Self::ForgedReceipt => "receipt",
            Self::WalletMismatch => "wallet_scanner",
            Self::MetadataLeak => "wallet_scanner",
        }
    }

    pub fn reconciliation_target(self) -> &'static str {
        match self {
            Self::MoneroReorg => "deposit_lock_runtime_output_reconciliation",
            Self::WatcherCollusion => "adversarial_gap_runtime_output_reconciliation",
            Self::StalePqEpoch => "release_verification_runtime_output_reconciliation",
            Self::LiquidityShortfall => "runtime_output_reconciliation_manifest",
            Self::ForgedReceipt => "settlement_receipt_runtime_output_reconciliation",
            Self::WalletMismatch => "wallet_runbook_runtime_output_reconciliation",
            Self::MetadataLeak => "private_note_runtime_output_reconciliation",
        }
    }

    pub fn fault_kind(self) -> &'static str {
        match self {
            Self::MoneroReorg => "reorged_lock_output_root",
            Self::WatcherCollusion => "colluding_watcher_quorum_root",
            Self::StalePqEpoch => "stale_pq_attestation_epoch_root",
            Self::LiquidityShortfall => "reserve_coverage_below_claim_root",
            Self::ForgedReceipt => "forged_settlement_receipt_root",
            Self::WalletMismatch => "wallet_visible_output_mismatch_root",
            Self::MetadataLeak => "metadata_leak_privacy_boundary_root",
        }
    }

    pub fn release_hold_reason(self) -> &'static str {
        match self {
            Self::MoneroReorg => "hold release until Monero finality and deposit lock root refresh",
            Self::WatcherCollusion => "hold release and require emergency watcher quorum rotation",
            Self::StalePqEpoch => "hold release until post-quantum authority epoch refresh",
            Self::LiquidityShortfall => {
                "hold release until reserve coverage exceeds forced-exit floor"
            }
            Self::ForgedReceipt => {
                "hold release until receipt transcript is rejected and replay proof is bound"
            }
            Self::WalletMismatch => "hold release until wallet scanner evidence is reconciled",
            Self::MetadataLeak => "hold release until wallet scan metadata is masked and rebound",
        }
    }

    pub fn wallet_action(self) -> &'static str {
        match self {
            Self::MoneroReorg => "rescan_monero_finality_window",
            Self::WatcherCollusion => "switch_to_emergency_watcher_set",
            Self::StalePqEpoch => "wait_for_pq_epoch_rotation",
            Self::LiquidityShortfall => "queue_exit_until_reserve_refresh",
            Self::ForgedReceipt => "reject_receipt_and_request_transcript",
            Self::WalletMismatch => "rescan_wallet_visible_outputs",
            Self::MetadataLeak => "rotate_scan_window_and_hide_timing",
        }
    }

    pub fn privacy_boundary(self) -> &'static str {
        match self {
            Self::MoneroReorg => "public_reorg_depth_and_header_roots_only",
            Self::WatcherCollusion => "redacted_watcher_set_and_slashing_roots_only",
            Self::StalePqEpoch => "public_pq_epoch_and_signature_roots_only",
            Self::LiquidityShortfall => "bucketed_reserve_coverage_roots_only",
            Self::ForgedReceipt => "receipt_transcript_commitments_only",
            Self::WalletMismatch => "wallet_encrypted_scan_roots_only",
            Self::MetadataLeak => "metadata_budget_commitments_only",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchFixture {
    pub scenario: MismatchScenario,
    pub ordinal: u64,
    pub process_feed_lane: String,
    pub reconciliation_target: String,
    pub fault_kind: String,
    pub binding_state_root: String,
    pub binding_handoff_root: String,
    pub original_process_feed_root: String,
    pub mutated_process_feed_root: String,
    pub reconciliation_reference_root: String,
    pub mismatch_digest: String,
    pub privacy_boundary: String,
    pub wallet_action: String,
    pub release_hold_reason: String,
    pub release_allowed: u64,
    pub release_hold_required: u64,
    pub fixture_root: String,
}

impl MismatchFixture {
    pub fn devnet(
        config: &Config,
        scenario: MismatchScenario,
        ordinal: u64,
        binding_state_root: &str,
        binding_handoff_root: &str,
    ) -> Self {
        let original_process_feed_root = process_feed_root_for(scenario);
        let reconciliation_reference_root = reconciliation_root_for(scenario);
        let mutated_process_feed_root = mutated_process_feed_root(
            scenario,
            ordinal,
            binding_state_root,
            &original_process_feed_root,
        );
        let release_allowed = config.expected_release_allowed;
        let release_hold_required = 1;
        let process_feed_lane = scenario.process_feed_lane().to_string();
        let reconciliation_target = scenario.reconciliation_target().to_string();
        let fault_kind = scenario.fault_kind().to_string();
        let privacy_boundary = scenario.privacy_boundary().to_string();
        let wallet_action = scenario.wallet_action().to_string();
        let release_hold_reason = scenario.release_hold_reason().to_string();
        let mismatch_digest = domain_hash(
            &format!("{DOMAIN}:mismatch-digest"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(scenario.as_str()),
                HashPart::Str(&process_feed_lane),
                HashPart::Str(&reconciliation_target),
                HashPart::Str(&fault_kind),
                HashPart::Str(binding_state_root),
                HashPart::Str(binding_handoff_root),
                HashPart::Str(&original_process_feed_root),
                HashPart::Str(&mutated_process_feed_root),
                HashPart::Str(&reconciliation_reference_root),
                HashPart::U64(release_allowed),
                HashPart::U64(release_hold_required),
            ],
            32,
        );
        let fixture_root = domain_hash(
            &format!("{DOMAIN}:fixture"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(scenario.as_str()),
                HashPart::U64(ordinal),
                HashPart::Str(&mismatch_digest),
                HashPart::Str(&privacy_boundary),
                HashPart::Str(&wallet_action),
                HashPart::Str(&release_hold_reason),
            ],
            32,
        );
        Self {
            scenario,
            ordinal,
            process_feed_lane,
            reconciliation_target,
            fault_kind,
            binding_state_root: binding_state_root.to_string(),
            binding_handoff_root: binding_handoff_root.to_string(),
            original_process_feed_root,
            mutated_process_feed_root,
            reconciliation_reference_root,
            mismatch_digest,
            privacy_boundary,
            wallet_action,
            release_hold_reason,
            release_allowed,
            release_hold_required,
            fixture_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario": self.scenario,
            "ordinal": self.ordinal,
            "process_feed_lane": self.process_feed_lane,
            "reconciliation_target": self.reconciliation_target,
            "fault_kind": self.fault_kind,
            "binding_state_root": self.binding_state_root,
            "binding_handoff_root": self.binding_handoff_root,
            "original_process_feed_root": self.original_process_feed_root,
            "mutated_process_feed_root": self.mutated_process_feed_root,
            "reconciliation_reference_root": self.reconciliation_reference_root,
            "mismatch_digest": self.mismatch_digest,
            "privacy_boundary": self.privacy_boundary,
            "wallet_action": self.wallet_action,
            "release_hold_reason": self.release_hold_reason,
            "release_allowed": self.release_allowed,
            "release_hold_required": self.release_hold_required,
            "fixture_root": self.fixture_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureVerdict {
    pub fixture_count: u64,
    pub release_hold_count: u64,
    pub wallet_notice_count: u64,
    pub privacy_boundary_count: u64,
    pub binding_handoff_present: u64,
    pub all_mutations_change_feed_root: u64,
    pub release_allowed: u64,
    pub verdict: String,
    pub verdict_root: String,
}

impl FixtureVerdict {
    pub fn from_fixtures(
        config: &Config,
        fixtures: &[MismatchFixture],
        binding_handoff_root: &str,
    ) -> Self {
        let fixture_count = fixtures.len() as u64;
        let release_hold_count = fixtures
            .iter()
            .filter(|fixture| {
                fixture.release_hold_required == 1
                    && fixture.release_allowed == config.expected_release_allowed
            })
            .count() as u64;
        let wallet_notice_count = fixtures
            .iter()
            .filter(|fixture| !fixture.wallet_action.is_empty())
            .count() as u64;
        let privacy_boundary_count = fixtures
            .iter()
            .filter(|fixture| !fixture.privacy_boundary.is_empty())
            .count() as u64;
        let binding_handoff_present = non_empty_flag(binding_handoff_root);
        let all_mutations_change_feed_root = if fixtures
            .iter()
            .all(|fixture| fixture.original_process_feed_root != fixture.mutated_process_feed_root)
        {
            1
        } else {
            0
        };
        let release_allowed = 0;
        let verdict = if fixture_count >= config.min_fixture_count
            && release_hold_count >= config.required_release_hold_count
            && wallet_notice_count == fixture_count
            && privacy_boundary_count == fixture_count
            && binding_handoff_present == config.require_binding_handoff
            && all_mutations_change_feed_root == 1
        {
            "adversarial_mismatch_fixtures_hold_release".to_string()
        } else {
            "adversarial_mismatch_fixtures_incomplete_hold_release".to_string()
        };
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.lane_id),
                HashPart::U64(fixture_count),
                HashPart::U64(release_hold_count),
                HashPart::U64(wallet_notice_count),
                HashPart::U64(privacy_boundary_count),
                HashPart::U64(binding_handoff_present),
                HashPart::U64(all_mutations_change_feed_root),
                HashPart::U64(release_allowed),
                HashPart::Str(&verdict),
            ],
            32,
        );
        Self {
            fixture_count,
            release_hold_count,
            wallet_notice_count,
            privacy_boundary_count,
            binding_handoff_present,
            all_mutations_change_feed_root,
            release_allowed,
            verdict,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_count": self.fixture_count,
            "release_hold_count": self.release_hold_count,
            "wallet_notice_count": self.wallet_notice_count,
            "privacy_boundary_count": self.privacy_boundary_count,
            "binding_handoff_present": self.binding_handoff_present,
            "all_mutations_change_feed_root": self.all_mutations_change_feed_root,
            "release_allowed": self.release_allowed,
            "verdict": self.verdict,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub binding_state_root: String,
    pub binding_public_record_root: String,
    pub binding_handoff_root: String,
    pub fixtures: Vec<MismatchFixture>,
    pub verdict: FixtureVerdict,
    pub fixture_root: String,
    pub mismatch_digest_root: String,
    pub wallet_action_root: String,
    pub privacy_boundary_root: String,
    pub release_hold_root: String,
}

impl State {
    pub fn new(
        config: Config,
        binding_state_root: String,
        binding_public_record_root: String,
        binding_handoff_root: String,
        fixtures: Vec<MismatchFixture>,
    ) -> Result<Self> {
        if fixtures.len() as u64 != config.min_fixture_count {
            return Err("adversarial mismatch fixture count mismatch".to_string());
        }
        if binding_handoff_root.is_empty() {
            return Err("adversarial mismatch fixture requires binding handoff root".to_string());
        }
        let verdict = FixtureVerdict::from_fixtures(&config, &fixtures, &binding_handoff_root);
        let fixture_root = merkle_root(
            &format!("{DOMAIN}:fixtures"),
            &fixtures
                .iter()
                .map(MismatchFixture::public_record)
                .collect::<Vec<_>>(),
        );
        let mismatch_digest_root = merkle_root(
            &format!("{DOMAIN}:mismatch-digests"),
            &fixtures
                .iter()
                .map(|fixture| json!(fixture.mismatch_digest))
                .collect::<Vec<_>>(),
        );
        let wallet_action_root = merkle_root(
            &format!("{DOMAIN}:wallet-actions"),
            &fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "scenario": fixture.scenario,
                        "wallet_action": fixture.wallet_action,
                        "release_hold_reason": fixture.release_hold_reason,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let privacy_boundary_root = merkle_root(
            &format!("{DOMAIN}:privacy-boundaries"),
            &fixtures
                .iter()
                .map(|fixture| {
                    json!({
                        "scenario": fixture.scenario,
                        "privacy_boundary": fixture.privacy_boundary,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let release_hold_root = domain_hash(
            &format!("{DOMAIN}:release-hold"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.state_root()),
                HashPart::Str(&binding_handoff_root),
                HashPart::Str(&fixture_root),
                HashPart::Str(&mismatch_digest_root),
                HashPart::Str(&wallet_action_root),
                HashPart::Str(&privacy_boundary_root),
                HashPart::Str(&verdict.verdict_root),
                HashPart::U64(verdict.release_allowed),
            ],
            32,
        );
        Ok(Self {
            config,
            binding_state_root,
            binding_public_record_root,
            binding_handoff_root,
            fixtures,
            verdict,
            fixture_root,
            mismatch_digest_root,
            wallet_action_root,
            privacy_boundary_root,
            release_hold_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::default();
        let binding_state_root =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::state_root();
        let binding_public_record =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::public_record();
        let binding_public_record_root =
            record_root("binding_public_record", &binding_public_record);
        let binding_handoff_root = domain_hash(
            &format!("{DOMAIN}:binding-handoff"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&binding_state_root),
                HashPart::Str(&binding_public_record_root),
            ],
            32,
        );
        let fixtures = MismatchScenario::all()
            .iter()
            .enumerate()
            .map(|(index, scenario)| {
                MismatchFixture::devnet(
                    &config,
                    *scenario,
                    index as u64,
                    &binding_state_root,
                    &binding_handoff_root,
                )
            })
            .collect::<Vec<_>>();
        match Self::new(
            config,
            binding_state_root,
            binding_public_record_root,
            binding_handoff_root,
            fixtures,
        ) {
            Ok(state) => state,
            Err(error) => Self::invalid(error),
        }
    }

    pub fn invalid(error: String) -> Self {
        let config = Config::default();
        let binding_state_root = "missing-binding-state-root".to_string();
        let binding_public_record_root = "missing-binding-public-record-root".to_string();
        let binding_handoff_root = domain_hash(
            &format!("{DOMAIN}:invalid-binding-handoff"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&error),
            ],
            32,
        );
        let verdict = FixtureVerdict {
            fixture_count: 0,
            release_hold_count: 0,
            wallet_notice_count: 0,
            privacy_boundary_count: 0,
            binding_handoff_present: 1,
            all_mutations_change_feed_root: 0,
            release_allowed: 0,
            verdict: "adversarial_mismatch_fixtures_invalid_hold_release".to_string(),
            verdict_root: domain_hash(
                &format!("{DOMAIN}:invalid-verdict"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&error),
                ],
                32,
            ),
        };
        let release_hold_root = domain_hash(
            &format!("{DOMAIN}:invalid-release-hold"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&binding_handoff_root),
                HashPart::Str(&verdict.verdict_root),
            ],
            32,
        );
        Self {
            config,
            binding_state_root,
            binding_public_record_root,
            binding_handoff_root,
            fixtures: Vec::new(),
            verdict,
            fixture_root: merkle_root(&format!("{DOMAIN}:fixtures"), &[]),
            mismatch_digest_root: merkle_root(&format!("{DOMAIN}:mismatch-digests"), &[]),
            wallet_action_root: merkle_root(&format!("{DOMAIN}:wallet-actions"), &[]),
            privacy_boundary_root: merkle_root(&format!("{DOMAIN}:privacy-boundaries"), &[]),
            release_hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "binding_state_root": self.binding_state_root,
            "binding_public_record_root": self.binding_public_record_root,
            "binding_handoff_root": self.binding_handoff_root,
            "fixture_root": self.fixture_root,
            "mismatch_digest_root": self.mismatch_digest_root,
            "wallet_action_root": self.wallet_action_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "release_hold_root": self.release_hold_root,
            "verdict": self.verdict.public_record(),
            "fixtures": self
                .fixtures
                .iter()
                .map(MismatchFixture::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "binding_state_root": self.binding_state_root,
                "binding_public_record_root": self.binding_public_record_root,
                "binding_handoff_root": self.binding_handoff_root,
                "fixture_root": self.fixture_root,
                "mismatch_digest_root": self.mismatch_digest_root,
                "wallet_action_root": self.wallet_action_root,
                "privacy_boundary_root": self.privacy_boundary_root,
                "release_hold_root": self.release_hold_root,
                "verdict_root": self.verdict.verdict_root,
            }),
        )
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

fn process_feed_root_for(scenario: MismatchScenario) -> String {
    match scenario {
        MismatchScenario::MoneroReorg => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_monero_watcher_process_feed_runtime::state_root()
        }
        MismatchScenario::WatcherCollusion => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime::state_root()
        }
        MismatchScenario::StalePqEpoch => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime::state_root()
        }
        MismatchScenario::LiquidityShortfall => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_reserve_process_feed_runtime::state_root()
        }
        MismatchScenario::ForgedReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime::state_root()
        }
        MismatchScenario::WalletMismatch | MismatchScenario::MetadataLeak => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime::state_root()
        }
    }
}

fn reconciliation_root_for(scenario: MismatchScenario) -> String {
    match scenario {
        MismatchScenario::MoneroReorg => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_deposit_lock_runtime_output_reconciliation_runtime::state_root()
        }
        MismatchScenario::WatcherCollusion => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_gap_runtime_output_reconciliation_runtime::state_root()
        }
        MismatchScenario::StalePqEpoch => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_runtime_output_reconciliation_runtime::state_root()
        }
        MismatchScenario::LiquidityShortfall => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_runtime_output_reconciliation_manifest_runtime::state_root()
        }
        MismatchScenario::ForgedReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_runtime_output_reconciliation_runtime::state_root()
        }
        MismatchScenario::WalletMismatch => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_runtime_output_reconciliation_runtime::state_root()
        }
        MismatchScenario::MetadataLeak => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_runtime_output_reconciliation_runtime::state_root()
        }
    }
}

fn mutated_process_feed_root(
    scenario: MismatchScenario,
    ordinal: u64,
    binding_state_root: &str,
    original_process_feed_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:mutated-process-feed-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(scenario.as_str()),
            HashPart::U64(ordinal),
            HashPart::Str(binding_state_root),
            HashPart::Str(original_process_feed_root),
            HashPart::Str(scenario.fault_kind()),
        ],
        32,
    )
}

fn non_empty_flag(value: &str) -> u64 {
    if value.is_empty() {
        0
    } else {
        1
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
