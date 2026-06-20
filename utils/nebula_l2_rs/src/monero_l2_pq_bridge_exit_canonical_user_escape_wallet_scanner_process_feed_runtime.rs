use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeWalletScannerProcessFeedRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_SCANNER_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-wallet-scanner-process-feed-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_SCANNER_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROCESS_FEED_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-wallet-scanner-process-feed-v1";
pub const DEVNET_SCENARIO_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-wallet-scanner-process-feed-devnet";
pub const DEFAULT_MAX_SCAN_BATCH_SIZE: u64 = 64;
pub const DEFAULT_VIEW_KEY_BUDGET_UNITS: u64 = 96;
pub const DEFAULT_MAX_METADATA_LEAK_UNITS: u64 = 8;
pub const DEFAULT_NULLIFIER_FENCE_DEPTH: u64 = 12;
pub const DEFAULT_MIN_OWNED_OUTPUTS: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedVerdict {
    Accepted,
    Quarantined,
    Blocked,
}

impl FeedVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Quarantined => "quarantined",
            Self::Blocked => "blocked",
        }
    }

    pub fn wallet_visible(self) -> bool {
        matches!(self, Self::Accepted | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakBlockerKind {
    TimingBucket,
    AmountBucket,
    ProcessSource,
    ViewTagHint,
    OutputOrdering,
}

impl LeakBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TimingBucket => "timing_bucket",
            Self::AmountBucket => "amount_bucket",
            Self::ProcessSource => "process_source",
            Self::ViewTagHint => "view_tag_hint",
            Self::OutputOrdering => "output_ordering",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub process_feed_suite: String,
    pub scenario_id: String,
    pub max_scan_batch_size: u64,
    pub view_key_budget_units: u64,
    pub max_metadata_leak_units: u64,
    pub nullifier_fence_depth: u64,
    pub min_owned_outputs: u64,
    pub metadata_leak_blockers_required: bool,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            process_feed_suite: PROCESS_FEED_SUITE.to_string(),
            scenario_id: DEVNET_SCENARIO_ID.to_string(),
            max_scan_batch_size: DEFAULT_MAX_SCAN_BATCH_SIZE,
            view_key_budget_units: DEFAULT_VIEW_KEY_BUDGET_UNITS,
            max_metadata_leak_units: DEFAULT_MAX_METADATA_LEAK_UNITS,
            nullifier_fence_depth: DEFAULT_NULLIFIER_FENCE_DEPTH,
            min_owned_outputs: DEFAULT_MIN_OWNED_OUTPUTS,
            metadata_leak_blockers_required: true,
            fail_closed: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "process_feed_suite": self.process_feed_suite,
            "scenario_id": self.scenario_id,
            "max_scan_batch_size": self.max_scan_batch_size,
            "view_key_budget_units": self.view_key_budget_units,
            "max_metadata_leak_units": self.max_metadata_leak_units,
            "nullifier_fence_depth": self.nullifier_fence_depth,
            "min_owned_outputs": self.min_owned_outputs,
            "metadata_leak_blockers_required": self.metadata_leak_blockers_required,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedNoteScanBatch {
    pub batch_id: String,
    pub process_feed_id: String,
    pub scanner_epoch: u64,
    pub l2_height: u64,
    pub encrypted_note_count: u64,
    pub scan_ciphertext_root: String,
    pub view_tag_commitment_root: String,
    pub decoy_set_root: String,
    pub batch_root: String,
}

impl EncryptedNoteScanBatch {
    pub fn devnet(config: &Config, ordinal: u64) -> Self {
        let scanner_epoch = 42 + ordinal;
        let l2_height = 1_730_000 + ordinal * 9;
        let encrypted_note_count = 16 + ordinal * 8;
        let process_feed_id = process_feed_id(&config.scenario_id, ordinal);
        let scan_ciphertext_root = deterministic_leaf_root("scan-ciphertext", ordinal, 5);
        let view_tag_commitment_root = deterministic_leaf_root("view-tag", ordinal, 5);
        let decoy_set_root = deterministic_leaf_root("decoy-set", ordinal, 7);
        let batch_id = batch_id(&config.scenario_id, &process_feed_id, scanner_epoch);
        let batch_root = record_root(
            "encrypted-note-scan-batch",
            &json!({
                "batch_id": batch_id,
                "process_feed_id": process_feed_id,
                "scanner_epoch": scanner_epoch,
                "l2_height": l2_height,
                "encrypted_note_count": encrypted_note_count,
                "scan_ciphertext_root": scan_ciphertext_root,
                "view_tag_commitment_root": view_tag_commitment_root,
                "decoy_set_root": decoy_set_root,
            }),
        );
        Self {
            batch_id,
            process_feed_id,
            scanner_epoch,
            l2_height,
            encrypted_note_count,
            scan_ciphertext_root,
            view_tag_commitment_root,
            decoy_set_root,
            batch_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "process_feed_id": self.process_feed_id,
            "scanner_epoch": self.scanner_epoch,
            "l2_height": self.l2_height,
            "encrypted_note_count": self.encrypted_note_count,
            "scan_ciphertext_root": self.scan_ciphertext_root,
            "view_tag_commitment_root": self.view_tag_commitment_root,
            "decoy_set_root": self.decoy_set_root,
            "batch_root": self.batch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OwnedOutputDiscovery {
    pub discovery_id: String,
    pub batch_id: String,
    pub wallet_account_commitment: String,
    pub owned_output_count: u64,
    pub owned_output_root: String,
    pub note_commitment_root: String,
    pub escape_claim_root: String,
    pub discovery_root: String,
}

impl OwnedOutputDiscovery {
    pub fn devnet(config: &Config, batch: &EncryptedNoteScanBatch, ordinal: u64) -> Self {
        let wallet_account_commitment = wallet_account_commitment(&config.scenario_id, ordinal);
        let owned_output_count = config.min_owned_outputs + ordinal;
        let owned_output_root =
            deterministic_leaf_root("owned-output", ordinal, owned_output_count);
        let note_commitment_root = deterministic_leaf_root("note-commitment", ordinal, 4);
        let escape_claim_root = deterministic_leaf_root("escape-claim", ordinal, 3);
        let discovery_id = discovery_id(&batch.batch_id, &wallet_account_commitment);
        let discovery_root = record_root(
            "owned-output-discovery",
            &json!({
                "discovery_id": discovery_id,
                "batch_id": batch.batch_id,
                "wallet_account_commitment": wallet_account_commitment,
                "owned_output_count": owned_output_count,
                "owned_output_root": owned_output_root,
                "note_commitment_root": note_commitment_root,
                "escape_claim_root": escape_claim_root,
            }),
        );
        Self {
            discovery_id,
            batch_id: batch.batch_id.clone(),
            wallet_account_commitment,
            owned_output_count,
            owned_output_root,
            note_commitment_root,
            escape_claim_root,
            discovery_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "discovery_id": self.discovery_id,
            "batch_id": self.batch_id,
            "wallet_account_commitment": self.wallet_account_commitment,
            "owned_output_count": self.owned_output_count,
            "owned_output_root": self.owned_output_root,
            "note_commitment_root": self.note_commitment_root,
            "escape_claim_root": self.escape_claim_root,
            "discovery_root": self.discovery_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub discovery_id: String,
    pub nullifier_set_root: String,
    pub key_image_commitment_root: String,
    pub fence_depth: u64,
    pub replay_window_start_height: u64,
    pub replay_window_end_height: u64,
    pub fence_root: String,
}

impl NullifierFence {
    pub fn devnet(
        config: &Config,
        discovery: &OwnedOutputDiscovery,
        batch: &EncryptedNoteScanBatch,
        ordinal: u64,
    ) -> Self {
        let nullifier_set_root = deterministic_leaf_root("nullifier-set", ordinal, 6);
        let key_image_commitment_root = deterministic_leaf_root("key-image-commitment", ordinal, 6);
        let replay_window_start_height = batch.l2_height;
        let replay_window_end_height = batch.l2_height + config.nullifier_fence_depth;
        let fence_id = fence_id(&discovery.discovery_id, replay_window_end_height);
        let fence_root = record_root(
            "nullifier-fence",
            &json!({
                "fence_id": fence_id,
                "discovery_id": discovery.discovery_id,
                "nullifier_set_root": nullifier_set_root,
                "key_image_commitment_root": key_image_commitment_root,
                "fence_depth": config.nullifier_fence_depth,
                "replay_window_start_height": replay_window_start_height,
                "replay_window_end_height": replay_window_end_height,
            }),
        );
        Self {
            fence_id,
            discovery_id: discovery.discovery_id.clone(),
            nullifier_set_root,
            key_image_commitment_root,
            fence_depth: config.nullifier_fence_depth,
            replay_window_start_height,
            replay_window_end_height,
            fence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "discovery_id": self.discovery_id,
            "nullifier_set_root": self.nullifier_set_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "fence_depth": self.fence_depth,
            "replay_window_start_height": self.replay_window_start_height,
            "replay_window_end_height": self.replay_window_end_height,
            "fence_root": self.fence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewKeyPrivacyBudget {
    pub budget_id: String,
    pub batch_id: String,
    pub view_key_budget_units: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub metadata_leak_units: u64,
    pub blocker_root: String,
    pub budget_root: String,
}

impl ViewKeyPrivacyBudget {
    pub fn devnet(config: &Config, batch: &EncryptedNoteScanBatch, ordinal: u64) -> Self {
        let spent_units = 18 + ordinal * 7;
        let metadata_leak_units = 3 + ordinal;
        let remaining_units = remaining_budget(config.view_key_budget_units, spent_units);
        let blocker_root = deterministic_leaf_root("metadata-blocker", ordinal, 5);
        let budget_id = budget_id(&batch.batch_id, ordinal);
        let budget_root = record_root(
            "view-key-privacy-budget",
            &json!({
                "budget_id": budget_id,
                "batch_id": batch.batch_id,
                "view_key_budget_units": config.view_key_budget_units,
                "spent_units": spent_units,
                "remaining_units": remaining_units,
                "metadata_leak_units": metadata_leak_units,
                "blocker_root": blocker_root,
            }),
        );
        Self {
            budget_id,
            batch_id: batch.batch_id.clone(),
            view_key_budget_units: config.view_key_budget_units,
            spent_units,
            remaining_units,
            metadata_leak_units,
            blocker_root,
            budget_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "batch_id": self.batch_id,
            "view_key_budget_units": self.view_key_budget_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units,
            "metadata_leak_units": self.metadata_leak_units,
            "blocker_root": self.blocker_root,
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataLeakBlocker {
    pub blocker_id: String,
    pub kind: LeakBlockerKind,
    pub budget_id: String,
    pub leak_units_blocked: u64,
    pub public_hint_root: String,
    pub private_hint_redaction_root: String,
    pub blocker_root: String,
}

impl MetadataLeakBlocker {
    pub fn devnet(budget: &ViewKeyPrivacyBudget, kind: LeakBlockerKind, ordinal: u64) -> Self {
        let leak_units_blocked = 2 + ordinal;
        let public_hint_root = deterministic_leaf_root(kind.as_str(), ordinal, 2);
        let private_hint_redaction_root = deterministic_leaf_root("private-redaction", ordinal, 3);
        let blocker_id = blocker_id(&budget.budget_id, kind, ordinal);
        let blocker_root = record_root(
            "metadata-leak-blocker",
            &json!({
                "blocker_id": blocker_id,
                "kind": kind.as_str(),
                "budget_id": budget.budget_id,
                "leak_units_blocked": leak_units_blocked,
                "public_hint_root": public_hint_root,
                "private_hint_redaction_root": private_hint_redaction_root,
            }),
        );
        Self {
            blocker_id,
            kind,
            budget_id: budget.budget_id.clone(),
            leak_units_blocked,
            public_hint_root,
            private_hint_redaction_root,
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "budget_id": self.budget_id,
            "leak_units_blocked": self.leak_units_blocked,
            "public_hint_root": self.public_hint_root,
            "private_hint_redaction_root": self.private_hint_redaction_root,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EscapeEvidence {
    pub evidence_id: String,
    pub discovery_id: String,
    pub fence_id: String,
    pub wallet_visible: bool,
    pub evidence_height: u64,
    pub owned_output_root: String,
    pub nullifier_fence_root: String,
    pub process_feed_observation_root: String,
    pub verdict: FeedVerdict,
    pub evidence_root: String,
}

impl EscapeEvidence {
    pub fn devnet(
        config: &Config,
        discovery: &OwnedOutputDiscovery,
        fence: &NullifierFence,
        budget: &ViewKeyPrivacyBudget,
        batch: &EncryptedNoteScanBatch,
        ordinal: u64,
    ) -> Self {
        let verdict = classify_feed(config, discovery, budget, batch);
        let wallet_visible = verdict.wallet_visible();
        let evidence_height = fence.replay_window_end_height + 1;
        let process_feed_observation_root = record_root(
            "process-feed-observation",
            &json!({
                "batch_root": batch.batch_root,
                "discovery_root": discovery.discovery_root,
                "budget_root": budget.budget_root,
            }),
        );
        let evidence_id = evidence_id(&discovery.discovery_id, &fence.fence_id, ordinal);
        let evidence_root = record_root(
            "wallet-visible-escape-evidence",
            &json!({
                "evidence_id": evidence_id,
                "discovery_id": discovery.discovery_id,
                "fence_id": fence.fence_id,
                "wallet_visible": wallet_visible,
                "evidence_height": evidence_height,
                "owned_output_root": discovery.owned_output_root,
                "nullifier_fence_root": fence.fence_root,
                "process_feed_observation_root": process_feed_observation_root,
                "verdict": verdict.as_str(),
            }),
        );
        Self {
            evidence_id,
            discovery_id: discovery.discovery_id.clone(),
            fence_id: fence.fence_id.clone(),
            wallet_visible,
            evidence_height,
            owned_output_root: discovery.owned_output_root.clone(),
            nullifier_fence_root: fence.fence_root.clone(),
            process_feed_observation_root,
            verdict,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "discovery_id": self.discovery_id,
            "fence_id": self.fence_id,
            "wallet_visible": self.wallet_visible,
            "evidence_height": self.evidence_height,
            "owned_output_root": self.owned_output_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "process_feed_observation_root": self.process_feed_observation_root,
            "verdict": self.verdict.as_str(),
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub scan_batches: Vec<EncryptedNoteScanBatch>,
    pub owned_output_discoveries: Vec<OwnedOutputDiscovery>,
    pub nullifier_fences: Vec<NullifierFence>,
    pub view_key_privacy_budgets: Vec<ViewKeyPrivacyBudget>,
    pub metadata_leak_blockers: Vec<MetadataLeakBlocker>,
    pub wallet_visible_escape_evidence: Vec<EscapeEvidence>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let scan_batches = (0..3)
            .map(|ordinal| EncryptedNoteScanBatch::devnet(&config, ordinal))
            .collect::<Vec<_>>();
        let owned_output_discoveries = scan_batches
            .iter()
            .enumerate()
            .map(|(index, batch)| OwnedOutputDiscovery::devnet(&config, batch, index as u64))
            .collect::<Vec<_>>();
        let nullifier_fences = owned_output_discoveries
            .iter()
            .zip(scan_batches.iter())
            .enumerate()
            .map(|(index, (discovery, batch))| {
                NullifierFence::devnet(&config, discovery, batch, index as u64)
            })
            .collect::<Vec<_>>();
        let view_key_privacy_budgets = scan_batches
            .iter()
            .enumerate()
            .map(|(index, batch)| ViewKeyPrivacyBudget::devnet(&config, batch, index as u64))
            .collect::<Vec<_>>();
        let metadata_leak_blockers = view_key_privacy_budgets
            .iter()
            .enumerate()
            .flat_map(|(index, budget)| {
                blocker_kinds()
                    .into_iter()
                    .map(move |kind| MetadataLeakBlocker::devnet(budget, kind, index as u64))
            })
            .collect::<Vec<_>>();
        let wallet_visible_escape_evidence = owned_output_discoveries
            .iter()
            .zip(nullifier_fences.iter())
            .zip(view_key_privacy_budgets.iter())
            .zip(scan_batches.iter())
            .enumerate()
            .map(|(index, (((discovery, fence), budget), batch))| {
                EscapeEvidence::devnet(&config, discovery, fence, budget, batch, index as u64)
            })
            .collect::<Vec<_>>();
        Self {
            config,
            scan_batches,
            owned_output_discoveries,
            nullifier_fences,
            view_key_privacy_budgets,
            metadata_leak_blockers,
            wallet_visible_escape_evidence,
        }
    }

    pub fn roots(&self) -> Value {
        json!({
            "config_root": self.config.state_root(),
            "scan_batch_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-SCAN-BATCHES",
                &records(&self.scan_batches),
            ),
            "owned_output_discovery_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-OWNED-OUTPUTS",
                &records(&self.owned_output_discoveries),
            ),
            "nullifier_fence_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-NULLIFIER-FENCES",
                &records(&self.nullifier_fences),
            ),
            "view_key_privacy_budget_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-VIEW-KEY-BUDGETS",
                &records(&self.view_key_privacy_budgets),
            ),
            "metadata_leak_blocker_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-METADATA-BLOCKERS",
                &records(&self.metadata_leak_blockers),
            ),
            "wallet_visible_escape_evidence_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-ESCAPE-EVIDENCE",
                &records(&self.wallet_visible_escape_evidence),
            ),
        })
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "config": self.config.public_record(),
            "scan_batches": records(&self.scan_batches),
            "owned_output_discoveries": records(&self.owned_output_discoveries),
            "nullifier_fences": records(&self.nullifier_fences),
            "view_key_privacy_budgets": records(&self.view_key_privacy_budgets),
            "metadata_leak_blockers": records(&self.metadata_leak_blockers),
            "wallet_visible_escape_evidence": records(&self.wallet_visible_escape_evidence),
            "roots": roots,
            "state_root": self.state_root_from_roots(&roots),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root_from_roots(&self.roots())
    }

    fn state_root_from_roots(&self, roots: &Value) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-PROCESS-FEED-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.scenario_id),
                HashPart::Json(roots),
            ],
            32,
        )
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for EncryptedNoteScanBatch {
    fn public_record(&self) -> Value {
        EncryptedNoteScanBatch::public_record(self)
    }
}

impl PublicRecord for OwnedOutputDiscovery {
    fn public_record(&self) -> Value {
        OwnedOutputDiscovery::public_record(self)
    }
}

impl PublicRecord for NullifierFence {
    fn public_record(&self) -> Value {
        NullifierFence::public_record(self)
    }
}

impl PublicRecord for ViewKeyPrivacyBudget {
    fn public_record(&self) -> Value {
        ViewKeyPrivacyBudget::public_record(self)
    }
}

impl PublicRecord for MetadataLeakBlocker {
    fn public_record(&self) -> Value {
        MetadataLeakBlocker::public_record(self)
    }
}

impl PublicRecord for EscapeEvidence {
    fn public_record(&self) -> Value {
        EscapeEvidence::public_record(self)
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

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-PROCESS-FEED-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn records<T: PublicRecord>(items: &[T]) -> Vec<Value> {
    items.iter().map(PublicRecord::public_record).collect()
}

fn blocker_kinds() -> Vec<LeakBlockerKind> {
    vec![
        LeakBlockerKind::TimingBucket,
        LeakBlockerKind::AmountBucket,
        LeakBlockerKind::ProcessSource,
        LeakBlockerKind::ViewTagHint,
        LeakBlockerKind::OutputOrdering,
    ]
}

fn classify_feed(
    config: &Config,
    discovery: &OwnedOutputDiscovery,
    budget: &ViewKeyPrivacyBudget,
    batch: &EncryptedNoteScanBatch,
) -> FeedVerdict {
    if batch.encrypted_note_count > config.max_scan_batch_size {
        FeedVerdict::Blocked
    } else if budget.metadata_leak_units > config.max_metadata_leak_units {
        FeedVerdict::Blocked
    } else if discovery.owned_output_count < config.min_owned_outputs {
        FeedVerdict::Quarantined
    } else if budget.remaining_units == 0 {
        FeedVerdict::Quarantined
    } else {
        FeedVerdict::Accepted
    }
}

fn remaining_budget(total_units: u64, spent_units: u64) -> u64 {
    if spent_units > total_units {
        0
    } else {
        total_units - spent_units
    }
}

fn process_feed_id(scenario_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-PROCESS-FEED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scenario_id),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn batch_id(scenario_id: &str, process_feed_id: &str, scanner_epoch: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scenario_id),
            HashPart::Str(process_feed_id),
            HashPart::U64(scanner_epoch),
        ],
        16,
    )
}

fn wallet_account_commitment(scenario_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-WALLET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scenario_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn discovery_id(batch_id: &str, wallet_account_commitment: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-DISCOVERY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(wallet_account_commitment),
        ],
        16,
    )
}

fn fence_id(discovery_id: &str, replay_window_end_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(discovery_id),
            HashPart::U64(replay_window_end_height),
        ],
        16,
    )
}

fn budget_id(batch_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn blocker_id(budget_id: &str, kind: LeakBlockerKind, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-BLOCKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(budget_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn evidence_id(discovery_id: &str, fence_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(discovery_id),
            HashPart::Str(fence_id),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn deterministic_leaf_root(label: &str, ordinal: u64, count: u64) -> String {
    let leaves = (0..count)
        .map(|index| {
            json!({
                "label": label,
                "ordinal": ordinal,
                "index": index,
                "commitment": domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-LEAF",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(label),
                        HashPart::U64(ordinal),
                        HashPart::U64(index),
                    ],
                    32,
                ),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WALLET-SCANNER-DETERMINISTIC-LEAVES",
        &leaves,
    )
}
