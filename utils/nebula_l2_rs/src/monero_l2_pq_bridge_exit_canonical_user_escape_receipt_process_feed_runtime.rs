use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReceiptProcessFeedRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RECEIPT_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-receipt-process-feed-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RECEIPT_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_ENVELOPE_SUITE: &str =
    "monero-l2-pq-canonical-user-escape-settlement-receipt-envelope-v1";
pub const TRANSCRIPT_SUITE: &str = "monero-l2-pq-canonical-user-escape-process-feed-transcript-v1";
pub const INCLUSION_WITNESS_SUITE: &str =
    "monero-l2-pq-canonical-user-escape-receipt-inclusion-witness-v1";
pub const WALLET_SUMMARY_SUITE: &str =
    "wallet-visible-roots-only-canonical-user-escape-receipt-summary-v1";
pub const RECONCILIATION_SUITE: &str = "canonical-user-escape-receipt-feed-reconciliation-root-v1";
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MAX_ENVELOPES: usize = 524_288;
pub const DEFAULT_MAX_DUPLICATE_BLOCKERS: usize = 524_288;
pub const DEFAULT_MAX_WALLET_SUMMARIES: usize = 524_288;
pub const DEFAULT_DEVNET_HEIGHT: u64 = 9_120;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLane {
    UserEscape,
    ForcedExit,
    ChallengeRelease,
    Reconciliation,
}

impl ReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserEscape => "user_escape",
            Self::ForcedExit => "forced_exit",
            Self::ChallengeRelease => "challenge_release",
            Self::Reconciliation => "reconciliation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Observed,
    Included,
    WalletVisible,
    Reconciled,
    Quarantined,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Included => "included",
            Self::WalletVisible => "wallet_visible",
            Self::Reconciled => "reconciled",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn blocks_wallet_visibility(self) -> bool {
        matches!(self, Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayBlockerStatus {
    Accepted,
    DuplicateEnvelope,
    DuplicateNullifier,
    DuplicateWitness,
    StaleTranscript,
}

impl ReplayBlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::DuplicateEnvelope => "duplicate_envelope",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::DuplicateWitness => "duplicate_witness",
            Self::StaleTranscript => "stale_transcript",
        }
    }

    pub fn accepts(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_envelope_suite: String,
    pub transcript_suite: String,
    pub inclusion_witness_suite: String,
    pub wallet_summary_suite: String,
    pub reconciliation_suite: String,
    pub min_confirmations: u64,
    pub max_envelopes: usize,
    pub max_duplicate_blockers: usize,
    pub max_wallet_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_envelope_suite: RECEIPT_ENVELOPE_SUITE.to_string(),
            transcript_suite: TRANSCRIPT_SUITE.to_string(),
            inclusion_witness_suite: INCLUSION_WITNESS_SUITE.to_string(),
            wallet_summary_suite: WALLET_SUMMARY_SUITE.to_string(),
            reconciliation_suite: RECONCILIATION_SUITE.to_string(),
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            max_envelopes: DEFAULT_MAX_ENVELOPES,
            max_duplicate_blockers: DEFAULT_MAX_DUPLICATE_BLOCKERS,
            max_wallet_summaries: DEFAULT_MAX_WALLET_SUMMARIES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_envelope_suite": self.receipt_envelope_suite,
            "transcript_suite": self.transcript_suite,
            "inclusion_witness_suite": self.inclusion_witness_suite,
            "wallet_summary_suite": self.wallet_summary_suite,
            "reconciliation_suite": self.reconciliation_suite,
            "min_confirmations": self.min_confirmations,
            "max_envelopes": self.max_envelopes,
            "max_duplicate_blockers": self.max_duplicate_blockers,
            "max_wallet_summaries": self.max_wallet_summaries
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptEnvelopeObservation {
    pub envelope_id: String,
    pub lane: ReceiptLane,
    pub status: ReceiptStatus,
    pub exit_request_id: String,
    pub settlement_receipt_root: String,
    pub transcript_root: String,
    pub inclusion_witness_root: String,
    pub wallet_summary_id: String,
    pub replay_key: String,
    pub observed_at_height: u64,
    pub confirmed_at_height: u64,
}

impl ReceiptEnvelopeObservation {
    pub fn new(
        envelope_id: impl Into<String>,
        lane: ReceiptLane,
        status: ReceiptStatus,
        exit_request_id: impl Into<String>,
        observed_at_height: u64,
        confirmed_at_height: u64,
    ) -> Self {
        let envelope_id = envelope_id.into();
        let exit_request_id = exit_request_id.into();
        Self {
            settlement_receipt_root: record_root("settlement-receipt", &envelope_id),
            transcript_root: record_root("transcript", &envelope_id),
            inclusion_witness_root: record_root("inclusion-witness", &envelope_id),
            wallet_summary_id: stable_id("wallet-summary", &envelope_id),
            replay_key: stable_id("receipt-replay", &envelope_id),
            envelope_id,
            lane,
            status,
            exit_request_id,
            observed_at_height,
            confirmed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "exit_request_id": self.exit_request_id,
            "settlement_receipt_root": self.settlement_receipt_root,
            "transcript_root": self.transcript_root,
            "inclusion_witness_root": self.inclusion_witness_root,
            "wallet_summary_id": self.wallet_summary_id,
            "replay_key": self.replay_key,
            "observed_at_height": self.observed_at_height,
            "confirmed_at_height": self.confirmed_at_height,
            "wallet_visibility_blocked": self.status.blocks_wallet_visibility()
        })
    }

    pub fn record_root(&self) -> String {
        receipt_feed_hash(
            "RECEIPT-ENVELOPE-OBSERVATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TranscriptObservation {
    pub transcript_id: String,
    pub envelope_id: String,
    pub action_count: u64,
    pub transcript_root: String,
    pub event_root: String,
    pub operator_attestation_root: String,
    pub observed_at_height: u64,
}

impl TranscriptObservation {
    pub fn new(
        transcript_id: impl Into<String>,
        envelope_id: impl Into<String>,
        action_count: u64,
        observed_at_height: u64,
    ) -> Self {
        let transcript_id = transcript_id.into();
        let envelope_id = envelope_id.into();
        Self {
            transcript_root: record_root("transcript-root", &transcript_id),
            event_root: record_root("transcript-events", &transcript_id),
            operator_attestation_root: record_root("operator-attestation", &transcript_id),
            transcript_id,
            envelope_id,
            action_count,
            observed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "transcript_id": self.transcript_id,
            "envelope_id": self.envelope_id,
            "action_count": self.action_count,
            "transcript_root": self.transcript_root,
            "event_root": self.event_root,
            "operator_attestation_root": self.operator_attestation_root,
            "observed_at_height": self.observed_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InclusionWitnessObservation {
    pub witness_id: String,
    pub envelope_id: String,
    pub receipt_tree_root: String,
    pub sibling_path_root: String,
    pub leaf_index: u64,
    pub anchor_height: u64,
    pub finality_confirmations: u64,
}

impl InclusionWitnessObservation {
    pub fn new(
        witness_id: impl Into<String>,
        envelope_id: impl Into<String>,
        leaf_index: u64,
        anchor_height: u64,
        finality_confirmations: u64,
    ) -> Self {
        let witness_id = witness_id.into();
        Self {
            receipt_tree_root: record_root("receipt-tree", &witness_id),
            sibling_path_root: record_root("receipt-sibling-path", &witness_id),
            witness_id,
            envelope_id: envelope_id.into(),
            leaf_index,
            anchor_height,
            finality_confirmations,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "witness_id": self.witness_id,
            "envelope_id": self.envelope_id,
            "receipt_tree_root": self.receipt_tree_root,
            "sibling_path_root": self.sibling_path_root,
            "leaf_index": self.leaf_index,
            "anchor_height": self.anchor_height,
            "finality_confirmations": self.finality_confirmations
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletVisibleReceiptSummary {
    pub summary_id: String,
    pub wallet_view_tag_root: String,
    pub envelope_id: String,
    pub exit_request_id: String,
    pub claim_amount_bucket_piconero: u64,
    pub recipient_commitment_root: String,
    pub settlement_status: ReceiptStatus,
    pub visible_at_height: u64,
}

impl WalletVisibleReceiptSummary {
    pub fn new(
        summary_id: impl Into<String>,
        envelope_id: impl Into<String>,
        exit_request_id: impl Into<String>,
        claim_amount_bucket_piconero: u64,
        settlement_status: ReceiptStatus,
        visible_at_height: u64,
    ) -> Self {
        let summary_id = summary_id.into();
        Self {
            wallet_view_tag_root: record_root("wallet-view-tag", &summary_id),
            recipient_commitment_root: record_root("wallet-recipient", &summary_id),
            summary_id,
            envelope_id: envelope_id.into(),
            exit_request_id: exit_request_id.into(),
            claim_amount_bucket_piconero,
            settlement_status,
            visible_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "summary_id": self.summary_id,
            "wallet_view_tag_root": self.wallet_view_tag_root,
            "envelope_id": self.envelope_id,
            "exit_request_id": self.exit_request_id,
            "claim_amount_bucket_piconero": self.claim_amount_bucket_piconero,
            "recipient_commitment_root": self.recipient_commitment_root,
            "settlement_status": self.settlement_status.as_str(),
            "visible_at_height": self.visible_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DuplicateReplayBlocker {
    pub blocker_id: String,
    pub envelope_id: String,
    pub replay_key: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub status: ReplayBlockerStatus,
    pub observed_at_height: u64,
}

impl DuplicateReplayBlocker {
    pub fn accepted(envelope: &ReceiptEnvelopeObservation) -> Self {
        Self {
            blocker_id: stable_id("duplicate-replay-blocker", &envelope.envelope_id),
            envelope_id: envelope.envelope_id.clone(),
            replay_key: envelope.replay_key.clone(),
            nullifier_root: record_root("nullifier", &envelope.envelope_id),
            witness_root: envelope.inclusion_witness_root.clone(),
            status: ReplayBlockerStatus::Accepted,
            observed_at_height: envelope.observed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "blocker_id": self.blocker_id,
            "envelope_id": self.envelope_id,
            "replay_key": self.replay_key,
            "nullifier_root": self.nullifier_root,
            "witness_root": self.witness_root,
            "status": self.status.as_str(),
            "accepted": self.status.accepts(),
            "observed_at_height": self.observed_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReconciliationSnapshot {
    pub reconciliation_id: String,
    pub envelope_root: String,
    pub transcript_root: String,
    pub inclusion_witness_root: String,
    pub wallet_summary_root: String,
    pub duplicate_blocker_root: String,
    pub reconciled_envelopes: u64,
    pub quarantined_envelopes: u64,
    pub emitted_at_height: u64,
}

impl ReconciliationSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reconciliation_id": self.reconciliation_id,
            "envelope_root": self.envelope_root,
            "transcript_root": self.transcript_root,
            "inclusion_witness_root": self.inclusion_witness_root,
            "wallet_summary_root": self.wallet_summary_root,
            "duplicate_blocker_root": self.duplicate_blocker_root,
            "reconciled_envelopes": self.reconciled_envelopes,
            "quarantined_envelopes": self.quarantined_envelopes,
            "emitted_at_height": self.emitted_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeedRoots {
    pub envelope_root: String,
    pub transcript_root: String,
    pub inclusion_witness_root: String,
    pub wallet_summary_root: String,
    pub duplicate_blocker_root: String,
    pub replay_key_root: String,
    pub reconciliation_root: String,
}

impl FeedRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_root": self.envelope_root,
            "transcript_root": self.transcript_root,
            "inclusion_witness_root": self.inclusion_witness_root,
            "wallet_summary_root": self.wallet_summary_root,
            "duplicate_blocker_root": self.duplicate_blocker_root,
            "replay_key_root": self.replay_key_root,
            "reconciliation_root": self.reconciliation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeedCounters {
    pub envelopes: usize,
    pub transcripts: usize,
    pub inclusion_witnesses: usize,
    pub wallet_summaries: usize,
    pub duplicate_blockers: usize,
    pub replay_keys: usize,
    pub reconciliations: usize,
    pub quarantined_envelopes: usize,
}

impl FeedCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "envelopes": self.envelopes,
            "transcripts": self.transcripts,
            "inclusion_witnesses": self.inclusion_witnesses,
            "wallet_summaries": self.wallet_summaries,
            "duplicate_blockers": self.duplicate_blockers,
            "replay_keys": self.replay_keys,
            "reconciliations": self.reconciliations,
            "quarantined_envelopes": self.quarantined_envelopes
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub envelopes: BTreeMap<String, ReceiptEnvelopeObservation>,
    pub transcripts: BTreeMap<String, TranscriptObservation>,
    pub inclusion_witnesses: BTreeMap<String, InclusionWitnessObservation>,
    pub wallet_summaries: BTreeMap<String, WalletVisibleReceiptSummary>,
    pub duplicate_blockers: BTreeMap<String, DuplicateReplayBlocker>,
    pub replay_keys: BTreeSet<String>,
    pub reconciliation_snapshots: BTreeMap<String, ReconciliationSnapshot>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        Self {
            config,
            height,
            envelopes: BTreeMap::new(),
            transcripts: BTreeMap::new(),
            inclusion_witnesses: BTreeMap::new(),
            wallet_summaries: BTreeMap::new(),
            duplicate_blockers: BTreeMap::new(),
            replay_keys: BTreeSet::new(),
            reconciliation_snapshots: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEFAULT_DEVNET_HEIGHT);
        state.seed_devnet();
        state
    }

    pub fn observe_envelope(
        &mut self,
        envelope: ReceiptEnvelopeObservation,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeReceiptProcessFeedRuntimeResult<String> {
        if self.envelopes.len() >= self.config.max_envelopes {
            return Err("receipt envelope capacity exhausted".to_string());
        }
        if self.envelopes.contains_key(&envelope.envelope_id) {
            return Err(format!("duplicate envelope {}", envelope.envelope_id));
        }
        if self.replay_keys.contains(&envelope.replay_key) {
            return Err(format!("duplicate replay key {}", envelope.replay_key));
        }
        if envelope.confirmed_at_height < envelope.observed_at_height {
            return Err("receipt confirmation height precedes observation height".to_string());
        }
        let confirmations = envelope.confirmed_at_height - envelope.observed_at_height;
        if confirmations < self.config.min_confirmations {
            return Err(format!(
                "receipt envelope {} has insufficient confirmations",
                envelope.envelope_id
            ));
        }

        let record_root = envelope.record_root();
        self.replay_keys.insert(envelope.replay_key.clone());
        self.duplicate_blockers.insert(
            stable_id("duplicate-replay-blocker", &envelope.envelope_id),
            DuplicateReplayBlocker::accepted(&envelope),
        );
        self.envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        Ok(record_root)
    }

    pub fn observe_transcript(
        &mut self,
        transcript: TranscriptObservation,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeReceiptProcessFeedRuntimeResult<String> {
        require_known_envelope(&self.envelopes, &transcript.envelope_id)?;
        if self.transcripts.contains_key(&transcript.transcript_id) {
            return Err(format!("duplicate transcript {}", transcript.transcript_id));
        }
        let root = receipt_feed_hash(
            "TRANSCRIPT-OBSERVATION",
            &[HashPart::Json(&transcript.public_record())],
        );
        self.transcripts
            .insert(transcript.transcript_id.clone(), transcript);
        Ok(root)
    }

    pub fn observe_inclusion_witness(
        &mut self,
        witness: InclusionWitnessObservation,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeReceiptProcessFeedRuntimeResult<String> {
        require_known_envelope(&self.envelopes, &witness.envelope_id)?;
        if self.inclusion_witnesses.contains_key(&witness.witness_id) {
            return Err(format!(
                "duplicate inclusion witness {}",
                witness.witness_id
            ));
        }
        let root = receipt_feed_hash(
            "INCLUSION-WITNESS-OBSERVATION",
            &[HashPart::Json(&witness.public_record())],
        );
        self.inclusion_witnesses
            .insert(witness.witness_id.clone(), witness);
        Ok(root)
    }

    pub fn publish_wallet_summary(
        &mut self,
        summary: WalletVisibleReceiptSummary,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeReceiptProcessFeedRuntimeResult<String> {
        require_known_envelope(&self.envelopes, &summary.envelope_id)?;
        if self.wallet_summaries.len() >= self.config.max_wallet_summaries {
            return Err("wallet summary capacity exhausted".to_string());
        }
        if self.wallet_summaries.contains_key(&summary.summary_id) {
            return Err(format!("duplicate wallet summary {}", summary.summary_id));
        }
        let root = receipt_feed_hash(
            "WALLET-VISIBLE-RECEIPT-SUMMARY",
            &[HashPart::Json(&summary.public_record())],
        );
        self.wallet_summaries
            .insert(summary.summary_id.clone(), summary);
        Ok(root)
    }

    pub fn reconcile(
        &mut self,
        reconciliation_id: impl Into<String>,
    ) -> MoneroL2PqBridgeExitCanonicalUserEscapeReceiptProcessFeedRuntimeResult<String> {
        let reconciliation_id = reconciliation_id.into();
        if self
            .reconciliation_snapshots
            .contains_key(&reconciliation_id)
        {
            return Err(format!("duplicate reconciliation {}", reconciliation_id));
        }
        let roots = self.roots();
        let snapshot = ReconciliationSnapshot {
            reconciliation_id: reconciliation_id.clone(),
            envelope_root: roots.envelope_root,
            transcript_root: roots.transcript_root,
            inclusion_witness_root: roots.inclusion_witness_root,
            wallet_summary_root: roots.wallet_summary_root,
            duplicate_blocker_root: roots.duplicate_blocker_root,
            reconciled_envelopes: self.reconciled_envelope_count(),
            quarantined_envelopes: self.quarantined_envelope_count() as u64,
            emitted_at_height: self.height,
        };
        let root = receipt_feed_hash(
            "RECONCILIATION-SNAPSHOT",
            &[HashPart::Json(&snapshot.public_record())],
        );
        self.reconciliation_snapshots
            .insert(reconciliation_id, snapshot);
        Ok(root)
    }

    pub fn roots(&self) -> FeedRoots {
        FeedRoots {
            envelope_root: map_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-FEED-ENVELOPES",
                self.envelopes
                    .values()
                    .map(ReceiptEnvelopeObservation::public_record),
            ),
            transcript_root: map_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-FEED-TRANSCRIPTS",
                self.transcripts
                    .values()
                    .map(TranscriptObservation::public_record),
            ),
            inclusion_witness_root: map_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-FEED-INCLUSION-WITNESSES",
                self.inclusion_witnesses
                    .values()
                    .map(InclusionWitnessObservation::public_record),
            ),
            wallet_summary_root: map_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-FEED-WALLET-SUMMARIES",
                self.wallet_summaries
                    .values()
                    .map(WalletVisibleReceiptSummary::public_record),
            ),
            duplicate_blocker_root: map_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-FEED-DUPLICATE-BLOCKERS",
                self.duplicate_blockers
                    .values()
                    .map(DuplicateReplayBlocker::public_record),
            ),
            replay_key_root: map_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-FEED-REPLAY-KEYS",
                self.replay_keys
                    .iter()
                    .map(|replay_key| json!({ "replay_key": replay_key })),
            ),
            reconciliation_root: map_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-FEED-RECONCILIATIONS",
                self.reconciliation_snapshots
                    .values()
                    .map(ReconciliationSnapshot::public_record),
            ),
        }
    }

    pub fn counters(&self) -> FeedCounters {
        FeedCounters {
            envelopes: self.envelopes.len(),
            transcripts: self.transcripts.len(),
            inclusion_witnesses: self.inclusion_witnesses.len(),
            wallet_summaries: self.wallet_summaries.len(),
            duplicate_blockers: self.duplicate_blockers.len(),
            replay_keys: self.replay_keys.len(),
            reconciliations: self.reconciliation_snapshots.len(),
            quarantined_envelopes: self.quarantined_envelope_count(),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        receipt_feed_hash(
            "STATE",
            &[
                HashPart::Str(&self.height.to_string()),
                HashPart::Json(&roots.public_record()),
                HashPart::Json(&counters.public_record()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "state_root": self.state_root(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "privacy": {
                "receipt_envelopes_are_commitment_only": true,
                "wallet_summaries_are_roots_only": true,
                "recipient_commitments_are_not_plain_addresses": true,
                "transcripts_are_rooted_without_plaintext_actions": true,
                "duplicate_blockers_publish_replay_keys_only": true
            }
        })
    }

    fn seed_devnet(&mut self) {
        let first = ReceiptEnvelopeObservation::new(
            "devnet-escape-receipt-envelope-0001",
            ReceiptLane::UserEscape,
            ReceiptStatus::WalletVisible,
            "devnet-user-escape-exit-0001",
            self.height - 64,
            self.height - 40,
        );
        let second = ReceiptEnvelopeObservation::new(
            "devnet-escape-receipt-envelope-0002",
            ReceiptLane::ForcedExit,
            ReceiptStatus::Reconciled,
            "devnet-user-escape-exit-0002",
            self.height - 58,
            self.height - 32,
        );
        let third = ReceiptEnvelopeObservation::new(
            "devnet-escape-receipt-envelope-0003",
            ReceiptLane::ChallengeRelease,
            ReceiptStatus::Included,
            "devnet-user-escape-exit-0003",
            self.height - 43,
            self.height - 20,
        );

        self.seed_envelope(first, 0, 2_400_000_000_000);
        self.seed_envelope(second, 1, 1_800_000_000_000);
        self.seed_envelope(third, 2, 900_000_000_000);
        let _ = self.reconcile("devnet-reconciliation-0001");
    }

    fn seed_envelope(
        &mut self,
        envelope: ReceiptEnvelopeObservation,
        leaf_index: u64,
        claim_amount_bucket_piconero: u64,
    ) {
        let envelope_id = envelope.envelope_id.clone();
        let exit_request_id = envelope.exit_request_id.clone();
        let summary_id = envelope.wallet_summary_id.clone();
        let observed_at_height = envelope.observed_at_height;
        let confirmed_at_height = envelope.confirmed_at_height;
        let settlement_status = envelope.status;

        let _ = self.observe_envelope(envelope);
        let _ = self.observe_transcript(TranscriptObservation::new(
            stable_id("transcript", &envelope_id),
            envelope_id.clone(),
            4,
            observed_at_height,
        ));
        let _ = self.observe_inclusion_witness(InclusionWitnessObservation::new(
            stable_id("inclusion-witness", &envelope_id),
            envelope_id.clone(),
            leaf_index,
            confirmed_at_height,
            self.config.min_confirmations,
        ));
        let _ = self.publish_wallet_summary(WalletVisibleReceiptSummary::new(
            summary_id,
            envelope_id,
            exit_request_id,
            claim_amount_bucket_piconero,
            settlement_status,
            confirmed_at_height,
        ));
    }

    fn reconciled_envelope_count(&self) -> u64 {
        self.envelopes
            .values()
            .filter(|envelope| {
                matches!(
                    envelope.status,
                    ReceiptStatus::Included
                        | ReceiptStatus::WalletVisible
                        | ReceiptStatus::Reconciled
                )
            })
            .count() as u64
    }

    fn quarantined_envelope_count(&self) -> usize {
        self.envelopes
            .values()
            .filter(|envelope| matches!(envelope.status, ReceiptStatus::Quarantined))
            .count()
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

pub fn root_from_record(record: &Value) -> String {
    receipt_feed_hash("RECORD", &[HashPart::Json(record)])
}

fn require_known_envelope(
    envelopes: &BTreeMap<String, ReceiptEnvelopeObservation>,
    envelope_id: &str,
) -> MoneroL2PqBridgeExitCanonicalUserEscapeReceiptProcessFeedRuntimeResult<()> {
    if envelopes.contains_key(envelope_id) {
        return Ok(());
    }
    Err(format!("unknown receipt envelope {envelope_id}"))
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_root(label: &str, value: &str) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "label": label,
        "value": value
    });
    receipt_feed_hash("RECORD-ROOT", &[HashPart::Json(&record)])
}

fn stable_id(label: &str, value: &str) -> String {
    receipt_feed_hash("STABLE-ID", &[HashPart::Str(label), HashPart::Str(value)])
}

fn receipt_feed_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let scoped_domain = format!("MONERO-L2-PQ-BRIDGE-EXIT-RECEIPT-PROCESS-FEED-{domain}");
    domain_hash(
        &scoped_domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&json!({
                "parts": parts
                    .iter()
                    .enumerate()
                    .map(|(index, part)| hash_part_record(index, part))
                    .collect::<Vec<_>>()
            })),
        ],
        32,
    )
}

fn hash_part_record(index: usize, part: &HashPart<'_>) -> Value {
    match part {
        HashPart::Bytes(value) => json!({
            "index": index,
            "type": "bytes",
            "value_root": domain_hash("RECEIPT-FEED-BYTES-PART", &[HashPart::Bytes(*value)], 32)
        }),
        HashPart::Str(value) => json!({
            "index": index,
            "type": "str",
            "value": value
        }),
        HashPart::U64(value) => json!({
            "index": index,
            "type": "u64",
            "value": value
        }),
        HashPart::Int(value) => json!({
            "index": index,
            "type": "int",
            "value": value.to_string()
        }),
        HashPart::Json(value) => json!({
            "index": index,
            "type": "json",
            "value": value
        }),
    }
}
