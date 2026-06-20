use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitForcedWithdrawalFixtureReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FORCED_WITHDRAWAL_FIXTURE_REPLAY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-forced-withdrawal-fixture-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FORCED_WITHDRAWAL_FIXTURE_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FIXTURE_REPLAY_SUITE: &str =
    "monero-l2-pq-bridge-exit-forced-withdrawal-fixture-replay-spine-v1";
pub const DEFAULT_MIN_USER_SIGNATURES: u16 = 1;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u16 = 67;
pub const DEFAULT_MIN_PQ_QUORUM_WEIGHT: u16 = 80;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 288;
pub const DEFAULT_EXIT_FINALITY_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_FIXTURES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    UserLocalOnly,
    WatcherOffline,
    SequencerOffline,
    SequencerWatcherOffline,
}

impl ReplayMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserLocalOnly => "user_local_only",
            Self::WatcherOffline => "watcher_offline",
            Self::SequencerOffline => "sequencer_offline",
            Self::SequencerWatcherOffline => "sequencer_watcher_offline",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    WalletTranscriptRoot,
    NoteCommitmentRoot,
    PrivateBalanceCommitment,
    WithdrawalIntentRoot,
    BurnNullifier,
    ExitNullifier,
    MoneroDestinationCommitment,
    UserPqSignatureRoot,
    ReplayFenceRoot,
    PqQuorumRoot,
    SequencerFailureRoot,
    WatcherFailureRoot,
    ExitPackageRoot,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTranscriptRoot => "wallet_transcript_root",
            Self::NoteCommitmentRoot => "note_commitment_root",
            Self::PrivateBalanceCommitment => "private_balance_commitment",
            Self::WithdrawalIntentRoot => "withdrawal_intent_root",
            Self::BurnNullifier => "burn_nullifier",
            Self::ExitNullifier => "exit_nullifier",
            Self::MoneroDestinationCommitment => "monero_destination_commitment",
            Self::UserPqSignatureRoot => "user_pq_signature_root",
            Self::ReplayFenceRoot => "replay_fence_root",
            Self::PqQuorumRoot => "pq_quorum_root",
            Self::SequencerFailureRoot => "sequencer_failure_root",
            Self::WatcherFailureRoot => "watcher_failure_root",
            Self::ExitPackageRoot => "exit_package_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    Authorized,
    Denied,
    Quarantined,
}

impl FixtureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Denied => "denied",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    MissingUserLocalEvidence,
    MissingUserPqSignature,
    ReplayNullifierSeen,
    ReplayFenceMismatch,
    InsufficientPqQuorumWeight,
    InsufficientWatcherFailureEvidence,
    InsufficientSequencerFailureEvidence,
    AmountExceedsPrivateBalance,
    ExpiredReplayWindow,
    ExitPackageRootMismatch,
    ProductionReleaseDisabled,
}

impl DenialReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingUserLocalEvidence => "missing_user_local_evidence",
            Self::MissingUserPqSignature => "missing_user_pq_signature",
            Self::ReplayNullifierSeen => "replay_nullifier_seen",
            Self::ReplayFenceMismatch => "replay_fence_mismatch",
            Self::InsufficientPqQuorumWeight => "insufficient_pq_quorum_weight",
            Self::InsufficientWatcherFailureEvidence => "insufficient_watcher_failure_evidence",
            Self::InsufficientSequencerFailureEvidence => "insufficient_sequencer_failure_evidence",
            Self::AmountExceedsPrivateBalance => "amount_exceeds_private_balance",
            Self::ExpiredReplayWindow => "expired_replay_window",
            Self::ExitPackageRootMismatch => "exit_package_root_mismatch",
            Self::ProductionReleaseDisabled => "production_release_disabled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub fixture_replay_suite: String,
    pub min_user_signatures: u16,
    pub min_watcher_weight: u16,
    pub min_pq_quorum_weight: u16,
    pub min_pq_security_bits: u16,
    pub replay_window_blocks: u64,
    pub exit_finality_blocks: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fixture_replay_suite: FIXTURE_REPLAY_SUITE.to_string(),
            min_user_signatures: DEFAULT_MIN_USER_SIGNATURES,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            min_pq_quorum_weight: DEFAULT_MIN_PQ_QUORUM_WEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            exit_finality_blocks: DEFAULT_EXIT_FINALITY_BLOCKS,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_fixtures: DEFAULT_MAX_FIXTURES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "fixture_replay_suite": self.fixture_replay_suite,
            "min_user_signatures": self.min_user_signatures,
            "min_watcher_weight": self.min_watcher_weight,
            "min_pq_quorum_weight": self.min_pq_quorum_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "replay_window_blocks": self.replay_window_blocks,
            "exit_finality_blocks": self.exit_finality_blocks,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_fixtures": self.max_fixtures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserLocalEvidence {
    pub wallet_transcript_root: String,
    pub note_commitment_root: String,
    pub private_balance_commitment: String,
    pub withdrawal_intent_root: String,
    pub burn_nullifier: String,
    pub exit_nullifier: String,
    pub monero_destination_commitment: String,
    pub amount_atomic: u64,
    pub balance_floor_atomic: u64,
    pub evidence_epoch: u64,
    pub evidence_root: String,
}

impl UserLocalEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_transcript_root: impl Into<String>,
        note_commitment_root: impl Into<String>,
        private_balance_commitment: impl Into<String>,
        withdrawal_intent_root: impl Into<String>,
        burn_nullifier: impl Into<String>,
        exit_nullifier: impl Into<String>,
        monero_destination_commitment: impl Into<String>,
        amount_atomic: u64,
        balance_floor_atomic: u64,
        evidence_epoch: u64,
    ) -> Self {
        let mut evidence = Self {
            wallet_transcript_root: wallet_transcript_root.into(),
            note_commitment_root: note_commitment_root.into(),
            private_balance_commitment: private_balance_commitment.into(),
            withdrawal_intent_root: withdrawal_intent_root.into(),
            burn_nullifier: burn_nullifier.into(),
            exit_nullifier: exit_nullifier.into(),
            monero_destination_commitment: monero_destination_commitment.into(),
            amount_atomic,
            balance_floor_atomic,
            evidence_epoch,
            evidence_root: String::new(),
        };
        evidence.evidence_root = evidence.compute_root();
        evidence
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_transcript_root": self.wallet_transcript_root,
            "note_commitment_root": self.note_commitment_root,
            "private_balance_commitment": self.private_balance_commitment,
            "withdrawal_intent_root": self.withdrawal_intent_root,
            "burn_nullifier": self.burn_nullifier,
            "exit_nullifier": self.exit_nullifier,
            "monero_destination_commitment": self.monero_destination_commitment,
            "amount_atomic": self.amount_atomic,
            "balance_floor_atomic": self.balance_floor_atomic,
            "evidence_epoch": self.evidence_epoch,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn compute_root(&self) -> String {
        user_local_evidence_root(
            &self.wallet_transcript_root,
            &self.note_commitment_root,
            &self.private_balance_commitment,
            &self.withdrawal_intent_root,
            &self.burn_nullifier,
            &self.exit_nullifier,
            &self.monero_destination_commitment,
            self.amount_atomic,
            self.balance_floor_atomic,
            self.evidence_epoch,
        )
    }

    pub fn required_evidence_kinds() -> BTreeSet<EvidenceKind> {
        [
            EvidenceKind::WalletTranscriptRoot,
            EvidenceKind::NoteCommitmentRoot,
            EvidenceKind::PrivateBalanceCommitment,
            EvidenceKind::WithdrawalIntentRoot,
            EvidenceKind::BurnNullifier,
            EvidenceKind::ExitNullifier,
            EvidenceKind::MoneroDestinationCommitment,
        ]
        .into_iter()
        .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignatureWitness {
    pub scheme: String,
    pub signer_commitment: String,
    pub signed_root: String,
    pub security_bits: u16,
    pub signature_root: String,
}

impl PqSignatureWitness {
    pub fn new(
        scheme: impl Into<String>,
        signer_commitment: impl Into<String>,
        signed_root: impl Into<String>,
        security_bits: u16,
    ) -> Self {
        let scheme = scheme.into();
        let signer_commitment = signer_commitment.into();
        let signed_root = signed_root.into();
        let signature_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-PQ-SIGNATURE",
            &[
                HashPart::Str(&scheme),
                HashPart::Str(&signer_commitment),
                HashPart::Str(&signed_root),
                HashPart::U64(security_bits as u64),
            ],
            32,
        );
        Self {
            scheme,
            signer_commitment,
            signed_root,
            security_bits,
            signature_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": self.scheme,
            "signer_commitment": self.signer_commitment,
            "signed_root": self.signed_root,
            "security_bits": self.security_bits,
            "signature_root": self.signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqQuorumWitness {
    pub quorum_id: String,
    pub authority_set_root: String,
    pub attestation_roots: Vec<String>,
    pub observed_weight: u16,
    pub threshold_weight: u16,
    pub quorum_root: String,
}

impl PqQuorumWitness {
    pub fn new(
        quorum_id: impl Into<String>,
        authority_set_root: impl Into<String>,
        attestation_roots: Vec<String>,
        observed_weight: u16,
        threshold_weight: u16,
    ) -> Self {
        let quorum_id = quorum_id.into();
        let authority_set_root = authority_set_root.into();
        let leaves = attestation_roots
            .iter()
            .map(|root| json!({ "attestation_root": root }))
            .collect::<Vec<_>>();
        let attestation_merkle_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-PQ-QUORUM-ATTESTATIONS",
            &leaves,
        );
        let quorum_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-PQ-QUORUM",
            &[
                HashPart::Str(&quorum_id),
                HashPart::Str(&authority_set_root),
                HashPart::Str(&attestation_merkle_root),
                HashPart::U64(observed_weight as u64),
                HashPart::U64(threshold_weight as u64),
            ],
            32,
        );
        Self {
            quorum_id,
            authority_set_root,
            attestation_roots,
            observed_weight,
            threshold_weight,
            quorum_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "authority_set_root": self.authority_set_root,
            "attestation_roots": self.attestation_roots,
            "observed_weight": self.observed_weight,
            "threshold_weight": self.threshold_weight,
            "quorum_root": self.quorum_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailureEvidence {
    pub sequencer_failure_root: String,
    pub watcher_failure_root: String,
    pub sequencer_missed_blocks: u64,
    pub watcher_missing_weight: u16,
    pub failure_root: String,
}

impl FailureEvidence {
    pub fn new(
        sequencer_failure_root: impl Into<String>,
        watcher_failure_root: impl Into<String>,
        sequencer_missed_blocks: u64,
        watcher_missing_weight: u16,
    ) -> Self {
        let sequencer_failure_root = sequencer_failure_root.into();
        let watcher_failure_root = watcher_failure_root.into();
        let failure_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-FAILURE-EVIDENCE",
            &[
                HashPart::Str(&sequencer_failure_root),
                HashPart::Str(&watcher_failure_root),
                HashPart::U64(sequencer_missed_blocks),
                HashPart::U64(watcher_missing_weight as u64),
            ],
            32,
        );
        Self {
            sequencer_failure_root,
            watcher_failure_root,
            sequencer_missed_blocks,
            watcher_missing_weight,
            failure_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sequencer_failure_root": self.sequencer_failure_root,
            "watcher_failure_root": self.watcher_failure_root,
            "sequencer_missed_blocks": self.sequencer_missed_blocks,
            "watcher_missing_weight": self.watcher_missing_weight,
            "failure_root": self.failure_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureReplay {
    pub fixture_id: String,
    pub mode: ReplayMode,
    pub evidence: UserLocalEvidence,
    pub user_signatures: Vec<PqSignatureWitness>,
    pub pq_quorum: PqQuorumWitness,
    pub failure_evidence: FailureEvidence,
    pub replay_fence_root: String,
    pub expected_exit_package_root: String,
    pub submitted_at_block: u64,
    pub fixture_root: String,
}

impl FixtureReplay {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        mode: ReplayMode,
        evidence: UserLocalEvidence,
        user_signatures: Vec<PqSignatureWitness>,
        pq_quorum: PqQuorumWitness,
        failure_evidence: FailureEvidence,
        submitted_at_block: u64,
    ) -> Self {
        let label = label.into();
        let replay_fence_root = replay_fence_root(
            &evidence.burn_nullifier,
            &evidence.exit_nullifier,
            evidence.evidence_epoch,
            &evidence.withdrawal_intent_root,
        );
        let expected_exit_package_root = exit_package_root(
            mode,
            &evidence.evidence_root,
            &signature_set_root(&user_signatures),
            &pq_quorum.quorum_root,
            &failure_evidence.failure_root,
            &replay_fence_root,
            submitted_at_block,
        );
        let fixture_id = fixture_id(&label, &expected_exit_package_root);
        let fixture_root = fixture_record_root(
            &fixture_id,
            mode,
            &evidence.evidence_root,
            &pq_quorum.quorum_root,
            &failure_evidence.failure_root,
            &expected_exit_package_root,
            submitted_at_block,
        );
        Self {
            fixture_id,
            mode,
            evidence,
            user_signatures,
            pq_quorum,
            failure_evidence,
            replay_fence_root,
            expected_exit_package_root,
            submitted_at_block,
            fixture_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "mode": self.mode.as_str(),
            "evidence": self.evidence.public_record(),
            "user_signatures": self.user_signatures.iter().map(PqSignatureWitness::public_record).collect::<Vec<_>>(),
            "pq_quorum": self.pq_quorum.public_record(),
            "failure_evidence": self.failure_evidence.public_record(),
            "replay_fence_root": self.replay_fence_root,
            "expected_exit_package_root": self.expected_exit_package_root,
            "submitted_at_block": self.submitted_at_block,
            "fixture_root": self.fixture_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayDecision {
    pub fixture_id: String,
    pub status: FixtureStatus,
    pub denial_reasons: Vec<DenialReason>,
    pub recreated_authorization_root: String,
    pub replay_fence_root: String,
    pub pq_quorum_root: String,
    pub exit_package_root: String,
    pub decision_root: String,
}

impl ReplayDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "status": self.status.as_str(),
            "denial_reasons": self.denial_reasons.iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
            "recreated_authorization_root": self.recreated_authorization_root,
            "replay_fence_root": self.replay_fence_root,
            "pq_quorum_root": self.pq_quorum_root,
            "exit_package_root": self.exit_package_root,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub fixtures: BTreeMap<String, FixtureReplay>,
    pub decisions: BTreeMap<String, ReplayDecision>,
    pub seen_nullifiers: BTreeSet<String>,
    pub root_log: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            fixtures: BTreeMap::new(),
            decisions: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
            root_log: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        for fixture in devnet_fixtures(&state.config) {
            state
                .add_fixture(fixture)
                .expect("devnet fixture limit should accept seeded replay");
        }
        let fixture_ids = state.fixtures.keys().cloned().collect::<Vec<_>>();
        for fixture_id in fixture_ids {
            state
                .replay_fixture(&fixture_id)
                .expect("devnet fixture replay should be deterministic");
        }
        state
    }

    pub fn add_fixture(&mut self, fixture: FixtureReplay) -> Result<()> {
        ensure(
            self.fixtures.len() < self.config.max_fixtures,
            "fixture capacity exhausted",
        )?;
        ensure(
            !self.fixtures.contains_key(&fixture.fixture_id),
            "fixture id already exists",
        )?;
        self.root_log.insert(
            format!("fixture:{}", fixture.fixture_id),
            fixture.fixture_root.clone(),
        );
        self.fixtures.insert(fixture.fixture_id.clone(), fixture);
        Ok(())
    }

    pub fn replay_fixture(&mut self, fixture_id: &str) -> Result<ReplayDecision> {
        let fixture = self
            .fixtures
            .get(fixture_id)
            .cloned()
            .ok_or_else(|| format!("unknown fixture id: {fixture_id}"))?;
        let decision = self.evaluate_fixture(&fixture);
        if decision.status == FixtureStatus::Authorized {
            self.seen_nullifiers
                .insert(fixture.evidence.burn_nullifier.clone());
            self.seen_nullifiers
                .insert(fixture.evidence.exit_nullifier.clone());
        }
        self.root_log.insert(
            format!("decision:{}", decision.fixture_id),
            decision.decision_root.clone(),
        );
        self.decisions
            .insert(decision.fixture_id.clone(), decision.clone());
        Ok(decision)
    }

    pub fn evaluate_fixture(&self, fixture: &FixtureReplay) -> ReplayDecision {
        let signature_root = signature_set_root(&fixture.user_signatures);
        let recreated_authorization_root = recreated_authorization_root(
            fixture.mode,
            &fixture.evidence.evidence_root,
            &signature_root,
            &fixture.pq_quorum.quorum_root,
            &fixture.failure_evidence.failure_root,
        );
        let replay_fence = replay_fence_root(
            &fixture.evidence.burn_nullifier,
            &fixture.evidence.exit_nullifier,
            fixture.evidence.evidence_epoch,
            &fixture.evidence.withdrawal_intent_root,
        );
        let exit_package = exit_package_root(
            fixture.mode,
            &fixture.evidence.evidence_root,
            &signature_root,
            &fixture.pq_quorum.quorum_root,
            &fixture.failure_evidence.failure_root,
            &replay_fence,
            fixture.submitted_at_block,
        );
        let denial_reasons =
            self.denial_reasons(fixture, &signature_root, &replay_fence, &exit_package);
        let status = if denial_reasons.is_empty() {
            FixtureStatus::Authorized
        } else if denial_reasons.contains(&DenialReason::ReplayNullifierSeen)
            || denial_reasons.contains(&DenialReason::ExitPackageRootMismatch)
        {
            FixtureStatus::Quarantined
        } else {
            FixtureStatus::Denied
        };
        let decision_root = replay_decision_root(
            &fixture.fixture_id,
            status,
            &denial_reasons,
            &recreated_authorization_root,
            &replay_fence,
            &fixture.pq_quorum.quorum_root,
            &exit_package,
        );
        ReplayDecision {
            fixture_id: fixture.fixture_id.clone(),
            status,
            denial_reasons,
            recreated_authorization_root,
            replay_fence_root: replay_fence,
            pq_quorum_root: fixture.pq_quorum.quorum_root.clone(),
            exit_package_root: exit_package,
            decision_root,
        }
    }

    pub fn denial_reasons(
        &self,
        fixture: &FixtureReplay,
        signature_root: &str,
        replay_fence: &str,
        exit_package: &str,
    ) -> Vec<DenialReason> {
        let mut reasons = Vec::new();
        if !self.user_local_evidence_complete(&fixture.evidence) {
            reasons.push(DenialReason::MissingUserLocalEvidence);
        }
        if fixture.user_signatures.len() < self.config.min_user_signatures as usize
            || signature_root == empty_signature_root()
            || fixture
                .user_signatures
                .iter()
                .any(|signature| signature.security_bits < self.config.min_pq_security_bits)
        {
            reasons.push(DenialReason::MissingUserPqSignature);
        }
        if self
            .seen_nullifiers
            .contains(&fixture.evidence.burn_nullifier)
            || self
                .seen_nullifiers
                .contains(&fixture.evidence.exit_nullifier)
        {
            reasons.push(DenialReason::ReplayNullifierSeen);
        }
        if replay_fence != fixture.replay_fence_root {
            reasons.push(DenialReason::ReplayFenceMismatch);
        }
        if fixture.pq_quorum.observed_weight < self.config.min_pq_quorum_weight
            || fixture.pq_quorum.observed_weight < fixture.pq_quorum.threshold_weight
        {
            reasons.push(DenialReason::InsufficientPqQuorumWeight);
        }
        if requires_watcher_failure(fixture.mode)
            && fixture.failure_evidence.watcher_missing_weight < self.config.min_watcher_weight
        {
            reasons.push(DenialReason::InsufficientWatcherFailureEvidence);
        }
        if requires_sequencer_failure(fixture.mode)
            && fixture.failure_evidence.sequencer_missed_blocks < self.config.exit_finality_blocks
        {
            reasons.push(DenialReason::InsufficientSequencerFailureEvidence);
        }
        if fixture.evidence.amount_atomic > fixture.evidence.balance_floor_atomic {
            reasons.push(DenialReason::AmountExceedsPrivateBalance);
        }
        if fixture.submitted_at_block
            > fixture.evidence.evidence_epoch + self.config.replay_window_blocks
        {
            reasons.push(DenialReason::ExpiredReplayWindow);
        }
        if exit_package != fixture.expected_exit_package_root {
            reasons.push(DenialReason::ExitPackageRootMismatch);
        }
        if !self.config.production_release_allowed {
            reasons.push(DenialReason::ProductionReleaseDisabled);
        }
        reasons
    }

    pub fn user_local_evidence_complete(&self, evidence: &UserLocalEvidence) -> bool {
        let fields = [
            evidence.wallet_transcript_root.as_str(),
            evidence.note_commitment_root.as_str(),
            evidence.private_balance_commitment.as_str(),
            evidence.withdrawal_intent_root.as_str(),
            evidence.burn_nullifier.as_str(),
            evidence.exit_nullifier.as_str(),
            evidence.monero_destination_commitment.as_str(),
        ];
        fields.iter().all(|field| !field.is_empty())
            && evidence.evidence_root == evidence.compute_root()
    }

    pub fn authorized_decisions(&self) -> Vec<&ReplayDecision> {
        self.decisions
            .values()
            .filter(|decision| decision.status == FixtureStatus::Authorized)
            .collect()
    }

    pub fn denied_decisions(&self) -> Vec<&ReplayDecision> {
        self.decisions
            .values()
            .filter(|decision| decision.status == FixtureStatus::Denied)
            .collect()
    }

    pub fn quarantined_decisions(&self) -> Vec<&ReplayDecision> {
        self.decisions
            .values()
            .filter(|decision| decision.status == FixtureStatus::Quarantined)
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "fixtures": self.fixtures.values().map(FixtureReplay::public_record).collect::<Vec<_>>(),
            "decisions": self.decisions.values().map(ReplayDecision::public_record).collect::<Vec<_>>(),
            "seen_nullifiers": self.seen_nullifiers.iter().collect::<Vec<_>>(),
            "root_log": self.root_log,
            "fixture_count": self.fixtures.len(),
            "decision_count": self.decisions.len(),
        })
    }

    pub fn state_root(&self) -> String {
        let fixture_leaves = self
            .fixtures
            .values()
            .map(|fixture| fixture.public_record())
            .collect::<Vec<_>>();
        let decision_leaves = self
            .decisions
            .values()
            .map(|decision| decision.public_record())
            .collect::<Vec<_>>();
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&merkle_root(
                    "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-FIXTURES",
                    &fixture_leaves,
                )),
                HashPart::Str(&merkle_root(
                    "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-DECISIONS",
                    &decision_leaves,
                )),
                HashPart::Json(&json!({
                    "seen_nullifiers": self.seen_nullifiers.iter().collect::<Vec<_>>(),
                    "root_log": self.root_log,
                })),
            ],
            32,
        )
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

pub fn fixture_id(label: &str, exit_package_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-FIXTURE-ID",
        &[HashPart::Str(label), HashPart::Str(exit_package_root)],
        32,
    )
}

pub fn replay_fence_root(
    burn_nullifier: &str,
    exit_nullifier: &str,
    evidence_epoch: u64,
    withdrawal_intent_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-FENCE",
        &[
            HashPart::Str(burn_nullifier),
            HashPart::Str(exit_nullifier),
            HashPart::U64(evidence_epoch),
            HashPart::Str(withdrawal_intent_root),
        ],
        32,
    )
}

pub fn exit_package_root(
    mode: ReplayMode,
    evidence_root: &str,
    signature_set_root: &str,
    pq_quorum_root: &str,
    failure_root: &str,
    replay_fence_root: &str,
    submitted_at_block: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-EXIT-PACKAGE",
        &[
            HashPart::Str(mode.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(signature_set_root),
            HashPart::Str(pq_quorum_root),
            HashPart::Str(failure_root),
            HashPart::Str(replay_fence_root),
            HashPart::U64(submitted_at_block),
        ],
        32,
    )
}

pub fn signature_set_root(signatures: &[PqSignatureWitness]) -> String {
    let leaves = signatures
        .iter()
        .map(PqSignatureWitness::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-SIGNATURE-SET",
        &leaves,
    )
}

pub fn empty_signature_root() -> &'static str {
    "0000000000000000000000000000000000000000000000000000000000000000"
}

pub fn required_user_local_evidence() -> BTreeSet<EvidenceKind> {
    UserLocalEvidence::required_evidence_kinds()
}

pub fn evidence_kind_names(kinds: &BTreeSet<EvidenceKind>) -> Vec<&'static str> {
    kinds.iter().map(|kind| kind.as_str()).collect()
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn user_local_evidence_root(
    wallet_transcript_root: &str,
    note_commitment_root: &str,
    private_balance_commitment: &str,
    withdrawal_intent_root: &str,
    burn_nullifier: &str,
    exit_nullifier: &str,
    monero_destination_commitment: &str,
    amount_atomic: u64,
    balance_floor_atomic: u64,
    evidence_epoch: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-USER-LOCAL-EVIDENCE",
        &[
            HashPart::Str(wallet_transcript_root),
            HashPart::Str(note_commitment_root),
            HashPart::Str(private_balance_commitment),
            HashPart::Str(withdrawal_intent_root),
            HashPart::Str(burn_nullifier),
            HashPart::Str(exit_nullifier),
            HashPart::Str(monero_destination_commitment),
            HashPart::U64(amount_atomic),
            HashPart::U64(balance_floor_atomic),
            HashPart::U64(evidence_epoch),
        ],
        32,
    )
}

fn recreated_authorization_root(
    mode: ReplayMode,
    evidence_root: &str,
    signature_set_root: &str,
    pq_quorum_root: &str,
    failure_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-RECREATED-AUTHORIZATION",
        &[
            HashPart::Str(mode.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(signature_set_root),
            HashPart::Str(pq_quorum_root),
            HashPart::Str(failure_root),
        ],
        32,
    )
}

fn replay_decision_root(
    fixture_id: &str,
    status: FixtureStatus,
    denial_reasons: &[DenialReason],
    recreated_authorization_root: &str,
    replay_fence_root: &str,
    pq_quorum_root: &str,
    exit_package_root: &str,
) -> String {
    let denial_reason_names = denial_reasons
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>();
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-DECISION",
        &[
            HashPart::Str(fixture_id),
            HashPart::Str(status.as_str()),
            HashPart::Json(&json!(denial_reason_names)),
            HashPart::Str(recreated_authorization_root),
            HashPart::Str(replay_fence_root),
            HashPart::Str(pq_quorum_root),
            HashPart::Str(exit_package_root),
        ],
        32,
    )
}

fn fixture_record_root(
    fixture_id: &str,
    mode: ReplayMode,
    evidence_root: &str,
    pq_quorum_root: &str,
    failure_root: &str,
    exit_package_root: &str,
    submitted_at_block: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-FIXTURE-RECORD",
        &[
            HashPart::Str(fixture_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(pq_quorum_root),
            HashPart::Str(failure_root),
            HashPart::Str(exit_package_root),
            HashPart::U64(submitted_at_block),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-FIXTURE-REPLAY-ROOT",
        &[HashPart::Str(kind), HashPart::Str(label)],
        32,
    )
}

fn requires_watcher_failure(mode: ReplayMode) -> bool {
    matches!(
        mode,
        ReplayMode::WatcherOffline | ReplayMode::SequencerWatcherOffline
    )
}

fn requires_sequencer_failure(mode: ReplayMode) -> bool {
    matches!(
        mode,
        ReplayMode::SequencerOffline | ReplayMode::SequencerWatcherOffline
    )
}

fn devnet_fixtures(config: &Config) -> Vec<FixtureReplay> {
    let authorized = devnet_fixture(
        config,
        "devnet-user-local-replay",
        ReplayMode::SequencerWatcherOffline,
        1_250_000_000_000,
        1_500_000_000_000,
        config.min_pq_quorum_weight,
        config.min_watcher_weight,
        config.exit_finality_blocks + 4,
        8_020,
    );
    let replayed = devnet_fixture(
        config,
        "devnet-replay-nullifier",
        ReplayMode::UserLocalOnly,
        1_250_000_000_000,
        1_500_000_000_000,
        config.min_pq_quorum_weight,
        0,
        0,
        8_025,
    );
    let insufficient_quorum = devnet_fixture(
        config,
        "devnet-insufficient-quorum",
        ReplayMode::WatcherOffline,
        900_000_000_000,
        1_500_000_000_000,
        config.min_pq_quorum_weight - 1,
        config.min_watcher_weight - 1,
        0,
        8_030,
    );
    vec![authorized, replayed, insufficient_quorum]
}

#[allow(clippy::too_many_arguments)]
fn devnet_fixture(
    config: &Config,
    label: &str,
    mode: ReplayMode,
    amount_atomic: u64,
    balance_floor_atomic: u64,
    quorum_weight: u16,
    watcher_missing_weight: u16,
    sequencer_missed_blocks: u64,
    submitted_at_block: u64,
) -> FixtureReplay {
    let shared_nullifier_label = if label == "devnet-replay-nullifier" {
        "devnet-user-local-replay"
    } else {
        label
    };
    let evidence = UserLocalEvidence::new(
        root("wallet_transcript", label),
        root("note_commitment", label),
        root("private_balance", label),
        root("withdrawal_intent", label),
        root("burn_nullifier", shared_nullifier_label),
        root("exit_nullifier", shared_nullifier_label),
        root("monero_destination_commitment", label),
        amount_atomic,
        balance_floor_atomic,
        submitted_at_block - 24,
    );
    let signature = PqSignatureWitness::new(
        "ml_dsa_87",
        root("user_pq_signer", label),
        evidence.evidence_root.clone(),
        config.min_pq_security_bits,
    );
    let pq_quorum = PqQuorumWitness::new(
        format!("devnet-pq-quorum-{label}"),
        root("pq_authority_set", label),
        vec![
            root("pq_attestation", &format!("{label}-a")),
            root("pq_attestation", &format!("{label}-b")),
        ],
        quorum_weight,
        config.min_pq_quorum_weight,
    );
    let failure_evidence = FailureEvidence::new(
        root("sequencer_failure", label),
        root("watcher_failure", label),
        sequencer_missed_blocks,
        watcher_missing_weight,
    );
    FixtureReplay::new(
        label,
        mode,
        evidence,
        vec![signature],
        pq_quorum,
        failure_evidence,
        submitted_at_block,
    )
}
