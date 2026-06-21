use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::hash::{Hash, Hasher};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-force-exit-wave89-release-captain-no-go-evidence-archive-bridge-custody-gate-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "stdlib-default-hasher-plus-local-mixer-roots-only-v1";
pub const DEFAULT_WAVE: u64 = 89;
pub const DEFAULT_SOURCE_WAVE: u64 = 88;
pub const DEFAULT_REPLAY_HEIGHT: u64 = 1_890_000;
pub const DEFAULT_MAX_REPLAY_AGE_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_WATCHER_QUORUM: u16 = 4;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_SIGNER_QUORUM: u16 = 5;
pub const DEFAULT_MIN_SIGNER_WEIGHT: u64 = 80;
pub const DEFAULT_MIN_CUSTODY_PROOFS: u16 = 4;
pub const DEFAULT_MIN_RESERVE_PROOFS: u16 = 3;
pub const DEFAULT_MIN_WITHDRAWAL_HOLDS: u16 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub archive_id: String,
    pub release_id: String,
    pub bridge_id: String,
    pub custody_gate_id: String,
    pub source_replay_id: String,
    pub wave: u64,
    pub source_wave: u64,
    pub replay_height: u64,
    pub max_replay_age_blocks: u64,
    pub min_watcher_quorum: u16,
    pub min_watcher_weight: u64,
    pub min_signer_quorum: u16,
    pub min_signer_weight: u64,
    pub min_custody_proofs: u16,
    pub min_reserve_proofs: u16,
    pub min_withdrawal_holds: u16,
    pub require_monero_watcher_no_reorg: bool,
    pub require_reserve_solvent: bool,
    pub require_withdrawals_held: bool,
    pub require_signer_quorum_hold: bool,
    pub fail_closed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: "dinero-devnet".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            archive_id: "wave89-no-go-evidence-archive".to_string(),
            release_id: "wave89-force-exit-release".to_string(),
            bridge_id: "monero-l2-pq-bridge".to_string(),
            custody_gate_id: "bridge-custody-gate".to_string(),
            source_replay_id: "wave88-go-no-go-replay-decisions".to_string(),
            wave: DEFAULT_WAVE,
            source_wave: DEFAULT_SOURCE_WAVE,
            replay_height: DEFAULT_REPLAY_HEIGHT,
            max_replay_age_blocks: DEFAULT_MAX_REPLAY_AGE_BLOCKS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            min_signer_quorum: DEFAULT_MIN_SIGNER_QUORUM,
            min_signer_weight: DEFAULT_MIN_SIGNER_WEIGHT,
            min_custody_proofs: DEFAULT_MIN_CUSTODY_PROOFS,
            min_reserve_proofs: DEFAULT_MIN_RESERVE_PROOFS,
            min_withdrawal_holds: DEFAULT_MIN_WITHDRAWAL_HOLDS,
            require_monero_watcher_no_reorg: true,
            require_reserve_solvent: true,
            require_withdrawals_held: true,
            require_signer_quorum_hold: true,
            fail_closed: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("archive_id", &self.archive_id)?;
        require_non_empty("release_id", &self.release_id)?;
        require_non_empty("bridge_id", &self.bridge_id)?;
        require_non_empty("custody_gate_id", &self.custody_gate_id)?;
        require_non_empty("source_replay_id", &self.source_replay_id)?;
        if self.schema_version != SCHEMA_VERSION {
            return Err("schema_version_mismatch".to_string());
        }
        if self.wave <= self.source_wave {
            return Err("wave_must_follow_source_wave".to_string());
        }
        if self.replay_height == 0 {
            return Err("replay_height_required".to_string());
        }
        if self.max_replay_age_blocks == 0 {
            return Err("max_replay_age_blocks_required".to_string());
        }
        if self.min_watcher_quorum == 0
            || self.min_signer_quorum == 0
            || self.min_custody_proofs == 0
            || self.min_reserve_proofs == 0
            || self.min_withdrawal_holds == 0
        {
            return Err("minimum_counts_must_be_non_zero".to_string());
        }
        if !self.fail_closed {
            return Err("release_archive_must_fail_closed".to_string());
        }
        Ok(())
    }

    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "archive_id", &self.archive_id);
        push_pair(&mut out, "bridge_id", &self.bridge_id);
        push_pair(&mut out, "chain_id", &self.chain_id);
        push_bool(&mut out, "fail_closed", self.fail_closed);
        push_pair(&mut out, "hash_suite", &self.hash_suite);
        push_u64(
            &mut out,
            "max_replay_age_blocks",
            self.max_replay_age_blocks,
        );
        push_u16(&mut out, "min_custody_proofs", self.min_custody_proofs);
        push_u16(&mut out, "min_reserve_proofs", self.min_reserve_proofs);
        push_u16(&mut out, "min_signer_quorum", self.min_signer_quorum);
        push_u64(&mut out, "min_signer_weight", self.min_signer_weight);
        push_u16(&mut out, "min_watcher_quorum", self.min_watcher_quorum);
        push_u64(&mut out, "min_watcher_weight", self.min_watcher_weight);
        push_u16(&mut out, "min_withdrawal_holds", self.min_withdrawal_holds);
        push_pair(&mut out, "protocol_version", &self.protocol_version);
        push_pair(&mut out, "release_id", &self.release_id);
        push_bool(
            &mut out,
            "require_monero_watcher_no_reorg",
            self.require_monero_watcher_no_reorg,
        );
        push_bool(
            &mut out,
            "require_reserve_solvent",
            self.require_reserve_solvent,
        );
        push_bool(
            &mut out,
            "require_signer_quorum_hold",
            self.require_signer_quorum_hold,
        );
        push_bool(
            &mut out,
            "require_withdrawals_held",
            self.require_withdrawals_held,
        );
        push_u64(&mut out, "replay_height", self.replay_height);
        push_u64(&mut out, "schema_version", self.schema_version);
        push_pair(&mut out, "source_replay_id", &self.source_replay_id);
        push_u64(&mut out, "source_wave", self.source_wave);
        push_u64(&mut out, "wave", self.wave);
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceDomain {
    BridgeCustody,
    MoneroWatcher,
    Reserve,
    Withdrawal,
    SignerQuorum,
    ReleaseDecision,
}

impl EvidenceDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeCustody => "bridge_custody",
            Self::MoneroWatcher => "monero_watcher",
            Self::Reserve => "reserve",
            Self::Withdrawal => "withdrawal",
            Self::SignerQuorum => "signer_quorum",
            Self::ReleaseDecision => "release_decision",
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::BridgeCustody,
            Self::MoneroWatcher,
            Self::Reserve,
            Self::Withdrawal,
            Self::SignerQuorum,
            Self::ReleaseDecision,
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BlockerKind {
    MissingWave88DecisionRoot,
    MissingBridgeCustodyProof,
    CustodyRootMismatch,
    CustodyProofExpired,
    MoneroWatcherQuorumLow,
    MoneroWatcherWeightLow,
    MoneroWatcherReorgObserved,
    ReserveProofCountLow,
    ReserveLiabilityMismatch,
    ReserveInsolvent,
    WithdrawalHoldCountLow,
    WithdrawalReleaseAttempted,
    SignerQuorumLow,
    SignerWeightLow,
    SignerUnholdVoteObserved,
    ReleaseCaptainNoGo,
    ReleaseHeld,
    ArchiveIncomplete,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave88DecisionRoot => "missing_wave88_decision_root",
            Self::MissingBridgeCustodyProof => "missing_bridge_custody_proof",
            Self::CustodyRootMismatch => "custody_root_mismatch",
            Self::CustodyProofExpired => "custody_proof_expired",
            Self::MoneroWatcherQuorumLow => "monero_watcher_quorum_low",
            Self::MoneroWatcherWeightLow => "monero_watcher_weight_low",
            Self::MoneroWatcherReorgObserved => "monero_watcher_reorg_observed",
            Self::ReserveProofCountLow => "reserve_proof_count_low",
            Self::ReserveLiabilityMismatch => "reserve_liability_mismatch",
            Self::ReserveInsolvent => "reserve_insolvent",
            Self::WithdrawalHoldCountLow => "withdrawal_hold_count_low",
            Self::WithdrawalReleaseAttempted => "withdrawal_release_attempted",
            Self::SignerQuorumLow => "signer_quorum_low",
            Self::SignerWeightLow => "signer_weight_low",
            Self::SignerUnholdVoteObserved => "signer_unhold_vote_observed",
            Self::ReleaseCaptainNoGo => "release_captain_no_go",
            Self::ReleaseHeld => "release_held",
            Self::ArchiveIncomplete => "archive_incomplete",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseDisposition {
    ReleaseHeld,
    NoGo,
    Go,
}

impl ReleaseDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseHeld => "release_held",
            Self::NoGo => "no_go",
            Self::Go => "go",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Go)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldStatus {
    Missing,
    Held,
    ReleaseAttempted,
    Disputed,
}

impl HoldStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Held => "held",
            Self::ReleaseAttempted => "release_attempted",
            Self::Disputed => "disputed",
        }
    }

    pub fn blocks_release(self) -> bool {
        !matches!(self, Self::Held)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyRecord {
    pub domain: EvidenceDomain,
    pub record_id: String,
    pub source_id: String,
    pub root: String,
    pub height: u64,
    pub note: String,
}

impl PrivacyRecord {
    pub fn new(
        domain: EvidenceDomain,
        record_id: impl Into<String>,
        source_id: impl Into<String>,
        root: impl Into<String>,
        height: u64,
        note: impl Into<String>,
    ) -> Self {
        Self {
            domain,
            record_id: record_id.into(),
            source_id: source_id.into(),
            root: normalize_root(root.into()),
            height,
            note: note.into(),
        }
    }

    pub fn validate(&self, replay_height: u64, max_age: u64) -> Result<()> {
        require_non_empty("record_id", &self.record_id)?;
        require_non_empty("source_id", &self.source_id)?;
        require_root("root", &self.root)?;
        if self.height == 0 {
            return Err("record_height_required".to_string());
        }
        if self.height > replay_height {
            return Err("record_height_after_replay".to_string());
        }
        if replay_height.saturating_sub(self.height) > max_age {
            return Err("record_expired".to_string());
        }
        Ok(())
    }

    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "domain", self.domain.as_str());
        push_u64(&mut out, "height", self.height);
        push_pair(&mut out, "note", &self.note);
        push_pair(&mut out, "record_id", &self.record_id);
        push_pair(&mut out, "root", &self.root);
        push_pair(&mut out, "source_id", &self.source_id);
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyProof {
    pub proof_id: String,
    pub custodian_id: String,
    pub wave88_decision_root: String,
    pub custody_root: String,
    pub bridge_pause_root: String,
    pub height: u64,
    pub held: bool,
}

impl CustodyProof {
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "bridge_pause_root", &self.bridge_pause_root);
        push_pair(&mut out, "custodian_id", &self.custodian_id);
        push_pair(&mut out, "custody_root", &self.custody_root);
        push_bool(&mut out, "held", self.held);
        push_u64(&mut out, "height", self.height);
        push_pair(&mut out, "proof_id", &self.proof_id);
        push_pair(&mut out, "wave88_decision_root", &self.wave88_decision_root);
        out
    }

    pub fn validate(&self, cfg: &Config) -> Vec<BlockerKind> {
        let mut blockers = Vec::new();
        if self.wave88_decision_root.is_empty() {
            blockers.push(BlockerKind::MissingWave88DecisionRoot);
        }
        if self.custody_root.is_empty() || self.bridge_pause_root.is_empty() {
            blockers.push(BlockerKind::MissingBridgeCustodyProof);
        }
        if !self.held {
            blockers.push(BlockerKind::ReleaseHeld);
        }
        if self.height == 0 || self.height > cfg.replay_height {
            blockers.push(BlockerKind::CustodyProofExpired);
        } else if cfg.replay_height.saturating_sub(self.height) > cfg.max_replay_age_blocks {
            blockers.push(BlockerKind::CustodyProofExpired);
        }
        blockers
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatcherQuorumRecord {
    pub quorum_id: String,
    pub watcher_roots: BTreeMap<String, String>,
    pub observed_tip_root: String,
    pub reorg_root: String,
    pub height: u64,
    pub total_weight: u64,
    pub reorg_observed: bool,
}

impl WatcherQuorumRecord {
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_u64(&mut out, "height", self.height);
        push_pair(&mut out, "observed_tip_root", &self.observed_tip_root);
        push_bool(&mut out, "reorg_observed", self.reorg_observed);
        push_pair(&mut out, "reorg_root", &self.reorg_root);
        push_u64(&mut out, "total_weight", self.total_weight);
        push_pair(&mut out, "quorum_id", &self.quorum_id);
        for (id, root) in &self.watcher_roots {
            push_pair(&mut out, &format!("watcher_root:{id}"), root);
        }
        out
    }

    pub fn watcher_count(&self) -> u16 {
        bounded_u16(self.watcher_roots.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveEvidence {
    pub reserve_id: String,
    pub liability_root: String,
    pub reserve_root: String,
    pub reconciliation_root: String,
    pub proof_roots: BTreeSet<String>,
    pub liabilities_atomic: u128,
    pub reserves_atomic: u128,
    pub height: u64,
}

impl ReserveEvidence {
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_u64(&mut out, "height", self.height);
        push_u128(&mut out, "liabilities_atomic", self.liabilities_atomic);
        push_pair(&mut out, "liability_root", &self.liability_root);
        push_pair(&mut out, "reconciliation_root", &self.reconciliation_root);
        push_pair(&mut out, "reserve_id", &self.reserve_id);
        push_pair(&mut out, "reserve_root", &self.reserve_root);
        push_u128(&mut out, "reserves_atomic", self.reserves_atomic);
        for root in &self.proof_roots {
            push_pair(&mut out, "proof_root", root);
        }
        out
    }

    pub fn solvent(&self) -> bool {
        self.reserves_atomic >= self.liabilities_atomic
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalHoldEvidence {
    pub hold_id: String,
    pub withdrawal_batch_root: String,
    pub nullifier_root: String,
    pub recipient_commitment_root: String,
    pub hold_status: HoldStatus,
    pub release_attempt_root: String,
    pub height: u64,
}

impl WithdrawalHoldEvidence {
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_u64(&mut out, "height", self.height);
        push_pair(&mut out, "hold_id", &self.hold_id);
        push_pair(&mut out, "hold_status", self.hold_status.as_str());
        push_pair(&mut out, "nullifier_root", &self.nullifier_root);
        push_pair(
            &mut out,
            "recipient_commitment_root",
            &self.recipient_commitment_root,
        );
        push_pair(&mut out, "release_attempt_root", &self.release_attempt_root);
        push_pair(
            &mut out,
            "withdrawal_batch_root",
            &self.withdrawal_batch_root,
        );
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerQuorumRecord {
    pub quorum_id: String,
    pub signer_hold_roots: BTreeMap<String, String>,
    pub aggregate_hold_root: String,
    pub unhold_vote_root: String,
    pub total_weight: u64,
    pub unhold_votes_observed: bool,
}

impl SignerQuorumRecord {
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "aggregate_hold_root", &self.aggregate_hold_root);
        push_pair(&mut out, "quorum_id", &self.quorum_id);
        push_u64(&mut out, "total_weight", self.total_weight);
        push_bool(
            &mut out,
            "unhold_votes_observed",
            self.unhold_votes_observed,
        );
        push_pair(&mut out, "unhold_vote_root", &self.unhold_vote_root);
        for (id, root) in &self.signer_hold_roots {
            push_pair(&mut out, &format!("signer_hold_root:{id}"), root);
        }
        out
    }

    pub fn signer_count(&self) -> u16 {
        bounded_u16(self.signer_hold_roots.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockerRecord {
    pub kind: BlockerKind,
    pub domain: EvidenceDomain,
    pub evidence_id: String,
    pub root: String,
    pub message: String,
}

impl BlockerRecord {
    pub fn new(
        kind: BlockerKind,
        domain: EvidenceDomain,
        evidence_id: impl Into<String>,
        root: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            domain,
            evidence_id: evidence_id.into(),
            root: normalize_root(root.into()),
            message: message.into(),
        }
    }

    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "domain", self.domain.as_str());
        push_pair(&mut out, "evidence_id", &self.evidence_id);
        push_pair(&mut out, "kind", self.kind.as_str());
        push_pair(&mut out, "message", &self.message);
        push_pair(&mut out, "root", &self.root);
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicRecord {
    pub archive_id: String,
    pub release_id: String,
    pub disposition: ReleaseDisposition,
    pub release_permitted: bool,
    pub state_root: String,
    pub public_root: String,
    pub blocker_root: String,
    pub custody_root: String,
    pub watcher_root: String,
    pub reserve_root: String,
    pub withdrawal_root: String,
    pub signer_root: String,
    pub privacy_record_count: u64,
    pub blocker_count: u64,
}

impl PublicRecord {
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "archive_id", &self.archive_id);
        push_pair(&mut out, "blocker_root", &self.blocker_root);
        push_u64(&mut out, "blocker_count", self.blocker_count);
        push_pair(&mut out, "custody_root", &self.custody_root);
        push_pair(&mut out, "disposition", self.disposition.as_str());
        push_u64(&mut out, "privacy_record_count", self.privacy_record_count);
        push_pair(&mut out, "public_root", &self.public_root);
        push_pair(&mut out, "release_id", &self.release_id);
        push_bool(&mut out, "release_permitted", self.release_permitted);
        push_pair(&mut out, "reserve_root", &self.reserve_root);
        push_pair(&mut out, "signer_root", &self.signer_root);
        push_pair(&mut out, "state_root", &self.state_root);
        push_pair(&mut out, "watcher_root", &self.watcher_root);
        push_pair(&mut out, "withdrawal_root", &self.withdrawal_root);
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub config: Config,
    pub privacy_records: BTreeMap<String, PrivacyRecord>,
    pub custody_proofs: BTreeMap<String, CustodyProof>,
    pub watcher_quorums: BTreeMap<String, WatcherQuorumRecord>,
    pub reserve_evidence: BTreeMap<String, ReserveEvidence>,
    pub withdrawal_holds: BTreeMap<String, WithdrawalHoldEvidence>,
    pub signer_quorums: BTreeMap<String, SignerQuorumRecord>,
    pub manual_blockers: BTreeMap<String, BlockerRecord>,
    pub captain_note: String,
    pub captain_no_go: bool,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            privacy_records: BTreeMap::new(),
            custody_proofs: BTreeMap::new(),
            watcher_quorums: BTreeMap::new(),
            reserve_evidence: BTreeMap::new(),
            withdrawal_holds: BTreeMap::new(),
            signer_quorums: BTreeMap::new(),
            manual_blockers: BTreeMap::new(),
            captain_note: "release held pending wave88 no-go evidence archive".to_string(),
            captain_no_go: true,
        })
    }

    pub fn insert_privacy_record(&mut self, record: PrivacyRecord) -> Result<()> {
        record.validate(self.config.replay_height, self.config.max_replay_age_blocks)?;
        self.privacy_records
            .insert(record.record_id.clone(), record);
        Ok(())
    }

    pub fn insert_custody_proof(&mut self, mut proof: CustodyProof) -> Result<()> {
        require_non_empty("proof_id", &proof.proof_id)?;
        require_non_empty("custodian_id", &proof.custodian_id)?;
        proof.wave88_decision_root = normalize_root(proof.wave88_decision_root);
        proof.custody_root = normalize_root(proof.custody_root);
        proof.bridge_pause_root = normalize_root(proof.bridge_pause_root);
        self.custody_proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_watcher_quorum(&mut self, mut record: WatcherQuorumRecord) -> Result<()> {
        require_non_empty("quorum_id", &record.quorum_id)?;
        record.observed_tip_root = normalize_root(record.observed_tip_root);
        record.reorg_root = normalize_root(record.reorg_root);
        record.watcher_roots = normalize_root_map(record.watcher_roots);
        self.watcher_quorums
            .insert(record.quorum_id.clone(), record);
        Ok(())
    }

    pub fn insert_reserve_evidence(&mut self, mut record: ReserveEvidence) -> Result<()> {
        require_non_empty("reserve_id", &record.reserve_id)?;
        record.liability_root = normalize_root(record.liability_root);
        record.reserve_root = normalize_root(record.reserve_root);
        record.reconciliation_root = normalize_root(record.reconciliation_root);
        record.proof_roots = normalize_root_set(record.proof_roots);
        self.reserve_evidence
            .insert(record.reserve_id.clone(), record);
        Ok(())
    }

    pub fn insert_withdrawal_hold(&mut self, mut record: WithdrawalHoldEvidence) -> Result<()> {
        require_non_empty("hold_id", &record.hold_id)?;
        record.withdrawal_batch_root = normalize_root(record.withdrawal_batch_root);
        record.nullifier_root = normalize_root(record.nullifier_root);
        record.recipient_commitment_root = normalize_root(record.recipient_commitment_root);
        record.release_attempt_root = normalize_root(record.release_attempt_root);
        self.withdrawal_holds.insert(record.hold_id.clone(), record);
        Ok(())
    }

    pub fn insert_signer_quorum(&mut self, mut record: SignerQuorumRecord) -> Result<()> {
        require_non_empty("quorum_id", &record.quorum_id)?;
        record.aggregate_hold_root = normalize_root(record.aggregate_hold_root);
        record.unhold_vote_root = normalize_root(record.unhold_vote_root);
        record.signer_hold_roots = normalize_root_map(record.signer_hold_roots);
        self.signer_quorums.insert(record.quorum_id.clone(), record);
        Ok(())
    }

    pub fn add_manual_blocker(
        &mut self,
        id: impl Into<String>,
        blocker: BlockerRecord,
    ) -> Result<()> {
        let key = id.into();
        require_non_empty("manual_blocker_id", &key)?;
        self.manual_blockers.insert(key, blocker);
        Ok(())
    }

    pub fn set_captain_note(&mut self, note: impl Into<String>) {
        self.captain_note = note.into();
    }

    pub fn set_captain_no_go(&mut self, no_go: bool) {
        self.captain_no_go = no_go;
    }

    pub fn blocker_records(&self) -> Vec<BlockerRecord> {
        let mut blockers = Vec::new();
        self.collect_custody_blockers(&mut blockers);
        self.collect_watcher_blockers(&mut blockers);
        self.collect_reserve_blockers(&mut blockers);
        self.collect_withdrawal_blockers(&mut blockers);
        self.collect_signer_blockers(&mut blockers);
        if self.captain_no_go {
            blockers.push(BlockerRecord::new(
                BlockerKind::ReleaseCaptainNoGo,
                EvidenceDomain::ReleaseDecision,
                "release-captain",
                self.release_decision_root(),
                &self.captain_note,
            ));
        }
        for blocker in self.manual_blockers.values() {
            blockers.push(blocker.clone());
        }
        blockers.sort_by(|a, b| {
            a.domain
                .cmp(&b.domain)
                .then(a.kind.cmp(&b.kind))
                .then(a.evidence_id.cmp(&b.evidence_id))
        });
        blockers
    }

    pub fn disposition(&self) -> ReleaseDisposition {
        if !self.config.fail_closed {
            return ReleaseDisposition::NoGo;
        }
        let blockers = self.blocker_records();
        if blockers.is_empty() {
            ReleaseDisposition::Go
        } else if self.captain_no_go {
            ReleaseDisposition::NoGo
        } else {
            ReleaseDisposition::ReleaseHeld
        }
    }

    pub fn release_permitted(&self) -> bool {
        self.disposition().permits_release()
    }

    pub fn public_record(&self) -> PublicRecord {
        let mut record = PublicRecord {
            archive_id: self.config.archive_id.clone(),
            release_id: self.config.release_id.clone(),
            disposition: self.disposition(),
            release_permitted: self.release_permitted(),
            state_root: self.state_root(),
            public_root: String::new(),
            blocker_root: self.blocker_root(),
            custody_root: self.custody_root(),
            watcher_root: self.watcher_root(),
            reserve_root: self.reserve_root(),
            withdrawal_root: self.withdrawal_root(),
            signer_root: self.signer_root(),
            privacy_record_count: self.privacy_records.len() as u64,
            blocker_count: self.blocker_records().len() as u64,
        };
        record.public_root = root_hex("public_record", &record.canonical());
        record
    }

    pub fn state_root(&self) -> String {
        let mut out = String::new();
        push_pair(
            &mut out,
            "config_root",
            &root_hex("config", &self.config.canonical()),
        );
        push_pair(&mut out, "custody_root", &self.custody_root());
        push_pair(&mut out, "watcher_root", &self.watcher_root());
        push_pair(&mut out, "reserve_root", &self.reserve_root());
        push_pair(&mut out, "withdrawal_root", &self.withdrawal_root());
        push_pair(&mut out, "signer_root", &self.signer_root());
        push_pair(&mut out, "privacy_root", &self.privacy_root());
        push_pair(&mut out, "blocker_root", &self.blocker_root());
        push_pair(
            &mut out,
            "release_decision_root",
            &self.release_decision_root(),
        );
        root_hex("state", &out)
    }

    pub fn privacy_root(&self) -> String {
        collection_root(
            "privacy_records",
            self.privacy_records
                .values()
                .map(|r| r.canonical())
                .collect::<Vec<String>>(),
        )
    }

    pub fn custody_root(&self) -> String {
        collection_root(
            "custody_proofs",
            self.custody_proofs
                .values()
                .map(|p| p.canonical())
                .collect::<Vec<String>>(),
        )
    }

    pub fn watcher_root(&self) -> String {
        collection_root(
            "watcher_quorums",
            self.watcher_quorums
                .values()
                .map(|q| q.canonical())
                .collect::<Vec<String>>(),
        )
    }

    pub fn reserve_root(&self) -> String {
        collection_root(
            "reserve_evidence",
            self.reserve_evidence
                .values()
                .map(|r| r.canonical())
                .collect::<Vec<String>>(),
        )
    }

    pub fn withdrawal_root(&self) -> String {
        collection_root(
            "withdrawal_holds",
            self.withdrawal_holds
                .values()
                .map(|h| h.canonical())
                .collect::<Vec<String>>(),
        )
    }

    pub fn signer_root(&self) -> String {
        collection_root(
            "signer_quorums",
            self.signer_quorums
                .values()
                .map(|q| q.canonical())
                .collect::<Vec<String>>(),
        )
    }

    pub fn blocker_root(&self) -> String {
        collection_root(
            "blockers",
            self.blocker_records()
                .iter()
                .map(|b| b.canonical())
                .collect::<Vec<String>>(),
        )
    }

    pub fn release_decision_root(&self) -> String {
        let mut out = String::new();
        push_pair(&mut out, "captain_note", &self.captain_note);
        push_bool(&mut out, "captain_no_go", self.captain_no_go);
        push_pair(
            &mut out,
            "disposition",
            self.disposition_without_decision_blocker().as_str(),
        );
        push_bool(&mut out, "fail_closed", self.config.fail_closed);
        root_hex("release_decision", &out)
    }

    fn disposition_without_decision_blocker(&self) -> ReleaseDisposition {
        if !self.config.fail_closed {
            return ReleaseDisposition::NoGo;
        }
        let mut blockers = Vec::new();
        self.collect_custody_blockers(&mut blockers);
        self.collect_watcher_blockers(&mut blockers);
        self.collect_reserve_blockers(&mut blockers);
        self.collect_withdrawal_blockers(&mut blockers);
        self.collect_signer_blockers(&mut blockers);
        for blocker in self.manual_blockers.values() {
            blockers.push(blocker.clone());
        }
        if blockers.is_empty() {
            ReleaseDisposition::Go
        } else {
            ReleaseDisposition::ReleaseHeld
        }
    }

    fn collect_custody_blockers(&self, blockers: &mut Vec<BlockerRecord>) {
        if self.custody_proofs.len() < self.config.min_custody_proofs as usize {
            blockers.push(BlockerRecord::new(
                BlockerKind::MissingBridgeCustodyProof,
                EvidenceDomain::BridgeCustody,
                "custody-proof-count",
                self.custody_root(),
                "bridge custody proof count below release gate minimum",
            ));
        }
        let mut required_decision_root = String::new();
        for proof in self.custody_proofs.values() {
            if required_decision_root.is_empty() {
                required_decision_root = proof.wave88_decision_root.clone();
            } else if required_decision_root != proof.wave88_decision_root {
                blockers.push(BlockerRecord::new(
                    BlockerKind::CustodyRootMismatch,
                    EvidenceDomain::BridgeCustody,
                    &proof.proof_id,
                    &proof.wave88_decision_root,
                    "custody proof points at a different wave88 decision root",
                ));
            }
            for kind in proof.validate(&self.config) {
                blockers.push(BlockerRecord::new(
                    kind,
                    EvidenceDomain::BridgeCustody,
                    &proof.proof_id,
                    &proof.custody_root,
                    "custody proof failed fail-closed validation",
                ));
            }
        }
    }

    fn collect_watcher_blockers(&self, blockers: &mut Vec<BlockerRecord>) {
        let best = self.best_watcher_quorum();
        match best {
            Some(record) => {
                if record.watcher_count() < self.config.min_watcher_quorum {
                    blockers.push(BlockerRecord::new(
                        BlockerKind::MoneroWatcherQuorumLow,
                        EvidenceDomain::MoneroWatcher,
                        &record.quorum_id,
                        &record.observed_tip_root,
                        "monero watcher quorum count below minimum",
                    ));
                }
                if record.total_weight < self.config.min_watcher_weight {
                    blockers.push(BlockerRecord::new(
                        BlockerKind::MoneroWatcherWeightLow,
                        EvidenceDomain::MoneroWatcher,
                        &record.quorum_id,
                        &record.observed_tip_root,
                        "monero watcher quorum weight below minimum",
                    ));
                }
                if self.config.require_monero_watcher_no_reorg && record.reorg_observed {
                    blockers.push(BlockerRecord::new(
                        BlockerKind::MoneroWatcherReorgObserved,
                        EvidenceDomain::MoneroWatcher,
                        &record.quorum_id,
                        &record.reorg_root,
                        "monero watcher recorded a reorg during replay window",
                    ));
                }
            }
            None => blockers.push(BlockerRecord::new(
                BlockerKind::MoneroWatcherQuorumLow,
                EvidenceDomain::MoneroWatcher,
                "watcher-quorum-missing",
                self.watcher_root(),
                "no monero watcher quorum record archived",
            )),
        }
    }

    fn collect_reserve_blockers(&self, blockers: &mut Vec<BlockerRecord>) {
        if self.reserve_evidence.len() < self.config.min_reserve_proofs as usize {
            blockers.push(BlockerRecord::new(
                BlockerKind::ReserveProofCountLow,
                EvidenceDomain::Reserve,
                "reserve-proof-count",
                self.reserve_root(),
                "reserve proof count below minimum",
            ));
        }
        for record in self.reserve_evidence.values() {
            if record.proof_roots.len() < self.config.min_reserve_proofs as usize {
                blockers.push(BlockerRecord::new(
                    BlockerKind::ReserveProofCountLow,
                    EvidenceDomain::Reserve,
                    &record.reserve_id,
                    &record.reconciliation_root,
                    "reserve reconciliation does not include enough proof roots",
                ));
            }
            if record.liability_root.is_empty() || record.reserve_root.is_empty() {
                blockers.push(BlockerRecord::new(
                    BlockerKind::ReserveLiabilityMismatch,
                    EvidenceDomain::Reserve,
                    &record.reserve_id,
                    &record.reconciliation_root,
                    "reserve or liability root missing",
                ));
            }
            if self.config.require_reserve_solvent && !record.solvent() {
                blockers.push(BlockerRecord::new(
                    BlockerKind::ReserveInsolvent,
                    EvidenceDomain::Reserve,
                    &record.reserve_id,
                    &record.reconciliation_root,
                    "reserve evidence is insolvent against archived liabilities",
                ));
            }
        }
    }

    fn collect_withdrawal_blockers(&self, blockers: &mut Vec<BlockerRecord>) {
        if self.withdrawal_holds.len() < self.config.min_withdrawal_holds as usize {
            blockers.push(BlockerRecord::new(
                BlockerKind::WithdrawalHoldCountLow,
                EvidenceDomain::Withdrawal,
                "withdrawal-hold-count",
                self.withdrawal_root(),
                "withdrawal hold evidence count below minimum",
            ));
        }
        for hold in self.withdrawal_holds.values() {
            if self.config.require_withdrawals_held && hold.hold_status.blocks_release() {
                blockers.push(BlockerRecord::new(
                    BlockerKind::WithdrawalReleaseAttempted,
                    EvidenceDomain::Withdrawal,
                    &hold.hold_id,
                    &hold.release_attempt_root,
                    "withdrawal hold is missing, disputed, or has a release attempt",
                ));
            }
        }
    }

    fn collect_signer_blockers(&self, blockers: &mut Vec<BlockerRecord>) {
        let best = self.best_signer_quorum();
        match best {
            Some(record) => {
                if record.signer_count() < self.config.min_signer_quorum {
                    blockers.push(BlockerRecord::new(
                        BlockerKind::SignerQuorumLow,
                        EvidenceDomain::SignerQuorum,
                        &record.quorum_id,
                        &record.aggregate_hold_root,
                        "signer quorum count below minimum",
                    ));
                }
                if record.total_weight < self.config.min_signer_weight {
                    blockers.push(BlockerRecord::new(
                        BlockerKind::SignerWeightLow,
                        EvidenceDomain::SignerQuorum,
                        &record.quorum_id,
                        &record.aggregate_hold_root,
                        "signer quorum weight below minimum",
                    ));
                }
                if self.config.require_signer_quorum_hold && record.unhold_votes_observed {
                    blockers.push(BlockerRecord::new(
                        BlockerKind::SignerUnholdVoteObserved,
                        EvidenceDomain::SignerQuorum,
                        &record.quorum_id,
                        &record.unhold_vote_root,
                        "signer quorum observed unhold votes",
                    ));
                }
            }
            None => blockers.push(BlockerRecord::new(
                BlockerKind::SignerQuorumLow,
                EvidenceDomain::SignerQuorum,
                "signer-quorum-missing",
                self.signer_root(),
                "no signer quorum hold record archived",
            )),
        }
    }

    fn best_watcher_quorum(&self) -> Option<&WatcherQuorumRecord> {
        self.watcher_quorums.values().max_by(|a, b| {
            a.total_weight
                .cmp(&b.total_weight)
                .then(a.watcher_count().cmp(&b.watcher_count()))
                .then(a.quorum_id.cmp(&b.quorum_id))
        })
    }

    fn best_signer_quorum(&self) -> Option<&SignerQuorumRecord> {
        self.signer_quorums.values().max_by(|a, b| {
            a.total_weight
                .cmp(&b.total_weight)
                .then(a.signer_count().cmp(&b.signer_count()))
                .then(a.quorum_id.cmp(&b.quorum_id))
        })
    }
}

pub fn devnet() -> State {
    let mut state = match State::new(Config::default()) {
        Ok(s) => s,
        Err(_) => State {
            config: Config::default(),
            privacy_records: BTreeMap::new(),
            custody_proofs: BTreeMap::new(),
            watcher_quorums: BTreeMap::new(),
            reserve_evidence: BTreeMap::new(),
            withdrawal_holds: BTreeMap::new(),
            signer_quorums: BTreeMap::new(),
            manual_blockers: BTreeMap::new(),
            captain_note: "release held by construction".to_string(),
            captain_no_go: true,
        },
    };

    let wave88_root = root_hex(
        "wave88-replay",
        "bridge custody reserve withdrawal signer blockers",
    );
    for idx in 0..4 {
        let id = format!("custody-proof-{idx}");
        let _ = state.insert_custody_proof(CustodyProof {
            proof_id: id,
            custodian_id: format!("custodian-{idx}"),
            wave88_decision_root: wave88_root.clone(),
            custody_root: root_hex("custody", &format!("custody-{idx}")),
            bridge_pause_root: root_hex("pause", &format!("pause-{idx}")),
            height: DEFAULT_REPLAY_HEIGHT.saturating_sub(idx as u64),
            held: true,
        });
    }

    let mut watchers = BTreeMap::new();
    for idx in 0..4 {
        watchers.insert(
            format!("watcher-{idx}"),
            root_hex("watcher", &format!("monero-tip-{idx}")),
        );
    }
    let _ = state.insert_watcher_quorum(WatcherQuorumRecord {
        quorum_id: "watcher-quorum-devnet".to_string(),
        watcher_roots: watchers,
        observed_tip_root: root_hex("monero-tip", "devnet-tip"),
        reorg_root: root_hex("monero-reorg", "none"),
        height: DEFAULT_REPLAY_HEIGHT,
        total_weight: 72,
        reorg_observed: false,
    });

    for idx in 0..3 {
        let mut roots = BTreeSet::new();
        roots.insert(root_hex("reserve-proof", &format!("reserve-proof-{idx}-a")));
        roots.insert(root_hex("reserve-proof", &format!("reserve-proof-{idx}-b")));
        roots.insert(root_hex("reserve-proof", &format!("reserve-proof-{idx}-c")));
        let _ = state.insert_reserve_evidence(ReserveEvidence {
            reserve_id: format!("reserve-{idx}"),
            liability_root: root_hex("liability", &format!("liability-{idx}")),
            reserve_root: root_hex("reserve", &format!("reserve-{idx}")),
            reconciliation_root: root_hex("reconciliation", &format!("reconciliation-{idx}")),
            proof_roots: roots,
            liabilities_atomic: 10_000 + idx as u128,
            reserves_atomic: 10_500 + idx as u128,
            height: DEFAULT_REPLAY_HEIGHT,
        });
    }

    for idx in 0..3 {
        let _ = state.insert_withdrawal_hold(WithdrawalHoldEvidence {
            hold_id: format!("withdrawal-hold-{idx}"),
            withdrawal_batch_root: root_hex("withdrawal-batch", &format!("batch-{idx}")),
            nullifier_root: root_hex("nullifier", &format!("nullifier-{idx}")),
            recipient_commitment_root: root_hex("recipient", &format!("recipient-{idx}")),
            hold_status: HoldStatus::Held,
            release_attempt_root: root_hex("release-attempt", "none"),
            height: DEFAULT_REPLAY_HEIGHT,
        });
    }

    let mut signers = BTreeMap::new();
    for idx in 0..5 {
        signers.insert(
            format!("signer-{idx}"),
            root_hex("signer-hold", &format!("signer-hold-{idx}")),
        );
    }
    let _ = state.insert_signer_quorum(SignerQuorumRecord {
        quorum_id: "signer-quorum-devnet".to_string(),
        signer_hold_roots: signers,
        aggregate_hold_root: root_hex("aggregate-hold", "devnet"),
        unhold_vote_root: root_hex("unhold-vote", "none"),
        total_weight: 84,
        unhold_votes_observed: false,
    });

    for domain in EvidenceDomain::all() {
        let id = format!("privacy-{}", domain.as_str());
        let _ = state.insert_privacy_record(PrivacyRecord::new(
            domain,
            id,
            "devnet",
            root_hex("privacy", domain.as_str()),
            DEFAULT_REPLAY_HEIGHT,
            "roots-only archive record",
        ));
    }
    state
}

pub fn public_record(state: &State) -> PublicRecord {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn archive_no_go_blocker(
    state: &mut State,
    id: impl Into<String>,
    domain: EvidenceDomain,
    kind: BlockerKind,
    evidence_id: impl Into<String>,
    root: impl Into<String>,
    message: impl Into<String>,
) -> Result<()> {
    state.add_manual_blocker(
        id,
        BlockerRecord::new(kind, domain, evidence_id, root, message),
    )
}

pub fn release_held(state: &State) -> bool {
    !state.release_permitted()
}

pub fn roots_only_record(domain: EvidenceDomain, id: &str, root: &str) -> PrivacyRecord {
    PrivacyRecord::new(
        domain,
        id,
        "roots-only",
        root,
        DEFAULT_REPLAY_HEIGHT,
        "redacted",
    )
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name}_required"))
    } else {
        Ok(())
    }
}

fn require_root(name: &str, value: &str) -> Result<()> {
    require_non_empty(name, value)?;
    if value == empty_root() {
        Err(format!("{name}_empty_root"))
    } else {
        Ok(())
    }
}

fn normalize_root(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn normalize_root_map(input: BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    for (key, value) in input {
        if !key.trim().is_empty() {
            output.insert(key, normalize_root(value));
        }
    }
    output
}

fn normalize_root_set(input: BTreeSet<String>) -> BTreeSet<String> {
    let mut output = BTreeSet::new();
    for value in input {
        let root = normalize_root(value);
        if !root.is_empty() {
            output.insert(root);
        }
    }
    output
}

fn bounded_u16(value: usize) -> u16 {
    if value > u16::MAX as usize {
        u16::MAX
    } else {
        value as u16
    }
}

fn push_pair(out: &mut String, key: &str, value: &str) {
    let _ = write!(out, "{}={};", escape(key), escape(value));
}

fn push_bool(out: &mut String, key: &str, value: bool) {
    let v = if value { "true" } else { "false" };
    push_pair(out, key, v);
}

fn push_u16(out: &mut String, key: &str, value: u16) {
    let _ = write!(out, "{}={};", escape(key), value);
}

fn push_u64(out: &mut String, key: &str, value: u64) {
    let _ = write!(out, "{}={};", escape(key), value);
}

fn push_u128(out: &mut String, key: &str, value: u128) {
    let _ = write!(out, "{}={};", escape(key), value);
}

fn escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn collection_root(domain: &str, mut items: Vec<String>) -> String {
    if items.is_empty() {
        return root_hex(domain, "empty");
    }
    items.sort();
    let mut level: Vec<String> = items
        .iter()
        .map(|item| root_hex(&format!("{domain}:leaf"), item))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut idx = 0usize;
        while idx < level.len() {
            let left = &level[idx];
            let right = if idx + 1 < level.len() {
                &level[idx + 1]
            } else {
                &level[idx]
            };
            next.push(root_hex(
                &format!("{domain}:node"),
                &format!("{left}:{right}"),
            ));
            idx += 2;
        }
        level = next;
    }
    match level.first() {
        Some(root) => root.clone(),
        None => root_hex(domain, "empty"),
    }
}

fn empty_root() -> &'static str {
    "0000000000000000000000000000000000000000000000000000000000000000"
}

fn root_hex(domain: &str, payload: &str) -> String {
    let mut h1 = std::collections::hash_map::DefaultHasher::new();
    domain.hash(&mut h1);
    payload.hash(&mut h1);
    let a = mix64(h1.finish() ^ 0x9e37_79b9_7f4a_7c15);

    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    payload.hash(&mut h2);
    domain.hash(&mut h2);
    let b = mix64(h2.finish() ^ 0xc2b2_ae3d_27d4_eb4f);

    let c = mix64(a ^ rotate_left(b, 17) ^ payload.len() as u64);
    let d = mix64(b ^ rotate_left(a, 31) ^ domain.len() as u64);
    format!("{a:016x}{b:016x}{c:016x}{d:016x}")
}

fn rotate_left(value: u64, bits: u32) -> u64 {
    value.rotate_left(bits)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
