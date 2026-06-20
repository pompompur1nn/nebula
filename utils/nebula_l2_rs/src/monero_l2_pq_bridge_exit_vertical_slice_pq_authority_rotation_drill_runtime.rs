use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSlicePqAuthorityRotationDrillRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_PQ_AUTHORITY_ROTATION_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-vertical-slice-pq-authority-rotation-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_PQ_AUTHORITY_ROTATION_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DRILL_SUITE: &str =
    "monero-private-l2-bridge-exit-pq-control-plane-authority-rotation-drill-v1";
pub const DEFAULT_MIN_WATCHERS: u16 = 5;
pub const DEFAULT_WATCHER_THRESHOLD: u16 = 4;
pub const DEFAULT_MIN_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ANNOUNCEMENT_GRACE_BLOCKS: u64 = 72;
pub const DEFAULT_OVERLAP_GRACE_BLOCKS: u64 = 144;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 288;
pub const DEFAULT_ROLLBACK_REVIEW_BLOCKS: u64 = 36;
pub const DEFAULT_UPGRADE_TIMELOCK_BLOCKS: u64 = 10_080;
pub const DEFAULT_MAX_DRILLS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityPlane {
    SequencerKeys,
    WatcherQuorumAttestations,
    BridgeReleaseAuthority,
    UpgradeAuthority,
    EmergencyWithdrawalAuthorization,
}

impl AuthorityPlane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerKeys => "sequencer_keys",
            Self::WatcherQuorumAttestations => "watcher_quorum_attestations",
            Self::BridgeReleaseAuthority => "bridge_release_authority",
            Self::UpgradeAuthority => "upgrade_authority",
            Self::EmergencyWithdrawalAuthorization => "emergency_withdrawal_authorization",
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::SequencerKeys,
            Self::WatcherQuorumAttestations,
            Self::BridgeReleaseAuthority,
            Self::UpgradeAuthority,
            Self::EmergencyWithdrawalAuthorization,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFamily {
    MlDsa,
    SlhDsa,
    HybridMlDsaEd25519,
    HybridSlhDsaEd25519,
}

impl SignatureFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa => "ml_dsa",
            Self::SlhDsa => "slh_dsa",
            Self::HybridMlDsaEd25519 => "hybrid_ml_dsa_ed25519",
            Self::HybridSlhDsaEd25519 => "hybrid_slh_dsa_ed25519",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillPhase {
    Announced,
    DualControlOverlap,
    WitnessedCutover,
    Quarantine,
    RollbackReview,
    Sealed,
}

impl DrillPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::DualControlOverlap => "dual_control_overlap",
            Self::WitnessedCutover => "witnessed_cutover",
            Self::Quarantine => "quarantine",
            Self::RollbackReview => "rollback_review",
            Self::Sealed => "sealed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Passed,
    Deferred,
    Quarantined,
    Blocked,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Deferred => "deferred",
            Self::Quarantined => "quarantined",
            Self::Blocked => "blocked",
        }
    }

    pub fn allows_drill_progress(self) -> bool {
        matches!(self, Self::Passed | Self::Deferred)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackGate {
    WatcherQuorumDispute,
    SequencerEquivocation,
    ReleaseAuthorityMismatch,
    UpgradeTimelockBypass,
    EmergencyWithdrawalPolicyDrift,
    QuarantineExpiry,
}

impl RollbackGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherQuorumDispute => "watcher_quorum_dispute",
            Self::SequencerEquivocation => "sequencer_equivocation",
            Self::ReleaseAuthorityMismatch => "release_authority_mismatch",
            Self::UpgradeTimelockBypass => "upgrade_timelock_bypass",
            Self::EmergencyWithdrawalPolicyDrift => "emergency_withdrawal_policy_drift",
            Self::QuarantineExpiry => "quarantine_expiry",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub drill_suite: String,
    pub min_watchers: u16,
    pub watcher_threshold: u16,
    pub min_security_bits: u16,
    pub announcement_grace_blocks: u64,
    pub overlap_grace_blocks: u64,
    pub quarantine_blocks: u64,
    pub rollback_review_blocks: u64,
    pub upgrade_timelock_blocks: u64,
    pub max_drills: usize,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            drill_suite: DRILL_SUITE.to_string(),
            min_watchers: DEFAULT_MIN_WATCHERS,
            watcher_threshold: DEFAULT_WATCHER_THRESHOLD,
            min_security_bits: DEFAULT_MIN_SECURITY_BITS,
            announcement_grace_blocks: DEFAULT_ANNOUNCEMENT_GRACE_BLOCKS,
            overlap_grace_blocks: DEFAULT_OVERLAP_GRACE_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            rollback_review_blocks: DEFAULT_ROLLBACK_REVIEW_BLOCKS,
            upgrade_timelock_blocks: DEFAULT_UPGRADE_TIMELOCK_BLOCKS,
            max_drills: DEFAULT_MAX_DRILLS,
            cargo_checks_deferred: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "drill_suite": self.drill_suite,
            "min_watchers": self.min_watchers,
            "watcher_threshold": self.watcher_threshold,
            "min_security_bits": self.min_security_bits,
            "announcement_grace_blocks": self.announcement_grace_blocks,
            "overlap_grace_blocks": self.overlap_grace_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "rollback_review_blocks": self.rollback_review_blocks,
            "upgrade_timelock_blocks": self.upgrade_timelock_blocks,
            "max_drills": self.max_drills,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAlgorithmLabel {
    pub label: String,
    pub family: SignatureFamily,
    pub nist_level: u8,
    pub security_bits: u16,
    pub implementation_note: String,
}

impl PqAlgorithmLabel {
    pub fn new(
        label: impl Into<String>,
        family: SignatureFamily,
        nist_level: u8,
        security_bits: u16,
        implementation_note: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            family,
            nist_level,
            security_bits,
            implementation_note: implementation_note.into(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "family": self.family.as_str(),
            "nist_level": self.nist_level,
            "security_bits": self.security_bits,
            "implementation_note": self.implementation_note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq_algorithm_label", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityKeyEpoch {
    pub epoch_id: String,
    pub plane: AuthorityPlane,
    pub phase: DrillPhase,
    pub previous_key_commitment: String,
    pub candidate_key_commitment: String,
    pub signature_label: PqAlgorithmLabel,
    pub announced_at_height: u64,
    pub effective_from_height: u64,
    pub quarantine_until_height: u64,
    pub release_blocked_during_quarantine: bool,
}

impl AuthorityKeyEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "plane": self.plane.as_str(),
            "phase": self.phase.as_str(),
            "previous_key_commitment": self.previous_key_commitment,
            "candidate_key_commitment": self.candidate_key_commitment,
            "signature_label": self.signature_label.public_record(),
            "announced_at_height": self.announced_at_height,
            "effective_from_height": self.effective_from_height,
            "quarantine_until_height": self.quarantine_until_height,
            "release_blocked_during_quarantine": self.release_blocked_during_quarantine,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_key_epoch", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub watcher_id: String,
    pub plane: AuthorityPlane,
    pub observed_epoch_id: String,
    pub attestation_root: String,
    pub signature_family: SignatureFamily,
    pub signed_height: u64,
    pub quarantine_vote: bool,
    pub rollback_vote: bool,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "plane": self.plane.as_str(),
            "observed_epoch_id": self.observed_epoch_id,
            "attestation_root": self.attestation_root,
            "signature_family": self.signature_family.as_str(),
            "signed_height": self.signed_height,
            "quarantine_vote": self.quarantine_vote,
            "rollback_vote": self.rollback_vote,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuorumCertificate {
    pub certificate_id: String,
    pub plane: AuthorityPlane,
    pub epoch_id: String,
    pub threshold: u16,
    pub observed_watchers: u16,
    pub attestation_root: String,
    pub quorum_met: bool,
    pub quarantine_votes: u16,
    pub rollback_votes: u16,
}

impl QuorumCertificate {
    pub fn from_attestations(
        plane: AuthorityPlane,
        epoch_id: impl Into<String>,
        threshold: u16,
        attestations: &[WatcherAttestation],
    ) -> Self {
        let epoch_id = epoch_id.into();
        let leaves = attestations
            .iter()
            .map(WatcherAttestation::public_record)
            .collect::<Vec<_>>();
        let attestation_root = merkle_root("pq-authority-rotation-attestations", &leaves);
        let observed_watchers = attestations.len() as u16;
        let quarantine_votes = attestations
            .iter()
            .filter(|attestation| attestation.quarantine_vote)
            .count() as u16;
        let rollback_votes = attestations
            .iter()
            .filter(|attestation| attestation.rollback_vote)
            .count() as u16;
        let certificate_id = domain_hash(
            "pq-authority-rotation-quorum-certificate-id",
            &[
                HashPart::Str(plane.as_str()),
                HashPart::Str(&epoch_id),
                HashPart::Str(&attestation_root),
                HashPart::U64(threshold as u64),
            ],
            16,
        );
        Self {
            certificate_id,
            plane,
            epoch_id,
            threshold,
            observed_watchers,
            attestation_root,
            quorum_met: observed_watchers >= threshold,
            quarantine_votes,
            rollback_votes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "plane": self.plane.as_str(),
            "epoch_id": self.epoch_id,
            "threshold": self.threshold,
            "observed_watchers": self.observed_watchers,
            "attestation_root": self.attestation_root,
            "quorum_met": self.quorum_met,
            "quarantine_votes": self.quarantine_votes,
            "rollback_votes": self.rollback_votes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("quorum_certificate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotationGate {
    pub gate_id: String,
    pub plane: AuthorityPlane,
    pub status: GateStatus,
    pub rollback_gate: Option<RollbackGate>,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub quarantine_required: bool,
    pub emergency_rollback_allowed: bool,
}

impl RotationGate {
    pub fn new(
        plane: AuthorityPlane,
        status: GateStatus,
        rollback_gate: Option<RollbackGate>,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_root: impl Into<String>,
        quarantine_required: bool,
        emergency_rollback_allowed: bool,
    ) -> Self {
        let requirement = requirement.into();
        let observed = observed.into();
        let evidence_root = evidence_root.into();
        let gate_id = domain_hash(
            "pq-authority-rotation-gate-id",
            &[
                HashPart::Str(plane.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(rollback_gate.map(RollbackGate::as_str).unwrap_or("none")),
                HashPart::Str(&requirement),
                HashPart::Str(&observed),
                HashPart::Str(&evidence_root),
            ],
            16,
        );
        Self {
            gate_id,
            plane,
            status,
            rollback_gate,
            requirement,
            observed,
            evidence_root,
            quarantine_required,
            emergency_rollback_allowed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "plane": self.plane.as_str(),
            "status": self.status.as_str(),
            "rollback_gate": self.rollback_gate.map(RollbackGate::as_str),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "quarantine_required": self.quarantine_required,
            "emergency_rollback_allowed": self.emergency_rollback_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rotation_gate", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub drill_runs: u64,
    pub authority_epochs: u64,
    pub watcher_attestations: u64,
    pub quorum_certificates: u64,
    pub rotation_gates: u64,
    pub quarantined_planes: u64,
    pub rollback_gates_armed: u64,
    pub blocked_release_planes: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "drill_runs": self.drill_runs,
            "authority_epochs": self.authority_epochs,
            "watcher_attestations": self.watcher_attestations,
            "quorum_certificates": self.quorum_certificates,
            "rotation_gates": self.rotation_gates,
            "quarantined_planes": self.quarantined_planes,
            "rollback_gates_armed": self.rollback_gates_armed,
            "blocked_release_planes": self.blocked_release_planes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub algorithm_label_root: String,
    pub authority_epoch_root: String,
    pub watcher_attestation_root: String,
    pub quorum_certificate_root: String,
    pub rotation_gate_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn new(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            algorithm_label_root: empty_root("algorithm-labels"),
            authority_epoch_root: empty_root("authority-epochs"),
            watcher_attestation_root: empty_root("watcher-attestations"),
            quorum_certificate_root: empty_root("quorum-certificates"),
            rotation_gate_root: empty_root("rotation-gates"),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "algorithm_label_root": self.algorithm_label_root,
            "authority_epoch_root": self.authority_epoch_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "quorum_certificate_root": self.quorum_certificate_root,
            "rotation_gate_root": self.rotation_gate_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "pq-authority-rotation-state-root",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.algorithm_label_root),
                HashPart::Str(&self.authority_epoch_root),
                HashPart::Str(&self.watcher_attestation_root),
                HashPart::Str(&self.quorum_certificate_root),
                HashPart::Str(&self.rotation_gate_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub algorithm_labels: BTreeMap<String, PqAlgorithmLabel>,
    pub authority_epochs: BTreeMap<String, AuthorityKeyEpoch>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub quorum_certificates: BTreeMap<String, QuorumCertificate>,
    pub rotation_gates: BTreeMap<String, RotationGate>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        Self {
            roots: Roots::new(&config, &counters),
            config,
            algorithm_labels: BTreeMap::new(),
            authority_epochs: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            quorum_certificates: BTreeMap::new(),
            rotation_gates: BTreeMap::new(),
            counters,
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.install_devnet_algorithm_labels();
        state.install_devnet_rotation_drill();
        state
    }

    pub fn add_algorithm_label(&mut self, label: PqAlgorithmLabel) -> Result<String> {
        if label.security_bits < self.config.min_security_bits {
            return Err("pq algorithm label below configured security floor".to_string());
        }
        let label_id = label.label.clone();
        if self.algorithm_labels.contains_key(&label_id) {
            return Err("pq algorithm label already registered".to_string());
        }
        self.algorithm_labels.insert(label_id.clone(), label);
        self.refresh_roots();
        Ok(label_id)
    }

    pub fn add_authority_epoch(&mut self, epoch: AuthorityKeyEpoch) -> Result<String> {
        if !self
            .algorithm_labels
            .contains_key(&epoch.signature_label.label)
        {
            return Err("authority epoch references unknown pq algorithm label".to_string());
        }
        if epoch.effective_from_height
            < epoch.announced_at_height + self.config.announcement_grace_blocks
        {
            return Err("authority epoch violates announcement grace window".to_string());
        }
        if epoch.quarantine_until_height
            < epoch.effective_from_height + self.config.quarantine_blocks
        {
            return Err("authority epoch violates quarantine window".to_string());
        }
        if self.authority_epochs.contains_key(&epoch.epoch_id) {
            return Err("authority epoch already registered".to_string());
        }
        let epoch_id = epoch.epoch_id.clone();
        self.authority_epochs.insert(epoch_id.clone(), epoch);
        self.refresh_roots();
        Ok(epoch_id)
    }

    pub fn add_watcher_attestation(&mut self, attestation: WatcherAttestation) -> Result<String> {
        if !self
            .authority_epochs
            .contains_key(&attestation.observed_epoch_id)
        {
            return Err("watcher attestation references unknown authority epoch".to_string());
        }
        let attestation_id = watcher_attestation_id(&attestation);
        if self.watcher_attestations.contains_key(&attestation_id) {
            return Err("watcher attestation already registered".to_string());
        }
        self.watcher_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn certify_quorum(&mut self, plane: AuthorityPlane, epoch_id: &str) -> Result<String> {
        if !self.authority_epochs.contains_key(epoch_id) {
            return Err("quorum certificate references unknown authority epoch".to_string());
        }
        let attestations = self
            .watcher_attestations
            .values()
            .filter(|attestation| {
                attestation.plane == plane && attestation.observed_epoch_id == epoch_id
            })
            .cloned()
            .collect::<Vec<_>>();
        if attestations.len() < self.config.min_watchers as usize {
            return Err("quorum certificate has too few watchers".to_string());
        }
        let certificate = QuorumCertificate::from_attestations(
            plane,
            epoch_id,
            self.config.watcher_threshold,
            &attestations,
        );
        if !certificate.quorum_met {
            return Err("watcher quorum threshold not met".to_string());
        }
        let certificate_id = certificate.certificate_id.clone();
        self.quorum_certificates
            .insert(certificate_id.clone(), certificate);
        self.refresh_roots();
        Ok(certificate_id)
    }

    pub fn add_rotation_gate(&mut self, gate: RotationGate) -> Result<String> {
        if gate.status == GateStatus::Blocked && gate.emergency_rollback_allowed {
            return Err("blocked gate cannot directly authorize emergency rollback".to_string());
        }
        let gate_id = gate.gate_id.clone();
        if self.rotation_gates.contains_key(&gate_id) {
            return Err("rotation gate already registered".to_string());
        }
        self.rotation_gates.insert(gate_id.clone(), gate);
        self.refresh_roots();
        Ok(gate_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "algorithm_labels": self.algorithm_labels.values().map(PqAlgorithmLabel::public_record).collect::<Vec<_>>(),
            "authority_epochs": self.authority_epochs.values().map(AuthorityKeyEpoch::public_record).collect::<Vec<_>>(),
            "watcher_attestations": self.watcher_attestations.values().map(WatcherAttestation::public_record).collect::<Vec<_>>(),
            "quorum_certificates": self.quorum_certificates.values().map(QuorumCertificate::public_record).collect::<Vec<_>>(),
            "rotation_gates": self.rotation_gates.values().map(RotationGate::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "cargo_checks_deferred": self.config.cargo_checks_deferred,
            "production_release_allowed": self.config.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.compute_counters();
        self.roots = Roots {
            config_root: self.config.state_root(),
            algorithm_label_root: map_root(
                "algorithm-labels",
                self.algorithm_labels
                    .iter()
                    .map(|(id, label)| (id.as_str(), label.state_root())),
            ),
            authority_epoch_root: map_root(
                "authority-epochs",
                self.authority_epochs
                    .iter()
                    .map(|(id, epoch)| (id.as_str(), epoch.state_root())),
            ),
            watcher_attestation_root: map_root(
                "watcher-attestations",
                self.watcher_attestations
                    .iter()
                    .map(|(id, attestation)| (id.as_str(), attestation.state_root())),
            ),
            quorum_certificate_root: map_root(
                "quorum-certificates",
                self.quorum_certificates
                    .iter()
                    .map(|(id, certificate)| (id.as_str(), certificate.state_root())),
            ),
            rotation_gate_root: map_root(
                "rotation-gates",
                self.rotation_gates
                    .iter()
                    .map(|(id, gate)| (id.as_str(), gate.state_root())),
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }

    fn compute_counters(&self) -> Counters {
        Counters {
            drill_runs: 1,
            authority_epochs: self.authority_epochs.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            quorum_certificates: self.quorum_certificates.len() as u64,
            rotation_gates: self.rotation_gates.len() as u64,
            quarantined_planes: self
                .rotation_gates
                .values()
                .filter(|gate| gate.quarantine_required)
                .count() as u64,
            rollback_gates_armed: self
                .rotation_gates
                .values()
                .filter(|gate| gate.emergency_rollback_allowed)
                .count() as u64,
            blocked_release_planes: self
                .authority_epochs
                .values()
                .filter(|epoch| epoch.release_blocked_during_quarantine)
                .count() as u64,
        }
    }

    fn install_devnet_algorithm_labels(&mut self) {
        for label in devnet_algorithm_labels() {
            let label_id = label.label.clone();
            self.algorithm_labels.insert(label_id, label);
        }
        self.refresh_roots();
    }

    fn install_devnet_rotation_drill(&mut self) {
        for plane in AuthorityPlane::all() {
            let label = match plane {
                AuthorityPlane::SequencerKeys => {
                    self.algorithm_labels["ML-DSA-87-control-plane"].clone()
                }
                AuthorityPlane::WatcherQuorumAttestations => {
                    self.algorithm_labels["SLH-DSA-SHAKE-256f-watcher-quorum"].clone()
                }
                AuthorityPlane::BridgeReleaseAuthority => {
                    self.algorithm_labels["hybrid-ML-DSA-87-Ed25519-release"].clone()
                }
                AuthorityPlane::UpgradeAuthority => {
                    self.algorithm_labels["hybrid-SLH-DSA-SHAKE-256f-Ed25519-upgrade"].clone()
                }
                AuthorityPlane::EmergencyWithdrawalAuthorization => {
                    self.algorithm_labels["ML-DSA-87-emergency-withdrawal"].clone()
                }
            };
            let epoch_id = authority_epoch_id(plane, 42_000, &label.label);
            let epoch = AuthorityKeyEpoch {
                epoch_id: epoch_id.clone(),
                plane,
                phase: DrillPhase::Quarantine,
                previous_key_commitment: commitment("previous", plane.as_str()),
                candidate_key_commitment: commitment("candidate", plane.as_str()),
                signature_label: label,
                announced_at_height: 42_000,
                effective_from_height: 42_000
                    + self.config.announcement_grace_blocks
                    + self.config.overlap_grace_blocks,
                quarantine_until_height: 42_000
                    + self.config.announcement_grace_blocks
                    + self.config.overlap_grace_blocks
                    + self.config.quarantine_blocks,
                release_blocked_during_quarantine: matches!(
                    plane,
                    AuthorityPlane::BridgeReleaseAuthority
                        | AuthorityPlane::EmergencyWithdrawalAuthorization
                ),
            };
            self.authority_epochs.insert(epoch_id.clone(), epoch);

            for watcher_index in 0..self.config.min_watchers {
                let attestation = WatcherAttestation {
                    watcher_id: format!("devnet-watcher-{watcher_index:02}"),
                    plane,
                    observed_epoch_id: epoch_id.clone(),
                    attestation_root: domain_hash(
                        "pq-authority-rotation-devnet-attestation",
                        &[
                            HashPart::Str(plane.as_str()),
                            HashPart::Str(&epoch_id),
                            HashPart::U64(watcher_index as u64),
                        ],
                        32,
                    ),
                    signature_family: SignatureFamily::HybridMlDsaEd25519,
                    signed_height: 42_300 + watcher_index as u64,
                    quarantine_vote: matches!(
                        plane,
                        AuthorityPlane::BridgeReleaseAuthority
                            | AuthorityPlane::EmergencyWithdrawalAuthorization
                    ),
                    rollback_vote: false,
                };
                let attestation_id = watcher_attestation_id(&attestation);
                self.watcher_attestations
                    .insert(attestation_id, attestation);
            }
        }

        let epoch_pairs = self
            .authority_epochs
            .values()
            .map(|epoch| (epoch.plane, epoch.epoch_id.clone()))
            .collect::<Vec<_>>();
        for (plane, epoch_id) in epoch_pairs {
            let attestations = self
                .watcher_attestations
                .values()
                .filter(|attestation| {
                    attestation.plane == plane && attestation.observed_epoch_id == epoch_id
                })
                .cloned()
                .collect::<Vec<_>>();
            let certificate = QuorumCertificate::from_attestations(
                plane,
                epoch_id,
                self.config.watcher_threshold,
                &attestations,
            );
            self.quorum_certificates
                .insert(certificate.certificate_id.clone(), certificate);
        }

        for gate in devnet_rotation_gates(&self.quorum_certificates) {
            self.rotation_gates.insert(gate.gate_id.clone(), gate);
        }
        self.refresh_roots();
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

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("pq-authority-rotation-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(&format!("pq-authority-rotation-{domain}"), &[])
}

pub fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| json!({ "id": id, "root": root }))
        .collect::<Vec<_>>();
    merkle_root(&format!("pq-authority-rotation-{domain}"), &leaves)
}

pub fn vector_root(domain: &str, records: &[Value]) -> String {
    merkle_root(&format!("pq-authority-rotation-{domain}"), records)
}

pub fn authority_epoch_id(plane: AuthorityPlane, announced_at_height: u64, label: &str) -> String {
    domain_hash(
        "pq-authority-rotation-epoch-id",
        &[
            HashPart::Str(plane.as_str()),
            HashPart::U64(announced_at_height),
            HashPart::Str(label),
        ],
        16,
    )
}

pub fn watcher_attestation_id(attestation: &WatcherAttestation) -> String {
    domain_hash(
        "pq-authority-rotation-watcher-attestation-id",
        &[
            HashPart::Str(&attestation.watcher_id),
            HashPart::Str(attestation.plane.as_str()),
            HashPart::Str(&attestation.observed_epoch_id),
            HashPart::Str(&attestation.attestation_root),
            HashPart::U64(attestation.signed_height),
        ],
        16,
    )
}

pub fn devnet_algorithm_labels() -> Vec<PqAlgorithmLabel> {
    vec![
        PqAlgorithmLabel::new(
            "ML-DSA-87-control-plane",
            SignatureFamily::MlDsa,
            5,
            256,
            "data label only; no signature implementation in this runtime",
        ),
        PqAlgorithmLabel::new(
            "SLH-DSA-SHAKE-256f-watcher-quorum",
            SignatureFamily::SlhDsa,
            5,
            256,
            "data label only; no signature implementation in this runtime",
        ),
        PqAlgorithmLabel::new(
            "hybrid-ML-DSA-87-Ed25519-release",
            SignatureFamily::HybridMlDsaEd25519,
            5,
            256,
            "hybrid label binds legacy release authority to PQ control-plane evidence",
        ),
        PqAlgorithmLabel::new(
            "hybrid-SLH-DSA-SHAKE-256f-Ed25519-upgrade",
            SignatureFamily::HybridSlhDsaEd25519,
            5,
            256,
            "hybrid label binds upgrade authority to watcher-attested PQ evidence",
        ),
        PqAlgorithmLabel::new(
            "ML-DSA-87-emergency-withdrawal",
            SignatureFamily::MlDsa,
            5,
            256,
            "data label only for emergency withdrawal authorization drill evidence",
        ),
    ]
}

pub fn devnet_rotation_gates(
    certificates: &BTreeMap<String, QuorumCertificate>,
) -> Vec<RotationGate> {
    AuthorityPlane::all()
        .into_iter()
        .map(|plane| {
            let evidence_root = certificates
                .values()
                .find(|certificate| certificate.plane == plane)
                .map(QuorumCertificate::state_root)
                .unwrap_or_else(|| empty_root("missing-quorum-certificate"));
            let quarantine_required = matches!(
                plane,
                AuthorityPlane::BridgeReleaseAuthority
                    | AuthorityPlane::EmergencyWithdrawalAuthorization
            );
            let rollback_gate = match plane {
                AuthorityPlane::SequencerKeys => Some(RollbackGate::SequencerEquivocation),
                AuthorityPlane::WatcherQuorumAttestations => {
                    Some(RollbackGate::WatcherQuorumDispute)
                }
                AuthorityPlane::BridgeReleaseAuthority => {
                    Some(RollbackGate::ReleaseAuthorityMismatch)
                }
                AuthorityPlane::UpgradeAuthority => Some(RollbackGate::UpgradeTimelockBypass),
                AuthorityPlane::EmergencyWithdrawalAuthorization => {
                    Some(RollbackGate::EmergencyWithdrawalPolicyDrift)
                }
            };
            RotationGate::new(
                plane,
                if quarantine_required {
                    GateStatus::Quarantined
                } else {
                    GateStatus::Passed
                },
                rollback_gate,
                "watcher quorum attests candidate PQ authority epoch and grace windows",
                "devnet drill evidence captured with release locked during quarantine where required",
                evidence_root,
                quarantine_required,
                quarantine_required,
            )
        })
        .collect()
}

fn commitment(prefix: &str, plane: &str) -> String {
    domain_hash(
        "pq-authority-rotation-key-commitment",
        &[HashPart::Str(prefix), HashPart::Str(plane)],
        32,
    )
}
