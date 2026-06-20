use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitPqWatcherQuorumFixtureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PQ_WATCHER_QUORUM_FIXTURE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-pq-watcher-quorum-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PQ_WATCHER_QUORUM_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const QUORUM_FIXTURE_SUITE: &str = "monero-l2-pq-bridge-exit-pq-watcher-quorum-fixture-v1";
pub const ML_DSA_DOMAIN_LABEL: &str = "ML-DSA-87:nebula:bridge-exit:watcher-quorum:v1";
pub const SLH_DSA_DOMAIN_LABEL: &str = "SLH-DSA-SHAKE-256f:nebula:bridge-exit:watcher-quorum:v1";
pub const SHAKE_TRANSCRIPT_DOMAIN_LABEL: &str =
    "SHAKE256:nebula:bridge-exit:watcher-quorum-canonical-transcript:v1";
pub const DEFAULT_CURRENT_SIGNER_EPOCH: u64 = 77;
pub const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MIN_EMERGENCY_WEIGHT_BPS: u16 = 8_000;
pub const DEFAULT_MAX_EPOCH_LAG: u64 = 1;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUARANTINE_EPOCHS: u64 = 3;
pub const DEFAULT_MAX_FIXTURES: usize = 256;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsaShake,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsaShake => "hybrid_ml_dsa_slh_dsa_shake",
        }
    }

    pub fn domain_label(self) -> &'static str {
        match self {
            Self::MlDsa87 => ML_DSA_DOMAIN_LABEL,
            Self::SlhDsaShake256f => SLH_DSA_DOMAIN_LABEL,
            Self::HybridMlDsaSlhDsaShake => SHAKE_TRANSCRIPT_DOMAIN_LABEL,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumFixtureKind {
    BridgeLockAttestation,
    BridgeReleaseAttestation,
    WithdrawalAuthorization,
    SignerSetEpochTransition,
    KeyRotationContinuity,
    EmergencyEscapeAuthority,
    UpgradeAuthority,
    FailClosedRejection,
}

impl QuorumFixtureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeLockAttestation => "bridge_lock_attestation",
            Self::BridgeReleaseAttestation => "bridge_release_attestation",
            Self::WithdrawalAuthorization => "withdrawal_authorization",
            Self::SignerSetEpochTransition => "signer_set_epoch_transition",
            Self::KeyRotationContinuity => "key_rotation_continuity",
            Self::EmergencyEscapeAuthority => "emergency_escape_authority",
            Self::UpgradeAuthority => "upgrade_authority",
            Self::FailClosedRejection => "fail_closed_rejection",
        }
    }

    pub fn all() -> [Self; 8] {
        [
            Self::BridgeLockAttestation,
            Self::BridgeReleaseAttestation,
            Self::WithdrawalAuthorization,
            Self::SignerSetEpochTransition,
            Self::KeyRotationContinuity,
            Self::EmergencyEscapeAuthority,
            Self::UpgradeAuthority,
            Self::FailClosedRejection,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumDecisionStatus {
    Authorized,
    Rejected,
    Quarantined,
}

impl QuorumDecisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Authorized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumRejectReason {
    None,
    InsufficientThresholdWeight,
    StaleSignerEpoch,
    MissingPqDomainBinding,
    WatcherQuarantined,
    DuplicateWatcherAttestation,
    CollusionClusterExceeded,
    PrivacyWitnessLinkage,
    ReleaseWithoutBridgeLock,
    WithdrawalIntentMismatch,
    EmergencyAuthorityMissing,
    UpgradeAuthorityMismatch,
}

impl QuorumRejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InsufficientThresholdWeight => "insufficient_threshold_weight",
            Self::StaleSignerEpoch => "stale_signer_epoch",
            Self::MissingPqDomainBinding => "missing_pq_domain_binding",
            Self::WatcherQuarantined => "watcher_quarantined",
            Self::DuplicateWatcherAttestation => "duplicate_watcher_attestation",
            Self::CollusionClusterExceeded => "collusion_cluster_exceeded",
            Self::PrivacyWitnessLinkage => "privacy_witness_linkage",
            Self::ReleaseWithoutBridgeLock => "release_without_bridge_lock",
            Self::WithdrawalIntentMismatch => "withdrawal_intent_mismatch",
            Self::EmergencyAuthorityMissing => "emergency_authority_missing",
            Self::UpgradeAuthorityMismatch => "upgrade_authority_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub quorum_fixture_suite: String,
    pub ml_dsa_domain_label: String,
    pub slh_dsa_domain_label: String,
    pub shake_transcript_domain_label: String,
    pub current_signer_epoch: u64,
    pub min_watcher_weight_bps: u16,
    pub min_emergency_weight_bps: u16,
    pub max_epoch_lag: u64,
    pub min_pq_security_bits: u16,
    pub quarantine_epochs: u64,
    pub fail_closed_on_rejection: bool,
    pub require_privacy_witness_commitments: bool,
    pub require_bridge_lock_before_release: bool,
    pub max_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            quorum_fixture_suite: QUORUM_FIXTURE_SUITE.to_string(),
            ml_dsa_domain_label: ML_DSA_DOMAIN_LABEL.to_string(),
            slh_dsa_domain_label: SLH_DSA_DOMAIN_LABEL.to_string(),
            shake_transcript_domain_label: SHAKE_TRANSCRIPT_DOMAIN_LABEL.to_string(),
            current_signer_epoch: DEFAULT_CURRENT_SIGNER_EPOCH,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            min_emergency_weight_bps: DEFAULT_MIN_EMERGENCY_WEIGHT_BPS,
            max_epoch_lag: DEFAULT_MAX_EPOCH_LAG,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quarantine_epochs: DEFAULT_QUARANTINE_EPOCHS,
            fail_closed_on_rejection: true,
            require_privacy_witness_commitments: true,
            require_bridge_lock_before_release: true,
            max_fixtures: DEFAULT_MAX_FIXTURES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "quorum_fixture_suite": self.quorum_fixture_suite,
            "ml_dsa_domain_label": self.ml_dsa_domain_label,
            "slh_dsa_domain_label": self.slh_dsa_domain_label,
            "shake_transcript_domain_label": self.shake_transcript_domain_label,
            "current_signer_epoch": self.current_signer_epoch,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "min_emergency_weight_bps": self.min_emergency_weight_bps,
            "max_epoch_lag": self.max_epoch_lag,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quarantine_epochs": self.quarantine_epochs,
            "fail_closed_on_rejection": self.fail_closed_on_rejection,
            "require_privacy_witness_commitments": self.require_privacy_witness_commitments,
            "require_bridge_lock_before_release": self.require_bridge_lock_before_release,
            "max_fixtures": self.max_fixtures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherSigner {
    pub watcher_id: String,
    pub operator_commitment: String,
    pub scheme: PqSignatureScheme,
    pub signer_epoch: u64,
    pub weight_bps: u16,
    pub pq_security_bits: u16,
    pub public_key_commitment: String,
    pub rotation_parent_root: String,
    pub quarantine_until_epoch: u64,
    pub collusion_cluster: String,
}

impl WatcherSigner {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "operator_commitment": self.operator_commitment,
            "scheme": self.scheme.as_str(),
            "domain_label": self.scheme.domain_label(),
            "signer_epoch": self.signer_epoch,
            "weight_bps": self.weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "public_key_commitment": self.public_key_commitment,
            "rotation_parent_root": self.rotation_parent_root,
            "quarantine_until_epoch": self.quarantine_until_epoch,
            "collusion_cluster": self.collusion_cluster,
        })
    }

    pub fn signer_root(&self) -> String {
        record_root("watcher_signer", &self.public_record())
    }

    pub fn is_quarantined(&self, current_epoch: u64) -> bool {
        self.quarantine_until_epoch >= current_epoch
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerSetEpoch {
    pub epoch: u64,
    pub activation_height: u64,
    pub previous_signer_set_root: String,
    pub signer_set_root: String,
    pub rotation_root: String,
    pub threshold_policy_root: String,
    pub upgrade_authority_root: String,
    pub emergency_authority_root: String,
}

impl SignerSetEpoch {
    pub fn from_signers(
        epoch: u64,
        activation_height: u64,
        previous_signer_set_root: &str,
        signers: &[WatcherSigner],
        min_watcher_weight_bps: u16,
        min_emergency_weight_bps: u16,
    ) -> Self {
        let signer_records = signers
            .iter()
            .map(WatcherSigner::public_record)
            .collect::<Vec<_>>();
        let signer_set_root = merkle_records("PQ-WATCHER-QUORUM-SIGNER-SET", &signer_records);
        let rotation_root = domain_hash(
            "PQ-WATCHER-QUORUM-KEY-ROTATION-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(epoch),
                HashPart::Str(previous_signer_set_root),
                HashPart::Str(&signer_set_root),
            ],
            32,
        );
        let threshold_policy_root = threshold_policy_root(
            epoch,
            min_watcher_weight_bps,
            min_emergency_weight_bps,
            signers.len() as u64,
        );
        let upgrade_authority_root = authority_root("upgrade", epoch, &signer_set_root);
        let emergency_authority_root = authority_root("emergency_escape", epoch, &signer_set_root);
        Self {
            epoch,
            activation_height,
            previous_signer_set_root: previous_signer_set_root.to_string(),
            signer_set_root,
            rotation_root,
            threshold_policy_root,
            upgrade_authority_root,
            emergency_authority_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "activation_height": self.activation_height,
            "previous_signer_set_root": self.previous_signer_set_root,
            "signer_set_root": self.signer_set_root,
            "rotation_root": self.rotation_root,
            "threshold_policy_root": self.threshold_policy_root,
            "upgrade_authority_root": self.upgrade_authority_root,
            "emergency_authority_root": self.emergency_authority_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub fixture_id: String,
    pub kind: QuorumFixtureKind,
    pub signer_epoch: u64,
    pub scheme: PqSignatureScheme,
    pub weight_bps: u16,
    pub pq_domain_label: String,
    pub message_root: String,
    pub signature_commitment: String,
    pub witness_commitment_root: String,
    pub bridge_lock_root: String,
    pub release_claim_root: String,
    pub withdrawal_authorization_root: String,
}

impl WatcherAttestation {
    pub fn from_fixture(
        signer: &WatcherSigner,
        fixture_id: &str,
        kind: QuorumFixtureKind,
        signer_epoch: u64,
        bridge_lock_root: &str,
        release_claim_root: &str,
        withdrawal_authorization_root: &str,
    ) -> Self {
        let witness_commitment_root = witness_commitment_root(fixture_id, &signer.watcher_id);
        let message_root = domain_hash(
            "PQ-WATCHER-QUORUM-ATTESTATION-MESSAGE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(fixture_id),
                HashPart::Str(kind.as_str()),
                HashPart::U64(signer_epoch),
                HashPart::Str(bridge_lock_root),
                HashPart::Str(release_claim_root),
                HashPart::Str(withdrawal_authorization_root),
                HashPart::Str(&witness_commitment_root),
            ],
            32,
        );
        let signature_commitment = domain_hash(
            "PQ-WATCHER-QUORUM-SIGNATURE-COMMITMENT",
            &[
                HashPart::Str(signer.scheme.domain_label()),
                HashPart::Str(&signer.public_key_commitment),
                HashPart::Str(&message_root),
            ],
            32,
        );
        let attestation_id = domain_hash(
            "PQ-WATCHER-QUORUM-ATTESTATION-ID",
            &[
                HashPart::Str(&signer.watcher_id),
                HashPart::Str(fixture_id),
                HashPart::Str(&signature_commitment),
            ],
            32,
        );
        Self {
            attestation_id,
            watcher_id: signer.watcher_id.clone(),
            fixture_id: fixture_id.to_string(),
            kind,
            signer_epoch,
            scheme: signer.scheme,
            weight_bps: signer.weight_bps,
            pq_domain_label: signer.scheme.domain_label().to_string(),
            message_root,
            signature_commitment,
            witness_commitment_root,
            bridge_lock_root: bridge_lock_root.to_string(),
            release_claim_root: release_claim_root.to_string(),
            withdrawal_authorization_root: withdrawal_authorization_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "fixture_id": self.fixture_id,
            "kind": self.kind.as_str(),
            "signer_epoch": self.signer_epoch,
            "scheme": self.scheme.as_str(),
            "pq_domain_label": self.pq_domain_label,
            "weight_bps": self.weight_bps,
            "message_root": self.message_root,
            "signature_commitment": self.signature_commitment,
            "witness_commitment_root": self.witness_commitment_root,
            "bridge_lock_root": self.bridge_lock_root,
            "release_claim_root": self.release_claim_root,
            "withdrawal_authorization_root": self.withdrawal_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuorumFixture {
    pub fixture_id: String,
    pub kind: QuorumFixtureKind,
    pub signer_epoch: u64,
    pub transfer_id: String,
    pub bridge_lock_root: String,
    pub release_claim_root: String,
    pub withdrawal_authorization_root: String,
    pub privacy_witness_root: String,
    pub signer_set_root: String,
    pub threshold_policy_root: String,
    pub quorum_attestation_root: String,
    pub control_plane_auth_root: String,
    pub emergency_authority_root: String,
    pub upgrade_authority_root: String,
    pub total_weight_bps: u16,
    pub accepted_weight_bps: u16,
    pub rejected_reason: QuorumRejectReason,
    pub status: QuorumDecisionStatus,
}

impl QuorumFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "kind": self.kind.as_str(),
            "signer_epoch": self.signer_epoch,
            "transfer_id": self.transfer_id,
            "bridge_lock_root": self.bridge_lock_root,
            "release_claim_root": self.release_claim_root,
            "withdrawal_authorization_root": self.withdrawal_authorization_root,
            "privacy_witness_root": self.privacy_witness_root,
            "signer_set_root": self.signer_set_root,
            "threshold_policy_root": self.threshold_policy_root,
            "quorum_attestation_root": self.quorum_attestation_root,
            "control_plane_auth_root": self.control_plane_auth_root,
            "emergency_authority_root": self.emergency_authority_root,
            "upgrade_authority_root": self.upgrade_authority_root,
            "total_weight_bps": self.total_weight_bps,
            "accepted_weight_bps": self.accepted_weight_bps,
            "rejected_reason": self.rejected_reason.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn fixture_root(&self) -> String {
        record_root("quorum_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedCase {
    pub case_id: String,
    pub fixture_id: String,
    pub rejected_reason: QuorumRejectReason,
    pub observed_status: QuorumDecisionStatus,
    pub policy: String,
    pub evidence_root: String,
    pub release_block_root: String,
}

impl FailClosedCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "fixture_id": self.fixture_id,
            "rejected_reason": self.rejected_reason.as_str(),
            "observed_status": self.observed_status.as_str(),
            "policy": self.policy,
            "evidence_root": self.evidence_root,
            "release_block_root": self.release_block_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub signers: BTreeMap<String, WatcherSigner>,
    pub signer_epochs: BTreeMap<u64, SignerSetEpoch>,
    pub attestations: BTreeMap<String, WatcherAttestation>,
    pub fixtures: BTreeMap<String, QuorumFixture>,
    pub fail_closed_cases: BTreeMap<String, FailClosedCase>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let signers = devnet_signers(&config);
        let signer_vec = signers.values().cloned().collect::<Vec<_>>();
        let previous_signer_set_root = label_root("previous-signer-set", "epoch-76");
        let signer_epoch = SignerSetEpoch::from_signers(
            config.current_signer_epoch,
            982_144,
            &previous_signer_set_root,
            &signer_vec,
            config.min_watcher_weight_bps,
            config.min_emergency_weight_bps,
        );
        let mut signer_epochs = BTreeMap::new();
        signer_epochs.insert(signer_epoch.epoch, signer_epoch.clone());
        let fixtures = build_devnet_fixtures(&config, &signer_vec, &signer_epoch);
        let attestations = build_devnet_attestations(&config, &signer_vec, &fixtures);
        let fail_closed_cases = fixtures
            .values()
            .filter(|fixture| !fixture.status.passes())
            .map(|fixture| {
                let case = FailClosedCase {
                    case_id: domain_hash(
                        "PQ-WATCHER-QUORUM-FAIL-CLOSED-CASE-ID",
                        &[
                            HashPart::Str(&fixture.fixture_id),
                            HashPart::Str(fixture.rejected_reason.as_str()),
                        ],
                        32,
                    ),
                    fixture_id: fixture.fixture_id.clone(),
                    rejected_reason: fixture.rejected_reason,
                    observed_status: fixture.status,
                    policy: "fail_closed_no_release_without_epoch_fresh_pq_threshold".to_string(),
                    evidence_root: fixture.fixture_root(),
                    release_block_root: domain_hash(
                        "PQ-WATCHER-QUORUM-RELEASE-BLOCK-ROOT",
                        &[
                            HashPart::Str(&fixture.fixture_id),
                            HashPart::Str(fixture.status.as_str()),
                        ],
                        32,
                    ),
                };
                (case.case_id.clone(), case)
            })
            .collect::<BTreeMap<_, _>>();
        Self {
            config,
            signers,
            signer_epochs,
            attestations,
            fixtures,
            fail_closed_cases,
        }
    }

    pub fn public_record(&self) -> Value {
        let signer_records = self
            .signers
            .values()
            .map(WatcherSigner::public_record)
            .collect::<Vec<_>>();
        let epoch_records = self
            .signer_epochs
            .values()
            .map(SignerSetEpoch::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(WatcherAttestation::public_record)
            .collect::<Vec<_>>();
        let fixture_records = self
            .fixtures
            .values()
            .map(QuorumFixture::public_record)
            .collect::<Vec<_>>();
        let fail_closed_records = self
            .fail_closed_cases
            .values()
            .map(FailClosedCase::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "signer_count": self.signers.len(),
            "signer_epoch_count": self.signer_epochs.len(),
            "attestation_count": self.attestations.len(),
            "fixture_count": self.fixtures.len(),
            "fail_closed_case_count": self.fail_closed_cases.len(),
            "signer_root": merkle_records("PQ-WATCHER-QUORUM-PUBLIC-SIGNERS", &signer_records),
            "signer_epoch_root": merkle_records("PQ-WATCHER-QUORUM-PUBLIC-EPOCHS", &epoch_records),
            "attestation_root": merkle_records("PQ-WATCHER-QUORUM-PUBLIC-ATTESTATIONS", &attestation_records),
            "fixture_root": merkle_records("PQ-WATCHER-QUORUM-PUBLIC-FIXTURES", &fixture_records),
            "fail_closed_root": merkle_records("PQ-WATCHER-QUORUM-PUBLIC-FAIL-CLOSED", &fail_closed_records),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn evaluate_fixture(&self, fixture_id: &str) -> Result<QuorumDecisionStatus> {
        let fixture = self
            .fixtures
            .get(fixture_id)
            .ok_or_else(|| format!("unknown pq watcher quorum fixture: {fixture_id}"))?;
        Ok(fixture.status)
    }

    pub fn accepted_fixtures(&self) -> Vec<&QuorumFixture> {
        self.fixtures
            .values()
            .filter(|fixture| fixture.status.passes())
            .collect()
    }

    pub fn rejected_fixtures(&self) -> Vec<&QuorumFixture> {
        self.fixtures
            .values()
            .filter(|fixture| !fixture.status.passes())
            .collect()
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

pub fn quorum_fixture_root(fixture: &QuorumFixture) -> String {
    fixture.fixture_root()
}

pub fn threshold_policy_root(
    signer_epoch: u64,
    min_watcher_weight_bps: u16,
    min_emergency_weight_bps: u16,
    signer_count: u64,
) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-THRESHOLD-POLICY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(signer_epoch),
            HashPart::U64(min_watcher_weight_bps as u64),
            HashPart::U64(min_emergency_weight_bps as u64),
            HashPart::U64(signer_count),
        ],
        32,
    )
}

fn build_devnet_fixtures(
    config: &Config,
    signers: &[WatcherSigner],
    signer_epoch: &SignerSetEpoch,
) -> BTreeMap<String, QuorumFixture> {
    QuorumFixtureKind::all()
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            let fixture = build_fixture(config, signers, signer_epoch, *kind, index as u64);
            (fixture.fixture_id.clone(), fixture)
        })
        .collect()
}

fn build_devnet_attestations(
    config: &Config,
    signers: &[WatcherSigner],
    fixtures: &BTreeMap<String, QuorumFixture>,
) -> BTreeMap<String, WatcherAttestation> {
    let mut attestations = BTreeMap::new();
    for fixture in fixtures.values() {
        for signer in signers.iter().filter(|signer| {
            !signer.is_quarantined(config.current_signer_epoch)
                && signer.pq_security_bits >= config.min_pq_security_bits
        }) {
            let attestation = WatcherAttestation::from_fixture(
                signer,
                &fixture.fixture_id,
                fixture.kind,
                fixture.signer_epoch,
                &fixture.bridge_lock_root,
                &fixture.release_claim_root,
                &fixture.withdrawal_authorization_root,
            );
            attestations.insert(attestation.attestation_id.clone(), attestation);
        }
    }
    attestations
}

fn build_fixture(
    config: &Config,
    signers: &[WatcherSigner],
    signer_epoch: &SignerSetEpoch,
    kind: QuorumFixtureKind,
    ordinal: u64,
) -> QuorumFixture {
    let transfer_id = domain_hash(
        "PQ-WATCHER-QUORUM-TRANSFER-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::U64(ordinal)],
        32,
    );
    let fixture_id = domain_hash(
        "PQ-WATCHER-QUORUM-FIXTURE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(&transfer_id),
        ],
        32,
    );
    let stale_epoch = matches!(
        kind,
        QuorumFixtureKind::SignerSetEpochTransition | QuorumFixtureKind::FailClosedRejection
    );
    let signer_epoch_number = if stale_epoch {
        config
            .current_signer_epoch
            .saturating_sub(config.max_epoch_lag + 1)
    } else {
        config.current_signer_epoch
    };
    let bridge_lock_root = bridge_lock_root(&transfer_id, ordinal);
    let release_claim_root = release_claim_root(&transfer_id, &bridge_lock_root, ordinal);
    let withdrawal_authorization_root =
        withdrawal_authorization_root(&transfer_id, &release_claim_root, ordinal);
    let privacy_witness_root = privacy_witness_set_root(&fixture_id, ordinal);
    let accepted_signers = accepted_signers(config, signers, signer_epoch_number, kind);
    let total_weight_bps = signers.iter().map(|signer| signer.weight_bps).sum::<u16>();
    let accepted_weight_bps = accepted_signers
        .iter()
        .map(|signer| signer.weight_bps)
        .sum::<u16>();
    let attestation_records = accepted_signers
        .iter()
        .map(|signer| {
            WatcherAttestation::from_fixture(
                signer,
                &fixture_id,
                kind,
                signer_epoch_number,
                &bridge_lock_root,
                &release_claim_root,
                &withdrawal_authorization_root,
            )
            .public_record()
        })
        .collect::<Vec<_>>();
    let quorum_attestation_root =
        merkle_records("PQ-WATCHER-QUORUM-ATTESTATION-SET", &attestation_records);
    let rejected_reason = reject_reason(
        config,
        kind,
        signer_epoch_number,
        accepted_weight_bps,
        &accepted_signers,
        &bridge_lock_root,
        &release_claim_root,
    );
    let status = if rejected_reason == QuorumRejectReason::None {
        QuorumDecisionStatus::Authorized
    } else if matches!(rejected_reason, QuorumRejectReason::WatcherQuarantined) {
        QuorumDecisionStatus::Quarantined
    } else {
        QuorumDecisionStatus::Rejected
    };
    let control_plane_auth_root = domain_hash(
        "PQ-WATCHER-QUORUM-CONTROL-PLANE-AUTH-ROOT",
        &[
            HashPart::Str(&fixture_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(signer_epoch_number),
            HashPart::Str(&signer_epoch.signer_set_root),
            HashPart::Str(&signer_epoch.threshold_policy_root),
            HashPart::Str(&quorum_attestation_root),
            HashPart::Str(status.as_str()),
        ],
        32,
    );
    QuorumFixture {
        fixture_id,
        kind,
        signer_epoch: signer_epoch_number,
        transfer_id,
        bridge_lock_root,
        release_claim_root,
        withdrawal_authorization_root,
        privacy_witness_root,
        signer_set_root: signer_epoch.signer_set_root.clone(),
        threshold_policy_root: signer_epoch.threshold_policy_root.clone(),
        quorum_attestation_root,
        control_plane_auth_root,
        emergency_authority_root: signer_epoch.emergency_authority_root.clone(),
        upgrade_authority_root: signer_epoch.upgrade_authority_root.clone(),
        total_weight_bps,
        accepted_weight_bps,
        rejected_reason,
        status,
    }
}

fn accepted_signers<'a>(
    config: &Config,
    signers: &'a [WatcherSigner],
    signer_epoch: u64,
    kind: QuorumFixtureKind,
) -> Vec<&'a WatcherSigner> {
    signers
        .iter()
        .filter(|signer| signer.signer_epoch == signer_epoch)
        .filter(|signer| !signer.is_quarantined(config.current_signer_epoch))
        .filter(|signer| signer.pq_security_bits >= config.min_pq_security_bits)
        .filter(|signer| {
            !matches!(kind, QuorumFixtureKind::FailClosedRejection)
                || signer.collusion_cluster == "cluster_alpha"
        })
        .collect()
}

fn reject_reason(
    config: &Config,
    kind: QuorumFixtureKind,
    signer_epoch: u64,
    accepted_weight_bps: u16,
    accepted_signers: &[&WatcherSigner],
    bridge_lock_root: &str,
    release_claim_root: &str,
) -> QuorumRejectReason {
    if config.current_signer_epoch.saturating_sub(signer_epoch) > config.max_epoch_lag {
        return QuorumRejectReason::StaleSignerEpoch;
    }
    if accepted_signers.is_empty() {
        return QuorumRejectReason::InsufficientThresholdWeight;
    }
    if has_duplicate_watchers(accepted_signers) {
        return QuorumRejectReason::DuplicateWatcherAttestation;
    }
    if accepted_signers
        .iter()
        .any(|signer| signer.is_quarantined(config.current_signer_epoch))
    {
        return QuorumRejectReason::WatcherQuarantined;
    }
    if accepted_signers
        .iter()
        .any(|signer| signer.scheme.domain_label().is_empty())
    {
        return QuorumRejectReason::MissingPqDomainBinding;
    }
    if collusion_cluster_weight(accepted_signers) > config.min_watcher_weight_bps {
        return QuorumRejectReason::CollusionClusterExceeded;
    }
    if matches!(kind, QuorumFixtureKind::BridgeReleaseAttestation)
        && config.require_bridge_lock_before_release
        && bridge_lock_root == release_claim_root
    {
        return QuorumRejectReason::ReleaseWithoutBridgeLock;
    }
    if matches!(kind, QuorumFixtureKind::EmergencyEscapeAuthority)
        && accepted_weight_bps < config.min_emergency_weight_bps
    {
        return QuorumRejectReason::EmergencyAuthorityMissing;
    }
    if matches!(kind, QuorumFixtureKind::UpgradeAuthority)
        && accepted_weight_bps < config.min_emergency_weight_bps
    {
        return QuorumRejectReason::UpgradeAuthorityMismatch;
    }
    if accepted_weight_bps < config.min_watcher_weight_bps {
        return QuorumRejectReason::InsufficientThresholdWeight;
    }
    QuorumRejectReason::None
}

fn devnet_signers(config: &Config) -> BTreeMap<String, WatcherSigner> {
    [
        (
            "watcher_alpha",
            PqSignatureScheme::MlDsa87,
            2_500,
            "cluster_alpha",
            0,
        ),
        (
            "watcher_beta",
            PqSignatureScheme::SlhDsaShake256f,
            2_400,
            "cluster_beta",
            0,
        ),
        (
            "watcher_gamma",
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            2_300,
            "cluster_gamma",
            0,
        ),
        (
            "watcher_delta",
            PqSignatureScheme::MlDsa87,
            1_800,
            "cluster_delta",
            config.current_signer_epoch + config.quarantine_epochs,
        ),
        (
            "watcher_epsilon",
            PqSignatureScheme::SlhDsaShake256f,
            1_000,
            "cluster_alpha",
            0,
        ),
    ]
    .into_iter()
    .map(
        |(watcher_id, scheme, weight_bps, cluster, quarantine_until_epoch)| {
            let watcher_id = watcher_id.to_string();
            let public_key_commitment = domain_hash(
                "PQ-WATCHER-QUORUM-PUBLIC-KEY-COMMITMENT",
                &[
                    HashPart::Str(&watcher_id),
                    HashPart::Str(scheme.domain_label()),
                    HashPart::U64(config.current_signer_epoch),
                ],
                32,
            );
            let signer = WatcherSigner {
                watcher_id: watcher_id.clone(),
                operator_commitment: label_root("operator", &watcher_id),
                scheme,
                signer_epoch: config.current_signer_epoch,
                weight_bps,
                pq_security_bits: config.min_pq_security_bits,
                public_key_commitment,
                rotation_parent_root: label_root("rotation-parent", &watcher_id),
                quarantine_until_epoch,
                collusion_cluster: cluster.to_string(),
            };
            (watcher_id, signer)
        },
    )
    .collect()
}

fn bridge_lock_root(transfer_id: &str, ordinal: u64) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-BRIDGE-LOCK-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transfer_id),
            HashPart::U64(ordinal),
            HashPart::Str("monero_lock_observed"),
        ],
        32,
    )
}

fn release_claim_root(transfer_id: &str, bridge_lock_root: &str, ordinal: u64) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-BRIDGE-RELEASE-CLAIM-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transfer_id),
            HashPart::Str(bridge_lock_root),
            HashPart::U64(ordinal),
            HashPart::Str("release_claim_bound_to_lock"),
        ],
        32,
    )
}

fn withdrawal_authorization_root(
    transfer_id: &str,
    release_claim_root: &str,
    ordinal: u64,
) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-WITHDRAWAL-AUTHORIZATION-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transfer_id),
            HashPart::Str(release_claim_root),
            HashPart::U64(ordinal),
            HashPart::Str("private_withdrawal_intent_commitment_bound"),
        ],
        32,
    )
}

fn witness_commitment_root(fixture_id: &str, watcher_id: &str) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-PRIVACY-WITNESS-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(fixture_id),
            HashPart::Str(watcher_id),
            HashPart::Str("amount_destination_key_image_hidden"),
        ],
        32,
    )
}

fn privacy_witness_set_root(fixture_id: &str, ordinal: u64) -> String {
    let records = (0..4)
        .map(|index| {
            json!({
                "fixture_id": fixture_id,
                "witness_position": index,
                "commitment": domain_hash(
                    "PQ-WATCHER-QUORUM-PRIVACY-WITNESS-SET-LEAF",
                    &[HashPart::Str(fixture_id), HashPart::U64(ordinal), HashPart::U64(index)],
                    32,
                ),
                "disclosure": "commitment_only",
            })
        })
        .collect::<Vec<_>>();
    merkle_records("PQ-WATCHER-QUORUM-PRIVACY-WITNESS-SET", &records)
}

fn authority_root(kind: &str, epoch: u64, signer_set_root: &str) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-AUTHORITY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::U64(epoch),
            HashPart::Str(signer_set_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn merkle_records(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn label_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PQ-WATCHER-QUORUM-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn collusion_cluster_weight(signers: &[&WatcherSigner]) -> u16 {
    let mut clusters: BTreeMap<&str, u16> = BTreeMap::new();
    for signer in signers {
        let entry = clusters.entry(&signer.collusion_cluster).or_default();
        *entry = entry.saturating_add(signer.weight_bps);
    }
    clusters.values().copied().max().unwrap_or(0)
}

fn has_duplicate_watchers(signers: &[&WatcherSigner]) -> bool {
    let mut seen = BTreeSet::new();
    signers
        .iter()
        .any(|signer| !seen.insert(signer.watcher_id.as_str()))
}
