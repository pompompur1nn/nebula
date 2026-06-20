use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqBridgeExitCanonicalPqKeyRotationReleaseDrillRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PQ_KEY_ROTATION_RELEASE_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-pq-key-rotation-release-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PQ_KEY_ROTATION_RELEASE_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DRILL_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-pq-key-rotation-release-drill-v1";
pub const ML_DSA_SIGNER_DOMAIN: &str =
    "ML-DSA-87:nebula:monero-l2:forced-exit-release-key-rotation:v1";
pub const SLH_DSA_SIGNER_DOMAIN: &str =
    "SLH-DSA-SHAKE-256f:nebula:monero-l2:forced-exit-release-key-rotation:v1";
pub const RELEASE_AUTHORIZATION_DOMAIN: &str =
    "SHAKE256:nebula:monero-l2:forced-exit-release-continuity:v1";
pub const DEFAULT_RELEASE_HEIGHT: u64 = 1_935_040;
pub const DEFAULT_FORCED_EXIT_HEIGHT: u64 = 1_934_912;
pub const DEFAULT_PRE_ROTATION_EPOCH: u64 = 211;
pub const DEFAULT_POST_ROTATION_EPOCH: u64 = 212;
pub const DEFAULT_EMERGENCY_EPOCH: u64 = 213;
pub const DEFAULT_THRESHOLD_WEIGHT_BPS: u16 = 7_000;
pub const DEFAULT_MAX_STALE_EPOCH_LAG: u64 = 0;
pub const DEFAULT_OVERLAP_BLOCKS: u64 = 144;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqScheme {
    MlDsa87,
    SlhDsaShake256f,
}

impl PqScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
        }
    }

    pub fn domain(self) -> &'static str {
        match self {
            Self::MlDsa87 => ML_DSA_SIGNER_DOMAIN,
            Self::SlhDsaShake256f => SLH_DSA_SIGNER_DOMAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Active,
    Retiring,
    Quarantined,
    Revoked,
}

impl EpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_authorize(self) -> bool {
        matches!(self, Self::Active | Self::Retiring)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecision {
    Authorized,
    Rejected,
}

impl ReleaseDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationMode {
    Scheduled,
    Emergency,
}

impl RotationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Emergency => "emergency",
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
    pub ml_dsa_signer_domain: String,
    pub slh_dsa_signer_domain: String,
    pub release_authorization_domain: String,
    pub release_height: u64,
    pub forced_exit_height: u64,
    pub threshold_weight_bps: u16,
    pub max_stale_epoch_lag: u64,
    pub overlap_blocks: u64,
    pub quarantine_blocks: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            drill_suite: DRILL_SUITE.to_string(),
            ml_dsa_signer_domain: ML_DSA_SIGNER_DOMAIN.to_string(),
            slh_dsa_signer_domain: SLH_DSA_SIGNER_DOMAIN.to_string(),
            release_authorization_domain: RELEASE_AUTHORIZATION_DOMAIN.to_string(),
            release_height: DEFAULT_RELEASE_HEIGHT,
            forced_exit_height: DEFAULT_FORCED_EXIT_HEIGHT,
            threshold_weight_bps: DEFAULT_THRESHOLD_WEIGHT_BPS,
            max_stale_epoch_lag: DEFAULT_MAX_STALE_EPOCH_LAG,
            overlap_blocks: DEFAULT_OVERLAP_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "drill_suite": self.drill_suite,
            "ml_dsa_signer_domain": self.ml_dsa_signer_domain,
            "slh_dsa_signer_domain": self.slh_dsa_signer_domain,
            "release_authorization_domain": self.release_authorization_domain,
            "release_height": self.release_height,
            "forced_exit_height": self.forced_exit_height,
            "threshold_weight_bps": self.threshold_weight_bps,
            "max_stale_epoch_lag": self.max_stale_epoch_lag,
            "overlap_blocks": self.overlap_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerKey {
    pub signer_id: String,
    pub scheme: PqScheme,
    pub weight_bps: u16,
    pub pq_security_bits: u16,
    pub key_commitment: String,
    pub activation_height: u64,
    pub deactivation_height: Option<u64>,
    pub status: EpochStatus,
    pub slashing_bond_id: String,
}

impl SignerKey {
    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "scheme": self.scheme.as_str(),
            "scheme_domain": self.scheme.domain(),
            "weight_bps": self.weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "key_commitment": self.key_commitment,
            "activation_height": self.activation_height,
            "deactivation_height": self.deactivation_height,
            "status": self.status.as_str(),
            "slashing_bond_id": self.slashing_bond_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerEpoch {
    pub epoch: u64,
    pub mode: RotationMode,
    pub activation_height: u64,
    pub deactivation_height: Option<u64>,
    pub quarantine_until_height: Option<u64>,
    pub status: EpochStatus,
    pub signers: Vec<SignerKey>,
}

impl SignerEpoch {
    pub fn signer_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-SIGNER",
            &self
                .signers
                .iter()
                .map(SignerKey::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn threshold_weight_bps(&self) -> u16 {
        self.signers
            .iter()
            .filter(|signer| signer.status.can_authorize())
            .map(|signer| signer.weight_bps)
            .sum()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "mode": self.mode.as_str(),
            "activation_height": self.activation_height,
            "deactivation_height": self.deactivation_height,
            "quarantine_until_height": self.quarantine_until_height,
            "status": self.status.as_str(),
            "signer_root": self.signer_root(),
            "threshold_weight_bps": self.threshold_weight_bps(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotationWindow {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub mode: RotationMode,
    pub activation_height: u64,
    pub overlap_until_height: u64,
    pub retired_epoch_quarantine_until_height: u64,
    pub prior_epoch_root: String,
    pub next_epoch_root: String,
    pub continuity_root: String,
}

impl RotationWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "from_epoch": self.from_epoch,
            "to_epoch": self.to_epoch,
            "mode": self.mode.as_str(),
            "activation_height": self.activation_height,
            "overlap_until_height": self.overlap_until_height,
            "retired_epoch_quarantine_until_height": self.retired_epoch_quarantine_until_height,
            "prior_epoch_root": self.prior_epoch_root,
            "next_epoch_root": self.next_epoch_root,
            "continuity_root": self.continuity_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitRelease {
    pub release_id: String,
    pub forced_exit_id: String,
    pub epoch: u64,
    pub height: u64,
    pub signer_ids: Vec<String>,
    pub release_weight_bps: u16,
    pub threshold_weight_bps: u16,
    pub authorization_root: String,
    pub decision: ReleaseDecision,
    pub reason: String,
}

impl ForcedExitRelease {
    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "forced_exit_id": self.forced_exit_id,
            "epoch": self.epoch,
            "height": self.height,
            "signer_ids": self.signer_ids,
            "release_weight_bps": self.release_weight_bps,
            "threshold_weight_bps": self.threshold_weight_bps,
            "authorization_root": self.authorization_root,
            "decision": self.decision.as_str(),
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StaleKeyRejection {
    pub probe_id: String,
    pub attempted_epoch: u64,
    pub active_epoch: u64,
    pub signer_id: String,
    pub rejected_height: u64,
    pub rejection_root: String,
    pub slashing_link_root: String,
}

impl StaleKeyRejection {
    pub fn public_record(&self) -> Value {
        json!({
            "probe_id": self.probe_id,
            "attempted_epoch": self.attempted_epoch,
            "active_epoch": self.active_epoch,
            "signer_id": self.signer_id,
            "rejected_height": self.rejected_height,
            "rejection_root": self.rejection_root,
            "slashing_link_root": self.slashing_link_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuarantineRecord {
    pub record_id: String,
    pub epoch: u64,
    pub signer_id: String,
    pub from_height: u64,
    pub until_height: u64,
    pub evidence_root: String,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "epoch": self.epoch,
            "signer_id": self.signer_id,
            "from_height": self.from_height,
            "until_height": self.until_height,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingLink {
    pub link_id: String,
    pub signer_id: String,
    pub bond_id: String,
    pub evidence_root: String,
    pub slashable_weight_bps: u16,
}

impl SlashingLink {
    pub fn public_record(&self) -> Value {
        json!({
            "link_id": self.link_id,
            "signer_id": self.signer_id,
            "bond_id": self.bond_id,
            "evidence_root": self.evidence_root,
            "slashable_weight_bps": self.slashable_weight_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEvidence {
    pub signer_epoch_root: String,
    pub rotation_window_root: String,
    pub forced_exit_release_root: String,
    pub stale_key_rejection_root: String,
    pub quarantine_root: String,
    pub slashing_link_root: String,
    pub release_authorization_continuity_root: String,
    pub emergency_rotation_root: String,
}

impl AuditEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "signer_epoch_root": self.signer_epoch_root,
            "rotation_window_root": self.rotation_window_root,
            "forced_exit_release_root": self.forced_exit_release_root,
            "stale_key_rejection_root": self.stale_key_rejection_root,
            "quarantine_root": self.quarantine_root,
            "slashing_link_root": self.slashing_link_root,
            "release_authorization_continuity_root": self.release_authorization_continuity_root,
            "emergency_rotation_root": self.emergency_rotation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub signer_epochs: Vec<SignerEpoch>,
    pub rotation_windows: Vec<RotationWindow>,
    pub forced_exit_releases: Vec<ForcedExitRelease>,
    pub stale_key_rejections: Vec<StaleKeyRejection>,
    pub quarantines: Vec<QuarantineRecord>,
    pub slashing_links: Vec<SlashingLink>,
    pub audit_evidence: AuditEvidence,
    pub forced_exit_release_remains_pq_authorized: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let pre_epoch = signer_epoch(
            DEFAULT_PRE_ROTATION_EPOCH,
            RotationMode::Scheduled,
            DEFAULT_FORCED_EXIT_HEIGHT - 720,
            Some(config.release_height + config.overlap_blocks),
            None,
            EpochStatus::Retiring,
            &[
                ("aurora", PqScheme::MlDsa87, 2_800),
                ("borealis", PqScheme::SlhDsaShake256f, 2_600),
                ("cygnus", PqScheme::MlDsa87, 2_400),
                ("deneb", PqScheme::SlhDsaShake256f, 2_200),
            ],
        );
        let post_epoch = signer_epoch(
            DEFAULT_POST_ROTATION_EPOCH,
            RotationMode::Scheduled,
            config.release_height - 12,
            Some(config.release_height + config.quarantine_blocks),
            None,
            EpochStatus::Active,
            &[
                ("eos", PqScheme::MlDsa87, 2_700),
                ("fornax", PqScheme::SlhDsaShake256f, 2_500),
                ("gemini", PqScheme::MlDsa87, 2_500),
                ("helix", PqScheme::SlhDsaShake256f, 2_300),
            ],
        );
        let emergency_epoch = signer_epoch(
            DEFAULT_EMERGENCY_EPOCH,
            RotationMode::Emergency,
            config.release_height + 96,
            None,
            None,
            EpochStatus::Active,
            &[
                ("iris", PqScheme::MlDsa87, 3_400),
                ("janus", PqScheme::SlhDsaShake256f, 3_300),
                ("kepler", PqScheme::MlDsa87, 3_300),
            ],
        );

        let signer_epochs = vec![pre_epoch, post_epoch, emergency_epoch];
        let pre_epoch_root = epoch_root(&signer_epochs[0]);
        let post_epoch_root = epoch_root(&signer_epochs[1]);
        let emergency_epoch_root = epoch_root(&signer_epochs[2]);
        let scheduled_continuity_root = continuity_root(
            DEFAULT_PRE_ROTATION_EPOCH,
            DEFAULT_POST_ROTATION_EPOCH,
            &pre_epoch_root,
            &post_epoch_root,
        );
        let emergency_continuity_root = continuity_root(
            DEFAULT_POST_ROTATION_EPOCH,
            DEFAULT_EMERGENCY_EPOCH,
            &post_epoch_root,
            &emergency_epoch_root,
        );
        let rotation_windows = vec![
            RotationWindow {
                from_epoch: DEFAULT_PRE_ROTATION_EPOCH,
                to_epoch: DEFAULT_POST_ROTATION_EPOCH,
                mode: RotationMode::Scheduled,
                activation_height: config.release_height - 12,
                overlap_until_height: config.release_height + config.overlap_blocks,
                retired_epoch_quarantine_until_height: config.release_height
                    + config.quarantine_blocks,
                prior_epoch_root: pre_epoch_root.clone(),
                next_epoch_root: post_epoch_root.clone(),
                continuity_root: scheduled_continuity_root.clone(),
            },
            RotationWindow {
                from_epoch: DEFAULT_POST_ROTATION_EPOCH,
                to_epoch: DEFAULT_EMERGENCY_EPOCH,
                mode: RotationMode::Emergency,
                activation_height: config.release_height + 96,
                overlap_until_height: config.release_height + 96,
                retired_epoch_quarantine_until_height: config.release_height
                    + 96
                    + config.quarantine_blocks,
                prior_epoch_root: post_epoch_root.clone(),
                next_epoch_root: emergency_epoch_root.clone(),
                continuity_root: emergency_continuity_root.clone(),
            },
        ];

        let forced_exit_releases = vec![
            release_record(
                "release-before-cutover",
                "forced-exit-devnet-rotation-001",
                DEFAULT_PRE_ROTATION_EPOCH,
                config.release_height - 18,
                &["aurora", "borealis", "cygnus"],
                7_800,
                config.threshold_weight_bps,
                &pre_epoch_root,
            ),
            release_record(
                "release-after-cutover",
                "forced-exit-devnet-rotation-001",
                DEFAULT_POST_ROTATION_EPOCH,
                config.release_height + 18,
                &["eos", "fornax", "gemini"],
                7_700,
                config.threshold_weight_bps,
                &post_epoch_root,
            ),
            release_record(
                "release-after-emergency-rotation",
                "forced-exit-devnet-rotation-001",
                DEFAULT_EMERGENCY_EPOCH,
                config.release_height + 120,
                &["iris", "janus", "kepler"],
                10_000,
                config.threshold_weight_bps,
                &emergency_epoch_root,
            ),
        ];

        let stale_key_rejections = vec![StaleKeyRejection {
            probe_id: "stale-pre-rotation-key-after-cutover".to_string(),
            attempted_epoch: DEFAULT_PRE_ROTATION_EPOCH,
            active_epoch: DEFAULT_POST_ROTATION_EPOCH,
            signer_id: "aurora".to_string(),
            rejected_height: config.release_height + config.overlap_blocks + 1,
            rejection_root: record_root(
                "STALE-KEY-REJECTION",
                &json!({
                    "attempted_epoch": DEFAULT_PRE_ROTATION_EPOCH,
                    "active_epoch": DEFAULT_POST_ROTATION_EPOCH,
                    "signer_id": "aurora",
                    "max_stale_epoch_lag": config.max_stale_epoch_lag,
                }),
            ),
            slashing_link_root: record_root(
                "STALE-KEY-SLASHING-LINK",
                &json!({
                    "signer_id": "aurora",
                    "bond_id": "bond-aurora-211",
                    "evidence": "late_release_signature_after_retirement",
                }),
            ),
        }];

        let quarantines = vec![QuarantineRecord {
            record_id: "retired-epoch-211-quarantine".to_string(),
            epoch: DEFAULT_PRE_ROTATION_EPOCH,
            signer_id: "aurora".to_string(),
            from_height: config.release_height + config.overlap_blocks + 1,
            until_height: config.release_height + config.quarantine_blocks,
            evidence_root: stale_key_rejections[0].rejection_root.clone(),
        }];

        let slashing_links = vec![SlashingLink {
            link_id: "slash-link-aurora-stale-key".to_string(),
            signer_id: "aurora".to_string(),
            bond_id: "bond-aurora-211".to_string(),
            evidence_root: stale_key_rejections[0].slashing_link_root.clone(),
            slashable_weight_bps: 2_800,
        }];

        let signer_epoch_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-EPOCH",
            &signer_epochs
                .iter()
                .map(SignerEpoch::public_record)
                .collect::<Vec<_>>(),
        );
        let rotation_window_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-WINDOW",
            &rotation_windows
                .iter()
                .map(RotationWindow::public_record)
                .collect::<Vec<_>>(),
        );
        let forced_exit_release_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-RELEASE",
            &forced_exit_releases
                .iter()
                .map(ForcedExitRelease::public_record)
                .collect::<Vec<_>>(),
        );
        let stale_key_rejection_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-STALE-REJECTION",
            &stale_key_rejections
                .iter()
                .map(StaleKeyRejection::public_record)
                .collect::<Vec<_>>(),
        );
        let quarantine_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-QUARANTINE",
            &quarantines
                .iter()
                .map(QuarantineRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let slashing_link_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-SLASHING",
            &slashing_links
                .iter()
                .map(SlashingLink::public_record)
                .collect::<Vec<_>>(),
        );
        let release_authorization_continuity_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-CONTINUITY",
            &rotation_windows
                .iter()
                .map(|window| json!(window.continuity_root))
                .collect::<Vec<_>>(),
        );
        let emergency_rotation_root = record_root(
            "EMERGENCY-ROTATION",
            &json!({
                "epoch": DEFAULT_EMERGENCY_EPOCH,
                "epoch_root": emergency_epoch_root,
                "continuity_root": emergency_continuity_root,
                "authorized_release_id": "release-after-emergency-rotation",
            }),
        );
        let audit_evidence = AuditEvidence {
            signer_epoch_root,
            rotation_window_root,
            forced_exit_release_root,
            stale_key_rejection_root,
            quarantine_root,
            slashing_link_root,
            release_authorization_continuity_root,
            emergency_rotation_root,
        };

        let forced_exit_release_remains_pq_authorized =
            forced_exit_releases.iter().all(|release| {
                release.decision == ReleaseDecision::Authorized
                    && release.release_weight_bps >= release.threshold_weight_bps
            });

        Self {
            config,
            signer_epochs,
            rotation_windows,
            forced_exit_releases,
            stale_key_rejections,
            quarantines,
            slashing_links,
            audit_evidence,
            forced_exit_release_remains_pq_authorized,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "signer_epoch_root": self.audit_evidence.signer_epoch_root,
            "rotation_window_root": self.audit_evidence.rotation_window_root,
            "forced_exit_release_root": self.audit_evidence.forced_exit_release_root,
            "stale_key_rejection_root": self.audit_evidence.stale_key_rejection_root,
            "quarantine_root": self.audit_evidence.quarantine_root,
            "slashing_link_root": self.audit_evidence.slashing_link_root,
            "release_authorization_continuity_root": self.audit_evidence.release_authorization_continuity_root,
            "emergency_rotation_root": self.audit_evidence.emergency_rotation_root,
            "forced_exit_release_remains_pq_authorized": self.forced_exit_release_remains_pq_authorized,
            "forced_exit_answer": "yes_forced_exit_release_remains_pq_authorized_across_scheduled_and_emergency_key_rotation",
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record())
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

fn signer_epoch(
    epoch: u64,
    mode: RotationMode,
    activation_height: u64,
    deactivation_height: Option<u64>,
    quarantine_until_height: Option<u64>,
    status: EpochStatus,
    signers: &[(&str, PqScheme, u16)],
) -> SignerEpoch {
    SignerEpoch {
        epoch,
        mode,
        activation_height,
        deactivation_height,
        quarantine_until_height,
        status,
        signers: signers
            .iter()
            .map(|(signer_id, scheme, weight_bps)| SignerKey {
                signer_id: (*signer_id).to_string(),
                scheme: *scheme,
                weight_bps: *weight_bps,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                key_commitment: domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-KEY",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::U64(epoch),
                        HashPart::Str(signer_id),
                        HashPart::Str(scheme.as_str()),
                    ],
                    32,
                ),
                activation_height,
                deactivation_height,
                status,
                slashing_bond_id: format!("bond-{signer_id}-{epoch}"),
            })
            .collect(),
    }
}

fn release_record(
    release_id: &str,
    forced_exit_id: &str,
    epoch: u64,
    height: u64,
    signer_ids: &[&str],
    release_weight_bps: u16,
    threshold_weight_bps: u16,
    epoch_root: &str,
) -> ForcedExitRelease {
    let signer_values = signer_ids
        .iter()
        .map(|signer_id| json!(signer_id))
        .collect::<Vec<_>>();
    let signer_set_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-RELEASE-SIGNER-SET",
        &signer_values,
    );
    let authorization_root = domain_hash(
        RELEASE_AUTHORIZATION_DOMAIN,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(release_id),
            HashPart::Str(forced_exit_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
            HashPart::Str(epoch_root),
            HashPart::Str(&signer_set_root),
        ],
        32,
    );

    ForcedExitRelease {
        release_id: release_id.to_string(),
        forced_exit_id: forced_exit_id.to_string(),
        epoch,
        height,
        signer_ids: signer_ids
            .iter()
            .map(|signer_id| (*signer_id).to_string())
            .collect(),
        release_weight_bps,
        threshold_weight_bps,
        authorization_root,
        decision: if release_weight_bps >= threshold_weight_bps {
            ReleaseDecision::Authorized
        } else {
            ReleaseDecision::Rejected
        },
        reason: if release_weight_bps >= threshold_weight_bps {
            "threshold_met_with_current_pq_epoch".to_string()
        } else {
            "threshold_weight_not_met".to_string()
        },
    }
}

fn epoch_root(epoch: &SignerEpoch) -> String {
    record_root("SIGNER-EPOCH", &epoch.public_record())
}

fn continuity_root(from_epoch: u64, to_epoch: u64, from_root: &str, to_root: &str) -> String {
    domain_hash(
        RELEASE_AUTHORIZATION_DOMAIN,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(from_epoch),
            HashPart::U64(to_epoch),
            HashPart::Str(from_root),
            HashPart::Str(to_root),
        ],
        32,
    )
}

fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-KEY-ROTATION-RELEASE-DRILL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(value),
        ],
        32,
    )
}
