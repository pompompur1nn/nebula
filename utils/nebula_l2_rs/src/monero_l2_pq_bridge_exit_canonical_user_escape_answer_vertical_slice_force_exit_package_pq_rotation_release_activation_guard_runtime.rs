use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePqRotationReleaseActivationGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_ROTATION_RELEASE_ACTIVATION_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-pq-rotation-release-activation-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_ROTATION_RELEASE_ACTIVATION_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROTATION_RELEASE_ACTIVATION_GUARD_SUITE: &str =
    "monero-l2-pq-bridge-exit-force-exit-package-pq-rotation-release-activation-guard-v1";
pub const DEFAULT_CURRENT_SIGNER_EPOCH: u64 = 88;
pub const DEFAULT_RELEASE_ACTIVATION_EPOCH: u64 = 89;
pub const DEFAULT_REQUIRED_THRESHOLD_WEIGHT: u64 = 67;
pub const DEFAULT_REQUIRED_ML_DSA_SIGNERS: u64 = 3;
pub const DEFAULT_REQUIRED_SLH_DSA_RECOVERY_SIGNERS: u64 = 2;
pub const DEFAULT_ACTIVATION_DELAY_BLOCKS: u64 = 720;
pub const DEFAULT_LEGACY_QUARANTINE_BLOCKS: u64 = 14_400;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub guard_suite: String,
    pub current_signer_epoch: u64,
    pub release_activation_epoch: u64,
    pub required_threshold_weight: u64,
    pub required_ml_dsa_signers: u64,
    pub required_slh_dsa_recovery_signers: u64,
    pub activation_delay_blocks: u64,
    pub legacy_quarantine_blocks: u64,
    pub reject_duplicate_signers: bool,
    pub quarantine_legacy_signers: bool,
    pub require_threshold_activation_root: bool,
    pub require_timelock_root: bool,
    pub require_dual_pq_roots: bool,
    pub fail_closed_on_guard_gap: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            guard_suite: ROTATION_RELEASE_ACTIVATION_GUARD_SUITE.to_string(),
            current_signer_epoch: DEFAULT_CURRENT_SIGNER_EPOCH,
            release_activation_epoch: DEFAULT_RELEASE_ACTIVATION_EPOCH,
            required_threshold_weight: DEFAULT_REQUIRED_THRESHOLD_WEIGHT,
            required_ml_dsa_signers: DEFAULT_REQUIRED_ML_DSA_SIGNERS,
            required_slh_dsa_recovery_signers: DEFAULT_REQUIRED_SLH_DSA_RECOVERY_SIGNERS,
            activation_delay_blocks: DEFAULT_ACTIVATION_DELAY_BLOCKS,
            legacy_quarantine_blocks: DEFAULT_LEGACY_QUARANTINE_BLOCKS,
            reject_duplicate_signers: true,
            quarantine_legacy_signers: true,
            require_threshold_activation_root: true,
            require_timelock_root: true,
            require_dual_pq_roots: true,
            fail_closed_on_guard_gap: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "guard_suite": self.guard_suite,
            "current_signer_epoch": self.current_signer_epoch,
            "release_activation_epoch": self.release_activation_epoch,
            "required_threshold_weight": self.required_threshold_weight,
            "required_ml_dsa_signers": self.required_ml_dsa_signers,
            "required_slh_dsa_recovery_signers": self.required_slh_dsa_recovery_signers,
            "activation_delay_blocks": self.activation_delay_blocks,
            "legacy_quarantine_blocks": self.legacy_quarantine_blocks,
            "reject_duplicate_signers": self.reject_duplicate_signers,
            "quarantine_legacy_signers": self.quarantine_legacy_signers,
            "require_threshold_activation_root": self.require_threshold_activation_root,
            "require_timelock_root": self.require_timelock_root,
            "require_dual_pq_roots": self.require_dual_pq_roots,
            "fail_closed_on_guard_gap": self.fail_closed_on_guard_gap,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub ml_dsa_signer_root: String,
    pub slh_dsa_recovery_root: String,
    pub threshold_activation_root: String,
    pub timelock_root: String,
    pub duplicate_signer_rejection_root: String,
    pub legacy_signer_quarantine_root: String,
    pub release_activation_verdict_root: String,
    pub fail_closed_status_root: String,
    pub guard_package_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "ml_dsa_signer_root": self.ml_dsa_signer_root,
            "slh_dsa_recovery_root": self.slh_dsa_recovery_root,
            "threshold_activation_root": self.threshold_activation_root,
            "timelock_root": self.timelock_root,
            "duplicate_signer_rejection_root": self.duplicate_signer_rejection_root,
            "legacy_signer_quarantine_root": self.legacy_signer_quarantine_root,
            "release_activation_verdict_root": self.release_activation_verdict_root,
            "fail_closed_status_root": self.fail_closed_status_root,
            "guard_package_root": self.guard_package_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub candidate_signer_count: u64,
    pub accepted_signer_count: u64,
    pub duplicate_signer_count: u64,
    pub legacy_quarantined_count: u64,
    pub threshold_weight: u64,
    pub ml_dsa_signer_count: u64,
    pub slh_dsa_recovery_count: u64,
    pub timelock_receipt_count: u64,
    pub guard_gap_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "candidate_signer_count": self.candidate_signer_count,
            "accepted_signer_count": self.accepted_signer_count,
            "duplicate_signer_count": self.duplicate_signer_count,
            "legacy_quarantined_count": self.legacy_quarantined_count,
            "threshold_weight": self.threshold_weight,
            "ml_dsa_signer_count": self.ml_dsa_signer_count,
            "slh_dsa_recovery_count": self.slh_dsa_recovery_count,
            "timelock_receipt_count": self.timelock_receipt_count,
            "guard_gap_count": self.guard_gap_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerDisposition {
    Accepted,
    DuplicateRejected,
    LegacyQuarantined,
}

impl SignerDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::LegacyQuarantined => "legacy_quarantined",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationGuardSigner {
    pub signer_id: String,
    pub ordinal: u64,
    pub weight: u64,
    pub signer_epoch: u64,
    pub ml_dsa_signer_root: String,
    pub slh_dsa_recovery_root: String,
    pub threshold_share_root: String,
    pub timelock_receipt_root: String,
    pub duplicate_rejection_root: String,
    pub legacy_quarantine_root: String,
    pub disposition: SignerDisposition,
}

impl RotationGuardSigner {
    pub fn devnet(config: &Config, ordinal: u64, signer_id: &str, weight: u64) -> Self {
        Self::new(
            config,
            ordinal,
            signer_id,
            weight,
            config.release_activation_epoch,
            SignerDisposition::Accepted,
        )
    }

    pub fn new(
        config: &Config,
        ordinal: u64,
        signer_id: &str,
        weight: u64,
        signer_epoch: u64,
        disposition: SignerDisposition,
    ) -> Self {
        let ml_dsa_signer_root = pq_role_root(config, signer_id, ordinal, "ml-dsa-87", "release");
        let slh_dsa_recovery_root =
            pq_role_root(config, signer_id, ordinal, "slh-dsa-shake-256f", "recovery");
        let duplicate_rejection_root =
            duplicate_signer_rejection_root(config, signer_id, ordinal, disposition);
        let legacy_quarantine_root =
            legacy_signer_quarantine_root(config, signer_id, signer_epoch, disposition);
        let threshold_share_root = threshold_share_root(
            config,
            signer_id,
            ordinal,
            weight,
            &ml_dsa_signer_root,
            &slh_dsa_recovery_root,
            &duplicate_rejection_root,
            &legacy_quarantine_root,
        );
        let timelock_receipt_root =
            timelock_receipt_root(config, signer_id, ordinal, activation_height(config));
        Self {
            signer_id: signer_id.to_string(),
            ordinal,
            weight,
            signer_epoch,
            ml_dsa_signer_root,
            slh_dsa_recovery_root,
            threshold_share_root,
            timelock_receipt_root,
            duplicate_rejection_root,
            legacy_quarantine_root,
            disposition,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "ordinal": self.ordinal,
            "weight": self.weight,
            "signer_epoch": self.signer_epoch,
            "ml_dsa_signer_root": self.ml_dsa_signer_root,
            "slh_dsa_recovery_root": self.slh_dsa_recovery_root,
            "threshold_share_root": self.threshold_share_root,
            "timelock_receipt_root": self.timelock_receipt_root,
            "duplicate_rejection_root": self.duplicate_rejection_root,
            "legacy_quarantine_root": self.legacy_quarantine_root,
            "disposition": self.disposition.as_str(),
        })
    }

    pub fn accepted(&self) -> bool {
        self.disposition == SignerDisposition::Accepted
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseActivationVerdict {
    pub verdict_id: String,
    pub status: String,
    pub threshold_met: bool,
    pub ml_dsa_roots_present: bool,
    pub slh_dsa_recovery_roots_present: bool,
    pub duplicates_rejected: bool,
    pub legacy_signers_quarantined: bool,
    pub timelock_satisfied: bool,
    pub fail_closed: bool,
    pub activation_height: u64,
    pub required_outcome: String,
    pub verdict_root: String,
}

impl ReleaseActivationVerdict {
    pub fn new(
        config: &Config,
        roots: &Roots,
        counters: &Counters,
        activation_height: u64,
    ) -> Self {
        let threshold_met = counters.threshold_weight >= config.required_threshold_weight
            && counters.accepted_signer_count >= config.required_ml_dsa_signers;
        let ml_dsa_roots_present = counters.ml_dsa_signer_count >= config.required_ml_dsa_signers;
        let slh_dsa_recovery_roots_present =
            counters.slh_dsa_recovery_count >= config.required_slh_dsa_recovery_signers;
        let duplicates_rejected =
            !config.reject_duplicate_signers || counters.duplicate_signer_count > 0;
        let legacy_signers_quarantined =
            !config.quarantine_legacy_signers || counters.legacy_quarantined_count > 0;
        let timelock_satisfied =
            !config.require_timelock_root || counters.timelock_receipt_count > 0;
        let guard_gap_count = guard_gap_count(
            config,
            threshold_met,
            ml_dsa_roots_present,
            slh_dsa_recovery_roots_present,
            duplicates_rejected,
            legacy_signers_quarantined,
            timelock_satisfied,
        );
        let fail_closed = config.fail_closed_on_guard_gap && guard_gap_count > 0;
        let status = if fail_closed {
            "fail_closed"
        } else {
            "release_activation_allowed"
        }
        .to_string();
        let verdict_root = release_activation_verdict_root(
            config,
            roots,
            counters,
            threshold_met,
            ml_dsa_roots_present,
            slh_dsa_recovery_roots_present,
            duplicates_rejected,
            legacy_signers_quarantined,
            timelock_satisfied,
            fail_closed,
            activation_height,
            &status,
        );
        Self {
            verdict_id: record_root(
                "release-activation-verdict-id",
                &json!({"root": &verdict_root}),
            ),
            status,
            threshold_met,
            ml_dsa_roots_present,
            slh_dsa_recovery_roots_present,
            duplicates_rejected,
            legacy_signers_quarantined,
            timelock_satisfied,
            fail_closed,
            activation_height,
            required_outcome: "release activation requires PQ rotation guard allow verdict"
                .to_string(),
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "status": self.status,
            "threshold_met": self.threshold_met,
            "ml_dsa_roots_present": self.ml_dsa_roots_present,
            "slh_dsa_recovery_roots_present": self.slh_dsa_recovery_roots_present,
            "duplicates_rejected": self.duplicates_rejected,
            "legacy_signers_quarantined": self.legacy_signers_quarantined,
            "timelock_satisfied": self.timelock_satisfied,
            "fail_closed": self.fail_closed,
            "activation_height": self.activation_height,
            "required_outcome": self.required_outcome,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub signers: Vec<RotationGuardSigner>,
    pub counters: Counters,
    pub roots: Roots,
    pub release_activation_verdict: ReleaseActivationVerdict,
    pub state_commitment_root: String,
}

impl State {
    pub fn new(config: Config, signers: Vec<RotationGuardSigner>) -> Result<Self> {
        validate_config(&config)?;
        validate_signers(&config, &signers)?;
        let counters = counters(&config, &signers);
        let mut roots = roots(&config, &signers, &counters);
        let release_activation_verdict =
            ReleaseActivationVerdict::new(&config, &roots, &counters, activation_height(&config));
        roots.release_activation_verdict_root = release_activation_verdict.verdict_root.clone();
        roots.fail_closed_status_root =
            fail_closed_status_root(&config, &roots, &counters, &release_activation_verdict);
        roots.guard_package_root = guard_package_root(&config, &roots, &counters);
        let state_commitment_root =
            state_commitment_root(&config, &roots, &counters, &release_activation_verdict);
        Ok(Self {
            config,
            signers,
            counters,
            roots,
            release_activation_verdict,
            state_commitment_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let signers = vec![
            RotationGuardSigner::devnet(&config, 1, "pq-release-guard-alpha", 24),
            RotationGuardSigner::devnet(&config, 2, "pq-release-guard-beta", 23),
            RotationGuardSigner::devnet(&config, 3, "pq-release-guard-gamma", 22),
            RotationGuardSigner::new(
                &config,
                4,
                "pq-release-guard-alpha",
                0,
                config.release_activation_epoch,
                SignerDisposition::DuplicateRejected,
            ),
            RotationGuardSigner::new(
                &config,
                5,
                "pq-release-guard-legacy-delta",
                0,
                config.current_signer_epoch.saturating_sub(1),
                SignerDisposition::LegacyQuarantined,
            ),
        ];
        match Self::new(config, signers) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "signers": self.signers.iter().map(RotationGuardSigner::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "release_activation_verdict": self.release_activation_verdict.public_record(),
            "state_commitment_root": self.state_commitment_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_commitment_root.clone()
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

fn counters(config: &Config, signers: &[RotationGuardSigner]) -> Counters {
    let accepted = signers
        .iter()
        .filter(|signer| signer.accepted())
        .collect::<Vec<_>>();
    let threshold_weight = accepted.iter().map(|signer| signer.weight).sum();
    let ml_dsa_signer_count = accepted
        .iter()
        .filter(|signer| !signer.ml_dsa_signer_root.is_empty())
        .count() as u64;
    let slh_dsa_recovery_count = accepted
        .iter()
        .filter(|signer| !signer.slh_dsa_recovery_root.is_empty())
        .count() as u64;
    let timelock_receipt_count = accepted
        .iter()
        .filter(|signer| !signer.timelock_receipt_root.is_empty())
        .count() as u64;
    let duplicate_signer_count = signers
        .iter()
        .filter(|signer| signer.disposition == SignerDisposition::DuplicateRejected)
        .count() as u64;
    let legacy_quarantined_count = signers
        .iter()
        .filter(|signer| signer.disposition == SignerDisposition::LegacyQuarantined)
        .count() as u64;
    let threshold_met = threshold_weight >= config.required_threshold_weight
        && accepted.len() as u64 >= config.required_ml_dsa_signers;
    let ml_dsa_roots_present = ml_dsa_signer_count >= config.required_ml_dsa_signers;
    let slh_dsa_recovery_roots_present =
        slh_dsa_recovery_count >= config.required_slh_dsa_recovery_signers;
    let duplicates_rejected = !config.reject_duplicate_signers || duplicate_signer_count > 0;
    let legacy_signers_quarantined =
        !config.quarantine_legacy_signers || legacy_quarantined_count > 0;
    let timelock_satisfied = !config.require_timelock_root || timelock_receipt_count > 0;
    Counters {
        candidate_signer_count: signers.len() as u64,
        accepted_signer_count: accepted.len() as u64,
        duplicate_signer_count,
        legacy_quarantined_count,
        threshold_weight,
        ml_dsa_signer_count,
        slh_dsa_recovery_count,
        timelock_receipt_count,
        guard_gap_count: guard_gap_count(
            config,
            threshold_met,
            ml_dsa_roots_present,
            slh_dsa_recovery_roots_present,
            duplicates_rejected,
            legacy_signers_quarantined,
            timelock_satisfied,
        ),
    }
}

fn roots(config: &Config, signers: &[RotationGuardSigner], counters: &Counters) -> Roots {
    let accepted_records = signers
        .iter()
        .filter(|signer| signer.accepted())
        .map(RotationGuardSigner::public_record)
        .collect::<Vec<_>>();
    let duplicate_records = signers
        .iter()
        .filter(|signer| signer.disposition == SignerDisposition::DuplicateRejected)
        .map(RotationGuardSigner::public_record)
        .collect::<Vec<_>>();
    let legacy_records = signers
        .iter()
        .filter(|signer| signer.disposition == SignerDisposition::LegacyQuarantined)
        .map(RotationGuardSigner::public_record)
        .collect::<Vec<_>>();
    let ml_dsa_signer_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-ML-DSA-SIGNERS",
        &accepted_records,
    );
    let slh_dsa_recovery_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-SLH-DSA-RECOVERY",
        &accepted_records,
    );
    let threshold_activation_root = threshold_activation_root(
        config,
        counters,
        &ml_dsa_signer_root,
        &slh_dsa_recovery_root,
    );
    let timelock_root = timelock_root(config, signers);
    let duplicate_signer_rejection_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-DUPLICATE-REJECTIONS",
        &duplicate_records,
    );
    let legacy_signer_quarantine_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-LEGACY-QUARANTINE",
        &legacy_records,
    );
    let mut roots = Roots {
        ml_dsa_signer_root,
        slh_dsa_recovery_root,
        threshold_activation_root,
        timelock_root,
        duplicate_signer_rejection_root,
        legacy_signer_quarantine_root,
        release_activation_verdict_root: String::new(),
        fail_closed_status_root: String::new(),
        guard_package_root: String::new(),
    };
    roots.guard_package_root = guard_package_root(config, &roots, counters);
    roots
}

fn guard_gap_count(
    config: &Config,
    threshold_met: bool,
    ml_dsa_roots_present: bool,
    slh_dsa_recovery_roots_present: bool,
    duplicates_rejected: bool,
    legacy_signers_quarantined: bool,
    timelock_satisfied: bool,
) -> u64 {
    bool_gap(config.require_threshold_activation_root && !threshold_met)
        + bool_gap(config.require_dual_pq_roots && !ml_dsa_roots_present)
        + bool_gap(config.require_dual_pq_roots && !slh_dsa_recovery_roots_present)
        + bool_gap(config.reject_duplicate_signers && !duplicates_rejected)
        + bool_gap(config.quarantine_legacy_signers && !legacy_signers_quarantined)
        + bool_gap(config.require_timelock_root && !timelock_satisfied)
}

fn pq_role_root(
    config: &Config,
    signer_id: &str,
    ordinal: u64,
    scheme: &str,
    role: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-PQ-ROLE",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::Str(signer_id),
            HashPart::U64(ordinal),
            HashPart::Str(scheme),
            HashPart::Str(role),
            HashPart::U64(config.release_activation_epoch),
        ],
        32,
    )
}

fn threshold_share_root(
    config: &Config,
    signer_id: &str,
    ordinal: u64,
    weight: u64,
    ml_dsa_signer_root: &str,
    slh_dsa_recovery_root: &str,
    duplicate_rejection_root: &str,
    legacy_quarantine_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-THRESHOLD-SHARE",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::Str(signer_id),
            HashPart::U64(ordinal),
            HashPart::U64(weight),
            HashPart::Str(ml_dsa_signer_root),
            HashPart::Str(slh_dsa_recovery_root),
            HashPart::Str(duplicate_rejection_root),
            HashPart::Str(legacy_quarantine_root),
        ],
        32,
    )
}

fn duplicate_signer_rejection_root(
    config: &Config,
    signer_id: &str,
    ordinal: u64,
    disposition: SignerDisposition,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-DUPLICATE-SIGNER",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::Str(signer_id),
            HashPart::U64(ordinal),
            HashPart::Str(disposition.as_str()),
            HashPart::Str(bool_str(disposition == SignerDisposition::DuplicateRejected)),
        ],
        32,
    )
}

fn legacy_signer_quarantine_root(
    config: &Config,
    signer_id: &str,
    signer_epoch: u64,
    disposition: SignerDisposition,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-LEGACY-QUARANTINE",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::Str(signer_id),
            HashPart::U64(signer_epoch),
            HashPart::U64(config.current_signer_epoch),
            HashPart::U64(config.release_activation_epoch),
            HashPart::U64(config.legacy_quarantine_blocks),
            HashPart::Str(disposition.as_str()),
        ],
        32,
    )
}

fn timelock_receipt_root(
    config: &Config,
    signer_id: &str,
    ordinal: u64,
    activation_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-TIMELOCK-RECEIPT",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::Str(signer_id),
            HashPart::U64(ordinal),
            HashPart::U64(config.activation_delay_blocks),
            HashPart::U64(activation_height),
        ],
        32,
    )
}

fn threshold_activation_root(
    config: &Config,
    counters: &Counters,
    ml_dsa_signer_root: &str,
    slh_dsa_recovery_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-THRESHOLD-ACTIVATION",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::U64(counters.threshold_weight),
            HashPart::U64(config.required_threshold_weight),
            HashPart::U64(counters.accepted_signer_count),
            HashPart::U64(config.required_ml_dsa_signers),
            HashPart::Str(ml_dsa_signer_root),
            HashPart::Str(slh_dsa_recovery_root),
        ],
        32,
    )
}

fn timelock_root(config: &Config, signers: &[RotationGuardSigner]) -> String {
    let records = signers
        .iter()
        .filter(|signer| signer.accepted())
        .map(|signer| {
            json!({
                "signer_id": signer.signer_id,
                "ordinal": signer.ordinal,
                "timelock_receipt_root": signer.timelock_receipt_root,
                "activation_height": activation_height(config),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-TIMELOCKS",
        &records,
    )
}

fn release_activation_verdict_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    threshold_met: bool,
    ml_dsa_roots_present: bool,
    slh_dsa_recovery_roots_present: bool,
    duplicates_rejected: bool,
    legacy_signers_quarantined: bool,
    timelock_satisfied: bool,
    fail_closed: bool,
    activation_height: u64,
    status: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-VERDICT",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::Str(&roots.ml_dsa_signer_root),
            HashPart::Str(&roots.slh_dsa_recovery_root),
            HashPart::Str(&roots.threshold_activation_root),
            HashPart::Str(&roots.timelock_root),
            HashPart::Str(&roots.duplicate_signer_rejection_root),
            HashPart::Str(&roots.legacy_signer_quarantine_root),
            HashPart::U64(counters.guard_gap_count),
            HashPart::U64(activation_height),
            HashPart::Str(bool_str(threshold_met)),
            HashPart::Str(bool_str(ml_dsa_roots_present)),
            HashPart::Str(bool_str(slh_dsa_recovery_roots_present)),
            HashPart::Str(bool_str(duplicates_rejected)),
            HashPart::Str(bool_str(legacy_signers_quarantined)),
            HashPart::Str(bool_str(timelock_satisfied)),
            HashPart::Str(bool_str(fail_closed)),
            HashPart::Str(status),
        ],
        32,
    )
}

fn fail_closed_status_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    verdict: &ReleaseActivationVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-FAIL-CLOSED",
        &[
            HashPart::Str(&config.guard_suite),
            HashPart::Str(&roots.release_activation_verdict_root),
            HashPart::U64(counters.guard_gap_count),
            HashPart::Str(bool_str(verdict.fail_closed)),
            HashPart::Str(&verdict.status),
        ],
        32,
    )
}

fn guard_package_root(config: &Config, roots: &Roots, counters: &Counters) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-PACKAGE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&roots.ml_dsa_signer_root),
            HashPart::Str(&roots.slh_dsa_recovery_root),
            HashPart::Str(&roots.threshold_activation_root),
            HashPart::Str(&roots.timelock_root),
            HashPart::Str(&roots.duplicate_signer_rejection_root),
            HashPart::Str(&roots.legacy_signer_quarantine_root),
            HashPart::Str(&roots.release_activation_verdict_root),
            HashPart::Str(&roots.fail_closed_status_root),
            HashPart::Str(&counters.state_root()),
        ],
        32,
    )
}

fn state_commitment_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    verdict: &ReleaseActivationVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&roots.state_root()),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&verdict.verdict_root),
            HashPart::Str(&roots.guard_package_root),
        ],
        32,
    )
}

fn activation_height(config: &Config) -> u64 {
    config
        .release_activation_epoch
        .saturating_mul(10_000)
        .saturating_add(config.activation_delay_blocks)
}

fn validate_config(config: &Config) -> Result<()> {
    ensure(
        config.chain_id == CHAIN_ID,
        "PQ rotation release activation guard chain mismatch",
    )?;
    ensure(
        config.protocol_version == PROTOCOL_VERSION,
        "PQ rotation release activation guard protocol mismatch",
    )?;
    ensure(
        config.schema_version == SCHEMA_VERSION,
        "PQ rotation release activation guard schema mismatch",
    )?;
    ensure(
        config.release_activation_epoch > config.current_signer_epoch,
        "PQ rotation release activation guard requires forward activation epoch",
    )?;
    ensure(
        config.required_threshold_weight > 0,
        "PQ rotation release activation guard requires threshold weight",
    )?;
    ensure(
        config.required_ml_dsa_signers > 0,
        "PQ rotation release activation guard requires ML-DSA signers",
    )?;
    ensure(
        config.required_slh_dsa_recovery_signers > 0,
        "PQ rotation release activation guard requires SLH-DSA recovery signers",
    )?;
    Ok(())
}

fn validate_signers(config: &Config, signers: &[RotationGuardSigner]) -> Result<()> {
    ensure(
        signers.len() as u64 >= config.required_ml_dsa_signers,
        "PQ rotation release activation guard has too few signer records",
    )?;
    let mut seen = BTreeSet::new();
    for signer in signers {
        let fresh_insert = seen.insert(signer.signer_id.clone());
        ensure(
            fresh_insert || signer.disposition == SignerDisposition::DuplicateRejected,
            "PQ rotation release activation guard duplicate signer was not rejected",
        )?;
        ensure(
            signer.signer_epoch >= config.current_signer_epoch
                || signer.disposition == SignerDisposition::LegacyQuarantined,
            "PQ rotation release activation guard legacy signer was not quarantined",
        )?;
    }
    Ok(())
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let signers = vec![RotationGuardSigner::new(
        &config,
        1,
        "pq-rotation-release-activation-guard-fallback",
        config.required_threshold_weight,
        config.release_activation_epoch,
        SignerDisposition::Accepted,
    )];
    let counters = Counters {
        candidate_signer_count: 1,
        accepted_signer_count: 1,
        duplicate_signer_count: 0,
        legacy_quarantined_count: 0,
        threshold_weight: config.required_threshold_weight,
        ml_dsa_signer_count: 1,
        slh_dsa_recovery_count: 1,
        timelock_receipt_count: 1,
        guard_gap_count: 1,
    };
    let mut roots = roots(&config, &signers, &counters);
    roots.release_activation_verdict_root = record_root(
        "fallback-release-activation-verdict",
        &json!({"reason": &reason}),
    );
    let release_activation_verdict =
        ReleaseActivationVerdict::new(&config, &roots, &counters, activation_height(&config));
    roots.release_activation_verdict_root = release_activation_verdict.verdict_root.clone();
    roots.fail_closed_status_root =
        fail_closed_status_root(&config, &roots, &counters, &release_activation_verdict);
    roots.guard_package_root = guard_package_root(&config, &roots, &counters);
    let state_commitment_root =
        state_commitment_root(&config, &roots, &counters, &release_activation_verdict);
    State {
        config,
        signers,
        counters,
        roots,
        release_activation_verdict,
        state_commitment_root,
    }
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCE-EXIT-PACKAGE-PQ-ROTATION-RELEASE-ACTIVATION-GUARD-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn bool_gap(value: bool) -> u64 {
    if value {
        1
    } else {
        0
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
