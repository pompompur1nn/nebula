use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePqReservePrivacyGoNoGoGovernanceBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-force-exit-pq-reserve-privacy-go-no-go-governance-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_MANIFEST_SCHEME: &str =
    "monero-l2-force-exit-release-manifest-enforcement-root-v1";
pub const CIRCUIT_BREAKER_SCHEME: &str = "monero-l2-force-exit-circuit-breaker-root-v1";
pub const PQ_EPOCH_SCHEME: &str = "monero-l2-pq-epoch-governance-binding-root-v1";
pub const RESERVE_SLO_SCHEME: &str = "monero-l2-reserve-slo-governance-binding-root-v1";
pub const PRIVACY_NON_LINKAGE_SCHEME: &str =
    "monero-l2-privacy-non-linkage-governance-binding-root-v1";
pub const OPERATOR_ACK_SCHEME: &str = "monero-l2-operator-acknowledgement-root-v1";
pub const WALLET_HOLD_NOTICE_SCHEME: &str = "monero-l2-wallet-public-hold-notice-root-v1";
pub const DEFAULT_GOVERNANCE_REALM: &str = "monero-l2-force-exit-go-no-go";
pub const DEFAULT_RELEASE_ID: &str = "force-exit-package-pq-reserve-privacy-devnet";
pub const DEFAULT_BINDING_ID: &str = "force-exit-governance-binding-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 12_500;
pub const DEFAULT_MAX_EXIT_LATENCY_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_HOLD_NOTICE_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_OPEN_BREAKERS: u16 = 0;
pub const DEFAULT_OPERATOR_ACK_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_WALLET_NOTICE_QUORUM_BPS: u64 = 9_500;
pub const DEFAULT_PUBLIC_HOLD_NOTICE_QUORUM_BPS: u64 = 10_000;
pub const DEFAULT_DEVNET_HEIGHT: u64 = 1_990_400;
pub const DEFAULT_MAX_MANIFESTS: usize = 1_024;
pub const DEFAULT_MAX_GOVERNANCE_PACKAGES: usize = 4_096;
pub const DEFAULT_MAX_OPERATOR_ACKS: usize = 65_536;
pub const DEFAULT_MAX_HOLD_NOTICES: usize = 65_536;
pub const DEFAULT_MAX_DECISIONS: usize = 16_384;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    Draft,
    Armed,
    Enforced,
    Blocked,
    Expired,
}

impl EnforcementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Armed => "armed",
            Self::Enforced => "enforced",
            Self::Blocked => "blocked",
            Self::Expired => "expired",
        }
    }

    pub fn is_go_capable(self) -> bool {
        matches!(self, Self::Armed | Self::Enforced)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerStatus {
    Closed,
    Armed,
    Open,
    Tripped,
    Unknown,
}

impl BreakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Armed => "armed",
            Self::Open => "open",
            Self::Tripped => "tripped",
            Self::Unknown => "unknown",
        }
    }

    pub fn fail_closed(self) -> bool {
        !matches!(self, Self::Closed | Self::Armed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqEpochStatus {
    Pending,
    Active,
    Grace,
    Rotating,
    Revoked,
    Unknown,
}

impl PqEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }

    pub fn accepts_release(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSloStatus {
    Met,
    Watch,
    Breached,
    Stale,
    Unknown,
}

impl ReserveSloStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Met => "met",
            Self::Watch => "watch",
            Self::Breached => "breached",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }

    pub fn accepts_release(self) -> bool {
        matches!(self, Self::Met | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyStatus {
    Proven,
    Guarded,
    LinkageRisk,
    Stale,
    Unknown,
}

impl PrivacyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Guarded => "guarded",
            Self::LinkageRisk => "linkage_risk",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }

    pub fn accepts_release(self) -> bool {
        matches!(self, Self::Proven | Self::Guarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
    Unknown,
}

impl AcknowledgementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldNoticeStatus {
    Draft,
    Published,
    Acknowledged,
    Superseded,
    Expired,
    Missing,
}

impl HoldNoticeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Acknowledged => "acknowledged",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Missing => "missing",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Published | Self::Acknowledged)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoNoGoStatus {
    Go,
    NoGo,
    Hold,
    FailClosed,
}

impl GoNoGoStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no_go",
            Self::Hold => "hold",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVote {
    Go,
    NoGo,
    Abstain,
    FailClosed,
}

impl GovernanceVote {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no_go",
            Self::Abstain => "abstain",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlockerKind {
    MissingEnforcementRoot,
    MissingCircuitBreakerRoot,
    CircuitBreakerOpen,
    PqEpochInvalid,
    ReserveSloBreached,
    PrivacyLinkageRisk,
    OperatorAckMissing,
    WalletNoticeMissing,
    PublicHoldNoticeMissing,
    GovernanceNoGo,
    StaleManifest,
}

impl ReleaseBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingEnforcementRoot => "missing_enforcement_root",
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::CircuitBreakerOpen => "circuit_breaker_open",
            Self::PqEpochInvalid => "pq_epoch_invalid",
            Self::ReserveSloBreached => "reserve_slo_breached",
            Self::PrivacyLinkageRisk => "privacy_linkage_risk",
            Self::OperatorAckMissing => "operator_ack_missing",
            Self::WalletNoticeMissing => "wallet_notice_missing",
            Self::PublicHoldNoticeMissing => "public_hold_notice_missing",
            Self::GovernanceNoGo => "governance_no_go",
            Self::StaleManifest => "stale_manifest",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub governance_realm: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_exit_latency_blocks: u64,
    pub max_hold_notice_age_blocks: u64,
    pub max_open_breakers: u16,
    pub operator_ack_quorum_bps: u64,
    pub wallet_notice_quorum_bps: u64,
    pub public_hold_notice_quorum_bps: u64,
    pub max_manifests: usize,
    pub max_governance_packages: usize,
    pub max_operator_acks: usize,
    pub max_hold_notices: usize,
    pub max_decisions: usize,
    pub hash_suite: String,
    pub release_manifest_scheme: String,
    pub circuit_breaker_scheme: String,
    pub pq_epoch_scheme: String,
    pub reserve_slo_scheme: String,
    pub privacy_non_linkage_scheme: String,
    pub operator_ack_scheme: String,
    pub wallet_hold_notice_scheme: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            governance_realm: DEFAULT_GOVERNANCE_REALM.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_exit_latency_blocks: DEFAULT_MAX_EXIT_LATENCY_BLOCKS,
            max_hold_notice_age_blocks: DEFAULT_MAX_HOLD_NOTICE_AGE_BLOCKS,
            max_open_breakers: DEFAULT_MAX_OPEN_BREAKERS,
            operator_ack_quorum_bps: DEFAULT_OPERATOR_ACK_QUORUM_BPS,
            wallet_notice_quorum_bps: DEFAULT_WALLET_NOTICE_QUORUM_BPS,
            public_hold_notice_quorum_bps: DEFAULT_PUBLIC_HOLD_NOTICE_QUORUM_BPS,
            max_manifests: DEFAULT_MAX_MANIFESTS,
            max_governance_packages: DEFAULT_MAX_GOVERNANCE_PACKAGES,
            max_operator_acks: DEFAULT_MAX_OPERATOR_ACKS,
            max_hold_notices: DEFAULT_MAX_HOLD_NOTICES,
            max_decisions: DEFAULT_MAX_DECISIONS,
            hash_suite: HASH_SUITE.to_string(),
            release_manifest_scheme: RELEASE_MANIFEST_SCHEME.to_string(),
            circuit_breaker_scheme: CIRCUIT_BREAKER_SCHEME.to_string(),
            pq_epoch_scheme: PQ_EPOCH_SCHEME.to_string(),
            reserve_slo_scheme: RESERVE_SLO_SCHEME.to_string(),
            privacy_non_linkage_scheme: PRIVACY_NON_LINKAGE_SCHEME.to_string(),
            operator_ack_scheme: OPERATOR_ACK_SCHEME.to_string(),
            wallet_hold_notice_scheme: WALLET_HOLD_NOTICE_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("governance_realm", &self.governance_realm)?;
        require(
            self.min_pq_security_bits >= 128,
            "pq floor must be at least 128 bits",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "privacy set floor must be nonzero",
        )?;
        require(
            self.min_reserve_coverage_bps >= MAX_BPS,
            "reserve coverage must cover at least 100%",
        )?;
        require(
            self.operator_ack_quorum_bps <= MAX_BPS,
            "operator ack quorum exceeds bps",
        )?;
        require(
            self.wallet_notice_quorum_bps <= MAX_BPS,
            "wallet notice quorum exceeds bps",
        )?;
        require(
            self.public_hold_notice_quorum_bps <= MAX_BPS,
            "public hold notice quorum exceeds bps",
        )?;
        require(self.max_manifests > 0, "max manifests must be nonzero")?;
        require(
            self.max_governance_packages > 0,
            "max packages must be nonzero",
        )?;
        require(
            self.max_operator_acks > 0,
            "max operator acks must be nonzero",
        )?;
        require(
            self.max_hold_notices > 0,
            "max hold notices must be nonzero",
        )?;
        require(self.max_decisions > 0, "max decisions must be nonzero")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "governance_realm": self.governance_realm,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_exit_latency_blocks": self.max_exit_latency_blocks,
            "max_hold_notice_age_blocks": self.max_hold_notice_age_blocks,
            "max_open_breakers": self.max_open_breakers,
            "operator_ack_quorum_bps": self.operator_ack_quorum_bps,
            "wallet_notice_quorum_bps": self.wallet_notice_quorum_bps,
            "public_hold_notice_quorum_bps": self.public_hold_notice_quorum_bps,
            "max_manifests": self.max_manifests,
            "max_governance_packages": self.max_governance_packages,
            "max_operator_acks": self.max_operator_acks,
            "max_hold_notices": self.max_hold_notices,
            "max_decisions": self.max_decisions,
            "hash_suite": self.hash_suite,
            "release_manifest_scheme": self.release_manifest_scheme,
            "circuit_breaker_scheme": self.circuit_breaker_scheme,
            "pq_epoch_scheme": self.pq_epoch_scheme,
            "reserve_slo_scheme": self.reserve_slo_scheme,
            "privacy_non_linkage_scheme": self.privacy_non_linkage_scheme,
            "operator_ack_scheme": self.operator_ack_scheme,
            "wallet_hold_notice_scheme": self.wallet_hold_notice_scheme
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseManifest {
    pub manifest_id: String,
    pub release_id: String,
    pub package_id: String,
    pub enforcement_root: String,
    pub circuit_breaker_root: String,
    pub pq_epoch_root: String,
    pub reserve_slo_root: String,
    pub privacy_non_linkage_root: String,
    pub wallet_hold_notice_root: String,
    pub public_hold_notice_root: String,
    pub enforcement_status: EnforcementStatus,
    pub breaker_status: BreakerStatus,
    pub pq_epoch_status: PqEpochStatus,
    pub reserve_slo_status: ReserveSloStatus,
    pub privacy_status: PrivacyStatus,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub reserve_coverage_bps: u64,
    pub open_breaker_count: u16,
    pub exit_latency_blocks: u64,
    pub manifest_height: u64,
    pub expires_at_height: u64,
}

impl ReleaseManifest {
    pub fn devnet() -> Self {
        Self {
            manifest_id: DEFAULT_RELEASE_ID.to_string(),
            release_id: "force-exit-package-pq-reserve-privacy-r1".to_string(),
            package_id: "monero-l2-canonical-user-escape-force-exit-package".to_string(),
            enforcement_root: hash_str("DEVNET-ENFORCEMENT", DEFAULT_RELEASE_ID),
            circuit_breaker_root: hash_str("DEVNET-BREAKER", DEFAULT_RELEASE_ID),
            pq_epoch_root: hash_str("DEVNET-PQ-EPOCH", DEFAULT_RELEASE_ID),
            reserve_slo_root: hash_str("DEVNET-RESERVE-SLO", DEFAULT_RELEASE_ID),
            privacy_non_linkage_root: hash_str("DEVNET-PRIVACY", DEFAULT_RELEASE_ID),
            wallet_hold_notice_root: hash_str("DEVNET-WALLET-HOLD", DEFAULT_RELEASE_ID),
            public_hold_notice_root: hash_str("DEVNET-PUBLIC-HOLD", DEFAULT_RELEASE_ID),
            enforcement_status: EnforcementStatus::Enforced,
            breaker_status: BreakerStatus::Closed,
            pq_epoch_status: PqEpochStatus::Active,
            reserve_slo_status: ReserveSloStatus::Met,
            privacy_status: PrivacyStatus::Proven,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 4,
            reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            open_breaker_count: 0,
            exit_latency_blocks: 18,
            manifest_height: DEFAULT_DEVNET_HEIGHT,
            expires_at_height: DEFAULT_DEVNET_HEIGHT + 144,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "release_id": self.release_id,
            "package_id": self.package_id,
            "enforcement_root": self.enforcement_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "pq_epoch_root": self.pq_epoch_root,
            "reserve_slo_root": self.reserve_slo_root,
            "privacy_non_linkage_root": self.privacy_non_linkage_root,
            "wallet_hold_notice_root": self.wallet_hold_notice_root,
            "public_hold_notice_root": self.public_hold_notice_root,
            "enforcement_status": self.enforcement_status.as_str(),
            "breaker_status": self.breaker_status.as_str(),
            "pq_epoch_status": self.pq_epoch_status.as_str(),
            "reserve_slo_status": self.reserve_slo_status.as_str(),
            "privacy_status": self.privacy_status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "open_breaker_count": self.open_breaker_count,
            "exit_latency_blocks": self.exit_latency_blocks,
            "manifest_height": self.manifest_height,
            "expires_at_height": self.expires_at_height,
            "manifest_root": self.manifest_root()
        })
    }

    pub fn manifest_root(&self) -> String {
        hash_json("RELEASE-MANIFEST", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "release_id": self.release_id,
            "package_id": self.package_id,
            "enforcement_root": self.enforcement_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "pq_epoch_root": self.pq_epoch_root,
            "reserve_slo_root": self.reserve_slo_root,
            "privacy_non_linkage_root": self.privacy_non_linkage_root,
            "wallet_hold_notice_root": self.wallet_hold_notice_root,
            "public_hold_notice_root": self.public_hold_notice_root,
            "enforcement_status": self.enforcement_status.as_str(),
            "breaker_status": self.breaker_status.as_str(),
            "pq_epoch_status": self.pq_epoch_status.as_str(),
            "reserve_slo_status": self.reserve_slo_status.as_str(),
            "privacy_status": self.privacy_status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "open_breaker_count": self.open_breaker_count,
            "exit_latency_blocks": self.exit_latency_blocks,
            "manifest_height": self.manifest_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn validate_for_config(&self, config: &Config, height: u64) -> Result<()> {
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("release_id", &self.release_id)?;
        require_non_empty("package_id", &self.package_id)?;
        require_root("enforcement_root", &self.enforcement_root)?;
        require_root("circuit_breaker_root", &self.circuit_breaker_root)?;
        require_root("pq_epoch_root", &self.pq_epoch_root)?;
        require_root("reserve_slo_root", &self.reserve_slo_root)?;
        require_root("privacy_non_linkage_root", &self.privacy_non_linkage_root)?;
        require_root("wallet_hold_notice_root", &self.wallet_hold_notice_root)?;
        require_root("public_hold_notice_root", &self.public_hold_notice_root)?;
        require(
            self.enforcement_status.is_go_capable(),
            "manifest enforcement is not go-capable",
        )?;
        require(
            !self.breaker_status.fail_closed(),
            "circuit breaker fails closed",
        )?;
        require(
            self.pq_epoch_status.accepts_release(),
            "pq epoch does not accept release",
        )?;
        require(
            self.reserve_slo_status.accepts_release(),
            "reserve slo does not accept release",
        )?;
        require(
            self.privacy_status.accepts_release(),
            "privacy status does not accept release",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "pq security bits below governance floor",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "privacy set size below governance floor",
        )?;
        require(
            self.reserve_coverage_bps >= config.min_reserve_coverage_bps,
            "reserve coverage below governance floor",
        )?;
        require(
            self.open_breaker_count <= config.max_open_breakers,
            "open circuit breaker count exceeds policy",
        )?;
        require(
            self.exit_latency_blocks <= config.max_exit_latency_blocks,
            "exit latency exceeds governance policy",
        )?;
        require(
            height <= self.expires_at_height,
            "release manifest is stale",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_id: String,
    pub manifest_id: String,
    pub release_id: String,
    pub status: AcknowledgementStatus,
    pub signer_root: String,
    pub transcript_root: String,
    pub acknowledged_at_height: u64,
    pub weight_bps: u64,
}

impl OperatorAcknowledgement {
    pub fn devnet(operator_id: &str, weight_bps: u64) -> Self {
        let acknowledgement_id = hash_str("DEVNET-OPERATOR-ACK-ID", operator_id);
        Self {
            acknowledgement_id,
            operator_id: operator_id.to_string(),
            manifest_id: DEFAULT_RELEASE_ID.to_string(),
            release_id: "force-exit-package-pq-reserve-privacy-r1".to_string(),
            status: AcknowledgementStatus::Accepted,
            signer_root: hash_str("DEVNET-OPERATOR-SIGNER", operator_id),
            transcript_root: hash_str("DEVNET-OPERATOR-TRANSCRIPT", operator_id),
            acknowledged_at_height: DEFAULT_DEVNET_HEIGHT + 2,
            weight_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_id": self.operator_id,
            "manifest_id": self.manifest_id,
            "release_id": self.release_id,
            "status": self.status.as_str(),
            "signer_root": self.signer_root,
            "transcript_root": self.transcript_root,
            "acknowledged_at_height": self.acknowledged_at_height,
            "weight_bps": self.weight_bps,
            "acknowledgement_root": self.acknowledgement_root()
        })
    }

    pub fn acknowledgement_root(&self) -> String {
        hash_json(
            "OPERATOR-ACK",
            &json!({
                "acknowledgement_id": self.acknowledgement_id,
                "operator_id": self.operator_id,
                "manifest_id": self.manifest_id,
                "release_id": self.release_id,
                "status": self.status.as_str(),
                "signer_root": self.signer_root,
                "transcript_root": self.transcript_root,
                "acknowledged_at_height": self.acknowledged_at_height,
                "weight_bps": self.weight_bps
            }),
        )
    }

    pub fn validates(&self, manifest: &ReleaseManifest) -> bool {
        self.status == AcknowledgementStatus::Accepted
            && self.manifest_id == manifest.manifest_id
            && self.release_id == manifest.release_id
            && !self.signer_root.is_empty()
            && !self.transcript_root.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldNotice {
    pub notice_id: String,
    pub audience_id: String,
    pub manifest_id: String,
    pub release_id: String,
    pub status: HoldNoticeStatus,
    pub wallet_notice_root: String,
    pub public_notice_root: String,
    pub published_at_height: u64,
    pub acknowledged_wallet_bps: u64,
    pub public_notice_bps: u64,
}

impl HoldNotice {
    pub fn devnet(audience_id: &str, wallet_bps: u64, public_bps: u64) -> Self {
        let notice_id = hash_str("DEVNET-HOLD-NOTICE-ID", audience_id);
        Self {
            notice_id,
            audience_id: audience_id.to_string(),
            manifest_id: DEFAULT_RELEASE_ID.to_string(),
            release_id: "force-exit-package-pq-reserve-privacy-r1".to_string(),
            status: HoldNoticeStatus::Acknowledged,
            wallet_notice_root: hash_str("DEVNET-WALLET-NOTICE", audience_id),
            public_notice_root: hash_str("DEVNET-PUBLIC-NOTICE", audience_id),
            published_at_height: DEFAULT_DEVNET_HEIGHT + 3,
            acknowledged_wallet_bps: wallet_bps,
            public_notice_bps: public_bps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "notice_id": self.notice_id,
            "audience_id": self.audience_id,
            "manifest_id": self.manifest_id,
            "release_id": self.release_id,
            "status": self.status.as_str(),
            "wallet_notice_root": self.wallet_notice_root,
            "public_notice_root": self.public_notice_root,
            "published_at_height": self.published_at_height,
            "acknowledged_wallet_bps": self.acknowledged_wallet_bps,
            "public_notice_bps": self.public_notice_bps,
            "hold_notice_root": self.hold_notice_root()
        })
    }

    pub fn hold_notice_root(&self) -> String {
        hash_json(
            "HOLD-NOTICE",
            &json!({
                "notice_id": self.notice_id,
                "audience_id": self.audience_id,
                "manifest_id": self.manifest_id,
                "release_id": self.release_id,
                "status": self.status.as_str(),
                "wallet_notice_root": self.wallet_notice_root,
                "public_notice_root": self.public_notice_root,
                "published_at_height": self.published_at_height,
                "acknowledged_wallet_bps": self.acknowledged_wallet_bps,
                "public_notice_bps": self.public_notice_bps
            }),
        )
    }

    pub fn validates(&self, manifest: &ReleaseManifest, config: &Config, height: u64) -> bool {
        let age = height.saturating_sub(self.published_at_height);
        self.status.is_live()
            && self.manifest_id == manifest.manifest_id
            && self.release_id == manifest.release_id
            && self.acknowledged_wallet_bps >= config.wallet_notice_quorum_bps
            && self.public_notice_bps >= config.public_hold_notice_quorum_bps
            && age <= config.max_hold_notice_age_blocks
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernancePackage {
    pub package_id: String,
    pub manifest_id: String,
    pub proposal_id: String,
    pub governance_vote: GovernanceVote,
    pub vote_weight_bps: u64,
    pub quorum_bps: u64,
    pub enforcement_binding_root: String,
    pub release_manifest_root: String,
    pub operator_ack_root: String,
    pub hold_notice_root: String,
    pub submitted_at_height: u64,
}

impl GovernancePackage {
    pub fn devnet(
        manifest: &ReleaseManifest,
        operator_ack_root: &str,
        hold_notice_root: &str,
    ) -> Self {
        Self {
            package_id: DEFAULT_BINDING_ID.to_string(),
            manifest_id: manifest.manifest_id.clone(),
            proposal_id: "governance-proposal-force-exit-package-r1".to_string(),
            governance_vote: GovernanceVote::Go,
            vote_weight_bps: MAX_BPS,
            quorum_bps: DEFAULT_OPERATOR_ACK_QUORUM_BPS,
            enforcement_binding_root: hash_str("DEVNET-GOVERNANCE-BINDING", &manifest.manifest_id),
            release_manifest_root: manifest.manifest_root(),
            operator_ack_root: operator_ack_root.to_string(),
            hold_notice_root: hold_notice_root.to_string(),
            submitted_at_height: DEFAULT_DEVNET_HEIGHT + 4,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "package_id": self.package_id,
            "manifest_id": self.manifest_id,
            "proposal_id": self.proposal_id,
            "governance_vote": self.governance_vote.as_str(),
            "vote_weight_bps": self.vote_weight_bps,
            "quorum_bps": self.quorum_bps,
            "enforcement_binding_root": self.enforcement_binding_root,
            "release_manifest_root": self.release_manifest_root,
            "operator_ack_root": self.operator_ack_root,
            "hold_notice_root": self.hold_notice_root,
            "submitted_at_height": self.submitted_at_height,
            "package_root": self.package_root()
        })
    }

    pub fn package_root(&self) -> String {
        hash_json(
            "GOVERNANCE-PACKAGE",
            &json!({
                "package_id": self.package_id,
                "manifest_id": self.manifest_id,
                "proposal_id": self.proposal_id,
                "governance_vote": self.governance_vote.as_str(),
                "vote_weight_bps": self.vote_weight_bps,
                "quorum_bps": self.quorum_bps,
                "enforcement_binding_root": self.enforcement_binding_root,
                "release_manifest_root": self.release_manifest_root,
                "operator_ack_root": self.operator_ack_root,
                "hold_notice_root": self.hold_notice_root,
                "submitted_at_height": self.submitted_at_height
            }),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseBlocker {
    pub blocker_id: String,
    pub manifest_id: String,
    pub kind: ReleaseBlockerKind,
    pub evidence_root: String,
    pub observed_at_height: u64,
}

impl ReleaseBlocker {
    pub fn new(
        manifest_id: &str,
        kind: ReleaseBlockerKind,
        evidence_root: String,
        observed_at_height: u64,
    ) -> Self {
        let blocker_id = domain_hash(
            "MONERO-L2-GO-NO-GO-BLOCKER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(manifest_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&evidence_root),
                HashPart::U64(observed_at_height),
            ],
            32,
        );
        Self {
            blocker_id,
            manifest_id: manifest_id.to_string(),
            kind,
            evidence_root,
            observed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "manifest_id": self.manifest_id,
            "kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoNoGoDecision {
    pub decision_id: String,
    pub manifest_id: String,
    pub package_id: String,
    pub status: GoNoGoStatus,
    pub reason: String,
    pub release_manifest_root: String,
    pub enforcement_root: String,
    pub circuit_breaker_root: String,
    pub pq_epoch_root: String,
    pub reserve_slo_root: String,
    pub privacy_non_linkage_root: String,
    pub operator_ack_root: String,
    pub hold_notice_root: String,
    pub blocker_root: String,
    pub decided_at_height: u64,
}

impl GoNoGoDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "manifest_id": self.manifest_id,
            "package_id": self.package_id,
            "status": self.status.as_str(),
            "reason": self.reason,
            "release_manifest_root": self.release_manifest_root,
            "enforcement_root": self.enforcement_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "pq_epoch_root": self.pq_epoch_root,
            "reserve_slo_root": self.reserve_slo_root,
            "privacy_non_linkage_root": self.privacy_non_linkage_root,
            "operator_ack_root": self.operator_ack_root,
            "hold_notice_root": self.hold_notice_root,
            "blocker_root": self.blocker_root,
            "decided_at_height": self.decided_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub manifest_root: String,
    pub governance_package_root: String,
    pub operator_ack_root: String,
    pub hold_notice_root: String,
    pub decision_root: String,
    pub blocker_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "manifest_root": self.manifest_root,
            "governance_package_root": self.governance_package_root,
            "operator_ack_root": self.operator_ack_root,
            "hold_notice_root": self.hold_notice_root,
            "decision_root": self.decision_root,
            "blocker_root": self.blocker_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub manifest_count: u64,
    pub governance_package_count: u64,
    pub operator_ack_count: u64,
    pub hold_notice_count: u64,
    pub decision_count: u64,
    pub blocker_count: u64,
    pub go_count: u64,
    pub no_go_count: u64,
    pub hold_count: u64,
    pub fail_closed_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_count": self.manifest_count,
            "governance_package_count": self.governance_package_count,
            "operator_ack_count": self.operator_ack_count,
            "hold_notice_count": self.hold_notice_count,
            "decision_count": self.decision_count,
            "blocker_count": self.blocker_count,
            "go_count": self.go_count,
            "no_go_count": self.no_go_count,
            "hold_count": self.hold_count,
            "fail_closed_count": self.fail_closed_count
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub manifests: BTreeMap<String, ReleaseManifest>,
    pub governance_packages: BTreeMap<String, GovernancePackage>,
    pub operator_acknowledgements: BTreeMap<String, OperatorAcknowledgement>,
    pub hold_notices: BTreeMap<String, HoldNotice>,
    pub decisions: BTreeMap<String, GoNoGoDecision>,
    pub blockers: BTreeMap<String, ReleaseBlocker>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            manifests: BTreeMap::new(),
            governance_packages: BTreeMap::new(),
            operator_acknowledgements: BTreeMap::new(),
            hold_notices: BTreeMap::new(),
            decisions: BTreeMap::new(),
            blockers: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let manifest = ReleaseManifest::devnet();
        let mut state = Self {
            config,
            height: DEFAULT_DEVNET_HEIGHT + 6,
            manifests: BTreeMap::new(),
            governance_packages: BTreeMap::new(),
            operator_acknowledgements: BTreeMap::new(),
            hold_notices: BTreeMap::new(),
            decisions: BTreeMap::new(),
            blockers: BTreeMap::new(),
        };
        let primary_ack = OperatorAcknowledgement::devnet("operator-alpha", 4_000);
        let secondary_ack = OperatorAcknowledgement::devnet("operator-beta", 4_000);
        let tertiary_ack = OperatorAcknowledgement::devnet("operator-gamma", 2_000);
        let hold_notice = HoldNotice::devnet("all-wallets", MAX_BPS, MAX_BPS);
        let operator_ack_root = merkle_root(
            "MONERO-L2-GO-NO-GO-DEVNET-ACKS",
            &[
                primary_ack.public_record(),
                secondary_ack.public_record(),
                tertiary_ack.public_record(),
            ],
        );
        let hold_notice_root = merkle_root(
            "MONERO-L2-GO-NO-GO-DEVNET-HOLD-NOTICES",
            &[hold_notice.public_record()],
        );
        let package = GovernancePackage::devnet(&manifest, &operator_ack_root, &hold_notice_root);
        state
            .manifests
            .insert(manifest.manifest_id.clone(), manifest.clone());
        state
            .operator_acknowledgements
            .insert(primary_ack.acknowledgement_id.clone(), primary_ack);
        state
            .operator_acknowledgements
            .insert(secondary_ack.acknowledgement_id.clone(), secondary_ack);
        state
            .operator_acknowledgements
            .insert(tertiary_ack.acknowledgement_id.clone(), tertiary_ack);
        state
            .hold_notices
            .insert(hold_notice.notice_id.clone(), hold_notice);
        state
            .governance_packages
            .insert(package.package_id.clone(), package.clone());
        let _ = state.bind_governance_decision(&manifest.manifest_id, &package.package_id);
        state
    }

    pub fn add_manifest(&mut self, manifest: ReleaseManifest) -> Result<()> {
        require(
            self.manifests.len() < self.config.max_manifests,
            "manifest capacity reached",
        )?;
        manifest.validate_for_config(&self.config, self.height)?;
        self.manifests
            .insert(manifest.manifest_id.clone(), manifest);
        Ok(())
    }

    pub fn add_operator_acknowledgement(&mut self, ack: OperatorAcknowledgement) -> Result<()> {
        require(
            self.operator_acknowledgements.len() < self.config.max_operator_acks,
            "operator acknowledgement capacity reached",
        )?;
        require_non_empty("acknowledgement_id", &ack.acknowledgement_id)?;
        require(
            ack.weight_bps <= MAX_BPS,
            "operator acknowledgement weight exceeds bps",
        )?;
        require_root("signer_root", &ack.signer_root)?;
        require_root("transcript_root", &ack.transcript_root)?;
        self.operator_acknowledgements
            .insert(ack.acknowledgement_id.clone(), ack);
        Ok(())
    }

    pub fn add_hold_notice(&mut self, notice: HoldNotice) -> Result<()> {
        require(
            self.hold_notices.len() < self.config.max_hold_notices,
            "hold notice capacity reached",
        )?;
        require_non_empty("notice_id", &notice.notice_id)?;
        require_root("wallet_notice_root", &notice.wallet_notice_root)?;
        require_root("public_notice_root", &notice.public_notice_root)?;
        require(
            notice.acknowledged_wallet_bps <= MAX_BPS,
            "wallet notice acknowledgement exceeds bps",
        )?;
        require(
            notice.public_notice_bps <= MAX_BPS,
            "public notice exceeds bps",
        )?;
        self.hold_notices.insert(notice.notice_id.clone(), notice);
        Ok(())
    }

    pub fn add_governance_package(&mut self, package: GovernancePackage) -> Result<()> {
        require(
            self.governance_packages.len() < self.config.max_governance_packages,
            "governance package capacity reached",
        )?;
        require_non_empty("package_id", &package.package_id)?;
        require_root(
            "enforcement_binding_root",
            &package.enforcement_binding_root,
        )?;
        require_root("release_manifest_root", &package.release_manifest_root)?;
        require_root("operator_ack_root", &package.operator_ack_root)?;
        require_root("hold_notice_root", &package.hold_notice_root)?;
        require(
            package.vote_weight_bps <= MAX_BPS,
            "governance vote weight exceeds bps",
        )?;
        require(
            package.quorum_bps <= MAX_BPS,
            "governance quorum exceeds bps",
        )?;
        self.governance_packages
            .insert(package.package_id.clone(), package);
        Ok(())
    }

    pub fn bind_governance_decision(
        &mut self,
        manifest_id: &str,
        package_id: &str,
    ) -> Result<GoNoGoDecision> {
        require(
            self.decisions.len() < self.config.max_decisions,
            "decision capacity reached",
        )?;
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or_else(|| "manifest not found".to_string())?
            .clone();
        let package = self
            .governance_packages
            .get(package_id)
            .ok_or_else(|| "governance package not found".to_string())?
            .clone();
        let blockers = self.evaluate_blockers(&manifest, &package);
        for blocker in blockers.iter() {
            self.blockers
                .insert(blocker.blocker_id.clone(), blocker.clone());
        }
        let blocker_records = blockers
            .iter()
            .map(ReleaseBlocker::public_record)
            .collect::<Vec<_>>();
        let blocker_root = merkle_root("MONERO-L2-GO-NO-GO-BLOCKERS", &blocker_records);
        let (status, reason) = if blockers.is_empty() {
            (
                GoNoGoStatus::Go,
                "all release-manifest enforcement gates are bound".to_string(),
            )
        } else if blockers.iter().any(|blocker| {
            matches!(
                blocker.kind,
                ReleaseBlockerKind::MissingEnforcementRoot
                    | ReleaseBlockerKind::MissingCircuitBreakerRoot
                    | ReleaseBlockerKind::CircuitBreakerOpen
                    | ReleaseBlockerKind::PqEpochInvalid
                    | ReleaseBlockerKind::PrivacyLinkageRisk
            )
        }) {
            (
                GoNoGoStatus::FailClosed,
                "one or more critical roots fail closed".to_string(),
            )
        } else {
            (
                GoNoGoStatus::NoGo,
                "release blockers require governance remediation".to_string(),
            )
        };
        let decision_id = domain_hash(
            "MONERO-L2-GO-NO-GO-DECISION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&manifest.manifest_id),
                HashPart::Str(&package.package_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&blocker_root),
                HashPart::U64(self.height),
            ],
            32,
        );
        let decision = GoNoGoDecision {
            decision_id,
            manifest_id: manifest.manifest_id.clone(),
            package_id: package.package_id.clone(),
            status,
            reason,
            release_manifest_root: manifest.manifest_root(),
            enforcement_root: manifest.enforcement_root.clone(),
            circuit_breaker_root: manifest.circuit_breaker_root.clone(),
            pq_epoch_root: manifest.pq_epoch_root.clone(),
            reserve_slo_root: manifest.reserve_slo_root.clone(),
            privacy_non_linkage_root: manifest.privacy_non_linkage_root.clone(),
            operator_ack_root: package.operator_ack_root.clone(),
            hold_notice_root: package.hold_notice_root.clone(),
            blocker_root,
            decided_at_height: self.height,
        };
        self.decisions
            .insert(decision.decision_id.clone(), decision.clone());
        Ok(decision)
    }

    pub fn evaluate_blockers(
        &self,
        manifest: &ReleaseManifest,
        package: &GovernancePackage,
    ) -> Vec<ReleaseBlocker> {
        let mut blockers = Vec::new();
        self.push_root_blocker(
            &mut blockers,
            manifest,
            ReleaseBlockerKind::MissingEnforcementRoot,
            &manifest.enforcement_root,
        );
        self.push_root_blocker(
            &mut blockers,
            manifest,
            ReleaseBlockerKind::MissingCircuitBreakerRoot,
            &manifest.circuit_breaker_root,
        );
        if manifest.breaker_status.fail_closed()
            || manifest.open_breaker_count > self.config.max_open_breakers
        {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::CircuitBreakerOpen,
                manifest.circuit_breaker_root.clone(),
                self.height,
            ));
        }
        if !manifest.pq_epoch_status.accepts_release()
            || manifest.pq_security_bits < self.config.min_pq_security_bits
        {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::PqEpochInvalid,
                manifest.pq_epoch_root.clone(),
                self.height,
            ));
        }
        if !manifest.reserve_slo_status.accepts_release()
            || manifest.reserve_coverage_bps < self.config.min_reserve_coverage_bps
            || manifest.exit_latency_blocks > self.config.max_exit_latency_blocks
        {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::ReserveSloBreached,
                manifest.reserve_slo_root.clone(),
                self.height,
            ));
        }
        if !manifest.privacy_status.accepts_release()
            || manifest.privacy_set_size < self.config.min_privacy_set_size
        {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::PrivacyLinkageRisk,
                manifest.privacy_non_linkage_root.clone(),
                self.height,
            ));
        }
        if self.accepted_operator_ack_bps(manifest) < self.config.operator_ack_quorum_bps {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::OperatorAckMissing,
                package.operator_ack_root.clone(),
                self.height,
            ));
        }
        if !self.hold_notice_quorum_met(manifest) {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::WalletNoticeMissing,
                package.hold_notice_root.clone(),
                self.height,
            ));
        }
        if package.governance_vote != GovernanceVote::Go
            || package.vote_weight_bps < package.quorum_bps
        {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::GovernanceNoGo,
                package.package_root(),
                self.height,
            ));
        }
        if self.height > manifest.expires_at_height {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                ReleaseBlockerKind::StaleManifest,
                manifest.manifest_root(),
                self.height,
            ));
        }
        blockers
    }

    pub fn accepted_operator_ack_bps(&self, manifest: &ReleaseManifest) -> u64 {
        self.operator_acknowledgements
            .values()
            .filter(|ack| ack.validates(manifest))
            .map(|ack| ack.weight_bps)
            .fold(0_u64, |acc, value| acc.saturating_add(value))
            .min(MAX_BPS)
    }

    pub fn hold_notice_quorum_met(&self, manifest: &ReleaseManifest) -> bool {
        self.hold_notices
            .values()
            .any(|notice| notice.validates(manifest, &self.config, self.height))
    }

    pub fn roots(&self) -> Roots {
        let config_root = hash_json("CONFIG", &self.config.public_record());
        let manifest_root = merkle_root(
            "MONERO-L2-GO-NO-GO-MANIFESTS",
            &self
                .manifests
                .values()
                .map(ReleaseManifest::public_record)
                .collect::<Vec<_>>(),
        );
        let governance_package_root = merkle_root(
            "MONERO-L2-GO-NO-GO-GOVERNANCE-PACKAGES",
            &self
                .governance_packages
                .values()
                .map(GovernancePackage::public_record)
                .collect::<Vec<_>>(),
        );
        let operator_ack_root = merkle_root(
            "MONERO-L2-GO-NO-GO-OPERATOR-ACKS",
            &self
                .operator_acknowledgements
                .values()
                .map(OperatorAcknowledgement::public_record)
                .collect::<Vec<_>>(),
        );
        let hold_notice_root = merkle_root(
            "MONERO-L2-GO-NO-GO-HOLD-NOTICES",
            &self
                .hold_notices
                .values()
                .map(HoldNotice::public_record)
                .collect::<Vec<_>>(),
        );
        let decision_root = merkle_root(
            "MONERO-L2-GO-NO-GO-DECISIONS",
            &self
                .decisions
                .values()
                .map(GoNoGoDecision::public_record)
                .collect::<Vec<_>>(),
        );
        let blocker_root = merkle_root(
            "MONERO-L2-GO-NO-GO-BLOCKERS-STATE",
            &self
                .blockers
                .values()
                .map(ReleaseBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let state_root = domain_hash(
            "MONERO-L2-GO-NO-GO-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Str(&config_root),
                HashPart::Str(&manifest_root),
                HashPart::Str(&governance_package_root),
                HashPart::Str(&operator_ack_root),
                HashPart::Str(&hold_notice_root),
                HashPart::Str(&decision_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        Roots {
            config_root,
            manifest_root,
            governance_package_root,
            operator_ack_root,
            hold_notice_root,
            decision_root,
            blocker_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let mut go_count = 0_u64;
        let mut no_go_count = 0_u64;
        let mut hold_count = 0_u64;
        let mut fail_closed_count = 0_u64;
        for decision in self.decisions.values() {
            match decision.status {
                GoNoGoStatus::Go => go_count = go_count.saturating_add(1),
                GoNoGoStatus::NoGo => no_go_count = no_go_count.saturating_add(1),
                GoNoGoStatus::Hold => hold_count = hold_count.saturating_add(1),
                GoNoGoStatus::FailClosed => fail_closed_count = fail_closed_count.saturating_add(1),
            }
        }
        Counters {
            manifest_count: self.manifests.len() as u64,
            governance_package_count: self.governance_packages.len() as u64,
            operator_ack_count: self.operator_acknowledgements.len() as u64,
            hold_notice_count: self.hold_notices.len() as u64,
            decision_count: self.decisions.len() as u64,
            blocker_count: self.blockers.len() as u64,
            go_count,
            no_go_count,
            hold_count,
            fail_closed_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "manifests": self.manifests.values().map(ReleaseManifest::public_record).collect::<Vec<_>>(),
            "governance_packages": self.governance_packages.values().map(GovernancePackage::public_record).collect::<Vec<_>>(),
            "operator_acknowledgements": self.operator_acknowledgements.values().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "hold_notices": self.hold_notices.values().map(HoldNotice::public_record).collect::<Vec<_>>(),
            "decisions": self.decisions.values().map(GoNoGoDecision::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.values().map(ReleaseBlocker::public_record).collect::<Vec<_>>(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn push_root_blocker(
        &self,
        blockers: &mut Vec<ReleaseBlocker>,
        manifest: &ReleaseManifest,
        kind: ReleaseBlockerKind,
        root: &str,
    ) {
        if root.is_empty() {
            blockers.push(ReleaseBlocker::new(
                &manifest.manifest_id,
                kind,
                hash_str("EMPTY-ROOT-EVIDENCE", kind.as_str()),
                self.height,
            ));
        }
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

pub fn state_root_from_record(record: &Value) -> String {
    hash_json("STATE-FROM-RECORD", record)
}

fn hash_json(label: &str, value: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-GO-NO-GO-{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn hash_str(label: &str, value: &str) -> String {
    domain_hash(
        &format!("MONERO-L2-GO-NO-GO-{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must be non-empty"),
    )
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    require(value.len() >= 32, &format!("{label} must be root-like"))
}
