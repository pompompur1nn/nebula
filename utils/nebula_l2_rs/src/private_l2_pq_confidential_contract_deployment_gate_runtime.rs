use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_DEPLOYMENT_GATE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-deployment-gate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_DEPLOYMENT_GATE_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_DEPLOYMENT_GATE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_DEPLOYMENT_GATE_RUNTIME_SCHEMA_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-deployment-gate-v1";
pub const CONTRACT_MANIFEST_SCHEME: &str =
    "private-l2-pq-confidential-contract-deployment-manifest-v1";
pub const BYTECODE_ATTESTATION_SCHEME: &str = "private-l2-pq-confidential-bytecode-attestation-v1";
pub const PRIVACY_FENCE_SCHEME: &str =
    "private-l2-pq-confidential-contract-deployment-privacy-fence-v1";
pub const LOW_FEE_SPONSOR_SCHEME: &str =
    "private-l2-low-fee-pq-confidential-deployment-sponsor-reservation-v1";
pub const UPGRADE_WINDOW_SCHEME: &str = "private-l2-pq-confidential-contract-upgrade-window-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "private-l2-pq-confidential-contract-deployment-slashing-evidence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_CHAIN_ID: u64 = 20_260_617;
pub const DEVNET_HEIGHT: u64 = 2_240_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_STRONG_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_DEPLOYMENT_FEE_BPS: u64 = 24;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 15;
pub const DEFAULT_GATE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_GATE_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MANIFEST_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_FEE_RESERVATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_UPGRADE_WINDOW_TTL_BLOCKS: u64 = 43_200;
pub const MAX_MANIFESTS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_FENCES: usize = 4_194_304;
pub const MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const MAX_UPGRADE_WINDOWS: usize = 1_048_576;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Wallet,
    Token,
    Dex,
    Lending,
    Derivatives,
    Governance,
    Oracle,
    Bridge,
    Treasury,
    General,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Token => "token",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Derivatives => "derivatives",
            Self::Governance => "governance",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::General => "general",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentLane {
    FastPath,
    Standard,
    LowFeeBatch,
    GovernanceGuarded,
    EmergencyPatch,
}

impl DeploymentLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastPath => "fast_path",
            Self::Standard => "standard",
            Self::LowFeeBatch => "low_fee_batch",
            Self::GovernanceGuarded => "governance_guarded",
            Self::EmergencyPatch => "emergency_patch",
        }
    }

    pub fn max_fee_bps(self) -> u64 {
        match self {
            Self::FastPath => 36,
            Self::Standard => 24,
            Self::LowFeeBatch => 12,
            Self::GovernanceGuarded => 18,
            Self::EmergencyPatch => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Pending,
    Approved,
    ApprovedWithSponsor,
    NeedsMoreAttestations,
    NeedsPrivacyFence,
    Rejected,
}

impl GateDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::ApprovedWithSponsor => "approved_with_sponsor",
            Self::NeedsMoreAttestations => "needs_more_attestations",
            Self::NeedsPrivacyFence => "needs_privacy_fence",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub strong_privacy_set_size: u64,
    pub max_deployment_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub gate_quorum_bps: u64,
    pub strong_gate_quorum_bps: u64,
    pub manifest_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub fee_reservation_ttl_blocks: u64,
    pub upgrade_window_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            strong_privacy_set_size: DEFAULT_STRONG_PRIVACY_SET_SIZE,
            max_deployment_fee_bps: DEFAULT_MAX_DEPLOYMENT_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            gate_quorum_bps: DEFAULT_GATE_QUORUM_BPS,
            strong_gate_quorum_bps: DEFAULT_STRONG_GATE_QUORUM_BPS,
            manifest_ttl_blocks: DEFAULT_MANIFEST_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            fee_reservation_ttl_blocks: DEFAULT_FEE_RESERVATION_TTL_BLOCKS,
            upgrade_window_ttl_blocks: DEFAULT_UPGRADE_WINDOW_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "strong_privacy_set_size": self.strong_privacy_set_size,
            "max_deployment_fee_bps": self.max_deployment_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "gate_quorum_bps": self.gate_quorum_bps,
            "strong_gate_quorum_bps": self.strong_gate_quorum_bps,
            "manifest_ttl_blocks": self.manifest_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fence_ttl_blocks": self.fence_ttl_blocks,
            "fee_reservation_ttl_blocks": self.fee_reservation_ttl_blocks,
            "upgrade_window_ttl_blocks": self.upgrade_window_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub manifests_submitted: u64,
    pub attestations_recorded: u64,
    pub privacy_fences_registered: u64,
    pub sponsor_reservations_opened: u64,
    pub upgrade_windows_opened: u64,
    pub approvals_issued: u64,
    pub rejections_issued: u64,
    pub slashing_reports: u64,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "manifests_submitted": self.manifests_submitted,
            "attestations_recorded": self.attestations_recorded,
            "privacy_fences_registered": self.privacy_fences_registered,
            "sponsor_reservations_opened": self.sponsor_reservations_opened,
            "upgrade_windows_opened": self.upgrade_windows_opened,
            "approvals_issued": self.approvals_issued,
            "rejections_issued": self.rejections_issued,
            "slashing_reports": self.slashing_reports,
            "events_emitted": self.events_emitted,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub manifests_root: String,
    pub attestations_root: String,
    pub privacy_fences_root: String,
    pub sponsor_reservations_root: String,
    pub upgrade_windows_root: String,
    pub denied_nullifiers_root: String,
    pub slashing_evidence_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "manifests_root": self.manifests_root,
            "attestations_root": self.attestations_root,
            "privacy_fences_root": self.privacy_fences_root,
            "sponsor_reservations_root": self.sponsor_reservations_root,
            "upgrade_windows_root": self.upgrade_windows_root,
            "denied_nullifiers_root": self.denied_nullifiers_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentManifest {
    pub manifest_id: String,
    pub contract_domain: ContractDomain,
    pub deployment_lane: DeploymentLane,
    pub deployer_commitment: String,
    pub contract_address_commitment: String,
    pub bytecode_commitment: String,
    pub abi_commitment: String,
    pub initial_state_root: String,
    pub witness_policy_root: String,
    pub fee_policy_root: String,
    pub pq_keyset_root: String,
    pub privacy_budget_root: String,
    pub requested_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub dependencies: BTreeSet<String>,
    pub metadata_commitment: String,
}

impl DeploymentManifest {
    pub fn new(
        config: &Config,
        contract_domain: ContractDomain,
        deployment_lane: DeploymentLane,
        deployer_commitment: impl Into<String>,
        bytecode_commitment: impl Into<String>,
        abi_commitment: impl Into<String>,
        nonce: u64,
    ) -> Self {
        let deployer_commitment = deployer_commitment.into();
        let bytecode_commitment = bytecode_commitment.into();
        let abi_commitment = abi_commitment.into();
        let manifest_id = deployment_manifest_id(
            contract_domain,
            deployment_lane,
            &deployer_commitment,
            &bytecode_commitment,
            nonce,
        );
        let contract_address_commitment = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:CONTRACT-ADDRESS",
            &[
                HashPart::Str(&manifest_id),
                HashPart::Str(contract_domain.as_str()),
                HashPart::U64(nonce),
            ],
            32,
        );
        let initial_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:INITIAL-STATE",
            &[HashPart::Str(&manifest_id)],
            32,
        );
        let witness_policy_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:WITNESS-POLICY",
            &[HashPart::Str(&manifest_id), HashPart::Str("devnet-witness")],
            32,
        );
        let fee_policy_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:FEE-POLICY",
            &[
                HashPart::Str(&manifest_id),
                HashPart::U64(deployment_lane.max_fee_bps()),
            ],
            32,
        );
        let pq_keyset_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:PQ-KEYSET",
            &[
                HashPart::Str(&manifest_id),
                HashPart::U64(config.min_pq_security_bits as u64),
            ],
            32,
        );
        let privacy_budget_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:PRIVACY-BUDGET",
            &[
                HashPart::Str(&manifest_id),
                HashPart::U64(config.min_privacy_set_size),
            ],
            32,
        );
        let metadata_commitment = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:METADATA",
            &[
                HashPart::Str(&manifest_id),
                HashPart::Str(CONTRACT_MANIFEST_SCHEME),
            ],
            32,
        );
        Self {
            manifest_id,
            contract_domain,
            deployment_lane,
            deployer_commitment,
            contract_address_commitment,
            bytecode_commitment,
            abi_commitment,
            initial_state_root,
            witness_policy_root,
            fee_policy_root,
            pq_keyset_root,
            privacy_budget_root,
            requested_fee_bps: deployment_lane
                .max_fee_bps()
                .min(config.max_deployment_fee_bps),
            requested_rebate_bps: config.target_rebate_bps,
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            nonce,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.manifest_ttl_blocks),
            dependencies: BTreeSet::new(),
            metadata_commitment,
        }
    }

    pub fn with_dependency(mut self, dependency_id: impl Into<String>) -> Self {
        self.dependencies.insert(dependency_id.into());
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "contract_domain": self.contract_domain,
            "deployment_lane": self.deployment_lane,
            "deployer_commitment": self.deployer_commitment,
            "contract_address_commitment": self.contract_address_commitment,
            "bytecode_commitment": self.bytecode_commitment,
            "abi_commitment": self.abi_commitment,
            "initial_state_root": self.initial_state_root,
            "witness_policy_root": self.witness_policy_root,
            "fee_policy_root": self.fee_policy_root,
            "pq_keyset_root": self.pq_keyset_root,
            "privacy_budget_root": self.privacy_budget_root,
            "requested_fee_bps": self.requested_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "nonce": self.nonce,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "dependencies": self.dependencies,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("MANIFEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqReadinessAttestation {
    pub attestation_id: String,
    pub manifest_id: String,
    pub attestor_commitment: String,
    pub attestor_weight_bps: u64,
    pub pq_security_bits: u16,
    pub bytecode_attestation_root: String,
    pub verifier_policy_root: String,
    pub side_channel_review_root: String,
    pub signature_scheme: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl PqReadinessAttestation {
    pub fn new(
        config: &Config,
        manifest_id: impl Into<String>,
        attestor_commitment: impl Into<String>,
        attestor_weight_bps: u64,
        pq_security_bits: u16,
        nonce: u64,
    ) -> Self {
        let manifest_id = manifest_id.into();
        let attestor_commitment = attestor_commitment.into();
        let attestation_id = pq_attestation_id(&manifest_id, &attestor_commitment, nonce);
        let bytecode_attestation_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:BYTECODE-ATTESTATION",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(BYTECODE_ATTESTATION_SCHEME),
            ],
            32,
        );
        let verifier_policy_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:VERIFIER-POLICY",
            &[
                HashPart::Str(&attestation_id),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        let side_channel_review_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:SIDE-CHANNEL-REVIEW",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str("constant-time-reviewed"),
            ],
            32,
        );
        Self {
            attestation_id,
            manifest_id,
            attestor_commitment,
            attestor_weight_bps: attestor_weight_bps.min(MAX_BPS),
            pq_security_bits,
            bytecode_attestation_root,
            verifier_policy_root,
            side_channel_review_root,
            signature_scheme: PQ_AUTH_SUITE.to_string(),
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.attestation_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "manifest_id": self.manifest_id,
            "attestor_commitment": self.attestor_commitment,
            "attestor_weight_bps": self.attestor_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "bytecode_attestation_root": self.bytecode_attestation_root,
            "verifier_policy_root": self.verifier_policy_root,
            "side_channel_review_root": self.side_channel_review_root,
            "signature_scheme": self.signature_scheme,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub manifest_id: String,
    pub nullifier_root: String,
    pub viewer_policy_root: String,
    pub event_topic_root: String,
    pub minimum_anonymity_set: u64,
    pub disclosure_delay_blocks: u64,
    pub fee_privacy_sponsor_commitment: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn new(config: &Config, manifest_id: impl Into<String>, nonce: u64) -> Self {
        let manifest_id = manifest_id.into();
        let fence_id = privacy_fence_id(&manifest_id, nonce);
        let nullifier_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:NULLIFIER-ROOT",
            &[
                HashPart::Str(&fence_id),
                HashPart::Str(PRIVACY_FENCE_SCHEME),
            ],
            32,
        );
        let viewer_policy_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:VIEWER-POLICY",
            &[
                HashPart::Str(&fence_id),
                HashPart::Str("selective-disclosure"),
            ],
            32,
        );
        let event_topic_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:EVENT-TOPICS",
            &[HashPart::Str(&fence_id), HashPart::Str("sealed-events")],
            32,
        );
        let fee_privacy_sponsor_commitment = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:FEE-PRIVACY-SPONSOR",
            &[
                HashPart::Str(&fence_id),
                HashPart::U64(config.target_rebate_bps),
            ],
            32,
        );
        Self {
            fence_id,
            manifest_id,
            nullifier_root,
            viewer_policy_root,
            event_topic_root,
            minimum_anonymity_set: config.strong_privacy_set_size,
            disclosure_delay_blocks: 720,
            fee_privacy_sponsor_commitment,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.fence_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "manifest_id": self.manifest_id,
            "nullifier_root": self.nullifier_root,
            "viewer_policy_root": self.viewer_policy_root,
            "event_topic_root": self.event_topic_root,
            "minimum_anonymity_set": self.minimum_anonymity_set,
            "disclosure_delay_blocks": self.disclosure_delay_blocks,
            "fee_privacy_sponsor_commitment": self.fee_privacy_sponsor_commitment,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub manifest_id: String,
    pub sponsor_commitment: String,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub reserved_fee_credits: u64,
    pub proof_cache_coupon_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn new(
        config: &Config,
        manifest_id: impl Into<String>,
        sponsor_commitment: impl Into<String>,
        reserved_fee_credits: u64,
        nonce: u64,
    ) -> Self {
        let manifest_id = manifest_id.into();
        let sponsor_commitment = sponsor_commitment.into();
        let reservation_id = sponsor_reservation_id(&manifest_id, &sponsor_commitment, nonce);
        let proof_cache_coupon_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:PROOF-CACHE-COUPON",
            &[
                HashPart::Str(&reservation_id),
                HashPart::U64(reserved_fee_credits),
                HashPart::Str(LOW_FEE_SPONSOR_SCHEME),
            ],
            32,
        );
        Self {
            reservation_id,
            manifest_id,
            sponsor_commitment,
            max_fee_bps: config.max_deployment_fee_bps,
            rebate_bps: config.target_rebate_bps,
            reserved_fee_credits,
            proof_cache_coupon_root,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.fee_reservation_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "manifest_id": self.manifest_id,
            "sponsor_commitment": self.sponsor_commitment,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "reserved_fee_credits": self.reserved_fee_credits,
            "proof_cache_coupon_root": self.proof_cache_coupon_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("SPONSOR-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeWindow {
    pub window_id: String,
    pub manifest_id: String,
    pub previous_manifest_id: String,
    pub timelock_root: String,
    pub compatibility_root: String,
    pub emergency_guard_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl UpgradeWindow {
    pub fn new(
        config: &Config,
        manifest_id: impl Into<String>,
        previous_manifest_id: impl Into<String>,
        nonce: u64,
    ) -> Self {
        let manifest_id = manifest_id.into();
        let previous_manifest_id = previous_manifest_id.into();
        let window_id = upgrade_window_id(&manifest_id, &previous_manifest_id, nonce);
        let timelock_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:TIMELOCK",
            &[
                HashPart::Str(&window_id),
                HashPart::Str(UPGRADE_WINDOW_SCHEME),
            ],
            32,
        );
        let compatibility_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:COMPATIBILITY",
            &[HashPart::Str(&window_id), HashPart::Str("state-compatible")],
            32,
        );
        let emergency_guard_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:EMERGENCY-GUARD",
            &[HashPart::Str(&window_id), HashPart::Str("quorum-guarded")],
            32,
        );
        Self {
            window_id,
            manifest_id,
            previous_manifest_id,
            timelock_root,
            compatibility_root,
            emergency_guard_root,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.upgrade_window_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "manifest_id": self.manifest_id,
            "previous_manifest_id": self.previous_manifest_id,
            "timelock_root": self.timelock_root,
            "compatibility_root": self.compatibility_root,
            "emergency_guard_root": self.emergency_guard_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("UPGRADE-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub manifest_id: String,
    pub accused_commitment: String,
    pub evidence_root: String,
    pub penalty_bps: u64,
    pub reporter_commitment: String,
    pub sealed_details_root: String,
}

impl SlashingEvidence {
    pub fn new(
        manifest_id: impl Into<String>,
        accused_commitment: impl Into<String>,
        reporter_commitment: impl Into<String>,
        penalty_bps: u64,
        nonce: u64,
    ) -> Self {
        let manifest_id = manifest_id.into();
        let accused_commitment = accused_commitment.into();
        let reporter_commitment = reporter_commitment.into();
        let evidence_id = slashing_evidence_id(&manifest_id, &accused_commitment, nonce);
        let evidence_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:SLASHING-EVIDENCE",
            &[
                HashPart::Str(&evidence_id),
                HashPart::Str(SLASHING_EVIDENCE_SCHEME),
            ],
            32,
        );
        let sealed_details_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:SEALED-DETAILS",
            &[
                HashPart::Str(&evidence_id),
                HashPart::Str("privacy-preserving-report"),
            ],
            32,
        );
        Self {
            evidence_id,
            manifest_id,
            accused_commitment,
            evidence_root,
            penalty_bps: penalty_bps.min(MAX_BPS),
            reporter_commitment,
            sealed_details_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "manifest_id": self.manifest_id,
            "accused_commitment": self.accused_commitment,
            "evidence_root": self.evidence_root,
            "penalty_bps": self.penalty_bps,
            "reporter_commitment": self.reporter_commitment,
            "sealed_details_root": self.sealed_details_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("SLASHING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GateReceipt {
    pub receipt_id: String,
    pub manifest_id: String,
    pub decision: GateDecision,
    pub quorum_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub sponsor_reservation_id: Option<String>,
    pub gate_root: String,
}

impl GateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "manifest_id": self.manifest_id,
            "decision": self.decision,
            "quorum_bps": self.quorum_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "gate_root": self.gate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub manifests: BTreeMap<String, DeploymentManifest>,
    pub attestations: BTreeMap<String, PqReadinessAttestation>,
    pub attestations_by_manifest: BTreeMap<String, BTreeSet<String>>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub sponsor_by_manifest: BTreeMap<String, BTreeSet<String>>,
    pub upgrade_windows: BTreeMap<String, UpgradeWindow>,
    pub denied_nullifiers: BTreeSet<String>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub gate_receipts: BTreeMap<String, GateReceipt>,
    pub events: Vec<Value>,
}

impl State {
    pub fn empty(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            manifests: BTreeMap::new(),
            attestations: BTreeMap::new(),
            attestations_by_manifest: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            sponsor_by_manifest: BTreeMap::new(),
            upgrade_windows: BTreeMap::new(),
            denied_nullifiers: BTreeSet::new(),
            slashing_evidence: BTreeMap::new(),
            gate_receipts: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::empty(config.clone());
        let swap_manifest = DeploymentManifest::new(
            &config,
            ContractDomain::Dex,
            DeploymentLane::LowFeeBatch,
            "deployer:sealed:devnet:amm-router",
            "bytecode:shake256:amm-router:v1",
            "abi:confidential-swap-router:v1",
            7,
        )
        .with_dependency("private-l2-pq-confidential-token-covenant-runtime");
        let lending_manifest = DeploymentManifest::new(
            &config,
            ContractDomain::Lending,
            DeploymentLane::GovernanceGuarded,
            "deployer:sealed:devnet:lending",
            "bytecode:shake256:confidential-lending:v1",
            "abi:confidential-lending-pool:v1",
            11,
        )
        .with_dependency("private-l2-pq-confidential-oracle-mev-resistant-batch-feed-runtime");
        let swap_id = swap_manifest.manifest_id.clone();
        let lending_id = lending_manifest.manifest_id.clone();
        let _ = state.submit_deployment_manifest(swap_manifest);
        let _ = state.submit_deployment_manifest(lending_manifest);
        let _ = state.attest_pq_readiness(PqReadinessAttestation::new(
            &config,
            &swap_id,
            "attestor:ml-dsa:committee-a",
            3_400,
            256,
            1,
        ));
        let _ = state.attest_pq_readiness(PqReadinessAttestation::new(
            &config,
            &swap_id,
            "attestor:slh-dsa:committee-b",
            3_500,
            256,
            2,
        ));
        let _ = state.attest_pq_readiness(PqReadinessAttestation::new(
            &config,
            &lending_id,
            "attestor:ml-dsa:committee-c",
            4_200,
            256,
            3,
        ));
        let _ = state.register_privacy_fence(PrivacyFence::new(&config, &swap_id, 4));
        let _ = state.register_privacy_fence(PrivacyFence::new(&config, &lending_id, 5));
        let _ = state.reserve_deployment_fee(SponsorReservation::new(
            &config,
            &swap_id,
            "sponsor:fee-credit-vault:amm-router",
            2_500_000,
            6,
        ));
        let _ = state.open_upgrade_window(UpgradeWindow::new(
            &config,
            &lending_id,
            "legacy:lending:manifest:v0",
            9,
        ));
        let _ = state.evaluate_gate(&swap_id);
        let _ = state.evaluate_gate(&lending_id);
        state
    }

    pub fn submit_deployment_manifest(&mut self, manifest: DeploymentManifest) -> Result<String> {
        if self.manifests.len() >= MAX_MANIFESTS {
            return Err("deployment manifest capacity exhausted".to_string());
        }
        if manifest.requested_fee_bps > manifest.deployment_lane.max_fee_bps() {
            return Err("manifest fee exceeds lane cap".to_string());
        }
        if manifest.pq_security_bits < self.config.min_pq_security_bits {
            return Err("manifest pq security below runtime minimum".to_string());
        }
        if manifest.privacy_set_size < self.config.min_privacy_set_size {
            return Err("manifest privacy set below runtime minimum".to_string());
        }
        let manifest_id = manifest.manifest_id.clone();
        self.manifests.insert(manifest_id.clone(), manifest);
        self.counters.manifests_submitted = self.counters.manifests_submitted.saturating_add(1);
        self.emit_event("deployment_manifest_submitted", &manifest_id);
        self.refresh_roots();
        Ok(manifest_id)
    }

    pub fn attest_pq_readiness(&mut self, attestation: PqReadinessAttestation) -> Result<String> {
        if self.attestations.len() >= MAX_ATTESTATIONS {
            return Err("pq readiness attestation capacity exhausted".to_string());
        }
        if !self.manifests.contains_key(&attestation.manifest_id) {
            return Err("attestation references unknown manifest".to_string());
        }
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err("attestation pq security below runtime minimum".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        let manifest_id = attestation.manifest_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.attestations_by_manifest
            .entry(manifest_id.clone())
            .or_default()
            .insert(attestation_id.clone());
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.emit_event("pq_readiness_attested", &manifest_id);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn register_privacy_fence(&mut self, fence: PrivacyFence) -> Result<String> {
        if self.privacy_fences.len() >= MAX_FENCES {
            return Err("privacy fence capacity exhausted".to_string());
        }
        if !self.manifests.contains_key(&fence.manifest_id) {
            return Err("privacy fence references unknown manifest".to_string());
        }
        if fence.minimum_anonymity_set < self.config.min_privacy_set_size {
            return Err("privacy fence anonymity set below runtime minimum".to_string());
        }
        let fence_id = fence.fence_id.clone();
        let manifest_id = fence.manifest_id.clone();
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.counters.privacy_fences_registered =
            self.counters.privacy_fences_registered.saturating_add(1);
        self.emit_event("privacy_fence_registered", &manifest_id);
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn reserve_deployment_fee(&mut self, reservation: SponsorReservation) -> Result<String> {
        if self.sponsor_reservations.len() >= MAX_SPONSOR_RESERVATIONS {
            return Err("sponsor reservation capacity exhausted".to_string());
        }
        if !self.manifests.contains_key(&reservation.manifest_id) {
            return Err("sponsor reservation references unknown manifest".to_string());
        }
        if reservation.max_fee_bps > self.config.max_deployment_fee_bps {
            return Err("sponsor reservation exceeds deployment fee cap".to_string());
        }
        let reservation_id = reservation.reservation_id.clone();
        let manifest_id = reservation.manifest_id.clone();
        self.sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        self.sponsor_by_manifest
            .entry(manifest_id.clone())
            .or_default()
            .insert(reservation_id.clone());
        self.counters.sponsor_reservations_opened =
            self.counters.sponsor_reservations_opened.saturating_add(1);
        self.emit_event("deployment_fee_reserved", &manifest_id);
        self.refresh_roots();
        Ok(reservation_id)
    }

    pub fn open_upgrade_window(&mut self, window: UpgradeWindow) -> Result<String> {
        if self.upgrade_windows.len() >= MAX_UPGRADE_WINDOWS {
            return Err("upgrade window capacity exhausted".to_string());
        }
        if !self.manifests.contains_key(&window.manifest_id) {
            return Err("upgrade window references unknown manifest".to_string());
        }
        let window_id = window.window_id.clone();
        let manifest_id = window.manifest_id.clone();
        self.upgrade_windows.insert(window_id.clone(), window);
        self.counters.upgrade_windows_opened =
            self.counters.upgrade_windows_opened.saturating_add(1);
        self.emit_event("upgrade_window_opened", &manifest_id);
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn deny_nullifier(
        &mut self,
        nullifier: impl Into<String>,
        manifest_id: impl AsRef<str>,
    ) -> Result<String> {
        let manifest_id = manifest_id.as_ref();
        if !self.manifests.contains_key(manifest_id) {
            return Err("nullifier denial references unknown manifest".to_string());
        }
        let nullifier = nullifier.into();
        self.denied_nullifiers.insert(nullifier.clone());
        self.emit_event("deployment_nullifier_denied", manifest_id);
        self.refresh_roots();
        Ok(nullifier)
    }

    pub fn slash_invalid_attestation(&mut self, evidence: SlashingEvidence) -> Result<String> {
        if self.slashing_evidence.len() >= MAX_SLASHING_EVIDENCE {
            return Err("slashing evidence capacity exhausted".to_string());
        }
        if !self.manifests.contains_key(&evidence.manifest_id) {
            return Err("slashing evidence references unknown manifest".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        let manifest_id = evidence.manifest_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.counters.slashing_reports = self.counters.slashing_reports.saturating_add(1);
        self.emit_event("invalid_deployment_attestation_slashed", &manifest_id);
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn evaluate_gate(&mut self, manifest_id: impl AsRef<str>) -> Result<GateReceipt> {
        let manifest_id = manifest_id.as_ref();
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or_else(|| "gate evaluation references unknown manifest".to_string())?;
        let quorum_bps = self.attestation_quorum_bps(manifest_id);
        let pq_security_bits = self.minimum_attested_pq_bits(manifest_id);
        let has_privacy_fence = self.has_privacy_fence(manifest_id);
        let sponsor_reservation_id = self
            .sponsor_by_manifest
            .get(manifest_id)
            .and_then(|ids| ids.iter().next().cloned());
        let decision = if self.denied_nullifiers.contains(manifest_id) {
            GateDecision::Rejected
        } else if quorum_bps < self.config.gate_quorum_bps {
            GateDecision::NeedsMoreAttestations
        } else if pq_security_bits < self.config.min_pq_security_bits {
            GateDecision::NeedsMoreAttestations
        } else if !has_privacy_fence {
            GateDecision::NeedsPrivacyFence
        } else if sponsor_reservation_id.is_some()
            || manifest.requested_rebate_bps >= self.config.target_rebate_bps
        {
            GateDecision::ApprovedWithSponsor
        } else {
            GateDecision::Approved
        };
        let receipt_id = gate_receipt_id(manifest_id, decision, quorum_bps);
        let receipt_payload = json!({
            "manifest_id": manifest_id,
            "decision": decision,
            "quorum_bps": quorum_bps,
            "privacy_set_size": manifest.privacy_set_size,
            "pq_security_bits": pq_security_bits,
            "sponsor_reservation_id": sponsor_reservation_id,
        });
        let gate_root = record_root("GATE-RECEIPT", &receipt_payload);
        let receipt = GateReceipt {
            receipt_id: receipt_id.clone(),
            manifest_id: manifest_id.to_string(),
            decision,
            quorum_bps,
            privacy_set_size: manifest.privacy_set_size,
            pq_security_bits,
            sponsor_reservation_id,
            gate_root,
        };
        self.gate_receipts.insert(receipt_id, receipt.clone());
        match decision {
            GateDecision::Approved | GateDecision::ApprovedWithSponsor => {
                self.counters.approvals_issued = self.counters.approvals_issued.saturating_add(1);
            }
            GateDecision::Rejected => {
                self.counters.rejections_issued = self.counters.rejections_issued.saturating_add(1);
            }
            GateDecision::Pending
            | GateDecision::NeedsMoreAttestations
            | GateDecision::NeedsPrivacyFence => {}
        }
        self.emit_event("deployment_gate_evaluated", manifest_id);
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn attestation_quorum_bps(&self, manifest_id: &str) -> u64 {
        self.attestations_by_manifest
            .get(manifest_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.attestations.get(id))
            .map(|attestation| attestation.attestor_weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    pub fn minimum_attested_pq_bits(&self, manifest_id: &str) -> u16 {
        self.attestations_by_manifest
            .get(manifest_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.attestations.get(id))
            .map(|attestation| attestation.pq_security_bits)
            .min()
            .unwrap_or(0)
    }

    pub fn has_privacy_fence(&self, manifest_id: &str) -> bool {
        self.privacy_fences
            .values()
            .any(|fence| fence.manifest_id == manifest_id)
    }

    pub fn quote_deployment_fee_bps(
        &self,
        domain: ContractDomain,
        lane: DeploymentLane,
        expected_witness_bytes: u64,
    ) -> u64 {
        let domain_premium = match domain {
            ContractDomain::Wallet => 1,
            ContractDomain::Token => 2,
            ContractDomain::Dex => 4,
            ContractDomain::Lending => 5,
            ContractDomain::Derivatives => 7,
            ContractDomain::Governance => 3,
            ContractDomain::Oracle => 3,
            ContractDomain::Bridge => 6,
            ContractDomain::Treasury => 4,
            ContractDomain::General => 2,
        };
        let witness_premium = expected_witness_bytes / 64_000;
        lane.max_fee_bps()
            .saturating_add(domain_premium)
            .saturating_add(witness_premium)
            .min(self.config.max_deployment_fee_bps.max(lane.max_fee_bps()))
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            manifests_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:MANIFESTS",
                self.manifests
                    .values()
                    .map(DeploymentManifest::public_record),
            ),
            attestations_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:ATTESTATIONS",
                self.attestations
                    .values()
                    .map(PqReadinessAttestation::public_record),
            ),
            privacy_fences_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:PRIVACY-FENCES",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            sponsor_reservations_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:SPONSORS",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservation::public_record),
            ),
            upgrade_windows_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:UPGRADES",
                self.upgrade_windows
                    .values()
                    .map(UpgradeWindow::public_record),
            ),
            denied_nullifiers_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:DENIED-NULLIFIERS",
                self.denied_nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier)),
            ),
            slashing_evidence_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:SLASHING",
                self.slashing_evidence
                    .values()
                    .map(SlashingEvidence::public_record),
            ),
            events_root: collection_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:EVENTS",
                self.events.iter().cloned(),
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "manifests": self.manifests.values().map(DeploymentManifest::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqReadinessAttestation::public_record).collect::<Vec<_>>(),
            "attestations_by_manifest": self.attestations_by_manifest,
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "sponsor_reservations": self.sponsor_reservations.values().map(SponsorReservation::public_record).collect::<Vec<_>>(),
            "sponsor_by_manifest": self.sponsor_by_manifest,
            "upgrade_windows": self.upgrade_windows.values().map(UpgradeWindow::public_record).collect::<Vec<_>>(),
            "denied_nullifiers": self.denied_nullifiers,
            "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidence::public_record).collect::<Vec<_>>(),
            "gate_receipts": self.gate_receipts.values().map(GateReceipt::public_record).collect::<Vec<_>>(),
            "events": self.events,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:EVENT",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.counters.events_emitted),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "kind": kind,
            "subject_id": subject_id,
            "event_index": self.counters.events_emitted,
        }));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    record
        .get("state_root")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| record_root("STATE-FROM-PUBLIC-RECORD", record))
}

pub fn deployment_manifest_id(
    contract_domain: ContractDomain,
    deployment_lane: DeploymentLane,
    deployer_commitment: &str,
    bytecode_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:MANIFEST-ID",
        &[
            HashPart::Str(contract_domain.as_str()),
            HashPart::Str(deployment_lane.as_str()),
            HashPart::Str(deployer_commitment),
            HashPart::Str(bytecode_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_attestation_id(manifest_id: &str, attestor_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:ATTESTATION-ID",
        &[
            HashPart::Str(manifest_id),
            HashPart::Str(attestor_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn privacy_fence_id(manifest_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:PRIVACY-FENCE-ID",
        &[HashPart::Str(manifest_id), HashPart::U64(nonce)],
        32,
    )
}

pub fn sponsor_reservation_id(manifest_id: &str, sponsor_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:SPONSOR-ID",
        &[
            HashPart::Str(manifest_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn upgrade_window_id(manifest_id: &str, previous_manifest_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:UPGRADE-WINDOW-ID",
        &[
            HashPart::Str(manifest_id),
            HashPart::Str(previous_manifest_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn slashing_evidence_id(manifest_id: &str, accused_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:SLASHING-ID",
        &[
            HashPart::Str(manifest_id),
            HashPart::Str(accused_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn gate_receipt_id(manifest_id: &str, decision: GateDecision, quorum_bps: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:GATE-RECEIPT-ID",
        &[
            HashPart::Str(manifest_id),
            HashPart::Str(decision.as_str()),
            HashPart::U64(quorum_bps),
        ],
        32,
    )
}

fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-DEPLOYMENT-GATE:{label}"),
        &[HashPart::Json(value)],
        32,
    )
}

fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
