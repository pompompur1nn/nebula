#![recursion_limit = "512"]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod runtime;

pub const VERSION: &str = "nebula-testnet-runner/0.2.0";
pub const CHAIN_ID: &str = "nebula-private-l2-testnet";
pub const PUBLIC_LAUNCH_BLOCKER: &str = "public-launch-deployment-attestation";
pub const PUBLIC_TESTNET_BUNDLE_ID: &str = "nebula-public-testnet-bundle-1";
pub const RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT: &str = "external-public-endpoint";
pub const RUNTIME_SURFACE_CAPTURE_MODE_LOOPBACK_DEVNET: &str = "loopback-devnet";
pub const NBLA_SYMBOL: &str = "NBLA";
pub const NXMR_SYMBOL: &str = "nXMR";
pub const NEBULAI_UNIT: &str = "nebulai";
pub const NEBULAI_PER_NBLA: u128 = 1_000_000;
pub const NBLA_TARGET_NXMR_NUMERATOR: u128 = 1;
pub const NBLA_TARGET_NXMR_DENOMINATOR: u128 = 1_000;
pub const TARGET_NXMR_BASE_UNITS_PER_NXMR: u128 =
    NEBULAI_PER_NBLA * NBLA_TARGET_NXMR_DENOMINATOR / NBLA_TARGET_NXMR_NUMERATOR;
pub const TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT: u128 = 1;
pub const MINIMUM_GAS_PRICE_NEBULAI: u128 = 1;
pub const FEE_BASIS_POINTS: u128 = 10_000;
pub const NXMR_BUYBACK_BPS: u128 = FEE_BASIS_POINTS;
pub const NXMR_RESERVE_BACKING_BPS: u128 = 0;
pub const NXMR_VALIDATOR_REWARD_BPS: u128 = FEE_BASIS_POINTS;
pub const TESTNET_POINTS_PER_NEBULAI: u128 = 1;
pub const MIN_PUBLIC_TESTNET_VALIDATORS: usize = 2;
pub const MIN_PUBLIC_TESTNET_OPERATORS: usize = 2;
pub const MIN_PUBLIC_TESTNET_OBSERVERS: usize = 2;
pub const MIN_PUBLIC_TESTNET_REGIONS: usize = 2;
pub const MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS: u128 = 5_000;
pub const MAX_SINGLE_OPERATOR_GENESIS_POWER_BPS: u128 = 5_000;
pub const PUBLIC_TESTNET_GENESIS_EPOCH: u64 = 0;
pub const PUBLIC_TESTNET_ACTIVATION_HEIGHT: u64 = 1;
pub const FUTURE_CLOCK_SKEW_MS: u128 = 300_000;
pub const PUBLIC_ATTESTATION_MAX_AGE_MS: u128 = 86_400_000;
pub const PUBLIC_ATTESTATION_MAX_TTL_MS: u128 = 604_800_000;
pub const MIN_TLS_PIN_VALIDITY_MS: u128 = 604_800_000;
pub const ROLLBACK_DRILL_MAX_AGE_MS: u128 = 604_800_000;

#[derive(Debug, Clone, Serialize)]
pub struct Acceptance {
    pub nebula_guide_mirrored: bool,
    pub testnet_ready: bool,
    pub ci_owned_by_nebula: bool,
    pub legacy_upstream_removed: bool,
    pub local_runtime_buildable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicLaunchReadiness {
    pub public_launch_ready: bool,
    pub level: String,
    pub blocking_gaps: Vec<String>,
    pub required_attestation: String,
    pub remediation_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NebulaReadiness {
    pub chain_id: String,
    pub version: String,
    pub generated_at_unix_ms: u128,
    pub acceptance: Acceptance,
    pub public_launch_readiness: PublicLaunchReadiness,
    pub status_roots: Value,
    pub economics: HybridFeePolicy,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeAsset {
    Nbla,
    NXmr,
}

impl FeeAsset {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Nbla => NBLA_SYMBOL,
            Self::NXmr => NXMR_SYMBOL,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HybridFeePolicy {
    pub native_fee_token: &'static str,
    pub bridged_fee_token: &'static str,
    pub native_base_unit: &'static str,
    pub nebulai_per_nbla: u128,
    pub target_nxmr_per_nbla_numerator: u128,
    pub target_nxmr_per_nbla_denominator: u128,
    pub target_nxmr_base_units_per_nxmr: u128,
    pub target_nxmr_to_nbla_rate_nebulai_per_unit: u128,
    pub minimum_gas_price_nebulai: u128,
    pub bridged_fee_conversion: &'static str,
    pub nxmr_buyback_bps: u128,
    pub nxmr_reserve_backing_bps: u128,
    pub nxmr_validator_reward_bps: u128,
    pub nbla_validator_reward_bps: u128,
    pub testnet_reward_unit: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct HybridFeeQuote {
    pub payment_asset: FeeAsset,
    pub payment_asset_symbol: &'static str,
    pub gas_units: u128,
    pub gas_price_nebulai: u128,
    pub required_fee_nebulai: u128,
    pub nxmr_to_nbla_rate_nebulai_per_unit: Option<u128>,
    pub paid_amount_units: u128,
    pub converted_nbla_nebulai: u128,
    pub buyback_nebulai: u128,
    pub reserve_backing_nebulai: u128,
    pub validator_reward_nebulai: u128,
    pub validator_points: u128,
    pub settlement_note: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAttestation {
    pub chain_id: String,
    pub runtime_version: String,
    pub generated_at_unix_ms: u128,
    pub expires_at_unix_ms: u128,
    pub package_identity: PackageIdentity,
    pub launch_bundle: LaunchBundle,
    pub public_status_manifest: PublicStatusManifest,
    pub public_endpoint: PublicEndpointEvidence,
    pub policy_claim: PolicyClaim,
    pub public_probe: PublicProbe,
    pub preflight_receipt: Receipt,
    pub runbook_receipt: Receipt,
    pub bootstrap_nodes: Vec<BootstrapNode>,
    pub operators: Vec<OperatorAttestation>,
    pub observers: Vec<ObserverAttestation>,
    pub rollback_evidence: RollbackEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub package_name: String,
    pub chain_id: String,
    pub runtime_version: String,
    pub artifact_sha3_256: String,
    pub cargo_lock_sha3_256: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchBundle {
    pub bundle_id: String,
    pub chain_id: String,
    pub package_root: String,
    pub runtime_root: String,
    pub economics_root: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicStatusManifest {
    pub chain_id: String,
    pub status: String,
    pub public_launch_ready: bool,
    pub launch_bundle_root: String,
    pub endpoint_url: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEndpointEvidence {
    pub url: String,
    pub public_status_manifest_root: String,
    pub tls_pins: Vec<TlsEndpointPin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsEndpointPin {
    pub cert_sha256: String,
    pub public_key_sha256: String,
    pub not_after_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyClaim {
    pub readiness_remediation_root: String,
    pub economics_root: String,
    pub native_fee_token: String,
    pub bridged_fee_token: String,
    pub native_base_unit: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProbe {
    pub url: String,
    pub status_code: u16,
    pub body: PublicProbeBody,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicProbeBody {
    pub chain_id: String,
    pub status: String,
    pub public_launch_ready: bool,
    pub launch_bundle_root: String,
    pub fee_policy_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub receipt_id: String,
    pub completed_at_unix_ms: u128,
    pub phases: Vec<ReceiptPhase>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPhase {
    pub name: String,
    pub status: String,
    pub steps: Vec<ReceiptStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptStep {
    pub name: String,
    pub status: String,
    pub evidence_sha3_256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapNode {
    pub node_id: String,
    pub operator_id: String,
    pub region: String,
    pub endpoint: String,
    pub attestation_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAttestation {
    pub operator_id: String,
    pub region: String,
    pub public_key: String,
    pub signed_evidence_root: String,
    pub signature_sha3_256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverAttestation {
    pub observer_id: String,
    pub region: String,
    pub observed_endpoint: String,
    pub observed_evidence_root: String,
    pub signature: SignatureVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureVerification {
    pub algorithm: String,
    pub public_key: String,
    pub signature_sha3_256: String,
    pub signature_hex: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackEvidence {
    pub rollback_plan_sha3_256: String,
    pub last_drill_unix_ms: u128,
    pub recovery_point_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentAttestationReport {
    pub public_launch_ready: bool,
    pub level: &'static str,
    pub evidence_root: String,
    pub endpoint_url: String,
    pub witness_evidence_root: String,
    pub public_surface_root: String,
    pub operator_approval_root: String,
    pub observer_confirmation_root: String,
    pub rollback_readiness_root: String,
    pub deployment_validity_root: String,
    pub deployment_quorum_root: String,
    pub bootstrap_roster_root: String,
    pub operational_evidence_root: String,
    pub attestation_expires_at_unix_ms: u128,
    pub verified_operator_count: usize,
    pub verified_observer_count: usize,
    pub verified_region_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorSetManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub epoch: u64,
    pub reward_unit: String,
    pub fee_policy_root: String,
    pub minimum_validator_count: usize,
    pub minimum_operator_count: usize,
    pub minimum_region_count: usize,
    pub validators: Vec<ValidatorAdmission>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorAdmission {
    pub validator_id: String,
    pub operator_id: String,
    pub node_id: String,
    pub region: String,
    pub operator_contact: String,
    pub consensus_public_key: String,
    pub network_public_key: String,
    pub p2p_endpoint: String,
    pub reward_account: String,
    pub commission_bps: u16,
    pub genesis_power: u64,
    pub signed_admission_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorSetReport {
    pub validator_set_ready: bool,
    pub level: &'static str,
    pub validator_set_root: String,
    pub operator_roster_root: String,
    pub reward_ledger_root: String,
    pub validator_count: usize,
    pub reward_account_count: usize,
    pub operator_count: usize,
    pub region_count: usize,
    pub total_genesis_power: u64,
    pub reward_unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub genesis_time_unix_ms: u128,
    pub activation_height: u64,
    pub deployment_attestation_root: String,
    pub public_surface_root: String,
    pub operator_approval_root: String,
    pub observer_confirmation_root: String,
    pub rollback_readiness_root: String,
    pub deployment_validity_root: String,
    pub deployment_quorum_root: String,
    pub bootstrap_roster_root: String,
    pub operational_evidence_root: String,
    pub validator_set_root: String,
    pub validator_set_epoch: u64,
    pub fee_policy_root: String,
    pub validator_admission_root: String,
    pub operator_roster_root: String,
    pub reward_ledger_root: String,
    pub validator_deployment_binding_root: String,
    pub initial_validator_count: usize,
    pub initial_operator_count: usize,
    pub initial_region_count: usize,
    pub initial_total_power: u64,
    pub native_fee_token: String,
    pub native_base_unit: String,
    pub bridged_fee_token: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenesisManifestReport {
    pub genesis_ready: bool,
    pub level: &'static str,
    pub genesis_root: String,
    pub deployment_attestation_root: String,
    pub public_surface_root: String,
    pub operator_approval_root: String,
    pub observer_confirmation_root: String,
    pub rollback_readiness_root: String,
    pub deployment_validity_root: String,
    pub deployment_quorum_root: String,
    pub bootstrap_roster_root: String,
    pub operational_evidence_root: String,
    pub validator_set_root: String,
    pub validator_set_epoch: u64,
    pub operator_roster_root: String,
    pub reward_ledger_root: String,
    pub validator_deployment_binding_root: String,
    pub initial_validator_count: usize,
    pub initial_operator_count: usize,
    pub initial_region_count: usize,
    pub initial_total_power: u64,
    pub activation_height: u64,
    pub native_fee_token: String,
    pub native_base_unit: String,
    pub bridged_fee_token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchPackageReport {
    pub launch_package_ready: bool,
    pub level: &'static str,
    pub deployment_attestation_root: String,
    pub witness_evidence_root: String,
    pub public_surface_root: String,
    pub operator_approval_root: String,
    pub observer_confirmation_root: String,
    pub rollback_readiness_root: String,
    pub deployment_validity_root: String,
    pub deployment_quorum_root: String,
    pub bootstrap_roster_root: String,
    pub operational_evidence_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub endpoint_url: String,
    pub launch_bundle_root: String,
    pub fee_policy_root: String,
    pub validator_set_root: String,
    pub validator_set_epoch: u64,
    pub operator_roster_root: String,
    pub reward_ledger_root: String,
    pub validator_deployment_binding_root: String,
    pub operator_handoff_root: String,
    pub genesis_root: String,
    pub matched_validator_count: usize,
    pub matched_reward_account_count: usize,
    pub matched_operator_count: usize,
    pub matched_region_count: usize,
    pub deployment_operator_count: usize,
    pub deployment_observer_count: usize,
    pub deployment_region_count: usize,
    pub bootstrap_node_count: usize,
    pub validator_count: usize,
    pub total_genesis_power: u64,
    pub activation_height: u64,
    pub native_fee_token: String,
    pub native_base_unit: String,
    pub bridged_fee_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPackageBundleManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub generated_at_unix_ms: u128,
    pub deployment_attestation_root: String,
    pub deployment_attestation_sha3_256: String,
    pub public_status_manifest_root: String,
    pub public_status_sha3_256: String,
    pub public_probe_root: String,
    pub public_probe_sha3_256: String,
    pub validator_set_root: String,
    pub validator_set_sha3_256: String,
    pub operator_handoff_root: String,
    pub operator_handoff_sha3_256: String,
    pub operator_acceptance_root: String,
    pub operator_acceptance_sha3_256: String,
    pub genesis_root: String,
    pub genesis_manifest_sha3_256: String,
    pub launch_package_root: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchPackageBundleReport {
    pub launch_package_bundle_ready: bool,
    pub level: &'static str,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub generated_at_unix_ms: u128,
    pub artifact_count: usize,
    pub deployment_attestation_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub validator_set_root: String,
    pub operator_handoff_root: String,
    pub operator_acceptance_root: String,
    pub genesis_root: String,
    pub validator_count: usize,
    pub matched_operator_count: usize,
    pub matched_region_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicTestnetPeerManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub generated_at_unix_ms: u128,
    pub endpoint_url: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub deployment_attestation_root: String,
    pub validator_set_root: String,
    pub operator_handoff_root: String,
    pub operator_acceptance_root: String,
    pub genesis_root: String,
    pub sync_peer_quorum: usize,
    pub peers: Vec<PublicTestnetPeer>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicTestnetPeer {
    pub validator_id: String,
    pub operator_id: String,
    pub node_id: String,
    pub region: String,
    pub p2p_endpoint: String,
    pub bootstrap_endpoint: String,
    pub rpc_url: String,
    pub status_url: String,
    pub snapshot_url: String,
    pub consensus_public_key: String,
    pub network_public_key: String,
    pub reward_account: String,
    pub bootstrap_attestation_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicTestnetPeerManifestReport {
    pub public_testnet_peer_manifest_ready: bool,
    pub level: &'static str,
    pub public_testnet_peer_manifest_root: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub deployment_attestation_root: String,
    pub validator_set_root: String,
    pub operator_handoff_root: String,
    pub operator_acceptance_root: String,
    pub genesis_root: String,
    pub endpoint_url: String,
    pub sync_peer_quorum: usize,
    pub peer_count: usize,
    pub operator_count: usize,
    pub region_count: usize,
    pub rpc_peer_urls: Vec<String>,
    pub snapshot_peer_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorActivationManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub validator_set_root: String,
    pub operator_acceptance_root: String,
    pub activated_at_unix_ms: u128,
    pub entries: Vec<ValidatorActivationEntry>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorActivationEntry {
    pub validator_id: String,
    pub operator_id: String,
    pub node_id: String,
    pub p2p_endpoint: String,
    pub consensus_public_key: String,
    pub network_public_key: String,
    pub reward_account: String,
    pub launch_package_bundle_root: String,
    pub operator_acceptance_root: String,
    pub activated: bool,
    pub activation_root: String,
    pub signature: SignatureVerification,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorActivationReport {
    pub validator_activation_ready: bool,
    pub level: &'static str,
    pub validator_activation_root: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub validator_set_root: String,
    pub operator_acceptance_root: String,
    pub activated_validator_count: usize,
    pub activated_operator_count: usize,
    pub activated_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorJoinReceipt {
    pub chain_id: String,
    pub runtime_version: String,
    pub validator_activation_root: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub validator_set_root: String,
    pub joined_at_unix_ms: u128,
    pub activation_height: u64,
    pub entries: Vec<ValidatorJoinEntry>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorJoinEntry {
    pub validator_id: String,
    pub operator_id: String,
    pub node_id: String,
    pub p2p_endpoint: String,
    pub consensus_public_key: String,
    pub activation_root: String,
    pub launch_package_bundle_root: String,
    pub observed_block_height: u64,
    pub peer_count: usize,
    pub joined: bool,
    pub join_root: String,
    pub signature: SignatureVerification,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorJoinReport {
    pub validator_join_ready: bool,
    pub level: &'static str,
    pub validator_join_root: String,
    pub validator_activation_root: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub validator_set_root: String,
    pub joined_validator_count: usize,
    pub joined_operator_count: usize,
    pub activation_height: u64,
    pub min_observed_block_height: u64,
    pub min_peer_count: usize,
    pub joined_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorJoinConfirmationManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub validator_join_root: String,
    pub validator_activation_root: String,
    pub launch_package_bundle_root: String,
    pub operator_acceptance_root: String,
    pub confirmed_at_unix_ms: u128,
    pub entries: Vec<OperatorJoinConfirmationEntry>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorJoinConfirmationEntry {
    pub operator_id: String,
    pub validator_id: String,
    pub node_id: String,
    pub confirmed_join_root: String,
    pub validator_join_root: String,
    pub operator_public_key: String,
    pub confirmed: bool,
    pub confirmation_root: String,
    pub signature: SignatureVerification,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperatorJoinConfirmationReport {
    pub operator_join_confirmation_ready: bool,
    pub level: &'static str,
    pub operator_join_confirmation_root: String,
    pub validator_join_root: String,
    pub validator_activation_root: String,
    pub launch_package_bundle_root: String,
    pub operator_acceptance_root: String,
    pub confirmed_operator_count: usize,
    pub confirmed_validator_count: usize,
    pub confirmed_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicObserverConfirmationManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub operator_join_confirmation_root: String,
    pub validator_join_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub endpoint_url: String,
    pub observed_at_unix_ms: u128,
    pub entries: Vec<PublicObserverConfirmationEntry>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicObserverConfirmationEntry {
    pub observer_id: String,
    pub region: String,
    pub observed_endpoint: String,
    pub observed_public_status_root: String,
    pub observed_public_probe_root: String,
    pub operator_join_confirmation_root: String,
    pub observation_root: String,
    pub signature: SignatureVerification,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicObserverConfirmationReport {
    pub public_observer_confirmation_ready: bool,
    pub level: &'static str,
    pub public_observer_confirmation_root: String,
    pub operator_join_confirmation_root: String,
    pub validator_join_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub endpoint_url: String,
    pub confirmed_observer_count: usize,
    pub confirmed_region_count: usize,
    pub observed_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicTestnetLaunchCertificate {
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub fee_policy_root: String,
    pub validator_activation_root: String,
    pub validator_join_root: String,
    pub operator_join_confirmation_root: String,
    pub public_observer_confirmation_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub runtime_surface_root: String,
    pub validator_set_root: String,
    pub genesis_root: String,
    pub endpoint_url: String,
    pub certified_at_unix_ms: u128,
    pub validator_count: usize,
    pub operator_count: usize,
    pub observer_count: usize,
    pub region_count: usize,
    pub root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicTestnetLaunchCertificateReport {
    pub public_testnet_launch_certificate_ready: bool,
    pub level: &'static str,
    pub public_testnet_launch_certificate_root: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub fee_policy_root: String,
    pub validator_activation_root: String,
    pub validator_join_root: String,
    pub operator_join_confirmation_root: String,
    pub public_observer_confirmation_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub runtime_surface_root: String,
    pub validator_set_root: String,
    pub genesis_root: String,
    pub endpoint_url: String,
    pub validator_count: usize,
    pub operator_count: usize,
    pub observer_count: usize,
    pub region_count: usize,
    pub certified_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicTestnetLaunchReadinessReport {
    pub public_launch_ready: bool,
    pub level: &'static str,
    pub blocking_gaps: Vec<String>,
    pub satisfied_attestation: &'static str,
    pub public_launch_readiness_root: String,
    pub public_testnet_launch_certificate_root: String,
    pub deployment_attestation_root: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub fee_policy_root: String,
    pub validator_activation_root: String,
    pub validator_join_root: String,
    pub operator_join_confirmation_root: String,
    pub public_observer_confirmation_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub runtime_surface_root: String,
    pub runtime_surface_capture_mode: String,
    pub live_rpc_devnet_rehearsal_root: String,
    pub live_rpc_devnet_runtime_surface_root: String,
    pub validator_set_root: String,
    pub genesis_root: String,
    pub endpoint_url: String,
    pub validator_count: usize,
    pub operator_count: usize,
    pub observer_count: usize,
    pub region_count: usize,
    pub certified_at_unix_ms: u128,
    pub generated_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicTestnetLaunchReadinessRejectionReport {
    pub public_launch_ready: bool,
    pub level: &'static str,
    pub blocking_gaps: Vec<String>,
    pub errors: Vec<String>,
    pub required_attestation: &'static str,
    pub public_launch_readiness_rejection_root: String,
    pub generated_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalPublicTestnetRehearsalArtifact {
    pub name: &'static str,
    pub level: &'static str,
    pub root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalPublicTestnetRehearsalReport {
    pub local_public_testnet_rehearsed: bool,
    pub level: &'static str,
    pub chain_id: String,
    pub runtime_version: String,
    pub public_launch_ready: bool,
    pub public_launch_blocker: String,
    pub verified_artifact_count: usize,
    pub verified_artifacts: Vec<LocalPublicTestnetRehearsalArtifact>,
    pub public_testnet_launch_certificate_root: String,
    pub public_testnet_peer_manifest_root: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub validator_activation_root: String,
    pub validator_join_root: String,
    pub operator_join_confirmation_root: String,
    pub public_observer_confirmation_root: String,
    pub validator_count: usize,
    pub operator_count: usize,
    pub observer_count: usize,
    pub region_count: usize,
    pub generated_at_unix_ms: u128,
    pub rehearsal_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRpcDevnetRehearsalReport {
    pub live_rpc_devnet_rehearsed: bool,
    pub level: String,
    pub chain_id: String,
    pub runtime_version: String,
    pub public_launch_ready: bool,
    pub public_launch_blocker: String,
    pub endpoint_url: String,
    pub sequencer_rpc_addr: String,
    pub follower_rpc_addr: String,
    pub block_millis: u64,
    pub sub_second_blocks: bool,
    pub produced_block_count: u64,
    pub runtime_surface_ready: bool,
    pub runtime_surface_root: String,
    pub latest_height: u64,
    pub sync_quorum_met: bool,
    pub sync_successful_peer_count: u64,
    pub sync_import_count: u64,
    pub sync_last_import_height: u64,
    pub sync_quorum_height: u64,
    pub bridge_deposit_count: u64,
    pub withdrawal_request_count: u64,
    pub finalized_withdrawal_count: u64,
    pub bridge_replay_cache_count: u64,
    pub bridge_deposited_nxmr_units: u128,
    pub account_nxmr_units: u128,
    pub withdrawal_reserved_nxmr_units: u128,
    pub total_nxmr_fees_units: u128,
    pub buyback_pool_nebulai: u128,
    pub validator_reward_nebulai: u128,
    pub bridge_custody_reconciled: bool,
    pub nxmr_custody_deficit_units: u128,
    pub sequencer_key_rotation_count: u64,
    pub launch_package_bundle_root: String,
    pub rehearsal_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorHandoffManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_bundle_root: String,
    pub validator_set_root: String,
    pub validator_set_epoch: u64,
    pub validator_deployment_binding_root: String,
    pub entries: Vec<OperatorHandoffEntry>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorHandoffEntry {
    pub operator_id: String,
    pub validator_id: String,
    pub node_id: String,
    pub region: String,
    pub operator_contact: String,
    pub bootstrap_endpoint: String,
    pub p2p_endpoint: String,
    pub reward_account: String,
    pub consensus_public_key: String,
    pub network_public_key: String,
    pub genesis_power: u64,
    pub signed_admission_root: String,
    pub bootstrap_attestation_root: String,
    pub handoff_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperatorHandoffReport {
    pub operator_handoff_ready: bool,
    pub level: &'static str,
    pub operator_handoff_root: String,
    pub entry_count: usize,
    pub operator_count: usize,
    pub region_count: usize,
    pub launch_bundle_root: String,
    pub validator_set_root: String,
    pub validator_deployment_binding_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorAcceptanceManifest {
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_bundle_root: String,
    pub operator_handoff_root: String,
    pub accepted_at_unix_ms: u128,
    pub entries: Vec<OperatorAcceptanceEntry>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorAcceptanceEntry {
    pub operator_id: String,
    pub validator_id: String,
    pub node_id: String,
    pub accepted_handoff_root: String,
    pub operator_public_key: String,
    pub accepted: bool,
    pub acceptance_root: String,
    pub signature: SignatureVerification,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperatorAcceptanceReport {
    pub operator_acceptance_ready: bool,
    pub level: &'static str,
    pub operator_acceptance_root: String,
    pub operator_handoff_root: String,
    pub accepted_operator_count: usize,
    pub accepted_validator_count: usize,
    pub accepted_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicStatusReport {
    pub public_status_ready: bool,
    pub level: &'static str,
    pub public_status_manifest_root: String,
    pub endpoint_url: String,
    pub launch_bundle_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicProbeReport {
    pub public_probe_ready: bool,
    pub level: &'static str,
    pub public_probe_root: String,
    pub endpoint_url: String,
    pub launch_bundle_root: String,
    pub fee_policy_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSurfaceEvidence {
    pub chain_id: String,
    pub runtime_version: String,
    pub endpoint_url: String,
    pub capture_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_observation: Option<TlsEndpointPin>,
    pub captured_at_unix_ms: u128,
    pub health: Value,
    pub status: Value,
    pub snapshot: Value,
    pub ops: Value,
    pub backup: Value,
    pub rpc_status: Value,
    pub rpc_ops_status: Value,
    pub rpc_backup_manifest: Value,
    pub metrics_text: String,
    pub root: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeSurfaceEvidenceBuildInput {
    pub endpoint_url: String,
    pub capture_mode: String,
    pub tls_observation: Option<TlsEndpointPin>,
    pub captured_at_unix_ms: u128,
    pub health_json: String,
    pub status_json: String,
    pub snapshot_json: String,
    pub ops_json: String,
    pub backup_json: String,
    pub rpc_status_json: String,
    pub rpc_ops_status_json: String,
    pub rpc_backup_manifest_json: String,
    pub metrics_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeSurfaceEvidenceReport {
    pub runtime_surface_ready: bool,
    pub level: &'static str,
    pub runtime_surface_root: String,
    pub endpoint_url: String,
    pub capture_mode: String,
    pub tls_observation: Option<TlsEndpointPin>,
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_package_bundle_root: String,
    pub launch_package_root: String,
    pub fee_policy_root: String,
    pub gas_price_nebulai: u128,
    pub validator_set_root: String,
    pub genesis_root: String,
    pub latest_height: u64,
    pub latest_hash: String,
    pub snapshot_root: String,
    pub state_root: String,
    pub included_nbla_receipt_count: u64,
    pub included_nxmr_receipt_count: u64,
    pub total_nxmr_fees_units: u128,
    pub buyback_pool_nebulai: u128,
    pub validator_reward_nebulai: u128,
    pub nxmr_validator_reward_nebulai: u128,
    pub ops_root: String,
    pub backup_root: String,
    pub public_ops_ready: bool,
    pub blocking_gaps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptReport {
    pub receipt_ready: bool,
    pub level: &'static str,
    pub receipt_id: String,
    pub receipt_root: String,
    pub phase_count: usize,
    pub step_count: usize,
}

#[derive(Debug, Clone)]
pub struct PublicSurfaceBuildInput {
    pub endpoint_url: String,
    pub artifact_sha3_256: String,
    pub cargo_lock_sha3_256: String,
}

#[derive(Debug, Clone)]
pub struct DeploymentAttestationBuildInput {
    pub public_status_json: String,
    pub public_probe_json: String,
    pub preflight_receipt_json: String,
    pub runbook_receipt_json: String,
    pub artifact_sha3_256: String,
    pub cargo_lock_sha3_256: String,
    pub generated_at_unix_ms: u128,
    pub expires_at_unix_ms: u128,
    pub tls_pins: Vec<TlsEndpointPin>,
    pub bootstrap_nodes: Vec<BootstrapNodeBuildInput>,
    pub operators: Vec<OperatorBuildInput>,
    pub observers: Vec<ObserverBuildInput>,
    pub rollback_plan_sha3_256: String,
    pub rollback_last_drill_unix_ms: u128,
    pub rollback_recovery_point_root: String,
}

#[derive(Debug, Clone)]
pub struct BootstrapNodeBuildInput {
    pub node_id: String,
    pub operator_id: String,
    pub region: String,
    pub endpoint: String,
}

#[derive(Debug, Clone)]
pub struct OperatorBuildInput {
    pub operator_id: String,
    pub region: String,
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub struct ObserverBuildInput {
    pub observer_id: String,
    pub region: String,
    pub public_key: String,
    pub secret_key_hex: Option<String>,
}

struct PublicSurfaceSample {
    endpoint_url: String,
    launch_bundle_root: String,
    economics_root: String,
    public_status_manifest: PublicStatusManifest,
    public_probe: PublicProbe,
}

struct LaunchCertificateReports {
    launch_package_bundle: LaunchPackageBundleReport,
    validator_activation: ValidatorActivationReport,
    validator_join: ValidatorJoinReport,
    operator_join_confirmation: OperatorJoinConfirmationReport,
    public_observer_confirmation: PublicObserverConfirmationReport,
    runtime_surface: RuntimeSurfaceEvidenceReport,
    genesis: GenesisManifestReport,
    deployment: DeploymentAttestationReport,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FeeError {
    ZeroGas,
    ZeroGasPrice,
    MissingNXmrRate,
    ZeroNXmrRate,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AttestationError {
    MalformedJson(String),
    Invalid(Vec<String>),
}

pub fn hybrid_fee_policy() -> HybridFeePolicy {
    HybridFeePolicy {
        native_fee_token: NBLA_SYMBOL,
        bridged_fee_token: NXMR_SYMBOL,
        native_base_unit: NEBULAI_UNIT,
        nebulai_per_nbla: NEBULAI_PER_NBLA,
        target_nxmr_per_nbla_numerator: NBLA_TARGET_NXMR_NUMERATOR,
        target_nxmr_per_nbla_denominator: NBLA_TARGET_NXMR_DENOMINATOR,
        target_nxmr_base_units_per_nxmr: TARGET_NXMR_BASE_UNITS_PER_NXMR,
        target_nxmr_to_nbla_rate_nebulai_per_unit: TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT,
        minimum_gas_price_nebulai: MINIMUM_GAS_PRICE_NEBULAI,
        bridged_fee_conversion:
            "nXMR fees fund NBLA buybacks at the target rate, and bought NBLA rewards validators",
        nxmr_buyback_bps: NXMR_BUYBACK_BPS,
        nxmr_reserve_backing_bps: NXMR_RESERVE_BACKING_BPS,
        nxmr_validator_reward_bps: NXMR_VALIDATOR_REWARD_BPS,
        nbla_validator_reward_bps: FEE_BASIS_POINTS,
        testnet_reward_unit: "non-transferable validator points",
    }
}

pub fn fee_policy_root() -> String {
    stable_root(&json!(hybrid_fee_policy()))
}

pub fn quote_hybrid_fee(
    payment_asset: FeeAsset,
    gas_units: u128,
    gas_price_nebulai: u128,
    nxmr_to_nbla_rate_nebulai_per_unit: Option<u128>,
) -> Result<HybridFeeQuote, FeeError> {
    if gas_units == 0 {
        return Err(FeeError::ZeroGas);
    }
    if gas_price_nebulai == 0 {
        return Err(FeeError::ZeroGasPrice);
    }

    let required_fee_nebulai = gas_units
        .checked_mul(gas_price_nebulai)
        .ok_or(FeeError::ArithmeticOverflow)?;

    match payment_asset {
        FeeAsset::Nbla => Ok(HybridFeeQuote {
            payment_asset,
            payment_asset_symbol: payment_asset.symbol(),
            gas_units,
            gas_price_nebulai,
            required_fee_nebulai,
            nxmr_to_nbla_rate_nebulai_per_unit: None,
            paid_amount_units: required_fee_nebulai,
            converted_nbla_nebulai: required_fee_nebulai,
            buyback_nebulai: 0,
            reserve_backing_nebulai: 0,
            validator_reward_nebulai: required_fee_nebulai,
            validator_points: required_fee_nebulai
                .checked_mul(TESTNET_POINTS_PER_NEBULAI)
                .ok_or(FeeError::ArithmeticOverflow)?,
            settlement_note: "NBLA gas is paid directly to the validator reward ledger",
        }),
        FeeAsset::NXmr => {
            let rate = nxmr_to_nbla_rate_nebulai_per_unit.ok_or(FeeError::MissingNXmrRate)?;
            if rate == 0 {
                return Err(FeeError::ZeroNXmrRate);
            }

            let paid_amount_units = ceil_div(required_fee_nebulai, rate);
            let converted_nbla_nebulai = paid_amount_units
                .checked_mul(rate)
                .ok_or(FeeError::ArithmeticOverflow)?;
            let buyback_nebulai = split_basis_points(converted_nbla_nebulai, NXMR_BUYBACK_BPS)?;
            let reserve_backing_nebulai =
                split_basis_points(converted_nbla_nebulai, NXMR_RESERVE_BACKING_BPS)?;
            let validator_reward_nebulai =
                split_basis_points(converted_nbla_nebulai, NXMR_VALIDATOR_REWARD_BPS)?;

            Ok(HybridFeeQuote {
                payment_asset,
                payment_asset_symbol: payment_asset.symbol(),
                gas_units,
                gas_price_nebulai,
                required_fee_nebulai,
                nxmr_to_nbla_rate_nebulai_per_unit: Some(rate),
                paid_amount_units,
                converted_nbla_nebulai,
                buyback_nebulai,
                reserve_backing_nebulai,
                validator_reward_nebulai,
                validator_points: validator_reward_nebulai
                    .checked_mul(TESTNET_POINTS_PER_NEBULAI)
                    .ok_or(FeeError::ArithmeticOverflow)?,
                settlement_note:
                    "nXMR gas funds NBLA buybacks at 0.001 XMR/NBLA; bought NBLA rewards validators",
            })
        }
    }
}

pub fn quote_hybrid_fee_at_target_rate(
    payment_asset: FeeAsset,
    gas_units: u128,
    gas_price_nebulai: u128,
) -> Result<HybridFeeQuote, FeeError> {
    let nxmr_rate = match payment_asset {
        FeeAsset::Nbla => None,
        FeeAsset::NXmr => Some(TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT),
    };
    quote_hybrid_fee(payment_asset, gas_units, gas_price_nebulai, nxmr_rate)
}

pub fn readiness_report() -> NebulaReadiness {
    let acceptance = Acceptance {
        nebula_guide_mirrored: true,
        testnet_ready: true,
        ci_owned_by_nebula: true,
        legacy_upstream_removed: true,
        local_runtime_buildable: true,
    };

    let blocking_gaps = vec![PUBLIC_LAUNCH_BLOCKER.to_string()];
    let required_attestation =
        "operator-signed public endpoint, surface probe, and rollback evidence".to_string();
    let remediation_root = stable_root(&json!({
        "required_gap": PUBLIC_LAUNCH_BLOCKER,
        "required_attestation": required_attestation,
        "minimum_observer_count": MIN_PUBLIC_TESTNET_OBSERVERS,
        "minimum_operator_count": MIN_PUBLIC_TESTNET_OPERATORS,
        "minimum_region_count": MIN_PUBLIC_TESTNET_REGIONS,
    }));

    let public_launch_readiness = PublicLaunchReadiness {
        public_launch_ready: false,
        level: "public-launch-blocked".to_string(),
        blocking_gaps,
        required_attestation,
        remediation_root,
    };

    NebulaReadiness {
        chain_id: CHAIN_ID.to_string(),
        version: VERSION.to_string(),
        generated_at_unix_ms: unix_ms(),
        status_roots: json!({
            "runtime": stable_root(&json!({
                "chain_id": CHAIN_ID,
                "version": VERSION,
                "mode": "private-l2-testnet",
            })),
            "ci": stable_root(&json!({
                "workflow": "nebula-ci",
                "checks": [
                    "format",
                    "build",
                    "test-suite",
                    "readiness-contract",
                    "guide-mirror"
                ],
            })),
            "economics": fee_policy_root(),
            "validator_admission": stable_root(&json!({
                "minimum_validator_count": MIN_PUBLIC_TESTNET_VALIDATORS,
                "minimum_operator_count": MIN_PUBLIC_TESTNET_OPERATORS,
                "minimum_region_count": MIN_PUBLIC_TESTNET_REGIONS,
                "genesis_epoch": PUBLIC_TESTNET_GENESIS_EPOCH,
                "reward_unit": NEBULAI_UNIT,
                "fee_policy_root_required": true,
                "signed_admission_root_binds_validator_payload": true,
                "validator_identity_whitespace_free": true,
                "validator_identity_domains_disjoint": true,
                "validator_region_whitespace_free": true,
                "operator_contact_required": true,
                "operator_contact_address_required": true,
                "operator_contact_single_mailto_required": true,
                "operator_contact_query_fragment_forbidden": true,
                "unique_operator_ids_required": true,
                "operator_roster_root_reported": true,
                "hex_consensus_key_required": true,
                "hex_network_key_required": true,
                "consensus_network_key_domains_disjoint": true,
                "unique_consensus_keys_required": true,
                "unique_reward_accounts_required": true,
                "reward_account_operator_binding_required": true,
                "reward_ledger_root_reported": true,
                "unique_p2p_endpoints_required": true,
                "p2p_endpoint_host_port_required": true,
                "p2p_endpoint_path_forbidden": true,
                "p2p_endpoint_userinfo_forbidden": true,
                "p2p_endpoint_query_fragment_forbidden": true,
                "max_single_validator_genesis_power_bps": MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS,
                "max_single_operator_genesis_power_bps": MAX_SINGLE_OPERATOR_GENESIS_POWER_BPS,
            })),
            "operator_handoff": stable_root(&json!({
                "launch_bundle_root_required": true,
                "validator_set_root_required": true,
                "validator_deployment_binding_root_required": true,
                "one_handoff_entry_per_admitted_validator": true,
                "operator_contact_reported": true,
                "bootstrap_endpoint_reported": true,
                "p2p_endpoint_reported": true,
                "reward_account_reported": true,
                "signed_admission_root_reported": true,
                "entry_roots_required": true,
            })),
            "operator_acceptance": stable_root(&json!({
                "operator_handoff_root_required": true,
                "accepted_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "one_acceptance_entry_per_handoff_entry": true,
                "accepted_handoff_root_required": true,
                "operator_public_key_required": true,
                "operator_acceptance_signature_roots_verified": true,
                "operator_acceptance_signatures_verified": true,
                "all_handoff_entries_accepted": true,
            })),
            "genesis_manifest": stable_root(&json!({
                "deployment_attestation_root_required": true,
                "validator_set_root_required": true,
                "validator_set_epoch": PUBLIC_TESTNET_GENESIS_EPOCH,
                "fee_policy_root_required": true,
                "validator_admission_root_required": true,
                "operator_roster_root_required": true,
                "reward_ledger_root_required": true,
                "validator_deployment_binding_root_required": true,
                "artifact_root_domains_disjoint": true,
                "initial_operator_count_required": true,
                "initial_region_count_required": true,
                "genesis_time_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "activation_height": PUBLIC_TESTNET_ACTIVATION_HEIGHT,
                "native_fee_token": NBLA_SYMBOL,
                "native_base_unit": NEBULAI_UNIT,
                "bridged_fee_token": NXMR_SYMBOL,
            })),
            "launch_package": stable_root(&json!({
                "deployment_attestation_verified": true,
                "deployment_attestation_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "deployment_attestation_max_ttl_ms": PUBLIC_ATTESTATION_MAX_TTL_MS,
                "deployment_attestation_max_validity_window_ms": PUBLIC_ATTESTATION_MAX_TTL_MS,
                "deployment_attestation_expires_after_generated": true,
                "deployment_validity_root_reported": true,
                "deployment_quorum_root_reported": true,
                "launch_bundle_id": PUBLIC_TESTNET_BUNDLE_ID,
                "package_artifact_lock_roots_disjoint": true,
                "minimum_tls_pin_validity_ms": MIN_TLS_PIN_VALIDITY_MS,
                "rollback_drill_max_age_ms": ROLLBACK_DRILL_MAX_AGE_MS,
                "preflight_runbook_evidence_domains_disjoint": true,
                "receipts_complete_before_deployment_generation": true,
                "rollback_drill_before_deployment_generation": true,
                "rollback_plan_recovery_roots_disjoint": true,
                "rollback_readiness_root_reported": true,
                "operational_evidence_root_reported": true,
                "deployment_component_roots_disjoint": true,
                "deployment_witness_root_verified": true,
                "public_https_endpoint_required": true,
                "public_endpoint_authority_required": true,
                "https_endpoint_port_numeric_when_present": true,
                "endpoint_userinfo_forbidden": true,
                "endpoint_query_fragment_forbidden": true,
                "unique_tls_cert_pins_required": true,
                "unique_tls_public_key_pins_required": true,
                "tls_cert_public_key_pin_domains_disjoint": true,
                "unique_bootstrap_node_ids_required": true,
                "bootstrap_operator_id_domains_disjoint": true,
                "unique_bootstrap_endpoints_required": true,
                "unique_bootstrap_endpoint_hosts_required": true,
                "public_bootstrap_endpoint_hosts_disjoint": true,
                "bootstrap_endpoint_authority_required": true,
                "bootstrap_endpoint_path_forbidden": true,
                "bootstrap_region_spread_required": true,
                "bootstrap_operator_region_binding_required": true,
                "bootstrap_roster_root_reported": true,
                "deployment_region_whitespace_free": true,
                "unique_operator_ids_required": true,
                "unique_operator_keys_required": true,
                "hex_operator_keys_required": true,
                "unique_observer_ids_required": true,
                "unique_observer_keys_required": true,
                "operator_observer_id_domains_disjoint": true,
                "bootstrap_observer_id_domains_disjoint": true,
                "hex_observer_keys_required": true,
                "operator_observer_key_domains_disjoint": true,
                "witness_identity_whitespace_free": true,
                "operator_region_spread_required": true,
                "observer_region_spread_required": true,
                "operator_signature_roots_verified": true,
                "operator_approval_root_reported": true,
                "observer_signature_roots_verified": true,
                "observer_confirmation_root_reported": true,
                "deployment_observer_count_reported": true,
                "deployment_region_count_reported": true,
                "public_status_surface_verified": true,
                "public_probe_surface_verified": true,
                "public_surface_root_reported": true,
                "validator_set_verified": true,
                "genesis_manifest_verified": true,
                "validator_deployment_binding_root_reported": true,
                "operator_handoff_root_reported": true,
                "operator_handoff_verified": true,
                "operator_acceptance_verified": true,
                "operator_acceptance_counts_bind_launch_package": true,
                "public_status_binds_deployment_attestation": true,
                "public_probe_binds_deployment_attestation": true,
                "validator_set_binds_deployment_operators": true,
                "validator_set_binds_bootstrap_nodes": true,
                "validator_p2p_host_binds_bootstrap_endpoint": true,
                "validator_witness_key_domains_disjoint": true,
                "all_deployment_operators_admitted": true,
                "all_bootstrap_nodes_admitted": true,
                "genesis_binds_deployment_attestation_root": true,
                "genesis_binds_public_surface_root": true,
                "genesis_binds_operator_approval_root": true,
                "genesis_binds_observer_confirmation_root": true,
                "genesis_binds_rollback_readiness_root": true,
                "genesis_binds_deployment_validity_root": true,
                "genesis_binds_deployment_quorum_root": true,
                "genesis_binds_bootstrap_roster_root": true,
                "genesis_binds_operational_evidence_root": true,
                "genesis_binds_validator_set_root": true,
                "genesis_binds_operator_count": true,
                "genesis_binds_region_count": true,
                "genesis_binds_validator_count": true,
                "genesis_binds_operator_roster_root": true,
                "genesis_binds_reward_ledger_root": true,
                "genesis_binds_validator_deployment_binding_root": true,
                "validator_reward_ledger_reported": true,
                "validator_operator_roster_reported": true,
                "genesis_binds_total_power": true,
                "genesis_fee_token_identities_reported": true,
                "genesis_time_within_deployment_window": true,
            })),
            "launch_package_bundle": stable_root(&json!({
                "launch_package_bundle_root_reported": true,
                "launch_package_root_reported": true,
                "deployment_attestation_artifact_hash_required": true,
                "public_status_artifact_hash_required": true,
                "public_probe_artifact_hash_required": true,
                "validator_set_artifact_hash_required": true,
                "operator_handoff_artifact_hash_required": true,
                "operator_acceptance_artifact_hash_required": true,
                "genesis_manifest_artifact_hash_required": true,
                "operator_acceptance_root_required": true,
                "artifact_count": 7,
            })),
            "public_testnet_peer_manifest": stable_root(&json!({
                "launch_package_bundle_root_required": true,
                "validator_set_root_required": true,
                "deployment_bootstrap_roster_required": true,
                "one_peer_per_admitted_validator": true,
                "rpc_status_snapshot_urls_reported": true,
                "sync_peer_quorum_reported": true,
                "peer_regions_and_operator_coverage_required": true,
            })),
            "validator_activation": stable_root(&json!({
                "launch_package_bundle_root_required": true,
                "launch_package_root_required": true,
                "validator_set_root_required": true,
                "operator_acceptance_root_required": true,
                "activated_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "one_activation_entry_per_admitted_validator": true,
                "validator_consensus_key_signs_activation": true,
                "validator_activation_signature_roots_verified": true,
                "validator_activation_signatures_verified": true,
                "all_validators_activated": true,
            })),
            "validator_join": stable_root(&json!({
                "validator_activation_root_required": true,
                "launch_package_bundle_root_required": true,
                "launch_package_root_required": true,
                "validator_set_root_required": true,
                "joined_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "one_join_entry_per_activated_validator": true,
                "observed_block_height_at_or_after_activation": true,
                "minimum_peer_count_required": true,
                "validator_join_signature_roots_verified": true,
                "validator_join_signatures_verified": true,
                "all_validators_joined": true,
            })),
            "operator_join_confirmation": stable_root(&json!({
                "validator_join_root_required": true,
                "validator_activation_root_required": true,
                "launch_package_bundle_root_required": true,
                "operator_acceptance_root_required": true,
                "confirmed_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "one_confirmation_entry_per_joined_validator": true,
                "operator_confirmation_signature_roots_verified": true,
                "operator_confirmation_signatures_verified": true,
                "all_joined_validators_operator_confirmed": true,
            })),
            "public_observer_confirmation": stable_root(&json!({
                "operator_join_confirmation_root_required": true,
                "validator_join_root_required": true,
                "public_status_manifest_root_required": true,
                "public_probe_root_required": true,
                "endpoint_url_required": true,
                "observed_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "one_confirmation_entry_per_deployment_observer": true,
                "minimum_observer_count_required": MIN_PUBLIC_TESTNET_OBSERVERS,
                "minimum_observer_region_count_required": MIN_PUBLIC_TESTNET_REGIONS,
                "observer_confirmation_signature_roots_verified": true,
                "observer_confirmation_signatures_verified": true,
            })),
            "public_testnet_launch_certificate": stable_root(&json!({
                "launch_package_bundle_root_required": true,
                "validator_activation_root_required": true,
                "validator_join_root_required": true,
                "operator_join_confirmation_root_required": true,
                "public_observer_confirmation_root_required": true,
                "public_status_manifest_root_required": true,
                "public_probe_root_required": true,
                "genesis_root_required": true,
                "validator_set_root_required": true,
                "certified_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "operator_validator_observer_region_counts_bound": true,
                "single_launch_candidate_root_reported": true,
            })),
            "public_status_surface": stable_root(&json!({
                "status": "deployment-attested",
                "public_launch_ready": false,
                "launch_bundle_root_required": true,
                "endpoint_url_required": true,
                "endpoint_url_matches_public_surface": true,
                "endpoint_authority_required": true,
                "redacted_public_status": true,
            })),
            "public_probe_surface": stable_root(&json!({
                "status_code": 200,
                "body_chain_id_required": true,
                "body_launch_bundle_root_required": true,
                "body_fee_policy_root_required": true,
                "endpoint_authority_required": true,
                "unexpected_fields_rejected": true,
            })),
            "preflight_receipt": stable_root(&json!({
                "receipt_id": "preflight-receipt",
                "completed_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "all_phases_passed": true,
                "all_steps_passed": true,
                "phase_names_required": true,
                "step_names_required": true,
                "unique_phase_names_required": true,
                "unique_step_names_per_phase_required": true,
                "step_evidence_roots_required": true,
                "unique_step_evidence_roots_required": true,
                "root_required": true,
            })),
            "runbook_receipt": stable_root(&json!({
                "receipt_id": "runbook-receipt",
                "completed_at_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "all_phases_passed": true,
                "all_steps_passed": true,
                "phase_names_required": true,
                "step_names_required": true,
                "unique_phase_names_required": true,
                "unique_step_names_per_phase_required": true,
                "step_evidence_roots_required": true,
                "unique_step_evidence_roots_required": true,
                "root_required": true,
            })),
            "guide": stable_root(&json!({
                "root_readme": "README.md",
                "guide": "docs/NEBULA_LAYER2.md",
                "mirror_required": true,
            })),
        }),
        acceptance,
        public_launch_readiness,
        economics: hybrid_fee_policy(),
    }
}

pub fn readiness_json_pretty() -> String {
    serde_json::to_string_pretty(&readiness_report()).expect("readiness report serializes")
}

pub fn readiness_summary() -> String {
    let report = readiness_report();
    format!(
        "Nebula local testnet is ready. Public launch is blocked by: {}",
        report.public_launch_readiness.blocking_gaps.join(", ")
    )
}

pub fn prove_local_public_testnet_rehearsal_json_pretty() -> Result<String, AttestationError> {
    let report = prove_local_public_testnet_rehearsal()?;
    serde_json::to_string_pretty(&report)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn prove_local_public_testnet_rehearsal(
) -> Result<LocalPublicTestnetRehearsalReport, AttestationError> {
    let readiness = readiness_report();
    let public_launch_blocker = readiness
        .public_launch_readiness
        .blocking_gaps
        .first()
        .cloned()
        .unwrap_or_else(|| "none".to_string());

    let public_status_json = sample_public_status_manifest_json_pretty();
    let public_status_report = verify_public_status_manifest_json(&public_status_json)?;
    let public_probe_json = sample_public_probe_json_pretty();
    let public_probe_report = verify_public_probe_json(&public_probe_json)?;
    let preflight_receipt_json = sample_preflight_receipt_json_pretty();
    let preflight_report = verify_preflight_receipt_json(&preflight_receipt_json)?;
    let runbook_receipt_json = sample_runbook_receipt_json_pretty();
    let runbook_report = verify_runbook_receipt_json(&runbook_receipt_json)?;

    let generated_at_unix_ms = unix_ms();
    let deployment_attestation_json =
        build_deployment_attestation_json_pretty(DeploymentAttestationBuildInput {
            public_status_json: public_status_json.clone(),
            public_probe_json: public_probe_json.clone(),
            preflight_receipt_json: preflight_receipt_json.clone(),
            runbook_receipt_json: runbook_receipt_json.clone(),
            artifact_sha3_256: default_artifact_sha3_256(),
            cargo_lock_sha3_256: default_cargo_lock_sha3_256(),
            generated_at_unix_ms,
            expires_at_unix_ms: generated_at_unix_ms + PUBLIC_ATTESTATION_MAX_AGE_MS,
            tls_pins: vec![
                TlsEndpointPin {
                    cert_sha256: hex_64("tls-cert-a"),
                    public_key_sha256: hex_64("tls-key-a"),
                    not_after_unix_ms: generated_at_unix_ms + 2_592_000_000,
                },
                TlsEndpointPin {
                    cert_sha256: hex_64("tls-cert-b"),
                    public_key_sha256: hex_64("tls-key-b"),
                    not_after_unix_ms: generated_at_unix_ms + 2_592_000_000,
                },
            ],
            bootstrap_nodes: vec![
                BootstrapNodeBuildInput {
                    node_id: "bootstrap-us-east-1".to_string(),
                    operator_id: "operator-a".to_string(),
                    region: "us-east".to_string(),
                    endpoint: "https://bootstrap-a.testnet.nebula.example".to_string(),
                },
                BootstrapNodeBuildInput {
                    node_id: "bootstrap-eu-west-1".to_string(),
                    operator_id: "operator-b".to_string(),
                    region: "eu-west".to_string(),
                    endpoint: "https://bootstrap-b.testnet.nebula.example".to_string(),
                },
            ],
            operators: vec![
                OperatorBuildInput {
                    operator_id: "operator-a".to_string(),
                    region: "us-east".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xa1),
                },
                OperatorBuildInput {
                    operator_id: "operator-b".to_string(),
                    region: "eu-west".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xa2),
                },
            ],
            observers: vec![
                ObserverBuildInput {
                    observer_id: "observer-us-east-1".to_string(),
                    region: "us-east".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xb1),
                    secret_key_hex: None,
                },
                ObserverBuildInput {
                    observer_id: "observer-eu-west-1".to_string(),
                    region: "eu-west".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xb2),
                    secret_key_hex: None,
                },
            ],
            rollback_plan_sha3_256: hex_64("rollback-plan"),
            rollback_last_drill_unix_ms: generated_at_unix_ms,
            rollback_recovery_point_root: hex_64("rollback-recovery-point"),
        })?;
    let deployment_report = verify_deployment_attestation_json(&deployment_attestation_json)?;

    let validator_set_json = sample_validator_set_json_pretty();
    let validator_set_report = verify_validator_set_json(&validator_set_json)?;
    let operator_handoff_json =
        build_operator_handoff_json_pretty(&deployment_attestation_json, &validator_set_json)?;
    let operator_handoff_report = verify_operator_handoff_jsons(
        &operator_handoff_json,
        &deployment_attestation_json,
        &validator_set_json,
    )?;
    let operator_acceptance_json = build_operator_acceptance_json_pretty(
        &operator_handoff_json,
        &deployment_attestation_json,
        &validator_set_json,
    )?;
    let operator_acceptance_report = verify_operator_acceptance_jsons(
        &operator_acceptance_json,
        &operator_handoff_json,
        &deployment_attestation_json,
        &validator_set_json,
    )?;
    let genesis_manifest_json =
        build_genesis_manifest_json_pretty(&deployment_attestation_json, &validator_set_json)?;
    let genesis_report = verify_genesis_manifest_json(&genesis_manifest_json)?;
    let launch_package_report = verify_launch_package_with_operator_acceptance_jsons(
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let launch_package_bundle_json = build_launch_package_bundle_json_pretty(
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let launch_package_bundle_report = verify_launch_package_bundle_jsons(
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let public_testnet_peer_manifest_json = build_public_testnet_peer_manifest_json_pretty(
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let public_testnet_peer_manifest_report = verify_public_testnet_peer_manifest_jsons(
        &public_testnet_peer_manifest_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let sequencer_binding = build_runtime_launch_binding_from_jsons(
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
        &launch_package_bundle_json,
        "validator-a",
    )?;
    let follower_binding = build_runtime_launch_binding_from_jsons(
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
        &launch_package_bundle_json,
        "validator-b",
    )?;
    let (_live_rpc_report, runtime_surface_evidence) =
        prove_live_rpc_devnet_rehearsal_with_bindings(sequencer_binding, follower_binding)?;
    let runtime_surface_evidence_json = runtime_surface_evidence.to_string();
    let runtime_surface_report =
        verify_runtime_surface_evidence_json(&runtime_surface_evidence_json)?;
    let validator_activation_json = build_validator_activation_json_pretty(
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let validator_activation_report = verify_validator_activation_jsons(
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let validator_join_json = build_validator_join_receipt_json_pretty(
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let validator_join_report = verify_validator_join_receipt_jsons(
        &validator_join_json,
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let operator_join_confirmation_json = build_operator_join_confirmation_json_pretty(
        &validator_join_json,
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let operator_join_confirmation_report = verify_operator_join_confirmation_jsons(
        &operator_join_confirmation_json,
        &validator_join_json,
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let public_observer_confirmation_json = build_public_observer_confirmation_json_pretty(
        &operator_join_confirmation_json,
        &validator_join_json,
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let public_observer_confirmation_report = verify_public_observer_confirmation_jsons(
        &public_observer_confirmation_json,
        &operator_join_confirmation_json,
        &validator_join_json,
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let public_testnet_launch_certificate_json =
        build_public_testnet_launch_certificate_json_pretty(
            &public_observer_confirmation_json,
            &runtime_surface_evidence_json,
            &operator_join_confirmation_json,
            &validator_join_json,
            &validator_activation_json,
            &launch_package_bundle_json,
            &deployment_attestation_json,
            &public_status_json,
            &public_probe_json,
            &validator_set_json,
            &operator_handoff_json,
            &operator_acceptance_json,
            &genesis_manifest_json,
        )?;
    let public_testnet_launch_certificate_report = verify_public_testnet_launch_certificate_jsons(
        &public_testnet_launch_certificate_json,
        &public_observer_confirmation_json,
        &runtime_surface_evidence_json,
        &operator_join_confirmation_json,
        &validator_join_json,
        &validator_activation_json,
        &launch_package_bundle_json,
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;

    let verified_artifacts = vec![
        local_rehearsal_artifact(
            "public_status",
            public_status_report.level,
            public_status_report.public_status_manifest_root,
        ),
        local_rehearsal_artifact(
            "public_probe",
            public_probe_report.level,
            public_probe_report.public_probe_root,
        ),
        local_rehearsal_artifact(
            "preflight_receipt",
            preflight_report.level,
            preflight_report.receipt_root,
        ),
        local_rehearsal_artifact(
            "runbook_receipt",
            runbook_report.level,
            runbook_report.receipt_root,
        ),
        local_rehearsal_artifact(
            "deployment_attestation",
            deployment_report.level,
            deployment_report.evidence_root,
        ),
        local_rehearsal_artifact(
            "validator_set",
            validator_set_report.level,
            validator_set_report.validator_set_root,
        ),
        local_rehearsal_artifact(
            "operator_handoff",
            operator_handoff_report.level,
            operator_handoff_report.operator_handoff_root,
        ),
        local_rehearsal_artifact(
            "operator_acceptance",
            operator_acceptance_report.level,
            operator_acceptance_report.operator_acceptance_root,
        ),
        local_rehearsal_artifact(
            "genesis_manifest",
            genesis_report.level,
            genesis_report.genesis_root,
        ),
        local_rehearsal_artifact(
            "launch_package",
            launch_package_report.level,
            launch_package_bundle_report.launch_package_root.clone(),
        ),
        local_rehearsal_artifact(
            "launch_package_bundle",
            launch_package_bundle_report.level,
            launch_package_bundle_report
                .launch_package_bundle_root
                .clone(),
        ),
        local_rehearsal_artifact(
            "public_testnet_peer_manifest",
            public_testnet_peer_manifest_report.level,
            public_testnet_peer_manifest_report
                .public_testnet_peer_manifest_root
                .clone(),
        ),
        local_rehearsal_artifact(
            "validator_activation",
            validator_activation_report.level,
            validator_activation_report
                .validator_activation_root
                .clone(),
        ),
        local_rehearsal_artifact(
            "validator_join",
            validator_join_report.level,
            validator_join_report.validator_join_root.clone(),
        ),
        local_rehearsal_artifact(
            "operator_join_confirmation",
            operator_join_confirmation_report.level,
            operator_join_confirmation_report
                .operator_join_confirmation_root
                .clone(),
        ),
        local_rehearsal_artifact(
            "public_observer_confirmation",
            public_observer_confirmation_report.level,
            public_observer_confirmation_report
                .public_observer_confirmation_root
                .clone(),
        ),
        local_rehearsal_artifact(
            "runtime_surface_evidence",
            runtime_surface_report.level,
            runtime_surface_report.runtime_surface_root.clone(),
        ),
        local_rehearsal_artifact(
            "public_testnet_launch_certificate",
            public_testnet_launch_certificate_report.level,
            public_testnet_launch_certificate_report
                .public_testnet_launch_certificate_root
                .clone(),
        ),
    ];

    let mut report = LocalPublicTestnetRehearsalReport {
        local_public_testnet_rehearsed: true,
        level: "local-public-testnet-rehearsal-ready",
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        public_launch_ready: readiness.public_launch_readiness.public_launch_ready,
        public_launch_blocker,
        verified_artifact_count: verified_artifacts.len(),
        verified_artifacts,
        public_testnet_launch_certificate_root: public_testnet_launch_certificate_report
            .public_testnet_launch_certificate_root,
        public_testnet_peer_manifest_root: public_testnet_peer_manifest_report
            .public_testnet_peer_manifest_root,
        launch_package_bundle_root: launch_package_bundle_report.launch_package_bundle_root,
        launch_package_root: launch_package_bundle_report.launch_package_root,
        validator_activation_root: validator_activation_report.validator_activation_root,
        validator_join_root: validator_join_report.validator_join_root,
        operator_join_confirmation_root: operator_join_confirmation_report
            .operator_join_confirmation_root,
        public_observer_confirmation_root: public_observer_confirmation_report
            .public_observer_confirmation_root,
        validator_count: public_testnet_launch_certificate_report.validator_count,
        operator_count: public_testnet_launch_certificate_report.operator_count,
        observer_count: public_testnet_launch_certificate_report.observer_count,
        region_count: public_testnet_launch_certificate_report.region_count,
        generated_at_unix_ms: unix_ms(),
        rehearsal_root: String::new(),
    };
    report.rehearsal_root = local_public_testnet_rehearsal_root(&report);
    Ok(report)
}

pub fn prove_live_rpc_devnet_rehearsal_json_pretty() -> Result<String, AttestationError> {
    let report = prove_live_rpc_devnet_rehearsal()?;
    serde_json::to_string_pretty(&report)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn prove_live_rpc_devnet_rehearsal() -> Result<LiveRpcDevnetRehearsalReport, AttestationError> {
    let (report, _evidence) = prove_live_rpc_devnet_rehearsal_with_evidence()?;
    Ok(report)
}

pub fn prove_live_rpc_devnet_rehearsal_with_evidence(
) -> Result<(LiveRpcDevnetRehearsalReport, Value), AttestationError> {
    let (sequencer_binding, follower_binding) = live_runtime_launch_bindings()?;
    prove_live_rpc_devnet_rehearsal_with_bindings(sequencer_binding, follower_binding)
}

#[allow(clippy::too_many_arguments)]
pub fn prove_live_rpc_devnet_rehearsal_with_jsons(
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<LiveRpcDevnetRehearsalReport, AttestationError> {
    let (report, _evidence) = prove_live_rpc_devnet_rehearsal_with_jsons_and_evidence(
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
pub fn prove_live_rpc_devnet_rehearsal_with_jsons_and_evidence(
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<(LiveRpcDevnetRehearsalReport, Value), AttestationError> {
    let sequencer_binding = build_runtime_launch_binding_from_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
        launch_package_bundle_json,
        "validator-a",
    )?;
    let follower_binding = build_runtime_launch_binding_from_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
        launch_package_bundle_json,
        "validator-b",
    )?;
    prove_live_rpc_devnet_rehearsal_with_bindings(sequencer_binding, follower_binding)
}

#[allow(clippy::too_many_arguments)]
pub fn build_live_rpc_devnet_runtime_surface_evidence_json_pretty(
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let sequencer_binding = build_runtime_launch_binding_from_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
        launch_package_bundle_json,
        "validator-a",
    )?;
    let follower_binding = build_runtime_launch_binding_from_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
        launch_package_bundle_json,
        "validator-b",
    )?;
    let (_report, evidence) =
        prove_live_rpc_devnet_rehearsal_with_bindings(sequencer_binding, follower_binding)?;
    serde_json::to_string_pretty(&evidence)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

fn prove_live_rpc_devnet_rehearsal_with_bindings(
    sequencer_binding: runtime::RuntimeLaunchBinding,
    follower_binding: runtime::RuntimeLaunchBinding,
) -> Result<(LiveRpcDevnetRehearsalReport, Value), AttestationError> {
    const ADMIN_TOKEN: &str = "live-rpc-devnet-rehearsal-admin";
    let readiness = readiness_report();
    let public_launch_blocker = readiness
        .public_launch_readiness
        .blocking_gaps
        .first()
        .cloned()
        .unwrap_or_else(|| "none".to_string());
    let endpoint_url = sequencer_binding.endpoint_url.clone();
    let sequencer_launch_binding = sequencer_binding.clone();
    let block_millis = runtime::DEFAULT_SUBSECOND_BLOCK_MS;
    let bridge_account_seed = 0x46;
    let bridge_account = live_account_id(bridge_account_seed);

    let mut sequencer_config = runtime::RuntimeConfig::public_testnet_default();
    sequencer_config.block_target_ms = block_millis;
    sequencer_config.validator_id = "validator-a".to_string();
    sequencer_config.launch_binding = Some(sequencer_binding);
    sequencer_config.faucet_nbla_nebulai = 0;
    let initial_sequencer_secret_key_hex = "3c".repeat(32);
    sequencer_config.sequencer_public_key_hex = live_account_id(0x3c);
    let sequencer_data_dir = live_temp_data_dir("sequencer");
    let sequencer_storage = runtime::RuntimeStorage::from_data_dir(&sequencer_data_dir);
    let mut seeded_runtime = runtime::NebulaRuntime::with_sequencer_secret(
        sequencer_config.clone(),
        Some(initial_sequencer_secret_key_hex.clone()),
    )
    .map_err(|error| live_rehearsal_invalid(format!("failed to seed sequencer: {error}")))?;
    seeded_runtime
        .seed_local_rehearsal_nbla(&bridge_account, 10_000)
        .map_err(|error| live_rehearsal_invalid(format!("failed to seed NBLA balance: {error}")))?;
    seeded_runtime.try_produce_block().map_err(|error| {
        live_rehearsal_invalid(format!("failed to commit seeded NBLA: {error}"))
    })?;
    sequencer_storage
        .save_runtime(&seeded_runtime)
        .map_err(|error| {
            live_rehearsal_invalid(format!("failed to persist seeded sequencer: {error}"))
        })?;
    let (sequencer_rpc_addr, sequencer_admin_addr) = live_rpc_start_server_with_admin(
        sequencer_config,
        runtime::RuntimeNodeOptions {
            admin_token: Some(ADMIN_TOKEN.to_string()),
            sequencer_secret_key_hex: Some(initial_sequencer_secret_key_hex),
            data_dir: Some(sequencer_data_dir),
            auto_produce_blocks: false,
            max_requests_per_minute: 10_000,
            trusted_proxy_ips: vec!["127.0.0.1".to_string()],
            ..runtime::RuntimeNodeOptions::default()
        },
    )?;

    let initial_block = live_rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    )?;
    if live_rpc_result(&initial_block)?["height"]
        .as_u64()
        .unwrap_or(0)
        == 0
    {
        return Err(live_rehearsal_invalid(
            "initial block production did not advance height",
        ));
    }
    live_wait_for_json_condition(
        &sequencer_rpc_addr,
        "/ops",
        "sequencer public ops ready",
        |ops| ops["public_ops_ready"] == true && ops["latest_height"].as_u64().unwrap_or(0) > 0,
    )?;
    let initial_status = live_rpc_call(&sequencer_rpc_addr, "nebula_status", json!({}))?;
    let initial_status = live_rpc_result(&initial_status)?.clone();
    let rotation_secret_key_hex = "4d".repeat(32);
    let rotation_public_key_hex = live_account_id(0x4d);
    let rotation_proof_root = hex_64("live-rotation-proof");
    let rotation_activation_height = live_value_u64(&initial_status, "latest_height")?
        .checked_add(1)
        .ok_or_else(|| live_rehearsal_invalid("rotation activation height overflowed"))?;
    let previous_key_history_root = initial_status["sequencer_key_history_root"]
        .as_str()
        .ok_or_else(|| live_rehearsal_invalid("initial status missing key history root"))?;
    let old_public_key_hex = initial_status["sequencer_public_key_hex"]
        .as_str()
        .ok_or_else(|| live_rehearsal_invalid("initial status missing sequencer public key"))?;
    let (rotation_operator_ids, rotation_approval_roots, rotation_approvals) =
        live_rotation_operator_approval_quorum(
            Some(&sequencer_launch_binding),
            previous_key_history_root,
            rotation_activation_height,
            old_public_key_hex,
            &rotation_public_key_hex,
            &rotation_proof_root,
        );

    let rotation = live_rpc_call(
        &sequencer_admin_addr,
        "nebula_rotateSequencerKey",
        json!({
            "admin_token": ADMIN_TOKEN,
            "new_sequencer_secret_key_hex": rotation_secret_key_hex,
            "rotation_proof_root": rotation_proof_root,
            "operator_approval_ids": rotation_operator_ids,
            "operator_approval_roots": rotation_approval_roots,
            "operator_approvals": rotation_approvals,
        }),
    )?;
    let rotation = live_rpc_result(&rotation)?;
    if rotation["rotated"] != true {
        return Err(live_rehearsal_invalid(
            "sequencer key rotation did not report rotated=true",
        ));
    }
    if rotation["rotation"]["operator_approvals"]
        .as_array()
        .map(Vec::len)
        != Some(2)
    {
        return Err(live_rehearsal_invalid(
            "sequencer key rotation did not include signed operator approval quorum",
        ));
    }
    let rotated_public_key = rotation["sequencer_public_key_hex"]
        .as_str()
        .ok_or_else(|| live_rehearsal_invalid("sequencer rotation response missing public key"))?
        .to_string();

    let disabled_faucet = live_rpc_call(
        &sequencer_rpc_addr,
        "nebula_faucet",
        json!({ "account": bridge_account.clone() }),
    )?;
    let faucet_error = disabled_faucet
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !faucet_error.contains("NBLA faucet is disabled") {
        return Err(live_rehearsal_invalid(
            "launch-bound public NBLA faucet was not disabled",
        ));
    }

    let bridge_deposit = live_rpc_call(
        &sequencer_admin_addr,
        "nebula_observeBridgeDeposit",
        json!({
            "admin_token": ADMIN_TOKEN,
            "deposit": live_bridge_deposit(bridge_account_seed, 5_000),
        }),
    )?;
    let bridge_deposit = live_rpc_result(&bridge_deposit)?;
    if bridge_deposit["credited"] != true {
        return Err(live_rehearsal_invalid(
            "bridge deposit did not report credited=true",
        ));
    }

    let nbla_tx = live_signed_transaction_with_fee_asset(
        bridge_account_seed,
        0,
        "live-nbla-gas-recipient",
        10,
        5,
        2,
        NBLA_SYMBOL,
    );
    let nbla_submission = live_rpc_call(
        &sequencer_rpc_addr,
        "nebula_sendTransaction",
        json!({ "tx": nbla_tx }),
    )?;
    let nbla_submission = live_rpc_result(&nbla_submission)?;
    if nbla_submission["accepted_to_mempool"] != true {
        return Err(live_rehearsal_invalid(
            "NBLA gas transaction was not accepted to mempool",
        ));
    }
    let nbla_tx_id = nbla_submission["tx_id"]
        .as_str()
        .ok_or_else(|| live_rehearsal_invalid("NBLA gas transaction response missing tx_id"))?
        .to_string();
    live_rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    )?;
    let nbla_receipt = live_rpc_call(
        &sequencer_rpc_addr,
        "nebula_getReceipt",
        json!({ "tx_id": nbla_tx_id }),
    )?;
    let nbla_receipt = live_rpc_result(&nbla_receipt)?;
    if nbla_receipt["status"].as_str() != Some("included")
        || nbla_receipt["fee_asset"].as_str() != Some(NBLA_SYMBOL)
        || live_value_u128(nbla_receipt, "paid_amount_units")? != 10
        || live_value_u128(nbla_receipt, "buyback_nebulai")? != 0
        || live_value_u128(nbla_receipt, "validator_reward_nebulai")? != 10
    {
        return Err(live_rehearsal_invalid(format!(
            "NBLA gas receipt did not credit validator rewards directly: {nbla_receipt}"
        )));
    }

    let nxmr_tx = live_signed_transaction_with_fee_asset(
        bridge_account_seed,
        1,
        "live-nxmr-gas-recipient",
        100,
        100,
        10,
        NXMR_SYMBOL,
    );
    let nxmr_submission = live_rpc_call(
        &sequencer_rpc_addr,
        "nebula_sendTransaction",
        json!({ "tx": nxmr_tx }),
    )?;
    let nxmr_submission = live_rpc_result(&nxmr_submission)?;
    if nxmr_submission["accepted_to_mempool"] != true {
        return Err(live_rehearsal_invalid(
            "nXMR gas transaction was not accepted to mempool",
        ));
    }
    let nxmr_tx_id = nxmr_submission["tx_id"]
        .as_str()
        .ok_or_else(|| live_rehearsal_invalid("nXMR gas transaction response missing tx_id"))?
        .to_string();
    live_rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    )?;
    let nxmr_receipt = live_rpc_call(
        &sequencer_rpc_addr,
        "nebula_getReceipt",
        json!({ "tx_id": nxmr_tx_id }),
    )?;
    let nxmr_receipt = live_rpc_result(&nxmr_receipt)?;
    if nxmr_receipt["status"].as_str() != Some("included")
        || nxmr_receipt["fee_asset"].as_str() != Some(NXMR_SYMBOL)
        || live_value_u128(nxmr_receipt, "paid_amount_units")? != 1_000
        || live_value_u128(nxmr_receipt, "buyback_nebulai")? != 1_000
        || live_value_u128(nxmr_receipt, "validator_reward_nebulai")? != 1_000
    {
        return Err(live_rehearsal_invalid(format!(
            "nXMR gas receipt did not fund NBLA buyback and validator rewards: {nxmr_receipt}"
        )));
    }

    let withdrawal = live_rpc_call(
        &sequencer_rpc_addr,
        "nebula_requestWithdrawal",
        json!({
            "account": bridge_account.clone(),
            "monero_address": "9xTestnetMoneroAddressForNebulaWithdrawals",
            "amount_nxmr_units": 2_000,
            "nonce": 2,
            "signature": live_withdrawal_signature(
                bridge_account_seed,
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                2,
            ),
        }),
    )?;
    let withdrawal = live_rpc_result(&withdrawal)?;
    if withdrawal["accepted"] != true {
        return Err(live_rehearsal_invalid(
            "withdrawal request did not report accepted=true",
        ));
    }
    let withdrawal_id = withdrawal["withdrawal"]["withdrawal_id"]
        .as_str()
        .ok_or_else(|| live_rehearsal_invalid("withdrawal response missing withdrawal_id"))?
        .to_string();
    let withdrawal_request = serde_json::from_value::<runtime::RuntimeWithdrawalRequest>(
        withdrawal["withdrawal"].clone(),
    )
    .map_err(|error| live_rehearsal_invalid(format!("invalid withdrawal response: {error}")))?;
    let finalized_monero_tx_id = hex_64("live-finalized-withdrawal");
    let finalization_proof_root = hex_64("live-finalization-proof");
    let (operator_approval_ids, operator_approval_roots, operator_approvals) =
        live_operator_approval_quorum(
            &withdrawal_request,
            &finalized_monero_tx_id,
            &finalization_proof_root,
        );
    let finalization = live_rpc_call(
        &sequencer_admin_addr,
        "nebula_finalizeWithdrawal",
        json!({
            "admin_token": ADMIN_TOKEN,
            "withdrawal_id": withdrawal_id,
            "finalized_monero_tx_id": finalized_monero_tx_id,
            "finalization_proof_root": finalization_proof_root,
            "operator_approval_ids": operator_approval_ids,
            "operator_approval_roots": operator_approval_roots,
            "operator_approvals": operator_approvals,
        }),
    )?;
    if live_rpc_result(&finalization)?["finalized"] != true {
        return Err(live_rehearsal_invalid(
            "withdrawal finalization did not report finalized=true",
        ));
    }

    let sequencer_status = live_wait_for_json_condition(
        &sequencer_rpc_addr,
        "/status",
        "sequencer lifecycle state committed",
        |status| {
            status["sequencer_key_rotation_count"] == 1
                && status["bridge_deposit_count"] == 1
                && status["withdrawal_request_count"] == 1
                && status["finalized_withdrawal_count"] == 1
                && status["faucet_nbla_nebulai"] == 0
                && status["total_nxmr_fees_units"] == 1_000
                && status["buyback_pool_nebulai"] == 1_000
                && status["validator_reward_nebulai"] == 1_010
                && status["bridge_custody_reconciled"] == true
        },
    )?;

    let snapshot_url = format!("http://{sequencer_rpc_addr}/snapshot");
    let mut follower_config = runtime::RuntimeConfig::public_testnet_default();
    follower_config.block_target_ms = block_millis;
    follower_config.validator_id = "validator-b".to_string();
    follower_config.produce_blocks = false;
    follower_config.sequencer_public_key_hex = rotated_public_key;
    follower_config.launch_binding = Some(follower_binding.clone());
    follower_config.faucet_nbla_nebulai = 0;
    let follower_rpc_addr = live_rpc_start_server(
        follower_config,
        runtime::RuntimeNodeOptions {
            data_dir: Some(live_temp_data_dir("follower")),
            bootstrap_rpc_url: Some(snapshot_url.clone()),
            sync_rpc_url: Some(snapshot_url.clone()),
            sync_peer_quorum: 1,
            public_testnet_peer_manifest: Some(runtime::RuntimePublicTestnetPeerManifestBinding {
                public_testnet_peer_manifest_root: hex_64("live-peer-manifest"),
                launch_package_bundle_root: follower_binding.launch_package_bundle_root.clone(),
                snapshot_peer_urls: vec![snapshot_url],
                sync_peer_quorum: 1,
            }),
            max_requests_per_minute: 10_000,
            trusted_proxy_ips: vec!["127.0.0.1".to_string()],
            ..runtime::RuntimeNodeOptions::default()
        },
    )?;
    live_rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    )?;

    let follower_ops = live_wait_for_json_condition(
        &follower_rpc_addr,
        "/ops",
        "follower public ops ready",
        |ops| {
            let latest_height = ops["latest_height"].as_u64().unwrap_or(0);
            ops["public_ops_ready"] == true
                && ops["node_role"] == "follower"
                && ops["sync_quorum_met"] == true
                && ops["sync_successful_peer_count"].as_u64().unwrap_or(0) >= 1
                && ops["sync_import_count"].as_u64().unwrap_or(0) >= 1
                && ops["sync_last_import_height"].as_u64() == Some(latest_height)
                && ops["sync_quorum_height"].as_u64() == Some(latest_height)
                && ops["sync_quorum_latest_hash"] == ops["latest_hash"]
                && ops["sync_quorum_state_root"] == ops["current_state_root"]
                && latest_height >= 2
        },
    )?;
    let evidence = live_wait_for_runtime_surface_evidence(&follower_rpc_addr, &endpoint_url)?;
    let runtime_surface_report = verify_runtime_surface_evidence_json(&evidence.to_string())?;
    if !runtime_surface_report.runtime_surface_ready {
        return Err(live_rehearsal_invalid(
            "runtime surface evidence did not report ready=true",
        ));
    }
    if !runtime_surface_report.blocking_gaps.is_empty() {
        return Err(live_rehearsal_invalid(format!(
            "runtime surface evidence has blocking gaps: {}",
            runtime_surface_report.blocking_gaps.join(", ")
        )));
    }
    let status = &evidence["status"];
    let produced_block_count = live_value_u64(status, "latest_height")?;
    let mut report = LiveRpcDevnetRehearsalReport {
        live_rpc_devnet_rehearsed: true,
        level: "live-rpc-devnet-rehearsal-ready".to_string(),
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        public_launch_ready: readiness.public_launch_readiness.public_launch_ready,
        public_launch_blocker,
        endpoint_url,
        sequencer_rpc_addr,
        follower_rpc_addr,
        block_millis,
        sub_second_blocks: live_value_bool(status, "sub_second_blocks")?,
        produced_block_count,
        runtime_surface_ready: runtime_surface_report.runtime_surface_ready,
        runtime_surface_root: runtime_surface_report.runtime_surface_root,
        latest_height: runtime_surface_report.latest_height,
        sync_quorum_met: live_value_bool(&follower_ops, "sync_quorum_met")?,
        sync_successful_peer_count: live_value_u64(&follower_ops, "sync_successful_peer_count")?,
        sync_import_count: live_value_u64(&follower_ops, "sync_import_count")?,
        sync_last_import_height: live_value_u64(&follower_ops, "sync_last_import_height")?,
        sync_quorum_height: live_value_u64(&follower_ops, "sync_quorum_height")?,
        bridge_deposit_count: live_value_u64(status, "bridge_deposit_count")?,
        withdrawal_request_count: live_value_u64(status, "withdrawal_request_count")?,
        finalized_withdrawal_count: live_value_u64(status, "finalized_withdrawal_count")?,
        bridge_replay_cache_count: live_value_u64(status, "bridge_replay_cache_count")?,
        bridge_deposited_nxmr_units: live_value_u128(status, "bridge_deposited_nxmr_units")?,
        account_nxmr_units: live_value_u128(status, "account_nxmr_units")?,
        withdrawal_reserved_nxmr_units: live_value_u128(status, "withdrawal_reserved_nxmr_units")?,
        total_nxmr_fees_units: runtime_surface_report.total_nxmr_fees_units,
        buyback_pool_nebulai: runtime_surface_report.buyback_pool_nebulai,
        validator_reward_nebulai: runtime_surface_report.validator_reward_nebulai,
        bridge_custody_reconciled: live_value_bool(status, "bridge_custody_reconciled")?,
        nxmr_custody_deficit_units: live_value_u128(status, "nxmr_custody_deficit_units")?,
        sequencer_key_rotation_count: live_value_u64(status, "sequencer_key_rotation_count")?,
        launch_package_bundle_root: follower_binding.launch_package_bundle_root,
        rehearsal_root: String::new(),
    };
    if report.produced_block_count < 2 {
        return Err(live_rehearsal_invalid(
            "live RPC rehearsal produced fewer than two blocks",
        ));
    }
    if !report.sub_second_blocks || report.block_millis >= 1_000 {
        return Err(live_rehearsal_invalid(
            "live RPC rehearsal did not prove sub-second blocks",
        ));
    }
    if sequencer_status["nxmr_custody_deficit_units"] != 0
        || !report.bridge_custody_reconciled
        || report.nxmr_custody_deficit_units != 0
    {
        return Err(live_rehearsal_invalid(
            "live RPC rehearsal did not reconcile nXMR custody",
        ));
    }
    if report.sync_import_count == 0
        || report.sync_last_import_height != report.latest_height
        || report.sync_quorum_height != report.latest_height
    {
        return Err(live_rehearsal_invalid(
            "live RPC rehearsal did not prove follower imported the served head",
        ));
    }
    if report.total_nxmr_fees_units != 1_000
        || report.buyback_pool_nebulai != 1_000
        || report.validator_reward_nebulai != 1_010
    {
        return Err(live_rehearsal_invalid(
            "live RPC rehearsal did not prove NBLA/nXMR gas economics",
        ));
    }
    report.rehearsal_root = live_rpc_devnet_rehearsal_root(&report);
    Ok((report, evidence))
}

pub fn sample_deployment_attestation_json_pretty() -> String {
    let now = unix_ms();
    let package_identity = sample_package_identity();
    let readiness = readiness_report();
    let runtime_root = readiness.status_roots["runtime"]
        .as_str()
        .expect("runtime root is a string")
        .to_string();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string")
        .to_string();
    let launch_bundle =
        sample_launch_bundle(&package_identity.root, &runtime_root, &economics_root);
    let endpoint_url = "https://testnet.nebula.example/status".to_string();
    let public_status_manifest = sample_public_status_manifest(&launch_bundle.root, &endpoint_url);
    let policy_claim = sample_policy_claim(
        &readiness.public_launch_readiness.remediation_root,
        &economics_root,
    );
    let public_probe = sample_public_probe(&endpoint_url, &launch_bundle.root, &economics_root);
    let preflight_receipt = sample_receipt("preflight-receipt", now);
    let runbook_receipt = sample_receipt("runbook-receipt", now);
    let public_status_manifest_root = public_status_manifest.root.clone();
    let public_endpoint = PublicEndpointEvidence {
        url: endpoint_url.clone(),
        public_status_manifest_root,
        tls_pins: vec![
            TlsEndpointPin {
                cert_sha256: hex_64("tls-cert-a"),
                public_key_sha256: hex_64("tls-key-a"),
                not_after_unix_ms: now + 2_592_000_000,
            },
            TlsEndpointPin {
                cert_sha256: hex_64("tls-cert-b"),
                public_key_sha256: hex_64("tls-key-b"),
                not_after_unix_ms: now + 2_592_000_000,
            },
        ],
    };
    let witness_evidence_root = deployment_witness_root(
        &launch_bundle,
        &public_status_manifest,
        &public_endpoint,
        &policy_claim,
        &public_probe,
    );
    let mut bootstrap_nodes = vec![
        BootstrapNode {
            node_id: "bootstrap-us-east-1".to_string(),
            operator_id: "operator-a".to_string(),
            region: "us-east".to_string(),
            endpoint: "https://bootstrap-a.testnet.nebula.example".to_string(),
            attestation_root: String::new(),
        },
        BootstrapNode {
            node_id: "bootstrap-eu-west-1".to_string(),
            operator_id: "operator-b".to_string(),
            region: "eu-west".to_string(),
            endpoint: "https://bootstrap-b.testnet.nebula.example".to_string(),
            attestation_root: String::new(),
        },
    ];
    for node in &mut bootstrap_nodes {
        node.attestation_root = bootstrap_node_root(node, &witness_evidence_root);
    }

    let attestation = DeploymentAttestation {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        generated_at_unix_ms: now,
        expires_at_unix_ms: now + 86_400_000,
        package_identity,
        launch_bundle,
        public_status_manifest,
        public_endpoint,
        policy_claim,
        public_probe,
        preflight_receipt,
        runbook_receipt,
        bootstrap_nodes,
        operators: {
            let mut operators = vec![
                OperatorAttestation {
                    operator_id: "operator-a".to_string(),
                    region: "us-east".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xa1),
                    signed_evidence_root: witness_evidence_root.clone(),
                    signature_sha3_256: String::new(),
                },
                OperatorAttestation {
                    operator_id: "operator-b".to_string(),
                    region: "eu-west".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xa2),
                    signed_evidence_root: witness_evidence_root.clone(),
                    signature_sha3_256: String::new(),
                },
            ];
            for operator in &mut operators {
                operator.signature_sha3_256 =
                    operator_signature_root(operator, &witness_evidence_root);
            }
            operators
        },
        observers: {
            let mut observers = vec![
                ObserverAttestation {
                    observer_id: "observer-us-east-1".to_string(),
                    region: "us-east".to_string(),
                    observed_endpoint: endpoint_url.clone(),
                    observed_evidence_root: witness_evidence_root.clone(),
                    signature: SignatureVerification {
                        algorithm: "ed25519-testnet-attestation".to_string(),
                        public_key: sample_ed25519_public_key_hex(0xb1),
                        signature_sha3_256: String::new(),
                        signature_hex: String::new(),
                        verified: false,
                    },
                },
                ObserverAttestation {
                    observer_id: "observer-eu-west-1".to_string(),
                    region: "eu-west".to_string(),
                    observed_endpoint: endpoint_url,
                    observed_evidence_root: witness_evidence_root.clone(),
                    signature: SignatureVerification {
                        algorithm: "ed25519-testnet-attestation".to_string(),
                        public_key: sample_ed25519_public_key_hex(0xb2),
                        signature_sha3_256: String::new(),
                        signature_hex: String::new(),
                        verified: false,
                    },
                },
            ];
            for observer in &mut observers {
                observer.signature.signature_sha3_256 =
                    observer_signature_root(observer, &witness_evidence_root);
                complete_sample_signature(&mut observer.signature);
            }
            observers
        },
        rollback_evidence: RollbackEvidence {
            rollback_plan_sha3_256: hex_64("rollback-plan"),
            last_drill_unix_ms: now,
            recovery_point_root: hex_64("rollback-recovery-point"),
        },
    };

    serde_json::to_string_pretty(&attestation).expect("sample attestation serializes")
}

pub fn sample_public_status_manifest_json_pretty() -> String {
    let sample = sample_public_surface();
    serde_json::to_string_pretty(&sample.public_status_manifest)
        .expect("sample public status manifest serializes")
}

pub fn sample_public_probe_json_pretty() -> String {
    let sample = sample_public_surface();
    serde_json::to_string_pretty(&sample.public_probe).expect("sample public probe serializes")
}

pub fn default_artifact_sha3_256() -> String {
    hex_64("nebula-testnet-artifact")
}

pub fn default_cargo_lock_sha3_256() -> String {
    hex_64("nebula-testnet-cargo-lock")
}

pub fn build_public_status_manifest_json_pretty(
    input: PublicSurfaceBuildInput,
) -> Result<String, AttestationError> {
    let surface = build_public_surface(input)?;
    serde_json::to_string_pretty(&surface.public_status_manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn build_public_probe_json_pretty(
    input: PublicSurfaceBuildInput,
) -> Result<String, AttestationError> {
    let surface = build_public_surface(input)?;
    serde_json::to_string_pretty(&surface.public_probe)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn build_deployment_attestation_json_pretty(
    input: DeploymentAttestationBuildInput,
) -> Result<String, AttestationError> {
    let readiness = readiness_report();
    let runtime_root = readiness.status_roots["runtime"]
        .as_str()
        .expect("runtime root is a string")
        .to_string();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string")
        .to_string();
    let package_identity =
        build_package_identity(&input.artifact_sha3_256, &input.cargo_lock_sha3_256)?;
    let launch_bundle =
        sample_launch_bundle(&package_identity.root, &runtime_root, &economics_root);
    let public_status_manifest =
        parse_public_status_manifest_json(&input.public_status_json, "public_status")?;
    let public_probe = parse_public_probe_json(&input.public_probe_json, "public_probe")?;
    let preflight_receipt = parse_receipt_json(&input.preflight_receipt_json, "preflight_receipt")?;
    let runbook_receipt = parse_receipt_json(&input.runbook_receipt_json, "runbook_receipt")?;

    let mut errors = Vec::new();
    verify_public_status_manifest(
        &mut errors,
        &public_status_manifest,
        &public_status_manifest.endpoint_url,
        &launch_bundle.root,
    );
    verify_public_probe(
        &mut errors,
        &public_probe,
        &public_status_manifest.endpoint_url,
        &launch_bundle.root,
        &economics_root,
    );
    verify_receipt(
        &mut errors,
        "preflight_receipt",
        &preflight_receipt,
        input.generated_at_unix_ms,
    );
    verify_receipt(
        &mut errors,
        "runbook_receipt",
        &runbook_receipt,
        input.generated_at_unix_ms,
    );
    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let policy_claim = sample_policy_claim(
        &readiness.public_launch_readiness.remediation_root,
        &economics_root,
    );
    let public_endpoint = PublicEndpointEvidence {
        url: public_status_manifest.endpoint_url.clone(),
        public_status_manifest_root: public_status_manifest.root.clone(),
        tls_pins: input.tls_pins,
    };
    let witness_evidence_root = deployment_witness_root(
        &launch_bundle,
        &public_status_manifest,
        &public_endpoint,
        &policy_claim,
        &public_probe,
    );
    let bootstrap_nodes = input
        .bootstrap_nodes
        .into_iter()
        .map(|node| {
            let mut node = BootstrapNode {
                node_id: node.node_id,
                operator_id: node.operator_id,
                region: node.region,
                endpoint: node.endpoint,
                attestation_root: String::new(),
            };
            node.attestation_root = bootstrap_node_root(&node, &witness_evidence_root);
            node
        })
        .collect::<Vec<_>>();
    let operators = input
        .operators
        .into_iter()
        .map(|operator| {
            let mut operator = OperatorAttestation {
                operator_id: operator.operator_id,
                region: operator.region,
                public_key: operator.public_key,
                signed_evidence_root: witness_evidence_root.clone(),
                signature_sha3_256: String::new(),
            };
            operator.signature_sha3_256 =
                operator_signature_root(&operator, &witness_evidence_root);
            operator
        })
        .collect::<Vec<_>>();
    let mut observers = Vec::new();
    for observer in input.observers {
        let observer_secret_key_hex = observer.secret_key_hex;
        let mut observer = ObserverAttestation {
            observer_id: observer.observer_id,
            region: observer.region,
            observed_endpoint: public_endpoint.url.clone(),
            observed_evidence_root: witness_evidence_root.clone(),
            signature: SignatureVerification {
                algorithm: "ed25519-testnet-attestation".to_string(),
                public_key: observer.public_key,
                signature_sha3_256: String::new(),
                signature_hex: String::new(),
                verified: false,
            },
        };
        observer.signature.signature_sha3_256 =
            observer_signature_root(&observer, &witness_evidence_root);
        if let Some(secret_key_hex) = observer_secret_key_hex {
            let derived_public_key = public_key_hex_for_secret_key(&secret_key_hex)
                .map_err(|error| AttestationError::Invalid(vec![error]))?;
            if !derived_public_key.eq_ignore_ascii_case(&observer.signature.public_key) {
                return Err(AttestationError::Invalid(vec![format!(
                    "observer {} secret_key_hex does not match public_key",
                    observer.observer_id
                )]));
            }
            observer.signature.signature_hex =
                sign_root_with_secret_key(&secret_key_hex, &observer.signature.signature_sha3_256)
                    .map_err(|error| AttestationError::Invalid(vec![error]))?;
            observer.signature.verified = true;
        } else {
            complete_sample_signature(&mut observer.signature);
        }
        observers.push(observer);
    }
    let attestation = DeploymentAttestation {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        generated_at_unix_ms: input.generated_at_unix_ms,
        expires_at_unix_ms: input.expires_at_unix_ms,
        package_identity,
        launch_bundle,
        public_status_manifest,
        public_endpoint,
        policy_claim,
        public_probe,
        preflight_receipt,
        runbook_receipt,
        bootstrap_nodes,
        operators,
        observers,
        rollback_evidence: RollbackEvidence {
            rollback_plan_sha3_256: input.rollback_plan_sha3_256,
            last_drill_unix_ms: input.rollback_last_drill_unix_ms,
            recovery_point_root: input.rollback_recovery_point_root,
        },
    };
    let output = serde_json::to_string_pretty(&attestation)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    verify_deployment_attestation_json(&output)?;
    Ok(output)
}

pub fn verify_public_status_manifest_json(
    input: &str,
) -> Result<PublicStatusReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let manifest = serde_json::from_str::<PublicStatusManifest>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let expected = sample_public_surface();

    verify_public_status_manifest(
        &mut errors,
        &manifest,
        &expected.endpoint_url,
        &expected.launch_bundle_root,
    );

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(PublicStatusReport {
        public_status_ready: true,
        level: "public-status-attested",
        public_status_manifest_root: manifest.root,
        endpoint_url: manifest.endpoint_url,
        launch_bundle_root: manifest.launch_bundle_root,
    })
}

pub fn verify_public_probe_json(input: &str) -> Result<PublicProbeReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let probe = serde_json::from_str::<PublicProbe>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let expected = sample_public_surface();

    verify_public_probe(
        &mut errors,
        &probe,
        &expected.endpoint_url,
        &expected.launch_bundle_root,
        &expected.economics_root,
    );

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(PublicProbeReport {
        public_probe_ready: true,
        level: "public-probe-attested",
        public_probe_root: probe.root,
        endpoint_url: probe.url,
        launch_bundle_root: probe.body.launch_bundle_root,
        fee_policy_root: probe.body.fee_policy_root,
    })
}

pub fn build_runtime_surface_evidence_json_pretty(
    input: RuntimeSurfaceEvidenceBuildInput,
) -> Result<String, AttestationError> {
    let status = parse_json_value(&input.status_json, "status")?;
    let chain_id = json_string_field(&status, "status.chain_id")?;
    let runtime_version = json_string_field(&status, "status.runtime_version")?;
    let mut evidence = RuntimeSurfaceEvidence {
        chain_id,
        runtime_version,
        endpoint_url: input.endpoint_url,
        capture_mode: input.capture_mode,
        tls_observation: input.tls_observation,
        captured_at_unix_ms: input.captured_at_unix_ms,
        health: parse_json_value(&input.health_json, "health")?,
        status,
        snapshot: parse_json_value(&input.snapshot_json, "snapshot")?,
        ops: parse_json_value(&input.ops_json, "ops")?,
        backup: parse_json_value(&input.backup_json, "backup")?,
        rpc_status: parse_json_value(&input.rpc_status_json, "rpc_status")?,
        rpc_ops_status: parse_json_value(&input.rpc_ops_status_json, "rpc_ops_status")?,
        rpc_backup_manifest: parse_json_value(
            &input.rpc_backup_manifest_json,
            "rpc_backup_manifest",
        )?,
        metrics_text: input.metrics_text,
        root: String::new(),
    };
    evidence.root = runtime_surface_evidence_root(&evidence);
    let output = serde_json::to_string_pretty(&evidence)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    verify_runtime_surface_evidence_json(&output)?;
    Ok(output)
}

pub fn verify_runtime_surface_evidence_json(
    input: &str,
) -> Result<RuntimeSurfaceEvidenceReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let evidence = serde_json::from_str::<RuntimeSurfaceEvidence>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    verify_runtime_surface_evidence(&evidence)
}

fn verify_runtime_surface_evidence(
    evidence: &RuntimeSurfaceEvidence,
) -> Result<RuntimeSurfaceEvidenceReport, AttestationError> {
    let mut errors = Vec::new();
    let now = unix_ms();
    require_https_endpoint(
        &mut errors,
        "runtime_surface.endpoint_url",
        &evidence.endpoint_url,
    );
    require_eq(
        &mut errors,
        "runtime_surface.chain_id",
        &evidence.chain_id,
        CHAIN_ID,
    );
    require_eq(
        &mut errors,
        "runtime_surface.runtime_version",
        &evidence.runtime_version,
        VERSION,
    );
    match evidence.capture_mode.as_str() {
        RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT => {
            if evidence.tls_observation.is_none() {
                errors.push(
                    "runtime_surface.tls_observation is required for external-public-endpoint capture"
                        .to_string(),
                );
            }
        }
        RUNTIME_SURFACE_CAPTURE_MODE_LOOPBACK_DEVNET => {}
        _ => errors.push(format!(
            "runtime_surface.capture_mode must be {RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT} or {RUNTIME_SURFACE_CAPTURE_MODE_LOOPBACK_DEVNET}"
        )),
    }
    if let Some(tls_observation) = &evidence.tls_observation {
        verify_runtime_surface_tls_observation(&mut errors, tls_observation, now);
    }
    if let Some(launch_endpoint_url) = evidence
        .status
        .get("launch_endpoint_url")
        .and_then(Value::as_str)
    {
        require_eq(
            &mut errors,
            "runtime_surface.endpoint_url",
            &evidence.endpoint_url,
            launch_endpoint_url,
        );
    }
    if evidence.captured_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push(
            "runtime_surface.captured_at_unix_ms is more than five minutes in the future"
                .to_string(),
        );
    }
    if evidence.captured_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("runtime_surface.captured_at_unix_ms is older than 24 hours".to_string());
    }
    require_root(
        &mut errors,
        "runtime_surface.root",
        &evidence.root,
        &runtime_surface_evidence_root(evidence),
    );

    let rpc_status = rpc_result_or_value(&mut errors, "rpc_status", &evidence.rpc_status);
    let rpc_ops = rpc_result_or_value(&mut errors, "rpc_ops_status", &evidence.rpc_ops_status);
    let rpc_backup = rpc_result_or_value(
        &mut errors,
        "rpc_backup_manifest",
        &evidence.rpc_backup_manifest,
    );

    require_durable_field_set_eq(
        &mut errors,
        "rpc_status.result",
        rpc_status,
        "status",
        &evidence.status,
        RUNTIME_STATUS_DURABLE_FIELDS,
    );
    require_durable_field_set_eq(
        &mut errors,
        "rpc_ops_status.result",
        rpc_ops,
        "ops",
        &evidence.ops,
        RUNTIME_OPS_DURABLE_FIELDS,
    );
    require_durable_field_set_eq(
        &mut errors,
        "rpc_backup_manifest.result",
        rpc_backup,
        "backup",
        &evidence.backup,
        RUNTIME_BACKUP_DURABLE_FIELDS,
    );

    let snapshot = parse_surface_value::<runtime::RuntimeSnapshot>(
        &mut errors,
        "snapshot",
        &evidence.snapshot,
    );
    let ops = parse_surface_value::<runtime::RuntimeOpsStatus>(&mut errors, "ops", &evidence.ops);
    let backup = parse_surface_value::<runtime::RuntimeBackupManifest>(
        &mut errors,
        "backup",
        &evidence.backup,
    );

    if let Some(snapshot) = &snapshot {
        if let Err(error) = runtime::validate_runtime_snapshot(snapshot) {
            errors.push(format!("snapshot validation failed: {error}"));
        }
        require_root(
            &mut errors,
            "snapshot.root",
            &snapshot.root,
            &runtime::runtime_snapshot_root(snapshot),
        );
    }
    if let Some(ops) = &ops {
        require_root(
            &mut errors,
            "ops.ops_root",
            &ops.ops_root,
            &runtime::runtime_ops_status_root(ops),
        );
    }
    if let Some(backup) = &backup {
        require_root(
            &mut errors,
            "backup.backup_root",
            &backup.backup_root,
            &runtime::runtime_backup_manifest_root(backup),
        );
    }

    require_health_status_agreement(&mut errors, &evidence.health, &evidence.status);
    require_ops_backup_snapshot_agreement(
        &mut errors,
        &evidence.health,
        &evidence.status,
        &evidence.snapshot,
        &evidence.ops,
        &evidence.backup,
    );

    if let Some(snapshot) = &snapshot {
        require_metrics_agreement(
            &mut errors,
            &evidence.metrics_text,
            &evidence.status,
            snapshot,
        );
        require_runtime_surface_snapshot_economics(&mut errors, &evidence.status, snapshot);
    }

    let launch_package_bundle_root =
        json_string_field(&evidence.status, "status.launch_package_bundle_root").ok();
    let launch_package_root =
        json_string_field(&evidence.status, "status.launch_package_root").ok();
    let runtime_fee_policy_root =
        json_string_field(&evidence.status, "status.fee_policy_root").ok();
    let runtime_gas_price_nebulai =
        json_u128_field(&evidence.status, "status.gas_price_nebulai").ok();
    let validator_set_root = json_string_field(&evidence.status, "status.validator_set_root").ok();
    let genesis_root = json_string_field(&evidence.status, "status.genesis_root").ok();
    match &launch_package_bundle_root {
        Some(root) => require_hex_root(&mut errors, "status.launch_package_bundle_root", root),
        None => errors.push("status.launch_package_bundle_root must be a string".to_string()),
    }
    match &launch_package_root {
        Some(root) => require_hex_root(&mut errors, "status.launch_package_root", root),
        None => errors.push("status.launch_package_root must be a string".to_string()),
    }
    let expected_fee_policy_root = fee_policy_root();
    match &runtime_fee_policy_root {
        Some(root) => require_root(
            &mut errors,
            "status.fee_policy_root",
            root,
            &expected_fee_policy_root,
        ),
        None => errors.push("status.fee_policy_root must be a string".to_string()),
    }
    let expected_gas_price_nebulai = hybrid_fee_policy().minimum_gas_price_nebulai;
    match runtime_gas_price_nebulai {
        Some(gas_price_nebulai) if gas_price_nebulai == expected_gas_price_nebulai => {}
        Some(gas_price_nebulai) => errors.push(format!(
            "status.gas_price_nebulai expected {expected_gas_price_nebulai} but got {gas_price_nebulai}"
        )),
        None => errors.push("status.gas_price_nebulai must be a u128".to_string()),
    }
    match &validator_set_root {
        Some(root) => require_hex_root(&mut errors, "status.validator_set_root", root),
        None => errors.push("status.validator_set_root must be a string".to_string()),
    }
    match &genesis_root {
        Some(root) => require_hex_root(&mut errors, "status.genesis_root", root),
        None => errors.push("status.genesis_root must be a string".to_string()),
    }

    let health_ready = json_bool(&evidence.health, "public_ops_ready").unwrap_or(false);
    let ops_ready = json_bool(&evidence.ops, "public_ops_ready").unwrap_or(false);
    if !health_ready {
        errors
            .push("health.public_ops_ready must be true for runtime surface evidence".to_string());
    }
    if !ops_ready {
        errors.push("ops.public_ops_ready must be true for runtime surface evidence".to_string());
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let snapshot = snapshot.expect("snapshot was parsed when no errors were recorded");
    let latest = snapshot
        .blocks
        .last()
        .expect("validated snapshot always has a latest block");
    let economics = runtime::derive_runtime_snapshot_economics(&snapshot)
        .expect("snapshot economics were derived when no errors were recorded");
    let ops = ops.expect("ops was parsed when no errors were recorded");
    let backup = backup.expect("backup was parsed when no errors were recorded");

    Ok(RuntimeSurfaceEvidenceReport {
        runtime_surface_ready: true,
        level: "runtime-surface-attested",
        runtime_surface_root: evidence.root.clone(),
        endpoint_url: evidence.endpoint_url.clone(),
        capture_mode: evidence.capture_mode.clone(),
        tls_observation: evidence.tls_observation.clone(),
        chain_id: evidence.chain_id.clone(),
        runtime_version: evidence.runtime_version.clone(),
        launch_package_bundle_root: launch_package_bundle_root
            .expect("launch package bundle root was parsed when no errors were recorded"),
        launch_package_root: launch_package_root
            .expect("launch package root was parsed when no errors were recorded"),
        fee_policy_root: runtime_fee_policy_root
            .expect("fee policy root was parsed when no errors were recorded"),
        gas_price_nebulai: runtime_gas_price_nebulai
            .expect("gas price was parsed when no errors were recorded"),
        validator_set_root: validator_set_root
            .expect("validator set root was parsed when no errors were recorded"),
        genesis_root: genesis_root.expect("genesis root was parsed when no errors were recorded"),
        latest_height: latest.height,
        latest_hash: latest.block_hash.clone(),
        snapshot_root: snapshot.root,
        state_root: snapshot.state_root,
        included_nbla_receipt_count: economics.included_nbla_receipt_count,
        included_nxmr_receipt_count: economics.included_nxmr_receipt_count,
        total_nxmr_fees_units: economics.total_nxmr_fees_units,
        buyback_pool_nebulai: economics.buyback_pool_nebulai,
        validator_reward_nebulai: economics.validator_reward_nebulai,
        nxmr_validator_reward_nebulai: economics.nxmr_validator_reward_nebulai,
        ops_root: ops.ops_root,
        backup_root: backup.backup_root,
        public_ops_ready: true,
        blocking_gaps: ops.blocking_gaps,
    })
}

fn verify_public_surface_jsons_for_deployment(
    public_status_json: &str,
    public_probe_json: &str,
    deployment_attestation: &DeploymentAttestation,
) -> Result<(PublicStatusReport, PublicProbeReport), AttestationError> {
    let readiness = readiness_report();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string");
    let public_status_manifest =
        parse_public_status_manifest_json(public_status_json, "public_status")?;
    let public_probe = parse_public_probe_json(public_probe_json, "public_probe")?;
    let mut errors = Vec::new();
    verify_public_status_manifest(
        &mut errors,
        &public_status_manifest,
        &deployment_attestation.public_endpoint.url,
        &deployment_attestation.launch_bundle.root,
    );
    verify_public_probe(
        &mut errors,
        &public_probe,
        &deployment_attestation.public_endpoint.url,
        &deployment_attestation.launch_bundle.root,
        economics_root,
    );
    require_root(
        &mut errors,
        "public_status_manifest.root",
        &public_status_manifest.root,
        &deployment_attestation.public_status_manifest.root,
    );
    require_root(
        &mut errors,
        "public_probe.root",
        &public_probe.root,
        &deployment_attestation.public_probe.root,
    );
    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok((
        PublicStatusReport {
            public_status_ready: true,
            level: "public-status-attested",
            public_status_manifest_root: public_status_manifest.root,
            endpoint_url: public_status_manifest.endpoint_url,
            launch_bundle_root: public_status_manifest.launch_bundle_root,
        },
        PublicProbeReport {
            public_probe_ready: true,
            level: "public-probe-attested",
            public_probe_root: public_probe.root,
            endpoint_url: public_probe.url,
            launch_bundle_root: public_probe.body.launch_bundle_root,
            fee_policy_root: public_probe.body.fee_policy_root,
        },
    ))
}

pub fn sample_preflight_receipt_json_pretty() -> String {
    let receipt = sample_receipt("preflight-receipt", unix_ms());
    serde_json::to_string_pretty(&receipt).expect("sample preflight receipt serializes")
}

pub fn sample_runbook_receipt_json_pretty() -> String {
    let receipt = sample_receipt("runbook-receipt", unix_ms());
    serde_json::to_string_pretty(&receipt).expect("sample runbook receipt serializes")
}

pub fn verify_preflight_receipt_json(input: &str) -> Result<ReceiptReport, AttestationError> {
    verify_receipt_json(input, "preflight-receipt", "preflight-receipt")
}

pub fn verify_runbook_receipt_json(input: &str) -> Result<ReceiptReport, AttestationError> {
    verify_receipt_json(input, "runbook-receipt", "runbook-receipt")
}

pub fn sample_validator_set_json_pretty() -> String {
    let readiness = readiness_report();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string")
        .to_string();

    let mut validators = vec![
        ValidatorAdmission {
            validator_id: "validator-a".to_string(),
            operator_id: "operator-a".to_string(),
            node_id: "bootstrap-us-east-1".to_string(),
            region: "us-east".to_string(),
            operator_contact: "mailto:operator-a@testnet.nebula.example".to_string(),
            consensus_public_key: sample_ed25519_public_key_hex(0xc1),
            network_public_key: sample_ed25519_public_key_hex(0xd1),
            p2p_endpoint: "tcp://bootstrap-a.testnet.nebula.example:26656".to_string(),
            reward_account: "nbla-reward-operator-a".to_string(),
            commission_bps: 500,
            genesis_power: 1,
            signed_admission_root: String::new(),
        },
        ValidatorAdmission {
            validator_id: "validator-b".to_string(),
            operator_id: "operator-b".to_string(),
            node_id: "bootstrap-eu-west-1".to_string(),
            region: "eu-west".to_string(),
            operator_contact: "mailto:operator-b@testnet.nebula.example".to_string(),
            consensus_public_key: sample_ed25519_public_key_hex(0xc2),
            network_public_key: sample_ed25519_public_key_hex(0xd2),
            p2p_endpoint: "tcp://bootstrap-b.testnet.nebula.example:26656".to_string(),
            reward_account: "nbla-reward-operator-b".to_string(),
            commission_bps: 500,
            genesis_power: 1,
            signed_admission_root: String::new(),
        },
    ];
    for validator in &mut validators {
        validator.signed_admission_root =
            validator_admission_signature_root(validator, &economics_root);
    }

    let mut manifest = ValidatorSetManifest {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        epoch: PUBLIC_TESTNET_GENESIS_EPOCH,
        reward_unit: NEBULAI_UNIT.to_string(),
        fee_policy_root: economics_root,
        minimum_validator_count: MIN_PUBLIC_TESTNET_VALIDATORS,
        minimum_operator_count: MIN_PUBLIC_TESTNET_OPERATORS,
        minimum_region_count: MIN_PUBLIC_TESTNET_REGIONS,
        validators,
        root: String::new(),
    };
    manifest.root = validator_set_root(&manifest);

    serde_json::to_string_pretty(&manifest).expect("sample validator set serializes")
}

pub fn verify_validator_set_json(input: &str) -> Result<ValidatorSetReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let value = serde_json::from_str::<Value>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let manifest = serde_json::from_value::<ValidatorSetManifest>(value)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let readiness = readiness_report();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string");

    require_eq(&mut errors, "chain_id", &manifest.chain_id, CHAIN_ID);
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        VERSION,
    );
    if manifest.epoch != PUBLIC_TESTNET_GENESIS_EPOCH {
        errors.push(format!("epoch must be {PUBLIC_TESTNET_GENESIS_EPOCH}"));
    }
    require_eq(
        &mut errors,
        "reward_unit",
        &manifest.reward_unit,
        NEBULAI_UNIT,
    );
    require_eq(
        &mut errors,
        "fee_policy_root",
        &manifest.fee_policy_root,
        economics_root,
    );
    if manifest.minimum_validator_count < MIN_PUBLIC_TESTNET_VALIDATORS {
        errors.push(format!(
            "minimum_validator_count must be at least {MIN_PUBLIC_TESTNET_VALIDATORS}"
        ));
    }
    if manifest.minimum_operator_count < MIN_PUBLIC_TESTNET_OPERATORS {
        errors.push(format!(
            "minimum_operator_count must be at least {MIN_PUBLIC_TESTNET_OPERATORS}"
        ));
    }
    if manifest.minimum_region_count < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push(format!(
            "minimum_region_count must be at least {MIN_PUBLIC_TESTNET_REGIONS}"
        ));
    }
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &validator_set_root(&manifest),
    );

    let mut validator_ids = BTreeSet::new();
    let mut operator_ids = BTreeSet::new();
    let mut node_ids = BTreeSet::new();
    let mut regions = BTreeSet::new();
    let mut consensus_keys = BTreeSet::new();
    let mut network_keys = BTreeSet::new();
    let mut reward_accounts = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut total_genesis_power = 0_u64;

    for (index, validator) in manifest.validators.iter().enumerate() {
        verify_validator_admission(
            &mut errors,
            index,
            validator,
            &mut validator_ids,
            &mut operator_ids,
            &mut node_ids,
            &mut regions,
            &mut consensus_keys,
            &mut network_keys,
            &mut reward_accounts,
            &mut endpoints,
            &mut total_genesis_power,
            economics_root,
        );
    }

    if manifest.validators.len() < manifest.minimum_validator_count {
        errors.push(format!(
            "validators must include at least {} entries",
            manifest.minimum_validator_count
        ));
    }
    if operator_ids.len() < manifest.minimum_operator_count {
        errors.push(format!(
            "validators must include at least {} operators",
            manifest.minimum_operator_count
        ));
    }
    if regions.len() < manifest.minimum_region_count {
        errors.push(format!(
            "validators must cover at least {} regions",
            manifest.minimum_region_count
        ));
    }
    verify_validator_power_concentration(&mut errors, &manifest.validators, total_genesis_power);

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(ValidatorSetReport {
        validator_set_ready: true,
        level: "validator-set-attested",
        operator_roster_root: validator_operator_roster_root(&manifest),
        reward_ledger_root: validator_reward_ledger_root(&manifest),
        validator_set_root: manifest.root,
        validator_count: manifest.validators.len(),
        reward_account_count: reward_accounts.len(),
        operator_count: operator_ids.len(),
        region_count: regions.len(),
        total_genesis_power,
        reward_unit: manifest.reward_unit,
    })
}

pub fn sample_genesis_manifest_json_pretty() -> String {
    build_genesis_manifest_json_pretty(
        &sample_deployment_attestation_json_pretty(),
        &sample_validator_set_json_pretty(),
    )
    .expect("sample genesis manifest builds")
}

fn verified_deployment_attestation_manifest(
    deployment_attestation_json: &str,
) -> Result<DeploymentAttestation, AttestationError> {
    verify_deployment_attestation_json(deployment_attestation_json)?;
    serde_json::from_str::<DeploymentAttestation>(
        deployment_attestation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

fn verified_validator_set_manifest(
    validator_set_json: &str,
) -> Result<ValidatorSetManifest, AttestationError> {
    verify_validator_set_json(validator_set_json)?;
    serde_json::from_str::<ValidatorSetManifest>(validator_set_json.trim_start_matches('\u{feff}'))
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn sample_operator_handoff_json_pretty() -> String {
    build_operator_handoff_json_pretty(
        &sample_deployment_attestation_json_pretty(),
        &sample_validator_set_json_pretty(),
    )
    .expect("sample operator handoff builds")
}

pub fn build_operator_handoff_json_pretty(
    deployment_attestation_json: &str,
    validator_set_json: &str,
) -> Result<String, AttestationError> {
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let validator_set_manifest = verified_validator_set_manifest(validator_set_json)?;
    let mut binding_errors = Vec::new();
    verify_validator_deployment_binding(
        &mut binding_errors,
        &validator_set_manifest,
        &deployment_attestation,
    );
    if !binding_errors.is_empty() {
        return Err(AttestationError::Invalid(binding_errors));
    }

    let manifest = operator_handoff_manifest(&deployment_attestation, &validator_set_manifest);
    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn verify_operator_handoff_jsons(
    operator_handoff_json: &str,
    deployment_attestation_json: &str,
    validator_set_json: &str,
) -> Result<OperatorHandoffReport, AttestationError> {
    let manifest = serde_json::from_str::<OperatorHandoffManifest>(
        operator_handoff_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let validator_set_manifest = verified_validator_set_manifest(validator_set_json)?;
    let mut errors = Vec::new();

    verify_validator_deployment_binding(
        &mut errors,
        &validator_set_manifest,
        &deployment_attestation,
    );
    let expected = operator_handoff_manifest(&deployment_attestation, &validator_set_manifest);
    require_eq(
        &mut errors,
        "chain_id",
        &manifest.chain_id,
        &expected.chain_id,
    );
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        &expected.runtime_version,
    );
    require_eq(
        &mut errors,
        "launch_bundle_root",
        &manifest.launch_bundle_root,
        &expected.launch_bundle_root,
    );
    require_eq(
        &mut errors,
        "validator_set_root",
        &manifest.validator_set_root,
        &expected.validator_set_root,
    );
    if manifest.validator_set_epoch != expected.validator_set_epoch {
        errors.push(format!(
            "validator_set_epoch expected {} but got {}",
            expected.validator_set_epoch, manifest.validator_set_epoch
        ));
    }
    require_eq(
        &mut errors,
        "validator_deployment_binding_root",
        &manifest.validator_deployment_binding_root,
        &expected.validator_deployment_binding_root,
    );
    if manifest.entries != expected.entries {
        errors.push(
            "operator handoff entries do not match verified deployment and validator set"
                .to_string(),
        );
    }
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &operator_handoff_manifest_root(&manifest),
    );
    if manifest.root != expected.root {
        errors.push(format!(
            "operator handoff root does not match expected root {}",
            expected.root
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let operators = manifest
        .entries
        .iter()
        .map(|entry| entry.operator_id.as_str())
        .collect::<BTreeSet<_>>();
    let regions = manifest
        .entries
        .iter()
        .map(|entry| entry.region.as_str())
        .collect::<BTreeSet<_>>();

    Ok(OperatorHandoffReport {
        operator_handoff_ready: true,
        level: "operator-handoff-attested",
        operator_handoff_root: manifest.root,
        entry_count: manifest.entries.len(),
        operator_count: operators.len(),
        region_count: regions.len(),
        launch_bundle_root: manifest.launch_bundle_root,
        validator_set_root: manifest.validator_set_root,
        validator_deployment_binding_root: manifest.validator_deployment_binding_root,
    })
}

pub fn sample_operator_acceptance_json_pretty() -> String {
    build_operator_acceptance_json_pretty(
        &sample_operator_handoff_json_pretty(),
        &sample_deployment_attestation_json_pretty(),
        &sample_validator_set_json_pretty(),
    )
    .expect("sample operator acceptance builds")
}

pub fn build_operator_acceptance_json_pretty(
    operator_handoff_json: &str,
    deployment_attestation_json: &str,
    validator_set_json: &str,
) -> Result<String, AttestationError> {
    verify_operator_handoff_jsons(
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let handoff = serde_json::from_str::<OperatorHandoffManifest>(
        operator_handoff_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let manifest = operator_acceptance_manifest(&handoff, &deployment_attestation, unix_ms());

    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn verify_operator_acceptance_jsons(
    operator_acceptance_json: &str,
    operator_handoff_json: &str,
    deployment_attestation_json: &str,
    validator_set_json: &str,
) -> Result<OperatorAcceptanceReport, AttestationError> {
    verify_operator_handoff_jsons(
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let manifest = serde_json::from_str::<OperatorAcceptanceManifest>(
        operator_acceptance_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let handoff = serde_json::from_str::<OperatorHandoffManifest>(
        operator_handoff_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let mut errors = Vec::new();
    let now = unix_ms();
    let mut expected = operator_acceptance_manifest(
        &handoff,
        &deployment_attestation,
        manifest.accepted_at_unix_ms,
    );
    for expected_entry in &mut expected.entries {
        if let Some(entry) = manifest.entries.iter().find(|entry| {
            entry.operator_id == expected_entry.operator_id
                && entry.validator_id == expected_entry.validator_id
                && entry.node_id == expected_entry.node_id
        }) {
            expected_entry.signature = entry.signature.clone();
        }
    }
    expected.root = operator_acceptance_manifest_root(&expected);

    if manifest.accepted_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("accepted_at_unix_ms is more than five minutes in the future".to_string());
    }
    if manifest.accepted_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("accepted_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(
        &mut errors,
        "chain_id",
        &manifest.chain_id,
        &expected.chain_id,
    );
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        &expected.runtime_version,
    );
    require_eq(
        &mut errors,
        "launch_bundle_root",
        &manifest.launch_bundle_root,
        &expected.launch_bundle_root,
    );
    require_eq(
        &mut errors,
        "operator_handoff_root",
        &manifest.operator_handoff_root,
        &expected.operator_handoff_root,
    );
    if manifest.entries != expected.entries {
        errors.push(
            "operator acceptance entries do not match verified operator handoff and deployment"
                .to_string(),
        );
    }
    for (index, entry) in manifest.entries.iter().enumerate() {
        if !entry.accepted {
            errors.push(format!("entries[{index}].accepted must be true"));
        }
        require_root(
            &mut errors,
            &format!("entries[{index}].acceptance_root"),
            &entry.acceptance_root,
            &operator_acceptance_entry_root(
                entry,
                &manifest.launch_bundle_root,
                &manifest.operator_handoff_root,
                manifest.accepted_at_unix_ms,
            ),
        );
        verify_signature_material(
            &mut errors,
            &format!("entries[{index}].signature"),
            &entry.signature,
            "ed25519-testnet-operator-acceptance",
            &entry.operator_public_key,
            &operator_acceptance_signature_root(entry),
        );
    }
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &operator_acceptance_manifest_root(&manifest),
    );
    if manifest.root != expected.root {
        errors.push(format!(
            "operator acceptance root does not match expected root {}",
            expected.root
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let accepted_operators = manifest
        .entries
        .iter()
        .map(|entry| entry.operator_id.as_str())
        .collect::<BTreeSet<_>>();
    let accepted_validators = manifest
        .entries
        .iter()
        .map(|entry| entry.validator_id.as_str())
        .collect::<BTreeSet<_>>();

    Ok(OperatorAcceptanceReport {
        operator_acceptance_ready: true,
        level: "operator-acceptance-attested",
        operator_acceptance_root: manifest.root,
        operator_handoff_root: manifest.operator_handoff_root,
        accepted_operator_count: accepted_operators.len(),
        accepted_validator_count: accepted_validators.len(),
        accepted_at_unix_ms: manifest.accepted_at_unix_ms,
    })
}

pub fn build_genesis_manifest_json_pretty(
    deployment_attestation_json: &str,
    validator_set_json: &str,
) -> Result<String, AttestationError> {
    let deployment_report = verify_deployment_attestation_json(deployment_attestation_json)?;
    let validator_set_report = verify_validator_set_json(validator_set_json)?;
    let deployment_attestation = serde_json::from_str::<DeploymentAttestation>(
        deployment_attestation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let validator_set_manifest = serde_json::from_str::<ValidatorSetManifest>(
        validator_set_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let readiness = readiness_report();
    let fee_policy_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string")
        .to_string();
    let validator_admission_root = readiness.status_roots["validator_admission"]
        .as_str()
        .expect("validator admission root is a string")
        .to_string();

    let mut manifest = GenesisManifest {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        genesis_time_unix_ms: unix_ms(),
        activation_height: PUBLIC_TESTNET_ACTIVATION_HEIGHT,
        deployment_attestation_root: deployment_report.evidence_root,
        public_surface_root: deployment_report.public_surface_root,
        operator_approval_root: deployment_report.operator_approval_root,
        observer_confirmation_root: deployment_report.observer_confirmation_root,
        rollback_readiness_root: deployment_report.rollback_readiness_root,
        deployment_validity_root: deployment_report.deployment_validity_root,
        deployment_quorum_root: deployment_report.deployment_quorum_root,
        bootstrap_roster_root: deployment_report.bootstrap_roster_root,
        operational_evidence_root: deployment_report.operational_evidence_root,
        validator_set_root: validator_set_report.validator_set_root,
        validator_set_epoch: PUBLIC_TESTNET_GENESIS_EPOCH,
        fee_policy_root,
        validator_admission_root,
        operator_roster_root: validator_set_report.operator_roster_root,
        reward_ledger_root: validator_set_report.reward_ledger_root,
        validator_deployment_binding_root: validator_deployment_binding_root(
            &deployment_attestation,
            &validator_set_manifest,
        ),
        initial_validator_count: validator_set_report.validator_count,
        initial_operator_count: validator_set_report.operator_count,
        initial_region_count: validator_set_report.region_count,
        initial_total_power: validator_set_report.total_genesis_power,
        native_fee_token: NBLA_SYMBOL.to_string(),
        native_base_unit: NEBULAI_UNIT.to_string(),
        bridged_fee_token: NXMR_SYMBOL.to_string(),
        root: String::new(),
    };
    manifest.root = genesis_manifest_root(&manifest);

    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

pub fn verify_genesis_manifest_json(
    input: &str,
) -> Result<GenesisManifestReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let manifest = serde_json::from_str::<GenesisManifest>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let now = unix_ms();
    let readiness = readiness_report();
    let fee_policy_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string");
    let validator_admission_root = readiness.status_roots["validator_admission"]
        .as_str()
        .expect("validator admission root is a string");

    require_eq(&mut errors, "chain_id", &manifest.chain_id, CHAIN_ID);
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        VERSION,
    );
    if manifest.genesis_time_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("genesis_time_unix_ms is more than five minutes in the future".to_string());
    }
    if manifest.genesis_time_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("genesis_time_unix_ms is older than 24 hours".to_string());
    }
    if manifest.activation_height != PUBLIC_TESTNET_ACTIVATION_HEIGHT {
        errors.push(format!(
            "activation_height must be {PUBLIC_TESTNET_ACTIVATION_HEIGHT}"
        ));
    }
    require_hex_root(
        &mut errors,
        "deployment_attestation_root",
        &manifest.deployment_attestation_root,
    );
    require_hex_root(
        &mut errors,
        "public_surface_root",
        &manifest.public_surface_root,
    );
    require_hex_root(
        &mut errors,
        "operator_approval_root",
        &manifest.operator_approval_root,
    );
    require_hex_root(
        &mut errors,
        "observer_confirmation_root",
        &manifest.observer_confirmation_root,
    );
    require_hex_root(
        &mut errors,
        "rollback_readiness_root",
        &manifest.rollback_readiness_root,
    );
    require_hex_root(
        &mut errors,
        "deployment_validity_root",
        &manifest.deployment_validity_root,
    );
    require_hex_root(
        &mut errors,
        "deployment_quorum_root",
        &manifest.deployment_quorum_root,
    );
    require_hex_root(
        &mut errors,
        "bootstrap_roster_root",
        &manifest.bootstrap_roster_root,
    );
    require_hex_root(
        &mut errors,
        "operational_evidence_root",
        &manifest.operational_evidence_root,
    );
    require_hex_root(
        &mut errors,
        "validator_set_root",
        &manifest.validator_set_root,
    );
    if manifest.validator_set_epoch != PUBLIC_TESTNET_GENESIS_EPOCH {
        errors.push(format!(
            "validator_set_epoch must be {PUBLIC_TESTNET_GENESIS_EPOCH}"
        ));
    }
    require_eq(
        &mut errors,
        "fee_policy_root",
        &manifest.fee_policy_root,
        fee_policy_root,
    );
    require_eq(
        &mut errors,
        "validator_admission_root",
        &manifest.validator_admission_root,
        validator_admission_root,
    );
    require_hex_root(
        &mut errors,
        "operator_roster_root",
        &manifest.operator_roster_root,
    );
    require_hex_root(
        &mut errors,
        "reward_ledger_root",
        &manifest.reward_ledger_root,
    );
    require_hex_root(
        &mut errors,
        "validator_deployment_binding_root",
        &manifest.validator_deployment_binding_root,
    );
    verify_genesis_root_domains(&mut errors, &manifest);
    if manifest.initial_validator_count < MIN_PUBLIC_TESTNET_VALIDATORS {
        errors.push(format!(
            "initial_validator_count must be at least {MIN_PUBLIC_TESTNET_VALIDATORS}"
        ));
    }
    if manifest.initial_operator_count < MIN_PUBLIC_TESTNET_OPERATORS {
        errors.push(format!(
            "initial_operator_count must be at least {MIN_PUBLIC_TESTNET_OPERATORS}"
        ));
    }
    if manifest.initial_region_count < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push(format!(
            "initial_region_count must be at least {MIN_PUBLIC_TESTNET_REGIONS}"
        ));
    }
    if manifest.initial_total_power == 0 {
        errors.push("initial_total_power must be greater than zero".to_string());
    }
    require_eq(
        &mut errors,
        "native_fee_token",
        &manifest.native_fee_token,
        NBLA_SYMBOL,
    );
    require_eq(
        &mut errors,
        "native_base_unit",
        &manifest.native_base_unit,
        NEBULAI_UNIT,
    );
    require_eq(
        &mut errors,
        "bridged_fee_token",
        &manifest.bridged_fee_token,
        NXMR_SYMBOL,
    );
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &genesis_manifest_root(&manifest),
    );

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(GenesisManifestReport {
        genesis_ready: true,
        level: "genesis-manifest-attested",
        genesis_root: manifest.root,
        deployment_attestation_root: manifest.deployment_attestation_root,
        public_surface_root: manifest.public_surface_root,
        operator_approval_root: manifest.operator_approval_root,
        observer_confirmation_root: manifest.observer_confirmation_root,
        rollback_readiness_root: manifest.rollback_readiness_root,
        deployment_validity_root: manifest.deployment_validity_root,
        deployment_quorum_root: manifest.deployment_quorum_root,
        bootstrap_roster_root: manifest.bootstrap_roster_root,
        operational_evidence_root: manifest.operational_evidence_root,
        validator_set_root: manifest.validator_set_root,
        validator_set_epoch: manifest.validator_set_epoch,
        operator_roster_root: manifest.operator_roster_root,
        reward_ledger_root: manifest.reward_ledger_root,
        validator_deployment_binding_root: manifest.validator_deployment_binding_root,
        initial_validator_count: manifest.initial_validator_count,
        initial_operator_count: manifest.initial_operator_count,
        initial_region_count: manifest.initial_region_count,
        initial_total_power: manifest.initial_total_power,
        activation_height: manifest.activation_height,
        native_fee_token: manifest.native_fee_token,
        native_base_unit: manifest.native_base_unit,
        bridged_fee_token: manifest.bridged_fee_token,
    })
}

fn verify_genesis_root_domains(errors: &mut Vec<String>, manifest: &GenesisManifest) {
    let mut roots_by_value = BTreeMap::new();
    for (label, root) in [
        (
            "deployment_attestation_root",
            manifest.deployment_attestation_root.as_str(),
        ),
        ("public_surface_root", manifest.public_surface_root.as_str()),
        (
            "operator_approval_root",
            manifest.operator_approval_root.as_str(),
        ),
        (
            "observer_confirmation_root",
            manifest.observer_confirmation_root.as_str(),
        ),
        (
            "rollback_readiness_root",
            manifest.rollback_readiness_root.as_str(),
        ),
        (
            "deployment_validity_root",
            manifest.deployment_validity_root.as_str(),
        ),
        (
            "deployment_quorum_root",
            manifest.deployment_quorum_root.as_str(),
        ),
        (
            "bootstrap_roster_root",
            manifest.bootstrap_roster_root.as_str(),
        ),
        (
            "operational_evidence_root",
            manifest.operational_evidence_root.as_str(),
        ),
        ("validator_set_root", manifest.validator_set_root.as_str()),
        ("fee_policy_root", manifest.fee_policy_root.as_str()),
        (
            "validator_admission_root",
            manifest.validator_admission_root.as_str(),
        ),
        (
            "operator_roster_root",
            manifest.operator_roster_root.as_str(),
        ),
        ("reward_ledger_root", manifest.reward_ledger_root.as_str()),
        (
            "validator_deployment_binding_root",
            manifest.validator_deployment_binding_root.as_str(),
        ),
    ] {
        if let Some(previous_label) = roots_by_value.insert(root, label) {
            errors.push(format!("{label} must differ from {previous_label}"));
        }
    }
}

pub fn verify_launch_package_jsons(
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    genesis_manifest_json: &str,
) -> Result<LaunchPackageReport, AttestationError> {
    let deployment_report = verify_deployment_attestation_json(deployment_attestation_json)?;
    let deployment_attestation = serde_json::from_str::<DeploymentAttestation>(
        deployment_attestation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let public_status_manifest = serde_json::from_str::<PublicStatusManifest>(
        public_status_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let public_probe =
        serde_json::from_str::<PublicProbe>(public_probe_json.trim_start_matches('\u{feff}'))
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let validator_set_manifest = serde_json::from_str::<ValidatorSetManifest>(
        validator_set_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let genesis_manifest = serde_json::from_str::<GenesisManifest>(
        genesis_manifest_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let validator_set_report = verify_validator_set_json(validator_set_json)?;
    let genesis_report = verify_genesis_manifest_json(genesis_manifest_json)?;
    let mut errors = Vec::new();
    let readiness = readiness_report();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string");
    let expected_validator_deployment_binding_root =
        validator_deployment_binding_root(&deployment_attestation, &validator_set_manifest);
    let expected_operator_handoff_root =
        operator_handoff_manifest(&deployment_attestation, &validator_set_manifest).root;

    verify_public_status_manifest(
        &mut errors,
        &public_status_manifest,
        &deployment_attestation.public_endpoint.url,
        &deployment_attestation.launch_bundle.root,
    );
    verify_public_probe(
        &mut errors,
        &public_probe,
        &deployment_attestation.public_endpoint.url,
        &deployment_attestation.launch_bundle.root,
        economics_root,
    );

    if public_status_manifest.root != deployment_attestation.public_status_manifest.root {
        errors.push(format!(
            "public status root does not match deployment attestation public status root {}",
            deployment_attestation.public_status_manifest.root
        ));
    }
    if public_status_manifest.endpoint_url != deployment_attestation.public_endpoint.url {
        errors.push(format!(
            "public status endpoint_url expected {} but got {}",
            deployment_attestation.public_endpoint.url, public_status_manifest.endpoint_url
        ));
    }
    if public_probe.root != deployment_attestation.public_probe.root {
        errors.push(format!(
            "public probe root does not match deployment attestation public probe root {}",
            deployment_attestation.public_probe.root
        ));
    }
    verify_validator_deployment_binding(
        &mut errors,
        &validator_set_manifest,
        &deployment_attestation,
    );

    if genesis_report.deployment_attestation_root != deployment_report.evidence_root {
        errors.push(format!(
            "genesis deployment_attestation_root does not match deployment evidence root {}",
            deployment_report.evidence_root
        ));
    }
    if genesis_report.public_surface_root != deployment_report.public_surface_root {
        errors.push(format!(
            "genesis public_surface_root does not match deployment public surface root {}",
            deployment_report.public_surface_root
        ));
    }
    if genesis_report.operator_approval_root != deployment_report.operator_approval_root {
        errors.push(format!(
            "genesis operator_approval_root does not match deployment operator approval root {}",
            deployment_report.operator_approval_root
        ));
    }
    if genesis_report.observer_confirmation_root != deployment_report.observer_confirmation_root {
        errors.push(format!(
            "genesis observer_confirmation_root does not match deployment observer confirmation root {}",
            deployment_report.observer_confirmation_root
        ));
    }
    if genesis_report.rollback_readiness_root != deployment_report.rollback_readiness_root {
        errors.push(format!(
            "genesis rollback_readiness_root does not match deployment rollback readiness root {}",
            deployment_report.rollback_readiness_root
        ));
    }
    if genesis_report.deployment_validity_root != deployment_report.deployment_validity_root {
        errors.push(format!(
            "genesis deployment_validity_root does not match deployment validity root {}",
            deployment_report.deployment_validity_root
        ));
    }
    if genesis_report.deployment_quorum_root != deployment_report.deployment_quorum_root {
        errors.push(format!(
            "genesis deployment_quorum_root does not match deployment quorum root {}",
            deployment_report.deployment_quorum_root
        ));
    }
    if genesis_report.bootstrap_roster_root != deployment_report.bootstrap_roster_root {
        errors.push(format!(
            "genesis bootstrap_roster_root does not match deployment bootstrap roster root {}",
            deployment_report.bootstrap_roster_root
        ));
    }
    if genesis_report.operational_evidence_root != deployment_report.operational_evidence_root {
        errors.push(format!(
            "genesis operational_evidence_root does not match deployment operational evidence root {}",
            deployment_report.operational_evidence_root
        ));
    }
    if genesis_report.validator_set_root != validator_set_report.validator_set_root {
        errors.push(format!(
            "genesis validator_set_root does not match validator set root {}",
            validator_set_report.validator_set_root
        ));
    }
    if genesis_report.validator_set_epoch != validator_set_manifest.epoch {
        errors.push(format!(
            "genesis validator_set_epoch expected {} but got {}",
            validator_set_manifest.epoch, genesis_report.validator_set_epoch
        ));
    }
    if genesis_report.operator_roster_root != validator_set_report.operator_roster_root {
        errors.push(format!(
            "genesis operator_roster_root does not match validator operator roster root {}",
            validator_set_report.operator_roster_root
        ));
    }
    if genesis_report.reward_ledger_root != validator_set_report.reward_ledger_root {
        errors.push(format!(
            "genesis reward_ledger_root does not match validator reward ledger root {}",
            validator_set_report.reward_ledger_root
        ));
    }
    if genesis_report.validator_deployment_binding_root
        != expected_validator_deployment_binding_root
    {
        errors.push(format!(
            "genesis validator_deployment_binding_root does not match validator deployment binding root {}",
            expected_validator_deployment_binding_root
        ));
    }
    if genesis_report.initial_validator_count != validator_set_report.validator_count {
        errors.push(format!(
            "genesis initial_validator_count expected {} but got {}",
            validator_set_report.validator_count, genesis_report.initial_validator_count
        ));
    }
    if genesis_report.initial_operator_count != validator_set_report.operator_count {
        errors.push(format!(
            "genesis initial_operator_count expected {} but got {}",
            validator_set_report.operator_count, genesis_report.initial_operator_count
        ));
    }
    if genesis_report.initial_region_count != validator_set_report.region_count {
        errors.push(format!(
            "genesis initial_region_count expected {} but got {}",
            validator_set_report.region_count, genesis_report.initial_region_count
        ));
    }
    if genesis_report.initial_total_power != validator_set_report.total_genesis_power {
        errors.push(format!(
            "genesis initial_total_power expected {} but got {}",
            validator_set_report.total_genesis_power, genesis_report.initial_total_power
        ));
    }
    if genesis_manifest.genesis_time_unix_ms < deployment_attestation.generated_at_unix_ms {
        errors.push(format!(
            "genesis genesis_time_unix_ms must be at or after deployment generated_at_unix_ms {}",
            deployment_attestation.generated_at_unix_ms
        ));
    }
    if genesis_manifest.genesis_time_unix_ms > deployment_attestation.expires_at_unix_ms {
        errors.push(format!(
            "genesis genesis_time_unix_ms must be at or before deployment expires_at_unix_ms {}",
            deployment_attestation.expires_at_unix_ms
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(LaunchPackageReport {
        launch_package_ready: true,
        level: "launch-package-attested",
        deployment_attestation_root: deployment_report.evidence_root,
        witness_evidence_root: deployment_report.witness_evidence_root,
        public_surface_root: deployment_report.public_surface_root,
        operator_approval_root: deployment_report.operator_approval_root,
        observer_confirmation_root: deployment_report.observer_confirmation_root,
        rollback_readiness_root: deployment_report.rollback_readiness_root,
        deployment_validity_root: deployment_report.deployment_validity_root,
        deployment_quorum_root: deployment_report.deployment_quorum_root,
        bootstrap_roster_root: deployment_report.bootstrap_roster_root,
        operational_evidence_root: deployment_report.operational_evidence_root,
        public_status_manifest_root: public_status_manifest.root,
        public_probe_root: public_probe.root,
        endpoint_url: public_status_manifest.endpoint_url,
        launch_bundle_root: deployment_attestation.launch_bundle.root,
        fee_policy_root: economics_root.to_string(),
        validator_set_root: validator_set_report.validator_set_root,
        validator_set_epoch: genesis_report.validator_set_epoch,
        operator_roster_root: genesis_report.operator_roster_root,
        reward_ledger_root: genesis_report.reward_ledger_root,
        validator_deployment_binding_root: expected_validator_deployment_binding_root,
        operator_handoff_root: expected_operator_handoff_root,
        genesis_root: genesis_report.genesis_root,
        matched_validator_count: validator_set_manifest.validators.len(),
        matched_reward_account_count: validator_set_report.reward_account_count,
        matched_operator_count: validator_set_report.operator_count,
        matched_region_count: validator_set_report.region_count,
        deployment_operator_count: deployment_attestation.operators.len(),
        deployment_observer_count: deployment_report.verified_observer_count,
        deployment_region_count: deployment_report.verified_region_count,
        bootstrap_node_count: deployment_attestation.bootstrap_nodes.len(),
        validator_count: validator_set_report.validator_count,
        total_genesis_power: validator_set_report.total_genesis_power,
        activation_height: genesis_report.activation_height,
        native_fee_token: genesis_report.native_fee_token,
        native_base_unit: genesis_report.native_base_unit,
        bridged_fee_token: genesis_report.bridged_fee_token,
    })
}

pub fn verify_launch_package_with_operator_acceptance_jsons(
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<LaunchPackageReport, AttestationError> {
    let handoff_report = verify_operator_handoff_jsons(
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let acceptance_report = verify_operator_acceptance_jsons(
        operator_acceptance_json,
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let launch_report = verify_launch_package_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        genesis_manifest_json,
    )?;
    let mut errors = Vec::new();

    if launch_report.operator_handoff_root != handoff_report.operator_handoff_root {
        errors.push(format!(
            "launch package operator_handoff_root does not match operator handoff root {}",
            handoff_report.operator_handoff_root
        ));
    }
    if acceptance_report.operator_handoff_root != handoff_report.operator_handoff_root {
        errors.push(format!(
            "operator acceptance operator_handoff_root does not match operator handoff root {}",
            handoff_report.operator_handoff_root
        ));
    }
    if acceptance_report.accepted_operator_count != launch_report.matched_operator_count {
        errors.push(format!(
            "operator acceptance accepted_operator_count expected {} but got {}",
            launch_report.matched_operator_count, acceptance_report.accepted_operator_count
        ));
    }
    if acceptance_report.accepted_validator_count != launch_report.matched_validator_count {
        errors.push(format!(
            "operator acceptance accepted_validator_count expected {} but got {}",
            launch_report.matched_validator_count, acceptance_report.accepted_validator_count
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(launch_report)
}

pub fn build_launch_package_bundle_json_pretty(
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let launch_report = verify_launch_package_with_operator_acceptance_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let acceptance_report = verify_operator_acceptance_jsons(
        operator_acceptance_json,
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let mut manifest = launch_package_bundle_manifest(
        unix_ms(),
        &launch_report,
        &acceptance_report,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    );
    manifest.root = launch_package_bundle_root(&manifest);

    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_launch_package_bundle_jsons(
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<LaunchPackageBundleReport, AttestationError> {
    let manifest = serde_json::from_str::<LaunchPackageBundleManifest>(
        launch_package_bundle_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let launch_report = verify_launch_package_with_operator_acceptance_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let acceptance_report = verify_operator_acceptance_jsons(
        operator_acceptance_json,
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let expected = launch_package_bundle_manifest(
        manifest.generated_at_unix_ms,
        &launch_report,
        &acceptance_report,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    );
    let now = unix_ms();
    let mut errors = Vec::new();

    if manifest.generated_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("generated_at_unix_ms is more than five minutes in the future".to_string());
    }
    if manifest.generated_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("generated_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(&mut errors, "chain_id", &manifest.chain_id, CHAIN_ID);
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        VERSION,
    );
    require_eq(
        &mut errors,
        "deployment_attestation_root",
        &manifest.deployment_attestation_root,
        &expected.deployment_attestation_root,
    );
    require_root(
        &mut errors,
        "deployment_attestation_sha3_256",
        &manifest.deployment_attestation_sha3_256,
        &expected.deployment_attestation_sha3_256,
    );
    require_eq(
        &mut errors,
        "public_status_manifest_root",
        &manifest.public_status_manifest_root,
        &expected.public_status_manifest_root,
    );
    require_root(
        &mut errors,
        "public_status_sha3_256",
        &manifest.public_status_sha3_256,
        &expected.public_status_sha3_256,
    );
    require_eq(
        &mut errors,
        "public_probe_root",
        &manifest.public_probe_root,
        &expected.public_probe_root,
    );
    require_root(
        &mut errors,
        "public_probe_sha3_256",
        &manifest.public_probe_sha3_256,
        &expected.public_probe_sha3_256,
    );
    require_eq(
        &mut errors,
        "validator_set_root",
        &manifest.validator_set_root,
        &expected.validator_set_root,
    );
    require_root(
        &mut errors,
        "validator_set_sha3_256",
        &manifest.validator_set_sha3_256,
        &expected.validator_set_sha3_256,
    );
    require_eq(
        &mut errors,
        "operator_handoff_root",
        &manifest.operator_handoff_root,
        &expected.operator_handoff_root,
    );
    require_root(
        &mut errors,
        "operator_handoff_sha3_256",
        &manifest.operator_handoff_sha3_256,
        &expected.operator_handoff_sha3_256,
    );
    require_eq(
        &mut errors,
        "operator_acceptance_root",
        &manifest.operator_acceptance_root,
        &expected.operator_acceptance_root,
    );
    require_root(
        &mut errors,
        "operator_acceptance_sha3_256",
        &manifest.operator_acceptance_sha3_256,
        &expected.operator_acceptance_sha3_256,
    );
    require_eq(
        &mut errors,
        "genesis_root",
        &manifest.genesis_root,
        &expected.genesis_root,
    );
    require_root(
        &mut errors,
        "genesis_manifest_sha3_256",
        &manifest.genesis_manifest_sha3_256,
        &expected.genesis_manifest_sha3_256,
    );
    require_root(
        &mut errors,
        "launch_package_root",
        &manifest.launch_package_root,
        &expected.launch_package_root,
    );
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &launch_package_bundle_root(&manifest),
    );
    if manifest.root != launch_package_bundle_root(&expected) {
        errors.push(format!(
            "root does not match expected launch package bundle root {}",
            launch_package_bundle_root(&expected)
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(LaunchPackageBundleReport {
        launch_package_bundle_ready: true,
        level: "launch-package-bundle-attested",
        launch_package_bundle_root: manifest.root,
        launch_package_root: manifest.launch_package_root,
        generated_at_unix_ms: manifest.generated_at_unix_ms,
        artifact_count: 7,
        deployment_attestation_root: manifest.deployment_attestation_root,
        public_status_manifest_root: manifest.public_status_manifest_root,
        public_probe_root: manifest.public_probe_root,
        validator_set_root: manifest.validator_set_root,
        operator_handoff_root: manifest.operator_handoff_root,
        operator_acceptance_root: manifest.operator_acceptance_root,
        genesis_root: manifest.genesis_root,
        validator_count: launch_report.validator_count,
        matched_operator_count: launch_report.matched_operator_count,
        matched_region_count: launch_report.matched_region_count,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_public_testnet_peer_manifest_json_pretty(
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let manifest = public_testnet_peer_manifest_from_jsons(
        unix_ms(),
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_public_testnet_peer_manifest_jsons(
    public_testnet_peer_manifest_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<PublicTestnetPeerManifestReport, AttestationError> {
    let manifest = serde_json::from_str::<PublicTestnetPeerManifest>(
        public_testnet_peer_manifest_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let expected = public_testnet_peer_manifest_from_jsons(
        manifest.generated_at_unix_ms,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let mut errors = Vec::new();
    let now = unix_ms();

    if manifest.generated_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("generated_at_unix_ms is more than five minutes in the future".to_string());
    }
    if manifest.generated_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("generated_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(&mut errors, "chain_id", &manifest.chain_id, CHAIN_ID);
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        VERSION,
    );
    require_eq(
        &mut errors,
        "endpoint_url",
        &manifest.endpoint_url,
        &expected.endpoint_url,
    );
    require_root(
        &mut errors,
        "launch_package_bundle_root",
        &manifest.launch_package_bundle_root,
        &expected.launch_package_bundle_root,
    );
    require_root(
        &mut errors,
        "launch_package_root",
        &manifest.launch_package_root,
        &expected.launch_package_root,
    );
    require_root(
        &mut errors,
        "deployment_attestation_root",
        &manifest.deployment_attestation_root,
        &expected.deployment_attestation_root,
    );
    require_root(
        &mut errors,
        "validator_set_root",
        &manifest.validator_set_root,
        &expected.validator_set_root,
    );
    require_root(
        &mut errors,
        "operator_handoff_root",
        &manifest.operator_handoff_root,
        &expected.operator_handoff_root,
    );
    require_root(
        &mut errors,
        "operator_acceptance_root",
        &manifest.operator_acceptance_root,
        &expected.operator_acceptance_root,
    );
    require_root(
        &mut errors,
        "genesis_root",
        &manifest.genesis_root,
        &expected.genesis_root,
    );
    if manifest.sync_peer_quorum == 0 {
        errors.push("sync_peer_quorum must be greater than zero".to_string());
    }
    let max_sync_quorum = manifest.peers.len().saturating_sub(1).max(1);
    if manifest.sync_peer_quorum > max_sync_quorum {
        errors.push(format!(
            "sync_peer_quorum must be <= {max_sync_quorum} for {} peers",
            manifest.peers.len()
        ));
    }
    if manifest.peers != expected.peers {
        errors.push(
            "peers do not match verified launch validator and bootstrap artifacts".to_string(),
        );
    }
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &public_testnet_peer_manifest_root(&manifest),
    );
    if manifest.root != public_testnet_peer_manifest_root(&expected) {
        errors.push(format!(
            "root does not match expected public testnet peer manifest root {}",
            public_testnet_peer_manifest_root(&expected)
        ));
    }

    let mut validator_ids = BTreeSet::new();
    let mut node_ids = BTreeSet::new();
    let mut operators = BTreeSet::new();
    let mut regions = BTreeSet::new();
    let mut p2p_endpoints = BTreeSet::new();
    let mut bootstrap_endpoints = BTreeSet::new();
    let mut rpc_urls = BTreeSet::new();
    let mut status_urls = BTreeSet::new();
    let mut snapshot_urls = BTreeSet::new();
    for (index, peer) in manifest.peers.iter().enumerate() {
        insert_unique(
            &mut errors,
            &mut validator_ids,
            &format!("peers[{index}].validator_id"),
            &peer.validator_id,
        );
        insert_unique(
            &mut errors,
            &mut node_ids,
            &format!("peers[{index}].node_id"),
            &peer.node_id,
        );
        operators.insert(peer.operator_id.clone());
        regions.insert(peer.region.clone());
        require_tcp_endpoint_with_port(
            &mut errors,
            &format!("peers[{index}].p2p_endpoint"),
            &peer.p2p_endpoint,
        );
        require_https_endpoint_without_path(
            &mut errors,
            &format!("peers[{index}].bootstrap_endpoint"),
            &peer.bootstrap_endpoint,
        );
        require_https_endpoint(
            &mut errors,
            &format!("peers[{index}].rpc_url"),
            &peer.rpc_url,
        );
        require_https_endpoint(
            &mut errors,
            &format!("peers[{index}].status_url"),
            &peer.status_url,
        );
        require_https_endpoint(
            &mut errors,
            &format!("peers[{index}].snapshot_url"),
            &peer.snapshot_url,
        );
        require_hex_value(
            &mut errors,
            &format!("peers[{index}].consensus_public_key"),
            &peer.consensus_public_key,
        );
        require_hex_value(
            &mut errors,
            &format!("peers[{index}].network_public_key"),
            &peer.network_public_key,
        );
        require_hex_root(
            &mut errors,
            &format!("peers[{index}].bootstrap_attestation_root"),
            &peer.bootstrap_attestation_root,
        );
        insert_unique(
            &mut errors,
            &mut p2p_endpoints,
            &format!("peers[{index}].p2p_endpoint"),
            &peer.p2p_endpoint,
        );
        insert_unique(
            &mut errors,
            &mut bootstrap_endpoints,
            &format!("peers[{index}].bootstrap_endpoint"),
            &peer.bootstrap_endpoint,
        );
        insert_unique(
            &mut errors,
            &mut rpc_urls,
            &format!("peers[{index}].rpc_url"),
            &peer.rpc_url,
        );
        insert_unique(
            &mut errors,
            &mut status_urls,
            &format!("peers[{index}].status_url"),
            &peer.status_url,
        );
        insert_unique(
            &mut errors,
            &mut snapshot_urls,
            &format!("peers[{index}].snapshot_url"),
            &peer.snapshot_url,
        );
    }
    if manifest.peers.len() < MIN_PUBLIC_TESTNET_VALIDATORS {
        errors.push(format!(
            "peers must include at least {MIN_PUBLIC_TESTNET_VALIDATORS} validators"
        ));
    }
    if operators.len() < MIN_PUBLIC_TESTNET_OPERATORS {
        errors.push(format!(
            "peers must cover at least {MIN_PUBLIC_TESTNET_OPERATORS} operators"
        ));
    }
    if regions.len() < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push(format!(
            "peers must cover at least {MIN_PUBLIC_TESTNET_REGIONS} regions"
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(PublicTestnetPeerManifestReport {
        public_testnet_peer_manifest_ready: true,
        level: "public-testnet-peer-manifest-attested",
        public_testnet_peer_manifest_root: manifest.root,
        launch_package_bundle_root: manifest.launch_package_bundle_root,
        launch_package_root: manifest.launch_package_root,
        deployment_attestation_root: manifest.deployment_attestation_root,
        validator_set_root: manifest.validator_set_root,
        operator_handoff_root: manifest.operator_handoff_root,
        operator_acceptance_root: manifest.operator_acceptance_root,
        genesis_root: manifest.genesis_root,
        endpoint_url: manifest.endpoint_url,
        sync_peer_quorum: manifest.sync_peer_quorum,
        peer_count: manifest.peers.len(),
        operator_count: operators.len(),
        region_count: regions.len(),
        rpc_peer_urls: manifest
            .peers
            .iter()
            .map(|peer| peer.rpc_url.clone())
            .collect(),
        snapshot_peer_urls: manifest
            .peers
            .iter()
            .map(|peer| peer.snapshot_url.clone())
            .collect(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_runtime_launch_binding_from_jsons(
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
    launch_package_bundle_json: &str,
    validator_id: &str,
) -> Result<runtime::RuntimeLaunchBinding, AttestationError> {
    if validator_id.trim().is_empty() {
        return Err(AttestationError::Invalid(vec![
            "validator_id must not be empty for runtime launch binding".to_string(),
        ]));
    }
    let launch_report = verify_launch_package_with_operator_acceptance_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let bundle_report = verify_launch_package_bundle_jsons(
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let deployment_attestation = serde_json::from_str::<DeploymentAttestation>(
        deployment_attestation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let validator_set_manifest = serde_json::from_str::<ValidatorSetManifest>(
        validator_set_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    if !validator_set_manifest
        .validators
        .iter()
        .any(|validator| validator.validator_id == validator_id)
    {
        return Err(AttestationError::Invalid(vec![format!(
            "validator_id {validator_id} is not admitted in validator set"
        )]));
    }
    let mut validator_reward_accounts = validator_set_manifest
        .validators
        .iter()
        .map(|validator| runtime::RuntimeValidatorRewardAccount {
            validator_id: validator.validator_id.clone(),
            operator_id: validator.operator_id.clone(),
            reward_account: validator.reward_account.clone(),
        })
        .collect::<Vec<_>>();
    validator_reward_accounts.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    let mut bridge_operator_keys = deployment_attestation
        .operators
        .iter()
        .map(|operator| runtime::RuntimeBridgeOperatorKey {
            operator_id: operator.operator_id.clone(),
            region: operator.region.clone(),
            public_key: operator.public_key.clone(),
        })
        .collect::<Vec<_>>();
    bridge_operator_keys.sort_by(|left, right| left.operator_id.cmp(&right.operator_id));
    let mut bridge_observer_keys = deployment_attestation
        .observers
        .iter()
        .map(|observer| runtime::RuntimeBridgeObserverKey {
            observer_id: observer.observer_id.clone(),
            region: observer.region.clone(),
            public_key: observer.signature.public_key.clone(),
        })
        .collect::<Vec<_>>();
    bridge_observer_keys.sort_by(|left, right| left.observer_id.cmp(&right.observer_id));

    let binding = runtime::RuntimeLaunchBinding {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        endpoint_url: launch_report.endpoint_url,
        deployment_attestation_root: launch_report.deployment_attestation_root,
        public_status_manifest_root: launch_report.public_status_manifest_root,
        public_probe_root: launch_report.public_probe_root,
        fee_policy_root: launch_report.fee_policy_root,
        validator_set_root: launch_report.validator_set_root,
        operator_handoff_root: launch_report.operator_handoff_root,
        operator_acceptance_root: bundle_report.operator_acceptance_root,
        genesis_root: launch_report.genesis_root,
        launch_package_root: bundle_report.launch_package_root,
        launch_package_bundle_root: bundle_report.launch_package_bundle_root,
        activation_height: launch_report.activation_height,
        validator_count: launch_report.validator_count,
        operator_count: launch_report.matched_operator_count,
        region_count: launch_report.matched_region_count,
        validator_reward_accounts,
        bridge_operator_keys,
        bridge_observer_keys,
    };
    let mut validation_config = runtime::RuntimeConfig::public_testnet_default();
    validation_config.validator_id = validator_id.to_string();
    binding
        .validate_against_config(&validation_config)
        .map_err(|error| AttestationError::Invalid(vec![error]))?;
    Ok(binding)
}

#[allow(clippy::too_many_arguments)]
pub fn build_validator_activation_json_pretty(
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let bundle_report = verify_launch_package_bundle_jsons(
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let acceptance_report = verify_operator_acceptance_jsons(
        operator_acceptance_json,
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let validator_set = verified_validator_set_manifest(validator_set_json)?;
    let mut manifest = validator_activation_manifest(
        &bundle_report,
        &acceptance_report,
        &validator_set,
        unix_ms(),
    );
    manifest.root = validator_activation_manifest_root(&manifest);

    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_validator_activation_jsons(
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<ValidatorActivationReport, AttestationError> {
    let manifest = serde_json::from_str::<ValidatorActivationManifest>(
        validator_activation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let bundle_report = verify_launch_package_bundle_jsons(
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let acceptance_report = verify_operator_acceptance_jsons(
        operator_acceptance_json,
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let validator_set = verified_validator_set_manifest(validator_set_json)?;
    let mut expected = validator_activation_manifest(
        &bundle_report,
        &acceptance_report,
        &validator_set,
        manifest.activated_at_unix_ms,
    );
    for expected_entry in &mut expected.entries {
        if let Some(entry) = manifest.entries.iter().find(|entry| {
            entry.operator_id == expected_entry.operator_id
                && entry.validator_id == expected_entry.validator_id
                && entry.node_id == expected_entry.node_id
        }) {
            expected_entry.signature = entry.signature.clone();
        }
    }
    expected.root = validator_activation_manifest_root(&expected);
    let now = unix_ms();
    let mut errors = Vec::new();

    if manifest.activated_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("activated_at_unix_ms is more than five minutes in the future".to_string());
    }
    if manifest.activated_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("activated_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(&mut errors, "chain_id", &manifest.chain_id, CHAIN_ID);
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        VERSION,
    );
    require_root(
        &mut errors,
        "launch_package_bundle_root",
        &manifest.launch_package_bundle_root,
        &bundle_report.launch_package_bundle_root,
    );
    require_root(
        &mut errors,
        "launch_package_root",
        &manifest.launch_package_root,
        &bundle_report.launch_package_root,
    );
    require_root(
        &mut errors,
        "validator_set_root",
        &manifest.validator_set_root,
        &bundle_report.validator_set_root,
    );
    require_root(
        &mut errors,
        "operator_acceptance_root",
        &manifest.operator_acceptance_root,
        &acceptance_report.operator_acceptance_root,
    );
    if manifest.entries != expected.entries {
        errors.push(
            "validator activation entries do not match verified bundle and validator set"
                .to_string(),
        );
    }
    for (index, entry) in manifest.entries.iter().enumerate() {
        if !entry.activated {
            errors.push(format!("entries[{index}].activated must be true"));
        }
        require_root(
            &mut errors,
            &format!("entries[{index}].activation_root"),
            &entry.activation_root,
            &validator_activation_entry_root(
                entry,
                &manifest.launch_package_bundle_root,
                &manifest.operator_acceptance_root,
                manifest.activated_at_unix_ms,
            ),
        );
        verify_signature_material(
            &mut errors,
            &format!("entries[{index}].signature"),
            &entry.signature,
            "ed25519-testnet-validator-activation",
            &entry.consensus_public_key,
            &validator_activation_signature_root(entry),
        );
    }
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &validator_activation_manifest_root(&manifest),
    );
    if manifest.root != expected.root {
        errors.push(format!(
            "root does not match expected validator activation root {}",
            expected.root
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let activated_operators = manifest
        .entries
        .iter()
        .map(|entry| entry.operator_id.as_str())
        .collect::<BTreeSet<_>>();

    Ok(ValidatorActivationReport {
        validator_activation_ready: true,
        level: "validator-activation-attested",
        validator_activation_root: manifest.root,
        launch_package_bundle_root: manifest.launch_package_bundle_root,
        launch_package_root: manifest.launch_package_root,
        validator_set_root: manifest.validator_set_root,
        operator_acceptance_root: manifest.operator_acceptance_root,
        activated_validator_count: manifest.entries.len(),
        activated_operator_count: activated_operators.len(),
        activated_at_unix_ms: manifest.activated_at_unix_ms,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_validator_join_receipt_json_pretty(
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let activation_report = verify_validator_activation_jsons(
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let activation = serde_json::from_str::<ValidatorActivationManifest>(
        validator_activation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let genesis_report = verify_genesis_manifest_json(genesis_manifest_json)?;
    let mut receipt = validator_join_receipt(
        &activation,
        &activation_report,
        genesis_report.activation_height,
        unix_ms(),
    );
    receipt.root = validator_join_receipt_root(&receipt);

    serde_json::to_string_pretty(&receipt)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_validator_join_receipt_jsons(
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<ValidatorJoinReport, AttestationError> {
    let receipt = serde_json::from_str::<ValidatorJoinReceipt>(
        validator_join_receipt_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let activation_report = verify_validator_activation_jsons(
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let activation = serde_json::from_str::<ValidatorActivationManifest>(
        validator_activation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let genesis_report = verify_genesis_manifest_json(genesis_manifest_json)?;
    let now = unix_ms();
    let mut errors = Vec::new();

    if receipt.joined_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("joined_at_unix_ms is more than five minutes in the future".to_string());
    }
    if receipt.joined_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("joined_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(&mut errors, "chain_id", &receipt.chain_id, CHAIN_ID);
    require_eq(
        &mut errors,
        "runtime_version",
        &receipt.runtime_version,
        VERSION,
    );
    require_root(
        &mut errors,
        "validator_activation_root",
        &receipt.validator_activation_root,
        &activation_report.validator_activation_root,
    );
    require_root(
        &mut errors,
        "launch_package_bundle_root",
        &receipt.launch_package_bundle_root,
        &activation_report.launch_package_bundle_root,
    );
    require_root(
        &mut errors,
        "launch_package_root",
        &receipt.launch_package_root,
        &activation_report.launch_package_root,
    );
    require_root(
        &mut errors,
        "validator_set_root",
        &receipt.validator_set_root,
        &activation_report.validator_set_root,
    );
    if receipt.activation_height != genesis_report.activation_height {
        errors.push(format!(
            "activation_height expected {} but got {}",
            genesis_report.activation_height, receipt.activation_height
        ));
    }
    verify_validator_join_entries(
        &mut errors,
        &receipt,
        &activation,
        genesis_report.activation_height,
    );
    require_root(
        &mut errors,
        "root",
        &receipt.root,
        &validator_join_receipt_root(&receipt),
    );

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let joined_operators = receipt
        .entries
        .iter()
        .map(|entry| entry.operator_id.as_str())
        .collect::<BTreeSet<_>>();
    let min_observed_block_height = receipt
        .entries
        .iter()
        .map(|entry| entry.observed_block_height)
        .min()
        .unwrap_or_default();
    let min_peer_count = receipt
        .entries
        .iter()
        .map(|entry| entry.peer_count)
        .min()
        .unwrap_or_default();

    Ok(ValidatorJoinReport {
        validator_join_ready: true,
        level: "validator-join-attested",
        validator_join_root: receipt.root,
        validator_activation_root: receipt.validator_activation_root,
        launch_package_bundle_root: receipt.launch_package_bundle_root,
        launch_package_root: receipt.launch_package_root,
        validator_set_root: receipt.validator_set_root,
        joined_validator_count: receipt.entries.len(),
        joined_operator_count: joined_operators.len(),
        activation_height: receipt.activation_height,
        min_observed_block_height,
        min_peer_count,
        joined_at_unix_ms: receipt.joined_at_unix_ms,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_operator_join_confirmation_json_pretty(
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let join_report = verify_validator_join_receipt_jsons(
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let acceptance_report = verify_operator_acceptance_jsons(
        operator_acceptance_json,
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let receipt = serde_json::from_str::<ValidatorJoinReceipt>(
        validator_join_receipt_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let acceptance = serde_json::from_str::<OperatorAcceptanceManifest>(
        operator_acceptance_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let mut manifest = operator_join_confirmation_manifest(
        &receipt,
        &join_report,
        &acceptance,
        &acceptance_report,
        &deployment_attestation,
        unix_ms(),
    );
    manifest.root = operator_join_confirmation_manifest_root(&manifest);

    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_operator_join_confirmation_jsons(
    operator_join_confirmation_json: &str,
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<OperatorJoinConfirmationReport, AttestationError> {
    let manifest = serde_json::from_str::<OperatorJoinConfirmationManifest>(
        operator_join_confirmation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let join_report = verify_validator_join_receipt_jsons(
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let acceptance_report = verify_operator_acceptance_jsons(
        operator_acceptance_json,
        operator_handoff_json,
        deployment_attestation_json,
        validator_set_json,
    )?;
    let receipt = serde_json::from_str::<ValidatorJoinReceipt>(
        validator_join_receipt_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let acceptance = serde_json::from_str::<OperatorAcceptanceManifest>(
        operator_acceptance_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let now = unix_ms();
    let mut expected = operator_join_confirmation_manifest(
        &receipt,
        &join_report,
        &acceptance,
        &acceptance_report,
        &deployment_attestation,
        manifest.confirmed_at_unix_ms,
    );
    for expected_entry in &mut expected.entries {
        if let Some(entry) = manifest.entries.iter().find(|entry| {
            entry.operator_id == expected_entry.operator_id
                && entry.validator_id == expected_entry.validator_id
                && entry.node_id == expected_entry.node_id
        }) {
            expected_entry.signature = entry.signature.clone();
        }
    }
    expected.root = operator_join_confirmation_manifest_root(&expected);
    let mut errors = Vec::new();

    if manifest.confirmed_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("confirmed_at_unix_ms is more than five minutes in the future".to_string());
    }
    if manifest.confirmed_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("confirmed_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(
        &mut errors,
        "chain_id",
        &manifest.chain_id,
        &expected.chain_id,
    );
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        &expected.runtime_version,
    );
    require_root(
        &mut errors,
        "validator_join_root",
        &manifest.validator_join_root,
        &expected.validator_join_root,
    );
    require_root(
        &mut errors,
        "validator_activation_root",
        &manifest.validator_activation_root,
        &expected.validator_activation_root,
    );
    require_root(
        &mut errors,
        "launch_package_bundle_root",
        &manifest.launch_package_bundle_root,
        &expected.launch_package_bundle_root,
    );
    require_root(
        &mut errors,
        "operator_acceptance_root",
        &manifest.operator_acceptance_root,
        &expected.operator_acceptance_root,
    );
    if manifest.entries != expected.entries {
        errors.push(
            "operator join confirmation entries do not match verified validator join and operator acceptance"
                .to_string(),
        );
    }
    for (index, entry) in manifest.entries.iter().enumerate() {
        if !entry.confirmed {
            errors.push(format!("entries[{index}].confirmed must be true"));
        }
        require_root(
            &mut errors,
            &format!("entries[{index}].confirmation_root"),
            &entry.confirmation_root,
            &operator_join_confirmation_entry_root(
                entry,
                &manifest.validator_join_root,
                &manifest.validator_activation_root,
                &manifest.launch_package_bundle_root,
                &manifest.operator_acceptance_root,
                manifest.confirmed_at_unix_ms,
            ),
        );
        verify_signature_material(
            &mut errors,
            &format!("entries[{index}].signature"),
            &entry.signature,
            "ed25519-testnet-operator-join-confirmation",
            &entry.operator_public_key,
            &operator_join_confirmation_signature_root(entry),
        );
    }
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &operator_join_confirmation_manifest_root(&manifest),
    );
    if manifest.root != expected.root {
        errors.push(format!(
            "operator join confirmation root does not match expected root {}",
            expected.root
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let confirmed_operators = manifest
        .entries
        .iter()
        .map(|entry| entry.operator_id.as_str())
        .collect::<BTreeSet<_>>();
    let confirmed_validators = manifest
        .entries
        .iter()
        .map(|entry| entry.validator_id.as_str())
        .collect::<BTreeSet<_>>();

    Ok(OperatorJoinConfirmationReport {
        operator_join_confirmation_ready: true,
        level: "operator-join-confirmed",
        operator_join_confirmation_root: manifest.root,
        validator_join_root: manifest.validator_join_root,
        validator_activation_root: manifest.validator_activation_root,
        launch_package_bundle_root: manifest.launch_package_bundle_root,
        operator_acceptance_root: manifest.operator_acceptance_root,
        confirmed_operator_count: confirmed_operators.len(),
        confirmed_validator_count: confirmed_validators.len(),
        confirmed_at_unix_ms: manifest.confirmed_at_unix_ms,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_public_observer_confirmation_json_pretty(
    operator_join_confirmation_json: &str,
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let join_confirmation_report = verify_operator_join_confirmation_jsons(
        operator_join_confirmation_json,
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let (public_status_report, public_probe_report) = verify_public_surface_jsons_for_deployment(
        public_status_json,
        public_probe_json,
        &deployment_attestation,
    )?;
    let manifest = public_observer_confirmation_manifest(
        &deployment_attestation,
        &join_confirmation_report,
        &public_status_report,
        &public_probe_report,
        unix_ms(),
    );

    serde_json::to_string_pretty(&manifest)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_public_observer_confirmation_jsons(
    public_observer_confirmation_json: &str,
    operator_join_confirmation_json: &str,
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<PublicObserverConfirmationReport, AttestationError> {
    let manifest = serde_json::from_str::<PublicObserverConfirmationManifest>(
        public_observer_confirmation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let join_confirmation_report = verify_operator_join_confirmation_jsons(
        operator_join_confirmation_json,
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let (public_status_report, public_probe_report) = verify_public_surface_jsons_for_deployment(
        public_status_json,
        public_probe_json,
        &deployment_attestation,
    )?;
    let now = unix_ms();
    let mut expected = public_observer_confirmation_manifest(
        &deployment_attestation,
        &join_confirmation_report,
        &public_status_report,
        &public_probe_report,
        manifest.observed_at_unix_ms,
    );
    for expected_entry in &mut expected.entries {
        if let Some(entry) = manifest.entries.iter().find(|entry| {
            entry.observer_id == expected_entry.observer_id && entry.region == expected_entry.region
        }) {
            expected_entry.signature = entry.signature.clone();
        }
    }
    expected.root = public_observer_confirmation_manifest_root(&expected);
    let observer_keys_by_id_region = deployment_attestation
        .observers
        .iter()
        .map(|observer| {
            (
                (observer.observer_id.as_str(), observer.region.as_str()),
                observer.signature.public_key.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut errors = Vec::new();

    if manifest.observed_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("observed_at_unix_ms is more than five minutes in the future".to_string());
    }
    if manifest.observed_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("observed_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(
        &mut errors,
        "chain_id",
        &manifest.chain_id,
        &expected.chain_id,
    );
    require_eq(
        &mut errors,
        "runtime_version",
        &manifest.runtime_version,
        &expected.runtime_version,
    );
    require_root(
        &mut errors,
        "operator_join_confirmation_root",
        &manifest.operator_join_confirmation_root,
        &expected.operator_join_confirmation_root,
    );
    require_root(
        &mut errors,
        "validator_join_root",
        &manifest.validator_join_root,
        &expected.validator_join_root,
    );
    require_root(
        &mut errors,
        "public_status_manifest_root",
        &manifest.public_status_manifest_root,
        &expected.public_status_manifest_root,
    );
    require_root(
        &mut errors,
        "public_probe_root",
        &manifest.public_probe_root,
        &expected.public_probe_root,
    );
    require_eq(
        &mut errors,
        "endpoint_url",
        &manifest.endpoint_url,
        &expected.endpoint_url,
    );
    if manifest.entries != expected.entries {
        errors.push(
            "public observer confirmation entries do not match verified deployment observers and public surface"
                .to_string(),
        );
    }
    for (index, entry) in manifest.entries.iter().enumerate() {
        require_eq(
            &mut errors,
            &format!("entries[{index}].observed_endpoint"),
            &entry.observed_endpoint,
            &manifest.endpoint_url,
        );
        require_root(
            &mut errors,
            &format!("entries[{index}].observed_public_status_root"),
            &entry.observed_public_status_root,
            &manifest.public_status_manifest_root,
        );
        require_root(
            &mut errors,
            &format!("entries[{index}].observed_public_probe_root"),
            &entry.observed_public_probe_root,
            &manifest.public_probe_root,
        );
        require_root(
            &mut errors,
            &format!("entries[{index}].operator_join_confirmation_root"),
            &entry.operator_join_confirmation_root,
            &manifest.operator_join_confirmation_root,
        );
        require_root(
            &mut errors,
            &format!("entries[{index}].observation_root"),
            &entry.observation_root,
            &public_observer_confirmation_entry_root(entry, manifest.observed_at_unix_ms),
        );
        verify_signature_material(
            &mut errors,
            &format!("entries[{index}].signature"),
            &entry.signature,
            "ed25519-testnet-public-observer-confirmation",
            observer_keys_by_id_region
                .get(&(entry.observer_id.as_str(), entry.region.as_str()))
                .copied()
                .unwrap_or_default(),
            &public_observer_confirmation_signature_root(entry),
        );
    }
    require_root(
        &mut errors,
        "root",
        &manifest.root,
        &public_observer_confirmation_manifest_root(&manifest),
    );
    if manifest.root != expected.root {
        errors.push(format!(
            "public observer confirmation root does not match expected root {}",
            expected.root
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let confirmed_observers = manifest
        .entries
        .iter()
        .map(|entry| entry.observer_id.as_str())
        .collect::<BTreeSet<_>>();
    let confirmed_regions = manifest
        .entries
        .iter()
        .map(|entry| entry.region.as_str())
        .collect::<BTreeSet<_>>();

    Ok(PublicObserverConfirmationReport {
        public_observer_confirmation_ready: true,
        level: "public-observer-confirmed",
        public_observer_confirmation_root: manifest.root,
        operator_join_confirmation_root: manifest.operator_join_confirmation_root,
        validator_join_root: manifest.validator_join_root,
        public_status_manifest_root: manifest.public_status_manifest_root,
        public_probe_root: manifest.public_probe_root,
        endpoint_url: manifest.endpoint_url,
        confirmed_observer_count: confirmed_observers.len(),
        confirmed_region_count: confirmed_regions.len(),
        observed_at_unix_ms: manifest.observed_at_unix_ms,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_public_testnet_launch_certificate_json_pretty(
    public_observer_confirmation_json: &str,
    runtime_surface_evidence_json: &str,
    operator_join_confirmation_json: &str,
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<String, AttestationError> {
    let reports = verified_launch_certificate_reports(
        public_observer_confirmation_json,
        runtime_surface_evidence_json,
        operator_join_confirmation_json,
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let certificate = public_testnet_launch_certificate(&reports, unix_ms());

    serde_json::to_string_pretty(&certificate)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_public_testnet_launch_certificate_jsons(
    public_testnet_launch_certificate_json: &str,
    public_observer_confirmation_json: &str,
    runtime_surface_evidence_json: &str,
    operator_join_confirmation_json: &str,
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<PublicTestnetLaunchCertificateReport, AttestationError> {
    let certificate = serde_json::from_str::<PublicTestnetLaunchCertificate>(
        public_testnet_launch_certificate_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let reports = verified_launch_certificate_reports(
        public_observer_confirmation_json,
        runtime_surface_evidence_json,
        operator_join_confirmation_json,
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let expected = public_testnet_launch_certificate(&reports, certificate.certified_at_unix_ms);
    let now = unix_ms();
    let mut errors = Vec::new();

    if certificate.certified_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("certified_at_unix_ms is more than five minutes in the future".to_string());
    }
    if certificate.certified_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("certified_at_unix_ms is older than 24 hours".to_string());
    }
    require_eq(
        &mut errors,
        "chain_id",
        &certificate.chain_id,
        &expected.chain_id,
    );
    require_eq(
        &mut errors,
        "runtime_version",
        &certificate.runtime_version,
        &expected.runtime_version,
    );
    require_root(
        &mut errors,
        "launch_package_bundle_root",
        &certificate.launch_package_bundle_root,
        &expected.launch_package_bundle_root,
    );
    require_root(
        &mut errors,
        "launch_package_root",
        &certificate.launch_package_root,
        &expected.launch_package_root,
    );
    require_root(
        &mut errors,
        "fee_policy_root",
        &certificate.fee_policy_root,
        &expected.fee_policy_root,
    );
    require_root(
        &mut errors,
        "validator_activation_root",
        &certificate.validator_activation_root,
        &expected.validator_activation_root,
    );
    require_root(
        &mut errors,
        "validator_join_root",
        &certificate.validator_join_root,
        &expected.validator_join_root,
    );
    require_root(
        &mut errors,
        "operator_join_confirmation_root",
        &certificate.operator_join_confirmation_root,
        &expected.operator_join_confirmation_root,
    );
    require_root(
        &mut errors,
        "public_observer_confirmation_root",
        &certificate.public_observer_confirmation_root,
        &expected.public_observer_confirmation_root,
    );
    require_root(
        &mut errors,
        "public_status_manifest_root",
        &certificate.public_status_manifest_root,
        &expected.public_status_manifest_root,
    );
    require_root(
        &mut errors,
        "public_probe_root",
        &certificate.public_probe_root,
        &expected.public_probe_root,
    );
    require_root(
        &mut errors,
        "runtime_surface_root",
        &certificate.runtime_surface_root,
        &expected.runtime_surface_root,
    );
    require_root(
        &mut errors,
        "validator_set_root",
        &certificate.validator_set_root,
        &expected.validator_set_root,
    );
    require_root(
        &mut errors,
        "genesis_root",
        &certificate.genesis_root,
        &expected.genesis_root,
    );
    require_eq(
        &mut errors,
        "endpoint_url",
        &certificate.endpoint_url,
        &expected.endpoint_url,
    );
    if certificate.validator_count != expected.validator_count {
        errors.push(format!(
            "validator_count expected {} but got {}",
            expected.validator_count, certificate.validator_count
        ));
    }
    if certificate.operator_count != expected.operator_count {
        errors.push(format!(
            "operator_count expected {} but got {}",
            expected.operator_count, certificate.operator_count
        ));
    }
    if certificate.observer_count != expected.observer_count {
        errors.push(format!(
            "observer_count expected {} but got {}",
            expected.observer_count, certificate.observer_count
        ));
    }
    if certificate.region_count != expected.region_count {
        errors.push(format!(
            "region_count expected {} but got {}",
            expected.region_count, certificate.region_count
        ));
    }
    require_root(
        &mut errors,
        "root",
        &certificate.root,
        &public_testnet_launch_certificate_root(&certificate),
    );
    if certificate.root != expected.root {
        errors.push(format!(
            "public testnet launch certificate root does not match expected root {}",
            expected.root
        ));
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(PublicTestnetLaunchCertificateReport {
        public_testnet_launch_certificate_ready: true,
        level: "public-testnet-launch-candidate-certified",
        public_testnet_launch_certificate_root: certificate.root,
        launch_package_bundle_root: certificate.launch_package_bundle_root,
        launch_package_root: certificate.launch_package_root,
        fee_policy_root: certificate.fee_policy_root,
        validator_activation_root: certificate.validator_activation_root,
        validator_join_root: certificate.validator_join_root,
        operator_join_confirmation_root: certificate.operator_join_confirmation_root,
        public_observer_confirmation_root: certificate.public_observer_confirmation_root,
        public_status_manifest_root: certificate.public_status_manifest_root,
        public_probe_root: certificate.public_probe_root,
        runtime_surface_root: certificate.runtime_surface_root,
        validator_set_root: certificate.validator_set_root,
        genesis_root: certificate.genesis_root,
        endpoint_url: certificate.endpoint_url,
        validator_count: certificate.validator_count,
        operator_count: certificate.operator_count,
        observer_count: certificate.observer_count,
        region_count: certificate.region_count,
        certified_at_unix_ms: certificate.certified_at_unix_ms,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_public_testnet_launch_readiness_jsons(
    public_testnet_launch_certificate_json: &str,
    public_observer_confirmation_json: &str,
    runtime_surface_evidence_json: &str,
    live_rpc_devnet_rehearsal_json: &str,
    live_rpc_devnet_runtime_surface_evidence_json: &str,
    operator_join_confirmation_json: &str,
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<PublicTestnetLaunchReadinessReport, AttestationError> {
    let certificate = verify_public_testnet_launch_certificate_jsons(
        public_testnet_launch_certificate_json,
        public_observer_confirmation_json,
        runtime_surface_evidence_json,
        operator_join_confirmation_json,
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let runtime_surface = verify_runtime_surface_evidence_json(runtime_surface_evidence_json)?;
    let live_rehearsal = verify_live_rpc_devnet_rehearsal_json(live_rpc_devnet_rehearsal_json)?;
    let live_runtime_surface =
        verify_runtime_surface_evidence_json(live_rpc_devnet_runtime_surface_evidence_json)?;
    let runtime_surface_evidence = serde_json::from_str::<RuntimeSurfaceEvidence>(
        runtime_surface_evidence_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let deployment = verify_deployment_attestation_json(deployment_attestation_json)?;
    let deployment_attestation = serde_json::from_str::<DeploymentAttestation>(
        deployment_attestation_json.trim_start_matches('\u{feff}'),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();

    if !certificate.public_testnet_launch_certificate_ready {
        errors.push("public testnet launch certificate is not ready".to_string());
    }
    if !deployment.public_launch_ready {
        errors.push("deployment attestation is not public-launch ready".to_string());
    }
    require_eq(
        &mut errors,
        "deployment.endpoint_url",
        &certificate.endpoint_url,
        &deployment.endpoint_url,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_rehearsal.endpoint_url",
        &live_rehearsal.endpoint_url,
        &certificate.endpoint_url,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_rehearsal.launch_package_bundle_root",
        &live_rehearsal.launch_package_bundle_root,
        &certificate.launch_package_bundle_root,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.capture_mode",
        &live_runtime_surface.capture_mode,
        RUNTIME_SURFACE_CAPTURE_MODE_LOOPBACK_DEVNET,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.runtime_surface_root",
        &live_runtime_surface.runtime_surface_root,
        &live_rehearsal.runtime_surface_root,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.endpoint_url",
        &live_runtime_surface.endpoint_url,
        &certificate.endpoint_url,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.launch_package_bundle_root",
        &live_runtime_surface.launch_package_bundle_root,
        &certificate.launch_package_bundle_root,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.launch_package_root",
        &live_runtime_surface.launch_package_root,
        &certificate.launch_package_root,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.fee_policy_root",
        &live_runtime_surface.fee_policy_root,
        &certificate.fee_policy_root,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.validator_set_root",
        &live_runtime_surface.validator_set_root,
        &certificate.validator_set_root,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_runtime_surface.genesis_root",
        &live_runtime_surface.genesis_root,
        &certificate.genesis_root,
    );
    if live_runtime_surface.latest_height != live_rehearsal.latest_height {
        errors.push(format!(
            "live_rpc_devnet_runtime_surface.latest_height expected {} but got {}",
            live_rehearsal.latest_height, live_runtime_surface.latest_height
        ));
    }
    if live_runtime_surface.total_nxmr_fees_units != live_rehearsal.total_nxmr_fees_units {
        errors.push(format!(
            "live_rpc_devnet_runtime_surface.total_nxmr_fees_units expected {} but got {}",
            live_rehearsal.total_nxmr_fees_units, live_runtime_surface.total_nxmr_fees_units
        ));
    }
    if live_runtime_surface.buyback_pool_nebulai != live_rehearsal.buyback_pool_nebulai {
        errors.push(format!(
            "live_rpc_devnet_runtime_surface.buyback_pool_nebulai expected {} but got {}",
            live_rehearsal.buyback_pool_nebulai, live_runtime_surface.buyback_pool_nebulai
        ));
    }
    if live_runtime_surface.validator_reward_nebulai != live_rehearsal.validator_reward_nebulai {
        errors.push(format!(
            "live_rpc_devnet_runtime_surface.validator_reward_nebulai expected {} but got {}",
            live_rehearsal.validator_reward_nebulai, live_runtime_surface.validator_reward_nebulai
        ));
    }
    require_eq(
        &mut errors,
        "runtime_surface.capture_mode",
        &runtime_surface.capture_mode,
        RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT,
    );
    match runtime_surface.tls_observation.as_ref() {
        Some(observed)
            if deployment_attestation
                .public_endpoint
                .tls_pins
                .iter()
                .any(|pin| tls_endpoint_pins_match(observed, pin)) => {}
        Some(_) => errors.push(
            "runtime_surface.tls_observation does not match deployment public_endpoint.tls_pins"
                .to_string(),
        ),
        None => errors.push(
            "runtime_surface.tls_observation is required for public launch readiness".to_string(),
        ),
    }
    if certificate.operator_count < MIN_PUBLIC_TESTNET_OPERATORS {
        errors.push(format!(
            "operator_count must be at least {MIN_PUBLIC_TESTNET_OPERATORS}"
        ));
    }
    if certificate.observer_count < MIN_PUBLIC_TESTNET_OBSERVERS {
        errors.push(format!(
            "observer_count must be at least {MIN_PUBLIC_TESTNET_OBSERVERS}"
        ));
    }
    if certificate.region_count < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push(format!(
            "region_count must be at least {MIN_PUBLIC_TESTNET_REGIONS}"
        ));
    }
    let runtime_surface_snapshot = serde_json::from_value::<runtime::RuntimeSnapshot>(
        runtime_surface_evidence.snapshot.clone(),
    )
    .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    if let Some(economics) = require_runtime_surface_snapshot_economics(
        &mut errors,
        &runtime_surface_evidence.status,
        &runtime_surface_snapshot,
    ) {
        require_public_launch_economics_trial(&mut errors, &economics);
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let mut report = PublicTestnetLaunchReadinessReport {
        public_launch_ready: true,
        level: "public-testnet-launch-ready",
        blocking_gaps: Vec::new(),
        satisfied_attestation:
            "operator-signed public endpoint, runtime surface, observer, rollback, and launch certificate evidence",
        public_launch_readiness_root: String::new(),
        public_testnet_launch_certificate_root: certificate.public_testnet_launch_certificate_root,
        deployment_attestation_root: deployment.evidence_root,
        launch_package_bundle_root: certificate.launch_package_bundle_root,
        launch_package_root: certificate.launch_package_root,
        fee_policy_root: certificate.fee_policy_root,
        validator_activation_root: certificate.validator_activation_root,
        validator_join_root: certificate.validator_join_root,
        operator_join_confirmation_root: certificate.operator_join_confirmation_root,
        public_observer_confirmation_root: certificate.public_observer_confirmation_root,
        public_status_manifest_root: certificate.public_status_manifest_root,
        public_probe_root: certificate.public_probe_root,
        runtime_surface_root: certificate.runtime_surface_root,
        runtime_surface_capture_mode: runtime_surface.capture_mode,
        live_rpc_devnet_rehearsal_root: live_rehearsal.rehearsal_root,
        live_rpc_devnet_runtime_surface_root: live_runtime_surface.runtime_surface_root,
        validator_set_root: certificate.validator_set_root,
        genesis_root: certificate.genesis_root,
        endpoint_url: certificate.endpoint_url,
        validator_count: certificate.validator_count,
        operator_count: certificate.operator_count,
        observer_count: certificate.observer_count,
        region_count: certificate.region_count,
        certified_at_unix_ms: certificate.certified_at_unix_ms,
        generated_at_unix_ms: unix_ms(),
    };
    report.public_launch_readiness_root = public_testnet_launch_readiness_root(&report);

    Ok(report)
}

pub fn public_testnet_launch_readiness_rejection_report(
    errors: &[String],
) -> PublicTestnetLaunchReadinessRejectionReport {
    let blocking_gaps = if errors.is_empty() {
        vec!["public-testnet-launch-readiness-unknown-blocker".to_string()]
    } else {
        errors.to_vec()
    };
    let mut report = PublicTestnetLaunchReadinessRejectionReport {
        public_launch_ready: false,
        level: "public-testnet-launch-readiness-rejected",
        blocking_gaps,
        errors: errors.to_vec(),
        required_attestation:
            "operator-signed public endpoint, runtime surface, observer, rollback, and launch certificate evidence",
        public_launch_readiness_rejection_root: String::new(),
        generated_at_unix_ms: unix_ms(),
    };
    report.public_launch_readiness_rejection_root =
        public_testnet_launch_readiness_rejection_root(&report);
    report
}

pub fn verify_live_rpc_devnet_rehearsal_json(
    input: &str,
) -> Result<LiveRpcDevnetRehearsalReport, AttestationError> {
    let report =
        serde_json::from_str::<LiveRpcDevnetRehearsalReport>(input.trim_start_matches('\u{feff}'))
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let expected_root = live_rpc_devnet_rehearsal_root(&report);

    if !report.live_rpc_devnet_rehearsed {
        errors.push("live_rpc_devnet_rehearsed must be true".to_string());
    }
    require_eq(
        &mut errors,
        "live_rpc_devnet_rehearsal.level",
        &report.level,
        "live-rpc-devnet-rehearsal-ready",
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_rehearsal.chain_id",
        &report.chain_id,
        CHAIN_ID,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_rehearsal.runtime_version",
        &report.runtime_version,
        VERSION,
    );
    if report.public_launch_ready {
        errors.push("live_rpc_devnet_rehearsal.public_launch_ready must be false".to_string());
    }
    require_eq(
        &mut errors,
        "live_rpc_devnet_rehearsal.public_launch_blocker",
        &report.public_launch_blocker,
        PUBLIC_LAUNCH_BLOCKER,
    );
    if report.block_millis >= 1_000 || !report.sub_second_blocks {
        errors.push("live_rpc_devnet_rehearsal must prove sub-second blocks".to_string());
    }
    if report.produced_block_count < 2 {
        errors
            .push("live_rpc_devnet_rehearsal.produced_block_count must be at least 2".to_string());
    }
    if report.latest_height != report.produced_block_count {
        errors.push(format!(
            "live_rpc_devnet_rehearsal.latest_height expected {} but got {}",
            report.produced_block_count, report.latest_height
        ));
    }
    if !report.runtime_surface_ready {
        errors.push("live_rpc_devnet_rehearsal.runtime_surface_ready must be true".to_string());
    }
    require_hex_root(
        &mut errors,
        "live_rpc_devnet_rehearsal.runtime_surface_root",
        &report.runtime_surface_root,
    );
    if !report.sync_quorum_met {
        errors.push("live_rpc_devnet_rehearsal.sync_quorum_met must be true".to_string());
    }
    if report.sync_successful_peer_count < 1 {
        errors.push(
            "live_rpc_devnet_rehearsal.sync_successful_peer_count must be at least 1".to_string(),
        );
    }
    if report.sync_import_count < 1 {
        errors.push("live_rpc_devnet_rehearsal.sync_import_count must be at least 1".to_string());
    }
    if report.sync_last_import_height != report.latest_height {
        errors.push(format!(
            "live_rpc_devnet_rehearsal.sync_last_import_height expected {} but got {}",
            report.latest_height, report.sync_last_import_height
        ));
    }
    if report.sync_quorum_height != report.latest_height {
        errors.push(format!(
            "live_rpc_devnet_rehearsal.sync_quorum_height expected {} but got {}",
            report.latest_height, report.sync_quorum_height
        ));
    }
    if report.bridge_deposit_count != 1 {
        errors.push(format!(
            "live_rpc_devnet_rehearsal.bridge_deposit_count expected 1 but got {}",
            report.bridge_deposit_count
        ));
    }
    if report.withdrawal_request_count != 1 {
        errors.push(format!(
            "live_rpc_devnet_rehearsal.withdrawal_request_count expected 1 but got {}",
            report.withdrawal_request_count
        ));
    }
    if report.finalized_withdrawal_count != 1 {
        errors.push(format!(
            "live_rpc_devnet_rehearsal.finalized_withdrawal_count expected 1 but got {}",
            report.finalized_withdrawal_count
        ));
    }
    if !report.bridge_custody_reconciled || report.nxmr_custody_deficit_units != 0 {
        errors.push("live_rpc_devnet_rehearsal must prove reconciled nXMR custody".to_string());
    }
    if report.total_nxmr_fees_units != 1_000
        || report.buyback_pool_nebulai != 1_000
        || report.validator_reward_nebulai != 1_010
    {
        errors.push("live_rpc_devnet_rehearsal must prove NBLA and nXMR gas economics".to_string());
    }
    if report.sequencer_key_rotation_count != 1 {
        errors.push(format!(
            "live_rpc_devnet_rehearsal.sequencer_key_rotation_count expected 1 but got {}",
            report.sequencer_key_rotation_count
        ));
    }
    require_hex_root(
        &mut errors,
        "live_rpc_devnet_rehearsal.launch_package_bundle_root",
        &report.launch_package_bundle_root,
    );
    require_eq(
        &mut errors,
        "live_rpc_devnet_rehearsal.rehearsal_root",
        &report.rehearsal_root,
        &expected_root,
    );

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(report)
}

fn require_runtime_surface_snapshot_economics(
    errors: &mut Vec<String>,
    status: &Value,
    snapshot: &runtime::RuntimeSnapshot,
) -> Option<runtime::RuntimeSnapshotEconomics> {
    let economics = match runtime::derive_runtime_snapshot_economics(snapshot) {
        Ok(economics) => economics,
        Err(error) => {
            errors.push(format!("runtime_surface.snapshot.economics: {error}"));
            return None;
        }
    };

    require_status_counter_matches_snapshot(
        errors,
        status,
        "total_nxmr_fees_units",
        snapshot.total_nxmr_fees_units,
    );
    require_status_counter_matches_snapshot(
        errors,
        status,
        "buyback_pool_nebulai",
        snapshot.buyback_pool_nebulai,
    );
    require_status_counter_matches_snapshot(
        errors,
        status,
        "validator_reward_nebulai",
        snapshot.validator_reward_nebulai,
    );

    Some(economics)
}

fn require_status_counter_matches_snapshot(
    errors: &mut Vec<String>,
    status: &Value,
    field: &str,
    expected: u128,
) {
    match json_u128_field(status, &format!("runtime_surface.status.{field}")) {
        Ok(value) if value == expected => {}
        Ok(value) => errors.push(format!(
            "runtime_surface.status.{field} expected snapshot {expected} but got {value}"
        )),
        Err(AttestationError::Invalid(mut field_errors)) => errors.append(&mut field_errors),
        Err(AttestationError::MalformedJson(error)) => errors.push(error),
    }
}

fn require_public_launch_economics_trial(
    errors: &mut Vec<String>,
    economics: &runtime::RuntimeSnapshotEconomics,
) {
    if economics.total_nxmr_fees_units == 0 {
        errors.push(
            "runtime_surface.snapshot.total_nxmr_fees_units must be greater than zero to prove nXMR gas was exercised"
                .to_string(),
        );
    }
    if economics.included_nxmr_receipt_count == 0 {
        errors.push(
            "runtime_surface.snapshot must include at least one signed-block nXMR gas receipt"
                .to_string(),
        );
    }
    if economics.included_nbla_receipt_count == 0 {
        errors.push(
            "runtime_surface.snapshot must include at least one signed-block NBLA gas receipt"
                .to_string(),
        );
    }

    let converted_nbla_nebulai = match economics
        .total_nxmr_fees_units
        .checked_mul(TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT)
    {
        Some(value) => value,
        None => {
            errors.push(
                "runtime_surface.snapshot.total_nxmr_fees_units conversion overflowed".to_string(),
            );
            return;
        }
    };
    let expected_buyback_nebulai =
        match split_basis_points(converted_nbla_nebulai, NXMR_BUYBACK_BPS) {
            Ok(value) => value,
            Err(_) => {
                errors.push(
                    "runtime_surface.snapshot.buyback_pool_nebulai accounting overflowed"
                        .to_string(),
                );
                return;
            }
        };
    let expected_nxmr_validator_reward_nebulai =
        match split_basis_points(converted_nbla_nebulai, NXMR_VALIDATOR_REWARD_BPS) {
            Ok(value) => value,
            Err(_) => {
                errors.push(
                    "runtime_surface.snapshot.validator_reward_nebulai accounting overflowed"
                        .to_string(),
                );
                return;
            }
        };

    if economics.buyback_pool_nebulai != expected_buyback_nebulai {
        errors.push(format!(
            "runtime_surface.snapshot.buyback_pool_nebulai expected {expected_buyback_nebulai} from {} nXMR fee units at 0.001 XMR/NBLA but got {}",
            economics.total_nxmr_fees_units, economics.buyback_pool_nebulai
        ));
    }
    if economics.nxmr_validator_reward_nebulai < expected_nxmr_validator_reward_nebulai {
        errors.push(format!(
            "runtime_surface.snapshot.nxmr_validator_reward_nebulai expected at least {expected_nxmr_validator_reward_nebulai} from nXMR gas rewards but got {}",
            economics.nxmr_validator_reward_nebulai
        ));
    }
    if economics.validator_reward_nebulai <= expected_nxmr_validator_reward_nebulai {
        errors.push(
            "runtime_surface.snapshot.validator_reward_nebulai must exceed nXMR-derived rewards to prove NBLA gas was exercised"
                .to_string(),
        );
    }
}

pub fn verify_deployment_attestation_json(
    input: &str,
) -> Result<DeploymentAttestationReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let value = serde_json::from_str::<Value>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let attestation = serde_json::from_value::<DeploymentAttestation>(value.clone())
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let now = unix_ms();
    let readiness = readiness_report();
    let runtime_root = readiness.status_roots["runtime"]
        .as_str()
        .expect("runtime root is a string");
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string");

    require_eq(&mut errors, "chain_id", &attestation.chain_id, CHAIN_ID);
    require_eq(
        &mut errors,
        "runtime_version",
        &attestation.runtime_version,
        VERSION,
    );
    if attestation.generated_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push("generated_at_unix_ms is more than five minutes in the future".to_string());
    }
    if attestation.generated_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push("generated_at_unix_ms is older than 24 hours".to_string());
    }
    if attestation.expires_at_unix_ms <= now {
        errors.push("expires_at_unix_ms is stale".to_string());
    }
    if attestation.expires_at_unix_ms > now + PUBLIC_ATTESTATION_MAX_TTL_MS {
        errors.push("expires_at_unix_ms is more than seven days in the future".to_string());
    }
    if attestation.expires_at_unix_ms <= attestation.generated_at_unix_ms {
        errors.push("expires_at_unix_ms must be after generated_at_unix_ms".to_string());
    }
    if attestation.expires_at_unix_ms
        > attestation
            .generated_at_unix_ms
            .saturating_add(PUBLIC_ATTESTATION_MAX_TTL_MS)
    {
        errors.push(
            "expires_at_unix_ms must be within seven days of generated_at_unix_ms".to_string(),
        );
    }

    verify_package_identity(&mut errors, &attestation.package_identity);
    verify_launch_bundle(
        &mut errors,
        &attestation.launch_bundle,
        &attestation.package_identity.root,
        runtime_root,
        economics_root,
    );
    verify_public_status_manifest(
        &mut errors,
        &attestation.public_status_manifest,
        &attestation.public_endpoint.url,
        &attestation.launch_bundle.root,
    );
    verify_public_endpoint(
        &mut errors,
        &attestation.public_endpoint,
        &attestation.public_status_manifest,
        now,
    );
    verify_policy_claim(
        &mut errors,
        &attestation.policy_claim,
        &readiness.public_launch_readiness.remediation_root,
        economics_root,
    );
    verify_public_probe(
        &mut errors,
        &attestation.public_probe,
        &attestation.public_endpoint.url,
        &attestation.launch_bundle.root,
        economics_root,
    );
    verify_deployment_component_root_domains(&mut errors, &attestation);
    verify_receipt(
        &mut errors,
        "preflight_receipt",
        &attestation.preflight_receipt,
        now,
    );
    verify_receipt(
        &mut errors,
        "runbook_receipt",
        &attestation.runbook_receipt,
        now,
    );
    verify_receipt_evidence_separation(
        &mut errors,
        &attestation.preflight_receipt,
        &attestation.runbook_receipt,
    );
    verify_receipts_before_deployment_generation(
        &mut errors,
        &attestation.preflight_receipt,
        &attestation.runbook_receipt,
        attestation.generated_at_unix_ms,
    );
    verify_network_witnesses(&mut errors, &attestation);
    verify_rollback_evidence(
        &mut errors,
        &attestation.rollback_evidence,
        now,
        attestation.generated_at_unix_ms,
    );

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let regions = attestation
        .operators
        .iter()
        .map(|operator| operator.region.as_str())
        .chain(
            attestation
                .observers
                .iter()
                .map(|observer| observer.region.as_str()),
        )
        .collect::<BTreeSet<_>>();

    let witness_evidence_root = deployment_witness_root(
        &attestation.launch_bundle,
        &attestation.public_status_manifest,
        &attestation.public_endpoint,
        &attestation.policy_claim,
        &attestation.public_probe,
    );

    Ok(DeploymentAttestationReport {
        public_launch_ready: true,
        level: "public-launch-attested",
        evidence_root: stable_root(&value),
        endpoint_url: attestation.public_endpoint.url.clone(),
        witness_evidence_root,
        public_surface_root: deployment_public_surface_root(&attestation),
        operator_approval_root: deployment_operator_approval_root(&attestation),
        observer_confirmation_root: deployment_observer_confirmation_root(&attestation),
        rollback_readiness_root: deployment_rollback_readiness_root(&attestation),
        deployment_validity_root: deployment_validity_root(&attestation),
        deployment_quorum_root: deployment_quorum_root(&attestation),
        bootstrap_roster_root: deployment_bootstrap_roster_root(&attestation),
        operational_evidence_root: deployment_operational_evidence_root(&attestation),
        attestation_expires_at_unix_ms: attestation.expires_at_unix_ms,
        verified_operator_count: attestation.operators.len(),
        verified_observer_count: attestation.observers.len(),
        verified_region_count: regions.len(),
    })
}

fn sample_package_identity() -> PackageIdentity {
    let mut package_identity = PackageIdentity {
        package_name: "nebula-testnet".to_string(),
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        artifact_sha3_256: hex_64("nebula-testnet-artifact"),
        cargo_lock_sha3_256: hex_64("nebula-testnet-cargo-lock"),
        root: String::new(),
    };
    package_identity.root = package_identity_root(&package_identity);
    package_identity
}

fn local_rehearsal_artifact(
    name: &'static str,
    level: &'static str,
    root: String,
) -> LocalPublicTestnetRehearsalArtifact {
    LocalPublicTestnetRehearsalArtifact { name, level, root }
}

fn local_public_testnet_rehearsal_root(report: &LocalPublicTestnetRehearsalReport) -> String {
    stable_root(&json!({
        "local_public_testnet_rehearsal_domain": "nebula-local-public-testnet-rehearsal-v1",
        "chain_id": report.chain_id,
        "runtime_version": report.runtime_version,
        "level": report.level,
        "local_public_testnet_rehearsed": report.local_public_testnet_rehearsed,
        "public_launch_ready": report.public_launch_ready,
        "public_launch_blocker": report.public_launch_blocker,
        "verified_artifact_count": report.verified_artifact_count,
        "verified_artifacts": report.verified_artifacts,
        "public_testnet_launch_certificate_root": report.public_testnet_launch_certificate_root,
        "public_testnet_peer_manifest_root": report.public_testnet_peer_manifest_root,
        "launch_package_bundle_root": report.launch_package_bundle_root,
        "launch_package_root": report.launch_package_root,
        "validator_activation_root": report.validator_activation_root,
        "validator_join_root": report.validator_join_root,
        "operator_join_confirmation_root": report.operator_join_confirmation_root,
        "public_observer_confirmation_root": report.public_observer_confirmation_root,
        "validator_count": report.validator_count,
        "operator_count": report.operator_count,
        "observer_count": report.observer_count,
        "region_count": report.region_count,
        "generated_at_unix_ms": report.generated_at_unix_ms,
    }))
}

fn live_rehearsal_invalid(error: impl Into<String>) -> AttestationError {
    AttestationError::Invalid(vec![error.into()])
}

fn live_runtime_launch_bindings(
) -> Result<(runtime::RuntimeLaunchBinding, runtime::RuntimeLaunchBinding), AttestationError> {
    let deployment_attestation_json = sample_deployment_attestation_json_pretty();
    let public_status_json = sample_public_status_manifest_json_pretty();
    let public_probe_json = sample_public_probe_json_pretty();
    let validator_set_json = sample_validator_set_json_pretty();
    let operator_handoff_json =
        build_operator_handoff_json_pretty(&deployment_attestation_json, &validator_set_json)?;
    let operator_acceptance_json = build_operator_acceptance_json_pretty(
        &operator_handoff_json,
        &deployment_attestation_json,
        &validator_set_json,
    )?;
    let genesis_manifest_json =
        build_genesis_manifest_json_pretty(&deployment_attestation_json, &validator_set_json)?;
    let launch_package_bundle_json = build_launch_package_bundle_json_pretty(
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
    )?;
    let sequencer_binding = build_runtime_launch_binding_from_jsons(
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
        &launch_package_bundle_json,
        "validator-a",
    )?;
    let follower_binding = build_runtime_launch_binding_from_jsons(
        &deployment_attestation_json,
        &public_status_json,
        &public_probe_json,
        &validator_set_json,
        &operator_handoff_json,
        &operator_acceptance_json,
        &genesis_manifest_json,
        &launch_package_bundle_json,
        "validator-b",
    )?;
    Ok((sequencer_binding, follower_binding))
}

fn live_rpc_start_server(
    config: runtime::RuntimeConfig,
    options: runtime::RuntimeNodeOptions,
) -> Result<String, AttestationError> {
    let rpc_addr = live_reserve_local_addr().map_err(live_rehearsal_invalid)?;
    let served_addr = rpc_addr.clone();
    thread::spawn(move || {
        if let Err(error) = runtime::serve_runtime_rpc_with_options(&served_addr, config, options) {
            eprintln!("live RPC rehearsal server failed on {served_addr}: {error}");
        }
    });
    live_wait_for_rpc(&rpc_addr).map_err(live_rehearsal_invalid)?;
    Ok(rpc_addr)
}

fn live_rpc_start_server_with_admin(
    config: runtime::RuntimeConfig,
    mut options: runtime::RuntimeNodeOptions,
) -> Result<(String, String), AttestationError> {
    let rpc_addr = live_reserve_local_addr().map_err(live_rehearsal_invalid)?;
    let admin_addr = live_reserve_local_addr().map_err(live_rehearsal_invalid)?;
    options.admin_rpc_bind_addr = Some(admin_addr.clone());
    let served_addr = rpc_addr.clone();
    thread::spawn(move || {
        if let Err(error) = runtime::serve_runtime_rpc_with_options(&served_addr, config, options) {
            eprintln!("live RPC rehearsal server failed on {served_addr}: {error}");
        }
    });
    live_wait_for_rpc(&rpc_addr).map_err(live_rehearsal_invalid)?;
    live_wait_for_rpc(&admin_addr).map_err(live_rehearsal_invalid)?;
    Ok((rpc_addr, admin_addr))
}

fn live_reserve_local_addr() -> Result<String, String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|error| format!("bind local port: {error}"))?;
    listener
        .local_addr()
        .map(|addr| addr.to_string())
        .map_err(|error| format!("read local port: {error}"))
}

fn live_wait_for_rpc(rpc_addr: &str) -> Result<(), String> {
    let deadline = unix_ms().saturating_add(5_000);
    loop {
        match live_http_json(rpc_addr, "/health") {
            Ok(health) if health["chain_id"] == CHAIN_ID => return Ok(()),
            Ok(_) | Err(_) if unix_ms() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(health) => {
                return Err(format!(
                    "RPC {rpc_addr} returned unexpected health response {health}"
                ));
            }
            Err(error) => return Err(format!("RPC {rpc_addr} did not become ready: {error}")),
        }
    }
}

fn live_wait_for_json_condition<F>(
    rpc_addr: &str,
    path: &str,
    description: &str,
    condition: F,
) -> Result<Value, AttestationError>
where
    F: Fn(&Value) -> bool,
{
    let deadline = unix_ms().saturating_add(5_000);
    loop {
        match live_http_json(rpc_addr, path) {
            Ok(value) if condition(&value) => return Ok(value),
            Ok(value) => {
                if unix_ms() >= deadline {
                    return Err(live_rehearsal_invalid(format!(
                        "{description} not satisfied by {value}"
                    )));
                }
            }
            Err(error) => {
                if unix_ms() >= deadline {
                    return Err(live_rehearsal_invalid(error));
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn live_wait_for_runtime_surface_evidence(
    rpc_addr: &str,
    endpoint_url: &str,
) -> Result<Value, AttestationError> {
    let deadline = unix_ms().saturating_add(5_000);
    loop {
        match live_capture_runtime_surface_evidence(rpc_addr, endpoint_url) {
            Ok(evidence) => return Ok(evidence),
            Err(error) => {
                if unix_ms() >= deadline {
                    return Err(live_rehearsal_invalid(error));
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn live_capture_runtime_surface_evidence(
    rpc_addr: &str,
    endpoint_url: &str,
) -> Result<Value, String> {
    let health = live_http_json(rpc_addr, "/health")?;
    let status = live_http_json(rpc_addr, "/status")?;
    let snapshot = live_http_json(rpc_addr, "/snapshot")?;
    let ops = live_http_json(rpc_addr, "/ops")?;
    let backup = live_http_json(rpc_addr, "/backup")?;
    let (_content_type, metrics_text) = live_http_text(rpc_addr, "/metrics")?;
    let rpc_status = live_rpc_request_value(rpc_addr, "nebula_status", json!({}))?;
    let rpc_ops_status = live_rpc_request_value(rpc_addr, "nebula_opsStatus", json!({}))?;
    let rpc_backup_manifest = live_rpc_request_value(rpc_addr, "nebula_backupManifest", json!({}))?;
    let evidence_json =
        build_runtime_surface_evidence_json_pretty(RuntimeSurfaceEvidenceBuildInput {
            endpoint_url: endpoint_url.to_string(),
            capture_mode: RUNTIME_SURFACE_CAPTURE_MODE_LOOPBACK_DEVNET.to_string(),
            tls_observation: None,
            captured_at_unix_ms: unix_ms(),
            health_json: health.to_string(),
            status_json: status.to_string(),
            snapshot_json: snapshot.to_string(),
            ops_json: ops.to_string(),
            backup_json: backup.to_string(),
            rpc_status_json: rpc_status.to_string(),
            rpc_ops_status_json: rpc_ops_status.to_string(),
            rpc_backup_manifest_json: rpc_backup_manifest.to_string(),
            metrics_text,
        })
        .map_err(|error| match error {
            AttestationError::MalformedJson(error) => error,
            AttestationError::Invalid(errors) => errors.join("; "),
        })?;

    serde_json::from_str::<Value>(&evidence_json).map_err(|error| error.to_string())
}

fn live_rpc_call(rpc_addr: &str, method: &str, params: Value) -> Result<Value, AttestationError> {
    live_rpc_request_value(rpc_addr, method, params).map_err(live_rehearsal_invalid)
}

fn live_rpc_request_value(rpc_addr: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let (_content_type, response) = live_http_request(rpc_addr, "/rpc", "POST", Some(body))?;
    serde_json::from_str::<Value>(&response)
        .map_err(|error| format!("invalid JSON-RPC response for {method}: {error}: {response}"))
}

fn live_rpc_result(response: &Value) -> Result<&Value, AttestationError> {
    if let Some(error) = response.get("error") {
        return Err(live_rehearsal_invalid(format!("JSON-RPC error: {error}")));
    }
    response.get("result").ok_or_else(|| {
        live_rehearsal_invalid(format!("JSON-RPC response missing result: {response}"))
    })
}

fn live_http_json(rpc_addr: &str, path: &str) -> Result<Value, String> {
    let (_content_type, body) = live_http_text(rpc_addr, path)?;
    serde_json::from_str::<Value>(&body)
        .map_err(|error| format!("invalid JSON from {path}: {error}: {body}"))
}

fn live_http_text(rpc_addr: &str, path: &str) -> Result<(String, String), String> {
    live_http_request(rpc_addr, path, "GET", None)
}

fn live_http_request(
    rpc_addr: &str,
    path: &str,
    method: &str,
    body: Option<String>,
) -> Result<(String, String), String> {
    let mut stream =
        TcpStream::connect(rpc_addr).map_err(|error| format!("connect {rpc_addr}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set write timeout: {error}"))?;
    let body = body.unwrap_or_default();
    let request = if method == "POST" {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {rpc_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        format!("GET {path} HTTP/1.1\r\nHost: {rpc_addr}\r\nConnection: close\r\n\r\n")
    };
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write request {path}: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flush request {path}: {error}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read response {path}: {error}"))?;
    let Some((head, response_body)) = response.split_once("\r\n\r\n") else {
        return Err(format!("malformed HTTP response from {path}: {response}"));
    };
    let mut header_lines = head.lines();
    let status_line = header_lines.next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(format!(
            "HTTP {path} failed with {status_line}: {response_body}"
        ));
    }
    let content_type = header_lines
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-type")
                    .then(|| value.trim().to_string())
            })
        })
        .unwrap_or_default();
    Ok((content_type, response_body.to_string()))
}

fn live_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn live_account_id(seed: u8) -> String {
    hex::encode(live_signing_key(seed).verifying_key().to_bytes())
}

fn live_sign_root(seed: u8, root: &str) -> String {
    hex::encode(live_signing_key(seed).sign(root.as_bytes()).to_bytes())
}

fn live_signed_transaction_with_fee_asset(
    seed: u8,
    nonce: u64,
    to: &str,
    amount_nebulai: u128,
    gas_units: u128,
    gas_price_nebulai: u128,
    fee_asset: &str,
) -> runtime::RuntimeTransaction {
    let mut tx = runtime::RuntimeTransaction {
        from: live_account_id(seed),
        to: to.to_string(),
        amount_nebulai,
        gas_units,
        gas_price_nebulai,
        fee_asset: fee_asset.to_string(),
        nonce,
        signature: String::new(),
        memo: None,
    };
    tx.signature = live_sign_root(seed, &tx.signing_root());
    tx
}

fn live_withdrawal_signature(
    seed: u8,
    monero_address: &str,
    amount_nxmr_units: u128,
    nonce: u64,
) -> String {
    let root = runtime::withdrawal_authorization_root(
        &live_account_id(seed),
        monero_address,
        amount_nxmr_units,
        nonce,
    );
    live_sign_root(seed, &root)
}

fn live_bridge_deposit(seed: u8, amount_nxmr_units: u128) -> Value {
    let mut deposit = runtime::RuntimeBridgeDeposit {
        monero_tx_id: hex_64("live-rpc-devnet-monero-deposit"),
        account: live_account_id(seed),
        amount_nxmr_units,
        confirmations: runtime::MIN_BRIDGE_CONFIRMATIONS,
        observer_id: "observer-us-east-1".to_string(),
        observer_ids: vec![
            "observer-us-east-1".to_string(),
            "observer-eu-west-1".to_string(),
        ],
        proof_root: hex_64("live-rpc-devnet-deposit-proof"),
        custody_proof_root: hex_64("live-rpc-devnet-custody-proof"),
        relayer_set_root: hex_64("live-rpc-devnet-relayer-set"),
        observer_signature_roots: Vec::new(),
        observer_evidence: Vec::new(),
        observed_at_unix_ms: 1,
    };
    let observer_a = live_observer_evidence(&deposit, "observer-us-east-1", 0xb1);
    let observer_b = live_observer_evidence(&deposit, "observer-eu-west-1", 0xb2);
    deposit.observer_signature_roots = vec![
        observer_a.evidence_root.clone(),
        observer_b.evidence_root.clone(),
    ];
    deposit.observer_evidence = vec![observer_a, observer_b];
    json!(deposit)
}

fn live_observer_evidence(
    deposit: &runtime::RuntimeBridgeDeposit,
    observer_id: &str,
    seed: u8,
) -> runtime::RuntimeBridgeObserverEvidence {
    let payload_root = runtime::bridge_observer_deposit_payload_root(deposit);
    let mut evidence = runtime::RuntimeBridgeObserverEvidence {
        observer_id: observer_id.to_string(),
        observer_public_key_hex: live_account_id(seed),
        payload_root: payload_root.clone(),
        signature: live_sign_root(seed, &payload_root),
        signed_at_unix_ms: 1,
        evidence_root: String::new(),
    };
    evidence.evidence_root = runtime::bridge_observer_evidence_root(&evidence);
    evidence
}

fn live_operator_approval_quorum(
    withdrawal: &runtime::RuntimeWithdrawalRequest,
    finalized_monero_tx_id: &str,
    finalization_proof_root: &str,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<runtime::RuntimeWithdrawalOperatorApproval>,
) {
    let approval_a = live_operator_approval(
        withdrawal,
        finalized_monero_tx_id,
        finalization_proof_root,
        "operator-a",
        0xa1,
    );
    let approval_b = live_operator_approval(
        withdrawal,
        finalized_monero_tx_id,
        finalization_proof_root,
        "operator-b",
        0xa2,
    );
    (
        vec![
            approval_a.operator_id.clone(),
            approval_b.operator_id.clone(),
        ],
        vec![
            approval_a.approval_root.clone(),
            approval_b.approval_root.clone(),
        ],
        vec![approval_a, approval_b],
    )
}

fn live_operator_approval(
    withdrawal: &runtime::RuntimeWithdrawalRequest,
    finalized_monero_tx_id: &str,
    finalization_proof_root: &str,
    operator_id: &str,
    seed: u8,
) -> runtime::RuntimeWithdrawalOperatorApproval {
    let payload_root = runtime::withdrawal_operator_finalization_payload_root(
        withdrawal,
        finalized_monero_tx_id,
        finalization_proof_root,
    );
    let mut approval = runtime::RuntimeWithdrawalOperatorApproval {
        operator_id: operator_id.to_string(),
        operator_public_key_hex: live_account_id(seed),
        payload_root: payload_root.clone(),
        signature: live_sign_root(seed, &payload_root),
        signed_at_unix_ms: 1,
        approval_root: String::new(),
    };
    approval.approval_root = runtime::withdrawal_operator_approval_root(&approval);
    approval
}

fn live_rotation_operator_approval_quorum(
    launch_binding: Option<&runtime::RuntimeLaunchBinding>,
    previous_sequencer_key_history_root: &str,
    activation_height: u64,
    old_public_key_hex: &str,
    new_public_key_hex: &str,
    rotation_proof_root: &str,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<runtime::RuntimeSequencerKeyRotationApproval>,
) {
    let approval_a = live_rotation_operator_approval(
        launch_binding,
        previous_sequencer_key_history_root,
        activation_height,
        old_public_key_hex,
        new_public_key_hex,
        rotation_proof_root,
        "operator-a",
        0xa1,
    );
    let approval_b = live_rotation_operator_approval(
        launch_binding,
        previous_sequencer_key_history_root,
        activation_height,
        old_public_key_hex,
        new_public_key_hex,
        rotation_proof_root,
        "operator-b",
        0xa2,
    );
    (
        vec![
            approval_a.operator_id.clone(),
            approval_b.operator_id.clone(),
        ],
        vec![
            approval_a.approval_root.clone(),
            approval_b.approval_root.clone(),
        ],
        vec![approval_a, approval_b],
    )
}

#[allow(clippy::too_many_arguments)]
fn live_rotation_operator_approval(
    launch_binding: Option<&runtime::RuntimeLaunchBinding>,
    previous_sequencer_key_history_root: &str,
    activation_height: u64,
    old_public_key_hex: &str,
    new_public_key_hex: &str,
    rotation_proof_root: &str,
    operator_id: &str,
    seed: u8,
) -> runtime::RuntimeSequencerKeyRotationApproval {
    let payload_root = runtime::sequencer_key_rotation_payload_root(
        launch_binding,
        previous_sequencer_key_history_root,
        activation_height,
        old_public_key_hex,
        new_public_key_hex,
        rotation_proof_root,
    );
    let mut approval = runtime::RuntimeSequencerKeyRotationApproval {
        operator_id: operator_id.to_string(),
        operator_public_key_hex: live_account_id(seed),
        payload_root: payload_root.clone(),
        signature: live_sign_root(seed, &payload_root),
        signed_at_unix_ms: 1,
        approval_root: String::new(),
    };
    approval.approval_root = runtime::sequencer_key_rotation_approval_root(&approval);
    approval
}

fn live_value_u64(value: &Value, field: &str) -> Result<u64, AttestationError> {
    value[field]
        .as_u64()
        .ok_or_else(|| live_rehearsal_invalid(format!("{field} must be an unsigned integer")))
}

fn live_value_u128(value: &Value, field: &str) -> Result<u128, AttestationError> {
    value[field]
        .as_u64()
        .map(u128::from)
        .ok_or_else(|| live_rehearsal_invalid(format!("{field} must be an unsigned integer")))
}

fn live_value_bool(value: &Value, field: &str) -> Result<bool, AttestationError> {
    value[field]
        .as_bool()
        .ok_or_else(|| live_rehearsal_invalid(format!("{field} must be a boolean")))
}

fn live_temp_data_dir(label: &str) -> String {
    let mut path: PathBuf = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let thread_id = format!("{:?}", thread::current().id())
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    path.push(format!(
        "nebula-live-rpc-devnet-{label}-{}-{thread_id}-{nanos}",
        std::process::id()
    ));
    path.to_string_lossy().into_owned()
}

fn live_rpc_devnet_rehearsal_root(report: &LiveRpcDevnetRehearsalReport) -> String {
    stable_root(&json!({
        "live_rpc_devnet_rehearsal_domain": "nebula-live-rpc-devnet-rehearsal-v1",
        "chain_id": report.chain_id,
        "runtime_version": report.runtime_version,
        "level": report.level,
        "live_rpc_devnet_rehearsed": report.live_rpc_devnet_rehearsed,
        "public_launch_ready": report.public_launch_ready,
        "public_launch_blocker": report.public_launch_blocker,
        "endpoint_url": report.endpoint_url,
        "block_millis": report.block_millis,
        "sub_second_blocks": report.sub_second_blocks,
        "produced_block_count": report.produced_block_count,
        "runtime_surface_ready": report.runtime_surface_ready,
        "runtime_surface_root": report.runtime_surface_root,
        "latest_height": report.latest_height,
        "sync_quorum_met": report.sync_quorum_met,
        "sync_successful_peer_count": report.sync_successful_peer_count,
        "sync_import_count": report.sync_import_count,
        "sync_last_import_height": report.sync_last_import_height,
        "sync_quorum_height": report.sync_quorum_height,
        "bridge_deposit_count": report.bridge_deposit_count,
        "withdrawal_request_count": report.withdrawal_request_count,
        "finalized_withdrawal_count": report.finalized_withdrawal_count,
        "bridge_replay_cache_count": report.bridge_replay_cache_count,
        "bridge_deposited_nxmr_units": report.bridge_deposited_nxmr_units,
        "account_nxmr_units": report.account_nxmr_units,
        "withdrawal_reserved_nxmr_units": report.withdrawal_reserved_nxmr_units,
        "total_nxmr_fees_units": report.total_nxmr_fees_units,
        "buyback_pool_nebulai": report.buyback_pool_nebulai,
        "validator_reward_nebulai": report.validator_reward_nebulai,
        "bridge_custody_reconciled": report.bridge_custody_reconciled,
        "nxmr_custody_deficit_units": report.nxmr_custody_deficit_units,
        "sequencer_key_rotation_count": report.sequencer_key_rotation_count,
        "launch_package_bundle_root": report.launch_package_bundle_root,
    }))
}

fn sample_launch_bundle(
    package_root: &str,
    runtime_root: &str,
    economics_root: &str,
) -> LaunchBundle {
    let mut launch_bundle = LaunchBundle {
        bundle_id: PUBLIC_TESTNET_BUNDLE_ID.to_string(),
        chain_id: CHAIN_ID.to_string(),
        package_root: package_root.to_string(),
        runtime_root: runtime_root.to_string(),
        economics_root: economics_root.to_string(),
        root: String::new(),
    };
    launch_bundle.root = launch_bundle_root(&launch_bundle);
    launch_bundle
}

fn sample_public_surface() -> PublicSurfaceSample {
    let package_identity = sample_package_identity();
    let readiness = readiness_report();
    let runtime_root = readiness.status_roots["runtime"]
        .as_str()
        .expect("runtime root is a string")
        .to_string();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string")
        .to_string();
    let launch_bundle =
        sample_launch_bundle(&package_identity.root, &runtime_root, &economics_root);
    let endpoint_url = "https://testnet.nebula.example/status".to_string();
    let public_status_manifest = sample_public_status_manifest(&launch_bundle.root, &endpoint_url);
    let public_probe = sample_public_probe(&endpoint_url, &launch_bundle.root, &economics_root);

    PublicSurfaceSample {
        endpoint_url,
        launch_bundle_root: launch_bundle.root,
        economics_root,
        public_status_manifest,
        public_probe,
    }
}

fn build_public_surface(
    input: PublicSurfaceBuildInput,
) -> Result<PublicSurfaceSample, AttestationError> {
    let package_identity =
        build_package_identity(&input.artifact_sha3_256, &input.cargo_lock_sha3_256)?;
    let readiness = readiness_report();
    let runtime_root = readiness.status_roots["runtime"]
        .as_str()
        .expect("runtime root is a string")
        .to_string();
    let economics_root = readiness.status_roots["economics"]
        .as_str()
        .expect("economics root is a string")
        .to_string();
    let launch_bundle =
        sample_launch_bundle(&package_identity.root, &runtime_root, &economics_root);
    let public_status_manifest =
        sample_public_status_manifest(&launch_bundle.root, &input.endpoint_url);
    let public_probe =
        sample_public_probe(&input.endpoint_url, &launch_bundle.root, &economics_root);
    let mut errors = Vec::new();
    verify_public_status_manifest(
        &mut errors,
        &public_status_manifest,
        &input.endpoint_url,
        &launch_bundle.root,
    );
    verify_public_probe(
        &mut errors,
        &public_probe,
        &input.endpoint_url,
        &launch_bundle.root,
        &economics_root,
    );
    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(PublicSurfaceSample {
        endpoint_url: input.endpoint_url,
        launch_bundle_root: launch_bundle.root,
        economics_root,
        public_status_manifest,
        public_probe,
    })
}

fn build_package_identity(
    artifact_sha3_256: &str,
    cargo_lock_sha3_256: &str,
) -> Result<PackageIdentity, AttestationError> {
    let mut package_identity = PackageIdentity {
        package_name: "nebula-testnet".to_string(),
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        artifact_sha3_256: artifact_sha3_256.to_string(),
        cargo_lock_sha3_256: cargo_lock_sha3_256.to_string(),
        root: String::new(),
    };
    package_identity.root = package_identity_root(&package_identity);
    let mut errors = Vec::new();
    verify_package_identity(&mut errors, &package_identity);
    if errors.is_empty() {
        Ok(package_identity)
    } else {
        Err(AttestationError::Invalid(errors))
    }
}

fn parse_public_status_manifest_json(
    input: &str,
    label: &str,
) -> Result<PublicStatusManifest, AttestationError> {
    serde_json::from_str::<PublicStatusManifest>(input.trim_start_matches('\u{feff}'))
        .map_err(|error| AttestationError::MalformedJson(format!("{label}: {error}")))
}

fn parse_public_probe_json(input: &str, label: &str) -> Result<PublicProbe, AttestationError> {
    serde_json::from_str::<PublicProbe>(input.trim_start_matches('\u{feff}'))
        .map_err(|error| AttestationError::MalformedJson(format!("{label}: {error}")))
}

fn parse_receipt_json(input: &str, label: &str) -> Result<Receipt, AttestationError> {
    serde_json::from_str::<Receipt>(input.trim_start_matches('\u{feff}'))
        .map_err(|error| AttestationError::MalformedJson(format!("{label}: {error}")))
}

const RUNTIME_STATUS_DURABLE_FIELDS: &[&str] = &[
    "chain_id",
    "runtime_version",
    "launch_binding_present",
    "launch_endpoint_url",
    "deployment_attestation_root",
    "public_status_manifest_root",
    "public_probe_root",
    "fee_policy_root",
    "validator_set_root",
    "operator_handoff_root",
    "operator_acceptance_root",
    "genesis_root",
    "launch_package_root",
    "launch_package_bundle_root",
    "launch_activation_height",
    "launch_validator_count",
    "launch_operator_count",
    "launch_region_count",
    "node_role",
    "latest_height",
    "latest_hash",
    "latest_state_root",
    "current_state_root",
    "block_target_ms",
    "sub_second_blocks",
    "gas_price_nebulai",
    "block_production_enabled",
    "sequencer_public_key_hex",
    "sequencer_key_history_root",
    "accountability_report_count",
    "accountability_root",
    "sequencer_accountability_clean",
    "sync_peer_count",
    "sync_peer_quorum",
    "public_testnet_peer_manifest_present",
    "public_testnet_peer_manifest_root",
    "public_testnet_peer_manifest_launch_package_bundle_root",
    "public_testnet_peer_manifest_snapshot_peer_count",
    "public_testnet_peer_manifest_sync_peer_quorum",
    "sync_quorum_met",
    "sync_quorum_peer_count",
    "sync_quorum_height",
    "sync_quorum_latest_hash",
    "sync_quorum_state_root",
    "sync_successful_peer_count",
    "sync_failed_peer_count",
    "rpc_max_request_bytes",
    "rpc_max_requests_per_minute",
    "rpc_max_active_connections",
    "admin_rpc_max_active_connections",
    "sync_max_snapshot_response_bytes",
    "rpc_client_identity_mode",
    "rpc_client_identity_proxy_aware",
    "rpc_trust_private_proxy_headers",
    "rpc_trusted_proxy_count",
    "admin_rpc_enabled",
    "admin_rpc_private_listener",
    "public_rpc_admin_methods_enabled",
    "default_dev_sequencer_key",
    "max_mempool_transactions",
    "mempool_size",
    "mempool_capacity_remaining",
    "mempool_full_rejection_count",
    "mempool_admission_rejection_count",
    "total_nxmr_fees_units",
    "buyback_pool_nebulai",
    "validator_reward_nebulai",
    "validator_reward_account",
    "faucet_nbla_nebulai",
    "faucet_nxmr_units",
    "bridge_only_nxmr",
    "bridge_deposited_nxmr_units",
    "account_nxmr_units",
    "withdrawal_reserved_nxmr_units",
    "nxmr_fee_units",
    "nxmr_custody_required_units",
    "nxmr_custody_surplus_units",
    "bridge_custody_reconciled",
    "nxmr_custody_deficit_units",
    "bridge_policy_root",
    "bridge_min_deposit_confirmations",
    "bridge_deposit_observer_quorum",
    "bridge_withdrawal_operator_quorum",
    "bridge_live_value_enabled",
    "bridge_deposit_count",
    "withdrawal_request_count",
    "finalized_withdrawal_count",
];

const RUNTIME_OPS_DURABLE_FIELDS: &[&str] = &[
    "service",
    "chain_id",
    "runtime_version",
    "launch_binding_present",
    "launch_endpoint_url",
    "deployment_attestation_root",
    "public_status_manifest_root",
    "public_probe_root",
    "fee_policy_root",
    "validator_set_root",
    "operator_handoff_root",
    "operator_acceptance_root",
    "genesis_root",
    "launch_package_root",
    "launch_package_bundle_root",
    "launch_activation_height",
    "launch_validator_count",
    "launch_operator_count",
    "launch_region_count",
    "node_role",
    "latest_height",
    "latest_hash",
    "block_target_ms",
    "sub_second_blocks",
    "gas_price_nebulai",
    "block_production_enabled",
    "snapshot_version",
    "snapshot_root",
    "state_root",
    "current_state_root",
    "storage_snapshot_path",
    "storage_snapshot_present",
    "storage_snapshot_root",
    "storage_snapshot_height",
    "storage_snapshot_matches_runtime",
    "sync_peer_count",
    "sync_peer_quorum",
    "public_testnet_peer_manifest_present",
    "public_testnet_peer_manifest_root",
    "public_testnet_peer_manifest_launch_package_bundle_root",
    "public_testnet_peer_manifest_snapshot_peer_count",
    "public_testnet_peer_manifest_sync_peer_quorum",
    "sync_quorum_met",
    "sync_quorum_peer_count",
    "sync_quorum_height",
    "sync_quorum_latest_hash",
    "sync_quorum_state_root",
    "sync_successful_peer_count",
    "sync_failed_peer_count",
    "rpc_max_request_bytes",
    "rpc_max_requests_per_minute",
    "rpc_max_active_connections",
    "admin_rpc_max_active_connections",
    "sync_max_snapshot_response_bytes",
    "rpc_client_identity_mode",
    "rpc_client_identity_proxy_aware",
    "rpc_trust_private_proxy_headers",
    "rpc_trusted_proxy_count",
    "admin_rpc_enabled",
    "admin_rpc_private_listener",
    "public_rpc_admin_methods_enabled",
    "default_dev_sequencer_key",
    "max_mempool_transactions",
    "mempool_size",
    "mempool_capacity_remaining",
    "mempool_full_rejection_count",
    "mempool_admission_rejection_count",
    "sequencer_public_key_hex",
    "sequencer_key_rotation_count",
    "sequencer_latest_rotation_activation_height",
    "sequencer_key_history_root",
    "accountability_report_count",
    "accountability_root",
    "sequencer_accountability_clean",
    "bridge_policy_root",
    "bridge_live_value_enabled",
    "faucet_nbla_nebulai",
    "faucet_nxmr_units",
    "bridge_only_nxmr",
    "bridge_deposited_nxmr_units",
    "account_nxmr_units",
    "withdrawal_reserved_nxmr_units",
    "nxmr_fee_units",
    "nxmr_custody_required_units",
    "nxmr_custody_surplus_units",
    "nxmr_custody_deficit_units",
    "bridge_custody_reconciled",
    "public_ops_ready",
    "blocking_gaps",
];

const RUNTIME_BACKUP_DURABLE_FIELDS: &[&str] = &[
    "manifest_version",
    "chain_id",
    "runtime_version",
    "launch_binding_present",
    "launch_endpoint_url",
    "deployment_attestation_root",
    "public_status_manifest_root",
    "public_probe_root",
    "fee_policy_root",
    "validator_set_root",
    "operator_handoff_root",
    "operator_acceptance_root",
    "genesis_root",
    "launch_package_root",
    "launch_package_bundle_root",
    "launch_activation_height",
    "launch_validator_count",
    "launch_operator_count",
    "launch_region_count",
    "latest_height",
    "latest_hash",
    "snapshot_version",
    "snapshot_root",
    "state_root",
    "current_state_root",
    "gas_price_nebulai",
    "snapshot_path",
    "snapshot_persisted",
    "storage_snapshot_root",
    "storage_snapshot_matches_runtime",
    "sequencer_public_key_hex",
    "sequencer_key_rotation_count",
    "sequencer_latest_rotation_activation_height",
    "sequencer_key_history_root",
    "accountability_report_count",
    "accountability_root",
    "sequencer_accountability_clean",
    "bridge_policy_root",
    "sync_peer_count",
    "sync_peer_quorum",
    "public_testnet_peer_manifest_present",
    "public_testnet_peer_manifest_root",
    "public_testnet_peer_manifest_launch_package_bundle_root",
    "public_testnet_peer_manifest_snapshot_peer_count",
    "public_testnet_peer_manifest_sync_peer_quorum",
    "sync_quorum_met",
    "sync_quorum_peer_count",
    "sync_quorum_height",
    "sync_quorum_latest_hash",
    "sync_quorum_state_root",
    "sync_successful_peer_count",
    "sync_failed_peer_count",
    "rpc_max_request_bytes",
    "rpc_max_requests_per_minute",
    "rpc_max_active_connections",
    "admin_rpc_max_active_connections",
    "sync_max_snapshot_response_bytes",
    "rpc_client_identity_mode",
    "rpc_client_identity_proxy_aware",
    "rpc_trust_private_proxy_headers",
    "rpc_trusted_proxy_count",
    "admin_rpc_enabled",
    "admin_rpc_private_listener",
    "public_rpc_admin_methods_enabled",
    "default_dev_sequencer_key",
    "max_mempool_transactions",
    "mempool_size",
    "mempool_capacity_remaining",
    "mempool_full_rejection_count",
    "mempool_admission_rejection_count",
    "faucet_nbla_nebulai",
    "faucet_nxmr_units",
    "bridge_only_nxmr",
    "bridge_deposited_nxmr_units",
    "account_nxmr_units",
    "withdrawal_reserved_nxmr_units",
    "nxmr_fee_units",
    "nxmr_custody_required_units",
    "nxmr_custody_surplus_units",
    "nxmr_custody_deficit_units",
    "bridge_custody_reconciled",
];

fn parse_json_value(input: &str, label: &str) -> Result<Value, AttestationError> {
    serde_json::from_str::<Value>(input.trim_start_matches('\u{feff}'))
        .map_err(|error| AttestationError::MalformedJson(format!("{label}: {error}")))
}

fn json_string_field(value: &Value, label: &str) -> Result<String, AttestationError> {
    let field = label.rsplit('.').next().unwrap_or(label);
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AttestationError::Invalid(vec![format!("{label} must be a string")]))
}

fn json_u128_field(value: &Value, label: &str) -> Result<u128, AttestationError> {
    let field = label.rsplit('.').next().unwrap_or(label);
    let Some(value) = value.get(field) else {
        return Err(AttestationError::Invalid(vec![format!(
            "{label} must be a u128"
        )]));
    };
    if let Some(number) = value.as_u64() {
        return Ok(u128::from(number));
    }
    if let Some(text) = value.as_str() {
        return text.parse::<u128>().map_err(|error| {
            AttestationError::Invalid(vec![format!("{label} must be a u128: {error}")])
        });
    }
    Err(AttestationError::Invalid(vec![format!(
        "{label} must be a u128"
    )]))
}

fn runtime_surface_evidence_root(evidence: &RuntimeSurfaceEvidence) -> String {
    stable_root(&json!({
        "runtime_surface_domain": "nebula-runtime-surface-evidence-v1",
        "chain_id": evidence.chain_id,
        "runtime_version": evidence.runtime_version,
        "endpoint_url": evidence.endpoint_url,
        "capture_mode": evidence.capture_mode,
        "tls_observation": evidence.tls_observation,
        "captured_at_unix_ms": evidence.captured_at_unix_ms,
        "health": evidence.health,
        "status": evidence.status,
        "snapshot": evidence.snapshot,
        "ops": evidence.ops,
        "backup": evidence.backup,
        "rpc_status": evidence.rpc_status,
        "rpc_ops_status": evidence.rpc_ops_status,
        "rpc_backup_manifest": evidence.rpc_backup_manifest,
        "metrics_text": evidence.metrics_text,
    }))
}

fn rpc_result_or_value<'a>(errors: &mut Vec<String>, label: &str, value: &'a Value) -> &'a Value {
    if value.get("error").is_some() {
        errors.push(format!("{label} contains a JSON-RPC error"));
    }
    value.get("result").unwrap_or(value)
}

fn require_value_eq(errors: &mut Vec<String>, label: &str, actual: &Value, expected: &Value) {
    if actual != expected {
        errors.push(format!("{label} does not match expected captured value"));
    }
}

fn verify_runtime_surface_tls_observation(
    errors: &mut Vec<String>,
    tls_observation: &TlsEndpointPin,
    now: u128,
) {
    require_hex_root(
        errors,
        "runtime_surface.tls_observation.cert_sha256",
        &tls_observation.cert_sha256,
    );
    require_hex_root(
        errors,
        "runtime_surface.tls_observation.public_key_sha256",
        &tls_observation.public_key_sha256,
    );
    if tls_observation.cert_sha256 == tls_observation.public_key_sha256 {
        errors.push(
            "runtime_surface.tls_observation.public_key_sha256 must differ from cert_sha256"
                .to_string(),
        );
    }
    if tls_observation.not_after_unix_ms <= now {
        errors.push("runtime_surface.tls_observation.not_after_unix_ms is stale".to_string());
    }
}

fn tls_endpoint_pins_match(left: &TlsEndpointPin, right: &TlsEndpointPin) -> bool {
    left.cert_sha256.eq_ignore_ascii_case(&right.cert_sha256)
        && left
            .public_key_sha256
            .eq_ignore_ascii_case(&right.public_key_sha256)
        && left.not_after_unix_ms == right.not_after_unix_ms
}

fn require_durable_field_set_eq(
    errors: &mut Vec<String>,
    left_label: &str,
    left: &Value,
    right_label: &str,
    right: &Value,
    fields: &[&str],
) {
    for field in fields {
        let actual = left.get(*field).unwrap_or(&Value::Null);
        let expected = right.get(*field).unwrap_or(&Value::Null);
        if actual != expected {
            errors.push(format!(
                "{left_label}.{field} does not match {right_label}.{field}"
            ));
        }
    }
}

fn parse_surface_value<T: serde::de::DeserializeOwned>(
    errors: &mut Vec<String>,
    label: &str,
    value: &Value,
) -> Option<T> {
    match serde_json::from_value::<T>(value.clone()) {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            errors.push(format!("{label} failed typed decode: {error}"));
            None
        }
    }
}

fn json_bool(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn require_health_status_agreement(errors: &mut Vec<String>, health: &Value, status: &Value) {
    for field in [
        "chain_id",
        "runtime_version",
        "launch_binding_present",
        "launch_endpoint_url",
        "deployment_attestation_root",
        "public_status_manifest_root",
        "public_probe_root",
        "fee_policy_root",
        "validator_set_root",
        "operator_handoff_root",
        "operator_acceptance_root",
        "genesis_root",
        "launch_package_root",
        "launch_package_bundle_root",
        "launch_activation_height",
        "launch_validator_count",
        "launch_operator_count",
        "launch_region_count",
        "node_role",
        "latest_height",
        "latest_hash",
        "latest_state_root",
        "current_state_root",
        "block_target_ms",
        "sub_second_blocks",
        "gas_price_nebulai",
        "block_production_enabled",
        "sequencer_public_key_hex",
        "sequencer_key_history_root",
        "accountability_root",
        "bridge_policy_root",
        "sync_peer_count",
        "sync_peer_quorum",
        "public_testnet_peer_manifest_present",
        "public_testnet_peer_manifest_root",
        "public_testnet_peer_manifest_launch_package_bundle_root",
        "public_testnet_peer_manifest_snapshot_peer_count",
        "public_testnet_peer_manifest_sync_peer_quorum",
        "sync_quorum_met",
        "sync_quorum_peer_count",
        "sync_quorum_height",
        "sync_quorum_latest_hash",
        "sync_quorum_state_root",
        "sync_successful_peer_count",
        "admin_rpc_enabled",
        "admin_rpc_private_listener",
        "public_rpc_admin_methods_enabled",
        "default_dev_sequencer_key",
        "max_mempool_transactions",
        "mempool_size",
        "mempool_capacity_remaining",
        "mempool_full_rejection_count",
        "mempool_admission_rejection_count",
        "faucet_nbla_nebulai",
        "faucet_nxmr_units",
        "bridge_only_nxmr",
        "bridge_custody_reconciled",
        "nxmr_custody_deficit_units",
        "bridge_deposit_count",
        "withdrawal_request_count",
        "finalized_withdrawal_count",
    ] {
        let actual = health.get(field).unwrap_or(&Value::Null);
        let expected = status.get(field).unwrap_or(&Value::Null);
        if actual != expected {
            errors.push(format!("health.{field} does not match status.{field}"));
        }
    }
    if health.get("ok") != Some(&Value::Bool(true)) {
        errors.push("health.ok must be true".to_string());
    }
    require_hex_root_from_value(errors, "health.ops_root", health.get("ops_root"));
    require_hex_root_from_value(errors, "health.backup_root", health.get("backup_root"));
}

fn require_ops_backup_snapshot_agreement(
    errors: &mut Vec<String>,
    health: &Value,
    status: &Value,
    snapshot: &Value,
    ops: &Value,
    backup: &Value,
) {
    let latest_block = snapshot
        .get("blocks")
        .and_then(Value::as_array)
        .and_then(|blocks| blocks.last());
    require_value_eq(
        errors,
        "snapshot.config.chain_id",
        snapshot.pointer("/config/chain_id").unwrap_or(&Value::Null),
        status.get("chain_id").unwrap_or(&Value::Null),
    );
    require_value_eq(
        errors,
        "snapshot.config.runtime_version",
        snapshot
            .pointer("/config/runtime_version")
            .unwrap_or(&Value::Null),
        status.get("runtime_version").unwrap_or(&Value::Null),
    );
    let snapshot_launch_binding_present = Value::Bool(
        snapshot
            .pointer("/config/launch_binding")
            .is_some_and(|value| !value.is_null()),
    );
    require_value_eq(
        errors,
        "snapshot.config.launch_binding_present",
        &snapshot_launch_binding_present,
        status.get("launch_binding_present").unwrap_or(&Value::Null),
    );
    require_value_eq(
        errors,
        "snapshot.config.gas_price_nebulai",
        snapshot
            .pointer("/config/gas_price_nebulai")
            .unwrap_or(&Value::Null),
        status.get("gas_price_nebulai").unwrap_or(&Value::Null),
    );
    if let Some(launch_binding) = snapshot
        .pointer("/config/launch_binding")
        .and_then(Value::as_object)
    {
        for (snapshot_field, status_field) in [
            ("endpoint_url", "launch_endpoint_url"),
            ("deployment_attestation_root", "deployment_attestation_root"),
            ("public_status_manifest_root", "public_status_manifest_root"),
            ("public_probe_root", "public_probe_root"),
            ("fee_policy_root", "fee_policy_root"),
            ("validator_set_root", "validator_set_root"),
            ("operator_handoff_root", "operator_handoff_root"),
            ("operator_acceptance_root", "operator_acceptance_root"),
            ("genesis_root", "genesis_root"),
            ("launch_package_root", "launch_package_root"),
            ("launch_package_bundle_root", "launch_package_bundle_root"),
            ("activation_height", "launch_activation_height"),
            ("validator_count", "launch_validator_count"),
            ("operator_count", "launch_operator_count"),
            ("region_count", "launch_region_count"),
        ] {
            require_value_eq(
                errors,
                &format!("snapshot.config.launch_binding.{snapshot_field}"),
                launch_binding.get(snapshot_field).unwrap_or(&Value::Null),
                status.get(status_field).unwrap_or(&Value::Null),
            );
        }
    }
    if let Some(latest_block) = latest_block {
        require_value_eq(
            errors,
            "status.latest_height",
            status.get("latest_height").unwrap_or(&Value::Null),
            latest_block.get("height").unwrap_or(&Value::Null),
        );
        require_value_eq(
            errors,
            "status.latest_hash",
            status.get("latest_hash").unwrap_or(&Value::Null),
            latest_block.get("block_hash").unwrap_or(&Value::Null),
        );
        require_value_eq(
            errors,
            "status.latest_state_root",
            status.get("latest_state_root").unwrap_or(&Value::Null),
            latest_block.get("state_root").unwrap_or(&Value::Null),
        );
    } else {
        errors.push("snapshot.blocks must contain a latest block".to_string());
    }
    require_value_eq(
        errors,
        "status.current_state_root",
        status.get("current_state_root").unwrap_or(&Value::Null),
        snapshot.get("state_root").unwrap_or(&Value::Null),
    );
    require_value_eq(
        errors,
        "health.snapshot_root",
        health.get("snapshot_root").unwrap_or(&Value::Null),
        snapshot.get("root").unwrap_or(&Value::Null),
    );
    require_value_eq(
        errors,
        "ops.snapshot_root",
        ops.get("snapshot_root").unwrap_or(&Value::Null),
        snapshot.get("root").unwrap_or(&Value::Null),
    );
    require_value_eq(
        errors,
        "backup.snapshot_root",
        backup.get("snapshot_root").unwrap_or(&Value::Null),
        snapshot.get("root").unwrap_or(&Value::Null),
    );
    for field in ["latest_height", "latest_hash", "current_state_root"] {
        require_value_eq(
            errors,
            &format!("ops.{field}"),
            ops.get(field).unwrap_or(&Value::Null),
            status.get(field).unwrap_or(&Value::Null),
        );
        require_value_eq(
            errors,
            &format!("backup.{field}"),
            backup.get(field).unwrap_or(&Value::Null),
            status.get(field).unwrap_or(&Value::Null),
        );
    }
    for field in [
        "storage_snapshot_matches_runtime",
        "sync_peer_count",
        "sync_peer_quorum",
        "public_testnet_peer_manifest_present",
        "public_testnet_peer_manifest_root",
        "public_testnet_peer_manifest_launch_package_bundle_root",
        "public_testnet_peer_manifest_snapshot_peer_count",
        "public_testnet_peer_manifest_sync_peer_quorum",
        "sync_successful_peer_count",
        "rpc_max_request_bytes",
        "rpc_max_requests_per_minute",
        "rpc_max_active_connections",
        "admin_rpc_max_active_connections",
        "sync_max_snapshot_response_bytes",
        "rpc_client_identity_mode",
        "rpc_client_identity_proxy_aware",
        "rpc_trust_private_proxy_headers",
        "rpc_trusted_proxy_count",
        "admin_rpc_enabled",
        "admin_rpc_private_listener",
        "public_rpc_admin_methods_enabled",
        "default_dev_sequencer_key",
        "gas_price_nebulai",
        "mempool_capacity_remaining",
        "bridge_policy_root",
        "bridge_custody_reconciled",
        "launch_binding_present",
        "launch_endpoint_url",
        "deployment_attestation_root",
        "public_status_manifest_root",
        "public_probe_root",
        "fee_policy_root",
        "validator_set_root",
        "operator_handoff_root",
        "operator_acceptance_root",
        "genesis_root",
        "launch_package_root",
        "launch_package_bundle_root",
        "launch_activation_height",
        "launch_validator_count",
        "launch_operator_count",
        "launch_region_count",
    ] {
        let backup_field = field;
        require_value_eq(
            errors,
            &format!("health.{field}"),
            health.get(field).unwrap_or(&Value::Null),
            ops.get(field).unwrap_or(&Value::Null),
        );
        require_value_eq(
            errors,
            &format!("backup.{backup_field}"),
            backup.get(backup_field).unwrap_or(&Value::Null),
            ops.get(field).unwrap_or(&Value::Null),
        );
    }
    require_value_eq(
        errors,
        "health.public_ops_ready",
        health.get("public_ops_ready").unwrap_or(&Value::Null),
        ops.get("public_ops_ready").unwrap_or(&Value::Null),
    );
    require_value_eq(
        errors,
        "health.public_ops_blocking_gaps",
        health
            .get("public_ops_blocking_gaps")
            .unwrap_or(&Value::Null),
        ops.get("blocking_gaps").unwrap_or(&Value::Null),
    );
}

fn require_metrics_agreement(
    errors: &mut Vec<String>,
    metrics_text: &str,
    status: &Value,
    snapshot: &runtime::RuntimeSnapshot,
) {
    let latest_height = snapshot.latest_height();
    require_metric_value(errors, metrics_text, "nebula_latest_height", latest_height);
    require_metric_value(
        errors,
        metrics_text,
        "nebula_sub_second_blocks",
        u8::from(json_bool(status, "sub_second_blocks").unwrap_or(false)),
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_gas_price_nebulai",
        status,
        "gas_price_nebulai",
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_launch_binding_present",
        u8::from(json_bool(status, "launch_binding_present").unwrap_or(false)),
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_launch_validator_count",
        status,
        "launch_validator_count",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_launch_operator_count",
        status,
        "launch_operator_count",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_launch_region_count",
        status,
        "launch_region_count",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_sync_peer_quorum",
        status,
        "sync_peer_quorum",
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_public_testnet_peer_manifest_present",
        u8::from(json_bool(status, "public_testnet_peer_manifest_present").unwrap_or(false)),
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_public_testnet_peer_manifest_snapshot_peer_count",
        status,
        "public_testnet_peer_manifest_snapshot_peer_count",
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_public_testnet_peer_manifest_sync_peer_quorum",
        status
            .get("public_testnet_peer_manifest_sync_peer_quorum")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_sync_quorum_met",
        u8::from(json_bool(status, "sync_quorum_met").unwrap_or(false)),
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_sync_quorum_peer_count",
        status,
        "sync_quorum_peer_count",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_sync_successful_peer_count",
        status,
        "sync_successful_peer_count",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_mempool_capacity_remaining",
        status,
        "mempool_capacity_remaining",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_total_nxmr_fees_units",
        status,
        "total_nxmr_fees_units",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_buyback_pool_nebulai",
        status,
        "buyback_pool_nebulai",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_validator_reward_nebulai",
        status,
        "validator_reward_nebulai",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_rpc_max_request_bytes",
        status,
        "rpc_max_request_bytes",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_rpc_max_requests_per_minute",
        status,
        "rpc_max_requests_per_minute",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_rpc_max_active_connections",
        status,
        "rpc_max_active_connections",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_admin_rpc_max_active_connections",
        status,
        "admin_rpc_max_active_connections",
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_sync_max_snapshot_response_bytes",
        status,
        "sync_max_snapshot_response_bytes",
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_rpc_client_identity_proxy_aware",
        u8::from(json_bool(status, "rpc_client_identity_proxy_aware").unwrap_or(false)),
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_rpc_trust_private_proxy_headers",
        u8::from(json_bool(status, "rpc_trust_private_proxy_headers").unwrap_or(false)),
    );
    require_metric_from_json(
        errors,
        metrics_text,
        "nebula_rpc_trusted_proxy_count",
        status,
        "rpc_trusted_proxy_count",
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_admin_rpc_enabled",
        u8::from(json_bool(status, "admin_rpc_enabled").unwrap_or(false)),
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_admin_rpc_private_listener",
        u8::from(json_bool(status, "admin_rpc_private_listener").unwrap_or(false)),
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_public_rpc_admin_methods_enabled",
        u8::from(json_bool(status, "public_rpc_admin_methods_enabled").unwrap_or(false)),
    );
    require_metric_value(
        errors,
        metrics_text,
        "nebula_default_dev_sequencer_key",
        u8::from(json_bool(status, "default_dev_sequencer_key").unwrap_or(false)),
    );
    require_metric_value(errors, metrics_text, "nebula_bridge_custody_reconciled", 1);
    require_metric_value(
        errors,
        metrics_text,
        "nebula_storage_snapshot_matches_runtime",
        1,
    );
    require_metric_value(errors, metrics_text, "nebula_public_ops_ready", 1);
    require_metric_value(
        errors,
        metrics_text,
        "nebula_public_ops_blocking_gap_count",
        0,
    );
}

fn require_metric_from_json(
    errors: &mut Vec<String>,
    metrics_text: &str,
    metric_name: &str,
    json: &Value,
    field: &str,
) {
    match json.get(field) {
        Some(value) => require_metric_value(errors, metrics_text, metric_name, value),
        None => errors.push(format!("{field} is missing from status JSON")),
    }
}

fn require_metric_value<T: ToString>(
    errors: &mut Vec<String>,
    metrics_text: &str,
    metric_name: &str,
    expected: T,
) {
    let expected = expected.to_string();
    match metric_value(metrics_text, metric_name) {
        Some(actual) if actual == expected => {}
        Some(actual) => errors.push(format!(
            "metric {metric_name} expected {expected} but got {actual}"
        )),
        None => errors.push(format!("metric {metric_name} is missing")),
    }
}

fn metric_value<'a>(metrics_text: &'a str, metric_name: &str) -> Option<&'a str> {
    metrics_text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some(name), Some(value)) if name == metric_name => Some(value),
            _ => None,
        }
    })
}

fn require_hex_root_from_value(errors: &mut Vec<String>, label: &str, value: Option<&Value>) {
    match value.and_then(Value::as_str) {
        Some(root) => require_hex_root(errors, label, root),
        None => errors.push(format!("{label} must be a 64-character hex root")),
    }
}

fn sample_public_status_manifest(
    launch_bundle_root: &str,
    endpoint_url: &str,
) -> PublicStatusManifest {
    let mut public_status_manifest = PublicStatusManifest {
        chain_id: CHAIN_ID.to_string(),
        status: "deployment-attested".to_string(),
        public_launch_ready: false,
        launch_bundle_root: launch_bundle_root.to_string(),
        endpoint_url: endpoint_url.to_string(),
        root: String::new(),
    };
    public_status_manifest.root = public_status_manifest_root(&public_status_manifest);
    public_status_manifest
}

fn sample_policy_claim(remediation_root: &str, economics_root: &str) -> PolicyClaim {
    let mut policy_claim = PolicyClaim {
        readiness_remediation_root: remediation_root.to_string(),
        economics_root: economics_root.to_string(),
        native_fee_token: NBLA_SYMBOL.to_string(),
        bridged_fee_token: NXMR_SYMBOL.to_string(),
        native_base_unit: NEBULAI_UNIT.to_string(),
        root: String::new(),
    };
    policy_claim.root = policy_claim_root(&policy_claim);
    policy_claim
}

fn sample_public_probe(url: &str, launch_bundle_root: &str, economics_root: &str) -> PublicProbe {
    let mut public_probe = PublicProbe {
        url: url.to_string(),
        status_code: 200,
        body: PublicProbeBody {
            chain_id: CHAIN_ID.to_string(),
            status: "deployment-attested".to_string(),
            public_launch_ready: false,
            launch_bundle_root: launch_bundle_root.to_string(),
            fee_policy_root: economics_root.to_string(),
        },
        root: String::new(),
    };
    public_probe.root = public_probe_root(&public_probe);
    public_probe
}

fn sample_receipt(receipt_id: &str, completed_at_unix_ms: u128) -> Receipt {
    let mut receipt = Receipt {
        receipt_id: receipt_id.to_string(),
        completed_at_unix_ms,
        phases: vec![ReceiptPhase {
            name: "launch-gate".to_string(),
            status: "passed".to_string(),
            steps: vec![
                ReceiptStep {
                    name: "build".to_string(),
                    status: "passed".to_string(),
                    evidence_sha3_256: hex_64(&format!("{receipt_id}-build")),
                },
                ReceiptStep {
                    name: "readiness".to_string(),
                    status: "passed".to_string(),
                    evidence_sha3_256: hex_64(&format!("{receipt_id}-readiness")),
                },
            ],
        }],
        root: String::new(),
    };
    receipt.root = receipt_root(&receipt);
    receipt
}

fn verify_package_identity(errors: &mut Vec<String>, package_identity: &PackageIdentity) {
    require_eq(
        errors,
        "package_identity.package_name",
        &package_identity.package_name,
        "nebula-testnet",
    );
    require_eq(
        errors,
        "package_identity.chain_id",
        &package_identity.chain_id,
        CHAIN_ID,
    );
    require_eq(
        errors,
        "package_identity.runtime_version",
        &package_identity.runtime_version,
        VERSION,
    );
    require_hex_root(
        errors,
        "package_identity.artifact_sha3_256",
        &package_identity.artifact_sha3_256,
    );
    require_hex_root(
        errors,
        "package_identity.cargo_lock_sha3_256",
        &package_identity.cargo_lock_sha3_256,
    );
    if package_identity.artifact_sha3_256 == package_identity.cargo_lock_sha3_256 {
        errors.push(
            "package_identity.cargo_lock_sha3_256 must differ from artifact_sha3_256".to_string(),
        );
    }
    require_root(
        errors,
        "package_identity.root",
        &package_identity.root,
        &package_identity_root(package_identity),
    );
}

fn verify_launch_bundle(
    errors: &mut Vec<String>,
    launch_bundle: &LaunchBundle,
    package_root: &str,
    runtime_root: &str,
    economics_root: &str,
) {
    require_eq(
        errors,
        "launch_bundle.bundle_id",
        &launch_bundle.bundle_id,
        PUBLIC_TESTNET_BUNDLE_ID,
    );
    require_eq(
        errors,
        "launch_bundle.chain_id",
        &launch_bundle.chain_id,
        CHAIN_ID,
    );
    require_eq(
        errors,
        "launch_bundle.package_root",
        &launch_bundle.package_root,
        package_root,
    );
    require_eq(
        errors,
        "launch_bundle.runtime_root",
        &launch_bundle.runtime_root,
        runtime_root,
    );
    require_eq(
        errors,
        "launch_bundle.economics_root",
        &launch_bundle.economics_root,
        economics_root,
    );
    require_root(
        errors,
        "launch_bundle.root",
        &launch_bundle.root,
        &launch_bundle_root(launch_bundle),
    );
}

fn verify_public_status_manifest(
    errors: &mut Vec<String>,
    public_status_manifest: &PublicStatusManifest,
    endpoint_url: &str,
    launch_bundle_root: &str,
) {
    require_eq(
        errors,
        "public_status_manifest.chain_id",
        &public_status_manifest.chain_id,
        CHAIN_ID,
    );
    require_eq(
        errors,
        "public_status_manifest.status",
        &public_status_manifest.status,
        "deployment-attested",
    );
    if public_status_manifest.public_launch_ready {
        errors.push(
            "public_status_manifest.public_launch_ready must remain false before final launch"
                .to_string(),
        );
    }
    require_eq(
        errors,
        "public_status_manifest.launch_bundle_root",
        &public_status_manifest.launch_bundle_root,
        launch_bundle_root,
    );
    require_eq(
        errors,
        "public_status_manifest.endpoint_url",
        &public_status_manifest.endpoint_url,
        endpoint_url,
    );
    require_https_endpoint(
        errors,
        "public_status_manifest.endpoint_url",
        &public_status_manifest.endpoint_url,
    );
    require_root(
        errors,
        "public_status_manifest.root",
        &public_status_manifest.root,
        &public_status_manifest_root(public_status_manifest),
    );
}

fn verify_public_endpoint(
    errors: &mut Vec<String>,
    public_endpoint: &PublicEndpointEvidence,
    public_status_manifest: &PublicStatusManifest,
    now: u128,
) {
    require_eq(
        errors,
        "public_endpoint.url",
        &public_endpoint.url,
        &public_status_manifest.endpoint_url,
    );
    require_https_endpoint(errors, "public_endpoint.url", &public_endpoint.url);
    require_eq(
        errors,
        "public_endpoint.public_status_manifest_root",
        &public_endpoint.public_status_manifest_root,
        &public_status_manifest.root,
    );
    if public_endpoint.tls_pins.is_empty() {
        errors.push("public_endpoint.tls_pins must not be empty".to_string());
    }
    let mut cert_pins = BTreeSet::new();
    let mut public_key_pins = BTreeSet::new();
    for (index, pin) in public_endpoint.tls_pins.iter().enumerate() {
        require_hex_root(
            errors,
            &format!("public_endpoint.tls_pins[{index}].cert_sha256"),
            &pin.cert_sha256,
        );
        require_hex_root(
            errors,
            &format!("public_endpoint.tls_pins[{index}].public_key_sha256"),
            &pin.public_key_sha256,
        );
        if pin.cert_sha256 == pin.public_key_sha256 {
            errors.push(format!(
                "public_endpoint.tls_pins[{index}].public_key_sha256 must differ from cert_sha256"
            ));
        }
        if public_key_pins.contains(&pin.cert_sha256) {
            errors.push(format!(
                "public_endpoint.tls_pins[{index}].cert_sha256 must not reuse a public_key_sha256"
            ));
        }
        if cert_pins.contains(&pin.public_key_sha256) {
            errors.push(format!(
                "public_endpoint.tls_pins[{index}].public_key_sha256 must not reuse a cert_sha256"
            ));
        }
        insert_unique(
            errors,
            &mut cert_pins,
            &format!("public_endpoint.tls_pins[{index}].cert_sha256"),
            &pin.cert_sha256,
        );
        insert_unique(
            errors,
            &mut public_key_pins,
            &format!("public_endpoint.tls_pins[{index}].public_key_sha256"),
            &pin.public_key_sha256,
        );
        if pin.not_after_unix_ms <= now {
            errors.push(format!(
                "public_endpoint.tls_pins[{index}].not_after_unix_ms is stale"
            ));
        } else if pin.not_after_unix_ms < now + MIN_TLS_PIN_VALIDITY_MS {
            errors.push(format!(
                "public_endpoint.tls_pins[{index}].not_after_unix_ms expires in less than seven days"
            ));
        }
    }
}

fn verify_policy_claim(
    errors: &mut Vec<String>,
    policy_claim: &PolicyClaim,
    remediation_root: &str,
    economics_root: &str,
) {
    require_eq(
        errors,
        "policy_claim.readiness_remediation_root",
        &policy_claim.readiness_remediation_root,
        remediation_root,
    );
    require_eq(
        errors,
        "policy_claim.economics_root",
        &policy_claim.economics_root,
        economics_root,
    );
    require_eq(
        errors,
        "policy_claim.native_fee_token",
        &policy_claim.native_fee_token,
        NBLA_SYMBOL,
    );
    require_eq(
        errors,
        "policy_claim.bridged_fee_token",
        &policy_claim.bridged_fee_token,
        NXMR_SYMBOL,
    );
    require_eq(
        errors,
        "policy_claim.native_base_unit",
        &policy_claim.native_base_unit,
        NEBULAI_UNIT,
    );
    require_root(
        errors,
        "policy_claim.root",
        &policy_claim.root,
        &policy_claim_root(policy_claim),
    );
}

fn verify_public_probe(
    errors: &mut Vec<String>,
    public_probe: &PublicProbe,
    endpoint_url: &str,
    launch_bundle_root: &str,
    economics_root: &str,
) {
    require_eq(errors, "public_probe.url", &public_probe.url, endpoint_url);
    require_https_endpoint(errors, "public_probe.url", &public_probe.url);
    if public_probe.status_code != 200 {
        errors.push(format!(
            "public_probe.status_code expected 200 but got {}",
            public_probe.status_code
        ));
    }
    require_eq(
        errors,
        "public_probe.body.chain_id",
        &public_probe.body.chain_id,
        CHAIN_ID,
    );
    require_eq(
        errors,
        "public_probe.body.status",
        &public_probe.body.status,
        "deployment-attested",
    );
    if public_probe.body.public_launch_ready {
        errors.push(
            "public_probe.body.public_launch_ready must remain false before final launch"
                .to_string(),
        );
    }
    require_eq(
        errors,
        "public_probe.body.launch_bundle_root",
        &public_probe.body.launch_bundle_root,
        launch_bundle_root,
    );
    require_eq(
        errors,
        "public_probe.body.fee_policy_root",
        &public_probe.body.fee_policy_root,
        economics_root,
    );
    require_root(
        errors,
        "public_probe.root",
        &public_probe.root,
        &public_probe_root(public_probe),
    );
}

fn verify_receipt_json(
    input: &str,
    expected_receipt_id: &str,
    label: &str,
) -> Result<ReceiptReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let receipt = serde_json::from_str::<Receipt>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let now = unix_ms();

    require_eq(
        &mut errors,
        "receipt_id",
        &receipt.receipt_id,
        expected_receipt_id,
    );
    verify_receipt(&mut errors, label, &receipt, now);

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    let step_count = receipt
        .phases
        .iter()
        .map(|phase| phase.steps.len())
        .sum::<usize>();

    Ok(ReceiptReport {
        receipt_ready: true,
        level: "receipt-attested",
        receipt_id: receipt.receipt_id,
        receipt_root: receipt.root,
        phase_count: receipt.phases.len(),
        step_count,
    })
}

fn verify_receipt(errors: &mut Vec<String>, label: &str, receipt: &Receipt, now: u128) {
    if receipt.completed_at_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push(format!(
            "{label}.completed_at_unix_ms is more than five minutes in the future"
        ));
    }
    if receipt.completed_at_unix_ms < now.saturating_sub(PUBLIC_ATTESTATION_MAX_AGE_MS) {
        errors.push(format!("{label}.completed_at_unix_ms is stale"));
    }
    if receipt.phases.is_empty() {
        errors.push(format!("{label}.phases must not be empty"));
    }
    let mut phase_names = BTreeSet::new();
    let mut step_evidence_roots = BTreeSet::new();
    for (phase_index, phase) in receipt.phases.iter().enumerate() {
        require_non_empty(
            errors,
            &format!("{label}.phases[{phase_index}].name"),
            &phase.name,
        );
        insert_unique(
            errors,
            &mut phase_names,
            &format!("{label}.phases[{phase_index}].name"),
            &phase.name,
        );
        require_eq(
            errors,
            &format!("{label}.phases[{phase_index}].status"),
            &phase.status,
            "passed",
        );
        if phase.steps.is_empty() {
            errors.push(format!(
                "{label}.phases[{phase_index}].steps must not be empty"
            ));
        }
        let mut step_names = BTreeSet::new();
        for (step_index, step) in phase.steps.iter().enumerate() {
            require_non_empty(
                errors,
                &format!("{label}.phases[{phase_index}].steps[{step_index}].name"),
                &step.name,
            );
            insert_unique(
                errors,
                &mut step_names,
                &format!("{label}.phases[{phase_index}].steps[{step_index}].name"),
                &step.name,
            );
            require_eq(
                errors,
                &format!("{label}.phases[{phase_index}].steps[{step_index}].status"),
                &step.status,
                "passed",
            );
            require_hex_root(
                errors,
                &format!("{label}.phases[{phase_index}].steps[{step_index}].evidence_sha3_256"),
                &step.evidence_sha3_256,
            );
            insert_unique(
                errors,
                &mut step_evidence_roots,
                &format!("{label}.phases[{phase_index}].steps[{step_index}].evidence_sha3_256"),
                &step.evidence_sha3_256,
            );
        }
    }
    require_root(
        errors,
        &format!("{label}.root"),
        &receipt.root,
        &receipt_root(receipt),
    );
}

fn verify_receipt_evidence_separation(
    errors: &mut Vec<String>,
    preflight_receipt: &Receipt,
    runbook_receipt: &Receipt,
) {
    let preflight_evidence_roots = preflight_receipt
        .phases
        .iter()
        .flat_map(|phase| phase.steps.iter())
        .map(|step| step.evidence_sha3_256.as_str())
        .collect::<BTreeSet<_>>();

    for (phase_index, phase) in runbook_receipt.phases.iter().enumerate() {
        for (step_index, step) in phase.steps.iter().enumerate() {
            if preflight_evidence_roots.contains(step.evidence_sha3_256.as_str()) {
                errors.push(format!(
                    "runbook_receipt.phases[{phase_index}].steps[{step_index}].evidence_sha3_256 must not reuse preflight_receipt evidence"
                ));
            }
        }
    }
}

fn verify_receipts_before_deployment_generation(
    errors: &mut Vec<String>,
    preflight_receipt: &Receipt,
    runbook_receipt: &Receipt,
    generated_at_unix_ms: u128,
) {
    if preflight_receipt.completed_at_unix_ms > generated_at_unix_ms {
        errors.push(
            "preflight_receipt.completed_at_unix_ms must be at or before generated_at_unix_ms"
                .to_string(),
        );
    }
    if runbook_receipt.completed_at_unix_ms > generated_at_unix_ms {
        errors.push(
            "runbook_receipt.completed_at_unix_ms must be at or before generated_at_unix_ms"
                .to_string(),
        );
    }
}

fn verify_deployment_component_root_domains(
    errors: &mut Vec<String>,
    attestation: &DeploymentAttestation,
) {
    let mut roots_by_value = BTreeMap::new();
    for (label, root) in [
        (
            "launch_bundle.root",
            attestation.launch_bundle.root.as_str(),
        ),
        (
            "public_status_manifest.root",
            attestation.public_status_manifest.root.as_str(),
        ),
        ("policy_claim.root", attestation.policy_claim.root.as_str()),
        ("public_probe.root", attestation.public_probe.root.as_str()),
    ] {
        if let Some(previous_label) = roots_by_value.insert(root, label) {
            errors.push(format!("{label} must differ from {previous_label}"));
        }
    }
}

fn verify_network_witnesses(errors: &mut Vec<String>, attestation: &DeploymentAttestation) {
    if attestation.bootstrap_nodes.len() < MIN_PUBLIC_TESTNET_VALIDATORS {
        errors.push("bootstrap_nodes must include at least two nodes".to_string());
    }
    if attestation.operators.len() < MIN_PUBLIC_TESTNET_OPERATORS {
        errors.push("operators must include at least two operators".to_string());
    }
    if attestation.observers.len() < MIN_PUBLIC_TESTNET_OBSERVERS {
        errors.push("observers must include at least two observers".to_string());
    }
    let witness_evidence_root = deployment_witness_root(
        &attestation.launch_bundle,
        &attestation.public_status_manifest,
        &attestation.public_endpoint,
        &attestation.policy_claim,
        &attestation.public_probe,
    );

    let regions = attestation
        .operators
        .iter()
        .map(|operator| operator.region.as_str())
        .chain(
            attestation
                .observers
                .iter()
                .map(|observer| observer.region.as_str()),
        )
        .collect::<BTreeSet<_>>();
    if regions.len() < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push("operators and observers must cover at least two regions".to_string());
    }

    let mut operator_ids = BTreeSet::new();
    let mut operator_keys = BTreeSet::new();
    let mut operator_regions = BTreeSet::new();
    let mut operator_regions_by_id = BTreeMap::new();
    for (index, operator) in attestation.operators.iter().enumerate() {
        require_non_empty(
            errors,
            &format!("operators[{index}].operator_id"),
            &operator.operator_id,
        );
        require_no_whitespace(
            errors,
            &format!("operators[{index}].operator_id"),
            &operator.operator_id,
        );
        require_non_empty(
            errors,
            &format!("operators[{index}].region"),
            &operator.region,
        );
        require_no_whitespace(
            errors,
            &format!("operators[{index}].region"),
            &operator.region,
        );
        require_non_empty(
            errors,
            &format!("operators[{index}].public_key"),
            &operator.public_key,
        );
        require_hex_value(
            errors,
            &format!("operators[{index}].public_key"),
            &operator.public_key,
        );
        operator_regions.insert(operator.region.clone());
        operator_regions_by_id.insert(operator.operator_id.clone(), operator.region.clone());
        insert_unique(
            errors,
            &mut operator_ids,
            &format!("operators[{index}].operator_id"),
            &operator.operator_id,
        );
        insert_unique(
            errors,
            &mut operator_keys,
            &format!("operators[{index}].public_key"),
            &operator.public_key,
        );
        require_hex_root(
            errors,
            &format!("operators[{index}].signed_evidence_root"),
            &operator.signed_evidence_root,
        );
        require_eq(
            errors,
            &format!("operators[{index}].signed_evidence_root"),
            &operator.signed_evidence_root,
            &witness_evidence_root,
        );
        require_hex_root(
            errors,
            &format!("operators[{index}].signature_sha3_256"),
            &operator.signature_sha3_256,
        );
        require_root(
            errors,
            &format!("operators[{index}].signature_sha3_256"),
            &operator.signature_sha3_256,
            &operator_signature_root(operator, &witness_evidence_root),
        );
    }
    if operator_ids.len() < MIN_PUBLIC_TESTNET_OPERATORS {
        errors.push(format!(
            "operators must include at least {MIN_PUBLIC_TESTNET_OPERATORS} unique operator_id values"
        ));
    }
    if operator_regions.len() < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push(format!(
            "operators must cover at least {MIN_PUBLIC_TESTNET_REGIONS} regions"
        ));
    }

    let mut bootstrap_node_ids = BTreeSet::new();
    let mut bootstrap_endpoints = BTreeSet::new();
    let mut bootstrap_endpoint_hosts = BTreeSet::new();
    let mut bootstrap_regions = BTreeSet::new();
    let public_endpoint_host = endpoint_host(&attestation.public_endpoint.url, "https://")
        .filter(|host| !host.trim().is_empty());
    for (index, node) in attestation.bootstrap_nodes.iter().enumerate() {
        require_non_empty(
            errors,
            &format!("bootstrap_nodes[{index}].node_id"),
            &node.node_id,
        );
        require_no_whitespace(
            errors,
            &format!("bootstrap_nodes[{index}].node_id"),
            &node.node_id,
        );
        if operator_ids.contains(&node.node_id) {
            errors.push(format!(
                "bootstrap_nodes[{index}].node_id must not reuse an operator_id"
            ));
        }
        require_non_empty(
            errors,
            &format!("bootstrap_nodes[{index}].operator_id"),
            &node.operator_id,
        );
        require_no_whitespace(
            errors,
            &format!("bootstrap_nodes[{index}].operator_id"),
            &node.operator_id,
        );
        require_non_empty(
            errors,
            &format!("bootstrap_nodes[{index}].region"),
            &node.region,
        );
        require_no_whitespace(
            errors,
            &format!("bootstrap_nodes[{index}].region"),
            &node.region,
        );
        require_non_empty(
            errors,
            &format!("bootstrap_nodes[{index}].endpoint"),
            &node.endpoint,
        );
        require_https_endpoint_without_path(
            errors,
            &format!("bootstrap_nodes[{index}].endpoint"),
            &node.endpoint,
        );
        if let Some(host) = endpoint_host(&node.endpoint, "https://") {
            if !host.trim().is_empty() {
                if Some(host) == public_endpoint_host {
                    errors.push(format!(
                        "bootstrap_nodes[{index}].endpoint.host must not reuse public_endpoint.url host"
                    ));
                }
                insert_unique(
                    errors,
                    &mut bootstrap_endpoint_hosts,
                    &format!("bootstrap_nodes[{index}].endpoint.host"),
                    host,
                );
            }
        }
        bootstrap_regions.insert(node.region.clone());
        insert_unique(
            errors,
            &mut bootstrap_node_ids,
            &format!("bootstrap_nodes[{index}].node_id"),
            &node.node_id,
        );
        insert_unique(
            errors,
            &mut bootstrap_endpoints,
            &format!("bootstrap_nodes[{index}].endpoint"),
            &node.endpoint,
        );
        if !operator_ids.contains(&node.operator_id) {
            errors.push(format!(
                "bootstrap_nodes[{index}].operator_id does not match an operator"
            ));
        }
        if let Some(operator_region) = operator_regions_by_id.get(&node.operator_id) {
            require_eq(
                errors,
                &format!("bootstrap_nodes[{index}].operator.region"),
                operator_region,
                &node.region,
            );
        }
        require_hex_root(
            errors,
            &format!("bootstrap_nodes[{index}].attestation_root"),
            &node.attestation_root,
        );
        require_root(
            errors,
            &format!("bootstrap_nodes[{index}].attestation_root"),
            &node.attestation_root,
            &bootstrap_node_root(node, &witness_evidence_root),
        );
    }
    if bootstrap_node_ids.len() < MIN_PUBLIC_TESTNET_VALIDATORS {
        errors.push(format!(
            "bootstrap_nodes must include at least {MIN_PUBLIC_TESTNET_VALIDATORS} unique node_id values"
        ));
    }
    if bootstrap_regions.len() < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push(format!(
            "bootstrap_nodes must cover at least {MIN_PUBLIC_TESTNET_REGIONS} regions"
        ));
    }

    let mut observer_ids = BTreeSet::new();
    let mut observer_keys = BTreeSet::new();
    let mut observer_regions = BTreeSet::new();
    for (index, observer) in attestation.observers.iter().enumerate() {
        require_non_empty(
            errors,
            &format!("observers[{index}].observer_id"),
            &observer.observer_id,
        );
        require_no_whitespace(
            errors,
            &format!("observers[{index}].observer_id"),
            &observer.observer_id,
        );
        require_non_empty(
            errors,
            &format!("observers[{index}].region"),
            &observer.region,
        );
        require_no_whitespace(
            errors,
            &format!("observers[{index}].region"),
            &observer.region,
        );
        insert_unique(
            errors,
            &mut observer_ids,
            &format!("observers[{index}].observer_id"),
            &observer.observer_id,
        );
        if operator_ids.contains(&observer.observer_id) {
            errors.push(format!(
                "observers[{index}].observer_id must not reuse an operator_id"
            ));
        }
        if bootstrap_node_ids.contains(&observer.observer_id) {
            errors.push(format!(
                "observers[{index}].observer_id must not reuse a bootstrap node_id"
            ));
        }
        observer_regions.insert(observer.region.clone());
        require_eq(
            errors,
            &format!("observers[{index}].observed_endpoint"),
            &observer.observed_endpoint,
            &attestation.public_endpoint.url,
        );
        require_hex_root(
            errors,
            &format!("observers[{index}].observed_evidence_root"),
            &observer.observed_evidence_root,
        );
        require_eq(
            errors,
            &format!("observers[{index}].observed_evidence_root"),
            &observer.observed_evidence_root,
            &witness_evidence_root,
        );
        require_eq(
            errors,
            &format!("observers[{index}].signature.algorithm"),
            &observer.signature.algorithm,
            "ed25519-testnet-attestation",
        );
        require_non_empty(
            errors,
            &format!("observers[{index}].signature.public_key"),
            &observer.signature.public_key,
        );
        require_hex_value(
            errors,
            &format!("observers[{index}].signature.public_key"),
            &observer.signature.public_key,
        );
        if operator_keys.contains(&observer.signature.public_key) {
            errors.push(format!(
                "observers[{index}].signature.public_key must not reuse an operator public_key"
            ));
        }
        insert_unique(
            errors,
            &mut observer_keys,
            &format!("observers[{index}].signature.public_key"),
            &observer.signature.public_key,
        );
        require_root(
            errors,
            &format!("observers[{index}].signature.signature_sha3_256"),
            &observer.signature.signature_sha3_256,
            &observer_signature_root(observer, &witness_evidence_root),
        );
        verify_signature_material(
            errors,
            &format!("observers[{index}].signature"),
            &observer.signature,
            "ed25519-testnet-attestation",
            &observer.signature.public_key,
            &observer_signature_root(observer, &witness_evidence_root),
        );
    }
    if observer_ids.len() < MIN_PUBLIC_TESTNET_OBSERVERS {
        errors.push(format!(
            "observers must include at least {MIN_PUBLIC_TESTNET_OBSERVERS} unique observer_id values"
        ));
    }
    if observer_regions.len() < MIN_PUBLIC_TESTNET_REGIONS {
        errors.push(format!(
            "observers must cover at least {MIN_PUBLIC_TESTNET_REGIONS} regions"
        ));
    }
}

fn verify_validator_deployment_binding(
    errors: &mut Vec<String>,
    validator_set: &ValidatorSetManifest,
    attestation: &DeploymentAttestation,
) {
    let operators_by_id = attestation
        .operators
        .iter()
        .map(|operator| (operator.operator_id.as_str(), operator))
        .collect::<BTreeMap<_, _>>();
    let bootstrap_nodes_by_id = attestation
        .bootstrap_nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut admitted_operator_ids = BTreeSet::new();
    let mut admitted_node_ids = BTreeSet::new();
    let deployment_witness_keys = attestation
        .operators
        .iter()
        .map(|operator| operator.public_key.as_str())
        .chain(
            attestation
                .observers
                .iter()
                .map(|observer| observer.signature.public_key.as_str()),
        )
        .collect::<BTreeSet<_>>();

    for (index, validator) in validator_set.validators.iter().enumerate() {
        admitted_operator_ids.insert(validator.operator_id.as_str());
        admitted_node_ids.insert(validator.node_id.as_str());

        if deployment_witness_keys.contains(validator.consensus_public_key.as_str()) {
            errors.push(format!(
                "validators[{index}].consensus_public_key must not reuse a deployment witness public key"
            ));
        }
        if deployment_witness_keys.contains(validator.network_public_key.as_str()) {
            errors.push(format!(
                "validators[{index}].network_public_key must not reuse a deployment witness public key"
            ));
        }

        match operators_by_id.get(validator.operator_id.as_str()) {
            Some(operator) => {
                require_eq(
                    errors,
                    &format!("validators[{index}].operator.region"),
                    &operator.region,
                    &validator.region,
                );
            }
            None => errors.push(format!(
                "validators[{index}].operator_id {} is not present in deployment operators",
                validator.operator_id
            )),
        }

        match bootstrap_nodes_by_id.get(validator.node_id.as_str()) {
            Some(node) => {
                require_eq(
                    errors,
                    &format!("validators[{index}].bootstrap_node.operator_id"),
                    &node.operator_id,
                    &validator.operator_id,
                );
                require_eq(
                    errors,
                    &format!("validators[{index}].bootstrap_node.region"),
                    &node.region,
                    &validator.region,
                );
                if let (Some(validator_host), Some(bootstrap_host)) = (
                    endpoint_host(&validator.p2p_endpoint, "tcp://"),
                    endpoint_host(&node.endpoint, "https://"),
                ) {
                    require_eq(
                        errors,
                        &format!("validators[{index}].p2p_endpoint.host"),
                        validator_host,
                        bootstrap_host,
                    );
                }
            }
            None => errors.push(format!(
                "validators[{index}].node_id {} is not present in deployment bootstrap_nodes",
                validator.node_id
            )),
        }
    }

    for (index, operator) in attestation.operators.iter().enumerate() {
        if !admitted_operator_ids.contains(operator.operator_id.as_str()) {
            errors.push(format!(
                "operators[{index}].operator_id {} has no admitted validator",
                operator.operator_id
            ));
        }
    }

    for (index, node) in attestation.bootstrap_nodes.iter().enumerate() {
        if !admitted_node_ids.contains(node.node_id.as_str()) {
            errors.push(format!(
                "bootstrap_nodes[{index}].node_id {} has no admitted validator",
                node.node_id
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_validator_admission(
    errors: &mut Vec<String>,
    index: usize,
    validator: &ValidatorAdmission,
    validator_ids: &mut BTreeSet<String>,
    operator_ids: &mut BTreeSet<String>,
    node_ids: &mut BTreeSet<String>,
    regions: &mut BTreeSet<String>,
    consensus_keys: &mut BTreeSet<String>,
    network_keys: &mut BTreeSet<String>,
    reward_accounts: &mut BTreeSet<String>,
    endpoints: &mut BTreeSet<String>,
    total_genesis_power: &mut u64,
    fee_policy_root: &str,
) {
    require_non_empty(
        errors,
        &format!("validators[{index}].validator_id"),
        &validator.validator_id,
    );
    require_no_whitespace(
        errors,
        &format!("validators[{index}].validator_id"),
        &validator.validator_id,
    );
    require_non_empty(
        errors,
        &format!("validators[{index}].operator_id"),
        &validator.operator_id,
    );
    require_no_whitespace(
        errors,
        &format!("validators[{index}].operator_id"),
        &validator.operator_id,
    );
    require_non_empty(
        errors,
        &format!("validators[{index}].node_id"),
        &validator.node_id,
    );
    require_no_whitespace(
        errors,
        &format!("validators[{index}].node_id"),
        &validator.node_id,
    );
    if validator.validator_id == validator.operator_id {
        errors.push(format!(
            "validators[{index}].validator_id must differ from operator_id"
        ));
    }
    if validator.validator_id == validator.node_id {
        errors.push(format!(
            "validators[{index}].validator_id must differ from node_id"
        ));
    }
    if validator.operator_id == validator.node_id {
        errors.push(format!(
            "validators[{index}].node_id must differ from operator_id"
        ));
    }
    require_non_empty(
        errors,
        &format!("validators[{index}].region"),
        &validator.region,
    );
    require_no_whitespace(
        errors,
        &format!("validators[{index}].region"),
        &validator.region,
    );
    require_non_empty(
        errors,
        &format!("validators[{index}].operator_contact"),
        &validator.operator_contact,
    );
    require_non_empty(
        errors,
        &format!("validators[{index}].consensus_public_key"),
        &validator.consensus_public_key,
    );
    require_hex_value(
        errors,
        &format!("validators[{index}].consensus_public_key"),
        &validator.consensus_public_key,
    );
    require_non_empty(
        errors,
        &format!("validators[{index}].network_public_key"),
        &validator.network_public_key,
    );
    require_hex_value(
        errors,
        &format!("validators[{index}].network_public_key"),
        &validator.network_public_key,
    );
    if validator.consensus_public_key == validator.network_public_key {
        errors.push(format!(
            "validators[{index}].network_public_key must differ from consensus_public_key"
        ));
    }
    if network_keys.contains(&validator.consensus_public_key) {
        errors.push(format!(
            "validators[{index}].consensus_public_key must not reuse a network_public_key"
        ));
    }
    if consensus_keys.contains(&validator.network_public_key) {
        errors.push(format!(
            "validators[{index}].network_public_key must not reuse a consensus_public_key"
        ));
    }
    require_non_empty(
        errors,
        &format!("validators[{index}].p2p_endpoint"),
        &validator.p2p_endpoint,
    );
    require_non_empty(
        errors,
        &format!("validators[{index}].reward_account"),
        &validator.reward_account,
    );
    if !validator.reward_account.starts_with("nbla-reward-") {
        errors.push(format!(
            "validators[{index}].reward_account must use the nbla-reward- prefix"
        ));
    }
    let expected_reward_account = format!("nbla-reward-{}", validator.operator_id);
    if validator.reward_account != expected_reward_account {
        errors.push(format!(
            "validators[{index}].reward_account expected {expected_reward_account} but got {}",
            validator.reward_account
        ));
    }
    require_tcp_endpoint_with_port(
        errors,
        &format!("validators[{index}].p2p_endpoint"),
        &validator.p2p_endpoint,
    );
    require_operator_contact(
        errors,
        &format!("validators[{index}].operator_contact"),
        &validator.operator_contact,
    );
    if validator.commission_bps > FEE_BASIS_POINTS as u16 {
        errors.push(format!(
            "validators[{index}].commission_bps must be <= {}",
            FEE_BASIS_POINTS
        ));
    }
    if validator.genesis_power == 0 {
        errors.push(format!(
            "validators[{index}].genesis_power must be greater than zero"
        ));
    }
    match total_genesis_power.checked_add(validator.genesis_power) {
        Some(total) => *total_genesis_power = total,
        None => errors.push("total genesis power overflowed u64".to_string()),
    }
    require_hex_root(
        errors,
        &format!("validators[{index}].signed_admission_root"),
        &validator.signed_admission_root,
    );
    require_root(
        errors,
        &format!("validators[{index}].signed_admission_root"),
        &validator.signed_admission_root,
        &validator_admission_signature_root(validator, fee_policy_root),
    );

    insert_unique(
        errors,
        validator_ids,
        &format!("validators[{index}].validator_id"),
        &validator.validator_id,
    );
    insert_unique(
        errors,
        node_ids,
        &format!("validators[{index}].node_id"),
        &validator.node_id,
    );
    insert_unique(
        errors,
        consensus_keys,
        &format!("validators[{index}].consensus_public_key"),
        &validator.consensus_public_key,
    );
    insert_unique(
        errors,
        network_keys,
        &format!("validators[{index}].network_public_key"),
        &validator.network_public_key,
    );
    insert_unique(
        errors,
        reward_accounts,
        &format!("validators[{index}].reward_account"),
        &validator.reward_account,
    );
    insert_unique(
        errors,
        endpoints,
        &format!("validators[{index}].p2p_endpoint"),
        &validator.p2p_endpoint,
    );

    insert_unique(
        errors,
        operator_ids,
        &format!("validators[{index}].operator_id"),
        &validator.operator_id,
    );
    regions.insert(validator.region.clone());
}

fn verify_validator_power_concentration(
    errors: &mut Vec<String>,
    validators: &[ValidatorAdmission],
    total_genesis_power: u64,
) {
    if total_genesis_power == 0 {
        return;
    }
    let total = u128::from(total_genesis_power);
    let mut operator_power_by_id = BTreeMap::new();
    for (index, validator) in validators.iter().enumerate() {
        let validator_power_bps =
            u128::from(validator.genesis_power).saturating_mul(FEE_BASIS_POINTS) / total;
        if validator_power_bps > MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS {
            errors.push(format!(
                "validators[{index}].genesis_power must not exceed {MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS} bps of total genesis power"
            ));
        }
        let operator_power = operator_power_by_id
            .entry(validator.operator_id.as_str())
            .or_insert(0_u128);
        *operator_power = operator_power.saturating_add(u128::from(validator.genesis_power));
    }
    for (operator_id, operator_power) in operator_power_by_id {
        let operator_power_bps = operator_power.saturating_mul(FEE_BASIS_POINTS) / total;
        if operator_power_bps > MAX_SINGLE_OPERATOR_GENESIS_POWER_BPS {
            errors.push(format!(
                "operator_id {operator_id} aggregate genesis_power must not exceed {MAX_SINGLE_OPERATOR_GENESIS_POWER_BPS} bps of total genesis power"
            ));
        }
    }
}

fn verify_rollback_evidence(
    errors: &mut Vec<String>,
    rollback_evidence: &RollbackEvidence,
    now: u128,
    generated_at_unix_ms: u128,
) {
    require_hex_root(
        errors,
        "rollback_evidence.rollback_plan_sha3_256",
        &rollback_evidence.rollback_plan_sha3_256,
    );
    if rollback_evidence.last_drill_unix_ms > now + FUTURE_CLOCK_SKEW_MS {
        errors.push(
            "rollback_evidence.last_drill_unix_ms is more than five minutes in the future"
                .to_string(),
        );
    }
    if rollback_evidence.last_drill_unix_ms < now.saturating_sub(ROLLBACK_DRILL_MAX_AGE_MS) {
        errors.push("rollback_evidence.last_drill_unix_ms is older than seven days".to_string());
    }
    if rollback_evidence.last_drill_unix_ms > generated_at_unix_ms {
        errors.push(
            "rollback_evidence.last_drill_unix_ms must be at or before generated_at_unix_ms"
                .to_string(),
        );
    }
    require_hex_root(
        errors,
        "rollback_evidence.recovery_point_root",
        &rollback_evidence.recovery_point_root,
    );
    if rollback_evidence.rollback_plan_sha3_256 == rollback_evidence.recovery_point_root {
        errors.push(
            "rollback_evidence.recovery_point_root must differ from rollback_plan_sha3_256"
                .to_string(),
        );
    }
}

fn package_identity_root(package_identity: &PackageIdentity) -> String {
    stable_root(&json!({
        "package_name": package_identity.package_name,
        "chain_id": package_identity.chain_id,
        "runtime_version": package_identity.runtime_version,
        "artifact_sha3_256": package_identity.artifact_sha3_256,
        "cargo_lock_sha3_256": package_identity.cargo_lock_sha3_256,
    }))
}

fn launch_bundle_root(launch_bundle: &LaunchBundle) -> String {
    stable_root(&json!({
        "bundle_id": launch_bundle.bundle_id,
        "chain_id": launch_bundle.chain_id,
        "package_root": launch_bundle.package_root,
        "runtime_root": launch_bundle.runtime_root,
        "economics_root": launch_bundle.economics_root,
    }))
}

fn public_status_manifest_root(public_status_manifest: &PublicStatusManifest) -> String {
    stable_root(&json!({
        "chain_id": public_status_manifest.chain_id,
        "status": public_status_manifest.status,
        "public_launch_ready": public_status_manifest.public_launch_ready,
        "launch_bundle_root": public_status_manifest.launch_bundle_root,
        "endpoint_url": public_status_manifest.endpoint_url,
    }))
}

fn policy_claim_root(policy_claim: &PolicyClaim) -> String {
    stable_root(&json!({
        "readiness_remediation_root": policy_claim.readiness_remediation_root,
        "economics_root": policy_claim.economics_root,
        "native_fee_token": policy_claim.native_fee_token,
        "bridged_fee_token": policy_claim.bridged_fee_token,
        "native_base_unit": policy_claim.native_base_unit,
    }))
}

fn public_probe_root(public_probe: &PublicProbe) -> String {
    stable_root(&json!({
        "url": public_probe.url,
        "status_code": public_probe.status_code,
        "body": public_probe.body,
    }))
}

fn deployment_witness_root(
    launch_bundle: &LaunchBundle,
    public_status_manifest: &PublicStatusManifest,
    public_endpoint: &PublicEndpointEvidence,
    policy_claim: &PolicyClaim,
    public_probe: &PublicProbe,
) -> String {
    stable_root(&json!({
        "chain_id": CHAIN_ID,
        "launch_bundle_root": launch_bundle.root,
        "public_status_manifest_root": public_status_manifest.root,
        "public_endpoint": public_endpoint,
        "policy_claim_root": policy_claim.root,
        "public_probe_root": public_probe.root,
    }))
}

fn bootstrap_node_root(node: &BootstrapNode, witness_evidence_root: &str) -> String {
    stable_root(&json!({
        "node_id": node.node_id,
        "operator_id": node.operator_id,
        "region": node.region,
        "endpoint": node.endpoint,
        "witness_evidence_root": witness_evidence_root,
    }))
}

fn operator_signature_root(operator: &OperatorAttestation, witness_evidence_root: &str) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-operator-witness-v1",
        "operator_id": operator.operator_id,
        "region": operator.region,
        "public_key": operator.public_key,
        "signed_evidence_root": witness_evidence_root,
    }))
}

fn observer_signature_root(observer: &ObserverAttestation, witness_evidence_root: &str) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-observer-witness-v1",
        "algorithm": observer.signature.algorithm,
        "observer_id": observer.observer_id,
        "region": observer.region,
        "public_key": observer.signature.public_key,
        "observed_endpoint": observer.observed_endpoint,
        "observed_evidence_root": witness_evidence_root,
    }))
}

fn deployment_public_surface_root(attestation: &DeploymentAttestation) -> String {
    let mut tls_pins = attestation
        .public_endpoint
        .tls_pins
        .iter()
        .map(|pin| {
            (
                pin.cert_sha256.as_str(),
                pin.public_key_sha256.as_str(),
                pin.not_after_unix_ms,
            )
        })
        .collect::<Vec<_>>();
    tls_pins.sort_unstable();
    let tls_pins = tls_pins
        .into_iter()
        .map(|(cert_sha256, public_key_sha256, not_after_unix_ms)| {
            json!({
                "cert_sha256": cert_sha256,
                "public_key_sha256": public_key_sha256,
                "not_after_unix_ms": not_after_unix_ms,
            })
        })
        .collect::<Vec<_>>();

    stable_root(&json!({
        "surface_domain": "nebula-deployment-public-surface-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "public_status_manifest_root": attestation.public_status_manifest.root,
        "public_endpoint_url": attestation.public_endpoint.url,
        "public_endpoint_status_manifest_root": attestation.public_endpoint.public_status_manifest_root,
        "tls_pins": tls_pins,
        "policy_claim_root": attestation.policy_claim.root,
        "public_probe_root": attestation.public_probe.root,
    }))
}

fn deployment_operator_approval_root(attestation: &DeploymentAttestation) -> String {
    let witness_evidence_root = deployment_witness_root(
        &attestation.launch_bundle,
        &attestation.public_status_manifest,
        &attestation.public_endpoint,
        &attestation.policy_claim,
        &attestation.public_probe,
    );
    let mut operators = attestation
        .operators
        .iter()
        .map(|operator| {
            (
                operator.operator_id.as_str(),
                operator.region.as_str(),
                operator.public_key.as_str(),
                operator.signed_evidence_root.as_str(),
                operator.signature_sha3_256.as_str(),
            )
        })
        .collect::<Vec<_>>();
    operators.sort_unstable();
    let operators = operators
        .into_iter()
        .map(
            |(operator_id, region, public_key, signed_evidence_root, signature_sha3_256)| {
                json!({
                    "operator_id": operator_id,
                    "region": region,
                    "public_key": public_key,
                    "signed_evidence_root": signed_evidence_root,
                    "signature_sha3_256": signature_sha3_256,
                })
            },
        )
        .collect::<Vec<_>>();

    stable_root(&json!({
        "approval_domain": "nebula-deployment-operator-approval-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "witness_evidence_root": witness_evidence_root,
        "operators": operators,
    }))
}

fn deployment_observer_confirmation_root(attestation: &DeploymentAttestation) -> String {
    let witness_evidence_root = deployment_witness_root(
        &attestation.launch_bundle,
        &attestation.public_status_manifest,
        &attestation.public_endpoint,
        &attestation.policy_claim,
        &attestation.public_probe,
    );
    let mut observers = attestation
        .observers
        .iter()
        .map(|observer| {
            (
                observer.observer_id.as_str(),
                observer.region.as_str(),
                observer.observed_endpoint.as_str(),
                observer.observed_evidence_root.as_str(),
                observer.signature.algorithm.as_str(),
                observer.signature.public_key.as_str(),
                observer.signature.signature_sha3_256.as_str(),
                observer.signature.signature_hex.as_str(),
                observer.signature.verified,
            )
        })
        .collect::<Vec<_>>();
    observers.sort_unstable();
    let observers = observers
        .into_iter()
        .map(
            |(
                observer_id,
                region,
                observed_endpoint,
                observed_evidence_root,
                algorithm,
                public_key,
                signature_sha3_256,
                signature_hex,
                verified,
            )| {
                json!({
                    "observer_id": observer_id,
                    "region": region,
                    "observed_endpoint": observed_endpoint,
                    "observed_evidence_root": observed_evidence_root,
                    "algorithm": algorithm,
                    "public_key": public_key,
                    "signature_sha3_256": signature_sha3_256,
                    "signature_hex": signature_hex,
                    "verified": verified,
                })
            },
        )
        .collect::<Vec<_>>();

    stable_root(&json!({
        "confirmation_domain": "nebula-deployment-observer-confirmation-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "witness_evidence_root": witness_evidence_root,
        "public_endpoint_url": attestation.public_endpoint.url,
        "observers": observers,
    }))
}

fn deployment_rollback_readiness_root(attestation: &DeploymentAttestation) -> String {
    stable_root(&json!({
        "rollback_domain": "nebula-deployment-rollback-readiness-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "generated_at_unix_ms": attestation.generated_at_unix_ms,
        "preflight_receipt_root": attestation.preflight_receipt.root,
        "runbook_receipt_root": attestation.runbook_receipt.root,
        "rollback_plan_sha3_256": attestation.rollback_evidence.rollback_plan_sha3_256,
        "rollback_last_drill_unix_ms": attestation.rollback_evidence.last_drill_unix_ms,
        "rollback_recovery_point_root": attestation.rollback_evidence.recovery_point_root,
    }))
}

fn deployment_validity_root(attestation: &DeploymentAttestation) -> String {
    let mut tls_pins = attestation
        .public_endpoint
        .tls_pins
        .iter()
        .map(|pin| {
            (
                pin.cert_sha256.as_str(),
                pin.public_key_sha256.as_str(),
                pin.not_after_unix_ms,
            )
        })
        .collect::<Vec<_>>();
    tls_pins.sort_unstable();
    let tls_pins = tls_pins
        .into_iter()
        .map(|(cert_sha256, public_key_sha256, not_after_unix_ms)| {
            json!({
                "cert_sha256": cert_sha256,
                "public_key_sha256": public_key_sha256,
                "not_after_unix_ms": not_after_unix_ms,
            })
        })
        .collect::<Vec<_>>();

    stable_root(&json!({
        "validity_domain": "nebula-deployment-validity-window-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "public_endpoint_url": attestation.public_endpoint.url,
        "generated_at_unix_ms": attestation.generated_at_unix_ms,
        "expires_at_unix_ms": attestation.expires_at_unix_ms,
        "max_attestation_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
        "max_attestation_ttl_ms": PUBLIC_ATTESTATION_MAX_TTL_MS,
        "minimum_tls_pin_validity_ms": MIN_TLS_PIN_VALIDITY_MS,
        "tls_pins": tls_pins,
    }))
}

fn deployment_quorum_root(attestation: &DeploymentAttestation) -> String {
    let bootstrap_regions = attestation
        .bootstrap_nodes
        .iter()
        .map(|node| node.region.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let operator_regions = attestation
        .operators
        .iter()
        .map(|operator| operator.region.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let observer_regions = attestation
        .observers
        .iter()
        .map(|observer| observer.region.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let deployment_regions = attestation
        .operators
        .iter()
        .map(|operator| operator.region.as_str())
        .chain(
            attestation
                .observers
                .iter()
                .map(|observer| observer.region.as_str()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    stable_root(&json!({
        "quorum_domain": "nebula-deployment-quorum-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "minimum_bootstrap_node_count": MIN_PUBLIC_TESTNET_VALIDATORS,
        "minimum_operator_count": MIN_PUBLIC_TESTNET_OPERATORS,
        "minimum_observer_count": MIN_PUBLIC_TESTNET_OBSERVERS,
        "minimum_region_count": MIN_PUBLIC_TESTNET_REGIONS,
        "bootstrap_node_count": attestation.bootstrap_nodes.len(),
        "operator_count": attestation.operators.len(),
        "observer_count": attestation.observers.len(),
        "deployment_region_count": deployment_regions.len(),
        "bootstrap_regions": bootstrap_regions,
        "operator_regions": operator_regions,
        "observer_regions": observer_regions,
        "deployment_regions": deployment_regions,
    }))
}

fn deployment_bootstrap_roster_root(attestation: &DeploymentAttestation) -> String {
    let mut nodes = attestation
        .bootstrap_nodes
        .iter()
        .map(|node| {
            (
                node.node_id.as_str(),
                node.operator_id.as_str(),
                node.region.as_str(),
                node.endpoint.as_str(),
            )
        })
        .collect::<Vec<_>>();
    nodes.sort_unstable();
    let nodes = nodes
        .into_iter()
        .map(|(node_id, operator_id, region, endpoint)| {
            json!({
                "node_id": node_id,
                "operator_id": operator_id,
                "region": region,
                "endpoint": endpoint,
            })
        })
        .collect::<Vec<_>>();

    stable_root(&json!({
        "roster_domain": "nebula-deployment-bootstrap-roster-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "nodes": nodes,
    }))
}

fn deployment_operational_evidence_root(attestation: &DeploymentAttestation) -> String {
    stable_root(&json!({
        "evidence_domain": "nebula-deployment-operational-evidence-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "preflight_receipt_root": attestation.preflight_receipt.root,
        "runbook_receipt_root": attestation.runbook_receipt.root,
        "rollback_plan_sha3_256": attestation.rollback_evidence.rollback_plan_sha3_256,
        "rollback_last_drill_unix_ms": attestation.rollback_evidence.last_drill_unix_ms,
        "rollback_recovery_point_root": attestation.rollback_evidence.recovery_point_root,
    }))
}

fn validator_admission_signature_root(
    validator: &ValidatorAdmission,
    fee_policy_root: &str,
) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-validator-admission-v1",
        "validator_id": validator.validator_id,
        "operator_id": validator.operator_id,
        "node_id": validator.node_id,
        "region": validator.region,
        "operator_contact": validator.operator_contact,
        "consensus_public_key": validator.consensus_public_key,
        "network_public_key": validator.network_public_key,
        "p2p_endpoint": validator.p2p_endpoint,
        "reward_account": validator.reward_account,
        "commission_bps": validator.commission_bps,
        "genesis_power": validator.genesis_power,
        "fee_policy_root": fee_policy_root,
        "reward_unit": NEBULAI_UNIT,
    }))
}

fn receipt_root(receipt: &Receipt) -> String {
    stable_root(&json!({
        "receipt_id": receipt.receipt_id,
        "completed_at_unix_ms": receipt.completed_at_unix_ms,
        "phases": receipt.phases,
    }))
}

fn validator_set_root(manifest: &ValidatorSetManifest) -> String {
    stable_root(&json!({
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "epoch": manifest.epoch,
        "reward_unit": manifest.reward_unit,
        "fee_policy_root": manifest.fee_policy_root,
        "minimum_validator_count": manifest.minimum_validator_count,
        "minimum_operator_count": manifest.minimum_operator_count,
        "minimum_region_count": manifest.minimum_region_count,
        "validators": manifest.validators,
    }))
}

fn validator_operator_roster_root(manifest: &ValidatorSetManifest) -> String {
    let mut operators = manifest
        .validators
        .iter()
        .map(|validator| {
            (
                validator.operator_id.as_str(),
                validator.validator_id.as_str(),
                validator.node_id.as_str(),
                validator.region.as_str(),
                validator.operator_contact.as_str(),
                validator.p2p_endpoint.as_str(),
                validator.commission_bps,
            )
        })
        .collect::<Vec<_>>();
    operators.sort_unstable();
    let operators = operators
        .into_iter()
        .map(
            |(
                operator_id,
                validator_id,
                node_id,
                region,
                operator_contact,
                p2p_endpoint,
                commission_bps,
            )| {
                json!({
                    "operator_id": operator_id,
                    "validator_id": validator_id,
                    "node_id": node_id,
                    "region": region,
                    "operator_contact": operator_contact,
                    "p2p_endpoint": p2p_endpoint,
                    "commission_bps": commission_bps,
                })
            },
        )
        .collect::<Vec<_>>();

    stable_root(&json!({
        "roster_domain": "nebula-validator-operator-roster-v1",
        "chain_id": manifest.chain_id,
        "epoch": manifest.epoch,
        "operators": operators,
    }))
}

fn validator_reward_ledger_root(manifest: &ValidatorSetManifest) -> String {
    let mut accounts = manifest
        .validators
        .iter()
        .map(|validator| {
            (
                validator.reward_account.as_str(),
                validator.operator_id.as_str(),
                validator.validator_id.as_str(),
            )
        })
        .collect::<Vec<_>>();
    accounts.sort_unstable();
    let accounts = accounts
        .into_iter()
        .map(|(reward_account, operator_id, validator_id)| {
            json!({
                "reward_account": reward_account,
                "operator_id": operator_id,
                "validator_id": validator_id,
            })
        })
        .collect::<Vec<_>>();

    stable_root(&json!({
        "ledger_domain": "nebula-validator-reward-ledger-v1",
        "chain_id": manifest.chain_id,
        "epoch": manifest.epoch,
        "reward_unit": manifest.reward_unit,
        "accounts": accounts,
    }))
}

fn validator_deployment_binding_root(
    attestation: &DeploymentAttestation,
    manifest: &ValidatorSetManifest,
) -> String {
    let bootstrap_nodes_by_id = attestation
        .bootstrap_nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let operators_by_id = attestation
        .operators
        .iter()
        .map(|operator| (operator.operator_id.as_str(), operator))
        .collect::<BTreeMap<_, _>>();
    let mut bindings = manifest
        .validators
        .iter()
        .map(|validator| {
            let operator = operators_by_id.get(validator.operator_id.as_str());
            let bootstrap_node = bootstrap_nodes_by_id.get(validator.node_id.as_str());
            json!({
                "validator_id": validator.validator_id,
                "operator_id": validator.operator_id,
                "node_id": validator.node_id,
                "region": validator.region,
                "p2p_endpoint": validator.p2p_endpoint,
                "p2p_host": endpoint_host(&validator.p2p_endpoint, "tcp://"),
                "consensus_public_key": validator.consensus_public_key,
                "network_public_key": validator.network_public_key,
                "reward_account": validator.reward_account,
                "genesis_power": validator.genesis_power,
                "operator_region": operator.map(|operator| operator.region.as_str()),
                "operator_public_key": operator.map(|operator| operator.public_key.as_str()),
                "bootstrap_region": bootstrap_node.map(|node| node.region.as_str()),
                "bootstrap_endpoint": bootstrap_node.map(|node| node.endpoint.as_str()),
                "bootstrap_endpoint_host": bootstrap_node
                    .and_then(|node| endpoint_host(&node.endpoint, "https://")),
                "bootstrap_attestation_root": bootstrap_node
                    .map(|node| node.attestation_root.as_str()),
            })
        })
        .collect::<Vec<_>>();
    bindings.sort_by_key(|left| left.to_string());

    stable_root(&json!({
        "binding_domain": "nebula-validator-deployment-binding-v1",
        "chain_id": attestation.chain_id,
        "launch_bundle_root": attestation.launch_bundle.root,
        "validator_set_root": manifest.root,
        "validator_set_epoch": manifest.epoch,
        "minimum_validator_count": MIN_PUBLIC_TESTNET_VALIDATORS,
        "minimum_operator_count": MIN_PUBLIC_TESTNET_OPERATORS,
        "minimum_region_count": MIN_PUBLIC_TESTNET_REGIONS,
        "bindings": bindings,
    }))
}

fn operator_handoff_manifest(
    attestation: &DeploymentAttestation,
    manifest: &ValidatorSetManifest,
) -> OperatorHandoffManifest {
    let bootstrap_nodes_by_id = attestation
        .bootstrap_nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let validator_deployment_binding_root =
        validator_deployment_binding_root(attestation, manifest);
    let mut entries = manifest
        .validators
        .iter()
        .map(|validator| {
            let bootstrap_node = bootstrap_nodes_by_id.get(validator.node_id.as_str());
            let mut entry = OperatorHandoffEntry {
                operator_id: validator.operator_id.clone(),
                validator_id: validator.validator_id.clone(),
                node_id: validator.node_id.clone(),
                region: validator.region.clone(),
                operator_contact: validator.operator_contact.clone(),
                bootstrap_endpoint: bootstrap_node
                    .map(|node| node.endpoint.clone())
                    .unwrap_or_default(),
                p2p_endpoint: validator.p2p_endpoint.clone(),
                reward_account: validator.reward_account.clone(),
                consensus_public_key: validator.consensus_public_key.clone(),
                network_public_key: validator.network_public_key.clone(),
                genesis_power: validator.genesis_power,
                signed_admission_root: validator.signed_admission_root.clone(),
                bootstrap_attestation_root: bootstrap_node
                    .map(|node| node.attestation_root.clone())
                    .unwrap_or_default(),
                handoff_root: String::new(),
            };
            entry.handoff_root = operator_handoff_entry_root(
                &entry,
                &attestation.launch_bundle.root,
                &manifest.root,
                &validator_deployment_binding_root,
            );
            entry
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        (
            left.operator_id.as_str(),
            left.validator_id.as_str(),
            left.node_id.as_str(),
        )
            .cmp(&(
                right.operator_id.as_str(),
                right.validator_id.as_str(),
                right.node_id.as_str(),
            ))
    });

    let mut handoff = OperatorHandoffManifest {
        chain_id: attestation.chain_id.clone(),
        runtime_version: attestation.runtime_version.clone(),
        launch_bundle_root: attestation.launch_bundle.root.clone(),
        validator_set_root: manifest.root.clone(),
        validator_set_epoch: manifest.epoch,
        validator_deployment_binding_root,
        entries,
        root: String::new(),
    };
    handoff.root = operator_handoff_manifest_root(&handoff);
    handoff
}

fn operator_handoff_entry_root(
    entry: &OperatorHandoffEntry,
    launch_bundle_root: &str,
    validator_set_root: &str,
    validator_deployment_binding_root: &str,
) -> String {
    stable_root(&json!({
        "handoff_entry_domain": "nebula-operator-handoff-entry-v1",
        "launch_bundle_root": launch_bundle_root,
        "validator_set_root": validator_set_root,
        "validator_deployment_binding_root": validator_deployment_binding_root,
        "operator_id": entry.operator_id,
        "validator_id": entry.validator_id,
        "node_id": entry.node_id,
        "region": entry.region,
        "operator_contact": entry.operator_contact,
        "bootstrap_endpoint": entry.bootstrap_endpoint,
        "p2p_endpoint": entry.p2p_endpoint,
        "reward_account": entry.reward_account,
        "consensus_public_key": entry.consensus_public_key,
        "network_public_key": entry.network_public_key,
        "genesis_power": entry.genesis_power,
        "signed_admission_root": entry.signed_admission_root,
        "bootstrap_attestation_root": entry.bootstrap_attestation_root,
    }))
}

fn operator_handoff_manifest_root(manifest: &OperatorHandoffManifest) -> String {
    stable_root(&json!({
        "handoff_domain": "nebula-operator-handoff-v1",
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "launch_bundle_root": manifest.launch_bundle_root,
        "validator_set_root": manifest.validator_set_root,
        "validator_set_epoch": manifest.validator_set_epoch,
        "validator_deployment_binding_root": manifest.validator_deployment_binding_root,
        "entries": manifest.entries,
    }))
}

fn operator_acceptance_manifest(
    handoff: &OperatorHandoffManifest,
    attestation: &DeploymentAttestation,
    accepted_at_unix_ms: u128,
) -> OperatorAcceptanceManifest {
    let operator_keys_by_id = attestation
        .operators
        .iter()
        .map(|operator| (operator.operator_id.as_str(), operator.public_key.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut entries = handoff
        .entries
        .iter()
        .map(|handoff_entry| {
            let operator_public_key = operator_keys_by_id
                .get(handoff_entry.operator_id.as_str())
                .copied()
                .unwrap_or_default()
                .to_string();
            let mut entry = OperatorAcceptanceEntry {
                operator_id: handoff_entry.operator_id.clone(),
                validator_id: handoff_entry.validator_id.clone(),
                node_id: handoff_entry.node_id.clone(),
                accepted_handoff_root: handoff_entry.handoff_root.clone(),
                operator_public_key,
                accepted: true,
                acceptance_root: String::new(),
                signature: SignatureVerification {
                    algorithm: "ed25519-testnet-operator-acceptance".to_string(),
                    public_key: String::new(),
                    signature_sha3_256: String::new(),
                    signature_hex: String::new(),
                    verified: false,
                },
            };
            entry.signature.public_key = entry.operator_public_key.clone();
            entry.acceptance_root = operator_acceptance_entry_root(
                &entry,
                &handoff.launch_bundle_root,
                &handoff.root,
                accepted_at_unix_ms,
            );
            entry.signature.signature_sha3_256 = operator_acceptance_signature_root(&entry);
            complete_sample_signature(&mut entry.signature);
            entry
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        (
            left.operator_id.as_str(),
            left.validator_id.as_str(),
            left.node_id.as_str(),
        )
            .cmp(&(
                right.operator_id.as_str(),
                right.validator_id.as_str(),
                right.node_id.as_str(),
            ))
    });

    let mut manifest = OperatorAcceptanceManifest {
        chain_id: handoff.chain_id.clone(),
        runtime_version: handoff.runtime_version.clone(),
        launch_bundle_root: handoff.launch_bundle_root.clone(),
        operator_handoff_root: handoff.root.clone(),
        accepted_at_unix_ms,
        entries,
        root: String::new(),
    };
    manifest.root = operator_acceptance_manifest_root(&manifest);
    manifest
}

fn operator_acceptance_entry_root(
    entry: &OperatorAcceptanceEntry,
    launch_bundle_root: &str,
    operator_handoff_root: &str,
    accepted_at_unix_ms: u128,
) -> String {
    stable_root(&json!({
        "acceptance_entry_domain": "nebula-operator-acceptance-entry-v1",
        "launch_bundle_root": launch_bundle_root,
        "operator_handoff_root": operator_handoff_root,
        "accepted_at_unix_ms": accepted_at_unix_ms,
        "operator_id": entry.operator_id,
        "validator_id": entry.validator_id,
        "node_id": entry.node_id,
        "accepted_handoff_root": entry.accepted_handoff_root,
        "operator_public_key": entry.operator_public_key,
        "accepted": entry.accepted,
    }))
}

fn operator_acceptance_signature_root(entry: &OperatorAcceptanceEntry) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-operator-acceptance-signature-v1",
        "algorithm": entry.signature.algorithm,
        "operator_id": entry.operator_id,
        "validator_id": entry.validator_id,
        "node_id": entry.node_id,
        "public_key": entry.signature.public_key,
        "acceptance_root": entry.acceptance_root,
        "accepted": entry.accepted,
    }))
}

fn operator_acceptance_manifest_root(manifest: &OperatorAcceptanceManifest) -> String {
    stable_root(&json!({
        "acceptance_domain": "nebula-operator-acceptance-v1",
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "launch_bundle_root": manifest.launch_bundle_root,
        "operator_handoff_root": manifest.operator_handoff_root,
        "accepted_at_unix_ms": manifest.accepted_at_unix_ms,
        "entries": manifest.entries,
    }))
}

#[allow(clippy::too_many_arguments)]
fn launch_package_bundle_manifest(
    generated_at_unix_ms: u128,
    launch_report: &LaunchPackageReport,
    acceptance_report: &OperatorAcceptanceReport,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> LaunchPackageBundleManifest {
    LaunchPackageBundleManifest {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        generated_at_unix_ms,
        deployment_attestation_root: launch_report.deployment_attestation_root.clone(),
        deployment_attestation_sha3_256: json_artifact_sha3_256(deployment_attestation_json),
        public_status_manifest_root: launch_report.public_status_manifest_root.clone(),
        public_status_sha3_256: json_artifact_sha3_256(public_status_json),
        public_probe_root: launch_report.public_probe_root.clone(),
        public_probe_sha3_256: json_artifact_sha3_256(public_probe_json),
        validator_set_root: launch_report.validator_set_root.clone(),
        validator_set_sha3_256: json_artifact_sha3_256(validator_set_json),
        operator_handoff_root: launch_report.operator_handoff_root.clone(),
        operator_handoff_sha3_256: json_artifact_sha3_256(operator_handoff_json),
        operator_acceptance_root: acceptance_report.operator_acceptance_root.clone(),
        operator_acceptance_sha3_256: json_artifact_sha3_256(operator_acceptance_json),
        genesis_root: launch_report.genesis_root.clone(),
        genesis_manifest_sha3_256: json_artifact_sha3_256(genesis_manifest_json),
        launch_package_root: launch_package_summary_root(launch_report, acceptance_report),
        root: String::new(),
    }
}

fn launch_package_summary_root(
    launch_report: &LaunchPackageReport,
    acceptance_report: &OperatorAcceptanceReport,
) -> String {
    stable_root(&json!({
        "launch_package_domain": "nebula-launch-package-v1",
        "chain_id": CHAIN_ID,
        "runtime_version": VERSION,
        "deployment_attestation_root": launch_report.deployment_attestation_root,
        "public_status_manifest_root": launch_report.public_status_manifest_root,
        "public_probe_root": launch_report.public_probe_root,
        "validator_set_root": launch_report.validator_set_root,
        "operator_handoff_root": launch_report.operator_handoff_root,
        "operator_acceptance_root": acceptance_report.operator_acceptance_root,
        "genesis_root": launch_report.genesis_root,
        "launch_bundle_root": launch_report.launch_bundle_root,
        "fee_policy_root": launch_report.fee_policy_root,
        "validator_deployment_binding_root": launch_report.validator_deployment_binding_root,
        "matched_validator_count": launch_report.matched_validator_count,
        "matched_operator_count": launch_report.matched_operator_count,
        "matched_region_count": launch_report.matched_region_count,
        "accepted_operator_count": acceptance_report.accepted_operator_count,
        "accepted_validator_count": acceptance_report.accepted_validator_count,
        "activation_height": launch_report.activation_height,
        "native_fee_token": launch_report.native_fee_token,
        "native_base_unit": launch_report.native_base_unit,
        "bridged_fee_token": launch_report.bridged_fee_token,
    }))
}

fn launch_package_bundle_root(manifest: &LaunchPackageBundleManifest) -> String {
    stable_root(&json!({
        "bundle_domain": "nebula-launch-package-bundle-v1",
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "generated_at_unix_ms": manifest.generated_at_unix_ms,
        "deployment_attestation_root": manifest.deployment_attestation_root,
        "deployment_attestation_sha3_256": manifest.deployment_attestation_sha3_256,
        "public_status_manifest_root": manifest.public_status_manifest_root,
        "public_status_sha3_256": manifest.public_status_sha3_256,
        "public_probe_root": manifest.public_probe_root,
        "public_probe_sha3_256": manifest.public_probe_sha3_256,
        "validator_set_root": manifest.validator_set_root,
        "validator_set_sha3_256": manifest.validator_set_sha3_256,
        "operator_handoff_root": manifest.operator_handoff_root,
        "operator_handoff_sha3_256": manifest.operator_handoff_sha3_256,
        "operator_acceptance_root": manifest.operator_acceptance_root,
        "operator_acceptance_sha3_256": manifest.operator_acceptance_sha3_256,
        "genesis_root": manifest.genesis_root,
        "genesis_manifest_sha3_256": manifest.genesis_manifest_sha3_256,
        "launch_package_root": manifest.launch_package_root,
    }))
}

#[allow(clippy::too_many_arguments)]
fn public_testnet_peer_manifest_from_jsons(
    generated_at_unix_ms: u128,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<PublicTestnetPeerManifest, AttestationError> {
    let launch_report = verify_launch_package_with_operator_acceptance_jsons(
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let bundle_report = verify_launch_package_bundle_jsons(
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let deployment_attestation =
        verified_deployment_attestation_manifest(deployment_attestation_json)?;
    let validator_set = verified_validator_set_manifest(validator_set_json)?;
    let bootstrap_nodes_by_id = deployment_attestation
        .bootstrap_nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut errors = Vec::new();
    let mut peers = Vec::new();

    for validator in &validator_set.validators {
        let Some(bootstrap_node) = bootstrap_nodes_by_id.get(validator.node_id.as_str()) else {
            errors.push(format!(
                "validator {} node_id {} is not present in deployment bootstrap_nodes",
                validator.validator_id, validator.node_id
            ));
            continue;
        };
        let bootstrap_endpoint = bootstrap_node.endpoint.trim_end_matches('/');
        peers.push(PublicTestnetPeer {
            validator_id: validator.validator_id.clone(),
            operator_id: validator.operator_id.clone(),
            node_id: validator.node_id.clone(),
            region: validator.region.clone(),
            p2p_endpoint: validator.p2p_endpoint.clone(),
            bootstrap_endpoint: bootstrap_node.endpoint.clone(),
            rpc_url: format!("{bootstrap_endpoint}/rpc"),
            status_url: format!("{bootstrap_endpoint}/status"),
            snapshot_url: format!("{bootstrap_endpoint}/snapshot"),
            consensus_public_key: validator.consensus_public_key.clone(),
            network_public_key: validator.network_public_key.clone(),
            reward_account: validator.reward_account.clone(),
            bootstrap_attestation_root: bootstrap_node.attestation_root.clone(),
        });
    }

    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    peers.sort_by(|left, right| {
        (
            left.operator_id.as_str(),
            left.validator_id.as_str(),
            left.node_id.as_str(),
        )
            .cmp(&(
                right.operator_id.as_str(),
                right.validator_id.as_str(),
                right.node_id.as_str(),
            ))
    });
    let sync_peer_quorum = peers.len().saturating_sub(1).max(1);
    let mut manifest = PublicTestnetPeerManifest {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        generated_at_unix_ms,
        endpoint_url: launch_report.endpoint_url,
        launch_package_bundle_root: bundle_report.launch_package_bundle_root,
        launch_package_root: bundle_report.launch_package_root,
        deployment_attestation_root: bundle_report.deployment_attestation_root,
        validator_set_root: bundle_report.validator_set_root,
        operator_handoff_root: bundle_report.operator_handoff_root,
        operator_acceptance_root: bundle_report.operator_acceptance_root,
        genesis_root: bundle_report.genesis_root,
        sync_peer_quorum,
        peers,
        root: String::new(),
    };
    manifest.root = public_testnet_peer_manifest_root(&manifest);
    Ok(manifest)
}

fn public_testnet_peer_manifest_root(manifest: &PublicTestnetPeerManifest) -> String {
    stable_root(&json!({
        "peer_manifest_domain": "nebula-public-testnet-peer-manifest-v1",
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "generated_at_unix_ms": manifest.generated_at_unix_ms,
        "endpoint_url": manifest.endpoint_url,
        "launch_package_bundle_root": manifest.launch_package_bundle_root,
        "launch_package_root": manifest.launch_package_root,
        "deployment_attestation_root": manifest.deployment_attestation_root,
        "validator_set_root": manifest.validator_set_root,
        "operator_handoff_root": manifest.operator_handoff_root,
        "operator_acceptance_root": manifest.operator_acceptance_root,
        "genesis_root": manifest.genesis_root,
        "sync_peer_quorum": manifest.sync_peer_quorum,
        "peers": manifest.peers,
    }))
}

fn validator_activation_manifest(
    bundle_report: &LaunchPackageBundleReport,
    acceptance_report: &OperatorAcceptanceReport,
    validator_set: &ValidatorSetManifest,
    activated_at_unix_ms: u128,
) -> ValidatorActivationManifest {
    let mut entries = validator_set
        .validators
        .iter()
        .map(|validator| {
            let mut entry = ValidatorActivationEntry {
                validator_id: validator.validator_id.clone(),
                operator_id: validator.operator_id.clone(),
                node_id: validator.node_id.clone(),
                p2p_endpoint: validator.p2p_endpoint.clone(),
                consensus_public_key: validator.consensus_public_key.clone(),
                network_public_key: validator.network_public_key.clone(),
                reward_account: validator.reward_account.clone(),
                launch_package_bundle_root: bundle_report.launch_package_bundle_root.clone(),
                operator_acceptance_root: acceptance_report.operator_acceptance_root.clone(),
                activated: true,
                activation_root: String::new(),
                signature: SignatureVerification {
                    algorithm: "ed25519-testnet-validator-activation".to_string(),
                    public_key: validator.consensus_public_key.clone(),
                    signature_sha3_256: String::new(),
                    signature_hex: String::new(),
                    verified: false,
                },
            };
            entry.activation_root = validator_activation_entry_root(
                &entry,
                &bundle_report.launch_package_bundle_root,
                &acceptance_report.operator_acceptance_root,
                activated_at_unix_ms,
            );
            entry.signature.signature_sha3_256 = validator_activation_signature_root(&entry);
            complete_sample_signature(&mut entry.signature);
            entry
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        (
            left.operator_id.as_str(),
            left.validator_id.as_str(),
            left.node_id.as_str(),
        )
            .cmp(&(
                right.operator_id.as_str(),
                right.validator_id.as_str(),
                right.node_id.as_str(),
            ))
    });

    ValidatorActivationManifest {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        launch_package_bundle_root: bundle_report.launch_package_bundle_root.clone(),
        launch_package_root: bundle_report.launch_package_root.clone(),
        validator_set_root: bundle_report.validator_set_root.clone(),
        operator_acceptance_root: acceptance_report.operator_acceptance_root.clone(),
        activated_at_unix_ms,
        entries,
        root: String::new(),
    }
}

fn validator_activation_entry_root(
    entry: &ValidatorActivationEntry,
    launch_package_bundle_root: &str,
    operator_acceptance_root: &str,
    activated_at_unix_ms: u128,
) -> String {
    stable_root(&json!({
        "activation_entry_domain": "nebula-validator-activation-entry-v1",
        "launch_package_bundle_root": launch_package_bundle_root,
        "operator_acceptance_root": operator_acceptance_root,
        "activated_at_unix_ms": activated_at_unix_ms,
        "validator_id": entry.validator_id,
        "operator_id": entry.operator_id,
        "node_id": entry.node_id,
        "p2p_endpoint": entry.p2p_endpoint,
        "consensus_public_key": entry.consensus_public_key,
        "network_public_key": entry.network_public_key,
        "reward_account": entry.reward_account,
        "activated": entry.activated,
    }))
}

fn validator_activation_signature_root(entry: &ValidatorActivationEntry) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-validator-activation-signature-v1",
        "algorithm": entry.signature.algorithm,
        "validator_id": entry.validator_id,
        "operator_id": entry.operator_id,
        "node_id": entry.node_id,
        "public_key": entry.signature.public_key,
        "activation_root": entry.activation_root,
        "activated": entry.activated,
    }))
}

fn validator_activation_manifest_root(manifest: &ValidatorActivationManifest) -> String {
    stable_root(&json!({
        "activation_domain": "nebula-validator-activation-v1",
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "launch_package_bundle_root": manifest.launch_package_bundle_root,
        "launch_package_root": manifest.launch_package_root,
        "validator_set_root": manifest.validator_set_root,
        "operator_acceptance_root": manifest.operator_acceptance_root,
        "activated_at_unix_ms": manifest.activated_at_unix_ms,
        "entries": manifest.entries,
    }))
}

fn validator_join_receipt(
    activation: &ValidatorActivationManifest,
    activation_report: &ValidatorActivationReport,
    activation_height: u64,
    joined_at_unix_ms: u128,
) -> ValidatorJoinReceipt {
    let peer_count = activation.entries.len().saturating_sub(1);
    let mut entries = activation
        .entries
        .iter()
        .map(|activation_entry| {
            let mut entry = ValidatorJoinEntry {
                validator_id: activation_entry.validator_id.clone(),
                operator_id: activation_entry.operator_id.clone(),
                node_id: activation_entry.node_id.clone(),
                p2p_endpoint: activation_entry.p2p_endpoint.clone(),
                consensus_public_key: activation_entry.consensus_public_key.clone(),
                activation_root: activation_entry.activation_root.clone(),
                launch_package_bundle_root: activation.launch_package_bundle_root.clone(),
                observed_block_height: activation_height,
                peer_count,
                joined: true,
                join_root: String::new(),
                signature: SignatureVerification {
                    algorithm: "ed25519-testnet-validator-join".to_string(),
                    public_key: activation_entry.consensus_public_key.clone(),
                    signature_sha3_256: String::new(),
                    signature_hex: String::new(),
                    verified: false,
                },
            };
            entry.join_root =
                validator_join_entry_root(&entry, activation_height, joined_at_unix_ms);
            entry.signature.signature_sha3_256 = validator_join_signature_root(&entry);
            complete_sample_signature(&mut entry.signature);
            entry
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        (
            left.operator_id.as_str(),
            left.validator_id.as_str(),
            left.node_id.as_str(),
        )
            .cmp(&(
                right.operator_id.as_str(),
                right.validator_id.as_str(),
                right.node_id.as_str(),
            ))
    });

    ValidatorJoinReceipt {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        validator_activation_root: activation_report.validator_activation_root.clone(),
        launch_package_bundle_root: activation_report.launch_package_bundle_root.clone(),
        launch_package_root: activation_report.launch_package_root.clone(),
        validator_set_root: activation_report.validator_set_root.clone(),
        joined_at_unix_ms,
        activation_height,
        entries,
        root: String::new(),
    }
}

fn verify_validator_join_entries(
    errors: &mut Vec<String>,
    receipt: &ValidatorJoinReceipt,
    activation: &ValidatorActivationManifest,
    activation_height: u64,
) {
    let expected_by_validator = activation
        .entries
        .iter()
        .map(|entry| (entry.validator_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut seen_validators = BTreeSet::new();
    let minimum_peer_count = activation.entries.len().saturating_sub(1);

    if receipt.entries.len() != activation.entries.len() {
        errors.push(format!(
            "entries expected {} validators but got {}",
            activation.entries.len(),
            receipt.entries.len()
        ));
    }

    for (index, entry) in receipt.entries.iter().enumerate() {
        insert_unique(
            errors,
            &mut seen_validators,
            &format!("entries[{index}].validator_id"),
            &entry.validator_id,
        );
        let Some(expected) = expected_by_validator.get(entry.validator_id.as_str()) else {
            errors.push(format!(
                "entries[{index}].validator_id {} is not activated",
                entry.validator_id
            ));
            continue;
        };
        require_eq(
            errors,
            &format!("entries[{index}].operator_id"),
            &entry.operator_id,
            &expected.operator_id,
        );
        require_eq(
            errors,
            &format!("entries[{index}].node_id"),
            &entry.node_id,
            &expected.node_id,
        );
        require_eq(
            errors,
            &format!("entries[{index}].p2p_endpoint"),
            &entry.p2p_endpoint,
            &expected.p2p_endpoint,
        );
        require_eq(
            errors,
            &format!("entries[{index}].consensus_public_key"),
            &entry.consensus_public_key,
            &expected.consensus_public_key,
        );
        require_root(
            errors,
            &format!("entries[{index}].activation_root"),
            &entry.activation_root,
            &expected.activation_root,
        );
        require_root(
            errors,
            &format!("entries[{index}].launch_package_bundle_root"),
            &entry.launch_package_bundle_root,
            &receipt.launch_package_bundle_root,
        );
        if entry.observed_block_height < activation_height {
            errors.push(format!(
                "entries[{index}].observed_block_height must be at least {activation_height}"
            ));
        }
        if entry.peer_count < minimum_peer_count {
            errors.push(format!(
                "entries[{index}].peer_count must be at least {minimum_peer_count}"
            ));
        }
        if !entry.joined {
            errors.push(format!("entries[{index}].joined must be true"));
        }
        require_root(
            errors,
            &format!("entries[{index}].join_root"),
            &entry.join_root,
            &validator_join_entry_root(entry, receipt.activation_height, receipt.joined_at_unix_ms),
        );
        verify_signature_material(
            errors,
            &format!("entries[{index}].signature"),
            &entry.signature,
            "ed25519-testnet-validator-join",
            &entry.consensus_public_key,
            &validator_join_signature_root(entry),
        );
    }
}

fn validator_join_entry_root(
    entry: &ValidatorJoinEntry,
    activation_height: u64,
    joined_at_unix_ms: u128,
) -> String {
    stable_root(&json!({
        "join_entry_domain": "nebula-validator-join-entry-v1",
        "activation_height": activation_height,
        "joined_at_unix_ms": joined_at_unix_ms,
        "validator_id": entry.validator_id,
        "operator_id": entry.operator_id,
        "node_id": entry.node_id,
        "p2p_endpoint": entry.p2p_endpoint,
        "consensus_public_key": entry.consensus_public_key,
        "activation_root": entry.activation_root,
        "launch_package_bundle_root": entry.launch_package_bundle_root,
        "observed_block_height": entry.observed_block_height,
        "peer_count": entry.peer_count,
        "joined": entry.joined,
    }))
}

fn validator_join_signature_root(entry: &ValidatorJoinEntry) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-validator-join-signature-v1",
        "algorithm": entry.signature.algorithm,
        "validator_id": entry.validator_id,
        "operator_id": entry.operator_id,
        "node_id": entry.node_id,
        "public_key": entry.signature.public_key,
        "join_root": entry.join_root,
        "joined": entry.joined,
    }))
}

fn validator_join_receipt_root(receipt: &ValidatorJoinReceipt) -> String {
    stable_root(&json!({
        "join_domain": "nebula-validator-join-v1",
        "chain_id": receipt.chain_id,
        "runtime_version": receipt.runtime_version,
        "validator_activation_root": receipt.validator_activation_root,
        "launch_package_bundle_root": receipt.launch_package_bundle_root,
        "launch_package_root": receipt.launch_package_root,
        "validator_set_root": receipt.validator_set_root,
        "joined_at_unix_ms": receipt.joined_at_unix_ms,
        "activation_height": receipt.activation_height,
        "entries": receipt.entries,
    }))
}

fn operator_join_confirmation_manifest(
    receipt: &ValidatorJoinReceipt,
    join_report: &ValidatorJoinReport,
    acceptance: &OperatorAcceptanceManifest,
    acceptance_report: &OperatorAcceptanceReport,
    attestation: &DeploymentAttestation,
    confirmed_at_unix_ms: u128,
) -> OperatorJoinConfirmationManifest {
    let operator_keys_by_id = attestation
        .operators
        .iter()
        .map(|operator| (operator.operator_id.as_str(), operator.public_key.as_str()))
        .collect::<BTreeMap<_, _>>();
    let accepted_by_operator_validator = acceptance
        .entries
        .iter()
        .map(|entry| {
            (
                (entry.operator_id.as_str(), entry.validator_id.as_str()),
                entry,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut entries = receipt
        .entries
        .iter()
        .map(|join_entry| {
            let accepted_entry = accepted_by_operator_validator.get(&(
                join_entry.operator_id.as_str(),
                join_entry.validator_id.as_str(),
            ));
            let node_id = accepted_entry
                .map(|entry| entry.node_id.clone())
                .unwrap_or_else(|| join_entry.node_id.clone());
            let operator_public_key = operator_keys_by_id
                .get(join_entry.operator_id.as_str())
                .copied()
                .unwrap_or_default()
                .to_string();
            let mut entry = OperatorJoinConfirmationEntry {
                operator_id: join_entry.operator_id.clone(),
                validator_id: join_entry.validator_id.clone(),
                node_id,
                confirmed_join_root: join_entry.join_root.clone(),
                validator_join_root: receipt.root.clone(),
                operator_public_key,
                confirmed: true,
                confirmation_root: String::new(),
                signature: SignatureVerification {
                    algorithm: "ed25519-testnet-operator-join-confirmation".to_string(),
                    public_key: String::new(),
                    signature_sha3_256: String::new(),
                    signature_hex: String::new(),
                    verified: false,
                },
            };
            entry.signature.public_key = entry.operator_public_key.clone();
            entry.confirmation_root = operator_join_confirmation_entry_root(
                &entry,
                &join_report.validator_join_root,
                &join_report.validator_activation_root,
                &join_report.launch_package_bundle_root,
                &acceptance_report.operator_acceptance_root,
                confirmed_at_unix_ms,
            );
            entry.signature.signature_sha3_256 = operator_join_confirmation_signature_root(&entry);
            complete_sample_signature(&mut entry.signature);
            entry
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        (
            left.operator_id.as_str(),
            left.validator_id.as_str(),
            left.node_id.as_str(),
        )
            .cmp(&(
                right.operator_id.as_str(),
                right.validator_id.as_str(),
                right.node_id.as_str(),
            ))
    });

    let mut manifest = OperatorJoinConfirmationManifest {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        validator_join_root: join_report.validator_join_root.clone(),
        validator_activation_root: join_report.validator_activation_root.clone(),
        launch_package_bundle_root: join_report.launch_package_bundle_root.clone(),
        operator_acceptance_root: acceptance_report.operator_acceptance_root.clone(),
        confirmed_at_unix_ms,
        entries,
        root: String::new(),
    };
    manifest.root = operator_join_confirmation_manifest_root(&manifest);
    manifest
}

fn operator_join_confirmation_entry_root(
    entry: &OperatorJoinConfirmationEntry,
    validator_join_root: &str,
    validator_activation_root: &str,
    launch_package_bundle_root: &str,
    operator_acceptance_root: &str,
    confirmed_at_unix_ms: u128,
) -> String {
    stable_root(&json!({
        "confirmation_entry_domain": "nebula-operator-join-confirmation-entry-v1",
        "validator_join_root": validator_join_root,
        "validator_activation_root": validator_activation_root,
        "launch_package_bundle_root": launch_package_bundle_root,
        "operator_acceptance_root": operator_acceptance_root,
        "confirmed_at_unix_ms": confirmed_at_unix_ms,
        "operator_id": entry.operator_id,
        "validator_id": entry.validator_id,
        "node_id": entry.node_id,
        "confirmed_join_root": entry.confirmed_join_root,
        "entry_validator_join_root": entry.validator_join_root,
        "operator_public_key": entry.operator_public_key,
        "confirmed": entry.confirmed,
    }))
}

fn operator_join_confirmation_signature_root(entry: &OperatorJoinConfirmationEntry) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-operator-join-confirmation-signature-v1",
        "algorithm": entry.signature.algorithm,
        "operator_id": entry.operator_id,
        "validator_id": entry.validator_id,
        "node_id": entry.node_id,
        "public_key": entry.signature.public_key,
        "confirmation_root": entry.confirmation_root,
        "confirmed": entry.confirmed,
    }))
}

fn operator_join_confirmation_manifest_root(manifest: &OperatorJoinConfirmationManifest) -> String {
    stable_root(&json!({
        "confirmation_domain": "nebula-operator-join-confirmation-v1",
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "validator_join_root": manifest.validator_join_root,
        "validator_activation_root": manifest.validator_activation_root,
        "launch_package_bundle_root": manifest.launch_package_bundle_root,
        "operator_acceptance_root": manifest.operator_acceptance_root,
        "confirmed_at_unix_ms": manifest.confirmed_at_unix_ms,
        "entries": manifest.entries,
    }))
}

fn public_observer_confirmation_manifest(
    attestation: &DeploymentAttestation,
    join_confirmation_report: &OperatorJoinConfirmationReport,
    public_status_report: &PublicStatusReport,
    public_probe_report: &PublicProbeReport,
    observed_at_unix_ms: u128,
) -> PublicObserverConfirmationManifest {
    let mut entries = attestation
        .observers
        .iter()
        .map(|observer| {
            let mut entry = PublicObserverConfirmationEntry {
                observer_id: observer.observer_id.clone(),
                region: observer.region.clone(),
                observed_endpoint: public_status_report.endpoint_url.clone(),
                observed_public_status_root: public_status_report
                    .public_status_manifest_root
                    .clone(),
                observed_public_probe_root: public_probe_report.public_probe_root.clone(),
                operator_join_confirmation_root: join_confirmation_report
                    .operator_join_confirmation_root
                    .clone(),
                observation_root: String::new(),
                signature: SignatureVerification {
                    algorithm: "ed25519-testnet-public-observer-confirmation".to_string(),
                    public_key: observer.signature.public_key.clone(),
                    signature_sha3_256: String::new(),
                    signature_hex: String::new(),
                    verified: false,
                },
            };
            entry.observation_root =
                public_observer_confirmation_entry_root(&entry, observed_at_unix_ms);
            entry.signature.signature_sha3_256 =
                public_observer_confirmation_signature_root(&entry);
            complete_sample_signature(&mut entry.signature);
            entry
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        (left.observer_id.as_str(), left.region.as_str())
            .cmp(&(right.observer_id.as_str(), right.region.as_str()))
    });

    let mut manifest = PublicObserverConfirmationManifest {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        operator_join_confirmation_root: join_confirmation_report
            .operator_join_confirmation_root
            .clone(),
        validator_join_root: join_confirmation_report.validator_join_root.clone(),
        public_status_manifest_root: public_status_report.public_status_manifest_root.clone(),
        public_probe_root: public_probe_report.public_probe_root.clone(),
        endpoint_url: public_status_report.endpoint_url.clone(),
        observed_at_unix_ms,
        entries,
        root: String::new(),
    };
    manifest.root = public_observer_confirmation_manifest_root(&manifest);
    manifest
}

fn public_observer_confirmation_entry_root(
    entry: &PublicObserverConfirmationEntry,
    observed_at_unix_ms: u128,
) -> String {
    stable_root(&json!({
        "observer_confirmation_entry_domain": "nebula-public-observer-confirmation-entry-v1",
        "observer_id": entry.observer_id,
        "region": entry.region,
        "observed_endpoint": entry.observed_endpoint,
        "observed_public_status_root": entry.observed_public_status_root,
        "observed_public_probe_root": entry.observed_public_probe_root,
        "operator_join_confirmation_root": entry.operator_join_confirmation_root,
        "observed_at_unix_ms": observed_at_unix_ms,
    }))
}

fn public_observer_confirmation_signature_root(entry: &PublicObserverConfirmationEntry) -> String {
    stable_root(&json!({
        "signature_domain": "nebula-public-observer-confirmation-signature-v1",
        "algorithm": entry.signature.algorithm,
        "observer_id": entry.observer_id,
        "region": entry.region,
        "public_key": entry.signature.public_key,
        "observation_root": entry.observation_root,
    }))
}

fn public_observer_confirmation_manifest_root(
    manifest: &PublicObserverConfirmationManifest,
) -> String {
    stable_root(&json!({
        "observer_confirmation_domain": "nebula-public-observer-confirmation-v1",
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "operator_join_confirmation_root": manifest.operator_join_confirmation_root,
        "validator_join_root": manifest.validator_join_root,
        "public_status_manifest_root": manifest.public_status_manifest_root,
        "public_probe_root": manifest.public_probe_root,
        "endpoint_url": manifest.endpoint_url,
        "observed_at_unix_ms": manifest.observed_at_unix_ms,
        "entries": manifest.entries,
    }))
}

#[allow(clippy::too_many_arguments)]
fn verified_launch_certificate_reports(
    public_observer_confirmation_json: &str,
    runtime_surface_evidence_json: &str,
    operator_join_confirmation_json: &str,
    validator_join_receipt_json: &str,
    validator_activation_json: &str,
    launch_package_bundle_json: &str,
    deployment_attestation_json: &str,
    public_status_json: &str,
    public_probe_json: &str,
    validator_set_json: &str,
    operator_handoff_json: &str,
    operator_acceptance_json: &str,
    genesis_manifest_json: &str,
) -> Result<LaunchCertificateReports, AttestationError> {
    let launch_package_bundle = verify_launch_package_bundle_jsons(
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let validator_activation = verify_validator_activation_jsons(
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let validator_join = verify_validator_join_receipt_jsons(
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let operator_join_confirmation = verify_operator_join_confirmation_jsons(
        operator_join_confirmation_json,
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let public_observer_confirmation = verify_public_observer_confirmation_jsons(
        public_observer_confirmation_json,
        operator_join_confirmation_json,
        validator_join_receipt_json,
        validator_activation_json,
        launch_package_bundle_json,
        deployment_attestation_json,
        public_status_json,
        public_probe_json,
        validator_set_json,
        operator_handoff_json,
        operator_acceptance_json,
        genesis_manifest_json,
    )?;
    let runtime_surface = verify_runtime_surface_evidence_json(runtime_surface_evidence_json)?;
    let genesis = verify_genesis_manifest_json(genesis_manifest_json)?;
    let deployment = verify_deployment_attestation_json(deployment_attestation_json)?;
    let public_probe = parse_public_probe_json(public_probe_json, "public_probe")?;
    let mut errors = Vec::new();
    require_eq(
        &mut errors,
        "runtime_surface.endpoint_url",
        &runtime_surface.endpoint_url,
        &public_observer_confirmation.endpoint_url,
    );
    require_root(
        &mut errors,
        "runtime_surface.launch_package_bundle_root",
        &runtime_surface.launch_package_bundle_root,
        &launch_package_bundle.launch_package_bundle_root,
    );
    require_root(
        &mut errors,
        "runtime_surface.launch_package_root",
        &runtime_surface.launch_package_root,
        &launch_package_bundle.launch_package_root,
    );
    require_root(
        &mut errors,
        "runtime_surface.fee_policy_root",
        &runtime_surface.fee_policy_root,
        &public_probe.body.fee_policy_root,
    );
    require_root(
        &mut errors,
        "runtime_surface.validator_set_root",
        &runtime_surface.validator_set_root,
        &launch_package_bundle.validator_set_root,
    );
    require_root(
        &mut errors,
        "runtime_surface.genesis_root",
        &runtime_surface.genesis_root,
        &genesis.genesis_root,
    );
    if !errors.is_empty() {
        return Err(AttestationError::Invalid(errors));
    }

    Ok(LaunchCertificateReports {
        launch_package_bundle,
        validator_activation,
        validator_join,
        operator_join_confirmation,
        public_observer_confirmation,
        runtime_surface,
        genesis,
        deployment,
    })
}

fn public_testnet_launch_certificate(
    reports: &LaunchCertificateReports,
    certified_at_unix_ms: u128,
) -> PublicTestnetLaunchCertificate {
    let mut certificate = PublicTestnetLaunchCertificate {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        launch_package_bundle_root: reports
            .launch_package_bundle
            .launch_package_bundle_root
            .clone(),
        launch_package_root: reports.launch_package_bundle.launch_package_root.clone(),
        fee_policy_root: reports.runtime_surface.fee_policy_root.clone(),
        validator_activation_root: reports
            .validator_activation
            .validator_activation_root
            .clone(),
        validator_join_root: reports.validator_join.validator_join_root.clone(),
        operator_join_confirmation_root: reports
            .operator_join_confirmation
            .operator_join_confirmation_root
            .clone(),
        public_observer_confirmation_root: reports
            .public_observer_confirmation
            .public_observer_confirmation_root
            .clone(),
        public_status_manifest_root: reports
            .public_observer_confirmation
            .public_status_manifest_root
            .clone(),
        public_probe_root: reports
            .public_observer_confirmation
            .public_probe_root
            .clone(),
        runtime_surface_root: reports.runtime_surface.runtime_surface_root.clone(),
        validator_set_root: reports.launch_package_bundle.validator_set_root.clone(),
        genesis_root: reports.genesis.genesis_root.clone(),
        endpoint_url: reports.public_observer_confirmation.endpoint_url.clone(),
        certified_at_unix_ms,
        validator_count: reports.validator_join.joined_validator_count,
        operator_count: reports.operator_join_confirmation.confirmed_operator_count,
        observer_count: reports
            .public_observer_confirmation
            .confirmed_observer_count,
        region_count: reports.deployment.verified_region_count,
        root: String::new(),
    };
    certificate.root = public_testnet_launch_certificate_root(&certificate);
    certificate
}

fn public_testnet_launch_certificate_root(certificate: &PublicTestnetLaunchCertificate) -> String {
    stable_root(&json!({
        "launch_certificate_domain": "nebula-public-testnet-launch-certificate-v1",
        "chain_id": certificate.chain_id,
        "runtime_version": certificate.runtime_version,
        "launch_package_bundle_root": certificate.launch_package_bundle_root,
        "launch_package_root": certificate.launch_package_root,
        "fee_policy_root": certificate.fee_policy_root,
        "validator_activation_root": certificate.validator_activation_root,
        "validator_join_root": certificate.validator_join_root,
        "operator_join_confirmation_root": certificate.operator_join_confirmation_root,
        "public_observer_confirmation_root": certificate.public_observer_confirmation_root,
        "public_status_manifest_root": certificate.public_status_manifest_root,
        "public_probe_root": certificate.public_probe_root,
        "runtime_surface_root": certificate.runtime_surface_root,
        "validator_set_root": certificate.validator_set_root,
        "genesis_root": certificate.genesis_root,
        "endpoint_url": certificate.endpoint_url,
        "certified_at_unix_ms": certificate.certified_at_unix_ms,
        "validator_count": certificate.validator_count,
        "operator_count": certificate.operator_count,
        "observer_count": certificate.observer_count,
        "region_count": certificate.region_count,
    }))
}

fn public_testnet_launch_readiness_root(report: &PublicTestnetLaunchReadinessReport) -> String {
    stable_root(&json!({
        "launch_readiness_domain": "nebula-public-testnet-launch-readiness-v1",
        "level": report.level,
        "public_launch_ready": report.public_launch_ready,
        "blocking_gaps": report.blocking_gaps,
        "satisfied_attestation": report.satisfied_attestation,
        "public_testnet_launch_certificate_root": report.public_testnet_launch_certificate_root,
        "deployment_attestation_root": report.deployment_attestation_root,
        "launch_package_bundle_root": report.launch_package_bundle_root,
        "launch_package_root": report.launch_package_root,
        "fee_policy_root": report.fee_policy_root,
        "validator_activation_root": report.validator_activation_root,
        "validator_join_root": report.validator_join_root,
        "operator_join_confirmation_root": report.operator_join_confirmation_root,
        "public_observer_confirmation_root": report.public_observer_confirmation_root,
        "public_status_manifest_root": report.public_status_manifest_root,
        "public_probe_root": report.public_probe_root,
        "runtime_surface_root": report.runtime_surface_root,
        "runtime_surface_capture_mode": report.runtime_surface_capture_mode,
        "live_rpc_devnet_rehearsal_root": report.live_rpc_devnet_rehearsal_root,
        "live_rpc_devnet_runtime_surface_root": report.live_rpc_devnet_runtime_surface_root,
        "validator_set_root": report.validator_set_root,
        "genesis_root": report.genesis_root,
        "endpoint_url": report.endpoint_url,
        "validator_count": report.validator_count,
        "operator_count": report.operator_count,
        "observer_count": report.observer_count,
        "region_count": report.region_count,
        "certified_at_unix_ms": report.certified_at_unix_ms,
        "generated_at_unix_ms": report.generated_at_unix_ms,
    }))
}

fn public_testnet_launch_readiness_rejection_root(
    report: &PublicTestnetLaunchReadinessRejectionReport,
) -> String {
    stable_root(&json!({
        "launch_readiness_rejection_domain": "nebula-public-testnet-launch-readiness-rejection-v1",
        "level": report.level,
        "public_launch_ready": report.public_launch_ready,
        "blocking_gaps": report.blocking_gaps,
        "errors": report.errors,
        "required_attestation": report.required_attestation,
        "generated_at_unix_ms": report.generated_at_unix_ms,
    }))
}

fn genesis_manifest_root(manifest: &GenesisManifest) -> String {
    stable_root(&json!({
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "genesis_time_unix_ms": manifest.genesis_time_unix_ms,
        "activation_height": manifest.activation_height,
        "deployment_attestation_root": manifest.deployment_attestation_root,
        "public_surface_root": manifest.public_surface_root,
        "operator_approval_root": manifest.operator_approval_root,
        "observer_confirmation_root": manifest.observer_confirmation_root,
        "rollback_readiness_root": manifest.rollback_readiness_root,
        "deployment_validity_root": manifest.deployment_validity_root,
        "deployment_quorum_root": manifest.deployment_quorum_root,
        "bootstrap_roster_root": manifest.bootstrap_roster_root,
        "operational_evidence_root": manifest.operational_evidence_root,
        "validator_set_root": manifest.validator_set_root,
        "validator_set_epoch": manifest.validator_set_epoch,
        "fee_policy_root": manifest.fee_policy_root,
        "validator_admission_root": manifest.validator_admission_root,
        "operator_roster_root": manifest.operator_roster_root,
        "reward_ledger_root": manifest.reward_ledger_root,
        "validator_deployment_binding_root": manifest.validator_deployment_binding_root,
        "initial_validator_count": manifest.initial_validator_count,
        "initial_operator_count": manifest.initial_operator_count,
        "initial_region_count": manifest.initial_region_count,
        "initial_total_power": manifest.initial_total_power,
        "native_fee_token": manifest.native_fee_token,
        "native_base_unit": manifest.native_base_unit,
        "bridged_fee_token": manifest.bridged_fee_token,
    }))
}

fn require_eq(errors: &mut Vec<String>, label: &str, actual: &str, expected: &str) {
    if actual != expected {
        errors.push(format!("{label} expected {} but got {}", expected, actual));
    }
}

fn require_root(errors: &mut Vec<String>, label: &str, actual: &str, expected: &str) {
    require_hex_root(errors, label, actual);
    if actual != expected {
        errors.push(format!("{label} does not match expected root {expected}"));
    }
}

fn require_hex_root(errors: &mut Vec<String>, label: &str, value: &str) {
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        errors.push(format!("{label} must be a 64-character hex root"));
    }
}

fn require_hex_value(errors: &mut Vec<String>, label: &str, value: &str) {
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        errors.push(format!("{label} must be a 64-character hex value"));
    }
}

fn require_signature_hex(errors: &mut Vec<String>, label: &str, value: &str) {
    if value.len() != 128 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        errors.push(format!(
            "{label} must be a 128-character hex Ed25519 signature"
        ));
    }
}

fn decode_fixed_hex(value: &str, label: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let decoded = hex::decode(value).map_err(|error| format!("{label} must be hex: {error}"))?;
    if decoded.len() != expected_len {
        return Err(format!("{label} must decode to {expected_len} bytes"));
    }
    Ok(decoded)
}

fn verifying_key_from_hex(public_key_hex: &str, label: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_fixed_hex(public_key_hex, label, 32)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{label} must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| format!("{label} is not an Ed25519 key: {error}"))
}

fn verify_ed25519_signature(
    public_key_hex: &str,
    signing_root: &str,
    signature_hex: &str,
    signature_label: &str,
) -> Result<(), String> {
    if signing_root.len() != 64 || !signing_root.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("signing root must be a 64-character hex root".to_string());
    }
    let verifying_key = verifying_key_from_hex(public_key_hex, "public_key")?;
    let signature_bytes = decode_fixed_hex(signature_hex, signature_label, 64)?;
    let signature_bytes: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{signature_label} must decode to 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(signing_root.as_bytes(), &signature)
        .map_err(|error| format!("{signature_label} Ed25519 verification failed: {error}"))
}

fn verify_signature_material(
    errors: &mut Vec<String>,
    label: &str,
    signature: &SignatureVerification,
    expected_algorithm: &str,
    expected_public_key: &str,
    expected_signature_root: &str,
) {
    require_eq(
        errors,
        &format!("{label}.algorithm"),
        &signature.algorithm,
        expected_algorithm,
    );
    require_eq(
        errors,
        &format!("{label}.public_key"),
        &signature.public_key,
        expected_public_key,
    );
    require_hex_value(
        errors,
        &format!("{label}.public_key"),
        &signature.public_key,
    );
    require_root(
        errors,
        &format!("{label}.signature_sha3_256"),
        &signature.signature_sha3_256,
        expected_signature_root,
    );
    require_signature_hex(
        errors,
        &format!("{label}.signature_hex"),
        &signature.signature_hex,
    );
    if !signature.verified {
        errors.push(format!("{label}.verified must be true"));
    }
    if let Err(error) = verify_ed25519_signature(
        &signature.public_key,
        expected_signature_root,
        &signature.signature_hex,
        &format!("{label}.signature_hex"),
    ) {
        errors.push(error);
    }
}

fn require_https_endpoint(errors: &mut Vec<String>, label: &str, endpoint: &str) {
    let scheme = "https://";
    if !endpoint.starts_with(scheme) {
        errors.push(format!("{label} must use an https:// endpoint"));
        return;
    }
    require_endpoint_authority(errors, label, endpoint, scheme);
}

fn require_https_endpoint_without_path(errors: &mut Vec<String>, label: &str, endpoint: &str) {
    let scheme = "https://";
    if !endpoint.starts_with(scheme) {
        errors.push(format!("{label} must use an https:// endpoint"));
        return;
    }
    let Some(_authority) = require_endpoint_authority(errors, label, endpoint, scheme) else {
        return;
    };
    let remainder = endpoint.strip_prefix(scheme).unwrap_or_default();
    if remainder.contains('/') {
        errors.push(format!("{label} must not include a path"));
    }
}

fn require_tcp_endpoint_with_port(errors: &mut Vec<String>, label: &str, endpoint: &str) {
    let scheme = "tcp://";
    if !endpoint.starts_with(scheme) {
        errors.push(format!("{label} must use a tcp:// endpoint"));
        return;
    }
    let Some(authority) = require_endpoint_authority(errors, label, endpoint, scheme) else {
        return;
    };
    let remainder = endpoint.strip_prefix(scheme).unwrap_or_default();
    if remainder.contains('/') {
        errors.push(format!("{label} must not include a path"));
        return;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        errors.push(format!("{label} must include a numeric port"));
        return;
    };
    if host.trim().is_empty()
        || port.trim().is_empty()
        || !port.chars().all(|character| character.is_ascii_digit())
        || port.parse::<u16>().ok().filter(|port| *port > 0).is_none()
    {
        errors.push(format!("{label} must include a numeric port"));
    }
}

fn require_operator_contact(errors: &mut Vec<String>, label: &str, contact: &str) {
    if let Some(address) = contact.strip_prefix("mailto:") {
        if address.trim().is_empty()
            || address.chars().any(char::is_whitespace)
            || !address.contains('@')
        {
            errors.push(format!(
                "{label} must include an email address after mailto:"
            ));
        }
        if address.contains('?') || address.contains('#') {
            errors.push(format!("{label} must not include query or fragment"));
        }
        if address.contains(',') || address.contains(';') || address.matches('@').count() != 1 {
            errors.push(format!("{label} must include exactly one mailto address"));
        }
        return;
    }
    if contact.starts_with("https://") {
        require_https_endpoint(errors, label, contact);
        return;
    }
    errors.push(format!("{label} must use mailto: or https://"));
}

fn require_endpoint_authority<'a>(
    errors: &mut Vec<String>,
    label: &str,
    endpoint: &'a str,
    scheme: &str,
) -> Option<&'a str> {
    let remainder = endpoint.strip_prefix(scheme).unwrap_or_default();
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.trim().is_empty() || authority.chars().any(char::is_whitespace) {
        errors.push(format!("{label} must include a host after {scheme}"));
        return None;
    }
    if authority.contains('@') {
        errors.push(format!("{label} must not include userinfo"));
        return None;
    }
    if let Some((_host, port)) = authority.rsplit_once(':') {
        if port.trim().is_empty()
            || !port.chars().all(|character| character.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|port| *port > 0).is_none()
        {
            errors.push(format!(
                "{label} must include a numeric port when a port is present"
            ));
            return None;
        }
    }
    if remainder.contains('?') || remainder.contains('#') {
        errors.push(format!("{label} must not include query or fragment"));
        return None;
    }
    Some(authority)
}

fn endpoint_host<'a>(endpoint: &'a str, scheme: &str) -> Option<&'a str> {
    let authority = endpoint
        .strip_prefix(scheme)?
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if scheme == "tcp://" {
        return authority.rsplit_once(':').map(|(host, _port)| host);
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|character| character.is_ascii_digit()) {
            return Some(host);
        }
    }
    Some(authority)
}

fn require_non_empty(errors: &mut Vec<String>, label: &str, value: &str) {
    if value.trim().is_empty() {
        errors.push(format!("{label} must not be empty"));
    }
}

fn require_no_whitespace(errors: &mut Vec<String>, label: &str, value: &str) {
    if value.chars().any(char::is_whitespace) {
        errors.push(format!("{label} must not contain whitespace"));
    }
}

fn insert_unique(errors: &mut Vec<String>, seen: &mut BTreeSet<String>, label: &str, value: &str) {
    if !seen.insert(value.to_string()) {
        errors.push(format!("{label} must be unique"));
    }
}

fn hex_64(label: &str) -> String {
    stable_root(&json!({ "sample": label }))
}

fn sample_ed25519_public_key_hex(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn sample_ed25519_secret_key_hex(seed: u8) -> String {
    hex::encode([seed; 32])
}

fn sign_root_with_secret_key(secret_key_hex: &str, signing_root: &str) -> Result<String, String> {
    if signing_root.len() != 64 || !signing_root.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("signing root must be a 64-character hex root".to_string());
    }
    let bytes = decode_fixed_hex(secret_key_hex, "secret_key_hex", 32)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "secret_key_hex must decode to 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&bytes);
    Ok(hex::encode(
        signing_key.sign(signing_root.as_bytes()).to_bytes(),
    ))
}

fn public_key_hex_for_secret_key(secret_key_hex: &str) -> Result<String, String> {
    let bytes = decode_fixed_hex(secret_key_hex, "secret_key_hex", 32)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "secret_key_hex must decode to 32 bytes".to_string())?;
    Ok(hex::encode(
        SigningKey::from_bytes(&bytes).verifying_key().to_bytes(),
    ))
}

fn sample_secret_key_for_public_key(public_key_hex: &str) -> Option<String> {
    [0xa1, 0xa2, 0xb1, 0xb2, 0xc1, 0xc2, 0xd1, 0xd2, 0xe1, 0xe2]
        .into_iter()
        .find(|seed| sample_ed25519_public_key_hex(*seed) == public_key_hex)
        .map(sample_ed25519_secret_key_hex)
}

fn sample_signature_for_public_key(public_key_hex: &str, signing_root: &str) -> Option<String> {
    sample_secret_key_for_public_key(public_key_hex)
        .and_then(|secret_key| sign_root_with_secret_key(&secret_key, signing_root).ok())
}

fn complete_sample_signature(signature: &mut SignatureVerification) {
    if let Some(signature_hex) =
        sample_signature_for_public_key(&signature.public_key, &signature.signature_sha3_256)
    {
        signature.signature_hex = signature_hex;
        signature.verified = true;
    } else {
        signature.signature_hex.clear();
        signature.verified = false;
    }
}

fn stable_root(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("status root input serializes");
    let digest = Sha3_256::digest(bytes);
    hex::encode(digest)
}

fn json_artifact_sha3_256(input: &str) -> String {
    let digest = Sha3_256::digest(input.trim_start_matches('\u{feff}').as_bytes());
    hex::encode(digest)
}

fn split_basis_points(amount: u128, bps: u128) -> Result<u128, FeeError> {
    amount
        .checked_mul(bps)
        .ok_or(FeeError::ArithmeticOverflow)
        .map(|scaled| scaled / FEE_BASIS_POINTS)
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator + u128::from(!numerator.is_multiple_of(denominator))
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod public_launch {
    use super::*;

    fn external_public_runtime_surface_from(
        runtime_surface_json: &str,
        tls_observation: Option<TlsEndpointPin>,
    ) -> Result<String, AttestationError> {
        let evidence = serde_json::from_str::<RuntimeSurfaceEvidence>(runtime_surface_json)
            .expect("runtime surface evidence parses");
        build_runtime_surface_evidence_json_pretty(RuntimeSurfaceEvidenceBuildInput {
            endpoint_url: evidence.endpoint_url,
            capture_mode: RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT.to_string(),
            tls_observation,
            captured_at_unix_ms: unix_ms(),
            health_json: evidence.health.to_string(),
            status_json: evidence.status.to_string(),
            snapshot_json: evidence.snapshot.to_string(),
            ops_json: evidence.ops.to_string(),
            backup_json: evidence.backup.to_string(),
            rpc_status_json: evidence.rpc_status.to_string(),
            rpc_ops_status_json: evidence.rpc_ops_status.to_string(),
            rpc_backup_manifest_json: evidence.rpc_backup_manifest.to_string(),
            metrics_text: evidence.metrics_text,
        })
    }

    fn runtime_surface_with_endpoint_url(
        runtime_surface_json: &str,
        endpoint_url: &str,
    ) -> Result<String, AttestationError> {
        let mut evidence = serde_json::from_str::<RuntimeSurfaceEvidence>(runtime_surface_json)
            .expect("runtime surface evidence parses");
        evidence.endpoint_url = endpoint_url.to_string();
        evidence.status["launch_endpoint_url"] = json!(endpoint_url);

        let mut snapshot =
            serde_json::from_value::<runtime::RuntimeSnapshot>(evidence.snapshot.clone())
                .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
        if let Some(launch_binding) = snapshot.config.launch_binding.as_mut() {
            launch_binding.endpoint_url = endpoint_url.to_string();
        }
        snapshot.root = runtime::runtime_snapshot_root(&snapshot);
        evidence.snapshot = serde_json::to_value(&snapshot)
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;

        let mut ops = serde_json::from_value::<runtime::RuntimeOpsStatus>(evidence.ops.clone())
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
        ops.launch_endpoint_url = Some(endpoint_url.to_string());
        ops.snapshot_root = snapshot.root.clone();
        ops.ops_root = runtime::runtime_ops_status_root(&ops);
        evidence.ops = serde_json::to_value(&ops)
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;

        let mut backup =
            serde_json::from_value::<runtime::RuntimeBackupManifest>(evidence.backup.clone())
                .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
        backup.launch_endpoint_url = Some(endpoint_url.to_string());
        backup.snapshot_root = snapshot.root.clone();
        backup.backup_root = runtime::runtime_backup_manifest_root(&backup);
        evidence.backup = serde_json::to_value(&backup)
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;

        evidence.health["launch_endpoint_url"] = json!(endpoint_url);
        evidence.health["snapshot_root"] = json!(snapshot.root);
        evidence.health["ops_root"] = json!(ops.ops_root);
        evidence.health["backup_root"] = json!(backup.backup_root);

        match evidence.rpc_status.get_mut("result") {
            Some(result) => *result = evidence.status.clone(),
            None => evidence.rpc_status = evidence.status.clone(),
        }
        match evidence.rpc_ops_status.get_mut("result") {
            Some(result) => *result = evidence.ops.clone(),
            None => evidence.rpc_ops_status = evidence.ops.clone(),
        }
        match evidence.rpc_backup_manifest.get_mut("result") {
            Some(result) => *result = evidence.backup.clone(),
            None => evidence.rpc_backup_manifest = evidence.backup.clone(),
        }
        evidence.root = runtime_surface_evidence_root(&evidence);
        let output = serde_json::to_string_pretty(&evidence)
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
        verify_runtime_surface_evidence_json(&output)?;
        Ok(output)
    }

    fn runtime_surface_with_economics_counters(
        runtime_surface_json: &str,
        total_nxmr_fees_units: u128,
        buyback_pool_nebulai: u128,
        validator_reward_nebulai: u128,
    ) -> Result<String, AttestationError> {
        let mut evidence = serde_json::from_str::<RuntimeSurfaceEvidence>(runtime_surface_json)
            .expect("runtime surface evidence parses");
        evidence.status["total_nxmr_fees_units"] = json!(total_nxmr_fees_units);
        evidence.status["buyback_pool_nebulai"] = json!(buyback_pool_nebulai);
        evidence.status["validator_reward_nebulai"] = json!(validator_reward_nebulai);
        match evidence.rpc_status.get_mut("result") {
            Some(result) => *result = evidence.status.clone(),
            None => evidence.rpc_status = evidence.status.clone(),
        }
        evidence.metrics_text = metrics_text_with_value(
            &evidence.metrics_text,
            "nebula_total_nxmr_fees_units",
            total_nxmr_fees_units,
        );
        evidence.metrics_text = metrics_text_with_value(
            &evidence.metrics_text,
            "nebula_buyback_pool_nebulai",
            buyback_pool_nebulai,
        );
        evidence.metrics_text = metrics_text_with_value(
            &evidence.metrics_text,
            "nebula_validator_reward_nebulai",
            validator_reward_nebulai,
        );
        evidence.root = runtime_surface_evidence_root(&evidence);
        let output = serde_json::to_string_pretty(&evidence)
            .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
        verify_runtime_surface_evidence_json(&output)?;
        Ok(output)
    }

    fn runtime_surface_with_snapshot_economics_counters(
        runtime_surface_json: &str,
        total_nxmr_fees_units: u128,
        buyback_pool_nebulai: u128,
        validator_reward_nebulai: u128,
    ) -> String {
        let mut evidence = serde_json::from_str::<RuntimeSurfaceEvidence>(runtime_surface_json)
            .expect("runtime surface evidence parses");
        let mut snapshot =
            serde_json::from_value::<runtime::RuntimeSnapshot>(evidence.snapshot.clone())
                .expect("snapshot parses");
        snapshot.total_nxmr_fees_units = total_nxmr_fees_units;
        snapshot.buyback_pool_nebulai = buyback_pool_nebulai;
        snapshot.validator_reward_nebulai = validator_reward_nebulai;
        snapshot.state_root = runtime_snapshot_state_root_for_test(&snapshot);
        let active_sequencer_secret_key_hex = "4d".repeat(32);
        assert_eq!(
            public_key_hex_for_secret_key(&active_sequencer_secret_key_hex)
                .expect("sequencer public key"),
            snapshot.config.sequencer_public_key_hex
        );
        let latest_block = snapshot
            .blocks
            .last_mut()
            .expect("snapshot has a latest block");
        latest_block.state_root = snapshot.state_root.clone();
        latest_block.block_hash = runtime_block_root_for_test(latest_block);
        latest_block.signature =
            sign_root_with_secret_key(&active_sequencer_secret_key_hex, &latest_block.block_hash)
                .expect("latest block signature");
        let latest_hash = latest_block.block_hash.clone();
        snapshot.root = runtime::runtime_snapshot_root(&snapshot);

        evidence.status["total_nxmr_fees_units"] = json!(total_nxmr_fees_units);
        evidence.status["buyback_pool_nebulai"] = json!(buyback_pool_nebulai);
        evidence.status["validator_reward_nebulai"] = json!(validator_reward_nebulai);
        evidence.status["latest_hash"] = json!(latest_hash);
        evidence.status["latest_state_root"] = json!(snapshot.state_root.clone());
        evidence.status["current_state_root"] = json!(snapshot.state_root.clone());
        evidence.status["sync_quorum_latest_hash"] = evidence.status["latest_hash"].clone();
        evidence.status["sync_quorum_state_root"] = json!(snapshot.state_root.clone());

        evidence.health["latest_hash"] = evidence.status["latest_hash"].clone();
        evidence.health["latest_state_root"] = evidence.status["latest_state_root"].clone();
        evidence.health["current_state_root"] = evidence.status["current_state_root"].clone();
        evidence.health["snapshot_root"] = json!(snapshot.root.clone());

        let ops_root = update_surface_ops_like_for_snapshot_economics(
            &mut evidence.ops,
            &evidence.status,
            &snapshot,
        );
        let backup_root = update_surface_ops_like_for_snapshot_economics(
            &mut evidence.backup,
            &evidence.status,
            &snapshot,
        );
        evidence.health["ops_root"] = json!(ops_root);
        evidence.health["backup_root"] = json!(backup_root);

        evidence.snapshot = serde_json::to_value(&snapshot).expect("snapshot serializes");
        match evidence.rpc_status.get_mut("result") {
            Some(result) => *result = evidence.status.clone(),
            None => evidence.rpc_status = evidence.status.clone(),
        }
        match evidence.rpc_ops_status.get_mut("result") {
            Some(result) => *result = evidence.ops.clone(),
            None => evidence.rpc_ops_status = evidence.ops.clone(),
        }
        match evidence.rpc_backup_manifest.get_mut("result") {
            Some(result) => *result = evidence.backup.clone(),
            None => evidence.rpc_backup_manifest = evidence.backup.clone(),
        }
        evidence.metrics_text = metrics_text_with_value(
            &evidence.metrics_text,
            "nebula_total_nxmr_fees_units",
            total_nxmr_fees_units,
        );
        evidence.metrics_text = metrics_text_with_value(
            &evidence.metrics_text,
            "nebula_buyback_pool_nebulai",
            buyback_pool_nebulai,
        );
        evidence.metrics_text = metrics_text_with_value(
            &evidence.metrics_text,
            "nebula_validator_reward_nebulai",
            validator_reward_nebulai,
        );
        evidence.root = runtime_surface_evidence_root(&evidence);
        serde_json::to_string_pretty(&evidence).expect("runtime surface serializes")
    }

    fn update_surface_ops_like_for_snapshot_economics(
        value: &mut Value,
        status: &Value,
        snapshot: &runtime::RuntimeSnapshot,
    ) -> String {
        value["latest_hash"] = status["latest_hash"].clone();
        value["latest_state_root"] = status["latest_state_root"].clone();
        value["current_state_root"] = status["current_state_root"].clone();
        value["sync_quorum_latest_hash"] = status["sync_quorum_latest_hash"].clone();
        value["sync_quorum_state_root"] = status["sync_quorum_state_root"].clone();
        value["snapshot_root"] = json!(snapshot.root.clone());
        value["storage_snapshot_root"] = json!(snapshot.root.clone());
        value["total_nxmr_fees_units"] = status["total_nxmr_fees_units"].clone();
        value["buyback_pool_nebulai"] = status["buyback_pool_nebulai"].clone();
        value["validator_reward_nebulai"] = status["validator_reward_nebulai"].clone();
        if value.get("ops_root").is_some() {
            let mut ops = serde_json::from_value::<runtime::RuntimeOpsStatus>(value.clone())
                .expect("ops parses");
            ops.ops_root = runtime::runtime_ops_status_root(&ops);
            let root = ops.ops_root.clone();
            *value = serde_json::to_value(ops).expect("ops serializes");
            root
        } else {
            let mut backup =
                serde_json::from_value::<runtime::RuntimeBackupManifest>(value.clone())
                    .expect("backup parses");
            backup.backup_root = runtime::runtime_backup_manifest_root(&backup);
            let root = backup.backup_root.clone();
            *value = serde_json::to_value(backup).expect("backup serializes");
            root
        }
    }

    fn runtime_snapshot_state_root_for_test(snapshot: &runtime::RuntimeSnapshot) -> String {
        stable_root(&json!({
            "state_domain": "nebula-runtime-state-v1",
            "accounts": snapshot.accounts,
            "bridge_deposits": snapshot.bridge_deposits,
            "withdrawals": snapshot.withdrawals,
            "total_nxmr_fees_units": snapshot.total_nxmr_fees_units,
            "buyback_pool_nebulai": snapshot.buyback_pool_nebulai,
            "validator_reward_nebulai": snapshot.validator_reward_nebulai,
        }))
    }

    fn runtime_block_root_for_test(block: &runtime::RuntimeBlock) -> String {
        stable_root(&json!({
            "block_domain": "nebula-runtime-block-v1",
            "height": block.height,
            "parent_hash": block.parent_hash,
            "timestamp_unix_ms": block.timestamp_unix_ms,
            "producer": block.producer,
            "producer_public_key": block.producer_public_key,
            "tx_root": block.tx_root,
            "state_root": block.state_root,
        }))
    }

    fn metrics_text_with_value(metrics_text: &str, metric_name: &str, value: u128) -> String {
        let prefix = format!("{metric_name} ");
        metrics_text
            .lines()
            .map(|line| {
                if line.starts_with(&prefix) {
                    format!("{prefix}{value}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    struct SampleLaunchArtifacts {
        deployment: String,
        public_status: String,
        public_probe: String,
        validators: String,
        handoff: String,
        acceptance: String,
        genesis: String,
        bundle: String,
    }

    fn sample_launch_artifacts() -> SampleLaunchArtifacts {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        SampleLaunchArtifacts {
            deployment,
            public_status,
            public_probe,
            validators,
            handoff,
            acceptance,
            genesis,
            bundle,
        }
    }

    #[test]
    fn public_launch_blocks_without_deployment_attestation() {
        let report = readiness_report();

        assert!(report.acceptance.testnet_ready);
        assert!(!report.public_launch_readiness.public_launch_ready);
        assert_eq!(
            report.public_launch_readiness.level,
            "public-launch-blocked"
        );
        assert_eq!(
            report.public_launch_readiness.blocking_gaps,
            vec![PUBLIC_LAUNCH_BLOCKER.to_string()]
        );
    }

    #[test]
    fn public_launch_remediation_root_is_stable_shape() {
        let report = readiness_report();

        assert_eq!(report.public_launch_readiness.remediation_root.len(), 64);
        assert!(report
            .public_launch_readiness
            .remediation_root
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn public_launch_readiness_includes_hybrid_fee_policy() {
        let report = readiness_report();

        assert_eq!(report.economics.native_fee_token, NBLA_SYMBOL);
        assert_eq!(report.economics.bridged_fee_token, NXMR_SYMBOL);
        assert_eq!(report.economics.native_base_unit, NEBULAI_UNIT);
        assert_eq!(report.economics.nebulai_per_nbla, 1_000_000);
        assert_eq!(report.economics.target_nxmr_per_nbla_numerator, 1);
        assert_eq!(report.economics.target_nxmr_per_nbla_denominator, 1_000);
        assert_eq!(report.economics.nxmr_buyback_bps, 10_000);
        assert_eq!(report.economics.nxmr_reserve_backing_bps, 0);
        assert_eq!(report.economics.nxmr_validator_reward_bps, 10_000);
        assert_eq!(
            report.status_roots["economics"].as_str().unwrap(),
            fee_policy_root()
        );
    }

    #[test]
    fn public_launch_readiness_includes_bundle_and_activation_roots() {
        let report = readiness_report();

        for root_name in [
            "launch_package_bundle",
            "public_testnet_peer_manifest",
            "validator_activation",
            "validator_join",
            "operator_join_confirmation",
            "public_observer_confirmation",
            "public_testnet_launch_certificate",
        ] {
            let root = report.status_roots[root_name].as_str().unwrap();
            assert_eq!(root.len(), 64);
            assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn sample_deployment_attestation_verifies_public_launch_gate() {
        let report =
            verify_deployment_attestation_json(&sample_deployment_attestation_json_pretty())
                .unwrap();

        assert!(report.public_launch_ready);
        assert_eq!(report.level, "public-launch-attested");
        assert_eq!(report.verified_operator_count, 2);
        assert_eq!(report.verified_observer_count, 2);
        assert_eq!(report.verified_region_count, 2);
        assert_eq!(report.evidence_root.len(), 64);
        assert_eq!(report.witness_evidence_root.len(), 64);
        assert_eq!(report.public_surface_root.len(), 64);
        assert_eq!(report.operator_approval_root.len(), 64);
        assert_eq!(report.observer_confirmation_root.len(), 64);
        assert_eq!(report.rollback_readiness_root.len(), 64);
        assert_eq!(report.deployment_validity_root.len(), 64);
        assert_eq!(report.deployment_quorum_root.len(), 64);
        assert_eq!(report.bootstrap_roster_root.len(), 64);
        assert_eq!(report.operational_evidence_root.len(), 64);
    }

    #[test]
    fn sample_public_status_manifest_verifies_surface() {
        let report =
            verify_public_status_manifest_json(&sample_public_status_manifest_json_pretty())
                .unwrap();

        assert!(report.public_status_ready);
        assert_eq!(report.level, "public-status-attested");
        assert_eq!(report.public_status_manifest_root.len(), 64);
        assert_eq!(report.endpoint_url, "https://testnet.nebula.example/status");
        assert_eq!(report.launch_bundle_root.len(), 64);
    }

    #[test]
    fn sample_public_probe_verifies_surface() {
        let report = verify_public_probe_json(&sample_public_probe_json_pretty()).unwrap();

        assert!(report.public_probe_ready);
        assert_eq!(report.level, "public-probe-attested");
        assert_eq!(report.public_probe_root.len(), 64);
        assert_eq!(report.endpoint_url, "https://testnet.nebula.example/status");
        assert_eq!(report.launch_bundle_root.len(), 64);
        assert_eq!(report.fee_policy_root, fee_policy_root());
    }

    #[test]
    fn builds_deployment_attestation_for_custom_public_surface() {
        let endpoint_url = "https://public.testnet.nebula.example/status";
        let public_status_json =
            build_public_status_manifest_json_pretty(PublicSurfaceBuildInput {
                endpoint_url: endpoint_url.to_string(),
                artifact_sha3_256: default_artifact_sha3_256(),
                cargo_lock_sha3_256: default_cargo_lock_sha3_256(),
            })
            .unwrap();
        let public_probe_json = build_public_probe_json_pretty(PublicSurfaceBuildInput {
            endpoint_url: endpoint_url.to_string(),
            artifact_sha3_256: default_artifact_sha3_256(),
            cargo_lock_sha3_256: default_cargo_lock_sha3_256(),
        })
        .unwrap();
        let preflight_receipt_json = sample_preflight_receipt_json_pretty();
        let runbook_receipt_json = sample_runbook_receipt_json_pretty();
        let generated_at_unix_ms = unix_ms();
        let output = build_deployment_attestation_json_pretty(DeploymentAttestationBuildInput {
            public_status_json: public_status_json.clone(),
            public_probe_json: public_probe_json.clone(),
            preflight_receipt_json,
            runbook_receipt_json,
            artifact_sha3_256: default_artifact_sha3_256(),
            cargo_lock_sha3_256: default_cargo_lock_sha3_256(),
            generated_at_unix_ms,
            expires_at_unix_ms: generated_at_unix_ms + 86_400_000,
            tls_pins: vec![
                TlsEndpointPin {
                    cert_sha256: hex_64("custom-tls-cert-a"),
                    public_key_sha256: hex_64("custom-tls-key-a"),
                    not_after_unix_ms: generated_at_unix_ms + 2_592_000_000,
                },
                TlsEndpointPin {
                    cert_sha256: hex_64("custom-tls-cert-b"),
                    public_key_sha256: hex_64("custom-tls-key-b"),
                    not_after_unix_ms: generated_at_unix_ms + 2_592_000_000,
                },
            ],
            bootstrap_nodes: vec![
                BootstrapNodeBuildInput {
                    node_id: "bootstrap-us-east-1".to_string(),
                    operator_id: "operator-a".to_string(),
                    region: "us-east".to_string(),
                    endpoint: "https://bootstrap-a.public-nebula.example".to_string(),
                },
                BootstrapNodeBuildInput {
                    node_id: "bootstrap-eu-west-1".to_string(),
                    operator_id: "operator-b".to_string(),
                    region: "eu-west".to_string(),
                    endpoint: "https://bootstrap-b.public-nebula.example".to_string(),
                },
            ],
            operators: vec![
                OperatorBuildInput {
                    operator_id: "operator-a".to_string(),
                    region: "us-east".to_string(),
                    public_key: hex_64("custom-operator-a"),
                },
                OperatorBuildInput {
                    operator_id: "operator-b".to_string(),
                    region: "eu-west".to_string(),
                    public_key: hex_64("custom-operator-b"),
                },
            ],
            observers: vec![
                ObserverBuildInput {
                    observer_id: "observer-us-east-1".to_string(),
                    region: "us-east".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xe1),
                    secret_key_hex: Some(sample_ed25519_secret_key_hex(0xe1)),
                },
                ObserverBuildInput {
                    observer_id: "observer-eu-west-1".to_string(),
                    region: "eu-west".to_string(),
                    public_key: sample_ed25519_public_key_hex(0xe2),
                    secret_key_hex: Some(sample_ed25519_secret_key_hex(0xe2)),
                },
            ],
            rollback_plan_sha3_256: hex_64("custom-rollback-plan"),
            rollback_last_drill_unix_ms: generated_at_unix_ms,
            rollback_recovery_point_root: hex_64("custom-rollback-recovery"),
        })
        .unwrap();

        let report = verify_deployment_attestation_json(&output).unwrap();
        assert!(report.public_launch_ready);
        assert_eq!(report.verified_operator_count, 2);
        assert_eq!(report.verified_observer_count, 2);

        let attestation = serde_json::from_str::<DeploymentAttestation>(&output).unwrap();
        assert_eq!(attestation.public_endpoint.url, endpoint_url);
        assert_eq!(
            attestation.public_status_manifest.endpoint_url,
            endpoint_url
        );
        assert_eq!(attestation.public_probe.url, endpoint_url);
        assert!(verify_public_status_manifest_json(&public_status_json).is_err());
        assert!(verify_public_probe_json(&public_probe_json).is_err());
        let (status_report, probe_report) = verify_public_surface_jsons_for_deployment(
            &public_status_json,
            &public_probe_json,
            &attestation,
        )
        .unwrap();
        assert_eq!(status_report.endpoint_url, endpoint_url);
        assert_eq!(probe_report.endpoint_url, endpoint_url);
    }

    #[test]
    fn deployment_attestation_builder_rejects_mismatched_public_probe() {
        let status = build_public_status_manifest_json_pretty(PublicSurfaceBuildInput {
            endpoint_url: "https://status.testnet.nebula.example/status".to_string(),
            artifact_sha3_256: default_artifact_sha3_256(),
            cargo_lock_sha3_256: default_cargo_lock_sha3_256(),
        })
        .unwrap();
        let probe = build_public_probe_json_pretty(PublicSurfaceBuildInput {
            endpoint_url: "https://other.testnet.nebula.example/status".to_string(),
            artifact_sha3_256: default_artifact_sha3_256(),
            cargo_lock_sha3_256: default_cargo_lock_sha3_256(),
        })
        .unwrap();
        let generated_at_unix_ms = unix_ms();

        let error = build_deployment_attestation_json_pretty(DeploymentAttestationBuildInput {
            public_status_json: status,
            public_probe_json: probe,
            preflight_receipt_json: sample_preflight_receipt_json_pretty(),
            runbook_receipt_json: sample_runbook_receipt_json_pretty(),
            artifact_sha3_256: default_artifact_sha3_256(),
            cargo_lock_sha3_256: default_cargo_lock_sha3_256(),
            generated_at_unix_ms,
            expires_at_unix_ms: generated_at_unix_ms + 86_400_000,
            tls_pins: vec![TlsEndpointPin {
                cert_sha256: hex_64("mismatch-tls-cert"),
                public_key_sha256: hex_64("mismatch-tls-key"),
                not_after_unix_ms: generated_at_unix_ms + 2_592_000_000,
            }],
            bootstrap_nodes: Vec::new(),
            operators: Vec::new(),
            observers: Vec::new(),
            rollback_plan_sha3_256: hex_64("mismatch-rollback-plan"),
            rollback_last_drill_unix_ms: generated_at_unix_ms,
            rollback_recovery_point_root: hex_64("mismatch-rollback-recovery"),
        })
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.contains("public_probe.url")))
            }
            AttestationError::MalformedJson(error) => {
                panic!("unexpected malformed JSON: {error}")
            }
        }
    }

    #[test]
    fn public_status_rejects_unknown_fields() {
        let mut value =
            serde_json::from_str::<Value>(&sample_public_status_manifest_json_pretty()).unwrap();
        value["unexpected_field"] = json!(true);

        let error = verify_public_status_manifest_json(&value.to_string()).unwrap_err();

        assert!(matches!(error, AttestationError::MalformedJson(_)));
    }

    #[test]
    fn public_status_rejects_non_https_endpoint() {
        let mut value =
            serde_json::from_str::<Value>(&sample_public_status_manifest_json_pretty()).unwrap();
        value["endpoint_url"] = json!("http://testnet.nebula.example/status");
        value["root"] = json!(public_status_manifest_root(
            &serde_json::from_value::<PublicStatusManifest>(value.clone()).unwrap()
        ));

        let error = verify_public_status_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "public_status_manifest.endpoint_url must use an https:// endpoint"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_status_rejects_endpoint_without_host() {
        let mut value =
            serde_json::from_str::<Value>(&sample_public_status_manifest_json_pretty()).unwrap();
        value["endpoint_url"] = json!("https://");
        value["root"] = json!(public_status_manifest_root(
            &serde_json::from_value::<PublicStatusManifest>(value.clone()).unwrap()
        ));

        let error = verify_public_status_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "public_status_manifest.endpoint_url must include a host after https://"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_status_rejects_endpoint_with_userinfo() {
        let mut value =
            serde_json::from_str::<Value>(&sample_public_status_manifest_json_pretty()).unwrap();
        value["endpoint_url"] = json!("https://operator@testnet.nebula.example/status");
        value["root"] = json!(public_status_manifest_root(
            &serde_json::from_value::<PublicStatusManifest>(value.clone()).unwrap()
        ));

        let error = verify_public_status_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "public_status_manifest.endpoint_url must not include userinfo"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_status_rejects_endpoint_with_query() {
        let mut value =
            serde_json::from_str::<Value>(&sample_public_status_manifest_json_pretty()).unwrap();
        value["endpoint_url"] = json!("https://testnet.nebula.example/status?operator=a");
        value["root"] = json!(public_status_manifest_root(
            &serde_json::from_value::<PublicStatusManifest>(value.clone()).unwrap()
        ));

        let error = verify_public_status_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "public_status_manifest.endpoint_url must not include query or fragment"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_status_rejects_endpoint_with_nonnumeric_port() {
        let mut value =
            serde_json::from_str::<Value>(&sample_public_status_manifest_json_pretty()).unwrap();
        value["endpoint_url"] = json!("https://testnet.nebula.example:status/status");
        value["root"] = json!(public_status_manifest_root(
            &serde_json::from_value::<PublicStatusManifest>(value.clone()).unwrap()
        ));

        let error = verify_public_status_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "public_status_manifest.endpoint_url must include a numeric port when a port is present"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_status_rejects_mismatched_endpoint_url() {
        let mut value =
            serde_json::from_str::<Value>(&sample_public_status_manifest_json_pretty()).unwrap();
        value["endpoint_url"] = json!("https://other.testnet.nebula.example/status");
        value["root"] = json!(public_status_manifest_root(
            &serde_json::from_value::<PublicStatusManifest>(value.clone()).unwrap()
        ));

        let error = verify_public_status_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "public_status_manifest.endpoint_url expected https://testnet.nebula.example/status but got https://other.testnet.nebula.example/status"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_probe_rejects_unexpected_body_fields() {
        let mut value = serde_json::from_str::<Value>(&sample_public_probe_json_pretty()).unwrap();
        value["body"]["unexpected_field"] = json!(true);

        let error = verify_public_probe_json(&value.to_string()).unwrap_err();

        assert!(matches!(error, AttestationError::MalformedJson(_)));
    }

    #[test]
    fn public_probe_rejects_non_https_endpoint() {
        let mut value = serde_json::from_str::<Value>(&sample_public_probe_json_pretty()).unwrap();
        value["url"] = json!("http://testnet.nebula.example/status");
        value["root"] = json!(public_probe_root(
            &serde_json::from_value::<PublicProbe>(value.clone()).unwrap()
        ));

        let error = verify_public_probe_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "public_probe.url must use an https:// endpoint"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn sample_preflight_receipt_verifies() {
        let report =
            verify_preflight_receipt_json(&sample_preflight_receipt_json_pretty()).unwrap();

        assert!(report.receipt_ready);
        assert_eq!(report.level, "receipt-attested");
        assert_eq!(report.receipt_id, "preflight-receipt");
        assert_eq!(report.receipt_root.len(), 64);
        assert_eq!(report.phase_count, 1);
        assert_eq!(report.step_count, 2);
    }

    #[test]
    fn sample_runbook_receipt_verifies() {
        let report = verify_runbook_receipt_json(&sample_runbook_receipt_json_pretty()).unwrap();

        assert!(report.receipt_ready);
        assert_eq!(report.level, "receipt-attested");
        assert_eq!(report.receipt_id, "runbook-receipt");
        assert_eq!(report.receipt_root.len(), 64);
        assert_eq!(report.phase_count, 1);
        assert_eq!(report.step_count, 2);
    }

    #[test]
    fn preflight_receipt_rejects_wrong_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_preflight_receipt_json_pretty()).unwrap();
        value["receipt_id"] = json!("runbook-receipt");
        value["root"] = json!(receipt_root(
            &serde_json::from_value::<Receipt>(value.clone()).unwrap()
        ));

        let error = verify_preflight_receipt_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "receipt_id expected preflight-receipt but got runbook-receipt"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn preflight_receipt_rejects_duplicate_phase_names() {
        let mut value =
            serde_json::from_str::<Value>(&sample_preflight_receipt_json_pretty()).unwrap();
        let duplicate_phase = value["phases"][0].clone();
        value["phases"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_phase);
        value["root"] = json!(receipt_root(
            &serde_json::from_value::<Receipt>(value.clone()).unwrap()
        ));

        let error = verify_preflight_receipt_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "preflight-receipt.phases[1].name must be unique"));
                assert!(errors.iter().any(|error| {
                    error == "preflight-receipt.phases[1].steps[0].evidence_sha3_256 must be unique"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn preflight_receipt_rejects_duplicate_step_names_and_evidence_roots() {
        let mut value =
            serde_json::from_str::<Value>(&sample_preflight_receipt_json_pretty()).unwrap();
        value["phases"][0]["steps"][1]["name"] = value["phases"][0]["steps"][0]["name"].clone();
        value["phases"][0]["steps"][1]["evidence_sha3_256"] =
            value["phases"][0]["steps"][0]["evidence_sha3_256"].clone();
        value["root"] = json!(receipt_root(
            &serde_json::from_value::<Receipt>(value.clone()).unwrap()
        ));

        let error = verify_preflight_receipt_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "preflight-receipt.phases[0].steps[1].name must be unique"
                }));
                assert!(errors.iter().any(|error| {
                    error == "preflight-receipt.phases[0].steps[1].evidence_sha3_256 must be unique"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn preflight_receipt_rejects_stale_completion_time() {
        let mut value =
            serde_json::from_str::<Value>(&sample_preflight_receipt_json_pretty()).unwrap();
        value["completed_at_unix_ms"] = json!(0);
        value["root"] = json!(receipt_root(
            &serde_json::from_value::<Receipt>(value.clone()).unwrap()
        ));

        let error = verify_preflight_receipt_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "preflight-receipt.completed_at_unix_ms is stale"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn runbook_receipt_rejects_unexpected_fields() {
        let mut value =
            serde_json::from_str::<Value>(&sample_runbook_receipt_json_pretty()).unwrap();
        value["unexpected_field"] = json!(true);

        let error = verify_runbook_receipt_json(&value.to_string()).unwrap_err();

        assert!(matches!(error, AttestationError::MalformedJson(_)));
    }

    #[test]
    fn deployment_attestation_rejects_unknown_fields() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["unexpected_field"] = json!(true);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        assert!(matches!(error, AttestationError::MalformedJson(_)));
    }

    #[test]
    fn deployment_attestation_rejects_stale_evidence() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["expires_at_unix_ms"] = json!(0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "expires_at_unix_ms is stale"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_expiry_before_generation_time() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        let now = unix_ms();
        value["generated_at_unix_ms"] = json!(now + 60_000);
        value["expires_at_unix_ms"] = json!(now + 30_000);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "expires_at_unix_ms must be after generated_at_unix_ms"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_wrong_launch_bundle_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["launch_bundle"]["bundle_id"] = json!("nebula-wrong-testnet-bundle");
        value["launch_bundle"]["root"] = json!(launch_bundle_root(
            &serde_json::from_value::<LaunchBundle>(value["launch_bundle"].clone()).unwrap()
        ));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "launch_bundle.bundle_id expected nebula-public-testnet-bundle-1 but got nebula-wrong-testnet-bundle"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_reused_package_identity_roots() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["package_identity"]["cargo_lock_sha3_256"] =
            value["package_identity"]["artifact_sha3_256"].clone();
        value["package_identity"]["root"] = json!(package_identity_root(
            &serde_json::from_value::<PackageIdentity>(value["package_identity"].clone()).unwrap()
        ));
        value["launch_bundle"]["package_root"] = value["package_identity"]["root"].clone();
        value["launch_bundle"]["root"] = json!(launch_bundle_root(
            &serde_json::from_value::<LaunchBundle>(value["launch_bundle"].clone()).unwrap()
        ));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "package_identity.cargo_lock_sha3_256 must differ from artifact_sha3_256"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_reused_component_roots() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["policy_claim"]["root"] = value["launch_bundle"]["root"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "policy_claim.root must differ from launch_bundle.root"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_stale_preflight_receipt() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["preflight_receipt"]["completed_at_unix_ms"] = json!(0);
        value["preflight_receipt"]["root"] = json!(receipt_root(
            &serde_json::from_value::<Receipt>(value["preflight_receipt"].clone()).unwrap()
        ));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "preflight_receipt.completed_at_unix_ms is stale"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_runbook_reusing_preflight_evidence() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["runbook_receipt"]["phases"][0]["steps"][0]["evidence_sha3_256"] =
            value["preflight_receipt"]["phases"][0]["steps"][0]["evidence_sha3_256"].clone();
        value["runbook_receipt"]["root"] = json!(receipt_root(
            &serde_json::from_value::<Receipt>(value["runbook_receipt"].clone()).unwrap()
        ));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "runbook_receipt.phases[0].steps[0].evidence_sha3_256 must not reuse preflight_receipt evidence"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_preflight_after_generation_time() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        let generated_at = value["generated_at_unix_ms"]
            .as_u64()
            .expect("sample generated_at fits u64");
        value["preflight_receipt"]["completed_at_unix_ms"] = json!(generated_at + 1);
        value["preflight_receipt"]["root"] = json!(receipt_root(
            &serde_json::from_value::<Receipt>(value["preflight_receipt"].clone()).unwrap()
        ));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "preflight_receipt.completed_at_unix_ms must be at or before generated_at_unix_ms"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_old_generation_time() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["generated_at_unix_ms"] = json!(0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "generated_at_unix_ms is older than 24 hours"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_excessive_expiry_window() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["expires_at_unix_ms"] = json!(unix_ms() + PUBLIC_ATTESTATION_MAX_TTL_MS + 60_000);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "expires_at_unix_ms is more than seven days in the future"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_excessive_validity_window() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        let generated_at = unix_ms().saturating_sub(3_600_000);
        value["generated_at_unix_ms"] = json!(generated_at);
        value["expires_at_unix_ms"] = json!(generated_at + PUBLIC_ATTESTATION_MAX_TTL_MS + 1);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "expires_at_unix_ms must be within seven days of generated_at_unix_ms"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_short_tls_pin_validity() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["public_endpoint"]["tls_pins"][0]["not_after_unix_ms"] =
            json!(unix_ms() + MIN_TLS_PIN_VALIDITY_MS - 1);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "public_endpoint.tls_pins[0].not_after_unix_ms expires in less than seven days"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_non_https_public_endpoint() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["public_endpoint"]["url"] = json!("http://testnet.nebula.example/status");

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "public_endpoint.url must use an https:// endpoint"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_bootstrap_endpoint_without_host() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][0]["endpoint"] = json!("https://");
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "bootstrap_nodes[0].endpoint must include a host after https://"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_bootstrap_endpoint_with_path() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][0]["endpoint"] =
            json!("https://bootstrap-a.testnet.nebula.example/rpc");
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "bootstrap_nodes[0].endpoint must not include a path"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_bootstrap_endpoint_with_zero_port() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][0]["endpoint"] =
            json!("https://bootstrap-a.testnet.nebula.example:0");
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "bootstrap_nodes[0].endpoint must include a numeric port when a port is present"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_duplicate_bootstrap_endpoint_host() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][1]["endpoint"] =
            json!("https://bootstrap-a.testnet.nebula.example/alternate");
        refresh_bootstrap_node_root(&mut value, 1);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "bootstrap_nodes[1].endpoint.host must be unique"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_bootstrap_endpoint_reusing_public_host() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][0]["endpoint"] = json!("https://testnet.nebula.example");
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "bootstrap_nodes[0].endpoint.host must not reuse public_endpoint.url host"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_duplicate_tls_cert_pin() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["public_endpoint"]["tls_pins"][1]["cert_sha256"] =
            value["public_endpoint"]["tls_pins"][0]["cert_sha256"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "public_endpoint.tls_pins[1].cert_sha256 must be unique"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_duplicate_tls_public_key_pin() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["public_endpoint"]["tls_pins"][1]["public_key_sha256"] =
            value["public_endpoint"]["tls_pins"][0]["public_key_sha256"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "public_endpoint.tls_pins[1].public_key_sha256 must be unique"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_tls_public_key_pin_reused_as_cert_pin() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["public_endpoint"]["tls_pins"][1]["public_key_sha256"] =
            value["public_endpoint"]["tls_pins"][0]["cert_sha256"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "public_endpoint.tls_pins[1].public_key_sha256 must not reuse a cert_sha256"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_stale_rollback_drill() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["rollback_evidence"]["last_drill_unix_ms"] = json!(0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "rollback_evidence.last_drill_unix_ms is older than seven days"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_rollback_drill_after_generation_time() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        let generated_at = value["generated_at_unix_ms"]
            .as_u64()
            .expect("sample generated_at fits u64");
        value["rollback_evidence"]["last_drill_unix_ms"] = json!(generated_at + 1);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "rollback_evidence.last_drill_unix_ms must be at or before generated_at_unix_ms"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_reused_rollback_recovery_root() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["rollback_evidence"]["recovery_point_root"] =
            value["rollback_evidence"]["rollback_plan_sha3_256"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "rollback_evidence.recovery_point_root must differ from rollback_plan_sha3_256"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_operator_wrong_witness_root() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["operators"][0]["signed_evidence_root"] = json!(hex_64("wrong-operator-root"));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("operators[0].signed_evidence_root expected")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_non_hex_operator_public_key() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["operators"][0]["public_key"] = json!("operator-key-a");
        refresh_operator_signature_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(
                    |error| error == "operators[0].public_key must be a 64-character hex value"
                ));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_operator_wrong_signature_root() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["operators"][0]["signature_sha3_256"] = json!(hex_64("wrong-operator-signature"));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("operators[0].signature_sha3_256 does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_duplicate_operator_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["operators"][1]["operator_id"] = value["operators"][0]["operator_id"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "operators[1].operator_id must be unique"));
                assert!(errors.iter().any(|error| {
                    error == "operators must include at least 2 unique operator_id values"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_operator_id_with_whitespace() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["operators"][0]["operator_id"] = json!("operator a");
        value["bootstrap_nodes"][0]["operator_id"] = json!("operator a");
        refresh_operator_signature_root(&mut value, 0);
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "operators[0].operator_id must not contain whitespace"));
                assert!(errors.iter().any(|error| {
                    error == "bootstrap_nodes[0].operator_id must not contain whitespace"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_single_region_operator_quorum() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["operators"][1]["region"] = value["operators"][0]["region"].clone();
        refresh_operator_signature_root(&mut value, 1);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "operators must cover at least 2 regions"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_operator_region_with_whitespace() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["operators"][0]["region"] = json!("us east");
        value["bootstrap_nodes"][0]["region"] = json!("us east");
        refresh_operator_signature_root(&mut value, 0);
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "operators[0].region must not contain whitespace"));
                assert!(errors.iter().any(|error| {
                    error == "bootstrap_nodes[0].region must not contain whitespace"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_duplicate_bootstrap_node_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][1]["node_id"] = value["bootstrap_nodes"][0]["node_id"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "bootstrap_nodes[1].node_id must be unique"));
                assert!(errors.iter().any(|error| {
                    error == "bootstrap_nodes must include at least 2 unique node_id values"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_bootstrap_node_id_reused_as_operator_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][0]["node_id"] = value["operators"][0]["operator_id"].clone();
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "bootstrap_nodes[0].node_id must not reuse an operator_id"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_single_region_bootstrap_nodes() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][1]["region"] = value["bootstrap_nodes"][0]["region"].clone();
        refresh_bootstrap_node_root(&mut value, 1);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "bootstrap_nodes must cover at least 2 regions"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_bootstrap_region_mismatched_operator() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["bootstrap_nodes"][0]["region"] = json!("ap-south");
        refresh_bootstrap_node_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "bootstrap_nodes[0].operator.region expected ap-south but got us-east"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_observer_wrong_witness_root() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][0]["observed_evidence_root"] = json!(hex_64("wrong-observer-root"));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("observers[0].observed_evidence_root expected")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_observer_wrong_signature_root() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][0]["signature"]["signature_sha3_256"] =
            json!(hex_64("wrong-observer-signature"));

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("observers[0].signature.signature_sha3_256 does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_duplicate_observer_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][1]["observer_id"] = value["observers"][0]["observer_id"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "observers[1].observer_id must be unique"));
                assert!(errors.iter().any(|error| {
                    error == "observers must include at least 2 unique observer_id values"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_observer_id_reused_as_operator_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][0]["observer_id"] = value["operators"][0]["operator_id"].clone();
        refresh_observer_signature_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "observers[0].observer_id must not reuse an operator_id"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_observer_id_reused_as_bootstrap_node_id() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][0]["observer_id"] = value["bootstrap_nodes"][0]["node_id"].clone();
        refresh_observer_signature_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "observers[0].observer_id must not reuse a bootstrap node_id"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_duplicate_observer_public_key() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][1]["signature"]["public_key"] =
            value["observers"][0]["signature"]["public_key"].clone();

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| { error == "observers[1].signature.public_key must be unique" }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_observer_key_reused_as_operator_key() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][0]["signature"]["public_key"] =
            value["operators"][0]["public_key"].clone();
        refresh_observer_signature_root(&mut value, 0);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "observers[0].signature.public_key must not reuse an operator public_key"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn deployment_attestation_rejects_single_region_observer_quorum() {
        let mut value =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        value["observers"][1]["region"] = value["observers"][0]["region"].clone();
        refresh_observer_signature_root(&mut value, 1);

        let error = verify_deployment_attestation_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "observers must cover at least 2 regions"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn sample_validator_set_verifies_public_testnet_admission() {
        let report = verify_validator_set_json(&sample_validator_set_json_pretty()).unwrap();

        assert!(report.validator_set_ready);
        assert_eq!(report.level, "validator-set-attested");
        assert_eq!(report.validator_count, 2);
        assert_eq!(report.reward_account_count, 2);
        assert_eq!(report.operator_count, 2);
        assert_eq!(report.region_count, 2);
        assert_eq!(report.reward_unit, NEBULAI_UNIT);
        assert_eq!(report.total_genesis_power, 2);
        assert_eq!(report.operator_roster_root.len(), 64);
        assert_eq!(report.reward_ledger_root.len(), 64);
    }

    #[test]
    fn validator_set_rejects_unknown_fields() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["unexpected_field"] = json!(true);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        assert!(matches!(error, AttestationError::MalformedJson(_)));
    }

    #[test]
    fn validator_set_rejects_non_genesis_epoch() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["epoch"] = json!(PUBLIC_TESTNET_GENESIS_EPOCH + 1);
        value["root"] = json!(validator_set_root(
            &serde_json::from_value::<ValidatorSetManifest>(value.clone()).unwrap()
        ));

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| error == "epoch must be 0"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_duplicate_consensus_keys() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        let duplicate_key = value["validators"][0]["consensus_public_key"].clone();
        value["validators"][1]["consensus_public_key"] = duplicate_key;

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "validators[1].consensus_public_key must be unique"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_validator_id_with_whitespace() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["validator_id"] = json!("validator a");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(
                    errors
                        .iter()
                        .any(|error| error
                            == "validators[0].validator_id must not contain whitespace")
                );
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_validator_id_reused_as_operator_id() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["validator_id"] = value["validators"][0]["operator_id"].clone();
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(
                    |error| error == "validators[0].validator_id must differ from operator_id"
                ));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_duplicate_operator_id() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][1]["operator_id"] = value["validators"][0]["operator_id"].clone();
        value["validators"][1]["reward_account"] = value["validators"][0]["reward_account"].clone();
        refresh_validator_manifest_root(&mut value, 1);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "validators[1].operator_id must be unique"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_region_with_whitespace() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["region"] = json!("us east");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "validators[0].region must not contain whitespace"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_non_hex_consensus_key() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["consensus_public_key"] = json!("consensus-key-a");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].consensus_public_key must be a 64-character hex value"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_same_consensus_and_network_key() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["network_public_key"] =
            value["validators"][0]["consensus_public_key"].clone();
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].network_public_key must differ from consensus_public_key"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_network_key_reused_as_consensus_key() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][1]["network_public_key"] =
            value["validators"][0]["consensus_public_key"].clone();
        refresh_validator_manifest_root(&mut value, 1);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[1].network_public_key must not reuse a consensus_public_key"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_duplicate_reward_accounts() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][1]["reward_account"] = value["validators"][0]["reward_account"].clone();
        refresh_validator_manifest_root(&mut value, 1);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "validators[1].reward_account must be unique"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_reward_account_for_wrong_operator() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["reward_account"] = json!("nbla-reward-operator-c");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "validators[0].reward_account expected nbla-reward-operator-a but got nbla-reward-operator-c"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_concentrated_genesis_power() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["genesis_power"] = json!(3);
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "validators[0].genesis_power must not exceed 5000 bps of total genesis power"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_concentrated_operator_genesis_power() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        let mut validator = value["validators"][0].clone();
        validator["validator_id"] = json!("validator-c");
        validator["node_id"] = json!("bootstrap-us-east-2");
        validator["consensus_public_key"] = json!(hex_64("consensus-key-c"));
        validator["network_public_key"] = json!(hex_64("network-key-c"));
        validator["p2p_endpoint"] = json!("tcp://bootstrap-a2.testnet.nebula.example:26656");
        value["validators"].as_array_mut().unwrap().push(validator);
        refresh_validator_manifest_root(&mut value, 2);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "operator_id operator-a aggregate genesis_power must not exceed 5000 bps of total genesis power"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_unsupported_operator_contact() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["operator_contact"] = json!("irc://operator-a");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].operator_contact must use mailto: or https://"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_operator_contact_without_email_address() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["operator_contact"] = json!("mailto:");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "validators[0].operator_contact must include an email address after mailto:"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_operator_contact_without_https_host() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["operator_contact"] = json!("https://");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].operator_contact must include a host after https://"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_operator_contact_with_mailto_query() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["operator_contact"] =
            json!("mailto:operator-a@testnet.nebula.example?subject=admission");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].operator_contact must not include query or fragment"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_operator_contact_with_multiple_mailto_addresses() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["operator_contact"] =
            json!("mailto:operator-a@testnet.nebula.example,backup-a@testnet.nebula.example");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].operator_contact must include exactly one mailto address"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_p2p_endpoint_without_numeric_port() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["p2p_endpoint"] = json!("tcp://bootstrap-a.testnet.nebula.example");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].p2p_endpoint must include a numeric port"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_p2p_endpoint_with_userinfo() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["p2p_endpoint"] =
            json!("tcp://operator@bootstrap-a.testnet.nebula.example:26656");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].p2p_endpoint must not include userinfo"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_p2p_endpoint_with_fragment() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["p2p_endpoint"] =
            json!("tcp://bootstrap-a.testnet.nebula.example:26656#operator-a");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].p2p_endpoint must not include query or fragment"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_p2p_endpoint_with_path() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["p2p_endpoint"] =
            json!("tcp://bootstrap-a.testnet.nebula.example:26656/p2p");
        refresh_validator_manifest_root(&mut value, 0);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "validators[0].p2p_endpoint must not include a path"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_set_rejects_wrong_admission_signature_root() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["validators"][0]["signed_admission_root"] =
            json!(hex_64("wrong-validator-admission"));

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("validators[0].signed_admission_root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn sample_genesis_manifest_verifies_launch_roots() {
        let report = verify_genesis_manifest_json(&sample_genesis_manifest_json_pretty()).unwrap();

        assert!(report.genesis_ready);
        assert_eq!(report.level, "genesis-manifest-attested");
        assert_eq!(report.initial_validator_count, 2);
        assert_eq!(report.initial_operator_count, 2);
        assert_eq!(report.initial_region_count, 2);
        assert_eq!(report.initial_total_power, 2);
        assert_eq!(report.activation_height, 1);
        assert_eq!(report.native_fee_token, NBLA_SYMBOL);
        assert_eq!(report.native_base_unit, NEBULAI_UNIT);
        assert_eq!(report.bridged_fee_token, NXMR_SYMBOL);
        assert_eq!(report.genesis_root.len(), 64);
        assert_eq!(report.deployment_attestation_root.len(), 64);
        assert_eq!(report.public_surface_root.len(), 64);
        assert_eq!(report.operator_approval_root.len(), 64);
        assert_eq!(report.observer_confirmation_root.len(), 64);
        assert_eq!(report.rollback_readiness_root.len(), 64);
        assert_eq!(report.deployment_validity_root.len(), 64);
        assert_eq!(report.deployment_quorum_root.len(), 64);
        assert_eq!(report.bootstrap_roster_root.len(), 64);
        assert_eq!(report.operational_evidence_root.len(), 64);
        assert_eq!(report.validator_set_root.len(), 64);
        assert_eq!(report.operator_roster_root.len(), 64);
        assert_eq!(report.reward_ledger_root.len(), 64);
        assert_eq!(report.validator_deployment_binding_root.len(), 64);
    }

    #[test]
    fn operator_handoff_builds_from_verified_inputs() {
        let deployment = sample_deployment_attestation_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();

        let report = verify_operator_handoff_jsons(&handoff, &deployment, &validators).unwrap();

        assert!(report.operator_handoff_ready);
        assert_eq!(report.level, "operator-handoff-attested");
        assert_eq!(report.operator_handoff_root.len(), 64);
        assert_eq!(report.validator_deployment_binding_root.len(), 64);
        assert_eq!(report.entry_count, 2);
        assert_eq!(report.operator_count, 2);
        assert_eq!(report.region_count, 2);
    }

    #[test]
    fn operator_handoff_rejects_tampered_entries() {
        let deployment = sample_deployment_attestation_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut handoff = serde_json::from_str::<Value>(
            &build_operator_handoff_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        handoff["entries"][0]["p2p_endpoint"] =
            json!("tcp://different-bootstrap.testnet.nebula.example:26656");

        let error = verify_operator_handoff_jsons(&handoff.to_string(), &deployment, &validators)
            .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "operator handoff entries do not match verified deployment and validator set"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn operator_acceptance_builds_from_verified_handoff() {
        let deployment = sample_deployment_attestation_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();

        let report =
            verify_operator_acceptance_jsons(&acceptance, &handoff, &deployment, &validators)
                .unwrap();

        assert!(report.operator_acceptance_ready);
        assert_eq!(report.level, "operator-acceptance-attested");
        assert_eq!(report.operator_acceptance_root.len(), 64);
        assert_eq!(report.operator_handoff_root.len(), 64);
        assert_eq!(report.accepted_operator_count, 2);
        assert_eq!(report.accepted_validator_count, 2);
    }

    #[test]
    fn operator_acceptance_rejects_unaccepted_entry() {
        let deployment = sample_deployment_attestation_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let mut acceptance = serde_json::from_str::<Value>(
            &build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap(),
        )
        .unwrap();
        acceptance["entries"][0]["accepted"] = json!(false);

        let error = verify_operator_acceptance_jsons(
            &acceptance.to_string(),
            &handoff,
            &deployment,
            &validators,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "entries[0].accepted must be true"));
                assert!(errors.iter().any(|error| error
                    == "operator acceptance entries do not match verified operator handoff and deployment"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn operator_acceptance_rejects_bad_signature_hex() {
        let chain = sample_launch_chain();
        let mut acceptance =
            serde_json::from_str::<OperatorAcceptanceManifest>(&chain.acceptance).unwrap();
        acceptance.entries[0].signature.signature_hex = "00".repeat(64);
        acceptance.root = operator_acceptance_manifest_root(&acceptance);
        let acceptance_json = serde_json::to_string(&acceptance).unwrap();

        let error = verify_operator_acceptance_jsons(
            &acceptance_json,
            &chain.handoff,
            &chain.deployment,
            &chain.validators,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with(
                        "entries[0].signature.signature_hex Ed25519 verification failed",
                    )
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn genesis_manifest_builds_from_verified_inputs() {
        let genesis = build_genesis_manifest_json_pretty(
            &sample_deployment_attestation_json_pretty(),
            &sample_validator_set_json_pretty(),
        )
        .unwrap();

        let report = verify_genesis_manifest_json(&genesis).unwrap();

        assert!(report.genesis_ready);
        assert_eq!(report.initial_validator_count, 2);
        assert_eq!(report.initial_operator_count, 2);
        assert_eq!(report.initial_region_count, 2);
        assert_eq!(report.validator_set_epoch, PUBLIC_TESTNET_GENESIS_EPOCH);
        assert_eq!(report.public_surface_root.len(), 64);
        assert_eq!(report.operator_approval_root.len(), 64);
        assert_eq!(report.observer_confirmation_root.len(), 64);
        assert_eq!(report.rollback_readiness_root.len(), 64);
        assert_eq!(report.deployment_validity_root.len(), 64);
        assert_eq!(report.deployment_quorum_root.len(), 64);
        assert_eq!(report.bootstrap_roster_root.len(), 64);
        assert_eq!(report.operational_evidence_root.len(), 64);
        assert_eq!(report.operator_roster_root.len(), 64);
        assert_eq!(report.reward_ledger_root.len(), 64);
        assert_eq!(report.validator_deployment_binding_root.len(), 64);
    }

    #[test]
    fn genesis_manifest_rejects_unknown_fields() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["unexpected_field"] = json!(true);

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        assert!(matches!(error, AttestationError::MalformedJson(_)));
    }

    #[test]
    fn genesis_manifest_rejects_wrong_activation_height() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["activation_height"] = json!(2);
        value["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(value.clone()).unwrap()
        ));

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "activation_height must be 1"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn genesis_manifest_rejects_wrong_validator_set_epoch() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["validator_set_epoch"] = json!(PUBLIC_TESTNET_GENESIS_EPOCH + 1);
        value["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(value.clone()).unwrap()
        ));

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "validator_set_epoch must be 0"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn genesis_manifest_rejects_insufficient_operator_count() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["initial_operator_count"] = json!(MIN_PUBLIC_TESTNET_OPERATORS - 1);
        value["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(value.clone()).unwrap()
        ));

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "initial_operator_count must be at least 2"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn genesis_manifest_rejects_insufficient_region_count() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["initial_region_count"] = json!(MIN_PUBLIC_TESTNET_REGIONS - 1);
        value["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(value.clone()).unwrap()
        ));

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "initial_region_count must be at least 2"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn genesis_manifest_rejects_stale_genesis_time() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["genesis_time_unix_ms"] = json!(0);
        value["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(value.clone()).unwrap()
        ));

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "genesis_time_unix_ms is older than 24 hours"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn genesis_manifest_rejects_reused_artifact_roots() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["validator_set_root"] = value["deployment_attestation_root"].clone();
        value["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(value.clone()).unwrap()
        ));

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| error
                    == "validator_set_root must differ from deployment_attestation_root"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_verifies_consistent_artifacts() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();

        let report = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis,
        )
        .unwrap();

        assert!(report.launch_package_ready);
        assert_eq!(report.level, "launch-package-attested");
        assert_eq!(report.validator_count, 2);
        assert_eq!(report.total_genesis_power, 2);
        assert_eq!(report.activation_height, 1);
        assert_eq!(report.native_fee_token, NBLA_SYMBOL);
        assert_eq!(report.native_base_unit, NEBULAI_UNIT);
        assert_eq!(report.bridged_fee_token, NXMR_SYMBOL);
        assert_eq!(report.deployment_attestation_root.len(), 64);
        assert_eq!(report.witness_evidence_root.len(), 64);
        assert_eq!(report.public_surface_root.len(), 64);
        assert_eq!(report.operator_approval_root.len(), 64);
        assert_eq!(report.observer_confirmation_root.len(), 64);
        assert_eq!(report.rollback_readiness_root.len(), 64);
        assert_eq!(report.deployment_validity_root.len(), 64);
        assert_eq!(report.deployment_quorum_root.len(), 64);
        assert_eq!(report.bootstrap_roster_root.len(), 64);
        assert_eq!(report.operational_evidence_root.len(), 64);
        assert_eq!(report.public_status_manifest_root.len(), 64);
        assert_eq!(report.public_probe_root.len(), 64);
        assert_eq!(report.endpoint_url, "https://testnet.nebula.example/status");
        assert_eq!(report.launch_bundle_root.len(), 64);
        assert_eq!(report.fee_policy_root.len(), 64);
        assert_eq!(report.validator_set_root.len(), 64);
        assert_eq!(report.validator_set_epoch, PUBLIC_TESTNET_GENESIS_EPOCH);
        assert_eq!(report.operator_roster_root.len(), 64);
        assert_eq!(report.reward_ledger_root.len(), 64);
        assert_eq!(report.validator_deployment_binding_root.len(), 64);
        assert_eq!(report.operator_handoff_root.len(), 64);
        assert_eq!(report.genesis_root.len(), 64);
        assert_eq!(report.matched_validator_count, 2);
        assert_eq!(report.matched_reward_account_count, 2);
        assert_eq!(report.matched_operator_count, 2);
        assert_eq!(report.matched_region_count, 2);
        assert_eq!(report.deployment_operator_count, 2);
        assert_eq!(report.deployment_observer_count, 2);
        assert_eq!(report.deployment_region_count, 2);
        assert_eq!(report.bootstrap_node_count, 2);
    }

    #[test]
    fn launch_package_with_operator_acceptance_verifies_consistent_artifacts() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();

        let report = verify_launch_package_with_operator_acceptance_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(report.launch_package_ready);
        assert_eq!(report.operator_handoff_root.len(), 64);
        assert_eq!(report.matched_operator_count, 2);
        assert_eq!(report.matched_validator_count, 2);
    }

    #[test]
    fn launch_package_with_operator_acceptance_rejects_unaccepted_entry() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let mut acceptance = serde_json::from_str::<Value>(
            &build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap(),
        )
        .unwrap();
        acceptance["entries"][0]["accepted"] = json!(false);
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();

        let error = verify_launch_package_with_operator_acceptance_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance.to_string(),
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "entries[0].accepted must be true"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_bundle_verifies_artifact_hashes_and_roots() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        let report = verify_launch_package_bundle_jsons(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(report.launch_package_bundle_ready);
        assert_eq!(report.level, "launch-package-bundle-attested");
        assert_eq!(report.launch_package_bundle_root.len(), 64);
        assert_eq!(report.launch_package_root.len(), 64);
        assert_eq!(report.operator_acceptance_root.len(), 64);
        assert_eq!(report.artifact_count, 7);
        assert_eq!(report.validator_count, 2);
        assert_eq!(report.matched_operator_count, 2);
        assert_eq!(report.matched_region_count, 2);
    }

    #[test]
    fn public_testnet_peer_manifest_builds_launch_bound_peer_roster() {
        let artifacts = sample_launch_artifacts();
        let manifest_json = build_public_testnet_peer_manifest_json_pretty(
            &artifacts.bundle,
            &artifacts.deployment,
            &artifacts.public_status,
            &artifacts.public_probe,
            &artifacts.validators,
            &artifacts.handoff,
            &artifacts.acceptance,
            &artifacts.genesis,
        )
        .unwrap();

        let manifest = serde_json::from_str::<PublicTestnetPeerManifest>(&manifest_json).unwrap();
        let report = verify_public_testnet_peer_manifest_jsons(
            &manifest_json,
            &artifacts.bundle,
            &artifacts.deployment,
            &artifacts.public_status,
            &artifacts.public_probe,
            &artifacts.validators,
            &artifacts.handoff,
            &artifacts.acceptance,
            &artifacts.genesis,
        )
        .unwrap();

        assert!(report.public_testnet_peer_manifest_ready);
        assert_eq!(report.level, "public-testnet-peer-manifest-attested");
        assert_eq!(report.public_testnet_peer_manifest_root, manifest.root);
        assert_eq!(
            report.launch_package_bundle_root,
            manifest.launch_package_bundle_root
        );
        assert_eq!(report.validator_set_root, manifest.validator_set_root);
        assert_eq!(report.endpoint_url, "https://testnet.nebula.example/status");
        assert_eq!(report.sync_peer_quorum, 1);
        assert_eq!(report.peer_count, 2);
        assert_eq!(report.operator_count, 2);
        assert_eq!(report.region_count, 2);
        assert_eq!(report.rpc_peer_urls.len(), 2);
        assert_eq!(report.snapshot_peer_urls.len(), 2);
        assert_eq!(manifest.peers.len(), 2);
        assert_eq!(
            manifest.peers[0].bootstrap_endpoint,
            "https://bootstrap-a.testnet.nebula.example"
        );
        assert_eq!(
            manifest.peers[0].rpc_url,
            "https://bootstrap-a.testnet.nebula.example/rpc"
        );
        assert_eq!(
            manifest.peers[0].status_url,
            "https://bootstrap-a.testnet.nebula.example/status"
        );
        assert_eq!(
            manifest.peers[0].snapshot_url,
            "https://bootstrap-a.testnet.nebula.example/snapshot"
        );
        assert_eq!(
            manifest.peers[1].rpc_url,
            "https://bootstrap-b.testnet.nebula.example/rpc"
        );
    }

    #[test]
    fn public_testnet_peer_manifest_rejects_tampered_peer_urls() {
        let artifacts = sample_launch_artifacts();
        let manifest_json = build_public_testnet_peer_manifest_json_pretty(
            &artifacts.bundle,
            &artifacts.deployment,
            &artifacts.public_status,
            &artifacts.public_probe,
            &artifacts.validators,
            &artifacts.handoff,
            &artifacts.acceptance,
            &artifacts.genesis,
        )
        .unwrap();
        let mut manifest =
            serde_json::from_str::<PublicTestnetPeerManifest>(&manifest_json).unwrap();
        manifest.peers[0].rpc_url = "https://evil.testnet.nebula.example/rpc".to_string();
        manifest.root = public_testnet_peer_manifest_root(&manifest);
        let tampered_json = serde_json::to_string(&manifest).unwrap();

        let error = verify_public_testnet_peer_manifest_jsons(
            &tampered_json,
            &artifacts.bundle,
            &artifacts.deployment,
            &artifacts.public_status,
            &artifacts.public_probe,
            &artifacts.validators,
            &artifacts.handoff,
            &artifacts.acceptance,
            &artifacts.genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "peers do not match verified launch validator and bootstrap artifacts"
                }));
                assert!(errors.iter().any(|error| {
                    error.starts_with(
                        "root does not match expected public testnet peer manifest root",
                    )
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_testnet_peer_manifest_rejects_impossible_sync_quorum() {
        let artifacts = sample_launch_artifacts();
        let manifest_json = build_public_testnet_peer_manifest_json_pretty(
            &artifacts.bundle,
            &artifacts.deployment,
            &artifacts.public_status,
            &artifacts.public_probe,
            &artifacts.validators,
            &artifacts.handoff,
            &artifacts.acceptance,
            &artifacts.genesis,
        )
        .unwrap();
        let mut manifest =
            serde_json::from_str::<PublicTestnetPeerManifest>(&manifest_json).unwrap();
        manifest.sync_peer_quorum = 2;
        manifest.root = public_testnet_peer_manifest_root(&manifest);
        let tampered_json = serde_json::to_string(&manifest).unwrap();

        let error = verify_public_testnet_peer_manifest_jsons(
            &tampered_json,
            &artifacts.bundle,
            &artifacts.deployment,
            &artifacts.public_status,
            &artifacts.public_probe,
            &artifacts.validators,
            &artifacts.handoff,
            &artifacts.acceptance,
            &artifacts.genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => assert!(errors
                .iter()
                .any(|error| error == "sync_peer_quorum must be <= 1 for 2 peers")),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn runtime_launch_binding_builds_from_verified_bundle_and_validator_set() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        let binding = build_runtime_launch_binding_from_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
            &bundle,
            "validator-a",
        )
        .unwrap();
        binding
            .validate_against_config(&runtime::RuntimeConfig::public_testnet_default())
            .unwrap();
        assert_eq!(binding.chain_id, CHAIN_ID);
        assert_eq!(binding.runtime_version, VERSION);
        assert_eq!(binding.validator_count, 2);
        assert_eq!(binding.operator_count, 2);
        assert_eq!(binding.region_count, 2);
        assert_eq!(binding.launch_package_bundle_root.len(), 64);
        assert_eq!(binding.fee_policy_root, fee_policy_root());
        assert_eq!(binding.validator_reward_accounts.len(), 2);
        assert_eq!(
            binding.validator_reward_accounts[0].reward_account,
            "nbla-reward-operator-a"
        );
        assert_eq!(
            binding.validator_reward_accounts[1].reward_account,
            "nbla-reward-operator-b"
        );
        assert_eq!(binding.bridge_operator_keys.len(), 2);
        assert_eq!(binding.bridge_operator_keys[0].operator_id, "operator-a");
        assert_eq!(binding.bridge_operator_keys[1].operator_id, "operator-b");
        assert_eq!(binding.bridge_observer_keys.len(), 2);
        assert_eq!(
            binding.bridge_observer_keys[0].observer_id,
            "observer-eu-west-1"
        );
        assert_eq!(
            binding.bridge_observer_keys[1].observer_id,
            "observer-us-east-1"
        );

        let error = build_runtime_launch_binding_from_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
            &bundle,
            "validator-z",
        )
        .unwrap_err();
        match error {
            AttestationError::Invalid(errors) => assert!(errors
                .iter()
                .any(|error| error == "validator_id validator-z is not admitted in validator set")),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_bundle_rejects_tampered_artifact_hash() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let mut bundle = serde_json::from_str::<Value>(
            &build_launch_package_bundle_json_pretty(
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap(),
        )
        .unwrap();
        bundle["public_probe_sha3_256"] = json!(hex_64("wrong-public-probe-artifact"));

        let error = verify_launch_package_bundle_jsons(
            &bundle.to_string(),
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.starts_with("public_probe_sha3_256 does not match")));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_activation_verifies_against_launch_package_bundle() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        let report = verify_validator_activation_jsons(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(report.validator_activation_ready);
        assert_eq!(report.level, "validator-activation-attested");
        assert_eq!(report.validator_activation_root.len(), 64);
        assert_eq!(report.launch_package_bundle_root.len(), 64);
        assert_eq!(report.operator_acceptance_root.len(), 64);
        assert_eq!(report.activated_validator_count, 2);
        assert_eq!(report.activated_operator_count, 2);
    }

    #[test]
    fn validator_activation_rejects_inactive_entry() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let mut activation = serde_json::from_str::<Value>(
            &build_validator_activation_json_pretty(
                &bundle,
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap(),
        )
        .unwrap();
        activation["entries"][0]["activated"] = json!(false);

        let error = verify_validator_activation_jsons(
            &activation.to_string(),
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "entries[0].activated must be true"));
                assert!(errors.iter().any(|error| {
                    error
                    == "validator activation entries do not match verified bundle and validator set"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_activation_rejects_signature_public_key_mismatch() {
        let chain = sample_launch_chain();
        let mut activation =
            serde_json::from_str::<ValidatorActivationManifest>(&chain.activation).unwrap();
        activation.entries[0].signature.public_key =
            activation.entries[1].signature.public_key.clone();
        activation.entries[0].signature.signature_sha3_256 =
            validator_activation_signature_root(&activation.entries[0]);
        complete_sample_signature(&mut activation.entries[0].signature);
        activation.root = validator_activation_manifest_root(&activation);
        let activation_json = serde_json::to_string(&activation).unwrap();

        let error = verify_validator_activation_jsons(
            &activation_json,
            &chain.bundle,
            &chain.deployment,
            &chain.public_status,
            &chain.public_probe,
            &chain.validators,
            &chain.handoff,
            &chain.acceptance,
            &chain.genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("entries[0].signature.public_key expected")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn validator_join_receipt_verifies_after_activation() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        let report = verify_validator_join_receipt_jsons(
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(report.validator_join_ready);
        assert_eq!(report.level, "validator-join-attested");
        assert_eq!(report.validator_join_root.len(), 64);
        assert_eq!(report.joined_validator_count, 2);
        assert_eq!(report.joined_operator_count, 2);
        assert_eq!(report.activation_height, PUBLIC_TESTNET_ACTIVATION_HEIGHT);
        assert_eq!(
            report.min_observed_block_height,
            PUBLIC_TESTNET_ACTIVATION_HEIGHT
        );
        assert_eq!(report.min_peer_count, 1);
    }

    #[test]
    fn validator_join_receipt_rejects_pre_activation_height() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let mut join = serde_json::from_str::<Value>(
            &build_validator_join_receipt_json_pretty(
                &activation,
                &bundle,
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap(),
        )
        .unwrap();
        join["entries"][0]["observed_block_height"] = json!(0);

        let error = verify_validator_join_receipt_jsons(
            &join.to_string(),
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "entries[0].observed_block_height must be at least 1"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn operator_join_confirmation_verifies_after_validator_join() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let confirmation = build_operator_join_confirmation_json_pretty(
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        let report = verify_operator_join_confirmation_jsons(
            &confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(report.operator_join_confirmation_ready);
        assert_eq!(report.level, "operator-join-confirmed");
        assert_eq!(report.operator_join_confirmation_root.len(), 64);
        assert_eq!(report.validator_join_root.len(), 64);
        assert_eq!(report.confirmed_validator_count, 2);
        assert_eq!(report.confirmed_operator_count, 2);
    }

    #[test]
    fn operator_join_confirmation_rejects_unconfirmed_entry() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let mut confirmation = serde_json::from_str::<Value>(
            &build_operator_join_confirmation_json_pretty(
                &join,
                &activation,
                &bundle,
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap(),
        )
        .unwrap();
        confirmation["entries"][0]["confirmed"] = json!(false);

        let error = verify_operator_join_confirmation_jsons(
            &confirmation.to_string(),
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "entries[0].confirmed must be true"));
                assert!(errors.iter().any(|error| {
                    error
                        == "operator join confirmation entries do not match verified validator join and operator acceptance"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_observer_confirmation_verifies_after_operator_join_confirmation() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join_confirmation = build_operator_join_confirmation_json_pretty(
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let observer_confirmation = build_public_observer_confirmation_json_pretty(
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        let report = verify_public_observer_confirmation_jsons(
            &observer_confirmation,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(report.public_observer_confirmation_ready);
        assert_eq!(report.level, "public-observer-confirmed");
        assert_eq!(report.public_observer_confirmation_root.len(), 64);
        assert_eq!(report.operator_join_confirmation_root.len(), 64);
        assert_eq!(report.confirmed_observer_count, 2);
        assert_eq!(report.confirmed_region_count, 2);
        assert_eq!(report.endpoint_url, "https://testnet.nebula.example/status");
    }

    #[test]
    fn public_observer_confirmation_rejects_wrong_probe_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join_confirmation = build_operator_join_confirmation_json_pretty(
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let mut observer_confirmation = serde_json::from_str::<Value>(
            &build_public_observer_confirmation_json_pretty(
                &join_confirmation,
                &join,
                &activation,
                &bundle,
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap(),
        )
        .unwrap();
        observer_confirmation["entries"][0]["observed_public_probe_root"] =
            json!(hex_64("different-public-probe-root"));

        let error = verify_public_observer_confirmation_jsons(
            &observer_confirmation.to_string(),
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("entries[0].observed_public_probe_root does not match")
                }));
                assert!(errors.iter().any(|error| {
                    error
                        == "public observer confirmation entries do not match verified deployment observers and public surface"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_observer_confirmation_rejects_wrong_signed_root() {
        let chain = sample_launch_chain();
        let mut observer_confirmation = serde_json::from_str::<PublicObserverConfirmationManifest>(
            &chain.observer_confirmation,
        )
        .unwrap();
        observer_confirmation.entries[0]
            .signature
            .signature_sha3_256 = hex_64("wrong-public-observer-confirmation-signature-root");
        complete_sample_signature(&mut observer_confirmation.entries[0].signature);
        observer_confirmation.root =
            public_observer_confirmation_manifest_root(&observer_confirmation);
        let observer_confirmation_json = serde_json::to_string(&observer_confirmation).unwrap();

        let error = verify_public_observer_confirmation_jsons(
            &observer_confirmation_json,
            &chain.join_confirmation,
            &chain.join,
            &chain.activation,
            &chain.bundle,
            &chain.deployment,
            &chain.public_status,
            &chain.public_probe,
            &chain.validators,
            &chain.handoff,
            &chain.acceptance,
            &chain.genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("entries[0].signature.signature_sha3_256 does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_testnet_launch_certificate_verifies_full_candidate_chain() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join_confirmation = build_operator_join_confirmation_json_pretty(
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let observer_confirmation = build_public_observer_confirmation_json_pretty(
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let (live_rehearsal_report, runtime_surface_evidence) =
            prove_live_rpc_devnet_rehearsal_with_jsons_and_evidence(
                &bundle,
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap();
        let runtime_surface = serde_json::to_string_pretty(&runtime_surface_evidence).unwrap();
        let live_rehearsal = serde_json::to_string_pretty(&live_rehearsal_report).unwrap();
        let certificate = build_public_testnet_launch_certificate_json_pretty(
            &observer_confirmation,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        let report = verify_public_testnet_launch_certificate_jsons(
            &certificate,
            &observer_confirmation,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(report.public_testnet_launch_certificate_ready);
        assert_eq!(report.level, "public-testnet-launch-candidate-certified");
        assert_eq!(report.public_testnet_launch_certificate_root.len(), 64);
        assert_eq!(report.runtime_surface_root.len(), 64);
        assert_eq!(report.validator_count, 2);
        assert_eq!(report.operator_count, 2);
        assert_eq!(report.observer_count, 2);
        assert_eq!(report.region_count, 2);
        assert_eq!(report.endpoint_url, "https://testnet.nebula.example/status");

        let loopback_ready_error = verify_public_testnet_launch_readiness_jsons(
            &certificate,
            &observer_confirmation,
            &runtime_surface,
            &live_rehearsal,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();
        match loopback_ready_error {
            AttestationError::Invalid(errors) => assert!(errors.iter().any(|error| {
                error
                    == "runtime_surface.capture_mode expected external-public-endpoint but got loopback-devnet"
            })),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let missing_tls_error = external_public_runtime_surface_from(&runtime_surface, None)
            .expect_err("external runtime surface evidence requires a TLS observation");
        match missing_tls_error {
            AttestationError::Invalid(errors) => assert!(errors.iter().any(|error| {
                error
                    == "runtime_surface.tls_observation is required for external-public-endpoint capture"
            })),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let deployment_attestation =
            serde_json::from_str::<DeploymentAttestation>(&deployment).unwrap();
        let matching_tls_observation = deployment_attestation.public_endpoint.tls_pins[0].clone();
        let external_runtime_surface =
            external_public_runtime_surface_from(&runtime_surface, Some(matching_tls_observation))
                .unwrap();
        let external_certificate = build_public_testnet_launch_certificate_json_pretty(
            &observer_confirmation,
            &external_runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let readiness = verify_public_testnet_launch_readiness_jsons(
            &external_certificate,
            &observer_confirmation,
            &external_runtime_surface,
            &live_rehearsal,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        assert!(readiness.public_launch_ready);
        assert_eq!(readiness.level, "public-testnet-launch-ready");
        assert!(readiness.blocking_gaps.is_empty());
        assert_eq!(
            readiness.runtime_surface_capture_mode,
            RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT
        );
        assert_eq!(readiness.public_launch_readiness_root.len(), 64);
        assert_eq!(
            readiness.public_testnet_launch_certificate_root,
            verify_public_testnet_launch_certificate_jsons(
                &external_certificate,
                &observer_confirmation,
                &external_runtime_surface,
                &join_confirmation,
                &join,
                &activation,
                &bundle,
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap()
            .public_testnet_launch_certificate_root
        );
        assert_eq!(
            readiness.live_rpc_devnet_rehearsal_root,
            serde_json::from_str::<LiveRpcDevnetRehearsalReport>(&live_rehearsal)
                .unwrap()
                .rehearsal_root
        );
        assert_eq!(
            readiness.live_rpc_devnet_runtime_surface_root,
            verify_runtime_surface_evidence_json(&runtime_surface)
                .unwrap()
                .runtime_surface_root
        );

        let mut forged_rehearsal_surface_root =
            serde_json::from_str::<LiveRpcDevnetRehearsalReport>(&live_rehearsal).unwrap();
        forged_rehearsal_surface_root.runtime_surface_root =
            hex_64("forged-live-rpc-devnet-runtime-surface-root");
        forged_rehearsal_surface_root.rehearsal_root =
            live_rpc_devnet_rehearsal_root(&forged_rehearsal_surface_root);
        let forged_rehearsal_surface_root =
            serde_json::to_string_pretty(&forged_rehearsal_surface_root).unwrap();
        let forged_surface_ready_error = verify_public_testnet_launch_readiness_jsons(
            &external_certificate,
            &observer_confirmation,
            &external_runtime_surface,
            &forged_rehearsal_surface_root,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();
        match forged_surface_ready_error {
            AttestationError::Invalid(errors) => assert!(errors.iter().any(|error| {
                error.starts_with("live_rpc_devnet_runtime_surface.runtime_surface_root expected ")
            })),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let mut wrong_rehearsal =
            serde_json::from_str::<LiveRpcDevnetRehearsalReport>(&live_rehearsal).unwrap();
        wrong_rehearsal.launch_package_bundle_root =
            hex_64("wrong-live-rpc-devnet-launch-package-bundle");
        wrong_rehearsal.rehearsal_root = live_rpc_devnet_rehearsal_root(&wrong_rehearsal);
        let wrong_rehearsal = serde_json::to_string_pretty(&wrong_rehearsal).unwrap();
        let wrong_rehearsal_ready_error = verify_public_testnet_launch_readiness_jsons(
            &external_certificate,
            &observer_confirmation,
            &external_runtime_surface,
            &wrong_rehearsal,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();
        match wrong_rehearsal_ready_error {
            AttestationError::Invalid(errors) => assert!(errors.iter().any(|error| {
                error.starts_with("live_rpc_devnet_rehearsal.launch_package_bundle_root expected ")
            })),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let status_only_economics_error =
            runtime_surface_with_economics_counters(&external_runtime_surface, 0, 0, 0)
                .unwrap_err();
        match status_only_economics_error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "runtime_surface.status.total_nxmr_fees_units expected snapshot 1000 but got 0"
                }));
                assert!(errors.iter().any(|error| {
                    error
                        == "runtime_surface.status.validator_reward_nebulai expected snapshot 1010 but got 0"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let mispriced_nxmr_runtime_surface = runtime_surface_with_snapshot_economics_counters(
            &external_runtime_surface,
            1_000,
            999,
            1_010,
        );
        let mispriced_nxmr_error =
            verify_runtime_surface_evidence_json(&mispriced_nxmr_runtime_surface).unwrap_err();
        match mispriced_nxmr_error {
            AttestationError::Invalid(errors) => assert!(errors.iter().any(|error| {
                error.contains(
                    "buyback_pool_nebulai expected 1000 from included nXMR receipts but got 999",
                )
            })),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let wrong_endpoint = "https://other.testnet.nebula.example/status";
        let wrong_endpoint_runtime_surface =
            runtime_surface_with_endpoint_url(&external_runtime_surface, wrong_endpoint).unwrap();
        let wrong_endpoint_ready_error = verify_public_testnet_launch_readiness_jsons(
            &external_certificate,
            &observer_confirmation,
            &wrong_endpoint_runtime_surface,
            &live_rehearsal,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();
        match wrong_endpoint_ready_error {
            AttestationError::Invalid(errors) => assert!(errors.iter().any(|error| {
                error
                    == "runtime_surface.endpoint_url expected https://testnet.nebula.example/status but got https://other.testnet.nebula.example/status"
            })),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let mismatched_tls_observation = TlsEndpointPin {
            cert_sha256: "cc".repeat(32),
            public_key_sha256: "dd".repeat(32),
            not_after_unix_ms: unix_ms() + 2_592_000_000,
        };
        let mismatched_runtime_surface = external_public_runtime_surface_from(
            &runtime_surface,
            Some(mismatched_tls_observation),
        )
        .unwrap();
        let mismatched_certificate = build_public_testnet_launch_certificate_json_pretty(
            &observer_confirmation,
            &mismatched_runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let mismatch_ready_error = verify_public_testnet_launch_readiness_jsons(
            &mismatched_certificate,
            &observer_confirmation,
            &mismatched_runtime_surface,
            &live_rehearsal,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();
        match mismatch_ready_error {
            AttestationError::Invalid(errors) => assert!(errors.iter().any(|error| {
                error
                    == "runtime_surface.tls_observation does not match deployment public_endpoint.tls_pins"
            })),
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn public_testnet_launch_certificate_rejects_wrong_validator_count() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join_confirmation = build_operator_join_confirmation_json_pretty(
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let observer_confirmation = build_public_observer_confirmation_json_pretty(
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let runtime_surface = build_live_rpc_devnet_runtime_surface_evidence_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let certificate = serde_json::from_str::<Value>(
            &build_public_testnet_launch_certificate_json_pretty(
                &observer_confirmation,
                &runtime_surface,
                &join_confirmation,
                &join,
                &activation,
                &bundle,
                &deployment,
                &public_status,
                &public_probe,
                &validators,
                &handoff,
                &acceptance,
                &genesis,
            )
            .unwrap(),
        )
        .unwrap();
        let mut wrong_validator_count = certificate.clone();
        wrong_validator_count["validator_count"] = json!(1);
        wrong_validator_count["root"] = json!(public_testnet_launch_certificate_root(
            &serde_json::from_value::<PublicTestnetLaunchCertificate>(
                wrong_validator_count.clone()
            )
            .unwrap()
        ));

        let error = verify_public_testnet_launch_certificate_jsons(
            &wrong_validator_count.to_string(),
            &observer_confirmation,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "validator_count expected 2 but got 1"));
                assert!(errors.iter().any(|error| {
                    error.starts_with("public testnet launch certificate root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let mut wrong_fee_policy = certificate.clone();
        wrong_fee_policy["fee_policy_root"] = json!(hex_64("wrong-fee-policy-root"));
        wrong_fee_policy["root"] = json!(public_testnet_launch_certificate_root(
            &serde_json::from_value::<PublicTestnetLaunchCertificate>(wrong_fee_policy.clone())
                .unwrap()
        ));

        let error = verify_public_testnet_launch_certificate_jsons(
            &wrong_fee_policy.to_string(),
            &observer_confirmation,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.starts_with("fee_policy_root does not match")));
                assert!(errors.iter().any(|error| {
                    error.starts_with("public testnet launch certificate root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }

        let mut wrong_runtime_surface = certificate;
        wrong_runtime_surface["runtime_surface_root"] = json!(hex_64("wrong-runtime-surface-root"));
        wrong_runtime_surface["root"] = json!(public_testnet_launch_certificate_root(
            &serde_json::from_value::<PublicTestnetLaunchCertificate>(
                wrong_runtime_surface.clone()
            )
            .unwrap()
        ));

        let error = verify_public_testnet_launch_certificate_jsons(
            &wrong_runtime_surface.to_string(),
            &observer_confirmation,
            &runtime_surface,
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.starts_with("runtime_surface_root does not match")));
                assert!(errors.iter().any(|error| {
                    error.starts_with("public testnet launch certificate root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_roots() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["deployment_attestation_root"] = json!(hex_64("different-deployment-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error
                        .starts_with("genesis deployment_attestation_root does not match")));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_public_surface_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["public_surface_root"] = json!(hex_64("different-public-surface-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.starts_with("genesis public_surface_root does not match")));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_operator_approval_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["operator_approval_root"] = json!(hex_64("different-operator-approval-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("genesis operator_approval_root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_observer_confirmation_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["observer_confirmation_root"] =
            json!(hex_64("different-observer-confirmation-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("genesis observer_confirmation_root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_rollback_readiness_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["rollback_readiness_root"] = json!(hex_64("different-rollback-readiness-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("genesis rollback_readiness_root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_deployment_validity_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["deployment_validity_root"] = json!(hex_64("different-deployment-validity-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("genesis deployment_validity_root does not match")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_deployment_quorum_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["deployment_quorum_root"] = json!(hex_64("different-deployment-quorum-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(
                    |error| error.starts_with("genesis deployment_quorum_root does not match")
                ));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_bootstrap_roster_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["bootstrap_roster_root"] = json!(hex_64("different-bootstrap-roster-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(
                    errors
                        .iter()
                        .any(|error| error
                            .starts_with("genesis bootstrap_roster_root does not match"))
                );
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_operational_evidence_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["operational_evidence_root"] = json!(hex_64("different-operational-evidence"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error
                        .starts_with("genesis operational_evidence_root does not match")));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_operator_and_region_counts() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["initial_operator_count"] = json!(MIN_PUBLIC_TESTNET_OPERATORS + 1);
        genesis["initial_region_count"] = json!(MIN_PUBLIC_TESTNET_REGIONS + 1);
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "genesis initial_operator_count expected 2 but got 3"));
                assert!(errors
                    .iter()
                    .any(|error| error == "genesis initial_region_count expected 2 but got 3"));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_operator_roster_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["operator_roster_root"] = json!(hex_64("different-operator-roster-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.starts_with("genesis operator_roster_root does not match")));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_reward_ledger_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["reward_ledger_root"] = json!(hex_64("different-reward-ledger-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error.starts_with("genesis reward_ledger_root does not match")));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_genesis_validator_deployment_binding_root() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["validator_deployment_binding_root"] =
            json!(hex_64("different-validator-deployment-binding-root"));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| error
                    .starts_with("genesis validator_deployment_binding_root does not match")));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_genesis_time_before_deployment_generation() {
        let deployment = sample_deployment_attestation_json_pretty();
        let deployment_value = serde_json::from_str::<Value>(&deployment).unwrap();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        let generated_at = deployment_value["generated_at_unix_ms"]
            .as_u64()
            .expect("sample generated_at fits u64");
        genesis["genesis_time_unix_ms"] = json!(generated_at.saturating_sub(1));
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with(
                        "genesis genesis_time_unix_ms must be at or after deployment generated_at_unix_ms",
                    )
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_genesis_time_after_deployment_expiry() {
        let mut deployment =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        let now = unix_ms();
        deployment["generated_at_unix_ms"] = json!(now);
        deployment["expires_at_unix_ms"] = json!(now + 60_000);
        let deployment = deployment.to_string();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let mut genesis = serde_json::from_str::<Value>(
            &build_genesis_manifest_json_pretty(&deployment, &validators).unwrap(),
        )
        .unwrap();
        genesis["genesis_time_unix_ms"] = json!(now + 60_001);
        genesis["root"] = json!(genesis_manifest_root(
            &serde_json::from_value::<GenesisManifest>(genesis.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis.to_string(),
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with(
                        "genesis genesis_time_unix_ms must be at or before deployment expires_at_unix_ms",
                    )
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_mismatched_public_probe() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let mut public_probe =
            serde_json::from_str::<Value>(&sample_public_probe_json_pretty()).unwrap();
        let validators = sample_validator_set_json_pretty();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();

        public_probe["body"]["launch_bundle_root"] = json!(hex_64("different-launch-bundle"));
        public_probe["root"] = json!(public_probe_root(
            &serde_json::from_value::<PublicProbe>(public_probe.clone()).unwrap()
        ));

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe.to_string(),
            &validators,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error.starts_with("public_probe.body.launch_bundle_root expected")
                }));
                assert!(errors.iter().any(|error| {
                    error.starts_with("public probe root does not match deployment attestation")
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_validator_without_attested_operator() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let mut validators =
            serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        validators["validators"][0]["operator_id"] = json!("operator-c");
        validators["validators"][0]["reward_account"] = json!("nbla-reward-operator-c");
        refresh_validator_manifest_root(&mut validators, 0);
        let genesis =
            build_genesis_manifest_json_pretty(&deployment, &validators.to_string()).unwrap();

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators.to_string(),
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "validators[0].operator_id operator-c is not present in deployment operators"
                }));
                assert!(errors.iter().any(|error| {
                    error
                        == "validators[0].bootstrap_node.operator_id expected operator-c but got operator-a"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_validator_without_attested_bootstrap_node() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let mut validators =
            serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        validators["validators"][0]["node_id"] = json!("bootstrap-ap-south-1");
        refresh_validator_manifest_root(&mut validators, 0);
        let genesis =
            build_genesis_manifest_json_pretty(&deployment, &validators.to_string()).unwrap();

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators.to_string(),
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "validators[0].node_id bootstrap-ap-south-1 is not present in deployment bootstrap_nodes"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_validator_p2p_host_mismatched_bootstrap_endpoint() {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let mut validators =
            serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        validators["validators"][0]["p2p_endpoint"] =
            json!("tcp://other-bootstrap.testnet.nebula.example:26656");
        refresh_validator_manifest_root(&mut validators, 0);
        let genesis =
            build_genesis_manifest_json_pretty(&deployment, &validators.to_string()).unwrap();

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators.to_string(),
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "validators[0].p2p_endpoint.host expected bootstrap-a.testnet.nebula.example but got other-bootstrap.testnet.nebula.example"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_validator_key_reused_as_witness_key() {
        let deployment = sample_deployment_attestation_json_pretty();
        let deployment_value = serde_json::from_str::<Value>(&deployment).unwrap();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let mut validators =
            serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        validators["validators"][0]["consensus_public_key"] =
            deployment_value["operators"][0]["public_key"].clone();
        refresh_validator_manifest_root(&mut validators, 0);
        let validators = validators.to_string();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error
                        == "validators[0].consensus_public_key must not reuse a deployment witness public key"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    #[test]
    fn launch_package_rejects_unadmitted_deployment_operator_and_bootstrap_node() {
        let mut deployment =
            serde_json::from_str::<Value>(&sample_deployment_attestation_json_pretty()).unwrap();
        let mut operator = deployment["operators"][0].clone();
        operator["operator_id"] = json!("operator-c");
        operator["region"] = json!("ap-south");
        operator["public_key"] = json!(hex_64("operator-c-key"));
        deployment["operators"]
            .as_array_mut()
            .unwrap()
            .push(operator);
        refresh_operator_signature_root(&mut deployment, 2);

        let mut bootstrap_node = deployment["bootstrap_nodes"][0].clone();
        bootstrap_node["node_id"] = json!("bootstrap-ap-south-1");
        bootstrap_node["operator_id"] = json!("operator-c");
        bootstrap_node["region"] = json!("ap-south");
        bootstrap_node["endpoint"] = json!("https://bootstrap-ap-south-1.nebula.example:443");
        deployment["bootstrap_nodes"]
            .as_array_mut()
            .unwrap()
            .push(bootstrap_node);
        refresh_bootstrap_node_root(&mut deployment, 2);

        let deployment = deployment.to_string();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();

        let error = verify_launch_package_jsons(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &genesis,
        )
        .unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors.iter().any(|error| {
                    error == "operators[2].operator_id operator-c has no admitted validator"
                }));
                assert!(errors.iter().any(|error| {
                    error
                        == "bootstrap_nodes[2].node_id bootstrap-ap-south-1 has no admitted validator"
                }));
            }
            AttestationError::MalformedJson(error) => panic!("unexpected malformed JSON: {error}"),
        }
    }

    struct SampleLaunchChain {
        deployment: String,
        public_status: String,
        public_probe: String,
        validators: String,
        handoff: String,
        acceptance: String,
        genesis: String,
        bundle: String,
        activation: String,
        join: String,
        join_confirmation: String,
        observer_confirmation: String,
    }

    fn sample_launch_chain() -> SampleLaunchChain {
        let deployment = sample_deployment_attestation_json_pretty();
        let public_status = sample_public_status_manifest_json_pretty();
        let public_probe = sample_public_probe_json_pretty();
        let validators = sample_validator_set_json_pretty();
        let handoff = build_operator_handoff_json_pretty(&deployment, &validators).unwrap();
        let acceptance =
            build_operator_acceptance_json_pretty(&handoff, &deployment, &validators).unwrap();
        let genesis = build_genesis_manifest_json_pretty(&deployment, &validators).unwrap();
        let bundle = build_launch_package_bundle_json_pretty(
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let activation = build_validator_activation_json_pretty(
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join = build_validator_join_receipt_json_pretty(
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let join_confirmation = build_operator_join_confirmation_json_pretty(
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();
        let observer_confirmation = build_public_observer_confirmation_json_pretty(
            &join_confirmation,
            &join,
            &activation,
            &bundle,
            &deployment,
            &public_status,
            &public_probe,
            &validators,
            &handoff,
            &acceptance,
            &genesis,
        )
        .unwrap();

        SampleLaunchChain {
            deployment,
            public_status,
            public_probe,
            validators,
            handoff,
            acceptance,
            genesis,
            bundle,
            activation,
            join,
            join_confirmation,
            observer_confirmation,
        }
    }

    fn refresh_validator_manifest_root(manifest: &mut Value, validator_index: usize) {
        let fee_policy_root = manifest["fee_policy_root"]
            .as_str()
            .expect("sample fee policy root")
            .to_string();
        let validator = serde_json::from_value::<ValidatorAdmission>(
            manifest["validators"][validator_index].clone(),
        )
        .unwrap();
        manifest["validators"][validator_index]["signed_admission_root"] = json!(
            validator_admission_signature_root(&validator, &fee_policy_root)
        );
        manifest["root"] = json!(validator_set_root(
            &serde_json::from_value::<ValidatorSetManifest>(manifest.clone()).unwrap()
        ));
    }

    fn refresh_observer_signature_root(attestation: &mut Value, observer_index: usize) {
        let deployment =
            serde_json::from_value::<DeploymentAttestation>(attestation.clone()).unwrap();
        let witness_evidence_root = deployment_witness_root(
            &deployment.launch_bundle,
            &deployment.public_status_manifest,
            &deployment.public_endpoint,
            &deployment.policy_claim,
            &deployment.public_probe,
        );
        let mut observer = serde_json::from_value::<ObserverAttestation>(
            attestation["observers"][observer_index].clone(),
        )
        .unwrap();
        observer.signature.signature_sha3_256 =
            observer_signature_root(&observer, &witness_evidence_root);
        complete_sample_signature(&mut observer.signature);
        attestation["observers"][observer_index]["signature"] = json!(observer.signature);
    }

    fn refresh_operator_signature_root(attestation: &mut Value, operator_index: usize) {
        let deployment =
            serde_json::from_value::<DeploymentAttestation>(attestation.clone()).unwrap();
        let witness_evidence_root = deployment_witness_root(
            &deployment.launch_bundle,
            &deployment.public_status_manifest,
            &deployment.public_endpoint,
            &deployment.policy_claim,
            &deployment.public_probe,
        );
        let operator = serde_json::from_value::<OperatorAttestation>(
            attestation["operators"][operator_index].clone(),
        )
        .unwrap();
        attestation["operators"][operator_index]["signature_sha3_256"] =
            json!(operator_signature_root(&operator, &witness_evidence_root));
    }

    fn refresh_bootstrap_node_root(attestation: &mut Value, node_index: usize) {
        let deployment =
            serde_json::from_value::<DeploymentAttestation>(attestation.clone()).unwrap();
        let witness_evidence_root = deployment_witness_root(
            &deployment.launch_bundle,
            &deployment.public_status_manifest,
            &deployment.public_endpoint,
            &deployment.policy_claim,
            &deployment.public_probe,
        );
        let node = serde_json::from_value::<BootstrapNode>(
            attestation["bootstrap_nodes"][node_index].clone(),
        )
        .unwrap();
        attestation["bootstrap_nodes"][node_index]["attestation_root"] =
            json!(bootstrap_node_root(&node, &witness_evidence_root));
    }
}

#[cfg(test)]
mod economics {
    use super::*;

    #[test]
    fn nbla_fee_goes_directly_to_validator_rewards() {
        let quote = quote_hybrid_fee(FeeAsset::Nbla, 25, 4_000, None).unwrap();

        assert_eq!(quote.payment_asset_symbol, NBLA_SYMBOL);
        assert_eq!(quote.required_fee_nebulai, 100_000);
        assert_eq!(quote.paid_amount_units, 100_000);
        assert_eq!(quote.buyback_nebulai, 0);
        assert_eq!(quote.reserve_backing_nebulai, 0);
        assert_eq!(quote.validator_reward_nebulai, 100_000);
        assert_eq!(quote.validator_points, 100_000);
    }

    #[test]
    fn nxmr_fee_buys_nbla_and_rewards_validators_at_target_rate() {
        let quote = quote_hybrid_fee_at_target_rate(FeeAsset::NXmr, 100, 10_000).unwrap();

        assert_eq!(quote.payment_asset_symbol, NXMR_SYMBOL);
        assert_eq!(quote.required_fee_nebulai, 1_000_000);
        assert_eq!(quote.paid_amount_units, 1_000_000);
        assert_eq!(quote.converted_nbla_nebulai, 1_000_000);
        assert_eq!(quote.buyback_nebulai, 1_000_000);
        assert_eq!(quote.reserve_backing_nebulai, 0);
        assert_eq!(quote.validator_reward_nebulai, 1_000_000);
        assert_eq!(quote.validator_points, 1_000_000);
    }

    #[test]
    fn nbla_target_rate_maps_one_nebulai_to_one_nxmr_base_unit() {
        assert_eq!(NEBULAI_PER_NBLA, 1_000_000);
        assert_eq!(TARGET_NXMR_BASE_UNITS_PER_NXMR, 1_000_000_000);
        assert_eq!(TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT, 1);
    }

    #[test]
    fn nxmr_fee_requires_conversion_rate() {
        assert_eq!(
            quote_hybrid_fee(FeeAsset::NXmr, 1, 1, None).unwrap_err(),
            FeeError::MissingNXmrRate
        );
    }
}
