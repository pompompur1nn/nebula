#![recursion_limit = "256"]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "nebula-testnet-runner/0.2.0";
pub const CHAIN_ID: &str = "nebula-private-l2-testnet";
pub const PUBLIC_LAUNCH_BLOCKER: &str = "public-launch-deployment-attestation";
pub const NBLA_SYMBOL: &str = "NBLA";
pub const NXMR_SYMBOL: &str = "nXMR";
pub const NEBULAI_UNIT: &str = "nebulai";
pub const NEBULAI_PER_NBLA: u128 = 1_000_000;
pub const NBLA_TARGET_NXMR_NUMERATOR: u128 = 1;
pub const NBLA_TARGET_NXMR_DENOMINATOR: u128 = 1_000;
pub const TARGET_NXMR_BASE_UNITS_PER_NXMR: u128 =
    NEBULAI_PER_NBLA * NBLA_TARGET_NXMR_DENOMINATOR / NBLA_TARGET_NXMR_NUMERATOR;
pub const TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT: u128 = 1;
pub const FEE_BASIS_POINTS: u128 = 10_000;
pub const NXMR_RESERVE_BACKING_BPS: u128 = 9_000;
pub const NXMR_VALIDATOR_REWARD_BPS: u128 = 1_000;
pub const TESTNET_POINTS_PER_NEBULAI: u128 = 1;
pub const MIN_PUBLIC_TESTNET_VALIDATORS: usize = 2;
pub const MIN_PUBLIC_TESTNET_OPERATORS: usize = 2;
pub const MIN_PUBLIC_TESTNET_OBSERVERS: usize = 2;
pub const MIN_PUBLIC_TESTNET_REGIONS: usize = 2;
pub const MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS: u128 = 5_000;
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
    pub bridged_fee_conversion: &'static str,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureVerification {
    pub algorithm: String,
    pub public_key: String,
    pub signature_sha3_256: String,
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
    pub witness_evidence_root: String,
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
    pub validator_count: usize,
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
    pub validator_set_root: String,
    pub fee_policy_root: String,
    pub validator_admission_root: String,
    pub initial_validator_count: usize,
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
    pub validator_set_root: String,
    pub initial_validator_count: usize,
    pub initial_total_power: u64,
    pub activation_height: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchPackageReport {
    pub launch_package_ready: bool,
    pub level: &'static str,
    pub deployment_attestation_root: String,
    pub witness_evidence_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub endpoint_url: String,
    pub launch_bundle_root: String,
    pub fee_policy_root: String,
    pub validator_set_root: String,
    pub genesis_root: String,
    pub matched_validator_count: usize,
    pub deployment_operator_count: usize,
    pub bootstrap_node_count: usize,
    pub validator_count: usize,
    pub total_genesis_power: u64,
    pub activation_height: u64,
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

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptReport {
    pub receipt_ready: bool,
    pub level: &'static str,
    pub receipt_id: String,
    pub receipt_root: String,
    pub phase_count: usize,
    pub step_count: usize,
}

struct PublicSurfaceSample {
    endpoint_url: String,
    launch_bundle_root: String,
    economics_root: String,
    public_status_manifest: PublicStatusManifest,
    public_probe: PublicProbe,
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
        bridged_fee_conversion: "nXMR fees are converted into NBLA accounting value before split",
        nxmr_reserve_backing_bps: NXMR_RESERVE_BACKING_BPS,
        nxmr_validator_reward_bps: NXMR_VALIDATOR_REWARD_BPS,
        nbla_validator_reward_bps: FEE_BASIS_POINTS,
        testnet_reward_unit: "non-transferable validator points",
    }
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
            let reserve_backing_nebulai =
                split_basis_points(converted_nbla_nebulai, NXMR_RESERVE_BACKING_BPS)?;
            let validator_reward_nebulai = converted_nbla_nebulai - reserve_backing_nebulai;

            Ok(HybridFeeQuote {
                payment_asset,
                payment_asset_symbol: payment_asset.symbol(),
                gas_units,
                gas_price_nebulai,
                required_fee_nebulai,
                nxmr_to_nbla_rate_nebulai_per_unit: Some(rate),
                paid_amount_units,
                converted_nbla_nebulai,
                reserve_backing_nebulai,
                validator_reward_nebulai,
                validator_points: validator_reward_nebulai
                    .checked_mul(TESTNET_POINTS_PER_NEBULAI)
                    .ok_or(FeeError::ArithmeticOverflow)?,
                settlement_note:
                    "nXMR gas is converted to NBLA value: 90% backs NBLA, 10% rewards validators",
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
            "economics": stable_root(&json!({
                "native_fee_token": NBLA_SYMBOL,
                "bridged_fee_token": NXMR_SYMBOL,
                "native_base_unit": NEBULAI_UNIT,
                "nebulai_per_nbla": NEBULAI_PER_NBLA,
                "target_nxmr_per_nbla": "0.001",
                "target_nxmr_base_units_per_nxmr": TARGET_NXMR_BASE_UNITS_PER_NXMR,
                "target_nxmr_to_nbla_rate_nebulai_per_unit": TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT,
                "nxmr_reserve_backing_bps": NXMR_RESERVE_BACKING_BPS,
                "nxmr_validator_reward_bps": NXMR_VALIDATOR_REWARD_BPS,
                "testnet_reward_unit": "non-transferable validator points",
            })),
            "validator_admission": stable_root(&json!({
                "minimum_validator_count": MIN_PUBLIC_TESTNET_VALIDATORS,
                "minimum_operator_count": MIN_PUBLIC_TESTNET_OPERATORS,
                "minimum_region_count": MIN_PUBLIC_TESTNET_REGIONS,
                "reward_unit": NEBULAI_UNIT,
                "fee_policy_root_required": true,
                "signed_admission_root_binds_validator_payload": true,
                "validator_identity_whitespace_free": true,
                "validator_identity_domains_disjoint": true,
                "operator_contact_required": true,
                "operator_contact_address_required": true,
                "hex_consensus_key_required": true,
                "hex_network_key_required": true,
                "consensus_network_key_domains_disjoint": true,
                "unique_consensus_keys_required": true,
                "unique_reward_accounts_required": true,
                "reward_account_operator_binding_required": true,
                "unique_p2p_endpoints_required": true,
                "p2p_endpoint_host_port_required": true,
                "max_single_validator_genesis_power_bps": MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS,
            })),
            "genesis_manifest": stable_root(&json!({
                "deployment_attestation_root_required": true,
                "validator_set_root_required": true,
                "fee_policy_root_required": true,
                "validator_admission_root_required": true,
                "native_fee_token": NBLA_SYMBOL,
                "native_base_unit": NEBULAI_UNIT,
                "bridged_fee_token": NXMR_SYMBOL,
            })),
            "launch_package": stable_root(&json!({
                "deployment_attestation_verified": true,
                "deployment_attestation_max_age_ms": PUBLIC_ATTESTATION_MAX_AGE_MS,
                "deployment_attestation_max_ttl_ms": PUBLIC_ATTESTATION_MAX_TTL_MS,
                "deployment_attestation_expires_after_generated": true,
                "minimum_tls_pin_validity_ms": MIN_TLS_PIN_VALIDITY_MS,
                "rollback_drill_max_age_ms": ROLLBACK_DRILL_MAX_AGE_MS,
                "preflight_runbook_evidence_domains_disjoint": true,
                "receipts_complete_before_deployment_generation": true,
                "rollback_drill_before_deployment_generation": true,
                "rollback_plan_recovery_roots_disjoint": true,
                "deployment_witness_root_verified": true,
                "public_https_endpoint_required": true,
                "public_endpoint_authority_required": true,
                "unique_tls_cert_pins_required": true,
                "unique_tls_public_key_pins_required": true,
                "tls_cert_public_key_pin_domains_disjoint": true,
                "unique_bootstrap_node_ids_required": true,
                "unique_bootstrap_endpoints_required": true,
                "bootstrap_endpoint_authority_required": true,
                "bootstrap_region_spread_required": true,
                "bootstrap_operator_region_binding_required": true,
                "unique_operator_ids_required": true,
                "unique_operator_keys_required": true,
                "hex_operator_keys_required": true,
                "unique_observer_ids_required": true,
                "unique_observer_keys_required": true,
                "operator_observer_id_domains_disjoint": true,
                "hex_observer_keys_required": true,
                "operator_observer_key_domains_disjoint": true,
                "witness_identity_whitespace_free": true,
                "operator_region_spread_required": true,
                "observer_region_spread_required": true,
                "operator_signature_roots_verified": true,
                "observer_signature_roots_verified": true,
                "public_status_surface_verified": true,
                "public_probe_surface_verified": true,
                "validator_set_verified": true,
                "genesis_manifest_verified": true,
                "public_status_binds_deployment_attestation": true,
                "public_probe_binds_deployment_attestation": true,
                "validator_set_binds_deployment_operators": true,
                "validator_set_binds_bootstrap_nodes": true,
                "validator_p2p_host_binds_bootstrap_endpoint": true,
                "validator_witness_key_domains_disjoint": true,
                "all_deployment_operators_admitted": true,
                "all_bootstrap_nodes_admitted": true,
                "genesis_binds_deployment_attestation_root": true,
                "genesis_binds_validator_set_root": true,
                "genesis_binds_validator_count": true,
                "genesis_binds_total_power": true,
                "genesis_time_within_deployment_window": true,
            })),
            "public_status_surface": stable_root(&json!({
                "status": "deployment-attested",
                "public_launch_ready": false,
                "launch_bundle_root_required": true,
                "endpoint_url_required": true,
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
                    public_key: hex_64("operator-key-a"),
                    signed_evidence_root: witness_evidence_root.clone(),
                    signature_sha3_256: String::new(),
                },
                OperatorAttestation {
                    operator_id: "operator-b".to_string(),
                    region: "eu-west".to_string(),
                    public_key: hex_64("operator-key-b"),
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
                        public_key: hex_64("observer-key-a"),
                        signature_sha3_256: String::new(),
                        verified: true,
                    },
                },
                ObserverAttestation {
                    observer_id: "observer-eu-west-1".to_string(),
                    region: "eu-west".to_string(),
                    observed_endpoint: endpoint_url,
                    observed_evidence_root: witness_evidence_root.clone(),
                    signature: SignatureVerification {
                        algorithm: "ed25519-testnet-attestation".to_string(),
                        public_key: hex_64("observer-key-b"),
                        signature_sha3_256: String::new(),
                        verified: true,
                    },
                },
            ];
            for observer in &mut observers {
                observer.signature.signature_sha3_256 =
                    observer_signature_root(observer, &witness_evidence_root);
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

pub fn verify_public_status_manifest_json(
    input: &str,
) -> Result<PublicStatusReport, AttestationError> {
    let input = input.trim_start_matches('\u{feff}');
    let manifest = serde_json::from_str::<PublicStatusManifest>(input)
        .map_err(|error| AttestationError::MalformedJson(error.to_string()))?;
    let mut errors = Vec::new();
    let expected = sample_public_surface();

    verify_public_status_manifest(&mut errors, &manifest, &expected.launch_bundle_root);

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
            consensus_public_key: hex_64("consensus-key-a"),
            network_public_key: hex_64("network-key-a"),
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
            consensus_public_key: hex_64("consensus-key-b"),
            network_public_key: hex_64("network-key-b"),
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
        epoch: 0,
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
        validator_set_root: manifest.root,
        validator_count: manifest.validators.len(),
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

pub fn build_genesis_manifest_json_pretty(
    deployment_attestation_json: &str,
    validator_set_json: &str,
) -> Result<String, AttestationError> {
    let deployment_report = verify_deployment_attestation_json(deployment_attestation_json)?;
    let validator_set_report = verify_validator_set_json(validator_set_json)?;
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
        activation_height: 1,
        deployment_attestation_root: deployment_report.evidence_root,
        validator_set_root: validator_set_report.validator_set_root,
        fee_policy_root,
        validator_admission_root,
        initial_validator_count: validator_set_report.validator_count,
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
    if manifest.activation_height == 0 {
        errors.push("activation_height must be greater than zero".to_string());
    }
    require_hex_root(
        &mut errors,
        "deployment_attestation_root",
        &manifest.deployment_attestation_root,
    );
    require_hex_root(
        &mut errors,
        "validator_set_root",
        &manifest.validator_set_root,
    );
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
    if manifest.initial_validator_count < MIN_PUBLIC_TESTNET_VALIDATORS {
        errors.push(format!(
            "initial_validator_count must be at least {MIN_PUBLIC_TESTNET_VALIDATORS}"
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
        validator_set_root: manifest.validator_set_root,
        initial_validator_count: manifest.initial_validator_count,
        initial_total_power: manifest.initial_total_power,
        activation_height: manifest.activation_height,
    })
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

    verify_public_status_manifest(
        &mut errors,
        &public_status_manifest,
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
    if genesis_report.validator_set_root != validator_set_report.validator_set_root {
        errors.push(format!(
            "genesis validator_set_root does not match validator set root {}",
            validator_set_report.validator_set_root
        ));
    }
    if genesis_report.initial_validator_count != validator_set_report.validator_count {
        errors.push(format!(
            "genesis initial_validator_count expected {} but got {}",
            validator_set_report.validator_count, genesis_report.initial_validator_count
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
        public_status_manifest_root: public_status_manifest.root,
        public_probe_root: public_probe.root,
        endpoint_url: public_status_manifest.endpoint_url,
        launch_bundle_root: deployment_attestation.launch_bundle.root,
        fee_policy_root: economics_root.to_string(),
        validator_set_root: validator_set_report.validator_set_root,
        genesis_root: genesis_report.genesis_root,
        matched_validator_count: validator_set_manifest.validators.len(),
        deployment_operator_count: deployment_attestation.operators.len(),
        bootstrap_node_count: deployment_attestation.bootstrap_nodes.len(),
        validator_count: validator_set_report.validator_count,
        total_genesis_power: validator_set_report.total_genesis_power,
        activation_height: genesis_report.activation_height,
    })
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
        witness_evidence_root,
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

fn sample_launch_bundle(
    package_root: &str,
    runtime_root: &str,
    economics_root: &str,
) -> LaunchBundle {
    let mut launch_bundle = LaunchBundle {
        bundle_id: "nebula-public-testnet-bundle-1".to_string(),
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
    let mut bootstrap_regions = BTreeSet::new();
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
        require_non_empty(
            errors,
            &format!("bootstrap_nodes[{index}].endpoint"),
            &node.endpoint,
        );
        require_https_endpoint(
            errors,
            &format!("bootstrap_nodes[{index}].endpoint"),
            &node.endpoint,
        );
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
        require_hex_root(
            errors,
            &format!("observers[{index}].signature.signature_sha3_256"),
            &observer.signature.signature_sha3_256,
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
        if !observer.signature.verified {
            errors.push(format!(
                "observers[{index}].signature.verified must be true"
            ));
        }
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

    operator_ids.insert(validator.operator_id.clone());
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
    for (index, validator) in validators.iter().enumerate() {
        let validator_power_bps =
            u128::from(validator.genesis_power).saturating_mul(FEE_BASIS_POINTS) / total;
        if validator_power_bps > MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS {
            errors.push(format!(
                "validators[{index}].genesis_power must not exceed {MAX_SINGLE_VALIDATOR_GENESIS_POWER_BPS} bps of total genesis power"
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

fn genesis_manifest_root(manifest: &GenesisManifest) -> String {
    stable_root(&json!({
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "genesis_time_unix_ms": manifest.genesis_time_unix_ms,
        "activation_height": manifest.activation_height,
        "deployment_attestation_root": manifest.deployment_attestation_root,
        "validator_set_root": manifest.validator_set_root,
        "fee_policy_root": manifest.fee_policy_root,
        "validator_admission_root": manifest.validator_admission_root,
        "initial_validator_count": manifest.initial_validator_count,
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

fn require_https_endpoint(errors: &mut Vec<String>, label: &str, endpoint: &str) {
    let scheme = "https://";
    if !endpoint.starts_with(scheme) {
        errors.push(format!("{label} must use an https:// endpoint"));
        return;
    }
    require_endpoint_authority(errors, label, endpoint, scheme);
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

fn stable_root(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("status root input serializes");
    let digest = Sha3_256::digest(bytes);
    hex::encode(digest)
}

fn split_basis_points(amount: u128, bps: u128) -> Result<u128, FeeError> {
    amount
        .checked_mul(bps)
        .ok_or(FeeError::ArithmeticOverflow)
        .map(|scaled| scaled / FEE_BASIS_POINTS)
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator + u128::from(numerator % denominator != 0)
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
        assert_eq!(report.economics.nxmr_reserve_backing_bps, 9_000);
        assert_eq!(report.economics.nxmr_validator_reward_bps, 1_000);
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
        assert_eq!(report.fee_policy_root.len(), 64);
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
        assert_eq!(report.operator_count, 2);
        assert_eq!(report.region_count, 2);
        assert_eq!(report.reward_unit, NEBULAI_UNIT);
        assert_eq!(report.total_genesis_power, 2);
    }

    #[test]
    fn validator_set_rejects_unknown_fields() {
        let mut value = serde_json::from_str::<Value>(&sample_validator_set_json_pretty()).unwrap();
        value["unexpected_field"] = json!(true);

        let error = verify_validator_set_json(&value.to_string()).unwrap_err();

        assert!(matches!(error, AttestationError::MalformedJson(_)));
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
        assert_eq!(report.initial_total_power, 2);
        assert_eq!(report.activation_height, 1);
        assert_eq!(report.genesis_root.len(), 64);
        assert_eq!(report.deployment_attestation_root.len(), 64);
        assert_eq!(report.validator_set_root.len(), 64);
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
    fn genesis_manifest_rejects_zero_activation_height() {
        let mut value =
            serde_json::from_str::<Value>(&sample_genesis_manifest_json_pretty()).unwrap();
        value["activation_height"] = json!(0);

        let error = verify_genesis_manifest_json(&value.to_string()).unwrap_err();

        match error {
            AttestationError::Invalid(errors) => {
                assert!(errors
                    .iter()
                    .any(|error| error == "activation_height must be greater than zero"));
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
        assert_eq!(report.deployment_attestation_root.len(), 64);
        assert_eq!(report.witness_evidence_root.len(), 64);
        assert_eq!(report.public_status_manifest_root.len(), 64);
        assert_eq!(report.public_probe_root.len(), 64);
        assert_eq!(report.endpoint_url, "https://testnet.nebula.example/status");
        assert_eq!(report.launch_bundle_root.len(), 64);
        assert_eq!(report.fee_policy_root.len(), 64);
        assert_eq!(report.validator_set_root.len(), 64);
        assert_eq!(report.genesis_root.len(), 64);
        assert_eq!(report.matched_validator_count, 2);
        assert_eq!(report.deployment_operator_count, 2);
        assert_eq!(report.bootstrap_node_count, 2);
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
        let observer = serde_json::from_value::<ObserverAttestation>(
            attestation["observers"][observer_index].clone(),
        )
        .unwrap();
        attestation["observers"][observer_index]["signature"]["signature_sha3_256"] =
            json!(observer_signature_root(&observer, &witness_evidence_root));
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
        assert_eq!(quote.reserve_backing_nebulai, 0);
        assert_eq!(quote.validator_reward_nebulai, 100_000);
        assert_eq!(quote.validator_points, 100_000);
    }

    #[test]
    fn nxmr_fee_converts_to_nbla_and_splits_ninety_ten() {
        let quote = quote_hybrid_fee_at_target_rate(FeeAsset::NXmr, 100, 10_000).unwrap();

        assert_eq!(quote.payment_asset_symbol, NXMR_SYMBOL);
        assert_eq!(quote.required_fee_nebulai, 1_000_000);
        assert_eq!(quote.paid_amount_units, 1_000_000);
        assert_eq!(quote.converted_nbla_nebulai, 1_000_000);
        assert_eq!(quote.reserve_backing_nebulai, 900_000);
        assert_eq!(quote.validator_reward_nebulai, 100_000);
        assert_eq!(quote.validator_points, 100_000);
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
