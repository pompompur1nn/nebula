use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;
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
    pub attestation_expires_at_unix_ms: u128,
    pub verified_operator_count: usize,
    pub verified_observer_count: usize,
    pub verified_region_count: usize,
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
        "minimum_observer_count": 2,
        "minimum_operator_count": 2,
        "minimum_region_count": 2,
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

    let attestation = DeploymentAttestation {
        chain_id: CHAIN_ID.to_string(),
        runtime_version: VERSION.to_string(),
        generated_at_unix_ms: now,
        expires_at_unix_ms: now + 86_400_000,
        package_identity,
        launch_bundle,
        public_status_manifest,
        public_endpoint: PublicEndpointEvidence {
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
        },
        policy_claim,
        public_probe,
        preflight_receipt,
        runbook_receipt,
        bootstrap_nodes: vec![
            BootstrapNode {
                node_id: "bootstrap-us-east-1".to_string(),
                operator_id: "operator-a".to_string(),
                region: "us-east".to_string(),
                endpoint: "https://bootstrap-a.testnet.nebula.example".to_string(),
                attestation_root: hex_64("bootstrap-a"),
            },
            BootstrapNode {
                node_id: "bootstrap-eu-west-1".to_string(),
                operator_id: "operator-b".to_string(),
                region: "eu-west".to_string(),
                endpoint: "https://bootstrap-b.testnet.nebula.example".to_string(),
                attestation_root: hex_64("bootstrap-b"),
            },
        ],
        operators: vec![
            OperatorAttestation {
                operator_id: "operator-a".to_string(),
                region: "us-east".to_string(),
                public_key: "nebula-operator-key-a".to_string(),
                signed_evidence_root: hex_64("operator-a-root"),
                signature_sha3_256: hex_64("operator-a-signature"),
            },
            OperatorAttestation {
                operator_id: "operator-b".to_string(),
                region: "eu-west".to_string(),
                public_key: "nebula-operator-key-b".to_string(),
                signed_evidence_root: hex_64("operator-b-root"),
                signature_sha3_256: hex_64("operator-b-signature"),
            },
        ],
        observers: vec![
            ObserverAttestation {
                observer_id: "observer-us-east-1".to_string(),
                region: "us-east".to_string(),
                observed_endpoint: endpoint_url.clone(),
                observed_evidence_root: hex_64("observer-a-root"),
                signature: SignatureVerification {
                    algorithm: "ed25519-testnet-attestation".to_string(),
                    public_key: "nebula-observer-key-a".to_string(),
                    signature_sha3_256: hex_64("observer-a-signature"),
                    verified: true,
                },
            },
            ObserverAttestation {
                observer_id: "observer-eu-west-1".to_string(),
                region: "eu-west".to_string(),
                observed_endpoint: endpoint_url,
                observed_evidence_root: hex_64("observer-b-root"),
                signature: SignatureVerification {
                    algorithm: "ed25519-testnet-attestation".to_string(),
                    public_key: "nebula-observer-key-b".to_string(),
                    signature_sha3_256: hex_64("observer-b-signature"),
                    verified: true,
                },
            },
        ],
        rollback_evidence: RollbackEvidence {
            rollback_plan_sha3_256: hex_64("rollback-plan"),
            last_drill_unix_ms: now,
            recovery_point_root: hex_64("rollback-recovery-point"),
        },
    };

    serde_json::to_string_pretty(&attestation).expect("sample attestation serializes")
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
    if attestation.generated_at_unix_ms > now + 300_000 {
        errors.push("generated_at_unix_ms is more than five minutes in the future".to_string());
    }
    if attestation.expires_at_unix_ms <= now {
        errors.push("expires_at_unix_ms is stale".to_string());
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
    verify_network_witnesses(&mut errors, &attestation);
    verify_rollback_evidence(&mut errors, &attestation.rollback_evidence, now);

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

    Ok(DeploymentAttestationReport {
        public_launch_ready: true,
        level: "public-launch-attested",
        evidence_root: stable_root(&value),
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
    require_eq(
        errors,
        "public_endpoint.public_status_manifest_root",
        &public_endpoint.public_status_manifest_root,
        &public_status_manifest.root,
    );
    if public_endpoint.tls_pins.is_empty() {
        errors.push("public_endpoint.tls_pins must not be empty".to_string());
    }
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
        if pin.not_after_unix_ms <= now {
            errors.push(format!(
                "public_endpoint.tls_pins[{index}].not_after_unix_ms is stale"
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

fn verify_receipt(errors: &mut Vec<String>, label: &str, receipt: &Receipt, now: u128) {
    if receipt.completed_at_unix_ms > now + 300_000 {
        errors.push(format!(
            "{label}.completed_at_unix_ms is more than five minutes in the future"
        ));
    }
    if receipt.phases.is_empty() {
        errors.push(format!("{label}.phases must not be empty"));
    }
    for (phase_index, phase) in receipt.phases.iter().enumerate() {
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
        for (step_index, step) in phase.steps.iter().enumerate() {
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
        }
    }
    require_root(
        errors,
        &format!("{label}.root"),
        &receipt.root,
        &receipt_root(receipt),
    );
}

fn verify_network_witnesses(errors: &mut Vec<String>, attestation: &DeploymentAttestation) {
    if attestation.bootstrap_nodes.len() < 2 {
        errors.push("bootstrap_nodes must include at least two nodes".to_string());
    }
    if attestation.operators.len() < 2 {
        errors.push("operators must include at least two operators".to_string());
    }
    if attestation.observers.len() < 2 {
        errors.push("observers must include at least two observers".to_string());
    }

    let operator_ids = attestation
        .operators
        .iter()
        .map(|operator| operator.operator_id.as_str())
        .collect::<BTreeSet<_>>();
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
    if regions.len() < 2 {
        errors.push("operators and observers must cover at least two regions".to_string());
    }

    for (index, node) in attestation.bootstrap_nodes.iter().enumerate() {
        if !operator_ids.contains(node.operator_id.as_str()) {
            errors.push(format!(
                "bootstrap_nodes[{index}].operator_id does not match an operator"
            ));
        }
        require_hex_root(
            errors,
            &format!("bootstrap_nodes[{index}].attestation_root"),
            &node.attestation_root,
        );
    }
    for (index, operator) in attestation.operators.iter().enumerate() {
        require_hex_root(
            errors,
            &format!("operators[{index}].signed_evidence_root"),
            &operator.signed_evidence_root,
        );
        require_hex_root(
            errors,
            &format!("operators[{index}].signature_sha3_256"),
            &operator.signature_sha3_256,
        );
    }
    for (index, observer) in attestation.observers.iter().enumerate() {
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
        require_hex_root(
            errors,
            &format!("observers[{index}].signature.signature_sha3_256"),
            &observer.signature.signature_sha3_256,
        );
        if !observer.signature.verified {
            errors.push(format!(
                "observers[{index}].signature.verified must be true"
            ));
        }
    }
}

fn verify_rollback_evidence(
    errors: &mut Vec<String>,
    rollback_evidence: &RollbackEvidence,
    now: u128,
) {
    require_hex_root(
        errors,
        "rollback_evidence.rollback_plan_sha3_256",
        &rollback_evidence.rollback_plan_sha3_256,
    );
    if rollback_evidence.last_drill_unix_ms > now + 300_000 {
        errors.push(
            "rollback_evidence.last_drill_unix_ms is more than five minutes in the future"
                .to_string(),
        );
    }
    require_hex_root(
        errors,
        "rollback_evidence.recovery_point_root",
        &rollback_evidence.recovery_point_root,
    );
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

fn receipt_root(receipt: &Receipt) -> String {
    stable_root(&json!({
        "receipt_id": receipt.receipt_id,
        "completed_at_unix_ms": receipt.completed_at_unix_ms,
        "phases": receipt.phases,
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

        assert_eq!(
            error,
            AttestationError::Invalid(vec!["expires_at_unix_ms is stale".to_string()])
        );
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
