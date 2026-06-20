use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqContractBytecodeAttestationRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-contract-bytecode-attestation-runtime-v1";
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256s-bytecode-attestation-v1";
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_WITNESS_SCHEME: &str =
    "shake256-private-contract-bytecode-witness-v1";
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEPLOYMENT_CERTIFICATE_SCHEME: &str =
    "private-l2-pq-bytecode-deployment-certificate-v1";
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_LOW_FEE_PROOF_SCHEME: &str =
    "roots-only-low-fee-bytecode-proof-reservation-v1";
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEVNET_HEIGHT: u64 = 356_000;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    4_096;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MIN_VERIFIER_QUORUM: u64 = 3;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 =
    7_200;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    24;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_CONTRACTS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_WITNESSES: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_UPGRADE_SIMULATIONS:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_CERTIFICATES: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractKind {
    Account,
    Token,
    Paymaster,
    PrivateAmm,
    PrivateDex,
    LendingMarket,
    IntentRouter,
    MoneroBridgeAdapter,
    ProofAggregator,
    Custom,
}

impl ContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Token => "token",
            Self::Paymaster => "paymaster",
            Self::PrivateAmm => "private_amm",
            Self::PrivateDex => "private_dex",
            Self::LendingMarket => "lending_market",
            Self::IntentRouter => "intent_router",
            Self::MoneroBridgeAdapter => "monero_bridge_adapter",
            Self::ProofAggregator => "proof_aggregator",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Registered,
    Witnessed,
    QuorumAttested,
    Certified,
    Retired,
}

impl ContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Witnessed => "witnessed",
            Self::QuorumAttested => "quorum_attested",
            Self::Certified => "certified",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Witnessed | Self::QuorumAttested
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeWitnessKind {
    WasmImage,
    AbiManifest,
    StorageLayout,
    Constructor,
    RuntimeMetadata,
    StaticAnalysis,
}

impl BytecodeWitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WasmImage => "wasm_image",
            Self::AbiManifest => "abi_manifest",
            Self::StorageLayout => "storage_layout",
            Self::Constructor => "constructor",
            Self::RuntimeMetadata => "runtime_metadata",
            Self::StaticAnalysis => "static_analysis",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ReproducibleBuild,
    BytecodeHash,
    AbiCompatibility,
    StaticAnalysis,
    PrivacyInvariant,
    PqSignature,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReproducibleBuild => "reproducible_build",
            Self::BytecodeHash => "bytecode_hash",
            Self::AbiCompatibility => "abi_compatibility",
            Self::StaticAnalysis => "static_analysis",
            Self::PrivacyInvariant => "privacy_invariant",
            Self::PqSignature => "pq_signature",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approve,
    Reject,
    Abstain,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeSimulationStatus {
    Proposed,
    Simulated,
    Approved,
    Rejected,
}

impl UpgradeSimulationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Simulated => "simulated",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_verifier_quorum: u64,
    pub max_fee_bps: u64,
    pub attestation_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub max_contracts: usize,
    pub max_witnesses: usize,
    pub max_attestations: usize,
    pub max_upgrade_simulations: usize,
    pub max_reservations: usize,
    pub max_certificates: usize,
    pub require_reproducible_build: bool,
    pub require_privacy_invariant: bool,
    pub require_low_fee_reservation: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_verifier_quorum:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MIN_VERIFIER_QUORUM,
            max_fee_bps: PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_FEE_BPS,
            attestation_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            max_contracts:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_CONTRACTS,
            max_witnesses:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_WITNESSES,
            max_attestations:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_upgrade_simulations:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_UPGRADE_SIMULATIONS,
            max_reservations:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_certificates:
                PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEFAULT_MAX_CERTIFICATES,
            require_reproducible_build: true,
            require_privacy_invariant: true,
            require_low_fee_reservation: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        if self.min_privacy_set_size == 0 {
            return Err("bytecode attestation privacy set minimum must be positive".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("bytecode attestation PQ security floor is too low".to_string());
        }
        if self.min_verifier_quorum == 0 {
            return Err("bytecode attestation verifier quorum must be positive".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_MAX_BPS {
            return Err("bytecode attestation fee cap exceeds BPS range".to_string());
        }
        if self.attestation_ttl_blocks == 0 || self.reservation_ttl_blocks == 0 {
            return Err("bytecode attestation TTL windows must be positive".to_string());
        }
        if self.max_contracts == 0
            || self.max_witnesses == 0
            || self.max_attestations == 0
            || self.max_upgrade_simulations == 0
            || self.max_reservations == 0
            || self.max_certificates == 0
        {
            return Err("bytecode attestation capacity limits must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_attestation_config",
            "chain_id": self.chain_id,
            "protocol_version": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PROTOCOL_VERSION,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_verifier_quorum": self.min_verifier_quorum,
            "max_fee_bps": self.max_fee_bps,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "max_contracts": self.max_contracts,
            "max_witnesses": self.max_witnesses,
            "max_attestations": self.max_attestations,
            "max_upgrade_simulations": self.max_upgrade_simulations,
            "max_reservations": self.max_reservations,
            "max_certificates": self.max_certificates,
            "require_reproducible_build": self.require_reproducible_build,
            "require_privacy_invariant": self.require_privacy_invariant,
            "require_low_fee_reservation": self.require_low_fee_reservation,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub contract_count: u64,
    pub witness_count: u64,
    pub attestation_count: u64,
    pub upgrade_simulation_count: u64,
    pub reservation_count: u64,
    pub certificate_count: u64,
    pub certified_contract_count: u64,
    pub consumed_nullifier_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_attestation_counters",
            "contract_count": self.contract_count,
            "witness_count": self.witness_count,
            "attestation_count": self.attestation_count,
            "upgrade_simulation_count": self.upgrade_simulation_count,
            "reservation_count": self.reservation_count,
            "certificate_count": self.certificate_count,
            "certified_contract_count": self.certified_contract_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterContractRequest {
    pub contract_kind: ContractKind,
    pub deployer_commitment: String,
    pub admin_commitment: String,
    pub bytecode_root: String,
    pub source_commitment_root: String,
    pub abi_root: String,
    pub constructor_root: String,
    pub initial_state_root: String,
    pub verifier_policy_root: String,
    pub low_fee_policy_root: String,
    pub privacy_policy_root: String,
    pub registration_nullifier: String,
    pub registered_at_height: u64,
}

impl RegisterContractRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_kind": self.contract_kind.as_str(),
            "deployer_commitment": self.deployer_commitment,
            "admin_commitment": self.admin_commitment,
            "bytecode_root": self.bytecode_root,
            "source_commitment_root": self.source_commitment_root,
            "abi_root": self.abi_root,
            "constructor_root": self.constructor_root,
            "initial_state_root": self.initial_state_root,
            "verifier_policy_root": self.verifier_policy_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "registration_nullifier": self.registration_nullifier,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitBytecodeWitnessRequest {
    pub contract_id: String,
    pub witness_kind: BytecodeWitnessKind,
    pub witness_commitment_root: String,
    pub bytecode_chunk_root: String,
    pub build_manifest_root: String,
    pub dependency_root: String,
    pub reproducibility_proof_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub witness_nullifier: String,
    pub committed_at_height: u64,
}

impl CommitBytecodeWitnessRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "witness_kind": self.witness_kind.as_str(),
            "witness_commitment_root": self.witness_commitment_root,
            "bytecode_chunk_root": self.bytecode_chunk_root,
            "build_manifest_root": self.build_manifest_root,
            "dependency_root": self.dependency_root,
            "reproducibility_proof_root": self.reproducibility_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "witness_nullifier": self.witness_nullifier,
            "committed_at_height": self.committed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestBytecodeRequest {
    pub contract_id: String,
    pub witness_id: String,
    pub verifier_commitment: String,
    pub verifier_set_id: String,
    pub attestation_kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_bps: u64,
    pub attested_at_height: u64,
}

impl AttestBytecodeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "witness_id": self.witness_id,
            "verifier_commitment": self.verifier_commitment,
            "verifier_set_id": self.verifier_set_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "verdict": self.verdict.as_str(),
            "evidence_root": self.evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "fee_bps": self.fee_bps,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestUpgradeSimulationRequest {
    pub contract_id: String,
    pub current_bytecode_root: String,
    pub proposed_bytecode_root: String,
    pub migration_witness_root: String,
    pub simulation_trace_root: String,
    pub compatibility_report_root: String,
    pub rollback_plan_root: String,
    pub simulator_commitment: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub simulation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_bps: u64,
    pub simulated_at_height: u64,
}

impl AttestUpgradeSimulationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "current_bytecode_root": self.current_bytecode_root,
            "proposed_bytecode_root": self.proposed_bytecode_root,
            "migration_witness_root": self.migration_witness_root,
            "simulation_trace_root": self.simulation_trace_root,
            "compatibility_report_root": self.compatibility_report_root,
            "rollback_plan_root": self.rollback_plan_root,
            "simulator_commitment": self.simulator_commitment,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "simulation_nullifier": self.simulation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "fee_bps": self.fee_bps,
            "simulated_at_height": self.simulated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeProofRequest {
    pub contract_id: String,
    pub sponsor_commitment: String,
    pub proof_budget_root: String,
    pub fee_asset_id: String,
    pub reserved_fee_bps: u64,
    pub max_proof_count: u64,
    pub pq_reservation_root: String,
    pub reservation_nullifier: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeProofRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "sponsor_commitment": self.sponsor_commitment,
            "proof_budget_root": self.proof_budget_root,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_bps": self.reserved_fee_bps,
            "max_proof_count": self.max_proof_count,
            "pq_reservation_root": self.pq_reservation_root,
            "reservation_nullifier": self.reservation_nullifier,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueDeploymentCertificateRequest {
    pub contract_id: String,
    pub witness_id: String,
    pub reservation_id: Option<String>,
    pub verifier_quorum_root: String,
    pub deployment_policy_root: String,
    pub runtime_host_root: String,
    pub deployment_proof_root: String,
    pub pq_certificate_signature_root: String,
    pub certificate_nullifier: String,
    pub issued_at_height: u64,
}

impl IssueDeploymentCertificateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "witness_id": self.witness_id,
            "reservation_id": self.reservation_id,
            "verifier_quorum_root": self.verifier_quorum_root,
            "deployment_policy_root": self.deployment_policy_root,
            "runtime_host_root": self.runtime_host_root,
            "deployment_proof_root": self.deployment_proof_root,
            "pq_certificate_signature_root": self.pq_certificate_signature_root,
            "certificate_nullifier": self.certificate_nullifier,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRegistration {
    pub contract_id: String,
    pub contract_kind: ContractKind,
    pub status: ContractStatus,
    pub registered_at_height: u64,
    pub request: RegisterContractRequest,
    pub witness_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub upgrade_simulation_ids: Vec<String>,
    pub deployment_certificate_id: Option<String>,
}

impl ContractRegistration {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_registration",
            "contract_id": self.contract_id,
            "contract_kind": self.contract_kind.as_str(),
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
            "request": self.request.public_record(),
            "witness_ids": self.witness_ids,
            "attestation_ids": self.attestation_ids,
            "upgrade_simulation_ids": self.upgrade_simulation_ids,
            "deployment_certificate_id": self.deployment_certificate_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeWitnessCommitment {
    pub witness_id: String,
    pub contract_id: String,
    pub request: CommitBytecodeWitnessRequest,
}

impl BytecodeWitnessCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_witness_commitment",
            "witness_id": self.witness_id,
            "contract_id": self.contract_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierAttestation {
    pub attestation_id: String,
    pub contract_id: String,
    pub witness_id: String,
    pub request: AttestBytecodeRequest,
}

impl PqVerifierAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_verifier_attestation",
            "attestation_id": self.attestation_id,
            "contract_id": self.contract_id,
            "witness_id": self.witness_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeSimulationAttestation {
    pub simulation_id: String,
    pub contract_id: String,
    pub status: UpgradeSimulationStatus,
    pub request: AttestUpgradeSimulationRequest,
}

impl UpgradeSimulationAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_upgrade_simulation_attestation",
            "simulation_id": self.simulation_id,
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofReservation {
    pub reservation_id: String,
    pub contract_id: String,
    pub request: ReserveLowFeeProofRequest,
    pub status: ReservationStatus,
}

impl LowFeeProofReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_low_fee_proof_reservation",
            "reservation_id": self.reservation_id,
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentCertificate {
    pub certificate_id: String,
    pub contract_id: String,
    pub witness_id: String,
    pub request: IssueDeploymentCertificateRequest,
    pub verifier_count: u64,
    pub required_attestation_kinds: BTreeSet<AttestationKind>,
}

impl DeploymentCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_deployment_certificate",
            "certificate_id": self.certificate_id,
            "contract_id": self.contract_id,
            "witness_id": self.witness_id,
            "request": self.request.public_record(),
            "verifier_count": self.verifier_count,
            "required_attestation_kinds": self
                .required_attestation_kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub contract_root: String,
    pub witness_root: String,
    pub attestation_root: String,
    pub upgrade_simulation_root: String,
    pub reservation_root: String,
    pub certificate_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "contract_root": self.contract_root,
            "witness_root": self.witness_root,
            "attestation_root": self.attestation_root,
            "upgrade_simulation_root": self.upgrade_simulation_root,
            "reservation_root": self.reservation_root,
            "certificate_root": self.certificate_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub contracts: BTreeMap<String, ContractRegistration>,
    pub witnesses: BTreeMap<String, BytecodeWitnessCommitment>,
    pub attestations: BTreeMap<String, PqVerifierAttestation>,
    pub upgrade_simulations: BTreeMap<String, UpgradeSimulationAttestation>,
    pub reservations: BTreeMap<String, LowFeeProofReservation>,
    pub certificates: BTreeMap<String, DeploymentCertificate>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub counters: Counters,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn new(
        current_height: u64,
        config: Config,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            contracts: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            attestations: BTreeMap::new(),
            upgrade_simulations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            certificates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            counters: Counters::default(),
            public_records: Vec::new(),
        })
    }

    pub fn devnet() -> Self {
        Self::new(
            PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEVNET_HEIGHT,
            Config::devnet(),
        )
        .expect("devnet bytecode attestation config is valid")
    }

    pub fn register_contract(
        &mut self,
        request: RegisterContractRequest,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<ContractRegistration> {
        self.config.validate()?;
        if self.contracts.len() >= self.config.max_contracts {
            return Err("bytecode attestation contract registry is full".to_string());
        }
        validate_registration(&request)?;
        self.insert_nullifier(&request.registration_nullifier)?;
        self.counters.contract_count = self.counters.contract_count.saturating_add(1);
        self.current_height = self.current_height.max(request.registered_at_height);
        let contract_id = contract_id(&request, self.counters.contract_count);
        if self.contracts.contains_key(&contract_id) {
            return Err("bytecode attestation contract id already exists".to_string());
        }
        let record = ContractRegistration {
            contract_id: contract_id.clone(),
            contract_kind: request.contract_kind,
            status: ContractStatus::Registered,
            registered_at_height: request.registered_at_height,
            request,
            witness_ids: Vec::new(),
            attestation_ids: Vec::new(),
            upgrade_simulation_ids: Vec::new(),
            deployment_certificate_id: None,
        };
        self.public_records.push(record.public_record());
        self.contracts.insert(contract_id, record.clone());
        Ok(record)
    }

    pub fn commit_bytecode_witness(
        &mut self,
        request: CommitBytecodeWitnessRequest,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<BytecodeWitnessCommitment> {
        self.config.validate()?;
        if self.witnesses.len() >= self.config.max_witnesses {
            return Err("bytecode witness store is full".to_string());
        }
        validate_witness(&request)?;
        {
            let contract = self
                .contracts
                .get(&request.contract_id)
                .ok_or_else(|| "bytecode witness references unknown contract".to_string())?;
            if !contract.status.accepts_attestations() {
                return Err(
                    "bytecode witness cannot be added to current contract status".to_string(),
                );
            }
        }
        self.insert_nullifier(&request.witness_nullifier)?;
        self.counters.witness_count = self.counters.witness_count.saturating_add(1);
        self.current_height = self.current_height.max(request.committed_at_height);
        let witness_id = bytecode_witness_id(&request, self.counters.witness_count);
        let contract_id = request.contract_id.clone();
        let record = BytecodeWitnessCommitment {
            witness_id: witness_id.clone(),
            contract_id: contract_id.clone(),
            request,
        };
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.status = ContractStatus::Witnessed;
            contract.witness_ids.push(witness_id.clone());
        }
        self.public_records.push(record.public_record());
        self.witnesses.insert(witness_id, record.clone());
        Ok(record)
    }

    pub fn attest_bytecode(
        &mut self,
        request: AttestBytecodeRequest,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<PqVerifierAttestation> {
        self.config.validate()?;
        if self.attestations.len() >= self.config.max_attestations {
            return Err("bytecode attestation store is full".to_string());
        }
        validate_attestation(&request, &self.config)?;
        {
            let witness = self
                .witnesses
                .get(&request.witness_id)
                .ok_or_else(|| "bytecode attestation references unknown witness".to_string())?;
            if witness.contract_id != request.contract_id {
                return Err("bytecode attestation witness contract mismatch".to_string());
            }
            let contract = self
                .contracts
                .get(&request.contract_id)
                .ok_or_else(|| "bytecode attestation references unknown contract".to_string())?;
            if !contract.status.accepts_attestations() {
                return Err(
                    "bytecode attestation cannot be added to current contract status".to_string(),
                );
            }
        }
        self.insert_nullifier(&request.attestation_nullifier)?;
        self.counters.attestation_count = self.counters.attestation_count.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let attestation_id = pq_verifier_attestation_id(&request, self.counters.attestation_count);
        let contract_id = request.contract_id.clone();
        let witness_id = request.witness_id.clone();
        let record = PqVerifierAttestation {
            attestation_id: attestation_id.clone(),
            contract_id: contract_id.clone(),
            witness_id,
            request,
        };
        self.public_records.push(record.public_record());
        self.attestations
            .insert(attestation_id.clone(), record.clone());
        let has_quorum = self.contract_has_quorum(&contract_id);
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.attestation_ids.push(attestation_id);
            if has_quorum {
                contract.status = ContractStatus::QuorumAttested;
            }
        }
        Ok(record)
    }

    pub fn attest_upgrade_simulation(
        &mut self,
        request: AttestUpgradeSimulationRequest,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<UpgradeSimulationAttestation> {
        self.config.validate()?;
        if self.upgrade_simulations.len() >= self.config.max_upgrade_simulations {
            return Err("bytecode upgrade simulation store is full".to_string());
        }
        validate_upgrade_simulation(&request, &self.config)?;
        let contract = self
            .contracts
            .get(&request.contract_id)
            .ok_or_else(|| "bytecode upgrade simulation references unknown contract".to_string())?;
        if contract.request.bytecode_root != request.current_bytecode_root {
            return Err("bytecode upgrade simulation current root mismatch".to_string());
        }
        self.insert_nullifier(&request.simulation_nullifier)?;
        self.counters.upgrade_simulation_count =
            self.counters.upgrade_simulation_count.saturating_add(1);
        self.current_height = self.current_height.max(request.simulated_at_height);
        let simulation_id = upgrade_simulation_id(&request, self.counters.upgrade_simulation_count);
        let contract_id = request.contract_id.clone();
        let status = if request.current_bytecode_root == request.proposed_bytecode_root {
            UpgradeSimulationStatus::Rejected
        } else {
            UpgradeSimulationStatus::Approved
        };
        let record = UpgradeSimulationAttestation {
            simulation_id: simulation_id.clone(),
            contract_id: contract_id.clone(),
            status,
            request,
        };
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.upgrade_simulation_ids.push(simulation_id.clone());
        }
        self.public_records.push(record.public_record());
        self.upgrade_simulations
            .insert(simulation_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_proof(
        &mut self,
        request: ReserveLowFeeProofRequest,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<LowFeeProofReservation> {
        self.config.validate()?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("bytecode low-fee reservation store is full".to_string());
        }
        validate_reservation(&request, &self.config)?;
        if !self.contracts.contains_key(&request.contract_id) {
            return Err("bytecode low-fee reservation references unknown contract".to_string());
        }
        self.insert_nullifier(&request.reservation_nullifier)?;
        self.counters.reservation_count = self.counters.reservation_count.saturating_add(1);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let reservation_id =
            low_fee_proof_reservation_id(&request, self.counters.reservation_count);
        let contract_id = request.contract_id.clone();
        let record = LowFeeProofReservation {
            reservation_id: reservation_id.clone(),
            contract_id,
            request,
            status: ReservationStatus::Reserved,
        };
        self.public_records.push(record.public_record());
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn issue_deployment_certificate(
        &mut self,
        request: IssueDeploymentCertificateRequest,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<DeploymentCertificate> {
        self.config.validate()?;
        if self.certificates.len() >= self.config.max_certificates {
            return Err("bytecode deployment certificate store is full".to_string());
        }
        validate_certificate(&request)?;
        {
            let witness = self
                .witnesses
                .get(&request.witness_id)
                .ok_or_else(|| "deployment certificate references unknown witness".to_string())?;
            if witness.contract_id != request.contract_id {
                return Err("deployment certificate witness contract mismatch".to_string());
            }
            if !self.contract_has_quorum(&request.contract_id) {
                return Err("deployment certificate requires verifier quorum".to_string());
            }
            if let Some(reservation_id) = &request.reservation_id {
                let reservation = self.reservations.get(reservation_id).ok_or_else(|| {
                    "deployment certificate references unknown low-fee reservation".to_string()
                })?;
                if reservation.contract_id != request.contract_id {
                    return Err("deployment certificate reservation contract mismatch".to_string());
                }
                if reservation.status != ReservationStatus::Reserved {
                    return Err("deployment certificate reservation is not active".to_string());
                }
            } else if self.config.require_low_fee_reservation {
                return Err("deployment certificate requires low-fee reservation".to_string());
            }
        }
        self.insert_nullifier(&request.certificate_nullifier)?;
        self.counters.certificate_count = self.counters.certificate_count.saturating_add(1);
        self.current_height = self.current_height.max(request.issued_at_height);
        let certificate_id = deployment_certificate_id(&request, self.counters.certificate_count);
        let verifier_count = self
            .approving_verifiers_for_witness(&request.witness_id)
            .len() as u64;
        let required_attestation_kinds = self.required_attestation_kinds();
        let contract_id = request.contract_id.clone();
        let witness_id = request.witness_id.clone();
        let reservation_id = request.reservation_id.clone();
        let record = DeploymentCertificate {
            certificate_id: certificate_id.clone(),
            contract_id: contract_id.clone(),
            witness_id,
            request,
            verifier_count,
            required_attestation_kinds,
        };
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.status = ContractStatus::Certified;
            contract.deployment_certificate_id = Some(certificate_id.clone());
            self.counters.certified_contract_count =
                self.counters.certified_contract_count.saturating_add(1);
        }
        if let Some(reservation_id) = reservation_id {
            if let Some(reservation) = self.reservations.get_mut(&reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        self.public_records.push(record.public_record());
        self.certificates.insert(certificate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-CONFIG",
            &self.config.public_record(),
        );
        let contract_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-CONTRACTS",
            &self
                .contracts
                .values()
                .map(ContractRegistration::public_record)
                .collect::<Vec<_>>(),
        );
        let witness_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-WITNESSES",
            &self
                .witnesses
                .values()
                .map(BytecodeWitnessCommitment::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-ATTESTATIONS",
            &self
                .attestations
                .values()
                .map(PqVerifierAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let upgrade_simulation_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-UPGRADE-SIMULATIONS",
            &self
                .upgrade_simulations
                .values()
                .map(UpgradeSimulationAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(LowFeeProofReservation::public_record)
                .collect::<Vec<_>>(),
        );
        let certificate_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-CERTIFICATES",
            &self
                .certificates
                .values()
                .map(DeploymentCertificate::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let public_record_root = merkle_root(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-PUBLIC-RECORDS",
            &self.public_records,
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-STATE",
            &json!({
                "chain_id": self.config.chain_id,
                "current_height": self.current_height,
                "config_root": config_root,
                "contract_root": contract_root,
                "witness_root": witness_root,
                "attestation_root": attestation_root,
                "upgrade_simulation_root": upgrade_simulation_root,
                "reservation_root": reservation_root,
                "certificate_root": certificate_root,
                "nullifier_root": nullifier_root,
                "public_record_root": public_record_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            config_root,
            contract_root,
            witness_root,
            attestation_root,
            upgrade_simulation_root,
            reservation_root,
            certificate_root,
            nullifier_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_bytecode_attestation_runtime",
            "chain_id": self.config.chain_id,
            "protocol_version": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_HASH_SUITE,
            "pq_attestation_suite": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PQ_ATTESTATION_SUITE,
            "witness_scheme": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_WITNESS_SCHEME,
            "deployment_certificate_scheme": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_DEPLOYMENT_CERTIFICATE_SCHEME,
            "low_fee_proof_scheme": PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_LOW_FEE_PROOF_SCHEME,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "contract_ids": self.contracts.keys().cloned().collect::<Vec<_>>(),
            "witness_ids": self.witnesses.keys().cloned().collect::<Vec<_>>(),
            "attestation_ids": self.attestations.keys().cloned().collect::<Vec<_>>(),
            "upgrade_simulation_ids": self.upgrade_simulations.keys().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservations.keys().cloned().collect::<Vec<_>>(),
            "certificate_ids": self.certificates.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root(),
            "record": self.public_record_without_state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn contract_has_quorum(&self, contract_id: &str) -> bool {
        self.contracts
            .get(contract_id)
            .and_then(|contract| contract.witness_ids.last())
            .map(|witness_id| self.witness_has_required_attestations(witness_id))
            .unwrap_or(false)
    }

    pub fn witness_has_required_attestations(&self, witness_id: &str) -> bool {
        let approved_kinds = self.approved_kinds_for_witness(witness_id);
        let verifier_count = self.approving_verifiers_for_witness(witness_id).len() as u64;
        let required_kinds = self.required_attestation_kinds();
        verifier_count >= self.config.min_verifier_quorum
            && required_kinds
                .iter()
                .all(|kind| approved_kinds.contains(kind))
    }

    pub fn approved_kinds_for_witness(&self, witness_id: &str) -> BTreeSet<AttestationKind> {
        self.attestations
            .values()
            .filter(|attestation| {
                attestation.witness_id == witness_id
                    && attestation.request.verdict == AttestationVerdict::Approve
            })
            .map(|attestation| attestation.request.attestation_kind)
            .collect()
    }

    pub fn approving_verifiers_for_witness(&self, witness_id: &str) -> BTreeSet<String> {
        self.attestations
            .values()
            .filter(|attestation| {
                attestation.witness_id == witness_id
                    && attestation.request.verdict == AttestationVerdict::Approve
            })
            .map(|attestation| attestation.request.verifier_commitment.clone())
            .collect()
    }

    pub fn required_attestation_kinds(&self) -> BTreeSet<AttestationKind> {
        let mut kinds = BTreeSet::from([
            AttestationKind::BytecodeHash,
            AttestationKind::AbiCompatibility,
            AttestationKind::PqSignature,
        ]);
        if self.config.require_reproducible_build {
            kinds.insert(AttestationKind::ReproducibleBuild);
        }
        if self.config.require_privacy_invariant {
            kinds.insert(AttestationKind::PrivacyInvariant);
        }
        kinds
    }

    fn insert_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
        if !self.consumed_nullifiers.insert(nullifier.to_string()) {
            return Err("bytecode attestation nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_count =
            self.counters.consumed_nullifier_count.saturating_add(1);
        Ok(())
    }
}

pub fn contract_id(request: &RegisterContractRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-CONTRACT-ID",
        &[
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.contract_kind.as_str()),
            HashPart::Str(&request.deployer_commitment),
            HashPart::Str(&request.admin_commitment),
            HashPart::Str(&request.bytecode_root),
            HashPart::Str(&request.abi_root),
            HashPart::Str(&request.registration_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn bytecode_witness_id(request: &CommitBytecodeWitnessRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-WITNESS-ID",
        &[
            HashPart::Str(&request.contract_id),
            HashPart::Str(request.witness_kind.as_str()),
            HashPart::Str(&request.witness_commitment_root),
            HashPart::Str(&request.bytecode_chunk_root),
            HashPart::Str(&request.witness_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn pq_verifier_attestation_id(request: &AttestBytecodeRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-VERIFIER-ID",
        &[
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.witness_id),
            HashPart::Str(&request.verifier_commitment),
            HashPart::Str(&request.verifier_set_id),
            HashPart::Str(request.attestation_kind.as_str()),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn upgrade_simulation_id(request: &AttestUpgradeSimulationRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-UPGRADE-SIMULATION-ID",
        &[
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.current_bytecode_root),
            HashPart::Str(&request.proposed_bytecode_root),
            HashPart::Str(&request.simulation_trace_root),
            HashPart::Str(&request.simulation_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn low_fee_proof_reservation_id(request: &ReserveLowFeeProofRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-LOW-FEE-RESERVATION-ID",
        &[
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.proof_budget_root),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Str(&request.reservation_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn deployment_certificate_id(
    request: &IssueDeploymentCertificateRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-BYTECODE-ATTESTATION-DEPLOYMENT-CERTIFICATE-ID",
        &[
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.witness_id),
            HashPart::Str(&request.verifier_quorum_root),
            HashPart::Str(&request.deployment_policy_root),
            HashPart::Str(&request.runtime_host_root),
            HashPart::Str(&request.certificate_nullifier),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_BYTECODE_ATTESTATION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

fn validate_registration(
    request: &RegisterContractRequest,
) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    required("deployer_commitment", &request.deployer_commitment)?;
    required("admin_commitment", &request.admin_commitment)?;
    required("bytecode_root", &request.bytecode_root)?;
    required("source_commitment_root", &request.source_commitment_root)?;
    required("abi_root", &request.abi_root)?;
    required("constructor_root", &request.constructor_root)?;
    required("initial_state_root", &request.initial_state_root)?;
    required("verifier_policy_root", &request.verifier_policy_root)?;
    required("low_fee_policy_root", &request.low_fee_policy_root)?;
    required("privacy_policy_root", &request.privacy_policy_root)?;
    required("registration_nullifier", &request.registration_nullifier)?;
    Ok(())
}

fn validate_witness(
    request: &CommitBytecodeWitnessRequest,
) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    required("contract_id", &request.contract_id)?;
    required("witness_commitment_root", &request.witness_commitment_root)?;
    required("bytecode_chunk_root", &request.bytecode_chunk_root)?;
    required("build_manifest_root", &request.build_manifest_root)?;
    required("dependency_root", &request.dependency_root)?;
    required(
        "reproducibility_proof_root",
        &request.reproducibility_proof_root,
    )?;
    required("pq_authorization_root", &request.pq_authorization_root)?;
    required("privacy_proof_root", &request.privacy_proof_root)?;
    required("witness_nullifier", &request.witness_nullifier)?;
    Ok(())
}

fn validate_attestation(
    request: &AttestBytecodeRequest,
    config: &Config,
) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    required("contract_id", &request.contract_id)?;
    required("witness_id", &request.witness_id)?;
    required("verifier_commitment", &request.verifier_commitment)?;
    required("verifier_set_id", &request.verifier_set_id)?;
    required("evidence_root", &request.evidence_root)?;
    required("pq_signature_root", &request.pq_signature_root)?;
    required("privacy_proof_root", &request.privacy_proof_root)?;
    required("attestation_nullifier", &request.attestation_nullifier)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.fee_bps > config.max_fee_bps {
        return Err("bytecode attestation fee exceeds runtime cap".to_string());
    }
    Ok(())
}

fn validate_upgrade_simulation(
    request: &AttestUpgradeSimulationRequest,
    config: &Config,
) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    required("contract_id", &request.contract_id)?;
    required("current_bytecode_root", &request.current_bytecode_root)?;
    required("proposed_bytecode_root", &request.proposed_bytecode_root)?;
    required("migration_witness_root", &request.migration_witness_root)?;
    required("simulation_trace_root", &request.simulation_trace_root)?;
    required(
        "compatibility_report_root",
        &request.compatibility_report_root,
    )?;
    required("rollback_plan_root", &request.rollback_plan_root)?;
    required("simulator_commitment", &request.simulator_commitment)?;
    required("pq_signature_root", &request.pq_signature_root)?;
    required("privacy_proof_root", &request.privacy_proof_root)?;
    required("simulation_nullifier", &request.simulation_nullifier)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.fee_bps > config.max_fee_bps {
        return Err("bytecode upgrade simulation fee exceeds runtime cap".to_string());
    }
    Ok(())
}

fn validate_reservation(
    request: &ReserveLowFeeProofRequest,
    config: &Config,
) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    required("contract_id", &request.contract_id)?;
    required("sponsor_commitment", &request.sponsor_commitment)?;
    required("proof_budget_root", &request.proof_budget_root)?;
    required("fee_asset_id", &request.fee_asset_id)?;
    required("pq_reservation_root", &request.pq_reservation_root)?;
    required("reservation_nullifier", &request.reservation_nullifier)?;
    if request.reserved_fee_bps > config.max_fee_bps {
        return Err("bytecode low-fee reservation exceeds runtime fee cap".to_string());
    }
    if request.max_proof_count == 0 {
        return Err("bytecode low-fee reservation proof count must be positive".to_string());
    }
    if request.expires_at_height <= request.reserved_at_height {
        return Err("bytecode low-fee reservation expiry must follow reservation".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.reserved_at_height)
        > config.reservation_ttl_blocks
    {
        return Err("bytecode low-fee reservation exceeds TTL".to_string());
    }
    Ok(())
}

fn validate_certificate(
    request: &IssueDeploymentCertificateRequest,
) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    required("contract_id", &request.contract_id)?;
    required("witness_id", &request.witness_id)?;
    required("verifier_quorum_root", &request.verifier_quorum_root)?;
    required("deployment_policy_root", &request.deployment_policy_root)?;
    required("runtime_host_root", &request.runtime_host_root)?;
    required("deployment_proof_root", &request.deployment_proof_root)?;
    required(
        "pq_certificate_signature_root",
        &request.pq_certificate_signature_root,
    )?;
    required("certificate_nullifier", &request.certificate_nullifier)?;
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("bytecode attestation privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("bytecode attestation PQ security bits below minimum".to_string());
    }
    Ok(())
}

fn required(field: &str, value: &str) -> PrivateL2PqContractBytecodeAttestationRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("bytecode attestation field {field} is required"));
    }
    Ok(())
}
