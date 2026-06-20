use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedMerkleReplayAttestorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedMerkleReplayAttestorRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_MERKLE_REPLAY_ATTESTOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-merkle-replay-attestor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_MERKLE_REPLAY_ATTESTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_MERKLE_REPLAY_ATTESTOR_SUITE: &str =
    "confidential-contract-sealed-merkle-replay-attestor-v1";
pub const PQ_REPLAY_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-sealed-merkle-replay-attestation-v1";
pub const SEALED_ROLLBACK_SUITE: &str = "sealed-confidential-contract-rollback-root-v1";
pub const SEALED_COMPENSATION_SUITE: &str = "sealed-confidential-contract-compensation-root-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-sealed-merkle-replay-attestor-batch-v1";
pub const DETERMINISTIC_ROOT_SUITE: &str = "deterministic-sealed-merkle-replay-attestor-root-v1";
pub const CONTRACT_ATTESTOR_SCHEME: &str = "sealed-merkle-replay-contract-attestor-root-v1";
pub const REPLAY_CLAIM_SCHEME: &str = "sealed-merkle-replay-claim-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-authenticated-merkle-replay-attestation-root-v1";
pub const ROLLBACK_ROOT_SCHEME: &str = "sealed-merkle-replay-rollback-root-v1";
pub const COMPENSATION_ROOT_SCHEME: &str = "sealed-merkle-replay-compensation-root-v1";
pub const EXECUTION_BATCH_SCHEME: &str = "low-fee-merkle-replay-attestor-batch-root-v1";
pub const DETERMINISTIC_TRACE_SCHEME: &str = "sealed-merkle-replay-attestor-trace-root-v1";
pub const FIXTURE_SCHEME: &str = "sealed-merkle-replay-attestor-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_285_376;
pub const DEVNET_EPOCH: u64 = 10_325;
pub const DEFAULT_ATTESTATION_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_COMPENSATION_WINDOW_BLOCKS: u64 = 80;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MAX_ATTESTORS: usize = 512;
pub const DEFAULT_MAX_REPLAY_CLAIMS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_BASE_ATTESTATION_MICRO_FEE: u64 = 6;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 32_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractReplayDomain {
    ContractCall,
    CrossContractCall,
    VaultMutation,
    OracleGuardedMutation,
    GovernanceExecution,
    AccountRecovery,
    RollbackCompensation,
    EmergencyPatch,
}

impl ContractReplayDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::CrossContractCall => "cross_contract_call",
            Self::VaultMutation => "vault_mutation",
            Self::OracleGuardedMutation => "oracle_guarded_mutation",
            Self::GovernanceExecution => "governance_execution",
            Self::AccountRecovery => "account_recovery",
            Self::RollbackCompensation => "rollback_compensation",
            Self::EmergencyPatch => "emergency_patch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayClaimStatus {
    Sealed,
    MerkleCommitted,
    PqAttested,
    BatchReady,
    Executed,
    RolledBack,
    Compensated,
    DuplicateRejected,
    Expired,
}

impl ReplayClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::MerkleCommitted => "merkle_committed",
            Self::PqAttested => "pq_attested",
            Self::BatchReady => "batch_ready",
            Self::Executed => "executed",
            Self::RolledBack => "rolled_back",
            Self::Compensated => "compensated",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::Expired => "expired",
        }
    }

    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::MerkleCommitted | Self::PqAttested | Self::BatchReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Proposed,
    Authenticated,
    Applied,
    Challenged,
    Rejected,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authenticated => "authenticated",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRootStatus {
    Sealed,
    Armed,
    Applied,
    Cancelled,
}

impl RecoveryRootStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Armed => "armed",
            Self::Applied => "applied",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub sealed_merkle_replay_attestor_suite: String,
    pub pq_replay_attestation_suite: String,
    pub sealed_rollback_suite: String,
    pub sealed_compensation_suite: String,
    pub low_fee_batch_suite: String,
    pub deterministic_root_suite: String,
    pub attestation_window_blocks: u64,
    pub rollback_window_blocks: u64,
    pub compensation_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_attestors: usize,
    pub max_replay_claims_per_batch: usize,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub base_attestation_micro_fee: u64,
    pub max_vm_steps_per_batch: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            sealed_merkle_replay_attestor_suite: SEALED_MERKLE_REPLAY_ATTESTOR_SUITE.to_string(),
            pq_replay_attestation_suite: PQ_REPLAY_ATTESTATION_SUITE.to_string(),
            sealed_rollback_suite: SEALED_ROLLBACK_SUITE.to_string(),
            sealed_compensation_suite: SEALED_COMPENSATION_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            deterministic_root_suite: DETERMINISTIC_ROOT_SUITE.to_string(),
            attestation_window_blocks: DEFAULT_ATTESTATION_WINDOW_BLOCKS,
            rollback_window_blocks: DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            compensation_window_blocks: DEFAULT_COMPENSATION_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            max_attestors: DEFAULT_MAX_ATTESTORS,
            max_replay_claims_per_batch: DEFAULT_MAX_REPLAY_CLAIMS_PER_BATCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            base_attestation_micro_fee: DEFAULT_BASE_ATTESTATION_MICRO_FEE,
            max_vm_steps_per_batch: DEFAULT_MAX_VM_STEPS_PER_BATCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("schema version mismatch".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.operator_fee_bps > MAX_BPS
            || self.batch_rebate_bps > MAX_BPS
        {
            return Err("basis point configuration exceeds MAX_BPS".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security below policy".to_string());
        }
        if self.max_attestors == 0 || self.max_replay_claims_per_batch == 0 {
            return Err("attestor and replay claim limits must be nonzero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub contract_attestors: u64,
    pub enabled_contract_attestors: u64,
    pub replay_claims: u64,
    pub pending_replay_claims: u64,
    pub pq_replay_attestations: u64,
    pub authenticated_pq_attestations: u64,
    pub sealed_rollback_roots: u64,
    pub applied_rollbacks: u64,
    pub sealed_compensation_roots: u64,
    pub applied_compensations: u64,
    pub execution_batches: u64,
    pub deterministic_traces: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub contract_attestor_root: String,
    pub replay_claim_root: String,
    pub pq_attestation_root: String,
    pub sealed_rollback_root: String,
    pub sealed_compensation_root: String,
    pub execution_batch_root: String,
    pub deterministic_trace_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            contract_attestor_root: merkle_root(CONTRACT_ATTESTOR_SCHEME, &[]),
            replay_claim_root: merkle_root(REPLAY_CLAIM_SCHEME, &[]),
            pq_attestation_root: merkle_root(PQ_ATTESTATION_SCHEME, &[]),
            sealed_rollback_root: merkle_root(ROLLBACK_ROOT_SCHEME, &[]),
            sealed_compensation_root: merkle_root(COMPENSATION_ROOT_SCHEME, &[]),
            execution_batch_root: merkle_root(EXECUTION_BATCH_SCHEME, &[]),
            deterministic_trace_root: merkle_root(DETERMINISTIC_TRACE_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractAttestor {
    pub attestor_id: String,
    pub contract_id: String,
    pub domain: ContractReplayDomain,
    pub contract_code_root: String,
    pub verifier_key_root: String,
    pub replay_policy_root: String,
    pub latest_attested_merkle_root: String,
    pub min_privacy_set_size: u64,
    pub enabled: bool,
}

impl ContractAttestor {
    pub fn public_record(&self) -> Value {
        json!({
            "attestor_id": self.attestor_id,
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "contract_code_root": self.contract_code_root,
            "verifier_key_root": self.verifier_key_root,
            "replay_policy_root": self.replay_policy_root,
            "latest_attested_merkle_root": self.latest_attested_merkle_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedReplayClaim {
    pub claim_id: String,
    pub attestor_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub sealed_call_root: String,
    pub replay_nullifier_root: String,
    pub merkle_witness_root: String,
    pub prior_state_root: String,
    pub expected_state_root: String,
    pub rollback_commitment_root: String,
    pub compensation_commitment_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub status: ReplayClaimStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl SealedReplayClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "attestor_id": self.attestor_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "sealed_call_root": self.sealed_call_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "merkle_witness_root": self.merkle_witness_root,
            "prior_state_root": self.prior_state_root,
            "expected_state_root": self.expected_state_root,
            "rollback_commitment_root": self.rollback_commitment_root,
            "compensation_commitment_root": self.compensation_commitment_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqReplayAttestation {
    pub attestation_id: String,
    pub claim_id: String,
    pub predecessor_state_root: String,
    pub successor_state_root: String,
    pub replay_transcript_root: String,
    pub merkle_inclusion_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub status: PqAttestationStatus,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
}

impl PqReplayAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "claim_id": self.claim_id,
            "predecessor_state_root": self.predecessor_state_root,
            "successor_state_root": self.successor_state_root,
            "replay_transcript_root": self.replay_transcript_root,
            "merkle_inclusion_root": self.merkle_inclusion_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "authenticated_height": self.authenticated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedRollbackRoot {
    pub rollback_id: String,
    pub claim_id: String,
    pub trigger_state_root: String,
    pub sealed_rollback_root: String,
    pub rollback_note_root: String,
    pub status: RecoveryRootStatus,
    pub available_height: u64,
    pub applied_height: Option<u64>,
}

impl SealedRollbackRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "rollback_id": self.rollback_id,
            "claim_id": self.claim_id,
            "trigger_state_root": self.trigger_state_root,
            "sealed_rollback_root": self.sealed_rollback_root,
            "rollback_note_root": self.rollback_note_root,
            "status": self.status.as_str(),
            "available_height": self.available_height,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedCompensationRoot {
    pub compensation_id: String,
    pub claim_id: String,
    pub trigger_state_root: String,
    pub sealed_compensation_root: String,
    pub beneficiary_note_root: String,
    pub status: RecoveryRootStatus,
    pub available_height: u64,
    pub applied_height: Option<u64>,
}

impl SealedCompensationRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "compensation_id": self.compensation_id,
            "claim_id": self.claim_id,
            "trigger_state_root": self.trigger_state_root,
            "sealed_compensation_root": self.sealed_compensation_root,
            "beneficiary_note_root": self.beneficiary_note_root,
            "status": self.status.as_str(),
            "available_height": self.available_height,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExecutionBatch {
    pub batch_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub attestor_root: String,
    pub replay_claim_root: String,
    pub pq_attestation_root: String,
    pub rollback_root: String,
    pub compensation_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub claim_count: u64,
    pub aggregate_fee_micro_units: u64,
    pub low_fee_eligible: bool,
    pub executed_height: u64,
}

impl ExecutionBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "attestor_root": self.attestor_root,
            "replay_claim_root": self.replay_claim_root,
            "pq_attestation_root": self.pq_attestation_root,
            "rollback_root": self.rollback_root,
            "compensation_root": self.compensation_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "claim_count": self.claim_count,
            "aggregate_fee_micro_units": self.aggregate_fee_micro_units,
            "low_fee_eligible": self.low_fee_eligible,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DeterministicTrace {
    pub trace_id: String,
    pub batch_id: String,
    pub claim_id: String,
    pub attestation_id: String,
    pub deterministic_merkle_root: String,
    pub replay_attestor_root: String,
    pub rollback_branch_root: String,
    pub compensation_branch_root: String,
    pub fee_meter_root: String,
}

impl DeterministicTrace {
    pub fn public_record(&self) -> Value {
        json!({
            "trace_id": self.trace_id,
            "batch_id": self.batch_id,
            "claim_id": self.claim_id,
            "attestation_id": self.attestation_id,
            "deterministic_merkle_root": self.deterministic_merkle_root,
            "replay_attestor_root": self.replay_attestor_root,
            "rollback_branch_root": self.rollback_branch_root,
            "compensation_branch_root": self.compensation_branch_root,
            "fee_meter_root": self.fee_meter_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub deterministic_seed_root: String,
    pub expected_state_root: String,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "label": self.label,
            "deterministic_seed_root": self.deterministic_seed_root,
            "expected_state_root": self.expected_state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub contract_attestors: BTreeMap<String, ContractAttestor>,
    pub replay_claims: BTreeMap<String, SealedReplayClaim>,
    pub pq_replay_attestations: BTreeMap<String, PqReplayAttestation>,
    pub sealed_rollback_roots: BTreeMap<String, SealedRollbackRoot>,
    pub sealed_compensation_roots: BTreeMap<String, SealedCompensationRoot>,
    pub execution_batches: BTreeMap<String, ExecutionBatch>,
    pub deterministic_traces: BTreeMap<String, DeterministicTrace>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            contract_attestors: BTreeMap::new(),
            replay_claims: BTreeMap::new(),
            pq_replay_attestations: BTreeMap::new(),
            sealed_rollback_roots: BTreeMap::new(),
            sealed_compensation_roots: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            deterministic_traces: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let domain = ContractReplayDomain::CrossContractCall;
        let attestor_id = contract_attestor_id(domain, "contract-private-router", 0);
        let claim_id = sealed_replay_claim_id(&attestor_id, "caller-commitment-alice", 0);
        let attestation_id = pq_replay_attestation_id(&claim_id, "devnet-merkle-replay", 0);
        let rollback_id = rollback_root_id(&claim_id, "vault-route-rollback", 0);
        let compensation_id = compensation_root_id(&claim_id, "vault-route-compensation", 0);
        let operator_id = operator_id("devnet-merkle-replay-attestor-alpha", DEVNET_EPOCH);
        let batch_id = execution_batch_id(&operator_id, DEVNET_EPOCH, DEVNET_HEIGHT + 2);
        let trace_id = deterministic_trace_id(&batch_id, &claim_id, &attestation_id);

        state.contract_attestors.insert(
            attestor_id.clone(),
            ContractAttestor {
                attestor_id: attestor_id.clone(),
                contract_id: "contract-private-router".to_string(),
                domain,
                contract_code_root: deterministic_root("contract-code", "private-router", 0),
                verifier_key_root: deterministic_root("verifier-key", "private-router", 0),
                replay_policy_root: deterministic_root("replay-policy", "low-fee-attestor", 0),
                latest_attested_merkle_root: deterministic_root("latest-merkle", "vault-route", 0),
                min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                enabled: true,
            },
        );
        state.replay_claims.insert(
            claim_id.clone(),
            SealedReplayClaim {
                claim_id: claim_id.clone(),
                attestor_id: attestor_id.clone(),
                contract_id: "contract-private-router".to_string(),
                caller_commitment: "caller-commitment-alice".to_string(),
                sealed_call_root: deterministic_root("sealed-call", "vault-route", 0),
                replay_nullifier_root: deterministic_root("replay-nullifier", "vault-route", 0),
                merkle_witness_root: deterministic_root("merkle-witness", "vault-route", 0),
                prior_state_root: deterministic_root("prior-state", "vault-route", 0),
                expected_state_root: deterministic_root("expected-state", "vault-route", 1),
                rollback_commitment_root: deterministic_root("rollback", "vault-route", 0),
                compensation_commitment_root: deterministic_root("compensation", "vault-route", 0),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                status: ReplayClaimStatus::Executed,
                submitted_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_WINDOW_BLOCKS,
            },
        );
        state.pq_replay_attestations.insert(
            attestation_id.clone(),
            PqReplayAttestation {
                attestation_id: attestation_id.clone(),
                claim_id: claim_id.clone(),
                predecessor_state_root: deterministic_root("predecessor-state", "vault-route", 0),
                successor_state_root: deterministic_root("successor-state", "vault-route", 1),
                replay_transcript_root: deterministic_root("replay-transcript", "vault-route", 0),
                merkle_inclusion_root: deterministic_root("merkle-inclusion", "vault-route", 0),
                pq_public_key_root: deterministic_root("pq-public-key", "attestor-alpha", 0),
                pq_signature_root: deterministic_root("pq-signature", "replay-attestation", 0),
                status: PqAttestationStatus::Applied,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                authenticated_height: DEVNET_HEIGHT + 1,
            },
        );
        state.sealed_rollback_roots.insert(
            rollback_id.clone(),
            SealedRollbackRoot {
                rollback_id,
                claim_id: claim_id.clone(),
                trigger_state_root: deterministic_root("rollback-trigger", "vault-timeout", 0),
                sealed_rollback_root: deterministic_root("sealed-rollback", "vault-rewind", 0),
                rollback_note_root: deterministic_root("rollback-note", "vault-rewind", 0),
                status: RecoveryRootStatus::Cancelled,
                available_height: DEVNET_HEIGHT + DEFAULT_ROLLBACK_WINDOW_BLOCKS,
                applied_height: None,
            },
        );
        state.sealed_compensation_roots.insert(
            compensation_id.clone(),
            SealedCompensationRoot {
                compensation_id,
                claim_id: claim_id.clone(),
                trigger_state_root: deterministic_root(
                    "compensation-trigger",
                    "vault-compensate",
                    0,
                ),
                sealed_compensation_root: deterministic_root(
                    "sealed-compensation",
                    "vault-credit",
                    0,
                ),
                beneficiary_note_root: deterministic_root("beneficiary-note", "alice-credit", 0),
                status: RecoveryRootStatus::Cancelled,
                available_height: DEVNET_HEIGHT + DEFAULT_COMPENSATION_WINDOW_BLOCKS,
                applied_height: None,
            },
        );
        state.execution_batches.insert(
            batch_id.clone(),
            ExecutionBatch {
                batch_id: batch_id.clone(),
                operator_id,
                epoch: DEVNET_EPOCH,
                attestor_root: root_for_values(CONTRACT_ATTESTOR_SCHEME, &[json!(attestor_id)]),
                replay_claim_root: root_for_values(REPLAY_CLAIM_SCHEME, &[json!(claim_id)]),
                pq_attestation_root: root_for_values(
                    PQ_ATTESTATION_SCHEME,
                    &[json!(attestation_id)],
                ),
                rollback_root: root_for_values(ROLLBACK_ROOT_SCHEME, &[json!("vault-rewind")]),
                compensation_root: root_for_values(
                    COMPENSATION_ROOT_SCHEME,
                    &[json!("alice-credit")],
                ),
                pre_state_root: deterministic_root("batch-pre-state", "vault-route", DEVNET_EPOCH),
                post_state_root: deterministic_root(
                    "batch-post-state",
                    "vault-route",
                    DEVNET_EPOCH,
                ),
                claim_count: 1,
                aggregate_fee_micro_units: DEFAULT_BASE_ATTESTATION_MICRO_FEE,
                low_fee_eligible: true,
                executed_height: DEVNET_HEIGHT + 2,
            },
        );
        state.deterministic_traces.insert(
            trace_id.clone(),
            DeterministicTrace {
                trace_id,
                batch_id,
                claim_id,
                attestation_id,
                deterministic_merkle_root: deterministic_root(
                    "deterministic-merkle",
                    "vault-route",
                    0,
                ),
                replay_attestor_root: deterministic_root("replay-attestor", "vault-route", 0),
                rollback_branch_root: deterministic_root("rollback-branch", "vault-rewind", 0),
                compensation_branch_root: deterministic_root(
                    "compensation-branch",
                    "alice-credit",
                    0,
                ),
                fee_meter_root: deterministic_root("fee-meter", "vault-route", 0),
            },
        );

        state.recompute_counters();
        state.recompute_roots();
        let expected_state_root = state.state_root();
        let fixture_id = fixture_id("sealed-merkle-replay-attestor-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "sealed-merkle-replay-attestor-demo".to_string(),
                deterministic_seed_root: deterministic_root("fixture-seed", "demo", 1),
                expected_state_root,
            },
        );
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_sealed_merkle_replay_attestor_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "sealed_merkle_replay_attestor_suite": SEALED_MERKLE_REPLAY_ATTESTOR_SUITE,
            "pq_replay_attestation_suite": PQ_REPLAY_ATTESTATION_SUITE,
            "sealed_rollback_suite": SEALED_ROLLBACK_SUITE,
            "sealed_compensation_suite": SEALED_COMPENSATION_SUITE,
            "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
            "deterministic_root_suite": DETERMINISTIC_ROOT_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "contract_attestors": self.contract_attestors.values().map(ContractAttestor::public_record).collect::<Vec<_>>(),
            "replay_claims": self.replay_claims.values().map(SealedReplayClaim::public_record).collect::<Vec<_>>(),
            "pq_replay_attestations": self.pq_replay_attestations.values().map(PqReplayAttestation::public_record).collect::<Vec<_>>(),
            "sealed_rollback_roots": self.sealed_rollback_roots.values().map(SealedRollbackRoot::public_record).collect::<Vec<_>>(),
            "sealed_compensation_roots": self.sealed_compensation_roots.values().map(SealedCompensationRoot::public_record).collect::<Vec<_>>(),
            "execution_batches": self.execution_batches.values().map(ExecutionBatch::public_record).collect::<Vec<_>>(),
            "deterministic_traces": self.deterministic_traces.values().map(DeterministicTrace::public_record).collect::<Vec<_>>(),
            "devnet_fixtures": self.devnet_fixtures.values().map(DevnetFixture::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            contract_attestors: self.contract_attestors.len() as u64,
            enabled_contract_attestors: self
                .contract_attestors
                .values()
                .filter(|attestor| attestor.enabled)
                .count() as u64,
            replay_claims: self.replay_claims.len() as u64,
            pending_replay_claims: self
                .replay_claims
                .values()
                .filter(|claim| claim.status.pending())
                .count() as u64,
            pq_replay_attestations: self.pq_replay_attestations.len() as u64,
            authenticated_pq_attestations: self
                .pq_replay_attestations
                .values()
                .filter(|attestation| {
                    matches!(
                        attestation.status,
                        PqAttestationStatus::Authenticated | PqAttestationStatus::Applied
                    )
                })
                .count() as u64,
            sealed_rollback_roots: self.sealed_rollback_roots.len() as u64,
            applied_rollbacks: self
                .sealed_rollback_roots
                .values()
                .filter(|root| root.status == RecoveryRootStatus::Applied)
                .count() as u64,
            sealed_compensation_roots: self.sealed_compensation_roots.len() as u64,
            applied_compensations: self
                .sealed_compensation_roots
                .values()
                .filter(|root| root.status == RecoveryRootStatus::Applied)
                .count() as u64,
            execution_batches: self.execution_batches.len() as u64,
            deterministic_traces: self.deterministic_traces.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            contract_attestor_root: record_root(
                CONTRACT_ATTESTOR_SCHEME,
                self.contract_attestors
                    .values()
                    .map(ContractAttestor::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            replay_claim_root: record_root(
                REPLAY_CLAIM_SCHEME,
                self.replay_claims
                    .values()
                    .map(SealedReplayClaim::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                self.pq_replay_attestations
                    .values()
                    .map(PqReplayAttestation::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_rollback_root: record_root(
                ROLLBACK_ROOT_SCHEME,
                self.sealed_rollback_roots
                    .values()
                    .map(SealedRollbackRoot::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_compensation_root: record_root(
                COMPENSATION_ROOT_SCHEME,
                self.sealed_compensation_roots
                    .values()
                    .map(SealedCompensationRoot::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            execution_batch_root: record_root(
                EXECUTION_BATCH_SCHEME,
                self.execution_batches
                    .values()
                    .map(ExecutionBatch::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            deterministic_trace_root: record_root(
                DETERMINISTIC_TRACE_SCHEME,
                self.deterministic_traces
                    .values()
                    .map(DeterministicTrace::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            fixture_root: record_root(
                FIXTURE_SCHEME,
                self.devnet_fixtures
                    .values()
                    .map(DevnetFixture::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        };
    }
}

pub fn contract_attestor_id(domain: ContractReplayDomain, contract_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:ATTESTOR-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(contract_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sealed_replay_claim_id(attestor_id: &str, caller_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:CLAIM-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(attestor_id),
            HashPart::Str(caller_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_replay_attestation_id(claim_id: &str, proof_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(claim_id),
            HashPart::Str(proof_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn rollback_root_id(claim_id: &str, root_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:ROLLBACK-ROOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(claim_id),
            HashPart::Str(root_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn compensation_root_id(claim_id: &str, root_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:COMPENSATION-ROOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(claim_id),
            HashPart::Str(root_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn operator_id(operator_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:OPERATOR-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn execution_batch_id(operator_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn deterministic_trace_id(batch_id: &str, claim_id: &str, attestation_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:TRACE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(claim_id),
            HashPart::Str(attestation_id),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:FIXTURE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn root_for_values(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-MERKLE-REPLAY-ATTESTOR:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
