use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-smart-contract-rollup-vm-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_BYTECODE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-bytecode-commitment-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-encrypted-calldata-queue-v1";
pub const RECURSIVE_PROOF_SUITE: &str = "pq-recursive-private-rollup-proof-attachment-v1";
pub const PRIVATE_EVENT_SCHEME: &str = "confidential-contract-private-event-root-v1";
pub const PRECONFIRMATION_SCHEME: &str = "fast-private-rollup-preconfirmation-receipt-v1";
pub const PRIVACY_ACCOUNTING_SCHEME: &str = "monero-l2-contract-privacy-accounting-v1";
pub const SLASHING_SCHEME: &str = "pq-rollup-vm-slashing-challenge-evidence-v1";
pub const DEVNET_HEIGHT: u64 = 2_440_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractKind {
    Account,
    Token,
    Amm,
    Lending,
    Perpetuals,
    Options,
    Oracle,
    Paymaster,
    BridgeAdapter,
    Governance,
    ProofAggregator,
    Custom,
}

impl ContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Token => "token",
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::Oracle => "oracle",
            Self::Paymaster => "paymaster",
            Self::BridgeAdapter => "bridge_adapter",
            Self::Governance => "governance",
            Self::ProofAggregator => "proof_aggregator",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Pending,
    Deployed,
    Warm,
    Paused,
    Retired,
    Slashed,
}

impl ContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Deployed => "deployed",
            Self::Warm => "warm",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn callable(self) -> bool {
        matches!(self, Self::Deployed | Self::Warm)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeCommitmentKind {
    WasmModule,
    RiscVElf,
    NoirCircuit,
    CairoProgram,
    AbiManifest,
    StorageLayout,
    PolicyManifest,
}

impl BytecodeCommitmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WasmModule => "wasm_module",
            Self::RiscVElf => "riscv_elf",
            Self::NoirCircuit => "noir_circuit",
            Self::CairoProgram => "cairo_program",
            Self::AbiManifest => "abi_manifest",
            Self::StorageLayout => "storage_layout",
            Self::PolicyManifest => "policy_manifest",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataQueueStatus {
    Queued,
    Assigned,
    Executing,
    Proved,
    Settled,
    Expired,
    Rejected,
    Challenged,
}

impl CalldataQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Assigned => "assigned",
            Self::Executing => "executing",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Assigned | Self::Executing | Self::Proved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessLaneKind {
    HotSwap,
    DefiBatch,
    BridgeExit,
    OracleUpdate,
    RecursiveProof,
    GeneralPurpose,
}

impl WitnessLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotSwap => "hot_swap",
            Self::DefiBatch => "defi_batch",
            Self::BridgeExit => "bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::RecursiveProof => "recursive_proof",
            Self::GeneralPurpose => "general_purpose",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::HotSwap => 960,
            Self::BridgeExit => 920,
            Self::DefiBatch => 880,
            Self::RecursiveProof => 820,
            Self::OracleUpdate => 720,
            Self::GeneralPurpose => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Open,
    Reserved,
    Consumed,
    Refunded,
    Expired,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofAttachmentStatus {
    Attached,
    Aggregating,
    Verified,
    Rejected,
    Settled,
}

impl ProofAttachmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Aggregating => "aggregating",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidBytecode,
    InvalidWitness,
    DataUnavailable,
    PreconfirmationFault,
    PrivacyLeakage,
    FeeOvercharge,
    RecursiveProofMismatch,
    SequencerEquivocation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidBytecode => "invalid_bytecode",
            Self::InvalidWitness => "invalid_witness",
            Self::DataUnavailable => "data_unavailable",
            Self::PreconfirmationFault => "preconfirmation_fault",
            Self::PrivacyLeakage => "privacy_leakage",
            Self::FeeOvercharge => "fee_overcharge",
            Self::RecursiveProofMismatch => "recursive_proof_mismatch",
            Self::SequencerEquivocation => "sequencer_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    UnderReview,
    Accepted,
    Rejected,
    Slashed,
    Resolved,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::UnderReview => "under_review",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub rollup_id: String,
    pub monero_network: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_preconfirmation_ms: u64,
    pub max_preconfirmation_ms: u64,
    pub base_gas_price_micro_xmr: u64,
    pub max_fee_bps: u64,
    pub coupon_discount_bps: u64,
    pub calldata_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_parallel_lanes: u32,
    pub max_contracts: usize,
    pub max_calldata_queue: usize,
    pub max_events: usize,
    pub max_proofs: usize,
    pub max_challenges: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: "nebula-devnet".to_string(),
            rollup_id: "monero-private-l2-pq-vm".to_string(),
            monero_network: "stagenet".to_string(),
            min_pq_security_bits: 256,
            min_privacy_set_size: 65_536,
            target_preconfirmation_ms: 250,
            max_preconfirmation_ms: 1_200,
            base_gas_price_micro_xmr: 2,
            max_fee_bps: 20,
            coupon_discount_bps: 3_500,
            calldata_ttl_blocks: 64,
            proof_ttl_blocks: 512,
            challenge_window_blocks: 720,
            max_parallel_lanes: 64,
            max_contracts: 262_144,
            max_calldata_queue: 2_097_152,
            max_events: 4_194_304,
            max_proofs: 1_048_576,
            max_challenges: 524_288,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_bytecode_suite": PQ_BYTECODE_SUITE,
            "pq_kem_suite": PQ_KEM_SUITE,
            "recursive_proof_suite": RECURSIVE_PROOF_SUITE,
            "private_event_scheme": PRIVATE_EVENT_SCHEME,
            "preconfirmation_scheme": PRECONFIRMATION_SCHEME,
            "privacy_accounting_scheme": PRIVACY_ACCOUNTING_SCHEME,
            "slashing_scheme": SLASHING_SCHEME,
            "chain_id": self.chain_id,
            "rollup_id": self.rollup_id,
            "monero_network": self.monero_network,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "max_preconfirmation_ms": self.max_preconfirmation_ms,
            "base_gas_price_micro_xmr": self.base_gas_price_micro_xmr,
            "max_fee_bps": self.max_fee_bps,
            "coupon_discount_bps": self.coupon_discount_bps,
            "calldata_ttl_blocks": self.calldata_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_parallel_lanes": self.max_parallel_lanes,
            "max_contracts": self.max_contracts,
            "max_calldata_queue": self.max_calldata_queue,
            "max_events": self.max_events,
            "max_proofs": self.max_proofs,
            "max_challenges": self.max_challenges,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_nonce: u64,
    pub contracts_deployed: u64,
    pub bytecode_commitments: u64,
    pub calldata_enqueued: u64,
    pub calldata_settled: u64,
    pub witness_lanes_opened: u64,
    pub gas_coupons_issued: u64,
    pub private_events_emitted: u64,
    pub recursive_proofs_attached: u64,
    pub preconfirmations_issued: u64,
    pub privacy_debits: u64,
    pub challenges_filed: u64,
    pub slashes_executed: u64,
    pub total_gas_reserved: u64,
    pub total_fees_micro_xmr: u64,
    pub total_fee_discounts_micro_xmr: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_nonce": self.next_nonce,
            "contracts_deployed": self.contracts_deployed,
            "bytecode_commitments": self.bytecode_commitments,
            "calldata_enqueued": self.calldata_enqueued,
            "calldata_settled": self.calldata_settled,
            "witness_lanes_opened": self.witness_lanes_opened,
            "gas_coupons_issued": self.gas_coupons_issued,
            "private_events_emitted": self.private_events_emitted,
            "recursive_proofs_attached": self.recursive_proofs_attached,
            "preconfirmations_issued": self.preconfirmations_issued,
            "privacy_debits": self.privacy_debits,
            "challenges_filed": self.challenges_filed,
            "slashes_executed": self.slashes_executed,
            "total_gas_reserved": self.total_gas_reserved,
            "total_fees_micro_xmr": self.total_fees_micro_xmr,
            "total_fee_discounts_micro_xmr": self.total_fee_discounts_micro_xmr,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub contracts_root: String,
    pub bytecode_root: String,
    pub deployment_receipts_root: String,
    pub calldata_queue_root: String,
    pub witness_lanes_root: String,
    pub gas_coupons_root: String,
    pub private_events_root: String,
    pub recursive_proofs_root: String,
    pub preconfirmation_root: String,
    pub privacy_accounting_root: String,
    pub challenge_evidence_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "contracts_root": self.contracts_root,
            "bytecode_root": self.bytecode_root,
            "deployment_receipts_root": self.deployment_receipts_root,
            "calldata_queue_root": self.calldata_queue_root,
            "witness_lanes_root": self.witness_lanes_root,
            "gas_coupons_root": self.gas_coupons_root,
            "private_events_root": self.private_events_root,
            "recursive_proofs_root": self.recursive_proofs_root,
            "preconfirmation_root": self.preconfirmation_root,
            "privacy_accounting_root": self.privacy_accounting_root,
            "challenge_evidence_root": self.challenge_evidence_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DeployContractRequest {
    pub owner_commitment: String,
    pub contract_kind: ContractKind,
    pub bytecode_commitment_root: String,
    pub abi_commitment_root: String,
    pub storage_layout_root: String,
    pub constructor_calldata_root: String,
    pub policy_root: String,
    pub pq_signer_commitment: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub max_gas_per_call: u64,
    pub deploy_fee_micro_xmr: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractRecord {
    pub contract_id: String,
    pub address_commitment: String,
    pub owner_commitment: String,
    pub contract_kind: ContractKind,
    pub status: ContractStatus,
    pub bytecode_commitment_root: String,
    pub abi_commitment_root: String,
    pub storage_layout_root: String,
    pub policy_root: String,
    pub deploy_receipt_id: String,
    pub privacy_set_size: u64,
    pub max_gas_per_call: u64,
    pub deployed_at_height: u64,
    pub last_call_height: u64,
}

impl ContractRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "address_commitment": self.address_commitment,
            "owner_commitment": self.owner_commitment,
            "contract_kind": self.contract_kind.as_str(),
            "status": self.status.as_str(),
            "bytecode_commitment_root": self.bytecode_commitment_root,
            "abi_commitment_root": self.abi_commitment_root,
            "storage_layout_root": self.storage_layout_root,
            "policy_root": self.policy_root,
            "deploy_receipt_id": self.deploy_receipt_id,
            "privacy_set_size": self.privacy_set_size,
            "max_gas_per_call": self.max_gas_per_call,
            "deployed_at_height": self.deployed_at_height,
            "last_call_height": self.last_call_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BytecodeCommitmentRecord {
    pub commitment_id: String,
    pub contract_id: String,
    pub kind: BytecodeCommitmentKind,
    pub commitment_root: String,
    pub pq_attestation_root: String,
    pub verifier_key_root: String,
    pub reproducible_build_root: String,
    pub security_bits: u16,
    pub height: u64,
}

impl BytecodeCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "contract_id": self.contract_id,
            "kind": self.kind.as_str(),
            "commitment_root": self.commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "verifier_key_root": self.verifier_key_root,
            "reproducible_build_root": self.reproducible_build_root,
            "security_bits": self.security_bits,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DeploymentReceipt {
    pub receipt_id: String,
    pub contract_id: String,
    pub address_commitment: String,
    pub constructor_calldata_root: String,
    pub deployment_state_root: String,
    pub pq_signature_root: String,
    pub fee_paid_micro_xmr: u64,
    pub privacy_set_size: u64,
    pub height: u64,
}

impl DeploymentReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "contract_id": self.contract_id,
            "address_commitment": self.address_commitment,
            "constructor_calldata_root": self.constructor_calldata_root,
            "deployment_state_root": self.deployment_state_root,
            "pq_signature_root": self.pq_signature_root,
            "fee_paid_micro_xmr": self.fee_paid_micro_xmr,
            "privacy_set_size": self.privacy_set_size,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EnqueueCalldataRequest {
    pub contract_id: String,
    pub caller_commitment: String,
    pub encrypted_calldata_root: String,
    pub calldata_ciphertext_bytes: u64,
    pub nullifier_root: String,
    pub gas_limit: u64,
    pub max_fee_micro_xmr: u64,
    pub coupon_id: Option<String>,
    pub privacy_set_size: u64,
    pub priority: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedCalldataRecord {
    pub call_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub encrypted_calldata_root: String,
    pub ciphertext_bytes: u64,
    pub nullifier_root: String,
    pub lane_id: Option<String>,
    pub status: CalldataQueueStatus,
    pub gas_limit: u64,
    pub reserved_fee_micro_xmr: u64,
    pub fee_discount_micro_xmr: u64,
    pub privacy_set_size: u64,
    pub priority: u64,
    pub enqueued_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedCalldataRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "ciphertext_bytes": self.ciphertext_bytes,
            "nullifier_root": self.nullifier_root,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "gas_limit": self.gas_limit,
            "reserved_fee_micro_xmr": self.reserved_fee_micro_xmr,
            "fee_discount_micro_xmr": self.fee_discount_micro_xmr,
            "privacy_set_size": self.privacy_set_size,
            "priority": self.priority,
            "enqueued_at_height": self.enqueued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct WitnessLaneRecord {
    pub lane_id: String,
    pub kind: WitnessLaneKind,
    pub sequencer_commitment: String,
    pub prover_commitment: String,
    pub encrypted_witness_root: String,
    pub assigned_call_ids: BTreeSet<String>,
    pub max_parallel_calls: u32,
    pub target_latency_ms: u64,
    pub fee_ceiling_micro_xmr: u64,
    pub opened_at_height: u64,
    pub last_activity_height: u64,
}

impl WitnessLaneRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "sequencer_commitment": self.sequencer_commitment,
            "prover_commitment": self.prover_commitment,
            "encrypted_witness_root": self.encrypted_witness_root,
            "assigned_call_ids": self.assigned_call_ids,
            "max_parallel_calls": self.max_parallel_calls,
            "target_latency_ms": self.target_latency_ms,
            "fee_ceiling_micro_xmr": self.fee_ceiling_micro_xmr,
            "opened_at_height": self.opened_at_height,
            "last_activity_height": self.last_activity_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct GasCouponRecord {
    pub coupon_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub gas_units: u64,
    pub face_value_micro_xmr: u64,
    pub discount_bps: u64,
    pub status: CouponStatus,
    pub reserved_call_id: Option<String>,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl GasCouponRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "gas_units": self.gas_units,
            "face_value_micro_xmr": self.face_value_micro_xmr,
            "discount_bps": self.discount_bps,
            "status": self.status.as_str(),
            "reserved_call_id": self.reserved_call_id,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateEventRecord {
    pub event_id: String,
    pub contract_id: String,
    pub call_id: String,
    pub encrypted_topic_root: String,
    pub encrypted_payload_root: String,
    pub viewer_tag_root: String,
    pub event_root: String,
    pub height: u64,
}

impl PrivateEventRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "contract_id": self.contract_id,
            "call_id": self.call_id,
            "encrypted_topic_root": self.encrypted_topic_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "viewer_tag_root": self.viewer_tag_root,
            "event_root": self.event_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecursiveProofAttachment {
    pub proof_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub previous_state_root: String,
    pub next_state_root: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub verifier_key_root: String,
    pub aggregation_root: String,
    pub status: ProofAttachmentStatus,
    pub attached_at_height: u64,
    pub expires_at_height: u64,
}

impl RecursiveProofAttachment {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "previous_state_root": self.previous_state_root,
            "next_state_root": self.next_state_root,
            "proof_root": self.proof_root,
            "public_input_root": self.public_input_root,
            "verifier_key_root": self.verifier_key_root,
            "aggregation_root": self.aggregation_root,
            "status": self.status.as_str(),
            "attached_at_height": self.attached_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub sequencer_commitment: String,
    pub expected_state_root: String,
    pub fee_quote_micro_xmr: u64,
    pub latency_budget_ms: u64,
    pub pq_signature_root: String,
    pub issued_at_height: u64,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "lane_id": self.lane_id,
            "sequencer_commitment": self.sequencer_commitment,
            "expected_state_root": self.expected_state_root,
            "fee_quote_micro_xmr": self.fee_quote_micro_xmr,
            "latency_budget_ms": self.latency_budget_ms,
            "pq_signature_root": self.pq_signature_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyAccountingRecord {
    pub accounting_id: String,
    pub call_id: String,
    pub contract_id: String,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
    pub disclosure_budget_used: u64,
    pub leakage_score_bps: u64,
    pub auditor_commitment: String,
    pub height: u64,
}

impl PrivacyAccountingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "accounting_id": self.accounting_id,
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": self.nullifier_root,
            "disclosure_budget_used": self.disclosure_budget_used,
            "leakage_score_bps": self.leakage_score_bps,
            "auditor_commitment": self.auditor_commitment,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ChallengeEvidenceRecord {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub accused_commitment: String,
    pub challenger_commitment: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub slash_amount_micro_xmr: u64,
    pub filed_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl ChallengeEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "accused_commitment": self.accused_commitment,
            "challenger_commitment": self.challenger_commitment,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "slash_amount_micro_xmr": self.slash_amount_micro_xmr,
            "filed_at_height": self.filed_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub contract_id: String,
    pub gas_limit: u64,
    pub base_fee_micro_xmr: u64,
    pub max_fee_micro_xmr: u64,
    pub coupon_discount_micro_xmr: u64,
    pub final_fee_micro_xmr: u64,
    pub fee_bps: u64,
    pub height: u64,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "contract_id": self.contract_id,
            "gas_limit": self.gas_limit,
            "base_fee_micro_xmr": self.base_fee_micro_xmr,
            "max_fee_micro_xmr": self.max_fee_micro_xmr,
            "coupon_discount_micro_xmr": self.coupon_discount_micro_xmr,
            "final_fee_micro_xmr": self.final_fee_micro_xmr,
            "fee_bps": self.fee_bps,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LaneLoadSummary {
    pub lane_id: String,
    pub kind: WitnessLaneKind,
    pub assigned_calls: usize,
    pub max_parallel_calls: u32,
    pub spare_parallel_slots: u32,
    pub priority_weight: u64,
    pub target_latency_ms: u64,
    pub last_activity_height: u64,
}

impl LaneLoadSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "assigned_calls": self.assigned_calls,
            "max_parallel_calls": self.max_parallel_calls,
            "spare_parallel_slots": self.spare_parallel_slots,
            "priority_weight": self.priority_weight,
            "target_latency_ms": self.target_latency_ms,
            "last_activity_height": self.last_activity_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyHealthSummary {
    pub min_privacy_set_size: u64,
    pub observed_calls: usize,
    pub weak_call_count: usize,
    pub max_leakage_score_bps: u64,
    pub privacy_accounting_root: String,
    pub spent_nullifier_count: usize,
}

impl PrivacyHealthSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "min_privacy_set_size": self.min_privacy_set_size,
            "observed_calls": self.observed_calls,
            "weak_call_count": self.weak_call_count,
            "max_leakage_score_bps": self.max_leakage_score_bps,
            "privacy_accounting_root": self.privacy_accounting_root,
            "spent_nullifier_count": self.spent_nullifier_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeSnapshot {
    pub snapshot_id: String,
    pub protocol_version: String,
    pub roots: Roots,
    pub counters: Counters,
    pub live_call_count: usize,
    pub open_coupon_count: usize,
    pub active_lane_count: usize,
    pub pending_challenge_count: usize,
}

impl RuntimeSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "protocol_version": self.protocol_version,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "live_call_count": self.live_call_count,
            "open_coupon_count": self.open_coupon_count,
            "active_lane_count": self.active_lane_count,
            "pending_challenge_count": self.pending_challenge_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub contracts: BTreeMap<String, ContractRecord>,
    pub bytecode_commitments: BTreeMap<String, BytecodeCommitmentRecord>,
    pub deployment_receipts: BTreeMap<String, DeploymentReceipt>,
    pub calldata_queue: BTreeMap<String, EncryptedCalldataRecord>,
    pub pending_calldata: VecDeque<String>,
    pub witness_lanes: BTreeMap<String, WitnessLaneRecord>,
    pub gas_coupons: BTreeMap<String, GasCouponRecord>,
    pub private_events: BTreeMap<String, PrivateEventRecord>,
    pub recursive_proofs: BTreeMap<String, RecursiveProofAttachment>,
    pub preconfirmations: BTreeMap<String, PreconfirmationReceipt>,
    pub privacy_accounting: BTreeMap<String, PrivacyAccountingRecord>,
    pub challenge_evidence: BTreeMap<String, ChallengeEvidenceRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            contracts: BTreeMap::new(),
            bytecode_commitments: BTreeMap::new(),
            deployment_receipts: BTreeMap::new(),
            calldata_queue: BTreeMap::new(),
            pending_calldata: VecDeque::new(),
            witness_lanes: BTreeMap::new(),
            gas_coupons: BTreeMap::new(),
            private_events: BTreeMap::new(),
            recursive_proofs: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            privacy_accounting: BTreeMap::new(),
            challenge_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };

        let contract = state
            .deploy_contract(DeployContractRequest {
                owner_commitment: deterministic_id("OWNER", &[HashPart::Str("devnet-treasury")]),
                contract_kind: ContractKind::Amm,
                bytecode_commitment_root: deterministic_id(
                    "BYTECODE",
                    &[HashPart::Str("private-amm-v1")],
                ),
                abi_commitment_root: deterministic_id("ABI", &[HashPart::Str("private-amm-v1")]),
                storage_layout_root: deterministic_id(
                    "STORAGE",
                    &[HashPart::Str("private-amm-v1")],
                ),
                constructor_calldata_root: deterministic_id(
                    "CONSTRUCTOR",
                    &[HashPart::Str("private-amm-v1")],
                ),
                policy_root: deterministic_id("POLICY", &[HashPart::Str("low-fee-private-defi")]),
                pq_signer_commitment: deterministic_id(
                    "PQ-SIGNER",
                    &[HashPart::Str("devnet-deployer")],
                ),
                pq_signature_root: deterministic_id(
                    "PQ-SIGNATURE",
                    &[HashPart::Str("deploy-private-amm-v1")],
                ),
                privacy_set_size: 131_072,
                max_gas_per_call: 500_000,
                deploy_fee_micro_xmr: 5_000,
                height: DEVNET_HEIGHT,
            })
            .expect("devnet deployment");
        state
            .open_witness_lane(
                WitnessLaneKind::DefiBatch,
                deterministic_id("SEQUENCER", &[HashPart::Str("devnet-fast-sequencer")]),
                deterministic_id("PROVER", &[HashPart::Str("devnet-pq-prover")]),
                deterministic_id("WITNESS", &[HashPart::Str("defi-lane-genesis")]),
                16,
                250,
                500,
                DEVNET_HEIGHT,
            )
            .expect("devnet lane");
        state
            .issue_gas_coupon(
                deterministic_id("SPONSOR", &[HashPart::Str("devnet-fee-sponsor")]),
                deterministic_id("BENEFICIARY", &[HashPart::Str("devnet-trader")]),
                250_000,
                350,
                DEVNET_HEIGHT,
                DEVNET_HEIGHT + 10_000,
            )
            .expect("devnet coupon");
        state
            .enqueue_calldata(EnqueueCalldataRequest {
                contract_id: contract.contract_id,
                caller_commitment: deterministic_id("CALLER", &[HashPart::Str("devnet-trader")]),
                encrypted_calldata_root: deterministic_id(
                    "CALLDATA",
                    &[HashPart::Str("swap-dusd-xmr")],
                ),
                calldata_ciphertext_bytes: 384,
                nullifier_root: deterministic_id("NULLIFIER", &[HashPart::Str("swap-dusd-xmr")]),
                gas_limit: 180_000,
                max_fee_micro_xmr: 360,
                coupon_id: None,
                privacy_set_size: 131_072,
                priority: 950,
                height: DEVNET_HEIGHT + 1,
            })
            .expect("devnet calldata");
        state
    }

    pub fn roots(&self) -> Roots {
        let public_record = self.public_record_without_state_root();
        let mut roots = self.roots_without_recursing();
        roots.public_record_root = record_root("PUBLIC-RECORD", &public_record);
        roots.state_root = record_root("ROOTS", &roots.public_record_without_state_root());
        roots
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "roots": self.roots_without_recursing().public_record_without_state_root(),
            "counters": self.counters.public_record(),
            "pending_calldata": self.pending_calldata,
            "spent_nullifier_count": self.spent_nullifiers.len(),
        })
    }

    pub fn deploy_contract(&mut self, request: DeployContractRequest) -> Result<ContractRecord> {
        self.ensure_capacity(self.contracts.len(), self.config.max_contracts, "contracts")?;
        ensure_non_empty(&request.owner_commitment, "owner commitment")?;
        ensure_non_empty(
            &request.bytecode_commitment_root,
            "bytecode commitment root",
        )?;
        ensure_non_empty(&request.pq_signature_root, "pq signature root")?;
        ensure_minimum(
            request.privacy_set_size,
            self.config.min_privacy_set_size,
            "privacy set",
        )?;
        ensure_max_bps(self.config.max_fee_bps, "max fee bps")?;

        let nonce = self.take_nonce();
        let contract_id = deterministic_id(
            "CONTRACT-ID",
            &[
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(request.contract_kind.as_str()),
                HashPart::Str(&request.bytecode_commitment_root),
                HashPart::U64(nonce),
            ],
        );
        let address_commitment = deterministic_id(
            "CONTRACT-ADDRESS",
            &[
                HashPart::Str(&contract_id),
                HashPart::Str(&request.policy_root),
            ],
        );
        let receipt_id = deterministic_id(
            "DEPLOYMENT-RECEIPT-ID",
            &[HashPart::Str(&contract_id), HashPart::U64(request.height)],
        );
        let deployment_state_root = deterministic_id(
            "DEPLOYMENT-STATE",
            &[
                HashPart::Str(&contract_id),
                HashPart::Str(&request.constructor_calldata_root),
                HashPart::Str(&request.storage_layout_root),
            ],
        );

        let contract = ContractRecord {
            contract_id: contract_id.clone(),
            address_commitment: address_commitment.clone(),
            owner_commitment: request.owner_commitment.clone(),
            contract_kind: request.contract_kind,
            status: ContractStatus::Deployed,
            bytecode_commitment_root: request.bytecode_commitment_root.clone(),
            abi_commitment_root: request.abi_commitment_root.clone(),
            storage_layout_root: request.storage_layout_root.clone(),
            policy_root: request.policy_root.clone(),
            deploy_receipt_id: receipt_id.clone(),
            privacy_set_size: request.privacy_set_size,
            max_gas_per_call: request.max_gas_per_call,
            deployed_at_height: request.height,
            last_call_height: request.height,
        };
        let receipt = DeploymentReceipt {
            receipt_id: receipt_id.clone(),
            contract_id: contract_id.clone(),
            address_commitment,
            constructor_calldata_root: request.constructor_calldata_root.clone(),
            deployment_state_root,
            pq_signature_root: request.pq_signature_root.clone(),
            fee_paid_micro_xmr: request.deploy_fee_micro_xmr,
            privacy_set_size: request.privacy_set_size,
            height: request.height,
        };
        let bytecode = BytecodeCommitmentRecord {
            commitment_id: deterministic_id(
                "BYTECODE-COMMITMENT-ID",
                &[
                    HashPart::Str(&contract_id),
                    HashPart::Str(&request.bytecode_commitment_root),
                ],
            ),
            contract_id: contract_id.clone(),
            kind: BytecodeCommitmentKind::WasmModule,
            commitment_root: request.bytecode_commitment_root.clone(),
            pq_attestation_root: request.pq_signature_root.clone(),
            verifier_key_root: deterministic_id("VERIFIER-KEY", &[HashPart::Str(&contract_id)]),
            reproducible_build_root: deterministic_id(
                "REPRODUCIBLE-BUILD",
                &[HashPart::Str(&request.bytecode_commitment_root)],
            ),
            security_bits: self.config.min_pq_security_bits,
            height: request.height,
        };

        self.counters.contracts_deployed += 1;
        self.counters.bytecode_commitments += 1;
        self.counters.total_fees_micro_xmr += request.deploy_fee_micro_xmr;
        self.contracts.insert(contract_id.clone(), contract.clone());
        self.deployment_receipts.insert(receipt_id, receipt);
        self.bytecode_commitments
            .insert(bytecode.commitment_id.clone(), bytecode);
        Ok(contract)
    }

    pub fn register_bytecode_commitment(
        &mut self,
        record: BytecodeCommitmentRecord,
    ) -> Result<String> {
        ensure_non_empty(&record.contract_id, "bytecode contract")?;
        ensure_non_empty(&record.commitment_root, "bytecode commitment")?;
        ensure_minimum(
            record.security_bits as u64,
            self.config.min_pq_security_bits as u64,
            "pq security",
        )?;
        if !self.contracts.contains_key(&record.contract_id) {
            return Err(format!("unknown contract {}", record.contract_id));
        }
        let id = record.commitment_id.clone();
        self.bytecode_commitments.insert(id.clone(), record);
        self.counters.bytecode_commitments += 1;
        Ok(id)
    }

    pub fn enqueue_calldata(
        &mut self,
        request: EnqueueCalldataRequest,
    ) -> Result<EncryptedCalldataRecord> {
        self.ensure_capacity(
            self.calldata_queue.len(),
            self.config.max_calldata_queue,
            "calldata queue",
        )?;
        let contract = self
            .contracts
            .get(&request.contract_id)
            .ok_or_else(|| format!("unknown contract {}", request.contract_id))?;
        if !contract.status.callable() {
            return Err(format!("contract {} is not callable", request.contract_id));
        }
        ensure_non_empty(&request.encrypted_calldata_root, "encrypted calldata root")?;
        ensure_non_empty(&request.nullifier_root, "nullifier root")?;
        ensure_minimum(
            request.privacy_set_size,
            self.config.min_privacy_set_size,
            "privacy set",
        )?;
        if request.gas_limit > contract.max_gas_per_call {
            return Err("gas limit exceeds contract maximum".to_string());
        }
        if self.spent_nullifiers.contains(&request.nullifier_root) {
            return Err("nullifier already spent".to_string());
        }

        let mut discount = 0;
        if let Some(coupon_id) = &request.coupon_id {
            let coupon = self
                .gas_coupons
                .get_mut(coupon_id)
                .ok_or_else(|| format!("unknown coupon {coupon_id}"))?;
            if coupon.status != CouponStatus::Open {
                return Err(format!("coupon {coupon_id} is not open"));
            }
            discount = request
                .max_fee_micro_xmr
                .saturating_mul(coupon.discount_bps)
                / MAX_BPS;
            coupon.status = CouponStatus::Reserved;
        }

        let call_id = deterministic_id(
            "CALL-ID",
            &[
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.caller_commitment),
                HashPart::Str(&request.encrypted_calldata_root),
                HashPart::U64(self.take_nonce()),
            ],
        );
        if let Some(coupon_id) = &request.coupon_id {
            if let Some(coupon) = self.gas_coupons.get_mut(coupon_id) {
                coupon.reserved_call_id = Some(call_id.clone());
            }
        }
        let record = EncryptedCalldataRecord {
            call_id: call_id.clone(),
            contract_id: request.contract_id,
            caller_commitment: request.caller_commitment,
            encrypted_calldata_root: request.encrypted_calldata_root,
            ciphertext_bytes: request.calldata_ciphertext_bytes,
            nullifier_root: request.nullifier_root,
            lane_id: None,
            status: CalldataQueueStatus::Queued,
            gas_limit: request.gas_limit,
            reserved_fee_micro_xmr: request.max_fee_micro_xmr.saturating_sub(discount),
            fee_discount_micro_xmr: discount,
            privacy_set_size: request.privacy_set_size,
            priority: request.priority,
            enqueued_at_height: request.height,
            expires_at_height: request.height + self.config.calldata_ttl_blocks,
        };
        self.pending_calldata.push_back(call_id.clone());
        self.calldata_queue.insert(call_id, record.clone());
        self.counters.calldata_enqueued += 1;
        self.counters.total_gas_reserved += record.gas_limit;
        self.counters.total_fees_micro_xmr += record.reserved_fee_micro_xmr;
        self.counters.total_fee_discounts_micro_xmr += discount;
        Ok(record)
    }

    pub fn open_witness_lane(
        &mut self,
        kind: WitnessLaneKind,
        sequencer_commitment: String,
        prover_commitment: String,
        encrypted_witness_root: String,
        max_parallel_calls: u32,
        target_latency_ms: u64,
        fee_ceiling_micro_xmr: u64,
        height: u64,
    ) -> Result<WitnessLaneRecord> {
        if max_parallel_calls == 0 || max_parallel_calls > self.config.max_parallel_lanes {
            return Err("invalid parallel lane width".to_string());
        }
        ensure_non_empty(&sequencer_commitment, "sequencer commitment")?;
        ensure_non_empty(&prover_commitment, "prover commitment")?;
        ensure_non_empty(&encrypted_witness_root, "encrypted witness root")?;
        let lane_id = deterministic_id(
            "WITNESS-LANE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&sequencer_commitment),
                HashPart::Str(&prover_commitment),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let lane = WitnessLaneRecord {
            lane_id: lane_id.clone(),
            kind,
            sequencer_commitment,
            prover_commitment,
            encrypted_witness_root,
            assigned_call_ids: BTreeSet::new(),
            max_parallel_calls,
            target_latency_ms,
            fee_ceiling_micro_xmr,
            opened_at_height: height,
            last_activity_height: height,
        };
        self.witness_lanes.insert(lane_id, lane.clone());
        self.counters.witness_lanes_opened += 1;
        Ok(lane)
    }

    pub fn assign_next_calls(
        &mut self,
        lane_id: &str,
        limit: usize,
        height: u64,
    ) -> Result<Vec<String>> {
        let lane = self
            .witness_lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        let remaining = lane
            .max_parallel_calls
            .saturating_sub(lane.assigned_call_ids.len() as u32) as usize;
        let take = remaining.min(limit);
        let mut assigned = Vec::new();
        while assigned.len() < take {
            let Some(call_id) = self.pending_calldata.pop_front() else {
                break;
            };
            let Some(call) = self.calldata_queue.get_mut(&call_id) else {
                continue;
            };
            if !call.status.live() || call.expires_at_height < height {
                call.status = CalldataQueueStatus::Expired;
                continue;
            }
            call.lane_id = Some(lane_id.to_string());
            call.status = CalldataQueueStatus::Assigned;
            lane.assigned_call_ids.insert(call_id.clone());
            assigned.push(call_id);
        }
        lane.last_activity_height = height;
        Ok(assigned)
    }

    pub fn issue_gas_coupon(
        &mut self,
        sponsor_commitment: String,
        beneficiary_commitment: String,
        gas_units: u64,
        face_value_micro_xmr: u64,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> Result<GasCouponRecord> {
        ensure_non_empty(&sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&beneficiary_commitment, "beneficiary commitment")?;
        if expires_at_height <= issued_at_height {
            return Err("coupon expiry must be after issue height".to_string());
        }
        let coupon_id = deterministic_id(
            "GAS-COUPON-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&beneficiary_commitment),
                HashPart::U64(gas_units),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let coupon = GasCouponRecord {
            coupon_id: coupon_id.clone(),
            sponsor_commitment,
            beneficiary_commitment,
            gas_units,
            face_value_micro_xmr,
            discount_bps: self.config.coupon_discount_bps,
            status: CouponStatus::Open,
            reserved_call_id: None,
            issued_at_height,
            expires_at_height,
        };
        self.gas_coupons.insert(coupon_id, coupon.clone());
        self.counters.gas_coupons_issued += 1;
        Ok(coupon)
    }

    pub fn emit_private_event(
        &mut self,
        contract_id: String,
        call_id: String,
        encrypted_topic_root: String,
        encrypted_payload_root: String,
        viewer_tag_root: String,
        height: u64,
    ) -> Result<PrivateEventRecord> {
        self.ensure_capacity(
            self.private_events.len(),
            self.config.max_events,
            "private events",
        )?;
        ensure_non_empty(&encrypted_topic_root, "encrypted topic root")?;
        ensure_non_empty(&encrypted_payload_root, "encrypted payload root")?;
        if !self.contracts.contains_key(&contract_id) {
            return Err(format!("unknown contract {contract_id}"));
        }
        if !self.calldata_queue.contains_key(&call_id) {
            return Err(format!("unknown call {call_id}"));
        }
        let event_root = deterministic_id(
            "PRIVATE-EVENT-ROOT",
            &[
                HashPart::Str(&contract_id),
                HashPart::Str(&call_id),
                HashPart::Str(&encrypted_topic_root),
                HashPart::Str(&encrypted_payload_root),
                HashPart::Str(&viewer_tag_root),
            ],
        );
        let event_id = deterministic_id(
            "PRIVATE-EVENT-ID",
            &[HashPart::Str(&event_root), HashPart::U64(self.take_nonce())],
        );
        let event = PrivateEventRecord {
            event_id: event_id.clone(),
            contract_id,
            call_id,
            encrypted_topic_root,
            encrypted_payload_root,
            viewer_tag_root,
            event_root,
            height,
        };
        self.private_events.insert(event_id, event.clone());
        self.counters.private_events_emitted += 1;
        Ok(event)
    }

    pub fn attach_recursive_proof(
        &mut self,
        call_id: String,
        lane_id: String,
        previous_state_root: String,
        next_state_root: String,
        proof_root: String,
        public_input_root: String,
        verifier_key_root: String,
        height: u64,
    ) -> Result<RecursiveProofAttachment> {
        self.ensure_capacity(
            self.recursive_proofs.len(),
            self.config.max_proofs,
            "recursive proofs",
        )?;
        ensure_non_empty(&proof_root, "proof root")?;
        ensure_non_empty(&public_input_root, "public input root")?;
        if !self.calldata_queue.contains_key(&call_id) {
            return Err(format!("unknown call {call_id}"));
        }
        if !self.witness_lanes.contains_key(&lane_id) {
            return Err(format!("unknown lane {lane_id}"));
        }
        let aggregation_root = deterministic_id(
            "RECURSIVE-AGGREGATION",
            &[
                HashPart::Str(&previous_state_root),
                HashPart::Str(&next_state_root),
                HashPart::Str(&proof_root),
                HashPart::Str(&public_input_root),
            ],
        );
        let proof_id = deterministic_id(
            "RECURSIVE-PROOF-ID",
            &[
                HashPart::Str(&call_id),
                HashPart::Str(&aggregation_root),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let proof = RecursiveProofAttachment {
            proof_id: proof_id.clone(),
            call_id: call_id.clone(),
            lane_id,
            previous_state_root,
            next_state_root,
            proof_root,
            public_input_root,
            verifier_key_root,
            aggregation_root,
            status: ProofAttachmentStatus::Attached,
            attached_at_height: height,
            expires_at_height: height + self.config.proof_ttl_blocks,
        };
        if let Some(call) = self.calldata_queue.get_mut(&call_id) {
            call.status = CalldataQueueStatus::Proved;
        }
        self.recursive_proofs.insert(proof_id, proof.clone());
        self.counters.recursive_proofs_attached += 1;
        Ok(proof)
    }

    pub fn issue_preconfirmation(
        &mut self,
        call_id: String,
        lane_id: String,
        sequencer_commitment: String,
        expected_state_root: String,
        fee_quote_micro_xmr: u64,
        latency_budget_ms: u64,
        pq_signature_root: String,
        issued_at_height: u64,
    ) -> Result<PreconfirmationReceipt> {
        if latency_budget_ms > self.config.max_preconfirmation_ms {
            return Err("latency budget exceeds runtime maximum".to_string());
        }
        if !self.calldata_queue.contains_key(&call_id) {
            return Err(format!("unknown call {call_id}"));
        }
        if !self.witness_lanes.contains_key(&lane_id) {
            return Err(format!("unknown lane {lane_id}"));
        }
        let receipt_id = deterministic_id(
            "PRECONFIRMATION-ID",
            &[
                HashPart::Str(&call_id),
                HashPart::Str(&lane_id),
                HashPart::Str(&expected_state_root),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let receipt = PreconfirmationReceipt {
            receipt_id: receipt_id.clone(),
            call_id,
            lane_id,
            sequencer_commitment,
            expected_state_root,
            fee_quote_micro_xmr,
            latency_budget_ms,
            pq_signature_root,
            issued_at_height,
        };
        self.preconfirmations.insert(receipt_id, receipt.clone());
        self.counters.preconfirmations_issued += 1;
        Ok(receipt)
    }

    pub fn record_privacy_accounting(
        &mut self,
        call_id: String,
        auditor_commitment: String,
        disclosure_budget_used: u64,
        leakage_score_bps: u64,
        height: u64,
    ) -> Result<PrivacyAccountingRecord> {
        ensure_max_bps(leakage_score_bps, "leakage score")?;
        let call = self
            .calldata_queue
            .get(&call_id)
            .ok_or_else(|| format!("unknown call {call_id}"))?;
        let accounting_id = deterministic_id(
            "PRIVACY-ACCOUNTING-ID",
            &[
                HashPart::Str(&call_id),
                HashPart::Str(&auditor_commitment),
                HashPart::U64(height),
                HashPart::U64(self.counters.privacy_debits),
            ],
        );
        let record = PrivacyAccountingRecord {
            accounting_id: accounting_id.clone(),
            call_id: call_id.clone(),
            contract_id: call.contract_id.clone(),
            privacy_set_size: call.privacy_set_size,
            nullifier_root: call.nullifier_root.clone(),
            disclosure_budget_used,
            leakage_score_bps,
            auditor_commitment,
            height,
        };
        self.privacy_accounting
            .insert(accounting_id, record.clone());
        self.counters.privacy_debits += 1;
        Ok(record)
    }

    pub fn settle_call(&mut self, call_id: &str, height: u64) -> Result<EncryptedCalldataRecord> {
        let call = self
            .calldata_queue
            .get_mut(call_id)
            .ok_or_else(|| format!("unknown call {call_id}"))?;
        if call.status != CalldataQueueStatus::Proved {
            return Err("call must be proved before settlement".to_string());
        }
        call.status = CalldataQueueStatus::Settled;
        self.spent_nullifiers.insert(call.nullifier_root.clone());
        if let Some(contract) = self.contracts.get_mut(&call.contract_id) {
            contract.last_call_height = height;
            if contract.status == ContractStatus::Deployed {
                contract.status = ContractStatus::Warm;
            }
        }
        if let Some(lane_id) = &call.lane_id {
            if let Some(lane) = self.witness_lanes.get_mut(lane_id) {
                lane.assigned_call_ids.remove(call_id);
                lane.last_activity_height = height;
            }
        }
        for coupon in self.gas_coupons.values_mut() {
            if coupon.reserved_call_id.as_deref() == Some(call_id) {
                coupon.status = CouponStatus::Consumed;
            }
        }
        self.counters.calldata_settled += 1;
        Ok(call.clone())
    }

    pub fn file_challenge(
        &mut self,
        kind: ChallengeKind,
        accused_commitment: String,
        challenger_commitment: String,
        subject_id: String,
        evidence_root: String,
        slash_amount_micro_xmr: u64,
        filed_at_height: u64,
    ) -> Result<ChallengeEvidenceRecord> {
        self.ensure_capacity(
            self.challenge_evidence.len(),
            self.config.max_challenges,
            "challenges",
        )?;
        ensure_non_empty(&evidence_root, "evidence root")?;
        let challenge_id = deterministic_id(
            "CHALLENGE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&accused_commitment),
                HashPart::Str(&challenger_commitment),
                HashPart::Str(&subject_id),
                HashPart::Str(&evidence_root),
                HashPart::U64(self.take_nonce()),
            ],
        );
        if let Some(call) = self.calldata_queue.get_mut(&subject_id) {
            call.status = CalldataQueueStatus::Challenged;
        }
        let record = ChallengeEvidenceRecord {
            challenge_id: challenge_id.clone(),
            kind,
            status: ChallengeStatus::Filed,
            accused_commitment,
            challenger_commitment,
            subject_id,
            evidence_root,
            slash_amount_micro_xmr,
            filed_at_height,
            resolved_at_height: None,
        };
        self.challenge_evidence.insert(challenge_id, record.clone());
        self.counters.challenges_filed += 1;
        Ok(record)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        accepted: bool,
        height: u64,
    ) -> Result<ChallengeEvidenceRecord> {
        let challenge = self
            .challenge_evidence
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown challenge {challenge_id}"))?;
        challenge.status = if accepted {
            ChallengeStatus::Slashed
        } else {
            ChallengeStatus::Rejected
        };
        challenge.resolved_at_height = Some(height);
        if accepted {
            self.counters.slashes_executed += 1;
            if let Some(call) = self.calldata_queue.get_mut(&challenge.subject_id) {
                call.status = CalldataQueueStatus::Rejected;
            }
            for contract in self.contracts.values_mut() {
                if contract.owner_commitment == challenge.accused_commitment {
                    contract.status = ContractStatus::Slashed;
                }
            }
        }
        Ok(challenge.clone())
    }

    pub fn expire_old_records(&mut self, height: u64) -> usize {
        let mut expired = 0;
        for call in self.calldata_queue.values_mut() {
            if call.status.live() && call.expires_at_height < height {
                call.status = CalldataQueueStatus::Expired;
                expired += 1;
            }
        }
        for coupon in self.gas_coupons.values_mut() {
            if matches!(coupon.status, CouponStatus::Open | CouponStatus::Reserved)
                && coupon.expires_at_height < height
            {
                coupon.status = CouponStatus::Expired;
                expired += 1;
            }
        }
        for proof in self.recursive_proofs.values_mut() {
            if matches!(
                proof.status,
                ProofAttachmentStatus::Attached | ProofAttachmentStatus::Aggregating
            ) && proof.expires_at_height < height
            {
                proof.status = ProofAttachmentStatus::Rejected;
                expired += 1;
            }
        }
        expired
    }

    pub fn quote_fee(
        &self,
        contract_id: &str,
        gas_limit: u64,
        coupon_id: Option<&str>,
        height: u64,
    ) -> Result<FeeQuote> {
        let contract = self
            .contracts
            .get(contract_id)
            .ok_or_else(|| format!("unknown contract {contract_id}"))?;
        if gas_limit > contract.max_gas_per_call {
            return Err("gas limit exceeds contract maximum".to_string());
        }
        let base_fee = gas_limit.saturating_mul(self.config.base_gas_price_micro_xmr);
        let max_fee = base_fee + (base_fee.saturating_mul(self.config.max_fee_bps) / MAX_BPS);
        let coupon_discount = if let Some(coupon_id) = coupon_id {
            let coupon = self
                .gas_coupons
                .get(coupon_id)
                .ok_or_else(|| format!("unknown coupon {coupon_id}"))?;
            if coupon.status != CouponStatus::Open {
                return Err(format!("coupon {coupon_id} is not open"));
            }
            max_fee.saturating_mul(coupon.discount_bps) / MAX_BPS
        } else {
            0
        };
        let final_fee = max_fee.saturating_sub(coupon_discount);
        let quote_id = deterministic_id(
            "FEE-QUOTE",
            &[
                HashPart::Str(contract_id),
                HashPart::U64(gas_limit),
                HashPart::U64(final_fee),
                HashPart::U64(height),
            ],
        );
        Ok(FeeQuote {
            quote_id,
            contract_id: contract_id.to_string(),
            gas_limit,
            base_fee_micro_xmr: base_fee,
            max_fee_micro_xmr: max_fee,
            coupon_discount_micro_xmr: coupon_discount,
            final_fee_micro_xmr: final_fee,
            fee_bps: self.config.max_fee_bps,
            height,
        })
    }

    pub fn lane_load_summary(&self, lane_id: &str) -> Result<LaneLoadSummary> {
        let lane = self
            .witness_lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown lane {lane_id}"))?;
        let assigned_calls = lane.assigned_call_ids.len();
        Ok(LaneLoadSummary {
            lane_id: lane.lane_id.clone(),
            kind: lane.kind,
            assigned_calls,
            max_parallel_calls: lane.max_parallel_calls,
            spare_parallel_slots: lane
                .max_parallel_calls
                .saturating_sub(assigned_calls as u32),
            priority_weight: lane.kind.priority_weight(),
            target_latency_ms: lane.target_latency_ms,
            last_activity_height: lane.last_activity_height,
        })
    }

    pub fn privacy_health_summary(&self) -> PrivacyHealthSummary {
        let weak_call_count = self
            .calldata_queue
            .values()
            .filter(|call| call.privacy_set_size < self.config.min_privacy_set_size)
            .count();
        let max_leakage_score_bps = self
            .privacy_accounting
            .values()
            .map(|record| record.leakage_score_bps)
            .max()
            .unwrap_or_default();
        PrivacyHealthSummary {
            min_privacy_set_size: self.config.min_privacy_set_size,
            observed_calls: self.calldata_queue.len(),
            weak_call_count,
            max_leakage_score_bps,
            privacy_accounting_root: self.roots_without_recursing().privacy_accounting_root,
            spent_nullifier_count: self.spent_nullifiers.len(),
        }
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        let roots = self.roots();
        let snapshot_id = deterministic_id(
            "RUNTIME-SNAPSHOT",
            &[
                HashPart::Str(&roots.state_root),
                HashPart::U64(self.counters.next_nonce),
            ],
        );
        RuntimeSnapshot {
            snapshot_id,
            protocol_version: PROTOCOL_VERSION.to_string(),
            roots,
            counters: self.counters.clone(),
            live_call_count: self
                .calldata_queue
                .values()
                .filter(|call| call.status.live())
                .count(),
            open_coupon_count: self
                .gas_coupons
                .values()
                .filter(|coupon| coupon.status == CouponStatus::Open)
                .count(),
            active_lane_count: self.witness_lanes.len(),
            pending_challenge_count: self
                .challenge_evidence
                .values()
                .filter(|challenge| {
                    matches!(
                        challenge.status,
                        ChallengeStatus::Filed | ChallengeStatus::UnderReview
                    )
                })
                .count(),
        }
    }

    pub fn public_record_root(&self) -> String {
        record_root("PUBLIC-RECORD", &self.public_record())
    }

    fn roots_without_recursing(&self) -> Roots {
        Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            contracts_root: map_root(
                "CONTRACTS",
                self.contracts.values().map(ContractRecord::public_record),
            ),
            bytecode_root: map_root(
                "BYTECODE",
                self.bytecode_commitments
                    .values()
                    .map(BytecodeCommitmentRecord::public_record),
            ),
            deployment_receipts_root: map_root(
                "DEPLOYMENT-RECEIPTS",
                self.deployment_receipts
                    .values()
                    .map(DeploymentReceipt::public_record),
            ),
            calldata_queue_root: map_root(
                "CALLDATA-QUEUE",
                self.calldata_queue
                    .values()
                    .map(EncryptedCalldataRecord::public_record),
            ),
            witness_lanes_root: map_root(
                "WITNESS-LANES",
                self.witness_lanes
                    .values()
                    .map(WitnessLaneRecord::public_record),
            ),
            gas_coupons_root: map_root(
                "GAS-COUPONS",
                self.gas_coupons
                    .values()
                    .map(GasCouponRecord::public_record),
            ),
            private_events_root: map_root(
                "PRIVATE-EVENTS",
                self.private_events
                    .values()
                    .map(PrivateEventRecord::public_record),
            ),
            recursive_proofs_root: map_root(
                "RECURSIVE-PROOFS",
                self.recursive_proofs
                    .values()
                    .map(RecursiveProofAttachment::public_record),
            ),
            preconfirmation_root: map_root(
                "PRECONFIRMATIONS",
                self.preconfirmations
                    .values()
                    .map(PreconfirmationReceipt::public_record),
            ),
            privacy_accounting_root: map_root(
                "PRIVACY-ACCOUNTING",
                self.privacy_accounting
                    .values()
                    .map(PrivacyAccountingRecord::public_record),
            ),
            challenge_evidence_root: map_root(
                "CHALLENGE-EVIDENCE",
                self.challenge_evidence
                    .values()
                    .map(ChallengeEvidenceRecord::public_record),
            ),
            public_record_root: empty_root("PUBLIC-RECORD-DEFERRED"),
            state_root: empty_root("STATE-DEFERRED"),
        }
    }

    fn take_nonce(&mut self) -> u64 {
        let nonce = self.counters.next_nonce;
        self.counters.next_nonce += 1;
        nonce
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            Err(format!("{label} capacity exhausted"))
        } else {
            Ok(())
        }
    }
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-VM:{domain}"),
        parts,
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    deterministic_id(domain, &[HashPart::Json(record)])
}

pub fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(&format!("PRIVATE-L2-PQ-CONFIDENTIAL-VM:{domain}"), &values)
    }
}

pub fn empty_root(domain: &str) -> String {
    deterministic_id(
        "EMPTY",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(domain)],
    )
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_minimum(value: u64, minimum: u64, label: &str) -> Result<()> {
    if value < minimum {
        Err(format!("{label} below minimum {minimum}"))
    } else {
        Ok(())
    }
}

fn ensure_max_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}
