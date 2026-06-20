use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-precompile-registry-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-precompile-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEVNET_HEIGHT: u64 = 690_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_PRECOMPILES: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_CALLS: usize =
    8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize =
    128;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize =
    512;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_CALL_FEE_BPS: u64 = 20;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    12;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecompileKind {
    HashToScalar,
    RangeProofVerify,
    MembershipProofVerify,
    ConfidentialSwapMath,
    ConfidentialCreditMath,
    PqSignatureVerify,
    PqKemEnvelopeOpen,
    RecursiveProofVerify,
    MoneroViewTagScan,
    MoneroKeyImageCheck,
}

impl PrecompileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashToScalar => "hash_to_scalar",
            Self::RangeProofVerify => "range_proof_verify",
            Self::MembershipProofVerify => "membership_proof_verify",
            Self::ConfidentialSwapMath => "confidential_swap_math",
            Self::ConfidentialCreditMath => "confidential_credit_math",
            Self::PqSignatureVerify => "pq_signature_verify",
            Self::PqKemEnvelopeOpen => "pq_kem_envelope_open",
            Self::RecursiveProofVerify => "recursive_proof_verify",
            Self::MoneroViewTagScan => "monero_view_tag_scan",
            Self::MoneroKeyImageCheck => "monero_key_image_check",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecompileStatus {
    Proposed,
    Active,
    RateLimited,
    Deprecated,
    Paused,
    Slashed,
}

impl PrecompileStatus {
    pub fn callable(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approved,
    NeedsMoreReview,
    Paused,
    Deprecated,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallLane {
    Wallet,
    Dex,
    Lending,
    Perpetuals,
    Bridge,
    Governance,
    Compliance,
    Emergency,
}

impl CallLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::Compliance => "compliance",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Submitted,
    Sponsored,
    Batched,
    Executed,
    Reverted,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Executing,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    PrecompileRegistered,
    AttestationPublished,
    CallSubmitted,
    SponsorReserved,
    BatchBuilt,
    SettlementPublished,
    RebatePublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrecompileRegistered => "precompile_registered",
            Self::AttestationPublished => "attestation_published",
            Self::CallSubmitted => "call_submitted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchBuilt => "batch_built",
            Self::SettlementPublished => "settlement_published",
            Self::RebatePublished => "rebate_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_precompiles: usize,
    pub max_attestations: usize,
    pub max_calls: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub min_pq_security_bits: u16,
    pub max_call_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            max_precompiles:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_PRECOMPILES,
            max_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_calls: PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_CALLS,
            max_reservations:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_call_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_MAX_CALL_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            devnet_height: PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        ensure_positive("max_precompiles", self.max_precompiles)?;
        ensure_positive("max_attestations", self.max_attestations)?;
        ensure_positive("max_calls", self.max_calls)?;
        ensure_positive("max_reservations", self.max_reservations)?;
        ensure_positive("max_batches", self.max_batches)?;
        ensure_positive("max_receipts", self.max_receipts)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must be at least 192".to_string());
        }
        ensure_bps("max_call_fee_bps", self.max_call_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.target_rebate_bps > self.max_call_fee_bps {
            return Err("target_rebate_bps cannot exceed max_call_fee_bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub precompile_counter: u64,
    pub attestation_counter: u64,
    pub call_counter: u64,
    pub reservation_counter: u64,
    pub batch_counter: u64,
    pub receipt_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPrecompileRequest {
    pub maintainer_commitment: String,
    pub precompile_kind: PrecompileKind,
    pub bytecode_commitment_root: String,
    pub interface_abi_root: String,
    pub privacy_policy_root: String,
    pub pq_verifier_key_root: String,
    pub gas_schedule_root: String,
    pub max_call_fee_bps: u64,
    pub min_privacy_set_size: usize,
    pub registration_nonce: String,
}

impl RegisterPrecompileRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
        ensure_non_empty("maintainer_commitment", &self.maintainer_commitment)?;
        ensure_root("bytecode_commitment_root", &self.bytecode_commitment_root)?;
        ensure_root("interface_abi_root", &self.interface_abi_root)?;
        ensure_root("privacy_policy_root", &self.privacy_policy_root)?;
        ensure_root("pq_verifier_key_root", &self.pq_verifier_key_root)?;
        ensure_root("gas_schedule_root", &self.gas_schedule_root)?;
        ensure_non_empty("registration_nonce", &self.registration_nonce)?;
        ensure_bps("max_call_fee_bps", self.max_call_fee_bps)?;
        if self.max_call_fee_bps > config.max_call_fee_bps {
            return Err("max_call_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("min_privacy_set_size below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishPrecompileAttestationRequest {
    pub precompile_id: String,
    pub attester_commitment: String,
    pub verdict: AttestationVerdict,
    pub audit_report_root: String,
    pub side_channel_analysis_root: String,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
    pub attestation_nonce: String,
}

impl PublishPrecompileAttestationRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
        ensure_non_empty("precompile_id", &self.precompile_id)?;
        ensure_non_empty("attester_commitment", &self.attester_commitment)?;
        ensure_root("audit_report_root", &self.audit_report_root)?;
        ensure_root(
            "side_channel_analysis_root",
            &self.side_channel_analysis_root,
        )?;
        ensure_root("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("attestation_nonce", &self.attestation_nonce)?;
        if self.attested_at_height == 0 {
            return Err("attested_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitConfidentialPrecompileCallRequest {
    pub precompile_id: String,
    pub caller_commitment: String,
    pub lane: CallLane,
    pub sealed_input_root: String,
    pub output_commitment_root: String,
    pub nullifier_root: String,
    pub witness_hint_root: String,
    pub pq_call_authorization_root: String,
    pub privacy_set_size: usize,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub call_nonce: String,
}

impl SubmitConfidentialPrecompileCallRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
        ensure_non_empty("precompile_id", &self.precompile_id)?;
        ensure_non_empty("caller_commitment", &self.caller_commitment)?;
        ensure_root("sealed_input_root", &self.sealed_input_root)?;
        ensure_root("output_commitment_root", &self.output_commitment_root)?;
        ensure_root("nullifier_root", &self.nullifier_root)?;
        ensure_root("witness_hint_root", &self.witness_hint_root)?;
        ensure_root(
            "pq_call_authorization_root",
            &self.pq_call_authorization_root,
        )?;
        ensure_non_empty("call_nonce", &self.call_nonce)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy_set_size below runtime minimum".to_string());
        }
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_call_fee_bps {
            return Err("max_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.expires_at_height == 0 {
            return Err("expires_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservePrecompileSponsorRequest {
    pub precompile_id: String,
    pub call_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_commitment_root: String,
    pub rebate_policy_root: String,
    pub pq_sponsor_authorization_root: String,
    pub reserved_fee_bps: u64,
    pub reserved_until_height: u64,
    pub reservation_nonce: String,
}

impl ReservePrecompileSponsorRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
        ensure_non_empty("precompile_id", &self.precompile_id)?;
        if self.call_ids.is_empty() {
            return Err("call_ids cannot be empty".to_string());
        }
        ensure_unique("call_ids", &self.call_ids)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_root("budget_commitment_root", &self.budget_commitment_root)?;
        ensure_root("rebate_policy_root", &self.rebate_policy_root)?;
        ensure_root(
            "pq_sponsor_authorization_root",
            &self.pq_sponsor_authorization_root,
        )?;
        ensure_non_empty("reservation_nonce", &self.reservation_nonce)?;
        ensure_bps("reserved_fee_bps", self.reserved_fee_bps)?;
        if self.reserved_fee_bps > config.max_call_fee_bps {
            return Err("reserved_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.reserved_until_height == 0 {
            return Err("reserved_until_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildPrecompileExecutionBatchRequest {
    pub precompile_ids: Vec<String>,
    pub call_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub executor_commitment: String,
    pub sealed_execution_trace_root: String,
    pub output_batch_root: String,
    pub recursive_proof_root: String,
    pub batch_privacy_set_size: usize,
    pub total_fee_bps: u64,
    pub built_at_height: u64,
    pub batch_nonce: String,
}

impl BuildPrecompileExecutionBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
        if self.precompile_ids.is_empty() {
            return Err("precompile_ids cannot be empty".to_string());
        }
        if self.call_ids.is_empty() {
            return Err("call_ids cannot be empty".to_string());
        }
        ensure_unique("precompile_ids", &self.precompile_ids)?;
        ensure_unique("call_ids", &self.call_ids)?;
        ensure_unique("reservation_ids", &self.reservation_ids)?;
        ensure_non_empty("executor_commitment", &self.executor_commitment)?;
        ensure_root(
            "sealed_execution_trace_root",
            &self.sealed_execution_trace_root,
        )?;
        ensure_root("output_batch_root", &self.output_batch_root)?;
        ensure_root("recursive_proof_root", &self.recursive_proof_root)?;
        ensure_non_empty("batch_nonce", &self.batch_nonce)?;
        if self.batch_privacy_set_size < config.batch_privacy_set_size {
            return Err("batch_privacy_set_size below runtime batch target".to_string());
        }
        ensure_bps("total_fee_bps", self.total_fee_bps)?;
        if self.total_fee_bps > config.max_call_fee_bps {
            return Err("total_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.built_at_height == 0 {
            return Err("built_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishPrecompileReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: ReceiptKind,
    pub batch_id: Option<String>,
    pub settlement_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub pq_receipt_signature_root: String,
    pub emitted_at_height: u64,
    pub receipt_nonce: String,
}

impl PublishPrecompileReceiptRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
        ensure_non_empty("subject_id", &self.subject_id)?;
        if let Some(batch_id) = &self.batch_id {
            ensure_non_empty("batch_id", batch_id)?;
        }
        ensure_root("settlement_root", &self.settlement_root)?;
        ensure_root("state_root_before", &self.state_root_before)?;
        ensure_root("state_root_after", &self.state_root_after)?;
        ensure_root("pq_receipt_signature_root", &self.pq_receipt_signature_root)?;
        ensure_non_empty("receipt_nonce", &self.receipt_nonce)?;
        if self.emitted_at_height == 0 {
            return Err("emitted_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrecompileRecord {
    pub precompile_id: String,
    pub request: RegisterPrecompileRequest,
    pub status: PrecompileStatus,
    pub precompile_root: String,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
}

impl PrecompileRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "precompile_id": self.precompile_id,
            "maintainer_commitment": self.request.maintainer_commitment,
            "precompile_kind": self.request.precompile_kind,
            "bytecode_commitment_root": self.request.bytecode_commitment_root,
            "interface_abi_root": self.request.interface_abi_root,
            "privacy_policy_root": self.request.privacy_policy_root,
            "pq_verifier_key_root": self.request.pq_verifier_key_root,
            "gas_schedule_root": self.request.gas_schedule_root,
            "max_call_fee_bps": self.request.max_call_fee_bps,
            "min_privacy_set_size": self.request.min_privacy_set_size,
            "status": self.status,
            "precompile_root": self.precompile_root,
            "registered_at_height": self.registered_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrecompileAttestationRecord {
    pub attestation_id: String,
    pub request: PublishPrecompileAttestationRequest,
    pub attestation_root: String,
}

impl PrecompileAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "precompile_id": self.request.precompile_id,
            "attester_commitment": self.request.attester_commitment,
            "verdict": self.request.verdict,
            "audit_report_root": self.request.audit_report_root,
            "side_channel_analysis_root": self.request.side_channel_analysis_root,
            "pq_signature_root": self.request.pq_signature_root,
            "attested_at_height": self.request.attested_at_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialPrecompileCallRecord {
    pub call_id: String,
    pub request: SubmitConfidentialPrecompileCallRequest,
    pub status: CallStatus,
    pub call_root: String,
    pub submitted_at_height: u64,
}

impl ConfidentialPrecompileCallRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "precompile_id": self.request.precompile_id,
            "caller_commitment": self.request.caller_commitment,
            "lane": self.request.lane,
            "sealed_input_root": self.request.sealed_input_root,
            "output_commitment_root": self.request.output_commitment_root,
            "nullifier_root": self.request.nullifier_root,
            "witness_hint_root": self.request.witness_hint_root,
            "pq_call_authorization_root": self.request.pq_call_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "max_fee_bps": self.request.max_fee_bps,
            "expires_at_height": self.request.expires_at_height,
            "status": self.status,
            "call_root": self.call_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrecompileSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReservePrecompileSponsorRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
    pub reserved_at_height: u64,
}

impl PrecompileSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "precompile_id": self.request.precompile_id,
            "call_ids": self.request.call_ids,
            "sponsor_commitment": self.request.sponsor_commitment,
            "fee_asset_id": self.request.fee_asset_id,
            "budget_commitment_root": self.request.budget_commitment_root,
            "rebate_policy_root": self.request.rebate_policy_root,
            "pq_sponsor_authorization_root": self.request.pq_sponsor_authorization_root,
            "reserved_fee_bps": self.request.reserved_fee_bps,
            "reserved_until_height": self.request.reserved_until_height,
            "status": self.status,
            "reservation_root": self.reservation_root,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrecompileExecutionBatchRecord {
    pub batch_id: String,
    pub request: BuildPrecompileExecutionBatchRequest,
    pub status: BatchStatus,
    pub batch_root: String,
    pub state_root_after: String,
}

impl PrecompileExecutionBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "precompile_ids": self.request.precompile_ids,
            "call_ids": self.request.call_ids,
            "reservation_ids": self.request.reservation_ids,
            "executor_commitment": self.request.executor_commitment,
            "sealed_execution_trace_root": self.request.sealed_execution_trace_root,
            "output_batch_root": self.request.output_batch_root,
            "recursive_proof_root": self.request.recursive_proof_root,
            "batch_privacy_set_size": self.request.batch_privacy_set_size,
            "total_fee_bps": self.request.total_fee_bps,
            "built_at_height": self.request.built_at_height,
            "status": self.status,
            "batch_root": self.batch_root,
            "state_root_after": self.state_root_after,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrecompileReceiptRecord {
    pub receipt_id: String,
    pub request: PublishPrecompileReceiptRequest,
    pub receipt_root: String,
}

impl PrecompileReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.request.subject_id,
            "receipt_kind": self.request.receipt_kind,
            "batch_id": self.request.batch_id,
            "settlement_root": self.request.settlement_root,
            "state_root_before": self.request.state_root_before,
            "state_root_after": self.request.state_root_after,
            "pq_receipt_signature_root": self.request.pq_receipt_signature_root,
            "emitted_at_height": self.request.emitted_at_height,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub precompile_root: String,
    pub attestation_root: String,
    pub call_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub precompiles: BTreeMap<String, PrecompileRecord>,
    pub attestations: BTreeMap<String, PrecompileAttestationRecord>,
    pub calls: BTreeMap<String, ConfidentialPrecompileCallRecord>,
    pub reservations: BTreeMap<String, PrecompileSponsorReservationRecord>,
    pub batches: BTreeMap<String, PrecompileExecutionBatchRecord>,
    pub receipts: BTreeMap<String, PrecompileReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            precompiles: BTreeMap::new(),
            attestations: BTreeMap::new(),
            calls: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_precompile(
        &mut self,
        request: RegisterPrecompileRequest,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<PrecompileRecord> {
        request.validate(&self.config)?;
        if self.precompiles.len() >= self.config.max_precompiles {
            return Err("precompile registry capacity exhausted".to_string());
        }
        self.counters.precompile_counter = self.counters.precompile_counter.saturating_add(1);
        let precompile_id = precompile_id(&request, self.counters.precompile_counter);
        let precompile_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-PRECOMPILE",
            &request.public_record(),
        );
        let record = PrecompileRecord {
            precompile_id: precompile_id.clone(),
            request,
            status: PrecompileStatus::Proposed,
            precompile_root,
            registered_at_height: self.config.devnet_height,
            updated_at_height: self.config.devnet_height,
        };
        self.precompiles.insert(precompile_id, record.clone());
        Ok(record)
    }

    pub fn publish_attestation(
        &mut self,
        request: PublishPrecompileAttestationRequest,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<PrecompileAttestationRecord> {
        request.validate()?;
        if self.attestations.len() >= self.config.max_attestations {
            return Err("precompile attestation capacity exhausted".to_string());
        }
        self.require_precompile(&request.precompile_id)?;
        self.counters.attestation_counter = self.counters.attestation_counter.saturating_add(1);
        let attestation_id = precompile_attestation_id(&request, self.counters.attestation_counter);
        let attestation_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-ATTESTATION",
            &request.public_record(),
        );
        let verdict = request.verdict;
        let precompile_id_value = request.precompile_id.clone();
        let record = PrecompileAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            attestation_root,
        };
        self.attestations.insert(attestation_id, record.clone());
        if let Some(precompile) = self.precompiles.get_mut(&precompile_id_value) {
            precompile.status = match verdict {
                AttestationVerdict::Approved => PrecompileStatus::Active,
                AttestationVerdict::NeedsMoreReview => PrecompileStatus::Proposed,
                AttestationVerdict::Paused => PrecompileStatus::Paused,
                AttestationVerdict::Deprecated => PrecompileStatus::Deprecated,
                AttestationVerdict::Slashed => PrecompileStatus::Slashed,
            };
            precompile.updated_at_height = self.config.devnet_height;
        }
        Ok(record)
    }

    pub fn submit_confidential_call(
        &mut self,
        request: SubmitConfidentialPrecompileCallRequest,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<ConfidentialPrecompileCallRecord>
    {
        request.validate(&self.config)?;
        if self.calls.len() >= self.config.max_calls {
            return Err("confidential precompile call capacity exhausted".to_string());
        }
        let precompile = self.require_precompile(&request.precompile_id)?;
        if !precompile.status.callable() {
            return Err(format!(
                "precompile {} is not callable",
                request.precompile_id
            ));
        }
        if self.consumed_nullifiers.contains(&request.nullifier_root) {
            return Err("precompile call nullifier replay detected".to_string());
        }
        self.counters.call_counter = self.counters.call_counter.saturating_add(1);
        let call_id = confidential_precompile_call_id(&request, self.counters.call_counter);
        let call_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-CALL",
            &request.public_record(),
        );
        let record = ConfidentialPrecompileCallRecord {
            call_id: call_id.clone(),
            request: request.clone(),
            status: CallStatus::Submitted,
            call_root,
            submitted_at_height: self.config.devnet_height,
        };
        self.consumed_nullifiers
            .insert(request.nullifier_root.clone());
        self.calls.insert(call_id, record.clone());
        Ok(record)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReservePrecompileSponsorRequest,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<PrecompileSponsorReservationRecord>
    {
        request.validate(&self.config)?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("precompile sponsor reservation capacity exhausted".to_string());
        }
        self.require_precompile(&request.precompile_id)?;
        for call_id in &request.call_ids {
            let call = self.require_call(call_id)?;
            if call.request.precompile_id != request.precompile_id {
                return Err(format!("call {call_id} belongs to another precompile"));
            }
            if call.status != CallStatus::Submitted {
                return Err(format!("call {call_id} is not sponsorable"));
            }
        }
        self.counters.reservation_counter = self.counters.reservation_counter.saturating_add(1);
        let reservation_id =
            precompile_sponsor_reservation_id(&request, self.counters.reservation_counter);
        let reservation_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-SPONSOR",
            &request.public_record(),
        );
        let record = PrecompileSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request: request.clone(),
            status: ReservationStatus::Reserved,
            reservation_root,
            reserved_at_height: self.config.devnet_height,
        };
        for call_id in &request.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = CallStatus::Sponsored;
            }
        }
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_execution_batch(
        &mut self,
        request: BuildPrecompileExecutionBatchRequest,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<PrecompileExecutionBatchRecord>
    {
        request.validate(&self.config)?;
        if self.batches.len() >= self.config.max_batches {
            return Err("precompile execution batch capacity exhausted".to_string());
        }
        for precompile_id in &request.precompile_ids {
            self.require_precompile(precompile_id)?;
        }
        for call_id in &request.call_ids {
            self.require_call(call_id)?;
        }
        for reservation_id in &request.reservation_ids {
            self.require_reservation(reservation_id)?;
        }
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        let batch_id = precompile_execution_batch_id(&request, self.counters.batch_counter);
        let batch_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-BATCH",
            &request.public_record(),
        );
        for call_id in &request.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = CallStatus::Batched;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let state_root_after = state_root_from_record(&json!({
            "batch_root": batch_root,
            "previous_state_root": self.state_root(),
            "batch_counter": self.counters.batch_counter,
        }));
        let record = PrecompileExecutionBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: BatchStatus::Proposed,
            batch_root,
            state_root_after,
        };
        self.batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishPrecompileReceiptRequest,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<PrecompileReceiptRecord> {
        request.validate()?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("precompile receipt capacity exhausted".to_string());
        }
        if let Some(batch_id) = &request.batch_id {
            self.require_batch(batch_id)?;
        }
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let receipt_id = precompile_receipt_id(&request, self.counters.receipt_counter);
        let receipt_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-RECEIPT",
            &request.public_record(),
        );
        let record = PrecompileReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            receipt_root,
        };
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let precompile_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-PRECOMPILES",
            &self
                .precompiles
                .values()
                .map(PrecompileRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-ATTESTATIONS",
            &self
                .attestations
                .values()
                .map(PrecompileAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let call_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-CALLS",
            &self
                .calls
                .values()
                .map(ConfidentialPrecompileCallRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(PrecompileSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-BATCHES",
            &self
                .batches
                .values()
                .map(PrecompileExecutionBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-RECEIPTS",
            &self
                .receipts
                .values()
                .map(PrecompileReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "precompile_root": precompile_root,
            "attestation_root": attestation_root,
            "call_root": call_root,
            "reservation_root": reservation_root,
            "batch_root": batch_root,
            "receipt_root": receipt_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            precompile_root,
            attestation_root,
            call_root,
            reservation_root,
            batch_root,
            receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_precompile(
        &self,
        precompile_id: &str,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<&PrecompileRecord> {
        self.precompiles
            .get(precompile_id)
            .ok_or_else(|| format!("unknown confidential precompile {precompile_id}"))
    }

    fn require_call(
        &self,
        call_id: &str,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<&ConfidentialPrecompileCallRecord>
    {
        self.calls
            .get(call_id)
            .ok_or_else(|| format!("unknown confidential precompile call {call_id}"))
    }

    fn require_reservation(
        &self,
        reservation_id: &str,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<&PrecompileSponsorReservationRecord>
    {
        self.reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown precompile sponsor reservation {reservation_id}"))
    }

    fn require_batch(
        &self,
        batch_id: &str,
    ) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<&PrecompileExecutionBatchRecord>
    {
        self.batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown precompile execution batch {batch_id}"))
    }
}

pub type Runtime = State;

pub fn precompile_id(request: &RegisterPrecompileRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-PRECOMPILE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.maintainer_commitment),
            HashPart::Str(request.precompile_kind.as_str()),
            HashPart::Str(&request.bytecode_commitment_root),
            HashPart::Str(&request.registration_nonce),
        ],
        32,
    )
}

pub fn precompile_attestation_id(
    request: &PublishPrecompileAttestationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.precompile_id),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(&request.audit_report_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn confidential_precompile_call_id(
    request: &SubmitConfidentialPrecompileCallRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.precompile_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.caller_commitment),
            HashPart::Str(&request.sealed_input_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.call_nonce),
        ],
        32,
    )
}

pub fn precompile_sponsor_reservation_id(
    request: &ReservePrecompileSponsorRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.precompile_id),
            HashPart::Str(&id_list_root("calls", &request.call_ids)),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.budget_commitment_root),
            HashPart::Str(&request.reservation_nonce),
        ],
        32,
    )
}

pub fn precompile_execution_batch_id(
    request: &BuildPrecompileExecutionBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("precompiles", &request.precompile_ids)),
            HashPart::Str(&id_list_root("calls", &request.call_ids)),
            HashPart::Str(&request.executor_commitment),
            HashPart::Str(&request.sealed_execution_trace_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn precompile_receipt_id(request: &PublishPrecompileReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.receipt_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-STATE",
        record,
    )
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-PRECOMPILE-REGISTRY-ID-LIST-{domain}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_root(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
    ensure_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn ensure_positive(
    field: &str,
    value: usize,
) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(
    field: &str,
    value: u64,
) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_PRECOMPILE_REGISTRY_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_unique(
    field: &str,
    values: &[String],
) -> PrivateL2PqConfidentialPrecompileRegistryRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}
