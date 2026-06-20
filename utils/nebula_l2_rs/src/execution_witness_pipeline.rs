use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ExecutionWitnessResult<T> = Result<T, String>;

pub const EXECUTION_WITNESS_PROTOCOL_VERSION: &str = "nebula-execution-witness-pipeline-v1";
pub const EXECUTION_WITNESS_COMMITMENT_SCHEME: &str = "shake256-execution-witness-commitment-v1";
pub const EXECUTION_WITNESS_TRACE_SCHEME: &str = "canonical-json-redacted-trace-v1";
pub const EXECUTION_WITNESS_RECURSION_SCHEME: &str = "nebula-recursive-proof-input-v1";
pub const EXECUTION_WITNESS_PQ_ATTESTATION_SCHEME: &str = "ml-dsa-65-witness-attestation-v1";
pub const EXECUTION_WITNESS_DISCLOSURE_SCHEME: &str = "zk-selective-witness-disclosure-v1";
pub const EXECUTION_WITNESS_DEFAULT_TRACE_TTL_BLOCKS: u64 = 144;
pub const EXECUTION_WITNESS_DEFAULT_PACKAGE_TTL_BLOCKS: u64 = 96;
pub const EXECUTION_WITNESS_DEFAULT_ASSIGNMENT_TTL_BLOCKS: u64 = 24;
pub const EXECUTION_WITNESS_DEFAULT_MAX_TRACE_STEPS: u64 = 25_000;
pub const EXECUTION_WITNESS_DEFAULT_MAX_PUBLIC_INPUTS: u64 = 512;
pub const EXECUTION_WITNESS_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_000;
pub const EXECUTION_WITNESS_DEFAULT_SECURITY_BITS: u16 = 128;
pub const EXECUTION_WITNESS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessDomain {
    PrivateTransfer,
    ContractCall,
    DefiSwap,
    MoneroBridge,
    FeeRebate,
    ProofAggregation,
    Governance,
    EmergencyExit,
}

impl WitnessDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::MoneroBridge => "monero_bridge",
            Self::FeeRebate => "fee_rebate",
            Self::ProofAggregation => "proof_aggregation",
            Self::Governance => "governance",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::MoneroBridge => 95,
            Self::FeeRebate => 85,
            Self::PrivateTransfer => 80,
            Self::DefiSwap => 75,
            Self::ContractCall => 70,
            Self::ProofAggregation => 65,
            Self::Governance => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessPrivacyMode {
    FullyShielded,
    PublicInputsOnly,
    AggregateOnly,
    RegulatedDisclosure,
    EmergencyOpen,
}

impl WitnessPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::PublicInputsOnly => "public_inputs_only",
            Self::AggregateOnly => "aggregate_only",
            Self::RegulatedDisclosure => "regulated_disclosure",
            Self::EmergencyOpen => "emergency_open",
        }
    }

    pub fn disclosure_weight_bps(self) -> u64 {
        match self {
            Self::FullyShielded => 0,
            Self::AggregateOnly => 250,
            Self::PublicInputsOnly => 600,
            Self::RegulatedDisclosure => 900,
            Self::EmergencyOpen => EXECUTION_WITNESS_MAX_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    Open,
    Sealed,
    Packaged,
    Proved,
    Disputed,
    Expired,
}

impl TraceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Packaged => "packaged",
            Self::Proved => "proved",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Sealed | Self::Packaged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessPackageStatus {
    Assembling,
    ReadyForProver,
    Assigned,
    Proved,
    Rejected,
    Expired,
}

impl WitnessPackageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assembling => "assembling",
            Self::ReadyForProver => "ready_for_prover",
            Self::Assigned => "assigned",
            Self::Proved => "proved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Assembling | Self::ReadyForProver | Self::Assigned
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofInputStatus {
    Draft,
    Ready,
    Submitted,
    Accepted,
    Rejected,
    Deprecated,
}

impl ProofInputStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Ready => "ready",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Deprecated => "deprecated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessDisclosureScope {
    None,
    PublicInputs,
    FeeSummary,
    StateDiffSummary,
    ComplianceView,
    EmergencyView,
}

impl WitnessDisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PublicInputs => "public_inputs",
            Self::FeeSummary => "fee_summary",
            Self::StateDiffSummary => "state_diff_summary",
            Self::ComplianceView => "compliance_view",
            Self::EmergencyView => "emergency_view",
        }
    }

    pub fn disclosure_bps(self) -> u64 {
        match self {
            Self::None => 0,
            Self::PublicInputs => 200,
            Self::FeeSummary => 300,
            Self::StateDiffSummary => 500,
            Self::ComplianceView => 900,
            Self::EmergencyView => EXECUTION_WITNESS_MAX_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverAssignmentStatus {
    Offered,
    Accepted,
    Proving,
    Submitted,
    Slashed,
    Expired,
}

impl ProverAssignmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Proving => "proving",
            Self::Submitted => "submitted",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Offered | Self::Accepted | Self::Proving)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessAttestationSubject {
    TraceSegment,
    WitnessPackage,
    ProofInputManifest,
    ProverAssignment,
    DisclosureReceipt,
    CircuitCompatibility,
}

impl WitnessAttestationSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TraceSegment => "trace_segment",
            Self::WitnessPackage => "witness_package",
            Self::ProofInputManifest => "proof_input_manifest",
            Self::ProverAssignment => "prover_assignment",
            Self::DisclosureReceipt => "disclosure_receipt",
            Self::CircuitCompatibility => "circuit_compatibility",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessAttestationStatus {
    Valid,
    ThresholdValid,
    Superseded,
    Revoked,
    Expired,
}

impl WitnessAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ThresholdValid => "threshold_valid",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Valid | Self::ThresholdValid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWitnessConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub trace_ttl_blocks: u64,
    pub package_ttl_blocks: u64,
    pub assignment_ttl_blocks: u64,
    pub max_trace_steps: u64,
    pub max_public_inputs: u64,
    pub max_disclosure_bps: u64,
    pub default_security_bits: u16,
    pub commitment_scheme: String,
    pub trace_scheme: String,
    pub recursion_scheme: String,
    pub pq_attestation_scheme: String,
    pub disclosure_scheme: String,
}

impl ExecutionWitnessConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: EXECUTION_WITNESS_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            trace_ttl_blocks: EXECUTION_WITNESS_DEFAULT_TRACE_TTL_BLOCKS,
            package_ttl_blocks: EXECUTION_WITNESS_DEFAULT_PACKAGE_TTL_BLOCKS,
            assignment_ttl_blocks: EXECUTION_WITNESS_DEFAULT_ASSIGNMENT_TTL_BLOCKS,
            max_trace_steps: EXECUTION_WITNESS_DEFAULT_MAX_TRACE_STEPS,
            max_public_inputs: EXECUTION_WITNESS_DEFAULT_MAX_PUBLIC_INPUTS,
            max_disclosure_bps: EXECUTION_WITNESS_DEFAULT_MAX_DISCLOSURE_BPS,
            default_security_bits: EXECUTION_WITNESS_DEFAULT_SECURITY_BITS,
            commitment_scheme: EXECUTION_WITNESS_COMMITMENT_SCHEME.to_string(),
            trace_scheme: EXECUTION_WITNESS_TRACE_SCHEME.to_string(),
            recursion_scheme: EXECUTION_WITNESS_RECURSION_SCHEME.to_string(),
            pq_attestation_scheme: EXECUTION_WITNESS_PQ_ATTESTATION_SCHEME.to_string(),
            disclosure_scheme: EXECUTION_WITNESS_DISCLOSURE_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_witness_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "trace_ttl_blocks": self.trace_ttl_blocks,
            "package_ttl_blocks": self.package_ttl_blocks,
            "assignment_ttl_blocks": self.assignment_ttl_blocks,
            "max_trace_steps": self.max_trace_steps,
            "max_public_inputs": self.max_public_inputs,
            "max_disclosure_bps": self.max_disclosure_bps,
            "default_security_bits": self.default_security_bits,
            "commitment_scheme": self.commitment_scheme,
            "trace_scheme": self.trace_scheme,
            "recursion_scheme": self.recursion_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "disclosure_scheme": self.disclosure_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        execution_witness_payload_root("EXECUTION-WITNESS-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        ensure_eq(
            "execution witness protocol version",
            &self.protocol_version,
            EXECUTION_WITNESS_PROTOCOL_VERSION,
        )?;
        ensure_eq("execution witness chain id", &self.chain_id, CHAIN_ID)?;
        ensure_positive("trace ttl blocks", self.trace_ttl_blocks)?;
        ensure_positive("package ttl blocks", self.package_ttl_blocks)?;
        ensure_positive("assignment ttl blocks", self.assignment_ttl_blocks)?;
        ensure_positive("max trace steps", self.max_trace_steps)?;
        ensure_positive("max public inputs", self.max_public_inputs)?;
        ensure_bps("max disclosure bps", self.max_disclosure_bps)?;
        if self.default_security_bits < 128 {
            return Err("execution witness security bits below 128".to_string());
        }
        ensure_eq(
            "execution witness commitment scheme",
            &self.commitment_scheme,
            EXECUTION_WITNESS_COMMITMENT_SCHEME,
        )?;
        ensure_eq(
            "execution witness trace scheme",
            &self.trace_scheme,
            EXECUTION_WITNESS_TRACE_SCHEME,
        )?;
        ensure_eq(
            "execution witness recursion scheme",
            &self.recursion_scheme,
            EXECUTION_WITNESS_RECURSION_SCHEME,
        )?;
        ensure_eq(
            "execution witness pq attestation scheme",
            &self.pq_attestation_scheme,
            EXECUTION_WITNESS_PQ_ATTESTATION_SCHEME,
        )?;
        ensure_eq(
            "execution witness disclosure scheme",
            &self.disclosure_scheme,
            EXECUTION_WITNESS_DISCLOSURE_SCHEME,
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTraceSegment {
    pub segment_id: String,
    pub domain: WitnessDomain,
    pub source_id: String,
    pub lane_id: String,
    pub sequence: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub status: TraceStatus,
    pub privacy_mode: WitnessPrivacyMode,
    pub public_input_root: String,
    pub private_witness_commitment: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub fee_commitment_root: String,
    pub step_count: u64,
    pub fuel_used: u64,
    pub payload_bytes: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ExecutionTraceSegment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: WitnessDomain,
        source_id: &str,
        lane_id: &str,
        sequence: u64,
        height_window: (u64, u64),
        privacy_mode: WitnessPrivacyMode,
        public_inputs: &Value,
        private_witness_label: &str,
        state_reads: &[String],
        state_writes: &[String],
        nullifiers: &[String],
        events: &[String],
        fee_commitments: &[String],
        step_count: u64,
        fuel_used: u64,
        payload_bytes: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> ExecutionWitnessResult<Self> {
        ensure_non_empty("trace source id", source_id)?;
        ensure_non_empty("trace lane id", lane_id)?;
        ensure_non_empty("private witness label", private_witness_label)?;
        ensure_height_window(height_window.0, height_window.1, "trace segment")?;
        ensure_positive("trace step count", step_count)?;
        ensure_positive("trace payload bytes", payload_bytes)?;
        ensure_positive("trace ttl blocks", ttl_blocks)?;
        let public_input_root = execution_witness_payload_root("TRACE-PUBLIC-INPUT", public_inputs);
        let private_witness_commitment =
            execution_witness_commitment("TRACE-PRIVATE-WITNESS", private_witness_label, sequence);
        let state_read_root = execution_witness_string_set_root("TRACE-STATE-READ", state_reads);
        let state_write_root = execution_witness_string_set_root("TRACE-STATE-WRITE", state_writes);
        let nullifier_root = execution_witness_string_set_root("TRACE-NULLIFIER", nullifiers);
        let event_root = execution_witness_string_set_root("TRACE-EVENT", events);
        let fee_commitment_root =
            execution_witness_string_set_root("TRACE-FEE-COMMITMENT", fee_commitments);
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let segment_id = execution_trace_segment_id(
            domain,
            source_id,
            lane_id,
            sequence,
            &private_witness_commitment,
        );
        Ok(Self {
            segment_id,
            domain,
            source_id: source_id.to_string(),
            lane_id: lane_id.to_string(),
            sequence,
            start_height: height_window.0,
            end_height: height_window.1,
            status: TraceStatus::Open,
            privacy_mode,
            public_input_root,
            private_witness_commitment,
            state_read_root,
            state_write_root,
            nullifier_root,
            event_root,
            fee_commitment_root,
            step_count,
            fuel_used,
            payload_bytes,
            created_at_height,
            expires_at_height,
        })
    }

    pub fn seal(&mut self) {
        if self.status == TraceStatus::Open {
            self.status = TraceStatus::Sealed;
        }
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height && self.status.active()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_trace_segment",
            "chain_id": CHAIN_ID,
            "segment_id": self.segment_id,
            "domain": self.domain.as_str(),
            "source_id": self.source_id,
            "lane_id": self.lane_id,
            "sequence": self.sequence,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "status": self.status.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "public_input_root": self.public_input_root,
            "private_witness_commitment": self.private_witness_commitment,
            "state_read_root": self.state_read_root,
            "state_write_root": self.state_write_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "fee_commitment_root": self.fee_commitment_root,
            "step_count": self.step_count,
            "fuel_used": self.fuel_used,
            "payload_bytes": self.payload_bytes,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn segment_root(&self) -> String {
        execution_witness_payload_root("EXECUTION-TRACE-SEGMENT", &self.public_record())
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        ensure_non_empty("trace segment id", &self.segment_id)?;
        ensure_non_empty("trace source id", &self.source_id)?;
        ensure_non_empty("trace lane id", &self.lane_id)?;
        ensure_height_window(self.start_height, self.end_height, "trace segment")?;
        ensure_non_empty("trace public input root", &self.public_input_root)?;
        ensure_non_empty(
            "trace private witness commitment",
            &self.private_witness_commitment,
        )?;
        ensure_positive("trace step count", self.step_count)?;
        ensure_positive("trace payload bytes", self.payload_bytes)?;
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "trace segment ttl",
        )?;
        let expected = execution_trace_segment_id(
            self.domain,
            &self.source_id,
            &self.lane_id,
            self.sequence,
            &self.private_witness_commitment,
        );
        if self.segment_id != expected {
            return Err("trace segment id mismatch".to_string());
        }
        Ok(self.segment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPackage {
    pub package_id: String,
    pub package_label: String,
    pub domain: WitnessDomain,
    pub segment_ids: Vec<String>,
    pub aggregate_trace_root: String,
    pub public_input_root: String,
    pub recursive_input_root: String,
    pub prover_hint_root: String,
    pub package_status: WitnessPackageStatus,
    pub privacy_mode: WitnessPrivacyMode,
    pub priority: u64,
    pub estimated_proof_bytes: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl WitnessPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_label: &str,
        domain: WitnessDomain,
        segments: &[ExecutionTraceSegment],
        privacy_mode: WitnessPrivacyMode,
        priority: u64,
        prover_hint: &Value,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> ExecutionWitnessResult<Self> {
        ensure_non_empty("witness package label", package_label)?;
        ensure_positive("witness package ttl blocks", ttl_blocks)?;
        if segments.is_empty() {
            return Err("witness package requires at least one segment".to_string());
        }
        let mut segment_ids = Vec::new();
        let mut public_input_roots = Vec::new();
        let mut estimated_proof_bytes = 0_u64;
        for segment in segments {
            if segment.domain != domain {
                return Err("witness package segment domain mismatch".to_string());
            }
            if !matches!(segment.status, TraceStatus::Sealed | TraceStatus::Packaged) {
                return Err("witness package requires sealed segments".to_string());
            }
            segment_ids.push(segment.segment_id.clone());
            public_input_roots.push(segment.public_input_root.clone());
            estimated_proof_bytes =
                estimated_proof_bytes.saturating_add(1024 + segment.payload_bytes / 2);
        }
        ensure_unique_strings(&segment_ids, "witness package segment ids")?;
        let aggregate_trace_root = execution_witness_trace_segment_set_root(segments);
        let public_input_root =
            execution_witness_string_set_root("WITNESS-PACKAGE-PUBLIC-INPUTS", &public_input_roots);
        let recursive_input_root = execution_witness_payload_root(
            "WITNESS-PACKAGE-RECURSIVE-INPUT",
            &json!({
                "domain": domain.as_str(),
                "segment_ids": segment_ids,
                "aggregate_trace_root": aggregate_trace_root,
                "public_input_root": public_input_root,
            }),
        );
        let prover_hint_root = execution_witness_payload_root("WITNESS-PROVER-HINT", prover_hint);
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let package_id = execution_witness_package_id(
            package_label,
            domain,
            &aggregate_trace_root,
            created_at_height,
        );
        Ok(Self {
            package_id,
            package_label: package_label.to_string(),
            domain,
            segment_ids,
            aggregate_trace_root,
            public_input_root,
            recursive_input_root,
            prover_hint_root,
            package_status: WitnessPackageStatus::ReadyForProver,
            privacy_mode,
            priority,
            estimated_proof_bytes,
            created_at_height,
            expires_at_height,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height && self.package_status.active()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_package",
            "chain_id": CHAIN_ID,
            "package_id": self.package_id,
            "package_label": self.package_label,
            "domain": self.domain.as_str(),
            "segment_ids": self.segment_ids,
            "aggregate_trace_root": self.aggregate_trace_root,
            "public_input_root": self.public_input_root,
            "recursive_input_root": self.recursive_input_root,
            "prover_hint_root": self.prover_hint_root,
            "package_status": self.package_status.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "priority": self.priority,
            "estimated_proof_bytes": self.estimated_proof_bytes,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn package_root(&self) -> String {
        execution_witness_payload_root("WITNESS-PACKAGE", &self.public_record())
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        ensure_non_empty("witness package id", &self.package_id)?;
        ensure_non_empty("witness package label", &self.package_label)?;
        if self.segment_ids.is_empty() {
            return Err("witness package has no segments".to_string());
        }
        ensure_unique_strings(&self.segment_ids, "witness package segment ids")?;
        ensure_non_empty("witness aggregate trace root", &self.aggregate_trace_root)?;
        ensure_non_empty("witness public input root", &self.public_input_root)?;
        ensure_non_empty("witness recursive input root", &self.recursive_input_root)?;
        ensure_non_empty("witness prover hint root", &self.prover_hint_root)?;
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "witness package ttl",
        )?;
        let expected = execution_witness_package_id(
            &self.package_label,
            self.domain,
            &self.aggregate_trace_root,
            self.created_at_height,
        );
        if self.package_id != expected {
            return Err("witness package id mismatch".to_string());
        }
        Ok(self.package_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInputManifest {
    pub manifest_id: String,
    pub package_id: String,
    pub circuit_family: String,
    pub verifier_key_root: String,
    pub public_input_root: String,
    pub witness_commitment_root: String,
    pub compatibility_root: String,
    pub max_recursion_depth: u64,
    pub security_bits: u16,
    pub status: ProofInputStatus,
}

impl ProofInputManifest {
    pub fn new(
        package: &WitnessPackage,
        circuit_family: &str,
        verifier_key_label: &str,
        max_recursion_depth: u64,
        security_bits: u16,
        compatibility_payload: &Value,
    ) -> ExecutionWitnessResult<Self> {
        ensure_non_empty("proof circuit family", circuit_family)?;
        ensure_non_empty("verifier key label", verifier_key_label)?;
        ensure_positive("max recursion depth", max_recursion_depth)?;
        if security_bits < EXECUTION_WITNESS_DEFAULT_SECURITY_BITS {
            return Err("proof input manifest security bits too low".to_string());
        }
        let verifier_key_root =
            execution_witness_string_root("PROOF-INPUT-VERIFYING-KEY", verifier_key_label);
        let witness_commitment_root = execution_witness_payload_root(
            "PROOF-INPUT-WITNESS-COMMITMENT",
            &json!({
                "package_id": package.package_id,
                "aggregate_trace_root": package.aggregate_trace_root,
                "recursive_input_root": package.recursive_input_root,
            }),
        );
        let compatibility_root =
            execution_witness_payload_root("PROOF-INPUT-COMPATIBILITY", compatibility_payload);
        let manifest_id = execution_proof_input_manifest_id(
            &package.package_id,
            circuit_family,
            &verifier_key_root,
            &compatibility_root,
        );
        Ok(Self {
            manifest_id,
            package_id: package.package_id.clone(),
            circuit_family: circuit_family.to_string(),
            verifier_key_root,
            public_input_root: package.public_input_root.clone(),
            witness_commitment_root,
            compatibility_root,
            max_recursion_depth,
            security_bits,
            status: ProofInputStatus::Ready,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_input_manifest",
            "chain_id": CHAIN_ID,
            "manifest_id": self.manifest_id,
            "package_id": self.package_id,
            "circuit_family": self.circuit_family,
            "verifier_key_root": self.verifier_key_root,
            "public_input_root": self.public_input_root,
            "witness_commitment_root": self.witness_commitment_root,
            "compatibility_root": self.compatibility_root,
            "max_recursion_depth": self.max_recursion_depth,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
        })
    }

    pub fn manifest_root(&self) -> String {
        execution_witness_payload_root("PROOF-INPUT-MANIFEST", &self.public_record())
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        ensure_non_empty("proof manifest id", &self.manifest_id)?;
        ensure_non_empty("proof manifest package id", &self.package_id)?;
        ensure_non_empty("proof circuit family", &self.circuit_family)?;
        ensure_non_empty("proof verifier key root", &self.verifier_key_root)?;
        ensure_non_empty("proof public input root", &self.public_input_root)?;
        ensure_non_empty(
            "proof witness commitment root",
            &self.witness_commitment_root,
        )?;
        ensure_non_empty("proof compatibility root", &self.compatibility_root)?;
        ensure_positive("proof max recursion depth", self.max_recursion_depth)?;
        if self.security_bits < EXECUTION_WITNESS_DEFAULT_SECURITY_BITS {
            return Err("proof manifest security below default".to_string());
        }
        let expected = execution_proof_input_manifest_id(
            &self.package_id,
            &self.circuit_family,
            &self.verifier_key_root,
            &self.compatibility_root,
        );
        if self.manifest_id != expected {
            return Err("proof input manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverWitnessAssignment {
    pub assignment_id: String,
    pub package_id: String,
    pub manifest_id: String,
    pub prover_commitment: String,
    pub worker_class: String,
    pub bid_fee_units: u64,
    pub sponsor_id: Option<String>,
    pub assigned_at_height: u64,
    pub deadline_height: u64,
    pub pq_attestation_root: String,
    pub status: ProverAssignmentStatus,
}

impl ProverWitnessAssignment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        manifest_id: &str,
        prover_label: &str,
        worker_class: &str,
        bid_fee_units: u64,
        sponsor_id: Option<String>,
        assigned_at_height: u64,
        ttl_blocks: u64,
    ) -> ExecutionWitnessResult<Self> {
        ensure_non_empty("assignment package id", package_id)?;
        ensure_non_empty("assignment manifest id", manifest_id)?;
        ensure_non_empty("assignment prover label", prover_label)?;
        ensure_non_empty("assignment worker class", worker_class)?;
        ensure_positive("assignment ttl blocks", ttl_blocks)?;
        let prover_commitment = execution_witness_commitment(
            "PROVER-WITNESS-COMMITMENT",
            prover_label,
            assigned_at_height,
        );
        let deadline_height = assigned_at_height.saturating_add(ttl_blocks);
        let pq_attestation_root = execution_witness_payload_root(
            "PROVER-WITNESS-PQ-ATTESTATION",
            &json!({
                "scheme": EXECUTION_WITNESS_PQ_ATTESTATION_SCHEME,
                "package_id": package_id,
                "manifest_id": manifest_id,
                "prover_commitment": prover_commitment,
                "worker_class": worker_class,
            }),
        );
        let assignment_id = execution_witness_assignment_id(
            package_id,
            manifest_id,
            &prover_commitment,
            assigned_at_height,
        );
        Ok(Self {
            assignment_id,
            package_id: package_id.to_string(),
            manifest_id: manifest_id.to_string(),
            prover_commitment,
            worker_class: worker_class.to_string(),
            bid_fee_units,
            sponsor_id,
            assigned_at_height,
            deadline_height,
            pq_attestation_root,
            status: ProverAssignmentStatus::Accepted,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.deadline_height && self.status.active()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_witness_assignment",
            "chain_id": CHAIN_ID,
            "assignment_id": self.assignment_id,
            "package_id": self.package_id,
            "manifest_id": self.manifest_id,
            "prover_commitment": self.prover_commitment,
            "worker_class": self.worker_class,
            "bid_fee_units": self.bid_fee_units,
            "sponsor_id": self.sponsor_id,
            "assigned_at_height": self.assigned_at_height,
            "deadline_height": self.deadline_height,
            "pq_attestation_root": self.pq_attestation_root,
            "status": self.status.as_str(),
        })
    }

    pub fn assignment_root(&self) -> String {
        execution_witness_payload_root("PROVER-WITNESS-ASSIGNMENT", &self.public_record())
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        ensure_non_empty("assignment id", &self.assignment_id)?;
        ensure_non_empty("assignment package id", &self.package_id)?;
        ensure_non_empty("assignment manifest id", &self.manifest_id)?;
        ensure_non_empty("assignment prover commitment", &self.prover_commitment)?;
        ensure_non_empty("assignment worker class", &self.worker_class)?;
        ensure_height_window(
            self.assigned_at_height,
            self.deadline_height,
            "prover assignment ttl",
        )?;
        ensure_non_empty("assignment pq attestation root", &self.pq_attestation_root)?;
        let expected = execution_witness_assignment_id(
            &self.package_id,
            &self.manifest_id,
            &self.prover_commitment,
            self.assigned_at_height,
        );
        if self.assignment_id != expected {
            return Err("prover witness assignment id mismatch".to_string());
        }
        Ok(self.assignment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessDisclosureReceipt {
    pub receipt_id: String,
    pub package_id: String,
    pub scope: WitnessDisclosureScope,
    pub recipient_commitment: String,
    pub disclosed_field_root: String,
    pub opening_proof_root: String,
    pub disclosure_bps: u64,
    pub disclosed_at_height: u64,
}

impl WitnessDisclosureReceipt {
    pub fn new(
        package_id: &str,
        scope: WitnessDisclosureScope,
        recipient_label: &str,
        disclosed_fields: &[String],
        opening_payload: &Value,
        disclosed_at_height: u64,
        nonce: u64,
    ) -> ExecutionWitnessResult<Self> {
        ensure_non_empty("disclosure package id", package_id)?;
        ensure_non_empty("disclosure recipient label", recipient_label)?;
        let recipient_commitment =
            execution_witness_commitment("WITNESS-DISCLOSURE-RECIPIENT", recipient_label, nonce);
        let disclosed_field_root =
            execution_witness_string_set_root("WITNESS-DISCLOSURE-FIELDS", disclosed_fields);
        let opening_proof_root =
            execution_witness_payload_root("WITNESS-DISCLOSURE-OPENING", opening_payload);
        let disclosure_bps = scope.disclosure_bps();
        let receipt_id = execution_witness_disclosure_id(
            package_id,
            scope,
            &recipient_commitment,
            &disclosed_field_root,
            disclosed_at_height,
        );
        Ok(Self {
            receipt_id,
            package_id: package_id.to_string(),
            scope,
            recipient_commitment,
            disclosed_field_root,
            opening_proof_root,
            disclosure_bps,
            disclosed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_disclosure_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "package_id": self.package_id,
            "scope": self.scope.as_str(),
            "recipient_commitment": self.recipient_commitment,
            "disclosed_field_root": self.disclosed_field_root,
            "opening_proof_root": self.opening_proof_root,
            "disclosure_bps": self.disclosure_bps,
            "disclosed_at_height": self.disclosed_at_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        execution_witness_payload_root("WITNESS-DISCLOSURE-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        ensure_non_empty("disclosure receipt id", &self.receipt_id)?;
        ensure_non_empty("disclosure package id", &self.package_id)?;
        ensure_non_empty(
            "disclosure recipient commitment",
            &self.recipient_commitment,
        )?;
        ensure_non_empty("disclosed field root", &self.disclosed_field_root)?;
        ensure_non_empty("opening proof root", &self.opening_proof_root)?;
        ensure_bps("disclosure bps", self.disclosure_bps)?;
        if self.disclosure_bps != self.scope.disclosure_bps() {
            return Err("disclosure bps does not match scope".to_string());
        }
        let expected = execution_witness_disclosure_id(
            &self.package_id,
            self.scope,
            &self.recipient_commitment,
            &self.disclosed_field_root,
            self.disclosed_at_height,
        );
        if self.receipt_id != expected {
            return Err("witness disclosure receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessAttestation {
    pub attestation_id: String,
    pub subject: WitnessAttestationSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_commitment: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub security_bits: u16,
    pub threshold_signer_count: u16,
    pub status: WitnessAttestationStatus,
}

impl WitnessAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: WitnessAttestationSubject,
        subject_id: &str,
        subject_root: &str,
        signer_label: &str,
        signature_label: &str,
        signed_at_height: u64,
        ttl_blocks: u64,
        security_bits: u16,
        threshold_signer_count: u16,
    ) -> ExecutionWitnessResult<Self> {
        ensure_non_empty("attestation subject id", subject_id)?;
        ensure_non_empty("attestation subject root", subject_root)?;
        ensure_non_empty("attestation signer label", signer_label)?;
        ensure_non_empty("attestation signature label", signature_label)?;
        ensure_positive("attestation ttl blocks", ttl_blocks)?;
        if security_bits < EXECUTION_WITNESS_DEFAULT_SECURITY_BITS {
            return Err("attestation security bits below default".to_string());
        }
        let signer_commitment = execution_witness_commitment(
            "WITNESS-ATTESTATION-SIGNER",
            signer_label,
            signed_at_height,
        );
        let signature_root = execution_witness_payload_root(
            "WITNESS-ATTESTATION-SIGNATURE",
            &json!({
                "scheme": EXECUTION_WITNESS_PQ_ATTESTATION_SCHEME,
                "subject": subject.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "signature_label": signature_label,
            }),
        );
        let expires_at_height = signed_at_height.saturating_add(ttl_blocks);
        let attestation_id = execution_witness_attestation_id(
            subject,
            subject_id,
            subject_root,
            &signer_commitment,
            signed_at_height,
        );
        let status = if threshold_signer_count > 1 {
            WitnessAttestationStatus::ThresholdValid
        } else {
            WitnessAttestationStatus::Valid
        };
        Ok(Self {
            attestation_id,
            subject,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            signer_commitment,
            signature_root,
            signed_at_height,
            expires_at_height,
            security_bits,
            threshold_signer_count,
            status,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height <= self.expires_at_height && self.status.usable()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_attestation",
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "subject": self.subject.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "security_bits": self.security_bits,
            "threshold_signer_count": self.threshold_signer_count,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        execution_witness_payload_root("WITNESS-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        ensure_non_empty("witness attestation id", &self.attestation_id)?;
        ensure_non_empty("witness attestation subject id", &self.subject_id)?;
        ensure_non_empty("witness attestation subject root", &self.subject_root)?;
        ensure_non_empty(
            "witness attestation signer commitment",
            &self.signer_commitment,
        )?;
        ensure_non_empty("witness attestation signature root", &self.signature_root)?;
        ensure_height_window(
            self.signed_at_height,
            self.expires_at_height,
            "witness attestation ttl",
        )?;
        if self.security_bits < EXECUTION_WITNESS_DEFAULT_SECURITY_BITS {
            return Err("witness attestation security below default".to_string());
        }
        let expected = execution_witness_attestation_id(
            self.subject,
            &self.subject_id,
            &self.subject_root,
            &self.signer_commitment,
            self.signed_at_height,
        );
        if self.attestation_id != expected {
            return Err("witness attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWitnessRoots {
    pub config_root: String,
    pub trace_segment_root: String,
    pub witness_package_root: String,
    pub proof_input_manifest_root: String,
    pub prover_assignment_root: String,
    pub disclosure_receipt_root: String,
    pub attestation_root: String,
    pub live_package_root: String,
}

impl ExecutionWitnessRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_witness_roots",
            "config_root": self.config_root,
            "trace_segment_root": self.trace_segment_root,
            "witness_package_root": self.witness_package_root,
            "proof_input_manifest_root": self.proof_input_manifest_root,
            "prover_assignment_root": self.prover_assignment_root,
            "disclosure_receipt_root": self.disclosure_receipt_root,
            "attestation_root": self.attestation_root,
            "live_package_root": self.live_package_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWitnessCounters {
    pub trace_segment_count: u64,
    pub live_trace_segment_count: u64,
    pub witness_package_count: u64,
    pub live_witness_package_count: u64,
    pub proof_input_manifest_count: u64,
    pub ready_manifest_count: u64,
    pub prover_assignment_count: u64,
    pub active_assignment_count: u64,
    pub disclosure_receipt_count: u64,
    pub attestation_count: u64,
    pub usable_attestation_count: u64,
    pub total_trace_steps: u64,
    pub total_fuel_used: u64,
    pub total_payload_bytes: u64,
    pub total_estimated_proof_bytes: u64,
    pub aggregate_disclosure_bps: u64,
}

impl ExecutionWitnessCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_witness_counters",
            "trace_segment_count": self.trace_segment_count,
            "live_trace_segment_count": self.live_trace_segment_count,
            "witness_package_count": self.witness_package_count,
            "live_witness_package_count": self.live_witness_package_count,
            "proof_input_manifest_count": self.proof_input_manifest_count,
            "ready_manifest_count": self.ready_manifest_count,
            "prover_assignment_count": self.prover_assignment_count,
            "active_assignment_count": self.active_assignment_count,
            "disclosure_receipt_count": self.disclosure_receipt_count,
            "attestation_count": self.attestation_count,
            "usable_attestation_count": self.usable_attestation_count,
            "total_trace_steps": self.total_trace_steps,
            "total_fuel_used": self.total_fuel_used,
            "total_payload_bytes": self.total_payload_bytes,
            "total_estimated_proof_bytes": self.total_estimated_proof_bytes,
            "aggregate_disclosure_bps": self.aggregate_disclosure_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWitnessPipelineState {
    pub height: u64,
    pub config: ExecutionWitnessConfig,
    pub trace_segments: BTreeMap<String, ExecutionTraceSegment>,
    pub witness_packages: BTreeMap<String, WitnessPackage>,
    pub proof_input_manifests: BTreeMap<String, ProofInputManifest>,
    pub prover_assignments: BTreeMap<String, ProverWitnessAssignment>,
    pub disclosure_receipts: BTreeMap<String, WitnessDisclosureReceipt>,
    pub attestations: BTreeMap<String, WitnessAttestation>,
}

impl Default for ExecutionWitnessPipelineState {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionWitnessPipelineState {
    pub fn new() -> Self {
        Self {
            height: 0,
            config: ExecutionWitnessConfig::devnet(),
            trace_segments: BTreeMap::new(),
            witness_packages: BTreeMap::new(),
            proof_input_manifests: BTreeMap::new(),
            prover_assignments: BTreeMap::new(),
            disclosure_receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
        }
    }

    pub fn with_config(config: ExecutionWitnessConfig) -> ExecutionWitnessResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> ExecutionWitnessResult<Self> {
        let mut state = Self::with_config(ExecutionWitnessConfig::devnet())?;
        state.set_height(80)?;

        let mut private_transfer = ExecutionTraceSegment::new(
            WitnessDomain::PrivateTransfer,
            "devnet-private-transfer-batch-80",
            "private-transfer-fast-lane",
            1,
            (state.height.saturating_sub(2), state.height),
            WitnessPrivacyMode::FullyShielded,
            &json!({
                "note_commitment_root": "devnet-note-root-80",
                "nullifier_set_root": "devnet-nullifier-root-80",
                "fee_bucket": "low",
            }),
            "private-transfer-witness-80",
            &[
                "account_root_before".to_string(),
                "fee_pool_before".to_string(),
            ],
            &[
                "account_root_after".to_string(),
                "fee_pool_after".to_string(),
            ],
            &["nullifier:private-transfer:80".to_string()],
            &["event:private-transfer-settled".to_string()],
            &["fee:private-transfer-low".to_string()],
            1_240,
            88_000,
            4_096,
            state.height,
            state.config.trace_ttl_blocks,
        )?;
        private_transfer.seal();
        let private_transfer_id = state.insert_trace_segment(private_transfer)?;

        let mut bridge_exit = ExecutionTraceSegment::new(
            WitnessDomain::MoneroBridge,
            "devnet-monero-exit-batch-80",
            "monero-bridge-low-fee-lane",
            2,
            (state.height.saturating_sub(4), state.height),
            WitnessPrivacyMode::AggregateOnly,
            &json!({
                "bridge_ticket_root": "devnet-bridge-ticket-root",
                "reserve_epoch_root": "devnet-reserve-epoch-root",
                "amount_bucket_root": "devnet-amount-bucket-root",
            }),
            "monero-bridge-witness-80",
            &[
                "bridge_queue_before".to_string(),
                "reserve_root_before".to_string(),
            ],
            &[
                "bridge_queue_after".to_string(),
                "reserve_root_after".to_string(),
            ],
            &["withdrawal-nullifier:80".to_string()],
            &["event:monero-withdrawal-observed".to_string()],
            &["fee:bridge-sponsored".to_string()],
            1_850,
            142_000,
            5_120,
            state.height,
            state.config.trace_ttl_blocks,
        )?;
        bridge_exit.seal();
        let bridge_exit_id = state.insert_trace_segment(bridge_exit)?;

        let mut defi_swap = ExecutionTraceSegment::new(
            WitnessDomain::DefiSwap,
            "devnet-private-swap-batch-80",
            "small-defi-low-fee-lane",
            3,
            (state.height.saturating_sub(1), state.height),
            WitnessPrivacyMode::FullyShielded,
            &json!({
                "pool_commitment_root": "devnet-private-pool-root",
                "route_hint_root": "devnet-route-hint-root",
                "slippage_bucket": "tight",
            }),
            "private-defi-swap-witness-80",
            &[
                "pool_state_before".to_string(),
                "router_budget_before".to_string(),
            ],
            &[
                "pool_state_after".to_string(),
                "router_budget_after".to_string(),
            ],
            &["swap-nullifier:80".to_string()],
            &["event:private-swap-filled".to_string()],
            &["fee:small-defi-sponsored".to_string()],
            2_220,
            198_000,
            6_144,
            state.height,
            state.config.trace_ttl_blocks,
        )?;
        defi_swap.seal();
        let defi_swap_id = state.insert_trace_segment(defi_swap)?;

        let package_id = state.package_segments(
            "devnet-private-proof-package-80",
            WitnessDomain::PrivateTransfer,
            &[private_transfer_id.clone()],
            WitnessPrivacyMode::FullyShielded,
            95,
            &json!({
                "preferred_circuit": "private-transfer-v1",
                "recursive_aggregation": true,
                "low_fee": true,
            }),
        )?;
        let bridge_package_id = state.package_segments(
            "devnet-bridge-proof-package-80",
            WitnessDomain::MoneroBridge,
            &[bridge_exit_id.clone()],
            WitnessPrivacyMode::AggregateOnly,
            100,
            &json!({
                "preferred_circuit": "monero-bridge-exit-v1",
                "reserve_check": true,
                "recursive_aggregation": true,
            }),
        )?;
        let defi_package_id = state.package_segments(
            "devnet-defi-proof-package-80",
            WitnessDomain::DefiSwap,
            &[defi_swap_id.clone()],
            WitnessPrivacyMode::FullyShielded,
            90,
            &json!({
                "preferred_circuit": "private-defi-swap-v1",
                "amm": "private-xmr-usdd",
                "low_fee": true,
            }),
        )?;

        let manifest_id = state.create_proof_input_manifest(
            &package_id,
            "private-transfer-proof",
            "vk-private-transfer-devnet",
            2,
            128,
            &json!({"compatible_with": ["recursive-aggregation-v1"], "proof_system": "devnet-pq-zk"}),
        )?;
        let bridge_manifest_id = state.create_proof_input_manifest(
            &bridge_package_id,
            "monero-bridge-exit-proof",
            "vk-monero-bridge-exit-devnet",
            3,
            192,
            &json!({"compatible_with": ["reserve-monitor-v1"], "proof_system": "devnet-pq-zk"}),
        )?;
        let defi_manifest_id = state.create_proof_input_manifest(
            &defi_package_id,
            "private-defi-swap-proof",
            "vk-private-defi-swap-devnet",
            2,
            128,
            &json!({"compatible_with": ["private-amm-v1"], "proof_system": "devnet-pq-zk"}),
        )?;

        state.assign_prover(
            &package_id,
            &manifest_id,
            "devnet-prover-private-transfer",
            "gpu-pq-prover",
            22_000,
            Some("privacy-fee-ledger-sponsor".to_string()),
        )?;
        state.assign_prover(
            &bridge_package_id,
            &bridge_manifest_id,
            "devnet-prover-monero-bridge",
            "bridge-recursive-prover",
            38_000,
            Some("bridge-proof-sponsor".to_string()),
        )?;
        state.assign_prover(
            &defi_package_id,
            &defi_manifest_id,
            "devnet-prover-private-defi",
            "defi-recursive-prover",
            31_000,
            Some("defi-proof-sponsor".to_string()),
        )?;

        state.add_disclosure_receipt(WitnessDisclosureReceipt::new(
            &bridge_package_id,
            WitnessDisclosureScope::FeeSummary,
            "devnet-bridge-risk-dashboard",
            &[
                "amount_bucket_root".to_string(),
                "reserve_epoch_root".to_string(),
                "fee_sponsor_root".to_string(),
            ],
            &json!({"redaction": "aggregate-only", "no_address": true, "no_txid": true}),
            state.height,
            9,
        )?)?;

        for (subject, subject_id, subject_root, signer, threshold) in [
            (
                WitnessAttestationSubject::WitnessPackage,
                package_id.clone(),
                state
                    .witness_packages
                    .get(&package_id)
                    .map(WitnessPackage::package_root)
                    .ok_or_else(|| "missing devnet witness package".to_string())?,
                "devnet-witness-committee-a",
                3_u16,
            ),
            (
                WitnessAttestationSubject::WitnessPackage,
                bridge_package_id.clone(),
                state
                    .witness_packages
                    .get(&bridge_package_id)
                    .map(WitnessPackage::package_root)
                    .ok_or_else(|| "missing devnet bridge witness package".to_string())?,
                "devnet-bridge-witness-committee",
                5_u16,
            ),
            (
                WitnessAttestationSubject::ProofInputManifest,
                defi_manifest_id.clone(),
                state
                    .proof_input_manifests
                    .get(&defi_manifest_id)
                    .map(ProofInputManifest::manifest_root)
                    .ok_or_else(|| "missing devnet defi manifest".to_string())?,
                "devnet-proof-manifest-signer",
                2_u16,
            ),
        ] {
            state.add_attestation(WitnessAttestation::new(
                subject,
                &subject_id,
                &subject_root,
                signer,
                "devnet-pq-signature-root",
                state.height,
                state.config.package_ttl_blocks,
                state.config.default_security_bits,
                threshold,
            )?)?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ExecutionWitnessResult<String> {
        self.height = height;
        for segment in self.trace_segments.values_mut() {
            if self.height > segment.expires_at_height && segment.status.active() {
                segment.status = TraceStatus::Expired;
            }
        }
        for package in self.witness_packages.values_mut() {
            if self.height > package.expires_at_height && package.package_status.active() {
                package.package_status = WitnessPackageStatus::Expired;
            }
        }
        for assignment in self.prover_assignments.values_mut() {
            if self.height > assignment.deadline_height && assignment.status.active() {
                assignment.status = ProverAssignmentStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            if self.height > attestation.expires_at_height && attestation.status.usable() {
                attestation.status = WitnessAttestationStatus::Expired;
            }
        }
        Ok(self.state_root())
    }

    pub fn insert_trace_segment(
        &mut self,
        segment: ExecutionTraceSegment,
    ) -> ExecutionWitnessResult<String> {
        segment.validate()?;
        if segment.step_count > self.config.max_trace_steps {
            return Err("trace segment exceeds configured max steps".to_string());
        }
        let segment_id = segment.segment_id.clone();
        if self.trace_segments.contains_key(&segment_id) {
            return Err("duplicate execution trace segment".to_string());
        }
        self.trace_segments.insert(segment_id.clone(), segment);
        Ok(segment_id)
    }

    pub fn package_segments(
        &mut self,
        package_label: &str,
        domain: WitnessDomain,
        segment_ids: &[String],
        privacy_mode: WitnessPrivacyMode,
        priority: u64,
        prover_hint: &Value,
    ) -> ExecutionWitnessResult<String> {
        if segment_ids.is_empty() {
            return Err("package_segments requires segment ids".to_string());
        }
        let mut segments = Vec::new();
        for segment_id in segment_ids {
            let segment = self
                .trace_segments
                .get(segment_id)
                .cloned()
                .ok_or_else(|| "witness package references unknown segment".to_string())?;
            if segment.domain != domain {
                return Err("witness package domain mismatch".to_string());
            }
            if !matches!(segment.status, TraceStatus::Sealed) {
                return Err("witness package requires sealed segment".to_string());
            }
            segments.push(segment);
        }
        let package = WitnessPackage::new(
            package_label,
            domain,
            &segments,
            privacy_mode,
            priority,
            prover_hint,
            self.height,
            self.config.package_ttl_blocks,
        )?;
        let package_id = package.package_id.clone();
        if self.witness_packages.contains_key(&package_id) {
            return Err("duplicate witness package".to_string());
        }
        for segment_id in segment_ids {
            if let Some(segment) = self.trace_segments.get_mut(segment_id) {
                segment.status = TraceStatus::Packaged;
            }
        }
        self.witness_packages.insert(package_id.clone(), package);
        Ok(package_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_proof_input_manifest(
        &mut self,
        package_id: &str,
        circuit_family: &str,
        verifier_key_label: &str,
        max_recursion_depth: u64,
        security_bits: u16,
        compatibility_payload: &Value,
    ) -> ExecutionWitnessResult<String> {
        let package = self
            .witness_packages
            .get(package_id)
            .ok_or_else(|| "proof input manifest references unknown package".to_string())?;
        let manifest = ProofInputManifest::new(
            package,
            circuit_family,
            verifier_key_label,
            max_recursion_depth,
            security_bits,
            compatibility_payload,
        )?;
        let manifest_id = manifest.manifest_id.clone();
        if self.proof_input_manifests.contains_key(&manifest_id) {
            return Err("duplicate proof input manifest".to_string());
        }
        self.proof_input_manifests
            .insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn assign_prover(
        &mut self,
        package_id: &str,
        manifest_id: &str,
        prover_label: &str,
        worker_class: &str,
        bid_fee_units: u64,
        sponsor_id: Option<String>,
    ) -> ExecutionWitnessResult<String> {
        if !self.witness_packages.contains_key(package_id) {
            return Err("prover assignment references unknown package".to_string());
        }
        if !self.proof_input_manifests.contains_key(manifest_id) {
            return Err("prover assignment references unknown manifest".to_string());
        }
        let assignment = ProverWitnessAssignment::new(
            package_id,
            manifest_id,
            prover_label,
            worker_class,
            bid_fee_units,
            sponsor_id,
            self.height,
            self.config.assignment_ttl_blocks,
        )?;
        let assignment_id = assignment.assignment_id.clone();
        if self.prover_assignments.contains_key(&assignment_id) {
            return Err("duplicate prover witness assignment".to_string());
        }
        if let Some(package) = self.witness_packages.get_mut(package_id) {
            package.package_status = WitnessPackageStatus::Assigned;
        }
        self.prover_assignments
            .insert(assignment_id.clone(), assignment);
        Ok(assignment_id)
    }

    pub fn add_disclosure_receipt(
        &mut self,
        receipt: WitnessDisclosureReceipt,
    ) -> ExecutionWitnessResult<String> {
        receipt.validate()?;
        if !self.witness_packages.contains_key(&receipt.package_id) {
            return Err("witness disclosure references unknown package".to_string());
        }
        if receipt.disclosure_bps > self.config.max_disclosure_bps {
            return Err("witness disclosure exceeds configured privacy bound".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        if self.disclosure_receipts.contains_key(&receipt_id) {
            return Err("duplicate witness disclosure receipt".to_string());
        }
        self.disclosure_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn add_attestation(
        &mut self,
        attestation: WitnessAttestation,
    ) -> ExecutionWitnessResult<String> {
        attestation.validate()?;
        self.validate_attestation_subject(&attestation)?;
        let attestation_id = attestation.attestation_id.clone();
        if self.attestations.contains_key(&attestation_id) {
            return Err("duplicate witness attestation".to_string());
        }
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    fn validate_attestation_subject(
        &self,
        attestation: &WitnessAttestation,
    ) -> ExecutionWitnessResult<()> {
        match attestation.subject {
            WitnessAttestationSubject::TraceSegment => {
                require_root_match(
                    self.trace_segments
                        .get(&attestation.subject_id)
                        .map(ExecutionTraceSegment::segment_root),
                    &attestation.subject_root,
                    "trace segment attestation",
                )?;
            }
            WitnessAttestationSubject::WitnessPackage => {
                require_root_match(
                    self.witness_packages
                        .get(&attestation.subject_id)
                        .map(WitnessPackage::package_root),
                    &attestation.subject_root,
                    "witness package attestation",
                )?;
            }
            WitnessAttestationSubject::ProofInputManifest => {
                require_root_match(
                    self.proof_input_manifests
                        .get(&attestation.subject_id)
                        .map(ProofInputManifest::manifest_root),
                    &attestation.subject_root,
                    "proof input manifest attestation",
                )?;
            }
            WitnessAttestationSubject::ProverAssignment => {
                require_root_match(
                    self.prover_assignments
                        .get(&attestation.subject_id)
                        .map(ProverWitnessAssignment::assignment_root),
                    &attestation.subject_root,
                    "prover assignment attestation",
                )?;
            }
            WitnessAttestationSubject::DisclosureReceipt => {
                require_root_match(
                    self.disclosure_receipts
                        .get(&attestation.subject_id)
                        .map(WitnessDisclosureReceipt::receipt_root),
                    &attestation.subject_root,
                    "disclosure receipt attestation",
                )?;
            }
            WitnessAttestationSubject::CircuitCompatibility => {
                ensure_non_empty(
                    "circuit compatibility subject root",
                    &attestation.subject_root,
                )?;
            }
        }
        Ok(())
    }

    pub fn trace_segment_root(&self) -> String {
        execution_witness_trace_segment_set_root(
            &self.trace_segments.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn witness_package_root(&self) -> String {
        execution_witness_package_set_root(
            &self.witness_packages.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn proof_input_manifest_root(&self) -> String {
        execution_witness_manifest_set_root(
            &self
                .proof_input_manifests
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn prover_assignment_root(&self) -> String {
        execution_witness_assignment_set_root(
            &self
                .prover_assignments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn disclosure_receipt_root(&self) -> String {
        execution_witness_disclosure_set_root(
            &self
                .disclosure_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn attestation_root(&self) -> String {
        execution_witness_attestation_set_root(
            &self.attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn live_package_ids(&self) -> Vec<String> {
        self.witness_packages
            .values()
            .filter(|package| package.is_live_at(self.height))
            .map(|package| package.package_id.clone())
            .collect()
    }

    pub fn live_package_root(&self) -> String {
        let leaves = self
            .live_package_ids()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        merkle_root("EXECUTION-WITNESS-LIVE-PACKAGES", &leaves)
    }

    pub fn total_estimated_proof_bytes(&self) -> u64 {
        self.witness_packages
            .values()
            .fold(0_u64, |total, package| {
                total.saturating_add(package.estimated_proof_bytes)
            })
    }

    pub fn aggregate_disclosure_bps(&self) -> u64 {
        if self.witness_packages.is_empty() {
            return 0;
        }
        let total_weight = self
            .witness_packages
            .values()
            .fold(0_u64, |total, package| {
                total.saturating_add(package.privacy_mode.disclosure_weight_bps())
            })
            .saturating_add(
                self.disclosure_receipts
                    .values()
                    .fold(0_u64, |total, receipt| {
                        total.saturating_add(receipt.disclosure_bps)
                    }),
            );
        total_weight.saturating_div(self.witness_packages.len() as u64)
    }

    pub fn roots(&self) -> ExecutionWitnessRoots {
        ExecutionWitnessRoots {
            config_root: self.config.config_root(),
            trace_segment_root: self.trace_segment_root(),
            witness_package_root: self.witness_package_root(),
            proof_input_manifest_root: self.proof_input_manifest_root(),
            prover_assignment_root: self.prover_assignment_root(),
            disclosure_receipt_root: self.disclosure_receipt_root(),
            attestation_root: self.attestation_root(),
            live_package_root: self.live_package_root(),
        }
    }

    pub fn counters(&self) -> ExecutionWitnessCounters {
        let mut counters = ExecutionWitnessCounters {
            trace_segment_count: self.trace_segments.len() as u64,
            witness_package_count: self.witness_packages.len() as u64,
            proof_input_manifest_count: self.proof_input_manifests.len() as u64,
            prover_assignment_count: self.prover_assignments.len() as u64,
            disclosure_receipt_count: self.disclosure_receipts.len() as u64,
            attestation_count: self.attestations.len() as u64,
            aggregate_disclosure_bps: self.aggregate_disclosure_bps(),
            ..ExecutionWitnessCounters::default()
        };
        for segment in self.trace_segments.values() {
            if segment.is_live_at(self.height) {
                counters.live_trace_segment_count =
                    counters.live_trace_segment_count.saturating_add(1);
            }
            counters.total_trace_steps = counters
                .total_trace_steps
                .saturating_add(segment.step_count);
            counters.total_fuel_used = counters.total_fuel_used.saturating_add(segment.fuel_used);
            counters.total_payload_bytes = counters
                .total_payload_bytes
                .saturating_add(segment.payload_bytes);
        }
        for package in self.witness_packages.values() {
            if package.is_live_at(self.height) {
                counters.live_witness_package_count =
                    counters.live_witness_package_count.saturating_add(1);
            }
            counters.total_estimated_proof_bytes = counters
                .total_estimated_proof_bytes
                .saturating_add(package.estimated_proof_bytes);
        }
        for manifest in self.proof_input_manifests.values() {
            if matches!(
                manifest.status,
                ProofInputStatus::Ready | ProofInputStatus::Submitted
            ) {
                counters.ready_manifest_count = counters.ready_manifest_count.saturating_add(1);
            }
        }
        for assignment in self.prover_assignments.values() {
            if assignment.is_live_at(self.height) {
                counters.active_assignment_count =
                    counters.active_assignment_count.saturating_add(1);
            }
        }
        for attestation in self.attestations.values() {
            if attestation.is_live_at(self.height) {
                counters.usable_attestation_count =
                    counters.usable_attestation_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn public_record_root(&self) -> String {
        execution_witness_payload_root("EXECUTION-WITNESS-PUBLIC-RECORD", &self.public_record())
    }

    pub fn state_root(&self) -> String {
        execution_witness_state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "execution_witness_pipeline_state",
            "chain_id": CHAIN_ID,
            "protocol_version": EXECUTION_WITNESS_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "live_package_ids": self.live_package_ids(),
            "total_estimated_proof_bytes": self.total_estimated_proof_bytes(),
            "aggregate_disclosure_bps": self.aggregate_disclosure_bps(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> ExecutionWitnessResult<String> {
        self.config.validate()?;
        let mut segment_ids = BTreeSet::new();
        for (id, segment) in &self.trace_segments {
            if id != &segment.segment_id {
                return Err("trace segment map key mismatch".to_string());
            }
            segment.validate()?;
            if segment.step_count > self.config.max_trace_steps {
                return Err("trace segment exceeds max steps".to_string());
            }
            if !segment_ids.insert(id.clone()) {
                return Err("duplicate trace segment id".to_string());
            }
        }
        for (id, package) in &self.witness_packages {
            if id != &package.package_id {
                return Err("witness package map key mismatch".to_string());
            }
            package.validate()?;
            for segment_id in &package.segment_ids {
                if !self.trace_segments.contains_key(segment_id) {
                    return Err("witness package references unknown segment".to_string());
                }
            }
        }
        for (id, manifest) in &self.proof_input_manifests {
            if id != &manifest.manifest_id {
                return Err("proof manifest map key mismatch".to_string());
            }
            manifest.validate()?;
            if !self.witness_packages.contains_key(&manifest.package_id) {
                return Err("proof manifest references unknown package".to_string());
            }
        }
        for (id, assignment) in &self.prover_assignments {
            if id != &assignment.assignment_id {
                return Err("prover assignment map key mismatch".to_string());
            }
            assignment.validate()?;
            if !self.witness_packages.contains_key(&assignment.package_id) {
                return Err("assignment references unknown package".to_string());
            }
            if !self
                .proof_input_manifests
                .contains_key(&assignment.manifest_id)
            {
                return Err("assignment references unknown manifest".to_string());
            }
        }
        for (id, receipt) in &self.disclosure_receipts {
            if id != &receipt.receipt_id {
                return Err("disclosure receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if receipt.disclosure_bps > self.config.max_disclosure_bps {
                return Err("disclosure exceeds configured maximum".to_string());
            }
            if !self.witness_packages.contains_key(&receipt.package_id) {
                return Err("disclosure references unknown package".to_string());
            }
        }
        for (id, attestation) in &self.attestations {
            if id != &attestation.attestation_id {
                return Err("witness attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            self.validate_attestation_subject(attestation)?;
        }
        if self.aggregate_disclosure_bps() > self.config.max_disclosure_bps {
            return Err(
                "aggregate witness disclosure exceeds configured privacy bound".to_string(),
            );
        }
        Ok(self.state_root())
    }
}

pub fn execution_witness_state_root_from_record(record: &Value) -> String {
    execution_witness_payload_root("EXECUTION-WITNESS-STATE", record)
}

pub fn execution_witness_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn execution_witness_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn execution_witness_commitment(domain: &str, label: &str, nonce: u64) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(label), HashPart::Int(nonce as i128)],
        32,
    )
}

pub fn execution_witness_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn execution_trace_segment_id(
    domain: WitnessDomain,
    source_id: &str,
    lane_id: &str,
    sequence: u64,
    private_witness_commitment: &str,
) -> String {
    domain_hash(
        "EXECUTION-TRACE-SEGMENT-ID",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(source_id),
            HashPart::Str(lane_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(private_witness_commitment),
        ],
        20,
    )
}

pub fn execution_witness_package_id(
    package_label: &str,
    domain: WitnessDomain,
    aggregate_trace_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "EXECUTION-WITNESS-PACKAGE-ID",
        &[
            HashPart::Str(package_label),
            HashPart::Str(domain.as_str()),
            HashPart::Str(aggregate_trace_root),
            HashPart::Int(created_at_height as i128),
        ],
        20,
    )
}

pub fn execution_proof_input_manifest_id(
    package_id: &str,
    circuit_family: &str,
    verifier_key_root: &str,
    compatibility_root: &str,
) -> String {
    domain_hash(
        "EXECUTION-PROOF-INPUT-MANIFEST-ID",
        &[
            HashPart::Str(package_id),
            HashPart::Str(circuit_family),
            HashPart::Str(verifier_key_root),
            HashPart::Str(compatibility_root),
        ],
        20,
    )
}

pub fn execution_witness_assignment_id(
    package_id: &str,
    manifest_id: &str,
    prover_commitment: &str,
    assigned_at_height: u64,
) -> String {
    domain_hash(
        "EXECUTION-WITNESS-ASSIGNMENT-ID",
        &[
            HashPart::Str(package_id),
            HashPart::Str(manifest_id),
            HashPart::Str(prover_commitment),
            HashPart::Int(assigned_at_height as i128),
        ],
        20,
    )
}

pub fn execution_witness_disclosure_id(
    package_id: &str,
    scope: WitnessDisclosureScope,
    recipient_commitment: &str,
    disclosed_field_root: &str,
    disclosed_at_height: u64,
) -> String {
    domain_hash(
        "EXECUTION-WITNESS-DISCLOSURE-ID",
        &[
            HashPart::Str(package_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(recipient_commitment),
            HashPart::Str(disclosed_field_root),
            HashPart::Int(disclosed_at_height as i128),
        ],
        20,
    )
}

pub fn execution_witness_attestation_id(
    subject: WitnessAttestationSubject,
    subject_id: &str,
    subject_root: &str,
    signer_commitment: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "EXECUTION-WITNESS-ATTESTATION-ID",
        &[
            HashPart::Str(subject.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Int(signed_at_height as i128),
        ],
        20,
    )
}

pub fn execution_witness_trace_segment_set_root(segments: &[ExecutionTraceSegment]) -> String {
    let leaves = segments
        .iter()
        .map(ExecutionTraceSegment::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-WITNESS-TRACE-SEGMENT-SET", &leaves)
}

pub fn execution_witness_package_set_root(packages: &[WitnessPackage]) -> String {
    let leaves = packages
        .iter()
        .map(WitnessPackage::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-WITNESS-PACKAGE-SET", &leaves)
}

pub fn execution_witness_manifest_set_root(manifests: &[ProofInputManifest]) -> String {
    let leaves = manifests
        .iter()
        .map(ProofInputManifest::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-WITNESS-MANIFEST-SET", &leaves)
}

pub fn execution_witness_assignment_set_root(assignments: &[ProverWitnessAssignment]) -> String {
    let leaves = assignments
        .iter()
        .map(ProverWitnessAssignment::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-WITNESS-ASSIGNMENT-SET", &leaves)
}

pub fn execution_witness_disclosure_set_root(disclosures: &[WitnessDisclosureReceipt]) -> String {
    let leaves = disclosures
        .iter()
        .map(WitnessDisclosureReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-WITNESS-DISCLOSURE-SET", &leaves)
}

pub fn execution_witness_attestation_set_root(attestations: &[WitnessAttestation]) -> String {
    let leaves = attestations
        .iter()
        .map(WitnessAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root("EXECUTION-WITNESS-ATTESTATION-SET", &leaves)
}

fn require_root_match(
    actual: Option<String>,
    expected: &str,
    label: &str,
) -> ExecutionWitnessResult<()> {
    let actual = actual.ok_or_else(|| format!("{label} references unknown subject"))?;
    if actual != expected {
        return Err(format!("{label} root mismatch"));
    }
    Ok(())
}

fn ensure_eq(label: &str, actual: &str, expected: &str) -> ExecutionWitnessResult<()> {
    if actual != expected {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

fn ensure_non_empty(label: &str, value: &str) -> ExecutionWitnessResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> ExecutionWitnessResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> ExecutionWitnessResult<()> {
    if value > EXECUTION_WITNESS_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> ExecutionWitnessResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> ExecutionWitnessResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
