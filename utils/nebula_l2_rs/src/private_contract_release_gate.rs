use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractReleaseGateResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION: &str =
    "nebula-private-contract-release-gate-v1";
pub const PRIVATE_CONTRACT_RELEASE_GATE_SCHEMA_VERSION: &str =
    "private-contract-release-gate-state-v1";
pub const PRIVATE_CONTRACT_RELEASE_GATE_DEVNET_LABEL: &str = "devnet-private-contract-release-gate";
pub const PRIVATE_CONTRACT_RELEASE_GATE_PQ_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-release-authorization";
pub const PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_ROLLBACK_BLOCKS: u64 = 144;
pub const PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_AUDIT_QUORUM: u64 = 4;
pub const PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_WITNESS_REPLICAS: u64 = 5;
pub const PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_FEE_CAP_MICRO_UNITS: u64 = 25_000;
pub const PRIVATE_CONTRACT_RELEASE_GATE_MAX_TRACKED_RECORDS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Draft,
    Pending,
    Approved,
    Released,
    RolledBack,
    Expired,
    Rejected,
}

impl ReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Released => "released",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn releasable(self) -> bool {
        matches!(self, Self::Pending | Self::Approved | Self::Released)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateLane {
    Bytecode,
    Calldata,
    Witness,
    PqAuthorization,
    StateRent,
    CrossShard,
    Audit,
    Rollback,
    FeeCap,
}

impl GateLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bytecode => "bytecode",
            Self::Calldata => "calldata",
            Self::Witness => "witness",
            Self::PqAuthorization => "pq_authorization",
            Self::StateRent => "state_rent",
            Self::CrossShard => "cross_shard",
            Self::Audit => "audit",
            Self::Rollback => "rollback",
            Self::FeeCap => "fee_cap",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub chain_id: String,
    pub operator_label: String,
    pub pq_authorization_scheme: String,
    pub privacy_policy_root: String,
    pub bytecode_manifest_policy_root: String,
    pub calldata_policy_root: String,
    pub witness_policy_root: String,
    pub state_rent_policy_root: String,
    pub cross_shard_policy_root: String,
    pub rollback_window_blocks: u64,
    pub audit_quorum: u64,
    pub witness_replicas: u64,
    pub default_fee_cap_micro_units: u64,
}

impl Config {
    pub fn devnet() -> PrivateContractReleaseGateResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_CONTRACT_RELEASE_GATE_SCHEMA_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_label: PRIVATE_CONTRACT_RELEASE_GATE_DEVNET_LABEL.to_string(),
            pq_authorization_scheme: PRIVATE_CONTRACT_RELEASE_GATE_PQ_SCHEME.to_string(),
            privacy_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-PRIVACY",
                "encrypted-public-records-only",
            ),
            bytecode_manifest_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-BYTECODE",
                "manifest-hashes-and-compiler-fingerprints",
            ),
            calldata_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-CALLDATA",
                "selector-roots-and-redaction-policy",
            ),
            witness_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-WITNESS",
                "availability-before-release",
            ),
            state_rent_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-STATE-RENT",
                "compressed-rent-before-cross-shard",
            ),
            cross_shard_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-CROSS-SHARD",
                "deterministic-scheduling",
            ),
            rollback_window_blocks: PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_ROLLBACK_BLOCKS,
            audit_quorum: PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_AUDIT_QUORUM,
            witness_replicas: PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_WITNESS_REPLICAS,
            default_fee_cap_micro_units: PRIVATE_CONTRACT_RELEASE_GATE_DEFAULT_FEE_CAP_MICRO_UNITS,
        };
        config.config_id = id_from_parts(
            "PRIVATE-CONTRACT-RELEASE-GATE-CONFIG-ID",
            &[
                config.protocol_version.as_str(),
                config.schema_version.as_str(),
                config.chain_id.as_str(),
            ],
        );
        config.validate()?;
        Ok(config)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "privacy_policy_root": self.privacy_policy_root,
            "bytecode_manifest_policy_root": self.bytecode_manifest_policy_root,
            "calldata_policy_root": self.calldata_policy_root,
            "witness_policy_root": self.witness_policy_root,
            "state_rent_policy_root": self.state_rent_policy_root,
            "cross_shard_policy_root": self.cross_shard_policy_root,
            "rollback_window_blocks": self.rollback_window_blocks,
            "audit_quorum": self.audit_quorum,
            "witness_replicas": self.witness_replicas,
            "default_fee_cap_micro_units": self.default_fee_cap_micro_units,
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(&self.config_id, "private contract release gate config id")?;
        if self.protocol_version != PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION {
            return Err("private contract release gate protocol version mismatch".to_string());
        }
        if self.schema_version != PRIVATE_CONTRACT_RELEASE_GATE_SCHEMA_VERSION {
            return Err("private contract release gate schema version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("private contract release gate chain id mismatch".to_string());
        }
        ensure_non_empty(
            &self.operator_label,
            "private contract release gate operator label",
        )?;
        ensure_non_empty(
            &self.pq_authorization_scheme,
            "private contract release gate pq authorization scheme",
        )?;
        ensure_non_empty(
            &self.privacy_policy_root,
            "private contract release gate privacy policy root",
        )?;
        ensure_non_empty(
            &self.bytecode_manifest_policy_root,
            "private contract release gate bytecode policy root",
        )?;
        ensure_non_empty(
            &self.calldata_policy_root,
            "private contract release gate calldata policy root",
        )?;
        ensure_non_empty(
            &self.witness_policy_root,
            "private contract release gate witness policy root",
        )?;
        ensure_non_empty(
            &self.state_rent_policy_root,
            "private contract release gate state rent policy root",
        )?;
        ensure_non_empty(
            &self.cross_shard_policy_root,
            "private contract release gate cross shard policy root",
        )?;
        ensure_positive(
            self.rollback_window_blocks,
            "private contract release gate rollback window blocks",
        )?;
        ensure_positive(
            self.audit_quorum,
            "private contract release gate audit quorum",
        )?;
        ensure_positive(
            self.witness_replicas,
            "private contract release gate witness replicas",
        )?;
        ensure_positive(
            self.default_fee_cap_micro_units,
            "private contract release gate default fee cap",
        )?;
        let anticipated = id_from_parts(
            "PRIVATE-CONTRACT-RELEASE-GATE-CONFIG-ID",
            &[
                self.protocol_version.as_str(),
                self.schema_version.as_str(),
                self.chain_id.as_str(),
            ],
        );
        if self.config_id != anticipated {
            return Err("private contract release gate config id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub bytecode_root: String,
    pub abi_root: String,
    pub compiler_fingerprint: String,
    pub version_label: String,
    pub declared_at_height: u64,
    pub effective_from_height: u64,
    pub max_runtime_bytes: u64,
    pub release_status: ReleaseStatus,
}

impl BytecodeManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_manifest",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "bytecode_root": self.bytecode_root,
            "abi_root": self.abi_root,
            "compiler_fingerprint": self.compiler_fingerprint,
            "version_label": self.version_label,
            "declared_at_height": self.declared_at_height,
            "effective_from_height": self.effective_from_height,
            "max_runtime_bytes": self.max_runtime_bytes,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-BYTECODE-MANIFEST",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.manifest_id,
            "private contract release gate manifest manifest_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate manifest contract_id",
        )?;
        ensure_non_empty(
            &self.bytecode_root,
            "private contract release gate manifest bytecode_root",
        )?;
        ensure_non_empty(
            &self.abi_root,
            "private contract release gate manifest abi_root",
        )?;
        ensure_non_empty(
            &self.compiler_fingerprint,
            "private contract release gate manifest compiler_fingerprint",
        )?;
        ensure_non_empty(
            &self.version_label,
            "private contract release gate manifest version_label",
        )?;
        ensure_positive(
            self.declared_at_height,
            "private contract release gate manifest declared_at_height",
        )?;
        ensure_positive(
            self.effective_from_height,
            "private contract release gate manifest effective_from_height",
        )?;
        ensure_positive(
            self.max_runtime_bytes,
            "private contract release gate manifest max_runtime_bytes",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate manifest status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalldataPrivacyEnvelope {
    pub envelope_id: String,
    pub contract_id: String,
    pub call_selector_root: String,
    pub encrypted_calldata_root: String,
    pub privacy_budget_root: String,
    pub redaction_policy_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub byte_length: u64,
    pub release_status: ReleaseStatus,
}

impl CalldataPrivacyEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_calldata",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "contract_id": self.contract_id,
            "call_selector_root": self.call_selector_root,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "privacy_budget_root": self.privacy_budget_root,
            "redaction_policy_root": self.redaction_policy_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "byte_length": self.byte_length,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-CALLDATA-PRIVACY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.envelope_id,
            "private contract release gate calldata envelope_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate calldata contract_id",
        )?;
        ensure_non_empty(
            &self.call_selector_root,
            "private contract release gate calldata call_selector_root",
        )?;
        ensure_non_empty(
            &self.encrypted_calldata_root,
            "private contract release gate calldata encrypted_calldata_root",
        )?;
        ensure_non_empty(
            &self.privacy_budget_root,
            "private contract release gate calldata privacy_budget_root",
        )?;
        ensure_non_empty(
            &self.redaction_policy_root,
            "private contract release gate calldata redaction_policy_root",
        )?;
        ensure_positive(
            self.submitted_at_height,
            "private contract release gate calldata submitted_at_height",
        )?;
        ensure_positive(
            self.expires_at_height,
            "private contract release gate calldata expires_at_height",
        )?;
        ensure_positive(
            self.byte_length,
            "private contract release gate calldata byte_length",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate calldata status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessAvailabilityClaim {
    pub claim_id: String,
    pub contract_id: String,
    pub witness_root: String,
    pub provider_set_root: String,
    pub availability_attestation_root: String,
    pub repair_policy_root: String,
    pub available_from_height: u64,
    pub available_until_height: u64,
    pub replica_count: u64,
    pub release_status: ReleaseStatus,
}

impl WitnessAvailabilityClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_witness",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "contract_id": self.contract_id,
            "witness_root": self.witness_root,
            "provider_set_root": self.provider_set_root,
            "availability_attestation_root": self.availability_attestation_root,
            "repair_policy_root": self.repair_policy_root,
            "available_from_height": self.available_from_height,
            "available_until_height": self.available_until_height,
            "replica_count": self.replica_count,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-WITNESS-AVAILABILITY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.claim_id,
            "private contract release gate witness claim_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate witness contract_id",
        )?;
        ensure_non_empty(
            &self.witness_root,
            "private contract release gate witness witness_root",
        )?;
        ensure_non_empty(
            &self.provider_set_root,
            "private contract release gate witness provider_set_root",
        )?;
        ensure_non_empty(
            &self.availability_attestation_root,
            "private contract release gate witness availability_attestation_root",
        )?;
        ensure_non_empty(
            &self.repair_policy_root,
            "private contract release gate witness repair_policy_root",
        )?;
        ensure_positive(
            self.available_from_height,
            "private contract release gate witness available_from_height",
        )?;
        ensure_positive(
            self.available_until_height,
            "private contract release gate witness available_until_height",
        )?;
        ensure_positive(
            self.replica_count,
            "private contract release gate witness replica_count",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate witness status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCallAuthorization {
    pub authorization_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub session_policy_root: String,
    pub authorized_from_height: u64,
    pub authorized_until_height: u64,
    pub call_limit: u64,
    pub release_status: ReleaseStatus,
}

impl PqCallAuthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_pq_authorization",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "session_policy_root": self.session_policy_root,
            "authorized_from_height": self.authorized_from_height,
            "authorized_until_height": self.authorized_until_height,
            "call_limit": self.call_limit,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-PQ-CALL-AUTHORIZATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.authorization_id,
            "private contract release gate pq_authorization authorization_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate pq_authorization contract_id",
        )?;
        ensure_non_empty(
            &self.caller_commitment,
            "private contract release gate pq_authorization caller_commitment",
        )?;
        ensure_non_empty(
            &self.pq_public_key_root,
            "private contract release gate pq_authorization pq_public_key_root",
        )?;
        ensure_non_empty(
            &self.signature_root,
            "private contract release gate pq_authorization signature_root",
        )?;
        ensure_non_empty(
            &self.session_policy_root,
            "private contract release gate pq_authorization session_policy_root",
        )?;
        ensure_positive(
            self.authorized_from_height,
            "private contract release gate pq_authorization authorized_from_height",
        )?;
        ensure_positive(
            self.authorized_until_height,
            "private contract release gate pq_authorization authorized_until_height",
        )?;
        ensure_positive(
            self.call_limit,
            "private contract release gate pq_authorization call_limit",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate pq_authorization status is not releasable"
                    .to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRentCompressionPlan {
    pub plan_id: String,
    pub contract_id: String,
    pub pre_compression_root: String,
    pub post_compression_root: String,
    pub rent_bucket_root: String,
    pub eviction_policy_root: String,
    pub scheduled_at_height: u64,
    pub applies_at_height: u64,
    pub saved_bytes: u64,
    pub release_status: ReleaseStatus,
}

impl StateRentCompressionPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_state_rent",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "contract_id": self.contract_id,
            "pre_compression_root": self.pre_compression_root,
            "post_compression_root": self.post_compression_root,
            "rent_bucket_root": self.rent_bucket_root,
            "eviction_policy_root": self.eviction_policy_root,
            "scheduled_at_height": self.scheduled_at_height,
            "applies_at_height": self.applies_at_height,
            "saved_bytes": self.saved_bytes,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-STATE-RENT-COMPRESSION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.plan_id,
            "private contract release gate state_rent plan_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate state_rent contract_id",
        )?;
        ensure_non_empty(
            &self.pre_compression_root,
            "private contract release gate state_rent pre_compression_root",
        )?;
        ensure_non_empty(
            &self.post_compression_root,
            "private contract release gate state_rent post_compression_root",
        )?;
        ensure_non_empty(
            &self.rent_bucket_root,
            "private contract release gate state_rent rent_bucket_root",
        )?;
        ensure_non_empty(
            &self.eviction_policy_root,
            "private contract release gate state_rent eviction_policy_root",
        )?;
        ensure_positive(
            self.scheduled_at_height,
            "private contract release gate state_rent scheduled_at_height",
        )?;
        ensure_positive(
            self.applies_at_height,
            "private contract release gate state_rent applies_at_height",
        )?;
        ensure_positive(
            self.saved_bytes,
            "private contract release gate state_rent saved_bytes",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate state_rent status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossShardSchedule {
    pub schedule_id: String,
    pub contract_id: String,
    pub source_shard: String,
    pub target_shard: String,
    pub dependency_root: String,
    pub sequencing_root: String,
    pub scheduled_for_height: u64,
    pub deadline_height: u64,
    pub priority_units: u64,
    pub release_status: ReleaseStatus,
}

impl CrossShardSchedule {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_schedule",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "schedule_id": self.schedule_id,
            "contract_id": self.contract_id,
            "source_shard": self.source_shard,
            "target_shard": self.target_shard,
            "dependency_root": self.dependency_root,
            "sequencing_root": self.sequencing_root,
            "scheduled_for_height": self.scheduled_for_height,
            "deadline_height": self.deadline_height,
            "priority_units": self.priority_units,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-CROSS-SHARD-SCHEDULE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.schedule_id,
            "private contract release gate schedule schedule_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate schedule contract_id",
        )?;
        ensure_non_empty(
            &self.source_shard,
            "private contract release gate schedule source_shard",
        )?;
        ensure_non_empty(
            &self.target_shard,
            "private contract release gate schedule target_shard",
        )?;
        ensure_non_empty(
            &self.dependency_root,
            "private contract release gate schedule dependency_root",
        )?;
        ensure_non_empty(
            &self.sequencing_root,
            "private contract release gate schedule sequencing_root",
        )?;
        ensure_positive(
            self.scheduled_for_height,
            "private contract release gate schedule scheduled_for_height",
        )?;
        ensure_positive(
            self.deadline_height,
            "private contract release gate schedule deadline_height",
        )?;
        ensure_positive(
            self.priority_units,
            "private contract release gate schedule priority_units",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate schedule status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSignoff {
    pub signoff_id: String,
    pub contract_id: String,
    pub auditor_committee_root: String,
    pub finding_root: String,
    pub exception_root: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub severity_floor_bps: u64,
    pub release_status: ReleaseStatus,
}

impl AuditSignoff {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_audit",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "signoff_id": self.signoff_id,
            "contract_id": self.contract_id,
            "auditor_committee_root": self.auditor_committee_root,
            "finding_root": self.finding_root,
            "exception_root": self.exception_root,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "severity_floor_bps": self.severity_floor_bps,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-AUDIT-SIGNOFF",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.signoff_id,
            "private contract release gate audit signoff_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate audit contract_id",
        )?;
        ensure_non_empty(
            &self.auditor_committee_root,
            "private contract release gate audit auditor_committee_root",
        )?;
        ensure_non_empty(
            &self.finding_root,
            "private contract release gate audit finding_root",
        )?;
        ensure_non_empty(
            &self.exception_root,
            "private contract release gate audit exception_root",
        )?;
        ensure_non_empty(
            &self.signature_root,
            "private contract release gate audit signature_root",
        )?;
        ensure_positive(
            self.signed_at_height,
            "private contract release gate audit signed_at_height",
        )?;
        ensure_positive(
            self.expires_at_height,
            "private contract release gate audit expires_at_height",
        )?;
        ensure_positive(
            self.severity_floor_bps,
            "private contract release gate audit severity_floor_bps",
        )?;
        if !self.release_status.releasable() {
            return Err("private contract release gate audit status is not releasable".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackWindow {
    pub window_id: String,
    pub contract_id: String,
    pub checkpoint_root: String,
    pub rollback_authority_root: String,
    pub freeze_policy_root: String,
    pub notification_root: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub bond_units: u64,
    pub release_status: ReleaseStatus,
}

impl RollbackWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_rollback",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "contract_id": self.contract_id,
            "checkpoint_root": self.checkpoint_root,
            "rollback_authority_root": self.rollback_authority_root,
            "freeze_policy_root": self.freeze_policy_root,
            "notification_root": self.notification_root,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "bond_units": self.bond_units,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-ROLLBACK-WINDOW",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.window_id,
            "private contract release gate rollback window_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate rollback contract_id",
        )?;
        ensure_non_empty(
            &self.checkpoint_root,
            "private contract release gate rollback checkpoint_root",
        )?;
        ensure_non_empty(
            &self.rollback_authority_root,
            "private contract release gate rollback rollback_authority_root",
        )?;
        ensure_non_empty(
            &self.freeze_policy_root,
            "private contract release gate rollback freeze_policy_root",
        )?;
        ensure_non_empty(
            &self.notification_root,
            "private contract release gate rollback notification_root",
        )?;
        ensure_positive(
            self.opens_at_height,
            "private contract release gate rollback opens_at_height",
        )?;
        ensure_positive(
            self.closes_at_height,
            "private contract release gate rollback closes_at_height",
        )?;
        ensure_positive(
            self.bond_units,
            "private contract release gate rollback bond_units",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate rollback status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCapEnforcement {
    pub fee_cap_id: String,
    pub contract_id: String,
    pub fee_asset_id: String,
    pub cap_policy_root: String,
    pub rebate_pool_root: String,
    pub sponsor_root: String,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub max_fee_micro_units: u64,
    pub release_status: ReleaseStatus,
}

impl FeeCapEnforcement {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_fee_cap",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "fee_cap_id": self.fee_cap_id,
            "contract_id": self.contract_id,
            "fee_asset_id": self.fee_asset_id,
            "cap_policy_root": self.cap_policy_root,
            "rebate_pool_root": self.rebate_pool_root,
            "sponsor_root": self.sponsor_root,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "max_fee_micro_units": self.max_fee_micro_units,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-FEE-CAP-ENFORCEMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.fee_cap_id,
            "private contract release gate fee_cap fee_cap_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate fee_cap contract_id",
        )?;
        ensure_non_empty(
            &self.fee_asset_id,
            "private contract release gate fee_cap fee_asset_id",
        )?;
        ensure_non_empty(
            &self.cap_policy_root,
            "private contract release gate fee_cap cap_policy_root",
        )?;
        ensure_non_empty(
            &self.rebate_pool_root,
            "private contract release gate fee_cap rebate_pool_root",
        )?;
        ensure_non_empty(
            &self.sponsor_root,
            "private contract release gate fee_cap sponsor_root",
        )?;
        ensure_positive(
            self.active_from_height,
            "private contract release gate fee_cap active_from_height",
        )?;
        ensure_positive(
            self.active_until_height,
            "private contract release gate fee_cap active_until_height",
        )?;
        ensure_positive(
            self.max_fee_micro_units,
            "private contract release gate fee_cap max_fee_micro_units",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate fee_cap status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseDecision {
    pub decision_id: String,
    pub contract_id: String,
    pub gate_bundle_root: String,
    pub approver_root: String,
    pub risk_score_root: String,
    pub public_notice_root: String,
    pub decided_at_height: u64,
    pub valid_until_height: u64,
    pub release_epoch: u64,
    pub release_status: ReleaseStatus,
}

impl ReleaseDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_decision",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "decision_id": self.decision_id,
            "contract_id": self.contract_id,
            "gate_bundle_root": self.gate_bundle_root,
            "approver_root": self.approver_root,
            "risk_score_root": self.risk_score_root,
            "public_notice_root": self.public_notice_root,
            "decided_at_height": self.decided_at_height,
            "valid_until_height": self.valid_until_height,
            "release_epoch": self.release_epoch,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-RELEASE-DECISION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.decision_id,
            "private contract release gate decision decision_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate decision contract_id",
        )?;
        ensure_non_empty(
            &self.gate_bundle_root,
            "private contract release gate decision gate_bundle_root",
        )?;
        ensure_non_empty(
            &self.approver_root,
            "private contract release gate decision approver_root",
        )?;
        ensure_non_empty(
            &self.risk_score_root,
            "private contract release gate decision risk_score_root",
        )?;
        ensure_non_empty(
            &self.public_notice_root,
            "private contract release gate decision public_notice_root",
        )?;
        ensure_positive(
            self.decided_at_height,
            "private contract release gate decision decided_at_height",
        )?;
        ensure_positive(
            self.valid_until_height,
            "private contract release gate decision valid_until_height",
        )?;
        ensure_positive(
            self.release_epoch,
            "private contract release gate decision release_epoch",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate decision status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateTelemetryEvent {
    pub event_id: String,
    pub contract_id: String,
    pub metric_root: String,
    pub counter_root: String,
    pub operator_root: String,
    pub evidence_root: String,
    pub observed_at_height: u64,
    pub reported_at_height: u64,
    pub weight_units: u64,
    pub release_status: ReleaseStatus,
}

impl GateTelemetryEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_telemetry",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "contract_id": self.contract_id,
            "metric_root": self.metric_root,
            "counter_root": self.counter_root,
            "operator_root": self.operator_root,
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height,
            "reported_at_height": self.reported_at_height,
            "weight_units": self.weight_units,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-GATE-TELEMETRY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.event_id,
            "private contract release gate telemetry event_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate telemetry contract_id",
        )?;
        ensure_non_empty(
            &self.metric_root,
            "private contract release gate telemetry metric_root",
        )?;
        ensure_non_empty(
            &self.counter_root,
            "private contract release gate telemetry counter_root",
        )?;
        ensure_non_empty(
            &self.operator_root,
            "private contract release gate telemetry operator_root",
        )?;
        ensure_non_empty(
            &self.evidence_root,
            "private contract release gate telemetry evidence_root",
        )?;
        ensure_positive(
            self.observed_at_height,
            "private contract release gate telemetry observed_at_height",
        )?;
        ensure_positive(
            self.reported_at_height,
            "private contract release gate telemetry reported_at_height",
        )?;
        ensure_positive(
            self.weight_units,
            "private contract release gate telemetry weight_units",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate telemetry status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicReleaseReceipt {
    pub receipt_id: String,
    pub contract_id: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub released_by_root: String,
    pub settlement_root: String,
    pub released_at_height: u64,
    pub finalized_at_height: u64,
    pub fee_charged_micro_units: u64,
    pub release_status: ReleaseStatus,
}

impl DeterministicReleaseReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_receipt",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "contract_id": self.contract_id,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "released_by_root": self.released_by_root,
            "settlement_root": self.settlement_root,
            "released_at_height": self.released_at_height,
            "finalized_at_height": self.finalized_at_height,
            "fee_charged_micro_units": self.fee_charged_micro_units,
            "release_status": self.release_status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-RELEASE-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_non_empty(
            &self.receipt_id,
            "private contract release gate receipt receipt_id",
        )?;
        ensure_non_empty(
            &self.contract_id,
            "private contract release gate receipt contract_id",
        )?;
        ensure_non_empty(
            &self.state_root_before,
            "private contract release gate receipt state_root_before",
        )?;
        ensure_non_empty(
            &self.state_root_after,
            "private contract release gate receipt state_root_after",
        )?;
        ensure_non_empty(
            &self.released_by_root,
            "private contract release gate receipt released_by_root",
        )?;
        ensure_non_empty(
            &self.settlement_root,
            "private contract release gate receipt settlement_root",
        )?;
        ensure_positive(
            self.released_at_height,
            "private contract release gate receipt released_at_height",
        )?;
        ensure_positive(
            self.finalized_at_height,
            "private contract release gate receipt finalized_at_height",
        )?;
        ensure_positive(
            self.fee_charged_micro_units,
            "private contract release gate receipt fee_charged_micro_units",
        )?;
        if !self.release_status.releasable() {
            return Err(
                "private contract release gate receipt status is not releasable".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub manifest_root: String,
    pub calldata_root: String,
    pub witness_root: String,
    pub pq_authorization_root: String,
    pub state_rent_root: String,
    pub schedule_root: String,
    pub audit_root: String,
    pub rollback_root: String,
    pub fee_cap_root: String,
    pub decision_root: String,
    pub telemetry_root: String,
    pub receipt_root: String,
    pub aggregate_gate_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_roots",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "manifest_root": self.manifest_root,
            "calldata_root": self.calldata_root,
            "witness_root": self.witness_root,
            "pq_authorization_root": self.pq_authorization_root,
            "state_rent_root": self.state_rent_root,
            "schedule_root": self.schedule_root,
            "audit_root": self.audit_root,
            "rollback_root": self.rollback_root,
            "fee_cap_root": self.fee_cap_root,
            "decision_root": self.decision_root,
            "telemetry_root": self.telemetry_root,
            "receipt_root": self.receipt_root,
            "aggregate_gate_root": self.aggregate_gate_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub height: u64,
    pub bytecode_manifests_count: u64,
    pub calldata_envelopes_count: u64,
    pub witness_claims_count: u64,
    pub pq_authorizations_count: u64,
    pub state_rent_plans_count: u64,
    pub cross_shard_schedules_count: u64,
    pub audit_signoffs_count: u64,
    pub rollback_windows_count: u64,
    pub fee_cap_enforcements_count: u64,
    pub release_decisions_count: u64,
    pub telemetry_events_count: u64,
    pub release_receipts_count: u64,
    pub approved_gate_count: u64,
    pub released_gate_count: u64,
    pub blocked_gate_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_release_gate_counters",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "height": self.height,
            "bytecode_manifests_count": self.bytecode_manifests_count,
            "calldata_envelopes_count": self.calldata_envelopes_count,
            "witness_claims_count": self.witness_claims_count,
            "pq_authorizations_count": self.pq_authorizations_count,
            "state_rent_plans_count": self.state_rent_plans_count,
            "cross_shard_schedules_count": self.cross_shard_schedules_count,
            "audit_signoffs_count": self.audit_signoffs_count,
            "rollback_windows_count": self.rollback_windows_count,
            "fee_cap_enforcements_count": self.fee_cap_enforcements_count,
            "release_decisions_count": self.release_decisions_count,
            "telemetry_events_count": self.telemetry_events_count,
            "release_receipts_count": self.release_receipts_count,
            "approved_gate_count": self.approved_gate_count,
            "released_gate_count": self.released_gate_count,
            "blocked_gate_count": self.blocked_gate_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub bytecode_manifests: BTreeMap<String, BytecodeManifest>,
    pub calldata_envelopes: BTreeMap<String, CalldataPrivacyEnvelope>,
    pub witness_claims: BTreeMap<String, WitnessAvailabilityClaim>,
    pub pq_authorizations: BTreeMap<String, PqCallAuthorization>,
    pub state_rent_plans: BTreeMap<String, StateRentCompressionPlan>,
    pub cross_shard_schedules: BTreeMap<String, CrossShardSchedule>,
    pub audit_signoffs: BTreeMap<String, AuditSignoff>,
    pub rollback_windows: BTreeMap<String, RollbackWindow>,
    pub fee_cap_enforcements: BTreeMap<String, FeeCapEnforcement>,
    pub release_decisions: BTreeMap<String, ReleaseDecision>,
    pub telemetry_events: BTreeMap<String, GateTelemetryEvent>,
    pub release_receipts: BTreeMap<String, DeterministicReleaseReceipt>,
}

impl State {
    pub fn devnet() -> PrivateContractReleaseGateResult<State> {
        let config = Config::devnet()?;
        let mut state = State {
            height: 1,
            config,
            bytecode_manifests: BTreeMap::new(),
            calldata_envelopes: BTreeMap::new(),
            witness_claims: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            state_rent_plans: BTreeMap::new(),
            cross_shard_schedules: BTreeMap::new(),
            audit_signoffs: BTreeMap::new(),
            rollback_windows: BTreeMap::new(),
            fee_cap_enforcements: BTreeMap::new(),
            release_decisions: BTreeMap::new(),
            telemetry_events: BTreeMap::new(),
            release_receipts: BTreeMap::new(),
        };
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractReleaseGateResult<()> {
        ensure_positive(height, "private contract release gate height")?;
        self.height = height;
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> PrivateContractReleaseGateResult<()> {
        if height < self.height {
            return Err("private contract release gate height cannot move backward".to_string());
        }
        self.set_height(height)
    }

    pub fn insert_manifest(
        &mut self,
        record: BytecodeManifest,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.bytecode_manifests
            .insert(record.manifest_id.clone(), record);
        Ok(root)
    }

    pub fn insert_calldata(
        &mut self,
        record: CalldataPrivacyEnvelope,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.calldata_envelopes
            .insert(record.envelope_id.clone(), record);
        Ok(root)
    }

    pub fn insert_witness(
        &mut self,
        record: WitnessAvailabilityClaim,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.witness_claims.insert(record.claim_id.clone(), record);
        Ok(root)
    }

    pub fn insert_pq_authorization(
        &mut self,
        record: PqCallAuthorization,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.pq_authorizations
            .insert(record.authorization_id.clone(), record);
        Ok(root)
    }

    pub fn insert_state_rent(
        &mut self,
        record: StateRentCompressionPlan,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.state_rent_plans.insert(record.plan_id.clone(), record);
        Ok(root)
    }

    pub fn insert_schedule(
        &mut self,
        record: CrossShardSchedule,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.cross_shard_schedules
            .insert(record.schedule_id.clone(), record);
        Ok(root)
    }

    pub fn insert_audit(
        &mut self,
        record: AuditSignoff,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.audit_signoffs
            .insert(record.signoff_id.clone(), record);
        Ok(root)
    }

    pub fn insert_rollback(
        &mut self,
        record: RollbackWindow,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.rollback_windows
            .insert(record.window_id.clone(), record);
        Ok(root)
    }

    pub fn insert_fee_cap(
        &mut self,
        record: FeeCapEnforcement,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.fee_cap_enforcements
            .insert(record.fee_cap_id.clone(), record);
        Ok(root)
    }

    pub fn insert_decision(
        &mut self,
        record: ReleaseDecision,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.release_decisions
            .insert(record.decision_id.clone(), record);
        Ok(root)
    }

    pub fn insert_telemetry(
        &mut self,
        record: GateTelemetryEvent,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.telemetry_events
            .insert(record.event_id.clone(), record);
        Ok(root)
    }

    pub fn insert_receipt(
        &mut self,
        record: DeterministicReleaseReceipt,
    ) -> PrivateContractReleaseGateResult<String> {
        let root = record.validate()?;
        self.release_receipts
            .insert(record.receipt_id.clone(), record);
        Ok(root)
    }

    pub fn roots(&self) -> Roots {
        let manifest_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-BYTECODE-MANIFEST-ROOT",
            &self.bytecode_manifests,
        );
        let calldata_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-CALLDATA-PRIVACY-ROOT",
            &self.calldata_envelopes,
        );
        let witness_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-WITNESS-AVAILABILITY-ROOT",
            &self.witness_claims,
        );
        let pq_authorization_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-PQ-CALL-AUTHORIZATION-ROOT",
            &self.pq_authorizations,
        );
        let state_rent_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-STATE-RENT-COMPRESSION-ROOT",
            &self.state_rent_plans,
        );
        let schedule_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-CROSS-SHARD-SCHEDULE-ROOT",
            &self.cross_shard_schedules,
        );
        let audit_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-AUDIT-SIGNOFF-ROOT",
            &self.audit_signoffs,
        );
        let rollback_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-ROLLBACK-WINDOW-ROOT",
            &self.rollback_windows,
        );
        let fee_cap_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-FEE-CAP-ENFORCEMENT-ROOT",
            &self.fee_cap_enforcements,
        );
        let decision_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-RELEASE-DECISION-ROOT",
            &self.release_decisions,
        );
        let telemetry_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-GATE-TELEMETRY-ROOT",
            &self.telemetry_events,
        );
        let receipt_root = map_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-RELEASE-RECEIPT-ROOT",
            &self.release_receipts,
        );
        let config_root = self.config.root();
        let aggregate_gate_record = json!({
            "config_root": config_root,
            "manifest_root": manifest_root,
            "calldata_root": calldata_root,
            "witness_root": witness_root,
            "pq_authorization_root": pq_authorization_root,
            "state_rent_root": state_rent_root,
            "schedule_root": schedule_root,
            "audit_root": audit_root,
            "rollback_root": rollback_root,
            "fee_cap_root": fee_cap_root,
            "decision_root": decision_root,
            "telemetry_root": telemetry_root,
            "receipt_root": receipt_root,
        });
        Roots {
            config_root,
            manifest_root,
            calldata_root,
            witness_root,
            pq_authorization_root,
            state_rent_root,
            schedule_root,
            audit_root,
            rollback_root,
            fee_cap_root,
            decision_root,
            telemetry_root,
            receipt_root,
            aggregate_gate_root: record_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-AGGREGATE",
                &aggregate_gate_record,
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        let approved_gate_count = self
            .release_decisions
            .values()
            .filter(|record| record.release_status == ReleaseStatus::Approved)
            .count() as u64;
        let released_gate_count = self
            .release_decisions
            .values()
            .filter(|record| record.release_status == ReleaseStatus::Released)
            .count() as u64;
        let blocked_gate_count = self
            .release_decisions
            .values()
            .filter(|record| {
                matches!(
                    record.release_status,
                    ReleaseStatus::Rejected | ReleaseStatus::Expired | ReleaseStatus::RolledBack
                )
            })
            .count() as u64;
        Counters {
            height: self.height,
            bytecode_manifests_count: self.bytecode_manifests.len() as u64,
            calldata_envelopes_count: self.calldata_envelopes.len() as u64,
            witness_claims_count: self.witness_claims.len() as u64,
            pq_authorizations_count: self.pq_authorizations.len() as u64,
            state_rent_plans_count: self.state_rent_plans.len() as u64,
            cross_shard_schedules_count: self.cross_shard_schedules.len() as u64,
            audit_signoffs_count: self.audit_signoffs.len() as u64,
            rollback_windows_count: self.rollback_windows.len() as u64,
            fee_cap_enforcements_count: self.fee_cap_enforcements.len() as u64,
            release_decisions_count: self.release_decisions.len() as u64,
            telemetry_events_count: self.telemetry_events.len() as u64,
            release_receipts_count: self.release_receipts.len() as u64,
            approved_gate_count,
            released_gate_count,
            blocked_gate_count,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_contract_release_gate_state",
            "protocol_version": PRIVATE_CONTRACT_RELEASE_GATE_PROTOCOL_VERSION,
            "schema_version": PRIVATE_CONTRACT_RELEASE_GATE_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "bytecode_manifests": self.bytecode_manifests.values().map(BytecodeManifest::public_record).collect::<Vec<_>>(),
            "calldata_envelopes": self.calldata_envelopes.values().map(CalldataPrivacyEnvelope::public_record).collect::<Vec<_>>(),
            "witness_claims": self.witness_claims.values().map(WitnessAvailabilityClaim::public_record).collect::<Vec<_>>(),
            "pq_authorizations": self.pq_authorizations.values().map(PqCallAuthorization::public_record).collect::<Vec<_>>(),
            "state_rent_plans": self.state_rent_plans.values().map(StateRentCompressionPlan::public_record).collect::<Vec<_>>(),
            "cross_shard_schedules": self.cross_shard_schedules.values().map(CrossShardSchedule::public_record).collect::<Vec<_>>(),
            "audit_signoffs": self.audit_signoffs.values().map(AuditSignoff::public_record).collect::<Vec<_>>(),
            "rollback_windows": self.rollback_windows.values().map(RollbackWindow::public_record).collect::<Vec<_>>(),
            "fee_cap_enforcements": self.fee_cap_enforcements.values().map(FeeCapEnforcement::public_record).collect::<Vec<_>>(),
            "release_decisions": self.release_decisions.values().map(ReleaseDecision::public_record).collect::<Vec<_>>(),
            "telemetry_events": self.telemetry_events.values().map(GateTelemetryEvent::public_record).collect::<Vec<_>>(),
            "release_receipts": self.release_receipts.values().map(DeterministicReleaseReceipt::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateContractReleaseGateResult<String> {
        ensure_positive(self.height, "private contract release gate state height")?;
        self.config.validate()?;
        ensure_limit(
            self.bytecode_manifests.len(),
            "private contract release gate bytecode manifests",
        )?;
        ensure_limit(
            self.calldata_envelopes.len(),
            "private contract release gate calldata envelopes",
        )?;
        ensure_limit(
            self.witness_claims.len(),
            "private contract release gate witness claims",
        )?;
        ensure_limit(
            self.pq_authorizations.len(),
            "private contract release gate pq authorizations",
        )?;
        ensure_limit(
            self.state_rent_plans.len(),
            "private contract release gate state rent plans",
        )?;
        ensure_limit(
            self.cross_shard_schedules.len(),
            "private contract release gate cross shard schedules",
        )?;
        ensure_limit(
            self.audit_signoffs.len(),
            "private contract release gate audit signoffs",
        )?;
        ensure_limit(
            self.rollback_windows.len(),
            "private contract release gate rollback windows",
        )?;
        ensure_limit(
            self.fee_cap_enforcements.len(),
            "private contract release gate fee cap enforcements",
        )?;
        ensure_limit(
            self.release_decisions.len(),
            "private contract release gate release decisions",
        )?;
        ensure_limit(
            self.telemetry_events.len(),
            "private contract release gate telemetry events",
        )?;
        ensure_limit(
            self.release_receipts.len(),
            "private contract release gate release receipts",
        )?;
        for record in self.bytecode_manifests.values() {
            record.validate()?;
        }
        for record in self.calldata_envelopes.values() {
            record.validate()?;
        }
        for record in self.witness_claims.values() {
            record.validate()?;
        }
        for record in self.pq_authorizations.values() {
            record.validate()?;
        }
        for record in self.state_rent_plans.values() {
            record.validate()?;
        }
        for record in self.cross_shard_schedules.values() {
            record.validate()?;
        }
        for record in self.audit_signoffs.values() {
            record.validate()?;
        }
        for record in self.rollback_windows.values() {
            record.validate()?;
        }
        for record in self.fee_cap_enforcements.values() {
            record.validate()?;
        }
        for record in self.release_decisions.values() {
            record.validate()?;
        }
        for record in self.telemetry_events.values() {
            record.validate()?;
        }
        for record in self.release_receipts.values() {
            record.validate()?;
        }
        self.validate_release_links()?;
        Ok(self.state_root())
    }

    fn validate_release_links(&self) -> PrivateContractReleaseGateResult<()> {
        for decision in self.release_decisions.values() {
            if !self
                .bytecode_manifests
                .values()
                .any(|record| record.contract_id == decision.contract_id)
            {
                return Err(
                    "private contract release gate decision missing bytecode manifest".to_string(),
                );
            }
            if !self
                .calldata_envelopes
                .values()
                .any(|record| record.contract_id == decision.contract_id)
            {
                return Err(
                    "private contract release gate decision missing calldata envelope".to_string(),
                );
            }
            if !self
                .witness_claims
                .values()
                .any(|record| record.contract_id == decision.contract_id)
            {
                return Err(
                    "private contract release gate decision missing witness claim".to_string(),
                );
            }
            if !self
                .pq_authorizations
                .values()
                .any(|record| record.contract_id == decision.contract_id)
            {
                return Err(
                    "private contract release gate decision missing pq authorization".to_string(),
                );
            }
            if !self
                .audit_signoffs
                .values()
                .any(|record| record.contract_id == decision.contract_id)
            {
                return Err(
                    "private contract release gate decision missing audit signoff".to_string(),
                );
            }
            if !self
                .fee_cap_enforcements
                .values()
                .any(|record| record.contract_id == decision.contract_id)
            {
                return Err(
                    "private contract release gate decision missing fee cap enforcement"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    fn seed_devnet_records(&mut self) -> PrivateContractReleaseGateResult<()> {
        let contract_id = string_root(
            "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CONTRACT",
            "private-vault-router-v1",
        );
        self.insert_manifest(BytecodeManifest {
            manifest_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-BYTECODE-MANIFEST-MANIFEST-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            bytecode_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-BYTECODE-MANIFEST-BYTECODE-ROOT",
                contract_id.as_str(),
            ),
            abi_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-BYTECODE-MANIFEST-ABI-ROOT",
                contract_id.as_str(),
            ),
            compiler_fingerprint: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-BYTECODE-MANIFEST-COMPILER-FINGERPRINT",
                contract_id.as_str(),
            ),
            version_label: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-BYTECODE-MANIFEST-VERSION-LABEL",
                contract_id.as_str(),
            ),
            declared_at_height: self.height,
            effective_from_height: self.height,
            max_runtime_bytes: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_calldata(CalldataPrivacyEnvelope {
            envelope_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CALLDATA-PRIVACY-ENVELOPE-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            call_selector_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CALLDATA-PRIVACY-CALL-SELECTOR-ROOT",
                contract_id.as_str(),
            ),
            encrypted_calldata_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CALLDATA-PRIVACY-ENCRYPTED-CALLDATA-ROOT",
                contract_id.as_str(),
            ),
            privacy_budget_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CALLDATA-PRIVACY-PRIVACY-BUDGET-ROOT",
                contract_id.as_str(),
            ),
            redaction_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CALLDATA-PRIVACY-REDACTION-POLICY-ROOT",
                contract_id.as_str(),
            ),
            submitted_at_height: self.height,
            expires_at_height: self.height + 144,
            byte_length: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_witness(WitnessAvailabilityClaim {
            claim_id: string_root("PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-WITNESS-AVAILABILITY-CLAIM-ID", contract_id.as_str()),
            contract_id: contract_id.clone(),
            witness_root: string_root("PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-WITNESS-AVAILABILITY-WITNESS-ROOT", contract_id.as_str()),
            provider_set_root: string_root("PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-WITNESS-AVAILABILITY-PROVIDER-SET-ROOT", contract_id.as_str()),
            availability_attestation_root: string_root("PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-WITNESS-AVAILABILITY-AVAILABILITY-ATTESTATION-ROOT", contract_id.as_str()),
            repair_policy_root: string_root("PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-WITNESS-AVAILABILITY-REPAIR-POLICY-ROOT", contract_id.as_str()),
            available_from_height: self.height,
            available_until_height: self.height + 144,
            replica_count: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_pq_authorization(PqCallAuthorization {
            authorization_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-PQ-CALL-AUTHORIZATION-AUTHORIZATION-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            caller_commitment: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-PQ-CALL-AUTHORIZATION-CALLER-COMMITMENT",
                contract_id.as_str(),
            ),
            pq_public_key_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-PQ-CALL-AUTHORIZATION-PQ-PUBLIC-KEY-ROOT",
                contract_id.as_str(),
            ),
            signature_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-PQ-CALL-AUTHORIZATION-SIGNATURE-ROOT",
                contract_id.as_str(),
            ),
            session_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-PQ-CALL-AUTHORIZATION-SESSION-POLICY-ROOT",
                contract_id.as_str(),
            ),
            authorized_from_height: self.height,
            authorized_until_height: self.height + 144,
            call_limit: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_state_rent(StateRentCompressionPlan {
            plan_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-STATE-RENT-COMPRESSION-PLAN-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            pre_compression_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-STATE-RENT-COMPRESSION-PRE-COMPRESSION-ROOT",
                contract_id.as_str(),
            ),
            post_compression_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-STATE-RENT-COMPRESSION-POST-COMPRESSION-ROOT",
                contract_id.as_str(),
            ),
            rent_bucket_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-STATE-RENT-COMPRESSION-RENT-BUCKET-ROOT",
                contract_id.as_str(),
            ),
            eviction_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-STATE-RENT-COMPRESSION-EVICTION-POLICY-ROOT",
                contract_id.as_str(),
            ),
            scheduled_at_height: self.height,
            applies_at_height: self.height,
            saved_bytes: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_schedule(CrossShardSchedule {
            schedule_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CROSS-SHARD-SCHEDULE-SCHEDULE-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            source_shard: "devnet-source-shard".to_string(),
            target_shard: "devnet-target-shard".to_string(),
            dependency_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CROSS-SHARD-SCHEDULE-DEPENDENCY-ROOT",
                contract_id.as_str(),
            ),
            sequencing_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-CROSS-SHARD-SCHEDULE-SEQUENCING-ROOT",
                contract_id.as_str(),
            ),
            scheduled_for_height: self.height,
            deadline_height: self.height + 144,
            priority_units: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_audit(AuditSignoff {
            signoff_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-AUDIT-SIGNOFF-SIGNOFF-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            auditor_committee_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-AUDIT-SIGNOFF-AUDITOR-COMMITTEE-ROOT",
                contract_id.as_str(),
            ),
            finding_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-AUDIT-SIGNOFF-FINDING-ROOT",
                contract_id.as_str(),
            ),
            exception_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-AUDIT-SIGNOFF-EXCEPTION-ROOT",
                contract_id.as_str(),
            ),
            signature_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-AUDIT-SIGNOFF-SIGNATURE-ROOT",
                contract_id.as_str(),
            ),
            signed_at_height: self.height,
            expires_at_height: self.height + 144,
            severity_floor_bps: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_rollback(RollbackWindow {
            window_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-ROLLBACK-WINDOW-WINDOW-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            checkpoint_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-ROLLBACK-WINDOW-CHECKPOINT-ROOT",
                contract_id.as_str(),
            ),
            rollback_authority_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-ROLLBACK-WINDOW-ROLLBACK-AUTHORITY-ROOT",
                contract_id.as_str(),
            ),
            freeze_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-ROLLBACK-WINDOW-FREEZE-POLICY-ROOT",
                contract_id.as_str(),
            ),
            notification_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-ROLLBACK-WINDOW-NOTIFICATION-ROOT",
                contract_id.as_str(),
            ),
            opens_at_height: self.height,
            closes_at_height: self.height + 144,
            bond_units: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_fee_cap(FeeCapEnforcement {
            fee_cap_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-FEE-CAP-ENFORCEMENT-FEE-CAP-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            fee_asset_id: "xmr-fee-credit".to_string(),
            cap_policy_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-FEE-CAP-ENFORCEMENT-CAP-POLICY-ROOT",
                contract_id.as_str(),
            ),
            rebate_pool_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-FEE-CAP-ENFORCEMENT-REBATE-POOL-ROOT",
                contract_id.as_str(),
            ),
            sponsor_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-FEE-CAP-ENFORCEMENT-SPONSOR-ROOT",
                contract_id.as_str(),
            ),
            active_from_height: self.height,
            active_until_height: self.height + 144,
            max_fee_micro_units: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_decision(ReleaseDecision {
            decision_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-DECISION-DECISION-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            gate_bundle_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-DECISION-GATE-BUNDLE-ROOT",
                contract_id.as_str(),
            ),
            approver_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-DECISION-APPROVER-ROOT",
                contract_id.as_str(),
            ),
            risk_score_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-DECISION-RISK-SCORE-ROOT",
                contract_id.as_str(),
            ),
            public_notice_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-DECISION-PUBLIC-NOTICE-ROOT",
                contract_id.as_str(),
            ),
            decided_at_height: self.height,
            valid_until_height: self.height + 144,
            release_epoch: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_telemetry(GateTelemetryEvent {
            event_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-GATE-TELEMETRY-EVENT-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            metric_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-GATE-TELEMETRY-METRIC-ROOT",
                contract_id.as_str(),
            ),
            counter_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-GATE-TELEMETRY-COUNTER-ROOT",
                contract_id.as_str(),
            ),
            operator_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-GATE-TELEMETRY-OPERATOR-ROOT",
                contract_id.as_str(),
            ),
            evidence_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-GATE-TELEMETRY-EVIDENCE-ROOT",
                contract_id.as_str(),
            ),
            observed_at_height: self.height,
            reported_at_height: self.height,
            weight_units: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        self.insert_receipt(DeterministicReleaseReceipt {
            receipt_id: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-RECEIPT-RECEIPT-ID",
                contract_id.as_str(),
            ),
            contract_id: contract_id.clone(),
            state_root_before: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-RECEIPT-STATE-ROOT-BEFORE",
                contract_id.as_str(),
            ),
            state_root_after: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-RECEIPT-STATE-ROOT-AFTER",
                contract_id.as_str(),
            ),
            released_by_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-RECEIPT-RELEASED-BY-ROOT",
                contract_id.as_str(),
            ),
            settlement_root: string_root(
                "PRIVATE-CONTRACT-RELEASE-GATE-DEVNET-RELEASE-RECEIPT-SETTLEMENT-ROOT",
                contract_id.as_str(),
            ),
            released_at_height: self.height,
            finalized_at_height: self.height + 144,
            fee_charged_micro_units: 7,
            release_status: ReleaseStatus::Approved,
        })?;
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PrivateContractReleaseGateResult<State> {
    State::devnet()
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

fn id_from_parts(domain: &str, parts: &[&str]) -> String {
    let values = parts
        .iter()
        .map(|part| Value::String((*part).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &values)
}

fn map_root<T>(domain: &str, records: &BTreeMap<String, T>) -> String
where
    T: ReleaseGateRecord,
{
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub trait ReleaseGateRecord {
    fn public_record(&self) -> Value;
}

impl ReleaseGateRecord for BytecodeManifest {
    fn public_record(&self) -> Value {
        BytecodeManifest::public_record(self)
    }
}

impl ReleaseGateRecord for CalldataPrivacyEnvelope {
    fn public_record(&self) -> Value {
        CalldataPrivacyEnvelope::public_record(self)
    }
}

impl ReleaseGateRecord for WitnessAvailabilityClaim {
    fn public_record(&self) -> Value {
        WitnessAvailabilityClaim::public_record(self)
    }
}

impl ReleaseGateRecord for PqCallAuthorization {
    fn public_record(&self) -> Value {
        PqCallAuthorization::public_record(self)
    }
}

impl ReleaseGateRecord for StateRentCompressionPlan {
    fn public_record(&self) -> Value {
        StateRentCompressionPlan::public_record(self)
    }
}

impl ReleaseGateRecord for CrossShardSchedule {
    fn public_record(&self) -> Value {
        CrossShardSchedule::public_record(self)
    }
}

impl ReleaseGateRecord for AuditSignoff {
    fn public_record(&self) -> Value {
        AuditSignoff::public_record(self)
    }
}

impl ReleaseGateRecord for RollbackWindow {
    fn public_record(&self) -> Value {
        RollbackWindow::public_record(self)
    }
}

impl ReleaseGateRecord for FeeCapEnforcement {
    fn public_record(&self) -> Value {
        FeeCapEnforcement::public_record(self)
    }
}

impl ReleaseGateRecord for ReleaseDecision {
    fn public_record(&self) -> Value {
        ReleaseDecision::public_record(self)
    }
}

impl ReleaseGateRecord for GateTelemetryEvent {
    fn public_record(&self) -> Value {
        GateTelemetryEvent::public_record(self)
    }
}

impl ReleaseGateRecord for DeterministicReleaseReceipt {
    fn public_record(&self) -> Value {
        DeterministicReleaseReceipt::public_record(self)
    }
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateContractReleaseGateResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateContractReleaseGateResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_limit(value: usize, label: &str) -> PrivateContractReleaseGateResult<()> {
    if value > PRIVATE_CONTRACT_RELEASE_GATE_MAX_TRACKED_RECORDS {
        return Err(format!("{label} exceeds max tracked records"));
    }
    Ok(())
}

pub fn deterministic_release_gate_policy_marker_01(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-01",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_02(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-02",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_03(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-03",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_04(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-04",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_05(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-05",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_06(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-06",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_07(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-07",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_08(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-08",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_09(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-09",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_10(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-10",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_11(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-11",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_12(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-12",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_policy_marker_13(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-POLICY-MARKER-13",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_release_gate_marker_1517(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1517"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1525(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1525"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1533(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1533"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1541(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1541"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1549(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1549"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1557(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1557"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1565(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1565"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1573(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1573"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1581(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1581"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1589(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1589"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1597(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1597"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1605(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1605"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1613(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1613"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1621(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1621"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1629(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1629"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1637(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1637"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1645(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1645"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1653(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1653"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1661(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1661"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1669(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1669"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1677(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1677"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1685(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1685"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1693(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1693"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1701(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1701"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1709(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1709"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1717(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1717"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1725(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1725"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1733(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1733"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1741(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1741"),
        ],
        32,
    )
}

pub fn deterministic_release_gate_marker_1749(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RELEASE-GATE-DETERMINISTIC-MARKER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str("1749"),
        ],
        32,
    )
}
