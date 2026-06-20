use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_NAMESPACE_ISOLATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-namespace-isolation-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_DEPLOYER_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256s-confidential-contract-deployer-v1";
pub const SEALED_CONTRACT_ROOT_SUITE: &str = "ml-kem-1024+xwing-sealed-contract-root-v1";
pub const CALL_BOUNDARY_POLICY_SUITE: &str = "zk-pq-confidential-contract-call-boundary-policy-v1";
pub const STORAGE_ISOLATION_RECEIPT_SUITE: &str =
    "zk-confidential-contract-storage-isolation-receipt-v1";
pub const PRIVACY_REDACTION_BUDGET_SUITE: &str =
    "zk-private-contract-public-record-redaction-budget-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_936_000;
pub const DEVNET_EPOCH: u64 = 3_088;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceClass {
    Contract,
    Library,
    Paymaster,
    Oracle,
    BridgeAdapter,
    Governance,
    Emergency,
}

impl NamespaceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Library => "library",
            Self::Paymaster => "paymaster",
            Self::Oracle => "oracle",
            Self::BridgeAdapter => "bridge_adapter",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_lease_blocks(self) -> u64 {
        match self {
            Self::Contract => 720,
            Self::Library => 2_880,
            Self::Paymaster => 360,
            Self::Oracle => 240,
            Self::BridgeAdapter => 1_440,
            Self::Governance => 8_640,
            Self::Emergency => 96,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Requested,
    Active,
    Renewing,
    Expired,
    Revoked,
    Quarantined,
}

impl LeaseStatus {
    pub fn accepts_deployments(self) -> bool {
        matches!(self, Self::Active | Self::Renewing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Verified,
    Rejected,
    Expired,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryAction {
    Allow,
    Redact,
    Meter,
    RequireAttestation,
    Deny,
    Quarantine,
}

impl BoundaryAction {
    pub fn permits_call(self) -> bool {
        matches!(
            self,
            Self::Allow | Self::Redact | Self::Meter | Self::RequireAttestation
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Verified,
    Reconciled,
    Challenged,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    Contained,
    Escalated,
    Released,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Paid,
    ClawedBack,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_deployer_attestation_suite: String,
    pub sealed_contract_root_suite: String,
    pub call_boundary_policy_suite: String,
    pub storage_isolation_receipt_suite: String,
    pub privacy_redaction_budget_suite: String,
    pub fee_asset_id: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
    pub min_namespace_lease_blocks: u64,
    pub max_namespace_lease_blocks: u64,
    pub default_namespace_lease_blocks: u64,
    pub renewal_grace_blocks: u64,
    pub max_contracts_per_namespace: usize,
    pub max_call_policies_per_namespace: usize,
    pub max_public_records: usize,
    pub max_redaction_units_per_epoch: u64,
    pub max_call_boundary_hops: u8,
    pub max_storage_slots_per_receipt: usize,
    pub max_quarantine_events: usize,
    pub min_pq_security_bits: u16,
    pub target_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub quarantine_bond_piconero: u64,
    pub deterministic_roots_required: bool,
    pub redact_contract_metadata_by_default: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_NAMESPACE_ISOLATION_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_deployer_attestation_suite: PQ_DEPLOYER_ATTESTATION_SUITE.to_string(),
            sealed_contract_root_suite: SEALED_CONTRACT_ROOT_SUITE.to_string(),
            call_boundary_policy_suite: CALL_BOUNDARY_POLICY_SUITE.to_string(),
            storage_isolation_receipt_suite: STORAGE_ISOLATION_RECEIPT_SUITE.to_string(),
            privacy_redaction_budget_suite: PRIVACY_REDACTION_BUDGET_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
            min_namespace_lease_blocks: 32,
            max_namespace_lease_blocks: 17_280,
            default_namespace_lease_blocks: NamespaceClass::Contract.default_lease_blocks(),
            renewal_grace_blocks: 64,
            max_contracts_per_namespace: 256,
            max_call_policies_per_namespace: 128,
            max_public_records: 16_384,
            max_redaction_units_per_epoch: 1_000_000,
            max_call_boundary_hops: 8,
            max_storage_slots_per_receipt: 4_096,
            max_quarantine_events: 1_024,
            min_pq_security_bits: 256,
            target_fee_bps: 6,
            low_fee_rebate_bps: 4,
            quarantine_bond_piconero: 5_000_000,
            deterministic_roots_required: true,
            redact_contract_metadata_by_default: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_namespace_isolation_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_deployer_attestation_suite": self.pq_deployer_attestation_suite,
            "sealed_contract_root_suite": self.sealed_contract_root_suite,
            "call_boundary_policy_suite": self.call_boundary_policy_suite,
            "storage_isolation_receipt_suite": self.storage_isolation_receipt_suite,
            "privacy_redaction_budget_suite": self.privacy_redaction_budget_suite,
            "fee_asset_id": self.fee_asset_id,
            "devnet_height": self.devnet_height,
            "devnet_epoch": self.devnet_epoch,
            "min_namespace_lease_blocks": self.min_namespace_lease_blocks,
            "max_namespace_lease_blocks": self.max_namespace_lease_blocks,
            "default_namespace_lease_blocks": self.default_namespace_lease_blocks,
            "renewal_grace_blocks": self.renewal_grace_blocks,
            "max_contracts_per_namespace": self.max_contracts_per_namespace,
            "max_call_policies_per_namespace": self.max_call_policies_per_namespace,
            "max_public_records": self.max_public_records,
            "max_redaction_units_per_epoch": self.max_redaction_units_per_epoch,
            "max_call_boundary_hops": self.max_call_boundary_hops,
            "max_storage_slots_per_receipt": self.max_storage_slots_per_receipt,
            "max_quarantine_events": self.max_quarantine_events,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_fee_bps": self.target_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "quarantine_bond_piconero": self.quarantine_bond_piconero,
            "deterministic_roots_required": self.deterministic_roots_required,
            "redact_contract_metadata_by_default": self.redact_contract_metadata_by_default,
        })
    }

    pub fn validate(&self) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<()> {
        require(
            self.min_namespace_lease_blocks > 0,
            "min namespace lease blocks is zero",
        )?;
        require(
            self.min_namespace_lease_blocks <= self.default_namespace_lease_blocks,
            "default namespace lease below minimum",
        )?;
        require(
            self.default_namespace_lease_blocks <= self.max_namespace_lease_blocks,
            "default namespace lease above maximum",
        )?;
        require(
            self.max_contracts_per_namespace > 0,
            "max contracts per namespace is zero",
        )?;
        require(
            self.max_call_policies_per_namespace > 0,
            "max call policies per namespace is zero",
        )?;
        require(self.max_public_records > 0, "max public records is zero")?;
        require(
            self.max_redaction_units_per_epoch > 0,
            "max redaction units per epoch is zero",
        )?;
        require(
            self.low_fee_rebate_bps <= self.target_fee_bps,
            "rebate bps above target fee bps",
        )?;
        require(self.target_fee_bps <= MAX_BPS, "target fee bps above max")?;
        require(
            self.min_pq_security_bits >= 128,
            "minimum pq security below generated runtime floor",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub namespace_leases: u64,
    pub active_namespaces: u64,
    pub sealed_contract_roots: u64,
    pub deployer_attestations: u64,
    pub call_boundary_policies: u64,
    pub storage_isolation_receipts: u64,
    pub low_fee_namespace_rebates: u64,
    pub violation_quarantines: u64,
    pub privacy_redaction_budgets: u64,
    pub deterministic_root_snapshots: u64,
    pub public_records: u64,
    pub rejected_calls: u64,
    pub quarantined_namespaces: u64,
    pub redaction_units_reserved: u64,
    pub redaction_units_spent: u64,
    pub rebate_piconero_reserved: u64,
    pub rebate_piconero_paid: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_namespace_isolation_counters",
            "namespace_leases": self.namespace_leases,
            "active_namespaces": self.active_namespaces,
            "sealed_contract_roots": self.sealed_contract_roots,
            "deployer_attestations": self.deployer_attestations,
            "call_boundary_policies": self.call_boundary_policies,
            "storage_isolation_receipts": self.storage_isolation_receipts,
            "low_fee_namespace_rebates": self.low_fee_namespace_rebates,
            "violation_quarantines": self.violation_quarantines,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "deterministic_root_snapshots": self.deterministic_root_snapshots,
            "public_records": self.public_records,
            "rejected_calls": self.rejected_calls,
            "quarantined_namespaces": self.quarantined_namespaces,
            "redaction_units_reserved": self.redaction_units_reserved,
            "redaction_units_spent": self.redaction_units_spent,
            "rebate_piconero_reserved": self.rebate_piconero_reserved,
            "rebate_piconero_paid": self.rebate_piconero_paid,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub namespace_lease_root: String,
    pub sealed_contract_root_root: String,
    pub deployer_attestation_root: String,
    pub call_boundary_policy_root: String,
    pub storage_isolation_receipt_root: String,
    pub low_fee_namespace_rebate_root: String,
    pub violation_quarantine_root: String,
    pub privacy_redaction_budget_root: String,
    pub deterministic_root_snapshot_root: String,
    pub namespace_index_root: String,
    pub public_record_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_namespace_isolation_roots",
            "config_root": self.config_root,
            "namespace_lease_root": self.namespace_lease_root,
            "sealed_contract_root_root": self.sealed_contract_root_root,
            "deployer_attestation_root": self.deployer_attestation_root,
            "call_boundary_policy_root": self.call_boundary_policy_root,
            "storage_isolation_receipt_root": self.storage_isolation_receipt_root,
            "low_fee_namespace_rebate_root": self.low_fee_namespace_rebate_root,
            "violation_quarantine_root": self.violation_quarantine_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "deterministic_root_snapshot_root": self.deterministic_root_snapshot_root,
            "namespace_index_root": self.namespace_index_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceLease {
    pub lease_id: String,
    pub namespace_id: String,
    pub namespace_label_commitment: String,
    pub namespace_class: NamespaceClass,
    pub tenant_commitment: String,
    pub controller_pq_key_commitment: String,
    pub status: LeaseStatus,
    pub start_height: u64,
    pub expiry_height: u64,
    pub renewal_nonce: u64,
    pub fee_cap_bps: u64,
    pub low_fee_eligible: bool,
    pub allowed_callers: BTreeSet<String>,
    pub metadata_commitment: String,
}

impl NamespaceLease {
    pub fn new(
        namespace_label_commitment: impl Into<String>,
        namespace_class: NamespaceClass,
        tenant_commitment: impl Into<String>,
        controller_pq_key_commitment: impl Into<String>,
        start_height: u64,
        lease_blocks: u64,
        fee_cap_bps: u64,
    ) -> Self {
        let namespace_label_commitment = namespace_label_commitment.into();
        let tenant_commitment = tenant_commitment.into();
        let controller_pq_key_commitment = controller_pq_key_commitment.into();
        let namespace_id = id_from_parts(
            "NAMESPACE-ID",
            &[
                HashPart::Str(&namespace_label_commitment),
                HashPart::Str(&tenant_commitment),
                HashPart::Str(namespace_class.as_str()),
            ],
        );
        let mut record = Self {
            lease_id: String::new(),
            namespace_id,
            namespace_label_commitment,
            namespace_class,
            tenant_commitment,
            controller_pq_key_commitment,
            status: LeaseStatus::Requested,
            start_height,
            expiry_height: start_height.saturating_add(lease_blocks),
            renewal_nonce: 0,
            fee_cap_bps,
            low_fee_eligible: fee_cap_bps <= 8,
            allowed_callers: BTreeSet::new(),
            metadata_commitment: String::new(),
        };
        record.metadata_commitment =
            root_from_record("NAMESPACE-METADATA", &record.redacted_record());
        record.lease_id = id_from_record("NAMESPACE-LEASE-ID", &record.public_record_without_id());
        record
    }

    pub fn activate(&mut self) {
        self.status = LeaseStatus::Active;
        self.refresh_id();
    }

    pub fn renew(&mut self, current_height: u64, lease_blocks: u64) {
        self.status = LeaseStatus::Renewing;
        self.start_height = current_height;
        self.expiry_height = current_height.saturating_add(lease_blocks);
        self.renewal_nonce = self.renewal_nonce.saturating_add(1);
        self.refresh_id();
    }

    pub fn quarantine(&mut self) {
        self.status = LeaseStatus::Quarantined;
        self.refresh_id();
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["lease_id"] = json!(self.lease_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "namespace_lease",
            "namespace_id": self.namespace_id,
            "namespace_label_commitment": self.namespace_label_commitment,
            "namespace_class": self.namespace_class,
            "tenant_commitment": self.tenant_commitment,
            "controller_pq_key_commitment": self.controller_pq_key_commitment,
            "status": self.status,
            "start_height": self.start_height,
            "expiry_height": self.expiry_height,
            "renewal_nonce": self.renewal_nonce,
            "fee_cap_bps": self.fee_cap_bps,
            "low_fee_eligible": self.low_fee_eligible,
            "allowed_callers": self.allowed_callers,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    fn redacted_record(&self) -> Value {
        json!({
            "namespace_id": self.namespace_id,
            "namespace_class": self.namespace_class,
            "tenant_commitment": self.tenant_commitment,
            "status": self.status,
        })
    }

    fn refresh_id(&mut self) {
        self.metadata_commitment = root_from_record("NAMESPACE-METADATA", &self.redacted_record());
        self.lease_id = id_from_record("NAMESPACE-LEASE-ID", &self.public_record_without_id());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedContractRoot {
    pub contract_id: String,
    pub namespace_id: String,
    pub sealed_root: String,
    pub deterministic_root: String,
    pub code_hash_commitment: String,
    pub storage_schema_commitment: String,
    pub constructor_calldata_commitment: String,
    pub deployer_attestation_id: String,
    pub version: u64,
    pub deployed_height: u64,
    pub active: bool,
}

impl SealedContractRoot {
    pub fn new(
        namespace_id: impl Into<String>,
        code_hash_commitment: impl Into<String>,
        storage_schema_commitment: impl Into<String>,
        constructor_calldata_commitment: impl Into<String>,
        deployer_attestation_id: impl Into<String>,
        deployed_height: u64,
    ) -> Self {
        let namespace_id = namespace_id.into();
        let code_hash_commitment = code_hash_commitment.into();
        let storage_schema_commitment = storage_schema_commitment.into();
        let constructor_calldata_commitment = constructor_calldata_commitment.into();
        let deployer_attestation_id = deployer_attestation_id.into();
        let deterministic_root = id_from_parts(
            "CONTRACT-DETERMINISTIC-ROOT",
            &[
                HashPart::Str(&namespace_id),
                HashPart::Str(&code_hash_commitment),
                HashPart::Str(&storage_schema_commitment),
                HashPart::Str(&constructor_calldata_commitment),
            ],
        );
        let sealed_root = id_from_parts(
            "SEALED-CONTRACT-ROOT",
            &[
                HashPart::Str(&deterministic_root),
                HashPart::Str(&deployer_attestation_id),
            ],
        );
        let mut record = Self {
            contract_id: String::new(),
            namespace_id,
            sealed_root,
            deterministic_root,
            code_hash_commitment,
            storage_schema_commitment,
            constructor_calldata_commitment,
            deployer_attestation_id,
            version: 1,
            deployed_height,
            active: true,
        };
        record.contract_id = id_from_record("CONTRACT-ID", &record.public_record_without_id());
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["contract_id"] = json!(self.contract_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "sealed_contract_root",
            "namespace_id": self.namespace_id,
            "sealed_root": self.sealed_root,
            "deterministic_root": self.deterministic_root,
            "code_hash_commitment": self.code_hash_commitment,
            "storage_schema_commitment": self.storage_schema_commitment,
            "constructor_calldata_commitment": self.constructor_calldata_commitment,
            "deployer_attestation_id": self.deployer_attestation_id,
            "version": self.version,
            "deployed_height": self.deployed_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqDeployerAttestation {
    pub attestation_id: String,
    pub namespace_id: String,
    pub deployer_commitment: String,
    pub pq_key_commitment: String,
    pub signature_commitment: String,
    pub security_bits: u16,
    pub status: AttestationStatus,
    pub issued_height: u64,
    pub expires_height: u64,
    pub allowed_contract_classes: BTreeSet<NamespaceClass>,
}

impl PqDeployerAttestation {
    pub fn new(
        namespace_id: impl Into<String>,
        deployer_commitment: impl Into<String>,
        pq_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        security_bits: u16,
        issued_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let namespace_id = namespace_id.into();
        let deployer_commitment = deployer_commitment.into();
        let pq_key_commitment = pq_key_commitment.into();
        let signature_commitment = signature_commitment.into();
        let mut allowed_contract_classes = BTreeSet::new();
        allowed_contract_classes.insert(NamespaceClass::Contract);
        allowed_contract_classes.insert(NamespaceClass::Library);
        let mut record = Self {
            attestation_id: String::new(),
            namespace_id,
            deployer_commitment,
            pq_key_commitment,
            signature_commitment,
            security_bits,
            status: AttestationStatus::Submitted,
            issued_height,
            expires_height: issued_height.saturating_add(ttl_blocks),
            allowed_contract_classes,
        };
        record.attestation_id = id_from_record(
            "DEPLOYER-ATTESTATION-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn verify(&mut self) {
        self.status = AttestationStatus::Verified;
        self.refresh_id();
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["attestation_id"] = json!(self.attestation_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "pq_deployer_attestation",
            "namespace_id": self.namespace_id,
            "deployer_commitment": self.deployer_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "signature_commitment": self.signature_commitment,
            "security_bits": self.security_bits,
            "status": self.status,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "allowed_contract_classes": self.allowed_contract_classes,
        })
    }

    fn refresh_id(&mut self) {
        self.attestation_id =
            id_from_record("DEPLOYER-ATTESTATION-ID", &self.public_record_without_id());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallBoundaryPolicy {
    pub policy_id: String,
    pub namespace_id: String,
    pub source_contract_id: String,
    pub target_namespace_id: String,
    pub action: BoundaryAction,
    pub selector_commitment: String,
    pub max_hops: u8,
    pub redaction_units_per_call: u64,
    pub require_storage_receipt: bool,
    pub policy_epoch: u64,
}

impl CallBoundaryPolicy {
    pub fn new(
        namespace_id: impl Into<String>,
        source_contract_id: impl Into<String>,
        target_namespace_id: impl Into<String>,
        action: BoundaryAction,
        selector_commitment: impl Into<String>,
        max_hops: u8,
        redaction_units_per_call: u64,
        policy_epoch: u64,
    ) -> Self {
        let mut record = Self {
            policy_id: String::new(),
            namespace_id: namespace_id.into(),
            source_contract_id: source_contract_id.into(),
            target_namespace_id: target_namespace_id.into(),
            action,
            selector_commitment: selector_commitment.into(),
            max_hops,
            redaction_units_per_call,
            require_storage_receipt: matches!(
                action,
                BoundaryAction::Meter | BoundaryAction::Redact
            ),
            policy_epoch,
        };
        record.policy_id = id_from_record(
            "CALL-BOUNDARY-POLICY-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["policy_id"] = json!(self.policy_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "call_boundary_policy",
            "namespace_id": self.namespace_id,
            "source_contract_id": self.source_contract_id,
            "target_namespace_id": self.target_namespace_id,
            "action": self.action,
            "selector_commitment": self.selector_commitment,
            "max_hops": self.max_hops,
            "redaction_units_per_call": self.redaction_units_per_call,
            "require_storage_receipt": self.require_storage_receipt,
            "policy_epoch": self.policy_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageIsolationReceipt {
    pub receipt_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub storage_root_before: String,
    pub storage_root_after: String,
    pub touched_slot_commitments: BTreeSet<String>,
    pub nullifier_root: String,
    pub proof_commitment: String,
    pub status: ReceiptStatus,
    pub height: u64,
}

impl StorageIsolationReceipt {
    pub fn new(
        namespace_id: impl Into<String>,
        contract_id: impl Into<String>,
        storage_root_before: impl Into<String>,
        storage_root_after: impl Into<String>,
        touched_slot_commitments: BTreeSet<String>,
        proof_commitment: impl Into<String>,
        height: u64,
    ) -> Self {
        let nullifier_leaves = touched_slot_commitments
            .iter()
            .map(|slot| json!(slot))
            .collect::<Vec<_>>();
        let mut record = Self {
            receipt_id: String::new(),
            namespace_id: namespace_id.into(),
            contract_id: contract_id.into(),
            storage_root_before: storage_root_before.into(),
            storage_root_after: storage_root_after.into(),
            touched_slot_commitments,
            nullifier_root: merkle_root("STORAGE-SLOT-NULLIFIERS", &nullifier_leaves),
            proof_commitment: proof_commitment.into(),
            status: ReceiptStatus::Pending,
            height,
        };
        record.receipt_id = id_from_record(
            "STORAGE-ISOLATION-RECEIPT-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn verify(&mut self) {
        self.status = ReceiptStatus::Verified;
        self.receipt_id = id_from_record(
            "STORAGE-ISOLATION-RECEIPT-ID",
            &self.public_record_without_id(),
        );
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["receipt_id"] = json!(self.receipt_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "storage_isolation_receipt",
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "storage_root_before": self.storage_root_before,
            "storage_root_after": self.storage_root_after,
            "touched_slot_commitments": self.touched_slot_commitments,
            "nullifier_root": self.nullifier_root,
            "proof_commitment": self.proof_commitment,
            "status": self.status,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeNamespaceRebate {
    pub rebate_id: String,
    pub namespace_id: String,
    pub lease_id: String,
    pub fee_asset_id: String,
    pub measured_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_bps: u64,
    pub reserved_piconero: u64,
    pub paid_piconero: u64,
    pub status: RebateStatus,
    pub epoch: u64,
}

impl LowFeeNamespaceRebate {
    pub fn new(
        namespace_id: impl Into<String>,
        lease_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        measured_fee_bps: u64,
        target_fee_bps: u64,
        rebate_bps: u64,
        reserved_piconero: u64,
        epoch: u64,
    ) -> Self {
        let mut record = Self {
            rebate_id: String::new(),
            namespace_id: namespace_id.into(),
            lease_id: lease_id.into(),
            fee_asset_id: fee_asset_id.into(),
            measured_fee_bps,
            target_fee_bps,
            rebate_bps,
            reserved_piconero,
            paid_piconero: 0,
            status: RebateStatus::Reserved,
            epoch,
        };
        record.rebate_id = id_from_record(
            "LOW-FEE-NAMESPACE-REBATE-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn earn(&mut self) {
        self.status = RebateStatus::Earned;
        self.rebate_id = id_from_record(
            "LOW-FEE-NAMESPACE-REBATE-ID",
            &self.public_record_without_id(),
        );
    }

    pub fn pay(&mut self) {
        self.status = RebateStatus::Paid;
        self.paid_piconero = self.reserved_piconero;
        self.rebate_id = id_from_record(
            "LOW-FEE-NAMESPACE-REBATE-ID",
            &self.public_record_without_id(),
        );
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["rebate_id"] = json!(self.rebate_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "low_fee_namespace_rebate",
            "namespace_id": self.namespace_id,
            "lease_id": self.lease_id,
            "fee_asset_id": self.fee_asset_id,
            "measured_fee_bps": self.measured_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_bps": self.rebate_bps,
            "reserved_piconero": self.reserved_piconero,
            "paid_piconero": self.paid_piconero,
            "status": self.status,
            "epoch": self.epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViolationQuarantine {
    pub quarantine_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub policy_id: String,
    pub violation_commitment: String,
    pub evidence_root: String,
    pub status: QuarantineStatus,
    pub opened_height: u64,
    pub release_height: u64,
    pub bond_piconero: u64,
    pub redacted_public_summary: String,
}

impl ViolationQuarantine {
    pub fn new(
        namespace_id: impl Into<String>,
        contract_id: impl Into<String>,
        policy_id: impl Into<String>,
        violation_commitment: impl Into<String>,
        evidence_items: Vec<Value>,
        opened_height: u64,
        release_height: u64,
        bond_piconero: u64,
    ) -> Self {
        let mut record = Self {
            quarantine_id: String::new(),
            namespace_id: namespace_id.into(),
            contract_id: contract_id.into(),
            policy_id: policy_id.into(),
            violation_commitment: violation_commitment.into(),
            evidence_root: merkle_root("VIOLATION-EVIDENCE", &evidence_items),
            status: QuarantineStatus::Open,
            opened_height,
            release_height,
            bond_piconero,
            redacted_public_summary: String::new(),
        };
        record.redacted_public_summary =
            root_from_record("QUARANTINE-SUMMARY", &record.public_record_without_id());
        record.quarantine_id = id_from_record(
            "VIOLATION-QUARANTINE-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn contain(&mut self) {
        self.status = QuarantineStatus::Contained;
        self.quarantine_id =
            id_from_record("VIOLATION-QUARANTINE-ID", &self.public_record_without_id());
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["quarantine_id"] = json!(self.quarantine_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "violation_quarantine",
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "policy_id": self.policy_id,
            "violation_commitment": self.violation_commitment,
            "evidence_root": self.evidence_root,
            "status": self.status,
            "opened_height": self.opened_height,
            "release_height": self.release_height,
            "bond_piconero": self.bond_piconero,
            "redacted_public_summary": self.redacted_public_summary,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub namespace_id: String,
    pub epoch: u64,
    pub units_reserved: u64,
    pub units_spent: u64,
    pub policy_root: String,
    pub auditor_commitment: String,
    pub exhausted: bool,
}

impl PrivacyRedactionBudget {
    pub fn new(
        namespace_id: impl Into<String>,
        epoch: u64,
        units_reserved: u64,
        policy_root: impl Into<String>,
        auditor_commitment: impl Into<String>,
    ) -> Self {
        let mut record = Self {
            budget_id: String::new(),
            namespace_id: namespace_id.into(),
            epoch,
            units_reserved,
            units_spent: 0,
            policy_root: policy_root.into(),
            auditor_commitment: auditor_commitment.into(),
            exhausted: false,
        };
        record.budget_id = id_from_record(
            "PRIVACY-REDACTION-BUDGET-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn spend(
        &mut self,
        units: u64,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<()> {
        require(
            self.units_spent.saturating_add(units) <= self.units_reserved,
            "redaction budget exhausted",
        )?;
        self.units_spent = self.units_spent.saturating_add(units);
        self.exhausted = self.units_spent == self.units_reserved;
        self.budget_id = id_from_record(
            "PRIVACY-REDACTION-BUDGET-ID",
            &self.public_record_without_id(),
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["budget_id"] = json!(self.budget_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "privacy_redaction_budget",
            "namespace_id": self.namespace_id,
            "epoch": self.epoch,
            "units_reserved": self.units_reserved,
            "units_spent": self.units_spent,
            "policy_root": self.policy_root,
            "auditor_commitment": self.auditor_commitment,
            "exhausted": self.exhausted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicRootSnapshot {
    pub snapshot_id: String,
    pub namespace_id: String,
    pub contract_root: String,
    pub storage_receipt_root: String,
    pub call_policy_root: String,
    pub redaction_budget_root: String,
    pub height: u64,
}

impl DeterministicRootSnapshot {
    pub fn new(
        namespace_id: impl Into<String>,
        contract_root: impl Into<String>,
        storage_receipt_root: impl Into<String>,
        call_policy_root: impl Into<String>,
        redaction_budget_root: impl Into<String>,
        height: u64,
    ) -> Self {
        let mut record = Self {
            snapshot_id: String::new(),
            namespace_id: namespace_id.into(),
            contract_root: contract_root.into(),
            storage_receipt_root: storage_receipt_root.into(),
            call_policy_root: call_policy_root.into(),
            redaction_budget_root: redaction_budget_root.into(),
            height,
        };
        record.snapshot_id = id_from_record(
            "DETERMINISTIC-ROOT-SNAPSHOT-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["snapshot_id"] = json!(self.snapshot_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "deterministic_root_snapshot",
            "namespace_id": self.namespace_id,
            "contract_root": self.contract_root,
            "storage_receipt_root": self.storage_receipt_root,
            "call_policy_root": self.call_policy_root,
            "redaction_budget_root": self.redaction_budget_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub family: String,
    pub commitment: String,
    pub root: String,
    pub height: u64,
}

impl RootsOnlyPublicRecord {
    pub fn new(
        family: impl Into<String>,
        commitment: impl Into<String>,
        root: impl Into<String>,
        height: u64,
    ) -> Self {
        let mut record = Self {
            record_id: String::new(),
            family: family.into(),
            commitment: commitment.into(),
            root: root.into(),
            height,
        };
        record.record_id = id_from_record(
            "ROOTS-ONLY-PUBLIC-RECORD-ID",
            &record.public_record_without_id(),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["record_id"] = json!(self.record_id);
        record
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": "confidential_contract_namespace_roots_only_public_record",
            "family": self.family,
            "commitment": self.commitment,
            "root": self.root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub namespace_leases: BTreeMap<String, NamespaceLease>,
    pub sealed_contract_roots: BTreeMap<String, SealedContractRoot>,
    pub deployer_attestations: BTreeMap<String, PqDeployerAttestation>,
    pub call_boundary_policies: BTreeMap<String, CallBoundaryPolicy>,
    pub storage_isolation_receipts: BTreeMap<String, StorageIsolationReceipt>,
    pub low_fee_namespace_rebates: BTreeMap<String, LowFeeNamespaceRebate>,
    pub violation_quarantines: BTreeMap<String, ViolationQuarantine>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub deterministic_root_snapshots: BTreeMap<String, DeterministicRootSnapshot>,
    pub namespace_contract_index: BTreeMap<String, BTreeSet<String>>,
    pub namespace_policy_index: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            namespace_leases: BTreeMap::new(),
            sealed_contract_roots: BTreeMap::new(),
            deployer_attestations: BTreeMap::new(),
            call_boundary_policies: BTreeMap::new(),
            storage_isolation_receipts: BTreeMap::new(),
            low_fee_namespace_rebates: BTreeMap::new(),
            violation_quarantines: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            deterministic_root_snapshots: BTreeMap::new(),
            namespace_contract_index: BTreeMap::new(),
            namespace_policy_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_counters();
        state.refresh_public_records();
        state
    }

    pub fn lease_namespace(
        &mut self,
        mut lease: NamespaceLease,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        self.config.validate()?;
        let lease_blocks = lease.expiry_height.saturating_sub(lease.start_height);
        require(
            lease_blocks >= self.config.min_namespace_lease_blocks,
            "namespace lease below minimum blocks",
        )?;
        require(
            lease_blocks <= self.config.max_namespace_lease_blocks,
            "namespace lease above maximum blocks",
        )?;
        require(
            lease.fee_cap_bps <= MAX_BPS,
            "namespace lease fee cap above max bps",
        )?;
        lease.activate();
        let lease_id = lease.lease_id.clone();
        self.namespace_leases.insert(lease_id.clone(), lease);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(lease_id)
    }

    pub fn attest_deployer(
        &mut self,
        mut attestation: PqDeployerAttestation,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        require(
            self.namespace_exists(&attestation.namespace_id),
            "namespace missing for deployer attestation",
        )?;
        require(
            attestation.security_bits >= self.config.min_pq_security_bits,
            "deployer attestation below pq security floor",
        )?;
        attestation.verify();
        let attestation_id = attestation.attestation_id.clone();
        self.deployer_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(attestation_id)
    }

    pub fn deploy_contract_root(
        &mut self,
        contract: SealedContractRoot,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        let lease = self
            .active_lease_for_namespace(&contract.namespace_id)
            .ok_or_else(|| "active namespace lease missing for contract root".to_string())?;
        require(
            lease.status.accepts_deployments(),
            "namespace lease does not accept deployments",
        )?;
        require(
            self.deployer_attestations
                .get(&contract.deployer_attestation_id)
                .map(|attestation| attestation.status == AttestationStatus::Verified)
                .unwrap_or(false),
            "verified deployer attestation missing",
        )?;
        let contract_count = self
            .namespace_contract_index
            .get(&contract.namespace_id)
            .map(BTreeSet::len)
            .unwrap_or(0);
        require(
            contract_count < self.config.max_contracts_per_namespace,
            "namespace contract limit reached",
        )?;
        require(
            !self
                .sealed_contract_roots
                .values()
                .any(|existing| existing.deterministic_root == contract.deterministic_root),
            "deterministic contract root already registered",
        )?;
        let contract_id = contract.contract_id.clone();
        self.namespace_contract_index
            .entry(contract.namespace_id.clone())
            .or_default()
            .insert(contract_id.clone());
        self.sealed_contract_roots
            .insert(contract_id.clone(), contract);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(contract_id)
    }

    pub fn publish_call_boundary_policy(
        &mut self,
        policy: CallBoundaryPolicy,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        require(
            self.namespace_exists(&policy.namespace_id),
            "namespace missing for call boundary policy",
        )?;
        require(
            self.namespace_exists(&policy.target_namespace_id),
            "target namespace missing for call boundary policy",
        )?;
        require(
            policy.max_hops <= self.config.max_call_boundary_hops,
            "call boundary policy exceeds max hops",
        )?;
        let policy_count = self
            .namespace_policy_index
            .get(&policy.namespace_id)
            .map(BTreeSet::len)
            .unwrap_or(0);
        require(
            policy_count < self.config.max_call_policies_per_namespace,
            "namespace policy limit reached",
        )?;
        let policy_id = policy.policy_id.clone();
        self.namespace_policy_index
            .entry(policy.namespace_id.clone())
            .or_default()
            .insert(policy_id.clone());
        self.call_boundary_policies
            .insert(policy_id.clone(), policy);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(policy_id)
    }

    pub fn record_storage_isolation_receipt(
        &mut self,
        mut receipt: StorageIsolationReceipt,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        require(
            receipt.touched_slot_commitments.len() <= self.config.max_storage_slots_per_receipt,
            "storage isolation receipt slot limit reached",
        )?;
        require(
            self.sealed_contract_roots
                .contains_key(&receipt.contract_id),
            "contract missing for storage isolation receipt",
        )?;
        receipt.verify();
        let receipt_id = receipt.receipt_id.clone();
        self.storage_isolation_receipts
            .insert(receipt_id.clone(), receipt);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(receipt_id)
    }

    pub fn reserve_redaction_budget(
        &mut self,
        budget: PrivacyRedactionBudget,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        require(
            self.namespace_exists(&budget.namespace_id),
            "namespace missing for redaction budget",
        )?;
        require(
            budget.units_reserved <= self.config.max_redaction_units_per_epoch,
            "redaction budget above epoch maximum",
        )?;
        let budget_id = budget.budget_id.clone();
        self.privacy_redaction_budgets
            .insert(budget_id.clone(), budget);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(budget_id)
    }

    pub fn spend_redaction_budget(
        &mut self,
        budget_id: &str,
        units: u64,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<()> {
        let budget = self
            .privacy_redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "redaction budget missing".to_string())?;
        budget.spend(units)?;
        self.refresh_counters();
        self.refresh_public_records();
        Ok(())
    }

    pub fn reserve_low_fee_rebate(
        &mut self,
        rebate: LowFeeNamespaceRebate,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        require(
            self.namespace_exists(&rebate.namespace_id),
            "namespace missing for low fee rebate",
        )?;
        require(
            rebate.measured_fee_bps <= rebate.target_fee_bps,
            "low fee rebate requires measured fee under target",
        )?;
        require(
            rebate.rebate_bps <= self.config.low_fee_rebate_bps,
            "rebate bps exceeds configured rebate",
        )?;
        let rebate_id = rebate.rebate_id.clone();
        self.low_fee_namespace_rebates
            .insert(rebate_id.clone(), rebate);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(rebate_id)
    }

    pub fn pay_low_fee_rebate(
        &mut self,
        rebate_id: &str,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<()> {
        let rebate = self
            .low_fee_namespace_rebates
            .get_mut(rebate_id)
            .ok_or_else(|| "low fee namespace rebate missing".to_string())?;
        rebate.earn();
        rebate.pay();
        self.refresh_counters();
        self.refresh_public_records();
        Ok(())
    }

    pub fn quarantine_violation(
        &mut self,
        mut quarantine: ViolationQuarantine,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        require(
            self.violation_quarantines.len() < self.config.max_quarantine_events,
            "quarantine event limit reached",
        )?;
        require(
            self.namespace_exists(&quarantine.namespace_id),
            "namespace missing for quarantine",
        )?;
        require(
            self.sealed_contract_roots
                .contains_key(&quarantine.contract_id),
            "contract missing for quarantine",
        )?;
        quarantine.contain();
        if let Some(lease_id) = self.lease_id_for_namespace(&quarantine.namespace_id) {
            if let Some(lease) = self.namespace_leases.get_mut(&lease_id) {
                lease.quarantine();
            }
        }
        let quarantine_id = quarantine.quarantine_id.clone();
        self.violation_quarantines
            .insert(quarantine_id.clone(), quarantine);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(quarantine_id)
    }

    pub fn snapshot_deterministic_roots(
        &mut self,
        namespace_id: &str,
        height: u64,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<String> {
        require(
            self.namespace_exists(namespace_id),
            "namespace missing for deterministic root snapshot",
        )?;
        let contract_ids = self
            .namespace_contract_index
            .get(namespace_id)
            .cloned()
            .unwrap_or_default();
        let policy_ids = self
            .namespace_policy_index
            .get(namespace_id)
            .cloned()
            .unwrap_or_default();
        let contracts = values_by_ids(
            &self.sealed_contract_roots,
            &contract_ids,
            SealedContractRoot::public_record,
        );
        let policies = values_by_ids(
            &self.call_boundary_policies,
            &policy_ids,
            CallBoundaryPolicy::public_record,
        );
        let receipts = self
            .storage_isolation_receipts
            .values()
            .filter(|receipt| receipt.namespace_id == namespace_id)
            .map(StorageIsolationReceipt::public_record)
            .collect::<Vec<_>>();
        let budgets = self
            .privacy_redaction_budgets
            .values()
            .filter(|budget| budget.namespace_id == namespace_id)
            .map(PrivacyRedactionBudget::public_record)
            .collect::<Vec<_>>();
        let snapshot = DeterministicRootSnapshot::new(
            namespace_id,
            merkle_root("SNAPSHOT-CONTRACTS", &contracts),
            merkle_root("SNAPSHOT-STORAGE-RECEIPTS", &receipts),
            merkle_root("SNAPSHOT-CALL-POLICIES", &policies),
            merkle_root("SNAPSHOT-REDACTION-BUDGETS", &budgets),
            height,
        );
        let snapshot_id = snapshot.snapshot_id.clone();
        self.deterministic_root_snapshots
            .insert(snapshot_id.clone(), snapshot);
        self.refresh_counters();
        self.refresh_public_records();
        Ok(snapshot_id)
    }

    pub fn evaluate_call_boundary(
        &mut self,
        source_contract_id: &str,
        target_namespace_id: &str,
        selector_commitment: &str,
        hop_count: u8,
    ) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<BoundaryAction> {
        let source = self
            .sealed_contract_roots
            .get(source_contract_id)
            .ok_or_else(|| "source contract missing for call boundary".to_string())?;
        let action = self
            .call_boundary_policies
            .values()
            .filter(|policy| {
                policy.source_contract_id == source_contract_id
                    && policy.target_namespace_id == target_namespace_id
                    && policy.selector_commitment == selector_commitment
            })
            .map(|policy| {
                if hop_count > policy.max_hops {
                    BoundaryAction::Deny
                } else {
                    policy.action
                }
            })
            .next()
            .unwrap_or(BoundaryAction::Deny);
        if !action.permits_call() {
            self.counters.rejected_calls = self.counters.rejected_calls.saturating_add(1);
            let quarantine = ViolationQuarantine::new(
                source.namespace_id.clone(),
                source_contract_id,
                "implicit-deny",
                id_from_parts(
                    "CALL-BOUNDARY-VIOLATION",
                    &[
                        HashPart::Str(source_contract_id),
                        HashPart::Str(target_namespace_id),
                        HashPart::Str(selector_commitment),
                        HashPart::U64(hop_count as u64),
                    ],
                ),
                vec![json!({
                    "source_contract_id": source_contract_id,
                    "target_namespace_id": target_namespace_id,
                    "selector_commitment": selector_commitment,
                    "hop_count": hop_count,
                })],
                self.config.devnet_height,
                self.config.devnet_height + self.config.renewal_grace_blocks,
                self.config.quarantine_bond_piconero,
            );
            self.quarantine_violation(quarantine)?;
        }
        self.refresh_counters();
        self.refresh_public_records();
        Ok(action)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(
                "NAMESPACE-ISOLATION-CONFIG",
                &self.config.public_record(),
            ),
            namespace_lease_root: map_root(
                "NAMESPACE-LEASES",
                &self.namespace_leases,
                NamespaceLease::public_record,
            ),
            sealed_contract_root_root: map_root(
                "SEALED-CONTRACT-ROOTS",
                &self.sealed_contract_roots,
                SealedContractRoot::public_record,
            ),
            deployer_attestation_root: map_root(
                "DEPLOYER-ATTESTATIONS",
                &self.deployer_attestations,
                PqDeployerAttestation::public_record,
            ),
            call_boundary_policy_root: map_root(
                "CALL-BOUNDARY-POLICIES",
                &self.call_boundary_policies,
                CallBoundaryPolicy::public_record,
            ),
            storage_isolation_receipt_root: map_root(
                "STORAGE-ISOLATION-RECEIPTS",
                &self.storage_isolation_receipts,
                StorageIsolationReceipt::public_record,
            ),
            low_fee_namespace_rebate_root: map_root(
                "LOW-FEE-NAMESPACE-REBATES",
                &self.low_fee_namespace_rebates,
                LowFeeNamespaceRebate::public_record,
            ),
            violation_quarantine_root: map_root(
                "VIOLATION-QUARANTINES",
                &self.violation_quarantines,
                ViolationQuarantine::public_record,
            ),
            privacy_redaction_budget_root: map_root(
                "PRIVACY-REDACTION-BUDGETS",
                &self.privacy_redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            deterministic_root_snapshot_root: map_root(
                "DETERMINISTIC-ROOT-SNAPSHOTS",
                &self.deterministic_root_snapshots,
                DeterministicRootSnapshot::public_record,
            ),
            namespace_index_root: namespace_index_root(
                &self.namespace_contract_index,
                &self.namespace_policy_index,
            ),
            public_record_root: map_root(
                "CONFIDENTIAL-CONTRACT-NAMESPACE-PUBLIC-RECORDS",
                &self.public_records,
                RootsOnlyPublicRecord::public_record,
            ),
            counters_root: root_from_record(
                "NAMESPACE-ISOLATION-COUNTERS",
                &self.counters.public_record(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_namespace_isolation_state",
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_NAMESPACE_ISOLATION_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "namespace_leases": self.namespace_leases.values().map(NamespaceLease::public_record).collect::<Vec<_>>(),
            "sealed_contract_roots": self.sealed_contract_roots.values().map(SealedContractRoot::public_record).collect::<Vec<_>>(),
            "deployer_attestations": self.deployer_attestations.values().map(PqDeployerAttestation::public_record).collect::<Vec<_>>(),
            "call_boundary_policies": self.call_boundary_policies.values().map(CallBoundaryPolicy::public_record).collect::<Vec<_>>(),
            "storage_isolation_receipts": self.storage_isolation_receipts.values().map(StorageIsolationReceipt::public_record).collect::<Vec<_>>(),
            "low_fee_namespace_rebates": self.low_fee_namespace_rebates.values().map(LowFeeNamespaceRebate::public_record).collect::<Vec<_>>(),
            "violation_quarantines": self.violation_quarantines.values().map(ViolationQuarantine::public_record).collect::<Vec<_>>(),
            "privacy_redaction_budgets": self.privacy_redaction_budgets.values().map(PrivacyRedactionBudget::public_record).collect::<Vec<_>>(),
            "deterministic_root_snapshots": self.deterministic_root_snapshots.values().map(DeterministicRootSnapshot::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(RootsOnlyPublicRecord::public_record).collect::<Vec<_>>(),
        })
    }

    fn namespace_exists(&self, namespace_id: &str) -> bool {
        self.namespace_leases
            .values()
            .any(|lease| lease.namespace_id == namespace_id)
    }

    fn active_lease_for_namespace(&self, namespace_id: &str) -> Option<&NamespaceLease> {
        self.namespace_leases
            .values()
            .find(|lease| lease.namespace_id == namespace_id && lease.status.accepts_deployments())
    }

    fn lease_id_for_namespace(&self, namespace_id: &str) -> Option<String> {
        self.namespace_leases
            .values()
            .find(|lease| lease.namespace_id == namespace_id)
            .map(|lease| lease.lease_id.clone())
    }

    fn refresh_counters(&mut self) {
        self.counters.namespace_leases = self.namespace_leases.len() as u64;
        self.counters.active_namespaces = self
            .namespace_leases
            .values()
            .filter(|lease| lease.status.accepts_deployments())
            .count() as u64;
        self.counters.sealed_contract_roots = self.sealed_contract_roots.len() as u64;
        self.counters.deployer_attestations = self.deployer_attestations.len() as u64;
        self.counters.call_boundary_policies = self.call_boundary_policies.len() as u64;
        self.counters.storage_isolation_receipts = self.storage_isolation_receipts.len() as u64;
        self.counters.low_fee_namespace_rebates = self.low_fee_namespace_rebates.len() as u64;
        self.counters.violation_quarantines = self.violation_quarantines.len() as u64;
        self.counters.privacy_redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        self.counters.deterministic_root_snapshots = self.deterministic_root_snapshots.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.quarantined_namespaces = self
            .namespace_leases
            .values()
            .filter(|lease| lease.status == LeaseStatus::Quarantined)
            .count() as u64;
        self.counters.redaction_units_reserved = self
            .privacy_redaction_budgets
            .values()
            .map(|budget| budget.units_reserved)
            .sum();
        self.counters.redaction_units_spent = self
            .privacy_redaction_budgets
            .values()
            .map(|budget| budget.units_spent)
            .sum();
        self.counters.rebate_piconero_reserved = self
            .low_fee_namespace_rebates
            .values()
            .map(|rebate| rebate.reserved_piconero)
            .sum();
        self.counters.rebate_piconero_paid = self
            .low_fee_namespace_rebates
            .values()
            .map(|rebate| rebate.paid_piconero)
            .sum();
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        let height = self.config.devnet_height;
        let roots = vec![
            (
                "config",
                root_from_record("CONFIG", &self.config.public_record()),
            ),
            (
                "namespace_leases",
                map_root(
                    "NAMESPACE-LEASES",
                    &self.namespace_leases,
                    NamespaceLease::public_record,
                ),
            ),
            (
                "sealed_contract_roots",
                map_root(
                    "SEALED-CONTRACT-ROOTS",
                    &self.sealed_contract_roots,
                    SealedContractRoot::public_record,
                ),
            ),
            (
                "deployer_attestations",
                map_root(
                    "DEPLOYER-ATTESTATIONS",
                    &self.deployer_attestations,
                    PqDeployerAttestation::public_record,
                ),
            ),
            (
                "call_boundary_policies",
                map_root(
                    "CALL-BOUNDARY-POLICIES",
                    &self.call_boundary_policies,
                    CallBoundaryPolicy::public_record,
                ),
            ),
            (
                "storage_isolation_receipts",
                map_root(
                    "STORAGE-ISOLATION-RECEIPTS",
                    &self.storage_isolation_receipts,
                    StorageIsolationReceipt::public_record,
                ),
            ),
            (
                "low_fee_namespace_rebates",
                map_root(
                    "LOW-FEE-NAMESPACE-REBATES",
                    &self.low_fee_namespace_rebates,
                    LowFeeNamespaceRebate::public_record,
                ),
            ),
            (
                "violation_quarantines",
                map_root(
                    "VIOLATION-QUARANTINES",
                    &self.violation_quarantines,
                    ViolationQuarantine::public_record,
                ),
            ),
            (
                "privacy_redaction_budgets",
                map_root(
                    "PRIVACY-REDACTION-BUDGETS",
                    &self.privacy_redaction_budgets,
                    PrivacyRedactionBudget::public_record,
                ),
            ),
            (
                "deterministic_root_snapshots",
                map_root(
                    "DETERMINISTIC-ROOT-SNAPSHOTS",
                    &self.deterministic_root_snapshots,
                    DeterministicRootSnapshot::public_record,
                ),
            ),
        ];
        for (family, root) in roots {
            if self.public_records.len() >= self.config.max_public_records {
                break;
            }
            let commitment = id_from_parts(
                "PUBLIC-ROOT-COMMITMENT",
                &[HashPart::Str(family), HashPart::Str(&root)],
            );
            let record = RootsOnlyPublicRecord::new(family, commitment, root, height);
            self.public_records.insert(record.record_id.clone(), record);
        }
        self.counters.public_records = self.public_records.len() as u64;
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let lease = NamespaceLease::new(
        "commitment:namespace:private-dex-vault",
        NamespaceClass::Contract,
        "commitment:tenant:nebula-devnet-labs",
        "commitment:pq-controller:ml-dsa-87:alpha",
        DEVNET_HEIGHT,
        NamespaceClass::Contract.default_lease_blocks(),
        6,
    );
    let namespace_id = lease.namespace_id.clone();
    let lease_id = state
        .lease_namespace(lease)
        .expect("generated devnet namespace lease");
    let attestation = PqDeployerAttestation::new(
        namespace_id.clone(),
        "commitment:deployer:shielded-builder-alpha",
        "commitment:pq-key:ml-dsa-87:builder-alpha",
        "commitment:signature:builder-alpha:namespace",
        256,
        DEVNET_HEIGHT,
        1_440,
    );
    let attestation_id = state
        .attest_deployer(attestation)
        .expect("generated devnet deployer attestation");
    let contract = SealedContractRoot::new(
        namespace_id.clone(),
        "commitment:code:confidential-vault-router",
        "commitment:storage-schema:vault-router:v1",
        "commitment:constructor:vault-router:redacted",
        attestation_id.clone(),
        DEVNET_HEIGHT + 1,
    );
    let contract_id = state
        .deploy_contract_root(contract)
        .expect("generated devnet sealed contract root");
    let budget = PrivacyRedactionBudget::new(
        namespace_id.clone(),
        DEVNET_EPOCH,
        50_000,
        "commitment:redaction-policy:devnet-default",
        "commitment:auditor:view-key:demo",
    );
    let budget_id = state
        .reserve_redaction_budget(budget)
        .expect("generated devnet privacy redaction budget");
    state
        .spend_redaction_budget(&budget_id, 128)
        .expect("generated devnet redaction spend");
    let policy = CallBoundaryPolicy::new(
        namespace_id.clone(),
        contract_id.clone(),
        namespace_id.clone(),
        BoundaryAction::Redact,
        "commitment:selector:swap_exact_private",
        2,
        16,
        DEVNET_EPOCH,
    );
    let policy_id = state
        .publish_call_boundary_policy(policy)
        .expect("generated devnet call boundary policy");
    let mut slots = BTreeSet::new();
    slots.insert("commitment:slot:vault:balance-nullifier".to_string());
    slots.insert("commitment:slot:vault:allowance-nullifier".to_string());
    let receipt = StorageIsolationReceipt::new(
        namespace_id.clone(),
        contract_id.clone(),
        "root:storage:before:private-vault",
        "root:storage:after:private-vault",
        slots,
        "commitment:proof:storage-isolation:vault-router",
        DEVNET_HEIGHT + 2,
    );
    state
        .record_storage_isolation_receipt(receipt)
        .expect("generated devnet storage isolation receipt");
    let mut rebate = LowFeeNamespaceRebate::new(
        namespace_id.clone(),
        lease_id,
        DEFAULT_FEE_ASSET_ID,
        3,
        state.config.target_fee_bps,
        state.config.low_fee_rebate_bps,
        42_000,
        DEVNET_EPOCH,
    );
    rebate.earn();
    state
        .reserve_low_fee_rebate(rebate)
        .expect("generated devnet low fee namespace rebate");
    state
        .snapshot_deterministic_roots(&namespace_id, DEVNET_HEIGHT + 3)
        .expect("generated devnet deterministic roots");
    let _ = policy_id;
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let target_lease = NamespaceLease::new(
        "commitment:namespace:oracle-prices",
        NamespaceClass::Oracle,
        "commitment:tenant:nebula-oracle-demo",
        "commitment:pq-controller:ml-dsa-87:oracle",
        DEVNET_HEIGHT + 4,
        NamespaceClass::Oracle.default_lease_blocks(),
        9,
    );
    let target_namespace_id = target_lease.namespace_id.clone();
    state
        .lease_namespace(target_lease)
        .expect("generated demo target namespace lease");
    let source_contract_id = state
        .sealed_contract_roots
        .keys()
        .next()
        .cloned()
        .expect("generated demo source contract");
    let policy = CallBoundaryPolicy::new(
        state
            .sealed_contract_roots
            .get(&source_contract_id)
            .expect("generated demo contract namespace")
            .namespace_id
            .clone(),
        source_contract_id.clone(),
        target_namespace_id.clone(),
        BoundaryAction::RequireAttestation,
        "commitment:selector:read_private_price",
        1,
        8,
        DEVNET_EPOCH,
    );
    state
        .publish_call_boundary_policy(policy)
        .expect("generated demo oracle boundary policy");
    state
        .evaluate_call_boundary(
            &source_contract_id,
            &target_namespace_id,
            "commitment:selector:forbidden_admin_call",
            3,
        )
        .expect("generated demo quarantine path");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqConfidentialContractNamespaceIsolationRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn id_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-NAMESPACE-ISOLATION-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn namespace_index_root(
    contract_index: &BTreeMap<String, BTreeSet<String>>,
    policy_index: &BTreeMap<String, BTreeSet<String>>,
) -> String {
    let mut namespaces = BTreeSet::new();
    namespaces.extend(contract_index.keys().cloned());
    namespaces.extend(policy_index.keys().cloned());
    let leaves = namespaces
        .iter()
        .map(|namespace_id| {
            json!({
                "namespace_id": namespace_id,
                "contracts": contract_index.get(namespace_id).cloned().unwrap_or_default(),
                "policies": policy_index.get(namespace_id).cloned().unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("NAMESPACE-CONTRACT-POLICY-INDEX", &leaves)
}

fn values_by_ids<T, F>(
    map: &BTreeMap<String, T>,
    ids: &BTreeSet<String>,
    public_record: F,
) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    ids.iter()
        .filter_map(|id| map.get(id))
        .map(public_record)
        .collect()
}
