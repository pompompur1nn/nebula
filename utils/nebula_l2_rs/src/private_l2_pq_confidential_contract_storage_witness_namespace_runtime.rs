use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractStorageWitnessNamespaceRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_WITNESS_NAMESPACE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-storage-witness-namespace-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_WITNESS_NAMESPACE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const NAMESPACE_MANIFEST_SUITE: &str = "private-l2-contract-storage-namespace-manifest-v1";
pub const STORAGE_WITNESS_COMMITMENT_SUITE: &str =
    "private-l2-contract-storage-witness-commitment-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-storage-witness-v1";
pub const WITNESS_LEASE_MARKET_SUITE: &str = "privacy-preserving-storage-witness-lease-market-v1";
pub const ACCESS_POLICY_SUITE: &str = "namespace-access-policy-nullifier-gate-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-storage-witness-rebate-v1";
pub const QUARANTINE_SUITE: &str = "namespace-violation-quarantine-v1";
pub const REDACTION_BUDGET_SUITE: &str = "privacy-redaction-budget-v1";
pub const DETERMINISTIC_ROOT_SUITE: &str = "deterministic-storage-witness-namespace-roots-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_966_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_NAMESPACE_TTL_BLOCKS: u64 = 172_800;
pub const DEFAULT_WITNESS_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTIONS_PER_EPOCH: u64 = 16;
pub const DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS: u64 = 2_500_000;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const DEFAULT_REBATE_CAP_BPS: u64 = 18;
pub const DEFAULT_MAX_NAMESPACE_BYTES: u64 = 16_777_216;
pub const DEFAULT_MAX_WITNESS_BYTES: u64 = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceKind {
    ContractStorage,
    SecretIndex,
    MerkleDelta,
    OracleMemo,
    LeaseEscrow,
    QuarantineShadow,
    RedactionLedger,
}

impl NamespaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractStorage => "contract_storage",
            Self::SecretIndex => "secret_index",
            Self::MerkleDelta => "merkle_delta",
            Self::OracleMemo => "oracle_memo",
            Self::LeaseEscrow => "lease_escrow",
            Self::QuarantineShadow => "quarantine_shadow",
            Self::RedactionLedger => "redaction_ledger",
        }
    }

    pub fn requires_redaction_budget(self) -> bool {
        matches!(
            self,
            Self::ContractStorage | Self::SecretIndex | Self::OracleMemo | Self::RedactionLedger
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceStatus {
    Draft,
    Active,
    Leasing,
    Throttled,
    Quarantined,
    Frozen,
    Retired,
}

impl NamespaceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Leasing => "leasing",
            Self::Throttled => "throttled",
            Self::Quarantined => "quarantined",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_witnesses(self) -> bool {
        matches!(self, Self::Active | Self::Leasing | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessKind {
    SlotRead,
    SlotWrite,
    RangeRead,
    MerkleDelta,
    StateExpiry,
    RedactedSnapshot,
    QuarantineReplay,
}

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SlotRead => "slot_read",
            Self::SlotWrite => "slot_write",
            Self::RangeRead => "range_read",
            Self::MerkleDelta => "merkle_delta",
            Self::StateExpiry => "state_expiry",
            Self::RedactedSnapshot => "redacted_snapshot",
            Self::QuarantineReplay => "quarantine_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    Committed,
    Sealed,
    Leased,
    Attested,
    Settled,
    Rebated,
    Challenged,
    Expired,
}

impl WitnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Sealed => "sealed",
            Self::Leased => "leased",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Sealed | Self::Leased | Self::Attested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationSubject {
    Contract,
    Operator,
    Lease,
    AccessPolicy,
    RedactionBudget,
    QuarantineDecision,
}

impl AttestationSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Operator => "operator",
            Self::Lease => "lease",
            Self::AccessPolicy => "access_policy",
            Self::RedactionBudget => "redaction_budget",
            Self::QuarantineDecision => "quarantine_decision",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Listed,
    Reserved,
    Active,
    Fulfilled,
    Settled,
    Slashed,
    Cancelled,
    Expired,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Listed => "listed",
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Fulfilled => "fulfilled",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Auditor,
    Emergency,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::WriteOnly => "write_only",
            Self::ReadWrite => "read_write",
            Self::Auditor => "auditor",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Proposed,
    Active,
    Rotating,
    Revoked,
    Expired,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Reserved,
    Paid,
    ClawedBack,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Reserved => "reserved",
            Self::Paid => "paid",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    UnauthorizedRead,
    UnauthorizedWrite,
    NamespaceCollision,
    WitnessMismatch,
    RedactionOverrun,
    LeaseNonDelivery,
    PqAttestationFailure,
}

impl ViolationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnauthorizedRead => "unauthorized_read",
            Self::UnauthorizedWrite => "unauthorized_write",
            Self::NamespaceCollision => "namespace_collision",
            Self::WitnessMismatch => "witness_mismatch",
            Self::RedactionOverrun => "redaction_overrun",
            Self::LeaseNonDelivery => "lease_non_delivery",
            Self::PqAttestationFailure => "pq_attestation_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    EvidenceLocked,
    Mitigating,
    Released,
    Slashed,
    Expired,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceLocked => "evidence_locked",
            Self::Mitigating => "mitigating",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub namespace_ttl_blocks: u64,
    pub witness_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub policy_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_redactions_per_epoch: u64,
    pub min_operator_bond_micro_units: u64,
    pub low_fee_target_bps: u64,
    pub rebate_cap_bps: u64,
    pub max_namespace_bytes: u64,
    pub max_witness_bytes: u64,
    pub allowed_namespace_kinds: BTreeSet<NamespaceKind>,
    pub accepted_fee_assets: BTreeSet<String>,
    pub operator_allowlist_root: String,
    pub governance_key_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let mut allowed_namespace_kinds = BTreeSet::new();
        allowed_namespace_kinds.insert(NamespaceKind::ContractStorage);
        allowed_namespace_kinds.insert(NamespaceKind::SecretIndex);
        allowed_namespace_kinds.insert(NamespaceKind::MerkleDelta);
        allowed_namespace_kinds.insert(NamespaceKind::OracleMemo);
        allowed_namespace_kinds.insert(NamespaceKind::LeaseEscrow);
        allowed_namespace_kinds.insert(NamespaceKind::QuarantineShadow);
        allowed_namespace_kinds.insert(NamespaceKind::RedactionLedger);

        let mut accepted_fee_assets = BTreeSet::new();
        accepted_fee_assets.insert("piconero-devnet".to_string());
        accepted_fee_assets.insert("private-usd-devnet".to_string());
        accepted_fee_assets.insert("witness-credit-devnet".to_string());

        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            namespace_ttl_blocks: DEFAULT_NAMESPACE_TTL_BLOCKS,
            witness_ttl_blocks: DEFAULT_WITNESS_TTL_BLOCKS,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_redactions_per_epoch: DEFAULT_MAX_REDACTIONS_PER_EPOCH,
            min_operator_bond_micro_units: DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            rebate_cap_bps: DEFAULT_REBATE_CAP_BPS,
            max_namespace_bytes: DEFAULT_MAX_NAMESPACE_BYTES,
            max_witness_bytes: DEFAULT_MAX_WITNESS_BYTES,
            allowed_namespace_kinds,
            accepted_fee_assets,
            operator_allowlist_root: root_from_values("operator-allowlist", &[]),
            governance_key_root: root_from_values("governance-keys", &[]),
        }
    }

    pub fn validate(
        &self,
    ) -> PrivateL2PqConfidentialContractStorageWitnessNamespaceRuntimeResult<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below policy",
        )?;
        require(
            self.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE,
            "privacy set below policy",
        )?;
        require(
            self.low_fee_target_bps <= MAX_BPS,
            "low fee target outside bps",
        )?;
        require(self.rebate_cap_bps <= MAX_BPS, "rebate cap outside bps")?;
        require(
            self.low_fee_target_bps <= self.rebate_cap_bps,
            "low fee target above rebate cap",
        )?;
        require(
            self.max_witness_bytes <= self.max_namespace_bytes,
            "witness bytes exceed namespace bytes",
        )?;
        require(
            !self.allowed_namespace_kinds.is_empty(),
            "no namespace kinds",
        )?;
        require(
            !self.accepted_fee_assets.is_empty(),
            "no accepted fee assets",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "namespace_ttl_blocks": self.namespace_ttl_blocks,
            "witness_ttl_blocks": self.witness_ttl_blocks,
            "lease_ttl_blocks": self.lease_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_redactions_per_epoch": self.max_redactions_per_epoch,
            "min_operator_bond_micro_units": self.min_operator_bond_micro_units,
            "low_fee_target_bps": self.low_fee_target_bps,
            "rebate_cap_bps": self.rebate_cap_bps,
            "max_namespace_bytes": self.max_namespace_bytes,
            "max_witness_bytes": self.max_witness_bytes,
            "allowed_namespace_kinds": self.allowed_namespace_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "accepted_fee_assets": self.accepted_fee_assets,
            "operator_allowlist_root": self.operator_allowlist_root,
            "governance_key_root": self.governance_key_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub namespace_manifests: u64,
    pub witness_commitments: u64,
    pub pq_attestations: u64,
    pub lease_orders: u64,
    pub access_policies: u64,
    pub low_fee_rebates: u64,
    pub quarantine_cases: u64,
    pub redaction_budgets: u64,
    pub deterministic_root_checkpoints: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_manifests": self.namespace_manifests,
            "witness_commitments": self.witness_commitments,
            "pq_attestations": self.pq_attestations,
            "lease_orders": self.lease_orders,
            "access_policies": self.access_policies,
            "low_fee_rebates": self.low_fee_rebates,
            "quarantine_cases": self.quarantine_cases,
            "redaction_budgets": self.redaction_budgets,
            "deterministic_root_checkpoints": self.deterministic_root_checkpoints,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub namespace_manifest_root: String,
    pub witness_commitment_root: String,
    pub pq_attestation_root: String,
    pub lease_market_root: String,
    pub access_policy_root: String,
    pub rebate_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub deterministic_checkpoint_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: root_from_values("config", &[]),
            namespace_manifest_root: root_from_values("namespace-manifests", &[]),
            witness_commitment_root: root_from_values("witness-commitments", &[]),
            pq_attestation_root: root_from_values("pq-attestations", &[]),
            lease_market_root: root_from_values("lease-market", &[]),
            access_policy_root: root_from_values("access-policies", &[]),
            rebate_root: root_from_values("rebates", &[]),
            quarantine_root: root_from_values("quarantine", &[]),
            redaction_budget_root: root_from_values("redaction-budgets", &[]),
            deterministic_checkpoint_root: root_from_values("deterministic-checkpoints", &[]),
            event_root: root_from_values("events", &[]),
            public_record_root: root_from_values("public-record", &[]),
            state_root: domain_hash("storage-witness-empty-state", &[], 32),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "namespace_manifest_root": self.namespace_manifest_root,
            "witness_commitment_root": self.witness_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "lease_market_root": self.lease_market_root,
            "access_policy_root": self.access_policy_root,
            "rebate_root": self.rebate_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "deterministic_checkpoint_root": self.deterministic_checkpoint_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceManifest {
    pub namespace_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub kind: NamespaceKind,
    pub status: NamespaceStatus,
    pub version: u64,
    pub storage_schema_root: String,
    pub initial_state_root: String,
    pub current_state_root: String,
    pub witness_policy_root: String,
    pub access_policy_ids: BTreeSet<String>,
    pub allowed_operator_ids: BTreeSet<String>,
    pub privacy_set_size: u64,
    pub namespace_bytes: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub redaction_budget_id: Option<String>,
    pub metadata_commitment: String,
}

impl NamespaceManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "owner_commitment": self.owner_commitment,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "version": self.version,
            "storage_schema_root": self.storage_schema_root,
            "initial_state_root": self.initial_state_root,
            "current_state_root": self.current_state_root,
            "witness_policy_root": self.witness_policy_root,
            "access_policy_ids": self.access_policy_ids,
            "allowed_operator_ids": self.allowed_operator_ids,
            "privacy_set_size": self.privacy_set_size,
            "namespace_bytes": self.namespace_bytes,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "redaction_budget_id": self.redaction_budget_id,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn deterministic_id(
        contract_id: &str,
        kind: NamespaceKind,
        salt_commitment: &str,
    ) -> String {
        domain_hash(
            "storage-witness-namespace-id",
            &[
                HashPart::Str(contract_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(salt_commitment),
            ],
            20,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageWitnessCommitment {
    pub witness_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub operator_id: String,
    pub kind: WitnessKind,
    pub status: WitnessStatus,
    pub slot_commitment_root: String,
    pub before_root: String,
    pub after_root: String,
    pub delta_commitment: String,
    pub encrypted_witness_root: String,
    pub nullifier: String,
    pub lease_id: Option<String>,
    pub fee_asset: String,
    pub fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub witness_bytes: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub redaction_budget_id: Option<String>,
}

impl StorageWitnessCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "operator_id": self.operator_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "slot_commitment_root": self.slot_commitment_root,
            "before_root": self.before_root,
            "after_root": self.after_root,
            "delta_commitment": self.delta_commitment,
            "encrypted_witness_root": self.encrypted_witness_root,
            "nullifier": self.nullifier,
            "lease_id": self.lease_id,
            "fee_asset": self.fee_asset,
            "fee_micro_units": self.fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "witness_bytes": self.witness_bytes,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "redaction_budget_id": self.redaction_budget_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject: AttestationSubject,
    pub subject_id: String,
    pub namespace_id: Option<String>,
    pub contract_id: Option<String>,
    pub operator_id: String,
    pub pq_public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub quorum_weight_bps: u64,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject": self.subject.as_str(),
            "subject_id": self.subject_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "operator_id": self.operator_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessLeaseOrder {
    pub lease_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub lessee_commitment: String,
    pub operator_id: String,
    pub witness_kind: WitnessKind,
    pub status: LeaseStatus,
    pub ask_fee_asset: String,
    pub ask_fee_micro_units: u64,
    pub max_fee_bps: u64,
    pub capacity_witnesses: u64,
    pub fulfilled_witnesses: u64,
    pub market_epoch: u64,
    pub listed_height: u64,
    pub expires_height: u64,
    pub escrow_root: String,
}

impl WitnessLeaseOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "lessee_commitment": self.lessee_commitment,
            "operator_id": self.operator_id,
            "witness_kind": self.witness_kind.as_str(),
            "status": self.status.as_str(),
            "ask_fee_asset": self.ask_fee_asset,
            "ask_fee_micro_units": self.ask_fee_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "capacity_witnesses": self.capacity_witnesses,
            "fulfilled_witnesses": self.fulfilled_witnesses,
            "market_epoch": self.market_epoch,
            "listed_height": self.listed_height,
            "expires_height": self.expires_height,
            "escrow_root": self.escrow_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessPolicy {
    pub policy_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub mode: AccessMode,
    pub status: PolicyStatus,
    pub grantee_commitment: String,
    pub policy_root: String,
    pub nullifier_root: String,
    pub spending_limit_root: String,
    pub redaction_limit: u64,
    pub granted_height: u64,
    pub expires_height: u64,
}

impl AccessPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "mode": self.mode.as_str(),
            "status": self.status.as_str(),
            "grantee_commitment": self.grantee_commitment,
            "policy_root": self.policy_root,
            "nullifier_root": self.nullifier_root,
            "spending_limit_root": self.spending_limit_root,
            "redaction_limit": self.redaction_limit,
            "granted_height": self.granted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeWitnessRebate {
    pub rebate_id: String,
    pub witness_id: String,
    pub namespace_id: String,
    pub operator_id: String,
    pub status: RebateStatus,
    pub fee_asset: String,
    pub paid_fee_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub coupon_commitment: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl LowFeeWitnessRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "witness_id": self.witness_id,
            "namespace_id": self.namespace_id,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "fee_asset": self.fee_asset,
            "paid_fee_micro_units": self.paid_fee_micro_units,
            "target_fee_micro_units": self.target_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_bps": self.rebate_bps,
            "coupon_commitment": self.coupon_commitment,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceViolationQuarantine {
    pub quarantine_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub violation_kind: ViolationKind,
    pub status: QuarantineStatus,
    pub reporter_commitment: String,
    pub accused_operator_id: Option<String>,
    pub evidence_root: String,
    pub shadow_state_root: String,
    pub mitigation_root: String,
    pub slash_bond_micro_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl NamespaceViolationQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "violation_kind": self.violation_kind.as_str(),
            "status": self.status.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "accused_operator_id": self.accused_operator_id,
            "evidence_root": self.evidence_root,
            "shadow_state_root": self.shadow_state_root,
            "mitigation_root": self.mitigation_root,
            "slash_bond_micro_units": self.slash_bond_micro_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub epoch: u64,
    pub max_redactions: u64,
    pub used_redactions: u64,
    pub policy_root: String,
    pub redacted_field_root: String,
    pub auditor_commitment_root: String,
    pub replenishes_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "epoch": self.epoch,
            "max_redactions": self.max_redactions,
            "used_redactions": self.used_redactions,
            "policy_root": self.policy_root,
            "redacted_field_root": self.redacted_field_root,
            "auditor_commitment_root": self.auditor_commitment_root,
            "replenishes_height": self.replenishes_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicRootCheckpoint {
    pub checkpoint_id: String,
    pub namespace_id: String,
    pub contract_id: String,
    pub height: u64,
    pub manifest_root: String,
    pub witness_root: String,
    pub policy_root: String,
    pub redaction_root: String,
    pub quarantine_root: String,
    pub aggregate_root: String,
}

impl DeterministicRootCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "namespace_id": self.namespace_id,
            "contract_id": self.contract_id,
            "height": self.height,
            "manifest_root": self.manifest_root,
            "witness_root": self.witness_root,
            "policy_root": self.policy_root,
            "redaction_root": self.redaction_root,
            "quarantine_root": self.quarantine_root,
            "aggregate_root": self.aggregate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub namespace_id: Option<String>,
    pub subject_id: String,
    pub kind: String,
    pub record_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "namespace_id": self.namespace_id,
            "subject_id": self.subject_id,
            "kind": self.kind,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub namespace_manifests: BTreeMap<String, NamespaceManifest>,
    pub witness_commitments: BTreeMap<String, StorageWitnessCommitment>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub lease_orders: BTreeMap<String, WitnessLeaseOrder>,
    pub access_policies: BTreeMap<String, AccessPolicy>,
    pub low_fee_rebates: BTreeMap<String, LowFeeWitnessRebate>,
    pub quarantine_cases: BTreeMap<String, NamespaceViolationQuarantine>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub deterministic_root_checkpoints: BTreeMap<String, DeterministicRootCheckpoint>,
    pub events: Vec<RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            namespace_manifests: BTreeMap::new(),
            witness_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            lease_orders: BTreeMap::new(),
            access_policies: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            quarantine_cases: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_root_checkpoints: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_counters_and_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let base_height = state.config.l2_height;
        let contract_id = id("demo-confidential-vault-contract", 20);
        let operator_id = id("demo-storage-witness-operator", 20);
        let namespace_id = NamespaceManifest::deterministic_id(
            &contract_id,
            NamespaceKind::ContractStorage,
            "demo-namespace-salt-commitment",
        );
        let budget_id = id("demo-redaction-budget", 20);
        let policy_id = id("demo-access-policy", 20);
        let lease_id = id("demo-witness-lease", 20);
        let witness_id = id("demo-storage-witness", 20);
        let quarantine_id = id("demo-namespace-quarantine", 20);

        let mut policy_ids = BTreeSet::new();
        policy_ids.insert(policy_id.clone());
        let mut operators = BTreeSet::new();
        operators.insert(operator_id.clone());

        let namespace = NamespaceManifest {
            namespace_id: namespace_id.clone(),
            contract_id: contract_id.clone(),
            owner_commitment: commitment("namespace-owner", &contract_id),
            kind: NamespaceKind::ContractStorage,
            status: NamespaceStatus::Leasing,
            version: 1,
            storage_schema_root: root_from_strs("demo-storage-schema", &["balances", "leases"]),
            initial_state_root: root_from_strs("demo-initial-state", &["vault-empty"]),
            current_state_root: root_from_strs("demo-current-state", &["vault-slot-7"]),
            witness_policy_root: root_from_strs("demo-witness-policy", &["slot", "range", "delta"]),
            access_policy_ids: policy_ids,
            allowed_operator_ids: operators,
            privacy_set_size: 65_536,
            namespace_bytes: 1_048_576,
            created_height: base_height,
            expires_height: base_height + state.config.namespace_ttl_blocks,
            redaction_budget_id: Some(budget_id.clone()),
            metadata_commitment: commitment("namespace-metadata", "demo-vault"),
        };
        state
            .namespace_manifests
            .insert(namespace.namespace_id.clone(), namespace);

        let access_policy = AccessPolicy {
            policy_id: policy_id.clone(),
            namespace_id: namespace_id.clone(),
            contract_id: contract_id.clone(),
            mode: AccessMode::ReadWrite,
            status: PolicyStatus::Active,
            grantee_commitment: commitment("policy-grantee", "devnet-demo-wallet"),
            policy_root: root_from_strs("demo-policy", &["read", "write", "redact-2"]),
            nullifier_root: root_from_strs("demo-policy-nullifiers", &["nf-001", "nf-002"]),
            spending_limit_root: root_from_strs("demo-policy-limits", &["12-bps", "64-witnesses"]),
            redaction_limit: 2,
            granted_height: base_height,
            expires_height: base_height + state.config.policy_ttl_blocks,
        };
        state
            .access_policies
            .insert(access_policy.policy_id.clone(), access_policy);

        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            namespace_id: namespace_id.clone(),
            contract_id: contract_id.clone(),
            epoch: base_height / state.config.redaction_epoch_blocks,
            max_redactions: state.config.max_redactions_per_epoch,
            used_redactions: 2,
            policy_root: root_from_strs("demo-redaction-policy", &["hash-address", "hash-memo"]),
            redacted_field_root: root_from_strs("demo-redacted-fields", &["memo", "view-tag"]),
            auditor_commitment_root: root_from_strs("demo-auditors", &["auditor-a", "auditor-b"]),
            replenishes_height: base_height + state.config.redaction_epoch_blocks,
        };
        state
            .redaction_budgets
            .insert(budget.budget_id.clone(), budget);

        let lease = WitnessLeaseOrder {
            lease_id: lease_id.clone(),
            namespace_id: namespace_id.clone(),
            contract_id: contract_id.clone(),
            lessee_commitment: commitment("lease-lessee", "demo-contract-caller"),
            operator_id: operator_id.clone(),
            witness_kind: WitnessKind::MerkleDelta,
            status: LeaseStatus::Active,
            ask_fee_asset: "piconero-devnet".to_string(),
            ask_fee_micro_units: 1_800,
            max_fee_bps: 12,
            capacity_witnesses: 512,
            fulfilled_witnesses: 17,
            market_epoch: base_height / state.config.lease_ttl_blocks,
            listed_height: base_height,
            expires_height: base_height + state.config.lease_ttl_blocks,
            escrow_root: root_from_strs("demo-lease-escrow", &["bond", "fee-cap"]),
        };
        state.lease_orders.insert(lease.lease_id.clone(), lease);

        let witness = StorageWitnessCommitment {
            witness_id: witness_id.clone(),
            namespace_id: namespace_id.clone(),
            contract_id: contract_id.clone(),
            operator_id: operator_id.clone(),
            kind: WitnessKind::MerkleDelta,
            status: WitnessStatus::Attested,
            slot_commitment_root: root_from_strs("demo-slots", &["slot-7", "slot-19"]),
            before_root: root_from_strs("demo-before", &["vault-slot-7-old"]),
            after_root: root_from_strs("demo-after", &["vault-slot-7-new"]),
            delta_commitment: commitment("demo-delta", "slot-7"),
            encrypted_witness_root: root_from_strs(
                "demo-encrypted-witness",
                &["sealed-a", "sealed-b"],
            ),
            nullifier: commitment("demo-witness-nullifier", "slot-7"),
            lease_id: Some(lease_id.clone()),
            fee_asset: "piconero-devnet".to_string(),
            fee_micro_units: 1_650,
            privacy_set_size: 65_536,
            witness_bytes: 24_576,
            created_height: base_height + 1,
            expires_height: base_height + state.config.witness_ttl_blocks,
            redaction_budget_id: Some(budget_id.clone()),
        };
        state
            .witness_commitments
            .insert(witness.witness_id.clone(), witness);

        let contract_attestation = PqAttestation {
            attestation_id: id("demo-contract-attestation", 20),
            subject: AttestationSubject::Contract,
            subject_id: contract_id.clone(),
            namespace_id: Some(namespace_id.clone()),
            contract_id: Some(contract_id.clone()),
            operator_id: operator_id.clone(),
            pq_public_key_commitment: commitment("pq-key", "contract"),
            signature_commitment: commitment("pq-signature", "contract"),
            transcript_root: root_from_strs("contract-transcript", &["manifest", "policy"]),
            security_bits: 256,
            quorum_weight_bps: 7_200,
            issued_height: base_height + 1,
            expires_height: base_height + state.config.attestation_ttl_blocks,
        };
        state.pq_attestations.insert(
            contract_attestation.attestation_id.clone(),
            contract_attestation,
        );

        let operator_attestation = PqAttestation {
            attestation_id: id("demo-operator-attestation", 20),
            subject: AttestationSubject::Operator,
            subject_id: operator_id.clone(),
            namespace_id: Some(namespace_id.clone()),
            contract_id: Some(contract_id.clone()),
            operator_id: operator_id.clone(),
            pq_public_key_commitment: commitment("pq-key", "operator"),
            signature_commitment: commitment("pq-signature", "operator"),
            transcript_root: root_from_strs("operator-transcript", &["bond", "capacity"]),
            security_bits: 256,
            quorum_weight_bps: 8_000,
            issued_height: base_height + 1,
            expires_height: base_height + state.config.attestation_ttl_blocks,
        };
        state.pq_attestations.insert(
            operator_attestation.attestation_id.clone(),
            operator_attestation,
        );

        let rebate = LowFeeWitnessRebate {
            rebate_id: id("demo-witness-rebate", 20),
            witness_id: witness_id.clone(),
            namespace_id: namespace_id.clone(),
            operator_id: operator_id.clone(),
            status: RebateStatus::Reserved,
            fee_asset: "piconero-devnet".to_string(),
            paid_fee_micro_units: 1_650,
            target_fee_micro_units: 1_200,
            rebate_micro_units: 450,
            rebate_bps: 7,
            coupon_commitment: commitment("demo-rebate-coupon", &witness_id),
            created_height: base_height + 2,
            expires_height: base_height + state.config.lease_ttl_blocks,
        };
        state
            .low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);

        let quarantine = NamespaceViolationQuarantine {
            quarantine_id: quarantine_id.clone(),
            namespace_id: namespace_id.clone(),
            contract_id: contract_id.clone(),
            violation_kind: ViolationKind::WitnessMismatch,
            status: QuarantineStatus::EvidenceLocked,
            reporter_commitment: commitment("demo-quarantine-reporter", "watchtower"),
            accused_operator_id: Some(operator_id.clone()),
            evidence_root: root_from_strs(
                "demo-quarantine-evidence",
                &["before", "after", "delta"],
            ),
            shadow_state_root: root_from_strs("demo-shadow-state", &["shadow-slot-7"]),
            mitigation_root: root_from_strs("demo-mitigation", &["replay", "slash-if-confirmed"]),
            slash_bond_micro_units: state.config.min_operator_bond_micro_units / 2,
            opened_height: base_height + 3,
            expires_height: base_height + state.config.quarantine_ttl_blocks,
        };
        state
            .quarantine_cases
            .insert(quarantine.quarantine_id.clone(), quarantine);

        state.add_checkpoint(&namespace_id, &contract_id, base_height + 4);
        state.add_event(
            base_height,
            Some(namespace_id.clone()),
            contract_id,
            "namespace_demo_seeded",
        );
        state.add_event(
            base_height + 1,
            Some(namespace_id.clone()),
            witness_id,
            "witness_commitment_attested",
        );
        state.add_event(
            base_height + 3,
            Some(namespace_id),
            quarantine_id,
            "namespace_violation_quarantined",
        );
        state.refresh_counters_and_roots();
        state
    }

    pub fn validate(
        &self,
    ) -> PrivateL2PqConfidentialContractStorageWitnessNamespaceRuntimeResult<()> {
        self.config.validate()?;
        for manifest in self.namespace_manifests.values() {
            require(
                self.config.allowed_namespace_kinds.contains(&manifest.kind),
                "namespace kind not allowed",
            )?;
            require(
                manifest.privacy_set_size >= self.config.min_privacy_set_size,
                "namespace privacy set below policy",
            )?;
            require(
                manifest.namespace_bytes <= self.config.max_namespace_bytes,
                "namespace exceeds byte cap",
            )?;
            if manifest.kind.requires_redaction_budget() {
                require(
                    manifest.redaction_budget_id.is_some(),
                    "namespace requires redaction budget",
                )?;
            }
        }
        for witness in self.witness_commitments.values() {
            require(
                self.namespace_manifests.contains_key(&witness.namespace_id),
                "witness references missing namespace",
            )?;
            require(
                self.config.accepted_fee_assets.contains(&witness.fee_asset),
                "witness fee asset not accepted",
            )?;
            require(
                witness.witness_bytes <= self.config.max_witness_bytes,
                "witness exceeds byte cap",
            )?;
            require(
                witness.privacy_set_size >= self.config.min_privacy_set_size,
                "witness privacy set below policy",
            )?;
        }
        for attestation in self.pq_attestations.values() {
            require(
                attestation.security_bits >= self.config.min_pq_security_bits,
                "attestation pq security below policy",
            )?;
            require(
                attestation.quorum_weight_bps <= MAX_BPS,
                "attestation quorum above bps",
            )?;
        }
        for lease in self.lease_orders.values() {
            require(
                self.namespace_manifests.contains_key(&lease.namespace_id),
                "lease references missing namespace",
            )?;
            require(
                self.config
                    .accepted_fee_assets
                    .contains(&lease.ask_fee_asset),
                "lease fee asset not accepted",
            )?;
            require(lease.max_fee_bps <= MAX_BPS, "lease fee cap above bps")?;
        }
        for rebate in self.low_fee_rebates.values() {
            require(
                rebate.rebate_bps <= self.config.rebate_cap_bps,
                "rebate exceeds cap",
            )?;
        }
        Ok(())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "namespace_manifest_suite": NAMESPACE_MANIFEST_SUITE,
            "storage_witness_commitment_suite": STORAGE_WITNESS_COMMITMENT_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "witness_lease_market_suite": WITNESS_LEASE_MARKET_SUITE,
            "access_policy_suite": ACCESS_POLICY_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "quarantine_suite": QUARANTINE_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "deterministic_root_suite": DETERMINISTIC_ROOT_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "namespace_manifest_root": self.roots.namespace_manifest_root,
                "witness_commitment_root": self.roots.witness_commitment_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "lease_market_root": self.roots.lease_market_root,
                "access_policy_root": self.roots.access_policy_root,
                "rebate_root": self.roots.rebate_root,
                "quarantine_root": self.roots.quarantine_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "deterministic_checkpoint_root": self.roots.deterministic_checkpoint_root,
                "event_root": self.roots.event_root,
            },
            "namespace_manifests": records(self.namespace_manifests.values().map(NamespaceManifest::public_record)),
            "witness_commitments": records(self.witness_commitments.values().map(StorageWitnessCommitment::public_record)),
            "pq_attestations": records(self.pq_attestations.values().map(PqAttestation::public_record)),
            "lease_orders": records(self.lease_orders.values().map(WitnessLeaseOrder::public_record)),
            "access_policies": records(self.access_policies.values().map(AccessPolicy::public_record)),
            "low_fee_rebates": records(self.low_fee_rebates.values().map(LowFeeWitnessRebate::public_record)),
            "quarantine_cases": records(self.quarantine_cases.values().map(NamespaceViolationQuarantine::public_record)),
            "redaction_budgets": records(self.redaction_budgets.values().map(PrivacyRedactionBudget::public_record)),
            "deterministic_root_checkpoints": records(self.deterministic_root_checkpoints.values().map(DeterministicRootCheckpoint::public_record)),
            "events": self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(values) = &mut record {
            values.insert(
                "state_root".to_string(),
                Value::String(self.roots.state_root.clone()),
            );
            values.insert(
                "public_record_root".to_string(),
                Value::String(self.roots.public_record_root.clone()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_counters_and_roots(&mut self) {
        self.counters = Counters {
            namespace_manifests: self.namespace_manifests.len() as u64,
            witness_commitments: self.witness_commitments.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            lease_orders: self.lease_orders.len() as u64,
            access_policies: self.access_policies.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            quarantine_cases: self.quarantine_cases.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            deterministic_root_checkpoints: self.deterministic_root_checkpoints.len() as u64,
            events: self.events.len() as u64,
        };

        self.roots.config_root = root_from_values("config", &[self.config.public_record()]);
        self.roots.namespace_manifest_root = root_from_values(
            "namespace-manifests",
            &records(
                self.namespace_manifests
                    .values()
                    .map(NamespaceManifest::public_record),
            ),
        );
        self.roots.witness_commitment_root = root_from_values(
            "witness-commitments",
            &records(
                self.witness_commitments
                    .values()
                    .map(StorageWitnessCommitment::public_record),
            ),
        );
        self.roots.pq_attestation_root = root_from_values(
            "pq-attestations",
            &records(
                self.pq_attestations
                    .values()
                    .map(PqAttestation::public_record),
            ),
        );
        self.roots.lease_market_root = root_from_values(
            "lease-market",
            &records(
                self.lease_orders
                    .values()
                    .map(WitnessLeaseOrder::public_record),
            ),
        );
        self.roots.access_policy_root = root_from_values(
            "access-policies",
            &records(
                self.access_policies
                    .values()
                    .map(AccessPolicy::public_record),
            ),
        );
        self.roots.rebate_root = root_from_values(
            "rebates",
            &records(
                self.low_fee_rebates
                    .values()
                    .map(LowFeeWitnessRebate::public_record),
            ),
        );
        self.roots.quarantine_root = root_from_values(
            "quarantine",
            &records(
                self.quarantine_cases
                    .values()
                    .map(NamespaceViolationQuarantine::public_record),
            ),
        );
        self.roots.redaction_budget_root = root_from_values(
            "redaction-budgets",
            &records(
                self.redaction_budgets
                    .values()
                    .map(PrivacyRedactionBudget::public_record),
            ),
        );
        self.roots.deterministic_checkpoint_root = root_from_values(
            "deterministic-checkpoints",
            &records(
                self.deterministic_root_checkpoints
                    .values()
                    .map(DeterministicRootCheckpoint::public_record),
            ),
        );
        self.roots.event_root = root_from_values(
            "events",
            &self
                .events
                .iter()
                .map(RuntimeEvent::public_record)
                .collect::<Vec<_>>(),
        );
        let public_without_root = self.public_record_without_state_root();
        self.roots.public_record_root = public_record_root(&public_without_root);
        self.roots.state_root = domain_hash(
            "storage-witness-namespace-state-root",
            &[
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.namespace_manifest_root),
                HashPart::Str(&self.roots.witness_commitment_root),
                HashPart::Str(&self.roots.pq_attestation_root),
                HashPart::Str(&self.roots.lease_market_root),
                HashPart::Str(&self.roots.access_policy_root),
                HashPart::Str(&self.roots.rebate_root),
                HashPart::Str(&self.roots.quarantine_root),
                HashPart::Str(&self.roots.redaction_budget_root),
                HashPart::Str(&self.roots.deterministic_checkpoint_root),
                HashPart::Str(&self.roots.event_root),
                HashPart::Str(&self.roots.public_record_root),
            ],
            32,
        );
    }

    fn add_checkpoint(&mut self, namespace_id: &str, contract_id: &str, height: u64) {
        let manifest_root = root_from_values(
            "checkpoint-manifest",
            &records(
                self.namespace_manifests
                    .values()
                    .filter(|manifest| manifest.namespace_id == namespace_id)
                    .map(NamespaceManifest::public_record),
            ),
        );
        let witness_root = root_from_values(
            "checkpoint-witness",
            &records(
                self.witness_commitments
                    .values()
                    .filter(|witness| witness.namespace_id == namespace_id)
                    .map(StorageWitnessCommitment::public_record),
            ),
        );
        let policy_root = root_from_values(
            "checkpoint-policy",
            &records(
                self.access_policies
                    .values()
                    .filter(|policy| policy.namespace_id == namespace_id)
                    .map(AccessPolicy::public_record),
            ),
        );
        let redaction_root = root_from_values(
            "checkpoint-redaction",
            &records(
                self.redaction_budgets
                    .values()
                    .filter(|budget| budget.namespace_id == namespace_id)
                    .map(PrivacyRedactionBudget::public_record),
            ),
        );
        let quarantine_root = root_from_values(
            "checkpoint-quarantine",
            &records(
                self.quarantine_cases
                    .values()
                    .filter(|case| case.namespace_id == namespace_id)
                    .map(NamespaceViolationQuarantine::public_record),
            ),
        );
        let aggregate_root = domain_hash(
            "storage-witness-namespace-checkpoint-root",
            &[
                HashPart::Str(namespace_id),
                HashPart::Str(contract_id),
                HashPart::U64(height),
                HashPart::Str(&manifest_root),
                HashPart::Str(&witness_root),
                HashPart::Str(&policy_root),
                HashPart::Str(&redaction_root),
                HashPart::Str(&quarantine_root),
            ],
            32,
        );
        let checkpoint = DeterministicRootCheckpoint {
            checkpoint_id: id(&format!("checkpoint:{namespace_id}:{height}"), 20),
            namespace_id: namespace_id.to_string(),
            contract_id: contract_id.to_string(),
            height,
            manifest_root,
            witness_root,
            policy_root,
            redaction_root,
            quarantine_root,
            aggregate_root,
        };
        self.deterministic_root_checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint);
    }

    fn add_event(
        &mut self,
        height: u64,
        namespace_id: Option<String>,
        subject_id: String,
        kind: &str,
    ) {
        let record_root = domain_hash(
            "storage-witness-event-record",
            &[
                HashPart::U64(height),
                HashPart::Str(namespace_id.as_deref().unwrap_or("none")),
                HashPart::Str(&subject_id),
                HashPart::Str(kind),
            ],
            32,
        );
        let event = RuntimeEvent {
            event_id: id(&format!("event:{height}:{subject_id}:{kind}"), 20),
            height,
            namespace_id,
            subject_id,
            kind: kind.to_string(),
            record_root,
        };
        self.events.push(event);
    }
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

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "storage-witness-namespace-public-record",
        &[HashPart::Json(record)],
        32,
    )
}

fn root_from_values(domain: &str, values: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-STORAGE-WITNESS-NAMESPACE-{domain}"),
        values,
    )
}

fn root_from_strs(domain: &str, values: &[&str]) -> String {
    let records = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    root_from_values(domain, &records)
}

fn records<I>(items: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    let mut values = items.into_iter().collect::<Vec<_>>();
    values.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
    values
}

fn id(seed: &str, out_len: usize) -> String {
    domain_hash(
        "storage-witness-namespace-id-fragment",
        &[HashPart::Str(seed)],
        out_len,
    )
}

fn commitment(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!("storage-witness-namespace-commitment-{domain}"),
        &[HashPart::Str(seed)],
        32,
    )
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqConfidentialContractStorageWitnessNamespaceRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
