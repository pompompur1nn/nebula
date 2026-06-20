use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqContractRuntimeAttestationLedgerResult<T> = Result<T, String>;

pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION: &str =
    "nebula-pq-contract-runtime-attestation-ledger-v1";
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MIN_ATTESTER_QUORUM: u64 = 3;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MAX_RELEASE_AGE_BLOCKS: u64 = 7_200;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MAX_KEY_EPOCH_AGE_BLOCKS: u64 = 43_200;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_REVOCATION_TTL_BLOCKS: u64 = 2_880;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_RUNTIMES: usize = 256;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_KEY_EPOCHS: usize = 512;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_RELEASES: usize = 1_024;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_ATTESTATIONS: usize = 2_048;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_REVOCATIONS: usize = 512;
pub const PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEVNET_HEIGHT: u64 = 58_240;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeClass {
    ContractVm,
    ZkCircuitHost,
    PrivateEventIndex,
    TokenHookRuntime,
    BridgeSettlementAdapter,
    EmergencyRecoveryRuntime,
}

impl RuntimeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractVm => "contract_vm",
            Self::ZkCircuitHost => "zk_circuit_host",
            Self::PrivateEventIndex => "private_event_index",
            Self::TokenHookRuntime => "token_hook_runtime",
            Self::BridgeSettlementAdapter => "bridge_settlement_adapter",
            Self::EmergencyRecoveryRuntime => "emergency_recovery_runtime",
        }
    }

    pub fn critical(self) -> bool {
        matches!(
            self,
            Self::ContractVm | Self::ZkCircuitHost | Self::BridgeSettlementAdapter
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    BuildReproducibility,
    CircuitHash,
    PqSignature,
    StaticAnalysis,
    PrivacyInvariant,
    OperatorQuorum,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuildReproducibility => "build_reproducibility",
            Self::CircuitHash => "circuit_hash",
            Self::PqSignature => "pq_signature",
            Self::StaticAnalysis => "static_analysis",
            Self::PrivacyInvariant => "privacy_invariant",
            Self::OperatorQuorum => "operator_quorum",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Candidate,
    Active,
    Deprecated,
    Frozen,
    Revoked,
}

impl ReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Frozen => "frozen",
            Self::Revoked => "revoked",
        }
    }

    pub fn executable(self) -> bool {
        matches!(self, Self::Candidate | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    KeyCompromise,
    CircuitMismatch,
    PrivacyLeakage,
    BuildMismatch,
    GovernanceEmergency,
    ExpiredEpoch,
}

impl RevocationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyCompromise => "key_compromise",
            Self::CircuitMismatch => "circuit_mismatch",
            Self::PrivacyLeakage => "privacy_leakage",
            Self::BuildMismatch => "build_mismatch",
            Self::GovernanceEmergency => "governance_emergency",
            Self::ExpiredEpoch => "expired_epoch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub min_pq_security_bits: u64,
    pub min_attester_quorum: u64,
    pub max_release_age_blocks: u64,
    pub max_key_epoch_age_blocks: u64,
    pub revocation_ttl_blocks: u64,
    pub require_privacy_invariant_attestation: bool,
    pub require_reproducible_build: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            min_pq_security_bits:
                PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_attester_quorum: PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MIN_ATTESTER_QUORUM,
            max_release_age_blocks:
                PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MAX_RELEASE_AGE_BLOCKS,
            max_key_epoch_age_blocks:
                PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_MAX_KEY_EPOCH_AGE_BLOCKS,
            revocation_ttl_blocks:
                PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEFAULT_REVOCATION_TTL_BLOCKS,
            require_privacy_invariant_attestation: true,
            require_reproducible_build: true,
        }
    }

    pub fn validate(&self) -> PqContractRuntimeAttestationLedgerResult<()> {
        if self.min_pq_security_bits < 128 {
            return Err("minimum post-quantum security target is too low".to_string());
        }
        if self.min_attester_quorum == 0 {
            return Err("attester quorum must be positive".to_string());
        }
        if self.max_release_age_blocks == 0
            || self.max_key_epoch_age_blocks == 0
            || self.revocation_ttl_blocks == 0
        {
            return Err("runtime attestation windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_runtime_attestation_ledger_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_attester_quorum": self.min_attester_quorum,
            "max_release_age_blocks": self.max_release_age_blocks,
            "max_key_epoch_age_blocks": self.max_key_epoch_age_blocks,
            "revocation_ttl_blocks": self.revocation_ttl_blocks,
            "require_privacy_invariant_attestation": self.require_privacy_invariant_attestation,
            "require_reproducible_build": self.require_reproducible_build,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDescriptor {
    pub runtime_id: String,
    pub runtime_class: RuntimeClass,
    pub label: String,
    pub owner_commitment: String,
    pub policy_root: String,
    pub critical: bool,
}

impl RuntimeDescriptor {
    pub fn new(
        runtime_class: RuntimeClass,
        label: &str,
        owner_commitment: &str,
        policy: &Value,
    ) -> PqContractRuntimeAttestationLedgerResult<Self> {
        if label.is_empty() || owner_commitment.is_empty() {
            return Err("runtime descriptor identifiers cannot be empty".to_string());
        }
        let policy_root =
            pq_contract_runtime_attestation_payload_root("PQ-CONTRACT-RUNTIME-POLICY", policy);
        let runtime_id =
            runtime_descriptor_id(runtime_class, label, owner_commitment, &policy_root);
        Ok(Self {
            runtime_id,
            runtime_class,
            label: label.to_string(),
            owner_commitment: owner_commitment.to_string(),
            policy_root,
            critical: runtime_class.critical(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_runtime_descriptor",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION,
            "runtime_id": self.runtime_id,
            "runtime_class": self.runtime_class.as_str(),
            "label": self.label,
            "owner_commitment": self.owner_commitment,
            "policy_root": self.policy_root,
            "critical": self.critical,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEpoch {
    pub key_epoch_id: String,
    pub runtime_id: String,
    pub epoch: u64,
    pub pq_scheme: String,
    pub public_key_root: String,
    pub security_bits: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub attester_commitments: BTreeSet<String>,
}

impl KeyEpoch {
    pub fn new(
        runtime_id: &str,
        epoch: u64,
        pq_scheme: &str,
        public_key_root: &str,
        security_bits: u64,
        starts_at_height: u64,
        expires_at_height: u64,
        attester_commitments: BTreeSet<String>,
    ) -> PqContractRuntimeAttestationLedgerResult<Self> {
        if runtime_id.is_empty() || pq_scheme.is_empty() || public_key_root.is_empty() {
            return Err("key epoch identifiers cannot be empty".to_string());
        }
        if expires_at_height <= starts_at_height {
            return Err("key epoch must expire after it starts".to_string());
        }
        if attester_commitments.is_empty() {
            return Err("key epoch must have attesters".to_string());
        }
        let key_epoch_id = key_epoch_id(
            runtime_id,
            epoch,
            pq_scheme,
            public_key_root,
            security_bits,
            starts_at_height,
            expires_at_height,
        );
        Ok(Self {
            key_epoch_id,
            runtime_id: runtime_id.to_string(),
            epoch,
            pq_scheme: pq_scheme.to_string(),
            public_key_root: public_key_root.to_string(),
            security_bits,
            starts_at_height,
            expires_at_height,
            attester_commitments,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.starts_at_height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_runtime_key_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION,
            "key_epoch_id": self.key_epoch_id,
            "runtime_id": self.runtime_id,
            "epoch": self.epoch,
            "pq_scheme": self.pq_scheme,
            "public_key_root": self.public_key_root,
            "security_bits": self.security_bits,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "attester_commitments": self.attester_commitments.iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRelease {
    pub release_id: String,
    pub runtime_id: String,
    pub key_epoch_id: String,
    pub release_label: String,
    pub source_commitment: String,
    pub artifact_root: String,
    pub circuit_root: String,
    pub status: ReleaseStatus,
    pub published_at_height: u64,
}

impl RuntimeRelease {
    pub fn new(
        runtime_id: &str,
        key_epoch_id: &str,
        release_label: &str,
        source_commitment: &str,
        artifact: &Value,
        circuit: &Value,
        status: ReleaseStatus,
        published_at_height: u64,
    ) -> PqContractRuntimeAttestationLedgerResult<Self> {
        if runtime_id.is_empty()
            || key_epoch_id.is_empty()
            || release_label.is_empty()
            || source_commitment.is_empty()
        {
            return Err("runtime release identifiers cannot be empty".to_string());
        }
        let artifact_root =
            pq_contract_runtime_attestation_payload_root("PQ-CONTRACT-RUNTIME-ARTIFACT", artifact);
        let circuit_root =
            pq_contract_runtime_attestation_payload_root("PQ-CONTRACT-RUNTIME-CIRCUIT", circuit);
        let release_id = runtime_release_id(
            runtime_id,
            key_epoch_id,
            release_label,
            source_commitment,
            &artifact_root,
            &circuit_root,
        );
        Ok(Self {
            release_id,
            runtime_id: runtime_id.to_string(),
            key_epoch_id: key_epoch_id.to_string(),
            release_label: release_label.to_string(),
            source_commitment: source_commitment.to_string(),
            artifact_root,
            circuit_root,
            status,
            published_at_height,
        })
    }

    pub fn active_at(&self, height: u64, config: &Config) -> bool {
        self.status.executable()
            && height.saturating_sub(self.published_at_height) <= config.max_release_age_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_runtime_release",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION,
            "release_id": self.release_id,
            "runtime_id": self.runtime_id,
            "key_epoch_id": self.key_epoch_id,
            "release_label": self.release_label,
            "source_commitment": self.source_commitment,
            "artifact_root": self.artifact_root,
            "circuit_root": self.circuit_root,
            "status": self.status.as_str(),
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAttestation {
    pub attestation_id: String,
    pub release_id: String,
    pub attestation_kind: AttestationKind,
    pub attester_commitment: String,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub height: u64,
}

impl RuntimeAttestation {
    pub fn new(
        release_id: &str,
        attestation_kind: AttestationKind,
        attester_commitment: &str,
        evidence: &Value,
        pq_signature_root: &str,
        height: u64,
    ) -> PqContractRuntimeAttestationLedgerResult<Self> {
        if release_id.is_empty() || attester_commitment.is_empty() || pq_signature_root.is_empty() {
            return Err("runtime attestation identifiers cannot be empty".to_string());
        }
        let evidence_root = pq_contract_runtime_attestation_payload_root(
            "PQ-CONTRACT-RUNTIME-ATTESTATION-EVIDENCE",
            evidence,
        );
        let attestation_id = runtime_attestation_id(
            release_id,
            attestation_kind,
            attester_commitment,
            &evidence_root,
            pq_signature_root,
            height,
        );
        Ok(Self {
            attestation_id,
            release_id: release_id.to_string(),
            attestation_kind,
            attester_commitment: attester_commitment.to_string(),
            evidence_root,
            pq_signature_root: pq_signature_root.to_string(),
            height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_runtime_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "release_id": self.release_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "attester_commitment": self.attester_commitment,
            "evidence_root": self.evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRevocation {
    pub revocation_id: String,
    pub release_id: String,
    pub reason: RevocationReason,
    pub evidence_root: String,
    pub governance_root: String,
    pub height: u64,
    pub expires_at_height: u64,
}

impl RuntimeRevocation {
    pub fn new(
        release_id: &str,
        reason: RevocationReason,
        evidence: &Value,
        governance: &Value,
        height: u64,
        expires_at_height: u64,
    ) -> PqContractRuntimeAttestationLedgerResult<Self> {
        if release_id.is_empty() {
            return Err("runtime revocation release id cannot be empty".to_string());
        }
        if expires_at_height <= height {
            return Err("runtime revocation must expire after its height".to_string());
        }
        let evidence_root = pq_contract_runtime_attestation_payload_root(
            "PQ-CONTRACT-RUNTIME-REVOCATION-EVIDENCE",
            evidence,
        );
        let governance_root = pq_contract_runtime_attestation_payload_root(
            "PQ-CONTRACT-RUNTIME-REVOCATION-GOVERNANCE",
            governance,
        );
        let revocation_id = runtime_revocation_id(
            release_id,
            reason,
            &evidence_root,
            &governance_root,
            height,
            expires_at_height,
        );
        Ok(Self {
            revocation_id,
            release_id: release_id.to_string(),
            reason,
            evidence_root,
            governance_root,
            height,
            expires_at_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_contract_runtime_revocation",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION,
            "revocation_id": self.revocation_id,
            "release_id": self.release_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "governance_root": self.governance_root,
            "height": self.height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub runtime_root: String,
    pub key_epoch_root: String,
    pub release_root: String,
    pub attestation_root: String,
    pub revocation_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "runtime_root": self.runtime_root,
            "key_epoch_root": self.key_epoch_root,
            "release_root": self.release_root,
            "attestation_root": self.attestation_root,
            "revocation_root": self.revocation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub runtime_count: u64,
    pub key_epoch_count: u64,
    pub release_count: u64,
    pub attestation_count: u64,
    pub revocation_count: u64,
    pub executable_release_count: u64,
    pub revoked_release_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "runtime_count": self.runtime_count,
            "key_epoch_count": self.key_epoch_count,
            "release_count": self.release_count,
            "attestation_count": self.attestation_count,
            "revocation_count": self.revocation_count,
            "executable_release_count": self.executable_release_count,
            "revoked_release_count": self.revoked_release_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub runtimes: BTreeMap<String, RuntimeDescriptor>,
    pub key_epochs: BTreeMap<String, KeyEpoch>,
    pub releases: BTreeMap<String, RuntimeRelease>,
    pub attestations: BTreeMap<String, RuntimeAttestation>,
    pub revocations: BTreeMap<String, RuntimeRevocation>,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl State {
    pub fn new(height: u64, config: Config) -> PqContractRuntimeAttestationLedgerResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            runtimes: BTreeMap::new(),
            key_epochs: BTreeMap::new(),
            releases: BTreeMap::new(),
            attestations: BTreeMap::new(),
            revocations: BTreeMap::new(),
            roots: Roots {
                config_root: String::new(),
                runtime_root: String::new(),
                key_epoch_root: String::new(),
                release_root: String::new(),
                attestation_root: String::new(),
                revocation_root: String::new(),
            },
            counters: Counters {
                runtime_count: 0,
                key_epoch_count: 0,
                release_count: 0,
                attestation_count: 0,
                revocation_count: 0,
                executable_release_count: 0,
                revoked_release_count: 0,
            },
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn insert_runtime(
        &mut self,
        runtime: RuntimeDescriptor,
    ) -> PqContractRuntimeAttestationLedgerResult<()> {
        if self.runtimes.len() >= PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_RUNTIMES {
            return Err("runtime descriptor limit exceeded".to_string());
        }
        self.runtimes.insert(runtime.runtime_id.clone(), runtime);
        self.refresh();
        Ok(())
    }

    pub fn insert_key_epoch(
        &mut self,
        key_epoch: KeyEpoch,
    ) -> PqContractRuntimeAttestationLedgerResult<()> {
        if self.key_epochs.len() >= PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_KEY_EPOCHS {
            return Err("key epoch limit exceeded".to_string());
        }
        if !self.runtimes.contains_key(&key_epoch.runtime_id) {
            return Err("key epoch references unknown runtime".to_string());
        }
        if key_epoch.security_bits < self.config.min_pq_security_bits {
            return Err("key epoch security bits below configured floor".to_string());
        }
        if key_epoch.attester_commitments.len() < self.config.min_attester_quorum as usize {
            return Err("key epoch attester quorum below configured floor".to_string());
        }
        self.key_epochs
            .insert(key_epoch.key_epoch_id.clone(), key_epoch);
        self.refresh();
        Ok(())
    }

    pub fn insert_release(
        &mut self,
        release: RuntimeRelease,
    ) -> PqContractRuntimeAttestationLedgerResult<()> {
        if self.releases.len() >= PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_RELEASES {
            return Err("runtime release limit exceeded".to_string());
        }
        if !self.runtimes.contains_key(&release.runtime_id) {
            return Err("runtime release references unknown runtime".to_string());
        }
        if !self.key_epochs.contains_key(&release.key_epoch_id) {
            return Err("runtime release references unknown key epoch".to_string());
        }
        self.releases.insert(release.release_id.clone(), release);
        self.refresh();
        Ok(())
    }

    pub fn insert_attestation(
        &mut self,
        attestation: RuntimeAttestation,
    ) -> PqContractRuntimeAttestationLedgerResult<()> {
        if self.attestations.len() >= PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_ATTESTATIONS {
            return Err("runtime attestation limit exceeded".to_string());
        }
        if !self.releases.contains_key(&attestation.release_id) {
            return Err("runtime attestation references unknown release".to_string());
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh();
        Ok(())
    }

    pub fn insert_revocation(
        &mut self,
        revocation: RuntimeRevocation,
    ) -> PqContractRuntimeAttestationLedgerResult<()> {
        if self.revocations.len() >= PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_MAX_REVOCATIONS {
            return Err("runtime revocation limit exceeded".to_string());
        }
        if !self.releases.contains_key(&revocation.release_id) {
            return Err("runtime revocation references unknown release".to_string());
        }
        self.revocations
            .insert(revocation.revocation_id.clone(), revocation);
        self.refresh();
        Ok(())
    }

    pub fn attestation_kinds_for_release(&self, release_id: &str) -> BTreeSet<AttestationKind> {
        self.attestations
            .values()
            .filter(|attestation| attestation.release_id == release_id)
            .map(|attestation| attestation.attestation_kind)
            .collect()
    }

    pub fn release_has_required_attestations(&self, release: &RuntimeRelease) -> bool {
        let kinds = self.attestation_kinds_for_release(&release.release_id);
        let has_quorum = self
            .attestations
            .values()
            .filter(|attestation| attestation.release_id == release.release_id)
            .map(|attestation| attestation.attester_commitment.clone())
            .collect::<BTreeSet<_>>()
            .len()
            >= self.config.min_attester_quorum as usize;
        let privacy_ok = !self.config.require_privacy_invariant_attestation
            || kinds.contains(&AttestationKind::PrivacyInvariant);
        let build_ok = !self.config.require_reproducible_build
            || kinds.contains(&AttestationKind::BuildReproducibility);
        has_quorum
            && privacy_ok
            && build_ok
            && kinds.contains(&AttestationKind::CircuitHash)
            && kinds.contains(&AttestationKind::PqSignature)
    }

    pub fn release_is_revoked(&self, release_id: &str) -> bool {
        self.revocations.values().any(|revocation| {
            revocation.release_id == release_id && revocation.active_at(self.height)
        })
    }

    pub fn executable_release_ids(&self) -> Vec<String> {
        self.releases
            .values()
            .filter(|release| {
                release.active_at(self.height, &self.config)
                    && self.release_has_required_attestations(release)
                    && !self.release_is_revoked(&release.release_id)
            })
            .map(|release| release.release_id.clone())
            .collect()
    }

    pub fn refresh(&mut self) {
        self.roots = Roots {
            config_root: pq_contract_runtime_attestation_payload_root(
                "PQ-CONTRACT-RUNTIME-CONFIG",
                &self.config.public_record(),
            ),
            runtime_root: runtime_descriptor_root(
                &self.runtimes.values().cloned().collect::<Vec<_>>(),
            ),
            key_epoch_root: key_epoch_root(&self.key_epochs.values().cloned().collect::<Vec<_>>()),
            release_root: runtime_release_root(
                &self.releases.values().cloned().collect::<Vec<_>>(),
            ),
            attestation_root: runtime_attestation_root(
                &self.attestations.values().cloned().collect::<Vec<_>>(),
            ),
            revocation_root: runtime_revocation_root(
                &self.revocations.values().cloned().collect::<Vec<_>>(),
            ),
        };
        self.counters = Counters {
            runtime_count: self.runtimes.len() as u64,
            key_epoch_count: self.key_epochs.len() as u64,
            release_count: self.releases.len() as u64,
            attestation_count: self.attestations.len() as u64,
            revocation_count: self.revocations.len() as u64,
            executable_release_count: self.executable_release_ids().len() as u64,
            revoked_release_count: self
                .releases
                .keys()
                .filter(|release_id| self.release_is_revoked(release_id))
                .count() as u64,
        };
        self.state_root = root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "pq_contract_runtime_attestation_ledger_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "executable_release_ids": self.executable_release_ids(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }

    pub fn devnet() -> PqContractRuntimeAttestationLedgerResult<Self> {
        let mut state = Self::new(
            PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        let runtime = RuntimeDescriptor::new(
            RuntimeClass::ContractVm,
            "devnet-private-contract-vm",
            "owner-commitment-contract-vm",
            &json!({"max_call_depth": 16, "private_events": true, "pq_required": true}),
        )?;
        state.insert_runtime(runtime.clone())?;
        let attesters = ["attester-a", "attester-b", "attester-c"]
            .iter()
            .map(|value| value.to_string())
            .collect::<BTreeSet<_>>();
        let key_epoch = KeyEpoch::new(
            &runtime.runtime_id,
            7,
            "ml-dsa-87+shake256",
            "runtime-public-key-root-devnet",
            256,
            PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEVNET_HEIGHT.saturating_sub(512),
            PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEVNET_HEIGHT.saturating_add(43_200),
            attesters,
        )?;
        state.insert_key_epoch(key_epoch.clone())?;
        let release = RuntimeRelease::new(
            &runtime.runtime_id,
            &key_epoch.key_epoch_id,
            "private-contract-vm-0.9.0-devnet",
            "source-commitment-contract-vm-090",
            &json!({"wasm_root": "artifact-wasm-root", "prover_abi": "abi-v4"}),
            &json!({"circuit_set_root": "circuit-root-contract-vm", "field": "pallas"}),
            ReleaseStatus::Active,
            PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEVNET_HEIGHT.saturating_sub(64),
        )?;
        state.insert_release(release.clone())?;
        for kind in [
            AttestationKind::BuildReproducibility,
            AttestationKind::CircuitHash,
            AttestationKind::PqSignature,
            AttestationKind::PrivacyInvariant,
        ] {
            state.insert_attestation(RuntimeAttestation::new(
                &release.release_id,
                kind,
                &format!("attester-commitment-{}", kind.as_str()),
                &json!({"release_label": release.release_label, "attestation_kind": kind.as_str()}),
                &format!("pq-signature-root-{}", kind.as_str()),
                PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_DEVNET_HEIGHT,
            )?)?;
        }
        Ok(state)
    }
}

pub fn runtime_descriptor_id(
    runtime_class: RuntimeClass,
    label: &str,
    owner_commitment: &str,
    policy_root: &str,
) -> String {
    domain_hash(
        "PQ-CONTRACT-RUNTIME-DESCRIPTOR-ID",
        &[
            HashPart::Str(PQ_CONTRACT_RUNTIME_ATTESTATION_LEDGER_PROTOCOL_VERSION),
            HashPart::Str(runtime_class.as_str()),
            HashPart::Str(label),
            HashPart::Str(owner_commitment),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn key_epoch_id(
    runtime_id: &str,
    epoch: u64,
    pq_scheme: &str,
    public_key_root: &str,
    security_bits: u64,
    starts_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-RUNTIME-KEY-EPOCH-ID",
        &[
            HashPart::Str(runtime_id),
            HashPart::Int(epoch as i128),
            HashPart::Str(pq_scheme),
            HashPart::Str(public_key_root),
            HashPart::Int(security_bits as i128),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn runtime_release_id(
    runtime_id: &str,
    key_epoch_id: &str,
    release_label: &str,
    source_commitment: &str,
    artifact_root: &str,
    circuit_root: &str,
) -> String {
    domain_hash(
        "PQ-CONTRACT-RUNTIME-RELEASE-ID",
        &[
            HashPart::Str(runtime_id),
            HashPart::Str(key_epoch_id),
            HashPart::Str(release_label),
            HashPart::Str(source_commitment),
            HashPart::Str(artifact_root),
            HashPart::Str(circuit_root),
        ],
        32,
    )
}

pub fn runtime_attestation_id(
    release_id: &str,
    attestation_kind: AttestationKind,
    attester_commitment: &str,
    evidence_root: &str,
    pq_signature_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-RUNTIME-ATTESTATION-ID",
        &[
            HashPart::Str(release_id),
            HashPart::Str(attestation_kind.as_str()),
            HashPart::Str(attester_commitment),
            HashPart::Str(evidence_root),
            HashPart::Str(pq_signature_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn runtime_revocation_id(
    release_id: &str,
    reason: RevocationReason,
    evidence_root: &str,
    governance_root: &str,
    height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CONTRACT-RUNTIME-REVOCATION-ID",
        &[
            HashPart::Str(release_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(governance_root),
            HashPart::Int(height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn runtime_descriptor_root(runtimes: &[RuntimeDescriptor]) -> String {
    let leaves = runtimes
        .iter()
        .map(RuntimeDescriptor::public_record)
        .collect::<Vec<_>>();
    merkle_root("PQ-CONTRACT-RUNTIME-DESCRIPTORS", &leaves)
}

pub fn key_epoch_root(epochs: &[KeyEpoch]) -> String {
    let leaves = epochs
        .iter()
        .map(KeyEpoch::public_record)
        .collect::<Vec<_>>();
    merkle_root("PQ-CONTRACT-RUNTIME-KEY-EPOCHS", &leaves)
}

pub fn runtime_release_root(releases: &[RuntimeRelease]) -> String {
    let leaves = releases
        .iter()
        .map(RuntimeRelease::public_record)
        .collect::<Vec<_>>();
    merkle_root("PQ-CONTRACT-RUNTIME-RELEASES", &leaves)
}

pub fn runtime_attestation_root(attestations: &[RuntimeAttestation]) -> String {
    let leaves = attestations
        .iter()
        .map(RuntimeAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root("PQ-CONTRACT-RUNTIME-ATTESTATIONS", &leaves)
}

pub fn runtime_revocation_root(revocations: &[RuntimeRevocation]) -> String {
    let leaves = revocations
        .iter()
        .map(RuntimeRevocation::public_record)
        .collect::<Vec<_>>();
    merkle_root("PQ-CONTRACT-RUNTIME-REVOCATIONS", &leaves)
}

pub fn pq_contract_runtime_attestation_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-CONTRACT-RUNTIME-ATTESTATION-LEDGER-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PqContractRuntimeAttestationLedgerResult<State> {
    State::devnet()
}
