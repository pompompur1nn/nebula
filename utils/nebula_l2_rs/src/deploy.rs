use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DeployResult<T> = Result<T, String>;

pub const DEPLOY_PROTOCOL_VERSION: &str = "nebula-deploy-v1";
pub const DEPLOY_PROFILE_VERSION: u64 = 1;
pub const DEPLOY_STATUS_DRAFT: &str = "draft";
pub const DEPLOY_STATUS_READY: &str = "ready";
pub const DEPLOY_STATUS_BLOCKED: &str = "blocked";
pub const DEPLOY_STATUS_ACTIVE: &str = "active";
pub const DEPLOY_STATUS_ROLLBACK_READY: &str = "rollback_ready";
pub const DEPLOY_DEFAULT_DEVNET_MONERO_CONFIRMATIONS: u64 = 3;
pub const DEPLOY_DEFAULT_TESTNET_MONERO_CONFIRMATIONS: u64 = 10;
pub const DEPLOY_DEFAULT_MAINNET_MONERO_CONFIRMATIONS: u64 = 20;
pub const DEPLOY_MIN_READY_SCORE_BPS: u64 = 8_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTier {
    Devnet,
    Testnet,
    Mainnet,
}

impl DeploymentTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    pub fn monero_confirmations(self) -> u64 {
        match self {
            Self::Devnet => DEPLOY_DEFAULT_DEVNET_MONERO_CONFIRMATIONS,
            Self::Testnet => DEPLOY_DEFAULT_TESTNET_MONERO_CONFIRMATIONS,
            Self::Mainnet => DEPLOY_DEFAULT_MAINNET_MONERO_CONFIRMATIONS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployServiceKind {
    Sequencer,
    Rpc,
    P2p,
    Prover,
    DataAvailability,
    MoneroRpc,
    MoneroWalletRpc,
    Watchtower,
    Oracle,
    Indexer,
    Operator,
}

impl DeployServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Rpc => "rpc",
            Self::P2p => "p2p",
            Self::Prover => "prover",
            Self::DataAvailability => "data_availability",
            Self::MoneroRpc => "monero_rpc",
            Self::MoneroWalletRpc => "monero_wallet_rpc",
            Self::Watchtower => "watchtower",
            Self::Oracle => "oracle",
            Self::Indexer => "indexer",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeGateKind {
    CryptoPolicy,
    StateMigration,
    MoneroBridge,
    DataAvailability,
    Governance,
    OperatorQuorum,
}

impl UpgradeGateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CryptoPolicy => "crypto_policy",
            Self::StateMigration => "state_migration",
            Self::MoneroBridge => "monero_bridge",
            Self::DataAvailability => "data_availability",
            Self::Governance => "governance",
            Self::OperatorQuorum => "operator_quorum",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub endpoint_id: String,
    pub service_label: String,
    pub service_kind: DeployServiceKind,
    pub bind_commitment: String,
    pub advertised_url_commitment: String,
    pub port: u16,
    pub tls_required: bool,
    pub status: String,
}

impl ServiceEndpoint {
    pub fn new(
        service_label: impl Into<String>,
        service_kind: DeployServiceKind,
        bind_commitment: impl Into<String>,
        advertised_url_commitment: impl Into<String>,
        port: u16,
        tls_required: bool,
    ) -> DeployResult<Self> {
        let service_label = service_label.into();
        let bind_commitment = bind_commitment.into();
        let advertised_url_commitment = advertised_url_commitment.into();
        ensure_non_empty(&service_label, "deploy endpoint service label")?;
        ensure_non_empty(&bind_commitment, "deploy endpoint bind commitment")?;
        ensure_non_empty(
            &advertised_url_commitment,
            "deploy endpoint advertised url commitment",
        )?;
        if port == 0 {
            return Err("deploy endpoint port must be non-zero".to_string());
        }
        let endpoint_id = service_endpoint_id(
            &service_label,
            service_kind,
            &bind_commitment,
            &advertised_url_commitment,
            port,
            tls_required,
        );
        Ok(Self {
            endpoint_id,
            service_label,
            service_kind,
            bind_commitment,
            advertised_url_commitment,
            port,
            tls_required,
            status: DEPLOY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "service_endpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": DEPLOY_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "service_label": self.service_label,
            "service_kind": self.service_kind.as_str(),
            "bind_commitment": self.bind_commitment,
            "advertised_url_commitment": self.advertised_url_commitment,
            "port": self.port,
            "tls_required": self.tls_required,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployService {
    pub service_id: String,
    pub label: String,
    pub service_kind: DeployServiceKind,
    pub replicas: u64,
    pub image_commitment: String,
    pub endpoint_root: String,
    pub dependency_root: String,
    pub status: String,
}

impl DeployService {
    pub fn new(
        label: impl Into<String>,
        service_kind: DeployServiceKind,
        replicas: u64,
        image_commitment: impl Into<String>,
        endpoints: &[ServiceEndpoint],
        dependencies: &[String],
    ) -> DeployResult<Self> {
        let label = label.into();
        let image_commitment = image_commitment.into();
        ensure_non_empty(&label, "deploy service label")?;
        ensure_non_empty(&image_commitment, "deploy service image commitment")?;
        ensure_positive(replicas, "deploy service replicas")?;
        ensure_unique_strings(dependencies, "deploy service dependencies")?;
        let endpoint_root = service_endpoint_root(endpoints);
        let dependency_root = deploy_string_set_root("DEPLOY-SERVICE-DEPENDENCIES", dependencies);
        let service_id = deploy_service_id(
            &label,
            service_kind,
            replicas,
            &image_commitment,
            &endpoint_root,
            &dependency_root,
        );
        Ok(Self {
            service_id,
            label,
            service_kind,
            replicas,
            image_commitment,
            endpoint_root,
            dependency_root,
            status: DEPLOY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deploy_service",
            "chain_id": CHAIN_ID,
            "service_id": self.service_id,
            "label": self.label,
            "service_kind": self.service_kind.as_str(),
            "replicas": self.replicas,
            "image_commitment": self.image_commitment,
            "endpoint_root": self.endpoint_root,
            "dependency_root": self.dependency_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceTopology {
    pub topology_id: String,
    pub tier: DeploymentTier,
    pub endpoints: Vec<ServiceEndpoint>,
    pub services: Vec<DeployService>,
    pub network_policy_root: String,
    pub status: String,
}

impl ServiceTopology {
    pub fn new(
        tier: DeploymentTier,
        endpoints: Vec<ServiceEndpoint>,
        services: Vec<DeployService>,
        network_policy_root: impl Into<String>,
    ) -> DeployResult<Self> {
        let network_policy_root = network_policy_root.into();
        ensure_non_empty(&network_policy_root, "deploy topology network policy root")?;
        if services.is_empty() {
            return Err("deploy topology requires at least one service".to_string());
        }
        ensure_unique_strings(
            &services
                .iter()
                .map(|service| service.label.clone())
                .collect::<Vec<_>>(),
            "deploy service labels",
        )?;
        let topology_id = service_topology_id(
            tier,
            &service_endpoint_root(&endpoints),
            &deploy_service_root(&services),
            &network_policy_root,
        );
        Ok(Self {
            topology_id,
            tier,
            endpoints,
            services,
            network_policy_root,
            status: DEPLOY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "service_topology",
            "chain_id": CHAIN_ID,
            "topology_id": self.topology_id,
            "tier": self.tier.as_str(),
            "endpoint_root": service_endpoint_root(&self.endpoints),
            "service_root": deploy_service_root(&self.services),
            "service_count": self.services.len() as u64,
            "network_policy_root": self.network_policy_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCommitment {
    pub secret_id: String,
    pub label: String,
    pub purpose: String,
    pub commitment_root: String,
    pub rotation_height: u64,
    pub status: String,
}

impl SecretCommitment {
    pub fn new(
        label: impl Into<String>,
        purpose: impl Into<String>,
        commitment_root: impl Into<String>,
        rotation_height: u64,
    ) -> DeployResult<Self> {
        let label = label.into();
        let purpose = purpose.into();
        let commitment_root = commitment_root.into();
        ensure_non_empty(&label, "deploy secret label")?;
        ensure_non_empty(&purpose, "deploy secret purpose")?;
        ensure_non_empty(&commitment_root, "deploy secret commitment root")?;
        let secret_id = secret_commitment_id(&label, &purpose, &commitment_root, rotation_height);
        Ok(Self {
            secret_id,
            label,
            purpose,
            commitment_root,
            rotation_height,
            status: DEPLOY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "secret_commitment",
            "chain_id": CHAIN_ID,
            "secret_id": self.secret_id,
            "label": self.label,
            "purpose": self.purpose,
            "commitment_root": self.commitment_root,
            "rotation_height": self.rotation_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumKeyRollout {
    pub rollout_id: String,
    pub scheme: String,
    pub old_key_root: Option<String>,
    pub new_key_root: String,
    pub activation_height: u64,
    pub fallback_until_height: u64,
    pub signer_set_root: String,
    pub status: String,
}

impl QuantumKeyRollout {
    pub fn new(
        scheme: impl Into<String>,
        old_key_root: Option<String>,
        new_key_root: impl Into<String>,
        activation_height: u64,
        fallback_until_height: u64,
        signer_set_root: impl Into<String>,
    ) -> DeployResult<Self> {
        let scheme = scheme.into();
        let new_key_root = new_key_root.into();
        let signer_set_root = signer_set_root.into();
        ensure_non_empty(&scheme, "deploy quantum scheme")?;
        ensure_non_empty(&new_key_root, "deploy quantum new key root")?;
        ensure_non_empty(&signer_set_root, "deploy quantum signer set root")?;
        if fallback_until_height < activation_height {
            return Err("deploy quantum fallback must last through activation".to_string());
        }
        let rollout_id = quantum_key_rollout_id(
            &scheme,
            old_key_root.as_deref(),
            &new_key_root,
            activation_height,
            fallback_until_height,
            &signer_set_root,
        );
        Ok(Self {
            rollout_id,
            scheme,
            old_key_root,
            new_key_root,
            activation_height,
            fallback_until_height,
            signer_set_root,
            status: DEPLOY_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_key_rollout",
            "chain_id": CHAIN_ID,
            "rollout_id": self.rollout_id,
            "scheme": self.scheme,
            "old_key_root": self.old_key_root,
            "new_key_root": self.new_key_root,
            "activation_height": self.activation_height,
            "fallback_until_height": self.fallback_until_height,
            "signer_set_root": self.signer_set_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcBinding {
    pub binding_id: String,
    pub network: String,
    pub rpc_endpoint_commitment: String,
    pub wallet_rpc_commitment: String,
    pub zmq_endpoint_commitment: String,
    pub view_only_required: bool,
    pub confirmations_required: u64,
    pub status: String,
}

impl MoneroRpcBinding {
    pub fn new(
        network: impl Into<String>,
        rpc_endpoint_commitment: impl Into<String>,
        wallet_rpc_commitment: impl Into<String>,
        zmq_endpoint_commitment: impl Into<String>,
        view_only_required: bool,
        confirmations_required: u64,
    ) -> DeployResult<Self> {
        let network = network.into();
        let rpc_endpoint_commitment = rpc_endpoint_commitment.into();
        let wallet_rpc_commitment = wallet_rpc_commitment.into();
        let zmq_endpoint_commitment = zmq_endpoint_commitment.into();
        ensure_non_empty(&network, "deploy monero network")?;
        ensure_non_empty(&rpc_endpoint_commitment, "deploy monero rpc commitment")?;
        ensure_non_empty(
            &wallet_rpc_commitment,
            "deploy monero wallet rpc commitment",
        )?;
        ensure_non_empty(&zmq_endpoint_commitment, "deploy monero zmq commitment")?;
        ensure_positive(
            confirmations_required,
            "deploy monero confirmations required",
        )?;
        let binding_id = monero_rpc_binding_id(
            &network,
            &rpc_endpoint_commitment,
            &wallet_rpc_commitment,
            &zmq_endpoint_commitment,
            view_only_required,
            confirmations_required,
        );
        Ok(Self {
            binding_id,
            network,
            rpc_endpoint_commitment,
            wallet_rpc_commitment,
            zmq_endpoint_commitment,
            view_only_required,
            confirmations_required,
            status: DEPLOY_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_binding",
            "chain_id": CHAIN_ID,
            "binding_id": self.binding_id,
            "network": self.network,
            "rpc_endpoint_commitment": self.rpc_endpoint_commitment,
            "wallet_rpc_commitment": self.wallet_rpc_commitment,
            "zmq_endpoint_commitment": self.zmq_endpoint_commitment,
            "view_only_required": self.view_only_required,
            "confirmations_required": self.confirmations_required,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityPlan {
    pub plan_id: String,
    pub cpu_units: u64,
    pub memory_mb: u64,
    pub disk_gb: u64,
    pub bandwidth_mbps: u64,
    pub expected_tps: u64,
    pub max_batch_bytes: u64,
    pub status: String,
}

impl CapacityPlan {
    pub fn new(
        cpu_units: u64,
        memory_mb: u64,
        disk_gb: u64,
        bandwidth_mbps: u64,
        expected_tps: u64,
        max_batch_bytes: u64,
    ) -> DeployResult<Self> {
        ensure_positive(cpu_units, "deploy capacity cpu units")?;
        ensure_positive(memory_mb, "deploy capacity memory")?;
        ensure_positive(disk_gb, "deploy capacity disk")?;
        ensure_positive(bandwidth_mbps, "deploy capacity bandwidth")?;
        ensure_positive(expected_tps, "deploy capacity expected tps")?;
        ensure_positive(max_batch_bytes, "deploy capacity batch bytes")?;
        let plan_id = capacity_plan_id(
            cpu_units,
            memory_mb,
            disk_gb,
            bandwidth_mbps,
            expected_tps,
            max_batch_bytes,
        );
        Ok(Self {
            plan_id,
            cpu_units,
            memory_mb,
            disk_gb,
            bandwidth_mbps,
            expected_tps,
            max_batch_bytes,
            status: DEPLOY_STATUS_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "capacity_plan",
            "chain_id": CHAIN_ID,
            "plan_id": self.plan_id,
            "cpu_units": self.cpu_units,
            "memory_mb": self.memory_mb,
            "disk_gb": self.disk_gb,
            "bandwidth_mbps": self.bandwidth_mbps,
            "expected_tps": self.expected_tps,
            "max_batch_bytes": self.max_batch_bytes,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeGate {
    pub gate_id: String,
    pub gate_kind: UpgradeGateKind,
    pub required: bool,
    pub passed: bool,
    pub evidence_root: String,
    pub blocker_count: u64,
    pub status: String,
}

impl UpgradeGate {
    pub fn new(
        gate_kind: UpgradeGateKind,
        required: bool,
        passed: bool,
        evidence_root: impl Into<String>,
        blocker_count: u64,
    ) -> DeployResult<Self> {
        let evidence_root = evidence_root.into();
        ensure_non_empty(&evidence_root, "deploy upgrade gate evidence root")?;
        let status = if passed && blocker_count == 0 {
            DEPLOY_STATUS_READY
        } else if required {
            DEPLOY_STATUS_BLOCKED
        } else {
            DEPLOY_STATUS_DRAFT
        };
        let gate_id = upgrade_gate_id(gate_kind, required, passed, &evidence_root, blocker_count);
        Ok(Self {
            gate_id,
            gate_kind,
            required,
            passed,
            evidence_root,
            blocker_count,
            status: status.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "upgrade_gate",
            "chain_id": CHAIN_ID,
            "gate_id": self.gate_id,
            "gate_kind": self.gate_kind.as_str(),
            "required": self.required,
            "passed": self.passed,
            "evidence_root": self.evidence_root,
            "blocker_count": self.blocker_count,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessCheck {
    pub check_id: String,
    pub service_label: String,
    pub check_kind: String,
    pub observed_root: String,
    pub severity_bps: u64,
    pub passed: bool,
    pub status: String,
}

impl ReadinessCheck {
    pub fn new(
        service_label: impl Into<String>,
        check_kind: impl Into<String>,
        observed_root: impl Into<String>,
        severity_bps: u64,
        passed: bool,
    ) -> DeployResult<Self> {
        let service_label = service_label.into();
        let check_kind = check_kind.into();
        let observed_root = observed_root.into();
        ensure_non_empty(&service_label, "deploy readiness service label")?;
        ensure_non_empty(&check_kind, "deploy readiness check kind")?;
        ensure_non_empty(&observed_root, "deploy readiness observed root")?;
        if severity_bps > 10_000 {
            return Err("deploy readiness severity cannot exceed 10000 bps".to_string());
        }
        let check_id = readiness_check_id(
            &service_label,
            &check_kind,
            &observed_root,
            severity_bps,
            passed,
        );
        Ok(Self {
            check_id,
            service_label,
            check_kind,
            observed_root,
            severity_bps,
            passed,
            status: if passed {
                DEPLOY_STATUS_READY.to_string()
            } else {
                DEPLOY_STATUS_BLOCKED.to_string()
            },
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "readiness_check",
            "chain_id": CHAIN_ID,
            "check_id": self.check_id,
            "service_label": self.service_label,
            "check_kind": self.check_kind,
            "observed_root": self.observed_root,
            "severity_bps": self.severity_bps,
            "passed": self.passed,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub plan_id: String,
    pub from_version: String,
    pub to_version: String,
    pub snapshot_root: String,
    pub action_root: String,
    pub approval_root: String,
    pub status: String,
}

impl RollbackPlan {
    pub fn new(
        from_version: impl Into<String>,
        to_version: impl Into<String>,
        snapshot_root: impl Into<String>,
        action_root: impl Into<String>,
        approval_root: impl Into<String>,
    ) -> DeployResult<Self> {
        let from_version = from_version.into();
        let to_version = to_version.into();
        let snapshot_root = snapshot_root.into();
        let action_root = action_root.into();
        let approval_root = approval_root.into();
        ensure_non_empty(&from_version, "deploy rollback from version")?;
        ensure_non_empty(&to_version, "deploy rollback to version")?;
        ensure_non_empty(&snapshot_root, "deploy rollback snapshot root")?;
        ensure_non_empty(&action_root, "deploy rollback action root")?;
        ensure_non_empty(&approval_root, "deploy rollback approval root")?;
        let plan_id = rollback_plan_id(
            &from_version,
            &to_version,
            &snapshot_root,
            &action_root,
            &approval_root,
        );
        Ok(Self {
            plan_id,
            from_version,
            to_version,
            snapshot_root,
            action_root,
            approval_root,
            status: DEPLOY_STATUS_ROLLBACK_READY.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollback_plan",
            "chain_id": CHAIN_ID,
            "plan_id": self.plan_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "snapshot_root": self.snapshot_root,
            "action_root": self.action_root,
            "approval_root": self.approval_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentManifest {
    pub manifest_id: String,
    pub tier: DeploymentTier,
    pub profile_version: u64,
    pub label: String,
    pub topology: ServiceTopology,
    pub secrets: Vec<SecretCommitment>,
    pub quantum_rollouts: Vec<QuantumKeyRollout>,
    pub monero: MoneroRpcBinding,
    pub capacity: CapacityPlan,
    pub gates: Vec<UpgradeGate>,
    pub readiness: Vec<ReadinessCheck>,
    pub rollback: RollbackPlan,
    pub created_at_height: u64,
    pub status: String,
}

impl DeploymentManifest {
    pub fn devnet(operator_label: &str) -> DeployResult<Self> {
        Self::profile(DeploymentTier::Devnet, operator_label, 0)
    }

    pub fn testnet(operator_label: &str, created_at_height: u64) -> DeployResult<Self> {
        Self::profile(DeploymentTier::Testnet, operator_label, created_at_height)
    }

    pub fn mainnet(operator_label: &str, created_at_height: u64) -> DeployResult<Self> {
        Self::profile(DeploymentTier::Mainnet, operator_label, created_at_height)
    }

    pub fn readiness_score_bps(&self) -> u64 {
        if self.readiness.is_empty() {
            return 0;
        }
        let total = self
            .readiness
            .iter()
            .map(|check| if check.passed { check.severity_bps } else { 0 })
            .sum::<u64>();
        let max = self
            .readiness
            .iter()
            .map(|check| check.severity_bps)
            .sum::<u64>();
        if max == 0 {
            0
        } else {
            total.saturating_mul(10_000) / max
        }
    }

    pub fn validate(&self) -> DeployResult<()> {
        ensure_non_empty(&self.label, "deploy manifest label")?;
        if self.secrets.is_empty() {
            return Err("deploy manifest requires secret commitments".to_string());
        }
        if self.quantum_rollouts.is_empty() {
            return Err("deploy manifest requires a quantum key rollout".to_string());
        }
        if self.gates.iter().any(|gate| gate.required && !gate.passed) {
            return Err("deploy manifest has a blocked required gate".to_string());
        }
        if self.readiness_score_bps() < DEPLOY_MIN_READY_SCORE_BPS {
            return Err("deploy manifest readiness score is below minimum".to_string());
        }
        if self.manifest_id
            != deployment_manifest_id(
                self.tier,
                self.profile_version,
                &self.label,
                &self.topology.topology_id,
                &secret_commitment_root(&self.secrets),
                &quantum_key_rollout_root(&self.quantum_rollouts),
                &self.monero.binding_id,
                &self.capacity.plan_id,
                &upgrade_gate_root(&self.gates),
                &readiness_check_root(&self.readiness),
                &self.rollback.plan_id,
                self.created_at_height,
            )
        {
            return Err("deploy manifest id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deployment_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": DEPLOY_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "tier": self.tier.as_str(),
            "profile_version": self.profile_version,
            "label": self.label,
            "topology_root": service_topology_root(std::slice::from_ref(&self.topology)),
            "secret_root": secret_commitment_root(&self.secrets),
            "quantum_rollout_root": quantum_key_rollout_root(&self.quantum_rollouts),
            "monero_binding_id": self.monero.binding_id,
            "capacity_plan_id": self.capacity.plan_id,
            "upgrade_gate_root": upgrade_gate_root(&self.gates),
            "readiness_root": readiness_check_root(&self.readiness),
            "rollback_plan_id": self.rollback.plan_id,
            "created_at_height": self.created_at_height,
            "readiness_score_bps": self.readiness_score_bps(),
            "status": self.status,
        })
    }

    fn profile(
        tier: DeploymentTier,
        operator_label: &str,
        created_at_height: u64,
    ) -> DeployResult<Self> {
        ensure_non_empty(operator_label, "deploy operator label")?;
        let label = format!("nebula-{}-{operator_label}", tier.as_str());
        let endpoints = default_endpoints(tier, operator_label)?;
        let services = default_services(tier, operator_label, &endpoints)?;
        let topology = ServiceTopology::new(
            tier,
            endpoints,
            services,
            deploy_label_commitment(operator_label, "network-policy"),
        )?;
        let secrets = vec![
            SecretCommitment::new(
                "operator-admin",
                "governance and upgrade authorization",
                deploy_label_commitment(operator_label, "operator-admin-secret"),
                created_at_height + 10_000,
            )?,
            SecretCommitment::new(
                "monero-view-only",
                "view-only reserve observation",
                deploy_label_commitment(operator_label, "monero-view-secret"),
                created_at_height + 5_000,
            )?,
        ];
        let quantum_rollouts = vec![QuantumKeyRollout::new(
            "ml-dsa-65+slh-dsa-shake-128s",
            None,
            deploy_label_commitment(operator_label, "quantum-auth-key"),
            created_at_height,
            created_at_height + 1_000,
            deploy_label_commitment(operator_label, "custody-signer-set"),
        )?];
        let monero = MoneroRpcBinding::new(
            format!("monero-{}", tier.as_str()),
            deploy_label_commitment(operator_label, "monero-rpc"),
            deploy_label_commitment(operator_label, "monero-wallet-rpc"),
            deploy_label_commitment(operator_label, "monero-zmq"),
            true,
            tier.monero_confirmations(),
        )?;
        let capacity = match tier {
            DeploymentTier::Devnet => CapacityPlan::new(8, 16_384, 250, 500, 1_000, 2_000_000)?,
            DeploymentTier::Testnet => {
                CapacityPlan::new(32, 65_536, 2_000, 2_000, 5_000, 8_000_000)?
            }
            DeploymentTier::Mainnet => {
                CapacityPlan::new(128, 262_144, 10_000, 10_000, 20_000, 16_000_000)?
            }
        };
        let gates = default_upgrade_gates(operator_label)?;
        let readiness = default_readiness_checks(operator_label, &topology.services)?;
        let rollback = RollbackPlan::new(
            format!("{}-v{}", tier.as_str(), DEPLOY_PROFILE_VERSION),
            format!("{}-previous", tier.as_str()),
            deploy_label_commitment(operator_label, "rollback-snapshot"),
            deploy_label_commitment(operator_label, "rollback-actions"),
            deploy_label_commitment(operator_label, "rollback-approval"),
        )?;
        let manifest_id = deployment_manifest_id(
            tier,
            DEPLOY_PROFILE_VERSION,
            &label,
            &topology.topology_id,
            &secret_commitment_root(&secrets),
            &quantum_key_rollout_root(&quantum_rollouts),
            &monero.binding_id,
            &capacity.plan_id,
            &upgrade_gate_root(&gates),
            &readiness_check_root(&readiness),
            &rollback.plan_id,
            created_at_height,
        );
        let manifest = Self {
            manifest_id,
            tier,
            profile_version: DEPLOY_PROFILE_VERSION,
            label,
            topology,
            secrets,
            quantum_rollouts,
            monero,
            capacity,
            gates,
            readiness,
            rollback,
            created_at_height,
            status: DEPLOY_STATUS_READY.to_string(),
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployState {
    pub height: u64,
    pub manifests: Vec<DeploymentManifest>,
}

impl DeployState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            manifests: Vec::new(),
        }
    }

    pub fn devnet(operator_label: &str) -> DeployResult<Self> {
        let mut state = Self::new(0);
        state.add_manifest(DeploymentManifest::devnet(operator_label)?)?;
        Ok(state)
    }

    pub fn add_manifest(&mut self, manifest: DeploymentManifest) -> DeployResult<String> {
        manifest.validate()?;
        let manifest_id = manifest.manifest_id.clone();
        self.manifests.push(manifest);
        Ok(manifest_id)
    }

    pub fn latest_manifest(&self) -> Option<&DeploymentManifest> {
        self.manifests.last()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn state_root(&self) -> String {
        deploy_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deploy_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "manifest_root": deployment_manifest_root(&self.manifests),
            "manifest_count": self.manifests.len() as u64,
            "latest_manifest_id": self.latest_manifest().map(|manifest| manifest.manifest_id.clone()),
        })
    }
}

pub fn deploy_label_commitment(operator_label: &str, label: &str) -> String {
    domain_hash(
        "DEPLOY-LABEL-COMMITMENT",
        &[HashPart::Str(operator_label), HashPart::Str(label)],
        32,
    )
}

pub fn service_endpoint_id(
    service_label: &str,
    service_kind: DeployServiceKind,
    bind_commitment: &str,
    advertised_url_commitment: &str,
    port: u16,
    tls_required: bool,
) -> String {
    domain_hash(
        "DEPLOY-SERVICE-ENDPOINT-ID",
        &[
            HashPart::Str(service_label),
            HashPart::Str(service_kind.as_str()),
            HashPart::Str(bind_commitment),
            HashPart::Str(advertised_url_commitment),
            HashPart::Int(port as i128),
            HashPart::Int(tls_required as i128),
        ],
        32,
    )
}

pub fn deploy_service_id(
    label: &str,
    service_kind: DeployServiceKind,
    replicas: u64,
    image_commitment: &str,
    endpoint_root: &str,
    dependency_root: &str,
) -> String {
    domain_hash(
        "DEPLOY-SERVICE-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(service_kind.as_str()),
            HashPart::Int(replicas as i128),
            HashPart::Str(image_commitment),
            HashPart::Str(endpoint_root),
            HashPart::Str(dependency_root),
        ],
        32,
    )
}

pub fn service_topology_id(
    tier: DeploymentTier,
    endpoint_root: &str,
    service_root: &str,
    network_policy_root: &str,
) -> String {
    domain_hash(
        "DEPLOY-SERVICE-TOPOLOGY-ID",
        &[
            HashPart::Str(tier.as_str()),
            HashPart::Str(endpoint_root),
            HashPart::Str(service_root),
            HashPart::Str(network_policy_root),
        ],
        32,
    )
}

pub fn secret_commitment_id(
    label: &str,
    purpose: &str,
    commitment_root: &str,
    rotation_height: u64,
) -> String {
    domain_hash(
        "DEPLOY-SECRET-COMMITMENT-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(purpose),
            HashPart::Str(commitment_root),
            HashPart::Int(rotation_height as i128),
        ],
        32,
    )
}

pub fn quantum_key_rollout_id(
    scheme: &str,
    old_key_root: Option<&str>,
    new_key_root: &str,
    activation_height: u64,
    fallback_until_height: u64,
    signer_set_root: &str,
) -> String {
    domain_hash(
        "DEPLOY-QUANTUM-KEY-ROLLOUT-ID",
        &[
            HashPart::Str(scheme),
            HashPart::Str(old_key_root.unwrap_or("none")),
            HashPart::Str(new_key_root),
            HashPart::Int(activation_height as i128),
            HashPart::Int(fallback_until_height as i128),
            HashPart::Str(signer_set_root),
        ],
        32,
    )
}

pub fn monero_rpc_binding_id(
    network: &str,
    rpc_endpoint_commitment: &str,
    wallet_rpc_commitment: &str,
    zmq_endpoint_commitment: &str,
    view_only_required: bool,
    confirmations_required: u64,
) -> String {
    domain_hash(
        "DEPLOY-MONERO-RPC-BINDING-ID",
        &[
            HashPart::Str(network),
            HashPart::Str(rpc_endpoint_commitment),
            HashPart::Str(wallet_rpc_commitment),
            HashPart::Str(zmq_endpoint_commitment),
            HashPart::Int(view_only_required as i128),
            HashPart::Int(confirmations_required as i128),
        ],
        32,
    )
}

pub fn capacity_plan_id(
    cpu_units: u64,
    memory_mb: u64,
    disk_gb: u64,
    bandwidth_mbps: u64,
    expected_tps: u64,
    max_batch_bytes: u64,
) -> String {
    domain_hash(
        "DEPLOY-CAPACITY-PLAN-ID",
        &[
            HashPart::Int(cpu_units as i128),
            HashPart::Int(memory_mb as i128),
            HashPart::Int(disk_gb as i128),
            HashPart::Int(bandwidth_mbps as i128),
            HashPart::Int(expected_tps as i128),
            HashPart::Int(max_batch_bytes as i128),
        ],
        32,
    )
}

pub fn upgrade_gate_id(
    gate_kind: UpgradeGateKind,
    required: bool,
    passed: bool,
    evidence_root: &str,
    blocker_count: u64,
) -> String {
    domain_hash(
        "DEPLOY-UPGRADE-GATE-ID",
        &[
            HashPart::Str(gate_kind.as_str()),
            HashPart::Int(required as i128),
            HashPart::Int(passed as i128),
            HashPart::Str(evidence_root),
            HashPart::Int(blocker_count as i128),
        ],
        32,
    )
}

pub fn readiness_check_id(
    service_label: &str,
    check_kind: &str,
    observed_root: &str,
    severity_bps: u64,
    passed: bool,
) -> String {
    domain_hash(
        "DEPLOY-READINESS-CHECK-ID",
        &[
            HashPart::Str(service_label),
            HashPart::Str(check_kind),
            HashPart::Str(observed_root),
            HashPart::Int(severity_bps as i128),
            HashPart::Int(passed as i128),
        ],
        32,
    )
}

pub fn rollback_plan_id(
    from_version: &str,
    to_version: &str,
    snapshot_root: &str,
    action_root: &str,
    approval_root: &str,
) -> String {
    domain_hash(
        "DEPLOY-ROLLBACK-PLAN-ID",
        &[
            HashPart::Str(from_version),
            HashPart::Str(to_version),
            HashPart::Str(snapshot_root),
            HashPart::Str(action_root),
            HashPart::Str(approval_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn deployment_manifest_id(
    tier: DeploymentTier,
    profile_version: u64,
    label: &str,
    topology_id: &str,
    secret_root: &str,
    quantum_rollout_root: &str,
    monero_binding_id: &str,
    capacity_plan_id: &str,
    upgrade_gate_root: &str,
    readiness_root: &str,
    rollback_plan_id: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-MANIFEST-ID",
        &[
            HashPart::Str(tier.as_str()),
            HashPart::Int(profile_version as i128),
            HashPart::Str(label),
            HashPart::Str(topology_id),
            HashPart::Str(secret_root),
            HashPart::Str(quantum_rollout_root),
            HashPart::Str(monero_binding_id),
            HashPart::Str(capacity_plan_id),
            HashPart::Str(upgrade_gate_root),
            HashPart::Str(readiness_root),
            HashPart::Str(rollback_plan_id),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn deploy_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn deploy_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn deploy_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn service_endpoint_root(values: &[ServiceEndpoint]) -> String {
    let leaves = values
        .iter()
        .map(ServiceEndpoint::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-SERVICE-ENDPOINT-ROOT", &leaves)
}

pub fn deploy_service_root(values: &[DeployService]) -> String {
    let leaves = values
        .iter()
        .map(DeployService::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-SERVICE-ROOT", &leaves)
}

pub fn service_topology_root(values: &[ServiceTopology]) -> String {
    let leaves = values
        .iter()
        .map(ServiceTopology::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-SERVICE-TOPOLOGY-ROOT", &leaves)
}

pub fn secret_commitment_root(values: &[SecretCommitment]) -> String {
    let leaves = values
        .iter()
        .map(SecretCommitment::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-SECRET-COMMITMENT-ROOT", &leaves)
}

pub fn quantum_key_rollout_root(values: &[QuantumKeyRollout]) -> String {
    let leaves = values
        .iter()
        .map(QuantumKeyRollout::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-QUANTUM-KEY-ROLLOUT-ROOT", &leaves)
}

pub fn monero_rpc_binding_root(values: &[MoneroRpcBinding]) -> String {
    let leaves = values
        .iter()
        .map(MoneroRpcBinding::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-MONERO-RPC-BINDING-ROOT", &leaves)
}

pub fn capacity_plan_root(values: &[CapacityPlan]) -> String {
    let leaves = values
        .iter()
        .map(CapacityPlan::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-CAPACITY-PLAN-ROOT", &leaves)
}

pub fn upgrade_gate_root(values: &[UpgradeGate]) -> String {
    let leaves = values
        .iter()
        .map(UpgradeGate::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-UPGRADE-GATE-ROOT", &leaves)
}

pub fn readiness_check_root(values: &[ReadinessCheck]) -> String {
    let leaves = values
        .iter()
        .map(ReadinessCheck::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-READINESS-CHECK-ROOT", &leaves)
}

pub fn rollback_plan_root(values: &[RollbackPlan]) -> String {
    let leaves = values
        .iter()
        .map(RollbackPlan::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOY-ROLLBACK-PLAN-ROOT", &leaves)
}

pub fn deployment_manifest_root(values: &[DeploymentManifest]) -> String {
    let leaves = values
        .iter()
        .map(DeploymentManifest::public_record)
        .collect::<Vec<_>>();
    merkle_root("DEPLOYMENT-MANIFEST-ROOT", &leaves)
}

pub fn deploy_state_root_from_record(record: &Value) -> String {
    deploy_payload_root("DEPLOY-STATE-ROOT", record)
}

fn default_endpoints(
    tier: DeploymentTier,
    operator_label: &str,
) -> DeployResult<Vec<ServiceEndpoint>> {
    let base = match tier {
        DeploymentTier::Devnet => 18_480,
        DeploymentTier::Testnet => 28_480,
        DeploymentTier::Mainnet => 38_480,
    };
    let tls = tier != DeploymentTier::Devnet;
    Ok(vec![
        ServiceEndpoint::new(
            "rpc",
            DeployServiceKind::Rpc,
            deploy_label_commitment(operator_label, "rpc-bind"),
            deploy_label_commitment(operator_label, "rpc-advertised"),
            base,
            tls,
        )?,
        ServiceEndpoint::new(
            "p2p",
            DeployServiceKind::P2p,
            deploy_label_commitment(operator_label, "p2p-bind"),
            deploy_label_commitment(operator_label, "p2p-advertised"),
            base + 1,
            tls,
        )?,
        ServiceEndpoint::new(
            "monero-rpc",
            DeployServiceKind::MoneroRpc,
            deploy_label_commitment(operator_label, "monero-rpc-bind"),
            deploy_label_commitment(operator_label, "monero-rpc-advertised"),
            base + 2,
            tls,
        )?,
        ServiceEndpoint::new(
            "monero-wallet-rpc",
            DeployServiceKind::MoneroWalletRpc,
            deploy_label_commitment(operator_label, "monero-wallet-rpc-bind"),
            deploy_label_commitment(operator_label, "monero-wallet-rpc-advertised"),
            base + 3,
            tls,
        )?,
    ])
}

fn default_services(
    tier: DeploymentTier,
    operator_label: &str,
    endpoints: &[ServiceEndpoint],
) -> DeployResult<Vec<DeployService>> {
    let replicas = match tier {
        DeploymentTier::Devnet => 1,
        DeploymentTier::Testnet => 2,
        DeploymentTier::Mainnet => 4,
    };
    let no_deps: Vec<String> = Vec::new();
    let sequencer_deps = vec![
        "rpc".to_string(),
        "p2p".to_string(),
        "monero-rpc".to_string(),
    ];
    let prover_deps = vec!["sequencer".to_string(), "data-availability".to_string()];
    let bridge_deps = vec!["monero-rpc".to_string(), "monero-wallet-rpc".to_string()];
    Ok(vec![
        DeployService::new(
            "sequencer",
            DeployServiceKind::Sequencer,
            replicas,
            deploy_label_commitment(operator_label, "sequencer-image"),
            endpoints,
            &sequencer_deps,
        )?,
        DeployService::new(
            "data-availability",
            DeployServiceKind::DataAvailability,
            replicas,
            deploy_label_commitment(operator_label, "da-image"),
            &[],
            &no_deps,
        )?,
        DeployService::new(
            "prover",
            DeployServiceKind::Prover,
            replicas,
            deploy_label_commitment(operator_label, "prover-image"),
            &[],
            &prover_deps,
        )?,
        DeployService::new(
            "watchtower",
            DeployServiceKind::Watchtower,
            replicas + 1,
            deploy_label_commitment(operator_label, "watchtower-image"),
            &[],
            &bridge_deps,
        )?,
        DeployService::new(
            "operator",
            DeployServiceKind::Operator,
            1,
            deploy_label_commitment(operator_label, "operator-image"),
            &[],
            &no_deps,
        )?,
    ])
}

fn default_upgrade_gates(operator_label: &str) -> DeployResult<Vec<UpgradeGate>> {
    Ok(vec![
        UpgradeGate::new(
            UpgradeGateKind::CryptoPolicy,
            true,
            true,
            deploy_label_commitment(operator_label, "crypto-gate-evidence"),
            0,
        )?,
        UpgradeGate::new(
            UpgradeGateKind::MoneroBridge,
            true,
            true,
            deploy_label_commitment(operator_label, "bridge-gate-evidence"),
            0,
        )?,
        UpgradeGate::new(
            UpgradeGateKind::DataAvailability,
            true,
            true,
            deploy_label_commitment(operator_label, "da-gate-evidence"),
            0,
        )?,
        UpgradeGate::new(
            UpgradeGateKind::OperatorQuorum,
            true,
            true,
            deploy_label_commitment(operator_label, "operator-gate-evidence"),
            0,
        )?,
    ])
}

fn default_readiness_checks(
    operator_label: &str,
    services: &[DeployService],
) -> DeployResult<Vec<ReadinessCheck>> {
    let mut checks = Vec::new();
    for service in services {
        checks.push(ReadinessCheck::new(
            &service.label,
            "health",
            deploy_label_commitment(operator_label, &format!("{}-health", service.label)),
            2_500,
            true,
        )?);
        checks.push(ReadinessCheck::new(
            &service.label,
            "config_root",
            deploy_label_commitment(operator_label, &format!("{}-config", service.label)),
            2_500,
            true,
        )?);
    }
    Ok(checks)
}

fn ensure_non_empty(value: &str, field: &str) -> DeployResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> DeployResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], field: &str) -> DeployResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value"));
        }
    }
    Ok(())
}
