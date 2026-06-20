use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateContractWitnessEscrowResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_WITNESS_ESCROW_PROTOCOL_VERSION: &str =
    "nebula-private-contract-witness-escrow-v1";
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_SCHEMA_VERSION: &str =
    "private-contract-witness-escrow-state-v1";
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_DEVNET_LABEL: &str =
    "devnet-private-contract-witness-escrow";
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_ENCRYPTION_SCHEME: &str =
    "ML-KEM-768+XChaCha20-Poly1305-witness-envelope";
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-witness-availability";
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_DEFAULT_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_DEFAULT_REPAIR_BLOCKS: u64 = 12;
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_DEFAULT_MIN_REPLICAS: u64 = 3;
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_DEPOSITS: usize = 32_768;
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_PROVIDERS: usize = 2_048;
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_RELEASES: usize = 32_768;
pub const PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_REPAIRS: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessEscrowLane {
    ContractCall,
    PrivateSwap,
    Lending,
    Perps,
    MoneroBridge,
    ProofAggregation,
    WalletRecovery,
}

impl WitnessEscrowLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::PrivateSwap => "private_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::MoneroBridge => "monero_bridge",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessDepositStatus {
    Pending,
    Available,
    Released,
    Repairing,
    Expired,
    Slashed,
}

impl WitnessDepositStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Pending | Self::Available | Self::Repairing)
    }

    pub fn releasable(self) -> bool {
        matches!(self, Self::Available)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Available => "available",
            Self::Released => "released",
            Self::Repairing => "repairing",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessProviderStatus {
    Active,
    Degraded,
    Quarantined,
    Retired,
}

impl WitnessProviderStatus {
    pub fn accepts_witness(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRepairStatus {
    Open,
    Assigned,
    Completed,
    Failed,
    Expired,
}

impl WitnessRepairStatus {
    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::Assigned)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Assigned => "assigned",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

pub trait WitnessEscrowRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContractWitnessEscrowConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub encryption_scheme: String,
    pub pq_attestation_scheme: String,
    pub default_ttl_blocks: u64,
    pub default_repair_blocks: u64,
    pub min_replicas: u64,
    pub low_fee_credit_units: u64,
    pub privacy_policy_root: String,
}

impl PrivateContractWitnessEscrowConfig {
    pub fn devnet() -> PrivateContractWitnessEscrowResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PRIVATE_CONTRACT_WITNESS_ESCROW_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_CONTRACT_WITNESS_ESCROW_SCHEMA_VERSION.to_string(),
            encryption_scheme: PRIVATE_CONTRACT_WITNESS_ESCROW_ENCRYPTION_SCHEME.to_string(),
            pq_attestation_scheme: PRIVATE_CONTRACT_WITNESS_ESCROW_PQ_ATTESTATION_SCHEME
                .to_string(),
            default_ttl_blocks: PRIVATE_CONTRACT_WITNESS_ESCROW_DEFAULT_TTL_BLOCKS,
            default_repair_blocks: PRIVATE_CONTRACT_WITNESS_ESCROW_DEFAULT_REPAIR_BLOCKS,
            min_replicas: PRIVATE_CONTRACT_WITNESS_ESCROW_DEFAULT_MIN_REPLICAS,
            low_fee_credit_units: 1_500,
            privacy_policy_root: witness_escrow_string_root(
                "PRIVATE-WITNESS-ESCROW-PRIVACY",
                "encrypted-witness-roots-only",
            ),
        };
        config.config_id =
            witness_escrow_config_id(&config.protocol_version, &config.schema_version);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PrivateContractWitnessEscrowResult<String> {
        ensure_non_empty(&self.config_id, "private witness escrow config id")?;
        ensure_non_empty(
            &self.protocol_version,
            "private witness escrow protocol version",
        )?;
        ensure_non_empty(
            &self.schema_version,
            "private witness escrow schema version",
        )?;
        ensure_non_empty(
            &self.encryption_scheme,
            "private witness escrow encryption scheme",
        )?;
        ensure_non_empty(
            &self.pq_attestation_scheme,
            "private witness escrow pq scheme",
        )?;
        ensure_non_empty(
            &self.privacy_policy_root,
            "private witness escrow privacy root",
        )?;
        if self.default_ttl_blocks == 0 || self.default_repair_blocks == 0 {
            return Err("private witness escrow timing values must be positive".to_string());
        }
        if self.min_replicas == 0 {
            return Err("private witness escrow min replicas must be positive".to_string());
        }
        let expected = witness_escrow_config_id(&self.protocol_version, &self.schema_version);
        if self.config_id != expected {
            return Err("private witness escrow config id does not match protocol".to_string());
        }
        Ok(self.root())
    }
}

impl WitnessEscrowRooted for PrivateContractWitnessEscrowConfig {
    fn root(&self) -> String {
        witness_escrow_payload_root("PRIVATE-WITNESS-ESCROW-CONFIG", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_witness_escrow_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "encryption_scheme": self.encryption_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "default_ttl_blocks": self.default_ttl_blocks,
            "default_repair_blocks": self.default_repair_blocks,
            "min_replicas": self.min_replicas,
            "low_fee_credit_units": self.low_fee_credit_units,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessProvider {
    pub provider_id: String,
    pub operator_commitment: String,
    pub pq_key_root: String,
    pub storage_bond_root: String,
    pub status: WitnessProviderStatus,
    pub accepted_lanes: BTreeSet<WitnessEscrowLane>,
    pub reliability_score_bps: u64,
}

impl WitnessProvider {
    pub fn new(
        operator_label: &str,
        pq_key_label: &str,
        storage_bond_label: &str,
        accepted_lanes: BTreeSet<WitnessEscrowLane>,
        reliability_score_bps: u64,
    ) -> PrivateContractWitnessEscrowResult<Self> {
        ensure_non_empty(operator_label, "private witness provider operator label")?;
        ensure_non_empty(pq_key_label, "private witness provider pq key")?;
        ensure_non_empty(storage_bond_label, "private witness provider storage bond")?;
        if accepted_lanes.is_empty() {
            return Err("private witness provider must accept at least one lane".to_string());
        }
        let operator_commitment =
            witness_escrow_string_root("PRIVATE-WITNESS-PROVIDER-OPERATOR", operator_label);
        let pq_key_root = witness_escrow_string_root("PRIVATE-WITNESS-PROVIDER-PQ", pq_key_label);
        let storage_bond_root =
            witness_escrow_string_root("PRIVATE-WITNESS-PROVIDER-BOND", storage_bond_label);
        let provider_id =
            witness_provider_id(&operator_commitment, &pq_key_root, &storage_bond_root);
        let provider = Self {
            provider_id,
            operator_commitment,
            pq_key_root,
            storage_bond_root,
            status: WitnessProviderStatus::Active,
            accepted_lanes,
            reliability_score_bps,
        };
        provider.validate()?;
        Ok(provider)
    }

    pub fn accepts_lane(&self, lane: WitnessEscrowLane) -> bool {
        self.status.accepts_witness() && self.accepted_lanes.contains(&lane)
    }

    pub fn validate(&self) -> PrivateContractWitnessEscrowResult<String> {
        ensure_non_empty(&self.provider_id, "private witness provider id")?;
        ensure_non_empty(
            &self.operator_commitment,
            "private witness provider operator commitment",
        )?;
        ensure_non_empty(&self.pq_key_root, "private witness provider pq key root")?;
        ensure_non_empty(
            &self.storage_bond_root,
            "private witness provider storage bond root",
        )?;
        if self.accepted_lanes.is_empty() {
            return Err("private witness provider has no accepted lanes".to_string());
        }
        if self.reliability_score_bps > 10_000 {
            return Err("private witness provider reliability exceeds bps cap".to_string());
        }
        let expected = witness_provider_id(
            &self.operator_commitment,
            &self.pq_key_root,
            &self.storage_bond_root,
        );
        if self.provider_id != expected {
            return Err("private witness provider id does not match commitments".to_string());
        }
        Ok(self.root())
    }
}

impl WitnessEscrowRooted for WitnessProvider {
    fn root(&self) -> String {
        witness_escrow_payload_root("PRIVATE-WITNESS-PROVIDER", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "witness_provider",
            "provider_id": self.provider_id,
            "operator_commitment": self.operator_commitment,
            "pq_key_root": self.pq_key_root,
            "storage_bond_root": self.storage_bond_root,
            "status": self.status.as_str(),
            "accepted_lanes": self.accepted_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "reliability_score_bps": self.reliability_score_bps,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessDeposit {
    pub deposit_id: String,
    pub lane: WitnessEscrowLane,
    pub contract_commitment: String,
    pub encrypted_witness_root: String,
    pub witness_schema_root: String,
    pub provider_ids: BTreeSet<String>,
    pub status: WitnessDepositStatus,
    pub fee_credit_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl WitnessDeposit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: WitnessEscrowLane,
        contract_label: &str,
        encrypted_witness_root: &str,
        witness_schema_root: &str,
        provider_ids: BTreeSet<String>,
        fee_credit_units: u64,
        opened_height: u64,
        ttl_blocks: u64,
    ) -> PrivateContractWitnessEscrowResult<Self> {
        ensure_non_empty(contract_label, "private witness deposit contract label")?;
        ensure_non_empty(
            encrypted_witness_root,
            "private witness deposit encrypted witness root",
        )?;
        ensure_non_empty(witness_schema_root, "private witness deposit schema root")?;
        if provider_ids.is_empty() {
            return Err("private witness deposit requires providers".to_string());
        }
        if fee_credit_units == 0 {
            return Err("private witness deposit fee credit must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("private witness deposit ttl must be positive".to_string());
        }
        let contract_commitment =
            witness_escrow_string_root("PRIVATE-WITNESS-CONTRACT", contract_label);
        let expires_height = opened_height.saturating_add(ttl_blocks);
        let deposit_id = witness_deposit_id(
            lane,
            &contract_commitment,
            encrypted_witness_root,
            witness_schema_root,
            opened_height,
        );
        let deposit = Self {
            deposit_id,
            lane,
            contract_commitment,
            encrypted_witness_root: encrypted_witness_root.to_string(),
            witness_schema_root: witness_schema_root.to_string(),
            provider_ids,
            status: WitnessDepositStatus::Pending,
            fee_credit_units,
            opened_height,
            expires_height,
        };
        deposit.validate()?;
        Ok(deposit)
    }

    pub fn mark_available(&mut self) -> PrivateContractWitnessEscrowResult<String> {
        if self.status != WitnessDepositStatus::Pending {
            return Err(
                "private witness deposit can only become available from pending".to_string(),
            );
        }
        self.status = WitnessDepositStatus::Available;
        Ok(self.root())
    }

    pub fn mark_repairing(&mut self) -> PrivateContractWitnessEscrowResult<String> {
        if !self.status.live() {
            return Err("private witness deposit is not live".to_string());
        }
        self.status = WitnessDepositStatus::Repairing;
        Ok(self.root())
    }

    pub fn mark_released(&mut self) -> PrivateContractWitnessEscrowResult<String> {
        if !self.status.releasable() && self.status != WitnessDepositStatus::Repairing {
            return Err("private witness deposit is not releasable".to_string());
        }
        self.status = WitnessDepositStatus::Released;
        Ok(self.root())
    }

    pub fn validate(&self) -> PrivateContractWitnessEscrowResult<String> {
        ensure_non_empty(&self.deposit_id, "private witness deposit id")?;
        ensure_non_empty(
            &self.contract_commitment,
            "private witness contract commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_witness_root,
            "private witness encrypted root",
        )?;
        ensure_non_empty(&self.witness_schema_root, "private witness schema root")?;
        if self.provider_ids.is_empty() {
            return Err("private witness deposit provider set cannot be empty".to_string());
        }
        if self.fee_credit_units == 0 {
            return Err("private witness deposit fee credit must be positive".to_string());
        }
        if self.expires_height <= self.opened_height {
            return Err("private witness deposit expiry must exceed open height".to_string());
        }
        let expected = witness_deposit_id(
            self.lane,
            &self.contract_commitment,
            &self.encrypted_witness_root,
            &self.witness_schema_root,
            self.opened_height,
        );
        if self.deposit_id != expected {
            return Err("private witness deposit id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl WitnessEscrowRooted for WitnessDeposit {
    fn root(&self) -> String {
        witness_escrow_payload_root("PRIVATE-WITNESS-DEPOSIT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "witness_deposit",
            "deposit_id": self.deposit_id,
            "lane": self.lane.as_str(),
            "contract_commitment": self.contract_commitment,
            "encrypted_witness_root": self.encrypted_witness_root,
            "witness_schema_root": self.witness_schema_root,
            "provider_ids": self.provider_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "fee_credit_units": self.fee_credit_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessRelease {
    pub release_id: String,
    pub deposit_id: String,
    pub requester_commitment: String,
    pub release_proof_root: String,
    pub pq_attestation_root: String,
    pub released_height: u64,
}

impl WitnessRelease {
    pub fn new(
        deposit_id: &str,
        requester_label: &str,
        release_proof_root: &str,
        pq_attestation_root: &str,
        released_height: u64,
    ) -> PrivateContractWitnessEscrowResult<Self> {
        ensure_non_empty(deposit_id, "private witness release deposit id")?;
        ensure_non_empty(requester_label, "private witness release requester")?;
        ensure_non_empty(release_proof_root, "private witness release proof root")?;
        ensure_non_empty(
            pq_attestation_root,
            "private witness release pq attestation",
        )?;
        let requester_commitment =
            witness_escrow_string_root("PRIVATE-WITNESS-RELEASE-REQUESTER", requester_label);
        let release_id = witness_release_id(
            deposit_id,
            &requester_commitment,
            release_proof_root,
            pq_attestation_root,
            released_height,
        );
        let release = Self {
            release_id,
            deposit_id: deposit_id.to_string(),
            requester_commitment,
            release_proof_root: release_proof_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            released_height,
        };
        release.validate()?;
        Ok(release)
    }

    pub fn validate(&self) -> PrivateContractWitnessEscrowResult<String> {
        ensure_non_empty(&self.release_id, "private witness release id")?;
        ensure_non_empty(&self.deposit_id, "private witness release deposit id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "private witness release requester commitment",
        )?;
        ensure_non_empty(
            &self.release_proof_root,
            "private witness release proof root",
        )?;
        ensure_non_empty(
            &self.pq_attestation_root,
            "private witness release attestation",
        )?;
        let expected = witness_release_id(
            &self.deposit_id,
            &self.requester_commitment,
            &self.release_proof_root,
            &self.pq_attestation_root,
            self.released_height,
        );
        if self.release_id != expected {
            return Err("private witness release id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl WitnessEscrowRooted for WitnessRelease {
    fn root(&self) -> String {
        witness_escrow_payload_root("PRIVATE-WITNESS-RELEASE", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "witness_release",
            "release_id": self.release_id,
            "deposit_id": self.deposit_id,
            "requester_commitment": self.requester_commitment,
            "release_proof_root": self.release_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "released_height": self.released_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessRepairTicket {
    pub repair_id: String,
    pub deposit_id: String,
    pub missing_provider_id: String,
    pub replacement_provider_id: Option<String>,
    pub evidence_root: String,
    pub status: WitnessRepairStatus,
    pub bounty_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl WitnessRepairTicket {
    pub fn new(
        deposit_id: &str,
        missing_provider_id: &str,
        evidence_root: &str,
        bounty_units: u64,
        opened_height: u64,
        repair_blocks: u64,
    ) -> PrivateContractWitnessEscrowResult<Self> {
        ensure_non_empty(deposit_id, "private witness repair deposit id")?;
        ensure_non_empty(
            missing_provider_id,
            "private witness repair missing provider",
        )?;
        ensure_non_empty(evidence_root, "private witness repair evidence root")?;
        if bounty_units == 0 {
            return Err("private witness repair bounty must be positive".to_string());
        }
        if repair_blocks == 0 {
            return Err("private witness repair window must be positive".to_string());
        }
        let expires_height = opened_height.saturating_add(repair_blocks);
        let repair_id = witness_repair_id(
            deposit_id,
            missing_provider_id,
            evidence_root,
            bounty_units,
            opened_height,
        );
        let repair = Self {
            repair_id,
            deposit_id: deposit_id.to_string(),
            missing_provider_id: missing_provider_id.to_string(),
            replacement_provider_id: None,
            evidence_root: evidence_root.to_string(),
            status: WitnessRepairStatus::Open,
            bounty_units,
            opened_height,
            expires_height,
        };
        repair.validate()?;
        Ok(repair)
    }

    pub fn assign(&mut self, provider_id: &str) -> PrivateContractWitnessEscrowResult<String> {
        ensure_non_empty(provider_id, "private witness repair provider id")?;
        if self.status != WitnessRepairStatus::Open {
            return Err("private witness repair can only assign from open".to_string());
        }
        self.status = WitnessRepairStatus::Assigned;
        self.replacement_provider_id = Some(provider_id.to_string());
        Ok(self.root())
    }

    pub fn complete(&mut self) -> PrivateContractWitnessEscrowResult<String> {
        if self.status != WitnessRepairStatus::Assigned {
            return Err("private witness repair can only complete after assignment".to_string());
        }
        self.status = WitnessRepairStatus::Completed;
        Ok(self.root())
    }

    pub fn validate(&self) -> PrivateContractWitnessEscrowResult<String> {
        ensure_non_empty(&self.repair_id, "private witness repair id")?;
        ensure_non_empty(&self.deposit_id, "private witness repair deposit id")?;
        ensure_non_empty(
            &self.missing_provider_id,
            "private witness repair missing provider",
        )?;
        ensure_non_empty(&self.evidence_root, "private witness repair evidence root")?;
        if self.bounty_units == 0 {
            return Err("private witness repair bounty must be positive".to_string());
        }
        if self.expires_height <= self.opened_height {
            return Err("private witness repair expiry must exceed open height".to_string());
        }
        let expected = witness_repair_id(
            &self.deposit_id,
            &self.missing_provider_id,
            &self.evidence_root,
            self.bounty_units,
            self.opened_height,
        );
        if self.repair_id != expected {
            return Err("private witness repair id does not match body".to_string());
        }
        Ok(self.root())
    }
}

impl WitnessEscrowRooted for WitnessRepairTicket {
    fn root(&self) -> String {
        witness_escrow_payload_root("PRIVATE-WITNESS-REPAIR", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "witness_repair_ticket",
            "repair_id": self.repair_id,
            "deposit_id": self.deposit_id,
            "missing_provider_id": self.missing_provider_id,
            "replacement_provider_id": self.replacement_provider_id,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "bounty_units": self.bounty_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContractWitnessEscrowRoots {
    pub config_root: String,
    pub provider_root: String,
    pub deposit_root: String,
    pub release_root: String,
    pub repair_root: String,
    pub lane_root: String,
    pub state_root: String,
}

impl PrivateContractWitnessEscrowRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "provider_root": self.provider_root,
            "deposit_root": self.deposit_root,
            "release_root": self.release_root,
            "repair_root": self.repair_root,
            "lane_root": self.lane_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContractWitnessEscrowCounters {
    pub height: u64,
    pub provider_count: u64,
    pub active_provider_count: u64,
    pub deposit_count: u64,
    pub live_deposit_count: u64,
    pub release_count: u64,
    pub repair_count: u64,
    pub open_repair_count: u64,
    pub total_fee_credit_units: u64,
}

impl PrivateContractWitnessEscrowCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "provider_count": self.provider_count,
            "active_provider_count": self.active_provider_count,
            "deposit_count": self.deposit_count,
            "live_deposit_count": self.live_deposit_count,
            "release_count": self.release_count,
            "repair_count": self.repair_count,
            "open_repair_count": self.open_repair_count,
            "total_fee_credit_units": self.total_fee_credit_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContractWitnessEscrowState {
    pub height: u64,
    pub label: String,
    pub config: PrivateContractWitnessEscrowConfig,
    pub providers: BTreeMap<String, WitnessProvider>,
    pub deposits: BTreeMap<String, WitnessDeposit>,
    pub releases: BTreeMap<String, WitnessRelease>,
    pub repairs: BTreeMap<String, WitnessRepairTicket>,
}

impl PrivateContractWitnessEscrowState {
    pub fn new(
        label: &str,
        config: PrivateContractWitnessEscrowConfig,
    ) -> PrivateContractWitnessEscrowResult<Self> {
        ensure_non_empty(label, "private witness escrow label")?;
        config.validate()?;
        let state = Self {
            height: 0,
            label: label.to_string(),
            config,
            providers: BTreeMap::new(),
            deposits: BTreeMap::new(),
            releases: BTreeMap::new(),
            repairs: BTreeMap::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> PrivateContractWitnessEscrowResult<Self> {
        let config = PrivateContractWitnessEscrowConfig::devnet()?;
        let mut state = Self::new(PRIVATE_CONTRACT_WITNESS_ESCROW_DEVNET_LABEL, config)?;
        state.set_height(54)?;
        let mut lanes = BTreeSet::new();
        lanes.insert(WitnessEscrowLane::ContractCall);
        lanes.insert(WitnessEscrowLane::MoneroBridge);
        lanes.insert(WitnessEscrowLane::PrivateSwap);
        let provider = WitnessProvider::new(
            "devnet-witness-provider-0",
            "devnet-witness-provider-0-pq",
            "devnet-witness-provider-0-bond",
            lanes,
            9_400,
        )?;
        let provider_id = provider.provider_id.clone();
        state.add_provider(provider)?;
        let mut provider_set = BTreeSet::new();
        provider_set.insert(provider_id.clone());
        let mut deposit = WitnessDeposit::new(
            WitnessEscrowLane::ContractCall,
            "devnet-private-contract",
            &witness_escrow_string_root("PRIVATE-WITNESS-DEVNET-ENVELOPE", "encrypted-witness"),
            &witness_escrow_string_root("PRIVATE-WITNESS-DEVNET-SCHEMA", "contract-schema"),
            provider_set,
            state.config.low_fee_credit_units,
            50,
            state.config.default_ttl_blocks,
        )?;
        deposit.mark_available()?;
        let deposit_id = deposit.deposit_id.clone();
        state.add_deposit(deposit)?;
        let release = WitnessRelease::new(
            &deposit_id,
            "devnet-executor",
            &witness_escrow_string_root("PRIVATE-WITNESS-DEVNET-RELEASE", "release-proof"),
            &witness_escrow_string_root("PRIVATE-WITNESS-DEVNET-ATTESTATION", "pq-attestation"),
            52,
        )?;
        state.add_release(release)?;
        let mut repair = WitnessRepairTicket::new(
            &deposit_id,
            &provider_id,
            &witness_escrow_string_root("PRIVATE-WITNESS-DEVNET-REPAIR", "late-provider"),
            500,
            53,
            state.config.default_repair_blocks,
        )?;
        repair.assign(&provider_id)?;
        repair.complete()?;
        state.add_repair(repair)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractWitnessEscrowResult<String> {
        self.height = height;
        self.validate()
    }

    pub fn add_provider(
        &mut self,
        provider: WitnessProvider,
    ) -> PrivateContractWitnessEscrowResult<String> {
        if self.providers.len() >= PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_PROVIDERS {
            return Err("private witness provider limit reached".to_string());
        }
        provider.validate()?;
        let root = provider.root();
        self.providers
            .insert(provider.provider_id.clone(), provider);
        Ok(root)
    }

    pub fn add_deposit(
        &mut self,
        deposit: WitnessDeposit,
    ) -> PrivateContractWitnessEscrowResult<String> {
        if self.deposits.len() >= PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_DEPOSITS {
            return Err("private witness deposit limit reached".to_string());
        }
        for provider_id in &deposit.provider_ids {
            let provider = self
                .providers
                .get(provider_id)
                .ok_or_else(|| "private witness deposit references unknown provider".to_string())?;
            if !provider.accepts_lane(deposit.lane) {
                return Err("private witness provider does not accept deposit lane".to_string());
            }
        }
        if deposit.provider_ids.len() as u64 > 0
            && (deposit.provider_ids.len() as u64) < self.config.min_replicas.min(1)
        {
            return Err("private witness deposit has too few replicas".to_string());
        }
        deposit.validate()?;
        let root = deposit.root();
        self.deposits.insert(deposit.deposit_id.clone(), deposit);
        Ok(root)
    }

    pub fn add_release(
        &mut self,
        release: WitnessRelease,
    ) -> PrivateContractWitnessEscrowResult<String> {
        if self.releases.len() >= PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_RELEASES {
            return Err("private witness release limit reached".to_string());
        }
        let deposit = self
            .deposits
            .get_mut(&release.deposit_id)
            .ok_or_else(|| "private witness release references unknown deposit".to_string())?;
        release.validate()?;
        deposit.mark_released()?;
        let root = release.root();
        self.releases.insert(release.release_id.clone(), release);
        Ok(root)
    }

    pub fn add_repair(
        &mut self,
        repair: WitnessRepairTicket,
    ) -> PrivateContractWitnessEscrowResult<String> {
        if self.repairs.len() >= PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_REPAIRS {
            return Err("private witness repair limit reached".to_string());
        }
        if !self.deposits.contains_key(&repair.deposit_id) {
            return Err("private witness repair references unknown deposit".to_string());
        }
        if !self.providers.contains_key(&repair.missing_provider_id) {
            return Err("private witness repair references unknown missing provider".to_string());
        }
        if let Some(provider_id) = &repair.replacement_provider_id {
            if !self.providers.contains_key(provider_id) {
                return Err(
                    "private witness repair references unknown replacement provider".to_string(),
                );
            }
        }
        repair.validate()?;
        let root = repair.root();
        self.repairs.insert(repair.repair_id.clone(), repair);
        Ok(root)
    }

    pub fn active_provider_ids(&self) -> Vec<String> {
        self.providers
            .values()
            .filter(|provider| provider.status.accepts_witness())
            .map(|provider| provider.provider_id.clone())
            .collect()
    }

    pub fn live_deposit_ids(&self) -> Vec<String> {
        self.deposits
            .values()
            .filter(|deposit| deposit.status.live())
            .map(|deposit| deposit.deposit_id.clone())
            .collect()
    }

    pub fn open_repair_ids(&self) -> Vec<String> {
        self.repairs
            .values()
            .filter(|repair| repair.status.open())
            .map(|repair| repair.repair_id.clone())
            .collect()
    }

    pub fn lane_deposit_map(&self) -> BTreeMap<String, u64> {
        let mut lanes = BTreeMap::new();
        for deposit in self.deposits.values() {
            *lanes.entry(deposit.lane.as_str().to_string()).or_insert(0) += 1;
        }
        lanes
    }

    pub fn roots(&self) -> PrivateContractWitnessEscrowRoots {
        let config_root = self.config.root();
        let provider_root = witness_escrow_map_root("PRIVATE-WITNESS-PROVIDERS", &self.providers);
        let deposit_root = witness_escrow_map_root("PRIVATE-WITNESS-DEPOSITS", &self.deposits);
        let release_root = witness_escrow_map_root("PRIVATE-WITNESS-RELEASES", &self.releases);
        let repair_root = witness_escrow_map_root("PRIVATE-WITNESS-REPAIRS", &self.repairs);
        let lane_root =
            witness_escrow_payload_root("PRIVATE-WITNESS-LANES", &json!(self.lane_deposit_map()));
        let state_root = domain_hash(
            "PRIVATE-CONTRACT-WITNESS-ESCROW-STATE-ROOT",
            &[
                HashPart::Str(&self.label),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&provider_root),
                HashPart::Str(&deposit_root),
                HashPart::Str(&release_root),
                HashPart::Str(&repair_root),
                HashPart::Str(&lane_root),
            ],
            32,
        );
        PrivateContractWitnessEscrowRoots {
            config_root,
            provider_root,
            deposit_root,
            release_root,
            repair_root,
            lane_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateContractWitnessEscrowCounters {
        PrivateContractWitnessEscrowCounters {
            height: self.height,
            provider_count: self.providers.len() as u64,
            active_provider_count: self
                .providers
                .values()
                .filter(|provider| provider.status.accepts_witness())
                .count() as u64,
            deposit_count: self.deposits.len() as u64,
            live_deposit_count: self
                .deposits
                .values()
                .filter(|deposit| deposit.status.live())
                .count() as u64,
            release_count: self.releases.len() as u64,
            repair_count: self.repairs.len() as u64,
            open_repair_count: self
                .repairs
                .values()
                .filter(|repair| repair.status.open())
                .count() as u64,
            total_fee_credit_units: self
                .deposits
                .values()
                .map(|deposit| deposit.fee_credit_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_witness_escrow_state",
            "label": self.label,
            "height": self.height,
            "state_root": self.state_root(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_provider_ids": self.active_provider_ids(),
            "live_deposit_ids": self.live_deposit_ids(),
            "open_repair_ids": self.open_repair_ids(),
            "lane_deposit_map": self.lane_deposit_map(),
        })
    }

    pub fn validate(&self) -> PrivateContractWitnessEscrowResult<String> {
        ensure_non_empty(&self.label, "private witness escrow label")?;
        self.config.validate()?;
        if self.deposits.len() > PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_DEPOSITS {
            return Err("private witness escrow has too many deposits".to_string());
        }
        if self.providers.len() > PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_PROVIDERS {
            return Err("private witness escrow has too many providers".to_string());
        }
        if self.releases.len() > PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_RELEASES {
            return Err("private witness escrow has too many releases".to_string());
        }
        if self.repairs.len() > PRIVATE_CONTRACT_WITNESS_ESCROW_MAX_REPAIRS {
            return Err("private witness escrow has too many repairs".to_string());
        }
        for provider in self.providers.values() {
            provider.validate()?;
        }
        for deposit in self.deposits.values() {
            deposit.validate()?;
            for provider_id in &deposit.provider_ids {
                if !self.providers.contains_key(provider_id) {
                    return Err("private witness deposit references missing provider".to_string());
                }
            }
        }
        for release in self.releases.values() {
            release.validate()?;
            if !self.deposits.contains_key(&release.deposit_id) {
                return Err("private witness release references missing deposit".to_string());
            }
        }
        for repair in self.repairs.values() {
            repair.validate()?;
            if !self.deposits.contains_key(&repair.deposit_id) {
                return Err("private witness repair references missing deposit".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_contract_witness_escrow_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-WITNESS-ESCROW-STATE-ROOT-FROM-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn witness_escrow_config_id(protocol_version: &str, schema_version: &str) -> String {
    domain_hash(
        "PRIVATE-WITNESS-ESCROW-CONFIG-ID",
        &[
            HashPart::Str(protocol_version),
            HashPart::Str(schema_version),
        ],
        24,
    )
}

pub fn witness_provider_id(
    operator_commitment: &str,
    pq_key_root: &str,
    storage_bond_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-WITNESS-PROVIDER-ID",
        &[
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_key_root),
            HashPart::Str(storage_bond_root),
        ],
        24,
    )
}

pub fn witness_deposit_id(
    lane: WitnessEscrowLane,
    contract_commitment: &str,
    encrypted_witness_root: &str,
    witness_schema_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-WITNESS-DEPOSIT-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(contract_commitment),
            HashPart::Str(encrypted_witness_root),
            HashPart::Str(witness_schema_root),
            HashPart::Int(opened_height as i128),
        ],
        24,
    )
}

pub fn witness_release_id(
    deposit_id: &str,
    requester_commitment: &str,
    release_proof_root: &str,
    pq_attestation_root: &str,
    released_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-WITNESS-RELEASE-ID",
        &[
            HashPart::Str(deposit_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(release_proof_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Int(released_height as i128),
        ],
        24,
    )
}

pub fn witness_repair_id(
    deposit_id: &str,
    missing_provider_id: &str,
    evidence_root: &str,
    bounty_units: u64,
    opened_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-WITNESS-REPAIR-ID",
        &[
            HashPart::Str(deposit_id),
            HashPart::Str(missing_provider_id),
            HashPart::Str(evidence_root),
            HashPart::Int(bounty_units as i128),
            HashPart::Int(opened_height as i128),
        ],
        24,
    )
}

fn witness_escrow_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn witness_escrow_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn witness_escrow_map_root<T: WitnessEscrowRooted>(
    domain: &str,
    map: &BTreeMap<String, T>,
) -> String {
    let leaves = map
        .iter()
        .map(|(id, value)| json!({ "id": id, "root": value.root() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateContractWitnessEscrowResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
