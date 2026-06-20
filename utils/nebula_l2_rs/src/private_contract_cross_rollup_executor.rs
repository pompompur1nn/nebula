use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractCrossRollupExecutorResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PROTOCOL_LABEL: &str =
    "nebula-private-contract-cross-rollup-executor-v1";
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT: u64 = 2_048;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+HPKE-private-contract-call-v1";
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-cross-rollup-executor";
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_WITNESS_SUITE: &str =
    "zk-private-contract-witness-bundle-v1";
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_SETTLEMENT_SUITE: &str =
    "recursive-pq-settlement-proof-v1";
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_REORG_DEPTH: u64 = 8;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_PRECONFIRM_MS: u64 = 420;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_MAX_HOPS: u64 = 6;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_BASE_FEE_MICRO_XMR: u64 = 37;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_SPONSOR_BUDGET_MICRO_XMR: u64 = 9_500;
pub const PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossRollupExecutionLane {
    DefiSwap,
    Lending,
    Perps,
    Stablecoin,
    Governance,
    OracleUpdate,
    BridgeSettlement,
    EmergencyRecovery,
}

impl CrossRollupExecutionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Stablecoin => "stablecoin",
            Self::Governance => "governance",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeSettlement => "bridge_settlement",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyRecovery => 100,
            Self::BridgeSettlement => 92,
            Self::Stablecoin => 88,
            Self::Lending => 84,
            Self::DefiSwap => 80,
            Self::Perps => 76,
            Self::OracleUpdate => 70,
            Self::Governance => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScopeKind {
    ReadPrivateState,
    WritePrivateState,
    SpendShieldedBalance,
    MintConfidentialAsset,
    BurnConfidentialAsset,
    CrossRollupDispatch,
    OracleRead,
    SponsorFee,
    SettlementSubmit,
    EmergencyRollback,
}

impl CapabilityScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadPrivateState => "read_private_state",
            Self::WritePrivateState => "write_private_state",
            Self::SpendShieldedBalance => "spend_shielded_balance",
            Self::MintConfidentialAsset => "mint_confidential_asset",
            Self::BurnConfidentialAsset => "burn_confidential_asset",
            Self::CrossRollupDispatch => "cross_rollup_dispatch",
            Self::OracleRead => "oracle_read",
            Self::SponsorFee => "sponsor_fee",
            Self::SettlementSubmit => "settlement_submit",
            Self::EmergencyRollback => "emergency_rollback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedCallStatus {
    Queued,
    Ordered,
    Witnessed,
    Executed,
    Receipted,
    Settled,
    Reverted,
    RolledBack,
    Expired,
}

impl EncryptedCallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Ordered => "ordered",
            Self::Witnessed => "witnessed",
            Self::Executed => "executed",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Ordered | Self::Witnessed | Self::Executed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessBundleStatus {
    Committed,
    Available,
    Sampled,
    Pinned,
    Challenged,
    Slashed,
    Expired,
}

impl WitnessBundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Available => "available",
            Self::Sampled => "sampled",
            Self::Pinned => "pinned",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Available | Self::Sampled | Self::Pinned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Pending,
    Verified,
    Aggregated,
    Quarantined,
    Revoked,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Aggregated => "aggregated",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
        }
    }

    pub fn trusted(self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingTicketStatus {
    Reserved,
    Sequenced,
    Preconfirmed,
    Finalized,
    Cancelled,
    Reorged,
}

impl OrderingTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Sequenced => "sequenced",
            Self::Preconfirmed => "preconfirmed",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
            Self::Reorged => "reorged",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Reserved | Self::Sequenced | Self::Preconfirmed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Succeeded,
    Reverted,
    PartialCommit,
    DeferredSettlement,
}

impl ExecutionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Reverted => "reverted",
            Self::PartialCommit => "partial_commit",
            Self::DeferredSettlement => "deferred_settlement",
        }
    }

    pub fn commits_state(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::PartialCommit | Self::DeferredSettlement
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementProofStatus {
    Draft,
    Submitted,
    Accepted,
    Challenged,
    Rejected,
    ReorgProtected,
}

impl SettlementProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::ReorgProtected => "reorg_protected",
        }
    }

    pub fn final_for_devnet(self) -> bool {
        matches!(self, Self::Accepted | Self::ReorgProtected)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupExecutorConfig {
    pub protocol_label: String,
    pub protocol_version: u32,
    pub schema_version: u64,
    pub chain_id: String,
    pub encryption_suite: String,
    pub pq_attestation_suite: String,
    pub witness_suite: String,
    pub settlement_suite: String,
    pub hash_suite: String,
    pub max_hops: u64,
    pub reorg_depth: u64,
    pub preconfirm_target_ms: u64,
    pub base_fee_micro_xmr: u64,
    pub sponsor_budget_micro_xmr: u64,
    pub privacy_floor_bps: u64,
    pub low_fee_discount_bps: u64,
}

impl CrossRollupExecutorConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_label: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PROTOCOL_LABEL.to_string(),
            protocol_version: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PROTOCOL_VERSION,
            schema_version: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            encryption_suite: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_ENCRYPTION_SUITE.to_string(),
            pq_attestation_suite: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PQ_ATTESTATION_SUITE
                .to_string(),
            witness_suite: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_WITNESS_SUITE.to_string(),
            settlement_suite: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_SETTLEMENT_SUITE.to_string(),
            hash_suite: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_HASH_SUITE.to_string(),
            max_hops: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_MAX_HOPS,
            reorg_depth: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_REORG_DEPTH,
            preconfirm_target_ms: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_PRECONFIRM_MS,
            base_fee_micro_xmr: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_BASE_FEE_MICRO_XMR,
            sponsor_budget_micro_xmr:
                PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_SPONSOR_BUDGET_MICRO_XMR,
            privacy_floor_bps: 9_250,
            low_fee_discount_bps: 7_500,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_label": self.protocol_label,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "encryption_suite": self.encryption_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "witness_suite": self.witness_suite,
            "settlement_suite": self.settlement_suite,
            "hash_suite": self.hash_suite,
            "max_hops": self.max_hops,
            "reorg_depth": self.reorg_depth,
            "preconfirm_target_ms": self.preconfirm_target_ms,
            "base_fee_micro_xmr": self.base_fee_micro_xmr,
            "sponsor_budget_micro_xmr": self.sponsor_budget_micro_xmr,
            "privacy_floor_bps": self.privacy_floor_bps,
            "low_fee_discount_bps": self.low_fee_discount_bps,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.protocol_label, "cross-rollup executor protocol label")?;
        ensure_non_empty(&self.chain_id, "cross-rollup executor chain id")?;
        ensure_non_empty(
            &self.encryption_suite,
            "cross-rollup executor encryption suite",
        )?;
        ensure_non_empty(
            &self.pq_attestation_suite,
            "cross-rollup executor pq attestation suite",
        )?;
        ensure_non_empty(&self.witness_suite, "cross-rollup executor witness suite")?;
        ensure_non_empty(
            &self.settlement_suite,
            "cross-rollup executor settlement suite",
        )?;
        ensure_non_empty(&self.hash_suite, "cross-rollup executor hash suite")?;
        if self.protocol_version == 0 || self.schema_version == 0 {
            return Err("cross-rollup executor versions must be positive".to_string());
        }
        if self.max_hops == 0 || self.reorg_depth == 0 || self.preconfirm_target_ms == 0 {
            return Err(
                "cross-rollup executor timing and path limits must be positive".to_string(),
            );
        }
        if self.privacy_floor_bps > PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_MAX_BPS
            || self.low_fee_discount_bps > PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_MAX_BPS
        {
            return Err("cross-rollup executor bps values exceed max".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupEndpoint {
    pub rollup_id: String,
    pub domain: String,
    pub sequencer_committee_root: String,
    pub state_root: String,
    pub settlement_bridge: String,
    pub privacy_pool_root: String,
    pub latest_height: u64,
    pub finality_lag: u64,
    pub accepts_sponsored_calls: bool,
    pub supported_lanes: BTreeSet<CrossRollupExecutionLane>,
}

impl RollupEndpoint {
    pub fn devnet(
        label: &str,
        domain: &str,
        lanes: &[CrossRollupExecutionLane],
        latest_height: u64,
    ) -> Self {
        let supported_lanes = lanes.iter().copied().collect::<BTreeSet<_>>();
        let rollup_id = cross_rollup_executor_id("ROLLUP", &[label, domain]);
        Self {
            rollup_id: rollup_id.clone(),
            domain: domain.to_string(),
            sequencer_committee_root: cross_rollup_executor_id(
                "SEQUENCER-COMMITTEE",
                &[label, domain],
            ),
            state_root: cross_rollup_executor_id("ROLLUP-STATE", &[label, domain]),
            settlement_bridge: format!("{domain}-settlement-bridge"),
            privacy_pool_root: cross_rollup_executor_id("PRIVACY-POOL", &[label, domain]),
            latest_height,
            finality_lag: 2,
            accepts_sponsored_calls: true,
            supported_lanes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rollup_id": self.rollup_id,
            "domain": self.domain,
            "sequencer_committee_root": self.sequencer_committee_root,
            "state_root": self.state_root,
            "settlement_bridge": self.settlement_bridge,
            "privacy_pool_root": self.privacy_pool_root,
            "latest_height": self.latest_height,
            "finality_lag": self.finality_lag,
            "accepts_sponsored_calls": self.accepts_sponsored_calls,
            "supported_lanes": self.supported_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("ROLLUP-ENDPOINT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.rollup_id, "rollup endpoint id")?;
        ensure_non_empty(&self.domain, "rollup endpoint domain")?;
        ensure_non_empty(
            &self.sequencer_committee_root,
            "rollup endpoint sequencer committee root",
        )?;
        ensure_non_empty(&self.state_root, "rollup endpoint state root")?;
        ensure_non_empty(&self.settlement_bridge, "rollup endpoint settlement bridge")?;
        ensure_non_empty(&self.privacy_pool_root, "rollup endpoint privacy pool root")?;
        if self.latest_height == 0 {
            return Err("rollup endpoint latest height must be positive".to_string());
        }
        if self.supported_lanes.is_empty() {
            return Err("rollup endpoint must support at least one lane".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    pub scope_id: String,
    pub holder_commitment: String,
    pub contract_commitment: String,
    pub source_rollup_id: String,
    pub target_rollup_ids: BTreeSet<String>,
    pub allowed_kinds: BTreeSet<CapabilityScopeKind>,
    pub max_value_commitment: String,
    pub expiry_height: u64,
    pub nonce: u64,
    pub revocation_root: String,
}

impl CapabilityScope {
    pub fn new(
        holder_commitment: &str,
        contract_commitment: &str,
        source_rollup_id: &str,
        target_rollup_ids: BTreeSet<String>,
        allowed_kinds: BTreeSet<CapabilityScopeKind>,
        expiry_height: u64,
        nonce: u64,
    ) -> Self {
        let scope_id = cross_rollup_executor_id(
            "CAPABILITY-SCOPE",
            &[
                holder_commitment,
                contract_commitment,
                source_rollup_id,
                &nonce.to_string(),
            ],
        );
        Self {
            scope_id,
            holder_commitment: holder_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            source_rollup_id: source_rollup_id.to_string(),
            target_rollup_ids,
            allowed_kinds,
            max_value_commitment: cross_rollup_executor_id(
                "CAPABILITY-MAX-VALUE",
                &[holder_commitment, contract_commitment],
            ),
            expiry_height,
            nonce,
            revocation_root: cross_rollup_executor_id(
                "CAPABILITY-REVOCATION",
                &[holder_commitment],
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scope_id": self.scope_id,
            "holder_commitment": self.holder_commitment,
            "contract_commitment": self.contract_commitment,
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_ids": self.target_rollup_ids.iter().cloned().collect::<Vec<_>>(),
            "allowed_kinds": self.allowed_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "max_value_commitment": self.max_value_commitment,
            "expiry_height": self.expiry_height,
            "nonce": self.nonce,
            "revocation_root": self.revocation_root,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("CAPABILITY-SCOPE", &self.public_record())
    }

    pub fn grants(&self, kind: CapabilityScopeKind, target_rollup_id: &str, height: u64) -> bool {
        self.allowed_kinds.contains(&kind)
            && self.target_rollup_ids.contains(target_rollup_id)
            && height <= self.expiry_height
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.scope_id, "capability scope id")?;
        ensure_non_empty(&self.holder_commitment, "capability holder commitment")?;
        ensure_non_empty(&self.contract_commitment, "capability contract commitment")?;
        ensure_non_empty(&self.source_rollup_id, "capability source rollup")?;
        ensure_non_empty(
            &self.max_value_commitment,
            "capability max value commitment",
        )?;
        ensure_non_empty(&self.revocation_root, "capability revocation root")?;
        if self.target_rollup_ids.is_empty() || self.allowed_kinds.is_empty() {
            return Err("capability scope must target rollups and grant kinds".to_string());
        }
        if self.expiry_height == 0 {
            return Err("capability scope expiry height must be positive".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCallEnvelope {
    pub call_id: String,
    pub lane: CrossRollupExecutionLane,
    pub status: EncryptedCallStatus,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub capability_scope_id: String,
    pub ciphertext_root: String,
    pub ephemeral_key_commitment: String,
    pub nullifier_root: String,
    pub calldata_commitment: String,
    pub witness_hint_root: String,
    pub fee_commitment: String,
    pub sponsor_policy_id: Option<String>,
    pub max_fee_micro_xmr: u64,
    pub gas_limit: u64,
    pub created_height: u64,
    pub expiry_height: u64,
    pub nonce: u64,
}

impl EncryptedCallEnvelope {
    pub fn new(
        lane: CrossRollupExecutionLane,
        source_rollup_id: &str,
        target_rollup_id: &str,
        sender_commitment: &str,
        contract_commitment: &str,
        capability_scope_id: &str,
        created_height: u64,
        nonce: u64,
    ) -> Self {
        let call_id = cross_rollup_executor_id(
            "ENCRYPTED-CALL",
            &[
                lane.as_str(),
                source_rollup_id,
                target_rollup_id,
                sender_commitment,
                contract_commitment,
                &nonce.to_string(),
            ],
        );
        Self {
            call_id: call_id.clone(),
            lane,
            status: EncryptedCallStatus::Queued,
            source_rollup_id: source_rollup_id.to_string(),
            target_rollup_id: target_rollup_id.to_string(),
            sender_commitment: sender_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            capability_scope_id: capability_scope_id.to_string(),
            ciphertext_root: cross_rollup_executor_id("CALL-CIPHERTEXT", &[&call_id]),
            ephemeral_key_commitment: cross_rollup_executor_id("CALL-EPHEMERAL-KEY", &[&call_id]),
            nullifier_root: cross_rollup_executor_id("CALL-NULLIFIER", &[&call_id]),
            calldata_commitment: cross_rollup_executor_id("CALLDATA", &[&call_id]),
            witness_hint_root: cross_rollup_executor_id("CALL-WITNESS-HINT", &[&call_id]),
            fee_commitment: cross_rollup_executor_id("CALL-FEE", &[&call_id]),
            sponsor_policy_id: None,
            max_fee_micro_xmr: 180,
            gas_limit: 1_250_000,
            created_height,
            expiry_height: created_height.saturating_add(64),
            nonce,
        }
    }

    pub fn with_sponsor(mut self, sponsor_policy_id: &str, max_fee_micro_xmr: u64) -> Self {
        self.sponsor_policy_id = Some(sponsor_policy_id.to_string());
        self.max_fee_micro_xmr = max_fee_micro_xmr;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "sender_commitment": self.sender_commitment,
            "contract_commitment": self.contract_commitment,
            "capability_scope_id": self.capability_scope_id,
            "ciphertext_root": self.ciphertext_root,
            "ephemeral_key_commitment": self.ephemeral_key_commitment,
            "nullifier_root": self.nullifier_root,
            "calldata_commitment": self.calldata_commitment,
            "witness_hint_root": self.witness_hint_root,
            "fee_commitment": self.fee_commitment,
            "sponsor_policy_id": self.sponsor_policy_id,
            "max_fee_micro_xmr": self.max_fee_micro_xmr,
            "gas_limit": self.gas_limit,
            "created_height": self.created_height,
            "expiry_height": self.expiry_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("ENCRYPTED-CALL-ENVELOPE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.call_id, "encrypted call id")?;
        ensure_non_empty(&self.source_rollup_id, "encrypted call source rollup")?;
        ensure_non_empty(&self.target_rollup_id, "encrypted call target rollup")?;
        ensure_non_empty(&self.sender_commitment, "encrypted call sender commitment")?;
        ensure_non_empty(
            &self.contract_commitment,
            "encrypted call contract commitment",
        )?;
        ensure_non_empty(&self.capability_scope_id, "encrypted call capability scope")?;
        ensure_non_empty(&self.ciphertext_root, "encrypted call ciphertext root")?;
        ensure_non_empty(
            &self.ephemeral_key_commitment,
            "encrypted call ephemeral key commitment",
        )?;
        ensure_non_empty(&self.nullifier_root, "encrypted call nullifier root")?;
        ensure_non_empty(
            &self.calldata_commitment,
            "encrypted call calldata commitment",
        )?;
        ensure_non_empty(&self.witness_hint_root, "encrypted call witness hint root")?;
        ensure_non_empty(&self.fee_commitment, "encrypted call fee commitment")?;
        if self.source_rollup_id == self.target_rollup_id {
            return Err("encrypted cross-rollup call must cross rollup domains".to_string());
        }
        if self.max_fee_micro_xmr == 0 || self.gas_limit == 0 {
            return Err("encrypted call fee and gas limits must be positive".to_string());
        }
        if self.created_height == 0 || self.expiry_height <= self.created_height {
            return Err("encrypted call heights must be ordered".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessBundle {
    pub bundle_id: String,
    pub call_id: String,
    pub status: WitnessBundleStatus,
    pub witness_root: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub encrypted_blob_root: String,
    pub availability_committee_root: String,
    pub provider_ids: BTreeSet<String>,
    pub sample_count: u64,
    pub byte_size: u64,
    pub posted_height: u64,
    pub expires_height: u64,
}

impl WitnessBundle {
    pub fn new(call_id: &str, providers: BTreeSet<String>, posted_height: u64) -> Self {
        let bundle_id = cross_rollup_executor_id("WITNESS-BUNDLE", &[call_id]);
        Self {
            bundle_id: bundle_id.clone(),
            call_id: call_id.to_string(),
            status: WitnessBundleStatus::Available,
            witness_root: cross_rollup_executor_id("WITNESS-ROOT", &[call_id]),
            state_read_root: cross_rollup_executor_id("WITNESS-READ", &[call_id]),
            state_write_root: cross_rollup_executor_id("WITNESS-WRITE", &[call_id]),
            encrypted_blob_root: cross_rollup_executor_id("WITNESS-BLOB", &[call_id]),
            availability_committee_root: cross_rollup_executor_id("WITNESS-COMMITTEE", &[call_id]),
            provider_ids: providers,
            sample_count: 24,
            byte_size: 42_000,
            posted_height,
            expires_height: posted_height.saturating_add(96),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "call_id": self.call_id,
            "status": self.status.as_str(),
            "witness_root": self.witness_root,
            "state_read_root": self.state_read_root,
            "state_write_root": self.state_write_root,
            "encrypted_blob_root": self.encrypted_blob_root,
            "availability_committee_root": self.availability_committee_root,
            "provider_ids": self.provider_ids.iter().cloned().collect::<Vec<_>>(),
            "sample_count": self.sample_count,
            "byte_size": self.byte_size,
            "posted_height": self.posted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("WITNESS-BUNDLE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.bundle_id, "witness bundle id")?;
        ensure_non_empty(&self.call_id, "witness bundle call id")?;
        ensure_non_empty(&self.witness_root, "witness bundle root")?;
        ensure_non_empty(&self.state_read_root, "witness state read root")?;
        ensure_non_empty(&self.state_write_root, "witness state write root")?;
        ensure_non_empty(&self.encrypted_blob_root, "witness encrypted blob root")?;
        ensure_non_empty(
            &self.availability_committee_root,
            "witness availability committee root",
        )?;
        if self.provider_ids.is_empty() {
            return Err("witness bundle must have providers".to_string());
        }
        if self.sample_count == 0 || self.byte_size == 0 {
            return Err("witness bundle sample count and size must be positive".to_string());
        }
        if self.posted_height == 0 || self.expires_height <= self.posted_height {
            return Err("witness bundle heights must be ordered".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqExecutionAttestation {
    pub attestation_id: String,
    pub call_id: String,
    pub attester_id: String,
    pub status: PqAttestationStatus,
    pub suite: String,
    pub transcript_root: String,
    pub public_key_root: String,
    pub signature_root: String,
    pub aggregated_signature_root: Option<String>,
    pub safety_claims: BTreeSet<String>,
    pub issued_height: u64,
}

impl PqExecutionAttestation {
    pub fn new(call_id: &str, attester_id: &str, issued_height: u64) -> Self {
        let attestation_id =
            cross_rollup_executor_id("PQ-EXECUTION-ATTESTATION", &[call_id, attester_id]);
        let mut safety_claims = BTreeSet::new();
        safety_claims.insert("ciphertext-bound".to_string());
        safety_claims.insert("capability-checked".to_string());
        safety_claims.insert("witness-available".to_string());
        safety_claims.insert("quantum-resistant-auth".to_string());
        Self {
            attestation_id,
            call_id: call_id.to_string(),
            attester_id: attester_id.to_string(),
            status: PqAttestationStatus::Verified,
            suite: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PQ_ATTESTATION_SUITE.to_string(),
            transcript_root: cross_rollup_executor_id("PQ-TRANSCRIPT", &[call_id, attester_id]),
            public_key_root: cross_rollup_executor_id("PQ-PUBLIC-KEY", &[attester_id]),
            signature_root: cross_rollup_executor_id("PQ-SIGNATURE", &[call_id, attester_id]),
            aggregated_signature_root: Some(cross_rollup_executor_id(
                "PQ-AGGREGATED-SIGNATURE",
                &[call_id],
            )),
            safety_claims,
            issued_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "call_id": self.call_id,
            "attester_id": self.attester_id,
            "status": self.status.as_str(),
            "suite": self.suite,
            "transcript_root": self.transcript_root,
            "public_key_root": self.public_key_root,
            "signature_root": self.signature_root,
            "aggregated_signature_root": self.aggregated_signature_root,
            "safety_claims": self.safety_claims.iter().cloned().collect::<Vec<_>>(),
            "issued_height": self.issued_height,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("PQ-EXECUTION-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.attestation_id, "pq attestation id")?;
        ensure_non_empty(&self.call_id, "pq attestation call id")?;
        ensure_non_empty(&self.attester_id, "pq attestation attester id")?;
        ensure_non_empty(&self.suite, "pq attestation suite")?;
        ensure_non_empty(&self.transcript_root, "pq attestation transcript root")?;
        ensure_non_empty(&self.public_key_root, "pq attestation public key root")?;
        ensure_non_empty(&self.signature_root, "pq attestation signature root")?;
        if self.safety_claims.is_empty() {
            return Err("pq attestation must include safety claims".to_string());
        }
        if self.issued_height == 0 {
            return Err("pq attestation issued height must be positive".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingTicket {
    pub ticket_id: String,
    pub call_id: String,
    pub lane: CrossRollupExecutionLane,
    pub status: OrderingTicketStatus,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub sequencer_id: String,
    pub priority: u64,
    pub sequence_number: u64,
    pub reserved_height: u64,
    pub preconfirm_deadline_ms: u64,
    pub ordering_commitment: String,
    pub anti_mev_commitment: String,
}

impl OrderingTicket {
    pub fn new(call: &EncryptedCallEnvelope, sequencer_id: &str, sequence_number: u64) -> Self {
        let ticket_id = cross_rollup_executor_id(
            "ORDERING-TICKET",
            &[&call.call_id, &sequence_number.to_string()],
        );
        Self {
            ticket_id: ticket_id.clone(),
            call_id: call.call_id.clone(),
            lane: call.lane,
            status: OrderingTicketStatus::Preconfirmed,
            source_rollup_id: call.source_rollup_id.clone(),
            target_rollup_id: call.target_rollup_id.clone(),
            sequencer_id: sequencer_id.to_string(),
            priority: call.lane.priority(),
            sequence_number,
            reserved_height: call.created_height.saturating_add(1),
            preconfirm_deadline_ms: PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_PRECONFIRM_MS,
            ordering_commitment: cross_rollup_executor_id("ORDERING-COMMITMENT", &[&ticket_id]),
            anti_mev_commitment: cross_rollup_executor_id("ANTI-MEV-COMMITMENT", &[&ticket_id]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "call_id": self.call_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "sequencer_id": self.sequencer_id,
            "priority": self.priority,
            "sequence_number": self.sequence_number,
            "reserved_height": self.reserved_height,
            "preconfirm_deadline_ms": self.preconfirm_deadline_ms,
            "ordering_commitment": self.ordering_commitment,
            "anti_mev_commitment": self.anti_mev_commitment,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("ORDERING-TICKET", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.ticket_id, "ordering ticket id")?;
        ensure_non_empty(&self.call_id, "ordering ticket call id")?;
        ensure_non_empty(&self.source_rollup_id, "ordering ticket source rollup")?;
        ensure_non_empty(&self.target_rollup_id, "ordering ticket target rollup")?;
        ensure_non_empty(&self.sequencer_id, "ordering ticket sequencer id")?;
        ensure_non_empty(&self.ordering_commitment, "ordering ticket commitment")?;
        ensure_non_empty(
            &self.anti_mev_commitment,
            "ordering ticket anti mev commitment",
        )?;
        if self.priority == 0 || self.sequence_number == 0 || self.reserved_height == 0 {
            return Err(
                "ordering ticket priority and sequence values must be positive".to_string(),
            );
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub ticket_id: String,
    pub outcome: ExecutionOutcome,
    pub source_rollup_state_before: String,
    pub source_rollup_state_after: String,
    pub target_rollup_state_before: String,
    pub target_rollup_state_after: String,
    pub private_event_root: String,
    pub nullifier_root: String,
    pub gas_used: u64,
    pub fee_paid_micro_xmr: u64,
    pub sponsored_micro_xmr: u64,
    pub executed_height: u64,
    pub receipt_root: String,
}

impl ExecutionReceipt {
    pub fn new(
        call: &EncryptedCallEnvelope,
        ticket: &OrderingTicket,
        source_before: &str,
        target_before: &str,
        executed_height: u64,
    ) -> Self {
        let receipt_id =
            cross_rollup_executor_id("EXECUTION-RECEIPT", &[&call.call_id, &ticket.ticket_id]);
        let source_rollup_state_after =
            cross_rollup_executor_id("SOURCE-AFTER", &[source_before, &receipt_id]);
        let target_rollup_state_after =
            cross_rollup_executor_id("TARGET-AFTER", &[target_before, &receipt_id]);
        let sponsored_micro_xmr = if call.sponsor_policy_id.is_some() {
            call.max_fee_micro_xmr.saturating_sub(25)
        } else {
            0
        };
        let mut receipt = Self {
            receipt_id,
            call_id: call.call_id.clone(),
            ticket_id: ticket.ticket_id.clone(),
            outcome: ExecutionOutcome::Succeeded,
            source_rollup_state_before: source_before.to_string(),
            source_rollup_state_after,
            target_rollup_state_before: target_before.to_string(),
            target_rollup_state_after,
            private_event_root: cross_rollup_executor_id("PRIVATE-EVENT", &[&call.call_id]),
            nullifier_root: call.nullifier_root.clone(),
            gas_used: call.gas_limit.saturating_mul(62).saturating_div(100),
            fee_paid_micro_xmr: call.max_fee_micro_xmr.saturating_sub(sponsored_micro_xmr),
            sponsored_micro_xmr,
            executed_height,
            receipt_root: String::new(),
        };
        receipt.receipt_root = cross_rollup_executor_payload_root(
            "EXECUTION-RECEIPT-ROOT",
            &receipt.public_record_without_root(),
        );
        receipt
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "ticket_id": self.ticket_id,
            "outcome": self.outcome.as_str(),
            "source_rollup_state_before": self.source_rollup_state_before,
            "source_rollup_state_after": self.source_rollup_state_after,
            "target_rollup_state_before": self.target_rollup_state_before,
            "target_rollup_state_after": self.target_rollup_state_after,
            "private_event_root": self.private_event_root,
            "nullifier_root": self.nullifier_root,
            "gas_used": self.gas_used,
            "fee_paid_micro_xmr": self.fee_paid_micro_xmr,
            "sponsored_micro_xmr": self.sponsored_micro_xmr,
            "executed_height": self.executed_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert(
                "receipt_root".to_string(),
                Value::String(self.receipt_root.clone()),
            );
        }
        record
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("EXECUTION-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.receipt_id, "execution receipt id")?;
        ensure_non_empty(&self.call_id, "execution receipt call id")?;
        ensure_non_empty(&self.ticket_id, "execution receipt ticket id")?;
        ensure_non_empty(
            &self.source_rollup_state_before,
            "execution receipt source state before",
        )?;
        ensure_non_empty(
            &self.source_rollup_state_after,
            "execution receipt source state after",
        )?;
        ensure_non_empty(
            &self.target_rollup_state_before,
            "execution receipt target state before",
        )?;
        ensure_non_empty(
            &self.target_rollup_state_after,
            "execution receipt target state after",
        )?;
        ensure_non_empty(
            &self.private_event_root,
            "execution receipt private event root",
        )?;
        ensure_non_empty(&self.nullifier_root, "execution receipt nullifier root")?;
        ensure_non_empty(&self.receipt_root, "execution receipt root")?;
        if self.gas_used == 0 || self.executed_height == 0 {
            return Err("execution receipt gas and height must be positive".to_string());
        }
        let expected = cross_rollup_executor_payload_root(
            "EXECUTION-RECEIPT-ROOT",
            &self.public_record_without_root(),
        );
        if self.receipt_root != expected {
            return Err("execution receipt root mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackCheckpoint {
    pub checkpoint_id: String,
    pub receipt_id: String,
    pub rollup_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub rollback_state_root: String,
    pub reorg_window_start: u64,
    pub reorg_window_end: u64,
    pub protected: bool,
}

impl RollbackCheckpoint {
    pub fn new(receipt: &ExecutionReceipt, rollup_id: &str, reorg_depth: u64) -> Self {
        let checkpoint_id =
            cross_rollup_executor_id("ROLLBACK-CHECKPOINT", &[&receipt.receipt_id, rollup_id]);
        Self {
            checkpoint_id: checkpoint_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            rollup_id: rollup_id.to_string(),
            pre_state_root: receipt.target_rollup_state_before.clone(),
            post_state_root: receipt.target_rollup_state_after.clone(),
            rollback_state_root: cross_rollup_executor_id("ROLLBACK-STATE", &[&checkpoint_id]),
            reorg_window_start: receipt.executed_height,
            reorg_window_end: receipt.executed_height.saturating_add(reorg_depth),
            protected: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "receipt_id": self.receipt_id,
            "rollup_id": self.rollup_id,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "rollback_state_root": self.rollback_state_root,
            "reorg_window_start": self.reorg_window_start,
            "reorg_window_end": self.reorg_window_end,
            "protected": self.protected,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("ROLLBACK-CHECKPOINT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.checkpoint_id, "rollback checkpoint id")?;
        ensure_non_empty(&self.receipt_id, "rollback checkpoint receipt id")?;
        ensure_non_empty(&self.rollup_id, "rollback checkpoint rollup id")?;
        ensure_non_empty(&self.pre_state_root, "rollback checkpoint pre state")?;
        ensure_non_empty(&self.post_state_root, "rollback checkpoint post state")?;
        ensure_non_empty(
            &self.rollback_state_root,
            "rollback checkpoint rollback state",
        )?;
        if self.reorg_window_start == 0 || self.reorg_window_end <= self.reorg_window_start {
            return Err("rollback checkpoint reorg window must be ordered".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorPolicy {
    pub sponsor_policy_id: String,
    pub sponsor_commitment: String,
    pub accepted_lanes: BTreeSet<CrossRollupExecutionLane>,
    pub accepted_rollups: BTreeSet<String>,
    pub remaining_budget_micro_xmr: u64,
    pub max_per_call_micro_xmr: u64,
    pub discount_bps: u64,
    pub privacy_label_root: String,
    pub active: bool,
}

impl FeeSponsorPolicy {
    pub fn devnet(sponsor_commitment: &str, accepted_rollups: BTreeSet<String>) -> Self {
        let sponsor_policy_id =
            cross_rollup_executor_id("FEE-SPONSOR-POLICY", &[sponsor_commitment]);
        let accepted_lanes = [
            CrossRollupExecutionLane::DefiSwap,
            CrossRollupExecutionLane::Lending,
            CrossRollupExecutionLane::Stablecoin,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        Self {
            sponsor_policy_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            accepted_lanes,
            accepted_rollups,
            remaining_budget_micro_xmr:
                PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEFAULT_SPONSOR_BUDGET_MICRO_XMR,
            max_per_call_micro_xmr: 160,
            discount_bps: 7_500,
            privacy_label_root: cross_rollup_executor_id(
                "SPONSOR-PRIVACY-LABEL",
                &[sponsor_commitment],
            ),
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_policy_id": self.sponsor_policy_id,
            "sponsor_commitment": self.sponsor_commitment,
            "accepted_lanes": self.accepted_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "accepted_rollups": self.accepted_rollups.iter().cloned().collect::<Vec<_>>(),
            "remaining_budget_micro_xmr": self.remaining_budget_micro_xmr,
            "max_per_call_micro_xmr": self.max_per_call_micro_xmr,
            "discount_bps": self.discount_bps,
            "privacy_label_root": self.privacy_label_root,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("FEE-SPONSOR-POLICY", &self.public_record())
    }

    pub fn can_sponsor(&self, lane: CrossRollupExecutionLane, rollup_id: &str, fee: u64) -> bool {
        self.active
            && self.accepted_lanes.contains(&lane)
            && self.accepted_rollups.contains(rollup_id)
            && fee <= self.max_per_call_micro_xmr
            && fee <= self.remaining_budget_micro_xmr
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.sponsor_policy_id, "fee sponsor policy id")?;
        ensure_non_empty(&self.sponsor_commitment, "fee sponsor commitment")?;
        ensure_non_empty(&self.privacy_label_root, "fee sponsor privacy label root")?;
        if self.accepted_lanes.is_empty() || self.accepted_rollups.is_empty() {
            return Err("fee sponsor policy must accept lanes and rollups".to_string());
        }
        if self.max_per_call_micro_xmr == 0 {
            return Err("fee sponsor max per call must be positive".to_string());
        }
        if self.discount_bps > PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_MAX_BPS {
            return Err("fee sponsor discount exceeds max bps".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementProof {
    pub settlement_proof_id: String,
    pub receipt_id: String,
    pub status: SettlementProofStatus,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub receipt_root: String,
    pub witness_bundle_root: String,
    pub pq_attestation_root: String,
    pub rollback_checkpoint_root: String,
    pub recursive_proof_root: String,
    pub settlement_transaction_root: String,
    pub submitted_height: u64,
    pub challenge_deadline_height: u64,
}

impl SettlementProof {
    pub fn new(
        receipt: &ExecutionReceipt,
        source_rollup_id: &str,
        target_rollup_id: &str,
        witness_bundle_root: &str,
        pq_attestation_root: &str,
        rollback_checkpoint_root: &str,
        submitted_height: u64,
    ) -> Self {
        let settlement_proof_id =
            cross_rollup_executor_id("SETTLEMENT-PROOF", &[&receipt.receipt_id]);
        Self {
            settlement_proof_id: settlement_proof_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            status: SettlementProofStatus::ReorgProtected,
            source_rollup_id: source_rollup_id.to_string(),
            target_rollup_id: target_rollup_id.to_string(),
            receipt_root: receipt.receipt_root.clone(),
            witness_bundle_root: witness_bundle_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            rollback_checkpoint_root: rollback_checkpoint_root.to_string(),
            recursive_proof_root: cross_rollup_executor_id(
                "RECURSIVE-SETTLEMENT-PROOF",
                &[&settlement_proof_id],
            ),
            settlement_transaction_root: cross_rollup_executor_id(
                "SETTLEMENT-TX",
                &[&settlement_proof_id],
            ),
            submitted_height,
            challenge_deadline_height: submitted_height.saturating_add(16),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_proof_id": self.settlement_proof_id,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "receipt_root": self.receipt_root,
            "witness_bundle_root": self.witness_bundle_root,
            "pq_attestation_root": self.pq_attestation_root,
            "rollback_checkpoint_root": self.rollback_checkpoint_root,
            "recursive_proof_root": self.recursive_proof_root,
            "settlement_transaction_root": self.settlement_transaction_root,
            "submitted_height": self.submitted_height,
            "challenge_deadline_height": self.challenge_deadline_height,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("SETTLEMENT-PROOF", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        ensure_non_empty(&self.settlement_proof_id, "settlement proof id")?;
        ensure_non_empty(&self.receipt_id, "settlement proof receipt id")?;
        ensure_non_empty(&self.source_rollup_id, "settlement proof source rollup")?;
        ensure_non_empty(&self.target_rollup_id, "settlement proof target rollup")?;
        ensure_non_empty(&self.receipt_root, "settlement proof receipt root")?;
        ensure_non_empty(&self.witness_bundle_root, "settlement proof witness root")?;
        ensure_non_empty(&self.pq_attestation_root, "settlement proof pq root")?;
        ensure_non_empty(
            &self.rollback_checkpoint_root,
            "settlement proof rollback checkpoint root",
        )?;
        ensure_non_empty(
            &self.recursive_proof_root,
            "settlement proof recursive root",
        )?;
        ensure_non_empty(
            &self.settlement_transaction_root,
            "settlement proof transaction root",
        )?;
        if self.submitted_height == 0 || self.challenge_deadline_height <= self.submitted_height {
            return Err("settlement proof challenge window must be ordered".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupExecutorCounters {
    pub rollups: u64,
    pub capability_scopes: u64,
    pub encrypted_calls: u64,
    pub live_calls: u64,
    pub witness_bundles: u64,
    pub pq_attestations: u64,
    pub ordering_tickets: u64,
    pub execution_receipts: u64,
    pub rollback_checkpoints: u64,
    pub sponsor_policies: u64,
    pub settlement_proofs: u64,
    pub sponsored_micro_xmr: u64,
    pub total_fee_micro_xmr: u64,
}

impl CrossRollupExecutorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "rollups": self.rollups,
            "capability_scopes": self.capability_scopes,
            "encrypted_calls": self.encrypted_calls,
            "live_calls": self.live_calls,
            "witness_bundles": self.witness_bundles,
            "pq_attestations": self.pq_attestations,
            "ordering_tickets": self.ordering_tickets,
            "execution_receipts": self.execution_receipts,
            "rollback_checkpoints": self.rollback_checkpoints,
            "sponsor_policies": self.sponsor_policies,
            "settlement_proofs": self.settlement_proofs,
            "sponsored_micro_xmr": self.sponsored_micro_xmr,
            "total_fee_micro_xmr": self.total_fee_micro_xmr,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupExecutorRoots {
    pub config_root: String,
    pub rollup_root: String,
    pub capability_root: String,
    pub encrypted_call_root: String,
    pub witness_bundle_root: String,
    pub pq_attestation_root: String,
    pub ordering_ticket_root: String,
    pub execution_receipt_root: String,
    pub rollback_checkpoint_root: String,
    pub sponsor_policy_root: String,
    pub settlement_proof_root: String,
    pub counters_root: String,
}

impl CrossRollupExecutorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "rollup_root": self.rollup_root,
            "capability_root": self.capability_root,
            "encrypted_call_root": self.encrypted_call_root,
            "witness_bundle_root": self.witness_bundle_root,
            "pq_attestation_root": self.pq_attestation_root,
            "ordering_ticket_root": self.ordering_ticket_root,
            "execution_receipt_root": self.execution_receipt_root,
            "rollback_checkpoint_root": self.rollback_checkpoint_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "settlement_proof_root": self.settlement_proof_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn root(&self) -> String {
        cross_rollup_executor_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCrossRollupExecutorState {
    pub config: CrossRollupExecutorConfig,
    pub rollups: BTreeMap<String, RollupEndpoint>,
    pub capability_scopes: BTreeMap<String, CapabilityScope>,
    pub encrypted_calls: BTreeMap<String, EncryptedCallEnvelope>,
    pub witness_bundles: BTreeMap<String, WitnessBundle>,
    pub pq_attestations: BTreeMap<String, PqExecutionAttestation>,
    pub ordering_tickets: BTreeMap<String, OrderingTicket>,
    pub execution_receipts: BTreeMap<String, ExecutionReceipt>,
    pub rollback_checkpoints: BTreeMap<String, RollbackCheckpoint>,
    pub sponsor_policies: BTreeMap<String, FeeSponsorPolicy>,
    pub settlement_proofs: BTreeMap<String, SettlementProof>,
    pub blocked_nullifiers: BTreeSet<String>,
    pub reorg_guard_roots: BTreeSet<String>,
}

impl PrivateContractCrossRollupExecutorState {
    pub fn new(
        config: CrossRollupExecutorConfig,
    ) -> PrivateContractCrossRollupExecutorResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            rollups: BTreeMap::new(),
            capability_scopes: BTreeMap::new(),
            encrypted_calls: BTreeMap::new(),
            witness_bundles: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            ordering_tickets: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            rollback_checkpoints: BTreeMap::new(),
            sponsor_policies: BTreeMap::new(),
            settlement_proofs: BTreeMap::new(),
            blocked_nullifiers: BTreeSet::new(),
            reorg_guard_roots: BTreeSet::new(),
        })
    }

    pub fn devnet() -> PrivateContractCrossRollupExecutorResult<Self> {
        let mut state = Self::new(CrossRollupExecutorConfig::devnet())?;
        let rollup_a = RollupEndpoint::devnet(
            "nebula-alpha",
            "alpha.private.defi",
            &[
                CrossRollupExecutionLane::DefiSwap,
                CrossRollupExecutionLane::Lending,
                CrossRollupExecutionLane::Stablecoin,
                CrossRollupExecutionLane::BridgeSettlement,
            ],
            PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT,
        );
        let rollup_b = RollupEndpoint::devnet(
            "nebula-beta",
            "beta.private.perps",
            &[
                CrossRollupExecutionLane::DefiSwap,
                CrossRollupExecutionLane::Perps,
                CrossRollupExecutionLane::OracleUpdate,
                CrossRollupExecutionLane::BridgeSettlement,
            ],
            PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT.saturating_sub(1),
        );
        let rollup_c = RollupEndpoint::devnet(
            "nebula-gamma",
            "gamma.private.credit",
            &[
                CrossRollupExecutionLane::Lending,
                CrossRollupExecutionLane::Stablecoin,
                CrossRollupExecutionLane::Governance,
                CrossRollupExecutionLane::EmergencyRecovery,
            ],
            PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT.saturating_sub(2),
        );
        state.register_rollup(rollup_a.clone())?;
        state.register_rollup(rollup_b.clone())?;
        state.register_rollup(rollup_c.clone())?;

        let target_rollups = [rollup_b.rollup_id.clone(), rollup_c.rollup_id.clone()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let allowed_kinds = [
            CapabilityScopeKind::ReadPrivateState,
            CapabilityScopeKind::WritePrivateState,
            CapabilityScopeKind::SpendShieldedBalance,
            CapabilityScopeKind::CrossRollupDispatch,
            CapabilityScopeKind::SponsorFee,
            CapabilityScopeKind::SettlementSubmit,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let capability = CapabilityScope::new(
            "holder:devnet-liquidity-vault",
            "contract:private-cross-rollup-amm",
            &rollup_a.rollup_id,
            target_rollups,
            allowed_kinds,
            PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT.saturating_add(128),
            1,
        );
        state.register_capability_scope(capability.clone())?;

        let sponsor_rollups = [
            rollup_a.rollup_id.clone(),
            rollup_b.rollup_id.clone(),
            rollup_c.rollup_id.clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let sponsor = FeeSponsorPolicy::devnet("sponsor:devnet-low-fee-pool", sponsor_rollups);
        state.register_sponsor_policy(sponsor.clone())?;

        let call = EncryptedCallEnvelope::new(
            CrossRollupExecutionLane::DefiSwap,
            &rollup_a.rollup_id,
            &rollup_b.rollup_id,
            "sender:shielded-trader-7",
            "contract:private-cross-rollup-amm",
            &capability.scope_id,
            PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT,
            7,
        )
        .with_sponsor(&sponsor.sponsor_policy_id, 120);
        let call_id = call.call_id.clone();
        state.submit_encrypted_call(call)?;
        state.attach_witness_bundle(WitnessBundle::new(
            &call_id,
            ["witness:alpha", "witness:beta", "witness:gamma"]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>(),
            PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT.saturating_add(1),
        ))?;
        state.attach_pq_attestation(PqExecutionAttestation::new(
            &call_id,
            "pq-attester:committee-1",
            PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT.saturating_add(1),
        ))?;
        let ticket = state.issue_ordering_ticket(&call_id, "sequencer:fast-pq-1", 1)?;
        let receipt = state.execute_ordered_call(&call_id, &ticket.ticket_id)?;
        state.create_settlement_proof(&receipt.receipt_id)?;
        state.validate()?;
        Ok(state)
    }

    pub fn register_rollup(
        &mut self,
        rollup: RollupEndpoint,
    ) -> PrivateContractCrossRollupExecutorResult<String> {
        let root = rollup.validate()?;
        self.rollups.insert(rollup.rollup_id.clone(), rollup);
        Ok(root)
    }

    pub fn register_capability_scope(
        &mut self,
        scope: CapabilityScope,
    ) -> PrivateContractCrossRollupExecutorResult<String> {
        let root = scope.validate()?;
        if !self.rollups.contains_key(&scope.source_rollup_id) {
            return Err("capability source rollup is not registered".to_string());
        }
        for target in &scope.target_rollup_ids {
            if !self.rollups.contains_key(target) {
                return Err("capability target rollup is not registered".to_string());
            }
        }
        self.capability_scopes.insert(scope.scope_id.clone(), scope);
        Ok(root)
    }

    pub fn register_sponsor_policy(
        &mut self,
        policy: FeeSponsorPolicy,
    ) -> PrivateContractCrossRollupExecutorResult<String> {
        let root = policy.validate()?;
        for rollup_id in &policy.accepted_rollups {
            if !self.rollups.contains_key(rollup_id) {
                return Err("fee sponsor accepts an unknown rollup".to_string());
            }
        }
        self.sponsor_policies
            .insert(policy.sponsor_policy_id.clone(), policy);
        Ok(root)
    }

    pub fn submit_encrypted_call(
        &mut self,
        call: EncryptedCallEnvelope,
    ) -> PrivateContractCrossRollupExecutorResult<String> {
        let root = call.validate()?;
        if self.blocked_nullifiers.contains(&call.nullifier_root) {
            return Err("encrypted call nullifier has been blocked".to_string());
        }
        let source = self
            .rollups
            .get(&call.source_rollup_id)
            .ok_or_else(|| "encrypted call source rollup is unknown".to_string())?;
        let target = self
            .rollups
            .get(&call.target_rollup_id)
            .ok_or_else(|| "encrypted call target rollup is unknown".to_string())?;
        if !source.supported_lanes.contains(&call.lane)
            || !target.supported_lanes.contains(&call.lane)
        {
            return Err("encrypted call lane is not supported by both rollups".to_string());
        }
        let capability = self
            .capability_scopes
            .get(&call.capability_scope_id)
            .ok_or_else(|| "encrypted call capability scope is unknown".to_string())?;
        if !capability.grants(
            CapabilityScopeKind::CrossRollupDispatch,
            &call.target_rollup_id,
            call.created_height,
        ) {
            return Err(
                "encrypted call capability does not grant cross-rollup dispatch".to_string(),
            );
        }
        if let Some(policy_id) = &call.sponsor_policy_id {
            let policy = self
                .sponsor_policies
                .get(policy_id)
                .ok_or_else(|| "encrypted call sponsor policy is unknown".to_string())?;
            if !policy.can_sponsor(call.lane, &call.target_rollup_id, call.max_fee_micro_xmr) {
                return Err("encrypted call sponsor policy cannot cover call".to_string());
            }
        }
        self.encrypted_calls.insert(call.call_id.clone(), call);
        Ok(root)
    }

    pub fn attach_witness_bundle(
        &mut self,
        bundle: WitnessBundle,
    ) -> PrivateContractCrossRollupExecutorResult<String> {
        let root = bundle.validate()?;
        let call = self
            .encrypted_calls
            .get_mut(&bundle.call_id)
            .ok_or_else(|| "witness bundle references an unknown call".to_string())?;
        call.status = EncryptedCallStatus::Witnessed;
        self.witness_bundles
            .insert(bundle.bundle_id.clone(), bundle);
        Ok(root)
    }

    pub fn attach_pq_attestation(
        &mut self,
        attestation: PqExecutionAttestation,
    ) -> PrivateContractCrossRollupExecutorResult<String> {
        let root = attestation.validate()?;
        if !self.encrypted_calls.contains_key(&attestation.call_id) {
            return Err("pq attestation references an unknown call".to_string());
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(root)
    }

    pub fn issue_ordering_ticket(
        &mut self,
        call_id: &str,
        sequencer_id: &str,
        sequence_number: u64,
    ) -> PrivateContractCrossRollupExecutorResult<OrderingTicket> {
        let call = self
            .encrypted_calls
            .get(call_id)
            .ok_or_else(|| "ordering ticket call is unknown".to_string())?;
        let ticket = OrderingTicket::new(call, sequencer_id, sequence_number);
        ticket.validate()?;
        if let Some(call) = self.encrypted_calls.get_mut(call_id) {
            call.status = EncryptedCallStatus::Ordered;
        }
        self.ordering_tickets
            .insert(ticket.ticket_id.clone(), ticket.clone());
        Ok(ticket)
    }

    pub fn execute_ordered_call(
        &mut self,
        call_id: &str,
        ticket_id: &str,
    ) -> PrivateContractCrossRollupExecutorResult<ExecutionReceipt> {
        let call = self
            .encrypted_calls
            .get(call_id)
            .ok_or_else(|| "execution call is unknown".to_string())?
            .clone();
        let ticket = self
            .ordering_tickets
            .get(ticket_id)
            .ok_or_else(|| "execution ordering ticket is unknown".to_string())?
            .clone();
        if ticket.call_id != call.call_id {
            return Err("execution ticket does not belong to call".to_string());
        }
        if !self
            .witness_bundles
            .values()
            .any(|bundle| bundle.call_id == call.call_id && bundle.status.usable())
        {
            return Err("execution requires a usable witness bundle".to_string());
        }
        if !self
            .pq_attestations
            .values()
            .any(|attestation| attestation.call_id == call.call_id && attestation.status.trusted())
        {
            return Err("execution requires a trusted pq attestation".to_string());
        }
        let source_state = self
            .rollups
            .get(&call.source_rollup_id)
            .map(|rollup| rollup.state_root.clone())
            .ok_or_else(|| "execution source rollup is unknown".to_string())?;
        let target_state = self
            .rollups
            .get(&call.target_rollup_id)
            .map(|rollup| rollup.state_root.clone())
            .ok_or_else(|| "execution target rollup is unknown".to_string())?;
        let receipt = ExecutionReceipt::new(
            &call,
            &ticket,
            &source_state,
            &target_state,
            ticket.reserved_height.saturating_add(1),
        );
        receipt.validate()?;
        if let Some(source) = self.rollups.get_mut(&call.source_rollup_id) {
            source.state_root = receipt.source_rollup_state_after.clone();
            source.latest_height = source.latest_height.saturating_add(1);
        }
        if let Some(target) = self.rollups.get_mut(&call.target_rollup_id) {
            target.state_root = receipt.target_rollup_state_after.clone();
            target.latest_height = target.latest_height.saturating_add(1);
        }
        if let Some(call) = self.encrypted_calls.get_mut(call_id) {
            call.status = EncryptedCallStatus::Receipted;
        }
        if let Some(policy_id) = &call.sponsor_policy_id {
            if let Some(policy) = self.sponsor_policies.get_mut(policy_id) {
                policy.remaining_budget_micro_xmr = policy
                    .remaining_budget_micro_xmr
                    .saturating_sub(receipt.sponsored_micro_xmr);
            }
        }
        let checkpoint =
            RollbackCheckpoint::new(&receipt, &call.target_rollup_id, self.config.reorg_depth);
        checkpoint.validate()?;
        self.reorg_guard_roots
            .insert(checkpoint.rollback_state_root.clone());
        self.rollback_checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint);
        self.blocked_nullifiers.insert(call.nullifier_root.clone());
        self.execution_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn create_settlement_proof(
        &mut self,
        receipt_id: &str,
    ) -> PrivateContractCrossRollupExecutorResult<SettlementProof> {
        let receipt = self
            .execution_receipts
            .get(receipt_id)
            .ok_or_else(|| "settlement receipt is unknown".to_string())?
            .clone();
        let call = self
            .encrypted_calls
            .get(&receipt.call_id)
            .ok_or_else(|| "settlement call is unknown".to_string())?
            .clone();
        let witness_root = self
            .witness_bundles
            .values()
            .find(|bundle| bundle.call_id == call.call_id)
            .map(WitnessBundle::root)
            .ok_or_else(|| "settlement witness bundle is missing".to_string())?;
        let pq_root = self
            .pq_attestations
            .values()
            .find(|attestation| attestation.call_id == call.call_id)
            .map(PqExecutionAttestation::root)
            .ok_or_else(|| "settlement pq attestation is missing".to_string())?;
        let rollback_root = self
            .rollback_checkpoints
            .values()
            .find(|checkpoint| checkpoint.receipt_id == receipt.receipt_id)
            .map(RollbackCheckpoint::root)
            .ok_or_else(|| "settlement rollback checkpoint is missing".to_string())?;
        let proof = SettlementProof::new(
            &receipt,
            &call.source_rollup_id,
            &call.target_rollup_id,
            &witness_root,
            &pq_root,
            &rollback_root,
            receipt
                .executed_height
                .saturating_add(self.config.reorg_depth),
        );
        proof.validate()?;
        if let Some(call) = self.encrypted_calls.get_mut(&receipt.call_id) {
            call.status = EncryptedCallStatus::Settled;
        }
        self.settlement_proofs
            .insert(proof.settlement_proof_id.clone(), proof.clone());
        Ok(proof)
    }

    pub fn counters(&self) -> CrossRollupExecutorCounters {
        CrossRollupExecutorCounters {
            rollups: self.rollups.len() as u64,
            capability_scopes: self.capability_scopes.len() as u64,
            encrypted_calls: self.encrypted_calls.len() as u64,
            live_calls: self
                .encrypted_calls
                .values()
                .filter(|call| call.status.live())
                .count() as u64,
            witness_bundles: self.witness_bundles.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            ordering_tickets: self.ordering_tickets.len() as u64,
            execution_receipts: self.execution_receipts.len() as u64,
            rollback_checkpoints: self.rollback_checkpoints.len() as u64,
            sponsor_policies: self.sponsor_policies.len() as u64,
            settlement_proofs: self.settlement_proofs.len() as u64,
            sponsored_micro_xmr: self
                .execution_receipts
                .values()
                .map(|receipt| receipt.sponsored_micro_xmr)
                .sum(),
            total_fee_micro_xmr: self
                .execution_receipts
                .values()
                .map(|receipt| receipt.fee_paid_micro_xmr)
                .sum(),
        }
    }

    pub fn roots(&self) -> CrossRollupExecutorRoots {
        CrossRollupExecutorRoots {
            config_root: self.config.root(),
            rollup_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-ROLLUPS",
                &self
                    .rollups
                    .values()
                    .map(RollupEndpoint::public_record)
                    .collect::<Vec<_>>(),
            ),
            capability_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-CAPABILITIES",
                &self
                    .capability_scopes
                    .values()
                    .map(CapabilityScope::public_record)
                    .collect::<Vec<_>>(),
            ),
            encrypted_call_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-CALLS",
                &self
                    .encrypted_calls
                    .values()
                    .map(EncryptedCallEnvelope::public_record)
                    .collect::<Vec<_>>(),
            ),
            witness_bundle_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-WITNESSES",
                &self
                    .witness_bundles
                    .values()
                    .map(WitnessBundle::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-PQ-ATTESTATIONS",
                &self
                    .pq_attestations
                    .values()
                    .map(PqExecutionAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            ordering_ticket_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-ORDERING",
                &self
                    .ordering_tickets
                    .values()
                    .map(OrderingTicket::public_record)
                    .collect::<Vec<_>>(),
            ),
            execution_receipt_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-RECEIPTS",
                &self
                    .execution_receipts
                    .values()
                    .map(ExecutionReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            rollback_checkpoint_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-ROLLBACKS",
                &self
                    .rollback_checkpoints
                    .values()
                    .map(RollbackCheckpoint::public_record)
                    .collect::<Vec<_>>(),
            ),
            sponsor_policy_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-SPONSORS",
                &self
                    .sponsor_policies
                    .values()
                    .map(FeeSponsorPolicy::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_proof_root: merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-SETTLEMENTS",
                &self
                    .settlement_proofs
                    .values()
                    .map(SettlementProof::public_record)
                    .collect::<Vec<_>>(),
            ),
            counters_root: self.counters().root(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_contract_cross_rollup_executor_state",
            "protocol_label": PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_PROTOCOL_LABEL,
            "devnet_height": PRIVATE_CONTRACT_CROSS_ROLLUP_EXECUTOR_DEVNET_HEIGHT,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "blocked_nullifier_root": merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-BLOCKED-NULLIFIERS",
                &self.blocked_nullifiers.iter().cloned().map(Value::String).collect::<Vec<_>>(),
            ),
            "reorg_guard_root": merkle_root(
                "PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-REORG-GUARDS",
                &self.reorg_guard_roots.iter().cloned().map(Value::String).collect::<Vec<_>>(),
            ),
            "state_components_root": roots.root(),
        })
    }

    pub fn state_root(&self) -> String {
        cross_rollup_executor_payload_root("STATE", &self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateContractCrossRollupExecutorResult<String> {
        self.config.validate()?;
        for rollup in self.rollups.values() {
            rollup.validate()?;
        }
        for scope in self.capability_scopes.values() {
            scope.validate()?;
            if !self.rollups.contains_key(&scope.source_rollup_id) {
                return Err("state contains capability with unknown source rollup".to_string());
            }
            for target in &scope.target_rollup_ids {
                if !self.rollups.contains_key(target) {
                    return Err("state contains capability with unknown target rollup".to_string());
                }
            }
        }
        for call in self.encrypted_calls.values() {
            call.validate()?;
            if !self.rollups.contains_key(&call.source_rollup_id)
                || !self.rollups.contains_key(&call.target_rollup_id)
            {
                return Err("state contains call with unknown rollup".to_string());
            }
            if !self
                .capability_scopes
                .contains_key(&call.capability_scope_id)
            {
                return Err("state contains call with unknown capability scope".to_string());
            }
        }
        for bundle in self.witness_bundles.values() {
            bundle.validate()?;
            if !self.encrypted_calls.contains_key(&bundle.call_id) {
                return Err("state contains witness for unknown call".to_string());
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
            if !self.encrypted_calls.contains_key(&attestation.call_id) {
                return Err("state contains pq attestation for unknown call".to_string());
            }
        }
        for ticket in self.ordering_tickets.values() {
            ticket.validate()?;
            if !self.encrypted_calls.contains_key(&ticket.call_id) {
                return Err("state contains ordering ticket for unknown call".to_string());
            }
        }
        for receipt in self.execution_receipts.values() {
            receipt.validate()?;
            if !self.encrypted_calls.contains_key(&receipt.call_id) {
                return Err("state contains receipt for unknown call".to_string());
            }
            if !self.ordering_tickets.contains_key(&receipt.ticket_id) {
                return Err("state contains receipt for unknown ordering ticket".to_string());
            }
        }
        for checkpoint in self.rollback_checkpoints.values() {
            checkpoint.validate()?;
            if !self.execution_receipts.contains_key(&checkpoint.receipt_id) {
                return Err("state contains rollback checkpoint for unknown receipt".to_string());
            }
            if !self
                .reorg_guard_roots
                .contains(&checkpoint.rollback_state_root)
            {
                return Err("state rollback checkpoint is missing reorg guard".to_string());
            }
        }
        for policy in self.sponsor_policies.values() {
            policy.validate()?;
        }
        for proof in self.settlement_proofs.values() {
            proof.validate()?;
            if !self.execution_receipts.contains_key(&proof.receipt_id) {
                return Err("state contains settlement proof for unknown receipt".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn cross_rollup_executor_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn cross_rollup_executor_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-CONTRACT-CROSS-ROLLUP-EXECUTOR-ID-{domain}"),
        &hash_parts,
        32,
    )
}

pub fn private_contract_cross_rollup_executor_devnet_state(
) -> PrivateContractCrossRollupExecutorResult<PrivateContractCrossRollupExecutorState> {
    PrivateContractCrossRollupExecutorState::devnet()
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateContractCrossRollupExecutorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be populated"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_settlement() -> PrivateContractCrossRollupExecutorResult<()> {
        let state = PrivateContractCrossRollupExecutorState::devnet()?;
        assert_eq!(state.counters().rollups, 3);
        assert_eq!(state.counters().settlement_proofs, 1);
        state.validate()?;
        Ok(())
    }

    #[test]
    fn capability_blocks_unknown_target() -> PrivateContractCrossRollupExecutorResult<()> {
        let mut state =
            PrivateContractCrossRollupExecutorState::new(CrossRollupExecutorConfig::devnet())?;
        let rollup = RollupEndpoint::devnet(
            "only",
            "only.private",
            &[CrossRollupExecutionLane::DefiSwap],
            10,
        );
        let source_id = rollup.rollup_id.clone();
        state.register_rollup(rollup)?;
        let scope = CapabilityScope::new(
            "holder",
            "contract",
            &source_id,
            ["missing-rollup".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            [CapabilityScopeKind::CrossRollupDispatch]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            20,
            1,
        );
        assert!(state.register_capability_scope(scope).is_err());
        Ok(())
    }
}
