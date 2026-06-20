use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-cross-contract-state-oracle-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-cross-contract-state-oracle-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+Poseidon2-transcript+AEAD-confidential-state-query-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEVNET_HEIGHT: u64 =
    1_008_000;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_SOURCES: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_QUERIES: usize =
    33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_WITNESSES: usize =
    33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_REBATES: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_NULLIFIERS:
    usize = 67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_BATCH_QUERIES:
    usize = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    65_536;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    u64 = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_ORACLE_FEE_BPS:
    u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS:
    u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 5;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_SOURCE_TTL_BLOCKS:
    u64 = 86_400;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_QUERY_TTL_BLOCKS:
    u64 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS:
    u64 = 64;
pub const PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateOracleDomain {
    Dex,
    Lending,
    Perpetuals,
    Bridge,
    Governance,
    TokenRegistry,
    AccountAbstraction,
    CrossRollup,
    Custom,
}

impl StateOracleDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::TokenRegistry => "token_registry",
            Self::AccountAbstraction => "account_abstraction",
            Self::CrossRollup => "cross_rollup",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Proposed,
    Active,
    Paused,
    Draining,
    Retired,
}

impl SourceStatus {
    pub fn accepts_queries(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    StorageSlot,
    EventCursor,
    ReceiptInclusion,
    ContractBalance,
    TokenSupply,
    RiskMetric,
    BridgeReserve,
    GovernanceEpoch,
    Composite,
}

impl QueryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StorageSlot => "storage_slot",
            Self::EventCursor => "event_cursor",
            Self::ReceiptInclusion => "receipt_inclusion",
            Self::ContractBalance => "contract_balance",
            Self::TokenSupply => "token_supply",
            Self::RiskMetric => "risk_metric",
            Self::BridgeReserve => "bridge_reserve",
            Self::GovernanceEpoch => "governance_epoch",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Encrypted,
    Attested,
    Sponsored,
    Batched,
    Fulfilled,
    Disputed,
    Expired,
    Cancelled,
}

impl QueryStatus {
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Attested | Self::Sponsored | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    MerkleStorage,
    ReceiptMerkle,
    SparseState,
    VerkleTransition,
    RecursiveBatch,
    CrossContractRead,
    CrossRollupMessage,
    MoneroBridgeReserve,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqOracleKey,
    SourceRoot,
    QueryWellFormedness,
    WitnessAvailability,
    ReplayFence,
    SponsorAuthorization,
    EmergencyPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWitnesses,
    Quarantined,
    Invalid,
    Revoked,
}

impl AttestationVerdict {
    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    Submitted,
    Verified,
    Batched,
    Delivered,
    Stale,
    Disputed,
}

impl WitnessStatus {
    pub fn can_settle(self) -> bool {
        matches!(self, Self::Verified | Self::Batched | Self::Delivered)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    BoundToQuery,
    Consumed,
    RebateQueued,
    Released,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleBatchStatus {
    Open,
    Sealed,
    Posted,
    Settled,
    PartiallySettled,
    Disputed,
    Expired,
}

impl OracleBatchStatus {
    pub fn anchors_state(self) -> bool {
        matches!(self, Self::Sealed | Self::Posted | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    QueryFulfillment,
    SourceRootUpdate,
    OracleCredit,
    SponsorSettlement,
    RebateCredit,
    DisputeResolution,
    CursorAdvance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToBatch,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierFenceStatus {
    Open,
    Locked,
    Spent,
    Disputed,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleLaneKind {
    FastRead,
    LowFeeBatch,
    RiskCritical,
    BridgeReserve,
    GovernanceCheckpoint,
    CrossRollupSync,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub devnet_height: u64,
    pub fee_asset_id: String,
    pub max_sources: usize,
    pub max_queries: usize,
    pub max_attestations: usize,
    pub max_witnesses: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_nullifiers: usize,
    pub max_batch_queries: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_oracle_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub source_ttl_blocks: u64,
    pub query_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub encryption_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_SCHEMA_VERSION,
            devnet_height:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEVNET_HEIGHT,
            fee_asset_id: "nebula-private-l2-oracle-fee-credit".to_string(),
            max_sources:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_SOURCES,
            max_queries:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_QUERIES,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_witnesses:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_WITNESSES,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_REBATES,
            max_nullifiers:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_batch_queries:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_BATCH_QUERIES,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_oracle_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_ORACLE_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            source_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_SOURCE_TTL_BLOCKS,
            query_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_QUERY_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            hash_suite:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_PQ_AUTH_SUITE.to_string(),
            encryption_suite:
                PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_ENCRYPTION_SUITE
                    .to_string(),
        }
    }

    pub fn policy_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "fee_asset_id": self.fee_asset_id,
            "limits": {
                "max_sources": self.max_sources,
                "max_queries": self.max_queries,
                "max_attestations": self.max_attestations,
                "max_witnesses": self.max_witnesses,
                "max_reservations": self.max_reservations,
                "max_batches": self.max_batches,
                "max_receipts": self.max_receipts,
                "max_rebates": self.max_rebates,
                "max_nullifiers": self.max_nullifiers,
                "max_batch_queries": self.max_batch_queries,
            },
            "privacy": {
                "min_privacy_set_size": self.min_privacy_set_size,
                "batch_privacy_set_size": self.batch_privacy_set_size,
                "min_pq_security_bits": self.min_pq_security_bits,
            },
            "fees": {
                "max_oracle_fee_bps": self.max_oracle_fee_bps,
                "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
                "target_rebate_bps": self.target_rebate_bps,
            },
            "ttls": {
                "source_ttl_blocks": self.source_ttl_blocks,
                "query_ttl_blocks": self.query_ttl_blocks,
                "batch_ttl_blocks": self.batch_ttl_blocks,
                "reservation_ttl_blocks": self.reservation_ttl_blocks,
            },
            "suites": {
                "hash_suite": self.hash_suite,
                "pq_auth_suite": self.pq_auth_suite,
                "encryption_suite": self.encryption_suite,
            },
        })
    }

    pub fn policy_root(&self) -> String {
        payload_root("cross-contract-state-oracle:config", &self.policy_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub source_count: u64,
    pub query_count: u64,
    pub attestation_count: u64,
    pub witness_count: u64,
    pub reservation_count: u64,
    pub batch_count: u64,
    pub receipt_count: u64,
    pub rebate_count: u64,
    pub nullifier_count: u64,
    pub lane_metric_count: u64,
    pub root_update_count: u64,
    pub total_reserved_fee: u128,
    pub total_settled_fee: u128,
    pub total_rebate_amount: u128,
}

impl Counters {
    pub fn record(&self) -> Value {
        json!({
            "source_count": self.source_count,
            "query_count": self.query_count,
            "attestation_count": self.attestation_count,
            "witness_count": self.witness_count,
            "reservation_count": self.reservation_count,
            "batch_count": self.batch_count,
            "receipt_count": self.receipt_count,
            "rebate_count": self.rebate_count,
            "nullifier_count": self.nullifier_count,
            "lane_metric_count": self.lane_metric_count,
            "root_update_count": self.root_update_count,
            "total_reserved_fee": self.total_reserved_fee.to_string(),
            "total_settled_fee": self.total_settled_fee.to_string(),
            "total_rebate_amount": self.total_rebate_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub source_root: String,
    pub query_root: String,
    pub attestation_root: String,
    pub witness_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub lane_metric_root: String,
    pub root_update_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "source_root": self.source_root,
            "query_root": self.query_root,
            "attestation_root": self.attestation_root,
            "witness_root": self.witness_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "lane_metric_root": self.lane_metric_root,
            "root_update_root": self.root_update_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "source_root": self.source_root,
            "query_root": self.query_root,
            "attestation_root": self.attestation_root,
            "witness_root": self.witness_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "lane_metric_root": self.lane_metric_root,
            "root_update_root": self.root_update_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractStateSource {
    pub source_id: String,
    pub domain: StateOracleDomain,
    pub contract_commitment: String,
    pub runtime_commitment: String,
    pub state_schema_commitment: String,
    pub authorized_reader_root: String,
    pub oracle_committee_root: String,
    pub latest_state_root: String,
    pub latest_receipt_root: String,
    pub status: SourceStatus,
    pub min_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: String,
}

impl ContractStateSource {
    pub fn record(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "domain": self.domain,
            "contract_commitment": self.contract_commitment,
            "runtime_commitment": self.runtime_commitment,
            "state_schema_commitment": self.state_schema_commitment,
            "authorized_reader_root": self.authorized_reader_root,
            "oracle_committee_root": self.oracle_committee_root,
            "latest_state_root": self.latest_state_root,
            "latest_receipt_root": self.latest_receipt_root,
            "status": self.status,
            "min_confirmations": self.min_confirmations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "fee_bps": self.fee_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_commitment": self.metadata_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateQuery {
    pub query_id: String,
    pub source_id: String,
    pub requester_commitment: String,
    pub query_kind: QueryKind,
    pub encrypted_query_payload: String,
    pub query_key_commitment: String,
    pub response_key_commitment: String,
    pub access_policy_root: String,
    pub requested_state_root: String,
    pub nullifier: String,
    pub status: QueryStatus,
    pub max_fee_amount: u128,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedStateQuery {
    pub fn record(&self) -> Value {
        json!({
            "query_id": self.query_id,
            "source_id": self.source_id,
            "requester_commitment": self.requester_commitment,
            "query_kind": self.query_kind,
            "encrypted_query_payload": self.encrypted_query_payload,
            "query_key_commitment": self.query_key_commitment,
            "response_key_commitment": self.response_key_commitment,
            "access_policy_root": self.access_policy_root,
            "requested_state_root": self.requested_state_root,
            "nullifier": self.nullifier,
            "status": self.status,
            "max_fee_amount": self.max_fee_amount.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryAttestation {
    pub attestation_id: String,
    pub source_id: String,
    pub query_id: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub attester_commitment: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub pq_signature_commitment: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl QueryAttestation {
    pub fn record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "source_id": self.source_id,
            "query_id": self.query_id,
            "kind": self.kind,
            "verdict": self.verdict,
            "attester_commitment": self.attester_commitment,
            "attestation_root": self.attestation_root,
            "transcript_root": self.transcript_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleWitness {
    pub witness_id: String,
    pub source_id: String,
    pub query_id: String,
    pub proof_kind: ProofKind,
    pub encrypted_witness_payload: String,
    pub witness_root: String,
    pub source_state_root: String,
    pub receipt_root: String,
    pub verifier_transcript_root: String,
    pub status: WitnessStatus,
    pub privacy_set_size: u64,
    pub observed_at_height: u64,
}

impl OracleWitness {
    pub fn record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "source_id": self.source_id,
            "query_id": self.query_id,
            "proof_kind": self.proof_kind,
            "encrypted_witness_payload": self.encrypted_witness_payload,
            "witness_root": self.witness_root,
            "source_state_root": self.source_state_root,
            "receipt_root": self.receipt_root,
            "verifier_transcript_root": self.verifier_transcript_root,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub query_id: String,
    pub sponsor_commitment: String,
    pub requester_commitment: String,
    pub max_fee_amount: u128,
    pub reserved_fee_amount: u128,
    pub consumed_fee_amount: u128,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub sponsor_proof_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "query_id": self.query_id,
            "sponsor_commitment": self.sponsor_commitment,
            "requester_commitment": self.requester_commitment,
            "max_fee_amount": self.max_fee_amount.to_string(),
            "reserved_fee_amount": self.reserved_fee_amount.to_string(),
            "consumed_fee_amount": self.consumed_fee_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "sponsor_proof_root": self.sponsor_proof_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleBatch {
    pub batch_id: String,
    pub source_root: String,
    pub query_root: String,
    pub witness_root: String,
    pub attestation_root: String,
    pub reservation_root: String,
    pub oracle_committee_root: String,
    pub lane_id: String,
    pub status: OracleBatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub query_count: u64,
    pub max_fee_amount: u128,
    pub settlement_commitment: String,
}

impl OracleBatch {
    pub fn record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "source_root": self.source_root,
            "query_root": self.query_root,
            "witness_root": self.witness_root,
            "attestation_root": self.attestation_root,
            "reservation_root": self.reservation_root,
            "oracle_committee_root": self.oracle_committee_root,
            "lane_id": self.lane_id,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "query_count": self.query_count,
            "max_fee_amount": self.max_fee_amount.to_string(),
            "settlement_commitment": self.settlement_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub query_id: String,
    pub witness_id: String,
    pub reservation_id: String,
    pub kind: ReceiptKind,
    pub delivered_state_root: String,
    pub delivery_proof_root: String,
    pub fee_amount: u128,
    pub rebate_amount: u128,
    pub settled_at_height: u64,
}

impl DeliveryReceipt {
    pub fn record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "query_id": self.query_id,
            "witness_id": self.witness_id,
            "reservation_id": self.reservation_id,
            "kind": self.kind,
            "delivered_state_root": self.delivered_state_root,
            "delivery_proof_root": self.delivery_proof_root,
            "fee_amount": self.fee_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub reservation_id: String,
    pub claimant_commitment: String,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub claim_after_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_amount": self.rebate_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "claim_after_height": self.claim_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub query_id: String,
    pub source_id: String,
    pub fence_root: String,
    pub status: NullifierFenceStatus,
    pub locked_at_height: u64,
    pub released_at_height: u64,
}

impl NullifierFence {
    pub fn record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "query_id": self.query_id,
            "source_id": self.source_id,
            "fence_root": self.fence_root,
            "status": self.status,
            "locked_at_height": self.locked_at_height,
            "released_at_height": self.released_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneMetric {
    pub lane_id: String,
    pub lane_kind: OracleLaneKind,
    pub label: String,
    pub pending_query_count: u64,
    pub sealed_batch_count: u64,
    pub median_delivery_blocks: u64,
    pub target_fee_bps: u64,
    pub congestion_hint: u64,
    pub last_updated_height: u64,
}

impl LaneMetric {
    pub fn record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind,
            "label": self.label,
            "pending_query_count": self.pending_query_count,
            "sealed_batch_count": self.sealed_batch_count,
            "median_delivery_blocks": self.median_delivery_blocks,
            "target_fee_bps": self.target_fee_bps,
            "congestion_hint": self.congestion_hint,
            "last_updated_height": self.last_updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootUpdate {
    pub update_id: String,
    pub source_id: String,
    pub previous_state_root: String,
    pub next_state_root: String,
    pub receipt_root: String,
    pub attestation_root: String,
    pub observed_at_height: u64,
}

impl RootUpdate {
    pub fn record(&self) -> Value {
        json!({
            "update_id": self.update_id,
            "source_id": self.source_id,
            "previous_state_root": self.previous_state_root,
            "next_state_root": self.next_state_root,
            "receipt_root": self.receipt_root,
            "attestation_root": self.attestation_root,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sources: BTreeMap<String, ContractStateSource>,
    pub queries: BTreeMap<String, EncryptedStateQuery>,
    pub attestations: BTreeMap<String, QueryAttestation>,
    pub witnesses: BTreeMap<String, OracleWitness>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub batches: BTreeMap<String, OracleBatch>,
    pub receipts: BTreeMap<String, DeliveryReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub lane_metrics: BTreeMap<String, LaneMetric>,
    pub root_updates: BTreeMap<String, RootUpdate>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sources: BTreeMap::new(),
            queries: BTreeMap::new(),
            attestations: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            lane_metrics: BTreeMap::new(),
            root_updates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let height = state.config.devnet_height;
        let source_id =
            state_source_id("private-dex-v3", StateOracleDomain::Dex, "devnet-source-0");
        let latest_state_root = payload_root(
            "cross-contract-state-oracle:devnet:dex-state-root",
            &json!({"pool": "pXMR-pUSD", "tick": "devnet-encrypted-tick", "height": height - 8}),
        );
        let latest_receipt_root = payload_root(
            "cross-contract-state-oracle:devnet:dex-receipt-root",
            &json!({"pool": "pXMR-pUSD", "receipts": 8192, "height": height - 8}),
        );
        let source = ContractStateSource {
            source_id: source_id.clone(),
            domain: StateOracleDomain::Dex,
            contract_commitment: payload_root(
                "cross-contract-state-oracle:contract",
                &json!({"contract": "private-dex-v3", "address": "devnet-private-dex"}),
            ),
            runtime_commitment: payload_root(
                "cross-contract-state-oracle:runtime",
                &json!({"runtime": "confidential-amm+router", "version": 3}),
            ),
            state_schema_commitment: payload_root(
                "cross-contract-state-oracle:schema",
                &json!({"fields": ["pool_root", "tick_root", "liquidity_root", "fee_root"]}),
            ),
            authorized_reader_root: root_from_values(
                "cross-contract-state-oracle:readers",
                &[
                    "private-lending-v2",
                    "perps-margin-v4",
                    "bridge-risk-engine",
                ],
            ),
            oracle_committee_root: root_from_values(
                "cross-contract-state-oracle:committee",
                &["aurora-oracle", "cedar-oracle", "sable-oracle"],
            ),
            latest_state_root: latest_state_root.clone(),
            latest_receipt_root: latest_receipt_root.clone(),
            status: SourceStatus::Active,
            min_confirmations: 2,
            min_privacy_set_size: state.config.min_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            fee_bps: 4,
            created_at_height: height - 4_096,
            expires_at_height: height + state.config.source_ttl_blocks,
            metadata_commitment: payload_root(
                "cross-contract-state-oracle:metadata",
                &json!({"label": "private-dex-state-oracle", "sla_blocks": 3}),
            ),
        };
        state
            .register_source(source.clone())
            .expect("devnet source");

        let requester_commitment = payload_root(
            "cross-contract-state-oracle:requester",
            &json!({"contract": "private-lending-v2", "purpose": "collateral-factor"}),
        );
        let query_id = state_query_id(&source_id, &requester_commitment, QueryKind::RiskMetric, 7);
        let query = EncryptedStateQuery {
            query_id: query_id.clone(),
            source_id: source_id.clone(),
            requester_commitment: requester_commitment.clone(),
            query_kind: QueryKind::RiskMetric,
            encrypted_query_payload: payload_root(
                "cross-contract-state-oracle:encrypted-query",
                &json!({"ciphertext": "devnet-private-risk-query", "version": 1}),
            ),
            query_key_commitment: payload_root(
                "cross-contract-state-oracle:query-key",
                &json!({"key": "query-key-alpha", "suite": "ml-kem-1024"}),
            ),
            response_key_commitment: payload_root(
                "cross-contract-state-oracle:response-key",
                &json!({"key": "response-key-alpha", "suite": "ml-kem-1024"}),
            ),
            access_policy_root: payload_root(
                "cross-contract-state-oracle:access-policy",
                &json!({"reader": "private-lending-v2", "scope": "risk_metric"}),
            ),
            requested_state_root: latest_state_root.clone(),
            nullifier: query_nullifier(&source_id, &requester_commitment, 7),
            status: QueryStatus::Sponsored,
            max_fee_amount: 1_500_000,
            max_fee_bps: 4,
            privacy_set_size: state.config.min_privacy_set_size,
            created_at_height: height - 64,
            expires_at_height: height + state.config.query_ttl_blocks,
        };
        state.submit_query(query.clone()).expect("devnet query");

        let attestation = QueryAttestation {
            attestation_id: query_attestation_id(&source_id, &query_id, "source-root-valid"),
            source_id: source_id.clone(),
            query_id: query_id.clone(),
            kind: AttestationKind::SourceRoot,
            verdict: AttestationVerdict::Valid,
            attester_commitment: payload_root(
                "cross-contract-state-oracle:attester",
                &json!({"member": "aurora-oracle", "committee": "devnet-oracle-committee"}),
            ),
            attestation_root: payload_root(
                "cross-contract-state-oracle:attestation",
                &json!({"source_root": latest_state_root, "receipt_root": latest_receipt_root}),
            ),
            transcript_root: payload_root(
                "cross-contract-state-oracle:attestation-transcript",
                &json!({"query_id": query_id, "height": height - 6}),
            ),
            pq_signature_commitment: payload_root(
                "cross-contract-state-oracle:pq-signature",
                &json!({"suite": "ml-dsa-87", "signature": "devnet-oracle-signature-0"}),
            ),
            observed_at_height: height - 6,
            expires_at_height: height + state.config.query_ttl_blocks,
        };
        state
            .record_attestation(attestation.clone())
            .expect("devnet attestation");

        let witness_id = oracle_witness_id(&source_id, &query_id, ProofKind::SparseState, 0);
        let witness = OracleWitness {
            witness_id: witness_id.clone(),
            source_id: source_id.clone(),
            query_id: query_id.clone(),
            proof_kind: ProofKind::SparseState,
            encrypted_witness_payload: payload_root(
                "cross-contract-state-oracle:encrypted-witness",
                &json!({"ciphertext": "devnet-encrypted-risk-witness", "rows": 4}),
            ),
            witness_root: payload_root(
                "cross-contract-state-oracle:witness-root",
                &json!({"query_id": query_id, "proof": "sparse-state-risk-metric"}),
            ),
            source_state_root: source.latest_state_root.clone(),
            receipt_root: source.latest_receipt_root.clone(),
            verifier_transcript_root: payload_root(
                "cross-contract-state-oracle:verifier-transcript",
                &json!({"verifier": "recursive-state-oracle", "height": height - 4}),
            ),
            status: WitnessStatus::Verified,
            privacy_set_size: state.config.batch_privacy_set_size,
            observed_at_height: height - 4,
        };
        state
            .record_witness(witness.clone())
            .expect("devnet witness");

        let reservation = SponsorReservation {
            reservation_id: sponsor_reservation_id(&query_id, "fee-vault-alpha", 0),
            query_id: query_id.clone(),
            sponsor_commitment: payload_root(
                "cross-contract-state-oracle:sponsor",
                &json!({"vault": "fee-vault-alpha", "lane": "low-fee-oracle"}),
            ),
            requester_commitment: requester_commitment.clone(),
            max_fee_amount: 1_500_000,
            reserved_fee_amount: 750_000,
            consumed_fee_amount: 96_000,
            rebate_bps: state.config.target_rebate_bps,
            status: ReservationStatus::RebateQueued,
            sponsor_proof_root: payload_root(
                "cross-contract-state-oracle:sponsor-proof",
                &json!({"credit_root": "fee-vault-alpha-credit-root", "nonce": 99}),
            ),
            created_at_height: height - 60,
            expires_at_height: height + state.config.reservation_ttl_blocks,
        };
        state
            .reserve_sponsor_fee(reservation.clone())
            .expect("devnet reservation");

        let lane_id = oracle_lane_id(OracleLaneKind::FastRead, "dex-risk-fast-read");
        let batch_query_root = public_record_root(
            "cross-contract-state-oracle:devnet:batch-queries",
            &[query.record()],
        );
        let batch_witness_root = public_record_root(
            "cross-contract-state-oracle:devnet:batch-witnesses",
            &[witness.record()],
        );
        let batch_id = oracle_batch_id(&source_id, &batch_query_root, height - 2);
        let batch = OracleBatch {
            batch_id: batch_id.clone(),
            source_root: root_from_record("cross-contract-state-oracle:source", &source.record()),
            query_root: batch_query_root,
            witness_root: batch_witness_root,
            attestation_root: root_from_record(
                "cross-contract-state-oracle:attestation",
                &attestation.record(),
            ),
            reservation_root: root_from_record(
                "cross-contract-state-oracle:reservation",
                &reservation.record(),
            ),
            oracle_committee_root: source.oracle_committee_root.clone(),
            lane_id: lane_id.clone(),
            status: OracleBatchStatus::Settled,
            opened_at_height: height - 5,
            sealed_at_height: height - 2,
            expires_at_height: height + state.config.batch_ttl_blocks,
            query_count: 1,
            max_fee_amount: 128_000,
            settlement_commitment: payload_root(
                "cross-contract-state-oracle:settlement",
                &json!({"query_id": query_id, "witness_id": witness_id, "fee": "96000"}),
            ),
        };
        state.record_batch(batch.clone()).expect("devnet batch");

        let receipt = DeliveryReceipt {
            receipt_id: delivery_receipt_id(&batch_id, &query.query_id, 0),
            batch_id: batch_id.clone(),
            query_id: query.query_id.clone(),
            witness_id: witness.witness_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            kind: ReceiptKind::QueryFulfillment,
            delivered_state_root: source.latest_state_root.clone(),
            delivery_proof_root: payload_root(
                "cross-contract-state-oracle:delivery-proof",
                &json!({"batch_id": batch_id, "query_count": 1, "privacy_set": state.config.batch_privacy_set_size}),
            ),
            fee_amount: 96_000,
            rebate_amount: 48,
            settled_at_height: height - 1,
        };
        state
            .record_receipt(receipt.clone())
            .expect("devnet receipt");

        let rebate = FeeRebate {
            rebate_id: fee_rebate_id(&receipt.receipt_id, &reservation.reservation_id),
            receipt_id: receipt.receipt_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            claimant_commitment: requester_commitment.clone(),
            rebate_amount: receipt.rebate_amount,
            rebate_bps: state.config.target_rebate_bps,
            status: RebateStatus::Claimable,
            claim_after_height: height + 1,
            expires_at_height: height + 7_200,
        };
        state.record_rebate(rebate).expect("devnet rebate");

        let root_update = RootUpdate {
            update_id: root_update_id(&source_id, &source.latest_state_root, height),
            source_id: source_id.clone(),
            previous_state_root: payload_root(
                "cross-contract-state-oracle:previous-state-root",
                &json!({"source": source_id, "height": height - 16}),
            ),
            next_state_root: source.latest_state_root.clone(),
            receipt_root: source.latest_receipt_root.clone(),
            attestation_root: attestation.attestation_root.clone(),
            observed_at_height: height,
        };
        state
            .record_root_update(root_update)
            .expect("devnet root update");

        state
            .record_lane_metric(LaneMetric {
                lane_id,
                lane_kind: OracleLaneKind::FastRead,
                label: "dex-risk-fast-read".to_string(),
                pending_query_count: 8,
                sealed_batch_count: 144,
                median_delivery_blocks: 3,
                target_fee_bps: 4,
                congestion_hint: 12,
                last_updated_height: height,
            })
            .expect("devnet lane metric");

        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn register_source(
        &mut self,
        source: ContractStateSource,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.sources.len() >= self.config.max_sources {
            return Err("source capacity exceeded".to_string());
        }
        if !source.status.accepts_queries() && source.status != SourceStatus::Proposed {
            return Err("source status is not registerable".to_string());
        }
        if source.pq_security_bits < self.config.min_pq_security_bits {
            return Err("source pq security below runtime floor".to_string());
        }
        if source.fee_bps > self.config.max_oracle_fee_bps {
            return Err("source oracle fee above runtime ceiling".to_string());
        }
        self.sources.insert(source.source_id.clone(), source);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn submit_query(
        &mut self,
        query: EncryptedStateQuery,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.queries.len() >= self.config.max_queries {
            return Err("query capacity exceeded".to_string());
        }
        if !self.sources.contains_key(&query.source_id) {
            return Err("query references unknown source".to_string());
        }
        if self.consumed_nullifiers.contains(&query.nullifier) {
            return Err("query nullifier already consumed".to_string());
        }
        if !query.status.is_open() {
            return Err("query status is not open".to_string());
        }
        if query.privacy_set_size < self.config.min_privacy_set_size {
            return Err("query privacy set below runtime floor".to_string());
        }
        if query.max_fee_bps > self.config.max_oracle_fee_bps {
            return Err("query max fee above runtime ceiling".to_string());
        }
        let fence = NullifierFence {
            nullifier: query.nullifier.clone(),
            query_id: query.query_id.clone(),
            source_id: query.source_id.clone(),
            fence_root: replay_fence_leaf(&query.source_id, &query.nullifier),
            status: NullifierFenceStatus::Locked,
            locked_at_height: query.created_at_height,
            released_at_height: 0,
        };
        self.consumed_nullifiers.insert(query.nullifier.clone());
        self.nullifier_fences.insert(fence.nullifier.clone(), fence);
        self.queries.insert(query.query_id.clone(), query);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        attestation: QueryAttestation,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exceeded".to_string());
        }
        if !self.sources.contains_key(&attestation.source_id) {
            return Err("attestation references unknown source".to_string());
        }
        if !self.queries.contains_key(&attestation.query_id) {
            return Err("attestation references unknown query".to_string());
        }
        if !attestation.verdict.contributes_to_quorum() {
            return Err("attestation verdict does not contribute to quorum".to_string());
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_witness(
        &mut self,
        witness: OracleWitness,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.witnesses.len() >= self.config.max_witnesses {
            return Err("witness capacity exceeded".to_string());
        }
        if !self.sources.contains_key(&witness.source_id) {
            return Err("witness references unknown source".to_string());
        }
        if !self.queries.contains_key(&witness.query_id) {
            return Err("witness references unknown query".to_string());
        }
        if !witness.status.can_settle() {
            return Err("witness is not settleable".to_string());
        }
        if witness.privacy_set_size < self.config.min_privacy_set_size {
            return Err("witness privacy set below runtime floor".to_string());
        }
        self.witnesses.insert(witness.witness_id.clone(), witness);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn reserve_sponsor_fee(
        &mut self,
        reservation: SponsorReservation,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("reservation capacity exceeded".to_string());
        }
        if !self.queries.contains_key(&reservation.query_id) {
            return Err("reservation references unknown query".to_string());
        }
        if reservation.rebate_bps > self.config.target_rebate_bps {
            return Err("reservation rebate above runtime target".to_string());
        }
        if reservation.reserved_fee_amount > reservation.max_fee_amount {
            return Err("reserved fee exceeds maximum".to_string());
        }
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_batch(
        &mut self,
        batch: OracleBatch,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.batches.len() >= self.config.max_batches {
            return Err("batch capacity exceeded".to_string());
        }
        if batch.query_count as usize > self.config.max_batch_queries {
            return Err("batch query count exceeds max batch queries".to_string());
        }
        if !batch.status.anchors_state() && batch.status != OracleBatchStatus::Open {
            return Err("batch status is not recordable".to_string());
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        receipt: DeliveryReceipt,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exceeded".to_string());
        }
        if !self.batches.contains_key(&receipt.batch_id) {
            return Err("receipt references unknown batch".to_string());
        }
        if !self.queries.contains_key(&receipt.query_id) {
            return Err("receipt references unknown query".to_string());
        }
        if !self.witnesses.contains_key(&receipt.witness_id) {
            return Err("receipt references unknown witness".to_string());
        }
        if !self.reservations.contains_key(&receipt.reservation_id) {
            return Err("receipt references unknown reservation".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_rebate(
        &mut self,
        rebate: FeeRebate,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        if !self.receipts.contains_key(&rebate.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        if !self.reservations.contains_key(&rebate.reservation_id) {
            return Err("rebate references unknown reservation".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_lane_metric(
        &mut self,
        metric: LaneMetric,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if metric.target_fee_bps > self.config.max_oracle_fee_bps {
            return Err("lane target fee above runtime ceiling".to_string());
        }
        self.lane_metrics.insert(metric.lane_id.clone(), metric);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_root_update(
        &mut self,
        update: RootUpdate,
    ) -> PrivateL2ConfidentialCrossContractStateOracleRuntimeResult<()> {
        if !self.sources.contains_key(&update.source_id) {
            return Err("root update references unknown source".to_string());
        }
        self.root_updates.insert(update.update_id.clone(), update);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_counters(&mut self) {
        self.counters.source_count = self.sources.len() as u64;
        self.counters.query_count = self.queries.len() as u64;
        self.counters.attestation_count = self.attestations.len() as u64;
        self.counters.witness_count = self.witnesses.len() as u64;
        self.counters.reservation_count = self.reservations.len() as u64;
        self.counters.batch_count = self.batches.len() as u64;
        self.counters.receipt_count = self.receipts.len() as u64;
        self.counters.rebate_count = self.rebates.len() as u64;
        self.counters.nullifier_count = self.nullifier_fences.len() as u64;
        self.counters.lane_metric_count = self.lane_metrics.len() as u64;
        self.counters.root_update_count = self.root_updates.len() as u64;
        self.counters.total_reserved_fee = self
            .reservations
            .values()
            .map(|reservation| reservation.reserved_fee_amount)
            .sum();
        self.counters.total_settled_fee = self
            .receipts
            .values()
            .map(|receipt| receipt.fee_amount)
            .sum();
        self.counters.total_rebate_amount = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_amount)
            .sum();
    }

    pub fn recompute_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.policy_root(),
            source_root: public_record_root(
                "cross-contract-state-oracle:sources",
                &map_records(&self.sources),
            ),
            query_root: public_record_root(
                "cross-contract-state-oracle:queries",
                &map_records(&self.queries),
            ),
            attestation_root: public_record_root(
                "cross-contract-state-oracle:attestations",
                &map_records(&self.attestations),
            ),
            witness_root: public_record_root(
                "cross-contract-state-oracle:witnesses",
                &map_records(&self.witnesses),
            ),
            reservation_root: public_record_root(
                "cross-contract-state-oracle:reservations",
                &map_records(&self.reservations),
            ),
            batch_root: public_record_root(
                "cross-contract-state-oracle:batches",
                &map_records(&self.batches),
            ),
            receipt_root: public_record_root(
                "cross-contract-state-oracle:receipts",
                &map_records(&self.receipts),
            ),
            rebate_root: public_record_root(
                "cross-contract-state-oracle:rebates",
                &map_records(&self.rebates),
            ),
            nullifier_root: public_record_root(
                "cross-contract-state-oracle:nullifiers",
                &map_records(&self.nullifier_fences),
            ),
            lane_metric_root: public_record_root(
                "cross-contract-state-oracle:lane-metrics",
                &map_records(&self.lane_metrics),
            ),
            root_update_root: public_record_root(
                "cross-contract-state-oracle:root-updates",
                &map_records(&self.root_updates),
            ),
            counter_root: payload_root(
                "cross-contract-state-oracle:counters",
                &self.counters.record(),
            ),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&self.public_record_without_roots_state(&roots));
        self.roots = roots;
    }

    pub fn roots(&self) -> Roots {
        self.roots.clone()
    }

    pub fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_roots_state(&self.roots)
    }

    fn public_record_without_roots_state(&self, roots: &Roots) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_CROSS_CONTRACT_STATE_ORACLE_RUNTIME_SCHEMA_VERSION,
            "config": self.config.policy_record(),
            "counters": self.counters.record(),
            "roots": roots.without_state_root(),
            "sources": map_records(&self.sources),
            "queries": map_records(&self.queries),
            "attestations": map_records(&self.attestations),
            "witnesses": map_records(&self.witnesses),
            "reservations": map_records(&self.reservations),
            "batches": map_records(&self.batches),
            "receipts": map_records(&self.receipts),
            "rebates": map_records(&self.rebates),
            "nullifier_fences": map_records(&self.nullifier_fences),
            "lane_metrics": map_records(&self.lane_metrics),
            "root_updates": map_records(&self.root_updates),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn open_query_ids(&self) -> Vec<String> {
        self.queries
            .values()
            .filter(|query| query.status.is_open())
            .map(|query| query.query_id.clone())
            .collect()
    }

    pub fn claimable_rebate_ids(&self) -> Vec<String> {
        self.rebates
            .values()
            .filter(|rebate| rebate.status == RebateStatus::Claimable)
            .map(|rebate| rebate.rebate_id.clone())
            .collect()
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_confidential_cross_contract_state_oracle_runtime_public_record() -> Value {
    State::devnet().public_record()
}

pub fn private_l2_confidential_cross_contract_state_oracle_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn state_source_id(contract_label: &str, domain: StateOracleDomain, salt: &str) -> String {
    domain_hash(
        "cross-contract-state-oracle:source-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_label),
            HashPart::Str(domain.as_str()),
            HashPart::Str(salt),
        ],
        32,
    )
}

pub fn state_query_id(
    source_id: &str,
    requester_commitment: &str,
    query_kind: QueryKind,
    sequence: u64,
) -> String {
    domain_hash(
        "cross-contract-state-oracle:query-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(query_kind.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn query_attestation_id(source_id: &str, query_id: &str, nonce: &str) -> String {
    domain_hash(
        "cross-contract-state-oracle:attestation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(query_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn oracle_witness_id(
    source_id: &str,
    query_id: &str,
    proof_kind: ProofKind,
    sequence: u64,
) -> String {
    domain_hash(
        "cross-contract-state-oracle:witness-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(query_id),
            HashPart::Str(match proof_kind {
                ProofKind::MerkleStorage => "merkle_storage",
                ProofKind::ReceiptMerkle => "receipt_merkle",
                ProofKind::SparseState => "sparse_state",
                ProofKind::VerkleTransition => "verkle_transition",
                ProofKind::RecursiveBatch => "recursive_batch",
                ProofKind::CrossContractRead => "cross_contract_read",
                ProofKind::CrossRollupMessage => "cross_rollup_message",
                ProofKind::MoneroBridgeReserve => "monero_bridge_reserve",
            }),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(query_id: &str, sponsor_label: &str, sequence: u64) -> String {
    domain_hash(
        "cross-contract-state-oracle:sponsor-reservation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(query_id),
            HashPart::Str(sponsor_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn oracle_batch_id(source_id: &str, query_root: &str, sealed_at_height: u64) -> String {
    domain_hash(
        "cross-contract-state-oracle:batch-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(query_root),
            HashPart::U64(sealed_at_height),
        ],
        32,
    )
}

pub fn delivery_receipt_id(batch_id: &str, query_id: &str, sequence: u64) -> String {
    domain_hash(
        "cross-contract-state-oracle:delivery-receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(query_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_rebate_id(receipt_id: &str, reservation_id: &str) -> String {
    domain_hash(
        "cross-contract-state-oracle:fee-rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(reservation_id),
        ],
        32,
    )
}

pub fn query_nullifier(source_id: &str, requester_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "cross-contract-state-oracle:query-nullifier",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(requester_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn replay_fence_leaf(source_id: &str, nullifier: &str) -> String {
    domain_hash(
        "cross-contract-state-oracle:replay-fence-leaf",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn oracle_lane_id(lane_kind: OracleLaneKind, label: &str) -> String {
    let lane_kind = match lane_kind {
        OracleLaneKind::FastRead => "fast_read",
        OracleLaneKind::LowFeeBatch => "low_fee_batch",
        OracleLaneKind::RiskCritical => "risk_critical",
        OracleLaneKind::BridgeReserve => "bridge_reserve",
        OracleLaneKind::GovernanceCheckpoint => "governance_checkpoint",
        OracleLaneKind::CrossRollupSync => "cross_rollup_sync",
    };
    domain_hash(
        "cross-contract-state-oracle:lane-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn root_update_id(source_id: &str, next_state_root: &str, observed_at_height: u64) -> String {
    domain_hash(
        "cross-contract-state-oracle:root-update-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(next_state_root),
            HashPart::U64(observed_at_height),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("cross-contract-state-oracle:state-root", record)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values()
        .map(|value| serde_json::to_value(value).expect("serializable cross-contract oracle state"))
        .collect()
}
