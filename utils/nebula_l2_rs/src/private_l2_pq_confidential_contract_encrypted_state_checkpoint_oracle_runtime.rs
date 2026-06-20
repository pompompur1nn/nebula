use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2PqConfidentialContractEncryptedStateCheckpointOracleRuntimeResult<T>;
pub type PrivateL2PqConfidentialContractEncryptedStateCheckpointOracleRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_STATE_CHECKPOINT_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-encrypted-state-checkpoint-oracle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_STATE_CHECKPOINT_ORACLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_CHECKPOINT_FEED_SUITE: &str =
    "ML-KEM-1024+AEAD-encrypted-contract-state-checkpoint-feed-v1";
pub const PQ_CHECKPOINT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-checkpoint-attestation-v1";
pub const PRIVATE_CHECKPOINT_ROOT_SUITE: &str =
    "confidential-contract-private-checkpoint-root-commitment-v1";
pub const CALLBACK_RECEIPT_SUITE: &str =
    "confidential-contract-encrypted-checkpoint-callback-receipt-v1";
pub const ACCESS_BUDGET_SUITE: &str = "encrypted-checkpoint-oracle-access-budget-nullifier-v1";
pub const FEE_SPONSOR_SUITE: &str = "encrypted-checkpoint-oracle-fee-sponsor-authorization-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "encrypted-checkpoint-oracle-redaction-budget-and-disclosure-window-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "encrypted-checkpoint-oracle-operator-summary-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-encrypted-state-checkpoint-oracle-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 2_612_000;
pub const DEVNET_EPOCH: u64 = 4_352;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COMMITTEE_MEMBERS: u64 = 5;
pub const DEFAULT_TARGET_COMMITTEE_MEMBERS: u64 = 13;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_FEED_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_ROOT_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 256;
pub const DEFAULT_CALLBACK_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ACCESS_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 10_080;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_FEED_BYTES: u64 = 196_608;
pub const DEFAULT_MAX_CALLBACK_BYTES: u64 = 65_536;
pub const DEFAULT_BASE_FEE_MICRO_CREDITS: u128 = 4_000;
pub const DEFAULT_CALLBACK_FEE_MICRO_CREDITS: u128 = 1_250;
pub const DEFAULT_REDACTION_FEE_MICRO_CREDITS: u128 = 800;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 650;
pub const DEFAULT_OPERATOR_REBATE_BPS: u64 = 350;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_FEEDS: usize = 16_777_216;
pub const MAX_COMMITTEES: usize = 262_144;
pub const MAX_MEMBERS: usize = 4_194_304;
pub const MAX_PRIVATE_ROOTS: usize = 8_388_608;
pub const MAX_ATTESTATIONS: usize = 33_554_432;
pub const MAX_CALLBACK_RECEIPTS: usize = 16_777_216;
pub const MAX_ACCESS_BUDGETS: usize = 8_388_608;
pub const MAX_FEE_SPONSORS: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 8_388_608;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Dex,
    Lending,
    Perpetuals,
    Bridge,
    Governance,
    AccountAbstraction,
    TokenRegistry,
    ComplianceVault,
    CrossRuntime,
    Custom,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Bridge => "bridge",
            Self::Governance => "governance",
            Self::AccountAbstraction => "account_abstraction",
            Self::TokenRegistry => "token_registry",
            Self::ComplianceVault => "compliance_vault",
            Self::CrossRuntime => "cross_runtime",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    StateCheckpoint,
    StorageNamespace,
    NullifierSet,
    NoteCommitmentTree,
    EventCursor,
    LiquidityReserve,
    RiskMetric,
    Composite,
}

impl FeedKind {
    pub fn default_weight(self) -> u64 {
        match self {
            Self::StateCheckpoint => 24,
            Self::StorageNamespace => 16,
            Self::NullifierSet => 20,
            Self::NoteCommitmentTree => 18,
            Self::EventCursor => 8,
            Self::LiquidityReserve => 22,
            Self::RiskMetric => 14,
            Self::Composite => 30,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateCheckpoint => "state_checkpoint",
            Self::StorageNamespace => "storage_namespace",
            Self::NullifierSet => "nullifier_set",
            Self::NoteCommitmentTree => "note_commitment_tree",
            Self::EventCursor => "event_cursor",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::RiskMetric => "risk_metric",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedStatus {
    Proposed,
    Active,
    Throttled,
    Sealed,
    Expired,
    Rejected,
}

impl FeedStatus {
    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Sealed)
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Proposed | Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteePurpose {
    FeedPublisher,
    RootWitness,
    PqAttestor,
    CallbackExecutor,
    RedactionReviewer,
    FeeSponsor,
    Watchtower,
}

impl CommitteePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeedPublisher => "feed_publisher",
            Self::RootWitness => "root_witness",
            Self::PqAttestor => "pq_attestor",
            Self::CallbackExecutor => "callback_executor",
            Self::RedactionReviewer => "redaction_reviewer",
            Self::FeeSponsor => "fee_sponsor",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Pending,
    Active,
    Degraded,
    Suspended,
    Slashed,
    Retired,
}

impl MemberStatus {
    pub fn can_vote(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootStatus {
    Proposed,
    Attesting,
    Finalized,
    Reorged,
    Quarantined,
}

impl RootStatus {
    pub fn accepts_callbacks(self) -> bool {
        matches!(self, Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithRedactions,
    InsufficientWitness,
    StaleRoot,
    InvalidCiphertext,
    Rejected,
}

impl AttestationVerdict {
    pub fn approves(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithRedactions)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackStatus {
    Queued,
    Delivered,
    Failed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Depleted,
    Suspended,
    Expired,
}

impl BudgetStatus {
    pub fn can_spend(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Paused,
    Depleted,
    Revoked,
}

impl SponsorStatus {
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub min_pq_security_bits: u16,
    pub min_committee_members: u64,
    pub target_committee_members: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub feed_ttl_blocks: u64,
    pub root_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub callback_ttl_blocks: u64,
    pub access_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_feed_bytes: u64,
    pub max_callback_bytes: u64,
    pub base_fee_micro_credits: u128,
    pub callback_fee_micro_credits: u128,
    pub redaction_fee_micro_credits: u128,
    pub sponsor_rebate_bps: u64,
    pub operator_rebate_bps: u64,
    pub require_dual_pq_attestations: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_members: DEFAULT_MIN_COMMITTEE_MEMBERS,
            target_committee_members: DEFAULT_TARGET_COMMITTEE_MEMBERS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            feed_ttl_blocks: DEFAULT_FEED_TTL_BLOCKS,
            root_ttl_blocks: DEFAULT_ROOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            callback_ttl_blocks: DEFAULT_CALLBACK_TTL_BLOCKS,
            access_window_blocks: DEFAULT_ACCESS_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_feed_bytes: DEFAULT_MAX_FEED_BYTES,
            max_callback_bytes: DEFAULT_MAX_CALLBACK_BYTES,
            base_fee_micro_credits: DEFAULT_BASE_FEE_MICRO_CREDITS,
            callback_fee_micro_credits: DEFAULT_CALLBACK_FEE_MICRO_CREDITS,
            redaction_fee_micro_credits: DEFAULT_REDACTION_FEE_MICRO_CREDITS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            operator_rebate_bps: DEFAULT_OPERATOR_REBATE_BPS,
            require_dual_pq_attestations: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.chain_id.is_empty(), "chain_id must not be empty");
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "min_pq_security_bits must be at least {}",
            DEFAULT_MIN_PQ_SECURITY_BITS
        );
        ensure!(
            self.min_committee_members > 0
                && self.target_committee_members >= self.min_committee_members,
            "committee member targets are inconsistent"
        );
        ensure!(
            self.quorum_bps <= MAX_BPS && self.strong_quorum_bps <= MAX_BPS,
            "quorum bps must be <= {}",
            MAX_BPS
        );
        ensure!(
            self.strong_quorum_bps >= self.quorum_bps,
            "strong quorum must be >= quorum"
        );
        ensure!(
            self.feed_ttl_blocks > 0
                && self.root_ttl_blocks > 0
                && self.attestation_ttl_blocks > 0
                && self.callback_ttl_blocks > 0,
            "ttl values must be nonzero"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set must be >= minimum privacy set"
        );
        ensure!(
            self.sponsor_rebate_bps + self.operator_rebate_bps <= MAX_BPS,
            "rebate split exceeds {} bps",
            MAX_BPS
        );
        Ok(())
    }
}

impl PublicRecord for Config {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "hash_suite": HASH_SUITE,
            "encrypted_checkpoint_feed_suite": ENCRYPTED_CHECKPOINT_FEED_SUITE,
            "pq_checkpoint_attestation_suite": PQ_CHECKPOINT_ATTESTATION_SUITE,
            "private_checkpoint_root_suite": PRIVATE_CHECKPOINT_ROOT_SUITE,
            "callback_receipt_suite": CALLBACK_RECEIPT_SUITE,
            "access_budget_suite": ACCESS_BUDGET_SUITE,
            "fee_sponsor_suite": FEE_SPONSOR_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_committee_members": self.min_committee_members,
            "target_committee_members": self.target_committee_members,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "feed_ttl_blocks": self.feed_ttl_blocks,
            "root_ttl_blocks": self.root_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "callback_ttl_blocks": self.callback_ttl_blocks,
            "access_window_blocks": self.access_window_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_feed_bytes": self.max_feed_bytes,
            "max_callback_bytes": self.max_callback_bytes,
            "base_fee_micro_credits": self.base_fee_micro_credits.to_string(),
            "callback_fee_micro_credits": self.callback_fee_micro_credits.to_string(),
            "redaction_fee_micro_credits": self.redaction_fee_micro_credits.to_string(),
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "operator_rebate_bps": self.operator_rebate_bps,
            "require_dual_pq_attestations": self.require_dual_pq_attestations,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub feeds: u64,
    pub committees: u64,
    pub members: u64,
    pub private_roots: u64,
    pub attestations: u64,
    pub callback_receipts: u64,
    pub access_budgets: u64,
    pub fee_sponsors: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub total_fee_micro_credits: u128,
    pub sponsored_fee_micro_credits: u128,
    pub redacted_fields: u64,
    pub delivered_callbacks: u64,
    pub rejected_attestations: u64,
}

impl PublicRecord for Counters {
    fn public_record(&self) -> Value {
        json!({
            "feeds": self.feeds,
            "committees": self.committees,
            "members": self.members,
            "private_roots": self.private_roots,
            "attestations": self.attestations,
            "callback_receipts": self.callback_receipts,
            "access_budgets": self.access_budgets,
            "fee_sponsors": self.fee_sponsors,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "total_fee_micro_credits": self.total_fee_micro_credits.to_string(),
            "sponsored_fee_micro_credits": self.sponsored_fee_micro_credits.to_string(),
            "redacted_fields": self.redacted_fields,
            "delivered_callbacks": self.delivered_callbacks,
            "rejected_attestations": self.rejected_attestations,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub feed_root: String,
    pub committee_root: String,
    pub member_root: String,
    pub private_checkpoint_root: String,
    pub attestation_root: String,
    pub callback_receipt_root: String,
    pub access_budget_root: String,
    pub fee_sponsor_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn state_root(&self) -> String {
        domain_hash(
            "P2P-CC-ENC-CHECKPOINT-ORACLE-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl PublicRecord for Roots {
    fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "feed_root": self.feed_root,
            "committee_root": self.committee_root,
            "member_root": self.member_root,
            "private_checkpoint_root": self.private_checkpoint_root,
            "attestation_root": self.attestation_root,
            "callback_receipt_root": self.callback_receipt_root,
            "access_budget_root": self.access_budget_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "counters_root": self.counters_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedCheckpointFeed {
    pub feed_id: String,
    pub contract_id: String,
    pub domain: ContractDomain,
    pub kind: FeedKind,
    pub status: FeedStatus,
    pub publisher_committee_id: String,
    pub root_committee_id: String,
    pub encrypted_payload_hash: String,
    pub ciphertext_commitment: String,
    pub kem_ciphertext_hash: String,
    pub checkpoint_height: u64,
    pub l2_block_height: u64,
    pub expires_at_height: u64,
    pub payload_bytes: u64,
    pub privacy_set_size: u64,
    pub access_weight: u64,
    pub sponsor_id: Option<String>,
    pub callback_target: Option<String>,
    pub metadata_root: String,
}

impl EncryptedCheckpointFeed {
    pub fn new(
        feed_id: impl Into<String>,
        contract_id: impl Into<String>,
        domain: ContractDomain,
        kind: FeedKind,
        publisher_committee_id: impl Into<String>,
        root_committee_id: impl Into<String>,
        checkpoint_height: u64,
        l2_block_height: u64,
    ) -> Self {
        let feed_id = feed_id.into();
        let contract_id = contract_id.into();
        let seed = stable_hash("feed-seed", &[&feed_id, &contract_id]);
        Self {
            feed_id,
            contract_id,
            domain,
            kind,
            status: FeedStatus::Active,
            publisher_committee_id: publisher_committee_id.into(),
            root_committee_id: root_committee_id.into(),
            encrypted_payload_hash: stable_hash("encrypted-feed-payload", &[&seed]),
            ciphertext_commitment: stable_hash("encrypted-feed-ciphertext", &[&seed]),
            kem_ciphertext_hash: stable_hash("encrypted-feed-kem", &[&seed]),
            checkpoint_height,
            l2_block_height,
            expires_at_height: l2_block_height + DEFAULT_FEED_TTL_BLOCKS,
            payload_bytes: 32_768,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            access_weight: kind.default_weight(),
            sponsor_id: None,
            callback_target: None,
            metadata_root: stable_hash("encrypted-feed-metadata", &[&seed]),
        }
    }

    pub fn feed_root(&self) -> String {
        record_hash("P2P-CC-ENC-CHECKPOINT-FEED", &self.public_record())
    }
}

impl PublicRecord for EncryptedCheckpointFeed {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "feed_id": self.feed_id,
            "contract_id": self.contract_id,
            "domain": self.domain,
            "kind": self.kind,
            "status": self.status,
            "publisher_committee_id": self.publisher_committee_id,
            "root_committee_id": self.root_committee_id,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "ciphertext_commitment": self.ciphertext_commitment,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "checkpoint_height": self.checkpoint_height,
            "l2_block_height": self.l2_block_height,
            "expires_at_height": self.expires_at_height,
            "payload_bytes": self.payload_bytes,
            "privacy_set_size": self.privacy_set_size,
            "access_weight": self.access_weight,
            "sponsor_id": self.sponsor_id,
            "callback_target_hash": self.callback_target.as_ref().map(|target| stable_hash("callback-target", &[target])),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleCommittee {
    pub committee_id: String,
    pub purpose: CommitteePurpose,
    pub epoch: u64,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub active_members: u64,
    pub min_security_bits: u16,
    pub rotation_root: String,
    pub stake_root: String,
    pub status: String,
}

impl OracleCommittee {
    pub fn quorum_met(&self, weight: u64) -> bool {
        self.total_weight > 0
            && weight.saturating_mul(MAX_BPS) / self.total_weight >= DEFAULT_QUORUM_BPS
    }
}

impl PublicRecord for OracleCommittee {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "purpose": self.purpose,
            "epoch": self.epoch,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "active_members": self.active_members,
            "min_security_bits": self.min_security_bits,
            "rotation_root": self.rotation_root,
            "stake_root": self.stake_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleMember {
    pub member_id: String,
    pub committee_id: String,
    pub operator_id: String,
    pub status: MemberStatus,
    pub weight: u64,
    pub pq_identity_root: String,
    pub view_key_commitment: String,
    pub last_attested_height: u64,
    pub slash_count: u64,
}

impl PublicRecord for OracleMember {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "weight": self.weight,
            "pq_identity_root": self.pq_identity_root,
            "view_key_commitment": self.view_key_commitment,
            "last_attested_height": self.last_attested_height,
            "slash_count": self.slash_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateCheckpointRoot {
    pub root_id: String,
    pub feed_id: String,
    pub contract_id: String,
    pub status: RootStatus,
    pub private_root_commitment: String,
    pub encrypted_delta_root: String,
    pub nullifier_root: String,
    pub witness_commitment_root: String,
    pub root_height: u64,
    pub finalized_height: Option<u64>,
    pub expires_at_height: u64,
    pub attested_weight: u64,
    pub redaction_budget_id: Option<String>,
}

impl PublicRecord for PrivateCheckpointRoot {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "root_id": self.root_id,
            "feed_id": self.feed_id,
            "contract_id": self.contract_id,
            "status": self.status,
            "private_root_commitment": self.private_root_commitment,
            "encrypted_delta_root": self.encrypted_delta_root,
            "nullifier_root": self.nullifier_root,
            "witness_commitment_root": self.witness_commitment_root,
            "root_height": self.root_height,
            "finalized_height": self.finalized_height,
            "expires_at_height": self.expires_at_height,
            "attested_weight": self.attested_weight,
            "redaction_budget_id": self.redaction_budget_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCheckpointAttestation {
    pub attestation_id: String,
    pub root_id: String,
    pub feed_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub verdict: AttestationVerdict,
    pub attested_weight: u64,
    pub transcript_hash: String,
    pub ml_dsa_signature_hash: String,
    pub slh_dsa_signature_hash: String,
    pub redacted_fields: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqCheckpointAttestation {
    pub fn approves(&self) -> bool {
        self.verdict.approves()
    }
}

impl PublicRecord for PqCheckpointAttestation {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "root_id": self.root_id,
            "feed_id": self.feed_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "verdict": self.verdict,
            "attested_weight": self.attested_weight,
            "transcript_hash": self.transcript_hash,
            "ml_dsa_signature_hash": self.ml_dsa_signature_hash,
            "slh_dsa_signature_hash": self.slh_dsa_signature_hash,
            "redacted_fields": self.redacted_fields,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CallbackReceipt {
    pub receipt_id: String,
    pub root_id: String,
    pub feed_id: String,
    pub contract_id: String,
    pub callback_target_hash: String,
    pub status: CallbackStatus,
    pub payload_root: String,
    pub delivery_height: u64,
    pub gas_used: u64,
    pub fee_micro_credits: u128,
    pub sponsor_id: Option<String>,
}

impl PublicRecord for CallbackReceipt {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "root_id": self.root_id,
            "feed_id": self.feed_id,
            "contract_id": self.contract_id,
            "callback_target_hash": self.callback_target_hash,
            "status": self.status,
            "payload_root": self.payload_root,
            "delivery_height": self.delivery_height,
            "gas_used": self.gas_used,
            "fee_micro_credits": self.fee_micro_credits.to_string(),
            "sponsor_id": self.sponsor_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessBudget {
    pub budget_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub status: BudgetStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_weight: u64,
    pub spent_weight: u64,
    pub nullifier_root: String,
}

impl AccessBudget {
    pub fn remaining_weight(&self) -> u64 {
        self.max_weight.saturating_sub(self.spent_weight)
    }
}

impl PublicRecord for AccessBudget {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "contract_id": self.contract_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_weight": self.max_weight,
            "spent_weight": self.spent_weight,
            "remaining_weight": self.remaining_weight(),
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: SponsorStatus,
    pub max_fee_micro_credits: u128,
    pub spent_fee_micro_credits: u128,
    pub allowed_contract_root: String,
    pub authorization_root: String,
    pub rebate_bps: u64,
}

impl FeeSponsor {
    pub fn remaining_fee_micro_credits(&self) -> u128 {
        self.max_fee_micro_credits
            .saturating_sub(self.spent_fee_micro_credits)
    }
}

impl PublicRecord for FeeSponsor {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status,
            "max_fee_micro_credits": self.max_fee_micro_credits.to_string(),
            "spent_fee_micro_credits": self.spent_fee_micro_credits.to_string(),
            "remaining_fee_micro_credits": self.remaining_fee_micro_credits().to_string(),
            "allowed_contract_root": self.allowed_contract_root,
            "authorization_root": self.authorization_root,
            "rebate_bps": self.rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub redaction_budget_id: String,
    pub contract_id: String,
    pub reviewer_committee_id: String,
    pub status: BudgetStatus,
    pub max_redacted_fields: u64,
    pub spent_redacted_fields: u64,
    pub disclosure_window_start: u64,
    pub disclosure_window_end: u64,
    pub policy_root: String,
}

impl RedactionBudget {
    pub fn remaining_fields(&self) -> u64 {
        self.max_redacted_fields
            .saturating_sub(self.spent_redacted_fields)
    }
}

impl PublicRecord for RedactionBudget {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "redaction_budget_id": self.redaction_budget_id,
            "contract_id": self.contract_id,
            "reviewer_committee_id": self.reviewer_committee_id,
            "status": self.status,
            "max_redacted_fields": self.max_redacted_fields,
            "spent_redacted_fields": self.spent_redacted_fields,
            "remaining_fields": self.remaining_fields(),
            "disclosure_window_start": self.disclosure_window_start,
            "disclosure_window_end": self.disclosure_window_end,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub epoch: u64,
    pub committee_count: u64,
    pub feed_count: u64,
    pub attestation_count: u64,
    pub callback_count: u64,
    pub accepted_weight: u64,
    pub rejected_weight: u64,
    pub earned_fee_micro_credits: u128,
    pub slash_count: u64,
    pub summary_root: String,
}

impl PublicRecord for OperatorSummary {
    fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "committee_count": self.committee_count,
            "feed_count": self.feed_count,
            "attestation_count": self.attestation_count,
            "callback_count": self.callback_count,
            "accepted_weight": self.accepted_weight,
            "rejected_weight": self.rejected_weight,
            "earned_fee_micro_credits": self.earned_fee_micro_credits.to_string(),
            "slash_count": self.slash_count,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub feeds: BTreeMap<String, EncryptedCheckpointFeed>,
    pub committees: BTreeMap<String, OracleCommittee>,
    pub members: BTreeMap<String, OracleMember>,
    pub private_roots: BTreeMap<String, PrivateCheckpointRoot>,
    pub attestations: BTreeMap<String, PqCheckpointAttestation>,
    pub callback_receipts: BTreeMap<String, CallbackReceipt>,
    pub access_budgets: BTreeMap<String, AccessBudget>,
    pub fee_sponsors: BTreeMap<String, FeeSponsor>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub counters: Counters,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            height,
            epoch,
            feeds: BTreeMap::new(),
            committees: BTreeMap::new(),
            members: BTreeMap::new(),
            private_roots: BTreeMap::new(),
            attestations: BTreeMap::new(),
            callback_receipts: BTreeMap::new(),
            access_budgets: BTreeMap::new(),
            fee_sponsors: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            counters: Counters::default(),
        }
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: record_hash("P2P-CC-ENC-CHECKPOINT-CONFIG", &self.config.public_record()),
            feed_root: map_root("P2P-CC-ENC-CHECKPOINT-FEEDS", &self.feeds),
            committee_root: map_root("P2P-CC-ENC-CHECKPOINT-COMMITTEES", &self.committees),
            member_root: map_root("P2P-CC-ENC-CHECKPOINT-MEMBERS", &self.members),
            private_checkpoint_root: map_root(
                "P2P-CC-ENC-CHECKPOINT-PRIVATE-ROOTS",
                &self.private_roots,
            ),
            attestation_root: map_root("P2P-CC-ENC-CHECKPOINT-ATTESTATIONS", &self.attestations),
            callback_receipt_root: map_root(
                "P2P-CC-ENC-CHECKPOINT-CALLBACKS",
                &self.callback_receipts,
            ),
            access_budget_root: map_root(
                "P2P-CC-ENC-CHECKPOINT-ACCESS-BUDGETS",
                &self.access_budgets,
            ),
            fee_sponsor_root: map_root("P2P-CC-ENC-CHECKPOINT-FEE-SPONSORS", &self.fee_sponsors),
            redaction_budget_root: map_root(
                "P2P-CC-ENC-CHECKPOINT-REDACTION-BUDGETS",
                &self.redaction_budgets,
            ),
            operator_summary_root: map_root(
                "P2P-CC-ENC-CHECKPOINT-OPERATOR-SUMMARIES",
                &self.operator_summaries,
            ),
            counters_root: record_hash(
                "P2P-CC-ENC-CHECKPOINT-COUNTERS",
                &self.counters.public_record(),
            ),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(self.feeds.len() <= MAX_FEEDS, "too many feeds");
        ensure!(
            self.committees.len() <= MAX_COMMITTEES,
            "too many committees"
        );
        ensure!(self.members.len() <= MAX_MEMBERS, "too many members");
        ensure!(
            self.private_roots.len() <= MAX_PRIVATE_ROOTS,
            "too many private roots"
        );
        ensure!(
            self.attestations.len() <= MAX_ATTESTATIONS,
            "too many attestations"
        );
        ensure!(
            self.callback_receipts.len() <= MAX_CALLBACK_RECEIPTS,
            "too many callback receipts"
        );
        ensure!(
            self.access_budgets.len() <= MAX_ACCESS_BUDGETS,
            "too many access budgets"
        );
        ensure!(
            self.fee_sponsors.len() <= MAX_FEE_SPONSORS,
            "too many fee sponsors"
        );
        ensure!(
            self.redaction_budgets.len() <= MAX_REDACTION_BUDGETS,
            "too many redaction budgets"
        );
        ensure!(
            self.operator_summaries.len() <= MAX_OPERATOR_SUMMARIES,
            "too many operator summaries"
        );
        Ok(())
    }

    pub fn register_committee(&mut self, committee: OracleCommittee) -> Result<String> {
        ensure!(
            !self.committees.contains_key(&committee.committee_id),
            "committee already exists: {}",
            committee.committee_id
        );
        ensure!(
            committee.min_security_bits >= self.config.min_pq_security_bits,
            "committee pq security below runtime minimum"
        );
        let id = committee.committee_id.clone();
        self.committees.insert(id.clone(), committee);
        self.refresh_counters();
        Ok(id)
    }

    pub fn register_member(&mut self, member: OracleMember) -> Result<String> {
        ensure!(
            self.committees.contains_key(&member.committee_id),
            "unknown committee: {}",
            member.committee_id
        );
        ensure!(
            !self.members.contains_key(&member.member_id),
            "member already exists: {}",
            member.member_id
        );
        let id = member.member_id.clone();
        self.members.insert(id.clone(), member);
        self.recompute_committee_weight();
        self.refresh_counters();
        Ok(id)
    }

    pub fn publish_feed(&mut self, feed: EncryptedCheckpointFeed) -> Result<String> {
        ensure!(
            !self.feeds.contains_key(&feed.feed_id),
            "feed already exists: {}",
            feed.feed_id
        );
        ensure!(
            self.committees.contains_key(&feed.publisher_committee_id),
            "unknown publisher committee: {}",
            feed.publisher_committee_id
        );
        ensure!(
            self.committees.contains_key(&feed.root_committee_id),
            "unknown root committee: {}",
            feed.root_committee_id
        );
        ensure!(
            feed.payload_bytes <= self.config.max_feed_bytes,
            "feed payload exceeds max bytes"
        );
        ensure!(
            feed.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below runtime minimum"
        );
        let id = feed.feed_id.clone();
        self.feeds.insert(id.clone(), feed);
        self.refresh_counters();
        Ok(id)
    }

    pub fn commit_private_root(&mut self, root: PrivateCheckpointRoot) -> Result<String> {
        ensure!(
            !self.private_roots.contains_key(&root.root_id),
            "private root already exists: {}",
            root.root_id
        );
        ensure!(
            self.feeds.contains_key(&root.feed_id),
            "unknown feed: {}",
            root.feed_id
        );
        let id = root.root_id.clone();
        self.private_roots.insert(id.clone(), root);
        self.refresh_counters();
        Ok(id)
    }

    pub fn submit_attestation(&mut self, attestation: PqCheckpointAttestation) -> Result<String> {
        ensure!(
            !self.attestations.contains_key(&attestation.attestation_id),
            "attestation already exists: {}",
            attestation.attestation_id
        );
        let feed = self
            .feeds
            .get(&attestation.feed_id)
            .ok_or_else(|| format!("unknown feed: {}", attestation.feed_id))?;
        ensure!(
            feed.status.accepts_attestations(),
            "feed does not accept attestations"
        );
        let member = self
            .members
            .get(&attestation.member_id)
            .ok_or_else(|| format!("unknown member: {}", attestation.member_id))?;
        ensure!(member.status.can_vote(), "member cannot vote");
        ensure!(
            member.committee_id == attestation.committee_id,
            "member committee mismatch"
        );
        ensure!(
            self.private_roots.contains_key(&attestation.root_id),
            "unknown root: {}",
            attestation.root_id
        );
        let id = attestation.attestation_id.clone();
        let attested_weight = attestation.attested_weight;
        let redacted_fields = attestation.redacted_fields;
        let approved = attestation.approves();
        self.attestations.insert(id.clone(), attestation);
        if let Some(root) = self.private_roots.get_mut(&self.attestations[&id].root_id) {
            if approved {
                root.attested_weight = root.attested_weight.saturating_add(attested_weight);
                root.status = RootStatus::Attesting;
                if let Some(committee) = self.committees.get(&self.attestations[&id].committee_id) {
                    let quorum_bps = if committee.total_weight == 0 {
                        0
                    } else {
                        root.attested_weight.saturating_mul(MAX_BPS) / committee.total_weight
                    };
                    if quorum_bps >= self.config.quorum_bps {
                        root.status = RootStatus::Finalized;
                        root.finalized_height = Some(self.height);
                    }
                }
            } else {
                self.counters.rejected_attestations =
                    self.counters.rejected_attestations.saturating_add(1);
            }
        }
        self.counters.redacted_fields = self
            .counters
            .redacted_fields
            .saturating_add(redacted_fields);
        self.refresh_counters();
        Ok(id)
    }

    pub fn deliver_callback(&mut self, receipt: CallbackReceipt) -> Result<String> {
        ensure!(
            !self.callback_receipts.contains_key(&receipt.receipt_id),
            "callback receipt already exists: {}",
            receipt.receipt_id
        );
        let root = self
            .private_roots
            .get(&receipt.root_id)
            .ok_or_else(|| format!("unknown root: {}", receipt.root_id))?;
        ensure!(
            root.status.accepts_callbacks(),
            "root is not finalized for callback"
        );
        if let Some(sponsor_id) = &receipt.sponsor_id {
            self.spend_sponsor(sponsor_id, receipt.fee_micro_credits)?;
        }
        if receipt.status == CallbackStatus::Delivered {
            self.counters.delivered_callbacks = self.counters.delivered_callbacks.saturating_add(1);
        }
        self.counters.total_fee_micro_credits = self
            .counters
            .total_fee_micro_credits
            .saturating_add(receipt.fee_micro_credits);
        let id = receipt.receipt_id.clone();
        self.callback_receipts.insert(id.clone(), receipt);
        self.refresh_counters();
        Ok(id)
    }

    pub fn register_access_budget(&mut self, budget: AccessBudget) -> Result<String> {
        ensure!(
            !self.access_budgets.contains_key(&budget.budget_id),
            "access budget already exists: {}",
            budget.budget_id
        );
        ensure!(
            budget.window_end_height > budget.window_start_height,
            "access budget window must be increasing"
        );
        let id = budget.budget_id.clone();
        self.access_budgets.insert(id.clone(), budget);
        self.refresh_counters();
        Ok(id)
    }

    pub fn spend_access_budget(&mut self, budget_id: &str, weight: u64) -> Result<()> {
        let budget = self
            .access_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown access budget: {budget_id}"))?;
        ensure!(budget.status.can_spend(), "access budget cannot be spent");
        ensure!(
            budget.remaining_weight() >= weight,
            "access budget has insufficient remaining weight"
        );
        budget.spent_weight = budget.spent_weight.saturating_add(weight);
        if budget.remaining_weight() == 0 {
            budget.status = BudgetStatus::Depleted;
        }
        Ok(())
    }

    pub fn register_fee_sponsor(&mut self, sponsor: FeeSponsor) -> Result<String> {
        ensure!(
            !self.fee_sponsors.contains_key(&sponsor.sponsor_id),
            "fee sponsor already exists: {}",
            sponsor.sponsor_id
        );
        ensure!(
            sponsor.rebate_bps <= MAX_BPS,
            "sponsor rebate exceeds max bps"
        );
        let id = sponsor.sponsor_id.clone();
        self.fee_sponsors.insert(id.clone(), sponsor);
        self.refresh_counters();
        Ok(id)
    }

    pub fn spend_sponsor(&mut self, sponsor_id: &str, fee: u128) -> Result<()> {
        let sponsor = self
            .fee_sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| format!("unknown fee sponsor: {sponsor_id}"))?;
        ensure!(sponsor.status.can_sponsor(), "fee sponsor cannot sponsor");
        ensure!(
            sponsor.remaining_fee_micro_credits() >= fee,
            "fee sponsor has insufficient remaining balance"
        );
        sponsor.spent_fee_micro_credits = sponsor.spent_fee_micro_credits.saturating_add(fee);
        self.counters.sponsored_fee_micro_credits = self
            .counters
            .sponsored_fee_micro_credits
            .saturating_add(fee);
        if sponsor.remaining_fee_micro_credits() == 0 {
            sponsor.status = SponsorStatus::Depleted;
        }
        Ok(())
    }

    pub fn register_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        ensure!(
            !self
                .redaction_budgets
                .contains_key(&budget.redaction_budget_id),
            "redaction budget already exists: {}",
            budget.redaction_budget_id
        );
        ensure!(
            budget.disclosure_window_end > budget.disclosure_window_start,
            "redaction disclosure window must be increasing"
        );
        let id = budget.redaction_budget_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        self.refresh_counters();
        Ok(id)
    }

    pub fn spend_redaction_budget(&mut self, budget_id: &str, fields: u64) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown redaction budget: {budget_id}"))?;
        ensure!(
            budget.status.can_spend(),
            "redaction budget cannot be spent"
        );
        ensure!(
            budget.remaining_fields() >= fields,
            "redaction budget has insufficient fields"
        );
        budget.spent_redacted_fields = budget.spent_redacted_fields.saturating_add(fields);
        self.counters.redacted_fields = self.counters.redacted_fields.saturating_add(fields);
        if budget.remaining_fields() == 0 {
            budget.status = BudgetStatus::Depleted;
        }
        Ok(())
    }

    pub fn upsert_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        let id = operator_summary_key(&summary.operator_id, summary.epoch);
        self.operator_summaries.insert(id.clone(), summary);
        self.refresh_counters();
        Ok(id)
    }

    fn recompute_committee_weight(&mut self) {
        let mut totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for member in self.members.values() {
            if member.status.can_vote() {
                let entry = totals
                    .entry(member.committee_id.clone())
                    .or_insert((0_u64, 0_u64));
                entry.0 = entry.0.saturating_add(member.weight);
                entry.1 = entry.1.saturating_add(1);
            }
        }
        for committee in self.committees.values_mut() {
            let (weight, count) = totals
                .get(&committee.committee_id)
                .copied()
                .unwrap_or((0, 0));
            committee.total_weight = weight;
            committee.active_members = count;
            committee.threshold_weight = bps_threshold(weight, self.config.quorum_bps);
        }
    }

    fn refresh_counters(&mut self) {
        self.counters.feeds = self.feeds.len() as u64;
        self.counters.committees = self.committees.len() as u64;
        self.counters.members = self.members.len() as u64;
        self.counters.private_roots = self.private_roots.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.callback_receipts = self.callback_receipts.len() as u64;
        self.counters.access_budgets = self.access_budgets.len() as u64;
        self.counters.fee_sponsors = self.fee_sponsors.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
    }
}

pub fn public_record(state: &State) -> Value {
    let roots = state.roots();
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "public_record_scheme": PUBLIC_RECORD_SCHEME,
        "height": state.height,
        "epoch": state.epoch,
        "config": state.config.public_record(),
        "roots": roots.public_record(),
        "counters": state.counters.public_record(),
        "state_root": roots.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    domain_hash(
        "P2P-CC-ENC-CHECKPOINT-ORACLE-STATE",
        &[HashPart::Json(&state.roots().public_record())],
        32,
    )
}

pub fn demo() -> State {
    devnet()
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH);

    let publisher_committee = devnet_committee(
        "committee-feed-publishers",
        CommitteePurpose::FeedPublisher,
        9,
    );
    let root_committee = devnet_committee(
        "committee-root-witnesses",
        CommitteePurpose::RootWitness,
        11,
    );
    let attestor_committee =
        devnet_committee("committee-pq-attestors", CommitteePurpose::PqAttestor, 13);
    let callback_committee = devnet_committee(
        "committee-callback-executors",
        CommitteePurpose::CallbackExecutor,
        7,
    );
    let reviewer_committee = devnet_committee(
        "committee-redaction-reviewers",
        CommitteePurpose::RedactionReviewer,
        5,
    );

    for committee in [
        publisher_committee,
        root_committee,
        attestor_committee,
        callback_committee,
        reviewer_committee,
    ] {
        state
            .register_committee(committee)
            .expect("devnet committee registration");
    }

    let committee_ids = state.committees.keys().cloned().collect::<Vec<_>>();
    for committee_id in committee_ids {
        for idx in 0..5 {
            let member = devnet_member(&committee_id, idx);
            state
                .register_member(member)
                .expect("devnet member registration");
        }
    }

    let sponsor = FeeSponsor {
        sponsor_id: "devnet-oracle-sponsor-0".to_string(),
        sponsor_commitment: stable_hash("devnet-sponsor-commitment", &["devnet-oracle-sponsor-0"]),
        status: SponsorStatus::Active,
        max_fee_micro_credits: 2_000_000,
        spent_fee_micro_credits: 0,
        allowed_contract_root: stable_hash("devnet-sponsor-allowed-contracts", &["all-devnet"]),
        authorization_root: stable_hash("devnet-sponsor-authorization", &["sponsor-auth-0"]),
        rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
    };
    state.register_fee_sponsor(sponsor).expect("devnet sponsor");

    let access_budget = AccessBudget {
        budget_id: "devnet-access-budget-dex-0".to_string(),
        contract_id: "devnet-confidential-dex".to_string(),
        owner_commitment: stable_hash("devnet-access-owner", &["dex-operator"]),
        status: BudgetStatus::Open,
        window_start_height: DEVNET_HEIGHT,
        window_end_height: DEVNET_HEIGHT + DEFAULT_ACCESS_WINDOW_BLOCKS,
        max_weight: 1_000,
        spent_weight: 0,
        nullifier_root: stable_hash("devnet-access-nullifiers", &["dex-budget"]),
    };
    state
        .register_access_budget(access_budget)
        .expect("devnet access budget");

    let redaction_budget = RedactionBudget {
        redaction_budget_id: "devnet-redaction-budget-dex-0".to_string(),
        contract_id: "devnet-confidential-dex".to_string(),
        reviewer_committee_id: "committee-redaction-reviewers".to_string(),
        status: BudgetStatus::Open,
        max_redacted_fields: 64,
        spent_redacted_fields: 0,
        disclosure_window_start: DEVNET_HEIGHT,
        disclosure_window_end: DEVNET_HEIGHT + DEFAULT_REDACTION_WINDOW_BLOCKS,
        policy_root: stable_hash("devnet-redaction-policy", &["dex-policy"]),
    };
    state
        .register_redaction_budget(redaction_budget)
        .expect("devnet redaction budget");

    let mut feed = EncryptedCheckpointFeed::new(
        "devnet-feed-dex-checkpoint-0",
        "devnet-confidential-dex",
        ContractDomain::Dex,
        FeedKind::StateCheckpoint,
        "committee-feed-publishers",
        "committee-root-witnesses",
        DEVNET_HEIGHT - 4,
        DEVNET_HEIGHT,
    );
    feed.sponsor_id = Some("devnet-oracle-sponsor-0".to_string());
    feed.callback_target = Some("devnet-confidential-dex::checkpoint_callback".to_string());
    state.publish_feed(feed).expect("devnet feed");

    let root = PrivateCheckpointRoot {
        root_id: "devnet-private-root-dex-0".to_string(),
        feed_id: "devnet-feed-dex-checkpoint-0".to_string(),
        contract_id: "devnet-confidential-dex".to_string(),
        status: RootStatus::Proposed,
        private_root_commitment: stable_hash("devnet-private-root", &["dex-root-0"]),
        encrypted_delta_root: stable_hash("devnet-encrypted-delta", &["dex-root-0"]),
        nullifier_root: stable_hash("devnet-nullifier-root", &["dex-root-0"]),
        witness_commitment_root: stable_hash("devnet-witness-root", &["dex-root-0"]),
        root_height: DEVNET_HEIGHT,
        finalized_height: None,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_ROOT_TTL_BLOCKS,
        attested_weight: 0,
        redaction_budget_id: Some("devnet-redaction-budget-dex-0".to_string()),
    };
    state.commit_private_root(root).expect("devnet root");

    for idx in 0..4 {
        let attestation = devnet_attestation(
            idx,
            "devnet-private-root-dex-0",
            "devnet-feed-dex-checkpoint-0",
            "committee-pq-attestors",
        );
        state
            .submit_attestation(attestation)
            .expect("devnet attestation");
    }

    if let Some(root) = state.private_roots.get_mut("devnet-private-root-dex-0") {
        root.status = RootStatus::Finalized;
        root.finalized_height = Some(DEVNET_HEIGHT + 2);
    }

    let receipt = CallbackReceipt {
        receipt_id: "devnet-callback-receipt-dex-0".to_string(),
        root_id: "devnet-private-root-dex-0".to_string(),
        feed_id: "devnet-feed-dex-checkpoint-0".to_string(),
        contract_id: "devnet-confidential-dex".to_string(),
        callback_target_hash: stable_hash(
            "callback-target",
            &["devnet-confidential-dex::checkpoint_callback"],
        ),
        status: CallbackStatus::Delivered,
        payload_root: stable_hash("devnet-callback-payload", &["dex-root-0"]),
        delivery_height: DEVNET_HEIGHT + 3,
        gas_used: 81_000,
        fee_micro_credits: DEFAULT_CALLBACK_FEE_MICRO_CREDITS,
        sponsor_id: Some("devnet-oracle-sponsor-0".to_string()),
    };
    state.deliver_callback(receipt).expect("devnet callback");

    let summary = OperatorSummary {
        operator_id: "devnet-operator-0".to_string(),
        epoch: DEVNET_EPOCH,
        committee_count: 5,
        feed_count: 1,
        attestation_count: 4,
        callback_count: 1,
        accepted_weight: 4,
        rejected_weight: 0,
        earned_fee_micro_credits: DEFAULT_CALLBACK_FEE_MICRO_CREDITS,
        slash_count: 0,
        summary_root: stable_hash("devnet-operator-summary", &["devnet-operator-0"]),
    };
    state
        .upsert_operator_summary(summary)
        .expect("devnet operator summary");

    state.validate().expect("valid devnet state");
    state
}

fn devnet_committee(id: &str, purpose: CommitteePurpose, active_members: u64) -> OracleCommittee {
    let total_weight = active_members;
    OracleCommittee {
        committee_id: id.to_string(),
        purpose,
        epoch: DEVNET_EPOCH,
        threshold_weight: bps_threshold(total_weight, DEFAULT_QUORUM_BPS),
        total_weight,
        active_members,
        min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        rotation_root: stable_hash("devnet-committee-rotation", &[id, purpose.as_str()]),
        stake_root: stable_hash("devnet-committee-stake", &[id, purpose.as_str()]),
        status: "active".to_string(),
    }
}

fn devnet_member(committee_id: &str, idx: u64) -> OracleMember {
    let member_id = format!("{committee_id}-member-{idx}");
    OracleMember {
        member_id: member_id.clone(),
        committee_id: committee_id.to_string(),
        operator_id: format!("devnet-operator-{}", idx % 3),
        status: MemberStatus::Active,
        weight: 1,
        pq_identity_root: stable_hash("devnet-member-pq-identity", &[&member_id]),
        view_key_commitment: stable_hash("devnet-member-view-key", &[&member_id]),
        last_attested_height: DEVNET_HEIGHT.saturating_sub(idx),
        slash_count: 0,
    }
}

fn devnet_attestation(
    idx: u64,
    root_id: &str,
    feed_id: &str,
    committee_id: &str,
) -> PqCheckpointAttestation {
    let member_id = format!("{committee_id}-member-{idx}");
    let attestation_id = format!("devnet-attestation-{idx}");
    let transcript_hash = stable_hash(
        "devnet-attestation-transcript",
        &[&attestation_id, root_id, feed_id, &member_id],
    );
    PqCheckpointAttestation {
        attestation_id: attestation_id.clone(),
        root_id: root_id.to_string(),
        feed_id: feed_id.to_string(),
        committee_id: committee_id.to_string(),
        member_id,
        verdict: AttestationVerdict::ValidWithRedactions,
        attested_weight: 1,
        transcript_hash: transcript_hash.clone(),
        ml_dsa_signature_hash: stable_hash("devnet-ml-dsa-sig", &[&transcript_hash]),
        slh_dsa_signature_hash: stable_hash("devnet-slh-dsa-sig", &[&transcript_hash]),
        redacted_fields: idx % 2,
        issued_at_height: DEVNET_HEIGHT + idx,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
    }
}

fn bps_threshold(total_weight: u64, bps: u64) -> u64 {
    if total_weight == 0 {
        return 0;
    }
    total_weight.saturating_mul(bps).saturating_add(MAX_BPS - 1) / MAX_BPS
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn stable_hash(domain: &str, parts: &[&str]) -> String {
    let material = parts
        .iter()
        .enumerate()
        .map(|(idx, value)| json!({ "index": idx, "value": value }))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("P2P-CC-ENC-CHECKPOINT-{domain}"),
        &[HashPart::Json(&json!(material))],
        32,
    )
}

fn operator_summary_key(operator_id: &str, epoch: u64) -> String {
    stable_hash("operator-summary-key", &[operator_id, &epoch.to_string()])
}

pub fn encrypted_feed_id(contract_id: &str, kind: FeedKind, checkpoint_height: u64) -> String {
    stable_hash(
        "feed-id",
        &[contract_id, kind.as_str(), &checkpoint_height.to_string()],
    )
}

pub fn private_checkpoint_root_id(feed_id: &str, private_root_commitment: &str) -> String {
    stable_hash("private-root-id", &[feed_id, private_root_commitment])
}

pub fn checkpoint_attestation_id(root_id: &str, member_id: &str, transcript_hash: &str) -> String {
    stable_hash("attestation-id", &[root_id, member_id, transcript_hash])
}

pub fn callback_receipt_id(
    root_id: &str,
    callback_target_hash: &str,
    delivery_height: u64,
) -> String {
    stable_hash(
        "callback-receipt-id",
        &[root_id, callback_target_hash, &delivery_height.to_string()],
    )
}

pub fn access_budget_id(
    contract_id: &str,
    owner_commitment: &str,
    window_start_height: u64,
) -> String {
    stable_hash(
        "access-budget-id",
        &[
            contract_id,
            owner_commitment,
            &window_start_height.to_string(),
        ],
    )
}

pub fn fee_sponsor_id(sponsor_commitment: &str, authorization_root: &str) -> String {
    stable_hash("fee-sponsor-id", &[sponsor_commitment, authorization_root])
}

pub fn redaction_budget_id(
    contract_id: &str,
    policy_root: &str,
    disclosure_window_start: u64,
) -> String {
    stable_hash(
        "redaction-budget-id",
        &[
            contract_id,
            policy_root,
            &disclosure_window_start.to_string(),
        ],
    )
}
