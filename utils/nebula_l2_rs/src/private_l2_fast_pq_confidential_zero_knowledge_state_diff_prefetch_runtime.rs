use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialZeroKnowledgeStateDiffPrefetchRuntimeResult<T> = Result<T>;
pub type Runtime = State;
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_KNOWLEDGE_STATE_DIFF_PREFETCH_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-fast-pq-confidential-zero-knowledge-state-diff-prefetch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_KNOWLEDGE_STATE_DIFF_PREFETCH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_PROVER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-zk-state-diff-prefetch-v1";
pub const PQ_ENVELOPE_SUITE: &str = "ML-KEM-1024-threshold-confidential-state-diff-envelope-v1";
pub const ZK_PREFETCH_PROOF_SUITE: &str = "nova-pq-confidential-state-diff-prefetch-proof-v1";
pub const ENCRYPTED_STATE_DIFF_SHARD_SUITE: &str = "private-l2-encrypted-state-diff-shard-v1";
pub const CACHE_LEASE_SUITE: &str = "private-l2-state-diff-prefetch-cache-lease-v1";
pub const INVALIDATION_FENCE_SUITE: &str = "private-l2-state-diff-invalidation-fence-v1";
pub const LOW_FEE_PROOF_CREDIT_SUITE: &str = "low-fee-zk-state-diff-proof-credit-v1";
pub const WITNESS_REDACTION_SUITE: &str = "privacy-budgeted-state-diff-witness-redaction-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-state-diff-prefetch-summary-root-v1";
pub const DEVNET_L2_HEIGHT: u64 = 3_120_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_020_000;
pub const DEVNET_EPOCH: u64 = 24_576;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 72;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 280;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_SHARD_COUNT: u16 = 32;
pub const DEFAULT_MAX_DIFF_BYTES: u64 = 8 * 1_048_576;
pub const DEFAULT_CACHE_LEASE_TTL_SLOTS: u64 = 48;
pub const DEFAULT_TICKET_TTL_SLOTS: u64 = 40;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 64;
pub const DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_TARGET_LOW_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_LOW_FEE_BPS: u64 = 16;
pub const DEFAULT_PROOF_CREDIT_BPS: u64 = 750;
pub const DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_SHARDS: usize = 1_048_576;
pub const DEFAULT_MAX_TICKETS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_LEASES: usize = 1_048_576;
pub const DEFAULT_MAX_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_CREDITS: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTIONS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 2_097_152;
const D_STATE: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:ROOTS";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:SHARDS";
const D_TICKETS: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TICKETS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:ATTESTATIONS";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:LEASES";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:FENCES";
const D_CREDITS: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:CREDITS";
const D_REDACTIONS: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:REDACTIONS";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:SUMMARIES";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:PUBLIC";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}
impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateDiffShardKind {
    AccountDelta,
    ContractStorageDelta,
    NullifierDelta,
    CommitmentDelta,
    BridgeSettlementDelta,
    FeeMarketDelta,
    ProofCarryDelta,
    WalletSyncDelta,
}
impl StateDiffShardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountDelta => "account_delta",
            Self::ContractStorageDelta => "contract_storage_delta",
            Self::NullifierDelta => "nullifier_delta",
            Self::CommitmentDelta => "commitment_delta",
            Self::BridgeSettlementDelta => "bridge_settlement_delta",
            Self::FeeMarketDelta => "fee_market_delta",
            Self::ProofCarryDelta => "proof_carry_delta",
            Self::WalletSyncDelta => "wallet_sync_delta",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Announced,
    Encrypted,
    Warmed,
    Proving,
    Sealed,
    Fenced,
    Retired,
}
impl ShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Encrypted => "encrypted",
            Self::Warmed => "warmed",
            Self::Proving => "proving",
            Self::Sealed => "sealed",
            Self::Fenced => "fenced",
            Self::Retired => "retired",
        }
    }
    pub fn accepts_prefetch(self) -> bool {
        matches!(self, Self::Announced | Self::Encrypted | Self::Warmed)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Requested,
    Reserved,
    Prefetching,
    WitnessReady,
    ProofReady,
    Consumed,
    Expired,
    Cancelled,
}
impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Reserved => "reserved",
            Self::Prefetching => "prefetching",
            Self::WitnessReady => "witness_ready",
            Self::ProofReady => "proof_ready",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Requested
                | Self::Reserved
                | Self::Prefetching
                | Self::WitnessReady
                | Self::ProofReady
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Reject,
}
impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLeaseStatus {
    Open,
    Pinned,
    Hot,
    Cooling,
    Released,
    Expired,
}
impl CacheLeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Pinned => "pinned",
            Self::Hot => "hot",
            Self::Cooling => "cooling",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationFenceKind {
    NullifierWindow,
    ContractEpoch,
    ViewTagCohort,
    OperatorRotation,
    FeeMarketReprice,
    BridgeReorg,
}
impl InvalidationFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierWindow => "nullifier_window",
            Self::ContractEpoch => "contract_epoch",
            Self::ViewTagCohort => "view_tag_cohort",
            Self::OperatorRotation => "operator_rotation",
            Self::FeeMarketReprice => "fee_market_reprice",
            Self::BridgeReorg => "bridge_reorg",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    FullWitness,
    ReadSetOnly,
    WriteSetOnly,
    FeeFields,
    OperatorHints,
    WalletTags,
}
impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullWitness => "full_witness",
            Self::ReadSetOnly => "read_set_only",
            Self::WriteSetOnly => "write_set_only",
            Self::FeeFields => "fee_fields",
            Self::OperatorHints => "operator_hints",
            Self::WalletTags => "wallet_tags",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub runtime_mode: RuntimeMode,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub slot_width_ms: u64,
    pub shard_count: u16,
    pub max_diff_bytes: u64,
    pub cache_lease_ttl_slots: u64,
    pub ticket_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub invalidation_fence_ttl_blocks: u64,
    pub target_low_fee_bps: u64,
    pub max_low_fee_bps: u64,
    pub proof_credit_bps: u64,
    pub min_operator_bond_micro_units: u64,
    pub redaction_budget_units: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_shards: usize,
    pub max_tickets: usize,
    pub max_attestations: usize,
    pub max_leases: usize,
    pub max_fences: usize,
    pub max_credits: usize,
    pub max_redactions: usize,
    pub max_operator_summaries: usize,
    pub max_public_records: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            runtime_mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            shard_count: DEFAULT_SHARD_COUNT,
            max_diff_bytes: DEFAULT_MAX_DIFF_BYTES,
            cache_lease_ttl_slots: DEFAULT_CACHE_LEASE_TTL_SLOTS,
            ticket_ttl_slots: DEFAULT_TICKET_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            invalidation_fence_ttl_blocks: DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS,
            target_low_fee_bps: DEFAULT_TARGET_LOW_FEE_BPS,
            max_low_fee_bps: DEFAULT_MAX_LOW_FEE_BPS,
            proof_credit_bps: DEFAULT_PROOF_CREDIT_BPS,
            min_operator_bond_micro_units: DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_shards: DEFAULT_MAX_SHARDS,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_leases: DEFAULT_MAX_LEASES,
            max_fences: DEFAULT_MAX_FENCES,
            max_credits: DEFAULT_MAX_CREDITS,
            max_redactions: DEFAULT_MAX_REDACTIONS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure_bps("target_low_fee_bps", self.target_low_fee_bps)?;
        ensure_bps("max_low_fee_bps", self.max_low_fee_bps)?;
        ensure_bps("proof_credit_bps", self.proof_credit_bps)?;
        ensure_bps("quorum_weight_bps", self.quorum_weight_bps)?;
        ensure_bps("supermajority_weight_bps", self.supermajority_weight_bps)?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("privacy set target must cover minimum".to_string());
        }
        if self.target_prefetch_ms == 0 || self.target_prefetch_ms > self.max_prefetch_ms {
            return Err("prefetch latency target must be within max".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"config","protocol_version":self.protocol_version,"chain_id":self.chain_id,"runtime_mode":self.runtime_mode.as_str(),"l2_network":self.l2_network,"fee_asset_id":self.fee_asset_id,"min_pq_security_bits":self.min_pq_security_bits,"min_privacy_set_size":self.min_privacy_set_size,"target_privacy_set_size":self.target_privacy_set_size,"target_prefetch_ms":self.target_prefetch_ms,"max_prefetch_ms":self.max_prefetch_ms,"slot_width_ms":self.slot_width_ms,"shard_count":self.shard_count,"max_diff_bytes":self.max_diff_bytes,"cache_lease_ttl_slots":self.cache_lease_ttl_slots,"ticket_ttl_slots":self.ticket_ttl_slots,"attestation_ttl_slots":self.attestation_ttl_slots,"invalidation_fence_ttl_blocks":self.invalidation_fence_ttl_blocks,"target_low_fee_bps":self.target_low_fee_bps,"max_low_fee_bps":self.max_low_fee_bps,"proof_credit_bps":self.proof_credit_bps,"min_operator_bond_micro_units":self.min_operator_bond_micro_units,"redaction_budget_units":self.redaction_budget_units,"quorum_weight_bps":self.quorum_weight_bps,"supermajority_weight_bps":self.supermajority_weight_bps,"limits":{"max_shards":self.max_shards,"max_tickets":self.max_tickets,"max_attestations":self.max_attestations,"max_leases":self.max_leases,"max_fences":self.max_fences,"max_credits":self.max_credits,"max_redactions":self.max_redactions,"max_operator_summaries":self.max_operator_summaries,"max_public_records":self.max_public_records}})
    }
    pub fn state_root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub shard_count: u64,
    pub ticket_count: u64,
    pub attestation_count: u64,
    pub lease_count: u64,
    pub fence_count: u64,
    pub credit_count: u64,
    pub redaction_count: u64,
    pub operator_summary_count: u64,
    pub public_record_count: u64,
    pub encrypted_diff_bytes: u64,
    pub warmed_diff_bytes: u64,
    pub prepared_witness_bytes: u64,
    pub proof_credit_micro_units: u64,
    pub avoided_fee_micro_units: u64,
    pub redacted_witness_bytes: u64,
}
impl Counters {
    pub fn allocate_sequence(&mut self) -> u64 {
        let v = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        v
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"counters","protocol_version":PROTOCOL_VERSION,"next_sequence":self.next_sequence,"shard_count":self.shard_count,"ticket_count":self.ticket_count,"attestation_count":self.attestation_count,"lease_count":self.lease_count,"fence_count":self.fence_count,"credit_count":self.credit_count,"redaction_count":self.redaction_count,"operator_summary_count":self.operator_summary_count,"public_record_count":self.public_record_count,"encrypted_diff_bytes":self.encrypted_diff_bytes,"warmed_diff_bytes":self.warmed_diff_bytes,"prepared_witness_bytes":self.prepared_witness_bytes,"proof_credit_micro_units":self.proof_credit_micro_units,"avoided_fee_micro_units":self.avoided_fee_micro_units,"redacted_witness_bytes":self.redacted_witness_bytes})
    }
    pub fn state_root(&self) -> String {
        payload_root(D_COUNTERS, &self.public_record())
    }
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub shards_root: String,
    pub tickets_root: String,
    pub attestations_root: String,
    pub leases_root: String,
    pub fences_root: String,
    pub credits_root: String,
    pub redactions_root: String,
    pub operator_summaries_root: String,
    pub public_records_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({"kind":"roots","protocol_version":PROTOCOL_VERSION,"config_root":self.config_root,"counters_root":self.counters_root,"shards_root":self.shards_root,"tickets_root":self.tickets_root,"attestations_root":self.attestations_root,"leases_root":self.leases_root,"fences_root":self.fences_root,"credits_root":self.credits_root,"redactions_root":self.redactions_root,"operator_summaries_root":self.operator_summaries_root,"public_records_root":self.public_records_root,"state_root":self.state_root})
    }
    pub fn state_root_without_self(&self) -> String {
        payload_root(
            D_ROOTS,
            &json!({"config_root":self.config_root,"counters_root":self.counters_root,"shards_root":self.shards_root,"tickets_root":self.tickets_root,"attestations_root":self.attestations_root,"leases_root":self.leases_root,"fences_root":self.fences_root,"credits_root":self.credits_root,"redactions_root":self.redactions_root,"operator_summaries_root":self.operator_summaries_root,"public_records_root":self.public_records_root}),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedStateDiffShard {
    pub shard_id: String,
    pub shard_kind: StateDiffShardKind,
    pub status: ShardStatus,
    pub source_state_root: String,
    pub target_state_root: String,
    pub encrypted_diff_root: String,
    pub diff_commitment_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub nullifier_delta_root: String,
    pub view_tag_root: String,
    pub pq_envelope_root: String,
    pub assigned_operator: String,
    pub privacy_set_size: u64,
    pub encrypted_bytes: u64,
    pub witness_bytes: u64,
    pub fee_hint_micro_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}
impl EncryptedStateDiffShard {
    pub fn new(
        k: StateDiffShardKind,
        src: impl Into<String>,
        dst: impl Into<String>,
        op: impl Into<String>,
        encrypted_bytes: u64,
        witness_bytes: u64,
        height: u64,
        sequence: u64,
    ) -> Self {
        let source_state_root = src.into();
        let target_state_root = dst.into();
        let assigned_operator = op.into();
        let encrypted_diff_root = runtime_id(
            "ENCRYPTED-DIFF",
            &[HashPart::Str(&target_state_root), HashPart::U64(sequence)],
        );
        let diff_commitment_root = runtime_id(
            "DIFF-COMMITMENT",
            &[
                HashPart::Str(&source_state_root),
                HashPart::Str(&target_state_root),
            ],
        );
        let read_set_root = runtime_id("DIFF-READ-SET", &[HashPart::Str(&diff_commitment_root)]);
        let write_set_root = runtime_id("DIFF-WRITE-SET", &[HashPart::Str(&diff_commitment_root)]);
        let nullifier_delta_root = runtime_id(
            "DIFF-NULLIFIER-DELTA",
            &[HashPart::Str(&diff_commitment_root)],
        );
        let view_tag_root = runtime_id("DIFF-VIEW-TAGS", &[HashPart::Str(&diff_commitment_root)]);
        let pq_envelope_root = runtime_id(
            "DIFF-PQ-ENVELOPE",
            &[
                HashPart::Str(&encrypted_diff_root),
                HashPart::Str(&assigned_operator),
            ],
        );
        let mut r = Self {
            shard_id: String::new(),
            shard_kind: k,
            status: ShardStatus::Encrypted,
            source_state_root,
            target_state_root,
            encrypted_diff_root,
            diff_commitment_root,
            read_set_root,
            write_set_root,
            nullifier_delta_root,
            view_tag_root,
            pq_envelope_root,
            assigned_operator,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            encrypted_bytes,
            witness_bytes,
            fee_hint_micro_units: quote_low_fee_micro_units(
                encrypted_bytes,
                DEFAULT_TARGET_LOW_FEE_BPS,
            ),
            created_at_height: height,
            expires_at_height: height.saturating_add(DEFAULT_CACHE_LEASE_TTL_SLOTS),
            sequence,
        };
        r.shard_id = encrypted_state_diff_shard_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"encrypted_state_diff_shard","protocol_version":PROTOCOL_VERSION,"suite":ENCRYPTED_STATE_DIFF_SHARD_SUITE,"chain_id":CHAIN_ID,"shard_id":self.shard_id,"shard_kind":self.shard_kind.as_str(),"status":self.status.as_str(),"source_state_root":self.source_state_root,"target_state_root":self.target_state_root,"encrypted_diff_root":self.encrypted_diff_root,"diff_commitment_root":self.diff_commitment_root,"read_set_root":self.read_set_root,"write_set_root":self.write_set_root,"nullifier_delta_root":self.nullifier_delta_root,"view_tag_root":self.view_tag_root,"pq_envelope_root":self.pq_envelope_root,"assigned_operator":self.assigned_operator,"privacy_set_size":self.privacy_set_size,"encrypted_bytes":self.encrypted_bytes,"witness_bytes":self.witness_bytes,"fee_hint_micro_units":self.fee_hint_micro_units,"created_at_height":self.created_at_height,"expires_at_height":self.expires_at_height,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(ENCRYPTED_STATE_DIFF_SHARD_SUITE, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ZkPrefetchTicket {
    pub ticket_id: String,
    pub shard_id: String,
    pub requester_commitment: String,
    pub status: TicketStatus,
    pub priority_lane: String,
    pub proof_program_root: String,
    pub witness_plan_root: String,
    pub privacy_budget_bps: u64,
    pub max_fee_micro_units: u64,
    pub target_prefetch_ms: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}
impl ZkPrefetchTicket {
    pub fn for_shard(
        shard: &EncryptedStateDiffShard,
        requester_commitment: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let requester_commitment = requester_commitment.into();
        let proof_program_root = runtime_id(
            "ZK-PREFETCH-PROGRAM",
            &[HashPart::Str(&shard.diff_commitment_root)],
        );
        let witness_plan_root = runtime_id(
            "ZK-WITNESS-PLAN",
            &[
                HashPart::Str(&shard.read_set_root),
                HashPart::Str(&shard.write_set_root),
            ],
        );
        let mut r = Self {
            ticket_id: String::new(),
            shard_id: shard.shard_id.clone(),
            requester_commitment,
            status: TicketStatus::Reserved,
            priority_lane: "low_fee_fast_path".to_string(),
            proof_program_root,
            witness_plan_root,
            privacy_budget_bps: 2_500,
            max_fee_micro_units: shard.fee_hint_micro_units,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            reserved_at_height: shard.created_at_height,
            expires_at_height: shard
                .created_at_height
                .saturating_add(DEFAULT_TICKET_TTL_SLOTS),
            sequence,
        };
        r.ticket_id = zk_prefetch_ticket_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"zk_prefetch_ticket","protocol_version":PROTOCOL_VERSION,"suite":ZK_PREFETCH_PROOF_SUITE,"chain_id":CHAIN_ID,"ticket_id":self.ticket_id,"shard_id":self.shard_id,"requester_commitment":self.requester_commitment,"status":self.status.as_str(),"priority_lane":self.priority_lane,"proof_program_root":self.proof_program_root,"witness_plan_root":self.witness_plan_root,"privacy_budget_bps":self.privacy_budget_bps,"max_fee_micro_units":self.max_fee_micro_units,"target_prefetch_ms":self.target_prefetch_ms,"reserved_at_height":self.reserved_at_height,"expires_at_height":self.expires_at_height,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(ZK_PREFETCH_PROOF_SUITE, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqProverAttestation {
    pub attestation_id: String,
    pub ticket_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub verdict: AttestationVerdict,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub proof_input_root: String,
    pub prepared_witness_root: String,
    pub prover_capability_root: String,
    pub latency_ms: u64,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}
impl PqProverAttestation {
    pub fn include(
        ticket: &ZkPrefetchTicket,
        shard: &EncryptedStateDiffShard,
        operator_id: impl Into<String>,
        latency_ms: u64,
        sequence: u64,
    ) -> Self {
        let operator_id = operator_id.into();
        let proof_input_root = runtime_id(
            "PROOF-INPUT",
            &[
                HashPart::Str(&ticket.proof_program_root),
                HashPart::Str(&shard.diff_commitment_root),
            ],
        );
        let prepared_witness_root = runtime_id(
            "PREPARED-WITNESS",
            &[
                HashPart::Str(&ticket.witness_plan_root),
                HashPart::Str(&shard.pq_envelope_root),
            ],
        );
        let prover_capability_root = runtime_id(
            "PROVER-CAPABILITY",
            &[HashPart::Str(&operator_id), HashPart::U64(latency_ms)],
        );
        let pq_public_key_root = runtime_id("PQ-PROVER-PUBLIC-KEY", &[HashPart::Str(&operator_id)]);
        let signature_root = runtime_id(
            "PQ-PROVER-SIGNATURE",
            &[
                HashPart::Str(&prepared_witness_root),
                HashPart::Str(&pq_public_key_root),
            ],
        );
        let mut r = Self {
            attestation_id: String::new(),
            ticket_id: ticket.ticket_id.clone(),
            shard_id: shard.shard_id.clone(),
            operator_id,
            verdict: AttestationVerdict::Include,
            pq_public_key_root,
            signature_root,
            proof_input_root,
            prepared_witness_root,
            prover_capability_root,
            latency_ms,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attested_at_height: ticket.reserved_at_height,
            expires_at_height: ticket
                .reserved_at_height
                .saturating_add(DEFAULT_ATTESTATION_TTL_SLOTS),
            sequence,
        };
        r.attestation_id = pq_prover_attestation_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"pq_prover_attestation","protocol_version":PROTOCOL_VERSION,"suite":PQ_PROVER_ATTESTATION_SUITE,"chain_id":CHAIN_ID,"attestation_id":self.attestation_id,"ticket_id":self.ticket_id,"shard_id":self.shard_id,"operator_id":self.operator_id,"verdict":self.verdict.as_str(),"pq_public_key_root":self.pq_public_key_root,"signature_root":self.signature_root,"proof_input_root":self.proof_input_root,"prepared_witness_root":self.prepared_witness_root,"prover_capability_root":self.prover_capability_root,"latency_ms":self.latency_ms,"security_bits":self.security_bits,"attested_at_height":self.attested_at_height,"expires_at_height":self.expires_at_height,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(PQ_PROVER_ATTESTATION_SUITE, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub ticket_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub status: CacheLeaseStatus,
    pub cache_key_root: String,
    pub hotset_root: String,
    pub bytes_pinned: u64,
    pub hit_probability_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}
impl CacheLease {
    pub fn for_ticket(
        ticket: &ZkPrefetchTicket,
        shard: &EncryptedStateDiffShard,
        operator_id: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let operator_id = operator_id.into();
        let cache_key_root = runtime_id(
            "STATE-DIFF-CACHE-KEY",
            &[
                HashPart::Str(&ticket.ticket_id),
                HashPart::Str(&shard.encrypted_diff_root),
            ],
        );
        let hotset_root = runtime_id(
            "STATE-DIFF-HOTSET",
            &[HashPart::Str(&cache_key_root), HashPart::Str(&operator_id)],
        );
        let mut r = Self {
            lease_id: String::new(),
            ticket_id: ticket.ticket_id.clone(),
            shard_id: shard.shard_id.clone(),
            operator_id,
            status: CacheLeaseStatus::Hot,
            cache_key_root,
            hotset_root,
            bytes_pinned: shard.encrypted_bytes.saturating_add(shard.witness_bytes),
            hit_probability_bps: 9_350,
            opened_at_height: ticket.reserved_at_height,
            expires_at_height: ticket
                .reserved_at_height
                .saturating_add(DEFAULT_CACHE_LEASE_TTL_SLOTS),
            sequence,
        };
        r.lease_id = cache_lease_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"cache_lease","protocol_version":PROTOCOL_VERSION,"suite":CACHE_LEASE_SUITE,"chain_id":CHAIN_ID,"lease_id":self.lease_id,"ticket_id":self.ticket_id,"shard_id":self.shard_id,"operator_id":self.operator_id,"status":self.status.as_str(),"cache_key_root":self.cache_key_root,"hotset_root":self.hotset_root,"bytes_pinned":self.bytes_pinned,"hit_probability_bps":self.hit_probability_bps,"opened_at_height":self.opened_at_height,"expires_at_height":self.expires_at_height,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(CACHE_LEASE_SUITE, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub fence_kind: InvalidationFenceKind,
    pub affected_root: String,
    pub replacement_root: String,
    pub reason_code: String,
    pub applies_from_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}
impl InvalidationFence {
    pub fn for_shard(
        shard: &EncryptedStateDiffShard,
        fence_kind: InvalidationFenceKind,
        reason_code: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let reason_code = reason_code.into();
        let replacement_root = runtime_id(
            "FENCE-REPLACEMENT",
            &[
                HashPart::Str(&shard.target_state_root),
                HashPart::Str(&reason_code),
            ],
        );
        let mut r = Self {
            fence_id: String::new(),
            fence_kind,
            affected_root: shard.diff_commitment_root.clone(),
            replacement_root,
            reason_code,
            applies_from_height: shard.created_at_height,
            expires_at_height: shard
                .created_at_height
                .saturating_add(DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS),
            sequence,
        };
        r.fence_id = invalidation_fence_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"invalidation_fence","protocol_version":PROTOCOL_VERSION,"suite":INVALIDATION_FENCE_SUITE,"chain_id":CHAIN_ID,"fence_id":self.fence_id,"fence_kind":self.fence_kind.as_str(),"affected_root":self.affected_root,"replacement_root":self.replacement_root,"reason_code":self.reason_code,"applies_from_height":self.applies_from_height,"expires_at_height":self.expires_at_height,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(INVALIDATION_FENCE_SUITE, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeProofCredit {
    pub credit_id: String,
    pub ticket_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub fee_asset_id: String,
    pub credited_micro_units: u64,
    pub avoided_fee_micro_units: u64,
    pub credit_bps: u64,
    pub low_fee_lane: String,
    pub expires_at_height: u64,
    pub sequence: u64,
}
impl LowFeeProofCredit {
    pub fn for_ticket(
        ticket: &ZkPrefetchTicket,
        shard: &EncryptedStateDiffShard,
        operator_id: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let operator_id = operator_id.into();
        let avoided_fee_micro_units =
            quote_low_fee_micro_units(shard.witness_bytes, DEFAULT_MAX_LOW_FEE_BPS);
        let credited_micro_units =
            avoided_fee_micro_units.saturating_mul(DEFAULT_PROOF_CREDIT_BPS) / MAX_BPS;
        let mut r = Self {
            credit_id: String::new(),
            ticket_id: ticket.ticket_id.clone(),
            shard_id: shard.shard_id.clone(),
            operator_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            credited_micro_units,
            avoided_fee_micro_units,
            credit_bps: DEFAULT_PROOF_CREDIT_BPS,
            low_fee_lane: ticket.priority_lane.clone(),
            expires_at_height: ticket.expires_at_height,
            sequence,
        };
        r.credit_id = low_fee_proof_credit_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"low_fee_proof_credit","protocol_version":PROTOCOL_VERSION,"suite":LOW_FEE_PROOF_CREDIT_SUITE,"chain_id":CHAIN_ID,"credit_id":self.credit_id,"ticket_id":self.ticket_id,"shard_id":self.shard_id,"operator_id":self.operator_id,"fee_asset_id":self.fee_asset_id,"credited_micro_units":self.credited_micro_units,"avoided_fee_micro_units":self.avoided_fee_micro_units,"credit_bps":self.credit_bps,"low_fee_lane":self.low_fee_lane,"expires_at_height":self.expires_at_height,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(LOW_FEE_PROOF_CREDIT_SUITE, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct WitnessRedactionMetadata {
    pub redaction_id: String,
    pub ticket_id: String,
    pub shard_id: String,
    pub scope: RedactionScope,
    pub original_witness_root: String,
    pub redacted_witness_root: String,
    pub disclosure_policy_root: String,
    pub redacted_bytes: u64,
    pub retained_privacy_set_size: u64,
    pub budget_units_spent: u64,
    pub sequence: u64,
}
impl WitnessRedactionMetadata {
    pub fn for_attestation(
        attestation: &PqProverAttestation,
        shard: &EncryptedStateDiffShard,
        scope: RedactionScope,
        sequence: u64,
    ) -> Self {
        let original_witness_root = attestation.prepared_witness_root.clone();
        let redacted_witness_root = runtime_id(
            "REDACTED-WITNESS",
            &[
                HashPart::Str(&original_witness_root),
                HashPart::Str(scope.as_str()),
            ],
        );
        let disclosure_policy_root = runtime_id(
            "DISCLOSURE-POLICY",
            &[HashPart::Str(&redacted_witness_root)],
        );
        let redacted_bytes = shard.witness_bytes / 3;
        let mut r = Self {
            redaction_id: String::new(),
            ticket_id: attestation.ticket_id.clone(),
            shard_id: shard.shard_id.clone(),
            scope,
            original_witness_root,
            redacted_witness_root,
            disclosure_policy_root,
            redacted_bytes,
            retained_privacy_set_size: shard.privacy_set_size,
            budget_units_spent: redacted_bytes / 64,
            sequence,
        };
        r.redaction_id = witness_redaction_metadata_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"witness_redaction_metadata","protocol_version":PROTOCOL_VERSION,"suite":WITNESS_REDACTION_SUITE,"chain_id":CHAIN_ID,"redaction_id":self.redaction_id,"ticket_id":self.ticket_id,"shard_id":self.shard_id,"scope":self.scope.as_str(),"original_witness_root":self.original_witness_root,"redacted_witness_root":self.redacted_witness_root,"disclosure_policy_root":self.disclosure_policy_root,"redacted_bytes":self.redacted_bytes,"retained_privacy_set_size":self.retained_privacy_set_size,"budget_units_spent":self.budget_units_spent,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(WITNESS_REDACTION_SUITE, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub shard_root: String,
    pub ticket_root: String,
    pub attestation_root: String,
    pub lease_root: String,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub cache_hit_bps: u64,
    pub proof_ready_bps: u64,
    pub low_fee_fill_bps: u64,
    pub bonded_micro_units: u64,
    pub sequence: u64,
}
impl OperatorSummary {
    pub fn new(
        operator_id: impl Into<String>,
        window_start_height: u64,
        window_end_height: u64,
        shard_root: impl Into<String>,
        ticket_root: impl Into<String>,
        attestation_root: impl Into<String>,
        lease_root: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let mut r = Self {
            summary_id: String::new(),
            operator_id: operator_id.into(),
            window_start_height,
            window_end_height,
            shard_root: shard_root.into(),
            ticket_root: ticket_root.into(),
            attestation_root: attestation_root.into(),
            lease_root: lease_root.into(),
            median_latency_ms: DEFAULT_TARGET_PREFETCH_MS,
            p95_latency_ms: DEFAULT_MAX_PREFETCH_MS,
            cache_hit_bps: 9_280,
            proof_ready_bps: 9_600,
            low_fee_fill_bps: 9_100,
            bonded_micro_units: DEFAULT_MIN_OPERATOR_BOND_MICRO_UNITS,
            sequence,
        };
        r.summary_id = operator_summary_id(&r.public_record());
        r
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"operator_summary","protocol_version":PROTOCOL_VERSION,"suite":OPERATOR_SUMMARY_SUITE,"chain_id":CHAIN_ID,"summary_id":self.summary_id,"operator_id":self.operator_id,"window_start_height":self.window_start_height,"window_end_height":self.window_end_height,"shard_root":self.shard_root,"ticket_root":self.ticket_root,"attestation_root":self.attestation_root,"lease_root":self.lease_root,"median_latency_ms":self.median_latency_ms,"p95_latency_ms":self.p95_latency_ms,"cache_hit_bps":self.cache_hit_bps,"proof_ready_bps":self.proof_ready_bps,"low_fee_fill_bps":self.low_fee_fill_bps,"bonded_micro_units":self.bonded_micro_units,"sequence":self.sequence})
    }
    pub fn state_root(&self) -> String {
        payload_root(OPERATOR_SUMMARY_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub shards: BTreeMap<String, EncryptedStateDiffShard>,
    pub tickets: BTreeMap<String, ZkPrefetchTicket>,
    pub attestations: BTreeMap<String, PqProverAttestation>,
    pub leases: BTreeMap<String, CacheLease>,
    pub fences: BTreeMap<String, InvalidationFence>,
    pub credits: BTreeMap<String, LowFeeProofCredit>,
    pub redactions: BTreeMap<String, WitnessRedactionMetadata>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_records: BTreeMap<String, Value>,
    pub hot_shards_by_operator: BTreeMap<String, BTreeSet<String>>,
}
impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            shards: BTreeMap::new(),
            tickets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            leases: BTreeMap::new(),
            fences: BTreeMap::new(),
            credits: BTreeMap::new(),
            redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_records: BTreeMap::new(),
            hot_shards_by_operator: BTreeMap::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut s = Self::new(Config::devnet());
        s.seed_devnet_fixture().expect("valid devnet fixture");
        s.refresh_roots();
        s
    }
    pub fn demo() -> Self {
        let mut s = Self::devnet();
        let _ = s.add_prefetch_bundle(
            StateDiffShardKind::FeeMarketDelta,
            "demo-source-state-root",
            "demo-target-state-root",
            "demo-operator-2",
            1_966_080,
            4_194_304,
            DEVNET_L2_HEIGHT + 12,
        );
        s.refresh_roots();
        s
    }
    pub fn add_prefetch_bundle(
        &mut self,
        k: StateDiffShardKind,
        src: impl Into<String>,
        dst: impl Into<String>,
        op: impl Into<String>,
        encrypted_bytes: u64,
        witness_bytes: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        let operator_id = op.into();
        let shard = EncryptedStateDiffShard::new(
            k,
            src,
            dst,
            operator_id.clone(),
            encrypted_bytes,
            witness_bytes,
            height,
            self.counters.allocate_sequence(),
        );
        if shard.encrypted_bytes > self.config.max_diff_bytes {
            return Err("encrypted state diff exceeds configured max bytes".to_string());
        }
        let shard_id = shard.shard_id.clone();
        self.insert_shard(shard)?;
        let requester = runtime_id(
            "REQUESTER",
            &[
                HashPart::Str(&shard_id),
                HashPart::U64(self.counters.next_sequence),
            ],
        );
        let ticket = ZkPrefetchTicket::for_shard(
            self.shards
                .get(&shard_id)
                .ok_or_else(|| "missing shard".to_string())?,
            requester,
            self.counters.allocate_sequence(),
        );
        let ticket_id = ticket.ticket_id.clone();
        self.insert_ticket(ticket)?;
        let att = PqProverAttestation::include(
            self.tickets
                .get(&ticket_id)
                .ok_or_else(|| "missing ticket".to_string())?,
            self.shards
                .get(&shard_id)
                .ok_or_else(|| "missing shard".to_string())?,
            operator_id.clone(),
            self.config.target_prefetch_ms,
            self.counters.allocate_sequence(),
        );
        let att_id = att.attestation_id.clone();
        self.insert_attestation(att)?;
        let lease = CacheLease::for_ticket(
            self.tickets
                .get(&ticket_id)
                .ok_or_else(|| "missing ticket".to_string())?,
            self.shards
                .get(&shard_id)
                .ok_or_else(|| "missing shard".to_string())?,
            operator_id.clone(),
            self.counters.allocate_sequence(),
        );
        self.insert_lease(lease)?;
        let credit = LowFeeProofCredit::for_ticket(
            self.tickets
                .get(&ticket_id)
                .ok_or_else(|| "missing ticket".to_string())?,
            self.shards
                .get(&shard_id)
                .ok_or_else(|| "missing shard".to_string())?,
            operator_id,
            self.counters.allocate_sequence(),
        );
        self.insert_credit(credit)?;
        let redaction = WitnessRedactionMetadata::for_attestation(
            self.attestations
                .get(&att_id)
                .ok_or_else(|| "missing attestation".to_string())?,
            self.shards
                .get(&shard_id)
                .ok_or_else(|| "missing shard".to_string())?,
            RedactionScope::ReadSetOnly,
            self.counters.allocate_sequence(),
        );
        self.insert_redaction(redaction)?;
        self.refresh_operator_summary(&shard_id)?;
        self.refresh_roots();
        Ok(shard_id)
    }
    pub fn insert_shard(&mut self, r: EncryptedStateDiffShard) -> Result<()> {
        if self.shards.len() >= self.config.max_shards {
            return Err("shard capacity exhausted".to_string());
        }
        self.counters.shard_count += 1;
        self.counters.encrypted_diff_bytes = self
            .counters
            .encrypted_diff_bytes
            .saturating_add(r.encrypted_bytes);
        self.hot_shards_by_operator
            .entry(r.assigned_operator.clone())
            .or_default()
            .insert(r.shard_id.clone());
        self.record_public(format!("shard:{}", r.shard_id), r.public_record())?;
        self.shards.insert(r.shard_id.clone(), r);
        Ok(())
    }
    pub fn insert_ticket(&mut self, r: ZkPrefetchTicket) -> Result<()> {
        if self.tickets.len() >= self.config.max_tickets {
            return Err("ticket capacity exhausted".to_string());
        }
        self.counters.ticket_count += 1;
        self.record_public(format!("ticket:{}", r.ticket_id), r.public_record())?;
        self.tickets.insert(r.ticket_id.clone(), r);
        Ok(())
    }
    pub fn insert_attestation(&mut self, r: PqProverAttestation) -> Result<()> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exhausted".to_string());
        }
        self.counters.attestation_count += 1;
        if let Some(s) = self.shards.get(&r.shard_id) {
            self.counters.prepared_witness_bytes = self
                .counters
                .prepared_witness_bytes
                .saturating_add(s.witness_bytes)
        }
        self.record_public(
            format!("attestation:{}", r.attestation_id),
            r.public_record(),
        )?;
        self.attestations.insert(r.attestation_id.clone(), r);
        Ok(())
    }
    pub fn insert_lease(&mut self, r: CacheLease) -> Result<()> {
        if self.leases.len() >= self.config.max_leases {
            return Err("lease capacity exhausted".to_string());
        }
        self.counters.lease_count += 1;
        self.counters.warmed_diff_bytes = self
            .counters
            .warmed_diff_bytes
            .saturating_add(r.bytes_pinned);
        self.record_public(format!("lease:{}", r.lease_id), r.public_record())?;
        self.leases.insert(r.lease_id.clone(), r);
        Ok(())
    }
    pub fn insert_fence(&mut self, r: InvalidationFence) -> Result<()> {
        if self.fences.len() >= self.config.max_fences {
            return Err("fence capacity exhausted".to_string());
        }
        self.counters.fence_count += 1;
        self.record_public(format!("fence:{}", r.fence_id), r.public_record())?;
        self.fences.insert(r.fence_id.clone(), r);
        Ok(())
    }
    pub fn insert_credit(&mut self, r: LowFeeProofCredit) -> Result<()> {
        if self.credits.len() >= self.config.max_credits {
            return Err("credit capacity exhausted".to_string());
        }
        self.counters.credit_count += 1;
        self.counters.proof_credit_micro_units = self
            .counters
            .proof_credit_micro_units
            .saturating_add(r.credited_micro_units);
        self.counters.avoided_fee_micro_units = self
            .counters
            .avoided_fee_micro_units
            .saturating_add(r.avoided_fee_micro_units);
        self.record_public(format!("credit:{}", r.credit_id), r.public_record())?;
        self.credits.insert(r.credit_id.clone(), r);
        Ok(())
    }
    pub fn insert_redaction(&mut self, r: WitnessRedactionMetadata) -> Result<()> {
        if self.redactions.len() >= self.config.max_redactions {
            return Err("redaction capacity exhausted".to_string());
        }
        self.counters.redaction_count += 1;
        self.counters.redacted_witness_bytes = self
            .counters
            .redacted_witness_bytes
            .saturating_add(r.redacted_bytes);
        self.record_public(format!("redaction:{}", r.redaction_id), r.public_record())?;
        self.redactions.insert(r.redaction_id.clone(), r);
        Ok(())
    }
    pub fn insert_operator_summary(&mut self, r: OperatorSummary) -> Result<()> {
        if self.operator_summaries.len() >= self.config.max_operator_summaries {
            return Err("operator summary capacity exhausted".to_string());
        }
        self.counters.operator_summary_count += 1;
        self.record_public(
            format!("operator_summary:{}", r.summary_id),
            r.public_record(),
        )?;
        self.operator_summaries.insert(r.summary_id.clone(), r);
        Ok(())
    }
    pub fn record_public(&mut self, key: impl Into<String>, value: Value) -> Result<()> {
        if self.public_records.len() >= self.config.max_public_records {
            return Err("public record capacity exhausted".to_string());
        }
        let key = key.into();
        if !self.public_records.contains_key(&key) {
            self.counters.public_record_count += 1
        }
        self.public_records.insert(key, value);
        Ok(())
    }
    pub fn refresh_operator_summary(&mut self, shard_id: &str) -> Result<()> {
        let shard = self
            .shards
            .get(shard_id)
            .ok_or_else(|| "missing shard for operator summary".to_string())?;
        let tickets = self
            .tickets
            .values()
            .filter(|x| x.shard_id == shard_id)
            .map(|x| x.public_record())
            .collect::<Vec<_>>();
        let attestations = self
            .attestations
            .values()
            .filter(|x| x.shard_id == shard_id)
            .map(|x| x.public_record())
            .collect::<Vec<_>>();
        let leases = self
            .leases
            .values()
            .filter(|x| x.shard_id == shard_id)
            .map(|x| x.public_record())
            .collect::<Vec<_>>();
        let summary = OperatorSummary::new(
            shard.assigned_operator.clone(),
            shard.created_at_height,
            shard.expires_at_height,
            shard.state_root(),
            merkle_root(D_TICKETS, &tickets),
            merkle_root(D_ATTESTATIONS, &attestations),
            merkle_root(D_LEASES, &leases),
            self.counters.allocate_sequence(),
        );
        self.insert_operator_summary(summary)
    }
    pub fn create_invalidation_fence(
        &mut self,
        shard_id: &str,
        k: InvalidationFenceKind,
        reason: impl Into<String>,
    ) -> Result<String> {
        let shard = self
            .shards
            .get(shard_id)
            .ok_or_else(|| "missing shard for invalidation fence".to_string())?
            .clone();
        let fence =
            InvalidationFence::for_shard(&shard, k, reason, self.counters.allocate_sequence());
        let id = fence.fence_id.clone();
        self.insert_fence(fence)?;
        self.refresh_roots();
        Ok(id)
    }
    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            shards_root: merkle_root(D_SHARDS, &public_records_from_map(&self.shards)),
            tickets_root: merkle_root(D_TICKETS, &public_records_from_map(&self.tickets)),
            attestations_root: merkle_root(
                D_ATTESTATIONS,
                &public_records_from_map(&self.attestations),
            ),
            leases_root: merkle_root(D_LEASES, &public_records_from_map(&self.leases)),
            fences_root: merkle_root(D_FENCES, &public_records_from_map(&self.fences)),
            credits_root: merkle_root(D_CREDITS, &public_records_from_map(&self.credits)),
            redactions_root: merkle_root(D_REDACTIONS, &public_records_from_map(&self.redactions)),
            operator_summaries_root: merkle_root(
                D_SUMMARIES,
                &public_records_from_map(&self.operator_summaries),
            ),
            public_records_root: merkle_root(
                D_PUBLIC,
                &public_values_from_map(&self.public_records),
            ),
            state_root: String::new(),
        }
    }
    pub fn refresh_roots(&mut self) {
        let mut r = self.roots();
        r.state_root = self.state_root_from_roots(&r);
        self.roots = r
    }
    pub fn public_record_without_state_root(&self) -> Value {
        let mut roots = self.roots();
        roots.state_root = roots.state_root_without_self();
        json!({"kind":"private_l2_fast_pq_confidential_zero_knowledge_state_diff_prefetch_runtime_state","protocol_version":PROTOCOL_VERSION,"schema_version":SCHEMA_VERSION,"hash_suite":HASH_SUITE,"chain_id":CHAIN_ID,"config":self.config.public_record(),"counters":self.counters.public_record(),"roots":roots.public_record(),"shards":public_map(&self.shards),"tickets":public_map(&self.tickets),"attestations":public_map(&self.attestations),"leases":public_map(&self.leases),"fences":public_map(&self.fences),"credits":public_map(&self.credits),"redactions":public_map(&self.redactions),"operator_summaries":public_map(&self.operator_summaries),"hot_shards_by_operator":self.hot_shards_by_operator,"public_records_root":merkle_root(D_PUBLIC,&public_values_from_map(&self.public_records))})
    }
    pub fn public_record(&self) -> Value {
        let mut r = self.public_record_without_state_root();
        if let Value::Object(o) = &mut r {
            o.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        r
    }
    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }
    fn state_root_from_roots(&self, roots: &Roots) -> String {
        payload_root(
            D_STATE,
            &json!({"protocol_version":PROTOCOL_VERSION,"config_root":roots.config_root,"counters_root":roots.counters_root,"shards_root":roots.shards_root,"tickets_root":roots.tickets_root,"attestations_root":roots.attestations_root,"leases_root":roots.leases_root,"fences_root":roots.fences_root,"credits_root":roots.credits_root,"redactions_root":roots.redactions_root,"operator_summaries_root":roots.operator_summaries_root,"public_records_root":roots.public_records_root}),
        )
    }
    fn seed_devnet_fixture(&mut self) -> Result<()> {
        let a = self.add_prefetch_bundle(
            StateDiffShardKind::ContractStorageDelta,
            "devnet-source-state-root-a",
            "devnet-target-state-root-a",
            "devnet-operator-0",
            786_432,
            2_097_152,
            DEVNET_L2_HEIGHT,
        )?;
        let b = self.add_prefetch_bundle(
            StateDiffShardKind::NullifierDelta,
            "devnet-source-state-root-b",
            "devnet-target-state-root-b",
            "devnet-operator-1",
            524_288,
            1_572_864,
            DEVNET_L2_HEIGHT + 4,
        )?;
        let _ = self.create_invalidation_fence(
            &a,
            InvalidationFenceKind::ContractEpoch,
            "devnet-contract-epoch-roll",
        )?;
        let _ = self.create_invalidation_fence(
            &b,
            InvalidationFenceKind::NullifierWindow,
            "devnet-nullifier-hot-window",
        )?;
        Ok(())
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
pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    payload_root(D_STATE, record)
}
pub fn encrypted_state_diff_shard_id(record: &Value) -> String {
    payload_root(ENCRYPTED_STATE_DIFF_SHARD_SUITE, record)
}
pub fn zk_prefetch_ticket_id(record: &Value) -> String {
    payload_root(ZK_PREFETCH_PROOF_SUITE, record)
}
pub fn pq_prover_attestation_id(record: &Value) -> String {
    payload_root(PQ_PROVER_ATTESTATION_SUITE, record)
}
pub fn cache_lease_id(record: &Value) -> String {
    payload_root(CACHE_LEASE_SUITE, record)
}
pub fn invalidation_fence_id(record: &Value) -> String {
    payload_root(INVALIDATION_FENCE_SUITE, record)
}
pub fn low_fee_proof_credit_id(record: &Value) -> String {
    payload_root(LOW_FEE_PROOF_CREDIT_SUITE, record)
}
pub fn witness_redaction_metadata_id(record: &Value) -> String {
    payload_root(WITNESS_REDACTION_SUITE, record)
}
pub fn operator_summary_id(record: &Value) -> String {
    payload_root(OPERATOR_SUMMARY_SUITE, record)
}
pub fn quote_low_fee_micro_units(bytes: u64, fee_bps: u64) -> u64 {
    let kib = bytes.saturating_add(1023) / 1024;
    kib.saturating_mul(fee_bps.max(1))
}
fn runtime_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:{domain}"),
        parts,
        32,
    )
}
fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}
fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds MAX_BPS"))
    } else {
        Ok(())
    }
}
pub trait PublicRecord {
    fn public_record(&self) -> Value;
}
impl PublicRecord for EncryptedStateDiffShard {
    fn public_record(&self) -> Value {
        EncryptedStateDiffShard::public_record(self)
    }
}
impl PublicRecord for ZkPrefetchTicket {
    fn public_record(&self) -> Value {
        ZkPrefetchTicket::public_record(self)
    }
}
impl PublicRecord for PqProverAttestation {
    fn public_record(&self) -> Value {
        PqProverAttestation::public_record(self)
    }
}
impl PublicRecord for CacheLease {
    fn public_record(&self) -> Value {
        CacheLease::public_record(self)
    }
}
impl PublicRecord for InvalidationFence {
    fn public_record(&self) -> Value {
        InvalidationFence::public_record(self)
    }
}
impl PublicRecord for LowFeeProofCredit {
    fn public_record(&self) -> Value {
        LowFeeProofCredit::public_record(self)
    }
}
impl PublicRecord for WitnessRedactionMetadata {
    fn public_record(&self) -> Value {
        WitnessRedactionMetadata::public_record(self)
    }
}
impl PublicRecord for OperatorSummary {
    fn public_record(&self) -> Value {
        OperatorSummary::public_record(self)
    }
}
fn public_records_from_map<T: PublicRecord>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.iter()
        .map(|(id, value)| json!({"id":id,"record":value.public_record()}))
        .collect()
}
fn public_values_from_map(map: &BTreeMap<String, Value>) -> Vec<Value> {
    map.iter()
        .map(|(id, value)| json!({"id":id,"record":value}))
        .collect()
}
fn public_map<T: PublicRecord>(map: &BTreeMap<String, T>) -> Value {
    Value::Array(public_records_from_map(map))
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame0 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame0 {
    pub fn for_state_diff_prefetch_metric_0(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_0".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame1 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame1 {
    pub fn for_state_diff_prefetch_metric_1(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_1".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame2 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame2 {
    pub fn for_state_diff_prefetch_metric_2(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_2".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame3 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame3 {
    pub fn for_state_diff_prefetch_metric_3(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_3".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame4 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame4 {
    pub fn for_state_diff_prefetch_metric_4(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_4".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame5 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame5 {
    pub fn for_state_diff_prefetch_metric_5(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_5".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame6 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame6 {
    pub fn for_state_diff_prefetch_metric_6(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_6".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame7 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame7 {
    pub fn for_state_diff_prefetch_metric_7(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_7".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame8 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame8 {
    pub fn for_state_diff_prefetch_metric_8(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_8".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame9 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame9 {
    pub fn for_state_diff_prefetch_metric_9(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_9".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame10 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame10 {
    pub fn for_state_diff_prefetch_metric_10(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_10".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame11 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame11 {
    pub fn for_state_diff_prefetch_metric_11(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_11".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame12 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame12 {
    pub fn for_state_diff_prefetch_metric_12(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_12".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame13 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame13 {
    pub fn for_state_diff_prefetch_metric_13(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_13".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeTelemetryFrame14 {
    pub frame_id: String,
    pub frame_kind: String,
    pub subject_root: String,
    pub metric_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeTelemetryFrame14 {
    pub fn for_state_diff_prefetch_metric_14(
        subject_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> Self {
        let subject_root = subject_root.into();
        let frame_kind = "state_diff_prefetch_metric_14".to_string();
        let frame_id = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-FRAME",
            &[
                HashPart::Str(&frame_kind),
                HashPart::Str(&subject_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        let metric_root = runtime_id(
            "STATE-DIFF-PREFETCH-TELEMETRY-METRIC",
            &[HashPart::Str(&frame_id)],
        );
        Self {
            frame_id,
            frame_kind,
            subject_root,
            metric_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "runtime_telemetry_frame",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "frame_kind": self.frame_kind,
            "subject_root": self.subject_root,
            "metric_root": self.metric_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn state_root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZK-STATE-DIFF-PREFETCH:TELEMETRY",
            &self.public_record(),
        )
    }
}
