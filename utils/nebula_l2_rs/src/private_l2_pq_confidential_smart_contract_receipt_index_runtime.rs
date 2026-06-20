use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const PRIVATE_L2_PQ_RECEIPT_INDEX_PROTOCOL_VERSION: &str =
    "private-l2-pq-confidential-smart-contract-receipt-index/v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReceiptStatus {
    Pending,
    Accepted,
    Reverted,
    Disputed,
    Slashed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContractClass {
    Account,
    Token,
    Defi,
    Vault,
    Oracle,
    Bridge,
    Governance,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TopicVisibility {
    Blinded,
    Searchable,
    AuditorOnly,
    ShardLocal,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignerRole {
    Sequencer,
    Prover,
    Auditor,
    Watchtower,
    Committee,
    Sponsor,
}

impl SignerRole {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Prover => "prover",
            Self::Auditor => "auditor",
            Self::Watchtower => "watchtower",
            Self::Committee => "committee",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeeKind {
    Execution,
    DataAvailability,
    Proof,
    Sponsor,
    Rebate,
    Slash,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum BatchMode {
    SingleShard,
    CrossShard,
    DefiNetting,
    Sponsored,
    Emergency,
}

impl BatchMode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SingleShard => "single_shard",
            Self::CrossShard => "cross_shard",
            Self::DefiNetting => "defi_netting",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceKind {
    FalseInclusion,
    FalseEventTopic,
    StateDiffMismatch,
    NullifierReuse,
    FeeOverclaim,
    SignerEquivocation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexQueryKind {
    Receipt,
    Contract,
    Caller,
    Topic,
    Nullifier,
    Batch,
    Shard,
}

impl IndexQueryKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Receipt => "receipt",
            Self::Contract => "contract",
            Self::Caller => "caller",
            Self::Topic => "topic",
            Self::Nullifier => "nullifier",
            Self::Batch => "batch",
            Self::Shard => "shard",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub min_pq_signature_weight: u64,
    pub max_topics_per_receipt: u16,
    pub max_state_diffs_per_receipt: u16,
    pub max_batch_receipts: u32,
    pub base_fee_units: u64,
    pub da_fee_units: u64,
    pub proof_fee_units: u64,
    pub rebate_bps: u16,
    pub slash_bond_units: u64,
    pub audit_delay_blocks: u64,
    pub finality_depth: u64,
    pub shard_count: u16,
    pub locality_window: u64,
    pub allow_searchable_private_index: bool,
    pub require_nullifier_fence: bool,
    pub require_inclusion_witness: bool,
    pub allow_low_fee_aggregation: bool,
    pub allow_contract_tokens: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_RECEIPT_INDEX_PROTOCOL_VERSION.to_string(),
            min_pq_signature_weight: 2,
            max_topics_per_receipt: 16,
            max_state_diffs_per_receipt: 32,
            max_batch_receipts: 256,
            base_fee_units: 4,
            da_fee_units: 2,
            proof_fee_units: 3,
            rebate_bps: 2200,
            slash_bond_units: 10_000,
            audit_delay_blocks: 12,
            finality_depth: 8,
            shard_count: 8,
            locality_window: 64,
            allow_searchable_private_index: true,
            require_nullifier_fence: true,
            require_inclusion_witness: true,
            allow_low_fee_aggregation: true,
            allow_contract_tokens: true,
        }
    }

    pub fn public_record(&self) -> Value {
        serialize_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractAddressCommitment {
    pub contract_id: String,
    pub class: ContractClass,
    pub address_commitment: String,
    pub deployer_commitment: String,
    pub salt_commitment: String,
    pub code_root: String,
    pub abi_root: String,
    pub token_root: String,
    pub created_at_height: u64,
}

impl ContractAddressCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "class": self.class,
            "address_commitment": self.address_commitment,
            "deployer_commitment": self.deployer_commitment,
            "salt_commitment": self.salt_commitment,
            "code_root": self.code_root,
            "abi_root": self.abi_root,
            "token_root": self.token_root,
            "created_at_height": self.created_at_height
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-CONTRACT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractCallReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub caller_commitment: String,
    pub contract_commitment: String,
    pub entrypoint_commitment: String,
    pub calldata_root: String,
    pub return_data_root: String,
    pub event_topic_root: String,
    pub state_diff_root: String,
    pub nullifier_fence_root: String,
    pub fee_receipt_root: String,
    pub pq_attestation_root: String,
    pub inclusion_witness_root: String,
    pub shard_id: u16,
    pub height: u64,
    pub gas_units: u64,
    pub privacy_budget_units: u64,
}

impl ContractCallReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "batch_id": self.batch_id,
            "status": self.status,
            "caller_commitment": self.caller_commitment,
            "contract_commitment": self.contract_commitment,
            "entrypoint_commitment": self.entrypoint_commitment,
            "calldata_root": self.calldata_root,
            "return_data_root": self.return_data_root,
            "event_topic_root": self.event_topic_root,
            "state_diff_root": self.state_diff_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_attestation_root": self.pq_attestation_root,
            "inclusion_witness_root": self.inclusion_witness_root,
            "shard_id": self.shard_id,
            "height": self.height,
            "gas_units": self.gas_units,
            "privacy_budget_units": self.privacy_budget_units
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEventTopic {
    pub topic_id: String,
    pub receipt_id: String,
    pub topic_position: u16,
    pub visibility: TopicVisibility,
    pub ciphertext_commitment: String,
    pub search_tag: String,
    pub auditor_tag: String,
    pub locality_tag: String,
    pub ciphertext_bytes: u32,
}

impl EncryptedEventTopic {
    pub fn public_record(&self) -> Value {
        json!({
            "topic_id": self.topic_id,
            "receipt_id": self.receipt_id,
            "topic_position": self.topic_position,
            "visibility": self.visibility,
            "ciphertext_commitment": self.ciphertext_commitment,
            "search_tag": self.search_tag,
            "auditor_tag": self.auditor_tag,
            "locality_tag": self.locality_tag,
            "ciphertext_bytes": self.ciphertext_bytes
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-TOPIC", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateDiffCommitment {
    pub diff_id: String,
    pub receipt_id: String,
    pub contract_commitment: String,
    pub slot_commitment: String,
    pub old_value_commitment: String,
    pub new_value_commitment: String,
    pub witness_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub diff_bytes: u32,
}

impl StateDiffCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "diff_id": self.diff_id,
            "receipt_id": self.receipt_id,
            "contract_commitment": self.contract_commitment,
            "slot_commitment": self.slot_commitment,
            "old_value_commitment": self.old_value_commitment,
            "new_value_commitment": self.new_value_commitment,
            "witness_root": self.witness_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "diff_bytes": self.diff_bytes
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-STATE-DIFF", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierFence {
    pub fence_id: String,
    pub receipt_id: String,
    pub caller_nullifier: String,
    pub contract_nullifier: String,
    pub epoch_nullifier: String,
    pub spent_nullifier_root: String,
    pub reserved_nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "receipt_id": self.receipt_id,
            "caller_nullifier": self.caller_nullifier,
            "contract_nullifier": self.contract_nullifier,
            "epoch_nullifier": self.epoch_nullifier,
            "spent_nullifier_root": self.spent_nullifier_root,
            "reserved_nullifier_root": self.reserved_nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-NULLIFIER-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeReceipt {
    pub fee_receipt_id: String,
    pub receipt_id: String,
    pub payer_commitment: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub kind: FeeKind,
    pub gross_fee_units: u64,
    pub rebate_units: u64,
    pub burn_units: u64,
    pub operator_units: u64,
}

impl FeeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_receipt_id": self.fee_receipt_id,
            "receipt_id": self.receipt_id,
            "payer_commitment": self.payer_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "kind": self.kind,
            "gross_fee_units": self.gross_fee_units,
            "rebate_units": self.rebate_units,
            "burn_units": self.burn_units,
            "operator_units": self.operator_units
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-FEE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardLocalityHint {
    pub hint_id: String,
    pub receipt_id: String,
    pub shard_id: u16,
    pub lane_id: String,
    pub locality_tag: String,
    pub cross_shard_tags: BTreeSet<String>,
    pub preferred_builder: String,
    pub max_delay_blocks: u64,
}

impl ShardLocalityHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "receipt_id": self.receipt_id,
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "locality_tag": self.locality_tag,
            "cross_shard_tags": self.cross_shard_tags,
            "preferred_builder": self.preferred_builder,
            "max_delay_blocks": self.max_delay_blocks
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-LOCALITY-HINT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionWitness {
    pub witness_id: String,
    pub receipt_id: String,
    pub batch_id: String,
    pub block_height: u64,
    pub receipt_position: u32,
    pub receipt_root: String,
    pub batch_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub proof_path_root: String,
}

impl InclusionWitness {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "block_height": self.block_height,
            "receipt_position": self.receipt_position,
            "receipt_root": self.receipt_root,
            "batch_root": self.batch_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "proof_path_root": self.proof_path_root
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-INCLUSION-WITNESS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqSignerAttestation {
    pub attestation_id: String,
    pub signer_id: String,
    pub role: SignerRole,
    pub subject_id: String,
    pub subject_root: String,
    pub pq_key_commitment: String,
    pub signature_root: String,
    pub weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSignerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "signer_id": self.signer_id,
            "role": self.role,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "pq_key_commitment": self.pq_key_commitment,
            "signature_root": self.signature_root,
            "weight": self.weight,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-PQ-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateReceiptIndexEntry {
    pub entry_id: String,
    pub query_kind: IndexQueryKind,
    pub query_tag: String,
    pub receipt_id: String,
    pub contract_commitment: String,
    pub batch_id: String,
    pub shard_id: u16,
    pub height: u64,
    pub encrypted_pointer: String,
    pub access_policy_root: String,
}

impl PrivateReceiptIndexEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "query_kind": self.query_kind,
            "query_tag": self.query_tag,
            "receipt_id": self.receipt_id,
            "contract_commitment": self.contract_commitment,
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "height": self.height,
            "encrypted_pointer": self.encrypted_pointer,
            "access_policy_root": self.access_policy_root
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-PRIVATE-ENTRY", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LowFeeAggregationBatch {
    pub batch_id: String,
    pub mode: BatchMode,
    pub shard_id: u16,
    pub coordinator_commitment: String,
    pub receipt_ids: BTreeSet<String>,
    pub gross_fee_units: u64,
    pub rebate_units: u64,
    pub proof_units: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
}

impl LowFeeAggregationBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "mode": self.mode,
            "shard_id": self.shard_id,
            "coordinator_commitment": self.coordinator_commitment,
            "receipt_ids": self.receipt_ids,
            "gross_fee_units": self.gross_fee_units,
            "rebate_units": self.rebate_units,
            "proof_units": self.proof_units,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-LOW-FEE-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub accused_commitment: String,
    pub challenger_commitment: String,
    pub receipt_id: String,
    pub claimed_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "accused_commitment": self.accused_commitment,
            "challenger_commitment": self.challenger_commitment,
            "receipt_id": self.receipt_id,
            "claimed_root": self.claimed_root,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicReceiptRecord {
    pub record_id: String,
    pub receipt_id: String,
    pub status: ReceiptStatus,
    pub contract_commitment: String,
    pub batch_id: String,
    pub shard_id: u16,
    pub height: u64,
    pub receipt_root: String,
    pub index_root: String,
    pub witness_root: String,
    pub published_by: String,
}

impl PublicReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "receipt_id": self.receipt_id,
            "status": self.status,
            "contract_commitment": self.contract_commitment,
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "height": self.height,
            "receipt_root": self.receipt_root,
            "index_root": self.index_root,
            "witness_root": self.witness_root,
            "published_by": self.published_by
        })
    }

    pub fn root(&self) -> String {
        receipt_index_payload_root("RECEIPT-INDEX-PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub receipts: u64,
    pub topics: u64,
    pub state_diffs: u64,
    pub nullifier_fences: u64,
    pub fee_receipts: u64,
    pub contracts: u64,
    pub locality_hints: u64,
    pub inclusion_witnesses: u64,
    pub index_entries: u64,
    pub batches: u64,
    pub attestations: u64,
    pub evidence_items: u64,
    pub public_records: u64,
    pub total_gross_fee_units: u64,
    pub total_rebate_units: u64,
    pub total_slashed_units: u64,
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            receipts: 0,
            topics: 0,
            state_diffs: 0,
            nullifier_fences: 0,
            fee_receipts: 0,
            contracts: 0,
            locality_hints: 0,
            inclusion_witnesses: 0,
            index_entries: 0,
            batches: 0,
            attestations: 0,
            evidence_items: 0,
            public_records: 0,
            total_gross_fee_units: 0,
            total_rebate_units: 0,
            total_slashed_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        serialize_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub receipt_root: String,
    pub topic_root: String,
    pub state_diff_root: String,
    pub nullifier_fence_root: String,
    pub fee_receipt_root: String,
    pub contract_root: String,
    pub locality_hint_root: String,
    pub inclusion_witness_root: String,
    pub private_index_root: String,
    pub batch_root: String,
    pub attestation_root: String,
    pub slashing_evidence_root: String,
    pub public_record_root: String,
    pub nullifier_registry_root: String,
    pub search_tag_root: String,
    pub contract_receipt_root: String,
    pub fee_asset_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serialize_record(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub contracts: BTreeMap<String, ContractAddressCommitment>,
    pub receipts: BTreeMap<String, ContractCallReceipt>,
    pub topics: BTreeMap<String, EncryptedEventTopic>,
    pub state_diffs: BTreeMap<String, StateDiffCommitment>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub fee_receipts: BTreeMap<String, FeeReceipt>,
    pub locality_hints: BTreeMap<String, ShardLocalityHint>,
    pub inclusion_witnesses: BTreeMap<String, InclusionWitness>,
    pub attestations: BTreeMap<String, PqSignerAttestation>,
    pub private_index: BTreeMap<String, PrivateReceiptIndexEntry>,
    pub batches: BTreeMap<String, LowFeeAggregationBatch>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_records: BTreeMap<String, PublicReceiptRecord>,
    pub spent_nullifiers: BTreeSet<String>,
    pub reserved_nullifiers: BTreeSet<String>,
    pub searchable_tags: BTreeSet<String>,
    pub contract_receipts: BTreeMap<String, BTreeSet<String>>,
    pub fee_assets: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut runtime = Runtime::new(Config::devnet());
        runtime.seed_devnet_records();
        runtime.state
    }

    pub fn empty(config: Config) -> Self {
        Self {
            config,
            counters: Counters::empty(),
            contracts: BTreeMap::new(),
            receipts: BTreeMap::new(),
            topics: BTreeMap::new(),
            state_diffs: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            fee_receipts: BTreeMap::new(),
            locality_hints: BTreeMap::new(),
            inclusion_witnesses: BTreeMap::new(),
            attestations: BTreeMap::new(),
            private_index: BTreeMap::new(),
            batches: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            reserved_nullifiers: BTreeSet::new(),
            searchable_tags: BTreeSet::new(),
            contract_receipts: BTreeMap::new(),
            fee_assets: BTreeSet::new(),
        }
    }

    pub fn roots(&self) -> Roots {
        let receipt_records: Vec<Value> = self
            .receipts
            .values()
            .map(ContractCallReceipt::public_record)
            .collect();
        let topic_records: Vec<Value> = self
            .topics
            .values()
            .map(EncryptedEventTopic::public_record)
            .collect();
        let diff_records: Vec<Value> = self
            .state_diffs
            .values()
            .map(StateDiffCommitment::public_record)
            .collect();
        let fence_records: Vec<Value> = self
            .nullifier_fences
            .values()
            .map(NullifierFence::public_record)
            .collect();
        let fee_records: Vec<Value> = self
            .fee_receipts
            .values()
            .map(FeeReceipt::public_record)
            .collect();
        let contract_records: Vec<Value> = self
            .contracts
            .values()
            .map(ContractAddressCommitment::public_record)
            .collect();
        let hint_records: Vec<Value> = self
            .locality_hints
            .values()
            .map(ShardLocalityHint::public_record)
            .collect();
        let witness_records: Vec<Value> = self
            .inclusion_witnesses
            .values()
            .map(InclusionWitness::public_record)
            .collect();
        let index_records: Vec<Value> = self
            .private_index
            .values()
            .map(PrivateReceiptIndexEntry::public_record)
            .collect();
        let batch_records: Vec<Value> = self
            .batches
            .values()
            .map(LowFeeAggregationBatch::public_record)
            .collect();
        let attestation_records: Vec<Value> = self
            .attestations
            .values()
            .map(PqSignerAttestation::public_record)
            .collect();
        let evidence_records: Vec<Value> = self
            .slashing_evidence
            .values()
            .map(SlashingEvidence::public_record)
            .collect();
        let public_records: Vec<Value> = self
            .public_records
            .values()
            .map(PublicReceiptRecord::public_record)
            .collect();
        let nullifier_records: Vec<Value> = self
            .spent_nullifiers
            .iter()
            .chain(self.reserved_nullifiers.iter())
            .map(|value| Value::String(value.clone()))
            .collect();
        let search_records: Vec<Value> = self
            .searchable_tags
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect();
        let contract_receipt_records: Vec<Value> = self
            .contract_receipts
            .iter()
            .map(|(contract, receipts)| json!({"contract": contract, "receipts": receipts}))
            .collect();
        let fee_asset_records: Vec<Value> = self
            .fee_assets
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect();

        Roots {
            config_root: receipt_index_payload_root(
                "RECEIPT-INDEX-CONFIG",
                &self.config.public_record(),
            ),
            receipt_root: merkle_root("RECEIPT-INDEX-RECEIPTS", &receipt_records),
            topic_root: merkle_root("RECEIPT-INDEX-TOPICS", &topic_records),
            state_diff_root: merkle_root("RECEIPT-INDEX-STATE-DIFFS", &diff_records),
            nullifier_fence_root: merkle_root("RECEIPT-INDEX-NULLIFIER-FENCES", &fence_records),
            fee_receipt_root: merkle_root("RECEIPT-INDEX-FEES", &fee_records),
            contract_root: merkle_root("RECEIPT-INDEX-CONTRACTS", &contract_records),
            locality_hint_root: merkle_root("RECEIPT-INDEX-LOCALITY", &hint_records),
            inclusion_witness_root: merkle_root("RECEIPT-INDEX-INCLUSION", &witness_records),
            private_index_root: merkle_root("RECEIPT-INDEX-PRIVATE-INDEX", &index_records),
            batch_root: merkle_root("RECEIPT-INDEX-BATCHES", &batch_records),
            attestation_root: merkle_root("RECEIPT-INDEX-ATTESTATIONS", &attestation_records),
            slashing_evidence_root: merkle_root("RECEIPT-INDEX-EVIDENCE", &evidence_records),
            public_record_root: merkle_root("RECEIPT-INDEX-PUBLIC-RECORDS", &public_records),
            nullifier_registry_root: merkle_root(
                "RECEIPT-INDEX-NULLIFIER-REGISTRY",
                &nullifier_records,
            ),
            search_tag_root: merkle_root("RECEIPT-INDEX-SEARCH-TAGS", &search_records),
            contract_receipt_root: merkle_root(
                "RECEIPT-INDEX-CONTRACT-RECEIPTS",
                &contract_receipt_records,
            ),
            fee_asset_root: merkle_root("RECEIPT-INDEX-FEE-ASSETS", &fee_asset_records),
            counters_root: receipt_index_payload_root(
                "RECEIPT-INDEX-COUNTERS",
                &self.counters.public_record(),
            ),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record()
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_root();
        json!({
            "state_root": receipt_index_state_root_from_record(&record),
            "record": record
        })
    }

    pub fn state_root(&self) -> String {
        receipt_index_state_root_from_record(&self.public_record_without_root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Runtime {
    pub state: State,
}

impl Runtime {
    pub fn new(config: Config) -> Self {
        Self {
            state: State::empty(config),
        }
    }

    pub fn ingest_receipt(&mut self, receipt: ContractCallReceipt) -> Result<String> {
        if receipt.receipt_id.is_empty() {
            return Err("receipt id must not be empty".to_string());
        }
        validate_shard(receipt.shard_id, self.state.config.shard_count)?;
        if self.state.receipts.contains_key(&receipt.receipt_id) {
            return Err("receipt already indexed".to_string());
        }
        let root = receipt.root();
        self.state
            .contract_receipts
            .entry(receipt.contract_commitment.clone())
            .or_insert_with(BTreeSet::new)
            .insert(receipt.receipt_id.clone());
        self.state
            .receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.state.counters.receipts = self.state.counters.receipts.saturating_add(1);
        Ok(root)
    }

    pub fn register_contract(&mut self, contract: ContractAddressCommitment) -> Result<String> {
        if contract.contract_id.is_empty() {
            return Err("contract id must not be empty".to_string());
        }
        if self.state.contracts.contains_key(&contract.contract_id) {
            return Err("contract already registered".to_string());
        }
        let root = contract.root();
        self.state
            .contracts
            .insert(contract.contract_id.clone(), contract);
        self.state.counters.contracts = self.state.counters.contracts.saturating_add(1);
        Ok(root)
    }

    pub fn index_topic(&mut self, topic: EncryptedEventTopic) -> Result<String> {
        self.ensure_receipt(&topic.receipt_id)?;
        if topic.topic_position >= self.state.config.max_topics_per_receipt {
            return Err("topic position exceeds configured limit".to_string());
        }
        if matches!(topic.visibility, TopicVisibility::Searchable) {
            if !self.state.config.allow_searchable_private_index {
                return Err("searchable private index disabled".to_string());
            }
            self.state.searchable_tags.insert(topic.search_tag.clone());
        }
        let root = topic.root();
        self.state.topics.insert(topic.topic_id.clone(), topic);
        self.state.counters.topics = self.state.counters.topics.saturating_add(1);
        Ok(root)
    }

    pub fn commit_state_diff(&mut self, diff: StateDiffCommitment) -> Result<String> {
        self.ensure_receipt(&diff.receipt_id)?;
        let current = self
            .state
            .state_diffs
            .values()
            .filter(|item| item.receipt_id == diff.receipt_id)
            .count();
        if current as u16 >= self.state.config.max_state_diffs_per_receipt {
            return Err("state diff count exceeds configured limit".to_string());
        }
        let root = diff.root();
        self.state.state_diffs.insert(diff.diff_id.clone(), diff);
        self.state.counters.state_diffs = self.state.counters.state_diffs.saturating_add(1);
        Ok(root)
    }

    pub fn reserve_nullifier_fence(&mut self, fence: NullifierFence) -> Result<String> {
        self.ensure_receipt(&fence.receipt_id)?;
        for nullifier in [
            &fence.caller_nullifier,
            &fence.contract_nullifier,
            &fence.epoch_nullifier,
        ] {
            if self.state.spent_nullifiers.contains(nullifier)
                || self.state.reserved_nullifiers.contains(nullifier)
            {
                return Err("nullifier already fenced".to_string());
            }
        }
        self.state
            .reserved_nullifiers
            .insert(fence.caller_nullifier.clone());
        self.state
            .reserved_nullifiers
            .insert(fence.contract_nullifier.clone());
        self.state
            .reserved_nullifiers
            .insert(fence.epoch_nullifier.clone());
        let root = fence.root();
        self.state
            .nullifier_fences
            .insert(fence.fence_id.clone(), fence);
        self.state.counters.nullifier_fences =
            self.state.counters.nullifier_fences.saturating_add(1);
        Ok(root)
    }

    pub fn settle_fee(&mut self, fee: FeeReceipt) -> Result<String> {
        self.ensure_receipt(&fee.receipt_id)?;
        if fee.rebate_units > fee.gross_fee_units {
            return Err("rebate exceeds gross fee".to_string());
        }
        let accounted = fee
            .rebate_units
            .saturating_add(fee.burn_units)
            .saturating_add(fee.operator_units);
        if accounted > fee.gross_fee_units {
            return Err("fee accounting exceeds gross fee".to_string());
        }
        let root = fee.root();
        self.state.fee_assets.insert(fee.asset_id.clone());
        self.state.counters.total_gross_fee_units = self
            .state
            .counters
            .total_gross_fee_units
            .saturating_add(fee.gross_fee_units);
        self.state.counters.total_rebate_units = self
            .state
            .counters
            .total_rebate_units
            .saturating_add(fee.rebate_units);
        self.state
            .fee_receipts
            .insert(fee.fee_receipt_id.clone(), fee);
        self.state.counters.fee_receipts = self.state.counters.fee_receipts.saturating_add(1);
        Ok(root)
    }

    pub fn add_locality_hint(&mut self, hint: ShardLocalityHint) -> Result<String> {
        self.ensure_receipt(&hint.receipt_id)?;
        validate_shard(hint.shard_id, self.state.config.shard_count)?;
        let root = hint.root();
        self.state.locality_hints.insert(hint.hint_id.clone(), hint);
        self.state.counters.locality_hints = self.state.counters.locality_hints.saturating_add(1);
        Ok(root)
    }

    pub fn add_inclusion_witness(&mut self, witness: InclusionWitness) -> Result<String> {
        self.ensure_receipt(&witness.receipt_id)?;
        let root = witness.root();
        self.state
            .inclusion_witnesses
            .insert(witness.witness_id.clone(), witness);
        self.state.counters.inclusion_witnesses =
            self.state.counters.inclusion_witnesses.saturating_add(1);
        Ok(root)
    }

    pub fn add_attestation(&mut self, attestation: PqSignerAttestation) -> Result<String> {
        if attestation.weight == 0 {
            return Err("attestation weight must be positive".to_string());
        }
        let root = attestation.root();
        self.state
            .attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.state.counters.attestations = self.state.counters.attestations.saturating_add(1);
        Ok(root)
    }

    pub fn add_index_entry(&mut self, entry: PrivateReceiptIndexEntry) -> Result<String> {
        self.ensure_receipt(&entry.receipt_id)?;
        validate_shard(entry.shard_id, self.state.config.shard_count)?;
        if !self.state.config.allow_searchable_private_index {
            return Err("searchable private index disabled".to_string());
        }
        let root = entry.root();
        self.state.searchable_tags.insert(entry.query_tag.clone());
        self.state
            .private_index
            .insert(entry.entry_id.clone(), entry);
        self.state.counters.index_entries = self.state.counters.index_entries.saturating_add(1);
        Ok(root)
    }

    pub fn seal_low_fee_batch(&mut self, batch: LowFeeAggregationBatch) -> Result<String> {
        if !self.state.config.allow_low_fee_aggregation {
            return Err("low fee aggregation disabled".to_string());
        }
        validate_shard(batch.shard_id, self.state.config.shard_count)?;
        if batch.receipt_ids.len() as u32 > self.state.config.max_batch_receipts {
            return Err("batch exceeds configured receipt limit".to_string());
        }
        for receipt_id in &batch.receipt_ids {
            self.ensure_receipt(receipt_id)?;
        }
        let root = batch.root();
        self.state.counters.total_rebate_units = self
            .state
            .counters
            .total_rebate_units
            .saturating_add(batch.rebate_units);
        self.state.batches.insert(batch.batch_id.clone(), batch);
        self.state.counters.batches = self.state.counters.batches.saturating_add(1);
        Ok(root)
    }

    pub fn open_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<String> {
        self.ensure_receipt(&evidence.receipt_id)?;
        if evidence.claimed_root == evidence.observed_root {
            return Err("slashing evidence roots are identical".to_string());
        }
        let root = evidence.root();
        self.state.counters.total_slashed_units = self
            .state
            .counters
            .total_slashed_units
            .saturating_add(evidence.bond_units);
        self.state
            .slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        self.state.counters.evidence_items = self.state.counters.evidence_items.saturating_add(1);
        Ok(root)
    }

    pub fn publish_record(&mut self, record: PublicReceiptRecord) -> Result<String> {
        self.ensure_receipt(&record.receipt_id)?;
        validate_shard(record.shard_id, self.state.config.shard_count)?;
        let root = record.root();
        self.state
            .public_records
            .insert(record.record_id.clone(), record);
        self.state.counters.public_records = self.state.counters.public_records.saturating_add(1);
        Ok(root)
    }

    pub fn query_private_index(&self, query_tag: &str) -> Vec<PrivateReceiptIndexEntry> {
        self.state
            .private_index
            .values()
            .filter(|entry| entry.query_tag == query_tag)
            .cloned()
            .collect()
    }

    pub fn receipts_for_contract(&self, contract_commitment: &str) -> Vec<ContractCallReceipt> {
        self.state
            .contract_receipts
            .get(contract_commitment)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.state.receipts.get(id))
            .cloned()
            .collect()
    }

    pub fn verify_pq_weight(&self, subject_id: &str, at_height: u64) -> Result<u64> {
        let weight = self
            .state
            .attestations
            .values()
            .filter(|attestation| {
                attestation.subject_id == subject_id
                    && attestation.issued_at_height <= at_height
                    && attestation.expires_at_height >= at_height
            })
            .map(|attestation| attestation.weight)
            .fold(0_u64, u64::saturating_add);
        if weight < self.state.config.min_pq_signature_weight {
            Err("insufficient pq attestation weight".to_string())
        } else {
            Ok(weight)
        }
    }

    pub fn state_root(&self) -> String {
        self.state.state_root()
    }

    fn ensure_receipt(&self, receipt_id: &str) -> Result<()> {
        if self.state.receipts.contains_key(receipt_id) {
            Ok(())
        } else {
            Err("receipt is not indexed".to_string())
        }
    }

    fn seed_devnet_records(&mut self) {
        let contract = devnet_contract("confidential-swap", 1);
        let _ = self.register_contract(contract.clone());
        let receipt = devnet_receipt(
            "swap-call",
            &contract.contract_id,
            &contract.address_commitment,
            1,
            7,
        );
        let receipt_id = receipt.receipt_id.clone();
        let batch_id = receipt.batch_id.clone();
        let _ = self.ingest_receipt(receipt);
        let _ = self.index_topic(devnet_topic(&receipt_id, 0, TopicVisibility::Searchable));
        let _ = self.commit_state_diff(devnet_state_diff(
            &receipt_id,
            &contract.address_commitment,
            0,
        ));
        let _ = self.reserve_nullifier_fence(devnet_nullifier_fence(&receipt_id, 11));
        let _ = self.settle_fee(devnet_fee_receipt(&receipt_id));
        let _ = self.add_locality_hint(devnet_locality_hint(&receipt_id, 1));
        let _ = self.add_inclusion_witness(devnet_inclusion_witness(&receipt_id, &batch_id, 7));
        let _ = self.add_index_entry(devnet_index_entry(
            &receipt_id,
            &contract.address_commitment,
            &batch_id,
            1,
            7,
        ));
        let mut receipt_ids = BTreeSet::new();
        receipt_ids.insert(receipt_id.clone());
        let _ = self.seal_low_fee_batch(LowFeeAggregationBatch {
            batch_id: batch_id.clone(),
            mode: BatchMode::DefiNetting,
            shard_id: 1,
            coordinator_commitment: deterministic_commitment("coordinator", "devnet"),
            receipt_ids,
            gross_fee_units: 9,
            rebate_units: 2,
            proof_units: 1,
            opened_at_height: 7,
            sealed_at_height: 8,
        });
        let _ = self.add_attestation(devnet_attestation("attestation", &receipt_id, 7));
        let _ = self.publish_record(devnet_public_record(
            &receipt_id,
            &contract.address_commitment,
            &batch_id,
            1,
            7,
        ));
    }
}

pub fn receipt_index_state_root(state: &State) -> String {
    state.state_root()
}

pub fn receipt_index_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "RECEIPT-INDEX-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_RECEIPT_INDEX_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn receipt_index_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_RECEIPT_INDEX_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn receipt_index_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_RECEIPT_INDEX_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn deterministic_commitment(kind: &str, label: &str) -> String {
    domain_hash(
        "RECEIPT-INDEX-DETERMINISTIC-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_RECEIPT_INDEX_PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn deterministic_receipt_id(
    call_label: &str,
    contract_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "RECEIPT-INDEX-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_label),
            HashPart::Str(contract_commitment),
            HashPart::Int(height as i128),
        ],
        20,
    )
}

pub fn deterministic_batch_id(mode: BatchMode, shard_id: u16, height: u64) -> String {
    domain_hash(
        "RECEIPT-INDEX-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(mode.as_str()),
            HashPart::Int(shard_id as i128),
            HashPart::Int(height as i128),
        ],
        20,
    )
}

pub fn deterministic_index_tag(kind: IndexQueryKind, secret_root: &str, scope: &str) -> String {
    domain_hash(
        "RECEIPT-INDEX-SEARCH-TAG",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(secret_root),
            HashPart::Str(scope),
        ],
        20,
    )
}

pub fn deterministic_nullifier(scope: &str, receipt_id: &str, position: u16) -> String {
    domain_hash(
        "RECEIPT-INDEX-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(receipt_id),
            HashPart::Int(position as i128),
        ],
        32,
    )
}

fn validate_shard(shard_id: u16, shard_count: u16) -> Result<()> {
    if shard_id >= shard_count {
        Err("shard outside configured range".to_string())
    } else {
        Ok(())
    }
}

fn serialize_record<T: Serialize>(record: &T) -> Value {
    match serde_json::to_value(record) {
        Ok(value) => value,
        Err(error) => json!({"serialization_error": error.to_string()}),
    }
}

pub fn devnet_contract(label: &str, height: u64) -> ContractAddressCommitment {
    ContractAddressCommitment {
        contract_id: deterministic_commitment("contract-id", label),
        class: ContractClass::Defi,
        address_commitment: deterministic_commitment("contract-address", label),
        deployer_commitment: deterministic_commitment("deployer", label),
        salt_commitment: deterministic_commitment("salt", label),
        code_root: receipt_index_string_root("RECEIPT-INDEX-CODE", label),
        abi_root: receipt_index_string_root("RECEIPT-INDEX-ABI", label),
        token_root: receipt_index_string_root("RECEIPT-INDEX-TOKEN", label),
        created_at_height: height,
    }
}

pub fn devnet_receipt(
    label: &str,
    contract_id: &str,
    contract_commitment: &str,
    shard_id: u16,
    height: u64,
) -> ContractCallReceipt {
    let receipt_id = deterministic_receipt_id(label, contract_commitment, height);
    let batch_id = deterministic_batch_id(BatchMode::DefiNetting, shard_id, height);
    ContractCallReceipt {
        receipt_id: receipt_id.clone(),
        call_id: deterministic_commitment("call", label),
        batch_id,
        status: ReceiptStatus::Accepted,
        caller_commitment: deterministic_commitment("caller", label),
        contract_commitment: contract_commitment.to_string(),
        entrypoint_commitment: deterministic_commitment("entrypoint", contract_id),
        calldata_root: receipt_index_string_root("RECEIPT-INDEX-CALLDATA", label),
        return_data_root: receipt_index_string_root("RECEIPT-INDEX-RETURN", label),
        event_topic_root: receipt_index_string_root("RECEIPT-INDEX-EVENTS", &receipt_id),
        state_diff_root: receipt_index_string_root("RECEIPT-INDEX-DIFFS", &receipt_id),
        nullifier_fence_root: receipt_index_string_root("RECEIPT-INDEX-FENCE", &receipt_id),
        fee_receipt_root: receipt_index_string_root("RECEIPT-INDEX-FEE", &receipt_id),
        pq_attestation_root: receipt_index_string_root("RECEIPT-INDEX-PQ", &receipt_id),
        inclusion_witness_root: receipt_index_string_root("RECEIPT-INDEX-WITNESS", &receipt_id),
        shard_id,
        height,
        gas_units: 44_000,
        privacy_budget_units: 128,
    }
}

pub fn devnet_topic(
    receipt_id: &str,
    position: u16,
    visibility: TopicVisibility,
) -> EncryptedEventTopic {
    EncryptedEventTopic {
        topic_id: deterministic_commitment("topic", &format!("{}:{}", receipt_id, position)),
        receipt_id: receipt_id.to_string(),
        topic_position: position,
        visibility,
        ciphertext_commitment: deterministic_commitment("topic-ciphertext", receipt_id),
        search_tag: deterministic_index_tag(IndexQueryKind::Topic, receipt_id, "devnet"),
        auditor_tag: deterministic_commitment("auditor-topic", receipt_id),
        locality_tag: deterministic_commitment("local-topic", receipt_id),
        ciphertext_bytes: 96,
    }
}

pub fn devnet_state_diff(
    receipt_id: &str,
    contract_commitment: &str,
    position: u16,
) -> StateDiffCommitment {
    StateDiffCommitment {
        diff_id: deterministic_commitment("diff", &format!("{}:{}", receipt_id, position)),
        receipt_id: receipt_id.to_string(),
        contract_commitment: contract_commitment.to_string(),
        slot_commitment: deterministic_commitment("slot", receipt_id),
        old_value_commitment: deterministic_commitment("old-value", receipt_id),
        new_value_commitment: deterministic_commitment("new-value", receipt_id),
        witness_root: receipt_index_string_root("RECEIPT-INDEX-DIFF-WITNESS", receipt_id),
        read_set_root: receipt_index_string_root("RECEIPT-INDEX-READ-SET", receipt_id),
        write_set_root: receipt_index_string_root("RECEIPT-INDEX-WRITE-SET", receipt_id),
        diff_bytes: 128,
    }
}

pub fn devnet_nullifier_fence(receipt_id: &str, height: u64) -> NullifierFence {
    NullifierFence {
        fence_id: deterministic_commitment("fence", receipt_id),
        receipt_id: receipt_id.to_string(),
        caller_nullifier: deterministic_nullifier("caller", receipt_id, 0),
        contract_nullifier: deterministic_nullifier("contract", receipt_id, 1),
        epoch_nullifier: deterministic_nullifier("epoch", receipt_id, 2),
        spent_nullifier_root: receipt_index_string_root("RECEIPT-INDEX-SPENT", receipt_id),
        reserved_nullifier_root: receipt_index_string_root("RECEIPT-INDEX-RESERVED", receipt_id),
        opened_at_height: height,
        expires_at_height: height.saturating_add(64),
    }
}

pub fn devnet_fee_receipt(receipt_id: &str) -> FeeReceipt {
    FeeReceipt {
        fee_receipt_id: deterministic_commitment("fee", receipt_id),
        receipt_id: receipt_id.to_string(),
        payer_commitment: deterministic_commitment("payer", receipt_id),
        sponsor_commitment: deterministic_commitment("sponsor", receipt_id),
        asset_id: "dxmr-devnet".to_string(),
        kind: FeeKind::Execution,
        gross_fee_units: 9,
        rebate_units: 2,
        burn_units: 1,
        operator_units: 6,
    }
}

pub fn devnet_locality_hint(receipt_id: &str, shard_id: u16) -> ShardLocalityHint {
    let mut cross_shard_tags = BTreeSet::new();
    cross_shard_tags.insert(deterministic_commitment("cross-shard", receipt_id));
    ShardLocalityHint {
        hint_id: deterministic_commitment("hint", receipt_id),
        receipt_id: receipt_id.to_string(),
        shard_id,
        lane_id: "fast-private-defi".to_string(),
        locality_tag: deterministic_commitment("locality", receipt_id),
        cross_shard_tags,
        preferred_builder: deterministic_commitment("builder", receipt_id),
        max_delay_blocks: 3,
    }
}

pub fn devnet_inclusion_witness(receipt_id: &str, batch_id: &str, height: u64) -> InclusionWitness {
    InclusionWitness {
        witness_id: deterministic_commitment("witness", receipt_id),
        receipt_id: receipt_id.to_string(),
        batch_id: batch_id.to_string(),
        block_height: height,
        receipt_position: 0,
        receipt_root: receipt_index_string_root("RECEIPT-INDEX-RECEIPT-WITNESS", receipt_id),
        batch_root: receipt_index_string_root("RECEIPT-INDEX-BATCH-WITNESS", batch_id),
        state_root_before: receipt_index_string_root("RECEIPT-INDEX-STATE-BEFORE", receipt_id),
        state_root_after: receipt_index_string_root("RECEIPT-INDEX-STATE-AFTER", receipt_id),
        proof_path_root: receipt_index_string_root("RECEIPT-INDEX-PROOF-PATH", receipt_id),
    }
}

pub fn devnet_index_entry(
    receipt_id: &str,
    contract_commitment: &str,
    batch_id: &str,
    shard_id: u16,
    height: u64,
) -> PrivateReceiptIndexEntry {
    PrivateReceiptIndexEntry {
        entry_id: deterministic_commitment("index-entry", receipt_id),
        query_kind: IndexQueryKind::Receipt,
        query_tag: deterministic_index_tag(IndexQueryKind::Receipt, receipt_id, "owner"),
        receipt_id: receipt_id.to_string(),
        contract_commitment: contract_commitment.to_string(),
        batch_id: batch_id.to_string(),
        shard_id,
        height,
        encrypted_pointer: deterministic_commitment("encrypted-pointer", receipt_id),
        access_policy_root: receipt_index_string_root("RECEIPT-INDEX-ACCESS", receipt_id),
    }
}

pub fn devnet_attestation(label: &str, receipt_id: &str, height: u64) -> PqSignerAttestation {
    PqSignerAttestation {
        attestation_id: deterministic_commitment("attestation", label),
        signer_id: deterministic_commitment("signer", label),
        role: SignerRole::Sequencer,
        subject_id: receipt_id.to_string(),
        subject_root: receipt_index_string_root("RECEIPT-INDEX-ATTESTED-SUBJECT", receipt_id),
        pq_key_commitment: deterministic_commitment("pq-key", label),
        signature_root: receipt_index_string_root("RECEIPT-INDEX-PQ-SIGNATURE", label),
        weight: 2,
        issued_at_height: height,
        expires_at_height: height.saturating_add(128),
    }
}

pub fn devnet_public_record(
    receipt_id: &str,
    contract_commitment: &str,
    batch_id: &str,
    shard_id: u16,
    height: u64,
) -> PublicReceiptRecord {
    PublicReceiptRecord {
        record_id: deterministic_commitment("public-record", receipt_id),
        receipt_id: receipt_id.to_string(),
        status: ReceiptStatus::Accepted,
        contract_commitment: contract_commitment.to_string(),
        batch_id: batch_id.to_string(),
        shard_id,
        height,
        receipt_root: receipt_index_string_root("RECEIPT-INDEX-PUBLIC-RECEIPT", receipt_id),
        index_root: receipt_index_string_root("RECEIPT-INDEX-PUBLIC-INDEX", receipt_id),
        witness_root: receipt_index_string_root("RECEIPT-INDEX-PUBLIC-WITNESS", receipt_id),
        published_by: deterministic_commitment("publisher", receipt_id),
    }
}
