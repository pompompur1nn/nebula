use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "private-l2-pq-confidential-contract-receipt-bridge-settlement/v1";

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
pub enum ReceiptStatus {
    Indexed,
    Proven,
    Settled,
    Rejected,
    Challenged,
    Slashed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum BridgeDirection {
    L2ToMonero,
    MoneroToL2,
    ContractToContract,
    Reconciliation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofSystem {
    ZkStark,
    RecursiveStark,
    LatticeAccumulator,
    HashBasedSignature,
    HybridPq,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeeKind {
    Execution,
    DataAvailability,
    Proof,
    Bridge,
    Sponsor,
    Rebate,
    Slash,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateDiffKind {
    StorageWrite,
    TokenMint,
    TokenBurn,
    TokenTransfer,
    ReserveDebit,
    ReserveCredit,
    ContractUpgrade,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WitnessKind {
    ReceiptLeaf,
    EventLeaf,
    ReserveLeaf,
    StateDiffLeaf,
    FeeLeaf,
    NullifierLeaf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestationKind {
    Availability,
    Inclusion,
    Finality,
    ReserveBalance,
    FraudAbsence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceKind {
    FalseReceiptRoot,
    FalseEventRoot,
    FalseReserveCommitment,
    NullifierReuse,
    StateDiffMismatch,
    FeeOverclaim,
    WatcherEquivocation,
    InvalidPqSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub min_pq_signature_weight: u64,
    pub min_watcher_weight: u64,
    pub min_reserve_confirmations: u64,
    pub max_receipts_per_manifest: u32,
    pub max_events_per_contract: u32,
    pub max_state_diffs_per_claim: u32,
    pub finality_depth: u64,
    pub challenge_window_blocks: u64,
    pub slash_bond_units: u64,
    pub base_fee_units: u64,
    pub proof_fee_units: u64,
    pub bridge_fee_units: u64,
    pub rebate_bps: u16,
    pub low_fee_batch_size: u32,
    pub require_inclusion_witness: bool,
    pub require_privacy_fence: bool,
    pub require_monero_reserve: bool,
    pub allow_contract_tokens: bool,
    pub allow_defi_receipts: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            min_pq_signature_weight: 2,
            min_watcher_weight: 3,
            min_reserve_confirmations: 10,
            max_receipts_per_manifest: 512,
            max_events_per_contract: 256,
            max_state_diffs_per_claim: 128,
            finality_depth: 8,
            challenge_window_blocks: 64,
            slash_bond_units: 50_000,
            base_fee_units: 3,
            proof_fee_units: 4,
            bridge_fee_units: 5,
            rebate_bps: 1800,
            low_fee_batch_size: 64,
            require_inclusion_witness: true,
            require_privacy_fence: true,
            require_monero_reserve: true,
            allow_contract_tokens: true,
            allow_defi_receipts: true,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub next_contract_index: u64,
    pub next_manifest_index: u64,
    pub next_event_index: u64,
    pub next_claim_index: u64,
    pub next_reserve_index: u64,
    pub next_fee_index: u64,
    pub next_witness_index: u64,
    pub next_attestation_index: u64,
    pub next_fence_index: u64,
    pub next_evidence_index: u64,
    pub receipts_indexed: u64,
    pub claims_settled: u64,
    pub claims_rejected: u64,
    pub slash_events: u64,
    pub total_fee_units: u128,
    pub total_rebate_units: u128,
    pub total_slashed_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_contract_index: 1,
            next_manifest_index: 1,
            next_event_index: 1,
            next_claim_index: 1,
            next_reserve_index: 1,
            next_fee_index: 1,
            next_witness_index: 1,
            next_attestation_index: 1,
            next_fence_index: 1,
            next_evidence_index: 1,
            receipts_indexed: 0,
            claims_settled: 0,
            claims_rejected: 0,
            slash_events: 0,
            total_fee_units: 0,
            total_rebate_units: 0,
            total_slashed_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub contract_root: String,
    pub receipt_manifest_root: String,
    pub event_root: String,
    pub settlement_claim_root: String,
    pub reserve_commitment_root: String,
    pub encrypted_manifest_root: String,
    pub state_diff_root: String,
    pub fee_receipt_root: String,
    pub inclusion_witness_root: String,
    pub watcher_attestation_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub slashing_evidence_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractDescriptor {
    pub contract_id: String,
    pub class: ContractClass,
    pub address_commitment: String,
    pub deployer_commitment: String,
    pub code_root: String,
    pub abi_root: String,
    pub token_policy_root: String,
    pub pq_verifier_root: String,
    pub created_at_height: u64,
}

impl ContractDescriptor {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONTRACT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptIndexEntry {
    pub receipt_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub call_selector_commitment: String,
    pub receipt_commitment: String,
    pub event_root: String,
    pub state_diff_root: String,
    pub fee_root: String,
    pub nullifier_root: String,
    pub status: ReceiptStatus,
    pub l2_height: u64,
    pub sequence: u64,
}

impl ReceiptIndexEntry {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptIndexManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub receipt_root: String,
    pub event_root: String,
    pub state_diff_root: String,
    pub fee_root: String,
    pub encrypted_manifest_id: String,
    pub pq_signature_root: String,
    pub produced_by: String,
    pub l2_height: u64,
}

impl ReceiptIndexManifest {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("RECEIPT-MANIFEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractEventRoot {
    pub event_root_id: String,
    pub contract_id: String,
    pub receipt_id: String,
    pub topic_root: String,
    pub data_commitment_root: String,
    pub event_count: u32,
    pub bloom_commitment: String,
    pub emitted_at_height: u64,
}

impl ContractEventRoot {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("EVENT-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeSettlementProof {
    pub claim_id: String,
    pub direction: BridgeDirection,
    pub manifest_id: String,
    pub receipt_root: String,
    pub event_root: String,
    pub reserve_commitment_id: String,
    pub state_diff_root: String,
    pub inclusion_witness_root: String,
    pub privacy_fence_id: String,
    pub proof_system: ProofSystem,
    pub proof_root: String,
    pub pq_signature_root: String,
    pub claimed_amount_commitment: String,
    pub settlement_height: u64,
    pub status: ReceiptStatus,
}

impl BridgeSettlementProof {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-SETTLEMENT-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MoneroReserveCommitment {
    pub reserve_commitment_id: String,
    pub reserve_epoch: u64,
    pub view_tag_root: String,
    pub key_image_root: String,
    pub output_commitment_root: String,
    pub amount_commitment: String,
    pub reserve_proof_root: String,
    pub watcher_set_root: String,
    pub monero_height: u64,
    pub confirmations: u64,
}

impl MoneroReserveCommitment {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("MONERO-RESERVE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedReceiptManifest {
    pub encrypted_manifest_id: String,
    pub manifest_id: String,
    pub ciphertext_root: String,
    pub recipient_key_root: String,
    pub disclosure_policy_root: String,
    pub aad_root: String,
    pub chunk_count: u32,
    pub byte_size: u64,
}

impl EncryptedReceiptManifest {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("ENCRYPTED-MANIFEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossContractStateDiff {
    pub diff_id: String,
    pub claim_id: String,
    pub contract_id: String,
    pub target_contract_id: String,
    pub diff_kind: StateDiffKind,
    pub before_root: String,
    pub after_root: String,
    pub delta_commitment: String,
    pub token_id: String,
    pub witness_root: String,
}

impl CrossContractStateDiff {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("STATE-DIFF", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeReceipt {
    pub fee_id: String,
    pub claim_id: String,
    pub payer_commitment: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub fee_kind: FeeKind,
    pub amount_units: u64,
    pub rebate_units: u64,
    pub fee_commitment: String,
    pub rebate_commitment: String,
}

impl FeeReceipt {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("FEE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionWitness {
    pub witness_id: String,
    pub claim_id: String,
    pub witness_kind: WitnessKind,
    pub leaf_id: String,
    pub leaf_root: String,
    pub path_root: String,
    pub expected_root: String,
    pub position_commitment: String,
    pub verified: bool,
}

impl InclusionWitness {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("INCLUSION-WITNESS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub claim_id: String,
    pub watcher_id: String,
    pub attestation_kind: AttestationKind,
    pub observed_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub weight: u64,
    pub observed_at_height: u64,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("WATCHER-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub claim_id: String,
    pub nullifier_root: String,
    pub spent_nullifiers: BTreeSet<String>,
    pub anonymity_set_root: String,
    pub decoy_root: String,
    pub policy_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub claim_id: String,
    pub accused_party: String,
    pub evidence_kind: EvidenceKind,
    pub expected_root: String,
    pub observed_root: String,
    pub contradiction_root: String,
    pub reporter_commitment: String,
    pub slash_units: u64,
    pub accepted: bool,
    pub height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub contracts: BTreeMap<String, ContractDescriptor>,
    pub receipts: BTreeMap<String, ReceiptIndexEntry>,
    pub manifests: BTreeMap<String, ReceiptIndexManifest>,
    pub event_roots: BTreeMap<String, ContractEventRoot>,
    pub settlement_claims: BTreeMap<String, BridgeSettlementProof>,
    pub reserves: BTreeMap<String, MoneroReserveCommitment>,
    pub encrypted_manifests: BTreeMap<String, EncryptedReceiptManifest>,
    pub state_diffs: BTreeMap<String, CrossContractStateDiff>,
    pub fee_receipts: BTreeMap<String, FeeReceipt>,
    pub inclusion_witnesses: BTreeMap<String, InclusionWitness>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub claim_to_receipts: BTreeMap<String, BTreeSet<String>>,
    pub claim_to_watchers: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::new(),
            height: 0,
            contracts: BTreeMap::new(),
            receipts: BTreeMap::new(),
            manifests: BTreeMap::new(),
            event_roots: BTreeMap::new(),
            settlement_claims: BTreeMap::new(),
            reserves: BTreeMap::new(),
            encrypted_manifests: BTreeMap::new(),
            state_diffs: BTreeMap::new(),
            fee_receipts: BTreeMap::new(),
            inclusion_witnesses: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            slashing_evidence: BTreeMap::new(),
            claim_to_receipts: BTreeMap::new(),
            claim_to_watchers: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.height = 42;

        let contract = ContractDescriptor {
            contract_id: contract_id("private-defi-vault", 1),
            class: ContractClass::Defi,
            address_commitment: deterministic_id("DEVNET-CONTRACT-ADDRESS", "vault", 1),
            deployer_commitment: deterministic_id("DEVNET-DEPLOYER", "vault", 1),
            code_root: deterministic_id("DEVNET-CODE", "vault", 1),
            abi_root: deterministic_id("DEVNET-ABI", "vault", 1),
            token_policy_root: deterministic_id("DEVNET-TOKEN-POLICY", "vault", 1),
            pq_verifier_root: deterministic_id("DEVNET-PQ-VERIFIER", "vault", 1),
            created_at_height: 4,
        };
        state
            .contracts
            .insert(contract.contract_id.clone(), contract.clone());
        state.counters.next_contract_index = 2;

        let receipt = ReceiptIndexEntry {
            receipt_id: receipt_id(&contract.contract_id, 1),
            contract_id: contract.contract_id.clone(),
            caller_commitment: deterministic_id("DEVNET-CALLER", "vault", 1),
            call_selector_commitment: deterministic_id("DEVNET-SELECTOR", "swap", 1),
            receipt_commitment: deterministic_id("DEVNET-RECEIPT-COMMITMENT", "swap", 1),
            event_root: deterministic_id("DEVNET-RECEIPT-EVENTS", "swap", 1),
            state_diff_root: deterministic_id("DEVNET-RECEIPT-DIFFS", "swap", 1),
            fee_root: deterministic_id("DEVNET-RECEIPT-FEES", "swap", 1),
            nullifier_root: deterministic_id("DEVNET-RECEIPT-NULLIFIERS", "swap", 1),
            status: ReceiptStatus::Indexed,
            l2_height: 24,
            sequence: 1,
        };
        state
            .spent_nullifiers
            .insert(deterministic_id("DEVNET-SPENT-NULLIFIER", "swap", 1));
        state
            .receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        state.counters.next_manifest_index = 2;
        state.counters.receipts_indexed = 1;

        let encrypted = EncryptedReceiptManifest {
            encrypted_manifest_id: encrypted_manifest_id("devnet-manifest", 1),
            manifest_id: manifest_id(&contract.contract_id, 1),
            ciphertext_root: deterministic_id("DEVNET-CIPHERTEXT", "manifest", 1),
            recipient_key_root: deterministic_id("DEVNET-RECIPIENT-KEYS", "manifest", 1),
            disclosure_policy_root: deterministic_id("DEVNET-DISCLOSURE", "manifest", 1),
            aad_root: deterministic_id("DEVNET-AAD", "manifest", 1),
            chunk_count: 3,
            byte_size: 4096,
        };
        state
            .encrypted_manifests
            .insert(encrypted.encrypted_manifest_id.clone(), encrypted.clone());

        let mut receipt_ids = BTreeSet::new();
        receipt_ids.insert(receipt.receipt_id.clone());
        let manifest = ReceiptIndexManifest {
            manifest_id: encrypted.manifest_id.clone(),
            contract_id: contract.contract_id.clone(),
            receipt_ids,
            receipt_root: set_root("DEVNET-MANIFEST-RECEIPTS", &[receipt.root()]),
            event_root: receipt.event_root.clone(),
            state_diff_root: receipt.state_diff_root.clone(),
            fee_root: receipt.fee_root.clone(),
            encrypted_manifest_id: encrypted.encrypted_manifest_id.clone(),
            pq_signature_root: deterministic_id("DEVNET-MANIFEST-SIG", "manifest", 1),
            produced_by: deterministic_id("DEVNET-SEQUENCER", "manifest", 1),
            l2_height: 24,
        };
        state
            .manifests
            .insert(manifest.manifest_id.clone(), manifest.clone());

        let event = ContractEventRoot {
            event_root_id: event_root_id(&contract.contract_id, 1),
            contract_id: contract.contract_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            topic_root: deterministic_id("DEVNET-TOPICS", "swap", 1),
            data_commitment_root: deterministic_id("DEVNET-EVENT-DATA", "swap", 1),
            event_count: 2,
            bloom_commitment: deterministic_id("DEVNET-BLOOM", "swap", 1),
            emitted_at_height: 24,
        };
        state
            .event_roots
            .insert(event.event_root_id.clone(), event.clone());
        state.counters.next_event_index = 2;

        let reserve = MoneroReserveCommitment {
            reserve_commitment_id: reserve_id(1, 1),
            reserve_epoch: 1,
            view_tag_root: deterministic_id("DEVNET-VIEW-TAGS", "reserve", 1),
            key_image_root: deterministic_id("DEVNET-KEY-IMAGES", "reserve", 1),
            output_commitment_root: deterministic_id("DEVNET-OUTPUTS", "reserve", 1),
            amount_commitment: deterministic_id("DEVNET-RESERVE-AMOUNT", "reserve", 1),
            reserve_proof_root: deterministic_id("DEVNET-RESERVE-PROOF", "reserve", 1),
            watcher_set_root: deterministic_id("DEVNET-WATCHER-SET", "reserve", 1),
            monero_height: 1_000,
            confirmations: 24,
        };
        state
            .reserves
            .insert(reserve.reserve_commitment_id.clone(), reserve.clone());
        state.counters.next_reserve_index = 2;

        let fence = PrivacyFence {
            fence_id: privacy_fence_id("devnet-claim", 1),
            claim_id: settlement_claim_id("devnet-claim", 1),
            nullifier_root: receipt.nullifier_root.clone(),
            spent_nullifiers: state.spent_nullifiers.clone(),
            anonymity_set_root: deterministic_id("DEVNET-ANONYMITY", "claim", 1),
            decoy_root: deterministic_id("DEVNET-DECOYS", "claim", 1),
            policy_root: deterministic_id("DEVNET-FENCE-POLICY", "claim", 1),
            valid_from_height: 24,
            valid_until_height: 96,
        };
        state
            .privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        state.counters.next_fence_index = 2;

        let claim = BridgeSettlementProof {
            claim_id: fence.claim_id.clone(),
            direction: BridgeDirection::L2ToMonero,
            manifest_id: manifest.manifest_id.clone(),
            receipt_root: manifest.receipt_root.clone(),
            event_root: event.root(),
            reserve_commitment_id: reserve.reserve_commitment_id.clone(),
            state_diff_root: manifest.state_diff_root.clone(),
            inclusion_witness_root: deterministic_id("DEVNET-WITNESS-ROOT", "claim", 1),
            privacy_fence_id: fence.fence_id.clone(),
            proof_system: ProofSystem::HybridPq,
            proof_root: deterministic_id("DEVNET-CLAIM-PROOF", "claim", 1),
            pq_signature_root: deterministic_id("DEVNET-CLAIM-SIG", "claim", 1),
            claimed_amount_commitment: reserve.amount_commitment.clone(),
            settlement_height: 32,
            status: ReceiptStatus::Proven,
        };
        state
            .settlement_claims
            .insert(claim.claim_id.clone(), claim.clone());
        state
            .claim_to_receipts
            .entry(claim.claim_id.clone())
            .or_default()
            .insert(receipt.receipt_id.clone());
        state.counters.next_claim_index = 2;

        let diff = CrossContractStateDiff {
            diff_id: state_diff_id(&claim.claim_id, 1),
            claim_id: claim.claim_id.clone(),
            contract_id: contract.contract_id.clone(),
            target_contract_id: contract.contract_id.clone(),
            diff_kind: StateDiffKind::ReserveDebit,
            before_root: deterministic_id("DEVNET-BEFORE", "claim", 1),
            after_root: deterministic_id("DEVNET-AFTER", "claim", 1),
            delta_commitment: deterministic_id("DEVNET-DELTA", "claim", 1),
            token_id: deterministic_id("DEVNET-TOKEN", "claim", 1),
            witness_root: deterministic_id("DEVNET-DIFF-WITNESS", "claim", 1),
        };
        state.state_diffs.insert(diff.diff_id.clone(), diff);

        let fee = FeeReceipt {
            fee_id: fee_receipt_id(&claim.claim_id, 1),
            claim_id: claim.claim_id.clone(),
            payer_commitment: deterministic_id("DEVNET-PAYER", "claim", 1),
            sponsor_commitment: deterministic_id("DEVNET-SPONSOR", "claim", 1),
            asset_id: "xmr-private-fee".to_string(),
            fee_kind: FeeKind::Bridge,
            amount_units: 12,
            rebate_units: 2,
            fee_commitment: deterministic_id("DEVNET-FEE", "claim", 1),
            rebate_commitment: deterministic_id("DEVNET-REBATE", "claim", 1),
        };
        state.counters.total_fee_units = fee.amount_units as u128;
        state.counters.total_rebate_units = fee.rebate_units as u128;
        state.fee_receipts.insert(fee.fee_id.clone(), fee);
        state.counters.next_fee_index = 2;

        for index in 1..=3 {
            let attestation = WatcherAttestation {
                attestation_id: watcher_attestation_id(&claim.claim_id, index),
                claim_id: claim.claim_id.clone(),
                watcher_id: deterministic_id("DEVNET-WATCHER", "claim", index),
                attestation_kind: AttestationKind::Inclusion,
                observed_root: claim.root(),
                statement_root: deterministic_id("DEVNET-WATCHER-STATEMENT", "claim", index),
                pq_signature_root: deterministic_id("DEVNET-WATCHER-SIG", "claim", index),
                weight: 1,
                observed_at_height: 33 + index,
            };
            state
                .claim_to_watchers
                .entry(claim.claim_id.clone())
                .or_default()
                .insert(attestation.watcher_id.clone());
            state
                .watcher_attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }
        state.counters.next_attestation_index = 4;

        let witness = InclusionWitness {
            witness_id: inclusion_witness_id(&claim.claim_id, 1),
            claim_id: claim.claim_id.clone(),
            witness_kind: WitnessKind::ReceiptLeaf,
            leaf_id: receipt.receipt_id,
            leaf_root: receipt.root(),
            path_root: deterministic_id("DEVNET-PATH", "claim", 1),
            expected_root: manifest.receipt_root,
            position_commitment: deterministic_id("DEVNET-POSITION", "claim", 1),
            verified: true,
        };
        state
            .inclusion_witnesses
            .insert(witness.witness_id.clone(), witness);
        state.counters.next_witness_index = 2;

        state
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("height cannot move backward".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            contract_root: map_root("CONTRACTS", &self.contracts),
            receipt_manifest_root: map_root("RECEIPT-MANIFESTS", &self.manifests),
            event_root: map_root("EVENT-ROOTS", &self.event_roots),
            settlement_claim_root: map_root("SETTLEMENT-CLAIMS", &self.settlement_claims),
            reserve_commitment_root: map_root("RESERVE-COMMITMENTS", &self.reserves),
            encrypted_manifest_root: map_root("ENCRYPTED-MANIFESTS", &self.encrypted_manifests),
            state_diff_root: map_root("STATE-DIFFS", &self.state_diffs),
            fee_receipt_root: map_root("FEE-RECEIPTS", &self.fee_receipts),
            inclusion_witness_root: map_root("INCLUSION-WITNESSES", &self.inclusion_witnesses),
            watcher_attestation_root: map_root("WATCHER-ATTESTATIONS", &self.watcher_attestations),
            privacy_fence_root: map_root("PRIVACY-FENCES", &self.privacy_fences),
            nullifier_root: btree_set_root("SPENT-NULLIFIERS", &self.spent_nullifiers),
            slashing_evidence_root: map_root("SLASHING-EVIDENCE", &self.slashing_evidence),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "roots": roots.public_record()
        });
        payload_root("STATE", &record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "state_root": self.state_root(),
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "claim_count": self.settlement_claims.len(),
            "receipt_count": self.receipts.len(),
            "reserve_count": self.reserves.len(),
            "slashing_evidence_count": self.slashing_evidence.len()
        })
    }

    pub fn register_contract(
        &mut self,
        class: ContractClass,
        label: &str,
        address_commitment: &str,
        deployer_commitment: &str,
        code_root: &str,
        abi_root: &str,
        token_policy_root: &str,
        pq_verifier_root: &str,
    ) -> Result<String> {
        require_nonempty("label", label)?;
        for (name, value) in [
            ("address_commitment", address_commitment),
            ("deployer_commitment", deployer_commitment),
            ("code_root", code_root),
            ("abi_root", abi_root),
            ("token_policy_root", token_policy_root),
            ("pq_verifier_root", pq_verifier_root),
        ] {
            require_nonempty(name, value)?;
        }
        if matches!(class, ContractClass::Token) && !self.config.allow_contract_tokens {
            return Err("contract token registration disabled".to_string());
        }
        if matches!(class, ContractClass::Defi) && !self.config.allow_defi_receipts {
            return Err("defi contract registration disabled".to_string());
        }

        let index = self.counters.next_contract_index;
        let contract_id = contract_id(label, index);
        let contract = ContractDescriptor {
            contract_id: contract_id.clone(),
            class,
            address_commitment: address_commitment.to_string(),
            deployer_commitment: deployer_commitment.to_string(),
            code_root: code_root.to_string(),
            abi_root: abi_root.to_string(),
            token_policy_root: token_policy_root.to_string(),
            pq_verifier_root: pq_verifier_root.to_string(),
            created_at_height: self.height,
        };
        self.contracts.insert(contract_id.clone(), contract);
        self.counters.next_contract_index += 1;
        Ok(contract_id)
    }

    pub fn add_receipt(
        &mut self,
        contract_id: &str,
        caller_commitment: &str,
        call_selector_commitment: &str,
        receipt_commitment: &str,
        event_root: &str,
        state_diff_root: &str,
        fee_root: &str,
        nullifier_root: &str,
    ) -> Result<String> {
        self.require_contract(contract_id)?;
        for (name, value) in [
            ("caller_commitment", caller_commitment),
            ("call_selector_commitment", call_selector_commitment),
            ("receipt_commitment", receipt_commitment),
            ("event_root", event_root),
            ("state_diff_root", state_diff_root),
            ("fee_root", fee_root),
            ("nullifier_root", nullifier_root),
        ] {
            require_nonempty(name, value)?;
        }
        let sequence = self.counters.receipts_indexed + 1;
        let receipt_id = receipt_id(contract_id, sequence);
        let entry = ReceiptIndexEntry {
            receipt_id: receipt_id.clone(),
            contract_id: contract_id.to_string(),
            caller_commitment: caller_commitment.to_string(),
            call_selector_commitment: call_selector_commitment.to_string(),
            receipt_commitment: receipt_commitment.to_string(),
            event_root: event_root.to_string(),
            state_diff_root: state_diff_root.to_string(),
            fee_root: fee_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            status: ReceiptStatus::Indexed,
            l2_height: self.height,
            sequence,
        };
        self.receipts.insert(receipt_id.clone(), entry);
        self.counters.receipts_indexed += 1;
        Ok(receipt_id)
    }

    pub fn add_event_root(
        &mut self,
        contract_id: &str,
        receipt_id: &str,
        topic_root: &str,
        data_commitment_root: &str,
        event_count: u32,
        bloom_commitment: &str,
    ) -> Result<String> {
        self.require_contract(contract_id)?;
        self.require_receipt(receipt_id)?;
        require_nonempty("topic_root", topic_root)?;
        require_nonempty("data_commitment_root", data_commitment_root)?;
        require_nonempty("bloom_commitment", bloom_commitment)?;
        if event_count > self.config.max_events_per_contract {
            return Err("event count exceeds configured maximum".to_string());
        }

        let event_root_id = event_root_id(contract_id, self.counters.next_event_index);
        let event = ContractEventRoot {
            event_root_id: event_root_id.clone(),
            contract_id: contract_id.to_string(),
            receipt_id: receipt_id.to_string(),
            topic_root: topic_root.to_string(),
            data_commitment_root: data_commitment_root.to_string(),
            event_count,
            bloom_commitment: bloom_commitment.to_string(),
            emitted_at_height: self.height,
        };
        self.event_roots.insert(event_root_id.clone(), event);
        self.counters.next_event_index += 1;
        Ok(event_root_id)
    }

    pub fn add_encrypted_manifest(
        &mut self,
        manifest_label: &str,
        ciphertext_root: &str,
        recipient_key_root: &str,
        disclosure_policy_root: &str,
        aad_root: &str,
        chunk_count: u32,
        byte_size: u64,
    ) -> Result<String> {
        require_nonempty("manifest_label", manifest_label)?;
        for (name, value) in [
            ("ciphertext_root", ciphertext_root),
            ("recipient_key_root", recipient_key_root),
            ("disclosure_policy_root", disclosure_policy_root),
            ("aad_root", aad_root),
        ] {
            require_nonempty(name, value)?;
        }
        if chunk_count == 0 || byte_size == 0 {
            return Err("encrypted manifest must contain bytes".to_string());
        }

        let encrypted_manifest_id =
            encrypted_manifest_id(manifest_label, self.counters.next_manifest_index);
        let manifest_id = manifest_id(manifest_label, self.counters.next_manifest_index);
        let manifest = EncryptedReceiptManifest {
            encrypted_manifest_id: encrypted_manifest_id.clone(),
            manifest_id,
            ciphertext_root: ciphertext_root.to_string(),
            recipient_key_root: recipient_key_root.to_string(),
            disclosure_policy_root: disclosure_policy_root.to_string(),
            aad_root: aad_root.to_string(),
            chunk_count,
            byte_size,
        };
        self.encrypted_manifests
            .insert(encrypted_manifest_id.clone(), manifest);
        Ok(encrypted_manifest_id)
    }

    pub fn build_receipt_manifest(
        &mut self,
        contract_id: &str,
        receipt_ids: BTreeSet<String>,
        encrypted_manifest_id: &str,
        produced_by: &str,
        pq_signature_root: &str,
    ) -> Result<String> {
        self.require_contract(contract_id)?;
        require_nonempty("produced_by", produced_by)?;
        require_nonempty("pq_signature_root", pq_signature_root)?;
        if receipt_ids.is_empty() {
            return Err("receipt manifest cannot be empty".to_string());
        }
        if receipt_ids.len() as u32 > self.config.max_receipts_per_manifest {
            return Err("receipt manifest exceeds configured maximum".to_string());
        }
        let encrypted = self
            .encrypted_manifests
            .get(encrypted_manifest_id)
            .ok_or_else(|| "encrypted manifest not found".to_string())?;

        let mut receipt_records = Vec::new();
        let mut event_roots = Vec::new();
        let mut diff_roots = Vec::new();
        let mut fee_roots = Vec::new();
        for receipt_id in &receipt_ids {
            let receipt = self.require_receipt(receipt_id)?;
            if receipt.contract_id != contract_id {
                return Err("receipt contract mismatch".to_string());
            }
            receipt_records.push(receipt.root());
            event_roots.push(receipt.event_root.clone());
            diff_roots.push(receipt.state_diff_root.clone());
            fee_roots.push(receipt.fee_root.clone());
        }

        let manifest_id = encrypted.manifest_id.clone();
        let manifest = ReceiptIndexManifest {
            manifest_id: manifest_id.clone(),
            contract_id: contract_id.to_string(),
            receipt_ids,
            receipt_root: set_root("MANIFEST-RECEIPTS", &receipt_records),
            event_root: set_root("MANIFEST-EVENTS", &event_roots),
            state_diff_root: set_root("MANIFEST-STATE-DIFFS", &diff_roots),
            fee_root: set_root("MANIFEST-FEES", &fee_roots),
            encrypted_manifest_id: encrypted_manifest_id.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            produced_by: produced_by.to_string(),
            l2_height: self.height,
        };
        self.manifests.insert(manifest_id.clone(), manifest);
        self.counters.next_manifest_index += 1;
        Ok(manifest_id)
    }

    pub fn add_reserve_commitment(
        &mut self,
        reserve_epoch: u64,
        view_tag_root: &str,
        key_image_root: &str,
        output_commitment_root: &str,
        amount_commitment: &str,
        reserve_proof_root: &str,
        watcher_set_root: &str,
        monero_height: u64,
        confirmations: u64,
    ) -> Result<String> {
        for (name, value) in [
            ("view_tag_root", view_tag_root),
            ("key_image_root", key_image_root),
            ("output_commitment_root", output_commitment_root),
            ("amount_commitment", amount_commitment),
            ("reserve_proof_root", reserve_proof_root),
            ("watcher_set_root", watcher_set_root),
        ] {
            require_nonempty(name, value)?;
        }
        if confirmations < self.config.min_reserve_confirmations {
            return Err("reserve commitment has insufficient confirmations".to_string());
        }
        let reserve_commitment_id = reserve_id(reserve_epoch, self.counters.next_reserve_index);
        let reserve = MoneroReserveCommitment {
            reserve_commitment_id: reserve_commitment_id.clone(),
            reserve_epoch,
            view_tag_root: view_tag_root.to_string(),
            key_image_root: key_image_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            amount_commitment: amount_commitment.to_string(),
            reserve_proof_root: reserve_proof_root.to_string(),
            watcher_set_root: watcher_set_root.to_string(),
            monero_height,
            confirmations,
        };
        self.reserves.insert(reserve_commitment_id.clone(), reserve);
        self.counters.next_reserve_index += 1;
        Ok(reserve_commitment_id)
    }

    pub fn open_privacy_fence(
        &mut self,
        claim_label: &str,
        nullifiers: BTreeSet<String>,
        anonymity_set_root: &str,
        decoy_root: &str,
        policy_root: &str,
        valid_until_height: u64,
    ) -> Result<String> {
        require_nonempty("claim_label", claim_label)?;
        require_nonempty("anonymity_set_root", anonymity_set_root)?;
        require_nonempty("decoy_root", decoy_root)?;
        require_nonempty("policy_root", policy_root)?;
        if valid_until_height <= self.height {
            return Err("privacy fence expiry must be in the future".to_string());
        }
        if self.config.require_privacy_fence {
            for nullifier in &nullifiers {
                require_nonempty("nullifier", nullifier)?;
                if self.spent_nullifiers.contains(nullifier) {
                    return Err("privacy fence reuses a spent nullifier".to_string());
                }
            }
        }

        let claim_id = settlement_claim_id(claim_label, self.counters.next_claim_index);
        let fence_id = privacy_fence_id(&claim_id, self.counters.next_fence_index);
        let nullifier_root = btree_set_root("PRIVACY-FENCE-NULLIFIERS", &nullifiers);
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            claim_id,
            nullifier_root,
            spent_nullifiers: nullifiers,
            anonymity_set_root: anonymity_set_root.to_string(),
            decoy_root: decoy_root.to_string(),
            policy_root: policy_root.to_string(),
            valid_from_height: self.height,
            valid_until_height,
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.counters.next_fence_index += 1;
        Ok(fence_id)
    }

    pub fn submit_settlement_claim(
        &mut self,
        direction: BridgeDirection,
        manifest_id: &str,
        reserve_commitment_id: &str,
        privacy_fence_id: &str,
        proof_system: ProofSystem,
        proof_root: &str,
        pq_signature_root: &str,
        claimed_amount_commitment: &str,
    ) -> Result<String> {
        require_nonempty("proof_root", proof_root)?;
        require_nonempty("pq_signature_root", pq_signature_root)?;
        require_nonempty("claimed_amount_commitment", claimed_amount_commitment)?;
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or_else(|| "receipt manifest not found".to_string())?;
        let reserve = self
            .reserves
            .get(reserve_commitment_id)
            .ok_or_else(|| "reserve commitment not found".to_string())?;
        let fence = self
            .privacy_fences
            .get(privacy_fence_id)
            .ok_or_else(|| "privacy fence not found".to_string())?;
        if self.config.require_monero_reserve
            && reserve.amount_commitment != claimed_amount_commitment
        {
            return Err("claimed amount commitment does not match reserve".to_string());
        }
        if fence.valid_until_height <= self.height {
            return Err("privacy fence expired".to_string());
        }

        let claim_id = fence.claim_id.clone();
        let claim = BridgeSettlementProof {
            claim_id: claim_id.clone(),
            direction,
            manifest_id: manifest_id.to_string(),
            receipt_root: manifest.receipt_root.clone(),
            event_root: manifest.event_root.clone(),
            reserve_commitment_id: reserve_commitment_id.to_string(),
            state_diff_root: manifest.state_diff_root.clone(),
            inclusion_witness_root: empty_root("CLAIM-INCLUSION-WITNESSES"),
            privacy_fence_id: privacy_fence_id.to_string(),
            proof_system,
            proof_root: proof_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            claimed_amount_commitment: claimed_amount_commitment.to_string(),
            settlement_height: self.height + self.config.finality_depth,
            status: ReceiptStatus::Proven,
        };
        self.settlement_claims.insert(claim_id.clone(), claim);
        self.claim_to_receipts
            .insert(claim_id.clone(), manifest.receipt_ids.clone());
        self.counters.next_claim_index += 1;
        Ok(claim_id)
    }

    pub fn add_state_diff(
        &mut self,
        claim_id: &str,
        contract_id: &str,
        target_contract_id: &str,
        diff_kind: StateDiffKind,
        before_root: &str,
        after_root: &str,
        delta_commitment: &str,
        token_id: &str,
        witness_root: &str,
    ) -> Result<String> {
        self.require_claim(claim_id)?;
        self.require_contract(contract_id)?;
        self.require_contract(target_contract_id)?;
        for (name, value) in [
            ("before_root", before_root),
            ("after_root", after_root),
            ("delta_commitment", delta_commitment),
            ("token_id", token_id),
            ("witness_root", witness_root),
        ] {
            require_nonempty(name, value)?;
        }
        let count = self
            .state_diffs
            .values()
            .filter(|diff| diff.claim_id == claim_id)
            .count() as u32;
        if count >= self.config.max_state_diffs_per_claim {
            return Err("state diff count exceeds configured maximum".to_string());
        }
        let diff_id = state_diff_id(claim_id, count as u64 + 1);
        let diff = CrossContractStateDiff {
            diff_id: diff_id.clone(),
            claim_id: claim_id.to_string(),
            contract_id: contract_id.to_string(),
            target_contract_id: target_contract_id.to_string(),
            diff_kind,
            before_root: before_root.to_string(),
            after_root: after_root.to_string(),
            delta_commitment: delta_commitment.to_string(),
            token_id: token_id.to_string(),
            witness_root: witness_root.to_string(),
        };
        self.state_diffs.insert(diff_id.clone(), diff);
        Ok(diff_id)
    }

    pub fn add_fee_receipt(
        &mut self,
        claim_id: &str,
        payer_commitment: &str,
        sponsor_commitment: &str,
        asset_id: &str,
        fee_kind: FeeKind,
        amount_units: u64,
        fee_commitment: &str,
        rebate_commitment: &str,
    ) -> Result<String> {
        self.require_claim(claim_id)?;
        for (name, value) in [
            ("payer_commitment", payer_commitment),
            ("sponsor_commitment", sponsor_commitment),
            ("asset_id", asset_id),
            ("fee_commitment", fee_commitment),
            ("rebate_commitment", rebate_commitment),
        ] {
            require_nonempty(name, value)?;
        }
        if amount_units == 0 {
            return Err("fee amount must be nonzero".to_string());
        }
        let rebate_units = amount_units.saturating_mul(self.config.rebate_bps as u64) / 10_000;
        let fee_id = fee_receipt_id(claim_id, self.counters.next_fee_index);
        let receipt = FeeReceipt {
            fee_id: fee_id.clone(),
            claim_id: claim_id.to_string(),
            payer_commitment: payer_commitment.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            asset_id: asset_id.to_string(),
            fee_kind,
            amount_units,
            rebate_units,
            fee_commitment: fee_commitment.to_string(),
            rebate_commitment: rebate_commitment.to_string(),
        };
        self.fee_receipts.insert(fee_id.clone(), receipt);
        self.counters.total_fee_units += amount_units as u128;
        self.counters.total_rebate_units += rebate_units as u128;
        self.counters.next_fee_index += 1;
        Ok(fee_id)
    }

    pub fn add_inclusion_witness(
        &mut self,
        claim_id: &str,
        witness_kind: WitnessKind,
        leaf_id: &str,
        leaf_root: &str,
        path_root: &str,
        expected_root: &str,
        position_commitment: &str,
    ) -> Result<String> {
        self.require_claim(claim_id)?;
        for (name, value) in [
            ("leaf_id", leaf_id),
            ("leaf_root", leaf_root),
            ("path_root", path_root),
            ("expected_root", expected_root),
            ("position_commitment", position_commitment),
        ] {
            require_nonempty(name, value)?;
        }
        let witness_id = inclusion_witness_id(claim_id, self.counters.next_witness_index);
        let witness = InclusionWitness {
            witness_id: witness_id.clone(),
            claim_id: claim_id.to_string(),
            witness_kind,
            leaf_id: leaf_id.to_string(),
            leaf_root: leaf_root.to_string(),
            path_root: path_root.to_string(),
            expected_root: expected_root.to_string(),
            position_commitment: position_commitment.to_string(),
            verified: true,
        };
        self.inclusion_witnesses.insert(witness_id.clone(), witness);
        self.counters.next_witness_index += 1;
        self.refresh_claim_witness_root(claim_id)?;
        Ok(witness_id)
    }

    pub fn add_watcher_attestation(
        &mut self,
        claim_id: &str,
        watcher_id: &str,
        attestation_kind: AttestationKind,
        observed_root: &str,
        statement_root: &str,
        pq_signature_root: &str,
        weight: u64,
    ) -> Result<String> {
        self.require_claim(claim_id)?;
        require_nonempty("watcher_id", watcher_id)?;
        require_nonempty("observed_root", observed_root)?;
        require_nonempty("statement_root", statement_root)?;
        require_nonempty("pq_signature_root", pq_signature_root)?;
        if weight == 0 {
            return Err("watcher attestation weight must be nonzero".to_string());
        }
        let attestation_id = watcher_attestation_id(claim_id, self.counters.next_attestation_index);
        let attestation = WatcherAttestation {
            attestation_id: attestation_id.clone(),
            claim_id: claim_id.to_string(),
            watcher_id: watcher_id.to_string(),
            attestation_kind,
            observed_root: observed_root.to_string(),
            statement_root: statement_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            weight,
            observed_at_height: self.height,
        };
        self.claim_to_watchers
            .entry(claim_id.to_string())
            .or_default()
            .insert(watcher_id.to_string());
        self.watcher_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.next_attestation_index += 1;
        Ok(attestation_id)
    }

    pub fn settle_claim(&mut self, claim_id: &str) -> Result<()> {
        let watcher_weight = self.watcher_weight(claim_id);
        if watcher_weight < self.config.min_watcher_weight {
            return Err("insufficient watcher attestation weight".to_string());
        }
        if self.config.require_inclusion_witness && self.claim_witness_count(claim_id) == 0 {
            return Err("claim has no inclusion witness".to_string());
        }
        let claim = self
            .settlement_claims
            .get_mut(claim_id)
            .ok_or_else(|| "settlement claim not found".to_string())?;
        if self.height < claim.settlement_height {
            return Err("claim has not reached settlement height".to_string());
        }
        claim.status = ReceiptStatus::Settled;
        if let Some(receipts) = self.claim_to_receipts.get(claim_id) {
            for receipt_id in receipts {
                if let Some(receipt) = self.receipts.get_mut(receipt_id) {
                    receipt.status = ReceiptStatus::Settled;
                }
            }
        }
        if let Some(fence) = self.privacy_fences.get(&claim.privacy_fence_id) {
            for nullifier in &fence.spent_nullifiers {
                self.spent_nullifiers.insert(nullifier.clone());
            }
        }
        self.counters.claims_settled += 1;
        Ok(())
    }

    pub fn submit_slashing_evidence(
        &mut self,
        claim_id: &str,
        accused_party: &str,
        evidence_kind: EvidenceKind,
        expected_root: &str,
        observed_root: &str,
        contradiction_root: &str,
        reporter_commitment: &str,
    ) -> Result<String> {
        self.require_claim(claim_id)?;
        for (name, value) in [
            ("accused_party", accused_party),
            ("expected_root", expected_root),
            ("observed_root", observed_root),
            ("contradiction_root", contradiction_root),
            ("reporter_commitment", reporter_commitment),
        ] {
            require_nonempty(name, value)?;
        }
        let accepted = expected_root != observed_root;
        let slash_units = if accepted {
            self.config.slash_bond_units
        } else {
            0
        };
        let evidence_id = slashing_evidence_id(claim_id, self.counters.next_evidence_index);
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            claim_id: claim_id.to_string(),
            accused_party: accused_party.to_string(),
            evidence_kind,
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            contradiction_root: contradiction_root.to_string(),
            reporter_commitment: reporter_commitment.to_string(),
            slash_units,
            accepted,
            height: self.height,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.counters.next_evidence_index += 1;
        if accepted {
            if let Some(claim) = self.settlement_claims.get_mut(claim_id) {
                claim.status = ReceiptStatus::Slashed;
            }
            self.counters.slash_events += 1;
            self.counters.total_slashed_units += slash_units as u128;
        }
        Ok(evidence_id)
    }

    pub fn reject_claim(&mut self, claim_id: &str, reason_root: &str) -> Result<()> {
        require_nonempty("reason_root", reason_root)?;
        let claim = self
            .settlement_claims
            .get_mut(claim_id)
            .ok_or_else(|| "settlement claim not found".to_string())?;
        claim.status = ReceiptStatus::Rejected;
        self.counters.claims_rejected += 1;
        Ok(())
    }

    pub fn watcher_weight(&self, claim_id: &str) -> u64 {
        self.watcher_attestations
            .values()
            .filter(|attestation| attestation.claim_id == claim_id)
            .map(|attestation| attestation.weight)
            .sum()
    }

    pub fn claim_witness_count(&self, claim_id: &str) -> usize {
        self.inclusion_witnesses
            .values()
            .filter(|witness| witness.claim_id == claim_id && witness.verified)
            .count()
    }

    pub fn claim_fee_total(&self, claim_id: &str) -> u64 {
        self.fee_receipts
            .values()
            .filter(|receipt| receipt.claim_id == claim_id)
            .map(|receipt| receipt.amount_units)
            .sum()
    }

    pub fn claim_rebate_total(&self, claim_id: &str) -> u64 {
        self.fee_receipts
            .values()
            .filter(|receipt| receipt.claim_id == claim_id)
            .map(|receipt| receipt.rebate_units)
            .sum()
    }

    fn refresh_claim_witness_root(&mut self, claim_id: &str) -> Result<()> {
        let witness_roots = self
            .inclusion_witnesses
            .values()
            .filter(|witness| witness.claim_id == claim_id)
            .map(InclusionWitness::root)
            .collect::<Vec<_>>();
        let root = set_root("CLAIM-INCLUSION-WITNESSES", &witness_roots);
        let claim = self
            .settlement_claims
            .get_mut(claim_id)
            .ok_or_else(|| "settlement claim not found".to_string())?;
        claim.inclusion_witness_root = root;
        Ok(())
    }

    fn require_contract(&self, contract_id: &str) -> Result<&ContractDescriptor> {
        self.contracts
            .get(contract_id)
            .ok_or_else(|| "contract not found".to_string())
    }

    fn require_receipt(&self, receipt_id: &str) -> Result<&ReceiptIndexEntry> {
        self.receipts
            .get(receipt_id)
            .ok_or_else(|| "receipt not found".to_string())
    }

    fn require_claim(&self, claim_id: &str) -> Result<&BridgeSettlementProof> {
        self.settlement_claims
            .get(claim_id)
            .ok_or_else(|| "settlement claim not found".to_string())
    }
}

pub fn contract_id(label: &str, index: u64) -> String {
    deterministic_id("CONTRACT-ID", label, index)
}

pub fn receipt_id(contract_id: &str, sequence: u64) -> String {
    deterministic_id("RECEIPT-ID", contract_id, sequence)
}

pub fn manifest_id(label: &str, index: u64) -> String {
    deterministic_id("MANIFEST-ID", label, index)
}

pub fn encrypted_manifest_id(label: &str, index: u64) -> String {
    deterministic_id("ENCRYPTED-MANIFEST-ID", label, index)
}

pub fn event_root_id(contract_id: &str, index: u64) -> String {
    deterministic_id("EVENT-ROOT-ID", contract_id, index)
}

pub fn settlement_claim_id(label: &str, index: u64) -> String {
    deterministic_id("SETTLEMENT-CLAIM-ID", label, index)
}

pub fn reserve_id(epoch: u64, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-RECEIPT-BRIDGE:RESERVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(epoch),
            HashPart::U64(index),
        ],
        32,
    )
}

pub fn privacy_fence_id(claim_id: &str, index: u64) -> String {
    deterministic_id("PRIVACY-FENCE-ID", claim_id, index)
}

pub fn state_diff_id(claim_id: &str, index: u64) -> String {
    deterministic_id("STATE-DIFF-ID", claim_id, index)
}

pub fn fee_receipt_id(claim_id: &str, index: u64) -> String {
    deterministic_id("FEE-RECEIPT-ID", claim_id, index)
}

pub fn inclusion_witness_id(claim_id: &str, index: u64) -> String {
    deterministic_id("INCLUSION-WITNESS-ID", claim_id, index)
}

pub fn watcher_attestation_id(claim_id: &str, index: u64) -> String {
    deterministic_id("WATCHER-ATTESTATION-ID", claim_id, index)
}

pub fn slashing_evidence_id(claim_id: &str, index: u64) -> String {
    deterministic_id("SLASHING-EVIDENCE-ID", claim_id, index)
}

pub fn deterministic_id(domain: &str, label: &str, index: u64) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-RECEIPT-BRIDGE:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label.trim()),
            HashPart::U64(index),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-RECEIPT-BRIDGE:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn value_root<T: Serialize>(domain: &str, value: &T) -> String {
    payload_root(domain, &stable_record(value))
}

pub fn set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    let leaves = sorted.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-L2-PQ-RECEIPT-BRIDGE:{domain}"), &leaves)
}

pub fn btree_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-L2-PQ-RECEIPT-BRIDGE:{domain}"), &leaves)
}

pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": stable_record(value)
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-L2-PQ-RECEIPT-BRIDGE:{domain}"), &leaves)
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(&format!("PRIVATE-L2-PQ-RECEIPT-BRIDGE:{domain}"), &[])
}

pub fn stable_record<T: Serialize>(value: &T) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => value,
        Err(error) => json!({
            "serialization_error": error.to_string()
        }),
    }
}

fn require_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must be nonempty"))
    } else {
        Ok(())
    }
}
