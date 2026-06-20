use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-latency-mev-guard-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-threshold-delay-window";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const DELAY_ENCRYPTION_SUITE: &str = "threshold-timelock-delay-encryption-v1";
pub const LATENCY_COMMITMENT_SUITE: &str = "bounded-latency-commit-reveal-v1";
pub const FAIR_SEQUENCING_SUITE: &str = "private-contract-fair-sequencing-attestation-v1";
pub const PRIVACY_FENCE_SUITE: &str = "zk-nullifier-privacy-fence-v1";
pub const SLASHING_PROOF_SUITE: &str = "pq-signed-latency-mev-slashing-evidence-v1";
pub const FEE_REBATE_SUITE: &str = "private-contract-low-fee-rebate-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_628_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_404_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_DELAY_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 2;
pub const DEFAULT_MAX_TICKETS_PER_WINDOW: u64 = 768;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 2_500;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 850;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUORUM_THRESHOLD_BPS: u64 = 6_700;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 420;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 180;
pub const DEFAULT_REBATE_BUDGET_MICRO_UNITS: u64 = 90_000_000;
pub const DEFAULT_SEQUENCER_BOND_MICRO_UNITS: u64 = 1_500_000;
pub const DEFAULT_EMERGENCY_BYPASS_BOND_MICRO_UNITS: u64 = 3_000_000;
pub const MAX_TICKETS: usize = 65_536;
pub const MAX_WINDOWS: usize = 8_192;
pub const MAX_ATTESTATIONS: usize = 65_536;
pub const MAX_BONDS: usize = 16_384;
pub const MAX_REBATES: usize = 65_536;
pub const MAX_FENCES: usize = 65_536;
pub const MAX_BYPASSES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCallKind {
    ConfidentialTransfer,
    ConfidentialSwap,
    ConfidentialMint,
    ConfidentialBurn,
    PrivateContractCall,
    PrivateContractBatch,
    MoneroBridgeDeposit,
    MoneroBridgeExit,
    OracleUpdate,
    ProofAggregation,
    EmergencyBypass,
}

impl ContractCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::ConfidentialMint => "confidential_mint",
            Self::ConfidentialBurn => "confidential_burn",
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateContractBatch => "private_contract_batch",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::ProofAggregation => "proof_aggregation",
            Self::EmergencyBypass => "emergency_bypass",
        }
    }

    pub fn lane(self) -> SequencingLane {
        match self {
            Self::ConfidentialSwap => SequencingLane::PrivateDefi,
            Self::PrivateContractCall | Self::PrivateContractBatch => {
                SequencingLane::ConfidentialContracts
            }
            Self::MoneroBridgeDeposit | Self::MoneroBridgeExit => SequencingLane::BridgeCritical,
            Self::OracleUpdate => SequencingLane::OracleProtected,
            Self::ProofAggregation => SequencingLane::ProofAggregation,
            Self::EmergencyBypass => SequencingLane::Emergency,
            Self::ConfidentialTransfer | Self::ConfidentialMint | Self::ConfidentialBurn => {
                SequencingLane::PrivatePayments
            }
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::EmergencyBypass => 1_000,
            Self::MoneroBridgeExit => 940,
            Self::MoneroBridgeDeposit => 900,
            Self::ConfidentialSwap => 840,
            Self::PrivateContractBatch => 800,
            Self::PrivateContractCall => 760,
            Self::ConfidentialTransfer => 700,
            Self::ConfidentialMint => 660,
            Self::ConfidentialBurn => 640,
            Self::ProofAggregation => 560,
            Self::OracleUpdate => 520,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequencingLane {
    PrivatePayments,
    PrivateDefi,
    ConfidentialContracts,
    BridgeCritical,
    OracleProtected,
    ProofAggregation,
    Emergency,
}

impl SequencingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivatePayments => "private_payments",
            Self::PrivateDefi => "private_defi",
            Self::ConfidentialContracts => "confidential_contracts",
            Self::BridgeCritical => "bridge_critical",
            Self::OracleProtected => "oracle_protected",
            Self::ProofAggregation => "proof_aggregation",
            Self::Emergency => "emergency",
        }
    }

    pub fn rank(self) -> u64 {
        match self {
            Self::Emergency => 0,
            Self::BridgeCritical => 1,
            Self::PrivateDefi => 2,
            Self::ConfidentialContracts => 3,
            Self::PrivatePayments => 4,
            Self::ProofAggregation => 5,
            Self::OracleProtected => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Submitted,
    Admitted,
    Committed,
    Delayed,
    Revealed,
    Sequenced,
    Executed,
    Rebated,
    Expired,
    Rejected,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Committed => "committed",
            Self::Delayed => "delayed",
            Self::Revealed => "revealed",
            Self::Sequenced => "sequenced",
            Self::Executed => "executed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Admitted | Self::Committed | Self::Delayed | Self::Revealed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Sealed,
    DelayLocked,
    RevealReady,
    Sequenced,
    Executed,
    Finalized,
    Challenged,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::DelayLocked => "delay_locked",
            Self::RevealReady => "reveal_ready",
            Self::Sequenced => "sequenced",
            Self::Executed => "executed",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Admission,
    LatencyCommitment,
    DelayWindowSeal,
    ThresholdReveal,
    FairSequence,
    Execution,
    Rebate,
    EmergencyBypass,
    SlashingEvidence,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::LatencyCommitment => "latency_commitment",
            Self::DelayWindowSeal => "delay_window_seal",
            Self::ThresholdReveal => "threshold_reveal",
            Self::FairSequence => "fair_sequence",
            Self::Execution => "execution",
            Self::Rebate => "rebate",
            Self::EmergencyBypass => "emergency_bypass",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Nullifier,
    ContractNonce,
    AccountEpoch,
    CallGraph,
    StorageSlot,
    BridgeExit,
    MoneroKeyImage,
    ReplayDomain,
    SearcherIdentity,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::ContractNonce => "contract_nonce",
            Self::AccountEpoch => "account_epoch",
            Self::CallGraph => "call_graph",
            Self::StorageSlot => "storage_slot",
            Self::BridgeExit => "bridge_exit",
            Self::MoneroKeyImage => "monero_key_image",
            Self::ReplayDomain => "replay_domain",
            Self::SearcherIdentity => "searcher_identity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Posted,
    Locked,
    Released,
    Slashed,
    Disputed,
}

impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    EarlyReveal,
    LateReveal,
    LatencyEquivocation,
    FairOrderViolation,
    Censorship,
    PrivacyLeak,
    InvalidEmergencyBypass,
    InvalidExecutionReceipt,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EarlyReveal => "early_reveal",
            Self::LateReveal => "late_reveal",
            Self::LatencyEquivocation => "latency_equivocation",
            Self::FairOrderViolation => "fair_order_violation",
            Self::Censorship => "censorship",
            Self::PrivacyLeak => "privacy_leak",
            Self::InvalidEmergencyBypass => "invalid_emergency_bypass",
            Self::InvalidExecutionReceipt => "invalid_execution_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    SoftLatencyMet,
    BatchedProof,
    LowFeeLane,
    PrivacySetBoost,
    DelayWindowAmortization,
    BridgeCriticalSubsidy,
    EmergencyRefund,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SoftLatencyMet => "soft_latency_met",
            Self::BatchedProof => "batched_proof",
            Self::LowFeeLane => "low_fee_lane",
            Self::PrivacySetBoost => "privacy_set_boost",
            Self::DelayWindowAmortization => "delay_window_amortization",
            Self::BridgeCriticalSubsidy => "bridge_critical_subsidy",
            Self::EmergencyRefund => "emergency_refund",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_kem_suite: String,
    pub pq_signature_suite: String,
    pub delay_encryption_suite: String,
    pub latency_commitment_suite: String,
    pub fair_sequencing_suite: String,
    pub privacy_fence_suite: String,
    pub slashing_proof_suite: String,
    pub fee_rebate_suite: String,
    pub ticket_ttl_blocks: u64,
    pub delay_window_blocks: u64,
    pub reveal_window_blocks: u64,
    pub max_tickets_per_window: u64,
    pub max_latency_ms: u64,
    pub soft_latency_ms: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub quorum_threshold_bps: u64,
    pub base_fee_micro_units: u64,
    pub low_fee_target_micro_units: u64,
    pub rebate_budget_micro_units: u64,
    pub sequencer_bond_micro_units: u64,
    pub emergency_bypass_bond_micro_units: u64,
    pub emergency_bypass_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            delay_encryption_suite: DELAY_ENCRYPTION_SUITE.to_string(),
            latency_commitment_suite: LATENCY_COMMITMENT_SUITE.to_string(),
            fair_sequencing_suite: FAIR_SEQUENCING_SUITE.to_string(),
            privacy_fence_suite: PRIVACY_FENCE_SUITE.to_string(),
            slashing_proof_suite: SLASHING_PROOF_SUITE.to_string(),
            fee_rebate_suite: FEE_REBATE_SUITE.to_string(),
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            delay_window_blocks: DEFAULT_DELAY_WINDOW_BLOCKS,
            reveal_window_blocks: DEFAULT_REVEAL_WINDOW_BLOCKS,
            max_tickets_per_window: DEFAULT_MAX_TICKETS_PER_WINDOW,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_threshold_bps: DEFAULT_QUORUM_THRESHOLD_BPS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            rebate_budget_micro_units: DEFAULT_REBATE_BUDGET_MICRO_UNITS,
            sequencer_bond_micro_units: DEFAULT_SEQUENCER_BOND_MICRO_UNITS,
            emergency_bypass_bond_micro_units: DEFAULT_EMERGENCY_BYPASS_BOND_MICRO_UNITS,
            emergency_bypass_enabled: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch",
        )?;
        require(self.schema_version == SCHEMA_VERSION, "schema mismatch")?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(self.ticket_ttl_blocks > 0, "ticket ttl must be positive")?;
        require(
            self.delay_window_blocks > 0,
            "delay window must be positive",
        )?;
        require(
            self.reveal_window_blocks > 0,
            "reveal window must be positive",
        )?;
        require(
            self.max_tickets_per_window > 0,
            "window ticket capacity must be positive",
        )?;
        require(self.max_latency_ms > 0, "max latency must be positive")?;
        require(
            self.soft_latency_ms <= self.max_latency_ms,
            "soft latency cannot exceed max latency",
        )?;
        require(self.min_privacy_set > 0, "privacy set must be positive")?;
        require(
            self.min_pq_security_bits >= 128,
            "pq security floor must be at least 128 bits",
        )?;
        require(
            self.quorum_threshold_bps <= MAX_BPS,
            "quorum threshold exceeds max bps",
        )?;
        require(
            self.low_fee_target_micro_units <= self.base_fee_micro_units,
            "low fee target cannot exceed base fee",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "delay_encryption_suite": self.delay_encryption_suite,
            "latency_commitment_suite": self.latency_commitment_suite,
            "fair_sequencing_suite": self.fair_sequencing_suite,
            "privacy_fence_suite": self.privacy_fence_suite,
            "slashing_proof_suite": self.slashing_proof_suite,
            "fee_rebate_suite": self.fee_rebate_suite,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "delay_window_blocks": self.delay_window_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "max_tickets_per_window": self.max_tickets_per_window,
            "max_latency_ms": self.max_latency_ms,
            "soft_latency_ms": self.soft_latency_ms,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_threshold_bps": self.quorum_threshold_bps,
            "base_fee_micro_units": self.base_fee_micro_units,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "rebate_budget_micro_units": self.rebate_budget_micro_units,
            "sequencer_bond_micro_units": self.sequencer_bond_micro_units,
            "emergency_bypass_bond_micro_units": self.emergency_bypass_bond_micro_units,
            "emergency_bypass_enabled": self.emergency_bypass_enabled,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_ticket_sequence: u64,
    pub next_window_sequence: u64,
    pub next_attestation_sequence: u64,
    pub next_bond_sequence: u64,
    pub next_slash_sequence: u64,
    pub next_rebate_sequence: u64,
    pub next_fence_sequence: u64,
    pub next_bypass_sequence: u64,
    pub admitted_tickets: u64,
    pub rejected_tickets: u64,
    pub executed_tickets: u64,
    pub emergency_bypasses: u64,
    pub slashed_bonds: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "counters",
            "next_ticket_sequence": self.next_ticket_sequence,
            "next_window_sequence": self.next_window_sequence,
            "next_attestation_sequence": self.next_attestation_sequence,
            "next_bond_sequence": self.next_bond_sequence,
            "next_slash_sequence": self.next_slash_sequence,
            "next_rebate_sequence": self.next_rebate_sequence,
            "next_fence_sequence": self.next_fence_sequence,
            "next_bypass_sequence": self.next_bypass_sequence,
            "admitted_tickets": self.admitted_tickets,
            "rejected_tickets": self.rejected_tickets,
            "executed_tickets": self.executed_tickets,
            "emergency_bypasses": self.emergency_bypasses,
            "slashed_bonds": self.slashed_bonds,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOrderingTicket {
    pub ticket_id: String,
    pub sequence: u64,
    pub call_kind: ContractCallKind,
    pub lane: SequencingLane,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub encrypted_call_root: String,
    pub call_commitment_root: String,
    pub pq_kem_ciphertext_root: String,
    pub pq_signature_root: String,
    pub latency_commitment_root: String,
    pub nullifier_root: String,
    pub privacy_fence_root: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub submitted_at_ms: u64,
    pub expires_at_height: u64,
    pub status: TicketStatus,
}

impl EncryptedOrderingTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        call_kind: ContractCallKind,
        sender_commitment: &str,
        contract_commitment: &str,
        encrypted_call_root: &str,
        call_commitment_root: &str,
        pq_kem_ciphertext_root: &str,
        pq_signature_root: &str,
        latency_commitment_root: &str,
        nullifier_root: &str,
        privacy_fence_root: &str,
        fee_asset_id: &str,
        max_fee_micro_units: u64,
        priority_fee_micro_units: u64,
        privacy_set_size: u64,
        pq_security_bits: u16,
        submitted_at_height: u64,
        submitted_at_ms: u64,
        expires_at_height: u64,
    ) -> Result<Self> {
        require(
            !sender_commitment.is_empty(),
            "sender commitment is required",
        )?;
        require(
            !contract_commitment.is_empty(),
            "contract commitment is required",
        )?;
        require(
            !encrypted_call_root.is_empty(),
            "encrypted call root is required",
        )?;
        require(
            !call_commitment_root.is_empty(),
            "call commitment root is required",
        )?;
        require(
            !pq_kem_ciphertext_root.is_empty(),
            "pq kem root is required",
        )?;
        require(
            !pq_signature_root.is_empty(),
            "pq signature root is required",
        )?;
        require(
            !latency_commitment_root.is_empty(),
            "latency commitment root is required",
        )?;
        require(!nullifier_root.is_empty(), "nullifier root is required")?;
        require(
            !privacy_fence_root.is_empty(),
            "privacy fence root is required",
        )?;
        require(!fee_asset_id.is_empty(), "fee asset id is required")?;
        require(
            expires_at_height > submitted_at_height,
            "ticket expiry must be later",
        )?;
        let lane = call_kind.lane();
        let ticket_id = ticket_id(
            sequence,
            sender_commitment,
            contract_commitment,
            call_commitment_root,
            nullifier_root,
            submitted_at_height,
        );
        Ok(Self {
            ticket_id,
            sequence,
            call_kind,
            lane,
            sender_commitment: sender_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            encrypted_call_root: encrypted_call_root.to_string(),
            call_commitment_root: call_commitment_root.to_string(),
            pq_kem_ciphertext_root: pq_kem_ciphertext_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            latency_commitment_root: latency_commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            privacy_fence_root: privacy_fence_root.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_micro_units,
            priority_fee_micro_units,
            privacy_set_size,
            pq_security_bits,
            submitted_at_height,
            submitted_at_ms,
            expires_at_height,
            status: TicketStatus::Submitted,
        })
    }

    pub fn latency_score(&self) -> u64 {
        self.call_kind
            .base_weight()
            .saturating_add(self.priority_fee_micro_units.min(1_000))
            .saturating_add(self.privacy_set_size.min(1_000) / 8)
            .saturating_sub(self.lane.rank() * 8)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_ordering_ticket",
            "ticket_id": self.ticket_id,
            "sequence": self.sequence,
            "call_kind": self.call_kind.as_str(),
            "lane": self.lane.as_str(),
            "sender_commitment": self.sender_commitment,
            "contract_commitment": self.contract_commitment,
            "encrypted_call_root": self.encrypted_call_root,
            "call_commitment_root": self.call_commitment_root,
            "pq_kem_ciphertext_root": self.pq_kem_ciphertext_root,
            "pq_signature_root": self.pq_signature_root,
            "latency_commitment_root": self.latency_commitment_root,
            "nullifier_root": self.nullifier_root,
            "privacy_fence_root": self.privacy_fence_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "submitted_at_ms": self.submitted_at_ms,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "latency_score": self.latency_score(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("ENCRYPTED-ORDERING-TICKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyCommitment {
    pub commitment_id: String,
    pub sequence: u64,
    pub ticket_id: String,
    pub sequencer_id: String,
    pub arrival_commitment_root: String,
    pub receive_timestamp_ms: u64,
    pub soft_deadline_ms: u64,
    pub hard_deadline_ms: u64,
    pub path_oblivious_routing_root: String,
    pub pq_signature_root: String,
}

impl LatencyCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        ticket_id: &str,
        sequencer_id: &str,
        arrival_commitment_root: &str,
        receive_timestamp_ms: u64,
        soft_deadline_ms: u64,
        hard_deadline_ms: u64,
        path_oblivious_routing_root: &str,
        pq_signature_root: &str,
    ) -> Result<Self> {
        require(!ticket_id.is_empty(), "ticket id is required")?;
        require(!sequencer_id.is_empty(), "sequencer id is required")?;
        require(
            !arrival_commitment_root.is_empty(),
            "arrival commitment root is required",
        )?;
        require(
            soft_deadline_ms >= receive_timestamp_ms,
            "soft deadline cannot precede receive time",
        )?;
        require(
            hard_deadline_ms >= soft_deadline_ms,
            "hard deadline cannot precede soft deadline",
        )?;
        require(
            !path_oblivious_routing_root.is_empty(),
            "path oblivious routing root is required",
        )?;
        require(
            !pq_signature_root.is_empty(),
            "pq signature root is required",
        )?;
        let commitment_id =
            latency_commitment_id(sequence, ticket_id, sequencer_id, arrival_commitment_root);
        Ok(Self {
            commitment_id,
            sequence,
            ticket_id: ticket_id.to_string(),
            sequencer_id: sequencer_id.to_string(),
            arrival_commitment_root: arrival_commitment_root.to_string(),
            receive_timestamp_ms,
            soft_deadline_ms,
            hard_deadline_ms,
            path_oblivious_routing_root: path_oblivious_routing_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "latency_commitment",
            "commitment_id": self.commitment_id,
            "sequence": self.sequence,
            "ticket_id": self.ticket_id,
            "sequencer_id": self.sequencer_id,
            "arrival_commitment_root": self.arrival_commitment_root,
            "receive_timestamp_ms": self.receive_timestamp_ms,
            "soft_deadline_ms": self.soft_deadline_ms,
            "hard_deadline_ms": self.hard_deadline_ms,
            "path_oblivious_routing_root": self.path_oblivious_routing_root,
            "pq_signature_root": self.pq_signature_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("LATENCY-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayEncryptionWindow {
    pub window_id: String,
    pub sequence: u64,
    pub lane: SequencingLane,
    pub start_height: u64,
    pub seal_height: u64,
    pub reveal_height: u64,
    pub execute_height: u64,
    pub encrypted_ticket_root: String,
    pub latency_commitment_root: String,
    pub threshold_key_commitment_root: String,
    pub delay_ciphertext_root: String,
    pub status: WindowStatus,
}

impl DelayEncryptionWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        lane: SequencingLane,
        start_height: u64,
        seal_height: u64,
        reveal_height: u64,
        execute_height: u64,
        encrypted_ticket_root: &str,
        latency_commitment_root: &str,
        threshold_key_commitment_root: &str,
        delay_ciphertext_root: &str,
        status: WindowStatus,
    ) -> Result<Self> {
        require(
            seal_height > start_height,
            "seal height must follow start height",
        )?;
        require(
            reveal_height >= seal_height,
            "reveal height must follow seal height",
        )?;
        require(
            execute_height >= reveal_height,
            "execute height must follow reveal height",
        )?;
        require(
            !encrypted_ticket_root.is_empty(),
            "encrypted ticket root is required",
        )?;
        require(
            !latency_commitment_root.is_empty(),
            "latency commitment root is required",
        )?;
        require(
            !threshold_key_commitment_root.is_empty(),
            "threshold key root is required",
        )?;
        require(
            !delay_ciphertext_root.is_empty(),
            "delay ciphertext root is required",
        )?;
        let window_id = window_id(sequence, lane, start_height, reveal_height);
        Ok(Self {
            window_id,
            sequence,
            lane,
            start_height,
            seal_height,
            reveal_height,
            execute_height,
            encrypted_ticket_root: encrypted_ticket_root.to_string(),
            latency_commitment_root: latency_commitment_root.to_string(),
            threshold_key_commitment_root: threshold_key_commitment_root.to_string(),
            delay_ciphertext_root: delay_ciphertext_root.to_string(),
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "delay_encryption_window",
            "window_id": self.window_id,
            "sequence": self.sequence,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "seal_height": self.seal_height,
            "reveal_height": self.reveal_height,
            "execute_height": self.execute_height,
            "encrypted_ticket_root": self.encrypted_ticket_root,
            "latency_commitment_root": self.latency_commitment_root,
            "threshold_key_commitment_root": self.threshold_key_commitment_root,
            "delay_ciphertext_root": self.delay_ciphertext_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("DELAY-ENCRYPTION-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairSequencingAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub subject_root: String,
    pub ordered_ticket_root: String,
    pub committee_root: String,
    pub aggregate_public_key_root: String,
    pub aggregate_signature_root: String,
    pub signer_bitmap_root: String,
    pub weight_bps: u64,
    pub signed_at_height: u64,
}

impl FairSequencingAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        kind: AttestationKind,
        subject_id: &str,
        subject_root: &str,
        ordered_ticket_root: &str,
        committee_root: &str,
        aggregate_public_key_root: &str,
        aggregate_signature_root: &str,
        signer_bitmap_root: &str,
        weight_bps: u64,
        signed_at_height: u64,
    ) -> Result<Self> {
        require(!subject_id.is_empty(), "attestation subject id is required")?;
        require(
            !subject_root.is_empty(),
            "attestation subject root is required",
        )?;
        require(
            !ordered_ticket_root.is_empty(),
            "ordered ticket root is required",
        )?;
        require(!committee_root.is_empty(), "committee root is required")?;
        require(
            !aggregate_public_key_root.is_empty(),
            "aggregate public key root is required",
        )?;
        require(
            !aggregate_signature_root.is_empty(),
            "aggregate signature root is required",
        )?;
        require(
            !signer_bitmap_root.is_empty(),
            "signer bitmap root is required",
        )?;
        require(weight_bps <= MAX_BPS, "attestation weight exceeds max bps")?;
        let attestation_id = attestation_id(sequence, kind, subject_id, subject_root);
        Ok(Self {
            attestation_id,
            sequence,
            kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            ordered_ticket_root: ordered_ticket_root.to_string(),
            committee_root: committee_root.to_string(),
            aggregate_public_key_root: aggregate_public_key_root.to_string(),
            aggregate_signature_root: aggregate_signature_root.to_string(),
            signer_bitmap_root: signer_bitmap_root.to_string(),
            weight_bps,
            signed_at_height,
        })
    }

    pub fn satisfies(&self, threshold_bps: u64) -> bool {
        self.weight_bps >= threshold_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_sequencing_attestation",
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "attestation_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "ordered_ticket_root": self.ordered_ticket_root,
            "committee_root": self.committee_root,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "signer_bitmap_root": self.signer_bitmap_root,
            "weight_bps": self.weight_bps,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAIR-SEQUENCING-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingBond {
    pub bond_id: String,
    pub sequence: u64,
    pub operator_id: String,
    pub window_id: String,
    pub amount_micro_units: u64,
    pub bond_note_root: String,
    pub posted_at_height: u64,
    pub unlock_height: u64,
    pub status: BondStatus,
}

impl SlashingBond {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        operator_id: &str,
        window_id: &str,
        amount_micro_units: u64,
        bond_note_root: &str,
        posted_at_height: u64,
        unlock_height: u64,
        status: BondStatus,
    ) -> Result<Self> {
        require(!operator_id.is_empty(), "operator id is required")?;
        require(!window_id.is_empty(), "bond window id is required")?;
        require(amount_micro_units > 0, "bond amount must be positive")?;
        require(!bond_note_root.is_empty(), "bond note root is required")?;
        require(
            unlock_height > posted_at_height,
            "unlock height must follow post height",
        )?;
        let bond_id = bond_id(sequence, operator_id, window_id, bond_note_root);
        Ok(Self {
            bond_id,
            sequence,
            operator_id: operator_id.to_string(),
            window_id: window_id.to_string(),
            amount_micro_units,
            bond_note_root: bond_note_root.to_string(),
            posted_at_height,
            unlock_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_bond",
            "bond_id": self.bond_id,
            "sequence": self.sequence,
            "operator_id": self.operator_id,
            "window_id": self.window_id,
            "amount_micro_units": self.amount_micro_units,
            "bond_note_root": self.bond_note_root,
            "posted_at_height": self.posted_at_height,
            "unlock_height": self.unlock_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("SLASHING-BOND", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub slash_id: String,
    pub sequence: u64,
    pub bond_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub penalty_micro_units: u64,
    pub challenger_commitment: String,
    pub decided_at_height: u64,
}

impl SlashingEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        bond_id: &str,
        reason: SlashingReason,
        evidence_root: &str,
        penalty_micro_units: u64,
        challenger_commitment: &str,
        decided_at_height: u64,
    ) -> Result<Self> {
        require(!bond_id.is_empty(), "slash bond id is required")?;
        require(!evidence_root.is_empty(), "slash evidence root is required")?;
        require(penalty_micro_units > 0, "penalty must be positive")?;
        require(
            !challenger_commitment.is_empty(),
            "challenger commitment is required",
        )?;
        let slash_id = slash_id(sequence, bond_id, reason, evidence_root);
        Ok(Self {
            slash_id,
            sequence,
            bond_id: bond_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            penalty_micro_units,
            challenger_commitment: challenger_commitment.to_string(),
            decided_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_event",
            "slash_id": self.slash_id,
            "sequence": self.sequence,
            "bond_id": self.bond_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "penalty_micro_units": self.penalty_micro_units,
            "challenger_commitment": self.challenger_commitment,
            "decided_at_height": self.decided_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SLASHING-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub sequence: u64,
    pub ticket_id: String,
    pub reason: RebateReason,
    pub fee_asset_id: String,
    pub charged_micro_units: u64,
    pub target_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_note_root: String,
    pub issued_at_height: u64,
}

impl FeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        ticket_id: &str,
        reason: RebateReason,
        fee_asset_id: &str,
        charged_micro_units: u64,
        target_micro_units: u64,
        rebate_note_root: &str,
        issued_at_height: u64,
    ) -> Result<Self> {
        require(!ticket_id.is_empty(), "rebate ticket id is required")?;
        require(!fee_asset_id.is_empty(), "rebate fee asset id is required")?;
        require(!rebate_note_root.is_empty(), "rebate note root is required")?;
        let rebate_micro_units = charged_micro_units.saturating_sub(target_micro_units);
        let rebate_id = rebate_id(sequence, ticket_id, reason, rebate_note_root);
        Ok(Self {
            rebate_id,
            sequence,
            ticket_id: ticket_id.to_string(),
            reason,
            fee_asset_id: fee_asset_id.to_string(),
            charged_micro_units,
            target_micro_units,
            rebate_micro_units,
            rebate_note_root: rebate_note_root.to_string(),
            issued_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_rebate",
            "rebate_id": self.rebate_id,
            "sequence": self.sequence,
            "ticket_id": self.ticket_id,
            "reason": self.reason.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "charged_micro_units": self.charged_micro_units,
            "target_micro_units": self.target_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_note_root": self.rebate_note_root,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub sequence: u64,
    pub kind: FenceKind,
    pub ticket_id: String,
    pub namespace: String,
    pub fence_root: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl PrivacyFence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        kind: FenceKind,
        ticket_id: &str,
        namespace: &str,
        fence_root: &str,
        first_seen_height: u64,
        expires_at_height: u64,
        consumed: bool,
    ) -> Result<Self> {
        require(!ticket_id.is_empty(), "fence ticket id is required")?;
        require(!namespace.is_empty(), "fence namespace is required")?;
        require(!fence_root.is_empty(), "fence root is required")?;
        require(
            expires_at_height > first_seen_height,
            "fence expiry must follow first seen height",
        )?;
        let fence_id = fence_id(sequence, kind, namespace, fence_root);
        Ok(Self {
            fence_id,
            sequence,
            kind,
            ticket_id: ticket_id.to_string(),
            namespace: namespace.to_string(),
            fence_root: fence_root.to_string(),
            first_seen_height,
            expires_at_height,
            consumed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_fence",
            "fence_id": self.fence_id,
            "sequence": self.sequence,
            "fence_kind": self.kind.as_str(),
            "ticket_id": self.ticket_id,
            "namespace": self.namespace,
            "fence_root": self.fence_root,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyBypass {
    pub bypass_id: String,
    pub sequence: u64,
    pub ticket_id: String,
    pub requester_commitment: String,
    pub reason_root: String,
    pub bond_root: String,
    pub attestation_root: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub executed: bool,
}

impl EmergencyBypass {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        ticket_id: &str,
        requester_commitment: &str,
        reason_root: &str,
        bond_root: &str,
        attestation_root: &str,
        requested_at_height: u64,
        expires_at_height: u64,
        executed: bool,
    ) -> Result<Self> {
        require(!ticket_id.is_empty(), "bypass ticket id is required")?;
        require(
            !requester_commitment.is_empty(),
            "requester commitment is required",
        )?;
        require(!reason_root.is_empty(), "bypass reason root is required")?;
        require(!bond_root.is_empty(), "bypass bond root is required")?;
        require(
            !attestation_root.is_empty(),
            "bypass attestation root is required",
        )?;
        require(
            expires_at_height > requested_at_height,
            "bypass expiry must follow request height",
        )?;
        let bypass_id = bypass_id(sequence, ticket_id, requester_commitment, reason_root);
        Ok(Self {
            bypass_id,
            sequence,
            ticket_id: ticket_id.to_string(),
            requester_commitment: requester_commitment.to_string(),
            reason_root: reason_root.to_string(),
            bond_root: bond_root.to_string(),
            attestation_root: attestation_root.to_string(),
            requested_at_height,
            expires_at_height,
            executed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_bypass",
            "bypass_id": self.bypass_id,
            "sequence": self.sequence,
            "ticket_id": self.ticket_id,
            "requester_commitment": self.requester_commitment,
            "reason_root": self.reason_root,
            "bond_root": self.bond_root,
            "attestation_root": self.attestation_root,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "executed": self.executed,
        })
    }

    pub fn root(&self) -> String {
        payload_root("EMERGENCY-BYPASS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub ticket_root: String,
    pub latency_commitment_root: String,
    pub window_root: String,
    pub attestation_root: String,
    pub bond_root: String,
    pub slash_root: String,
    pub rebate_root: String,
    pub fence_root: String,
    pub bypass_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "roots",
            "ticket_root": self.ticket_root,
            "latency_commitment_root": self.latency_commitment_root,
            "window_root": self.window_root,
            "attestation_root": self.attestation_root,
            "bond_root": self.bond_root,
            "slash_root": self.slash_root,
            "rebate_root": self.rebate_root,
            "fence_root": self.fence_root,
            "bypass_root": self.bypass_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub rebate_budget_remaining_micro_units: u64,
    pub tickets: BTreeMap<String, EncryptedOrderingTicket>,
    pub latency_commitments: BTreeMap<String, LatencyCommitment>,
    pub windows: BTreeMap<String, DelayEncryptionWindow>,
    pub attestations: BTreeMap<String, FairSequencingAttestation>,
    pub bonds: BTreeMap<String, SlashingBond>,
    pub slashes: BTreeMap<String, SlashingEvent>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub fences: BTreeMap<String, PrivacyFence>,
    pub bypasses: BTreeMap<String, EmergencyBypass>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_monero_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            rebate_budget_remaining_micro_units: config.rebate_budget_micro_units,
            config,
            counters: Counters::default(),
            current_l2_height,
            current_monero_height,
            tickets: BTreeMap::new(),
            latency_commitments: BTreeMap::new(),
            windows: BTreeMap::new(),
            attestations: BTreeMap::new(),
            bonds: BTreeMap::new(),
            slashes: BTreeMap::new(),
            rebates: BTreeMap::new(),
            fences: BTreeMap::new(),
            bypasses: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::default(), DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT).expect("devnet");
        let ticket_a = EncryptedOrderingTicket::new(
            1,
            ContractCallKind::PrivateContractCall,
            &deterministic_root("SENDER", "alice"),
            &deterministic_root("CONTRACT", "private-vault"),
            &deterministic_root("CALL", "vault-rebalance-encrypted"),
            &deterministic_root("CALL-COMMITMENT", "vault-rebalance"),
            &deterministic_root("KEM", "ticket-a"),
            &deterministic_root("SIG", "ticket-a"),
            &deterministic_root("LATENCY", "ticket-a"),
            &deterministic_root("NULLIFIER", "ticket-a"),
            &deterministic_root("FENCE", "ticket-a"),
            "dxmr",
            420,
            20,
            512,
            256,
            DEVNET_L2_HEIGHT,
            1_700_000_000_100,
            DEVNET_L2_HEIGHT + DEFAULT_TICKET_TTL_BLOCKS,
        )
        .expect("devnet ticket a");
        let ticket_b = EncryptedOrderingTicket::new(
            2,
            ContractCallKind::ConfidentialSwap,
            &deterministic_root("SENDER", "bob"),
            &deterministic_root("CONTRACT", "private-amm"),
            &deterministic_root("CALL", "swap-encrypted"),
            &deterministic_root("CALL-COMMITMENT", "swap"),
            &deterministic_root("KEM", "ticket-b"),
            &deterministic_root("SIG", "ticket-b"),
            &deterministic_root("LATENCY", "ticket-b"),
            &deterministic_root("NULLIFIER", "ticket-b"),
            &deterministic_root("FENCE", "ticket-b"),
            "dxmr",
            390,
            35,
            640,
            256,
            DEVNET_L2_HEIGHT,
            1_700_000_000_220,
            DEVNET_L2_HEIGHT + DEFAULT_TICKET_TTL_BLOCKS,
        )
        .expect("devnet ticket b");
        let ticket_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-DEVNET-TICKETS",
            vec![ticket_a.public_record(), ticket_b.public_record()],
        );
        let latency_a = LatencyCommitment::new(
            1,
            &ticket_a.ticket_id,
            "sequencer-alpha",
            &deterministic_root("ARRIVAL", "ticket-a"),
            1_700_000_000_130,
            1_700_000_000_980,
            1_700_000_002_630,
            &deterministic_root("ROUTE", "alpha-private-path"),
            &deterministic_root("SIG", "latency-a"),
        )
        .expect("devnet latency a");
        let window = DelayEncryptionWindow::new(
            1,
            SequencingLane::ConfidentialContracts,
            DEVNET_L2_HEIGHT,
            DEVNET_L2_HEIGHT + DEFAULT_DELAY_WINDOW_BLOCKS,
            DEVNET_L2_HEIGHT + DEFAULT_DELAY_WINDOW_BLOCKS + DEFAULT_REVEAL_WINDOW_BLOCKS,
            DEVNET_L2_HEIGHT + DEFAULT_DELAY_WINDOW_BLOCKS + DEFAULT_REVEAL_WINDOW_BLOCKS + 1,
            &ticket_root,
            &latency_a.root(),
            &deterministic_root("THRESHOLD-KEY", "window-1"),
            &deterministic_root("DELAY-CIPHERTEXT", "window-1"),
            WindowStatus::DelayLocked,
        )
        .expect("devnet window");
        let attestation = FairSequencingAttestation::new(
            1,
            AttestationKind::FairSequence,
            &window.window_id,
            &window.root(),
            &ticket_root,
            &deterministic_root("COMMITTEE", "devnet-fast-finality"),
            &deterministic_root("AGG-PK", "devnet-fast-finality"),
            &deterministic_root("AGG-SIG", "window-1"),
            &deterministic_root("SIGNERS", "window-1"),
            DEFAULT_QUORUM_THRESHOLD_BPS,
            DEVNET_L2_HEIGHT + 6,
        )
        .expect("devnet attestation");
        let bond = SlashingBond::new(
            1,
            "sequencer-alpha",
            &window.window_id,
            DEFAULT_SEQUENCER_BOND_MICRO_UNITS,
            &deterministic_root("BOND-NOTE", "sequencer-alpha"),
            DEVNET_L2_HEIGHT - 8,
            DEVNET_L2_HEIGHT + 128,
            BondStatus::Locked,
        )
        .expect("devnet bond");
        let fence = PrivacyFence::new(
            1,
            FenceKind::Nullifier,
            &ticket_a.ticket_id,
            "private-contract-nullifier",
            &ticket_a.nullifier_root,
            DEVNET_L2_HEIGHT,
            DEVNET_L2_HEIGHT + DEFAULT_TICKET_TTL_BLOCKS,
            false,
        )
        .expect("devnet fence");
        let rebate = FeeRebate::new(
            1,
            &ticket_a.ticket_id,
            RebateReason::SoftLatencyMet,
            "dxmr",
            DEFAULT_BASE_FEE_MICRO_UNITS,
            DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            &deterministic_root("REBATE-NOTE", "ticket-a"),
            DEVNET_L2_HEIGHT + 7,
        )
        .expect("devnet rebate");

        state.counters = Counters {
            next_ticket_sequence: 3,
            next_window_sequence: 2,
            next_attestation_sequence: 2,
            next_bond_sequence: 2,
            next_slash_sequence: 1,
            next_rebate_sequence: 2,
            next_fence_sequence: 2,
            next_bypass_sequence: 1,
            admitted_tickets: 2,
            rejected_tickets: 0,
            executed_tickets: 0,
            emergency_bypasses: 0,
            slashed_bonds: 0,
            total_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            total_rebate_micro_units: rebate.rebate_micro_units,
        };
        state.tickets.insert(ticket_a.ticket_id.clone(), ticket_a);
        state.tickets.insert(ticket_b.ticket_id.clone(), ticket_b);
        state
            .latency_commitments
            .insert(latency_a.commitment_id.clone(), latency_a);
        state.windows.insert(window.window_id.clone(), window);
        state
            .attestations
            .insert(attestation.attestation_id.clone(), attestation);
        state.bonds.insert(bond.bond_id.clone(), bond);
        state.fences.insert(fence.fence_id.clone(), fence);
        state.rebates.insert(rebate.rebate_id.clone(), rebate);
        state.rebate_budget_remaining_micro_units = state
            .rebate_budget_remaining_micro_units
            .saturating_sub(state.counters.total_rebate_micro_units);
        state
    }

    pub fn roots(&self) -> Roots {
        let public_without_roots = self.public_record_without_roots();
        let public_record_root = public_record_root(&public_without_roots);
        let state_root = state_root_from_record(&public_without_roots);
        Roots {
            ticket_root: self.ticket_root(),
            latency_commitment_root: self.latency_commitment_root(),
            window_root: self.window_root(),
            attestation_root: self.attestation_root(),
            bond_root: self.bond_root(),
            slash_root: self.slash_root(),
            rebate_root: self.rebate_root(),
            fence_root: self.fence_root(),
            bypass_root: self.bypass_root(),
            consumed_nullifier_root: self.consumed_nullifier_root(),
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_roots();
        if let Value::Object(values) = &mut record {
            values.insert("roots".to_string(), self.roots().public_record());
        }
        record
    }

    pub fn public_record_without_roots(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_latency_mev_guard_state",
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "rebate_budget_remaining_micro_units": self.rebate_budget_remaining_micro_units,
            "tickets": self.tickets.values().map(EncryptedOrderingTicket::public_record).collect::<Vec<_>>(),
            "latency_commitments": self.latency_commitments.values().map(LatencyCommitment::public_record).collect::<Vec<_>>(),
            "windows": self.windows.values().map(DelayEncryptionWindow::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(FairSequencingAttestation::public_record).collect::<Vec<_>>(),
            "bonds": self.bonds.values().map(SlashingBond::public_record).collect::<Vec<_>>(),
            "slashes": self.slashes.values().map(SlashingEvent::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),
            "fences": self.fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "bypasses": self.bypasses.values().map(EmergencyBypass::public_record).collect::<Vec<_>>(),
            "consumed_nullifiers": self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_roots())
    }

    pub fn admit_ticket(&mut self, mut ticket: EncryptedOrderingTicket) -> Result<()> {
        require(self.tickets.len() < MAX_TICKETS, "ticket registry full")?;
        require(
            ticket.privacy_set_size >= self.config.min_privacy_set,
            "ticket privacy set below minimum",
        )?;
        require(
            ticket.pq_security_bits >= self.config.min_pq_security_bits,
            "ticket pq security below minimum",
        )?;
        require(
            ticket.expires_at_height > self.current_l2_height,
            "ticket is already expired",
        )?;
        require(
            !self.consumed_nullifiers.contains(&ticket.nullifier_root),
            "ticket nullifier already consumed",
        )?;
        ticket.status = TicketStatus::Admitted;
        self.counters.admitted_tickets = self.counters.admitted_tickets.saturating_add(1);
        self.counters.next_ticket_sequence =
            self.counters.next_ticket_sequence.max(ticket.sequence + 1);
        self.tickets.insert(ticket.ticket_id.clone(), ticket);
        Ok(())
    }

    pub fn add_latency_commitment(&mut self, commitment: LatencyCommitment) -> Result<()> {
        require(
            self.latency_commitments.len() < MAX_ATTESTATIONS,
            "latency commitment registry full",
        )?;
        require(
            self.tickets.contains_key(&commitment.ticket_id),
            "latency commitment ticket is unknown",
        )?;
        self.counters.next_attestation_sequence = self
            .counters
            .next_attestation_sequence
            .max(commitment.sequence + 1);
        self.latency_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn add_window(&mut self, window: DelayEncryptionWindow) -> Result<()> {
        require(
            self.windows.len() < MAX_WINDOWS,
            "delay window registry full",
        )?;
        self.counters.next_window_sequence =
            self.counters.next_window_sequence.max(window.sequence + 1);
        self.windows.insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn add_attestation(&mut self, attestation: FairSequencingAttestation) -> Result<()> {
        require(
            self.attestations.len() < MAX_ATTESTATIONS,
            "attestation registry full",
        )?;
        require(
            attestation.satisfies(self.config.quorum_threshold_bps),
            "attestation below quorum threshold",
        )?;
        self.counters.next_attestation_sequence = self
            .counters
            .next_attestation_sequence
            .max(attestation.sequence + 1);
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn add_bond(&mut self, bond: SlashingBond) -> Result<()> {
        require(self.bonds.len() < MAX_BONDS, "bond registry full")?;
        require(
            bond.amount_micro_units >= self.config.sequencer_bond_micro_units,
            "bond amount below sequencer floor",
        )?;
        self.counters.next_bond_sequence = self.counters.next_bond_sequence.max(bond.sequence + 1);
        self.bonds.insert(bond.bond_id.clone(), bond);
        Ok(())
    }

    pub fn record_slash(&mut self, slash: SlashingEvent) -> Result<()> {
        require(self.slashes.len() < MAX_BONDS, "slash registry full")?;
        let bond = self
            .bonds
            .get_mut(&slash.bond_id)
            .ok_or_else(|| "slash bond is unknown".to_string())?;
        require(
            slash.penalty_micro_units <= bond.amount_micro_units,
            "slash penalty exceeds bond",
        )?;
        bond.status = BondStatus::Slashed;
        self.counters.slashed_bonds = self.counters.slashed_bonds.saturating_add(1);
        self.counters.next_slash_sequence =
            self.counters.next_slash_sequence.max(slash.sequence + 1);
        self.slashes.insert(slash.slash_id.clone(), slash);
        Ok(())
    }

    pub fn issue_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        require(self.rebates.len() < MAX_REBATES, "rebate registry full")?;
        require(
            rebate.rebate_micro_units <= self.rebate_budget_remaining_micro_units,
            "rebate budget exhausted",
        )?;
        self.rebate_budget_remaining_micro_units = self
            .rebate_budget_remaining_micro_units
            .saturating_sub(rebate.rebate_micro_units);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(rebate.rebate_micro_units);
        self.counters.next_rebate_sequence =
            self.counters.next_rebate_sequence.max(rebate.sequence + 1);
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn add_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        require(
            self.fences.len() < MAX_FENCES,
            "privacy fence registry full",
        )?;
        self.counters.next_fence_sequence =
            self.counters.next_fence_sequence.max(fence.sequence + 1);
        self.fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    pub fn add_emergency_bypass(&mut self, bypass: EmergencyBypass) -> Result<()> {
        require(
            self.config.emergency_bypass_enabled,
            "emergency bypass is disabled",
        )?;
        require(self.bypasses.len() < MAX_BYPASSES, "bypass registry full")?;
        self.counters.emergency_bypasses = self.counters.emergency_bypasses.saturating_add(1);
        self.counters.next_bypass_sequence =
            self.counters.next_bypass_sequence.max(bypass.sequence + 1);
        self.bypasses.insert(bypass.bypass_id.clone(), bypass);
        Ok(())
    }

    pub fn consume_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        require(!nullifier_root.is_empty(), "nullifier root is required")?;
        require(
            !self.consumed_nullifiers.contains(nullifier_root),
            "nullifier already consumed",
        )?;
        self.consumed_nullifiers.insert(nullifier_root.to_string());
        Ok(())
    }

    pub fn ordered_ticket_ids_for_window(&self, lane: SequencingLane) -> Vec<String> {
        let mut tickets = self
            .tickets
            .values()
            .filter(|ticket| ticket.lane == lane && ticket.status.live())
            .collect::<Vec<_>>();
        tickets.sort_by(|left, right| {
            left.submitted_at_height
                .cmp(&right.submitted_at_height)
                .then(left.submitted_at_ms.cmp(&right.submitted_at_ms))
                .then(right.latency_score().cmp(&left.latency_score()))
                .then(left.ticket_id.cmp(&right.ticket_id))
        });
        tickets
            .into_iter()
            .take(self.config.max_tickets_per_window as usize)
            .map(|ticket| ticket.ticket_id.clone())
            .collect()
    }

    pub fn ticket_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-TICKET-ROOT",
            self.tickets
                .values()
                .map(EncryptedOrderingTicket::public_record)
                .collect(),
        )
    }

    pub fn latency_commitment_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-LATENCY-ROOT",
            self.latency_commitments
                .values()
                .map(LatencyCommitment::public_record)
                .collect(),
        )
    }

    pub fn window_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-WINDOW-ROOT",
            self.windows
                .values()
                .map(DelayEncryptionWindow::public_record)
                .collect(),
        )
    }

    pub fn attestation_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-ATTESTATION-ROOT",
            self.attestations
                .values()
                .map(FairSequencingAttestation::public_record)
                .collect(),
        )
    }

    pub fn bond_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-BOND-ROOT",
            self.bonds
                .values()
                .map(SlashingBond::public_record)
                .collect(),
        )
    }

    pub fn slash_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-SLASH-ROOT",
            self.slashes
                .values()
                .map(SlashingEvent::public_record)
                .collect(),
        )
    }

    pub fn rebate_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-REBATE-ROOT",
            self.rebates
                .values()
                .map(FeeRebate::public_record)
                .collect(),
        )
    }

    pub fn fence_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-FENCE-ROOT",
            self.fences
                .values()
                .map(PrivacyFence::public_record)
                .collect(),
        )
    }

    pub fn bypass_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-BYPASS-ROOT",
            self.bypasses
                .values()
                .map(EmergencyBypass::public_record)
                .collect(),
        )
    }

    pub fn consumed_nullifier_root(&self) -> String {
        let leaves = self
            .consumed_nullifiers
            .iter()
            .map(|root| json!({ "nullifier_root": root }))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-CONSUMED-NULLIFIER-ROOT",
            &leaves,
        )
    }
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn ticket_id(
    sequence: u64,
    sender_commitment: &str,
    contract_commitment: &str,
    call_commitment_root: &str,
    nullifier_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(sender_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Str(call_commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn latency_commitment_id(
    sequence: u64,
    ticket_id: &str,
    sequencer_id: &str,
    arrival_commitment_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-LATENCY-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(ticket_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(arrival_commitment_root),
        ],
        32,
    )
}

pub fn window_id(
    sequence: u64,
    lane: SequencingLane,
    start_height: u64,
    reveal_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Int(start_height as i128),
            HashPart::Int(reveal_height as i128),
        ],
        32,
    )
}

pub fn attestation_id(
    sequence: u64,
    kind: AttestationKind,
    subject_id: &str,
    subject_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
        ],
        32,
    )
}

pub fn bond_id(sequence: u64, operator_id: &str, window_id: &str, bond_note_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(operator_id),
            HashPart::Str(window_id),
            HashPart::Str(bond_note_root),
        ],
        32,
    )
}

pub fn slash_id(
    sequence: u64,
    bond_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-SLASH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(bond_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn rebate_id(
    sequence: u64,
    ticket_id: &str,
    reason: RebateReason,
    rebate_note_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(ticket_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(rebate_note_root),
        ],
        32,
    )
}

pub fn fence_id(sequence: u64, kind: FenceKind, namespace: &str, fence_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(namespace),
            HashPart::Str(fence_root),
        ],
        32,
    )
}

pub fn bypass_id(
    sequence: u64,
    ticket_id: &str,
    requester_commitment: &str,
    reason_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-BYPASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(ticket_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

pub fn lane_policy_root(lanes: &[SequencingLane]) -> String {
    let leaves = lanes
        .iter()
        .map(|lane| json!({ "lane": lane.as_str(), "rank": lane.rank() }))
        .collect::<Vec<_>>();
    merkle_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-LANE-POLICY-ROOT",
        &leaves,
    )
}

pub fn call_kind_root(kinds: &[ContractCallKind]) -> String {
    let leaves = kinds
        .iter()
        .map(|kind| {
            json!({
                "call_kind": kind.as_str(),
                "lane": kind.lane().as_str(),
                "base_weight": kind.base_weight(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-CALL-KIND-ROOT",
        &leaves,
    )
}

pub fn id_list_root(domain: &str, ids: &[&str]) -> String {
    let leaves = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-{domain}"),
        &leaves,
    )
}

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-LATENCY-MEV-GUARD-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
