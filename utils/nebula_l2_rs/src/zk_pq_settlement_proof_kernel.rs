use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkPqSettlementProofKernelResult<T> = Result<T, String>;

pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_PROTOCOL_VERSION: &str =
    "nebula-l2-zk-pq-settlement-proof-kernel-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_SCHEMA_VERSION: u64 = 1;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_ZK_VM: &str = "nebula-devnet-private-settlement-zkvm-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_RECURSION_SCHEME: &str =
    "folded-fri-recursive-settlement-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_TRANSCRIPT_SCHEME: &str =
    "ml-dsa-slh-dsa-shake256-transcript-binding-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_VERIFIER_KEY_SCHEME: &str =
    "pq-verifier-key-rotation-commitment-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_RECEIPT_SCHEME: &str =
    "monero-l2-bridge-settlement-receipt-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_SPONSOR_SCHEME: &str =
    "low-fee-private-proof-sponsorship-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_SLASHING_SCHEME: &str =
    "pq-proof-kernel-slashing-evidence-v1";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_HEIGHT: u64 = 512;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_OPERATOR_ID: &str =
    "zk-pq-settlement-operator-devnet";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_PROVER_ID: &str = "zk-pq-settlement-prover-devnet";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_SPONSOR_ID: &str = "zk-pq-settlement-sponsor-devnet";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_COMMITTEE_ID: &str =
    "zk-pq-settlement-committee-devnet";
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_BPS: u64 = 10_000;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS: usize = 8_192;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_JOBS_PER_AGGREGATE: usize = 128;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_RECURSION_DEPTH: u64 = 10;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_VERIFIER_KEY_DELAY_BLOCKS: u64 = 64;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 20;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_TARGET_VERIFY_MICROS: u64 = 18_000;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_PROOF_BYTES: u64 = 96_000;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_PUBLIC_INPUT_BYTES: u64 = 24_000;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_SPONSOR_POOL_MICRO_UNITS: u64 = 500_000;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_SLASH_BPS: u64 = 5_000;
pub const ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_LATE_PENALTY_BPS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkPqCircuitFamily {
    MoneroBridgeSettlement,
    PrivateRollupState,
    ConfidentialContractCall,
    PrivateDefiSettlement,
    FeeSponsorship,
    RecursiveAggregate,
    ChallengeResolution,
}

impl ZkPqCircuitFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridgeSettlement => "monero_bridge_settlement",
            Self::PrivateRollupState => "private_rollup_state",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::PrivateDefiSettlement => "private_defi_settlement",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::ChallengeResolution => "challenge_resolution",
        }
    }

    pub fn default_program_id(self) -> &'static str {
        match self {
            Self::MoneroBridgeSettlement => "nebula-zkvm-monero-bridge-settlement-v1",
            Self::PrivateRollupState => "nebula-zkvm-private-rollup-state-v1",
            Self::ConfidentialContractCall => "nebula-zkvm-confidential-contract-call-v1",
            Self::PrivateDefiSettlement => "nebula-zkvm-private-defi-settlement-v1",
            Self::FeeSponsorship => "nebula-zkvm-fee-sponsorship-v1",
            Self::RecursiveAggregate => "nebula-zkvm-recursive-aggregate-v1",
            Self::ChallengeResolution => "nebula-zkvm-challenge-resolution-v1",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MoneroBridgeSettlement
                | Self::PrivateRollupState
                | Self::ConfidentialContractCall
                | Self::PrivateDefiSettlement
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobKind {
    BaseProof,
    RecursiveFold,
    BatchAggregation,
    BridgeSettlement,
    SponsoredLowFee,
    VerifierKeyActivation,
    ChallengeReplay,
}

impl ProofJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseProof => "base_proof",
            Self::RecursiveFold => "recursive_fold",
            Self::BatchAggregation => "batch_aggregation",
            Self::BridgeSettlement => "bridge_settlement",
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::VerifierKeyActivation => "verifier_key_activation",
            Self::ChallengeReplay => "challenge_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    MoneroExit,
    MoneroDeposit,
    PrivateTransfer,
    ContractExecution,
    DefiNetting,
    SponsoredMaintenance,
    EmergencyChallenge,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero_exit",
            Self::MoneroDeposit => "monero_deposit",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractExecution => "contract_execution",
            Self::DefiNetting => "defi_netting",
            Self::SponsoredMaintenance => "sponsored_maintenance",
            Self::EmergencyChallenge => "emergency_challenge",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyChallenge => 10_000,
            Self::MoneroExit => 9_400,
            Self::MoneroDeposit => 8_900,
            Self::DefiNetting => 8_200,
            Self::ContractExecution => 7_600,
            Self::PrivateTransfer => 7_200,
            Self::SponsoredMaintenance => 4_500,
        }
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::ContractExecution | Self::SponsoredMaintenance
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Queued,
    WitnessLocked,
    Proving,
    Proved,
    Aggregating,
    Attested,
    ReceiptReady,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}

impl ProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::WitnessLocked => "witness_locked",
            Self::Proving => "proving",
            Self::Proved => "proved",
            Self::Aggregating => "aggregating",
            Self::Attested => "attested",
            Self::ReceiptReady => "receipt_ready",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::WitnessLocked
                | Self::Proving
                | Self::Proved
                | Self::Aggregating
                | Self::Attested
                | Self::ReceiptReady
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationStatus {
    Collecting,
    Sealed,
    Folding,
    Proved,
    TranscriptBound,
    ReceiptReady,
    Settled,
    Challenged,
    Rejected,
}

impl AggregationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Folding => "folding",
            Self::Proved => "proved",
            Self::TranscriptBound => "transcript_bound",
            Self::ReceiptReady => "receipt_ready",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }

    pub fn accepts_jobs(self) -> bool {
        matches!(self, Self::Collecting)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyStatus {
    Proposed,
    Active,
    Retiring,
    Retired,
    Revoked,
}

impl VerifierKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Retiring)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Posted,
    Confirming,
    Finalized,
    ReorgHeld,
    Challenged,
    Invalidated,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::Confirming => "confirming",
            Self::Finalized => "finalized",
            Self::ReorgHeld => "reorg_held",
            Self::Challenged => "challenged",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Reclaimed,
    Exhausted,
    Slashed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidProof,
    BadTranscriptBinding,
    StaleVerifierKey,
    BridgeReceiptMismatch,
    LateSettlement,
    SponsorFraud,
    DataUnavailable,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProof => "invalid_proof",
            Self::BadTranscriptBinding => "bad_transcript_binding",
            Self::StaleVerifierKey => "stale_verifier_key",
            Self::BridgeReceiptMismatch => "bridge_receipt_mismatch",
            Self::LateSettlement => "late_settlement",
            Self::SponsorFraud => "sponsor_fraud",
            Self::DataUnavailable => "data_unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceLocked,
    UnderReview,
    Upheld,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceLocked => "evidence_locked",
            Self::UnderReview => "under_review",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPqSettlementProofKernelConfig {
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub zk_vm: String,
    pub recursion_scheme: String,
    pub transcript_scheme: String,
    pub verifier_key_scheme: String,
    pub receipt_scheme: String,
    pub sponsor_scheme: String,
    pub slashing_scheme: String,
    pub max_jobs_per_aggregate: usize,
    pub max_recursion_depth: u64,
    pub challenge_window_blocks: u64,
    pub verifier_key_delay_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub target_verify_micros: u64,
    pub max_proof_bytes: u64,
    pub max_public_input_bytes: u64,
    pub sponsor_pool_micro_units: u64,
    pub sponsor_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub slash_bps: u64,
    pub late_penalty_bps: u64,
}

impl Default for ZkPqSettlementProofKernelConfig {
    fn default() -> Self {
        Self {
            monero_network: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_L2_NETWORK.to_string(),
            fee_asset_id: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: ZK_PQ_SETTLEMENT_PROOF_KERNEL_HASH_SUITE.to_string(),
            zk_vm: ZK_PQ_SETTLEMENT_PROOF_KERNEL_ZK_VM.to_string(),
            recursion_scheme: ZK_PQ_SETTLEMENT_PROOF_KERNEL_RECURSION_SCHEME.to_string(),
            transcript_scheme: ZK_PQ_SETTLEMENT_PROOF_KERNEL_TRANSCRIPT_SCHEME.to_string(),
            verifier_key_scheme: ZK_PQ_SETTLEMENT_PROOF_KERNEL_VERIFIER_KEY_SCHEME.to_string(),
            receipt_scheme: ZK_PQ_SETTLEMENT_PROOF_KERNEL_RECEIPT_SCHEME.to_string(),
            sponsor_scheme: ZK_PQ_SETTLEMENT_PROOF_KERNEL_SPONSOR_SCHEME.to_string(),
            slashing_scheme: ZK_PQ_SETTLEMENT_PROOF_KERNEL_SLASHING_SCHEME.to_string(),
            max_jobs_per_aggregate: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_JOBS_PER_AGGREGATE,
            max_recursion_depth: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_RECURSION_DEPTH,
            challenge_window_blocks: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            verifier_key_delay_blocks:
                ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_VERIFIER_KEY_DELAY_BLOCKS,
            receipt_finality_blocks: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            target_verify_micros: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_TARGET_VERIFY_MICROS,
            max_proof_bytes: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_PROOF_BYTES,
            max_public_input_bytes: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MAX_PUBLIC_INPUT_BYTES,
            sponsor_pool_micro_units:
                ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_SPONSOR_POOL_MICRO_UNITS,
            sponsor_rebate_bps: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_SPONSOR_REBATE_BPS,
            min_privacy_set_size: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_MIN_PRIVACY_SET_SIZE,
            slash_bps: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_SLASH_BPS,
            late_penalty_bps: ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEFAULT_LATE_PENALTY_BPS,
        }
    }
}

impl ZkPqSettlementProofKernelConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_pq_settlement_proof_kernel_config",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_PQ_SETTLEMENT_PROOF_KERNEL_PROTOCOL_VERSION,
            "schema_version": ZK_PQ_SETTLEMENT_PROOF_KERNEL_SCHEMA_VERSION,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "zk_vm": self.zk_vm,
            "recursion_scheme": self.recursion_scheme,
            "transcript_scheme": self.transcript_scheme,
            "verifier_key_scheme": self.verifier_key_scheme,
            "receipt_scheme": self.receipt_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "slashing_scheme": self.slashing_scheme,
            "max_jobs_per_aggregate": self.max_jobs_per_aggregate,
            "max_recursion_depth": self.max_recursion_depth,
            "challenge_window_blocks": self.challenge_window_blocks,
            "verifier_key_delay_blocks": self.verifier_key_delay_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "target_verify_micros": self.target_verify_micros,
            "max_proof_bytes": self.max_proof_bytes,
            "max_public_input_bytes": self.max_public_input_bytes,
            "sponsor_pool_micro_units": self.sponsor_pool_micro_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "slash_bps": self.slash_bps,
            "late_penalty_bps": self.late_penalty_bps
        })
    }

    pub fn config_root(&self) -> String {
        kernel_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ZkPqSettlementProofKernelResult<()> {
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("l2_network", &self.l2_network)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("zk_vm", &self.zk_vm)?;
        ensure_non_empty("recursion_scheme", &self.recursion_scheme)?;
        ensure_non_empty("transcript_scheme", &self.transcript_scheme)?;
        ensure_non_empty("verifier_key_scheme", &self.verifier_key_scheme)?;
        ensure_non_empty("receipt_scheme", &self.receipt_scheme)?;
        ensure_non_empty("sponsor_scheme", &self.sponsor_scheme)?;
        ensure_non_empty("slashing_scheme", &self.slashing_scheme)?;
        if self.max_jobs_per_aggregate == 0 {
            return Err("max_jobs_per_aggregate must be positive".to_string());
        }
        if self.max_recursion_depth == 0 {
            return Err("max_recursion_depth must be positive".to_string());
        }
        if self.target_verify_micros == 0 {
            return Err("target_verify_micros must be positive".to_string());
        }
        if self.max_proof_bytes == 0 {
            return Err("max_proof_bytes must be positive".to_string());
        }
        if self.max_public_input_bytes == 0 {
            return Err("max_public_input_bytes must be positive".to_string());
        }
        ensure_bps("sponsor_rebate_bps", self.sponsor_rebate_bps)?;
        ensure_bps("slash_bps", self.slash_bps)?;
        ensure_bps("late_penalty_bps", self.late_penalty_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKeyRotation {
    pub rotation_id: String,
    pub circuit_family: ZkPqCircuitFamily,
    pub key_epoch: u64,
    pub verifier_key_root: String,
    pub previous_key_root: String,
    pub activation_height: u64,
    pub retirement_height: u64,
    pub proposer_commitment: String,
    pub pq_committee_root: String,
    pub transcript_root: String,
    pub status: VerifierKeyStatus,
    pub metadata_root: String,
}

impl VerifierKeyRotation {
    pub fn new(
        circuit_family: ZkPqCircuitFamily,
        key_epoch: u64,
        verifier_key_root: &str,
        previous_key_root: &str,
        activation_height: u64,
        retirement_height: u64,
        proposer_commitment: &str,
        pq_committee_root: &str,
        metadata: &Value,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        ensure_non_empty("verifier_key_root", verifier_key_root)?;
        ensure_non_empty("previous_key_root", previous_key_root)?;
        ensure_non_empty("proposer_commitment", proposer_commitment)?;
        ensure_non_empty("pq_committee_root", pq_committee_root)?;
        if retirement_height <= activation_height {
            return Err("retirement_height must be greater than activation_height".to_string());
        }
        let metadata_root = kernel_payload_root("VERIFIER-KEY-METADATA", metadata);
        let transcript_root = verifier_key_transcript_root(
            circuit_family,
            key_epoch,
            verifier_key_root,
            previous_key_root,
            activation_height,
            retirement_height,
            proposer_commitment,
            pq_committee_root,
            &metadata_root,
        );
        let rotation_id = kernel_hash(
            "VERIFIER-KEY-ROTATION-ID",
            &[
                HashPart::Str(circuit_family.as_str()),
                HashPart::Int(key_epoch as i128),
                HashPart::Str(verifier_key_root),
                HashPart::Str(&transcript_root),
            ],
        );
        Ok(Self {
            rotation_id,
            circuit_family,
            key_epoch,
            verifier_key_root: verifier_key_root.to_string(),
            previous_key_root: previous_key_root.to_string(),
            activation_height,
            retirement_height,
            proposer_commitment: proposer_commitment.to_string(),
            pq_committee_root: pq_committee_root.to_string(),
            transcript_root,
            status: VerifierKeyStatus::Proposed,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_key_rotation",
            "chain_id": CHAIN_ID,
            "rotation_id": self.rotation_id,
            "circuit_family": self.circuit_family.as_str(),
            "key_epoch": self.key_epoch,
            "verifier_key_root": self.verifier_key_root,
            "previous_key_root": self.previous_key_root,
            "activation_height": self.activation_height,
            "retirement_height": self.retirement_height,
            "proposer_commitment": self.proposer_commitment,
            "pq_committee_root": self.pq_committee_root,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("VERIFIER-KEY-ROTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqTranscriptBinding {
    pub binding_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub verifier_key_root: String,
    pub challenge_root: String,
    pub public_input_root: String,
    pub witness_commitment_root: String,
    pub pq_signature_root: String,
    pub kem_ciphertext_root: String,
    pub signer_commitment: String,
    pub bound_at_height: u64,
}

impl PqTranscriptBinding {
    pub fn new(
        subject_id: &str,
        subject_root: &str,
        verifier_key_root: &str,
        challenge_root: &str,
        public_input_root: &str,
        witness_commitment_root: &str,
        pq_signature_root: &str,
        kem_ciphertext_root: &str,
        signer_commitment: &str,
        bound_at_height: u64,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        ensure_non_empty("subject_id", subject_id)?;
        ensure_non_empty("subject_root", subject_root)?;
        ensure_non_empty("verifier_key_root", verifier_key_root)?;
        ensure_non_empty("challenge_root", challenge_root)?;
        ensure_non_empty("public_input_root", public_input_root)?;
        ensure_non_empty("witness_commitment_root", witness_commitment_root)?;
        ensure_non_empty("pq_signature_root", pq_signature_root)?;
        ensure_non_empty("kem_ciphertext_root", kem_ciphertext_root)?;
        ensure_non_empty("signer_commitment", signer_commitment)?;
        let binding_id = pq_transcript_binding_id(
            subject_id,
            subject_root,
            verifier_key_root,
            challenge_root,
            public_input_root,
            witness_commitment_root,
            pq_signature_root,
            kem_ciphertext_root,
            signer_commitment,
            bound_at_height,
        );
        Ok(Self {
            binding_id,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            challenge_root: challenge_root.to_string(),
            public_input_root: public_input_root.to_string(),
            witness_commitment_root: witness_commitment_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            kem_ciphertext_root: kem_ciphertext_root.to_string(),
            signer_commitment: signer_commitment.to_string(),
            bound_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_transcript_binding",
            "chain_id": CHAIN_ID,
            "binding_id": self.binding_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "verifier_key_root": self.verifier_key_root,
            "challenge_root": self.challenge_root,
            "public_input_root": self.public_input_root,
            "witness_commitment_root": self.witness_commitment_root,
            "pq_signature_root": self.pq_signature_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "signer_commitment": self.signer_commitment,
            "bound_at_height": self.bound_at_height
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("PQ-TRANSCRIPT-BINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJob {
    pub job_id: String,
    pub kind: ProofJobKind,
    pub lane: SettlementLane,
    pub circuit_family: ZkPqCircuitFamily,
    pub requester_commitment: String,
    pub prover_commitment: String,
    pub verifier_key_root: String,
    pub witness_root: String,
    pub public_input_root: String,
    pub output_commitment_root: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub sponsor_id: Option<String>,
    pub privacy_set_size: u64,
    pub proof_size_bytes: u64,
    pub recursion_depth: u64,
    pub opened_at_height: u64,
    pub due_at_height: u64,
    pub status: ProofJobStatus,
    pub transcript_binding_id: Option<String>,
    pub aggregate_id: Option<String>,
}

impl ProofJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ProofJobKind,
        lane: SettlementLane,
        circuit_family: ZkPqCircuitFamily,
        requester_commitment: &str,
        prover_commitment: &str,
        verifier_key_root: &str,
        witness_root: &str,
        public_input_root: &str,
        output_commitment_root: &str,
        fee_asset_id: &str,
        max_fee_micro_units: u64,
        sponsor_id: Option<String>,
        privacy_set_size: u64,
        proof_size_bytes: u64,
        recursion_depth: u64,
        opened_at_height: u64,
        due_at_height: u64,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        ensure_non_empty("requester_commitment", requester_commitment)?;
        ensure_non_empty("prover_commitment", prover_commitment)?;
        ensure_non_empty("verifier_key_root", verifier_key_root)?;
        ensure_non_empty("witness_root", witness_root)?;
        ensure_non_empty("public_input_root", public_input_root)?;
        ensure_non_empty("output_commitment_root", output_commitment_root)?;
        ensure_non_empty("fee_asset_id", fee_asset_id)?;
        if due_at_height <= opened_at_height {
            return Err("due_at_height must be greater than opened_at_height".to_string());
        }
        let sponsor_ref = match &sponsor_id {
            Some(value) => value.clone(),
            None => String::new(),
        };
        let job_id = proof_job_id(
            kind,
            lane,
            circuit_family,
            requester_commitment,
            prover_commitment,
            verifier_key_root,
            witness_root,
            public_input_root,
            output_commitment_root,
            fee_asset_id,
            max_fee_micro_units,
            &sponsor_ref,
            opened_at_height,
        );
        Ok(Self {
            job_id,
            kind,
            lane,
            circuit_family,
            requester_commitment: requester_commitment.to_string(),
            prover_commitment: prover_commitment.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            witness_root: witness_root.to_string(),
            public_input_root: public_input_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_micro_units,
            sponsor_id,
            privacy_set_size,
            proof_size_bytes,
            recursion_depth,
            opened_at_height,
            due_at_height,
            status: ProofJobStatus::Queued,
            transcript_binding_id: None,
            aggregate_id: None,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.live() && height > self.due_at_height {
            self.status = ProofJobStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_job",
            "chain_id": CHAIN_ID,
            "job_id": self.job_id,
            "job_kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "circuit_family": self.circuit_family.as_str(),
            "requester_commitment": self.requester_commitment,
            "prover_commitment": self.prover_commitment,
            "verifier_key_root": self.verifier_key_root,
            "witness_root": self.witness_root,
            "public_input_root": self.public_input_root,
            "output_commitment_root": self.output_commitment_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsor_id": self.sponsor_id,
            "privacy_set_size": self.privacy_set_size,
            "proof_size_bytes": self.proof_size_bytes,
            "recursion_depth": self.recursion_depth,
            "opened_at_height": self.opened_at_height,
            "due_at_height": self.due_at_height,
            "status": self.status.as_str(),
            "transcript_binding_id": self.transcript_binding_id,
            "aggregate_id": self.aggregate_id
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("PROOF-JOB", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveAggregation {
    pub aggregate_id: String,
    pub lane: SettlementLane,
    pub circuit_family: ZkPqCircuitFamily,
    pub aggregator_commitment: String,
    pub job_ids: BTreeSet<String>,
    pub input_job_root: String,
    pub recursive_proof_root: String,
    pub verifier_key_root: String,
    pub transcript_binding_id: Option<String>,
    pub recursion_depth: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub status: AggregationStatus,
}

impl RecursiveAggregation {
    pub fn new(
        lane: SettlementLane,
        circuit_family: ZkPqCircuitFamily,
        aggregator_commitment: &str,
        verifier_key_root: &str,
        recursion_depth: u64,
        opened_at_height: u64,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        ensure_non_empty("aggregator_commitment", aggregator_commitment)?;
        ensure_non_empty("verifier_key_root", verifier_key_root)?;
        let input_job_root = merkle_string_root("AGGREGATE-EMPTY-JOBS", &[]);
        let recursive_proof_root = kernel_hash(
            "RECURSIVE-PROOF-PENDING",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(circuit_family.as_str()),
                HashPart::Str(aggregator_commitment),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        let aggregate_id = recursive_aggregation_id(
            lane,
            circuit_family,
            aggregator_commitment,
            verifier_key_root,
            &input_job_root,
            recursion_depth,
            opened_at_height,
        );
        Ok(Self {
            aggregate_id,
            lane,
            circuit_family,
            aggregator_commitment: aggregator_commitment.to_string(),
            job_ids: BTreeSet::new(),
            input_job_root,
            recursive_proof_root,
            verifier_key_root: verifier_key_root.to_string(),
            transcript_binding_id: None,
            recursion_depth,
            opened_at_height,
            sealed_at_height: None,
            status: AggregationStatus::Collecting,
        })
    }

    pub fn add_job(&mut self, job_id: &str) -> ZkPqSettlementProofKernelResult<()> {
        ensure_non_empty("job_id", job_id)?;
        if !self.status.accepts_jobs() {
            return Err("aggregation no longer accepts jobs".to_string());
        }
        self.job_ids.insert(job_id.to_string());
        self.refresh_input_root();
        Ok(())
    }

    pub fn seal(
        &mut self,
        recursive_proof_root: &str,
        height: u64,
    ) -> ZkPqSettlementProofKernelResult<()> {
        ensure_non_empty("recursive_proof_root", recursive_proof_root)?;
        if self.job_ids.is_empty() {
            return Err("cannot seal empty aggregation".to_string());
        }
        self.recursive_proof_root = recursive_proof_root.to_string();
        self.sealed_at_height = Some(height);
        self.status = AggregationStatus::Sealed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_aggregation",
            "chain_id": CHAIN_ID,
            "aggregate_id": self.aggregate_id,
            "lane": self.lane.as_str(),
            "circuit_family": self.circuit_family.as_str(),
            "aggregator_commitment": self.aggregator_commitment,
            "job_ids": self.job_ids,
            "input_job_root": self.input_job_root,
            "recursive_proof_root": self.recursive_proof_root,
            "verifier_key_root": self.verifier_key_root,
            "transcript_binding_id": self.transcript_binding_id,
            "recursion_depth": self.recursion_depth,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("RECURSIVE-AGGREGATION", &self.public_record())
    }

    fn refresh_input_root(&mut self) {
        let values = self.job_ids.iter().cloned().collect::<Vec<_>>();
        self.input_job_root = merkle_string_root("AGGREGATE-JOBS", &values);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSettlementReceipt {
    pub receipt_id: String,
    pub aggregate_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub bridge_epoch: u64,
    pub monero_anchor_height: u64,
    pub l2_settlement_height: u64,
    pub settlement_root: String,
    pub nullifier_root: String,
    pub output_root: String,
    pub fee_root: String,
    pub pq_transcript_root: String,
    pub verifier_key_root: String,
    pub finality_height: u64,
    pub status: ReceiptStatus,
}

impl BridgeSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aggregate_id: &str,
        monero_network: &str,
        l2_network: &str,
        bridge_epoch: u64,
        monero_anchor_height: u64,
        l2_settlement_height: u64,
        settlement_root: &str,
        nullifier_root: &str,
        output_root: &str,
        fee_root: &str,
        pq_transcript_root: &str,
        verifier_key_root: &str,
        finality_height: u64,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        ensure_non_empty("aggregate_id", aggregate_id)?;
        ensure_non_empty("monero_network", monero_network)?;
        ensure_non_empty("l2_network", l2_network)?;
        ensure_non_empty("settlement_root", settlement_root)?;
        ensure_non_empty("nullifier_root", nullifier_root)?;
        ensure_non_empty("output_root", output_root)?;
        ensure_non_empty("fee_root", fee_root)?;
        ensure_non_empty("pq_transcript_root", pq_transcript_root)?;
        ensure_non_empty("verifier_key_root", verifier_key_root)?;
        if finality_height < l2_settlement_height {
            return Err("finality_height cannot be below l2_settlement_height".to_string());
        }
        let receipt_id = bridge_receipt_id(
            aggregate_id,
            monero_network,
            l2_network,
            bridge_epoch,
            monero_anchor_height,
            l2_settlement_height,
            settlement_root,
            nullifier_root,
            output_root,
            fee_root,
            pq_transcript_root,
            verifier_key_root,
        );
        Ok(Self {
            receipt_id,
            aggregate_id: aggregate_id.to_string(),
            monero_network: monero_network.to_string(),
            l2_network: l2_network.to_string(),
            bridge_epoch,
            monero_anchor_height,
            l2_settlement_height,
            settlement_root: settlement_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            output_root: output_root.to_string(),
            fee_root: fee_root.to_string(),
            pq_transcript_root: pq_transcript_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            finality_height,
            status: ReceiptStatus::Draft,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            ReceiptStatus::Posted | ReceiptStatus::Confirming
        ) && height >= self.finality_height
        {
            self.status = ReceiptStatus::Finalized;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_settlement_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "aggregate_id": self.aggregate_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "bridge_epoch": self.bridge_epoch,
            "monero_anchor_height": self.monero_anchor_height,
            "l2_settlement_height": self.l2_settlement_height,
            "settlement_root": self.settlement_root,
            "nullifier_root": self.nullifier_root,
            "output_root": self.output_root,
            "fee_root": self.fee_root,
            "pq_transcript_root": self.pq_transcript_root,
            "verifier_key_root": self.verifier_key_root,
            "finality_height": self.finality_height,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("BRIDGE-SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane: SettlementLane,
    pub fee_asset_id: String,
    pub budget_micro_units: u64,
    pub reserved_micro_units: u64,
    pub spent_micro_units: u64,
    pub rebate_bps: u64,
    pub eligibility_root: String,
    pub privacy_budget_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeProofSponsorship {
    pub fn new(
        sponsor_commitment: &str,
        lane: SettlementLane,
        fee_asset_id: &str,
        budget_micro_units: u64,
        rebate_bps: u64,
        eligibility: &Value,
        privacy_budget: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        ensure_non_empty("sponsor_commitment", sponsor_commitment)?;
        ensure_non_empty("fee_asset_id", fee_asset_id)?;
        ensure_bps("rebate_bps", rebate_bps)?;
        if budget_micro_units == 0 {
            return Err("budget_micro_units must be positive".to_string());
        }
        if expires_at_height <= opened_at_height {
            return Err("expires_at_height must be greater than opened_at_height".to_string());
        }
        let eligibility_root = kernel_payload_root("SPONSOR-ELIGIBILITY", eligibility);
        let privacy_budget_root = kernel_payload_root("SPONSOR-PRIVACY-BUDGET", privacy_budget);
        let sponsorship_id = sponsorship_id(
            sponsor_commitment,
            lane,
            fee_asset_id,
            budget_micro_units,
            rebate_bps,
            &eligibility_root,
            &privacy_budget_root,
            opened_at_height,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            lane,
            fee_asset_id: fee_asset_id.to_string(),
            budget_micro_units,
            reserved_micro_units: 0,
            spent_micro_units: 0,
            rebate_bps,
            eligibility_root,
            privacy_budget_root,
            opened_at_height,
            expires_at_height,
            status: SponsorshipStatus::Offered,
        })
    }

    pub fn reserve(&mut self, amount: u64) -> ZkPqSettlementProofKernelResult<()> {
        if !self.status.spendable() {
            return Err("sponsorship is not spendable".to_string());
        }
        let next_reserved = self
            .reserved_micro_units
            .checked_add(amount)
            .ok_or_else(|| "sponsorship reservation overflow".to_string())?;
        let committed = next_reserved
            .checked_add(self.spent_micro_units)
            .ok_or_else(|| "sponsorship committed amount overflow".to_string())?;
        if committed > self.budget_micro_units {
            return Err("sponsorship budget exceeded".to_string());
        }
        self.reserved_micro_units = next_reserved;
        self.status = SponsorshipStatus::Reserved;
        Ok(())
    }

    pub fn apply(&mut self, amount: u64) -> ZkPqSettlementProofKernelResult<()> {
        if amount > self.reserved_micro_units {
            return Err("cannot spend more than reserved sponsorship".to_string());
        }
        self.reserved_micro_units -= amount;
        self.spent_micro_units = self
            .spent_micro_units
            .checked_add(amount)
            .ok_or_else(|| "sponsorship spend overflow".to_string())?;
        if self.spent_micro_units >= self.budget_micro_units {
            self.status = SponsorshipStatus::Exhausted;
        } else {
            self.status = SponsorshipStatus::Applied;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.spendable() && height > self.expires_at_height {
            self.status = SponsorshipStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_micro_units": self.budget_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "rebate_bps": self.rebate_bps,
            "eligibility_root": self.eligibility_root,
            "privacy_budget_root": self.privacy_budget_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("LOW-FEE-PROOF-SPONSORSHIP", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub subject_id: String,
    pub subject_root: String,
    pub challenger_commitment: String,
    pub accused_commitment: String,
    pub evidence_root: String,
    pub replay_trace_root: String,
    pub slashing_amount_micro_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ChallengeStatus,
}

impl ChallengeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ChallengeKind,
        subject_id: &str,
        subject_root: &str,
        challenger_commitment: &str,
        accused_commitment: &str,
        evidence: &Value,
        replay_trace: &Value,
        slashing_amount_micro_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        ensure_non_empty("subject_id", subject_id)?;
        ensure_non_empty("subject_root", subject_root)?;
        ensure_non_empty("challenger_commitment", challenger_commitment)?;
        ensure_non_empty("accused_commitment", accused_commitment)?;
        if expires_at_height <= opened_at_height {
            return Err("expires_at_height must be greater than opened_at_height".to_string());
        }
        let evidence_root = kernel_payload_root("CHALLENGE-EVIDENCE-PAYLOAD", evidence);
        let replay_trace_root = kernel_payload_root("CHALLENGE-REPLAY-TRACE", replay_trace);
        let challenge_id = challenge_id(
            kind,
            subject_id,
            subject_root,
            challenger_commitment,
            accused_commitment,
            &evidence_root,
            &replay_trace_root,
            opened_at_height,
        );
        Ok(Self {
            challenge_id,
            kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            accused_commitment: accused_commitment.to_string(),
            evidence_root,
            replay_trace_root,
            slashing_amount_micro_units,
            opened_at_height,
            expires_at_height,
            status: ChallengeStatus::Open,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            ChallengeStatus::Open | ChallengeStatus::EvidenceLocked | ChallengeStatus::UnderReview
        ) && height > self.expires_at_height
        {
            self.status = ChallengeStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_evidence",
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "challenger_commitment": self.challenger_commitment,
            "accused_commitment": self.accused_commitment,
            "evidence_root": self.evidence_root,
            "replay_trace_root": self.replay_trace_root,
            "slashing_amount_micro_units": self.slashing_amount_micro_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("CHALLENGE-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPqSettlementProofKernelRoots {
    pub verifier_key_root: String,
    pub proof_job_root: String,
    pub aggregation_root: String,
    pub transcript_root: String,
    pub receipt_root: String,
    pub sponsorship_root: String,
    pub challenge_root: String,
    pub active_key_root: String,
    pub live_job_root: String,
    pub settled_receipt_root: String,
}

impl ZkPqSettlementProofKernelRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_pq_settlement_proof_kernel_roots",
            "chain_id": CHAIN_ID,
            "verifier_key_root": self.verifier_key_root,
            "proof_job_root": self.proof_job_root,
            "aggregation_root": self.aggregation_root,
            "transcript_root": self.transcript_root,
            "receipt_root": self.receipt_root,
            "sponsorship_root": self.sponsorship_root,
            "challenge_root": self.challenge_root,
            "active_key_root": self.active_key_root,
            "live_job_root": self.live_job_root,
            "settled_receipt_root": self.settled_receipt_root
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPqSettlementProofKernelCounters {
    pub verifier_key_rotations: usize,
    pub proof_jobs: usize,
    pub recursive_aggregations: usize,
    pub transcript_bindings: usize,
    pub bridge_receipts: usize,
    pub sponsorships: usize,
    pub challenges: usize,
    pub active_verifier_keys: usize,
    pub live_jobs: usize,
    pub settled_receipts: usize,
    pub reserved_sponsor_micro_units: u64,
    pub spent_sponsor_micro_units: u64,
    pub open_challenges: usize,
}

impl ZkPqSettlementProofKernelCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_pq_settlement_proof_kernel_counters",
            "chain_id": CHAIN_ID,
            "verifier_key_rotations": self.verifier_key_rotations,
            "proof_jobs": self.proof_jobs,
            "recursive_aggregations": self.recursive_aggregations,
            "transcript_bindings": self.transcript_bindings,
            "bridge_receipts": self.bridge_receipts,
            "sponsorships": self.sponsorships,
            "challenges": self.challenges,
            "active_verifier_keys": self.active_verifier_keys,
            "live_jobs": self.live_jobs,
            "settled_receipts": self.settled_receipts,
            "reserved_sponsor_micro_units": self.reserved_sponsor_micro_units,
            "spent_sponsor_micro_units": self.spent_sponsor_micro_units,
            "open_challenges": self.open_challenges
        })
    }

    pub fn root(&self) -> String {
        kernel_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPqSettlementProofKernelState {
    pub config: ZkPqSettlementProofKernelConfig,
    pub height: u64,
    pub operator_commitment: String,
    pub verifier_key_rotations: BTreeMap<String, VerifierKeyRotation>,
    pub proof_jobs: BTreeMap<String, ProofJob>,
    pub recursive_aggregations: BTreeMap<String, RecursiveAggregation>,
    pub transcript_bindings: BTreeMap<String, PqTranscriptBinding>,
    pub bridge_receipts: BTreeMap<String, BridgeSettlementReceipt>,
    pub sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    pub public_records: BTreeMap<String, Value>,
}

impl ZkPqSettlementProofKernelState {
    pub fn new(
        config: ZkPqSettlementProofKernelConfig,
        operator_commitment: &str,
    ) -> ZkPqSettlementProofKernelResult<Self> {
        config.validate()?;
        ensure_non_empty("operator_commitment", operator_commitment)?;
        Ok(Self {
            config,
            height: 0,
            operator_commitment: operator_commitment.to_string(),
            verifier_key_rotations: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            recursive_aggregations: BTreeMap::new(),
            transcript_bindings: BTreeMap::new(),
            bridge_receipts: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> ZkPqSettlementProofKernelResult<Self> {
        let config = ZkPqSettlementProofKernelConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            &kernel_hash(
                "DEVNET-OPERATOR",
                &[HashPart::Str(
                    ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_OPERATOR_ID,
                )],
            ),
        )?;
        state.set_height(ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_HEIGHT)?;

        let committee_root = kernel_hash(
            "DEVNET-COMMITTEE",
            &[HashPart::Str(
                ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_COMMITTEE_ID,
            )],
        );
        let metadata = json!({
            "operator": ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_OPERATOR_ID,
            "program": ZkPqCircuitFamily::MoneroBridgeSettlement.default_program_id(),
            "network": config.l2_network
        });
        let mut rotation = VerifierKeyRotation::new(
            ZkPqCircuitFamily::MoneroBridgeSettlement,
            1,
            &kernel_hash("DEVNET-VK", &[HashPart::Str("monero-bridge-vk")]),
            &kernel_hash("DEVNET-VK-PREVIOUS", &[HashPart::Str("genesis")]),
            state.height,
            state.height + 10_000,
            &state.operator_commitment,
            &committee_root,
            &metadata,
        )?;
        rotation.status = VerifierKeyStatus::Active;
        let rotation_id = state.register_verifier_key_rotation(rotation)?;

        let sponsorship = LowFeeProofSponsorship::new(
            &kernel_hash(
                "DEVNET-SPONSOR",
                &[HashPart::Str(
                    ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_SPONSOR_ID,
                )],
            ),
            SettlementLane::SponsoredMaintenance,
            &config.fee_asset_id,
            config.sponsor_pool_micro_units,
            config.sponsor_rebate_bps,
            &json!({"lanes": ["private_transfer", "contract_execution", "sponsored_maintenance"]}),
            &json!({"min_privacy_set_size": config.min_privacy_set_size}),
            state.height,
            state.height + 1_000,
        )?;
        let sponsorship_id = state.register_sponsorship(sponsorship)?;

        let vk_root = state
            .verifier_key_rotations
            .get(&rotation_id)
            .map(|rotation| rotation.verifier_key_root.clone())
            .ok_or_else(|| "devnet verifier key rotation missing".to_string())?;
        let job = ProofJob::new(
            ProofJobKind::BridgeSettlement,
            SettlementLane::MoneroExit,
            ZkPqCircuitFamily::MoneroBridgeSettlement,
            &kernel_hash("DEVNET-REQUESTER", &[HashPart::Str("bridge-user")]),
            &kernel_hash(
                "DEVNET-PROVER",
                &[HashPart::Str(
                    ZK_PQ_SETTLEMENT_PROOF_KERNEL_DEVNET_PROVER_ID,
                )],
            ),
            &vk_root,
            &kernel_hash("DEVNET-WITNESS", &[HashPart::Str("shielded-exit-witness")]),
            &kernel_hash(
                "DEVNET-PUBLIC-INPUT",
                &[HashPart::Str("bridge-public-input")],
            ),
            &kernel_hash("DEVNET-OUTPUT", &[HashPart::Str("settlement-output")]),
            &config.fee_asset_id,
            25,
            Some(sponsorship_id),
            config.min_privacy_set_size,
            32_000,
            1,
            state.height,
            state.height + 24,
        )?;
        let job_id = state.register_proof_job(job)?;

        let aggregate = RecursiveAggregation::new(
            SettlementLane::MoneroExit,
            ZkPqCircuitFamily::MoneroBridgeSettlement,
            &state.operator_commitment,
            &vk_root,
            1,
            state.height,
        )?;
        let aggregate_id = state.register_recursive_aggregation(aggregate)?;
        state.attach_job_to_aggregation(&job_id, &aggregate_id)?;
        state.record_public_record("devnet_bootstrap", &state.public_record())?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ZkPqSettlementProofKernelResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        for job in self.proof_jobs.values_mut() {
            job.set_height(height);
        }
        for receipt in self.bridge_receipts.values_mut() {
            receipt.set_height(height);
        }
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.set_height(height);
        }
        for rotation in self.verifier_key_rotations.values_mut() {
            if rotation.status == VerifierKeyStatus::Proposed
                && height >= rotation.activation_height + self.config.verifier_key_delay_blocks
            {
                rotation.status = VerifierKeyStatus::Active;
            }
            if rotation.status == VerifierKeyStatus::Retiring
                && height >= rotation.retirement_height
            {
                rotation.status = VerifierKeyStatus::Retired;
            }
        }
        Ok(())
    }

    pub fn register_verifier_key_rotation(
        &mut self,
        rotation: VerifierKeyRotation,
    ) -> ZkPqSettlementProofKernelResult<String> {
        if self.verifier_key_rotations.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("verifier key rotation capacity exceeded".to_string());
        }
        if self
            .verifier_key_rotations
            .contains_key(&rotation.rotation_id)
        {
            return Err("verifier key rotation already registered".to_string());
        }
        let rotation_id = rotation.rotation_id.clone();
        self.verifier_key_rotations
            .insert(rotation_id.clone(), rotation);
        Ok(rotation_id)
    }

    pub fn register_proof_job(&mut self, job: ProofJob) -> ZkPqSettlementProofKernelResult<String> {
        if self.proof_jobs.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("proof job capacity exceeded".to_string());
        }
        self.validate_job_limits(&job)?;
        if self.proof_jobs.contains_key(&job.job_id) {
            return Err("proof job already registered".to_string());
        }
        let job_id = job.job_id.clone();
        self.proof_jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn register_recursive_aggregation(
        &mut self,
        aggregation: RecursiveAggregation,
    ) -> ZkPqSettlementProofKernelResult<String> {
        if self.recursive_aggregations.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("recursive aggregation capacity exceeded".to_string());
        }
        if aggregation.recursion_depth > self.config.max_recursion_depth {
            return Err("aggregation recursion depth exceeds configured maximum".to_string());
        }
        if self
            .recursive_aggregations
            .contains_key(&aggregation.aggregate_id)
        {
            return Err("recursive aggregation already registered".to_string());
        }
        let aggregate_id = aggregation.aggregate_id.clone();
        self.recursive_aggregations
            .insert(aggregate_id.clone(), aggregation);
        Ok(aggregate_id)
    }

    pub fn register_transcript_binding(
        &mut self,
        binding: PqTranscriptBinding,
    ) -> ZkPqSettlementProofKernelResult<String> {
        if self.transcript_bindings.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("transcript binding capacity exceeded".to_string());
        }
        if self.transcript_bindings.contains_key(&binding.binding_id) {
            return Err("transcript binding already registered".to_string());
        }
        let binding_id = binding.binding_id.clone();
        if let Some(job) = self.proof_jobs.get_mut(&binding.subject_id) {
            job.transcript_binding_id = Some(binding_id.clone());
            job.status = ProofJobStatus::Attested;
        }
        if let Some(aggregation) = self.recursive_aggregations.get_mut(&binding.subject_id) {
            aggregation.transcript_binding_id = Some(binding_id.clone());
            aggregation.status = AggregationStatus::TranscriptBound;
        }
        self.transcript_bindings.insert(binding_id.clone(), binding);
        Ok(binding_id)
    }

    pub fn register_bridge_receipt(
        &mut self,
        mut receipt: BridgeSettlementReceipt,
    ) -> ZkPqSettlementProofKernelResult<String> {
        if self.bridge_receipts.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("bridge receipt capacity exceeded".to_string());
        }
        if !self
            .recursive_aggregations
            .contains_key(&receipt.aggregate_id)
        {
            return Err("receipt aggregate is unknown".to_string());
        }
        if self.bridge_receipts.contains_key(&receipt.receipt_id) {
            return Err("bridge receipt already registered".to_string());
        }
        receipt.status = ReceiptStatus::Posted;
        let receipt_id = receipt.receipt_id.clone();
        if let Some(aggregation) = self.recursive_aggregations.get_mut(&receipt.aggregate_id) {
            aggregation.status = AggregationStatus::ReceiptReady;
        }
        self.bridge_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn register_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorship,
    ) -> ZkPqSettlementProofKernelResult<String> {
        if self.sponsorships.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("sponsorship capacity exceeded".to_string());
        }
        if self.sponsorships.contains_key(&sponsorship.sponsorship_id) {
            return Err("sponsorship already registered".to_string());
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn register_challenge(
        &mut self,
        challenge: ChallengeEvidence,
    ) -> ZkPqSettlementProofKernelResult<String> {
        if self.challenges.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("challenge capacity exceeded".to_string());
        }
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("challenge already registered".to_string());
        }
        if let Some(job) = self.proof_jobs.get_mut(&challenge.subject_id) {
            job.status = ProofJobStatus::Challenged;
        }
        if let Some(aggregation) = self.recursive_aggregations.get_mut(&challenge.subject_id) {
            aggregation.status = AggregationStatus::Challenged;
        }
        if let Some(receipt) = self.bridge_receipts.get_mut(&challenge.subject_id) {
            receipt.status = ReceiptStatus::Challenged;
        }
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn attach_job_to_aggregation(
        &mut self,
        job_id: &str,
        aggregate_id: &str,
    ) -> ZkPqSettlementProofKernelResult<()> {
        let job = self
            .proof_jobs
            .get_mut(job_id)
            .ok_or_else(|| "proof job not found".to_string())?;
        let aggregation = self
            .recursive_aggregations
            .get_mut(aggregate_id)
            .ok_or_else(|| "recursive aggregation not found".to_string())?;
        if job.circuit_family != aggregation.circuit_family {
            return Err("job circuit family does not match aggregation".to_string());
        }
        if job.recursion_depth > self.config.max_recursion_depth {
            return Err("job recursion depth exceeds configured maximum".to_string());
        }
        if aggregation.job_ids.len() >= self.config.max_jobs_per_aggregate {
            return Err("aggregation job limit exceeded".to_string());
        }
        aggregation.add_job(job_id)?;
        job.aggregate_id = Some(aggregate_id.to_string());
        job.status = ProofJobStatus::Aggregating;
        Ok(())
    }

    pub fn bind_job_transcript(
        &mut self,
        job_id: &str,
        challenge_root: &str,
        pq_signature_root: &str,
        kem_ciphertext_root: &str,
        signer_commitment: &str,
    ) -> ZkPqSettlementProofKernelResult<String> {
        let job = self
            .proof_jobs
            .get(job_id)
            .ok_or_else(|| "proof job not found".to_string())?;
        let binding = PqTranscriptBinding::new(
            &job.job_id,
            &job.root(),
            &job.verifier_key_root,
            challenge_root,
            &job.public_input_root,
            &job.witness_root,
            pq_signature_root,
            kem_ciphertext_root,
            signer_commitment,
            self.height,
        )?;
        self.register_transcript_binding(binding)
    }

    pub fn bind_aggregation_transcript(
        &mut self,
        aggregate_id: &str,
        challenge_root: &str,
        pq_signature_root: &str,
        kem_ciphertext_root: &str,
        signer_commitment: &str,
    ) -> ZkPqSettlementProofKernelResult<String> {
        let aggregation = self
            .recursive_aggregations
            .get(aggregate_id)
            .ok_or_else(|| "recursive aggregation not found".to_string())?;
        let binding = PqTranscriptBinding::new(
            &aggregation.aggregate_id,
            &aggregation.root(),
            &aggregation.verifier_key_root,
            challenge_root,
            &aggregation.input_job_root,
            &aggregation.recursive_proof_root,
            pq_signature_root,
            kem_ciphertext_root,
            signer_commitment,
            self.height,
        )?;
        self.register_transcript_binding(binding)
    }

    pub fn apply_sponsorship(
        &mut self,
        sponsorship_id: &str,
        job_id: &str,
        fee_micro_units: u64,
    ) -> ZkPqSettlementProofKernelResult<u64> {
        let job = self
            .proof_jobs
            .get(job_id)
            .ok_or_else(|| "proof job not found".to_string())?;
        let sponsorship = self
            .sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "sponsorship not found".to_string())?;
        if job.sponsor_id.as_deref() != Some(sponsorship_id) {
            return Err("job is not assigned to sponsorship".to_string());
        }
        if job.fee_asset_id != sponsorship.fee_asset_id {
            return Err("sponsorship fee asset mismatch".to_string());
        }
        if !job.lane.low_fee_eligible() && job.lane != sponsorship.lane {
            return Err("job lane is not eligible for sponsorship".to_string());
        }
        let rebate = fee_micro_units
            .checked_mul(sponsorship.rebate_bps)
            .ok_or_else(|| "rebate multiplication overflow".to_string())?
            / ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_BPS;
        sponsorship.reserve(rebate)?;
        sponsorship.apply(rebate)?;
        Ok(rebate)
    }

    pub fn uphold_challenge(&mut self, challenge_id: &str) -> ZkPqSettlementProofKernelResult<()> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        challenge.status = ChallengeStatus::Upheld;
        if let Some(job) = self.proof_jobs.get_mut(&challenge.subject_id) {
            job.status = ProofJobStatus::Slashed;
        }
        if let Some(aggregation) = self.recursive_aggregations.get_mut(&challenge.subject_id) {
            aggregation.status = AggregationStatus::Rejected;
        }
        if let Some(receipt) = self.bridge_receipts.get_mut(&challenge.subject_id) {
            receipt.status = ReceiptStatus::Invalidated;
        }
        Ok(())
    }

    pub fn reject_challenge(&mut self, challenge_id: &str) -> ZkPqSettlementProofKernelResult<()> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        challenge.status = ChallengeStatus::Rejected;
        Ok(())
    }

    pub fn record_public_record(
        &mut self,
        label: &str,
        record: &Value,
    ) -> ZkPqSettlementProofKernelResult<String> {
        ensure_non_empty("label", label)?;
        if self.public_records.len() >= ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_RECORDS {
            return Err("public record capacity exceeded".to_string());
        }
        let record_root = kernel_hash(
            "PUBLIC-RECORD",
            &[
                HashPart::Str(label),
                HashPart::Int(self.height as i128),
                HashPart::Json(record),
            ],
        );
        self.public_records
            .insert(record_root.clone(), record.clone());
        Ok(record_root)
    }

    pub fn roots(&self) -> ZkPqSettlementProofKernelRoots {
        let verifier_key_values = self
            .verifier_key_rotations
            .values()
            .map(VerifierKeyRotation::public_record)
            .collect::<Vec<_>>();
        let proof_job_values = self
            .proof_jobs
            .values()
            .map(ProofJob::public_record)
            .collect::<Vec<_>>();
        let aggregation_values = self
            .recursive_aggregations
            .values()
            .map(RecursiveAggregation::public_record)
            .collect::<Vec<_>>();
        let transcript_values = self
            .transcript_bindings
            .values()
            .map(PqTranscriptBinding::public_record)
            .collect::<Vec<_>>();
        let receipt_values = self
            .bridge_receipts
            .values()
            .map(BridgeSettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let sponsorship_values = self
            .sponsorships
            .values()
            .map(LowFeeProofSponsorship::public_record)
            .collect::<Vec<_>>();
        let challenge_values = self
            .challenges
            .values()
            .map(ChallengeEvidence::public_record)
            .collect::<Vec<_>>();
        let active_keys = self
            .verifier_key_rotations
            .values()
            .filter(|rotation| rotation.status.usable())
            .map(|rotation| rotation.verifier_key_root.clone())
            .collect::<Vec<_>>();
        let live_jobs = self
            .proof_jobs
            .values()
            .filter(|job| job.status.live())
            .map(|job| job.job_id.clone())
            .collect::<Vec<_>>();
        let settled_receipts = self
            .bridge_receipts
            .values()
            .filter(|receipt| receipt.status == ReceiptStatus::Finalized)
            .map(|receipt| receipt.receipt_id.clone())
            .collect::<Vec<_>>();
        ZkPqSettlementProofKernelRoots {
            verifier_key_root: merkle_root("ZK-PQ-VERIFIER-KEY-ROTATIONS", &verifier_key_values),
            proof_job_root: merkle_root("ZK-PQ-PROOF-JOBS", &proof_job_values),
            aggregation_root: merkle_root("ZK-PQ-RECURSIVE-AGGREGATIONS", &aggregation_values),
            transcript_root: merkle_root("ZK-PQ-TRANSCRIPT-BINDINGS", &transcript_values),
            receipt_root: merkle_root("ZK-PQ-BRIDGE-RECEIPTS", &receipt_values),
            sponsorship_root: merkle_root("ZK-PQ-SPONSORSHIPS", &sponsorship_values),
            challenge_root: merkle_root("ZK-PQ-CHALLENGES", &challenge_values),
            active_key_root: merkle_string_root("ZK-PQ-ACTIVE-KEYS", &active_keys),
            live_job_root: merkle_string_root("ZK-PQ-LIVE-JOBS", &live_jobs),
            settled_receipt_root: merkle_string_root("ZK-PQ-SETTLED-RECEIPTS", &settled_receipts),
        }
    }

    pub fn counters(&self) -> ZkPqSettlementProofKernelCounters {
        let reserved_sponsor_micro_units = self
            .sponsorships
            .values()
            .map(|sponsorship| sponsorship.reserved_micro_units)
            .sum();
        let spent_sponsor_micro_units = self
            .sponsorships
            .values()
            .map(|sponsorship| sponsorship.spent_micro_units)
            .sum();
        ZkPqSettlementProofKernelCounters {
            verifier_key_rotations: self.verifier_key_rotations.len(),
            proof_jobs: self.proof_jobs.len(),
            recursive_aggregations: self.recursive_aggregations.len(),
            transcript_bindings: self.transcript_bindings.len(),
            bridge_receipts: self.bridge_receipts.len(),
            sponsorships: self.sponsorships.len(),
            challenges: self.challenges.len(),
            active_verifier_keys: self
                .verifier_key_rotations
                .values()
                .filter(|rotation| rotation.status.usable())
                .count(),
            live_jobs: self
                .proof_jobs
                .values()
                .filter(|job| job.status.live())
                .count(),
            settled_receipts: self
                .bridge_receipts
                .values()
                .filter(|receipt| receipt.status == ReceiptStatus::Finalized)
                .count(),
            reserved_sponsor_micro_units,
            spent_sponsor_micro_units,
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| {
                    matches!(
                        challenge.status,
                        ChallengeStatus::Open
                            | ChallengeStatus::EvidenceLocked
                            | ChallengeStatus::UnderReview
                    )
                })
                .count(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "zk_pq_settlement_proof_kernel_state",
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_PQ_SETTLEMENT_PROOF_KERNEL_PROTOCOL_VERSION,
            "schema_version": ZK_PQ_SETTLEMENT_PROOF_KERNEL_SCHEMA_VERSION,
            "height": self.height,
            "operator_commitment": self.operator_commitment,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "public_record_count": self.public_records.len()
        })
    }

    pub fn state_root(&self) -> String {
        kernel_payload_root("STATE", &self.public_record())
    }

    pub fn validate(&self) -> ZkPqSettlementProofKernelResult<()> {
        self.config.validate()?;
        ensure_non_empty("operator_commitment", &self.operator_commitment)?;
        self.validate_unique_ids()?;
        for rotation in self.verifier_key_rotations.values() {
            ensure_non_empty("rotation_id", &rotation.rotation_id)?;
            ensure_non_empty("verifier_key_root", &rotation.verifier_key_root)?;
            if rotation.retirement_height <= rotation.activation_height {
                return Err("verifier key rotation has invalid height range".to_string());
            }
        }
        for job in self.proof_jobs.values() {
            self.validate_job_limits(job)?;
            if job.due_at_height <= job.opened_at_height {
                return Err("proof job has invalid height range".to_string());
            }
            if let Some(aggregate_id) = &job.aggregate_id {
                if !self.recursive_aggregations.contains_key(aggregate_id) {
                    return Err("proof job references unknown aggregation".to_string());
                }
            }
            if let Some(binding_id) = &job.transcript_binding_id {
                if !self.transcript_bindings.contains_key(binding_id) {
                    return Err("proof job references unknown transcript binding".to_string());
                }
            }
            if let Some(sponsorship_id) = &job.sponsor_id {
                if !self.sponsorships.contains_key(sponsorship_id) {
                    return Err("proof job references unknown sponsorship".to_string());
                }
            }
        }
        for aggregation in self.recursive_aggregations.values() {
            if aggregation.recursion_depth > self.config.max_recursion_depth {
                return Err("aggregation recursion depth exceeds configured maximum".to_string());
            }
            if aggregation.job_ids.len() > self.config.max_jobs_per_aggregate {
                return Err("aggregation job count exceeds configured maximum".to_string());
            }
            for job_id in &aggregation.job_ids {
                if !self.proof_jobs.contains_key(job_id) {
                    return Err("aggregation references unknown proof job".to_string());
                }
            }
        }
        for binding in self.transcript_bindings.values() {
            ensure_non_empty("binding_id", &binding.binding_id)?;
            ensure_non_empty("subject_id", &binding.subject_id)?;
            ensure_non_empty("pq_signature_root", &binding.pq_signature_root)?;
        }
        for receipt in self.bridge_receipts.values() {
            if !self
                .recursive_aggregations
                .contains_key(&receipt.aggregate_id)
            {
                return Err("bridge receipt references unknown aggregation".to_string());
            }
            if receipt.finality_height < receipt.l2_settlement_height {
                return Err("bridge receipt finality height is invalid".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            ensure_bps("sponsorship rebate_bps", sponsorship.rebate_bps)?;
            let committed = sponsorship
                .reserved_micro_units
                .checked_add(sponsorship.spent_micro_units)
                .ok_or_else(|| "sponsorship committed amount overflow".to_string())?;
            if committed > sponsorship.budget_micro_units {
                return Err("sponsorship committed amount exceeds budget".to_string());
            }
        }
        for challenge in self.challenges.values() {
            if challenge.expires_at_height <= challenge.opened_at_height {
                return Err("challenge has invalid height range".to_string());
            }
        }
        Ok(())
    }

    fn validate_job_limits(&self, job: &ProofJob) -> ZkPqSettlementProofKernelResult<()> {
        if job.privacy_set_size < self.config.min_privacy_set_size
            && job.circuit_family.privacy_sensitive()
        {
            return Err("privacy-sensitive job below minimum privacy set size".to_string());
        }
        if job.proof_size_bytes > self.config.max_proof_bytes {
            return Err("proof job exceeds max proof bytes".to_string());
        }
        if job.recursion_depth > self.config.max_recursion_depth {
            return Err("proof job exceeds max recursion depth".to_string());
        }
        Ok(())
    }

    fn validate_unique_ids(&self) -> ZkPqSettlementProofKernelResult<()> {
        let mut ids = BTreeSet::new();
        insert_unique_ids(
            &mut ids,
            self.verifier_key_rotations.keys(),
            "verifier key rotation",
        )?;
        insert_unique_ids(&mut ids, self.proof_jobs.keys(), "proof job")?;
        insert_unique_ids(
            &mut ids,
            self.recursive_aggregations.keys(),
            "recursive aggregation",
        )?;
        insert_unique_ids(
            &mut ids,
            self.transcript_bindings.keys(),
            "transcript binding",
        )?;
        insert_unique_ids(&mut ids, self.bridge_receipts.keys(), "bridge receipt")?;
        insert_unique_ids(&mut ids, self.sponsorships.keys(), "sponsorship")?;
        insert_unique_ids(&mut ids, self.challenges.keys(), "challenge")?;
        Ok(())
    }
}

pub fn kernel_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("ZK-PQ-SETTLEMENT-PROOF-KERNEL:{domain}"),
        parts,
        32,
    )
}

pub fn kernel_payload_root(domain: &str, payload: &Value) -> String {
    kernel_hash(
        domain,
        &[
            HashPart::Str(ZK_PQ_SETTLEMENT_PROOF_KERNEL_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
    )
}

pub fn merkle_string_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn verifier_key_transcript_root(
    circuit_family: ZkPqCircuitFamily,
    key_epoch: u64,
    verifier_key_root: &str,
    previous_key_root: &str,
    activation_height: u64,
    retirement_height: u64,
    proposer_commitment: &str,
    pq_committee_root: &str,
    metadata_root: &str,
) -> String {
    kernel_hash(
        "VERIFIER-KEY-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit_family.as_str()),
            HashPart::Int(key_epoch as i128),
            HashPart::Str(verifier_key_root),
            HashPart::Str(previous_key_root),
            HashPart::Int(activation_height as i128),
            HashPart::Int(retirement_height as i128),
            HashPart::Str(proposer_commitment),
            HashPart::Str(pq_committee_root),
            HashPart::Str(metadata_root),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn proof_job_id(
    kind: ProofJobKind,
    lane: SettlementLane,
    circuit_family: ZkPqCircuitFamily,
    requester_commitment: &str,
    prover_commitment: &str,
    verifier_key_root: &str,
    witness_root: &str,
    public_input_root: &str,
    output_commitment_root: &str,
    fee_asset_id: &str,
    max_fee_micro_units: u64,
    sponsor_id: &str,
    opened_at_height: u64,
) -> String {
    kernel_hash(
        "PROOF-JOB-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(circuit_family.as_str()),
            HashPart::Str(requester_commitment),
            HashPart::Str(prover_commitment),
            HashPart::Str(verifier_key_root),
            HashPart::Str(witness_root),
            HashPart::Str(public_input_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(fee_asset_id),
            HashPart::Int(max_fee_micro_units as i128),
            HashPart::Str(sponsor_id),
            HashPart::Int(opened_at_height as i128),
        ],
    )
}

pub fn recursive_aggregation_id(
    lane: SettlementLane,
    circuit_family: ZkPqCircuitFamily,
    aggregator_commitment: &str,
    verifier_key_root: &str,
    input_job_root: &str,
    recursion_depth: u64,
    opened_at_height: u64,
) -> String {
    kernel_hash(
        "RECURSIVE-AGGREGATION-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(circuit_family.as_str()),
            HashPart::Str(aggregator_commitment),
            HashPart::Str(verifier_key_root),
            HashPart::Str(input_job_root),
            HashPart::Int(recursion_depth as i128),
            HashPart::Int(opened_at_height as i128),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_transcript_binding_id(
    subject_id: &str,
    subject_root: &str,
    verifier_key_root: &str,
    challenge_root: &str,
    public_input_root: &str,
    witness_commitment_root: &str,
    pq_signature_root: &str,
    kem_ciphertext_root: &str,
    signer_commitment: &str,
    bound_at_height: u64,
) -> String {
    kernel_hash(
        "PQ-TRANSCRIPT-BINDING-ID",
        &[
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(verifier_key_root),
            HashPart::Str(challenge_root),
            HashPart::Str(public_input_root),
            HashPart::Str(witness_commitment_root),
            HashPart::Str(pq_signature_root),
            HashPart::Str(kem_ciphertext_root),
            HashPart::Str(signer_commitment),
            HashPart::Int(bound_at_height as i128),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn bridge_receipt_id(
    aggregate_id: &str,
    monero_network: &str,
    l2_network: &str,
    bridge_epoch: u64,
    monero_anchor_height: u64,
    l2_settlement_height: u64,
    settlement_root: &str,
    nullifier_root: &str,
    output_root: &str,
    fee_root: &str,
    pq_transcript_root: &str,
    verifier_key_root: &str,
) -> String {
    kernel_hash(
        "BRIDGE-RECEIPT-ID",
        &[
            HashPart::Str(aggregate_id),
            HashPart::Str(monero_network),
            HashPart::Str(l2_network),
            HashPart::Int(bridge_epoch as i128),
            HashPart::Int(monero_anchor_height as i128),
            HashPart::Int(l2_settlement_height as i128),
            HashPart::Str(settlement_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(output_root),
            HashPart::Str(fee_root),
            HashPart::Str(pq_transcript_root),
            HashPart::Str(verifier_key_root),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sponsorship_id(
    sponsor_commitment: &str,
    lane: SettlementLane,
    fee_asset_id: &str,
    budget_micro_units: u64,
    rebate_bps: u64,
    eligibility_root: &str,
    privacy_budget_root: &str,
    opened_at_height: u64,
) -> String {
    kernel_hash(
        "SPONSORSHIP-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(budget_micro_units as i128),
            HashPart::Int(rebate_bps as i128),
            HashPart::Str(eligibility_root),
            HashPart::Str(privacy_budget_root),
            HashPart::Int(opened_at_height as i128),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn challenge_id(
    kind: ChallengeKind,
    subject_id: &str,
    subject_root: &str,
    challenger_commitment: &str,
    accused_commitment: &str,
    evidence_root: &str,
    replay_trace_root: &str,
    opened_at_height: u64,
) -> String {
    kernel_hash(
        "CHALLENGE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(challenger_commitment),
            HashPart::Str(accused_commitment),
            HashPart::Str(evidence_root),
            HashPart::Str(replay_trace_root),
            HashPart::Int(opened_at_height as i128),
        ],
    )
}

fn ensure_non_empty(field: &str, value: &str) -> ZkPqSettlementProofKernelResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> ZkPqSettlementProofKernelResult<()> {
    if value > ZK_PQ_SETTLEMENT_PROOF_KERNEL_MAX_BPS {
        return Err(format!("{field} exceeds max bps"));
    }
    Ok(())
}

fn insert_unique_ids<'a, I>(
    ids: &mut BTreeSet<String>,
    values: I,
    label: &str,
) -> ZkPqSettlementProofKernelResult<()>
where
    I: Iterator<Item = &'a String>,
{
    for value in values {
        if !ids.insert(value.clone()) {
            return Err(format!("duplicate {label} id across kernel state"));
        }
    }
    Ok(())
}
