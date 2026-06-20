use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str = "nebula-private-l2-pq-encrypted-mempool-fair-order-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-threshold";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const ENVELOPE_AEAD_SUITE: &str = "XChaCha20-Poly1305-commitment-only";
pub const FAIR_ORDER_VDF_SUITE: &str = "devnet-delay-transcript-v1";
pub const PRIVACY_PROOF_SYSTEM: &str = "zk-nullifier-conflict-guard-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_424_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_212_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_MEMPOOL_ENVELOPES: usize = 65_536;
pub const MAX_FAIR_WINDOWS: usize = 4_096;
pub const MAX_SEQUENCER_COMMITMENTS: usize = 16_384;
pub const MAX_QUORUM_ATTESTATIONS: usize = 32_768;
pub const MAX_GUARDS: usize = 65_536;
pub const MAX_RECEIPTS: usize = 65_536;
pub const MAX_REBATES: usize = 32_768;
pub const DEFAULT_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_REVEAL_BLOCKS: u64 = 2;
pub const DEFAULT_MAX_ENVELOPES_PER_WINDOW: u64 = 512;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 256;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const DEFAULT_QUORUM_THRESHOLD_BPS: u64 = 6_700;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 650;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 300;
pub const DEFAULT_REBATE_BUDGET_UNITS: u64 = 25_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionClass {
    WalletTransfer,
    MoneroDeposit,
    MoneroExit,
    ConfidentialSwap,
    LiquidityProvision,
    Lending,
    PerpetualMargin,
    OracleUpdate,
    ProofAggregation,
    Emergency,
}

impl TransactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MoneroDeposit => "monero_deposit",
            Self::MoneroExit => "monero_exit",
            Self::ConfidentialSwap => "confidential_swap",
            Self::LiquidityProvision => "liquidity_provision",
            Self::Lending => "lending",
            Self::PerpetualMargin => "perpetual_margin",
            Self::OracleUpdate => "oracle_update",
            Self::ProofAggregation => "proof_aggregation",
            Self::Emergency => "emergency",
        }
    }

    pub fn fair_weight(self) -> u64 {
        match self {
            Self::Emergency => 192,
            Self::MoneroExit => 160,
            Self::MoneroDeposit => 144,
            Self::ConfidentialSwap => 128,
            Self::LiquidityProvision => 112,
            Self::PerpetualMargin => 108,
            Self::Lending => 100,
            Self::WalletTransfer => 96,
            Self::ProofAggregation => 80,
            Self::OracleUpdate => 64,
        }
    }

    pub fn low_fee_floor_bps(self) -> u64 {
        match self {
            Self::ProofAggregation => 1_500,
            Self::WalletTransfer => 2_500,
            Self::MoneroDeposit => 2_700,
            Self::MoneroExit => 3_000,
            Self::ConfidentialSwap => 3_200,
            Self::LiquidityProvision => 2_200,
            Self::Lending => 2_600,
            Self::PerpetualMargin => 3_500,
            Self::OracleUpdate => 1_000,
            Self::Emergency => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Pending,
    Committed,
    Revealed,
    Ordered,
    Included,
    Rebated,
    Expired,
    Rejected,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Ordered => "ordered",
            Self::Included => "included",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Sealed,
    Revealing,
    Ordered,
    Included,
    Finalized,
    Challenged,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Revealing => "revealing",
            Self::Ordered => "ordered",
            Self::Included => "included",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardKind {
    Nullifier,
    ConflictSet,
    AccountNonce,
    MoneroKeyImage,
    BridgeExitTicket,
    DefiPosition,
    LiquidityLock,
    ReplayFence,
}

impl GuardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::ConflictSet => "conflict_set",
            Self::AccountNonce => "account_nonce",
            Self::MoneroKeyImage => "monero_key_image",
            Self::BridgeExitTicket => "bridge_exit_ticket",
            Self::DefiPosition => "defi_position",
            Self::LiquidityLock => "liquidity_lock",
            Self::ReplayFence => "replay_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Admission,
    SequencerCommit,
    WindowSeal,
    Reveal,
    FairOrder,
    Inclusion,
    Rebate,
    SlashingEvidence,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::SequencerCommit => "sequencer_commit",
            Self::WindowSeal => "window_seal",
            Self::Reveal => "reveal",
            Self::FairOrder => "fair_order",
            Self::Inclusion => "inclusion",
            Self::Rebate => "rebate",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Included,
    Deferred,
    ConflictRejected,
    NullifierRejected,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Included => "included",
            Self::Deferred => "deferred",
            Self::ConflictRejected => "conflict_rejected",
            Self::NullifierRejected => "nullifier_rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    LowFeeLane,
    BatchNetting,
    LiquidityImprovement,
    ProofAmortization,
    CongestionRelief,
    PrivacySetBoost,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeLane => "low_fee_lane",
            Self::BatchNetting => "batch_netting",
            Self::LiquidityImprovement => "liquidity_improvement",
            Self::ProofAmortization => "proof_amortization",
            Self::CongestionRelief => "congestion_relief",
            Self::PrivacySetBoost => "privacy_set_boost",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_kem_suite: String,
    pub pq_signature_suite: String,
    pub envelope_aead_suite: String,
    pub fair_order_vdf_suite: String,
    pub privacy_proof_system: String,
    pub window_blocks: u64,
    pub reveal_blocks: u64,
    pub max_envelopes_per_window: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub quorum_threshold_bps: u64,
    pub base_fee_micro_units: u64,
    pub low_fee_target_micro_units: u64,
    pub rebate_budget_units: u64,
    pub defi_lane_weight_bps: u64,
    pub monero_lane_weight_bps: u64,
    pub emergency_lane_weight_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            envelope_aead_suite: ENVELOPE_AEAD_SUITE.to_string(),
            fair_order_vdf_suite: FAIR_ORDER_VDF_SUITE.to_string(),
            privacy_proof_system: PRIVACY_PROOF_SYSTEM.to_string(),
            window_blocks: DEFAULT_WINDOW_BLOCKS,
            reveal_blocks: DEFAULT_REVEAL_BLOCKS,
            max_envelopes_per_window: DEFAULT_MAX_ENVELOPES_PER_WINDOW,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_threshold_bps: DEFAULT_QUORUM_THRESHOLD_BPS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            rebate_budget_units: DEFAULT_REBATE_BUDGET_UNITS,
            defi_lane_weight_bps: 3_000,
            monero_lane_weight_bps: 2_500,
            emergency_lane_weight_bps: 500,
        }
    }
}

impl Config {
    pub fn validate(&self) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "encrypted mempool fair order protocol mismatch",
        )?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(self.window_blocks > 0, "window blocks must be positive")?;
        require(self.reveal_blocks > 0, "reveal blocks must be positive")?;
        require(
            self.max_envelopes_per_window > 0,
            "window envelope capacity must be positive",
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
            self.defi_lane_weight_bps
                + self.monero_lane_weight_bps
                + self.emergency_lane_weight_bps
                <= MAX_BPS,
            "lane weights exceed max bps",
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
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "envelope_aead_suite": self.envelope_aead_suite,
            "fair_order_vdf_suite": self.fair_order_vdf_suite,
            "privacy_proof_system": self.privacy_proof_system,
            "window_blocks": self.window_blocks,
            "reveal_blocks": self.reveal_blocks,
            "max_envelopes_per_window": self.max_envelopes_per_window,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_threshold_bps": self.quorum_threshold_bps,
            "base_fee_micro_units": self.base_fee_micro_units,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "rebate_budget_units": self.rebate_budget_units,
            "defi_lane_weight_bps": self.defi_lane_weight_bps,
            "monero_lane_weight_bps": self.monero_lane_weight_bps,
            "emergency_lane_weight_bps": self.emergency_lane_weight_bps,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_envelope_sequence: u64,
    pub next_window_sequence: u64,
    pub next_commitment_sequence: u64,
    pub next_attestation_sequence: u64,
    pub next_guard_sequence: u64,
    pub next_receipt_sequence: u64,
    pub next_rebate_sequence: u64,
    pub accepted_envelopes: u64,
    pub rejected_envelopes: u64,
    pub included_envelopes: u64,
    pub rebated_envelopes: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "counters",
            "next_envelope_sequence": self.next_envelope_sequence,
            "next_window_sequence": self.next_window_sequence,
            "next_commitment_sequence": self.next_commitment_sequence,
            "next_attestation_sequence": self.next_attestation_sequence,
            "next_guard_sequence": self.next_guard_sequence,
            "next_receipt_sequence": self.next_receipt_sequence,
            "next_rebate_sequence": self.next_rebate_sequence,
            "accepted_envelopes": self.accepted_envelopes,
            "rejected_envelopes": self.rejected_envelopes,
            "included_envelopes": self.included_envelopes,
            "rebated_envelopes": self.rebated_envelopes,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_rebate_units": self.total_rebate_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedTransactionEnvelope {
    pub envelope_id: String,
    pub tx_class: TransactionClass,
    pub sender_commitment: String,
    pub account_commitment: String,
    pub ciphertext_root: String,
    pub payload_commitment: String,
    pub pq_kem_ciphertext_root: String,
    pub pq_signature_root: String,
    pub nullifier_root: String,
    pub conflict_set_root: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: EnvelopeStatus,
    pub lane_hint: String,
}

impl EncryptedTransactionEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        tx_class: TransactionClass,
        sender_commitment: &str,
        account_commitment: &str,
        ciphertext_root: &str,
        payload_commitment: &str,
        pq_kem_ciphertext_root: &str,
        pq_signature_root: &str,
        nullifier_root: &str,
        conflict_set_root: &str,
        fee_asset_id: &str,
        max_fee_micro_units: u64,
        priority_fee_micro_units: u64,
        privacy_set_size: u64,
        pq_security_bits: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        lane_hint: &str,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(
            !sender_commitment.is_empty(),
            "sender commitment is required",
        )?;
        require(
            !account_commitment.is_empty(),
            "account commitment is required",
        )?;
        require(!ciphertext_root.is_empty(), "ciphertext root is required")?;
        require(
            !payload_commitment.is_empty(),
            "payload commitment is required",
        )?;
        require(
            !pq_kem_ciphertext_root.is_empty(),
            "pq kem ciphertext root is required",
        )?;
        require(
            !pq_signature_root.is_empty(),
            "pq signature root is required",
        )?;
        require(!nullifier_root.is_empty(), "nullifier root is required")?;
        require(
            !conflict_set_root.is_empty(),
            "conflict set root is required",
        )?;
        require(!fee_asset_id.is_empty(), "fee asset id is required")?;
        require(max_fee_micro_units > 0, "fee cap must be positive")?;
        require(
            expires_at_height > submitted_at_height,
            "envelope expiry must be after submission",
        )?;
        let envelope_id = envelope_id(
            sequence,
            sender_commitment,
            payload_commitment,
            nullifier_root,
            submitted_at_height,
        );
        Ok(Self {
            envelope_id,
            tx_class,
            sender_commitment: sender_commitment.to_string(),
            account_commitment: account_commitment.to_string(),
            ciphertext_root: ciphertext_root.to_string(),
            payload_commitment: payload_commitment.to_string(),
            pq_kem_ciphertext_root: pq_kem_ciphertext_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            conflict_set_root: conflict_set_root.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_micro_units,
            priority_fee_micro_units,
            privacy_set_size,
            pq_security_bits,
            submitted_at_height,
            expires_at_height,
            status: EnvelopeStatus::Pending,
            lane_hint: lane_hint.to_string(),
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<()> {
        require(!self.envelope_id.is_empty(), "envelope id is required")?;
        require(
            self.privacy_set_size >= config.min_privacy_set,
            "envelope privacy set below floor",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "envelope pq security below floor",
        )?;
        require(
            self.max_fee_micro_units >= config.low_fee_target_micro_units,
            "envelope fee cap below low fee target",
        )?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "envelope expiry must be after submission",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_transaction_envelope",
            "envelope_id": self.envelope_id,
            "tx_class": self.tx_class.as_str(),
            "fair_weight": self.tx_class.fair_weight(),
            "sender_commitment": self.sender_commitment,
            "account_commitment": self.account_commitment,
            "ciphertext_root": self.ciphertext_root,
            "payload_commitment": self.payload_commitment,
            "pq_kem_ciphertext_root": self.pq_kem_ciphertext_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_root": self.nullifier_root,
            "conflict_set_root": self.conflict_set_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "lane_hint": self.lane_hint,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ENVELOPE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderWindow {
    pub window_id: String,
    pub sequence: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub reveal_deadline_height: u64,
    pub lane_id: String,
    pub anchor_randomness_root: String,
    pub vdf_transcript_root: String,
    pub encrypted_envelope_root: String,
    pub ordered_envelope_root: String,
    pub status: WindowStatus,
    pub max_envelopes: u64,
    pub min_quorum_weight_bps: u64,
}

impl FairOrderWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        start_height: u64,
        end_height: u64,
        reveal_deadline_height: u64,
        lane_id: &str,
        anchor_randomness_root: &str,
        vdf_transcript_root: &str,
        encrypted_envelope_root: &str,
        ordered_envelope_root: &str,
        max_envelopes: u64,
        min_quorum_weight_bps: u64,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(end_height > start_height, "window end must be after start")?;
        require(
            reveal_deadline_height >= end_height,
            "reveal deadline must be at or after window end",
        )?;
        require(!lane_id.is_empty(), "lane id is required")?;
        require(
            !anchor_randomness_root.is_empty(),
            "anchor randomness root is required",
        )?;
        require(
            !vdf_transcript_root.is_empty(),
            "vdf transcript root is required",
        )?;
        require(
            !encrypted_envelope_root.is_empty(),
            "encrypted envelope root is required",
        )?;
        require(
            !ordered_envelope_root.is_empty(),
            "ordered envelope root is required",
        )?;
        require(max_envelopes > 0, "window capacity must be positive")?;
        require(
            min_quorum_weight_bps <= MAX_BPS,
            "window quorum threshold exceeds max bps",
        )?;
        let window_id = window_id(sequence, lane_id, start_height, end_height);
        Ok(Self {
            window_id,
            sequence,
            start_height,
            end_height,
            reveal_deadline_height,
            lane_id: lane_id.to_string(),
            anchor_randomness_root: anchor_randomness_root.to_string(),
            vdf_transcript_root: vdf_transcript_root.to_string(),
            encrypted_envelope_root: encrypted_envelope_root.to_string(),
            ordered_envelope_root: ordered_envelope_root.to_string(),
            status: WindowStatus::Open,
            max_envelopes,
            min_quorum_weight_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_order_window",
            "window_id": self.window_id,
            "sequence": self.sequence,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "lane_id": self.lane_id,
            "anchor_randomness_root": self.anchor_randomness_root,
            "vdf_transcript_root": self.vdf_transcript_root,
            "encrypted_envelope_root": self.encrypted_envelope_root,
            "ordered_envelope_root": self.ordered_envelope_root,
            "status": self.status.as_str(),
            "max_envelopes": self.max_envelopes,
            "min_quorum_weight_bps": self.min_quorum_weight_bps,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAIR-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerCommitment {
    pub commitment_id: String,
    pub sequence: u64,
    pub sequencer_id: String,
    pub window_id: String,
    pub preimage_commitment_root: String,
    pub envelope_set_root: String,
    pub fair_order_salt_root: String,
    pub low_fee_policy_root: String,
    pub pq_signature_root: String,
    pub committed_at_height: u64,
    pub reveal_after_height: u64,
}

impl SequencerCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        sequencer_id: &str,
        window_id: &str,
        preimage_commitment_root: &str,
        envelope_set_root: &str,
        fair_order_salt_root: &str,
        low_fee_policy_root: &str,
        pq_signature_root: &str,
        committed_at_height: u64,
        reveal_after_height: u64,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(!sequencer_id.is_empty(), "sequencer id is required")?;
        require(!window_id.is_empty(), "window id is required")?;
        require(
            !preimage_commitment_root.is_empty(),
            "preimage commitment root is required",
        )?;
        require(
            !envelope_set_root.is_empty(),
            "envelope set root is required",
        )?;
        require(
            !fair_order_salt_root.is_empty(),
            "fair order salt root is required",
        )?;
        require(
            !low_fee_policy_root.is_empty(),
            "low fee policy root is required",
        )?;
        require(
            !pq_signature_root.is_empty(),
            "pq signature root is required",
        )?;
        require(
            reveal_after_height >= committed_at_height,
            "reveal height must be after commitment",
        )?;
        let commitment_id = sequencer_commitment_id(sequence, sequencer_id, window_id);
        Ok(Self {
            commitment_id,
            sequence,
            sequencer_id: sequencer_id.to_string(),
            window_id: window_id.to_string(),
            preimage_commitment_root: preimage_commitment_root.to_string(),
            envelope_set_root: envelope_set_root.to_string(),
            fair_order_salt_root: fair_order_salt_root.to_string(),
            low_fee_policy_root: low_fee_policy_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            committed_at_height,
            reveal_after_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_commitment",
            "commitment_id": self.commitment_id,
            "sequence": self.sequence,
            "sequencer_id": self.sequencer_id,
            "window_id": self.window_id,
            "preimage_commitment_root": self.preimage_commitment_root,
            "envelope_set_root": self.envelope_set_root,
            "fair_order_salt_root": self.fair_order_salt_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "pq_signature_root": self.pq_signature_root,
            "committed_at_height": self.committed_at_height,
            "reveal_after_height": self.reveal_after_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SEQUENCER-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub subject_root: String,
    pub committee_root: String,
    pub aggregate_public_key_root: String,
    pub aggregate_signature_root: String,
    pub signer_bitmap_root: String,
    pub weight_bps: u64,
    pub signed_at_height: u64,
}

impl QuorumAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        kind: AttestationKind,
        subject_id: &str,
        subject_root: &str,
        committee_root: &str,
        aggregate_public_key_root: &str,
        aggregate_signature_root: &str,
        signer_bitmap_root: &str,
        weight_bps: u64,
        signed_at_height: u64,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(!subject_id.is_empty(), "attestation subject id is required")?;
        require(
            !subject_root.is_empty(),
            "attestation subject root is required",
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
            "kind": "quorum_attestation",
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "attestation_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "committee_root": self.committee_root,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "signer_bitmap_root": self.signer_bitmap_root,
            "weight_bps": self.weight_bps,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("QUORUM-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictNullifierGuard {
    pub guard_id: String,
    pub sequence: u64,
    pub kind: GuardKind,
    pub envelope_id: String,
    pub guard_root: String,
    pub namespace: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl ConflictNullifierGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        kind: GuardKind,
        envelope_id: &str,
        guard_root: &str,
        namespace: &str,
        first_seen_height: u64,
        expires_at_height: u64,
        consumed: bool,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(!envelope_id.is_empty(), "guard envelope id is required")?;
        require(!guard_root.is_empty(), "guard root is required")?;
        require(!namespace.is_empty(), "guard namespace is required")?;
        require(
            expires_at_height > first_seen_height,
            "guard expiry must be after first seen height",
        )?;
        let guard_id = guard_id(sequence, kind, namespace, guard_root);
        Ok(Self {
            guard_id,
            sequence,
            kind,
            envelope_id: envelope_id.to_string(),
            guard_root: guard_root.to_string(),
            namespace: namespace.to_string(),
            first_seen_height,
            expires_at_height,
            consumed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "conflict_nullifier_guard",
            "guard_id": self.guard_id,
            "sequence": self.sequence,
            "guard_kind": self.kind.as_str(),
            "envelope_id": self.envelope_id,
            "guard_root": self.guard_root,
            "namespace": self.namespace,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFLICT-NULLIFIER-GUARD", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub envelope_id: String,
    pub window_id: String,
    pub ordered_index: u64,
    pub block_height: u64,
    pub status: ReceiptStatus,
    pub execution_commitment_root: String,
    pub state_transition_root: String,
    pub fee_charged_micro_units: u64,
    pub attestation_root: String,
}

impl InclusionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        envelope_id: &str,
        window_id: &str,
        ordered_index: u64,
        block_height: u64,
        status: ReceiptStatus,
        execution_commitment_root: &str,
        state_transition_root: &str,
        fee_charged_micro_units: u64,
        attestation_root: &str,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(!envelope_id.is_empty(), "receipt envelope id is required")?;
        require(!window_id.is_empty(), "receipt window id is required")?;
        require(
            !execution_commitment_root.is_empty(),
            "execution commitment root is required",
        )?;
        require(
            !state_transition_root.is_empty(),
            "state transition root is required",
        )?;
        require(
            !attestation_root.is_empty(),
            "receipt attestation root is required",
        )?;
        let receipt_id = receipt_id(sequence, envelope_id, window_id, ordered_index);
        Ok(Self {
            receipt_id,
            sequence,
            envelope_id: envelope_id.to_string(),
            window_id: window_id.to_string(),
            ordered_index,
            block_height,
            status,
            execution_commitment_root: execution_commitment_root.to_string(),
            state_transition_root: state_transition_root.to_string(),
            fee_charged_micro_units,
            attestation_root: attestation_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "inclusion_receipt",
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "envelope_id": self.envelope_id,
            "window_id": self.window_id,
            "ordered_index": self.ordered_index,
            "block_height": self.block_height,
            "status": self.status.as_str(),
            "execution_commitment_root": self.execution_commitment_root,
            "state_transition_root": self.state_transition_root,
            "fee_charged_micro_units": self.fee_charged_micro_units,
            "attestation_root": self.attestation_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("INCLUSION-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub sequence: u64,
    pub envelope_id: String,
    pub receipt_id: String,
    pub reason: RebateReason,
    pub fee_asset_id: String,
    pub charged_micro_units: u64,
    pub target_micro_units: u64,
    pub rebate_units: u64,
    pub sponsor_commitment: String,
    pub rebate_note_root: String,
    pub issued_at_height: u64,
}

impl LowFeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        envelope_id: &str,
        receipt_id: &str,
        reason: RebateReason,
        fee_asset_id: &str,
        charged_micro_units: u64,
        target_micro_units: u64,
        sponsor_commitment: &str,
        rebate_note_root: &str,
        issued_at_height: u64,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(!envelope_id.is_empty(), "rebate envelope id is required")?;
        require(!receipt_id.is_empty(), "rebate receipt id is required")?;
        require(!fee_asset_id.is_empty(), "rebate fee asset id is required")?;
        require(!sponsor_commitment.is_empty(), "rebate sponsor is required")?;
        require(!rebate_note_root.is_empty(), "rebate note root is required")?;
        let rebate_units = charged_micro_units.saturating_sub(target_micro_units);
        let rebate_id = rebate_id(sequence, envelope_id, receipt_id, reason);
        Ok(Self {
            rebate_id,
            sequence,
            envelope_id: envelope_id.to_string(),
            receipt_id: receipt_id.to_string(),
            reason,
            fee_asset_id: fee_asset_id.to_string(),
            charged_micro_units,
            target_micro_units,
            rebate_units,
            sponsor_commitment: sponsor_commitment.to_string(),
            rebate_note_root: rebate_note_root.to_string(),
            issued_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rebate",
            "rebate_id": self.rebate_id,
            "sequence": self.sequence,
            "envelope_id": self.envelope_id,
            "receipt_id": self.receipt_id,
            "reason": self.reason.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "charged_micro_units": self.charged_micro_units,
            "target_micro_units": self.target_micro_units,
            "rebate_units": self.rebate_units,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_note_root": self.rebate_note_root,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("LOW-FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairLanePolicy {
    pub lane_id: String,
    pub label: String,
    pub accepted_classes: Vec<TransactionClass>,
    pub max_delay_blocks: u64,
    pub max_fee_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub reserved_capacity_bps: u64,
    pub privacy_boost_bps: u64,
    pub active: bool,
}

impl FairLanePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        accepted_classes: Vec<TransactionClass>,
        max_delay_blocks: u64,
        max_fee_micro_units: u64,
        target_fee_micro_units: u64,
        reserved_capacity_bps: u64,
        privacy_boost_bps: u64,
        active: bool,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(!label.is_empty(), "lane policy label is required")?;
        require(
            !accepted_classes.is_empty(),
            "lane policy must accept at least one class",
        )?;
        require(max_delay_blocks > 0, "lane policy delay must be positive")?;
        require(
            target_fee_micro_units <= max_fee_micro_units,
            "lane policy target fee cannot exceed max fee",
        )?;
        require(
            reserved_capacity_bps <= MAX_BPS,
            "lane reserved capacity exceeds max bps",
        )?;
        require(
            privacy_boost_bps <= MAX_BPS,
            "lane privacy boost exceeds max bps",
        )?;
        let class_root = tx_class_root(&accepted_classes);
        let lane_id = lane_policy_id(label, &class_root, max_delay_blocks);
        Ok(Self {
            lane_id,
            label: label.to_string(),
            accepted_classes,
            max_delay_blocks,
            max_fee_micro_units,
            target_fee_micro_units,
            reserved_capacity_bps,
            privacy_boost_bps,
            active,
        })
    }

    pub fn accepts(&self, tx_class: TransactionClass) -> bool {
        self.active && self.accepted_classes.contains(&tx_class)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_lane_policy",
            "lane_id": self.lane_id,
            "label": self.label,
            "accepted_classes": self.accepted_classes.iter().map(|class| class.as_str()).collect::<Vec<_>>(),
            "accepted_class_root": tx_class_root(&self.accepted_classes),
            "max_delay_blocks": self.max_delay_blocks,
            "max_fee_micro_units": self.max_fee_micro_units,
            "target_fee_micro_units": self.target_fee_micro_units,
            "reserved_capacity_bps": self.reserved_capacity_bps,
            "privacy_boost_bps": self.privacy_boost_bps,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAIR-LANE-POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAuditCheckpoint {
    pub checkpoint_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub envelope_root: String,
    pub window_root: String,
    pub commitment_root: String,
    pub attestation_root: String,
    pub guard_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub public_record_root: String,
    pub state_root: String,
    pub pq_signature_root: String,
}

impl PublicAuditCheckpoint {
    pub fn from_state(
        state: &State,
        pq_signature_root: &str,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<Self> {
        require(
            !pq_signature_root.is_empty(),
            "checkpoint pq signature root is required",
        )?;
        let roots = state.roots();
        let checkpoint_id = audit_checkpoint_id(state.l2_height, &roots.state_root);
        Ok(Self {
            checkpoint_id,
            l2_height: state.l2_height,
            monero_height: state.monero_height,
            envelope_root: roots.envelope_root,
            window_root: roots.window_root,
            commitment_root: roots.sequencer_commitment_root,
            attestation_root: roots.quorum_attestation_root,
            guard_root: roots.conflict_nullifier_guard_root,
            receipt_root: roots.inclusion_receipt_root,
            rebate_root: roots.low_fee_rebate_root,
            public_record_root: roots.public_record_root,
            state_root: roots.state_root,
            pq_signature_root: pq_signature_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_audit_checkpoint",
            "checkpoint_id": self.checkpoint_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "envelope_root": self.envelope_root,
            "window_root": self.window_root,
            "commitment_root": self.commitment_root,
            "attestation_root": self.attestation_root,
            "guard_root": self.guard_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
            "pq_signature_root": self.pq_signature_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PUBLIC-AUDIT-CHECKPOINT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMempoolMetrics {
    pub l2_height: u64,
    pub pending_envelopes: u64,
    pub included_envelopes: u64,
    pub rebated_envelopes: u64,
    pub average_fee_micro_units: u64,
    pub average_rebate_units: u64,
    pub privacy_set_floor: u64,
    pub pq_security_floor: u64,
    pub low_fee_target_micro_units: u64,
}

impl PublicMempoolMetrics {
    pub fn from_state(state: &State) -> Self {
        let pending_envelopes = state
            .envelopes
            .values()
            .filter(|envelope| {
                matches!(
                    envelope.status,
                    EnvelopeStatus::Pending
                        | EnvelopeStatus::Committed
                        | EnvelopeStatus::Revealed
                        | EnvelopeStatus::Ordered
                )
            })
            .count() as u64;
        let average_fee_micro_units = if state.receipts.is_empty() {
            0
        } else {
            state.counters.total_fee_micro_units / state.receipts.len() as u64
        };
        let average_rebate_units = if state.rebates.is_empty() {
            0
        } else {
            state.counters.total_rebate_units / state.rebates.len() as u64
        };
        Self {
            l2_height: state.l2_height,
            pending_envelopes,
            included_envelopes: state.counters.included_envelopes,
            rebated_envelopes: state.counters.rebated_envelopes,
            average_fee_micro_units,
            average_rebate_units,
            privacy_set_floor: state.config.min_privacy_set,
            pq_security_floor: state.config.min_pq_security_bits,
            low_fee_target_micro_units: state.config.low_fee_target_micro_units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_mempool_metrics",
            "l2_height": self.l2_height,
            "pending_envelopes": self.pending_envelopes,
            "included_envelopes": self.included_envelopes,
            "rebated_envelopes": self.rebated_envelopes,
            "average_fee_micro_units": self.average_fee_micro_units,
            "average_rebate_units": self.average_rebate_units,
            "privacy_set_floor": self.privacy_set_floor,
            "pq_security_floor": self.pq_security_floor,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PUBLIC-MEMPOOL-METRICS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub envelope_root: String,
    pub window_root: String,
    pub sequencer_commitment_root: String,
    pub quorum_attestation_root: String,
    pub conflict_nullifier_guard_root: String,
    pub inclusion_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub pending_nullifier_root: String,
    pub consumed_nullifier_root: String,
    pub conflict_namespace_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "roots",
            "envelope_root": self.envelope_root,
            "window_root": self.window_root,
            "sequencer_commitment_root": self.sequencer_commitment_root,
            "quorum_attestation_root": self.quorum_attestation_root,
            "conflict_nullifier_guard_root": self.conflict_nullifier_guard_root,
            "inclusion_receipt_root": self.inclusion_receipt_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "pending_nullifier_root": self.pending_nullifier_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "conflict_namespace_root": self.conflict_namespace_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub l2_height: u64,
    pub monero_height: u64,
    pub sequencer_set_root: String,
    pub committee_root: String,
    pub rebate_vault_root: String,
    pub envelopes: BTreeMap<String, EncryptedTransactionEnvelope>,
    pub windows: BTreeMap<String, FairOrderWindow>,
    pub sequencer_commitments: BTreeMap<String, SequencerCommitment>,
    pub quorum_attestations: BTreeMap<String, QuorumAttestation>,
    pub guards: BTreeMap<String, ConflictNullifierGuard>,
    pub receipts: BTreeMap<String, InclusionReceipt>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        Self {
            config,
            counters: Counters::default(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            sequencer_set_root: deterministic_root(
                "DEVNET-SEQUENCER-SET",
                "monero-l2-pq-sequencers",
            ),
            committee_root: deterministic_root("DEVNET-COMMITTEE", "pq-fair-order-committee"),
            rebate_vault_root: deterministic_root("DEVNET-REBATE-VAULT", "low-fee-rebate-vault"),
            envelopes: BTreeMap::new(),
            windows: BTreeMap::new(),
            sequencer_commitments: BTreeMap::new(),
            quorum_attestations: BTreeMap::new(),
            guards: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.populate_devnet();
        state
    }

    pub fn validate(&self) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<()> {
        self.config.validate()?;
        require(
            self.envelopes.len() <= MAX_MEMPOOL_ENVELOPES,
            "too many envelopes",
        )?;
        require(
            self.windows.len() <= MAX_FAIR_WINDOWS,
            "too many fair windows",
        )?;
        require(
            self.sequencer_commitments.len() <= MAX_SEQUENCER_COMMITMENTS,
            "too many sequencer commitments",
        )?;
        require(
            self.quorum_attestations.len() <= MAX_QUORUM_ATTESTATIONS,
            "too many quorum attestations",
        )?;
        require(self.guards.len() <= MAX_GUARDS, "too many guards")?;
        require(self.receipts.len() <= MAX_RECEIPTS, "too many receipts")?;
        require(self.rebates.len() <= MAX_REBATES, "too many rebates")?;
        let mut nullifiers = BTreeSet::new();
        for envelope in self.envelopes.values() {
            envelope.validate(&self.config)?;
            require(
                nullifiers.insert(envelope.nullifier_root.clone()),
                "duplicate envelope nullifier root",
            )?;
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let public_without_roots = self.public_record_without_roots();
        let public_root = public_record_root(&public_without_roots);
        let state_root = state_root_from_record(&public_without_roots);
        Roots {
            envelope_root: self.envelope_root(),
            window_root: self.window_root(),
            sequencer_commitment_root: self.sequencer_commitment_root(),
            quorum_attestation_root: self.quorum_attestation_root(),
            conflict_nullifier_guard_root: self.conflict_nullifier_guard_root(),
            inclusion_receipt_root: self.inclusion_receipt_root(),
            low_fee_rebate_root: self.low_fee_rebate_root(),
            pending_nullifier_root: self.pending_nullifier_root(),
            consumed_nullifier_root: self.consumed_nullifier_root(),
            conflict_namespace_root: self.conflict_namespace_root(),
            public_record_root: public_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_roots();
        if let Value::Object(ref mut values) = record {
            values.insert("roots".to_string(), self.roots().public_record());
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_roots())
    }

    pub fn public_record_without_roots(&self) -> Value {
        json!({
            "kind": "private_l2_pq_encrypted_mempool_fair_order_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "sequencer_set_root": self.sequencer_set_root,
            "committee_root": self.committee_root,
            "rebate_vault_root": self.rebate_vault_root,
            "envelopes": self.envelopes.values().map(EncryptedTransactionEnvelope::public_record).collect::<Vec<_>>(),
            "fair_windows": self.windows.values().map(FairOrderWindow::public_record).collect::<Vec<_>>(),
            "sequencer_commitments": self.sequencer_commitments.values().map(SequencerCommitment::public_record).collect::<Vec<_>>(),
            "quorum_attestations": self.quorum_attestations.values().map(QuorumAttestation::public_record).collect::<Vec<_>>(),
            "conflict_nullifier_guards": self.guards.values().map(ConflictNullifierGuard::public_record).collect::<Vec<_>>(),
            "inclusion_receipts": self.receipts.values().map(InclusionReceipt::public_record).collect::<Vec<_>>(),
            "low_fee_rebates": self.rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn envelope_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-ENVELOPES",
            self.envelopes
                .values()
                .map(EncryptedTransactionEnvelope::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn window_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-WINDOWS",
            self.windows
                .values()
                .map(FairOrderWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sequencer_commitment_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-SEQUENCER-COMMITMENTS",
            self.sequencer_commitments
                .values()
                .map(SequencerCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn quorum_attestation_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-QUORUM-ATTESTATIONS",
            self.quorum_attestations
                .values()
                .map(QuorumAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn conflict_nullifier_guard_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-CONFLICT-NULLIFIER-GUARDS",
            self.guards
                .values()
                .map(ConflictNullifierGuard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn inclusion_receipt_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-INCLUSION-RECEIPTS",
            self.receipts
                .values()
                .map(InclusionReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_rebate_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-LOW-FEE-REBATES",
            self.rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pending_nullifier_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-PENDING-NULLIFIERS",
            self.envelopes
                .values()
                .filter(|envelope| {
                    matches!(
                        envelope.status,
                        EnvelopeStatus::Pending
                            | EnvelopeStatus::Committed
                            | EnvelopeStatus::Revealed
                            | EnvelopeStatus::Ordered
                    )
                })
                .map(|envelope| {
                    json!({
                        "envelope_id": envelope.envelope_id,
                        "nullifier_root": envelope.nullifier_root,
                        "expires_at_height": envelope.expires_at_height,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn consumed_nullifier_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-CONSUMED-NULLIFIERS",
            self.guards
                .values()
                .filter(|guard| guard.consumed && guard.kind == GuardKind::Nullifier)
                .map(ConflictNullifierGuard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn conflict_namespace_root(&self) -> String {
        records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-CONFLICT-NAMESPACES",
            self.guards
                .values()
                .map(|guard| {
                    json!({
                        "guard_id": guard.guard_id,
                        "guard_kind": guard.kind.as_str(),
                        "namespace": guard.namespace,
                        "guard_root": guard.guard_root,
                        "consumed": guard.consumed,
                    })
                })
                .collect::<Vec<_>>(),
        )
    }

    pub fn admit_envelope(
        &mut self,
        mut envelope: EncryptedTransactionEnvelope,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<String> {
        envelope.validate(&self.config)?;
        require(
            !self.envelopes.contains_key(&envelope.envelope_id),
            "duplicate envelope id",
        )?;
        require(
            !self
                .envelopes
                .values()
                .any(|existing| existing.nullifier_root == envelope.nullifier_root),
            "duplicate pending nullifier",
        )?;
        envelope.status = EnvelopeStatus::Committed;
        let envelope_id = envelope.envelope_id.clone();
        self.counters.accepted_envelopes = self.counters.accepted_envelopes.saturating_add(1);
        self.counters.next_envelope_sequence = self
            .counters
            .next_envelope_sequence
            .max(envelope_id_sequence_hint(&envelope_id) + 1);
        self.envelopes.insert(envelope_id.clone(), envelope);
        Ok(envelope_id)
    }

    pub fn attach_guard(
        &mut self,
        guard: ConflictNullifierGuard,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<String> {
        require(
            self.envelopes.contains_key(&guard.envelope_id),
            "guard references unknown envelope",
        )?;
        require(
            !self.guards.contains_key(&guard.guard_id),
            "duplicate guard id",
        )?;
        let guard_id = guard.guard_id.clone();
        self.guards.insert(guard_id.clone(), guard);
        Ok(guard_id)
    }

    pub fn record_receipt(
        &mut self,
        receipt: InclusionReceipt,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<String> {
        require(
            self.envelopes.contains_key(&receipt.envelope_id),
            "receipt references unknown envelope",
        )?;
        require(
            self.windows.contains_key(&receipt.window_id),
            "receipt references unknown window",
        )?;
        require(
            !self.receipts.contains_key(&receipt.receipt_id),
            "duplicate receipt id",
        )?;
        if let Some(envelope) = self.envelopes.get_mut(&receipt.envelope_id) {
            envelope.status = match receipt.status {
                ReceiptStatus::Included => EnvelopeStatus::Included,
                ReceiptStatus::ConflictRejected | ReceiptStatus::NullifierRejected => {
                    EnvelopeStatus::Rejected
                }
                ReceiptStatus::Expired => EnvelopeStatus::Expired,
                ReceiptStatus::Accepted | ReceiptStatus::Deferred => envelope.status,
            };
        }
        let included_increment = if receipt.status == ReceiptStatus::Included {
            1
        } else {
            0
        };
        self.counters.included_envelopes = self
            .counters
            .included_envelopes
            .saturating_add(included_increment);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(receipt.fee_charged_micro_units);
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn record_rebate(
        &mut self,
        rebate: LowFeeRebate,
    ) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<String> {
        require(
            self.envelopes.contains_key(&rebate.envelope_id),
            "rebate references unknown envelope",
        )?;
        require(
            self.receipts.contains_key(&rebate.receipt_id),
            "rebate references unknown receipt",
        )?;
        require(
            !self.rebates.contains_key(&rebate.rebate_id),
            "duplicate rebate id",
        )?;
        if let Some(envelope) = self.envelopes.get_mut(&rebate.envelope_id) {
            envelope.status = EnvelopeStatus::Rebated;
        }
        self.counters.rebated_envelopes = self.counters.rebated_envelopes.saturating_add(1);
        self.counters.total_rebate_units = self
            .counters
            .total_rebate_units
            .saturating_add(rebate.rebate_units);
        let rebate_id = rebate.rebate_id.clone();
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    fn populate_devnet(&mut self) {
        let transfer = EncryptedTransactionEnvelope::new(
            0,
            TransactionClass::WalletTransfer,
            &deterministic_root("DEVNET-SENDER", "alice"),
            &deterministic_root("DEVNET-ACCOUNT", "alice-main"),
            &deterministic_root("DEVNET-CIPHERTEXT", "wallet-transfer"),
            &deterministic_root("DEVNET-PAYLOAD", "wallet-transfer"),
            &deterministic_root("DEVNET-KEM", "wallet-transfer"),
            &deterministic_root("DEVNET-PQ-SIG", "alice-transfer"),
            &deterministic_root("DEVNET-NULLIFIER", "alice-transfer-0"),
            &deterministic_root("DEVNET-CONFLICT", "alice-account-nonce-7"),
            "uxmr",
            520,
            40,
            512,
            256,
            self.l2_height,
            self.l2_height + 16,
            "wallet-fast",
        )
        .expect("valid devnet transfer envelope");
        let swap = EncryptedTransactionEnvelope::new(
            1,
            TransactionClass::ConfidentialSwap,
            &deterministic_root("DEVNET-SENDER", "market-maker"),
            &deterministic_root("DEVNET-ACCOUNT", "mm-vault"),
            &deterministic_root("DEVNET-CIPHERTEXT", "stable-swap"),
            &deterministic_root("DEVNET-PAYLOAD", "stable-swap"),
            &deterministic_root("DEVNET-KEM", "stable-swap"),
            &deterministic_root("DEVNET-PQ-SIG", "mm-swap"),
            &deterministic_root("DEVNET-NULLIFIER", "swap-note-42"),
            &deterministic_root("DEVNET-CONFLICT", "pool-xmr-usdc-tick"),
            "uusdc",
            740,
            80,
            768,
            256,
            self.l2_height + 1,
            self.l2_height + 12,
            "defi-netting",
        )
        .expect("valid devnet swap envelope");
        let exit = EncryptedTransactionEnvelope::new(
            2,
            TransactionClass::MoneroExit,
            &deterministic_root("DEVNET-SENDER", "merchant"),
            &deterministic_root("DEVNET-ACCOUNT", "merchant-exit"),
            &deterministic_root("DEVNET-CIPHERTEXT", "monero-exit"),
            &deterministic_root("DEVNET-PAYLOAD", "monero-exit"),
            &deterministic_root("DEVNET-KEM", "monero-exit"),
            &deterministic_root("DEVNET-PQ-SIG", "merchant-exit"),
            &deterministic_root("DEVNET-NULLIFIER", "exit-ticket-11"),
            &deterministic_root("DEVNET-CONFLICT", "monero-key-image-bucket"),
            "uxmr",
            680,
            90,
            1024,
            256,
            self.l2_height + 2,
            self.l2_height + 18,
            "monero-exit",
        )
        .expect("valid devnet exit envelope");

        let transfer_id = transfer.envelope_id.clone();
        let swap_id = swap.envelope_id.clone();
        let exit_id = exit.envelope_id.clone();
        let transfer_root = transfer.root();
        let swap_root = swap.root();
        let exit_root = exit.root();
        self.envelopes.insert(transfer_id.clone(), transfer);
        self.envelopes.insert(swap_id.clone(), swap);
        self.envelopes.insert(exit_id.clone(), exit);

        let encrypted_envelope_root = records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-DEVNET-ENVELOPE-SET",
            self.envelopes
                .values()
                .map(EncryptedTransactionEnvelope::public_record)
                .collect::<Vec<_>>(),
        );
        let ordered_envelope_root = id_list_root(
            "DEVNET-ORDERED-ENVELOPES",
            &[&transfer_id, &exit_id, &swap_id],
        );
        let window = FairOrderWindow::new(
            0,
            self.l2_height,
            self.l2_height + self.config.window_blocks,
            self.l2_height + self.config.window_blocks + self.config.reveal_blocks,
            "devnet-private-lane",
            &deterministic_root("DEVNET-RANDOMNESS", "window-0"),
            &deterministic_root("DEVNET-VDF", "window-0"),
            &encrypted_envelope_root,
            &ordered_envelope_root,
            self.config.max_envelopes_per_window,
            self.config.quorum_threshold_bps,
        )
        .expect("valid devnet fair order window");
        let window_id = window.window_id.clone();
        let window_root = window.root();
        self.windows.insert(window_id.clone(), window);

        let commitment = SequencerCommitment::new(
            0,
            "devnet-pq-sequencer-0",
            &window_id,
            &deterministic_root("DEVNET-PREIMAGE", "window-0"),
            &encrypted_envelope_root,
            &deterministic_root("DEVNET-FAIR-SALT", "window-0"),
            &deterministic_root("DEVNET-LOW-FEE-POLICY", "target-300"),
            &deterministic_root("DEVNET-PQ-SIG", "sequencer-window-0"),
            self.l2_height,
            self.l2_height + self.config.reveal_blocks,
        )
        .expect("valid devnet sequencer commitment");
        let commitment_id = commitment.commitment_id.clone();
        let commitment_root = commitment.root();
        self.sequencer_commitments
            .insert(commitment_id.clone(), commitment);

        for (sequence, (kind, subject_id, subject_root)) in [
            (
                AttestationKind::Admission,
                transfer_id.as_str(),
                transfer_root.as_str(),
            ),
            (
                AttestationKind::Admission,
                swap_id.as_str(),
                swap_root.as_str(),
            ),
            (
                AttestationKind::Admission,
                exit_id.as_str(),
                exit_root.as_str(),
            ),
            (
                AttestationKind::SequencerCommit,
                commitment_id.as_str(),
                commitment_root.as_str(),
            ),
            (
                AttestationKind::FairOrder,
                window_id.as_str(),
                window_root.as_str(),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let attestation = QuorumAttestation::new(
                sequence as u64,
                kind,
                subject_id,
                subject_root,
                &self.committee_root,
                &deterministic_root("DEVNET-AGG-PK", subject_id),
                &deterministic_root("DEVNET-AGG-SIG", subject_id),
                &deterministic_root("DEVNET-SIGNER-BITMAP", subject_id),
                7_600,
                self.l2_height + sequence as u64,
            )
            .expect("valid devnet attestation");
            self.quorum_attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }

        for (sequence, (kind, envelope_id, namespace, root, consumed)) in [
            (
                GuardKind::Nullifier,
                transfer_id.as_str(),
                "uxmr-nullifiers",
                deterministic_root("DEVNET-GUARD", "alice-transfer-nullifier"),
                true,
            ),
            (
                GuardKind::DefiPosition,
                swap_id.as_str(),
                "confidential-swap-pool",
                deterministic_root("DEVNET-GUARD", "swap-position"),
                true,
            ),
            (
                GuardKind::MoneroKeyImage,
                exit_id.as_str(),
                "monero-key-images",
                deterministic_root("DEVNET-GUARD", "exit-key-image"),
                false,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let guard = ConflictNullifierGuard::new(
                sequence as u64,
                kind,
                envelope_id,
                &root,
                namespace,
                self.l2_height,
                self.l2_height + 128,
                consumed,
            )
            .expect("valid devnet guard");
            self.guards.insert(guard.guard_id.clone(), guard);
        }

        let inclusion_attestation_root = records_root(
            "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-DEVNET-INCLUSION-ATTESTATIONS",
            self.quorum_attestations
                .values()
                .map(QuorumAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt = InclusionReceipt::new(
            0,
            &transfer_id,
            &window_id,
            0,
            self.l2_height + 5,
            ReceiptStatus::Included,
            &deterministic_root("DEVNET-EXECUTION", "transfer"),
            &deterministic_root("DEVNET-STATE-TRANSITION", "transfer"),
            430,
            &inclusion_attestation_root,
        )
        .expect("valid devnet receipt");
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);

        let rebate = LowFeeRebate::new(
            0,
            &transfer_id,
            &receipt_id,
            RebateReason::LowFeeLane,
            "uxmr",
            430,
            self.config.low_fee_target_micro_units,
            &deterministic_root("DEVNET-SPONSOR", "rebate-vault"),
            &deterministic_root("DEVNET-REBATE-NOTE", "transfer"),
            self.l2_height + 5,
        )
        .expect("valid devnet rebate");
        self.rebates.insert(rebate.rebate_id.clone(), rebate);

        self.counters.next_envelope_sequence = 3;
        self.counters.next_window_sequence = 1;
        self.counters.next_commitment_sequence = 1;
        self.counters.next_attestation_sequence = self.quorum_attestations.len() as u64;
        self.counters.next_guard_sequence = self.guards.len() as u64;
        self.counters.next_receipt_sequence = 1;
        self.counters.next_rebate_sequence = 1;
        self.counters.accepted_envelopes = self.envelopes.len() as u64;
        self.counters.included_envelopes = 1;
        self.counters.rebated_envelopes = 1;
        self.counters.total_fee_micro_units = 430;
        self.counters.total_rebate_units = 130;
    }
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-{domain}-PAYLOAD"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-{domain}-ROOT"),
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

pub fn envelope_id(
    sequence: u64,
    sender_commitment: &str,
    payload_commitment: &str,
    nullifier_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(sender_commitment),
            HashPart::Str(payload_commitment),
            HashPart::Str(nullifier_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn window_id(sequence: u64, lane_id: &str, start_height: u64, end_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(lane_id),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

pub fn sequencer_commitment_id(sequence: u64, sequencer_id: &str, window_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-SEQUENCER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(sequencer_id),
            HashPart::Str(window_id),
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
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-ATTESTATION-ID",
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

pub fn guard_id(sequence: u64, kind: GuardKind, namespace: &str, guard_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(namespace),
            HashPart::Str(guard_root),
        ],
        32,
    )
}

pub fn receipt_id(sequence: u64, envelope_id: &str, window_id: &str, ordered_index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(envelope_id),
            HashPart::Str(window_id),
            HashPart::Int(ordered_index as i128),
        ],
        32,
    )
}

pub fn rebate_id(
    sequence: u64,
    envelope_id: &str,
    receipt_id: &str,
    reason: RebateReason,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(envelope_id),
            HashPart::Str(receipt_id),
            HashPart::Str(reason.as_str()),
        ],
        32,
    )
}

pub fn lane_policy_id(label: &str, accepted_class_root: &str, max_delay_blocks: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-LANE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(accepted_class_root),
            HashPart::Int(max_delay_blocks as i128),
        ],
        32,
    )
}

pub fn audit_checkpoint_id(l2_height: u64, state_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-AUDIT-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(l2_height as i128),
            HashPart::Str(state_root),
        ],
        32,
    )
}

pub fn tx_class_root(classes: &[TransactionClass]) -> String {
    let leaves = classes
        .iter()
        .map(|class| {
            json!({
                "tx_class": class.as_str(),
                "fair_weight": class.fair_weight(),
                "low_fee_floor_bps": class.low_fee_floor_bps(),
            })
        })
        .collect::<Vec<Value>>();
    merkle_root(
        "PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-TX-CLASS-ROOT",
        &leaves,
    )
}

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn id_list_root(domain: &str, ids: &[&str]) -> String {
    let leaves = ids
        .iter()
        .map(|id| json!({ "id": id }))
        .collect::<Vec<Value>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-ENCRYPTED-MEMPOOL-FAIR-ORDER-{domain}"),
        &leaves,
    )
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn envelope_id_sequence_hint(_envelope_id: &str) -> u64 {
    0
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqEncryptedMempoolFairOrderRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
