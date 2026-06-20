use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqBridgeDisputeGameResult<T> = Result<T, String>;

pub const PQ_BRIDGE_DISPUTE_GAME_PROTOCOL_VERSION: &str = "nebula-pq-bridge-dispute-game-v1";
pub const PQ_BRIDGE_DISPUTE_GAME_SCHEMA_VERSION: u64 = 1;
pub const PQ_BRIDGE_DISPUTE_GAME_SECURITY_MODEL: &str =
    "post-quantum-commitment-records-with-devnet-placeholder-verification";
pub const PQ_BRIDGE_DISPUTE_GAME_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_BRIDGE_DISPUTE_GAME_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PQ_BRIDGE_DISPUTE_GAME_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-192f";
pub const PQ_BRIDGE_DISPUTE_GAME_COMMITMENT_SCHEME: &str =
    "lattice-and-hash-tree-evidence-commitments-v1";
pub const PQ_BRIDGE_DISPUTE_GAME_DEVNET_HEIGHT: u64 = 640;
pub const PQ_BRIDGE_DISPUTE_GAME_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PQ_BRIDGE_DISPUTE_GAME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_BRIDGE_DISPUTE_GAME_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_FAST_WINDOW_BLOCKS: u64 = 18;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_RESPONSE_WINDOW_BLOCKS: u64 = 36;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 12;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 8;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_EVIDENCE_RETENTION_BLOCKS: u64 = 4_320;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BATCH_ITEM_LIMIT: u64 = 128;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_MAX_EVIDENCE_ITEMS: u64 = 512;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_MIN_VERIFIER_WEIGHT_BPS: u64 = 6_700;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_FAST_VERIFIER_WEIGHT_BPS: u64 = 8_000;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_PRIVACY_FLOOR_BPS: u64 = 9_500;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BASE_BOND_UNITS: u64 = 250_000;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BATCH_FEE_UNITS: u64 = 15_000;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_SPONSORED_FEE_UNITS: u64 = 3_000;
pub const PQ_BRIDGE_DISPUTE_GAME_DEFAULT_SLASH_BPS: u64 = 1_000;
pub const PQ_BRIDGE_DISPUTE_GAME_MAX_BPS: u64 = 10_000;

const STATE_STATUS_BOOTSTRAPPING: &str = "bootstrapping";
const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_PAUSED: &str = "paused";
const STATE_STATUS_SETTLING: &str = "settling";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqDisputeAlgorithm {
    MlDsa87,
    SlhDsaShake192f,
    LatticeCommitment,
    HashTreeCommitment,
    HybridTranscript,
}

impl PqDisputeAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => PQ_BRIDGE_DISPUTE_GAME_PRIMARY_SIGNATURE_SCHEME,
            Self::SlhDsaShake192f => PQ_BRIDGE_DISPUTE_GAME_BACKUP_SIGNATURE_SCHEME,
            Self::LatticeCommitment => "module-lattice-evidence-commitment",
            Self::HashTreeCommitment => "hash-tree-evidence-commitment",
            Self::HybridTranscript => "hybrid-pq-transcript",
        }
    }

    pub fn quantum_resistant(self) -> bool {
        matches!(
            self,
            Self::MlDsa87
                | Self::SlhDsaShake192f
                | Self::LatticeCommitment
                | Self::HashTreeCommitment
                | Self::HybridTranscript
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeRole {
    BridgeOperator,
    Challenger,
    Watchtower,
    Verifier,
    FeeSponsor,
    PrivacyAuditor,
    SettlementGuardian,
}

impl DisputeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeOperator => "bridge_operator",
            Self::Challenger => "challenger",
            Self::Watchtower => "watchtower",
            Self::Verifier => "verifier",
            Self::FeeSponsor => "fee_sponsor",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::SettlementGuardian => "settlement_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeClaimKind {
    DepositMint,
    WithdrawalBurn,
    ReserveCheckpoint,
    ExitBatch,
    LiquidityRebalance,
    EmergencyPause,
}

impl BridgeClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositMint => "deposit_mint",
            Self::WithdrawalBurn => "withdrawal_burn",
            Self::ReserveCheckpoint => "reserve_checkpoint",
            Self::ExitBatch => "exit_batch",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeClaimStatus {
    Proposed,
    ChallengeOpen,
    Challenged,
    ResponseOpen,
    Accepted,
    Rejected,
    Settled,
    Expired,
}

impl BridgeClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::ResponseOpen => "response_open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Rejected | Self::Settled | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MoneroHeaderChain,
    OutputProof,
    KeyImageSpend,
    ReserveDelta,
    DataAvailability,
    AttestationTranscript,
    NullifierSet,
    PrivacyLeak,
    FeeReceipt,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeaderChain => "monero_header_chain",
            Self::OutputProof => "output_proof",
            Self::KeyImageSpend => "key_image_spend",
            Self::ReserveDelta => "reserve_delta",
            Self::DataAvailability => "data_availability",
            Self::AttestationTranscript => "attestation_transcript",
            Self::NullifierSet => "nullifier_set",
            Self::PrivacyLeak => "privacy_leak",
            Self::FeeReceipt => "fee_receipt",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::OutputProof | Self::KeyImageSpend | Self::NullifierSet | Self::PrivacyLeak
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidMoneroProof,
    DoubleSpend,
    WrongReserveDelta,
    MissingData,
    InvalidPqAttestation,
    PrivacyLeak,
    FeeOvercharge,
    ClaimTimeout,
    BatchEquivocation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidMoneroProof => "invalid_monero_proof",
            Self::DoubleSpend => "double_spend",
            Self::WrongReserveDelta => "wrong_reserve_delta",
            Self::MissingData => "missing_data",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::PrivacyLeak => "privacy_leak",
            Self::FeeOvercharge => "fee_overcharge",
            Self::ClaimTimeout => "claim_timeout",
            Self::BatchEquivocation => "batch_equivocation",
        }
    }

    pub fn fast_track(self) -> bool {
        matches!(
            self,
            Self::DoubleSpend | Self::MissingData | Self::PrivacyLeak | Self::BatchEquivocation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Batched,
    ResponseOpen,
    Verifying,
    Sustained,
    Dismissed,
    Expired,
    Settled,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Batched => "batched",
            Self::ResponseOpen => "response_open",
            Self::Verifying => "verifying",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
            Self::Settled => "settled",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Sustained | Self::Dismissed | Self::Expired | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Draft,
    Sealed,
    Submitted,
    Verifying,
    Resolved,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Verifying => "verifying",
            Self::Resolved => "resolved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Submitted,
    Verified,
    Rejected,
    Superseded,
    Expired,
}

impl ResponseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOutcome {
    ChallengerWins,
    DefenderWins,
    SplitFault,
    TimeoutForChallenger,
    TimeoutForDefender,
    PrivacyQuarantine,
}

impl VerdictOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChallengerWins => "challenger_wins",
            Self::DefenderWins => "defender_wins",
            Self::SplitFault => "split_fault",
            Self::TimeoutForChallenger => "timeout_for_challenger",
            Self::TimeoutForDefender => "timeout_for_defender",
            Self::PrivacyQuarantine => "privacy_quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAction {
    ReleaseClaim,
    CancelClaim,
    SlashDefender,
    SlashChallenger,
    RefundBond,
    QuarantineEvidence,
    RebateBatchFees,
}

impl SettlementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseClaim => "release_claim",
            Self::CancelClaim => "cancel_claim",
            Self::SlashDefender => "slash_defender",
            Self::SlashChallenger => "slash_challenger",
            Self::RefundBond => "refund_bond",
            Self::QuarantineEvidence => "quarantine_evidence",
            Self::RebateBatchFees => "rebate_batch_fees",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeDisputeGameConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub bridge_asset_id: String,
    pub fee_asset_id: String,
    pub security_model: String,
    pub hash_suite: String,
    pub primary_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub commitment_scheme: String,
    pub challenge_window_blocks: u64,
    pub fast_challenge_window_blocks: u64,
    pub response_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub evidence_retention_blocks: u64,
    pub batch_item_limit: u64,
    pub max_evidence_items: u64,
    pub min_verifier_weight_bps: u64,
    pub fast_verifier_weight_bps: u64,
    pub privacy_floor_bps: u64,
    pub base_bond_units: u64,
    pub batch_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub default_slash_bps: u64,
}

impl PqBridgeDisputeGameConfig {
    pub fn devnet() -> Self {
        let config_id = pq_bridge_dispute_config_id(
            PQ_BRIDGE_DISPUTE_GAME_DEVNET_MONERO_NETWORK,
            PQ_BRIDGE_DISPUTE_GAME_DEVNET_ASSET_ID,
            PQ_BRIDGE_DISPUTE_GAME_DEVNET_FEE_ASSET_ID,
        );
        Self {
            config_id,
            protocol_version: PQ_BRIDGE_DISPUTE_GAME_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_BRIDGE_DISPUTE_GAME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PQ_BRIDGE_DISPUTE_GAME_DEVNET_MONERO_NETWORK.to_string(),
            bridge_asset_id: PQ_BRIDGE_DISPUTE_GAME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: PQ_BRIDGE_DISPUTE_GAME_DEVNET_FEE_ASSET_ID.to_string(),
            security_model: PQ_BRIDGE_DISPUTE_GAME_SECURITY_MODEL.to_string(),
            hash_suite: PQ_BRIDGE_DISPUTE_GAME_HASH_SUITE.to_string(),
            primary_signature_scheme: PQ_BRIDGE_DISPUTE_GAME_PRIMARY_SIGNATURE_SCHEME.to_string(),
            backup_signature_scheme: PQ_BRIDGE_DISPUTE_GAME_BACKUP_SIGNATURE_SCHEME.to_string(),
            commitment_scheme: PQ_BRIDGE_DISPUTE_GAME_COMMITMENT_SCHEME.to_string(),
            challenge_window_blocks: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            fast_challenge_window_blocks: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_FAST_WINDOW_BLOCKS,
            response_window_blocks: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_RESPONSE_WINDOW_BLOCKS,
            batch_window_blocks: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BATCH_WINDOW_BLOCKS,
            settlement_delay_blocks: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            evidence_retention_blocks: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_EVIDENCE_RETENTION_BLOCKS,
            batch_item_limit: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BATCH_ITEM_LIMIT,
            max_evidence_items: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_MAX_EVIDENCE_ITEMS,
            min_verifier_weight_bps: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_MIN_VERIFIER_WEIGHT_BPS,
            fast_verifier_weight_bps: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_FAST_VERIFIER_WEIGHT_BPS,
            privacy_floor_bps: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_PRIVACY_FLOOR_BPS,
            base_bond_units: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BASE_BOND_UNITS,
            batch_fee_units: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_BATCH_FEE_UNITS,
            sponsored_fee_units: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_SPONSORED_FEE_UNITS,
            default_slash_bps: PQ_BRIDGE_DISPUTE_GAME_DEFAULT_SLASH_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "bridge_asset_id": self.bridge_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "security_model": self.security_model,
            "hash_suite": self.hash_suite,
            "primary_signature_scheme": self.primary_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "commitment_scheme": self.commitment_scheme,
            "challenge_window_blocks": self.challenge_window_blocks,
            "fast_challenge_window_blocks": self.fast_challenge_window_blocks,
            "response_window_blocks": self.response_window_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "evidence_retention_blocks": self.evidence_retention_blocks,
            "batch_item_limit": self.batch_item_limit,
            "max_evidence_items": self.max_evidence_items,
            "min_verifier_weight_bps": self.min_verifier_weight_bps,
            "fast_verifier_weight_bps": self.fast_verifier_weight_bps,
            "privacy_floor_bps": self.privacy_floor_bps,
            "base_bond_units": self.base_bond_units,
            "batch_fee_units": self.batch_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "default_slash_bps": self.default_slash_bps,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<()> {
        require_nonempty("config.config_id", &self.config_id)?;
        require_nonempty("config.protocol_version", &self.protocol_version)?;
        require_nonempty("config.chain_id", &self.chain_id)?;
        require_nonempty("config.monero_network", &self.monero_network)?;
        require_nonempty("config.bridge_asset_id", &self.bridge_asset_id)?;
        require_nonempty("config.fee_asset_id", &self.fee_asset_id)?;
        require_nonempty(
            "config.primary_signature_scheme",
            &self.primary_signature_scheme,
        )?;
        require_nonempty(
            "config.backup_signature_scheme",
            &self.backup_signature_scheme,
        )?;
        require_nonempty("config.commitment_scheme", &self.commitment_scheme)?;
        require_height_window(
            "config.fast_challenge_window_blocks",
            self.fast_challenge_window_blocks,
        )?;
        require_height_window(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        require_height_window("config.response_window_blocks", self.response_window_blocks)?;
        require_height_window("config.batch_window_blocks", self.batch_window_blocks)?;
        require_height_window(
            "config.settlement_delay_blocks",
            self.settlement_delay_blocks,
        )?;
        if self.fast_challenge_window_blocks > self.challenge_window_blocks {
            return Err("config fast challenge window exceeds full challenge window".to_string());
        }
        if self.batch_item_limit == 0 || self.batch_item_limit > self.max_evidence_items {
            return Err("config batch item limit is outside evidence capacity".to_string());
        }
        require_bps(
            "config.min_verifier_weight_bps",
            self.min_verifier_weight_bps,
        )?;
        require_bps(
            "config.fast_verifier_weight_bps",
            self.fast_verifier_weight_bps,
        )?;
        require_bps("config.privacy_floor_bps", self.privacy_floor_bps)?;
        require_bps("config.default_slash_bps", self.default_slash_bps)?;
        if self.min_verifier_weight_bps > self.fast_verifier_weight_bps {
            return Err("config fast verifier weight must meet baseline quorum".to_string());
        }
        require_positive("config.base_bond_units", self.base_bond_units)?;
        require_positive("config.batch_fee_units", self.batch_fee_units)?;
        require_positive("config.sponsored_fee_units", self.sponsored_fee_units)?;
        if self.sponsored_fee_units > self.batch_fee_units {
            return Err("config sponsored fee cannot exceed standard batch fee".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeParticipant {
    pub participant_id: String,
    pub role: DisputeRole,
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub bond_commitment_root: String,
    pub supported_algorithms: BTreeSet<PqDisputeAlgorithm>,
    pub verifier_weight_bps: u64,
    pub privacy_score_bps: u64,
    pub registered_at_height: u64,
    pub disabled_at_height: Option<u64>,
}

impl DisputeParticipant {
    pub fn public_record(&self) -> Value {
        json!({
            "participant_id": self.participant_id,
            "role": self.role.as_str(),
            "operator_commitment": self.operator_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "bond_commitment_root": self.bond_commitment_root,
            "supported_algorithms": self.supported_algorithms.iter().map(|algorithm| algorithm.as_str()).collect::<Vec<_>>(),
            "verifier_weight_bps": self.verifier_weight_bps,
            "privacy_score_bps": self.privacy_score_bps,
            "registered_at_height": self.registered_at_height,
            "disabled_at_height": self.disabled_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-PARTICIPANT", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("participant.participant_id", &self.participant_id)?;
        require_nonempty("participant.operator_commitment", &self.operator_commitment)?;
        require_nonempty("participant.pq_public_key_root", &self.pq_public_key_root)?;
        require_nonempty(
            "participant.bond_commitment_root",
            &self.bond_commitment_root,
        )?;
        if self.supported_algorithms.is_empty() {
            return Err("participant must advertise at least one pq algorithm".to_string());
        }
        for algorithm in &self.supported_algorithms {
            if !algorithm.quantum_resistant() {
                return Err("participant advertised a non pq algorithm".to_string());
            }
        }
        require_bps("participant.verifier_weight_bps", self.verifier_weight_bps)?;
        require_bps("participant.privacy_score_bps", self.privacy_score_bps)?;
        if let Some(disabled_at_height) = self.disabled_at_height {
            require_ordered_heights(
                "participant.registered_at_height",
                self.registered_at_height,
                "participant.disabled_at_height",
                disabled_at_height,
            )?;
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDisputedClaim {
    pub claim_id: String,
    pub claim_kind: BridgeClaimKind,
    pub status: BridgeClaimStatus,
    pub bridge_operator_id: String,
    pub monero_network: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub amount_bucket: u64,
    pub asset_id: String,
    pub recipient_commitment_root: String,
    pub monero_evidence_root: String,
    pub l2_state_transition_root: String,
    pub attestation_root: String,
    pub privacy_commitment_root: String,
    pub fee_commitment_root: String,
    pub proposed_at_height: u64,
    pub challenge_deadline_height: u64,
    pub fast_deadline_height: u64,
    pub settlement_height: u64,
}

impl BridgeDisputedClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "claim_kind": self.claim_kind.as_str(),
            "status": self.status.as_str(),
            "bridge_operator_id": self.bridge_operator_id,
            "monero_network": self.monero_network,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "amount_bucket": self.amount_bucket,
            "asset_id": self.asset_id,
            "recipient_commitment_root": self.recipient_commitment_root,
            "monero_evidence_root": self.monero_evidence_root,
            "l2_state_transition_root": self.l2_state_transition_root,
            "attestation_root": self.attestation_root,
            "privacy_commitment_root": self.privacy_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "proposed_at_height": self.proposed_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "fast_deadline_height": self.fast_deadline_height,
            "settlement_height": self.settlement_height,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-CLAIM", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("claim.claim_id", &self.claim_id)?;
        require_nonempty("claim.bridge_operator_id", &self.bridge_operator_id)?;
        require_nonempty("claim.monero_network", &self.monero_network)?;
        require_nonempty("claim.asset_id", &self.asset_id)?;
        require_nonempty(
            "claim.recipient_commitment_root",
            &self.recipient_commitment_root,
        )?;
        require_nonempty("claim.monero_evidence_root", &self.monero_evidence_root)?;
        require_nonempty(
            "claim.l2_state_transition_root",
            &self.l2_state_transition_root,
        )?;
        require_nonempty("claim.attestation_root", &self.attestation_root)?;
        require_nonempty(
            "claim.privacy_commitment_root",
            &self.privacy_commitment_root,
        )?;
        require_nonempty("claim.fee_commitment_root", &self.fee_commitment_root)?;
        require_positive("claim.amount_bucket", self.amount_bucket)?;
        require_ordered_heights(
            "claim.proposed_at_height",
            self.proposed_at_height,
            "claim.fast_deadline_height",
            self.fast_deadline_height,
        )?;
        require_ordered_heights(
            "claim.fast_deadline_height",
            self.fast_deadline_height,
            "claim.challenge_deadline_height",
            self.challenge_deadline_height,
        )?;
        require_ordered_heights(
            "claim.challenge_deadline_height",
            self.challenge_deadline_height,
            "claim.settlement_height",
            self.settlement_height,
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyEvidenceCommitment {
    pub evidence_id: String,
    pub evidence_kind: EvidenceKind,
    pub claim_id: String,
    pub submitter_id: String,
    pub sealed_payload_root: String,
    pub statement_root: String,
    pub witness_commitment_root: String,
    pub nullifier_root: String,
    pub redaction_root: String,
    pub disclosure_policy_root: String,
    pub pq_signature_root: String,
    pub size_bytes: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_score_bps: u64,
}

impl PrivacyEvidenceCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "claim_id": self.claim_id,
            "submitter_id": self.submitter_id,
            "sealed_payload_root": self.sealed_payload_root,
            "statement_root": self.statement_root,
            "witness_commitment_root": self.witness_commitment_root,
            "nullifier_root": self.nullifier_root,
            "redaction_root": self.redaction_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "pq_signature_root": self.pq_signature_root,
            "size_bytes": self.size_bytes,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_score_bps": self.privacy_score_bps,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("evidence.evidence_id", &self.evidence_id)?;
        require_nonempty("evidence.claim_id", &self.claim_id)?;
        require_nonempty("evidence.submitter_id", &self.submitter_id)?;
        require_nonempty("evidence.sealed_payload_root", &self.sealed_payload_root)?;
        require_nonempty("evidence.statement_root", &self.statement_root)?;
        require_nonempty(
            "evidence.witness_commitment_root",
            &self.witness_commitment_root,
        )?;
        require_nonempty("evidence.nullifier_root", &self.nullifier_root)?;
        require_nonempty("evidence.redaction_root", &self.redaction_root)?;
        require_nonempty(
            "evidence.disclosure_policy_root",
            &self.disclosure_policy_root,
        )?;
        require_nonempty("evidence.pq_signature_root", &self.pq_signature_root)?;
        require_positive("evidence.size_bytes", self.size_bytes)?;
        require_bps("evidence.privacy_score_bps", self.privacy_score_bps)?;
        require_ordered_heights(
            "evidence.opened_at_height",
            self.opened_at_height,
            "evidence.expires_at_height",
            self.expires_at_height,
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeChallenge {
    pub challenge_id: String,
    pub claim_id: String,
    pub challenge_kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub challenger_id: String,
    pub evidence_ids: BTreeSet<String>,
    pub evidence_root: String,
    pub disputed_claim_root: String,
    pub low_fee_batch_id: Option<String>,
    pub bond_commitment_root: String,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub verify_deadline_height: u64,
    pub bond_units: u64,
    pub batch_fee_units: u64,
}

impl BridgeChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "claim_id": self.claim_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "status": self.status.as_str(),
            "challenger_id": self.challenger_id,
            "evidence_ids": self.evidence_ids.iter().collect::<Vec<_>>(),
            "evidence_root": self.evidence_root,
            "disputed_claim_root": self.disputed_claim_root,
            "low_fee_batch_id": self.low_fee_batch_id,
            "bond_commitment_root": self.bond_commitment_root,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "verify_deadline_height": self.verify_deadline_height,
            "bond_units": self.bond_units,
            "batch_fee_units": self.batch_fee_units,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-CHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("challenge.challenge_id", &self.challenge_id)?;
        require_nonempty("challenge.claim_id", &self.claim_id)?;
        require_nonempty("challenge.challenger_id", &self.challenger_id)?;
        require_nonempty("challenge.evidence_root", &self.evidence_root)?;
        require_nonempty("challenge.disputed_claim_root", &self.disputed_claim_root)?;
        require_nonempty("challenge.bond_commitment_root", &self.bond_commitment_root)?;
        if self.evidence_ids.is_empty() {
            return Err("challenge must reference evidence".to_string());
        }
        require_ordered_heights(
            "challenge.opened_at_height",
            self.opened_at_height,
            "challenge.response_deadline_height",
            self.response_deadline_height,
        )?;
        require_ordered_heights(
            "challenge.response_deadline_height",
            self.response_deadline_height,
            "challenge.verify_deadline_height",
            self.verify_deadline_height,
        )?;
        require_positive("challenge.bond_units", self.bond_units)?;
        require_positive("challenge.batch_fee_units", self.batch_fee_units)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub sponsor_id: String,
    pub challenge_ids: BTreeSet<String>,
    pub challenge_root: String,
    pub evidence_root: String,
    pub fee_receipt_root: String,
    pub aggregator_signature_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub submitted_at_height: u64,
    pub total_fee_units: u64,
    pub amortized_fee_units: u64,
}

impl ChallengeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "sponsor_id": self.sponsor_id,
            "challenge_ids": self.challenge_ids.iter().collect::<Vec<_>>(),
            "challenge_root": self.challenge_root,
            "evidence_root": self.evidence_root,
            "fee_receipt_root": self.fee_receipt_root,
            "aggregator_signature_root": self.aggregator_signature_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "submitted_at_height": self.submitted_at_height,
            "total_fee_units": self.total_fee_units,
            "amortized_fee_units": self.amortized_fee_units,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("batch.batch_id", &self.batch_id)?;
        require_nonempty("batch.sponsor_id", &self.sponsor_id)?;
        require_nonempty("batch.challenge_root", &self.challenge_root)?;
        require_nonempty("batch.evidence_root", &self.evidence_root)?;
        require_nonempty("batch.fee_receipt_root", &self.fee_receipt_root)?;
        require_nonempty(
            "batch.aggregator_signature_root",
            &self.aggregator_signature_root,
        )?;
        if self.challenge_ids.is_empty() {
            return Err("batch must include at least one challenge".to_string());
        }
        require_ordered_heights(
            "batch.opened_at_height",
            self.opened_at_height,
            "batch.sealed_at_height",
            self.sealed_at_height,
        )?;
        require_ordered_heights(
            "batch.sealed_at_height",
            self.sealed_at_height,
            "batch.submitted_at_height",
            self.submitted_at_height,
        )?;
        require_positive("batch.total_fee_units", self.total_fee_units)?;
        require_positive("batch.amortized_fee_units", self.amortized_fee_units)?;
        if self.amortized_fee_units > self.total_fee_units {
            return Err("batch amortized fee exceeds total fee".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub response_id: String,
    pub challenge_id: String,
    pub responder_id: String,
    pub status: ResponseStatus,
    pub response_evidence_root: String,
    pub counter_statement_root: String,
    pub pq_signature_root: String,
    pub verifier_hint_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl ChallengeResponse {
    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "challenge_id": self.challenge_id,
            "responder_id": self.responder_id,
            "status": self.status.as_str(),
            "response_evidence_root": self.response_evidence_root,
            "counter_statement_root": self.counter_statement_root,
            "pq_signature_root": self.pq_signature_root,
            "verifier_hint_root": self.verifier_hint_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-RESPONSE", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("response.response_id", &self.response_id)?;
        require_nonempty("response.challenge_id", &self.challenge_id)?;
        require_nonempty("response.responder_id", &self.responder_id)?;
        require_nonempty(
            "response.response_evidence_root",
            &self.response_evidence_root,
        )?;
        require_nonempty(
            "response.counter_statement_root",
            &self.counter_statement_root,
        )?;
        require_nonempty("response.pq_signature_root", &self.pq_signature_root)?;
        require_nonempty("response.verifier_hint_root", &self.verifier_hint_root)?;
        require_ordered_heights(
            "response.submitted_at_height",
            self.submitted_at_height,
            "response.expires_at_height",
            self.expires_at_height,
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeVerdict {
    pub verdict_id: String,
    pub challenge_id: String,
    pub batch_id: Option<String>,
    pub outcome: VerdictOutcome,
    pub verifier_ids: BTreeSet<String>,
    pub verifier_weight_bps: u64,
    pub verdict_statement_root: String,
    pub transcript_root: String,
    pub settlement_actions: BTreeSet<SettlementAction>,
    pub settlement_root: String,
    pub decided_at_height: u64,
    pub executable_at_height: u64,
}

impl DisputeVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "outcome": self.outcome.as_str(),
            "verifier_ids": self.verifier_ids.iter().collect::<Vec<_>>(),
            "verifier_weight_bps": self.verifier_weight_bps,
            "verdict_statement_root": self.verdict_statement_root,
            "transcript_root": self.transcript_root,
            "settlement_actions": self.settlement_actions.iter().map(|action| action.as_str()).collect::<Vec<_>>(),
            "settlement_root": self.settlement_root,
            "decided_at_height": self.decided_at_height,
            "executable_at_height": self.executable_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-VERDICT", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("verdict.verdict_id", &self.verdict_id)?;
        require_nonempty("verdict.challenge_id", &self.challenge_id)?;
        require_nonempty(
            "verdict.verdict_statement_root",
            &self.verdict_statement_root,
        )?;
        require_nonempty("verdict.transcript_root", &self.transcript_root)?;
        require_nonempty("verdict.settlement_root", &self.settlement_root)?;
        if self.verifier_ids.is_empty() {
            return Err("verdict must reference verifiers".to_string());
        }
        if self.settlement_actions.is_empty() {
            return Err("verdict must define settlement actions".to_string());
        }
        require_bps("verdict.verifier_weight_bps", self.verifier_weight_bps)?;
        require_ordered_heights(
            "verdict.decided_at_height",
            self.decided_at_height,
            "verdict.executable_at_height",
            self.executable_at_height,
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeChallengeSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_commitment_root: String,
    pub rebate_policy_root: String,
    pub max_batch_fee_units: u64,
    pub max_rebate_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

impl LowFeeChallengeSponsor {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "budget_commitment_root": self.budget_commitment_root,
            "rebate_policy_root": self.rebate_policy_root,
            "max_batch_fee_units": self.max_batch_fee_units,
            "max_rebate_units": self.max_rebate_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-SPONSOR", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("sponsor.sponsor_id", &self.sponsor_id)?;
        require_nonempty("sponsor.sponsor_commitment", &self.sponsor_commitment)?;
        require_nonempty("sponsor.fee_asset_id", &self.fee_asset_id)?;
        require_nonempty(
            "sponsor.budget_commitment_root",
            &self.budget_commitment_root,
        )?;
        require_nonempty("sponsor.rebate_policy_root", &self.rebate_policy_root)?;
        require_positive("sponsor.max_batch_fee_units", self.max_batch_fee_units)?;
        require_positive("sponsor.max_rebate_units", self.max_rebate_units)?;
        require_ordered_heights(
            "sponsor.opened_at_height",
            self.opened_at_height,
            "sponsor.expires_at_height",
            self.expires_at_height,
        )?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputePublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub redacted_payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl DisputePublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "redacted_payload_root": self.redacted_payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
            "chain_id": CHAIN_ID,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-PUBLIC-EVENT", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        require_nonempty("event.event_id", &self.event_id)?;
        require_nonempty("event.event_kind", &self.event_kind)?;
        require_nonempty("event.subject_id", &self.subject_id)?;
        require_nonempty("event.subject_root", &self.subject_root)?;
        require_nonempty("event.redacted_payload_root", &self.redacted_payload_root)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeDisputeGameRoots {
    pub config_root: String,
    pub participant_root: String,
    pub claim_root: String,
    pub evidence_root: String,
    pub challenge_root: String,
    pub batch_root: String,
    pub response_root: String,
    pub verdict_root: String,
    pub sponsor_root: String,
    pub public_event_root: String,
}

impl PqBridgeDisputeGameRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "participant_root": self.participant_root,
            "claim_root": self.claim_root,
            "evidence_root": self.evidence_root,
            "challenge_root": self.challenge_root,
            "batch_root": self.batch_root,
            "response_root": self.response_root,
            "verdict_root": self.verdict_root,
            "sponsor_root": self.sponsor_root,
            "public_event_root": self.public_event_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeDisputeGameCounters {
    pub participant_count: u64,
    pub active_participant_count: u64,
    pub claim_count: u64,
    pub open_claim_count: u64,
    pub evidence_count: u64,
    pub privacy_sensitive_evidence_count: u64,
    pub challenge_count: u64,
    pub open_challenge_count: u64,
    pub fast_track_challenge_count: u64,
    pub batch_count: u64,
    pub response_count: u64,
    pub verdict_count: u64,
    pub sponsor_count: u64,
    pub active_sponsor_count: u64,
    pub public_event_count: u64,
    pub total_bond_units: u64,
    pub total_batch_fee_units: u64,
}

impl PqBridgeDisputeGameCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "participant_count": self.participant_count,
            "active_participant_count": self.active_participant_count,
            "claim_count": self.claim_count,
            "open_claim_count": self.open_claim_count,
            "evidence_count": self.evidence_count,
            "privacy_sensitive_evidence_count": self.privacy_sensitive_evidence_count,
            "challenge_count": self.challenge_count,
            "open_challenge_count": self.open_challenge_count,
            "fast_track_challenge_count": self.fast_track_challenge_count,
            "batch_count": self.batch_count,
            "response_count": self.response_count,
            "verdict_count": self.verdict_count,
            "sponsor_count": self.sponsor_count,
            "active_sponsor_count": self.active_sponsor_count,
            "public_event_count": self.public_event_count,
            "total_bond_units": self.total_bond_units,
            "total_batch_fee_units": self.total_batch_fee_units,
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root("PQ-BRIDGE-DISPUTE-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeDisputeGameState {
    pub config: PqBridgeDisputeGameConfig,
    pub height: u64,
    pub status: String,
    pub active_batch_id: Option<String>,
    pub participants: BTreeMap<String, DisputeParticipant>,
    pub claims: BTreeMap<String, BridgeDisputedClaim>,
    pub evidence: BTreeMap<String, PrivacyEvidenceCommitment>,
    pub challenges: BTreeMap<String, BridgeChallenge>,
    pub batches: BTreeMap<String, ChallengeBatch>,
    pub responses: BTreeMap<String, ChallengeResponse>,
    pub verdicts: BTreeMap<String, DisputeVerdict>,
    pub sponsors: BTreeMap<String, LowFeeChallengeSponsor>,
    pub public_events: BTreeMap<String, DisputePublicEvent>,
}

impl PqBridgeDisputeGameState {
    pub fn new(config: PqBridgeDisputeGameConfig, height: u64) -> Self {
        Self {
            config,
            height,
            status: STATE_STATUS_BOOTSTRAPPING.to_string(),
            active_batch_id: None,
            participants: BTreeMap::new(),
            claims: BTreeMap::new(),
            evidence: BTreeMap::new(),
            challenges: BTreeMap::new(),
            batches: BTreeMap::new(),
            responses: BTreeMap::new(),
            verdicts: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            public_events: BTreeMap::new(),
        }
    }

    pub fn devnet(operator_label: &str) -> PqBridgeDisputeGameResult<Self> {
        let mut state = Self::new(
            PqBridgeDisputeGameConfig::devnet(),
            PQ_BRIDGE_DISPUTE_GAME_DEVNET_HEIGHT,
        );
        state.status = STATE_STATUS_ACTIVE.to_string();

        let operator_commitment = pq_bridge_dispute_string_commitment(
            "PQ-BRIDGE-DISPUTE-DEVNET-OPERATOR",
            operator_label,
        );
        let challenger_commitment =
            pq_bridge_dispute_string_commitment("PQ-BRIDGE-DISPUTE-DEVNET-CHALLENGER", "alice");
        let verifier_commitment =
            pq_bridge_dispute_string_commitment("PQ-BRIDGE-DISPUTE-DEVNET-VERIFIER", "verifier-a");
        let sponsor_commitment =
            pq_bridge_dispute_string_commitment("PQ-BRIDGE-DISPUTE-DEVNET-SPONSOR", "sponsor-a");

        let bridge_operator = devnet_participant(
            operator_label,
            DisputeRole::BridgeOperator,
            &operator_commitment,
            0,
            state.height,
        );
        let challenger = devnet_participant(
            "alice",
            DisputeRole::Challenger,
            &challenger_commitment,
            0,
            state.height,
        );
        let verifier = devnet_participant(
            "verifier-a",
            DisputeRole::Verifier,
            &verifier_commitment,
            8_000,
            state.height,
        );

        state.participants.insert(
            bridge_operator.participant_id.clone(),
            bridge_operator.clone(),
        );
        state
            .participants
            .insert(challenger.participant_id.clone(), challenger.clone());
        state
            .participants
            .insert(verifier.participant_id.clone(), verifier.clone());

        let sponsor_id = pq_bridge_dispute_sponsor_id(
            &sponsor_commitment,
            PQ_BRIDGE_DISPUTE_GAME_DEVNET_FEE_ASSET_ID,
            state.height,
        );
        let sponsor = LowFeeChallengeSponsor {
            sponsor_id: sponsor_id.clone(),
            sponsor_commitment: sponsor_commitment.clone(),
            fee_asset_id: PQ_BRIDGE_DISPUTE_GAME_DEVNET_FEE_ASSET_ID.to_string(),
            budget_commitment_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-SPONSOR-BUDGET",
                "sponsor-budget-1000",
            ),
            rebate_policy_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-REBATE-POLICY",
                "low-fee-batched-challenges",
            ),
            max_batch_fee_units: state.config.batch_fee_units,
            max_rebate_units: state
                .config
                .batch_fee_units
                .saturating_sub(state.config.sponsored_fee_units),
            opened_at_height: state.height,
            expires_at_height: state
                .height
                .saturating_add(state.config.evidence_retention_blocks),
            active: true,
        };
        state.sponsors.insert(sponsor_id.clone(), sponsor.clone());

        let claim_id = pq_bridge_dispute_claim_id(
            BridgeClaimKind::WithdrawalBurn,
            &bridge_operator.participant_id,
            state.height,
            "devnet-withdrawal-42",
        );
        let claim = BridgeDisputedClaim {
            claim_id: claim_id.clone(),
            claim_kind: BridgeClaimKind::WithdrawalBurn,
            status: BridgeClaimStatus::ChallengeOpen,
            bridge_operator_id: bridge_operator.participant_id.clone(),
            monero_network: state.config.monero_network.clone(),
            monero_height: 1_280,
            l2_height: state.height,
            amount_bucket: 50_000_000_000,
            asset_id: state.config.bridge_asset_id.clone(),
            recipient_commitment_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-RECIPIENT",
                "recipient-output-redacted",
            ),
            monero_evidence_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-MONERO-EVIDENCE",
                "monero-output-proof-redacted",
            ),
            l2_state_transition_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-L2-TRANSITION",
                "burn-nullifier-redacted",
            ),
            attestation_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-ATTESTATION",
                "pq-attestation-transcript",
            ),
            privacy_commitment_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-PRIVACY",
                "redaction-policy",
            ),
            fee_commitment_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-FEE",
                "fee-bucket-1",
            ),
            proposed_at_height: state.height,
            fast_deadline_height: state
                .height
                .saturating_add(state.config.fast_challenge_window_blocks),
            challenge_deadline_height: state
                .height
                .saturating_add(state.config.challenge_window_blocks),
            settlement_height: state
                .height
                .saturating_add(state.config.challenge_window_blocks)
                .saturating_add(state.config.settlement_delay_blocks),
        };
        state.claims.insert(claim_id.clone(), claim.clone());

        let evidence_id = pq_bridge_dispute_evidence_id(
            EvidenceKind::KeyImageSpend,
            &claim_id,
            &challenger.participant_id,
            "devnet-key-image-commitment",
        );
        let evidence = PrivacyEvidenceCommitment {
            evidence_id: evidence_id.clone(),
            evidence_kind: EvidenceKind::KeyImageSpend,
            claim_id: claim_id.clone(),
            submitter_id: challenger.participant_id.clone(),
            sealed_payload_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-SEALED-PAYLOAD",
                "sealed-key-image-witness",
            ),
            statement_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-STATEMENT",
                "key-image-conflicts-with-withdrawal",
            ),
            witness_commitment_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-WITNESS",
                "lattice-witness-commitment",
            ),
            nullifier_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-NULLIFIER",
                "nullifier-redacted",
            ),
            redaction_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-REDACTION",
                "redaction-map-v1",
            ),
            disclosure_policy_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-DISCLOSURE",
                "verifier-only-view",
            ),
            pq_signature_root: pq_bridge_dispute_signature_root(
                &challenger.participant_id,
                "devnet-evidence-transcript",
                PQ_BRIDGE_DISPUTE_GAME_PRIMARY_SIGNATURE_SCHEME,
            ),
            size_bytes: 2_048,
            opened_at_height: state.height,
            expires_at_height: state
                .height
                .saturating_add(state.config.evidence_retention_blocks),
            privacy_score_bps: 9_800,
        };
        state.evidence.insert(evidence_id.clone(), evidence.clone());

        let evidence_root = pq_bridge_dispute_ids_root(
            "PQ-BRIDGE-DISPUTE-DEVNET-EVIDENCE-IDS",
            &BTreeSet::from([evidence_id.clone()]),
        );
        let challenge_id = pq_bridge_dispute_challenge_id(
            &claim_id,
            ChallengeKind::DoubleSpend,
            &challenger.participant_id,
            &evidence_root,
        );
        let challenge = BridgeChallenge {
            challenge_id: challenge_id.clone(),
            claim_id: claim_id.clone(),
            challenge_kind: ChallengeKind::DoubleSpend,
            status: ChallengeStatus::Batched,
            challenger_id: challenger.participant_id.clone(),
            evidence_ids: BTreeSet::from([evidence_id.clone()]),
            evidence_root: evidence_root.clone(),
            disputed_claim_root: claim.state_root(),
            low_fee_batch_id: None,
            bond_commitment_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-BOND",
                "challenger-bond",
            ),
            opened_at_height: state.height,
            response_deadline_height: state
                .height
                .saturating_add(state.config.fast_challenge_window_blocks),
            verify_deadline_height: state
                .height
                .saturating_add(state.config.response_window_blocks),
            bond_units: state.config.base_bond_units,
            batch_fee_units: state.config.sponsored_fee_units,
        };
        state
            .challenges
            .insert(challenge_id.clone(), challenge.clone());

        let batch_id =
            pq_bridge_dispute_batch_id(&sponsor_id, state.height, &challenge.evidence_root);
        let batch = ChallengeBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Submitted,
            sponsor_id,
            challenge_ids: BTreeSet::from([challenge_id.clone()]),
            challenge_root: pq_bridge_dispute_ids_root(
                "PQ-BRIDGE-DISPUTE-DEVNET-CHALLENGE-IDS",
                &BTreeSet::from([challenge_id.clone()]),
            ),
            evidence_root,
            fee_receipt_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-FEE-RECEIPT",
                "sponsored-batch-fee",
            ),
            aggregator_signature_root: pq_bridge_dispute_signature_root(
                &sponsor.sponsor_id,
                "devnet-batch-transcript",
                PQ_BRIDGE_DISPUTE_GAME_PRIMARY_SIGNATURE_SCHEME,
            ),
            opened_at_height: state.height,
            sealed_at_height: state.height.saturating_add(1),
            submitted_at_height: state.height.saturating_add(2),
            total_fee_units: state.config.sponsored_fee_units,
            amortized_fee_units: state.config.sponsored_fee_units,
        };
        state.active_batch_id = Some(batch_id.clone());
        state.batches.insert(batch_id.clone(), batch.clone());

        if let Some(stored_challenge) = state.challenges.get_mut(&challenge_id) {
            stored_challenge.low_fee_batch_id = Some(batch_id.clone());
        }

        let response_id = pq_bridge_dispute_response_id(
            &challenge_id,
            &bridge_operator.participant_id,
            "devnet-response-statement",
        );
        let response = ChallengeResponse {
            response_id: response_id.clone(),
            challenge_id: challenge_id.clone(),
            responder_id: bridge_operator.participant_id.clone(),
            status: ResponseStatus::Submitted,
            response_evidence_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-RESPONSE-EVIDENCE",
                "defender-counter-proof",
            ),
            counter_statement_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-COUNTER-STATEMENT",
                "operator-counter-statement",
            ),
            pq_signature_root: pq_bridge_dispute_signature_root(
                &bridge_operator.participant_id,
                "devnet-response-transcript",
                PQ_BRIDGE_DISPUTE_GAME_PRIMARY_SIGNATURE_SCHEME,
            ),
            verifier_hint_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-VERIFIER-HINT",
                "hint-root-redacted",
            ),
            submitted_at_height: state.height.saturating_add(3),
            expires_at_height: state
                .height
                .saturating_add(state.config.response_window_blocks),
        };
        state.responses.insert(response_id, response);

        let verdict_id = pq_bridge_dispute_verdict_id(
            &challenge_id,
            VerdictOutcome::ChallengerWins,
            state.height.saturating_add(6),
        );
        let verdict = DisputeVerdict {
            verdict_id: verdict_id.clone(),
            challenge_id: challenge_id.clone(),
            batch_id: Some(batch_id),
            outcome: VerdictOutcome::ChallengerWins,
            verifier_ids: BTreeSet::from([verifier.participant_id.clone()]),
            verifier_weight_bps: verifier.verifier_weight_bps,
            verdict_statement_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-VERDICT",
                "challenge-sustained",
            ),
            transcript_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-TRANSCRIPT",
                "verifier-transcript",
            ),
            settlement_actions: BTreeSet::from([
                SettlementAction::CancelClaim,
                SettlementAction::SlashDefender,
                SettlementAction::RebateBatchFees,
            ]),
            settlement_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-SETTLEMENT",
                "settlement-actions-redacted",
            ),
            decided_at_height: state.height.saturating_add(6),
            executable_at_height: state
                .height
                .saturating_add(6)
                .saturating_add(state.config.settlement_delay_blocks),
        };
        state.verdicts.insert(verdict_id.clone(), verdict.clone());

        let event = DisputePublicEvent {
            event_id: pq_bridge_dispute_event_id("verdict", &challenge_id, state.height, 0),
            event_kind: "verdict".to_string(),
            subject_id: challenge_id,
            subject_root: verdict.state_root(),
            redacted_payload_root: pq_bridge_dispute_string_commitment(
                "PQ-BRIDGE-DISPUTE-DEVNET-EVENT-PAYLOAD",
                "redacted-verdict-payload",
            ),
            emitted_at_height: state.height.saturating_add(6),
            sequence: 0,
        };
        state.public_events.insert(event.event_id.clone(), event);

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn roots(&self) -> PqBridgeDisputeGameRoots {
        PqBridgeDisputeGameRoots {
            config_root: self.config.state_root(),
            participant_root: map_root(
                "PQ-BRIDGE-DISPUTE-PARTICIPANTS",
                self.participants
                    .values()
                    .map(DisputeParticipant::public_record)
                    .collect(),
            ),
            claim_root: map_root(
                "PQ-BRIDGE-DISPUTE-CLAIMS",
                self.claims
                    .values()
                    .map(BridgeDisputedClaim::public_record)
                    .collect(),
            ),
            evidence_root: map_root(
                "PQ-BRIDGE-DISPUTE-EVIDENCE",
                self.evidence
                    .values()
                    .map(PrivacyEvidenceCommitment::public_record)
                    .collect(),
            ),
            challenge_root: map_root(
                "PQ-BRIDGE-DISPUTE-CHALLENGES",
                self.challenges
                    .values()
                    .map(BridgeChallenge::public_record)
                    .collect(),
            ),
            batch_root: map_root(
                "PQ-BRIDGE-DISPUTE-BATCHES",
                self.batches
                    .values()
                    .map(ChallengeBatch::public_record)
                    .collect(),
            ),
            response_root: map_root(
                "PQ-BRIDGE-DISPUTE-RESPONSES",
                self.responses
                    .values()
                    .map(ChallengeResponse::public_record)
                    .collect(),
            ),
            verdict_root: map_root(
                "PQ-BRIDGE-DISPUTE-VERDICTS",
                self.verdicts
                    .values()
                    .map(DisputeVerdict::public_record)
                    .collect(),
            ),
            sponsor_root: map_root(
                "PQ-BRIDGE-DISPUTE-SPONSORS",
                self.sponsors
                    .values()
                    .map(LowFeeChallengeSponsor::public_record)
                    .collect(),
            ),
            public_event_root: map_root(
                "PQ-BRIDGE-DISPUTE-PUBLIC-EVENTS",
                self.public_events
                    .values()
                    .map(DisputePublicEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PqBridgeDisputeGameCounters {
        let active_participant_count = self
            .participants
            .values()
            .filter(|participant| participant.disabled_at_height.is_none())
            .count() as u64;
        let open_claim_count = self
            .claims
            .values()
            .filter(|claim| !claim.status.terminal())
            .count() as u64;
        let privacy_sensitive_evidence_count = self
            .evidence
            .values()
            .filter(|evidence| evidence.evidence_kind.privacy_sensitive())
            .count() as u64;
        let open_challenge_count = self
            .challenges
            .values()
            .filter(|challenge| !challenge.status.terminal())
            .count() as u64;
        let fast_track_challenge_count = self
            .challenges
            .values()
            .filter(|challenge| challenge.challenge_kind.fast_track())
            .count() as u64;
        let active_sponsor_count = self
            .sponsors
            .values()
            .filter(|sponsor| sponsor.active && sponsor.expires_at_height >= self.height)
            .count() as u64;
        let total_bond_units = self.challenges.values().fold(0_u64, |total, challenge| {
            total.saturating_add(challenge.bond_units)
        });
        let total_batch_fee_units = self.batches.values().fold(0_u64, |total, batch| {
            total.saturating_add(batch.total_fee_units)
        });

        PqBridgeDisputeGameCounters {
            participant_count: self.participants.len() as u64,
            active_participant_count,
            claim_count: self.claims.len() as u64,
            open_claim_count,
            evidence_count: self.evidence.len() as u64,
            privacy_sensitive_evidence_count,
            challenge_count: self.challenges.len() as u64,
            open_challenge_count,
            fast_track_challenge_count,
            batch_count: self.batches.len() as u64,
            response_count: self.responses.len() as u64,
            verdict_count: self.verdicts.len() as u64,
            sponsor_count: self.sponsors.len() as u64,
            active_sponsor_count,
            public_event_count: self.public_events.len() as u64,
            total_bond_units,
            total_batch_fee_units,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "status": self.status,
            "active_batch_id": self.active_batch_id,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_bridge_dispute_payload_root(
            "PQ-BRIDGE-DISPUTE-STATE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let root = self.state_root();
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(root));
        }
        record
    }

    pub fn validate(&self) -> PqBridgeDisputeGameResult<String> {
        self.config.validate()?;
        require_state_status("state.status", &self.status)?;
        if let Some(batch_id) = &self.active_batch_id {
            require_map_key("state.active_batch_id", batch_id, &self.batches)?;
        }
        for (participant_id, participant) in &self.participants {
            if participant_id != &participant.participant_id {
                return Err("participant map key does not match participant id".to_string());
            }
            participant.validate()?;
        }
        for (claim_id, claim) in &self.claims {
            if claim_id != &claim.claim_id {
                return Err("claim map key does not match claim id".to_string());
            }
            claim.validate()?;
            require_map_key(
                "claim.bridge_operator_id",
                &claim.bridge_operator_id,
                &self.participants,
            )?;
        }
        for (evidence_id, evidence) in &self.evidence {
            if evidence_id != &evidence.evidence_id {
                return Err("evidence map key does not match evidence id".to_string());
            }
            evidence.validate()?;
            require_map_key("evidence.claim_id", &evidence.claim_id, &self.claims)?;
            require_map_key(
                "evidence.submitter_id",
                &evidence.submitter_id,
                &self.participants,
            )?;
            if evidence.privacy_score_bps < self.config.privacy_floor_bps {
                return Err("evidence privacy score falls below configured floor".to_string());
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            if challenge_id != &challenge.challenge_id {
                return Err("challenge map key does not match challenge id".to_string());
            }
            challenge.validate()?;
            require_map_key("challenge.claim_id", &challenge.claim_id, &self.claims)?;
            require_map_key(
                "challenge.challenger_id",
                &challenge.challenger_id,
                &self.participants,
            )?;
            if challenge.bond_units < self.config.base_bond_units {
                return Err("challenge bond is below configured base bond".to_string());
            }
            for evidence_id in &challenge.evidence_ids {
                require_map_key("challenge.evidence_id", evidence_id, &self.evidence)?;
            }
            if let Some(batch_id) = &challenge.low_fee_batch_id {
                require_map_key("challenge.low_fee_batch_id", batch_id, &self.batches)?;
            }
        }
        for (batch_id, batch) in &self.batches {
            if batch_id != &batch.batch_id {
                return Err("batch map key does not match batch id".to_string());
            }
            batch.validate()?;
            require_map_key("batch.sponsor_id", &batch.sponsor_id, &self.sponsors)?;
            if batch.challenge_ids.len() as u64 > self.config.batch_item_limit {
                return Err("batch challenge count exceeds configured item limit".to_string());
            }
            for challenge_id in &batch.challenge_ids {
                require_map_key("batch.challenge_id", challenge_id, &self.challenges)?;
            }
        }
        for (response_id, response) in &self.responses {
            if response_id != &response.response_id {
                return Err("response map key does not match response id".to_string());
            }
            response.validate()?;
            require_map_key(
                "response.challenge_id",
                &response.challenge_id,
                &self.challenges,
            )?;
            require_map_key(
                "response.responder_id",
                &response.responder_id,
                &self.participants,
            )?;
        }
        for (verdict_id, verdict) in &self.verdicts {
            if verdict_id != &verdict.verdict_id {
                return Err("verdict map key does not match verdict id".to_string());
            }
            verdict.validate()?;
            require_map_key(
                "verdict.challenge_id",
                &verdict.challenge_id,
                &self.challenges,
            )?;
            if verdict.verifier_weight_bps < self.config.min_verifier_weight_bps {
                return Err("verdict verifier weight is below quorum".to_string());
            }
            for verifier_id in &verdict.verifier_ids {
                require_map_key("verdict.verifier_id", verifier_id, &self.participants)?;
            }
            if let Some(batch_id) = &verdict.batch_id {
                require_map_key("verdict.batch_id", batch_id, &self.batches)?;
            }
        }
        for (sponsor_id, sponsor) in &self.sponsors {
            if sponsor_id != &sponsor.sponsor_id {
                return Err("sponsor map key does not match sponsor id".to_string());
            }
            sponsor.validate()?;
        }
        for (event_id, event) in &self.public_events {
            if event_id != &event.event_id {
                return Err("event map key does not match event id".to_string());
            }
            event.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn pq_bridge_dispute_config_id(
    monero_network: &str,
    bridge_asset_id: &str,
    fee_asset_id: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(monero_network),
            HashPart::Str(bridge_asset_id),
            HashPart::Str(fee_asset_id),
            HashPart::Str(PQ_BRIDGE_DISPUTE_GAME_PROTOCOL_VERSION),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_participant_id(
    role: DisputeRole,
    operator_commitment: &str,
    pq_public_key_root: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-PARTICIPANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_public_key_root),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_claim_id(
    claim_kind: BridgeClaimKind,
    bridge_operator_id: &str,
    l2_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_kind.as_str()),
            HashPart::Str(bridge_operator_id),
            HashPart::Int(l2_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_evidence_id(
    evidence_kind: EvidenceKind,
    claim_id: &str,
    submitter_id: &str,
    sealed_payload_root: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(claim_id),
            HashPart::Str(submitter_id),
            HashPart::Str(sealed_payload_root),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_challenge_id(
    claim_id: &str,
    challenge_kind: ChallengeKind,
    challenger_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_id),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(challenger_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_batch_id(
    sponsor_id: &str,
    opened_at_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_response_id(
    challenge_id: &str,
    responder_id: &str,
    counter_statement_root: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(responder_id),
            HashPart::Str(counter_statement_root),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_verdict_id(
    challenge_id: &str,
    outcome: VerdictOutcome,
    decided_at_height: u64,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-VERDICT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(outcome.as_str()),
            HashPart::Int(decided_at_height as i128),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_sponsor_id(
    sponsor_commitment: &str,
    fee_asset_id: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_event_id(
    event_kind: &str,
    subject_id: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_BRIDGE_DISPUTE_GAME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_ids_root(domain: &str, ids: &BTreeSet<String>) -> String {
    let leaves = ids.iter().map(|id| json!(id)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn pq_bridge_dispute_string_commitment(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_BRIDGE_DISPUTE_GAME_COMMITMENT_SCHEME),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn pq_bridge_dispute_signature_root(
    signer_id: &str,
    transcript_root: &str,
    scheme: &str,
) -> String {
    domain_hash(
        "PQ-BRIDGE-DISPUTE-SIGNATURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_id),
            HashPart::Str(transcript_root),
            HashPart::Str(scheme),
        ],
        32,
    )
}

fn devnet_participant(
    label: &str,
    role: DisputeRole,
    operator_commitment: &str,
    verifier_weight_bps: u64,
    height: u64,
) -> DisputeParticipant {
    let pq_public_key_root =
        pq_bridge_dispute_string_commitment("PQ-BRIDGE-DISPUTE-DEVNET-PUBLIC-KEY", label);
    let participant_id =
        pq_bridge_dispute_participant_id(role, operator_commitment, &pq_public_key_root);
    DisputeParticipant {
        participant_id,
        role,
        operator_commitment: operator_commitment.to_string(),
        pq_public_key_root,
        bond_commitment_root: pq_bridge_dispute_string_commitment(
            "PQ-BRIDGE-DISPUTE-DEVNET-PARTICIPANT-BOND",
            label,
        ),
        supported_algorithms: BTreeSet::from([
            PqDisputeAlgorithm::MlDsa87,
            PqDisputeAlgorithm::SlhDsaShake192f,
            PqDisputeAlgorithm::HybridTranscript,
        ]),
        verifier_weight_bps,
        privacy_score_bps: 9_900,
        registered_at_height: height,
        disabled_at_height: None,
    }
}

fn map_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn require_nonempty(field: &str, value: &str) -> PqBridgeDisputeGameResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    Ok(())
}

fn require_positive(field: &str, value: u64) -> PqBridgeDisputeGameResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn require_height_window(field: &str, value: u64) -> PqBridgeDisputeGameResult<()> {
    if value == 0 {
        return Err(format!("{field} must be at least one block"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> PqBridgeDisputeGameResult<()> {
    if value == 0 || value > PQ_BRIDGE_DISPUTE_GAME_MAX_BPS {
        return Err(format!("{field} must be within 1..=10000 bps"));
    }
    Ok(())
}

fn require_ordered_heights(
    left_field: &str,
    left: u64,
    right_field: &str,
    right: u64,
) -> PqBridgeDisputeGameResult<()> {
    if left > right {
        return Err(format!(
            "{left_field} must be less than or equal to {right_field}"
        ));
    }
    Ok(())
}

fn require_state_status(field: &str, value: &str) -> PqBridgeDisputeGameResult<()> {
    match value {
        STATE_STATUS_BOOTSTRAPPING
        | STATE_STATUS_ACTIVE
        | STATE_STATUS_PAUSED
        | STATE_STATUS_SETTLING
        | STATE_STATUS_HALTED => Ok(()),
        _ => Err(format!("{field} is not a supported dispute game state")),
    }
}

fn require_map_key<T>(
    field: &str,
    key: &str,
    map: &BTreeMap<String, T>,
) -> PqBridgeDisputeGameResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{field} references an unknown id"));
    }
    Ok(())
}
