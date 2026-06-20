use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type MoneroPrivateExitBatchDisputeArbitratorResult<T> = Result<T, String>;

pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_PROTOCOL_VERSION: &str =
    "nebula-monero-private-exit-batch-dispute-arbitrator-v1";
pub const PROTOCOL_VERSION: &str = MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_PROTOCOL_VERSION;

fn stable_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_SCHEMA_VERSION: u64 = 1;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_HEIGHT: u64 = 1_184;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_CHALLENGER_CREDENTIAL_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-private-challenger-credential-v1";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_SEALED_CLAIM_SCHEME: &str =
    "ML-KEM-1024+Monero-view-tag-sealed-exit-claim-v1";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_VIEW_KEY_AUDIT_SCHEME: &str =
    "selective-disclosure-view-key-audit-commitment-v1";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_EVIDENCE_QUEUE_SCHEME: &str =
    "privacy-preserving-priority-evidence-queue-v1";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_SLASHING_RECEIPT_SCHEME: &str =
    "bond-slashing-receipt-with-pq-arbitrator-attestation-v1";
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_REORG_GRACE_BLOCKS: u64 = 24;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_HEADER_FINALITY_DEPTH: u64 = 60;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_RESPONSE_WINDOW_BLOCKS: u64 = 36;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_ARBITRATION_ROUND_BLOCKS: u64 = 18;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MAX_ARBITRATION_ROUNDS: u64 = 5;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_EVIDENCE_RETENTION_BLOCKS: u64 =
    4_320;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MIN_CHALLENGER_BOND_PICONERO: u64 =
    25_000_000_000;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MIN_LP_BOND_PICONERO: u64 =
    250_000_000_000;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MAX_ARBITRATION_FEE_PICONERO: u64 =
    8_000_000_000;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_SLASH_BPS: u64 = 1_500;
pub const MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Pending | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Sealed,
    ChallengeOpen,
    Challenged,
    ResponseOpen,
    ArbitrationQueued,
    Arbitrating,
    Sustained,
    Dismissed,
    Settled,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::ResponseOpen => "response_open",
            Self::ArbitrationQueued => "arbitration_queued",
            Self::Arbitrating => "arbitrating",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Sustained | Self::Dismissed | Self::Settled | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidHeader,
    ReorgConflict,
    DuplicateKeyImage,
    MissingPayout,
    WrongFee,
    InvalidViewKeyDisclosure,
    LpBondShortfall,
    BatchEquivocation,
    PrivacyLeak,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidHeader => "invalid_header",
            Self::ReorgConflict => "reorg_conflict",
            Self::DuplicateKeyImage => "duplicate_key_image",
            Self::MissingPayout => "missing_payout",
            Self::WrongFee => "wrong_fee",
            Self::InvalidViewKeyDisclosure => "invalid_view_key_disclosure",
            Self::LpBondShortfall => "lp_bond_shortfall",
            Self::BatchEquivocation => "batch_equivocation",
            Self::PrivacyLeak => "privacy_leak",
        }
    }

    pub fn high_priority(self) -> bool {
        matches!(
            self,
            Self::ReorgConflict
                | Self::DuplicateKeyImage
                | Self::LpBondShortfall
                | Self::BatchEquivocation
                | Self::PrivacyLeak
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    HeaderChain,
    SealedClaimTranscript,
    KeyImageSet,
    PayoutObservation,
    ViewKeyAudit,
    LiquidityBondProof,
    FeeScheduleProof,
    PrivacySetProof,
    ArbitratorAttestation,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderChain => "header_chain",
            Self::SealedClaimTranscript => "sealed_claim_transcript",
            Self::KeyImageSet => "key_image_set",
            Self::PayoutObservation => "payout_observation",
            Self::ViewKeyAudit => "view_key_audit",
            Self::LiquidityBondProof => "liquidity_bond_proof",
            Self::FeeScheduleProof => "fee_schedule_proof",
            Self::PrivacySetProof => "privacy_set_proof",
            Self::ArbitratorAttestation => "arbitrator_attestation",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::SealedClaimTranscript
                | Self::KeyImageSet
                | Self::PayoutObservation
                | Self::ViewKeyAudit
                | Self::PrivacySetProof
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Queued,
    Reserved,
    RevealedToArbitrator,
    Accepted,
    Rejected,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Reserved => "reserved",
            Self::RevealedToArbitrator => "revealed_to_arbitrator",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
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
    Expired,
}

impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationRoundStatus {
    Scheduled,
    CollectingEvidence,
    Deliberating,
    Ruled,
    FeeCapped,
    Cancelled,
}

impl ArbitrationRoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::CollectingEvidence => "collecting_evidence",
            Self::Deliberating => "deliberating",
            Self::Ruled => "ruled",
            Self::FeeCapped => "fee_capped",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ruling {
    Pending,
    SustainChallenge,
    DismissChallenge,
    PartialSlash,
    FullSlash,
    ReorgHold,
}

impl Ruling {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SustainChallenge => "sustain_challenge",
            Self::DismissChallenge => "dismiss_challenge",
            Self::PartialSlash => "partial_slash",
            Self::FullSlash => "full_slash",
            Self::ReorgHold => "reorg_hold",
        }
    }

    pub fn slashing(self) -> bool {
        matches!(self, Self::PartialSlash | Self::FullSlash)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub challenge_window_blocks: u64,
    pub reorg_grace_blocks: u64,
    pub header_finality_depth: u64,
    pub response_window_blocks: u64,
    pub arbitration_round_blocks: u64,
    pub max_arbitration_rounds: u64,
    pub evidence_retention_blocks: u64,
    pub min_challenger_bond_piconero: u64,
    pub min_liquidity_provider_bond_piconero: u64,
    pub max_arbitration_fee_piconero: u64,
    pub min_privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub slash_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            network: MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_FEE_ASSET_ID
                .to_string(),
            challenge_window_blocks:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            reorg_grace_blocks:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_REORG_GRACE_BLOCKS,
            header_finality_depth:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_HEADER_FINALITY_DEPTH,
            response_window_blocks:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_RESPONSE_WINDOW_BLOCKS,
            arbitration_round_blocks:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_ARBITRATION_ROUND_BLOCKS,
            max_arbitration_rounds:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MAX_ARBITRATION_ROUNDS,
            evidence_retention_blocks:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_EVIDENCE_RETENTION_BLOCKS,
            min_challenger_bond_piconero:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MIN_CHALLENGER_BOND_PICONERO,
            min_liquidity_provider_bond_piconero:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MIN_LP_BOND_PICONERO,
            max_arbitration_fee_piconero:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MAX_ARBITRATION_FEE_PICONERO,
            min_privacy_set_size:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            quorum_weight_bps:
                MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_QUORUM_WEIGHT_BPS,
            slash_bps: MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEFAULT_SLASH_BPS,
        }
    }

    pub fn validate(&self) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_non_empty("network", &self.network)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_positive("challenge_window_blocks", self.challenge_window_blocks)?;
        require_positive("reorg_grace_blocks", self.reorg_grace_blocks)?;
        require_positive("header_finality_depth", self.header_finality_depth)?;
        require_positive("response_window_blocks", self.response_window_blocks)?;
        require_positive("arbitration_round_blocks", self.arbitration_round_blocks)?;
        require_positive("max_arbitration_rounds", self.max_arbitration_rounds)?;
        require_positive("evidence_retention_blocks", self.evidence_retention_blocks)?;
        require_positive(
            "min_challenger_bond_piconero",
            self.min_challenger_bond_piconero,
        )?;
        require_positive(
            "min_liquidity_provider_bond_piconero",
            self.min_liquidity_provider_bond_piconero,
        )?;
        require_positive(
            "max_arbitration_fee_piconero",
            self.max_arbitration_fee_piconero,
        )?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_bps("quorum_weight_bps", self.quorum_weight_bps)?;
        require_bps("slash_bps", self.slash_bps)?;
        if self.response_window_blocks > self.challenge_window_blocks {
            return Err("response_window_blocks cannot exceed challenge_window_blocks".to_string());
        }
        if self.reorg_grace_blocks >= self.challenge_window_blocks {
            return Err(
                "reorg_grace_blocks must be smaller than challenge_window_blocks".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "challenge_window_blocks": self.challenge_window_blocks,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "header_finality_depth": self.header_finality_depth,
            "response_window_blocks": self.response_window_blocks,
            "arbitration_round_blocks": self.arbitration_round_blocks,
            "max_arbitration_rounds": self.max_arbitration_rounds,
            "evidence_retention_blocks": self.evidence_retention_blocks,
            "min_challenger_bond_piconero": self.min_challenger_bond_piconero,
            "min_liquidity_provider_bond_piconero": self.min_liquidity_provider_bond_piconero,
            "max_arbitration_fee_piconero": self.max_arbitration_fee_piconero,
            "min_privacy_set_size": self.min_privacy_set_size,
            "quorum_weight_bps": self.quorum_weight_bps,
            "slash_bps": self.slash_bps,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-CONFIG",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostQuantumChallengerCredential {
    pub credential_id: String,
    pub challenger_commitment: String,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub credential_nullifier: String,
    pub issuer_attestation_root: String,
    pub weight_bps: u64,
    pub status: CredentialStatus,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl PostQuantumChallengerCredential {
    pub fn public_record(&self) -> Value {
        json!({
            "credential_id": self.credential_id,
            "challenger_commitment": self.challenger_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_public_key_commitment": self.backup_public_key_commitment,
            "credential_nullifier": self.credential_nullifier,
            "issuer_attestation_root": self.issuer_attestation_root,
            "weight_bps": self.weight_bps,
            "status": self.status.as_str(),
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-CREDENTIAL",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self, height: u64) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("credential_id", &self.credential_id)?;
        require_hash("challenger_commitment", &self.challenger_commitment)?;
        require_hash("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        require_hash(
            "backup_public_key_commitment",
            &self.backup_public_key_commitment,
        )?;
        require_hash("credential_nullifier", &self.credential_nullifier)?;
        require_hash("issuer_attestation_root", &self.issuer_attestation_root)?;
        require_bps("credential.weight_bps", self.weight_bps)?;
        if self.activated_at_height >= self.expires_at_height {
            return Err(format!(
                "credential {} expires before activation",
                self.credential_id
            ));
        }
        if self.status.usable() && height > self.expires_at_height {
            return Err(format!(
                "credential {} is expired at height",
                self.credential_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedExitClaim {
    pub claim_id: String,
    pub batch_id: String,
    pub bridge_header_id: String,
    pub liquidity_provider_id: String,
    pub sealed_claim_commitment: String,
    pub encrypted_claim_payload_root: String,
    pub exit_note_commitment_root: String,
    pub key_image_commitment_root: String,
    pub view_key_audit_root: String,
    pub fee_commitment_root: String,
    pub privacy_set_size: u64,
    pub exit_count: u64,
    pub claimed_amount_piconero: u64,
    pub max_fee_piconero: u64,
    pub posted_at_height: u64,
    pub challenge_deadline_height: u64,
    pub status: ClaimStatus,
}

impl SealedExitClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "batch_id": self.batch_id,
            "bridge_header_id": self.bridge_header_id,
            "liquidity_provider_id": self.liquidity_provider_id,
            "sealed_claim_commitment": self.sealed_claim_commitment,
            "encrypted_claim_payload_root": self.encrypted_claim_payload_root,
            "exit_note_commitment_root": self.exit_note_commitment_root,
            "key_image_commitment_root": self.key_image_commitment_root,
            "view_key_audit_root": self.view_key_audit_root,
            "fee_commitment_root": self.fee_commitment_root,
            "privacy_set_size": self.privacy_set_size,
            "exit_count": self.exit_count,
            "claimed_amount_piconero": self.claimed_amount_piconero,
            "max_fee_piconero": self.max_fee_piconero,
            "posted_at_height": self.posted_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-SEALED-CLAIM",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("claim_id", &self.claim_id)?;
        require_id("batch_id", &self.batch_id)?;
        require_id("bridge_header_id", &self.bridge_header_id)?;
        require_id("liquidity_provider_id", &self.liquidity_provider_id)?;
        require_hash("sealed_claim_commitment", &self.sealed_claim_commitment)?;
        require_hash(
            "encrypted_claim_payload_root",
            &self.encrypted_claim_payload_root,
        )?;
        require_hash("exit_note_commitment_root", &self.exit_note_commitment_root)?;
        require_hash("key_image_commitment_root", &self.key_image_commitment_root)?;
        require_hash("view_key_audit_root", &self.view_key_audit_root)?;
        require_hash("fee_commitment_root", &self.fee_commitment_root)?;
        require_positive("claim.privacy_set_size", self.privacy_set_size)?;
        require_positive("claim.exit_count", self.exit_count)?;
        require_positive(
            "claim.claimed_amount_piconero",
            self.claimed_amount_piconero,
        )?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "claim {} privacy set is below floor",
                self.claim_id
            ));
        }
        if self.max_fee_piconero > config.max_arbitration_fee_piconero {
            return Err(format!("claim {} exceeds fee cap", self.claim_id));
        }
        if self.challenge_deadline_height <= self.posted_at_height {
            return Err(format!(
                "claim {} has invalid challenge deadline",
                self.claim_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeHeaderReference {
    pub header_id: String,
    pub monero_network: String,
    pub header_hash: String,
    pub previous_header_hash: String,
    pub header_commitment_root: String,
    pub height: u64,
    pub observed_at_l2_height: u64,
    pub finality_depth: u64,
    pub reorg_anchor_root: String,
}

impl BridgeHeaderReference {
    pub fn public_record(&self) -> Value {
        json!({
            "header_id": self.header_id,
            "monero_network": self.monero_network,
            "header_hash": self.header_hash,
            "previous_header_hash": self.previous_header_hash,
            "header_commitment_root": self.header_commitment_root,
            "height": self.height,
            "observed_at_l2_height": self.observed_at_l2_height,
            "finality_depth": self.finality_depth,
            "reorg_anchor_root": self.reorg_anchor_root,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-BRIDGE-HEADER",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn mature_at_height(&self, config: &Config) -> u64 {
        self.observed_at_l2_height
            .saturating_add(config.header_finality_depth)
            .saturating_add(config.reorg_grace_blocks)
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("header_id", &self.header_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_hash("header_hash", &self.header_hash)?;
        require_hash("previous_header_hash", &self.previous_header_hash)?;
        require_hash("header_commitment_root", &self.header_commitment_root)?;
        require_positive("header.height", self.height)?;
        require_hash("reorg_anchor_root", &self.reorg_anchor_root)?;
        if self.finality_depth < config.header_finality_depth {
            return Err(format!(
                "header {} finality depth below config",
                self.header_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidityProviderBond {
    pub bond_id: String,
    pub liquidity_provider_id: String,
    pub claim_id: String,
    pub bond_commitment: String,
    pub amount_piconero: u64,
    pub locked_at_height: u64,
    pub release_after_height: u64,
    pub status: BondStatus,
}

impl LiquidityProviderBond {
    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "liquidity_provider_id": self.liquidity_provider_id,
            "claim_id": self.claim_id,
            "bond_commitment": self.bond_commitment,
            "amount_piconero": self.amount_piconero,
            "locked_at_height": self.locked_at_height,
            "release_after_height": self.release_after_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-LP-BOND",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("bond_id", &self.bond_id)?;
        require_id("liquidity_provider_id", &self.liquidity_provider_id)?;
        require_id("claim_id", &self.claim_id)?;
        require_hash("bond_commitment", &self.bond_commitment)?;
        if self.amount_piconero < config.min_liquidity_provider_bond_piconero {
            return Err(format!("bond {} is below minimum", self.bond_id));
        }
        if self.release_after_height <= self.locked_at_height {
            return Err(format!("bond {} release height is invalid", self.bond_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewKeyAuditCommitment {
    pub audit_id: String,
    pub claim_id: String,
    pub auditor_commitment: String,
    pub encrypted_view_key_root: String,
    pub selective_disclosure_root: String,
    pub spend_visibility_root: String,
    pub privacy_budget_commitment: String,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
}

impl ViewKeyAuditCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "claim_id": self.claim_id,
            "auditor_commitment": self.auditor_commitment,
            "encrypted_view_key_root": self.encrypted_view_key_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "spend_visibility_root": self.spend_visibility_root,
            "privacy_budget_commitment": self.privacy_budget_commitment,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-VIEW-KEY-AUDIT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("audit_id", &self.audit_id)?;
        require_id("claim_id", &self.claim_id)?;
        require_hash("auditor_commitment", &self.auditor_commitment)?;
        require_hash("encrypted_view_key_root", &self.encrypted_view_key_root)?;
        require_hash("selective_disclosure_root", &self.selective_disclosure_root)?;
        require_hash("spend_visibility_root", &self.spend_visibility_root)?;
        require_hash("privacy_budget_commitment", &self.privacy_budget_commitment)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "audit {} privacy set is below floor",
                self.audit_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyPreservingEvidence {
    pub evidence_id: String,
    pub claim_id: String,
    pub challenge_id: String,
    pub kind: EvidenceKind,
    pub sealed_evidence_root: String,
    pub public_hint_root: String,
    pub queue_commitment: String,
    pub priority: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: EvidenceStatus,
}

impl PrivacyPreservingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "claim_id": self.claim_id,
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "privacy_sensitive": self.kind.privacy_sensitive(),
            "sealed_evidence_root": self.sealed_evidence_root,
            "public_hint_root": self.public_hint_root,
            "queue_commitment": self.queue_commitment,
            "priority": self.priority,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-EVIDENCE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("evidence_id", &self.evidence_id)?;
        require_id("claim_id", &self.claim_id)?;
        require_id("challenge_id", &self.challenge_id)?;
        require_hash("sealed_evidence_root", &self.sealed_evidence_root)?;
        require_hash("public_hint_root", &self.public_hint_root)?;
        require_hash("queue_commitment", &self.queue_commitment)?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err(format!("evidence {} expiry is invalid", self.evidence_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReorgAwareChallengeWindow {
    pub window_id: String,
    pub claim_id: String,
    pub header_id: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub reorg_grace_until_height: u64,
    pub observed_reorg_depth: u64,
    pub anchor_header_root: String,
}

impl ReorgAwareChallengeWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "claim_id": self.claim_id,
            "header_id": self.header_id,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "reorg_grace_until_height": self.reorg_grace_until_height,
            "observed_reorg_depth": self.observed_reorg_depth,
            "anchor_header_root": self.anchor_header_root,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-CHALLENGE-WINDOW",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn open_at(&self, height: u64) -> bool {
        height >= self.opens_at_height && height <= self.reorg_grace_until_height
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("window_id", &self.window_id)?;
        require_id("claim_id", &self.claim_id)?;
        require_id("header_id", &self.header_id)?;
        require_hash("anchor_header_root", &self.anchor_header_root)?;
        if self.closes_at_height <= self.opens_at_height {
            return Err(format!("window {} closes before it opens", self.window_id));
        }
        if self.reorg_grace_until_height < self.closes_at_height {
            return Err(format!("window {} has invalid reorg grace", self.window_id));
        }
        if self
            .closes_at_height
            .saturating_sub(self.opens_at_height)
            .saturating_add(config.reorg_grace_blocks)
            > config
                .challenge_window_blocks
                .saturating_add(config.reorg_grace_blocks)
        {
            return Err(format!("window {} exceeds configured span", self.window_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitBatchChallenge {
    pub challenge_id: String,
    pub claim_id: String,
    pub credential_id: String,
    pub challenger_bond_commitment: String,
    pub kind: ChallengeKind,
    pub sealed_argument_root: String,
    pub evidence_queue_root: String,
    pub challenger_bond_piconero: u64,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub status: ClaimStatus,
}

impl ExitBatchChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "claim_id": self.claim_id,
            "credential_id": self.credential_id,
            "challenger_bond_commitment": self.challenger_bond_commitment,
            "kind": self.kind.as_str(),
            "high_priority": self.kind.high_priority(),
            "sealed_argument_root": self.sealed_argument_root,
            "evidence_queue_root": self.evidence_queue_root,
            "challenger_bond_piconero": self.challenger_bond_piconero,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-CHALLENGE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("challenge_id", &self.challenge_id)?;
        require_id("claim_id", &self.claim_id)?;
        require_id("credential_id", &self.credential_id)?;
        require_hash(
            "challenger_bond_commitment",
            &self.challenger_bond_commitment,
        )?;
        require_hash("sealed_argument_root", &self.sealed_argument_root)?;
        require_hash("evidence_queue_root", &self.evidence_queue_root)?;
        if self.challenger_bond_piconero < config.min_challenger_bond_piconero {
            return Err(format!(
                "challenge {} bond below minimum",
                self.challenge_id
            ));
        }
        if self.response_deadline_height <= self.opened_at_height {
            return Err(format!(
                "challenge {} response deadline invalid",
                self.challenge_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeCappedArbitrationRound {
    pub round_id: String,
    pub challenge_id: String,
    pub arbitrator_committee_root: String,
    pub round_index: u64,
    pub scheduled_at_height: u64,
    pub evidence_cutoff_height: u64,
    pub fee_cap_piconero: u64,
    pub fee_charged_piconero: u64,
    pub ruling: Ruling,
    pub ruling_commitment_root: String,
    pub status: ArbitrationRoundStatus,
}

impl FeeCappedArbitrationRound {
    pub fn public_record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "challenge_id": self.challenge_id,
            "arbitrator_committee_root": self.arbitrator_committee_root,
            "round_index": self.round_index,
            "scheduled_at_height": self.scheduled_at_height,
            "evidence_cutoff_height": self.evidence_cutoff_height,
            "fee_cap_piconero": self.fee_cap_piconero,
            "fee_charged_piconero": self.fee_charged_piconero,
            "ruling": self.ruling.as_str(),
            "ruling_slashing": self.ruling.slashing(),
            "ruling_commitment_root": self.ruling_commitment_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-ROUND",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("round_id", &self.round_id)?;
        require_id("challenge_id", &self.challenge_id)?;
        require_hash("arbitrator_committee_root", &self.arbitrator_committee_root)?;
        require_hash("ruling_commitment_root", &self.ruling_commitment_root)?;
        if self.round_index >= config.max_arbitration_rounds {
            return Err(format!("round {} exceeds max round index", self.round_id));
        }
        if self.evidence_cutoff_height <= self.scheduled_at_height {
            return Err(format!("round {} cutoff is invalid", self.round_id));
        }
        if self.fee_cap_piconero > config.max_arbitration_fee_piconero {
            return Err(format!("round {} fee cap exceeds config", self.round_id));
        }
        if self.fee_charged_piconero > self.fee_cap_piconero {
            return Err(format!("round {} charged fee exceeds cap", self.round_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingReceipt {
    pub receipt_id: String,
    pub challenge_id: String,
    pub bond_id: String,
    pub ruling_round_id: String,
    pub slashed_party_commitment: String,
    pub slashed_amount_piconero: u64,
    pub slash_bps: u64,
    pub settlement_commitment_root: String,
    pub posted_at_height: u64,
}

impl SlashingReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "challenge_id": self.challenge_id,
            "bond_id": self.bond_id,
            "ruling_round_id": self.ruling_round_id,
            "slashed_party_commitment": self.slashed_party_commitment,
            "slashed_amount_piconero": self.slashed_amount_piconero,
            "slash_bps": self.slash_bps,
            "settlement_commitment_root": self.settlement_commitment_root,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-SLASHING-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        require_id("receipt_id", &self.receipt_id)?;
        require_id("challenge_id", &self.challenge_id)?;
        require_id("bond_id", &self.bond_id)?;
        require_id("ruling_round_id", &self.ruling_round_id)?;
        require_hash("slashed_party_commitment", &self.slashed_party_commitment)?;
        require_hash(
            "settlement_commitment_root",
            &self.settlement_commitment_root,
        )?;
        require_positive("slashed_amount_piconero", self.slashed_amount_piconero)?;
        require_bps("slash_bps", self.slash_bps)?;
        if self.slash_bps > config.slash_bps {
            return Err(format!("receipt {} slash exceeds config", self.receipt_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub credential_root: String,
    pub sealed_claim_root: String,
    pub bridge_header_root: String,
    pub liquidity_bond_root: String,
    pub view_key_audit_root: String,
    pub challenge_window_root: String,
    pub challenge_root: String,
    pub evidence_queue_root: String,
    pub arbitration_round_root: String,
    pub slashing_receipt_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "credential_root": self.credential_root,
            "sealed_claim_root": self.sealed_claim_root,
            "bridge_header_root": self.bridge_header_root,
            "liquidity_bond_root": self.liquidity_bond_root,
            "view_key_audit_root": self.view_key_audit_root,
            "challenge_window_root": self.challenge_window_root,
            "challenge_root": self.challenge_root,
            "evidence_queue_root": self.evidence_queue_root,
            "arbitration_round_root": self.arbitration_round_root,
            "slashing_receipt_root": self.slashing_receipt_root,
            "event_root": self.event_root,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-ROOTS",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub credentials: u64,
    pub sealed_claims: u64,
    pub bridge_headers: u64,
    pub liquidity_bonds: u64,
    pub view_key_audits: u64,
    pub challenge_windows: u64,
    pub challenges: u64,
    pub queued_evidence: u64,
    pub active_evidence: u64,
    pub arbitration_rounds: u64,
    pub slashing_receipts: u64,
    pub sustained_challenges: u64,
    pub dismissed_challenges: u64,
    pub fee_capped_rounds: u64,
    pub total_bonded_piconero: u64,
    pub total_slashed_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "credentials": self.credentials,
            "sealed_claims": self.sealed_claims,
            "bridge_headers": self.bridge_headers,
            "liquidity_bonds": self.liquidity_bonds,
            "view_key_audits": self.view_key_audits,
            "challenge_windows": self.challenge_windows,
            "challenges": self.challenges,
            "queued_evidence": self.queued_evidence,
            "active_evidence": self.active_evidence,
            "arbitration_rounds": self.arbitration_rounds,
            "slashing_receipts": self.slashing_receipts,
            "sustained_challenges": self.sustained_challenges,
            "dismissed_challenges": self.dismissed_challenges,
            "fee_capped_rounds": self.fee_capped_rounds,
            "total_bonded_piconero": self.total_bonded_piconero,
            "total_slashed_piconero": self.total_slashed_piconero,
        })
    }

    pub fn root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-COUNTERS",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub credentials: BTreeMap<String, PostQuantumChallengerCredential>,
    pub sealed_claims: BTreeMap<String, SealedExitClaim>,
    pub bridge_headers: BTreeMap<String, BridgeHeaderReference>,
    pub liquidity_bonds: BTreeMap<String, LiquidityProviderBond>,
    pub view_key_audits: BTreeMap<String, ViewKeyAuditCommitment>,
    pub challenge_windows: BTreeMap<String, ReorgAwareChallengeWindow>,
    pub challenges: BTreeMap<String, ExitBatchChallenge>,
    pub evidence_queue: VecDeque<PrivacyPreservingEvidence>,
    pub arbitration_rounds: BTreeMap<String, FeeCappedArbitrationRound>,
    pub slashing_receipts: BTreeMap<String, SlashingReceipt>,
    pub event_log: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64) -> MoneroPrivateExitBatchDisputeArbitratorResult<Self> {
        config.validate()?;
        Ok(Self {
            height,
            config,
            credentials: BTreeMap::new(),
            sealed_claims: BTreeMap::new(),
            bridge_headers: BTreeMap::new(),
            liquidity_bonds: BTreeMap::new(),
            view_key_audits: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            challenges: BTreeMap::new(),
            evidence_queue: VecDeque::new(),
            arbitration_rounds: BTreeMap::new(),
            slashing_receipts: BTreeMap::new(),
            event_log: Vec::new(),
        })
    }

    pub fn devnet() -> MoneroPrivateExitBatchDisputeArbitratorResult<State> {
        let mut state = State::new(
            Config::devnet(),
            MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_DEVNET_HEIGHT,
        )?;
        state.install_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        self.height = height;
        self.expire_windows_and_evidence();
        self.validate()
    }

    pub fn update_height(
        &mut self,
        delta: u64,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        self.set_height(self.height.saturating_add(delta))
    }

    pub fn register_credential(
        &mut self,
        credential: PostQuantumChallengerCredential,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        credential.validate(self.height)?;
        require_unique_key(&self.credentials, "credential", &credential.credential_id)?;
        self.event_log.push(event_record(
            self.height,
            "credential_registered",
            &credential.credential_id,
            &credential.root(),
        ));
        self.credentials
            .insert(credential.credential_id.clone(), credential);
        Ok(())
    }

    pub fn register_header(
        &mut self,
        header: BridgeHeaderReference,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        header.validate(&self.config)?;
        require_unique_key(&self.bridge_headers, "header", &header.header_id)?;
        self.event_log.push(event_record(
            self.height,
            "bridge_header_registered",
            &header.header_id,
            &header.root(),
        ));
        self.bridge_headers.insert(header.header_id.clone(), header);
        Ok(())
    }

    pub fn post_sealed_claim(
        &mut self,
        claim: SealedExitClaim,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        claim.validate(&self.config)?;
        require_unique_key(&self.sealed_claims, "claim", &claim.claim_id)?;
        require_present_key(&self.bridge_headers, "header", &claim.bridge_header_id)?;
        let window = ReorgAwareChallengeWindow {
            window_id: stable_hash(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-WINDOW-ID",
                &[
                    HashPart::Str(&claim.claim_id),
                    HashPart::Str(&claim.bridge_header_id),
                ],
            ),
            claim_id: claim.claim_id.clone(),
            header_id: claim.bridge_header_id.clone(),
            opens_at_height: claim.posted_at_height,
            closes_at_height: claim.challenge_deadline_height,
            reorg_grace_until_height: claim
                .challenge_deadline_height
                .saturating_add(self.config.reorg_grace_blocks),
            observed_reorg_depth: 0,
            anchor_header_root: match self.bridge_headers.get(&claim.bridge_header_id) {
                Some(header) => header.root(),
                None => String::new(),
            },
        };
        window.validate(&self.config)?;
        self.challenge_windows
            .insert(window.window_id.clone(), window);
        self.event_log.push(event_record(
            self.height,
            "sealed_claim_posted",
            &claim.claim_id,
            &claim.root(),
        ));
        self.sealed_claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    pub fn lock_liquidity_bond(
        &mut self,
        bond: LiquidityProviderBond,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        bond.validate(&self.config)?;
        require_unique_key(&self.liquidity_bonds, "bond", &bond.bond_id)?;
        require_present_key(&self.sealed_claims, "claim", &bond.claim_id)?;
        self.event_log.push(event_record(
            self.height,
            "liquidity_bond_locked",
            &bond.bond_id,
            &bond.root(),
        ));
        self.liquidity_bonds.insert(bond.bond_id.clone(), bond);
        Ok(())
    }

    pub fn commit_view_key_audit(
        &mut self,
        audit: ViewKeyAuditCommitment,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        audit.validate(&self.config)?;
        require_unique_key(&self.view_key_audits, "audit", &audit.audit_id)?;
        require_present_key(&self.sealed_claims, "claim", &audit.claim_id)?;
        self.event_log.push(event_record(
            self.height,
            "view_key_audit_committed",
            &audit.audit_id,
            &audit.root(),
        ));
        self.view_key_audits.insert(audit.audit_id.clone(), audit);
        Ok(())
    }

    pub fn open_challenge(
        &mut self,
        challenge: ExitBatchChallenge,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        challenge.validate(&self.config)?;
        require_unique_key(&self.challenges, "challenge", &challenge.challenge_id)?;
        require_present_key(&self.sealed_claims, "claim", &challenge.claim_id)?;
        require_present_key(&self.credentials, "credential", &challenge.credential_id)?;
        let credential = self
            .credentials
            .get(&challenge.credential_id)
            .ok_or_else(|| format!("credential {} missing", challenge.credential_id))?;
        credential.validate(self.height)?;
        if !self.claim_challenge_window_open(&challenge.claim_id) {
            return Err(format!(
                "claim {} challenge window is not open",
                challenge.claim_id
            ));
        }
        if let Some(claim) = self.sealed_claims.get_mut(&challenge.claim_id) {
            claim.status = ClaimStatus::Challenged;
        }
        self.event_log.push(event_record(
            self.height,
            "challenge_opened",
            &challenge.challenge_id,
            &challenge.root(),
        ));
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn enqueue_evidence(
        &mut self,
        evidence: PrivacyPreservingEvidence,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        evidence.validate()?;
        if self
            .evidence_queue
            .iter()
            .any(|item| item.evidence_id == evidence.evidence_id)
        {
            return Err(format!("evidence {} already exists", evidence.evidence_id));
        }
        require_present_key(&self.sealed_claims, "claim", &evidence.claim_id)?;
        require_present_key(&self.challenges, "challenge", &evidence.challenge_id)?;
        self.event_log.push(event_record(
            self.height,
            "evidence_enqueued",
            &evidence.evidence_id,
            &evidence.root(),
        ));
        self.evidence_queue.push_back(evidence);
        self.sort_evidence_queue();
        Ok(())
    }

    pub fn schedule_arbitration_round(
        &mut self,
        round: FeeCappedArbitrationRound,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        round.validate(&self.config)?;
        require_unique_key(&self.arbitration_rounds, "round", &round.round_id)?;
        require_present_key(&self.challenges, "challenge", &round.challenge_id)?;
        if let Some(challenge) = self.challenges.get_mut(&round.challenge_id) {
            challenge.status = ClaimStatus::Arbitrating;
        }
        self.event_log.push(event_record(
            self.height,
            "arbitration_round_scheduled",
            &round.round_id,
            &round.root(),
        ));
        self.arbitration_rounds
            .insert(round.round_id.clone(), round);
        Ok(())
    }

    pub fn record_slashing(
        &mut self,
        receipt: SlashingReceipt,
    ) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        receipt.validate(&self.config)?;
        require_unique_key(&self.slashing_receipts, "receipt", &receipt.receipt_id)?;
        require_present_key(&self.challenges, "challenge", &receipt.challenge_id)?;
        require_present_key(&self.liquidity_bonds, "bond", &receipt.bond_id)?;
        require_present_key(&self.arbitration_rounds, "round", &receipt.ruling_round_id)?;
        if let Some(bond) = self.liquidity_bonds.get_mut(&receipt.bond_id) {
            bond.status = BondStatus::Slashed;
        }
        if let Some(challenge) = self.challenges.get_mut(&receipt.challenge_id) {
            challenge.status = ClaimStatus::Sustained;
        }
        self.event_log.push(event_record(
            self.height,
            "slashing_recorded",
            &receipt.receipt_id,
            &receipt.root(),
        ));
        self.slashing_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn claim_challenge_window_open(&self, claim_id: &str) -> bool {
        self.challenge_windows
            .values()
            .any(|window| window.claim_id == claim_id && window.open_at(self.height))
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            credential_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-CREDENTIAL-ROOT",
                self.credentials
                    .values()
                    .map(PostQuantumChallengerCredential::root),
            ),
            sealed_claim_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-CLAIM-ROOT",
                self.sealed_claims.values().map(SealedExitClaim::root),
            ),
            bridge_header_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-HEADER-ROOT",
                self.bridge_headers
                    .values()
                    .map(BridgeHeaderReference::root),
            ),
            liquidity_bond_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-BOND-ROOT",
                self.liquidity_bonds
                    .values()
                    .map(LiquidityProviderBond::root),
            ),
            view_key_audit_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-AUDIT-ROOT",
                self.view_key_audits
                    .values()
                    .map(ViewKeyAuditCommitment::root),
            ),
            challenge_window_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-WINDOW-ROOT",
                self.challenge_windows
                    .values()
                    .map(ReorgAwareChallengeWindow::root),
            ),
            challenge_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-CHALLENGE-ROOT",
                self.challenges.values().map(ExitBatchChallenge::root),
            ),
            evidence_queue_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-EVIDENCE-ROOT",
                self.evidence_queue
                    .iter()
                    .map(PrivacyPreservingEvidence::root),
            ),
            arbitration_round_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-ROUND-ROOT",
                self.arbitration_rounds
                    .values()
                    .map(FeeCappedArbitrationRound::root),
            ),
            slashing_receipt_root: map_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-RECEIPT-ROOT",
                self.slashing_receipts.values().map(SlashingReceipt::root),
            ),
            event_root: value_list_root(
                "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-EVENT-ROOT",
                self.event_log.iter(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            credentials: self.credentials.len() as u64,
            sealed_claims: self.sealed_claims.len() as u64,
            bridge_headers: self.bridge_headers.len() as u64,
            liquidity_bonds: self.liquidity_bonds.len() as u64,
            view_key_audits: self.view_key_audits.len() as u64,
            challenge_windows: self.challenge_windows.len() as u64,
            challenges: self.challenges.len() as u64,
            queued_evidence: self
                .evidence_queue
                .iter()
                .filter(|item| item.status == EvidenceStatus::Queued)
                .count() as u64,
            active_evidence: self
                .evidence_queue
                .iter()
                .filter(|item| !matches!(item.status, EvidenceStatus::Expired))
                .count() as u64,
            arbitration_rounds: self.arbitration_rounds.len() as u64,
            slashing_receipts: self.slashing_receipts.len() as u64,
            sustained_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ClaimStatus::Sustained)
                .count() as u64,
            dismissed_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ClaimStatus::Dismissed)
                .count() as u64,
            fee_capped_rounds: self
                .arbitration_rounds
                .values()
                .filter(|round| round.status == ArbitrationRoundStatus::FeeCapped)
                .count() as u64,
            total_bonded_piconero: self
                .liquidity_bonds
                .values()
                .map(|bond| bond.amount_piconero)
                .sum::<u64>()
                .saturating_add(
                    self.challenges
                        .values()
                        .map(|challenge| challenge.challenger_bond_piconero)
                        .sum::<u64>(),
                ),
            total_slashed_piconero: self
                .slashing_receipts
                .values()
                .map(|receipt| receipt.slashed_amount_piconero)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        stable_hash(
            "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-STATE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_PROTOCOL_VERSION,
            "schema_version": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_SCHEMA_VERSION,
            "hash_suite": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_HASH_SUITE,
            "challenger_credential_scheme": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_CHALLENGER_CREDENTIAL_SCHEME,
            "sealed_claim_scheme": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_SEALED_CLAIM_SCHEME,
            "view_key_audit_scheme": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_VIEW_KEY_AUDIT_SCHEME,
            "evidence_queue_scheme": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_EVIDENCE_QUEUE_SCHEME,
            "slashing_receipt_scheme": MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_SLASHING_RECEIPT_SCHEME,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": counters.public_record(),
            "counters_root": counters.root(),
            "credentials": self.credentials.values().map(PostQuantumChallengerCredential::public_record).collect::<Vec<_>>(),
            "sealed_claims": self.sealed_claims.values().map(SealedExitClaim::public_record).collect::<Vec<_>>(),
            "bridge_headers": self.bridge_headers.values().map(BridgeHeaderReference::public_record).collect::<Vec<_>>(),
            "liquidity_bonds": self.liquidity_bonds.values().map(LiquidityProviderBond::public_record).collect::<Vec<_>>(),
            "view_key_audits": self.view_key_audits.values().map(ViewKeyAuditCommitment::public_record).collect::<Vec<_>>(),
            "challenge_windows": self.challenge_windows.values().map(ReorgAwareChallengeWindow::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(ExitBatchChallenge::public_record).collect::<Vec<_>>(),
            "evidence_queue": self.evidence_queue.iter().map(PrivacyPreservingEvidence::public_record).collect::<Vec<_>>(),
            "arbitration_rounds": self.arbitration_rounds.values().map(FeeCappedArbitrationRound::public_record).collect::<Vec<_>>(),
            "slashing_receipts": self.slashing_receipts.values().map(SlashingReceipt::public_record).collect::<Vec<_>>(),
            "event_log": self.event_log,
        })
    }

    pub fn validate(&self) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        self.config.validate()?;
        validate_unique_roots(
            "credential_nullifier",
            self.credentials
                .values()
                .map(|credential| credential.credential_nullifier.as_str()),
        )?;
        for credential in self.credentials.values() {
            credential.validate(self.height)?;
        }
        for header in self.bridge_headers.values() {
            header.validate(&self.config)?;
        }
        for claim in self.sealed_claims.values() {
            claim.validate(&self.config)?;
            require_present_key(&self.bridge_headers, "header", &claim.bridge_header_id)?;
        }
        for bond in self.liquidity_bonds.values() {
            bond.validate(&self.config)?;
            require_present_key(&self.sealed_claims, "claim", &bond.claim_id)?;
        }
        for audit in self.view_key_audits.values() {
            audit.validate(&self.config)?;
            require_present_key(&self.sealed_claims, "claim", &audit.claim_id)?;
        }
        for window in self.challenge_windows.values() {
            window.validate(&self.config)?;
            require_present_key(&self.sealed_claims, "claim", &window.claim_id)?;
            require_present_key(&self.bridge_headers, "header", &window.header_id)?;
        }
        for challenge in self.challenges.values() {
            challenge.validate(&self.config)?;
            require_present_key(&self.sealed_claims, "claim", &challenge.claim_id)?;
            require_present_key(&self.credentials, "credential", &challenge.credential_id)?;
        }
        for evidence in &self.evidence_queue {
            evidence.validate()?;
            require_present_key(&self.sealed_claims, "claim", &evidence.claim_id)?;
            require_present_key(&self.challenges, "challenge", &evidence.challenge_id)?;
        }
        for round in self.arbitration_rounds.values() {
            round.validate(&self.config)?;
            require_present_key(&self.challenges, "challenge", &round.challenge_id)?;
        }
        for receipt in self.slashing_receipts.values() {
            receipt.validate(&self.config)?;
            require_present_key(&self.challenges, "challenge", &receipt.challenge_id)?;
            require_present_key(&self.liquidity_bonds, "bond", &receipt.bond_id)?;
            require_present_key(&self.arbitration_rounds, "round", &receipt.ruling_round_id)?;
        }
        Ok(())
    }

    fn sort_evidence_queue(&mut self) {
        let mut items = self.evidence_queue.drain(..).collect::<Vec<_>>();
        items.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.submitted_at_height.cmp(&right.submitted_at_height))
                .then_with(|| left.evidence_id.cmp(&right.evidence_id))
        });
        self.evidence_queue = items.into_iter().collect();
    }

    fn expire_windows_and_evidence(&mut self) {
        for claim in self.sealed_claims.values_mut() {
            if !claim.status.terminal() && self.height > claim.challenge_deadline_height {
                claim.status = ClaimStatus::Expired;
            }
        }
        for evidence in &mut self.evidence_queue {
            if evidence.status == EvidenceStatus::Queued && self.height > evidence.expires_at_height
            {
                evidence.status = EvidenceStatus::Expired;
            }
        }
    }

    fn install_devnet_records(&mut self) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
        let header = BridgeHeaderReference {
            header_id: "xmr-header-devnet-1184".to_string(),
            monero_network: self.config.network.clone(),
            header_hash: sample_hash("header-hash"),
            previous_header_hash: sample_hash("previous-header-hash"),
            header_commitment_root: sample_hash("header-commitment-root"),
            height: 3_210_456,
            observed_at_l2_height: self.height.saturating_sub(12),
            finality_depth: self.config.header_finality_depth,
            reorg_anchor_root: sample_hash("reorg-anchor-root"),
        };
        self.register_header(header)?;

        let credential = PostQuantumChallengerCredential {
            credential_id: "pq-challenger-devnet-001".to_string(),
            challenger_commitment: sample_hash("challenger-commitment"),
            pq_public_key_commitment: sample_hash("pq-public-key"),
            backup_public_key_commitment: sample_hash("backup-public-key"),
            credential_nullifier: sample_hash("credential-nullifier"),
            issuer_attestation_root: sample_hash("issuer-attestation"),
            weight_bps: 7_000,
            status: CredentialStatus::Active,
            activated_at_height: self.height.saturating_sub(100),
            expires_at_height: self.height.saturating_add(4_000),
        };
        self.register_credential(credential)?;

        let claim = SealedExitClaim {
            claim_id: "sealed-exit-claim-devnet-001".to_string(),
            batch_id: "private-exit-batch-devnet-041".to_string(),
            bridge_header_id: "xmr-header-devnet-1184".to_string(),
            liquidity_provider_id: "lp-devnet-amber".to_string(),
            sealed_claim_commitment: sample_hash("sealed-claim"),
            encrypted_claim_payload_root: sample_hash("encrypted-claim-payload"),
            exit_note_commitment_root: sample_hash("exit-note-root"),
            key_image_commitment_root: sample_hash("key-image-root"),
            view_key_audit_root: sample_hash("view-key-root"),
            fee_commitment_root: sample_hash("fee-root"),
            privacy_set_size: self.config.min_privacy_set_size.saturating_add(256),
            exit_count: 32,
            claimed_amount_piconero: 98_000_000_000,
            max_fee_piconero: self.config.max_arbitration_fee_piconero / 2,
            posted_at_height: self.height,
            challenge_deadline_height: self
                .height
                .saturating_add(self.config.challenge_window_blocks),
            status: ClaimStatus::ChallengeOpen,
        };
        self.post_sealed_claim(claim)?;

        let bond = LiquidityProviderBond {
            bond_id: "lp-bond-devnet-001".to_string(),
            liquidity_provider_id: "lp-devnet-amber".to_string(),
            claim_id: "sealed-exit-claim-devnet-001".to_string(),
            bond_commitment: sample_hash("lp-bond"),
            amount_piconero: self
                .config
                .min_liquidity_provider_bond_piconero
                .saturating_mul(2),
            locked_at_height: self.height,
            release_after_height: self
                .height
                .saturating_add(self.config.challenge_window_blocks)
                .saturating_add(self.config.reorg_grace_blocks),
            status: BondStatus::Locked,
        };
        self.lock_liquidity_bond(bond)?;

        let audit = ViewKeyAuditCommitment {
            audit_id: "view-key-audit-devnet-001".to_string(),
            claim_id: "sealed-exit-claim-devnet-001".to_string(),
            auditor_commitment: sample_hash("auditor"),
            encrypted_view_key_root: sample_hash("encrypted-view-key"),
            selective_disclosure_root: sample_hash("selective-disclosure"),
            spend_visibility_root: sample_hash("spend-visibility"),
            privacy_budget_commitment: sample_hash("privacy-budget"),
            min_privacy_set_size: self.config.min_privacy_set_size,
            opened_at_height: self.height,
        };
        self.commit_view_key_audit(audit)?;

        let challenge = ExitBatchChallenge {
            challenge_id: "exit-batch-challenge-devnet-001".to_string(),
            claim_id: "sealed-exit-claim-devnet-001".to_string(),
            credential_id: "pq-challenger-devnet-001".to_string(),
            challenger_bond_commitment: sample_hash("challenger-bond"),
            kind: ChallengeKind::BatchEquivocation,
            sealed_argument_root: sample_hash("sealed-argument"),
            evidence_queue_root: sample_hash("challenge-evidence-root"),
            challenger_bond_piconero: self.config.min_challenger_bond_piconero,
            opened_at_height: self.height,
            response_deadline_height: self
                .height
                .saturating_add(self.config.response_window_blocks),
            status: ClaimStatus::ResponseOpen,
        };
        self.open_challenge(challenge)?;

        let evidence_items = [
            (EvidenceKind::HeaderChain, "header-chain", 90),
            (EvidenceKind::KeyImageSet, "key-image-set", 100),
            (EvidenceKind::ViewKeyAudit, "view-key-audit", 80),
        ];
        for (kind, label, priority) in evidence_items {
            let evidence = PrivacyPreservingEvidence {
                evidence_id: format!("evidence-devnet-{label}"),
                claim_id: "sealed-exit-claim-devnet-001".to_string(),
                challenge_id: "exit-batch-challenge-devnet-001".to_string(),
                kind,
                sealed_evidence_root: sample_hash(&format!("sealed-evidence-{label}")),
                public_hint_root: sample_hash(&format!("public-hint-{label}")),
                queue_commitment: sample_hash(&format!("queue-{label}")),
                priority,
                submitted_at_height: self.height,
                expires_at_height: self
                    .height
                    .saturating_add(self.config.evidence_retention_blocks),
                status: EvidenceStatus::Queued,
            };
            self.enqueue_evidence(evidence)?;
        }

        let round = FeeCappedArbitrationRound {
            round_id: "arbitration-round-devnet-001".to_string(),
            challenge_id: "exit-batch-challenge-devnet-001".to_string(),
            arbitrator_committee_root: sample_hash("arbitrator-committee"),
            round_index: 0,
            scheduled_at_height: self.height,
            evidence_cutoff_height: self
                .height
                .saturating_add(self.config.arbitration_round_blocks),
            fee_cap_piconero: self.config.max_arbitration_fee_piconero,
            fee_charged_piconero: self.config.max_arbitration_fee_piconero / 4,
            ruling: Ruling::Pending,
            ruling_commitment_root: sample_hash("pending-ruling"),
            status: ArbitrationRoundStatus::CollectingEvidence,
        };
        self.schedule_arbitration_round(round)?;
        Ok(())
    }
}

pub fn root_from_record(record: &serde_json::Value) -> String {
    stable_hash(
        "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-RECORD",
        &[HashPart::Json(record)],
    )
}

pub fn devnet() -> MoneroPrivateExitBatchDisputeArbitratorResult<State> {
    State::devnet()
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn require_positive(field: &str, value: u64) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
    if value == 0 || value > MONERO_PRIVATE_EXIT_BATCH_DISPUTE_ARBITRATOR_MAX_BPS {
        return Err(format!("{field} must be within 1..=10000"));
    }
    Ok(())
}

fn require_id(field: &str, value: &str) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
    require_non_empty(field, value)?;
    if value.len() > 128 {
        return Err(format!("{field} is too long"));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(format!("{field} contains unsupported characters"));
    }
    Ok(())
}

fn require_hash(field: &str, value: &str) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 32 {
        return Err(format!("{field} must be at least 32 characters"));
    }
    Ok(())
}

fn require_unique_key<T>(
    map: &BTreeMap<String, T>,
    label: &str,
    key: &str,
) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
    if map.contains_key(key) {
        return Err(format!("{label} {key} already exists"));
    }
    Ok(())
}

fn require_present_key<T>(
    map: &BTreeMap<String, T>,
    label: &str,
    key: &str,
) -> MoneroPrivateExitBatchDisputeArbitratorResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{label} {key} is missing"));
    }
    Ok(())
}

fn validate_unique_roots<'a, I>(
    label: &str,
    values: I,
) -> MoneroPrivateExitBatchDisputeArbitratorResult<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.to_string()) {
            return Err(format!("{label} {value} is duplicated"));
        }
    }
    Ok(())
}

fn map_root<I>(domain: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let values = roots.into_iter().map(Value::String).collect::<Vec<_>>();
    value_list_root(domain, values.iter())
}

fn value_list_root<'a, I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = &'a Value>,
{
    let mut records = values.into_iter().cloned().collect::<Vec<_>>();
    records.sort_by_key(root_from_record);
    stable_hash(domain, &[HashPart::Json(&Value::Array(records))])
}

fn event_record(height: u64, kind: &str, subject_id: &str, subject_root: &str) -> Value {
    let body = json!({
        "height": height,
        "kind": kind,
        "subject_id": subject_id,
        "subject_root": subject_root,
    });
    json!({
        "height": height,
        "kind": kind,
        "subject_id": subject_id,
        "subject_root": subject_root,
        "event_root": root_from_record(&body),
    })
}

fn sample_hash(label: &str) -> String {
    stable_hash(
        "MONERO-PRIVATE-EXIT-BATCH-DISPUTE-ARBITRATOR-DEVNET-SAMPLE",
        &[HashPart::Str(label)],
    )
}
