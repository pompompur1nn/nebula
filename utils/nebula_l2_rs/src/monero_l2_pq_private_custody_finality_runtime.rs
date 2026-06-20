use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str = "nebula-monero-l2-pq-private-custody-finality-runtime-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_ATTESTATION_SCHEME: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const RESERVE_PROOF_SCHEME: &str = "zk-monero-private-reserve-proof-v1";
pub const CUSTODY_COMMITMENT_SCHEME: &str = "monero-view-key-sealed-epoch-commitment-v1";
pub const FAST_FINALITY_SCHEME: &str = "pq-aggregate-fast-finality-ticket-v1";
pub const ESCAPE_MANIFEST_SCHEME: &str = "timelocked-monero-emergency-escape-v1";
pub const DEVNET_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_CHAIN: &str = "nebula-monero-l2-devnet";
pub const DEVNET_XMR_ASSET: &str = "xmr";
pub const DEVNET_WXMR_ASSET: &str = "wxmr";
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyEpochStatus {
    Open,
    Committing,
    Attested,
    Finalized,
    Delayed,
    Escaping,
    Closed,
}

impl CustodyEpochStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Committing => "committing",
            Self::Attested => "attested",
            Self::Finalized => "finalized",
            Self::Delayed => "delayed",
            Self::Escaping => "escaping",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_commitments(&self) -> bool {
        matches!(self, Self::Open | Self::Committing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    Paused,
    Retired,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_attest(&self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    CustodyEpoch,
    ReserveProof,
    FastFinality,
    WithdrawalDelay,
    EscapeManifest,
    BridgeLiquidity,
}

impl AttestationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CustodyEpoch => "custody_epoch",
            Self::ReserveProof => "reserve_proof",
            Self::FastFinality => "fast_finality",
            Self::WithdrawalDelay => "withdrawal_delay",
            Self::EscapeManifest => "escape_manifest",
            Self::BridgeLiquidity => "bridge_liquidity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityTicketStatus {
    Proposed,
    QuorumCertified,
    Executed,
    Delayed,
    Rejected,
    Superseded,
}

impl FinalityTicketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuorumCertified => "quorum_certified",
            Self::Executed => "executed",
            Self::Delayed => "delayed",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    pub fn live(&self) -> bool {
        matches!(self, Self::Proposed | Self::QuorumCertified | Self::Delayed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Submitted,
    Verified,
    Stale,
    Challenged,
    Rejected,
}

impl ReserveProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Stale => "stale",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeClaimStatus {
    Open,
    Reserved,
    Filled,
    Finalized,
    Expired,
    Disputed,
}

impl BridgeClaimStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalStatus {
    Requested,
    DelayLocked,
    ReleaseReady,
    Released,
    Cancelled,
    Escaped,
    Slashed,
}

impl WithdrawalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::DelayLocked => "delay_locked",
            Self::ReleaseReady => "release_ready",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Escaped => "escaped",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeStatus {
    Draft,
    Published,
    ChallengeWindow,
    Executable,
    Executed,
    Cancelled,
}

impl EscapeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::ChallengeWindow => "challenge_window",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Active,
    Throttled,
    Exhausted,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyEventKind {
    Deposit,
    Withdrawal,
    BridgeClaim,
    ReserveProof,
    SponsoredFee,
    Escape,
    Slash,
}

impl PrivacyEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::BridgeClaim => "bridge_claim",
            Self::ReserveProof => "reserve_proof",
            Self::SponsoredFee => "sponsored_fee",
            Self::Escape => "escape",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    Equivocation,
    InvalidReserveProof,
    DelayedWithdrawalCensorship,
    BadFinalityTicket,
    LiquidityDefault,
    PrivacyLeak,
    EscapeObstruction,
}

impl SlashingReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::InvalidReserveProof => "invalid_reserve_proof",
            Self::DelayedWithdrawalCensorship => "delayed_withdrawal_censorship",
            Self::BadFinalityTicket => "bad_finality_ticket",
            Self::LiquidityDefault => "liquidity_default",
            Self::PrivacyLeak => "privacy_leak",
            Self::EscapeObstruction => "escape_obstruction",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub network: String,
    pub l2_chain_id: String,
    pub xmr_asset_id: String,
    pub wrapped_xmr_asset_id: String,
    pub epoch_length_blocks: u64,
    pub withdrawal_delay_blocks: u64,
    pub escape_delay_blocks: u64,
    pub fast_finality_blocks: u64,
    pub reserve_proof_ttl_blocks: u64,
    pub min_committee_size: usize,
    pub pq_quorum_threshold: usize,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub sponsor_fee_cap: u64,
    pub min_privacy_set: u64,
    pub max_bridge_claim_ttl_blocks: u64,
    pub slash_bond_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            network: DEVNET_NETWORK.to_string(),
            l2_chain_id: DEVNET_L2_CHAIN.to_string(),
            xmr_asset_id: DEVNET_XMR_ASSET.to_string(),
            wrapped_xmr_asset_id: DEVNET_WXMR_ASSET.to_string(),
            epoch_length_blocks: 720,
            withdrawal_delay_blocks: 60,
            escape_delay_blocks: 180,
            fast_finality_blocks: 2,
            reserve_proof_ttl_blocks: 720,
            min_committee_size: 4,
            pq_quorum_threshold: 3,
            min_pq_security_bits: 256,
            max_fee_bps: 25,
            sponsor_fee_cap: 100_000,
            min_privacy_set: 32,
            max_bridge_claim_ttl_blocks: 1_440,
            slash_bond_bps: 1_000,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "network": self.network,
            "l2_chain_id": self.l2_chain_id,
            "xmr_asset_id": self.xmr_asset_id,
            "wrapped_xmr_asset_id": self.wrapped_xmr_asset_id,
            "epoch_length_blocks": self.epoch_length_blocks,
            "withdrawal_delay_blocks": self.withdrawal_delay_blocks,
            "escape_delay_blocks": self.escape_delay_blocks,
            "fast_finality_blocks": self.fast_finality_blocks,
            "reserve_proof_ttl_blocks": self.reserve_proof_ttl_blocks,
            "min_committee_size": self.min_committee_size,
            "pq_quorum_threshold": self.pq_quorum_threshold,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_fee_cap": self.sponsor_fee_cap,
            "min_privacy_set": self.min_privacy_set,
            "max_bridge_claim_ttl_blocks": self.max_bridge_claim_ttl_blocks,
            "slash_bond_bps": self.slash_bond_bps,
            "hash_suite": HASH_SUITE,
            "pq_attestation_scheme": PQ_ATTESTATION_SCHEME,
            "reserve_proof_scheme": RESERVE_PROOF_SCHEME,
            "custody_commitment_scheme": CUSTODY_COMMITMENT_SCHEME,
            "fast_finality_scheme": FAST_FINALITY_SCHEME,
            "escape_manifest_scheme": ESCAPE_MANIFEST_SCHEME,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.network, "network")?;
        ensure_non_empty(&self.l2_chain_id, "l2 chain id")?;
        if self.min_committee_size == 0 {
            return Err("minimum committee size must be non-zero".to_string());
        }
        if self.pq_quorum_threshold == 0 || self.pq_quorum_threshold > self.min_committee_size {
            return Err("PQ quorum threshold must fit committee size".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("PQ security bits below runtime floor".to_string());
        }
        if self.max_fee_bps > MAX_BPS || self.slash_bond_bps > MAX_BPS {
            return Err("basis point config exceeds 100%".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub custody_epochs: u64,
    pub committees: u64,
    pub attestations: u64,
    pub finality_tickets: u64,
    pub reserve_proofs: u64,
    pub bridge_claims: u64,
    pub withdrawals: u64,
    pub escape_manifests: u64,
    pub fee_sponsorships: u64,
    pub privacy_events: u64,
    pub slashing_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "custody_epochs": self.custody_epochs,
            "committees": self.committees,
            "attestations": self.attestations,
            "finality_tickets": self.finality_tickets,
            "reserve_proofs": self.reserve_proofs,
            "bridge_claims": self.bridge_claims,
            "withdrawals": self.withdrawals,
            "escape_manifests": self.escape_manifests,
            "fee_sponsorships": self.fee_sponsorships,
            "privacy_events": self.privacy_events,
            "slashing_events": self.slashing_events,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub custody_epoch_root: String,
    pub committee_root: String,
    pub attestation_root: String,
    pub finality_ticket_root: String,
    pub reserve_proof_root: String,
    pub bridge_claim_root: String,
    pub withdrawal_root: String,
    pub escape_manifest_root: String,
    pub fee_sponsorship_root: String,
    pub privacy_accounting_root: String,
    pub slashing_evidence_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "custody_epoch_root": self.custody_epoch_root,
            "committee_root": self.committee_root,
            "attestation_root": self.attestation_root,
            "finality_ticket_root": self.finality_ticket_root,
            "reserve_proof_root": self.reserve_proof_root,
            "bridge_claim_root": self.bridge_claim_root,
            "withdrawal_root": self.withdrawal_root,
            "escape_manifest_root": self.escape_manifest_root,
            "fee_sponsorship_root": self.fee_sponsorship_root,
            "privacy_accounting_root": self.privacy_accounting_root,
            "slashing_evidence_root": self.slashing_evidence_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub stake_commitment: String,
    pub security_bits: u16,
    pub weight: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl PqCommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "stake_commitment": self.stake_commitment,
            "security_bits": self.security_bits,
            "weight": self.weight,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommittee {
    pub committee_id: String,
    pub epoch_id: String,
    pub status: CommitteeStatus,
    pub threshold: usize,
    pub aggregate_key_root: String,
    pub member_ids: Vec<String>,
    pub created_height: u64,
    pub rotation_height: u64,
}

impl PqCommittee {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "threshold": self.threshold,
            "aggregate_key_root": self.aggregate_key_root,
            "member_ids": self.member_ids,
            "member_count": self.member_ids.len(),
            "created_height": self.created_height,
            "rotation_height": self.rotation_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyEpoch {
    pub epoch_id: String,
    pub index: u64,
    pub status: CustodyEpochStatus,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub custody_commitment_root: String,
    pub reserve_root: String,
    pub withdrawal_queue_root: String,
    pub bridge_liquidity_root: String,
    pub committee_id: String,
    pub finalized_ticket_id: Option<String>,
}

impl CustodyEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "index": self.index,
            "status": self.status.as_str(),
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "custody_commitment_root": self.custody_commitment_root,
            "reserve_root": self.reserve_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "bridge_liquidity_root": self.bridge_liquidity_root,
            "committee_id": self.committee_id,
            "finalized_ticket_id": self.finalized_ticket_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCommitmentRequest {
    pub epoch_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub custody_commitment_root: String,
    pub reserve_root: String,
    pub withdrawal_queue_root: String,
    pub bridge_liquidity_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttestationRequest {
    pub committee_id: String,
    pub epoch_id: String,
    pub kind: AttestationKind,
    pub subject_root: String,
    pub signer_ids: Vec<String>,
    pub aggregate_signature_root: String,
    pub public_input_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub epoch_id: String,
    pub kind: AttestationKind,
    pub subject_root: String,
    pub signer_ids: Vec<String>,
    pub aggregate_signature_root: String,
    pub public_input_root: String,
    pub height: u64,
    pub signer_threshold: usize,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "epoch_id": self.epoch_id,
            "kind": self.kind.as_str(),
            "subject_root": self.subject_root,
            "signer_ids": self.signer_ids,
            "signer_count": self.signer_ids.len(),
            "aggregate_signature_root": self.aggregate_signature_root,
            "public_input_root": self.public_input_root,
            "height": self.height,
            "signer_threshold": self.signer_threshold,
            "pq_attestation_scheme": PQ_ATTESTATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityTicketRequest {
    pub epoch_id: String,
    pub l2_block_height: u64,
    pub previous_state_root: String,
    pub proposed_state_root: String,
    pub tx_batch_root: String,
    pub da_root: String,
    pub max_fee_bps: u64,
    pub attestation_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityTicket {
    pub ticket_id: String,
    pub epoch_id: String,
    pub status: FinalityTicketStatus,
    pub l2_block_height: u64,
    pub previous_state_root: String,
    pub proposed_state_root: String,
    pub tx_batch_root: String,
    pub da_root: String,
    pub max_fee_bps: u64,
    pub attestation_ids: Vec<String>,
    pub created_height: u64,
    pub execute_after_height: u64,
}

impl FastFinalityTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "l2_block_height": self.l2_block_height,
            "previous_state_root": self.previous_state_root,
            "proposed_state_root": self.proposed_state_root,
            "tx_batch_root": self.tx_batch_root,
            "da_root": self.da_root,
            "max_fee_bps": self.max_fee_bps,
            "attestation_ids": self.attestation_ids,
            "attestation_count": self.attestation_ids.len(),
            "created_height": self.created_height,
            "execute_after_height": self.execute_after_height,
            "fast_finality_scheme": FAST_FINALITY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateReserveProofRequest {
    pub epoch_id: String,
    pub vault_commitment: String,
    pub asset_id: String,
    pub reserve_amount_commitment: String,
    pub liability_amount_commitment: String,
    pub monero_output_set_root: String,
    pub proof_root: String,
    pub verifier_key_root: String,
    pub privacy_set_size: u64,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateReserveProof {
    pub proof_id: String,
    pub epoch_id: String,
    pub status: ReserveProofStatus,
    pub vault_commitment: String,
    pub asset_id: String,
    pub reserve_amount_commitment: String,
    pub liability_amount_commitment: String,
    pub monero_output_set_root: String,
    pub proof_root: String,
    pub verifier_key_root: String,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PrivateReserveProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "vault_commitment": self.vault_commitment,
            "asset_id": self.asset_id,
            "reserve_amount_commitment": self.reserve_amount_commitment,
            "liability_amount_commitment": self.liability_amount_commitment,
            "monero_output_set_root": self.monero_output_set_root,
            "proof_root": self.proof_root,
            "verifier_key_root": self.verifier_key_root,
            "privacy_set_size": self.privacy_set_size,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "reserve_proof_scheme": RESERVE_PROOF_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquidityClaimRequest {
    pub epoch_id: String,
    pub claimant_commitment: String,
    pub liquidity_pool_id: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub route_root: String,
    pub fee_commitment: String,
    pub proof_root: String,
    pub ttl_blocks: u64,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquidityClaim {
    pub claim_id: String,
    pub epoch_id: String,
    pub status: BridgeClaimStatus,
    pub claimant_commitment: String,
    pub liquidity_pool_id: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub route_root: String,
    pub fee_commitment: String,
    pub proof_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl BridgeLiquidityClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "claimant_commitment": self.claimant_commitment,
            "liquidity_pool_id": self.liquidity_pool_id,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "route_root": self.route_root,
            "fee_commitment": self.fee_commitment,
            "proof_root": self.proof_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedWithdrawalRequest {
    pub epoch_id: String,
    pub owner_commitment: String,
    pub destination_commitment: String,
    pub amount_commitment: String,
    pub nullifier_root: String,
    pub reserve_proof_id: String,
    pub safety_proof_root: String,
    pub fee_sponsor_id: Option<String>,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedWithdrawal {
    pub withdrawal_id: String,
    pub epoch_id: String,
    pub status: WithdrawalStatus,
    pub owner_commitment: String,
    pub destination_commitment: String,
    pub amount_commitment: String,
    pub nullifier_root: String,
    pub reserve_proof_id: String,
    pub safety_proof_root: String,
    pub fee_sponsor_id: Option<String>,
    pub requested_height: u64,
    pub release_height: u64,
    pub released_ticket_id: Option<String>,
}

impl DelayedWithdrawal {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "destination_commitment": self.destination_commitment,
            "amount_commitment": self.amount_commitment,
            "nullifier_root": self.nullifier_root,
            "reserve_proof_id": self.reserve_proof_id,
            "safety_proof_root": self.safety_proof_root,
            "fee_sponsor_id": self.fee_sponsor_id,
            "requested_height": self.requested_height,
            "release_height": self.release_height,
            "released_ticket_id": self.released_ticket_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyEscapeManifestRequest {
    pub epoch_id: String,
    pub publisher_commitment: String,
    pub affected_withdrawal_ids: Vec<String>,
    pub escape_root: String,
    pub monero_sweep_root: String,
    pub privacy_preserving_notice_root: String,
    pub attestation_ids: Vec<String>,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyEscapeManifest {
    pub manifest_id: String,
    pub epoch_id: String,
    pub status: EscapeStatus,
    pub publisher_commitment: String,
    pub affected_withdrawal_ids: Vec<String>,
    pub escape_root: String,
    pub monero_sweep_root: String,
    pub privacy_preserving_notice_root: String,
    pub attestation_ids: Vec<String>,
    pub published_height: u64,
    pub executable_height: u64,
}

impl EmergencyEscapeManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "publisher_commitment": self.publisher_commitment,
            "affected_withdrawal_ids": self.affected_withdrawal_ids,
            "affected_withdrawal_count": self.affected_withdrawal_ids.len(),
            "escape_root": self.escape_root,
            "monero_sweep_root": self.monero_sweep_root,
            "privacy_preserving_notice_root": self.privacy_preserving_notice_root,
            "attestation_ids": self.attestation_ids,
            "published_height": self.published_height,
            "executable_height": self.executable_height,
            "escape_manifest_scheme": ESCAPE_MANIFEST_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorshipRequest {
    pub sponsor_commitment: String,
    pub beneficiary_root: String,
    pub asset_id: String,
    pub budget_commitment: String,
    pub max_fee_per_action: u64,
    pub privacy_set_size: u64,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorship {
    pub sponsor_id: String,
    pub status: SponsorshipStatus,
    pub sponsor_commitment: String,
    pub beneficiary_root: String,
    pub asset_id: String,
    pub budget_commitment: String,
    pub spent_commitment: String,
    pub max_fee_per_action: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub use_count: u64,
}

impl FeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_root": self.beneficiary_root,
            "asset_id": self.asset_id,
            "budget_commitment": self.budget_commitment,
            "spent_commitment": self.spent_commitment,
            "max_fee_per_action": self.max_fee_per_action,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "use_count": self.use_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAccountingEvent {
    pub event_id: String,
    pub kind: PrivacyEventKind,
    pub subject_id: String,
    pub epoch_id: String,
    pub privacy_set_size: u64,
    pub disclosure_budget_used: u64,
    pub public_signal_root: String,
    pub witness_commitment_root: String,
    pub height: u64,
}

impl PrivacyAccountingEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "epoch_id": self.epoch_id,
            "privacy_set_size": self.privacy_set_size,
            "disclosure_budget_used": self.disclosure_budget_used,
            "public_signal_root": self.public_signal_root,
            "witness_commitment_root": self.witness_commitment_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidenceRequest {
    pub accused_commitment: String,
    pub reporter_commitment: String,
    pub reason: SlashingReason,
    pub subject_id: String,
    pub evidence_root: String,
    pub penalty_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub accused_commitment: String,
    pub reporter_commitment: String,
    pub reason: SlashingReason,
    pub subject_id: String,
    pub evidence_root: String,
    pub penalty_commitment: String,
    pub accepted: bool,
    pub height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "accused_commitment": self.accused_commitment,
            "reporter_commitment": self.reporter_commitment,
            "reason": self.reason.as_str(),
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "penalty_commitment": self.penalty_commitment,
            "accepted": self.accepted,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_monero_height: u64,
    pub custody_epochs: BTreeMap<String, CustodyEpoch>,
    pub committee_members: BTreeMap<String, PqCommitteeMember>,
    pub committees: BTreeMap<String, PqCommittee>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub finality_tickets: BTreeMap<String, FastFinalityTicket>,
    pub reserve_proofs: BTreeMap<String, PrivateReserveProof>,
    pub bridge_claims: BTreeMap<String, BridgeLiquidityClaim>,
    pub delayed_withdrawals: BTreeMap<String, DelayedWithdrawal>,
    pub escape_manifests: BTreeMap<String, EmergencyEscapeManifest>,
    pub fee_sponsorships: BTreeMap<String, FeeSponsorship>,
    pub privacy_events: BTreeMap<String, PrivacyAccountingEvent>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub consumed_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height: 0,
            current_monero_height: 0,
            custody_epochs: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            committees: BTreeMap::new(),
            attestations: BTreeMap::new(),
            finality_tickets: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            bridge_claims: BTreeMap::new(),
            delayed_withdrawals: BTreeMap::new(),
            escape_manifests: BTreeMap::new(),
            fee_sponsorships: BTreeMap::new(),
            privacy_events: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet config");
        state.current_height = 1;
        state.current_monero_height = 1_000;

        for label in ["alpha", "beta", "gamma", "delta"] {
            let member = PqCommitteeMember {
                member_id: deterministic_id("COMMITTEE-MEMBER", &[label]),
                operator_commitment: deterministic_id("OPERATOR", &[label]),
                pq_public_key_root: deterministic_id("PQ-PUBLIC-KEY", &[label]),
                stake_commitment: deterministic_id("STAKE", &[label, "devnet"]),
                security_bits: 256,
                weight: 1,
                active_from_height: 1,
                active_until_height: 10_000,
            };
            state
                .committee_members
                .insert(member.member_id.clone(), member);
        }

        let epoch_id = deterministic_id("CUSTODY-EPOCH", &["devnet", "0"]);
        let member_ids = state.committee_members.keys().cloned().collect::<Vec<_>>();
        let committee_id = deterministic_id("COMMITTEE", &[&epoch_id, "genesis"]);
        let aggregate_key_root = list_root("DEVNET-AGGREGATE-KEY", &member_ids);
        state.committees.insert(
            committee_id.clone(),
            PqCommittee {
                committee_id: committee_id.clone(),
                epoch_id: epoch_id.clone(),
                status: CommitteeStatus::Active,
                threshold: state.config.pq_quorum_threshold,
                aggregate_key_root,
                member_ids,
                created_height: 1,
                rotation_height: 721,
            },
        );
        state.custody_epochs.insert(
            epoch_id.clone(),
            CustodyEpoch {
                epoch_id,
                index: 0,
                status: CustodyEpochStatus::Open,
                monero_start_height: state.current_monero_height,
                monero_end_height: state.current_monero_height + state.config.epoch_length_blocks,
                l2_start_height: state.current_height,
                l2_end_height: state.current_height + state.config.epoch_length_blocks,
                custody_commitment_root: deterministic_id("CUSTODY-COMMITMENT", &["genesis"]),
                reserve_root: deterministic_id("RESERVE-ROOT", &["genesis"]),
                withdrawal_queue_root: deterministic_id("WITHDRAWAL-QUEUE", &["empty"]),
                bridge_liquidity_root: deterministic_id("BRIDGE-LIQUIDITY", &["genesis"]),
                committee_id,
                finalized_ticket_id: None,
            },
        );
        state
    }

    pub fn advance_height(&mut self, l2_height: u64, monero_height: u64) -> Result<()> {
        if l2_height < self.current_height {
            return Err("cannot move L2 height backwards".to_string());
        }
        if monero_height < self.current_monero_height {
            return Err("cannot move Monero height backwards".to_string());
        }
        self.current_height = l2_height;
        self.current_monero_height = monero_height;
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            custody_epochs: self.custody_epochs.len() as u64,
            committees: self.committees.len() as u64,
            attestations: self.attestations.len() as u64,
            finality_tickets: self.finality_tickets.len() as u64,
            reserve_proofs: self.reserve_proofs.len() as u64,
            bridge_claims: self.bridge_claims.len() as u64,
            withdrawals: self.delayed_withdrawals.len() as u64,
            escape_manifests: self.escape_manifests.len() as u64,
            fee_sponsorships: self.fee_sponsorships.len() as u64,
            privacy_events: self.privacy_events.len() as u64,
            slashing_events: self.slashing_evidence.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: value_root("CONFIG", &self.config.public_record()),
            custody_epoch_root: map_root("CUSTODY-EPOCHS", &self.custody_epochs, |v| {
                v.public_record()
            }),
            committee_root: value_root(
                "COMMITTEES",
                &json!({
                    "members": map_records(&self.committee_members, |v| v.public_record()),
                    "committees": map_records(&self.committees, |v| v.public_record()),
                }),
            ),
            attestation_root: map_root("PQ-ATTESTATIONS", &self.attestations, |v| {
                v.public_record()
            }),
            finality_ticket_root: map_root("FAST-FINALITY-TICKETS", &self.finality_tickets, |v| {
                v.public_record()
            }),
            reserve_proof_root: map_root("PRIVATE-RESERVE-PROOFS", &self.reserve_proofs, |v| {
                v.public_record()
            }),
            bridge_claim_root: map_root("BRIDGE-LIQUIDITY-CLAIMS", &self.bridge_claims, |v| {
                v.public_record()
            }),
            withdrawal_root: map_root("DELAYED-WITHDRAWALS", &self.delayed_withdrawals, |v| {
                v.public_record()
            }),
            escape_manifest_root: map_root("EMERGENCY-ESCAPES", &self.escape_manifests, |v| {
                v.public_record()
            }),
            fee_sponsorship_root: map_root("FEE-SPONSORSHIPS", &self.fee_sponsorships, |v| {
                v.public_record()
            }),
            privacy_accounting_root: map_root("PRIVACY-ACCOUNTING", &self.privacy_events, |v| {
                v.public_record()
            }),
            slashing_evidence_root: map_root("SLASHING-EVIDENCE", &self.slashing_evidence, |v| {
                v.public_record()
            }),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "current_monero_height": self.current_monero_height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "consumed_nullifier_root": set_root("CONSUMED-NULLIFIERS", &self.consumed_nullifier_roots),
        })
    }

    pub fn public_record(&self) -> Value {
        json_insert(
            self.public_record_without_root(),
            "state_root",
            json!(self.state_root()),
        )
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn start_custody_epoch(
        &mut self,
        index: u64,
        monero_start_height: u64,
        l2_start_height: u64,
        committee_id: impl Into<String>,
    ) -> Result<CustodyEpoch> {
        let committee_id = committee_id.into();
        let committee = self
            .committees
            .get(&committee_id)
            .ok_or_else(|| "committee not found for custody epoch".to_string())?;
        if !committee.status.can_attest() {
            return Err("committee cannot attest new epoch".to_string());
        }
        let epoch_id = deterministic_id("CUSTODY-EPOCH", &[&index.to_string(), &committee_id]);
        if self.custody_epochs.contains_key(&epoch_id) {
            return Err("custody epoch already exists".to_string());
        }
        let epoch = CustodyEpoch {
            epoch_id: epoch_id.clone(),
            index,
            status: CustodyEpochStatus::Open,
            monero_start_height,
            monero_end_height: monero_start_height + self.config.epoch_length_blocks,
            l2_start_height,
            l2_end_height: l2_start_height + self.config.epoch_length_blocks,
            custody_commitment_root: deterministic_id("CUSTODY-COMMITMENT", &[&epoch_id, "open"]),
            reserve_root: deterministic_id("RESERVE-ROOT", &[&epoch_id, "open"]),
            withdrawal_queue_root: deterministic_id("WITHDRAWAL-QUEUE", &[&epoch_id, "empty"]),
            bridge_liquidity_root: deterministic_id("BRIDGE-LIQUIDITY", &[&epoch_id, "open"]),
            committee_id,
            finalized_ticket_id: None,
        };
        self.custody_epochs.insert(epoch_id, epoch.clone());
        Ok(epoch)
    }

    pub fn record_epoch_commitment(
        &mut self,
        request: EpochCommitmentRequest,
    ) -> Result<CustodyEpoch> {
        ensure_non_empty(&request.custody_commitment_root, "custody commitment root")?;
        ensure_non_empty(&request.reserve_root, "reserve root")?;
        ensure_non_empty(&request.withdrawal_queue_root, "withdrawal queue root")?;
        ensure_non_empty(&request.bridge_liquidity_root, "bridge liquidity root")?;
        let epoch = self
            .custody_epochs
            .get_mut(&request.epoch_id)
            .ok_or_else(|| "custody epoch not found".to_string())?;
        if !epoch.status.accepts_commitments() {
            return Err("custody epoch no longer accepts commitments".to_string());
        }
        if request.monero_height < epoch.monero_start_height
            || request.l2_height < epoch.l2_start_height
        {
            return Err("epoch commitment height is before epoch start".to_string());
        }
        epoch.status = CustodyEpochStatus::Committing;
        epoch.custody_commitment_root = request.custody_commitment_root;
        epoch.reserve_root = request.reserve_root;
        epoch.withdrawal_queue_root = request.withdrawal_queue_root;
        epoch.bridge_liquidity_root = request.bridge_liquidity_root;
        epoch.monero_end_height = epoch.monero_end_height.max(request.monero_height);
        epoch.l2_end_height = epoch.l2_end_height.max(request.l2_height);
        Ok(epoch.clone())
    }

    pub fn record_pq_attestation(
        &mut self,
        request: PqAttestationRequest,
    ) -> Result<PqAttestation> {
        ensure_non_empty(&request.subject_root, "attestation subject root")?;
        ensure_non_empty(
            &request.aggregate_signature_root,
            "aggregate signature root",
        )?;
        ensure_non_empty(&request.public_input_root, "public input root")?;
        let committee = self
            .committees
            .get(&request.committee_id)
            .ok_or_else(|| "PQ committee not found".to_string())?;
        if !committee.status.can_attest() {
            return Err("PQ committee cannot attest".to_string());
        }
        if committee.epoch_id != request.epoch_id {
            return Err("attestation epoch does not match committee epoch".to_string());
        }
        let signer_set = request.signer_ids.iter().cloned().collect::<BTreeSet<_>>();
        if signer_set.len() < committee.threshold {
            return Err("attestation signer set below threshold".to_string());
        }
        for signer_id in &signer_set {
            if !committee.member_ids.contains(signer_id) {
                return Err("attestation signer is not in committee".to_string());
            }
            let member = self
                .committee_members
                .get(signer_id)
                .ok_or_else(|| "attestation signer member missing".to_string())?;
            if member.security_bits < self.config.min_pq_security_bits {
                return Err("attestation signer below PQ security floor".to_string());
            }
        }
        let sorted_signers = signer_set.into_iter().collect::<Vec<_>>();
        let attestation_id = deterministic_id(
            "PQ-ATTESTATION",
            &[
                &request.committee_id,
                &request.epoch_id,
                request.kind.as_str(),
                &request.subject_root,
                &request.height.to_string(),
            ],
        );
        let attestation = PqAttestation {
            attestation_id: attestation_id.clone(),
            committee_id: request.committee_id,
            epoch_id: request.epoch_id.clone(),
            kind: request.kind,
            subject_root: request.subject_root,
            signer_ids: sorted_signers,
            aggregate_signature_root: request.aggregate_signature_root,
            public_input_root: request.public_input_root,
            height: request.height,
            signer_threshold: committee.threshold,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        if let Some(epoch) = self.custody_epochs.get_mut(&request.epoch_id) {
            if matches!(request.kind, AttestationKind::CustodyEpoch) {
                epoch.status = CustodyEpochStatus::Attested;
            }
        }
        Ok(attestation)
    }

    pub fn propose_fast_finality_ticket(
        &mut self,
        request: FastFinalityTicketRequest,
    ) -> Result<FastFinalityTicket> {
        ensure_non_empty(&request.previous_state_root, "previous state root")?;
        ensure_non_empty(&request.proposed_state_root, "proposed state root")?;
        ensure_non_empty(&request.tx_batch_root, "transaction batch root")?;
        ensure_non_empty(&request.da_root, "data availability root")?;
        if request.max_fee_bps > self.config.max_fee_bps {
            return Err("fast finality ticket exceeds fee ceiling".to_string());
        }
        let epoch = self
            .custody_epochs
            .get(&request.epoch_id)
            .ok_or_else(|| "fast finality epoch not found".to_string())?;
        let mut custody_attestations = 0_usize;
        for attestation_id in &request.attestation_ids {
            let attestation = self
                .attestations
                .get(attestation_id)
                .ok_or_else(|| "fast finality attestation missing".to_string())?;
            if attestation.epoch_id != request.epoch_id {
                return Err("fast finality attestation epoch mismatch".to_string());
            }
            if matches!(
                attestation.kind,
                AttestationKind::CustodyEpoch | AttestationKind::FastFinality
            ) {
                custody_attestations += 1;
            }
        }
        if custody_attestations == 0 {
            return Err("fast finality ticket needs custody or finality attestation".to_string());
        }
        let ticket_id = deterministic_id(
            "FAST-FINALITY-TICKET",
            &[
                &request.epoch_id,
                &request.l2_block_height.to_string(),
                &request.proposed_state_root,
            ],
        );
        let status = if request.attestation_ids.len() >= self.config.pq_quorum_threshold {
            FinalityTicketStatus::QuorumCertified
        } else {
            FinalityTicketStatus::Proposed
        };
        let ticket = FastFinalityTicket {
            ticket_id: ticket_id.clone(),
            epoch_id: request.epoch_id,
            status,
            l2_block_height: request.l2_block_height,
            previous_state_root: request.previous_state_root,
            proposed_state_root: request.proposed_state_root,
            tx_batch_root: request.tx_batch_root,
            da_root: request.da_root,
            max_fee_bps: request.max_fee_bps,
            attestation_ids: request.attestation_ids,
            created_height: self.current_height.max(epoch.l2_start_height),
            execute_after_height: self.current_height + self.config.fast_finality_blocks,
        };
        self.finality_tickets.insert(ticket_id, ticket.clone());
        Ok(ticket)
    }

    pub fn execute_fast_finality_ticket(&mut self, ticket_id: &str) -> Result<FastFinalityTicket> {
        let ticket = self
            .finality_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "fast finality ticket not found".to_string())?;
        if ticket.status != FinalityTicketStatus::QuorumCertified {
            return Err("fast finality ticket is not quorum certified".to_string());
        }
        if self.current_height < ticket.execute_after_height {
            return Err("fast finality delay has not elapsed".to_string());
        }
        ticket.status = FinalityTicketStatus::Executed;
        if let Some(epoch) = self.custody_epochs.get_mut(&ticket.epoch_id) {
            epoch.status = CustodyEpochStatus::Finalized;
            epoch.finalized_ticket_id = Some(ticket.ticket_id.clone());
        }
        Ok(ticket.clone())
    }

    pub fn submit_private_reserve_proof(
        &mut self,
        request: PrivateReserveProofRequest,
    ) -> Result<PrivateReserveProof> {
        ensure_non_empty(&request.vault_commitment, "vault commitment")?;
        ensure_non_empty(
            &request.reserve_amount_commitment,
            "reserve amount commitment",
        )?;
        ensure_non_empty(
            &request.liability_amount_commitment,
            "liability amount commitment",
        )?;
        ensure_non_empty(&request.monero_output_set_root, "monero output set root")?;
        ensure_non_empty(&request.proof_root, "reserve proof root")?;
        ensure_non_empty(&request.verifier_key_root, "reserve verifier key root")?;
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("reserve proof privacy set too small".to_string());
        }
        self.require_epoch(&request.epoch_id)?;
        let proof_id = deterministic_id(
            "PRIVATE-RESERVE-PROOF",
            &[
                &request.epoch_id,
                &request.vault_commitment,
                &request.monero_output_set_root,
                &request.height.to_string(),
            ],
        );
        let proof = PrivateReserveProof {
            proof_id: proof_id.clone(),
            epoch_id: request.epoch_id.clone(),
            status: ReserveProofStatus::Verified,
            vault_commitment: request.vault_commitment,
            asset_id: request.asset_id,
            reserve_amount_commitment: request.reserve_amount_commitment,
            liability_amount_commitment: request.liability_amount_commitment,
            monero_output_set_root: request.monero_output_set_root,
            proof_root: request.proof_root,
            verifier_key_root: request.verifier_key_root,
            privacy_set_size: request.privacy_set_size,
            submitted_height: request.height,
            expires_height: request.height + self.config.reserve_proof_ttl_blocks,
        };
        self.reserve_proofs.insert(proof_id.clone(), proof.clone());
        self.record_privacy_event(
            PrivacyEventKind::ReserveProof,
            proof_id,
            request.epoch_id,
            request.privacy_set_size,
            1,
            proof.proof_root.clone(),
            proof.monero_output_set_root.clone(),
            request.height,
        )?;
        Ok(proof)
    }

    pub fn submit_bridge_liquidity_claim(
        &mut self,
        request: BridgeLiquidityClaimRequest,
    ) -> Result<BridgeLiquidityClaim> {
        ensure_non_empty(&request.claimant_commitment, "claimant commitment")?;
        ensure_non_empty(&request.liquidity_pool_id, "liquidity pool id")?;
        ensure_non_empty(&request.amount_commitment, "bridge claim amount commitment")?;
        ensure_non_empty(&request.route_root, "bridge route root")?;
        ensure_non_empty(&request.fee_commitment, "bridge fee commitment")?;
        ensure_non_empty(&request.proof_root, "bridge proof root")?;
        self.require_epoch(&request.epoch_id)?;
        if request.ttl_blocks == 0 || request.ttl_blocks > self.config.max_bridge_claim_ttl_blocks {
            return Err("bridge claim ttl is outside policy".to_string());
        }
        let claim_id = deterministic_id(
            "BRIDGE-LIQUIDITY-CLAIM",
            &[
                &request.epoch_id,
                &request.claimant_commitment,
                &request.liquidity_pool_id,
                &request.height.to_string(),
            ],
        );
        let claim = BridgeLiquidityClaim {
            claim_id: claim_id.clone(),
            epoch_id: request.epoch_id.clone(),
            status: BridgeClaimStatus::Open,
            claimant_commitment: request.claimant_commitment,
            liquidity_pool_id: request.liquidity_pool_id,
            asset_id: request.asset_id,
            amount_commitment: request.amount_commitment,
            route_root: request.route_root,
            fee_commitment: request.fee_commitment,
            proof_root: request.proof_root.clone(),
            created_height: request.height,
            expires_height: request.height + request.ttl_blocks,
        };
        self.bridge_claims.insert(claim_id.clone(), claim.clone());
        self.record_privacy_event(
            PrivacyEventKind::BridgeClaim,
            claim_id,
            request.epoch_id,
            self.config.min_privacy_set,
            1,
            request.proof_root,
            claim.route_root.clone(),
            request.height,
        )?;
        Ok(claim)
    }

    pub fn update_bridge_claim_status(
        &mut self,
        claim_id: &str,
        status: BridgeClaimStatus,
    ) -> Result<BridgeLiquidityClaim> {
        let claim = self
            .bridge_claims
            .get_mut(claim_id)
            .ok_or_else(|| "bridge claim not found".to_string())?;
        if self.current_height > claim.expires_height
            && !matches!(status, BridgeClaimStatus::Expired)
        {
            return Err("bridge claim expired before requested status update".to_string());
        }
        claim.status = status;
        Ok(claim.clone())
    }

    pub fn request_delayed_withdrawal(
        &mut self,
        request: DelayedWithdrawalRequest,
    ) -> Result<DelayedWithdrawal> {
        ensure_non_empty(&request.owner_commitment, "withdrawal owner commitment")?;
        ensure_non_empty(
            &request.destination_commitment,
            "withdrawal destination commitment",
        )?;
        ensure_non_empty(&request.amount_commitment, "withdrawal amount commitment")?;
        ensure_non_empty(&request.nullifier_root, "withdrawal nullifier root")?;
        ensure_non_empty(&request.safety_proof_root, "withdrawal safety proof root")?;
        self.require_epoch(&request.epoch_id)?;
        let reserve = self
            .reserve_proofs
            .get(&request.reserve_proof_id)
            .ok_or_else(|| "withdrawal reserve proof not found".to_string())?;
        if reserve.status != ReserveProofStatus::Verified {
            return Err("withdrawal reserve proof is not verified".to_string());
        }
        if reserve.expires_height < request.height {
            return Err("withdrawal reserve proof has expired".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
        {
            return Err("withdrawal nullifier root already consumed".to_string());
        }
        if let Some(sponsor_id) = &request.fee_sponsor_id {
            self.spend_fee_sponsorship(sponsor_id, request.height)?;
        }
        let withdrawal_id = deterministic_id(
            "DELAYED-WITHDRAWAL",
            &[
                &request.epoch_id,
                &request.owner_commitment,
                &request.nullifier_root,
                &request.height.to_string(),
            ],
        );
        let withdrawal = DelayedWithdrawal {
            withdrawal_id: withdrawal_id.clone(),
            epoch_id: request.epoch_id.clone(),
            status: WithdrawalStatus::DelayLocked,
            owner_commitment: request.owner_commitment,
            destination_commitment: request.destination_commitment,
            amount_commitment: request.amount_commitment,
            nullifier_root: request.nullifier_root.clone(),
            reserve_proof_id: request.reserve_proof_id,
            safety_proof_root: request.safety_proof_root.clone(),
            fee_sponsor_id: request.fee_sponsor_id,
            requested_height: request.height,
            release_height: request.height + self.config.withdrawal_delay_blocks,
            released_ticket_id: None,
        };
        self.consumed_nullifier_roots
            .insert(request.nullifier_root.clone());
        self.delayed_withdrawals
            .insert(withdrawal_id.clone(), withdrawal.clone());
        self.record_privacy_event(
            PrivacyEventKind::Withdrawal,
            withdrawal_id,
            request.epoch_id,
            self.config.min_privacy_set,
            2,
            request.safety_proof_root,
            request.nullifier_root,
            request.height,
        )?;
        Ok(withdrawal)
    }

    pub fn release_delayed_withdrawal(
        &mut self,
        withdrawal_id: &str,
        ticket_id: &str,
    ) -> Result<DelayedWithdrawal> {
        let ticket = self
            .finality_tickets
            .get(ticket_id)
            .ok_or_else(|| "withdrawal release ticket not found".to_string())?;
        if ticket.status != FinalityTicketStatus::Executed {
            return Err("withdrawal release requires executed finality ticket".to_string());
        }
        let withdrawal = self
            .delayed_withdrawals
            .get_mut(withdrawal_id)
            .ok_or_else(|| "withdrawal not found".to_string())?;
        if self.current_height < withdrawal.release_height {
            return Err("withdrawal delay has not elapsed".to_string());
        }
        if withdrawal.epoch_id != ticket.epoch_id {
            return Err("withdrawal ticket epoch mismatch".to_string());
        }
        withdrawal.status = WithdrawalStatus::Released;
        withdrawal.released_ticket_id = Some(ticket_id.to_string());
        Ok(withdrawal.clone())
    }

    pub fn publish_escape_manifest(
        &mut self,
        request: EmergencyEscapeManifestRequest,
    ) -> Result<EmergencyEscapeManifest> {
        ensure_non_empty(&request.publisher_commitment, "escape publisher commitment")?;
        ensure_non_empty(&request.escape_root, "escape root")?;
        ensure_non_empty(&request.monero_sweep_root, "monero sweep root")?;
        ensure_non_empty(
            &request.privacy_preserving_notice_root,
            "privacy preserving notice root",
        )?;
        self.require_epoch(&request.epoch_id)?;
        if request.affected_withdrawal_ids.is_empty() {
            return Err("escape manifest needs affected withdrawals".to_string());
        }
        for withdrawal_id in &request.affected_withdrawal_ids {
            let withdrawal = self
                .delayed_withdrawals
                .get(withdrawal_id)
                .ok_or_else(|| "escape manifest withdrawal missing".to_string())?;
            if withdrawal.epoch_id != request.epoch_id {
                return Err("escape manifest withdrawal epoch mismatch".to_string());
            }
        }
        for attestation_id in &request.attestation_ids {
            let attestation = self
                .attestations
                .get(attestation_id)
                .ok_or_else(|| "escape manifest attestation missing".to_string())?;
            if !matches!(attestation.kind, AttestationKind::EscapeManifest) {
                return Err("escape manifest references non-escape attestation".to_string());
            }
        }
        let manifest_id = deterministic_id(
            "EMERGENCY-ESCAPE-MANIFEST",
            &[
                &request.epoch_id,
                &request.escape_root,
                &request.height.to_string(),
            ],
        );
        let manifest = EmergencyEscapeManifest {
            manifest_id: manifest_id.clone(),
            epoch_id: request.epoch_id.clone(),
            status: EscapeStatus::ChallengeWindow,
            publisher_commitment: request.publisher_commitment,
            affected_withdrawal_ids: request.affected_withdrawal_ids,
            escape_root: request.escape_root.clone(),
            monero_sweep_root: request.monero_sweep_root,
            privacy_preserving_notice_root: request.privacy_preserving_notice_root,
            attestation_ids: request.attestation_ids,
            published_height: request.height,
            executable_height: request.height + self.config.escape_delay_blocks,
        };
        self.escape_manifests
            .insert(manifest_id.clone(), manifest.clone());
        if let Some(epoch) = self.custody_epochs.get_mut(&request.epoch_id) {
            epoch.status = CustodyEpochStatus::Escaping;
        }
        self.record_privacy_event(
            PrivacyEventKind::Escape,
            manifest_id,
            request.epoch_id,
            self.config.min_privacy_set,
            1,
            request.escape_root,
            manifest.privacy_preserving_notice_root.clone(),
            request.height,
        )?;
        Ok(manifest)
    }

    pub fn execute_escape_manifest(
        &mut self,
        manifest_id: &str,
    ) -> Result<EmergencyEscapeManifest> {
        let manifest = self
            .escape_manifests
            .get_mut(manifest_id)
            .ok_or_else(|| "escape manifest not found".to_string())?;
        if self.current_height < manifest.executable_height {
            return Err("escape manifest challenge window still open".to_string());
        }
        manifest.status = EscapeStatus::Executed;
        for withdrawal_id in &manifest.affected_withdrawal_ids {
            if let Some(withdrawal) = self.delayed_withdrawals.get_mut(withdrawal_id) {
                withdrawal.status = WithdrawalStatus::Escaped;
            }
        }
        Ok(manifest.clone())
    }

    pub fn create_fee_sponsorship(
        &mut self,
        request: FeeSponsorshipRequest,
    ) -> Result<FeeSponsorship> {
        ensure_non_empty(&request.sponsor_commitment, "fee sponsor commitment")?;
        ensure_non_empty(
            &request.beneficiary_root,
            "fee sponsorship beneficiary root",
        )?;
        ensure_non_empty(
            &request.budget_commitment,
            "fee sponsorship budget commitment",
        )?;
        if request.max_fee_per_action == 0
            || request.max_fee_per_action > self.config.sponsor_fee_cap
        {
            return Err("fee sponsorship action cap outside policy".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("fee sponsorship privacy set too small".to_string());
        }
        let sponsor_id = deterministic_id(
            "FEE-SPONSORSHIP",
            &[
                &request.sponsor_commitment,
                &request.beneficiary_root,
                &request.height.to_string(),
            ],
        );
        let sponsorship = FeeSponsorship {
            sponsor_id: sponsor_id.clone(),
            status: SponsorshipStatus::Active,
            sponsor_commitment: request.sponsor_commitment,
            beneficiary_root: request.beneficiary_root,
            asset_id: request.asset_id,
            budget_commitment: request.budget_commitment,
            spent_commitment: deterministic_id("FEE-SPONSORSHIP-SPENT", &[&sponsor_id, "0"]),
            max_fee_per_action: request.max_fee_per_action,
            privacy_set_size: request.privacy_set_size,
            created_height: request.height,
            use_count: 0,
        };
        self.fee_sponsorships
            .insert(sponsor_id, sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        request: SlashingEvidenceRequest,
    ) -> Result<SlashingEvidence> {
        ensure_non_empty(&request.accused_commitment, "slashing accused commitment")?;
        ensure_non_empty(&request.reporter_commitment, "slashing reporter commitment")?;
        ensure_non_empty(&request.subject_id, "slashing subject id")?;
        ensure_non_empty(&request.evidence_root, "slashing evidence root")?;
        ensure_non_empty(&request.penalty_commitment, "slashing penalty commitment")?;
        let evidence_id = deterministic_id(
            "SLASHING-EVIDENCE",
            &[
                request.reason.as_str(),
                &request.accused_commitment,
                &request.subject_id,
                &request.height.to_string(),
            ],
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            accused_commitment: request.accused_commitment,
            reporter_commitment: request.reporter_commitment,
            reason: request.reason,
            subject_id: request.subject_id.clone(),
            evidence_root: request.evidence_root.clone(),
            penalty_commitment: request.penalty_commitment,
            accepted: true,
            height: request.height,
        };
        self.slashing_evidence
            .insert(evidence_id.clone(), evidence.clone());
        self.apply_slash_marker(&evidence.subject_id, evidence.reason);
        self.record_privacy_event(
            PrivacyEventKind::Slash,
            evidence_id,
            "slashing".to_string(),
            self.config.min_privacy_set,
            1,
            request.evidence_root,
            evidence.penalty_commitment.clone(),
            request.height,
        )?;
        Ok(evidence)
    }

    pub fn expire_stale_records(&mut self) -> Vec<String> {
        let mut changed = Vec::new();
        for proof in self.reserve_proofs.values_mut() {
            if proof.status == ReserveProofStatus::Verified
                && self.current_height > proof.expires_height
            {
                proof.status = ReserveProofStatus::Stale;
                changed.push(proof.proof_id.clone());
            }
        }
        for claim in self.bridge_claims.values_mut() {
            if matches!(
                claim.status,
                BridgeClaimStatus::Open | BridgeClaimStatus::Reserved
            ) && self.current_height > claim.expires_height
            {
                claim.status = BridgeClaimStatus::Expired;
                changed.push(claim.claim_id.clone());
            }
        }
        for withdrawal in self.delayed_withdrawals.values_mut() {
            if withdrawal.status == WithdrawalStatus::DelayLocked
                && self.current_height >= withdrawal.release_height
            {
                withdrawal.status = WithdrawalStatus::ReleaseReady;
                changed.push(withdrawal.withdrawal_id.clone());
            }
        }
        for manifest in self.escape_manifests.values_mut() {
            if manifest.status == EscapeStatus::ChallengeWindow
                && self.current_height >= manifest.executable_height
            {
                manifest.status = EscapeStatus::Executable;
                changed.push(manifest.manifest_id.clone());
            }
        }
        changed
    }

    fn require_epoch(&self, epoch_id: &str) -> Result<&CustodyEpoch> {
        self.custody_epochs
            .get(epoch_id)
            .ok_or_else(|| "custody epoch not found".to_string())
    }

    fn spend_fee_sponsorship(&mut self, sponsor_id: &str, height: u64) -> Result<()> {
        let sponsorship = self
            .fee_sponsorships
            .get_mut(sponsor_id)
            .ok_or_else(|| "fee sponsorship not found".to_string())?;
        if sponsorship.status != SponsorshipStatus::Active {
            return Err("fee sponsorship is not active".to_string());
        }
        sponsorship.use_count += 1;
        sponsorship.spent_commitment = deterministic_id(
            "FEE-SPONSORSHIP-SPENT",
            &[
                sponsor_id,
                &sponsorship.use_count.to_string(),
                &height.to_string(),
            ],
        );
        if sponsorship.use_count >= self.config.sponsor_fee_cap {
            sponsorship.status = SponsorshipStatus::Throttled;
        }
        Ok(())
    }

    fn record_privacy_event(
        &mut self,
        kind: PrivacyEventKind,
        subject_id: String,
        epoch_id: String,
        privacy_set_size: u64,
        disclosure_budget_used: u64,
        public_signal_root: String,
        witness_commitment_root: String,
        height: u64,
    ) -> Result<PrivacyAccountingEvent> {
        if privacy_set_size < self.config.min_privacy_set {
            return Err("privacy accounting event below minimum set".to_string());
        }
        let event_id = deterministic_id(
            "PRIVACY-ACCOUNTING-EVENT",
            &[kind.as_str(), &subject_id, &epoch_id, &height.to_string()],
        );
        let event = PrivacyAccountingEvent {
            event_id: event_id.clone(),
            kind,
            subject_id,
            epoch_id,
            privacy_set_size,
            disclosure_budget_used,
            public_signal_root,
            witness_commitment_root,
            height,
        };
        self.privacy_events.insert(event_id, event.clone());
        Ok(event)
    }

    fn apply_slash_marker(&mut self, subject_id: &str, reason: SlashingReason) {
        if let Some(committee) = self.committees.get_mut(subject_id) {
            committee.status = CommitteeStatus::Slashed;
        }
        if let Some(ticket) = self.finality_tickets.get_mut(subject_id) {
            ticket.status = FinalityTicketStatus::Rejected;
        }
        if let Some(proof) = self.reserve_proofs.get_mut(subject_id) {
            proof.status = ReserveProofStatus::Challenged;
        }
        if let Some(claim) = self.bridge_claims.get_mut(subject_id) {
            claim.status = BridgeClaimStatus::Disputed;
        }
        if let Some(withdrawal) = self.delayed_withdrawals.get_mut(subject_id) {
            withdrawal.status = WithdrawalStatus::Slashed;
        }
        if reason == SlashingReason::EscapeObstruction {
            if let Some(manifest) = self.escape_manifests.get_mut(subject_id) {
                manifest.status = EscapeStatus::Executable;
            }
        }
    }
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-CUSTODY-FINALITY:STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_id(domain: &str, values: &[&str]) -> String {
    let joined = values.join("\u{1f}");
    domain_hash(
        &format!("MONERO-L2-PQ-PRIVATE-CUSTODY-FINALITY:{domain}:ID"),
        &[HashPart::Str(&joined)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-PRIVATE-CUSTODY-FINALITY:{domain}:ROOT"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn list_root(domain: &str, values: &[String]) -> String {
    let records = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-PRIVATE-CUSTODY-FINALITY:{domain}:LIST"),
        &records,
    )
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let records = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-PRIVATE-CUSTODY-FINALITY:{domain}:SET"),
        &records,
    )
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, mut public_record: F) -> String
where
    F: FnMut(&T) -> Value,
{
    value_root(domain, &map_records(values, |value| public_record(value)))
}

pub fn map_records<T, F>(values: &BTreeMap<String, T>, mut public_record: F) -> Value
where
    F: FnMut(&T) -> Value,
{
    let records = values
        .iter()
        .map(|(key, value)| {
            json!({
                "id": key,
                "record": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    Value::Array(records)
}

pub fn json_insert(mut value: Value, key: &str, inserted: Value) -> Value {
    if let Value::Object(ref mut map) = value {
        map.insert(key.to_string(), inserted);
    }
    value
}

pub fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
