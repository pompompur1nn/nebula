use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialSequencerBlobFeeRebateVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SEQUENCER_BLOB_FEE_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-sequencer-blob-fee-rebate-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SEQUENCER_BLOB_FEE_REBATE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_BID_SUITE: &str = "ml-kem-1024-sealed-sequencer-blob-fee-bid-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-sequencer-attestation-v1";
pub const REBATE_VAULT_SUITE: &str = "confidential-sequencer-blob-fee-rebate-vault-root-v1";
pub const SPONSOR_COUPON_SUITE: &str = "private-l2-low-fee-sponsor-coupon-root-v1";
pub const CONGESTION_SMOOTHING_SUITE: &str = "private-l2-congestion-smoothing-root-v1";
pub const LOW_FEE_BATCH_SETTLEMENT_SUITE: &str = "private-l2-low-fee-batch-settlement-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-sequencer-blob-fee-rebate-vault-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_bids_addresses_view_keys_payloads_coupons_or_secret_keys";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_VAULT_ID: &str = "private-l2-sequencer-blob-fee-rebate-vault-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "dxmr-rebate-devnet";
pub const DEVNET_HEIGHT: u64 = 3_480_000;
pub const DEVNET_EPOCH: u64 = 720;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_PROTOCOL_TAKE_BPS: u64 = 2;
pub const DEFAULT_SPONSOR_MATCH_BPS: u64 = 2_000;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 8_400;
pub const DEFAULT_BLOB_OFFSET_BPS: u64 = 6_500;
pub const DEFAULT_PROOF_OFFSET_BPS: u64 = 2_200;
pub const DEFAULT_CONGESTION_ALPHA_BPS: u64 = 1_250;
pub const DEFAULT_CONGESTION_SPIKE_CAP_BPS: u64 = 1_800;
pub const DEFAULT_BATCH_SETTLEMENT_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_CLAIM_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ATTESTATION_QUORUM: u16 = 5;
pub const DEFAULT_MAX_BIDS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 2_097_152;
pub const DEFAULT_MAX_VAULT_ENTRIES: usize = 8_388_608;
pub const DEFAULT_MAX_NULLIFIERS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobLane {
    MoneroExit,
    PrivateContractCall,
    ConfidentialDefi,
    PaymentChannel,
    WalletSync,
    BridgeProof,
    AuditProof,
    EmergencyInclusion,
}
impl BlobLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero_exit",
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialDefi => "confidential_defi",
            Self::PaymentChannel => "payment_channel",
            Self::WalletSync => "wallet_sync",
            Self::BridgeProof => "bridge_proof",
            Self::AuditProof => "audit_proof",
            Self::EmergencyInclusion => "emergency_inclusion",
        }
    }
    pub fn latency_weight(self) -> u64 {
        match self {
            Self::EmergencyInclusion => 10_000,
            Self::PaymentChannel => 8_800,
            Self::MoneroExit => 8_200,
            Self::PrivateContractCall => 7_800,
            Self::ConfidentialDefi => 7_200,
            Self::BridgeProof => 6_900,
            Self::WalletSync => 5_400,
            Self::AuditProof => 4_200,
        }
    }
    pub fn fee_cap_bps(self, config: &Config) -> u64 {
        match self {
            Self::EmergencyInclusion => config.max_user_fee_bps,
            Self::MoneroExit | Self::PaymentChannel => config.max_user_fee_bps.saturating_sub(2),
            Self::PrivateContractCall | Self::ConfidentialDefi => {
                config.max_user_fee_bps.saturating_sub(4)
            }
            Self::BridgeProof | Self::WalletSync | Self::AuditProof => {
                config.target_user_fee_bps + 4
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Eligible,
    Selected,
    OffsetApplied,
    Settled,
    Rejected,
    Expired,
    Slashed,
}
impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::OffsetApplied => "offset_applied",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Posted | Self::Eligible | Self::Selected | Self::OffsetApplied
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    SequencerIdentity,
    BlobAvailability,
    ProofCost,
    BatchInclusion,
    RebateAccounting,
    CongestionObservation,
    SponsorCouponSpend,
}
impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerIdentity => "sequencer_identity",
            Self::BlobAvailability => "blob_availability",
            Self::ProofCost => "proof_cost",
            Self::BatchInclusion => "batch_inclusion",
            Self::RebateAccounting => "rebate_accounting",
            Self::CongestionObservation => "congestion_observation",
            Self::SponsorCouponSpend => "sponsor_coupon_spend",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Applied,
    Refunded,
    Expired,
    Revoked,
}
impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Collecting,
    Netted,
    Attested,
    Settled,
    Rebated,
    Disputed,
    Expired,
}
impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Collecting => "collecting",
            Self::Netted => "netted",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultEntryKind {
    SequencerDeposit,
    UserRebateAccrual,
    BlobCostOffset,
    ProofCostOffset,
    SponsorCouponDebit,
    ProtocolFeeSkim,
    BatchSettlementCredit,
    SlashingCredit,
}
impl VaultEntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerDeposit => "sequencer_deposit",
            Self::UserRebateAccrual => "user_rebate_accrual",
            Self::BlobCostOffset => "blob_cost_offset",
            Self::ProofCostOffset => "proof_cost_offset",
            Self::SponsorCouponDebit => "sponsor_coupon_debit",
            Self::ProtocolFeeSkim => "protocol_fee_skim",
            Self::BatchSettlementCredit => "batch_settlement_credit",
            Self::SlashingCredit => "slashing_credit",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub vault_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub sealed_bid_suite: String,
    pub pq_attestation_suite: String,
    pub rebate_vault_suite: String,
    pub sponsor_coupon_suite: String,
    pub congestion_smoothing_suite: String,
    pub low_fee_batch_settlement_suite: String,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub protocol_take_bps: u64,
    pub sponsor_match_bps: u64,
    pub rebate_share_bps: u64,
    pub blob_offset_bps: u64,
    pub proof_offset_bps: u64,
    pub congestion_alpha_bps: u64,
    pub congestion_spike_cap_bps: u64,
    pub batch_settlement_window_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub rebate_claim_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_attestation_quorum: u16,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_coupons: usize,
    pub max_settlements: usize,
    pub max_vault_entries: usize,
    pub max_nullifiers: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            vault_id: DEVNET_VAULT_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            sealed_bid_suite: SEALED_BID_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            rebate_vault_suite: REBATE_VAULT_SUITE.to_string(),
            sponsor_coupon_suite: SPONSOR_COUPON_SUITE.to_string(),
            congestion_smoothing_suite: CONGESTION_SMOOTHING_SUITE.to_string(),
            low_fee_batch_settlement_suite: LOW_FEE_BATCH_SETTLEMENT_SUITE.to_string(),
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            protocol_take_bps: DEFAULT_PROTOCOL_TAKE_BPS,
            sponsor_match_bps: DEFAULT_SPONSOR_MATCH_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            blob_offset_bps: DEFAULT_BLOB_OFFSET_BPS,
            proof_offset_bps: DEFAULT_PROOF_OFFSET_BPS,
            congestion_alpha_bps: DEFAULT_CONGESTION_ALPHA_BPS,
            congestion_spike_cap_bps: DEFAULT_CONGESTION_SPIKE_CAP_BPS,
            batch_settlement_window_blocks: DEFAULT_BATCH_SETTLEMENT_WINDOW_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            rebate_claim_ttl_blocks: DEFAULT_REBATE_CLAIM_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_attestation_quorum: DEFAULT_MIN_ATTESTATION_QUORUM,
            max_bids: DEFAULT_MAX_BIDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_vault_entries: DEFAULT_MAX_VAULT_ENTRIES,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("invalid protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("invalid schema version".to_string());
        }
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target fee exceeds max fee".to_string());
        }
        if self.max_user_fee_bps > 100 {
            return Err("max fee cap is not low-fee".to_string());
        }
        for (name, value) in [
            ("protocol_take_bps", self.protocol_take_bps),
            ("sponsor_match_bps", self.sponsor_match_bps),
            ("rebate_share_bps", self.rebate_share_bps),
            ("blob_offset_bps", self.blob_offset_bps),
            ("proof_offset_bps", self.proof_offset_bps),
            ("congestion_alpha_bps", self.congestion_alpha_bps),
            ("congestion_spike_cap_bps", self.congestion_spike_cap_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{name} exceeds bps denominator"));
            }
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security floor below 192 bits".to_string());
        }
        if self.min_privacy_set_size < 16
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set target below floor".to_string());
        }
        if self.min_attestation_quorum == 0 {
            return Err("attestation quorum cannot be zero".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub bids_posted: u64,
    pub bids_selected: u64,
    pub bids_settled: u64,
    pub bids_rejected: u64,
    pub attestations_posted: u64,
    pub coupons_minted: u64,
    pub coupons_applied: u64,
    pub settlements_opened: u64,
    pub settlements_finalized: u64,
    pub vault_entries_posted: u64,
    pub nullifiers_seen: u64,
    pub congestion_observations: u64,
    pub total_blob_cost_units: u128,
    pub total_proof_cost_units: u128,
    pub total_user_fee_units: u128,
    pub total_rebate_units: u128,
    pub total_sponsor_units: u128,
    pub total_protocol_fee_units: u128,
    pub total_settled_units: u128,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({"bids_posted": self.bids_posted, "bids_selected": self.bids_selected, "bids_settled": self.bids_settled, "bids_rejected": self.bids_rejected, "attestations_posted": self.attestations_posted, "coupons_minted": self.coupons_minted, "coupons_applied": self.coupons_applied, "settlements_opened": self.settlements_opened, "settlements_finalized": self.settlements_finalized, "vault_entries_posted": self.vault_entries_posted, "nullifiers_seen": self.nullifiers_seen, "congestion_observations": self.congestion_observations, "total_blob_cost_units": self.total_blob_cost_units.to_string(), "total_proof_cost_units": self.total_proof_cost_units.to_string(), "total_user_fee_units": self.total_user_fee_units.to_string(), "total_rebate_units": self.total_rebate_units.to_string(), "total_sponsor_units": self.total_sponsor_units.to_string(), "total_protocol_fee_units": self.total_protocol_fee_units.to_string(), "total_settled_units": self.total_settled_units.to_string()})
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub bids_root: String,
    pub attestations_root: String,
    pub coupons_root: String,
    pub settlements_root: String,
    pub vault_entries_root: String,
    pub nullifiers_root: String,
    pub congestion_root: String,
    pub sequencer_scores_root: String,
    pub public_record_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({"bids_root": self.bids_root, "attestations_root": self.attestations_root, "coupons_root": self.coupons_root, "settlements_root": self.settlements_root, "vault_entries_root": self.vault_entries_root, "nullifiers_root": self.nullifiers_root, "congestion_root": self.congestion_root, "sequencer_scores_root": self.sequencer_scores_root, "public_record_root": self.public_record_root})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedBlobFeeBid {
    pub bid_id: String,
    pub sequencer_commitment: String,
    pub lane: BlobLane,
    pub sealed_fee_bid_root: String,
    pub encrypted_bid_bytes_root: String,
    pub blob_bundle_root: String,
    pub proof_bundle_root: String,
    pub max_user_fee_bps: u64,
    pub requested_blob_cost_units: u128,
    pub requested_proof_cost_units: u128,
    pub target_latency_ms: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub coupon_commitment: Option<String>,
    pub status: BidStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub selected_settlement_id: Option<String>,
}
impl SealedBlobFeeBid {
    pub fn public_record(&self) -> Value {
        json!({"bid_id": self.bid_id, "sequencer_commitment": self.sequencer_commitment, "lane": self.lane.as_str(), "sealed_fee_bid_root": self.sealed_fee_bid_root, "encrypted_bid_bytes_root": self.encrypted_bid_bytes_root, "blob_bundle_root": self.blob_bundle_root, "proof_bundle_root": self.proof_bundle_root, "max_user_fee_bps": self.max_user_fee_bps, "requested_blob_cost_units": self.requested_blob_cost_units.to_string(), "requested_proof_cost_units": self.requested_proof_cost_units.to_string(), "target_latency_ms": self.target_latency_ms, "privacy_set_size": self.privacy_set_size, "pq_security_bits": self.pq_security_bits, "coupon_commitment_root": self.coupon_commitment, "status": self.status.as_str(), "created_height": self.created_height, "expires_height": self.expires_height, "selected_settlement_id": self.selected_settlement_id})
    }
    pub fn priority_score(&self, config: &Config, congestion: u64) -> u128 {
        let fee_room = self.max_user_fee_bps.min(config.max_user_fee_bps) as u128;
        let privacy_bonus = self.privacy_set_size.min(config.target_privacy_set_size) as u128;
        let latency = self.target_latency_ms.max(1) as u128;
        let lane = self.lane.latency_weight() as u128;
        let cost = self
            .requested_blob_cost_units
            .saturating_add(self.requested_proof_cost_units)
            .max(1);
        lane.saturating_mul(1_000_000)
            .saturating_add(privacy_bonus / 64)
            .saturating_add((fee_room + 1).saturating_mul(20_000))
            .saturating_add(congestion as u128 * 10)
            .saturating_sub(cost / latency)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSequencerAttestation {
    pub attestation_id: String,
    pub sequencer_commitment: String,
    pub kind: AttestationKind,
    pub subject_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub aggregate_weight: u64,
    pub pq_security_bits: u16,
    pub observed_height: u64,
    pub expires_height: u64,
}
impl PqSequencerAttestation {
    pub fn public_record(&self) -> Value {
        json!({"attestation_id": self.attestation_id, "sequencer_commitment": self.sequencer_commitment, "kind": self.kind.as_str(), "subject_root": self.subject_root, "pq_public_key_root": self.pq_public_key_root, "signature_root": self.signature_root, "transcript_root": self.transcript_root, "aggregate_weight": self.aggregate_weight, "pq_security_bits": self.pq_security_bits, "observed_height": self.observed_height, "expires_height": self.expires_height})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCoupon {
    pub coupon_id: String,
    pub sponsor_commitment: String,
    pub coupon_commitment: String,
    pub coupon_nullifier: String,
    pub lane: BlobLane,
    pub max_discount_units: u128,
    pub match_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: CouponStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub applied_bid_id: Option<String>,
}
impl SponsorCoupon {
    pub fn public_record(&self) -> Value {
        json!({"coupon_id": self.coupon_id, "sponsor_commitment": self.sponsor_commitment, "coupon_commitment": self.coupon_commitment, "coupon_nullifier": self.coupon_nullifier, "lane": self.lane.as_str(), "max_discount_units": self.max_discount_units.to_string(), "match_bps": self.match_bps, "privacy_set_size": self.privacy_set_size, "pq_security_bits": self.pq_security_bits, "status": self.status.as_str(), "created_height": self.created_height, "expires_height": self.expires_height, "applied_bid_id": self.applied_bid_id})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionSample {
    pub sample_id: String,
    pub lane: BlobLane,
    pub blob_base_fee_units: u128,
    pub proof_base_fee_units: u128,
    pub observed_blob_bytes: u64,
    pub observed_proof_units: u64,
    pub smoothed_blob_fee_units: u128,
    pub smoothed_proof_fee_units: u128,
    pub pressure_bps: u64,
    pub observed_height: u64,
}
impl CongestionSample {
    pub fn public_record(&self) -> Value {
        json!({"sample_id": self.sample_id, "lane": self.lane.as_str(), "blob_base_fee_units": self.blob_base_fee_units.to_string(), "proof_base_fee_units": self.proof_base_fee_units.to_string(), "observed_blob_bytes": self.observed_blob_bytes, "observed_proof_units": self.observed_proof_units, "smoothed_blob_fee_units": self.smoothed_blob_fee_units.to_string(), "smoothed_proof_fee_units": self.smoothed_proof_fee_units.to_string(), "pressure_bps": self.pressure_bps, "observed_height": self.observed_height})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateVaultEntry {
    pub entry_id: String,
    pub settlement_id: String,
    pub bid_id: Option<String>,
    pub kind: VaultEntryKind,
    pub account_commitment: String,
    pub amount_units: u128,
    pub asset_id: String,
    pub note_commitment_root: String,
    pub nullifier: Option<String>,
    pub created_height: u64,
}
impl RebateVaultEntry {
    pub fn public_record(&self) -> Value {
        json!({"entry_id": self.entry_id, "settlement_id": self.settlement_id, "bid_id": self.bid_id, "kind": self.kind.as_str(), "account_commitment": self.account_commitment, "amount_units": self.amount_units.to_string(), "asset_id": self.asset_id, "note_commitment_root": self.note_commitment_root, "nullifier_root": self.nullifier, "created_height": self.created_height})
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchSettlement {
    pub settlement_id: String,
    pub lane: BlobLane,
    pub batch_root: String,
    pub selected_bid_roots: Vec<String>,
    pub attestation_roots: Vec<String>,
    pub coupon_roots: Vec<String>,
    pub total_blob_cost_units: u128,
    pub total_proof_cost_units: u128,
    pub total_user_fee_units: u128,
    pub total_sponsor_units: u128,
    pub total_rebate_units: u128,
    pub protocol_fee_units: u128,
    pub smoothed_pressure_bps: u64,
    pub status: SettlementStatus,
    pub opened_height: u64,
    pub settle_after_height: u64,
    pub settled_height: Option<u64>,
}
impl LowFeeBatchSettlement {
    pub fn public_record(&self) -> Value {
        json!({"settlement_id": self.settlement_id, "lane": self.lane.as_str(), "batch_root": self.batch_root, "selected_bid_roots_root": merkle_root("selected-bid-roots", &self.selected_bid_roots.iter().map(|v| json!(v)).collect::<Vec<_>>()), "attestation_roots_root": merkle_root("attestation-roots", &self.attestation_roots.iter().map(|v| json!(v)).collect::<Vec<_>>()), "coupon_roots_root": merkle_root("coupon-roots", &self.coupon_roots.iter().map(|v| json!(v)).collect::<Vec<_>>()), "total_blob_cost_units": self.total_blob_cost_units.to_string(), "total_proof_cost_units": self.total_proof_cost_units.to_string(), "total_user_fee_units": self.total_user_fee_units.to_string(), "total_sponsor_units": self.total_sponsor_units.to_string(), "total_rebate_units": self.total_rebate_units.to_string(), "protocol_fee_units": self.protocol_fee_units.to_string(), "smoothed_pressure_bps": self.smoothed_pressure_bps, "status": self.status.as_str(), "opened_height": self.opened_height, "settle_after_height": self.settle_after_height, "settled_height": self.settled_height})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedBidInput {
    pub sequencer_commitment: String,
    pub lane: BlobLane,
    pub sealed_fee_bid_root: String,
    pub encrypted_bid_bytes_root: String,
    pub blob_bundle_root: String,
    pub proof_bundle_root: String,
    pub max_user_fee_bps: u64,
    pub requested_blob_cost_units: u128,
    pub requested_proof_cost_units: u128,
    pub target_latency_ms: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub coupon_commitment: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationInput {
    pub sequencer_commitment: String,
    pub kind: AttestationKind,
    pub subject_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub aggregate_weight: u64,
    pub pq_security_bits: u16,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCouponInput {
    pub sponsor_commitment: String,
    pub coupon_commitment: String,
    pub coupon_nullifier: String,
    pub lane: BlobLane,
    pub max_discount_units: u128,
    pub match_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionInput {
    pub lane: BlobLane,
    pub blob_base_fee_units: u128,
    pub proof_base_fee_units: u128,
    pub observed_blob_bytes: u64,
    pub observed_proof_units: u64,
    pub pressure_bps: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementInput {
    pub lane: BlobLane,
    pub bid_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub coupon_ids: Vec<String>,
    pub batch_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub sealed_bids: BTreeMap<String, SealedBlobFeeBid>,
    pub attestations: BTreeMap<String, PqSequencerAttestation>,
    pub sponsor_coupons: BTreeMap<String, SponsorCoupon>,
    pub congestion_samples: BTreeMap<String, CongestionSample>,
    pub settlements: BTreeMap<String, LowFeeBatchSettlement>,
    pub vault_entries: BTreeMap<String, RebateVaultEntry>,
    pub nullifiers: BTreeSet<String>,
    pub sequencer_scores: BTreeMap<String, u64>,
}
impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            sealed_bids: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_coupons: BTreeMap::new(),
            congestion_samples: BTreeMap::new(),
            settlements: BTreeMap::new(),
            vault_entries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            sequencer_scores: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }
    pub fn devnet() -> Self {
        devnet()
    }
    pub fn post_sealed_bid(&mut self, input: SealedBidInput) -> Result<String> {
        self.ensure_capacity(self.sealed_bids.len(), self.config.max_bids, "sealed bids")?;
        self.validate_commitment(&input.sequencer_commitment, "sequencer commitment")?;
        self.validate_commitment(&input.sealed_fee_bid_root, "sealed fee bid root")?;
        self.validate_commitment(&input.encrypted_bid_bytes_root, "encrypted bid bytes root")?;
        self.validate_commitment(&input.blob_bundle_root, "blob bundle root")?;
        self.validate_commitment(&input.proof_bundle_root, "proof bundle root")?;
        if input.max_user_fee_bps > input.lane.fee_cap_bps(&self.config) {
            return Err("sealed bid exceeds lane fee cap".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("sealed bid privacy set below floor".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("sealed bid pq security below floor".to_string());
        }
        let id = self.derive_id(
            "sealed-bid",
            &[
                HashPart::Str(&input.sequencer_commitment),
                HashPart::Str(&input.sealed_fee_bid_root),
                HashPart::U64(self.counters.bids_posted),
            ],
        );
        let bid = SealedBlobFeeBid {
            bid_id: id.clone(),
            sequencer_commitment: input.sequencer_commitment,
            lane: input.lane,
            sealed_fee_bid_root: input.sealed_fee_bid_root,
            encrypted_bid_bytes_root: input.encrypted_bid_bytes_root,
            blob_bundle_root: input.blob_bundle_root,
            proof_bundle_root: input.proof_bundle_root,
            max_user_fee_bps: input.max_user_fee_bps,
            requested_blob_cost_units: input.requested_blob_cost_units,
            requested_proof_cost_units: input.requested_proof_cost_units,
            target_latency_ms: input.target_latency_ms.max(1),
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            coupon_commitment: input.coupon_commitment,
            status: BidStatus::Posted,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.bid_ttl_blocks),
            selected_settlement_id: None,
        };
        self.counters.bids_posted = self.counters.bids_posted.saturating_add(1);
        self.counters.total_blob_cost_units = self
            .counters
            .total_blob_cost_units
            .saturating_add(bid.requested_blob_cost_units);
        self.counters.total_proof_cost_units = self
            .counters
            .total_proof_cost_units
            .saturating_add(bid.requested_proof_cost_units);
        self.sequencer_scores
            .entry(bid.sequencer_commitment.clone())
            .or_insert(0);
        self.sealed_bids.insert(id.clone(), bid);
        self.refresh_roots();
        Ok(id)
    }
    pub fn post_pq_attestation(&mut self, input: AttestationInput) -> Result<String> {
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        self.validate_commitment(&input.sequencer_commitment, "sequencer commitment")?;
        self.validate_commitment(&input.subject_root, "subject root")?;
        self.validate_commitment(&input.pq_public_key_root, "pq public key root")?;
        self.validate_commitment(&input.signature_root, "signature root")?;
        self.validate_commitment(&input.transcript_root, "transcript root")?;
        if input.aggregate_weight < self.config.min_attestation_quorum as u64 {
            return Err("attestation quorum below floor".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("attestation pq security below floor".to_string());
        }
        let id = self.derive_id(
            "pq-attestation",
            &[
                HashPart::Str(&input.sequencer_commitment),
                HashPart::Str(&input.subject_root),
                HashPart::U64(self.counters.attestations_posted),
            ],
        );
        let attestation = PqSequencerAttestation {
            attestation_id: id.clone(),
            sequencer_commitment: input.sequencer_commitment,
            kind: input.kind,
            subject_root: input.subject_root,
            pq_public_key_root: input.pq_public_key_root,
            signature_root: input.signature_root,
            transcript_root: input.transcript_root,
            aggregate_weight: input.aggregate_weight,
            pq_security_bits: input.pq_security_bits,
            observed_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.counters.attestations_posted = self.counters.attestations_posted.saturating_add(1);
        self.bump_sequencer_score(
            &attestation.sequencer_commitment,
            attestation.aggregate_weight,
        );
        self.attestations.insert(id.clone(), attestation);
        self.refresh_roots();
        Ok(id)
    }
    pub fn mint_sponsor_coupon(&mut self, input: SponsorCouponInput) -> Result<String> {
        self.ensure_capacity(
            self.sponsor_coupons.len(),
            self.config.max_coupons,
            "sponsor coupons",
        )?;
        self.ensure_capacity(
            self.nullifiers.len(),
            self.config.max_nullifiers,
            "nullifiers",
        )?;
        self.validate_commitment(&input.sponsor_commitment, "sponsor commitment")?;
        self.validate_commitment(&input.coupon_commitment, "coupon commitment")?;
        self.validate_commitment(&input.coupon_nullifier, "coupon nullifier")?;
        if self.nullifiers.contains(&input.coupon_nullifier) {
            return Err("coupon nullifier already seen".to_string());
        }
        if input.match_bps > self.config.sponsor_match_bps || input.match_bps > MAX_BPS {
            return Err("coupon match bps exceeds cap".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("coupon privacy set below floor".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("coupon pq security below floor".to_string());
        }
        let id = self.derive_id(
            "sponsor-coupon",
            &[
                HashPart::Str(&input.sponsor_commitment),
                HashPart::Str(&input.coupon_commitment),
                HashPart::U64(self.counters.coupons_minted),
            ],
        );
        let coupon = SponsorCoupon {
            coupon_id: id.clone(),
            sponsor_commitment: input.sponsor_commitment,
            coupon_commitment: input.coupon_commitment,
            coupon_nullifier: input.coupon_nullifier.clone(),
            lane: input.lane,
            max_discount_units: input.max_discount_units,
            match_bps: input.match_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            status: CouponStatus::Minted,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.coupon_ttl_blocks),
            applied_bid_id: None,
        };
        self.nullifiers.insert(input.coupon_nullifier);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        self.counters.coupons_minted = self.counters.coupons_minted.saturating_add(1);
        self.sponsor_coupons.insert(id.clone(), coupon);
        self.refresh_roots();
        Ok(id)
    }
    pub fn observe_congestion(&mut self, input: CongestionInput) -> Result<String> {
        if input.pressure_bps > MAX_BPS {
            return Err("congestion pressure exceeds bps denominator".to_string());
        }
        let previous = self.latest_congestion(input.lane);
        let smoothed_blob = self.smooth_units(
            previous
                .as_ref()
                .map(|v| v.smoothed_blob_fee_units)
                .unwrap_or(input.blob_base_fee_units),
            input.blob_base_fee_units,
        );
        let smoothed_proof = self.smooth_units(
            previous
                .as_ref()
                .map(|v| v.smoothed_proof_fee_units)
                .unwrap_or(input.proof_base_fee_units),
            input.proof_base_fee_units,
        );
        let sample_id = self.derive_id(
            "congestion-sample",
            &[
                HashPart::Str(input.lane.as_str()),
                HashPart::U64(self.counters.congestion_observations),
                HashPart::U64(self.height),
            ],
        );
        let sample = CongestionSample {
            sample_id: sample_id.clone(),
            lane: input.lane,
            blob_base_fee_units: input.blob_base_fee_units,
            proof_base_fee_units: input.proof_base_fee_units,
            observed_blob_bytes: input.observed_blob_bytes,
            observed_proof_units: input.observed_proof_units,
            smoothed_blob_fee_units: smoothed_blob,
            smoothed_proof_fee_units: smoothed_proof,
            pressure_bps: input.pressure_bps.min(self.config.congestion_spike_cap_bps),
            observed_height: self.height,
        };
        self.counters.congestion_observations =
            self.counters.congestion_observations.saturating_add(1);
        self.congestion_samples.insert(sample_id.clone(), sample);
        self.refresh_roots();
        Ok(sample_id)
    }
    pub fn open_low_fee_batch_settlement(&mut self, input: SettlementInput) -> Result<String> {
        self.ensure_capacity(
            self.settlements.len(),
            self.config.max_settlements,
            "settlements",
        )?;
        self.validate_commitment(&input.batch_root, "batch root")?;
        if input.bid_ids.is_empty() {
            return Err("settlement requires at least one bid".to_string());
        }
        let mut selected_bid_roots = Vec::new();
        let mut total_blob = 0_u128;
        let mut total_proof = 0_u128;
        let mut total_user_fee = 0_u128;
        for bid_id in &input.bid_ids {
            let bid = self
                .sealed_bids
                .get(bid_id)
                .ok_or_else(|| format!("missing bid {bid_id}"))?;
            if bid.lane != input.lane {
                return Err("settlement lane mismatch".to_string());
            }
            if !bid.status.live() {
                return Err("settlement bid is not live".to_string());
            }
            if self.height > bid.expires_height {
                return Err("settlement bid expired".to_string());
            }
            selected_bid_roots.push(domain_hash(
                "settlement-bid-root",
                &[HashPart::Json(&bid.public_record())],
                32,
            ));
            total_blob = total_blob.saturating_add(bid.requested_blob_cost_units);
            total_proof = total_proof.saturating_add(bid.requested_proof_cost_units);
            let gross = bid
                .requested_blob_cost_units
                .saturating_add(bid.requested_proof_cost_units);
            total_user_fee = total_user_fee.saturating_add(
                gross.saturating_mul(bid.max_user_fee_bps as u128) / MAX_BPS as u128,
            );
        }
        let mut attestation_roots = Vec::new();
        for attestation_id in &input.attestation_ids {
            let attestation = self
                .attestations
                .get(attestation_id)
                .ok_or_else(|| format!("missing attestation {attestation_id}"))?;
            if self.height > attestation.expires_height {
                return Err("settlement attestation expired".to_string());
            }
            attestation_roots.push(domain_hash(
                "settlement-attestation-root",
                &[HashPart::Json(&attestation.public_record())],
                32,
            ));
        }
        let mut coupon_roots = Vec::new();
        let mut total_sponsor = 0_u128;
        for coupon_id in &input.coupon_ids {
            let coupon = self
                .sponsor_coupons
                .get(coupon_id)
                .ok_or_else(|| format!("missing coupon {coupon_id}"))?;
            if coupon.lane != input.lane {
                return Err("coupon lane mismatch".to_string());
            }
            if coupon.status != CouponStatus::Minted && coupon.status != CouponStatus::Reserved {
                return Err("coupon not spendable".to_string());
            }
            if self.height > coupon.expires_height {
                return Err("coupon expired".to_string());
            }
            total_sponsor = total_sponsor.saturating_add(coupon.max_discount_units);
            coupon_roots.push(domain_hash(
                "settlement-coupon-root",
                &[HashPart::Json(&coupon.public_record())],
                32,
            ));
        }
        let pressure = self
            .latest_congestion(input.lane)
            .map(|v| v.pressure_bps)
            .unwrap_or(0);
        let blob_offset =
            total_blob.saturating_mul(self.config.blob_offset_bps as u128) / MAX_BPS as u128;
        let proof_offset =
            total_proof.saturating_mul(self.config.proof_offset_bps as u128) / MAX_BPS as u128;
        let protocol_fee =
            total_user_fee.saturating_mul(self.config.protocol_take_bps as u128) / MAX_BPS as u128;
        let rebate_base = total_user_fee
            .saturating_add(total_sponsor)
            .saturating_add(blob_offset)
            .saturating_add(proof_offset)
            .saturating_sub(protocol_fee);
        let total_rebate =
            rebate_base.saturating_mul(self.config.rebate_share_bps as u128) / MAX_BPS as u128;
        let settlement_id = self.derive_id(
            "low-fee-batch-settlement",
            &[
                HashPart::Str(&input.batch_root),
                HashPart::U64(self.counters.settlements_opened),
                HashPart::U64(self.height),
            ],
        );
        let settlement = LowFeeBatchSettlement {
            settlement_id: settlement_id.clone(),
            lane: input.lane,
            batch_root: input.batch_root,
            selected_bid_roots,
            attestation_roots,
            coupon_roots,
            total_blob_cost_units: total_blob,
            total_proof_cost_units: total_proof,
            total_user_fee_units: total_user_fee,
            total_sponsor_units: total_sponsor,
            total_rebate_units: total_rebate,
            protocol_fee_units: protocol_fee,
            smoothed_pressure_bps: pressure,
            status: SettlementStatus::Open,
            opened_height: self.height,
            settle_after_height: self
                .height
                .saturating_add(self.config.batch_settlement_window_blocks),
            settled_height: None,
        };
        for bid_id in input.bid_ids {
            if let Some(bid) = self.sealed_bids.get_mut(&bid_id) {
                bid.status = BidStatus::Selected;
                bid.selected_settlement_id = Some(settlement_id.clone());
                self.counters.bids_selected = self.counters.bids_selected.saturating_add(1);
            }
        }
        for coupon_id in input.coupon_ids {
            if let Some(coupon) = self.sponsor_coupons.get_mut(&coupon_id) {
                coupon.status = CouponStatus::Reserved;
            }
        }
        self.counters.settlements_opened = self.counters.settlements_opened.saturating_add(1);
        self.counters.total_user_fee_units = self
            .counters
            .total_user_fee_units
            .saturating_add(total_user_fee);
        self.counters.total_sponsor_units = self
            .counters
            .total_sponsor_units
            .saturating_add(total_sponsor);
        self.counters.total_protocol_fee_units = self
            .counters
            .total_protocol_fee_units
            .saturating_add(protocol_fee);
        self.counters.total_rebate_units = self
            .counters
            .total_rebate_units
            .saturating_add(total_rebate);
        self.settlements.insert(settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(settlement_id)
    }
    pub fn finalize_settlement(&mut self, settlement_id: &str) -> Result<()> {
        let snapshot = self
            .settlements
            .get(settlement_id)
            .ok_or_else(|| "missing settlement".to_string())?
            .clone();
        if self.height < snapshot.settle_after_height {
            return Err("settlement window still open".to_string());
        }
        if !matches!(
            snapshot.status,
            SettlementStatus::Open
                | SettlementStatus::Collecting
                | SettlementStatus::Netted
                | SettlementStatus::Attested
        ) {
            return Err("settlement cannot be finalized".to_string());
        }
        let entry_id = self.derive_id(
            "vault-rebate",
            &[
                HashPart::Str(settlement_id),
                HashPart::U64(self.counters.vault_entries_posted),
            ],
        );
        let account_commitment = domain_hash(
            "rebate-account-commitment",
            &[HashPart::Str(settlement_id)],
            32,
        );
        let note_commitment_root = domain_hash(
            "rebate-note",
            &[
                HashPart::Str(settlement_id),
                HashPart::Int(snapshot.total_rebate_units as i128),
            ],
            32,
        );
        if let Some(settlement) = self.settlements.get_mut(settlement_id) {
            settlement.status = SettlementStatus::Settled;
            settlement.settled_height = Some(self.height);
        }
        self.counters.settlements_finalized = self.counters.settlements_finalized.saturating_add(1);
        self.counters.total_settled_units = self
            .counters
            .total_settled_units
            .saturating_add(snapshot.total_user_fee_units)
            .saturating_add(snapshot.total_sponsor_units);
        self.post_vault_entry(RebateVaultEntry {
            entry_id,
            settlement_id: settlement_id.to_string(),
            bid_id: None,
            kind: VaultEntryKind::UserRebateAccrual,
            account_commitment,
            amount_units: snapshot.total_rebate_units,
            asset_id: self.config.rebate_asset_id.clone(),
            note_commitment_root,
            nullifier: None,
            created_height: self.height,
        })?;
        self.refresh_roots();
        Ok(())
    }
    pub fn expire_stale(&mut self) -> u64 {
        let mut expired = 0_u64;
        for bid in self.sealed_bids.values_mut() {
            if bid.status.live() && self.height > bid.expires_height {
                bid.status = BidStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for coupon in self.sponsor_coupons.values_mut() {
            if matches!(coupon.status, CouponStatus::Minted | CouponStatus::Reserved)
                && self.height > coupon.expires_height
            {
                coupon.status = CouponStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for settlement in self.settlements.values_mut() {
            if matches!(
                settlement.status,
                SettlementStatus::Open | SettlementStatus::Collecting
            ) && self.height
                > settlement
                    .settle_after_height
                    .saturating_add(self.config.rebate_claim_ttl_blocks)
            {
                settlement.status = SettlementStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        self.refresh_roots();
        expired
    }
    pub fn advance_height(&mut self, height: u64) {
        self.height = self.height.max(height);
        self.epoch = self.height / self.config.batch_settlement_window_blocks.max(1);
        self.expire_stale();
        self.refresh_roots();
    }
    pub fn public_record(&self) -> Value {
        json!({"protocol_version": self.config.protocol_version, "schema_version": self.config.schema_version, "chain_id": self.config.chain_id, "l2_network": self.config.l2_network, "monero_network": self.config.monero_network, "vault_id": self.config.vault_id, "fee_asset_id": self.config.fee_asset_id, "rebate_asset_id": self.config.rebate_asset_id, "height": self.height, "epoch": self.epoch, "hash_suite": self.config.hash_suite, "sealed_bid_suite": self.config.sealed_bid_suite, "pq_attestation_suite": self.config.pq_attestation_suite, "rebate_vault_suite": self.config.rebate_vault_suite, "sponsor_coupon_suite": self.config.sponsor_coupon_suite, "congestion_smoothing_suite": self.config.congestion_smoothing_suite, "low_fee_batch_settlement_suite": self.config.low_fee_batch_settlement_suite, "privacy_boundary": PRIVACY_BOUNDARY, "counters": self.counters.public_record(), "roots": self.roots.public_record()})
    }
    pub fn state_root(&self) -> String {
        domain_hash(
            PUBLIC_RECORD_SUITE,
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn refresh_roots(&mut self) {
        let bid_records = self
            .sealed_bids
            .values()
            .map(SealedBlobFeeBid::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(PqSequencerAttestation::public_record)
            .collect::<Vec<_>>();
        let coupon_records = self
            .sponsor_coupons
            .values()
            .map(SponsorCoupon::public_record)
            .collect::<Vec<_>>();
        let congestion_records = self
            .congestion_samples
            .values()
            .map(CongestionSample::public_record)
            .collect::<Vec<_>>();
        let settlement_records = self
            .settlements
            .values()
            .map(LowFeeBatchSettlement::public_record)
            .collect::<Vec<_>>();
        let vault_records = self
            .vault_entries
            .values()
            .map(RebateVaultEntry::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self.nullifiers.iter().map(|v| json!(v)).collect::<Vec<_>>();
        let score_records = self
            .sequencer_scores
            .iter()
            .map(|(k, v)| json!({"sequencer_commitment": k, "score": v}))
            .collect::<Vec<_>>();
        self.roots.bids_root = merkle_root("sealed-sequencer-blob-fee-bids", &bid_records);
        self.roots.attestations_root =
            merkle_root("pq-sequencer-attestations", &attestation_records);
        self.roots.coupons_root = merkle_root("sponsor-coupons", &coupon_records);
        self.roots.congestion_root = merkle_root("congestion-samples", &congestion_records);
        self.roots.settlements_root = merkle_root("low-fee-batch-settlements", &settlement_records);
        self.roots.vault_entries_root = merkle_root("rebate-vault-entries", &vault_records);
        self.roots.nullifiers_root = merkle_root("rebate-vault-nullifiers", &nullifier_records);
        self.roots.sequencer_scores_root = merkle_root("sequencer-score-roots", &score_records);
        let mut record = self.public_record();
        if let Some(roots) = record.get_mut("roots") {
            if let Some(object) = roots.as_object_mut() {
                object.insert("public_record_root".to_string(), json!("pending"));
            }
        }
        self.roots.public_record_root =
            domain_hash("rebate-vault-public-record", &[HashPart::Json(&record)], 32);
    }
    fn post_vault_entry(&mut self, entry: RebateVaultEntry) -> Result<()> {
        self.ensure_capacity(
            self.vault_entries.len(),
            self.config.max_vault_entries,
            "vault entries",
        )?;
        self.counters.vault_entries_posted = self.counters.vault_entries_posted.saturating_add(1);
        self.vault_entries.insert(entry.entry_id.clone(), entry);
        Ok(())
    }
    fn latest_congestion(&self, lane: BlobLane) -> Option<CongestionSample> {
        self.congestion_samples
            .values()
            .filter(|sample| sample.lane == lane)
            .max_by_key(|sample| sample.observed_height)
            .cloned()
    }
    fn smooth_units(&self, previous: u128, observed: u128) -> u128 {
        let alpha = self.config.congestion_alpha_bps.min(MAX_BPS) as u128;
        let base = previous.saturating_mul((MAX_BPS as u128).saturating_sub(alpha));
        let next = observed.saturating_mul(alpha);
        base.saturating_add(next) / MAX_BPS as u128
    }
    fn bump_sequencer_score(&mut self, sequencer: &str, delta: u64) {
        let score = self
            .sequencer_scores
            .entry(sequencer.to_string())
            .or_insert(0);
        *score = score.saturating_add(delta);
    }
    fn derive_id(&self, domain: &str, parts: &[HashPart<'_>]) -> String {
        domain_hash(domain, parts, 32)
    }
    fn validate_commitment(&self, value: &str, label: &str) -> Result<()> {
        if value.len() < 16 {
            return Err(format!("{label} is too short"));
        }
        if value.chars().any(char::is_whitespace) {
            return Err(format!("{label} contains whitespace"));
        }
        Ok(())
    }
    fn ensure_capacity(&self, len: usize, max: usize, label: &str) -> Result<()> {
        if len >= max {
            return Err(format!("{label} capacity exceeded"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state =
        State::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH).expect("valid devnet config");
    let _ = state.observe_congestion(CongestionInput {
        lane: BlobLane::MoneroExit,
        blob_base_fee_units: 88_000,
        proof_base_fee_units: 41_000,
        observed_blob_bytes: 786_432,
        observed_proof_units: 2048,
        pressure_bps: 620,
    });
    let coupon_id = state
        .mint_sponsor_coupon(SponsorCouponInput {
            sponsor_commitment: "devnet-sponsor-commitment-root-0001".to_string(),
            coupon_commitment: "devnet-coupon-commitment-root-0001".to_string(),
            coupon_nullifier: "devnet-coupon-nullifier-root-0001".to_string(),
            lane: BlobLane::MoneroExit,
            max_discount_units: 25_000,
            match_bps: 1_500,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet coupon");
    let bid_id = state
        .post_sealed_bid(SealedBidInput {
            sequencer_commitment: "devnet-sequencer-commitment-root-0001".to_string(),
            lane: BlobLane::MoneroExit,
            sealed_fee_bid_root: "devnet-sealed-fee-bid-root-0001".to_string(),
            encrypted_bid_bytes_root: "devnet-encrypted-bid-bytes-root-0001".to_string(),
            blob_bundle_root: "devnet-blob-bundle-root-0001".to_string(),
            proof_bundle_root: "devnet-proof-bundle-root-0001".to_string(),
            max_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            requested_blob_cost_units: 84_000,
            requested_proof_cost_units: 39_000,
            target_latency_ms: 850,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            coupon_commitment: Some("devnet-coupon-commitment-root-0001".to_string()),
        })
        .expect("devnet bid");
    let attestation_id = state
        .post_pq_attestation(AttestationInput {
            sequencer_commitment: "devnet-sequencer-commitment-root-0001".to_string(),
            kind: AttestationKind::BatchInclusion,
            subject_root: "devnet-sealed-fee-bid-root-0001".to_string(),
            pq_public_key_root: "devnet-pq-public-key-root-0001".to_string(),
            signature_root: "devnet-pq-signature-root-0001".to_string(),
            transcript_root: "devnet-pq-transcript-root-0001".to_string(),
            aggregate_weight: DEFAULT_MIN_ATTESTATION_QUORUM as u64,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet attestation");
    let _ = state
        .open_low_fee_batch_settlement(SettlementInput {
            lane: BlobLane::MoneroExit,
            bid_ids: vec![bid_id],
            attestation_ids: vec![attestation_id],
            coupon_ids: vec![coupon_id],
            batch_root: "devnet-low-fee-batch-root-0001".to_string(),
        })
        .expect("devnet settlement");
    state.refresh_roots();
    state
}
pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(PUBLIC_RECORD_SUITE, &[HashPart::Json(record)], 32)
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimePolicyMarker {
    pub marker_id: u16,
    pub family: String,
    pub public_root_domain: String,
    pub privacy_goal: String,
    pub fee_goal_bps: u64,
    pub speed_goal_ms: u64,
}
impl RuntimePolicyMarker {
    pub fn public_record(&self) -> Value {
        json!({"marker_id": self.marker_id, "family": self.family, "public_root_domain": self.public_root_domain, "privacy_goal": self.privacy_goal, "fee_goal_bps": self.fee_goal_bps, "speed_goal_ms": self.speed_goal_ms})
    }
}
pub fn policy_marker_001() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 1,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-001".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 501,
    }
}
pub fn policy_marker_002() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 2,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-002".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 502,
    }
}
pub fn policy_marker_003() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 3,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-003".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 503,
    }
}
pub fn policy_marker_004() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 4,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-004".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 504,
    }
}
pub fn policy_marker_005() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 5,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-005".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 505,
    }
}
pub fn policy_marker_006() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 6,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-006".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 506,
    }
}
pub fn policy_marker_007() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 7,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-007".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 507,
    }
}
pub fn policy_marker_008() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 8,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-008".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 508,
    }
}
pub fn policy_marker_009() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 9,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-009".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 509,
    }
}
pub fn policy_marker_010() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 10,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-010".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 510,
    }
}
pub fn policy_marker_011() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 11,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-011".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 511,
    }
}
pub fn policy_marker_012() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 12,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-012".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 512,
    }
}
pub fn policy_marker_013() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 13,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-013".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 513,
    }
}
pub fn policy_marker_014() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 14,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-014".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 514,
    }
}
pub fn policy_marker_015() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 15,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-015".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 515,
    }
}
pub fn policy_marker_016() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 16,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-016".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 516,
    }
}
pub fn policy_marker_017() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 17,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-017".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 517,
    }
}
pub fn policy_marker_018() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 18,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-018".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 518,
    }
}
pub fn policy_marker_019() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 19,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-019".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 519,
    }
}
pub fn policy_marker_020() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 20,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-020".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 520,
    }
}
pub fn policy_marker_021() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 21,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-021".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 521,
    }
}
pub fn policy_marker_022() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 22,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-022".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 522,
    }
}
pub fn policy_marker_023() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 23,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-023".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 523,
    }
}
pub fn policy_marker_024() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 24,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-024".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 524,
    }
}
pub fn policy_marker_025() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 25,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-025".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 525,
    }
}
pub fn policy_marker_026() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 26,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-026".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 526,
    }
}
pub fn policy_marker_027() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 27,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-027".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 527,
    }
}
pub fn policy_marker_028() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 28,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-028".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 528,
    }
}
pub fn policy_marker_029() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 29,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-029".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 529,
    }
}
pub fn policy_marker_030() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 30,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-030".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 530,
    }
}
pub fn policy_marker_031() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 31,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-031".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 531,
    }
}
pub fn policy_marker_032() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 32,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-032".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 532,
    }
}
pub fn policy_marker_033() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 33,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-033".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 533,
    }
}
pub fn policy_marker_034() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 34,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-034".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 534,
    }
}
pub fn policy_marker_035() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 35,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-035".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 535,
    }
}
pub fn policy_marker_036() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 36,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-036".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 536,
    }
}
pub fn policy_marker_037() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 37,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-037".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 537,
    }
}
pub fn policy_marker_038() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 38,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-038".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 538,
    }
}
pub fn policy_marker_039() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 39,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-039".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 539,
    }
}
pub fn policy_marker_040() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 40,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-040".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 540,
    }
}
pub fn policy_marker_041() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 41,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-041".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 541,
    }
}
pub fn policy_marker_042() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 42,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-042".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 542,
    }
}
pub fn policy_marker_043() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 43,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-043".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 543,
    }
}
pub fn policy_marker_044() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 44,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-044".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 544,
    }
}
pub fn policy_marker_045() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 45,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-045".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 545,
    }
}
pub fn policy_marker_046() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 46,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-046".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 546,
    }
}
pub fn policy_marker_047() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 47,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-047".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 547,
    }
}
pub fn policy_marker_048() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 48,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-048".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 548,
    }
}
pub fn policy_marker_049() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 49,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-049".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 549,
    }
}
pub fn policy_marker_050() -> RuntimePolicyMarker {
    RuntimePolicyMarker {
        marker_id: 50,
        family: "sequencer_blob_fee_rebate_vault".to_string(),
        public_root_domain: "roots-only-policy-marker-050".to_string(),
        privacy_goal: "sealed_inputs_commitments_only".to_string(),
        fee_goal_bps: DEFAULT_TARGET_USER_FEE_BPS,
        speed_goal_ms: 550,
    }
}
