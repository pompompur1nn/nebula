use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPrivateBridgeLiquidityNettingVaultResult<T> = Result<T, String>;

pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PROTOCOL_VERSION: &str =
    "nebula-monero-private-bridge-liquidity-netting-vault-v1";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_SCHEMA_VERSION: u64 = 1;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_HEIGHT: u64 = 9_600;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_XMR_ASSET_ID: &str = "xmr-devnet";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_WRAPPED_XMR_ASSET_ID: &str =
    "wxmr-devnet";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_NOTE_COMMITMENT_SCHEME: &str =
    "zk-shielded-xmr-note-v1";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_INVENTORY_COMMITMENT_SCHEME: &str =
    "maker-xmr-inventory-commitment-v1";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_STEALTH_PAYOUT_SCHEME: &str =
    "monero-stealth-payout-commitment-v1";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_RESERVE_PROOF_SCHEME: &str =
    "monero-viewkey-reserve-proof-v1";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-vault-attestation-v1";
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_MAX_BPS: u64 = 10_000;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_NETTING_WINDOW_BLOCKS: u64 = 24;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 10;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_REORG_BUFFER_BLOCKS: u64 = 18;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_RESERVE_PROOF_TTL_BLOCKS: u64 =
    1_440;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 240;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_MIN_PRIVACY_SET: u64 = 32;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_LOW_RISK_BPS: u64 = 2_500;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_GUARDED_RISK_BPS: u64 = 5_000;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_STRESSED_RISK_BPS: u64 = 7_500;
pub const MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_HALT_RISK_BPS: u64 = 9_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Bootstrapping,
    Open,
    Guarded,
    Stressed,
    Paused,
    EmergencyExit,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Open => "open",
            Self::Guarded => "guarded",
            Self::Stressed => "stressed",
            Self::Paused => "paused",
            Self::EmergencyExit => "emergency_exit",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_flow(self) -> bool {
        matches!(self, Self::Open | Self::Guarded | Self::Stressed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    ShieldedDeposit,
    ShieldedExit,
    MakerInventory,
    StealthPayout,
    SponsoredWithdrawal,
    ReserveRebalance,
}

impl FlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedDeposit => "shielded_deposit",
            Self::ShieldedExit => "shielded_exit",
            Self::MakerInventory => "maker_inventory",
            Self::StealthPayout => "stealth_payout",
            Self::SponsoredWithdrawal => "sponsored_withdrawal",
            Self::ReserveRebalance => "reserve_rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Pending,
    Queued,
    Netted,
    Reserved,
    Settling,
    Settled,
    Released,
    Disputed,
    Expired,
    Cancelled,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Queued => "queued",
            Self::Netted => "netted",
            Self::Reserved => "reserved",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Queued | Self::Netted | Self::Reserved | Self::Settling
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Released | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerStatus {
    Candidate,
    Active,
    Constrained,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl MakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Constrained => "constrained",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Constrained | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    SponsorOnly,
    Settling,
    Paused,
    Exhausted,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::SponsorOnly => "sponsor_only",
            Self::Settling => "settling",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_withdrawal(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::SponsorOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBandKind {
    Low,
    Guarded,
    Stressed,
    Halt,
}

impl RiskBandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Guarded => "guarded",
            Self::Stressed => "stressed",
            Self::Halt => "halt",
        }
    }

    pub fn permits_new_exits(self) -> bool {
        !matches!(self, Self::Halt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    WaitingForDelay,
    Eligible,
    Submitted,
    Confirming,
    Final,
    ReorgBuffered,
    Replayed,
    Cancelled,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::WaitingForDelay => "waiting_for_delay",
            Self::Eligible => "eligible",
            Self::Submitted => "submitted",
            Self::Confirming => "confirming",
            Self::Final => "final",
            Self::ReorgBuffered => "reorg_buffered",
            Self::Replayed => "replayed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn counts_as_pending(self) -> bool {
        matches!(
            self,
            Self::WaitingForDelay | Self::Eligible | Self::Submitted | Self::Confirming
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Fresh,
    Usable,
    Aging,
    Challenged,
    Expired,
    Revoked,
}

impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Usable => "usable",
            Self::Aging => "aging",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Fresh | Self::Usable | Self::Aging)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub xmr_asset_id: String,
    pub wrapped_xmr_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub note_commitment_scheme: String,
    pub inventory_commitment_scheme: String,
    pub stealth_payout_scheme: String,
    pub reserve_proof_scheme: String,
    pub pq_attestation_scheme: String,
    pub epoch_blocks: u64,
    pub netting_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub reorg_buffer_blocks: u64,
    pub reserve_proof_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_lane_share_bps: u64,
    pub max_maker_share_bps: u64,
    pub max_unproven_reserve_bps: u64,
    pub low_risk_bps: u64,
    pub guarded_risk_bps: u64,
    pub stressed_risk_bps: u64,
    pub halt_risk_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PROTOCOL_VERSION
                .to_string(),
            schema_version: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_MONERO_NETWORK
                .to_string(),
            xmr_asset_id: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_XMR_ASSET_ID
                .to_string(),
            wrapped_xmr_asset_id:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_WRAPPED_XMR_ASSET_ID
                    .to_string(),
            fee_asset_id: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_HASH_SUITE.to_string(),
            note_commitment_scheme:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_NOTE_COMMITMENT_SCHEME.to_string(),
            inventory_commitment_scheme:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_INVENTORY_COMMITMENT_SCHEME
                    .to_string(),
            stealth_payout_scheme:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_STEALTH_PAYOUT_SCHEME.to_string(),
            reserve_proof_scheme:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_RESERVE_PROOF_SCHEME.to_string(),
            pq_attestation_scheme:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PQ_ATTESTATION_SCHEME.to_string(),
            epoch_blocks: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_EPOCH_BLOCKS,
            netting_window_blocks:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_NETTING_WINDOW_BLOCKS,
            settlement_delay_blocks:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            reorg_buffer_blocks:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_REORG_BUFFER_BLOCKS,
            reserve_proof_ttl_blocks:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_RESERVE_PROOF_TTL_BLOCKS,
            sponsor_ttl_blocks:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_privacy_set: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_lane_share_bps: 4_500,
            max_maker_share_bps: 3_500,
            max_unproven_reserve_bps: 1_000,
            low_risk_bps: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_LOW_RISK_BPS,
            guarded_risk_bps:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_GUARDED_RISK_BPS,
            stressed_risk_bps:
                MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_STRESSED_RISK_BPS,
            halt_risk_bps: MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEFAULT_HALT_RISK_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "xmr_asset_id": self.xmr_asset_id,
            "wrapped_xmr_asset_id": self.wrapped_xmr_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "note_commitment_scheme": self.note_commitment_scheme,
            "inventory_commitment_scheme": self.inventory_commitment_scheme,
            "stealth_payout_scheme": self.stealth_payout_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "epoch_blocks": self.epoch_blocks,
            "netting_window_blocks": self.netting_window_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "reorg_buffer_blocks": self.reorg_buffer_blocks,
            "reserve_proof_ttl_blocks": self.reserve_proof_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_lane_share_bps": self.max_lane_share_bps,
            "max_maker_share_bps": self.max_maker_share_bps,
            "max_unproven_reserve_bps": self.max_unproven_reserve_bps,
            "risk_bands": {
                "low_risk_bps": self.low_risk_bps,
                "guarded_risk_bps": self.guarded_risk_bps,
                "stressed_risk_bps": self.stressed_risk_bps,
                "halt_risk_bps": self.halt_risk_bps
            }
        })
    }

    pub fn validate(&self) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()> {
        if self.protocol_version != MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PROTOCOL_VERSION {
            return Err("unexpected protocol version".to_string());
        }
        if self.schema_version == 0 {
            return Err("schema version must be non-zero".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("config chain id does not match runtime chain id".to_string());
        }
        if self.monero_network.is_empty()
            || self.xmr_asset_id.is_empty()
            || self.wrapped_xmr_asset_id.is_empty()
            || self.fee_asset_id.is_empty()
        {
            return Err("asset and network identifiers must be present".to_string());
        }
        if self.epoch_blocks == 0
            || self.netting_window_blocks == 0
            || self.settlement_delay_blocks == 0
            || self.reorg_buffer_blocks == 0
            || self.reserve_proof_ttl_blocks == 0
            || self.sponsor_ttl_blocks == 0
        {
            return Err("config block windows must be non-zero".to_string());
        }
        if self.netting_window_blocks > self.epoch_blocks {
            return Err("netting window cannot exceed epoch".to_string());
        }
        if self.min_privacy_set == 0 {
            return Err("minimum privacy set must be non-zero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("minimum post-quantum security bits too low".to_string());
        }
        for (name, value) in [
            ("max_lane_share_bps", self.max_lane_share_bps),
            ("max_maker_share_bps", self.max_maker_share_bps),
            ("max_unproven_reserve_bps", self.max_unproven_reserve_bps),
            ("low_risk_bps", self.low_risk_bps),
            ("guarded_risk_bps", self.guarded_risk_bps),
            ("stressed_risk_bps", self.stressed_risk_bps),
            ("halt_risk_bps", self.halt_risk_bps),
        ] {
            if value > MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_MAX_BPS {
                return Err(format!("{name} exceeds bps denominator"));
            }
        }
        if !(self.low_risk_bps < self.guarded_risk_bps
            && self.guarded_risk_bps < self.stressed_risk_bps
            && self.stressed_risk_bps < self.halt_risk_bps)
        {
            return Err("risk band thresholds must increase".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub maker_root: String,
    pub inventory_commitment_root: String,
    pub shielded_deposit_root: String,
    pub shielded_exit_root: String,
    pub stealth_payout_root: String,
    pub sponsored_withdrawal_lane_root: String,
    pub sponsored_withdrawal_root: String,
    pub netting_batch_root: String,
    pub settlement_receipt_root: String,
    pub reserve_proof_root: String,
    pub risk_band_root: String,
    pub reorg_buffer_root: String,
    pub watchtower_attestation_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "maker_root": self.maker_root,
            "inventory_commitment_root": self.inventory_commitment_root,
            "shielded_deposit_root": self.shielded_deposit_root,
            "shielded_exit_root": self.shielded_exit_root,
            "stealth_payout_root": self.stealth_payout_root,
            "sponsored_withdrawal_lane_root": self.sponsored_withdrawal_lane_root,
            "sponsored_withdrawal_root": self.sponsored_withdrawal_root,
            "netting_batch_root": self.netting_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "reserve_proof_root": self.reserve_proof_root,
            "risk_band_root": self.risk_band_root,
            "reorg_buffer_root": self.reorg_buffer_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub vaults: usize,
    pub makers: usize,
    pub usable_makers: usize,
    pub inventory_commitments: usize,
    pub live_inventory_commitments: usize,
    pub shielded_deposits: usize,
    pub live_shielded_deposits: usize,
    pub shielded_exits: usize,
    pub live_shielded_exits: usize,
    pub stealth_payouts: usize,
    pub live_stealth_payouts: usize,
    pub sponsored_withdrawal_lanes: usize,
    pub sponsored_withdrawals: usize,
    pub live_sponsored_withdrawals: usize,
    pub netting_batches: usize,
    pub settlement_receipts: usize,
    pub pending_settlement_receipts: usize,
    pub reserve_proofs: usize,
    pub usable_reserve_proofs: usize,
    pub risk_bands: usize,
    pub reorg_buffers: usize,
    pub watchtower_attestations: usize,
    pub unique_nullifiers: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vaults": self.vaults,
            "makers": self.makers,
            "usable_makers": self.usable_makers,
            "inventory_commitments": self.inventory_commitments,
            "live_inventory_commitments": self.live_inventory_commitments,
            "shielded_deposits": self.shielded_deposits,
            "live_shielded_deposits": self.live_shielded_deposits,
            "shielded_exits": self.shielded_exits,
            "live_shielded_exits": self.live_shielded_exits,
            "stealth_payouts": self.stealth_payouts,
            "live_stealth_payouts": self.live_stealth_payouts,
            "sponsored_withdrawal_lanes": self.sponsored_withdrawal_lanes,
            "sponsored_withdrawals": self.sponsored_withdrawals,
            "live_sponsored_withdrawals": self.live_sponsored_withdrawals,
            "netting_batches": self.netting_batches,
            "settlement_receipts": self.settlement_receipts,
            "pending_settlement_receipts": self.pending_settlement_receipts,
            "reserve_proofs": self.reserve_proofs,
            "usable_reserve_proofs": self.usable_reserve_proofs,
            "risk_bands": self.risk_bands,
            "reorg_buffers": self.reorg_buffers,
            "watchtower_attestations": self.watchtower_attestations,
            "unique_nullifiers": self.unique_nullifiers
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub vault_id: String,
    pub label: String,
    pub status: VaultStatus,
    pub monero_subaddress_commitment: String,
    pub view_key_commitment: String,
    pub operator_committee_root: String,
    pub maker_set_root: String,
    pub lane_set_root: String,
    pub risk_band_id: String,
    pub opened_at_height: u64,
    pub max_private_exit_amount: u64,
    pub max_private_deposit_amount: u64,
    pub reserve_floor_piconero: u64,
    pub shielded_note_root: String,
    pub nullifier_root: String,
}

impl Vault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "label": self.label,
            "status": self.status.as_str(),
            "monero_subaddress_commitment": self.monero_subaddress_commitment,
            "view_key_commitment": self.view_key_commitment,
            "operator_committee_root": self.operator_committee_root,
            "maker_set_root": self.maker_set_root,
            "lane_set_root": self.lane_set_root,
            "risk_band_id": self.risk_band_id,
            "opened_at_height": self.opened_at_height,
            "max_private_exit_amount": self.max_private_exit_amount,
            "max_private_deposit_amount": self.max_private_deposit_amount,
            "reserve_floor_piconero": self.reserve_floor_piconero,
            "shielded_note_root": self.shielded_note_root,
            "nullifier_root": self.nullifier_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Maker {
    pub maker_id: String,
    pub label: String,
    pub status: MakerStatus,
    pub inventory_commitment_root: String,
    pub reserve_proof_id: String,
    pub max_inventory_piconero: u64,
    pub reserved_inventory_piconero: u64,
    pub private_quote_bps: u64,
    pub reliability_bps: u64,
    pub pq_key_commitment: String,
    pub last_seen_height: u64,
}

impl Maker {
    pub fn public_record(&self) -> Value {
        json!({
            "maker_id": self.maker_id,
            "label": self.label,
            "status": self.status.as_str(),
            "inventory_commitment_root": self.inventory_commitment_root,
            "reserve_proof_id": self.reserve_proof_id,
            "max_inventory_piconero": self.max_inventory_piconero,
            "reserved_inventory_piconero": self.reserved_inventory_piconero,
            "private_quote_bps": self.private_quote_bps,
            "reliability_bps": self.reliability_bps,
            "pq_key_commitment": self.pq_key_commitment,
            "last_seen_height": self.last_seen_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryCommitment {
    pub commitment_id: String,
    pub maker_id: String,
    pub vault_id: String,
    pub status: CommitmentStatus,
    pub amount_piconero: u64,
    pub reserved_piconero: u64,
    pub min_exit_amount: u64,
    pub max_exit_amount: u64,
    pub inventory_blinding_commitment: String,
    pub reserve_proof_id: String,
    pub expires_at_height: u64,
}

impl InventoryCommitment {
    pub fn available_piconero(&self) -> u64 {
        self.amount_piconero.saturating_sub(self.reserved_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "maker_id": self.maker_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "amount_piconero": self.amount_piconero,
            "reserved_piconero": self.reserved_piconero,
            "available_piconero": self.available_piconero(),
            "min_exit_amount": self.min_exit_amount,
            "max_exit_amount": self.max_exit_amount,
            "inventory_blinding_commitment": self.inventory_blinding_commitment,
            "reserve_proof_id": self.reserve_proof_id,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedDeposit {
    pub deposit_id: String,
    pub vault_id: String,
    pub status: CommitmentStatus,
    pub amount_piconero: u64,
    pub note_commitment: String,
    pub depositor_commitment: String,
    pub monero_txid_commitment: String,
    pub unlock_height: u64,
    pub netting_batch_id: String,
    pub received_at_height: u64,
}

impl ShieldedDeposit {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "amount_piconero": self.amount_piconero,
            "note_commitment": self.note_commitment,
            "depositor_commitment": self.depositor_commitment,
            "monero_txid_commitment": self.monero_txid_commitment,
            "unlock_height": self.unlock_height,
            "netting_batch_id": self.netting_batch_id,
            "received_at_height": self.received_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedExit {
    pub exit_id: String,
    pub vault_id: String,
    pub status: CommitmentStatus,
    pub amount_piconero: u64,
    pub nullifier: String,
    pub payout_commitment_id: String,
    pub maker_id: String,
    pub sponsored_withdrawal_id: String,
    pub netting_batch_id: String,
    pub privacy_set_size: u64,
    pub requested_at_height: u64,
    pub deadline_height: u64,
}

impl ShieldedExit {
    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "amount_piconero": self.amount_piconero,
            "nullifier": self.nullifier,
            "payout_commitment_id": self.payout_commitment_id,
            "maker_id": self.maker_id,
            "sponsored_withdrawal_id": self.sponsored_withdrawal_id,
            "netting_batch_id": self.netting_batch_id,
            "privacy_set_size": self.privacy_set_size,
            "requested_at_height": self.requested_at_height,
            "deadline_height": self.deadline_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthPayoutCommitment {
    pub payout_commitment_id: String,
    pub exit_id: String,
    pub vault_id: String,
    pub status: CommitmentStatus,
    pub stealth_address_commitment: String,
    pub one_time_public_key_commitment: String,
    pub encrypted_amount_commitment: String,
    pub view_tag_commitment: String,
    pub amount_piconero: u64,
    pub created_at_height: u64,
}

impl StealthPayoutCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "payout_commitment_id": self.payout_commitment_id,
            "exit_id": self.exit_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "stealth_address_commitment": self.stealth_address_commitment,
            "one_time_public_key_commitment": self.one_time_public_key_commitment,
            "encrypted_amount_commitment": self.encrypted_amount_commitment,
            "view_tag_commitment": self.view_tag_commitment,
            "amount_piconero": self.amount_piconero,
            "created_at_height": self.created_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredWithdrawalLane {
    pub lane_id: String,
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub status: LaneStatus,
    pub fee_budget_piconero: u64,
    pub spent_fee_budget_piconero: u64,
    pub max_withdrawals_per_window: u64,
    pub min_privacy_set: u64,
    pub preferred_maker_ids: BTreeSet<String>,
    pub expires_at_height: u64,
}

impl SponsoredWithdrawalLane {
    pub fn remaining_fee_budget_piconero(&self) -> u64 {
        self.fee_budget_piconero
            .saturating_sub(self.spent_fee_budget_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "fee_budget_piconero": self.fee_budget_piconero,
            "spent_fee_budget_piconero": self.spent_fee_budget_piconero,
            "remaining_fee_budget_piconero": self.remaining_fee_budget_piconero(),
            "max_withdrawals_per_window": self.max_withdrawals_per_window,
            "min_privacy_set": self.min_privacy_set,
            "preferred_maker_ids": self.preferred_maker_ids,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredWithdrawal {
    pub withdrawal_id: String,
    pub lane_id: String,
    pub exit_id: String,
    pub status: CommitmentStatus,
    pub fee_piconero: u64,
    pub sponsor_authorization_commitment: String,
    pub relayer_commitment: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsoredWithdrawal {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "lane_id": self.lane_id,
            "exit_id": self.exit_id,
            "status": self.status.as_str(),
            "fee_piconero": self.fee_piconero,
            "sponsor_authorization_commitment": self.sponsor_authorization_commitment,
            "relayer_commitment": self.relayer_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingBatch {
    pub batch_id: String,
    pub vault_id: String,
    pub epoch: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub status: CommitmentStatus,
    pub deposit_ids: BTreeSet<String>,
    pub exit_ids: BTreeSet<String>,
    pub gross_deposit_piconero: u64,
    pub gross_exit_piconero: u64,
    pub net_required_piconero: i128,
    pub settlement_receipt_id: String,
    pub batch_proof_commitment: String,
}

impl NettingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "epoch": self.epoch,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "status": self.status.as_str(),
            "deposit_ids": self.deposit_ids,
            "exit_ids": self.exit_ids,
            "gross_deposit_piconero": self.gross_deposit_piconero,
            "gross_exit_piconero": self.gross_exit_piconero,
            "net_required_piconero": self.net_required_piconero,
            "settlement_receipt_id": self.settlement_receipt_id,
            "batch_proof_commitment": self.batch_proof_commitment
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub vault_id: String,
    pub status: ReceiptStatus,
    pub delayed_until_height: u64,
    pub submitted_at_height: u64,
    pub finalized_at_height: u64,
    pub monero_txid_commitment: String,
    pub reserve_delta_piconero: i128,
    pub payout_count: u64,
    pub reorg_buffer_id: String,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "delayed_until_height": self.delayed_until_height,
            "submitted_at_height": self.submitted_at_height,
            "finalized_at_height": self.finalized_at_height,
            "monero_txid_commitment": self.monero_txid_commitment,
            "reserve_delta_piconero": self.reserve_delta_piconero,
            "payout_count": self.payout_count,
            "reorg_buffer_id": self.reorg_buffer_id
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProof {
    pub proof_id: String,
    pub vault_id: String,
    pub maker_id: String,
    pub status: ReserveProofStatus,
    pub reserve_amount_piconero: u64,
    pub liabilities_piconero: u64,
    pub view_key_root: String,
    pub output_set_root: String,
    pub challenge_root: String,
    pub proven_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveProof {
    pub fn surplus_piconero(&self) -> u64 {
        self.reserve_amount_piconero
            .saturating_sub(self.liabilities_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "vault_id": self.vault_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "reserve_amount_piconero": self.reserve_amount_piconero,
            "liabilities_piconero": self.liabilities_piconero,
            "surplus_piconero": self.surplus_piconero(),
            "view_key_root": self.view_key_root,
            "output_set_root": self.output_set_root,
            "challenge_root": self.challenge_root,
            "proven_at_height": self.proven_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBand {
    pub band_id: String,
    pub vault_id: String,
    pub kind: RiskBandKind,
    pub exposure_bps: u64,
    pub inventory_utilization_bps: u64,
    pub unproven_reserve_bps: u64,
    pub withdrawal_throttle_bps: u64,
    pub requires_manual_attestation: bool,
    pub evaluated_at_height: u64,
}

impl RiskBand {
    pub fn public_record(&self) -> Value {
        json!({
            "band_id": self.band_id,
            "vault_id": self.vault_id,
            "kind": self.kind.as_str(),
            "exposure_bps": self.exposure_bps,
            "inventory_utilization_bps": self.inventory_utilization_bps,
            "unproven_reserve_bps": self.unproven_reserve_bps,
            "withdrawal_throttle_bps": self.withdrawal_throttle_bps,
            "requires_manual_attestation": self.requires_manual_attestation,
            "evaluated_at_height": self.evaluated_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgBuffer {
    pub buffer_id: String,
    pub vault_id: String,
    pub receipt_id: String,
    pub anchor_height: u64,
    pub release_height: u64,
    pub buffered_txid_commitment: String,
    pub replacement_txid_commitment: String,
    pub affected_exit_ids: BTreeSet<String>,
    pub status: ReceiptStatus,
}

impl ReorgBuffer {
    pub fn public_record(&self) -> Value {
        json!({
            "buffer_id": self.buffer_id,
            "vault_id": self.vault_id,
            "receipt_id": self.receipt_id,
            "anchor_height": self.anchor_height,
            "release_height": self.release_height,
            "buffered_txid_commitment": self.buffered_txid_commitment,
            "replacement_txid_commitment": self.replacement_txid_commitment,
            "affected_exit_ids": self.affected_exit_ids,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub subject_root: String,
    pub signer_commitment: String,
    pub pq_signature_commitment: String,
    pub observed_height: u64,
    pub signed_at_height: u64,
}

impl WatchtowerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "pq_signature_commitment": self.pq_signature_commitment,
            "observed_height": self.observed_height,
            "signed_at_height": self.signed_at_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub vaults: BTreeMap<String, Vault>,
    pub makers: BTreeMap<String, Maker>,
    pub inventory_commitments: BTreeMap<String, InventoryCommitment>,
    pub shielded_deposits: BTreeMap<String, ShieldedDeposit>,
    pub shielded_exits: BTreeMap<String, ShieldedExit>,
    pub stealth_payout_commitments: BTreeMap<String, StealthPayoutCommitment>,
    pub sponsored_withdrawal_lanes: BTreeMap<String, SponsoredWithdrawalLane>,
    pub sponsored_withdrawals: BTreeMap<String, SponsoredWithdrawal>,
    pub netting_batches: BTreeMap<String, NettingBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub reserve_proofs: BTreeMap<String, ReserveProof>,
    pub risk_bands: BTreeMap<String, RiskBand>,
    pub reorg_buffers: BTreeMap<String, ReorgBuffer>,
    pub watchtower_attestations: BTreeMap<String, WatchtowerAttestation>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> MoneroPrivateBridgeLiquidityNettingVaultResult<Self> {
        let config = Config::devnet();
        let height = MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_DEVNET_HEIGHT;
        let vault_id = deterministic_id("MPBLNV-VAULT", "devnet-primary");
        let guarded_vault_id = deterministic_id("MPBLNV-VAULT", "devnet-guarded");
        let risk_low_id = deterministic_id("MPBLNV-RISK", "low");
        let risk_guarded_id = deterministic_id("MPBLNV-RISK", "guarded");

        let reserve_alpha_id = deterministic_id("MPBLNV-RESERVE", "maker-alpha");
        let reserve_beta_id = deterministic_id("MPBLNV-RESERVE", "maker-beta");
        let reserve_gamma_id = deterministic_id("MPBLNV-RESERVE", "maker-gamma");
        let maker_alpha_id = deterministic_id("MPBLNV-MAKER", "alpha");
        let maker_beta_id = deterministic_id("MPBLNV-MAKER", "beta");
        let maker_gamma_id = deterministic_id("MPBLNV-MAKER", "gamma");

        let lane_fast_id = deterministic_id("MPBLNV-LANE", "fast-sponsored");
        let lane_batch_id = deterministic_id("MPBLNV-LANE", "batch-sponsored");
        let lane_guarded_id = deterministic_id("MPBLNV-LANE", "guarded-sponsored");

        let mut preferred_fast = BTreeSet::new();
        preferred_fast.insert(maker_alpha_id.clone());
        preferred_fast.insert(maker_beta_id.clone());

        let mut preferred_batch = BTreeSet::new();
        preferred_batch.insert(maker_beta_id.clone());
        preferred_batch.insert(maker_gamma_id.clone());

        let mut preferred_guarded = BTreeSet::new();
        preferred_guarded.insert(maker_gamma_id.clone());

        let vaults = map_from_items(vec![
            Vault {
                vault_id: vault_id.clone(),
                label: "devnet-primary-xmr-netting-vault".to_string(),
                status: VaultStatus::Open,
                monero_subaddress_commitment: deterministic_id(
                    "MPBLNV-SUBADDRESS",
                    "primary-subaddress",
                ),
                view_key_commitment: deterministic_id("MPBLNV-VIEWKEY", "primary-view-key"),
                operator_committee_root: string_root(
                    "MPBLNV-OPERATOR-COMMITTEE",
                    &["operator-a", "operator-b", "operator-c"],
                ),
                maker_set_root: string_root(
                    "MPBLNV-MAKER-SET",
                    &[&maker_alpha_id, &maker_beta_id, &maker_gamma_id],
                ),
                lane_set_root: string_root("MPBLNV-LANE-SET", &[&lane_fast_id, &lane_batch_id]),
                risk_band_id: risk_low_id.clone(),
                opened_at_height: height.saturating_sub(1_800),
                max_private_exit_amount: 850_000_000_000,
                max_private_deposit_amount: 1_250_000_000_000,
                reserve_floor_piconero: 2_500_000_000_000,
                shielded_note_root: deterministic_id("MPBLNV-NOTE-ROOT", "primary"),
                nullifier_root: deterministic_id("MPBLNV-NULLIFIER-ROOT", "primary"),
            },
            Vault {
                vault_id: guarded_vault_id.clone(),
                label: "devnet-guarded-xmr-netting-vault".to_string(),
                status: VaultStatus::Guarded,
                monero_subaddress_commitment: deterministic_id(
                    "MPBLNV-SUBADDRESS",
                    "guarded-subaddress",
                ),
                view_key_commitment: deterministic_id("MPBLNV-VIEWKEY", "guarded-view-key"),
                operator_committee_root: string_root(
                    "MPBLNV-OPERATOR-COMMITTEE",
                    &["operator-b", "operator-d", "operator-e"],
                ),
                maker_set_root: string_root("MPBLNV-MAKER-SET", &[&maker_gamma_id]),
                lane_set_root: string_root("MPBLNV-LANE-SET", &[&lane_guarded_id]),
                risk_band_id: risk_guarded_id.clone(),
                opened_at_height: height.saturating_sub(900),
                max_private_exit_amount: 420_000_000_000,
                max_private_deposit_amount: 620_000_000_000,
                reserve_floor_piconero: 1_100_000_000_000,
                shielded_note_root: deterministic_id("MPBLNV-NOTE-ROOT", "guarded"),
                nullifier_root: deterministic_id("MPBLNV-NULLIFIER-ROOT", "guarded"),
            },
        ]);

        let reserve_proofs = map_from_items(vec![
            ReserveProof {
                proof_id: reserve_alpha_id.clone(),
                vault_id: vault_id.clone(),
                maker_id: maker_alpha_id.clone(),
                status: ReserveProofStatus::Fresh,
                reserve_amount_piconero: 3_900_000_000_000,
                liabilities_piconero: 1_280_000_000_000,
                view_key_root: deterministic_id("MPBLNV-RESERVE-VIEW-ROOT", "alpha"),
                output_set_root: deterministic_id("MPBLNV-RESERVE-OUTPUT-ROOT", "alpha"),
                challenge_root: deterministic_id("MPBLNV-RESERVE-CHALLENGE-ROOT", "alpha"),
                proven_at_height: height.saturating_sub(32),
                expires_at_height: height + config.reserve_proof_ttl_blocks,
            },
            ReserveProof {
                proof_id: reserve_beta_id.clone(),
                vault_id: vault_id.clone(),
                maker_id: maker_beta_id.clone(),
                status: ReserveProofStatus::Usable,
                reserve_amount_piconero: 4_250_000_000_000,
                liabilities_piconero: 2_020_000_000_000,
                view_key_root: deterministic_id("MPBLNV-RESERVE-VIEW-ROOT", "beta"),
                output_set_root: deterministic_id("MPBLNV-RESERVE-OUTPUT-ROOT", "beta"),
                challenge_root: deterministic_id("MPBLNV-RESERVE-CHALLENGE-ROOT", "beta"),
                proven_at_height: height.saturating_sub(110),
                expires_at_height: height + config.reserve_proof_ttl_blocks - 20,
            },
            ReserveProof {
                proof_id: reserve_gamma_id.clone(),
                vault_id: guarded_vault_id.clone(),
                maker_id: maker_gamma_id.clone(),
                status: ReserveProofStatus::Aging,
                reserve_amount_piconero: 1_900_000_000_000,
                liabilities_piconero: 1_020_000_000_000,
                view_key_root: deterministic_id("MPBLNV-RESERVE-VIEW-ROOT", "gamma"),
                output_set_root: deterministic_id("MPBLNV-RESERVE-OUTPUT-ROOT", "gamma"),
                challenge_root: deterministic_id("MPBLNV-RESERVE-CHALLENGE-ROOT", "gamma"),
                proven_at_height: height.saturating_sub(420),
                expires_at_height: height + config.reserve_proof_ttl_blocks - 400,
            },
        ]);

        let inv_alpha_id = deterministic_id("MPBLNV-INVENTORY", "alpha-hot");
        let inv_beta_id = deterministic_id("MPBLNV-INVENTORY", "beta-batch");
        let inv_gamma_id = deterministic_id("MPBLNV-INVENTORY", "gamma-guarded");

        let inventory_commitments = map_from_items(vec![
            InventoryCommitment {
                commitment_id: inv_alpha_id.clone(),
                maker_id: maker_alpha_id.clone(),
                vault_id: vault_id.clone(),
                status: CommitmentStatus::Reserved,
                amount_piconero: 1_650_000_000_000,
                reserved_piconero: 540_000_000_000,
                min_exit_amount: 20_000_000_000,
                max_exit_amount: 450_000_000_000,
                inventory_blinding_commitment: deterministic_id(
                    "MPBLNV-INVENTORY-BLINDING",
                    "alpha-hot",
                ),
                reserve_proof_id: reserve_alpha_id.clone(),
                expires_at_height: height + 360,
            },
            InventoryCommitment {
                commitment_id: inv_beta_id.clone(),
                maker_id: maker_beta_id.clone(),
                vault_id: vault_id.clone(),
                status: CommitmentStatus::Netted,
                amount_piconero: 2_100_000_000_000,
                reserved_piconero: 800_000_000_000,
                min_exit_amount: 15_000_000_000,
                max_exit_amount: 650_000_000_000,
                inventory_blinding_commitment: deterministic_id(
                    "MPBLNV-INVENTORY-BLINDING",
                    "beta-batch",
                ),
                reserve_proof_id: reserve_beta_id.clone(),
                expires_at_height: height + 480,
            },
            InventoryCommitment {
                commitment_id: inv_gamma_id.clone(),
                maker_id: maker_gamma_id.clone(),
                vault_id: guarded_vault_id.clone(),
                status: CommitmentStatus::Queued,
                amount_piconero: 920_000_000_000,
                reserved_piconero: 120_000_000_000,
                min_exit_amount: 10_000_000_000,
                max_exit_amount: 220_000_000_000,
                inventory_blinding_commitment: deterministic_id(
                    "MPBLNV-INVENTORY-BLINDING",
                    "gamma-guarded",
                ),
                reserve_proof_id: reserve_gamma_id.clone(),
                expires_at_height: height + 260,
            },
        ]);

        let makers = map_from_items(vec![
            Maker {
                maker_id: maker_alpha_id.clone(),
                label: "devnet-maker-alpha".to_string(),
                status: MakerStatus::Active,
                inventory_commitment_root: item_root_from_map(
                    "MPBLNV-MAKER-INVENTORY",
                    &inventory_commitments,
                    &[&inv_alpha_id],
                ),
                reserve_proof_id: reserve_alpha_id.clone(),
                max_inventory_piconero: 2_000_000_000_000,
                reserved_inventory_piconero: 540_000_000_000,
                private_quote_bps: 34,
                reliability_bps: 9_960,
                pq_key_commitment: deterministic_id("MPBLNV-MAKER-PQ-KEY", "alpha"),
                last_seen_height: height.saturating_sub(2),
            },
            Maker {
                maker_id: maker_beta_id.clone(),
                label: "devnet-maker-beta".to_string(),
                status: MakerStatus::Constrained,
                inventory_commitment_root: item_root_from_map(
                    "MPBLNV-MAKER-INVENTORY",
                    &inventory_commitments,
                    &[&inv_beta_id],
                ),
                reserve_proof_id: reserve_beta_id.clone(),
                max_inventory_piconero: 2_600_000_000_000,
                reserved_inventory_piconero: 800_000_000_000,
                private_quote_bps: 42,
                reliability_bps: 9_820,
                pq_key_commitment: deterministic_id("MPBLNV-MAKER-PQ-KEY", "beta"),
                last_seen_height: height.saturating_sub(6),
            },
            Maker {
                maker_id: maker_gamma_id.clone(),
                label: "devnet-maker-gamma".to_string(),
                status: MakerStatus::Draining,
                inventory_commitment_root: item_root_from_map(
                    "MPBLNV-MAKER-INVENTORY",
                    &inventory_commitments,
                    &[&inv_gamma_id],
                ),
                reserve_proof_id: reserve_gamma_id.clone(),
                max_inventory_piconero: 1_200_000_000_000,
                reserved_inventory_piconero: 120_000_000_000,
                private_quote_bps: 51,
                reliability_bps: 9_720,
                pq_key_commitment: deterministic_id("MPBLNV-MAKER-PQ-KEY", "gamma"),
                last_seen_height: height.saturating_sub(12),
            },
        ]);

        let deposit_0_id = deterministic_id("MPBLNV-DEPOSIT", "primary-0");
        let deposit_1_id = deterministic_id("MPBLNV-DEPOSIT", "primary-1");
        let deposit_2_id = deterministic_id("MPBLNV-DEPOSIT", "guarded-0");
        let exit_0_id = deterministic_id("MPBLNV-EXIT", "primary-0");
        let exit_1_id = deterministic_id("MPBLNV-EXIT", "primary-1");
        let exit_2_id = deterministic_id("MPBLNV-EXIT", "guarded-0");
        let payout_0_id = deterministic_id("MPBLNV-PAYOUT", "primary-0");
        let payout_1_id = deterministic_id("MPBLNV-PAYOUT", "primary-1");
        let payout_2_id = deterministic_id("MPBLNV-PAYOUT", "guarded-0");
        let withdrawal_0_id = deterministic_id("MPBLNV-WITHDRAWAL", "primary-fast-0");
        let withdrawal_1_id = deterministic_id("MPBLNV-WITHDRAWAL", "primary-batch-0");
        let withdrawal_2_id = deterministic_id("MPBLNV-WITHDRAWAL", "guarded-0");
        let batch_primary_id = deterministic_id("MPBLNV-BATCH", "primary-window");
        let batch_guarded_id = deterministic_id("MPBLNV-BATCH", "guarded-window");
        let receipt_primary_id = deterministic_id("MPBLNV-RECEIPT", "primary-window");
        let receipt_guarded_id = deterministic_id("MPBLNV-RECEIPT", "guarded-window");
        let reorg_primary_id = deterministic_id("MPBLNV-REORG-BUFFER", "primary-window");
        let reorg_guarded_id = deterministic_id("MPBLNV-REORG-BUFFER", "guarded-window");

        let shielded_deposits = map_from_items(vec![
            ShieldedDeposit {
                deposit_id: deposit_0_id.clone(),
                vault_id: vault_id.clone(),
                status: CommitmentStatus::Netted,
                amount_piconero: 480_000_000_000,
                note_commitment: deterministic_id("MPBLNV-NOTE", "primary-deposit-0"),
                depositor_commitment: deterministic_id("MPBLNV-DEPOSITOR", "primary-0"),
                monero_txid_commitment: deterministic_id("MPBLNV-MONERO-TXID", "deposit-0"),
                unlock_height: height.saturating_sub(18),
                netting_batch_id: batch_primary_id.clone(),
                received_at_height: height.saturating_sub(42),
            },
            ShieldedDeposit {
                deposit_id: deposit_1_id.clone(),
                vault_id: vault_id.clone(),
                status: CommitmentStatus::Queued,
                amount_piconero: 360_000_000_000,
                note_commitment: deterministic_id("MPBLNV-NOTE", "primary-deposit-1"),
                depositor_commitment: deterministic_id("MPBLNV-DEPOSITOR", "primary-1"),
                monero_txid_commitment: deterministic_id("MPBLNV-MONERO-TXID", "deposit-1"),
                unlock_height: height + 4,
                netting_batch_id: batch_primary_id.clone(),
                received_at_height: height.saturating_sub(6),
            },
            ShieldedDeposit {
                deposit_id: deposit_2_id.clone(),
                vault_id: guarded_vault_id.clone(),
                status: CommitmentStatus::Netted,
                amount_piconero: 210_000_000_000,
                note_commitment: deterministic_id("MPBLNV-NOTE", "guarded-deposit-0"),
                depositor_commitment: deterministic_id("MPBLNV-DEPOSITOR", "guarded-0"),
                monero_txid_commitment: deterministic_id("MPBLNV-MONERO-TXID", "deposit-2"),
                unlock_height: height.saturating_sub(20),
                netting_batch_id: batch_guarded_id.clone(),
                received_at_height: height.saturating_sub(45),
            },
        ]);

        let nullifier_0 = deterministic_id("MPBLNV-NULLIFIER", "primary-exit-0");
        let nullifier_1 = deterministic_id("MPBLNV-NULLIFIER", "primary-exit-1");
        let nullifier_2 = deterministic_id("MPBLNV-NULLIFIER", "guarded-exit-0");

        let shielded_exits = map_from_items(vec![
            ShieldedExit {
                exit_id: exit_0_id.clone(),
                vault_id: vault_id.clone(),
                status: CommitmentStatus::Settling,
                amount_piconero: 520_000_000_000,
                nullifier: nullifier_0.clone(),
                payout_commitment_id: payout_0_id.clone(),
                maker_id: maker_alpha_id.clone(),
                sponsored_withdrawal_id: withdrawal_0_id.clone(),
                netting_batch_id: batch_primary_id.clone(),
                privacy_set_size: 96,
                requested_at_height: height.saturating_sub(36),
                deadline_height: height + 60,
            },
            ShieldedExit {
                exit_id: exit_1_id.clone(),
                vault_id: vault_id.clone(),
                status: CommitmentStatus::Netted,
                amount_piconero: 300_000_000_000,
                nullifier: nullifier_1.clone(),
                payout_commitment_id: payout_1_id.clone(),
                maker_id: maker_beta_id.clone(),
                sponsored_withdrawal_id: withdrawal_1_id.clone(),
                netting_batch_id: batch_primary_id.clone(),
                privacy_set_size: 84,
                requested_at_height: height.saturating_sub(20),
                deadline_height: height + 84,
            },
            ShieldedExit {
                exit_id: exit_2_id.clone(),
                vault_id: guarded_vault_id.clone(),
                status: CommitmentStatus::Reserved,
                amount_piconero: 160_000_000_000,
                nullifier: nullifier_2.clone(),
                payout_commitment_id: payout_2_id.clone(),
                maker_id: maker_gamma_id.clone(),
                sponsored_withdrawal_id: withdrawal_2_id.clone(),
                netting_batch_id: batch_guarded_id.clone(),
                privacy_set_size: 48,
                requested_at_height: height.saturating_sub(14),
                deadline_height: height + 50,
            },
        ]);

        let stealth_payout_commitments = map_from_items(vec![
            stealth_payout(
                &payout_0_id,
                &exit_0_id,
                &vault_id,
                CommitmentStatus::Settling,
                520_000_000_000,
                height,
                "primary-0",
            ),
            stealth_payout(
                &payout_1_id,
                &exit_1_id,
                &vault_id,
                CommitmentStatus::Netted,
                300_000_000_000,
                height,
                "primary-1",
            ),
            stealth_payout(
                &payout_2_id,
                &exit_2_id,
                &guarded_vault_id,
                CommitmentStatus::Reserved,
                160_000_000_000,
                height,
                "guarded-0",
            ),
        ]);

        let sponsored_withdrawal_lanes = map_from_items(vec![
            SponsoredWithdrawalLane {
                lane_id: lane_fast_id.clone(),
                vault_id: vault_id.clone(),
                sponsor_commitment: deterministic_id("MPBLNV-SPONSOR", "fast-lane"),
                status: LaneStatus::Open,
                fee_budget_piconero: 18_000_000_000,
                spent_fee_budget_piconero: 5_300_000_000,
                max_withdrawals_per_window: 128,
                min_privacy_set: 48,
                preferred_maker_ids: preferred_fast,
                expires_at_height: height + config.sponsor_ttl_blocks,
            },
            SponsoredWithdrawalLane {
                lane_id: lane_batch_id.clone(),
                vault_id: vault_id.clone(),
                sponsor_commitment: deterministic_id("MPBLNV-SPONSOR", "batch-lane"),
                status: LaneStatus::Throttled,
                fee_budget_piconero: 12_000_000_000,
                spent_fee_budget_piconero: 2_100_000_000,
                max_withdrawals_per_window: 256,
                min_privacy_set: 64,
                preferred_maker_ids: preferred_batch,
                expires_at_height: height + config.sponsor_ttl_blocks + 100,
            },
            SponsoredWithdrawalLane {
                lane_id: lane_guarded_id.clone(),
                vault_id: guarded_vault_id.clone(),
                sponsor_commitment: deterministic_id("MPBLNV-SPONSOR", "guarded-lane"),
                status: LaneStatus::SponsorOnly,
                fee_budget_piconero: 6_000_000_000,
                spent_fee_budget_piconero: 1_400_000_000,
                max_withdrawals_per_window: 48,
                min_privacy_set: 40,
                preferred_maker_ids: preferred_guarded,
                expires_at_height: height + config.sponsor_ttl_blocks - 20,
            },
        ]);

        let sponsored_withdrawals = map_from_items(vec![
            SponsoredWithdrawal {
                withdrawal_id: withdrawal_0_id.clone(),
                lane_id: lane_fast_id.clone(),
                exit_id: exit_0_id.clone(),
                status: CommitmentStatus::Settling,
                fee_piconero: 1_800_000_000,
                sponsor_authorization_commitment: deterministic_id("MPBLNV-SPONSOR-AUTH", "fast-0"),
                relayer_commitment: deterministic_id("MPBLNV-RELAYER", "fast-0"),
                submitted_at_height: height.saturating_sub(10),
                expires_at_height: height + 120,
            },
            SponsoredWithdrawal {
                withdrawal_id: withdrawal_1_id.clone(),
                lane_id: lane_batch_id.clone(),
                exit_id: exit_1_id.clone(),
                status: CommitmentStatus::Netted,
                fee_piconero: 1_100_000_000,
                sponsor_authorization_commitment: deterministic_id(
                    "MPBLNV-SPONSOR-AUTH",
                    "batch-0",
                ),
                relayer_commitment: deterministic_id("MPBLNV-RELAYER", "batch-0"),
                submitted_at_height: height.saturating_sub(8),
                expires_at_height: height + 160,
            },
            SponsoredWithdrawal {
                withdrawal_id: withdrawal_2_id.clone(),
                lane_id: lane_guarded_id.clone(),
                exit_id: exit_2_id.clone(),
                status: CommitmentStatus::Reserved,
                fee_piconero: 900_000_000,
                sponsor_authorization_commitment: deterministic_id(
                    "MPBLNV-SPONSOR-AUTH",
                    "guarded-0",
                ),
                relayer_commitment: deterministic_id("MPBLNV-RELAYER", "guarded-0"),
                submitted_at_height: height.saturating_sub(5),
                expires_at_height: height + 100,
            },
        ]);

        let mut primary_deposits = BTreeSet::new();
        primary_deposits.insert(deposit_0_id.clone());
        primary_deposits.insert(deposit_1_id.clone());
        let mut primary_exits = BTreeSet::new();
        primary_exits.insert(exit_0_id.clone());
        primary_exits.insert(exit_1_id.clone());
        let mut guarded_deposits = BTreeSet::new();
        guarded_deposits.insert(deposit_2_id.clone());
        let mut guarded_exits = BTreeSet::new();
        guarded_exits.insert(exit_2_id.clone());

        let netting_batches = map_from_items(vec![
            NettingBatch {
                batch_id: batch_primary_id.clone(),
                vault_id: vault_id.clone(),
                epoch: height / config.epoch_blocks,
                window_start_height: height.saturating_sub(config.netting_window_blocks),
                window_end_height: height,
                status: CommitmentStatus::Settling,
                deposit_ids: primary_deposits,
                exit_ids: primary_exits,
                gross_deposit_piconero: 840_000_000_000,
                gross_exit_piconero: 820_000_000_000,
                net_required_piconero: -20_000_000_000,
                settlement_receipt_id: receipt_primary_id.clone(),
                batch_proof_commitment: deterministic_id("MPBLNV-BATCH-PROOF", "primary"),
            },
            NettingBatch {
                batch_id: batch_guarded_id.clone(),
                vault_id: guarded_vault_id.clone(),
                epoch: height / config.epoch_blocks,
                window_start_height: height.saturating_sub(config.netting_window_blocks),
                window_end_height: height,
                status: CommitmentStatus::Reserved,
                deposit_ids: guarded_deposits,
                exit_ids: guarded_exits,
                gross_deposit_piconero: 210_000_000_000,
                gross_exit_piconero: 160_000_000_000,
                net_required_piconero: -50_000_000_000,
                settlement_receipt_id: receipt_guarded_id.clone(),
                batch_proof_commitment: deterministic_id("MPBLNV-BATCH-PROOF", "guarded"),
            },
        ]);

        let settlement_receipts = map_from_items(vec![
            SettlementReceipt {
                receipt_id: receipt_primary_id.clone(),
                batch_id: batch_primary_id.clone(),
                vault_id: vault_id.clone(),
                status: ReceiptStatus::Confirming,
                delayed_until_height: height + config.settlement_delay_blocks,
                submitted_at_height: height.saturating_sub(2),
                finalized_at_height: 0,
                monero_txid_commitment: deterministic_id("MPBLNV-MONERO-TXID", "primary-receipt"),
                reserve_delta_piconero: -20_000_000_000,
                payout_count: 2,
                reorg_buffer_id: reorg_primary_id.clone(),
            },
            SettlementReceipt {
                receipt_id: receipt_guarded_id.clone(),
                batch_id: batch_guarded_id.clone(),
                vault_id: guarded_vault_id.clone(),
                status: ReceiptStatus::WaitingForDelay,
                delayed_until_height: height + config.settlement_delay_blocks + 4,
                submitted_at_height: 0,
                finalized_at_height: 0,
                monero_txid_commitment: deterministic_id("MPBLNV-MONERO-TXID", "guarded-receipt"),
                reserve_delta_piconero: -50_000_000_000,
                payout_count: 1,
                reorg_buffer_id: reorg_guarded_id.clone(),
            },
        ]);

        let risk_low = RiskBand {
            band_id: risk_low_id.clone(),
            vault_id: vault_id.clone(),
            kind: RiskBandKind::Low,
            exposure_bps: 2_120,
            inventory_utilization_bps: 3_410,
            unproven_reserve_bps: 220,
            withdrawal_throttle_bps: 10_000,
            requires_manual_attestation: false,
            evaluated_at_height: height.saturating_sub(1),
        };
        let risk_guarded = RiskBand {
            band_id: risk_guarded_id.clone(),
            vault_id: guarded_vault_id.clone(),
            kind: RiskBandKind::Guarded,
            exposure_bps: 4_680,
            inventory_utilization_bps: 5_920,
            unproven_reserve_bps: 780,
            withdrawal_throttle_bps: 6_500,
            requires_manual_attestation: true,
            evaluated_at_height: height.saturating_sub(1),
        };
        let primary_risk_subject_root =
            item_root("MPBLNV-WATCHTOWER-SUBJECT", &risk_low.public_record());
        let guarded_risk_subject_root =
            item_root("MPBLNV-WATCHTOWER-SUBJECT", &risk_guarded.public_record());
        let risk_bands = map_from_items(vec![risk_low, risk_guarded]);

        let mut primary_affected = BTreeSet::new();
        primary_affected.insert(exit_0_id.clone());
        primary_affected.insert(exit_1_id.clone());
        let mut guarded_affected = BTreeSet::new();
        guarded_affected.insert(exit_2_id.clone());

        let reorg_buffers = map_from_items(vec![
            ReorgBuffer {
                buffer_id: reorg_primary_id.clone(),
                vault_id: vault_id.clone(),
                receipt_id: receipt_primary_id.clone(),
                anchor_height: height.saturating_sub(2),
                release_height: height + config.reorg_buffer_blocks,
                buffered_txid_commitment: deterministic_id("MPBLNV-BUFFERED-TXID", "primary"),
                replacement_txid_commitment: deterministic_id("MPBLNV-REPLACEMENT-TXID", "primary"),
                affected_exit_ids: primary_affected,
                status: ReceiptStatus::ReorgBuffered,
            },
            ReorgBuffer {
                buffer_id: reorg_guarded_id.clone(),
                vault_id: guarded_vault_id.clone(),
                receipt_id: receipt_guarded_id.clone(),
                anchor_height: height,
                release_height: height + config.reorg_buffer_blocks + 4,
                buffered_txid_commitment: deterministic_id("MPBLNV-BUFFERED-TXID", "guarded"),
                replacement_txid_commitment: deterministic_id("MPBLNV-REPLACEMENT-TXID", "guarded"),
                affected_exit_ids: guarded_affected,
                status: ReceiptStatus::WaitingForDelay,
            },
        ]);

        let watchtower_attestations = map_from_items(vec![
            WatchtowerAttestation {
                attestation_id: deterministic_id("MPBLNV-WATCHTOWER", "primary-risk"),
                vault_id: vault_id.clone(),
                subject_root: primary_risk_subject_root,
                signer_commitment: deterministic_id("MPBLNV-WATCHTOWER-SIGNER", "sentinel-a"),
                pq_signature_commitment: deterministic_id(
                    "MPBLNV-WATCHTOWER-SIG",
                    "sentinel-a-primary",
                ),
                observed_height: height.saturating_sub(1),
                signed_at_height: height,
            },
            WatchtowerAttestation {
                attestation_id: deterministic_id("MPBLNV-WATCHTOWER", "guarded-risk"),
                vault_id: guarded_vault_id.clone(),
                subject_root: guarded_risk_subject_root,
                signer_commitment: deterministic_id("MPBLNV-WATCHTOWER-SIGNER", "sentinel-b"),
                pq_signature_commitment: deterministic_id(
                    "MPBLNV-WATCHTOWER-SIG",
                    "sentinel-b-guarded",
                ),
                observed_height: height.saturating_sub(1),
                signed_at_height: height,
            },
        ]);

        let spent_nullifiers = BTreeSet::from([nullifier_0, nullifier_1, nullifier_2]);

        let state = Self {
            height,
            config,
            vaults,
            makers,
            inventory_commitments,
            shielded_deposits,
            shielded_exits,
            stealth_payout_commitments,
            sponsored_withdrawal_lanes,
            sponsored_withdrawals,
            netting_batches,
            settlement_receipts,
            reserve_proofs,
            risk_bands,
            reorg_buffers,
            watchtower_attestations,
            spent_nullifiers,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()> {
        self.config.validate()?;
        if self.height == 0 {
            return Err("state height must be non-zero".to_string());
        }
        if self.vaults.is_empty() {
            return Err("at least one vault is required".to_string());
        }
        validate_unique_keys("vault", self.vaults.keys())?;
        validate_unique_keys("maker", self.makers.keys())?;
        validate_unique_keys("inventory commitment", self.inventory_commitments.keys())?;
        validate_unique_keys("shielded deposit", self.shielded_deposits.keys())?;
        validate_unique_keys("shielded exit", self.shielded_exits.keys())?;
        validate_unique_keys(
            "stealth payout commitment",
            self.stealth_payout_commitments.keys(),
        )?;
        validate_unique_keys(
            "sponsored withdrawal lane",
            self.sponsored_withdrawal_lanes.keys(),
        )?;
        validate_unique_keys("sponsored withdrawal", self.sponsored_withdrawals.keys())?;
        validate_unique_keys("netting batch", self.netting_batches.keys())?;
        validate_unique_keys("settlement receipt", self.settlement_receipts.keys())?;
        validate_unique_keys("reserve proof", self.reserve_proofs.keys())?;
        validate_unique_keys("risk band", self.risk_bands.keys())?;
        validate_unique_keys("reorg buffer", self.reorg_buffers.keys())?;
        validate_unique_keys(
            "watchtower attestation",
            self.watchtower_attestations.keys(),
        )?;

        for vault in self.vaults.values() {
            require_id("vault", &vault.vault_id)?;
            if !self.risk_bands.contains_key(&vault.risk_band_id) {
                return Err(format!(
                    "vault {} references missing risk band",
                    vault.vault_id
                ));
            }
            if vault.max_private_exit_amount == 0
                || vault.max_private_deposit_amount == 0
                || vault.reserve_floor_piconero == 0
            {
                return Err(format!("vault {} has zero limits", vault.vault_id));
            }
            if vault.opened_at_height > self.height {
                return Err(format!("vault {} opens in the future", vault.vault_id));
            }
        }

        for maker in self.makers.values() {
            require_id("maker", &maker.maker_id)?;
            if !self.reserve_proofs.contains_key(&maker.reserve_proof_id) {
                return Err(format!(
                    "maker {} references missing reserve proof",
                    maker.maker_id
                ));
            }
            if maker.reserved_inventory_piconero > maker.max_inventory_piconero {
                return Err(format!("maker {} over-reserved inventory", maker.maker_id));
            }
            validate_bps("maker private quote", maker.private_quote_bps)?;
            validate_bps("maker reliability", maker.reliability_bps)?;
            if maker.last_seen_height > self.height {
                return Err(format!("maker {} last seen in future", maker.maker_id));
            }
        }

        for commitment in self.inventory_commitments.values() {
            require_id("inventory commitment", &commitment.commitment_id)?;
            require_link(&self.vaults, "inventory vault", &commitment.vault_id)?;
            require_link(&self.makers, "inventory maker", &commitment.maker_id)?;
            require_link(
                &self.reserve_proofs,
                "inventory reserve proof",
                &commitment.reserve_proof_id,
            )?;
            if commitment.amount_piconero == 0 || commitment.max_exit_amount == 0 {
                return Err(format!(
                    "inventory commitment {} has zero amount",
                    commitment.commitment_id
                ));
            }
            if commitment.reserved_piconero > commitment.amount_piconero {
                return Err(format!(
                    "inventory commitment {} over-reserved",
                    commitment.commitment_id
                ));
            }
            if commitment.min_exit_amount > commitment.max_exit_amount {
                return Err(format!(
                    "inventory commitment {} min exceeds max",
                    commitment.commitment_id
                ));
            }
        }

        for deposit in self.shielded_deposits.values() {
            require_id("shielded deposit", &deposit.deposit_id)?;
            require_link(&self.vaults, "deposit vault", &deposit.vault_id)?;
            require_link(
                &self.netting_batches,
                "deposit netting batch",
                &deposit.netting_batch_id,
            )?;
            if deposit.amount_piconero == 0 {
                return Err(format!("deposit {} amount is zero", deposit.deposit_id));
            }
            if deposit.received_at_height > self.height {
                return Err(format!("deposit {} received in future", deposit.deposit_id));
            }
        }

        let mut observed_nullifiers = BTreeSet::new();
        for exit in self.shielded_exits.values() {
            require_id("shielded exit", &exit.exit_id)?;
            require_link(&self.vaults, "exit vault", &exit.vault_id)?;
            require_link(&self.makers, "exit maker", &exit.maker_id)?;
            require_link(
                &self.stealth_payout_commitments,
                "exit payout commitment",
                &exit.payout_commitment_id,
            )?;
            require_link(
                &self.sponsored_withdrawals,
                "exit sponsored withdrawal",
                &exit.sponsored_withdrawal_id,
            )?;
            require_link(
                &self.netting_batches,
                "exit netting batch",
                &exit.netting_batch_id,
            )?;
            if exit.amount_piconero == 0 {
                return Err(format!("exit {} amount is zero", exit.exit_id));
            }
            if exit.privacy_set_size < self.config.min_privacy_set {
                return Err(format!("exit {} privacy set too small", exit.exit_id));
            }
            if exit.requested_at_height > self.height {
                return Err(format!("exit {} requested in future", exit.exit_id));
            }
            if !observed_nullifiers.insert(exit.nullifier.clone()) {
                return Err(format!("duplicate nullifier on exit {}", exit.exit_id));
            }
        }
        if observed_nullifiers != self.spent_nullifiers {
            return Err("spent nullifier set does not match exits".to_string());
        }

        for payout in self.stealth_payout_commitments.values() {
            require_id("stealth payout", &payout.payout_commitment_id)?;
            require_link(&self.vaults, "payout vault", &payout.vault_id)?;
            require_link(&self.shielded_exits, "payout exit", &payout.exit_id)?;
            if payout.amount_piconero == 0 {
                return Err(format!(
                    "payout commitment {} amount is zero",
                    payout.payout_commitment_id
                ));
            }
            if payout.created_at_height > self.height {
                return Err(format!(
                    "payout commitment {} created in future",
                    payout.payout_commitment_id
                ));
            }
        }

        for lane in self.sponsored_withdrawal_lanes.values() {
            require_id("sponsored lane", &lane.lane_id)?;
            require_link(&self.vaults, "lane vault", &lane.vault_id)?;
            if lane.spent_fee_budget_piconero > lane.fee_budget_piconero {
                return Err(format!("lane {} over-spent fee budget", lane.lane_id));
            }
            if lane.min_privacy_set < self.config.min_privacy_set {
                return Err(format!("lane {} privacy floor too low", lane.lane_id));
            }
            for maker_id in &lane.preferred_maker_ids {
                require_link(&self.makers, "lane preferred maker", maker_id)?;
            }
        }

        for withdrawal in self.sponsored_withdrawals.values() {
            require_id("sponsored withdrawal", &withdrawal.withdrawal_id)?;
            require_link(
                &self.sponsored_withdrawal_lanes,
                "withdrawal lane",
                &withdrawal.lane_id,
            )?;
            require_link(&self.shielded_exits, "withdrawal exit", &withdrawal.exit_id)?;
            if withdrawal.fee_piconero == 0 {
                return Err(format!(
                    "sponsored withdrawal {} fee is zero",
                    withdrawal.withdrawal_id
                ));
            }
            if withdrawal.submitted_at_height > self.height {
                return Err(format!(
                    "sponsored withdrawal {} submitted in future",
                    withdrawal.withdrawal_id
                ));
            }
        }

        for batch in self.netting_batches.values() {
            require_id("netting batch", &batch.batch_id)?;
            require_link(&self.vaults, "batch vault", &batch.vault_id)?;
            require_link(
                &self.settlement_receipts,
                "batch settlement receipt",
                &batch.settlement_receipt_id,
            )?;
            if batch.window_start_height > batch.window_end_height {
                return Err(format!("batch {} has inverted window", batch.batch_id));
            }
            if batch.window_end_height > self.height {
                return Err(format!("batch {} ends in future", batch.batch_id));
            }
            let deposit_total = sum_deposits(&self.shielded_deposits, &batch.deposit_ids)?;
            let exit_total = sum_exits(&self.shielded_exits, &batch.exit_ids)?;
            if deposit_total != batch.gross_deposit_piconero {
                return Err(format!("batch {} deposit total mismatch", batch.batch_id));
            }
            if exit_total != batch.gross_exit_piconero {
                return Err(format!("batch {} exit total mismatch", batch.batch_id));
            }
            let expected_net = exit_total as i128 - deposit_total as i128;
            if batch.net_required_piconero != expected_net {
                return Err(format!("batch {} net amount mismatch", batch.batch_id));
            }
        }

        for receipt in self.settlement_receipts.values() {
            require_id("settlement receipt", &receipt.receipt_id)?;
            require_link(&self.vaults, "receipt vault", &receipt.vault_id)?;
            require_link(&self.netting_batches, "receipt batch", &receipt.batch_id)?;
            require_link(
                &self.reorg_buffers,
                "receipt reorg buffer",
                &receipt.reorg_buffer_id,
            )?;
            if receipt.submitted_at_height > self.height {
                return Err(format!(
                    "receipt {} submitted in future",
                    receipt.receipt_id
                ));
            }
            if receipt.finalized_at_height != 0
                && receipt.finalized_at_height < receipt.submitted_at_height
            {
                return Err(format!(
                    "receipt {} finalized before submission",
                    receipt.receipt_id
                ));
            }
        }

        for proof in self.reserve_proofs.values() {
            require_id("reserve proof", &proof.proof_id)?;
            require_link(&self.vaults, "reserve proof vault", &proof.vault_id)?;
            if proof.reserve_amount_piconero < proof.liabilities_piconero {
                return Err(format!("reserve proof {} is insolvent", proof.proof_id));
            }
            if proof.proven_at_height > self.height {
                return Err(format!("reserve proof {} proven in future", proof.proof_id));
            }
            if proof.expires_at_height <= proof.proven_at_height {
                return Err(format!(
                    "reserve proof {} expires too early",
                    proof.proof_id
                ));
            }
        }

        for band in self.risk_bands.values() {
            require_id("risk band", &band.band_id)?;
            require_link(&self.vaults, "risk band vault", &band.vault_id)?;
            validate_bps("risk exposure", band.exposure_bps)?;
            validate_bps("risk inventory utilization", band.inventory_utilization_bps)?;
            validate_bps("risk unproven reserve", band.unproven_reserve_bps)?;
            validate_bps("risk withdrawal throttle", band.withdrawal_throttle_bps)?;
            if band.evaluated_at_height > self.height {
                return Err(format!("risk band {} evaluated in future", band.band_id));
            }
        }

        for buffer in self.reorg_buffers.values() {
            require_id("reorg buffer", &buffer.buffer_id)?;
            require_link(&self.vaults, "reorg vault", &buffer.vault_id)?;
            require_link(
                &self.settlement_receipts,
                "reorg receipt",
                &buffer.receipt_id,
            )?;
            if buffer.release_height <= buffer.anchor_height {
                return Err(format!(
                    "reorg buffer {} release too early",
                    buffer.buffer_id
                ));
            }
            for exit_id in &buffer.affected_exit_ids {
                require_link(&self.shielded_exits, "reorg affected exit", exit_id)?;
            }
        }

        for attestation in self.watchtower_attestations.values() {
            require_id("watchtower attestation", &attestation.attestation_id)?;
            require_link(&self.vaults, "attestation vault", &attestation.vault_id)?;
            if attestation.observed_height > attestation.signed_at_height {
                return Err(format!(
                    "watchtower attestation {} signed before observation",
                    attestation.attestation_id
                ));
            }
            if attestation.signed_at_height > self.height {
                return Err(format!(
                    "watchtower attestation {} signed in future",
                    attestation.attestation_id
                ));
            }
        }

        Ok(())
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()> {
        if height == 0 {
            return Err("height must be non-zero".to_string());
        }
        self.height = height;
        self.validate()
    }

    pub fn update_height(
        &mut self,
        delta: u64,
    ) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()> {
        let next = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "height overflow".to_string())?;
        self.set_height(next)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(&self.config.public_record());
        let vault_root = map_root("MPBLNV-VAULT-ROOT", &self.vaults);
        let maker_root = map_root("MPBLNV-MAKER-ROOT", &self.makers);
        let inventory_commitment_root = map_root(
            "MPBLNV-INVENTORY-COMMITMENT-ROOT",
            &self.inventory_commitments,
        );
        let shielded_deposit_root =
            map_root("MPBLNV-SHIELDED-DEPOSIT-ROOT", &self.shielded_deposits);
        let shielded_exit_root = map_root("MPBLNV-SHIELDED-EXIT-ROOT", &self.shielded_exits);
        let stealth_payout_root = map_root(
            "MPBLNV-STEALTH-PAYOUT-ROOT",
            &self.stealth_payout_commitments,
        );
        let sponsored_withdrawal_lane_root = map_root(
            "MPBLNV-SPONSORED-WITHDRAWAL-LANE-ROOT",
            &self.sponsored_withdrawal_lanes,
        );
        let sponsored_withdrawal_root = map_root(
            "MPBLNV-SPONSORED-WITHDRAWAL-ROOT",
            &self.sponsored_withdrawals,
        );
        let netting_batch_root = map_root("MPBLNV-NETTING-BATCH-ROOT", &self.netting_batches);
        let settlement_receipt_root =
            map_root("MPBLNV-SETTLEMENT-RECEIPT-ROOT", &self.settlement_receipts);
        let reserve_proof_root = map_root("MPBLNV-RESERVE-PROOF-ROOT", &self.reserve_proofs);
        let risk_band_root = map_root("MPBLNV-RISK-BAND-ROOT", &self.risk_bands);
        let reorg_buffer_root = map_root("MPBLNV-REORG-BUFFER-ROOT", &self.reorg_buffers);
        let watchtower_attestation_root = map_root(
            "MPBLNV-WATCHTOWER-ATTESTATION-ROOT",
            &self.watchtower_attestations,
        );
        let state_payload = json!({
            "height": self.height,
            "config_root": config_root,
            "vault_root": vault_root,
            "maker_root": maker_root,
            "inventory_commitment_root": inventory_commitment_root,
            "shielded_deposit_root": shielded_deposit_root,
            "shielded_exit_root": shielded_exit_root,
            "stealth_payout_root": stealth_payout_root,
            "sponsored_withdrawal_lane_root": sponsored_withdrawal_lane_root,
            "sponsored_withdrawal_root": sponsored_withdrawal_root,
            "netting_batch_root": netting_batch_root,
            "settlement_receipt_root": settlement_receipt_root,
            "reserve_proof_root": reserve_proof_root,
            "risk_band_root": risk_band_root,
            "reorg_buffer_root": reorg_buffer_root,
            "watchtower_attestation_root": watchtower_attestation_root,
            "spent_nullifier_root": string_set_root("MPBLNV-SPENT-NULLIFIER-ROOT", &self.spent_nullifiers),
        });
        let state_root = domain_hash("MPBLNV-STATE-ROOT", &[HashPart::Json(&state_payload)], 32);
        Roots {
            config_root,
            vault_root,
            maker_root,
            inventory_commitment_root,
            shielded_deposit_root,
            shielded_exit_root,
            stealth_payout_root,
            sponsored_withdrawal_lane_root,
            sponsored_withdrawal_root,
            netting_batch_root,
            settlement_receipt_root,
            reserve_proof_root,
            risk_band_root,
            reorg_buffer_root,
            watchtower_attestation_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            vaults: self.vaults.len(),
            makers: self.makers.len(),
            usable_makers: self
                .makers
                .values()
                .filter(|maker| maker.status.usable())
                .count(),
            inventory_commitments: self.inventory_commitments.len(),
            live_inventory_commitments: self
                .inventory_commitments
                .values()
                .filter(|commitment| commitment.status.is_live())
                .count(),
            shielded_deposits: self.shielded_deposits.len(),
            live_shielded_deposits: self
                .shielded_deposits
                .values()
                .filter(|deposit| deposit.status.is_live())
                .count(),
            shielded_exits: self.shielded_exits.len(),
            live_shielded_exits: self
                .shielded_exits
                .values()
                .filter(|exit| exit.status.is_live())
                .count(),
            stealth_payouts: self.stealth_payout_commitments.len(),
            live_stealth_payouts: self
                .stealth_payout_commitments
                .values()
                .filter(|payout| payout.status.is_live())
                .count(),
            sponsored_withdrawal_lanes: self.sponsored_withdrawal_lanes.len(),
            sponsored_withdrawals: self.sponsored_withdrawals.len(),
            live_sponsored_withdrawals: self
                .sponsored_withdrawals
                .values()
                .filter(|withdrawal| withdrawal.status.is_live())
                .count(),
            netting_batches: self.netting_batches.len(),
            settlement_receipts: self.settlement_receipts.len(),
            pending_settlement_receipts: self
                .settlement_receipts
                .values()
                .filter(|receipt| receipt.status.counts_as_pending())
                .count(),
            reserve_proofs: self.reserve_proofs.len(),
            usable_reserve_proofs: self
                .reserve_proofs
                .values()
                .filter(|proof| proof.status.usable())
                .count(),
            risk_bands: self.risk_bands.len(),
            reorg_buffers: self.reorg_buffers.len(),
            watchtower_attestations: self.watchtower_attestations.len(),
            unique_nullifiers: self.spent_nullifiers.len(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "height": self.height,
            "protocol_version": MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "vaults": map_records(&self.vaults),
            "makers": map_records(&self.makers),
            "inventory_commitments": map_records(&self.inventory_commitments),
            "shielded_deposits": map_records(&self.shielded_deposits),
            "shielded_exits": map_records(&self.shielded_exits),
            "stealth_payout_commitments": map_records(&self.stealth_payout_commitments),
            "sponsored_withdrawal_lanes": map_records(&self.sponsored_withdrawal_lanes),
            "sponsored_withdrawals": map_records(&self.sponsored_withdrawals),
            "netting_batches": map_records(&self.netting_batches),
            "settlement_receipts": map_records(&self.settlement_receipts),
            "reserve_proofs": map_records(&self.reserve_proofs),
            "risk_bands": map_records(&self.risk_bands),
            "reorg_buffers": map_records(&self.reorg_buffers),
            "watchtower_attestations": map_records(&self.watchtower_attestations),
            "spent_nullifiers": self.spent_nullifiers
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "MPBLNV-ROOT-FROM-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> MoneroPrivateBridgeLiquidityNettingVaultResult<State> {
    State::devnet()
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for Vault {
    fn public_record(&self) -> Value {
        Vault::public_record(self)
    }
}

impl PublicRecord for Maker {
    fn public_record(&self) -> Value {
        Maker::public_record(self)
    }
}

impl PublicRecord for InventoryCommitment {
    fn public_record(&self) -> Value {
        InventoryCommitment::public_record(self)
    }
}

impl PublicRecord for ShieldedDeposit {
    fn public_record(&self) -> Value {
        ShieldedDeposit::public_record(self)
    }
}

impl PublicRecord for ShieldedExit {
    fn public_record(&self) -> Value {
        ShieldedExit::public_record(self)
    }
}

impl PublicRecord for StealthPayoutCommitment {
    fn public_record(&self) -> Value {
        StealthPayoutCommitment::public_record(self)
    }
}

impl PublicRecord for SponsoredWithdrawalLane {
    fn public_record(&self) -> Value {
        SponsoredWithdrawalLane::public_record(self)
    }
}

impl PublicRecord for SponsoredWithdrawal {
    fn public_record(&self) -> Value {
        SponsoredWithdrawal::public_record(self)
    }
}

impl PublicRecord for NettingBatch {
    fn public_record(&self) -> Value {
        NettingBatch::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for ReserveProof {
    fn public_record(&self) -> Value {
        ReserveProof::public_record(self)
    }
}

impl PublicRecord for RiskBand {
    fn public_record(&self) -> Value {
        RiskBand::public_record(self)
    }
}

impl PublicRecord for ReorgBuffer {
    fn public_record(&self) -> Value {
        ReorgBuffer::public_record(self)
    }
}

impl PublicRecord for WatchtowerAttestation {
    fn public_record(&self) -> Value {
        WatchtowerAttestation::public_record(self)
    }
}

trait Identified {
    fn id(&self) -> &str;
}

impl Identified for Vault {
    fn id(&self) -> &str {
        &self.vault_id
    }
}

impl Identified for Maker {
    fn id(&self) -> &str {
        &self.maker_id
    }
}

impl Identified for InventoryCommitment {
    fn id(&self) -> &str {
        &self.commitment_id
    }
}

impl Identified for ShieldedDeposit {
    fn id(&self) -> &str {
        &self.deposit_id
    }
}

impl Identified for ShieldedExit {
    fn id(&self) -> &str {
        &self.exit_id
    }
}

impl Identified for StealthPayoutCommitment {
    fn id(&self) -> &str {
        &self.payout_commitment_id
    }
}

impl Identified for SponsoredWithdrawalLane {
    fn id(&self) -> &str {
        &self.lane_id
    }
}

impl Identified for SponsoredWithdrawal {
    fn id(&self) -> &str {
        &self.withdrawal_id
    }
}

impl Identified for NettingBatch {
    fn id(&self) -> &str {
        &self.batch_id
    }
}

impl Identified for SettlementReceipt {
    fn id(&self) -> &str {
        &self.receipt_id
    }
}

impl Identified for ReserveProof {
    fn id(&self) -> &str {
        &self.proof_id
    }
}

impl Identified for RiskBand {
    fn id(&self) -> &str {
        &self.band_id
    }
}

impl Identified for ReorgBuffer {
    fn id(&self) -> &str {
        &self.buffer_id
    }
}

impl Identified for WatchtowerAttestation {
    fn id(&self) -> &str {
        &self.attestation_id
    }
}

fn deterministic_id(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn item_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn string_root(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .values()
        .map(|value| value.public_record())
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T: PublicRecord>(values: &BTreeMap<String, T>) -> Value {
    Value::Array(
        values
            .values()
            .map(|value| value.public_record())
            .collect::<Vec<_>>(),
    )
}

fn map_from_items<T: Identified>(items: Vec<T>) -> BTreeMap<String, T> {
    let mut values = BTreeMap::new();
    for item in items {
        values.insert(item.id().to_string(), item);
    }
    values
}

fn item_root_from_map<T: PublicRecord>(
    domain: &str,
    values: &BTreeMap<String, T>,
    ids: &[&str],
) -> String {
    let leaves = ids
        .iter()
        .filter_map(|id| values.get(*id))
        .map(|value| value.public_record())
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn validate_unique_keys<'a, I>(
    label: &str,
    keys: I,
) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut seen = BTreeSet::new();
    for key in keys {
        if key.is_empty() {
            return Err(format!("{label} id must not be empty"));
        }
        if !seen.insert(key.clone()) {
            return Err(format!("duplicate {label} id {key}"));
        }
    }
    Ok(())
}

fn require_id(label: &str, id: &str) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()> {
    if id.is_empty() {
        return Err(format!("{label} id must not be empty"));
    }
    Ok(())
}

fn require_link<T>(
    values: &BTreeMap<String, T>,
    label: &str,
    id: &str,
) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()> {
    if id.is_empty() {
        return Err(format!("{label} id must not be empty"));
    }
    if !values.contains_key(id) {
        return Err(format!("{label} missing linked id {id}"));
    }
    Ok(())
}

fn validate_bps(label: &str, value: u64) -> MoneroPrivateBridgeLiquidityNettingVaultResult<()> {
    if value > MONERO_PRIVATE_BRIDGE_LIQUIDITY_NETTING_VAULT_MAX_BPS {
        return Err(format!("{label} exceeds bps denominator"));
    }
    Ok(())
}

fn sum_deposits(
    deposits: &BTreeMap<String, ShieldedDeposit>,
    ids: &BTreeSet<String>,
) -> MoneroPrivateBridgeLiquidityNettingVaultResult<u64> {
    let mut total = 0_u64;
    for id in ids {
        let deposit = deposits
            .get(id)
            .ok_or_else(|| format!("missing batch deposit {id}"))?;
        total = total
            .checked_add(deposit.amount_piconero)
            .ok_or_else(|| "deposit total overflow".to_string())?;
    }
    Ok(total)
}

fn sum_exits(
    exits: &BTreeMap<String, ShieldedExit>,
    ids: &BTreeSet<String>,
) -> MoneroPrivateBridgeLiquidityNettingVaultResult<u64> {
    let mut total = 0_u64;
    for id in ids {
        let exit = exits
            .get(id)
            .ok_or_else(|| format!("missing batch exit {id}"))?;
        total = total
            .checked_add(exit.amount_piconero)
            .ok_or_else(|| "exit total overflow".to_string())?;
    }
    Ok(total)
}

fn stealth_payout(
    payout_commitment_id: &str,
    exit_id: &str,
    vault_id: &str,
    status: CommitmentStatus,
    amount_piconero: u64,
    height: u64,
    label: &str,
) -> StealthPayoutCommitment {
    StealthPayoutCommitment {
        payout_commitment_id: payout_commitment_id.to_string(),
        exit_id: exit_id.to_string(),
        vault_id: vault_id.to_string(),
        status,
        stealth_address_commitment: deterministic_id("MPBLNV-STEALTH-ADDRESS", label),
        one_time_public_key_commitment: deterministic_id("MPBLNV-ONE-TIME-KEY", label),
        encrypted_amount_commitment: deterministic_id("MPBLNV-ENCRYPTED-AMOUNT", label),
        view_tag_commitment: deterministic_id("MPBLNV-VIEW-TAG", label),
        amount_piconero,
        created_at_height: height.saturating_sub(18),
    }
}
