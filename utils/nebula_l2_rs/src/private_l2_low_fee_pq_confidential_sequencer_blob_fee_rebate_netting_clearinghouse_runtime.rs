use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialSequencerBlobFeeRebateNettingClearinghouseRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SEQUENCER_BLOB_FEE_REBATE_NETTING_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-sequencer-blob-fee-rebate-netting-clearinghouse-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SEQUENCER_BLOB_FEE_REBATE_NETTING_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ENVELOPE_SUITE: &str =
    "ml-kem-1024+ml-dsa-87-netting-clearinghouse-fee-rebate-envelope-v1";
pub const NETTING_CLEARINGHOUSE_SUITE: &str =
    "private-l2-low-fee-confidential-sequencer-rebate-netting-clearinghouse-clearing-settlement-v1";
pub const BALANCE_COMMITMENT_SUITE: &str =
    "pedersen+bulletproofs-plus-clearinghouse-balance-root-v1";
pub const SETTLEMENT_PROOF_SUITE: &str =
    "slh-dsa-shake-256f-netting-clearinghouse-settlement-proof-root-v1";
pub const FAST_PATH_PROOF_SUITE: &str = "ml-dsa-87-fast-netting-clearinghouse-attestation-root-v1";
pub const NULLIFIER_SUITE: &str = "confidential-netting-clearinghouse-nullifier-set-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-sequencer-blob-fee-rebate-netting-clearinghouse-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_accounts_amounts_addresses_view_keys_blob_payloads_or_secret_keys";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-netting-clearinghouse-devnet";
pub const DEVNET_CLEARINGHOUSE_ID: &str =
    "private-l2-sequencer-blob-fee-rebate-netting-clearinghouse-devnet";
pub const DEVNET_OPERATOR_SET_ID: &str = "private-l2-netting-clearinghouse-operator-set-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "dxmr-rebate-devnet";
pub const DEVNET_HEIGHT: u64 = 4_260_000;
pub const DEVNET_EPOCH: u64 = 2_084;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_FEE_BPS: u64 = 12;
pub const DEFAULT_PROTOCOL_TAKE_BPS: u64 = 1;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 8_850;
pub const DEFAULT_NETTING_EFFICIENCY_BPS: u64 = 9_450;
pub const DEFAULT_LIQUIDITY_RESERVE_BPS: u64 = 700;
pub const DEFAULT_DUST_SWEEP_BPS: u64 = 4;
pub const DEFAULT_FAST_PATH_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 20_160;
pub const DEFAULT_CLEARINGHOUSE_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2_097_152;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ATTESTATION_QUORUM: u16 = 9;
pub const DEFAULT_MAX_DEBIT_NOTES: usize = 8_388_608;
pub const DEFAULT_MAX_CREDIT_NOTES: usize = 8_388_608;
pub const DEFAULT_MAX_NETTING_WINDOWS: usize = 2_097_152;
pub const DEFAULT_MAX_SETTLEMENT_BATCHES: usize = 2_097_152;
pub const DEFAULT_MAX_LIQUIDITY_BUCKETS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_NULLIFIERS: usize = 16_777_216;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 2_097_152;

const D_STATE: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:STATE";
const D_CONFIG: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:CONFIG";
const D_COUNTERS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:COUNTERS";
const D_ROOTS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:ROOTS";
const D_DEBITS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:DEBITS";
const D_CREDITS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:CREDITS";
const D_WINDOWS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:WINDOWS";
const D_SETTLEMENTS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:SETTLEMENTS";
const D_BUCKETS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:BUCKETS";
const D_ATTESTATIONS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:ATTESTATIONS";
const D_NULLIFIERS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:NULLIFIERS";
const D_PUBLIC_RECORDS: &str =
    "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-NETTING-CLEARINGHOUSE:PUBLIC-RECORDS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearinghouseLane {
    SequencerBlobFee,
    UserRebate,
    ProverRefund,
    SponsorOffset,
    LiquidityReserve,
    BatchSurplus,
    ProtocolTake,
    DisputeHoldback,
}
impl ClearinghouseLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerBlobFee => "sequencer_blob_fee",
            Self::UserRebate => "user_rebate",
            Self::ProverRefund => "prover_refund",
            Self::SponsorOffset => "sponsor_offset",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::BatchSurplus => "batch_surplus",
            Self::ProtocolTake => "protocol_take",
            Self::DisputeHoldback => "dispute_holdback",
        }
    }
    pub fn is_rebate_lane(self) -> bool {
        matches!(
            self,
            Self::UserRebate | Self::ProverRefund | Self::SponsorOffset | Self::BatchSurplus
        )
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::UserRebate => 10_000,
            Self::SponsorOffset => 9_400,
            Self::SequencerBlobFee => 8_800,
            Self::ProverRefund => 8_100,
            Self::BatchSurplus => 7_200,
            Self::LiquidityReserve => 6_000,
            Self::DisputeHoldback => 4_800,
            Self::ProtocolTake => 3_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingSide {
    Debit,
    Credit,
}
impl NettingSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debit => "debit",
            Self::Credit => "credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Sealed,
    Eligible,
    Matched,
    Netted,
    Settled,
    Expired,
    Cancelled,
    Disputed,
}
impl NoteStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Sealed | Self::Eligible | Self::Matched)
    }
    pub fn nettable(self) -> bool {
        matches!(self, Self::Sealed | Self::Eligible)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Collecting,
    Locked,
    PqAttested,
    Netted,
    SettlementQueued,
    Settled,
    Expired,
    Disputed,
}
impl WindowStatus {
    pub fn accepts_notes(self) -> bool {
        matches!(self, Self::Open | Self::Collecting)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    FastPath,
    Batched,
    Proved,
    Published,
    Finalized,
    Reconciled,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    OperatorSet,
    BalanceConservation,
    DebitEligibility,
    CreditEligibility,
    WindowLock,
    NettingComputation,
    SettlementPublication,
    LiquidityReserve,
}
impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorSet => "operator_set",
            Self::BalanceConservation => "balance_conservation",
            Self::DebitEligibility => "debit_eligibility",
            Self::CreditEligibility => "credit_eligibility",
            Self::WindowLock => "window_lock",
            Self::NettingComputation => "netting_computation",
            Self::SettlementPublication => "settlement_publication",
            Self::LiquidityReserve => "liquidity_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityBucketStatus {
    Open,
    Reserved,
    Netted,
    Settling,
    Released,
    Disputed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub clearinghouse_id: String,
    pub operator_set_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_envelope_suite: String,
    pub netting_clearinghouse_suite: String,
    pub balance_commitment_suite: String,
    pub settlement_proof_suite: String,
    pub fast_path_proof_suite: String,
    pub nullifier_suite: String,
    pub public_record_suite: String,
    pub target_fee_bps: u64,
    pub max_fee_bps: u64,
    pub protocol_take_bps: u64,
    pub rebate_share_bps: u64,
    pub netting_efficiency_bps: u64,
    pub liquidity_reserve_bps: u64,
    pub dust_sweep_bps: u64,
    pub fast_path_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub clearinghouse_epoch_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_attestation_quorum: u16,
    pub max_debit_notes: usize,
    pub max_credit_notes: usize,
    pub max_netting_windows: usize,
    pub max_settlement_batches: usize,
    pub max_liquidity_buckets: usize,
    pub max_attestations: usize,
    pub max_nullifiers: usize,
    pub max_public_records: usize,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            clearinghouse_id: DEVNET_CLEARINGHOUSE_ID.to_string(),
            operator_set_id: DEVNET_OPERATOR_SET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_envelope_suite: PQ_ENVELOPE_SUITE.to_string(),
            netting_clearinghouse_suite: NETTING_CLEARINGHOUSE_SUITE.to_string(),
            balance_commitment_suite: BALANCE_COMMITMENT_SUITE.to_string(),
            settlement_proof_suite: SETTLEMENT_PROOF_SUITE.to_string(),
            fast_path_proof_suite: FAST_PATH_PROOF_SUITE.to_string(),
            nullifier_suite: NULLIFIER_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            protocol_take_bps: DEFAULT_PROTOCOL_TAKE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            netting_efficiency_bps: DEFAULT_NETTING_EFFICIENCY_BPS,
            liquidity_reserve_bps: DEFAULT_LIQUIDITY_RESERVE_BPS,
            dust_sweep_bps: DEFAULT_DUST_SWEEP_BPS,
            fast_path_window_blocks: DEFAULT_FAST_PATH_WINDOW_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            clearinghouse_epoch_blocks: DEFAULT_CLEARINGHOUSE_EPOCH_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_attestation_quorum: DEFAULT_MIN_ATTESTATION_QUORUM,
            max_debit_notes: DEFAULT_MAX_DEBIT_NOTES,
            max_credit_notes: DEFAULT_MAX_CREDIT_NOTES,
            max_netting_windows: DEFAULT_MAX_NETTING_WINDOWS,
            max_settlement_batches: DEFAULT_MAX_SETTLEMENT_BATCHES,
            max_liquidity_buckets: DEFAULT_MAX_LIQUIDITY_BUCKETS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("invalid protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("invalid schema version".to_string());
        }
        if self.target_fee_bps > self.max_fee_bps || self.max_fee_bps > 100 {
            return Err("fee policy is not low-fee".to_string());
        }
        for (name, value) in [
            ("protocol_take_bps", self.protocol_take_bps),
            ("rebate_share_bps", self.rebate_share_bps),
            ("netting_efficiency_bps", self.netting_efficiency_bps),
            ("liquidity_reserve_bps", self.liquidity_reserve_bps),
            ("dust_sweep_bps", self.dust_sweep_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{name} exceeds bps denominator"));
            }
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security floor below 192 bits".to_string());
        }
        if self.min_privacy_set_size < 65_536 {
            return Err("privacy set floor too small".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("privacy set target below floor".to_string());
        }
        if self.min_attestation_quorum == 0 {
            return Err("attestation quorum cannot be zero".to_string());
        }
        if self.fast_path_window_blocks == 0 || self.settlement_window_blocks == 0 {
            return Err("window sizes cannot be zero".to_string());
        }
        if self.fast_path_window_blocks > self.settlement_window_blocks {
            return Err("fast path window exceeds settlement window".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "clearinghouse_id": self.clearinghouse_id,
            "operator_set_id": self.operator_set_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "pq_envelope_suite": self.pq_envelope_suite,
            "netting_clearinghouse_suite": self.netting_clearinghouse_suite,
            "balance_commitment_suite": self.balance_commitment_suite,
            "settlement_proof_suite": self.settlement_proof_suite,
            "fast_path_proof_suite": self.fast_path_proof_suite,
            "nullifier_suite": self.nullifier_suite,
            "public_record_suite": self.public_record_suite,
            "target_fee_bps": self.target_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "protocol_take_bps": self.protocol_take_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "netting_efficiency_bps": self.netting_efficiency_bps,
            "liquidity_reserve_bps": self.liquidity_reserve_bps,
            "dust_sweep_bps": self.dust_sweep_bps,
            "fast_path_window_blocks": self.fast_path_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "clearinghouse_epoch_blocks": self.clearinghouse_epoch_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_attestation_quorum": self.min_attestation_quorum,
            "devnet_height": self.devnet_height,
            "devnet_epoch": self.devnet_epoch
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub debit_notes_posted: u64,
    pub credit_notes_posted: u64,
    pub notes_matched: u64,
    pub notes_netted: u64,
    pub netting_windows_opened: u64,
    pub netting_windows_locked: u64,
    pub netting_windows_settled: u64,
    pub settlement_batches_queued: u64,
    pub settlement_batches_finalized: u64,
    pub liquidity_buckets_opened: u64,
    pub liquidity_buckets_released: u64,
    pub attestations_posted: u64,
    pub nullifiers_seen: u64,
    pub public_records_emitted: u64,
    pub total_committed_cost_units: u128,
    pub total_committed_rebate_units: u128,
    pub total_estimated_net_units: u128,
    pub total_estimated_saved_units: u128,
    pub total_protocol_take_units: u128,
    pub total_reserve_units: u128,
    pub low_fee_violations_rejected: u64,
    pub privacy_rejections: u64,
    pub pq_rejections: u64,
}
impl Counters {
    pub fn live_notes(&self) -> u64 {
        self.debit_notes_posted
            .saturating_add(self.credit_notes_posted)
            .saturating_sub(self.notes_netted)
    }
    pub fn public_record(&self) -> Value {
        json!({
            "debit_notes_posted": self.debit_notes_posted,
            "credit_notes_posted": self.credit_notes_posted,
            "notes_matched": self.notes_matched,
            "notes_netted": self.notes_netted,
            "netting_windows_opened": self.netting_windows_opened,
            "netting_windows_locked": self.netting_windows_locked,
            "netting_windows_settled": self.netting_windows_settled,
            "settlement_batches_queued": self.settlement_batches_queued,
            "settlement_batches_finalized": self.settlement_batches_finalized,
            "liquidity_buckets_opened": self.liquidity_buckets_opened,
            "liquidity_buckets_released": self.liquidity_buckets_released,
            "attestations_posted": self.attestations_posted,
            "nullifiers_seen": self.nullifiers_seen,
            "public_records_emitted": self.public_records_emitted,
            "total_committed_cost_units": self.total_committed_cost_units.to_string(),
            "total_committed_rebate_units": self.total_committed_rebate_units.to_string(),
            "total_estimated_net_units": self.total_estimated_net_units.to_string(),
            "total_estimated_saved_units": self.total_estimated_saved_units.to_string(),
            "total_protocol_take_units": self.total_protocol_take_units.to_string(),
            "total_reserve_units": self.total_reserve_units.to_string(),
            "live_notes": self.live_notes(),
            "low_fee_violations_rejected": self.low_fee_violations_rejected,
            "privacy_rejections": self.privacy_rejections,
            "pq_rejections": self.pq_rejections
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub debit_notes_root: String,
    pub credit_notes_root: String,
    pub netting_windows_root: String,
    pub settlement_batches_root: String,
    pub liquidity_buckets_root: String,
    pub attestations_root: String,
    pub nullifiers_root: String,
    pub public_records_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "debit_notes_root": self.debit_notes_root,
            "credit_notes_root": self.credit_notes_root,
            "netting_windows_root": self.netting_windows_root,
            "settlement_batches_root": self.settlement_batches_root,
            "liquidity_buckets_root": self.liquidity_buckets_root,
            "attestations_root": self.attestations_root,
            "nullifiers_root": self.nullifiers_root,
            "public_records_root": self.public_records_root,
            "state_root": self.state_root
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DebitNoteInput {
    pub note_id: String,
    pub lane: ClearinghouseLane,
    pub sequencer_commitment: String,
    pub account_commitment_root: String,
    pub sealed_amount_root: String,
    pub blob_fee_bundle_root: String,
    pub pq_envelope_root: String,
    pub nullifier_commitment: String,
    pub max_fee_bps: u64,
    pub estimated_cost_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditNoteInput {
    pub note_id: String,
    pub lane: ClearinghouseLane,
    pub beneficiary_commitment_root: String,
    pub rebate_commitment_root: String,
    pub eligibility_proof_root: String,
    pub pq_envelope_root: String,
    pub nullifier_hash: String,
    pub min_rebate_bps: u64,
    pub estimated_rebate_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowInput {
    pub window_id: String,
    pub lane: ClearinghouseLane,
    pub debit_note_ids: Vec<String>,
    pub credit_note_ids: Vec<String>,
    pub liquidity_bucket_ids: Vec<String>,
    pub window_commitment_root: String,
    pub conservation_proof_root: String,
    pub fast_path: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementInput {
    pub settlement_id: String,
    pub window_id: String,
    pub settlement_commitment_root: String,
    pub netted_debit_root: String,
    pub netted_credit_root: String,
    pub residual_root: String,
    pub proof_root: String,
    pub publication_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityBucketInput {
    pub bucket_id: String,
    pub lane: ClearinghouseLane,
    pub provider_commitment_root: String,
    pub reserve_commitment_root: String,
    pub capacity_commitment_root: String,
    pub nullifier_commitment: String,
    pub reserve_floor_units: u128,
    pub max_exposure_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationInput {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub subject_root: String,
    pub operator_set_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub aggregate_weight: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdvanceInput {
    pub next_height: u64,
    pub next_epoch: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialDebitNote {
    pub note_id: String,
    pub lane: ClearinghouseLane,
    pub status: NoteStatus,
    pub sequencer_commitment: String,
    pub account_commitment_root: String,
    pub sealed_amount_root: String,
    pub blob_fee_bundle_root: String,
    pub pq_envelope_root: String,
    pub nullifier_commitment: String,
    pub max_fee_bps: u64,
    pub estimated_cost_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub matched_credit_id: Option<String>,
    pub window_id: Option<String>,
    pub settlement_id: Option<String>,
    pub epoch: u64,
    pub created_height: u64,
    pub expires_height: u64,
}
impl ConfidentialDebitNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "side": NettingSide::Debit.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status,
            "sequencer_commitment": self.sequencer_commitment,
            "account_commitment_root": self.account_commitment_root,
            "sealed_amount_root": self.sealed_amount_root,
            "blob_fee_bundle_root": self.blob_fee_bundle_root,
            "pq_envelope_root": self.pq_envelope_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "matched_credit_id": self.matched_credit_id,
            "window_id": self.window_id,
            "settlement_id": self.settlement_id,
            "epoch": self.epoch,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_DEBITS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialCreditNote {
    pub note_id: String,
    pub lane: ClearinghouseLane,
    pub status: NoteStatus,
    pub beneficiary_commitment_root: String,
    pub rebate_commitment_root: String,
    pub eligibility_proof_root: String,
    pub pq_envelope_root: String,
    pub nullifier_hash: String,
    pub min_rebate_bps: u64,
    pub estimated_rebate_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub matched_debit_id: Option<String>,
    pub window_id: Option<String>,
    pub settlement_id: Option<String>,
    pub epoch: u64,
    pub created_height: u64,
    pub expires_height: u64,
}
impl ConfidentialCreditNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "side": NettingSide::Credit.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status,
            "beneficiary_commitment_root": self.beneficiary_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "eligibility_proof_root": self.eligibility_proof_root,
            "pq_envelope_root": self.pq_envelope_root,
            "min_rebate_bps": self.min_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "matched_debit_id": self.matched_debit_id,
            "window_id": self.window_id,
            "settlement_id": self.settlement_id,
            "epoch": self.epoch,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_CREDITS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityBucket {
    pub bucket_id: String,
    pub lane: ClearinghouseLane,
    pub status: LiquidityBucketStatus,
    pub provider_commitment_root: String,
    pub reserve_commitment_root: String,
    pub capacity_commitment_root: String,
    pub nullifier_commitment: String,
    pub reserve_floor_units: u128,
    pub max_exposure_units: u128,
    pub reserved_window_id: Option<String>,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub epoch: u64,
    pub created_height: u64,
}
impl LiquidityBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "provider_commitment_root": self.provider_commitment_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "capacity_commitment_root": self.capacity_commitment_root,
            "reserve_floor_units": self.reserve_floor_units.to_string(),
            "max_exposure_units": self.max_exposure_units.to_string(),
            "reserved_window_id": self.reserved_window_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "epoch": self.epoch,
            "created_height": self.created_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_BUCKETS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingWindow {
    pub window_id: String,
    pub lane: ClearinghouseLane,
    pub status: WindowStatus,
    pub debit_note_ids: Vec<String>,
    pub credit_note_ids: Vec<String>,
    pub liquidity_bucket_ids: Vec<String>,
    pub window_commitment_root: String,
    pub conservation_proof_root: String,
    pub debit_set_root: String,
    pub credit_set_root: String,
    pub liquidity_set_root: String,
    pub netted_flow_root: String,
    pub residual_root: String,
    pub attestation_ids: Vec<String>,
    pub estimated_debit_units: u128,
    pub estimated_credit_units: u128,
    pub estimated_net_units: u128,
    pub estimated_saved_units: u128,
    pub reserve_units: u128,
    pub protocol_take_units: u128,
    pub fast_path: bool,
    pub epoch: u64,
    pub opened_height: u64,
    pub locks_at_height: u64,
    pub settles_by_height: u64,
}
impl NettingWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "debit_set_root": self.debit_set_root,
            "credit_set_root": self.credit_set_root,
            "liquidity_set_root": self.liquidity_set_root,
            "window_commitment_root": self.window_commitment_root,
            "conservation_proof_root": self.conservation_proof_root,
            "netted_flow_root": self.netted_flow_root,
            "residual_root": self.residual_root,
            "attestation_root": vector_root(D_ATTESTATIONS, &self.attestation_ids),
            "debit_count": self.debit_note_ids.len(),
            "credit_count": self.credit_note_ids.len(),
            "liquidity_bucket_count": self.liquidity_bucket_ids.len(),
            "estimated_net_units": self.estimated_net_units.to_string(),
            "estimated_saved_units": self.estimated_saved_units.to_string(),
            "reserve_units": self.reserve_units.to_string(),
            "protocol_take_units": self.protocol_take_units.to_string(),
            "fast_path": self.fast_path,
            "epoch": self.epoch,
            "opened_height": self.opened_height,
            "locks_at_height": self.locks_at_height,
            "settles_by_height": self.settles_by_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_WINDOWS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub settlement_id: String,
    pub window_id: String,
    pub lane: ClearinghouseLane,
    pub status: SettlementStatus,
    pub settlement_commitment_root: String,
    pub netted_debit_root: String,
    pub netted_credit_root: String,
    pub residual_root: String,
    pub proof_root: String,
    pub publication_root: String,
    pub finalized_root: Option<String>,
    pub estimated_net_units: u128,
    pub estimated_saved_units: u128,
    pub reserve_units: u128,
    pub protocol_take_units: u128,
    pub queued_height: u64,
    pub published_height: Option<u64>,
    pub finalized_height: Option<u64>,
}
impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "settlement_commitment_root": self.settlement_commitment_root,
            "netted_debit_root": self.netted_debit_root,
            "netted_credit_root": self.netted_credit_root,
            "residual_root": self.residual_root,
            "proof_root": self.proof_root,
            "publication_root": self.publication_root,
            "finalized_root": self.finalized_root,
            "estimated_net_units": self.estimated_net_units.to_string(),
            "estimated_saved_units": self.estimated_saved_units.to_string(),
            "reserve_units": self.reserve_units.to_string(),
            "protocol_take_units": self.protocol_take_units.to_string(),
            "queued_height": self.queued_height,
            "published_height": self.published_height,
            "finalized_height": self.finalized_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_SETTLEMENTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClearinghouseAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub subject_root: String,
    pub operator_set_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub aggregate_weight: u64,
    pub pq_security_bits: u16,
    pub epoch: u64,
    pub created_height: u64,
    pub expires_height: u64,
}
impl PqClearinghouseAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "operator_set_root": self.operator_set_root,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "aggregate_weight": self.aggregate_weight,
            "pq_security_bits": self.pq_security_bits,
            "epoch": self.epoch,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_ATTESTATIONS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearinghousePublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub roots_only_payload_root: String,
    pub height: u64,
    pub epoch: u64,
}
impl ClearinghousePublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "roots_only_payload_root": self.roots_only_payload_root,
            "height": self.height,
            "epoch": self.epoch
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_PUBLIC_RECORDS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub debit_notes: BTreeMap<String, ConfidentialDebitNote>,
    pub credit_notes: BTreeMap<String, ConfidentialCreditNote>,
    pub netting_windows: BTreeMap<String, NettingWindow>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub liquidity_buckets: BTreeMap<String, LiquidityBucket>,
    pub attestations: BTreeMap<String, PqClearinghouseAttestation>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, ClearinghousePublicRecord>,
}
impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            epoch,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            debit_notes: BTreeMap::new(),
            credit_notes: BTreeMap::new(),
            netting_windows: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            liquidity_buckets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.recompute_roots();
        Ok(state)
    }
    pub fn devnet() -> Self {
        devnet()
    }
    pub fn post_debit_note(&mut self, input: DebitNoteInput) -> Result<String> {
        self.config.validate()?;
        self.ensure_capacity(
            self.debit_notes.len(),
            self.config.max_debit_notes,
            "debit notes",
        )?;
        self.ensure_unique_id(&input.note_id, "debit note")?;
        self.validate_low_fee(input.max_fee_bps)?;
        self.validate_privacy(input.privacy_set_size, input.pq_security_bits)?;
        self.validate_commitment(&input.sequencer_commitment, "sequencer commitment")?;
        self.validate_commitment(&input.account_commitment_root, "account commitment root")?;
        self.validate_commitment(&input.sealed_amount_root, "sealed amount root")?;
        self.validate_commitment(&input.blob_fee_bundle_root, "blob fee bundle root")?;
        self.validate_commitment(&input.pq_envelope_root, "pq envelope root")?;
        self.insert_nullifier(format!("debit:{}", input.nullifier_commitment))?;
        let id = input.note_id.clone();
        let note = ConfidentialDebitNote {
            note_id: id.clone(),
            lane: input.lane,
            status: NoteStatus::Sealed,
            sequencer_commitment: input.sequencer_commitment,
            account_commitment_root: input.account_commitment_root,
            sealed_amount_root: input.sealed_amount_root,
            blob_fee_bundle_root: input.blob_fee_bundle_root,
            pq_envelope_root: input.pq_envelope_root,
            nullifier_commitment: input.nullifier_commitment,
            max_fee_bps: input.max_fee_bps,
            estimated_cost_units: input.estimated_cost_units,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            matched_credit_id: None,
            window_id: None,
            settlement_id: None,
            epoch: self.epoch,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.rebate_ttl_blocks),
        };
        self.counters.debit_notes_posted = self.counters.debit_notes_posted.saturating_add(1);
        self.counters.total_committed_cost_units = self
            .counters
            .total_committed_cost_units
            .saturating_add(note.estimated_cost_units);
        self.debit_notes.insert(id.clone(), note);
        self.emit_public_record("debit_note", &id)?;
        self.recompute_roots();
        Ok(id)
    }
    pub fn post_credit_note(&mut self, input: CreditNoteInput) -> Result<String> {
        self.config.validate()?;
        self.ensure_capacity(
            self.credit_notes.len(),
            self.config.max_credit_notes,
            "credit notes",
        )?;
        self.ensure_unique_id(&input.note_id, "credit note")?;
        if input.min_rebate_bps > MAX_BPS {
            return Err("credit note rebate floor exceeds bps denominator".to_string());
        }
        self.validate_privacy(input.privacy_set_size, input.pq_security_bits)?;
        self.validate_commitment(
            &input.beneficiary_commitment_root,
            "beneficiary commitment root",
        )?;
        self.validate_commitment(&input.rebate_commitment_root, "rebate commitment root")?;
        self.validate_commitment(&input.eligibility_proof_root, "eligibility proof root")?;
        self.validate_commitment(&input.pq_envelope_root, "pq envelope root")?;
        self.insert_nullifier(format!("credit:{}", input.nullifier_hash))?;
        let id = input.note_id.clone();
        let note = ConfidentialCreditNote {
            note_id: id.clone(),
            lane: input.lane,
            status: NoteStatus::Sealed,
            beneficiary_commitment_root: input.beneficiary_commitment_root,
            rebate_commitment_root: input.rebate_commitment_root,
            eligibility_proof_root: input.eligibility_proof_root,
            pq_envelope_root: input.pq_envelope_root,
            nullifier_hash: input.nullifier_hash,
            min_rebate_bps: input.min_rebate_bps,
            estimated_rebate_units: input.estimated_rebate_units,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            matched_debit_id: None,
            window_id: None,
            settlement_id: None,
            epoch: self.epoch,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.rebate_ttl_blocks),
        };
        self.counters.credit_notes_posted = self.counters.credit_notes_posted.saturating_add(1);
        self.counters.total_committed_rebate_units = self
            .counters
            .total_committed_rebate_units
            .saturating_add(note.estimated_rebate_units);
        self.credit_notes.insert(id.clone(), note);
        self.emit_public_record("credit_note", &id)?;
        self.recompute_roots();
        Ok(id)
    }
    pub fn open_liquidity_bucket(&mut self, input: LiquidityBucketInput) -> Result<String> {
        self.config.validate()?;
        self.ensure_capacity(
            self.liquidity_buckets.len(),
            self.config.max_liquidity_buckets,
            "liquidity buckets",
        )?;
        if self.liquidity_buckets.contains_key(&input.bucket_id) {
            return Err("duplicate liquidity bucket".to_string());
        }
        if input.reserve_floor_units > input.max_exposure_units {
            return Err("reserve floor exceeds exposure".to_string());
        }
        self.validate_privacy(input.privacy_set_size, input.pq_security_bits)?;
        self.validate_commitment(&input.provider_commitment_root, "provider commitment root")?;
        self.validate_commitment(&input.reserve_commitment_root, "reserve commitment root")?;
        self.validate_commitment(&input.capacity_commitment_root, "capacity commitment root")?;
        self.insert_nullifier(format!("bucket:{}", input.nullifier_commitment))?;
        let id = input.bucket_id.clone();
        let bucket = LiquidityBucket {
            bucket_id: id.clone(),
            lane: input.lane,
            status: LiquidityBucketStatus::Open,
            provider_commitment_root: input.provider_commitment_root,
            reserve_commitment_root: input.reserve_commitment_root,
            capacity_commitment_root: input.capacity_commitment_root,
            nullifier_commitment: input.nullifier_commitment,
            reserve_floor_units: input.reserve_floor_units,
            max_exposure_units: input.max_exposure_units,
            reserved_window_id: None,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            epoch: self.epoch,
            created_height: self.height,
        };
        self.counters.liquidity_buckets_opened =
            self.counters.liquidity_buckets_opened.saturating_add(1);
        self.liquidity_buckets.insert(id.clone(), bucket);
        self.emit_public_record("liquidity_bucket", &id)?;
        self.recompute_roots();
        Ok(id)
    }
    pub fn match_notes(&mut self, debit_note_id: &str, credit_note_id: &str) -> Result<()> {
        let debit_lane = self
            .debit_notes
            .get(debit_note_id)
            .ok_or_else(|| "missing debit note".to_string())?
            .lane;
        let credit_lane = self
            .credit_notes
            .get(credit_note_id)
            .ok_or_else(|| "missing credit note".to_string())?
            .lane;
        if debit_lane != credit_lane && !credit_lane.is_rebate_lane() {
            return Err("note lanes are not nettable".to_string());
        }
        {
            let debit = self
                .debit_notes
                .get_mut(debit_note_id)
                .ok_or_else(|| "missing debit note".to_string())?;
            if !debit.status.nettable() {
                return Err("debit note is not nettable".to_string());
            }
            debit.status = NoteStatus::Matched;
            debit.matched_credit_id = Some(credit_note_id.to_string());
        }
        {
            let credit = self
                .credit_notes
                .get_mut(credit_note_id)
                .ok_or_else(|| "missing credit note".to_string())?;
            if !credit.status.nettable() {
                return Err("credit note is not nettable".to_string());
            }
            credit.status = NoteStatus::Matched;
            credit.matched_debit_id = Some(debit_note_id.to_string());
        }
        self.counters.notes_matched = self.counters.notes_matched.saturating_add(2);
        self.recompute_roots();
        Ok(())
    }
    pub fn open_netting_window(&mut self, input: WindowInput) -> Result<String> {
        self.config.validate()?;
        self.ensure_capacity(
            self.netting_windows.len(),
            self.config.max_netting_windows,
            "netting windows",
        )?;
        if self.netting_windows.contains_key(&input.window_id) {
            return Err("duplicate netting window".to_string());
        }
        if input.debit_note_ids.is_empty() && input.credit_note_ids.is_empty() {
            return Err("netting window needs at least one note".to_string());
        }
        self.validate_commitment(&input.window_commitment_root, "window commitment root")?;
        self.validate_commitment(&input.conservation_proof_root, "conservation proof root")?;
        let debit_set_root = vector_root(D_DEBITS, &input.debit_note_ids);
        let credit_set_root = vector_root(D_CREDITS, &input.credit_note_ids);
        let liquidity_set_root = vector_root(D_BUCKETS, &input.liquidity_bucket_ids);
        let mut debit_units = 0_u128;
        let mut credit_units = 0_u128;
        for id in &input.debit_note_ids {
            let note = self
                .debit_notes
                .get_mut(id)
                .ok_or_else(|| format!("missing debit note {id}"))?;
            if !note.status.live() || note.lane != input.lane {
                return Err("debit note cannot enter window".to_string());
            }
            note.status = NoteStatus::Eligible;
            note.window_id = Some(input.window_id.clone());
            debit_units = debit_units.saturating_add(note.estimated_cost_units);
        }
        for id in &input.credit_note_ids {
            let note = self
                .credit_notes
                .get_mut(id)
                .ok_or_else(|| format!("missing credit note {id}"))?;
            if !note.status.live() {
                return Err("credit note cannot enter window".to_string());
            }
            if note.lane != input.lane && !note.lane.is_rebate_lane() {
                return Err("credit note lane cannot enter window".to_string());
            }
            note.status = NoteStatus::Eligible;
            note.window_id = Some(input.window_id.clone());
            credit_units = credit_units.saturating_add(note.estimated_rebate_units);
        }
        let reserve_units = apply_bps(debit_units, self.config.liquidity_reserve_bps);
        for id in &input.liquidity_bucket_ids {
            let bucket = self
                .liquidity_buckets
                .get_mut(id)
                .ok_or_else(|| format!("missing liquidity bucket {id}"))?;
            if bucket.status != LiquidityBucketStatus::Open || bucket.lane != input.lane {
                return Err("liquidity bucket cannot enter window".to_string());
            }
            bucket.status = LiquidityBucketStatus::Reserved;
            bucket.reserved_window_id = Some(input.window_id.clone());
        }
        let gross = debit_units.max(credit_units);
        let matched = debit_units.min(credit_units);
        let saved = apply_bps(matched, self.config.netting_efficiency_bps);
        let net = gross.saturating_sub(saved);
        let protocol_take = apply_bps(net, self.config.protocol_take_bps);
        let netted_flow_root = record_root(
            D_WINDOWS,
            &json!({
                "debit_set_root": debit_set_root,
                "credit_set_root": credit_set_root,
                "liquidity_set_root": liquidity_set_root,
                "estimated_net_units": net.to_string(),
                "estimated_saved_units": saved.to_string()
            }),
        );
        let residual_root = record_root(
            D_WINDOWS,
            &json!({
                "reserve_units": reserve_units.to_string(),
                "protocol_take_units": protocol_take.to_string(),
                "dust_sweep_bps": self.config.dust_sweep_bps
            }),
        );
        let lock_delta = if input.fast_path {
            self.config.fast_path_window_blocks
        } else {
            self.config.settlement_window_blocks
        };
        let window = NettingWindow {
            window_id: input.window_id.clone(),
            lane: input.lane,
            status: WindowStatus::Collecting,
            debit_note_ids: input.debit_note_ids,
            credit_note_ids: input.credit_note_ids,
            liquidity_bucket_ids: input.liquidity_bucket_ids,
            window_commitment_root: input.window_commitment_root,
            conservation_proof_root: input.conservation_proof_root,
            debit_set_root,
            credit_set_root,
            liquidity_set_root,
            netted_flow_root,
            residual_root,
            attestation_ids: Vec::new(),
            estimated_debit_units: debit_units,
            estimated_credit_units: credit_units,
            estimated_net_units: net,
            estimated_saved_units: saved,
            reserve_units,
            protocol_take_units: protocol_take,
            fast_path: input.fast_path,
            epoch: self.epoch,
            opened_height: self.height,
            locks_at_height: self.height.saturating_add(lock_delta),
            settles_by_height: self
                .height
                .saturating_add(lock_delta)
                .saturating_add(self.config.settlement_window_blocks),
        };
        self.counters.netting_windows_opened =
            self.counters.netting_windows_opened.saturating_add(1);
        self.counters.total_estimated_net_units = self
            .counters
            .total_estimated_net_units
            .saturating_add(window.estimated_net_units);
        self.counters.total_estimated_saved_units = self
            .counters
            .total_estimated_saved_units
            .saturating_add(window.estimated_saved_units);
        self.counters.total_reserve_units = self
            .counters
            .total_reserve_units
            .saturating_add(window.reserve_units);
        self.counters.total_protocol_take_units = self
            .counters
            .total_protocol_take_units
            .saturating_add(window.protocol_take_units);
        let id = window.window_id.clone();
        self.netting_windows.insert(id.clone(), window);
        self.emit_public_record("netting_window", &id)?;
        self.recompute_roots();
        Ok(id)
    }
    pub fn post_attestation(&mut self, input: AttestationInput) -> Result<String> {
        self.config.validate()?;
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        if self.attestations.contains_key(&input.attestation_id) {
            return Err("duplicate attestation".to_string());
        }
        if input.aggregate_weight < self.config.min_attestation_quorum as u64 {
            return Err("attestation quorum below floor".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            self.counters.pq_rejections = self.counters.pq_rejections.saturating_add(1);
            return Err("attestation pq security below floor".to_string());
        }
        self.validate_commitment(&input.subject_root, "subject root")?;
        self.validate_commitment(&input.operator_set_root, "operator set root")?;
        self.validate_commitment(&input.pq_public_key_root, "pq public key root")?;
        self.validate_commitment(&input.signature_root, "signature root")?;
        self.validate_commitment(&input.transcript_root, "transcript root")?;
        let id = input.attestation_id.clone();
        let attestation = PqClearinghouseAttestation {
            attestation_id: id.clone(),
            kind: input.kind,
            subject_id: input.subject_id.clone(),
            subject_root: input.subject_root,
            operator_set_root: input.operator_set_root,
            pq_public_key_root: input.pq_public_key_root,
            signature_root: input.signature_root,
            transcript_root: input.transcript_root,
            aggregate_weight: input.aggregate_weight,
            pq_security_bits: input.pq_security_bits,
            epoch: self.epoch,
            created_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        if let Some(window) = self.netting_windows.get_mut(&input.subject_id) {
            window.attestation_ids.push(id.clone());
            if matches!(
                input.kind,
                AttestationKind::WindowLock
                    | AttestationKind::NettingComputation
                    | AttestationKind::BalanceConservation
            ) {
                window.status = WindowStatus::PqAttested;
            }
        }
        self.counters.attestations_posted = self.counters.attestations_posted.saturating_add(1);
        self.attestations.insert(id.clone(), attestation);
        self.emit_public_record("pq_clearinghouse_attestation", &id)?;
        self.recompute_roots();
        Ok(id)
    }
    pub fn lock_window(&mut self, window_id: &str) -> Result<()> {
        let window = self
            .netting_windows
            .get_mut(window_id)
            .ok_or_else(|| "missing netting window".to_string())?;
        if !matches!(
            window.status,
            WindowStatus::Collecting | WindowStatus::PqAttested
        ) {
            return Err("window cannot be locked".to_string());
        }
        if self.height < window.locks_at_height && !window.fast_path {
            return Err("window lock height not reached".to_string());
        }
        if window.attestation_ids.len() < self.config.min_attestation_quorum as usize {
            return Err("window has insufficient pq attestations".to_string());
        }
        window.status = WindowStatus::Locked;
        self.counters.netting_windows_locked =
            self.counters.netting_windows_locked.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }
    pub fn queue_settlement(&mut self, input: SettlementInput) -> Result<String> {
        self.config.validate()?;
        self.ensure_capacity(
            self.settlement_batches.len(),
            self.config.max_settlement_batches,
            "settlement batches",
        )?;
        if self.settlement_batches.contains_key(&input.settlement_id) {
            return Err("duplicate settlement".to_string());
        }
        self.validate_commitment(
            &input.settlement_commitment_root,
            "settlement commitment root",
        )?;
        self.validate_commitment(&input.netted_debit_root, "netted debit root")?;
        self.validate_commitment(&input.netted_credit_root, "netted credit root")?;
        self.validate_commitment(&input.residual_root, "residual root")?;
        self.validate_commitment(&input.proof_root, "proof root")?;
        self.validate_commitment(&input.publication_root, "publication root")?;
        let window = self
            .netting_windows
            .get_mut(&input.window_id)
            .ok_or_else(|| "missing netting window".to_string())?;
        if !matches!(
            window.status,
            WindowStatus::Locked | WindowStatus::PqAttested
        ) {
            return Err("window is not settlement-ready".to_string());
        }
        window.status = WindowStatus::SettlementQueued;
        let batch = SettlementBatch {
            settlement_id: input.settlement_id.clone(),
            window_id: input.window_id.clone(),
            lane: window.lane,
            status: if window.fast_path {
                SettlementStatus::FastPath
            } else {
                SettlementStatus::Queued
            },
            settlement_commitment_root: input.settlement_commitment_root,
            netted_debit_root: input.netted_debit_root,
            netted_credit_root: input.netted_credit_root,
            residual_root: input.residual_root,
            proof_root: input.proof_root,
            publication_root: input.publication_root,
            finalized_root: None,
            estimated_net_units: window.estimated_net_units,
            estimated_saved_units: window.estimated_saved_units,
            reserve_units: window.reserve_units,
            protocol_take_units: window.protocol_take_units,
            queued_height: self.height,
            published_height: None,
            finalized_height: None,
        };
        for id in &window.debit_note_ids {
            if let Some(note) = self.debit_notes.get_mut(id) {
                note.status = NoteStatus::Netted;
                note.settlement_id = Some(batch.settlement_id.clone());
            }
        }
        for id in &window.credit_note_ids {
            if let Some(note) = self.credit_notes.get_mut(id) {
                note.status = NoteStatus::Netted;
                note.settlement_id = Some(batch.settlement_id.clone());
            }
        }
        for id in &window.liquidity_bucket_ids {
            if let Some(bucket) = self.liquidity_buckets.get_mut(id) {
                bucket.status = LiquidityBucketStatus::Netted;
            }
        }
        self.counters.notes_netted = self
            .counters
            .notes_netted
            .saturating_add(window.debit_note_ids.len() as u64)
            .saturating_add(window.credit_note_ids.len() as u64);
        self.counters.settlement_batches_queued =
            self.counters.settlement_batches_queued.saturating_add(1);
        let id = batch.settlement_id.clone();
        self.settlement_batches.insert(id.clone(), batch);
        self.emit_public_record("settlement_batch", &id)?;
        self.recompute_roots();
        Ok(id)
    }
    pub fn publish_settlement(
        &mut self,
        settlement_id: &str,
        publication_root: String,
    ) -> Result<()> {
        self.validate_commitment(&publication_root, "publication root")?;
        let batch = self
            .settlement_batches
            .get_mut(settlement_id)
            .ok_or_else(|| "missing settlement".to_string())?;
        if !matches!(
            batch.status,
            SettlementStatus::Queued | SettlementStatus::FastPath | SettlementStatus::Batched
        ) {
            return Err("settlement cannot be published".to_string());
        }
        batch.status = SettlementStatus::Published;
        batch.publication_root = publication_root;
        batch.published_height = Some(self.height);
        self.recompute_roots();
        Ok(())
    }
    pub fn finalize_settlement(
        &mut self,
        settlement_id: &str,
        finalized_root: String,
    ) -> Result<()> {
        self.validate_commitment(&finalized_root, "finalized root")?;
        let batch = self
            .settlement_batches
            .get_mut(settlement_id)
            .ok_or_else(|| "missing settlement".to_string())?;
        if !matches!(
            batch.status,
            SettlementStatus::Published | SettlementStatus::Proved
        ) {
            return Err("settlement cannot be finalized".to_string());
        }
        batch.status = SettlementStatus::Finalized;
        batch.finalized_root = Some(finalized_root);
        batch.finalized_height = Some(self.height);
        if let Some(window) = self.netting_windows.get_mut(&batch.window_id) {
            window.status = WindowStatus::Settled;
            for id in &window.debit_note_ids {
                if let Some(note) = self.debit_notes.get_mut(id) {
                    note.status = NoteStatus::Settled;
                }
            }
            for id in &window.credit_note_ids {
                if let Some(note) = self.credit_notes.get_mut(id) {
                    note.status = NoteStatus::Settled;
                }
            }
            for id in &window.liquidity_bucket_ids {
                if let Some(bucket) = self.liquidity_buckets.get_mut(id) {
                    bucket.status = LiquidityBucketStatus::Released;
                }
            }
        }
        self.counters.settlement_batches_finalized =
            self.counters.settlement_batches_finalized.saturating_add(1);
        self.counters.netting_windows_settled =
            self.counters.netting_windows_settled.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }
    pub fn advance(&mut self, input: AdvanceInput) -> Result<()> {
        if input.next_height < self.height {
            return Err("cannot move height backwards".to_string());
        }
        self.height = input.next_height;
        if let Some(next_epoch) = input.next_epoch {
            if next_epoch < self.epoch {
                return Err("cannot move epoch backwards".to_string());
            }
            self.epoch = next_epoch;
        } else if self.config.clearinghouse_epoch_blocks > 0 {
            self.epoch = self.height / self.config.clearinghouse_epoch_blocks;
        }
        self.expire_stale_notes();
        self.expire_stale_windows();
        self.recompute_roots();
        Ok(())
    }
    pub fn counters(&self) -> Counters {
        self.counters.clone()
    }
    pub fn roots(&self) -> Roots {
        let mut clone = self.clone();
        clone.recompute_roots();
        clone.roots
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "l2_network": self.config.l2_network,
            "clearinghouse_id": self.config.clearinghouse_id,
            "height": self.height,
            "epoch": self.epoch,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "roots": roots.public_record()
        })
    }
    pub fn recompute_roots(&mut self) {
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.debit_notes_root = map_root(D_DEBITS, &self.debit_notes);
        self.roots.credit_notes_root = map_root(D_CREDITS, &self.credit_notes);
        self.roots.netting_windows_root = map_root(D_WINDOWS, &self.netting_windows);
        self.roots.settlement_batches_root = map_root(D_SETTLEMENTS, &self.settlement_batches);
        self.roots.liquidity_buckets_root = map_root(D_BUCKETS, &self.liquidity_buckets);
        self.roots.attestations_root = map_root(D_ATTESTATIONS, &self.attestations);
        self.roots.nullifiers_root = set_root(D_NULLIFIERS, &self.nullifiers);
        self.roots.public_records_root = map_root(D_PUBLIC_RECORDS, &self.public_records);
        self.roots.state_root = record_root(
            D_STATE,
            &json!({
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "schema_version": self.config.schema_version,
                "height": self.height,
                "epoch": self.epoch,
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "debit_notes_root": self.roots.debit_notes_root,
                "credit_notes_root": self.roots.credit_notes_root,
                "netting_windows_root": self.roots.netting_windows_root,
                "settlement_batches_root": self.roots.settlement_batches_root,
                "liquidity_buckets_root": self.roots.liquidity_buckets_root,
                "attestations_root": self.roots.attestations_root,
                "nullifiers_root": self.roots.nullifiers_root,
                "public_records_root": self.roots.public_records_root
            }),
        );
    }
    fn ensure_capacity(&self, len: usize, cap: usize, label: &str) -> Result<()> {
        if len >= cap {
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }
    fn ensure_unique_id(&self, id: &str, label: &str) -> Result<()> {
        if id.trim().is_empty() {
            return Err(format!("{label} id cannot be empty"));
        }
        if self.debit_notes.contains_key(id)
            || self.credit_notes.contains_key(id)
            || self.netting_windows.contains_key(id)
            || self.settlement_batches.contains_key(id)
            || self.liquidity_buckets.contains_key(id)
            || self.attestations.contains_key(id)
            || self.public_records.contains_key(id)
        {
            return Err(format!("duplicate {label} id"));
        }
        Ok(())
    }
    fn validate_low_fee(&mut self, fee_bps: u64) -> Result<()> {
        if fee_bps > self.config.max_fee_bps {
            self.counters.low_fee_violations_rejected =
                self.counters.low_fee_violations_rejected.saturating_add(1);
            return Err("note exceeds low-fee cap".to_string());
        }
        Ok(())
    }
    fn validate_privacy(&mut self, privacy_set_size: u64, pq_security_bits: u16) -> Result<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            self.counters.privacy_rejections = self.counters.privacy_rejections.saturating_add(1);
            return Err("privacy set below floor".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            self.counters.pq_rejections = self.counters.pq_rejections.saturating_add(1);
            return Err("pq security below floor".to_string());
        }
        Ok(())
    }
    fn validate_commitment(&self, commitment: &str, label: &str) -> Result<()> {
        if commitment.trim().is_empty() {
            Err(format!("{label} cannot be empty"))
        } else {
            Ok(())
        }
    }
    fn insert_nullifier(&mut self, nullifier: String) -> Result<()> {
        self.ensure_capacity(
            self.nullifiers.len(),
            self.config.max_nullifiers,
            "nullifiers",
        )?;
        if !self.nullifiers.insert(nullifier) {
            return Err("duplicate nullifier".to_string());
        }
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        Ok(())
    }
    fn emit_public_record(&mut self, record_kind: &str, subject_id: &str) -> Result<()> {
        self.ensure_capacity(
            self.public_records.len(),
            self.config.max_public_records,
            "public records",
        )?;
        let subject_root = self.subject_root(record_kind, subject_id)?;
        let payload_root = record_root(
            D_PUBLIC_RECORDS,
            &json!({
                "record_kind": record_kind,
                "subject_id": subject_id,
                "subject_root": subject_root,
                "height": self.height,
                "epoch": self.epoch,
                "privacy_boundary": PRIVACY_BOUNDARY
            }),
        );
        let record_id = domain_hash(
            D_PUBLIC_RECORDS,
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&subject_root),
                HashPart::U64(self.counters.public_records_emitted),
            ],
            32,
        );
        let record = ClearinghousePublicRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            roots_only_payload_root: payload_root,
            height: self.height,
            epoch: self.epoch,
        };
        self.public_records.insert(record_id, record);
        self.counters.public_records_emitted =
            self.counters.public_records_emitted.saturating_add(1);
        Ok(())
    }
    fn subject_root(&self, record_kind: &str, subject_id: &str) -> Result<String> {
        match record_kind {
            "debit_note" => self
                .debit_notes
                .get(subject_id)
                .map(ConfidentialDebitNote::state_root)
                .ok_or_else(|| "missing debit note for public record".to_string()),
            "credit_note" => self
                .credit_notes
                .get(subject_id)
                .map(ConfidentialCreditNote::state_root)
                .ok_or_else(|| "missing credit note for public record".to_string()),
            "netting_window" => self
                .netting_windows
                .get(subject_id)
                .map(NettingWindow::state_root)
                .ok_or_else(|| "missing netting window for public record".to_string()),
            "settlement_batch" => self
                .settlement_batches
                .get(subject_id)
                .map(SettlementBatch::state_root)
                .ok_or_else(|| "missing settlement batch for public record".to_string()),
            "liquidity_bucket" => self
                .liquidity_buckets
                .get(subject_id)
                .map(LiquidityBucket::state_root)
                .ok_or_else(|| "missing liquidity bucket for public record".to_string()),
            "pq_clearinghouse_attestation" => self
                .attestations
                .get(subject_id)
                .map(PqClearinghouseAttestation::state_root)
                .ok_or_else(|| "missing attestation for public record".to_string()),
            _ => Err("unknown public record kind".to_string()),
        }
    }
    fn expire_stale_notes(&mut self) {
        for note in self.debit_notes.values_mut() {
            if note.status.live() && self.height > note.expires_height {
                note.status = NoteStatus::Expired;
            }
        }
        for note in self.credit_notes.values_mut() {
            if note.status.live() && self.height > note.expires_height {
                note.status = NoteStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            if self.height > attestation.expires_height {
                // Expired attestations remain committed; windows simply stop counting them.
            }
        }
    }
    fn expire_stale_windows(&mut self) {
        for window in self.netting_windows.values_mut() {
            if matches!(
                window.status,
                WindowStatus::Open | WindowStatus::Collecting | WindowStatus::Locked
            ) && self.height > window.settles_by_height
            {
                window.status = WindowStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> State {
    let mut state =
        State::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH).expect("valid devnet config");
    let bucket_id = state
        .open_liquidity_bucket(LiquidityBucketInput {
            bucket_id: "devnet-netting-clearinghouse-liquidity-bucket-0001".to_string(),
            lane: ClearinghouseLane::SequencerBlobFee,
            provider_commitment_root: "devnet-provider-commitment-root-0001".to_string(),
            reserve_commitment_root: "devnet-reserve-commitment-root-0001".to_string(),
            capacity_commitment_root: "devnet-capacity-commitment-root-0001".to_string(),
            nullifier_commitment: "devnet-bucket-nullifier-0001".to_string(),
            reserve_floor_units: 12_000,
            max_exposure_units: 220_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet liquidity bucket");
    let debit_id = state
        .post_debit_note(DebitNoteInput {
            note_id: "devnet-confidential-debit-note-0001".to_string(),
            lane: ClearinghouseLane::SequencerBlobFee,
            sequencer_commitment: "devnet-sequencer-commitment-root-0001".to_string(),
            account_commitment_root: "devnet-debit-account-commitment-root-0001".to_string(),
            sealed_amount_root: "devnet-debit-sealed-amount-root-0001".to_string(),
            blob_fee_bundle_root: "devnet-blob-fee-bundle-root-0001".to_string(),
            pq_envelope_root: "devnet-debit-pq-envelope-root-0001".to_string(),
            nullifier_commitment: "devnet-debit-nullifier-0001".to_string(),
            max_fee_bps: DEFAULT_TARGET_FEE_BPS,
            estimated_cost_units: 96_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet debit note");
    let credit_id = state
        .post_credit_note(CreditNoteInput {
            note_id: "devnet-confidential-credit-note-0001".to_string(),
            lane: ClearinghouseLane::UserRebate,
            beneficiary_commitment_root: "devnet-beneficiary-commitment-root-0001".to_string(),
            rebate_commitment_root: "devnet-rebate-commitment-root-0001".to_string(),
            eligibility_proof_root: "devnet-eligibility-proof-root-0001".to_string(),
            pq_envelope_root: "devnet-credit-pq-envelope-root-0001".to_string(),
            nullifier_hash: "devnet-credit-nullifier-0001".to_string(),
            min_rebate_bps: 6,
            estimated_rebate_units: 74_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet credit note");
    state
        .match_notes(&debit_id, &credit_id)
        .expect("devnet matched notes");
    let window_id = state
        .open_netting_window(WindowInput {
            window_id: "devnet-netting-window-0001".to_string(),
            lane: ClearinghouseLane::SequencerBlobFee,
            debit_note_ids: vec![debit_id],
            credit_note_ids: vec![credit_id],
            liquidity_bucket_ids: vec![bucket_id],
            window_commitment_root: "devnet-window-commitment-root-0001".to_string(),
            conservation_proof_root: "devnet-conservation-proof-root-0001".to_string(),
            fast_path: true,
        })
        .expect("devnet netting window");
    for idx in 0..DEFAULT_MIN_ATTESTATION_QUORUM {
        let attestation_id = format!("devnet-pq-netting-attestation-{idx:04}");
        let _ = state
            .post_attestation(AttestationInput {
                attestation_id,
                kind: AttestationKind::NettingComputation,
                subject_id: window_id.clone(),
                subject_root: "devnet-window-commitment-root-0001".to_string(),
                operator_set_root: "devnet-operator-set-root-0001".to_string(),
                pq_public_key_root: format!("devnet-pq-public-key-root-{idx:04}"),
                signature_root: format!("devnet-pq-signature-root-{idx:04}"),
                transcript_root: format!("devnet-pq-transcript-root-{idx:04}"),
                aggregate_weight: DEFAULT_MIN_ATTESTATION_QUORUM as u64,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            })
            .expect("devnet pq attestation");
    }
    state.lock_window(&window_id).expect("devnet lock window");
    let settlement_id = state
        .queue_settlement(SettlementInput {
            settlement_id: "devnet-netting-settlement-0001".to_string(),
            window_id,
            settlement_commitment_root: "devnet-settlement-commitment-root-0001".to_string(),
            netted_debit_root: "devnet-netted-debit-root-0001".to_string(),
            netted_credit_root: "devnet-netted-credit-root-0001".to_string(),
            residual_root: "devnet-residual-root-0001".to_string(),
            proof_root: "devnet-settlement-proof-root-0001".to_string(),
            publication_root: "devnet-publication-root-0001".to_string(),
        })
        .expect("devnet settlement");
    state
        .publish_settlement(&settlement_id, "devnet-published-root-0001".to_string())
        .expect("devnet publish settlement");
    state
        .finalize_settlement(&settlement_id, "devnet-finalized-root-0001".to_string())
        .expect("devnet finalize settlement");
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn apply_bps(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set.iter().map(|value| json!(value)).collect();
    merkle_root(domain, &leaves)
}

fn vector_root(domain: &str, values: &[String]) -> String {
    let leaves: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| json!({"index": index, "value": value}))
        .collect();
    merkle_root(domain, &leaves)
}
