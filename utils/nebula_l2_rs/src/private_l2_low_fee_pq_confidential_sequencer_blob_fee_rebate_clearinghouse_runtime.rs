use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialSequencerBlobFeeRebateClearinghouseRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SEQUENCER_BLOB_FEE_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-sequencer-blob-fee-rebate-clearinghouse-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SEQUENCER_BLOB_FEE_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ENVELOPE_SUITE: &str = "ml-kem-1024+ml-dsa-87-clearinghouse-fee-rebate-envelope-v1";
pub const REBATE_NETTING_SUITE: &str =
    "private-l2-low-fee-confidential-sequencer-rebate-netting-v1";
pub const SETTLEMENT_PROOF_SUITE: &str =
    "slh-dsa-shake-256f-clearinghouse-settlement-proof-root-v1";
pub const NULLIFIER_SUITE: &str = "confidential-clearinghouse-rebate-nullifier-set-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-sequencer-blob-fee-rebate-clearinghouse-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_accounts_amounts_addresses_view_keys_blob_payloads_or_secret_keys";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-clearinghouse-devnet";
pub const DEVNET_CLEARINGHOUSE_ID: &str =
    "private-l2-sequencer-blob-fee-rebate-clearinghouse-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "dxmr-rebate-devnet";
pub const DEVNET_HEIGHT: u64 = 4_220_000;
pub const DEVNET_EPOCH: u64 = 2_040;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_FEE_BPS: u64 = 14;
pub const DEFAULT_PROTOCOL_TAKE_BPS: u64 = 1;
pub const DEFAULT_REBATE_FLOOR_BPS: u64 = 6;
pub const DEFAULT_NETTING_EFFICIENCY_BPS: u64 = 9_250;
pub const DEFAULT_LIQUIDITY_RESERVE_BPS: u64 = 850;
pub const DEFAULT_FAST_PATH_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 20_160;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ATTESTATION_QUORUM: u16 = 7;
pub const DEFAULT_MAX_OBLIGATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_CLAIMS: usize = 8_388_608;
pub const DEFAULT_MAX_NETTING_ROUNDS: usize = 2_097_152;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 2_097_152;
pub const DEFAULT_MAX_NULLIFIERS: usize = 16_777_216;

const D_STATE: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:STATE";
const D_CONFIG: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:CONFIG";
const D_COUNTERS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:COUNTERS";
const D_ROOTS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:ROOTS";
const D_OBLIGATIONS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:OBLIGATIONS";
const D_CLAIMS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:CLAIMS";
const D_ROUNDS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:ROUNDS";
const D_SETTLEMENTS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:SETTLEMENTS";
const D_ATTESTATIONS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:ATTESTATIONS";
const D_NULLIFIERS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:NULLIFIERS";
const D_PUBLIC_RECORDS: &str = "PL2-LF-PQ-CONF-SEQ-BLOB-REBATE-CLEARINGHOUSE:PUBLIC-RECORDS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingLane {
    SequencerBlobFee,
    UserRebate,
    SponsorOffset,
    ProverPassThrough,
    LiquidityReserve,
    ProtocolTake,
    DisputeEscrow,
}
impl ClearingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerBlobFee => "sequencer_blob_fee",
            Self::UserRebate => "user_rebate",
            Self::SponsorOffset => "sponsor_offset",
            Self::ProverPassThrough => "prover_pass_through",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::ProtocolTake => "protocol_take",
            Self::DisputeEscrow => "dispute_escrow",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    Sealed,
    Eligible,
    Netted,
    Settled,
    Expired,
    Disputed,
}
impl ObligationStatus {
    pub fn nettable(self) -> bool {
        matches!(self, Self::Sealed | Self::Eligible)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Committed,
    Matched,
    RebateReady,
    Settled,
    Nullified,
    Expired,
    Disputed,
}
impl ClaimStatus {
    pub fn payable(self) -> bool {
        matches!(self, Self::Committed | Self::Matched | Self::RebateReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Open,
    Collecting,
    PqAttested,
    Netted,
    SettlementQueued,
    Settled,
    Cancelled,
    Disputed,
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
    Disputed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub clearinghouse_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_envelope_suite: String,
    pub rebate_netting_suite: String,
    pub settlement_proof_suite: String,
    pub nullifier_suite: String,
    pub public_record_suite: String,
    pub target_fee_bps: u64,
    pub max_fee_bps: u64,
    pub protocol_take_bps: u64,
    pub rebate_floor_bps: u64,
    pub netting_efficiency_bps: u64,
    pub liquidity_reserve_bps: u64,
    pub fast_path_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_attestation_quorum: u16,
    pub max_obligations: usize,
    pub max_claims: usize,
    pub max_netting_rounds: usize,
    pub max_settlements: usize,
    pub max_nullifiers: usize,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            clearinghouse_id: DEVNET_CLEARINGHOUSE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_envelope_suite: PQ_ENVELOPE_SUITE.to_string(),
            rebate_netting_suite: REBATE_NETTING_SUITE.to_string(),
            settlement_proof_suite: SETTLEMENT_PROOF_SUITE.to_string(),
            nullifier_suite: NULLIFIER_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            protocol_take_bps: DEFAULT_PROTOCOL_TAKE_BPS,
            rebate_floor_bps: DEFAULT_REBATE_FLOOR_BPS,
            netting_efficiency_bps: DEFAULT_NETTING_EFFICIENCY_BPS,
            liquidity_reserve_bps: DEFAULT_LIQUIDITY_RESERVE_BPS,
            fast_path_window_blocks: DEFAULT_FAST_PATH_WINDOW_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_attestation_quorum: DEFAULT_MIN_ATTESTATION_QUORUM,
            max_obligations: DEFAULT_MAX_OBLIGATIONS,
            max_claims: DEFAULT_MAX_CLAIMS,
            max_netting_rounds: DEFAULT_MAX_NETTING_ROUNDS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }
}
impl Config {
    pub fn devnet() -> Self {
        Self::default()
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
            ("rebate_floor_bps", self.rebate_floor_bps),
            ("netting_efficiency_bps", self.netting_efficiency_bps),
            ("liquidity_reserve_bps", self.liquidity_reserve_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{name} exceeds bps denominator"));
            }
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security floor below 192 bits".to_string());
        }
        if self.min_privacy_set_size < 65_536
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set target below floor".to_string());
        }
        if self.min_attestation_quorum == 0 {
            return Err("attestation quorum cannot be zero".to_string());
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
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "hash_suite": self.hash_suite,
            "pq_envelope_suite": self.pq_envelope_suite,
            "rebate_netting_suite": self.rebate_netting_suite,
            "settlement_proof_suite": self.settlement_proof_suite,
            "nullifier_suite": self.nullifier_suite,
            "public_record_suite": self.public_record_suite,
            "target_fee_bps": self.target_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "protocol_take_bps": self.protocol_take_bps,
            "rebate_floor_bps": self.rebate_floor_bps,
            "netting_efficiency_bps": self.netting_efficiency_bps,
            "liquidity_reserve_bps": self.liquidity_reserve_bps,
            "fast_path_window_blocks": self.fast_path_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
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
    pub obligations_posted: u64,
    pub claims_posted: u64,
    pub netting_rounds_opened: u64,
    pub netting_rounds_settled: u64,
    pub settlements_published: u64,
    pub attestations_posted: u64,
    pub nullifiers_seen: u64,
    pub public_records: u64,
    pub gross_fee_units: u128,
    pub netted_fee_units: u128,
    pub rebate_units: u128,
    pub protocol_fee_units: u128,
    pub liquidity_reserved_units: u128,
    pub fee_savings_units: u128,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "obligations_posted": self.obligations_posted,
            "claims_posted": self.claims_posted,
            "netting_rounds_opened": self.netting_rounds_opened,
            "netting_rounds_settled": self.netting_rounds_settled,
            "settlements_published": self.settlements_published,
            "attestations_posted": self.attestations_posted,
            "nullifiers_seen": self.nullifiers_seen,
            "public_records": self.public_records,
            "gross_fee_units": self.gross_fee_units.to_string(),
            "netted_fee_units": self.netted_fee_units.to_string(),
            "rebate_units": self.rebate_units.to_string(),
            "protocol_fee_units": self.protocol_fee_units.to_string(),
            "liquidity_reserved_units": self.liquidity_reserved_units.to_string(),
            "fee_savings_units": self.fee_savings_units.to_string()
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
    pub obligation_root: String,
    pub claim_root: String,
    pub netting_round_root: String,
    pub settlement_root: String,
    pub attestation_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingObligation {
    pub obligation_id: String,
    pub lane: ClearingLane,
    pub status: ObligationStatus,
    pub sequencer_commitment: String,
    pub account_commitment_root: String,
    pub sealed_amount_root: String,
    pub blob_fee_bundle_root: String,
    pub pq_envelope_root: String,
    pub nullifier_commitment: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub epoch: u64,
    pub created_height: u64,
    pub expires_height: u64,
}
impl ClearingObligation {
    pub fn public_record(&self) -> Value {
        json!({
            "obligation_id": self.obligation_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "sequencer_commitment": self.sequencer_commitment,
            "account_commitment_root": self.account_commitment_root,
            "sealed_amount_root": self.sealed_amount_root,
            "blob_fee_bundle_root": self.blob_fee_bundle_root,
            "pq_envelope_root": self.pq_envelope_root,
            "nullifier_commitment": self.nullifier_commitment,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "epoch": self.epoch,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_OBLIGATIONS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateClaim {
    pub claim_id: String,
    pub status: ClaimStatus,
    pub beneficiary_commitment_root: String,
    pub sealed_rebate_root: String,
    pub eligibility_proof_root: String,
    pub nullifier_hash: String,
    pub rebate_asset_id: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub epoch: u64,
    pub created_height: u64,
    pub expires_height: u64,
}
impl RebateClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "status": self.status,
            "beneficiary_commitment_root": self.beneficiary_commitment_root,
            "sealed_rebate_root": self.sealed_rebate_root,
            "eligibility_proof_root": self.eligibility_proof_root,
            "nullifier_hash": self.nullifier_hash,
            "rebate_asset_id": self.rebate_asset_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "epoch": self.epoch,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_CLAIMS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClearingAttestation {
    pub attestation_id: String,
    pub round_id: String,
    pub quorum_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub pq_scheme: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_height: u64,
    pub expires_height: u64,
}
impl PqClearingAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_ATTESTATIONS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingRound {
    pub round_id: String,
    pub status: NettingStatus,
    pub epoch: u64,
    pub open_height: u64,
    pub close_height: u64,
    pub obligation_ids: BTreeSet<String>,
    pub claim_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub gross_fee_units: u128,
    pub netted_fee_units: u128,
    pub rebate_units: u128,
    pub protocol_fee_units: u128,
    pub liquidity_reserved_units: u128,
    pub netting_transcript_root: String,
}
impl NettingRound {
    pub fn public_record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "status": self.status,
            "epoch": self.epoch,
            "open_height": self.open_height,
            "close_height": self.close_height,
            "obligation_count": self.obligation_ids.len(),
            "claim_count": self.claim_ids.len(),
            "attestation_count": self.attestation_ids.len(),
            "gross_fee_units": self.gross_fee_units.to_string(),
            "netted_fee_units": self.netted_fee_units.to_string(),
            "rebate_units": self.rebate_units.to_string(),
            "protocol_fee_units": self.protocol_fee_units.to_string(),
            "liquidity_reserved_units": self.liquidity_reserved_units.to_string(),
            "netting_transcript_root": self.netting_transcript_root
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_ROUNDS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementEntry {
    pub settlement_id: String,
    pub round_id: String,
    pub status: SettlementStatus,
    pub settlement_root: String,
    pub rebate_output_root: String,
    pub fee_output_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub published_height: u64,
    pub finalized_height: u64,
}
impl SettlementEntry {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_SETTLEMENTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub state_root: String,
    pub roots: Roots,
    pub protocol_version: String,
    pub privacy_boundary: String,
    pub height: u64,
    pub epoch: u64,
}
impl RootsOnlyPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "state_root": self.state_root,
            "roots": self.roots.public_record(),
            "protocol_version": self.protocol_version,
            "privacy_boundary": self.privacy_boundary,
            "height": self.height,
            "epoch": self.epoch
        })
    }
    pub fn state_root(&self) -> String {
        record_root(D_PUBLIC_RECORDS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObligationInput {
    pub obligation_id: String,
    pub lane: ClearingLane,
    pub sequencer_commitment: String,
    pub account_commitment_root: String,
    pub sealed_amount_root: String,
    pub blob_fee_bundle_root: String,
    pub pq_envelope_root: String,
    pub nullifier_commitment: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimInput {
    pub claim_id: String,
    pub beneficiary_commitment_root: String,
    pub sealed_rebate_root: String,
    pub eligibility_proof_root: String,
    pub nullifier_hash: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingInput {
    pub round_id: String,
    pub obligation_ids: BTreeSet<String>,
    pub claim_ids: BTreeSet<String>,
    pub gross_fee_units: u128,
    pub netting_transcript_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationInput {
    pub attestation_id: String,
    pub round_id: String,
    pub quorum_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub pq_scheme: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementInput {
    pub settlement_id: String,
    pub round_id: String,
    pub settlement_root: String,
    pub rebate_output_root: String,
    pub fee_output_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub obligations: BTreeMap<String, ClearingObligation>,
    pub claims: BTreeMap<String, RebateClaim>,
    pub netting_rounds: BTreeMap<String, NettingRound>,
    pub settlements: BTreeMap<String, SettlementEntry>,
    pub attestations: BTreeMap<String, PqClearingAttestation>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub height: u64,
    pub epoch: u64,
}
impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            height: config.devnet_height,
            epoch: config.devnet_epoch,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            obligations: BTreeMap::new(),
            claims: BTreeMap::new(),
            netting_rounds: BTreeMap::new(),
            settlements: BTreeMap::new(),
            attestations: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn post_obligation(&mut self, input: ObligationInput) -> Result<()> {
        self.config.validate()?;
        if self.obligations.len() >= self.config.max_obligations {
            return Err("obligation capacity exceeded".to_string());
        }
        if self.obligations.contains_key(&input.obligation_id) {
            return Err("duplicate obligation".to_string());
        }
        self.validate_privacy(input.privacy_set_size, input.pq_security_bits)?;
        if input.max_fee_bps > self.config.max_fee_bps {
            return Err("obligation exceeds low-fee cap".to_string());
        }
        if !self
            .nullifiers
            .insert(format!("obligation:{}", input.nullifier_commitment))
        {
            return Err("duplicate obligation nullifier".to_string());
        }
        let obligation = ClearingObligation {
            obligation_id: input.obligation_id.clone(),
            lane: input.lane,
            status: ObligationStatus::Sealed,
            sequencer_commitment: input.sequencer_commitment,
            account_commitment_root: input.account_commitment_root,
            sealed_amount_root: input.sealed_amount_root,
            blob_fee_bundle_root: input.blob_fee_bundle_root,
            pq_envelope_root: input.pq_envelope_root,
            nullifier_commitment: input.nullifier_commitment,
            max_fee_bps: input.max_fee_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            epoch: self.epoch,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.rebate_ttl_blocks),
        };
        self.obligations.insert(input.obligation_id, obligation);
        self.counters.obligations_posted = self.counters.obligations_posted.saturating_add(1);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn post_claim(&mut self, input: ClaimInput) -> Result<()> {
        self.config.validate()?;
        if self.claims.len() >= self.config.max_claims {
            return Err("claim capacity exceeded".to_string());
        }
        if self.claims.contains_key(&input.claim_id) {
            return Err("duplicate claim".to_string());
        }
        self.validate_privacy(input.privacy_set_size, input.pq_security_bits)?;
        if !self
            .nullifiers
            .insert(format!("claim:{}", input.nullifier_hash))
        {
            return Err("duplicate claim nullifier".to_string());
        }
        let claim = RebateClaim {
            claim_id: input.claim_id.clone(),
            status: ClaimStatus::Committed,
            beneficiary_commitment_root: input.beneficiary_commitment_root,
            sealed_rebate_root: input.sealed_rebate_root,
            eligibility_proof_root: input.eligibility_proof_root,
            nullifier_hash: input.nullifier_hash,
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            epoch: self.epoch,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.rebate_ttl_blocks),
        };
        self.claims.insert(input.claim_id, claim);
        self.counters.claims_posted = self.counters.claims_posted.saturating_add(1);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn open_netting_round(&mut self, input: NettingInput) -> Result<()> {
        self.config.validate()?;
        if self.netting_rounds.len() >= self.config.max_netting_rounds {
            return Err("netting round capacity exceeded".to_string());
        }
        if self.netting_rounds.contains_key(&input.round_id) {
            return Err("duplicate netting round".to_string());
        }
        for obligation_id in &input.obligation_ids {
            let obligation = self
                .obligations
                .get(obligation_id)
                .ok_or_else(|| format!("missing obligation {obligation_id}"))?;
            if !obligation.status.nettable() {
                return Err(format!("obligation {obligation_id} is not nettable"));
            }
        }
        for claim_id in &input.claim_ids {
            let claim = self
                .claims
                .get(claim_id)
                .ok_or_else(|| format!("missing claim {claim_id}"))?;
            if !claim.status.payable() {
                return Err(format!("claim {claim_id} is not payable"));
            }
        }
        let protocol_fee_units = apply_bps(input.gross_fee_units, self.config.protocol_take_bps);
        let liquidity_reserved_units =
            apply_bps(input.gross_fee_units, self.config.liquidity_reserve_bps);
        let netted_fee_units = apply_bps(input.gross_fee_units, self.config.netting_efficiency_bps)
            .saturating_sub(protocol_fee_units)
            .saturating_sub(liquidity_reserved_units);
        let rebate_units = apply_bps(input.gross_fee_units, self.config.rebate_floor_bps)
            .saturating_add(input.gross_fee_units.saturating_sub(netted_fee_units));
        let round = NettingRound {
            round_id: input.round_id.clone(),
            status: NettingStatus::Collecting,
            epoch: self.epoch,
            open_height: self.height,
            close_height: self
                .height
                .saturating_add(self.config.settlement_window_blocks),
            obligation_ids: input.obligation_ids,
            claim_ids: input.claim_ids,
            attestation_ids: BTreeSet::new(),
            gross_fee_units: input.gross_fee_units,
            netted_fee_units,
            rebate_units,
            protocol_fee_units,
            liquidity_reserved_units,
            netting_transcript_root: input.netting_transcript_root,
        };
        self.netting_rounds.insert(input.round_id, round);
        self.counters.netting_rounds_opened = self.counters.netting_rounds_opened.saturating_add(1);
        self.counters.gross_fee_units = self
            .counters
            .gross_fee_units
            .saturating_add(input.gross_fee_units);
        self.counters.netted_fee_units = self
            .counters
            .netted_fee_units
            .saturating_add(netted_fee_units);
        self.counters.rebate_units = self.counters.rebate_units.saturating_add(rebate_units);
        self.counters.protocol_fee_units = self
            .counters
            .protocol_fee_units
            .saturating_add(protocol_fee_units);
        self.counters.liquidity_reserved_units = self
            .counters
            .liquidity_reserved_units
            .saturating_add(liquidity_reserved_units);
        self.counters.fee_savings_units = self
            .counters
            .fee_savings_units
            .saturating_add(input.gross_fee_units.saturating_sub(netted_fee_units));
        self.recompute_roots();
        Ok(())
    }

    pub fn post_attestation(&mut self, input: AttestationInput) -> Result<()> {
        self.config.validate()?;
        self.validate_privacy(input.privacy_set_size, input.pq_security_bits)?;
        if self.attestations.contains_key(&input.attestation_id) {
            return Err("duplicate attestation".to_string());
        }
        let round = self
            .netting_rounds
            .get_mut(&input.round_id)
            .ok_or_else(|| "missing netting round".to_string())?;
        let attestation = PqClearingAttestation {
            attestation_id: input.attestation_id.clone(),
            round_id: input.round_id,
            quorum_root: input.quorum_root,
            transcript_root: input.transcript_root,
            signature_root: input.signature_root,
            pq_scheme: input.pq_scheme,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            created_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        round.attestation_ids.insert(input.attestation_id.clone());
        if round.attestation_ids.len() >= self.config.min_attestation_quorum as usize {
            round.status = NettingStatus::PqAttested;
        }
        self.attestations.insert(input.attestation_id, attestation);
        self.counters.attestations_posted = self.counters.attestations_posted.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn publish_settlement(&mut self, input: SettlementInput) -> Result<()> {
        self.config.validate()?;
        if self.settlements.len() >= self.config.max_settlements {
            return Err("settlement capacity exceeded".to_string());
        }
        if self.settlements.contains_key(&input.settlement_id) {
            return Err("duplicate settlement".to_string());
        }
        let round = self
            .netting_rounds
            .get_mut(&input.round_id)
            .ok_or_else(|| "missing netting round".to_string())?;
        if round.attestation_ids.len() < self.config.min_attestation_quorum as usize {
            return Err("attestation quorum not met".to_string());
        }
        round.status = NettingStatus::Settled;
        let settlement = SettlementEntry {
            settlement_id: input.settlement_id.clone(),
            round_id: input.round_id,
            status: if self.height <= round.open_height + self.config.fast_path_window_blocks {
                SettlementStatus::FastPath
            } else {
                SettlementStatus::Batched
            },
            settlement_root: input.settlement_root,
            rebate_output_root: input.rebate_output_root,
            fee_output_root: input.fee_output_root,
            nullifier_root: input.nullifier_root,
            proof_root: input.proof_root,
            published_height: self.height,
            finalized_height: self.height.saturating_add(1),
        };
        self.settlements.insert(input.settlement_id, settlement);
        self.counters.netting_rounds_settled =
            self.counters.netting_rounds_settled.saturating_add(1);
        self.counters.settlements_published = self.counters.settlements_published.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root(
            D_STATE,
            &json!({
                "config_root": self.config.state_root(),
                "counters_root": self.counters.state_root(),
                "roots_root": self.roots.state_root(),
                "height": self.height,
                "epoch": self.epoch
            }),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "height": self.height,
            "epoch": self.epoch,
            "state_root": self.state_root(),
            "roots": self.roots.public_record()
        })
    }

    pub fn roots_only_record(&mut self, record_id: impl Into<String>) -> RootsOnlyPublicRecord {
        self.recompute_roots();
        let record = RootsOnlyPublicRecord {
            record_id: record_id.into(),
            state_root: self.state_root(),
            roots: self.roots.clone(),
            protocol_version: self.config.protocol_version.clone(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            height: self.height,
            epoch: self.epoch,
        };
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        self.counters.public_records = self.counters.public_records.saturating_add(1);
        self.recompute_roots();
        record
    }

    fn validate_privacy(&self, privacy_set_size: u64, pq_security_bits: u16) -> Result<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below clearinghouse floor".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security below clearinghouse floor".to_string());
        }
        Ok(())
    }

    fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            obligation_root: map_root(D_OBLIGATIONS, &self.obligations),
            claim_root: map_root(D_CLAIMS, &self.claims),
            netting_round_root: map_root(D_ROUNDS, &self.netting_rounds),
            settlement_root: map_root(D_SETTLEMENTS, &self.settlements),
            attestation_root: map_root(D_ATTESTATIONS, &self.attestations),
            nullifier_root: set_root(D_NULLIFIERS, &self.nullifiers),
            public_record_root: map_root(D_PUBLIC_RECORDS, &self.public_records),
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

fn apply_bps(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves: Vec<String> = map
        .iter()
        .map(|(key, value)| record_root(domain, &json!({"key": key, "value": value})))
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<String> = set
        .iter()
        .map(|value| record_root(domain, &json!(value)))
        .collect();
    merkle_root(domain, &leaves)
}
