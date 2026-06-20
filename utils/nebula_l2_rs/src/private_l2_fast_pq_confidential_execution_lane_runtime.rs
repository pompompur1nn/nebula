use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialExecutionLaneRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_EXECUTION_LANE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-execution-lane-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_EXECUTION_LANE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_640_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-fast-confidential-execution-v1";
pub const ENCRYPTED_PACKET_SCHEME: &str = "ml-kem-sealed-confidential-contract-call-packet-v1";
pub const PQ_ADMISSION_SCHEME: &str = "pq-sequencer-confidential-execution-admission-root-v1";
pub const WITNESS_LEASE_SCHEME: &str = "confidential-witness-lease-root-v1";
pub const EXECUTION_SLOT_SCHEME: &str = "parallel-private-contract-execution-slot-root-v1";
pub const PRECONFIRMATION_SCHEME: &str = "fast-confidential-execution-preconfirmation-root-v1";
pub const FEE_REBATE_SCHEME: &str = "sponsored-low-fee-confidential-execution-rebate-root-v1";
pub const PROOF_RECEIPT_SCHEME: &str = "low-fee-recursive-execution-proof-receipt-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "confidential-execution-nullifier-fence-root-v1";
pub const CHALLENGE_SCHEME: &str = "pq-confidential-execution-challenge-evidence-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_PACKET_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_ADMISSION_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_WITNESS_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 4;
pub const DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 6;
pub const DEFAULT_MAX_PACKETS: usize = 4_194_304;
pub const DEFAULT_MAX_ADMISSIONS: usize = 4_194_304;
pub const DEFAULT_MAX_WITNESS_LEASES: usize = 2_097_152;
pub const DEFAULT_MAX_EXECUTION_SLOTS: usize = 2_097_152;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_PROOF_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLaneKind {
    FastContract,
    DefiCritical,
    TokenSettlement,
    OracleBound,
    Governance,
    Emergency,
    BatchCheap,
}

impl ExecutionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastContract => "fast_contract",
            Self::DefiCritical => "defi_critical",
            Self::TokenSettlement => "token_settlement",
            Self::OracleBound => "oracle_bound",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
            Self::BatchCheap => "batch_cheap",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::DefiCritical => 940,
            Self::FastContract => 900,
            Self::TokenSettlement => 850,
            Self::OracleBound => 780,
            Self::Governance => 660,
            Self::BatchCheap => 520,
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::BatchCheap => 5_000,
            Self::Governance => 6_500,
            Self::OracleBound => 7_500,
            Self::TokenSettlement => 8_000,
            Self::FastContract => 10_000,
            Self::DefiCritical => 11_000,
            Self::Emergency => 12_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialPacketStatus {
    Submitted,
    Admitted,
    Leased,
    Scheduled,
    Preconfirmed,
    Proven,
    Settled,
    Cancelled,
    Challenged,
    Expired,
}

impl ConfidentialPacketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Leased => "leased",
            Self::Scheduled => "scheduled",
            Self::Preconfirmed => "preconfirmed",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn can_admit(self) -> bool {
        matches!(self, Self::Submitted)
    }

    pub fn can_schedule(self) -> bool {
        matches!(self, Self::Admitted | Self::Leased)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessLeaseStatus {
    Reserved,
    Bound,
    Consumed,
    Released,
    Slashed,
    Expired,
}

impl WitnessLeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Bound => "bound",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Reserved,
    Executing,
    Preconfirmed,
    Settled,
    Replayed,
    Failed,
    Challenged,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Replayed => "replayed",
            Self::Failed => "failed",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
    Challenged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    PacketNullifier,
    WitnessNullifier,
    StateReplay,
    BundleReplay,
    FeeClaim,
    ProofReuse,
}

impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PacketNullifier => "packet_nullifier",
            Self::WitnessNullifier => "witness_nullifier",
            Self::StateReplay => "state_replay",
            Self::BundleReplay => "bundle_replay",
            Self::FeeClaim => "fee_claim",
            Self::ProofReuse => "proof_reuse",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidPqAdmission,
    WitnessWithheld,
    BadStateTransition,
    FeeOvercharge,
    PrivacyLeak,
    SlaMiss,
    DoubleExecution,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqAdmission => "invalid_pq_admission",
            Self::WitnessWithheld => "witness_withheld",
            Self::BadStateTransition => "bad_state_transition",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyLeak => "privacy_leak",
            Self::SlaMiss => "sla_miss",
            Self::DoubleExecution => "double_execution",
        }
    }

    pub fn severity_score(self) -> u64 {
        match self {
            Self::PrivacyLeak | Self::BadStateTransition | Self::DoubleExecution => 10_000,
            Self::InvalidPqAdmission => 9_000,
            Self::WitnessWithheld => 7_500,
            Self::SlaMiss => 5_000,
            Self::FeeOvercharge => 4_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub packet_ttl_blocks: u64,
    pub admission_ttl_blocks: u64,
    pub witness_ttl_blocks: u64,
    pub slot_ttl_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_packets: usize,
    pub max_admissions: usize,
    pub max_witness_leases: usize,
    pub max_execution_slots: usize,
    pub max_preconfirmations: usize,
    pub max_rebates: usize,
    pub max_proof_receipts: usize,
    pub max_privacy_fences: usize,
    pub max_challenges: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            packet_ttl_blocks: DEFAULT_PACKET_TTL_BLOCKS,
            admission_ttl_blocks: DEFAULT_ADMISSION_TTL_BLOCKS,
            witness_ttl_blocks: DEFAULT_WITNESS_TTL_BLOCKS,
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            preconfirmation_ttl_blocks: DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_packets: DEFAULT_MAX_PACKETS,
            max_admissions: DEFAULT_MAX_ADMISSIONS,
            max_witness_leases: DEFAULT_MAX_WITNESS_LEASES,
            max_execution_slots: DEFAULT_MAX_EXECUTION_SLOTS,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_proof_receipts: DEFAULT_MAX_PROOF_RECEIPTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.min_privacy_set_size < 16_384 {
            return Err("min_privacy_set_size is below confidential execution floor".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits is below runtime floor".to_string());
        }
        if self.max_user_fee_bps > 100 {
            return Err("max_user_fee_bps is above low-fee runtime envelope".to_string());
        }
        if self.target_rebate_bps > self.max_user_fee_bps {
            return Err("target_rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.sponsor_cover_bps > MAX_BPS {
            return Err("sponsor_cover_bps cannot exceed MAX_BPS".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_execution_lane_config",
            "chain_id": self.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "packet_ttl_blocks": self.packet_ttl_blocks,
            "admission_ttl_blocks": self.admission_ttl_blocks,
            "witness_ttl_blocks": self.witness_ttl_blocks,
            "slot_ttl_blocks": self.slot_ttl_blocks,
            "preconfirmation_ttl_blocks": self.preconfirmation_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub next_packet: u64,
    pub next_admission: u64,
    pub next_witness_lease: u64,
    pub next_execution_slot: u64,
    pub next_preconfirmation: u64,
    pub next_rebate: u64,
    pub next_proof_receipt: u64,
    pub next_privacy_fence: u64,
    pub next_challenge: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_execution_lane_counters",
            "packet_count": self.next_packet,
            "admission_count": self.next_admission,
            "witness_lease_count": self.next_witness_lease,
            "execution_slot_count": self.next_execution_slot,
            "preconfirmation_count": self.next_preconfirmation,
            "rebate_count": self.next_rebate,
            "proof_receipt_count": self.next_proof_receipt,
            "privacy_fence_count": self.next_privacy_fence,
            "challenge_count": self.next_challenge,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub packet_root: String,
    pub admission_root: String,
    pub witness_lease_root: String,
    pub execution_slot_root: String,
    pub preconfirmation_root: String,
    pub rebate_root: String,
    pub proof_receipt_root: String,
    pub privacy_fence_root: String,
    pub challenge_root: String,
    pub spent_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_execution_lane_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "packet_root": self.packet_root,
            "admission_root": self.admission_root,
            "witness_lease_root": self.witness_lease_root,
            "execution_slot_root": self.execution_slot_root,
            "preconfirmation_root": self.preconfirmation_root,
            "rebate_root": self.rebate_root,
            "proof_receipt_root": self.proof_receipt_root,
            "privacy_fence_root": self.privacy_fence_root,
            "challenge_root": self.challenge_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedCallPacketRequest {
    pub owner_commitment: String,
    pub contract_namespace: String,
    pub lane: ExecutionLaneKind,
    pub encrypted_calldata_root: String,
    pub call_graph_root: String,
    pub state_read_set_root: String,
    pub state_write_set_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_ephemeral_key_root: String,
    pub packet_nullifier: String,
    pub submitted_height: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedCallPacket {
    pub packet_id: String,
    pub owner_commitment: String,
    pub contract_namespace: String,
    pub lane: ExecutionLaneKind,
    pub encrypted_calldata_root: String,
    pub call_graph_root: String,
    pub state_read_set_root: String,
    pub state_write_set_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_ephemeral_key_root: String,
    pub packet_nullifier: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: ConfidentialPacketStatus,
    pub priority_score: u64,
    pub metadata_root: String,
}

impl EncryptedCallPacket {
    pub fn from_request(config: &Config, request: EncryptedCallPacketRequest) -> Result<Self> {
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        ensure_nonempty("contract_namespace", &request.contract_namespace)?;
        ensure_nonempty("encrypted_calldata_root", &request.encrypted_calldata_root)?;
        ensure_nonempty("call_graph_root", &request.call_graph_root)?;
        ensure_nonempty("state_read_set_root", &request.state_read_set_root)?;
        ensure_nonempty(
            "state_write_set_commitment",
            &request.state_write_set_commitment,
        )?;
        ensure_nonempty("pq_ephemeral_key_root", &request.pq_ephemeral_key_root)?;
        ensure_nonempty("packet_nullifier", &request.packet_nullifier)?;
        if request.fee_asset_id != config.fee_asset_id {
            return Err("packet fee_asset_id does not match runtime fee asset".to_string());
        }
        if request.privacy_set_size < config.min_privacy_set_size {
            return Err("packet privacy set is below configured minimum".to_string());
        }
        let fee_cap = config
            .max_user_fee_bps
            .saturating_mul(request.lane.fee_multiplier_bps())
            / MAX_BPS;
        let packet_id = packet_id(&request);
        Ok(Self {
            packet_id,
            owner_commitment: request.owner_commitment,
            contract_namespace: request.contract_namespace,
            lane: request.lane,
            encrypted_calldata_root: request.encrypted_calldata_root,
            call_graph_root: request.call_graph_root,
            state_read_set_root: request.state_read_set_root,
            state_write_set_commitment: request.state_write_set_commitment,
            fee_asset_id: request.fee_asset_id,
            max_fee_micro_units: request.max_fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            pq_ephemeral_key_root: request.pq_ephemeral_key_root,
            packet_nullifier: request.packet_nullifier,
            submitted_height: request.submitted_height,
            expires_height: request
                .submitted_height
                .saturating_add(config.packet_ttl_blocks),
            status: ConfidentialPacketStatus::Submitted,
            priority_score: packet_priority_score(
                request.lane,
                request.privacy_set_size,
                request.max_fee_micro_units,
                fee_cap,
            ),
            metadata_root: request.metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_confidential_execution_packet",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "owner_commitment": self.owner_commitment,
            "contract_namespace": self.contract_namespace,
            "lane": self.lane.as_str(),
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "call_graph_root": self.call_graph_root,
            "state_read_set_root": self.state_read_set_root,
            "state_write_set_commitment": self.state_write_set_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_ephemeral_key_root": self.pq_ephemeral_key_root,
            "packet_nullifier": self.packet_nullifier,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "priority_score": self.priority_score,
            "scheme": ENCRYPTED_PACKET_SCHEME,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSequencerAdmissionRequest {
    pub packet_id: String,
    pub sequencer_id: String,
    pub committee_id: String,
    pub admission_round: u64,
    pub admitted_payload_root: String,
    pub pq_signature_root: String,
    pub admitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSequencerAdmission {
    pub admission_id: String,
    pub packet_id: String,
    pub sequencer_id: String,
    pub committee_id: String,
    pub admission_round: u64,
    pub admitted_payload_root: String,
    pub pq_signature_root: String,
    pub admitted_height: u64,
    pub expires_height: u64,
}

impl PqSequencerAdmission {
    pub fn from_request(config: &Config, request: PqSequencerAdmissionRequest) -> Result<Self> {
        ensure_nonempty("packet_id", &request.packet_id)?;
        ensure_nonempty("sequencer_id", &request.sequencer_id)?;
        ensure_nonempty("committee_id", &request.committee_id)?;
        ensure_nonempty("admitted_payload_root", &request.admitted_payload_root)?;
        ensure_nonempty("pq_signature_root", &request.pq_signature_root)?;
        let admission_id = admission_id(&request);
        Ok(Self {
            admission_id,
            packet_id: request.packet_id,
            sequencer_id: request.sequencer_id,
            committee_id: request.committee_id,
            admission_round: request.admission_round,
            admitted_payload_root: request.admitted_payload_root,
            pq_signature_root: request.pq_signature_root,
            admitted_height: request.admitted_height,
            expires_height: request
                .admitted_height
                .saturating_add(config.admission_ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_execution_admission",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "admission_id": self.admission_id,
            "packet_id": self.packet_id,
            "sequencer_id": self.sequencer_id,
            "committee_id": self.committee_id,
            "admission_round": self.admission_round,
            "admitted_payload_root": self.admitted_payload_root,
            "pq_signature_root": self.pq_signature_root,
            "admitted_height": self.admitted_height,
            "expires_height": self.expires_height,
            "scheme": PQ_ADMISSION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialWitnessLeaseRequest {
    pub packet_id: String,
    pub admission_id: String,
    pub witness_provider_id: String,
    pub encrypted_witness_root: String,
    pub witness_policy_root: String,
    pub witness_fee_micro_units: u64,
    pub lease_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialWitnessLease {
    pub lease_id: String,
    pub packet_id: String,
    pub admission_id: String,
    pub witness_provider_id: String,
    pub encrypted_witness_root: String,
    pub witness_policy_root: String,
    pub witness_fee_micro_units: u64,
    pub lease_height: u64,
    pub expires_height: u64,
    pub status: WitnessLeaseStatus,
}

impl ConfidentialWitnessLease {
    pub fn from_request(config: &Config, request: ConfidentialWitnessLeaseRequest) -> Result<Self> {
        ensure_nonempty("packet_id", &request.packet_id)?;
        ensure_nonempty("admission_id", &request.admission_id)?;
        ensure_nonempty("witness_provider_id", &request.witness_provider_id)?;
        ensure_nonempty("encrypted_witness_root", &request.encrypted_witness_root)?;
        ensure_nonempty("witness_policy_root", &request.witness_policy_root)?;
        let lease_id = witness_lease_id(&request);
        Ok(Self {
            lease_id,
            packet_id: request.packet_id,
            admission_id: request.admission_id,
            witness_provider_id: request.witness_provider_id,
            encrypted_witness_root: request.encrypted_witness_root,
            witness_policy_root: request.witness_policy_root,
            witness_fee_micro_units: request.witness_fee_micro_units,
            lease_height: request.lease_height,
            expires_height: request
                .lease_height
                .saturating_add(config.witness_ttl_blocks),
            status: WitnessLeaseStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_execution_witness_lease",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "lease_id": self.lease_id,
            "packet_id": self.packet_id,
            "admission_id": self.admission_id,
            "witness_provider_id": self.witness_provider_id,
            "encrypted_witness_root": self.encrypted_witness_root,
            "witness_policy_root": self.witness_policy_root,
            "witness_fee_micro_units": self.witness_fee_micro_units,
            "lease_height": self.lease_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "scheme": WITNESS_LEASE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParallelExecutionSlotRequest {
    pub packet_id: String,
    pub admission_id: String,
    pub lease_id: Option<String>,
    pub executor_id: String,
    pub lane: ExecutionLaneKind,
    pub parallel_group_root: String,
    pub read_conflict_root: String,
    pub write_lock_root: String,
    pub scheduled_height: u64,
    pub max_latency_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParallelExecutionSlot {
    pub slot_id: String,
    pub packet_id: String,
    pub admission_id: String,
    pub lease_id: Option<String>,
    pub executor_id: String,
    pub lane: ExecutionLaneKind,
    pub parallel_group_root: String,
    pub read_conflict_root: String,
    pub write_lock_root: String,
    pub scheduled_height: u64,
    pub expires_height: u64,
    pub max_latency_ms: u64,
    pub status: SlotStatus,
}

impl ParallelExecutionSlot {
    pub fn from_request(config: &Config, request: ParallelExecutionSlotRequest) -> Result<Self> {
        ensure_nonempty("packet_id", &request.packet_id)?;
        ensure_nonempty("admission_id", &request.admission_id)?;
        ensure_nonempty("executor_id", &request.executor_id)?;
        ensure_nonempty("parallel_group_root", &request.parallel_group_root)?;
        ensure_nonempty("read_conflict_root", &request.read_conflict_root)?;
        ensure_nonempty("write_lock_root", &request.write_lock_root)?;
        if request.max_latency_ms == 0 {
            return Err("max_latency_ms must be positive".to_string());
        }
        let slot_id = execution_slot_id(&request);
        Ok(Self {
            slot_id,
            packet_id: request.packet_id,
            admission_id: request.admission_id,
            lease_id: request.lease_id,
            executor_id: request.executor_id,
            lane: request.lane,
            parallel_group_root: request.parallel_group_root,
            read_conflict_root: request.read_conflict_root,
            write_lock_root: request.write_lock_root,
            scheduled_height: request.scheduled_height,
            expires_height: request
                .scheduled_height
                .saturating_add(config.slot_ttl_blocks),
            max_latency_ms: request.max_latency_ms,
            status: SlotStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_confidential_execution_slot",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "slot_id": self.slot_id,
            "packet_id": self.packet_id,
            "admission_id": self.admission_id,
            "lease_id": self.lease_id,
            "executor_id": self.executor_id,
            "lane": self.lane.as_str(),
            "parallel_group_root": self.parallel_group_root,
            "read_conflict_root": self.read_conflict_root,
            "write_lock_root": self.write_lock_root,
            "scheduled_height": self.scheduled_height,
            "expires_height": self.expires_height,
            "max_latency_ms": self.max_latency_ms,
            "status": self.status.as_str(),
            "scheme": EXECUTION_SLOT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FastExecutionPreconfirmationRequest {
    pub packet_id: String,
    pub slot_id: String,
    pub executor_id: String,
    pub pre_state_root: String,
    pub post_state_commitment: String,
    pub encrypted_receipt_root: String,
    pub fee_charged_micro_units: u64,
    pub observed_latency_ms: u64,
    pub preconfirmed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FastExecutionPreconfirmation {
    pub preconfirmation_id: String,
    pub packet_id: String,
    pub slot_id: String,
    pub executor_id: String,
    pub pre_state_root: String,
    pub post_state_commitment: String,
    pub encrypted_receipt_root: String,
    pub fee_charged_micro_units: u64,
    pub observed_latency_ms: u64,
    pub preconfirmed_height: u64,
    pub finality_height: u64,
    pub status: ReceiptStatus,
}

impl FastExecutionPreconfirmation {
    pub fn from_request(
        config: &Config,
        request: FastExecutionPreconfirmationRequest,
    ) -> Result<Self> {
        ensure_nonempty("packet_id", &request.packet_id)?;
        ensure_nonempty("slot_id", &request.slot_id)?;
        ensure_nonempty("executor_id", &request.executor_id)?;
        ensure_nonempty("pre_state_root", &request.pre_state_root)?;
        ensure_nonempty("post_state_commitment", &request.post_state_commitment)?;
        ensure_nonempty("encrypted_receipt_root", &request.encrypted_receipt_root)?;
        let preconfirmation_id = preconfirmation_id(&request);
        Ok(Self {
            preconfirmation_id,
            packet_id: request.packet_id,
            slot_id: request.slot_id,
            executor_id: request.executor_id,
            pre_state_root: request.pre_state_root,
            post_state_commitment: request.post_state_commitment,
            encrypted_receipt_root: request.encrypted_receipt_root,
            fee_charged_micro_units: request.fee_charged_micro_units,
            observed_latency_ms: request.observed_latency_ms,
            preconfirmed_height: request.preconfirmed_height,
            finality_height: request
                .preconfirmed_height
                .saturating_add(config.receipt_finality_blocks),
            status: ReceiptStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_confidential_execution_preconfirmation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "preconfirmation_id": self.preconfirmation_id,
            "packet_id": self.packet_id,
            "slot_id": self.slot_id,
            "executor_id": self.executor_id,
            "pre_state_root": self.pre_state_root,
            "post_state_commitment": self.post_state_commitment,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "fee_charged_micro_units": self.fee_charged_micro_units,
            "observed_latency_ms": self.observed_latency_ms,
            "preconfirmed_height": self.preconfirmed_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "scheme": PRECONFIRMATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeSponsorRebateRequest {
    pub preconfirmation_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_nullifier: String,
    pub sponsor_policy_root: String,
    pub issued_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeSponsorRebate {
    pub rebate_id: String,
    pub preconfirmation_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_nullifier: String,
    pub sponsor_policy_root: String,
    pub issued_height: u64,
}

impl FeeSponsorRebate {
    pub fn from_request(config: &Config, request: FeeSponsorRebateRequest) -> Result<Self> {
        ensure_nonempty("preconfirmation_id", &request.preconfirmation_id)?;
        ensure_nonempty("sponsor_id", &request.sponsor_id)?;
        ensure_nonempty("beneficiary_commitment", &request.beneficiary_commitment)?;
        ensure_nonempty("rebate_nullifier", &request.rebate_nullifier)?;
        ensure_nonempty("sponsor_policy_root", &request.sponsor_policy_root)?;
        let rebate_micro_units = request
            .fee_paid_micro_units
            .saturating_mul(config.target_rebate_bps)
            / MAX_BPS;
        let rebate_id = rebate_id(&request, rebate_micro_units);
        Ok(Self {
            rebate_id,
            preconfirmation_id: request.preconfirmation_id,
            sponsor_id: request.sponsor_id,
            beneficiary_commitment: request.beneficiary_commitment,
            fee_paid_micro_units: request.fee_paid_micro_units,
            rebate_micro_units,
            rebate_nullifier: request.rebate_nullifier,
            sponsor_policy_root: request.sponsor_policy_root,
            issued_height: request.issued_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_confidential_execution_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "preconfirmation_id": self.preconfirmation_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_nullifier": self.rebate_nullifier,
            "sponsor_policy_root": self.sponsor_policy_root,
            "issued_height": self.issued_height,
            "scheme": FEE_REBATE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeProofAggregationReceiptRequest {
    pub packet_id: String,
    pub preconfirmation_id: String,
    pub aggregator_id: String,
    pub recursive_proof_root: String,
    pub da_commitment_root: String,
    pub proof_fee_micro_units: u64,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeProofAggregationReceipt {
    pub proof_receipt_id: String,
    pub packet_id: String,
    pub preconfirmation_id: String,
    pub aggregator_id: String,
    pub recursive_proof_root: String,
    pub da_commitment_root: String,
    pub proof_fee_micro_units: u64,
    pub settled_height: u64,
    pub status: ReceiptStatus,
}

impl LowFeeProofAggregationReceipt {
    pub fn from_request(request: LowFeeProofAggregationReceiptRequest) -> Result<Self> {
        ensure_nonempty("packet_id", &request.packet_id)?;
        ensure_nonempty("preconfirmation_id", &request.preconfirmation_id)?;
        ensure_nonempty("aggregator_id", &request.aggregator_id)?;
        ensure_nonempty("recursive_proof_root", &request.recursive_proof_root)?;
        ensure_nonempty("da_commitment_root", &request.da_commitment_root)?;
        let proof_receipt_id = proof_receipt_id(&request);
        Ok(Self {
            proof_receipt_id,
            packet_id: request.packet_id,
            preconfirmation_id: request.preconfirmation_id,
            aggregator_id: request.aggregator_id,
            recursive_proof_root: request.recursive_proof_root,
            da_commitment_root: request.da_commitment_root,
            proof_fee_micro_units: request.proof_fee_micro_units,
            settled_height: request.settled_height,
            status: ReceiptStatus::Published,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_confidential_execution_proof_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "proof_receipt_id": self.proof_receipt_id,
            "packet_id": self.packet_id,
            "preconfirmation_id": self.preconfirmation_id,
            "aggregator_id": self.aggregator_id,
            "recursive_proof_root": self.recursive_proof_root,
            "da_commitment_root": self.da_commitment_root,
            "proof_fee_micro_units": self.proof_fee_micro_units,
            "settled_height": self.settled_height,
            "status": self.status.as_str(),
            "scheme": PROOF_RECEIPT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRequest {
    pub subject_id: String,
    pub kind: PrivacyFenceKind,
    pub nullifier: String,
    pub anchor_root: String,
    pub owner_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub subject_id: String,
    pub kind: PrivacyFenceKind,
    pub nullifier: String,
    pub anchor_root: String,
    pub owner_commitment: String,
    pub height: u64,
}

impl PrivacyFence {
    pub fn from_request(request: PrivacyFenceRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("nullifier", &request.nullifier)?;
        ensure_nonempty("anchor_root", &request.anchor_root)?;
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        let fence_id = privacy_fence_id(&request);
        Ok(Self {
            fence_id,
            subject_id: request.subject_id,
            kind: request.kind,
            nullifier: request.nullifier,
            anchor_root: request.anchor_root,
            owner_commitment: request.owner_commitment,
            height: request.height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_execution_privacy_fence",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "fence_id": self.fence_id,
            "subject_id": self.subject_id,
            "fence_kind": self.kind.as_str(),
            "nullifier": self.nullifier,
            "anchor_root": self.anchor_root,
            "owner_commitment": self.owner_commitment,
            "height": self.height,
            "scheme": PRIVACY_FENCE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeEvidenceRequest {
    pub subject_id: String,
    pub offender_id: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub witness_root: String,
    pub challenger_commitment: String,
    pub bond_micro_units: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub subject_id: String,
    pub offender_id: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub witness_root: String,
    pub challenger_commitment: String,
    pub bond_micro_units: u64,
    pub severity_score: u64,
    pub height: u64,
    pub executed: bool,
}

impl ChallengeEvidence {
    pub fn from_request(request: ChallengeEvidenceRequest) -> Result<Self> {
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("offender_id", &request.offender_id)?;
        ensure_nonempty("evidence_root", &request.evidence_root)?;
        ensure_nonempty("witness_root", &request.witness_root)?;
        ensure_nonempty("challenger_commitment", &request.challenger_commitment)?;
        let challenge_id = challenge_id(&request);
        Ok(Self {
            challenge_id,
            subject_id: request.subject_id,
            offender_id: request.offender_id,
            kind: request.kind,
            evidence_root: request.evidence_root,
            witness_root: request.witness_root,
            challenger_commitment: request.challenger_commitment,
            bond_micro_units: request.bond_micro_units,
            severity_score: request.kind.severity_score(),
            height: request.height,
            executed: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_execution_challenge_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "subject_id": self.subject_id,
            "offender_id": self.offender_id,
            "challenge_kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "challenger_commitment": self.challenger_commitment,
            "bond_micro_units": self.bond_micro_units,
            "severity_score": self.severity_score,
            "height": self.height,
            "executed": self.executed,
            "scheme": CHALLENGE_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub packets: BTreeMap<String, EncryptedCallPacket>,
    pub admissions: BTreeMap<String, PqSequencerAdmission>,
    pub witness_leases: BTreeMap<String, ConfidentialWitnessLease>,
    pub execution_slots: BTreeMap<String, ParallelExecutionSlot>,
    pub preconfirmations: BTreeMap<String, FastExecutionPreconfirmation>,
    pub rebates: BTreeMap<String, FeeSponsorRebate>,
    pub proof_receipts: BTreeMap<String, LowFeeProofAggregationReceipt>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            packets: BTreeMap::new(),
            admissions: BTreeMap::new(),
            witness_leases: BTreeMap::new(),
            execution_slots: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn with_config(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            ..Self::devnet()
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn submit_packet(
        &mut self,
        request: EncryptedCallPacketRequest,
    ) -> Result<EncryptedCallPacket> {
        ensure_capacity("packets", self.packets.len(), self.config.max_packets)?;
        if self.spent_nullifiers.contains(&request.packet_nullifier) {
            return Err("packet nullifier already spent".to_string());
        }
        let packet = EncryptedCallPacket::from_request(&self.config, request)?;
        ensure_absent("packet", &self.packets, &packet.packet_id)?;
        self.spent_nullifiers
            .insert(packet.packet_nullifier.clone());
        self.counters.next_packet = self.counters.next_packet.saturating_add(1);
        self.packets
            .insert(packet.packet_id.clone(), packet.clone());
        self.recompute_roots();
        Ok(packet)
    }

    pub fn admit_packet(
        &mut self,
        request: PqSequencerAdmissionRequest,
    ) -> Result<PqSequencerAdmission> {
        ensure_capacity(
            "admissions",
            self.admissions.len(),
            self.config.max_admissions,
        )?;
        let admission = PqSequencerAdmission::from_request(&self.config, request)?;
        let packet = self
            .packets
            .get_mut(&admission.packet_id)
            .ok_or_else(|| format!("unknown packet_id {}", admission.packet_id))?;
        if !packet.status.can_admit() {
            return Err("packet cannot be admitted from current status".to_string());
        }
        ensure_absent("admission", &self.admissions, &admission.admission_id)?;
        packet.status = ConfidentialPacketStatus::Admitted;
        self.counters.next_admission = self.counters.next_admission.saturating_add(1);
        self.admissions
            .insert(admission.admission_id.clone(), admission.clone());
        self.recompute_roots();
        Ok(admission)
    }

    pub fn lease_witness(
        &mut self,
        request: ConfidentialWitnessLeaseRequest,
    ) -> Result<ConfidentialWitnessLease> {
        ensure_capacity(
            "witness_leases",
            self.witness_leases.len(),
            self.config.max_witness_leases,
        )?;
        let lease = ConfidentialWitnessLease::from_request(&self.config, request)?;
        ensure_known("admission", &self.admissions, &lease.admission_id)?;
        let packet = self
            .packets
            .get_mut(&lease.packet_id)
            .ok_or_else(|| format!("unknown packet_id {}", lease.packet_id))?;
        if !packet.status.can_schedule() {
            return Err("packet is not eligible for witness lease".to_string());
        }
        ensure_absent("witness_lease", &self.witness_leases, &lease.lease_id)?;
        packet.status = ConfidentialPacketStatus::Leased;
        self.counters.next_witness_lease = self.counters.next_witness_lease.saturating_add(1);
        self.witness_leases
            .insert(lease.lease_id.clone(), lease.clone());
        self.recompute_roots();
        Ok(lease)
    }

    pub fn reserve_execution_slot(
        &mut self,
        request: ParallelExecutionSlotRequest,
    ) -> Result<ParallelExecutionSlot> {
        ensure_capacity(
            "execution_slots",
            self.execution_slots.len(),
            self.config.max_execution_slots,
        )?;
        let slot = ParallelExecutionSlot::from_request(&self.config, request)?;
        ensure_known("admission", &self.admissions, &slot.admission_id)?;
        if let Some(lease_id) = &slot.lease_id {
            let lease = self
                .witness_leases
                .get_mut(lease_id)
                .ok_or_else(|| format!("unknown lease_id {}", lease_id))?;
            lease.status = WitnessLeaseStatus::Bound;
        }
        let packet = self
            .packets
            .get_mut(&slot.packet_id)
            .ok_or_else(|| format!("unknown packet_id {}", slot.packet_id))?;
        if !packet.status.can_schedule() {
            return Err("packet is not eligible for execution scheduling".to_string());
        }
        ensure_absent("execution_slot", &self.execution_slots, &slot.slot_id)?;
        packet.status = ConfidentialPacketStatus::Scheduled;
        self.counters.next_execution_slot = self.counters.next_execution_slot.saturating_add(1);
        self.execution_slots
            .insert(slot.slot_id.clone(), slot.clone());
        self.recompute_roots();
        Ok(slot)
    }

    pub fn issue_preconfirmation(
        &mut self,
        request: FastExecutionPreconfirmationRequest,
    ) -> Result<FastExecutionPreconfirmation> {
        ensure_capacity(
            "preconfirmations",
            self.preconfirmations.len(),
            self.config.max_preconfirmations,
        )?;
        let preconfirmation = FastExecutionPreconfirmation::from_request(&self.config, request)?;
        let slot = self
            .execution_slots
            .get_mut(&preconfirmation.slot_id)
            .ok_or_else(|| format!("unknown slot_id {}", preconfirmation.slot_id))?;
        if slot.packet_id != preconfirmation.packet_id {
            return Err("preconfirmation packet_id does not match execution slot".to_string());
        }
        let packet = self
            .packets
            .get_mut(&preconfirmation.packet_id)
            .ok_or_else(|| format!("unknown packet_id {}", preconfirmation.packet_id))?;
        ensure_absent(
            "preconfirmation",
            &self.preconfirmations,
            &preconfirmation.preconfirmation_id,
        )?;
        slot.status = SlotStatus::Preconfirmed;
        packet.status = ConfidentialPacketStatus::Preconfirmed;
        self.counters.next_preconfirmation = self.counters.next_preconfirmation.saturating_add(1);
        self.preconfirmations.insert(
            preconfirmation.preconfirmation_id.clone(),
            preconfirmation.clone(),
        );
        self.recompute_roots();
        Ok(preconfirmation)
    }

    pub fn issue_rebate(&mut self, request: FeeSponsorRebateRequest) -> Result<FeeSponsorRebate> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        if self.spent_nullifiers.contains(&request.rebate_nullifier) {
            return Err("rebate nullifier already spent".to_string());
        }
        ensure_known(
            "preconfirmation",
            &self.preconfirmations,
            &request.preconfirmation_id,
        )?;
        let rebate = FeeSponsorRebate::from_request(&self.config, request)?;
        ensure_absent("rebate", &self.rebates, &rebate.rebate_id)?;
        self.spent_nullifiers
            .insert(rebate.rebate_nullifier.clone());
        self.counters.next_rebate = self.counters.next_rebate.saturating_add(1);
        self.rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        self.recompute_roots();
        Ok(rebate)
    }

    pub fn publish_proof_receipt(
        &mut self,
        request: LowFeeProofAggregationReceiptRequest,
    ) -> Result<LowFeeProofAggregationReceipt> {
        ensure_capacity(
            "proof_receipts",
            self.proof_receipts.len(),
            self.config.max_proof_receipts,
        )?;
        ensure_known(
            "preconfirmation",
            &self.preconfirmations,
            &request.preconfirmation_id,
        )?;
        let receipt = LowFeeProofAggregationReceipt::from_request(request)?;
        let packet = self
            .packets
            .get_mut(&receipt.packet_id)
            .ok_or_else(|| format!("unknown packet_id {}", receipt.packet_id))?;
        packet.status = ConfidentialPacketStatus::Proven;
        ensure_absent(
            "proof_receipt",
            &self.proof_receipts,
            &receipt.proof_receipt_id,
        )?;
        self.counters.next_proof_receipt = self.counters.next_proof_receipt.saturating_add(1);
        self.proof_receipts
            .insert(receipt.proof_receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn insert_privacy_fence(&mut self, request: PrivacyFenceRequest) -> Result<PrivacyFence> {
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        if self.spent_nullifiers.contains(&request.nullifier) {
            return Err("privacy fence nullifier already spent".to_string());
        }
        let fence = PrivacyFence::from_request(request)?;
        ensure_absent("privacy_fence", &self.privacy_fences, &fence.fence_id)?;
        self.spent_nullifiers.insert(fence.nullifier.clone());
        self.counters.next_privacy_fence = self.counters.next_privacy_fence.saturating_add(1);
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.recompute_roots();
        Ok(fence)
    }

    pub fn file_challenge(
        &mut self,
        request: ChallengeEvidenceRequest,
    ) -> Result<ChallengeEvidence> {
        ensure_capacity(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        let challenge = ChallengeEvidence::from_request(request)?;
        ensure_absent("challenge", &self.challenges, &challenge.challenge_id)?;
        if let Some(packet) = self.packets.get_mut(&challenge.subject_id) {
            packet.status = ConfidentialPacketStatus::Challenged;
        }
        if let Some(slot) = self.execution_slots.get_mut(&challenge.subject_id) {
            slot.status = SlotStatus::Challenged;
        }
        self.counters.next_challenge = self.counters.next_challenge.saturating_add(1);
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        self.recompute_roots();
        Ok(challenge)
    }

    pub fn finalize_preconfirmation(&mut self, preconfirmation_id: &str) -> Result<()> {
        let preconfirmation = self
            .preconfirmations
            .get_mut(preconfirmation_id)
            .ok_or_else(|| format!("unknown preconfirmation_id {}", preconfirmation_id))?;
        preconfirmation.status = ReceiptStatus::Finalized;
        if let Some(slot) = self.execution_slots.get_mut(&preconfirmation.slot_id) {
            slot.status = SlotStatus::Settled;
        }
        if let Some(packet) = self.packets.get_mut(&preconfirmation.packet_id) {
            packet.status = ConfidentialPacketStatus::Settled;
        }
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: record_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: record_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-COUNTERS",
                &self.counters.public_record(),
            ),
            packet_root: map_root("FAST-PQ-CONFIDENTIAL-EXECUTION-PACKETS", &self.packets),
            admission_root: map_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-ADMISSIONS",
                &self.admissions,
            ),
            witness_lease_root: map_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-WITNESS-LEASES",
                &self.witness_leases,
            ),
            execution_slot_root: map_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-SLOTS",
                &self.execution_slots,
            ),
            preconfirmation_root: map_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-PRECONFIRMATIONS",
                &self.preconfirmations,
            ),
            rebate_root: map_root("FAST-PQ-CONFIDENTIAL-EXECUTION-REBATES", &self.rebates),
            proof_receipt_root: map_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-PROOF-RECEIPTS",
                &self.proof_receipts,
            ),
            privacy_fence_root: map_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-PRIVACY-FENCES",
                &self.privacy_fences,
            ),
            challenge_root: map_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-CHALLENGES",
                &self.challenges,
            ),
            spent_nullifier_root: set_root(
                "FAST-PQ-CONFIDENTIAL-EXECUTION-SPENT-NULLIFIERS",
                &self.spent_nullifiers,
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_execution_lane_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "packet_count": self.packets.len(),
            "admission_count": self.admissions.len(),
            "witness_lease_count": self.witness_leases.len(),
            "execution_slot_count": self.execution_slots.len(),
            "preconfirmation_count": self.preconfirmations.len(),
            "rebate_count": self.rebates.len(),
            "proof_receipt_count": self.proof_receipts.len(),
            "privacy_fence_count": self.privacy_fences.len(),
            "challenge_count": self.challenges.len(),
            "spent_nullifier_count": self.spent_nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_fast_pq_confidential_execution_lane_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_fast_pq_confidential_execution_lane_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn packet_id(request: &EncryptedCallPacketRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.contract_namespace),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.encrypted_calldata_root),
            HashPart::Str(&request.call_graph_root),
            HashPart::Str(&request.packet_nullifier),
            HashPart::U64(request.submitted_height),
        ],
        32,
    )
}

pub fn admission_id(request: &PqSequencerAdmissionRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-ADMISSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.packet_id),
            HashPart::Str(&request.sequencer_id),
            HashPart::Str(&request.committee_id),
            HashPart::U64(request.admission_round),
            HashPart::Str(&request.admitted_payload_root),
            HashPart::Str(&request.pq_signature_root),
        ],
        32,
    )
}

pub fn witness_lease_id(request: &ConfidentialWitnessLeaseRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-WITNESS-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.packet_id),
            HashPart::Str(&request.admission_id),
            HashPart::Str(&request.witness_provider_id),
            HashPart::Str(&request.encrypted_witness_root),
            HashPart::Str(&request.witness_policy_root),
            HashPart::U64(request.lease_height),
        ],
        32,
    )
}

pub fn execution_slot_id(request: &ParallelExecutionSlotRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.packet_id),
            HashPart::Str(&request.admission_id),
            HashPart::Str(request.lease_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.executor_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.parallel_group_root),
            HashPart::Str(&request.write_lock_root),
            HashPart::U64(request.scheduled_height),
        ],
        32,
    )
}

pub fn preconfirmation_id(request: &FastExecutionPreconfirmationRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-PRECONFIRMATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.packet_id),
            HashPart::Str(&request.slot_id),
            HashPart::Str(&request.executor_id),
            HashPart::Str(&request.pre_state_root),
            HashPart::Str(&request.post_state_commitment),
            HashPart::Str(&request.encrypted_receipt_root),
            HashPart::U64(request.preconfirmed_height),
        ],
        32,
    )
}

pub fn rebate_id(request: &FeeSponsorRebateRequest, rebate_micro_units: u64) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.preconfirmation_id),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::U64(request.fee_paid_micro_units),
            HashPart::U64(rebate_micro_units),
            HashPart::U64(request.issued_height),
        ],
        32,
    )
}

pub fn proof_receipt_id(request: &LowFeeProofAggregationReceiptRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-PROOF-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.packet_id),
            HashPart::Str(&request.preconfirmation_id),
            HashPart::Str(&request.aggregator_id),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::Str(&request.da_commitment_root),
            HashPart::U64(request.proof_fee_micro_units),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &PrivacyFenceRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.anchor_root),
            HashPart::Str(&request.owner_commitment),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn challenge_id(request: &ChallengeEvidenceRequest) -> String {
    domain_hash(
        "FAST-PQ-CONFIDENTIAL-EXECUTION-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.offender_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.witness_root),
            HashPart::Str(&request.challenger_commitment),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn packet_priority_score(
    lane: ExecutionLaneKind,
    privacy_set_size: u64,
    max_fee_micro_units: u64,
    fee_cap_bps: u64,
) -> u64 {
    let privacy_score = privacy_set_size.min(1_048_576) / 512;
    let fee_score = max_fee_micro_units.min(10_000_000) / 5_000;
    let low_fee_bonus = 100_u64.saturating_sub(fee_cap_bps.min(100));
    lane.priority_weight()
        .saturating_add(privacy_score)
        .saturating_add(fee_score)
        .saturating_add(low_fee_bonus)
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("FAST-PQ-CONFIDENTIAL-EXECUTION-STATE-ROOT", record)
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"})),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

pub fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

pub fn ensure_known<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("unknown {label} {key}"))
    }
}
