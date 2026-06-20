use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialProofStreamMultiplexerRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PROOF_STREAM_MULTIPLEXER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-proof-stream-multiplexer-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PROOF_STREAM_MULTIPLEXER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_STREAM_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-proof-stream-multiplexer-v1";
pub const RECURSIVE_FRAGMENT_SUITE: &str =
    "nova-pq-confidential-recursive-proof-fragment-stream-v1";
pub const ENCRYPTED_WITNESS_CHUNK_SUITE: &str =
    "ml-kem-sealed-confidential-witness-chunk-stream-v1";
pub const PRECONFIRMATION_ROOT_SUITE: &str =
    "deterministic-confidential-preconfirmation-root-multiplex-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-confidential-proof-multiplex-rebate-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_920_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_620_000;
pub const DEVNET_EPOCH: u64 = 18_944;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 25;
pub const DEFAULT_TARGET_MUX_LATENCY_MS: u64 = 90;
pub const DEFAULT_HARD_MUX_LATENCY_MS: u64 = 450;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS: u64 = 8_300;
pub const DEFAULT_BACKPRESSURE_LOW_WATERMARK_BPS: u64 = 5_700;
pub const DEFAULT_MIN_LANE_BOND_MICRO_UNITS: u64 = 35_000_000;
pub const DEFAULT_MIN_PROVER_BOND_MICRO_UNITS: u64 = 75_000_000;
pub const DEFAULT_MAX_PROOF_LANES: usize = 65_536;
pub const DEFAULT_MAX_PROVER_STREAMS: usize = 262_144;
pub const DEFAULT_MAX_RECURSIVE_FRAGMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_WITNESS_CHUNKS: usize = 2_097_152;
pub const DEFAULT_MAX_PRECONFIRMATION_ROOTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATES: usize = 1_048_576;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:ROOTS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:LANES";
const D_STREAMS: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:STREAMS";
const D_FRAGMENTS: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:FRAGMENTS";
const D_CHUNKS: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:CHUNKS";
const D_PRECONFIRMATIONS: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:PRECONFIRMATIONS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:ATTESTATIONS";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:REBATES";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:PUBLIC";
const D_STATE: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:STATE";
const D_STABLE_ID: &str = "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:STABLE-ID";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLaneClass {
    Instant,
    Fast,
    Recursive,
    Witness,
    LowFeeBulk,
    Watchtower,
}

impl ProofLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Recursive => "recursive",
            Self::Witness => "witness",
            Self::LowFeeBulk => "low_fee_bulk",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Backpressured,
    SheddingLowFee,
    Draining,
    Suspended,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Backpressured => "backpressured",
            Self::SheddingLowFee => "shedding_low_fee",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Announced,
    Active,
    Multiplexing,
    Preconfirmed,
    Settled,
    Quarantined,
}

impl StreamStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Active => "active",
            Self::Multiplexing => "multiplexing",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Throttle,
    Quarantine,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Hold => "hold",
            Self::Throttle => "throttle",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub mode: RuntimeMode,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_stream_attestation_suite: String,
    pub recursive_fragment_suite: String,
    pub encrypted_witness_chunk_suite: String,
    pub preconfirmation_root_suite: String,
    pub low_fee_rebate_suite: String,
    pub min_pq_security_bits: u16,
    pub slot_width_ms: u64,
    pub target_mux_latency_ms: u64,
    pub hard_mux_latency_ms: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub backpressure_high_watermark_bps: u64,
    pub backpressure_low_watermark_bps: u64,
    pub min_lane_bond_micro_units: u64,
    pub min_prover_bond_micro_units: u64,
    pub enable_low_fee_rebates: bool,
    pub enable_preconfirmation_roots: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            mode: RuntimeMode::Devnet,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_stream_attestation_suite: PQ_STREAM_ATTESTATION_SUITE.to_string(),
            recursive_fragment_suite: RECURSIVE_FRAGMENT_SUITE.to_string(),
            encrypted_witness_chunk_suite: ENCRYPTED_WITNESS_CHUNK_SUITE.to_string(),
            preconfirmation_root_suite: PRECONFIRMATION_ROOT_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_mux_latency_ms: DEFAULT_TARGET_MUX_LATENCY_MS,
            hard_mux_latency_ms: DEFAULT_HARD_MUX_LATENCY_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            backpressure_high_watermark_bps: DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS,
            backpressure_low_watermark_bps: DEFAULT_BACKPRESSURE_LOW_WATERMARK_BPS,
            min_lane_bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            min_prover_bond_micro_units: DEFAULT_MIN_PROVER_BOND_MICRO_UNITS,
            enable_low_fee_rebates: true,
            enable_preconfirmation_roots: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_proof_stream_multiplexer_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "mode": self.mode.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_stream_attestation_suite": self.pq_stream_attestation_suite,
            "recursive_fragment_suite": self.recursive_fragment_suite,
            "encrypted_witness_chunk_suite": self.encrypted_witness_chunk_suite,
            "preconfirmation_root_suite": self.preconfirmation_root_suite,
            "low_fee_rebate_suite": self.low_fee_rebate_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "slot_width_ms": self.slot_width_ms,
            "target_mux_latency_ms": self.target_mux_latency_ms,
            "hard_mux_latency_ms": self.hard_mux_latency_ms,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "backpressure_high_watermark_bps": self.backpressure_high_watermark_bps,
            "backpressure_low_watermark_bps": self.backpressure_low_watermark_bps,
            "min_lane_bond_micro_units": self.min_lane_bond_micro_units,
            "min_prover_bond_micro_units": self.min_prover_bond_micro_units,
            "enable_low_fee_rebates": self.enable_low_fee_rebates,
            "enable_preconfirmation_roots": self.enable_preconfirmation_roots,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub proof_lanes: u64,
    pub prover_streams: u64,
    pub recursive_proof_fragments: u64,
    pub encrypted_witness_chunks: u64,
    pub preconfirmation_roots: u64,
    pub pq_stream_attestations: u64,
    pub low_fee_multiplex_rebates: u64,
    pub public_records: u64,
    pub active_streams: u64,
    pub backpressured_lanes: u64,
    pub total_witness_bytes: u64,
    pub total_rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub proof_lanes_root: String,
    pub prover_streams_root: String,
    pub recursive_proof_fragments_root: String,
    pub encrypted_witness_chunks_root: String,
    pub preconfirmation_roots_root: String,
    pub pq_stream_attestations_root: String,
    pub low_fee_multiplex_rebates_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_proof_stream_multiplexer_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "proof_lanes_root": self.proof_lanes_root,
            "prover_streams_root": self.prover_streams_root,
            "recursive_proof_fragments_root": self.recursive_proof_fragments_root,
            "encrypted_witness_chunks_root": self.encrypted_witness_chunks_root,
            "preconfirmation_roots_root": self.preconfirmation_roots_root,
            "pq_stream_attestations_root": self.pq_stream_attestations_root,
            "low_fee_multiplex_rebates_root": self.low_fee_multiplex_rebates_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofLane {
    pub lane_id: String,
    pub lane_class: ProofLaneClass,
    pub status: LaneStatus,
    pub capacity_weight: u64,
    pub queued_fragments: u64,
    pub backpressure_bps: u64,
    pub bond_micro_units: u64,
    pub deterministic_lane_root: String,
}

impl ProofLane {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_lane",
            "lane_id": self.lane_id,
            "lane_class": self.lane_class.as_str(),
            "status": self.status.as_str(),
            "capacity_weight": self.capacity_weight,
            "queued_fragments": self.queued_fragments,
            "backpressure_bps": self.backpressure_bps,
            "bond_micro_units": self.bond_micro_units,
            "deterministic_lane_root": self.deterministic_lane_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverStream {
    pub stream_id: String,
    pub lane_id: String,
    pub prover_commitment: String,
    pub status: StreamStatus,
    pub priority_score: u64,
    pub fee_cap_bps: u64,
    pub fragments_expected: u64,
    pub witness_chunks_expected: u64,
    pub stream_root: String,
}

impl ProverStream {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_stream",
            "stream_id": self.stream_id,
            "lane_id": self.lane_id,
            "prover_commitment": self.prover_commitment,
            "status": self.status.as_str(),
            "priority_score": self.priority_score,
            "fee_cap_bps": self.fee_cap_bps,
            "fragments_expected": self.fragments_expected,
            "witness_chunks_expected": self.witness_chunks_expected,
            "stream_root": self.stream_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofFragment {
    pub fragment_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub parent_fragment_root: String,
    pub recursive_commitment: String,
    pub proof_bytes: u64,
    pub ready_for_wrap: bool,
}

impl RecursiveProofFragment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_fragment",
            "fragment_id": self.fragment_id,
            "stream_id": self.stream_id,
            "sequence": self.sequence,
            "parent_fragment_root": self.parent_fragment_root,
            "recursive_commitment": self.recursive_commitment,
            "proof_bytes": self.proof_bytes,
            "ready_for_wrap": self.ready_for_wrap,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedWitnessChunk {
    pub chunk_id: String,
    pub stream_id: String,
    pub chunk_sequence: u64,
    pub encrypted_chunk_commitment: String,
    pub chunk_bytes: u64,
    pub pq_envelope_root: String,
}

impl EncryptedWitnessChunk {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_witness_chunk",
            "chunk_id": self.chunk_id,
            "stream_id": self.stream_id,
            "chunk_sequence": self.chunk_sequence,
            "encrypted_chunk_commitment": self.encrypted_chunk_commitment,
            "chunk_bytes": self.chunk_bytes,
            "pq_envelope_root": self.pq_envelope_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationRoot {
    pub preconfirmation_id: String,
    pub stream_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub lane_root: String,
    pub proof_stream_root: String,
    pub deterministic_root: String,
}

impl PreconfirmationRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_root",
            "preconfirmation_id": self.preconfirmation_id,
            "stream_id": self.stream_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "lane_root": self.lane_root,
            "proof_stream_root": self.proof_stream_root,
            "deterministic_root": self.deterministic_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqStreamAttestation {
    pub attestation_id: String,
    pub stream_id: String,
    pub attestor_committee_root: String,
    pub verdict: AttestationVerdict,
    pub attested_latency_ms: u64,
    pub pq_signature_root: String,
}

impl PqStreamAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_stream_attestation",
            "attestation_id": self.attestation_id,
            "stream_id": self.stream_id,
            "attestor_committee_root": self.attestor_committee_root,
            "verdict": self.verdict.as_str(),
            "attested_latency_ms": self.attested_latency_ms,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeMultiplexRebate {
    pub rebate_id: String,
    pub stream_id: String,
    pub lane_id: String,
    pub beneficiary_commitment: String,
    pub rebate_micro_units: u64,
    pub settlement_root: String,
}

impl LowFeeMultiplexRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_multiplex_rebate",
            "rebate_id": self.rebate_id,
            "stream_id": self.stream_id,
            "lane_id": self.lane_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_micro_units": self.rebate_micro_units,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub proof_lanes: BTreeMap<String, ProofLane>,
    pub prover_streams: BTreeMap<String, ProverStream>,
    pub recursive_proof_fragments: BTreeMap<String, RecursiveProofFragment>,
    pub encrypted_witness_chunks: BTreeMap<String, EncryptedWitnessChunk>,
    pub preconfirmation_roots: BTreeMap<String, PreconfirmationRoot>,
    pub pq_stream_attestations: BTreeMap<String, PqStreamAttestation>,
    pub low_fee_multiplex_rebates: BTreeMap<String, LowFeeMultiplexRebate>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            proof_lanes: BTreeMap::new(),
            prover_streams: BTreeMap::new(),
            recursive_proof_fragments: BTreeMap::new(),
            encrypted_witness_chunks: BTreeMap::new(),
            preconfirmation_roots: BTreeMap::new(),
            pq_stream_attestations: BTreeMap::new(),
            low_fee_multiplex_rebates: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.install_devnet_fixtures();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_proof_stream_multiplexer_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "devnet_l2_height": DEVNET_L2_HEIGHT,
            "devnet_monero_height": DEVNET_MONERO_HEIGHT,
            "devnet_epoch": DEVNET_EPOCH,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "proof_lanes": public_map(&self.proof_lanes),
            "prover_streams": public_map(&self.prover_streams),
            "recursive_proof_fragments": public_map(&self.recursive_proof_fragments),
            "encrypted_witness_chunks": public_map(&self.encrypted_witness_chunks),
            "preconfirmation_roots": public_map(&self.preconfirmation_roots),
            "pq_stream_attestations": public_map(&self.pq_stream_attestations),
            "low_fee_multiplex_rebates": public_map(&self.low_fee_multiplex_rebates),
            "public_records": self.public_records,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        self.counters = Counters {
            proof_lanes: self.proof_lanes.len() as u64,
            prover_streams: self.prover_streams.len() as u64,
            recursive_proof_fragments: self.recursive_proof_fragments.len() as u64,
            encrypted_witness_chunks: self.encrypted_witness_chunks.len() as u64,
            preconfirmation_roots: self.preconfirmation_roots.len() as u64,
            pq_stream_attestations: self.pq_stream_attestations.len() as u64,
            low_fee_multiplex_rebates: self.low_fee_multiplex_rebates.len() as u64,
            public_records: self.public_records.len() as u64,
            active_streams: self
                .prover_streams
                .values()
                .filter(|stream| {
                    matches!(
                        stream.status,
                        StreamStatus::Active
                            | StreamStatus::Multiplexing
                            | StreamStatus::Preconfirmed
                    )
                })
                .count() as u64,
            backpressured_lanes: self
                .proof_lanes
                .values()
                .filter(|lane| {
                    matches!(
                        lane.status,
                        LaneStatus::Backpressured | LaneStatus::SheddingLowFee
                    )
                })
                .count() as u64,
            total_witness_bytes: self
                .encrypted_witness_chunks
                .values()
                .map(|chunk| chunk.chunk_bytes)
                .sum(),
            total_rebate_micro_units: self
                .low_fee_multiplex_rebates
                .values()
                .map(|rebate| rebate.rebate_micro_units)
                .sum(),
        };
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            proof_lanes_root: values_root(D_LANES, &self.proof_lanes),
            prover_streams_root: values_root(D_STREAMS, &self.prover_streams),
            recursive_proof_fragments_root: values_root(
                D_FRAGMENTS,
                &self.recursive_proof_fragments,
            ),
            encrypted_witness_chunks_root: values_root(D_CHUNKS, &self.encrypted_witness_chunks),
            preconfirmation_roots_root: values_root(
                D_PRECONFIRMATIONS,
                &self.preconfirmation_roots,
            ),
            pq_stream_attestations_root: values_root(D_ATTESTATIONS, &self.pq_stream_attestations),
            low_fee_multiplex_rebates_root: values_root(D_REBATES, &self.low_fee_multiplex_rebates),
            public_record_root: value_map_root(D_PUBLIC, &self.public_records),
        };
    }

    fn install_devnet_fixtures(&mut self) {
        let instant_lane_root = deterministic_root("lane", "instant-proof", 0);
        let low_fee_lane_root = deterministic_root("lane", "low-fee-bulk", 1);
        let stream_root = deterministic_root("stream", "gpu-prover-a", 0);
        let fragment_root = deterministic_root("recursive-fragment", &stream_root, 0);
        let witness_root = deterministic_root("witness-chunk", &stream_root, 0);

        let instant_lane = ProofLane {
            lane_id: stable_id("lane", &json!({"name": "instant-proof", "sequence": 0})),
            lane_class: ProofLaneClass::Instant,
            status: LaneStatus::Open,
            capacity_weight: 9_600,
            queued_fragments: 3,
            backpressure_bps: 2_100,
            bond_micro_units: self.config.min_lane_bond_micro_units,
            deterministic_lane_root: instant_lane_root.clone(),
        };
        let low_fee_lane = ProofLane {
            lane_id: stable_id("lane", &json!({"name": "low-fee-bulk", "sequence": 1})),
            lane_class: ProofLaneClass::LowFeeBulk,
            status: LaneStatus::SheddingLowFee,
            capacity_weight: 4_200,
            queued_fragments: 89,
            backpressure_bps: 8_700,
            bond_micro_units: self.config.min_lane_bond_micro_units,
            deterministic_lane_root: low_fee_lane_root,
        };
        let stream = ProverStream {
            stream_id: stable_id("stream", &json!({"prover": "gpu-prover-a", "sequence": 0})),
            lane_id: instant_lane.lane_id.clone(),
            prover_commitment: deterministic_root("prover-commitment", "gpu-prover-a", 0),
            status: StreamStatus::Multiplexing,
            priority_score: 9_480,
            fee_cap_bps: 9,
            fragments_expected: 4,
            witness_chunks_expected: 2,
            stream_root: stream_root.clone(),
        };
        let fragment = RecursiveProofFragment {
            fragment_id: stable_id(
                "fragment",
                &json!({"stream": stream.stream_id, "sequence": 0}),
            ),
            stream_id: stream.stream_id.clone(),
            sequence: 0,
            parent_fragment_root: fragment_root.clone(),
            recursive_commitment: deterministic_root("recursive-commitment", &fragment_root, 0),
            proof_bytes: 65_536,
            ready_for_wrap: true,
        };
        let chunk = EncryptedWitnessChunk {
            chunk_id: stable_id(
                "witness-chunk",
                &json!({"stream": stream.stream_id, "sequence": 0}),
            ),
            stream_id: stream.stream_id.clone(),
            chunk_sequence: 0,
            encrypted_chunk_commitment: deterministic_root("encrypted-witness", &witness_root, 0),
            chunk_bytes: 131_072,
            pq_envelope_root: witness_root,
        };
        let preconfirmation = PreconfirmationRoot {
            preconfirmation_id: stable_id("preconfirmation", &json!({"stream": stream.stream_id})),
            stream_id: stream.stream_id.clone(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            lane_root: instant_lane_root,
            proof_stream_root: stream_root.clone(),
            deterministic_root: deterministic_root("preconfirmation", &stream_root, DEVNET_EPOCH),
        };
        let attestation = PqStreamAttestation {
            attestation_id: stable_id("attestation", &json!({"stream": stream.stream_id})),
            stream_id: stream.stream_id.clone(),
            attestor_committee_root: deterministic_root("attestor-committee", "devnet-fast-pq", 0),
            verdict: AttestationVerdict::Include,
            attested_latency_ms: 72,
            pq_signature_root: deterministic_root("pq-signature", &stream_root, 0),
        };
        let rebate = LowFeeMultiplexRebate {
            rebate_id: stable_id(
                "rebate",
                &json!({"stream": stream.stream_id, "lane": low_fee_lane.lane_id}),
            ),
            stream_id: stream.stream_id.clone(),
            lane_id: low_fee_lane.lane_id.clone(),
            beneficiary_commitment: deterministic_root("rebate-beneficiary", "low-fee-wallet", 0),
            rebate_micro_units: 42_000,
            settlement_root: deterministic_root("rebate-settlement", &stream_root, 0),
        };

        self.record_public(
            format!("proof_lane:{}", instant_lane.lane_id),
            instant_lane.public_record(),
        );
        self.record_public(
            format!("proof_lane:{}", low_fee_lane.lane_id),
            low_fee_lane.public_record(),
        );
        self.record_public(
            format!("prover_stream:{}", stream.stream_id),
            stream.public_record(),
        );
        self.record_public(
            format!("recursive_proof_fragment:{}", fragment.fragment_id),
            fragment.public_record(),
        );
        self.record_public(
            format!("encrypted_witness_chunk:{}", chunk.chunk_id),
            chunk.public_record(),
        );
        self.record_public(
            format!(
                "preconfirmation_root:{}",
                preconfirmation.preconfirmation_id
            ),
            preconfirmation.public_record(),
        );
        self.record_public(
            format!("pq_stream_attestation:{}", attestation.attestation_id),
            attestation.public_record(),
        );
        self.record_public(
            format!("low_fee_multiplex_rebate:{}", rebate.rebate_id),
            rebate.public_record(),
        );

        self.proof_lanes
            .insert(instant_lane.lane_id.clone(), instant_lane);
        self.proof_lanes
            .insert(low_fee_lane.lane_id.clone(), low_fee_lane);
        self.prover_streams.insert(stream.stream_id.clone(), stream);
        self.recursive_proof_fragments
            .insert(fragment.fragment_id.clone(), fragment);
        self.encrypted_witness_chunks
            .insert(chunk.chunk_id.clone(), chunk);
        self.preconfirmation_roots
            .insert(preconfirmation.preconfirmation_id.clone(), preconfirmation);
        self.pq_stream_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.low_fee_multiplex_rebates
            .insert(rebate.rebate_id.clone(), rebate);
    }

    fn record_public(&mut self, key: String, record: Value) {
        self.public_records.insert(key, record);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn state_root_from_public_record(record: &Value) -> String {
    record_root(D_STATE, record)
}

fn stable_id(kind: &str, record: &Value) -> String {
    domain_hash(
        D_STABLE_ID,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        20,
    )
}

fn deterministic_root(label: &str, value: &str, sequence: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-PROOF-STREAM-MUX:DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn values_root<T>(domain: &str, values: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn value_map_root(domain: &str, values: &BTreeMap<String, Value>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn public_map<T>(values: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    values.values().map(PublicRecord::public_record).collect()
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for ProofLane {
    fn public_record(&self) -> Value {
        ProofLane::public_record(self)
    }
}

impl PublicRecord for ProverStream {
    fn public_record(&self) -> Value {
        ProverStream::public_record(self)
    }
}

impl PublicRecord for RecursiveProofFragment {
    fn public_record(&self) -> Value {
        RecursiveProofFragment::public_record(self)
    }
}

impl PublicRecord for EncryptedWitnessChunk {
    fn public_record(&self) -> Value {
        EncryptedWitnessChunk::public_record(self)
    }
}

impl PublicRecord for PreconfirmationRoot {
    fn public_record(&self) -> Value {
        PreconfirmationRoot::public_record(self)
    }
}

impl PublicRecord for PqStreamAttestation {
    fn public_record(&self) -> Value {
        PqStreamAttestation::public_record(self)
    }
}

impl PublicRecord for LowFeeMultiplexRebate {
    fn public_record(&self) -> Value {
        LowFeeMultiplexRebate::public_record(self)
    }
}
