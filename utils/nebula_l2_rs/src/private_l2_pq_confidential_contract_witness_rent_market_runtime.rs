use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-witness-rent-market-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_PQ_ATTESTATION_SUITE:
    &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-witness-rent-publisher-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_WITNESS_ENCRYPTION_SUITE: &str = "ML-KEM-1024+XChaCha20Poly1305+view-tagged-witness-envelope-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_NULLIFIER_SUITE: &str =
    "monero-l2-nullifier-fence-witness-rent-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_DEVNET_HEIGHT: u64 =
    1_386_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_COMMITMENT_TTL_BLOCKS: u64 = 172_800;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 4_096;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 7_200;
pub const DEFAULT_MAX_LANES: usize = 1_048_576;
pub const DEFAULT_MAX_COMMITMENTS: usize = 16_777_216;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_SLOTS: usize = 67_108_864;
pub const DEFAULT_MAX_TICKETS: usize = 134_217_728;
pub const DEFAULT_MAX_REBATES: usize = 33_554_432;
pub const DEFAULT_MAX_INVALIDATIONS: usize = 16_777_216;
pub const DEFAULT_MAX_CHALLENGES: usize = 8_388_608;
pub const DEFAULT_MAX_SLASHING_EVENTS: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 134_217_728;
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    ContractDeployment,
    HotPathLibrary,
    VerifierPrelude,
    AccountAbstraction,
    DefiRouter,
    BridgeAdapter,
    OracleAdapter,
    GovernanceModule,
    CustomContract,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Proposed,
    Active,
    Congested,
    Paused,
    Draining,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessClass {
    Wasm,
    EvmCompatible,
    CairoLike,
    NoirCircuit,
    RiscZeroGuest,
    MoveModule,
    NativeVerifier,
    CustomVm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Encrypted,
    Attested,
    Cacheable,
    Warmed,
    Invalidating,
    Invalidated,
    Challenged,
    Malicious,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PublisherKey,
    WitnessOpening,
    PqSignature,
    ReproducibleBuild,
    GasProfile,
    NoMalware,
    PrivacyFence,
    VerifierCacheProof,
    EmergencyRevocation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheSlotStatus {
    Reserved,
    Filled,
    Warm,
    Cooling,
    Released,
    Invalidated,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Issued,
    BoundToCall,
    Consumed,
    RebateQueued,
    RebateSettled,
    Expired,
    Cancelled,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToLane,
    Expired,
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    TtlExpired,
    PublisherRevoked,
    VerifierMismatch,
    PrivacyFenceBroken,
    ChallengeAccepted,
    ChainUpgrade,
    LaneRetired,
    EmergencyPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    MaliciousWitness,
    WrongCommitmentOpening,
    PqSignatureForgery,
    NonDeterministicBuild,
    GasProfileFraud,
    PrivacyLeak,
    VerifierCachePoisoning,
    ReplayFenceBypass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    EvidenceCommitted,
    UnderReview,
    Accepted,
    Rejected,
    Expired,
    Settled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingTarget {
    Publisher,
    Verifier,
    Both,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    MaliciousWitness,
    FalseAttestation,
    CachePoisoning,
    TicketFraud,
    RebateFraud,
    PrivacyFenceViolation,
    ReplayAttack,
    RefusedOpening,
}

impl LaneStatus {
    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Active | Self::Congested | Self::Draining)
    }
    pub fn accepts_slots(self) -> bool {
        matches!(self, Self::Active | Self::Congested)
    }
}
impl CommitmentStatus {
    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Attested | Self::Cacheable | Self::Warmed)
    }
    pub fn can_challenge(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Attested | Self::Cacheable | Self::Warmed | Self::Invalidating
        )
    }
}
impl CacheSlotStatus {
    pub fn can_issue_ticket(self) -> bool {
        matches!(self, Self::Filled | Self::Warm)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub market_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub protocol_version: String,
    pub witness_encryption_suite: String,
    pub pq_attestation_suite: String,
    pub nullifier_suite: String,
    pub min_privacy_set: u64,
    pub batch_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub lane_ttl_blocks: u64,
    pub commitment_ttl_blocks: u64,
    pub slot_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_lane_fee_bps: u64,
    pub max_publisher_fee_bps: u64,
    pub max_verifier_fee_bps: u64,
    pub max_rebate_bps: u64,
    pub max_lanes: usize,
    pub max_commitments: usize,
    pub max_attestations: usize,
    pub max_slots: usize,
    pub max_tickets: usize,
    pub max_rebates: usize,
    pub max_invalidations: usize,
    pub max_challenges: usize,
    pub max_slashing_events: usize,
    pub max_privacy_fences: usize,
}
impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self { chain_id: CHAIN_ID.to_string(), market_id: "devnet-pq-confidential-witness-rent-market".to_string(), l2_network: "nebula-private-l2-devnet".to_string(), fee_asset_id: "piconero-devnet".to_string(), protocol_version: PROTOCOL_VERSION.to_string(), witness_encryption_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_WITNESS_ENCRYPTION_SUITE.to_string(), pq_attestation_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_PQ_ATTESTATION_SUITE.to_string(), nullifier_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_NULLIFIER_SUITE.to_string(), min_privacy_set: DEFAULT_MIN_PRIVACY_SET, batch_privacy_set: DEFAULT_BATCH_PRIVACY_SET, min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS, lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS, commitment_ttl_blocks: DEFAULT_COMMITMENT_TTL_BLOCKS, slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS, ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS, rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS, challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS, max_lane_fee_bps: 25, max_publisher_fee_bps: 40, max_verifier_fee_bps: 30, max_rebate_bps: 600, max_lanes: DEFAULT_MAX_LANES, max_commitments: DEFAULT_MAX_COMMITMENTS, max_attestations: DEFAULT_MAX_ATTESTATIONS, max_slots: DEFAULT_MAX_SLOTS, max_tickets: DEFAULT_MAX_TICKETS, max_rebates: DEFAULT_MAX_REBATES, max_invalidations: DEFAULT_MAX_INVALIDATIONS, max_challenges: DEFAULT_MAX_CHALLENGES, max_slashing_events: DEFAULT_MAX_SLASHING_EVENTS, max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES }
    }
    pub fn validate(&self) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        required("market_id", &self.market_id)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported witness cache market protocol version".to_string());
        }
        if self.batch_privacy_set < self.min_privacy_set
            || self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("privacy or pq security floor violated".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub lane_sequence: u64,
    pub commitment_sequence: u64,
    pub attestation_sequence: u64,
    pub slot_sequence: u64,
    pub ticket_sequence: u64,
    pub rebate_sequence: u64,
    pub invalidation_sequence: u64,
    pub challenge_sequence: u64,
    pub slashing_sequence: u64,
    pub fence_sequence: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub lane_root: String,
    pub commitment_root: String,
    pub attestation_root: String,
    pub slot_root: String,
    pub ticket_root: String,
    pub rebate_root: String,
    pub invalidation_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheLaneRecord {
    pub lane_id: String,
    pub lane_kind: LaneKind,
    pub owner_commitment: String,
    pub verifier_set_commitment: String,
    pub fee_asset_id: String,
    pub base_fee: u64,
    pub lane_fee_bps: u64,
    pub publisher_fee_bps: u64,
    pub verifier_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub status: LaneStatus,
    pub created_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: String,
    pub active_commitments: u64,
    pub reserved_slots: u64,
    pub tickets_issued: u64,
    pub total_fees_locked: u128,
}
impl CacheLaneRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessCommitmentRecord {
    pub commitment_id: String,
    pub lane_id: String,
    pub publisher_commitment: String,
    pub witness_class: WitnessClass,
    pub encrypted_witness_root: String,
    pub witness_commitment: String,
    pub code_hash_commitment: String,
    pub abi_commitment: String,
    pub metadata_commitment: String,
    pub size_bytes: u64,
    pub gas_profile_commitment: String,
    pub pq_key_commitment: String,
    pub privacy_fence_id: String,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub status: CommitmentStatus,
    pub created_height: u64,
    pub expires_at_height: u64,
    pub attestation_count: u64,
    pub slot_count: u64,
    pub ticket_count: u64,
    pub challenge_count: u64,
}
impl WitnessCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherAttestationRecord {
    pub attestation_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub publisher_commitment: String,
    pub attestation_kind: AttestationKind,
    pub attestation_root: String,
    pub signature_commitment: String,
    pub pq_key_commitment: String,
    pub transcript_root: String,
    pub status: AttestationStatus,
    pub pq_security_bits: u16,
    pub created_height: u64,
    pub expires_at_height: u64,
}
impl PublisherAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifierCacheSlotRecord {
    pub slot_id: String,
    pub lane_id: String,
    pub commitment_id: String,
    pub verifier_commitment: String,
    pub slot_commitment: String,
    pub capacity_units: u64,
    pub price_per_warm_call: u64,
    pub reserved_fee: u128,
    pub status: CacheSlotStatus,
    pub created_height: u64,
    pub expires_at_height: u64,
    pub tickets_issued: u64,
    pub tickets_consumed: u64,
}
impl VerifierCacheSlotRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WarmCallTicketRecord {
    pub ticket_id: String,
    pub slot_id: String,
    pub lane_id: String,
    pub commitment_id: String,
    pub caller_commitment: String,
    pub call_nullifier: String,
    pub call_hint_root: String,
    pub max_call_units: u64,
    pub paid_fee: u128,
    pub expected_rebate: u128,
    pub status: TicketStatus,
    pub issued_height: u64,
    pub expires_at_height: u64,
    pub consumed_height: Option<u64>,
}
impl WarmCallTicketRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub commitment_id: String,
    pub recipient_commitment: String,
    pub rebate_amount: u128,
    pub settlement_nullifier: String,
    pub proof_root: String,
    pub status: RebateStatus,
    pub created_height: u64,
    pub expires_at_height: u64,
}
impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvalidationReceiptRecord {
    pub invalidation_id: String,
    pub lane_id: String,
    pub commitment_id: String,
    pub slot_id: Option<String>,
    pub reason: InvalidationReason,
    pub receipt_root: String,
    pub reporter_commitment: String,
    pub created_height: u64,
}
impl InvalidationReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub lane_id: String,
    pub fence_nullifier: String,
    pub anonymity_set_root: String,
    pub min_privacy_set: u64,
    pub batch_privacy_set: u64,
    pub view_tag_root: String,
    pub created_height: u64,
}
impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MaliciousWitnessChallengeRecord {
    pub challenge_id: String,
    pub lane_id: String,
    pub commitment_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub evidence_root: String,
    pub bond_amount: u128,
    pub status: ChallengeStatus,
    pub filed_height: u64,
    pub expires_at_height: u64,
    pub resolved_height: Option<u64>,
}
impl MaliciousWitnessChallengeRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidenceRecord {
    pub slashing_id: String,
    pub lane_id: String,
    pub commitment_id: Option<String>,
    pub slot_id: Option<String>,
    pub challenge_id: Option<String>,
    pub target: SlashingTarget,
    pub reason: SlashingReason,
    pub offender_commitment: String,
    pub evidence_root: String,
    pub slash_amount: u128,
    pub beneficiary_commitment: String,
    pub created_height: u64,
}
impl SlashingEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterCacheLaneRequest {
    pub lane_kind: LaneKind,
    pub owner_commitment: String,
    pub verifier_set_commitment: String,
    pub fee_asset_id: String,
    pub base_fee: u64,
    pub lane_fee_bps: u64,
    pub publisher_fee_bps: u64,
    pub verifier_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub metadata_commitment: String,
}
impl RegisterCacheLaneRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitWitnessCommitmentRequest {
    pub lane_id: String,
    pub publisher_commitment: String,
    pub witness_class: WitnessClass,
    pub encrypted_witness_root: String,
    pub witness_commitment: String,
    pub code_hash_commitment: String,
    pub abi_commitment: String,
    pub metadata_commitment: String,
    pub size_bytes: u64,
    pub gas_profile_commitment: String,
    pub pq_key_commitment: String,
    pub fence_nullifier: String,
    pub anonymity_set_root: String,
    pub view_tag_root: String,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
}
impl SubmitWitnessCommitmentRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestPublisherRequest {
    pub commitment_id: String,
    pub publisher_commitment: String,
    pub attestation_kind: AttestationKind,
    pub attestation_root: String,
    pub signature_commitment: String,
    pub pq_key_commitment: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
}
impl AttestPublisherRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveCacheSlotRequest {
    pub lane_id: String,
    pub commitment_id: String,
    pub verifier_commitment: String,
    pub slot_commitment: String,
    pub capacity_units: u64,
    pub price_per_warm_call: u64,
    pub reserved_fee: u128,
}
impl ReserveCacheSlotRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueWarmCallTicketRequest {
    pub slot_id: String,
    pub caller_commitment: String,
    pub call_nullifier: String,
    pub call_hint_root: String,
    pub max_call_units: u64,
    pub paid_fee: u128,
}
impl IssueWarmCallTicketRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleRebateRequest {
    pub ticket_id: String,
    pub recipient_commitment: String,
    pub settlement_nullifier: String,
    pub proof_root: String,
    pub consumed_call_units: u64,
}
impl SettleRebateRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvalidateStaleCodeRequest {
    pub commitment_id: String,
    pub slot_id: Option<String>,
    pub reason: InvalidationReason,
    pub receipt_root: String,
    pub reporter_commitment: String,
}
impl InvalidateStaleCodeRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeMaliciousCodeRequest {
    pub commitment_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub evidence_root: String,
    pub bond_amount: u128,
}
impl ChallengeMaliciousCodeRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashPublisherVerifierRequest {
    pub lane_id: String,
    pub commitment_id: Option<String>,
    pub slot_id: Option<String>,
    pub challenge_id: Option<String>,
    pub target: SlashingTarget,
    pub reason: SlashingReason,
    pub offender_commitment: String,
    pub evidence_root: String,
    pub slash_amount: u128,
    pub beneficiary_commitment: String,
}
impl SlashPublisherVerifierRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl RegisterCacheLaneRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        required("owner_commitment", &self.owner_commitment)?;
        required("verifier_set_commitment", &self.verifier_set_commitment)?;
        required("metadata_commitment", &self.metadata_commitment)?;
        if self.fee_asset_id != config.fee_asset_id {
            return Err("unsupported fee asset for cache lane".to_string());
        }
        if self.lane_fee_bps > config.max_lane_fee_bps
            || self.publisher_fee_bps > config.max_publisher_fee_bps
            || self.verifier_fee_bps > config.max_verifier_fee_bps
            || self.rebate_bps > config.max_rebate_bps
        {
            return Err("fee bps exceeds configured market limits".to_string());
        }
        if self.min_privacy_set < config.min_privacy_set
            || self.pq_security_bits < config.min_pq_security_bits
        {
            return Err("lane privacy or pq security below floor".to_string());
        }
        Ok(())
    }
}
impl SubmitWitnessCommitmentRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        for (n, v) in [
            ("lane_id", &self.lane_id),
            ("publisher_commitment", &self.publisher_commitment),
            ("encrypted_witness_root", &self.encrypted_witness_root),
            ("witness_commitment", &self.witness_commitment),
            ("code_hash_commitment", &self.code_hash_commitment),
            ("abi_commitment", &self.abi_commitment),
            ("gas_profile_commitment", &self.gas_profile_commitment),
            ("pq_key_commitment", &self.pq_key_commitment),
            ("fence_nullifier", &self.fence_nullifier),
            ("anonymity_set_root", &self.anonymity_set_root),
            ("view_tag_root", &self.view_tag_root),
        ] {
            required(n, v)?;
        }
        if self.size_bytes == 0 {
            return Err("witness commitment cannot be empty".to_string());
        }
        if self.min_privacy_set < config.min_privacy_set
            || self.pq_security_bits < config.min_pq_security_bits
        {
            return Err("witness privacy or pq security below floor".to_string());
        }
        Ok(())
    }
}
impl AttestPublisherRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        for (n, v) in [
            ("commitment_id", &self.commitment_id),
            ("publisher_commitment", &self.publisher_commitment),
            ("attestation_root", &self.attestation_root),
            ("signature_commitment", &self.signature_commitment),
            ("pq_key_commitment", &self.pq_key_commitment),
            ("transcript_root", &self.transcript_root),
        ] {
            required(n, v)?;
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("attestation pq security below floor".to_string());
        }
        Ok(())
    }
}
impl ReserveCacheSlotRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        for (n, v) in [
            ("lane_id", &self.lane_id),
            ("commitment_id", &self.commitment_id),
            ("verifier_commitment", &self.verifier_commitment),
            ("slot_commitment", &self.slot_commitment),
        ] {
            required(n, v)?;
        }
        if self.capacity_units == 0 || self.price_per_warm_call == 0 || self.reserved_fee == 0 {
            return Err("cache slot capacity, price, and fee must be non-zero".to_string());
        }
        Ok(())
    }
}
impl IssueWarmCallTicketRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        for (n, v) in [
            ("slot_id", &self.slot_id),
            ("caller_commitment", &self.caller_commitment),
            ("call_nullifier", &self.call_nullifier),
            ("call_hint_root", &self.call_hint_root),
        ] {
            required(n, v)?;
        }
        if self.max_call_units == 0 || self.paid_fee == 0 {
            return Err("ticket units and fee must be non-zero".to_string());
        }
        Ok(())
    }
}
impl SettleRebateRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        for (n, v) in [
            ("ticket_id", &self.ticket_id),
            ("recipient_commitment", &self.recipient_commitment),
            ("settlement_nullifier", &self.settlement_nullifier),
            ("proof_root", &self.proof_root),
        ] {
            required(n, v)?;
        }
        if self.consumed_call_units == 0 {
            return Err("consumed call units must be non-zero".to_string());
        }
        Ok(())
    }
}
impl InvalidateStaleCodeRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        required("commitment_id", &self.commitment_id)?;
        required("receipt_root", &self.receipt_root)?;
        required("reporter_commitment", &self.reporter_commitment)?;
        Ok(())
    }
}
impl ChallengeMaliciousCodeRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        required("commitment_id", &self.commitment_id)?;
        required("challenger_commitment", &self.challenger_commitment)?;
        required("evidence_root", &self.evidence_root)?;
        if self.bond_amount == 0 {
            return Err("challenge bond must be non-zero".to_string());
        }
        Ok(())
    }
}
impl SlashPublisherVerifierRequest {
    pub fn validate(&self) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        required("lane_id", &self.lane_id)?;
        required("offender_commitment", &self.offender_commitment)?;
        required("evidence_root", &self.evidence_root)?;
        required("beneficiary_commitment", &self.beneficiary_commitment)?;
        if self.slash_amount == 0 {
            return Err("slash amount must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub lanes: BTreeMap<String, CacheLaneRecord>,
    pub commitments: BTreeMap<String, WitnessCommitmentRecord>,
    pub attestations: BTreeMap<String, PublisherAttestationRecord>,
    pub slots: BTreeMap<String, VerifierCacheSlotRecord>,
    pub tickets: BTreeMap<String, WarmCallTicketRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub invalidations: BTreeMap<String, InvalidationReceiptRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub challenges: BTreeMap<String, MaliciousWitnessChallengeRecord>,
    pub slashing_events: BTreeMap<String, SlashingEvidenceRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_DEVNET_HEIGHT,
            lanes: BTreeMap::new(),
            commitments: BTreeMap::new(),
            attestations: BTreeMap::new(),
            slots: BTreeMap::new(),
            tickets: BTreeMap::new(),
            rebates: BTreeMap::new(),
            invalidations: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        })
    }
    pub fn devnet() -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<Self> {
        Self::new(Config::devnet())
    }
    pub fn advance_height(
        &mut self,
        new_height: u64,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        if new_height < self.current_height {
            return Err("cannot move height backwards".to_string());
        }
        self.current_height = new_height;
        Ok(())
    }
    pub fn register_cache_lane(
        &mut self,
        request: RegisterCacheLaneRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate(&self.config)?;
        self.ensure_capacity(self.lanes.len(), self.config.max_lanes, "cache lanes")?;
        self.counters.lane_sequence = self.counters.lane_sequence.saturating_add(1);
        let lane_id = cache_lane_id(&request, self.counters.lane_sequence);
        let record = CacheLaneRecord {
            lane_id: lane_id.clone(),
            lane_kind: request.lane_kind,
            owner_commitment: request.owner_commitment,
            verifier_set_commitment: request.verifier_set_commitment,
            fee_asset_id: request.fee_asset_id,
            base_fee: request.base_fee,
            lane_fee_bps: request.lane_fee_bps,
            publisher_fee_bps: request.publisher_fee_bps,
            verifier_fee_bps: request.verifier_fee_bps,
            rebate_bps: request.rebate_bps,
            min_privacy_set: request.min_privacy_set,
            pq_security_bits: request.pq_security_bits,
            status: LaneStatus::Active,
            created_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.lane_ttl_blocks),
            metadata_commitment: request.metadata_commitment,
            active_commitments: 0,
            reserved_slots: 0,
            tickets_issued: 0,
            total_fees_locked: 0,
        };
        self.lanes.insert(lane_id.clone(), record);
        Ok(lane_id)
    }
    pub fn submit_witness_commitment(
        &mut self,
        request: SubmitWitnessCommitmentRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate(&self.config)?;
        self.ensure_capacity(
            self.commitments.len(),
            self.config.max_commitments,
            "witness commitments",
        )?;
        self.ensure_capacity(
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
            "privacy fences",
        )?;
        if self.spent_nullifiers.contains(&request.fence_nullifier) {
            return Err("privacy fence nullifier already spent".to_string());
        }
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "unknown cache lane".to_string())?;
        if !lane.status.accepts_commitments() {
            return Err("cache lane is not accepting witness commitments".to_string());
        }
        if self.current_height > lane.expires_at_height {
            lane.status = LaneStatus::Retired;
            return Err("cache lane expired".to_string());
        }
        if request.min_privacy_set < lane.min_privacy_set
            || request.pq_security_bits < lane.pq_security_bits
        {
            return Err("commitment below lane privacy or pq floor".to_string());
        }
        self.counters.fence_sequence = self.counters.fence_sequence.saturating_add(1);
        let fence_id = privacy_fence_id(&request, self.counters.fence_sequence);
        self.privacy_fences.insert(
            fence_id.clone(),
            PrivacyFenceRecord {
                fence_id: fence_id.clone(),
                lane_id: request.lane_id.clone(),
                fence_nullifier: request.fence_nullifier.clone(),
                anonymity_set_root: request.anonymity_set_root.clone(),
                min_privacy_set: request.min_privacy_set,
                batch_privacy_set: self.config.batch_privacy_set,
                view_tag_root: request.view_tag_root.clone(),
                created_height: self.current_height,
            },
        );
        self.spent_nullifiers
            .insert(request.fence_nullifier.clone());
        self.counters.commitment_sequence = self.counters.commitment_sequence.saturating_add(1);
        let commitment_id = witness_commitment_id(&request, self.counters.commitment_sequence);
        let record = WitnessCommitmentRecord {
            commitment_id: commitment_id.clone(),
            lane_id: request.lane_id.clone(),
            publisher_commitment: request.publisher_commitment,
            witness_class: request.witness_class,
            encrypted_witness_root: request.encrypted_witness_root,
            witness_commitment: request.witness_commitment,
            code_hash_commitment: request.code_hash_commitment,
            abi_commitment: request.abi_commitment,
            metadata_commitment: request.metadata_commitment,
            size_bytes: request.size_bytes,
            gas_profile_commitment: request.gas_profile_commitment,
            pq_key_commitment: request.pq_key_commitment,
            privacy_fence_id: fence_id,
            min_privacy_set: request.min_privacy_set,
            pq_security_bits: request.pq_security_bits,
            status: CommitmentStatus::Encrypted,
            created_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.commitment_ttl_blocks),
            attestation_count: 0,
            slot_count: 0,
            ticket_count: 0,
            challenge_count: 0,
        };
        lane.active_commitments = lane.active_commitments.saturating_add(1);
        self.commitments.insert(commitment_id.clone(), record);
        Ok(commitment_id)
    }
    pub fn attest_publisher(
        &mut self,
        request: AttestPublisherRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate(&self.config)?;
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "publisher attestations",
        )?;
        let commitment = self
            .commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| "unknown witness commitment".to_string())?;
        if commitment.publisher_commitment != request.publisher_commitment {
            return Err("publisher commitment mismatch".to_string());
        }
        if self.current_height > commitment.expires_at_height {
            commitment.status = CommitmentStatus::Expired;
            return Err("witness commitment expired".to_string());
        }
        self.counters.attestation_sequence = self.counters.attestation_sequence.saturating_add(1);
        let attestation_id = publisher_attestation_id(&request, self.counters.attestation_sequence);
        self.attestations.insert(
            attestation_id.clone(),
            PublisherAttestationRecord {
                attestation_id: attestation_id.clone(),
                commitment_id: request.commitment_id.clone(),
                lane_id: commitment.lane_id.clone(),
                publisher_commitment: request.publisher_commitment,
                attestation_kind: request.attestation_kind,
                attestation_root: request.attestation_root,
                signature_commitment: request.signature_commitment,
                pq_key_commitment: request.pq_key_commitment,
                transcript_root: request.transcript_root,
                status: AttestationStatus::Accepted,
                pq_security_bits: request.pq_security_bits,
                created_height: self.current_height,
                expires_at_height: commitment.expires_at_height,
            },
        );
        commitment.attestation_count = commitment.attestation_count.saturating_add(1);
        commitment.status = if commitment.attestation_count >= 2 {
            CommitmentStatus::Cacheable
        } else {
            CommitmentStatus::Attested
        };
        Ok(attestation_id)
    }
    pub fn reserve_cache_slot(
        &mut self,
        request: ReserveCacheSlotRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate()?;
        self.ensure_capacity(
            self.slots.len(),
            self.config.max_slots,
            "verifier cache slots",
        )?;
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "unknown cache lane".to_string())?;
        if !lane.status.accepts_slots() {
            return Err("cache lane is not accepting slots".to_string());
        }
        let commitment = self
            .commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| "unknown witness commitment".to_string())?;
        if commitment.lane_id != request.lane_id || !commitment.status.can_reserve() {
            return Err("commitment is not reserveable for this lane".to_string());
        }
        self.counters.slot_sequence = self.counters.slot_sequence.saturating_add(1);
        let slot_id = verifier_cache_slot_id(&request, self.counters.slot_sequence);
        self.slots.insert(
            slot_id.clone(),
            VerifierCacheSlotRecord {
                slot_id: slot_id.clone(),
                lane_id: request.lane_id.clone(),
                commitment_id: request.commitment_id.clone(),
                verifier_commitment: request.verifier_commitment,
                slot_commitment: request.slot_commitment,
                capacity_units: request.capacity_units,
                price_per_warm_call: request.price_per_warm_call,
                reserved_fee: request.reserved_fee,
                status: CacheSlotStatus::Warm,
                created_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.slot_ttl_blocks),
                tickets_issued: 0,
                tickets_consumed: 0,
            },
        );
        lane.reserved_slots = lane.reserved_slots.saturating_add(1);
        lane.total_fees_locked = lane.total_fees_locked.saturating_add(request.reserved_fee);
        commitment.slot_count = commitment.slot_count.saturating_add(1);
        commitment.status = CommitmentStatus::Warmed;
        Ok(slot_id)
    }
    pub fn issue_warm_call_ticket(
        &mut self,
        request: IssueWarmCallTicketRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate()?;
        self.ensure_capacity(
            self.tickets.len(),
            self.config.max_tickets,
            "warm-call tickets",
        )?;
        if self.spent_nullifiers.contains(&request.call_nullifier) {
            return Err("warm-call nullifier already spent".to_string());
        }
        let slot = self
            .slots
            .get_mut(&request.slot_id)
            .ok_or_else(|| "unknown verifier cache slot".to_string())?;
        if !slot.status.can_issue_ticket() || self.current_height > slot.expires_at_height {
            return Err("cache slot cannot issue ticket".to_string());
        }
        if request.max_call_units > slot.capacity_units
            || request.paid_fee < slot.price_per_warm_call as u128
        {
            return Err("ticket exceeds slot capacity or price".to_string());
        }
        let lane = self
            .lanes
            .get_mut(&slot.lane_id)
            .ok_or_else(|| "slot lane missing".to_string())?;
        let commitment = self
            .commitments
            .get_mut(&slot.commitment_id)
            .ok_or_else(|| "slot commitment missing".to_string())?;
        self.counters.ticket_sequence = self.counters.ticket_sequence.saturating_add(1);
        let ticket_id = warm_call_ticket_id(&request, self.counters.ticket_sequence);
        let expected_rebate = bps_amount(request.paid_fee, lane.rebate_bps);
        self.tickets.insert(
            ticket_id.clone(),
            WarmCallTicketRecord {
                ticket_id: ticket_id.clone(),
                slot_id: request.slot_id.clone(),
                lane_id: slot.lane_id.clone(),
                commitment_id: slot.commitment_id.clone(),
                caller_commitment: request.caller_commitment,
                call_nullifier: request.call_nullifier.clone(),
                call_hint_root: request.call_hint_root,
                max_call_units: request.max_call_units,
                paid_fee: request.paid_fee,
                expected_rebate,
                status: TicketStatus::Issued,
                issued_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.ticket_ttl_blocks),
                consumed_height: None,
            },
        );
        self.spent_nullifiers.insert(request.call_nullifier);
        slot.tickets_issued = slot.tickets_issued.saturating_add(1);
        lane.tickets_issued = lane.tickets_issued.saturating_add(1);
        lane.total_fees_locked = lane.total_fees_locked.saturating_add(request.paid_fee);
        commitment.ticket_count = commitment.ticket_count.saturating_add(1);
        Ok(ticket_id)
    }
    pub fn settle_rebate(
        &mut self,
        request: SettleRebateRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate()?;
        self.ensure_capacity(self.rebates.len(), self.config.max_rebates, "fee rebates")?;
        if self
            .spent_nullifiers
            .contains(&request.settlement_nullifier)
        {
            return Err("rebate nullifier already spent".to_string());
        }
        let ticket = self
            .tickets
            .get_mut(&request.ticket_id)
            .ok_or_else(|| "unknown warm-call ticket".to_string())?;
        if !matches!(
            ticket.status,
            TicketStatus::Issued | TicketStatus::BoundToCall
        ) || self.current_height > ticket.expires_at_height
        {
            return Err("ticket is not settleable".to_string());
        }
        if request.consumed_call_units > ticket.max_call_units {
            return Err("consumed units exceed ticket maximum".to_string());
        }
        let slot = self
            .slots
            .get_mut(&ticket.slot_id)
            .ok_or_else(|| "ticket slot missing".to_string())?;
        let rebate_amount = ticket
            .expected_rebate
            .saturating_mul(request.consumed_call_units as u128)
            / ticket.max_call_units.max(1) as u128;
        self.counters.rebate_sequence = self.counters.rebate_sequence.saturating_add(1);
        let rebate_id = fee_rebate_id(&request, self.counters.rebate_sequence);
        self.rebates.insert(
            rebate_id.clone(),
            FeeRebateRecord {
                rebate_id: rebate_id.clone(),
                ticket_id: request.ticket_id.clone(),
                lane_id: ticket.lane_id.clone(),
                commitment_id: ticket.commitment_id.clone(),
                recipient_commitment: request.recipient_commitment,
                rebate_amount,
                settlement_nullifier: request.settlement_nullifier.clone(),
                proof_root: request.proof_root,
                status: RebateStatus::Claimable,
                created_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.rebate_ttl_blocks),
            },
        );
        self.spent_nullifiers.insert(request.settlement_nullifier);
        ticket.status = TicketStatus::RebateSettled;
        ticket.consumed_height = Some(self.current_height);
        slot.tickets_consumed = slot.tickets_consumed.saturating_add(1);
        Ok(rebate_id)
    }
    pub fn invalidate_stale_code(
        &mut self,
        request: InvalidateStaleCodeRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate()?;
        self.ensure_capacity(
            self.invalidations.len(),
            self.config.max_invalidations,
            "invalidation receipts",
        )?;
        let commitment = self
            .commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| "unknown witness commitment".to_string())?;
        let allowed = self.current_height > commitment.expires_at_height
            || !matches!(request.reason, InvalidationReason::TtlExpired);
        if !allowed {
            return Err(
                "stale-code invalidation requires expiry or explicit fault reason".to_string(),
            );
        }
        commitment.status = CommitmentStatus::Invalidated;
        if let Some(slot_id) = &request.slot_id {
            let slot = self
                .slots
                .get_mut(slot_id)
                .ok_or_else(|| "unknown cache slot for invalidation".to_string())?;
            if slot.commitment_id != request.commitment_id {
                return Err("invalidation slot mismatch".to_string());
            }
            slot.status = CacheSlotStatus::Invalidated;
        }
        self.counters.invalidation_sequence = self.counters.invalidation_sequence.saturating_add(1);
        let invalidation_id =
            invalidation_receipt_id(&request, self.counters.invalidation_sequence);
        self.invalidations.insert(
            invalidation_id.clone(),
            InvalidationReceiptRecord {
                invalidation_id: invalidation_id.clone(),
                lane_id: commitment.lane_id.clone(),
                commitment_id: request.commitment_id,
                slot_id: request.slot_id,
                reason: request.reason,
                receipt_root: request.receipt_root,
                reporter_commitment: request.reporter_commitment,
                created_height: self.current_height,
            },
        );
        Ok(invalidation_id)
    }
    pub fn challenge_malicious_code(
        &mut self,
        request: ChallengeMaliciousCodeRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate()?;
        self.ensure_capacity(
            self.challenges.len(),
            self.config.max_challenges,
            "malicious witness challenges",
        )?;
        let commitment = self
            .commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| "unknown witness commitment".to_string())?;
        if !commitment.status.can_challenge() {
            return Err("commitment cannot be challenged".to_string());
        }
        if self.current_height
            > commitment
                .expires_at_height
                .saturating_add(self.config.challenge_window_blocks)
        {
            return Err("challenge window closed".to_string());
        }
        self.counters.challenge_sequence = self.counters.challenge_sequence.saturating_add(1);
        let challenge_id =
            malicious_witness_challenge_id(&request, self.counters.challenge_sequence);
        self.challenges.insert(
            challenge_id.clone(),
            MaliciousWitnessChallengeRecord {
                challenge_id: challenge_id.clone(),
                lane_id: commitment.lane_id.clone(),
                commitment_id: request.commitment_id.clone(),
                challenger_commitment: request.challenger_commitment,
                challenge_kind: request.challenge_kind,
                evidence_root: request.evidence_root,
                bond_amount: request.bond_amount,
                status: ChallengeStatus::Filed,
                filed_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.challenge_window_blocks),
                resolved_height: None,
            },
        );
        commitment.challenge_count = commitment.challenge_count.saturating_add(1);
        commitment.status = CommitmentStatus::Challenged;
        Ok(challenge_id)
    }
    pub fn slash_publisher_verifier(
        &mut self,
        request: SlashPublisherVerifierRequest,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<String> {
        request.validate()?;
        self.ensure_capacity(
            self.slashing_events.len(),
            self.config.max_slashing_events,
            "slashing evidence",
        )?;
        if !self.lanes.contains_key(&request.lane_id) {
            return Err("unknown slashing lane".to_string());
        }
        if let Some(commitment_id) = &request.commitment_id {
            let commitment = self
                .commitments
                .get_mut(commitment_id)
                .ok_or_else(|| "unknown slashing commitment".to_string())?;
            if commitment.lane_id != request.lane_id {
                return Err("slashing commitment lane mismatch".to_string());
            }
            if matches!(
                request.reason,
                SlashingReason::MaliciousWitness
                    | SlashingReason::FalseAttestation
                    | SlashingReason::PrivacyFenceViolation
                    | SlashingReason::RefusedOpening
            ) {
                commitment.status = CommitmentStatus::Malicious;
            }
        }
        if let Some(slot_id) = &request.slot_id {
            let slot = self
                .slots
                .get_mut(slot_id)
                .ok_or_else(|| "unknown slashing slot".to_string())?;
            if slot.lane_id != request.lane_id {
                return Err("slashing slot lane mismatch".to_string());
            }
            slot.status = CacheSlotStatus::Slashed;
        }
        if let Some(challenge_id) = &request.challenge_id {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| "unknown slashing challenge".to_string())?;
            challenge.status = ChallengeStatus::Settled;
            challenge.resolved_height = Some(self.current_height);
        }
        self.counters.slashing_sequence = self.counters.slashing_sequence.saturating_add(1);
        let slashing_id = slashing_evidence_id(&request, self.counters.slashing_sequence);
        self.slashing_events.insert(
            slashing_id.clone(),
            SlashingEvidenceRecord {
                slashing_id: slashing_id.clone(),
                lane_id: request.lane_id,
                commitment_id: request.commitment_id,
                slot_id: request.slot_id,
                challenge_id: request.challenge_id,
                target: request.target,
                reason: request.reason,
                offender_commitment: request.offender_commitment,
                evidence_root: request.evidence_root,
                slash_amount: request.slash_amount,
                beneficiary_commitment: request.beneficiary_commitment,
                created_height: self.current_height,
            },
        );
        Ok(slashing_id)
    }
    pub fn roots(&self) -> Roots {
        let lane_root = public_record_root(
            "witness-rent-market:lanes",
            &self
                .lanes
                .values()
                .map(CacheLaneRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let commitment_root = public_record_root(
            "witness-rent-market:commitments",
            &self
                .commitments
                .values()
                .map(WitnessCommitmentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = public_record_root(
            "witness-rent-market:attestations",
            &self
                .attestations
                .values()
                .map(PublisherAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let slot_root = public_record_root(
            "witness-rent-market:slots",
            &self
                .slots
                .values()
                .map(VerifierCacheSlotRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let ticket_root = public_record_root(
            "witness-rent-market:tickets",
            &self
                .tickets
                .values()
                .map(WarmCallTicketRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "witness-rent-market:rebates",
            &self
                .rebates
                .values()
                .map(FeeRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let invalidation_root = public_record_root(
            "witness-rent-market:invalidations",
            &self
                .invalidations
                .values()
                .map(InvalidationReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let challenge_root = public_record_root(
            "witness-rent-market:challenges",
            &self
                .challenges
                .values()
                .map(MaliciousWitnessChallengeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let slashing_root = public_record_root(
            "witness-rent-market:slashing",
            &self
                .slashing_events
                .values()
                .map(SlashingEvidenceRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let privacy_fence_root = public_record_root(
            "witness-rent-market:privacy-fences",
            &self
                .privacy_fences
                .values()
                .map(PrivacyFenceRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifiers = self
            .spent_nullifiers
            .iter()
            .map(|v| json!(v))
            .collect::<Vec<_>>();
        let nullifier_root = public_record_root("witness-rent-market:nullifiers", &nullifiers);
        let state_root = state_root_from_record(
            &json!({"protocol_version": PROTOCOL_VERSION, "chain_id": self.config.chain_id, "market_id": self.config.market_id, "current_height": self.current_height, "counters": self.counters.public_record(), "lane_root": lane_root, "commitment_root": commitment_root, "attestation_root": attestation_root, "slot_root": slot_root, "ticket_root": ticket_root, "rebate_root": rebate_root, "invalidation_root": invalidation_root, "challenge_root": challenge_root, "slashing_root": slashing_root, "privacy_fence_root": privacy_fence_root, "nullifier_root": nullifier_root}),
        );
        Roots {
            lane_root,
            commitment_root,
            attestation_root,
            slot_root,
            ticket_root,
            rebate_root,
            invalidation_root,
            challenge_root,
            slashing_root,
            privacy_fence_root,
            nullifier_root,
            state_root,
        }
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({"protocol_version": PROTOCOL_VERSION, "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_SCHEMA_VERSION, "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_HASH_SUITE, "config": self.config.public_record(), "counters": self.counters.public_record(), "current_height": self.current_height, "roots": self.roots().public_record(), "counts": {"lanes": self.lanes.len(), "commitments": self.commitments.len(), "attestations": self.attestations.len(), "slots": self.slots.len(), "tickets": self.tickets.len(), "rebates": self.rebates.len(), "invalidations": self.invalidations.len(), "privacy_fences": self.privacy_fences.len(), "challenges": self.challenges.len(), "slashing_events": self.slashing_events.len(), "spent_nullifiers": self.spent_nullifiers.len()}})
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    pub fn lane(&self, lane_id: &str) -> Option<&CacheLaneRecord> {
        self.lanes.get(lane_id)
    }
    pub fn commitment(&self, commitment_id: &str) -> Option<&WitnessCommitmentRecord> {
        self.commitments.get(commitment_id)
    }
    pub fn slot(&self, slot_id: &str) -> Option<&VerifierCacheSlotRecord> {
        self.slots.get(slot_id)
    }
    pub fn ticket(&self, ticket_id: &str) -> Option<&WarmCallTicketRecord> {
        self.tickets.get(ticket_id)
    }
    pub fn has_spent_nullifier(&self, nullifier: &str) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }
    pub fn active_lane_ids(&self) -> Vec<String> {
        self.lanes
            .iter()
            .filter(|(_, lane)| lane.status.accepts_commitments())
            .map(|(lane_id, _)| lane_id.clone())
            .collect()
    }
    pub fn cacheable_commitment_ids(&self, lane_id: &str) -> Vec<String> {
        self.commitments
            .iter()
            .filter(|(_, commitment)| {
                commitment.lane_id == lane_id && commitment.status.can_reserve()
            })
            .map(|(commitment_id, _)| commitment_id.clone())
            .collect()
    }
    pub fn warm_slot_ids(&self, commitment_id: &str) -> Vec<String> {
        self.slots
            .iter()
            .filter(|(_, slot)| {
                slot.commitment_id == commitment_id && slot.status.can_issue_ticket()
            })
            .map(|(slot_id, _)| slot_id.clone())
            .collect()
    }
    pub fn open_challenge_ids(&self, commitment_id: &str) -> Vec<String> {
        self.challenges
            .iter()
            .filter(|(_, challenge)| {
                challenge.commitment_id == commitment_id
                    && matches!(
                        challenge.status,
                        ChallengeStatus::Filed
                            | ChallengeStatus::EvidenceCommitted
                            | ChallengeStatus::UnderReview
                    )
            })
            .map(|(challenge_id, _)| challenge_id.clone())
            .collect()
    }
    pub fn claimable_rebate_ids(&self, recipient_commitment: &str) -> Vec<String> {
        self.rebates
            .iter()
            .filter(|(_, rebate)| {
                rebate.recipient_commitment == recipient_commitment
                    && matches!(rebate.status, RebateStatus::Claimable)
                    && self.current_height <= rebate.expires_at_height
            })
            .map(|(rebate_id, _)| rebate_id.clone())
            .collect()
    }
    pub fn expired_commitment_ids(&self) -> Vec<String> {
        self.commitments
            .iter()
            .filter(|(_, commitment)| self.current_height > commitment.expires_at_height)
            .map(|(commitment_id, _)| commitment_id.clone())
            .collect()
    }
    pub fn expired_slot_ids(&self) -> Vec<String> {
        self.slots
            .iter()
            .filter(|(_, slot)| self.current_height > slot.expires_at_height)
            .map(|(slot_id, _)| slot_id.clone())
            .collect()
    }
    pub fn expired_ticket_ids(&self) -> Vec<String> {
        self.tickets
            .iter()
            .filter(|(_, ticket)| self.current_height > ticket.expires_at_height)
            .map(|(ticket_id, _)| ticket_id.clone())
            .collect()
    }
    pub fn lane_fee_quote(
        &self,
        lane_id: &str,
        call_units: u64,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<Value> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "unknown cache lane".to_string())?;
        if call_units == 0 {
            return Err("call units must be non-zero".to_string());
        }
        let base = lane.base_fee as u128;
        let unit_fee = base.saturating_mul(call_units as u128);
        let lane_fee = bps_amount(unit_fee, lane.lane_fee_bps);
        let publisher_fee = bps_amount(unit_fee, lane.publisher_fee_bps);
        let verifier_fee = bps_amount(unit_fee, lane.verifier_fee_bps);
        let rebate = bps_amount(unit_fee, lane.rebate_bps);
        Ok(json!({
            "lane_id": lane_id,
            "call_units": call_units,
            "fee_asset_id": lane.fee_asset_id,
            "base_unit_fee": base.to_string(),
            "gross_fee": unit_fee.to_string(),
            "lane_fee": lane_fee.to_string(),
            "publisher_fee": publisher_fee.to_string(),
            "verifier_fee": verifier_fee.to_string(),
            "expected_rebate": rebate.to_string(),
            "net_fee_after_rebate": unit_fee.saturating_sub(rebate).to_string()
        }))
    }
    fn ensure_capacity(
        &self,
        current_len: usize,
        max_len: usize,
        name: &str,
    ) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
        if current_len >= max_len {
            return Err(format!("{name} capacity exhausted"));
        }
        Ok(())
    }
}

pub fn cache_lane_id(request: &RegisterCacheLaneRequest, sequence: u64) -> String {
    deterministic_id("LANE-ID", sequence, &request.public_record())
}
pub fn witness_commitment_id(request: &SubmitWitnessCommitmentRequest, sequence: u64) -> String {
    deterministic_id("COMMITMENT-ID", sequence, &request.public_record())
}
pub fn publisher_attestation_id(request: &AttestPublisherRequest, sequence: u64) -> String {
    deterministic_id("ATTESTATION-ID", sequence, &request.public_record())
}
pub fn verifier_cache_slot_id(request: &ReserveCacheSlotRequest, sequence: u64) -> String {
    deterministic_id("SLOT-ID", sequence, &request.public_record())
}
pub fn warm_call_ticket_id(request: &IssueWarmCallTicketRequest, sequence: u64) -> String {
    deterministic_id("TICKET-ID", sequence, &request.public_record())
}
pub fn fee_rebate_id(request: &SettleRebateRequest, sequence: u64) -> String {
    deterministic_id("REBATE-ID", sequence, &request.public_record())
}
pub fn invalidation_receipt_id(request: &InvalidateStaleCodeRequest, sequence: u64) -> String {
    deterministic_id("INVALIDATION-ID", sequence, &request.public_record())
}
pub fn privacy_fence_id(request: &SubmitWitnessCommitmentRequest, sequence: u64) -> String {
    deterministic_id(
        "PRIVACY-FENCE-ID",
        sequence,
        &json!({"lane_id": request.lane_id, "fence_nullifier": request.fence_nullifier, "anonymity_set_root": request.anonymity_set_root, "view_tag_root": request.view_tag_root}),
    )
}
pub fn malicious_witness_challenge_id(
    request: &ChallengeMaliciousCodeRequest,
    sequence: u64,
) -> String {
    deterministic_id("CHALLENGE-ID", sequence, &request.public_record())
}
pub fn slashing_evidence_id(request: &SlashPublisherVerifierRequest, sequence: u64) -> String {
    deterministic_id("SLASHING-ID", sequence, &request.public_record())
}
pub fn deterministic_id(kind: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:{kind}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}
pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}
pub fn lane_record_root(record: &CacheLaneRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:LANE-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn commitment_record_root(record: &WitnessCommitmentRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:COMMITMENT-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn attestation_record_root(record: &PublisherAttestationRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:ATTESTATION-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn slot_record_root(record: &VerifierCacheSlotRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:SLOT-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn ticket_record_root(record: &WarmCallTicketRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:TICKET-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn rebate_record_root(record: &FeeRebateRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:REBATE-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn invalidation_record_root(record: &InvalidationReceiptRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:INVALIDATION-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn privacy_fence_record_root(record: &PrivacyFenceRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:PRIVACY-FENCE-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn challenge_record_root(record: &MaliciousWitnessChallengeRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:CHALLENGE-RECORD-ROOT",
        &record.public_record(),
    )
}
pub fn slashing_record_root(record: &SlashingEvidenceRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-WITNESS-CACHE-MARKET:SLASHING-RECORD-ROOT",
        &record.public_record(),
    )
}
fn required(
    name: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractWitnessRentMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}
fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128)
        / PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_WITNESS_RENT_MARKET_RUNTIME_MAX_BPS as u128
}
