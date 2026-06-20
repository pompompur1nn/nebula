use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialZkvmPrecompileAttestationMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-zkvm-precompile-attestation-market-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ZKVM_ATTESTATION_SCHEME: &str =
    "zkvm-confidential-precompile-attestation-transcript-root-v1";
pub const PQ_SIGNER_COMMITMENT_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-signer-commitment-root-v1";
pub const PQ_KEM_SCHEME: &str = "ML-KEM-1024-confidential-provider-envelope-v1";
pub const CONFIDENTIAL_CLAIM_SCHEME: &str =
    "private-l2-confidential-precompile-claim-commitment-v1";
pub const LOW_FEE_SPONSOR_SCHEME: &str = "confidential-zkvm-precompile-fee-sponsor-v1";
pub const REBATE_SCHEME: &str = "operator-safe-private-l2-precompile-rebate-v1";
pub const SLASHING_SCHEME: &str = "pq-zkvm-precompile-attestation-slashing-evidence-v1";
pub const DEVNET_COMMITTEE_ID: &str = "zkvm-precompile-attestation-devnet-committee";
pub const DEVNET_HEIGHT: u64 = 3_210_144;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_PROVIDER_BOND_MICRO_UNITS: u64 = 7_500_000;
pub const DEFAULT_SPONSOR_BOND_MICRO_UNITS: u64 = 2_000_000;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_PROVIDER_FEE_SHARE_BPS: u64 = 7_500;
pub const MAX_PROVIDERS: usize = 1_048_576;
pub const MAX_SIGNER_COMMITMENTS: usize = 4_194_304;
pub const MAX_CLAIMS: usize = 8_388_608;
pub const MAX_TRANSCRIPTS: usize = 8_388_608;
pub const MAX_SPONSORSHIPS: usize = 4_194_304;
pub const MAX_REBATES: usize = 8_388_608;
pub const MAX_QUARANTINES: usize = 1_048_576;
pub const MAX_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    ZkvmHost,
    PrecompileAuditor,
    TranscriptAggregator,
    PqSigner,
    FeeSponsor,
    PrivacyWatcher,
    SlashingJudge,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZkvmHost => "zkvm_host",
            Self::PrecompileAuditor => "precompile_auditor",
            Self::TranscriptAggregator => "transcript_aggregator",
            Self::PqSigner => "pq_signer",
            Self::FeeSponsor => "fee_sponsor",
            Self::PrivacyWatcher => "privacy_watcher",
            Self::SlashingJudge => "slashing_judge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Pending,
    Active,
    Degraded,
    Quarantined,
    Suspended,
    Slashed,
    Retired,
}

impl ProviderStatus {
    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn operator_visible(self) -> bool {
        !matches!(self, Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecompileFamily {
    PqSignatureVerify,
    PqKemEnvelopeOpen,
    RecursiveProofVerify,
    RangeProofVerify,
    MembershipProofVerify,
    MoneroViewTagScan,
    MoneroKeyImageCheck,
    ConfidentialSwapMath,
    ConfidentialCreditMath,
    FheQueryGate,
    PrivateStateRead,
    BridgeReserveProof,
}

impl PrecompileFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureVerify => "pq_signature_verify",
            Self::PqKemEnvelopeOpen => "pq_kem_envelope_open",
            Self::RecursiveProofVerify => "recursive_proof_verify",
            Self::RangeProofVerify => "range_proof_verify",
            Self::MembershipProofVerify => "membership_proof_verify",
            Self::MoneroViewTagScan => "monero_view_tag_scan",
            Self::MoneroKeyImageCheck => "monero_key_image_check",
            Self::ConfidentialSwapMath => "confidential_swap_math",
            Self::ConfidentialCreditMath => "confidential_credit_math",
            Self::FheQueryGate => "fhe_query_gate",
            Self::PrivateStateRead => "private_state_read",
            Self::BridgeReserveProof => "bridge_reserve_proof",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::BridgeReserveProof => 980,
            Self::RecursiveProofVerify => 940,
            Self::PqSignatureVerify => 900,
            Self::PqKemEnvelopeOpen => 860,
            Self::MoneroKeyImageCheck => 830,
            Self::MoneroViewTagScan => 800,
            Self::RangeProofVerify => 760,
            Self::MembershipProofVerify => 720,
            Self::PrivateStateRead => 680,
            Self::FheQueryGate => 640,
            Self::ConfidentialSwapMath => 600,
            Self::ConfidentialCreditMath => 560,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    Matched,
    TranscriptPublished,
    Attested,
    Sponsored,
    Rebated,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl ClaimStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Matched
                | Self::TranscriptPublished
                | Self::Attested
                | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptVerdict {
    Accepted,
    NeedsMoreWeight,
    PrivacyRegression,
    InvalidGuestImage,
    InvalidPrecompileState,
    ProviderFault,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    RebateQueued,
    Rebated,
    Refunded,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidTranscript,
    EquivocatedRoot,
    WeakPqCommitment,
    PrivacyLeak,
    FeeOvercharge,
    LateAttestation,
    OperatorUnsafeDisclosure,
}

impl SlashingReason {
    pub fn severity(self) -> u64 {
        match self {
            Self::PrivacyLeak => 1_000,
            Self::EquivocatedRoot => 920,
            Self::InvalidTranscript => 860,
            Self::OperatorUnsafeDisclosure => 780,
            Self::WeakPqCommitment => 720,
            Self::FeeOvercharge => 640,
            Self::LateAttestation => 520,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub zkvm_attestation_scheme: String,
    pub pq_signer_commitment_scheme: String,
    pub pq_kem_scheme: String,
    pub confidential_claim_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub rebate_scheme: String,
    pub slashing_scheme: String,
    pub committee_id: String,
    pub devnet_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_provider_bond_micro_units: u64,
    pub min_sponsor_bond_micro_units: u64,
    pub attestation_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub quarantine_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub provider_fee_share_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            zkvm_attestation_scheme: ZKVM_ATTESTATION_SCHEME.to_string(),
            pq_signer_commitment_scheme: PQ_SIGNER_COMMITMENT_SCHEME.to_string(),
            pq_kem_scheme: PQ_KEM_SCHEME.to_string(),
            confidential_claim_scheme: CONFIDENTIAL_CLAIM_SCHEME.to_string(),
            low_fee_sponsor_scheme: LOW_FEE_SPONSOR_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            slashing_scheme: SLASHING_SCHEME.to_string(),
            committee_id: DEVNET_COMMITTEE_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_provider_bond_micro_units: DEFAULT_PROVIDER_BOND_MICRO_UNITS,
            min_sponsor_bond_micro_units: DEFAULT_SPONSOR_BOND_MICRO_UNITS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            provider_fee_share_bps: DEFAULT_PROVIDER_FEE_SHARE_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive_u64("batch_privacy_set_size", self.batch_privacy_set_size)?;
        ensure_positive_u64("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        ensure_positive_u64("claim_ttl_blocks", self.claim_ttl_blocks)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("provider_fee_share_bps", self.provider_fee_share_bps)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size must cover min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below devnet security floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub providers_registered: u64,
    pub signer_commitments: u64,
    pub claims_submitted: u64,
    pub transcript_roots_published: u64,
    pub attestations_accepted: u64,
    pub sponsorships_reserved: u64,
    pub rebates_queued: u64,
    pub rebates_paid_micro_units: u64,
    pub slashing_events: u64,
    pub quarantines_opened: u64,
    pub operator_summaries: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub provider_root: String,
    pub signer_commitment_root: String,
    pub confidential_claim_root: String,
    pub proof_transcript_root: String,
    pub sponsorship_root: String,
    pub rebate_root: String,
    pub quarantine_root: String,
    pub event_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            provider_root: empty_root("PROVIDER"),
            signer_commitment_root: empty_root("SIGNER-COMMITMENT"),
            confidential_claim_root: empty_root("CONFIDENTIAL-CLAIM"),
            proof_transcript_root: empty_root("PROOF-TRANSCRIPT"),
            sponsorship_root: empty_root("SPONSORSHIP"),
            rebate_root: empty_root("REBATE"),
            quarantine_root: empty_root("QUARANTINE"),
            event_root: empty_root("EVENT"),
            operator_summary_root: empty_root("OPERATOR-SUMMARY"),
            state_root: empty_root("STATE"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderRegistrationRequest {
    pub provider_label: String,
    pub kind: ProviderKind,
    pub operator_commitment: String,
    pub pq_identity_commitment: String,
    pub zkvm_image_root: String,
    pub supported_precompile_families: Vec<PrecompileFamily>,
    pub endpoint_commitment_root: String,
    pub bond_micro_units: u64,
    pub declared_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderRecord {
    pub provider_id: String,
    pub provider_label: String,
    pub kind: ProviderKind,
    pub status: ProviderStatus,
    pub operator_commitment: String,
    pub pq_identity_commitment: String,
    pub zkvm_image_root: String,
    pub supported_precompile_root: String,
    pub endpoint_commitment_root: String,
    pub bond_micro_units: u64,
    pub declared_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub accepted_claims: u64,
    pub slashing_count: u64,
    pub quarantine_until_height: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignerCommitmentRequest {
    pub provider_id: String,
    pub signer_epoch: u64,
    pub signer_set_commitment: String,
    pub hybrid_deprecation_root: String,
    pub rotation_policy_root: String,
    pub aggregation_key_commitment: String,
    pub declared_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignerCommitmentRecord {
    pub commitment_id: String,
    pub provider_id: String,
    pub signer_epoch: u64,
    pub signer_set_commitment: String,
    pub hybrid_deprecation_root: String,
    pub rotation_policy_root: String,
    pub aggregation_key_commitment: String,
    pub declared_security_bits: u16,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialPrecompileClaimRequest {
    pub caller_commitment: String,
    pub provider_id: String,
    pub precompile_family: PrecompileFamily,
    pub encrypted_call_root: String,
    pub input_note_root: String,
    pub output_note_commitment_root: String,
    pub nullifier_root: String,
    pub witness_commitment_root: String,
    pub max_fee_micro_units: u64,
    pub requested_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialPrecompileClaimRecord {
    pub claim_id: String,
    pub caller_commitment: String,
    pub provider_id: String,
    pub precompile_family: PrecompileFamily,
    pub status: ClaimStatus,
    pub encrypted_call_root: String,
    pub input_note_root: String,
    pub output_note_commitment_root: String,
    pub nullifier_root: String,
    pub witness_commitment_root: String,
    pub max_fee_micro_units: u64,
    pub requested_rebate_bps: u64,
    pub priority_score: u64,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
    pub transcript_id: Option<String>,
    pub sponsorship_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofTranscriptRootRequest {
    pub claim_id: String,
    pub provider_id: String,
    pub signer_commitment_id: String,
    pub zkvm_guest_image_root: String,
    pub public_input_root: String,
    pub private_input_commitment_root: String,
    pub execution_trace_root: String,
    pub precompile_state_root: String,
    pub attestation_signature_root: String,
    pub latency_micros: u64,
    pub fee_charged_micro_units: u64,
    pub verdict: TranscriptVerdict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofTranscriptRootRecord {
    pub transcript_id: String,
    pub claim_id: String,
    pub provider_id: String,
    pub signer_commitment_id: String,
    pub zkvm_guest_image_root: String,
    pub public_input_root: String,
    pub private_input_commitment_root: String,
    pub execution_trace_root: String,
    pub precompile_state_root: String,
    pub attestation_signature_root: String,
    pub transcript_root: String,
    pub latency_micros: u64,
    pub fee_charged_micro_units: u64,
    pub verdict: TranscriptVerdict,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorshipRequest {
    pub sponsor_commitment: String,
    pub claim_id: String,
    pub provider_id: String,
    pub budget_micro_units: u64,
    pub max_cover_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_bond_micro_units: u64,
    pub privacy_pool_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorshipRecord {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub claim_id: String,
    pub provider_id: String,
    pub status: SponsorshipStatus,
    pub budget_micro_units: u64,
    pub max_cover_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_bond_micro_units: u64,
    pub privacy_pool_root: String,
    pub reserved_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub sponsorship_id: String,
    pub claim_id: String,
    pub provider_id: String,
    pub recipient_commitment: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub rebate_root: String,
    pub operator_safe: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingRequest {
    pub provider_id: String,
    pub claim_id: Option<String>,
    pub transcript_id: Option<String>,
    pub evidence_root: String,
    pub reason: SlashingReason,
    pub reporter_commitment: String,
    pub quarantine: bool,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub provider_id: String,
    pub claim_id: Option<String>,
    pub transcript_id: Option<String>,
    pub evidence_root: String,
    pub reason: SlashingReason,
    pub reporter_commitment: String,
    pub opened_at_height: u64,
    pub release_height: u64,
    pub slashed_micro_units: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub chain_id: String,
    pub protocol_version: String,
    pub provider_count: u64,
    pub active_provider_count: u64,
    pub live_claim_count: u64,
    pub accepted_transcript_count: u64,
    pub queued_rebate_count: u64,
    pub quarantined_provider_count: u64,
    pub low_fee_rebate_micro_units: u64,
    pub roots: Roots,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub providers: Vec<ProviderRecord>,
    pub signer_commitments: Vec<PqSignerCommitmentRecord>,
    pub claims: Vec<ConfidentialPrecompileClaimRecord>,
    pub transcripts: Vec<ProofTranscriptRootRecord>,
    pub sponsorships: Vec<FeeSponsorshipRecord>,
    pub rebates: Vec<RebateRecord>,
    pub quarantines: Vec<QuarantineRecord>,
    pub operator_summaries: Vec<OperatorSafeSummary>,
    pub events: Vec<Value>,
    pub provider_index: BTreeMap<String, usize>,
    pub claim_index: BTreeMap<String, usize>,
    pub transcript_index: BTreeMap<String, usize>,
    pub sponsorship_index: BTreeMap<String, usize>,
    pub quarantined_providers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            providers: Vec::new(),
            signer_commitments: Vec::new(),
            claims: Vec::new(),
            transcripts: Vec::new(),
            sponsorships: Vec::new(),
            rebates: Vec::new(),
            quarantines: Vec::new(),
            operator_summaries: Vec::new(),
            events: Vec::new(),
            provider_index: BTreeMap::new(),
            claim_index: BTreeMap::new(),
            transcript_index: BTreeMap::new(),
            sponsorship_index: BTreeMap::new(),
            quarantined_providers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet config is valid")
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let host = state
            .register_provider(ProviderRegistrationRequest {
                provider_label: "devnet-zkvm-host-0".to_string(),
                kind: ProviderKind::ZkvmHost,
                operator_commitment: commitment("operator", "host-0"),
                pq_identity_commitment: commitment("pq-identity", "host-0"),
                zkvm_image_root: commitment("zkvm-image", "confidential-precompile-host"),
                supported_precompile_families: vec![
                    PrecompileFamily::PqSignatureVerify,
                    PrecompileFamily::RecursiveProofVerify,
                    PrecompileFamily::MoneroViewTagScan,
                    PrecompileFamily::BridgeReserveProof,
                ],
                endpoint_commitment_root: commitment("endpoint", "host-0"),
                bond_micro_units: DEFAULT_PROVIDER_BOND_MICRO_UNITS * 2,
                declared_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                max_fee_bps: 12,
            })
            .expect("demo provider");
        let signer = state
            .commit_pq_signer(PqSignerCommitmentRequest {
                provider_id: host.provider_id.clone(),
                signer_epoch: 1,
                signer_set_commitment: commitment("signer-set", "epoch-1"),
                hybrid_deprecation_root: commitment("hybrid-deprecation", "epoch-1"),
                rotation_policy_root: commitment("rotation-policy", "fast-rotation"),
                aggregation_key_commitment: commitment("aggregation-key", "epoch-1"),
                declared_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            })
            .expect("demo signer");
        let claim = state
            .submit_precompile_claim(ConfidentialPrecompileClaimRequest {
                caller_commitment: commitment("caller", "wallet-7"),
                provider_id: host.provider_id.clone(),
                precompile_family: PrecompileFamily::RecursiveProofVerify,
                encrypted_call_root: commitment("encrypted-call", "recursive-proof"),
                input_note_root: commitment("input-note", "shielded-batch"),
                output_note_commitment_root: commitment("output-note", "shielded-batch"),
                nullifier_root: commitment("nullifier", "recursive-proof"),
                witness_commitment_root: commitment("witness", "recursive-proof"),
                max_fee_micro_units: 48_000,
                requested_rebate_bps: 9,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_CLAIM_TTL_BLOCKS,
            })
            .expect("demo claim");
        state
            .publish_transcript_root(ProofTranscriptRootRequest {
                claim_id: claim.claim_id.clone(),
                provider_id: host.provider_id.clone(),
                signer_commitment_id: signer.commitment_id,
                zkvm_guest_image_root: host.zkvm_image_root,
                public_input_root: commitment("public-input", "recursive-proof"),
                private_input_commitment_root: commitment("private-input", "recursive-proof"),
                execution_trace_root: commitment("execution-trace", "recursive-proof"),
                precompile_state_root: commitment("precompile-state", "recursive-proof"),
                attestation_signature_root: commitment("attestation-sig", "recursive-proof"),
                latency_micros: 18_500,
                fee_charged_micro_units: 34_000,
                verdict: TranscriptVerdict::Accepted,
            })
            .expect("demo transcript");
        let sponsorship = state
            .reserve_fee_sponsorship(FeeSponsorshipRequest {
                sponsor_commitment: commitment("sponsor", "low-fee-pool"),
                claim_id: claim.claim_id,
                provider_id: host.provider_id,
                budget_micro_units: 60_000,
                max_cover_bps: 8_500,
                rebate_bps: DEFAULT_TARGET_REBATE_BPS,
                sponsor_bond_micro_units: DEFAULT_SPONSOR_BOND_MICRO_UNITS,
                privacy_pool_root: commitment("privacy-pool", "wallet-rebates"),
            })
            .expect("demo sponsorship");
        state
            .settle_rebate(&sponsorship.sponsorship_id)
            .expect("demo rebate");
        state.push_operator_summary();
        state
    }

    pub fn register_provider(
        &mut self,
        request: ProviderRegistrationRequest,
    ) -> Result<ProviderRecord> {
        ensure_capacity("providers", self.providers.len(), MAX_PROVIDERS)?;
        ensure_non_empty("provider_label", &request.provider_label)?;
        ensure_non_empty("operator_commitment", &request.operator_commitment)?;
        ensure_non_empty("pq_identity_commitment", &request.pq_identity_commitment)?;
        ensure_non_empty("zkvm_image_root", &request.zkvm_image_root)?;
        ensure_non_empty(
            "endpoint_commitment_root",
            &request.endpoint_commitment_root,
        )?;
        ensure_positive_u64("bond_micro_units", request.bond_micro_units)?;
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        if request.bond_micro_units < self.config.min_provider_bond_micro_units {
            return Err("provider bond below configured minimum".to_string());
        }
        if request.declared_pq_security_bits < self.config.min_pq_security_bits {
            return Err("provider pq security below configured minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("provider privacy set below configured minimum".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("provider fee exceeds private L2 low-fee cap".to_string());
        }
        let family_values = request
            .supported_precompile_families
            .iter()
            .map(|family| json!(family.as_str()))
            .collect::<Vec<_>>();
        let provider_id = record_id(
            "PROVIDER-ID",
            &json!({
                "chain_id": self.config.chain_id,
                "label": request.provider_label,
                "kind": request.kind,
                "operator_commitment": request.operator_commitment,
                "pq_identity_commitment": request.pq_identity_commitment,
                "zkvm_image_root": request.zkvm_image_root,
            }),
        );
        if self.provider_index.contains_key(&provider_id) {
            return Err("provider already registered".to_string());
        }
        let record = ProviderRecord {
            provider_id: provider_id.clone(),
            provider_label: request.provider_label,
            kind: request.kind,
            status: ProviderStatus::Active,
            operator_commitment: request.operator_commitment,
            pq_identity_commitment: request.pq_identity_commitment,
            zkvm_image_root: request.zkvm_image_root,
            supported_precompile_root: merkle_root("ZKVM-PRECOMPILE-FAMILY", &family_values),
            endpoint_commitment_root: request.endpoint_commitment_root,
            bond_micro_units: request.bond_micro_units,
            declared_pq_security_bits: request.declared_pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            accepted_claims: 0,
            slashing_count: 0,
            quarantine_until_height: None,
        };
        self.provider_index
            .insert(provider_id.clone(), self.providers.len());
        self.providers.push(record.clone());
        self.counters.providers_registered += 1;
        self.push_event("provider_registered", &record);
        self.refresh_roots();
        Ok(record)
    }

    pub fn commit_pq_signer(
        &mut self,
        request: PqSignerCommitmentRequest,
    ) -> Result<PqSignerCommitmentRecord> {
        ensure_capacity(
            "signer_commitments",
            self.signer_commitments.len(),
            MAX_SIGNER_COMMITMENTS,
        )?;
        self.provider_can_attest(&request.provider_id)?;
        ensure_non_empty("signer_set_commitment", &request.signer_set_commitment)?;
        ensure_non_empty("hybrid_deprecation_root", &request.hybrid_deprecation_root)?;
        ensure_non_empty("rotation_policy_root", &request.rotation_policy_root)?;
        ensure_non_empty(
            "aggregation_key_commitment",
            &request.aggregation_key_commitment,
        )?;
        if request.declared_security_bits < self.config.min_pq_security_bits {
            return Err("signer commitment below pq security floor".to_string());
        }
        let commitment_id = record_id(
            "PQ-SIGNER-COMMITMENT-ID",
            &json!({
                "provider_id": request.provider_id,
                "signer_epoch": request.signer_epoch,
                "signer_set_commitment": request.signer_set_commitment,
                "aggregation_key_commitment": request.aggregation_key_commitment,
            }),
        );
        let record = PqSignerCommitmentRecord {
            commitment_id,
            provider_id: request.provider_id,
            signer_epoch: request.signer_epoch,
            signer_set_commitment: request.signer_set_commitment,
            hybrid_deprecation_root: request.hybrid_deprecation_root,
            rotation_policy_root: request.rotation_policy_root,
            aggregation_key_commitment: request.aggregation_key_commitment,
            declared_security_bits: request.declared_security_bits,
            active: true,
        };
        self.signer_commitments.push(record.clone());
        self.counters.signer_commitments += 1;
        self.push_event("pq_signer_committed", &record);
        self.refresh_roots();
        Ok(record)
    }

    pub fn submit_precompile_claim(
        &mut self,
        request: ConfidentialPrecompileClaimRequest,
    ) -> Result<ConfidentialPrecompileClaimRecord> {
        ensure_capacity("claims", self.claims.len(), MAX_CLAIMS)?;
        self.provider_can_attest(&request.provider_id)?;
        ensure_non_empty("caller_commitment", &request.caller_commitment)?;
        ensure_non_empty("encrypted_call_root", &request.encrypted_call_root)?;
        ensure_non_empty("input_note_root", &request.input_note_root)?;
        ensure_non_empty(
            "output_note_commitment_root",
            &request.output_note_commitment_root,
        )?;
        ensure_non_empty("nullifier_root", &request.nullifier_root)?;
        ensure_non_empty("witness_commitment_root", &request.witness_commitment_root)?;
        ensure_positive_u64("max_fee_micro_units", request.max_fee_micro_units)?;
        ensure_bps("requested_rebate_bps", request.requested_rebate_bps)?;
        if request.requested_rebate_bps > self.config.target_rebate_bps {
            return Err("requested rebate exceeds configured target".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("claim privacy set below configured minimum".to_string());
        }
        if request.expires_at_height <= self.config.devnet_height {
            return Err("claim expiry must be in the future".to_string());
        }
        let claim_id = record_id(
            "CONFIDENTIAL-PRECOMPILE-CLAIM-ID",
            &json!({
                "caller_commitment": request.caller_commitment,
                "provider_id": request.provider_id,
                "precompile_family": request.precompile_family,
                "encrypted_call_root": request.encrypted_call_root,
                "nullifier_root": request.nullifier_root,
            }),
        );
        let priority_score = request.precompile_family.priority()
            + request
                .privacy_set_size
                .min(self.config.batch_privacy_set_size)
                / 4096
            + request.requested_rebate_bps;
        let record = ConfidentialPrecompileClaimRecord {
            claim_id: claim_id.clone(),
            caller_commitment: request.caller_commitment,
            provider_id: request.provider_id,
            precompile_family: request.precompile_family,
            status: ClaimStatus::Submitted,
            encrypted_call_root: request.encrypted_call_root,
            input_note_root: request.input_note_root,
            output_note_commitment_root: request.output_note_commitment_root,
            nullifier_root: request.nullifier_root,
            witness_commitment_root: request.witness_commitment_root,
            max_fee_micro_units: request.max_fee_micro_units,
            requested_rebate_bps: request.requested_rebate_bps,
            priority_score,
            privacy_set_size: request.privacy_set_size,
            expires_at_height: request.expires_at_height,
            transcript_id: None,
            sponsorship_id: None,
        };
        self.claim_index.insert(claim_id, self.claims.len());
        self.claims.push(record.clone());
        self.counters.claims_submitted += 1;
        self.push_event("confidential_precompile_claim_submitted", &record);
        self.refresh_roots();
        Ok(record)
    }

    pub fn publish_transcript_root(
        &mut self,
        request: ProofTranscriptRootRequest,
    ) -> Result<ProofTranscriptRootRecord> {
        ensure_capacity("transcripts", self.transcripts.len(), MAX_TRANSCRIPTS)?;
        self.provider_can_attest(&request.provider_id)?;
        let claim_index = self.lookup_claim(&request.claim_id)?;
        if self.claims[claim_index].provider_id != request.provider_id {
            return Err("transcript provider does not match claim provider".to_string());
        }
        if !self.signer_commitments.iter().any(|commitment| {
            commitment.commitment_id == request.signer_commitment_id && commitment.active
        }) {
            return Err("active signer commitment not found".to_string());
        }
        ensure_non_empty("zkvm_guest_image_root", &request.zkvm_guest_image_root)?;
        ensure_non_empty("public_input_root", &request.public_input_root)?;
        ensure_non_empty(
            "private_input_commitment_root",
            &request.private_input_commitment_root,
        )?;
        ensure_non_empty("execution_trace_root", &request.execution_trace_root)?;
        ensure_non_empty("precompile_state_root", &request.precompile_state_root)?;
        ensure_non_empty(
            "attestation_signature_root",
            &request.attestation_signature_root,
        )?;
        let transcript_payload = json!({
            "chain_id": self.config.chain_id,
            "claim_id": request.claim_id,
            "provider_id": request.provider_id,
            "signer_commitment_id": request.signer_commitment_id,
            "zkvm_guest_image_root": request.zkvm_guest_image_root,
            "public_input_root": request.public_input_root,
            "private_input_commitment_root": request.private_input_commitment_root,
            "execution_trace_root": request.execution_trace_root,
            "precompile_state_root": request.precompile_state_root,
            "attestation_signature_root": request.attestation_signature_root,
        });
        let transcript_root = record_hash("ZKVM-PRECOMPILE-PROOF-TRANSCRIPT", &transcript_payload);
        let transcript_id = record_id("ZKVM-PRECOMPILE-TRANSCRIPT-ID", &transcript_payload);
        let accepted = request.verdict == TranscriptVerdict::Accepted;
        let record = ProofTranscriptRootRecord {
            transcript_id: transcript_id.clone(),
            claim_id: request.claim_id.clone(),
            provider_id: request.provider_id.clone(),
            signer_commitment_id: request.signer_commitment_id,
            zkvm_guest_image_root: request.zkvm_guest_image_root,
            public_input_root: request.public_input_root,
            private_input_commitment_root: request.private_input_commitment_root,
            execution_trace_root: request.execution_trace_root,
            precompile_state_root: request.precompile_state_root,
            attestation_signature_root: request.attestation_signature_root,
            transcript_root,
            latency_micros: request.latency_micros,
            fee_charged_micro_units: request.fee_charged_micro_units,
            verdict: request.verdict,
            accepted,
        };
        self.transcript_index
            .insert(transcript_id.clone(), self.transcripts.len());
        self.transcripts.push(record.clone());
        self.claims[claim_index].transcript_id = Some(transcript_id);
        self.claims[claim_index].status = if accepted {
            ClaimStatus::Attested
        } else {
            ClaimStatus::Rejected
        };
        if accepted {
            self.counters.attestations_accepted += 1;
            if let Some(provider_index) = self.provider_index.get(&request.provider_id).copied() {
                self.providers[provider_index].accepted_claims += 1;
            }
        }
        self.counters.transcript_roots_published += 1;
        self.push_event("proof_transcript_root_published", &record);
        self.refresh_roots();
        Ok(record)
    }

    pub fn reserve_fee_sponsorship(
        &mut self,
        request: FeeSponsorshipRequest,
    ) -> Result<FeeSponsorshipRecord> {
        ensure_capacity("sponsorships", self.sponsorships.len(), MAX_SPONSORSHIPS)?;
        let claim_index = self.lookup_claim(&request.claim_id)?;
        if self.claims[claim_index].provider_id != request.provider_id {
            return Err("sponsorship provider does not match claim provider".to_string());
        }
        ensure_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        ensure_non_empty("privacy_pool_root", &request.privacy_pool_root)?;
        ensure_positive_u64("budget_micro_units", request.budget_micro_units)?;
        ensure_bps("max_cover_bps", request.max_cover_bps)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        if request.sponsor_bond_micro_units < self.config.min_sponsor_bond_micro_units {
            return Err("sponsor bond below configured minimum".to_string());
        }
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("rebate exceeds configured target".to_string());
        }
        let max_fee = self.claims[claim_index].max_fee_micro_units;
        let reserved_micro_units = max_fee.saturating_mul(request.max_cover_bps) / MAX_BPS;
        if reserved_micro_units > request.budget_micro_units {
            return Err("sponsor budget cannot cover requested fee reservation".to_string());
        }
        let sponsorship_id = record_id(
            "FEE-SPONSORSHIP-ID",
            &json!({
                "sponsor_commitment": request.sponsor_commitment,
                "claim_id": request.claim_id,
                "provider_id": request.provider_id,
                "privacy_pool_root": request.privacy_pool_root,
            }),
        );
        let record = FeeSponsorshipRecord {
            sponsorship_id: sponsorship_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            claim_id: request.claim_id.clone(),
            provider_id: request.provider_id,
            status: SponsorshipStatus::Reserved,
            budget_micro_units: request.budget_micro_units,
            max_cover_bps: request.max_cover_bps,
            rebate_bps: request.rebate_bps,
            sponsor_bond_micro_units: request.sponsor_bond_micro_units,
            privacy_pool_root: request.privacy_pool_root,
            reserved_micro_units,
        };
        self.sponsorship_index
            .insert(sponsorship_id.clone(), self.sponsorships.len());
        self.sponsorships.push(record.clone());
        self.claims[claim_index].sponsorship_id = Some(sponsorship_id);
        self.claims[claim_index].status = ClaimStatus::Sponsored;
        self.counters.sponsorships_reserved += 1;
        self.push_event("fee_sponsorship_reserved", &record);
        self.refresh_roots();
        Ok(record)
    }

    pub fn settle_rebate(&mut self, sponsorship_id: &str) -> Result<RebateRecord> {
        ensure_capacity("rebates", self.rebates.len(), MAX_REBATES)?;
        let sponsorship_index = self.lookup_sponsorship(sponsorship_id)?;
        let sponsorship = self.sponsorships[sponsorship_index].clone();
        let claim_index = self.lookup_claim(&sponsorship.claim_id)?;
        let claim = self.claims[claim_index].clone();
        let charged = self
            .transcripts
            .iter()
            .find(|transcript| transcript.claim_id == claim.claim_id && transcript.accepted)
            .map(|transcript| transcript.fee_charged_micro_units)
            .unwrap_or(claim.max_fee_micro_units);
        let amount_micro_units = charged
            .min(sponsorship.reserved_micro_units)
            .saturating_mul(sponsorship.rebate_bps)
            / MAX_BPS;
        let rebate_payload = json!({
            "sponsorship_id": sponsorship.sponsorship_id,
            "claim_id": claim.claim_id,
            "provider_id": claim.provider_id,
            "recipient_commitment": claim.caller_commitment,
            "amount_micro_units": amount_micro_units,
            "rebate_bps": sponsorship.rebate_bps,
        });
        let record = RebateRecord {
            rebate_id: record_id("LOW-FEE-REBATE-ID", &rebate_payload),
            sponsorship_id: sponsorship.sponsorship_id,
            claim_id: claim.claim_id,
            provider_id: claim.provider_id,
            recipient_commitment: claim.caller_commitment,
            amount_micro_units,
            rebate_bps: sponsorship.rebate_bps,
            rebate_root: record_hash("LOW-FEE-REBATE-ROOT", &rebate_payload),
            operator_safe: true,
        };
        self.sponsorships[sponsorship_index].status = SponsorshipStatus::Rebated;
        self.claims[claim_index].status = ClaimStatus::Rebated;
        self.rebates.push(record.clone());
        self.counters.rebates_queued += 1;
        self.counters.rebates_paid_micro_units = self
            .counters
            .rebates_paid_micro_units
            .saturating_add(amount_micro_units);
        self.push_event("low_fee_rebate_settled", &record);
        self.refresh_roots();
        Ok(record)
    }

    pub fn slash_or_quarantine(&mut self, request: SlashingRequest) -> Result<QuarantineRecord> {
        ensure_capacity("quarantines", self.quarantines.len(), MAX_QUARANTINES)?;
        let provider_index = self.lookup_provider(&request.provider_id)?;
        ensure_non_empty("evidence_root", &request.evidence_root)?;
        ensure_non_empty("reporter_commitment", &request.reporter_commitment)?;
        let slashed_micro_units = self.providers[provider_index]
            .bond_micro_units
            .saturating_mul(request.reason.severity())
            / MAX_BPS;
        let quarantine_id = record_id(
            "ZKVM-PRECOMPILE-QUARANTINE-ID",
            &json!({
                "provider_id": request.provider_id,
                "claim_id": request.claim_id,
                "transcript_id": request.transcript_id,
                "evidence_root": request.evidence_root,
                "reason": request.reason,
                "height": request.height,
            }),
        );
        let release_height = request.height.saturating_add(if request.quarantine {
            self.config.quarantine_blocks
        } else {
            0
        });
        let record = QuarantineRecord {
            quarantine_id,
            provider_id: request.provider_id.clone(),
            claim_id: request.claim_id.clone(),
            transcript_id: request.transcript_id,
            evidence_root: request.evidence_root,
            reason: request.reason,
            reporter_commitment: request.reporter_commitment,
            opened_at_height: request.height,
            release_height,
            slashed_micro_units,
            active: request.quarantine,
        };
        self.providers[provider_index].slashing_count += 1;
        self.providers[provider_index].bond_micro_units = self.providers[provider_index]
            .bond_micro_units
            .saturating_sub(slashed_micro_units);
        self.providers[provider_index].status = if request.quarantine {
            ProviderStatus::Quarantined
        } else {
            ProviderStatus::Degraded
        };
        self.providers[provider_index].quarantine_until_height =
            request.quarantine.then_some(release_height);
        if request.quarantine {
            self.quarantined_providers.insert(request.provider_id);
            self.counters.quarantines_opened += 1;
        }
        if let Some(claim_id) = request.claim_id {
            if let Some(index) = self.claim_index.get(&claim_id).copied() {
                self.claims[index].status = ClaimStatus::Slashed;
            }
        }
        self.quarantines.push(record.clone());
        self.counters.slashing_events += 1;
        self.push_event("provider_slashed_or_quarantined", &record);
        self.refresh_roots();
        Ok(record)
    }

    pub fn push_operator_summary(&mut self) -> OperatorSafeSummary {
        let summary = self.operator_summary();
        self.operator_summaries.push(summary.clone());
        self.counters.operator_summaries += 1;
        self.push_event("operator_safe_summary_published", &summary);
        self.refresh_roots();
        summary
    }

    pub fn operator_summary(&self) -> OperatorSafeSummary {
        let active_provider_count = self
            .providers
            .iter()
            .filter(|provider| provider.status == ProviderStatus::Active)
            .count() as u64;
        let live_claim_count = self
            .claims
            .iter()
            .filter(|claim| claim.status.live())
            .count() as u64;
        let accepted_transcript_count = self
            .transcripts
            .iter()
            .filter(|transcript| transcript.accepted)
            .count() as u64;
        let queued_rebate_count = self.rebates.len() as u64;
        let summary_payload = json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "provider_count": self.providers.len(),
            "active_provider_count": active_provider_count,
            "live_claim_count": live_claim_count,
            "accepted_transcript_count": accepted_transcript_count,
            "queued_rebate_count": queued_rebate_count,
            "quarantined_provider_count": self.quarantined_providers.len(),
            "low_fee_rebate_micro_units": self.counters.rebates_paid_micro_units,
            "roots": self.roots,
        });
        OperatorSafeSummary {
            summary_id: record_id("OPERATOR-SAFE-SUMMARY-ID", &summary_payload),
            chain_id: self.config.chain_id.clone(),
            protocol_version: self.config.protocol_version.clone(),
            provider_count: self.providers.len() as u64,
            active_provider_count,
            live_claim_count,
            accepted_transcript_count,
            queued_rebate_count,
            quarantined_provider_count: self.quarantined_providers.len() as u64,
            low_fee_rebate_micro_units: self.counters.rebates_paid_micro_units,
            roots: self.roots.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "committee_id": self.config.committee_id,
            "privacy": {
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "batch_privacy_set_size": self.config.batch_privacy_set_size,
                "confidential_claim_scheme": self.config.confidential_claim_scheme,
            },
            "pq": {
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "pq_signer_commitment_scheme": self.config.pq_signer_commitment_scheme,
                "pq_kem_scheme": self.config.pq_kem_scheme,
            },
            "fees": {
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "target_rebate_bps": self.config.target_rebate_bps,
                "rebates_paid_micro_units": self.counters.rebates_paid_micro_units,
            },
            "counters": self.counters,
            "roots": self.roots,
            "operator_safe_summary": self.operator_summary(),
        })
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "ZKVM-PRECOMPILE-ATTESTATION-MARKET-STATE",
            &self.public_record(),
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.provider_root = records_root("ZKVM-PRECOMPILE-PROVIDER", &self.providers);
        self.roots.signer_commitment_root = records_root(
            "ZKVM-PRECOMPILE-PQ-SIGNER-COMMITMENT",
            &self.signer_commitments,
        );
        self.roots.confidential_claim_root =
            records_root("ZKVM-PRECOMPILE-CONFIDENTIAL-CLAIM", &self.claims);
        self.roots.proof_transcript_root =
            records_root("ZKVM-PRECOMPILE-PROOF-TRANSCRIPT", &self.transcripts);
        self.roots.sponsorship_root =
            records_root("ZKVM-PRECOMPILE-FEE-SPONSORSHIP", &self.sponsorships);
        self.roots.rebate_root = records_root("ZKVM-PRECOMPILE-REBATE", &self.rebates);
        self.roots.quarantine_root = records_root("ZKVM-PRECOMPILE-QUARANTINE", &self.quarantines);
        self.roots.event_root = merkle_root("ZKVM-PRECOMPILE-EVENT", &self.events);
        self.roots.operator_summary_root =
            records_root("ZKVM-PRECOMPILE-OPERATOR-SUMMARY", &self.operator_summaries);
        self.roots.state_root = record_hash(
            "ZKVM-PRECOMPILE-ATTESTATION-MARKET-ROOTS",
            &json!({
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "provider_root": self.roots.provider_root,
                "signer_commitment_root": self.roots.signer_commitment_root,
                "confidential_claim_root": self.roots.confidential_claim_root,
                "proof_transcript_root": self.roots.proof_transcript_root,
                "sponsorship_root": self.roots.sponsorship_root,
                "rebate_root": self.roots.rebate_root,
                "quarantine_root": self.roots.quarantine_root,
                "event_root": self.roots.event_root,
                "operator_summary_root": self.roots.operator_summary_root,
            }),
        );
    }

    fn provider_can_attest(&self, provider_id: &str) -> Result<()> {
        let index = self.lookup_provider(provider_id)?;
        if !self.providers[index].status.can_attest() {
            return Err("provider cannot attest in current status".to_string());
        }
        if self.quarantined_providers.contains(provider_id) {
            return Err("provider is quarantined".to_string());
        }
        Ok(())
    }

    fn lookup_provider(&self, provider_id: &str) -> Result<usize> {
        self.provider_index
            .get(provider_id)
            .copied()
            .ok_or_else(|| format!("provider not found: {provider_id}"))
    }

    fn lookup_claim(&self, claim_id: &str) -> Result<usize> {
        self.claim_index
            .get(claim_id)
            .copied()
            .ok_or_else(|| format!("claim not found: {claim_id}"))
    }

    fn lookup_sponsorship(&self, sponsorship_id: &str) -> Result<usize> {
        self.sponsorship_index
            .get(sponsorship_id)
            .copied()
            .ok_or_else(|| format!("sponsorship not found: {sponsorship_id}"))
    }

    fn push_event<T: Serialize>(&mut self, kind: &str, record: &T) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let record_value = serde_json::to_value(record).unwrap_or_else(|_| json!({}));
        self.events.push(json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "kind": kind,
            "record_hash": record_hash("ZKVM-PRECOMPILE-EVENT-RECORD", &record_value),
            "record": record_value,
        }));
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(field: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{field} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn commitment(domain: &str, value: &str) -> String {
    domain_hash(
        "ZKVM-PRECOMPILE-DEMO-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(&format!("ZKVM-PRECOMPILE-{domain}"), &[])
}

fn record_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn record_hash(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn records_root<T: Serialize>(domain: &str, records: &[T]) -> String {
    let leaves = records
        .iter()
        .map(|record| serde_json::to_value(record).unwrap_or_else(|_| json!({})))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
