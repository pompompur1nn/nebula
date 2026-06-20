use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlDsaKeyCeremonyRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_KEY_CEREMONY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-ml-dsa-key-ceremony-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_KEY_CEREMONY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIMARY_SIGNATURE_SUITE: &str = "ML-DSA-87-threshold-ceremony-v1";
pub const SECONDARY_SIGNATURE_SUITE: &str = "Falcon-1024-threshold-backstop-v1";
pub const HYBRID_CUTOVER_SUITE: &str = "legacy-monero-spend-to-ml-dsa-falcon-cutover-v1";
pub const CONFIDENTIAL_SHARE_SCHEME: &str = "pedersen-share-commitment+viewtag-redaction-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str = "pq-key-ceremony-watchtower-attestation-v1";
pub const SLASHING_SCHEME: &str = "pq-key-ceremony-equivocation-slashing-v1";
pub const FEE_REBATE_SCHEME: &str = "low-fee-pq-key-ceremony-sponsor-rebate-v1";
pub const DEVNET_HEIGHT: u64 = 812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_SIGNER_COHORT: u16 = 11;
pub const DEFAULT_THRESHOLD: u16 = 8;
pub const DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_CUTOVER_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_SHARE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_CUTOVER_DELAY_BLOCKS: u64 = 1_440;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 4_320;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const DEFAULT_MAX_REBATE_MICRONERO: u64 = 250_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyPurpose {
    BridgeReserve,
    SequencerFailover,
    WatcherAttestation,
    ContractAdmin,
    WalletRecovery,
    EmergencyEscape,
}

impl CeremonyPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeReserve => "bridge_reserve",
            Self::SequencerFailover => "sequencer_failover",
            Self::WatcherAttestation => "watcher_attestation",
            Self::ContractAdmin => "contract_admin",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureFamily {
    MlDsa65,
    MlDsa87,
    Falcon512,
    Falcon1024,
    HybridMlDsa87Falcon1024,
}

impl PqSignatureFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::Falcon512 => "falcon_512",
            Self::Falcon1024 => "falcon_1024",
            Self::HybridMlDsa87Falcon1024 => "hybrid_ml_dsa_87_falcon_1024",
        }
    }

    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 | Self::Falcon512 => 192,
            Self::MlDsa87 | Self::Falcon1024 | Self::HybridMlDsa87Falcon1024 => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStatus {
    Drafted,
    CohortRegistered,
    SharesCommitted,
    WatcherAttested,
    CutoverVoting,
    CutoverReady,
    Active,
    Quarantined,
    Slashed,
    Retired,
}

impl CeremonyStatus {
    pub fn accepts_shares(self) -> bool {
        matches!(self, Self::CohortRegistered | Self::SharesCommitted)
    }

    pub fn accepts_votes(self) -> bool {
        matches!(
            self,
            Self::WatcherAttested | Self::CutoverVoting | Self::CutoverReady
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Quarantined | Self::Slashed | Self::Retired
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::CohortRegistered => "cohort_registered",
            Self::SharesCommitted => "shares_committed",
            Self::WatcherAttested => "watcher_attested",
            Self::CutoverVoting => "cutover_voting",
            Self::CutoverReady => "cutover_ready",
            Self::Active => "active",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Pending,
    Committed,
    Verified,
    Disputed,
    Quarantined,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoverVote {
    Approve,
    Reject,
    Abstain,
    EmergencyPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Observed,
    MissingShare,
    Equivocation,
    WeakEntropy,
    TranscriptMismatch,
    LegacyKeyReuse,
}

impl AttestationVerdict {
    pub fn is_positive(self) -> bool {
        matches!(self, Self::Observed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    EquivocatedShare,
    InvalidPqProof,
    MissingOpening,
    WatcherMajorityVeto,
    CutoverFraud,
    SponsorAbuse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub network: String,
    pub chain_id: u64,
    pub l2_chain_id: u64,
    pub activation_height: u64,
    pub min_pq_security_bits: u16,
    pub min_signer_cohort: u16,
    pub default_threshold: u16,
    pub watcher_quorum_bps: u64,
    pub cutover_quorum_bps: u64,
    pub share_ttl_blocks: u64,
    pub cutover_delay_blocks: u64,
    pub quarantine_blocks: u64,
    pub sponsor_rebate_bps: u64,
    pub max_rebate_micronero: u64,
    pub require_falcon_backstop: bool,
    pub require_dual_transcript_roots: bool,
    pub allow_fee_sponsor_rebates: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            network: "devnet".to_string(),
            chain_id: 31337,
            l2_chain_id: 731337,
            activation_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_signer_cohort: DEFAULT_MIN_SIGNER_COHORT,
            default_threshold: DEFAULT_THRESHOLD,
            watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            cutover_quorum_bps: DEFAULT_CUTOVER_QUORUM_BPS,
            share_ttl_blocks: DEFAULT_SHARE_TTL_BLOCKS,
            cutover_delay_blocks: DEFAULT_CUTOVER_DELAY_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            max_rebate_micronero: DEFAULT_MAX_REBATE_MICRONERO,
            require_falcon_backstop: true,
            require_dual_transcript_roots: true,
            allow_fee_sponsor_rebates: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "network": self.network,
            "chain_id": self.chain_id,
            "l2_chain_id": self.l2_chain_id,
            "activation_height": self.activation_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_signer_cohort": self.min_signer_cohort,
            "default_threshold": self.default_threshold,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "cutover_quorum_bps": self.cutover_quorum_bps,
            "share_ttl_blocks": self.share_ttl_blocks,
            "cutover_delay_blocks": self.cutover_delay_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "max_rebate_micronero": self.max_rebate_micronero,
            "require_falcon_backstop": self.require_falcon_backstop,
            "require_dual_transcript_roots": self.require_dual_transcript_roots,
            "allow_fee_sponsor_rebates": self.allow_fee_sponsor_rebates,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub ceremonies: u64,
    pub active_ceremonies: u64,
    pub signer_cohorts: u64,
    pub threshold_shares: u64,
    pub verified_shares: u64,
    pub cutover_votes: u64,
    pub watcher_attestations: u64,
    pub watcher_vetoes: u64,
    pub quarantines: u64,
    pub slashes: u64,
    pub sponsor_rebates: u64,
    pub total_rebate_micronero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "ceremonies": self.ceremonies,
            "active_ceremonies": self.active_ceremonies,
            "signer_cohorts": self.signer_cohorts,
            "threshold_shares": self.threshold_shares,
            "verified_shares": self.verified_shares,
            "cutover_votes": self.cutover_votes,
            "watcher_attestations": self.watcher_attestations,
            "watcher_vetoes": self.watcher_vetoes,
            "quarantines": self.quarantines,
            "slashes": self.slashes,
            "sponsor_rebates": self.sponsor_rebates,
            "total_rebate_micronero": self.total_rebate_micronero,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-COUNTERS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub ceremony_root: String,
    pub cohort_root: String,
    pub share_root: String,
    pub vote_root: String,
    pub attestation_root: String,
    pub slashing_root: String,
    pub rebate_root: String,
    pub quarantine_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "ceremony_root": self.ceremony_root,
            "cohort_root": self.cohort_root,
            "share_root": self.share_root,
            "vote_root": self.vote_root,
            "attestation_root": self.attestation_root,
            "slashing_root": self.slashing_root,
            "rebate_root": self.rebate_root,
            "quarantine_root": self.quarantine_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerCohort {
    pub cohort_id: String,
    pub label: String,
    pub purpose: CeremonyPurpose,
    pub signer_commitments: BTreeMap<String, String>,
    pub threshold: u16,
    pub weight_bps: u64,
    pub quarantine_until_height: Option<u64>,
}

impl SignerCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "label": self.label,
            "purpose": self.purpose.as_str(),
            "signer_count": self.signer_commitments.len(),
            "signer_commitment_root": merkle_string_root("ML-DSA-CEREMONY-SIGNERS", self.signer_commitments.values()),
            "threshold": self.threshold,
            "weight_bps": self.weight_bps,
            "quarantine_until_height": self.quarantine_until_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-COHORT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyCeremony {
    pub ceremony_id: String,
    pub purpose: CeremonyPurpose,
    pub status: CeremonyStatus,
    pub primary_family: PqSignatureFamily,
    pub backstop_family: PqSignatureFamily,
    pub cohort_id: String,
    pub legacy_key_commitment: String,
    pub pq_public_key_commitment: String,
    pub ml_dsa_transcript_root: String,
    pub falcon_transcript_root: String,
    pub threshold: u16,
    pub total_signers: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub cutover_height: Option<u64>,
}

impl KeyCeremony {
    pub fn public_record(&self) -> Value {
        json!({
            "ceremony_id": self.ceremony_id,
            "purpose": self.purpose.as_str(),
            "status": self.status.as_str(),
            "primary_family": self.primary_family.as_str(),
            "backstop_family": self.backstop_family.as_str(),
            "primary_security_bits": self.primary_family.pq_security_bits(),
            "backstop_security_bits": self.backstop_family.pq_security_bits(),
            "cohort_id": self.cohort_id,
            "legacy_key_commitment": self.legacy_key_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "ml_dsa_transcript_root": self.ml_dsa_transcript_root,
            "falcon_transcript_root": self.falcon_transcript_root,
            "threshold": self.threshold,
            "total_signers": self.total_signers,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "cutover_height": self.cutover_height,
        })
    }

    pub fn operator_summary(&self) -> Value {
        json!({
            "ceremony_id": self.ceremony_id,
            "purpose": self.purpose.as_str(),
            "status": self.status.as_str(),
            "cohort_id": self.cohort_id,
            "threshold": self.threshold,
            "total_signers": self.total_signers,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "cutover_height": self.cutover_height,
            "redacted": [
                "legacy_key_material",
                "signer_share_openings",
                "witness_network_addresses"
            ],
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThresholdShare {
    pub share_id: String,
    pub ceremony_id: String,
    pub signer_id: String,
    pub family: PqSignatureFamily,
    pub encrypted_share_commitment: String,
    pub share_proof_root: String,
    pub nullifier: String,
    pub status: ShareStatus,
    pub submitted_at_height: u64,
}

impl ThresholdShare {
    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "ceremony_id": self.ceremony_id,
            "signer_id": self.signer_id,
            "family": self.family.as_str(),
            "encrypted_share_commitment": self.encrypted_share_commitment,
            "share_proof_root": self.share_proof_root,
            "nullifier": self.nullifier,
            "status": self.status,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-SHARE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationCutoverBallot {
    pub ballot_id: String,
    pub ceremony_id: String,
    pub voter_id: String,
    pub vote: CutoverVote,
    pub voting_weight_bps: u64,
    pub cutover_root: String,
    pub submitted_at_height: u64,
}

impl MigrationCutoverBallot {
    pub fn public_record(&self) -> Value {
        json!({
            "ballot_id": self.ballot_id,
            "ceremony_id": self.ceremony_id,
            "voter_id": self.voter_id,
            "vote": self.vote,
            "voting_weight_bps": self.voting_weight_bps,
            "cutover_root": self.cutover_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-CUTOVER-VOTE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub ceremony_id: String,
    pub watcher_id: String,
    pub verdict: AttestationVerdict,
    pub transcript_root: String,
    pub evidence_root: String,
    pub stake_weight_bps: u64,
    pub observed_at_height: u64,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "ceremony_id": self.ceremony_id,
            "watcher_id": self.watcher_id,
            "verdict": self.verdict,
            "transcript_root": self.transcript_root,
            "evidence_root": self.evidence_root,
            "stake_weight_bps": self.stake_weight_bps,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-WATCHER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingRecord {
    pub slashing_id: String,
    pub ceremony_id: String,
    pub offender_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub slash_amount_atomic: u128,
    pub quarantine_until_height: u64,
    pub resolved: bool,
}

impl SlashingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "ceremony_id": self.ceremony_id,
            "offender_id": self.offender_id,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "slash_amount_atomic": self.slash_amount_atomic,
            "quarantine_until_height": self.quarantine_until_height,
            "resolved": self.resolved,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-SLASHING",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeSponsorRebate {
    pub rebate_id: String,
    pub ceremony_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micronero: u64,
    pub rebate_micronero: u64,
    pub rebate_root: String,
    pub settled_at_height: u64,
}

impl FeeSponsorRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "ceremony_id": self.ceremony_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_paid_micronero": self.fee_paid_micronero,
            "rebate_micronero": self.rebate_micronero,
            "rebate_root": self.rebate_root,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-REBATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub ceremonies: BTreeMap<String, KeyCeremony>,
    pub cohorts: BTreeMap<String, SignerCohort>,
    pub shares: BTreeMap<String, ThresholdShare>,
    pub cutover_votes: BTreeMap<String, MigrationCutoverBallot>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
    pub fee_sponsor_rebates: BTreeMap<String, FeeSponsorRebate>,
    pub quarantined_subjects: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            ceremonies: BTreeMap::new(),
            cohorts: BTreeMap::new(),
            shares: BTreeMap::new(),
            cutover_votes: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            fee_sponsor_rebates: BTreeMap::new(),
            quarantined_subjects: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet());
        let cohort = SignerCohort {
            cohort_id: "cohort-devnet-reserve-0".to_string(),
            label: "devnet reserve ceremony signers".to_string(),
            purpose: CeremonyPurpose::BridgeReserve,
            signer_commitments: (0..11)
                .map(|index| {
                    let signer = format!("devnet-signer-{index:02}");
                    let commitment = commitment("SIGNER", &[&signer, "ml-dsa-falcon"]);
                    (signer, commitment)
                })
                .collect(),
            threshold: DEFAULT_THRESHOLD,
            weight_bps: MAX_BPS,
            quarantine_until_height: None,
        };
        state.register_cohort(cohort)?;

        let ceremony = KeyCeremony {
            ceremony_id: "ceremony-devnet-ml-dsa-reserve-0".to_string(),
            purpose: CeremonyPurpose::BridgeReserve,
            status: CeremonyStatus::CohortRegistered,
            primary_family: PqSignatureFamily::MlDsa87,
            backstop_family: PqSignatureFamily::Falcon1024,
            cohort_id: "cohort-devnet-reserve-0".to_string(),
            legacy_key_commitment: commitment("LEGACY", &["monero-spend-key", "reserve-0"]),
            pq_public_key_commitment: commitment("PQ-PUBKEY", &["ml-dsa-87", "reserve-0"]),
            ml_dsa_transcript_root: commitment("TRANSCRIPT", &["ml-dsa", "round-0"]),
            falcon_transcript_root: commitment("TRANSCRIPT", &["falcon", "round-0"]),
            threshold: DEFAULT_THRESHOLD,
            total_signers: 11,
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_SHARE_TTL_BLOCKS,
            cutover_height: Some(DEVNET_HEIGHT + DEFAULT_CUTOVER_DELAY_BLOCKS),
        };
        state.open_ceremony(ceremony)?;

        for index in 0..8 {
            state.record_share(ThresholdShare {
                share_id: format!("share-devnet-{index:02}"),
                ceremony_id: "ceremony-devnet-ml-dsa-reserve-0".to_string(),
                signer_id: format!("devnet-signer-{index:02}"),
                family: if index % 2 == 0 {
                    PqSignatureFamily::MlDsa87
                } else {
                    PqSignatureFamily::Falcon1024
                },
                encrypted_share_commitment: commitment("ENC-SHARE", &[&index.to_string()]),
                share_proof_root: commitment("SHARE-PROOF", &[&index.to_string()]),
                nullifier: commitment("SHARE-NULLIFIER", &[&index.to_string()]),
                status: ShareStatus::Verified,
                submitted_at_height: DEVNET_HEIGHT + 4 + index,
            })?;
        }

        for index in 0..5 {
            state.record_watcher_attestation(WatcherAttestation {
                attestation_id: format!("watcher-attestation-devnet-{index:02}"),
                ceremony_id: "ceremony-devnet-ml-dsa-reserve-0".to_string(),
                watcher_id: format!("watcher-{index:02}"),
                verdict: AttestationVerdict::Observed,
                transcript_root: commitment("WATCHER-TRANSCRIPT", &[&index.to_string()]),
                evidence_root: commitment("WATCHER-EVIDENCE", &[&index.to_string()]),
                stake_weight_bps: 1_600,
                observed_at_height: DEVNET_HEIGHT + 16 + index,
            })?;
        }

        for index in 0..9 {
            state.record_cutover_vote(MigrationCutoverBallot {
                ballot_id: format!("cutover-ballot-devnet-{index:02}"),
                ceremony_id: "ceremony-devnet-ml-dsa-reserve-0".to_string(),
                voter_id: format!("devnet-signer-{index:02}"),
                vote: CutoverVote::Approve,
                voting_weight_bps: 1_100,
                cutover_root: commitment("CUTOVER", &[&index.to_string()]),
                submitted_at_height: DEVNET_HEIGHT + 48 + index,
            })?;
        }

        state.record_fee_sponsor_rebate(FeeSponsorRebate {
            rebate_id: "rebate-devnet-0".to_string(),
            ceremony_id: "ceremony-devnet-ml-dsa-reserve-0".to_string(),
            sponsor_id: "devnet-sponsor-low-fee".to_string(),
            beneficiary_commitment: commitment("BENEFICIARY", &["reserve-operators"]),
            fee_paid_micronero: 42_000,
            rebate_micronero: 35_700,
            rebate_root: commitment("REBATE", &["devnet", "0"]),
            settled_at_height: DEVNET_HEIGHT + 64,
        })?;

        state.refresh_statuses();
        state.refresh_roots();
        Ok(state)
    }

    pub fn demo() -> Result<Self> {
        Self::devnet()
    }

    pub fn register_cohort(&mut self, cohort: SignerCohort) -> Result<String> {
        if cohort.signer_commitments.len() < self.config.min_signer_cohort as usize {
            return Err("signer cohort below configured quantum-safe minimum".to_string());
        }
        if cohort.threshold == 0 || cohort.threshold as usize > cohort.signer_commitments.len() {
            return Err("invalid threshold for signer cohort".to_string());
        }
        let id = cohort.cohort_id.clone();
        self.cohorts.insert(id.clone(), cohort);
        self.counters.signer_cohorts = self.cohorts.len() as u64;
        self.refresh_roots();
        Ok(id)
    }

    pub fn open_ceremony(&mut self, ceremony: KeyCeremony) -> Result<String> {
        if ceremony.primary_family.pq_security_bits() < self.config.min_pq_security_bits {
            return Err("primary ML-DSA family below minimum PQ security bits".to_string());
        }
        if self.config.require_falcon_backstop
            && ceremony.backstop_family.pq_security_bits() < self.config.min_pq_security_bits
        {
            return Err("Falcon backstop below minimum PQ security bits".to_string());
        }
        if !self.cohorts.contains_key(&ceremony.cohort_id) {
            return Err("missing signer cohort for ceremony".to_string());
        }
        let id = ceremony.ceremony_id.clone();
        self.ceremonies.insert(id.clone(), ceremony);
        self.refresh_statuses();
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_share(&mut self, share: ThresholdShare) -> Result<String> {
        let ceremony = self
            .ceremonies
            .get(&share.ceremony_id)
            .ok_or_else(|| "missing ceremony for threshold share".to_string())?;
        if !ceremony.status.accepts_shares() && !matches!(share.status, ShareStatus::Quarantined) {
            return Err("ceremony no longer accepts threshold shares".to_string());
        }
        let id = share.share_id.clone();
        self.shares.insert(id.clone(), share);
        self.refresh_statuses();
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_cutover_vote(&mut self, ballot: MigrationCutoverBallot) -> Result<String> {
        if !self.ceremonies.contains_key(&ballot.ceremony_id) {
            return Err("missing ceremony for cutover vote".to_string());
        }
        let id = ballot.ballot_id.clone();
        self.cutover_votes.insert(id.clone(), ballot);
        self.refresh_statuses();
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_watcher_attestation(
        &mut self,
        attestation: WatcherAttestation,
    ) -> Result<String> {
        if !self.ceremonies.contains_key(&attestation.ceremony_id) {
            return Err("missing ceremony for watcher attestation".to_string());
        }
        let id = attestation.attestation_id.clone();
        self.watcher_attestations.insert(id.clone(), attestation);
        self.refresh_statuses();
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_slashing(&mut self, slashing: SlashingRecord) -> Result<String> {
        if !self.ceremonies.contains_key(&slashing.ceremony_id) {
            return Err("missing ceremony for slashing record".to_string());
        }
        self.quarantined_subjects
            .insert(slashing.offender_id.clone());
        let id = slashing.slashing_id.clone();
        self.slashing_records.insert(id.clone(), slashing);
        self.refresh_statuses();
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_fee_sponsor_rebate(&mut self, rebate: FeeSponsorRebate) -> Result<String> {
        if !self.config.allow_fee_sponsor_rebates {
            return Err("fee sponsor rebates disabled".to_string());
        }
        if rebate.rebate_micronero > self.config.max_rebate_micronero {
            return Err("fee sponsor rebate exceeds configured cap".to_string());
        }
        if !self.ceremonies.contains_key(&rebate.ceremony_id) {
            return Err("missing ceremony for fee sponsor rebate".to_string());
        }
        let id = rebate.rebate_id.clone();
        self.fee_sponsor_rebates.insert(id.clone(), rebate);
        self.refresh_statuses();
        self.refresh_roots();
        Ok(id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.state_root(),
            ceremony_root: merkle_values_root(
                "ML-DSA-CEREMONY-SET",
                self.ceremonies.values().map(KeyCeremony::public_record),
            ),
            cohort_root: merkle_values_root(
                "ML-DSA-CEREMONY-COHORT-SET",
                self.cohorts.values().map(SignerCohort::public_record),
            ),
            share_root: merkle_values_root(
                "ML-DSA-CEREMONY-SHARE-SET",
                self.shares.values().map(ThresholdShare::public_record),
            ),
            vote_root: merkle_values_root(
                "ML-DSA-CEREMONY-VOTE-SET",
                self.cutover_votes
                    .values()
                    .map(MigrationCutoverBallot::public_record),
            ),
            attestation_root: merkle_values_root(
                "ML-DSA-CEREMONY-ATTESTATION-SET",
                self.watcher_attestations
                    .values()
                    .map(WatcherAttestation::public_record),
            ),
            slashing_root: merkle_values_root(
                "ML-DSA-CEREMONY-SLASHING-SET",
                self.slashing_records
                    .values()
                    .map(SlashingRecord::public_record),
            ),
            rebate_root: merkle_values_root(
                "ML-DSA-CEREMONY-REBATE-SET",
                self.fee_sponsor_rebates
                    .values()
                    .map(FeeSponsorRebate::public_record),
            ),
            quarantine_root: merkle_values_root(
                "ML-DSA-CEREMONY-QUARANTINE-SET",
                self.quarantined_subjects
                    .iter()
                    .map(|subject| json!({ "subject": subject })),
            ),
            counters_root: self.counters.state_root(),
        };
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ML-DSA-CEREMONY-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "primary_signature_suite": PRIMARY_SIGNATURE_SUITE,
            "secondary_signature_suite": SECONDARY_SIGNATURE_SUITE,
            "hybrid_cutover_suite": HYBRID_CUTOVER_SUITE,
            "confidential_share_scheme": CONFIDENTIAL_SHARE_SCHEME,
            "watcher_attestation_scheme": WATCHER_ATTESTATION_SCHEME,
            "slashing_scheme": SLASHING_SCHEME,
            "fee_rebate_scheme": FEE_REBATE_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.roots.state_root(),
            "active_ceremony_ids": self.active_ceremony_ids(),
            "quarantined_subject_count": self.quarantined_subjects.len(),
        })
    }

    pub fn operator_summary(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "state_root": self.state_root(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "ceremonies": self.ceremonies
                .values()
                .map(KeyCeremony::operator_summary)
                .collect::<Vec<_>>(),
            "redaction_policy": {
                "share_material": "redacted",
                "beneficiary_identifiers": "commitment_only",
                "watcher_network_metadata": "redacted",
                "operator_action": "safe_to_log"
            },
        })
    }

    pub fn public_root_summary(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "state_root": self.state_root(),
            "config_root": self.roots.config_root,
            "ceremony_root": self.roots.ceremony_root,
            "share_root": self.roots.share_root,
            "vote_root": self.roots.vote_root,
            "attestation_root": self.roots.attestation_root,
            "slashing_root": self.roots.slashing_root,
            "rebate_root": self.roots.rebate_root,
            "counters": self.counters.public_record(),
        })
    }

    fn active_ceremony_ids(&self) -> Vec<String> {
        self.ceremonies
            .values()
            .filter(|ceremony| !ceremony.status.terminal())
            .map(|ceremony| ceremony.ceremony_id.clone())
            .collect()
    }

    fn refresh_statuses(&mut self) {
        let verified_shares = self
            .shares
            .values()
            .filter(|share| matches!(share.status, ShareStatus::Verified))
            .count() as u64;
        let watcher_vetoes = self
            .watcher_attestations
            .values()
            .filter(|attestation| !attestation.verdict.is_positive())
            .count() as u64;
        self.counters = Counters {
            ceremonies: self.ceremonies.len() as u64,
            active_ceremonies: self
                .ceremonies
                .values()
                .filter(|ceremony| matches!(ceremony.status, CeremonyStatus::Active))
                .count() as u64,
            signer_cohorts: self.cohorts.len() as u64,
            threshold_shares: self.shares.len() as u64,
            verified_shares,
            cutover_votes: self.cutover_votes.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            watcher_vetoes,
            quarantines: self.quarantined_subjects.len() as u64,
            slashes: self.slashing_records.len() as u64,
            sponsor_rebates: self.fee_sponsor_rebates.len() as u64,
            total_rebate_micronero: self
                .fee_sponsor_rebates
                .values()
                .map(|rebate| rebate.rebate_micronero as u128)
                .sum(),
        };

        let updates = self
            .ceremonies
            .iter()
            .map(|(id, ceremony)| {
                let share_count = self
                    .shares
                    .values()
                    .filter(|share| {
                        share.ceremony_id == *id && matches!(share.status, ShareStatus::Verified)
                    })
                    .count() as u16;
                let positive_watcher_weight = self
                    .watcher_attestations
                    .values()
                    .filter(|attestation| {
                        attestation.ceremony_id == *id && attestation.verdict.is_positive()
                    })
                    .map(|attestation| attestation.stake_weight_bps)
                    .sum::<u64>();
                let approval_weight = self
                    .cutover_votes
                    .values()
                    .filter(|vote| {
                        vote.ceremony_id == *id && matches!(vote.vote, CutoverVote::Approve)
                    })
                    .map(|vote| vote.voting_weight_bps)
                    .sum::<u64>();
                let ceremony_vetoes = self
                    .watcher_attestations
                    .values()
                    .filter(|attestation| {
                        attestation.ceremony_id == *id && !attestation.verdict.is_positive()
                    })
                    .count();
                let slashed = self
                    .slashing_records
                    .values()
                    .any(|slashing| slashing.ceremony_id == *id && !slashing.resolved);

                let status = if slashed {
                    CeremonyStatus::Slashed
                } else if ceremony_vetoes > 0 {
                    CeremonyStatus::Quarantined
                } else if approval_weight >= self.config.cutover_quorum_bps {
                    CeremonyStatus::Active
                } else if positive_watcher_weight >= self.config.watcher_quorum_bps {
                    CeremonyStatus::CutoverReady
                } else if share_count >= ceremony.threshold {
                    CeremonyStatus::WatcherAttested
                } else if share_count > 0 {
                    CeremonyStatus::SharesCommitted
                } else {
                    ceremony.status
                };
                (id.clone(), status)
            })
            .collect::<Vec<_>>();

        for (id, status) in updates {
            if let Some(ceremony) = self.ceremonies.get_mut(&id) {
                ceremony.status = status;
            }
        }
        self.counters.active_ceremonies = self
            .ceremonies
            .values()
            .filter(|ceremony| matches!(ceremony.status, CeremonyStatus::Active))
            .count() as u64;
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn demo() -> Result<State> {
    State::demo()
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

fn merkle_values_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = values.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_string_root<'a, I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = &'a String>,
{
    let leaves = values
        .into_iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
