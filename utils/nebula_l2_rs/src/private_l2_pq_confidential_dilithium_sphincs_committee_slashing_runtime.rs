use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialDilithiumSphincsCommitteeSlashingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DILITHIUM_SPHINCS_COMMITTEE_SLASHING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-dilithium-sphincs-committee-slashing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_DILITHIUM_SPHINCS_COMMITTEE_SLASHING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DILITHIUM_SUITE: &str = "ML-DSA-87-committee-slashing-evidence-v1";
pub const SPHINCS_PLUS_SUITE: &str = "SLH-DSA-SHAKE-256f-committee-witness-v1";
pub const HYBRID_EVIDENCE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-slashing-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "private-low-fee-batched-dispute-window-root-v1";
pub const OFFENDER_BUCKET_SUITE: &str = "privacy-preserving-offender-bucket-root-v1";
pub const SLASHING_VERDICT_SUITE: &str = "pq-confidential-committee-slashing-verdict-root-v1";
pub const DEVNET_HEIGHT: u64 = 5_420_000;
pub const DEVNET_EPOCH: u64 = 21_680;
pub const DEVNET_SLOT: u64 = 144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 13;
pub const DEFAULT_THRESHOLD: u16 = 9;
pub const DEFAULT_DISPUTE_WINDOW_SLOTS: u64 = 720;
pub const DEFAULT_BATCH_SIZE_LIMIT: u16 = 128;
pub const DEFAULT_MAX_BATCH_FEE_MICRO_UNITS: u64 = 12_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MINOR_SLASH_BPS: u64 = 600;
pub const DEFAULT_MAJOR_SLASH_BPS: u64 = 2_800;
pub const DEFAULT_PRIVACY_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_400;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Sequencer,
    Prover,
    Watchtower,
    BridgeRelayer,
    DataAvailability,
    RecoveryGuardian,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Prover => "prover",
            Self::Watchtower => "watchtower",
            Self::BridgeRelayer => "bridge_relayer",
            Self::DataAvailability => "data_availability",
            Self::RecoveryGuardian => "recovery_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Equivocation,
    InvalidVote,
    WithheldShare,
    InvalidDilithiumSignature,
    InvalidSphincsWitness,
    PrivacyBoundaryLeak,
    BatchFeeOvercharge,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::InvalidVote => "invalid_vote",
            Self::WithheldShare => "withheld_share",
            Self::InvalidDilithiumSignature => "invalid_dilithium_signature",
            Self::InvalidSphincsWitness => "invalid_sphincs_witness",
            Self::PrivacyBoundaryLeak => "privacy_boundary_leak",
            Self::BatchFeeOvercharge => "batch_fee_overcharge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Batched,
    EvidenceSealed,
    CommitteeAttesting,
    VerdictReady,
    Settled,
    Rejected,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Batched => "batched",
            Self::EvidenceSealed => "evidence_sealed",
            Self::CommitteeAttesting => "committee_attesting",
            Self::VerdictReady => "verdict_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictDecision {
    Dismiss,
    Warning,
    MinorSlash,
    MajorSlash,
    PrivacySlash,
    Quarantine,
}

impl VerdictDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dismiss => "dismiss",
            Self::Warning => "warning",
            Self::MinorSlash => "minor_slash",
            Self::MajorSlash => "major_slash",
            Self::PrivacySlash => "privacy_slash",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub dilithium_suite: String,
    pub sphincs_plus_suite: String,
    pub hybrid_evidence_suite: String,
    pub low_fee_batch_suite: String,
    pub offender_bucket_suite: String,
    pub committee_size: u16,
    pub threshold: u16,
    pub min_pq_security_bits: u16,
    pub dispute_window_slots: u64,
    pub batch_size_limit: u16,
    pub max_batch_fee_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub minor_slash_bps: u64,
    pub major_slash_bps: u64,
    pub privacy_slash_bps: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
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
            network: "nebula-private-l2-devnet".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            dilithium_suite: DILITHIUM_SUITE.to_string(),
            sphincs_plus_suite: SPHINCS_PLUS_SUITE.to_string(),
            hybrid_evidence_suite: HYBRID_EVIDENCE_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            offender_bucket_suite: OFFENDER_BUCKET_SUITE.to_string(),
            committee_size: DEFAULT_COMMITTEE_SIZE,
            threshold: DEFAULT_THRESHOLD,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            dispute_window_slots: DEFAULT_DISPUTE_WINDOW_SLOTS,
            batch_size_limit: DEFAULT_BATCH_SIZE_LIMIT,
            max_batch_fee_micro_units: DEFAULT_MAX_BATCH_FEE_MICRO_UNITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            minor_slash_bps: DEFAULT_MINOR_SLASH_BPS,
            major_slash_bps: DEFAULT_MAJOR_SLASH_BPS,
            privacy_slash_bps: DEFAULT_PRIVACY_SLASH_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.threshold == 0 || self.threshold > self.committee_size {
            return Err("invalid committee threshold".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime minimum".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set below minimum".to_string());
        }
        for (label, value) in [
            ("minor_slash_bps", self.minor_slash_bps),
            ("major_slash_bps", self.major_slash_bps),
            ("privacy_slash_bps", self.privacy_slash_bps),
            ("quorum_bps", self.quorum_bps),
            ("strong_quorum_bps", self.strong_quorum_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{label} exceeds basis point denominator"));
            }
        }
        if self.minor_slash_bps > self.major_slash_bps
            || self.major_slash_bps > self.privacy_slash_bps
        {
            return Err("slash bps ladder is not monotonic".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committee_members: u64,
    pub dispute_windows: u64,
    pub slashing_disputes: u64,
    pub hybrid_evidence: u64,
    pub committee_attestations: u64,
    pub offender_buckets: u64,
    pub slashing_verdicts: u64,
    pub total_batch_fee_micro_units: u64,
    pub total_slashed_micro_units: u64,
    pub privacy_safe_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub committee_member_root: String,
    pub dispute_window_root: String,
    pub slashing_dispute_root: String,
    pub hybrid_evidence_root: String,
    pub committee_attestation_root: String,
    pub offender_bucket_root: String,
    pub slashing_verdict_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub role: CommitteeRole,
    pub operator_commitment: String,
    pub dilithium_key_root: String,
    pub sphincs_key_root: String,
    pub bond_commitment: String,
    pub bond_micro_units: u64,
    pub active: bool,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "role": self.role.as_str(),
            "operator_commitment": self.operator_commitment,
            "dilithium_key_root": self.dilithium_key_root,
            "sphincs_key_root": self.sphincs_key_root,
            "bond_commitment": self.bond_commitment,
            "bond_micro_units": self.bond_micro_units,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeWindow {
    pub window_id: String,
    pub opens_slot: u64,
    pub closes_slot: u64,
    pub batch_index: u64,
    pub max_disputes: u16,
    pub fee_cap_micro_units: u64,
    pub dispute_ids: BTreeSet<String>,
}

impl DisputeWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingDispute {
    pub dispute_id: String,
    pub window_id: String,
    pub offender_bucket_id: String,
    pub reporter_commitment: String,
    pub evidence_kind: EvidenceKind,
    pub status: DisputeStatus,
    pub submitted_slot: u64,
    pub batch_fee_micro_units: u64,
    pub requested_slash_bps: u64,
}

impl SlashingDispute {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "window_id": self.window_id,
            "offender_bucket_id": self.offender_bucket_id,
            "reporter_commitment": self.reporter_commitment,
            "evidence_kind": self.evidence_kind.as_str(),
            "status": self.status.as_str(),
            "submitted_slot": self.submitted_slot,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "requested_slash_bps": self.requested_slash_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HybridEvidence {
    pub evidence_id: String,
    pub dispute_id: String,
    pub sealed_payload_root: String,
    pub redacted_payload_root: String,
    pub dilithium_signature_root: String,
    pub sphincs_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
}

impl HybridEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub dispute_id: String,
    pub member_id: String,
    pub supports_slash: bool,
    pub dilithium_vote_root: String,
    pub sphincs_witness_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

impl CommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OffenderBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub role: CommitteeRole,
    pub offender_commitment_root: String,
    pub anonymity_set_root: String,
    pub privacy_set_size: u64,
    pub open_disputes: u64,
    pub sealed: bool,
}

impl OffenderBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "role": self.role.as_str(),
            "offender_commitment_root": self.offender_commitment_root,
            "anonymity_set_root": self.anonymity_set_root,
            "privacy_set_size": self.privacy_set_size,
            "open_disputes": self.open_disputes,
            "sealed": self.sealed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingVerdict {
    pub verdict_id: String,
    pub dispute_id: String,
    pub decision: VerdictDecision,
    pub slash_bps: u64,
    pub slashed_micro_units: u64,
    pub settlement_root: String,
    pub published_slot: u64,
}

impl SlashingVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "dispute_id": self.dispute_id,
            "decision": self.decision.as_str(),
            "slash_bps": self.slash_bps,
            "slashed_micro_units": self.slashed_micro_units,
            "settlement_root": self.settlement_root,
            "published_slot": self.published_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub committee_members: BTreeMap<String, CommitteeMember>,
    pub dispute_windows: BTreeMap<String, DisputeWindow>,
    pub slashing_disputes: BTreeMap<String, SlashingDispute>,
    pub hybrid_evidence: BTreeMap<String, HybridEvidence>,
    pub committee_attestations: BTreeMap<String, CommitteeAttestation>,
    pub offender_buckets: BTreeMap<String, OffenderBucket>,
    pub slashing_verdicts: BTreeMap<String, SlashingVerdict>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64, slot: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            slot,
            counters: Counters::default(),
            roots: Roots::default(),
            committee_members: BTreeMap::new(),
            dispute_windows: BTreeMap::new(),
            slashing_disputes: BTreeMap::new(),
            hybrid_evidence: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            offender_buckets: BTreeMap::new(),
            slashing_verdicts: BTreeMap::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH, DEVNET_SLOT)
            .unwrap_or_else(|_| Self::empty_devnet());
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    fn seed_devnet(&mut self) {
        for index in 0..self.config.committee_size {
            let role = match index % 6 {
                0 => CommitteeRole::Sequencer,
                1 => CommitteeRole::Prover,
                2 => CommitteeRole::Watchtower,
                3 => CommitteeRole::BridgeRelayer,
                4 => CommitteeRole::DataAvailability,
                _ => CommitteeRole::RecoveryGuardian,
            };
            let member_id = format!("dilithium-sphincs-member-devnet-{index:04}");
            self.committee_members.insert(
                member_id.clone(),
                CommitteeMember {
                    member_id: member_id.clone(),
                    role,
                    operator_commitment: sample_root("operator", u64::from(index)),
                    dilithium_key_root: sample_root("dilithium-key", u64::from(index)),
                    sphincs_key_root: sample_root("sphincs-key", u64::from(index)),
                    bond_commitment: sample_root("bond", u64::from(index)),
                    bond_micro_units: 40_000_000 + u64::from(index) * 1_000_000,
                    active: true,
                },
            );
        }

        let bucket_id = deterministic_id("offender-bucket", &[HashPart::U64(self.epoch)]);
        self.offender_buckets.insert(
            bucket_id.clone(),
            OffenderBucket {
                bucket_id: bucket_id.clone(),
                epoch: self.epoch,
                role: CommitteeRole::Sequencer,
                offender_commitment_root: sample_root("offender-commitment", 0),
                anonymity_set_root: sample_root("offender-anonymity-set", 0),
                privacy_set_size: self.config.target_privacy_set_size,
                open_disputes: 1,
                sealed: false,
            },
        );

        let window_id = deterministic_id("dispute-window", &[HashPart::U64(self.slot)]);
        let dispute_id = deterministic_id("slashing-dispute", &[HashPart::Str(&window_id)]);
        self.dispute_windows.insert(
            window_id.clone(),
            DisputeWindow {
                window_id: window_id.clone(),
                opens_slot: self.slot,
                closes_slot: self.slot + self.config.dispute_window_slots,
                batch_index: 0,
                max_disputes: self.config.batch_size_limit,
                fee_cap_micro_units: self.config.max_batch_fee_micro_units,
                dispute_ids: [dispute_id.clone()].into_iter().collect(),
            },
        );
        self.slashing_disputes.insert(
            dispute_id.clone(),
            SlashingDispute {
                dispute_id: dispute_id.clone(),
                window_id: window_id.clone(),
                offender_bucket_id: bucket_id,
                reporter_commitment: sample_root("reporter", 0),
                evidence_kind: EvidenceKind::Equivocation,
                status: DisputeStatus::VerdictReady,
                submitted_slot: self.slot + 1,
                batch_fee_micro_units: 1_200,
                requested_slash_bps: self.config.minor_slash_bps,
            },
        );
        self.hybrid_evidence.insert(
            "hybrid-evidence-devnet-0000".to_string(),
            HybridEvidence {
                evidence_id: "hybrid-evidence-devnet-0000".to_string(),
                dispute_id: dispute_id.clone(),
                sealed_payload_root: sample_root("sealed-payload", 0),
                redacted_payload_root: sample_root("redacted-payload", 0),
                dilithium_signature_root: sample_root("dilithium-evidence-signature", 0),
                sphincs_signature_root: sample_root("sphincs-evidence-signature", 0),
                transcript_root: sample_root("evidence-transcript", 0),
                pq_security_bits: self.config.min_pq_security_bits,
            },
        );
        for index in 0..self.config.threshold {
            let member_id = format!("dilithium-sphincs-member-devnet-{index:04}");
            let attestation_id = deterministic_id(
                "committee-attestation",
                &[HashPart::Str(&dispute_id), HashPart::U64(u64::from(index))],
            );
            self.committee_attestations.insert(
                attestation_id.clone(),
                CommitteeAttestation {
                    attestation_id,
                    dispute_id: dispute_id.clone(),
                    member_id,
                    supports_slash: true,
                    dilithium_vote_root: sample_root("dilithium-vote", u64::from(index)),
                    sphincs_witness_root: sample_root("sphincs-witness", u64::from(index)),
                    observed_slot: self.slot + 8 + u64::from(index),
                    quorum_weight_bps: self.config.strong_quorum_bps,
                },
            );
        }
        self.slashing_verdicts.insert(
            "slashing-verdict-devnet-0000".to_string(),
            SlashingVerdict {
                verdict_id: "slashing-verdict-devnet-0000".to_string(),
                dispute_id,
                decision: VerdictDecision::MinorSlash,
                slash_bps: self.config.minor_slash_bps,
                slashed_micro_units: 240_000,
                settlement_root: sample_root("settlement", 0),
                published_slot: self.slot + 24,
            },
        );
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            committee_members: self.committee_members.len() as u64,
            dispute_windows: self.dispute_windows.len() as u64,
            slashing_disputes: self.slashing_disputes.len() as u64,
            hybrid_evidence: self.hybrid_evidence.len() as u64,
            committee_attestations: self.committee_attestations.len() as u64,
            offender_buckets: self.offender_buckets.len() as u64,
            slashing_verdicts: self.slashing_verdicts.len() as u64,
            total_batch_fee_micro_units: self
                .slashing_disputes
                .values()
                .map(|dispute| dispute.batch_fee_micro_units)
                .sum(),
            total_slashed_micro_units: self
                .slashing_verdicts
                .values()
                .map(|verdict| verdict.slashed_micro_units)
                .sum(),
            privacy_safe_records: self
                .offender_buckets
                .values()
                .filter(|bucket| bucket.privacy_set_size >= self.config.min_privacy_set_size)
                .count() as u64,
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let committee_member_root = record_root(
            "committee-members",
            self.committee_members
                .values()
                .map(CommitteeMember::public_record)
                .collect(),
        );
        let dispute_window_root = record_root(
            "dispute-windows",
            self.dispute_windows
                .values()
                .map(DisputeWindow::public_record)
                .collect(),
        );
        let slashing_dispute_root = record_root(
            "slashing-disputes",
            self.slashing_disputes
                .values()
                .map(SlashingDispute::public_record)
                .collect(),
        );
        let hybrid_evidence_root = record_root(
            "hybrid-evidence",
            self.hybrid_evidence
                .values()
                .map(HybridEvidence::public_record)
                .collect(),
        );
        let committee_attestation_root = record_root(
            "committee-attestations",
            self.committee_attestations
                .values()
                .map(CommitteeAttestation::public_record)
                .collect(),
        );
        let offender_bucket_root = record_root(
            "offender-buckets",
            self.offender_buckets
                .values()
                .map(OffenderBucket::public_record)
                .collect(),
        );
        let slashing_verdict_root = record_root(
            "slashing-verdicts",
            self.slashing_verdicts
                .values()
                .map(SlashingVerdict::public_record)
                .collect(),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "committee_member_root": committee_member_root,
                "dispute_window_root": dispute_window_root,
                "slashing_dispute_root": slashing_dispute_root,
                "hybrid_evidence_root": hybrid_evidence_root,
                "committee_attestation_root": committee_attestation_root,
                "offender_bucket_root": offender_bucket_root,
                "slashing_verdict_root": slashing_verdict_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DILITHIUM-SPHINCS-COMMITTEE-SLASHING-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&public_record_root),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slot),
            ],
            32,
        );
        Roots {
            committee_member_root,
            dispute_window_root,
            slashing_dispute_root,
            hybrid_evidence_root,
            committee_attestation_root,
            offender_bucket_root,
            slashing_verdict_root,
            public_record_root,
            state_root,
        }
    }

    fn empty_devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            slot: DEVNET_SLOT,
            counters: Counters::default(),
            roots: Roots::default(),
            committee_members: BTreeMap::new(),
            dispute_windows: BTreeMap::new(),
            slashing_disputes: BTreeMap::new(),
            hybrid_evidence: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            offender_buckets: BTreeMap::new(),
            slashing_verdicts: BTreeMap::new(),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "height": state.height,
        "epoch": state.epoch,
        "slot": state.slot,
        "hash_suite": HASH_SUITE,
        "dilithium_suite": DILITHIUM_SUITE,
        "sphincs_plus_suite": SPHINCS_PLUS_SUITE,
        "hybrid_evidence_suite": HYBRID_EVIDENCE_SUITE,
        "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
        "offender_bucket_suite": OFFENDER_BUCKET_SUITE,
        "slashing_verdict_suite": SLASHING_VERDICT_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "committee_members": state
            .committee_members
            .values()
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>(),
        "dispute_windows": state
            .dispute_windows
            .values()
            .map(DisputeWindow::public_record)
            .collect::<Vec<_>>(),
        "slashing_disputes": state
            .slashing_disputes
            .values()
            .map(SlashingDispute::public_record)
            .collect::<Vec<_>>(),
        "hybrid_evidence": state
            .hybrid_evidence
            .values()
            .map(HybridEvidence::public_record)
            .collect::<Vec<_>>(),
        "committee_attestations": state
            .committee_attestations
            .values()
            .map(CommitteeAttestation::public_record)
            .collect::<Vec<_>>(),
        "offender_buckets": state
            .offender_buckets
            .values()
            .map(OffenderBucket::public_record)
            .collect::<Vec<_>>(),
        "slashing_verdicts": state
            .slashing_verdicts
            .values()
            .map(SlashingVerdict::public_record)
            .collect::<Vec<_>>(),
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-DILITHIUM-SPHINCS-COMMITTEE-SLASHING-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DILITHIUM-SPHINCS-COMMITTEE-SLASHING-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-DILITHIUM-SPHINCS-COMMITTEE-SLASHING-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-DILITHIUM-SPHINCS-COMMITTEE-SLASHING-{domain}"),
        &values,
    )
}
