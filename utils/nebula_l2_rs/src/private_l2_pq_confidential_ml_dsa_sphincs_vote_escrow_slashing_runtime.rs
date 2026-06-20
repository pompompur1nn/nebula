use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlDsaSphincsVoteEscrowSlashingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_SPHINCS_VOTE_ESCROW_SLASHING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-ml-dsa-sphincs-vote-escrow-slashing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_SPHINCS_VOTE_ESCROW_SLASHING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_DSA_SUITE: &str = "ML-DSA-87-vote-escrow-slashing-evidence-v1";
pub const SPHINCS_SUITE: &str = "SLH-DSA-SHAKE-256f-vote-escrow-witness-v1";
pub const HYBRID_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-vote-escrow-v1";
pub const PRIVATE_STAKE_BUCKET_SUITE: &str = "confidential-vote-escrow-stake-bucket-root-v1";
pub const EVIDENCE_WINDOW_SUITE: &str = "batched-vote-escrow-evidence-window-root-v1";
pub const DISPUTE_AMORTIZATION_SUITE: &str = "low-fee-vote-escrow-dispute-amortization-v1";
pub const SLASHING_SETTLEMENT_SUITE: &str = "confidential-vote-escrow-slashing-settlement-v1";
pub const DEVNET_HEIGHT: u64 = 6_180_000;
pub const DEVNET_EPOCH: u64 = 24_720;
pub const DEVNET_SLOT: u64 = 312;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ESCROW_OPERATOR_SET_SIZE: u16 = 17;
pub const DEFAULT_SLASH_THRESHOLD: u16 = 12;
pub const DEFAULT_EVIDENCE_WINDOW_SLOTS: u64 = 960;
pub const DEFAULT_MAX_EVIDENCE_PER_WINDOW: u16 = 192;
pub const DEFAULT_FEE_AMORTIZATION_BATCH_SIZE: u16 = 64;
pub const DEFAULT_MAX_DISPUTE_FEE_MICRO_UNITS: u64 = 9_500;
pub const DEFAULT_MIN_PRIVATE_BUCKET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVATE_BUCKET_SIZE: u64 = 524_288;
pub const DEFAULT_LOCKED_VOTE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_SLASH_QUORUM_BPS: u64 = 8_600;
pub const DEFAULT_SOFT_SLASH_BPS: u64 = 450;
pub const DEFAULT_HARD_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_PRIVACY_FAULT_SLASH_BPS: u64 = 5_500;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowRole {
    VoteEscrowValidator,
    DelegationAggregator,
    EvidenceWatcher,
    DisputeArbiter,
    SettlementRelay,
}

impl EscrowRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VoteEscrowValidator => "vote_escrow_validator",
            Self::DelegationAggregator => "delegation_aggregator",
            Self::EvidenceWatcher => "evidence_watcher",
            Self::DisputeArbiter => "dispute_arbiter",
            Self::SettlementRelay => "settlement_relay",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DoubleVote,
    LockExtensionForgery,
    DelegationReplay,
    InvalidMlDsaVote,
    InvalidSphincsWitness,
    PrivateBucketLeak,
    FeeAmortizationFraud,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleVote => "double_vote",
            Self::LockExtensionForgery => "lock_extension_forgery",
            Self::DelegationReplay => "delegation_replay",
            Self::InvalidMlDsaVote => "invalid_ml_dsa_vote",
            Self::InvalidSphincsWitness => "invalid_sphincs_witness",
            Self::PrivateBucketLeak => "private_bucket_leak",
            Self::FeeAmortizationFraud => "fee_amortization_fraud",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    WindowOpen,
    Batched,
    EvidenceSealed,
    ArbitersAttesting,
    SlashReady,
    Settled,
    Rejected,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowOpen => "window_open",
            Self::Batched => "batched",
            Self::EvidenceSealed => "evidence_sealed",
            Self::ArbitersAttesting => "arbiters_attesting",
            Self::SlashReady => "slash_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashDecision {
    Dismiss,
    Warning,
    SoftSlash,
    HardSlash,
    PrivacyFaultSlash,
    EscrowQuarantine,
}

impl SlashDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dismiss => "dismiss",
            Self::Warning => "warning",
            Self::SoftSlash => "soft_slash",
            Self::HardSlash => "hard_slash",
            Self::PrivacyFaultSlash => "privacy_fault_slash",
            Self::EscrowQuarantine => "escrow_quarantine",
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
    pub ml_dsa_suite: String,
    pub sphincs_suite: String,
    pub hybrid_signature_suite: String,
    pub private_stake_bucket_suite: String,
    pub evidence_window_suite: String,
    pub dispute_amortization_suite: String,
    pub escrow_operator_set_size: u16,
    pub slash_threshold: u16,
    pub min_pq_security_bits: u16,
    pub evidence_window_slots: u64,
    pub max_evidence_per_window: u16,
    pub fee_amortization_batch_size: u16,
    pub max_dispute_fee_micro_units: u64,
    pub min_private_bucket_size: u64,
    pub target_private_bucket_size: u64,
    pub locked_vote_quorum_bps: u64,
    pub strong_slash_quorum_bps: u64,
    pub soft_slash_bps: u64,
    pub hard_slash_bps: u64,
    pub privacy_fault_slash_bps: u64,
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
            ml_dsa_suite: ML_DSA_SUITE.to_string(),
            sphincs_suite: SPHINCS_SUITE.to_string(),
            hybrid_signature_suite: HYBRID_SIGNATURE_SUITE.to_string(),
            private_stake_bucket_suite: PRIVATE_STAKE_BUCKET_SUITE.to_string(),
            evidence_window_suite: EVIDENCE_WINDOW_SUITE.to_string(),
            dispute_amortization_suite: DISPUTE_AMORTIZATION_SUITE.to_string(),
            escrow_operator_set_size: DEFAULT_ESCROW_OPERATOR_SET_SIZE,
            slash_threshold: DEFAULT_SLASH_THRESHOLD,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            evidence_window_slots: DEFAULT_EVIDENCE_WINDOW_SLOTS,
            max_evidence_per_window: DEFAULT_MAX_EVIDENCE_PER_WINDOW,
            fee_amortization_batch_size: DEFAULT_FEE_AMORTIZATION_BATCH_SIZE,
            max_dispute_fee_micro_units: DEFAULT_MAX_DISPUTE_FEE_MICRO_UNITS,
            min_private_bucket_size: DEFAULT_MIN_PRIVATE_BUCKET_SIZE,
            target_private_bucket_size: DEFAULT_TARGET_PRIVATE_BUCKET_SIZE,
            locked_vote_quorum_bps: DEFAULT_LOCKED_VOTE_QUORUM_BPS,
            strong_slash_quorum_bps: DEFAULT_STRONG_SLASH_QUORUM_BPS,
            soft_slash_bps: DEFAULT_SOFT_SLASH_BPS,
            hard_slash_bps: DEFAULT_HARD_SLASH_BPS,
            privacy_fault_slash_bps: DEFAULT_PRIVACY_FAULT_SLASH_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.slash_threshold == 0 || self.slash_threshold > self.escrow_operator_set_size {
            return Err("invalid vote escrow slash threshold".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime minimum".to_string());
        }
        if self.target_private_bucket_size < self.min_private_bucket_size {
            return Err("target private bucket size below minimum".to_string());
        }
        if self.fee_amortization_batch_size == 0
            || self.fee_amortization_batch_size > self.max_evidence_per_window
        {
            return Err("invalid dispute fee amortization batch size".to_string());
        }
        for (label, value) in [
            ("locked_vote_quorum_bps", self.locked_vote_quorum_bps),
            ("strong_slash_quorum_bps", self.strong_slash_quorum_bps),
            ("soft_slash_bps", self.soft_slash_bps),
            ("hard_slash_bps", self.hard_slash_bps),
            ("privacy_fault_slash_bps", self.privacy_fault_slash_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{label} exceeds basis point denominator"));
            }
        }
        if self.soft_slash_bps > self.hard_slash_bps
            || self.hard_slash_bps > self.privacy_fault_slash_bps
        {
            return Err("vote escrow slash bps ladder is not monotonic".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub escrow_operators: u64,
    pub private_stake_buckets: u64,
    pub evidence_windows: u64,
    pub slashing_disputes: u64,
    pub hybrid_evidence: u64,
    pub arbiter_attestations: u64,
    pub amortization_batches: u64,
    pub slashing_settlements: u64,
    pub total_amortized_fee_micro_units: u64,
    pub total_slashed_vote_power: u64,
    pub privacy_safe_buckets: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub escrow_operator_root: String,
    pub private_stake_bucket_root: String,
    pub evidence_window_root: String,
    pub slashing_dispute_root: String,
    pub hybrid_evidence_root: String,
    pub arbiter_attestation_root: String,
    pub amortization_batch_root: String,
    pub slashing_settlement_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscrowOperator {
    pub operator_id: String,
    pub role: EscrowRole,
    pub operator_commitment: String,
    pub ml_dsa_key_root: String,
    pub sphincs_key_root: String,
    pub escrow_bond_commitment: String,
    pub active_vote_power: u64,
    pub active: bool,
}

impl EscrowOperator {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "operator_commitment": self.operator_commitment,
            "ml_dsa_key_root": self.ml_dsa_key_root,
            "sphincs_key_root": self.sphincs_key_root,
            "escrow_bond_commitment": self.escrow_bond_commitment,
            "active_vote_power": self.active_vote_power,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateStakeBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub encrypted_stake_root: String,
    pub vote_power_commitment_root: String,
    pub nullifier_set_root: String,
    pub anonymity_set_root: String,
    pub private_bucket_size: u64,
    pub locked_vote_power: u64,
    pub sealed: bool,
}

impl PrivateStakeBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceWindow {
    pub window_id: String,
    pub opens_slot: u64,
    pub closes_slot: u64,
    pub batch_index: u64,
    pub max_evidence: u16,
    pub fee_cap_micro_units: u64,
    pub dispute_ids: BTreeSet<String>,
}

impl EvidenceWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingDispute {
    pub dispute_id: String,
    pub window_id: String,
    pub stake_bucket_id: String,
    pub reporter_commitment: String,
    pub evidence_kind: EvidenceKind,
    pub status: DisputeStatus,
    pub submitted_slot: u64,
    pub amortized_fee_micro_units: u64,
    pub requested_slash_bps: u64,
}

impl SlashingDispute {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "window_id": self.window_id,
            "stake_bucket_id": self.stake_bucket_id,
            "reporter_commitment": self.reporter_commitment,
            "evidence_kind": self.evidence_kind.as_str(),
            "status": self.status.as_str(),
            "submitted_slot": self.submitted_slot,
            "amortized_fee_micro_units": self.amortized_fee_micro_units,
            "requested_slash_bps": self.requested_slash_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HybridEvidence {
    pub evidence_id: String,
    pub dispute_id: String,
    pub sealed_vote_payload_root: String,
    pub redacted_vote_payload_root: String,
    pub ml_dsa_signature_root: String,
    pub sphincs_witness_root: String,
    pub escrow_transcript_root: String,
    pub pq_security_bits: u16,
}

impl HybridEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArbiterAttestation {
    pub attestation_id: String,
    pub dispute_id: String,
    pub operator_id: String,
    pub supports_slash: bool,
    pub ml_dsa_vote_root: String,
    pub sphincs_backstop_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

impl ArbiterAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmortizationBatch {
    pub batch_id: String,
    pub window_id: String,
    pub dispute_count: u16,
    pub aggregate_fee_micro_units: u64,
    pub per_dispute_fee_micro_units: u64,
    pub compression_root: String,
    pub settlement_coupon_root: String,
}

impl AmortizationBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingSettlement {
    pub settlement_id: String,
    pub dispute_id: String,
    pub decision: SlashDecision,
    pub slash_bps: u64,
    pub slashed_vote_power: u64,
    pub escrow_relock_root: String,
    pub published_slot: u64,
}

impl SlashingSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "dispute_id": self.dispute_id,
            "decision": self.decision.as_str(),
            "slash_bps": self.slash_bps,
            "slashed_vote_power": self.slashed_vote_power,
            "escrow_relock_root": self.escrow_relock_root,
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
    pub escrow_operators: BTreeMap<String, EscrowOperator>,
    pub private_stake_buckets: BTreeMap<String, PrivateStakeBucket>,
    pub evidence_windows: BTreeMap<String, EvidenceWindow>,
    pub slashing_disputes: BTreeMap<String, SlashingDispute>,
    pub hybrid_evidence: BTreeMap<String, HybridEvidence>,
    pub arbiter_attestations: BTreeMap<String, ArbiterAttestation>,
    pub amortization_batches: BTreeMap<String, AmortizationBatch>,
    pub slashing_settlements: BTreeMap<String, SlashingSettlement>,
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
            escrow_operators: BTreeMap::new(),
            private_stake_buckets: BTreeMap::new(),
            evidence_windows: BTreeMap::new(),
            slashing_disputes: BTreeMap::new(),
            hybrid_evidence: BTreeMap::new(),
            arbiter_attestations: BTreeMap::new(),
            amortization_batches: BTreeMap::new(),
            slashing_settlements: BTreeMap::new(),
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
        for index in 0..self.config.escrow_operator_set_size {
            let role = match index % 5 {
                0 => EscrowRole::VoteEscrowValidator,
                1 => EscrowRole::DelegationAggregator,
                2 => EscrowRole::EvidenceWatcher,
                3 => EscrowRole::DisputeArbiter,
                _ => EscrowRole::SettlementRelay,
            };
            let operator_id = format!("ml-dsa-sphincs-escrow-operator-devnet-{index:04}");
            self.escrow_operators.insert(
                operator_id.clone(),
                EscrowOperator {
                    operator_id,
                    role,
                    operator_commitment: sample_root("operator", u64::from(index)),
                    ml_dsa_key_root: sample_root("ml-dsa-key", u64::from(index)),
                    sphincs_key_root: sample_root("sphincs-key", u64::from(index)),
                    escrow_bond_commitment: sample_root("escrow-bond", u64::from(index)),
                    active_vote_power: 1_000_000 + u64::from(index) * 25_000,
                    active: true,
                },
            );
        }

        let bucket_id = deterministic_id(
            "private-stake-bucket",
            &[HashPart::U64(self.epoch), HashPart::U64(0)],
        );
        self.private_stake_buckets.insert(
            bucket_id.clone(),
            PrivateStakeBucket {
                bucket_id: bucket_id.clone(),
                epoch: self.epoch,
                encrypted_stake_root: sample_root("encrypted-stake", 0),
                vote_power_commitment_root: sample_root("vote-power-commitment", 0),
                nullifier_set_root: sample_root("vote-nullifier-set", 0),
                anonymity_set_root: sample_root("stake-anonymity-set", 0),
                private_bucket_size: self.config.target_private_bucket_size,
                locked_vote_power: 18_750_000,
                sealed: false,
            },
        );

        let window_id = deterministic_id("evidence-window", &[HashPart::U64(self.slot)]);
        let dispute_id = deterministic_id("slashing-dispute", &[HashPart::Str(&window_id)]);
        self.evidence_windows.insert(
            window_id.clone(),
            EvidenceWindow {
                window_id: window_id.clone(),
                opens_slot: self.slot,
                closes_slot: self.slot + self.config.evidence_window_slots,
                batch_index: 0,
                max_evidence: self.config.max_evidence_per_window,
                fee_cap_micro_units: self.config.max_dispute_fee_micro_units,
                dispute_ids: [dispute_id.clone()].into_iter().collect(),
            },
        );

        self.slashing_disputes.insert(
            dispute_id.clone(),
            SlashingDispute {
                dispute_id: dispute_id.clone(),
                window_id: window_id.clone(),
                stake_bucket_id: bucket_id,
                reporter_commitment: sample_root("reporter", 0),
                evidence_kind: EvidenceKind::DoubleVote,
                status: DisputeStatus::SlashReady,
                submitted_slot: self.slot + 2,
                amortized_fee_micro_units: 740,
                requested_slash_bps: self.config.hard_slash_bps,
            },
        );

        self.hybrid_evidence.insert(
            "hybrid-vote-escrow-evidence-devnet-0000".to_string(),
            HybridEvidence {
                evidence_id: "hybrid-vote-escrow-evidence-devnet-0000".to_string(),
                dispute_id: dispute_id.clone(),
                sealed_vote_payload_root: sample_root("sealed-vote-payload", 0),
                redacted_vote_payload_root: sample_root("redacted-vote-payload", 0),
                ml_dsa_signature_root: sample_root("ml-dsa-vote-signature", 0),
                sphincs_witness_root: sample_root("sphincs-vote-witness", 0),
                escrow_transcript_root: sample_root("vote-escrow-transcript", 0),
                pq_security_bits: self.config.min_pq_security_bits,
            },
        );

        for index in 0..self.config.slash_threshold {
            let operator_id = format!("ml-dsa-sphincs-escrow-operator-devnet-{index:04}");
            let attestation_id = deterministic_id(
                "arbiter-attestation",
                &[HashPart::Str(&dispute_id), HashPart::U64(u64::from(index))],
            );
            self.arbiter_attestations.insert(
                attestation_id.clone(),
                ArbiterAttestation {
                    attestation_id,
                    dispute_id: dispute_id.clone(),
                    operator_id,
                    supports_slash: true,
                    ml_dsa_vote_root: sample_root("arbiter-ml-dsa-vote", u64::from(index)),
                    sphincs_backstop_root: sample_root(
                        "arbiter-sphincs-backstop",
                        u64::from(index),
                    ),
                    observed_slot: self.slot + 12 + u64::from(index),
                    quorum_weight_bps: self.config.strong_slash_quorum_bps,
                },
            );
        }

        let batch_id = deterministic_id(
            "amortization-batch",
            &[HashPart::Str(&window_id), HashPart::U64(0)],
        );
        self.amortization_batches.insert(
            batch_id.clone(),
            AmortizationBatch {
                batch_id,
                window_id,
                dispute_count: self.config.fee_amortization_batch_size,
                aggregate_fee_micro_units: 47_360,
                per_dispute_fee_micro_units: 740,
                compression_root: sample_root("dispute-compression", 0),
                settlement_coupon_root: sample_root("dispute-settlement-coupon", 0),
            },
        );

        self.slashing_settlements.insert(
            "vote-escrow-slashing-settlement-devnet-0000".to_string(),
            SlashingSettlement {
                settlement_id: "vote-escrow-slashing-settlement-devnet-0000".to_string(),
                dispute_id,
                decision: SlashDecision::HardSlash,
                slash_bps: self.config.hard_slash_bps,
                slashed_vote_power: 468_750,
                escrow_relock_root: sample_root("escrow-relock", 0),
                published_slot: self.slot + 36,
            },
        );
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            escrow_operators: self.escrow_operators.len() as u64,
            private_stake_buckets: self.private_stake_buckets.len() as u64,
            evidence_windows: self.evidence_windows.len() as u64,
            slashing_disputes: self.slashing_disputes.len() as u64,
            hybrid_evidence: self.hybrid_evidence.len() as u64,
            arbiter_attestations: self.arbiter_attestations.len() as u64,
            amortization_batches: self.amortization_batches.len() as u64,
            slashing_settlements: self.slashing_settlements.len() as u64,
            total_amortized_fee_micro_units: self
                .slashing_disputes
                .values()
                .map(|dispute| dispute.amortized_fee_micro_units)
                .sum(),
            total_slashed_vote_power: self
                .slashing_settlements
                .values()
                .map(|settlement| settlement.slashed_vote_power)
                .sum(),
            privacy_safe_buckets: self
                .private_stake_buckets
                .values()
                .filter(|bucket| bucket.private_bucket_size >= self.config.min_private_bucket_size)
                .count() as u64,
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let escrow_operator_root = record_root(
            "escrow-operators",
            self.escrow_operators
                .values()
                .map(EscrowOperator::public_record)
                .collect(),
        );
        let private_stake_bucket_root = record_root(
            "private-stake-buckets",
            self.private_stake_buckets
                .values()
                .map(PrivateStakeBucket::public_record)
                .collect(),
        );
        let evidence_window_root = record_root(
            "evidence-windows",
            self.evidence_windows
                .values()
                .map(EvidenceWindow::public_record)
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
        let arbiter_attestation_root = record_root(
            "arbiter-attestations",
            self.arbiter_attestations
                .values()
                .map(ArbiterAttestation::public_record)
                .collect(),
        );
        let amortization_batch_root = record_root(
            "amortization-batches",
            self.amortization_batches
                .values()
                .map(AmortizationBatch::public_record)
                .collect(),
        );
        let slashing_settlement_root = record_root(
            "slashing-settlements",
            self.slashing_settlements
                .values()
                .map(SlashingSettlement::public_record)
                .collect(),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "escrow_operator_root": escrow_operator_root,
                "private_stake_bucket_root": private_stake_bucket_root,
                "evidence_window_root": evidence_window_root,
                "slashing_dispute_root": slashing_dispute_root,
                "hybrid_evidence_root": hybrid_evidence_root,
                "arbiter_attestation_root": arbiter_attestation_root,
                "amortization_batch_root": amortization_batch_root,
                "slashing_settlement_root": slashing_settlement_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPHINCS-VOTE-ESCROW-SLASHING-STATE",
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
            escrow_operator_root,
            private_stake_bucket_root,
            evidence_window_root,
            slashing_dispute_root,
            hybrid_evidence_root,
            arbiter_attestation_root,
            amortization_batch_root,
            slashing_settlement_root,
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
            escrow_operators: BTreeMap::new(),
            private_stake_buckets: BTreeMap::new(),
            evidence_windows: BTreeMap::new(),
            slashing_disputes: BTreeMap::new(),
            hybrid_evidence: BTreeMap::new(),
            arbiter_attestations: BTreeMap::new(),
            amortization_batches: BTreeMap::new(),
            slashing_settlements: BTreeMap::new(),
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
        "ml_dsa_suite": ML_DSA_SUITE,
        "sphincs_suite": SPHINCS_SUITE,
        "hybrid_signature_suite": HYBRID_SIGNATURE_SUITE,
        "private_stake_bucket_suite": PRIVATE_STAKE_BUCKET_SUITE,
        "evidence_window_suite": EVIDENCE_WINDOW_SUITE,
        "dispute_amortization_suite": DISPUTE_AMORTIZATION_SUITE,
        "slashing_settlement_suite": SLASHING_SETTLEMENT_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "escrow_operators": state
            .escrow_operators
            .values()
            .map(EscrowOperator::public_record)
            .collect::<Vec<_>>(),
        "private_stake_buckets": state
            .private_stake_buckets
            .values()
            .map(PrivateStakeBucket::public_record)
            .collect::<Vec<_>>(),
        "evidence_windows": state
            .evidence_windows
            .values()
            .map(EvidenceWindow::public_record)
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
        "arbiter_attestations": state
            .arbiter_attestations
            .values()
            .map(ArbiterAttestation::public_record)
            .collect::<Vec<_>>(),
        "amortization_batches": state
            .amortization_batches
            .values()
            .map(AmortizationBatch::public_record)
            .collect::<Vec<_>>(),
        "slashing_settlements": state
            .slashing_settlements
            .values()
            .map(SlashingSettlement::public_record)
            .collect::<Vec<_>>(),
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPHINCS-VOTE-ESCROW-SLASHING-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPHINCS-VOTE-ESCROW-SLASHING-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPHINCS-VOTE-ESCROW-SLASHING-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-SPHINCS-VOTE-ESCROW-SLASHING-{domain}"),
        &values,
    )
}
