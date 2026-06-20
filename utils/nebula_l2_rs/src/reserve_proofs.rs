use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ReserveProofResult<T> = Result<T, String>;

pub const RESERVE_PROOF_PROTOCOL_VERSION: &str = "nebula-reserve-proofs-v1";
pub const RESERVE_PROOF_DEVNET_HEIGHT: u64 = 96;
pub const RESERVE_PROOF_MAX_BPS: u64 = 10_000;
pub const RESERVE_PROOF_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const RESERVE_PROOF_DEFAULT_MIN_SOLVENCY_BPS: u64 = 10_500;
pub const RESERVE_PROOF_DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 12_500;
pub const RESERVE_PROOF_DEFAULT_MAX_STALENESS_BLOCKS: u64 = 30;
pub const RESERVE_PROOF_DEFAULT_REFRESH_CADENCE_BLOCKS: u64 = 20;
pub const RESERVE_PROOF_DEFAULT_REFRESH_GRACE_BLOCKS: u64 = 6;
pub const RESERVE_PROOF_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 18;
pub const RESERVE_PROOF_DEFAULT_ATTESTER_THRESHOLD_WEIGHT: u64 = 3;
pub const RESERVE_PROOF_DEFAULT_LOW_FEE_LANE: &str = "reserve_proofs";
pub const RESERVE_PROOF_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const RESERVE_PROOF_DEVNET_USDD_ASSET_ID: &str = "usdd-devnet";
pub const RESERVE_PROOF_DEVNET_LP_TOKEN_ID: &str = "dlp-wxmr-usdd-devnet";
pub const RESERVE_PROOF_DEVNET_MARKET_ID: &str = "lending-wxmr-usdd-devnet";
pub const RESERVE_PROOF_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const RESERVE_PROOF_STATUS_ACTIVE: &str = "active";
pub const RESERVE_PROOF_STATUS_PENDING: &str = "pending";
pub const RESERVE_PROOF_STATUS_EXPIRED: &str = "expired";
pub const RESERVE_PROOF_STATUS_CHALLENGED: &str = "challenged";
pub const RESERVE_PROOF_STATUS_REVOKED: &str = "revoked";
pub const RESERVE_PROOF_STATUS_SLASHED: &str = "slashed";
pub const RESERVE_PROOF_STATUS_SETTLED: &str = "settled";
pub const RESERVE_PROOF_STATUS_PAUSED: &str = "paused";
pub const RESERVE_PROOF_STATUS_MISSED: &str = "missed";
pub const RESERVE_PROOF_TRANSPARENT_RESERVE_SYSTEM: &str =
    "devnet-transparent-wrapped-xmr-reserve-proof";
pub const RESERVE_PROOF_TRANSPARENT_LIABILITY_SYSTEM: &str =
    "devnet-transparent-liability-range-proof";
pub const RESERVE_PROOF_TRANSPARENT_SOLVENCY_SYSTEM: &str = "devnet-transparent-solvency-proof";
pub const RESERVE_PROOF_TRANSPARENT_DEFI_SYSTEM: &str =
    "devnet-transparent-defi-pool-reserve-proof";
pub const RESERVE_PROOF_TRANSPARENT_LENDING_SYSTEM: &str =
    "devnet-transparent-lending-collateral-coverage-proof";
pub const RESERVE_PROOF_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSubjectKind {
    WrappedXmrReserve,
    ExchangeRate,
    LiabilityCommitment,
    PrivateLiability,
    SolvencyProof,
    DefiPoolReserve,
    LendingCollateralCoverage,
    RefreshSchedule,
    LowFeeSponsorship,
    ChallengeEvidence,
}

impl ReserveSubjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WrappedXmrReserve => "wrapped_xmr_reserve",
            Self::ExchangeRate => "exchange_rate",
            Self::LiabilityCommitment => "liability_commitment",
            Self::PrivateLiability => "private_liability",
            Self::SolvencyProof => "solvency_proof",
            Self::DefiPoolReserve => "defi_pool_reserve",
            Self::LendingCollateralCoverage => "lending_collateral_coverage",
            Self::RefreshSchedule => "refresh_schedule",
            Self::LowFeeSponsorship => "low_fee_sponsorship",
            Self::ChallengeEvidence => "challenge_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Pending,
    Active,
    Expired,
    Challenged,
    Revoked,
    Slashed,
    Settled,
    Paused,
    Missed,
}

impl ReserveProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => RESERVE_PROOF_STATUS_PENDING,
            Self::Active => RESERVE_PROOF_STATUS_ACTIVE,
            Self::Expired => RESERVE_PROOF_STATUS_EXPIRED,
            Self::Challenged => RESERVE_PROOF_STATUS_CHALLENGED,
            Self::Revoked => RESERVE_PROOF_STATUS_REVOKED,
            Self::Slashed => RESERVE_PROOF_STATUS_SLASHED,
            Self::Settled => RESERVE_PROOF_STATUS_SETTLED,
            Self::Paused => RESERVE_PROOF_STATUS_PAUSED,
            Self::Missed => RESERVE_PROOF_STATUS_MISSED,
        }
    }

    pub fn counts_as_live(&self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAttesterRole {
    Custodian,
    Watcher,
    Oracle,
    Auditor,
    Sequencer,
    EmergencyCouncil,
}

impl ReserveAttesterRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Custodian => "custodian",
            Self::Watcher => "watcher",
            Self::Oracle => "oracle",
            Self::Auditor => "auditor",
            Self::Sequencer => "sequencer",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityVisibility {
    Public,
    Shielded,
    Private,
    AggregateOnly,
}

impl LiabilityVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Shielded => "shielded",
            Self::Private => "private",
            Self::AggregateOnly => "aggregate_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeEvidenceKind {
    MissingReserve,
    SpentReserveOutput,
    OverstatedReserve,
    UnderstatedLiability,
    StaleExchangeRate,
    InvalidRangeProof,
    AttesterEquivocation,
    RefreshMiss,
    SponsorshipAbuse,
}

impl ChallengeEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingReserve => "missing_reserve",
            Self::SpentReserveOutput => "spent_reserve_output",
            Self::OverstatedReserve => "overstated_reserve",
            Self::UnderstatedLiability => "understated_liability",
            Self::StaleExchangeRate => "stale_exchange_rate",
            Self::InvalidRangeProof => "invalid_range_proof",
            Self::AttesterEquivocation => "attester_equivocation",
            Self::RefreshMiss => "refresh_miss",
            Self::SponsorshipAbuse => "sponsorship_abuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
    Resolved,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshScheduleStatus {
    Active,
    Due,
    Grace,
    Missed,
    Paused,
    Retired,
}

impl RefreshScheduleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Due => "due",
            Self::Grace => "grace",
            Self::Missed => "missed",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSponsorshipStatus {
    Active,
    Exhausted,
    Expired,
    Paused,
    Slashed,
}

impl ProofSponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofConfig {
    pub protocol_version: String,
    pub min_attester_threshold_weight: u64,
    pub min_solvency_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub max_staleness_blocks: u64,
    pub default_refresh_cadence_blocks: u64,
    pub default_refresh_grace_blocks: u64,
    pub challenge_window_blocks: u64,
    pub low_fee_lane: String,
    pub proof_fee_asset_id: String,
}

impl Default for ReserveProofConfig {
    fn default() -> Self {
        Self {
            protocol_version: RESERVE_PROOF_PROTOCOL_VERSION.to_string(),
            min_attester_threshold_weight: RESERVE_PROOF_DEFAULT_ATTESTER_THRESHOLD_WEIGHT,
            min_solvency_bps: RESERVE_PROOF_DEFAULT_MIN_SOLVENCY_BPS,
            min_collateral_coverage_bps: RESERVE_PROOF_DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            max_staleness_blocks: RESERVE_PROOF_DEFAULT_MAX_STALENESS_BLOCKS,
            default_refresh_cadence_blocks: RESERVE_PROOF_DEFAULT_REFRESH_CADENCE_BLOCKS,
            default_refresh_grace_blocks: RESERVE_PROOF_DEFAULT_REFRESH_GRACE_BLOCKS,
            challenge_window_blocks: RESERVE_PROOF_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            low_fee_lane: RESERVE_PROOF_DEFAULT_LOW_FEE_LANE.to_string(),
            proof_fee_asset_id: RESERVE_PROOF_DEVNET_WXMR_ASSET_ID.to_string(),
        }
    }
}

impl ReserveProofConfig {
    pub fn validate(&self) -> ReserveProofResult<()> {
        ensure_non_empty(&self.protocol_version, "reserve proof protocol_version")?;
        ensure_non_empty(&self.low_fee_lane, "reserve proof low_fee_lane")?;
        ensure_non_empty(&self.proof_fee_asset_id, "reserve proof fee asset")?;
        ensure_positive(
            self.min_attester_threshold_weight,
            "reserve proof attester threshold",
        )?;
        ensure_positive(
            self.default_refresh_cadence_blocks,
            "reserve proof refresh cadence",
        )?;
        ensure_positive(
            self.challenge_window_blocks,
            "reserve proof challenge window",
        )?;
        validate_bps("reserve proof min solvency bps", self.min_solvency_bps)?;
        validate_bps(
            "reserve proof min collateral coverage bps",
            self.min_collateral_coverage_bps,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "min_attester_threshold_weight": self.min_attester_threshold_weight,
            "min_solvency_bps": self.min_solvency_bps,
            "min_collateral_coverage_bps": self.min_collateral_coverage_bps,
            "max_staleness_blocks": self.max_staleness_blocks,
            "default_refresh_cadence_blocks": self.default_refresh_cadence_blocks,
            "default_refresh_grace_blocks": self.default_refresh_grace_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "low_fee_lane": self.low_fee_lane,
            "proof_fee_asset_id": self.proof_fee_asset_id,
        })
    }

    pub fn config_root(&self) -> String {
        reserve_proof_payload_root("RESERVE-PROOF-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttester {
    pub attester_id: String,
    pub label: String,
    pub role: ReserveAttesterRole,
    pub signature_scheme: String,
    pub public_key_commitment: String,
    pub weight: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub slashing_bond_commitment: String,
    pub metadata_root: String,
    pub status: String,
}

impl PqAttester {
    pub fn new(
        label: &str,
        role: ReserveAttesterRole,
        signature_scheme: &str,
        public_key_label: &str,
        weight: u64,
        active_from_height: u64,
        active_until_height: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(label, "reserve attester label")?;
        ensure_non_empty(signature_scheme, "reserve attester signature scheme")?;
        ensure_non_empty(public_key_label, "reserve attester public key label")?;
        ensure_positive(weight, "reserve attester weight")?;
        if active_until_height != 0 && active_until_height < active_from_height {
            return Err(
                "reserve attester active_until_height cannot precede active_from_height"
                    .to_string(),
            );
        }
        let public_key_commitment =
            reserve_proof_string_root("RESERVE-PQ-ATTESTER-PUBLIC-KEY", public_key_label);
        let slashing_bond_commitment =
            reserve_proof_string_root("RESERVE-PQ-ATTESTER-SLASHING-BOND", label);
        let metadata_root = reserve_proof_payload_root(
            "RESERVE-PQ-ATTESTER-METADATA",
            &json!({
                "label": label,
                "role": role.as_str(),
                "signature_scheme": signature_scheme,
            }),
        );
        let attester_id = reserve_pq_attester_id(
            label,
            role.as_str(),
            signature_scheme,
            &public_key_commitment,
            active_from_height,
        );
        Ok(Self {
            attester_id,
            label: label.to_string(),
            role,
            signature_scheme: signature_scheme.to_string(),
            public_key_commitment,
            weight,
            active_from_height,
            active_until_height,
            slashing_bond_commitment,
            metadata_root,
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE
            && height >= self.active_from_height
            && (self.active_until_height == 0 || height <= self.active_until_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_pq_attester",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "attester_id": self.attester_id,
            "label": self.label,
            "role": self.role.as_str(),
            "signature_scheme": self.signature_scheme,
            "public_key_commitment": self.public_key_commitment,
            "weight": self.weight,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "slashing_bond_commitment": self.slashing_bond_commitment,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn attester_root(&self) -> String {
        reserve_pq_attester_payload_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttesterSet {
    pub attester_set_id: String,
    pub label: String,
    pub activation_height: u64,
    pub retirement_height: u64,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub attester_ids: BTreeSet<String>,
    pub attester_root: String,
    pub aggregate_public_key_root: String,
    pub metadata_root: String,
    pub status: String,
}

impl PqAttesterSet {
    pub fn new(
        label: &str,
        activation_height: u64,
        retirement_height: u64,
        threshold_weight: u64,
        attesters: &[PqAttester],
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(label, "reserve attester set label")?;
        ensure_positive(threshold_weight, "reserve attester set threshold")?;
        if attesters.is_empty() {
            return Err("reserve attester set requires at least one attester".to_string());
        }
        if retirement_height != 0 && retirement_height < activation_height {
            return Err("reserve attester set retirement cannot precede activation".to_string());
        }
        let mut attester_ids = BTreeSet::new();
        let mut public_keys = Vec::new();
        let mut total_weight = 0_u64;
        for attester in attesters {
            if !attester_ids.insert(attester.attester_id.clone()) {
                return Err("reserve attester set contains duplicate attester".to_string());
            }
            total_weight = total_weight.saturating_add(attester.weight);
            public_keys.push(attester.public_key_commitment.clone());
        }
        if threshold_weight > total_weight {
            return Err("reserve attester threshold exceeds total weight".to_string());
        }
        let attester_root = reserve_pq_attester_root(attesters);
        let aggregate_public_key_root =
            reserve_proof_string_set_root("RESERVE-PQ-AGGREGATE-PUBLIC-KEY", &public_keys);
        let metadata_root = reserve_proof_payload_root(
            "RESERVE-PQ-ATTESTER-SET-METADATA",
            &json!({
                "label": label,
                "attester_count": attesters.len(),
                "threshold_weight": threshold_weight,
            }),
        );
        let attester_set_id = reserve_pq_attester_set_id(
            label,
            activation_height,
            threshold_weight,
            &attester_root,
            &aggregate_public_key_root,
        );
        Ok(Self {
            attester_set_id,
            label: label.to_string(),
            activation_height,
            retirement_height,
            threshold_weight,
            total_weight,
            attester_ids,
            attester_root,
            aggregate_public_key_root,
            metadata_root,
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE
            && height >= self.activation_height
            && (self.retirement_height == 0 || height <= self.retirement_height)
    }

    pub fn has_quorum_weight(&self, weight: u64) -> bool {
        weight >= self.threshold_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_pq_attester_set",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "attester_set_id": self.attester_set_id,
            "label": self.label,
            "activation_height": self.activation_height,
            "retirement_height": self.retirement_height,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "attester_ids": self.attester_ids,
            "attester_root": self.attester_root,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn set_root(&self) -> String {
        reserve_pq_attester_set_payload_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub attester_id: String,
    pub attester_set_id: String,
    pub subject_kind: ReserveSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub l2_height: u64,
    pub signature_scheme: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub weight: u64,
}

impl PqAttestation {
    pub fn new(
        attester: &PqAttester,
        attester_set_id: &str,
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        subject_root: &str,
        l2_height: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(attester_set_id, "reserve attestation attester_set_id")?;
        ensure_non_empty(subject_id, "reserve attestation subject_id")?;
        ensure_non_empty(subject_root, "reserve attestation subject_root")?;
        let transcript_root = reserve_proof_payload_root(
            "RESERVE-PQ-ATTESTATION-TRANSCRIPT",
            &json!({
                "attester_id": attester.attester_id,
                "attester_set_id": attester_set_id,
                "subject_kind": subject_kind.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "l2_height": l2_height,
            }),
        );
        let signature_root = reserve_pq_attestation_signature_root(
            &attester.attester_id,
            attester_set_id,
            subject_kind.as_str(),
            subject_id,
            subject_root,
            &transcript_root,
        );
        let attestation_id = reserve_pq_attestation_id(
            &attester.attester_id,
            attester_set_id,
            subject_kind.as_str(),
            subject_id,
            subject_root,
            l2_height,
        );
        Ok(Self {
            attestation_id,
            attester_id: attester.attester_id.clone(),
            attester_set_id: attester_set_id.to_string(),
            subject_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            l2_height,
            signature_scheme: attester.signature_scheme.clone(),
            signature_root,
            transcript_root,
            weight: attester.weight,
        })
    }

    pub fn subject_matches(
        &self,
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        subject_root: &str,
    ) -> bool {
        self.subject_kind == subject_kind
            && self.subject_id == subject_id
            && self.subject_root == subject_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_pq_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "attester_id": self.attester_id,
            "attester_set_id": self.attester_set_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "l2_height": self.l2_height,
            "signature_scheme": self.signature_scheme,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "weight": self.weight,
        })
    }

    pub fn attestation_root(&self) -> String {
        reserve_pq_attestation_payload_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedXmrReserveAttestation {
    pub reserve_id: String,
    pub operator_commitment: String,
    pub custody_wallet_commitment: String,
    pub view_key_commitment: String,
    pub monero_network: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub asset_id: String,
    pub reserve_amount_atomic: u64,
    pub locked_output_count: u64,
    pub unlocked_output_count: u64,
    pub output_commitment_root: String,
    pub spent_key_image_root: String,
    pub attester_set_id: String,
    pub attestation_root: String,
    pub proof_system: String,
    pub proof_root: String,
    pub expires_at_height: u64,
    pub status: String,
}

impl WrappedXmrReserveAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_label: &str,
        custody_wallet_label: &str,
        view_key_label: &str,
        monero_network: &str,
        monero_height: u64,
        l2_height: u64,
        asset_id: &str,
        reserve_amount_atomic: u64,
        locked_output_count: u64,
        unlocked_output_count: u64,
        attester_set_id: &str,
        attestation_root: &str,
        expires_at_height: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(operator_label, "wrapped XMR reserve operator")?;
        ensure_non_empty(custody_wallet_label, "wrapped XMR custody wallet")?;
        ensure_non_empty(view_key_label, "wrapped XMR view key")?;
        ensure_non_empty(monero_network, "wrapped XMR monero network")?;
        ensure_non_empty(asset_id, "wrapped XMR reserve asset")?;
        ensure_non_empty(attester_set_id, "wrapped XMR reserve attester_set_id")?;
        ensure_non_empty(attestation_root, "wrapped XMR reserve attestation_root")?;
        ensure_positive(reserve_amount_atomic, "wrapped XMR reserve amount")?;
        if expires_at_height <= l2_height {
            return Err("wrapped XMR reserve proof must expire after l2_height".to_string());
        }
        let operator_commitment = reserve_account_commitment(operator_label);
        let custody_wallet_commitment =
            reserve_proof_string_root("RESERVE-WXMR-CUSTODY-WALLET", custody_wallet_label);
        let view_key_commitment =
            reserve_proof_string_root("RESERVE-WXMR-VIEW-KEY", view_key_label);
        let output_commitment_root = merkle_root("RESERVE-WXMR-OUTPUT-COMMITMENT", &[]);
        let spent_key_image_root = merkle_root("RESERVE-WXMR-SPENT-KEY-IMAGE", &[]);
        let reserve_id = wrapped_xmr_reserve_attestation_id(
            &operator_commitment,
            &custody_wallet_commitment,
            monero_network,
            monero_height,
            asset_id,
            reserve_amount_atomic,
        );
        let mut record = Self {
            reserve_id,
            operator_commitment,
            custody_wallet_commitment,
            view_key_commitment,
            monero_network: monero_network.to_string(),
            monero_height,
            l2_height,
            asset_id: asset_id.to_string(),
            reserve_amount_atomic,
            locked_output_count,
            unlocked_output_count,
            output_commitment_root,
            spent_key_image_root,
            attester_set_id: attester_set_id.to_string(),
            attestation_root: attestation_root.to_string(),
            proof_system: RESERVE_PROOF_TRANSPARENT_RESERVE_SYSTEM.to_string(),
            proof_root: String::new(),
            expires_at_height,
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        };
        record.proof_root = wrapped_xmr_reserve_proof_root(&record.statement_record());
        Ok(record)
    }

    pub fn is_fresh_at(&self, height: u64, max_staleness_blocks: u64) -> bool {
        height <= self.expires_at_height
            && height.saturating_sub(self.l2_height) <= max_staleness_blocks
    }

    pub fn live_reserve_units(&self, height: u64) -> u64 {
        if self.status == RESERVE_PROOF_STATUS_ACTIVE && height <= self.expires_at_height {
            self.reserve_amount_atomic
        } else {
            0
        }
    }

    pub fn set_observed_roots(&mut self, output_commitment_root: &str, spent_key_image_root: &str) {
        self.output_commitment_root = output_commitment_root.to_string();
        self.spent_key_image_root = spent_key_image_root.to_string();
        self.proof_root = wrapped_xmr_reserve_proof_root(&self.statement_record());
    }

    pub fn statement_record(&self) -> Value {
        json!({
            "kind": "wrapped_xmr_reserve_statement",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "reserve_id": self.reserve_id,
            "operator_commitment": self.operator_commitment,
            "custody_wallet_commitment": self.custody_wallet_commitment,
            "view_key_commitment": self.view_key_commitment,
            "monero_network": self.monero_network,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "asset_id": self.asset_id,
            "reserve_amount_atomic": self.reserve_amount_atomic,
            "locked_output_count": self.locked_output_count,
            "unlocked_output_count": self.unlocked_output_count,
            "output_commitment_root": self.output_commitment_root,
            "spent_key_image_root": self.spent_key_image_root,
            "proof_system": self.proof_system,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn statement_root(&self) -> String {
        reserve_proof_payload_root("RESERVE-WXMR-STATEMENT", &self.statement_record())
    }

    pub fn public_record(&self) -> Value {
        let statement_root = self.statement_root();
        json!({
            "kind": "wrapped_xmr_reserve_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "reserve_id": self.reserve_id,
            "statement_root": statement_root,
            "operator_commitment": self.operator_commitment,
            "custody_wallet_commitment": self.custody_wallet_commitment,
            "view_key_commitment": self.view_key_commitment,
            "monero_network": self.monero_network,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "asset_id": self.asset_id,
            "reserve_amount_atomic": self.reserve_amount_atomic,
            "locked_output_count": self.locked_output_count,
            "unlocked_output_count": self.unlocked_output_count,
            "output_commitment_root": self.output_commitment_root,
            "spent_key_image_root": self.spent_key_image_root,
            "attester_set_id": self.attester_set_id,
            "attestation_root": self.attestation_root,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn reserve_root(&self) -> String {
        wrapped_xmr_reserve_attestation_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeRateCommitment {
    pub rate_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub oracle_commitment: String,
    pub price_numerator: u64,
    pub price_denominator: u64,
    pub scale: u64,
    pub effective_height: u64,
    pub expires_at_height: u64,
    pub source_root: String,
    pub attester_set_id: String,
    pub attestation_root: String,
    pub status: String,
}

impl ExchangeRateCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_asset_id: &str,
        quote_asset_id: &str,
        oracle_label: &str,
        price_numerator: u64,
        price_denominator: u64,
        effective_height: u64,
        expires_at_height: u64,
        source_root: &str,
        attester_set_id: &str,
        attestation_root: &str,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(base_asset_id, "exchange rate base asset")?;
        ensure_non_empty(quote_asset_id, "exchange rate quote asset")?;
        ensure_non_empty(oracle_label, "exchange rate oracle")?;
        ensure_positive(price_numerator, "exchange rate numerator")?;
        ensure_positive(price_denominator, "exchange rate denominator")?;
        ensure_non_empty(source_root, "exchange rate source_root")?;
        ensure_non_empty(attester_set_id, "exchange rate attester_set_id")?;
        ensure_non_empty(attestation_root, "exchange rate attestation_root")?;
        if expires_at_height <= effective_height {
            return Err("exchange rate must expire after effective_height".to_string());
        }
        let oracle_commitment = reserve_account_commitment(oracle_label);
        let rate_id = reserve_exchange_rate_id(
            base_asset_id,
            quote_asset_id,
            &oracle_commitment,
            price_numerator,
            price_denominator,
            effective_height,
        );
        Ok(Self {
            rate_id,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            oracle_commitment,
            price_numerator,
            price_denominator,
            scale: RESERVE_PROOF_PRICE_SCALE,
            effective_height,
            expires_at_height,
            source_root: source_root.to_string(),
            attester_set_id: attester_set_id.to_string(),
            attestation_root: attestation_root.to_string(),
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn quote_value_units(&self, base_units: u64) -> u64 {
        mul_div_floor(base_units, self.price_numerator, self.price_denominator)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE
            && height >= self.effective_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_exchange_rate_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "rate_id": self.rate_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "oracle_commitment": self.oracle_commitment,
            "price_numerator": self.price_numerator,
            "price_denominator": self.price_denominator,
            "scale": self.scale,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
            "source_root": self.source_root,
            "attester_set_id": self.attester_set_id,
            "attestation_root": self.attestation_root,
            "status": self.status,
        })
    }

    pub fn rate_root(&self) -> String {
        reserve_exchange_rate_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiabilityCommitment {
    pub liability_id: String,
    pub operator_commitment: String,
    pub asset_id: String,
    pub visibility: LiabilityVisibility,
    pub liability_root: String,
    pub private_liability_root: String,
    pub account_count: u64,
    pub public_liability_units: u64,
    pub disclosed_private_liability_units: u64,
    pub total_disclosed_liability_units: u64,
    pub liability_proof_root: String,
    pub proof_system: String,
    pub snapshot_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl LiabilityCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_label: &str,
        asset_id: &str,
        visibility: LiabilityVisibility,
        public_liability_units: u64,
        disclosed_private_liability_units: u64,
        account_count: u64,
        snapshot_height: u64,
        expires_at_height: u64,
        liability_leaf_roots: &[String],
        private_note_roots: &[String],
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(operator_label, "liability operator")?;
        ensure_non_empty(asset_id, "liability asset")?;
        ensure_positive(account_count, "liability account count")?;
        if expires_at_height <= snapshot_height {
            return Err("liability commitment must expire after snapshot_height".to_string());
        }
        let operator_commitment = reserve_account_commitment(operator_label);
        let liability_root =
            reserve_proof_string_set_root("RESERVE-LIABILITY-LEAF", liability_leaf_roots);
        let private_liability_root =
            reserve_proof_string_set_root("RESERVE-PRIVATE-LIABILITY-NOTE", private_note_roots);
        let total_disclosed_liability_units =
            public_liability_units.saturating_add(disclosed_private_liability_units);
        let liability_id = reserve_liability_commitment_id(
            &operator_commitment,
            asset_id,
            visibility.as_str(),
            &liability_root,
            snapshot_height,
        );
        let proof_system = RESERVE_PROOF_TRANSPARENT_LIABILITY_SYSTEM.to_string();
        let liability_proof_root = reserve_liability_proof_root_from_fields(
            &liability_id,
            &liability_root,
            &private_liability_root,
            total_disclosed_liability_units,
            &proof_system,
        );
        Ok(Self {
            liability_id,
            operator_commitment,
            asset_id: asset_id.to_string(),
            visibility,
            liability_root,
            private_liability_root,
            account_count,
            public_liability_units,
            disclosed_private_liability_units,
            total_disclosed_liability_units,
            liability_proof_root,
            proof_system,
            snapshot_height,
            expires_at_height,
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE
            && height >= self.snapshot_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_liability_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "liability_id": self.liability_id,
            "operator_commitment": self.operator_commitment,
            "asset_id": self.asset_id,
            "visibility": self.visibility.as_str(),
            "liability_root": self.liability_root,
            "private_liability_root": self.private_liability_root,
            "account_count": self.account_count,
            "public_liability_units": self.public_liability_units,
            "disclosed_private_liability_units": self.disclosed_private_liability_units,
            "total_disclosed_liability_units": self.total_disclosed_liability_units,
            "liability_proof_root": self.liability_proof_root,
            "proof_system": self.proof_system,
            "snapshot_height": self.snapshot_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn liability_commitment_root(&self) -> String {
        reserve_liability_commitment_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiabilityNote {
    pub note_id: String,
    pub liability_id: String,
    pub account_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub amount_bucket: u64,
    pub range_proof_root: String,
    pub membership_proof_root: String,
    pub disclosure_nullifier: String,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PrivateLiabilityNote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        liability_id: &str,
        account_label: &str,
        asset_id: &str,
        amount_units: u64,
        opened_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(liability_id, "private liability liability_id")?;
        ensure_non_empty(account_label, "private liability account")?;
        ensure_non_empty(asset_id, "private liability asset")?;
        ensure_positive(amount_units, "private liability amount")?;
        if expires_at_height <= opened_height {
            return Err("private liability note must expire after opened_height".to_string());
        }
        let account_commitment = reserve_account_commitment(account_label);
        let amount_bucket = reserve_amount_bucket(amount_units);
        let amount_commitment =
            reserve_private_amount_commitment(&account_commitment, asset_id, amount_bucket, nonce);
        let range_proof_root = reserve_proof_payload_root(
            "RESERVE-PRIVATE-LIABILITY-RANGE-PROOF",
            &json!({
                "account_commitment": account_commitment,
                "asset_id": asset_id,
                "amount_commitment": amount_commitment,
                "amount_bucket": amount_bucket,
            }),
        );
        let membership_proof_root = reserve_proof_payload_root(
            "RESERVE-PRIVATE-LIABILITY-MEMBERSHIP-PROOF",
            &json!({
                "liability_id": liability_id,
                "account_commitment": account_commitment,
                "amount_commitment": amount_commitment,
            }),
        );
        let disclosure_nullifier = reserve_private_liability_nullifier(
            liability_id,
            &account_commitment,
            &amount_commitment,
            nonce,
        );
        let note_id = reserve_private_liability_note_id(
            liability_id,
            &account_commitment,
            asset_id,
            &amount_commitment,
            opened_height,
        );
        Ok(Self {
            note_id,
            liability_id: liability_id.to_string(),
            account_commitment,
            asset_id: asset_id.to_string(),
            amount_commitment,
            amount_bucket,
            range_proof_root,
            membership_proof_root,
            disclosure_nullifier,
            opened_height,
            expires_at_height,
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_private_liability_note",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "note_id": self.note_id,
            "liability_id": self.liability_id,
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "range_proof_root": self.range_proof_root,
            "membership_proof_root": self.membership_proof_root,
            "disclosure_nullifier": self.disclosure_nullifier,
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn note_root(&self) -> String {
        reserve_private_liability_note_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencyProof {
    pub proof_id: String,
    pub operator_commitment: String,
    pub reserve_asset_id: String,
    pub liability_asset_id: String,
    pub reserve_attestation_id: String,
    pub reserve_attestation_root: String,
    pub liability_commitment_id: String,
    pub liability_commitment_root: String,
    pub exchange_rate_id: Option<String>,
    pub exchange_rate_root: Option<String>,
    pub reserve_value_units: u64,
    pub liability_value_units: u64,
    pub surplus_units: u64,
    pub solvency_bps: u64,
    pub min_solvency_bps: u64,
    pub proof_system: String,
    pub proof_root: String,
    pub attester_set_id: String,
    pub attestation_root: String,
    pub l2_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl SolvencyProof {
    #[allow(clippy::too_many_arguments)]
    pub fn from_reserve_and_liability(
        reserve: &WrappedXmrReserveAttestation,
        liability: &LiabilityCommitment,
        exchange_rate: Option<&ExchangeRateCommitment>,
        min_solvency_bps: u64,
        attester_set_id: &str,
        attestation_root: &str,
        l2_height: u64,
        expires_at_height: u64,
    ) -> ReserveProofResult<Self> {
        validate_bps("solvency proof min_solvency_bps", min_solvency_bps)?;
        ensure_non_empty(attester_set_id, "solvency proof attester_set_id")?;
        ensure_non_empty(attestation_root, "solvency proof attestation_root")?;
        if expires_at_height <= l2_height {
            return Err("solvency proof must expire after l2_height".to_string());
        }
        let reserve_value_units = match exchange_rate {
            Some(rate) => {
                if rate.base_asset_id != reserve.asset_id
                    || rate.quote_asset_id != liability.asset_id
                {
                    return Err(
                        "exchange rate assets do not connect reserve and liability".to_string()
                    );
                }
                rate.quote_value_units(reserve.reserve_amount_atomic)
            }
            None => {
                if reserve.asset_id != liability.asset_id {
                    return Err(
                        "reserve and liability assets differ without exchange rate".to_string()
                    );
                }
                reserve.reserve_amount_atomic
            }
        };
        let liability_value_units = liability.total_disclosed_liability_units;
        let surplus_units = reserve_value_units.saturating_sub(liability_value_units);
        let solvency_bps = ratio_bps(reserve_value_units, liability_value_units);
        let reserve_attestation_root = reserve.reserve_root();
        let liability_commitment_root = liability.liability_commitment_root();
        let exchange_rate_id = exchange_rate.map(|rate| rate.rate_id.clone());
        let exchange_rate_root = exchange_rate.map(ExchangeRateCommitment::rate_root);
        let proof_system = RESERVE_PROOF_TRANSPARENT_SOLVENCY_SYSTEM.to_string();
        let proof_id = reserve_solvency_proof_id(
            &reserve.operator_commitment,
            &reserve.reserve_id,
            &liability.liability_id,
            exchange_rate_id.as_deref().unwrap_or("same-asset"),
            l2_height,
        );
        let public_inputs = json!({
            "proof_id": proof_id,
            "reserve_attestation_root": reserve_attestation_root,
            "liability_commitment_root": liability_commitment_root,
            "exchange_rate_root": exchange_rate_root,
            "reserve_value_units": reserve_value_units,
            "liability_value_units": liability_value_units,
            "surplus_units": surplus_units,
            "solvency_bps": solvency_bps,
            "min_solvency_bps": min_solvency_bps,
            "l2_height": l2_height,
        });
        let proof_root = reserve_proof_payload_root("RESERVE-SOLVENCY-PROOF", &public_inputs);
        let status = if solvency_bps >= min_solvency_bps {
            RESERVE_PROOF_STATUS_ACTIVE
        } else {
            RESERVE_PROOF_STATUS_CHALLENGED
        }
        .to_string();
        Ok(Self {
            proof_id,
            operator_commitment: reserve.operator_commitment.clone(),
            reserve_asset_id: reserve.asset_id.clone(),
            liability_asset_id: liability.asset_id.clone(),
            reserve_attestation_id: reserve.reserve_id.clone(),
            reserve_attestation_root,
            liability_commitment_id: liability.liability_id.clone(),
            liability_commitment_root,
            exchange_rate_id,
            exchange_rate_root,
            reserve_value_units,
            liability_value_units,
            surplus_units,
            solvency_bps,
            min_solvency_bps,
            proof_system,
            proof_root,
            attester_set_id: attester_set_id.to_string(),
            attestation_root: attestation_root.to_string(),
            l2_height,
            expires_at_height,
            status,
        })
    }

    pub fn is_solvent(&self) -> bool {
        self.solvency_bps >= self.min_solvency_bps
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_solvency_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "operator_commitment": self.operator_commitment,
            "reserve_asset_id": self.reserve_asset_id,
            "liability_asset_id": self.liability_asset_id,
            "reserve_attestation_id": self.reserve_attestation_id,
            "reserve_attestation_root": self.reserve_attestation_root,
            "liability_commitment_id": self.liability_commitment_id,
            "liability_commitment_root": self.liability_commitment_root,
            "exchange_rate_id": self.exchange_rate_id,
            "exchange_rate_root": self.exchange_rate_root,
            "reserve_value_units": self.reserve_value_units,
            "liability_value_units": self.liability_value_units,
            "surplus_units": self.surplus_units,
            "solvency_bps": self.solvency_bps,
            "min_solvency_bps": self.min_solvency_bps,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "attester_set_id": self.attester_set_id,
            "attestation_root": self.attestation_root,
            "l2_height": self.l2_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn solvency_root(&self) -> String {
        reserve_solvency_proof_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiPoolReserveProof {
    pub pool_proof_id: String,
    pub pool_label: String,
    pub dex_protocol: String,
    pub pool_asset_id: String,
    pub reserve_asset_id: String,
    pub lp_token_id: String,
    pub reserve_units: u64,
    pub lp_supply_units: u64,
    pub reserve_per_lp_scaled: u64,
    pub invariant_commitment: String,
    pub fee_growth_commitment: String,
    pub oracle_rate_id: String,
    pub reserve_attestation_id: String,
    pub proof_system: String,
    pub proof_root: String,
    pub snapshot_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl DefiPoolReserveProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_label: &str,
        dex_protocol: &str,
        pool_asset_id: &str,
        reserve_asset_id: &str,
        lp_token_id: &str,
        reserve_units: u64,
        lp_supply_units: u64,
        invariant_label: &str,
        fee_growth_label: &str,
        oracle_rate_id: &str,
        reserve_attestation_id: &str,
        snapshot_height: u64,
        expires_at_height: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(pool_label, "DeFi pool label")?;
        ensure_non_empty(dex_protocol, "DeFi pool protocol")?;
        ensure_non_empty(pool_asset_id, "DeFi pool asset")?;
        ensure_non_empty(reserve_asset_id, "DeFi pool reserve asset")?;
        ensure_non_empty(lp_token_id, "DeFi pool LP token")?;
        ensure_non_empty(invariant_label, "DeFi pool invariant label")?;
        ensure_non_empty(fee_growth_label, "DeFi pool fee growth label")?;
        ensure_non_empty(oracle_rate_id, "DeFi pool oracle_rate_id")?;
        ensure_non_empty(reserve_attestation_id, "DeFi pool reserve_attestation_id")?;
        ensure_positive(reserve_units, "DeFi pool reserve units")?;
        ensure_positive(lp_supply_units, "DeFi pool LP supply")?;
        if expires_at_height <= snapshot_height {
            return Err("DeFi pool reserve proof must expire after snapshot_height".to_string());
        }
        let invariant_commitment =
            reserve_proof_string_root("RESERVE-DEFI-POOL-INVARIANT", invariant_label);
        let fee_growth_commitment =
            reserve_proof_string_root("RESERVE-DEFI-POOL-FEE-GROWTH", fee_growth_label);
        let reserve_per_lp_scaled =
            mul_div_floor(reserve_units, RESERVE_PROOF_PRICE_SCALE, lp_supply_units);
        let pool_proof_id = reserve_defi_pool_proof_id(
            pool_label,
            dex_protocol,
            pool_asset_id,
            reserve_asset_id,
            lp_token_id,
            snapshot_height,
        );
        let proof_system = RESERVE_PROOF_TRANSPARENT_DEFI_SYSTEM.to_string();
        let proof_root = reserve_proof_payload_root(
            "RESERVE-DEFI-POOL-PROOF",
            &json!({
                "pool_proof_id": pool_proof_id,
                "reserve_units": reserve_units,
                "lp_supply_units": lp_supply_units,
                "reserve_per_lp_scaled": reserve_per_lp_scaled,
                "invariant_commitment": invariant_commitment,
                "fee_growth_commitment": fee_growth_commitment,
            }),
        );
        Ok(Self {
            pool_proof_id,
            pool_label: pool_label.to_string(),
            dex_protocol: dex_protocol.to_string(),
            pool_asset_id: pool_asset_id.to_string(),
            reserve_asset_id: reserve_asset_id.to_string(),
            lp_token_id: lp_token_id.to_string(),
            reserve_units,
            lp_supply_units,
            reserve_per_lp_scaled,
            invariant_commitment,
            fee_growth_commitment,
            oracle_rate_id: oracle_rate_id.to_string(),
            reserve_attestation_id: reserve_attestation_id.to_string(),
            proof_system,
            proof_root,
            snapshot_height,
            expires_at_height,
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_defi_pool_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "pool_proof_id": self.pool_proof_id,
            "pool_label": self.pool_label,
            "dex_protocol": self.dex_protocol,
            "pool_asset_id": self.pool_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "lp_token_id": self.lp_token_id,
            "reserve_units": self.reserve_units,
            "lp_supply_units": self.lp_supply_units,
            "reserve_per_lp_scaled": self.reserve_per_lp_scaled,
            "invariant_commitment": self.invariant_commitment,
            "fee_growth_commitment": self.fee_growth_commitment,
            "oracle_rate_id": self.oracle_rate_id,
            "reserve_attestation_id": self.reserve_attestation_id,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "snapshot_height": self.snapshot_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn pool_root(&self) -> String {
        reserve_defi_pool_proof_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingCollateralCoverageProof {
    pub coverage_id: String,
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_commitment_root: String,
    pub debt_commitment_root: String,
    pub private_position_root: String,
    pub price_rate_id: String,
    pub collateral_value_units: u64,
    pub debt_value_units: u64,
    pub coverage_bps: u64,
    pub min_coverage_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub proof_system: String,
    pub proof_root: String,
    pub snapshot_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl LendingCollateralCoverageProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        collateral_commitment_root: &str,
        debt_commitment_root: &str,
        private_position_root: &str,
        price_rate_id: &str,
        collateral_value_units: u64,
        debt_value_units: u64,
        min_coverage_bps: u64,
        liquidation_threshold_bps: u64,
        snapshot_height: u64,
        expires_at_height: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(market_id, "lending coverage market_id")?;
        ensure_non_empty(collateral_asset_id, "lending coverage collateral_asset_id")?;
        ensure_non_empty(debt_asset_id, "lending coverage debt_asset_id")?;
        ensure_non_empty(
            collateral_commitment_root,
            "lending coverage collateral commitment root",
        )?;
        ensure_non_empty(
            debt_commitment_root,
            "lending coverage debt commitment root",
        )?;
        ensure_non_empty(
            private_position_root,
            "lending coverage private position root",
        )?;
        ensure_non_empty(price_rate_id, "lending coverage price_rate_id")?;
        ensure_positive(collateral_value_units, "lending coverage collateral value")?;
        validate_bps("lending coverage min_coverage_bps", min_coverage_bps)?;
        validate_bps(
            "lending coverage liquidation_threshold_bps",
            liquidation_threshold_bps,
        )?;
        if expires_at_height <= snapshot_height {
            return Err("lending coverage proof must expire after snapshot_height".to_string());
        }
        let coverage_bps = ratio_bps(collateral_value_units, debt_value_units);
        let coverage_id = reserve_lending_coverage_id(
            market_id,
            collateral_asset_id,
            debt_asset_id,
            collateral_commitment_root,
            debt_commitment_root,
            snapshot_height,
        );
        let proof_system = RESERVE_PROOF_TRANSPARENT_LENDING_SYSTEM.to_string();
        let proof_root = reserve_proof_payload_root(
            "RESERVE-LENDING-COLLATERAL-COVERAGE-PROOF",
            &json!({
                "coverage_id": coverage_id,
                "collateral_value_units": collateral_value_units,
                "debt_value_units": debt_value_units,
                "coverage_bps": coverage_bps,
                "min_coverage_bps": min_coverage_bps,
                "liquidation_threshold_bps": liquidation_threshold_bps,
            }),
        );
        let status = if coverage_bps >= min_coverage_bps {
            RESERVE_PROOF_STATUS_ACTIVE
        } else {
            RESERVE_PROOF_STATUS_CHALLENGED
        }
        .to_string();
        Ok(Self {
            coverage_id,
            market_id: market_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            collateral_commitment_root: collateral_commitment_root.to_string(),
            debt_commitment_root: debt_commitment_root.to_string(),
            private_position_root: private_position_root.to_string(),
            price_rate_id: price_rate_id.to_string(),
            collateral_value_units,
            debt_value_units,
            coverage_bps,
            min_coverage_bps,
            liquidation_threshold_bps,
            proof_system,
            proof_root,
            snapshot_height,
            expires_at_height,
            status,
        })
    }

    pub fn covers_liabilities(&self) -> bool {
        self.coverage_bps >= self.min_coverage_bps
    }

    pub fn allows_liquidation_buffer(&self) -> bool {
        self.coverage_bps >= self.liquidation_threshold_bps
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == RESERVE_PROOF_STATUS_ACTIVE && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_lending_collateral_coverage_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "coverage_id": self.coverage_id,
            "market_id": self.market_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "collateral_commitment_root": self.collateral_commitment_root,
            "debt_commitment_root": self.debt_commitment_root,
            "private_position_root": self.private_position_root,
            "price_rate_id": self.price_rate_id,
            "collateral_value_units": self.collateral_value_units,
            "debt_value_units": self.debt_value_units,
            "coverage_bps": self.coverage_bps,
            "min_coverage_bps": self.min_coverage_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "snapshot_height": self.snapshot_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn coverage_root(&self) -> String {
        reserve_lending_coverage_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRefreshSchedule {
    pub schedule_id: String,
    pub subject_kind: ReserveSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub cadence_blocks: u64,
    pub grace_blocks: u64,
    pub created_at_height: u64,
    pub last_proof_id: String,
    pub last_proof_root: String,
    pub last_proof_height: u64,
    pub next_due_height: u64,
    pub sponsor_policy_id: Option<String>,
    pub status: RefreshScheduleStatus,
}

impl ProofRefreshSchedule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        subject_root: &str,
        cadence_blocks: u64,
        grace_blocks: u64,
        created_at_height: u64,
        last_proof_id: &str,
        last_proof_root: &str,
        sponsor_policy_id: Option<String>,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(subject_id, "refresh schedule subject_id")?;
        ensure_non_empty(subject_root, "refresh schedule subject_root")?;
        ensure_positive(cadence_blocks, "refresh schedule cadence")?;
        ensure_non_empty(last_proof_id, "refresh schedule last_proof_id")?;
        ensure_non_empty(last_proof_root, "refresh schedule last_proof_root")?;
        let next_due_height = created_at_height.saturating_add(cadence_blocks);
        let schedule_id = reserve_refresh_schedule_id(
            subject_kind.as_str(),
            subject_id,
            subject_root,
            cadence_blocks,
            created_at_height,
        );
        Ok(Self {
            schedule_id,
            subject_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            cadence_blocks,
            grace_blocks,
            created_at_height,
            last_proof_id: last_proof_id.to_string(),
            last_proof_root: last_proof_root.to_string(),
            last_proof_height: created_at_height,
            next_due_height,
            sponsor_policy_id,
            status: RefreshScheduleStatus::Active,
        })
    }

    pub fn refresh_with(&mut self, proof_id: &str, proof_root: &str, height: u64) {
        self.last_proof_id = proof_id.to_string();
        self.last_proof_root = proof_root.to_string();
        self.last_proof_height = height;
        self.next_due_height = height.saturating_add(self.cadence_blocks);
        self.status = RefreshScheduleStatus::Active;
    }

    pub fn refresh_status_at(&self, height: u64) -> RefreshScheduleStatus {
        if matches!(
            self.status,
            RefreshScheduleStatus::Paused | RefreshScheduleStatus::Retired
        ) {
            return self.status;
        }
        if height < self.next_due_height {
            RefreshScheduleStatus::Active
        } else if height == self.next_due_height {
            RefreshScheduleStatus::Due
        } else if height <= self.next_due_height.saturating_add(self.grace_blocks) {
            RefreshScheduleStatus::Grace
        } else {
            RefreshScheduleStatus::Missed
        }
    }

    pub fn is_due_at(&self, height: u64) -> bool {
        matches!(
            self.refresh_status_at(height),
            RefreshScheduleStatus::Due
                | RefreshScheduleStatus::Grace
                | RefreshScheduleStatus::Missed
        )
    }

    pub fn set_height(&mut self, height: u64) {
        self.status = self.refresh_status_at(height);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof_refresh_schedule",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "schedule_id": self.schedule_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "cadence_blocks": self.cadence_blocks,
            "grace_blocks": self.grace_blocks,
            "created_at_height": self.created_at_height,
            "last_proof_id": self.last_proof_id,
            "last_proof_root": self.last_proof_root,
            "last_proof_height": self.last_proof_height,
            "next_due_height": self.next_due_height,
            "sponsor_policy_id": self.sponsor_policy_id,
            "status": self.status.as_str(),
        })
    }

    pub fn schedule_root(&self) -> String {
        reserve_refresh_schedule_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub subject_kind: ReserveSubjectKind,
    pub subject_id: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub max_fee_units: u64,
    pub remaining_fee_units: u64,
    pub rebate_bps: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub status: ProofSponsorshipStatus,
}

impl LowFeeProofSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        fee_asset_id: &str,
        low_fee_lane: &str,
        max_fee_units: u64,
        rebate_bps: u64,
        start_height: u64,
        end_height: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(sponsor_label, "proof sponsorship sponsor")?;
        ensure_non_empty(subject_id, "proof sponsorship subject_id")?;
        ensure_non_empty(fee_asset_id, "proof sponsorship fee_asset_id")?;
        ensure_non_empty(low_fee_lane, "proof sponsorship low_fee_lane")?;
        ensure_positive(max_fee_units, "proof sponsorship max fee")?;
        validate_bps("proof sponsorship rebate_bps", rebate_bps)?;
        if end_height < start_height {
            return Err("proof sponsorship end_height cannot precede start_height".to_string());
        }
        let sponsor_commitment = reserve_account_commitment(sponsor_label);
        let sponsorship_id = reserve_low_fee_sponsorship_id(
            &sponsor_commitment,
            subject_kind.as_str(),
            subject_id,
            fee_asset_id,
            low_fee_lane,
            start_height,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            subject_kind,
            subject_id: subject_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            max_fee_units,
            remaining_fee_units: max_fee_units,
            rebate_bps,
            start_height,
            end_height,
            status: ProofSponsorshipStatus::Active,
        })
    }

    pub fn available_at(&self, height: u64) -> bool {
        self.status == ProofSponsorshipStatus::Active
            && height >= self.start_height
            && height <= self.end_height
            && self.remaining_fee_units > 0
    }

    pub fn spend_fee(&mut self, fee_units: u64) -> ReserveProofResult<()> {
        if fee_units > self.remaining_fee_units {
            return Err("proof sponsorship remaining fee balance is insufficient".to_string());
        }
        self.remaining_fee_units = self.remaining_fee_units.saturating_sub(fee_units);
        if self.remaining_fee_units == 0 {
            self.status = ProofSponsorshipStatus::Exhausted;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == ProofSponsorshipStatus::Active && height > self.end_height {
            self.status = ProofSponsorshipStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_low_fee_proof_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "max_fee_units": self.max_fee_units,
            "remaining_fee_units": self.remaining_fee_units,
            "rebate_bps": self.rebate_bps,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        reserve_low_fee_sponsorship_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub challenger_commitment: String,
    pub subject_kind: ReserveSubjectKind,
    pub subject_id: String,
    pub alleged_root: String,
    pub evidence_kind: ChallengeEvidenceKind,
    pub evidence_root: String,
    pub opened_height: u64,
    pub response_due_height: u64,
    pub bond_units: u64,
    pub reward_units: u64,
    pub status: ChallengeStatus,
}

impl ChallengeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenger_label: &str,
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        alleged_root: &str,
        evidence_kind: ChallengeEvidenceKind,
        evidence_root: &str,
        opened_height: u64,
        response_window_blocks: u64,
        bond_units: u64,
        reward_units: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(challenger_label, "challenge challenger")?;
        ensure_non_empty(subject_id, "challenge subject_id")?;
        ensure_non_empty(alleged_root, "challenge alleged_root")?;
        ensure_non_empty(evidence_root, "challenge evidence_root")?;
        ensure_positive(response_window_blocks, "challenge response window")?;
        let challenger_commitment = reserve_account_commitment(challenger_label);
        let response_due_height = opened_height.saturating_add(response_window_blocks);
        let challenge_id = reserve_challenge_id(
            &challenger_commitment,
            subject_kind.as_str(),
            subject_id,
            alleged_root,
            evidence_kind.as_str(),
            evidence_root,
            opened_height,
        );
        Ok(Self {
            challenge_id,
            challenger_commitment,
            subject_kind,
            subject_id: subject_id.to_string(),
            alleged_root: alleged_root.to_string(),
            evidence_kind,
            evidence_root: evidence_root.to_string(),
            opened_height,
            response_due_height,
            bond_units,
            reward_units,
            status: ChallengeStatus::Open,
        })
    }

    pub fn is_overdue_at(&self, height: u64) -> bool {
        self.status == ChallengeStatus::Open && height > self.response_due_height
    }

    pub fn accept(&mut self) {
        self.status = ChallengeStatus::Accepted;
    }

    pub fn reject(&mut self) {
        self.status = ChallengeStatus::Rejected;
    }

    pub fn resolve(&mut self) {
        self.status = ChallengeStatus::Resolved;
    }

    pub fn set_height(&mut self, height: u64) {
        if self.is_overdue_at(height) {
            self.status = ChallengeStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_challenge_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenger_commitment": self.challenger_commitment,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "alleged_root": self.alleged_root,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "response_due_height": self.response_due_height,
            "bond_units": self.bond_units,
            "reward_units": self.reward_units,
            "status": self.status.as_str(),
        })
    }

    pub fn challenge_root(&self) -> String {
        reserve_challenge_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofPublicRecord {
    pub record_id: String,
    pub publisher_commitment: String,
    pub subject_kind: ReserveSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub published_height: u64,
    pub status: String,
}

impl ReserveProofPublicRecord {
    pub fn new(
        publisher_label: &str,
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        published_height: u64,
    ) -> ReserveProofResult<Self> {
        ensure_non_empty(publisher_label, "reserve public record publisher")?;
        ensure_non_empty(subject_id, "reserve public record subject_id")?;
        ensure_non_empty(subject_root, "reserve public record subject_root")?;
        let publisher_commitment = reserve_account_commitment(publisher_label);
        let payload_root = reserve_proof_payload_root("RESERVE-PUBLIC-RECORD-PAYLOAD", payload);
        let record_id = reserve_public_record_id(
            &publisher_commitment,
            subject_kind.as_str(),
            subject_id,
            subject_root,
            &payload_root,
            published_height,
        );
        Ok(Self {
            record_id,
            publisher_commitment,
            subject_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            published_height,
            status: RESERVE_PROOF_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "publisher_commitment": self.publisher_commitment,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "published_height": self.published_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        reserve_public_record_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofState {
    pub height: u64,
    pub config: ReserveProofConfig,
    pub current_attester_set_id: String,
    pub attesters: BTreeMap<String, PqAttester>,
    pub attester_sets: BTreeMap<String, PqAttesterSet>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub wrapped_xmr_reserves: BTreeMap<String, WrappedXmrReserveAttestation>,
    pub exchange_rates: BTreeMap<String, ExchangeRateCommitment>,
    pub liability_commitments: BTreeMap<String, LiabilityCommitment>,
    pub private_liabilities: BTreeMap<String, PrivateLiabilityNote>,
    pub solvency_proofs: BTreeMap<String, SolvencyProof>,
    pub defi_pool_reserves: BTreeMap<String, DefiPoolReserveProof>,
    pub lending_collateral_coverages: BTreeMap<String, LendingCollateralCoverageProof>,
    pub refresh_schedules: BTreeMap<String, ProofRefreshSchedule>,
    pub sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    pub public_records: BTreeMap<String, ReserveProofPublicRecord>,
}

impl ReserveProofState {
    pub fn new(config: ReserveProofConfig, height: u64) -> ReserveProofResult<Self> {
        config.validate()?;
        Ok(Self {
            height,
            config,
            current_attester_set_id: String::new(),
            attesters: BTreeMap::new(),
            attester_sets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            wrapped_xmr_reserves: BTreeMap::new(),
            exchange_rates: BTreeMap::new(),
            liability_commitments: BTreeMap::new(),
            private_liabilities: BTreeMap::new(),
            solvency_proofs: BTreeMap::new(),
            defi_pool_reserves: BTreeMap::new(),
            lending_collateral_coverages: BTreeMap::new(),
            refresh_schedules: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> ReserveProofResult<Self> {
        let mut state = Self::new(ReserveProofConfig::default(), RESERVE_PROOF_DEVNET_HEIGHT)?;
        let attesters = vec![
            PqAttester::new(
                "nebula-reserve-custodian",
                ReserveAttesterRole::Custodian,
                RESERVE_PROOF_PQ_SIGNATURE_SCHEME,
                "nebula-reserve-custodian-pq",
                2,
                1,
                0,
            )?,
            PqAttester::new(
                "nebula-monero-watch",
                ReserveAttesterRole::Watcher,
                RESERVE_PROOF_PQ_SIGNATURE_SCHEME,
                "nebula-monero-watch-pq",
                1,
                1,
                0,
            )?,
            PqAttester::new(
                "nebula-oracle",
                ReserveAttesterRole::Oracle,
                RESERVE_PROOF_PQ_SIGNATURE_SCHEME,
                "nebula-oracle-pq",
                1,
                1,
                0,
            )?,
            PqAttester::new(
                "nebula-auditor",
                ReserveAttesterRole::Auditor,
                RESERVE_PROOF_PQ_SIGNATURE_SCHEME,
                "nebula-auditor-pq",
                1,
                1,
                0,
            )?,
        ];
        for attester in attesters.iter().cloned() {
            state.insert_attester(attester)?;
        }
        let attester_set = PqAttesterSet::new(
            "nebula-devnet-reserve-attesters",
            1,
            0,
            state.config.min_attester_threshold_weight,
            &attesters,
        )?;
        state.current_attester_set_id = attester_set.attester_set_id.clone();
        state.insert_attester_set(attester_set)?;

        let empty_attestation_root = merkle_root("RESERVE-PQ-ATTESTATION", &[]);
        let mut reserve = WrappedXmrReserveAttestation::new(
            "nebula-reserve-operator",
            "devnet-wxmr-custody-wallet",
            "devnet-wxmr-view-key",
            RESERVE_PROOF_DEVNET_MONERO_NETWORK,
            42_000,
            state.height,
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            12_500_000_000_000,
            2,
            38,
            &state.current_attester_set_id,
            &empty_attestation_root,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
        )?;
        reserve.set_observed_roots(
            &reserve_proof_string_root("RESERVE-DEVNET-OUTPUT-ROOT", "wxmr-output-set"),
            &reserve_proof_string_root("RESERVE-DEVNET-SPENT-KEY-IMAGE-ROOT", "no-spends"),
        );
        let reserve_statement_root = reserve.statement_root();
        let reserve_attestations = state.attest_subject_with_current_set(
            ReserveSubjectKind::WrappedXmrReserve,
            &reserve.reserve_id,
            &reserve_statement_root,
        )?;
        reserve.attestation_root = reserve_pq_attestation_root(&reserve_attestations);
        state.insert_wrapped_xmr_reserve(reserve.clone())?;
        state.register_public_record(
            "nebula-reserve-operator",
            ReserveSubjectKind::WrappedXmrReserve,
            &reserve.reserve_id,
            &reserve.reserve_root(),
            &reserve.public_record(),
        )?;

        let rate_source_root =
            reserve_proof_string_root("RESERVE-DEVNET-ORACLE-SOURCE", "wxmr-usdd-oracle");
        let rate = ExchangeRateCommitment::new(
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            RESERVE_PROOF_DEVNET_USDD_ASSET_ID,
            "nebula-oracle",
            160 * RESERVE_PROOF_PRICE_SCALE,
            RESERVE_PROOF_PRICE_SCALE,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
            &rate_source_root,
            &state.current_attester_set_id,
            &empty_attestation_root,
        )?;
        state.insert_exchange_rate(rate.clone())?;

        let liability_leaf_roots = vec![
            reserve_proof_string_root("RESERVE-DEVNET-LIABILITY-LEAF", "public-liability-root"),
            reserve_proof_string_root("RESERVE-DEVNET-LIABILITY-LEAF", "exchange-balance-root"),
        ];
        let liability_root =
            reserve_proof_string_set_root("RESERVE-LIABILITY-LEAF", &liability_leaf_roots);
        let liability_id = reserve_liability_commitment_id(
            &reserve_account_commitment("nebula-reserve-operator"),
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            LiabilityVisibility::Private.as_str(),
            &liability_root,
            state.height,
        );
        let note_a = PrivateLiabilityNote::new(
            &liability_id,
            "alice-private-liability",
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            1_250_000_000_000,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
            7,
        )?;
        let note_b = PrivateLiabilityNote::new(
            &liability_id,
            "bob-private-liability",
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            900_000_000_000,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
            8,
        )?;
        let private_note_roots = vec![note_a.note_root(), note_b.note_root()];
        state.insert_private_liability(note_a)?;
        state.insert_private_liability(note_b)?;

        let liability = LiabilityCommitment::new(
            "nebula-reserve-operator",
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            LiabilityVisibility::Private,
            7_500_000_000_000,
            2_150_000_000_000,
            128,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
            &liability_leaf_roots,
            &private_note_roots,
        )?;
        state.insert_liability_commitment(liability.clone())?;

        let mut solvency = SolvencyProof::from_reserve_and_liability(
            &reserve,
            &liability,
            None,
            state.config.min_solvency_bps,
            &state.current_attester_set_id,
            &empty_attestation_root,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
        )?;
        let solvency_attestations = state.attest_subject_with_current_set(
            ReserveSubjectKind::SolvencyProof,
            &solvency.proof_id,
            &solvency.proof_root,
        )?;
        solvency.attestation_root = reserve_pq_attestation_root(&solvency_attestations);
        state.insert_solvency_proof(solvency.clone())?;

        let defi_pool = DefiPoolReserveProof::new(
            "devnet-wxmr-usdd-pool",
            "nebula-amm",
            "pool-wxmr-usdd-devnet",
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            RESERVE_PROOF_DEVNET_LP_TOKEN_ID,
            3_200_000_000_000,
            100_000_000,
            "constant-product-devnet",
            "fee-growth-devnet",
            &rate.rate_id,
            &reserve.reserve_id,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
        )?;
        state.insert_defi_pool_reserve(defi_pool)?;

        let collateral_root =
            reserve_proof_string_root("RESERVE-DEVNET-LENDING-COLLATERAL", "collateral-root");
        let debt_root = reserve_proof_string_root("RESERVE-DEVNET-LENDING-DEBT", "debt-root");
        let private_position_root =
            reserve_proof_string_root("RESERVE-DEVNET-LENDING-PRIVATE", "private-position-root");
        let lending_coverage = LendingCollateralCoverageProof::new(
            RESERVE_PROOF_DEVNET_MARKET_ID,
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            RESERVE_PROOF_DEVNET_USDD_ASSET_ID,
            &collateral_root,
            &debt_root,
            &private_position_root,
            &rate.rate_id,
            21_000_000_000_000,
            12_000_000_000_000,
            state.config.min_collateral_coverage_bps,
            11_000,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks),
        )?;
        state.insert_lending_collateral_coverage(lending_coverage)?;

        let sponsorship = LowFeeProofSponsorship::new(
            "nebula-proof-sponsor",
            ReserveSubjectKind::WrappedXmrReserve,
            &reserve.reserve_id,
            RESERVE_PROOF_DEVNET_WXMR_ASSET_ID,
            &state.config.low_fee_lane,
            250_000,
            9_000,
            state.height,
            state
                .height
                .saturating_add(state.config.default_refresh_cadence_blocks * 4),
        )?;
        state.insert_sponsorship(sponsorship.clone())?;

        let schedule = ProofRefreshSchedule::new(
            ReserveSubjectKind::WrappedXmrReserve,
            &reserve.reserve_id,
            &reserve.reserve_root(),
            state.config.default_refresh_cadence_blocks,
            state.config.default_refresh_grace_blocks,
            state.height,
            &reserve.reserve_id,
            &reserve.reserve_root(),
            Some(sponsorship.sponsorship_id),
        )?;
        state.insert_refresh_schedule(schedule)?;

        let challenge = ChallengeEvidence::new(
            "devnet-watchdog",
            ReserveSubjectKind::SolvencyProof,
            &solvency.proof_id,
            &solvency.solvency_root(),
            ChallengeEvidenceKind::AttesterEquivocation,
            &reserve_proof_string_root("RESERVE-DEVNET-CHALLENGE-EVIDENCE", "watchdog-evidence"),
            state.height,
            state.config.challenge_window_blocks,
            10_000,
            5_000,
        )?;
        state.insert_challenge(challenge)?;
        state.set_height(RESERVE_PROOF_DEVNET_HEIGHT);
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for reserve in self.wrapped_xmr_reserves.values_mut() {
            if reserve.status == RESERVE_PROOF_STATUS_ACTIVE && height > reserve.expires_at_height {
                reserve.status = RESERVE_PROOF_STATUS_EXPIRED.to_string();
            }
        }
        for rate in self.exchange_rates.values_mut() {
            if rate.status == RESERVE_PROOF_STATUS_ACTIVE && height > rate.expires_at_height {
                rate.status = RESERVE_PROOF_STATUS_EXPIRED.to_string();
            }
        }
        for liability in self.liability_commitments.values_mut() {
            if liability.status == RESERVE_PROOF_STATUS_ACTIVE
                && height > liability.expires_at_height
            {
                liability.status = RESERVE_PROOF_STATUS_EXPIRED.to_string();
            }
        }
        for note in self.private_liabilities.values_mut() {
            if note.status == RESERVE_PROOF_STATUS_ACTIVE && height > note.expires_at_height {
                note.status = RESERVE_PROOF_STATUS_EXPIRED.to_string();
            }
        }
        for proof in self.solvency_proofs.values_mut() {
            if proof.status == RESERVE_PROOF_STATUS_ACTIVE && height > proof.expires_at_height {
                proof.status = RESERVE_PROOF_STATUS_EXPIRED.to_string();
            }
        }
        for proof in self.defi_pool_reserves.values_mut() {
            if proof.status == RESERVE_PROOF_STATUS_ACTIVE && height > proof.expires_at_height {
                proof.status = RESERVE_PROOF_STATUS_EXPIRED.to_string();
            }
        }
        for proof in self.lending_collateral_coverages.values_mut() {
            if proof.status == RESERVE_PROOF_STATUS_ACTIVE && height > proof.expires_at_height {
                proof.status = RESERVE_PROOF_STATUS_EXPIRED.to_string();
            }
        }
        for schedule in self.refresh_schedules.values_mut() {
            schedule.set_height(height);
        }
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.set_height(height);
        }
    }

    pub fn insert_attester(&mut self, attester: PqAttester) -> ReserveProofResult<()> {
        ensure_non_empty(&attester.attester_id, "reserve attester_id")?;
        self.attesters
            .insert(attester.attester_id.clone(), attester);
        Ok(())
    }

    pub fn insert_attester_set(&mut self, attester_set: PqAttesterSet) -> ReserveProofResult<()> {
        ensure_attester_set_known(&attester_set, &self.attesters)?;
        self.attester_sets
            .insert(attester_set.attester_set_id.clone(), attester_set);
        Ok(())
    }

    pub fn insert_wrapped_xmr_reserve(
        &mut self,
        reserve: WrappedXmrReserveAttestation,
    ) -> ReserveProofResult<()> {
        ensure_non_empty(&reserve.reserve_id, "wrapped XMR reserve_id")?;
        self.wrapped_xmr_reserves
            .insert(reserve.reserve_id.clone(), reserve);
        Ok(())
    }

    pub fn insert_exchange_rate(&mut self, rate: ExchangeRateCommitment) -> ReserveProofResult<()> {
        ensure_non_empty(&rate.rate_id, "exchange rate_id")?;
        self.exchange_rates.insert(rate.rate_id.clone(), rate);
        Ok(())
    }

    pub fn insert_liability_commitment(
        &mut self,
        liability: LiabilityCommitment,
    ) -> ReserveProofResult<()> {
        ensure_non_empty(&liability.liability_id, "liability_id")?;
        self.liability_commitments
            .insert(liability.liability_id.clone(), liability);
        Ok(())
    }

    pub fn insert_private_liability(
        &mut self,
        note: PrivateLiabilityNote,
    ) -> ReserveProofResult<()> {
        ensure_non_empty(&note.note_id, "private liability note_id")?;
        self.private_liabilities.insert(note.note_id.clone(), note);
        Ok(())
    }

    pub fn insert_solvency_proof(&mut self, proof: SolvencyProof) -> ReserveProofResult<()> {
        ensure_non_empty(&proof.proof_id, "solvency proof_id")?;
        self.solvency_proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_defi_pool_reserve(
        &mut self,
        proof: DefiPoolReserveProof,
    ) -> ReserveProofResult<()> {
        ensure_non_empty(&proof.pool_proof_id, "DeFi pool proof_id")?;
        self.defi_pool_reserves
            .insert(proof.pool_proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_lending_collateral_coverage(
        &mut self,
        proof: LendingCollateralCoverageProof,
    ) -> ReserveProofResult<()> {
        ensure_non_empty(&proof.coverage_id, "lending coverage_id")?;
        self.lending_collateral_coverages
            .insert(proof.coverage_id.clone(), proof);
        Ok(())
    }

    pub fn insert_refresh_schedule(
        &mut self,
        schedule: ProofRefreshSchedule,
    ) -> ReserveProofResult<()> {
        ensure_non_empty(&schedule.schedule_id, "refresh schedule_id")?;
        self.refresh_schedules
            .insert(schedule.schedule_id.clone(), schedule);
        Ok(())
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorship,
    ) -> ReserveProofResult<()> {
        ensure_non_empty(&sponsorship.sponsorship_id, "proof sponsorship_id")?;
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_challenge(&mut self, challenge: ChallengeEvidence) -> ReserveProofResult<()> {
        ensure_non_empty(&challenge.challenge_id, "challenge_id")?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn register_public_record(
        &mut self,
        publisher_label: &str,
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
    ) -> ReserveProofResult<ReserveProofPublicRecord> {
        let record = ReserveProofPublicRecord::new(
            publisher_label,
            subject_kind,
            subject_id,
            subject_root,
            payload,
            self.height,
        )?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn attest_subject_with_current_set(
        &mut self,
        subject_kind: ReserveSubjectKind,
        subject_id: &str,
        subject_root: &str,
    ) -> ReserveProofResult<Vec<PqAttestation>> {
        let attester_set = self
            .attester_sets
            .get(&self.current_attester_set_id)
            .ok_or_else(|| "current reserve attester set is missing".to_string())?
            .clone();
        let mut attestations = Vec::new();
        let mut accumulated_weight = 0_u64;
        for attester_id in &attester_set.attester_ids {
            let attester = self
                .attesters
                .get(attester_id)
                .ok_or_else(|| format!("reserve attester {attester_id} is missing"))?;
            if !attester.active_at(self.height) {
                continue;
            }
            let attestation = PqAttestation::new(
                attester,
                &attester_set.attester_set_id,
                subject_kind,
                subject_id,
                subject_root,
                self.height,
            )?;
            accumulated_weight = accumulated_weight.saturating_add(attestation.weight);
            self.attestations
                .insert(attestation.attestation_id.clone(), attestation.clone());
            attestations.push(attestation);
            if attester_set.has_quorum_weight(accumulated_weight) {
                break;
            }
        }
        if !attester_set.has_quorum_weight(accumulated_weight) {
            return Err("reserve attester quorum was not reached".to_string());
        }
        Ok(attestations)
    }

    pub fn validate(&self) -> ReserveProofResult<()> {
        self.config.validate()?;
        if !self.current_attester_set_id.is_empty()
            && !self
                .attester_sets
                .contains_key(&self.current_attester_set_id)
        {
            return Err("current reserve attester set is unknown".to_string());
        }
        for attester_set in self.attester_sets.values() {
            ensure_attester_set_known(attester_set, &self.attesters)?;
            if attester_set.threshold_weight < self.config.min_attester_threshold_weight {
                return Err("reserve attester set threshold is below config minimum".to_string());
            }
        }
        for proof in self.solvency_proofs.values() {
            if proof.status == RESERVE_PROOF_STATUS_ACTIVE && !proof.is_solvent() {
                return Err(format!(
                    "solvency proof {} is below threshold",
                    proof.proof_id
                ));
            }
        }
        for coverage in self.lending_collateral_coverages.values() {
            if coverage.status == RESERVE_PROOF_STATUS_ACTIVE && !coverage.covers_liabilities() {
                return Err(format!(
                    "lending coverage {} is below threshold",
                    coverage.coverage_id
                ));
            }
        }
        Ok(())
    }

    pub fn live_reserve_units(&self, asset_id: &str) -> u64 {
        self.wrapped_xmr_reserves
            .values()
            .filter(|reserve| reserve.asset_id == asset_id)
            .fold(0_u64, |total, reserve| {
                total.saturating_add(reserve.live_reserve_units(self.height))
            })
    }

    pub fn disclosed_liability_units(&self, asset_id: &str) -> u64 {
        self.liability_commitments
            .values()
            .filter(|liability| liability.asset_id == asset_id && liability.is_live_at(self.height))
            .fold(0_u64, |total, liability| {
                total.saturating_add(liability.total_disclosed_liability_units)
            })
    }

    pub fn open_challenge_count(&self) -> u64 {
        self.challenges
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Open)
            .count() as u64
    }

    pub fn due_refresh_count(&self) -> u64 {
        self.refresh_schedules
            .values()
            .filter(|schedule| schedule.is_due_at(self.height))
            .count() as u64
    }

    pub fn sponsorship_available_units(&self) -> u64 {
        self.sponsorships
            .values()
            .fold(0_u64, |total, sponsorship| {
                if sponsorship.available_at(self.height) {
                    total.saturating_add(sponsorship.remaining_fee_units)
                } else {
                    total
                }
            })
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn pq_attester_root(&self) -> String {
        reserve_pq_attester_root(&self.attesters.values().cloned().collect::<Vec<_>>())
    }

    pub fn pq_attester_set_root(&self) -> String {
        reserve_pq_attester_set_root(&self.attester_sets.values().cloned().collect::<Vec<_>>())
    }

    pub fn pq_attestation_root(&self) -> String {
        reserve_pq_attestation_root(&self.attestations.values().cloned().collect::<Vec<_>>())
    }

    pub fn wrapped_xmr_reserve_root(&self) -> String {
        reserve_wrapped_xmr_root(
            &self
                .wrapped_xmr_reserves
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn exchange_rate_root(&self) -> String {
        reserve_exchange_rate_collection_root(
            &self.exchange_rates.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn liability_commitment_root(&self) -> String {
        reserve_liability_collection_root(
            &self
                .liability_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_liability_root(&self) -> String {
        reserve_private_liability_collection_root(
            &self
                .private_liabilities
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn solvency_proof_root(&self) -> String {
        reserve_solvency_collection_root(
            &self.solvency_proofs.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn defi_pool_reserve_root(&self) -> String {
        reserve_defi_pool_collection_root(
            &self
                .defi_pool_reserves
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn lending_collateral_coverage_root(&self) -> String {
        reserve_lending_coverage_collection_root(
            &self
                .lending_collateral_coverages
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn refresh_schedule_root(&self) -> String {
        reserve_refresh_schedule_collection_root(
            &self.refresh_schedules.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        reserve_low_fee_sponsorship_collection_root(
            &self.sponsorships.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn challenge_root(&self) -> String {
        reserve_challenge_collection_root(&self.challenges.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record_root(&self) -> String {
        reserve_public_record_collection_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        reserve_proof_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("reserve proof state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "reserve_proof_state",
            "chain_id": CHAIN_ID,
            "protocol_version": RESERVE_PROOF_PROTOCOL_VERSION,
            "height": self.height,
            "current_attester_set_id": self.current_attester_set_id,
            "config": self.config.public_record(),
            "config_root": self.config_root(),
            "pq_attester_root": self.pq_attester_root(),
            "pq_attester_set_root": self.pq_attester_set_root(),
            "pq_attestation_root": self.pq_attestation_root(),
            "wrapped_xmr_reserve_root": self.wrapped_xmr_reserve_root(),
            "exchange_rate_root": self.exchange_rate_root(),
            "liability_commitment_root": self.liability_commitment_root(),
            "private_liability_root": self.private_liability_root(),
            "solvency_proof_root": self.solvency_proof_root(),
            "defi_pool_reserve_root": self.defi_pool_reserve_root(),
            "lending_collateral_coverage_root": self.lending_collateral_coverage_root(),
            "refresh_schedule_root": self.refresh_schedule_root(),
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root(),
            "challenge_root": self.challenge_root(),
            "public_record_root": self.public_record_root(),
            "attester_count": self.attesters.len() as u64,
            "attester_set_count": self.attester_sets.len() as u64,
            "attestation_count": self.attestations.len() as u64,
            "wrapped_xmr_reserve_count": self.wrapped_xmr_reserves.len() as u64,
            "exchange_rate_count": self.exchange_rates.len() as u64,
            "liability_commitment_count": self.liability_commitments.len() as u64,
            "private_liability_count": self.private_liabilities.len() as u64,
            "solvency_proof_count": self.solvency_proofs.len() as u64,
            "defi_pool_reserve_count": self.defi_pool_reserves.len() as u64,
            "lending_collateral_coverage_count": self.lending_collateral_coverages.len() as u64,
            "refresh_schedule_count": self.refresh_schedules.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "challenge_count": self.challenges.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "live_wxmr_reserve_units": self.live_reserve_units(RESERVE_PROOF_DEVNET_WXMR_ASSET_ID),
            "disclosed_wxmr_liability_units": self.disclosed_liability_units(RESERVE_PROOF_DEVNET_WXMR_ASSET_ID),
            "open_challenge_count": self.open_challenge_count(),
            "due_refresh_count": self.due_refresh_count(),
            "sponsorship_available_units": self.sponsorship_available_units(),
        })
    }
}

pub fn reserve_account_commitment(label: &str) -> String {
    domain_hash(
        "RESERVE-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn reserve_amount_bucket(amount_units: u64) -> u64 {
    if amount_units == 0 {
        0
    } else {
        let bucket_size = 1_000_u64;
        amount_units.saturating_add(bucket_size - 1) / bucket_size
    }
}

pub fn reserve_private_amount_commitment(
    account_commitment: &str,
    asset_id: &str,
    amount_bucket: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "RESERVE-PRIVATE-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(amount_bucket as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn reserve_private_liability_nullifier(
    liability_id: &str,
    account_commitment: &str,
    amount_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "RESERVE-PRIVATE-LIABILITY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(liability_id),
            HashPart::Str(account_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn reserve_pq_attester_id(
    label: &str,
    role: &str,
    signature_scheme: &str,
    public_key_commitment: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "RESERVE-PQ-ATTESTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role),
            HashPart::Str(signature_scheme),
            HashPart::Str(public_key_commitment),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn reserve_pq_attester_set_id(
    label: &str,
    activation_height: u64,
    threshold_weight: u64,
    attester_root: &str,
    aggregate_public_key_root: &str,
) -> String {
    domain_hash(
        "RESERVE-PQ-ATTESTER-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(activation_height as i128),
            HashPart::Int(threshold_weight as i128),
            HashPart::Str(attester_root),
            HashPart::Str(aggregate_public_key_root),
        ],
        32,
    )
}

pub fn reserve_pq_attestation_id(
    attester_id: &str,
    attester_set_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    l2_height: u64,
) -> String {
    domain_hash(
        "RESERVE-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(attester_id),
            HashPart::Str(attester_set_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(l2_height as i128),
        ],
        32,
    )
}

pub fn reserve_pq_attestation_signature_root(
    attester_id: &str,
    attester_set_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "RESERVE-PQ-ATTESTATION-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(attester_id),
            HashPart::Str(attester_set_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn wrapped_xmr_reserve_attestation_id(
    operator_commitment: &str,
    custody_wallet_commitment: &str,
    monero_network: &str,
    monero_height: u64,
    asset_id: &str,
    reserve_amount_atomic: u64,
) -> String {
    domain_hash(
        "RESERVE-WXMR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(custody_wallet_commitment),
            HashPart::Str(monero_network),
            HashPart::Int(monero_height as i128),
            HashPart::Str(asset_id),
            HashPart::Int(reserve_amount_atomic as i128),
        ],
        32,
    )
}

pub fn reserve_exchange_rate_id(
    base_asset_id: &str,
    quote_asset_id: &str,
    oracle_commitment: &str,
    price_numerator: u64,
    price_denominator: u64,
    effective_height: u64,
) -> String {
    domain_hash(
        "RESERVE-EXCHANGE-RATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Str(oracle_commitment),
            HashPart::Int(price_numerator as i128),
            HashPart::Int(price_denominator as i128),
            HashPart::Int(effective_height as i128),
        ],
        32,
    )
}

pub fn reserve_liability_commitment_id(
    operator_commitment: &str,
    asset_id: &str,
    visibility: &str,
    liability_root: &str,
    snapshot_height: u64,
) -> String {
    domain_hash(
        "RESERVE-LIABILITY-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(visibility),
            HashPart::Str(liability_root),
            HashPart::Int(snapshot_height as i128),
        ],
        32,
    )
}

pub fn reserve_private_liability_note_id(
    liability_id: &str,
    account_commitment: &str,
    asset_id: &str,
    amount_commitment: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "RESERVE-PRIVATE-LIABILITY-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(liability_id),
            HashPart::Str(account_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(amount_commitment),
            HashPart::Int(opened_height as i128),
        ],
        32,
    )
}

pub fn reserve_solvency_proof_id(
    operator_commitment: &str,
    reserve_attestation_id: &str,
    liability_commitment_id: &str,
    exchange_rate_id: &str,
    l2_height: u64,
) -> String {
    domain_hash(
        "RESERVE-SOLVENCY-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(reserve_attestation_id),
            HashPart::Str(liability_commitment_id),
            HashPart::Str(exchange_rate_id),
            HashPart::Int(l2_height as i128),
        ],
        32,
    )
}

pub fn reserve_defi_pool_proof_id(
    pool_label: &str,
    dex_protocol: &str,
    pool_asset_id: &str,
    reserve_asset_id: &str,
    lp_token_id: &str,
    snapshot_height: u64,
) -> String {
    domain_hash(
        "RESERVE-DEFI-POOL-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_label),
            HashPart::Str(dex_protocol),
            HashPart::Str(pool_asset_id),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(lp_token_id),
            HashPart::Int(snapshot_height as i128),
        ],
        32,
    )
}

pub fn reserve_lending_coverage_id(
    market_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    collateral_commitment_root: &str,
    debt_commitment_root: &str,
    snapshot_height: u64,
) -> String {
    domain_hash(
        "RESERVE-LENDING-COVERAGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(collateral_commitment_root),
            HashPart::Str(debt_commitment_root),
            HashPart::Int(snapshot_height as i128),
        ],
        32,
    )
}

pub fn reserve_refresh_schedule_id(
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    cadence_blocks: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "RESERVE-REFRESH-SCHEDULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(cadence_blocks as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn reserve_low_fee_sponsorship_id(
    sponsor_commitment: &str,
    subject_kind: &str,
    subject_id: &str,
    fee_asset_id: &str,
    low_fee_lane: &str,
    start_height: u64,
) -> String {
    domain_hash(
        "RESERVE-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(fee_asset_id),
            HashPart::Str(low_fee_lane),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn reserve_challenge_id(
    challenger_commitment: &str,
    subject_kind: &str,
    subject_id: &str,
    alleged_root: &str,
    evidence_kind: &str,
    evidence_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "RESERVE-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenger_commitment),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(alleged_root),
            HashPart::Str(evidence_kind),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_height as i128),
        ],
        32,
    )
}

pub fn reserve_public_record_id(
    publisher_commitment: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    published_height: u64,
) -> String {
    domain_hash(
        "RESERVE-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(publisher_commitment),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(published_height as i128),
        ],
        32,
    )
}

pub fn reserve_liability_proof_root_from_fields(
    liability_id: &str,
    liability_root: &str,
    private_liability_root: &str,
    total_disclosed_liability_units: u64,
    proof_system: &str,
) -> String {
    reserve_proof_payload_root(
        "RESERVE-LIABILITY-PROOF",
        &json!({
            "liability_id": liability_id,
            "liability_root": liability_root,
            "private_liability_root": private_liability_root,
            "total_disclosed_liability_units": total_disclosed_liability_units,
            "proof_system": proof_system,
        }),
    )
}

pub fn wrapped_xmr_reserve_proof_root(statement_record: &Value) -> String {
    reserve_proof_payload_root("RESERVE-WXMR-PROOF", statement_record)
}

pub fn reserve_pq_attester_payload_root(attester: &PqAttester) -> String {
    reserve_proof_payload_root("RESERVE-PQ-ATTESTER", &attester.public_record())
}

pub fn reserve_pq_attester_set_payload_root(attester_set: &PqAttesterSet) -> String {
    reserve_proof_payload_root("RESERVE-PQ-ATTESTER-SET", &attester_set.public_record())
}

pub fn reserve_pq_attestation_payload_root(attestation: &PqAttestation) -> String {
    reserve_proof_payload_root("RESERVE-PQ-ATTESTATION", &attestation.public_record())
}

pub fn wrapped_xmr_reserve_attestation_root(reserve: &WrappedXmrReserveAttestation) -> String {
    reserve_proof_payload_root("RESERVE-WXMR-ATTESTATION", &reserve.public_record())
}

pub fn reserve_exchange_rate_root(rate: &ExchangeRateCommitment) -> String {
    reserve_proof_payload_root("RESERVE-EXCHANGE-RATE", &rate.public_record())
}

pub fn reserve_liability_commitment_root(liability: &LiabilityCommitment) -> String {
    reserve_proof_payload_root("RESERVE-LIABILITY-COMMITMENT", &liability.public_record())
}

pub fn reserve_private_liability_note_root(note: &PrivateLiabilityNote) -> String {
    reserve_proof_payload_root("RESERVE-PRIVATE-LIABILITY-NOTE", &note.public_record())
}

pub fn reserve_solvency_proof_root(proof: &SolvencyProof) -> String {
    reserve_proof_payload_root("RESERVE-SOLVENCY-PROOF-RECORD", &proof.public_record())
}

pub fn reserve_defi_pool_proof_root(proof: &DefiPoolReserveProof) -> String {
    reserve_proof_payload_root("RESERVE-DEFI-POOL-PROOF-RECORD", &proof.public_record())
}

pub fn reserve_lending_coverage_root(proof: &LendingCollateralCoverageProof) -> String {
    reserve_proof_payload_root("RESERVE-LENDING-COVERAGE-RECORD", &proof.public_record())
}

pub fn reserve_refresh_schedule_root(schedule: &ProofRefreshSchedule) -> String {
    reserve_proof_payload_root("RESERVE-REFRESH-SCHEDULE", &schedule.public_record())
}

pub fn reserve_low_fee_sponsorship_root(sponsorship: &LowFeeProofSponsorship) -> String {
    reserve_proof_payload_root("RESERVE-LOW-FEE-SPONSORSHIP", &sponsorship.public_record())
}

pub fn reserve_challenge_root(challenge: &ChallengeEvidence) -> String {
    reserve_proof_payload_root("RESERVE-CHALLENGE", &challenge.public_record())
}

pub fn reserve_public_record_root(record: &ReserveProofPublicRecord) -> String {
    reserve_proof_payload_root("RESERVE-PUBLIC-RECORD", &record.public_record())
}

pub fn reserve_pq_attester_root(attesters: &[PqAttester]) -> String {
    keyed_record_root(
        "RESERVE-PQ-ATTESTER",
        attesters
            .iter()
            .map(|attester| (attester.attester_id.clone(), attester.public_record()))
            .collect(),
    )
}

pub fn reserve_pq_attester_set_root(attester_sets: &[PqAttesterSet]) -> String {
    keyed_record_root(
        "RESERVE-PQ-ATTESTER-SET",
        attester_sets
            .iter()
            .map(|attester_set| {
                (
                    attester_set.attester_set_id.clone(),
                    attester_set.public_record(),
                )
            })
            .collect(),
    )
}

pub fn reserve_pq_attestation_root(attestations: &[PqAttestation]) -> String {
    keyed_record_root(
        "RESERVE-PQ-ATTESTATION",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn reserve_wrapped_xmr_root(reserves: &[WrappedXmrReserveAttestation]) -> String {
    keyed_record_root(
        "RESERVE-WXMR",
        reserves
            .iter()
            .map(|reserve| (reserve.reserve_id.clone(), reserve.public_record()))
            .collect(),
    )
}

pub fn reserve_exchange_rate_collection_root(rates: &[ExchangeRateCommitment]) -> String {
    keyed_record_root(
        "RESERVE-EXCHANGE-RATE",
        rates
            .iter()
            .map(|rate| (rate.rate_id.clone(), rate.public_record()))
            .collect(),
    )
}

pub fn reserve_liability_collection_root(liabilities: &[LiabilityCommitment]) -> String {
    keyed_record_root(
        "RESERVE-LIABILITY",
        liabilities
            .iter()
            .map(|liability| (liability.liability_id.clone(), liability.public_record()))
            .collect(),
    )
}

pub fn reserve_private_liability_collection_root(notes: &[PrivateLiabilityNote]) -> String {
    keyed_record_root(
        "RESERVE-PRIVATE-LIABILITY",
        notes
            .iter()
            .map(|note| (note.note_id.clone(), note.public_record()))
            .collect(),
    )
}

pub fn reserve_solvency_collection_root(proofs: &[SolvencyProof]) -> String {
    keyed_record_root(
        "RESERVE-SOLVENCY",
        proofs
            .iter()
            .map(|proof| (proof.proof_id.clone(), proof.public_record()))
            .collect(),
    )
}

pub fn reserve_defi_pool_collection_root(proofs: &[DefiPoolReserveProof]) -> String {
    keyed_record_root(
        "RESERVE-DEFI-POOL",
        proofs
            .iter()
            .map(|proof| (proof.pool_proof_id.clone(), proof.public_record()))
            .collect(),
    )
}

pub fn reserve_lending_coverage_collection_root(
    proofs: &[LendingCollateralCoverageProof],
) -> String {
    keyed_record_root(
        "RESERVE-LENDING-COVERAGE",
        proofs
            .iter()
            .map(|proof| (proof.coverage_id.clone(), proof.public_record()))
            .collect(),
    )
}

pub fn reserve_refresh_schedule_collection_root(schedules: &[ProofRefreshSchedule]) -> String {
    keyed_record_root(
        "RESERVE-REFRESH-SCHEDULE",
        schedules
            .iter()
            .map(|schedule| (schedule.schedule_id.clone(), schedule.public_record()))
            .collect(),
    )
}

pub fn reserve_low_fee_sponsorship_collection_root(
    sponsorships: &[LowFeeProofSponsorship],
) -> String {
    keyed_record_root(
        "RESERVE-LOW-FEE-SPONSORSHIP",
        sponsorships
            .iter()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn reserve_challenge_collection_root(challenges: &[ChallengeEvidence]) -> String {
    keyed_record_root(
        "RESERVE-CHALLENGE",
        challenges
            .iter()
            .map(|challenge| (challenge.challenge_id.clone(), challenge.public_record()))
            .collect(),
    )
}

pub fn reserve_public_record_collection_root(records: &[ReserveProofPublicRecord]) -> String {
    keyed_record_root(
        "RESERVE-PUBLIC-RECORD",
        records
            .iter()
            .map(|record| (record.record_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn reserve_proof_state_root_from_record(record: &Value) -> String {
    reserve_proof_payload_root("RESERVE-PROOF-STATE", record)
}

pub fn reserve_proof_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn reserve_proof_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn reserve_proof_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn reserve_validate_attestation_quorum(
    attester_set: &PqAttesterSet,
    attestations: &[PqAttestation],
    subject_kind: ReserveSubjectKind,
    subject_id: &str,
    subject_root: &str,
) -> ReserveProofResult<u64> {
    let mut seen = BTreeSet::new();
    let mut weight = 0_u64;
    for attestation in attestations {
        if attestation.attester_set_id != attester_set.attester_set_id {
            continue;
        }
        if !attestation.subject_matches(subject_kind, subject_id, subject_root) {
            continue;
        }
        if !seen.insert(attestation.attester_id.clone()) {
            return Err("duplicate reserve attester signature".to_string());
        }
        if !attester_set.attester_ids.contains(&attestation.attester_id) {
            return Err("reserve attestation signed by non-member".to_string());
        }
        weight = weight.saturating_add(attestation.weight);
    }
    if !attester_set.has_quorum_weight(weight) {
        return Err("reserve attestation quorum weight is insufficient".to_string());
    }
    Ok(weight)
}

pub fn reserve_validate_solvency(
    reserve_value_units: u64,
    liability_value_units: u64,
    min_solvency_bps: u64,
) -> ReserveProofResult<u64> {
    validate_bps("reserve solvency minimum", min_solvency_bps)?;
    let solvency_bps = ratio_bps(reserve_value_units, liability_value_units);
    if solvency_bps < min_solvency_bps {
        return Err("reserve solvency ratio is below minimum".to_string());
    }
    Ok(solvency_bps)
}

pub fn reserve_validate_lending_coverage(
    collateral_value_units: u64,
    debt_value_units: u64,
    min_coverage_bps: u64,
) -> ReserveProofResult<u64> {
    validate_bps("reserve lending coverage minimum", min_coverage_bps)?;
    let coverage_bps = ratio_bps(collateral_value_units, debt_value_units);
    if coverage_bps < min_coverage_bps {
        return Err("lending collateral coverage is below minimum".to_string());
    }
    Ok(coverage_bps)
}

pub fn validate_bps(label: &str, value: u64) -> ReserveProofResult<()> {
    ensure_positive(value, label)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    mul_div_floor(numerator, RESERVE_PROOF_MAX_BPS, denominator)
}

pub fn mul_div_floor(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let result = (value as u128).saturating_mul(multiplier as u128) / denominator as u128;
    result.min(u64::MAX as u128) as u64
}

pub fn ensure_non_empty(value: &str, label: &str) -> ReserveProofResult<()> {
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

pub fn ensure_positive(value: u64, label: &str) -> ReserveProofResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_attester_set_known(
    attester_set: &PqAttesterSet,
    attesters: &BTreeMap<String, PqAttester>,
) -> ReserveProofResult<()> {
    for attester_id in &attester_set.attester_ids {
        if !attesters.contains_key(attester_id) {
            return Err(format!(
                "reserve attester set member {attester_id} is unknown"
            ));
        }
    }
    Ok(())
}
