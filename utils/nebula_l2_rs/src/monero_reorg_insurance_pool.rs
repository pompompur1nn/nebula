use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type MoneroReorgInsurancePoolResult<T> = Result<T, String>;

pub const MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION: &str =
    "nebula-monero-reorg-insurance-pool-v1";
pub const MONERO_REORG_INSURANCE_POOL_PUBLIC_RECORD_SCHEMA: &str =
    "monero-reorg-insurance-pool-public-record-v1";
pub const MONERO_REORG_INSURANCE_POOL_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_REORG_INSURANCE_POOL_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_REORG_INSURANCE_POOL_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const MONERO_REORG_INSURANCE_POOL_PQ_SIGNER_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-insurance-attestation-root";
pub const MONERO_REORG_INSURANCE_POOL_PRIVACY_COMMITMENT_SCHEME: &str =
    "zk-monero-claim-commitment-nullifier-v1";
pub const MONERO_REORG_INSURANCE_POOL_CLAIM_ENVELOPE_SCHEME: &str =
    "ML-KEM-768+XChaCha20-Poly1305-private-claim-envelope";
pub const MONERO_REORG_INSURANCE_POOL_MAX_BPS: u64 = 10_000;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_MIN_REORG_DEPTH_BLOCKS: u64 = 3;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_SEVERE_REORG_DEPTH_BLOCKS: u64 = 18;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_QUORUM_SIZE: u64 = 5;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_MIN_QUORUM_AGREEMENT: u64 = 3;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_DISAGREEMENT_PAUSE_BPS: u64 = 4_000;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_MAX_POLICY_AMOUNT_UNITS: u64 = 25_000_000_000;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_MIN_PREMIUM_UNITS: u64 = 500;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_PREMIUM_BPS: u64 = 18;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6_500;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_PRIVATE_DEFI_DISCOUNT_BPS: u64 = 2_000;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_CLAIM_DELAY_BLOCKS: u64 = 20;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 720;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 120;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_PAUSE_TTL_BLOCKS: u64 = 60;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_RESERVE_TARGET_BPS: u64 = 12_000;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_SENIOR_ATTACHMENT_BPS: u64 = 0;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_MEZZANINE_ATTACHMENT_BPS: u64 = 3_000;
pub const MONERO_REORG_INSURANCE_POOL_DEFAULT_JUNIOR_ATTACHMENT_BPS: u64 = 7_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeInsuranceFlow {
    Deposit,
    Exit,
    PrivateDefiDeposit,
    PrivateDefiExit,
    LowFeeExit,
    EmergencyExit,
}

impl BridgeInsuranceFlow {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Exit => "exit",
            Self::PrivateDefiDeposit => "private_defi_deposit",
            Self::PrivateDefiExit => "private_defi_exit",
            Self::LowFeeExit => "low_fee_exit",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn is_exit(self) -> bool {
        matches!(
            self,
            Self::Exit | Self::PrivateDefiExit | Self::LowFeeExit | Self::EmergencyExit
        )
    }

    pub fn private_weight_bps(self) -> u64 {
        match self {
            Self::PrivateDefiDeposit | Self::PrivateDefiExit => 10_000,
            Self::LowFeeExit => 8_000,
            Self::EmergencyExit => 6_500,
            Self::Deposit | Self::Exit => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsurancePolicyStatus {
    Quoted,
    Active,
    Matured,
    Claimed,
    Paid,
    Denied,
    Expired,
    Cancelled,
}

impl InsurancePolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Active => "active",
            Self::Matured => "matured",
            Self::Claimed => "claimed",
            Self::Paid => "paid",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Quoted | Self::Active | Self::Matured | Self::Claimed
        )
    }

    pub fn locked(self) -> bool {
        matches!(self, Self::Active | Self::Matured | Self::Claimed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgRiskBand {
    Normal,
    Watch,
    Throttled,
    Paused,
    Emergency,
}

impl ReorgRiskBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Watch => "watch",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Emergency => "emergency",
        }
    }

    pub fn risk_score_bps(self) -> u64 {
        match self {
            Self::Normal => 1_000,
            Self::Watch => 3_000,
            Self::Throttled => 6_000,
            Self::Paused => 8_500,
            Self::Emergency => 10_000,
        }
    }

    pub fn allows_new_policy(self) -> bool {
        matches!(self, Self::Normal | Self::Watch | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumObservationKind {
    StableTip,
    DeepReorg,
    ConflictingDaemonTip,
    MissingDeposit,
    RolledBackExit,
    DelayedPayout,
    ForkChoiceDisagreement,
}

impl QuorumObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableTip => "stable_tip",
            Self::DeepReorg => "deep_reorg",
            Self::ConflictingDaemonTip => "conflicting_daemon_tip",
            Self::MissingDeposit => "missing_deposit",
            Self::RolledBackExit => "rolled_back_exit",
            Self::DelayedPayout => "delayed_payout",
            Self::ForkChoiceDisagreement => "fork_choice_disagreement",
        }
    }

    pub fn triggers_claim(self) -> bool {
        matches!(
            self,
            Self::DeepReorg | Self::MissingDeposit | Self::RolledBackExit | Self::DelayedPayout
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Committed,
    WaitingDelay,
    EvidenceOpen,
    QuorumAccepted,
    QueuedForPayout,
    Paid,
    Denied,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::WaitingDelay => "waiting_delay",
            Self::EvidenceOpen => "evidence_open",
            Self::QuorumAccepted => "quorum_accepted",
            Self::QueuedForPayout => "queued_for_payout",
            Self::Paid => "paid",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::WaitingDelay
                | Self::EvidenceOpen
                | Self::QuorumAccepted
                | Self::QueuedForPayout
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsurerTrancheKind {
    Senior,
    Mezzanine,
    Junior,
    ProtocolBackstop,
}

impl InsurerTrancheKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::ProtocolBackstop => "protocol_backstop",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Senior => 0,
            Self::Mezzanine => 1,
            Self::Junior => 2,
            Self::ProtocolBackstop => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheStatus {
    Funding,
    Active,
    Locked,
    Impaired,
    Retiring,
    Retired,
}

impl TrancheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Impaired => "impaired",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
        }
    }

    pub fn can_cover(self) -> bool {
        matches!(self, Self::Active | Self::Locked | Self::Impaired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Submitted,
    Counted,
    Superseded,
    Expired,
    Rejected,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Submitted | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseBandStatus {
    Scheduled,
    Active,
    Lifted,
    Expired,
    Superseded,
}

impl PauseBandStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Lifted => "lifted",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    Config,
    Policy,
    QuorumReport,
    ClaimCommitment,
    Claim,
    Tranche,
    PqAttestation,
    PauseBand,
    Payout,
    StateCheckpoint,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Policy => "policy",
            Self::QuorumReport => "quorum_report",
            Self::ClaimCommitment => "claim_commitment",
            Self::Claim => "claim",
            Self::Tranche => "tranche",
            Self::PqAttestation => "pq_attestation",
            Self::PauseBand => "pause_band",
            Self::Payout => "payout",
            Self::StateCheckpoint => "state_checkpoint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReorgInsurancePoolConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub public_record_schema: String,
    pub chain_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub pq_signer_scheme: String,
    pub privacy_commitment_scheme: String,
    pub claim_envelope_scheme: String,
    pub min_reorg_depth_blocks: u64,
    pub severe_reorg_depth_blocks: u64,
    pub daemon_quorum_size: u64,
    pub min_quorum_agreement: u64,
    pub disagreement_pause_bps: u64,
    pub max_policy_amount_units: u64,
    pub min_premium_units: u64,
    pub base_premium_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub private_defi_discount_bps: u64,
    pub claim_delay_blocks: u64,
    pub claim_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub pause_ttl_blocks: u64,
    pub reserve_target_bps: u64,
}

impl Default for MoneroReorgInsurancePoolConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl MoneroReorgInsurancePoolConfig {
    pub fn devnet() -> Self {
        let identity = json!({
            "chain_id": CHAIN_ID,
            "monero_network": MONERO_REORG_INSURANCE_POOL_DEVNET_NETWORK,
            "asset_id": MONERO_REORG_INSURANCE_POOL_DEVNET_ASSET_ID,
            "fee_asset_id": MONERO_REORG_INSURANCE_POOL_DEVNET_FEE_ASSET_ID,
        });
        Self {
            config_id: monero_reorg_insurance_pool_payload_root(
                "MONERO-REORG-INSURANCE-POOL-CONFIG-ID",
                &identity,
            ),
            protocol_version: MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION.to_string(),
            public_record_schema: MONERO_REORG_INSURANCE_POOL_PUBLIC_RECORD_SCHEMA.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_REORG_INSURANCE_POOL_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_REORG_INSURANCE_POOL_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_REORG_INSURANCE_POOL_DEVNET_FEE_ASSET_ID.to_string(),
            pq_signer_scheme: MONERO_REORG_INSURANCE_POOL_PQ_SIGNER_SCHEME.to_string(),
            privacy_commitment_scheme: MONERO_REORG_INSURANCE_POOL_PRIVACY_COMMITMENT_SCHEME
                .to_string(),
            claim_envelope_scheme: MONERO_REORG_INSURANCE_POOL_CLAIM_ENVELOPE_SCHEME.to_string(),
            min_reorg_depth_blocks: MONERO_REORG_INSURANCE_POOL_DEFAULT_MIN_REORG_DEPTH_BLOCKS,
            severe_reorg_depth_blocks:
                MONERO_REORG_INSURANCE_POOL_DEFAULT_SEVERE_REORG_DEPTH_BLOCKS,
            daemon_quorum_size: MONERO_REORG_INSURANCE_POOL_DEFAULT_QUORUM_SIZE,
            min_quorum_agreement: MONERO_REORG_INSURANCE_POOL_DEFAULT_MIN_QUORUM_AGREEMENT,
            disagreement_pause_bps: MONERO_REORG_INSURANCE_POOL_DEFAULT_DISAGREEMENT_PAUSE_BPS,
            max_policy_amount_units: MONERO_REORG_INSURANCE_POOL_DEFAULT_MAX_POLICY_AMOUNT_UNITS,
            min_premium_units: MONERO_REORG_INSURANCE_POOL_DEFAULT_MIN_PREMIUM_UNITS,
            base_premium_bps: MONERO_REORG_INSURANCE_POOL_DEFAULT_PREMIUM_BPS,
            low_fee_rebate_bps: MONERO_REORG_INSURANCE_POOL_DEFAULT_LOW_FEE_REBATE_BPS,
            private_defi_discount_bps:
                MONERO_REORG_INSURANCE_POOL_DEFAULT_PRIVATE_DEFI_DISCOUNT_BPS,
            claim_delay_blocks: MONERO_REORG_INSURANCE_POOL_DEFAULT_CLAIM_DELAY_BLOCKS,
            claim_window_blocks: MONERO_REORG_INSURANCE_POOL_DEFAULT_CLAIM_WINDOW_BLOCKS,
            attestation_ttl_blocks: MONERO_REORG_INSURANCE_POOL_DEFAULT_ATTESTATION_TTL_BLOCKS,
            pause_ttl_blocks: MONERO_REORG_INSURANCE_POOL_DEFAULT_PAUSE_TTL_BLOCKS,
            reserve_target_bps: MONERO_REORG_INSURANCE_POOL_DEFAULT_RESERVE_TARGET_BPS,
        }
    }

    pub fn premium_for(&self, flow: BridgeInsuranceFlow, amount_units: u64) -> u64 {
        let raw = amount_units
            .saturating_mul(self.base_premium_bps)
            .saturating_div(MONERO_REORG_INSURANCE_POOL_MAX_BPS);
        let discounted = match flow {
            BridgeInsuranceFlow::LowFeeExit => apply_rebate(raw, self.low_fee_rebate_bps),
            BridgeInsuranceFlow::PrivateDefiDeposit | BridgeInsuranceFlow::PrivateDefiExit => {
                apply_rebate(raw, self.private_defi_discount_bps)
            }
            _ => raw,
        };
        discounted.max(self.min_premium_units)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_reorg_insurance_pool_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "public_record_schema": self.public_record_schema,
            "config_id": self.config_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "pq_signer_scheme": self.pq_signer_scheme,
            "privacy_commitment_scheme": self.privacy_commitment_scheme,
            "claim_envelope_scheme": self.claim_envelope_scheme,
            "min_reorg_depth_blocks": self.min_reorg_depth_blocks,
            "severe_reorg_depth_blocks": self.severe_reorg_depth_blocks,
            "daemon_quorum_size": self.daemon_quorum_size,
            "min_quorum_agreement": self.min_quorum_agreement,
            "disagreement_pause_bps": self.disagreement_pause_bps,
            "max_policy_amount_units": self.max_policy_amount_units,
            "min_premium_units": self.min_premium_units,
            "base_premium_bps": self.base_premium_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "private_defi_discount_bps": self.private_defi_discount_bps,
            "claim_delay_blocks": self.claim_delay_blocks,
            "claim_window_blocks": self.claim_window_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "pause_ttl_blocks": self.pause_ttl_blocks,
            "reserve_target_bps": self.reserve_target_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "config_root",
            self.config_root(),
        )
    }

    pub fn config_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-CONFIG",
            &self.public_record_without_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.config_id, "insurance config id")?;
        ensure_non_empty(&self.protocol_version, "insurance protocol version")?;
        ensure_non_empty(&self.public_record_schema, "insurance public record schema")?;
        ensure_non_empty(&self.chain_id, "insurance chain id")?;
        ensure_non_empty(&self.monero_network, "insurance monero network")?;
        ensure_non_empty(&self.asset_id, "insurance asset id")?;
        ensure_non_empty(&self.fee_asset_id, "insurance fee asset id")?;
        ensure_non_empty(&self.pq_signer_scheme, "insurance pq signer scheme")?;
        ensure_non_empty(
            &self.privacy_commitment_scheme,
            "insurance privacy commitment scheme",
        )?;
        ensure_non_empty(
            &self.claim_envelope_scheme,
            "insurance claim envelope scheme",
        )?;
        if self.protocol_version != MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION {
            return Err("insurance protocol version mismatch".to_string());
        }
        if self.public_record_schema != MONERO_REORG_INSURANCE_POOL_PUBLIC_RECORD_SCHEMA {
            return Err("insurance public record schema mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("insurance chain id mismatch".to_string());
        }
        ensure_positive(self.min_reorg_depth_blocks, "min reorg depth blocks")?;
        ensure_positive(self.severe_reorg_depth_blocks, "severe reorg depth blocks")?;
        ensure_positive(self.daemon_quorum_size, "daemon quorum size")?;
        ensure_positive(self.min_quorum_agreement, "min quorum agreement")?;
        ensure_bps(self.disagreement_pause_bps, "disagreement pause bps")?;
        ensure_positive(self.max_policy_amount_units, "max policy amount")?;
        ensure_positive(self.min_premium_units, "min premium units")?;
        ensure_bps(self.base_premium_bps, "base premium bps")?;
        ensure_bps(self.low_fee_rebate_bps, "low fee rebate bps")?;
        ensure_bps(self.private_defi_discount_bps, "private defi discount bps")?;
        ensure_positive(self.claim_delay_blocks, "claim delay blocks")?;
        ensure_positive(self.claim_window_blocks, "claim window blocks")?;
        ensure_positive(self.attestation_ttl_blocks, "attestation ttl blocks")?;
        ensure_positive(self.pause_ttl_blocks, "pause ttl blocks")?;
        ensure_positive(self.reserve_target_bps, "reserve target bps")?;
        if self.severe_reorg_depth_blocks < self.min_reorg_depth_blocks {
            return Err("severe reorg depth must cover min reorg depth".to_string());
        }
        if self.min_quorum_agreement > self.daemon_quorum_size {
            return Err("min quorum agreement exceeds quorum size".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsurerTranche {
    pub tranche_id: String,
    pub kind: InsurerTrancheKind,
    pub sponsor_commitment: String,
    pub capital_commitment_root: String,
    pub reserve_asset_id: String,
    pub funded_units: u64,
    pub locked_units: u64,
    pub paid_loss_units: u64,
    pub attachment_point_bps: u64,
    pub premium_share_bps: u64,
    pub registered_at_height: u64,
    pub status: TrancheStatus,
}

impl InsurerTranche {
    pub fn new(
        kind: InsurerTrancheKind,
        sponsor_commitment: impl Into<String>,
        capital_commitment_root: impl Into<String>,
        reserve_asset_id: impl Into<String>,
        funded_units: u64,
        attachment_point_bps: u64,
        premium_share_bps: u64,
        registered_at_height: u64,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let capital_commitment_root = capital_commitment_root.into();
        let reserve_asset_id = reserve_asset_id.into();
        let tranche_id = monero_reorg_insurance_pool_tranche_id(
            kind,
            &sponsor_commitment,
            &capital_commitment_root,
            funded_units,
            registered_at_height,
        );
        let tranche = Self {
            tranche_id,
            kind,
            sponsor_commitment,
            capital_commitment_root,
            reserve_asset_id,
            funded_units,
            locked_units: 0,
            paid_loss_units: 0,
            attachment_point_bps,
            premium_share_bps,
            registered_at_height,
            status: TrancheStatus::Active,
        };
        tranche.validate()?;
        Ok(tranche)
    }

    pub fn available_units(&self) -> u64 {
        self.funded_units
            .saturating_sub(self.locked_units)
            .saturating_sub(self.paid_loss_units)
    }

    pub fn lock_capacity(&mut self, amount_units: u64) -> MoneroReorgInsurancePoolResult<String> {
        let next = self.locked_units.saturating_add(amount_units);
        if next.saturating_add(self.paid_loss_units) > self.funded_units {
            return Err("insurance tranche capacity exceeded".to_string());
        }
        self.locked_units = next;
        if self.locked_units > 0 && self.status == TrancheStatus::Active {
            self.status = TrancheStatus::Locked;
        }
        self.validate()
    }

    pub fn absorb_loss(&mut self, amount_units: u64) -> MoneroReorgInsurancePoolResult<String> {
        let unlocked = self.locked_units.saturating_sub(amount_units);
        self.locked_units = unlocked;
        self.paid_loss_units = self.paid_loss_units.saturating_add(amount_units);
        if self.paid_loss_units >= self.funded_units {
            self.status = TrancheStatus::Impaired;
        }
        self.validate()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "insurer_tranche",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "tranche_id": self.tranche_id,
            "tranche_kind": self.kind.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "capital_commitment_root": self.capital_commitment_root,
            "reserve_asset_id": self.reserve_asset_id,
            "funded_units": self.funded_units,
            "locked_units": self.locked_units,
            "available_units": self.available_units(),
            "paid_loss_units": self.paid_loss_units,
            "attachment_point_bps": self.attachment_point_bps,
            "premium_share_bps": self.premium_share_bps,
            "registered_at_height": self.registered_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn tranche_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-TRANCHE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "tranche_root",
            self.tranche_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.tranche_id, "tranche id")?;
        ensure_non_empty(&self.sponsor_commitment, "tranche sponsor commitment")?;
        ensure_non_empty(
            &self.capital_commitment_root,
            "tranche capital commitment root",
        )?;
        ensure_non_empty(&self.reserve_asset_id, "tranche reserve asset id")?;
        ensure_positive(self.funded_units, "tranche funded units")?;
        ensure_bps(self.attachment_point_bps, "tranche attachment point")?;
        ensure_bps(self.premium_share_bps, "tranche premium share")?;
        if self.locked_units.saturating_add(self.paid_loss_units) > self.funded_units {
            return Err("tranche locked plus paid loss exceeds funded units".to_string());
        }
        let expected = monero_reorg_insurance_pool_tranche_id(
            self.kind,
            &self.sponsor_commitment,
            &self.capital_commitment_root,
            self.funded_units,
            self.registered_at_height,
        );
        if self.tranche_id != expected {
            return Err("tranche id mismatch".to_string());
        }
        Ok(self.tranche_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeInsurancePolicy {
    pub policy_id: String,
    pub flow: BridgeInsuranceFlow,
    pub policyholder_commitment: String,
    pub bridge_transfer_commitment: String,
    pub monero_txid_root: String,
    pub l2_receipt_root: String,
    pub claim_commitment_root: String,
    pub coverage_units: u64,
    pub premium_units: u64,
    pub min_reorg_depth_blocks: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub low_fee: bool,
    pub private_defi: bool,
    pub tranche_ids: Vec<String>,
    pub status: InsurancePolicyStatus,
}

impl BridgeInsurancePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &MoneroReorgInsurancePoolConfig,
        flow: BridgeInsuranceFlow,
        policyholder_commitment: impl Into<String>,
        bridge_transfer_commitment: impl Into<String>,
        monero_txid_root: impl Into<String>,
        l2_receipt_root: impl Into<String>,
        claim_commitment_root: impl Into<String>,
        coverage_units: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
        tranche_ids: Vec<String>,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let policyholder_commitment = policyholder_commitment.into();
        let bridge_transfer_commitment = bridge_transfer_commitment.into();
        let monero_txid_root = monero_txid_root.into();
        let l2_receipt_root = l2_receipt_root.into();
        let claim_commitment_root = claim_commitment_root.into();
        let policy_id = monero_reorg_insurance_pool_policy_id(
            flow,
            &policyholder_commitment,
            &bridge_transfer_commitment,
            &monero_txid_root,
            coverage_units,
            opened_at_height,
        );
        let premium_units = config.premium_for(flow, coverage_units);
        let policy = Self {
            policy_id,
            flow,
            policyholder_commitment,
            bridge_transfer_commitment,
            monero_txid_root,
            l2_receipt_root,
            claim_commitment_root,
            coverage_units,
            premium_units,
            min_reorg_depth_blocks: config.min_reorg_depth_blocks,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            low_fee: flow == BridgeInsuranceFlow::LowFeeExit,
            private_defi: matches!(
                flow,
                BridgeInsuranceFlow::PrivateDefiDeposit | BridgeInsuranceFlow::PrivateDefiExit
            ),
            tranche_ids,
            status: InsurancePolicyStatus::Active,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == InsurancePolicyStatus::Active && height >= self.expires_at_height {
            self.status = InsurancePolicyStatus::Matured;
        }
        if self.status == InsurancePolicyStatus::Matured
            && height > self.expires_at_height.saturating_add(1)
        {
            self.status = InsurancePolicyStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_insurance_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "flow": self.flow.as_str(),
            "policyholder_commitment": self.policyholder_commitment,
            "bridge_transfer_commitment": self.bridge_transfer_commitment,
            "monero_txid_root": self.monero_txid_root,
            "l2_receipt_root": self.l2_receipt_root,
            "claim_commitment_root": self.claim_commitment_root,
            "coverage_units": self.coverage_units,
            "premium_units": self.premium_units,
            "min_reorg_depth_blocks": self.min_reorg_depth_blocks,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "low_fee": self.low_fee,
            "private_defi": self.private_defi,
            "private_weight_bps": self.flow.private_weight_bps(),
            "tranche_ids": self.tranche_ids,
            "status": self.status.as_str(),
        })
    }

    pub fn policy_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-POLICY",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "policy_root",
            self.policy_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.policy_id, "policy id")?;
        ensure_non_empty(
            &self.policyholder_commitment,
            "policyholder privacy commitment",
        )?;
        ensure_non_empty(
            &self.bridge_transfer_commitment,
            "bridge transfer commitment",
        )?;
        ensure_non_empty(&self.monero_txid_root, "policy monero txid root")?;
        ensure_non_empty(&self.l2_receipt_root, "policy l2 receipt root")?;
        ensure_non_empty(&self.claim_commitment_root, "policy claim commitment root")?;
        ensure_positive(self.coverage_units, "policy coverage units")?;
        ensure_positive(self.premium_units, "policy premium units")?;
        ensure_positive(self.min_reorg_depth_blocks, "policy min reorg depth")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("policy expiry must be after open height".to_string());
        }
        if self.tranche_ids.is_empty() {
            return Err("policy must reference at least one tranche".to_string());
        }
        ensure_unique_strings(&self.tranche_ids, "policy tranche id")?;
        let expected = monero_reorg_insurance_pool_policy_id(
            self.flow,
            &self.policyholder_commitment,
            &self.bridge_transfer_commitment,
            &self.monero_txid_root,
            self.coverage_units,
            self.opened_at_height,
        );
        if self.policy_id != expected {
            return Err("policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroDaemonQuorumReport {
    pub report_id: String,
    pub observation_kind: QuorumObservationKind,
    pub monero_height: u64,
    pub l2_height: u64,
    pub canonical_block_root: String,
    pub observed_tip_root: String,
    pub daemon_set_root: String,
    pub agreeing_daemons: u64,
    pub disagreeing_daemons: u64,
    pub reorg_depth_blocks: u64,
    pub affected_policy_ids: Vec<String>,
    pub pq_attestation_ids: Vec<String>,
    pub report_commitment_root: String,
}

impl MoneroDaemonQuorumReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_kind: QuorumObservationKind,
        monero_height: u64,
        l2_height: u64,
        canonical_block_root: impl Into<String>,
        observed_tip_root: impl Into<String>,
        daemon_set_root: impl Into<String>,
        agreeing_daemons: u64,
        disagreeing_daemons: u64,
        reorg_depth_blocks: u64,
        affected_policy_ids: Vec<String>,
        pq_attestation_ids: Vec<String>,
        report_commitment_root: impl Into<String>,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let canonical_block_root = canonical_block_root.into();
        let observed_tip_root = observed_tip_root.into();
        let daemon_set_root = daemon_set_root.into();
        let report_commitment_root = report_commitment_root.into();
        let report_id = monero_reorg_insurance_pool_quorum_report_id(
            observation_kind,
            monero_height,
            l2_height,
            &canonical_block_root,
            &observed_tip_root,
        );
        let report = Self {
            report_id,
            observation_kind,
            monero_height,
            l2_height,
            canonical_block_root,
            observed_tip_root,
            daemon_set_root,
            agreeing_daemons,
            disagreeing_daemons,
            reorg_depth_blocks,
            affected_policy_ids,
            pq_attestation_ids,
            report_commitment_root,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn quorum_size(&self) -> u64 {
        self.agreeing_daemons
            .saturating_add(self.disagreeing_daemons)
    }

    pub fn disagreement_bps(&self) -> u64 {
        ratio_bps(self.disagreeing_daemons, self.quorum_size())
    }

    pub fn confirms_reorg(&self, min_depth: u64, min_agreement: u64) -> bool {
        self.observation_kind.triggers_claim()
            && self.reorg_depth_blocks >= min_depth
            && self.agreeing_daemons >= min_agreement
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_daemon_quorum_report",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "observation_kind": self.observation_kind.as_str(),
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "canonical_block_root": self.canonical_block_root,
            "observed_tip_root": self.observed_tip_root,
            "daemon_set_root": self.daemon_set_root,
            "agreeing_daemons": self.agreeing_daemons,
            "disagreeing_daemons": self.disagreeing_daemons,
            "quorum_size": self.quorum_size(),
            "disagreement_bps": self.disagreement_bps(),
            "reorg_depth_blocks": self.reorg_depth_blocks,
            "affected_policy_ids": self.affected_policy_ids,
            "pq_attestation_ids": self.pq_attestation_ids,
            "report_commitment_root": self.report_commitment_root,
        })
    }

    pub fn report_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-QUORUM-REPORT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "report_root",
            self.report_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.report_id, "quorum report id")?;
        ensure_positive(self.monero_height, "quorum monero height")?;
        ensure_positive(self.l2_height, "quorum l2 height")?;
        ensure_non_empty(&self.canonical_block_root, "quorum canonical block root")?;
        ensure_non_empty(&self.observed_tip_root, "quorum observed tip root")?;
        ensure_non_empty(&self.daemon_set_root, "quorum daemon set root")?;
        ensure_positive(self.agreeing_daemons, "quorum agreeing daemon count")?;
        ensure_non_empty(
            &self.report_commitment_root,
            "quorum report commitment root",
        )?;
        ensure_unique_strings(&self.affected_policy_ids, "quorum affected policy id")?;
        ensure_unique_strings(&self.pq_attestation_ids, "quorum attestation id")?;
        let expected = monero_reorg_insurance_pool_quorum_report_id(
            self.observation_kind,
            self.monero_height,
            self.l2_height,
            &self.canonical_block_root,
            &self.observed_tip_root,
        );
        if self.report_id != expected {
            return Err("quorum report id mismatch".to_string());
        }
        Ok(self.report_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyClaimCommitment {
    pub commitment_id: String,
    pub policy_id: String,
    pub nullifier: String,
    pub claimant_commitment: String,
    pub claim_amount_commitment: String,
    pub witness_root: String,
    pub encrypted_claim_envelope_root: String,
    pub proof_system: String,
    pub created_at_height: u64,
}

impl PrivacyClaimCommitment {
    pub fn new(
        policy_id: impl Into<String>,
        nullifier: impl Into<String>,
        claimant_commitment: impl Into<String>,
        claim_amount_commitment: impl Into<String>,
        witness_root: impl Into<String>,
        encrypted_claim_envelope_root: impl Into<String>,
        created_at_height: u64,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let policy_id = policy_id.into();
        let nullifier = nullifier.into();
        let claimant_commitment = claimant_commitment.into();
        let claim_amount_commitment = claim_amount_commitment.into();
        let witness_root = witness_root.into();
        let encrypted_claim_envelope_root = encrypted_claim_envelope_root.into();
        let commitment_id = monero_reorg_insurance_pool_claim_commitment_id(
            &policy_id,
            &nullifier,
            &claimant_commitment,
            &witness_root,
        );
        let commitment = Self {
            commitment_id,
            policy_id,
            nullifier,
            claimant_commitment,
            claim_amount_commitment,
            witness_root,
            encrypted_claim_envelope_root,
            proof_system: MONERO_REORG_INSURANCE_POOL_PRIVACY_COMMITMENT_SCHEME.to_string(),
            created_at_height,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "privacy_claim_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "policy_id": self.policy_id,
            "nullifier": self.nullifier,
            "claimant_commitment": self.claimant_commitment,
            "claim_amount_commitment": self.claim_amount_commitment,
            "witness_root": self.witness_root,
            "encrypted_claim_envelope_root": self.encrypted_claim_envelope_root,
            "proof_system": self.proof_system,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn commitment_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-CLAIM-COMMITMENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "commitment_root",
            self.commitment_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.commitment_id, "claim commitment id")?;
        ensure_non_empty(&self.policy_id, "claim commitment policy id")?;
        ensure_non_empty(&self.nullifier, "claim commitment nullifier")?;
        ensure_non_empty(&self.claimant_commitment, "claimant commitment")?;
        ensure_non_empty(
            &self.claim_amount_commitment,
            "claim amount privacy commitment",
        )?;
        ensure_non_empty(&self.witness_root, "claim witness root")?;
        ensure_non_empty(
            &self.encrypted_claim_envelope_root,
            "encrypted claim envelope root",
        )?;
        ensure_non_empty(&self.proof_system, "claim proof system")?;
        if self.proof_system != MONERO_REORG_INSURANCE_POOL_PRIVACY_COMMITMENT_SCHEME {
            return Err("claim commitment proof system mismatch".to_string());
        }
        let expected = monero_reorg_insurance_pool_claim_commitment_id(
            &self.policy_id,
            &self.nullifier,
            &self.claimant_commitment,
            &self.witness_root,
        );
        if self.commitment_id != expected {
            return Err("claim commitment id mismatch".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedPayoutClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub commitment_id: String,
    pub quorum_report_id: String,
    pub claimed_units: u64,
    pub deductible_units: u64,
    pub payout_units: u64,
    pub opened_at_height: u64,
    pub earliest_payout_height: u64,
    pub expires_at_height: u64,
    pub status: ClaimStatus,
}

impl DelayedPayoutClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &MoneroReorgInsurancePoolConfig,
        policy_id: impl Into<String>,
        commitment_id: impl Into<String>,
        quorum_report_id: impl Into<String>,
        claimed_units: u64,
        deductible_units: u64,
        opened_at_height: u64,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let policy_id = policy_id.into();
        let commitment_id = commitment_id.into();
        let quorum_report_id = quorum_report_id.into();
        let payout_units = claimed_units.saturating_sub(deductible_units);
        let claim_id = monero_reorg_insurance_pool_claim_id(
            &policy_id,
            &commitment_id,
            &quorum_report_id,
            claimed_units,
            opened_at_height,
        );
        let claim = Self {
            claim_id,
            policy_id,
            commitment_id,
            quorum_report_id,
            claimed_units,
            deductible_units,
            payout_units,
            opened_at_height,
            earliest_payout_height: opened_at_height.saturating_add(config.claim_delay_blocks),
            expires_at_height: opened_at_height.saturating_add(config.claim_window_blocks),
            status: ClaimStatus::WaitingDelay,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == ClaimStatus::WaitingDelay && height >= self.earliest_payout_height {
            self.status = ClaimStatus::EvidenceOpen;
        }
        if self.status.open() && height > self.expires_at_height {
            self.status = ClaimStatus::Expired;
        }
    }

    pub fn accept(&mut self, height: u64) -> MoneroReorgInsurancePoolResult<String> {
        if height < self.earliest_payout_height {
            return Err("claim delay has not elapsed".to_string());
        }
        if !self.status.open() {
            return Err("claim is not open".to_string());
        }
        self.status = ClaimStatus::QueuedForPayout;
        self.validate()
    }

    pub fn mark_paid(&mut self) -> MoneroReorgInsurancePoolResult<String> {
        if self.status != ClaimStatus::QueuedForPayout {
            return Err("claim is not queued for payout".to_string());
        }
        self.status = ClaimStatus::Paid;
        self.validate()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "delayed_payout_claim",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "commitment_id": self.commitment_id,
            "quorum_report_id": self.quorum_report_id,
            "claimed_units": self.claimed_units,
            "deductible_units": self.deductible_units,
            "payout_units": self.payout_units,
            "opened_at_height": self.opened_at_height,
            "earliest_payout_height": self.earliest_payout_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn claim_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-CLAIM",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "claim_root",
            self.claim_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.claim_id, "claim id")?;
        ensure_non_empty(&self.policy_id, "claim policy id")?;
        ensure_non_empty(&self.commitment_id, "claim commitment id")?;
        ensure_non_empty(&self.quorum_report_id, "claim quorum report id")?;
        ensure_positive(self.claimed_units, "claim claimed units")?;
        if self.deductible_units > self.claimed_units {
            return Err("claim deductible exceeds claim amount".to_string());
        }
        if self.payout_units != self.claimed_units.saturating_sub(self.deductible_units) {
            return Err("claim payout units mismatch".to_string());
        }
        if self.earliest_payout_height <= self.opened_at_height {
            return Err("claim payout height must follow open height".to_string());
        }
        if self.expires_at_height <= self.earliest_payout_height {
            return Err("claim expiry must follow payout delay".to_string());
        }
        let expected = monero_reorg_insurance_pool_claim_id(
            &self.policy_id,
            &self.commitment_id,
            &self.quorum_report_id,
            self.claimed_units,
            self.opened_at_height,
        );
        if self.claim_id != expected {
            return Err("claim id mismatch".to_string());
        }
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerAttestation {
    pub attestation_id: String,
    pub signer_commitment: String,
    pub subject_root: String,
    pub signature_root: String,
    pub fallback_signature_root: String,
    pub pq_scheme: String,
    pub observed_height: u64,
    pub expires_at_height: u64,
    pub quorum_weight: u64,
    pub status: PqAttestationStatus,
}

impl PqSignerAttestation {
    pub fn new(
        signer_commitment: impl Into<String>,
        subject_root: impl Into<String>,
        signature_root: impl Into<String>,
        fallback_signature_root: impl Into<String>,
        observed_height: u64,
        ttl_blocks: u64,
        quorum_weight: u64,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let signer_commitment = signer_commitment.into();
        let subject_root = subject_root.into();
        let signature_root = signature_root.into();
        let fallback_signature_root = fallback_signature_root.into();
        let attestation_id = monero_reorg_insurance_pool_pq_attestation_id(
            &signer_commitment,
            &subject_root,
            &signature_root,
            observed_height,
        );
        let attestation = Self {
            attestation_id,
            signer_commitment,
            subject_root,
            signature_root,
            fallback_signature_root,
            pq_scheme: MONERO_REORG_INSURANCE_POOL_PQ_SIGNER_SCHEME.to_string(),
            observed_height,
            expires_at_height: observed_height.saturating_add(ttl_blocks),
            quorum_weight,
            status: PqAttestationStatus::Counted,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.expires_at_height {
            self.status = PqAttestationStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "pq_signer_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "signer_commitment": self.signer_commitment,
            "subject_root": self.subject_root,
            "signature_root": self.signature_root,
            "fallback_signature_root": self.fallback_signature_root,
            "pq_scheme": self.pq_scheme,
            "observed_height": self.observed_height,
            "expires_at_height": self.expires_at_height,
            "quorum_weight": self.quorum_weight,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-PQ-ATTESTATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "attestation_root",
            self.attestation_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.attestation_id, "pq attestation id")?;
        ensure_non_empty(&self.signer_commitment, "pq signer commitment")?;
        ensure_non_empty(&self.subject_root, "pq attestation subject root")?;
        ensure_non_empty(&self.signature_root, "pq attestation signature root")?;
        ensure_non_empty(&self.fallback_signature_root, "pq fallback signature root")?;
        ensure_non_empty(&self.pq_scheme, "pq scheme")?;
        ensure_positive(self.expires_at_height, "pq attestation expiry")?;
        ensure_positive(self.quorum_weight, "pq attestation quorum weight")?;
        if self.pq_scheme != MONERO_REORG_INSURANCE_POOL_PQ_SIGNER_SCHEME {
            return Err("pq attestation scheme mismatch".to_string());
        }
        if self.expires_at_height <= self.observed_height {
            return Err("pq attestation expiry must follow observation height".to_string());
        }
        let expected = monero_reorg_insurance_pool_pq_attestation_id(
            &self.signer_commitment,
            &self.subject_root,
            &self.signature_root,
            self.observed_height,
        );
        if self.attestation_id != expected {
            return Err("pq attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPauseBand {
    pub pause_id: String,
    pub risk_band: ReorgRiskBand,
    pub reason_root: String,
    pub triggering_report_ids: Vec<String>,
    pub min_reorg_depth_blocks: u64,
    pub min_disagreement_bps: u64,
    pub started_at_height: u64,
    pub expires_at_height: u64,
    pub status: PauseBandStatus,
}

impl EmergencyPauseBand {
    pub fn new(
        risk_band: ReorgRiskBand,
        reason_root: impl Into<String>,
        triggering_report_ids: Vec<String>,
        min_reorg_depth_blocks: u64,
        min_disagreement_bps: u64,
        started_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let reason_root = reason_root.into();
        let pause_id = monero_reorg_insurance_pool_pause_id(
            risk_band,
            &reason_root,
            min_reorg_depth_blocks,
            min_disagreement_bps,
            started_at_height,
        );
        let pause = Self {
            pause_id,
            risk_band,
            reason_root,
            triggering_report_ids,
            min_reorg_depth_blocks,
            min_disagreement_bps,
            started_at_height,
            expires_at_height: started_at_height.saturating_add(ttl_blocks),
            status: PauseBandStatus::Active,
        };
        pause.validate()?;
        Ok(pause)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.expires_at_height {
            self.status = PauseBandStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "emergency_pause_band",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "pause_id": self.pause_id,
            "risk_band": self.risk_band.as_str(),
            "risk_score_bps": self.risk_band.risk_score_bps(),
            "reason_root": self.reason_root,
            "triggering_report_ids": self.triggering_report_ids,
            "min_reorg_depth_blocks": self.min_reorg_depth_blocks,
            "min_disagreement_bps": self.min_disagreement_bps,
            "started_at_height": self.started_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn pause_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-PAUSE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "pause_root",
            self.pause_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.pause_id, "pause id")?;
        ensure_non_empty(&self.reason_root, "pause reason root")?;
        ensure_positive(self.min_reorg_depth_blocks, "pause min reorg depth")?;
        ensure_bps(self.min_disagreement_bps, "pause min disagreement bps")?;
        if self.expires_at_height <= self.started_at_height {
            return Err("pause expiry must follow start height".to_string());
        }
        ensure_unique_strings(&self.triggering_report_ids, "pause report id")?;
        let expected = monero_reorg_insurance_pool_pause_id(
            self.risk_band,
            &self.reason_root,
            self.min_reorg_depth_blocks,
            self.min_disagreement_bps,
            self.started_at_height,
        );
        if self.pause_id != expected {
            return Err("pause id mismatch".to_string());
        }
        Ok(self.pause_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsurancePayoutReceipt {
    pub payout_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub tranche_debit_root: String,
    pub recipient_commitment: String,
    pub amount_units: u64,
    pub paid_at_height: u64,
    pub privacy_receipt_root: String,
}

impl InsurancePayoutReceipt {
    pub fn new(
        claim_id: impl Into<String>,
        policy_id: impl Into<String>,
        tranche_debit_root: impl Into<String>,
        recipient_commitment: impl Into<String>,
        amount_units: u64,
        paid_at_height: u64,
        privacy_receipt_root: impl Into<String>,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let claim_id = claim_id.into();
        let policy_id = policy_id.into();
        let tranche_debit_root = tranche_debit_root.into();
        let recipient_commitment = recipient_commitment.into();
        let privacy_receipt_root = privacy_receipt_root.into();
        let payout_id = monero_reorg_insurance_pool_payout_id(
            &claim_id,
            &policy_id,
            &recipient_commitment,
            amount_units,
            paid_at_height,
        );
        let receipt = Self {
            payout_id,
            claim_id,
            policy_id,
            tranche_debit_root,
            recipient_commitment,
            amount_units,
            paid_at_height,
            privacy_receipt_root,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "insurance_payout_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "payout_id": self.payout_id,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "tranche_debit_root": self.tranche_debit_root,
            "recipient_commitment": self.recipient_commitment,
            "amount_units": self.amount_units,
            "paid_at_height": self.paid_at_height,
            "privacy_receipt_root": self.privacy_receipt_root,
        })
    }

    pub fn payout_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-PAYOUT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "payout_root",
            self.payout_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.payout_id, "payout id")?;
        ensure_non_empty(&self.claim_id, "payout claim id")?;
        ensure_non_empty(&self.policy_id, "payout policy id")?;
        ensure_non_empty(&self.tranche_debit_root, "payout tranche debit root")?;
        ensure_non_empty(&self.recipient_commitment, "payout recipient commitment")?;
        ensure_positive(self.amount_units, "payout amount")?;
        ensure_non_empty(&self.privacy_receipt_root, "payout privacy receipt root")?;
        let expected = monero_reorg_insurance_pool_payout_id(
            &self.claim_id,
            &self.policy_id,
            &self.recipient_commitment,
            self.amount_units,
            self.paid_at_height,
        );
        if self.payout_id != expected {
            return Err("payout id mismatch".to_string());
        }
        Ok(self.payout_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsurancePoolPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl InsurancePoolPublicRecord {
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        emitted_at_height: u64,
        sequence: u64,
    ) -> MoneroReorgInsurancePoolResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let payload = json!({
            "record_kind": record_kind.as_str(),
            "subject_id": subject_id,
            "subject_root": subject_root,
            "emitted_at_height": emitted_at_height,
            "sequence": sequence,
        });
        let payload_root = monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-RECORD-PAYLOAD",
            &payload,
        );
        let record_id = monero_reorg_insurance_pool_public_record_id(
            record_kind,
            &subject_id,
            &subject_root,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            record_kind,
            subject_id,
            subject_root,
            payload_root,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "insurance_pool_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "schema": MONERO_REORG_INSURANCE_POOL_PUBLIC_RECORD_SCHEMA,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-PUBLIC-RECORD",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "public record subject id")?;
        ensure_non_empty(&self.subject_root, "public record subject root")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        let expected = monero_reorg_insurance_pool_public_record_id(
            self.record_kind,
            &self.subject_id,
            &self.subject_root,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReorgInsurancePoolRoots {
    pub config_root: String,
    pub policy_root: String,
    pub quorum_report_root: String,
    pub claim_commitment_root: String,
    pub claim_root: String,
    pub tranche_root: String,
    pub pq_attestation_root: String,
    pub pause_band_root: String,
    pub payout_root: String,
    pub public_record_root: String,
    pub consumed_nullifier_root: String,
}

impl MoneroReorgInsurancePoolRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reorg_insurance_pool_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "policy_root": self.policy_root,
            "quorum_report_root": self.quorum_report_root,
            "claim_commitment_root": self.claim_commitment_root,
            "claim_root": self.claim_root,
            "tranche_root": self.tranche_root,
            "pq_attestation_root": self.pq_attestation_root,
            "pause_band_root": self.pause_band_root,
            "payout_root": self.payout_root,
            "public_record_root": self.public_record_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
        })
    }

    pub fn roots_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReorgInsurancePoolCounters {
    pub policy_count: u64,
    pub active_policy_count: u64,
    pub claim_count: u64,
    pub open_claim_count: u64,
    pub paid_claim_count: u64,
    pub quorum_report_count: u64,
    pub tranche_count: u64,
    pub active_tranche_count: u64,
    pub pq_attestation_count: u64,
    pub active_pause_count: u64,
    pub public_record_count: u64,
    pub consumed_nullifier_count: u64,
    pub insured_units: u64,
    pub locked_coverage_units: u64,
    pub total_premium_units: u64,
    pub tranche_funded_units: u64,
    pub tranche_available_units: u64,
    pub pending_payout_units: u64,
    pub paid_payout_units: u64,
    pub latest_reorg_depth_blocks: u64,
    pub latest_disagreement_bps: u64,
    pub reserve_coverage_bps: u64,
    pub risk_band: ReorgRiskBand,
}

impl MoneroReorgInsurancePoolCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reorg_insurance_pool_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "policy_count": self.policy_count,
            "active_policy_count": self.active_policy_count,
            "claim_count": self.claim_count,
            "open_claim_count": self.open_claim_count,
            "paid_claim_count": self.paid_claim_count,
            "quorum_report_count": self.quorum_report_count,
            "tranche_count": self.tranche_count,
            "active_tranche_count": self.active_tranche_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pause_count": self.active_pause_count,
            "public_record_count": self.public_record_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
            "insured_units": self.insured_units,
            "locked_coverage_units": self.locked_coverage_units,
            "total_premium_units": self.total_premium_units,
            "tranche_funded_units": self.tranche_funded_units,
            "tranche_available_units": self.tranche_available_units,
            "pending_payout_units": self.pending_payout_units,
            "paid_payout_units": self.paid_payout_units,
            "latest_reorg_depth_blocks": self.latest_reorg_depth_blocks,
            "latest_disagreement_bps": self.latest_disagreement_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "risk_band": self.risk_band.as_str(),
            "risk_score_bps": self.risk_band.risk_score_bps(),
        })
    }

    pub fn counters_root(&self) -> String {
        monero_reorg_insurance_pool_payload_root(
            "MONERO-REORG-INSURANCE-POOL-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReorgInsurancePoolState {
    pub config: MoneroReorgInsurancePoolConfig,
    pub height: u64,
    pub risk_band: ReorgRiskBand,
    pub next_public_record_sequence: u64,
    pub policies: BTreeMap<String, BridgeInsurancePolicy>,
    pub quorum_reports: BTreeMap<String, MoneroDaemonQuorumReport>,
    pub claim_commitments: BTreeMap<String, PrivacyClaimCommitment>,
    pub claims: BTreeMap<String, DelayedPayoutClaim>,
    pub tranches: BTreeMap<String, InsurerTranche>,
    pub pq_attestations: BTreeMap<String, PqSignerAttestation>,
    pub pause_bands: BTreeMap<String, EmergencyPauseBand>,
    pub payout_receipts: BTreeMap<String, InsurancePayoutReceipt>,
    pub public_records: BTreeMap<String, InsurancePoolPublicRecord>,
    pub consumed_claim_nullifiers: BTreeSet<String>,
}

impl MoneroReorgInsurancePoolState {
    pub fn devnet() -> MoneroReorgInsurancePoolResult<Self> {
        let config = MoneroReorgInsurancePoolConfig::devnet();
        let mut state = Self {
            config,
            height: 1,
            risk_band: ReorgRiskBand::Normal,
            next_public_record_sequence: 0,
            policies: BTreeMap::new(),
            quorum_reports: BTreeMap::new(),
            claim_commitments: BTreeMap::new(),
            claims: BTreeMap::new(),
            tranches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            pause_bands: BTreeMap::new(),
            payout_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_claim_nullifiers: BTreeSet::new(),
        };
        let config_root = state.config.config_root();
        state.record_public_record(
            PublicRecordKind::Config,
            state.config.config_id.clone(),
            config_root,
        )?;

        let senior = InsurerTranche::new(
            InsurerTrancheKind::Senior,
            "devnet-senior-insurer-commitment",
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-CAPITAL",
                "senior",
            ),
            state.config.asset_id.clone(),
            75_000_000_000,
            MONERO_REORG_INSURANCE_POOL_DEFAULT_SENIOR_ATTACHMENT_BPS,
            3_500,
            state.height,
        )?;
        let mezzanine = InsurerTranche::new(
            InsurerTrancheKind::Mezzanine,
            "devnet-mezzanine-insurer-commitment",
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-CAPITAL",
                "mezzanine",
            ),
            state.config.asset_id.clone(),
            35_000_000_000,
            MONERO_REORG_INSURANCE_POOL_DEFAULT_MEZZANINE_ATTACHMENT_BPS,
            4_000,
            state.height,
        )?;
        let junior = InsurerTranche::new(
            InsurerTrancheKind::Junior,
            "devnet-junior-insurer-commitment",
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-CAPITAL",
                "junior",
            ),
            state.config.asset_id.clone(),
            15_000_000_000,
            MONERO_REORG_INSURANCE_POOL_DEFAULT_JUNIOR_ATTACHMENT_BPS,
            2_500,
            state.height,
        )?;
        state.insert_tranche(senior)?;
        state.insert_tranche(mezzanine)?;
        state.insert_tranche(junior)?;

        let subject_root = monero_reorg_insurance_pool_string_root(
            "MONERO-REORG-INSURANCE-POOL-DEVNET-SUBJECT",
            "daemon-quorum-genesis",
        );
        let attestation = PqSignerAttestation::new(
            "devnet-insurance-signer-quorum",
            subject_root.clone(),
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-SIGNATURE",
                "primary",
            ),
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-SIGNATURE",
                "fallback",
            ),
            state.height,
            state.config.attestation_ttl_blocks,
            state.config.min_quorum_agreement,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        state.insert_pq_attestation(attestation)?;

        let tranche_ids = state.tranches.keys().cloned().collect::<Vec<_>>();
        let commitment = PrivacyClaimCommitment::new(
            "devnet-policy-placeholder",
            "devnet-claim-nullifier-0",
            "devnet-private-claimant-commitment",
            "devnet-private-amount-commitment",
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-WITNESS",
                "claim-witness",
            ),
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-ENVELOPE",
                "claim-envelope",
            ),
            state.height,
        )?;
        let mut policy = BridgeInsurancePolicy::new(
            &state.config,
            BridgeInsuranceFlow::PrivateDefiExit,
            "devnet-policyholder-commitment",
            "devnet-bridge-transfer-commitment",
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-TXID",
                "deposit-or-exit",
            ),
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-L2-RECEIPT",
                "receipt",
            ),
            commitment.commitment_root(),
            5_000_000_000,
            state.height,
            48,
            tranche_ids,
        )?;
        let policy_id = policy.policy_id.clone();
        let commitment = PrivacyClaimCommitment {
            policy_id: policy_id.clone(),
            commitment_id: monero_reorg_insurance_pool_claim_commitment_id(
                &policy_id,
                &commitment.nullifier,
                &commitment.claimant_commitment,
                &commitment.witness_root,
            ),
            ..commitment
        };
        policy.claim_commitment_root = commitment.commitment_root();
        state.insert_policy(policy)?;
        state.insert_claim_commitment(commitment)?;

        let report = MoneroDaemonQuorumReport::new(
            QuorumObservationKind::StableTip,
            3_100_000,
            state.height,
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-BLOCK",
                "canonical",
            ),
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-BLOCK",
                "observed",
            ),
            monero_reorg_insurance_pool_string_root(
                "MONERO-REORG-INSURANCE-POOL-DEVNET-DAEMON-SET",
                "quorum",
            ),
            state.config.min_quorum_agreement,
            0,
            0,
            vec![policy_id],
            vec![attestation_id],
            subject_root,
        )?;
        state.insert_quorum_report(report)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroReorgInsurancePoolResult<()> {
        if height < self.height {
            return Err("insurance pool height cannot move backwards".to_string());
        }
        self.height = height;
        for policy in self.policies.values_mut() {
            policy.set_height(height);
        }
        for claim in self.claims.values_mut() {
            claim.set_height(height);
        }
        for attestation in self.pq_attestations.values_mut() {
            attestation.set_height(height);
        }
        for pause in self.pause_bands.values_mut() {
            pause.set_height(height);
        }
        self.recompute_risk_band();
        self.validate()?;
        Ok(())
    }

    pub fn insert_tranche(
        &mut self,
        tranche: InsurerTranche,
    ) -> MoneroReorgInsurancePoolResult<String> {
        tranche.validate()?;
        let root = tranche.tranche_root();
        let id = tranche.tranche_id.clone();
        if self.tranches.contains_key(&id) {
            return Err("duplicate insurance tranche".to_string());
        }
        self.tranches.insert(id.clone(), tranche);
        self.record_public_record(PublicRecordKind::Tranche, id, root.clone())?;
        Ok(root)
    }

    pub fn insert_policy(
        &mut self,
        policy: BridgeInsurancePolicy,
    ) -> MoneroReorgInsurancePoolResult<String> {
        if !self.risk_band.allows_new_policy() {
            return Err("insurance pool paused for new policies".to_string());
        }
        policy.validate()?;
        if policy.coverage_units > self.config.max_policy_amount_units {
            return Err("policy coverage exceeds configured maximum".to_string());
        }
        for tranche_id in &policy.tranche_ids {
            if !self.tranches.contains_key(tranche_id) {
                return Err("policy references missing tranche".to_string());
            }
        }
        let root = policy.policy_root();
        let id = policy.policy_id.clone();
        if self.policies.contains_key(&id) {
            return Err("duplicate insurance policy".to_string());
        }
        self.policies.insert(id.clone(), policy);
        self.record_public_record(PublicRecordKind::Policy, id, root.clone())?;
        Ok(root)
    }

    pub fn insert_quorum_report(
        &mut self,
        report: MoneroDaemonQuorumReport,
    ) -> MoneroReorgInsurancePoolResult<String> {
        report.validate()?;
        if report.quorum_size() > self.config.daemon_quorum_size {
            return Err("quorum report exceeds configured quorum size".to_string());
        }
        for policy_id in &report.affected_policy_ids {
            if !self.policies.contains_key(policy_id) {
                return Err("quorum report references missing policy".to_string());
            }
        }
        for attestation_id in &report.pq_attestation_ids {
            if !self.pq_attestations.contains_key(attestation_id) {
                return Err("quorum report references missing pq attestation".to_string());
            }
        }
        let root = report.report_root();
        let id = report.report_id.clone();
        if self.quorum_reports.contains_key(&id) {
            return Err("duplicate quorum report".to_string());
        }
        self.quorum_reports.insert(id.clone(), report);
        self.recompute_risk_band();
        self.record_public_record(PublicRecordKind::QuorumReport, id, root.clone())?;
        Ok(root)
    }

    pub fn insert_claim_commitment(
        &mut self,
        commitment: PrivacyClaimCommitment,
    ) -> MoneroReorgInsurancePoolResult<String> {
        commitment.validate()?;
        if !self.policies.contains_key(&commitment.policy_id) {
            return Err("claim commitment references missing policy".to_string());
        }
        if self
            .consumed_claim_nullifiers
            .contains(&commitment.nullifier)
        {
            return Err("claim nullifier already consumed".to_string());
        }
        let root = commitment.commitment_root();
        let id = commitment.commitment_id.clone();
        if self.claim_commitments.contains_key(&id) {
            return Err("duplicate claim commitment".to_string());
        }
        self.consumed_claim_nullifiers
            .insert(commitment.nullifier.clone());
        self.claim_commitments.insert(id.clone(), commitment);
        self.record_public_record(PublicRecordKind::ClaimCommitment, id, root.clone())?;
        Ok(root)
    }

    pub fn insert_claim(
        &mut self,
        claim: DelayedPayoutClaim,
    ) -> MoneroReorgInsurancePoolResult<String> {
        claim.validate()?;
        let claim_policy_id = claim.policy_id.clone();
        let policy = match self.policies.get(&claim_policy_id) {
            Some(policy) => policy,
            None => return Err("claim references missing policy".to_string()),
        };
        if claim.claimed_units > policy.coverage_units {
            return Err("claim exceeds policy coverage".to_string());
        }
        if !self.claim_commitments.contains_key(&claim.commitment_id) {
            return Err("claim references missing commitment".to_string());
        }
        let report = match self.quorum_reports.get(&claim.quorum_report_id) {
            Some(report) => report,
            None => return Err("claim references missing quorum report".to_string()),
        };
        if !report.confirms_reorg(
            self.config.min_reorg_depth_blocks,
            self.config.min_quorum_agreement,
        ) {
            return Err("claim quorum report does not confirm covered event".to_string());
        }
        let root = claim.claim_root();
        let id = claim.claim_id.clone();
        if self.claims.contains_key(&id) {
            return Err("duplicate claim".to_string());
        }
        self.claims.insert(id.clone(), claim);
        if let Some(policy) = self.policies.get_mut(&claim_policy_id) {
            policy.status = InsurancePolicyStatus::Claimed;
        }
        self.record_public_record(PublicRecordKind::Claim, id, root.clone())?;
        Ok(root)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqSignerAttestation,
    ) -> MoneroReorgInsurancePoolResult<String> {
        attestation.validate()?;
        let root = attestation.attestation_root();
        let id = attestation.attestation_id.clone();
        if self.pq_attestations.contains_key(&id) {
            return Err("duplicate pq attestation".to_string());
        }
        self.pq_attestations.insert(id.clone(), attestation);
        self.record_public_record(PublicRecordKind::PqAttestation, id, root.clone())?;
        Ok(root)
    }

    pub fn insert_pause_band(
        &mut self,
        pause: EmergencyPauseBand,
    ) -> MoneroReorgInsurancePoolResult<String> {
        pause.validate()?;
        for report_id in &pause.triggering_report_ids {
            if !self.quorum_reports.contains_key(report_id) {
                return Err("pause references missing quorum report".to_string());
            }
        }
        let root = pause.pause_root();
        let id = pause.pause_id.clone();
        if self.pause_bands.contains_key(&id) {
            return Err("duplicate pause band".to_string());
        }
        self.pause_bands.insert(id.clone(), pause);
        self.recompute_risk_band();
        self.record_public_record(PublicRecordKind::PauseBand, id, root.clone())?;
        Ok(root)
    }

    pub fn insert_payout_receipt(
        &mut self,
        receipt: InsurancePayoutReceipt,
    ) -> MoneroReorgInsurancePoolResult<String> {
        receipt.validate()?;
        if !self.claims.contains_key(&receipt.claim_id) {
            return Err("payout references missing claim".to_string());
        }
        if !self.policies.contains_key(&receipt.policy_id) {
            return Err("payout references missing policy".to_string());
        }
        let root = receipt.payout_root();
        let id = receipt.payout_id.clone();
        if self.payout_receipts.contains_key(&id) {
            return Err("duplicate payout receipt".to_string());
        }
        self.payout_receipts.insert(id.clone(), receipt);
        self.record_public_record(PublicRecordKind::Payout, id, root.clone())?;
        Ok(root)
    }

    pub fn roots(&self) -> MoneroReorgInsurancePoolRoots {
        MoneroReorgInsurancePoolRoots {
            config_root: self.config.config_root(),
            policy_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-POLICY-COLLECTION",
                self.policies
                    .values()
                    .map(|policy| (policy.policy_id.clone(), policy.public_record()))
                    .collect(),
            ),
            quorum_report_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-QUORUM-REPORT-COLLECTION",
                self.quorum_reports
                    .values()
                    .map(|report| (report.report_id.clone(), report.public_record()))
                    .collect(),
            ),
            claim_commitment_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-CLAIM-COMMITMENT-COLLECTION",
                self.claim_commitments
                    .values()
                    .map(|commitment| {
                        (commitment.commitment_id.clone(), commitment.public_record())
                    })
                    .collect(),
            ),
            claim_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-CLAIM-COLLECTION",
                self.claims
                    .values()
                    .map(|claim| (claim.claim_id.clone(), claim.public_record()))
                    .collect(),
            ),
            tranche_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-TRANCHE-COLLECTION",
                self.tranches
                    .values()
                    .map(|tranche| (tranche.tranche_id.clone(), tranche.public_record()))
                    .collect(),
            ),
            pq_attestation_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-PQ-ATTESTATION-COLLECTION",
                self.pq_attestations
                    .values()
                    .map(|attestation| {
                        (
                            attestation.attestation_id.clone(),
                            attestation.public_record(),
                        )
                    })
                    .collect(),
            ),
            pause_band_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-PAUSE-COLLECTION",
                self.pause_bands
                    .values()
                    .map(|pause| (pause.pause_id.clone(), pause.public_record()))
                    .collect(),
            ),
            payout_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-PAYOUT-COLLECTION",
                self.payout_receipts
                    .values()
                    .map(|payout| (payout.payout_id.clone(), payout.public_record()))
                    .collect(),
            ),
            public_record_root: collection_root(
                "MONERO-REORG-INSURANCE-POOL-PUBLIC-RECORD-COLLECTION",
                self.public_records
                    .values()
                    .map(|record| (record.record_id.clone(), record.public_record()))
                    .collect(),
            ),
            consumed_nullifier_root: string_set_root(
                "MONERO-REORG-INSURANCE-POOL-CONSUMED-NULLIFIERS",
                &self
                    .consumed_claim_nullifiers
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> MoneroReorgInsurancePoolCounters {
        let active_policy_count = self
            .policies
            .values()
            .filter(|policy| policy.status.open())
            .count() as u64;
        let open_claim_count = self
            .claims
            .values()
            .filter(|claim| claim.status.open())
            .count() as u64;
        let paid_claim_count = self
            .claims
            .values()
            .filter(|claim| claim.status == ClaimStatus::Paid)
            .count() as u64;
        let active_tranche_count = self
            .tranches
            .values()
            .filter(|tranche| tranche.status.can_cover())
            .count() as u64;
        let active_pause_count = self
            .pause_bands
            .values()
            .filter(|pause| pause.status.active())
            .count() as u64;
        let insured_units = self
            .policies
            .values()
            .map(|policy| policy.coverage_units)
            .fold(0_u64, u64::saturating_add);
        let locked_coverage_units = self
            .policies
            .values()
            .filter(|policy| policy.status.locked())
            .map(|policy| policy.coverage_units)
            .fold(0_u64, u64::saturating_add);
        let total_premium_units = self
            .policies
            .values()
            .map(|policy| policy.premium_units)
            .fold(0_u64, u64::saturating_add);
        let tranche_funded_units = self
            .tranches
            .values()
            .map(|tranche| tranche.funded_units)
            .fold(0_u64, u64::saturating_add);
        let tranche_available_units = self
            .tranches
            .values()
            .map(InsurerTranche::available_units)
            .fold(0_u64, u64::saturating_add);
        let pending_payout_units = self
            .claims
            .values()
            .filter(|claim| claim.status == ClaimStatus::QueuedForPayout)
            .map(|claim| claim.payout_units)
            .fold(0_u64, u64::saturating_add);
        let paid_payout_units = self
            .payout_receipts
            .values()
            .map(|receipt| receipt.amount_units)
            .fold(0_u64, u64::saturating_add);
        let latest_report = self
            .quorum_reports
            .values()
            .max_by_key(|report| report.l2_height);
        let latest_reorg_depth_blocks = match latest_report {
            Some(report) => report.reorg_depth_blocks,
            None => 0,
        };
        let latest_disagreement_bps = match latest_report {
            Some(report) => report.disagreement_bps(),
            None => 0,
        };
        MoneroReorgInsurancePoolCounters {
            policy_count: self.policies.len() as u64,
            active_policy_count,
            claim_count: self.claims.len() as u64,
            open_claim_count,
            paid_claim_count,
            quorum_report_count: self.quorum_reports.len() as u64,
            tranche_count: self.tranches.len() as u64,
            active_tranche_count,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pause_count,
            public_record_count: self.public_records.len() as u64,
            consumed_nullifier_count: self.consumed_claim_nullifiers.len() as u64,
            insured_units,
            locked_coverage_units,
            total_premium_units,
            tranche_funded_units,
            tranche_available_units,
            pending_payout_units,
            paid_payout_units,
            latest_reorg_depth_blocks,
            latest_disagreement_bps,
            reserve_coverage_bps: ratio_bps(tranche_available_units, locked_coverage_units),
            risk_band: self.risk_band,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_reorg_insurance_pool_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION,
            "height": self.height,
            "risk_band": self.risk_band.as_str(),
            "risk_score_bps": self.risk_band.risk_score_bps(),
            "next_public_record_sequence": self.next_public_record_sequence,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "monero_reorg_insurance_pool_state_root",
            self.state_root(),
        )
    }

    pub fn state_root(&self) -> String {
        monero_reorg_insurance_pool_state_root_from_record(&self.public_record_without_root())
    }

    pub fn validate(&self) -> MoneroReorgInsurancePoolResult<String> {
        self.config.validate()?;
        for (key, tranche) in &self.tranches {
            if key != &tranche.tranche_id {
                return Err("tranche map key mismatch".to_string());
            }
            tranche.validate()?;
        }
        for (key, policy) in &self.policies {
            if key != &policy.policy_id {
                return Err("policy map key mismatch".to_string());
            }
            policy.validate()?;
            if policy.coverage_units > self.config.max_policy_amount_units {
                return Err("policy coverage exceeds configured maximum".to_string());
            }
            for tranche_id in &policy.tranche_ids {
                if !self.tranches.contains_key(tranche_id) {
                    return Err("policy references missing tranche".to_string());
                }
            }
        }
        for (key, attestation) in &self.pq_attestations {
            if key != &attestation.attestation_id {
                return Err("pq attestation map key mismatch".to_string());
            }
            attestation.validate()?;
        }
        for (key, report) in &self.quorum_reports {
            if key != &report.report_id {
                return Err("quorum report map key mismatch".to_string());
            }
            report.validate()?;
            if report.quorum_size() > self.config.daemon_quorum_size {
                return Err("quorum report exceeds configured quorum size".to_string());
            }
            for policy_id in &report.affected_policy_ids {
                if !self.policies.contains_key(policy_id) {
                    return Err("quorum report references missing policy".to_string());
                }
            }
            for attestation_id in &report.pq_attestation_ids {
                if !self.pq_attestations.contains_key(attestation_id) {
                    return Err("quorum report references missing pq attestation".to_string());
                }
            }
        }
        let mut expected_nullifiers = BTreeSet::new();
        for (key, commitment) in &self.claim_commitments {
            if key != &commitment.commitment_id {
                return Err("claim commitment map key mismatch".to_string());
            }
            commitment.validate()?;
            if !self.policies.contains_key(&commitment.policy_id) {
                return Err("claim commitment references missing policy".to_string());
            }
            if !expected_nullifiers.insert(commitment.nullifier.clone()) {
                return Err("duplicate consumed claim nullifier".to_string());
            }
        }
        if expected_nullifiers != self.consumed_claim_nullifiers {
            return Err("consumed claim nullifier set mismatch".to_string());
        }
        for (key, claim) in &self.claims {
            if key != &claim.claim_id {
                return Err("claim map key mismatch".to_string());
            }
            claim.validate()?;
            let policy = match self.policies.get(&claim.policy_id) {
                Some(policy) => policy,
                None => return Err("claim references missing policy".to_string()),
            };
            if claim.claimed_units > policy.coverage_units {
                return Err("claim exceeds policy coverage".to_string());
            }
            if !self.claim_commitments.contains_key(&claim.commitment_id) {
                return Err("claim references missing commitment".to_string());
            }
            if !self.quorum_reports.contains_key(&claim.quorum_report_id) {
                return Err("claim references missing quorum report".to_string());
            }
        }
        for (key, pause) in &self.pause_bands {
            if key != &pause.pause_id {
                return Err("pause map key mismatch".to_string());
            }
            pause.validate()?;
            for report_id in &pause.triggering_report_ids {
                if !self.quorum_reports.contains_key(report_id) {
                    return Err("pause references missing quorum report".to_string());
                }
            }
        }
        for (key, payout) in &self.payout_receipts {
            if key != &payout.payout_id {
                return Err("payout map key mismatch".to_string());
            }
            payout.validate()?;
            if !self.claims.contains_key(&payout.claim_id) {
                return Err("payout references missing claim".to_string());
            }
            if !self.policies.contains_key(&payout.policy_id) {
                return Err("payout references missing policy".to_string());
            }
        }
        let mut seen_sequences = BTreeSet::new();
        for (key, record) in &self.public_records {
            if key != &record.record_id {
                return Err("public record map key mismatch".to_string());
            }
            record.validate()?;
            if !seen_sequences.insert(record.sequence) {
                return Err("duplicate public record sequence".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn record_public_record(
        &mut self,
        record_kind: PublicRecordKind,
        subject_id: String,
        subject_root: String,
    ) -> MoneroReorgInsurancePoolResult<String> {
        let sequence = self.next_public_record_sequence;
        self.next_public_record_sequence = self.next_public_record_sequence.saturating_add(1);
        let record = InsurancePoolPublicRecord::new(
            record_kind,
            subject_id,
            subject_root,
            self.height,
            sequence,
        )?;
        let root = record.record_root();
        self.public_records.insert(record.record_id.clone(), record);
        Ok(root)
    }

    fn recompute_risk_band(&mut self) {
        let mut band = ReorgRiskBand::Normal;
        for pause in self.pause_bands.values() {
            if pause.status.active() && pause.risk_band > band {
                band = pause.risk_band;
            }
        }
        for report in self.quorum_reports.values() {
            if report.reorg_depth_blocks >= self.config.severe_reorg_depth_blocks {
                band = band.max(ReorgRiskBand::Emergency);
            } else if report.reorg_depth_blocks >= self.config.min_reorg_depth_blocks {
                band = band.max(ReorgRiskBand::Throttled);
            } else if report.disagreement_bps() >= self.config.disagreement_pause_bps {
                band = band.max(ReorgRiskBand::Paused);
            } else if report.disagreeing_daemons > 0 {
                band = band.max(ReorgRiskBand::Watch);
            }
        }
        self.risk_band = band;
    }
}

pub fn monero_reorg_insurance_pool_state_root_from_record(record: &Value) -> String {
    monero_reorg_insurance_pool_payload_root("MONERO-REORG-INSURANCE-POOL-STATE", record)
}

pub fn monero_reorg_insurance_pool_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_REORG_INSURANCE_POOL_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_tranche_id(
    kind: InsurerTrancheKind,
    sponsor_commitment: &str,
    capital_commitment_root: &str,
    funded_units: u64,
    registered_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-TRANCHE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(capital_commitment_root),
            HashPart::Int(funded_units as i128),
            HashPart::Int(registered_at_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_policy_id(
    flow: BridgeInsuranceFlow,
    policyholder_commitment: &str,
    bridge_transfer_commitment: &str,
    monero_txid_root: &str,
    coverage_units: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(flow.as_str()),
            HashPart::Str(policyholder_commitment),
            HashPart::Str(bridge_transfer_commitment),
            HashPart::Str(monero_txid_root),
            HashPart::Int(coverage_units as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_quorum_report_id(
    observation_kind: QuorumObservationKind,
    monero_height: u64,
    l2_height: u64,
    canonical_block_root: &str,
    observed_tip_root: &str,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-QUORUM-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(observation_kind.as_str()),
            HashPart::Int(monero_height as i128),
            HashPart::Int(l2_height as i128),
            HashPart::Str(canonical_block_root),
            HashPart::Str(observed_tip_root),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_claim_commitment_id(
    policy_id: &str,
    nullifier: &str,
    claimant_commitment: &str,
    witness_root: &str,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-CLAIM-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(nullifier),
            HashPart::Str(claimant_commitment),
            HashPart::Str(witness_root),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_claim_id(
    policy_id: &str,
    commitment_id: &str,
    quorum_report_id: &str,
    claimed_units: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(commitment_id),
            HashPart::Str(quorum_report_id),
            HashPart::Int(claimed_units as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_pq_attestation_id(
    signer_commitment: &str,
    subject_root: &str,
    signature_root: &str,
    observed_height: u64,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_commitment),
            HashPart::Str(subject_root),
            HashPart::Str(signature_root),
            HashPart::Int(observed_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_pause_id(
    risk_band: ReorgRiskBand,
    reason_root: &str,
    min_reorg_depth_blocks: u64,
    min_disagreement_bps: u64,
    started_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-PAUSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(risk_band.as_str()),
            HashPart::Str(reason_root),
            HashPart::Int(min_reorg_depth_blocks as i128),
            HashPart::Int(min_disagreement_bps as i128),
            HashPart::Int(started_at_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_payout_id(
    claim_id: &str,
    policy_id: &str,
    recipient_commitment: &str,
    amount_units: u64,
    paid_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-PAYOUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_id),
            HashPart::Str(policy_id),
            HashPart::Str(recipient_commitment),
            HashPart::Int(amount_units as i128),
            HashPart::Int(paid_at_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_insurance_pool_public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-REORG-INSURANCE-POOL-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn collection_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let payload = json!({
        "kind": "monero_reorg_insurance_pool_collection",
        "domain": domain,
        "records": records
            .into_iter()
            .map(|(key, value)| json!({"key": key, "value": value}))
            .collect::<Vec<_>>(),
    });
    monero_reorg_insurance_pool_payload_root(domain, &payload)
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    let payload = json!({
        "kind": "monero_reorg_insurance_pool_string_set",
        "domain": domain,
        "values": sorted,
    });
    monero_reorg_insurance_pool_payload_root(domain, &payload)
}

fn with_root_field(mut record: Value, field_name: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field_name.to_string(), Value::String(root));
    }
    record
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator
            .saturating_mul(MONERO_REORG_INSURANCE_POOL_MAX_BPS)
            .saturating_div(denominator)
    }
}

fn apply_rebate(amount_units: u64, rebate_bps: u64) -> u64 {
    let retained_bps = MONERO_REORG_INSURANCE_POOL_MAX_BPS.saturating_sub(rebate_bps);
    amount_units
        .saturating_mul(retained_bps)
        .saturating_div(MONERO_REORG_INSURANCE_POOL_MAX_BPS)
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroReorgInsurancePoolResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroReorgInsurancePoolResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroReorgInsurancePoolResult<()> {
    if value > MONERO_REORG_INSURANCE_POOL_MAX_BPS {
        Err(format!("{label} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> MoneroReorgInsurancePoolResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("duplicate {label}"));
        }
    }
    Ok(())
}
