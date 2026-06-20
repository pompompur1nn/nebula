use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type SettlementGuardResult<T> = Result<T, String>;

pub const SETTLEMENT_GUARD_PROTOCOL_VERSION: &str = "nebula-settlement-guard-v1";
pub const SETTLEMENT_GUARD_DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 12;
pub const SETTLEMENT_GUARD_DEFAULT_PROOF_GRACE_BLOCKS: u64 = 18;
pub const SETTLEMENT_GUARD_DEFAULT_EMERGENCY_EXIT_TTL_BLOCKS: u64 = 96;
pub const SETTLEMENT_GUARD_DEFAULT_ROLLBACK_QUARANTINE_BLOCKS: u64 = 72;
pub const SETTLEMENT_GUARD_DEFAULT_ESCAPE_SPONSORSHIP_TTL_BLOCKS: u64 = 144;
pub const SETTLEMENT_GUARD_DEFAULT_MIN_PROOF_WEIGHT_BPS: u64 = 6_700;
pub const SETTLEMENT_GUARD_DEFAULT_LOW_FEE_ESCAPE_REBATE_BPS: u64 = 8_500;
pub const SETTLEMENT_GUARD_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementGuardStatus {
    Open,
    Armed,
    Finalized,
    Quarantined,
    EmergencyExit,
    Expired,
    Revoked,
}

impl SettlementGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Armed => "armed",
            Self::Finalized => "finalized",
            Self::Quarantined => "quarantined",
            Self::EmergencyExit => "emergency_exit",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Armed | Self::EmergencyExit)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementProofKind {
    Validity,
    RecursiveValidity,
    MoneroBridgeFinality,
    ReserveCoverage,
    PrivateStateConsistency,
    LowFeeAccounting,
    WatchtowerChallenge,
}

impl SettlementProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validity => "validity",
            Self::RecursiveValidity => "recursive_validity",
            Self::MoneroBridgeFinality => "monero_bridge_finality",
            Self::ReserveCoverage => "reserve_coverage",
            Self::PrivateStateConsistency => "private_state_consistency",
            Self::LowFeeAccounting => "low_fee_accounting",
            Self::WatchtowerChallenge => "watchtower_challenge",
        }
    }

    pub fn default_weight_bps(self) -> u64 {
        match self {
            Self::RecursiveValidity => 2_500,
            Self::Validity => 2_000,
            Self::MoneroBridgeFinality => 1_800,
            Self::ReserveCoverage => 1_200,
            Self::PrivateStateConsistency => 1_000,
            Self::LowFeeAccounting => 700,
            Self::WatchtowerChallenge => 1_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRiskLevel {
    Clear,
    Watch,
    Delayed,
    Quarantined,
    Emergency,
}

impl SettlementRiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Watch => "watch",
            Self::Delayed => "delayed",
            Self::Quarantined => "quarantined",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyExitLane {
    MoneroWithdrawal,
    PrivateAccount,
    LowFeeUser,
    ContractEscrow,
    LiquidityProvider,
}

impl EmergencyExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroWithdrawal => "monero_withdrawal",
            Self::PrivateAccount => "private_account",
            Self::LowFeeUser => "low_fee_user",
            Self::ContractEscrow => "contract_escrow",
            Self::LiquidityProvider => "liquidity_provider",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackEvidenceKind {
    InvalidStateRoot,
    InvalidBridgeRoot,
    MissingDataAvailability,
    InvalidRecursiveProof,
    ReserveShortfall,
    SequencerEquivocation,
    PrivateNullifierReuse,
}

impl RollbackEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStateRoot => "invalid_state_root",
            Self::InvalidBridgeRoot => "invalid_bridge_root",
            Self::MissingDataAvailability => "missing_data_availability",
            Self::InvalidRecursiveProof => "invalid_recursive_proof",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::SequencerEquivocation => "sequencer_equivocation",
            Self::PrivateNullifierReuse => "private_nullifier_reuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementGuardEventKind {
    ProofGate,
    FinalityCheckpoint,
    EmergencyExitWindow,
    RollbackQuarantine,
    EscapeSponsorship,
    FinalizationDecision,
}

impl SettlementGuardEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofGate => "proof_gate",
            Self::FinalityCheckpoint => "finality_checkpoint",
            Self::EmergencyExitWindow => "emergency_exit_window",
            Self::RollbackQuarantine => "rollback_quarantine",
            Self::EscapeSponsorship => "escape_sponsorship",
            Self::FinalizationDecision => "finalization_decision",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementGuardConfig {
    pub protocol_version: String,
    pub finality_delay_blocks: u64,
    pub proof_grace_blocks: u64,
    pub emergency_exit_ttl_blocks: u64,
    pub rollback_quarantine_blocks: u64,
    pub escape_sponsorship_ttl_blocks: u64,
    pub min_proof_weight_bps: u64,
    pub low_fee_escape_rebate_bps: u64,
}

impl Default for SettlementGuardConfig {
    fn default() -> Self {
        Self {
            protocol_version: SETTLEMENT_GUARD_PROTOCOL_VERSION.to_string(),
            finality_delay_blocks: SETTLEMENT_GUARD_DEFAULT_FINALITY_DELAY_BLOCKS,
            proof_grace_blocks: SETTLEMENT_GUARD_DEFAULT_PROOF_GRACE_BLOCKS,
            emergency_exit_ttl_blocks: SETTLEMENT_GUARD_DEFAULT_EMERGENCY_EXIT_TTL_BLOCKS,
            rollback_quarantine_blocks: SETTLEMENT_GUARD_DEFAULT_ROLLBACK_QUARANTINE_BLOCKS,
            escape_sponsorship_ttl_blocks: SETTLEMENT_GUARD_DEFAULT_ESCAPE_SPONSORSHIP_TTL_BLOCKS,
            min_proof_weight_bps: SETTLEMENT_GUARD_DEFAULT_MIN_PROOF_WEIGHT_BPS,
            low_fee_escape_rebate_bps: SETTLEMENT_GUARD_DEFAULT_LOW_FEE_ESCAPE_REBATE_BPS,
        }
    }
}

impl SettlementGuardConfig {
    pub fn validate(&self) -> SettlementGuardResult<String> {
        require_non_empty("settlement guard protocol version", &self.protocol_version)?;
        if self.protocol_version != SETTLEMENT_GUARD_PROTOCOL_VERSION {
            return Err("settlement guard protocol version mismatch".to_string());
        }
        require_positive(
            "settlement guard finality delay",
            self.finality_delay_blocks,
        )?;
        require_positive("settlement guard proof grace", self.proof_grace_blocks)?;
        require_positive(
            "settlement guard emergency exit ttl",
            self.emergency_exit_ttl_blocks,
        )?;
        require_positive(
            "settlement guard rollback quarantine",
            self.rollback_quarantine_blocks,
        )?;
        require_positive(
            "settlement guard escape sponsorship ttl",
            self.escape_sponsorship_ttl_blocks,
        )?;
        require_bps(
            "settlement guard min proof weight",
            self.min_proof_weight_bps,
        )?;
        require_bps(
            "settlement guard low fee escape rebate",
            self.low_fee_escape_rebate_bps,
        )?;
        Ok(self.config_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_guard_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "finality_delay_blocks": self.finality_delay_blocks,
            "proof_grace_blocks": self.proof_grace_blocks,
            "emergency_exit_ttl_blocks": self.emergency_exit_ttl_blocks,
            "rollback_quarantine_blocks": self.rollback_quarantine_blocks,
            "escape_sponsorship_ttl_blocks": self.escape_sponsorship_ttl_blocks,
            "min_proof_weight_bps": self.min_proof_weight_bps,
            "low_fee_escape_rebate_bps": self.low_fee_escape_rebate_bps,
            "config_root": self.config_root(),
        })
    }

    pub fn config_root(&self) -> String {
        settlement_guard_payload_root(
            "SETTLEMENT-GUARD-CONFIG",
            &json!({
                "protocol_version": self.protocol_version,
                "finality_delay_blocks": self.finality_delay_blocks,
                "min_proof_weight_bps": self.min_proof_weight_bps,
                "low_fee_escape_rebate_bps": self.low_fee_escape_rebate_bps,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementProofGate {
    pub gate_id: String,
    pub batch_id: String,
    pub settlement_root: String,
    pub proof_kind: SettlementProofKind,
    pub proof_root: String,
    pub verifier_root: String,
    pub observed_height: u64,
    pub expires_at_height: u64,
    pub weight_bps: u64,
    pub status: SettlementGuardStatus,
}

impl SettlementProofGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        settlement_root: impl Into<String>,
        proof_kind: SettlementProofKind,
        proof_root: impl Into<String>,
        verifier_root: impl Into<String>,
        observed_height: u64,
        expires_at_height: u64,
        weight_bps: u64,
    ) -> SettlementGuardResult<Self> {
        let mut gate = Self {
            gate_id: String::new(),
            batch_id: batch_id.into(),
            settlement_root: settlement_root.into(),
            proof_kind,
            proof_root: proof_root.into(),
            verifier_root: verifier_root.into(),
            observed_height,
            expires_at_height,
            weight_bps,
            status: SettlementGuardStatus::Open,
        };
        gate.gate_id = settlement_guard_proof_gate_id(&gate.identity_record());
        gate.validate()?;
        Ok(gate)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.expires_at_height {
            self.status = SettlementGuardStatus::Expired;
        }
    }

    pub fn arm(&mut self) -> SettlementGuardResult<String> {
        if self.status == SettlementGuardStatus::Open {
            self.status = SettlementGuardStatus::Armed;
        }
        self.validate()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "settlement_proof_gate_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "settlement_root": self.settlement_root,
            "proof_kind": self.proof_kind.as_str(),
            "proof_root": self.proof_root,
            "observed_height": self.observed_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "settlement_proof_gate",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "gate_id": self.gate_id,
            "batch_id": self.batch_id,
            "settlement_root": self.settlement_root,
            "proof_kind": self.proof_kind.as_str(),
            "proof_root": self.proof_root,
            "verifier_root": self.verifier_root,
            "observed_height": self.observed_height,
            "expires_at_height": self.expires_at_height,
            "weight_bps": self.weight_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn gate_root(&self) -> String {
        settlement_guard_payload_root(
            "SETTLEMENT-GUARD-PROOF-GATE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "gate_root",
            self.gate_root(),
        )
    }

    pub fn validate(&self) -> SettlementGuardResult<String> {
        require_non_empty("settlement proof gate id", &self.gate_id)?;
        require_non_empty("settlement proof gate batch", &self.batch_id)?;
        require_non_empty(
            "settlement proof gate settlement root",
            &self.settlement_root,
        )?;
        require_non_empty("settlement proof gate proof root", &self.proof_root)?;
        require_non_empty("settlement proof gate verifier root", &self.verifier_root)?;
        require_bps("settlement proof gate weight", self.weight_bps)?;
        if self.expires_at_height <= self.observed_height {
            return Err("settlement proof gate expiry must follow observation".to_string());
        }
        let expected = settlement_guard_proof_gate_id(&self.identity_record());
        if self.gate_id != expected {
            return Err("settlement proof gate id mismatch".to_string());
        }
        Ok(self.gate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementFinalityCheckpoint {
    pub checkpoint_id: String,
    pub batch_id: String,
    pub l2_block_height: u64,
    pub monero_anchor_height: u64,
    pub state_root: String,
    pub bridge_root: String,
    pub da_root: String,
    pub proof_gate_ids: Vec<String>,
    pub required_weight_bps: u64,
    pub observed_weight_bps: u64,
    pub earliest_finalize_height: u64,
    pub finalized_at_height: Option<u64>,
    pub risk_level: SettlementRiskLevel,
    pub status: SettlementGuardStatus,
}

impl SettlementFinalityCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        l2_block_height: u64,
        monero_anchor_height: u64,
        state_root: impl Into<String>,
        bridge_root: impl Into<String>,
        da_root: impl Into<String>,
        proof_gate_ids: Vec<String>,
        required_weight_bps: u64,
        observed_weight_bps: u64,
        earliest_finalize_height: u64,
    ) -> SettlementGuardResult<Self> {
        let mut checkpoint = Self {
            checkpoint_id: String::new(),
            batch_id: batch_id.into(),
            l2_block_height,
            monero_anchor_height,
            state_root: state_root.into(),
            bridge_root: bridge_root.into(),
            da_root: da_root.into(),
            proof_gate_ids,
            required_weight_bps,
            observed_weight_bps,
            earliest_finalize_height,
            finalized_at_height: None,
            risk_level: if observed_weight_bps >= required_weight_bps {
                SettlementRiskLevel::Clear
            } else {
                SettlementRiskLevel::Delayed
            },
            status: if observed_weight_bps >= required_weight_bps {
                SettlementGuardStatus::Armed
            } else {
                SettlementGuardStatus::Open
            },
        };
        checkpoint.proof_gate_ids.sort();
        checkpoint.proof_gate_ids.dedup();
        checkpoint.checkpoint_id = settlement_guard_checkpoint_id(&checkpoint.identity_record());
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn set_height(&mut self, height: u64) -> SettlementGuardResult<()> {
        if self.status == SettlementGuardStatus::Armed && height >= self.earliest_finalize_height {
            self.status = SettlementGuardStatus::Finalized;
            self.finalized_at_height = Some(height);
            self.risk_level = SettlementRiskLevel::Clear;
        }
        self.validate().map(|_| ())
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "settlement_finality_checkpoint_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "l2_block_height": self.l2_block_height,
            "state_root": self.state_root,
            "bridge_root": self.bridge_root,
            "da_root": self.da_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "settlement_finality_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "batch_id": self.batch_id,
            "l2_block_height": self.l2_block_height,
            "monero_anchor_height": self.monero_anchor_height,
            "state_root": self.state_root,
            "bridge_root": self.bridge_root,
            "da_root": self.da_root,
            "proof_gate_ids": self.proof_gate_ids,
            "required_weight_bps": self.required_weight_bps,
            "observed_weight_bps": self.observed_weight_bps,
            "earliest_finalize_height": self.earliest_finalize_height,
            "finalized_at_height": self.finalized_at_height,
            "risk_level": self.risk_level.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn checkpoint_root(&self) -> String {
        settlement_guard_payload_root(
            "SETTLEMENT-GUARD-FINALITY-CHECKPOINT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "checkpoint_root",
            self.checkpoint_root(),
        )
    }

    pub fn validate(&self) -> SettlementGuardResult<String> {
        require_non_empty("settlement checkpoint id", &self.checkpoint_id)?;
        require_non_empty("settlement checkpoint batch", &self.batch_id)?;
        require_non_empty("settlement checkpoint state root", &self.state_root)?;
        require_non_empty("settlement checkpoint bridge root", &self.bridge_root)?;
        require_non_empty("settlement checkpoint da root", &self.da_root)?;
        require_bps(
            "settlement checkpoint required weight",
            self.required_weight_bps,
        )?;
        require_bps(
            "settlement checkpoint observed weight",
            self.observed_weight_bps,
        )?;
        ensure_unique_strings(&self.proof_gate_ids, "settlement checkpoint proof gates")?;
        if self.earliest_finalize_height <= self.l2_block_height {
            return Err("settlement checkpoint finality height must follow L2 height".to_string());
        }
        if let Some(finalized_at) = self.finalized_at_height {
            if finalized_at < self.earliest_finalize_height {
                return Err("settlement checkpoint finalized too early".to_string());
            }
        }
        let expected = settlement_guard_checkpoint_id(&self.identity_record());
        if self.checkpoint_id != expected {
            return Err("settlement checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyExitWindow {
    pub window_id: String,
    pub checkpoint_id: String,
    pub lane: EmergencyExitLane,
    pub account_commitment_root: String,
    pub claim_root: String,
    pub start_height: u64,
    pub expires_at_height: u64,
    pub max_exit_units: u64,
    pub claimed_exit_units: u64,
    pub status: SettlementGuardStatus,
}

impl EmergencyExitWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_id: impl Into<String>,
        lane: EmergencyExitLane,
        account_commitment_root: impl Into<String>,
        claim_root: impl Into<String>,
        start_height: u64,
        expires_at_height: u64,
        max_exit_units: u64,
    ) -> SettlementGuardResult<Self> {
        let mut window = Self {
            window_id: String::new(),
            checkpoint_id: checkpoint_id.into(),
            lane,
            account_commitment_root: account_commitment_root.into(),
            claim_root: claim_root.into(),
            start_height,
            expires_at_height,
            max_exit_units,
            claimed_exit_units: 0,
            status: SettlementGuardStatus::EmergencyExit,
        };
        window.window_id = settlement_guard_exit_window_id(&window.identity_record());
        window.validate()?;
        Ok(window)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.expires_at_height {
            self.status = SettlementGuardStatus::Expired;
        }
    }

    pub fn reserve_exit(&mut self, amount_units: u64) -> SettlementGuardResult<String> {
        let next = self.claimed_exit_units.saturating_add(amount_units);
        if next > self.max_exit_units {
            return Err("emergency exit window capacity exceeded".to_string());
        }
        self.claimed_exit_units = next;
        self.validate()
    }

    pub fn remaining_exit_units(&self) -> u64 {
        self.max_exit_units.saturating_sub(self.claimed_exit_units)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "emergency_exit_window_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "account_commitment_root": self.account_commitment_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "emergency_exit_window",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "checkpoint_id": self.checkpoint_id,
            "lane": self.lane.as_str(),
            "account_commitment_root": self.account_commitment_root,
            "claim_root": self.claim_root,
            "start_height": self.start_height,
            "expires_at_height": self.expires_at_height,
            "max_exit_units": self.max_exit_units,
            "claimed_exit_units": self.claimed_exit_units,
            "remaining_exit_units": self.remaining_exit_units(),
            "status": self.status.as_str(),
        })
    }

    pub fn window_root(&self) -> String {
        settlement_guard_payload_root(
            "SETTLEMENT-GUARD-EMERGENCY-EXIT-WINDOW",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "window_root",
            self.window_root(),
        )
    }

    pub fn validate(&self) -> SettlementGuardResult<String> {
        require_non_empty("emergency exit window id", &self.window_id)?;
        require_non_empty("emergency exit checkpoint", &self.checkpoint_id)?;
        require_non_empty(
            "emergency exit account commitment root",
            &self.account_commitment_root,
        )?;
        require_non_empty("emergency exit claim root", &self.claim_root)?;
        require_positive("emergency exit max units", self.max_exit_units)?;
        if self.expires_at_height <= self.start_height {
            return Err("emergency exit expiry must follow start".to_string());
        }
        if self.claimed_exit_units > self.max_exit_units {
            return Err("emergency exit claimed units exceed max".to_string());
        }
        let expected = settlement_guard_exit_window_id(&self.identity_record());
        if self.window_id != expected {
            return Err("emergency exit window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackQuarantine {
    pub quarantine_id: String,
    pub checkpoint_id: String,
    pub evidence_kind: RollbackEvidenceKind,
    pub evidence_root: String,
    pub reporter_root: String,
    pub detected_at_height: u64,
    pub expires_at_height: u64,
    pub affected_batch_ids: Vec<String>,
    pub challenge_bond_units: u64,
    pub status: SettlementGuardStatus,
}

impl RollbackQuarantine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_id: impl Into<String>,
        evidence_kind: RollbackEvidenceKind,
        evidence_root: impl Into<String>,
        reporter_root: impl Into<String>,
        detected_at_height: u64,
        expires_at_height: u64,
        affected_batch_ids: Vec<String>,
        challenge_bond_units: u64,
    ) -> SettlementGuardResult<Self> {
        let mut quarantine = Self {
            quarantine_id: String::new(),
            checkpoint_id: checkpoint_id.into(),
            evidence_kind,
            evidence_root: evidence_root.into(),
            reporter_root: reporter_root.into(),
            detected_at_height,
            expires_at_height,
            affected_batch_ids,
            challenge_bond_units,
            status: SettlementGuardStatus::Quarantined,
        };
        quarantine.affected_batch_ids.sort();
        quarantine.affected_batch_ids.dedup();
        quarantine.quarantine_id = settlement_guard_quarantine_id(&quarantine.identity_record());
        quarantine.validate()?;
        Ok(quarantine)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == SettlementGuardStatus::Quarantined && height > self.expires_at_height {
            self.status = SettlementGuardStatus::Expired;
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "rollback_quarantine_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "detected_at_height": self.detected_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "rollback_quarantine",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "quarantine_id": self.quarantine_id,
            "checkpoint_id": self.checkpoint_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "reporter_root": self.reporter_root,
            "detected_at_height": self.detected_at_height,
            "expires_at_height": self.expires_at_height,
            "affected_batch_ids": self.affected_batch_ids,
            "challenge_bond_units": self.challenge_bond_units,
            "status": self.status.as_str(),
        })
    }

    pub fn quarantine_root(&self) -> String {
        settlement_guard_payload_root(
            "SETTLEMENT-GUARD-ROLLBACK-QUARANTINE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "quarantine_root",
            self.quarantine_root(),
        )
    }

    pub fn validate(&self) -> SettlementGuardResult<String> {
        require_non_empty("rollback quarantine id", &self.quarantine_id)?;
        require_non_empty("rollback quarantine checkpoint", &self.checkpoint_id)?;
        require_non_empty("rollback quarantine evidence", &self.evidence_root)?;
        require_non_empty("rollback quarantine reporter", &self.reporter_root)?;
        require_positive(
            "rollback quarantine challenge bond",
            self.challenge_bond_units,
        )?;
        ensure_unique_strings(&self.affected_batch_ids, "rollback affected batches")?;
        if self.expires_at_height <= self.detected_at_height {
            return Err("rollback quarantine expiry must follow detection".to_string());
        }
        let expected = settlement_guard_quarantine_id(&self.identity_record());
        if self.quarantine_id != expected {
            return Err("rollback quarantine id mismatch".to_string());
        }
        Ok(self.quarantine_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeSponsorship {
    pub sponsorship_id: String,
    pub window_id: String,
    pub sponsor_root: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub spent_fee_units: u64,
    pub rebate_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SettlementGuardStatus,
}

impl EscapeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: impl Into<String>,
        sponsor_root: impl Into<String>,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        rebate_bps: u64,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> SettlementGuardResult<Self> {
        let mut sponsorship = Self {
            sponsorship_id: String::new(),
            window_id: window_id.into(),
            sponsor_root: sponsor_root.into(),
            fee_asset_id: fee_asset_id.into(),
            max_fee_units,
            spent_fee_units: 0,
            rebate_bps,
            created_at_height,
            expires_at_height,
            status: SettlementGuardStatus::Open,
        };
        sponsorship.sponsorship_id =
            settlement_guard_escape_sponsorship_id(&sponsorship.identity_record());
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.expires_at_height {
            self.status = SettlementGuardStatus::Expired;
        }
    }

    pub fn spend(&mut self, fee_units: u64) -> SettlementGuardResult<String> {
        let next = self.spent_fee_units.saturating_add(fee_units);
        if next > self.max_fee_units {
            return Err("escape sponsorship exhausted".to_string());
        }
        self.spent_fee_units = next;
        self.status = if self.spent_fee_units == self.max_fee_units {
            SettlementGuardStatus::Finalized
        } else {
            SettlementGuardStatus::Armed
        };
        self.validate()
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.spent_fee_units)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "escape_sponsorship_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "sponsor_root": self.sponsor_root,
            "fee_asset_id": self.fee_asset_id,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "escape_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "window_id": self.window_id,
            "sponsor_root": self.sponsor_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "rebate_bps": self.rebate_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        settlement_guard_payload_root(
            "SETTLEMENT-GUARD-ESCAPE-SPONSORSHIP",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "sponsorship_root",
            self.sponsorship_root(),
        )
    }

    pub fn validate(&self) -> SettlementGuardResult<String> {
        require_non_empty("escape sponsorship id", &self.sponsorship_id)?;
        require_non_empty("escape sponsorship window", &self.window_id)?;
        require_non_empty("escape sponsorship sponsor", &self.sponsor_root)?;
        require_non_empty("escape sponsorship fee asset", &self.fee_asset_id)?;
        require_positive("escape sponsorship max fee", self.max_fee_units)?;
        require_bps("escape sponsorship rebate", self.rebate_bps)?;
        if self.spent_fee_units > self.max_fee_units {
            return Err("escape sponsorship spent exceeds max".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("escape sponsorship expiry must follow creation".to_string());
        }
        let expected = settlement_guard_escape_sponsorship_id(&self.identity_record());
        if self.sponsorship_id != expected {
            return Err("escape sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementGuardEvent {
    pub event_id: String,
    pub sequence: u64,
    pub height: u64,
    pub kind: SettlementGuardEventKind,
    pub subject_id: String,
    pub event_root: String,
}

impl SettlementGuardEvent {
    pub fn new(
        sequence: u64,
        height: u64,
        kind: SettlementGuardEventKind,
        subject_id: impl Into<String>,
        event_root: impl Into<String>,
    ) -> SettlementGuardResult<Self> {
        let mut event = Self {
            event_id: String::new(),
            sequence,
            height,
            kind,
            subject_id: subject_id.into(),
            event_root: event_root.into(),
        };
        event.event_id = settlement_guard_event_id(&event.identity_record());
        event.validate()?;
        Ok(event)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "settlement_guard_event_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "sequence": self.sequence,
            "height": self.height,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "settlement_guard_event",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "event_root": self.event_root,
        })
    }

    pub fn record_root(&self) -> String {
        settlement_guard_payload_root("SETTLEMENT-GUARD-EVENT", &self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }

    pub fn validate(&self) -> SettlementGuardResult<String> {
        require_non_empty("settlement guard event id", &self.event_id)?;
        require_non_empty("settlement guard event subject", &self.subject_id)?;
        require_non_empty("settlement guard event root", &self.event_root)?;
        let expected = settlement_guard_event_id(&self.identity_record());
        if self.event_id != expected {
            return Err("settlement guard event id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementGuardCounters {
    pub proof_gate_count: u64,
    pub armed_proof_gate_count: u64,
    pub checkpoint_count: u64,
    pub finalized_checkpoint_count: u64,
    pub emergency_exit_window_count: u64,
    pub active_emergency_exit_window_count: u64,
    pub rollback_quarantine_count: u64,
    pub active_rollback_quarantine_count: u64,
    pub escape_sponsorship_count: u64,
    pub available_escape_fee_units: u64,
    pub total_claimed_exit_units: u64,
    pub event_count: u64,
}

impl SettlementGuardCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_guard_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "proof_gate_count": self.proof_gate_count,
            "armed_proof_gate_count": self.armed_proof_gate_count,
            "checkpoint_count": self.checkpoint_count,
            "finalized_checkpoint_count": self.finalized_checkpoint_count,
            "emergency_exit_window_count": self.emergency_exit_window_count,
            "active_emergency_exit_window_count": self.active_emergency_exit_window_count,
            "rollback_quarantine_count": self.rollback_quarantine_count,
            "active_rollback_quarantine_count": self.active_rollback_quarantine_count,
            "escape_sponsorship_count": self.escape_sponsorship_count,
            "available_escape_fee_units": self.available_escape_fee_units,
            "total_claimed_exit_units": self.total_claimed_exit_units,
            "event_count": self.event_count,
            "counters_root": self.counters_root(),
        })
    }

    pub fn counters_root(&self) -> String {
        settlement_guard_payload_root(
            "SETTLEMENT-GUARD-COUNTERS",
            &json!({
                "proof_gate_count": self.proof_gate_count,
                "armed_proof_gate_count": self.armed_proof_gate_count,
                "checkpoint_count": self.checkpoint_count,
                "finalized_checkpoint_count": self.finalized_checkpoint_count,
                "emergency_exit_window_count": self.emergency_exit_window_count,
                "rollback_quarantine_count": self.rollback_quarantine_count,
                "escape_sponsorship_count": self.escape_sponsorship_count,
                "event_count": self.event_count,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementGuardRoots {
    pub config_root: String,
    pub proof_gate_root: String,
    pub checkpoint_root: String,
    pub emergency_exit_window_root: String,
    pub rollback_quarantine_root: String,
    pub escape_sponsorship_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub public_record_root: String,
}

impl SettlementGuardRoots {
    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "settlement_guard_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "proof_gate_root": self.proof_gate_root,
            "checkpoint_root": self.checkpoint_root,
            "emergency_exit_window_root": self.emergency_exit_window_root,
            "rollback_quarantine_root": self.rollback_quarantine_root,
            "escape_sponsorship_root": self.escape_sponsorship_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        settlement_guard_payload_root("SETTLEMENT-GUARD-ROOTS", &self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "roots_root",
            self.roots_root(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementGuardState {
    pub config: SettlementGuardConfig,
    pub height: u64,
    pub next_event_sequence: u64,
    pub proof_gates: BTreeMap<String, SettlementProofGate>,
    pub checkpoints: BTreeMap<String, SettlementFinalityCheckpoint>,
    pub emergency_exit_windows: BTreeMap<String, EmergencyExitWindow>,
    pub rollback_quarantines: BTreeMap<String, RollbackQuarantine>,
    pub escape_sponsorships: BTreeMap<String, EscapeSponsorship>,
    pub events: BTreeMap<String, SettlementGuardEvent>,
}

impl Default for SettlementGuardState {
    fn default() -> Self {
        Self {
            config: SettlementGuardConfig::default(),
            height: 0,
            next_event_sequence: 0,
            proof_gates: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            emergency_exit_windows: BTreeMap::new(),
            rollback_quarantines: BTreeMap::new(),
            escape_sponsorships: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl SettlementGuardState {
    pub fn new(config: SettlementGuardConfig) -> SettlementGuardResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> SettlementGuardResult<Self> {
        let mut state = Self {
            height: 64,
            ..Self::default()
        };
        state.config.validate()?;

        let batch_id = "devnet-settlement-batch-64";
        let settlement_root =
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-SETTLEMENT", batch_id);
        let proof_specs = [
            (SettlementProofKind::RecursiveValidity, "recursive-validity"),
            (
                SettlementProofKind::MoneroBridgeFinality,
                "monero-bridge-finality",
            ),
            (SettlementProofKind::ReserveCoverage, "reserve-coverage"),
            (
                SettlementProofKind::PrivateStateConsistency,
                "private-state",
            ),
            (SettlementProofKind::LowFeeAccounting, "low-fee"),
        ];
        let mut gate_ids = Vec::new();
        for (kind, label) in proof_specs {
            let mut gate = SettlementProofGate::new(
                batch_id,
                settlement_root.clone(),
                kind,
                settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-PROOF", label),
                settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-VERIFIER", label),
                state.height,
                state.height + state.config.proof_grace_blocks,
                kind.default_weight_bps(),
            )?;
            gate.arm()?;
            let gate_id = gate.gate_id.clone();
            state.insert_proof_gate(gate)?;
            gate_ids.push(gate_id);
        }
        let observed_weight_bps = state
            .proof_gates
            .values()
            .filter(|gate| gate.status == SettlementGuardStatus::Armed)
            .map(|gate| gate.weight_bps)
            .sum::<u64>()
            .min(SETTLEMENT_GUARD_MAX_BPS);
        let checkpoint = SettlementFinalityCheckpoint::new(
            batch_id,
            64,
            2_904_064,
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-STATE", "state-64"),
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-BRIDGE", "bridge-64"),
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-DA", "da-64"),
            gate_ids,
            state.config.min_proof_weight_bps,
            observed_weight_bps,
            state.height + state.config.finality_delay_blocks,
        )?;
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        state.insert_checkpoint(checkpoint)?;

        let mut exit_window = EmergencyExitWindow::new(
            checkpoint_id.clone(),
            EmergencyExitLane::LowFeeUser,
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-EXIT-ACCOUNTS", "low-fee-users"),
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-EXIT-CLAIMS", "low-fee-claims"),
            state.height,
            state.height + state.config.emergency_exit_ttl_blocks,
            96_000,
        )?;
        exit_window.reserve_exit(12_000)?;
        let window_id = exit_window.window_id.clone();
        state.insert_emergency_exit_window(exit_window)?;

        let mut sponsorship = EscapeSponsorship::new(
            window_id.clone(),
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-SPONSOR", "escape-pool"),
            "wxmr-devnet",
            2_400,
            state.config.low_fee_escape_rebate_bps,
            state.height,
            state.height + state.config.escape_sponsorship_ttl_blocks,
        )?;
        sponsorship.spend(320)?;
        state.insert_escape_sponsorship(sponsorship)?;

        let quarantine = RollbackQuarantine::new(
            checkpoint_id,
            RollbackEvidenceKind::MissingDataAvailability,
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-ROLLBACK-EVIDENCE", "da-gap"),
            settlement_guard_string_root("SETTLEMENT-GUARD-DEVNET-REPORTER", "watchtower-alpha"),
            state.height + 1,
            state.height + 1 + state.config.rollback_quarantine_blocks,
            vec!["devnet-settlement-batch-63".to_string()],
            15_000,
        )?;
        state.insert_rollback_quarantine(quarantine)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> SettlementGuardResult<String> {
        self.height = height;
        for gate in self.proof_gates.values_mut() {
            gate.set_height(height);
        }
        for checkpoint in self.checkpoints.values_mut() {
            checkpoint.set_height(height)?;
        }
        for window in self.emergency_exit_windows.values_mut() {
            window.set_height(height);
        }
        for quarantine in self.rollback_quarantines.values_mut() {
            quarantine.set_height(height);
        }
        for sponsorship in self.escape_sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        self.validate()
    }

    pub fn insert_proof_gate(
        &mut self,
        gate: SettlementProofGate,
    ) -> SettlementGuardResult<String> {
        let root = gate.validate()?;
        let gate_id = gate.gate_id.clone();
        self.proof_gates.insert(gate_id.clone(), gate);
        self.record_event(SettlementGuardEventKind::ProofGate, gate_id, root.clone())?;
        Ok(root)
    }

    pub fn insert_checkpoint(
        &mut self,
        checkpoint: SettlementFinalityCheckpoint,
    ) -> SettlementGuardResult<String> {
        let root = checkpoint.validate()?;
        for gate_id in &checkpoint.proof_gate_ids {
            if !self.proof_gates.contains_key(gate_id) {
                return Err("settlement checkpoint references missing proof gate".to_string());
            }
        }
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);
        self.record_event(
            SettlementGuardEventKind::FinalityCheckpoint,
            checkpoint_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_emergency_exit_window(
        &mut self,
        window: EmergencyExitWindow,
    ) -> SettlementGuardResult<String> {
        let root = window.validate()?;
        if !self.checkpoints.contains_key(&window.checkpoint_id) {
            return Err("emergency exit references missing checkpoint".to_string());
        }
        let window_id = window.window_id.clone();
        self.emergency_exit_windows
            .insert(window_id.clone(), window);
        self.record_event(
            SettlementGuardEventKind::EmergencyExitWindow,
            window_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_rollback_quarantine(
        &mut self,
        quarantine: RollbackQuarantine,
    ) -> SettlementGuardResult<String> {
        let root = quarantine.validate()?;
        if !self.checkpoints.contains_key(&quarantine.checkpoint_id) {
            return Err("rollback quarantine references missing checkpoint".to_string());
        }
        let quarantine_id = quarantine.quarantine_id.clone();
        self.rollback_quarantines
            .insert(quarantine_id.clone(), quarantine);
        self.record_event(
            SettlementGuardEventKind::RollbackQuarantine,
            quarantine_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_escape_sponsorship(
        &mut self,
        sponsorship: EscapeSponsorship,
    ) -> SettlementGuardResult<String> {
        let root = sponsorship.validate()?;
        if !self
            .emergency_exit_windows
            .contains_key(&sponsorship.window_id)
        {
            return Err("escape sponsorship references missing emergency exit window".to_string());
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.escape_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.record_event(
            SettlementGuardEventKind::EscapeSponsorship,
            sponsorship_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn counters(&self) -> SettlementGuardCounters {
        SettlementGuardCounters {
            proof_gate_count: self.proof_gates.len() as u64,
            armed_proof_gate_count: self
                .proof_gates
                .values()
                .filter(|gate| gate.status == SettlementGuardStatus::Armed)
                .count() as u64,
            checkpoint_count: self.checkpoints.len() as u64,
            finalized_checkpoint_count: self
                .checkpoints
                .values()
                .filter(|checkpoint| checkpoint.status == SettlementGuardStatus::Finalized)
                .count() as u64,
            emergency_exit_window_count: self.emergency_exit_windows.len() as u64,
            active_emergency_exit_window_count: self
                .emergency_exit_windows
                .values()
                .filter(|window| window.status.active())
                .count() as u64,
            rollback_quarantine_count: self.rollback_quarantines.len() as u64,
            active_rollback_quarantine_count: self
                .rollback_quarantines
                .values()
                .filter(|quarantine| quarantine.status == SettlementGuardStatus::Quarantined)
                .count() as u64,
            escape_sponsorship_count: self.escape_sponsorships.len() as u64,
            available_escape_fee_units: self
                .escape_sponsorships
                .values()
                .map(EscapeSponsorship::remaining_fee_units)
                .sum(),
            total_claimed_exit_units: self
                .emergency_exit_windows
                .values()
                .map(|window| window.claimed_exit_units)
                .sum(),
            event_count: self.events.len() as u64,
        }
    }

    pub fn roots(&self) -> SettlementGuardRoots {
        let counters = self.counters();
        SettlementGuardRoots {
            config_root: self.config.config_root(),
            proof_gate_root: settlement_guard_proof_gate_collection_root(
                &self.proof_gates.values().cloned().collect::<Vec<_>>(),
            ),
            checkpoint_root: settlement_guard_checkpoint_collection_root(
                &self.checkpoints.values().cloned().collect::<Vec<_>>(),
            ),
            emergency_exit_window_root: settlement_guard_exit_window_collection_root(
                &self
                    .emergency_exit_windows
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            rollback_quarantine_root: settlement_guard_quarantine_collection_root(
                &self
                    .rollback_quarantines
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            escape_sponsorship_root: settlement_guard_sponsorship_collection_root(
                &self
                    .escape_sponsorships
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            event_root: settlement_guard_event_collection_root(
                &self.events.values().cloned().collect::<Vec<_>>(),
            ),
            counters_root: counters.counters_root(),
            public_record_root: settlement_guard_payload_root(
                "SETTLEMENT-GUARD-PUBLIC-RECORD",
                &json!({
                    "height": self.height,
                    "next_event_sequence": self.next_event_sequence,
                    "counters_root": counters.counters_root(),
                }),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        settlement_guard_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "state_root",
            self.state_root(),
        )
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "settlement_guard_state",
            "chain_id": CHAIN_ID,
            "protocol_version": SETTLEMENT_GUARD_PROTOCOL_VERSION,
            "height": self.height,
            "next_event_sequence": self.next_event_sequence,
            "config": self.config.public_record(),
            "roots": self.roots().public_record_without_root(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn validate(&self) -> SettlementGuardResult<String> {
        self.config.validate()?;
        for gate in self.proof_gates.values() {
            gate.validate()?;
        }
        for checkpoint in self.checkpoints.values() {
            checkpoint.validate()?;
            for gate_id in &checkpoint.proof_gate_ids {
                if !self.proof_gates.contains_key(gate_id) {
                    return Err("settlement checkpoint references missing gate".to_string());
                }
            }
        }
        for window in self.emergency_exit_windows.values() {
            window.validate()?;
            if !self.checkpoints.contains_key(&window.checkpoint_id) {
                return Err("settlement emergency exit references missing checkpoint".to_string());
            }
        }
        for quarantine in self.rollback_quarantines.values() {
            quarantine.validate()?;
            if !self.checkpoints.contains_key(&quarantine.checkpoint_id) {
                return Err("settlement rollback references missing checkpoint".to_string());
            }
        }
        for sponsorship in self.escape_sponsorships.values() {
            sponsorship.validate()?;
            if !self
                .emergency_exit_windows
                .contains_key(&sponsorship.window_id)
            {
                return Err("settlement sponsorship references missing exit window".to_string());
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(self.state_root())
    }

    fn record_event(
        &mut self,
        kind: SettlementGuardEventKind,
        subject_id: String,
        event_root: String,
    ) -> SettlementGuardResult<String> {
        let event = SettlementGuardEvent::new(
            self.next_event_sequence,
            self.height,
            kind,
            subject_id,
            event_root,
        )?;
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        let root = event.record_root();
        self.events.insert(event.event_id.clone(), event);
        Ok(root)
    }
}

pub fn settlement_guard_state_root_from_record(record: &Value) -> String {
    settlement_guard_payload_root("SETTLEMENT-GUARD-STATE", record)
}

pub fn settlement_guard_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SETTLEMENT_GUARD_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn settlement_guard_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SETTLEMENT_GUARD_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn settlement_guard_proof_gate_id(record: &Value) -> String {
    settlement_guard_payload_root("SETTLEMENT-GUARD-PROOF-GATE-ID", record)
}

pub fn settlement_guard_checkpoint_id(record: &Value) -> String {
    settlement_guard_payload_root("SETTLEMENT-GUARD-CHECKPOINT-ID", record)
}

pub fn settlement_guard_exit_window_id(record: &Value) -> String {
    settlement_guard_payload_root("SETTLEMENT-GUARD-EXIT-WINDOW-ID", record)
}

pub fn settlement_guard_quarantine_id(record: &Value) -> String {
    settlement_guard_payload_root("SETTLEMENT-GUARD-QUARANTINE-ID", record)
}

pub fn settlement_guard_escape_sponsorship_id(record: &Value) -> String {
    settlement_guard_payload_root("SETTLEMENT-GUARD-ESCAPE-SPONSORSHIP-ID", record)
}

pub fn settlement_guard_event_id(record: &Value) -> String {
    settlement_guard_payload_root("SETTLEMENT-GUARD-EVENT-ID", record)
}

pub fn settlement_guard_proof_gate_collection_root(records: &[SettlementProofGate]) -> String {
    keyed_value_root(
        "SETTLEMENT-GUARD-PROOF-GATE-COLLECTION",
        records
            .iter()
            .map(|record| (record.gate_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn settlement_guard_checkpoint_collection_root(
    records: &[SettlementFinalityCheckpoint],
) -> String {
    keyed_value_root(
        "SETTLEMENT-GUARD-CHECKPOINT-COLLECTION",
        records
            .iter()
            .map(|record| (record.checkpoint_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn settlement_guard_exit_window_collection_root(records: &[EmergencyExitWindow]) -> String {
    keyed_value_root(
        "SETTLEMENT-GUARD-EXIT-WINDOW-COLLECTION",
        records
            .iter()
            .map(|record| (record.window_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn settlement_guard_quarantine_collection_root(records: &[RollbackQuarantine]) -> String {
    keyed_value_root(
        "SETTLEMENT-GUARD-QUARANTINE-COLLECTION",
        records
            .iter()
            .map(|record| (record.quarantine_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn settlement_guard_sponsorship_collection_root(records: &[EscapeSponsorship]) -> String {
    keyed_value_root(
        "SETTLEMENT-GUARD-SPONSORSHIP-COLLECTION",
        records
            .iter()
            .map(|record| (record.sponsorship_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn settlement_guard_event_collection_root(records: &[SettlementGuardEvent]) -> String {
    keyed_value_root(
        "SETTLEMENT-GUARD-EVENT-COLLECTION",
        records
            .iter()
            .map(|record| (record.event_id.clone(), record.public_record()))
            .collect(),
    )
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn require_non_empty(label: &str, value: &str) -> SettlementGuardResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> SettlementGuardResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> SettlementGuardResult<()> {
    if value > SETTLEMENT_GUARD_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> SettlementGuardResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
