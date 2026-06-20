use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DecentralizedPqSequencerSlasherResult<T> = Result<T, String>;

pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_PROTOCOL_VERSION: &str =
    "nebula-decentralized-pq-sequencer-slasher-v1";
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_PQ_SIGNATURE_SCHEME: &str =
    "ml-dsa-87+shake256-ordering-commitment";
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_CENSORSHIP_PROOF_SYSTEM: &str =
    "zk-private-mempool-censorship-proof-v1";
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_EPOCH_BLOCKS: u64 = 64;
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_APPEAL_BLOCKS: u64 = 96;
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 720;
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_MIN_SECURITY_BITS: u16 = 256;
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_MIN_BOND_UNITS: u64 = 1_000_000;
pub const DECENTRALIZED_PQ_SEQUENCER_SLASHER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SequencerRole {
    Primary,
    Backup,
    Watchtower,
    PrivateMempoolRelay,
}

impl SequencerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
            Self::Watchtower => "watchtower",
            Self::PrivateMempoolRelay => "private_mempool_relay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SequencerStatus {
    Active,
    Jailed,
    Slashed,
    Exited,
}

impl SequencerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Jailed => "jailed",
            Self::Slashed => "slashed",
            Self::Exited => "exited",
        }
    }

    pub fn can_sequence(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceKind {
    Equivocation,
    Censorship,
    LowFeeLaneAbuse,
    PrivateMempoolLeak,
    InvalidPqSignature,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::Censorship => "censorship",
            Self::LowFeeLaneAbuse => "low_fee_lane_abuse",
            Self::PrivateMempoolLeak => "private_mempool_leak",
            Self::InvalidPqSignature => "invalid_pq_signature",
        }
    }

    pub fn severe(self) -> bool {
        matches!(
            self,
            Self::Equivocation | Self::PrivateMempoolLeak | Self::InvalidPqSignature
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceStatus {
    Submitted,
    Verified,
    Rejected,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Submitted | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlashingStatus {
    Pending,
    Applied,
    Appealed,
    Reversed,
    Finalized,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Appealed => "appealed",
            Self::Reversed => "reversed",
            Self::Finalized => "finalized",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Pending | Self::Applied | Self::Appealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AppealStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
}

impl AppealStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedPqSequencerSlasherConfig {
    pub epoch_blocks: u64,
    pub appeal_blocks: u64,
    pub evidence_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_bond_units: u64,
    pub equivocation_slash_bps: u64,
    pub censorship_slash_bps: u64,
    pub low_fee_abuse_slash_bps: u64,
    pub privacy_leak_slash_bps: u64,
    pub pq_signature_scheme: String,
    pub censorship_proof_system: String,
}

impl DecentralizedPqSequencerSlasherConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_EPOCH_BLOCKS,
            appeal_blocks: DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_APPEAL_BLOCKS,
            evidence_ttl_blocks: DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_EVIDENCE_TTL_BLOCKS,
            min_pq_security_bits: DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_MIN_SECURITY_BITS,
            min_bond_units: DECENTRALIZED_PQ_SEQUENCER_SLASHER_DEFAULT_MIN_BOND_UNITS,
            equivocation_slash_bps: 3_000,
            censorship_slash_bps: 1_500,
            low_fee_abuse_slash_bps: 1_000,
            privacy_leak_slash_bps: 5_000,
            pq_signature_scheme: DECENTRALIZED_PQ_SEQUENCER_SLASHER_PQ_SIGNATURE_SCHEME.to_string(),
            censorship_proof_system: DECENTRALIZED_PQ_SEQUENCER_SLASHER_CENSORSHIP_PROOF_SYSTEM
                .to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "appeal_blocks": self.appeal_blocks,
            "evidence_ttl_blocks": self.evidence_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_bond_units": self.min_bond_units,
            "equivocation_slash_bps": self.equivocation_slash_bps,
            "censorship_slash_bps": self.censorship_slash_bps,
            "low_fee_abuse_slash_bps": self.low_fee_abuse_slash_bps,
            "privacy_leak_slash_bps": self.privacy_leak_slash_bps,
            "pq_signature_scheme": self.pq_signature_scheme,
            "censorship_proof_system": self.censorship_proof_system,
        })
    }

    pub fn state_root(&self) -> String {
        dpqss_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> DecentralizedPqSequencerSlasherResult<()> {
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("appeal_blocks", self.appeal_blocks)?;
        ensure_positive("evidence_ttl_blocks", self.evidence_ttl_blocks)?;
        ensure_positive("min_bond_units", self.min_bond_units)?;
        ensure_bps("equivocation_slash_bps", self.equivocation_slash_bps)?;
        ensure_bps("censorship_slash_bps", self.censorship_slash_bps)?;
        ensure_bps("low_fee_abuse_slash_bps", self.low_fee_abuse_slash_bps)?;
        ensure_bps("privacy_leak_slash_bps", self.privacy_leak_slash_bps)?;
        ensure_nonempty("pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_nonempty("censorship_proof_system", &self.censorship_proof_system)?;
        if self.min_pq_security_bits < 192 {
            return Err("sequencer slasher pq security below policy".to_string());
        }
        Ok(())
    }

    pub fn slash_bps_for(&self, kind: EvidenceKind) -> u64 {
        match kind {
            EvidenceKind::Equivocation => self.equivocation_slash_bps,
            EvidenceKind::Censorship => self.censorship_slash_bps,
            EvidenceKind::LowFeeLaneAbuse => self.low_fee_abuse_slash_bps,
            EvidenceKind::PrivateMempoolLeak | EvidenceKind::InvalidPqSignature => {
                self.privacy_leak_slash_bps
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerBond {
    pub sequencer_id: String,
    pub operator_commitment: String,
    pub role: SequencerRole,
    pub status: SequencerStatus,
    pub pq_public_key_commitment: String,
    pub bond_asset_id: String,
    pub bonded_units: u64,
    pub slashed_units: u64,
    pub active_from_height: u64,
    pub last_commitment_height: u64,
}

impl SequencerBond {
    pub fn devnet(
        label: &str,
        role: SequencerRole,
        height: u64,
        config: &DecentralizedPqSequencerSlasherConfig,
    ) -> Self {
        Self {
            sequencer_id: dpqss_string_root("SEQUENCER-ID", label),
            operator_commitment: dpqss_string_root("SEQUENCER-OPERATOR", label),
            role,
            status: SequencerStatus::Active,
            pq_public_key_commitment: dpqss_string_root("SEQUENCER-PQ-PUBKEY", label),
            bond_asset_id: "dxmr".to_string(),
            bonded_units: config.min_bond_units * 2,
            slashed_units: 0,
            active_from_height: height,
            last_commitment_height: height,
        }
    }

    pub fn remaining_bond_units(&self) -> u64 {
        self.bonded_units.saturating_sub(self.slashed_units)
    }

    pub fn apply_slash(&mut self, units: u64) {
        self.slashed_units = self
            .slashed_units
            .saturating_add(units)
            .min(self.bonded_units);
        self.status = if self.remaining_bond_units() == 0 {
            SequencerStatus::Slashed
        } else {
            SequencerStatus::Jailed
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sequencer_id": self.sequencer_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bonded_units": self.bonded_units,
            "slashed_units": self.slashed_units,
            "remaining_bond_units": self.remaining_bond_units(),
            "active_from_height": self.active_from_height,
            "last_commitment_height": self.last_commitment_height,
        })
    }

    pub fn state_root(&self) -> String {
        dpqss_payload_root("SEQUENCER-BOND", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &DecentralizedPqSequencerSlasherConfig,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        ensure_nonempty("sequencer_id", &self.sequencer_id)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        ensure_nonempty("bond_asset_id", &self.bond_asset_id)?;
        ensure_positive("bonded_units", self.bonded_units)?;
        if self.bonded_units < config.min_bond_units {
            return Err(format!(
                "sequencer {} bond below minimum",
                self.sequencer_id
            ));
        }
        if self.slashed_units > self.bonded_units {
            return Err(format!("sequencer {} over-slashed", self.sequencer_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingCommitment {
    pub commitment_id: String,
    pub sequencer_id: String,
    pub slot: u64,
    pub parent_commitment_root: String,
    pub ordered_batch_root: String,
    pub private_mempool_root: String,
    pub low_fee_lane_root: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub height: u64,
}

impl OrderingCommitment {
    pub fn devnet(
        index: u64,
        sequencer_id: &str,
        height: u64,
        config: &DecentralizedPqSequencerSlasherConfig,
    ) -> Self {
        let seed = format!("ordering:{index}:{sequencer_id}:{height}");
        Self {
            commitment_id: dpqss_string_root("ORDERING-COMMITMENT-ID", &seed),
            sequencer_id: sequencer_id.to_string(),
            slot: height.saturating_add(index),
            parent_commitment_root: dpqss_string_root("ORDERING-PARENT", &seed),
            ordered_batch_root: dpqss_string_root("ORDERED-BATCH", &seed),
            private_mempool_root: dpqss_string_root("PRIVATE-MEMPOOL", &seed),
            low_fee_lane_root: dpqss_string_root("LOW-FEE-LANE", &seed),
            pq_signature_root: dpqss_string_root("PQ-SIGNATURE", &seed),
            security_bits: config.min_pq_security_bits,
            height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "sequencer_id": self.sequencer_id,
            "slot": self.slot,
            "parent_commitment_root": self.parent_commitment_root,
            "ordered_batch_root": self.ordered_batch_root,
            "private_mempool_root": self.private_mempool_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "pq_signature_root": self.pq_signature_root,
            "security_bits": self.security_bits,
            "height": self.height,
        })
    }

    pub fn state_root(&self) -> String {
        dpqss_payload_root("ORDERING-COMMITMENT", &self.public_record())
    }

    pub fn validate(
        &self,
        sequencers: &BTreeMap<String, SequencerBond>,
        config: &DecentralizedPqSequencerSlasherConfig,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        ensure_nonempty("commitment_id", &self.commitment_id)?;
        ensure_nonempty("sequencer_id", &self.sequencer_id)?;
        ensure_nonempty("parent_commitment_root", &self.parent_commitment_root)?;
        ensure_nonempty("ordered_batch_root", &self.ordered_batch_root)?;
        ensure_nonempty("private_mempool_root", &self.private_mempool_root)?;
        ensure_nonempty("low_fee_lane_root", &self.low_fee_lane_root)?;
        ensure_nonempty("pq_signature_root", &self.pq_signature_root)?;
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "ordering commitment {} has weak pq signature",
                self.commitment_id
            ));
        }
        if !sequencers.contains_key(&self.sequencer_id) {
            return Err(format!(
                "ordering commitment {} references missing sequencer {}",
                self.commitment_id, self.sequencer_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub accused_sequencer_id: String,
    pub reporter_commitment: String,
    pub primary_commitment_id: String,
    pub conflicting_commitment_id: Option<String>,
    pub proof_root: String,
    pub encrypted_witness_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SlashingEvidence {
    pub fn devnet(
        index: u64,
        kind: EvidenceKind,
        accused_sequencer_id: &str,
        primary_commitment_id: &str,
        conflicting_commitment_id: Option<String>,
        height: u64,
        config: &DecentralizedPqSequencerSlasherConfig,
    ) -> Self {
        let seed = format!("evidence:{index}:{accused_sequencer_id}:{}", kind.as_str());
        Self {
            evidence_id: dpqss_string_root("EVIDENCE-ID", &seed),
            kind,
            status: EvidenceStatus::Verified,
            accused_sequencer_id: accused_sequencer_id.to_string(),
            reporter_commitment: dpqss_string_root("REPORTER", &seed),
            primary_commitment_id: primary_commitment_id.to_string(),
            conflicting_commitment_id,
            proof_root: dpqss_string_root("EVIDENCE-PROOF", &seed),
            encrypted_witness_root: dpqss_string_root("EVIDENCE-WITNESS", &seed),
            opened_at_height: height,
            expires_at_height: height.saturating_add(config.evidence_ttl_blocks),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_at_height && self.status.active() {
            self.status = EvidenceStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "accused_sequencer_id": self.accused_sequencer_id,
            "reporter_commitment": self.reporter_commitment,
            "primary_commitment_id": self.primary_commitment_id,
            "conflicting_commitment_id": self.conflicting_commitment_id,
            "proof_root": self.proof_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        dpqss_payload_root("SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn validate(
        &self,
        sequencers: &BTreeMap<String, SequencerBond>,
        commitments: &BTreeMap<String, OrderingCommitment>,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        ensure_nonempty("evidence_id", &self.evidence_id)?;
        ensure_nonempty("accused_sequencer_id", &self.accused_sequencer_id)?;
        ensure_nonempty("reporter_commitment", &self.reporter_commitment)?;
        ensure_nonempty("primary_commitment_id", &self.primary_commitment_id)?;
        ensure_nonempty("proof_root", &self.proof_root)?;
        ensure_nonempty("encrypted_witness_root", &self.encrypted_witness_root)?;
        ensure_ordered_heights(
            "slashing evidence",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        if !sequencers.contains_key(&self.accused_sequencer_id) {
            return Err(format!(
                "evidence {} references missing sequencer",
                self.evidence_id
            ));
        }
        if !commitments.contains_key(&self.primary_commitment_id) {
            return Err(format!(
                "evidence {} references missing primary commitment",
                self.evidence_id
            ));
        }
        if self.kind == EvidenceKind::Equivocation && self.conflicting_commitment_id.is_none() {
            return Err(format!(
                "equivocation evidence {} missing conflict",
                self.evidence_id
            ));
        }
        if let Some(conflict) = &self.conflicting_commitment_id {
            if !commitments.contains_key(conflict) {
                return Err(format!(
                    "evidence {} references missing conflicting commitment {}",
                    self.evidence_id, conflict
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingSettlement {
    pub settlement_id: String,
    pub evidence_id: String,
    pub sequencer_id: String,
    pub status: SlashingStatus,
    pub slash_bps: u64,
    pub slashed_units: u64,
    pub reporter_reward_units: u64,
    pub treasury_units: u64,
    pub applied_at_height: u64,
    pub appeal_deadline_height: u64,
}

impl SlashingSettlement {
    pub fn new(
        evidence: &SlashingEvidence,
        sequencer: &SequencerBond,
        height: u64,
        config: &DecentralizedPqSequencerSlasherConfig,
    ) -> Self {
        let slash_bps = config.slash_bps_for(evidence.kind);
        let slashed_units = sequencer.bonded_units.saturating_mul(slash_bps)
            / DECENTRALIZED_PQ_SEQUENCER_SLASHER_MAX_BPS;
        let reporter_reward_units = slashed_units / 5;
        Self {
            settlement_id: dpqss_string_root(
                "SLASHING-SETTLEMENT-ID",
                &format!("{}:{}", evidence.evidence_id, height),
            ),
            evidence_id: evidence.evidence_id.clone(),
            sequencer_id: evidence.accused_sequencer_id.clone(),
            status: SlashingStatus::Applied,
            slash_bps,
            slashed_units,
            reporter_reward_units,
            treasury_units: slashed_units.saturating_sub(reporter_reward_units),
            applied_at_height: height,
            appeal_deadline_height: height.saturating_add(config.appeal_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "evidence_id": self.evidence_id,
            "sequencer_id": self.sequencer_id,
            "status": self.status.as_str(),
            "slash_bps": self.slash_bps,
            "slashed_units": self.slashed_units,
            "reporter_reward_units": self.reporter_reward_units,
            "treasury_units": self.treasury_units,
            "applied_at_height": self.applied_at_height,
            "appeal_deadline_height": self.appeal_deadline_height,
        })
    }

    pub fn state_root(&self) -> String {
        dpqss_payload_root("SLASHING-SETTLEMENT", &self.public_record())
    }

    pub fn validate(
        &self,
        evidences: &BTreeMap<String, SlashingEvidence>,
        sequencers: &BTreeMap<String, SequencerBond>,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        ensure_nonempty("settlement_id", &self.settlement_id)?;
        ensure_nonempty("evidence_id", &self.evidence_id)?;
        ensure_nonempty("sequencer_id", &self.sequencer_id)?;
        ensure_bps("slash_bps", self.slash_bps)?;
        ensure_ordered_heights(
            "slashing settlement",
            self.applied_at_height,
            self.appeal_deadline_height,
        )?;
        if !evidences.contains_key(&self.evidence_id) {
            return Err(format!(
                "settlement {} missing evidence",
                self.settlement_id
            ));
        }
        if !sequencers.contains_key(&self.sequencer_id) {
            return Err(format!(
                "settlement {} missing sequencer",
                self.settlement_id
            ));
        }
        if self
            .reporter_reward_units
            .saturating_add(self.treasury_units)
            != self.slashed_units
        {
            return Err(format!(
                "settlement {} accounting mismatch",
                self.settlement_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingAppeal {
    pub appeal_id: String,
    pub settlement_id: String,
    pub appellant_commitment: String,
    pub counter_evidence_root: String,
    pub status: AppealStatus,
    pub opened_at_height: u64,
    pub decided_at_height: Option<u64>,
}

impl SlashingAppeal {
    pub fn devnet(settlement_id: &str, height: u64) -> Self {
        let seed = format!("appeal:{settlement_id}:{height}");
        Self {
            appeal_id: dpqss_string_root("APPEAL-ID", &seed),
            settlement_id: settlement_id.to_string(),
            appellant_commitment: dpqss_string_root("APPELLANT", &seed),
            counter_evidence_root: dpqss_string_root("COUNTER-EVIDENCE", &seed),
            status: AppealStatus::Open,
            opened_at_height: height,
            decided_at_height: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "appeal_id": self.appeal_id,
            "settlement_id": self.settlement_id,
            "appellant_commitment": self.appellant_commitment,
            "counter_evidence_root": self.counter_evidence_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "decided_at_height": self.decided_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        dpqss_payload_root("SLASHING-APPEAL", &self.public_record())
    }

    pub fn validate(
        &self,
        settlements: &BTreeMap<String, SlashingSettlement>,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        ensure_nonempty("appeal_id", &self.appeal_id)?;
        ensure_nonempty("settlement_id", &self.settlement_id)?;
        ensure_nonempty("appellant_commitment", &self.appellant_commitment)?;
        ensure_nonempty("counter_evidence_root", &self.counter_evidence_root)?;
        if !settlements.contains_key(&self.settlement_id) {
            return Err(format!(
                "appeal {} references missing settlement",
                self.appeal_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedPqSequencerSlasherRoots {
    pub sequencer_root: String,
    pub ordering_commitment_root: String,
    pub evidence_root: String,
    pub settlement_root: String,
    pub appeal_root: String,
    pub nullifier_root: String,
}

impl DecentralizedPqSequencerSlasherRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "sequencer_root": self.sequencer_root,
            "ordering_commitment_root": self.ordering_commitment_root,
            "evidence_root": self.evidence_root,
            "settlement_root": self.settlement_root,
            "appeal_root": self.appeal_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn state_root(&self) -> String {
        dpqss_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedPqSequencerSlasherCounters {
    pub sequencers: usize,
    pub active_sequencers: usize,
    pub ordering_commitments: usize,
    pub evidences: usize,
    pub active_evidences: usize,
    pub settlements: usize,
    pub open_settlements: usize,
    pub appeals: usize,
    pub slashed_units: u64,
    pub privacy_leak_evidence_count: usize,
}

impl DecentralizedPqSequencerSlasherCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "sequencers": self.sequencers,
            "active_sequencers": self.active_sequencers,
            "ordering_commitments": self.ordering_commitments,
            "evidences": self.evidences,
            "active_evidences": self.active_evidences,
            "settlements": self.settlements,
            "open_settlements": self.open_settlements,
            "appeals": self.appeals,
            "slashed_units": self.slashed_units,
            "privacy_leak_evidence_count": self.privacy_leak_evidence_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecentralizedPqSequencerSlasherState {
    pub protocol_version: String,
    pub height: u64,
    pub config: DecentralizedPqSequencerSlasherConfig,
    pub sequencers: BTreeMap<String, SequencerBond>,
    pub ordering_commitments: BTreeMap<String, OrderingCommitment>,
    pub evidences: BTreeMap<String, SlashingEvidence>,
    pub settlements: BTreeMap<String, SlashingSettlement>,
    pub appeals: BTreeMap<String, SlashingAppeal>,
    pub evidence_nullifiers: BTreeSet<String>,
}

impl DecentralizedPqSequencerSlasherState {
    pub fn devnet() -> DecentralizedPqSequencerSlasherResult<Self> {
        let config = DecentralizedPqSequencerSlasherConfig::devnet();
        let height = 1;
        let mut state = Self {
            protocol_version: DECENTRALIZED_PQ_SEQUENCER_SLASHER_PROTOCOL_VERSION.to_string(),
            height,
            config,
            sequencers: BTreeMap::new(),
            ordering_commitments: BTreeMap::new(),
            evidences: BTreeMap::new(),
            settlements: BTreeMap::new(),
            appeals: BTreeMap::new(),
            evidence_nullifiers: BTreeSet::new(),
        };

        for (label, role) in [
            ("sequencer-primary-a", SequencerRole::Primary),
            ("sequencer-backup-a", SequencerRole::Backup),
            ("sequencer-watchtower-a", SequencerRole::Watchtower),
        ] {
            state.add_sequencer(SequencerBond::devnet(label, role, height, &state.config))?;
        }
        let sequencer_id = state
            .sequencers
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet slasher missing sequencer".to_string())?;
        let first = OrderingCommitment::devnet(0, &sequencer_id, height, &state.config);
        let second = OrderingCommitment::devnet(1, &sequencer_id, height, &state.config);
        let first_id = first.commitment_id.clone();
        let second_id = second.commitment_id.clone();
        state.add_ordering_commitment(first)?;
        state.add_ordering_commitment(second)?;
        let evidence = SlashingEvidence::devnet(
            0,
            EvidenceKind::Equivocation,
            &sequencer_id,
            &first_id,
            Some(second_id),
            height,
            &state.config,
        );
        let evidence_id = evidence.evidence_id.clone();
        state.submit_evidence(evidence)?;
        let settlement_id = state.apply_slashing(&evidence_id)?;
        state.open_appeal(SlashingAppeal::devnet(&settlement_id, height))?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> DecentralizedPqSequencerSlasherResult<()> {
        if height < self.height {
            return Err(
                "decentralized pq sequencer slasher height cannot move backwards".to_string(),
            );
        }
        self.height = height;
        for evidence in self.evidences.values_mut() {
            evidence.set_height(height);
        }
        self.validate()
    }

    pub fn roots(&self) -> DecentralizedPqSequencerSlasherRoots {
        DecentralizedPqSequencerSlasherRoots {
            sequencer_root: merkle_record_root("DPQSS-SEQUENCERS", &self.sequencers),
            ordering_commitment_root: merkle_record_root(
                "DPQSS-ORDERING-COMMITMENTS",
                &self.ordering_commitments,
            ),
            evidence_root: merkle_record_root("DPQSS-EVIDENCES", &self.evidences),
            settlement_root: merkle_record_root("DPQSS-SETTLEMENTS", &self.settlements),
            appeal_root: merkle_record_root("DPQSS-APPEALS", &self.appeals),
            nullifier_root: merkle_root(
                "DPQSS-EVIDENCE-NULLIFIERS",
                &self
                    .evidence_nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier))
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> DecentralizedPqSequencerSlasherCounters {
        DecentralizedPqSequencerSlasherCounters {
            sequencers: self.sequencers.len(),
            active_sequencers: self
                .sequencers
                .values()
                .filter(|sequencer| sequencer.status.can_sequence())
                .count(),
            ordering_commitments: self.ordering_commitments.len(),
            evidences: self.evidences.len(),
            active_evidences: self
                .evidences
                .values()
                .filter(|evidence| evidence.status.active())
                .count(),
            settlements: self.settlements.len(),
            open_settlements: self
                .settlements
                .values()
                .filter(|settlement| settlement.status.open())
                .count(),
            appeals: self.appeals.len(),
            slashed_units: self
                .settlements
                .values()
                .map(|settlement| settlement.slashed_units)
                .sum(),
            privacy_leak_evidence_count: self
                .evidences
                .values()
                .filter(|evidence| evidence.kind == EvidenceKind::PrivateMempoolLeak)
                .count(),
        }
    }

    pub fn active_sequencer_ids(&self) -> Vec<String> {
        self.sequencers
            .values()
            .filter(|sequencer| sequencer.status.can_sequence())
            .map(|sequencer| sequencer.sequencer_id.clone())
            .collect()
    }

    pub fn active_evidence_ids(&self) -> Vec<String> {
        self.evidences
            .values()
            .filter(|evidence| evidence.status.active())
            .map(|evidence| evidence.evidence_id.clone())
            .collect()
    }

    pub fn open_settlement_ids(&self) -> Vec<String> {
        self.settlements
            .values()
            .filter(|settlement| settlement.status.open())
            .map(|settlement| settlement.settlement_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        decentralized_pq_sequencer_slasher_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> DecentralizedPqSequencerSlasherResult<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        self.config.validate()?;
        for (id, sequencer) in &self.sequencers {
            if id != &sequencer.sequencer_id {
                return Err(format!("sequencer key mismatch {id}"));
            }
            sequencer.validate(&self.config)?;
        }
        for (id, commitment) in &self.ordering_commitments {
            if id != &commitment.commitment_id {
                return Err(format!("ordering commitment key mismatch {id}"));
            }
            commitment.validate(&self.sequencers, &self.config)?;
        }
        for (id, evidence) in &self.evidences {
            if id != &evidence.evidence_id {
                return Err(format!("evidence key mismatch {id}"));
            }
            evidence.validate(&self.sequencers, &self.ordering_commitments)?;
        }
        for (id, settlement) in &self.settlements {
            if id != &settlement.settlement_id {
                return Err(format!("settlement key mismatch {id}"));
            }
            settlement.validate(&self.evidences, &self.sequencers)?;
        }
        for (id, appeal) in &self.appeals {
            if id != &appeal.appeal_id {
                return Err(format!("appeal key mismatch {id}"));
            }
            appeal.validate(&self.settlements)?;
        }
        Ok(())
    }

    pub fn add_sequencer(
        &mut self,
        sequencer: SequencerBond,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        sequencer.validate(&self.config)?;
        self.sequencers
            .insert(sequencer.sequencer_id.clone(), sequencer);
        Ok(())
    }

    pub fn add_ordering_commitment(
        &mut self,
        commitment: OrderingCommitment,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        commitment.validate(&self.sequencers, &self.config)?;
        self.ordering_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn submit_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        evidence.validate(&self.sequencers, &self.ordering_commitments)?;
        let nullifier = dpqss_payload_root(
            "EVIDENCE-NULLIFIER",
            &json!({
                "kind": evidence.kind.as_str(),
                "accused": evidence.accused_sequencer_id,
                "primary": evidence.primary_commitment_id,
                "conflict": evidence.conflicting_commitment_id,
            }),
        );
        if !self.evidence_nullifiers.insert(nullifier) {
            return Err(format!(
                "duplicate slashing evidence {}",
                evidence.evidence_id
            ));
        }
        self.evidences
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn apply_slashing(
        &mut self,
        evidence_id: &str,
    ) -> DecentralizedPqSequencerSlasherResult<String> {
        let evidence = self
            .evidences
            .get(evidence_id)
            .ok_or_else(|| format!("missing evidence {evidence_id}"))?
            .clone();
        if evidence.status != EvidenceStatus::Verified {
            return Err(format!("evidence {evidence_id} is not verified"));
        }
        let sequencer = self
            .sequencers
            .get(&evidence.accused_sequencer_id)
            .ok_or_else(|| format!("missing sequencer {}", evidence.accused_sequencer_id))?
            .clone();
        let settlement = SlashingSettlement::new(&evidence, &sequencer, self.height, &self.config);
        let settlement_id = settlement.settlement_id.clone();
        if let Some(sequencer) = self.sequencers.get_mut(&evidence.accused_sequencer_id) {
            sequencer.apply_slash(settlement.slashed_units);
        }
        self.settlements.insert(settlement_id.clone(), settlement);
        Ok(settlement_id)
    }

    pub fn open_appeal(
        &mut self,
        appeal: SlashingAppeal,
    ) -> DecentralizedPqSequencerSlasherResult<()> {
        appeal.validate(&self.settlements)?;
        if let Some(settlement) = self.settlements.get_mut(&appeal.settlement_id) {
            settlement.status = SlashingStatus::Appealed;
        }
        self.appeals.insert(appeal.appeal_id.clone(), appeal);
        Ok(())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "decentralized_pq_sequencer_slasher_state",
            "protocol_version": self.protocol_version,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "sequencers": keyed_records(&self.sequencers),
            "ordering_commitments": keyed_records(&self.ordering_commitments),
            "evidences": keyed_records(&self.evidences),
            "settlements": keyed_records(&self.settlements),
            "appeals": keyed_records(&self.appeals),
        })
    }
}

pub fn decentralized_pq_sequencer_slasher_state_root_from_record(record: &Value) -> String {
    dpqss_payload_root("STATE", record)
}

fn dpqss_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("DECENTRALIZED-PQ-SEQUENCER-SLASHER-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn dpqss_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("DECENTRALIZED-PQ-SEQUENCER-SLASHER-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

trait SlasherPublicRecord {
    fn public_record(&self) -> Value;
}

impl SlasherPublicRecord for SequencerBond {
    fn public_record(&self) -> Value {
        SequencerBond::public_record(self)
    }
}

impl SlasherPublicRecord for OrderingCommitment {
    fn public_record(&self) -> Value {
        OrderingCommitment::public_record(self)
    }
}

impl SlasherPublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

impl SlasherPublicRecord for SlashingSettlement {
    fn public_record(&self) -> Value {
        SlashingSettlement::public_record(self)
    }
}

impl SlasherPublicRecord for SlashingAppeal {
    fn public_record(&self) -> Value {
        SlashingAppeal::public_record(self)
    }
}

fn keyed_records<T: SlasherPublicRecord>(records: &BTreeMap<String, T>) -> Vec<Value> {
    records
        .iter()
        .map(|(id, record)| json!({ "id": id, "record": record.public_record() }))
        .collect()
}

fn merkle_record_root<T: SlasherPublicRecord>(
    domain: &str,
    records: &BTreeMap<String, T>,
) -> String {
    merkle_root(
        domain,
        &records
            .iter()
            .map(|(id, record)| {
                json!({
                    "id": id,
                    "root": dpqss_payload_root(
                        domain,
                        &json!({ "id": id, "record": record.public_record() }),
                    ),
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn ensure_nonempty(field: &str, value: &str) -> DecentralizedPqSequencerSlasherResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> DecentralizedPqSequencerSlasherResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> DecentralizedPqSequencerSlasherResult<()> {
    if value > DECENTRALIZED_PQ_SEQUENCER_SLASHER_MAX_BPS {
        Err(format!("{field} exceeds bps denominator"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    label: &str,
    start_height: u64,
    end_height: u64,
) -> DecentralizedPqSequencerSlasherResult<()> {
    if end_height <= start_height {
        Err(format!("{label} end height must be after start height"))
    } else {
        Ok(())
    }
}
