use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqLightClientFastFinalityOracleResult<T> = Result<T, String>;

pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PROTOCOL_VERSION: &str =
    "nebula-pq-light-client-fast-finality-oracle-v1";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_SCHEMA_VERSION: u64 = 1;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_SECURITY_MODEL: &str =
    "deterministic-devnet-records-not-real-crypto";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_HASH_SUITE: &str = "SHAKE256";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-192s";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_AGGREGATE_PROOF_SCHEME: &str =
    "pq-aggregate-attestation-root-v1";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_MONERO_ANCHOR_SCHEME: &str =
    "monero-checkpoint-anchor-shake256-v1";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_HEIGHT: u64 = 768;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_SNAPSHOT_LOOKAHEAD_BLOCKS: u64 = 48;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FINALITY_TARGET_BLOCKS: u64 = 2;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_MONERO_CONFIRMATIONS: u64 = 20;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FAST_QUORUM_BPS: u64 = 8_000;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_SAFE_QUORUM_BPS: u64 = 6_700;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FALLBACK_QUORUM_BPS: u64 = 7_500;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_WATCHER_QUORUM: u64 = 2;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_LOW_FEE_PROOF_BUDGET: u64 = 80_000;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_SPONSORED_PROOF_FEE: u64 = 5;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_MAX_BPS: u64 = 10_000;
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_COMMITTEE_ID: &str =
    "pq-light-finality-devnet-committee";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastFinalityOracleLane {
    PrivateTransfer,
    MoneroBridge,
    TokenTransfer,
    DefiSettlement,
    ContractExecution,
    DaProof,
    Governance,
    EmergencyExit,
}

impl FastFinalityOracleLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenTransfer => "token_transfer",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractExecution => "contract_execution",
            Self::DaProof => "da_proof",
            Self::Governance => "governance",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::MoneroBridge | Self::DefiSettlement | Self::EmergencyExit
        )
    }

    pub fn default_sponsored_fee_units(self) -> u64 {
        match self {
            Self::PrivateTransfer => 3,
            Self::TokenTransfer => 2,
            Self::DefiSettlement => 5,
            Self::ContractExecution => 6,
            Self::MoneroBridge => 8,
            Self::DaProof => 7,
            Self::Governance => 4,
            Self::EmergencyExit => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleMemberRole {
    Validator,
    Sequencer,
    BridgeGuardian,
    Watcher,
    Sponsor,
    EmergencyGuardian,
}

impl OracleMemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Sequencer => "sequencer",
            Self::BridgeGuardian => "bridge_guardian",
            Self::Watcher => "watcher",
            Self::Sponsor => "sponsor",
            Self::EmergencyGuardian => "emergency_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleRecordStatus {
    Draft,
    Active,
    Pending,
    Attested,
    ChallengeOpen,
    Finalized,
    Rejected,
    Slashed,
    Superseded,
}

impl OracleRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Attested => "attested",
            Self::ChallengeOpen => "challenge_open",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Superseded => "superseded",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Active | Self::Pending | Self::Attested | Self::ChallengeOpen
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityRiskTier {
    Instant,
    Fast,
    Anchored,
    WatcherBacked,
    ChallengeOpen,
    EmergencyOnly,
    Unsafe,
}

impl FinalityRiskTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Anchored => "anchored",
            Self::WatcherBacked => "watcher_backed",
            Self::ChallengeOpen => "challenge_open",
            Self::EmergencyOnly => "emergency_only",
            Self::Unsafe => "unsafe",
        }
    }

    pub fn rank(self) -> u64 {
        match self {
            Self::Instant => 0,
            Self::Fast => 1,
            Self::Anchored => 2,
            Self::WatcherBacked => 3,
            Self::ChallengeOpen => 4,
            Self::EmergencyOnly => 5,
            Self::Unsafe => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudChallengeKind {
    InvalidAggregateSignature,
    WrongStateRoot,
    WrongMoneroAnchor,
    InsufficientCommitteeWeight,
    ExpiredCommitteeSnapshot,
    Equivocation,
    DataUnavailable,
    PrivacyLeak,
    SponsorAbuse,
    WatcherMisreport,
}

impl FraudChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidAggregateSignature => "invalid_aggregate_signature",
            Self::WrongStateRoot => "wrong_state_root",
            Self::WrongMoneroAnchor => "wrong_monero_anchor",
            Self::InsufficientCommitteeWeight => "insufficient_committee_weight",
            Self::ExpiredCommitteeSnapshot => "expired_committee_snapshot",
            Self::Equivocation => "equivocation",
            Self::DataUnavailable => "data_unavailable",
            Self::PrivacyLeak => "privacy_leak",
            Self::SponsorAbuse => "sponsor_abuse",
            Self::WatcherMisreport => "watcher_misreport",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudChallengeOutcome {
    Open,
    Dismissed,
    Sustained,
    AggregateRejected,
    WatcherFallbackActivated,
    Slashed,
    Expired,
}

impl FraudChallengeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Dismissed => "dismissed",
            Self::Sustained => "sustained",
            Self::AggregateRejected => "aggregate_rejected",
            Self::WatcherFallbackActivated => "watcher_fallback_activated",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn resolved(self) -> bool {
        !matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidAttestation,
    Equivocation,
    MissedFallbackDuty,
    AnchorFraud,
    SponsorFeeFraud,
    PrivacyLeak,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidAttestation => "invalid_attestation",
            Self::Equivocation => "equivocation",
            Self::MissedFallbackDuty => "missed_fallback_duty",
            Self::AnchorFraud => "anchor_fraud",
            Self::SponsorFeeFraud => "sponsor_fee_fraud",
            Self::PrivacyLeak => "privacy_leak",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFastFinalityOracleConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub security_model: String,
    pub hash_suite: String,
    pub primary_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub kem_scheme: String,
    pub aggregate_proof_scheme: String,
    pub monero_anchor_scheme: String,
    pub epoch_blocks: u64,
    pub snapshot_lookahead_blocks: u64,
    pub finality_target_blocks: u64,
    pub challenge_window_blocks: u64,
    pub monero_confirmation_target: u64,
    pub fast_quorum_bps: u64,
    pub safe_quorum_bps: u64,
    pub fallback_quorum_bps: u64,
    pub watcher_quorum: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_proof_budget_units: u64,
    pub sponsored_proof_fee_units: u64,
    pub fee_asset_id: String,
    pub monero_network: String,
    pub require_monero_anchor_for_bridge: bool,
    pub require_fallback_watchers_for_emergency: bool,
}

impl Default for PqLightClientFastFinalityOracleConfig {
    fn default() -> Self {
        Self {
            protocol_version: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_SCHEMA_VERSION,
            security_model: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_SECURITY_MODEL.to_string(),
            hash_suite: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_HASH_SUITE.to_string(),
            primary_signature_scheme: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PRIMARY_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            kem_scheme: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_KEM_SCHEME.to_string(),
            aggregate_proof_scheme: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_AGGREGATE_PROOF_SCHEME
                .to_string(),
            monero_anchor_scheme: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_MONERO_ANCHOR_SCHEME
                .to_string(),
            epoch_blocks: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_EPOCH_BLOCKS,
            snapshot_lookahead_blocks:
                PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_SNAPSHOT_LOOKAHEAD_BLOCKS,
            finality_target_blocks:
                PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FINALITY_TARGET_BLOCKS,
            challenge_window_blocks:
                PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            monero_confirmation_target:
                PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_MONERO_CONFIRMATIONS,
            fast_quorum_bps: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FAST_QUORUM_BPS,
            safe_quorum_bps: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_SAFE_QUORUM_BPS,
            fallback_quorum_bps: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FALLBACK_QUORUM_BPS,
            watcher_quorum: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_WATCHER_QUORUM,
            min_pq_security_bits: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_proof_budget_units:
                PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_LOW_FEE_PROOF_BUDGET,
            sponsored_proof_fee_units:
                PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_SPONSORED_PROOF_FEE,
            fee_asset_id: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_FEE_ASSET_ID.to_string(),
            monero_network: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_MONERO_NETWORK.to_string(),
            require_monero_anchor_for_bridge: true,
            require_fallback_watchers_for_emergency: true,
        }
    }
}

impl PqLightClientFastFinalityOracleConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_light_client_fast_finality_oracle_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "security_model": self.security_model,
            "hash_suite": self.hash_suite,
            "primary_signature_scheme": self.primary_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "kem_scheme": self.kem_scheme,
            "aggregate_proof_scheme": self.aggregate_proof_scheme,
            "monero_anchor_scheme": self.monero_anchor_scheme,
            "epoch_blocks": self.epoch_blocks,
            "snapshot_lookahead_blocks": self.snapshot_lookahead_blocks,
            "finality_target_blocks": self.finality_target_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "monero_confirmation_target": self.monero_confirmation_target,
            "fast_quorum_bps": self.fast_quorum_bps,
            "safe_quorum_bps": self.safe_quorum_bps,
            "fallback_quorum_bps": self.fallback_quorum_bps,
            "watcher_quorum": self.watcher_quorum,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_proof_budget_units": self.low_fee_proof_budget_units,
            "sponsored_proof_fee_units": self.sponsored_proof_fee_units,
            "fee_asset_id": self.fee_asset_id,
            "monero_network": self.monero_network,
            "require_monero_anchor_for_bridge": self.require_monero_anchor_for_bridge,
            "require_fallback_watchers_for_emergency": self.require_fallback_watchers_for_emergency,
        })
    }

    pub fn config_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.protocol_version, "oracle protocol version")?;
        ensure_non_empty(&self.security_model, "oracle security model")?;
        ensure_non_empty(&self.hash_suite, "oracle hash suite")?;
        ensure_non_empty(
            &self.primary_signature_scheme,
            "oracle primary signature scheme",
        )?;
        ensure_non_empty(
            &self.backup_signature_scheme,
            "oracle backup signature scheme",
        )?;
        ensure_non_empty(&self.kem_scheme, "oracle kem scheme")?;
        ensure_non_empty(
            &self.aggregate_proof_scheme,
            "oracle aggregate proof scheme",
        )?;
        ensure_non_empty(&self.monero_anchor_scheme, "oracle monero anchor scheme")?;
        ensure_non_empty(&self.fee_asset_id, "oracle fee asset id")?;
        ensure_non_empty(&self.monero_network, "oracle monero network")?;
        ensure_positive(self.schema_version, "oracle schema version")?;
        ensure_positive(self.epoch_blocks, "oracle epoch blocks")?;
        ensure_positive(
            self.snapshot_lookahead_blocks,
            "oracle snapshot lookahead blocks",
        )?;
        ensure_positive(self.finality_target_blocks, "oracle finality target blocks")?;
        ensure_positive(
            self.challenge_window_blocks,
            "oracle challenge window blocks",
        )?;
        ensure_positive(
            self.monero_confirmation_target,
            "oracle monero confirmation target",
        )?;
        ensure_bps(self.fast_quorum_bps, "oracle fast quorum")?;
        ensure_bps(self.safe_quorum_bps, "oracle safe quorum")?;
        ensure_bps(self.fallback_quorum_bps, "oracle fallback quorum")?;
        ensure_positive(self.watcher_quorum, "oracle watcher quorum")?;
        ensure_positive(
            self.min_pq_security_bits as u64,
            "oracle minimum pq security bits",
        )?;
        if self.fast_quorum_bps < self.safe_quorum_bps {
            return Err("oracle fast quorum cannot be lower than safe quorum".to_string());
        }
        if self.fallback_quorum_bps < self.safe_quorum_bps {
            return Err("oracle fallback quorum cannot be lower than safe quorum".to_string());
        }
        if self.protocol_version != PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PROTOCOL_VERSION {
            return Err("oracle protocol version mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeMember {
    pub member_id: String,
    pub role: OracleMemberRole,
    pub pq_public_key_root: String,
    pub backup_public_key_root: String,
    pub stake_weight: u64,
    pub security_bits: u16,
    pub privacy_domain_root: String,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub slashed: bool,
}

impl PqCommitteeMember {
    pub fn devnet(index: u64, role: OracleMemberRole, active_from_height: u64) -> Self {
        let member_id = format!("pq-ffo-member-{index:02}");
        Self {
            pq_public_key_root: devnet_root("member-pq-key", &member_id),
            backup_public_key_root: devnet_root("member-backup-key", &member_id),
            stake_weight: match role {
                OracleMemberRole::Validator => 120,
                OracleMemberRole::Sequencer => 100,
                OracleMemberRole::BridgeGuardian => 90,
                OracleMemberRole::Watcher => 70,
                OracleMemberRole::Sponsor => 40,
                OracleMemberRole::EmergencyGuardian => 110,
            },
            security_bits: 256,
            privacy_domain_root: devnet_root("member-privacy-domain", &member_id),
            active_until_height: active_from_height + 2_400,
            active_from_height,
            member_id,
            role,
            slashed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_committee_member",
            "chain_id": CHAIN_ID,
            "member_id": self.member_id,
            "role": self.role.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "backup_public_key_root": self.backup_public_key_root,
            "stake_weight": self.stake_weight,
            "security_bits": self.security_bits,
            "privacy_domain_root": self.privacy_domain_root,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "slashed": self.slashed,
        })
    }

    pub fn member_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-MEMBER", &self.public_record())
    }

    pub fn validate(
        &self,
        min_security_bits: u16,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.member_id, "committee member id")?;
        ensure_non_empty(&self.pq_public_key_root, "committee member pq key root")?;
        ensure_non_empty(
            &self.backup_public_key_root,
            "committee member backup key root",
        )?;
        ensure_non_empty(
            &self.privacy_domain_root,
            "committee member privacy domain root",
        )?;
        ensure_positive(self.stake_weight, "committee member stake weight")?;
        if self.security_bits < min_security_bits {
            return Err(format!(
                "committee member {} below minimum pq security bits",
                self.member_id
            ));
        }
        if self.active_until_height <= self.active_from_height {
            return Err(format!(
                "committee member {} active window is invalid",
                self.member_id
            ));
        }
        Ok(self.member_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeSnapshot {
    pub snapshot_id: String,
    pub committee_id: String,
    pub epoch_index: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub total_weight: u64,
    pub member_roots: BTreeMap<String, String>,
    pub active_members: BTreeSet<String>,
    pub watcher_members: BTreeSet<String>,
    pub sponsor_members: BTreeSet<String>,
    pub status: OracleRecordStatus,
}

impl PqCommitteeSnapshot {
    pub fn new(
        committee_id: &str,
        epoch_index: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        members: &BTreeMap<String, PqCommitteeMember>,
    ) -> Self {
        let mut member_roots = BTreeMap::new();
        let mut active_members = BTreeSet::new();
        let mut watcher_members = BTreeSet::new();
        let mut sponsor_members = BTreeSet::new();
        let mut total_weight = 0_u64;
        for (member_id, member) in members {
            if member.slashed {
                continue;
            }
            if member.active_from_height <= valid_from_height
                && member.active_until_height >= valid_until_height
            {
                member_roots.insert(member_id.clone(), member.member_root());
                active_members.insert(member_id.clone());
                total_weight = total_weight.saturating_add(member.stake_weight);
                if member.role == OracleMemberRole::Watcher {
                    watcher_members.insert(member_id.clone());
                }
                if member.role == OracleMemberRole::Sponsor {
                    sponsor_members.insert(member_id.clone());
                }
            }
        }
        let snapshot_id = oracle_id(
            "snapshot",
            &[
                HashPart::Str(committee_id),
                HashPart::Int(epoch_index as i128),
                HashPart::Int(valid_from_height as i128),
                HashPart::Int(valid_until_height as i128),
                HashPart::Int(total_weight as i128),
            ],
        );
        Self {
            snapshot_id,
            committee_id: committee_id.to_string(),
            epoch_index,
            valid_from_height,
            valid_until_height,
            total_weight,
            member_roots,
            active_members,
            watcher_members,
            sponsor_members,
            status: OracleRecordStatus::Active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_committee_snapshot",
            "chain_id": CHAIN_ID,
            "snapshot_id": self.snapshot_id,
            "committee_id": self.committee_id,
            "epoch_index": self.epoch_index,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "total_weight": self.total_weight,
            "member_roots": self.member_roots,
            "active_members": self.active_members,
            "watcher_members": self.watcher_members,
            "sponsor_members": self.sponsor_members,
            "status": self.status.as_str(),
        })
    }

    pub fn snapshot_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-SNAPSHOT", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.snapshot_id, "committee snapshot id")?;
        ensure_non_empty(&self.committee_id, "committee snapshot committee id")?;
        ensure_positive(self.total_weight, "committee snapshot total weight")?;
        if self.valid_until_height <= self.valid_from_height {
            return Err(format!(
                "committee snapshot {} window invalid",
                self.snapshot_id
            ));
        }
        if self.active_members.len() != self.member_roots.len() {
            return Err(format!(
                "committee snapshot {} active member/root mismatch",
                self.snapshot_id
            ));
        }
        Ok(self.snapshot_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityStatement {
    pub statement_id: String,
    pub lane: FastFinalityOracleLane,
    pub block_height: u64,
    pub l2_block_root: String,
    pub post_state_root: String,
    pub privacy_state_root: String,
    pub contract_state_root: String,
    pub da_commitment_root: String,
    pub monero_anchor_id: String,
    pub created_at_height: u64,
}

impl FinalityStatement {
    pub fn new(
        lane: FastFinalityOracleLane,
        block_height: u64,
        monero_anchor_id: &str,
        created_at_height: u64,
    ) -> Self {
        let lane_text = lane.as_str();
        let l2_block_root =
            devnet_root("statement-l2-block", &format!("{lane_text}-{block_height}"));
        let post_state_root = devnet_root(
            "statement-post-state",
            &format!("{lane_text}-{block_height}"),
        );
        let privacy_state_root = devnet_root(
            "statement-privacy-state",
            &format!("{lane_text}-{block_height}"),
        );
        let contract_state_root = devnet_root(
            "statement-contract-state",
            &format!("{lane_text}-{block_height}"),
        );
        let da_commitment_root =
            devnet_root("statement-da", &format!("{lane_text}-{block_height}"));
        let statement_id = oracle_id(
            "statement",
            &[
                HashPart::Str(lane_text),
                HashPart::Int(block_height as i128),
                HashPart::Str(&l2_block_root),
                HashPart::Str(&post_state_root),
                HashPart::Str(monero_anchor_id),
            ],
        );
        Self {
            statement_id,
            lane,
            block_height,
            l2_block_root,
            post_state_root,
            privacy_state_root,
            contract_state_root,
            da_commitment_root,
            monero_anchor_id: monero_anchor_id.to_string(),
            created_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_statement",
            "chain_id": CHAIN_ID,
            "statement_id": self.statement_id,
            "lane": self.lane.as_str(),
            "block_height": self.block_height,
            "l2_block_root": self.l2_block_root,
            "post_state_root": self.post_state_root,
            "privacy_state_root": self.privacy_state_root,
            "contract_state_root": self.contract_state_root,
            "da_commitment_root": self.da_commitment_root,
            "monero_anchor_id": self.monero_anchor_id,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn statement_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-STATEMENT", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.statement_id, "finality statement id")?;
        ensure_non_empty(&self.l2_block_root, "finality statement l2 block root")?;
        ensure_non_empty(&self.post_state_root, "finality statement post state root")?;
        ensure_non_empty(
            &self.privacy_state_root,
            "finality statement privacy state root",
        )?;
        ensure_non_empty(
            &self.contract_state_root,
            "finality statement contract state root",
        )?;
        ensure_non_empty(&self.da_commitment_root, "finality statement da root")?;
        ensure_non_empty(
            &self.monero_anchor_id,
            "finality statement monero anchor id",
        )?;
        ensure_positive(self.block_height, "finality statement block height")?;
        Ok(self.statement_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateAttestation {
    pub aggregate_id: String,
    pub snapshot_id: String,
    pub statement_id: String,
    pub signer_ids: BTreeSet<String>,
    pub signer_weight: u64,
    pub total_weight: u64,
    pub quorum_bps: u64,
    pub aggregate_signature_root: String,
    pub transcript_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: OracleRecordStatus,
}

impl AggregateAttestation {
    pub fn new(
        snapshot: &PqCommitteeSnapshot,
        statement: &FinalityStatement,
        signer_ids: BTreeSet<String>,
        signer_weight: u64,
        quorum_bps: u64,
        attested_at_height: u64,
        challenge_window_blocks: u64,
    ) -> Self {
        let transcript_root = oracle_id(
            "aggregate-transcript",
            &[
                HashPart::Str(&snapshot.snapshot_root()),
                HashPart::Str(&statement.statement_root()),
                HashPart::Int(signer_weight as i128),
                HashPart::Int(quorum_bps as i128),
            ],
        );
        let aggregate_signature_root = devnet_root(
            "aggregate-signature",
            &format!("{}-{transcript_root}", statement.statement_id),
        );
        let aggregate_id = oracle_id(
            "aggregate",
            &[
                HashPart::Str(&snapshot.snapshot_id),
                HashPart::Str(&statement.statement_id),
                HashPart::Str(&aggregate_signature_root),
            ],
        );
        Self {
            aggregate_id,
            snapshot_id: snapshot.snapshot_id.clone(),
            statement_id: statement.statement_id.clone(),
            signer_ids,
            signer_weight,
            total_weight: snapshot.total_weight,
            quorum_bps,
            aggregate_signature_root,
            transcript_root,
            attested_at_height,
            expires_at_height: attested_at_height.saturating_add(challenge_window_blocks),
            status: OracleRecordStatus::Attested,
        }
    }

    pub fn quorum_reached(&self) -> bool {
        if self.total_weight == 0 {
            return false;
        }
        self.signer_weight
            .saturating_mul(PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_MAX_BPS)
            >= self.total_weight.saturating_mul(self.quorum_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "aggregate_attestation",
            "chain_id": CHAIN_ID,
            "aggregate_id": self.aggregate_id,
            "snapshot_id": self.snapshot_id,
            "statement_id": self.statement_id,
            "signer_ids": self.signer_ids,
            "signer_weight": self.signer_weight,
            "total_weight": self.total_weight,
            "quorum_bps": self.quorum_bps,
            "aggregate_signature_root": self.aggregate_signature_root,
            "transcript_root": self.transcript_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "quorum_reached": self.quorum_reached(),
        })
    }

    pub fn aggregate_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-AGGREGATE", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.aggregate_id, "aggregate attestation id")?;
        ensure_non_empty(&self.snapshot_id, "aggregate attestation snapshot id")?;
        ensure_non_empty(&self.statement_id, "aggregate attestation statement id")?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "aggregate attestation signature root",
        )?;
        ensure_non_empty(
            &self.transcript_root,
            "aggregate attestation transcript root",
        )?;
        ensure_positive(self.signer_weight, "aggregate attestation signer weight")?;
        ensure_positive(self.total_weight, "aggregate attestation total weight")?;
        ensure_bps(self.quorum_bps, "aggregate attestation quorum")?;
        if self.expires_at_height <= self.attested_at_height {
            return Err(format!(
                "aggregate attestation {} expires too early",
                self.aggregate_id
            ));
        }
        if !self.quorum_reached() {
            return Err(format!(
                "aggregate attestation {} below quorum",
                self.aggregate_id
            ));
        }
        Ok(self.aggregate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackWatcherReport {
    pub report_id: String,
    pub watcher_id: String,
    pub statement_id: String,
    pub observed_block_height: u64,
    pub observed_state_root: String,
    pub availability_root: String,
    pub report_signature_root: String,
    pub reported_at_height: u64,
    pub status: OracleRecordStatus,
}

impl FallbackWatcherReport {
    pub fn new(watcher_id: &str, statement: &FinalityStatement, reported_at_height: u64) -> Self {
        let availability_root = devnet_root(
            "watcher-availability",
            &format!("{}-{watcher_id}", statement.statement_id),
        );
        let report_signature_root = devnet_root(
            "watcher-signature",
            &format!("{}-{watcher_id}", statement.statement_id),
        );
        let report_id = oracle_id(
            "watcher-report",
            &[
                HashPart::Str(watcher_id),
                HashPart::Str(&statement.statement_id),
                HashPart::Str(&statement.post_state_root),
                HashPart::Str(&availability_root),
            ],
        );
        Self {
            report_id,
            watcher_id: watcher_id.to_string(),
            statement_id: statement.statement_id.clone(),
            observed_block_height: statement.block_height,
            observed_state_root: statement.post_state_root.clone(),
            availability_root,
            report_signature_root,
            reported_at_height,
            status: OracleRecordStatus::Attested,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fallback_watcher_report",
            "chain_id": CHAIN_ID,
            "report_id": self.report_id,
            "watcher_id": self.watcher_id,
            "statement_id": self.statement_id,
            "observed_block_height": self.observed_block_height,
            "observed_state_root": self.observed_state_root,
            "availability_root": self.availability_root,
            "report_signature_root": self.report_signature_root,
            "reported_at_height": self.reported_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn report_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-WATCHER-REPORT", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.report_id, "watcher report id")?;
        ensure_non_empty(&self.watcher_id, "watcher report watcher id")?;
        ensure_non_empty(&self.statement_id, "watcher report statement id")?;
        ensure_non_empty(&self.observed_state_root, "watcher report state root")?;
        ensure_non_empty(&self.availability_root, "watcher report availability root")?;
        ensure_non_empty(&self.report_signature_root, "watcher report signature root")?;
        ensure_positive(self.observed_block_height, "watcher report observed height")?;
        Ok(self.report_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroCheckpointAnchor {
    pub anchor_id: String,
    pub lane: FastFinalityOracleLane,
    pub l2_block_height: u64,
    pub checkpoint_root: String,
    pub monero_network: String,
    pub monero_txid: String,
    pub monero_block_height: u64,
    pub monero_block_hash: String,
    pub confirmations: u64,
    pub anchor_fee_units: u64,
    pub observed_at_height: u64,
    pub status: OracleRecordStatus,
}

impl MoneroCheckpointAnchor {
    pub fn devnet(
        lane: FastFinalityOracleLane,
        l2_block_height: u64,
        observed_at_height: u64,
    ) -> Self {
        let seed = format!("{}-{l2_block_height}", lane.as_str());
        let checkpoint_root = devnet_root("monero-anchor-checkpoint", &seed);
        let monero_txid = devnet_root("monero-anchor-txid", &seed);
        let monero_block_hash = devnet_root("monero-anchor-block", &seed);
        let anchor_id = oracle_id(
            "monero-anchor",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Int(l2_block_height as i128),
                HashPart::Str(&checkpoint_root),
                HashPart::Str(&monero_txid),
            ],
        );
        Self {
            anchor_id,
            lane,
            l2_block_height,
            checkpoint_root,
            monero_network: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_MONERO_NETWORK.to_string(),
            monero_txid,
            monero_block_height: 90_000_u64.saturating_add(l2_block_height / 20),
            monero_block_hash,
            confirmations: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_MONERO_CONFIRMATIONS,
            anchor_fee_units: lane.default_sponsored_fee_units(),
            observed_at_height,
            status: OracleRecordStatus::Finalized,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_checkpoint_anchor",
            "chain_id": CHAIN_ID,
            "anchor_id": self.anchor_id,
            "lane": self.lane.as_str(),
            "l2_block_height": self.l2_block_height,
            "checkpoint_root": self.checkpoint_root,
            "monero_network": self.monero_network,
            "monero_txid": self.monero_txid,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
            "confirmations": self.confirmations,
            "anchor_fee_units": self.anchor_fee_units,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn anchor_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-MONERO-ANCHOR", &self.public_record())
    }

    pub fn validate(
        &self,
        required_confirmations: u64,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.anchor_id, "monero anchor id")?;
        ensure_non_empty(&self.checkpoint_root, "monero anchor checkpoint root")?;
        ensure_non_empty(&self.monero_network, "monero anchor network")?;
        ensure_non_empty(&self.monero_txid, "monero anchor txid")?;
        ensure_non_empty(&self.monero_block_hash, "monero anchor block hash")?;
        ensure_positive(self.l2_block_height, "monero anchor l2 height")?;
        ensure_positive(self.monero_block_height, "monero anchor block height")?;
        if self.confirmations < required_confirmations {
            return Err(format!(
                "monero anchor {} below confirmation target",
                self.anchor_id
            ));
        }
        Ok(self.anchor_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub statement_id: String,
    pub lane: FastFinalityOracleLane,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub consumed_fee_units: u64,
    pub proof_credit_root: String,
    pub privacy_nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: OracleRecordStatus,
}

impl LowFeeProofSponsorship {
    pub fn new(
        sponsor_id: &str,
        statement: &FinalityStatement,
        fee_asset_id: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let proof_credit_root = devnet_root(
            "sponsor-proof-credit",
            &format!("{}-{sponsor_id}", statement.statement_id),
        );
        let privacy_nullifier_root = devnet_root(
            "sponsor-nullifier",
            &format!("{}-{sponsor_id}", statement.statement_id),
        );
        let sponsorship_id = oracle_id(
            "proof-sponsorship",
            &[
                HashPart::Str(sponsor_id),
                HashPart::Str(&statement.statement_id),
                HashPart::Str(fee_asset_id),
                HashPart::Str(&proof_credit_root),
            ],
        );
        let reserved_fee_units = statement.lane.default_sponsored_fee_units();
        Self {
            sponsorship_id,
            sponsor_id: sponsor_id.to_string(),
            statement_id: statement.statement_id.clone(),
            lane: statement.lane,
            fee_asset_id: fee_asset_id.to_string(),
            reserved_fee_units,
            consumed_fee_units: reserved_fee_units,
            proof_credit_root,
            privacy_nullifier_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: OracleRecordStatus::Finalized,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "statement_id": self.statement_id,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "consumed_fee_units": self.consumed_fee_units,
            "proof_credit_root": self.proof_credit_root,
            "privacy_nullifier_root": self.privacy_nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-PROOF-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self, budget_units: u64) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.sponsorship_id, "proof sponsorship id")?;
        ensure_non_empty(&self.sponsor_id, "proof sponsorship sponsor id")?;
        ensure_non_empty(&self.statement_id, "proof sponsorship statement id")?;
        ensure_non_empty(&self.fee_asset_id, "proof sponsorship fee asset id")?;
        ensure_non_empty(&self.proof_credit_root, "proof sponsorship credit root")?;
        ensure_non_empty(
            &self.privacy_nullifier_root,
            "proof sponsorship privacy nullifier root",
        )?;
        if self.reserved_fee_units > budget_units {
            return Err(format!(
                "proof sponsorship {} exceeds low-fee proof budget",
                self.sponsorship_id
            ));
        }
        if self.consumed_fee_units > self.reserved_fee_units {
            return Err(format!(
                "proof sponsorship {} consumes more than reserved",
                self.sponsorship_id
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "proof sponsorship {} expiry invalid",
                self.sponsorship_id
            ));
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudChallenge {
    pub challenge_id: String,
    pub aggregate_id: String,
    pub challenger_id: String,
    pub kind: FraudChallengeKind,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub outcome: FraudChallengeOutcome,
}

impl FraudChallenge {
    pub fn new(
        aggregate_id: &str,
        challenger_id: &str,
        kind: FraudChallengeKind,
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> Self {
        let evidence_root =
            devnet_root("fraud-evidence", &format!("{aggregate_id}-{challenger_id}"));
        let challenge_id = oracle_id(
            "fraud-challenge",
            &[
                HashPart::Str(aggregate_id),
                HashPart::Str(challenger_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&evidence_root),
            ],
        );
        Self {
            challenge_id,
            aggregate_id: aggregate_id.to_string(),
            challenger_id: challenger_id.to_string(),
            kind,
            evidence_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(challenge_window_blocks),
            outcome: FraudChallengeOutcome::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fraud_challenge",
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "aggregate_id": self.aggregate_id,
            "challenger_id": self.challenger_id,
            "challenge_kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "outcome": self.outcome.as_str(),
        })
    }

    pub fn challenge_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-FRAUD-CHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.challenge_id, "fraud challenge id")?;
        ensure_non_empty(&self.aggregate_id, "fraud challenge aggregate id")?;
        ensure_non_empty(&self.challenger_id, "fraud challenge challenger id")?;
        ensure_non_empty(&self.evidence_root, "fraud challenge evidence root")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "fraud challenge {} expiry invalid",
                self.challenge_id
            ));
        }
        Ok(self.challenge_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingReceipt {
    pub receipt_id: String,
    pub member_id: String,
    pub challenge_id: String,
    pub reason: SlashingReason,
    pub slashed_weight: u64,
    pub penalty_bps: u64,
    pub redistribution_root: String,
    pub issued_at_height: u64,
}

impl SlashingReceipt {
    pub fn new(
        member_id: &str,
        challenge_id: &str,
        reason: SlashingReason,
        slashed_weight: u64,
        penalty_bps: u64,
        issued_at_height: u64,
    ) -> Self {
        let redistribution_root = devnet_root(
            "slashing-redistribution",
            &format!("{member_id}-{challenge_id}"),
        );
        let receipt_id = oracle_id(
            "slashing-receipt",
            &[
                HashPart::Str(member_id),
                HashPart::Str(challenge_id),
                HashPart::Str(reason.as_str()),
                HashPart::Int(slashed_weight as i128),
            ],
        );
        Self {
            receipt_id,
            member_id: member_id.to_string(),
            challenge_id: challenge_id.to_string(),
            reason,
            slashed_weight,
            penalty_bps,
            redistribution_root,
            issued_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "member_id": self.member_id,
            "challenge_id": self.challenge_id,
            "reason": self.reason.as_str(),
            "slashed_weight": self.slashed_weight,
            "penalty_bps": self.penalty_bps,
            "redistribution_root": self.redistribution_root,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-SLASHING-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.receipt_id, "slashing receipt id")?;
        ensure_non_empty(&self.member_id, "slashing receipt member id")?;
        ensure_non_empty(&self.challenge_id, "slashing receipt challenge id")?;
        ensure_non_empty(
            &self.redistribution_root,
            "slashing receipt redistribution root",
        )?;
        ensure_positive(self.slashed_weight, "slashing receipt weight")?;
        ensure_bps(self.penalty_bps, "slashing receipt penalty bps")?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityRiskAssessment {
    pub assessment_id: String,
    pub statement_id: String,
    pub aggregate_id: String,
    pub tier: FinalityRiskTier,
    pub quorum_bps: u64,
    pub watcher_reports: u64,
    pub monero_confirmations: u64,
    pub challenge_count: u64,
    pub sponsored_fee_units: u64,
    pub assessed_at_height: u64,
}

impl FinalityRiskAssessment {
    pub fn assess(
        statement: &FinalityStatement,
        aggregate: &AggregateAttestation,
        watcher_reports: u64,
        monero_confirmations: u64,
        challenge_count: u64,
        sponsored_fee_units: u64,
        assessed_at_height: u64,
    ) -> Self {
        let observed_bps = if aggregate.total_weight == 0 {
            0
        } else {
            aggregate
                .signer_weight
                .saturating_mul(PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_MAX_BPS)
                / aggregate.total_weight
        };
        let tier = if challenge_count > 0 {
            FinalityRiskTier::ChallengeOpen
        } else if statement.lane == FastFinalityOracleLane::EmergencyExit {
            FinalityRiskTier::EmergencyOnly
        } else if observed_bps >= PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FAST_QUORUM_BPS
            && monero_confirmations
                >= PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_MONERO_CONFIRMATIONS
        {
            FinalityRiskTier::Instant
        } else if observed_bps >= PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_FAST_QUORUM_BPS {
            FinalityRiskTier::Fast
        } else if monero_confirmations
            >= PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_MONERO_CONFIRMATIONS
        {
            FinalityRiskTier::Anchored
        } else if watcher_reports >= PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEFAULT_WATCHER_QUORUM {
            FinalityRiskTier::WatcherBacked
        } else {
            FinalityRiskTier::Unsafe
        };
        let assessment_id = oracle_id(
            "risk-assessment",
            &[
                HashPart::Str(&statement.statement_id),
                HashPart::Str(&aggregate.aggregate_id),
                HashPart::Str(tier.as_str()),
                HashPart::Int(assessed_at_height as i128),
            ],
        );
        Self {
            assessment_id,
            statement_id: statement.statement_id.clone(),
            aggregate_id: aggregate.aggregate_id.clone(),
            tier,
            quorum_bps: observed_bps,
            watcher_reports,
            monero_confirmations,
            challenge_count,
            sponsored_fee_units,
            assessed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_risk_assessment",
            "chain_id": CHAIN_ID,
            "assessment_id": self.assessment_id,
            "statement_id": self.statement_id,
            "aggregate_id": self.aggregate_id,
            "tier": self.tier.as_str(),
            "tier_rank": self.tier.rank(),
            "quorum_bps": self.quorum_bps,
            "watcher_reports": self.watcher_reports,
            "monero_confirmations": self.monero_confirmations,
            "challenge_count": self.challenge_count,
            "sponsored_fee_units": self.sponsored_fee_units,
            "assessed_at_height": self.assessed_at_height,
        })
    }

    pub fn assessment_root(&self) -> String {
        oracle_payload_root("PQ-LC-FFO-RISK-ASSESSMENT", &self.public_record())
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(&self.assessment_id, "risk assessment id")?;
        ensure_non_empty(&self.statement_id, "risk assessment statement id")?;
        ensure_non_empty(&self.aggregate_id, "risk assessment aggregate id")?;
        ensure_bps(self.quorum_bps, "risk assessment quorum bps")?;
        Ok(self.assessment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFastFinalityOracleRoots {
    pub config_root: String,
    pub member_root: String,
    pub snapshot_root: String,
    pub statement_root: String,
    pub aggregate_root: String,
    pub watcher_report_root: String,
    pub monero_anchor_root: String,
    pub sponsorship_root: String,
    pub fraud_challenge_root: String,
    pub slashing_receipt_root: String,
    pub risk_assessment_root: String,
}

impl PqLightClientFastFinalityOracleRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "member_root": self.member_root,
            "snapshot_root": self.snapshot_root,
            "statement_root": self.statement_root,
            "aggregate_root": self.aggregate_root,
            "watcher_report_root": self.watcher_report_root,
            "monero_anchor_root": self.monero_anchor_root,
            "sponsorship_root": self.sponsorship_root,
            "fraud_challenge_root": self.fraud_challenge_root,
            "slashing_receipt_root": self.slashing_receipt_root,
            "risk_assessment_root": self.risk_assessment_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFastFinalityOracleCounters {
    pub members: u64,
    pub active_members: u64,
    pub snapshots: u64,
    pub statements: u64,
    pub aggregate_attestations: u64,
    pub watcher_reports: u64,
    pub monero_anchors: u64,
    pub sponsorships: u64,
    pub open_challenges: u64,
    pub resolved_challenges: u64,
    pub slashing_receipts: u64,
    pub risk_assessments: u64,
    pub finalized_statements: u64,
    pub sponsored_fee_units: u64,
}

impl PqLightClientFastFinalityOracleCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "members": self.members,
            "active_members": self.active_members,
            "snapshots": self.snapshots,
            "statements": self.statements,
            "aggregate_attestations": self.aggregate_attestations,
            "watcher_reports": self.watcher_reports,
            "monero_anchors": self.monero_anchors,
            "sponsorships": self.sponsorships,
            "open_challenges": self.open_challenges,
            "resolved_challenges": self.resolved_challenges,
            "slashing_receipts": self.slashing_receipts,
            "risk_assessments": self.risk_assessments,
            "finalized_statements": self.finalized_statements,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLightClientFastFinalityOracle {
    pub config: PqLightClientFastFinalityOracleConfig,
    pub current_height: u64,
    pub committee_members: BTreeMap<String, PqCommitteeMember>,
    pub committee_snapshots: BTreeMap<String, PqCommitteeSnapshot>,
    pub statements: BTreeMap<String, FinalityStatement>,
    pub aggregate_attestations: BTreeMap<String, AggregateAttestation>,
    pub watcher_reports: BTreeMap<String, FallbackWatcherReport>,
    pub monero_anchors: BTreeMap<String, MoneroCheckpointAnchor>,
    pub sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub fraud_challenges: BTreeMap<String, FraudChallenge>,
    pub slashing_receipts: BTreeMap<String, SlashingReceipt>,
    pub risk_assessments: BTreeMap<String, FinalityRiskAssessment>,
    pub finalized_statements: BTreeSet<String>,
}

impl Default for PqLightClientFastFinalityOracle {
    fn default() -> Self {
        Self {
            config: PqLightClientFastFinalityOracleConfig::default(),
            current_height: 0,
            committee_members: BTreeMap::new(),
            committee_snapshots: BTreeMap::new(),
            statements: BTreeMap::new(),
            aggregate_attestations: BTreeMap::new(),
            watcher_reports: BTreeMap::new(),
            monero_anchors: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            fraud_challenges: BTreeMap::new(),
            slashing_receipts: BTreeMap::new(),
            risk_assessments: BTreeMap::new(),
            finalized_statements: BTreeSet::new(),
        }
    }
}

impl PqLightClientFastFinalityOracle {
    pub fn devnet() -> Self {
        let mut state = Self {
            current_height: PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_HEIGHT,
            ..Self::default()
        };
        let base_height = state.current_height.saturating_sub(120);
        let roles = [
            OracleMemberRole::Validator,
            OracleMemberRole::Validator,
            OracleMemberRole::Validator,
            OracleMemberRole::Sequencer,
            OracleMemberRole::BridgeGuardian,
            OracleMemberRole::Watcher,
            OracleMemberRole::Watcher,
            OracleMemberRole::Sponsor,
            OracleMemberRole::EmergencyGuardian,
        ];
        for (index, role) in roles.into_iter().enumerate() {
            let member = PqCommitteeMember::devnet((index as u64) + 1, role, base_height);
            state
                .committee_members
                .insert(member.member_id.clone(), member);
        }
        let snapshot = PqCommitteeSnapshot::new(
            PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_DEVNET_COMMITTEE_ID,
            3,
            base_height,
            base_height.saturating_add(state.config.epoch_blocks),
            &state.committee_members,
        );
        let snapshot_id = snapshot.snapshot_id.clone();
        state
            .committee_snapshots
            .insert(snapshot_id.clone(), snapshot);

        for lane in [
            FastFinalityOracleLane::PrivateTransfer,
            FastFinalityOracleLane::MoneroBridge,
            FastFinalityOracleLane::DefiSettlement,
            FastFinalityOracleLane::ContractExecution,
        ] {
            let anchor = MoneroCheckpointAnchor::devnet(
                lane,
                state
                    .current_height
                    .saturating_sub(lane.default_sponsored_fee_units()),
                state.current_height,
            );
            let statement = FinalityStatement::new(
                lane,
                anchor.l2_block_height,
                &anchor.anchor_id,
                state.current_height,
            );
            let statement_id = statement.statement_id.clone();
            state
                .monero_anchors
                .insert(anchor.anchor_id.clone(), anchor);
            state.statements.insert(statement_id.clone(), statement);
            let _ = state.attest_statement(&snapshot_id, &statement_id);
            let _ = state.add_default_watcher_reports(&statement_id);
            let _ = state.sponsor_statement(&statement_id);
            let _ = state.assess_statement(&statement_id);
        }
        state
    }

    pub fn update_height(&mut self, new_height: u64) -> PqLightClientFastFinalityOracleResult<u64> {
        if new_height < self.current_height {
            return Err("oracle height cannot move backwards".to_string());
        }
        self.current_height = new_height;
        Ok(self.current_height)
    }

    pub fn register_member(
        &mut self,
        member: PqCommitteeMember,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        member.validate(self.config.min_pq_security_bits)?;
        if self.committee_members.contains_key(&member.member_id) {
            return Err(format!(
                "committee member {} already exists",
                member.member_id
            ));
        }
        let member_id = member.member_id.clone();
        let member_root = member.member_root();
        self.committee_members.insert(member_id, member);
        Ok(member_root)
    }

    pub fn create_snapshot(
        &mut self,
        committee_id: &str,
        epoch_index: u64,
        valid_from_height: u64,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(committee_id, "committee id")?;
        if valid_from_height < self.current_height {
            return Err("snapshot valid_from_height cannot be below current height".to_string());
        }
        let valid_until_height = valid_from_height.saturating_add(self.config.epoch_blocks);
        let snapshot = PqCommitteeSnapshot::new(
            committee_id,
            epoch_index,
            valid_from_height,
            valid_until_height,
            &self.committee_members,
        );
        snapshot.validate()?;
        let snapshot_id = snapshot.snapshot_id.clone();
        let snapshot_root = snapshot.snapshot_root();
        self.committee_snapshots.insert(snapshot_id, snapshot);
        Ok(snapshot_root)
    }

    pub fn add_monero_anchor(
        &mut self,
        anchor: MoneroCheckpointAnchor,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        anchor.validate(self.config.monero_confirmation_target)?;
        if self.monero_anchors.contains_key(&anchor.anchor_id) {
            return Err(format!("monero anchor {} already exists", anchor.anchor_id));
        }
        let anchor_id = anchor.anchor_id.clone();
        let anchor_root = anchor.anchor_root();
        self.monero_anchors.insert(anchor_id, anchor);
        Ok(anchor_root)
    }

    pub fn open_statement(
        &mut self,
        statement: FinalityStatement,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        statement.validate()?;
        if statement.created_at_height < self.current_height {
            return Err("finality statement cannot be opened in the past".to_string());
        }
        if self.config.require_monero_anchor_for_bridge
            && statement.lane == FastFinalityOracleLane::MoneroBridge
            && !self
                .monero_anchors
                .contains_key(&statement.monero_anchor_id)
        {
            return Err("monero bridge statement requires known monero anchor".to_string());
        }
        let statement_id = statement.statement_id.clone();
        let statement_root = statement.statement_root();
        self.statements.insert(statement_id, statement);
        Ok(statement_root)
    }

    pub fn attest_statement(
        &mut self,
        snapshot_id: &str,
        statement_id: &str,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        let snapshot = self
            .committee_snapshots
            .get(snapshot_id)
            .ok_or_else(|| format!("unknown committee snapshot {snapshot_id}"))?;
        let statement = self
            .statements
            .get(statement_id)
            .ok_or_else(|| format!("unknown finality statement {statement_id}"))?;
        if statement.created_at_height < snapshot.valid_from_height
            || statement.created_at_height > snapshot.valid_until_height
        {
            return Err("statement outside committee snapshot validity window".to_string());
        }
        let mut signer_ids = BTreeSet::new();
        let mut signer_weight = 0_u64;
        for member_id in &snapshot.active_members {
            if let Some(member) = self.committee_members.get(member_id) {
                if member.role != OracleMemberRole::Sponsor
                    && member.role != OracleMemberRole::Watcher
                {
                    signer_ids.insert(member_id.clone());
                    signer_weight = signer_weight.saturating_add(member.stake_weight);
                }
            }
        }
        let aggregate = AggregateAttestation::new(
            snapshot,
            statement,
            signer_ids,
            signer_weight,
            self.config.safe_quorum_bps,
            self.current_height,
            self.config.challenge_window_blocks,
        );
        aggregate.validate()?;
        let aggregate_id = aggregate.aggregate_id.clone();
        let aggregate_root = aggregate.aggregate_root();
        self.aggregate_attestations.insert(aggregate_id, aggregate);
        Ok(aggregate_root)
    }

    pub fn add_watcher_report(
        &mut self,
        report: FallbackWatcherReport,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        report.validate()?;
        if !self.statements.contains_key(&report.statement_id) {
            return Err(format!(
                "watcher report references unknown statement {}",
                report.statement_id
            ));
        }
        if self.watcher_reports.contains_key(&report.report_id) {
            return Err(format!(
                "watcher report {} already exists",
                report.report_id
            ));
        }
        let report_id = report.report_id.clone();
        let report_root = report.report_root();
        self.watcher_reports.insert(report_id, report);
        Ok(report_root)
    }

    pub fn add_default_watcher_reports(
        &mut self,
        statement_id: &str,
    ) -> PqLightClientFastFinalityOracleResult<Vec<String>> {
        let statement = self
            .statements
            .get(statement_id)
            .ok_or_else(|| format!("unknown finality statement {statement_id}"))?
            .clone();
        let watcher_ids = self
            .committee_members
            .iter()
            .filter_map(|(member_id, member)| {
                if member.role == OracleMemberRole::Watcher && !member.slashed {
                    Some(member_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut roots = Vec::new();
        for watcher_id in watcher_ids {
            let report = FallbackWatcherReport::new(&watcher_id, &statement, self.current_height);
            roots.push(self.add_watcher_report(report)?);
        }
        Ok(roots)
    }

    pub fn sponsor_statement(
        &mut self,
        statement_id: &str,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        let statement = self
            .statements
            .get(statement_id)
            .ok_or_else(|| format!("unknown finality statement {statement_id}"))?
            .clone();
        let sponsor_id = self
            .committee_members
            .iter()
            .find_map(|(member_id, member)| {
                if member.role == OracleMemberRole::Sponsor && !member.slashed {
                    Some(member_id.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| "no active proof sponsor available".to_string())?;
        let sponsorship = LowFeeProofSponsorship::new(
            &sponsor_id,
            &statement,
            &self.config.fee_asset_id,
            self.current_height,
            self.config.challenge_window_blocks,
        );
        sponsorship.validate(self.config.low_fee_proof_budget_units)?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        let sponsorship_root = sponsorship.sponsorship_root();
        self.sponsorships.insert(sponsorship_id, sponsorship);
        Ok(sponsorship_root)
    }

    pub fn open_challenge(
        &mut self,
        aggregate_id: &str,
        challenger_id: &str,
        kind: FraudChallengeKind,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_non_empty(challenger_id, "challenge challenger id")?;
        if !self.aggregate_attestations.contains_key(aggregate_id) {
            return Err(format!("unknown aggregate attestation {aggregate_id}"));
        }
        let challenge = FraudChallenge::new(
            aggregate_id,
            challenger_id,
            kind,
            self.current_height,
            self.config.challenge_window_blocks,
        );
        challenge.validate()?;
        if let Some(aggregate) = self.aggregate_attestations.get_mut(aggregate_id) {
            aggregate.status = OracleRecordStatus::ChallengeOpen;
        }
        let challenge_id = challenge.challenge_id.clone();
        let challenge_root = challenge.challenge_root();
        self.fraud_challenges.insert(challenge_id, challenge);
        Ok(challenge_root)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        outcome: FraudChallengeOutcome,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        if !outcome.resolved() {
            return Err("challenge resolution outcome must be resolved".to_string());
        }
        let challenge = self
            .fraud_challenges
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown fraud challenge {challenge_id}"))?;
        challenge.outcome = outcome;
        if let Some(aggregate) = self.aggregate_attestations.get_mut(&challenge.aggregate_id) {
            aggregate.status = match outcome {
                FraudChallengeOutcome::Dismissed | FraudChallengeOutcome::Expired => {
                    OracleRecordStatus::Attested
                }
                FraudChallengeOutcome::Sustained
                | FraudChallengeOutcome::AggregateRejected
                | FraudChallengeOutcome::WatcherFallbackActivated
                | FraudChallengeOutcome::Slashed => OracleRecordStatus::Rejected,
                FraudChallengeOutcome::Open => OracleRecordStatus::ChallengeOpen,
            };
        }
        Ok(challenge.challenge_root())
    }

    pub fn issue_slashing_receipt(
        &mut self,
        member_id: &str,
        challenge_id: &str,
        reason: SlashingReason,
        penalty_bps: u64,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        ensure_bps(penalty_bps, "slashing penalty bps")?;
        let member = self
            .committee_members
            .get_mut(member_id)
            .ok_or_else(|| format!("unknown committee member {member_id}"))?;
        if !self.fraud_challenges.contains_key(challenge_id) {
            return Err(format!("unknown fraud challenge {challenge_id}"));
        }
        let slashed_weight = member.stake_weight.saturating_mul(penalty_bps)
            / PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_MAX_BPS;
        member.slashed = true;
        let receipt = SlashingReceipt::new(
            member_id,
            challenge_id,
            reason,
            slashed_weight.max(1),
            penalty_bps,
            self.current_height,
        );
        receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        let receipt_root = receipt.receipt_root();
        self.slashing_receipts.insert(receipt_id, receipt);
        Ok(receipt_root)
    }

    pub fn assess_statement(
        &mut self,
        statement_id: &str,
    ) -> PqLightClientFastFinalityOracleResult<String> {
        let statement = self
            .statements
            .get(statement_id)
            .ok_or_else(|| format!("unknown finality statement {statement_id}"))?;
        let aggregate = self
            .aggregate_attestations
            .values()
            .find(|aggregate| aggregate.statement_id == statement_id)
            .ok_or_else(|| format!("statement {statement_id} has no aggregate attestation"))?;
        let watcher_reports = self
            .watcher_reports
            .values()
            .filter(|report| report.statement_id == statement_id && report.status.live())
            .count() as u64;
        let monero_confirmations = self
            .monero_anchors
            .get(&statement.monero_anchor_id)
            .map(|anchor| anchor.confirmations)
            .unwrap_or(0);
        let challenge_count = self
            .fraud_challenges
            .values()
            .filter(|challenge| {
                challenge.aggregate_id == aggregate.aggregate_id && !challenge.outcome.resolved()
            })
            .count() as u64;
        let sponsored_fee_units = self
            .sponsorships
            .values()
            .filter(|sponsorship| sponsorship.statement_id == statement_id)
            .map(|sponsorship| sponsorship.consumed_fee_units)
            .sum();
        let assessment = FinalityRiskAssessment::assess(
            statement,
            aggregate,
            watcher_reports,
            monero_confirmations,
            challenge_count,
            sponsored_fee_units,
            self.current_height,
        );
        assessment.validate()?;
        if matches!(
            assessment.tier,
            FinalityRiskTier::Instant | FinalityRiskTier::Fast | FinalityRiskTier::Anchored
        ) {
            self.finalized_statements.insert(statement_id.to_string());
        }
        let assessment_id = assessment.assessment_id.clone();
        let assessment_root = assessment.assessment_root();
        self.risk_assessments.insert(assessment_id, assessment);
        Ok(assessment_root)
    }

    pub fn roots(&self) -> PqLightClientFastFinalityOracleRoots {
        PqLightClientFastFinalityOracleRoots {
            config_root: self.config.config_root(),
            member_root: merkle_map_root(
                "PQ-LC-FFO-MEMBERS",
                self.committee_members
                    .iter()
                    .map(|(id, member)| (id.clone(), member.public_record()))
                    .collect(),
            ),
            snapshot_root: merkle_map_root(
                "PQ-LC-FFO-SNAPSHOTS",
                self.committee_snapshots
                    .iter()
                    .map(|(id, snapshot)| (id.clone(), snapshot.public_record()))
                    .collect(),
            ),
            statement_root: merkle_map_root(
                "PQ-LC-FFO-STATEMENTS",
                self.statements
                    .iter()
                    .map(|(id, statement)| (id.clone(), statement.public_record()))
                    .collect(),
            ),
            aggregate_root: merkle_map_root(
                "PQ-LC-FFO-AGGREGATES",
                self.aggregate_attestations
                    .iter()
                    .map(|(id, aggregate)| (id.clone(), aggregate.public_record()))
                    .collect(),
            ),
            watcher_report_root: merkle_map_root(
                "PQ-LC-FFO-WATCHER-REPORTS",
                self.watcher_reports
                    .iter()
                    .map(|(id, report)| (id.clone(), report.public_record()))
                    .collect(),
            ),
            monero_anchor_root: merkle_map_root(
                "PQ-LC-FFO-MONERO-ANCHORS",
                self.monero_anchors
                    .iter()
                    .map(|(id, anchor)| (id.clone(), anchor.public_record()))
                    .collect(),
            ),
            sponsorship_root: merkle_map_root(
                "PQ-LC-FFO-SPONSORSHIPS",
                self.sponsorships
                    .iter()
                    .map(|(id, sponsorship)| (id.clone(), sponsorship.public_record()))
                    .collect(),
            ),
            fraud_challenge_root: merkle_map_root(
                "PQ-LC-FFO-FRAUD-CHALLENGES",
                self.fraud_challenges
                    .iter()
                    .map(|(id, challenge)| (id.clone(), challenge.public_record()))
                    .collect(),
            ),
            slashing_receipt_root: merkle_map_root(
                "PQ-LC-FFO-SLASHING-RECEIPTS",
                self.slashing_receipts
                    .iter()
                    .map(|(id, receipt)| (id.clone(), receipt.public_record()))
                    .collect(),
            ),
            risk_assessment_root: merkle_map_root(
                "PQ-LC-FFO-RISK-ASSESSMENTS",
                self.risk_assessments
                    .iter()
                    .map(|(id, assessment)| (id.clone(), assessment.public_record()))
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PqLightClientFastFinalityOracleCounters {
        PqLightClientFastFinalityOracleCounters {
            members: self.committee_members.len() as u64,
            active_members: self
                .committee_members
                .values()
                .filter(|member| !member.slashed)
                .count() as u64,
            snapshots: self.committee_snapshots.len() as u64,
            statements: self.statements.len() as u64,
            aggregate_attestations: self.aggregate_attestations.len() as u64,
            watcher_reports: self.watcher_reports.len() as u64,
            monero_anchors: self.monero_anchors.len() as u64,
            sponsorships: self.sponsorships.len() as u64,
            open_challenges: self
                .fraud_challenges
                .values()
                .filter(|challenge| !challenge.outcome.resolved())
                .count() as u64,
            resolved_challenges: self
                .fraud_challenges
                .values()
                .filter(|challenge| challenge.outcome.resolved())
                .count() as u64,
            slashing_receipts: self.slashing_receipts.len() as u64,
            risk_assessments: self.risk_assessments.len() as u64,
            finalized_statements: self.finalized_statements.len() as u64,
            sponsored_fee_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.consumed_fee_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_light_client_fast_finality_oracle",
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "finalized_statements": self.finalized_statements,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        oracle_payload_root(
            "PQ-LC-FFO-STATE",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": self.config.protocol_version,
                "current_height": self.current_height,
                "roots": roots.public_record(),
                "counters": counters.public_record(),
            }),
        )
    }

    pub fn validate(&self) -> PqLightClientFastFinalityOracleResult<String> {
        self.config.validate()?;
        ensure_positive(self.current_height, "oracle current height")?;
        for member in self.committee_members.values() {
            member.validate(self.config.min_pq_security_bits)?;
        }
        for snapshot in self.committee_snapshots.values() {
            snapshot.validate()?;
        }
        for statement in self.statements.values() {
            statement.validate()?;
            if statement.lane == FastFinalityOracleLane::MoneroBridge
                && self.config.require_monero_anchor_for_bridge
                && !self
                    .monero_anchors
                    .contains_key(&statement.monero_anchor_id)
            {
                return Err(format!(
                    "statement {} references missing monero anchor",
                    statement.statement_id
                ));
            }
        }
        for aggregate in self.aggregate_attestations.values() {
            aggregate.validate()?;
            if !self
                .committee_snapshots
                .contains_key(&aggregate.snapshot_id)
            {
                return Err(format!(
                    "aggregate {} missing snapshot",
                    aggregate.aggregate_id
                ));
            }
            if !self.statements.contains_key(&aggregate.statement_id) {
                return Err(format!(
                    "aggregate {} missing statement",
                    aggregate.aggregate_id
                ));
            }
        }
        for report in self.watcher_reports.values() {
            report.validate()?;
        }
        for anchor in self.monero_anchors.values() {
            anchor.validate(self.config.monero_confirmation_target)?;
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate(self.config.low_fee_proof_budget_units)?;
        }
        for challenge in self.fraud_challenges.values() {
            challenge.validate()?;
        }
        for receipt in self.slashing_receipts.values() {
            receipt.validate()?;
        }
        for assessment in self.risk_assessments.values() {
            assessment.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn pq_light_client_fast_finality_oracle_devnet() -> PqLightClientFastFinalityOracle {
    PqLightClientFastFinalityOracle::devnet()
}

pub fn pq_light_client_fast_finality_oracle_payload_root(domain: &str, payload: &Value) -> String {
    oracle_payload_root(domain, payload)
}

fn oracle_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn oracle_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let expanded_domain = format!("PQ-LC-FFO-ID-{domain}");
    domain_hash(
        &expanded_domain,
        &[
            HashPart::Str(PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
        ],
        16,
    ) + &domain_hash(&expanded_domain, parts, 16)
}

fn devnet_root(domain: &str, seed: &str) -> String {
    let expanded_domain = format!("PQ-LC-FFO-DEVNET-{domain}");
    domain_hash(
        &expanded_domain,
        &[
            HashPart::Str(PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn merkle_map_root(domain: &str, records: BTreeMap<String, Value>) -> String {
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> PqLightClientFastFinalityOracleResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PqLightClientFastFinalityOracleResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PqLightClientFastFinalityOracleResult<()> {
    if value == 0 || value > PQ_LIGHT_CLIENT_FAST_FINALITY_ORACLE_MAX_BPS {
        return Err(format!("{label} must be within 1..=10000 bps"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_stable_root() {
        let state = PqLightClientFastFinalityOracle::devnet();
        let first_root = state.validate().unwrap_or_else(|err| err);
        let second_root = PqLightClientFastFinalityOracle::devnet()
            .validate()
            .unwrap_or_else(|err| err);
        assert_eq!(first_root, second_root);
        assert_eq!(state.counters().members, 9);
        assert_eq!(state.counters().statements, 4);
    }

    #[test]
    fn height_update_is_monotonic() {
        let mut state = PqLightClientFastFinalityOracle::devnet();
        assert!(state.update_height(state.current_height + 1).is_ok());
        assert!(state.update_height(state.current_height - 1).is_err());
    }

    #[test]
    fn challenge_and_slash_flow_updates_records() {
        let mut state = PqLightClientFastFinalityOracle::devnet();
        let aggregate_id = state
            .aggregate_attestations
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| String::from("missing"));
        let challenge_root = state.open_challenge(
            &aggregate_id,
            "devnet-challenger",
            FraudChallengeKind::Equivocation,
        );
        assert!(challenge_root.is_ok());
        let challenge_id = state
            .fraud_challenges
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| String::from("missing"));
        assert!(state
            .resolve_challenge(&challenge_id, FraudChallengeOutcome::Slashed)
            .is_ok());
        assert!(state
            .issue_slashing_receipt(
                "pq-ffo-member-01",
                &challenge_id,
                SlashingReason::Equivocation,
                1_000,
            )
            .is_ok());
        assert_eq!(state.counters().slashing_receipts, 1);
    }
}
