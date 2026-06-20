use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateStateAvailabilityInsuranceResult<T> = Result<T, String>;

pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_PROTOCOL_VERSION: &str =
    "nebula-private-state-availability-insurance-v1";
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_SCHEMA_VERSION: &str =
    "private-state-availability-insurance-state-v1";
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_HASH_SUITE: &str =
    "shake256-domain-separated-canonical-json";
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_PQ_SIGNATURE_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_WITNESS_SCHEME: &str =
    "encrypted-private-state-witness-availability-v1";
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_CLAIM_PROOF_SYSTEM: &str =
    "zk-private-state-availability-claim-v1";
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEVNET_HEIGHT: u64 = 920;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_EPOCH_BLOCKS: u64 = 96;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_POLICY_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_PAYOUT_DELAY_BLOCKS: u64 = 12;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MAX_PREMIUM_BPS: u64 = 400;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MAX_PAYOUT_BPS: u64 = 8_000;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MIN_UNDERWRITER_BOND_UNITS: u64 = 50_000;
pub const PRIVATE_STATE_AVAILABILITY_INSURANCE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityLaneKind {
    ContractState,
    DefiVault,
    TokenRegistry,
    BridgeExit,
    WalletRecovery,
    FraudProof,
}

impl AvailabilityLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractState => "contract_state",
            Self::DefiVault => "defi_vault",
            Self::TokenRegistry => "token_registry",
            Self::BridgeExit => "bridge_exit",
            Self::WalletRecovery => "wallet_recovery",
            Self::FraudProof => "fraud_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityPolicyStatus {
    Draft,
    Active,
    Grace,
    Claimed,
    Expired,
    Cancelled,
}

impl AvailabilityPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessAttestationStatus {
    Submitted,
    Counted,
    Disputed,
    Expired,
}

impl WitnessAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityClaimStatus {
    Open,
    EvidencePosted,
    Approved,
    Rejected,
    Paid,
    Slashed,
    Expired,
}

impl AvailabilityClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidencePosted => "evidence_posted",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Paid => "paid",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::EvidencePosted | Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityChallengeKind {
    MissingWitness,
    InvalidShardRoot,
    LateAttestation,
    UnderwriterDefault,
    FraudulentClaim,
}

impl AvailabilityChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWitness => "missing_witness",
            Self::InvalidShardRoot => "invalid_shard_root",
            Self::LateAttestation => "late_attestation",
            Self::UnderwriterDefault => "underwriter_default",
            Self::FraudulentClaim => "fraudulent_claim",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateAvailabilityInsuranceConfig {
    pub protocol_version: String,
    pub schema_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub witness_scheme: String,
    pub claim_proof_system: String,
    pub epoch_blocks: u64,
    pub policy_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub claim_window_blocks: u64,
    pub payout_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_premium_bps: u64,
    pub max_payout_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub min_underwriter_bond_units: u64,
}

impl PrivateStateAvailabilityInsuranceConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_STATE_AVAILABILITY_INSURANCE_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_STATE_AVAILABILITY_INSURANCE_SCHEMA_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_STATE_AVAILABILITY_INSURANCE_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_STATE_AVAILABILITY_INSURANCE_PQ_SIGNATURE_SCHEME
                .to_string(),
            witness_scheme: PRIVATE_STATE_AVAILABILITY_INSURANCE_WITNESS_SCHEME.to_string(),
            claim_proof_system: PRIVATE_STATE_AVAILABILITY_INSURANCE_CLAIM_PROOF_SYSTEM.to_string(),
            epoch_blocks: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_EPOCH_BLOCKS,
            policy_ttl_blocks: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_POLICY_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            claim_window_blocks: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_CLAIM_WINDOW_BLOCKS,
            payout_delay_blocks: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_PAYOUT_DELAY_BLOCKS,
            min_privacy_set_size: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_premium_bps: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MAX_PREMIUM_BPS,
            max_payout_bps: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MAX_PAYOUT_BPS,
            low_fee_rebate_bps: PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_LOW_FEE_REBATE_BPS,
            min_underwriter_bond_units:
                PRIVATE_STATE_AVAILABILITY_INSURANCE_DEFAULT_MIN_UNDERWRITER_BOND_UNITS,
        }
    }

    pub fn validate(&self) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("protocol version", &self.protocol_version)?;
        ensure_nonempty("schema version", &self.schema_version)?;
        ensure_nonempty("chain id", &self.chain_id)?;
        ensure_positive("epoch blocks", self.epoch_blocks)?;
        ensure_positive("policy ttl blocks", self.policy_ttl_blocks)?;
        ensure_positive("attestation ttl blocks", self.attestation_ttl_blocks)?;
        ensure_positive("claim window blocks", self.claim_window_blocks)?;
        ensure_positive("payout delay blocks", self.payout_delay_blocks)?;
        ensure_positive("min privacy set size", self.min_privacy_set_size)?;
        ensure_bps("max premium bps", self.max_premium_bps)?;
        ensure_bps("max payout bps", self.max_payout_bps)?;
        ensure_bps("low fee rebate bps", self.low_fee_rebate_bps)?;
        if self.min_pq_security_bits < 128 {
            return Err("min PQ security bits below 128".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "witness_scheme": self.witness_scheme,
            "claim_proof_system": self.claim_proof_system,
            "epoch_blocks": self.epoch_blocks,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "claim_window_blocks": self.claim_window_blocks,
            "payout_delay_blocks": self.payout_delay_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_premium_bps": self.max_premium_bps,
            "max_payout_bps": self.max_payout_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_underwriter_bond_units": self.min_underwriter_bond_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityInsuranceLane {
    pub lane_id: String,
    pub lane_kind: AvailabilityLaneKind,
    pub fee_asset_id: String,
    pub max_premium_bps: u64,
    pub max_payout_bps: u64,
    pub min_privacy_set_size: u64,
    pub enabled: bool,
}

impl AvailabilityInsuranceLane {
    pub fn devnet(
        lane_kind: AvailabilityLaneKind,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> Self {
        Self {
            lane_id: psai_hash("LANE-ID", &[HashPart::Str(lane_kind.as_str())]),
            lane_kind,
            fee_asset_id: "wxmr-devnet".to_string(),
            max_premium_bps: config.max_premium_bps,
            max_payout_bps: config.max_payout_bps,
            min_privacy_set_size: config.min_privacy_set_size,
            enabled: true,
        }
    }

    pub fn validate(
        &self,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("fee asset id", &self.fee_asset_id)?;
        ensure_bps("lane premium bps", self.max_premium_bps)?;
        ensure_bps("lane payout bps", self.max_payout_bps)?;
        if self.max_premium_bps > config.max_premium_bps {
            return Err(format!("lane {} exceeds premium cap", self.lane_id));
        }
        if self.max_payout_bps > config.max_payout_bps {
            return Err(format!("lane {} exceeds payout cap", self.lane_id));
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!("lane {} privacy set below floor", self.lane_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_premium_bps": self.max_premium_bps,
            "max_payout_bps": self.max_payout_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnderwriterVault {
    pub vault_id: String,
    pub underwriter_commitment: String,
    pub lane_ids: BTreeSet<String>,
    pub bond_units: u64,
    pub reserved_units: u64,
    pub slashed_units: u64,
    pub pq_key_root: String,
    pub active: bool,
}

impl UnderwriterVault {
    pub fn devnet(
        label: &str,
        lane_ids: &[String],
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> Self {
        let underwriter_commitment = psai_string_root("UNDERWRITER", label);
        let pq_key_root = psai_string_root("UNDERWRITER-PQ-KEY", label);
        Self {
            vault_id: psai_hash(
                "UNDERWRITER-VAULT-ID",
                &[
                    HashPart::Str(&underwriter_commitment),
                    HashPart::Str(&pq_key_root),
                ],
            ),
            underwriter_commitment,
            lane_ids: lane_ids.iter().cloned().collect(),
            bond_units: config.min_underwriter_bond_units.saturating_mul(4),
            reserved_units: config.min_underwriter_bond_units,
            slashed_units: 0,
            pq_key_root,
            active: true,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.bond_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, AvailabilityInsuranceLane>,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("vault id", &self.vault_id)?;
        ensure_nonempty("underwriter commitment", &self.underwriter_commitment)?;
        ensure_nonempty("PQ key root", &self.pq_key_root)?;
        ensure_positive("bond units", self.bond_units)?;
        if self.bond_units < config.min_underwriter_bond_units {
            return Err(format!("vault {} bond below minimum", self.vault_id));
        }
        if self.reserved_units.saturating_add(self.slashed_units) > self.bond_units {
            return Err(format!("vault {} over-reserved", self.vault_id));
        }
        if self.lane_ids.is_empty() {
            return Err(format!("vault {} has no lanes", self.vault_id));
        }
        for lane_id in &self.lane_ids {
            if !lanes.contains_key(lane_id) {
                return Err(format!(
                    "vault {} references missing lane {}",
                    self.vault_id, lane_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "underwriter_commitment": self.underwriter_commitment,
            "lane_ids": self.lane_ids.iter().cloned().collect::<Vec<_>>(),
            "bond_units": self.bond_units,
            "reserved_units": self.reserved_units,
            "slashed_units": self.slashed_units,
            "available_units": self.available_units(),
            "pq_key_root": self.pq_key_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsuredStateShard {
    pub shard_id: String,
    pub lane_id: String,
    pub encrypted_state_root: String,
    pub witness_commitment_root: String,
    pub contract_scope_root: String,
    pub privacy_set_size: u64,
    pub opened_height: u64,
}

impl InsuredStateShard {
    pub fn devnet(lane: &AvailabilityInsuranceLane, label: &str, height: u64) -> Self {
        let encrypted_state_root = psai_string_root("ENCRYPTED-STATE", label);
        let witness_commitment_root = psai_string_root("WITNESS-COMMITMENT", label);
        let contract_scope_root = psai_string_root("CONTRACT-SCOPE", label);
        Self {
            shard_id: psai_hash(
                "INSURED-SHARD-ID",
                &[
                    HashPart::Str(&lane.lane_id),
                    HashPart::Str(&encrypted_state_root),
                    HashPart::Int(height as i128),
                ],
            ),
            lane_id: lane.lane_id.clone(),
            encrypted_state_root,
            witness_commitment_root,
            contract_scope_root,
            privacy_set_size: lane.min_privacy_set_size.saturating_add(64),
            opened_height: height,
        }
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, AvailabilityInsuranceLane>,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("shard id", &self.shard_id)?;
        ensure_nonempty("lane id", &self.lane_id)?;
        ensure_nonempty("encrypted state root", &self.encrypted_state_root)?;
        ensure_nonempty("witness commitment root", &self.witness_commitment_root)?;
        ensure_positive("privacy set size", self.privacy_set_size)?;
        if !lanes.contains_key(&self.lane_id) {
            return Err(format!("shard {} references missing lane", self.shard_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("shard {} privacy set below floor", self.shard_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "encrypted_state_root": self.encrypted_state_root,
            "witness_commitment_root": self.witness_commitment_root,
            "contract_scope_root": self.contract_scope_root,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityInsurancePolicy {
    pub policy_id: String,
    pub shard_id: String,
    pub vault_id: String,
    pub premium_commitment: String,
    pub coverage_units: u64,
    pub premium_bps: u64,
    pub payout_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: AvailabilityPolicyStatus,
}

impl AvailabilityInsurancePolicy {
    pub fn devnet(
        shard: &InsuredStateShard,
        vault: &UnderwriterVault,
        height: u64,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> Self {
        let premium_commitment = psai_string_root("PREMIUM", &shard.shard_id);
        Self {
            policy_id: psai_hash(
                "POLICY-ID",
                &[
                    HashPart::Str(&shard.shard_id),
                    HashPart::Str(&vault.vault_id),
                    HashPart::Int(height as i128),
                ],
            ),
            shard_id: shard.shard_id.clone(),
            vault_id: vault.vault_id.clone(),
            premium_commitment,
            coverage_units: 25_000,
            premium_bps: config.max_premium_bps / 2,
            payout_bps: config.max_payout_bps,
            opened_height: height,
            expires_height: height.saturating_add(config.policy_ttl_blocks),
            status: AvailabilityPolicyStatus::Active,
        }
    }

    pub fn validate(
        &self,
        shards: &BTreeMap<String, InsuredStateShard>,
        vaults: &BTreeMap<String, UnderwriterVault>,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("policy id", &self.policy_id)?;
        ensure_nonempty("shard id", &self.shard_id)?;
        ensure_nonempty("vault id", &self.vault_id)?;
        ensure_nonempty("premium commitment", &self.premium_commitment)?;
        ensure_positive("coverage units", self.coverage_units)?;
        ensure_bps("premium bps", self.premium_bps)?;
        ensure_bps("payout bps", self.payout_bps)?;
        if self.expires_height <= self.opened_height {
            return Err(format!("policy {} expiration too early", self.policy_id));
        }
        if self.premium_bps > config.max_premium_bps || self.payout_bps > config.max_payout_bps {
            return Err(format!("policy {} exceeds configured bps", self.policy_id));
        }
        if !shards.contains_key(&self.shard_id) {
            return Err(format!(
                "policy {} references missing shard",
                self.policy_id
            ));
        }
        if !vaults.contains_key(&self.vault_id) {
            return Err(format!(
                "policy {} references missing vault",
                self.policy_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "shard_id": self.shard_id,
            "vault_id": self.vault_id,
            "premium_commitment": self.premium_commitment,
            "coverage_units": self.coverage_units,
            "premium_bps": self.premium_bps,
            "payout_bps": self.payout_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAvailabilityAttestation {
    pub attestation_id: String,
    pub policy_id: String,
    pub shard_id: String,
    pub witness_root: String,
    pub signer_commitment: String,
    pub pq_signature_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: WitnessAttestationStatus,
}

impl PqAvailabilityAttestation {
    pub fn devnet(
        policy: &AvailabilityInsurancePolicy,
        shard: &InsuredStateShard,
        signer_label: &str,
        height: u64,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> Self {
        let signer_commitment = psai_string_root("PQ-SIGNER", signer_label);
        let witness_root = psai_hash(
            "WITNESS-ROOT",
            &[
                HashPart::Str(&shard.witness_commitment_root),
                HashPart::Str(&signer_commitment),
            ],
        );
        let pq_signature_root = psai_hash(
            "PQ-SIGNATURE",
            &[HashPart::Str(&witness_root), HashPart::Int(height as i128)],
        );
        Self {
            attestation_id: psai_hash(
                "ATTESTATION-ID",
                &[
                    HashPart::Str(&policy.policy_id),
                    HashPart::Str(&witness_root),
                    HashPart::Int(height as i128),
                ],
            ),
            policy_id: policy.policy_id.clone(),
            shard_id: shard.shard_id.clone(),
            witness_root,
            signer_commitment,
            pq_signature_root,
            submitted_height: height,
            expires_height: height.saturating_add(config.attestation_ttl_blocks),
            status: WitnessAttestationStatus::Counted,
        }
    }

    pub fn validate(
        &self,
        policies: &BTreeMap<String, AvailabilityInsurancePolicy>,
        shards: &BTreeMap<String, InsuredStateShard>,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("attestation id", &self.attestation_id)?;
        ensure_nonempty("policy id", &self.policy_id)?;
        ensure_nonempty("shard id", &self.shard_id)?;
        ensure_nonempty("witness root", &self.witness_root)?;
        ensure_nonempty("signer commitment", &self.signer_commitment)?;
        ensure_nonempty("PQ signature root", &self.pq_signature_root)?;
        if self.expires_height <= self.submitted_height {
            return Err(format!(
                "attestation {} expiration too early",
                self.attestation_id
            ));
        }
        if !policies.contains_key(&self.policy_id) {
            return Err(format!(
                "attestation {} references missing policy",
                self.attestation_id
            ));
        }
        if !shards.contains_key(&self.shard_id) {
            return Err(format!(
                "attestation {} references missing shard",
                self.attestation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "policy_id": self.policy_id,
            "shard_id": self.shard_id,
            "witness_root": self.witness_root,
            "signer_commitment": self.signer_commitment,
            "pq_signature_root": self.pq_signature_root,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeWitnessSubsidy {
    pub subsidy_id: String,
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub max_fee_units: u64,
    pub rebate_bps: u64,
    pub spent_fee_units: u64,
}

impl LowFeeWitnessSubsidy {
    pub fn devnet(
        policy: &AvailabilityInsurancePolicy,
        sponsor_label: &str,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> Self {
        let sponsor_commitment = psai_string_root("WITNESS-SPONSOR", sponsor_label);
        Self {
            subsidy_id: psai_hash(
                "LOW-FEE-WITNESS-SUBSIDY-ID",
                &[
                    HashPart::Str(&policy.policy_id),
                    HashPart::Str(&sponsor_commitment),
                ],
            ),
            policy_id: policy.policy_id.clone(),
            sponsor_commitment,
            max_fee_units: 12,
            rebate_bps: config.low_fee_rebate_bps,
            spent_fee_units: 3,
        }
    }

    pub fn validate(
        &self,
        policies: &BTreeMap<String, AvailabilityInsurancePolicy>,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("subsidy id", &self.subsidy_id)?;
        ensure_nonempty("policy id", &self.policy_id)?;
        ensure_nonempty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_positive("max fee units", self.max_fee_units)?;
        ensure_bps("rebate bps", self.rebate_bps)?;
        if self.rebate_bps > config.low_fee_rebate_bps {
            return Err(format!("subsidy {} exceeds rebate cap", self.subsidy_id));
        }
        if self.spent_fee_units > self.max_fee_units {
            return Err(format!("subsidy {} overspent", self.subsidy_id));
        }
        if !policies.contains_key(&self.policy_id) {
            return Err(format!(
                "subsidy {} references missing policy",
                self.subsidy_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "subsidy_id": self.subsidy_id,
            "policy_id": self.policy_id,
            "sponsor_commitment": self.sponsor_commitment,
            "max_fee_units": self.max_fee_units,
            "rebate_bps": self.rebate_bps,
            "spent_fee_units": self.spent_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub claimant_commitment: String,
    pub missing_witness_root: String,
    pub evidence_root: String,
    pub requested_payout_units: u64,
    pub opened_height: u64,
    pub payable_height: u64,
    pub expires_height: u64,
    pub status: AvailabilityClaimStatus,
}

impl AvailabilityClaim {
    pub fn devnet(
        policy: &AvailabilityInsurancePolicy,
        claimant_label: &str,
        height: u64,
        config: &PrivateStateAvailabilityInsuranceConfig,
    ) -> Self {
        let claimant_commitment = psai_string_root("CLAIMANT", claimant_label);
        let missing_witness_root = psai_string_root("MISSING-WITNESS", &policy.policy_id);
        let evidence_root = psai_hash(
            "CLAIM-EVIDENCE",
            &[
                HashPart::Str(&policy.policy_id),
                HashPart::Str(&missing_witness_root),
                HashPart::Int(height as i128),
            ],
        );
        Self {
            claim_id: psai_hash(
                "CLAIM-ID",
                &[
                    HashPart::Str(&policy.policy_id),
                    HashPart::Str(&claimant_commitment),
                    HashPart::Int(height as i128),
                ],
            ),
            policy_id: policy.policy_id.clone(),
            claimant_commitment,
            missing_witness_root,
            evidence_root,
            requested_payout_units: policy.coverage_units.saturating_mul(policy.payout_bps)
                / PRIVATE_STATE_AVAILABILITY_INSURANCE_MAX_BPS,
            opened_height: height,
            payable_height: height.saturating_add(config.payout_delay_blocks),
            expires_height: height.saturating_add(config.claim_window_blocks),
            status: AvailabilityClaimStatus::Approved,
        }
    }

    pub fn validate(
        &self,
        policies: &BTreeMap<String, AvailabilityInsurancePolicy>,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("claim id", &self.claim_id)?;
        ensure_nonempty("policy id", &self.policy_id)?;
        ensure_nonempty("claimant commitment", &self.claimant_commitment)?;
        ensure_nonempty("missing witness root", &self.missing_witness_root)?;
        ensure_nonempty("evidence root", &self.evidence_root)?;
        ensure_positive("requested payout units", self.requested_payout_units)?;
        if self.payable_height < self.opened_height || self.expires_height <= self.opened_height {
            return Err(format!("claim {} has invalid timing", self.claim_id));
        }
        if !policies.contains_key(&self.policy_id) {
            return Err(format!("claim {} references missing policy", self.claim_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "claimant_commitment": self.claimant_commitment,
            "missing_witness_root": self.missing_witness_root,
            "evidence_root": self.evidence_root,
            "requested_payout_units": self.requested_payout_units,
            "opened_height": self.opened_height,
            "payable_height": self.payable_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityPayout {
    pub payout_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub vault_id: String,
    pub payout_commitment: String,
    pub payout_units: u64,
    pub paid_height: u64,
}

impl AvailabilityPayout {
    pub fn devnet(
        claim: &AvailabilityClaim,
        policy: &AvailabilityInsurancePolicy,
        height: u64,
    ) -> Self {
        let payout_commitment = psai_string_root("PAYOUT", &claim.claim_id);
        Self {
            payout_id: psai_hash(
                "PAYOUT-ID",
                &[
                    HashPart::Str(&claim.claim_id),
                    HashPart::Str(&payout_commitment),
                    HashPart::Int(height as i128),
                ],
            ),
            claim_id: claim.claim_id.clone(),
            policy_id: claim.policy_id.clone(),
            vault_id: policy.vault_id.clone(),
            payout_commitment,
            payout_units: claim.requested_payout_units,
            paid_height: height,
        }
    }

    pub fn validate(
        &self,
        claims: &BTreeMap<String, AvailabilityClaim>,
        policies: &BTreeMap<String, AvailabilityInsurancePolicy>,
        vaults: &BTreeMap<String, UnderwriterVault>,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("payout id", &self.payout_id)?;
        ensure_nonempty("claim id", &self.claim_id)?;
        ensure_nonempty("policy id", &self.policy_id)?;
        ensure_nonempty("vault id", &self.vault_id)?;
        ensure_nonempty("payout commitment", &self.payout_commitment)?;
        ensure_positive("payout units", self.payout_units)?;
        if !claims.contains_key(&self.claim_id) {
            return Err(format!(
                "payout {} references missing claim",
                self.payout_id
            ));
        }
        if !policies.contains_key(&self.policy_id) {
            return Err(format!(
                "payout {} references missing policy",
                self.payout_id
            ));
        }
        if !vaults.contains_key(&self.vault_id) {
            return Err(format!(
                "payout {} references missing vault",
                self.payout_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "payout_id": self.payout_id,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "vault_id": self.vault_id,
            "payout_commitment": self.payout_commitment,
            "payout_units": self.payout_units,
            "paid_height": self.paid_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityChallenge {
    pub challenge_id: String,
    pub target_id: String,
    pub challenge_kind: AvailabilityChallengeKind,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub resolved_height: Option<u64>,
    pub upheld: bool,
}

impl AvailabilityChallenge {
    pub fn devnet(target_id: &str, kind: AvailabilityChallengeKind, height: u64) -> Self {
        let challenger_commitment = psai_string_root("AVAILABILITY-CHALLENGER", target_id);
        let evidence_root = psai_hash(
            "AVAILABILITY-CHALLENGE-EVIDENCE",
            &[
                HashPart::Str(target_id),
                HashPart::Str(kind.as_str()),
                HashPart::Int(height as i128),
            ],
        );
        Self {
            challenge_id: psai_hash(
                "AVAILABILITY-CHALLENGE-ID",
                &[
                    HashPart::Str(target_id),
                    HashPart::Str(kind.as_str()),
                    HashPart::Int(height as i128),
                ],
            ),
            target_id: target_id.to_string(),
            challenge_kind: kind,
            challenger_commitment,
            evidence_root,
            opened_height: height,
            resolved_height: None,
            upheld: false,
        }
    }

    pub fn validate(&self) -> PrivateStateAvailabilityInsuranceResult<()> {
        ensure_nonempty("challenge id", &self.challenge_id)?;
        ensure_nonempty("target id", &self.target_id)?;
        ensure_nonempty("challenger commitment", &self.challenger_commitment)?;
        ensure_nonempty("evidence root", &self.evidence_root)?;
        if let Some(resolved_height) = self.resolved_height {
            if resolved_height < self.opened_height {
                return Err(format!(
                    "challenge {} resolves before opening",
                    self.challenge_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "target_id": self.target_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "resolved_height": self.resolved_height,
            "upheld": self.upheld,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateAvailabilityInsuranceRoots {
    pub config_root: String,
    pub lane_root: String,
    pub vault_root: String,
    pub shard_root: String,
    pub policy_root: String,
    pub attestation_root: String,
    pub subsidy_root: String,
    pub claim_root: String,
    pub payout_root: String,
    pub challenge_root: String,
}

impl PrivateStateAvailabilityInsuranceRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "vault_root": self.vault_root,
            "shard_root": self.shard_root,
            "policy_root": self.policy_root,
            "attestation_root": self.attestation_root,
            "subsidy_root": self.subsidy_root,
            "claim_root": self.claim_root,
            "payout_root": self.payout_root,
            "challenge_root": self.challenge_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateAvailabilityInsuranceCounters {
    pub lane_count: u64,
    pub vault_count: u64,
    pub active_vault_count: u64,
    pub shard_count: u64,
    pub policy_count: u64,
    pub live_policy_count: u64,
    pub attestation_count: u64,
    pub subsidy_count: u64,
    pub claim_count: u64,
    pub live_claim_count: u64,
    pub payout_count: u64,
    pub challenge_count: u64,
    pub total_bond_units: u64,
    pub total_payout_units: u64,
}

impl PrivateStateAvailabilityInsuranceCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "vault_count": self.vault_count,
            "active_vault_count": self.active_vault_count,
            "shard_count": self.shard_count,
            "policy_count": self.policy_count,
            "live_policy_count": self.live_policy_count,
            "attestation_count": self.attestation_count,
            "subsidy_count": self.subsidy_count,
            "claim_count": self.claim_count,
            "live_claim_count": self.live_claim_count,
            "payout_count": self.payout_count,
            "challenge_count": self.challenge_count,
            "total_bond_units": self.total_bond_units,
            "total_payout_units": self.total_payout_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateAvailabilityInsuranceState {
    pub config: PrivateStateAvailabilityInsuranceConfig,
    pub current_height: u64,
    pub current_epoch: u64,
    pub lanes: BTreeMap<String, AvailabilityInsuranceLane>,
    pub vaults: BTreeMap<String, UnderwriterVault>,
    pub shards: BTreeMap<String, InsuredStateShard>,
    pub policies: BTreeMap<String, AvailabilityInsurancePolicy>,
    pub attestations: BTreeMap<String, PqAvailabilityAttestation>,
    pub subsidies: BTreeMap<String, LowFeeWitnessSubsidy>,
    pub claims: BTreeMap<String, AvailabilityClaim>,
    pub payouts: BTreeMap<String, AvailabilityPayout>,
    pub challenges: BTreeMap<String, AvailabilityChallenge>,
}

impl PrivateStateAvailabilityInsuranceState {
    pub fn devnet() -> PrivateStateAvailabilityInsuranceResult<Self> {
        let config = PrivateStateAvailabilityInsuranceConfig::devnet();
        let current_height = PRIVATE_STATE_AVAILABILITY_INSURANCE_DEVNET_HEIGHT;
        let current_epoch = current_height / config.epoch_blocks;
        let mut state = Self {
            config,
            current_height,
            current_epoch,
            lanes: BTreeMap::new(),
            vaults: BTreeMap::new(),
            shards: BTreeMap::new(),
            policies: BTreeMap::new(),
            attestations: BTreeMap::new(),
            subsidies: BTreeMap::new(),
            claims: BTreeMap::new(),
            payouts: BTreeMap::new(),
            challenges: BTreeMap::new(),
        };
        for lane_kind in [
            AvailabilityLaneKind::ContractState,
            AvailabilityLaneKind::DefiVault,
            AvailabilityLaneKind::TokenRegistry,
            AvailabilityLaneKind::BridgeExit,
            AvailabilityLaneKind::WalletRecovery,
            AvailabilityLaneKind::FraudProof,
        ] {
            state.insert_lane(AvailabilityInsuranceLane::devnet(lane_kind, &state.config))?;
        }
        let lane_ids = state.lanes.keys().cloned().collect::<Vec<_>>();
        let vault =
            UnderwriterVault::devnet("underwriter:availability:devnet", &lane_ids, &state.config);
        state.insert_vault(vault.clone())?;
        let lane = state
            .lanes
            .values()
            .find(|lane| lane.lane_kind == AvailabilityLaneKind::ContractState)
            .cloned()
            .ok_or_else(|| "missing devnet availability lane".to_string())?;
        let shard =
            InsuredStateShard::devnet(&lane, "contract-state:shielded-vault", current_height);
        state.insert_shard(shard.clone())?;
        let policy =
            AvailabilityInsurancePolicy::devnet(&shard, &vault, current_height, &state.config);
        state.insert_policy(policy.clone())?;
        let attestation = PqAvailabilityAttestation::devnet(
            &policy,
            &shard,
            "watcher:availability:devnet",
            current_height.saturating_add(1),
            &state.config,
        );
        state.insert_attestation(attestation)?;
        state.insert_subsidy(LowFeeWitnessSubsidy::devnet(
            &policy,
            "sponsor:availability:devnet",
            &state.config,
        ))?;
        let claim = AvailabilityClaim::devnet(
            &policy,
            "claimant:private-contract:devnet",
            current_height.saturating_add(4),
            &state.config,
        );
        state.insert_claim(claim.clone())?;
        state.insert_payout(AvailabilityPayout::devnet(
            &claim,
            &policy,
            claim.payable_height,
        ))?;
        state.insert_challenge(AvailabilityChallenge::devnet(
            &claim.claim_id,
            AvailabilityChallengeKind::MissingWitness,
            current_height.saturating_add(5),
        ))?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateStateAvailabilityInsuranceResult<()> {
        if height < self.current_height {
            return Err(format!(
                "private state availability insurance height cannot move backward from {} to {}",
                self.current_height, height
            ));
        }
        self.current_height = height;
        if self.config.epoch_blocks > 0 {
            self.current_epoch = height / self.config.epoch_blocks;
        }
        for policy in self.policies.values_mut() {
            if policy.status.live() && height > policy.expires_height {
                policy.status = AvailabilityPolicyStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            if matches!(
                attestation.status,
                WitnessAttestationStatus::Submitted | WitnessAttestationStatus::Counted
            ) && height > attestation.expires_height
            {
                attestation.status = WitnessAttestationStatus::Expired;
            }
        }
        for claim in self.claims.values_mut() {
            if claim.status.live() && height > claim.expires_height {
                claim.status = AvailabilityClaimStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_lane(
        &mut self,
        lane: AvailabilityInsuranceLane,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        lane.validate(&self.config)?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_vault(
        &mut self,
        vault: UnderwriterVault,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        vault.validate(&self.lanes, &self.config)?;
        self.vaults.insert(vault.vault_id.clone(), vault);
        Ok(())
    }

    pub fn insert_shard(
        &mut self,
        shard: InsuredStateShard,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        shard.validate(&self.lanes, &self.config)?;
        self.shards.insert(shard.shard_id.clone(), shard);
        Ok(())
    }

    pub fn insert_policy(
        &mut self,
        policy: AvailabilityInsurancePolicy,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        policy.validate(&self.shards, &self.vaults, &self.config)?;
        self.policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqAvailabilityAttestation,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        attestation.validate(&self.policies, &self.shards)?;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_subsidy(
        &mut self,
        subsidy: LowFeeWitnessSubsidy,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        subsidy.validate(&self.policies, &self.config)?;
        self.subsidies.insert(subsidy.subsidy_id.clone(), subsidy);
        Ok(())
    }

    pub fn insert_claim(
        &mut self,
        claim: AvailabilityClaim,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        claim.validate(&self.policies)?;
        self.claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    pub fn insert_payout(
        &mut self,
        payout: AvailabilityPayout,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        payout.validate(&self.claims, &self.policies, &self.vaults)?;
        self.payouts.insert(payout.payout_id.clone(), payout);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: AvailabilityChallenge,
    ) -> PrivateStateAvailabilityInsuranceResult<()> {
        challenge.validate()?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn live_policy_ids(&self) -> Vec<String> {
        self.policies
            .values()
            .filter(|policy| policy.status.live())
            .map(|policy| policy.policy_id.clone())
            .collect()
    }

    pub fn active_vault_ids(&self) -> Vec<String> {
        self.vaults
            .values()
            .filter(|vault| vault.active)
            .map(|vault| vault.vault_id.clone())
            .collect()
    }

    pub fn roots(&self) -> PrivateStateAvailabilityInsuranceRoots {
        PrivateStateAvailabilityInsuranceRoots {
            config_root: psai_payload_root("CONFIG", &self.config.public_record()),
            lane_root: map_root(
                "LANES",
                &self.lanes,
                AvailabilityInsuranceLane::public_record,
            ),
            vault_root: map_root("VAULTS", &self.vaults, UnderwriterVault::public_record),
            shard_root: map_root("SHARDS", &self.shards, InsuredStateShard::public_record),
            policy_root: map_root(
                "POLICIES",
                &self.policies,
                AvailabilityInsurancePolicy::public_record,
            ),
            attestation_root: map_root(
                "ATTESTATIONS",
                &self.attestations,
                PqAvailabilityAttestation::public_record,
            ),
            subsidy_root: map_root(
                "SUBSIDIES",
                &self.subsidies,
                LowFeeWitnessSubsidy::public_record,
            ),
            claim_root: map_root("CLAIMS", &self.claims, AvailabilityClaim::public_record),
            payout_root: map_root("PAYOUTS", &self.payouts, AvailabilityPayout::public_record),
            challenge_root: map_root(
                "CHALLENGES",
                &self.challenges,
                AvailabilityChallenge::public_record,
            ),
        }
    }

    pub fn counters(&self) -> PrivateStateAvailabilityInsuranceCounters {
        PrivateStateAvailabilityInsuranceCounters {
            lane_count: self.lanes.len() as u64,
            vault_count: self.vaults.len() as u64,
            active_vault_count: self.vaults.values().filter(|vault| vault.active).count() as u64,
            shard_count: self.shards.len() as u64,
            policy_count: self.policies.len() as u64,
            live_policy_count: self
                .policies
                .values()
                .filter(|policy| policy.status.live())
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            subsidy_count: self.subsidies.len() as u64,
            claim_count: self.claims.len() as u64,
            live_claim_count: self
                .claims
                .values()
                .filter(|claim| claim.status.live())
                .count() as u64,
            payout_count: self.payouts.len() as u64,
            challenge_count: self.challenges.len() as u64,
            total_bond_units: self.vaults.values().map(|vault| vault.bond_units).sum(),
            total_payout_units: self
                .payouts
                .values()
                .map(|payout| payout.payout_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_state_availability_insurance_state",
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_state_availability_insurance_state_root_from_record(&json!({
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        }))
    }

    pub fn validate(&self) -> PrivateStateAvailabilityInsuranceResult<()> {
        self.config.validate()?;
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for vault in self.vaults.values() {
            vault.validate(&self.lanes, &self.config)?;
        }
        for shard in self.shards.values() {
            shard.validate(&self.lanes, &self.config)?;
        }
        for policy in self.policies.values() {
            policy.validate(&self.shards, &self.vaults, &self.config)?;
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.policies, &self.shards)?;
        }
        for subsidy in self.subsidies.values() {
            subsidy.validate(&self.policies, &self.config)?;
        }
        for claim in self.claims.values() {
            claim.validate(&self.policies)?;
        }
        for payout in self.payouts.values() {
            payout.validate(&self.claims, &self.policies, &self.vaults)?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(())
    }
}

pub fn private_state_availability_insurance_state_root_from_record(record: &Value) -> String {
    psai_payload_root("STATE", record)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| json!({"id": id, "record": record(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-STATE-AVAILABILITY-INSURANCE-{domain}"),
        &leaves,
    )
}

fn psai_payload_root(domain: &str, payload: &Value) -> String {
    psai_hash(domain, &[HashPart::Json(payload)])
}

fn psai_string_root(domain: &str, value: &str) -> String {
    psai_hash(domain, &[HashPart::Str(value)])
}

fn psai_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-STATE-AVAILABILITY-INSURANCE-{domain}"),
        parts,
        32,
    )
}

fn ensure_nonempty(label: &str, value: &str) -> PrivateStateAvailabilityInsuranceResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PrivateStateAvailabilityInsuranceResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PrivateStateAvailabilityInsuranceResult<()> {
    if value > PRIVATE_STATE_AVAILABILITY_INSURANCE_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}
