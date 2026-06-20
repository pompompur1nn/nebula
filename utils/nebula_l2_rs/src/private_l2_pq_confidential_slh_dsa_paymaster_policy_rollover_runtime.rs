use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSlhDsaPaymasterPolicyRolloverRuntimeResult<T> = Result<T>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-slh-dsa-paymaster-policy-rollover-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PQ_AUTH_SUITE: &str =
    "SLH-DSA-SHAKE-256f+ML-DSA-87+ML-KEM-1024-paymaster-policy-rollover-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT: u64 =
    912_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_MAX_BPS: u64 =
    10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    usize = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    usize = 1_024;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_SPONSOR_MARGIN_BPS:
    u64 = 35;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_POLICY_EPOCH_BLOCKS:
    u64 = 7_200;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_ROLLOVER_GRACE_BLOCKS:
    u64 = 360;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS:
    u64 = 180;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_EPOCHS:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_CERTIFICATES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_VAULTS:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_INTENTS:
    usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_LEDGER_ENTRIES:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEpochStatus {
    Draft,
    PendingActivation,
    Active,
    Grace,
    Retired,
    Paused,
    Slashed,
}

impl PolicyEpochStatus {
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PendingActivation => "pending_activation",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Retired => "retired",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloverCertificateStatus {
    Proposed,
    QuorumCollected,
    Anchored,
    Activated,
    Superseded,
    Rejected,
    Expired,
}

impl RolloverCertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuorumCollected => "quorum_collected",
            Self::Anchored => "anchored",
            Self::Activated => "activated",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorVaultStatus {
    Open,
    Funding,
    Active,
    Throttled,
    Draining,
    Frozen,
    Slashed,
    Closed,
}

impl SponsorVaultStatus {
    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Funding => "funding",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Draining => "draining",
            Self::Frozen => "frozen",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateIntentStatus {
    Committed,
    Allowlisted,
    Sponsored,
    Settled,
    Expired,
    Rejected,
    Nullified,
}

impl PrivateIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Allowlisted => "allowlisted",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Nullified => "nullified",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCreditKind {
    Deposit,
    Reservation,
    Spend,
    Rebate,
    Slash,
    Refund,
    RolloverCarry,
}

impl FeeCreditKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Reservation => "reservation",
            Self::Spend => "spend",
            Self::Rebate => "rebate",
            Self::Slash => "slash",
            Self::Refund => "refund",
            Self::RolloverCarry => "rollover_carry",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationVerdict {
    Accept,
    Watch,
    Throttle,
    Pause,
    Slash,
}

impl PqAttestationVerdict {
    pub fn permits_activation(self) -> bool {
        matches!(self, Self::Accept | Self::Watch)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Watch => "watch",
            Self::Throttle => "throttle",
            Self::Pause => "pause",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSummaryKind {
    EpochOpened,
    CertificateAnchored,
    PolicyActivated,
    SponsorReserved,
    IntentSettled,
    FeeRebated,
    GuardTripped,
}

impl OperatorSummaryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EpochOpened => "epoch_opened",
            Self::CertificateAnchored => "certificate_anchored",
            Self::PolicyActivated => "policy_activated",
            Self::SponsorReserved => "sponsor_reserved",
            Self::IntentSettled => "intent_settled",
            Self::FeeRebated => "fee_rebated",
            Self::GuardTripped => "guard_tripped",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub max_user_fee_bps: u64,
    pub sponsor_margin_bps: u64,
    pub policy_epoch_blocks: u64,
    pub rollover_grace_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub max_epochs: usize,
    pub max_certificates: usize,
    pub max_sponsor_vaults: usize,
    pub max_private_intents: usize,
    pub max_fee_credit_entries: usize,
    pub max_pq_attestations: usize,
    pub confidential_policy_updates: bool,
    pub account_abstraction_required: bool,
    pub low_fee_mode: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_HASH_SUITE
                    .to_string(),
            pq_auth_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PQ_AUTH_SUITE
                    .to_string(),
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            sponsor_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_SPONSOR_MARGIN_BPS,
            policy_epoch_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_POLICY_EPOCH_BLOCKS,
            rollover_grace_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_ROLLOVER_GRACE_BLOCKS,
            intent_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            max_epochs:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_EPOCHS,
            max_certificates:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_CERTIFICATES,
            max_sponsor_vaults:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_VAULTS,
            max_private_intents:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_INTENTS,
            max_fee_credit_entries:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_LEDGER_ENTRIES,
            max_pq_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            confidential_policy_updates: true,
            account_abstraction_required: true,
            low_fee_mode: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_at_most_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_at_most_bps("sponsor_margin_bps", self.sponsor_margin_bps)?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        require_positive_u64("policy_epoch_blocks", self.policy_epoch_blocks)?;
        require_positive_u64("rollover_grace_blocks", self.rollover_grace_blocks)?;
        require_positive_u64("intent_ttl_blocks", self.intent_ttl_blocks)?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must be at least 192".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        if !self.confidential_policy_updates {
            return Err("confidential_policy_updates must remain enabled".to_string());
        }
        if !self.account_abstraction_required {
            return Err("account_abstraction_required must remain enabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_margin_bps": self.sponsor_margin_bps,
            "policy_epoch_blocks": self.policy_epoch_blocks,
            "rollover_grace_blocks": self.rollover_grace_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "max_epochs": self.max_epochs,
            "max_certificates": self.max_certificates,
            "max_sponsor_vaults": self.max_sponsor_vaults,
            "max_private_intents": self.max_private_intents,
            "max_fee_credit_entries": self.max_fee_credit_entries,
            "max_pq_attestations": self.max_pq_attestations,
            "confidential_policy_updates": self.confidential_policy_updates,
            "account_abstraction_required": self.account_abstraction_required,
            "low_fee_mode": self.low_fee_mode,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policy_epochs_opened: u64,
    pub rollover_certificates_issued: u64,
    pub sponsor_vaults_opened: u64,
    pub private_intents_committed: u64,
    pub private_intents_sponsored: u64,
    pub replay_nullifiers_consumed: u64,
    pub fee_credit_entries_posted: u64,
    pub pq_attestations_recorded: u64,
    pub operator_summaries_published: u64,
    pub total_fee_credits_reserved: u128,
    pub total_fee_credits_spent: u128,
    pub total_fee_credits_rebated: u128,
    pub total_fee_credits_slashed: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_epochs_opened": self.policy_epochs_opened,
            "rollover_certificates_issued": self.rollover_certificates_issued,
            "sponsor_vaults_opened": self.sponsor_vaults_opened,
            "private_intents_committed": self.private_intents_committed,
            "private_intents_sponsored": self.private_intents_sponsored,
            "replay_nullifiers_consumed": self.replay_nullifiers_consumed,
            "fee_credit_entries_posted": self.fee_credit_entries_posted,
            "pq_attestations_recorded": self.pq_attestations_recorded,
            "operator_summaries_published": self.operator_summaries_published,
            "total_fee_credits_reserved": self.total_fee_credits_reserved.to_string(),
            "total_fee_credits_spent": self.total_fee_credits_spent.to_string(),
            "total_fee_credits_rebated": self.total_fee_credits_rebated.to_string(),
            "total_fee_credits_slashed": self.total_fee_credits_slashed.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub policy_epoch_root: String,
    pub rollover_certificate_root: String,
    pub sponsor_vault_root: String,
    pub private_intent_root: String,
    pub replay_guard_root: String,
    pub fee_credit_ledger_root: String,
    pub pq_attestation_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn without_state_root(&self) -> Value {
        json!({
            "policy_epoch_root": self.policy_epoch_root,
            "rollover_certificate_root": self.rollover_certificate_root,
            "sponsor_vault_root": self.sponsor_vault_root,
            "private_intent_root": self.private_intent_root,
            "replay_guard_root": self.replay_guard_root,
            "fee_credit_ledger_root": self.fee_credit_ledger_root,
            "pq_attestation_root": self.pq_attestation_root,
            "operator_summary_root": self.operator_summary_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorVaultConstraints {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub status: SponsorVaultStatus,
    pub max_epoch_spend: u128,
    pub max_intent_spend: u128,
    pub reserved_credits: u128,
    pub spent_credits: u128,
    pub rebate_floor_bps: u64,
    pub user_fee_cap_bps: u64,
    pub allowed_policy_root: String,
    pub aa_entrypoint_root: String,
    pub vault_nullifier_root: String,
    pub opened_at_height: u64,
}

impl SponsorVaultConstraints {
    pub fn remaining_epoch_capacity(&self) -> u128 {
        self.max_epoch_spend
            .saturating_sub(self.reserved_credits + self.spent_credits)
    }

    pub fn can_reserve(&self, amount: u128) -> bool {
        self.status.can_reserve()
            && amount > 0
            && amount <= self.max_intent_spend
            && amount <= self.remaining_epoch_capacity()
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_root("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_at_most_bps("rebate_floor_bps", self.rebate_floor_bps)?;
        require_at_most_bps("user_fee_cap_bps", self.user_fee_cap_bps)?;
        require_root("allowed_policy_root", &self.allowed_policy_root)?;
        require_root("aa_entrypoint_root", &self.aa_entrypoint_root)?;
        require_root("vault_nullifier_root", &self.vault_nullifier_root)?;
        if self.max_intent_spend == 0 || self.max_epoch_spend == 0 {
            return Err("sponsor vault spend limits must be positive".to_string());
        }
        if self.max_intent_spend > self.max_epoch_spend {
            return Err("max_intent_spend cannot exceed max_epoch_spend".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "status": self.status,
            "max_epoch_spend": self.max_epoch_spend.to_string(),
            "max_intent_spend": self.max_intent_spend.to_string(),
            "reserved_credits": self.reserved_credits.to_string(),
            "spent_credits": self.spent_credits.to_string(),
            "rebate_floor_bps": self.rebate_floor_bps,
            "user_fee_cap_bps": self.user_fee_cap_bps,
            "allowed_policy_root": self.allowed_policy_root,
            "aa_entrypoint_root": self.aa_entrypoint_root,
            "vault_nullifier_root": self.vault_nullifier_root,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymasterPolicyEpoch {
    pub epoch_id: String,
    pub previous_epoch_id: Option<String>,
    pub sponsor_vault_id: String,
    pub status: PolicyEpochStatus,
    pub epoch_index: u64,
    pub activation_height: u64,
    pub expiry_height: u64,
    pub grace_expiry_height: u64,
    pub policy_commitment_root: String,
    pub private_allowlist_root: String,
    pub account_abstraction_rule_root: String,
    pub sponsor_constraint_root: String,
    pub low_fee_schedule_root: String,
    pub slh_dsa_public_key_root: String,
    pub pq_committee_root: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: usize,
}

impl PaymasterPolicyEpoch {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("epoch_id", &self.epoch_id)?;
        require_non_empty("sponsor_vault_id", &self.sponsor_vault_id)?;
        require_root("policy_commitment_root", &self.policy_commitment_root)?;
        require_root("private_allowlist_root", &self.private_allowlist_root)?;
        require_root(
            "account_abstraction_rule_root",
            &self.account_abstraction_rule_root,
        )?;
        require_root("sponsor_constraint_root", &self.sponsor_constraint_root)?;
        require_root("low_fee_schedule_root", &self.low_fee_schedule_root)?;
        require_root("slh_dsa_public_key_root", &self.slh_dsa_public_key_root)?;
        require_root("pq_committee_root", &self.pq_committee_root)?;
        require_at_most_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("epoch max_user_fee_bps exceeds runtime fee cap".to_string());
        }
        if self.expiry_height <= self.activation_height {
            return Err("expiry_height must be greater than activation_height".to_string());
        }
        if self.grace_expiry_height < self.expiry_height {
            return Err("grace_expiry_height cannot be below expiry_height".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("epoch privacy set is below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn accepts_height(&self, height: u64) -> bool {
        self.status.accepts_intents()
            && height >= self.activation_height
            && height <= self.grace_expiry_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "previous_epoch_id": self.previous_epoch_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "status": self.status,
            "epoch_index": self.epoch_index,
            "activation_height": self.activation_height,
            "expiry_height": self.expiry_height,
            "grace_expiry_height": self.grace_expiry_height,
            "policy_commitment_root": self.policy_commitment_root,
            "private_allowlist_root": self.private_allowlist_root,
            "account_abstraction_rule_root": self.account_abstraction_rule_root,
            "sponsor_constraint_root": self.sponsor_constraint_root,
            "low_fee_schedule_root": self.low_fee_schedule_root,
            "slh_dsa_public_key_root": self.slh_dsa_public_key_root,
            "pq_committee_root": self.pq_committee_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlhDsaRolloverCertificate {
    pub certificate_id: String,
    pub previous_epoch_id: String,
    pub next_epoch_id: String,
    pub status: RolloverCertificateStatus,
    pub slh_dsa_signature_root: String,
    pub ml_dsa_cosignature_root: String,
    pub signer_committee_root: String,
    pub transcript_root: String,
    pub nullifier_root: String,
    pub policy_delta_root: String,
    pub aggregate_weight: u64,
    pub threshold_weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SlhDsaRolloverCertificate {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("certificate_id", &self.certificate_id)?;
        require_non_empty("previous_epoch_id", &self.previous_epoch_id)?;
        require_non_empty("next_epoch_id", &self.next_epoch_id)?;
        require_root("slh_dsa_signature_root", &self.slh_dsa_signature_root)?;
        require_root("ml_dsa_cosignature_root", &self.ml_dsa_cosignature_root)?;
        require_root("signer_committee_root", &self.signer_committee_root)?;
        require_root("transcript_root", &self.transcript_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("policy_delta_root", &self.policy_delta_root)?;
        if self.aggregate_weight < self.threshold_weight || self.threshold_weight == 0 {
            return Err("rollover certificate quorum weight is insufficient".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("certificate expires_at_height must exceed issued_at_height".to_string());
        }
        Ok(())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            RolloverCertificateStatus::QuorumCollected
                | RolloverCertificateStatus::Anchored
                | RolloverCertificateStatus::Activated
        ) && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "previous_epoch_id": self.previous_epoch_id,
            "next_epoch_id": self.next_epoch_id,
            "status": self.status,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "ml_dsa_cosignature_root": self.ml_dsa_cosignature_root,
            "signer_committee_root": self.signer_committee_root,
            "transcript_root": self.transcript_root,
            "nullifier_root": self.nullifier_root,
            "policy_delta_root": self.policy_delta_root,
            "aggregate_weight": self.aggregate_weight,
            "threshold_weight": self.threshold_weight,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateIntentAllowlistEntry {
    pub intent_id: String,
    pub epoch_id: String,
    pub sponsor_vault_id: String,
    pub status: PrivateIntentStatus,
    pub account_commitment: String,
    pub intent_commitment_root: String,
    pub aa_call_root: String,
    pub fee_asset_id: String,
    pub max_fee_credit: u128,
    pub user_fee_bps: u64,
    pub privacy_bucket_root: String,
    pub allowlist_witness_root: String,
    pub replay_nullifier: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateIntentAllowlistEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("epoch_id", &self.epoch_id)?;
        require_non_empty("sponsor_vault_id", &self.sponsor_vault_id)?;
        require_root("account_commitment", &self.account_commitment)?;
        require_root("intent_commitment_root", &self.intent_commitment_root)?;
        require_root("aa_call_root", &self.aa_call_root)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_root("privacy_bucket_root", &self.privacy_bucket_root)?;
        require_root("allowlist_witness_root", &self.allowlist_witness_root)?;
        require_root("replay_nullifier", &self.replay_nullifier)?;
        require_at_most_bps("user_fee_bps", self.user_fee_bps)?;
        if self.user_fee_bps > config.max_user_fee_bps {
            return Err("intent user_fee_bps exceeds runtime fee cap".to_string());
        }
        if self.max_fee_credit == 0 {
            return Err("max_fee_credit must be positive".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("intent expires_at_height must exceed submitted_at_height".to_string());
        }
        Ok(())
    }

    pub fn live_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            PrivateIntentStatus::Committed
                | PrivateIntentStatus::Allowlisted
                | PrivateIntentStatus::Sponsored
        ) && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "epoch_id": self.epoch_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "status": self.status,
            "account_commitment": self.account_commitment,
            "intent_commitment_root": self.intent_commitment_root,
            "aa_call_root": self.aa_call_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_credit": self.max_fee_credit.to_string(),
            "user_fee_bps": self.user_fee_bps,
            "privacy_bucket_root": self.privacy_bucket_root,
            "allowlist_witness_root": self.allowlist_witness_root,
            "replay_nullifier": self.replay_nullifier,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayGuardRecord {
    pub replay_nullifier: String,
    pub subject_id: String,
    pub epoch_id: String,
    pub consumed_at_height: u64,
    pub guard_root: String,
}

impl ReplayGuardRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_nullifier": self.replay_nullifier,
            "subject_id": self.subject_id,
            "epoch_id": self.epoch_id,
            "consumed_at_height": self.consumed_at_height,
            "guard_root": self.guard_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditLedgerEntry {
    pub entry_id: String,
    pub vault_id: String,
    pub intent_id: Option<String>,
    pub epoch_id: String,
    pub kind: FeeCreditKind,
    pub asset_id: String,
    pub amount: u128,
    pub balance_after: u128,
    pub fee_schedule_root: String,
    pub posted_at_height: u64,
}

impl FeeCreditLedgerEntry {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("entry_id", &self.entry_id)?;
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("epoch_id", &self.epoch_id)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_root("fee_schedule_root", &self.fee_schedule_root)?;
        if self.amount == 0 {
            return Err("fee credit ledger amount must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "vault_id": self.vault_id,
            "intent_id": self.intent_id,
            "epoch_id": self.epoch_id,
            "kind": self.kind,
            "asset_id": self.asset_id,
            "amount": self.amount.to_string(),
            "balance_after": self.balance_after.to_string(),
            "fee_schedule_root": self.fee_schedule_root,
            "posted_at_height": self.posted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub subject_id: String,
    pub epoch_id: String,
    pub attester_commitment: String,
    pub verdict: PqAttestationVerdict,
    pub slh_dsa_key_health_root: String,
    pub ml_dsa_backup_health_root: String,
    pub entropy_audit_root: String,
    pub side_channel_review_root: String,
    pub proof_transcript_root: String,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl PqAttestationRecord {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("epoch_id", &self.epoch_id)?;
        require_root("attester_commitment", &self.attester_commitment)?;
        require_root("slh_dsa_key_health_root", &self.slh_dsa_key_health_root)?;
        require_root("ml_dsa_backup_health_root", &self.ml_dsa_backup_health_root)?;
        require_root("entropy_audit_root", &self.entropy_audit_root)?;
        require_root("side_channel_review_root", &self.side_channel_review_root)?;
        require_root("proof_transcript_root", &self.proof_transcript_root)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq attestation security bits below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "epoch_id": self.epoch_id,
            "attester_commitment": self.attester_commitment,
            "verdict": self.verdict,
            "slh_dsa_key_health_root": self.slh_dsa_key_health_root,
            "ml_dsa_backup_health_root": self.ml_dsa_backup_health_root,
            "entropy_audit_root": self.entropy_audit_root,
            "side_channel_review_root": self.side_channel_review_root,
            "proof_transcript_root": self.proof_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub kind: OperatorSummaryKind,
    pub subject_id: String,
    pub epoch_id: String,
    pub operator_commitment: String,
    pub public_metric_root: String,
    pub private_witness_root: String,
    pub state_root_after: String,
    pub published_at_height: u64,
}

impl OperatorSummary {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("summary_id", &self.summary_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("epoch_id", &self.epoch_id)?;
        require_root("operator_commitment", &self.operator_commitment)?;
        require_root("public_metric_root", &self.public_metric_root)?;
        require_root("private_witness_root", &self.private_witness_root)?;
        require_root("state_root_after", &self.state_root_after)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "epoch_id": self.epoch_id,
            "operator_commitment": self.operator_commitment,
            "public_metric_root": self.public_metric_root,
            "private_witness_root": self.private_witness_root,
            "state_root_after": self.state_root_after,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPolicyEpochRequest {
    pub previous_epoch_id: Option<String>,
    pub sponsor_vault_id: String,
    pub activation_height: u64,
    pub policy_commitment_root: String,
    pub private_allowlist_root: String,
    pub account_abstraction_rule_root: String,
    pub sponsor_constraint_root: String,
    pub low_fee_schedule_root: String,
    pub slh_dsa_public_key_root: String,
    pub pq_committee_root: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: usize,
    pub epoch_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRolloverCertificateRequest {
    pub previous_epoch_id: String,
    pub next_epoch_id: String,
    pub slh_dsa_signature_root: String,
    pub ml_dsa_cosignature_root: String,
    pub signer_committee_root: String,
    pub transcript_root: String,
    pub nullifier_root: String,
    pub policy_delta_root: String,
    pub aggregate_weight: u64,
    pub threshold_weight: u64,
    pub issued_at_height: u64,
    pub certificate_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenSponsorVaultRequest {
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub max_epoch_spend: u128,
    pub max_intent_spend: u128,
    pub rebate_floor_bps: u64,
    pub user_fee_cap_bps: u64,
    pub allowed_policy_root: String,
    pub aa_entrypoint_root: String,
    pub vault_nullifier_root: String,
    pub opened_at_height: u64,
    pub vault_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitPrivateIntentRequest {
    pub epoch_id: String,
    pub sponsor_vault_id: String,
    pub account_commitment: String,
    pub intent_commitment_root: String,
    pub aa_call_root: String,
    pub fee_asset_id: String,
    pub max_fee_credit: u128,
    pub user_fee_bps: u64,
    pub privacy_bucket_root: String,
    pub allowlist_witness_root: String,
    pub replay_nullifier: String,
    pub submitted_at_height: u64,
    pub intent_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostFeeCreditRequest {
    pub vault_id: String,
    pub intent_id: Option<String>,
    pub epoch_id: String,
    pub kind: FeeCreditKind,
    pub asset_id: String,
    pub amount: u128,
    pub fee_schedule_root: String,
    pub posted_at_height: u64,
    pub ledger_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordPqAttestationRequest {
    pub subject_id: String,
    pub epoch_id: String,
    pub attester_commitment: String,
    pub verdict: PqAttestationVerdict,
    pub slh_dsa_key_health_root: String,
    pub ml_dsa_backup_health_root: String,
    pub entropy_audit_root: String,
    pub side_channel_review_root: String,
    pub proof_transcript_root: String,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishOperatorSummaryRequest {
    pub kind: OperatorSummaryKind,
    pub subject_id: String,
    pub epoch_id: String,
    pub operator_commitment: String,
    pub public_metric_root: String,
    pub private_witness_root: String,
    pub published_at_height: u64,
    pub summary_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub policy_epochs: BTreeMap<String, PaymasterPolicyEpoch>,
    pub rollover_certificates: BTreeMap<String, SlhDsaRolloverCertificate>,
    pub sponsor_vaults: BTreeMap<String, SponsorVaultConstraints>,
    pub private_intents: BTreeMap<String, PrivateIntentAllowlistEntry>,
    pub replay_guards: BTreeMap<String, ReplayGuardRecord>,
    pub fee_credit_ledger: BTreeMap<String, FeeCreditLedgerEntry>,
    pub pq_attestations: BTreeMap<String, PqAttestationRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            policy_epochs: BTreeMap::new(),
            rollover_certificates: BTreeMap::new(),
            sponsor_vaults: BTreeMap::new(),
            private_intents: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            fee_credit_ledger: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        let vault = state
            .open_sponsor_vault(OpenSponsorVaultRequest {
                sponsor_commitment: fixture_root("sponsor", 0),
                asset_id: "xmr-fee-credit".to_string(),
                max_epoch_spend: 25_000_000_000,
                max_intent_spend: 75_000_000,
                rebate_floor_bps: 8,
                user_fee_cap_bps: 12,
                allowed_policy_root: fixture_root("allowed-policy", 0),
                aa_entrypoint_root: fixture_root("aa-entrypoint", 0),
                vault_nullifier_root: fixture_root("vault-nullifiers", 0),
                opened_at_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT,
                vault_nonce: "devnet-vault-0".to_string(),
            })
            .expect("devnet vault opens");
        let epoch0 = state
            .open_policy_epoch(OpenPolicyEpochRequest {
                previous_epoch_id: None,
                sponsor_vault_id: vault.vault_id.clone(),
                activation_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT,
                policy_commitment_root: fixture_root("policy", 0),
                private_allowlist_root: fixture_root("allowlist", 0),
                account_abstraction_rule_root: fixture_root("aa-rules", 0),
                sponsor_constraint_root: fixture_root("constraints", 0),
                low_fee_schedule_root: fixture_root("low-fee", 0),
                slh_dsa_public_key_root: fixture_root("slh-dsa-keyset", 0),
                pq_committee_root: fixture_root("pq-committee", 0),
                max_user_fee_bps: 12,
                privacy_set_size: 1_024,
                epoch_nonce: "devnet-epoch-0".to_string(),
            })
            .expect("devnet epoch opens");
        let epoch1 = state
            .open_policy_epoch(OpenPolicyEpochRequest {
                previous_epoch_id: Some(epoch0.epoch_id.clone()),
                sponsor_vault_id: vault.vault_id.clone(),
                activation_height: epoch0.expiry_height + 1,
                policy_commitment_root: fixture_root("policy", 1),
                private_allowlist_root: fixture_root("allowlist", 1),
                account_abstraction_rule_root: fixture_root("aa-rules", 1),
                sponsor_constraint_root: fixture_root("constraints", 1),
                low_fee_schedule_root: fixture_root("low-fee", 1),
                slh_dsa_public_key_root: fixture_root("slh-dsa-keyset", 1),
                pq_committee_root: fixture_root("pq-committee", 1),
                max_user_fee_bps: 10,
                privacy_set_size: 2_048,
                epoch_nonce: "devnet-epoch-1".to_string(),
            })
            .expect("devnet next epoch opens");
        state
            .issue_rollover_certificate(IssueRolloverCertificateRequest {
                previous_epoch_id: epoch0.epoch_id.clone(),
                next_epoch_id: epoch1.epoch_id.clone(),
                slh_dsa_signature_root: fixture_root("slh-dsa-signatures", 0),
                ml_dsa_cosignature_root: fixture_root("ml-dsa-cosignatures", 0),
                signer_committee_root: fixture_root("signer-committee", 0),
                transcript_root: fixture_root("rollover-transcript", 0),
                nullifier_root: fixture_root("rollover-nullifiers", 0),
                policy_delta_root: fixture_root("policy-delta", 0),
                aggregate_weight: 83,
                threshold_weight: 67,
                issued_at_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
                        + 12,
                certificate_nonce: "devnet-certificate-0".to_string(),
            })
            .expect("devnet certificate issues");
        state
            .record_pq_attestation(RecordPqAttestationRequest {
                subject_id: epoch0.epoch_id.clone(),
                epoch_id: epoch0.epoch_id.clone(),
                attester_commitment: fixture_root("attester", 0),
                verdict: PqAttestationVerdict::Accept,
                slh_dsa_key_health_root: fixture_root("slh-health", 0),
                ml_dsa_backup_health_root: fixture_root("ml-dsa-health", 0),
                entropy_audit_root: fixture_root("entropy", 0),
                side_channel_review_root: fixture_root("side-channel", 0),
                proof_transcript_root: fixture_root("attestation-transcript", 0),
                pq_security_bits: 256,
                attested_at_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
                        + 14,
                attestation_nonce: "devnet-attestation-0".to_string(),
            })
            .expect("devnet pq attestation records");
        let intent = state
            .commit_private_intent(CommitPrivateIntentRequest {
                epoch_id: epoch0.epoch_id.clone(),
                sponsor_vault_id: vault.vault_id.clone(),
                account_commitment: fixture_root("account", 0),
                intent_commitment_root: fixture_root("intent", 0),
                aa_call_root: fixture_root("aa-call", 0),
                fee_asset_id: "xmr-fee-credit".to_string(),
                max_fee_credit: 9_500_000,
                user_fee_bps: 9,
                privacy_bucket_root: fixture_root("privacy-bucket", 0),
                allowlist_witness_root: fixture_root("allowlist-witness", 0),
                replay_nullifier: fixture_root("intent-nullifier", 0),
                submitted_at_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
                        + 18,
                intent_nonce: "devnet-intent-0".to_string(),
            })
            .expect("devnet private intent commits");
        state
            .sponsor_private_intent(&intent.intent_id)
            .expect("devnet intent sponsors");
        state
            .settle_private_intent(&intent.intent_id)
            .expect("devnet intent settles");
        state
            .publish_operator_summary(PublishOperatorSummaryRequest {
                kind: OperatorSummaryKind::PolicyActivated,
                subject_id: epoch0.epoch_id.clone(),
                epoch_id: epoch0.epoch_id.clone(),
                operator_commitment: fixture_root("operator", 0),
                public_metric_root: fixture_root("metrics", 0),
                private_witness_root: fixture_root("operator-witness", 0),
                published_at_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
                        + 24,
                summary_nonce: "devnet-summary-0".to_string(),
            })
            .expect("devnet operator summary publishes");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let vault = state
            .open_sponsor_vault(OpenSponsorVaultRequest {
                sponsor_commitment: fixture_root("sponsor", 1),
                asset_id: "xmr-fee-credit".to_string(),
                max_epoch_spend: 9_000_000_000,
                max_intent_spend: 50_000_000,
                rebate_floor_bps: 10,
                user_fee_cap_bps: 14,
                allowed_policy_root: fixture_root("allowed-policy", 1),
                aa_entrypoint_root: fixture_root("aa-entrypoint", 1),
                vault_nullifier_root: fixture_root("vault-nullifiers", 1),
                opened_at_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
                        + 40,
                vault_nonce: "demo-vault-1".to_string(),
            })
            .expect("demo vault opens");
        let epoch = state
            .open_policy_epoch(OpenPolicyEpochRequest {
                previous_epoch_id: state.policy_epochs.keys().next_back().cloned(),
                sponsor_vault_id: vault.vault_id.clone(),
                activation_height:
                    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
                        + 60,
                policy_commitment_root: fixture_root("policy", 2),
                private_allowlist_root: fixture_root("allowlist", 2),
                account_abstraction_rule_root: fixture_root("aa-rules", 2),
                sponsor_constraint_root: fixture_root("constraints", 2),
                low_fee_schedule_root: fixture_root("low-fee", 2),
                slh_dsa_public_key_root: fixture_root("slh-dsa-keyset", 2),
                pq_committee_root: fixture_root("pq-committee", 2),
                max_user_fee_bps: 11,
                privacy_set_size: 4_096,
                epoch_nonce: "demo-epoch-2".to_string(),
            })
            .expect("demo epoch opens");
        for i in 0..3 {
            let intent = state
                .commit_private_intent(CommitPrivateIntentRequest {
                    epoch_id: epoch.epoch_id.clone(),
                    sponsor_vault_id: vault.vault_id.clone(),
                    account_commitment: fixture_root("demo-account", i),
                    intent_commitment_root: fixture_root("demo-intent", i),
                    aa_call_root: fixture_root("demo-aa-call", i),
                    fee_asset_id: "xmr-fee-credit".to_string(),
                    max_fee_credit: 4_000_000 + u128::from(i) * 500_000,
                    user_fee_bps: 7 + i,
                    privacy_bucket_root: fixture_root("demo-privacy-bucket", i),
                    allowlist_witness_root: fixture_root("demo-allowlist-witness", i),
                    replay_nullifier: fixture_root("demo-nullifier", i),
                    submitted_at_height:
                        PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
                            + 66
                            + i,
                    intent_nonce: format!("demo-intent-{i}"),
                })
                .expect("demo intent commits");
            state
                .sponsor_private_intent(&intent.intent_id)
                .expect("demo intent sponsors");
        }
        state
    }

    pub fn open_sponsor_vault(
        &mut self,
        request: OpenSponsorVaultRequest,
    ) -> Result<SponsorVaultConstraints> {
        if self.sponsor_vaults.len() >= self.config.max_sponsor_vaults {
            return Err("sponsor vault capacity reached".to_string());
        }
        require_root("sponsor_commitment", &request.sponsor_commitment)?;
        require_non_empty("asset_id", &request.asset_id)?;
        require_root("allowed_policy_root", &request.allowed_policy_root)?;
        require_root("aa_entrypoint_root", &request.aa_entrypoint_root)?;
        require_root("vault_nullifier_root", &request.vault_nullifier_root)?;
        let vault_id = sponsor_vault_id(&request, self.counters.sponsor_vaults_opened + 1);
        let vault = SponsorVaultConstraints {
            vault_id: vault_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            asset_id: request.asset_id,
            status: SponsorVaultStatus::Active,
            max_epoch_spend: request.max_epoch_spend,
            max_intent_spend: request.max_intent_spend,
            reserved_credits: 0,
            spent_credits: 0,
            rebate_floor_bps: request.rebate_floor_bps,
            user_fee_cap_bps: request.user_fee_cap_bps,
            allowed_policy_root: request.allowed_policy_root,
            aa_entrypoint_root: request.aa_entrypoint_root,
            vault_nullifier_root: request.vault_nullifier_root,
            opened_at_height: request.opened_at_height,
        };
        vault.validate()?;
        self.sponsor_vaults.insert(vault_id, vault.clone());
        self.counters.sponsor_vaults_opened += 1;
        self.post_fee_credit(PostFeeCreditRequest {
            vault_id: vault.vault_id.clone(),
            intent_id: None,
            epoch_id: "vault-open".to_string(),
            kind: FeeCreditKind::Deposit,
            asset_id: vault.asset_id.clone(),
            amount: vault.max_epoch_spend,
            fee_schedule_root: vault.allowed_policy_root.clone(),
            posted_at_height: vault.opened_at_height,
            ledger_nonce: format!("{}-opening-credit", vault.vault_id),
        })?;
        Ok(vault)
    }

    pub fn open_policy_epoch(
        &mut self,
        request: OpenPolicyEpochRequest,
    ) -> Result<PaymasterPolicyEpoch> {
        if self.policy_epochs.len() >= self.config.max_epochs {
            return Err("policy epoch capacity reached".to_string());
        }
        let vault = self.require_vault(&request.sponsor_vault_id)?;
        if !vault.status.can_reserve() {
            return Err("sponsor vault cannot back a new policy epoch".to_string());
        }
        let sequence = self.counters.policy_epochs_opened + 1;
        let epoch_id = paymaster_policy_epoch_id(&request, sequence);
        let status = if request.activation_height
            <= PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_DEVNET_HEIGHT
        {
            PolicyEpochStatus::Active
        } else {
            PolicyEpochStatus::PendingActivation
        };
        let expiry_height = request.activation_height + self.config.policy_epoch_blocks;
        let epoch = PaymasterPolicyEpoch {
            epoch_id: epoch_id.clone(),
            previous_epoch_id: request.previous_epoch_id,
            sponsor_vault_id: request.sponsor_vault_id,
            status,
            epoch_index: sequence,
            activation_height: request.activation_height,
            expiry_height,
            grace_expiry_height: expiry_height + self.config.rollover_grace_blocks,
            policy_commitment_root: request.policy_commitment_root,
            private_allowlist_root: request.private_allowlist_root,
            account_abstraction_rule_root: request.account_abstraction_rule_root,
            sponsor_constraint_root: request.sponsor_constraint_root,
            low_fee_schedule_root: request.low_fee_schedule_root,
            slh_dsa_public_key_root: request.slh_dsa_public_key_root,
            pq_committee_root: request.pq_committee_root,
            max_user_fee_bps: request.max_user_fee_bps,
            privacy_set_size: request.privacy_set_size,
        };
        epoch.validate(&self.config)?;
        self.policy_epochs.insert(epoch_id, epoch.clone());
        self.counters.policy_epochs_opened += 1;
        Ok(epoch)
    }

    pub fn issue_rollover_certificate(
        &mut self,
        request: IssueRolloverCertificateRequest,
    ) -> Result<SlhDsaRolloverCertificate> {
        if self.rollover_certificates.len() >= self.config.max_certificates {
            return Err("rollover certificate capacity reached".to_string());
        }
        self.require_epoch(&request.previous_epoch_id)?;
        self.require_epoch(&request.next_epoch_id)?;
        if self.consumed_nullifiers.contains(&request.nullifier_root) {
            return Err("rollover certificate nullifier already consumed".to_string());
        }
        let certificate_id = slh_dsa_rollover_certificate_id(
            &request,
            self.counters.rollover_certificates_issued + 1,
        );
        let certificate = SlhDsaRolloverCertificate {
            certificate_id: certificate_id.clone(),
            previous_epoch_id: request.previous_epoch_id,
            next_epoch_id: request.next_epoch_id,
            status: RolloverCertificateStatus::Anchored,
            slh_dsa_signature_root: request.slh_dsa_signature_root,
            ml_dsa_cosignature_root: request.ml_dsa_cosignature_root,
            signer_committee_root: request.signer_committee_root,
            transcript_root: request.transcript_root,
            nullifier_root: request.nullifier_root,
            policy_delta_root: request.policy_delta_root,
            aggregate_weight: request.aggregate_weight,
            threshold_weight: request.threshold_weight,
            issued_at_height: request.issued_at_height,
            expires_at_height: request.issued_at_height + self.config.rollover_grace_blocks,
        };
        certificate.validate()?;
        self.consume_nullifier(
            &certificate.nullifier_root,
            &certificate.certificate_id,
            &certificate.next_epoch_id,
            certificate.issued_at_height,
        )?;
        if let Some(previous) = self.policy_epochs.get_mut(&certificate.previous_epoch_id) {
            previous.status = PolicyEpochStatus::Grace;
        }
        if let Some(next) = self.policy_epochs.get_mut(&certificate.next_epoch_id) {
            next.status = PolicyEpochStatus::Active;
        }
        self.rollover_certificates
            .insert(certificate_id, certificate.clone());
        self.counters.rollover_certificates_issued += 1;
        Ok(certificate)
    }

    pub fn commit_private_intent(
        &mut self,
        request: CommitPrivateIntentRequest,
    ) -> Result<PrivateIntentAllowlistEntry> {
        if self.private_intents.len() >= self.config.max_private_intents {
            return Err("private intent capacity reached".to_string());
        }
        let epoch = self.require_epoch(&request.epoch_id)?;
        if !epoch.accepts_height(request.submitted_at_height) {
            return Err(
                "policy epoch does not accept private intents at submitted height".to_string(),
            );
        }
        let vault = self.require_vault(&request.sponsor_vault_id)?;
        if vault.user_fee_cap_bps < request.user_fee_bps {
            return Err("intent user fee exceeds sponsor vault cap".to_string());
        }
        if self.consumed_nullifiers.contains(&request.replay_nullifier) {
            return Err("intent replay nullifier already consumed".to_string());
        }
        let intent_id = private_intent_id(&request, self.counters.private_intents_committed + 1);
        let intent = PrivateIntentAllowlistEntry {
            intent_id: intent_id.clone(),
            epoch_id: request.epoch_id,
            sponsor_vault_id: request.sponsor_vault_id,
            status: PrivateIntentStatus::Allowlisted,
            account_commitment: request.account_commitment,
            intent_commitment_root: request.intent_commitment_root,
            aa_call_root: request.aa_call_root,
            fee_asset_id: request.fee_asset_id,
            max_fee_credit: request.max_fee_credit,
            user_fee_bps: request.user_fee_bps,
            privacy_bucket_root: request.privacy_bucket_root,
            allowlist_witness_root: request.allowlist_witness_root,
            replay_nullifier: request.replay_nullifier,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.submitted_at_height + self.config.intent_ttl_blocks,
        };
        intent.validate(&self.config)?;
        self.private_intents.insert(intent_id, intent.clone());
        self.counters.private_intents_committed += 1;
        Ok(intent)
    }

    pub fn sponsor_private_intent(&mut self, intent_id: &str) -> Result<FeeCreditLedgerEntry> {
        let intent = self.require_intent(intent_id)?.clone();
        if !intent.live_at(intent.submitted_at_height) {
            return Err("private intent is not live".to_string());
        }
        let vault = self
            .sponsor_vaults
            .get_mut(&intent.sponsor_vault_id)
            .ok_or_else(|| format!("unknown sponsor vault {}", intent.sponsor_vault_id))?;
        if !vault.can_reserve(intent.max_fee_credit) {
            return Err("sponsor vault cannot reserve requested fee credit".to_string());
        }
        vault.reserved_credits += intent.max_fee_credit;
        if let Some(intent) = self.private_intents.get_mut(intent_id) {
            intent.status = PrivateIntentStatus::Sponsored;
        }
        self.counters.private_intents_sponsored += 1;
        self.post_fee_credit(PostFeeCreditRequest {
            vault_id: intent.sponsor_vault_id,
            intent_id: Some(intent.intent_id),
            epoch_id: intent.epoch_id,
            kind: FeeCreditKind::Reservation,
            asset_id: intent.fee_asset_id,
            amount: intent.max_fee_credit,
            fee_schedule_root: intent.privacy_bucket_root,
            posted_at_height: intent.submitted_at_height,
            ledger_nonce: format!("reserve-{intent_id}"),
        })
    }

    pub fn settle_private_intent(&mut self, intent_id: &str) -> Result<FeeCreditLedgerEntry> {
        let intent = self.require_intent(intent_id)?.clone();
        if intent.status != PrivateIntentStatus::Sponsored {
            return Err("only sponsored intents can settle".to_string());
        }
        self.consume_nullifier(
            &intent.replay_nullifier,
            &intent.intent_id,
            &intent.epoch_id,
            intent.submitted_at_height + 1,
        )?;
        let vault = self
            .sponsor_vaults
            .get_mut(&intent.sponsor_vault_id)
            .ok_or_else(|| format!("unknown sponsor vault {}", intent.sponsor_vault_id))?;
        vault.reserved_credits = vault.reserved_credits.saturating_sub(intent.max_fee_credit);
        vault.spent_credits += intent.max_fee_credit;
        if let Some(intent) = self.private_intents.get_mut(intent_id) {
            intent.status = PrivateIntentStatus::Settled;
        }
        self.post_fee_credit(PostFeeCreditRequest {
            vault_id: intent.sponsor_vault_id,
            intent_id: Some(intent.intent_id),
            epoch_id: intent.epoch_id,
            kind: FeeCreditKind::Spend,
            asset_id: intent.fee_asset_id,
            amount: intent.max_fee_credit,
            fee_schedule_root: intent.allowlist_witness_root,
            posted_at_height: intent.submitted_at_height + 1,
            ledger_nonce: format!("spend-{intent_id}"),
        })
    }

    pub fn post_fee_credit(
        &mut self,
        request: PostFeeCreditRequest,
    ) -> Result<FeeCreditLedgerEntry> {
        if self.fee_credit_ledger.len() >= self.config.max_fee_credit_entries {
            return Err("fee credit ledger capacity reached".to_string());
        }
        let current_balance = self
            .fee_credit_ledger
            .values()
            .filter(|entry| entry.vault_id == request.vault_id)
            .next_back()
            .map(|entry| entry.balance_after)
            .unwrap_or(0);
        let balance_after = match request.kind {
            FeeCreditKind::Deposit | FeeCreditKind::Rebate | FeeCreditKind::RolloverCarry => {
                current_balance.saturating_add(request.amount)
            }
            FeeCreditKind::Reservation
            | FeeCreditKind::Spend
            | FeeCreditKind::Slash
            | FeeCreditKind::Refund => current_balance.saturating_sub(request.amount),
        };
        let entry_id =
            fee_credit_ledger_entry_id(&request, self.counters.fee_credit_entries_posted + 1);
        let entry = FeeCreditLedgerEntry {
            entry_id: entry_id.clone(),
            vault_id: request.vault_id,
            intent_id: request.intent_id,
            epoch_id: request.epoch_id,
            kind: request.kind,
            asset_id: request.asset_id,
            amount: request.amount,
            balance_after,
            fee_schedule_root: request.fee_schedule_root,
            posted_at_height: request.posted_at_height,
        };
        entry.validate()?;
        match entry.kind {
            FeeCreditKind::Reservation => self.counters.total_fee_credits_reserved += entry.amount,
            FeeCreditKind::Spend => self.counters.total_fee_credits_spent += entry.amount,
            FeeCreditKind::Rebate => self.counters.total_fee_credits_rebated += entry.amount,
            FeeCreditKind::Slash => self.counters.total_fee_credits_slashed += entry.amount,
            _ => {}
        }
        self.fee_credit_ledger.insert(entry_id, entry.clone());
        self.counters.fee_credit_entries_posted += 1;
        Ok(entry)
    }

    pub fn record_pq_attestation(
        &mut self,
        request: RecordPqAttestationRequest,
    ) -> Result<PqAttestationRecord> {
        if self.pq_attestations.len() >= self.config.max_pq_attestations {
            return Err("pq attestation capacity reached".to_string());
        }
        let attestation_id =
            pq_attestation_id(&request, self.counters.pq_attestations_recorded + 1);
        let attestation = PqAttestationRecord {
            attestation_id: attestation_id.clone(),
            subject_id: request.subject_id,
            epoch_id: request.epoch_id,
            attester_commitment: request.attester_commitment,
            verdict: request.verdict,
            slh_dsa_key_health_root: request.slh_dsa_key_health_root,
            ml_dsa_backup_health_root: request.ml_dsa_backup_health_root,
            entropy_audit_root: request.entropy_audit_root,
            side_channel_review_root: request.side_channel_review_root,
            proof_transcript_root: request.proof_transcript_root,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };
        attestation.validate(&self.config)?;
        if !attestation.verdict.permits_activation() {
            if let Some(epoch) = self.policy_epochs.get_mut(&attestation.epoch_id) {
                epoch.status = PolicyEpochStatus::Paused;
            }
        }
        self.pq_attestations
            .insert(attestation_id, attestation.clone());
        self.counters.pq_attestations_recorded += 1;
        Ok(attestation)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: PublishOperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        let summary_id =
            operator_summary_id(&request, self.counters.operator_summaries_published + 1);
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            kind: request.kind,
            subject_id: request.subject_id,
            epoch_id: request.epoch_id,
            operator_commitment: request.operator_commitment,
            public_metric_root: request.public_metric_root,
            private_witness_root: request.private_witness_root,
            state_root_after: self.state_root(),
            published_at_height: request.published_at_height,
        };
        summary.validate()?;
        self.operator_summaries.insert(summary_id, summary.clone());
        self.counters.operator_summaries_published += 1;
        Ok(summary)
    }

    pub fn roots(&self) -> Roots {
        let policy_epoch_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-EPOCHS",
            &self
                .policy_epochs
                .values()
                .map(PaymasterPolicyEpoch::public_record)
                .collect::<Vec<_>>(),
        );
        let rollover_certificate_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-CERTIFICATES",
            &self
                .rollover_certificates
                .values()
                .map(SlhDsaRolloverCertificate::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_vault_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-VAULTS",
            &self
                .sponsor_vaults
                .values()
                .map(SponsorVaultConstraints::public_record)
                .collect::<Vec<_>>(),
        );
        let private_intent_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-INTENTS",
            &self
                .private_intents
                .values()
                .map(PrivateIntentAllowlistEntry::public_record)
                .collect::<Vec<_>>(),
        );
        let replay_guard_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-REPLAY-GUARDS",
            &self
                .replay_guards
                .values()
                .map(ReplayGuardRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_credit_ledger_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-FEE-CREDITS",
            &self
                .fee_credit_ledger
                .values()
                .map(FeeCreditLedgerEntry::public_record)
                .collect::<Vec<_>>(),
        );
        let pq_attestation_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-PQ-ATTESTATIONS",
            &self
                .pq_attestations
                .values()
                .map(PqAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let operator_summary_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-OPERATOR-SUMMARIES",
            &self
                .operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "policy_epoch_root": policy_epoch_root,
            "rollover_certificate_root": rollover_certificate_root,
            "sponsor_vault_root": sponsor_vault_root,
            "private_intent_root": private_intent_root,
            "replay_guard_root": replay_guard_root,
            "fee_credit_ledger_root": fee_credit_ledger_root,
            "pq_attestation_root": pq_attestation_root,
            "operator_summary_root": operator_summary_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            policy_epoch_root,
            rollover_certificate_root,
            sponsor_vault_root,
            private_intent_root,
            replay_guard_root,
            fee_credit_ledger_root,
            pq_attestation_root,
            operator_summary_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.without_state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        replay_nullifier: &str,
        subject_id: &str,
        epoch_id: &str,
        consumed_at_height: u64,
    ) -> Result<ReplayGuardRecord> {
        require_root("replay_nullifier", replay_nullifier)?;
        if self.consumed_nullifiers.contains(replay_nullifier) {
            return Err("replay nullifier already consumed".to_string());
        }
        let guard_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-REPLAY-GUARD",
            &json!({
                "replay_nullifier": replay_nullifier,
                "subject_id": subject_id,
                "epoch_id": epoch_id,
                "consumed_at_height": consumed_at_height,
            }),
        );
        let record = ReplayGuardRecord {
            replay_nullifier: replay_nullifier.to_string(),
            subject_id: subject_id.to_string(),
            epoch_id: epoch_id.to_string(),
            consumed_at_height,
            guard_root,
        };
        self.consumed_nullifiers
            .insert(replay_nullifier.to_string());
        self.replay_guards
            .insert(replay_nullifier.to_string(), record.clone());
        self.counters.replay_nullifiers_consumed += 1;
        Ok(record)
    }

    fn require_epoch(&self, epoch_id: &str) -> Result<&PaymasterPolicyEpoch> {
        self.policy_epochs
            .get(epoch_id)
            .ok_or_else(|| format!("unknown paymaster policy epoch {epoch_id}"))
    }

    fn require_vault(&self, vault_id: &str) -> Result<&SponsorVaultConstraints> {
        self.sponsor_vaults
            .get(vault_id)
            .ok_or_else(|| format!("unknown sponsor vault {vault_id}"))
    }

    fn require_intent(&self, intent_id: &str) -> Result<&PrivateIntentAllowlistEntry> {
        self.private_intents
            .get(intent_id)
            .ok_or_else(|| format!("unknown private intent {intent_id}"))
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn sponsor_vault_id(request: &OpenSponsorVaultRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.asset_id),
            HashPart::Str(&request.allowed_policy_root),
            HashPart::Str(&request.vault_nonce),
        ],
        32,
    )
}

pub fn paymaster_policy_epoch_id(request: &OpenPolicyEpochRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_vault_id),
            HashPart::Str(request.previous_epoch_id.as_deref().unwrap_or("genesis")),
            HashPart::Str(&request.policy_commitment_root),
            HashPart::Str(&request.slh_dsa_public_key_root),
            HashPart::Str(&request.epoch_nonce),
        ],
        32,
    )
}

pub fn slh_dsa_rollover_certificate_id(
    request: &IssueRolloverCertificateRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.previous_epoch_id),
            HashPart::Str(&request.next_epoch_id),
            HashPart::Str(&request.slh_dsa_signature_root),
            HashPart::Str(&request.policy_delta_root),
            HashPart::Str(&request.certificate_nonce),
        ],
        32,
    )
}

pub fn private_intent_id(request: &CommitPrivateIntentRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.epoch_id),
            HashPart::Str(&request.sponsor_vault_id),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.intent_commitment_root),
            HashPart::Str(&request.replay_nullifier),
            HashPart::Str(&request.intent_nonce),
        ],
        32,
    )
}

pub fn fee_credit_ledger_entry_id(request: &PostFeeCreditRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-FEE-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.vault_id),
            HashPart::Str(request.intent_id.as_deref().unwrap_or("vault")),
            HashPart::Str(&request.epoch_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.ledger_nonce),
        ],
        32,
    )
}

pub fn pq_attestation_id(request: &RecordPqAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.epoch_id),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn operator_summary_id(request: &PublishOperatorSummaryRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.epoch_id),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.summary_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-STATE",
        record,
    )
}

pub fn fixture_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-PAYMASTER-POLICY-ROLLOVER-FIXTURE",
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(index as i128),
        ],
        32,
    )
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_positive(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_at_most_bps(field: &str, value: u64) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_PAYMASTER_POLICY_ROLLOVER_RUNTIME_MAX_BPS {
        Err(format!("{field} cannot exceed 10000 bps"))
    } else {
        Ok(())
    }
}
