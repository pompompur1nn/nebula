use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlDsaAccountAbstractionPaymasterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_ACCOUNT_ABSTRACTION_PAYMASTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-dsa-account-abstraction-paymaster-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_ACCOUNT_ABSTRACTION_PAYMASTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_128_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-account-abstraction-paymaster-attestation-v1";
pub const ACCOUNT_ABSTRACTION_SCHEME: &str =
    "private-l2-account-abstraction-user-operation-envelope-v1";
pub const PAYMASTER_POLICY_SCHEME: &str = "privacy-preserving-paymaster-policy-root-v1";
pub const PRIVATE_INTENT_SCHEME: &str = "sponsored-private-intent-commitment-root-v1";
pub const FEE_CREDIT_BUCKET_SCHEME: &str = "confidential-fee-credit-bucket-root-v1";
pub const REPLAY_GUARD_SCHEME: &str = "private-aa-paymaster-replay-nullifier-root-v1";
pub const REBATE_ACCOUNTING_SCHEME: &str = "privacy-preserving-paymaster-rebate-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-paymaster-market-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_users_amounts_view_keys_session_keys_signatures_or_call_data";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BUCKET_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_EPOCH_BLOCKS: u64 = 1_440;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 128;
pub const DEFAULT_DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 3;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 1_500;
pub const DEFAULT_OPERATOR_REWARD_BPS: u64 = 250;
pub const DEFAULT_SLASH_BPS: u64 = 750;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_INTENTS_PER_BUCKET: u64 = 256;
pub const DEFAULT_MAX_SPONSORED_UNITS_PER_BUCKET: u64 = 65_536;
pub const DEFAULT_MAX_POLICY_EXPOSURE_UNITS: u64 = 4_194_304;
pub const DEFAULT_OPERATOR_SUMMARY_EPOCH_BLOCKS: u64 = 120;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterPolicyStatus {
    Draft,
    Active,
    CapacityLimited,
    Paused,
    Draining,
    Settling,
    Retired,
    Slashed,
}

impl PaymasterPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::CapacityLimited => "capacity_limited",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Settling => "settling",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Active | Self::CapacityLimited)
    }

    pub fn operator_visible(self) -> bool {
        !matches!(self, Self::Draft)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipMode {
    Disabled,
    SelfPayFallback,
    PreferPrivateSponsor,
    RequirePrivateSponsor,
    ProtocolSubsidized,
    MerchantSubsidized,
}

impl SponsorshipMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SelfPayFallback => "self_pay_fallback",
            Self::PreferPrivateSponsor => "prefer_private_sponsor",
            Self::RequirePrivateSponsor => "require_private_sponsor",
            Self::ProtocolSubsidized => "protocol_subsidized",
            Self::MerchantSubsidized => "merchant_subsidized",
        }
    }

    pub fn requires_sponsor(self) -> bool {
        matches!(
            self,
            Self::RequirePrivateSponsor | Self::ProtocolSubsidized | Self::MerchantSubsidized
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    PrivateTransfer,
    ContractCall,
    TokenMint,
    TokenBurn,
    BridgeDeposit,
    BridgeWithdraw,
    DefiSwap,
    Recovery,
    SessionKeyRefresh,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdraw => "bridge_withdraw",
            Self::DefiSwap => "defi_swap",
            Self::Recovery => "recovery",
            Self::SessionKeyRefresh => "session_key_refresh",
        }
    }

    pub fn is_high_risk(self) -> bool {
        matches!(self, Self::BridgeWithdraw | Self::DefiSwap | Self::Recovery)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    PrivacyChecked,
    AttestationPending,
    SponsorReserved,
    Included,
    Settled,
    Rebated,
    Expired,
    Rejected,
    ReplayBlocked,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PrivacyChecked => "privacy_checked",
            Self::AttestationPending => "attestation_pending",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::ReplayBlocked => "replay_blocked",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::PrivacyChecked
                | Self::AttestationPending
                | Self::SponsorReserved
                | Self::Included
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rebated | Self::Expired | Self::Rejected | Self::ReplayBlocked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlDsaAttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl MlDsaAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Quorum => "quorum",
            Self::StrongQuorum => "strong_quorum",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCreditBucketStatus {
    Open,
    Reserving,
    Reserved,
    LowBalance,
    Exhausted,
    Refilling,
    Closed,
}

impl FeeCreditBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserving => "reserving",
            Self::Reserved => "reserved",
            Self::LowBalance => "low_balance",
            Self::Exhausted => "exhausted",
            Self::Refilling => "refilling",
            Self::Closed => "closed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Reserving | Self::Reserved | Self::LowBalance
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayGuardStatus {
    Observing,
    Spent,
    Quarantined,
    Released,
    Expired,
}

impl ReplayGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observing => "observing",
            Self::Spent => "spent",
            Self::Quarantined => "quarantined",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    RolledForward,
    Slashed,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::RolledForward => "rolled_forward",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSummaryAudience {
    Sequencer,
    Paymaster,
    Sponsor,
    Watchtower,
    Public,
}

impl OperatorSummaryAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Paymaster => "paymaster",
            Self::Sponsor => "sponsor",
            Self::Watchtower => "watchtower",
            Self::Public => "public",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    PolicyRegistered,
    BucketOpened,
    IntentSubmitted,
    AttestationAccepted,
    FeeReserved,
    ReplayBlocked,
    IntentSettled,
    RebateAccrued,
    RebateClaimed,
    SummaryPublished,
}

impl RuntimeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyRegistered => "policy_registered",
            Self::BucketOpened => "bucket_opened",
            Self::IntentSubmitted => "intent_submitted",
            Self::AttestationAccepted => "attestation_accepted",
            Self::FeeReserved => "fee_reserved",
            Self::ReplayBlocked => "replay_blocked",
            Self::IntentSettled => "intent_settled",
            Self::RebateAccrued => "rebate_accrued",
            Self::RebateClaimed => "rebate_claimed",
            Self::SummaryPublished => "summary_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub asset_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_attestation_scheme: String,
    pub account_abstraction_scheme: String,
    pub paymaster_policy_scheme: String,
    pub private_intent_scheme: String,
    pub fee_credit_bucket_scheme: String,
    pub replay_guard_scheme: String,
    pub rebate_accounting_scheme: String,
    pub operator_summary_scheme: String,
    pub privacy_boundary: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub bucket_epoch_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_share_bps: u64,
    pub operator_reward_bps: u64,
    pub slash_bps: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_intents_per_bucket: u64,
    pub max_sponsored_units_per_bucket: u64,
    pub max_policy_exposure_units: u64,
    pub operator_summary_epoch_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_scheme: PQ_SIGNATURE_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            account_abstraction_scheme: ACCOUNT_ABSTRACTION_SCHEME.to_string(),
            paymaster_policy_scheme: PAYMASTER_POLICY_SCHEME.to_string(),
            private_intent_scheme: PRIVATE_INTENT_SCHEME.to_string(),
            fee_credit_bucket_scheme: FEE_CREDIT_BUCKET_SCHEME.to_string(),
            replay_guard_scheme: REPLAY_GUARD_SCHEME.to_string(),
            rebate_accounting_scheme: REBATE_ACCOUNTING_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            bucket_epoch_blocks: DEFAULT_BUCKET_EPOCH_BLOCKS,
            rebate_epoch_blocks: DEFAULT_REBATE_EPOCH_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            max_user_fee_bps: DEFAULT_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            operator_reward_bps: DEFAULT_OPERATOR_REWARD_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_intents_per_bucket: DEFAULT_MAX_INTENTS_PER_BUCKET,
            max_sponsored_units_per_bucket: DEFAULT_MAX_SPONSORED_UNITS_PER_BUCKET,
            max_policy_exposure_units: DEFAULT_MAX_POLICY_EXPOSURE_UNITS,
            operator_summary_epoch_blocks: DEFAULT_OPERATOR_SUMMARY_EPOCH_BLOCKS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("minimum PQ security below ML-DSA safety floor".to_string());
        }
        if self.target_pq_security_bits < self.min_pq_security_bits {
            return Err("target PQ security below minimum".to_string());
        }
        if self.intent_ttl_blocks == 0 || self.attestation_ttl_blocks == 0 {
            return Err("TTL blocks must be non-zero".to_string());
        }
        if self.min_privacy_set_size < 1_024 {
            return Err("privacy set size below private L2 floor".to_string());
        }
        if self.min_decoy_set_size < 16 {
            return Err("decoy set size below replay analysis floor".to_string());
        }
        validate_bps(self.max_user_fee_bps, "max_user_fee_bps")?;
        validate_bps(self.low_fee_target_bps, "low_fee_target_bps")?;
        validate_bps(self.sponsor_cover_bps, "sponsor_cover_bps")?;
        validate_bps(self.rebate_share_bps, "rebate_share_bps")?;
        validate_bps(self.operator_reward_bps, "operator_reward_bps")?;
        validate_bps(self.slash_bps, "slash_bps")?;
        validate_bps(self.quorum_bps, "quorum_bps")?;
        validate_bps(self.strong_quorum_bps, "strong_quorum_bps")?;
        if self.low_fee_target_bps > self.max_user_fee_bps {
            return Err("low fee target exceeds maximum user fee".to_string());
        }
        if self.strong_quorum_bps < self.quorum_bps {
            return Err("strong quorum below normal quorum".to_string());
        }
        if self.max_intents_per_bucket == 0 {
            return Err("max intents per bucket must be non-zero".to_string());
        }
        if self.max_sponsored_units_per_bucket == 0 {
            return Err("max sponsored units per bucket must be non-zero".to_string());
        }
        if self.max_policy_exposure_units < self.max_sponsored_units_per_bucket {
            return Err("policy exposure below single bucket limit".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "account_abstraction_scheme": self.account_abstraction_scheme,
            "paymaster_policy_scheme": self.paymaster_policy_scheme,
            "private_intent_scheme": self.private_intent_scheme,
            "fee_credit_bucket_scheme": self.fee_credit_bucket_scheme,
            "replay_guard_scheme": self.replay_guard_scheme,
            "rebate_accounting_scheme": self.rebate_accounting_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "privacy_boundary": self.privacy_boundary,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "bucket_epoch_blocks": self.bucket_epoch_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "operator_reward_bps": self.operator_reward_bps,
            "slash_bps": self.slash_bps,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "max_intents_per_bucket": self.max_intents_per_bucket,
            "max_sponsored_units_per_bucket": self.max_sponsored_units_per_bucket,
            "max_policy_exposure_units": self.max_policy_exposure_units,
            "operator_summary_epoch_blocks": self.operator_summary_epoch_blocks
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub paymaster_policies: u64,
    pub ml_dsa_attestations: u64,
    pub private_intents: u64,
    pub fee_credit_buckets: u64,
    pub replay_guards: u64,
    pub rebate_accounts: u64,
    pub operator_summaries: u64,
    pub events: u64,
    pub active_policies: u64,
    pub live_intents: u64,
    pub settled_intents: u64,
    pub blocked_replays: u64,
    pub total_reserved_fee_units: u64,
    pub total_sponsored_fee_units: u64,
    pub total_rebate_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "paymaster_policies": self.paymaster_policies,
            "ml_dsa_attestations": self.ml_dsa_attestations,
            "private_intents": self.private_intents,
            "fee_credit_buckets": self.fee_credit_buckets,
            "replay_guards": self.replay_guards,
            "rebate_accounts": self.rebate_accounts,
            "operator_summaries": self.operator_summaries,
            "events": self.events,
            "active_policies": self.active_policies,
            "live_intents": self.live_intents,
            "settled_intents": self.settled_intents,
            "blocked_replays": self.blocked_replays,
            "total_reserved_fee_units": self.total_reserved_fee_units,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_rebate_units": self.total_rebate_units
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub paymaster_policy_root: String,
    pub ml_dsa_attestation_root: String,
    pub private_intent_root: String,
    pub fee_credit_bucket_root: String,
    pub replay_guard_root: String,
    pub rebate_accounting_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            paymaster_policy_root: empty_root("PAYMASTER-POLICY"),
            ml_dsa_attestation_root: empty_root("ML-DSA-ATTESTATION"),
            private_intent_root: empty_root("PRIVATE-INTENT"),
            fee_credit_bucket_root: empty_root("FEE-CREDIT-BUCKET"),
            replay_guard_root: empty_root("REPLAY-GUARD"),
            rebate_accounting_root: empty_root("REBATE-ACCOUNTING"),
            operator_summary_root: empty_root("OPERATOR-SUMMARY"),
            nullifier_root: empty_root("NULLIFIER"),
            event_root: empty_root("EVENT"),
            public_record_root: empty_root("PUBLIC-RECORD"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "paymaster_policy_root": self.paymaster_policy_root,
            "ml_dsa_attestation_root": self.ml_dsa_attestation_root,
            "private_intent_root": self.private_intent_root,
            "fee_credit_bucket_root": self.fee_credit_bucket_root,
            "replay_guard_root": self.replay_guard_root,
            "rebate_accounting_root": self.rebate_accounting_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymasterPolicy {
    pub policy_id: String,
    pub sponsor_id: String,
    pub status: PaymasterPolicyStatus,
    pub mode: SponsorshipMode,
    pub created_height: u64,
    pub updated_height: u64,
    pub valid_until_height: u64,
    pub allowed_intent_kinds: BTreeSet<IntentKind>,
    pub excluded_route_buckets: BTreeSet<String>,
    pub attestor_set_root: String,
    pub sponsor_commitment_root: String,
    pub policy_commitment_root: String,
    pub spend_limit_commitment_root: String,
    pub max_user_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub sponsor_cover_bps: u64,
    pub exposure_limit_units: u64,
    pub reserved_units: u64,
    pub sponsored_units: u64,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub route_bucket: String,
    pub operator_hint: String,
    pub privacy_notes: Vec<String>,
}

impl PaymasterPolicy {
    pub fn capacity_remaining(&self) -> u64 {
        self.exposure_limit_units
            .saturating_sub(self.reserved_units)
    }

    pub fn can_sponsor(&self, intent_kind: IntentKind, fee_units: u64, route_bucket: &str) -> bool {
        self.status.accepts_intents()
            && self.allowed_intent_kinds.contains(&intent_kind)
            && !self.excluded_route_buckets.contains(route_bucket)
            && self.capacity_remaining() >= fee_units
    }

    pub fn reserve_fee_units(&mut self, units: u64, height: u64) -> Result<()> {
        if self.capacity_remaining() < units {
            return Err("paymaster policy capacity exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.updated_height = height;
        if self.capacity_remaining() < units {
            self.status = PaymasterPolicyStatus::CapacityLimited;
        }
        Ok(())
    }

    pub fn mark_sponsored(&mut self, units: u64, height: u64) {
        self.sponsored_units = self.sponsored_units.saturating_add(units);
        self.updated_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "mode": self.mode,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "valid_until_height": self.valid_until_height,
            "allowed_intent_kinds": self.allowed_intent_kinds,
            "excluded_route_buckets": self.excluded_route_buckets,
            "attestor_set_root": self.attestor_set_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "policy_commitment_root": self.policy_commitment_root,
            "spend_limit_commitment_root": self.spend_limit_commitment_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "exposure_limit_units": self.exposure_limit_units,
            "reserved_units": self.reserved_units,
            "sponsored_units": self.sponsored_units,
            "capacity_remaining": self.capacity_remaining(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "route_bucket": self.route_bucket,
            "operator_hint": self.operator_hint,
            "privacy_notes": self.privacy_notes
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlDsaAuthorizationAttestation {
    pub attestation_id: String,
    pub policy_id: String,
    pub intent_id: String,
    pub attestor_id: String,
    pub status: MlDsaAttestationStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub message_root: String,
    pub signature_commitment_root: String,
    pub authorization_root: String,
    pub session_key_commitment_root: String,
    pub policy_snapshot_root: String,
    pub weight_bps: u64,
    pub low_s_canonical: bool,
    pub deterministic_transcript: bool,
    pub notes: Vec<String>,
}

impl MlDsaAuthorizationAttestation {
    pub fn is_live(&self, height: u64) -> bool {
        self.status.counts_for_quorum() && height <= self.expires_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "policy_id": self.policy_id,
            "intent_id": self.intent_id,
            "attestor_id": self.attestor_id,
            "status": self.status,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "message_root": self.message_root,
            "signature_commitment_root": self.signature_commitment_root,
            "authorization_root": self.authorization_root,
            "session_key_commitment_root": self.session_key_commitment_root,
            "policy_snapshot_root": self.policy_snapshot_root,
            "weight_bps": self.weight_bps,
            "low_s_canonical": self.low_s_canonical,
            "deterministic_transcript": self.deterministic_transcript,
            "notes": self.notes
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredPrivateIntent {
    pub intent_id: String,
    pub policy_id: String,
    pub bucket_id: String,
    pub replay_guard_id: String,
    pub kind: IntentKind,
    pub status: IntentStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub included_height: Option<u64>,
    pub settled_height: Option<u64>,
    pub account_commitment_root: String,
    pub user_operation_root: String,
    pub call_data_root: String,
    pub witness_root: String,
    pub nullifier: String,
    pub nullifier_root: String,
    pub route_bucket: String,
    pub wallet_bucket: String,
    pub fee_units: u64,
    pub sponsor_units: u64,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub attestation_quorum_bps: u64,
    pub rebate_account_id: Option<String>,
    pub privacy_notes: Vec<String>,
}

impl SponsoredPrivateIntent {
    pub fn is_live(&self) -> bool {
        self.status.live()
    }

    pub fn is_settled(&self) -> bool {
        matches!(self.status, IntentStatus::Settled | IntentStatus::Rebated)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "policy_id": self.policy_id,
            "bucket_id": self.bucket_id,
            "replay_guard_id": self.replay_guard_id,
            "kind": self.kind,
            "status": self.status,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "included_height": self.included_height,
            "settled_height": self.settled_height,
            "account_commitment_root": self.account_commitment_root,
            "user_operation_root": self.user_operation_root,
            "call_data_root": self.call_data_root,
            "witness_root": self.witness_root,
            "nullifier_root": self.nullifier_root,
            "route_bucket": self.route_bucket,
            "wallet_bucket": self.wallet_bucket,
            "fee_units": self.fee_units,
            "sponsor_units": self.sponsor_units,
            "user_fee_bps": self.user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "decoy_set_size": self.decoy_set_size,
            "attestation_quorum_bps": self.attestation_quorum_bps,
            "rebate_account_id": self.rebate_account_id,
            "privacy_notes": self.privacy_notes
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditBucket {
    pub bucket_id: String,
    pub policy_id: String,
    pub sponsor_id: String,
    pub status: FeeCreditBucketStatus,
    pub epoch: u64,
    pub opened_height: u64,
    pub closes_height: u64,
    pub credit_commitment_root: String,
    pub reservation_root: String,
    pub debit_root: String,
    pub refill_root: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
    pub refunded_fee_units: u64,
    pub intent_count: u64,
    pub route_bucket: String,
    pub liquidity_hint: String,
}

impl FeeCreditBucket {
    pub fn available_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.reserved_fee_units)
    }

    pub fn reserve(&mut self, fee_units: u64) -> Result<()> {
        if !self.status.usable() {
            return Err("fee credit bucket is not usable".to_string());
        }
        if self.available_units() < fee_units {
            self.status = FeeCreditBucketStatus::Exhausted;
            return Err("fee credit bucket exhausted".to_string());
        }
        self.reserved_fee_units = self.reserved_fee_units.saturating_add(fee_units);
        self.intent_count = self.intent_count.saturating_add(1);
        if self.available_units() == 0 {
            self.status = FeeCreditBucketStatus::Exhausted;
        } else if self.available_units() < fee_units {
            self.status = FeeCreditBucketStatus::LowBalance;
        } else {
            self.status = FeeCreditBucketStatus::Reserved;
        }
        Ok(())
    }

    pub fn spend(&mut self, fee_units: u64) {
        self.spent_fee_units = self.spent_fee_units.saturating_add(fee_units);
        self.status = if self.available_units() == 0 {
            FeeCreditBucketStatus::Exhausted
        } else {
            FeeCreditBucketStatus::Reserved
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "policy_id": self.policy_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "epoch": self.epoch,
            "opened_height": self.opened_height,
            "closes_height": self.closes_height,
            "credit_commitment_root": self.credit_commitment_root,
            "reservation_root": self.reservation_root,
            "debit_root": self.debit_root,
            "refill_root": self.refill_root,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "refunded_fee_units": self.refunded_fee_units,
            "available_units": self.available_units(),
            "intent_count": self.intent_count,
            "route_bucket": self.route_bucket,
            "liquidity_hint": self.liquidity_hint
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayNullifierGuard {
    pub guard_id: String,
    pub intent_id: String,
    pub policy_id: String,
    pub status: ReplayGuardStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub lane_commitment_root: String,
    pub spend_marker_root: String,
    pub account_bucket: String,
    pub route_bucket: String,
    pub observation_count: u64,
    pub blocked_replay_count: u64,
}

impl ReplayNullifierGuard {
    pub fn mark_spent(&mut self) {
        self.status = ReplayGuardStatus::Spent;
        self.observation_count = self.observation_count.saturating_add(1);
    }

    pub fn mark_replay_blocked(&mut self) {
        self.status = ReplayGuardStatus::Quarantined;
        self.blocked_replay_count = self.blocked_replay_count.saturating_add(1);
        self.observation_count = self.observation_count.saturating_add(1);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "intent_id": self.intent_id,
            "policy_id": self.policy_id,
            "status": self.status,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "nullifier_root": self.nullifier_root,
            "replay_domain": self.replay_domain,
            "lane_commitment_root": self.lane_commitment_root,
            "spend_marker_root": self.spend_marker_root,
            "account_bucket": self.account_bucket,
            "route_bucket": self.route_bucket,
            "observation_count": self.observation_count,
            "blocked_replay_count": self.blocked_replay_count
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAccount {
    pub rebate_account_id: String,
    pub policy_id: String,
    pub bucket_id: String,
    pub status: RebateStatus,
    pub epoch: u64,
    pub opened_height: u64,
    pub claimable_after_height: u64,
    pub beneficiary_commitment_root: String,
    pub rebate_commitment_root: String,
    pub settlement_root: String,
    pub claim_nullifier_root: String,
    pub accrued_units: u64,
    pub claimed_units: u64,
    pub slashed_units: u64,
    pub operator_reward_units: u64,
    pub sponsor_refund_units: u64,
    pub route_bucket: String,
}

impl RebateAccount {
    pub fn claimable_units(&self) -> u64 {
        self.accrued_units
            .saturating_sub(self.claimed_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn accrue(&mut self, units: u64) {
        self.accrued_units = self.accrued_units.saturating_add(units);
        self.status = RebateStatus::Claimable;
    }

    pub fn claim(&mut self, units: u64) -> Result<()> {
        if self.claimable_units() < units {
            return Err("rebate claim exceeds claimable units".to_string());
        }
        self.claimed_units = self.claimed_units.saturating_add(units);
        if self.claimable_units() == 0 {
            self.status = RebateStatus::Claimed;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_account_id": self.rebate_account_id,
            "policy_id": self.policy_id,
            "bucket_id": self.bucket_id,
            "status": self.status,
            "epoch": self.epoch,
            "opened_height": self.opened_height,
            "claimable_after_height": self.claimable_after_height,
            "beneficiary_commitment_root": self.beneficiary_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "settlement_root": self.settlement_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "accrued_units": self.accrued_units,
            "claimed_units": self.claimed_units,
            "slashed_units": self.slashed_units,
            "operator_reward_units": self.operator_reward_units,
            "sponsor_refund_units": self.sponsor_refund_units,
            "claimable_units": self.claimable_units(),
            "route_bucket": self.route_bucket
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub audience: OperatorSummaryAudience,
    pub epoch: u64,
    pub height: u64,
    pub policy_count: u64,
    pub active_policy_count: u64,
    pub live_intent_count: u64,
    pub settled_intent_count: u64,
    pub reserved_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub rebate_units: u64,
    pub blocked_replay_count: u64,
    pub paymaster_policy_root: String,
    pub private_intent_root: String,
    pub fee_credit_bucket_root: String,
    pub replay_guard_root: String,
    pub rebate_accounting_root: String,
    pub risk_root: String,
    pub disclosure_root: String,
    pub notes: Vec<String>,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "audience": self.audience,
            "epoch": self.epoch,
            "height": self.height,
            "policy_count": self.policy_count,
            "active_policy_count": self.active_policy_count,
            "live_intent_count": self.live_intent_count,
            "settled_intent_count": self.settled_intent_count,
            "reserved_fee_units": self.reserved_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "rebate_units": self.rebate_units,
            "blocked_replay_count": self.blocked_replay_count,
            "paymaster_policy_root": self.paymaster_policy_root,
            "private_intent_root": self.private_intent_root,
            "fee_credit_bucket_root": self.fee_credit_bucket_root,
            "replay_guard_root": self.replay_guard_root,
            "rebate_accounting_root": self.rebate_accounting_root,
            "risk_root": self.risk_root,
            "disclosure_root": self.disclosure_root,
            "notes": self.notes
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: RuntimeEventKind,
    pub height: u64,
    pub subject_id: String,
    pub commitment_root: String,
    pub operator_visible: bool,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "height": self.height,
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "operator_visible": self.operator_visible
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub paymaster_policies: BTreeMap<String, PaymasterPolicy>,
    pub ml_dsa_attestations: BTreeMap<String, MlDsaAuthorizationAttestation>,
    pub private_intents: BTreeMap<String, SponsoredPrivateIntent>,
    pub fee_credit_buckets: BTreeMap<String, FeeCreditBucket>,
    pub replay_guards: BTreeMap<String, ReplayNullifierGuard>,
    pub rebate_accounts: BTreeMap<String, RebateAccount>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            paymaster_policies: BTreeMap::new(),
            ml_dsa_attestations: BTreeMap::new(),
            private_intents: BTreeMap::new(),
            fee_credit_buckets: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            rebate_accounts: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.recompute();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default()).expect("default config is valid");
        state.seed_devnet();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn register_paymaster_policy(
        &mut self,
        sponsor_id: impl Into<String>,
        mode: SponsorshipMode,
        route_bucket: impl Into<String>,
        exposure_limit_units: u64,
        allowed_intent_kinds: BTreeSet<IntentKind>,
    ) -> Result<String> {
        let sponsor_id = sponsor_id.into();
        let route_bucket = route_bucket.into();
        if exposure_limit_units == 0 {
            return Err("policy exposure must be non-zero".to_string());
        }
        if exposure_limit_units > self.config.max_policy_exposure_units {
            return Err("policy exposure exceeds configured maximum".to_string());
        }
        if allowed_intent_kinds.is_empty() {
            return Err("policy must allow at least one intent kind".to_string());
        }
        let policy_id = deterministic_id(
            "POLICY-ID",
            &[
                HashPart::U64(self.counters.paymaster_policies + 1),
                HashPart::Str(&sponsor_id),
                HashPart::Str(&route_bucket),
            ],
        );
        let policy = PaymasterPolicy {
            policy_id: policy_id.clone(),
            sponsor_id: sponsor_id.clone(),
            status: PaymasterPolicyStatus::Active,
            mode,
            created_height: self.current_height,
            updated_height: self.current_height,
            valid_until_height: self
                .current_height
                .saturating_add(self.config.rebate_epoch_blocks.saturating_mul(8)),
            allowed_intent_kinds,
            excluded_route_buckets: BTreeSet::new(),
            attestor_set_root: deterministic_id("ATTESTOR-SET", &[HashPart::Str(&policy_id)]),
            sponsor_commitment_root: deterministic_id(
                "SPONSOR-COMMITMENT",
                &[HashPart::Str(&sponsor_id)],
            ),
            policy_commitment_root: deterministic_id(
                "POLICY-COMMITMENT",
                &[
                    HashPart::Str(&policy_id),
                    HashPart::U64(exposure_limit_units),
                ],
            ),
            spend_limit_commitment_root: deterministic_id(
                "SPEND-LIMIT",
                &[HashPart::Str(&policy_id)],
            ),
            max_user_fee_bps: self.config.max_user_fee_bps,
            low_fee_target_bps: self.config.low_fee_target_bps,
            sponsor_cover_bps: self.config.sponsor_cover_bps,
            exposure_limit_units,
            reserved_units: 0,
            sponsored_units: 0,
            min_privacy_set_size: self.config.min_privacy_set_size,
            min_decoy_set_size: self.config.min_decoy_set_size,
            min_pq_security_bits: self.config.min_pq_security_bits,
            route_bucket,
            operator_hint: "root-only-sponsor-market".to_string(),
            privacy_notes: vec![
                "sponsor identity represented by commitment root".to_string(),
                "per-user spend limits remain encrypted".to_string(),
                "policy exposes only aggregate fee capacity".to_string(),
            ],
        };
        self.paymaster_policies.insert(policy_id.clone(), policy);
        self.record_event(RuntimeEventKind::PolicyRegistered, &policy_id, true);
        self.recompute();
        Ok(policy_id)
    }

    pub fn open_fee_credit_bucket(
        &mut self,
        policy_id: &str,
        max_fee_units: u64,
    ) -> Result<String> {
        let policy = self
            .paymaster_policies
            .get(policy_id)
            .ok_or_else(|| format!("unknown paymaster policy {policy_id}"))?;
        if !policy.status.accepts_intents() {
            return Err("paymaster policy does not accept bucket opens".to_string());
        }
        if max_fee_units == 0 {
            return Err("fee credit bucket units must be non-zero".to_string());
        }
        if max_fee_units > self.config.max_sponsored_units_per_bucket {
            return Err("fee credit bucket exceeds configured maximum".to_string());
        }
        let epoch = self.current_height / self.config.bucket_epoch_blocks;
        let bucket_id = deterministic_id(
            "BUCKET-ID",
            &[
                HashPart::Str(policy_id),
                HashPart::U64(epoch),
                HashPart::U64(self.counters.fee_credit_buckets + 1),
            ],
        );
        let bucket = FeeCreditBucket {
            bucket_id: bucket_id.clone(),
            policy_id: policy_id.to_string(),
            sponsor_id: policy.sponsor_id.clone(),
            status: FeeCreditBucketStatus::Open,
            epoch,
            opened_height: self.current_height,
            closes_height: self.current_height + self.config.bucket_epoch_blocks,
            credit_commitment_root: deterministic_id("BUCKET-CREDIT", &[HashPart::Str(&bucket_id)]),
            reservation_root: empty_root("BUCKET-RESERVATION"),
            debit_root: empty_root("BUCKET-DEBIT"),
            refill_root: empty_root("BUCKET-REFILL"),
            max_fee_units,
            reserved_fee_units: 0,
            spent_fee_units: 0,
            refunded_fee_units: 0,
            intent_count: 0,
            route_bucket: policy.route_bucket.clone(),
            liquidity_hint: "low-fee-private-aa".to_string(),
        };
        self.fee_credit_buckets.insert(bucket_id.clone(), bucket);
        self.record_event(RuntimeEventKind::BucketOpened, &bucket_id, true);
        self.recompute();
        Ok(bucket_id)
    }

    pub fn submit_private_intent(
        &mut self,
        policy_id: &str,
        bucket_id: &str,
        kind: IntentKind,
        wallet_bucket: impl Into<String>,
        route_bucket: impl Into<String>,
        fee_units: u64,
    ) -> Result<String> {
        let wallet_bucket = wallet_bucket.into();
        let route_bucket = route_bucket.into();
        if fee_units == 0 {
            return Err("private intent fee units must be non-zero".to_string());
        }
        let policy = self
            .paymaster_policies
            .get(policy_id)
            .ok_or_else(|| format!("unknown paymaster policy {policy_id}"))?;
        if !policy.can_sponsor(kind, fee_units, &route_bucket) {
            return Err("paymaster policy cannot sponsor this intent".to_string());
        }
        if policy.min_privacy_set_size < self.config.min_privacy_set_size
            || policy.min_decoy_set_size < self.config.min_decoy_set_size
        {
            return Err("policy privacy floor below runtime config".to_string());
        }
        let bucket = self
            .fee_credit_buckets
            .get(bucket_id)
            .ok_or_else(|| format!("unknown fee credit bucket {bucket_id}"))?;
        if bucket.policy_id != policy_id {
            return Err("fee credit bucket does not belong to policy".to_string());
        }
        if bucket.available_units() < fee_units {
            return Err("bucket cannot reserve requested fee units".to_string());
        }
        let nullifier = deterministic_id(
            "INTENT-NULLIFIER",
            &[
                HashPart::Str(policy_id),
                HashPart::Str(bucket_id),
                HashPart::Str(&wallet_bucket),
                HashPart::Str(kind.as_str()),
                HashPart::U64(self.counters.private_intents + 1),
            ],
        );
        if self.nullifiers.contains(&nullifier) {
            return Err("duplicate private intent nullifier".to_string());
        }
        let intent_id = deterministic_id("PRIVATE-INTENT-ID", &[HashPart::Str(&nullifier)]);
        let replay_guard_id = deterministic_id("REPLAY-GUARD-ID", &[HashPart::Str(&intent_id)]);
        let rebate_account_id = deterministic_id(
            "REBATE-ACCOUNT-ID",
            &[
                HashPart::Str(policy_id),
                HashPart::Str(bucket_id),
                HashPart::Str(&wallet_bucket),
            ],
        );
        let sponsor_units = fee_units
            .saturating_mul(policy.sponsor_cover_bps)
            .saturating_div(MAX_BPS);
        let nullifier_root = deterministic_id("NULLIFIER-ROOT", &[HashPart::Str(&nullifier)]);
        let intent = SponsoredPrivateIntent {
            intent_id: intent_id.clone(),
            policy_id: policy_id.to_string(),
            bucket_id: bucket_id.to_string(),
            replay_guard_id: replay_guard_id.clone(),
            kind,
            status: IntentStatus::SponsorReserved,
            submitted_height: self.current_height,
            expires_height: self.current_height + self.config.intent_ttl_blocks,
            included_height: None,
            settled_height: None,
            account_commitment_root: deterministic_id(
                "ACCOUNT-COMMITMENT",
                &[HashPart::Str(&wallet_bucket)],
            ),
            user_operation_root: deterministic_id("USER-OP", &[HashPart::Str(&intent_id)]),
            call_data_root: deterministic_id("CALLDATA", &[HashPart::Str(&intent_id)]),
            witness_root: deterministic_id("WITNESS", &[HashPart::Str(&intent_id)]),
            nullifier: nullifier.clone(),
            nullifier_root: nullifier_root.clone(),
            route_bucket: route_bucket.clone(),
            wallet_bucket: wallet_bucket.clone(),
            fee_units,
            sponsor_units,
            user_fee_bps: policy.low_fee_target_bps,
            privacy_set_size: policy.min_privacy_set_size,
            decoy_set_size: policy.min_decoy_set_size,
            attestation_quorum_bps: 0,
            rebate_account_id: Some(rebate_account_id.clone()),
            privacy_notes: vec![
                "account and call data are commitment roots only".to_string(),
                "nullifier preimage is withheld".to_string(),
                "wallet bucket is an operator-safe coarse cohort".to_string(),
            ],
        };
        let guard = ReplayNullifierGuard {
            guard_id: replay_guard_id.clone(),
            intent_id: intent_id.clone(),
            policy_id: policy_id.to_string(),
            status: ReplayGuardStatus::Observing,
            created_height: self.current_height,
            expires_height: self.current_height + self.config.intent_ttl_blocks,
            nullifier_root,
            replay_domain: format!("{}:{}", self.config.l2_network, policy_id),
            lane_commitment_root: deterministic_id("LANE", &[HashPart::Str(&wallet_bucket)]),
            spend_marker_root: deterministic_id("SPEND-MARKER", &[HashPart::Str(&intent_id)]),
            account_bucket: wallet_bucket.clone(),
            route_bucket,
            observation_count: 0,
            blocked_replay_count: 0,
        };
        let rebate = RebateAccount {
            rebate_account_id: rebate_account_id.clone(),
            policy_id: policy_id.to_string(),
            bucket_id: bucket_id.to_string(),
            status: RebateStatus::Accruing,
            epoch: self.current_height / self.config.rebate_epoch_blocks,
            opened_height: self.current_height,
            claimable_after_height: self.current_height + self.config.rebate_epoch_blocks,
            beneficiary_commitment_root: deterministic_id(
                "REBATE-BENEFICIARY",
                &[HashPart::Str(&wallet_bucket)],
            ),
            rebate_commitment_root: deterministic_id(
                "REBATE-COMMITMENT",
                &[HashPart::Str(&rebate_account_id)],
            ),
            settlement_root: empty_root("REBATE-SETTLEMENT"),
            claim_nullifier_root: deterministic_id(
                "CLAIM-NULLIFIER",
                &[HashPart::Str(&rebate_account_id)],
            ),
            accrued_units: 0,
            claimed_units: 0,
            slashed_units: 0,
            operator_reward_units: 0,
            sponsor_refund_units: 0,
            route_bucket: wallet_bucket,
        };
        self.nullifiers.insert(nullifier);
        self.private_intents.insert(intent_id.clone(), intent);
        self.replay_guards.insert(replay_guard_id, guard);
        self.rebate_accounts
            .entry(rebate_account_id)
            .or_insert(rebate);
        self.fee_credit_buckets
            .get_mut(bucket_id)
            .expect("bucket checked")
            .reserve(fee_units)?;
        self.paymaster_policies
            .get_mut(policy_id)
            .expect("policy checked")
            .reserve_fee_units(fee_units, self.current_height)?;
        self.record_event(RuntimeEventKind::IntentSubmitted, &intent_id, true);
        self.record_event(RuntimeEventKind::FeeReserved, bucket_id, true);
        self.recompute();
        Ok(intent_id)
    }

    pub fn accept_ml_dsa_attestation(
        &mut self,
        attestor_id: impl Into<String>,
        intent_id: &str,
        weight_bps: u64,
    ) -> Result<String> {
        validate_bps(weight_bps, "attestation weight")?;
        let attestor_id = attestor_id.into();
        let intent = self
            .private_intents
            .get(intent_id)
            .ok_or_else(|| format!("unknown private intent {intent_id}"))?;
        let policy = self
            .paymaster_policies
            .get(&intent.policy_id)
            .ok_or_else(|| format!("unknown policy {}", intent.policy_id))?;
        if self.current_height > intent.expires_height {
            return Err("intent expired before attestation".to_string());
        }
        let attestation_id = deterministic_id(
            "ML-DSA-ATTESTATION-ID",
            &[
                HashPart::Str(intent_id),
                HashPart::Str(&attestor_id),
                HashPart::U64(self.counters.ml_dsa_attestations + 1),
            ],
        );
        let status = if weight_bps >= self.config.strong_quorum_bps {
            MlDsaAttestationStatus::StrongQuorum
        } else if weight_bps >= self.config.quorum_bps {
            MlDsaAttestationStatus::Quorum
        } else {
            MlDsaAttestationStatus::Accepted
        };
        let attestation = MlDsaAuthorizationAttestation {
            attestation_id: attestation_id.clone(),
            policy_id: intent.policy_id.clone(),
            intent_id: intent_id.to_string(),
            attestor_id,
            status,
            submitted_height: self.current_height,
            expires_height: self.current_height + self.config.attestation_ttl_blocks,
            pq_scheme: self.config.pq_signature_scheme.clone(),
            pq_security_bits: self.config.target_pq_security_bits,
            message_root: deterministic_id("ATTESTED-MESSAGE", &[HashPart::Str(intent_id)]),
            signature_commitment_root: deterministic_id(
                "ML-DSA-SIGNATURE",
                &[HashPart::Str(&attestation_id)],
            ),
            authorization_root: deterministic_id(
                "AUTHORIZATION",
                &[
                    HashPart::Str(&attestation_id),
                    HashPart::Str(policy.policy_id.as_str()),
                ],
            ),
            session_key_commitment_root: deterministic_id(
                "SESSION-KEY",
                &[HashPart::Str(intent_id)],
            ),
            policy_snapshot_root: value_root("POLICY-SNAPSHOT", &policy.public_record()),
            weight_bps,
            low_s_canonical: true,
            deterministic_transcript: true,
            notes: vec![
                "ML-DSA signature bytes redacted".to_string(),
                "authorization transcript is domain separated".to_string(),
                "attestor key material never enters public record".to_string(),
            ],
        };
        self.ml_dsa_attestations
            .insert(attestation_id.clone(), attestation);
        self.private_intents
            .get_mut(intent_id)
            .expect("intent checked")
            .attestation_quorum_bps = self.attestation_weight_for(intent_id);
        self.record_event(RuntimeEventKind::AttestationAccepted, &attestation_id, true);
        self.recompute();
        Ok(attestation_id)
    }

    pub fn settle_private_intent(&mut self, intent_id: &str) -> Result<()> {
        let quorum = self.attestation_weight_for(intent_id);
        if quorum < self.config.quorum_bps {
            return Err("private intent lacks ML-DSA attestation quorum".to_string());
        }
        let (policy_id, bucket_id, guard_id, rebate_account_id, sponsor_units, fee_units) = {
            let intent = self
                .private_intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown private intent {intent_id}"))?;
            if !intent.status.live() {
                return Err("private intent is not live".to_string());
            }
            (
                intent.policy_id.clone(),
                intent.bucket_id.clone(),
                intent.replay_guard_id.clone(),
                intent.rebate_account_id.clone(),
                intent.sponsor_units,
                intent.fee_units,
            )
        };
        let rebate_units = fee_units
            .saturating_mul(self.config.rebate_share_bps)
            .saturating_div(MAX_BPS);
        let operator_reward_units = fee_units
            .saturating_mul(self.config.operator_reward_bps)
            .saturating_div(MAX_BPS);
        if let Some(guard) = self.replay_guards.get_mut(&guard_id) {
            guard.mark_spent();
        }
        if let Some(bucket) = self.fee_credit_buckets.get_mut(&bucket_id) {
            bucket.spend(fee_units);
        }
        if let Some(policy) = self.paymaster_policies.get_mut(&policy_id) {
            policy.mark_sponsored(sponsor_units, self.current_height);
        }
        if let Some(rebate_account_id) = rebate_account_id {
            if let Some(rebate) = self.rebate_accounts.get_mut(&rebate_account_id) {
                rebate.accrue(rebate_units);
                rebate.operator_reward_units = rebate
                    .operator_reward_units
                    .saturating_add(operator_reward_units);
                rebate.sponsor_refund_units = rebate
                    .sponsor_refund_units
                    .saturating_add(fee_units.saturating_sub(sponsor_units));
            }
        }
        let intent = self
            .private_intents
            .get_mut(intent_id)
            .expect("intent checked");
        intent.status = IntentStatus::Settled;
        intent.included_height = Some(self.current_height);
        intent.settled_height = Some(self.current_height);
        intent.attestation_quorum_bps = quorum;
        self.record_event(RuntimeEventKind::IntentSettled, intent_id, true);
        self.record_event(RuntimeEventKind::RebateAccrued, intent_id, true);
        self.recompute();
        Ok(())
    }

    pub fn block_replay(&mut self, intent_id: &str) -> Result<()> {
        let intent = self
            .private_intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("unknown private intent {intent_id}"))?;
        let guard = self
            .replay_guards
            .get_mut(&intent.replay_guard_id)
            .ok_or_else(|| format!("missing replay guard {}", intent.replay_guard_id))?;
        intent.status = IntentStatus::ReplayBlocked;
        guard.mark_replay_blocked();
        self.record_event(RuntimeEventKind::ReplayBlocked, intent_id, true);
        self.recompute();
        Ok(())
    }

    pub fn claim_rebate(&mut self, rebate_account_id: &str, units: u64) -> Result<()> {
        let rebate = self
            .rebate_accounts
            .get_mut(rebate_account_id)
            .ok_or_else(|| format!("unknown rebate account {rebate_account_id}"))?;
        if self.current_height < rebate.claimable_after_height {
            return Err("rebate is not yet claimable".to_string());
        }
        rebate.claim(units)?;
        self.record_event(RuntimeEventKind::RebateClaimed, rebate_account_id, true);
        self.recompute();
        Ok(())
    }

    pub fn publish_operator_summary(
        &mut self,
        audience: OperatorSummaryAudience,
    ) -> Result<String> {
        let epoch = self.current_height / self.config.operator_summary_epoch_blocks;
        let summary_id = deterministic_id(
            "SUMMARY-ID",
            &[
                HashPart::Str(audience.as_str()),
                HashPart::U64(epoch),
                HashPart::U64(self.counters.operator_summaries + 1),
            ],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            audience,
            epoch,
            height: self.current_height,
            policy_count: self.paymaster_policies.len() as u64,
            active_policy_count: self
                .paymaster_policies
                .values()
                .filter(|policy| policy.status.accepts_intents())
                .count() as u64,
            live_intent_count: self
                .private_intents
                .values()
                .filter(|intent| intent.is_live())
                .count() as u64,
            settled_intent_count: self
                .private_intents
                .values()
                .filter(|intent| intent.is_settled())
                .count() as u64,
            reserved_fee_units: self
                .fee_credit_buckets
                .values()
                .map(|bucket| bucket.reserved_fee_units)
                .sum(),
            sponsored_fee_units: self
                .paymaster_policies
                .values()
                .map(|policy| policy.sponsored_units)
                .sum(),
            rebate_units: self
                .rebate_accounts
                .values()
                .map(|rebate| rebate.accrued_units)
                .sum(),
            blocked_replay_count: self
                .replay_guards
                .values()
                .map(|guard| guard.blocked_replay_count)
                .sum(),
            paymaster_policy_root: self.roots.paymaster_policy_root.clone(),
            private_intent_root: self.roots.private_intent_root.clone(),
            fee_credit_bucket_root: self.roots.fee_credit_bucket_root.clone(),
            replay_guard_root: self.roots.replay_guard_root.clone(),
            rebate_accounting_root: self.roots.rebate_accounting_root.clone(),
            risk_root: deterministic_id(
                "SUMMARY-RISK",
                &[
                    HashPart::Str(&summary_id),
                    HashPart::U64(self.counters.blocked_replays),
                ],
            ),
            disclosure_root: deterministic_id(
                "SUMMARY-DISCLOSURE",
                &[HashPart::Str(&summary_id), HashPart::Str(PRIVACY_BOUNDARY)],
            ),
            notes: vec![
                "summary omits user addresses and call data".to_string(),
                "market liquidity is represented by aggregate buckets".to_string(),
                "all roots are deterministic over sorted public records".to_string(),
            ],
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.record_event(RuntimeEventKind::SummaryPublished, &summary_id, true);
        self.recompute();
        Ok(summary_id)
    }

    pub fn advance_height(&mut self, blocks: u64) {
        self.current_height = self.current_height.saturating_add(blocks);
        self.expire_old_records();
        self.recompute();
    }

    pub fn attestation_weight_for(&self, intent_id: &str) -> u64 {
        self.ml_dsa_attestations
            .values()
            .filter(|attestation| {
                attestation.intent_id == intent_id && attestation.is_live(self.current_height)
            })
            .map(|attestation| attestation.weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    pub fn policy_exposure_ratio_bps(&self, policy_id: &str) -> Option<u64> {
        self.paymaster_policies.get(policy_id).map(|policy| {
            if policy.exposure_limit_units == 0 {
                0
            } else {
                policy
                    .reserved_units
                    .saturating_mul(MAX_BPS)
                    .saturating_div(policy.exposure_limit_units)
            }
        })
    }

    pub fn bucket_utilization_bps(&self, bucket_id: &str) -> Option<u64> {
        self.fee_credit_buckets.get(bucket_id).map(|bucket| {
            if bucket.max_fee_units == 0 {
                0
            } else {
                bucket
                    .reserved_fee_units
                    .saturating_mul(MAX_BPS)
                    .saturating_div(bucket.max_fee_units)
            }
        })
    }

    fn expire_old_records(&mut self) {
        for intent in self.private_intents.values_mut() {
            if intent.status.live() && self.current_height > intent.expires_height {
                intent.status = IntentStatus::Expired;
            }
        }
        for attestation in self.ml_dsa_attestations.values_mut() {
            if attestation.status.counts_for_quorum()
                && self.current_height > attestation.expires_height
            {
                attestation.status = MlDsaAttestationStatus::Expired;
            }
        }
        for guard in self.replay_guards.values_mut() {
            if matches!(guard.status, ReplayGuardStatus::Observing)
                && self.current_height > guard.expires_height
            {
                guard.status = ReplayGuardStatus::Expired;
            }
        }
        for bucket in self.fee_credit_buckets.values_mut() {
            if !matches!(bucket.status, FeeCreditBucketStatus::Closed)
                && self.current_height > bucket.closes_height
            {
                bucket.status = FeeCreditBucketStatus::Closed;
            }
        }
    }

    fn recompute(&mut self) {
        self.counters.paymaster_policies = self.paymaster_policies.len() as u64;
        self.counters.ml_dsa_attestations = self.ml_dsa_attestations.len() as u64;
        self.counters.private_intents = self.private_intents.len() as u64;
        self.counters.fee_credit_buckets = self.fee_credit_buckets.len() as u64;
        self.counters.replay_guards = self.replay_guards.len() as u64;
        self.counters.rebate_accounts = self.rebate_accounts.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.events = self.events.len() as u64;
        self.counters.active_policies = self
            .paymaster_policies
            .values()
            .filter(|policy| policy.status.accepts_intents())
            .count() as u64;
        self.counters.live_intents = self
            .private_intents
            .values()
            .filter(|intent| intent.is_live())
            .count() as u64;
        self.counters.settled_intents = self
            .private_intents
            .values()
            .filter(|intent| intent.is_settled())
            .count() as u64;
        self.counters.blocked_replays = self
            .replay_guards
            .values()
            .map(|guard| guard.blocked_replay_count)
            .sum();
        self.counters.total_reserved_fee_units = self
            .fee_credit_buckets
            .values()
            .map(|bucket| bucket.reserved_fee_units)
            .sum();
        self.counters.total_sponsored_fee_units = self
            .paymaster_policies
            .values()
            .map(|policy| policy.sponsored_units)
            .sum();
        self.counters.total_rebate_units = self
            .rebate_accounts
            .values()
            .map(|rebate| rebate.accrued_units)
            .sum();
        self.roots.config_root = value_root("CONFIG", &self.config.public_record());
        self.roots.paymaster_policy_root = map_root(
            "PAYMASTER-POLICY",
            self.paymaster_policies
                .values()
                .map(PaymasterPolicy::public_record)
                .collect(),
        );
        self.roots.ml_dsa_attestation_root = map_root(
            "ML-DSA-ATTESTATION",
            self.ml_dsa_attestations
                .values()
                .map(MlDsaAuthorizationAttestation::public_record)
                .collect(),
        );
        self.roots.private_intent_root = map_root(
            "PRIVATE-INTENT",
            self.private_intents
                .values()
                .map(SponsoredPrivateIntent::public_record)
                .collect(),
        );
        self.roots.fee_credit_bucket_root = map_root(
            "FEE-CREDIT-BUCKET",
            self.fee_credit_buckets
                .values()
                .map(FeeCreditBucket::public_record)
                .collect(),
        );
        self.roots.replay_guard_root = map_root(
            "REPLAY-GUARD",
            self.replay_guards
                .values()
                .map(ReplayNullifierGuard::public_record)
                .collect(),
        );
        self.roots.rebate_accounting_root = map_root(
            "REBATE-ACCOUNTING",
            self.rebate_accounts
                .values()
                .map(RebateAccount::public_record)
                .collect(),
        );
        self.roots.operator_summary_root = map_root(
            "OPERATOR-SUMMARY",
            self.operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect(),
        );
        self.roots.nullifier_root = merkle_root(
            "PRIVATE-AA-PAYMASTER-NULLIFIER",
            &self
                .nullifiers
                .iter()
                .map(|nullifier| {
                    json!(deterministic_id(
                        "NULLIFIER-LEAF",
                        &[HashPart::Str(nullifier)]
                    ))
                })
                .collect::<Vec<_>>(),
        );
        self.roots.event_root = map_root(
            "EVENT",
            self.events
                .values()
                .map(RuntimeEvent::public_record)
                .collect(),
        );
        self.roots.public_record_root =
            value_root("PUBLIC-RECORD", &self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "paymaster_policy_count": self.paymaster_policies.len(),
            "private_intent_count": self.private_intents.len(),
            "fee_credit_bucket_count": self.fee_credit_buckets.len(),
            "replay_guard_count": self.replay_guards.len(),
            "rebate_account_count": self.rebate_accounts.len()
        })
    }

    fn record_event(
        &mut self,
        kind: RuntimeEventKind,
        subject_id: &str,
        operator_visible: bool,
    ) -> String {
        let event_id = deterministic_id(
            "EVENT-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::U64(self.events.len() as u64 + 1),
                HashPart::U64(self.current_height),
            ],
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind,
            height: self.current_height,
            subject_id: subject_id.to_string(),
            commitment_root: deterministic_id("EVENT-COMMITMENT", &[HashPart::Str(&event_id)]),
            operator_visible,
        };
        self.events.insert(event_id.clone(), event);
        event_id
    }

    fn seed_devnet(&mut self) {
        let mut core_allowed = BTreeSet::new();
        core_allowed.insert(IntentKind::PrivateTransfer);
        core_allowed.insert(IntentKind::ContractCall);
        core_allowed.insert(IntentKind::SessionKeyRefresh);
        let core_policy = self
            .register_paymaster_policy(
                "sponsor-core-low-fee",
                SponsorshipMode::ProtocolSubsidized,
                "route-bucket-core-aa",
                2_000_000,
                core_allowed,
            )
            .expect("core paymaster policy");
        let core_bucket = self
            .open_fee_credit_bucket(&core_policy, 64_000)
            .expect("core fee bucket");
        let core_intent = self
            .submit_private_intent(
                &core_policy,
                &core_bucket,
                IntentKind::PrivateTransfer,
                "wallet-bucket-000",
                "route-bucket-core-aa",
                1_200,
            )
            .expect("core private intent");
        self.accept_ml_dsa_attestation("attestor-alpha-ml-dsa", &core_intent, 4_000)
            .expect("alpha attestation");
        self.accept_ml_dsa_attestation("attestor-beta-ml-dsa", &core_intent, 3_200)
            .expect("beta attestation");
        self.settle_private_intent(&core_intent)
            .expect("settle core intent");

        let mut merchant_allowed = BTreeSet::new();
        merchant_allowed.insert(IntentKind::PrivateTransfer);
        merchant_allowed.insert(IntentKind::TokenMint);
        merchant_allowed.insert(IntentKind::ContractCall);
        let merchant_policy = self
            .register_paymaster_policy(
                "sponsor-merchant-checkout",
                SponsorshipMode::MerchantSubsidized,
                "route-bucket-merchant-aa",
                1_250_000,
                merchant_allowed,
            )
            .expect("merchant paymaster policy");
        let merchant_bucket = self
            .open_fee_credit_bucket(&merchant_policy, 48_000)
            .expect("merchant fee bucket");
        let merchant_intent = self
            .submit_private_intent(
                &merchant_policy,
                &merchant_bucket,
                IntentKind::ContractCall,
                "wallet-bucket-merchant-021",
                "route-bucket-merchant-aa",
                2_400,
            )
            .expect("merchant private intent");
        self.accept_ml_dsa_attestation("attestor-gamma-ml-dsa", &merchant_intent, 7_000)
            .expect("gamma attestation");
        self.settle_private_intent(&merchant_intent)
            .expect("settle merchant intent");

        let replay_intent = self
            .submit_private_intent(
                &merchant_policy,
                &merchant_bucket,
                IntentKind::PrivateTransfer,
                "wallet-bucket-watchlist-004",
                "route-bucket-merchant-aa",
                600,
            )
            .expect("replay fixture intent");
        self.block_replay(&replay_intent)
            .expect("replay fixture blocked");
        self.advance_height(self.config.rebate_epoch_blocks);
        let rebate_ids = self.rebate_accounts.keys().cloned().collect::<Vec<_>>();
        for rebate_id in rebate_ids {
            let units = self
                .rebate_accounts
                .get(&rebate_id)
                .map(RebateAccount::claimable_units)
                .unwrap_or(0);
            if units > 0 {
                self.claim_rebate(&rebate_id, units)
                    .expect("devnet rebate claim");
            }
        }
        self.publish_operator_summary(OperatorSummaryAudience::Paymaster)
            .expect("paymaster summary");
        self.publish_operator_summary(OperatorSummaryAudience::Public)
            .expect("public summary");
        self.recompute();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash("PRIVATE-AA-PAYMASTER-STATE", &[HashPart::Json(record)], 32)
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("PRIVATE-AA-PAYMASTER-{domain}"), parts, 32)
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-AA-PAYMASTER-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(&format!("PRIVATE-AA-PAYMASTER-{domain}"), &[])
}

pub fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("PRIVATE-AA-PAYMASTER-{domain}"), &records)
}

pub fn validate_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} exceeds {MAX_BPS} bps"));
    }
    Ok(())
}

pub fn sponsor_units_for(fee_units: u64, sponsor_cover_bps: u64) -> u64 {
    fee_units
        .saturating_mul(sponsor_cover_bps)
        .saturating_div(MAX_BPS)
}

pub fn rebate_units_for(fee_units: u64, rebate_share_bps: u64) -> u64 {
    fee_units
        .saturating_mul(rebate_share_bps)
        .saturating_div(MAX_BPS)
}

pub fn operator_reward_units_for(fee_units: u64, operator_reward_bps: u64) -> u64 {
    fee_units
        .saturating_mul(operator_reward_bps)
        .saturating_div(MAX_BPS)
}

pub fn bucket_epoch_for(height: u64, epoch_blocks: u64) -> u64 {
    if epoch_blocks == 0 {
        0
    } else {
        height / epoch_blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_public_record_has_state_root() {
        let state = State::devnet();
        let record = state.public_record();
        assert_eq!(record["state_root"], json!(state.state_root()));
        assert!(state.counters.paymaster_policies >= 2);
        assert!(state.counters.settled_intents >= 2);
        assert!(state.counters.blocked_replays >= 1);
    }

    #[test]
    fn sponsorship_math_is_deterministic() {
        assert_eq!(sponsor_units_for(1_200, 9_500), 1_140);
        assert_eq!(rebate_units_for(1_200, 1_500), 180);
        assert_eq!(operator_reward_units_for(2_400, 250), 60);
        assert_eq!(bucket_epoch_for(1_128_000, 720), 1_566);
    }
}
