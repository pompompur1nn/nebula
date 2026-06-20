use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type ZkDefiPrivateCreditScoreOracleResult<T> = Result<T, String>;

pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROTOCOL_VERSION: &str =
    "nebula-zk-defi-private-credit-score-oracle-v1";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROOF_SYSTEM: &str =
    "recursive-private-credit-score-attestation-v1";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_SCORE_CIRCUIT: &str =
    "private-defi-credit-bucket-range-proof-v1";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DISCLOSURE_CIRCUIT: &str =
    "selective-credit-disclosure-nullifier-proof-v1";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_COMMITTEE_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_KEM_SCHEME: &str = "ML-KEM-1024";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_UPDATE_FEE_ASSET_ID: &str = "asset:dxmr";
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEVNET_HEIGHT: u64 = 1_444;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS: u64 = 10_000;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SCORE_TTL_BLOCKS: u64 = 2_880;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 144;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_LANE_TTL_BLOCKS: u64 = 36;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MIN_SCORE_QUORUM_BPS: u64 = 6_700;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MARKET_QUORUM_BPS: u64 = 6_000;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SUPERMAJORITY_BPS: u64 = 7_500;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MAX_SCORE_DRIFT_BPS: u64 = 1_200;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_STALE_GRACE_BLOCKS: u64 = 18;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_LOW_FEE_CAP_UNITS: u64 = 4;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 240_000;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_MARKETS: usize = 2_048;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_SCORE_MODELS: usize = 512;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BUCKETS: usize = 128;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_COMMITTEES: usize = 512;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_MEMBERS: usize = 16_384;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_SCORE_ATTESTATIONS: usize = 262_144;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_DISCLOSURES: usize = 262_144;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_MARKET_HOOKS: usize = 65_536;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_STALE_FENCES: usize = 65_536;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_LOW_FEE_LANES: usize = 65_536;
pub const ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditModelKind {
    WalletCashflow,
    PrivateBorrowHistory,
    CollateralStability,
    RepaymentVelocity,
    RiskAdjustedUtilization,
    IdentityCredential,
    TreasuryAttestation,
    MarketBehavior,
    CrossRollupReputation,
    MoneroReserveBacked,
}

impl CreditModelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletCashflow => "wallet_cashflow",
            Self::PrivateBorrowHistory => "private_borrow_history",
            Self::CollateralStability => "collateral_stability",
            Self::RepaymentVelocity => "repayment_velocity",
            Self::RiskAdjustedUtilization => "risk_adjusted_utilization",
            Self::IdentityCredential => "identity_credential",
            Self::TreasuryAttestation => "treasury_attestation",
            Self::MarketBehavior => "market_behavior",
            Self::CrossRollupReputation => "cross_rollup_reputation",
            Self::MoneroReserveBacked => "monero_reserve_backed",
        }
    }

    pub fn default_weight_bps(self) -> u64 {
        match self {
            Self::WalletCashflow => 1_600,
            Self::PrivateBorrowHistory => 1_800,
            Self::CollateralStability => 1_400,
            Self::RepaymentVelocity => 1_100,
            Self::RiskAdjustedUtilization => 1_250,
            Self::IdentityCredential => 700,
            Self::TreasuryAttestation => 650,
            Self::MarketBehavior => 900,
            Self::CrossRollupReputation => 850,
            Self::MoneroReserveBacked => 750,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreBucket {
    PrimeA,
    PrimeB,
    NearPrime,
    Standard,
    Watch,
    Restricted,
    Denied,
}

impl ScoreBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrimeA => "prime_a",
            Self::PrimeB => "prime_b",
            Self::NearPrime => "near_prime",
            Self::Standard => "standard",
            Self::Watch => "watch",
            Self::Restricted => "restricted",
            Self::Denied => "denied",
        }
    }

    pub fn min_score(self) -> u16 {
        match self {
            Self::PrimeA => 820,
            Self::PrimeB => 760,
            Self::NearPrime => 700,
            Self::Standard => 620,
            Self::Watch => 560,
            Self::Restricted => 500,
            Self::Denied => 0,
        }
    }

    pub fn max_ltv_bps(self) -> u64 {
        match self {
            Self::PrimeA => 8_000,
            Self::PrimeB => 7_200,
            Self::NearPrime => 6_400,
            Self::Standard => 5_500,
            Self::Watch => 4_200,
            Self::Restricted => 2_500,
            Self::Denied => 0,
        }
    }

    pub fn borrow_enabled(self) -> bool {
        !matches!(self, Self::Denied | Self::Restricted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreStatus {
    Pending,
    Attested,
    Active,
    Stale,
    Fenced,
    Revoked,
    Expired,
}

impl ScoreStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Fenced => "fenced",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn market_usable(self) -> bool {
        matches!(self, Self::Attested | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureKind {
    BucketOnly,
    LtvBand,
    RateTier,
    MaxBorrowBand,
    TenorBand,
    DefaultRiskBand,
    WatchtowerAudit,
    RegulatorAudit,
    LiquidationOverride,
}

impl DisclosureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BucketOnly => "bucket_only",
            Self::LtvBand => "ltv_band",
            Self::RateTier => "rate_tier",
            Self::MaxBorrowBand => "max_borrow_band",
            Self::TenorBand => "tenor_band",
            Self::DefaultRiskBand => "default_risk_band",
            Self::WatchtowerAudit => "watchtower_audit",
            Self::RegulatorAudit => "regulator_audit",
            Self::LiquidationOverride => "liquidation_override",
        }
    }

    pub fn reveals_raw_score(self) -> bool {
        matches!(self, Self::WatchtowerAudit | Self::RegulatorAudit)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketHookKind {
    BorrowLimit,
    CollateralFactor,
    InterestRateTier,
    TenorLimit,
    LiquidationBuffer,
    InsurancePremium,
    CreditLineRenewal,
    PaymasterAllowance,
    PrivateIntentAdmission,
}

impl MarketHookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BorrowLimit => "borrow_limit",
            Self::CollateralFactor => "collateral_factor",
            Self::InterestRateTier => "interest_rate_tier",
            Self::TenorLimit => "tenor_limit",
            Self::LiquidationBuffer => "liquidation_buffer",
            Self::InsurancePremium => "insurance_premium",
            Self::CreditLineRenewal => "credit_line_renewal",
            Self::PaymasterAllowance => "paymaster_allowance",
            Self::PrivateIntentAdmission => "private_intent_admission",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    ScoreAttester,
    ModelAuditor,
    DisclosureVerifier,
    MarketHookSigner,
    StaleFenceSigner,
    LowFeeLaneAuditor,
    Watchtower,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScoreAttester => "score_attester",
            Self::ModelAuditor => "model_auditor",
            Self::DisclosureVerifier => "disclosure_verifier",
            Self::MarketHookSigner => "market_hook_signer",
            Self::StaleFenceSigner => "stale_fence_signer",
            Self::LowFeeLaneAuditor => "low_fee_lane_auditor",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Active,
    Suspended,
    RotatingIn,
    RotatingOut,
    Slashed,
    Retired,
}

impl MemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::RotatingIn => "rotating_in",
            Self::RotatingOut => "rotating_out",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_sign(self) -> bool {
        matches!(self, Self::Active | Self::RotatingIn | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    StaleScore,
    ModelDrift,
    WeakPrivacySet,
    CommitteeDisagreement,
    DisclosureReplay,
    MarketCircuitBreaker,
    RevocationWitness,
}

impl FenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleScore => "stale_score",
            Self::ModelDrift => "model_drift",
            Self::WeakPrivacySet => "weak_privacy_set",
            Self::CommitteeDisagreement => "committee_disagreement",
            Self::DisclosureReplay => "disclosure_replay",
            Self::MarketCircuitBreaker => "market_circuit_breaker",
            Self::RevocationWitness => "revocation_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Sponsored,
    Draining,
    Paused,
    Expired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Sponsored => "sponsored",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_updates(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::Sponsored)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub epoch_blocks: u64,
    pub score_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub lane_ttl_blocks: u64,
    pub stale_grace_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_score_quorum_bps: u64,
    pub market_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub max_score_drift_bps: u64,
    pub low_fee_cap_units: u64,
    pub sponsor_budget_units: u64,
    pub max_markets: usize,
    pub max_score_models: usize,
    pub max_buckets: usize,
    pub max_committees: usize,
    pub max_members: usize,
    pub max_score_attestations: usize,
    pub max_disclosures: usize,
    pub max_market_hooks: usize,
    pub max_stale_fences: usize,
    pub max_low_fee_lanes: usize,
    pub max_events: usize,
    pub hash_suite: String,
    pub proof_system: String,
    pub score_circuit: String,
    pub disclosure_circuit: String,
    pub committee_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub kem_scheme: String,
    pub update_fee_asset_id: String,
    pub privacy_policy_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let privacy_policy_root = string_list_root(
            "privacy-policy",
            &[
                "bucket-only-lending-hooks",
                "score-nullifier-non-linkability",
                "range-proofed-model-features",
                "selective-disclosure-by-purpose",
                "stale-score-market-fences",
                "low-fee-sponsored-score-refresh",
            ],
        );
        Self {
            epoch_blocks: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_EPOCH_BLOCKS,
            score_ttl_blocks: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SCORE_TTL_BLOCKS,
            attestation_ttl_blocks:
                ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            disclosure_ttl_blocks:
                ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            lane_ttl_blocks: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_LANE_TTL_BLOCKS,
            stale_grace_blocks: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_STALE_GRACE_BLOCKS,
            min_privacy_set_size: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_score_quorum_bps: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MIN_SCORE_QUORUM_BPS,
            market_quorum_bps: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MARKET_QUORUM_BPS,
            supermajority_bps: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SUPERMAJORITY_BPS,
            max_score_drift_bps: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MAX_SCORE_DRIFT_BPS,
            low_fee_cap_units: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_LOW_FEE_CAP_UNITS,
            sponsor_budget_units: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_markets: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_MARKETS,
            max_score_models: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_SCORE_MODELS,
            max_buckets: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BUCKETS,
            max_committees: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_COMMITTEES,
            max_members: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_MEMBERS,
            max_score_attestations: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_SCORE_ATTESTATIONS,
            max_disclosures: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_DISCLOSURES,
            max_market_hooks: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_MARKET_HOOKS,
            max_stale_fences: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_STALE_FENCES,
            max_low_fee_lanes: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_LOW_FEE_LANES,
            max_events: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_EVENTS,
            hash_suite: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_HASH_SUITE.to_string(),
            proof_system: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROOF_SYSTEM.to_string(),
            score_circuit: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_SCORE_CIRCUIT.to_string(),
            disclosure_circuit: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DISCLOSURE_CIRCUIT.to_string(),
            committee_signature_scheme:
                ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_COMMITTEE_SIGNATURE_SCHEME.to_string(),
            backup_signature_scheme: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            kem_scheme: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_KEM_SCHEME.to_string(),
            update_fee_asset_id: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_UPDATE_FEE_ASSET_ID
                .to_string(),
            privacy_policy_root,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.epoch_blocks == 0
            || self.score_ttl_blocks == 0
            || self.attestation_ttl_blocks == 0
            || self.disclosure_ttl_blocks == 0
            || self.lane_ttl_blocks == 0
        {
            return Err("private credit score oracle windows must be non-zero".to_string());
        }
        if self.stale_grace_blocks >= self.score_ttl_blocks {
            return Err("private credit stale grace must fit inside score ttl".to_string());
        }
        if self.attestation_ttl_blocks >= self.score_ttl_blocks {
            return Err("private credit attestation ttl must fit inside score ttl".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("private credit privacy set size must be non-zero".to_string());
        }
        if self.min_score_quorum_bps == 0
            || self.market_quorum_bps == 0
            || self.supermajority_bps == 0
            || self.min_score_quorum_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
            || self.market_quorum_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
            || self.supermajority_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
            || self.max_score_drift_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
        {
            return Err("private credit quorum and drift bps must be in range".to_string());
        }
        if self.low_fee_cap_units == 0 || self.sponsor_budget_units == 0 {
            return Err("private credit low-fee lane budgets must be non-zero".to_string());
        }
        if self.max_markets == 0
            || self.max_score_models == 0
            || self.max_buckets == 0
            || self.max_committees == 0
            || self.max_members == 0
            || self.max_score_attestations == 0
            || self.max_disclosures == 0
            || self.max_market_hooks == 0
            || self.max_stale_fences == 0
            || self.max_low_fee_lanes == 0
            || self.max_events == 0
        {
            return Err("private credit oracle capacities must be non-zero".to_string());
        }
        for (name, value) in [
            ("hash_suite", self.hash_suite.as_str()),
            ("proof_system", self.proof_system.as_str()),
            ("score_circuit", self.score_circuit.as_str()),
            ("disclosure_circuit", self.disclosure_circuit.as_str()),
            (
                "committee_signature_scheme",
                self.committee_signature_scheme.as_str(),
            ),
            (
                "backup_signature_scheme",
                self.backup_signature_scheme.as_str(),
            ),
            ("kem_scheme", self.kem_scheme.as_str()),
            ("update_fee_asset_id", self.update_fee_asset_id.as_str()),
            ("privacy_policy_root", self.privacy_policy_root.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "private credit config field {name} cannot be empty"
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "score_ttl_blocks": self.score_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "lane_ttl_blocks": self.lane_ttl_blocks,
            "stale_grace_blocks": self.stale_grace_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_score_quorum_bps": self.min_score_quorum_bps,
            "market_quorum_bps": self.market_quorum_bps,
            "supermajority_bps": self.supermajority_bps,
            "max_score_drift_bps": self.max_score_drift_bps,
            "low_fee_cap_units": self.low_fee_cap_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "max_markets": self.max_markets,
            "max_score_models": self.max_score_models,
            "max_buckets": self.max_buckets,
            "max_committees": self.max_committees,
            "max_members": self.max_members,
            "max_score_attestations": self.max_score_attestations,
            "max_disclosures": self.max_disclosures,
            "max_market_hooks": self.max_market_hooks,
            "max_stale_fences": self.max_stale_fences,
            "max_low_fee_lanes": self.max_low_fee_lanes,
            "max_events": self.max_events,
            "hash_suite": self.hash_suite,
            "proof_system": self.proof_system,
            "score_circuit": self.score_circuit,
            "disclosure_circuit": self.disclosure_circuit,
            "committee_signature_scheme": self.committee_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "kem_scheme": self.kem_scheme,
            "update_fee_asset_id": self.update_fee_asset_id,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreModel {
    pub model_id: String,
    pub kind: CreditModelKind,
    pub model_commitment: String,
    pub feature_commitment_root: String,
    pub parameter_commitment_root: String,
    pub auditor_set_root: String,
    pub weight_bps: u64,
    pub min_privacy_set_size: u64,
    pub active_from_height: u64,
    pub retires_at_height: u64,
}

impl ScoreModel {
    pub fn new(label: &str, kind: CreditModelKind, active_from_height: u64) -> Self {
        let model_id = stable_id("score-model", &[label, kind.as_str()]);
        let model_commitment = commitment("model", &[label, kind.as_str()]);
        let feature_commitment_root = string_list_root(
            "model-features",
            &[
                "private-cashflow-range",
                "borrow-utilization-band",
                "repayment-velocity-band",
                "collateral-stability-band",
            ],
        );
        let parameter_commitment_root = string_list_root(
            "model-parameters",
            &[
                "monotonic-risk-weights",
                "calibrated-score-bounds",
                "drift-limited-updates",
            ],
        );
        let auditor_set_root = string_list_root(
            "model-auditors",
            &["committee-risk", "committee-privacy", "committee-market"],
        );
        Self {
            model_id,
            kind,
            model_commitment,
            feature_commitment_root,
            parameter_commitment_root,
            auditor_set_root,
            weight_bps: kind.default_weight_bps(),
            min_privacy_set_size: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            active_from_height,
            retires_at_height: active_from_height
                + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_EPOCH_BLOCKS * 8,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.model_id.trim().is_empty() || self.model_commitment.trim().is_empty() {
            return Err("private credit score model identifiers cannot be empty".to_string());
        }
        if self.feature_commitment_root.trim().is_empty()
            || self.parameter_commitment_root.trim().is_empty()
            || self.auditor_set_root.trim().is_empty()
        {
            return Err("private credit score model roots cannot be empty".to_string());
        }
        if self.weight_bps == 0
            || self.weight_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
            || self.min_privacy_set_size == 0
        {
            return Err("private credit score model weights must be in range".to_string());
        }
        if self.retires_at_height <= self.active_from_height {
            return Err("private credit score model retirement must follow activation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "model_id": self.model_id,
            "kind": self.kind.as_str(),
            "model_commitment": self.model_commitment,
            "feature_commitment_root": self.feature_commitment_root,
            "parameter_commitment_root": self.parameter_commitment_root,
            "auditor_set_root": self.auditor_set_root,
            "weight_bps": self.weight_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "active_from_height": self.active_from_height,
            "retires_at_height": self.retires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskBucketPolicy {
    pub bucket_id: String,
    pub bucket: ScoreBucket,
    pub min_score: u16,
    pub max_ltv_bps: u64,
    pub base_rate_bps: u64,
    pub liquidation_buffer_bps: u64,
    pub max_tenor_blocks: u64,
    pub max_borrow_notional_band: String,
    pub disclosure_template_root: String,
}

impl RiskBucketPolicy {
    pub fn new(bucket: ScoreBucket) -> Self {
        let bucket_name = bucket.as_str();
        let bucket_id = stable_id("risk-bucket", &[bucket_name]);
        let disclosure_template_root = string_list_root(
            "bucket-disclosure-template",
            &[
                bucket_name,
                "bucket-membership",
                "ltv-band",
                "rate-tier",
                "expiry-height",
            ],
        );
        Self {
            bucket_id,
            bucket,
            min_score: bucket.min_score(),
            max_ltv_bps: bucket.max_ltv_bps(),
            base_rate_bps: match bucket {
                ScoreBucket::PrimeA => 220,
                ScoreBucket::PrimeB => 340,
                ScoreBucket::NearPrime => 520,
                ScoreBucket::Standard => 780,
                ScoreBucket::Watch => 1_200,
                ScoreBucket::Restricted => 2_000,
                ScoreBucket::Denied => 0,
            },
            liquidation_buffer_bps: match bucket {
                ScoreBucket::PrimeA => 650,
                ScoreBucket::PrimeB => 800,
                ScoreBucket::NearPrime => 1_000,
                ScoreBucket::Standard => 1_300,
                ScoreBucket::Watch => 1_800,
                ScoreBucket::Restricted => 2_500,
                ScoreBucket::Denied => 10_000,
            },
            max_tenor_blocks: match bucket {
                ScoreBucket::PrimeA => 172_800,
                ScoreBucket::PrimeB => 129_600,
                ScoreBucket::NearPrime => 86_400,
                ScoreBucket::Standard => 43_200,
                ScoreBucket::Watch => 14_400,
                ScoreBucket::Restricted => 3_600,
                ScoreBucket::Denied => 0,
            },
            max_borrow_notional_band: match bucket {
                ScoreBucket::PrimeA => "band:private-notional-very-high",
                ScoreBucket::PrimeB => "band:private-notional-high",
                ScoreBucket::NearPrime => "band:private-notional-medium-high",
                ScoreBucket::Standard => "band:private-notional-medium",
                ScoreBucket::Watch => "band:private-notional-low",
                ScoreBucket::Restricted => "band:private-notional-minimum",
                ScoreBucket::Denied => "band:private-notional-zero",
            }
            .to_string(),
            disclosure_template_root,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.bucket_id.trim().is_empty() || self.disclosure_template_root.trim().is_empty() {
            return Err("private credit bucket policy roots cannot be empty".to_string());
        }
        if self.min_score != self.bucket.min_score() {
            return Err("private credit bucket minimum score mismatch".to_string());
        }
        if self.max_ltv_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
            || self.base_rate_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
            || self.liquidation_buffer_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
        {
            return Err("private credit bucket bps fields must be in range".to_string());
        }
        if self.max_tenor_blocks == 0 && self.bucket.borrow_enabled() {
            return Err("private credit borrowable buckets require tenor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "bucket": self.bucket.as_str(),
            "min_score": self.min_score,
            "max_ltv_bps": self.max_ltv_bps,
            "base_rate_bps": self.base_rate_bps,
            "liquidation_buffer_bps": self.liquidation_buffer_bps,
            "max_tenor_blocks": self.max_tenor_blocks,
            "max_borrow_notional_band": self.max_borrow_notional_band,
            "disclosure_template_root": self.disclosure_template_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleCommittee {
    pub committee_id: String,
    pub role: CommitteeRole,
    pub epoch: u64,
    pub member_root: String,
    pub threshold_weight_bps: u64,
    pub pq_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub transcript_root: String,
}

impl OracleCommittee {
    pub fn new(role: CommitteeRole, epoch: u64, member_records: &[Value]) -> Self {
        let role_name = role.as_str();
        let committee_id = stable_id("committee", &[role_name, &epoch.to_string()]);
        let member_root = merkle_root("PRIVATE-CREDIT-COMMITTEE-MEMBER", member_records);
        let transcript_root = payload_root(
            "committee-transcript",
            &json!({
                "role": role_name,
                "epoch": epoch,
                "member_root": member_root,
                "signature_scheme": ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_COMMITTEE_SIGNATURE_SCHEME,
            }),
        );
        Self {
            committee_id,
            role,
            epoch,
            member_root,
            threshold_weight_bps: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MIN_SCORE_QUORUM_BPS,
            pq_signature_scheme: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_COMMITTEE_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            transcript_root,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.committee_id.trim().is_empty()
            || self.member_root.trim().is_empty()
            || self.transcript_root.trim().is_empty()
        {
            return Err("private credit committee roots cannot be empty".to_string());
        }
        if self.threshold_weight_bps == 0
            || self.threshold_weight_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
        {
            return Err("private credit committee threshold must be in range".to_string());
        }
        if self.pq_signature_scheme.trim().is_empty()
            || self.backup_signature_scheme.trim().is_empty()
        {
            return Err("private credit committee signature schemes cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "role": self.role.as_str(),
            "epoch": self.epoch,
            "member_root": self.member_root,
            "threshold_weight_bps": self.threshold_weight_bps,
            "pq_signature_scheme": self.pq_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub role: CommitteeRole,
    pub status: MemberStatus,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub stake_bond_commitment: String,
    pub voting_weight_bps: u64,
    pub joined_at_height: u64,
    pub rotates_at_height: u64,
}

impl CommitteeMember {
    pub fn new(label: &str, role: CommitteeRole, voting_weight_bps: u64, height: u64) -> Self {
        let role_name = role.as_str();
        let member_id = stable_id("member", &[label, role_name]);
        Self {
            member_id,
            operator_commitment: commitment("operator", &[label]),
            role,
            status: MemberStatus::Active,
            pq_public_key_commitment: commitment("ml-dsa-key", &[label, role_name]),
            backup_public_key_commitment: commitment("slh-dsa-key", &[label, role_name]),
            stake_bond_commitment: commitment("stake-bond", &[label, role_name]),
            voting_weight_bps,
            joined_at_height: height,
            rotates_at_height: height
                + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_EPOCH_BLOCKS * 4,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.member_id.trim().is_empty()
            || self.operator_commitment.trim().is_empty()
            || self.pq_public_key_commitment.trim().is_empty()
            || self.backup_public_key_commitment.trim().is_empty()
            || self.stake_bond_commitment.trim().is_empty()
        {
            return Err("private credit committee member commitments cannot be empty".to_string());
        }
        if self.voting_weight_bps == 0
            || self.voting_weight_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
        {
            return Err("private credit committee member weight must be in range".to_string());
        }
        if self.rotates_at_height <= self.joined_at_height {
            return Err("private credit committee member rotation must follow join".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "can_sign": self.status.can_sign(),
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_public_key_commitment": self.backup_public_key_commitment,
            "stake_bond_commitment": self.stake_bond_commitment,
            "voting_weight_bps": self.voting_weight_bps,
            "joined_at_height": self.joined_at_height,
            "rotates_at_height": self.rotates_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateScoreAttestation {
    pub attestation_id: String,
    pub account_nullifier: String,
    pub score_commitment: String,
    pub score_bucket: ScoreBucket,
    pub status: ScoreStatus,
    pub model_root: String,
    pub feature_root: String,
    pub proof_root: String,
    pub committee_id: String,
    pub aggregate_signature_root: String,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub stale_after_height: u64,
}

impl PrivateScoreAttestation {
    pub fn new(
        account_label: &str,
        score_bucket: ScoreBucket,
        model_root: &str,
        committee_id: &str,
        issued_at_height: u64,
    ) -> Self {
        let account_nullifier = commitment("account-nullifier", &[account_label]);
        let score_commitment = commitment("score", &[account_label, score_bucket.as_str()]);
        let feature_root = string_list_root(
            "score-private-features",
            &[
                "income-range-proof",
                "repayment-range-proof",
                "utilization-range-proof",
                "collateral-stability-proof",
            ],
        );
        let proof_root = payload_root(
            "score-proof",
            &json!({
                "account_nullifier": account_nullifier,
                "bucket": score_bucket.as_str(),
                "model_root": model_root,
                "feature_root": feature_root,
                "proof_system": ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROOF_SYSTEM,
            }),
        );
        let aggregate_signature_root = payload_root(
            "score-aggregate-signature",
            &json!({
                "committee_id": committee_id,
                "proof_root": proof_root,
                "scheme": ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_COMMITTEE_SIGNATURE_SCHEME,
            }),
        );
        Self {
            attestation_id: stable_id(
                "score-attestation",
                &[
                    account_label,
                    score_bucket.as_str(),
                    &issued_at_height.to_string(),
                ],
            ),
            account_nullifier,
            score_commitment,
            score_bucket,
            status: ScoreStatus::Active,
            model_root: model_root.to_string(),
            feature_root,
            proof_root,
            committee_id: committee_id.to_string(),
            aggregate_signature_root,
            privacy_set_size: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_MIN_PRIVACY_SET_SIZE
                + 512,
            issued_at_height,
            expires_at_height: issued_at_height
                + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SCORE_TTL_BLOCKS,
            stale_after_height: issued_at_height
                + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SCORE_TTL_BLOCKS
                - ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_STALE_GRACE_BLOCKS,
        }
    }

    pub fn is_stale_at(&self, height: u64) -> bool {
        height >= self.stale_after_height || matches!(self.status, ScoreStatus::Stale)
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height || matches!(self.status, ScoreStatus::Expired)
    }

    pub fn validate(&self, config: &Config) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.attestation_id.trim().is_empty()
            || self.account_nullifier.trim().is_empty()
            || self.score_commitment.trim().is_empty()
            || self.model_root.trim().is_empty()
            || self.feature_root.trim().is_empty()
            || self.proof_root.trim().is_empty()
            || self.committee_id.trim().is_empty()
            || self.aggregate_signature_root.trim().is_empty()
        {
            return Err("private credit score attestation roots cannot be empty".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("private credit score attestation privacy set too small".to_string());
        }
        if self.stale_after_height <= self.issued_at_height
            || self.expires_at_height <= self.stale_after_height
        {
            return Err("private credit score attestation freshness windows invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "account_nullifier": self.account_nullifier,
            "score_commitment": self.score_commitment,
            "score_bucket": self.score_bucket.as_str(),
            "status": self.status.as_str(),
            "market_usable": self.status.market_usable(),
            "model_root": self.model_root,
            "feature_root": self.feature_root,
            "proof_root": self.proof_root,
            "committee_id": self.committee_id,
            "aggregate_signature_root": self.aggregate_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "stale_after_height": self.stale_after_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosure {
    pub disclosure_id: String,
    pub attestation_id: String,
    pub purpose: DisclosureKind,
    pub market_id: String,
    pub disclosed_bucket: ScoreBucket,
    pub disclosure_nullifier: String,
    pub audience_commitment: String,
    pub proof_root: String,
    pub policy_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SelectiveDisclosure {
    pub fn new(
        attestation_id: &str,
        purpose: DisclosureKind,
        market_id: &str,
        disclosed_bucket: ScoreBucket,
        height: u64,
    ) -> Self {
        let purpose_name = purpose.as_str();
        let disclosure_nullifier = commitment(
            "disclosure-nullifier",
            &[attestation_id, purpose_name, market_id, &height.to_string()],
        );
        let audience_commitment = commitment("disclosure-audience", &[market_id, purpose_name]);
        let policy_root = string_list_root(
            "disclosure-policy",
            &[
                purpose_name,
                "purpose-bound",
                "non-transferable",
                "ttl-bound",
                "nullifier-protected",
            ],
        );
        let proof_root = payload_root(
            "selective-disclosure-proof",
            &json!({
                "attestation_id": attestation_id,
                "purpose": purpose_name,
                "market_id": market_id,
                "bucket": disclosed_bucket.as_str(),
                "policy_root": policy_root,
            }),
        );
        Self {
            disclosure_id: stable_id(
                "selective-disclosure",
                &[attestation_id, purpose_name, market_id, &height.to_string()],
            ),
            attestation_id: attestation_id.to_string(),
            purpose,
            market_id: market_id.to_string(),
            disclosed_bucket,
            disclosure_nullifier,
            audience_commitment,
            proof_root,
            policy_root,
            issued_at_height: height,
            expires_at_height: height
                + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_DISCLOSURE_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.disclosure_id.trim().is_empty()
            || self.attestation_id.trim().is_empty()
            || self.market_id.trim().is_empty()
            || self.disclosure_nullifier.trim().is_empty()
            || self.audience_commitment.trim().is_empty()
            || self.proof_root.trim().is_empty()
            || self.policy_root.trim().is_empty()
        {
            return Err("private credit disclosure roots cannot be empty".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("private credit disclosure expiry must follow issue height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "disclosure_id": self.disclosure_id,
            "attestation_id": self.attestation_id,
            "purpose": self.purpose.as_str(),
            "reveals_raw_score": self.purpose.reveals_raw_score(),
            "market_id": self.market_id,
            "disclosed_bucket": self.disclosed_bucket.as_str(),
            "disclosure_nullifier": self.disclosure_nullifier,
            "audience_commitment": self.audience_commitment,
            "proof_root": self.proof_root,
            "policy_root": self.policy_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LendingMarketHook {
    pub hook_id: String,
    pub market_id: String,
    pub hook_kind: MarketHookKind,
    pub accepted_bucket_root: String,
    pub policy_root: String,
    pub oracle_committee_id: String,
    pub market_contract_commitment: String,
    pub max_ltv_bps: u64,
    pub rate_spread_bps: u64,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
}

impl LendingMarketHook {
    pub fn new(
        market_label: &str,
        hook_kind: MarketHookKind,
        bucket_records: &[Value],
        committee_id: &str,
        height: u64,
    ) -> Self {
        let hook_name = hook_kind.as_str();
        let market_id = stable_id("lending-market", &[market_label]);
        let accepted_bucket_root = merkle_root("PRIVATE-CREDIT-HOOK-BUCKETS", bucket_records);
        let policy_root = payload_root(
            "market-hook-policy",
            &json!({
                "market_label": market_label,
                "hook_kind": hook_name,
                "bucket_root": accepted_bucket_root,
                "purpose": "private-credit-risk-gating",
            }),
        );
        Self {
            hook_id: stable_id(
                "market-hook",
                &[market_label, hook_name, &height.to_string()],
            ),
            market_id,
            hook_kind,
            accepted_bucket_root,
            policy_root,
            oracle_committee_id: committee_id.to_string(),
            market_contract_commitment: commitment("market-contract", &[market_label]),
            max_ltv_bps: 7_200,
            rate_spread_bps: 360,
            effective_at_height: height,
            expires_at_height: height
                + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_EPOCH_BLOCKS * 2,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.hook_id.trim().is_empty()
            || self.market_id.trim().is_empty()
            || self.accepted_bucket_root.trim().is_empty()
            || self.policy_root.trim().is_empty()
            || self.oracle_committee_id.trim().is_empty()
            || self.market_contract_commitment.trim().is_empty()
        {
            return Err("private credit lending market hook roots cannot be empty".to_string());
        }
        if self.max_ltv_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
            || self.rate_spread_bps > ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_MAX_BPS
        {
            return Err(
                "private credit lending market hook bps fields must be in range".to_string(),
            );
        }
        if self.expires_at_height <= self.effective_at_height {
            return Err(
                "private credit lending market hook expiry must follow effective height"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "market_id": self.market_id,
            "hook_kind": self.hook_kind.as_str(),
            "accepted_bucket_root": self.accepted_bucket_root,
            "policy_root": self.policy_root,
            "oracle_committee_id": self.oracle_committee_id,
            "market_contract_commitment": self.market_contract_commitment,
            "max_ltv_bps": self.max_ltv_bps,
            "rate_spread_bps": self.rate_spread_bps,
            "effective_at_height": self.effective_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaleScoreFence {
    pub fence_id: String,
    pub attestation_id: String,
    pub account_nullifier: String,
    pub reason: FenceReason,
    pub market_id: String,
    pub fence_root: String,
    pub witness_root: String,
    pub signer_committee_id: String,
    pub opened_at_height: u64,
    pub clears_after_height: u64,
}

impl StaleScoreFence {
    pub fn new(
        attestation: &PrivateScoreAttestation,
        reason: FenceReason,
        market_id: &str,
        committee_id: &str,
        height: u64,
    ) -> Self {
        let reason_name = reason.as_str();
        let witness_root = payload_root(
            "stale-score-fence-witness",
            &json!({
                "attestation_id": attestation.attestation_id,
                "account_nullifier": attestation.account_nullifier,
                "reason": reason_name,
                "market_id": market_id,
                "height": height,
            }),
        );
        let fence_root = payload_root(
            "stale-score-fence",
            &json!({
                "witness_root": witness_root,
                "committee_id": committee_id,
                "reason": reason_name,
            }),
        );
        Self {
            fence_id: stable_id(
                "stale-fence",
                &[&attestation.attestation_id, reason_name, market_id],
            ),
            attestation_id: attestation.attestation_id.clone(),
            account_nullifier: attestation.account_nullifier.clone(),
            reason,
            market_id: market_id.to_string(),
            fence_root,
            witness_root,
            signer_committee_id: committee_id.to_string(),
            opened_at_height: height,
            clears_after_height: height
                + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_STALE_GRACE_BLOCKS,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.fence_id.trim().is_empty()
            || self.attestation_id.trim().is_empty()
            || self.account_nullifier.trim().is_empty()
            || self.market_id.trim().is_empty()
            || self.fence_root.trim().is_empty()
            || self.witness_root.trim().is_empty()
            || self.signer_committee_id.trim().is_empty()
        {
            return Err("private credit stale fence roots cannot be empty".to_string());
        }
        if self.clears_after_height <= self.opened_at_height {
            return Err(
                "private credit stale fence clear height must follow open height".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "attestation_id": self.attestation_id,
            "account_nullifier": self.account_nullifier,
            "reason": self.reason.as_str(),
            "market_id": self.market_id,
            "fence_root": self.fence_root,
            "witness_root": self.witness_root,
            "signer_committee_id": self.signer_committee_id,
            "opened_at_height": self.opened_at_height,
            "clears_after_height": self.clears_after_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeUpdateLane {
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub status: LaneStatus,
    pub fee_asset_id: String,
    pub fee_cap_units: u64,
    pub remaining_budget_units: u64,
    pub admitted_update_root: String,
    pub lane_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeUpdateLane {
    pub fn new(label: &str, update_records: &[Value], height: u64) -> Self {
        let admitted_update_root = merkle_root("PRIVATE-CREDIT-LOW-FEE-UPDATES", update_records);
        let lane_policy_root = payload_root(
            "low-fee-lane-policy",
            &json!({
                "label": label,
                "fee_asset_id": ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_UPDATE_FEE_ASSET_ID,
                "admitted_update_root": admitted_update_root,
                "lane_ttl_blocks": ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_LANE_TTL_BLOCKS,
            }),
        );
        Self {
            lane_id: stable_id("low-fee-lane", &[label, &height.to_string()]),
            sponsor_commitment: commitment("low-fee-sponsor", &[label]),
            status: LaneStatus::Sponsored,
            fee_asset_id: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_UPDATE_FEE_ASSET_ID.to_string(),
            fee_cap_units: ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_LOW_FEE_CAP_UNITS,
            remaining_budget_units:
                ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_SPONSOR_BUDGET_UNITS,
            admitted_update_root,
            lane_policy_root,
            opened_at_height: height,
            expires_at_height: height + ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEFAULT_LANE_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.lane_id.trim().is_empty()
            || self.sponsor_commitment.trim().is_empty()
            || self.fee_asset_id.trim().is_empty()
            || self.admitted_update_root.trim().is_empty()
            || self.lane_policy_root.trim().is_empty()
        {
            return Err("private credit low-fee lane roots cannot be empty".to_string());
        }
        if self.fee_cap_units == 0 || self.remaining_budget_units == 0 {
            return Err("private credit low-fee lane budgets must be non-zero".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("private credit low-fee lane expiry must follow open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "accepts_updates": self.status.accepts_updates(),
            "fee_asset_id": self.fee_asset_id,
            "fee_cap_units": self.fee_cap_units,
            "remaining_budget_units": self.remaining_budget_units,
            "admitted_update_root": self.admitted_update_root,
            "lane_policy_root": self.lane_policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl OracleEvent {
    pub fn new(kind: &str, subject_id: &str, payload: &Value, height: u64, sequence: u64) -> Self {
        let payload_root = payload_root("event-payload", payload);
        Self {
            event_id: stable_id(
                "oracle-event",
                &[kind, subject_id, &height.to_string(), &sequence.to_string()],
            ),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height: height,
            sequence,
        }
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if self.event_id.trim().is_empty()
            || self.kind.trim().is_empty()
            || self.subject_id.trim().is_empty()
            || self.payload_root.trim().is_empty()
        {
            return Err("private credit oracle event roots cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub score_model_root: String,
    pub risk_bucket_root: String,
    pub committee_root: String,
    pub member_root: String,
    pub score_attestation_root: String,
    pub selective_disclosure_root: String,
    pub lending_market_hook_root: String,
    pub stale_score_fence_root: String,
    pub low_fee_update_lane_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "score_model_root": self.score_model_root,
            "risk_bucket_root": self.risk_bucket_root,
            "committee_root": self.committee_root,
            "member_root": self.member_root,
            "score_attestation_root": self.score_attestation_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "lending_market_hook_root": self.lending_market_hook_root,
            "stale_score_fence_root": self.stale_score_fence_root,
            "low_fee_update_lane_root": self.low_fee_update_lane_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub score_models: usize,
    pub risk_buckets: usize,
    pub committees: usize,
    pub members: usize,
    pub score_attestations: usize,
    pub active_score_attestations: usize,
    pub stale_score_attestations: usize,
    pub selective_disclosures: usize,
    pub market_hooks: usize,
    pub stale_score_fences: usize,
    pub low_fee_update_lanes: usize,
    pub open_low_fee_update_lanes: usize,
    pub events: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "score_models": self.score_models,
            "risk_buckets": self.risk_buckets,
            "committees": self.committees,
            "members": self.members,
            "score_attestations": self.score_attestations,
            "active_score_attestations": self.active_score_attestations,
            "stale_score_attestations": self.stale_score_attestations,
            "selective_disclosures": self.selective_disclosures,
            "market_hooks": self.market_hooks,
            "stale_score_fences": self.stale_score_fences,
            "low_fee_update_lanes": self.low_fee_update_lanes,
            "open_low_fee_update_lanes": self.open_low_fee_update_lanes,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub score_models: Vec<ScoreModel>,
    pub risk_buckets: Vec<RiskBucketPolicy>,
    pub committees: Vec<OracleCommittee>,
    pub members: Vec<CommitteeMember>,
    pub score_attestations: Vec<PrivateScoreAttestation>,
    pub selective_disclosures: Vec<SelectiveDisclosure>,
    pub lending_market_hooks: Vec<LendingMarketHook>,
    pub stale_score_fences: Vec<StaleScoreFence>,
    pub low_fee_update_lanes: Vec<LowFeeUpdateLane>,
    pub events: Vec<OracleEvent>,
}

impl State {
    pub fn devnet() -> ZkDefiPrivateCreditScoreOracleResult<State> {
        let height = ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_DEVNET_HEIGHT;
        let config = Config::devnet();
        let score_models = vec![
            ScoreModel::new(
                "cashflow-stability-v1",
                CreditModelKind::WalletCashflow,
                height - 96,
            ),
            ScoreModel::new(
                "borrow-repayment-v1",
                CreditModelKind::PrivateBorrowHistory,
                height - 88,
            ),
            ScoreModel::new(
                "collateral-stability-v1",
                CreditModelKind::CollateralStability,
                height - 80,
            ),
            ScoreModel::new(
                "cross-rollup-reputation-v1",
                CreditModelKind::CrossRollupReputation,
                height - 72,
            ),
        ];
        let risk_buckets = vec![
            RiskBucketPolicy::new(ScoreBucket::PrimeA),
            RiskBucketPolicy::new(ScoreBucket::PrimeB),
            RiskBucketPolicy::new(ScoreBucket::NearPrime),
            RiskBucketPolicy::new(ScoreBucket::Standard),
            RiskBucketPolicy::new(ScoreBucket::Watch),
            RiskBucketPolicy::new(ScoreBucket::Restricted),
            RiskBucketPolicy::new(ScoreBucket::Denied),
        ];
        let members = vec![
            CommitteeMember::new("atlas", CommitteeRole::ScoreAttester, 1_700, height - 240),
            CommitteeMember::new("bravo", CommitteeRole::ScoreAttester, 1_650, height - 240),
            CommitteeMember::new("cipher", CommitteeRole::ScoreAttester, 1_650, height - 240),
            CommitteeMember::new(
                "delta",
                CommitteeRole::DisclosureVerifier,
                1_600,
                height - 220,
            ),
            CommitteeMember::new(
                "ember",
                CommitteeRole::MarketHookSigner,
                1_500,
                height - 220,
            ),
            CommitteeMember::new(
                "fathom",
                CommitteeRole::StaleFenceSigner,
                1_450,
                height - 200,
            ),
            CommitteeMember::new(
                "glint",
                CommitteeRole::LowFeeLaneAuditor,
                1_450,
                height - 200,
            ),
            CommitteeMember::new("helix", CommitteeRole::Watchtower, 1_000, height - 180),
        ];
        let score_member_records = members
            .iter()
            .filter(|member| member.role == CommitteeRole::ScoreAttester)
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>();
        let disclosure_member_records = members
            .iter()
            .filter(|member| member.role == CommitteeRole::DisclosureVerifier)
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>();
        let hook_member_records = members
            .iter()
            .filter(|member| member.role == CommitteeRole::MarketHookSigner)
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>();
        let fence_member_records = members
            .iter()
            .filter(|member| member.role == CommitteeRole::StaleFenceSigner)
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>();
        let lane_member_records = members
            .iter()
            .filter(|member| member.role == CommitteeRole::LowFeeLaneAuditor)
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>();
        let committees = vec![
            OracleCommittee::new(CommitteeRole::ScoreAttester, 2, &score_member_records),
            OracleCommittee::new(
                CommitteeRole::DisclosureVerifier,
                2,
                &disclosure_member_records,
            ),
            OracleCommittee::new(CommitteeRole::MarketHookSigner, 2, &hook_member_records),
            OracleCommittee::new(CommitteeRole::StaleFenceSigner, 2, &fence_member_records),
            OracleCommittee::new(CommitteeRole::LowFeeLaneAuditor, 2, &lane_member_records),
        ];
        let model_records = score_models
            .iter()
            .map(ScoreModel::public_record)
            .collect::<Vec<_>>();
        let model_root = merkle_root("PRIVATE-CREDIT-SCORE-MODELS", &model_records);
        let score_committee_id = committee_id_for_role(&committees, CommitteeRole::ScoreAttester)?;
        let disclosure_committee_id =
            committee_id_for_role(&committees, CommitteeRole::DisclosureVerifier)?;
        let hook_committee_id =
            committee_id_for_role(&committees, CommitteeRole::MarketHookSigner)?;
        let fence_committee_id =
            committee_id_for_role(&committees, CommitteeRole::StaleFenceSigner)?;
        let score_attestations = vec![
            PrivateScoreAttestation::new(
                "vault-alpha",
                ScoreBucket::PrimeA,
                &model_root,
                &score_committee_id,
                height - 24,
            ),
            PrivateScoreAttestation::new(
                "vault-beta",
                ScoreBucket::PrimeB,
                &model_root,
                &score_committee_id,
                height - 22,
            ),
            PrivateScoreAttestation::new(
                "vault-gamma",
                ScoreBucket::NearPrime,
                &model_root,
                &score_committee_id,
                height - 20,
            ),
            PrivateScoreAttestation::new(
                "vault-delta",
                ScoreBucket::Standard,
                &model_root,
                &score_committee_id,
                height - 18,
            ),
            PrivateScoreAttestation::new(
                "vault-epsilon",
                ScoreBucket::Watch,
                &model_root,
                &score_committee_id,
                height - 16,
            ),
        ];
        let selective_disclosures = score_attestations
            .iter()
            .take(4)
            .enumerate()
            .map(|(index, attestation)| {
                SelectiveDisclosure::new(
                    &attestation.attestation_id,
                    if index % 2 == 0 {
                        DisclosureKind::BucketOnly
                    } else {
                        DisclosureKind::LtvBand
                    },
                    "private-usdc-credit-market",
                    attestation.score_bucket,
                    height - 8 + index as u64,
                )
            })
            .collect::<Vec<_>>();
        let bucket_records = risk_buckets
            .iter()
            .filter(|bucket| bucket.bucket.borrow_enabled())
            .map(RiskBucketPolicy::public_record)
            .collect::<Vec<_>>();
        let lending_market_hooks = vec![
            LendingMarketHook::new(
                "private-usdc-credit-market",
                MarketHookKind::BorrowLimit,
                &bucket_records,
                &hook_committee_id,
                height - 12,
            ),
            LendingMarketHook::new(
                "private-usdc-credit-market",
                MarketHookKind::InterestRateTier,
                &bucket_records,
                &hook_committee_id,
                height - 11,
            ),
            LendingMarketHook::new(
                "private-wbtc-credit-market",
                MarketHookKind::CollateralFactor,
                &bucket_records,
                &hook_committee_id,
                height - 10,
            ),
        ];
        let stale_score_fences = score_attestations
            .iter()
            .filter(|attestation| attestation.score_bucket == ScoreBucket::Watch)
            .map(|attestation| {
                StaleScoreFence::new(
                    attestation,
                    FenceReason::ModelDrift,
                    "private-usdc-credit-market",
                    &fence_committee_id,
                    height - 2,
                )
            })
            .collect::<Vec<_>>();
        let update_records = score_attestations
            .iter()
            .map(PrivateScoreAttestation::public_record)
            .collect::<Vec<_>>();
        let low_fee_update_lanes = vec![
            LowFeeUpdateLane::new("retail-score-refresh", &update_records, height - 9),
            LowFeeUpdateLane::new("market-maker-score-refresh", &update_records, height - 7),
        ];
        let events = vec![
            OracleEvent::new(
                "score_attestation_batch",
                "devnet-score-batch",
                &json!({"score_attestations": score_attestations.len()}),
                height - 6,
                0,
            ),
            OracleEvent::new(
                "selective_disclosure_batch",
                &disclosure_committee_id,
                &json!({"selective_disclosures": selective_disclosures.len()}),
                height - 5,
                1,
            ),
            OracleEvent::new(
                "market_hook_refresh",
                &hook_committee_id,
                &json!({"market_hooks": lending_market_hooks.len()}),
                height - 4,
                2,
            ),
            OracleEvent::new(
                "low_fee_lane_opened",
                "retail-score-refresh",
                &json!({"lanes": low_fee_update_lanes.len()}),
                height - 3,
                3,
            ),
        ];
        let state = State {
            height,
            config,
            score_models,
            risk_buckets,
            committees,
            members,
            score_attestations,
            selective_disclosures,
            lending_market_hooks,
            stale_score_fences,
            low_fee_update_lanes,
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        self.config.validate()?;
        check_len(
            "score_models",
            self.score_models.len(),
            self.config.max_score_models,
        )?;
        check_len(
            "risk_buckets",
            self.risk_buckets.len(),
            self.config.max_buckets,
        )?;
        check_len(
            "committees",
            self.committees.len(),
            self.config.max_committees,
        )?;
        check_len("members", self.members.len(), self.config.max_members)?;
        check_len(
            "score_attestations",
            self.score_attestations.len(),
            self.config.max_score_attestations,
        )?;
        check_len(
            "selective_disclosures",
            self.selective_disclosures.len(),
            self.config.max_disclosures,
        )?;
        check_len(
            "lending_market_hooks",
            self.lending_market_hooks.len(),
            self.config.max_market_hooks,
        )?;
        check_len(
            "stale_score_fences",
            self.stale_score_fences.len(),
            self.config.max_stale_fences,
        )?;
        check_len(
            "low_fee_update_lanes",
            self.low_fee_update_lanes.len(),
            self.config.max_low_fee_lanes,
        )?;
        check_len("events", self.events.len(), self.config.max_events)?;

        validate_unique(
            "score model",
            self.score_models.iter().map(|item| item.model_id.as_str()),
        )?;
        validate_unique(
            "risk bucket",
            self.risk_buckets.iter().map(|item| item.bucket_id.as_str()),
        )?;
        validate_unique(
            "committee",
            self.committees
                .iter()
                .map(|item| item.committee_id.as_str()),
        )?;
        validate_unique(
            "member",
            self.members.iter().map(|item| item.member_id.as_str()),
        )?;
        validate_unique(
            "score attestation",
            self.score_attestations
                .iter()
                .map(|item| item.attestation_id.as_str()),
        )?;
        validate_unique(
            "selective disclosure",
            self.selective_disclosures
                .iter()
                .map(|item| item.disclosure_id.as_str()),
        )?;
        validate_unique(
            "lending market hook",
            self.lending_market_hooks
                .iter()
                .map(|item| item.hook_id.as_str()),
        )?;
        validate_unique(
            "stale score fence",
            self.stale_score_fences
                .iter()
                .map(|item| item.fence_id.as_str()),
        )?;
        validate_unique(
            "low fee update lane",
            self.low_fee_update_lanes
                .iter()
                .map(|item| item.lane_id.as_str()),
        )?;
        validate_unique(
            "event",
            self.events.iter().map(|item| item.event_id.as_str()),
        )?;

        for model in &self.score_models {
            model.validate()?;
        }
        for bucket in &self.risk_buckets {
            bucket.validate()?;
        }
        for committee in &self.committees {
            committee.validate()?;
        }
        for member in &self.members {
            member.validate()?;
        }
        for attestation in &self.score_attestations {
            attestation.validate(&self.config)?;
        }
        for disclosure in &self.selective_disclosures {
            disclosure.validate()?;
        }
        for hook in &self.lending_market_hooks {
            hook.validate()?;
        }
        for fence in &self.stale_score_fences {
            fence.validate()?;
        }
        for lane in &self.low_fee_update_lanes {
            lane.validate()?;
        }
        for event in &self.events {
            event.validate()?;
        }

        let committee_ids = self
            .committees
            .iter()
            .map(|committee| committee.committee_id.as_str())
            .collect::<BTreeSet<_>>();
        for attestation in &self.score_attestations {
            if !committee_ids.contains(attestation.committee_id.as_str()) {
                return Err(
                    "private credit score attestation references unknown committee".to_string(),
                );
            }
        }
        for hook in &self.lending_market_hooks {
            if !committee_ids.contains(hook.oracle_committee_id.as_str()) {
                return Err("private credit lending hook references unknown committee".to_string());
            }
        }
        for fence in &self.stale_score_fences {
            if !committee_ids.contains(fence.signer_committee_id.as_str()) {
                return Err("private credit stale fence references unknown committee".to_string());
            }
        }

        let attestation_ids = self
            .score_attestations
            .iter()
            .map(|attestation| attestation.attestation_id.as_str())
            .collect::<BTreeSet<_>>();
        for disclosure in &self.selective_disclosures {
            if !attestation_ids.contains(disclosure.attestation_id.as_str()) {
                return Err("private credit disclosure references unknown attestation".to_string());
            }
        }
        for fence in &self.stale_score_fences {
            if !attestation_ids.contains(fence.attestation_id.as_str()) {
                return Err("private credit stale fence references unknown attestation".to_string());
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        if height < self.height {
            return Err("private credit oracle height cannot move backward".to_string());
        }
        self.height = height;
        self.refresh_freshness();
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> ZkDefiPrivateCreditScoreOracleResult<()> {
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root("config", &self.config.public_record());
        let score_model_root = merkle_root(
            "PRIVATE-CREDIT-SCORE-MODELS",
            &self
                .score_models
                .iter()
                .map(ScoreModel::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_bucket_root = merkle_root(
            "PRIVATE-CREDIT-RISK-BUCKETS",
            &self
                .risk_buckets
                .iter()
                .map(RiskBucketPolicy::public_record)
                .collect::<Vec<_>>(),
        );
        let committee_root = merkle_root(
            "PRIVATE-CREDIT-COMMITTEES",
            &self
                .committees
                .iter()
                .map(OracleCommittee::public_record)
                .collect::<Vec<_>>(),
        );
        let member_root = merkle_root(
            "PRIVATE-CREDIT-MEMBERS",
            &self
                .members
                .iter()
                .map(CommitteeMember::public_record)
                .collect::<Vec<_>>(),
        );
        let score_attestation_root = merkle_root(
            "PRIVATE-CREDIT-SCORE-ATTESTATIONS",
            &self
                .score_attestations
                .iter()
                .map(PrivateScoreAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let selective_disclosure_root = merkle_root(
            "PRIVATE-CREDIT-SELECTIVE-DISCLOSURES",
            &self
                .selective_disclosures
                .iter()
                .map(SelectiveDisclosure::public_record)
                .collect::<Vec<_>>(),
        );
        let lending_market_hook_root = merkle_root(
            "PRIVATE-CREDIT-LENDING-MARKET-HOOKS",
            &self
                .lending_market_hooks
                .iter()
                .map(LendingMarketHook::public_record)
                .collect::<Vec<_>>(),
        );
        let stale_score_fence_root = merkle_root(
            "PRIVATE-CREDIT-STALE-SCORE-FENCES",
            &self
                .stale_score_fences
                .iter()
                .map(StaleScoreFence::public_record)
                .collect::<Vec<_>>(),
        );
        let low_fee_update_lane_root = merkle_root(
            "PRIVATE-CREDIT-LOW-FEE-LANES",
            &self
                .low_fee_update_lanes
                .iter()
                .map(LowFeeUpdateLane::public_record)
                .collect::<Vec<_>>(),
        );
        let event_root = merkle_root(
            "PRIVATE-CREDIT-EVENTS",
            &self
                .events
                .iter()
                .map(OracleEvent::public_record)
                .collect::<Vec<_>>(),
        );
        Roots {
            config_root,
            score_model_root,
            risk_bucket_root,
            committee_root,
            member_root,
            score_attestation_root,
            selective_disclosure_root,
            lending_market_hook_root,
            stale_score_fence_root,
            low_fee_update_lane_root,
            event_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            score_models: self.score_models.len(),
            risk_buckets: self.risk_buckets.len(),
            committees: self.committees.len(),
            members: self.members.len(),
            score_attestations: self.score_attestations.len(),
            active_score_attestations: self
                .score_attestations
                .iter()
                .filter(|attestation| attestation.status.market_usable())
                .count(),
            stale_score_attestations: self
                .score_attestations
                .iter()
                .filter(|attestation| attestation.is_stale_at(self.height))
                .count(),
            selective_disclosures: self.selective_disclosures.len(),
            market_hooks: self.lending_market_hooks.len(),
            stale_score_fences: self.stale_score_fences.len(),
            low_fee_update_lanes: self.low_fee_update_lanes.len(),
            open_low_fee_update_lanes: self
                .low_fee_update_lanes
                .iter()
                .filter(|lane| lane.status.accepts_updates())
                .count(),
            events: self.events.len(),
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn refresh_freshness(&mut self) {
        for attestation in &mut self.score_attestations {
            if self.height >= attestation.expires_at_height {
                attestation.status = ScoreStatus::Expired;
            } else if self.height >= attestation.stale_after_height {
                attestation.status = ScoreStatus::Stale;
            }
        }
        for lane in &mut self.low_fee_update_lanes {
            if self.height >= lane.expires_at_height {
                lane.status = LaneStatus::Expired;
            }
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-CREDIT-SCORE-ORACLE-STATE",
        &[
            HashPart::Str(ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> ZkDefiPrivateCreditScoreOracleResult<State> {
    State::devnet()
}

fn check_len(name: &str, actual: usize, max: usize) -> ZkDefiPrivateCreditScoreOracleResult<()> {
    if actual > max {
        return Err(format!(
            "private credit oracle {name} exceeds configured capacity"
        ));
    }
    Ok(())
}

fn validate_unique<'a>(
    name: &str,
    ids: impl Iterator<Item = &'a str>,
) -> ZkDefiPrivateCreditScoreOracleResult<()> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if id.trim().is_empty() {
            return Err(format!("private credit oracle {name} id cannot be empty"));
        }
        if !seen.insert(id) {
            return Err(format!("private credit oracle duplicate {name} id"));
        }
    }
    Ok(())
}

fn committee_id_for_role(
    committees: &[OracleCommittee],
    role: CommitteeRole,
) -> ZkDefiPrivateCreditScoreOracleResult<String> {
    for committee in committees {
        if committee.role == role {
            return Ok(committee.committee_id.clone());
        }
    }
    Err(format!(
        "private credit devnet missing committee role {}",
        role.as_str()
    ))
}

fn stable_id(domain: &str, parts: &[&str]) -> String {
    format!("private-credit-{domain}-{}", short_root(domain, parts))
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        &format!("PRIVATE-CREDIT-COMMITMENT-{domain}"),
        &[
            HashPart::Str(ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROTOCOL_VERSION),
            HashPart::Json(&json!({ "parts": parts })),
        ],
        32,
    )
}

fn short_root(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        &format!("PRIVATE-CREDIT-ID-{domain}"),
        &[
            HashPart::Str(ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROTOCOL_VERSION),
            HashPart::Json(&json!({ "parts": parts })),
        ],
        12,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-CREDIT-PAYLOAD-{domain}"),
        &[
            HashPart::Str(ZK_DEFI_PRIVATE_CREDIT_SCORE_ORACLE_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn string_list_root(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-CREDIT-LIST-{domain}"), &leaves)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreRefreshPlan {
    pub plan_id: String,
    pub target_attestation_id: String,
    pub next_model_root: String,
    pub low_fee_lane_id: String,
    pub refresh_after_height: u64,
    pub target_expiry_height: u64,
}

impl ScoreRefreshPlan {
    pub fn from_attestation(
        attestation: &PrivateScoreAttestation,
        next_model_root: &str,
        lane_id: &str,
    ) -> Self {
        Self {
            plan_id: stable_id(
                "score-refresh-plan",
                &[
                    &attestation.attestation_id,
                    next_model_root,
                    lane_id,
                    &attestation.stale_after_height.to_string(),
                ],
            ),
            target_attestation_id: attestation.attestation_id.clone(),
            next_model_root: next_model_root.to_string(),
            low_fee_lane_id: lane_id.to_string(),
            refresh_after_height: attestation.stale_after_height,
            target_expiry_height: attestation.expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "target_attestation_id": self.target_attestation_id,
            "next_model_root": self.next_model_root,
            "low_fee_lane_id": self.low_fee_lane_id,
            "refresh_after_height": self.refresh_after_height,
            "target_expiry_height": self.target_expiry_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketAdmissionDecision {
    pub decision_id: String,
    pub market_id: String,
    pub disclosure_id: String,
    pub bucket: ScoreBucket,
    pub admitted: bool,
    pub max_ltv_bps: u64,
    pub rate_spread_bps: u64,
    pub decision_root: String,
}

impl MarketAdmissionDecision {
    pub fn from_disclosure(
        disclosure: &SelectiveDisclosure,
        bucket_policy: &RiskBucketPolicy,
        hook: &LendingMarketHook,
    ) -> Self {
        let admitted = disclosure.disclosed_bucket.borrow_enabled()
            && bucket_policy.bucket == disclosure.disclosed_bucket
            && hook.max_ltv_bps <= bucket_policy.max_ltv_bps;
        let decision_root = payload_root(
            "market-admission-decision",
            &json!({
                "market_id": disclosure.market_id,
                "disclosure_id": disclosure.disclosure_id,
                "bucket": disclosure.disclosed_bucket.as_str(),
                "hook_id": hook.hook_id,
                "admitted": admitted,
            }),
        );
        Self {
            decision_id: stable_id(
                "market-admission",
                &[
                    &disclosure.market_id,
                    &disclosure.disclosure_id,
                    &hook.hook_id,
                ],
            ),
            market_id: disclosure.market_id.clone(),
            disclosure_id: disclosure.disclosure_id.clone(),
            bucket: disclosure.disclosed_bucket,
            admitted,
            max_ltv_bps: bucket_policy.max_ltv_bps.min(hook.max_ltv_bps),
            rate_spread_bps: bucket_policy.base_rate_bps + hook.rate_spread_bps,
            decision_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "market_id": self.market_id,
            "disclosure_id": self.disclosure_id,
            "bucket": self.bucket.as_str(),
            "admitted": self.admitted,
            "max_ltv_bps": self.max_ltv_bps,
            "rate_spread_bps": self.rate_spread_bps,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyAuditSnapshot {
    pub snapshot_id: String,
    pub score_attestation_root: String,
    pub disclosure_root: String,
    pub stale_fence_root: String,
    pub low_fee_lane_root: String,
    pub minimum_privacy_set_size: u64,
    pub disclosed_raw_score_count: usize,
    pub generated_at_height: u64,
}

impl PrivacyAuditSnapshot {
    pub fn from_state(state: &State) -> Self {
        let roots = state.roots();
        let disclosed_raw_score_count = state
            .selective_disclosures
            .iter()
            .filter(|disclosure| disclosure.purpose.reveals_raw_score())
            .count();
        Self {
            snapshot_id: stable_id("privacy-audit", &[&state.height.to_string()]),
            score_attestation_root: roots.score_attestation_root,
            disclosure_root: roots.selective_disclosure_root,
            stale_fence_root: roots.stale_score_fence_root,
            low_fee_lane_root: roots.low_fee_update_lane_root,
            minimum_privacy_set_size: state.config.min_privacy_set_size,
            disclosed_raw_score_count,
            generated_at_height: state.height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "score_attestation_root": self.score_attestation_root,
            "disclosure_root": self.disclosure_root,
            "stale_fence_root": self.stale_fence_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "minimum_privacy_set_size": self.minimum_privacy_set_size,
            "disclosed_raw_score_count": self.disclosed_raw_score_count,
            "generated_at_height": self.generated_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeterministicRootBook {
    pub roots: BTreeMap<String, String>,
}

impl DeterministicRootBook {
    pub fn from_state(state: &State) -> Self {
        let roots = state.roots();
        let mut book = BTreeMap::new();
        book.insert("config".to_string(), roots.config_root);
        book.insert("score_models".to_string(), roots.score_model_root);
        book.insert("risk_buckets".to_string(), roots.risk_bucket_root);
        book.insert("committees".to_string(), roots.committee_root);
        book.insert("members".to_string(), roots.member_root);
        book.insert(
            "score_attestations".to_string(),
            roots.score_attestation_root,
        );
        book.insert(
            "selective_disclosures".to_string(),
            roots.selective_disclosure_root,
        );
        book.insert(
            "lending_market_hooks".to_string(),
            roots.lending_market_hook_root,
        );
        book.insert(
            "stale_score_fences".to_string(),
            roots.stale_score_fence_root,
        );
        book.insert(
            "low_fee_update_lanes".to_string(),
            roots.low_fee_update_lane_root,
        );
        book.insert("events".to_string(), roots.event_root);
        book.insert("state".to_string(), state.state_root());
        Self { roots: book }
    }

    pub fn public_record(&self) -> Value {
        json!({ "roots": self.roots })
    }
}
