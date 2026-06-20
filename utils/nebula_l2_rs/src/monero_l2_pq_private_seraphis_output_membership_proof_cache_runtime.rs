use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisOutputMembershipProofCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_OUTPUT_MEMBERSHIP_PROOF_CACHE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-seraphis-output-membership-proof-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_OUTPUT_MEMBERSHIP_PROOF_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SERAPHIS_OUTPUT_COHORT_SCHEME: &str = "monero-seraphis-output-cohort-root-v1";
pub const OUTPUT_MEMBERSHIP_PROOF_CACHE_SCHEME: &str =
    "monero-seraphis-output-membership-proof-cache-root-v1";
pub const RING_MEMBER_PROOF_HINT_SCHEME: &str =
    "view-key-safe-seraphis-ring-member-proof-hint-root-v1";
pub const DECOY_AGE_BUCKET_SCHEME: &str = "monero-seraphis-decoy-age-bucket-root-v1";
pub const PQ_AUDITOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-seraphis-cache-auditor-attestation-v1";
pub const WALLET_SCAN_HINT_SCHEME: &str = "view-key-safe-seraphis-wallet-scan-hint-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "seraphis-output-membership-cache-redaction-budget-root-v1";
pub const LOW_FEE_CACHE_REBATE_SCHEME: &str =
    "low-fee-private-seraphis-output-membership-cache-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-seraphis-output-membership-proof-cache-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_or_membership_witnesses";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_040_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_720_000;
pub const DEVNET_EPOCH: u64 = 14_112;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 64;
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_COHORT_OUTPUTS: u64 = 524_288;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_HINT: u64 = 32;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortKind {
    WalletReceive,
    BridgeDeposit,
    BridgeWithdrawal,
    SwapSettlement,
    LiquidityRebalance,
    AuditCanary,
}

impl CohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletReceive => "wallet_receive",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::SwapSettlement => "swap_settlement",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::AuditCanary => "audit_canary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    Draft,
    Warm,
    Attested,
    RebateEligible,
    Sealed,
    Expired,
    Quarantined,
}

impl CacheStatus {
    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Warm | Self::Attested | Self::RebateEligible | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintStatus {
    Draft,
    Published,
    Consumed,
    Superseded,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Reserved,
    Applied,
    Exhausted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub mode: RuntimeMode,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_cohort_outputs: u64,
    pub target_cohort_outputs: u64,
    pub cache_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub public_bucket_size: u64,
    pub max_redaction_units_per_hint: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            target_cohort_outputs: DEFAULT_TARGET_COHORT_OUTPUTS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            max_redaction_units_per_hint: DEFAULT_MAX_REDACTION_UNITS_PER_HINT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.min_ring_size >= 16,
            "minimum Seraphis ring size is too low",
        )?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size must cover minimum ring size",
        )?;
        ensure(
            self.target_cohort_outputs >= self.min_cohort_outputs,
            "target cohort outputs must cover minimum cohort outputs",
        )?;
        ensure(self.cache_ttl_blocks > 0, "cache ttl must be non-zero")?;
        ensure(self.hint_ttl_blocks > 0, "hint ttl must be non-zero")?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target PQ security must cover minimum PQ security",
        )?;
        ensure(
            self.max_user_fee_bps <= MAX_BPS,
            "user fee cap exceeds max bps",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mode": self.mode.as_str(),
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_cohort_outputs": self.min_cohort_outputs,
            "target_cohort_outputs": self.target_cohort_outputs,
            "cache_ttl_blocks": self.cache_ttl_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "public_bucket_size": self.public_bucket_size,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub output_cohorts: u64,
    pub membership_caches: u64,
    pub ring_member_hints: u64,
    pub decoy_age_buckets: u64,
    pub pq_attestations: u64,
    pub wallet_scan_hints: u64,
    pub redaction_budgets: u64,
    pub low_fee_rebates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub output_cohorts_root: String,
    pub membership_caches_root: String,
    pub ring_member_hints_root: String,
    pub decoy_age_buckets_root: String,
    pub pq_attestations_root: String,
    pub wallet_scan_hints_root: String,
    pub redaction_budgets_root: String,
    pub low_fee_rebates_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            output_cohorts_root: empty_root(SERAPHIS_OUTPUT_COHORT_SCHEME),
            membership_caches_root: empty_root(OUTPUT_MEMBERSHIP_PROOF_CACHE_SCHEME),
            ring_member_hints_root: empty_root(RING_MEMBER_PROOF_HINT_SCHEME),
            decoy_age_buckets_root: empty_root(DECOY_AGE_BUCKET_SCHEME),
            pq_attestations_root: empty_root(PQ_AUDITOR_ATTESTATION_SCHEME),
            wallet_scan_hints_root: empty_root(WALLET_SCAN_HINT_SCHEME),
            redaction_budgets_root: empty_root(PRIVACY_REDACTION_BUDGET_SCHEME),
            low_fee_rebates_root: empty_root(LOW_FEE_CACHE_REBATE_SCHEME),
            deterministic_state_root: empty_root("seraphis-runtime-state"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputCohort {
    pub cohort_id: String,
    pub cohort_kind: CohortKind,
    pub epoch: u64,
    pub monero_height: u64,
    pub output_count_bucket: u64,
    pub membership_tree_root: String,
    pub status: CacheStatus,
}

impl OutputCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "cohort_kind": self.cohort_kind.as_str(),
            "epoch": self.epoch,
            "monero_height": self.monero_height,
            "output_count_bucket": self.output_count_bucket,
            "membership_tree_root": self.membership_tree_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(SERAPHIS_OUTPUT_COHORT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MembershipProofCache {
    pub cache_id: String,
    pub cohort_id: String,
    pub proof_transcript_root: String,
    pub proof_hint_root: String,
    pub expires_at_monero_height: u64,
    pub status: CacheStatus,
}

impl MembershipProofCache {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(OUTPUT_MEMBERSHIP_PROOF_CACHE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberProofHint {
    pub hint_id: String,
    pub cohort_id: String,
    pub cache_id: String,
    pub ring_size: u16,
    pub decoy_age_bucket_id: String,
    pub redacted_hint_root: String,
    pub status: HintStatus,
}

impl RingMemberProofHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(RING_MEMBER_PROOF_HINT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyAgeBucket {
    pub bucket_id: String,
    pub lower_age_blocks: u64,
    pub upper_age_blocks: u64,
    pub output_count_bucket: u64,
    pub decoy_distribution_root: String,
}

impl DecoyAgeBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(DECOY_AGE_BUCKET_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuditorAttestation {
    pub attestation_id: String,
    pub auditor_id: String,
    pub cache_id: String,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub status: AttestationStatus,
}

impl PqAuditorAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_AUDITOR_ATTESTATION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub cohort_id: String,
    pub scan_window_root: String,
    pub expires_at_monero_height: u64,
    pub redaction_units: u64,
}

impl WalletScanHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(WALLET_SCAN_HINT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub epoch: u64,
    pub units_total: u64,
    pub units_reserved: u64,
    pub status: BudgetStatus,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(PRIVACY_REDACTION_BUDGET_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCacheRebate {
    pub rebate_id: String,
    pub cache_id: String,
    pub cohort_id: String,
    pub fee_asset_id: String,
    pub fee_rebate_amount_bucket: u64,
    pub sponsor_receipt_root: String,
}

impl LowFeeCacheRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_CACHE_REBATE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub chain_id: String,
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub output_cohorts: BTreeMap<String, OutputCohort>,
    pub membership_caches: BTreeMap<String, MembershipProofCache>,
    pub ring_member_hints: BTreeMap<String, RingMemberProofHint>,
    pub decoy_age_buckets: BTreeMap<String, DecoyAgeBucket>,
    pub pq_attestations: BTreeMap<String, PqAuditorAttestation>,
    pub wallet_scan_hints: BTreeMap<String, WalletScanHint>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub low_fee_rebates: BTreeMap<String, LowFeeCacheRebate>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            config,
            l2_height,
            monero_height,
            epoch,
            counters: Counters::default(),
            roots: Roots::empty(),
            output_cohorts: BTreeMap::new(),
            membership_caches: BTreeMap::new(),
            ring_member_hints: BTreeMap::new(),
            decoy_age_buckets: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            wallet_scan_hints: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn insert_output_cohort(&mut self, cohort: OutputCohort) -> Result<()> {
        ensure(
            cohort.output_count_bucket >= self.config.min_cohort_outputs,
            "cohort output bucket is below privacy floor",
        )?;
        self.output_cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.counters.output_cohorts = self.output_cohorts.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_membership_cache(&mut self, cache: MembershipProofCache) -> Result<()> {
        ensure(
            self.output_cohorts.contains_key(&cache.cohort_id),
            "membership cache references unknown cohort",
        )?;
        self.membership_caches.insert(cache.cache_id.clone(), cache);
        self.counters.membership_caches = self.membership_caches.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_ring_member_hint(&mut self, hint: RingMemberProofHint) -> Result<()> {
        ensure(
            hint.ring_size >= self.config.min_ring_size,
            "ring member hint is below minimum ring size",
        )?;
        ensure(
            self.membership_caches.contains_key(&hint.cache_id),
            "ring member hint references unknown cache",
        )?;
        self.ring_member_hints.insert(hint.hint_id.clone(), hint);
        self.counters.ring_member_hints = self.ring_member_hints.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_decoy_age_bucket(&mut self, bucket: DecoyAgeBucket) -> Result<()> {
        ensure(
            bucket.upper_age_blocks >= bucket.lower_age_blocks,
            "decoy age bucket bounds are invalid",
        )?;
        self.decoy_age_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.counters.decoy_age_buckets = self.decoy_age_buckets.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqAuditorAttestation) -> Result<()> {
        ensure(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ attestation is below minimum security",
        )?;
        ensure(
            self.membership_caches.contains_key(&attestation.cache_id),
            "PQ attestation references unknown cache",
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_wallet_scan_hint(&mut self, hint: WalletScanHint) -> Result<()> {
        ensure(
            hint.redaction_units <= self.config.max_redaction_units_per_hint,
            "wallet scan hint exceeds redaction budget",
        )?;
        self.wallet_scan_hints.insert(hint.hint_id.clone(), hint);
        self.counters.wallet_scan_hints = self.wallet_scan_hints.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        ensure(
            budget.units_reserved <= budget.units_total,
            "redaction budget over-reserved",
        )?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_rebate(&mut self, rebate: LowFeeCacheRebate) -> Result<()> {
        ensure(
            self.membership_caches.contains_key(&rebate.cache_id),
            "low-fee rebate references unknown cache",
        )?;
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.counters.low_fee_rebates = self.low_fee_rebates.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "runtime": "monero_l2_pq_private_seraphis_output_membership_proof_cache_runtime",
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "hash_suite": HASH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "l2_height": bucket(self.l2_height, self.config.public_bucket_size),
            "monero_height": bucket(self.monero_height, self.config.public_bucket_size),
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.deterministic_state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.output_cohorts_root = map_root(
            SERAPHIS_OUTPUT_COHORT_SCHEME,
            self.output_cohorts
                .iter()
                .map(|(id, cohort)| (id.as_str(), cohort.state_root())),
        );
        self.roots.membership_caches_root = map_root(
            OUTPUT_MEMBERSHIP_PROOF_CACHE_SCHEME,
            self.membership_caches
                .iter()
                .map(|(id, cache)| (id.as_str(), cache.state_root())),
        );
        self.roots.ring_member_hints_root = map_root(
            RING_MEMBER_PROOF_HINT_SCHEME,
            self.ring_member_hints
                .iter()
                .map(|(id, hint)| (id.as_str(), hint.state_root())),
        );
        self.roots.decoy_age_buckets_root = map_root(
            DECOY_AGE_BUCKET_SCHEME,
            self.decoy_age_buckets
                .iter()
                .map(|(id, bucket)| (id.as_str(), bucket.state_root())),
        );
        self.roots.pq_attestations_root = map_root(
            PQ_AUDITOR_ATTESTATION_SCHEME,
            self.pq_attestations
                .iter()
                .map(|(id, attestation)| (id.as_str(), attestation.state_root())),
        );
        self.roots.wallet_scan_hints_root = map_root(
            WALLET_SCAN_HINT_SCHEME,
            self.wallet_scan_hints
                .iter()
                .map(|(id, hint)| (id.as_str(), hint.state_root())),
        );
        self.roots.redaction_budgets_root = map_root(
            PRIVACY_REDACTION_BUDGET_SCHEME,
            self.redaction_budgets
                .iter()
                .map(|(id, budget)| (id.as_str(), budget.state_root())),
        );
        self.roots.low_fee_rebates_root = map_root(
            LOW_FEE_CACHE_REBATE_SCHEME,
            self.low_fee_rebates
                .iter()
                .map(|(id, rebate)| (id.as_str(), rebate.state_root())),
        );
        self.roots.deterministic_state_root = self.state_root_without_cached_roots();
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "seraphis-output-membership-cache-state",
            &[
                HashPart::Str(&self.protocol_version),
                HashPart::Str(&self.chain_id),
                HashPart::Str(&self.config.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.roots.output_cohorts_root),
                HashPart::Str(&self.roots.membership_caches_root),
                HashPart::Str(&self.roots.ring_member_hints_root),
                HashPart::Str(&self.roots.decoy_age_buckets_root),
                HashPart::Str(&self.roots.pq_attestations_root),
                HashPart::Str(&self.roots.wallet_scan_hints_root),
                HashPart::Str(&self.roots.redaction_budgets_root),
                HashPart::Str(&self.roots.low_fee_rebates_root),
            ],
        )
    }
}

pub fn devnet() -> State {
    let mut state = State::new(
        Config::devnet(),
        DEVNET_L2_HEIGHT,
        DEVNET_MONERO_HEIGHT,
        DEVNET_EPOCH,
    )
    .expect("devnet Seraphis output membership proof cache config is valid");

    let cohort_id = "seraphis-output-cohort-devnet-0".to_string();
    let cache_id = "seraphis-membership-cache-devnet-0".to_string();
    let bucket_id = "seraphis-decoy-age-bucket-devnet-0".to_string();
    let membership_tree_root = root_from_parts(
        "devnet-membership-tree",
        &[
            HashPart::Str(&cohort_id),
            HashPart::U64(DEVNET_MONERO_HEIGHT),
        ],
    );
    state
        .insert_output_cohort(OutputCohort {
            cohort_id: cohort_id.clone(),
            cohort_kind: CohortKind::BridgeWithdrawal,
            epoch: DEVNET_EPOCH,
            monero_height: DEVNET_MONERO_HEIGHT,
            output_count_bucket: DEFAULT_TARGET_COHORT_OUTPUTS,
            membership_tree_root,
            status: CacheStatus::Warm,
        })
        .expect("devnet cohort inserts");
    state
        .insert_decoy_age_bucket(DecoyAgeBucket {
            bucket_id: bucket_id.clone(),
            lower_age_blocks: 720,
            upper_age_blocks: 7_200,
            output_count_bucket: DEFAULT_TARGET_COHORT_OUTPUTS,
            decoy_distribution_root: root_from_parts(
                "devnet-decoy-distribution",
                &[HashPart::Str(&bucket_id)],
            ),
        })
        .expect("devnet decoy bucket inserts");
    state
        .insert_membership_cache(MembershipProofCache {
            cache_id: cache_id.clone(),
            cohort_id: cohort_id.clone(),
            proof_transcript_root: root_from_parts(
                "devnet-proof-transcript",
                &[HashPart::Str(&cache_id)],
            ),
            proof_hint_root: root_from_parts("devnet-proof-hints", &[HashPart::Str(&cache_id)]),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_CACHE_TTL_BLOCKS,
            status: CacheStatus::Attested,
        })
        .expect("devnet cache inserts");
    state
        .insert_ring_member_hint(RingMemberProofHint {
            hint_id: "seraphis-ring-member-hint-devnet-0".to_string(),
            cohort_id: cohort_id.clone(),
            cache_id: cache_id.clone(),
            ring_size: DEFAULT_TARGET_RING_SIZE,
            decoy_age_bucket_id: bucket_id,
            redacted_hint_root: root_from_parts("devnet-redacted-ring-hint", &[HashPart::Str("0")]),
            status: HintStatus::Published,
        })
        .expect("devnet ring hint inserts");
    state
        .insert_pq_attestation(PqAuditorAttestation {
            attestation_id: "seraphis-pq-auditor-attestation-devnet-0".to_string(),
            auditor_id: "operator-devnet-pq-auditor-0".to_string(),
            cache_id: cache_id.clone(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attestation_root: root_from_parts(
                "devnet-pq-auditor-attestation",
                &[HashPart::Str(&cache_id)],
            ),
            status: AttestationStatus::Quorum,
        })
        .expect("devnet PQ attestation inserts");
    state
        .insert_wallet_scan_hint(WalletScanHint {
            hint_id: "seraphis-wallet-scan-hint-devnet-0".to_string(),
            cohort_id: cohort_id.clone(),
            scan_window_root: root_from_parts("devnet-scan-window", &[HashPart::Str(&cohort_id)]),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_HINT_TTL_BLOCKS,
            redaction_units: 12,
        })
        .expect("devnet wallet scan hint inserts");
    state
        .insert_redaction_budget(PrivacyRedactionBudget {
            budget_id: "seraphis-redaction-budget-devnet-0".to_string(),
            subject_id: cohort_id.clone(),
            epoch: DEVNET_EPOCH,
            units_total: 256,
            units_reserved: 12,
            status: BudgetStatus::Reserved,
        })
        .expect("devnet redaction budget inserts");
    state
        .insert_low_fee_rebate(LowFeeCacheRebate {
            rebate_id: "seraphis-low-fee-cache-rebate-devnet-0".to_string(),
            cache_id,
            cohort_id,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            fee_rebate_amount_bucket: 18_000,
            sponsor_receipt_root: root_from_parts("devnet-sponsor-receipt", &[HashPart::Str("0")]),
        })
        .expect("devnet low-fee rebate inserts");

    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bucket(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        (value / bucket_size) * bucket_size
    }
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts)
}

fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| root_from_parts(domain, &[HashPart::Str(id), HashPart::Str(&root)]))
        .collect::<Vec<_>>();
    merkle_root(domain, leaves.iter().map(String::as_str))
}
