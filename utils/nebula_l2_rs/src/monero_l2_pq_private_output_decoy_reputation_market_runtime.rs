use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateOutputDecoyReputationMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_OUTPUT_DECOY_REPUTATION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-output-decoy-reputation-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_OUTPUT_DECOY_REPUTATION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_REPUTATION_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-output-decoy-reputation-v1";
pub const RING_FRESHNESS_PROOF_SUITE: &str = "monero-ring-freshness-proof-root-v1";
pub const VIEW_KEY_REDACTION_SUITE: &str = "operator-safe-view-key-redaction-root-v1";
pub const DECOY_QUALITY_REBATE_SUITE: &str = "low-fee-decoy-quality-rebate-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_088_640;
pub const DEFAULT_MIN_PROVIDER_STAKE: u64 = 2_500_000;
pub const DEFAULT_MIN_REPUTATION_SCORE_BPS: u64 = 7_250;
pub const DEFAULT_MIN_FRESHNESS_SCORE_BPS: u64 = 7_000;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u64 = 4_096;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 96;
pub const DEFAULT_MAX_PROVIDER_FEE_MICRO_UNITS: u64 = 7_500;
pub const DEFAULT_REBATE_BPS: u64 = 1_100;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SLASH_STALE_BPS: u64 = 900;
pub const DEFAULT_SLASH_FALSE_ATTESTATION_BPS: u64 = 3_300;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketLane {
    WalletSpend,
    BridgeWithdrawal,
    MerchantPayment,
    AtomicSwap,
    DexSettlement,
    WatchtowerAudit,
}

impl MarketLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSpend => "wallet_spend",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantPayment => "merchant_payment",
            Self::AtomicSwap => "atomic_swap",
            Self::DexSettlement => "dex_settlement",
            Self::WatchtowerAudit => "watchtower_audit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputAgeBucket {
    Fresh0To2Hours,
    Recent2To24Hours,
    Standard1To7Days,
    Mature7To30Days,
    Deep30To180Days,
    Archive180DaysPlus,
}

impl OutputAgeBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh0To2Hours => "fresh_0_to_2_hours",
            Self::Recent2To24Hours => "recent_2_to_24_hours",
            Self::Standard1To7Days => "standard_1_to_7_days",
            Self::Mature7To30Days => "mature_7_to_30_days",
            Self::Deep30To180Days => "deep_30_to_180_days",
            Self::Archive180DaysPlus => "archive_180_days_plus",
        }
    }

    pub fn target_weight_bps(self) -> u64 {
        match self {
            Self::Fresh0To2Hours => 600,
            Self::Recent2To24Hours => 1_600,
            Self::Standard1To7Days => 3_800,
            Self::Mature7To30Days => 2_700,
            Self::Deep30To180Days => 1_000,
            Self::Archive180DaysPlus => 300,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Candidate,
    Active,
    Throttled,
    Slashed,
    Retired,
}

impl ProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Accepted,
    Stale,
    Disputed,
    Superseded,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakReputation,
    Rejected,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakReputation => "weak_reputation",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub min_provider_stake: u64,
    pub min_reputation_score_bps: u64,
    pub min_freshness_score_bps: u64,
    pub min_bucket_outputs: u64,
    pub target_ring_size: u16,
    pub max_provider_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub attestation_ttl_blocks: u64,
    pub redaction_ttl_blocks: u64,
    pub slash_stale_bps: u64,
    pub slash_false_attestation_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            min_provider_stake: DEFAULT_MIN_PROVIDER_STAKE,
            min_reputation_score_bps: DEFAULT_MIN_REPUTATION_SCORE_BPS,
            min_freshness_score_bps: DEFAULT_MIN_FRESHNESS_SCORE_BPS,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            max_provider_fee_micro_units: DEFAULT_MAX_PROVIDER_FEE_MICRO_UNITS,
            rebate_bps: DEFAULT_REBATE_BPS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redaction_ttl_blocks: DEFAULT_REDACTION_TTL_BLOCKS,
            slash_stale_bps: DEFAULT_SLASH_STALE_BPS,
            slash_false_attestation_bps: DEFAULT_SLASH_FALSE_ATTESTATION_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "min_provider_stake": self.min_provider_stake,
            "min_reputation_score_bps": self.min_reputation_score_bps,
            "min_freshness_score_bps": self.min_freshness_score_bps,
            "min_bucket_outputs": self.min_bucket_outputs,
            "target_ring_size": self.target_ring_size,
            "max_provider_fee_micro_units": self.max_provider_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "redaction_ttl_blocks": self.redaction_ttl_blocks,
            "slash_stale_bps": self.slash_stale_bps,
            "slash_false_attestation_bps": self.slash_false_attestation_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub providers: u64,
    pub age_buckets: u64,
    pub reputation_stakes: u64,
    pub ring_freshness_proofs: u64,
    pub pq_reputation_attestations: u64,
    pub decoy_quality_rebates: u64,
    pub view_key_redactions: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "providers": self.providers,
            "age_buckets": self.age_buckets,
            "reputation_stakes": self.reputation_stakes,
            "ring_freshness_proofs": self.ring_freshness_proofs,
            "pq_reputation_attestations": self.pq_reputation_attestations,
            "decoy_quality_rebates": self.decoy_quality_rebates,
            "view_key_redactions": self.view_key_redactions,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub provider_root: String,
    pub age_bucket_root: String,
    pub reputation_stake_root: String,
    pub ring_freshness_proof_root: String,
    pub pq_reputation_attestation_root: String,
    pub decoy_quality_rebate_root: String,
    pub view_key_redaction_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            provider_root: empty_root("providers"),
            age_bucket_root: empty_root("age_buckets"),
            reputation_stake_root: empty_root("reputation_stakes"),
            ring_freshness_proof_root: empty_root("ring_freshness_proofs"),
            pq_reputation_attestation_root: empty_root("pq_reputation_attestations"),
            decoy_quality_rebate_root: empty_root("decoy_quality_rebates"),
            view_key_redaction_root: empty_root("view_key_redactions"),
            public_record_root: empty_root("public_records"),
            state_root: String::new(),
        };
        roots.state_root = record_root("roots", &roots.public_record_without_state_root());
        roots
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "provider_root": self.provider_root,
            "age_bucket_root": self.age_bucket_root,
            "reputation_stake_root": self.reputation_stake_root,
            "ring_freshness_proof_root": self.ring_freshness_proof_root,
            "pq_reputation_attestation_root": self.pq_reputation_attestation_root,
            "decoy_quality_rebate_root": self.decoy_quality_rebate_root,
            "view_key_redaction_root": self.view_key_redaction_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyProviderRegistration {
    pub provider_label: String,
    pub operator_root: String,
    pub pq_signer_root: String,
    pub inventory_commitment_root: String,
    pub max_fee_micro_units: u64,
    pub stake_micro_units: u64,
    pub initial_reputation_bps: u64,
}

impl DecoyProviderRegistration {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_label": self.provider_label,
            "operator_root": self.operator_root,
            "pq_signer_root": self.pq_signer_root,
            "inventory_commitment_root": self.inventory_commitment_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "stake_micro_units": self.stake_micro_units,
            "initial_reputation_bps": self.initial_reputation_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyProviderRecord {
    pub provider_id: String,
    pub registration: DecoyProviderRegistration,
    pub status: ProviderStatus,
    pub reputation_score_bps: u64,
    pub active_stake_micro_units: u64,
    pub accepted_attestations: u64,
    pub slashed_events: u64,
    pub registered_at_height: u64,
    pub provider_root: String,
}

impl DecoyProviderRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "registration": self.registration.public_record(),
            "status": self.status.as_str(),
            "reputation_score_bps": self.reputation_score_bps,
            "active_stake_micro_units": self.active_stake_micro_units,
            "accepted_attestations": self.accepted_attestations,
            "slashed_events": self.slashed_events,
            "registered_at_height": self.registered_at_height,
            "provider_root": self.provider_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutputAgeBucketRecord {
    pub bucket_id: String,
    pub lane: MarketLane,
    pub age_bucket: OutputAgeBucket,
    pub output_commitment_root: String,
    pub histogram_root: String,
    pub output_count: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
    pub freshness_score_bps: u64,
    pub recorded_at_height: u64,
    pub bucket_root: String,
}

impl OutputAgeBucketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "age_bucket": self.age_bucket.as_str(),
            "target_weight_bps": self.age_bucket.target_weight_bps(),
            "output_commitment_root": self.output_commitment_root,
            "histogram_root": self.histogram_root,
            "output_count": self.output_count,
            "median_age_blocks": self.median_age_blocks,
            "p95_age_blocks": self.p95_age_blocks,
            "freshness_score_bps": self.freshness_score_bps,
            "recorded_at_height": self.recorded_at_height,
            "bucket_root": self.bucket_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReputationStakeRecord {
    pub stake_id: String,
    pub provider_id: String,
    pub bonded_root: String,
    pub amount_micro_units: u64,
    pub reputation_floor_bps: u64,
    pub locked_until_height: u64,
    pub stake_root: String,
}

impl ReputationStakeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "stake_id": self.stake_id,
            "provider_id": self.provider_id,
            "bonded_root": self.bonded_root,
            "amount_micro_units": self.amount_micro_units,
            "reputation_floor_bps": self.reputation_floor_bps,
            "locked_until_height": self.locked_until_height,
            "stake_root": self.stake_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RingFreshnessProofRecord {
    pub proof_id: String,
    pub provider_id: String,
    pub bucket_id: String,
    pub lane: MarketLane,
    pub ring_member_root: String,
    pub freshness_proof_root: String,
    pub view_key_redaction_root: String,
    pub ring_size: u16,
    pub freshness_score_bps: u64,
    pub status: ProofStatus,
    pub expires_at_height: u64,
    pub proof_root: String,
}

impl RingFreshnessProofRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "provider_id": self.provider_id,
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "ring_member_root": self.ring_member_root,
            "freshness_proof_root": self.freshness_proof_root,
            "view_key_redaction_root": self.view_key_redaction_root,
            "ring_size": self.ring_size,
            "freshness_score_bps": self.freshness_score_bps,
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqReputationAttestationRecord {
    pub attestation_id: String,
    pub proof_id: String,
    pub provider_id: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub reputation_score_bps: u64,
    pub quality_score_bps: u64,
    pub status: AttestationStatus,
    pub attested_at_height: u64,
    pub attestation_root: String,
}

impl PqReputationAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "proof_id": self.proof_id,
            "provider_id": self.provider_id,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "reputation_score_bps": self.reputation_score_bps,
            "quality_score_bps": self.quality_score_bps,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyQualityRebateRecord {
    pub rebate_id: String,
    pub attestation_id: String,
    pub provider_id: String,
    pub beneficiary_root: String,
    pub rebate_micro_units: u64,
    pub quality_score_bps: u64,
    pub rebate_root: String,
}

impl DecoyQualityRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "attestation_id": self.attestation_id,
            "provider_id": self.provider_id,
            "beneficiary_root": self.beneficiary_root,
            "rebate_micro_units": self.rebate_micro_units,
            "quality_score_bps": self.quality_score_bps,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewKeyRedactionRecord {
    pub redaction_id: String,
    pub proof_id: String,
    pub disclosure_policy_root: String,
    pub redacted_view_key_root: String,
    pub retained_fields_root: String,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
    pub redaction_root: String,
}

impl ViewKeyRedactionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "proof_id": self.proof_id,
            "disclosure_policy_root": self.disclosure_policy_root,
            "redacted_view_key_root": self.redacted_view_key_root,
            "retained_fields_root": self.retained_fields_root,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_height": self.expires_at_height,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub providers: BTreeMap<String, DecoyProviderRecord>,
    pub age_buckets: BTreeMap<String, OutputAgeBucketRecord>,
    pub reputation_stakes: BTreeMap<String, ReputationStakeRecord>,
    pub ring_freshness_proofs: BTreeMap<String, RingFreshnessProofRecord>,
    pub pq_reputation_attestations: BTreeMap<String, PqReputationAttestationRecord>,
    pub decoy_quality_rebates: BTreeMap<String, DecoyQualityRebateRecord>,
    pub view_key_redactions: BTreeMap<String, ViewKeyRedactionRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            config,
            counters,
            roots,
            current_height: DEVNET_HEIGHT,
            providers: BTreeMap::new(),
            age_buckets: BTreeMap::new(),
            reputation_stakes: BTreeMap::new(),
            ring_freshness_proofs: BTreeMap::new(),
            pq_reputation_attestations: BTreeMap::new(),
            decoy_quality_rebates: BTreeMap::new(),
            view_key_redactions: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            config,
            counters,
            roots,
            ..Self::default()
        }
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn register_provider(&mut self, registration: DecoyProviderRegistration) -> Result<String> {
        if registration.stake_micro_units < self.config.min_provider_stake {
            return Err("provider stake is below reputation market floor".to_string());
        }
        if registration.max_fee_micro_units > self.config.max_provider_fee_micro_units {
            return Err("provider max fee exceeds market cap".to_string());
        }
        let provider_id = id_from_record("provider", &registration.public_record());
        let mut record = DecoyProviderRecord {
            provider_id: provider_id.clone(),
            reputation_score_bps: registration.initial_reputation_bps.min(MAX_BPS),
            active_stake_micro_units: registration.stake_micro_units,
            status: ProviderStatus::Active,
            accepted_attestations: 0,
            slashed_events: 0,
            registered_at_height: self.current_height,
            provider_root: String::new(),
            registration,
        };
        record.provider_root = record_root("provider", &record.public_record());
        self.providers.insert(provider_id.clone(), record);
        self.counters.providers = self.providers.len() as u64;
        self.refresh_roots();
        Ok(provider_id)
    }

    pub fn record_output_age_bucket(
        &mut self,
        lane: MarketLane,
        age_bucket: OutputAgeBucket,
        output_commitment_root: String,
        histogram_root: String,
        output_count: u64,
        median_age_blocks: u64,
        p95_age_blocks: u64,
    ) -> Result<String> {
        if output_count < self.config.min_bucket_outputs {
            return Err("output age bucket is below minimum population".to_string());
        }
        let freshness_score_bps = freshness_score(median_age_blocks, p95_age_blocks);
        let seed = json!({
            "lane": lane.as_str(),
            "age_bucket": age_bucket.as_str(),
            "output_commitment_root": output_commitment_root,
            "histogram_root": histogram_root,
            "height": self.current_height,
        });
        let bucket_id = id_from_record("age_bucket", &seed);
        let mut record = OutputAgeBucketRecord {
            bucket_id: bucket_id.clone(),
            lane,
            age_bucket,
            output_commitment_root,
            histogram_root,
            output_count,
            median_age_blocks,
            p95_age_blocks,
            freshness_score_bps,
            recorded_at_height: self.current_height,
            bucket_root: String::new(),
        };
        record.bucket_root = record_root("age_bucket", &record.public_record());
        self.age_buckets.insert(bucket_id.clone(), record);
        self.counters.age_buckets = self.age_buckets.len() as u64;
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn bond_reputation_stake(
        &mut self,
        provider_id: &str,
        bonded_root: String,
        amount_micro_units: u64,
        lock_blocks: u64,
    ) -> Result<String> {
        let provider = self
            .providers
            .get_mut(provider_id)
            .ok_or_else(|| "unknown provider".to_string())?;
        if amount_micro_units < self.config.min_provider_stake {
            return Err("bonded reputation stake is below minimum".to_string());
        }
        provider.active_stake_micro_units = provider
            .active_stake_micro_units
            .saturating_add(amount_micro_units);
        provider.provider_root = record_root("provider", &provider.public_record());
        let seed = json!({
            "provider_id": provider_id,
            "bonded_root": bonded_root,
            "amount_micro_units": amount_micro_units,
        });
        let stake_id = id_from_record("reputation_stake", &seed);
        let mut record = ReputationStakeRecord {
            stake_id: stake_id.clone(),
            provider_id: provider_id.to_string(),
            bonded_root,
            amount_micro_units,
            reputation_floor_bps: self.config.min_reputation_score_bps,
            locked_until_height: self.current_height.saturating_add(lock_blocks),
            stake_root: String::new(),
        };
        record.stake_root = record_root("reputation_stake", &record.public_record());
        self.reputation_stakes.insert(stake_id.clone(), record);
        self.counters.reputation_stakes = self.reputation_stakes.len() as u64;
        self.refresh_roots();
        Ok(stake_id)
    }

    pub fn submit_ring_freshness_proof(
        &mut self,
        provider_id: &str,
        bucket_id: &str,
        ring_member_root: String,
        freshness_proof_root: String,
        view_key_redaction_root: String,
        ring_size: u16,
    ) -> Result<String> {
        if !self.providers.contains_key(provider_id) {
            return Err("unknown provider".to_string());
        }
        let bucket = self
            .age_buckets
            .get(bucket_id)
            .ok_or_else(|| "unknown output age bucket".to_string())?;
        if ring_size < self.config.target_ring_size {
            return Err("ring size is below market target".to_string());
        }
        let status = if bucket.freshness_score_bps >= self.config.min_freshness_score_bps {
            ProofStatus::Accepted
        } else {
            ProofStatus::Stale
        };
        let seed = json!({
            "provider_id": provider_id,
            "bucket_id": bucket_id,
            "ring_member_root": ring_member_root,
            "freshness_proof_root": freshness_proof_root,
        });
        let proof_id = id_from_record("ring_freshness_proof", &seed);
        let mut record = RingFreshnessProofRecord {
            proof_id: proof_id.clone(),
            provider_id: provider_id.to_string(),
            bucket_id: bucket_id.to_string(),
            lane: bucket.lane,
            ring_member_root,
            freshness_proof_root,
            view_key_redaction_root,
            ring_size,
            freshness_score_bps: bucket.freshness_score_bps,
            status,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.attestation_ttl_blocks),
            proof_root: String::new(),
        };
        record.proof_root = record_root("ring_freshness_proof", &record.public_record());
        self.ring_freshness_proofs.insert(proof_id.clone(), record);
        self.counters.ring_freshness_proofs = self.ring_freshness_proofs.len() as u64;
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn attest_reputation(
        &mut self,
        proof_id: &str,
        pq_signature_root: String,
        transcript_root: String,
    ) -> Result<String> {
        let proof = self
            .ring_freshness_proofs
            .get(proof_id)
            .ok_or_else(|| "unknown freshness proof".to_string())?;
        let provider = self
            .providers
            .get_mut(&proof.provider_id)
            .ok_or_else(|| "unknown provider".to_string())?;
        let quality_score_bps =
            quality_score(provider.reputation_score_bps, proof.freshness_score_bps);
        let status = if proof.status == ProofStatus::Accepted
            && quality_score_bps >= self.config.min_reputation_score_bps
        {
            provider.accepted_attestations = provider.accepted_attestations.saturating_add(1);
            provider.reputation_score_bps =
                reputation_after_success(provider.reputation_score_bps, proof.freshness_score_bps);
            AttestationStatus::Accepted
        } else {
            provider.slashed_events = provider.slashed_events.saturating_add(1);
            provider.reputation_score_bps =
                reputation_after_slash(provider.reputation_score_bps, self.config.slash_stale_bps);
            AttestationStatus::WeakReputation
        };
        provider.provider_root = record_root("provider", &provider.public_record());
        let seed = json!({
            "proof_id": proof_id,
            "provider_id": proof.provider_id,
            "pq_signature_root": pq_signature_root,
            "transcript_root": transcript_root,
        });
        let attestation_id = id_from_record("pq_reputation_attestation", &seed);
        let mut record = PqReputationAttestationRecord {
            attestation_id: attestation_id.clone(),
            proof_id: proof_id.to_string(),
            provider_id: proof.provider_id.clone(),
            pq_signature_root,
            transcript_root,
            reputation_score_bps: provider.reputation_score_bps,
            quality_score_bps,
            status,
            attested_at_height: self.current_height,
            attestation_root: String::new(),
        };
        record.attestation_root = record_root("pq_reputation_attestation", &record.public_record());
        self.pq_reputation_attestations
            .insert(attestation_id.clone(), record);
        self.counters.pq_reputation_attestations = self.pq_reputation_attestations.len() as u64;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_quality_rebate(
        &mut self,
        attestation_id: &str,
        beneficiary_root: String,
    ) -> Result<String> {
        let attestation = self
            .pq_reputation_attestations
            .get(attestation_id)
            .ok_or_else(|| "unknown reputation attestation".to_string())?;
        if attestation.status != AttestationStatus::Accepted {
            return Err("cannot rebate an unaccepted attestation".to_string());
        }
        let provider = self
            .providers
            .get(&attestation.provider_id)
            .ok_or_else(|| "unknown provider".to_string())?;
        let rebate_micro_units = provider
            .registration
            .max_fee_micro_units
            .saturating_mul(self.config.rebate_bps)
            / MAX_BPS;
        let seed = json!({
            "attestation_id": attestation_id,
            "beneficiary_root": beneficiary_root,
            "rebate_micro_units": rebate_micro_units,
        });
        let rebate_id = id_from_record("decoy_quality_rebate", &seed);
        let mut record = DecoyQualityRebateRecord {
            rebate_id: rebate_id.clone(),
            attestation_id: attestation_id.to_string(),
            provider_id: attestation.provider_id.clone(),
            beneficiary_root,
            rebate_micro_units,
            quality_score_bps: attestation.quality_score_bps,
            rebate_root: String::new(),
        };
        record.rebate_root = record_root("decoy_quality_rebate", &record.public_record());
        self.decoy_quality_rebates.insert(rebate_id.clone(), record);
        self.counters.decoy_quality_rebates = self.decoy_quality_rebates.len() as u64;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn redact_view_key(
        &mut self,
        proof_id: &str,
        disclosure_policy_root: String,
        redacted_view_key_root: String,
        retained_fields_root: String,
        privacy_set_size: u64,
    ) -> Result<String> {
        if !self.ring_freshness_proofs.contains_key(proof_id) {
            return Err("unknown freshness proof".to_string());
        }
        let seed = json!({
            "proof_id": proof_id,
            "disclosure_policy_root": disclosure_policy_root,
            "redacted_view_key_root": redacted_view_key_root,
        });
        let redaction_id = id_from_record("view_key_redaction", &seed);
        let mut record = ViewKeyRedactionRecord {
            redaction_id: redaction_id.clone(),
            proof_id: proof_id.to_string(),
            disclosure_policy_root,
            redacted_view_key_root,
            retained_fields_root,
            privacy_set_size,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.redaction_ttl_blocks),
            redaction_root: String::new(),
        };
        record.redaction_root = record_root("view_key_redaction", &record.public_record());
        self.view_key_redactions
            .insert(redaction_id.clone(), record);
        self.counters.view_key_redactions = self.view_key_redactions.len() as u64;
        self.refresh_roots();
        Ok(redaction_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.provider_root = map_root("providers", &self.providers, |record| {
            record.public_record()
        });
        self.roots.age_bucket_root = map_root("age_buckets", &self.age_buckets, |record| {
            record.public_record()
        });
        self.roots.reputation_stake_root =
            map_root("reputation_stakes", &self.reputation_stakes, |record| {
                record.public_record()
            });
        self.roots.ring_freshness_proof_root = map_root(
            "ring_freshness_proofs",
            &self.ring_freshness_proofs,
            |record| record.public_record(),
        );
        self.roots.pq_reputation_attestation_root = map_root(
            "pq_reputation_attestations",
            &self.pq_reputation_attestations,
            |record| record.public_record(),
        );
        self.roots.decoy_quality_rebate_root = map_root(
            "decoy_quality_rebates",
            &self.decoy_quality_rebates,
            |record| record.public_record(),
        );
        self.roots.view_key_redaction_root =
            map_root("view_key_redactions", &self.view_key_redactions, |record| {
                record.public_record()
            });
        self.roots.public_record_root = value_map_root("public_records", &self.public_records);
        self.roots.state_root = self.state_root();
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_reputation_attestation_suite": PQ_REPUTATION_ATTESTATION_SUITE,
            "ring_freshness_proof_suite": RING_FRESHNESS_PROOF_SUITE,
            "view_key_redaction_suite": VIEW_KEY_REDACTION_SUITE,
            "decoy_quality_rebate_suite": DECOY_QUALITY_REBATE_SUITE,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "operator_summary": {
                "providers": self.providers.len(),
                "age_buckets": self.age_buckets.len(),
                "accepted_proofs": self.ring_freshness_proofs.values().filter(|proof| proof.status == ProofStatus::Accepted).count(),
                "accepted_attestations": self.pq_reputation_attestations.values().filter(|attestation| attestation.status == AttestationStatus::Accepted).count(),
                "rebates": self.decoy_quality_rebates.len(),
                "view_key_redactions": self.view_key_redactions.len(),
            },
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    seed_devnet(&mut state);
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

fn seed_devnet(state: &mut State) {
    let provider_id = state
        .register_provider(DecoyProviderRegistration {
            provider_label: "output-decoy-reputation-provider-a".to_string(),
            operator_root: deterministic_root("operator", "provider-a"),
            pq_signer_root: deterministic_root("pq_signer", "provider-a"),
            inventory_commitment_root: deterministic_root("inventory", "provider-a"),
            max_fee_micro_units: 4_800,
            stake_micro_units: 8_000_000,
            initial_reputation_bps: 8_250,
        })
        .expect("devnet provider");
    state
        .bond_reputation_stake(
            &provider_id,
            deterministic_root("bonded_stake", "provider-a"),
            3_000_000,
            43_200,
        )
        .expect("devnet stake");
    let bucket_id = state
        .record_output_age_bucket(
            MarketLane::BridgeWithdrawal,
            OutputAgeBucket::Standard1To7Days,
            deterministic_root("output_commitments", "bridge-withdrawal-window-a"),
            deterministic_root("histogram", "bridge-withdrawal-window-a"),
            262_144,
            1_920,
            12_960,
        )
        .expect("devnet age bucket");
    let proof_id = state
        .submit_ring_freshness_proof(
            &provider_id,
            &bucket_id,
            deterministic_root("ring_members", "bridge-withdrawal-window-a"),
            deterministic_root("freshness_proof", "bridge-withdrawal-window-a"),
            deterministic_root("view_key_redaction", "bridge-withdrawal-window-a"),
            128,
        )
        .expect("devnet freshness proof");
    let attestation_id = state
        .attest_reputation(
            &proof_id,
            deterministic_root("pq_signature", "provider-a"),
            deterministic_root("transcript", "provider-a"),
        )
        .expect("devnet reputation attestation");
    state
        .settle_quality_rebate(
            &attestation_id,
            deterministic_root("beneficiary", "bridge-withdrawal-wallet-a"),
        )
        .expect("devnet rebate");
    state
        .redact_view_key(
            &proof_id,
            deterministic_root("disclosure_policy", "operator-safe"),
            deterministic_root("redacted_view_key", "wallet-a"),
            deterministic_root("retained_fields", "roots-only"),
            262_144,
        )
        .expect("devnet view-key redaction");
    state.public_records.insert(
        "devnet-output-decoy-reputation-market".to_string(),
        state.public_record_without_state_root(),
    );
    state.counters.public_records = state.public_records.len() as u64;
    state.refresh_roots();
}

fn freshness_score(median_age_blocks: u64, p95_age_blocks: u64) -> u64 {
    let median_component =
        MAX_BPS.saturating_sub(median_age_blocks.saturating_mul(MAX_BPS) / 21_600);
    let tail_component = MAX_BPS.saturating_sub(p95_age_blocks.saturating_mul(MAX_BPS) / 86_400);
    (median_component.saturating_mul(60) + tail_component.saturating_mul(40)) / 100
}

fn quality_score(reputation_score_bps: u64, freshness_score_bps: u64) -> u64 {
    ((reputation_score_bps.saturating_mul(55) + freshness_score_bps.saturating_mul(45)) / 100)
        .min(MAX_BPS)
}

fn reputation_after_success(current_bps: u64, freshness_score_bps: u64) -> u64 {
    let lift = freshness_score_bps.saturating_sub(current_bps) / 8;
    current_bps.saturating_add(lift.max(25)).min(MAX_BPS)
}

fn reputation_after_slash(current_bps: u64, slash_bps: u64) -> u64 {
    current_bps.saturating_mul(MAX_BPS.saturating_sub(slash_bps)) / MAX_BPS
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-output-decoy-reputation-market:{domain}:root"),
        &[HashPart::Str(label)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-output-decoy-reputation-market:{domain}:empty"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-output-decoy-reputation-market:{domain}:id"),
        &[HashPart::Json(record)],
        16,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-output-decoy-reputation-market:{domain}:record"),
        &[HashPart::Json(record)],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-output-decoy-reputation-market:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": public(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-output-decoy-reputation-market:{domain}"),
        &leaves,
    )
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-output-decoy-reputation-market:{domain}"),
        &leaves,
    )
}
