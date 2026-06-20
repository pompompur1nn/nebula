use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateDecoySetQualityMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_DECOY_SET_QUALITY_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-decoy-set-quality-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_DECOY_SET_QUALITY_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-decoy-quality-market-v1";
pub const DECOY_QUALITY_SUITE: &str = "monero-decoy-quality-commitment-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-decoy-quality-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-decoy-quality-redaction-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_064_800;
pub const DEFAULT_MIN_DECOYS: u16 = 64;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_ENTROPY_BPS: u64 = 8_500;
pub const DEFAULT_MIN_FRESHNESS_BPS: u64 = 7_200;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_QUOTE_FEE_MICRO_UNITS: u64 = 8_000;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_250;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 2_160;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyQualityLane {
    WalletScan,
    BridgeWithdrawal,
    TokenReceipt,
    DexSettlement,
    MerchantPayment,
    WatchtowerAudit,
}

impl DecoyQualityLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::TokenReceipt => "token_receipt",
            Self::DexSettlement => "dex_settlement",
            Self::MerchantPayment => "merchant_payment",
            Self::WatchtowerAudit => "watchtower_audit",
        }
    }

    pub fn default_fee_cap(self) -> u64 {
        match self {
            Self::WalletScan => 1_500,
            Self::BridgeWithdrawal => 5_500,
            Self::TokenReceipt => 2_400,
            Self::DexSettlement => 6_000,
            Self::MerchantPayment => 1_900,
            Self::WatchtowerAudit => 3_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Accepted,
    Attested,
    Rebated,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub min_decoys: u16,
    pub min_privacy_set_size: u64,
    pub min_entropy_bps: u64,
    pub min_freshness_bps: u64,
    pub target_pq_security_bits: u16,
    pub max_quote_fee_micro_units: u64,
    pub low_fee_rebate_bps: u64,
    pub quote_ttl_blocks: u64,
    pub quarantine_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            min_decoys: DEFAULT_MIN_DECOYS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_entropy_bps: DEFAULT_MIN_ENTROPY_BPS,
            min_freshness_bps: DEFAULT_MIN_FRESHNESS_BPS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_quote_fee_micro_units: DEFAULT_MAX_QUOTE_FEE_MICRO_UNITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "min_decoys": self.min_decoys,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_entropy_bps": self.min_entropy_bps,
            "min_freshness_bps": self.min_freshness_bps,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_quote_fee_micro_units": self.max_quote_fee_micro_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "quarantine_blocks": self.quarantine_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub providers: u64,
    pub decoy_sets: u64,
    pub quality_quotes: u64,
    pub pq_attestations: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub quarantines: u64,
    pub public_summaries: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "providers": self.providers,
            "decoy_sets": self.decoy_sets,
            "quality_quotes": self.quality_quotes,
            "pq_attestations": self.pq_attestations,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "quarantines": self.quarantines,
            "public_summaries": self.public_summaries,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub provider_root: String,
    pub decoy_set_root: String,
    pub quote_root: String,
    pub pq_attestation_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub public_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            provider_root: empty_root("providers"),
            decoy_set_root: empty_root("decoy_sets"),
            quote_root: empty_root("quotes"),
            pq_attestation_root: empty_root("pq_attestations"),
            rebate_root: empty_root("rebates"),
            redaction_root: empty_root("redactions"),
            public_summary_root: empty_root("public_summaries"),
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
            "decoy_set_root": self.decoy_set_root,
            "quote_root": self.quote_root,
            "pq_attestation_root": self.pq_attestation_root,
            "rebate_root": self.rebate_root,
            "redaction_root": self.redaction_root,
            "public_summary_root": self.public_summary_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderRegistrationRequest {
    pub provider_label: String,
    pub pq_signer_root: String,
    pub quote_commitment_root: String,
    pub capacity_sets: u64,
    pub max_fee_micro_units: u64,
    pub pq_security_bits: u16,
}

impl ProviderRegistrationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_label": self.provider_label,
            "pq_signer_root": self.pq_signer_root,
            "quote_commitment_root": self.quote_commitment_root,
            "capacity_sets": self.capacity_sets,
            "max_fee_micro_units": self.max_fee_micro_units,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderRecord {
    pub provider_id: String,
    pub request: ProviderRegistrationRequest,
    pub available_capacity: u64,
    pub registered_at_height: u64,
    pub slashed_count: u64,
    pub provider_root: String,
}

impl ProviderRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "request": self.request.public_record(),
            "available_capacity": self.available_capacity,
            "registered_at_height": self.registered_at_height,
            "slashed_count": self.slashed_count,
            "provider_root": self.provider_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoySetSubmissionRequest {
    pub wallet_context_root: String,
    pub lane: DecoyQualityLane,
    pub output_age_histogram_root: String,
    pub ring_member_root: String,
    pub decoy_selection_root: String,
    pub view_tag_redaction_root: String,
    pub bridge_context_root: String,
    pub decoy_count: u16,
    pub privacy_set_size: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
}

impl DecoySetSubmissionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "wallet_context_root": self.wallet_context_root,
            "lane": self.lane.as_str(),
            "output_age_histogram_root": self.output_age_histogram_root,
            "ring_member_root": self.ring_member_root,
            "decoy_selection_root": self.decoy_selection_root,
            "view_tag_redaction_root": self.view_tag_redaction_root,
            "bridge_context_root": self.bridge_context_root,
            "decoy_count": self.decoy_count,
            "privacy_set_size": self.privacy_set_size,
            "median_age_blocks": self.median_age_blocks,
            "p95_age_blocks": self.p95_age_blocks,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoySetRecord {
    pub decoy_set_id: String,
    pub request: DecoySetSubmissionRequest,
    pub entropy_score_bps: u64,
    pub freshness_score_bps: u64,
    pub quality_score_bps: u64,
    pub submitted_at_height: u64,
    pub quarantined_until_height: Option<u64>,
    pub decoy_set_root: String,
}

impl DecoySetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "decoy_set_id": self.decoy_set_id,
            "request": self.request.public_record(),
            "entropy_score_bps": self.entropy_score_bps,
            "freshness_score_bps": self.freshness_score_bps,
            "quality_score_bps": self.quality_score_bps,
            "submitted_at_height": self.submitted_at_height,
            "quarantined_until_height": self.quarantined_until_height,
            "decoy_set_root": self.decoy_set_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QualityQuoteRequest {
    pub decoy_set_id: String,
    pub provider_id: String,
    pub lane: DecoyQualityLane,
    pub max_fee_micro_units: u64,
    pub target_quality_bps: u64,
    pub low_fee_sponsor_root: String,
    pub pq_session_root: String,
}

impl QualityQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "decoy_set_id": self.decoy_set_id,
            "provider_id": self.provider_id,
            "lane": self.lane.as_str(),
            "max_fee_micro_units": self.max_fee_micro_units,
            "target_quality_bps": self.target_quality_bps,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_session_root": self.pq_session_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QualityQuoteRecord {
    pub quote_id: String,
    pub request: QualityQuoteRequest,
    pub quoted_fee_micro_units: u64,
    pub quoted_quality_bps: u64,
    pub status: QuoteStatus,
    pub accepted_at_height: Option<u64>,
    pub expires_at_height: u64,
    pub quote_root: String,
}

impl QualityQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "request": self.request.public_record(),
            "quoted_fee_micro_units": self.quoted_fee_micro_units,
            "quoted_quality_bps": self.quoted_quality_bps,
            "status": self.status,
            "accepted_at_height": self.accepted_at_height,
            "expires_at_height": self.expires_at_height,
            "quote_root": self.quote_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqQualityAttestationRequest {
    pub quote_id: String,
    pub provider_id: String,
    pub attested_decoy_set_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub quality_floor_bps: u64,
    pub privacy_set_size: u64,
    pub disclosure_root: String,
}

impl PqQualityAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "provider_id": self.provider_id,
            "attested_decoy_set_root": self.attested_decoy_set_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "quality_floor_bps": self.quality_floor_bps,
            "privacy_set_size": self.privacy_set_size,
            "disclosure_root": self.disclosure_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqQualityAttestationRecord {
    pub attestation_id: String,
    pub request: PqQualityAttestationRequest,
    pub attested_at_height: u64,
    pub attestation_root: String,
}

impl PqQualityAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "attested_at_height": self.attested_at_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub quote_id: String,
    pub provider_id: String,
    pub lane: DecoyQualityLane,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub sponsor_pool_root: String,
    pub settled_at_height: u64,
    pub rebate_root: String,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "quote_id": self.quote_id,
            "provider_id": self.provider_id,
            "lane": self.lane.as_str(),
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_pool_root": self.sponsor_pool_root,
            "settled_at_height": self.settled_at_height,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudgetRecord {
    pub redaction_id: String,
    pub subject_id: String,
    pub disclosed_fields_root: String,
    pub remaining_budget_units: u64,
    pub privacy_set_size: u64,
    pub redaction_root: String,
}

impl RedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "subject_id": self.subject_id,
            "disclosed_fields_root": self.disclosed_fields_root,
            "remaining_budget_units": self.remaining_budget_units,
            "privacy_set_size": self.privacy_set_size,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub protocol_version: String,
    pub state_root: String,
    pub provider_count: u64,
    pub decoy_set_count: u64,
    pub accepted_quotes: u64,
    pub quarantined_sets: u64,
    pub average_quality_bps: u64,
    pub average_fee_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub target_pq_security_bits: u16,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "state_root": self.state_root,
            "provider_count": self.provider_count,
            "decoy_set_count": self.decoy_set_count,
            "accepted_quotes": self.accepted_quotes,
            "quarantined_sets": self.quarantined_sets,
            "average_quality_bps": self.average_quality_bps,
            "average_fee_micro_units": self.average_fee_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_pq_security_bits": self.target_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub providers: BTreeMap<String, ProviderRecord>,
    pub decoy_sets: BTreeMap<String, DecoySetRecord>,
    pub quotes: BTreeMap<String, QualityQuoteRecord>,
    pub pq_attestations: BTreeMap<String, PqQualityAttestationRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub redactions: BTreeMap<String, RedactionBudgetRecord>,
    pub public_summaries: BTreeMap<String, Value>,
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
            decoy_sets: BTreeMap::new(),
            quotes: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redactions: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
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

    pub fn register_provider(&mut self, request: ProviderRegistrationRequest) -> Result<String> {
        if request.pq_security_bits < self.config.target_pq_security_bits {
            return Err("provider PQ security is below market floor".to_string());
        }
        if request.max_fee_micro_units > self.config.max_quote_fee_micro_units {
            return Err("provider max fee exceeds market cap".to_string());
        }
        let provider_id = id_from_record("provider", &request.public_record());
        let mut record = ProviderRecord {
            provider_id: provider_id.clone(),
            available_capacity: request.capacity_sets,
            registered_at_height: self.current_height,
            slashed_count: 0,
            provider_root: String::new(),
            request,
        };
        record.provider_root = record_root("provider", &record.public_record());
        self.providers.insert(provider_id.clone(), record);
        self.counters.providers = self.providers.len() as u64;
        self.refresh_roots();
        Ok(provider_id)
    }

    pub fn submit_decoy_set(&mut self, request: DecoySetSubmissionRequest) -> Result<String> {
        if request.decoy_count < self.config.min_decoys {
            return Err("decoy count below privacy floor".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set size below market floor".to_string());
        }
        let entropy = entropy_score(request.decoy_count, request.privacy_set_size);
        let freshness = freshness_score(request.median_age_blocks, request.p95_age_blocks);
        let quality = quality_score(entropy, freshness);
        let decoy_set_id = id_from_record("decoy_set", &request.public_record());
        let mut record = DecoySetRecord {
            decoy_set_id: decoy_set_id.clone(),
            request,
            entropy_score_bps: entropy,
            freshness_score_bps: freshness,
            quality_score_bps: quality,
            submitted_at_height: self.current_height,
            quarantined_until_height: None,
            decoy_set_root: String::new(),
        };
        record.decoy_set_root = record_root("decoy_set", &record.public_record());
        self.decoy_sets.insert(decoy_set_id.clone(), record);
        self.counters.decoy_sets = self.decoy_sets.len() as u64;
        self.refresh_roots();
        Ok(decoy_set_id)
    }

    pub fn quote_quality(&mut self, request: QualityQuoteRequest) -> Result<String> {
        let decoy_set = self
            .decoy_sets
            .get(&request.decoy_set_id)
            .ok_or_else(|| "unknown decoy set".to_string())?;
        let provider = self
            .providers
            .get(&request.provider_id)
            .ok_or_else(|| "unknown quality provider".to_string())?;
        if provider.available_capacity == 0 {
            return Err("provider capacity exhausted".to_string());
        }
        if request.target_quality_bps > decoy_set.quality_score_bps {
            return Err("target quality exceeds decoy-set quality".to_string());
        }
        let lane_cap = request.lane.default_fee_cap();
        let quoted_fee = quote_fee(
            decoy_set.quality_score_bps,
            request.target_quality_bps,
            lane_cap.min(request.max_fee_micro_units),
        );
        if quoted_fee > request.max_fee_micro_units {
            return Err("quoted fee exceeds request cap".to_string());
        }
        let quote_id = id_from_record("quote", &request.public_record());
        let mut record = QualityQuoteRecord {
            quote_id: quote_id.clone(),
            request,
            quoted_fee_micro_units: quoted_fee,
            quoted_quality_bps: decoy_set.quality_score_bps,
            status: QuoteStatus::Open,
            accepted_at_height: None,
            expires_at_height: self.current_height + self.config.quote_ttl_blocks,
            quote_root: String::new(),
        };
        record.quote_root = record_root("quote", &record.public_record());
        self.quotes.insert(quote_id.clone(), record);
        self.counters.quality_quotes = self.quotes.len() as u64;
        self.refresh_roots();
        Ok(quote_id)
    }

    pub fn accept_quote(&mut self, quote_id: &str) -> Result<()> {
        let (provider_id, status) = {
            let quote = self
                .quotes
                .get_mut(quote_id)
                .ok_or_else(|| "unknown quality quote".to_string())?;
            if quote.expires_at_height < self.current_height {
                return Err("quality quote expired".to_string());
            }
            quote.status = QuoteStatus::Accepted;
            quote.accepted_at_height = Some(self.current_height);
            (quote.request.provider_id.clone(), quote.status)
        };
        if status == QuoteStatus::Accepted {
            if let Some(provider) = self.providers.get_mut(&provider_id) {
                provider.available_capacity = provider.available_capacity.saturating_sub(1);
            }
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn attest_quality(&mut self, request: PqQualityAttestationRequest) -> Result<String> {
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("attestation privacy set below floor".to_string());
        }
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| "unknown quality quote".to_string())?;
        if quote.status != QuoteStatus::Accepted {
            return Err("quality quote must be accepted before attestation".to_string());
        }
        if quote.request.provider_id != request.provider_id {
            return Err("attestation provider mismatch".to_string());
        }
        if request.quality_floor_bps
            < self
                .config
                .min_entropy_bps
                .min(self.config.min_freshness_bps)
        {
            return Err("attestation quality floor below market floor".to_string());
        }
        quote.status = QuoteStatus::Attested;
        let attestation_id = id_from_record("pq_attestation", &request.public_record());
        let mut record = PqQualityAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            attested_at_height: self.current_height,
            attestation_root: String::new(),
        };
        record.attestation_root = record_root("pq_attestation", &record.public_record());
        self.pq_attestations.insert(attestation_id.clone(), record);
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_rebate(&mut self, quote_id: &str) -> Result<String> {
        let (provider_id, lane, fee_paid, sponsor_pool_root) = {
            let quote = self
                .quotes
                .get_mut(quote_id)
                .ok_or_else(|| "unknown quality quote".to_string())?;
            if quote.status != QuoteStatus::Attested {
                return Err("quality quote must be attested before rebate settlement".to_string());
            }
            quote.status = QuoteStatus::Rebated;
            (
                quote.request.provider_id.clone(),
                quote.request.lane,
                quote.quoted_fee_micro_units,
                quote.request.low_fee_sponsor_root.clone(),
            )
        };
        let rebate = fee_paid.saturating_mul(self.config.low_fee_rebate_bps) / MAX_BPS;
        let fee_paid_string = fee_paid.to_string();
        let rebate_id = deterministic_id("rebate", &[quote_id, &provider_id, &fee_paid_string]);
        let mut record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            quote_id: quote_id.to_string(),
            provider_id,
            lane,
            fee_paid_micro_units: fee_paid,
            rebate_micro_units: rebate,
            sponsor_pool_root,
            settled_at_height: self.current_height,
            rebate_root: String::new(),
        };
        record.rebate_root = record_root("rebate", &record.public_record());
        self.rebates.insert(rebate_id.clone(), record);
        self.counters.rebates = self.rebates.len() as u64;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn record_redaction_budget(
        &mut self,
        subject_id: &str,
        disclosed_fields_root: String,
        remaining_budget_units: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction privacy set below floor".to_string());
        }
        let privacy_set_string = privacy_set_size.to_string();
        let redaction_id = deterministic_id(
            "redaction",
            &[subject_id, &disclosed_fields_root, &privacy_set_string],
        );
        let mut record = RedactionBudgetRecord {
            redaction_id: redaction_id.clone(),
            subject_id: subject_id.to_string(),
            disclosed_fields_root,
            remaining_budget_units,
            privacy_set_size,
            redaction_root: String::new(),
        };
        record.redaction_root = record_root("redaction", &record.public_record());
        self.redactions.insert(redaction_id.clone(), record);
        self.counters.redaction_budgets = self.redactions.len() as u64;
        self.refresh_roots();
        Ok(redaction_id)
    }

    pub fn quarantine_decoy_set(
        &mut self,
        decoy_set_id: &str,
        reason_root: String,
    ) -> Result<String> {
        let decoy_set = self
            .decoy_sets
            .get_mut(decoy_set_id)
            .ok_or_else(|| "unknown decoy set".to_string())?;
        decoy_set.quarantined_until_height =
            Some(self.current_height + self.config.quarantine_blocks);
        self.counters.quarantines = self.counters.quarantines.saturating_add(1);
        let summary_id = deterministic_id("quarantine", &[decoy_set_id, &reason_root]);
        self.public_summaries.insert(
            summary_id.clone(),
            json!({
                "kind": "decoy_quality_quarantine",
                "decoy_set_id": decoy_set_id,
                "reason_root": reason_root,
                "until_height": decoy_set.quarantined_until_height,
                "height": self.current_height,
            }),
        );
        self.counters.public_summaries = self.public_summaries.len() as u64;
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn operator_summary(&self) -> OperatorSummary {
        self.operator_summary_with_state_root(self.state_root())
    }

    fn operator_summary_without_state_root(&self) -> OperatorSummary {
        self.operator_summary_with_state_root(String::new())
    }

    fn operator_summary_with_state_root(&self, state_root: String) -> OperatorSummary {
        let accepted_quotes = self
            .quotes
            .values()
            .filter(|quote| {
                quote.status == QuoteStatus::Accepted
                    || quote.status == QuoteStatus::Attested
                    || quote.status == QuoteStatus::Rebated
            })
            .count() as u64;
        let quarantined_sets = self
            .decoy_sets
            .values()
            .filter(|set| set.quarantined_until_height.unwrap_or(0) >= self.current_height)
            .count() as u64;
        let total_quality = self
            .decoy_sets
            .values()
            .map(|set| set.quality_score_bps)
            .sum::<u64>();
        let average_quality = if self.decoy_sets.is_empty() {
            0
        } else {
            total_quality / self.decoy_sets.len() as u64
        };
        let total_fee = self
            .quotes
            .values()
            .map(|quote| quote.quoted_fee_micro_units)
            .sum::<u64>();
        let average_fee = if self.quotes.is_empty() {
            0
        } else {
            total_fee / self.quotes.len() as u64
        };
        OperatorSummary {
            protocol_version: PROTOCOL_VERSION.to_string(),
            state_root,
            provider_count: self.providers.len() as u64,
            decoy_set_count: self.decoy_sets.len() as u64,
            accepted_quotes,
            quarantined_sets,
            average_quality_bps: average_quality,
            average_fee_micro_units: average_fee,
            min_privacy_set_size: self.config.min_privacy_set_size,
            target_pq_security_bits: self.config.target_pq_security_bits,
        }
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.provider_root =
            map_root("providers", &self.providers, ProviderRecord::public_record);
        self.roots.decoy_set_root = map_root(
            "decoy_sets",
            &self.decoy_sets,
            DecoySetRecord::public_record,
        );
        self.roots.quote_root = map_root("quotes", &self.quotes, QualityQuoteRecord::public_record);
        self.roots.pq_attestation_root = map_root(
            "pq_attestations",
            &self.pq_attestations,
            PqQualityAttestationRecord::public_record,
        );
        self.roots.rebate_root = map_root("rebates", &self.rebates, FeeRebateRecord::public_record);
        self.roots.redaction_root = map_root(
            "redactions",
            &self.redactions,
            RedactionBudgetRecord::public_record,
        );
        self.roots.public_summary_root = value_map_root("public_summaries", &self.public_summaries);
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
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "decoy_quality_suite": DECOY_QUALITY_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "redaction_suite": REDACTION_SUITE,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "operator_summary": self.operator_summary_without_state_root().public_record(),
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
        .register_provider(ProviderRegistrationRequest {
            provider_label: "decoy-quality-market-maker-a".to_string(),
            pq_signer_root: deterministic_root("pq_signer", "provider-a"),
            quote_commitment_root: deterministic_root("quote_commitment", "provider-a"),
            capacity_sets: 128,
            max_fee_micro_units: 4_200,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
        })
        .expect("devnet provider");

    let decoy_set_id = state
        .submit_decoy_set(DecoySetSubmissionRequest {
            wallet_context_root: deterministic_root("wallet_context", "bridge-wallet-a"),
            lane: DecoyQualityLane::BridgeWithdrawal,
            output_age_histogram_root: deterministic_root("age_histogram", "bridge-window-a"),
            ring_member_root: deterministic_root("ring_members", "bridge-window-a"),
            decoy_selection_root: deterministic_root("decoy_selection", "bridge-window-a"),
            view_tag_redaction_root: deterministic_root("view_tag_redaction", "bridge-window-a"),
            bridge_context_root: deterministic_root("bridge_context", "withdrawal-batch-a"),
            decoy_count: 96,
            privacy_set_size: 131_072,
            median_age_blocks: 1_440,
            p95_age_blocks: 9_600,
        })
        .expect("devnet decoy set");

    let quote_id = state
        .quote_quality(QualityQuoteRequest {
            decoy_set_id: decoy_set_id.clone(),
            provider_id: provider_id.clone(),
            lane: DecoyQualityLane::BridgeWithdrawal,
            max_fee_micro_units: 4_800,
            target_quality_bps: 7_800,
            low_fee_sponsor_root: deterministic_root("sponsor", "wallet-a"),
            pq_session_root: deterministic_root("pq_session", "wallet-a"),
        })
        .expect("devnet quote");

    state.accept_quote(&quote_id).expect("devnet accept");
    state
        .attest_quality(PqQualityAttestationRequest {
            quote_id: quote_id.clone(),
            provider_id,
            attested_decoy_set_root: deterministic_root("attested_decoy_set", "bridge-window-a"),
            pq_signature_root: deterministic_root("pq_signature", "quality-provider-a"),
            transcript_root: deterministic_root("transcript", "quality-provider-a"),
            quality_floor_bps: 7_650,
            privacy_set_size: 131_072,
            disclosure_root: deterministic_root("disclosure", "operator-safe"),
        })
        .expect("devnet attestation");
    state.settle_rebate(&quote_id).expect("devnet rebate");
    state
        .record_redaction_budget(
            &decoy_set_id,
            deterministic_root("disclosed_fields", "roots-only"),
            18_000,
            131_072,
        )
        .expect("devnet redaction");
    state.refresh_roots();
}

fn entropy_score(decoy_count: u16, privacy_set_size: u64) -> u64 {
    let decoy_component = (decoy_count as u64)
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_MIN_DECOYS as u64)
        .min(MAX_BPS);
    let set_component = privacy_set_size
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_MIN_PRIVACY_SET_SIZE)
        .min(MAX_BPS);
    (decoy_component.saturating_mul(45) + set_component.saturating_mul(55)) / 100
}

fn freshness_score(median_age_blocks: u64, p95_age_blocks: u64) -> u64 {
    let median_component =
        MAX_BPS.saturating_sub(median_age_blocks.saturating_mul(MAX_BPS) / 21_600);
    let tail_component = MAX_BPS.saturating_sub(p95_age_blocks.saturating_mul(MAX_BPS) / 86_400);
    (median_component.saturating_mul(60) + tail_component.saturating_mul(40)) / 100
}

fn quality_score(entropy_bps: u64, freshness_bps: u64) -> u64 {
    ((entropy_bps.saturating_mul(55) + freshness_bps.saturating_mul(45)) / 100).min(MAX_BPS)
}

fn quote_fee(quality_bps: u64, target_quality_bps: u64, cap: u64) -> u64 {
    let margin = quality_bps.saturating_sub(target_quality_bps);
    let discount_bps = (margin / 2).min(4_000);
    cap.saturating_mul(MAX_BPS.saturating_sub(discount_bps)) / MAX_BPS
}

fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("monero-l2-pq-decoy-quality-market:{domain}:id"),
        &hash_parts,
        16,
    )
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-decoy-quality-market:{domain}:root"),
        &[HashPart::Str(label)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-decoy-quality-market:{domain}:empty"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-decoy-quality-market:{domain}:id"),
        &[HashPart::Json(record)],
        16,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-decoy-quality-market:{domain}:record"),
        &[HashPart::Json(record)],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-decoy-quality-market:state-root",
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
        &format!("monero-l2-pq-decoy-quality-market:{domain}"),
        &leaves,
    )
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-decoy-quality-market:{domain}"),
        &leaves,
    )
}
