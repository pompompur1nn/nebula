use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_SPONSOR_SETTLEMENT_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-sponsor-settlement-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_SPONSOR_SETTLEMENT_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-fee-sponsor-settlement-router-v1";
pub const SPONSOR_COMMITMENT_SCHEME: &str =
    "private-l2-low-fee-pq-confidential-fee-sponsor-commitment-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str =
    "private-l2-low-fee-pq-confidential-sponsored-settlement-batch-v1";
pub const PRIVACY_FENCE_SCHEME: &str =
    "private-l2-low-fee-pq-confidential-sponsor-nullifier-fence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_CHAIN_ID: u64 = 731_337;
pub const DEVNET_HEIGHT: u64 = 2_240_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 12;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 4_320;
pub const MAX_SPONSORS: usize = 1_048_576;
pub const MAX_SETTLEMENT_BATCHES: usize = 2_097_152;
pub const MAX_PRIVACY_FENCES: usize = 4_194_304;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorLane {
    PrivateTransfer,
    ContractCall,
    DefiBundle,
    BridgeExit,
    ProofBatch,
}

impl SponsorLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiBundle => "defi_bundle",
            Self::BridgeExit => "bridge_exit",
            Self::ProofBatch => "proof_batch",
        }
    }

    pub fn lane_weight(self) -> u64 {
        match self {
            Self::PrivateTransfer => 2,
            Self::ContractCall => 4,
            Self::DefiBundle => 6,
            Self::BridgeExit => 7,
            Self::ProofBatch => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Routed,
    Settled,
    Disputed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub batch_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub sponsors_registered: u64,
    pub batches_opened: u64,
    pub batches_settled: u64,
    pub privacy_fences_registered: u64,
    pub routed_fee_credits: u64,
    pub rebates_issued: u64,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsors_registered": self.sponsors_registered,
            "batches_opened": self.batches_opened,
            "batches_settled": self.batches_settled,
            "privacy_fences_registered": self.privacy_fences_registered,
            "routed_fee_credits": self.routed_fee_credits,
            "rebates_issued": self.rebates_issued,
            "events_emitted": self.events_emitted,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub sponsors_root: String,
    pub batches_root: String,
    pub privacy_fences_root: String,
    pub sponsor_indexes_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsors_root": self.sponsors_root,
            "batches_root": self.batches_root,
            "privacy_fences_root": self.privacy_fences_root,
            "sponsor_indexes_root": self.sponsor_indexes_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCommitment {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub lane: SponsorLane,
    pub available_fee_credits: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub policy_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SponsorCommitment {
    pub fn new(
        config: &Config,
        sponsor_commitment: impl Into<String>,
        lane: SponsorLane,
        available_fee_credits: u64,
        nonce: u64,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let sponsor_id = sponsor_id(&sponsor_commitment, lane, nonce);
        let policy_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:POLICY",
            &[
                HashPart::Str(&sponsor_id),
                HashPart::Str(SPONSOR_COMMITMENT_SCHEME),
                HashPart::U64(lane.lane_weight()),
            ],
            32,
        );
        Self {
            sponsor_id,
            sponsor_commitment,
            lane,
            available_fee_credits,
            max_fee_bps: config.max_sponsor_fee_bps,
            rebate_bps: config.target_rebate_bps,
            pq_security_bits: config.min_pq_security_bits,
            privacy_set_size: config.min_privacy_set_size,
            policy_root,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.sponsor_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane,
            "available_fee_credits": self.available_fee_credits,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "policy_root": self.policy_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub lane: SponsorLane,
    pub sponsor_id: String,
    pub encrypted_bundle_root: String,
    pub fee_credit_amount: u64,
    pub rebate_amount: u64,
    pub nullifier_root: String,
    pub status: SettlementStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SettlementBatch {
    pub fn new(
        config: &Config,
        sponsor_id: impl Into<String>,
        lane: SponsorLane,
        encrypted_bundle_root: impl Into<String>,
        fee_credit_amount: u64,
        nonce: u64,
    ) -> Self {
        let sponsor_id = sponsor_id.into();
        let encrypted_bundle_root = encrypted_bundle_root.into();
        let batch_id = settlement_batch_id(&sponsor_id, lane, &encrypted_bundle_root, nonce);
        let rebate_amount = fee_credit_amount
            .saturating_mul(config.target_rebate_bps)
            .saturating_div(10_000);
        let nullifier_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:BATCH-NULLIFIER",
            &[
                HashPart::Str(&batch_id),
                HashPart::Str(SETTLEMENT_BATCH_SCHEME),
            ],
            32,
        );
        Self {
            batch_id,
            lane,
            sponsor_id,
            encrypted_bundle_root,
            fee_credit_amount,
            rebate_amount,
            nullifier_root,
            status: SettlementStatus::Open,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.batch_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane,
            "sponsor_id": self.sponsor_id,
            "encrypted_bundle_root": self.encrypted_bundle_root,
            "fee_credit_amount": self.fee_credit_amount,
            "rebate_amount": self.rebate_amount,
            "nullifier_root": self.nullifier_root,
            "status": self.status,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub sponsor_id: String,
    pub nullifier_root: String,
    pub disclosure_policy_root: String,
    pub privacy_set_size: u64,
}

impl PrivacyFence {
    pub fn new(config: &Config, sponsor_id: impl Into<String>, nonce: u64) -> Self {
        let sponsor_id = sponsor_id.into();
        let fence_id = privacy_fence_id(&sponsor_id, nonce);
        let nullifier_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:FENCE-NULLIFIER",
            &[
                HashPart::Str(&fence_id),
                HashPart::Str(PRIVACY_FENCE_SCHEME),
            ],
            32,
        );
        let disclosure_policy_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:DISCLOSURE",
            &[
                HashPart::Str(&fence_id),
                HashPart::Str("selective-view-key"),
            ],
            32,
        );
        Self {
            fence_id,
            sponsor_id,
            nullifier_root,
            disclosure_policy_root,
            privacy_set_size: config.min_privacy_set_size,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "sponsor_id": self.sponsor_id,
            "nullifier_root": self.nullifier_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsors: BTreeMap<String, SponsorCommitment>,
    pub batches: BTreeMap<String, SettlementBatch>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub sponsors_by_lane: BTreeMap<SponsorLane, BTreeSet<String>>,
    pub events: Vec<Value>,
}

impl State {
    pub fn empty(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sponsors: BTreeMap::new(),
            batches: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            sponsors_by_lane: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::empty(config.clone());
        let sponsor = SponsorCommitment::new(
            &config,
            "sponsor:sealed:devnet:contract-call-router",
            SponsorLane::ContractCall,
            7_500_000,
            1,
        );
        let sponsor_id = sponsor.sponsor_id.clone();
        let _ = state.register_sponsor(sponsor);
        let _ = state.register_privacy_fence(PrivacyFence::new(&config, &sponsor_id, 2));
        let batch = SettlementBatch::new(
            &config,
            &sponsor_id,
            SponsorLane::ContractCall,
            "encrypted-bundle-root:contract-call:devnet",
            1_250_000,
            3,
        );
        let batch_id = batch.batch_id.clone();
        let _ = state.open_settlement_batch(batch);
        let _ = state.route_batch(&batch_id);
        let _ = state.settle_batch(&batch_id);
        state
    }

    pub fn register_sponsor(&mut self, sponsor: SponsorCommitment) -> Result<String> {
        if self.sponsors.len() >= MAX_SPONSORS {
            return Err("fee sponsor capacity exhausted".to_string());
        }
        if sponsor.pq_security_bits < self.config.min_pq_security_bits {
            return Err("fee sponsor pq security below runtime minimum".to_string());
        }
        if sponsor.privacy_set_size < self.config.min_privacy_set_size {
            return Err("fee sponsor privacy set below runtime minimum".to_string());
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        let lane = sponsor.lane;
        self.sponsors.insert(sponsor_id.clone(), sponsor);
        self.sponsors_by_lane
            .entry(lane)
            .or_default()
            .insert(sponsor_id.clone());
        self.counters.sponsors_registered = self.counters.sponsors_registered.saturating_add(1);
        self.emit_event("fee_sponsor_registered", &sponsor_id);
        self.refresh_roots();
        Ok(sponsor_id)
    }

    pub fn register_privacy_fence(&mut self, fence: PrivacyFence) -> Result<String> {
        if self.privacy_fences.len() >= MAX_PRIVACY_FENCES {
            return Err("privacy fence capacity exhausted".to_string());
        }
        if !self.sponsors.contains_key(&fence.sponsor_id) {
            return Err("privacy fence references unknown sponsor".to_string());
        }
        let fence_id = fence.fence_id.clone();
        let sponsor_id = fence.sponsor_id.clone();
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.counters.privacy_fences_registered =
            self.counters.privacy_fences_registered.saturating_add(1);
        self.emit_event("sponsor_privacy_fence_registered", &sponsor_id);
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn open_settlement_batch(&mut self, batch: SettlementBatch) -> Result<String> {
        if self.batches.len() >= MAX_SETTLEMENT_BATCHES {
            return Err("settlement batch capacity exhausted".to_string());
        }
        let sponsor = self
            .sponsors
            .get(&batch.sponsor_id)
            .ok_or_else(|| "settlement batch references unknown sponsor".to_string())?;
        if sponsor.lane != batch.lane {
            return Err("settlement batch lane does not match sponsor lane".to_string());
        }
        if batch.fee_credit_amount > sponsor.available_fee_credits {
            return Err("settlement batch exceeds sponsor fee credits".to_string());
        }
        let batch_id = batch.batch_id.clone();
        self.batches.insert(batch_id.clone(), batch);
        self.counters.batches_opened = self.counters.batches_opened.saturating_add(1);
        self.emit_event("sponsored_settlement_batch_opened", &batch_id);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn route_batch(&mut self, batch_id: &str) -> Result<String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        batch.status = SettlementStatus::Routed;
        self.counters.routed_fee_credits = self
            .counters
            .routed_fee_credits
            .saturating_add(batch.fee_credit_amount);
        let routed_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:ROUTED",
            &[
                HashPart::Str(batch_id),
                HashPart::U64(self.counters.routed_fee_credits),
            ],
            32,
        );
        self.emit_event("sponsored_settlement_batch_routed", batch_id);
        self.refresh_roots();
        Ok(routed_id)
    }

    pub fn settle_batch(&mut self, batch_id: &str) -> Result<String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        batch.status = SettlementStatus::Settled;
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        self.counters.rebates_issued = self
            .counters
            .rebates_issued
            .saturating_add(batch.rebate_amount);
        let receipt_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:SETTLEMENT-RECEIPT",
            &[
                HashPart::Str(batch_id),
                HashPart::U64(batch.fee_credit_amount),
                HashPart::U64(batch.rebate_amount),
            ],
            32,
        );
        self.emit_event("sponsored_settlement_batch_settled", batch_id);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn quote_sponsor_fee(&self, lane: SponsorLane, fee_credit_amount: u64) -> u64 {
        fee_credit_amount
            .saturating_mul(lane.lane_weight())
            .saturating_mul(self.config.max_sponsor_fee_bps)
            .saturating_div(10_000)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            sponsors_root: collection_root(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:SPONSORS",
                self.sponsors.values().map(SponsorCommitment::public_record),
            ),
            batches_root: collection_root(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:BATCHES",
                self.batches.values().map(SettlementBatch::public_record),
            ),
            privacy_fences_root: collection_root(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:FENCES",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            sponsor_indexes_root: collection_root(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:INDEXES",
                self.sponsors_by_lane
                    .iter()
                    .map(|(lane, ids)| json!({"lane": lane, "sponsors": ids})),
            ),
            events_root: collection_root(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:EVENTS",
                self.events.iter().cloned(),
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "sponsors": self.sponsors.values().map(SponsorCommitment::public_record).collect::<Vec<_>>(),
            "batches": self.batches.values().map(SettlementBatch::public_record).collect::<Vec<_>>(),
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "sponsors_by_lane": self.sponsors_by_lane,
            "events": self.events,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:EVENT",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.counters.events_emitted),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "kind": kind,
            "subject_id": subject_id,
            "event_index": self.counters.events_emitted,
        }));
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    record
        .get("state_root")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| record_root("STATE-FROM-PUBLIC-RECORD", record))
}

pub fn sponsor_id(sponsor_commitment: &str, lane: SponsorLane, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:SPONSOR-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn settlement_batch_id(
    sponsor_id: &str,
    lane: SponsorLane,
    encrypted_bundle_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:BATCH-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(encrypted_bundle_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn privacy_fence_id(sponsor_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:FENCE-ID",
        &[HashPart::Str(sponsor_id), HashPart::U64(nonce)],
        32,
    )
}

fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-SPONSOR-SETTLEMENT-ROUTER:{label}"),
        &[HashPart::Json(value)],
        32,
    )
}

fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
