use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBlobWitnessRebateInsuranceRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REBATE_INSURANCE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-blob-witness-rebate-insurance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REBATE_INSURANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-blob-witness-rebate-insurance-claim-v1";
pub const SPONSOR_POOL_SCHEME: &str = "pq-confidential-blob-witness-sponsor-pool-root-v1";
pub const WITNESS_BLOB_CLASS_SCHEME: &str = "low-fee-witness-blob-class-policy-root-v1";
pub const REBATE_POLICY_SCHEME: &str = "fee-spike-witness-blob-rebate-policy-root-v1";
pub const CLAIM_SCHEME: &str = "wallet-capped-blob-witness-fee-spike-claim-root-v1";
pub const RESERVE_BUCKET_SCHEME: &str = "blob-witness-rebate-insurance-reserve-bucket-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-public-blob-witness-rebate-insurance-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RESERVE_ASSET_ID: &str = "blob-witness-rebate-insurance-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 2_730_000;
pub const DEVNET_EPOCH: u64 = 3_792;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_WALLET_CAP_PICONERO: u64 = 32_000;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 8_250;
pub const DEFAULT_SPIKE_TRIGGER_BPS: u64 = 1_600;
pub const DEFAULT_RESERVE_TARGET_BPS: u64 = 2_400;
pub const DEFAULT_RESERVE_FLOOR_BPS: u64 = 600;
pub const DEFAULT_SPONSOR_MATCH_BPS: u64 = 5_500;
pub const DEFAULT_FAST_LANE_WEIGHT_BPS: u64 = 7_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SPONSOR_POOLS: usize = 262_144;
pub const MAX_WITNESS_CLASSES: usize = 1_024;
pub const MAX_REBATE_POLICIES: usize = 262_144;
pub const MAX_CLAIMS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_WALLET_CAPS: usize = 2_097_152;
pub const MAX_RESERVE_BUCKETS: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessBlobClass {
    RecursiveProofWitness,
    ContractStateDiff,
    ConfidentialTransfer,
    PrivateContractCall,
    MoneroBridgeExit,
    OracleUpdate,
    LiquidityNetting,
    EmergencyEscape,
}

impl WitnessBlobClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecursiveProofWitness => "recursive_proof_witness",
            Self::ContractStateDiff => "contract_state_diff",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::PrivateContractCall => "private_contract_call",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::LiquidityNetting => "liquidity_netting",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn speed_weight_bps(self) -> u64 {
        match self {
            Self::RecursiveProofWitness => 8_800,
            Self::ContractStateDiff => 8_000,
            Self::PrivateContractCall => 7_400,
            Self::LiquidityNetting => 6_800,
            Self::MoneroBridgeExit => 6_200,
            Self::ConfidentialTransfer => 5_600,
            Self::OracleUpdate => 5_000,
            Self::EmergencyEscape => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Draft,
    Open,
    Active,
    Conserving,
    PayingClaims,
    Refilling,
    Frozen,
    Retired,
}

impl SponsorPoolStatus {
    pub fn drawable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Conserving | Self::PayingClaims | Self::Refilling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateMode {
    Baseline,
    FastLane,
    SpikeOnly,
    SponsorMatched,
    EmergencyBackstop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    Attested,
    Capped,
    Approved,
    PartiallyPaid,
    Paid,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveBucketKind {
    ExpectedWitnessRebate,
    TailFeeSpike,
    SponsorBackstop,
    FastLaneLiquidity,
    EmergencyEscape,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    Verified,
    QuorumReached,
    Disputed,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_claim_attestation_scheme: String,
    pub sponsor_pool_scheme: String,
    pub witness_blob_class_scheme: String,
    pub rebate_policy_scheme: String,
    pub claim_scheme: String,
    pub reserve_bucket_scheme: String,
    pub public_record_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub reserve_asset_id: String,
    pub epoch: u64,
    pub epoch_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub wallet_cap_piconero: u64,
    pub max_rebate_bps: u64,
    pub spike_trigger_bps: u64,
    pub reserve_target_bps: u64,
    pub reserve_floor_bps: u64,
    pub sponsor_match_bps: u64,
    pub fast_lane_weight_bps: u64,
    pub max_sponsor_pools: usize,
    pub max_witness_classes: usize,
    pub max_rebate_policies: usize,
    pub max_claims: usize,
    pub max_attestations: usize,
    pub max_wallet_caps: usize,
    pub max_reserve_buckets: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_attestation_scheme: PQ_CLAIM_ATTESTATION_SCHEME.to_string(),
            sponsor_pool_scheme: SPONSOR_POOL_SCHEME.to_string(),
            witness_blob_class_scheme: WITNESS_BLOB_CLASS_SCHEME.to_string(),
            rebate_policy_scheme: REBATE_POLICY_SCHEME.to_string(),
            claim_scheme: CLAIM_SCHEME.to_string(),
            reserve_bucket_scheme: RESERVE_BUCKET_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            reserve_asset_id: DEVNET_RESERVE_ASSET_ID.to_string(),
            epoch: DEVNET_EPOCH,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            wallet_cap_piconero: DEFAULT_WALLET_CAP_PICONERO,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            spike_trigger_bps: DEFAULT_SPIKE_TRIGGER_BPS,
            reserve_target_bps: DEFAULT_RESERVE_TARGET_BPS,
            reserve_floor_bps: DEFAULT_RESERVE_FLOOR_BPS,
            sponsor_match_bps: DEFAULT_SPONSOR_MATCH_BPS,
            fast_lane_weight_bps: DEFAULT_FAST_LANE_WEIGHT_BPS,
            max_sponsor_pools: MAX_SPONSOR_POOLS,
            max_witness_classes: MAX_WITNESS_CLASSES,
            max_rebate_policies: MAX_REBATE_POLICIES,
            max_claims: MAX_CLAIMS,
            max_attestations: MAX_ATTESTATIONS,
            max_wallet_caps: MAX_WALLET_CAPS,
            max_reserve_buckets: MAX_RESERVE_BUCKETS,
            max_public_records: MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_claim_attestation_scheme": self.pq_claim_attestation_scheme,
            "sponsor_pool_scheme": self.sponsor_pool_scheme,
            "witness_blob_class_scheme": self.witness_blob_class_scheme,
            "rebate_policy_scheme": self.rebate_policy_scheme,
            "claim_scheme": self.claim_scheme,
            "reserve_bucket_scheme": self.reserve_bucket_scheme,
            "public_record_scheme": self.public_record_scheme,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "epoch": self.epoch,
            "epoch_blocks": self.epoch_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "wallet_cap_piconero": self.wallet_cap_piconero,
            "max_rebate_bps": self.max_rebate_bps,
            "spike_trigger_bps": self.spike_trigger_bps,
            "reserve_target_bps": self.reserve_target_bps,
            "reserve_floor_bps": self.reserve_floor_bps,
            "sponsor_match_bps": self.sponsor_match_bps,
            "fast_lane_weight_bps": self.fast_lane_weight_bps,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub current_height: u64,
    pub next_sponsor_pool: u64,
    pub next_witness_class: u64,
    pub next_rebate_policy: u64,
    pub next_claim: u64,
    pub next_attestation: u64,
    pub next_wallet_cap: u64,
    pub next_reserve_bucket: u64,
    pub next_public_record: u64,
    pub total_reserved_piconero: u64,
    pub total_claimed_piconero: u64,
    pub total_paid_rebates_piconero: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "current_height": self.current_height,
            "next_sponsor_pool": self.next_sponsor_pool,
            "next_witness_class": self.next_witness_class,
            "next_rebate_policy": self.next_rebate_policy,
            "next_claim": self.next_claim,
            "next_attestation": self.next_attestation,
            "next_wallet_cap": self.next_wallet_cap,
            "next_reserve_bucket": self.next_reserve_bucket,
            "next_public_record": self.next_public_record,
            "total_reserved_piconero": self.total_reserved_piconero,
            "total_claimed_piconero": self.total_claimed_piconero,
            "total_paid_rebates_piconero": self.total_paid_rebates_piconero,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub sponsor_pools_root: String,
    pub witness_classes_root: String,
    pub rebate_policies_root: String,
    pub fee_spike_claims_root: String,
    pub pq_claim_attestations_root: String,
    pub wallet_caps_root: String,
    pub reserve_buckets_root: String,
    pub public_records_root: String,
    pub watched_nullifiers_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "sponsor_pools_root": self.sponsor_pools_root,
            "witness_classes_root": self.witness_classes_root,
            "rebate_policies_root": self.rebate_policies_root,
            "fee_spike_claims_root": self.fee_spike_claims_root,
            "pq_claim_attestations_root": self.pq_claim_attestations_root,
            "wallet_caps_root": self.wallet_caps_root,
            "reserve_buckets_root": self.reserve_buckets_root,
            "public_records_root": self.public_records_root,
            "watched_nullifiers_root": self.watched_nullifiers_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub label: String,
    pub status: SponsorPoolStatus,
    pub reserve_piconero: u64,
    pub available_piconero: u64,
    pub max_rebate_bps: u64,
    pub match_bps: u64,
    pub opened_height: u64,
    pub policy_ids: BTreeSet<String>,
}

impl SponsorPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "label": self.label,
            "status": self.status,
            "reserve_piconero": self.reserve_piconero,
            "available_piconero": self.available_piconero,
            "max_rebate_bps": self.max_rebate_bps,
            "match_bps": self.match_bps,
            "opened_height": self.opened_height,
            "policy_ids": self.policy_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessClassPolicy {
    pub class_id: String,
    pub blob_class: WitnessBlobClass,
    pub max_raw_bytes: u64,
    pub target_fee_piconero: u64,
    pub speed_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub active: bool,
}

impl WitnessClassPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "class_id": self.class_id,
            "blob_class": self.blob_class,
            "max_raw_bytes": self.max_raw_bytes,
            "target_fee_piconero": self.target_fee_piconero,
            "speed_weight_bps": self.speed_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebatePolicy {
    pub policy_id: String,
    pub pool_id: String,
    pub class_id: String,
    pub mode: RebateMode,
    pub baseline_fee_piconero: u64,
    pub spike_trigger_bps: u64,
    pub rebate_bps: u64,
    pub wallet_cap_piconero: u64,
    pub expires_height: u64,
}

impl RebatePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "pool_id": self.pool_id,
            "class_id": self.class_id,
            "mode": self.mode,
            "baseline_fee_piconero": self.baseline_fee_piconero,
            "spike_trigger_bps": self.spike_trigger_bps,
            "rebate_bps": self.rebate_bps,
            "wallet_cap_piconero": self.wallet_cap_piconero,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSpikeClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub wallet_commitment: String,
    pub witness_blob_root: String,
    pub observed_fee_piconero: u64,
    pub baseline_fee_piconero: u64,
    pub requested_rebate_piconero: u64,
    pub approved_rebate_piconero: u64,
    pub status: ClaimStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl FeeSpikeClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "wallet_commitment": self.wallet_commitment,
            "witness_blob_root": self.witness_blob_root,
            "observed_fee_piconero": self.observed_fee_piconero,
            "baseline_fee_piconero": self.baseline_fee_piconero,
            "requested_rebate_piconero": self.requested_rebate_piconero,
            "approved_rebate_piconero": self.approved_rebate_piconero,
            "status": self.status,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimAttestation {
    pub attestation_id: String,
    pub claim_id: String,
    pub attester_commitment: String,
    pub scheme: String,
    pub attestation_root: String,
    pub status: AttestationStatus,
    pub pq_security_bits: u16,
    pub posted_height: u64,
}

impl PqClaimAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "claim_id": self.claim_id,
            "attester_commitment": self.attester_commitment,
            "scheme": self.scheme,
            "attestation_root": self.attestation_root,
            "status": self.status,
            "pq_security_bits": self.pq_security_bits,
            "posted_height": self.posted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCap {
    pub cap_id: String,
    pub wallet_commitment: String,
    pub policy_id: String,
    pub epoch: u64,
    pub cap_piconero: u64,
    pub claimed_piconero: u64,
}

impl WalletCap {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "wallet_commitment": self.wallet_commitment,
            "policy_id": self.policy_id,
            "epoch": self.epoch,
            "cap_piconero": self.cap_piconero,
            "claimed_piconero": self.claimed_piconero,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveBucket {
    pub bucket_id: String,
    pub pool_id: String,
    pub kind: ReserveBucketKind,
    pub target_piconero: u64,
    pub balance_piconero: u64,
    pub floor_bps: u64,
}

impl ReserveBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "pool_id": self.pool_id,
            "kind": self.kind,
            "target_piconero": self.target_piconero,
            "balance_piconero": self.balance_piconero,
            "floor_bps": self.floor_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub witness_classes: BTreeMap<String, WitnessClassPolicy>,
    pub rebate_policies: BTreeMap<String, RebatePolicy>,
    pub fee_spike_claims: BTreeMap<String, FeeSpikeClaim>,
    pub pq_claim_attestations: BTreeMap<String, PqClaimAttestation>,
    pub wallet_caps: BTreeMap<String, WalletCap>,
    pub reserve_buckets: BTreeMap<String, ReserveBucket>,
    pub public_records: BTreeMap<String, Value>,
    pub watched_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters {
                current_height: DEVNET_HEIGHT,
                ..Counters::default()
            },
            sponsor_pools: BTreeMap::new(),
            witness_classes: BTreeMap::new(),
            rebate_policies: BTreeMap::new(),
            fee_spike_claims: BTreeMap::new(),
            pq_claim_attestations: BTreeMap::new(),
            wallet_caps: BTreeMap::new(),
            reserve_buckets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            watched_nullifiers: BTreeSet::new(),
        };
        state.seed_devnet();
        state
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.state_root();
        let counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        let sponsor_pools_root = map_root(
            "SPONSOR_POOLS",
            &self.sponsor_pools,
            SponsorPool::public_record,
        );
        let witness_classes_root = map_root(
            "WITNESS_CLASSES",
            &self.witness_classes,
            WitnessClassPolicy::public_record,
        );
        let rebate_policies_root = map_root(
            "REBATE_POLICIES",
            &self.rebate_policies,
            RebatePolicy::public_record,
        );
        let fee_spike_claims_root = map_root(
            "FEE_SPIKE_CLAIMS",
            &self.fee_spike_claims,
            FeeSpikeClaim::public_record,
        );
        let pq_claim_attestations_root = map_root(
            "PQ_CLAIM_ATTESTATIONS",
            &self.pq_claim_attestations,
            PqClaimAttestation::public_record,
        );
        let wallet_caps_root = map_root("WALLET_CAPS", &self.wallet_caps, WalletCap::public_record);
        let reserve_buckets_root = map_root(
            "RESERVE_BUCKETS",
            &self.reserve_buckets,
            ReserveBucket::public_record,
        );
        let public_records_root = map_value_root("PUBLIC_RECORDS", &self.public_records);
        let watched_nullifiers_root = set_root("WATCHED_NULLIFIERS", &self.watched_nullifiers);
        let state_root = root_from_record(
            "STATE",
            &json!({
                "config_root": config_root,
                "counters_root": counters_root,
                "sponsor_pools_root": sponsor_pools_root,
                "witness_classes_root": witness_classes_root,
                "rebate_policies_root": rebate_policies_root,
                "fee_spike_claims_root": fee_spike_claims_root,
                "pq_claim_attestations_root": pq_claim_attestations_root,
                "wallet_caps_root": wallet_caps_root,
                "reserve_buckets_root": reserve_buckets_root,
                "public_records_root": public_records_root,
                "watched_nullifiers_root": watched_nullifiers_root,
            }),
        );
        Roots {
            config_root,
            counters_root,
            sponsor_pools_root,
            witness_classes_root,
            rebate_policies_root,
            fee_spike_claims_root,
            pq_claim_attestations_root,
            wallet_caps_root,
            reserve_buckets_root,
            public_records_root,
            watched_nullifiers_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "sponsor_pools": self.sponsor_pools.len(),
            "witness_classes": self.witness_classes.len(),
            "rebate_policies": self.rebate_policies.len(),
            "fee_spike_claims": self.fee_spike_claims.len(),
            "pq_claim_attestations": self.pq_claim_attestations.len(),
            "wallet_caps": self.wallet_caps.len(),
            "reserve_buckets": self.reserve_buckets.len(),
            "public_records": self.public_records.len(),
            "watched_nullifiers": self.watched_nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn open_sponsor_pool(
        &mut self,
        sponsor_commitment: &str,
        label: &str,
        reserve_piconero: u64,
        max_rebate_bps: u64,
    ) -> Result<String> {
        ensure_nonempty("sponsor_commitment", sponsor_commitment)?;
        ensure_nonempty("label", label)?;
        ensure_bps(max_rebate_bps, "max_rebate_bps")?;
        ensure_limit(
            self.sponsor_pools.len(),
            self.config.max_sponsor_pools,
            "sponsor pool limit reached",
        )?;
        let sequence = self.counters.next_sponsor_pool;
        let record = json!({
            "sponsor_commitment": sponsor_commitment,
            "label": label,
            "reserve_piconero": reserve_piconero,
            "max_rebate_bps": max_rebate_bps,
            "sequence": sequence,
        });
        let pool_id = deterministic_id("SPONSOR_POOL", &record, sequence);
        let pool = SponsorPool {
            pool_id: pool_id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            label: label.to_string(),
            status: SponsorPoolStatus::Active,
            reserve_piconero,
            available_piconero: reserve_piconero,
            max_rebate_bps,
            match_bps: self.config.sponsor_match_bps,
            opened_height: self.counters.current_height,
            policy_ids: BTreeSet::new(),
        };
        self.counters.next_sponsor_pool = self.counters.next_sponsor_pool.saturating_add(1);
        self.counters.total_reserved_piconero = self
            .counters
            .total_reserved_piconero
            .saturating_add(reserve_piconero);
        self.sponsor_pools.insert(pool_id.clone(), pool);
        self.record_public("sponsor_pool_opened", &pool_id);
        Ok(pool_id)
    }

    pub fn register_witness_class(
        &mut self,
        blob_class: WitnessBlobClass,
        max_raw_bytes: u64,
        target_fee_piconero: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        ensure_limit(
            self.witness_classes.len(),
            self.config.max_witness_classes,
            "witness class limit reached",
        )?;
        ensure(
            privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below configured minimum",
        )?;
        let sequence = self.counters.next_witness_class;
        let record = json!({
            "blob_class": blob_class,
            "max_raw_bytes": max_raw_bytes,
            "target_fee_piconero": target_fee_piconero,
            "privacy_set_size": privacy_set_size,
            "sequence": sequence,
        });
        let class_id = deterministic_id("WITNESS_CLASS", &record, sequence);
        let policy = WitnessClassPolicy {
            class_id: class_id.clone(),
            blob_class,
            max_raw_bytes,
            target_fee_piconero,
            speed_weight_bps: blob_class.speed_weight_bps(),
            privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            active: true,
        };
        self.counters.next_witness_class = self.counters.next_witness_class.saturating_add(1);
        self.witness_classes.insert(class_id.clone(), policy);
        self.record_public("witness_class_registered", &class_id);
        Ok(class_id)
    }

    pub fn create_rebate_policy(
        &mut self,
        pool_id: &str,
        class_id: &str,
        mode: RebateMode,
        rebate_bps: u64,
    ) -> Result<String> {
        ensure_bps(rebate_bps, "rebate_bps")?;
        ensure(
            rebate_bps <= self.config.max_rebate_bps,
            "rebate exceeds configured maximum",
        )?;
        ensure_limit(
            self.rebate_policies.len(),
            self.config.max_rebate_policies,
            "rebate policy limit reached",
        )?;
        let class = self
            .witness_classes
            .get(class_id)
            .ok_or_else(|| "unknown witness class".to_string())?;
        let pool = self
            .sponsor_pools
            .get_mut(pool_id)
            .ok_or_else(|| "unknown sponsor pool".to_string())?;
        ensure(pool.status.drawable(), "sponsor pool is not drawable")?;
        let sequence = self.counters.next_rebate_policy;
        let record = json!({
            "pool_id": pool_id,
            "class_id": class_id,
            "mode": mode,
            "rebate_bps": rebate_bps,
            "sequence": sequence,
        });
        let policy_id = deterministic_id("REBATE_POLICY", &record, sequence);
        let policy = RebatePolicy {
            policy_id: policy_id.clone(),
            pool_id: pool_id.to_string(),
            class_id: class_id.to_string(),
            mode,
            baseline_fee_piconero: class.target_fee_piconero,
            spike_trigger_bps: self.config.spike_trigger_bps,
            rebate_bps,
            wallet_cap_piconero: self.config.wallet_cap_piconero,
            expires_height: self
                .counters
                .current_height
                .saturating_add(self.config.rebate_ttl_blocks),
        };
        pool.policy_ids.insert(policy_id.clone());
        self.counters.next_rebate_policy = self.counters.next_rebate_policy.saturating_add(1);
        self.rebate_policies.insert(policy_id.clone(), policy);
        self.record_public("rebate_policy_created", &policy_id);
        Ok(policy_id)
    }

    pub fn submit_fee_spike_claim(
        &mut self,
        policy_id: &str,
        wallet_commitment: &str,
        witness_blob_root: &str,
        observed_fee_piconero: u64,
    ) -> Result<String> {
        ensure_nonempty("wallet_commitment", wallet_commitment)?;
        ensure_nonempty("witness_blob_root", witness_blob_root)?;
        ensure_limit(
            self.fee_spike_claims.len(),
            self.config.max_claims,
            "claim limit reached",
        )?;
        let policy = self
            .rebate_policies
            .get(policy_id)
            .ok_or_else(|| "unknown rebate policy".to_string())?;
        ensure(
            observed_fee_piconero
                >= spike_threshold(policy.baseline_fee_piconero, policy.spike_trigger_bps),
            "observed fee does not satisfy spike trigger",
        )?;
        let requested = observed_fee_piconero
            .saturating_sub(policy.baseline_fee_piconero)
            .saturating_mul(policy.rebate_bps)
            / MAX_BPS;
        let approved = requested.min(policy.wallet_cap_piconero);
        let sequence = self.counters.next_claim;
        let record = json!({
            "policy_id": policy_id,
            "wallet_commitment": wallet_commitment,
            "witness_blob_root": witness_blob_root,
            "observed_fee_piconero": observed_fee_piconero,
            "sequence": sequence,
        });
        let claim_id = deterministic_id("FEE_SPIKE_CLAIM", &record, sequence);
        let claim = FeeSpikeClaim {
            claim_id: claim_id.clone(),
            policy_id: policy_id.to_string(),
            wallet_commitment: wallet_commitment.to_string(),
            witness_blob_root: witness_blob_root.to_string(),
            observed_fee_piconero,
            baseline_fee_piconero: policy.baseline_fee_piconero,
            requested_rebate_piconero: requested,
            approved_rebate_piconero: approved,
            status: ClaimStatus::Submitted,
            submitted_height: self.counters.current_height,
            expires_height: self
                .counters
                .current_height
                .saturating_add(self.config.claim_ttl_blocks),
        };
        self.counters.next_claim = self.counters.next_claim.saturating_add(1);
        self.counters.total_claimed_piconero = self
            .counters
            .total_claimed_piconero
            .saturating_add(requested);
        self.fee_spike_claims.insert(claim_id.clone(), claim);
        self.upsert_wallet_cap(policy_id, wallet_commitment, approved)?;
        self.record_public("fee_spike_claim_submitted", &claim_id);
        Ok(claim_id)
    }

    pub fn attest_claim(
        &mut self,
        claim_id: &str,
        attester_commitment: &str,
        attestation_root: &str,
    ) -> Result<String> {
        ensure_nonempty("attester_commitment", attester_commitment)?;
        ensure_nonempty("attestation_root", attestation_root)?;
        ensure_limit(
            self.pq_claim_attestations.len(),
            self.config.max_attestations,
            "attestation limit reached",
        )?;
        let claim = self
            .fee_spike_claims
            .get_mut(claim_id)
            .ok_or_else(|| "unknown claim".to_string())?;
        ensure(
            self.counters.current_height <= claim.expires_height,
            "claim expired",
        )?;
        let sequence = self.counters.next_attestation;
        let record = json!({
            "claim_id": claim_id,
            "attester_commitment": attester_commitment,
            "attestation_root": attestation_root,
            "sequence": sequence,
        });
        let attestation_id = deterministic_id("PQ_CLAIM_ATTESTATION", &record, sequence);
        let attestation = PqClaimAttestation {
            attestation_id: attestation_id.clone(),
            claim_id: claim_id.to_string(),
            attester_commitment: attester_commitment.to_string(),
            scheme: self.config.pq_claim_attestation_scheme.clone(),
            attestation_root: attestation_root.to_string(),
            status: AttestationStatus::Verified,
            pq_security_bits: self.config.min_pq_security_bits,
            posted_height: self.counters.current_height,
        };
        claim.status = ClaimStatus::Attested;
        self.counters.next_attestation = self.counters.next_attestation.saturating_add(1);
        self.pq_claim_attestations
            .insert(attestation_id.clone(), attestation);
        self.record_public("pq_claim_attested", &attestation_id);
        Ok(attestation_id)
    }

    pub fn approve_claim(&mut self, claim_id: &str) -> Result<()> {
        let claim = self
            .fee_spike_claims
            .get_mut(claim_id)
            .ok_or_else(|| "unknown claim".to_string())?;
        ensure(
            matches!(claim.status, ClaimStatus::Attested | ClaimStatus::Capped),
            "claim must be attested before approval",
        )?;
        let policy = self
            .rebate_policies
            .get(&claim.policy_id)
            .ok_or_else(|| "missing policy for claim".to_string())?;
        let pool = self
            .sponsor_pools
            .get_mut(&policy.pool_id)
            .ok_or_else(|| "missing pool for policy".to_string())?;
        ensure(pool.status.drawable(), "sponsor pool cannot pay claims")?;
        let paid = claim.approved_rebate_piconero.min(pool.available_piconero);
        pool.available_piconero = pool.available_piconero.saturating_sub(paid);
        claim.approved_rebate_piconero = paid;
        claim.status = if paid == claim.requested_rebate_piconero {
            ClaimStatus::Paid
        } else {
            ClaimStatus::PartiallyPaid
        };
        self.counters.total_paid_rebates_piconero = self
            .counters
            .total_paid_rebates_piconero
            .saturating_add(paid);
        self.record_public("fee_spike_claim_paid", claim_id);
        Ok(())
    }

    pub fn add_reserve_bucket(
        &mut self,
        pool_id: &str,
        kind: ReserveBucketKind,
        target_piconero: u64,
        balance_piconero: u64,
    ) -> Result<String> {
        ensure_limit(
            self.reserve_buckets.len(),
            self.config.max_reserve_buckets,
            "reserve bucket limit reached",
        )?;
        ensure(
            self.sponsor_pools.contains_key(pool_id),
            "unknown sponsor pool",
        )?;
        let sequence = self.counters.next_reserve_bucket;
        let record = json!({
            "pool_id": pool_id,
            "kind": kind,
            "target_piconero": target_piconero,
            "balance_piconero": balance_piconero,
            "sequence": sequence,
        });
        let bucket_id = deterministic_id("RESERVE_BUCKET", &record, sequence);
        let bucket = ReserveBucket {
            bucket_id: bucket_id.clone(),
            pool_id: pool_id.to_string(),
            kind,
            target_piconero,
            balance_piconero,
            floor_bps: self.config.reserve_floor_bps,
        };
        self.counters.next_reserve_bucket = self.counters.next_reserve_bucket.saturating_add(1);
        self.reserve_buckets.insert(bucket_id.clone(), bucket);
        self.record_public("reserve_bucket_added", &bucket_id);
        Ok(bucket_id)
    }

    fn seed_devnet(&mut self) {
        let pool_id = self
            .open_sponsor_pool(
                "sponsor_commitment_devnet_blob_witness_rebate_pool",
                "devnet blob witness rebate insurance pool",
                8_000_000,
                self.config.max_rebate_bps,
            )
            .unwrap_or_else(stable_error_id);
        let recursive_class = self
            .register_witness_class(
                WitnessBlobClass::RecursiveProofWitness,
                262_144,
                38_000,
                self.config.min_privacy_set_size,
            )
            .unwrap_or_else(stable_error_id);
        let diff_class = self
            .register_witness_class(
                WitnessBlobClass::ContractStateDiff,
                196_608,
                31_000,
                self.config.min_privacy_set_size,
            )
            .unwrap_or_else(stable_error_id);
        let recursive_policy = self
            .create_rebate_policy(&pool_id, &recursive_class, RebateMode::FastLane, 7_500)
            .unwrap_or_else(stable_error_id);
        let diff_policy = self
            .create_rebate_policy(&pool_id, &diff_class, RebateMode::SponsorMatched, 6_250)
            .unwrap_or_else(stable_error_id);
        let claim_id = self
            .submit_fee_spike_claim(
                &recursive_policy,
                "wallet_commitment_devnet_low_fee_fast_sync",
                "witness_blob_root_devnet_recursive_0001",
                74_000,
            )
            .unwrap_or_else(stable_error_id);
        let _ = self.attest_claim(
            &claim_id,
            "pq_attester_commitment_devnet_committee_alpha",
            "pq_claim_attestation_root_recursive_0001",
        );
        let _ = self.approve_claim(&claim_id);
        let _ = self.submit_fee_spike_claim(
            &diff_policy,
            "wallet_commitment_devnet_contract_user",
            "witness_blob_root_devnet_state_diff_0001",
            57_000,
        );
        let _ = self.add_reserve_bucket(
            &pool_id,
            ReserveBucketKind::ExpectedWitnessRebate,
            1_920_000,
            1_600_000,
        );
        let _ =
            self.add_reserve_bucket(&pool_id, ReserveBucketKind::TailFeeSpike, 720_000, 640_000);
        self.watched_nullifiers
            .insert(seeded("devnet-witness-rebate-nullifier-fence"));
    }

    fn upsert_wallet_cap(
        &mut self,
        policy_id: &str,
        wallet_commitment: &str,
        claimed_piconero: u64,
    ) -> Result<()> {
        ensure_limit(
            self.wallet_caps.len(),
            self.config.max_wallet_caps,
            "wallet cap limit reached",
        )?;
        let cap_key = format!("{policy_id}:{wallet_commitment}:{}", self.config.epoch);
        if let Some(cap) = self.wallet_caps.get_mut(&cap_key) {
            cap.claimed_piconero = cap.claimed_piconero.saturating_add(claimed_piconero);
            return Ok(());
        }
        let sequence = self.counters.next_wallet_cap;
        let cap = WalletCap {
            cap_id: cap_key.clone(),
            wallet_commitment: wallet_commitment.to_string(),
            policy_id: policy_id.to_string(),
            epoch: self.config.epoch,
            cap_piconero: self.config.wallet_cap_piconero,
            claimed_piconero,
        };
        self.counters.next_wallet_cap = self.counters.next_wallet_cap.saturating_add(1);
        self.wallet_caps.insert(cap_key, cap);
        self.counters.next_public_record = self.counters.next_public_record.max(sequence);
        Ok(())
    }

    fn record_public(&mut self, kind: &str, subject_id: &str) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let sequence = self.counters.next_public_record;
        let record = json!({
            "sequence": sequence,
            "kind": kind,
            "subject_id": subject_id,
            "record_root": domain_hash(
                "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REBATE_INSURANCE_RUNTIME:PUBLIC_SUBJECT",
                &[HashPart::Str(kind), HashPart::Str(subject_id), HashPart::U64(sequence)],
                32,
            ),
        });
        let record_id = deterministic_id("PUBLIC_RECORD", &record, sequence);
        self.counters.next_public_record = self.counters.next_public_record.saturating_add(1);
        self.public_records.insert(record_id, record);
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

fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REBATE_INSURANCE_RUNTIME:{domain}"
        ),
        &[HashPart::Json(record)],
        32,
    )
}

fn deterministic_id(domain: &str, record: &Value, sequence: u64) -> String {
    domain_hash(
        &format!(
            "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REBATE_INSURANCE_RUNTIME:{domain}:ID"
        ),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        20,
    )
}

fn seeded(label: &str) -> String {
    domain_hash(
        "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REBATE_INSURANCE_RUNTIME:SEED",
        &[HashPart::Str(label)],
        20,
    )
}

fn stable_error_id(error: String) -> String {
    domain_hash(
        "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_WITNESS_REBATE_INSURANCE_RUNTIME:ERROR_ID",
        &[HashPart::Str(&error)],
        20,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            root_from_record(
                domain,
                &json!({
                    "key": key,
                    "value": public_record(value),
                }),
            )
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("BLOB_WITNESS_REBATE_INSURANCE:{domain}"), &leaves)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            root_from_record(
                domain,
                &json!({
                    "key": key,
                    "value": value,
                }),
            )
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("BLOB_WITNESS_REBATE_INSURANCE:{domain}"), &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| root_from_record(domain, &json!({ "value": value })))
        .collect::<Vec<_>>();
    merkle_root(&format!("BLOB_WITNESS_REBATE_INSURANCE:{domain}"), &leaves)
}

fn spike_threshold(baseline_fee_piconero: u64, spike_trigger_bps: u64) -> u64 {
    baseline_fee_piconero
        .saturating_add(baseline_fee_piconero.saturating_mul(spike_trigger_bps) / MAX_BPS)
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_nonempty(name: &str, value: &str) -> Result<()> {
    ensure(!value.trim().is_empty(), &format!("{name} cannot be empty"))
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    ensure(value <= MAX_BPS, &format!("{name} exceeds MAX_BPS"))
}

fn ensure_limit(current: usize, max: usize, message: &str) -> Result<()> {
    ensure(current < max, message)
}
