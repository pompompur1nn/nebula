use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-proof-fee-insurance-pool-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-proof-fee-insurance-claim-attestation-v1";
pub const SPONSOR_DEPOSIT_SCHEME: &str =
    "pq-confidential-sponsor-deposit-proof-fee-insurance-root-v1";
pub const RESERVE_BUCKET_SCHEME: &str = "actuarial-proof-and-da-fee-spike-reserve-bucket-root-v1";
pub const CLAIM_CAP_SCHEME: &str = "wallet-capped-proof-fee-insurance-claim-root-v1";
pub const BATCH_REBATE_SCHEME: &str = "low-fee-proof-da-batch-rebate-netting-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "operator-safe-public-proof-fee-insurance-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RESERVE_ASSET_ID: &str = "proof-fee-insurance-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 2_411_880;
pub const DEVNET_EPOCH: u64 = 3_349;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_WALLET_FEE_CAP_PICONERO: u64 = 45_000;
pub const DEFAULT_TARGET_RESERVE_BPS: u64 = 2_000;
pub const DEFAULT_RESERVE_FLOOR_BPS: u64 = 550;
pub const DEFAULT_MAX_CLAIM_BPS: u64 = 3_000;
pub const DEFAULT_PROVER_SPIKE_COVER_BPS: u64 = 8_000;
pub const DEFAULT_DA_SPIKE_COVER_BPS: u64 = 7_500;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 6_250;
pub const DEFAULT_SPONSOR_MATCH_BPS: u64 = 5_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POOLS: usize = 262_144;
pub const MAX_SPONSOR_DEPOSITS: usize = 524_288;
pub const MAX_RESERVE_BUCKETS: usize = 524_288;
pub const MAX_CLAIMS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_BATCH_REBATES: usize = 524_288;
pub const MAX_WALLET_CAPS: usize = 2_097_152;
pub const MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSpikeKind {
    ProverMarket,
    BlobDa,
    RecursiveAggregation,
    WitnessDownload,
    PreconfirmationProof,
    BridgeExitProof,
}

impl FeeSpikeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProverMarket => "prover_market",
            Self::BlobDa => "blob_da",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::WitnessDownload => "witness_download",
            Self::PreconfirmationProof => "preconfirmation_proof",
            Self::BridgeExitProof => "bridge_exit_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Open,
    Active,
    Conserving,
    PayingClaims,
    Refilling,
    Frozen,
    Retired,
}

impl PoolStatus {
    pub fn claimable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Conserving | Self::PayingClaims | Self::Refilling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositStatus {
    Pledged,
    Active,
    Locked,
    Matching,
    PartiallyDrawn,
    Exhausted,
    Paused,
    Retired,
}

impl DepositStatus {
    pub fn drawable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Locked | Self::Matching | Self::PartiallyDrawn
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketKind {
    ExpectedLoss,
    TailRisk,
    ProverSpike,
    DaSpike,
    BatchRebate,
    SponsorBackstop,
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
pub enum RebateStatus {
    Proposed,
    Eligible,
    Netted,
    Paid,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_claim_attestation_scheme: String,
    pub sponsor_deposit_scheme: String,
    pub reserve_bucket_scheme: String,
    pub claim_cap_scheme: String,
    pub batch_rebate_scheme: String,
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
    pub wallet_fee_cap_piconero: u64,
    pub target_reserve_bps: u64,
    pub reserve_floor_bps: u64,
    pub max_claim_bps: u64,
    pub prover_spike_cover_bps: u64,
    pub da_spike_cover_bps: u64,
    pub batch_rebate_bps: u64,
    pub sponsor_match_bps: u64,
    pub max_pools: usize,
    pub max_sponsor_deposits: usize,
    pub max_reserve_buckets: usize,
    pub max_claims: usize,
    pub max_attestations: usize,
    pub max_batch_rebates: usize,
    pub max_wallet_caps: usize,
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
            sponsor_deposit_scheme: SPONSOR_DEPOSIT_SCHEME.to_string(),
            reserve_bucket_scheme: RESERVE_BUCKET_SCHEME.to_string(),
            claim_cap_scheme: CLAIM_CAP_SCHEME.to_string(),
            batch_rebate_scheme: BATCH_REBATE_SCHEME.to_string(),
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
            wallet_fee_cap_piconero: DEFAULT_WALLET_FEE_CAP_PICONERO,
            target_reserve_bps: DEFAULT_TARGET_RESERVE_BPS,
            reserve_floor_bps: DEFAULT_RESERVE_FLOOR_BPS,
            max_claim_bps: DEFAULT_MAX_CLAIM_BPS,
            prover_spike_cover_bps: DEFAULT_PROVER_SPIKE_COVER_BPS,
            da_spike_cover_bps: DEFAULT_DA_SPIKE_COVER_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            sponsor_match_bps: DEFAULT_SPONSOR_MATCH_BPS,
            max_pools: MAX_POOLS,
            max_sponsor_deposits: MAX_SPONSOR_DEPOSITS,
            max_reserve_buckets: MAX_RESERVE_BUCKETS,
            max_claims: MAX_CLAIMS,
            max_attestations: MAX_ATTESTATIONS,
            max_batch_rebates: MAX_BATCH_REBATES,
            max_wallet_caps: MAX_WALLET_CAPS,
            max_public_records: MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_pool: u64,
    pub next_sponsor_deposit: u64,
    pub next_reserve_bucket: u64,
    pub next_claim: u64,
    pub next_attestation: u64,
    pub next_batch_rebate: u64,
    pub next_wallet_cap: u64,
    pub next_public_record: u64,
    pub paid_claims: u64,
    pub capped_claims: u64,
    pub rejected_claims: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub sponsor_deposits_root: String,
    pub reserve_buckets_root: String,
    pub claims_root: String,
    pub attestations_root: String,
    pub batch_rebates_root: String,
    pub wallet_caps_root: String,
    pub public_records_root: String,
    pub watched_nullifiers_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InsurancePool {
    pub pool_id: String,
    pub label: String,
    pub status: PoolStatus,
    pub fee_spike_kind: FeeSpikeKind,
    pub opened_height: u64,
    pub total_reserve_piconero: u64,
    pub available_reserve_piconero: u64,
    pub target_reserve_piconero: u64,
    pub max_claim_piconero: u64,
    pub sponsor_deposit_ids: BTreeSet<String>,
    pub reserve_bucket_ids: BTreeSet<String>,
    pub policy_root: String,
}

impl InsurancePool {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorDeposit {
    pub deposit_id: String,
    pub pool_id: String,
    pub sponsor_id: String,
    pub status: DepositStatus,
    pub asset_id: String,
    pub committed_piconero: u64,
    pub remaining_piconero: u64,
    pub match_bps: u64,
    pub deposit_commitment_root: String,
    pub pq_authorization_root: String,
}

impl SponsorDeposit {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveBucket {
    pub bucket_id: String,
    pub pool_id: String,
    pub kind: BucketKind,
    pub epoch: u64,
    pub expected_loss_bps: u64,
    pub target_piconero: u64,
    pub available_piconero: u64,
    pub actuarial_model_root: String,
}

impl ReserveBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimAttestation {
    pub attestation_id: String,
    pub claim_id: String,
    pub committee_id: String,
    pub pq_security_bits: u16,
    pub observed_fee_piconero: u64,
    pub baseline_fee_piconero: u64,
    pub evidence_root: String,
    pub attestation_root: String,
}

impl PqClaimAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InsuranceClaim {
    pub claim_id: String,
    pub pool_id: String,
    pub wallet_cap_id: String,
    pub status: ClaimStatus,
    pub fee_spike_kind: FeeSpikeKind,
    pub submitted_height: u64,
    pub requested_piconero: u64,
    pub capped_piconero: u64,
    pub approved_piconero: u64,
    pub attestation_id: Option<String>,
    pub private_claim_commitment_root: String,
}

impl InsuranceClaim {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRebate {
    pub rebate_id: String,
    pub pool_id: String,
    pub status: RebateStatus,
    pub batch_root: String,
    pub eligible_claim_ids: BTreeSet<String>,
    pub gross_rebate_piconero: u64,
    pub net_rebate_piconero: u64,
    pub expires_height: u64,
}

impl BatchRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletFeeCap {
    pub wallet_cap_id: String,
    pub wallet_commitment_root: String,
    pub max_fee_piconero: u64,
    pub epoch: u64,
    pub cap_nullifier_root: String,
}

impl WalletFeeCap {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub pools: BTreeMap<String, InsurancePool>,
    pub sponsor_deposits: BTreeMap<String, SponsorDeposit>,
    pub reserve_buckets: BTreeMap<String, ReserveBucket>,
    pub claims: BTreeMap<String, InsuranceClaim>,
    pub attestations: BTreeMap<String, PqClaimAttestation>,
    pub batch_rebates: BTreeMap<String, BatchRebate>,
    pub wallet_caps: BTreeMap<String, WalletFeeCap>,
    pub public_records: BTreeMap<String, Value>,
    pub watched_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            pools: BTreeMap::new(),
            sponsor_deposits: BTreeMap::new(),
            reserve_buckets: BTreeMap::new(),
            claims: BTreeMap::new(),
            attestations: BTreeMap::new(),
            batch_rebates: BTreeMap::new(),
            wallet_caps: BTreeMap::new(),
            public_records: BTreeMap::new(),
            watched_nullifiers: BTreeSet::new(),
        };
        state.seed_devnet();
        state
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.state_root();
        let counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        let pools_root = map_root("POOLS", &self.pools, InsurancePool::public_record);
        let sponsor_deposits_root = map_root(
            "SPONSOR_DEPOSITS",
            &self.sponsor_deposits,
            SponsorDeposit::public_record,
        );
        let reserve_buckets_root = map_root(
            "RESERVE_BUCKETS",
            &self.reserve_buckets,
            ReserveBucket::public_record,
        );
        let claims_root = map_root("CLAIMS", &self.claims, InsuranceClaim::public_record);
        let attestations_root = map_root(
            "PQ_CLAIM_ATTESTATIONS",
            &self.attestations,
            PqClaimAttestation::public_record,
        );
        let batch_rebates_root = map_root(
            "BATCH_REBATES",
            &self.batch_rebates,
            BatchRebate::public_record,
        );
        let wallet_caps_root = map_root(
            "WALLET_CAPS",
            &self.wallet_caps,
            WalletFeeCap::public_record,
        );
        let public_records_root = map_value_root("PUBLIC_RECORDS", &self.public_records);
        let watched_nullifiers_root = set_root("WATCHED_NULLIFIERS", &self.watched_nullifiers);
        let state_root = root_from_record(
            "STATE",
            &json!({
                "config_root": config_root,
                "counters_root": counters_root,
                "pools_root": pools_root,
                "sponsor_deposits_root": sponsor_deposits_root,
                "reserve_buckets_root": reserve_buckets_root,
                "claims_root": claims_root,
                "attestations_root": attestations_root,
                "batch_rebates_root": batch_rebates_root,
                "wallet_caps_root": wallet_caps_root,
                "public_records_root": public_records_root,
                "watched_nullifiers_root": watched_nullifiers_root,
            }),
        );
        Roots {
            config_root,
            counters_root,
            pools_root,
            sponsor_deposits_root,
            reserve_buckets_root,
            claims_root,
            attestations_root,
            batch_rebates_root,
            wallet_caps_root,
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
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "pools": self.pools.len(),
            "sponsor_deposits": self.sponsor_deposits.len(),
            "reserve_buckets": self.reserve_buckets.len(),
            "claims": self.claims.len(),
            "attestations": self.attestations.len(),
            "batch_rebates": self.batch_rebates.len(),
            "wallet_caps": self.wallet_caps.len(),
            "public_records": self.public_records.len(),
            "watched_nullifiers": self.watched_nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn open_pool(
        &mut self,
        label: &str,
        fee_spike_kind: FeeSpikeKind,
        reserve_piconero: u64,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<String> {
        ensure_nonempty("label", label)?;
        ensure_limit(
            self.pools.len(),
            self.config.max_pools,
            "pool limit reached",
        )?;
        let sequence = self.counters.next_pool;
        let record = json!({
            "label": label,
            "fee_spike_kind": fee_spike_kind,
            "reserve_piconero": reserve_piconero,
            "sequence": sequence,
        });
        let pool_id = deterministic_id("POOL", &record, sequence);
        let max_claim_piconero =
            reserve_piconero.saturating_mul(self.config.max_claim_bps) / MAX_BPS;
        let pool = InsurancePool {
            pool_id: pool_id.clone(),
            label: label.to_string(),
            status: PoolStatus::Active,
            fee_spike_kind,
            opened_height: DEVNET_HEIGHT,
            total_reserve_piconero: reserve_piconero,
            available_reserve_piconero: reserve_piconero,
            target_reserve_piconero: reserve_piconero
                .saturating_mul(self.config.target_reserve_bps)
                / MAX_BPS,
            max_claim_piconero,
            sponsor_deposit_ids: BTreeSet::new(),
            reserve_bucket_ids: BTreeSet::new(),
            policy_root: seeded(&format!("{label}-policy")),
        };
        self.counters.next_pool = self.counters.next_pool.saturating_add(1);
        self.pools.insert(pool_id.clone(), pool);
        self.record_public("pool_opened", &pool_id);
        Ok(pool_id)
    }

    pub fn add_sponsor_deposit(
        &mut self,
        pool_id: &str,
        sponsor_id: &str,
        amount_piconero: u64,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<String> {
        ensure_nonempty("sponsor_id", sponsor_id)?;
        ensure_limit(
            self.sponsor_deposits.len(),
            self.config.max_sponsor_deposits,
            "sponsor deposit limit reached",
        )?;
        let pool = self.pools.get_mut(pool_id).ok_or("pool missing")?;
        let sequence = self.counters.next_sponsor_deposit;
        let record =
            json!({ "pool_id": pool_id, "sponsor_id": sponsor_id, "amount": amount_piconero });
        let deposit_id = deterministic_id("SPONSOR_DEPOSIT", &record, sequence);
        let deposit = SponsorDeposit {
            deposit_id: deposit_id.clone(),
            pool_id: pool_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            status: DepositStatus::Active,
            asset_id: self.config.reserve_asset_id.clone(),
            committed_piconero: amount_piconero,
            remaining_piconero: amount_piconero,
            match_bps: self.config.sponsor_match_bps,
            deposit_commitment_root: root_from_record("SPONSOR_DEPOSIT_COMMITMENT", &record),
            pq_authorization_root: seeded(&format!("{sponsor_id}-pq-authorization")),
        };
        pool.sponsor_deposit_ids.insert(deposit_id.clone());
        pool.total_reserve_piconero = pool.total_reserve_piconero.saturating_add(amount_piconero);
        pool.available_reserve_piconero = pool
            .available_reserve_piconero
            .saturating_add(amount_piconero);
        self.counters.next_sponsor_deposit = self.counters.next_sponsor_deposit.saturating_add(1);
        self.sponsor_deposits.insert(deposit_id.clone(), deposit);
        self.record_public("sponsor_deposit_active", &deposit_id);
        Ok(deposit_id)
    }

    pub fn add_reserve_bucket(
        &mut self,
        pool_id: &str,
        kind: BucketKind,
        target_piconero: u64,
        expected_loss_bps: u64,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<String> {
        ensure_limit(
            self.reserve_buckets.len(),
            self.config.max_reserve_buckets,
            "reserve bucket limit reached",
        )?;
        let pool = self.pools.get_mut(pool_id).ok_or("pool missing")?;
        let sequence = self.counters.next_reserve_bucket;
        let record = json!({ "pool_id": pool_id, "kind": kind, "target": target_piconero });
        let bucket_id = deterministic_id("RESERVE_BUCKET", &record, sequence);
        let bucket = ReserveBucket {
            bucket_id: bucket_id.clone(),
            pool_id: pool_id.to_string(),
            kind,
            epoch: self.config.epoch,
            expected_loss_bps,
            target_piconero,
            available_piconero: target_piconero.min(pool.available_reserve_piconero),
            actuarial_model_root: seeded(&format!("actuarial-{pool_id}-{}", kind as u8)),
        };
        pool.reserve_bucket_ids.insert(bucket_id.clone());
        self.counters.next_reserve_bucket = self.counters.next_reserve_bucket.saturating_add(1);
        self.reserve_buckets.insert(bucket_id.clone(), bucket);
        self.record_public("reserve_bucket_active", &bucket_id);
        Ok(bucket_id)
    }

    pub fn register_wallet_cap(
        &mut self,
        wallet_commitment_root: String,
        max_fee_piconero: u64,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<String> {
        ensure_root("wallet_commitment_root", &wallet_commitment_root)?;
        ensure_limit(
            self.wallet_caps.len(),
            self.config.max_wallet_caps,
            "wallet cap limit reached",
        )?;
        let sequence = self.counters.next_wallet_cap;
        let record = json!({
            "wallet_commitment_root": wallet_commitment_root,
            "max_fee_piconero": max_fee_piconero,
            "epoch": self.config.epoch,
        });
        let wallet_cap_id = deterministic_id("WALLET_CAP", &record, sequence);
        let cap_nullifier_root = root_from_record("WALLET_CAP_NULLIFIER", &record);
        let cap = WalletFeeCap {
            wallet_cap_id: wallet_cap_id.clone(),
            wallet_commitment_root,
            max_fee_piconero,
            epoch: self.config.epoch,
            cap_nullifier_root: cap_nullifier_root.clone(),
        };
        self.watched_nullifiers.insert(cap_nullifier_root);
        self.counters.next_wallet_cap = self.counters.next_wallet_cap.saturating_add(1);
        self.wallet_caps.insert(wallet_cap_id.clone(), cap);
        self.record_public("wallet_fee_cap_registered", &wallet_cap_id);
        Ok(wallet_cap_id)
    }

    pub fn submit_claim(
        &mut self,
        pool_id: &str,
        wallet_cap_id: &str,
        fee_spike_kind: FeeSpikeKind,
        requested_piconero: u64,
        private_claim_commitment_root: String,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<String> {
        ensure_root(
            "private_claim_commitment_root",
            &private_claim_commitment_root,
        )?;
        ensure_limit(
            self.claims.len(),
            self.config.max_claims,
            "claim limit reached",
        )?;
        let pool = self.pools.get(pool_id).ok_or("pool missing")?;
        let wallet_cap = self
            .wallet_caps
            .get(wallet_cap_id)
            .ok_or("wallet cap missing")?;
        if !pool.status.claimable() {
            return Err("pool is not claimable".to_string());
        }
        let sequence = self.counters.next_claim;
        let capped_piconero = requested_piconero
            .min(pool.max_claim_piconero)
            .min(wallet_cap.max_fee_piconero)
            .min(self.config.wallet_fee_cap_piconero);
        let status = if capped_piconero < requested_piconero {
            self.counters.capped_claims = self.counters.capped_claims.saturating_add(1);
            ClaimStatus::Capped
        } else {
            ClaimStatus::Submitted
        };
        let record = json!({
            "pool_id": pool_id,
            "wallet_cap_id": wallet_cap_id,
            "fee_spike_kind": fee_spike_kind,
            "requested_piconero": requested_piconero,
            "capped_piconero": capped_piconero,
        });
        let claim_id = deterministic_id("CLAIM", &record, sequence);
        let claim = InsuranceClaim {
            claim_id: claim_id.clone(),
            pool_id: pool_id.to_string(),
            wallet_cap_id: wallet_cap_id.to_string(),
            status,
            fee_spike_kind,
            submitted_height: DEVNET_HEIGHT.saturating_add(sequence),
            requested_piconero,
            capped_piconero,
            approved_piconero: 0,
            attestation_id: None,
            private_claim_commitment_root,
        };
        self.counters.next_claim = self.counters.next_claim.saturating_add(1);
        self.claims.insert(claim_id.clone(), claim);
        self.record_public("claim_submitted", &claim_id);
        Ok(claim_id)
    }

    pub fn attest_claim(
        &mut self,
        claim_id: &str,
        committee_id: &str,
        observed_fee_piconero: u64,
        baseline_fee_piconero: u64,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<String> {
        ensure_nonempty("committee_id", committee_id)?;
        ensure_limit(
            self.attestations.len(),
            self.config.max_attestations,
            "attestation limit reached",
        )?;
        let claim = self.claims.get_mut(claim_id).ok_or("claim missing")?;
        let sequence = self.counters.next_attestation;
        let evidence = json!({
            "claim_id": claim_id,
            "committee_id": committee_id,
            "observed_fee_piconero": observed_fee_piconero,
            "baseline_fee_piconero": baseline_fee_piconero,
        });
        let attestation_id = deterministic_id("PQ_CLAIM_ATTESTATION", &evidence, sequence);
        let attestation = PqClaimAttestation {
            attestation_id: attestation_id.clone(),
            claim_id: claim_id.to_string(),
            committee_id: committee_id.to_string(),
            pq_security_bits: self.config.min_pq_security_bits,
            observed_fee_piconero,
            baseline_fee_piconero,
            evidence_root: root_from_record("PQ_CLAIM_EVIDENCE", &evidence),
            attestation_root: root_from_record("PQ_CLAIM_ATTESTATION", &evidence),
        };
        claim.attestation_id = Some(attestation_id.clone());
        claim.status = ClaimStatus::Attested;
        self.counters.next_attestation = self.counters.next_attestation.saturating_add(1);
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.record_public("pq_claim_attested", &attestation_id);
        Ok(attestation_id)
    }

    pub fn approve_claim(
        &mut self,
        claim_id: &str,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<u64> {
        let claim = self.claims.get_mut(claim_id).ok_or("claim missing")?;
        if claim.attestation_id.is_none() {
            self.counters.rejected_claims = self.counters.rejected_claims.saturating_add(1);
            claim.status = ClaimStatus::Rejected;
            return Err("claim requires PQ attestation".to_string());
        }
        let pool = self.pools.get_mut(&claim.pool_id).ok_or("pool missing")?;
        let approved = claim.capped_piconero.min(pool.available_reserve_piconero);
        pool.available_reserve_piconero = pool.available_reserve_piconero.saturating_sub(approved);
        claim.approved_piconero = approved;
        claim.status = if approved == claim.capped_piconero {
            self.counters.paid_claims = self.counters.paid_claims.saturating_add(1);
            ClaimStatus::Paid
        } else {
            ClaimStatus::PartiallyPaid
        };
        self.record_public("claim_approved", claim_id);
        Ok(approved)
    }

    pub fn create_batch_rebate(
        &mut self,
        pool_id: &str,
        claim_ids: BTreeSet<String>,
    ) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<String> {
        ensure_limit(
            self.batch_rebates.len(),
            self.config.max_batch_rebates,
            "batch rebate limit reached",
        )?;
        if !self.pools.contains_key(pool_id) {
            return Err("pool missing".to_string());
        }
        for claim_id in &claim_ids {
            if !self.claims.contains_key(claim_id) {
                return Err(format!("claim {claim_id} missing"));
            }
        }
        let gross = claim_ids
            .iter()
            .filter_map(|claim_id| self.claims.get(claim_id))
            .map(|claim| claim.approved_piconero)
            .sum::<u64>();
        let net = gross.saturating_mul(self.config.batch_rebate_bps) / MAX_BPS;
        let sequence = self.counters.next_batch_rebate;
        let batch_root = set_root("BATCH_REBATE_CLAIMS", &claim_ids);
        let record =
            json!({ "pool_id": pool_id, "batch_root": batch_root, "gross": gross, "net": net });
        let rebate_id = deterministic_id("BATCH_REBATE", &record, sequence);
        let rebate = BatchRebate {
            rebate_id: rebate_id.clone(),
            pool_id: pool_id.to_string(),
            status: RebateStatus::Netted,
            batch_root,
            eligible_claim_ids: claim_ids,
            gross_rebate_piconero: gross,
            net_rebate_piconero: net,
            expires_height: DEVNET_HEIGHT.saturating_add(self.config.rebate_ttl_blocks),
        };
        self.counters.next_batch_rebate = self.counters.next_batch_rebate.saturating_add(1);
        self.batch_rebates.insert(rebate_id.clone(), rebate);
        self.record_public("batch_rebate_netted", &rebate_id);
        Ok(rebate_id)
    }

    fn seed_devnet(&mut self) {
        let Ok(pool_id) = self.open_pool(
            "devnet-proof-da-fee-spike-insurance",
            FeeSpikeKind::ProverMarket,
            8_000_000,
        ) else {
            return;
        };
        let _ = self.add_sponsor_deposit(&pool_id, "devnet-sponsor-alpha", 3_250_000);
        let _ = self.add_reserve_bucket(&pool_id, BucketKind::ProverSpike, 2_000_000, 420);
        let _ = self.add_reserve_bucket(&pool_id, BucketKind::DaSpike, 1_500_000, 360);
        let Ok(wallet_cap_id) =
            self.register_wallet_cap(seeded("devnet-wallet-fee-cap-commitment"), 38_000)
        else {
            return;
        };
        let Ok(claim_id) = self.submit_claim(
            &pool_id,
            &wallet_cap_id,
            FeeSpikeKind::ProverMarket,
            92_000,
            seeded("devnet-private-claim-commitment"),
        ) else {
            return;
        };
        let _ = self.attest_claim(&claim_id, "devnet-pq-fee-oracle-committee", 92_000, 21_000);
        let _ = self.approve_claim(&claim_id);
        let mut claims = BTreeSet::new();
        claims.insert(claim_id);
        let _ = self.create_batch_rebate(&pool_id, claims);
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
                "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME:PUBLIC_SUBJECT",
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
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn deterministic_id(domain: &str, record: &Value, sequence: u64) -> String {
    domain_hash(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME:{domain}:ID"),
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
        "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME:DEVNET_FIXTURE",
        &[HashPart::Str(label)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME:{domain}"),
        &leaves,
    )
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME:{domain}"),
        &leaves,
    )
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_INSURANCE_POOL_RUNTIME:{domain}"),
        &leaves,
    )
}

fn ensure_nonempty(
    field: &str,
    value: &str,
) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be nonempty"))
    } else {
        Ok(())
    }
}

fn ensure_root(
    field: &str,
    value: &str,
) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 32 {
        Err(format!("{field} must look like a deterministic root"))
    } else {
        Ok(())
    }
}

fn ensure_limit(
    current: usize,
    max: usize,
    message: &str,
) -> PrivateL2LowFeePqConfidentialProofFeeInsurancePoolRuntimeResult<()> {
    if current >= max {
        Err(message.to_string())
    } else {
        Ok(())
    }
}
