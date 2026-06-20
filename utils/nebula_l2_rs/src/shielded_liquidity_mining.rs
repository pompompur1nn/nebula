use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ShieldedLiquidityMiningResult<T> = Result<T, String>;

pub const SHIELDED_LIQUIDITY_MINING_PROTOCOL_VERSION: u32 = 1;
pub const SHIELDED_LIQUIDITY_MINING_PROTOCOL_LABEL: &str = "nebula-shielded-liquidity-mining-v1";
pub const SHIELDED_LIQUIDITY_MINING_SCHEMA_VERSION: u64 = 1;
pub const SHIELDED_LIQUIDITY_MINING_DEVNET_HEIGHT: u64 = 1_792;
pub const SHIELDED_LIQUIDITY_MINING_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const SHIELDED_LIQUIDITY_MINING_ELIGIBILITY_SUITE: &str = "zk-private-liquidity-eligibility-v1";
pub const SHIELDED_LIQUIDITY_MINING_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-reward-epoch";
pub const SHIELDED_LIQUIDITY_MINING_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const SHIELDED_LIQUIDITY_MINING_DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 288;
pub const SHIELDED_LIQUIDITY_MINING_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const SHIELDED_LIQUIDITY_MINING_DEFAULT_MIN_ANONYMITY_SET: u64 = 64;
pub const SHIELDED_LIQUIDITY_MINING_DEFAULT_REWARD_POOL_UNITS: u64 = 650_000;
pub const SHIELDED_LIQUIDITY_MINING_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityMiningVenue {
    PrivateDex,
    ConfidentialLending,
    StablecoinVault,
    BridgeInventory,
    PerpsMargin,
    TokenizedVault,
}

impl LiquidityMiningVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDex => "private_dex",
            Self::ConfidentialLending => "confidential_lending",
            Self::StablecoinVault => "stablecoin_vault",
            Self::BridgeInventory => "bridge_inventory",
            Self::PerpsMargin => "perps_margin",
            Self::TokenizedVault => "tokenized_vault",
        }
    }

    pub fn reward_weight(self) -> u64 {
        match self {
            Self::BridgeInventory => 100,
            Self::PrivateDex => 90,
            Self::StablecoinVault => 82,
            Self::ConfidentialLending => 76,
            Self::PerpsMargin => 68,
            Self::TokenizedVault => 60,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardEpochStatus {
    Scheduled,
    Open,
    Finalizing,
    Claimable,
    Settled,
    Cancelled,
}

impl RewardEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Finalizing => "finalizing",
            Self::Claimable => "claimable",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Scheduled | Self::Open | Self::Finalizing | Self::Claimable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardClaimStatus {
    Pending,
    Verified,
    Paid,
    Challenged,
    Rejected,
    Expired,
}

impl RewardClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Paid => "paid",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::Verified | Self::Challenged)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedLiquidityMiningConfig {
    pub epoch_blocks: u64,
    pub claim_window_blocks: u64,
    pub low_fee_rebate_bps: u64,
    pub min_anonymity_set: u64,
    pub reward_pool_units: u64,
    pub eligibility_suite: String,
    pub pq_auth_suite: String,
    pub hash_suite: String,
}

impl ShieldedLiquidityMiningConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: SHIELDED_LIQUIDITY_MINING_DEFAULT_EPOCH_BLOCKS,
            claim_window_blocks: SHIELDED_LIQUIDITY_MINING_DEFAULT_CLAIM_WINDOW_BLOCKS,
            low_fee_rebate_bps: SHIELDED_LIQUIDITY_MINING_DEFAULT_LOW_FEE_REBATE_BPS,
            min_anonymity_set: SHIELDED_LIQUIDITY_MINING_DEFAULT_MIN_ANONYMITY_SET,
            reward_pool_units: SHIELDED_LIQUIDITY_MINING_DEFAULT_REWARD_POOL_UNITS,
            eligibility_suite: SHIELDED_LIQUIDITY_MINING_ELIGIBILITY_SUITE.to_string(),
            pq_auth_suite: SHIELDED_LIQUIDITY_MINING_PQ_AUTH_SUITE.to_string(),
            hash_suite: SHIELDED_LIQUIDITY_MINING_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "claim_window_blocks": self.claim_window_blocks,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_anonymity_set": self.min_anonymity_set,
            "reward_pool_units": self.reward_pool_units,
            "eligibility_suite": self.eligibility_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        shielded_liquidity_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ShieldedLiquidityMiningResult<()> {
        if self.epoch_blocks == 0
            || self.claim_window_blocks == 0
            || self.min_anonymity_set == 0
            || self.reward_pool_units == 0
        {
            return Err("shielded liquidity mining config values must be positive".to_string());
        }
        if self.low_fee_rebate_bps > SHIELDED_LIQUIDITY_MINING_MAX_BPS {
            return Err("shielded liquidity mining rebate exceeds max bps".to_string());
        }
        if self.eligibility_suite.is_empty()
            || self.pq_auth_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("shielded liquidity mining suite labels must be populated".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardEpoch {
    pub epoch_id: String,
    pub venue: LiquidityMiningVenue,
    pub status: RewardEpochStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub reward_units: u64,
    pub eligibility_root: String,
    pub contribution_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
}

impl RewardEpoch {
    pub fn new(
        epoch_id: &str,
        venue: LiquidityMiningVenue,
        start_height: u64,
        end_height: u64,
        reward_units: u64,
    ) -> ShieldedLiquidityMiningResult<Self> {
        if epoch_id.is_empty() {
            return Err("reward epoch id must be populated".to_string());
        }
        if end_height <= start_height || reward_units == 0 {
            return Err("reward epoch range and rewards must be positive".to_string());
        }
        let eligibility_root = shielded_liquidity_hash(
            "EPOCH-ELIGIBILITY",
            &[
                HashPart::Str(epoch_id),
                HashPart::Str(venue.as_str()),
                HashPart::Int(start_height as i128),
                HashPart::Int(end_height as i128),
            ],
        );
        let contribution_root = shielded_liquidity_hash(
            "EPOCH-CONTRIBUTION",
            &[HashPart::Str(epoch_id), HashPart::Str(&eligibility_root)],
        );
        let pq_authorization_root = shielded_liquidity_hash(
            "EPOCH-PQ-AUTHORIZATION",
            &[HashPart::Str(epoch_id), HashPart::Str(&contribution_root)],
        );
        let low_fee_sponsor_root = shielded_liquidity_hash(
            "EPOCH-SPONSOR",
            &[HashPart::Str(epoch_id), HashPart::Int(reward_units as i128)],
        );
        Ok(Self {
            epoch_id: epoch_id.to_string(),
            venue,
            status: RewardEpochStatus::Open,
            start_height,
            end_height,
            reward_units,
            eligibility_root,
            contribution_root,
            pq_authorization_root,
            low_fee_sponsor_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "venue": self.venue.as_str(),
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "reward_units": self.reward_units,
            "eligibility_root": self.eligibility_root,
            "contribution_root": self.contribution_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
        })
    }

    pub fn root(&self) -> String {
        shielded_liquidity_hash("EPOCH", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height <= self.end_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedRewardClaim {
    pub claim_id: String,
    pub epoch_id: String,
    pub claimant_nullifier: String,
    pub reward_commitment: String,
    pub reward_units: u64,
    pub status: RewardClaimStatus,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub eligibility_proof_root: String,
    pub payout_note_root: String,
}

impl ShieldedRewardClaim {
    pub fn new(
        claim_id: &str,
        epoch: &RewardEpoch,
        claimant_nullifier: &str,
        reward_units: u64,
        opened_height: u64,
        claim_window_blocks: u64,
    ) -> ShieldedLiquidityMiningResult<Self> {
        if claim_id.is_empty() || claimant_nullifier.is_empty() {
            return Err("shielded reward claim identifiers must be populated".to_string());
        }
        if reward_units == 0 || reward_units > epoch.reward_units {
            return Err("shielded reward claim amount invalid".to_string());
        }
        let reward_commitment = shielded_liquidity_hash(
            "CLAIM-REWARD-COMMITMENT",
            &[
                HashPart::Str(claim_id),
                HashPart::Str(&epoch.epoch_id),
                HashPart::Str(claimant_nullifier),
                HashPart::Int(reward_units as i128),
            ],
        );
        let eligibility_proof_root = shielded_liquidity_hash(
            "CLAIM-ELIGIBILITY-PROOF",
            &[
                HashPart::Str(claim_id),
                HashPart::Str(&epoch.eligibility_root),
                HashPart::Str(&reward_commitment),
            ],
        );
        let payout_note_root = shielded_liquidity_hash(
            "CLAIM-PAYOUT-NOTE",
            &[HashPart::Str(claim_id), HashPart::Str(&reward_commitment)],
        );
        Ok(Self {
            claim_id: claim_id.to_string(),
            epoch_id: epoch.epoch_id.clone(),
            claimant_nullifier: claimant_nullifier.to_string(),
            reward_commitment,
            reward_units,
            status: RewardClaimStatus::Pending,
            opened_height,
            deadline_height: opened_height.saturating_add(claim_window_blocks),
            eligibility_proof_root,
            payout_note_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "epoch_id": self.epoch_id,
            "claimant_nullifier": self.claimant_nullifier,
            "reward_commitment": self.reward_commitment,
            "reward_units": self.reward_units,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "eligibility_proof_root": self.eligibility_proof_root,
            "payout_note_root": self.payout_note_root,
        })
    }

    pub fn root(&self) -> String {
        shielded_liquidity_hash("CLAIM", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedLiquidityMiningRoots {
    pub config_root: String,
    pub epoch_root: String,
    pub claim_root: String,
    pub venue_reward_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl ShieldedLiquidityMiningRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "epoch_root": self.epoch_root,
            "claim_root": self.claim_root,
            "venue_reward_root": self.venue_reward_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedLiquidityMiningCounters {
    pub epoch_count: u64,
    pub live_epoch_count: u64,
    pub claim_count: u64,
    pub open_claim_count: u64,
    pub total_reward_units: u64,
    pub claimed_reward_units: u64,
    pub venue_count: u64,
}

impl ShieldedLiquidityMiningCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_count": self.epoch_count,
            "live_epoch_count": self.live_epoch_count,
            "claim_count": self.claim_count,
            "open_claim_count": self.open_claim_count,
            "total_reward_units": self.total_reward_units,
            "claimed_reward_units": self.claimed_reward_units,
            "venue_count": self.venue_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedLiquidityMiningState {
    pub height: u64,
    pub config: ShieldedLiquidityMiningConfig,
    pub epochs: BTreeMap<String, RewardEpoch>,
    pub claims: BTreeMap<String, ShieldedRewardClaim>,
    pub venue_rewards: BTreeMap<LiquidityMiningVenue, u64>,
    pub used_nullifiers: BTreeSet<String>,
    pub paused: bool,
}

impl ShieldedLiquidityMiningState {
    pub fn devnet() -> ShieldedLiquidityMiningResult<Self> {
        let config = ShieldedLiquidityMiningConfig::devnet();
        config.validate()?;
        let mut state = Self {
            height: SHIELDED_LIQUIDITY_MINING_DEVNET_HEIGHT,
            config,
            epochs: BTreeMap::new(),
            claims: BTreeMap::new(),
            venue_rewards: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            paused: false,
        };
        let dex_epoch = RewardEpoch::new(
            "devnet-private-dex-epoch-a",
            LiquidityMiningVenue::PrivateDex,
            state.height,
            state.height.saturating_add(720),
            210_000,
        )?;
        state.insert_epoch(dex_epoch)?;
        let bridge_epoch = RewardEpoch::new(
            "devnet-bridge-inventory-epoch-a",
            LiquidityMiningVenue::BridgeInventory,
            state.height,
            state.height.saturating_add(720),
            180_000,
        )?;
        state.insert_epoch(bridge_epoch)?;
        state.open_claim(
            "devnet-private-dex-claim-a",
            "devnet-private-dex-epoch-a",
            "claim-nullifier-alice-a",
            4_200,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ShieldedLiquidityMiningResult<()> {
        if height < self.height {
            return Err("shielded liquidity mining height cannot move backwards".to_string());
        }
        self.height = height;
        for epoch in self.epochs.values_mut() {
            if epoch.status.is_live() && height > epoch.end_height {
                epoch.status = RewardEpochStatus::Claimable;
            }
        }
        for claim in self.claims.values_mut() {
            if claim.status.is_open() && height > claim.deadline_height {
                claim.status = RewardClaimStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_epoch(&mut self, epoch: RewardEpoch) -> ShieldedLiquidityMiningResult<()> {
        if self.paused {
            return Err("shielded liquidity mining is paused".to_string());
        }
        if self.epochs.contains_key(&epoch.epoch_id) {
            return Err("shielded liquidity mining epoch already exists".to_string());
        }
        let venue_reward = self.venue_rewards.entry(epoch.venue).or_insert(0);
        *venue_reward = venue_reward.saturating_add(epoch.reward_units);
        self.epochs.insert(epoch.epoch_id.clone(), epoch);
        Ok(())
    }

    pub fn open_claim(
        &mut self,
        claim_id: &str,
        epoch_id: &str,
        claimant_nullifier: &str,
        reward_units: u64,
    ) -> ShieldedLiquidityMiningResult<String> {
        if self.used_nullifiers.contains(claimant_nullifier) {
            return Err("shielded reward nullifier already used".to_string());
        }
        let epoch = self
            .epochs
            .get(epoch_id)
            .ok_or_else(|| "shielded reward epoch missing".to_string())?;
        if !epoch.is_live_at(self.height) && epoch.status != RewardEpochStatus::Claimable {
            return Err("shielded reward epoch is not claimable".to_string());
        }
        let claim = ShieldedRewardClaim::new(
            claim_id,
            epoch,
            claimant_nullifier,
            reward_units,
            self.height,
            self.config.claim_window_blocks,
        )?;
        let claim_root = claim.root();
        self.used_nullifiers
            .insert(claim.claimant_nullifier.clone());
        self.claims.insert(claim.claim_id.clone(), claim);
        Ok(claim_root)
    }

    pub fn live_epoch_ids(&self) -> Vec<String> {
        self.epochs
            .values()
            .filter(|epoch| epoch.is_live_at(self.height))
            .map(|epoch| epoch.epoch_id.clone())
            .collect()
    }

    pub fn open_claim_ids(&self) -> Vec<String> {
        self.claims
            .values()
            .filter(|claim| claim.status.is_open())
            .map(|claim| claim.claim_id.clone())
            .collect()
    }

    pub fn venue_reward_map(&self) -> BTreeMap<String, u64> {
        self.venue_rewards
            .iter()
            .map(|(venue, units)| (venue.as_str().to_string(), *units))
            .collect()
    }

    pub fn total_reward_units(&self) -> u64 {
        self.epochs.values().map(|epoch| epoch.reward_units).sum()
    }

    pub fn claimed_reward_units(&self) -> u64 {
        self.claims.values().map(|claim| claim.reward_units).sum()
    }

    pub fn roots(&self) -> ShieldedLiquidityMiningRoots {
        let config_root = self.config.config_root();
        let epoch_records = self
            .epochs
            .values()
            .map(RewardEpoch::public_record)
            .collect::<Vec<_>>();
        let claim_records = self
            .claims
            .values()
            .map(ShieldedRewardClaim::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .used_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        let epoch_root = merkle_root("SHIELDED-LIQUIDITY-EPOCH", &epoch_records);
        let claim_root = merkle_root("SHIELDED-LIQUIDITY-CLAIM", &claim_records);
        let venue_reward_root = shielded_liquidity_hash(
            "VENUE-REWARD",
            &[HashPart::Json(&json!(self.venue_reward_map()))],
        );
        let nullifier_root = merkle_root("SHIELDED-LIQUIDITY-NULLIFIER", &nullifier_records);
        let state_root = shielded_liquidity_hash(
            "STATE",
            &[
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&epoch_root),
                HashPart::Str(&claim_root),
                HashPart::Str(&venue_reward_root),
                HashPart::Str(&nullifier_root),
            ],
        );
        ShieldedLiquidityMiningRoots {
            config_root,
            epoch_root,
            claim_root,
            venue_reward_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> ShieldedLiquidityMiningCounters {
        ShieldedLiquidityMiningCounters {
            epoch_count: self.epochs.len() as u64,
            live_epoch_count: self.live_epoch_ids().len() as u64,
            claim_count: self.claims.len() as u64,
            open_claim_count: self.open_claim_ids().len() as u64,
            total_reward_units: self.total_reward_units(),
            claimed_reward_units: self.claimed_reward_units(),
            venue_count: self.venue_rewards.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "shielded_liquidity_mining",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_LIQUIDITY_MINING_PROTOCOL_VERSION,
            "protocol_label": SHIELDED_LIQUIDITY_MINING_PROTOCOL_LABEL,
            "schema_version": SHIELDED_LIQUIDITY_MINING_SCHEMA_VERSION,
            "height": self.height,
            "paused": self.paused,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "live_epoch_ids": self.live_epoch_ids(),
            "open_claim_ids": self.open_claim_ids(),
            "venue_reward_map": self.venue_reward_map(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> ShieldedLiquidityMiningResult<String> {
        self.config.validate()?;
        for epoch in self.epochs.values() {
            if epoch.end_height <= epoch.start_height {
                return Err("shielded reward epoch has invalid range".to_string());
            }
        }
        let mut seen_nullifiers = BTreeSet::new();
        for claim in self.claims.values() {
            if !self.epochs.contains_key(&claim.epoch_id) {
                return Err("shielded reward claim references missing epoch".to_string());
            }
            if !seen_nullifiers.insert(claim.claimant_nullifier.clone()) {
                return Err("duplicate shielded reward claim nullifier".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn shielded_liquidity_mining_state_root_from_record(record: &Value) -> String {
    shielded_liquidity_hash("STATE-FROM-RECORD", &[HashPart::Json(record)])
}

fn shielded_liquidity_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            SHIELDED_LIQUIDITY_MINING_PROTOCOL_LABEL, CHAIN_ID, label
        ),
        parts,
        32,
    )
}
