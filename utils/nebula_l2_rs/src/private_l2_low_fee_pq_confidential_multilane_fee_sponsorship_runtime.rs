use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialMultilaneFeeSponsorshipRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialMultilaneFeeSponsorshipRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTILANE_FEE_SPONSORSHIP_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-multilane-fee-sponsorship-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTILANE_FEE_SPONSORSHIP_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const PQ_SPONSORSHIP_ATTESTATION_SUITE: &str =
    "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f-multilane-fee-sponsorship-v1";
pub const PRIVATE_BUCKET_SCHEME: &str =
    "private-l2-low-fee-confidential-sponsor-bucket-commitment-v1";
pub const LANE_SUBSIDY_SCHEME: &str =
    "private-l2-low-fee-confidential-lane-specific-subsidy-split-v1";
pub const REBATE_SPLIT_SCHEME: &str = "calldata-proof-da-rebate-split-confidential-commitment-v1";
pub const WALLET_CAP_SCHEME: &str = "private-wallet-sponsored-fee-cap-nullifier-root-v1";
pub const SPONSOR_RISK_SCHEME: &str = "private-sponsor-risk-limit-drawdown-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "public-multilane-fee-sponsorship-record-redacted-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_360_000;
pub const DEVNET_EPOCH: u64 = 47_104;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_SPONSOR_ASSET_ID: &str = "piconero-sponsored-fee-credit-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_PUBLIC_RECORD_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_WALLET_CAP_MICROS: u64 = 125_000;
pub const DEFAULT_MAX_SPONSOR_DRAWDOWN_BPS: u64 = 2_000;
pub const DEFAULT_MAX_LANE_EXPOSURE_BPS: u64 = 3_500;
pub const DEFAULT_TARGET_SUBSIDY_BPS: u64 = 2_400;
pub const DEFAULT_CALLDATA_REBATE_BPS: u64 = 950;
pub const DEFAULT_PROOF_REBATE_BPS: u64 = 850;
pub const DEFAULT_DA_REBATE_BPS: u64 = 600;
pub const MAX_BUCKETS: usize = 524_288;
pub const MAX_LANE_POLICIES: usize = 128;
pub const MAX_WALLET_CAPS: usize = 1_048_576;
pub const MAX_RISK_LIMITS: usize = 524_288;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_PUBLIC_RECORDS: usize = 4_194_304;
pub const MAX_EVENTS: usize = 8_388_608;

const D: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP";
const D_CONFIG: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:CONFIG";
const D_COUNTERS: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:COUNTERS";
const D_ROOTS: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:ROOTS";
const D_BUCKETS: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:BUCKETS";
const D_LANES: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:LANES";
const D_WALLET_CAPS: &str =
    "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:WALLET-CAPS";
const D_RISK: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:RISK";
const D_ATTESTATIONS: &str =
    "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:ATTESTATIONS";
const D_PUBLIC_RECORDS: &str =
    "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:PUBLIC-RECORDS";
const D_EVENTS: &str = "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipLane {
    WalletTransfer,
    ContractCall,
    ProofBatch,
    BridgeExit,
    DexSwap,
    MerchantBatch,
    WalletSync,
    EmergencyCancel,
}

impl SponsorshipLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ContractCall => "contract_call",
            Self::ProofBatch => "proof_batch",
            Self::BridgeExit => "bridge_exit",
            Self::DexSwap => "dex_swap",
            Self::MerchantBatch => "merchant_batch",
            Self::WalletSync => "wallet_sync",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::WalletTransfer => 2,
            Self::ContractCall => 5,
            Self::ProofBatch => 4,
            Self::BridgeExit => 7,
            Self::DexSwap => 6,
            Self::MerchantBatch => 3,
            Self::WalletSync => 1,
            Self::EmergencyCancel => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Reserved,
    Attested,
    Active,
    LaneLimited,
    WalletLimited,
    Draining,
    Exhausted,
    Quarantined,
    Retired,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::LaneLimited => "lane_limited",
            Self::WalletLimited => "wallet_limited",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::Active | Self::LaneLimited | Self::WalletLimited
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPurpose {
    SponsorBucketFunding,
    LaneSubsidyAuthorization,
    WalletCapAuthorization,
    RebateSplitSettlement,
    RiskLimitRefresh,
    PublicRecordDisclosure,
}

impl AttestationPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorBucketFunding => "sponsor_bucket_funding",
            Self::LaneSubsidyAuthorization => "lane_subsidy_authorization",
            Self::WalletCapAuthorization => "wallet_cap_authorization",
            Self::RebateSplitSettlement => "rebate_split_settlement",
            Self::RiskLimitRefresh => "risk_limit_refresh",
            Self::PublicRecordDisclosure => "public_record_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    BucketOpened,
    LaneSubsidized,
    WalletCapDebited,
    RebateSplitSettled,
    SponsorRiskThrottled,
    AttestationAccepted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub sponsor_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub bucket_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub public_record_ttl_blocks: u64,
    pub max_wallet_cap_micros: u64,
    pub max_sponsor_drawdown_bps: u64,
    pub max_lane_exposure_bps: u64,
    pub target_subsidy_bps: u64,
    pub calldata_rebate_bps: u64,
    pub proof_rebate_bps: u64,
    pub da_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            sponsor_asset_id: DEVNET_SPONSOR_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            public_record_ttl_blocks: DEFAULT_PUBLIC_RECORD_TTL_BLOCKS,
            max_wallet_cap_micros: DEFAULT_MAX_WALLET_CAP_MICROS,
            max_sponsor_drawdown_bps: DEFAULT_MAX_SPONSOR_DRAWDOWN_BPS,
            max_lane_exposure_bps: DEFAULT_MAX_LANE_EXPOSURE_BPS,
            target_subsidy_bps: DEFAULT_TARGET_SUBSIDY_BPS,
            calldata_rebate_bps: DEFAULT_CALLDATA_REBATE_BPS,
            proof_rebate_bps: DEFAULT_PROOF_REBATE_BPS,
            da_rebate_bps: DEFAULT_DA_REBATE_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security bits below runtime floor".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("invalid privacy set bounds".to_string());
        }
        if self.max_sponsor_drawdown_bps > MAX_BPS || self.max_lane_exposure_bps > MAX_BPS {
            return Err("risk bps exceeds maximum".to_string());
        }
        let rebate_total = self
            .calldata_rebate_bps
            .saturating_add(self.proof_rebate_bps)
            .saturating_add(self.da_rebate_bps);
        if rebate_total != self.target_subsidy_bps {
            return Err("rebate split does not equal target subsidy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_asset_id": self.sponsor_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "public_record_ttl_blocks": self.public_record_ttl_blocks,
            "max_wallet_cap_micros": self.max_wallet_cap_micros,
            "max_sponsor_drawdown_bps": self.max_sponsor_drawdown_bps,
            "max_lane_exposure_bps": self.max_lane_exposure_bps,
            "target_subsidy_bps": self.target_subsidy_bps,
            "calldata_rebate_bps": self.calldata_rebate_bps,
            "proof_rebate_bps": self.proof_rebate_bps,
            "da_rebate_bps": self.da_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub buckets_opened: u64,
    pub lane_policies_registered: u64,
    pub wallet_caps_registered: u64,
    pub risk_limits_registered: u64,
    pub attestations_accepted: u64,
    pub sponsored_fee_micros: u64,
    pub calldata_rebated_micros: u64,
    pub proof_rebated_micros: u64,
    pub da_rebated_micros: u64,
    pub public_records_emitted: u64,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "buckets_opened": self.buckets_opened,
            "lane_policies_registered": self.lane_policies_registered,
            "wallet_caps_registered": self.wallet_caps_registered,
            "risk_limits_registered": self.risk_limits_registered,
            "attestations_accepted": self.attestations_accepted,
            "sponsored_fee_micros": self.sponsored_fee_micros,
            "calldata_rebated_micros": self.calldata_rebated_micros,
            "proof_rebated_micros": self.proof_rebated_micros,
            "da_rebated_micros": self.da_rebated_micros,
            "public_records_emitted": self.public_records_emitted,
            "events_emitted": self.events_emitted,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub buckets_root: String,
    pub lane_policies_root: String,
    pub wallet_caps_root: String,
    pub sponsor_risk_limits_root: String,
    pub attestations_root: String,
    pub lane_index_root: String,
    pub sponsor_index_root: String,
    pub public_records_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "buckets_root": self.buckets_root,
            "lane_policies_root": self.lane_policies_root,
            "wallet_caps_root": self.wallet_caps_root,
            "sponsor_risk_limits_root": self.sponsor_risk_limits_root,
            "attestations_root": self.attestations_root,
            "lane_index_root": self.lane_index_root,
            "sponsor_index_root": self.sponsor_index_root,
            "public_records_root": self.public_records_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateSplit {
    pub calldata_rebate_micros: u64,
    pub proof_rebate_micros: u64,
    pub da_rebate_micros: u64,
}

impl RebateSplit {
    pub fn from_fee(config: &Config, fee_micros: u64) -> Self {
        Self {
            calldata_rebate_micros: bps_amount(fee_micros, config.calldata_rebate_bps),
            proof_rebate_micros: bps_amount(fee_micros, config.proof_rebate_bps),
            da_rebate_micros: bps_amount(fee_micros, config.da_rebate_bps),
        }
    }

    pub fn total(&self) -> u64 {
        self.calldata_rebate_micros
            .saturating_add(self.proof_rebate_micros)
            .saturating_add(self.da_rebate_micros)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "calldata_rebate_micros": self.calldata_rebate_micros,
            "proof_rebate_micros": self.proof_rebate_micros,
            "da_rebate_micros": self.da_rebate_micros,
            "total_rebate_micros": self.total(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneSubsidyPolicy {
    pub lane_id: String,
    pub lane: SponsorshipLane,
    pub subsidy_bps: u64,
    pub calldata_rebate_bps: u64,
    pub proof_rebate_bps: u64,
    pub da_rebate_bps: u64,
    pub max_lane_exposure_micros: u64,
    pub min_privacy_set_size: u64,
    pub policy_root: String,
}

impl LaneSubsidyPolicy {
    pub fn new(
        config: &Config,
        lane: SponsorshipLane,
        max_lane_exposure_micros: u64,
        nonce: u64,
    ) -> Self {
        let lane_id = lane_policy_id(lane, nonce);
        let policy_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:LANE-POLICY",
            &[
                HashPart::Str(&lane_id),
                HashPart::Str(lane.as_str()),
                HashPart::U64(config.target_subsidy_bps),
                HashPart::U64(max_lane_exposure_micros),
            ],
            32,
        );
        Self {
            lane_id,
            lane,
            subsidy_bps: config.target_subsidy_bps,
            calldata_rebate_bps: config.calldata_rebate_bps,
            proof_rebate_bps: config.proof_rebate_bps,
            da_rebate_bps: config.da_rebate_bps,
            max_lane_exposure_micros,
            min_privacy_set_size: config.min_privacy_set_size,
            policy_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane,
            "subsidy_bps": self.subsidy_bps,
            "calldata_rebate_bps": self.calldata_rebate_bps,
            "proof_rebate_bps": self.proof_rebate_bps,
            "da_rebate_bps": self.da_rebate_bps,
            "max_lane_exposure_micros": self.max_lane_exposure_micros,
            "min_privacy_set_size": self.min_privacy_set_size,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorBucket {
    pub bucket_id: String,
    pub sponsor_id: String,
    pub bucket_commitment: String,
    pub lane: SponsorshipLane,
    pub status: BucketStatus,
    pub initial_balance_micros: u64,
    pub remaining_balance_micros: u64,
    pub spent_balance_micros: u64,
    pub max_wallet_cap_micros: u64,
    pub max_lane_exposure_bps: u64,
    pub max_drawdown_bps: u64,
    pub risk_limit_id: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SponsorBucket {
    pub fn new(
        config: &Config,
        sponsor_id: impl Into<String>,
        bucket_commitment: impl Into<String>,
        lane: SponsorshipLane,
        initial_balance_micros: u64,
        nonce: u64,
    ) -> Self {
        let sponsor_id = sponsor_id.into();
        let bucket_commitment = bucket_commitment.into();
        let bucket_id = sponsor_bucket_id(&sponsor_id, &bucket_commitment, lane, nonce);
        let risk_limit_id = sponsor_risk_limit_id(&sponsor_id, lane, nonce);
        Self {
            bucket_id,
            sponsor_id,
            bucket_commitment,
            lane,
            status: BucketStatus::Reserved,
            initial_balance_micros,
            remaining_balance_micros: initial_balance_micros,
            spent_balance_micros: 0,
            max_wallet_cap_micros: config.max_wallet_cap_micros,
            max_lane_exposure_bps: config.max_lane_exposure_bps,
            max_drawdown_bps: config.max_sponsor_drawdown_bps,
            risk_limit_id,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.bucket_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "sponsor_id": self.sponsor_id,
            "bucket_commitment": self.bucket_commitment,
            "lane": self.lane,
            "status": self.status,
            "initial_balance_micros": self.initial_balance_micros,
            "remaining_balance_micros": self.remaining_balance_micros,
            "spent_balance_micros": self.spent_balance_micros,
            "max_wallet_cap_micros": self.max_wallet_cap_micros,
            "max_lane_exposure_bps": self.max_lane_exposure_bps,
            "max_drawdown_bps": self.max_drawdown_bps,
            "risk_limit_id": self.risk_limit_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletCap {
    pub cap_id: String,
    pub wallet_nullifier: String,
    pub lane: SponsorshipLane,
    pub cap_micros: u64,
    pub spent_micros: u64,
    pub epoch: u64,
    pub disclosure_root: String,
}

impl WalletCap {
    pub fn new(
        wallet_nullifier: impl Into<String>,
        lane: SponsorshipLane,
        cap_micros: u64,
        nonce: u64,
    ) -> Self {
        let wallet_nullifier = wallet_nullifier.into();
        let cap_id = wallet_cap_id(&wallet_nullifier, lane, DEVNET_EPOCH, nonce);
        let disclosure_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:WALLET-CAP-DISCLOSURE",
            &[
                HashPart::Str(&cap_id),
                HashPart::Str(WALLET_CAP_SCHEME),
                HashPart::U64(cap_micros),
            ],
            32,
        );
        Self {
            cap_id,
            wallet_nullifier,
            lane,
            cap_micros,
            spent_micros: 0,
            epoch: DEVNET_EPOCH,
            disclosure_root,
        }
    }

    pub fn remaining_micros(&self) -> u64 {
        self.cap_micros.saturating_sub(self.spent_micros)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "wallet_nullifier": self.wallet_nullifier,
            "lane": self.lane,
            "cap_micros": self.cap_micros,
            "spent_micros": self.spent_micros,
            "remaining_micros": self.remaining_micros(),
            "epoch": self.epoch,
            "disclosure_root": self.disclosure_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorRiskLimit {
    pub risk_limit_id: String,
    pub sponsor_id: String,
    pub lane: SponsorshipLane,
    pub max_drawdown_micros: u64,
    pub current_drawdown_micros: u64,
    pub max_lane_exposure_micros: u64,
    pub throttle_threshold_bps: u64,
    pub risk_commitment_root: String,
}

impl SponsorRiskLimit {
    pub fn new(
        sponsor_id: impl Into<String>,
        lane: SponsorshipLane,
        max_drawdown_micros: u64,
        max_lane_exposure_micros: u64,
        nonce: u64,
    ) -> Self {
        let sponsor_id = sponsor_id.into();
        let risk_limit_id = sponsor_risk_limit_id(&sponsor_id, lane, nonce);
        let risk_commitment_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:RISK-COMMITMENT",
            &[
                HashPart::Str(&risk_limit_id),
                HashPart::Str(SPONSOR_RISK_SCHEME),
                HashPart::U64(max_drawdown_micros),
                HashPart::U64(max_lane_exposure_micros),
            ],
            32,
        );
        Self {
            risk_limit_id,
            sponsor_id,
            lane,
            max_drawdown_micros,
            current_drawdown_micros: 0,
            max_lane_exposure_micros,
            throttle_threshold_bps: 8_000,
            risk_commitment_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "risk_limit_id": self.risk_limit_id,
            "sponsor_id": self.sponsor_id,
            "lane": self.lane,
            "max_drawdown_micros": self.max_drawdown_micros,
            "current_drawdown_micros": self.current_drawdown_micros,
            "max_lane_exposure_micros": self.max_lane_exposure_micros,
            "throttle_threshold_bps": self.throttle_threshold_bps,
            "risk_commitment_root": self.risk_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSponsorshipAttestation {
    pub attestation_id: String,
    pub purpose: AttestationPurpose,
    pub sponsor_id: String,
    pub bucket_id: String,
    pub lane: SponsorshipLane,
    pub statement_root: String,
    pub pq_public_key_commitment: String,
    pub signature_commitment: String,
    pub pq_security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl PqSponsorshipAttestation {
    pub fn new(
        config: &Config,
        purpose: AttestationPurpose,
        sponsor_id: impl Into<String>,
        bucket_id: impl Into<String>,
        lane: SponsorshipLane,
        nonce: u64,
    ) -> Self {
        let sponsor_id = sponsor_id.into();
        let bucket_id = bucket_id.into();
        let statement_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:ATTESTATION-STATEMENT",
            &[
                HashPart::Str(purpose.as_str()),
                HashPart::Str(&sponsor_id),
                HashPart::Str(&bucket_id),
                HashPart::Str(lane.as_str()),
                HashPart::U64(nonce),
            ],
            32,
        );
        let attestation_id = pq_attestation_id(&sponsor_id, &bucket_id, purpose, nonce);
        let pq_public_key_commitment = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:PQ-KEY",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(PQ_SPONSORSHIP_ATTESTATION_SUITE),
            ],
            32,
        );
        let signature_commitment = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:PQ-SIGNATURE",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(&statement_root),
            ],
            32,
        );
        Self {
            attestation_id,
            purpose,
            sponsor_id,
            bucket_id,
            lane,
            statement_root,
            pq_public_key_commitment,
            signature_commitment,
            pq_security_bits: config.min_pq_security_bits,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.attestation_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "purpose": self.purpose,
            "sponsor_id": self.sponsor_id,
            "bucket_id": self.bucket_id,
            "lane": self.lane,
            "statement_root": self.statement_root,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "pq_security_bits": self.pq_security_bits,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorshipPublicRecord {
    pub record_id: String,
    pub kind: PublicRecordKind,
    pub bucket_id: String,
    pub lane: SponsorshipLane,
    pub wallet_cap_id: String,
    pub sponsored_fee_micros: u64,
    pub rebate_split: RebateSplit,
    pub redacted_subject_root: String,
    pub emitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorshipPublicRecord {
    pub fn new(
        config: &Config,
        kind: PublicRecordKind,
        bucket_id: impl Into<String>,
        lane: SponsorshipLane,
        wallet_cap_id: impl Into<String>,
        sponsored_fee_micros: u64,
        nonce: u64,
    ) -> Self {
        let bucket_id = bucket_id.into();
        let wallet_cap_id = wallet_cap_id.into();
        let rebate_split = RebateSplit::from_fee(config, sponsored_fee_micros);
        let redacted_subject_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:REDACTED-SUBJECT",
            &[
                HashPart::Str(&bucket_id),
                HashPart::Str(&wallet_cap_id),
                HashPart::Str(lane.as_str()),
                HashPart::U64(nonce),
            ],
            32,
        );
        let record_id = public_record_id(&bucket_id, &wallet_cap_id, lane, nonce);
        Self {
            record_id,
            kind,
            bucket_id,
            lane,
            wallet_cap_id,
            sponsored_fee_micros,
            rebate_split,
            redacted_subject_root,
            emitted_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.public_record_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "kind": self.kind,
            "bucket_id": self.bucket_id,
            "lane": self.lane,
            "wallet_cap_id": self.wallet_cap_id,
            "sponsored_fee_micros": self.sponsored_fee_micros,
            "rebate_split": self.rebate_split.public_record(),
            "redacted_subject_root": self.redacted_subject_root,
            "emitted_at_height": self.emitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsor_buckets: BTreeMap<String, SponsorBucket>,
    pub lane_policies: BTreeMap<String, LaneSubsidyPolicy>,
    pub wallet_caps: BTreeMap<String, WalletCap>,
    pub sponsor_risk_limits: BTreeMap<String, SponsorRiskLimit>,
    pub attestations: BTreeMap<String, PqSponsorshipAttestation>,
    pub public_records: BTreeMap<String, SponsorshipPublicRecord>,
    pub buckets_by_lane: BTreeMap<SponsorshipLane, BTreeSet<String>>,
    pub buckets_by_sponsor: BTreeMap<String, BTreeSet<String>>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sponsor_buckets: BTreeMap::new(),
            lane_policies: BTreeMap::new(),
            wallet_caps: BTreeMap::new(),
            sponsor_risk_limits: BTreeMap::new(),
            attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
            buckets_by_lane: BTreeMap::new(),
            buckets_by_sponsor: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");

        let wallet_lane = LaneSubsidyPolicy::new(
            &state.config,
            SponsorshipLane::WalletTransfer,
            125_000_000,
            1,
        );
        let proof_lane =
            LaneSubsidyPolicy::new(&state.config, SponsorshipLane::ProofBatch, 180_000_000, 2);
        let dex_lane =
            LaneSubsidyPolicy::new(&state.config, SponsorshipLane::DexSwap, 210_000_000, 3);
        state
            .register_lane_policy(wallet_lane)
            .expect("devnet wallet lane policy registers");
        state
            .register_lane_policy(proof_lane)
            .expect("devnet proof lane policy registers");
        state
            .register_lane_policy(dex_lane)
            .expect("devnet dex lane policy registers");

        let sponsor_id = "sponsor.commitment.devnet.alpha".to_string();
        let bucket = SponsorBucket::new(
            &state.config,
            sponsor_id.clone(),
            "bucket.commitment.devnet.alpha.0",
            SponsorshipLane::WalletTransfer,
            42_000_000,
            11,
        );
        let bucket_id = state
            .register_sponsor_bucket(bucket)
            .expect("devnet bucket registers");
        let risk = SponsorRiskLimit::new(
            sponsor_id.clone(),
            SponsorshipLane::WalletTransfer,
            8_400_000,
            125_000_000,
            11,
        );
        state
            .register_sponsor_risk_limit(risk)
            .expect("devnet risk limit registers");
        let cap = WalletCap::new(
            "wallet.nullifier.devnet.0001",
            SponsorshipLane::WalletTransfer,
            60_000,
            13,
        );
        let cap_id = state
            .register_wallet_cap(cap)
            .expect("devnet cap registers");
        let attestation = PqSponsorshipAttestation::new(
            &state.config,
            AttestationPurpose::SponsorBucketFunding,
            sponsor_id,
            bucket_id.clone(),
            SponsorshipLane::WalletTransfer,
            17,
        );
        state
            .accept_attestation(attestation)
            .expect("devnet attestation accepted");
        state
            .settle_sponsored_fee(&bucket_id, &cap_id, 24_000, 19)
            .expect("devnet sponsored fee settles");
        state.refresh_roots();
        state
    }

    pub fn register_lane_policy(&mut self, policy: LaneSubsidyPolicy) -> Result<String> {
        if self.lane_policies.len() >= MAX_LANE_POLICIES {
            return Err("lane policy capacity exhausted".to_string());
        }
        if policy.subsidy_bps > MAX_BPS {
            return Err("lane subsidy exceeds maximum bps".to_string());
        }
        let policy_id = policy.lane_id.clone();
        self.lane_policies.insert(policy_id.clone(), policy);
        self.counters.lane_policies_registered =
            self.counters.lane_policies_registered.saturating_add(1);
        self.emit_event("lane_subsidy_policy_registered", &policy_id);
        self.refresh_roots();
        Ok(policy_id)
    }

    pub fn register_sponsor_bucket(&mut self, bucket: SponsorBucket) -> Result<String> {
        if self.sponsor_buckets.len() >= MAX_BUCKETS {
            return Err("sponsor bucket capacity exhausted".to_string());
        }
        if bucket.pq_security_bits < self.config.min_pq_security_bits {
            return Err("sponsor bucket PQ security below runtime minimum".to_string());
        }
        if bucket.privacy_set_size < self.config.min_privacy_set_size {
            return Err("sponsor bucket privacy set below runtime minimum".to_string());
        }
        let bucket_id = bucket.bucket_id.clone();
        let sponsor_id = bucket.sponsor_id.clone();
        let lane = bucket.lane;
        self.sponsor_buckets.insert(bucket_id.clone(), bucket);
        self.buckets_by_lane
            .entry(lane)
            .or_default()
            .insert(bucket_id.clone());
        self.buckets_by_sponsor
            .entry(sponsor_id)
            .or_default()
            .insert(bucket_id.clone());
        self.counters.buckets_opened = self.counters.buckets_opened.saturating_add(1);
        self.emit_event("private_sponsor_bucket_opened", &bucket_id);
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn register_wallet_cap(&mut self, cap: WalletCap) -> Result<String> {
        if self.wallet_caps.len() >= MAX_WALLET_CAPS {
            return Err("wallet cap capacity exhausted".to_string());
        }
        if cap.cap_micros > self.config.max_wallet_cap_micros {
            return Err("wallet cap exceeds runtime cap".to_string());
        }
        let cap_id = cap.cap_id.clone();
        self.wallet_caps.insert(cap_id.clone(), cap);
        self.counters.wallet_caps_registered =
            self.counters.wallet_caps_registered.saturating_add(1);
        self.emit_event("wallet_sponsorship_cap_registered", &cap_id);
        self.refresh_roots();
        Ok(cap_id)
    }

    pub fn register_sponsor_risk_limit(&mut self, risk: SponsorRiskLimit) -> Result<String> {
        if self.sponsor_risk_limits.len() >= MAX_RISK_LIMITS {
            return Err("sponsor risk limit capacity exhausted".to_string());
        }
        let risk_id = risk.risk_limit_id.clone();
        self.sponsor_risk_limits.insert(risk_id.clone(), risk);
        self.counters.risk_limits_registered =
            self.counters.risk_limits_registered.saturating_add(1);
        self.emit_event("sponsor_risk_limit_registered", &risk_id);
        self.refresh_roots();
        Ok(risk_id)
    }

    pub fn accept_attestation(&mut self, attestation: PqSponsorshipAttestation) -> Result<String> {
        if self.attestations.len() >= MAX_ATTESTATIONS {
            return Err("PQ sponsorship attestation capacity exhausted".to_string());
        }
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ sponsorship attestation below security floor".to_string());
        }
        let (bucket_id_for_record, lane_for_record) = {
            let bucket = self
                .sponsor_buckets
                .get_mut(&attestation.bucket_id)
                .ok_or_else(|| "attestation references unknown sponsor bucket".to_string())?;
            if bucket.sponsor_id != attestation.sponsor_id || bucket.lane != attestation.lane {
                return Err("attestation does not match sponsor bucket".to_string());
            }
            bucket.status = BucketStatus::Attested;
            (bucket.bucket_id.clone(), bucket.lane)
        };
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.attestations_accepted = self.counters.attestations_accepted.saturating_add(1);
        self.emit_public_record(
            PublicRecordKind::AttestationAccepted,
            &bucket_id_for_record,
            lane_for_record,
            "",
            0,
            self.counters.attestations_accepted,
        );
        self.emit_event("pq_sponsorship_attestation_accepted", &attestation_id);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_sponsored_fee(
        &mut self,
        bucket_id: &str,
        wallet_cap_id: &str,
        fee_micros: u64,
        nonce: u64,
    ) -> Result<String> {
        let (lane, risk_limit_id) = {
            let bucket = self
                .sponsor_buckets
                .get(bucket_id)
                .ok_or_else(|| "unknown sponsor bucket".to_string())?;
            if !bucket.status.spendable() {
                return Err("sponsor bucket is not spendable".to_string());
            }
            if bucket.remaining_balance_micros < fee_micros {
                return Err("sponsor bucket balance insufficient".to_string());
            }
            (bucket.lane, bucket.risk_limit_id.clone())
        };
        {
            let cap = self
                .wallet_caps
                .get(wallet_cap_id)
                .ok_or_else(|| "unknown wallet cap".to_string())?;
            if cap.lane != lane {
                return Err("wallet cap lane does not match sponsor bucket".to_string());
            }
            if cap.remaining_micros() < fee_micros {
                if let Some(bucket) = self.sponsor_buckets.get_mut(bucket_id) {
                    bucket.status = BucketStatus::WalletLimited;
                }
                return Err("wallet cap insufficient".to_string());
            }
        }
        {
            let risk = self
                .sponsor_risk_limits
                .get(&risk_limit_id)
                .ok_or_else(|| "missing sponsor risk limit".to_string())?;
            if risk.current_drawdown_micros.saturating_add(fee_micros) > risk.max_drawdown_micros {
                if let Some(bucket) = self.sponsor_buckets.get_mut(bucket_id) {
                    bucket.status = BucketStatus::LaneLimited;
                }
                return Err("sponsor risk drawdown exceeded".to_string());
            }
        }

        {
            let bucket = self
                .sponsor_buckets
                .get_mut(bucket_id)
                .ok_or_else(|| "unknown sponsor bucket".to_string())?;
            bucket.remaining_balance_micros =
                bucket.remaining_balance_micros.saturating_sub(fee_micros);
            bucket.spent_balance_micros = bucket.spent_balance_micros.saturating_add(fee_micros);
            bucket.status = if bucket.remaining_balance_micros == 0 {
                BucketStatus::Exhausted
            } else {
                BucketStatus::Active
            };
        }
        if let Some(cap) = self.wallet_caps.get_mut(wallet_cap_id) {
            cap.spent_micros = cap.spent_micros.saturating_add(fee_micros);
        }
        if let Some(risk) = self.sponsor_risk_limits.get_mut(&risk_limit_id) {
            risk.current_drawdown_micros = risk.current_drawdown_micros.saturating_add(fee_micros);
        }

        let split = RebateSplit::from_fee(&self.config, fee_micros);
        self.counters.sponsored_fee_micros = self
            .counters
            .sponsored_fee_micros
            .saturating_add(fee_micros);
        self.counters.calldata_rebated_micros = self
            .counters
            .calldata_rebated_micros
            .saturating_add(split.calldata_rebate_micros);
        self.counters.proof_rebated_micros = self
            .counters
            .proof_rebated_micros
            .saturating_add(split.proof_rebate_micros);
        self.counters.da_rebated_micros = self
            .counters
            .da_rebated_micros
            .saturating_add(split.da_rebate_micros);
        let record_id = self.emit_public_record(
            PublicRecordKind::RebateSplitSettled,
            bucket_id,
            lane,
            wallet_cap_id,
            fee_micros,
            nonce,
        );
        self.emit_event("sponsored_fee_rebate_split_settled", &record_id);
        self.refresh_roots();
        Ok(record_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: record_root(D_CONFIG, &self.config.public_record()),
            counters_root: record_root(D_COUNTERS, &self.counters.public_record()),
            buckets_root: collection_root(
                D_BUCKETS,
                self.sponsor_buckets
                    .values()
                    .map(SponsorBucket::public_record),
            ),
            lane_policies_root: collection_root(
                D_LANES,
                self.lane_policies
                    .values()
                    .map(LaneSubsidyPolicy::public_record),
            ),
            wallet_caps_root: collection_root(
                D_WALLET_CAPS,
                self.wallet_caps.values().map(WalletCap::public_record),
            ),
            sponsor_risk_limits_root: collection_root(
                D_RISK,
                self.sponsor_risk_limits
                    .values()
                    .map(SponsorRiskLimit::public_record),
            ),
            attestations_root: collection_root(
                D_ATTESTATIONS,
                self.attestations
                    .values()
                    .map(PqSponsorshipAttestation::public_record),
            ),
            lane_index_root: collection_root(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:LANE-INDEX",
                self.buckets_by_lane
                    .iter()
                    .map(|(lane, buckets)| json!({"lane": lane, "buckets": buckets})),
            ),
            sponsor_index_root: collection_root(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:SPONSOR-INDEX",
                self.buckets_by_sponsor.iter().map(
                    |(sponsor_id, buckets)| json!({"sponsor_id": sponsor_id, "buckets": buckets}),
                ),
            ),
            public_records_root: collection_root(
                D_PUBLIC_RECORDS,
                self.public_records
                    .values()
                    .map(SponsorshipPublicRecord::public_record),
            ),
            events_root: collection_root(D_EVENTS, self.events.iter().cloned()),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_sponsorship_attestation_suite": PQ_SPONSORSHIP_ATTESTATION_SUITE,
            "private_bucket_scheme": PRIVATE_BUCKET_SCHEME,
            "lane_subsidy_scheme": LANE_SUBSIDY_SCHEME,
            "rebate_split_scheme": REBATE_SPLIT_SCHEME,
            "wallet_cap_scheme": WALLET_CAP_SCHEME,
            "sponsor_risk_scheme": SPONSOR_RISK_SCHEME,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "sponsor_buckets": self.sponsor_buckets.values().map(SponsorBucket::public_record).collect::<Vec<_>>(),
            "lane_policies": self.lane_policies.values().map(LaneSubsidyPolicy::public_record).collect::<Vec<_>>(),
            "wallet_caps": self.wallet_caps.values().map(WalletCap::public_record).collect::<Vec<_>>(),
            "sponsor_risk_limits": self.sponsor_risk_limits.values().map(SponsorRiskLimit::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqSponsorshipAttestation::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(SponsorshipPublicRecord::public_record).collect::<Vec<_>>(),
            "buckets_by_lane": self.buckets_by_lane,
            "buckets_by_sponsor": self.buckets_by_sponsor,
            "events": self.events,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D, &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn emit_public_record(
        &mut self,
        kind: PublicRecordKind,
        bucket_id: &str,
        lane: SponsorshipLane,
        wallet_cap_id: &str,
        sponsored_fee_micros: u64,
        nonce: u64,
    ) -> String {
        if self.public_records.len() >= MAX_PUBLIC_RECORDS {
            return domain_hash(
                D_PUBLIC_RECORDS,
                &[HashPart::Str(bucket_id), HashPart::U64(nonce)],
                32,
            );
        }
        let record = SponsorshipPublicRecord::new(
            &self.config,
            kind,
            bucket_id,
            lane,
            wallet_cap_id,
            sponsored_fee_micros,
            nonce,
        );
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        self.counters.public_records_emitted =
            self.counters.public_records_emitted.saturating_add(1);
        record_id
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:EVENT",
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

pub fn sponsor_bucket_id(
    sponsor_id: &str,
    bucket_commitment: &str,
    lane: SponsorshipLane,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:BUCKET-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(bucket_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn lane_policy_id(lane: SponsorshipLane, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:LANE-POLICY-ID",
        &[HashPart::Str(lane.as_str()), HashPart::U64(nonce)],
        32,
    )
}

pub fn wallet_cap_id(
    wallet_nullifier: &str,
    lane: SponsorshipLane,
    epoch: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:WALLET-CAP-ID",
        &[
            HashPart::Str(wallet_nullifier),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sponsor_risk_limit_id(sponsor_id: &str, lane: SponsorshipLane, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:RISK-LIMIT-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(lane.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_attestation_id(
    sponsor_id: &str,
    bucket_id: &str,
    purpose: AttestationPurpose,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:ATTESTATION-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(bucket_id),
            HashPart::Str(purpose.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn public_record_id(
    bucket_id: &str,
    wallet_cap_id: &str,
    lane: SponsorshipLane,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-MULTILANE-FEE-SPONSORSHIP:PUBLIC-RECORD-ID",
        &[
            HashPart::Str(bucket_id),
            HashPart::Str(wallet_cap_id),
            HashPart::Str(lane.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps).saturating_div(MAX_BPS)
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
