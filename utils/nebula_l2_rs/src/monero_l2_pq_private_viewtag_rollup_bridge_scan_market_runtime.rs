use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateViewtagRollupBridgeScanMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_ROLLUP_BRIDGE_SCAN_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-viewtag-rollup-bridge-scan-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_VIEWTAG_ROLLUP_BRIDGE_SCAN_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_442_880;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SCAN_PROVIDER_SCHEME: &str = "pq-private-viewtag-rollup-scan-provider-root-v1";
pub const ENCRYPTED_HINT_BATCH_SCHEME: &str = "ml-kem-1024-encrypted-viewtag-hint-batch-root-v1";
pub const SUBADDRESS_COHORT_SCHEME: &str = "private-subaddress-cohort-commitment-root-v1";
pub const DECOY_FLOOR_SCHEME: &str = "monero-ring-decoy-floor-policy-root-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-viewtag-bridge-scan-watcher-v1";
pub const MOBILE_ACCELERATION_SCHEME: &str = "mobile-viewtag-rollup-scan-acceleration-root-v1";
pub const SPONSORED_SCAN_SCHEME: &str = "low-fee-sponsored-private-bridge-scan-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "operator-safe-viewtag-scan-redaction-budget-root-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_FLOOR: u16 = 32;
pub const DEFAULT_TARGET_DECOY_FLOOR: u16 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_SCAN_FEE_MICRO_UNITS: u64 = 4_500;
pub const DEFAULT_LOW_FEE_SPONSOR_BPS: u16 = 9_250;
pub const DEFAULT_HINT_BATCH_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u32 = 24;
pub const MAX_BPS: u16 = 10_000;

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
pub enum ScanLane {
    BridgeDeposit,
    BridgeWithdrawal,
    WalletRestore,
    MerchantFastSync,
    WatchOnlyAudit,
    ReorgRepair,
}

impl ScanLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::WalletRestore => "wallet_restore",
            Self::MerchantFastSync => "merchant_fast_sync",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Attested,
    Sponsored,
    Delivered,
    Challenged,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Sponsored => "sponsored",
            Self::Delivered => "delivered",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    HintCompleteness,
    CohortCoverage,
    DecoyFloorSafety,
    MobileAcceleration,
    SponsoredFeeIntegrity,
    RedactionCompliance,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HintCompleteness => "hint_completeness",
            Self::CohortCoverage => "cohort_coverage",
            Self::DecoyFloorSafety => "decoy_floor_safety",
            Self::MobileAcceleration => "mobile_acceleration",
            Self::SponsoredFeeIntegrity => "sponsored_fee_integrity",
            Self::RedactionCompliance => "redaction_compliance",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub scan_provider_scheme: String,
    pub encrypted_hint_batch_scheme: String,
    pub subaddress_cohort_scheme: String,
    pub decoy_floor_scheme: String,
    pub watcher_attestation_scheme: String,
    pub mobile_acceleration_scheme: String,
    pub sponsored_scan_scheme: String,
    pub redaction_budget_scheme: String,
    pub min_privacy_set_size: u64,
    pub min_decoy_floor: u16,
    pub target_decoy_floor: u16,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_scan_fee_micro_units: u64,
    pub low_fee_sponsor_bps: u16,
    pub hint_batch_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub redaction_budget_per_epoch: u32,
    pub allow_mobile_acceleration: bool,
    pub allow_low_fee_sponsorship: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            hash_suite: HASH_SUITE.to_string(),
            scan_provider_scheme: SCAN_PROVIDER_SCHEME.to_string(),
            encrypted_hint_batch_scheme: ENCRYPTED_HINT_BATCH_SCHEME.to_string(),
            subaddress_cohort_scheme: SUBADDRESS_COHORT_SCHEME.to_string(),
            decoy_floor_scheme: DECOY_FLOOR_SCHEME.to_string(),
            watcher_attestation_scheme: WATCHER_ATTESTATION_SCHEME.to_string(),
            mobile_acceleration_scheme: MOBILE_ACCELERATION_SCHEME.to_string(),
            sponsored_scan_scheme: SPONSORED_SCAN_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_decoy_floor: DEFAULT_MIN_DECOY_FLOOR,
            target_decoy_floor: DEFAULT_TARGET_DECOY_FLOOR,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_scan_fee_micro_units: DEFAULT_MAX_SCAN_FEE_MICRO_UNITS,
            low_fee_sponsor_bps: DEFAULT_LOW_FEE_SPONSOR_BPS,
            hint_batch_ttl_blocks: DEFAULT_HINT_BATCH_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            allow_mobile_acceleration: true,
            allow_low_fee_sponsorship: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "scan_provider_scheme": self.scan_provider_scheme,
            "encrypted_hint_batch_scheme": self.encrypted_hint_batch_scheme,
            "subaddress_cohort_scheme": self.subaddress_cohort_scheme,
            "decoy_floor_scheme": self.decoy_floor_scheme,
            "watcher_attestation_scheme": self.watcher_attestation_scheme,
            "mobile_acceleration_scheme": self.mobile_acceleration_scheme,
            "sponsored_scan_scheme": self.sponsored_scan_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_decoy_floor": self.min_decoy_floor,
            "target_decoy_floor": self.target_decoy_floor,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_scan_fee_micro_units": self.max_scan_fee_micro_units,
            "low_fee_sponsor_bps": self.low_fee_sponsor_bps,
            "hint_batch_ttl_blocks": self.hint_batch_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "redaction_budget_per_epoch": self.redaction_budget_per_epoch,
            "allow_mobile_acceleration": self.allow_mobile_acceleration,
            "allow_low_fee_sponsorship": self.allow_low_fee_sponsorship,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub scan_providers: u64,
    pub encrypted_hint_batches: u64,
    pub subaddress_cohorts: u64,
    pub decoy_floors: u64,
    pub watcher_attestations: u64,
    pub mobile_accelerations: u64,
    pub sponsored_scans: u64,
    pub redaction_budgets: u64,
    pub delivered_batches: u64,
    pub public_records: u64,
    pub sponsored_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_providers": self.scan_providers,
            "encrypted_hint_batches": self.encrypted_hint_batches,
            "subaddress_cohorts": self.subaddress_cohorts,
            "decoy_floors": self.decoy_floors,
            "watcher_attestations": self.watcher_attestations,
            "mobile_accelerations": self.mobile_accelerations,
            "sponsored_scans": self.sponsored_scans,
            "redaction_budgets": self.redaction_budgets,
            "delivered_batches": self.delivered_batches,
            "public_records": self.public_records,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub scan_provider_root: String,
    pub encrypted_hint_batch_root: String,
    pub subaddress_cohort_root: String,
    pub decoy_floor_root: String,
    pub watcher_attestation_root: String,
    pub mobile_acceleration_root: String,
    pub sponsored_scan_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanProvider {
    pub provider_id: String,
    pub operator_commitment: String,
    pub endpoint_commitment: String,
    pub bond_micro_units: u64,
    pub supported_lanes: BTreeSet<ScanLane>,
    pub max_batch_outputs: u32,
    pub pq_security_bits: u16,
    pub status: ProviderStatus,
}

impl ScanProvider {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "operator_commitment": self.operator_commitment,
            "endpoint_commitment": self.endpoint_commitment,
            "bond_micro_units": self.bond_micro_units,
            "supported_lanes": self.supported_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "max_batch_outputs": self.max_batch_outputs,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedHintBatch {
    pub batch_id: String,
    pub provider_id: String,
    pub lane: ScanLane,
    pub bridge_note_root: String,
    pub viewtag_rollup_root: String,
    pub encrypted_hint_root: String,
    pub cohort_id: String,
    pub output_count: u32,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub fee_micro_units: u64,
    pub expires_height: u64,
    pub status: BatchStatus,
    pub watcher_ids: BTreeSet<String>,
}

impl EncryptedHintBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "provider_id": self.provider_id,
            "lane": self.lane.as_str(),
            "bridge_note_root": self.bridge_note_root,
            "viewtag_rollup_root": self.viewtag_rollup_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "cohort_id": self.cohort_id,
            "output_count": self.output_count,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "fee_micro_units": self.fee_micro_units,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "watcher_ids": self.watcher_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressCohort {
    pub cohort_id: String,
    pub wallet_group_commitment: String,
    pub subaddress_range_commitment: String,
    pub bloom_filter_root: String,
    pub cohort_size: u32,
    pub privacy_set_size: u64,
    pub redaction_class: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFloor {
    pub floor_id: String,
    pub lane: ScanLane,
    pub min_decoys: u16,
    pub target_decoys: u16,
    pub entropy_floor_bps: u16,
    pub applies_from_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub watcher_commitment: String,
    pub kind: AttestationKind,
    pub coverage_root: String,
    pub attested_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MobileAcceleration {
    pub acceleration_id: String,
    pub batch_id: String,
    pub device_class_commitment: String,
    pub compact_index_root: String,
    pub compressed_bytes: u32,
    pub estimated_scan_ms: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredScan {
    pub sponsor_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub covered_fee_micro_units: u64,
    pub wallet_fee_micro_units: u64,
    pub sponsor_bps: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub epoch: u64,
    pub allowance: u32,
    pub spent: u32,
    pub public_reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub scan_providers: BTreeMap<String, ScanProvider>,
    pub encrypted_hint_batches: BTreeMap<String, EncryptedHintBatch>,
    pub subaddress_cohorts: BTreeMap<String, SubaddressCohort>,
    pub decoy_floors: BTreeMap<String, DecoyFloor>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub mobile_accelerations: BTreeMap<String, MobileAcceleration>,
    pub sponsored_scans: BTreeMap<String, SponsoredScan>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            scan_providers: BTreeMap::new(),
            encrypted_hint_batches: BTreeMap::new(),
            subaddress_cohorts: BTreeMap::new(),
            decoy_floors: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            mobile_accelerations: BTreeMap::new(),
            sponsored_scans: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: Vec::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.seed("alpha", ScanLane::BridgeDeposit);
        state.seed("merchant", ScanLane::MerchantFastSync);
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.seed("restore", ScanLane::WalletRestore);
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            scan_providers: self.scan_providers.len() as u64,
            encrypted_hint_batches: self.encrypted_hint_batches.len() as u64,
            subaddress_cohorts: self.subaddress_cohorts.len() as u64,
            decoy_floors: self.decoy_floors.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            mobile_accelerations: self.mobile_accelerations.len() as u64,
            sponsored_scans: self.sponsored_scans.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            delivered_batches: self
                .encrypted_hint_batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Delivered)
                .count() as u64,
            public_records: self.public_records.len() as u64,
            sponsored_fee_micro_units: self
                .sponsored_scans
                .values()
                .map(|scan| scan.covered_fee_micro_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: value_root("config", &self.config.public_record()),
            counters_root: value_root("counters", &counters.public_record()),
            scan_provider_root: map_root("scan-providers", &self.scan_providers),
            encrypted_hint_batch_root: map_root(
                "encrypted-hint-batches",
                &self.encrypted_hint_batches,
            ),
            subaddress_cohort_root: map_root("subaddress-cohorts", &self.subaddress_cohorts),
            decoy_floor_root: map_root("decoy-floors", &self.decoy_floors),
            watcher_attestation_root: map_root("watcher-attestations", &self.watcher_attestations),
            mobile_acceleration_root: map_root("mobile-accelerations", &self.mobile_accelerations),
            sponsored_scan_root: map_root("sponsored-scans", &self.sponsored_scans),
            redaction_budget_root: map_root("redaction-budgets", &self.redaction_budgets),
            public_record_root: merkle_root(
                "viewtag-rollup-bridge-scan-market:public-records",
                &self.public_records,
            ),
            state_root: String::new(),
        };
        roots.state_root = value_root(
            "state",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.height,
                "epoch": self.epoch,
                "config_root": roots.config_root,
                "counters_root": roots.counters_root,
                "scan_provider_root": roots.scan_provider_root,
                "encrypted_hint_batch_root": roots.encrypted_hint_batch_root,
                "subaddress_cohort_root": roots.subaddress_cohort_root,
                "decoy_floor_root": roots.decoy_floor_root,
                "watcher_attestation_root": roots.watcher_attestation_root,
                "mobile_acceleration_root": roots.mobile_acceleration_root,
                "sponsored_scan_root": roots.sponsored_scan_root,
                "redaction_budget_root": roots.redaction_budget_root,
                "public_record_root": roots.public_record_root,
            }),
        );
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "operator_safe_summary": self.operator_safe_summary(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn register_provider(
        &mut self,
        operator_commitment: impl Into<String>,
        endpoint_commitment: impl Into<String>,
        supported_lanes: BTreeSet<ScanLane>,
    ) -> Result<String> {
        let operator_commitment = operator_commitment.into();
        let endpoint_commitment = endpoint_commitment.into();
        require_nonempty("operator_commitment", &operator_commitment)?;
        require_nonempty("endpoint_commitment", &endpoint_commitment)?;
        if supported_lanes.is_empty() {
            return Err("provider must support at least one scan lane".to_string());
        }
        let provider_id = id(
            "provider",
            json!([operator_commitment, endpoint_commitment]),
        );
        let provider = ScanProvider {
            provider_id: provider_id.clone(),
            operator_commitment,
            endpoint_commitment,
            bond_micro_units: 75_000_000,
            supported_lanes,
            max_batch_outputs: 16_384,
            pq_security_bits: self.config.target_pq_security_bits,
            status: ProviderStatus::Active,
        };
        self.scan_providers.insert(provider_id.clone(), provider);
        Ok(provider_id)
    }

    fn submit_batch(
        &mut self,
        provider_id: &str,
        cohort_id: &str,
        lane: ScanLane,
        label: &str,
    ) -> Result<String> {
        let provider = self
            .scan_providers
            .get(provider_id)
            .ok_or_else(|| "unknown scan provider".to_string())?;
        if !provider.supported_lanes.contains(&lane) {
            return Err("provider does not support requested scan lane".to_string());
        }
        if !self.subaddress_cohorts.contains_key(cohort_id) {
            return Err("unknown subaddress cohort".to_string());
        }
        let fee_micro_units = lane_fee_cap(lane).min(self.config.max_scan_fee_micro_units);
        let batch_id = id(
            "hint-batch",
            json!([provider_id, cohort_id, lane.as_str(), label]),
        );
        let batch = EncryptedHintBatch {
            batch_id: batch_id.clone(),
            provider_id: provider_id.to_string(),
            lane,
            bridge_note_root: devnet_payload_root("bridge-note-root", label),
            viewtag_rollup_root: devnet_payload_root("viewtag-rollup", label),
            encrypted_hint_root: devnet_payload_root("encrypted-hints", label),
            cohort_id: cohort_id.to_string(),
            output_count: 8_192,
            monero_start_height: self.height - 360,
            monero_end_height: self.height,
            fee_micro_units,
            expires_height: self.height + self.config.hint_batch_ttl_blocks,
            status: BatchStatus::Delivered,
            watcher_ids: BTreeSet::new(),
        };
        self.encrypted_hint_batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    fn seed(&mut self, label: &str, lane: ScanLane) {
        let mut lanes = BTreeSet::new();
        lanes.insert(lane);
        lanes.insert(ScanLane::ReorgRepair);
        let provider_id = self
            .register_provider(
                devnet_payload_root("operator", label),
                devnet_payload_root("endpoint", label),
                lanes,
            )
            .expect("devnet scan provider");
        let cohort_id = id("cohort", json!([label, "subaddresses"]));
        self.subaddress_cohorts.insert(
            cohort_id.clone(),
            SubaddressCohort {
                cohort_id: cohort_id.clone(),
                wallet_group_commitment: devnet_payload_root("wallet-group", label),
                subaddress_range_commitment: devnet_payload_root("subaddress-range", label),
                bloom_filter_root: devnet_payload_root("subaddress-bloom", label),
                cohort_size: 512,
                privacy_set_size: 131_072,
                redaction_class: "cohort_aggregate_only".to_string(),
            },
        );
        let floor_id = id("decoy-floor", json!([label, lane.as_str()]));
        self.decoy_floors.insert(
            floor_id.clone(),
            DecoyFloor {
                floor_id,
                lane,
                min_decoys: self.config.min_decoy_floor,
                target_decoys: self.config.target_decoy_floor,
                entropy_floor_bps: 8_800,
                applies_from_height: self.height,
            },
        );
        let batch_id = self
            .submit_batch(&provider_id, &cohort_id, lane, label)
            .expect("devnet hint batch");
        for kind in [
            AttestationKind::HintCompleteness,
            AttestationKind::CohortCoverage,
            AttestationKind::DecoyFloorSafety,
        ] {
            let attestation_id = id("attestation", json!([batch_id, kind.as_str()]));
            self.watcher_attestations.insert(
                attestation_id.clone(),
                WatcherAttestation {
                    attestation_id: attestation_id.clone(),
                    batch_id: batch_id.clone(),
                    watcher_commitment: devnet_payload_root("watcher", kind.as_str()),
                    kind,
                    coverage_root: devnet_payload_root("coverage", label),
                    attested_height: self.height,
                    expires_height: self.height + self.config.attestation_ttl_blocks,
                },
            );
            self.encrypted_hint_batches
                .get_mut(&batch_id)
                .expect("seeded batch")
                .watcher_ids
                .insert(attestation_id);
        }
        let acceleration_id = id("mobile-acceleration", json!([batch_id, label]));
        self.mobile_accelerations.insert(
            acceleration_id.clone(),
            MobileAcceleration {
                acceleration_id,
                batch_id: batch_id.clone(),
                device_class_commitment: devnet_payload_root("mobile-device-class", label),
                compact_index_root: devnet_payload_root("compact-index", label),
                compressed_bytes: 192_000,
                estimated_scan_ms: 480,
            },
        );
        let sponsored_fee =
            lane_fee_cap(lane) * u64::from(self.config.low_fee_sponsor_bps) / u64::from(MAX_BPS);
        let sponsor_id = id("sponsored-scan", json!([batch_id, label]));
        self.sponsored_scans.insert(
            sponsor_id.clone(),
            SponsoredScan {
                sponsor_id,
                batch_id: batch_id.clone(),
                sponsor_commitment: devnet_payload_root("fee-sponsor", label),
                covered_fee_micro_units: sponsored_fee,
                wallet_fee_micro_units: lane_fee_cap(lane) - sponsored_fee,
                sponsor_bps: self.config.low_fee_sponsor_bps,
            },
        );
        let budget_id = id("redaction-budget", json!([cohort_id, self.epoch]));
        self.redaction_budgets.insert(
            budget_id.clone(),
            RedactionBudget {
                budget_id,
                subject_id: cohort_id,
                epoch: self.epoch,
                allowance: self.config.redaction_budget_per_epoch,
                spent: 3,
                public_reason: "operator_support_without_hint_plaintext".to_string(),
            },
        );
        self.public_records.push(json!({
            "kind": "viewtag_rollup_bridge_scan_batch",
            "batch_id": batch_id,
            "provider_id": provider_id,
            "lane": lane.as_str(),
            "status": "delivered",
        }));
    }

    fn operator_safe_summary(&self) -> Value {
        json!({
            "active_providers": self.scan_providers.values().filter(|provider| provider.status == ProviderStatus::Active).count(),
            "delivered_batches": self.encrypted_hint_batches.values().filter(|batch| batch.status == BatchStatus::Delivered).count(),
            "min_decoy_floor": self.decoy_floors.values().map(|floor| floor.min_decoys).min().unwrap_or(0),
            "max_scan_fee_micro_units": self.encrypted_hint_batches.values().map(|batch| batch.fee_micro_units).max().unwrap_or(0),
            "mobile_acceleration_records": self.mobile_accelerations.len(),
            "redaction_budget_spent": self.redaction_budgets.values().map(|budget| budget.spent).sum::<u32>(),
            "plaintext_hints_exposed": false,
        })
    }
}

pub fn devnet_payload_root(kind: &str, label: &str) -> String {
    value_root(
        "devnet-payload",
        &json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "kind": kind,
            "label": label,
            "height": DEVNET_HEIGHT,
            "epoch": DEVNET_EPOCH,
        }),
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn lane_fee_cap(lane: ScanLane) -> u64 {
    match lane {
        ScanLane::BridgeDeposit => 2_200,
        ScanLane::BridgeWithdrawal => 3_600,
        ScanLane::WalletRestore => 1_800,
        ScanLane::MerchantFastSync => 1_200,
        ScanLane::WatchOnlyAudit => 2_800,
        ScanLane::ReorgRepair => 4_000,
    }
}

fn require_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn id(kind: &str, value: Value) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-rollup-bridge-scan-market:id",
        &[HashPart::Str(kind), HashPart::Json(&value)],
        32,
    )
}

fn value_root(kind: &str, value: &Value) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-rollup-bridge-scan-market:root",
        &[HashPart::Str(kind), HashPart::Json(value)],
        32,
    )
}

fn map_root<T: Serialize>(kind: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-private-viewtag-rollup-bridge-scan-market:{kind}"),
        &leaves,
    )
}
