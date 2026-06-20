use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateJamtisRingMemberEntropyBalancerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_RING_MEMBER_ENTROPY_BALANCER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-ring-member-entropy-balancer-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_RING_MEMBER_ENTROPY_BALANCER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const JAMTIS_RING_MEMBER_ENTROPY_SCHEME: &str =
    "monero-jamtis-ring-member-entropy-balancer-root-v1";
pub const RING_COHORT_FLOOR_SCHEME: &str = "jamtis-ring-cohort-floor-root-v1";
pub const OUTPUT_AGE_BUCKET_SCHEME: &str = "monero-output-age-bucket-privacy-root-v1";
pub const DECOY_ENTROPY_BALANCING_SCHEME: &str = "decoy-entropy-balancing-snapshot-root-v1";
pub const PQ_AUDITOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-jamtis-ring-entropy-auditor-attestation-v1";
pub const WALLET_SCAN_HINT_SCHEME: &str = "view-key-safe-jamtis-wallet-scan-hint-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "jamtis-ring-member-entropy-redaction-budget-root-v1";
pub const LOW_FEE_BATCH_REBATE_SCHEME: &str = "low-fee-jamtis-ring-entropy-batch-rebate-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-jamtis-ring-member-entropy-balancer-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_ring_indices_decoy_graphs_or_jamtis_tags";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_140_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_880_000;
pub const DEVNET_EPOCH: u64 = 14_120;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 32;
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 65_536;
pub const DEFAULT_TARGET_COHORT_OUTPUTS: u64 = 262_144;
pub const DEFAULT_MIN_AGE_BUCKETS: u16 = 8;
pub const DEFAULT_TARGET_AGE_BUCKETS: u16 = 16;
pub const DEFAULT_MIN_ENTROPY_BPS: u64 = 8_400;
pub const DEFAULT_TARGET_ENTROPY_BPS: u64 = 9_250;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_HINT: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SCAN_HINT_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_AUDITOR_QUORUM_BPS: u64 = 6_700;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Draft,
    Open,
    Floored,
    Balanced,
    Attested,
    RebateEligible,
    Quarantined,
    Sealed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeBucketKind {
    Fresh,
    Warm,
    Mature,
    Deep,
    Archive,
    Canary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    Revoked,
    Expired,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_cohort_outputs: u64,
    pub target_cohort_outputs: u64,
    pub min_age_buckets: u16,
    pub target_age_buckets: u16,
    pub min_entropy_bps: u64,
    pub target_entropy_bps: u64,
    pub max_redaction_units_per_hint: u64,
    pub attestation_ttl_blocks: u64,
    pub scan_hint_ttl_blocks: u64,
    pub batch_rebate_bps: u64,
    pub max_user_fee_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub auditor_quorum_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            target_cohort_outputs: DEFAULT_TARGET_COHORT_OUTPUTS,
            min_age_buckets: DEFAULT_MIN_AGE_BUCKETS,
            target_age_buckets: DEFAULT_TARGET_AGE_BUCKETS,
            min_entropy_bps: DEFAULT_MIN_ENTROPY_BPS,
            target_entropy_bps: DEFAULT_TARGET_ENTROPY_BPS,
            max_redaction_units_per_hint: DEFAULT_MAX_REDACTION_UNITS_PER_HINT,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            scan_hint_ttl_blocks: DEFAULT_SCAN_HINT_TTL_BLOCKS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            auditor_quorum_bps: DEFAULT_AUDITOR_QUORUM_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub ring_cohorts: u64,
    pub output_age_buckets: u64,
    pub decoy_entropy_snapshots: u64,
    pub pq_auditor_attestations: u64,
    pub wallet_scan_hints: u64,
    pub privacy_redaction_budgets: u64,
    pub low_fee_batch_rebates: u64,
    pub quarantined_cohorts: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingCohortFloor {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub ring_size_floor: u16,
    pub output_floor: u64,
    pub entropy_floor_bps: u64,
    pub age_bucket_floor: u16,
    pub member_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputAgeBucket {
    pub bucket_id: String,
    pub kind: AgeBucketKind,
    pub min_confirmations: u64,
    pub max_confirmations: u64,
    pub public_output_count: u64,
    pub decoy_weight_bps: u64,
    pub bucket_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyEntropySnapshot {
    pub snapshot_id: String,
    pub cohort_id: String,
    pub balanced_entropy_bps: u64,
    pub bucket_spread_bps: u64,
    pub ring_member_sample_root: String,
    pub rebalance_plan_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuditorAttestation {
    pub attestation_id: String,
    pub auditor_committee_id: String,
    pub status: AttestationStatus,
    pub pq_security_bits: u16,
    pub expires_at_monero_height: u64,
    pub attestation_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub cohort_id: String,
    pub wallet_hint_root: String,
    pub output_age_bucket_root: String,
    pub expires_at_monero_height: u64,
    pub redaction_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub purpose: String,
    pub committed_units: u64,
    pub spent_units: u64,
    pub redaction_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_commitment_root: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub ring_cohort_floor_root: String,
    pub output_age_bucket_root: String,
    pub decoy_entropy_balancing_root: String,
    pub pq_auditor_attestation_root: String,
    pub wallet_scan_hint_root: String,
    pub privacy_redaction_budget_root: String,
    pub low_fee_batch_rebate_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub ring_cohort_floors: BTreeMap<String, RingCohortFloor>,
    pub output_age_buckets: BTreeMap<String, OutputAgeBucket>,
    pub decoy_entropy_snapshots: BTreeMap<String, DecoyEntropySnapshot>,
    pub pq_auditor_attestations: BTreeMap<String, PqAuditorAttestation>,
    pub wallet_scan_hints: BTreeMap<String, WalletScanHint>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub low_fee_batch_rebates: BTreeMap<String, LowFeeBatchRebate>,
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = compute_roots(self);
        self.counters = compute_counters(self);
    }
}

pub fn devnet() -> State {
    let mut state = State {
        protocol_version: PROTOCOL_VERSION.to_string(),
        schema_version: SCHEMA_VERSION,
        l2_height: DEVNET_L2_HEIGHT,
        monero_height: DEVNET_MONERO_HEIGHT,
        epoch: DEVNET_EPOCH,
        config: Config::devnet(),
        counters: Counters::default(),
        roots: Roots::default(),
        ring_cohort_floors: BTreeMap::new(),
        output_age_buckets: BTreeMap::new(),
        decoy_entropy_snapshots: BTreeMap::new(),
        pq_auditor_attestations: BTreeMap::new(),
        wallet_scan_hints: BTreeMap::new(),
        privacy_redaction_budgets: BTreeMap::new(),
        low_fee_batch_rebates: BTreeMap::new(),
    };

    insert_demo_fixtures(&mut state);
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": state.protocol_version,
        "schema_version": state.schema_version,
        "chain_id": state.config.chain_id,
        "l2_height": state.l2_height,
        "monero_height": state.monero_height,
        "epoch": state.epoch,
        "privacy_boundary": PRIVACY_BOUNDARY,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "state_root": state_root_without_public_root(state),
    })
}

pub fn state_root(state: &State) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-JAMTIS-RING-MEMBER-ENTROPY-BALANCER-STATE",
        &[HashPart::Json(&public_record(state))],
        32,
    )
}

fn insert_demo_fixtures(state: &mut State) {
    let cohort_root = deterministic_root("RING-COHORT-MEMBER-COMMITMENTS", "devnet-floor-001");
    state.ring_cohort_floors.insert(
        "jamtis-ring-floor-devnet-001".to_string(),
        RingCohortFloor {
            cohort_id: "jamtis-ring-floor-devnet-001".to_string(),
            status: CohortStatus::Attested,
            ring_size_floor: DEFAULT_MIN_RING_SIZE,
            output_floor: DEFAULT_TARGET_COHORT_OUTPUTS,
            entropy_floor_bps: DEFAULT_TARGET_ENTROPY_BPS,
            age_bucket_floor: DEFAULT_TARGET_AGE_BUCKETS,
            member_commitment_root: cohort_root,
        },
    );

    for (bucket_id, kind, min_confirmations, max_confirmations, weight) in [
        ("age-fresh-0000-0072", AgeBucketKind::Fresh, 0, 72, 1_150),
        ("age-warm-0073-0720", AgeBucketKind::Warm, 73, 720, 2_350),
        (
            "age-mature-0721-7200",
            AgeBucketKind::Mature,
            721,
            7_200,
            3_100,
        ),
        (
            "age-deep-7201-43200",
            AgeBucketKind::Deep,
            7_201,
            43_200,
            2_400,
        ),
        (
            "age-archive-43201-plus",
            AgeBucketKind::Archive,
            43_201,
            u64::MAX,
            1_000,
        ),
    ] {
        state.output_age_buckets.insert(
            bucket_id.to_string(),
            OutputAgeBucket {
                bucket_id: bucket_id.to_string(),
                kind,
                min_confirmations,
                max_confirmations,
                public_output_count: DEFAULT_MIN_COHORT_OUTPUTS,
                decoy_weight_bps: weight,
                bucket_root: deterministic_root("OUTPUT-AGE-BUCKET", bucket_id),
            },
        );
    }

    state.decoy_entropy_snapshots.insert(
        "decoy-entropy-devnet-001".to_string(),
        DecoyEntropySnapshot {
            snapshot_id: "decoy-entropy-devnet-001".to_string(),
            cohort_id: "jamtis-ring-floor-devnet-001".to_string(),
            balanced_entropy_bps: 9_318,
            bucket_spread_bps: 9_810,
            ring_member_sample_root: deterministic_root("RING-MEMBER-SAMPLE", "devnet-001"),
            rebalance_plan_root: deterministic_root("DECOY-REBALANCE-PLAN", "devnet-001"),
        },
    );

    state.pq_auditor_attestations.insert(
        "pq-auditor-attestation-devnet-001".to_string(),
        PqAuditorAttestation {
            attestation_id: "pq-auditor-attestation-devnet-001".to_string(),
            auditor_committee_id: "pq-auditors-devnet-alpha".to_string(),
            status: AttestationStatus::Quorum,
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
            attestation_root: deterministic_root("PQ-AUDITOR-ATTESTATION", "devnet-001"),
        },
    );

    state.wallet_scan_hints.insert(
        "wallet-scan-hint-devnet-001".to_string(),
        WalletScanHint {
            hint_id: "wallet-scan-hint-devnet-001".to_string(),
            cohort_id: "jamtis-ring-floor-devnet-001".to_string(),
            wallet_hint_root: deterministic_root("WALLET-SCAN-HINT", "devnet-001"),
            output_age_bucket_root: deterministic_root("WALLET-SCAN-AGE-BUCKETS", "devnet-001"),
            expires_at_monero_height: DEVNET_MONERO_HEIGHT + DEFAULT_SCAN_HINT_TTL_BLOCKS,
            redaction_units: 18,
        },
    );

    state.privacy_redaction_budgets.insert(
        "redaction-budget-devnet-001".to_string(),
        PrivacyRedactionBudget {
            budget_id: "redaction-budget-devnet-001".to_string(),
            purpose: "operator_safe_wallet_scan_hint_publication".to_string(),
            committed_units: 24,
            spent_units: 18,
            redaction_policy_root: deterministic_root("REDACTION-POLICY", "devnet-001"),
        },
    );

    state.low_fee_batch_rebates.insert(
        "low-fee-rebate-devnet-001".to_string(),
        LowFeeBatchRebate {
            rebate_id: "low-fee-rebate-devnet-001".to_string(),
            batch_id: "jamtis-ring-batch-devnet-001".to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            rebate_commitment_root: deterministic_root("LOW-FEE-BATCH-REBATE", "devnet-001"),
        },
    );
}

fn compute_counters(state: &State) -> Counters {
    Counters {
        ring_cohorts: state.ring_cohort_floors.len() as u64,
        output_age_buckets: state.output_age_buckets.len() as u64,
        decoy_entropy_snapshots: state.decoy_entropy_snapshots.len() as u64,
        pq_auditor_attestations: state.pq_auditor_attestations.len() as u64,
        wallet_scan_hints: state.wallet_scan_hints.len() as u64,
        privacy_redaction_budgets: state.privacy_redaction_budgets.len() as u64,
        low_fee_batch_rebates: state.low_fee_batch_rebates.len() as u64,
        quarantined_cohorts: state
            .ring_cohort_floors
            .values()
            .filter(|cohort| cohort.status == CohortStatus::Quarantined)
            .count() as u64,
    }
}

fn compute_roots(state: &State) -> Roots {
    let ring_cohort_floor_root =
        collection_root(RING_COHORT_FLOOR_SCHEME, &state.ring_cohort_floors);
    let output_age_bucket_root =
        collection_root(OUTPUT_AGE_BUCKET_SCHEME, &state.output_age_buckets);
    let decoy_entropy_balancing_root = collection_root(
        DECOY_ENTROPY_BALANCING_SCHEME,
        &state.decoy_entropy_snapshots,
    );
    let pq_auditor_attestation_root = collection_root(
        PQ_AUDITOR_ATTESTATION_SCHEME,
        &state.pq_auditor_attestations,
    );
    let wallet_scan_hint_root = collection_root(WALLET_SCAN_HINT_SCHEME, &state.wallet_scan_hints);
    let privacy_redaction_budget_root = collection_root(
        PRIVACY_REDACTION_BUDGET_SCHEME,
        &state.privacy_redaction_budgets,
    );
    let low_fee_batch_rebate_root =
        collection_root(LOW_FEE_BATCH_REBATE_SCHEME, &state.low_fee_batch_rebates);
    let public_record_root = domain_hash(
        PUBLIC_RECORD_SCHEME,
        &[HashPart::Json(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "ring_cohort_floor_root": ring_cohort_floor_root,
            "output_age_bucket_root": output_age_bucket_root,
            "decoy_entropy_balancing_root": decoy_entropy_balancing_root,
            "pq_auditor_attestation_root": pq_auditor_attestation_root,
            "wallet_scan_hint_root": wallet_scan_hint_root,
            "privacy_redaction_budget_root": privacy_redaction_budget_root,
            "low_fee_batch_rebate_root": low_fee_batch_rebate_root,
        }))],
        32,
    );

    Roots {
        ring_cohort_floor_root,
        output_age_bucket_root,
        decoy_entropy_balancing_root,
        pq_auditor_attestation_root,
        wallet_scan_hint_root,
        privacy_redaction_budget_root,
        low_fee_batch_rebate_root,
        public_record_root,
    }
}

fn collection_root<T>(domain: &str, entries: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let leaves = entries
        .iter()
        .map(|(id, entry)| {
            domain_hash(
                domain,
                &[HashPart::String(id.as_str()), HashPart::Json(&json!(entry))],
                32,
            )
        })
        .collect::<Vec<_>>();
    merkle_root(domain, leaves)
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::String(label)], 32)
}

fn state_root_without_public_root(state: &State) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-JAMTIS-RING-MEMBER-ENTROPY-BALANCER-COMMITMENT",
        &[HashPart::Json(&json!({
            "protocol_version": state.protocol_version,
            "schema_version": state.schema_version,
            "l2_height": state.l2_height,
            "monero_height": state.monero_height,
            "epoch": state.epoch,
            "counters": state.counters,
            "roots": state.roots,
        }))],
        32,
    )
}
