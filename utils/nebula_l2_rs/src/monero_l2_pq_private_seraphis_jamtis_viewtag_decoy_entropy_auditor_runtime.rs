use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisJamtisViewtagDecoyEntropyAuditorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_VIEWTAG_DECOY_ENTROPY_AUDITOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-seraphis-jamtis-viewtag-decoy-entropy-auditor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_JAMTIS_VIEWTAG_DECOY_ENTROPY_AUDITOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_654_320;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VIEWTAG_COHORT_SCHEME: &str = "seraphis-jamtis-viewtag-cohort-root-v1";
pub const DECOY_ENTROPY_SCHEME: &str = "seraphis-jamtis-decoy-entropy-audit-root-v1";
pub const RING_OUTPUT_BUCKET_SCHEME: &str = "ring-output-entropy-bucket-root-v1";
pub const PQ_AUDITOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-viewtag-decoy-entropy-auditor-v1";
pub const WALLET_SCAN_HINT_SCHEME: &str = "wallet-safe-viewtag-scan-hint-root-v1";
pub const DECOY_FRESHNESS_SCHEME: &str = "decoy-freshness-score-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "privacy-redaction-budget-roots-only-no-addresses-amounts-key-images-v1";
pub const PUBLIC_ROOT_SCHEME: &str = "public-viewtag-decoy-entropy-auditor-roots-v1";
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 512;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_MIN_ENTROPY_BPS: u64 = 8_400;
pub const DEFAULT_MIN_FRESHNESS_BPS: u64 = 7_500;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTION_UNITS: u64 = 4_096;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLane {
    WalletScan,
    BridgeWithdrawal,
    MerchantReceive,
    DexSettlement,
    Watchtower,
    ReorgRepair,
}

impl AuditLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantReceive => "merchant_receive",
            Self::DexSettlement => "dex_settlement",
            Self::Watchtower => "watchtower",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Draft,
    Open,
    Bucketed,
    Scored,
    Attested,
    HintIssued,
    Redacted,
    Quarantined,
    Expired,
    Rejected,
}

impl AuditStatus {
    pub fn public(self) -> bool {
        matches!(
            self,
            Self::Bucketed | Self::Scored | Self::Attested | Self::HintIssued | Self::Redacted
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub hash_suite: String,
    pub viewtag_cohort_scheme: String,
    pub decoy_entropy_scheme: String,
    pub ring_output_bucket_scheme: String,
    pub pq_auditor_attestation_scheme: String,
    pub wallet_scan_hint_scheme: String,
    pub decoy_freshness_scheme: String,
    pub redaction_budget_scheme: String,
    pub public_root_scheme: String,
    pub min_cohort_outputs: u64,
    pub min_ring_size: u16,
    pub min_entropy_bps: u64,
    pub min_freshness_bps: u64,
    pub target_pq_security_bits: u16,
    pub attestation_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_redaction_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            viewtag_cohort_scheme: VIEWTAG_COHORT_SCHEME.to_string(),
            decoy_entropy_scheme: DECOY_ENTROPY_SCHEME.to_string(),
            ring_output_bucket_scheme: RING_OUTPUT_BUCKET_SCHEME.to_string(),
            pq_auditor_attestation_scheme: PQ_AUDITOR_ATTESTATION_SCHEME.to_string(),
            wallet_scan_hint_scheme: WALLET_SCAN_HINT_SCHEME.to_string(),
            decoy_freshness_scheme: DECOY_FRESHNESS_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            public_root_scheme: PUBLIC_ROOT_SCHEME.to_string(),
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_entropy_bps: DEFAULT_MIN_ENTROPY_BPS,
            min_freshness_bps: DEFAULT_MIN_FRESHNESS_BPS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_redaction_units: DEFAULT_MAX_REDACTION_UNITS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "hash_suite": self.hash_suite,
            "viewtag_cohort_scheme": self.viewtag_cohort_scheme,
            "decoy_entropy_scheme": self.decoy_entropy_scheme,
            "ring_output_bucket_scheme": self.ring_output_bucket_scheme,
            "pq_auditor_attestation_scheme": self.pq_auditor_attestation_scheme,
            "wallet_scan_hint_scheme": self.wallet_scan_hint_scheme,
            "decoy_freshness_scheme": self.decoy_freshness_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "public_root_scheme": self.public_root_scheme,
            "min_cohort_outputs": self.min_cohort_outputs,
            "min_ring_size": self.min_ring_size,
            "min_entropy_bps": self.min_entropy_bps,
            "min_freshness_bps": self.min_freshness_bps,
            "target_pq_security_bits": self.target_pq_security_bits,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_redaction_units": self.max_redaction_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub viewtag_cohorts: u64,
    pub decoy_entropy_audits: u64,
    pub ring_output_buckets: u64,
    pub pq_auditor_attestations: u64,
    pub wallet_scan_hints: u64,
    pub freshness_scores: u64,
    pub redaction_budgets: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "viewtag_cohorts": self.viewtag_cohorts,
            "decoy_entropy_audits": self.decoy_entropy_audits,
            "ring_output_buckets": self.ring_output_buckets,
            "pq_auditor_attestations": self.pq_auditor_attestations,
            "wallet_scan_hints": self.wallet_scan_hints,
            "freshness_scores": self.freshness_scores,
            "redaction_budgets": self.redaction_budgets,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub viewtag_cohort_root: String,
    pub decoy_entropy_audit_root: String,
    pub ring_output_bucket_root: String,
    pub pq_auditor_attestation_root: String,
    pub wallet_scan_hint_root: String,
    pub freshness_score_root: String,
    pub redaction_budget_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "viewtag_cohort_root": self.viewtag_cohort_root,
            "decoy_entropy_audit_root": self.decoy_entropy_audit_root,
            "ring_output_bucket_root": self.ring_output_bucket_root,
            "pq_auditor_attestation_root": self.pq_auditor_attestation_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "freshness_score_root": self.freshness_score_root,
            "redaction_budget_root": self.redaction_budget_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewtagCohort {
    pub cohort_id: String,
    pub lane: AuditLane,
    pub status: AuditStatus,
    pub opened_height: u64,
    pub close_height: u64,
    pub output_count: u64,
    pub viewtag_bucket_root: String,
    pub jamtis_address_set_root: String,
    pub seraphis_membership_root: String,
    pub public_root: String,
}

impl ViewtagCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "opened_height": self.opened_height,
            "close_height": self.close_height,
            "output_count": self.output_count,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "jamtis_address_set_root": self.jamtis_address_set_root,
            "seraphis_membership_root": self.seraphis_membership_root,
            "public_root": self.public_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyEntropyAudit {
    pub audit_id: String,
    pub cohort_id: String,
    pub status: AuditStatus,
    pub ring_size: u16,
    pub output_count: u64,
    pub entropy_bps: u64,
    pub freshness_bps: u64,
    pub ring_member_root: String,
    pub output_age_histogram_root: String,
    pub decoy_selection_root: String,
    pub audit_root: String,
}

impl DecoyEntropyAudit {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "ring_size": self.ring_size,
            "output_count": self.output_count,
            "entropy_bps": self.entropy_bps,
            "freshness_bps": self.freshness_bps,
            "ring_member_root": self.ring_member_root,
            "output_age_histogram_root": self.output_age_histogram_root,
            "decoy_selection_root": self.decoy_selection_root,
            "audit_root": self.audit_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingOutputEntropyBucket {
    pub bucket_id: String,
    pub cohort_id: String,
    pub lower_entropy_bps: u64,
    pub upper_entropy_bps: u64,
    pub output_count: u64,
    pub median_age_blocks: u64,
    pub bucket_root: String,
}

impl RingOutputEntropyBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "cohort_id": self.cohort_id,
            "lower_entropy_bps": self.lower_entropy_bps,
            "upper_entropy_bps": self.upper_entropy_bps,
            "output_count": self.output_count,
            "median_age_blocks": self.median_age_blocks,
            "bucket_root": self.bucket_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuditorAttestation {
    pub attestation_id: String,
    pub audit_id: String,
    pub auditor_set_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub expires_at_height: u64,
    pub accepted: bool,
    pub attestation_root: String,
}

impl PqAuditorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "audit_id": self.audit_id,
            "auditor_set_root": self.auditor_set_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "expires_at_height": self.expires_at_height,
            "accepted": self.accepted,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub cohort_id: String,
    pub hint_bucket_root: String,
    pub redacted_viewtag_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
    pub expires_at_height: u64,
    pub hint_root: String,
}

impl WalletScanHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "cohort_id": self.cohort_id,
            "hint_bucket_root": self.hint_bucket_root,
            "redacted_viewtag_root": self.redacted_viewtag_root,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
            "expires_at_height": self.expires_at_height,
            "hint_root": self.hint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFreshnessScore {
    pub score_id: String,
    pub audit_id: String,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
    pub freshness_bps: u64,
    pub score_root: String,
}

impl DecoyFreshnessScore {
    pub fn public_record(&self) -> Value {
        json!({
            "score_id": self.score_id,
            "audit_id": self.audit_id,
            "median_age_blocks": self.median_age_blocks,
            "p95_age_blocks": self.p95_age_blocks,
            "freshness_bps": self.freshness_bps,
            "score_root": self.score_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub cohort_id: String,
    pub epoch: u64,
    pub allowed_units: u64,
    pub spent_units: u64,
    pub redacted_fields_root: String,
    pub budget_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "cohort_id": self.cohort_id,
            "epoch": self.epoch,
            "allowed_units": self.allowed_units,
            "spent_units": self.spent_units,
            "redacted_fields_root": self.redacted_fields_root,
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub viewtag_cohorts: BTreeMap<String, ViewtagCohort>,
    pub decoy_entropy_audits: BTreeMap<String, DecoyEntropyAudit>,
    pub ring_output_buckets: BTreeMap<String, RingOutputEntropyBucket>,
    pub pq_auditor_attestations: BTreeMap<String, PqAuditorAttestation>,
    pub wallet_scan_hints: BTreeMap<String, WalletScanHint>,
    pub freshness_scores: BTreeMap<String, DecoyFreshnessScore>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            viewtag_cohorts: BTreeMap::new(),
            decoy_entropy_audits: BTreeMap::new(),
            ring_output_buckets: BTreeMap::new(),
            pq_auditor_attestations: BTreeMap::new(),
            wallet_scan_hints: BTreeMap::new(),
            freshness_scores: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        seed_devnet(&mut state);
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn open_viewtag_cohort(
        &mut self,
        lane: AuditLane,
        output_count: u64,
        label: impl AsRef<str>,
    ) -> Result<String> {
        if output_count < self.config.min_cohort_outputs {
            return Err("viewtag cohort output count below privacy floor".to_string());
        }
        let label = label.as_ref();
        let cohort_id = deterministic_id(
            "VIEWTAG-COHORT",
            &[
                HashPart::U64(self.counters.viewtag_cohorts + 1),
                HashPart::Str(lane.as_str()),
                HashPart::Str(label),
            ],
        );
        let mut cohort = ViewtagCohort {
            cohort_id: cohort_id.clone(),
            lane,
            status: AuditStatus::Open,
            opened_height: self.current_height,
            close_height: self.current_height + self.config.attestation_ttl_blocks,
            output_count,
            viewtag_bucket_root: deterministic_root("viewtag_bucket", label),
            jamtis_address_set_root: deterministic_root("jamtis_address_set", label),
            seraphis_membership_root: deterministic_root("seraphis_membership", label),
            public_root: String::new(),
        };
        cohort.public_root = value_root("VIEWTAG-COHORT", &cohort.public_record());
        self.viewtag_cohorts.insert(cohort_id.clone(), cohort);
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn audit_decoy_entropy(
        &mut self,
        cohort_id: impl AsRef<str>,
        ring_size: u16,
        median_age_blocks: u64,
        p95_age_blocks: u64,
    ) -> Result<String> {
        let cohort_id = cohort_id.as_ref();
        let cohort = self
            .viewtag_cohorts
            .get(cohort_id)
            .ok_or_else(|| "unknown viewtag cohort".to_string())?;
        if ring_size < self.config.min_ring_size {
            return Err("ring size below privacy floor".to_string());
        }

        let entropy_bps = entropy_score(ring_size, cohort.output_count);
        let freshness_bps = freshness_score(median_age_blocks, p95_age_blocks);
        let status = if entropy_bps >= self.config.min_entropy_bps
            && freshness_bps >= self.config.min_freshness_bps
        {
            AuditStatus::Scored
        } else {
            AuditStatus::Quarantined
        };
        let audit_id = deterministic_id(
            "DECOY-ENTROPY-AUDIT",
            &[
                HashPart::U64(self.counters.decoy_entropy_audits + 1),
                HashPart::Str(cohort_id),
                HashPart::U64(ring_size as u64),
            ],
        );
        let mut audit = DecoyEntropyAudit {
            audit_id: audit_id.clone(),
            cohort_id: cohort_id.to_string(),
            status,
            ring_size,
            output_count: cohort.output_count,
            entropy_bps,
            freshness_bps,
            ring_member_root: deterministic_root("ring_members", &audit_id),
            output_age_histogram_root: deterministic_root("output_age_histogram", &audit_id),
            decoy_selection_root: deterministic_root("decoy_selection", &audit_id),
            audit_root: String::new(),
        };
        audit.audit_root = value_root("DECOY-ENTROPY-AUDIT", &audit.public_record());
        self.decoy_entropy_audits.insert(audit_id.clone(), audit);
        self.record_freshness_score(&audit_id, median_age_blocks, p95_age_blocks)?;
        self.refresh_roots();
        Ok(audit_id)
    }

    pub fn attest_audit(
        &mut self,
        audit_id: impl AsRef<str>,
        auditor_label: impl AsRef<str>,
        pq_security_bits: u16,
    ) -> Result<String> {
        let audit_id = audit_id.as_ref();
        if !self.decoy_entropy_audits.contains_key(audit_id) {
            return Err("unknown decoy entropy audit".to_string());
        }
        if pq_security_bits < self.config.target_pq_security_bits {
            return Err("PQ auditor attestation below security target".to_string());
        }
        let auditor_label = auditor_label.as_ref();
        let attestation_id = deterministic_id(
            "PQ-AUDITOR-ATTESTATION",
            &[
                HashPart::U64(self.counters.pq_auditor_attestations + 1),
                HashPart::Str(audit_id),
                HashPart::Str(auditor_label),
            ],
        );
        let mut attestation = PqAuditorAttestation {
            attestation_id: attestation_id.clone(),
            audit_id: audit_id.to_string(),
            auditor_set_root: deterministic_root("auditor_set", auditor_label),
            pq_signature_root: deterministic_root("pq_signature", &attestation_id),
            transcript_root: deterministic_root("auditor_transcript", &attestation_id),
            pq_security_bits,
            expires_at_height: self.current_height + self.config.attestation_ttl_blocks,
            accepted: true,
            attestation_root: String::new(),
        };
        attestation.attestation_root =
            value_root("PQ-AUDITOR-ATTESTATION", &attestation.public_record());
        self.pq_auditor_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn issue_wallet_scan_hint(
        &mut self,
        cohort_id: impl AsRef<str>,
        scan_window_start: u64,
        scan_window_end: u64,
    ) -> Result<String> {
        let cohort_id = cohort_id.as_ref();
        if !self.viewtag_cohorts.contains_key(cohort_id) {
            return Err("unknown viewtag cohort".to_string());
        }
        if scan_window_end <= scan_window_start {
            return Err("wallet scan hint window is empty".to_string());
        }
        let hint_id = deterministic_id(
            "WALLET-SCAN-HINT",
            &[
                HashPart::U64(self.counters.wallet_scan_hints + 1),
                HashPart::Str(cohort_id),
                HashPart::U64(scan_window_start),
                HashPart::U64(scan_window_end),
            ],
        );
        let mut hint = WalletScanHint {
            hint_id: hint_id.clone(),
            cohort_id: cohort_id.to_string(),
            hint_bucket_root: deterministic_root("wallet_hint_bucket", &hint_id),
            redacted_viewtag_root: deterministic_root("redacted_viewtag", &hint_id),
            scan_window_start,
            scan_window_end,
            expires_at_height: self.current_height + self.config.hint_ttl_blocks,
            hint_root: String::new(),
        };
        hint.hint_root = value_root("WALLET-SCAN-HINT", &hint.public_record());
        self.wallet_scan_hints.insert(hint_id.clone(), hint);
        self.refresh_roots();
        Ok(hint_id)
    }

    pub fn record_ring_output_bucket(
        &mut self,
        cohort_id: impl AsRef<str>,
        lower_entropy_bps: u64,
        upper_entropy_bps: u64,
        output_count: u64,
        median_age_blocks: u64,
    ) -> Result<String> {
        let cohort_id = cohort_id.as_ref();
        if !self.viewtag_cohorts.contains_key(cohort_id) {
            return Err("unknown viewtag cohort".to_string());
        }
        if lower_entropy_bps > upper_entropy_bps || upper_entropy_bps > MAX_BPS {
            return Err("invalid entropy bucket bounds".to_string());
        }
        let bucket_id = deterministic_id(
            "RING-OUTPUT-BUCKET",
            &[
                HashPart::U64(self.counters.ring_output_buckets + 1),
                HashPart::Str(cohort_id),
                HashPart::U64(lower_entropy_bps),
                HashPart::U64(upper_entropy_bps),
            ],
        );
        let mut bucket = RingOutputEntropyBucket {
            bucket_id: bucket_id.clone(),
            cohort_id: cohort_id.to_string(),
            lower_entropy_bps,
            upper_entropy_bps,
            output_count,
            median_age_blocks,
            bucket_root: String::new(),
        };
        bucket.bucket_root = value_root("RING-OUTPUT-BUCKET", &bucket.public_record());
        self.ring_output_buckets.insert(bucket_id.clone(), bucket);
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn reserve_redaction_budget(
        &mut self,
        cohort_id: impl AsRef<str>,
        spent_units: u64,
    ) -> Result<String> {
        let cohort_id = cohort_id.as_ref();
        if !self.viewtag_cohorts.contains_key(cohort_id) {
            return Err("unknown viewtag cohort".to_string());
        }
        if spent_units > self.config.max_redaction_units {
            return Err("redaction spend exceeds privacy budget".to_string());
        }
        let epoch = self.current_height / self.config.redaction_epoch_blocks.max(1);
        let budget_id = deterministic_id(
            "PRIVACY-REDACTION-BUDGET",
            &[
                HashPart::U64(self.counters.redaction_budgets + 1),
                HashPart::Str(cohort_id),
                HashPart::U64(epoch),
            ],
        );
        let mut budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            cohort_id: cohort_id.to_string(),
            epoch,
            allowed_units: self.config.max_redaction_units,
            spent_units,
            redacted_fields_root: deterministic_root("redacted_fields", &budget_id),
            budget_root: String::new(),
        };
        budget.budget_root = value_root("PRIVACY-REDACTION-BUDGET", &budget.public_record());
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.refresh_roots();
        Ok(budget_id)
    }

    fn record_freshness_score(
        &mut self,
        audit_id: &str,
        median_age_blocks: u64,
        p95_age_blocks: u64,
    ) -> Result<String> {
        let score_id = deterministic_id(
            "DECOY-FRESHNESS-SCORE",
            &[
                HashPart::U64(self.counters.freshness_scores + 1),
                HashPart::Str(audit_id),
                HashPart::U64(median_age_blocks),
                HashPart::U64(p95_age_blocks),
            ],
        );
        let mut score = DecoyFreshnessScore {
            score_id: score_id.clone(),
            audit_id: audit_id.to_string(),
            median_age_blocks,
            p95_age_blocks,
            freshness_bps: freshness_score(median_age_blocks, p95_age_blocks),
            score_root: String::new(),
        };
        score.score_root = value_root("DECOY-FRESHNESS-SCORE", &score.public_record());
        self.freshness_scores.insert(score_id.clone(), score);
        Ok(score_id)
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": self.roots.public_record_without_state_root(),
        })
    }

    fn refresh_roots(&mut self) {
        self.counters.viewtag_cohorts = self.viewtag_cohorts.len() as u64;
        self.counters.decoy_entropy_audits = self.decoy_entropy_audits.len() as u64;
        self.counters.ring_output_buckets = self.ring_output_buckets.len() as u64;
        self.counters.pq_auditor_attestations = self.pq_auditor_attestations.len() as u64;
        self.counters.wallet_scan_hints = self.wallet_scan_hints.len() as u64;
        self.counters.freshness_scores = self.freshness_scores.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.roots = Roots {
            config_root: value_root("CONFIG", &self.config.public_record()),
            counters_root: value_root("COUNTERS", &self.counters.public_record()),
            viewtag_cohort_root: map_root(
                "VIEWTAG-COHORTS",
                self.viewtag_cohorts
                    .values()
                    .map(ViewtagCohort::public_record)
                    .collect(),
            ),
            decoy_entropy_audit_root: map_root(
                "DECOY-ENTROPY-AUDITS",
                self.decoy_entropy_audits
                    .values()
                    .map(DecoyEntropyAudit::public_record)
                    .collect(),
            ),
            ring_output_bucket_root: map_root(
                "RING-OUTPUT-BUCKETS",
                self.ring_output_buckets
                    .values()
                    .map(RingOutputEntropyBucket::public_record)
                    .collect(),
            ),
            pq_auditor_attestation_root: map_root(
                "PQ-AUDITOR-ATTESTATIONS",
                self.pq_auditor_attestations
                    .values()
                    .map(PqAuditorAttestation::public_record)
                    .collect(),
            ),
            wallet_scan_hint_root: map_root(
                "WALLET-SCAN-HINTS",
                self.wallet_scan_hints
                    .values()
                    .map(WalletScanHint::public_record)
                    .collect(),
            ),
            freshness_score_root: map_root(
                "DECOY-FRESHNESS-SCORES",
                self.freshness_scores
                    .values()
                    .map(DecoyFreshnessScore::public_record)
                    .collect(),
            ),
            redaction_budget_root: map_root(
                "PRIVACY-REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(PrivacyRedactionBudget::public_record)
                    .collect(),
            ),
            state_root: String::new(),
        };
        self.roots.state_root = self.state_root();
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

fn seed_devnet(state: &mut State) {
    let cohort_id = state
        .open_viewtag_cohort(AuditLane::BridgeWithdrawal, 4_096, "bridge-withdrawal-a")
        .expect("devnet viewtag cohort");
    let audit_id = state
        .audit_decoy_entropy(&cohort_id, 32, 1_440, 8_640)
        .expect("devnet decoy entropy audit");
    state
        .record_ring_output_bucket(&cohort_id, 8_500, 9_250, 1_024, 1_440)
        .expect("devnet ring output bucket");
    state
        .attest_audit(
            &audit_id,
            "pq-auditor-cohort-a",
            DEFAULT_TARGET_PQ_SECURITY_BITS,
        )
        .expect("devnet PQ auditor attestation");
    state
        .issue_wallet_scan_hint(&cohort_id, DEVNET_HEIGHT - 72, DEVNET_HEIGHT)
        .expect("devnet wallet scan hint");
    state
        .reserve_redaction_budget(&cohort_id, 96)
        .expect("devnet redaction budget");
    state.refresh_roots();
}

fn entropy_score(ring_size: u16, output_count: u64) -> u64 {
    let ring_component = (ring_size as u64)
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_MIN_RING_SIZE as u64)
        .min(MAX_BPS);
    let output_component = output_count
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_MIN_COHORT_OUTPUTS)
        .min(MAX_BPS);
    ring_component
        .saturating_mul(60)
        .saturating_add(output_component.saturating_mul(40))
        .saturating_div(100)
}

fn freshness_score(median_age_blocks: u64, p95_age_blocks: u64) -> u64 {
    let median_penalty = median_age_blocks.saturating_mul(10).min(3_500);
    let tail_penalty = p95_age_blocks.saturating_mul(2).min(3_000);
    MAX_BPS.saturating_sub(median_penalty.saturating_add(tail_penalty).min(MAX_BPS))
}

fn deterministic_root(domain: &str, label: &str) -> String {
    deterministic_id(domain, &[HashPart::Str(label)])
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("SERAPHIS-JAMTIS-VIEWTAG-DECOY-ENTROPY-AUDITOR-{domain}"),
        parts,
        32,
    )
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("SERAPHIS-JAMTIS-VIEWTAG-DECOY-ENTROPY-AUDITOR-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("SERAPHIS-JAMTIS-VIEWTAG-DECOY-ENTROPY-AUDITOR-{domain}"),
        &records,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "SERAPHIS-JAMTIS-VIEWTAG-DECOY-ENTROPY-AUDITOR-STATE",
        &[HashPart::Json(record)],
        32,
    )
}
