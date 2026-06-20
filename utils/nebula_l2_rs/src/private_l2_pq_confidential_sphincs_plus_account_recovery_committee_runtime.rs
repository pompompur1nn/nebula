use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSphincsPlusAccountRecoveryCommitteeRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SPHINCS_PLUS_ACCOUNT_RECOVERY_COMMITTEE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-sphincs-plus-account-recovery-committee-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SPHINCS_PLUS_ACCOUNT_RECOVERY_COMMITTEE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_260_480;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SPHINCS_PLUS_SUITE: &str = "SLH-DSA-SHAKE-256f-account-recovery-committee-v1";
pub const PQ_ENVELOPE_SCHEME: &str = "ml-kem-1024-sphincs-plus-recovery-envelope-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str =
    "threshold-watcher-sphincs-plus-recovery-attestation-root-v1";
pub const LEGACY_QUARANTINE_SCHEME: &str = "legacy-account-quarantine-root-v1";
pub const MIGRATION_RECEIPT_SCHEME: &str = "pq-account-migration-receipt-root-v1";
pub const SPONSOR_REBATE_SCHEME: &str = "private-l2-pq-recovery-sponsor-rebate-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "private-l2-account-recovery-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "private-l2-pq-sphincs-plus-account-recovery-public-record-root-v1";
pub const STATE_ROOT_DOMAIN: &str =
    "PRIVATE-L2-PQ-CONFIDENTIAL-SPHINCS-PLUS-ACCOUNT-RECOVERY-COMMITTEE-STATE";
pub const DEFAULT_RECOVERY_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_LEGACY_QUARANTINE_BLOCKS: u64 = 10_080;
pub const DEFAULT_MIN_COMMITTEE_SIZE: u16 = 5;
pub const DEFAULT_MIN_COMMITTEE_THRESHOLD: u16 = 3;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const DEFAULT_WATCHER_QUORUM_WEIGHT: u64 = 7;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_DAILY_REDACTION_BUDGET: u64 = 96;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_000;
pub const DEFAULT_MAX_RECOVERY_FEE_MICRO_UNITS: u64 = 25_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_COMMITTEES: usize = 262_144;
pub const MAX_RECOVERY_WINDOWS: usize = 524_288;
pub const MAX_RECOVERY_ENVELOPES: usize = 1_048_576;
pub const MAX_WATCHER_ATTESTATIONS: usize = 2_097_152;
pub const MAX_LEGACY_QUARANTINES: usize = 524_288;
pub const MAX_MIGRATION_RECEIPTS: usize = 1_048_576;
pub const MAX_SPONSOR_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLane {
    Standard,
    LowFee,
    Sponsored,
    Emergency,
    LegacyMigration,
}

impl RecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::LowFee => "low_fee",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
            Self::LegacyMigration => "legacy_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Drafted,
    Open,
    CommitteeSealed,
    WatcherQuorum,
    Migrated,
    Expired,
    Cancelled,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Open => "open",
            Self::CommitteeSealed => "committee_sealed",
            Self::WatcherQuorum => "watcher_quorum",
            Self::Migrated => "migrated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approve,
    Reject,
    Abstain,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub bridge_id: String,
    pub operator_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub sphincs_plus_suite: String,
    pub pq_envelope_scheme: String,
    pub watcher_attestation_scheme: String,
    pub recovery_window_blocks: u64,
    pub legacy_quarantine_blocks: u64,
    pub min_committee_size: u16,
    pub min_committee_threshold: u16,
    pub min_watcher_weight: u64,
    pub watcher_quorum_weight: u64,
    pub min_pq_security_bits: u16,
    pub daily_redaction_budget: u64,
    pub sponsor_rebate_bps: u64,
    pub max_recovery_fee_micro_units: u64,
}

impl Config {
    pub fn devnet(operator_id: &str) -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: "nebula-devnet".to_string(),
            bridge_id: "private-l2-pq-sphincs-plus-account-recovery-devnet".to_string(),
            operator_id: operator_id.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            sphincs_plus_suite: SPHINCS_PLUS_SUITE.to_string(),
            pq_envelope_scheme: PQ_ENVELOPE_SCHEME.to_string(),
            watcher_attestation_scheme: WATCHER_ATTESTATION_SCHEME.to_string(),
            recovery_window_blocks: DEFAULT_RECOVERY_WINDOW_BLOCKS,
            legacy_quarantine_blocks: DEFAULT_LEGACY_QUARANTINE_BLOCKS,
            min_committee_size: DEFAULT_MIN_COMMITTEE_SIZE,
            min_committee_threshold: DEFAULT_MIN_COMMITTEE_THRESHOLD,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            watcher_quorum_weight: DEFAULT_WATCHER_QUORUM_WEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            daily_redaction_budget: DEFAULT_DAILY_REDACTION_BUDGET,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            max_recovery_fee_micro_units: DEFAULT_MAX_RECOVERY_FEE_MICRO_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.min_committee_threshold == 0
            || self.min_committee_threshold > self.min_committee_size
        {
            return Err("invalid committee threshold".to_string());
        }
        if self.watcher_quorum_weight < self.min_watcher_weight {
            return Err("watcher quorum below minimum weight".to_string());
        }
        if self.sponsor_rebate_bps > MAX_BPS {
            return Err("sponsor rebate exceeds basis point denominator".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "network": self.network,
            "bridge_id": self.bridge_id,
            "operator_id": self.operator_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "sphincs_plus_suite": self.sphincs_plus_suite,
            "pq_envelope_scheme": self.pq_envelope_scheme,
            "watcher_attestation_scheme": self.watcher_attestation_scheme,
            "recovery_window_blocks": self.recovery_window_blocks,
            "legacy_quarantine_blocks": self.legacy_quarantine_blocks,
            "min_committee_size": self.min_committee_size,
            "min_committee_threshold": self.min_committee_threshold,
            "min_watcher_weight": self.min_watcher_weight,
            "watcher_quorum_weight": self.watcher_quorum_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "daily_redaction_budget": self.daily_redaction_budget,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "max_recovery_fee_micro_units": self.max_recovery_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committees_registered: u64,
    pub recovery_windows_opened: u64,
    pub pq_envelopes_sealed: u64,
    pub watcher_attestations_registered: u64,
    pub legacy_accounts_quarantined: u64,
    pub migration_receipts_issued: u64,
    pub sponsor_rebates_reserved: u64,
    pub redaction_budget_units_reserved: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "committees_registered": self.committees_registered,
            "recovery_windows_opened": self.recovery_windows_opened,
            "pq_envelopes_sealed": self.pq_envelopes_sealed,
            "watcher_attestations_registered": self.watcher_attestations_registered,
            "legacy_accounts_quarantined": self.legacy_accounts_quarantined,
            "migration_receipts_issued": self.migration_receipts_issued,
            "sponsor_rebates_reserved": self.sponsor_rebates_reserved,
            "redaction_budget_units_reserved": self.redaction_budget_units_reserved,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub committee_root: String,
    pub recovery_window_root: String,
    pub pq_envelope_root: String,
    pub watcher_attestation_root: String,
    pub legacy_quarantine_root: String,
    pub migration_receipt_root: String,
    pub sponsor_rebate_root: String,
    pub privacy_redaction_budget_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_root": self.committee_root,
            "recovery_window_root": self.recovery_window_root,
            "pq_envelope_root": self.pq_envelope_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "legacy_quarantine_root": self.legacy_quarantine_root,
            "migration_receipt_root": self.migration_receipt_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Committee {
    pub committee_id: String,
    pub account_commitment: String,
    pub epoch: u64,
    pub member_root: String,
    pub threshold: u16,
    pub committee_size: u16,
    pub sphincs_public_key_root: String,
    pub policy_root: String,
}

impl Committee {
    pub fn new(
        account_commitment: &str,
        epoch: u64,
        member_root: &str,
        threshold: u16,
        committee_size: u16,
        sphincs_public_key_root: &str,
        policy_root: &str,
    ) -> Self {
        let body = json!({
            "account_commitment": account_commitment,
            "epoch": epoch,
            "member_root": member_root,
            "threshold": threshold,
            "committee_size": committee_size,
            "sphincs_public_key_root": sphincs_public_key_root,
            "policy_root": policy_root,
        });
        Self {
            committee_id: id("COMMITTEE-ID", &body),
            account_commitment: account_commitment.to_string(),
            epoch,
            member_root: member_root.to_string(),
            threshold,
            committee_size,
            sphincs_public_key_root: sphincs_public_key_root.to_string(),
            policy_root: policy_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "account_commitment": self.account_commitment,
            "epoch": self.epoch,
            "member_root": self.member_root,
            "threshold": self.threshold,
            "committee_size": self.committee_size,
            "sphincs_public_key_root": self.sphincs_public_key_root,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryWindow {
    pub window_id: String,
    pub account_commitment: String,
    pub committee_id: String,
    pub lane: RecoveryLane,
    pub status: WindowStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub legacy_account_root: String,
    pub target_account_root: String,
    pub redaction_budget_id: String,
    pub fee_cap_micro_units: u64,
}

impl RecoveryWindow {
    pub fn new(
        account_commitment: &str,
        committee_id: &str,
        lane: RecoveryLane,
        opened_height: u64,
        config: &Config,
        legacy_account_root: &str,
        target_account_root: &str,
        redaction_budget_id: &str,
    ) -> Self {
        let body = json!({
            "account_commitment": account_commitment,
            "committee_id": committee_id,
            "lane": lane.as_str(),
            "opened_height": opened_height,
            "legacy_account_root": legacy_account_root,
            "target_account_root": target_account_root,
            "redaction_budget_id": redaction_budget_id,
        });
        Self {
            window_id: id("RECOVERY-WINDOW-ID", &body),
            account_commitment: account_commitment.to_string(),
            committee_id: committee_id.to_string(),
            lane,
            status: WindowStatus::Open,
            opened_height,
            expires_height: opened_height.saturating_add(config.recovery_window_blocks),
            legacy_account_root: legacy_account_root.to_string(),
            target_account_root: target_account_root.to_string(),
            redaction_budget_id: redaction_budget_id.to_string(),
            fee_cap_micro_units: config.max_recovery_fee_micro_units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "account_commitment": self.account_commitment,
            "committee_id": self.committee_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "legacy_account_root": self.legacy_account_root,
            "target_account_root": self.target_account_root,
            "redaction_budget_id": self.redaction_budget_id,
            "fee_cap_micro_units": self.fee_cap_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRecoveryEnvelope {
    pub envelope_id: String,
    pub window_id: String,
    pub committee_id: String,
    pub encrypted_payload_root: String,
    pub sphincs_signature_root: String,
    pub pq_security_bits: u16,
    pub sealed_height: u64,
}

impl PqRecoveryEnvelope {
    pub fn new(
        window_id: &str,
        committee_id: &str,
        encrypted_payload_root: &str,
        sphincs_signature_root: &str,
        pq_security_bits: u16,
        sealed_height: u64,
    ) -> Self {
        let body = json!({
            "window_id": window_id,
            "committee_id": committee_id,
            "encrypted_payload_root": encrypted_payload_root,
            "sphincs_signature_root": sphincs_signature_root,
            "pq_security_bits": pq_security_bits,
            "sealed_height": sealed_height,
        });
        Self {
            envelope_id: id("PQ-RECOVERY-ENVELOPE-ID", &body),
            window_id: window_id.to_string(),
            committee_id: committee_id.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            sphincs_signature_root: sphincs_signature_root.to_string(),
            pq_security_bits,
            sealed_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "window_id": self.window_id,
            "committee_id": self.committee_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "sphincs_signature_root": self.sphincs_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "sealed_height": self.sealed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub window_id: String,
    pub watcher_commitment: String,
    pub verdict: AttestationVerdict,
    pub weight: u64,
    pub evidence_root: String,
    pub signature_root: String,
    pub attested_height: u64,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "window_id": self.window_id,
            "watcher_commitment": self.watcher_commitment,
            "verdict": self.verdict.as_str(),
            "weight": self.weight,
            "evidence_root": self.evidence_root,
            "signature_root": self.signature_root,
            "attested_height": self.attested_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyQuarantine {
    pub quarantine_id: String,
    pub account_commitment: String,
    pub legacy_account_root: String,
    pub reason_root: String,
    pub start_height: u64,
    pub release_height: u64,
}

impl LegacyQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "account_commitment": self.account_commitment,
            "legacy_account_root": self.legacy_account_root,
            "reason_root": self.reason_root,
            "start_height": self.start_height,
            "release_height": self.release_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountMigrationReceipt {
    pub receipt_id: String,
    pub window_id: String,
    pub account_commitment: String,
    pub migrated_account_root: String,
    pub envelope_root: String,
    pub watcher_quorum_root: String,
    pub issued_height: u64,
}

impl AccountMigrationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "window_id": self.window_id,
            "account_commitment": self.account_commitment,
            "migrated_account_root": self.migrated_account_root,
            "envelope_root": self.envelope_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorFeeRebate {
    pub rebate_id: String,
    pub window_id: String,
    pub sponsor_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_root: String,
}

impl SponsorFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "window_id": self.window_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub account_commitment: String,
    pub epoch: u64,
    pub redaction_limit: u64,
    pub redaction_reserved: u64,
    pub policy_root: String,
}

impl PrivacyRedactionBudget {
    pub fn new(
        account_commitment: &str,
        epoch: u64,
        redaction_limit: u64,
        policy_root: &str,
    ) -> Self {
        let body = json!({
            "account_commitment": account_commitment,
            "epoch": epoch,
            "redaction_limit": redaction_limit,
            "policy_root": policy_root,
        });
        Self {
            budget_id: id("PRIVACY-REDACTION-BUDGET-ID", &body),
            account_commitment: account_commitment.to_string(),
            epoch,
            redaction_limit,
            redaction_reserved: 0,
            policy_root: policy_root.to_string(),
        }
    }

    pub fn reserve(&mut self, units: u64) -> Result<()> {
        if self.redaction_reserved.saturating_add(units) > self.redaction_limit {
            return Err("redaction budget exceeded".to_string());
        }
        self.redaction_reserved = self.redaction_reserved.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "account_commitment": self.account_commitment,
            "epoch": self.epoch,
            "redaction_limit": self.redaction_limit,
            "redaction_reserved": self.redaction_reserved,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub committees: BTreeMap<String, Committee>,
    pub recovery_windows: BTreeMap<String, RecoveryWindow>,
    pub pq_recovery_envelopes: BTreeMap<String, PqRecoveryEnvelope>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub legacy_quarantines: BTreeMap<String, LegacyQuarantine>,
    pub account_migration_receipts: BTreeMap<String, AccountMigrationReceipt>,
    pub sponsor_fee_rebates: BTreeMap<String, SponsorFeeRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            committees: BTreeMap::new(),
            recovery_windows: BTreeMap::new(),
            pq_recovery_envelopes: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            legacy_quarantines: BTreeMap::new(),
            account_migration_receipts: BTreeMap::new(),
            sponsor_fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        Self::new(
            Config::devnet("operator-devnet-sphincs-plus-recovery"),
            DEVNET_HEIGHT,
            0,
        )
        .unwrap_or_else(|_| Self::empty_devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let account = deterministic_root("account", "alice");
        let policy = deterministic_root("policy", "alice-recovery");
        let mut budget =
            PrivacyRedactionBudget::new(&account, 1, state.config.daily_redaction_budget, &policy);
        let _ = budget.reserve(12);
        let budget_id = budget.budget_id.clone();
        let _ = state.register_redaction_budget(budget);

        let committee = Committee::new(
            &account,
            1,
            &deterministic_root("committee-members", "alice"),
            state.config.min_committee_threshold,
            state.config.min_committee_size,
            &deterministic_root("sphincs-public-keys", "alice"),
            &policy,
        );
        let committee_id = committee.committee_id.clone();
        let _ = state.register_committee(committee);

        let window = RecoveryWindow::new(
            &account,
            &committee_id,
            RecoveryLane::Sponsored,
            state.height,
            &state.config,
            &deterministic_root("legacy-account", "alice"),
            &deterministic_root("pq-account", "alice"),
            &budget_id,
        );
        let window_id = window.window_id.clone();
        let _ = state.open_recovery_window(window);

        let envelope = PqRecoveryEnvelope::new(
            &window_id,
            &committee_id,
            &deterministic_root("encrypted-envelope", "alice"),
            &deterministic_root("sphincs-signature", "alice"),
            state.config.min_pq_security_bits,
            state.height,
        );
        let _ = state.seal_recovery_envelope(envelope);

        for index in 0..3 {
            let _ = state.register_watcher_attestation(WatcherAttestation {
                attestation_id: deterministic_root("watcher-attestation", &index.to_string()),
                window_id: window_id.clone(),
                watcher_commitment: deterministic_root("watcher", &index.to_string()),
                verdict: AttestationVerdict::Approve,
                weight: state.config.min_watcher_weight,
                evidence_root: deterministic_root("watcher-evidence", &index.to_string()),
                signature_root: deterministic_root("watcher-signature", &index.to_string()),
                attested_height: state.height,
            });
        }

        let _ = state.quarantine_legacy_account(LegacyQuarantine {
            quarantine_id: deterministic_root("legacy-quarantine", "alice"),
            account_commitment: account.clone(),
            legacy_account_root: deterministic_root("legacy-account", "alice"),
            reason_root: deterministic_root("quarantine-reason", "sphincs-migration"),
            start_height: state.height,
            release_height: state
                .height
                .saturating_add(state.config.legacy_quarantine_blocks),
        });
        let _ = state.reserve_sponsor_rebate(SponsorFeeRebate {
            rebate_id: deterministic_root("sponsor-rebate", "alice"),
            window_id: window_id.clone(),
            sponsor_commitment: deterministic_root("sponsor", "demo"),
            fee_paid_micro_units: state.config.max_recovery_fee_micro_units,
            rebate_micro_units: state
                .config
                .max_recovery_fee_micro_units
                .saturating_mul(state.config.sponsor_rebate_bps)
                / MAX_BPS,
            rebate_root: deterministic_root("rebate", "alice"),
        });
        let _ = state.issue_migration_receipt(AccountMigrationReceipt {
            receipt_id: deterministic_root("migration-receipt", "alice"),
            window_id,
            account_commitment: account,
            migrated_account_root: deterministic_root("pq-account", "alice"),
            envelope_root: state.roots().pq_envelope_root,
            watcher_quorum_root: state.watcher_quorum_root(),
            issued_height: state.height.saturating_add(12),
        });
        state
    }

    pub fn register_committee(&mut self, committee: Committee) -> Result<String> {
        bounded_insert_len(self.committees.len(), MAX_COMMITTEES, "committees")?;
        if committee.threshold == 0 || committee.threshold > committee.committee_size {
            return Err("invalid committee threshold".to_string());
        }
        let id = committee.committee_id.clone();
        self.committees.insert(id.clone(), committee);
        self.counters.committees_registered = self.counters.committees_registered.saturating_add(1);
        Ok(id)
    }

    pub fn open_recovery_window(&mut self, window: RecoveryWindow) -> Result<String> {
        bounded_insert_len(
            self.recovery_windows.len(),
            MAX_RECOVERY_WINDOWS,
            "recovery_windows",
        )?;
        if !self.committees.contains_key(&window.committee_id) {
            return Err("committee not registered".to_string());
        }
        if !self
            .privacy_redaction_budgets
            .contains_key(&window.redaction_budget_id)
        {
            return Err("redaction budget not registered".to_string());
        }
        let id = window.window_id.clone();
        self.recovery_windows.insert(id.clone(), window);
        self.counters.recovery_windows_opened =
            self.counters.recovery_windows_opened.saturating_add(1);
        Ok(id)
    }

    pub fn seal_recovery_envelope(&mut self, envelope: PqRecoveryEnvelope) -> Result<String> {
        bounded_insert_len(
            self.pq_recovery_envelopes.len(),
            MAX_RECOVERY_ENVELOPES,
            "pq_recovery_envelopes",
        )?;
        if envelope.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq recovery envelope below minimum security bits".to_string());
        }
        let id = envelope.envelope_id.clone();
        self.pq_recovery_envelopes.insert(id.clone(), envelope);
        self.counters.pq_envelopes_sealed = self.counters.pq_envelopes_sealed.saturating_add(1);
        Ok(id)
    }

    pub fn register_watcher_attestation(
        &mut self,
        attestation: WatcherAttestation,
    ) -> Result<String> {
        bounded_insert_len(
            self.watcher_attestations.len(),
            MAX_WATCHER_ATTESTATIONS,
            "watcher_attestations",
        )?;
        if attestation.weight < self.config.min_watcher_weight {
            return Err("watcher attestation below minimum weight".to_string());
        }
        let id = attestation.attestation_id.clone();
        self.watcher_attestations.insert(id.clone(), attestation);
        self.counters.watcher_attestations_registered = self
            .counters
            .watcher_attestations_registered
            .saturating_add(1);
        Ok(id)
    }

    pub fn quarantine_legacy_account(&mut self, quarantine: LegacyQuarantine) -> Result<String> {
        bounded_insert_len(
            self.legacy_quarantines.len(),
            MAX_LEGACY_QUARANTINES,
            "legacy_quarantines",
        )?;
        let id = quarantine.quarantine_id.clone();
        self.legacy_quarantines.insert(id.clone(), quarantine);
        self.counters.legacy_accounts_quarantined =
            self.counters.legacy_accounts_quarantined.saturating_add(1);
        Ok(id)
    }

    pub fn issue_migration_receipt(&mut self, receipt: AccountMigrationReceipt) -> Result<String> {
        bounded_insert_len(
            self.account_migration_receipts.len(),
            MAX_MIGRATION_RECEIPTS,
            "account_migration_receipts",
        )?;
        let id = receipt.receipt_id.clone();
        self.account_migration_receipts.insert(id.clone(), receipt);
        self.counters.migration_receipts_issued =
            self.counters.migration_receipts_issued.saturating_add(1);
        Ok(id)
    }

    pub fn reserve_sponsor_rebate(&mut self, rebate: SponsorFeeRebate) -> Result<String> {
        bounded_insert_len(
            self.sponsor_fee_rebates.len(),
            MAX_SPONSOR_REBATES,
            "sponsor_fee_rebates",
        )?;
        let id = rebate.rebate_id.clone();
        self.sponsor_fee_rebates.insert(id.clone(), rebate);
        self.counters.sponsor_rebates_reserved =
            self.counters.sponsor_rebates_reserved.saturating_add(1);
        Ok(id)
    }

    pub fn register_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<String> {
        bounded_insert_len(
            self.privacy_redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "privacy_redaction_budgets",
        )?;
        let id = budget.budget_id.clone();
        self.counters.redaction_budget_units_reserved = self
            .counters
            .redaction_budget_units_reserved
            .saturating_add(budget.redaction_reserved);
        self.privacy_redaction_budgets.insert(id.clone(), budget);
        Ok(id)
    }

    pub fn watcher_quorum_weight(&self) -> u64 {
        self.watcher_attestations
            .values()
            .filter(|attestation| attestation.verdict == AttestationVerdict::Approve)
            .map(|attestation| attestation.weight)
            .sum()
    }

    pub fn watcher_quorum_root(&self) -> String {
        map_root(
            WATCHER_ATTESTATION_SCHEME,
            self.watcher_attestations
                .values()
                .map(WatcherAttestation::public_record)
                .collect(),
        )
    }

    pub fn roots(&self) -> Roots {
        Roots {
            committee_root: map_root(
                "SPHINCS-PLUS-ACCOUNT-RECOVERY-COMMITTEE-ROOT",
                self.committees
                    .values()
                    .map(Committee::public_record)
                    .collect(),
            ),
            recovery_window_root: map_root(
                "SPHINCS-PLUS-ACCOUNT-RECOVERY-WINDOW-ROOT",
                self.recovery_windows
                    .values()
                    .map(RecoveryWindow::public_record)
                    .collect(),
            ),
            pq_envelope_root: map_root(
                PQ_ENVELOPE_SCHEME,
                self.pq_recovery_envelopes
                    .values()
                    .map(PqRecoveryEnvelope::public_record)
                    .collect(),
            ),
            watcher_attestation_root: self.watcher_quorum_root(),
            legacy_quarantine_root: map_root(
                LEGACY_QUARANTINE_SCHEME,
                self.legacy_quarantines
                    .values()
                    .map(LegacyQuarantine::public_record)
                    .collect(),
            ),
            migration_receipt_root: map_root(
                MIGRATION_RECEIPT_SCHEME,
                self.account_migration_receipts
                    .values()
                    .map(AccountMigrationReceipt::public_record)
                    .collect(),
            ),
            sponsor_rebate_root: map_root(
                SPONSOR_REBATE_SCHEME,
                self.sponsor_fee_rebates
                    .values()
                    .map(SponsorFeeRebate::public_record)
                    .collect(),
            ),
            privacy_redaction_budget_root: map_root(
                PRIVACY_REDACTION_BUDGET_SCHEME,
                self.privacy_redaction_budgets
                    .values()
                    .map(PrivacyRedactionBudget::public_record)
                    .collect(),
            ),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "watcher_quorum_weight": self.watcher_quorum_weight(),
            "state_root": state_root_from_roots(&roots, self.height, self.epoch),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    fn public_record_root(&self) -> String {
        let records = vec![
            self.config.public_record(),
            self.counters.public_record(),
            map_root_value(
                "committees",
                &self
                    .committees
                    .values()
                    .map(Committee::public_record)
                    .collect::<Vec<_>>(),
            ),
            map_root_value(
                "recovery_windows",
                &self
                    .recovery_windows
                    .values()
                    .map(RecoveryWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            map_root_value(
                "migration_receipts",
                &self
                    .account_migration_receipts
                    .values()
                    .map(AccountMigrationReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
        ];
        merkle_root(PUBLIC_RECORD_SCHEME, &records)
    }

    fn empty_devnet() -> Self {
        Self {
            config: Config::devnet("operator-devnet-sphincs-plus-recovery"),
            height: DEVNET_HEIGHT,
            epoch: 0,
            counters: Counters::default(),
            committees: BTreeMap::new(),
            recovery_windows: BTreeMap::new(),
            pq_recovery_envelopes: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            legacy_quarantines: BTreeMap::new(),
            account_migration_receipts: BTreeMap::new(),
            sponsor_fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
        }
    }
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(STATE_ROOT_DOMAIN, &[HashPart::Json(record)], 32)
}

pub fn state_root_from_roots(roots: &Roots, height: u64, epoch: u64) -> String {
    domain_hash(
        STATE_ROOT_DOMAIN,
        &[
            HashPart::Json(&roots.public_record()),
            HashPart::U64(height),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-SPHINCS-PLUS-ACCOUNT-RECOVERY-DETERMINISTIC",
        &[HashPart::Str(label), HashPart::Str(value)],
        32,
    )
}

pub fn map_root(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by_key(|record| record.to_string());
    merkle_root(domain, &records)
}

pub fn map_root_value(label: &str, records: &[Value]) -> Value {
    json!({
        "label": label,
        "root": map_root(label, records.to_vec()),
        "count": records.len(),
    })
}

pub fn id(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 16)
}

pub fn bounded_insert_len(current_len: usize, max_len: usize, label: &str) -> Result<()> {
    if current_len >= max_len {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}
