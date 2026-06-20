use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialFalconSlhDsaHybridAccountRotationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_FALCON_SLH_DSA_HYBRID_ACCOUNT_ROTATION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-falcon-slh-dsa-hybrid-account-rotation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_FALCON_SLH_DSA_HYBRID_ACCOUNT_ROTATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str =
    "Falcon-1024+SLH-DSA-SHAKE-256f-hybrid-account-rotation-envelope-v1";
pub const LEGACY_QUARANTINE_SCHEME: &str = "monero-private-l2-legacy-account-quarantine-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str = "falcon-slh-dsa-watcher-attestation-quorum-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "confidential-account-rotation-redaction-budget-v1";
pub const DEFAULT_MIGRATION_WINDOW_BLOCKS: u64 = 7_200;
pub const DEFAULT_SESSION_WINDOW_BLOCKS: u64 = 960;
pub const DEFAULT_LEGACY_QUARANTINE_BLOCKS: u64 = 21_600;
pub const DEFAULT_MIN_WATCHER_ATTESTATIONS: u16 = 3;
pub const DEFAULT_SPONSOR_REBATE_BPS: u16 = 8_500;
pub const DEFAULT_REDACTION_BUDGET: u64 = 128;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Announced,
    SessionWindowOpen,
    AccountWindowOpen,
    WatcherAttested,
    Sponsored,
    Finalized,
    Quarantined,
    Rejected,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::SessionWindowOpen => "session_window_open",
            Self::AccountWindowOpen => "account_window_open",
            Self::WatcherAttested => "watcher_attested",
            Self::Sponsored => "sponsored",
            Self::Finalized => "finalized",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureEnvelopeKind {
    FalconOnly,
    SlhDsaOnly,
    FalconSlhDsaHybrid,
    LegacySpendPlusFalcon,
    LegacySpendPlusSlhDsa,
}

impl SignatureEnvelopeKind {
    pub fn is_hybrid(self) -> bool {
        matches!(
            self,
            Self::FalconSlhDsaHybrid | Self::LegacySpendPlusFalcon | Self::LegacySpendPlusSlhDsa
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalconOnly => "falcon_only",
            Self::SlhDsaOnly => "slh_dsa_only",
            Self::FalconSlhDsaHybrid => "falcon_slh_dsa_hybrid",
            Self::LegacySpendPlusFalcon => "legacy_spend_plus_falcon",
            Self::LegacySpendPlusSlhDsa => "legacy_spend_plus_slh_dsa",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub migration_window_blocks: u64,
    pub session_window_blocks: u64,
    pub legacy_quarantine_blocks: u64,
    pub min_watcher_attestations: u16,
    pub sponsor_rebate_bps: u16,
    pub default_redaction_budget: u64,
    pub min_pq_security_bits: u16,
    pub deterministic_fixtures: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: "devnet".to_string(),
            migration_window_blocks: DEFAULT_MIGRATION_WINDOW_BLOCKS,
            session_window_blocks: DEFAULT_SESSION_WINDOW_BLOCKS,
            legacy_quarantine_blocks: DEFAULT_LEGACY_QUARANTINE_BLOCKS,
            min_watcher_attestations: DEFAULT_MIN_WATCHER_ATTESTATIONS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            default_redaction_budget: DEFAULT_REDACTION_BUDGET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            deterministic_fixtures: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "network": self.network,
            "migration_window_blocks": self.migration_window_blocks,
            "session_window_blocks": self.session_window_blocks,
            "legacy_quarantine_blocks": self.legacy_quarantine_blocks,
            "min_watcher_attestations": self.min_watcher_attestations,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "default_redaction_budget": self.default_redaction_budget,
            "min_pq_security_bits": self.min_pq_security_bits,
            "deterministic_fixtures": self.deterministic_fixtures,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub account_rotation_windows: u64,
    pub session_migration_windows: u64,
    pub pq_signature_envelopes: u64,
    pub hybrid_envelopes: u64,
    pub legacy_quarantine_entries: u64,
    pub watcher_attestations: u64,
    pub sponsor_rebates: u64,
    pub redaction_budget_spent: u64,
    pub finalized_rotations: u64,
    pub rejected_rotations: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub account_window_root: String,
    pub session_window_root: String,
    pub signature_envelope_root: String,
    pub legacy_quarantine_root: String,
    pub watcher_attestation_root: String,
    pub sponsor_rebate_root: String,
    pub redaction_budget_root: String,
    pub fixture_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "account_window_root": self.account_window_root,
            "session_window_root": self.session_window_root,
            "signature_envelope_root": self.signature_envelope_root,
            "legacy_quarantine_root": self.legacy_quarantine_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "fixture_root": self.fixture_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationWindow {
    pub window_id: String,
    pub account_commitment: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub session_cutover_height: u64,
    pub status: RotationStatus,
}

impl MigrationWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "account_commitment": self.account_commitment,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "session_cutover_height": self.session_cutover_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignatureEnvelope {
    pub envelope_id: String,
    pub account_commitment: String,
    pub session_commitment: String,
    pub kind: SignatureEnvelopeKind,
    pub payload_root: String,
    pub falcon_signature_commitment: String,
    pub slh_dsa_signature_commitment: String,
    pub nonce: u64,
}

impl PqSignatureEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "account_commitment": self.account_commitment,
            "session_commitment": self.session_commitment,
            "kind": self.kind.as_str(),
            "payload_root": self.payload_root,
            "falcon_signature_commitment": self.falcon_signature_commitment,
            "slh_dsa_signature_commitment": self.slh_dsa_signature_commitment,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub window_id: String,
    pub observed_root: String,
    pub envelope_id: String,
    pub height: u64,
    pub accepted: bool,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "window_id": self.window_id,
            "observed_root": self.observed_root,
            "envelope_id": self.envelope_id,
            "height": self.height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorRebate {
    pub rebate_id: String,
    pub sponsor_id: String,
    pub account_commitment: String,
    pub window_id: String,
    pub fee_paid_atomic: u64,
    pub rebate_bps: u16,
    pub rebate_atomic: u64,
}

impl SponsorRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "sponsor_id": self.sponsor_id,
            "account_commitment": self.account_commitment,
            "window_id": self.window_id,
            "fee_paid_atomic": self.fee_paid_atomic,
            "rebate_bps": self.rebate_bps,
            "rebate_atomic": self.rebate_atomic,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub account_commitment: String,
    pub window_id: String,
    pub allocated: u64,
    pub spent: u64,
    pub note_commitment_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "account_commitment": self.account_commitment,
            "window_id": self.window_id,
            "allocated": self.allocated,
            "spent": self.spent,
            "remaining": self.allocated.saturating_sub(self.spent),
            "note_commitment_root": self.note_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub account_windows: BTreeMap<String, MigrationWindow>,
    pub session_windows: BTreeMap<String, MigrationWindow>,
    pub pq_signature_envelopes: BTreeMap<String, PqSignatureEnvelope>,
    pub legacy_quarantine: BTreeSet<String>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub sponsor_rebates: BTreeMap<String, SponsorRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub devnet_fixtures: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut account_windows = BTreeMap::new();
        let mut session_windows = BTreeMap::new();
        let mut pq_signature_envelopes = BTreeMap::new();
        let mut legacy_quarantine = BTreeSet::new();
        let mut watcher_attestations = BTreeMap::new();
        let mut sponsor_rebates = BTreeMap::new();
        let mut redaction_budgets = BTreeMap::new();
        let mut devnet_fixtures = BTreeMap::new();

        let account_window = MigrationWindow {
            window_id: "devnet-account-rotation-window-0001".to_string(),
            account_commitment: "acctcm-devnet-falcon-slh-dsa-0001".to_string(),
            opens_at_height: 920_000,
            closes_at_height: 927_200,
            session_cutover_height: 920_960,
            status: RotationStatus::WatcherAttested,
        };
        let session_window = MigrationWindow {
            window_id: "devnet-session-migration-window-0001".to_string(),
            account_commitment: account_window.account_commitment.clone(),
            opens_at_height: 920_000,
            closes_at_height: 920_960,
            session_cutover_height: 920_128,
            status: RotationStatus::SessionWindowOpen,
        };
        let envelope = PqSignatureEnvelope {
            envelope_id: "devnet-pq-envelope-0001".to_string(),
            account_commitment: account_window.account_commitment.clone(),
            session_commitment: "sesscm-devnet-ratchet-0001".to_string(),
            kind: SignatureEnvelopeKind::FalconSlhDsaHybrid,
            payload_root: deterministic_root("DEVNET-PAYLOAD", "account-rotation-intent-0001"),
            falcon_signature_commitment: "falcon1024-sigcm-devnet-0001".to_string(),
            slh_dsa_signature_commitment: "slhdsa256f-sigcm-devnet-0001".to_string(),
            nonce: 1,
        };
        let attestation = WatcherAttestation {
            attestation_id: "devnet-watcher-attestation-0001".to_string(),
            watcher_id: "watcher-devnet-00".to_string(),
            window_id: account_window.window_id.clone(),
            observed_root: deterministic_root("DEVNET-WATCHER", "observed-account-window-0001"),
            envelope_id: envelope.envelope_id.clone(),
            height: 920_032,
            accepted: true,
        };
        let rebate = SponsorRebate {
            rebate_id: "devnet-sponsor-rebate-0001".to_string(),
            sponsor_id: "sponsor-devnet-00".to_string(),
            account_commitment: account_window.account_commitment.clone(),
            window_id: account_window.window_id.clone(),
            fee_paid_atomic: 12_000,
            rebate_bps: config.sponsor_rebate_bps,
            rebate_atomic: 10_200,
        };
        let budget = RedactionBudget {
            budget_id: "devnet-redaction-budget-0001".to_string(),
            account_commitment: account_window.account_commitment.clone(),
            window_id: account_window.window_id.clone(),
            allocated: config.default_redaction_budget,
            spent: 8,
            note_commitment_root: deterministic_root("DEVNET-REDACTION", "notes-0001"),
        };

        account_windows.insert(account_window.window_id.clone(), account_window);
        session_windows.insert(session_window.window_id.clone(), session_window);
        legacy_quarantine.insert("legacy-spend-key-quarantine-devnet-0001".to_string());
        pq_signature_envelopes.insert(envelope.envelope_id.clone(), envelope);
        watcher_attestations.insert(attestation.attestation_id.clone(), attestation);
        sponsor_rebates.insert(rebate.rebate_id.clone(), rebate);
        redaction_budgets.insert(budget.budget_id.clone(), budget);
        devnet_fixtures.insert(
            "demo_rotation_note".to_string(),
            "deterministic Falcon+SLH-DSA hybrid account rotation fixture".to_string(),
        );

        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            account_windows,
            session_windows,
            pq_signature_envelopes,
            legacy_quarantine,
            watcher_attestations,
            sponsor_rebates,
            redaction_budgets,
            devnet_fixtures,
        };
        state.recompute();
        state
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn recompute(&mut self) {
        self.counters = Counters {
            account_rotation_windows: self.account_windows.len() as u64,
            session_migration_windows: self.session_windows.len() as u64,
            pq_signature_envelopes: self.pq_signature_envelopes.len() as u64,
            hybrid_envelopes: self
                .pq_signature_envelopes
                .values()
                .filter(|envelope| envelope.kind.is_hybrid())
                .count() as u64,
            legacy_quarantine_entries: self.legacy_quarantine.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            sponsor_rebates: self.sponsor_rebates.len() as u64,
            redaction_budget_spent: self
                .redaction_budgets
                .values()
                .map(|budget| budget.spent)
                .sum(),
            finalized_rotations: self
                .account_windows
                .values()
                .filter(|window| window.status == RotationStatus::Finalized)
                .count() as u64,
            rejected_rotations: self
                .account_windows
                .values()
                .filter(|window| window.status == RotationStatus::Rejected)
                .count() as u64,
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let account_window_root = merkle_json(
            "FALCON-SLH-DSA-ACCOUNT-WINDOWS",
            self.account_windows
                .values()
                .map(MigrationWindow::public_record)
                .collect(),
        );
        let session_window_root = merkle_json(
            "FALCON-SLH-DSA-SESSION-WINDOWS",
            self.session_windows
                .values()
                .map(MigrationWindow::public_record)
                .collect(),
        );
        let signature_envelope_root = merkle_json(
            "FALCON-SLH-DSA-PQ-SIGNATURE-ENVELOPES",
            self.pq_signature_envelopes
                .values()
                .map(PqSignatureEnvelope::public_record)
                .collect(),
        );
        let legacy_quarantine_root = merkle_json(
            "FALCON-SLH-DSA-LEGACY-QUARANTINE",
            self.legacy_quarantine
                .iter()
                .map(|entry| json!({ "legacy_commitment": entry }))
                .collect(),
        );
        let watcher_attestation_root = merkle_json(
            "FALCON-SLH-DSA-WATCHER-ATTESTATIONS",
            self.watcher_attestations
                .values()
                .map(WatcherAttestation::public_record)
                .collect(),
        );
        let sponsor_rebate_root = merkle_json(
            "FALCON-SLH-DSA-SPONSOR-REBATES",
            self.sponsor_rebates
                .values()
                .map(SponsorRebate::public_record)
                .collect(),
        );
        let redaction_budget_root = merkle_json(
            "FALCON-SLH-DSA-REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect(),
        );
        let fixture_root = merkle_json(
            "FALCON-SLH-DSA-DEVNET-FIXTURES",
            self.devnet_fixtures
                .iter()
                .map(|(name, value)| json!({ "name": name, "value": value }))
                .collect(),
        );
        let state_root = domain_hash(
            "FALCON-SLH-DSA-HYBRID-ACCOUNT-ROTATION-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Str(&account_window_root),
                HashPart::Str(&session_window_root),
                HashPart::Str(&signature_envelope_root),
                HashPart::Str(&legacy_quarantine_root),
                HashPart::Str(&watcher_attestation_root),
                HashPart::Str(&sponsor_rebate_root),
                HashPart::Str(&redaction_budget_root),
                HashPart::Str(&fixture_root),
            ],
            32,
        );

        Roots {
            account_window_root,
            session_window_root,
            signature_envelope_root,
            legacy_quarantine_root,
            watcher_attestation_root,
            sponsor_rebate_root,
            redaction_budget_root,
            fixture_root,
            state_root,
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "pq_signature_suite": PQ_SIGNATURE_SUITE,
        "legacy_quarantine_scheme": LEGACY_QUARANTINE_SCHEME,
        "watcher_attestation_scheme": WATCHER_ATTESTATION_SCHEME,
        "redaction_budget_scheme": REDACTION_BUDGET_SCHEME,
        "config": state.config.public_record(),
        "counters": state.counters,
        "roots": state.roots.public_record(),
        "account_windows": state
            .account_windows
            .values()
            .map(MigrationWindow::public_record)
            .collect::<Vec<_>>(),
        "session_windows": state
            .session_windows
            .values()
            .map(MigrationWindow::public_record)
            .collect::<Vec<_>>(),
        "pq_signature_envelopes": state
            .pq_signature_envelopes
            .values()
            .map(PqSignatureEnvelope::public_record)
            .collect::<Vec<_>>(),
        "legacy_quarantine_count": state.legacy_quarantine.len(),
        "watcher_attestations": state
            .watcher_attestations
            .values()
            .map(WatcherAttestation::public_record)
            .collect::<Vec<_>>(),
        "sponsor_rebates": state
            .sponsor_rebates
            .values()
            .map(SponsorRebate::public_record)
            .collect::<Vec<_>>(),
        "redaction_budgets": state
            .redaction_budgets
            .values()
            .map(RedactionBudget::public_record)
            .collect::<Vec<_>>(),
        "devnet_fixtures": state.devnet_fixtures,
    })
}

pub fn state_root(state: &State) -> String {
    domain_hash(
        "FALCON-SLH-DSA-HYBRID-ACCOUNT-ROTATION-PUBLIC-RECORD",
        &[HashPart::Json(&public_record(state))],
        32,
    )
}

fn deterministic_root(domain: &str, seed: &str) -> String {
    domain_hash(domain, &[HashPart::Str(seed)], 32)
}

fn merkle_json(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}
