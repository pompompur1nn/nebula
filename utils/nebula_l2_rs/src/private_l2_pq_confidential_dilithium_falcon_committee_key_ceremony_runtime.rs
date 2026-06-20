use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialDilithiumFalconCommitteeKeyCeremonyRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DILITHIUM_FALCON_COMMITTEE_KEY_CEREMONY_RUNTIME_PROTOCOL_VERSION:
    &str =
    "nebula-private-l2-pq-confidential-dilithium-falcon-committee-key-ceremony-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_DILITHIUM_FALCON_COMMITTEE_KEY_CEREMONY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIMARY_SIGNATURE_SUITE: &str = "Dilithium5-threshold-committee-ceremony-v1";
pub const SECONDARY_SIGNATURE_SUITE: &str = "Falcon-1024-threshold-backstop-v1";
pub const HYBRID_ENVELOPE_SUITE: &str = "Dilithium5+Falcon1024-confidential-pq-ceremony-v1";
pub const LEGACY_QUARANTINE_SCHEME: &str = "monero-private-l2-legacy-key-quarantine-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str = "pq-committee-key-ceremony-watcher-attestation-v1";
pub const SPONSOR_REBATE_SCHEME: &str = "pq-committee-key-ceremony-sponsor-fee-rebate-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "pq-committee-key-ceremony-privacy-redaction-budget-v1";
pub const DEVNET_HEIGHT: u64 = 812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 13;
pub const DEFAULT_THRESHOLD: u16 = 9;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MEMBERSHIP_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_CEREMONY_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_ROTATION_EPOCH_BLOCKS: u64 = 21_600;
pub const DEFAULT_LEGACY_QUARANTINE_BLOCKS: u64 = 43_200;
pub const DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET: u64 = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStatus {
    Drafted,
    MembershipOpen,
    SharesCommitted,
    WatcherAttested,
    ReadyForActivation,
    Active,
    Rotating,
    Quarantined,
    Retired,
    Rejected,
}

impl CeremonyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::MembershipOpen => "membership_open",
            Self::SharesCommitted => "shares_committed",
            Self::WatcherAttested => "watcher_attested",
            Self::ReadyForActivation => "ready_for_activation",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    DilithiumOnly,
    FalconOnly,
    DilithiumFalconHybrid,
    LegacySpendPlusDilithium,
    LegacySpendPlusFalcon,
}

impl EnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DilithiumOnly => "dilithium_only",
            Self::FalconOnly => "falcon_only",
            Self::DilithiumFalconHybrid => "dilithium_falcon_hybrid",
            Self::LegacySpendPlusDilithium => "legacy_spend_plus_dilithium",
            Self::LegacySpendPlusFalcon => "legacy_spend_plus_falcon",
        }
    }

    pub fn is_hybrid(self) -> bool {
        matches!(
            self,
            Self::DilithiumFalconHybrid
                | Self::LegacySpendPlusDilithium
                | Self::LegacySpendPlusFalcon
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Observed,
    MissingMember,
    InvalidShare,
    TranscriptMismatch,
    LegacyReuse,
    PrivacyBudgetExceeded,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::MissingMember => "missing_member",
            Self::InvalidShare => "invalid_share",
            Self::TranscriptMismatch => "transcript_mismatch",
            Self::LegacyReuse => "legacy_reuse",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
        }
    }

    pub fn is_positive(self) -> bool {
        matches!(self, Self::Observed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub network: String,
    pub chain_id: u64,
    pub l2_chain_id: u64,
    pub activation_height: u64,
    pub committee_size: u16,
    pub threshold: u16,
    pub min_pq_security_bits: u16,
    pub membership_window_blocks: u64,
    pub ceremony_window_blocks: u64,
    pub rotation_epoch_blocks: u64,
    pub legacy_quarantine_blocks: u64,
    pub watcher_quorum_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub default_privacy_redaction_budget: u64,
    pub require_hybrid_envelopes: bool,
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
            network: "devnet".to_string(),
            chain_id: 31337,
            l2_chain_id: 731337,
            activation_height: DEVNET_HEIGHT,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            threshold: DEFAULT_THRESHOLD,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            membership_window_blocks: DEFAULT_MEMBERSHIP_WINDOW_BLOCKS,
            ceremony_window_blocks: DEFAULT_CEREMONY_WINDOW_BLOCKS,
            rotation_epoch_blocks: DEFAULT_ROTATION_EPOCH_BLOCKS,
            legacy_quarantine_blocks: DEFAULT_LEGACY_QUARANTINE_BLOCKS,
            watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            sponsor_rebate_bps: DEFAULT_SPONSOR_REBATE_BPS,
            default_privacy_redaction_budget: DEFAULT_PRIVACY_REDACTION_BUDGET,
            require_hybrid_envelopes: true,
            deterministic_fixtures: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "network": self.network,
            "chain_id": self.chain_id,
            "l2_chain_id": self.l2_chain_id,
            "activation_height": self.activation_height,
            "committee_size": self.committee_size,
            "threshold": self.threshold,
            "min_pq_security_bits": self.min_pq_security_bits,
            "membership_window_blocks": self.membership_window_blocks,
            "ceremony_window_blocks": self.ceremony_window_blocks,
            "rotation_epoch_blocks": self.rotation_epoch_blocks,
            "legacy_quarantine_blocks": self.legacy_quarantine_blocks,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "default_privacy_redaction_budget": self.default_privacy_redaction_budget,
            "require_hybrid_envelopes": self.require_hybrid_envelopes,
            "deterministic_fixtures": self.deterministic_fixtures,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committee_members: u64,
    pub membership_windows: u64,
    pub ceremony_envelopes: u64,
    pub hybrid_envelopes: u64,
    pub migration_epochs: u64,
    pub rotation_epochs: u64,
    pub legacy_quarantine_entries: u64,
    pub watcher_attestations: u64,
    pub sponsor_fee_rebates: u64,
    pub privacy_redaction_budget_spent: u64,
    pub active_ceremonies: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub committee_member_root: String,
    pub membership_window_root: String,
    pub ceremony_envelope_root: String,
    pub migration_epoch_root: String,
    pub rotation_epoch_root: String,
    pub legacy_quarantine_root: String,
    pub watcher_attestation_root: String,
    pub sponsor_fee_rebate_root: String,
    pub privacy_redaction_budget_root: String,
    pub fixture_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_member_root": self.committee_member_root,
            "membership_window_root": self.membership_window_root,
            "ceremony_envelope_root": self.ceremony_envelope_root,
            "migration_epoch_root": self.migration_epoch_root,
            "rotation_epoch_root": self.rotation_epoch_root,
            "legacy_quarantine_root": self.legacy_quarantine_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "sponsor_fee_rebate_root": self.sponsor_fee_rebate_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "fixture_root": self.fixture_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub dilithium_public_key_commitment: String,
    pub falcon_public_key_commitment: String,
    pub stake_bond_commitment: String,
    pub joined_height: u64,
    pub active: bool,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "dilithium_public_key_commitment": self.dilithium_public_key_commitment,
            "falcon_public_key_commitment": self.falcon_public_key_commitment,
            "stake_bond_commitment": self.stake_bond_commitment,
            "joined_height": self.joined_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MembershipWindow {
    pub window_id: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub min_members: u16,
    pub threshold: u16,
    pub member_ids: BTreeSet<String>,
}

impl MembershipWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "min_members": self.min_members,
            "threshold": self.threshold,
            "member_ids": self.member_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCeremonyEnvelope {
    pub envelope_id: String,
    pub ceremony_id: String,
    pub window_id: String,
    pub kind: EnvelopeKind,
    pub transcript_root: String,
    pub dilithium_share_root: String,
    pub falcon_share_root: String,
    pub encrypted_payload_root: String,
    pub redacted_payload_root: String,
    pub status: CeremonyStatus,
}

impl PqCeremonyEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "ceremony_id": self.ceremony_id,
            "window_id": self.window_id,
            "kind": self.kind.as_str(),
            "transcript_root": self.transcript_root,
            "dilithium_share_root": self.dilithium_share_root,
            "falcon_share_root": self.falcon_share_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "redacted_payload_root": self.redacted_payload_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Epoch {
    pub epoch_id: String,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub source_ceremony_id: String,
    pub target_ceremony_id: String,
    pub rotation: bool,
}

impl Epoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "source_ceremony_id": self.source_ceremony_id,
            "target_ceremony_id": self.target_ceremony_id,
            "rotation": self.rotation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyQuarantineEntry {
    pub legacy_commitment: String,
    pub quarantined_at_height: u64,
    pub release_height: u64,
    pub reason: String,
}

impl LegacyQuarantineEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "legacy_commitment": self.legacy_commitment,
            "quarantined_at_height": self.quarantined_at_height,
            "release_height": self.release_height,
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub watcher_commitment: String,
    pub ceremony_id: String,
    pub envelope_id: String,
    pub verdict: AttestationVerdict,
    pub observed_height: u64,
    pub attestation_root: String,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_commitment": self.watcher_commitment,
            "ceremony_id": self.ceremony_id,
            "envelope_id": self.envelope_id,
            "verdict": self.verdict.as_str(),
            "observed_height": self.observed_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorFeeRebate {
    pub rebate_id: String,
    pub sponsor_commitment: String,
    pub ceremony_id: String,
    pub fee_paid_micronero: u64,
    pub rebate_micronero: u64,
    pub settlement_root: String,
}

impl SponsorFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "sponsor_commitment": self.sponsor_commitment,
            "ceremony_id": self.ceremony_id,
            "fee_paid_micronero": self.fee_paid_micronero,
            "rebate_micronero": self.rebate_micronero,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub ceremony_id: String,
    pub allotted: u64,
    pub spent: u64,
    pub redaction_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "ceremony_id": self.ceremony_id,
            "allotted": self.allotted,
            "spent": self.spent,
            "remaining": self.allotted.saturating_sub(self.spent),
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub committee_members: BTreeMap<String, CommitteeMember>,
    pub membership_windows: BTreeMap<String, MembershipWindow>,
    pub ceremony_envelopes: BTreeMap<String, PqCeremonyEnvelope>,
    pub migration_epochs: BTreeMap<String, Epoch>,
    pub rotation_epochs: BTreeMap<String, Epoch>,
    pub legacy_quarantine: BTreeMap<String, LegacyQuarantineEntry>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub sponsor_fee_rebates: BTreeMap<String, SponsorFeeRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub devnet_fixtures: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            committee_members: BTreeMap::new(),
            membership_windows: BTreeMap::new(),
            ceremony_envelopes: BTreeMap::new(),
            migration_epochs: BTreeMap::new(),
            rotation_epochs: BTreeMap::new(),
            legacy_quarantine: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            sponsor_fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        };
        state.install_devnet_fixtures();
        state.refresh();
        state
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    fn install_devnet_fixtures(&mut self) {
        let activation = self.config.activation_height;
        let window_id = "membership-window-devnet-0001".to_string();
        let ceremony_id = "committee-key-ceremony-devnet-0001".to_string();
        let envelope_id = "pq-ceremony-envelope-devnet-0001".to_string();

        for index in 0..self.config.committee_size {
            let member_id = format!("committee-member-devnet-{index:04}");
            self.committee_members.insert(
                member_id.clone(),
                CommitteeMember {
                    member_id: member_id.clone(),
                    operator_commitment: deterministic_root(
                        "DILITHIUM-FALCON-OPERATOR",
                        &member_id,
                    ),
                    dilithium_public_key_commitment: deterministic_root(
                        "DILITHIUM-FALCON-DILITHIUM-PUBKEY",
                        &member_id,
                    ),
                    falcon_public_key_commitment: deterministic_root(
                        "DILITHIUM-FALCON-FALCON-PUBKEY",
                        &member_id,
                    ),
                    stake_bond_commitment: deterministic_root(
                        "DILITHIUM-FALCON-STAKE-BOND",
                        &member_id,
                    ),
                    joined_height: activation + u64::from(index),
                    active: true,
                },
            );
        }

        self.membership_windows.insert(
            window_id.clone(),
            MembershipWindow {
                window_id: window_id.clone(),
                opens_at_height: activation,
                closes_at_height: activation + self.config.membership_window_blocks,
                min_members: self.config.committee_size,
                threshold: self.config.threshold,
                member_ids: self.committee_members.keys().cloned().collect(),
            },
        );

        self.ceremony_envelopes.insert(
            envelope_id.clone(),
            PqCeremonyEnvelope {
                envelope_id: envelope_id.clone(),
                ceremony_id: ceremony_id.clone(),
                window_id: window_id.clone(),
                kind: EnvelopeKind::DilithiumFalconHybrid,
                transcript_root: deterministic_root("DILITHIUM-FALCON-TRANSCRIPT", &ceremony_id),
                dilithium_share_root: deterministic_root(
                    "DILITHIUM-FALCON-DILITHIUM-SHARES",
                    &ceremony_id,
                ),
                falcon_share_root: deterministic_root(
                    "DILITHIUM-FALCON-FALCON-SHARES",
                    &ceremony_id,
                ),
                encrypted_payload_root: deterministic_root(
                    "DILITHIUM-FALCON-ENCRYPTED-PAYLOAD",
                    &ceremony_id,
                ),
                redacted_payload_root: deterministic_root(
                    "DILITHIUM-FALCON-REDACTED-PAYLOAD",
                    &ceremony_id,
                ),
                status: CeremonyStatus::Active,
            },
        );

        self.migration_epochs.insert(
            "migration-epoch-devnet-0001".to_string(),
            Epoch {
                epoch_id: "migration-epoch-devnet-0001".to_string(),
                starts_at_height: activation,
                ends_at_height: activation + self.config.rotation_epoch_blocks,
                source_ceremony_id: "legacy-monero-committee".to_string(),
                target_ceremony_id: ceremony_id.clone(),
                rotation: false,
            },
        );

        self.rotation_epochs.insert(
            "rotation-epoch-devnet-0001".to_string(),
            Epoch {
                epoch_id: "rotation-epoch-devnet-0001".to_string(),
                starts_at_height: activation + self.config.rotation_epoch_blocks,
                ends_at_height: activation + (self.config.rotation_epoch_blocks * 2),
                source_ceremony_id: ceremony_id.clone(),
                target_ceremony_id: "committee-key-ceremony-devnet-0002".to_string(),
                rotation: true,
            },
        );

        self.legacy_quarantine.insert(
            "legacy-spend-key-quarantine-devnet-0001".to_string(),
            LegacyQuarantineEntry {
                legacy_commitment: deterministic_root("DILITHIUM-FALCON-LEGACY-KEY", "devnet-0001"),
                quarantined_at_height: activation,
                release_height: activation + self.config.legacy_quarantine_blocks,
                reason: "legacy_spend_key_pending_pq_committee_migration".to_string(),
            },
        );

        for index in 0..3_u16 {
            let attestation_id = format!("watcher-attestation-devnet-{index:04}");
            self.watcher_attestations.insert(
                attestation_id.clone(),
                WatcherAttestation {
                    attestation_id: attestation_id.clone(),
                    watcher_commitment: deterministic_root(
                        "DILITHIUM-FALCON-WATCHER",
                        &attestation_id,
                    ),
                    ceremony_id: ceremony_id.clone(),
                    envelope_id: envelope_id.clone(),
                    verdict: AttestationVerdict::Observed,
                    observed_height: activation
                        + self.config.ceremony_window_blocks
                        + u64::from(index),
                    attestation_root: deterministic_root(
                        "DILITHIUM-FALCON-WATCHER-ATTESTATION",
                        &attestation_id,
                    ),
                },
            );
        }

        self.sponsor_fee_rebates.insert(
            "sponsor-rebate-devnet-0001".to_string(),
            SponsorFeeRebate {
                rebate_id: "sponsor-rebate-devnet-0001".to_string(),
                sponsor_commitment: deterministic_root("DILITHIUM-FALCON-SPONSOR", "devnet"),
                ceremony_id: ceremony_id.clone(),
                fee_paid_micronero: 300_000,
                rebate_micronero: 255_000,
                settlement_root: deterministic_root("DILITHIUM-FALCON-SPONSOR-REBATE", "devnet"),
            },
        );

        self.privacy_redaction_budgets.insert(
            "redaction-budget-devnet-0001".to_string(),
            PrivacyRedactionBudget {
                budget_id: "redaction-budget-devnet-0001".to_string(),
                ceremony_id,
                allotted: self.config.default_privacy_redaction_budget,
                spent: 17,
                redaction_root: deterministic_root("DILITHIUM-FALCON-REDACTION-BUDGET", "devnet"),
            },
        );

        self.devnet_fixtures.insert(
            "deterministic_seed".to_string(),
            "nebula-private-l2-pq-dilithium-falcon-committee-key-ceremony-devnet".to_string(),
        );
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            committee_members: self.committee_members.len() as u64,
            membership_windows: self.membership_windows.len() as u64,
            ceremony_envelopes: self.ceremony_envelopes.len() as u64,
            hybrid_envelopes: self
                .ceremony_envelopes
                .values()
                .filter(|envelope| envelope.kind.is_hybrid())
                .count() as u64,
            migration_epochs: self.migration_epochs.len() as u64,
            rotation_epochs: self.rotation_epochs.len() as u64,
            legacy_quarantine_entries: self.legacy_quarantine.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            sponsor_fee_rebates: self.sponsor_fee_rebates.len() as u64,
            privacy_redaction_budget_spent: self
                .privacy_redaction_budgets
                .values()
                .map(|budget| budget.spent)
                .sum(),
            active_ceremonies: self
                .ceremony_envelopes
                .values()
                .filter(|envelope| envelope.status == CeremonyStatus::Active)
                .count() as u64,
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let committee_member_root = merkle_json(
            "DILITHIUM-FALCON-COMMITTEE-MEMBERS",
            self.committee_members
                .values()
                .map(CommitteeMember::public_record)
                .collect(),
        );
        let membership_window_root = merkle_json(
            "DILITHIUM-FALCON-MEMBERSHIP-WINDOWS",
            self.membership_windows
                .values()
                .map(MembershipWindow::public_record)
                .collect(),
        );
        let ceremony_envelope_root = merkle_json(
            "DILITHIUM-FALCON-PQ-CEREMONY-ENVELOPES",
            self.ceremony_envelopes
                .values()
                .map(PqCeremonyEnvelope::public_record)
                .collect(),
        );
        let migration_epoch_root = merkle_json(
            "DILITHIUM-FALCON-MIGRATION-EPOCHS",
            self.migration_epochs
                .values()
                .map(Epoch::public_record)
                .collect(),
        );
        let rotation_epoch_root = merkle_json(
            "DILITHIUM-FALCON-ROTATION-EPOCHS",
            self.rotation_epochs
                .values()
                .map(Epoch::public_record)
                .collect(),
        );
        let legacy_quarantine_root = merkle_json(
            "DILITHIUM-FALCON-LEGACY-QUARANTINE",
            self.legacy_quarantine
                .values()
                .map(LegacyQuarantineEntry::public_record)
                .collect(),
        );
        let watcher_attestation_root = merkle_json(
            "DILITHIUM-FALCON-WATCHER-ATTESTATIONS",
            self.watcher_attestations
                .values()
                .map(WatcherAttestation::public_record)
                .collect(),
        );
        let sponsor_fee_rebate_root = merkle_json(
            "DILITHIUM-FALCON-SPONSOR-FEE-REBATES",
            self.sponsor_fee_rebates
                .values()
                .map(SponsorFeeRebate::public_record)
                .collect(),
        );
        let privacy_redaction_budget_root = merkle_json(
            "DILITHIUM-FALCON-PRIVACY-REDACTION-BUDGETS",
            self.privacy_redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record)
                .collect(),
        );
        let fixture_root = merkle_json(
            "DILITHIUM-FALCON-DEVNET-FIXTURES",
            self.devnet_fixtures
                .iter()
                .map(|(name, value)| json!({ "name": name, "value": value }))
                .collect(),
        );
        let state_root = domain_hash(
            "DILITHIUM-FALCON-COMMITTEE-KEY-CEREMONY-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Str(&committee_member_root),
                HashPart::Str(&membership_window_root),
                HashPart::Str(&ceremony_envelope_root),
                HashPart::Str(&migration_epoch_root),
                HashPart::Str(&rotation_epoch_root),
                HashPart::Str(&legacy_quarantine_root),
                HashPart::Str(&watcher_attestation_root),
                HashPart::Str(&sponsor_fee_rebate_root),
                HashPart::Str(&privacy_redaction_budget_root),
                HashPart::Str(&fixture_root),
            ],
            32,
        );

        Roots {
            committee_member_root,
            membership_window_root,
            ceremony_envelope_root,
            migration_epoch_root,
            rotation_epoch_root,
            legacy_quarantine_root,
            watcher_attestation_root,
            sponsor_fee_rebate_root,
            privacy_redaction_budget_root,
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
        "primary_signature_suite": PRIMARY_SIGNATURE_SUITE,
        "secondary_signature_suite": SECONDARY_SIGNATURE_SUITE,
        "hybrid_envelope_suite": HYBRID_ENVELOPE_SUITE,
        "legacy_quarantine_scheme": LEGACY_QUARANTINE_SCHEME,
        "watcher_attestation_scheme": WATCHER_ATTESTATION_SCHEME,
        "sponsor_rebate_scheme": SPONSOR_REBATE_SCHEME,
        "privacy_redaction_budget_scheme": PRIVACY_REDACTION_BUDGET_SCHEME,
        "config": state.config.public_record(),
        "counters": state.counters,
        "roots": state.roots.public_record(),
        "committee_members": state
            .committee_members
            .values()
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>(),
        "membership_windows": state
            .membership_windows
            .values()
            .map(MembershipWindow::public_record)
            .collect::<Vec<_>>(),
        "ceremony_envelopes": state
            .ceremony_envelopes
            .values()
            .map(PqCeremonyEnvelope::public_record)
            .collect::<Vec<_>>(),
        "migration_epochs": state
            .migration_epochs
            .values()
            .map(Epoch::public_record)
            .collect::<Vec<_>>(),
        "rotation_epochs": state
            .rotation_epochs
            .values()
            .map(Epoch::public_record)
            .collect::<Vec<_>>(),
        "legacy_quarantine_count": state.legacy_quarantine.len(),
        "watcher_attestations": state
            .watcher_attestations
            .values()
            .map(WatcherAttestation::public_record)
            .collect::<Vec<_>>(),
        "sponsor_fee_rebates": state
            .sponsor_fee_rebates
            .values()
            .map(SponsorFeeRebate::public_record)
            .collect::<Vec<_>>(),
        "privacy_redaction_budgets": state
            .privacy_redaction_budgets
            .values()
            .map(PrivacyRedactionBudget::public_record)
            .collect::<Vec<_>>(),
        "devnet_fixtures": state.devnet_fixtures,
    })
}

pub fn state_root(state: &State) -> String {
    domain_hash(
        "DILITHIUM-FALCON-COMMITTEE-KEY-CEREMONY-PUBLIC-RECORD",
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
