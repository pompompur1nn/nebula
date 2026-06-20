use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePrivacyPreservingExitAcceptanceRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVACY_PRESERVING_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-privacy-preserving-exit-acceptance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVACY_PRESERVING_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACCEPTANCE_SUITE: &str = "monero-l2-pq-bridge-exit-privacy-preserving-acceptance-v1";
pub const DEVNET_SCENARIO_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-privacy-acceptance-devnet";

const DEVNET_EVALUATION_HEIGHT: u64 = 2_194_400;
const DEVNET_MIN_MONERO_CONFIRMATIONS: u64 = 30;
const DEVNET_MIN_RING_DECOYS: u16 = 15;
const DEVNET_MIN_DECOY_SPREAD_EPOCHS: u16 = 6;
const DEVNET_MIN_ANONYMITY_SET: u64 = 262_144;
const DEVNET_MIN_NULLIFIER_SEPARATION_BITS: u16 = 128;
const DEVNET_MIN_KEY_IMAGE_SEPARATION_BITS: u16 = 128;
const DEVNET_MAX_PUBLIC_FIELDS: u16 = 14;
const DEVNET_MAX_METADATA_BYTES: u64 = 1_536;
const DEVNET_MAX_SCAN_HINT_BITS: u16 = 10;
const DEVNET_MAX_RECEIPT_DISCLOSURE_UNITS: u16 = 5;
const DEVNET_MIN_ENCRYPTED_RECEIPT_SHARDS: u16 = 3;
const DEVNET_MIN_COMMITTED_PRIVATE_FIELDS: u16 = 11;
const DEVNET_MIN_PQ_SECURITY_BITS: u16 = 192;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceVerdict {
    Accepted,
    Held,
    Rejected,
}

impl AcceptanceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }

    pub fn release_allowed(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClass {
    Public,
    Committed,
    Encrypted,
    WalletLocal,
}

impl DisclosureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Committed => "committed",
            Self::Encrypted => "encrypted",
            Self::WalletLocal => "wallet_local",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSurface {
    DepositMembership,
    ExitNullifier,
    OutputCommitment,
    WalletScanHint,
    MetadataBudget,
    DecoyDistribution,
    LinkageGuard,
    ReceiptDisclosure,
    PqAuthorization,
    ReleaseHold,
}

impl EvidenceSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositMembership => "deposit_membership",
            Self::ExitNullifier => "exit_nullifier",
            Self::OutputCommitment => "output_commitment",
            Self::WalletScanHint => "wallet_scan_hint",
            Self::MetadataBudget => "metadata_budget",
            Self::DecoyDistribution => "decoy_distribution",
            Self::LinkageGuard => "linkage_guard",
            Self::ReceiptDisclosure => "receipt_disclosure",
            Self::PqAuthorization => "pq_authorization",
            Self::ReleaseHold => "release_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHoldReason {
    PrivacyEvidenceMissing,
    MetadataBudgetExceeded,
    LinkageGuardFailed,
    ReceiptDisclosureTooBroad,
    DecoyEvidenceThin,
    PqEvidenceInsufficient,
}

impl ReleaseHoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivacyEvidenceMissing => "privacy_evidence_missing",
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::LinkageGuardFailed => "linkage_guard_failed",
            Self::ReceiptDisclosureTooBroad => "receipt_disclosure_too_broad",
            Self::DecoyEvidenceThin => "decoy_evidence_thin",
            Self::PqEvidenceInsufficient => "pq_evidence_insufficient",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub acceptance_suite: String,
    pub scenario_id: String,
    pub evaluation_height: u64,
    pub min_monero_confirmations: u64,
    pub min_ring_decoys: u16,
    pub min_decoy_spread_epochs: u16,
    pub min_anonymity_set: u64,
    pub min_nullifier_separation_bits: u16,
    pub min_key_image_separation_bits: u16,
    pub max_public_fields: u16,
    pub max_metadata_bytes: u64,
    pub max_scan_hint_bits: u16,
    pub max_receipt_disclosure_units: u16,
    pub min_encrypted_receipt_shards: u16,
    pub min_committed_private_fields: u16,
    pub min_pq_security_bits: u16,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            acceptance_suite: ACCEPTANCE_SUITE.to_string(),
            scenario_id: DEVNET_SCENARIO_ID.to_string(),
            evaluation_height: DEVNET_EVALUATION_HEIGHT,
            min_monero_confirmations: DEVNET_MIN_MONERO_CONFIRMATIONS,
            min_ring_decoys: DEVNET_MIN_RING_DECOYS,
            min_decoy_spread_epochs: DEVNET_MIN_DECOY_SPREAD_EPOCHS,
            min_anonymity_set: DEVNET_MIN_ANONYMITY_SET,
            min_nullifier_separation_bits: DEVNET_MIN_NULLIFIER_SEPARATION_BITS,
            min_key_image_separation_bits: DEVNET_MIN_KEY_IMAGE_SEPARATION_BITS,
            max_public_fields: DEVNET_MAX_PUBLIC_FIELDS,
            max_metadata_bytes: DEVNET_MAX_METADATA_BYTES,
            max_scan_hint_bits: DEVNET_MAX_SCAN_HINT_BITS,
            max_receipt_disclosure_units: DEVNET_MAX_RECEIPT_DISCLOSURE_UNITS,
            min_encrypted_receipt_shards: DEVNET_MIN_ENCRYPTED_RECEIPT_SHARDS,
            min_committed_private_fields: DEVNET_MIN_COMMITTED_PRIVATE_FIELDS,
            min_pq_security_bits: DEVNET_MIN_PQ_SECURITY_BITS,
            fail_closed: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "acceptance_suite": self.acceptance_suite,
            "scenario_id": self.scenario_id,
            "evaluation_height": self.evaluation_height,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_ring_decoys": self.min_ring_decoys,
            "min_decoy_spread_epochs": self.min_decoy_spread_epochs,
            "min_anonymity_set": self.min_anonymity_set,
            "min_nullifier_separation_bits": self.min_nullifier_separation_bits,
            "min_key_image_separation_bits": self.min_key_image_separation_bits,
            "max_public_fields": self.max_public_fields,
            "max_metadata_bytes": self.max_metadata_bytes,
            "max_scan_hint_bits": self.max_scan_hint_bits,
            "max_receipt_disclosure_units": self.max_receipt_disclosure_units,
            "min_encrypted_receipt_shards": self.min_encrypted_receipt_shards,
            "min_committed_private_fields": self.min_committed_private_fields,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicDisclosureField {
    pub field_id: String,
    pub surface: EvidenceSurface,
    pub disclosure_class: DisclosureClass,
    pub public_label: String,
    pub value_root: String,
    pub budget_units: u16,
    pub rationale: String,
}

impl PublicDisclosureField {
    pub fn public_record(&self) -> Value {
        json!({
            "field_id": self.field_id,
            "surface": self.surface.as_str(),
            "disclosure_class": self.disclosure_class.as_str(),
            "public_label": self.public_label,
            "value_root": self.value_root,
            "budget_units": self.budget_units,
            "rationale": self.rationale,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("public-disclosure-field", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateCommitment {
    pub commitment_id: String,
    pub surface: EvidenceSurface,
    pub disclosure_class: DisclosureClass,
    pub commitment_root: String,
    pub encryption_root: String,
    pub verifier_hint_root: String,
    pub required_for_acceptance: bool,
    pub revealed_in_receipt: bool,
}

impl PrivateCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "surface": self.surface.as_str(),
            "disclosure_class": self.disclosure_class.as_str(),
            "commitment_root": self.commitment_root,
            "encryption_root": self.encryption_root,
            "verifier_hint_root": self.verifier_hint_root,
            "required_for_acceptance": self.required_for_acceptance,
            "revealed_in_receipt": self.revealed_in_receipt,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private-commitment", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub scan_hint_root: String,
    pub encrypted_payload_root: String,
    pub view_tag_prefix_bits: u16,
    pub subaddress_bucket_bits: u16,
    pub output_index_window: u16,
    pub wallet_local_only: bool,
    pub deterministic_scan_order: u16,
}

impl WalletScanHint {
    pub fn exposure_bits(&self) -> u16 {
        self.view_tag_prefix_bits + self.subaddress_bucket_bits
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "scan_hint_root": self.scan_hint_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "view_tag_prefix_bits": self.view_tag_prefix_bits,
            "subaddress_bucket_bits": self.subaddress_bucket_bits,
            "output_index_window": self.output_index_window,
            "wallet_local_only": self.wallet_local_only,
            "deterministic_scan_order": self.deterministic_scan_order,
            "exposure_bits": self.exposure_bits(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet-scan-hint", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataBudget {
    pub budget_id: String,
    pub surface: EvidenceSurface,
    pub allowed_bytes: u64,
    pub observed_bytes: u64,
    pub allowed_public_fields: u16,
    pub observed_public_fields: u16,
    pub allowed_scan_hint_bits: u16,
    pub observed_scan_hint_bits: u16,
    pub deterministic_padding_bytes: u64,
    pub within_budget: bool,
}

impl MetadataBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "surface": self.surface.as_str(),
            "allowed_bytes": self.allowed_bytes,
            "observed_bytes": self.observed_bytes,
            "allowed_public_fields": self.allowed_public_fields,
            "observed_public_fields": self.observed_public_fields,
            "allowed_scan_hint_bits": self.allowed_scan_hint_bits,
            "observed_scan_hint_bits": self.observed_scan_hint_bits,
            "deterministic_padding_bytes": self.deterministic_padding_bytes,
            "within_budget": self.within_budget,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("metadata-budget", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyGuard {
    pub guard_id: String,
    pub ring_decoys: u16,
    pub decoy_spread_epochs: u16,
    pub anonymity_set: u64,
    pub youngest_decoy_lag: u64,
    pub oldest_decoy_lag: u64,
    pub histogram_root: String,
    pub guard_passed: bool,
}

impl DecoyGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "ring_decoys": self.ring_decoys,
            "decoy_spread_epochs": self.decoy_spread_epochs,
            "anonymity_set": self.anonymity_set,
            "youngest_decoy_lag": self.youngest_decoy_lag,
            "oldest_decoy_lag": self.oldest_decoy_lag,
            "histogram_root": self.histogram_root,
            "guard_passed": self.guard_passed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("decoy-guard", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkageGuard {
    pub guard_id: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub deposit_note_link_root: String,
    pub nullifier_separation_bits: u16,
    pub key_image_separation_bits: u16,
    pub repeated_public_tuple_count: u16,
    pub cross_domain_linkage_hits: u16,
    pub guard_passed: bool,
}

impl LinkageGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "deposit_note_link_root": self.deposit_note_link_root,
            "nullifier_separation_bits": self.nullifier_separation_bits,
            "key_image_separation_bits": self.key_image_separation_bits,
            "repeated_public_tuple_count": self.repeated_public_tuple_count,
            "cross_domain_linkage_hits": self.cross_domain_linkage_hits,
            "guard_passed": self.guard_passed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("linkage-guard", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptDisclosureBound {
    pub bound_id: String,
    pub max_disclosure_units: u16,
    pub observed_disclosure_units: u16,
    pub encrypted_receipt_shards: u16,
    pub committed_private_fields: u16,
    pub public_receipt_fields: u16,
    pub disclosure_root: String,
    pub bound_passed: bool,
}

impl ReceiptDisclosureBound {
    pub fn public_record(&self) -> Value {
        json!({
            "bound_id": self.bound_id,
            "max_disclosure_units": self.max_disclosure_units,
            "observed_disclosure_units": self.observed_disclosure_units,
            "encrypted_receipt_shards": self.encrypted_receipt_shards,
            "committed_private_fields": self.committed_private_fields,
            "public_receipt_fields": self.public_receipt_fields,
            "disclosure_root": self.disclosure_root,
            "bound_passed": self.bound_passed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-disclosure-bound", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptanceRecord {
    pub record_id: String,
    pub exit_claim_id: String,
    pub deposit_membership_root: String,
    pub output_commitment_root: String,
    pub wallet_hint_root: String,
    pub privacy_evidence_root: String,
    pub public_disclosure_root: String,
    pub private_commitment_root: String,
    pub guard_root: String,
    pub verdict: AcceptanceVerdict,
    pub release_hold: bool,
    pub release_hold_reasons: Vec<ReleaseHoldReason>,
    pub record_root: String,
}

impl AcceptanceRecord {
    pub fn public_record(&self) -> Value {
        let hold_reasons: Vec<&str> = self
            .release_hold_reasons
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        json!({
            "record_id": self.record_id,
            "exit_claim_id": self.exit_claim_id,
            "deposit_membership_root": self.deposit_membership_root,
            "output_commitment_root": self.output_commitment_root,
            "wallet_hint_root": self.wallet_hint_root,
            "privacy_evidence_root": self.privacy_evidence_root,
            "public_disclosure_root": self.public_disclosure_root,
            "private_commitment_root": self.private_commitment_root,
            "guard_root": self.guard_root,
            "verdict": self.verdict.as_str(),
            "release_hold": self.release_hold,
            "release_hold_reasons": hold_reasons,
            "record_root": self.record_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("acceptance-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub record_id: String,
    pub reasons: Vec<ReleaseHoldReason>,
    pub required_evidence: Vec<EvidenceSurface>,
    pub observed_evidence_root: String,
    pub hold_root: String,
    pub release_allowed: bool,
}

impl ReleaseHold {
    pub fn public_record(&self) -> Value {
        let reasons: Vec<&str> = self.reasons.iter().map(|reason| reason.as_str()).collect();
        let required_evidence: Vec<&str> = self
            .required_evidence
            .iter()
            .map(|surface| surface.as_str())
            .collect();
        json!({
            "hold_id": self.hold_id,
            "record_id": self.record_id,
            "reasons": reasons,
            "required_evidence": required_evidence,
            "observed_evidence_root": self.observed_evidence_root,
            "hold_root": self.hold_root,
            "release_allowed": self.release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-hold", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub public_fields: Vec<PublicDisclosureField>,
    pub private_commitments: Vec<PrivateCommitment>,
    pub wallet_scan_hints: Vec<WalletScanHint>,
    pub metadata_budgets: Vec<MetadataBudget>,
    pub decoy_guards: Vec<DecoyGuard>,
    pub linkage_guards: Vec<LinkageGuard>,
    pub receipt_bounds: Vec<ReceiptDisclosureBound>,
    pub acceptance_records: Vec<AcceptanceRecord>,
    pub release_holds: Vec<ReleaseHold>,
    pub surface_roots: BTreeMap<String, String>,
    pub accepted_record_root: String,
    pub held_record_root: String,
    pub rejected_record_root: String,
    pub release_hold_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let public_fields = devnet_public_fields();
        let private_commitments = devnet_private_commitments();
        let wallet_scan_hints = devnet_wallet_scan_hints();
        let metadata_budgets = devnet_metadata_budgets(&config, &public_fields, &wallet_scan_hints);
        let decoy_guards = devnet_decoy_guards(&config);
        let linkage_guards = devnet_linkage_guards(&config);
        let receipt_bounds = devnet_receipt_bounds(&config);

        let public_disclosure_root = merkle_from_strings(
            "public-disclosure-root",
            public_fields
                .iter()
                .map(PublicDisclosureField::state_root)
                .collect(),
        );
        let private_commitment_root = merkle_from_strings(
            "private-commitment-root",
            private_commitments
                .iter()
                .map(PrivateCommitment::state_root)
                .collect(),
        );
        let wallet_hint_root = merkle_from_strings(
            "wallet-hint-root",
            wallet_scan_hints
                .iter()
                .map(WalletScanHint::state_root)
                .collect(),
        );
        let metadata_budget_root = merkle_from_strings(
            "metadata-budget-root",
            metadata_budgets
                .iter()
                .map(MetadataBudget::state_root)
                .collect(),
        );
        let decoy_guard_root = merkle_from_strings(
            "decoy-guard-root",
            decoy_guards.iter().map(DecoyGuard::state_root).collect(),
        );
        let linkage_guard_root = merkle_from_strings(
            "linkage-guard-root",
            linkage_guards
                .iter()
                .map(LinkageGuard::state_root)
                .collect(),
        );
        let receipt_bound_root = merkle_from_strings(
            "receipt-bound-root",
            receipt_bounds
                .iter()
                .map(ReceiptDisclosureBound::state_root)
                .collect(),
        );

        let guard_root = merkle_from_strings(
            "guard-root",
            vec![
                metadata_budget_root.clone(),
                decoy_guard_root.clone(),
                linkage_guard_root.clone(),
                receipt_bound_root.clone(),
            ],
        );
        let privacy_evidence_root = merkle_from_strings(
            "privacy-evidence-root",
            vec![
                public_disclosure_root.clone(),
                private_commitment_root.clone(),
                wallet_hint_root.clone(),
                guard_root.clone(),
            ],
        );

        let acceptance_records = vec![
            acceptance_record(
                "acceptance-record-devnet-clean-0001",
                "exit-claim-devnet-clean-0001",
                AcceptanceVerdict::Accepted,
                false,
                Vec::new(),
                &public_disclosure_root,
                &private_commitment_root,
                &wallet_hint_root,
                &privacy_evidence_root,
                &guard_root,
            ),
            acceptance_record(
                "acceptance-record-devnet-held-0002",
                "exit-claim-devnet-held-0002",
                AcceptanceVerdict::Held,
                true,
                vec![
                    ReleaseHoldReason::PrivacyEvidenceMissing,
                    ReleaseHoldReason::DecoyEvidenceThin,
                ],
                &public_disclosure_root,
                &private_commitment_root,
                &wallet_hint_root,
                &privacy_evidence_root,
                &guard_root,
            ),
            acceptance_record(
                "acceptance-record-devnet-rejected-0003",
                "exit-claim-devnet-rejected-0003",
                AcceptanceVerdict::Rejected,
                true,
                vec![
                    ReleaseHoldReason::MetadataBudgetExceeded,
                    ReleaseHoldReason::LinkageGuardFailed,
                    ReleaseHoldReason::ReceiptDisclosureTooBroad,
                ],
                &public_disclosure_root,
                &private_commitment_root,
                &wallet_hint_root,
                &privacy_evidence_root,
                &guard_root,
            ),
        ];

        let release_holds = acceptance_records
            .iter()
            .filter(|record| record.release_hold)
            .map(|record| release_hold(record, &privacy_evidence_root))
            .collect::<Vec<_>>();

        let mut surface_roots = BTreeMap::new();
        surface_roots.insert("public_disclosure_root".to_string(), public_disclosure_root);
        surface_roots.insert(
            "private_commitment_root".to_string(),
            private_commitment_root,
        );
        surface_roots.insert("wallet_hint_root".to_string(), wallet_hint_root);
        surface_roots.insert("metadata_budget_root".to_string(), metadata_budget_root);
        surface_roots.insert("decoy_guard_root".to_string(), decoy_guard_root);
        surface_roots.insert("linkage_guard_root".to_string(), linkage_guard_root);
        surface_roots.insert("receipt_bound_root".to_string(), receipt_bound_root);
        surface_roots.insert("guard_root".to_string(), guard_root);
        surface_roots.insert("privacy_evidence_root".to_string(), privacy_evidence_root);

        let accepted_record_root =
            record_root_by_verdict(&acceptance_records, AcceptanceVerdict::Accepted);
        let held_record_root = record_root_by_verdict(&acceptance_records, AcceptanceVerdict::Held);
        let rejected_record_root =
            record_root_by_verdict(&acceptance_records, AcceptanceVerdict::Rejected);
        let release_hold_root = merkle_from_strings(
            "release-hold-root",
            release_holds.iter().map(ReleaseHold::state_root).collect(),
        );

        Self {
            config,
            public_fields,
            private_commitments,
            wallet_scan_hints,
            metadata_budgets,
            decoy_guards,
            linkage_guards,
            receipt_bounds,
            acceptance_records,
            release_holds,
            surface_roots,
            accepted_record_root,
            held_record_root,
            rejected_record_root,
            release_hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "public_fields": self.public_fields.iter().map(PublicDisclosureField::public_record).collect::<Vec<_>>(),
            "private_commitments": self.private_commitments.iter().map(PrivateCommitment::public_record).collect::<Vec<_>>(),
            "wallet_scan_hints": self.wallet_scan_hints.iter().map(WalletScanHint::public_record).collect::<Vec<_>>(),
            "metadata_budgets": self.metadata_budgets.iter().map(MetadataBudget::public_record).collect::<Vec<_>>(),
            "decoy_guards": self.decoy_guards.iter().map(DecoyGuard::public_record).collect::<Vec<_>>(),
            "linkage_guards": self.linkage_guards.iter().map(LinkageGuard::public_record).collect::<Vec<_>>(),
            "receipt_bounds": self.receipt_bounds.iter().map(ReceiptDisclosureBound::public_record).collect::<Vec<_>>(),
            "acceptance_records": self.acceptance_records.iter().map(AcceptanceRecord::public_record).collect::<Vec<_>>(),
            "release_holds": self.release_holds.iter().map(ReleaseHold::public_record).collect::<Vec<_>>(),
            "surface_roots": self.surface_roots,
            "accepted_record_root": self.accepted_record_root,
            "held_record_root": self.held_record_root,
            "rejected_record_root": self.rejected_record_root,
            "release_hold_root": self.release_hold_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-PRESERVING-ACCEPTANCE-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.accepted_record_root),
                HashPart::Str(&self.held_record_root),
                HashPart::Str(&self.rejected_record_root),
                HashPart::Str(&self.release_hold_root),
                HashPart::Json(self.surface_roots.clone()),
            ],
            32,
        )
    }

    pub fn accepted_records(&self) -> Vec<AcceptanceRecord> {
        self.acceptance_records
            .iter()
            .filter(|record| record.verdict == AcceptanceVerdict::Accepted)
            .cloned()
            .collect()
    }

    pub fn held_records(&self) -> Vec<AcceptanceRecord> {
        self.acceptance_records
            .iter()
            .filter(|record| record.verdict == AcceptanceVerdict::Held)
            .cloned()
            .collect()
    }

    pub fn release_allowed(&self, record_id: &str) -> Result<bool> {
        self.acceptance_records
            .iter()
            .find(|record| record.record_id == record_id)
            .map(|record| record.verdict.release_allowed() && !record.release_hold)
            .ok_or_else(|| format!("acceptance record not found: {record_id}"))
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn devnet_public_fields() -> Vec<PublicDisclosureField> {
    vec![
        public_field(
            "public-field-chain",
            EvidenceSurface::DepositMembership,
            "chain_id",
            CHAIN_ID,
            1,
            "binds the record to the public bridge domain",
        ),
        public_field(
            "public-field-protocol",
            EvidenceSurface::DepositMembership,
            "protocol_version",
            PROTOCOL_VERSION,
            1,
            "permits deterministic replay of the acceptance rules",
        ),
        public_field(
            "public-field-height",
            EvidenceSurface::DepositMembership,
            "evaluation_height",
            &DEVNET_EVALUATION_HEIGHT.to_string(),
            1,
            "anchors the acceptance batch without exposing wallet timing",
        ),
        public_field(
            "public-field-asset",
            EvidenceSurface::OutputCommitment,
            "asset_id",
            "wxmr-devnet",
            1,
            "declares the bridge asset while value remains committed",
        ),
        public_field(
            "public-field-claim",
            EvidenceSurface::ExitNullifier,
            "exit_claim_root",
            "exit-claim-root-devnet",
            2,
            "publishes only a claim root for deduplication",
        ),
        public_field(
            "public-field-quorum",
            EvidenceSurface::PqAuthorization,
            "pq_watcher_quorum_root",
            "pq-watcher-quorum-root-devnet",
            2,
            "commits watcher authority without listing signer metadata",
        ),
        public_field(
            "public-field-receipt",
            EvidenceSurface::ReceiptDisclosure,
            "receipt_policy_root",
            "receipt-policy-root-devnet",
            2,
            "states disclosure policy rather than private receipt contents",
        ),
    ]
}

fn devnet_private_commitments() -> Vec<PrivateCommitment> {
    vec![
        private_commitment(
            "commitment-deposit-tx",
            EvidenceSurface::DepositMembership,
            true,
        ),
        private_commitment(
            "commitment-source-output",
            EvidenceSurface::DepositMembership,
            true,
        ),
        private_commitment(
            "commitment-exit-nullifier",
            EvidenceSurface::ExitNullifier,
            true,
        ),
        private_commitment(
            "commitment-recipient-output",
            EvidenceSurface::OutputCommitment,
            true,
        ),
        private_commitment(
            "commitment-change-output",
            EvidenceSurface::OutputCommitment,
            true,
        ),
        private_commitment(
            "commitment-wallet-view-hint",
            EvidenceSurface::WalletScanHint,
            true,
        ),
        private_commitment(
            "commitment-decoy-histogram",
            EvidenceSurface::DecoyDistribution,
            true,
        ),
        private_commitment(
            "commitment-linkage-transcript",
            EvidenceSurface::LinkageGuard,
            true,
        ),
        private_commitment(
            "commitment-receipt-shards",
            EvidenceSurface::ReceiptDisclosure,
            true,
        ),
        private_commitment(
            "commitment-pq-auth-payload",
            EvidenceSurface::PqAuthorization,
            true,
        ),
        private_commitment(
            "commitment-release-evidence",
            EvidenceSurface::ReleaseHold,
            false,
        ),
    ]
}

fn devnet_wallet_scan_hints() -> Vec<WalletScanHint> {
    (0..4)
        .map(|index| {
            let hint_id = format!("wallet-scan-hint-devnet-{index:04}");
            WalletScanHint {
                scan_hint_root: label_root("scan-hint", &hint_id),
                encrypted_payload_root: label_root("encrypted-scan-payload", &hint_id),
                hint_id,
                view_tag_prefix_bits: 6,
                subaddress_bucket_bits: if index == 3 { 3 } else { 2 },
                output_index_window: 32 + index,
                wallet_local_only: true,
                deterministic_scan_order: index,
            }
        })
        .collect()
}

fn devnet_metadata_budgets(
    config: &Config,
    public_fields: &[PublicDisclosureField],
    wallet_scan_hints: &[WalletScanHint],
) -> Vec<MetadataBudget> {
    let observed_public_fields = public_fields.len() as u16;
    let observed_scan_hint_bits = wallet_scan_hints
        .iter()
        .map(WalletScanHint::exposure_bits)
        .max()
        .unwrap_or(0);
    vec![
        metadata_budget(
            "metadata-budget-public-fields",
            EvidenceSurface::MetadataBudget,
            config.max_metadata_bytes,
            928,
            config.max_public_fields,
            observed_public_fields,
            config.max_scan_hint_bits,
            observed_scan_hint_bits,
            256,
        ),
        metadata_budget(
            "metadata-budget-receipt-envelope",
            EvidenceSurface::ReceiptDisclosure,
            config.max_metadata_bytes,
            1_152,
            config.max_public_fields,
            9,
            config.max_scan_hint_bits,
            8,
            384,
        ),
        metadata_budget(
            "metadata-budget-wallet-local",
            EvidenceSurface::WalletScanHint,
            config.max_metadata_bytes,
            768,
            config.max_public_fields,
            3,
            config.max_scan_hint_bits,
            observed_scan_hint_bits,
            512,
        ),
    ]
}

fn devnet_decoy_guards(config: &Config) -> Vec<DecoyGuard> {
    vec![
        decoy_guard(
            "decoy-guard-main-ring",
            config.min_ring_decoys + 1,
            config.min_decoy_spread_epochs + 2,
            config.min_anonymity_set + 65_536,
            48,
            19_200,
        ),
        decoy_guard(
            "decoy-guard-change-ring",
            config.min_ring_decoys,
            config.min_decoy_spread_epochs,
            config.min_anonymity_set,
            64,
            22_400,
        ),
    ]
}

fn devnet_linkage_guards(config: &Config) -> Vec<LinkageGuard> {
    vec![
        linkage_guard(
            "linkage-guard-nullifier-domain",
            config.min_nullifier_separation_bits + 4,
            config.min_key_image_separation_bits + 4,
            0,
            0,
        ),
        linkage_guard(
            "linkage-guard-deposit-output",
            config.min_nullifier_separation_bits,
            config.min_key_image_separation_bits,
            0,
            0,
        ),
    ]
}

fn devnet_receipt_bounds(config: &Config) -> Vec<ReceiptDisclosureBound> {
    vec![
        receipt_bound(
            "receipt-bound-wallet-copy",
            config.max_receipt_disclosure_units,
            3,
            config.min_encrypted_receipt_shards,
            config.min_committed_private_fields + 2,
            5,
        ),
        receipt_bound(
            "receipt-bound-public-audit-copy",
            config.max_receipt_disclosure_units,
            4,
            config.min_encrypted_receipt_shards + 1,
            config.min_committed_private_fields,
            6,
        ),
    ]
}

fn public_field(
    field_id: &str,
    surface: EvidenceSurface,
    public_label: &str,
    value: &str,
    budget_units: u16,
    rationale: &str,
) -> PublicDisclosureField {
    PublicDisclosureField {
        field_id: field_id.to_string(),
        surface,
        disclosure_class: DisclosureClass::Public,
        public_label: public_label.to_string(),
        value_root: label_root(public_label, value),
        budget_units,
        rationale: rationale.to_string(),
    }
}

fn private_commitment(
    commitment_id: &str,
    surface: EvidenceSurface,
    required_for_acceptance: bool,
) -> PrivateCommitment {
    PrivateCommitment {
        commitment_id: commitment_id.to_string(),
        surface,
        disclosure_class: match surface {
            EvidenceSurface::WalletScanHint => DisclosureClass::WalletLocal,
            EvidenceSurface::ReceiptDisclosure => DisclosureClass::Encrypted,
            _ => DisclosureClass::Committed,
        },
        commitment_root: label_root("commitment", commitment_id),
        encryption_root: label_root("encryption", commitment_id),
        verifier_hint_root: label_root("verifier-hint", commitment_id),
        required_for_acceptance,
        revealed_in_receipt: false,
    }
}

fn metadata_budget(
    budget_id: &str,
    surface: EvidenceSurface,
    allowed_bytes: u64,
    observed_bytes: u64,
    allowed_public_fields: u16,
    observed_public_fields: u16,
    allowed_scan_hint_bits: u16,
    observed_scan_hint_bits: u16,
    deterministic_padding_bytes: u64,
) -> MetadataBudget {
    MetadataBudget {
        budget_id: budget_id.to_string(),
        surface,
        allowed_bytes,
        observed_bytes,
        allowed_public_fields,
        observed_public_fields,
        allowed_scan_hint_bits,
        observed_scan_hint_bits,
        deterministic_padding_bytes,
        within_budget: observed_bytes <= allowed_bytes
            && observed_public_fields <= allowed_public_fields
            && observed_scan_hint_bits <= allowed_scan_hint_bits,
    }
}

fn decoy_guard(
    guard_id: &str,
    ring_decoys: u16,
    decoy_spread_epochs: u16,
    anonymity_set: u64,
    youngest_decoy_lag: u64,
    oldest_decoy_lag: u64,
) -> DecoyGuard {
    DecoyGuard {
        guard_id: guard_id.to_string(),
        ring_decoys,
        decoy_spread_epochs,
        anonymity_set,
        youngest_decoy_lag,
        oldest_decoy_lag,
        histogram_root: label_root("decoy-histogram", guard_id),
        guard_passed: ring_decoys >= DEVNET_MIN_RING_DECOYS
            && decoy_spread_epochs >= DEVNET_MIN_DECOY_SPREAD_EPOCHS
            && anonymity_set >= DEVNET_MIN_ANONYMITY_SET,
    }
}

fn linkage_guard(
    guard_id: &str,
    nullifier_separation_bits: u16,
    key_image_separation_bits: u16,
    repeated_public_tuple_count: u16,
    cross_domain_linkage_hits: u16,
) -> LinkageGuard {
    LinkageGuard {
        guard_id: guard_id.to_string(),
        nullifier_root: label_root("nullifier", guard_id),
        key_image_root: label_root("key-image", guard_id),
        deposit_note_link_root: label_root("deposit-note-link", guard_id),
        nullifier_separation_bits,
        key_image_separation_bits,
        repeated_public_tuple_count,
        cross_domain_linkage_hits,
        guard_passed: nullifier_separation_bits >= DEVNET_MIN_NULLIFIER_SEPARATION_BITS
            && key_image_separation_bits >= DEVNET_MIN_KEY_IMAGE_SEPARATION_BITS
            && repeated_public_tuple_count == 0
            && cross_domain_linkage_hits == 0,
    }
}

fn receipt_bound(
    bound_id: &str,
    max_disclosure_units: u16,
    observed_disclosure_units: u16,
    encrypted_receipt_shards: u16,
    committed_private_fields: u16,
    public_receipt_fields: u16,
) -> ReceiptDisclosureBound {
    ReceiptDisclosureBound {
        bound_id: bound_id.to_string(),
        max_disclosure_units,
        observed_disclosure_units,
        encrypted_receipt_shards,
        committed_private_fields,
        public_receipt_fields,
        disclosure_root: label_root("receipt-disclosure", bound_id),
        bound_passed: observed_disclosure_units <= max_disclosure_units
            && encrypted_receipt_shards >= DEVNET_MIN_ENCRYPTED_RECEIPT_SHARDS
            && committed_private_fields >= DEVNET_MIN_COMMITTED_PRIVATE_FIELDS,
    }
}

fn acceptance_record(
    record_id: &str,
    exit_claim_id: &str,
    verdict: AcceptanceVerdict,
    release_hold: bool,
    release_hold_reasons: Vec<ReleaseHoldReason>,
    public_disclosure_root: &str,
    private_commitment_root: &str,
    wallet_hint_root: &str,
    privacy_evidence_root: &str,
    guard_root: &str,
) -> AcceptanceRecord {
    let deposit_membership_root = label_root("deposit-membership", exit_claim_id);
    let output_commitment_root = label_root("output-commitment", exit_claim_id);
    let record_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-PRESERVING-ACCEPTANCE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_id),
            HashPart::Str(exit_claim_id),
            HashPart::Str(&deposit_membership_root),
            HashPart::Str(&output_commitment_root),
            HashPart::Str(wallet_hint_root),
            HashPart::Str(privacy_evidence_root),
            HashPart::Str(public_disclosure_root),
            HashPart::Str(private_commitment_root),
            HashPart::Str(guard_root),
            HashPart::Str(verdict.as_str()),
            HashPart::Int(if release_hold { 1 } else { 0 }),
        ],
        32,
    );
    AcceptanceRecord {
        record_id: record_id.to_string(),
        exit_claim_id: exit_claim_id.to_string(),
        deposit_membership_root,
        output_commitment_root,
        wallet_hint_root: wallet_hint_root.to_string(),
        privacy_evidence_root: privacy_evidence_root.to_string(),
        public_disclosure_root: public_disclosure_root.to_string(),
        private_commitment_root: private_commitment_root.to_string(),
        guard_root: guard_root.to_string(),
        verdict,
        release_hold,
        release_hold_reasons,
        record_root,
    }
}

fn release_hold(record: &AcceptanceRecord, privacy_evidence_root: &str) -> ReleaseHold {
    let required_evidence = record
        .release_hold_reasons
        .iter()
        .map(|reason| match reason {
            ReleaseHoldReason::PrivacyEvidenceMissing => EvidenceSurface::DepositMembership,
            ReleaseHoldReason::MetadataBudgetExceeded => EvidenceSurface::MetadataBudget,
            ReleaseHoldReason::LinkageGuardFailed => EvidenceSurface::LinkageGuard,
            ReleaseHoldReason::ReceiptDisclosureTooBroad => EvidenceSurface::ReceiptDisclosure,
            ReleaseHoldReason::DecoyEvidenceThin => EvidenceSurface::DecoyDistribution,
            ReleaseHoldReason::PqEvidenceInsufficient => EvidenceSurface::PqAuthorization,
        })
        .collect::<Vec<_>>();
    let hold_id = format!("release-hold-{}", record.record_id);
    let hold_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-PRESERVING-ACCEPTANCE-HOLD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&hold_id),
            HashPart::Str(&record.record_id),
            HashPart::Str(privacy_evidence_root),
            HashPart::Json(
                record
                    .release_hold_reasons
                    .iter()
                    .map(|reason| reason.as_str())
                    .collect::<Vec<_>>(),
            ),
        ],
        32,
    );
    ReleaseHold {
        hold_id,
        record_id: record.record_id.clone(),
        reasons: record.release_hold_reasons.clone(),
        required_evidence,
        observed_evidence_root: privacy_evidence_root.to_string(),
        hold_root,
        release_allowed: false,
    }
}

fn record_root_by_verdict(records: &[AcceptanceRecord], verdict: AcceptanceVerdict) -> String {
    merkle_from_strings(
        verdict.as_str(),
        records
            .iter()
            .filter(|record| record.verdict == verdict)
            .map(AcceptanceRecord::state_root)
            .collect(),
    )
}

fn label_root(label: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-PRESERVING-ACCEPTANCE-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVACY-PRESERVING-ACCEPTANCE-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record.clone()),
        ],
        32,
    )
}

fn merkle_from_strings(label: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        return label_root("empty-merkle", label);
    }
    let leaf_refs = leaves.iter().map(String::as_str).collect::<Vec<_>>();
    merkle_root(label, &leaf_refs)
}
