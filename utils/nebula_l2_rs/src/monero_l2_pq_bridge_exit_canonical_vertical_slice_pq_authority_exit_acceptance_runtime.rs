use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePqAuthorityExitAcceptanceRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_AUTHORITY_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-authority-exit-acceptance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_AUTHORITY_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACCEPTANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-authority-exit-acceptance-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_AUTHORITY_EPOCH: u64 = 73;
pub const DEFAULT_PREVIOUS_AUTHORITY_EPOCH: u64 = 72;
pub const DEFAULT_MONERO_HEIGHT: u64 = 2_771_552;
pub const DEFAULT_L2_HEIGHT: u64 = 884_336;
pub const DEFAULT_RELEASE_HEIGHT: u64 = 884_384;
pub const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MIN_WATCHER_COUNT: u16 = 5;
pub const DEFAULT_MIN_AUTHORITY_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MIN_AUTHORITY_SIGNATURES: u16 = 3;
pub const DEFAULT_MIN_EPOCH_CONTINUITY_LINKS: u16 = 2;
pub const DEFAULT_MAX_STALE_WATCHERS: u16 = 1;
pub const DEFAULT_MAX_ROTATION_LAG_BLOCKS: u64 = 96;
pub const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 48;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsaShake,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsaShake => "hybrid_ml_dsa_slh_dsa_shake",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceStatus {
    Accepted,
    Held,
    Rejected,
}

impl AcceptanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }

    pub fn releases_funds(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherVoteStatus {
    Accepted,
    Stale,
    Missing,
    Conflicting,
}

impl WatcherVoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Stale => "stale",
            Self::Missing => "missing",
            Self::Conflicting => "conflicting",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Authorized,
    Pending,
    Denied,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Pending => "pending",
            Self::Denied => "denied",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochContinuityStatus {
    Continuous,
    Grace,
    Broken,
}

impl EpochContinuityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continuous => "continuous",
            Self::Grace => "grace",
            Self::Broken => "broken",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Current,
    PendingActivation,
    Lagging,
    Revoked,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::PendingActivation => "pending_activation",
            Self::Lagging => "lagging",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHoldKind {
    WatcherQuorumShortfall,
    AuthoritySignatureShortfall,
    WithdrawalAuthorizationPending,
    EpochContinuityGap,
    RotationLag,
    AttestationRootMismatch,
    SignatureDomainMismatch,
    EvidenceIncomplete,
    PqSecurityBelowFloor,
}

impl ReleaseHoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherQuorumShortfall => "watcher_quorum_shortfall",
            Self::AuthoritySignatureShortfall => "authority_signature_shortfall",
            Self::WithdrawalAuthorizationPending => "withdrawal_authorization_pending",
            Self::EpochContinuityGap => "epoch_continuity_gap",
            Self::RotationLag => "rotation_lag",
            Self::AttestationRootMismatch => "attestation_root_mismatch",
            Self::SignatureDomainMismatch => "signature_domain_mismatch",
            Self::EvidenceIncomplete => "evidence_incomplete",
            Self::PqSecurityBelowFloor => "pq_security_below_floor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeAttestationKind {
    MoneroLock,
    PrivateNoteBurn,
    WithdrawalClaim,
    ReserveSufficiency,
    SettlementReceipt,
}

impl BridgeAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroLock => "monero_lock",
            Self::PrivateNoteBurn => "private_note_burn",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::ReserveSufficiency => "reserve_sufficiency",
            Self::SettlementReceipt => "settlement_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureDomainKind {
    WatcherQuorum,
    WithdrawalAuthorization,
    EpochContinuity,
    KeyRotation,
    BridgeAttestation,
    ReleaseHold,
}

impl SignatureDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherQuorum => "watcher_quorum",
            Self::WithdrawalAuthorization => "withdrawal_authorization",
            Self::EpochContinuity => "epoch_continuity",
            Self::KeyRotation => "key_rotation",
            Self::BridgeAttestation => "bridge_attestation",
            Self::ReleaseHold => "release_hold",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub acceptance_suite: String,
    pub vertical_slice_id: String,
    pub authority_epoch: u64,
    pub previous_authority_epoch: u64,
    pub monero_height: u64,
    pub l2_height: u64,
    pub release_height: u64,
    pub min_watcher_weight_bps: u16,
    pub min_watcher_count: u16,
    pub min_authority_weight_bps: u16,
    pub min_authority_signatures: u16,
    pub min_epoch_continuity_links: u16,
    pub max_stale_watchers: u16,
    pub max_rotation_lag_blocks: u64,
    pub release_hold_blocks: u64,
    pub min_pq_security_bits: u16,
    pub fail_closed_on_incomplete_evidence: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            acceptance_suite: ACCEPTANCE_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            authority_epoch: DEFAULT_AUTHORITY_EPOCH,
            previous_authority_epoch: DEFAULT_PREVIOUS_AUTHORITY_EPOCH,
            monero_height: DEFAULT_MONERO_HEIGHT,
            l2_height: DEFAULT_L2_HEIGHT,
            release_height: DEFAULT_RELEASE_HEIGHT,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            min_watcher_count: DEFAULT_MIN_WATCHER_COUNT,
            min_authority_weight_bps: DEFAULT_MIN_AUTHORITY_WEIGHT_BPS,
            min_authority_signatures: DEFAULT_MIN_AUTHORITY_SIGNATURES,
            min_epoch_continuity_links: DEFAULT_MIN_EPOCH_CONTINUITY_LINKS,
            max_stale_watchers: DEFAULT_MAX_STALE_WATCHERS,
            max_rotation_lag_blocks: DEFAULT_MAX_ROTATION_LAG_BLOCKS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            fail_closed_on_incomplete_evidence: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "acceptance_suite": self.acceptance_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "authority_epoch": self.authority_epoch,
            "previous_authority_epoch": self.previous_authority_epoch,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "release_height": self.release_height,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "min_watcher_count": self.min_watcher_count,
            "min_authority_weight_bps": self.min_authority_weight_bps,
            "min_authority_signatures": self.min_authority_signatures,
            "min_epoch_continuity_links": self.min_epoch_continuity_links,
            "max_stale_watchers": self.max_stale_watchers,
            "max_rotation_lag_blocks": self.max_rotation_lag_blocks,
            "release_hold_blocks": self.release_hold_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fail_closed_on_incomplete_evidence": self.fail_closed_on_incomplete_evidence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqWatcherVote {
    pub watcher_id: String,
    pub status: WatcherVoteStatus,
    pub weight_bps: u16,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub authority_epoch: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub signature_domain_root: String,
    pub transcript_root: String,
    pub vote_root: String,
}

impl PqWatcherVote {
    pub fn new(
        watcher_id: &str,
        status: WatcherVoteStatus,
        weight_bps: u16,
        observed_monero_height: u64,
        observed_l2_height: u64,
        authority_epoch: u64,
        pq_security_bits: u16,
        attestation_root: &str,
        signature_domain_root: &str,
    ) -> Self {
        let transcript_root = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-WATCHER-TRANSCRIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(watcher_id),
                HashPart::Str(status.as_str()),
                HashPart::U64(weight_bps as u64),
                HashPart::U64(observed_monero_height),
                HashPart::U64(observed_l2_height),
                HashPart::U64(authority_epoch),
                HashPart::U64(pq_security_bits as u64),
                HashPart::Str(attestation_root),
                HashPart::Str(signature_domain_root),
            ],
            32,
        );
        let vote_root = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-WATCHER-VOTE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(watcher_id),
                HashPart::Str(&transcript_root),
            ],
            32,
        );
        Self {
            watcher_id: watcher_id.to_string(),
            status,
            weight_bps,
            observed_monero_height,
            observed_l2_height,
            authority_epoch,
            pq_security_bits,
            attestation_root: attestation_root.to_string(),
            signature_domain_root: signature_domain_root.to_string(),
            transcript_root,
            vote_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "status": self.status.as_str(),
            "weight_bps": self.weight_bps,
            "observed_monero_height": self.observed_monero_height,
            "observed_l2_height": self.observed_l2_height,
            "authority_epoch": self.authority_epoch,
            "pq_security_bits": self.pq_security_bits,
            "attestation_root": self.attestation_root,
            "signature_domain_root": self.signature_domain_root,
            "transcript_root": self.transcript_root,
            "vote_root": self.vote_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherQuorumRecord {
    pub quorum_id: String,
    pub authority_epoch: u64,
    pub accepted_count: u16,
    pub stale_count: u16,
    pub missing_count: u16,
    pub conflicting_count: u16,
    pub accepted_weight_bps: u16,
    pub total_weight_bps: u16,
    pub min_weight_bps: u16,
    pub min_count: u16,
    pub max_stale_watchers: u16,
    pub min_pq_security_bits: u16,
    pub watcher_vote_root: String,
    pub quorum_met: bool,
    pub record_root: String,
}

impl WatcherQuorumRecord {
    pub fn evaluate(config: &Config, votes: &BTreeMap<String, PqWatcherVote>) -> Self {
        let accepted = votes
            .values()
            .filter(|vote| vote.status.counts_for_quorum())
            .collect::<Vec<_>>();
        let accepted_count = accepted.len() as u16;
        let stale_count = votes
            .values()
            .filter(|vote| vote.status == WatcherVoteStatus::Stale)
            .count() as u16;
        let missing_count = votes
            .values()
            .filter(|vote| vote.status == WatcherVoteStatus::Missing)
            .count() as u16;
        let conflicting_count = votes
            .values()
            .filter(|vote| vote.status == WatcherVoteStatus::Conflicting)
            .count() as u16;
        let accepted_weight_bps = capped_bps(
            accepted
                .iter()
                .map(|vote| vote.weight_bps as u64)
                .sum::<u64>(),
        );
        let total_weight_bps = capped_bps(
            votes
                .values()
                .map(|vote| vote.weight_bps as u64)
                .sum::<u64>(),
        );
        let min_pq_security_bits = votes
            .values()
            .map(|vote| vote.pq_security_bits)
            .min()
            .unwrap_or(config.min_pq_security_bits);
        let watcher_records = votes
            .values()
            .map(PqWatcherVote::public_record)
            .collect::<Vec<_>>();
        let watcher_vote_root = merkle_root(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-WATCHER-VOTES",
            &watcher_records,
        );
        let quorum_met = accepted_weight_bps >= config.min_watcher_weight_bps
            && accepted_count >= config.min_watcher_count
            && stale_count <= config.max_stale_watchers
            && min_pq_security_bits >= config.min_pq_security_bits;
        let quorum_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-WATCHER-QUORUM-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::U64(config.authority_epoch),
                HashPart::Str(&watcher_vote_root),
            ],
            32,
        );
        let mut record = Self {
            quorum_id,
            authority_epoch: config.authority_epoch,
            accepted_count,
            stale_count,
            missing_count,
            conflicting_count,
            accepted_weight_bps,
            total_weight_bps,
            min_weight_bps: config.min_watcher_weight_bps,
            min_count: config.min_watcher_count,
            max_stale_watchers: config.max_stale_watchers,
            min_pq_security_bits,
            watcher_vote_root,
            quorum_met,
            record_root: String::new(),
        };
        record.record_root = record_root("WATCHER-QUORUM", &record.public_record_without_root());
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "authority_epoch": self.authority_epoch,
            "accepted_count": self.accepted_count,
            "stale_count": self.stale_count,
            "missing_count": self.missing_count,
            "conflicting_count": self.conflicting_count,
            "accepted_weight_bps": self.accepted_weight_bps,
            "total_weight_bps": self.total_weight_bps,
            "min_weight_bps": self.min_weight_bps,
            "min_count": self.min_count,
            "max_stale_watchers": self.max_stale_watchers,
            "min_pq_security_bits": self.min_pq_security_bits,
            "watcher_vote_root": self.watcher_vote_root,
            "quorum_met": self.quorum_met,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("record_root".to_string(), json!(self.record_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalAuthorization {
    pub authorization_id: String,
    pub claim_id: String,
    pub account_commitment: String,
    pub nullifier_root: String,
    pub amount_commitment: String,
    pub destination_commitment: String,
    pub authority_signature_count: u16,
    pub authority_weight_bps: u16,
    pub min_authority_signatures: u16,
    pub min_authority_weight_bps: u16,
    pub status: AuthorizationStatus,
    pub signature_bundle_root: String,
    pub authorization_root: String,
}

impl WithdrawalAuthorization {
    pub fn new(
        config: &Config,
        claim_id: &str,
        account_commitment: &str,
        nullifier_root: &str,
        amount_commitment: &str,
        destination_commitment: &str,
        authority_signature_count: u16,
        authority_weight_bps: u16,
    ) -> Self {
        let status = if authority_signature_count >= config.min_authority_signatures
            && authority_weight_bps >= config.min_authority_weight_bps
        {
            AuthorizationStatus::Authorized
        } else if authority_signature_count == 0 || authority_weight_bps == 0 {
            AuthorizationStatus::Denied
        } else {
            AuthorizationStatus::Pending
        };
        let signature_bundle_root = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-WITHDRAWAL-SIGNATURE-BUNDLE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(claim_id),
                HashPart::U64(config.authority_epoch),
                HashPart::U64(authority_signature_count as u64),
                HashPart::U64(authority_weight_bps as u64),
                HashPart::Str(account_commitment),
                HashPart::Str(nullifier_root),
                HashPart::Str(amount_commitment),
                HashPart::Str(destination_commitment),
            ],
            32,
        );
        let authorization_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-WITHDRAWAL-AUTHORIZATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(claim_id),
                HashPart::Str(&signature_bundle_root),
            ],
            32,
        );
        let mut authorization = Self {
            authorization_id,
            claim_id: claim_id.to_string(),
            account_commitment: account_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            amount_commitment: amount_commitment.to_string(),
            destination_commitment: destination_commitment.to_string(),
            authority_signature_count,
            authority_weight_bps,
            min_authority_signatures: config.min_authority_signatures,
            min_authority_weight_bps: config.min_authority_weight_bps,
            status,
            signature_bundle_root,
            authorization_root: String::new(),
        };
        authorization.authorization_root = record_root(
            "WITHDRAWAL-AUTHORIZATION",
            &authorization.public_record_without_root(),
        );
        authorization
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "claim_id": self.claim_id,
            "account_commitment": self.account_commitment,
            "nullifier_root": self.nullifier_root,
            "amount_commitment": self.amount_commitment,
            "destination_commitment": self.destination_commitment,
            "authority_signature_count": self.authority_signature_count,
            "authority_weight_bps": self.authority_weight_bps,
            "min_authority_signatures": self.min_authority_signatures,
            "min_authority_weight_bps": self.min_authority_weight_bps,
            "status": self.status.as_str(),
            "signature_bundle_root": self.signature_bundle_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert(
                "authorization_root".to_string(),
                json!(self.authorization_root),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyEpochContinuity {
    pub continuity_id: String,
    pub previous_epoch: u64,
    pub active_epoch: u64,
    pub bridge_key_root: String,
    pub previous_authority_set_root: String,
    pub active_authority_set_root: String,
    pub continuity_link_count: u16,
    pub min_continuity_links: u16,
    pub status: EpochContinuityStatus,
    pub continuity_root: String,
}

impl KeyEpochContinuity {
    pub fn new(
        config: &Config,
        bridge_key_root: &str,
        previous_authority_set_root: &str,
        active_authority_set_root: &str,
        continuity_link_count: u16,
    ) -> Self {
        let expected_next = config.previous_authority_epoch.saturating_add(1);
        let status = if expected_next == config.authority_epoch
            && continuity_link_count >= config.min_epoch_continuity_links
        {
            EpochContinuityStatus::Continuous
        } else if expected_next == config.authority_epoch && continuity_link_count > 0 {
            EpochContinuityStatus::Grace
        } else {
            EpochContinuityStatus::Broken
        };
        let continuity_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-EPOCH-CONTINUITY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::U64(config.previous_authority_epoch),
                HashPart::U64(config.authority_epoch),
                HashPart::Str(bridge_key_root),
                HashPart::Str(previous_authority_set_root),
                HashPart::Str(active_authority_set_root),
            ],
            32,
        );
        let mut continuity = Self {
            continuity_id,
            previous_epoch: config.previous_authority_epoch,
            active_epoch: config.authority_epoch,
            bridge_key_root: bridge_key_root.to_string(),
            previous_authority_set_root: previous_authority_set_root.to_string(),
            active_authority_set_root: active_authority_set_root.to_string(),
            continuity_link_count,
            min_continuity_links: config.min_epoch_continuity_links,
            status,
            continuity_root: String::new(),
        };
        continuity.continuity_root = record_root(
            "KEY-EPOCH-CONTINUITY",
            &continuity.public_record_without_root(),
        );
        continuity
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "continuity_id": self.continuity_id,
            "previous_epoch": self.previous_epoch,
            "active_epoch": self.active_epoch,
            "bridge_key_root": self.bridge_key_root,
            "previous_authority_set_root": self.previous_authority_set_root,
            "active_authority_set_root": self.active_authority_set_root,
            "continuity_link_count": self.continuity_link_count,
            "min_continuity_links": self.min_continuity_links,
            "status": self.status.as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("continuity_root".to_string(), json!(self.continuity_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotationCheckpoint {
    pub rotation_id: String,
    pub key_id: String,
    pub authority_epoch: u64,
    pub activated_at_l2_height: u64,
    pub observed_at_l2_height: u64,
    pub rotation_status: RotationStatus,
    pub pq_security_bits: u16,
    pub rotation_lag_blocks: u64,
    pub rotation_proof_root: String,
    pub checkpoint_root: String,
}

impl RotationCheckpoint {
    pub fn new(
        config: &Config,
        key_id: &str,
        activated_at_l2_height: u64,
        observed_at_l2_height: u64,
        status: RotationStatus,
        pq_security_bits: u16,
        rotation_proof_root: &str,
    ) -> Self {
        let rotation_lag_blocks = observed_at_l2_height.saturating_sub(activated_at_l2_height);
        let rotation_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-ROTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(key_id),
                HashPart::U64(config.authority_epoch),
                HashPart::U64(activated_at_l2_height),
                HashPart::U64(observed_at_l2_height),
            ],
            32,
        );
        let mut checkpoint = Self {
            rotation_id,
            key_id: key_id.to_string(),
            authority_epoch: config.authority_epoch,
            activated_at_l2_height,
            observed_at_l2_height,
            rotation_status: status,
            pq_security_bits,
            rotation_lag_blocks,
            rotation_proof_root: rotation_proof_root.to_string(),
            checkpoint_root: String::new(),
        };
        checkpoint.checkpoint_root = record_root(
            "ROTATION-CHECKPOINT",
            &checkpoint.public_record_without_root(),
        );
        checkpoint
    }

    pub fn blocks_release(&self, config: &Config) -> bool {
        self.rotation_status == RotationStatus::Revoked
            || self.rotation_status == RotationStatus::Lagging
            || self.rotation_lag_blocks > config.max_rotation_lag_blocks
            || self.pq_security_bits < config.min_pq_security_bits
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "key_id": self.key_id,
            "authority_epoch": self.authority_epoch,
            "activated_at_l2_height": self.activated_at_l2_height,
            "observed_at_l2_height": self.observed_at_l2_height,
            "rotation_status": self.rotation_status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "rotation_lag_blocks": self.rotation_lag_blocks,
            "rotation_proof_root": self.rotation_proof_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("checkpoint_root".to_string(), json!(self.checkpoint_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeAttestation {
    pub attestation_id: String,
    pub kind: BridgeAttestationKind,
    pub claim_id: String,
    pub source_root: String,
    pub observed_root: String,
    pub authority_epoch: u64,
    pub matched: bool,
    pub attestation_root: String,
}

impl BridgeAttestation {
    pub fn new(
        config: &Config,
        kind: BridgeAttestationKind,
        claim_id: &str,
        source_root: &str,
        observed_root: &str,
    ) -> Self {
        let matched = source_root == observed_root;
        let attestation_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-BRIDGE-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(claim_id),
                HashPart::U64(config.authority_epoch),
            ],
            32,
        );
        let mut attestation = Self {
            attestation_id,
            kind,
            claim_id: claim_id.to_string(),
            source_root: source_root.to_string(),
            observed_root: observed_root.to_string(),
            authority_epoch: config.authority_epoch,
            matched,
            attestation_root: String::new(),
        };
        attestation.attestation_root = record_root(
            "BRIDGE-ATTESTATION",
            &attestation.public_record_without_root(),
        );
        attestation
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "claim_id": self.claim_id,
            "source_root": self.source_root,
            "observed_root": self.observed_root,
            "authority_epoch": self.authority_epoch,
            "matched": self.matched,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("attestation_root".to_string(), json!(self.attestation_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignatureDomainRoot {
    pub domain_id: String,
    pub kind: SignatureDomainKind,
    pub scheme: PqSignatureScheme,
    pub authority_epoch: u64,
    pub pq_security_bits: u16,
    pub transcript_root: String,
    pub domain_root: String,
}

impl SignatureDomainRoot {
    pub fn new(
        config: &Config,
        kind: SignatureDomainKind,
        scheme: PqSignatureScheme,
        pq_security_bits: u16,
        transcript_root: &str,
    ) -> Self {
        let domain_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-SIGNATURE-DOMAIN-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(scheme.as_str()),
                HashPart::U64(config.authority_epoch),
            ],
            32,
        );
        let domain_root = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-SIGNATURE-DOMAIN-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&domain_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(scheme.as_str()),
                HashPart::U64(config.authority_epoch),
                HashPart::U64(pq_security_bits as u64),
                HashPart::Str(transcript_root),
            ],
            32,
        );
        Self {
            domain_id,
            kind,
            scheme,
            authority_epoch: config.authority_epoch,
            pq_security_bits,
            transcript_root: transcript_root.to_string(),
            domain_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "domain_id": self.domain_id,
            "kind": self.kind.as_str(),
            "scheme": self.scheme.as_str(),
            "authority_epoch": self.authority_epoch,
            "pq_security_bits": self.pq_security_bits,
            "transcript_root": self.transcript_root,
            "domain_root": self.domain_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub kind: ReleaseHoldKind,
    pub claim_id: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub authority_epoch: u64,
    pub severity: u8,
    pub evidence_root: String,
    pub reason: String,
    pub blocks_release: bool,
    pub hold_root: String,
}

impl ReleaseHold {
    pub fn new(
        config: &Config,
        kind: ReleaseHoldKind,
        claim_id: &str,
        severity: u8,
        evidence_root: &str,
        reason: &str,
    ) -> Self {
        let expires_at_l2_height = config.l2_height.saturating_add(config.release_hold_blocks);
        let hold_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-RELEASE-HOLD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(claim_id),
                HashPart::U64(config.l2_height),
                HashPart::Str(evidence_root),
            ],
            32,
        );
        let mut hold = Self {
            hold_id,
            kind,
            claim_id: claim_id.to_string(),
            opened_at_l2_height: config.l2_height,
            expires_at_l2_height,
            authority_epoch: config.authority_epoch,
            severity,
            evidence_root: evidence_root.to_string(),
            reason: reason.to_string(),
            blocks_release: true,
            hold_root: String::new(),
        };
        hold.hold_root = record_root("RELEASE-HOLD", &hold.public_record_without_root());
        hold
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "kind": self.kind.as_str(),
            "claim_id": self.claim_id,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "authority_epoch": self.authority_epoch,
            "severity": self.severity,
            "evidence_root": self.evidence_root,
            "reason": self.reason,
            "blocks_release": self.blocks_release,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("hold_root".to_string(), json!(self.hold_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptanceRecord {
    pub acceptance_id: String,
    pub claim_id: String,
    pub status: AcceptanceStatus,
    pub authority_epoch: u64,
    pub watcher_quorum_root: String,
    pub withdrawal_authorization_root: String,
    pub epoch_continuity_root: String,
    pub rotation_status_root: String,
    pub bridge_attestation_root: String,
    pub signature_domain_root: String,
    pub release_hold_root: String,
    pub accepted_at_l2_height: u64,
    pub release_height: u64,
    pub release_allowed: bool,
    pub acceptance_root: String,
}

impl AcceptanceRecord {
    pub fn evaluate(
        config: &Config,
        claim_id: &str,
        watcher_quorum: &WatcherQuorumRecord,
        authorization: &WithdrawalAuthorization,
        continuity: &KeyEpochContinuity,
        rotations: &BTreeMap<String, RotationCheckpoint>,
        attestations: &BTreeMap<String, BridgeAttestation>,
        signature_domains: &BTreeMap<String, SignatureDomainRoot>,
        release_holds: &BTreeMap<String, ReleaseHold>,
    ) -> Self {
        let rotation_records = rotations
            .values()
            .map(RotationCheckpoint::public_record)
            .collect::<Vec<_>>();
        let attestation_records = attestations
            .values()
            .map(BridgeAttestation::public_record)
            .collect::<Vec<_>>();
        let signature_domain_records = signature_domains
            .values()
            .map(SignatureDomainRoot::public_record)
            .collect::<Vec<_>>();
        let release_hold_records = release_holds
            .values()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>();
        let rotation_status_root = merkle_root(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-ROTATION-STATUS",
            &rotation_records,
        );
        let bridge_attestation_root = merkle_root(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-BRIDGE-ATTESTATIONS",
            &attestation_records,
        );
        let signature_domain_root = merkle_root(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-SIGNATURE-DOMAINS",
            &signature_domain_records,
        );
        let release_hold_root = merkle_root(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-RELEASE-HOLDS",
            &release_hold_records,
        );
        let any_rotation_block = rotations
            .values()
            .any(|rotation| rotation.blocks_release(config));
        let all_attestations_match = attestations.values().all(|attestation| attestation.matched);
        let signature_domains_ready = signature_domains
            .values()
            .all(|domain| domain.pq_security_bits >= config.min_pq_security_bits);
        let active_holds = release_holds
            .values()
            .filter(|hold| hold.blocks_release)
            .count();
        let release_allowed = watcher_quorum.quorum_met
            && authorization.status == AuthorizationStatus::Authorized
            && continuity.status == EpochContinuityStatus::Continuous
            && !any_rotation_block
            && all_attestations_match
            && signature_domains_ready
            && active_holds == 0;
        let status = if release_allowed {
            AcceptanceStatus::Accepted
        } else if config.fail_closed_on_incomplete_evidence || active_holds > 0 {
            AcceptanceStatus::Held
        } else {
            AcceptanceStatus::Rejected
        };
        let acceptance_id = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(claim_id),
                HashPart::U64(config.authority_epoch),
                HashPart::Str(&watcher_quorum.record_root),
                HashPart::Str(&authorization.authorization_root),
                HashPart::Str(&continuity.continuity_root),
                HashPart::Str(&rotation_status_root),
                HashPart::Str(&bridge_attestation_root),
                HashPart::Str(&signature_domain_root),
                HashPart::Str(&release_hold_root),
            ],
            32,
        );
        let mut record = Self {
            acceptance_id,
            claim_id: claim_id.to_string(),
            status,
            authority_epoch: config.authority_epoch,
            watcher_quorum_root: watcher_quorum.record_root.clone(),
            withdrawal_authorization_root: authorization.authorization_root.clone(),
            epoch_continuity_root: continuity.continuity_root.clone(),
            rotation_status_root,
            bridge_attestation_root,
            signature_domain_root,
            release_hold_root,
            accepted_at_l2_height: config.l2_height,
            release_height: config.release_height,
            release_allowed,
            acceptance_root: String::new(),
        };
        record.acceptance_root =
            record_root("ACCEPTANCE-RECORD", &record.public_record_without_root());
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "acceptance_id": self.acceptance_id,
            "claim_id": self.claim_id,
            "status": self.status.as_str(),
            "authority_epoch": self.authority_epoch,
            "watcher_quorum_root": self.watcher_quorum_root,
            "withdrawal_authorization_root": self.withdrawal_authorization_root,
            "epoch_continuity_root": self.epoch_continuity_root,
            "rotation_status_root": self.rotation_status_root,
            "bridge_attestation_root": self.bridge_attestation_root,
            "signature_domain_root": self.signature_domain_root,
            "release_hold_root": self.release_hold_root,
            "accepted_at_l2_height": self.accepted_at_l2_height,
            "release_height": self.release_height,
            "release_allowed": self.release_allowed,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("acceptance_root".to_string(), json!(self.acceptance_root));
        }
        record
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RootIndex {
    pub watcher_quorum_root: String,
    pub withdrawal_authorization_root: String,
    pub epoch_continuity_root: String,
    pub rotation_status_root: String,
    pub bridge_attestation_root: String,
    pub signature_domain_root: String,
    pub release_hold_root: String,
    pub acceptance_record_root: String,
    pub state_root: String,
}

impl RootIndex {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_quorum_root": self.watcher_quorum_root,
            "withdrawal_authorization_root": self.withdrawal_authorization_root,
            "epoch_continuity_root": self.epoch_continuity_root,
            "rotation_status_root": self.rotation_status_root,
            "bridge_attestation_root": self.bridge_attestation_root,
            "signature_domain_root": self.signature_domain_root,
            "release_hold_root": self.release_hold_root,
            "acceptance_record_root": self.acceptance_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub watcher_votes: u64,
    pub accepted_watcher_votes: u64,
    pub withdrawal_authorizations: u64,
    pub epoch_continuity_records: u64,
    pub rotation_checkpoints: u64,
    pub bridge_attestations: u64,
    pub signature_domains: u64,
    pub release_holds: u64,
    pub acceptance_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_votes": self.watcher_votes,
            "accepted_watcher_votes": self.accepted_watcher_votes,
            "withdrawal_authorizations": self.withdrawal_authorizations,
            "epoch_continuity_records": self.epoch_continuity_records,
            "rotation_checkpoints": self.rotation_checkpoints,
            "bridge_attestations": self.bridge_attestations,
            "signature_domains": self.signature_domains,
            "release_holds": self.release_holds,
            "acceptance_records": self.acceptance_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub watcher_votes: BTreeMap<String, PqWatcherVote>,
    pub watcher_quorum: WatcherQuorumRecord,
    pub withdrawal_authorizations: BTreeMap<String, WithdrawalAuthorization>,
    pub epoch_continuity: KeyEpochContinuity,
    pub rotation_checkpoints: BTreeMap<String, RotationCheckpoint>,
    pub bridge_attestations: BTreeMap<String, BridgeAttestation>,
    pub signature_domains: BTreeMap<String, SignatureDomainRoot>,
    pub release_holds: BTreeMap<String, ReleaseHold>,
    pub acceptance_records: BTreeMap<String, AcceptanceRecord>,
}

impl State {
    pub fn new(
        config: Config,
        watcher_votes: BTreeMap<String, PqWatcherVote>,
        withdrawal_authorizations: BTreeMap<String, WithdrawalAuthorization>,
        epoch_continuity: KeyEpochContinuity,
        rotation_checkpoints: BTreeMap<String, RotationCheckpoint>,
        bridge_attestations: BTreeMap<String, BridgeAttestation>,
        signature_domains: BTreeMap<String, SignatureDomainRoot>,
        release_holds: BTreeMap<String, ReleaseHold>,
    ) -> Self {
        let watcher_quorum = WatcherQuorumRecord::evaluate(&config, &watcher_votes);
        let mut acceptance_records = BTreeMap::new();
        for (claim_id, authorization) in &withdrawal_authorizations {
            let acceptance = AcceptanceRecord::evaluate(
                &config,
                claim_id,
                &watcher_quorum,
                authorization,
                &epoch_continuity,
                &rotation_checkpoints,
                &bridge_attestations,
                &signature_domains,
                &release_holds,
            );
            acceptance_records.insert(claim_id.clone(), acceptance);
        }
        Self {
            config,
            watcher_votes,
            watcher_quorum,
            withdrawal_authorizations,
            epoch_continuity,
            rotation_checkpoints,
            bridge_attestations,
            signature_domains,
            release_holds,
            acceptance_records,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "watcher_quorum": self.watcher_quorum.public_record(),
            "withdrawal_authorizations": self
                .withdrawal_authorizations
                .values()
                .map(WithdrawalAuthorization::public_record)
                .collect::<Vec<_>>(),
            "epoch_continuity": self.epoch_continuity.public_record(),
            "rotation_checkpoints": self
                .rotation_checkpoints
                .values()
                .map(RotationCheckpoint::public_record)
                .collect::<Vec<_>>(),
            "bridge_attestations": self
                .bridge_attestations
                .values()
                .map(BridgeAttestation::public_record)
                .collect::<Vec<_>>(),
            "signature_domains": self
                .signature_domains
                .values()
                .map(SignatureDomainRoot::public_record)
                .collect::<Vec<_>>(),
            "release_holds": self
                .release_holds
                .values()
                .map(ReleaseHold::public_record)
                .collect::<Vec<_>>(),
            "acceptance_records": self
                .acceptance_records
                .values()
                .map(AcceptanceRecord::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn roots(&self) -> RootIndex {
        let withdrawal_records = self
            .withdrawal_authorizations
            .values()
            .map(WithdrawalAuthorization::public_record)
            .collect::<Vec<_>>();
        let rotation_records = self
            .rotation_checkpoints
            .values()
            .map(RotationCheckpoint::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .bridge_attestations
            .values()
            .map(BridgeAttestation::public_record)
            .collect::<Vec<_>>();
        let signature_records = self
            .signature_domains
            .values()
            .map(SignatureDomainRoot::public_record)
            .collect::<Vec<_>>();
        let hold_records = self
            .release_holds
            .values()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>();
        let acceptance_records = self
            .acceptance_records
            .values()
            .map(AcceptanceRecord::public_record)
            .collect::<Vec<_>>();
        let mut roots = RootIndex {
            watcher_quorum_root: self.watcher_quorum.record_root.clone(),
            withdrawal_authorization_root: merkle_root(
                "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-WITHDRAWAL-AUTHORIZATIONS",
                &withdrawal_records,
            ),
            epoch_continuity_root: self.epoch_continuity.continuity_root.clone(),
            rotation_status_root: merkle_root(
                "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-ROTATION-CHECKPOINTS",
                &rotation_records,
            ),
            bridge_attestation_root: merkle_root(
                "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-BRIDGE-ATTESTATION-INDEX",
                &attestation_records,
            ),
            signature_domain_root: merkle_root(
                "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-SIGNATURE-DOMAIN-INDEX",
                &signature_records,
            ),
            release_hold_root: merkle_root(
                "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-RELEASE-HOLD-INDEX",
                &hold_records,
            ),
            acceptance_record_root: merkle_root(
                "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-RECORD-INDEX",
                &acceptance_records,
            ),
            state_root: String::new(),
        };
        roots.state_root = domain_hash(
            "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.config.public_record()),
                HashPart::Str(&roots.watcher_quorum_root),
                HashPart::Str(&roots.withdrawal_authorization_root),
                HashPart::Str(&roots.epoch_continuity_root),
                HashPart::Str(&roots.rotation_status_root),
                HashPart::Str(&roots.bridge_attestation_root),
                HashPart::Str(&roots.signature_domain_root),
                HashPart::Str(&roots.release_hold_root),
                HashPart::Str(&roots.acceptance_record_root),
            ],
            32,
        );
        roots
    }

    pub fn counters(&self) -> Counters {
        Counters {
            watcher_votes: self.watcher_votes.len() as u64,
            accepted_watcher_votes: self
                .watcher_votes
                .values()
                .filter(|vote| vote.status.counts_for_quorum())
                .count() as u64,
            withdrawal_authorizations: self.withdrawal_authorizations.len() as u64,
            epoch_continuity_records: 1,
            rotation_checkpoints: self.rotation_checkpoints.len() as u64,
            bridge_attestations: self.bridge_attestations.len() as u64,
            signature_domains: self.signature_domains.len() as u64,
            release_holds: self.release_holds.len() as u64,
            acceptance_records: self.acceptance_records.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn acceptance_for_claim(&self, claim_id: &str) -> Result<&AcceptanceRecord> {
        self.acceptance_records
            .get(claim_id)
            .ok_or_else(|| format!("acceptance record not found for claim {claim_id}"))
    }

    pub fn has_active_release_holds(&self) -> bool {
        self.release_holds.values().any(|hold| hold.blocks_release)
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let claim_id = "monero-l2-pq-exit-claim-devnet-0001";
    let lock_root = fixture_root("monero-lock", 1);
    let burn_root = fixture_root("private-note-burn", 2);
    let claim_root = fixture_root("withdrawal-claim", 3);
    let reserve_root = fixture_root("reserve-sufficiency", 4);
    let receipt_root = fixture_root("settlement-receipt", 5);
    let watcher_domain_root = fixture_root("watcher-domain", 6);
    let authorization_domain_root = fixture_root("authorization-domain", 7);
    let mut watcher_votes = BTreeMap::new();
    for (index, watcher_id, weight_bps, status) in [
        (
            "001",
            "pq-watcher-alpha",
            1_700,
            WatcherVoteStatus::Accepted,
        ),
        ("002", "pq-watcher-beta", 1_550, WatcherVoteStatus::Accepted),
        (
            "003",
            "pq-watcher-gamma",
            1_500,
            WatcherVoteStatus::Accepted,
        ),
        (
            "004",
            "pq-watcher-delta",
            1_350,
            WatcherVoteStatus::Accepted,
        ),
        (
            "005",
            "pq-watcher-epsilon",
            1_250,
            WatcherVoteStatus::Accepted,
        ),
        ("006", "pq-watcher-zeta", 900, WatcherVoteStatus::Stale),
    ] {
        let vote = PqWatcherVote::new(
            watcher_id,
            status,
            weight_bps,
            config
                .monero_height
                .saturating_sub(index.parse::<u64>().unwrap_or(0)),
            config.l2_height,
            config.authority_epoch,
            256,
            &claim_root,
            &watcher_domain_root,
        );
        watcher_votes.insert(watcher_id.to_string(), vote);
    }
    let mut withdrawal_authorizations = BTreeMap::new();
    let authorization = WithdrawalAuthorization::new(
        &config,
        claim_id,
        &fixture_root("account-commitment", 8),
        &fixture_root("exit-nullifier", 9),
        &fixture_root("amount-commitment", 10),
        &fixture_root("destination-commitment", 11),
        4,
        7_400,
    );
    withdrawal_authorizations.insert(claim_id.to_string(), authorization);
    let continuity = KeyEpochContinuity::new(
        &config,
        &fixture_root("bridge-key", 12),
        &fixture_root("authority-set-previous", 13),
        &fixture_root("authority-set-active", 14),
        3,
    );
    let mut rotations = BTreeMap::new();
    for (key_id, activated_offset, observed_offset, status) in [
        (
            "authority-key-ml-dsa-active",
            64,
            2,
            RotationStatus::Current,
        ),
        (
            "authority-key-slh-dsa-standby",
            40,
            1,
            RotationStatus::PendingActivation,
        ),
    ] {
        let checkpoint = RotationCheckpoint::new(
            &config,
            key_id,
            config.l2_height.saturating_sub(activated_offset),
            config.l2_height.saturating_sub(observed_offset),
            status,
            256,
            &fixture_root(key_id, 15),
        );
        rotations.insert(key_id.to_string(), checkpoint);
    }
    let mut attestations = BTreeMap::new();
    for (kind, source_root) in [
        (BridgeAttestationKind::MoneroLock, lock_root),
        (BridgeAttestationKind::PrivateNoteBurn, burn_root),
        (BridgeAttestationKind::WithdrawalClaim, claim_root),
        (BridgeAttestationKind::ReserveSufficiency, reserve_root),
        (BridgeAttestationKind::SettlementReceipt, receipt_root),
    ] {
        let attestation =
            BridgeAttestation::new(&config, kind, claim_id, &source_root, &source_root);
        attestations.insert(kind.as_str().to_string(), attestation);
    }
    let mut signature_domains = BTreeMap::new();
    for (kind, scheme, transcript_root) in [
        (
            SignatureDomainKind::WatcherQuorum,
            PqSignatureScheme::MlDsa87,
            watcher_domain_root,
        ),
        (
            SignatureDomainKind::WithdrawalAuthorization,
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            authorization_domain_root,
        ),
        (
            SignatureDomainKind::EpochContinuity,
            PqSignatureScheme::SlhDsaShake256f,
            continuity.continuity_root.clone(),
        ),
        (
            SignatureDomainKind::KeyRotation,
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            fixture_root("rotation-domain", 16),
        ),
        (
            SignatureDomainKind::BridgeAttestation,
            PqSignatureScheme::MlDsa87,
            fixture_root("bridge-attestation-domain", 17),
        ),
        (
            SignatureDomainKind::ReleaseHold,
            PqSignatureScheme::SlhDsaShake256f,
            fixture_root("release-hold-domain", 18),
        ),
    ] {
        let domain = SignatureDomainRoot::new(&config, kind, scheme, 256, &transcript_root);
        signature_domains.insert(kind.as_str().to_string(), domain);
    }
    let release_holds = BTreeMap::new();
    State::new(
        config,
        watcher_votes,
        withdrawal_authorizations,
        continuity,
        rotations,
        attestations,
        signature_domains,
        release_holds,
    )
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn held_devnet() -> State {
    let config = Config::devnet();
    let claim_id = "monero-l2-pq-exit-claim-devnet-held-0001";
    let source_claim_root = fixture_root("held-withdrawal-claim-source", 21);
    let observed_claim_root = fixture_root("held-withdrawal-claim-observed", 22);
    let signature_root = fixture_root("held-signature-domain", 23);
    let mut watcher_votes = BTreeMap::new();
    for (watcher_id, weight_bps, status) in [
        ("pq-watcher-alpha", 1_700, WatcherVoteStatus::Accepted),
        ("pq-watcher-beta", 1_550, WatcherVoteStatus::Accepted),
        ("pq-watcher-gamma", 1_500, WatcherVoteStatus::Accepted),
        ("pq-watcher-delta", 1_350, WatcherVoteStatus::Missing),
        ("pq-watcher-epsilon", 1_250, WatcherVoteStatus::Stale),
    ] {
        let vote = PqWatcherVote::new(
            watcher_id,
            status,
            weight_bps,
            config.monero_height,
            config.l2_height,
            config.authority_epoch,
            256,
            &source_claim_root,
            &signature_root,
        );
        watcher_votes.insert(watcher_id.to_string(), vote);
    }
    let mut withdrawal_authorizations = BTreeMap::new();
    withdrawal_authorizations.insert(
        claim_id.to_string(),
        WithdrawalAuthorization::new(
            &config,
            claim_id,
            &fixture_root("held-account", 24),
            &fixture_root("held-nullifier", 25),
            &fixture_root("held-amount", 26),
            &fixture_root("held-destination", 27),
            2,
            4_900,
        ),
    );
    let continuity = KeyEpochContinuity::new(
        &config,
        &fixture_root("held-bridge-key", 28),
        &fixture_root("held-authority-previous", 29),
        &fixture_root("held-authority-active", 30),
        1,
    );
    let mut rotations = BTreeMap::new();
    rotations.insert(
        "authority-key-ml-dsa-lagging".to_string(),
        RotationCheckpoint::new(
            &config,
            "authority-key-ml-dsa-lagging",
            config.l2_height.saturating_sub(180),
            config.l2_height,
            RotationStatus::Lagging,
            256,
            &fixture_root("held-rotation", 31),
        ),
    );
    let mut attestations = BTreeMap::new();
    attestations.insert(
        BridgeAttestationKind::WithdrawalClaim.as_str().to_string(),
        BridgeAttestation::new(
            &config,
            BridgeAttestationKind::WithdrawalClaim,
            claim_id,
            &source_claim_root,
            &observed_claim_root,
        ),
    );
    let mut signature_domains = BTreeMap::new();
    signature_domains.insert(
        SignatureDomainKind::WithdrawalAuthorization
            .as_str()
            .to_string(),
        SignatureDomainRoot::new(
            &config,
            SignatureDomainKind::WithdrawalAuthorization,
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            256,
            &signature_root,
        ),
    );
    let mut release_holds = BTreeMap::new();
    for (kind, severity, evidence_root, reason) in [
        (
            ReleaseHoldKind::WatcherQuorumShortfall,
            2,
            fixture_root("held-quorum-evidence", 32),
            "watcher quorum below configured release floor",
        ),
        (
            ReleaseHoldKind::AuthoritySignatureShortfall,
            2,
            fixture_root("held-authority-evidence", 33),
            "authority signature weight below configured release floor",
        ),
        (
            ReleaseHoldKind::AttestationRootMismatch,
            3,
            fixture_root("held-attestation-evidence", 34),
            "bridge attestation source and observed roots diverged",
        ),
    ] {
        let hold = ReleaseHold::new(&config, kind, claim_id, severity, &evidence_root, reason);
        release_holds.insert(kind.as_str().to_string(), hold);
    }
    State::new(
        config,
        watcher_votes,
        withdrawal_authorizations,
        continuity,
        rotations,
        attestations,
        signature_domains,
        release_holds,
    )
}

pub fn acceptance_summary(state: &State) -> Value {
    json!({
        "state_root": state.state_root(),
        "release_allowed": state
            .acceptance_records
            .values()
            .all(|record| record.status.releases_funds()),
        "active_release_holds": state.has_active_release_holds(),
        "counters": state.counters().public_record(),
        "roots": state.roots().public_record(),
    })
}

fn capped_bps(value: u64) -> u16 {
    value.min(MAX_BPS as u64) as u16
}

fn fixture_root(label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-AUTHORITY-EXIT-ACCEPTANCE-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
