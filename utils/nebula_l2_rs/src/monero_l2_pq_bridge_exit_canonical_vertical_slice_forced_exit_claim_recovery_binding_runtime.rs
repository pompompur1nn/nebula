use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceForcedExitClaimRecoveryBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FORCED_EXIT_CLAIM_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-forced-exit-claim-recovery-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_FORCED_EXIT_CLAIM_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BINDING_SUITE: &str = "monero-l2-pq-bridge-exit-forced-exit-claim-recovery-binding-v1";
pub const DEFAULT_REFERENCE_HEIGHT: u64 = 4_261_120;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_NOTE_RECOVERY_SHARDS: u16 = 2;
pub const DEFAULT_MIN_OBSERVED_RECEIPTS: u16 = 3;
pub const DEFAULT_MIN_LIVE_FEED_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_SETTLEMENT_AUTHORIZERS: u16 = 2;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;

const DOMAIN: &str = "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-CLAIM-RECOVERY-BINDING";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimBuildStage {
    WalletRecovered,
    NoteRootsBound,
    ReceiptsObserved,
    LiveFeedAnchored,
    ChallengeWindowOpened,
    SettlementAuthorized,
    ReleaseHeld,
}

impl ClaimBuildStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecovered => "wallet_recovered",
            Self::NoteRootsBound => "note_roots_bound",
            Self::ReceiptsObserved => "receipts_observed",
            Self::LiveFeedAnchored => "live_feed_anchored",
            Self::ChallengeWindowOpened => "challenge_window_opened",
            Self::SettlementAuthorized => "settlement_authorized",
            Self::ReleaseHeld => "release_held",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimBlockerKind {
    WalletRecoveryIncomplete,
    NoteRecoveryMismatch,
    LiveFeedStale,
    ObservedReceiptMissing,
    SettlementTargetMismatch,
    ChallengeWindowOpen,
    ReleaseHoldActive,
    PqAuthorizationInsufficient,
}

impl ClaimBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecoveryIncomplete => "wallet_recovery_incomplete",
            Self::NoteRecoveryMismatch => "note_recovery_mismatch",
            Self::LiveFeedStale => "live_feed_stale",
            Self::ObservedReceiptMissing => "observed_receipt_missing",
            Self::SettlementTargetMismatch => "settlement_target_mismatch",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ReleaseHoldActive => "release_hold_active",
            Self::PqAuthorizationInsufficient => "pq_authorization_insufficient",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub binding_suite: String,
    pub reference_height: u64,
    pub challenge_window_blocks: u64,
    pub release_hold_blocks: u64,
    pub min_note_recovery_shards: u16,
    pub min_observed_receipts: u16,
    pub min_live_feed_confirmations: u64,
    pub min_settlement_authorizers: u16,
    pub min_pq_security_bits: u16,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            binding_suite: BINDING_SUITE.to_string(),
            reference_height: DEFAULT_REFERENCE_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            min_note_recovery_shards: DEFAULT_MIN_NOTE_RECOVERY_SHARDS,
            min_observed_receipts: DEFAULT_MIN_OBSERVED_RECEIPTS,
            min_live_feed_confirmations: DEFAULT_MIN_LIVE_FEED_CONFIRMATIONS,
            min_settlement_authorizers: DEFAULT_MIN_SETTLEMENT_AUTHORIZERS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "binding_suite": self.binding_suite,
            "reference_height": self.reference_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "release_hold_blocks": self.release_hold_blocks,
            "min_note_recovery_shards": self.min_note_recovery_shards,
            "min_observed_receipts": self.min_observed_receipts,
            "min_live_feed_confirmations": self.min_live_feed_confirmations,
            "min_settlement_authorizers": self.min_settlement_authorizers,
            "min_pq_security_bits": self.min_pq_security_bits,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimRootRecord {
    pub claim_id: String,
    pub wallet_recovery_root: String,
    pub note_recovery_root: String,
    pub live_feed_root: String,
    pub observed_receipt_root: String,
    pub settlement_target_root: String,
    pub challenge_window_root: String,
    pub blocker_root: String,
    pub builder_root: String,
}

impl ClaimRootRecord {
    pub fn new(
        claim_label: impl Into<String>,
        wallet_recovery_root: impl Into<String>,
        note_recovery_root: impl Into<String>,
        live_feed_root: impl Into<String>,
        observed_receipt_root: impl Into<String>,
        settlement_target_root: impl Into<String>,
        challenge_window_root: impl Into<String>,
        blocker_root: impl Into<String>,
    ) -> Self {
        let claim_label = claim_label.into();
        let wallet_recovery_root = wallet_recovery_root.into();
        let note_recovery_root = note_recovery_root.into();
        let live_feed_root = live_feed_root.into();
        let observed_receipt_root = observed_receipt_root.into();
        let settlement_target_root = settlement_target_root.into();
        let challenge_window_root = challenge_window_root.into();
        let blocker_root = blocker_root.into();
        let builder_root = domain_hash(
            &domain("claim-builder-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&wallet_recovery_root),
                HashPart::Str(&note_recovery_root),
                HashPart::Str(&live_feed_root),
                HashPart::Str(&observed_receipt_root),
                HashPart::Str(&settlement_target_root),
                HashPart::Str(&challenge_window_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        let claim_id = domain_hash(
            &domain("claim-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&claim_label),
                HashPart::Str(&builder_root),
            ],
            32,
        );

        Self {
            claim_id,
            wallet_recovery_root,
            note_recovery_root,
            live_feed_root,
            observed_receipt_root,
            settlement_target_root,
            challenge_window_root,
            blocker_root,
            builder_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "wallet_recovery_root": self.wallet_recovery_root,
            "note_recovery_root": self.note_recovery_root,
            "live_feed_root": self.live_feed_root,
            "observed_receipt_root": self.observed_receipt_root,
            "settlement_target_root": self.settlement_target_root,
            "challenge_window_root": self.challenge_window_root,
            "blocker_root": self.blocker_root,
            "builder_root": self.builder_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("claim_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletProofLink {
    pub link_id: String,
    pub recovery_session_id: String,
    pub wallet_account_commitment: String,
    pub local_backup_root: String,
    pub pq_authorization_root: String,
    pub recovered_at_height: u64,
    pub recovered_shards: u16,
    pub pq_security_bits: u16,
}

impl WalletProofLink {
    pub fn new(
        recovery_session_id: impl Into<String>,
        wallet_account_commitment: impl Into<String>,
        local_backup_root: impl Into<String>,
        pq_authorization_root: impl Into<String>,
        recovered_at_height: u64,
        recovered_shards: u16,
        pq_security_bits: u16,
    ) -> Self {
        let recovery_session_id = recovery_session_id.into();
        let wallet_account_commitment = wallet_account_commitment.into();
        let local_backup_root = local_backup_root.into();
        let pq_authorization_root = pq_authorization_root.into();
        let link_id = domain_hash(
            &domain("wallet-proof-link"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&recovery_session_id),
                HashPart::Str(&wallet_account_commitment),
                HashPart::Str(&local_backup_root),
                HashPart::Str(&pq_authorization_root),
                HashPart::U64(recovered_at_height),
                HashPart::U64(recovered_shards as u64),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );

        Self {
            link_id,
            recovery_session_id,
            wallet_account_commitment,
            local_backup_root,
            pq_authorization_root,
            recovered_at_height,
            recovered_shards,
            pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "link_id": self.link_id,
            "recovery_session_id": self.recovery_session_id,
            "wallet_account_commitment": self.wallet_account_commitment,
            "local_backup_root": self.local_backup_root,
            "pq_authorization_root": self.pq_authorization_root,
            "recovered_at_height": self.recovered_at_height,
            "recovered_shards": self.recovered_shards,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet_proof_link", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NoteRecoveryRoot {
    pub note_recovery_id: String,
    pub private_note_root: String,
    pub nullifier_root: String,
    pub receipt_shard_root: String,
    pub scan_hint_root: String,
    pub claimable_amount_commitment: String,
    pub recovered_note_count: u16,
}

impl NoteRecoveryRoot {
    pub fn new(
        private_note_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        receipt_shard_root: impl Into<String>,
        scan_hint_root: impl Into<String>,
        claimable_amount_commitment: impl Into<String>,
        recovered_note_count: u16,
    ) -> Self {
        let private_note_root = private_note_root.into();
        let nullifier_root = nullifier_root.into();
        let receipt_shard_root = receipt_shard_root.into();
        let scan_hint_root = scan_hint_root.into();
        let claimable_amount_commitment = claimable_amount_commitment.into();
        let note_recovery_id = domain_hash(
            &domain("note-recovery-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&private_note_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&receipt_shard_root),
                HashPart::Str(&scan_hint_root),
                HashPart::Str(&claimable_amount_commitment),
                HashPart::U64(recovered_note_count as u64),
            ],
            32,
        );

        Self {
            note_recovery_id,
            private_note_root,
            nullifier_root,
            receipt_shard_root,
            scan_hint_root,
            claimable_amount_commitment,
            recovered_note_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_recovery_id": self.note_recovery_id,
            "private_note_root": self.private_note_root,
            "nullifier_root": self.nullifier_root,
            "receipt_shard_root": self.receipt_shard_root,
            "scan_hint_root": self.scan_hint_root,
            "claimable_amount_commitment": self.claimable_amount_commitment,
            "recovered_note_count": self.recovered_note_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("note_recovery_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveFeedRoot {
    pub feed_id: String,
    pub adapter_id: String,
    pub feed_kind: String,
    pub observed_root: String,
    pub finalized_height: u64,
    pub confirmations: u64,
    pub freshness_bound_height: u64,
}

impl LiveFeedRoot {
    pub fn new(
        adapter_id: impl Into<String>,
        feed_kind: impl Into<String>,
        observed_root: impl Into<String>,
        finalized_height: u64,
        confirmations: u64,
        freshness_bound_height: u64,
    ) -> Self {
        let adapter_id = adapter_id.into();
        let feed_kind = feed_kind.into();
        let observed_root = observed_root.into();
        let feed_id = domain_hash(
            &domain("live-feed-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&adapter_id),
                HashPart::Str(&feed_kind),
                HashPart::Str(&observed_root),
                HashPart::U64(finalized_height),
                HashPart::U64(confirmations),
                HashPart::U64(freshness_bound_height),
            ],
            32,
        );

        Self {
            feed_id,
            adapter_id,
            feed_kind,
            observed_root,
            finalized_height,
            confirmations,
            freshness_bound_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "adapter_id": self.adapter_id,
            "feed_kind": self.feed_kind,
            "observed_root": self.observed_root,
            "finalized_height": self.finalized_height,
            "confirmations": self.confirmations,
            "freshness_bound_height": self.freshness_bound_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_feed_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceiptLink {
    pub receipt_link_id: String,
    pub source_runtime: String,
    pub receipt_kind: String,
    pub receipt_root: String,
    pub claim_binding_root: String,
    pub observed_at_height: u64,
    pub required_for_release: bool,
}

impl ObservedReceiptLink {
    pub fn new(
        source_runtime: impl Into<String>,
        receipt_kind: impl Into<String>,
        receipt_root: impl Into<String>,
        claim_binding_root: impl Into<String>,
        observed_at_height: u64,
        required_for_release: bool,
    ) -> Self {
        let source_runtime = source_runtime.into();
        let receipt_kind = receipt_kind.into();
        let receipt_root = receipt_root.into();
        let claim_binding_root = claim_binding_root.into();
        let receipt_link_id = domain_hash(
            &domain("observed-receipt-link"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&source_runtime),
                HashPart::Str(&receipt_kind),
                HashPart::Str(&receipt_root),
                HashPart::Str(&claim_binding_root),
                HashPart::U64(observed_at_height),
                HashPart::Str(bool_str(required_for_release)),
            ],
            32,
        );

        Self {
            receipt_link_id,
            source_runtime,
            receipt_kind,
            receipt_root,
            claim_binding_root,
            observed_at_height,
            required_for_release,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_link_id": self.receipt_link_id,
            "source_runtime": self.source_runtime,
            "receipt_kind": self.receipt_kind,
            "receipt_root": self.receipt_root,
            "claim_binding_root": self.claim_binding_root,
            "observed_at_height": self.observed_at_height,
            "required_for_release": self.required_for_release,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed_receipt_link", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementTargetRoot {
    pub settlement_id: String,
    pub target_chain: String,
    pub recipient_commitment: String,
    pub asset_commitment: String,
    pub amount_commitment: String,
    pub release_authority_root: String,
    pub authorizer_count: u16,
}

impl SettlementTargetRoot {
    pub fn new(
        target_chain: impl Into<String>,
        recipient_commitment: impl Into<String>,
        asset_commitment: impl Into<String>,
        amount_commitment: impl Into<String>,
        release_authority_root: impl Into<String>,
        authorizer_count: u16,
    ) -> Self {
        let target_chain = target_chain.into();
        let recipient_commitment = recipient_commitment.into();
        let asset_commitment = asset_commitment.into();
        let amount_commitment = amount_commitment.into();
        let release_authority_root = release_authority_root.into();
        let settlement_id = domain_hash(
            &domain("settlement-target-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&target_chain),
                HashPart::Str(&recipient_commitment),
                HashPart::Str(&asset_commitment),
                HashPart::Str(&amount_commitment),
                HashPart::Str(&release_authority_root),
                HashPart::U64(authorizer_count as u64),
            ],
            32,
        );

        Self {
            settlement_id,
            target_chain,
            recipient_commitment,
            asset_commitment,
            amount_commitment,
            release_authority_root,
            authorizer_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "target_chain": self.target_chain,
            "recipient_commitment": self.recipient_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "release_authority_root": self.release_authority_root,
            "authorizer_count": self.authorizer_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("settlement_target_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindow {
    pub window_id: String,
    pub claim_id: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub dispute_root: String,
    pub challenger_bond_root: String,
}

impl ChallengeWindow {
    pub fn new(
        claim_id: impl Into<String>,
        opened_at_height: u64,
        window_blocks: u64,
        dispute_root: impl Into<String>,
        challenger_bond_root: impl Into<String>,
    ) -> Self {
        let claim_id = claim_id.into();
        let dispute_root = dispute_root.into();
        let challenger_bond_root = challenger_bond_root.into();
        let closes_at_height = opened_at_height.saturating_add(window_blocks);
        let window_id = domain_hash(
            &domain("challenge-window"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&claim_id),
                HashPart::U64(opened_at_height),
                HashPart::U64(closes_at_height),
                HashPart::Str(&dispute_root),
                HashPart::Str(&challenger_bond_root),
            ],
            32,
        );

        Self {
            window_id,
            claim_id,
            opened_at_height,
            closes_at_height,
            dispute_root,
            challenger_bond_root,
        }
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        height < self.closes_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "claim_id": self.claim_id,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "dispute_root": self.dispute_root,
            "challenger_bond_root": self.challenger_bond_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("challenge_window", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub expected_root: String,
    pub observed_root: String,
    pub source: String,
    pub field: String,
    pub release_blocking: bool,
}

impl MismatchRecord {
    pub fn new(
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        source: impl Into<String>,
        field: impl Into<String>,
        release_blocking: bool,
    ) -> Self {
        let expected_root = expected_root.into();
        let observed_root = observed_root.into();
        let source = source.into();
        let field = field.into();
        let mismatch_id = domain_hash(
            &domain("mismatch-record"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&expected_root),
                HashPart::Str(&observed_root),
                HashPart::Str(&source),
                HashPart::Str(&field),
                HashPart::Str(bool_str(release_blocking)),
            ],
            32,
        );

        Self {
            mismatch_id,
            expected_root,
            observed_root,
            source,
            field,
            release_blocking,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "source": self.source,
            "field": self.field,
            "release_blocking": self.release_blocking,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("mismatch_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub claim_id: String,
    pub reason: String,
    pub hold_root: String,
    pub starts_at_height: u64,
    pub releases_at_height: u64,
    pub fail_closed: bool,
}

impl ReleaseHold {
    pub fn new(
        claim_id: impl Into<String>,
        reason: impl Into<String>,
        hold_root: impl Into<String>,
        starts_at_height: u64,
        release_hold_blocks: u64,
        fail_closed: bool,
    ) -> Self {
        let claim_id = claim_id.into();
        let reason = reason.into();
        let hold_root = hold_root.into();
        let releases_at_height = starts_at_height.saturating_add(release_hold_blocks);
        let hold_id = domain_hash(
            &domain("release-hold"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&claim_id),
                HashPart::Str(&reason),
                HashPart::Str(&hold_root),
                HashPart::U64(starts_at_height),
                HashPart::U64(releases_at_height),
                HashPart::Str(bool_str(fail_closed)),
            ],
            32,
        );

        Self {
            hold_id,
            claim_id,
            reason,
            hold_root,
            starts_at_height,
            releases_at_height,
            fail_closed,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        height < self.releases_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "claim_id": self.claim_id,
            "reason": self.reason,
            "hold_root": self.hold_root,
            "starts_at_height": self.starts_at_height,
            "releases_at_height": self.releases_at_height,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_hold", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimBlocker {
    pub blocker_id: String,
    pub kind: ClaimBlockerKind,
    pub claim_id: String,
    pub evidence_root: String,
    pub detected_at_height: u64,
    pub fail_closed: bool,
}

impl ClaimBlocker {
    pub fn new(
        kind: ClaimBlockerKind,
        claim_id: impl Into<String>,
        evidence_root: impl Into<String>,
        detected_at_height: u64,
        fail_closed: bool,
    ) -> Self {
        let claim_id = claim_id.into();
        let evidence_root = evidence_root.into();
        let blocker_id = domain_hash(
            &domain("claim-blocker"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&claim_id),
                HashPart::Str(&evidence_root),
                HashPart::U64(detected_at_height),
                HashPart::Str(bool_str(fail_closed)),
            ],
            32,
        );

        Self {
            blocker_id,
            kind,
            claim_id,
            evidence_root,
            detected_at_height,
            fail_closed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "claim_id": self.claim_id,
            "evidence_root": self.evidence_root,
            "detected_at_height": self.detected_at_height,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("claim_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub wallet_proof_links: BTreeMap<String, WalletProofLink>,
    pub note_recovery_roots: BTreeMap<String, NoteRecoveryRoot>,
    pub live_feed_roots: BTreeMap<String, LiveFeedRoot>,
    pub observed_receipt_links: BTreeMap<String, ObservedReceiptLink>,
    pub settlement_target_roots: BTreeMap<String, SettlementTargetRoot>,
    pub challenge_windows: BTreeMap<String, ChallengeWindow>,
    pub mismatches: BTreeMap<String, MismatchRecord>,
    pub release_holds: BTreeMap<String, ReleaseHold>,
    pub claim_blockers: BTreeMap<String, ClaimBlocker>,
    pub claim_roots: BTreeMap<String, ClaimRootRecord>,
    pub stage_roots: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let wallet = WalletProofLink::new(
            "wallet-recovery-session-devnet-001",
            seeded_root("wallet-account", "alice-emergency-account"),
            seeded_root("local-backup", "encrypted-recovery-bundle"),
            seeded_root("pq-authorization", "dilithium-authority-quorum"),
            config.reference_height.saturating_sub(12),
            3,
            config.min_pq_security_bits,
        );
        let note = NoteRecoveryRoot::new(
            seeded_root("private-note-set", "forced-exit-note-a"),
            seeded_root("nullifier-set", "forced-exit-nullifier-a"),
            seeded_root("receipt-shards", "wallet-recovered-shards"),
            seeded_root("scan-hints", "bounded-subaddress-window"),
            seeded_root("amount-commitment", "claimable-xmr-bucket"),
            2,
        );
        let live_feed = LiveFeedRoot::new(
            "monero-header-live-adapter",
            "monero_lock_finality",
            seeded_root("live-feed-observation", "lock-finalized"),
            config
                .reference_height
                .saturating_sub(config.min_live_feed_confirmations),
            config.min_live_feed_confirmations,
            config.reference_height,
        );
        let provisional_binding = domain_hash(
            &domain("provisional-claim-binding"),
            &[
                HashPart::Str(&wallet.state_root()),
                HashPart::Str(&note.state_root()),
                HashPart::Str(&live_feed.state_root()),
            ],
            32,
        );
        let receipt_links = vec![
            ObservedReceiptLink::new(
                "withdrawal-claim-observed-receipt-ingest",
                "claim_admission",
                seeded_root("observed-receipt", "claim-admitted"),
                &provisional_binding,
                config.reference_height.saturating_sub(10),
                true,
            ),
            ObservedReceiptLink::new(
                "private-receipt-observed-receipt-ingest",
                "private_note_recovered",
                seeded_root("observed-receipt", "private-note-recovered"),
                &provisional_binding,
                config.reference_height.saturating_sub(9),
                true,
            ),
            ObservedReceiptLink::new(
                "release-blocker-observed-receipt-ingest",
                "no_blocking_dispute",
                seeded_root("observed-receipt", "no-dispute"),
                &provisional_binding,
                config.reference_height.saturating_sub(8),
                true,
            ),
        ];
        let settlement = SettlementTargetRoot::new(
            "monero-mainnet-devnet-sim",
            seeded_root("recipient", "emergency-recovery-address"),
            seeded_root("asset", "xmr-custody-release"),
            seeded_root("amount", "claimable-amount"),
            seeded_root("release-authority", "pq-bridge-quorum"),
            config.min_settlement_authorizers,
        );
        let receipt_root = merkle_for_records(
            "observed-receipt-links",
            receipt_links
                .iter()
                .map(ObservedReceiptLink::public_record)
                .collect(),
        );
        let empty_blocker_root = merkle_root(&domain("empty-claim-blockers"), &[]);
        let provisional_claim = ClaimRootRecord::new(
            "devnet-forced-exit-claim",
            wallet.state_root(),
            note.state_root(),
            live_feed.state_root(),
            receipt_root,
            settlement.state_root(),
            seeded_root("challenge-window", "pending-window"),
            empty_blocker_root,
        );
        let challenge = ChallengeWindow::new(
            &provisional_claim.claim_id,
            config.reference_height,
            config.challenge_window_blocks,
            seeded_root("dispute", "none-opened"),
            seeded_root("challenger-bond", "empty-pool"),
        );
        let hold = ReleaseHold::new(
            &provisional_claim.claim_id,
            "challenge_window_and_settlement_authority_grace_period",
            challenge.state_root(),
            config.reference_height,
            config.release_hold_blocks,
            true,
        );
        let blocker = ClaimBlocker::new(
            ClaimBlockerKind::ChallengeWindowOpen,
            &provisional_claim.claim_id,
            challenge.state_root(),
            config.reference_height,
            true,
        );
        let mismatch = MismatchRecord::new(
            seeded_root("expected-settlement-target", "claim-builder"),
            settlement.state_root(),
            "settlement_authority_crosscheck",
            "recipient_commitment",
            false,
        );
        let blocker_root = merkle_for_records("claim-blockers", vec![blocker.public_record()]);
        let claim = ClaimRootRecord::new(
            "devnet-forced-exit-claim",
            wallet.state_root(),
            note.state_root(),
            live_feed.state_root(),
            merkle_for_records(
                "observed-receipt-links",
                receipt_links
                    .iter()
                    .map(ObservedReceiptLink::public_record)
                    .collect(),
            ),
            settlement.state_root(),
            challenge.state_root(),
            blocker_root,
        );

        let mut wallet_proof_links = BTreeMap::new();
        wallet_proof_links.insert(wallet.link_id.clone(), wallet);
        let mut note_recovery_roots = BTreeMap::new();
        note_recovery_roots.insert(note.note_recovery_id.clone(), note);
        let mut live_feed_roots = BTreeMap::new();
        live_feed_roots.insert(live_feed.feed_id.clone(), live_feed);
        let mut observed_receipt_links = BTreeMap::new();
        for receipt in receipt_links {
            observed_receipt_links.insert(receipt.receipt_link_id.clone(), receipt);
        }
        let mut settlement_target_roots = BTreeMap::new();
        settlement_target_roots.insert(settlement.settlement_id.clone(), settlement);
        let mut challenge_windows = BTreeMap::new();
        challenge_windows.insert(challenge.window_id.clone(), challenge);
        let mut mismatches = BTreeMap::new();
        mismatches.insert(mismatch.mismatch_id.clone(), mismatch);
        let mut release_holds = BTreeMap::new();
        release_holds.insert(hold.hold_id.clone(), hold);
        let mut claim_blockers = BTreeMap::new();
        claim_blockers.insert(blocker.blocker_id.clone(), blocker);
        let mut claim_roots = BTreeMap::new();
        claim_roots.insert(claim.claim_id.clone(), claim);
        let stage_roots = stage_roots(&[
            ClaimBuildStage::WalletRecovered,
            ClaimBuildStage::NoteRootsBound,
            ClaimBuildStage::ReceiptsObserved,
            ClaimBuildStage::LiveFeedAnchored,
            ClaimBuildStage::ChallengeWindowOpened,
            ClaimBuildStage::SettlementAuthorized,
            ClaimBuildStage::ReleaseHeld,
        ]);

        Self {
            config,
            wallet_proof_links,
            note_recovery_roots,
            live_feed_roots,
            observed_receipt_links,
            settlement_target_roots,
            challenge_windows,
            mismatches,
            release_holds,
            claim_blockers,
            claim_roots,
            stage_roots,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "config_root": self.config.state_root(),
            "wallet_proof_link_root": self.wallet_proof_link_root(),
            "note_recovery_root": self.note_recovery_root(),
            "live_feed_root": self.live_feed_root(),
            "observed_receipt_link_root": self.observed_receipt_link_root(),
            "settlement_target_root": self.settlement_target_root(),
            "challenge_window_root": self.challenge_window_root(),
            "mismatch_root": self.mismatch_root(),
            "release_hold_root": self.release_hold_root(),
            "claim_blocker_root": self.claim_blocker_root(),
            "claim_root": self.claim_root(),
            "stage_root": self.stage_root(),
            "fail_closed": self.has_fail_closed_blockers(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &domain("state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }

    pub fn wallet_proof_link_root(&self) -> String {
        merkle_for_records(
            "wallet-proof-links",
            records(self.wallet_proof_links.values()),
        )
    }

    pub fn note_recovery_root(&self) -> String {
        merkle_for_records(
            "note-recovery-roots",
            records(self.note_recovery_roots.values()),
        )
    }

    pub fn live_feed_root(&self) -> String {
        merkle_for_records("live-feed-roots", records(self.live_feed_roots.values()))
    }

    pub fn observed_receipt_link_root(&self) -> String {
        merkle_for_records(
            "observed-receipt-links",
            records(self.observed_receipt_links.values()),
        )
    }

    pub fn settlement_target_root(&self) -> String {
        merkle_for_records(
            "settlement-target-roots",
            records(self.settlement_target_roots.values()),
        )
    }

    pub fn challenge_window_root(&self) -> String {
        merkle_for_records(
            "challenge-windows",
            records(self.challenge_windows.values()),
        )
    }

    pub fn mismatch_root(&self) -> String {
        merkle_for_records("mismatch-records", records(self.mismatches.values()))
    }

    pub fn release_hold_root(&self) -> String {
        merkle_for_records("release-holds", records(self.release_holds.values()))
    }

    pub fn claim_blocker_root(&self) -> String {
        merkle_for_records("claim-blockers", records(self.claim_blockers.values()))
    }

    pub fn claim_root(&self) -> String {
        merkle_for_records("claim-roots", records(self.claim_roots.values()))
    }

    pub fn stage_root(&self) -> String {
        let records = self
            .stage_roots
            .iter()
            .map(|(stage, root)| json!({ "stage": stage, "root": root }))
            .collect();
        merkle_for_records("stage-roots", records)
    }

    pub fn has_fail_closed_blockers(&self) -> bool {
        self.claim_blockers
            .values()
            .any(|blocker| blocker.fail_closed)
            || self.release_holds.values().any(|hold| hold.fail_closed)
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

fn stage_roots(stages: &[ClaimBuildStage]) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    for stage in stages {
        roots.insert(
            stage.as_str().to_string(),
            domain_hash(
                &domain("stage-root"),
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(stage.as_str()),
                ],
                32,
            ),
        );
    }
    roots
}

fn seeded_root(label: &str, seed: &str) -> String {
    domain_hash(
        &domain(label),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &domain(label),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn merkle_for_records(label: &str, records: Vec<Value>) -> String {
    let leaves = records
        .iter()
        .map(|record| record_root(label, record))
        .collect::<Vec<_>>();
    merkle_root(&domain(label), &leaves)
}

fn records<'a, T, I>(items: I) -> Vec<Value>
where
    T: PublicRecord + 'a,
    I: Iterator<Item = &'a T>,
{
    items.map(PublicRecord::public_record).collect()
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for WalletProofLink {
    fn public_record(&self) -> Value {
        WalletProofLink::public_record(self)
    }
}

impl PublicRecord for NoteRecoveryRoot {
    fn public_record(&self) -> Value {
        NoteRecoveryRoot::public_record(self)
    }
}

impl PublicRecord for LiveFeedRoot {
    fn public_record(&self) -> Value {
        LiveFeedRoot::public_record(self)
    }
}

impl PublicRecord for ObservedReceiptLink {
    fn public_record(&self) -> Value {
        ObservedReceiptLink::public_record(self)
    }
}

impl PublicRecord for SettlementTargetRoot {
    fn public_record(&self) -> Value {
        SettlementTargetRoot::public_record(self)
    }
}

impl PublicRecord for ChallengeWindow {
    fn public_record(&self) -> Value {
        ChallengeWindow::public_record(self)
    }
}

impl PublicRecord for MismatchRecord {
    fn public_record(&self) -> Value {
        MismatchRecord::public_record(self)
    }
}

impl PublicRecord for ReleaseHold {
    fn public_record(&self) -> Value {
        ReleaseHold::public_record(self)
    }
}

impl PublicRecord for ClaimBlocker {
    fn public_record(&self) -> Value {
        ClaimBlocker::public_record(self)
    }
}

impl PublicRecord for ClaimRootRecord {
    fn public_record(&self) -> Value {
        ClaimRootRecord::public_record(self)
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn domain(label: &str) -> String {
    format!("{DOMAIN}-{label}")
}
