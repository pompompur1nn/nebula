use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePqCustodyReleaseAuthorizationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_CUSTODY_RELEASE_AUTHORIZATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-custody-release-authorization-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_CUSTODY_RELEASE_AUTHORIZATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-custody-release-v1";
pub const WITHDRAWAL_AUTHORITY_SUITE: &str =
    "monero-l2-private-withdrawal-authority-rooted-release-v1";
pub const WATCHER_ATTESTATION_SUITE: &str =
    "monero-l2-pq-watcher-release-attestation-roots-only-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_SIGNER_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 60;
pub const DEFAULT_MIN_TOTAL_WEIGHT: u64 = 140;
pub const DEFAULT_AUTHORIZATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_ROTATION_GRACE_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_EPOCH_GAP: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 480_000;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseLane {
    Standard,
    FastExit,
    LiquidityNetting,
    ForcedExit,
    EmergencyRecovery,
}

impl ReleaseLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::FastExit => "fast_exit",
            Self::LiquidityNetting => "liquidity_netting",
            Self::ForcedExit => "forced_exit",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn minimum_delay(self, config: &Config) -> u64 {
        match self {
            Self::FastExit => config.release_delay_blocks / 2,
            Self::EmergencyRecovery | Self::ForcedExit => config.release_delay_blocks,
            Self::LiquidityNetting => config.release_delay_blocks + 12,
            Self::Standard => config.release_delay_blocks,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Draft,
    PendingWitness,
    PendingQuorum,
    Authorized,
    Held,
    Expired,
    Revoked,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PendingWitness => "pending_witness",
            Self::PendingQuorum => "pending_quorum",
            Self::Authorized => "authorized",
            Self::Held => "held",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn releasable(self) -> bool {
        matches!(self, Self::Authorized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    MissingPqSignerQuorum,
    MissingWatcherAttestation,
    InsufficientThresholdWeight,
    KeyEpochGap,
    RotationPending,
    RotationRevoked,
    WithdrawalAuthorityMissing,
    TranscriptRootMismatch,
    SignatureDomainMismatch,
    ExpiredAuthorization,
    ChallengeOpen,
    DuplicateNullifier,
}

impl HoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingPqSignerQuorum => "missing_pq_signer_quorum",
            Self::MissingWatcherAttestation => "missing_watcher_attestation",
            Self::InsufficientThresholdWeight => "insufficient_threshold_weight",
            Self::KeyEpochGap => "key_epoch_gap",
            Self::RotationPending => "rotation_pending",
            Self::RotationRevoked => "rotation_revoked",
            Self::WithdrawalAuthorityMissing => "withdrawal_authority_missing",
            Self::TranscriptRootMismatch => "transcript_root_mismatch",
            Self::SignatureDomainMismatch => "signature_domain_mismatch",
            Self::ExpiredAuthorization => "expired_authorization",
            Self::ChallengeOpen => "challenge_open",
            Self::DuplicateNullifier => "duplicate_nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Active,
    Scheduled,
    Grace,
    Retired,
    Revoked,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Scheduled => "scheduled",
            Self::Grace => "grace",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    CustodyCouncil,
    WithdrawalCouncil,
    ReserveCouncil,
    EmergencyCouncil,
}

impl SignerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyCouncil => "custody_council",
            Self::WithdrawalCouncil => "withdrawal_council",
            Self::ReserveCouncil => "reserve_council",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherKind {
    MoneroLockWatcher,
    L2BurnWatcher,
    SettlementWatcher,
    ChallengeWatcher,
    ReserveWatcher,
}

impl WatcherKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroLockWatcher => "monero_lock_watcher",
            Self::L2BurnWatcher => "l2_burn_watcher",
            Self::SettlementWatcher => "settlement_watcher",
            Self::ChallengeWatcher => "challenge_watcher",
            Self::ReserveWatcher => "reserve_watcher",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityScope {
    ReleaseCustody,
    BindWithdrawal,
    BindBurnNullifier,
    BindSettlementOutput,
    EmergencyDelayOnly,
}

impl AuthorityScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseCustody => "release_custody",
            Self::BindWithdrawal => "bind_withdrawal",
            Self::BindBurnNullifier => "bind_burn_nullifier",
            Self::BindSettlementOutput => "bind_settlement_output",
            Self::EmergencyDelayOnly => "emergency_delay_only",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub withdrawal_authority_suite: String,
    pub watcher_attestation_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_signer_weight: u64,
    pub min_watcher_weight: u64,
    pub min_total_weight: u64,
    pub authorization_ttl_blocks: u64,
    pub release_delay_blocks: u64,
    pub rotation_grace_blocks: u64,
    pub max_epoch_gap: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            withdrawal_authority_suite: WITHDRAWAL_AUTHORITY_SUITE.to_string(),
            watcher_attestation_suite: WATCHER_ATTESTATION_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_signer_weight: DEFAULT_MIN_SIGNER_WEIGHT,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            min_total_weight: DEFAULT_MIN_TOTAL_WEIGHT,
            authorization_ttl_blocks: DEFAULT_AUTHORIZATION_TTL_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            rotation_grace_blocks: DEFAULT_ROTATION_GRACE_BLOCKS,
            max_epoch_gap: DEFAULT_MAX_EPOCH_GAP,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "authorization_ttl_blocks": self.authorization_ttl_blocks,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "l2_network": self.l2_network,
            "max_epoch_gap": self.max_epoch_gap,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_signer_weight": self.min_signer_weight,
            "min_total_weight": self.min_total_weight,
            "min_watcher_weight": self.min_watcher_weight,
            "monero_network": self.monero_network,
            "protocol_version": self.protocol_version,
            "pq_signature_suite": self.pq_signature_suite,
            "release_delay_blocks": self.release_delay_blocks,
            "rotation_grace_blocks": self.rotation_grace_blocks,
            "schema_version": self.schema_version,
            "watcher_attestation_suite": self.watcher_attestation_suite,
            "withdrawal_authority_suite": self.withdrawal_authority_suite,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSigner {
    pub signer_id: String,
    pub role: SignerRole,
    pub key_epoch: u64,
    pub public_key_commitment: String,
    pub signature_domain_root: String,
    pub rotation_id: String,
    pub threshold_weight: u64,
    pub pq_security_bits: u16,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl PqSigner {
    pub fn new(
        label: &str,
        role: SignerRole,
        key_epoch: u64,
        threshold_weight: u64,
        active_from_height: u64,
        active_until_height: u64,
    ) -> Self {
        let public_key_commitment = text_hash("MCRAR-PQ-SIGNER-PUBKEY", label);
        let rotation_id = domain_hash(
            "MCRAR-PQ-SIGNER-ROTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::U64(key_epoch),
            ],
            32,
        );
        let signature_domain_root = domain_hash(
            "MCRAR-PQ-SIGNER-DOMAIN-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(role.as_str()),
                HashPart::Str(&public_key_commitment),
                HashPart::U64(key_epoch),
            ],
            32,
        );
        let signer_id = domain_hash(
            "MCRAR-PQ-SIGNER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(&signature_domain_root),
            ],
            20,
        );
        Self {
            signer_id,
            role,
            key_epoch,
            public_key_commitment,
            signature_domain_root,
            rotation_id,
            threshold_weight,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            active_from_height,
            active_until_height,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.active_from_height <= height && height <= self.active_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "key_epoch": self.key_epoch,
            "pq_security_bits": self.pq_security_bits,
            "public_key_commitment": self.public_key_commitment,
            "role": self.role.as_str(),
            "rotation_id": self.rotation_id,
            "signature_domain_root": self.signature_domain_root,
            "signer_id": self.signer_id,
            "threshold_weight": self.threshold_weight,
        })
    }

    pub fn record_id(&self) -> String {
        domain_hash(
            "MCRAR-PQ-SIGNER-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Watcher {
    pub watcher_id: String,
    pub kind: WatcherKind,
    pub operator_commitment: String,
    pub attestation_domain_root: String,
    pub threshold_weight: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl Watcher {
    pub fn new(
        label: &str,
        kind: WatcherKind,
        threshold_weight: u64,
        active_from_height: u64,
        active_until_height: u64,
    ) -> Self {
        let operator_commitment = text_hash("MCRAR-WATCHER-OPERATOR", label);
        let attestation_domain_root = domain_hash(
            "MCRAR-WATCHER-DOMAIN-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&operator_commitment),
            ],
            32,
        );
        let watcher_id = domain_hash(
            "MCRAR-WATCHER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(&attestation_domain_root),
            ],
            20,
        );
        Self {
            watcher_id,
            kind,
            operator_commitment,
            attestation_domain_root,
            threshold_weight,
            active_from_height,
            active_until_height,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.active_from_height <= height && height <= self.active_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "attestation_domain_root": self.attestation_domain_root,
            "kind": self.kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "threshold_weight": self.threshold_weight,
            "watcher_id": self.watcher_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyEpoch {
    pub epoch: u64,
    pub previous_epoch: u64,
    pub signer_set_root: String,
    pub watcher_set_root: String,
    pub continuity_root: String,
    pub activation_height: u64,
    pub retirement_height: u64,
}

impl KeyEpoch {
    pub fn new(
        epoch: u64,
        previous_epoch: u64,
        signer_set_root: String,
        watcher_set_root: String,
        activation_height: u64,
        retirement_height: u64,
    ) -> Self {
        let continuity_root = domain_hash(
            "MCRAR-KEY-EPOCH-CONTINUITY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(previous_epoch),
                HashPart::U64(epoch),
                HashPart::Str(&signer_set_root),
                HashPart::Str(&watcher_set_root),
            ],
            32,
        );
        Self {
            epoch,
            previous_epoch,
            signer_set_root,
            watcher_set_root,
            continuity_root,
            activation_height,
            retirement_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "activation_height": self.activation_height,
            "continuity_root": self.continuity_root,
            "epoch": self.epoch,
            "previous_epoch": self.previous_epoch,
            "retirement_height": self.retirement_height,
            "signer_set_root": self.signer_set_root,
            "watcher_set_root": self.watcher_set_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotationRecord {
    pub rotation_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub status: RotationStatus,
    pub scheduled_height: u64,
    pub effective_height: u64,
    pub grace_until_height: u64,
    pub continuity_root: String,
}

impl RotationRecord {
    pub fn new(
        from_epoch: u64,
        to_epoch: u64,
        status: RotationStatus,
        scheduled_height: u64,
        effective_height: u64,
        grace_until_height: u64,
        continuity_root: String,
    ) -> Self {
        let rotation_id = domain_hash(
            "MCRAR-ROTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(from_epoch),
                HashPart::U64(to_epoch),
                HashPart::Str(status.as_str()),
                HashPart::Str(&continuity_root),
            ],
            32,
        );
        Self {
            rotation_id,
            from_epoch,
            to_epoch,
            status,
            scheduled_height,
            effective_height,
            grace_until_height,
            continuity_root,
        }
    }

    pub fn active_for_release(&self, height: u64) -> bool {
        self.status.permits_release()
            && self.effective_height <= height
            && height <= self.grace_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "continuity_root": self.continuity_root,
            "effective_height": self.effective_height,
            "from_epoch": self.from_epoch,
            "grace_until_height": self.grace_until_height,
            "rotation_id": self.rotation_id,
            "scheduled_height": self.scheduled_height,
            "status": self.status.as_str(),
            "to_epoch": self.to_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalAuthority {
    pub authority_id: String,
    pub scope: AuthorityScope,
    pub withdrawal_commitment: String,
    pub burn_nullifier: String,
    pub recipient_view_tag_root: String,
    pub settlement_output_root: String,
    pub authority_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl WithdrawalAuthority {
    pub fn new(
        label: &str,
        scope: AuthorityScope,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let withdrawal_commitment = text_hash("MCRAR-WITHDRAWAL-COMMITMENT", label);
        let burn_nullifier = text_hash("MCRAR-BURN-NULLIFIER", label);
        let recipient_view_tag_root = text_hash("MCRAR-RECIPIENT-VIEW-TAG-ROOT", label);
        let settlement_output_root = text_hash("MCRAR-SETTLEMENT-OUTPUT-ROOT", label);
        let authority_root = domain_hash(
            "MCRAR-WITHDRAWAL-AUTHORITY-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(scope.as_str()),
                HashPart::Str(&withdrawal_commitment),
                HashPart::Str(&burn_nullifier),
                HashPart::Str(&recipient_view_tag_root),
                HashPart::Str(&settlement_output_root),
            ],
            32,
        );
        let authority_id = domain_hash(
            "MCRAR-WITHDRAWAL-AUTHORITY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(&authority_root),
            ],
            20,
        );
        Self {
            authority_id,
            scope,
            withdrawal_commitment,
            burn_nullifier,
            recipient_view_tag_root,
            settlement_output_root,
            authority_root,
            valid_from_height,
            expires_at_height,
        }
    }

    pub fn valid_at(&self, height: u64) -> bool {
        self.valid_from_height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "authority_root": self.authority_root,
            "burn_nullifier": self.burn_nullifier,
            "expires_at_height": self.expires_at_height,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "scope": self.scope.as_str(),
            "settlement_output_root": self.settlement_output_root,
            "valid_from_height": self.valid_from_height,
            "withdrawal_commitment": self.withdrawal_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseRequest {
    pub request_id: String,
    pub lane: ReleaseLane,
    pub authority_id: String,
    pub key_epoch: u64,
    pub requested_height: u64,
    pub min_release_height: u64,
    pub expires_at_height: u64,
    pub custody_note_root: String,
    pub bridge_exit_root: String,
    pub transcript_root: String,
    pub signature_domain_root: String,
    pub withdrawal_authority_root: String,
    pub challenge_root: String,
    pub replay_nullifier: String,
}

impl ReleaseRequest {
    pub fn new(
        config: &Config,
        label: &str,
        lane: ReleaseLane,
        authority: &WithdrawalAuthority,
        key_epoch: u64,
        requested_height: u64,
    ) -> Self {
        let custody_note_root = text_hash("MCRAR-CUSTODY-NOTE-ROOT", label);
        let bridge_exit_root = text_hash("MCRAR-BRIDGE-EXIT-ROOT", label);
        let challenge_root = text_hash("MCRAR-CHALLENGE-ROOT", label);
        let replay_nullifier = text_hash("MCRAR-REPLAY-NULLIFIER", label);
        let transcript_root = domain_hash(
            "MCRAR-AUTHORIZATION-TRANSCRIPT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane.as_str()),
                HashPart::Str(&authority.authority_root),
                HashPart::Str(&custody_note_root),
                HashPart::Str(&bridge_exit_root),
                HashPart::Str(&challenge_root),
                HashPart::Str(&replay_nullifier),
                HashPart::U64(key_epoch),
            ],
            32,
        );
        let signature_domain_root = domain_hash(
            "MCRAR-REQUEST-SIGNATURE-DOMAIN",
            &[
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&config.chain_id),
                HashPart::Str(&config.asset_id),
                HashPart::Str(&transcript_root),
            ],
            32,
        );
        let min_release_height = requested_height.saturating_add(lane.minimum_delay(config));
        let expires_at_height = requested_height.saturating_add(config.authorization_ttl_blocks);
        let request_id = domain_hash(
            "MCRAR-RELEASE-REQUEST-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(&transcript_root),
                HashPart::Str(&signature_domain_root),
            ],
            20,
        );
        Self {
            request_id,
            lane,
            authority_id: authority.authority_id.clone(),
            key_epoch,
            requested_height,
            min_release_height,
            expires_at_height,
            custody_note_root,
            bridge_exit_root,
            transcript_root,
            signature_domain_root,
            withdrawal_authority_root: authority.authority_root.clone(),
            challenge_root,
            replay_nullifier,
        }
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn delay_satisfied_at(&self, height: u64) -> bool {
        height >= self.min_release_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "bridge_exit_root": self.bridge_exit_root,
            "challenge_root": self.challenge_root,
            "custody_note_root": self.custody_note_root,
            "expires_at_height": self.expires_at_height,
            "key_epoch": self.key_epoch,
            "lane": self.lane.as_str(),
            "min_release_height": self.min_release_height,
            "replay_nullifier": self.replay_nullifier,
            "request_id": self.request_id,
            "requested_height": self.requested_height,
            "signature_domain_root": self.signature_domain_root,
            "transcript_root": self.transcript_root,
            "withdrawal_authority_root": self.withdrawal_authority_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqQuorumSignature {
    pub signature_id: String,
    pub request_id: String,
    pub signer_id: String,
    pub key_epoch: u64,
    pub transcript_root: String,
    pub signature_domain_root: String,
    pub signature_commitment: String,
    pub threshold_weight: u64,
    pub observed_height: u64,
}

impl PqQuorumSignature {
    pub fn new(request: &ReleaseRequest, signer: &PqSigner, observed_height: u64) -> Self {
        let signature_commitment = domain_hash(
            "MCRAR-PQ-SIGNATURE-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.request_id),
                HashPart::Str(&signer.signer_id),
                HashPart::Str(&request.transcript_root),
                HashPart::Str(&request.signature_domain_root),
            ],
            32,
        );
        let signature_id = domain_hash(
            "MCRAR-PQ-SIGNATURE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&signature_commitment),
                HashPart::U64(observed_height),
            ],
            20,
        );
        Self {
            signature_id,
            request_id: request.request_id.clone(),
            signer_id: signer.signer_id.clone(),
            key_epoch: signer.key_epoch,
            transcript_root: request.transcript_root.clone(),
            signature_domain_root: request.signature_domain_root.clone(),
            signature_commitment,
            threshold_weight: signer.threshold_weight,
            observed_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "key_epoch": self.key_epoch,
            "observed_height": self.observed_height,
            "request_id": self.request_id,
            "signature_commitment": self.signature_commitment,
            "signature_domain_root": self.signature_domain_root,
            "signature_id": self.signature_id,
            "signer_id": self.signer_id,
            "threshold_weight": self.threshold_weight,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub request_id: String,
    pub watcher_id: String,
    pub kind: WatcherKind,
    pub observed_height: u64,
    pub withdrawal_authority_root: String,
    pub transcript_root: String,
    pub release_observation_root: String,
    pub challenge_absence_root: String,
    pub threshold_weight: u64,
}

impl WatcherAttestation {
    pub fn new(request: &ReleaseRequest, watcher: &Watcher, observed_height: u64) -> Self {
        let release_observation_root = domain_hash(
            "MCRAR-WATCHER-RELEASE-OBSERVATION",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.request_id),
                HashPart::Str(&request.withdrawal_authority_root),
                HashPart::Str(&request.replay_nullifier),
            ],
            32,
        );
        let challenge_absence_root = domain_hash(
            "MCRAR-WATCHER-CHALLENGE-ABSENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.challenge_root),
                HashPart::Str(&watcher.attestation_domain_root),
            ],
            32,
        );
        let attestation_id = domain_hash(
            "MCRAR-WATCHER-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.request_id),
                HashPart::Str(&watcher.watcher_id),
                HashPart::Str(&release_observation_root),
            ],
            20,
        );
        Self {
            attestation_id,
            request_id: request.request_id.clone(),
            watcher_id: watcher.watcher_id.clone(),
            kind: watcher.kind,
            observed_height,
            withdrawal_authority_root: request.withdrawal_authority_root.clone(),
            transcript_root: request.transcript_root.clone(),
            release_observation_root,
            challenge_absence_root,
            threshold_weight: watcher.threshold_weight,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "challenge_absence_root": self.challenge_absence_root,
            "kind": self.kind.as_str(),
            "observed_height": self.observed_height,
            "release_observation_root": self.release_observation_root,
            "request_id": self.request_id,
            "threshold_weight": self.threshold_weight,
            "transcript_root": self.transcript_root,
            "watcher_id": self.watcher_id,
            "withdrawal_authority_root": self.withdrawal_authority_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationHold {
    pub hold_id: String,
    pub request_id: String,
    pub reason: HoldReason,
    pub opened_height: u64,
    pub release_after_height: u64,
    pub evidence_root: String,
    pub fail_closed: bool,
}

impl AuthorizationHold {
    pub fn new(
        request_id: &str,
        reason: HoldReason,
        opened_height: u64,
        release_after_height: u64,
        evidence_root: String,
    ) -> Self {
        let hold_id = domain_hash(
            "MCRAR-AUTHORIZATION-HOLD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(request_id),
                HashPart::Str(reason.as_str()),
                HashPart::U64(opened_height),
                HashPart::Str(&evidence_root),
            ],
            20,
        );
        Self {
            hold_id,
            request_id: request_id.to_string(),
            reason,
            opened_height,
            release_after_height,
            evidence_root,
            fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_root": self.evidence_root,
            "fail_closed": self.fail_closed,
            "hold_id": self.hold_id,
            "opened_height": self.opened_height,
            "reason": self.reason.as_str(),
            "release_after_height": self.release_after_height,
            "request_id": self.request_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationDecision {
    pub decision_id: String,
    pub request_id: String,
    pub status: AuthorizationStatus,
    pub signer_weight: u64,
    pub watcher_weight: u64,
    pub total_weight: u64,
    pub signer_quorum_root: String,
    pub watcher_attestation_root: String,
    pub hold_root: String,
    pub key_epoch_continuity_root: String,
    pub rotation_root: String,
    pub withdrawal_authority_root: String,
    pub authorization_transcript_root: String,
    pub signature_domain_root: String,
    pub decided_height: u64,
    pub hold_reasons: Vec<String>,
}

impl AuthorizationDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_transcript_root": self.authorization_transcript_root,
            "decided_height": self.decided_height,
            "decision_id": self.decision_id,
            "hold_reasons": self.hold_reasons,
            "hold_root": self.hold_root,
            "key_epoch_continuity_root": self.key_epoch_continuity_root,
            "request_id": self.request_id,
            "rotation_root": self.rotation_root,
            "signature_domain_root": self.signature_domain_root,
            "signer_quorum_root": self.signer_quorum_root,
            "signer_weight": self.signer_weight,
            "status": self.status.as_str(),
            "total_weight": self.total_weight,
            "watcher_attestation_root": self.watcher_attestation_root,
            "watcher_weight": self.watcher_weight,
            "withdrawal_authority_root": self.withdrawal_authority_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateRoots {
    pub config_root: String,
    pub signer_root: String,
    pub watcher_root: String,
    pub key_epoch_root: String,
    pub rotation_root: String,
    pub withdrawal_authority_root: String,
    pub release_request_root: String,
    pub pq_signature_root: String,
    pub watcher_attestation_root: String,
    pub hold_root: String,
    pub decision_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl StateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "decision_root": self.decision_root,
            "hold_root": self.hold_root,
            "key_epoch_root": self.key_epoch_root,
            "pq_signature_root": self.pq_signature_root,
            "public_record_root": self.public_record_root,
            "release_request_root": self.release_request_root,
            "rotation_root": self.rotation_root,
            "signer_root": self.signer_root,
            "state_root": self.state_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "watcher_root": self.watcher_root,
            "withdrawal_authority_root": self.withdrawal_authority_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub signers: BTreeMap<String, PqSigner>,
    pub watchers: BTreeMap<String, Watcher>,
    pub key_epochs: BTreeMap<u64, KeyEpoch>,
    pub rotations: BTreeMap<String, RotationRecord>,
    pub withdrawal_authorities: BTreeMap<String, WithdrawalAuthority>,
    pub release_requests: BTreeMap<String, ReleaseRequest>,
    pub pq_signatures: BTreeMap<String, PqQuorumSignature>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub holds: BTreeMap<String, AuthorizationHold>,
    pub decisions: BTreeMap<String, AuthorizationDecision>,
    pub consumed_nullifiers: BTreeMap<String, String>,
    pub roots: StateRoots,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        let mut state = Self {
            config,
            height,
            signers: BTreeMap::new(),
            watchers: BTreeMap::new(),
            key_epochs: BTreeMap::new(),
            rotations: BTreeMap::new(),
            withdrawal_authorities: BTreeMap::new(),
            release_requests: BTreeMap::new(),
            pq_signatures: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            holds: BTreeMap::new(),
            decisions: BTreeMap::new(),
            consumed_nullifiers: BTreeMap::new(),
            roots: StateRoots::default(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let config = Config::default();
        let mut state = Self::new(config, DEVNET_HEIGHT);

        let signer_specs = [
            (
                "custody-alpha",
                SignerRole::CustodyCouncil,
                7_u64,
                34_u64,
                DEVNET_HEIGHT - 240,
                DEVNET_HEIGHT + 10_000,
            ),
            (
                "custody-beta",
                SignerRole::CustodyCouncil,
                7,
                33,
                DEVNET_HEIGHT - 240,
                DEVNET_HEIGHT + 10_000,
            ),
            (
                "withdrawal-gamma",
                SignerRole::WithdrawalCouncil,
                7,
                35,
                DEVNET_HEIGHT - 220,
                DEVNET_HEIGHT + 10_000,
            ),
            (
                "reserve-delta",
                SignerRole::ReserveCouncil,
                7,
                20,
                DEVNET_HEIGHT - 210,
                DEVNET_HEIGHT + 10_000,
            ),
        ];
        for spec in signer_specs {
            let signer = PqSigner::new(spec.0, spec.1, spec.2, spec.3, spec.4, spec.5);
            state.signers.insert(signer.signer_id.clone(), signer);
        }

        let watcher_specs = [
            (
                "monero-lock-watch-a",
                WatcherKind::MoneroLockWatcher,
                24_u64,
                DEVNET_HEIGHT - 300,
                DEVNET_HEIGHT + 12_000,
            ),
            (
                "l2-burn-watch-b",
                WatcherKind::L2BurnWatcher,
                22,
                DEVNET_HEIGHT - 300,
                DEVNET_HEIGHT + 12_000,
            ),
            (
                "settlement-watch-c",
                WatcherKind::SettlementWatcher,
                20,
                DEVNET_HEIGHT - 300,
                DEVNET_HEIGHT + 12_000,
            ),
            (
                "challenge-watch-d",
                WatcherKind::ChallengeWatcher,
                18,
                DEVNET_HEIGHT - 300,
                DEVNET_HEIGHT + 12_000,
            ),
        ];
        for spec in watcher_specs {
            let watcher = Watcher::new(spec.0, spec.1, spec.2, spec.3, spec.4);
            state.watchers.insert(watcher.watcher_id.clone(), watcher);
        }

        let signer_set_root = state.signer_root();
        let watcher_set_root = state.watcher_root();
        let previous_epoch = KeyEpoch::new(
            6,
            5,
            text_hash("MCRAR-PRIOR-SIGNER-SET", "epoch-6"),
            text_hash("MCRAR-PRIOR-WATCHER-SET", "epoch-6"),
            DEVNET_HEIGHT - 20_000,
            DEVNET_HEIGHT - 241,
        );
        let active_epoch = KeyEpoch::new(
            7,
            6,
            signer_set_root,
            watcher_set_root,
            DEVNET_HEIGHT - 240,
            DEVNET_HEIGHT + 10_000,
        );
        state
            .key_epochs
            .insert(previous_epoch.epoch, previous_epoch);
        state
            .key_epochs
            .insert(active_epoch.epoch, active_epoch.clone());

        let rotation = RotationRecord::new(
            6,
            7,
            RotationStatus::Active,
            DEVNET_HEIGHT - 360,
            DEVNET_HEIGHT - 240,
            DEVNET_HEIGHT + state.config.rotation_grace_blocks,
            active_epoch.continuity_root.clone(),
        );
        state
            .rotations
            .insert(rotation.rotation_id.clone(), rotation);

        let standard_authority = WithdrawalAuthority::new(
            "devnet-standard-release",
            AuthorityScope::ReleaseCustody,
            DEVNET_HEIGHT - 12,
            DEVNET_HEIGHT + 120,
        );
        let pending_authority = WithdrawalAuthority::new(
            "devnet-pending-release",
            AuthorityScope::BindWithdrawal,
            DEVNET_HEIGHT - 12,
            DEVNET_HEIGHT + 120,
        );
        state.withdrawal_authorities.insert(
            standard_authority.authority_id.clone(),
            standard_authority.clone(),
        );
        state.withdrawal_authorities.insert(
            pending_authority.authority_id.clone(),
            pending_authority.clone(),
        );

        let release = ReleaseRequest::new(
            &state.config,
            "devnet-standard-release",
            ReleaseLane::Standard,
            &standard_authority,
            7,
            DEVNET_HEIGHT - 40,
        );
        let pending = ReleaseRequest::new(
            &state.config,
            "devnet-pending-release",
            ReleaseLane::FastExit,
            &pending_authority,
            7,
            DEVNET_HEIGHT - 8,
        );
        state
            .release_requests
            .insert(release.request_id.clone(), release.clone());
        state
            .release_requests
            .insert(pending.request_id.clone(), pending.clone());

        let signer_values: Vec<PqSigner> = state.signers.values().cloned().collect();
        for signer in signer_values.iter().take(3) {
            let signature = PqQuorumSignature::new(&release, signer, DEVNET_HEIGHT - 6);
            state
                .pq_signatures
                .insert(signature.signature_id.clone(), signature);
        }
        for signer in signer_values.iter().take(1) {
            let signature = PqQuorumSignature::new(&pending, signer, DEVNET_HEIGHT - 4);
            state
                .pq_signatures
                .insert(signature.signature_id.clone(), signature);
        }

        let watcher_values: Vec<Watcher> = state.watchers.values().cloned().collect();
        for watcher in watcher_values.iter().take(3) {
            let attestation = WatcherAttestation::new(&release, watcher, DEVNET_HEIGHT - 5);
            state
                .watcher_attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }
        for watcher in watcher_values.iter().take(1) {
            let attestation = WatcherAttestation::new(&pending, watcher, DEVNET_HEIGHT - 3);
            state
                .watcher_attestations
                .insert(attestation.attestation_id.clone(), attestation);
        }

        let release_decision = state.evaluate_request(&release.request_id);
        state
            .decisions
            .insert(release_decision.decision_id.clone(), release_decision);
        let pending_decision = state.evaluate_request(&pending.request_id);
        for hold in state.derive_holds(&pending_decision) {
            state.holds.insert(hold.hold_id.clone(), hold);
        }
        state
            .decisions
            .insert(pending_decision.decision_id.clone(), pending_decision);
        state.recompute_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "consumed_nullifier_root": self.consumed_nullifier_root(),
            "height": self.height,
            "key_epoch_count": self.key_epochs.len(),
            "protocol_version": self.config.protocol_version,
            "release_request_count": self.release_requests.len(),
            "roots": self.roots.public_record(),
            "signer_count": self.signers.len(),
            "watcher_count": self.watchers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn signer_root(&self) -> String {
        records_root(
            "MCRAR-STATE-PQ-SIGNERS",
            self.signers.values().map(PqSigner::public_record).collect(),
        )
    }

    pub fn watcher_root(&self) -> String {
        records_root(
            "MCRAR-STATE-WATCHERS",
            self.watchers.values().map(Watcher::public_record).collect(),
        )
    }

    pub fn evaluate_request(&self, request_id: &str) -> AuthorizationDecision {
        let maybe_request = self.release_requests.get(request_id);
        let empty_root = merkle_root("MCRAR-EMPTY", &[]);
        let request = match maybe_request {
            Some(value) => value,
            None => {
                let decision_payload = json!({
                    "missing_request_id": request_id,
                    "status": AuthorizationStatus::Held.as_str(),
                });
                let decision_id = domain_hash(
                    "MCRAR-AUTHORIZATION-DECISION-ID",
                    &[HashPart::Json(&decision_payload)],
                    20,
                );
                return AuthorizationDecision {
                    decision_id,
                    request_id: request_id.to_string(),
                    status: AuthorizationStatus::Held,
                    signer_weight: 0,
                    watcher_weight: 0,
                    total_weight: 0,
                    signer_quorum_root: empty_root.clone(),
                    watcher_attestation_root: empty_root.clone(),
                    hold_root: empty_root.clone(),
                    key_epoch_continuity_root: empty_root.clone(),
                    rotation_root: empty_root.clone(),
                    withdrawal_authority_root: empty_root.clone(),
                    authorization_transcript_root: empty_root.clone(),
                    signature_domain_root: empty_root,
                    decided_height: self.height,
                    hold_reasons: vec![HoldReason::WithdrawalAuthorityMissing.as_str().to_string()],
                };
            }
        };

        let signatures = self.signatures_for_request(&request.request_id);
        let attestations = self.attestations_for_request(&request.request_id);
        let signer_weight = signatures
            .iter()
            .map(|record| record.threshold_weight)
            .sum();
        let watcher_weight = attestations
            .iter()
            .map(|record| record.threshold_weight)
            .sum();
        let total_weight = signer_weight + watcher_weight;
        let signer_quorum_root = records_root(
            "MCRAR-DECISION-SIGNER-QUORUM",
            signatures
                .iter()
                .map(|record| record.public_record())
                .collect::<Vec<_>>(),
        );
        let watcher_attestation_root = records_root(
            "MCRAR-DECISION-WATCHER-ATTESTATIONS",
            attestations
                .iter()
                .map(|record| record.public_record())
                .collect::<Vec<_>>(),
        );
        let key_epoch_continuity_root = self
            .key_epochs
            .get(&request.key_epoch)
            .map(|epoch| epoch.continuity_root.clone())
            .unwrap_or_else(|| merkle_root("MCRAR-MISSING-KEY-EPOCH", &[]));
        let rotation_root = self.rotation_root_for_epoch(request.key_epoch);
        let mut reasons = Vec::new();

        if signer_weight < self.config.min_signer_weight {
            reasons.push(HoldReason::MissingPqSignerQuorum.as_str().to_string());
        }
        if watcher_weight < self.config.min_watcher_weight {
            reasons.push(HoldReason::MissingWatcherAttestation.as_str().to_string());
        }
        if total_weight < self.config.min_total_weight {
            reasons.push(HoldReason::InsufficientThresholdWeight.as_str().to_string());
        }
        if !self.key_epoch_continuous(request.key_epoch) {
            reasons.push(HoldReason::KeyEpochGap.as_str().to_string());
        }
        if !self.rotation_permits_release(request.key_epoch) {
            reasons.push(HoldReason::RotationPending.as_str().to_string());
        }
        if !self.authority_valid(request) {
            reasons.push(HoldReason::WithdrawalAuthorityMissing.as_str().to_string());
        }
        if !self.signatures_match_request(request, &signatures) {
            reasons.push(HoldReason::SignatureDomainMismatch.as_str().to_string());
        }
        if !self.attestations_match_request(request, &attestations) {
            reasons.push(HoldReason::TranscriptRootMismatch.as_str().to_string());
        }
        if request.expired_at(self.height) {
            reasons.push(HoldReason::ExpiredAuthorization.as_str().to_string());
        }
        if self
            .consumed_nullifiers
            .contains_key(&request.replay_nullifier)
        {
            reasons.push(HoldReason::DuplicateNullifier.as_str().to_string());
        }

        let hold_root = if reasons.is_empty() {
            merkle_root("MCRAR-DECISION-HOLDS", &[])
        } else {
            let hold_records = reasons
                .iter()
                .map(|reason| {
                    json!({
                        "request_id": request.request_id,
                        "reason": reason,
                    })
                })
                .collect::<Vec<_>>();
            merkle_root("MCRAR-DECISION-HOLDS", &hold_records)
        };
        let status = if reasons.is_empty() && request.delay_satisfied_at(self.height) {
            AuthorizationStatus::Authorized
        } else if reasons.is_empty() {
            AuthorizationStatus::PendingWitness
        } else {
            AuthorizationStatus::Held
        };
        let decision_payload = json!({
            "authorization_transcript_root": request.transcript_root,
            "hold_root": hold_root,
            "key_epoch_continuity_root": key_epoch_continuity_root,
            "request_id": request.request_id,
            "rotation_root": rotation_root,
            "signature_domain_root": request.signature_domain_root,
            "signer_quorum_root": signer_quorum_root,
            "status": status.as_str(),
            "watcher_attestation_root": watcher_attestation_root,
            "withdrawal_authority_root": request.withdrawal_authority_root,
        });
        let decision_id = domain_hash(
            "MCRAR-AUTHORIZATION-DECISION-ID",
            &[
                HashPart::Json(&decision_payload),
                HashPart::U64(self.height),
            ],
            20,
        );

        AuthorizationDecision {
            decision_id,
            request_id: request.request_id.clone(),
            status,
            signer_weight,
            watcher_weight,
            total_weight,
            signer_quorum_root,
            watcher_attestation_root,
            hold_root,
            key_epoch_continuity_root,
            rotation_root,
            withdrawal_authority_root: request.withdrawal_authority_root.clone(),
            authorization_transcript_root: request.transcript_root.clone(),
            signature_domain_root: request.signature_domain_root.clone(),
            decided_height: self.height,
            hold_reasons: reasons,
        }
    }

    pub fn derive_holds(&self, decision: &AuthorizationDecision) -> Vec<AuthorizationHold> {
        decision
            .hold_reasons
            .iter()
            .map(|reason| {
                let hold_reason = hold_reason_from_str(reason);
                AuthorizationHold::new(
                    &decision.request_id,
                    hold_reason,
                    decision.decided_height,
                    decision
                        .decided_height
                        .saturating_add(self.config.release_delay_blocks),
                    domain_hash(
                        "MCRAR-HOLD-EVIDENCE",
                        &[
                            HashPart::Str(&decision.request_id),
                            HashPart::Str(reason),
                            HashPart::Str(&decision.hold_root),
                        ],
                        32,
                    ),
                )
            })
            .collect()
    }

    pub fn recompute_roots(&mut self) {
        let config_root = domain_hash(
            "MCRAR-CONFIG",
            &[HashPart::Json(&self.config.public_record())],
            32,
        );
        let signer_root = self.signer_root();
        let watcher_root = self.watcher_root();
        let key_epoch_root = records_root(
            "MCRAR-STATE-KEY-EPOCHS",
            self.key_epochs
                .values()
                .map(KeyEpoch::public_record)
                .collect::<Vec<_>>(),
        );
        let rotation_root = records_root(
            "MCRAR-STATE-ROTATIONS",
            self.rotations
                .values()
                .map(RotationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let withdrawal_authority_root = records_root(
            "MCRAR-STATE-WITHDRAWAL-AUTHORITIES",
            self.withdrawal_authorities
                .values()
                .map(WithdrawalAuthority::public_record)
                .collect::<Vec<_>>(),
        );
        let release_request_root = records_root(
            "MCRAR-STATE-RELEASE-REQUESTS",
            self.release_requests
                .values()
                .map(ReleaseRequest::public_record)
                .collect::<Vec<_>>(),
        );
        let pq_signature_root = records_root(
            "MCRAR-STATE-PQ-SIGNATURES",
            self.pq_signatures
                .values()
                .map(PqQuorumSignature::public_record)
                .collect::<Vec<_>>(),
        );
        let watcher_attestation_root = records_root(
            "MCRAR-STATE-WATCHER-ATTESTATIONS",
            self.watcher_attestations
                .values()
                .map(WatcherAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let hold_root = records_root(
            "MCRAR-STATE-HOLDS",
            self.holds
                .values()
                .map(AuthorizationHold::public_record)
                .collect::<Vec<_>>(),
        );
        let decision_root = records_root(
            "MCRAR-STATE-DECISIONS",
            self.decisions
                .values()
                .map(AuthorizationDecision::public_record)
                .collect::<Vec<_>>(),
        );
        let public_record_payload = json!({
            "config_root": config_root,
            "decision_root": decision_root,
            "hold_root": hold_root,
            "key_epoch_root": key_epoch_root,
            "pq_signature_root": pq_signature_root,
            "release_request_root": release_request_root,
            "rotation_root": rotation_root,
            "signer_root": signer_root,
            "watcher_attestation_root": watcher_attestation_root,
            "watcher_root": watcher_root,
            "withdrawal_authority_root": withdrawal_authority_root,
        });
        let public_record_root = domain_hash(
            "MCRAR-PUBLIC-RECORD-ROOT",
            &[HashPart::Json(&public_record_payload)],
            32,
        );
        let state_payload = json!({
            "config_root": config_root,
            "decision_root": decision_root,
            "height": self.height,
            "hold_root": hold_root,
            "key_epoch_root": key_epoch_root,
            "protocol_version": self.config.protocol_version,
            "public_record_root": public_record_root,
            "release_request_root": release_request_root,
        });
        let state_root = domain_hash("MCRAR-STATE-ROOT", &[HashPart::Json(&state_payload)], 32);
        self.roots = StateRoots {
            config_root,
            signer_root,
            watcher_root,
            key_epoch_root,
            rotation_root,
            withdrawal_authority_root,
            release_request_root,
            pq_signature_root,
            watcher_attestation_root,
            hold_root,
            decision_root,
            public_record_root,
            state_root,
        };
    }

    fn signatures_for_request(&self, request_id: &str) -> Vec<PqQuorumSignature> {
        self.pq_signatures
            .values()
            .filter(|signature| signature.request_id == request_id)
            .cloned()
            .collect()
    }

    fn attestations_for_request(&self, request_id: &str) -> Vec<WatcherAttestation> {
        self.watcher_attestations
            .values()
            .filter(|attestation| attestation.request_id == request_id)
            .cloned()
            .collect()
    }

    fn authority_valid(&self, request: &ReleaseRequest) -> bool {
        self.withdrawal_authorities
            .get(&request.authority_id)
            .map(|authority| {
                authority.authority_root == request.withdrawal_authority_root
                    && authority.valid_at(self.height)
            })
            .unwrap_or(false)
    }

    fn key_epoch_continuous(&self, key_epoch: u64) -> bool {
        self.key_epochs
            .get(&key_epoch)
            .map(|epoch| {
                key_epoch.saturating_sub(epoch.previous_epoch) <= self.config.max_epoch_gap
                    && self.key_epochs.contains_key(&epoch.previous_epoch)
            })
            .unwrap_or(false)
    }

    fn rotation_permits_release(&self, key_epoch: u64) -> bool {
        self.rotations.values().any(|rotation| {
            rotation.to_epoch == key_epoch && rotation.active_for_release(self.height)
        })
    }

    fn rotation_root_for_epoch(&self, key_epoch: u64) -> String {
        let records = self
            .rotations
            .values()
            .filter(|rotation| rotation.to_epoch == key_epoch || rotation.from_epoch == key_epoch)
            .map(RotationRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root("MCRAR-DECISION-ROTATION", &records)
    }

    fn signatures_match_request(
        &self,
        request: &ReleaseRequest,
        signatures: &[PqQuorumSignature],
    ) -> bool {
        signatures.iter().all(|signature| {
            signature.transcript_root == request.transcript_root
                && signature.signature_domain_root == request.signature_domain_root
                && signature.key_epoch == request.key_epoch
                && self
                    .signers
                    .get(&signature.signer_id)
                    .map(|signer| {
                        signer.active_at(signature.observed_height)
                            && signer.pq_security_bits >= self.config.min_pq_security_bits
                    })
                    .unwrap_or(false)
        })
    }

    fn attestations_match_request(
        &self,
        request: &ReleaseRequest,
        attestations: &[WatcherAttestation],
    ) -> bool {
        attestations.iter().all(|attestation| {
            attestation.transcript_root == request.transcript_root
                && attestation.withdrawal_authority_root == request.withdrawal_authority_root
                && self
                    .watchers
                    .get(&attestation.watcher_id)
                    .map(|watcher| watcher.active_at(attestation.observed_height))
                    .unwrap_or(false)
        })
    }

    fn consumed_nullifier_root(&self) -> String {
        let records = self
            .consumed_nullifiers
            .iter()
            .map(|(nullifier, request_id)| {
                json!({
                    "nullifier": nullifier,
                    "request_id": request_id,
                })
            })
            .collect::<Vec<_>>();
        merkle_root("MCRAR-CONSUMED-NULLIFIERS", &records)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn text_hash(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

fn hold_reason_from_str(reason: &str) -> HoldReason {
    match reason {
        "missing_pq_signer_quorum" => HoldReason::MissingPqSignerQuorum,
        "missing_watcher_attestation" => HoldReason::MissingWatcherAttestation,
        "insufficient_threshold_weight" => HoldReason::InsufficientThresholdWeight,
        "key_epoch_gap" => HoldReason::KeyEpochGap,
        "rotation_pending" => HoldReason::RotationPending,
        "rotation_revoked" => HoldReason::RotationRevoked,
        "withdrawal_authority_missing" => HoldReason::WithdrawalAuthorityMissing,
        "transcript_root_mismatch" => HoldReason::TranscriptRootMismatch,
        "signature_domain_mismatch" => HoldReason::SignatureDomainMismatch,
        "expired_authorization" => HoldReason::ExpiredAuthorization,
        "challenge_open" => HoldReason::ChallengeOpen,
        "duplicate_nullifier" => HoldReason::DuplicateNullifier,
        _ => HoldReason::WithdrawalAuthorityMissing,
    }
}
