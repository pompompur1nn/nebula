use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePqWithdrawalAuthorityRecoveryBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_WITHDRAWAL_AUTHORITY_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-withdrawal-authority-recovery-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_WITHDRAWAL_AUTHORITY_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-pq-withdrawal-authority-recovery-binding-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_AUTHORITY_EPOCH: u64 = 73;
pub const DEFAULT_L2_HEIGHT: u64 = 884_280;
pub const DEFAULT_MONERO_HEIGHT: u64 = 2_771_496;
pub const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MIN_AUTHORITY_SIGNATURES: u16 = 3;
pub const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 48;
pub const DEFAULT_UPGRADE_FENCE_DELAY_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;

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
pub enum SignatureDomainKind {
    WithdrawalAuthorization,
    WalletRecovery,
    ForcedExitClaim,
    ReleaseHold,
    UpgradeFence,
}

impl SignatureDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WithdrawalAuthorization => "withdrawal_authorization",
            Self::WalletRecovery => "wallet_recovery",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::ReleaseHold => "release_hold",
            Self::UpgradeFence => "upgrade_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingClaimKind {
    RecoveryForcedExit,
}

impl BindingClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryForcedExit => "recovery_forced_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedLaneKind {
    PqAuthorityEpoch,
    WatcherQuorum,
    WithdrawalClaim,
    RecoveryBundle,
    ObservedReceipt,
}

impl FeedLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqAuthorityEpoch => "pq_authority_epoch",
            Self::WatcherQuorum => "watcher_quorum",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::RecoveryBundle => "recovery_bundle",
            Self::ObservedReceipt => "observed_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    MissingRecoveryBinding,
    AuthorityEpochMismatch,
    WatcherQuorumShortfall,
    ReceiptMismatch,
    LiveFeedStale,
    UpgradeFenceActive,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingRecoveryBinding => "missing_recovery_binding",
            Self::AuthorityEpochMismatch => "authority_epoch_mismatch",
            Self::WatcherQuorumShortfall => "watcher_quorum_shortfall",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::LiveFeedStale => "live_feed_stale",
            Self::UpgradeFenceActive => "upgrade_fence_active",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub binding_suite: String,
    pub vertical_slice_id: String,
    pub authority_epoch: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_watcher_weight_bps: u16,
    pub min_authority_signatures: u16,
    pub release_hold_blocks: u64,
    pub upgrade_fence_delay_blocks: u64,
    pub min_pq_security_bits: u16,
    pub fail_closed_on_any_blocker: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            binding_suite: BINDING_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            authority_epoch: DEFAULT_AUTHORITY_EPOCH,
            l2_height: DEFAULT_L2_HEIGHT,
            monero_height: DEFAULT_MONERO_HEIGHT,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            min_authority_signatures: DEFAULT_MIN_AUTHORITY_SIGNATURES,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            upgrade_fence_delay_blocks: DEFAULT_UPGRADE_FENCE_DELAY_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            fail_closed_on_any_blocker: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "binding_suite": self.binding_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "authority_epoch": self.authority_epoch,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "min_authority_signatures": self.min_authority_signatures,
            "release_hold_blocks": self.release_hold_blocks,
            "upgrade_fence_delay_blocks": self.upgrade_fence_delay_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fail_closed_on_any_blocker": self.fail_closed_on_any_blocker,
        })
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignatureDomain {
    pub domain_id: String,
    pub kind: SignatureDomainKind,
    pub scheme: PqSignatureScheme,
    pub authority_epoch: u64,
    pub pq_security_bits: u16,
    pub transcript_root: String,
    pub domain_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityEpoch {
    pub epoch_id: String,
    pub epoch_number: u64,
    pub active_authority_set_root: String,
    pub recovery_delegate_set_root: String,
    pub watcher_set_root: String,
    pub upgrade_authority_root: String,
    pub starts_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub epoch_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherQuorumLink {
    pub quorum_id: String,
    pub feed_lane: FeedLaneKind,
    pub authority_epoch: u64,
    pub signer_set_root: String,
    pub signature_bundle_root: String,
    pub signed_message_root: String,
    pub observed_weight_bps: u16,
    pub required_weight_bps: u16,
    pub signature_count: u16,
    pub link_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalAuthorizationRoot {
    pub authorization_id: String,
    pub wallet_account_commitment: String,
    pub recovery_binding_root: String,
    pub forced_exit_claim_root: String,
    pub destination_commitment_root: String,
    pub amount_commitment_root: String,
    pub replay_nullifier_root: String,
    pub pq_signature_domain_root: String,
    pub authority_epoch_root: String,
    pub authorization_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryClaimBinding {
    pub binding_id: String,
    pub claim_kind: BindingClaimKind,
    pub wallet_recovery_root: String,
    pub forced_exit_claim_root: String,
    pub recovery_policy_root: String,
    pub delegate_signature_root: String,
    pub selective_disclosure_root: String,
    pub binding_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveFeedLink {
    pub feed_id: String,
    pub lane: FeedLaneKind,
    pub source_height: u64,
    pub l2_height: u64,
    pub payload_root: String,
    pub watcher_quorum_root: String,
    pub receipt_link_root: String,
    pub feed_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedReceiptLink {
    pub receipt_id: String,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub observed_at_l2_height: u64,
    pub source_height: u64,
    pub watcher_quorum_root: String,
    pub matches_expected: bool,
    pub link_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeAuthorityFence {
    pub fence_id: String,
    pub current_authority_root: String,
    pub proposed_authority_root: String,
    pub activation_height: u64,
    pub delay_blocks: u64,
    pub pq_upgrade_signature_root: String,
    pub watcher_veto_root: String,
    pub fence_active: bool,
    pub fence_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub kind: BlockerKind,
    pub expected_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub blocks_release: bool,
    pub mismatch_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub held_claim_root: String,
    pub hold_reason_root: String,
    pub held_until_l2_height: u64,
    pub release_authority_root: String,
    pub watcher_quorum_root: String,
    pub observed_receipt_root: String,
    pub release_allowed: bool,
    pub hold_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedAuthorityBlocker {
    pub blocker_id: String,
    pub kind: BlockerKind,
    pub source_root: String,
    pub reason_root: String,
    pub authority_epoch: u64,
    pub blocks_release: bool,
    pub blocker_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub signature_domains: Vec<PqSignatureDomain>,
    pub authority_epochs: Vec<AuthorityEpoch>,
    pub watcher_quorum_links: Vec<WatcherQuorumLink>,
    pub withdrawal_authorizations: Vec<WithdrawalAuthorizationRoot>,
    pub recovery_bindings: Vec<RecoveryClaimBinding>,
    pub live_feed_links: Vec<LiveFeedLink>,
    pub observed_receipt_links: Vec<ObservedReceiptLink>,
    pub upgrade_authority_fences: Vec<UpgradeAuthorityFence>,
    pub mismatch_records: Vec<MismatchRecord>,
    pub release_holds: Vec<ReleaseHold>,
    pub fail_closed_authority_blockers: Vec<FailClosedAuthorityBlocker>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let withdrawal_domain = signature_domain(
            SignatureDomainKind::WithdrawalAuthorization,
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            &config,
            "withdrawal-authorization",
        );
        let recovery_domain = signature_domain(
            SignatureDomainKind::WalletRecovery,
            PqSignatureScheme::MlDsa87,
            &config,
            "wallet-recovery-authority",
        );
        let forced_exit_domain = signature_domain(
            SignatureDomainKind::ForcedExitClaim,
            PqSignatureScheme::SlhDsaShake256f,
            &config,
            "forced-exit-claim-authority",
        );
        let hold_domain = signature_domain(
            SignatureDomainKind::ReleaseHold,
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            &config,
            "release-hold-authority",
        );
        let upgrade_domain = signature_domain(
            SignatureDomainKind::UpgradeFence,
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            &config,
            "upgrade-fence-authority",
        );
        let signature_domains = vec![
            withdrawal_domain.clone(),
            recovery_domain,
            forced_exit_domain,
            hold_domain,
            upgrade_domain,
        ];

        let authority_set_root = label_root("authority-set", "devnet-pq-withdrawal-authorities");
        let recovery_delegate_set_root = label_root("recovery-delegates", "devnet-wallet-recovery");
        let watcher_set_root = label_root("watcher-set", "canonical-slice-watchers");
        let upgrade_authority_root = label_root("upgrade-authority", "time-locked-pq-council");
        let authority_epoch = authority_epoch(
            &config,
            authority_set_root.clone(),
            recovery_delegate_set_root.clone(),
            watcher_set_root.clone(),
            upgrade_authority_root.clone(),
        );
        let authority_epochs = vec![authority_epoch.clone()];

        let claim_root = label_root("forced-exit-claim", "claim-0007");
        let wallet_recovery_root = label_root("wallet-recovery", "wallet-recovery-claim-0007");
        let recovery_policy_root = label_root("recovery-policy", "two-of-three-delegate-pq");
        let delegate_signature_root =
            label_root("delegate-signatures", "recovery-signature-bundle");
        let disclosure_root = label_root("selective-disclosure", "destination-and-nullifier-only");
        let recovery_binding = recovery_binding(
            BindingClaimKind::RecoveryForcedExit,
            wallet_recovery_root,
            claim_root.clone(),
            recovery_policy_root,
            delegate_signature_root,
            disclosure_root,
        );
        let recovery_bindings = vec![recovery_binding.clone()];

        let withdrawal_authorization = withdrawal_authorization(
            &authority_epoch,
            &withdrawal_domain,
            &recovery_binding,
            claim_root.clone(),
        );
        let primary_quorum = watcher_quorum(
            FeedLaneKind::WatcherQuorum,
            &config,
            &watcher_set_root,
            "release-quorum-signature-bundle",
            &withdrawal_authorization.authorization_root,
            7_600,
        );
        let receipt_quorum = watcher_quorum(
            FeedLaneKind::ObservedReceipt,
            &config,
            &watcher_set_root,
            "receipt-observation-signature-bundle",
            "observed-receipt-message-0007",
            7_400,
        );
        let watcher_quorum_links = vec![primary_quorum.clone(), receipt_quorum.clone()];

        let expected_receipt_root = label_root("expected-receipt", "release-receipt-0007");
        let observed_receipt_link = observed_receipt(
            &config,
            expected_receipt_root.clone(),
            expected_receipt_root,
            &receipt_quorum,
        );
        let observed_receipt_links = vec![observed_receipt_link.clone()];

        let live_feed_links = vec![
            live_feed(
                FeedLaneKind::PqAuthorityEpoch,
                &config,
                &authority_epoch.epoch_root,
                &primary_quorum,
                &observed_receipt_link,
            ),
            live_feed(
                FeedLaneKind::WithdrawalClaim,
                &config,
                &withdrawal_authorization.authorization_root,
                &primary_quorum,
                &observed_receipt_link,
            ),
            live_feed(
                FeedLaneKind::RecoveryBundle,
                &config,
                &recovery_binding.binding_root,
                &primary_quorum,
                &observed_receipt_link,
            ),
        ];

        let upgrade_fence = upgrade_fence(&config, &upgrade_authority_root);
        let mismatch = mismatch(
            BlockerKind::UpgradeFenceActive,
            label_root("expected-upgrade-state", "no-active-upgrade-fence"),
            upgrade_fence.fence_root.clone(),
            label_root("upgrade-fence-evidence", "active-delay-window"),
            true,
        );
        let release_hold = release_hold(
            &config,
            claim_root,
            upgrade_fence.fence_root.clone(),
            &authority_epoch,
            &primary_quorum,
            &observed_receipt_link,
            false,
        );
        let fail_closed_authority_blockers = vec![fail_closed_blocker(
            BlockerKind::UpgradeFenceActive,
            upgrade_fence.fence_root.clone(),
            release_hold.hold_root.clone(),
            config.authority_epoch,
            true,
        )];
        let withdrawal_authorizations = vec![withdrawal_authorization];
        let upgrade_authority_fences = vec![upgrade_fence];
        let mismatch_records = vec![mismatch];
        let release_holds = vec![release_hold];

        Self {
            config,
            signature_domains,
            authority_epochs,
            watcher_quorum_links,
            withdrawal_authorizations,
            recovery_bindings,
            live_feed_links,
            observed_receipt_links,
            upgrade_authority_fences,
            mismatch_records,
            release_holds,
            fail_closed_authority_blockers,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "signature_domain_root": vector_root("PQ-WITHDRAWAL-AUTHORITY-SIGNATURE-DOMAINS", &self.signature_domains),
            "authority_epoch_root": vector_root("PQ-WITHDRAWAL-AUTHORITY-EPOCHS", &self.authority_epochs),
            "watcher_quorum_link_root": vector_root("PQ-WITHDRAWAL-WATCHER-QUORUM-LINKS", &self.watcher_quorum_links),
            "withdrawal_authorization_root": vector_root("PQ-WITHDRAWAL-AUTHORIZATION-ROOTS", &self.withdrawal_authorizations),
            "recovery_binding_root": vector_root("PQ-WITHDRAWAL-RECOVERY-BINDINGS", &self.recovery_bindings),
            "live_feed_link_root": vector_root("PQ-WITHDRAWAL-LIVE-FEED-LINKS", &self.live_feed_links),
            "observed_receipt_link_root": vector_root("PQ-WITHDRAWAL-OBSERVED-RECEIPT-LINKS", &self.observed_receipt_links),
            "upgrade_authority_fence_root": vector_root("PQ-WITHDRAWAL-UPGRADE-AUTHORITY-FENCES", &self.upgrade_authority_fences),
            "mismatch_record_root": vector_root("PQ-WITHDRAWAL-MISMATCH-RECORDS", &self.mismatch_records),
            "release_hold_root": vector_root("PQ-WITHDRAWAL-RELEASE-HOLDS", &self.release_holds),
            "fail_closed_authority_blocker_root": vector_root("PQ-WITHDRAWAL-FAIL-CLOSED-AUTHORITY-BLOCKERS", &self.fail_closed_authority_blockers),
            "release_blocked": self.release_blocked(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record())
    }

    pub fn release_blocked(&self) -> bool {
        self.config.fail_closed_on_any_blocker
            && self
                .fail_closed_authority_blockers
                .iter()
                .any(|blocker| blocker.blocks_release)
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

fn signature_domain(
    kind: SignatureDomainKind,
    scheme: PqSignatureScheme,
    config: &Config,
    transcript_label: &str,
) -> PqSignatureDomain {
    let transcript_root = label_root("transcript", transcript_label);
    let domain_root = domain_hash(
        "PQ-WITHDRAWAL-SIGNATURE-DOMAIN",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(scheme.as_str()),
            HashPart::Int(config.authority_epoch as i128),
            HashPart::Int(config.min_pq_security_bits as i128),
            HashPart::Str(&transcript_root),
        ],
        32,
    );
    PqSignatureDomain {
        domain_id: id_root("signature-domain", &domain_root),
        kind,
        scheme,
        authority_epoch: config.authority_epoch,
        pq_security_bits: config.min_pq_security_bits,
        transcript_root,
        domain_root,
    }
}

fn authority_epoch(
    config: &Config,
    active_authority_set_root: String,
    recovery_delegate_set_root: String,
    watcher_set_root: String,
    upgrade_authority_root: String,
) -> AuthorityEpoch {
    let starts_at_l2_height = config.l2_height - 1_440;
    let expires_at_l2_height = config.l2_height + 1_440;
    let epoch_root = domain_hash(
        "PQ-WITHDRAWAL-AUTHORITY-EPOCH",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(config.authority_epoch as i128),
            HashPart::Str(&active_authority_set_root),
            HashPart::Str(&recovery_delegate_set_root),
            HashPart::Str(&watcher_set_root),
            HashPart::Str(&upgrade_authority_root),
            HashPart::Int(starts_at_l2_height as i128),
            HashPart::Int(expires_at_l2_height as i128),
        ],
        32,
    );
    AuthorityEpoch {
        epoch_id: id_root("authority-epoch", &epoch_root),
        epoch_number: config.authority_epoch,
        active_authority_set_root,
        recovery_delegate_set_root,
        watcher_set_root,
        upgrade_authority_root,
        starts_at_l2_height,
        expires_at_l2_height,
        epoch_root,
    }
}

fn recovery_binding(
    claim_kind: BindingClaimKind,
    wallet_recovery_root: String,
    forced_exit_claim_root: String,
    recovery_policy_root: String,
    delegate_signature_root: String,
    selective_disclosure_root: String,
) -> RecoveryClaimBinding {
    let binding_root = domain_hash(
        "PQ-WITHDRAWAL-RECOVERY-CLAIM-BINDING",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_kind.as_str()),
            HashPart::Str(&wallet_recovery_root),
            HashPart::Str(&forced_exit_claim_root),
            HashPart::Str(&recovery_policy_root),
            HashPart::Str(&delegate_signature_root),
            HashPart::Str(&selective_disclosure_root),
        ],
        32,
    );
    RecoveryClaimBinding {
        binding_id: id_root("recovery-binding", &binding_root),
        claim_kind,
        wallet_recovery_root,
        forced_exit_claim_root,
        recovery_policy_root,
        delegate_signature_root,
        selective_disclosure_root,
        binding_root,
    }
}

fn withdrawal_authorization(
    authority_epoch: &AuthorityEpoch,
    signature_domain: &PqSignatureDomain,
    recovery_binding: &RecoveryClaimBinding,
    forced_exit_claim_root: String,
) -> WithdrawalAuthorizationRoot {
    let wallet_account_commitment = label_root("wallet-account", "wallet-account-0007");
    let destination_commitment_root = label_root("destination", "monero-subaddress-0007");
    let amount_commitment_root = label_root("amount", "withdrawal-amount-0007");
    let replay_nullifier_root = label_root("replay-nullifier", "withdrawal-nullifier-0007");
    let authorization_root = domain_hash(
        "PQ-WITHDRAWAL-AUTHORIZATION-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&wallet_account_commitment),
            HashPart::Str(&recovery_binding.binding_root),
            HashPart::Str(&forced_exit_claim_root),
            HashPart::Str(&destination_commitment_root),
            HashPart::Str(&amount_commitment_root),
            HashPart::Str(&replay_nullifier_root),
            HashPart::Str(&signature_domain.domain_root),
            HashPart::Str(&authority_epoch.epoch_root),
        ],
        32,
    );
    WithdrawalAuthorizationRoot {
        authorization_id: id_root("withdrawal-authorization", &authorization_root),
        wallet_account_commitment,
        recovery_binding_root: recovery_binding.binding_root.clone(),
        forced_exit_claim_root,
        destination_commitment_root,
        amount_commitment_root,
        replay_nullifier_root,
        pq_signature_domain_root: signature_domain.domain_root.clone(),
        authority_epoch_root: authority_epoch.epoch_root.clone(),
        authorization_root,
    }
}

fn watcher_quorum(
    lane: FeedLaneKind,
    config: &Config,
    signer_set_root: &str,
    signature_label: &str,
    signed_message_root: &str,
    observed_weight_bps: u16,
) -> WatcherQuorumLink {
    let signature_bundle_root = label_root("watcher-signatures", signature_label);
    let link_root = domain_hash(
        "PQ-WITHDRAWAL-WATCHER-QUORUM-LINK",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(config.authority_epoch as i128),
            HashPart::Str(signer_set_root),
            HashPart::Str(&signature_bundle_root),
            HashPart::Str(signed_message_root),
            HashPart::Int(observed_weight_bps as i128),
            HashPart::Int(config.min_watcher_weight_bps as i128),
            HashPart::Int(config.min_authority_signatures as i128),
        ],
        32,
    );
    WatcherQuorumLink {
        quorum_id: id_root("watcher-quorum", &link_root),
        feed_lane: lane,
        authority_epoch: config.authority_epoch,
        signer_set_root: signer_set_root.to_string(),
        signature_bundle_root,
        signed_message_root: signed_message_root.to_string(),
        observed_weight_bps,
        required_weight_bps: config.min_watcher_weight_bps,
        signature_count: config.min_authority_signatures,
        link_root,
    }
}

fn observed_receipt(
    config: &Config,
    expected_receipt_root: String,
    observed_receipt_root: String,
    quorum: &WatcherQuorumLink,
) -> ObservedReceiptLink {
    let link_root = domain_hash(
        "PQ-WITHDRAWAL-OBSERVED-RECEIPT-LINK",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&expected_receipt_root),
            HashPart::Str(&observed_receipt_root),
            HashPart::Int(config.l2_height as i128),
            HashPart::Int(config.monero_height as i128),
            HashPart::Str(&quorum.link_root),
        ],
        32,
    );
    ObservedReceiptLink {
        receipt_id: id_root("observed-receipt", &link_root),
        matches_expected: expected_receipt_root == observed_receipt_root,
        expected_receipt_root,
        observed_receipt_root,
        observed_at_l2_height: config.l2_height,
        source_height: config.monero_height,
        watcher_quorum_root: quorum.link_root.clone(),
        link_root,
    }
}

fn live_feed(
    lane: FeedLaneKind,
    config: &Config,
    payload_root: &str,
    quorum: &WatcherQuorumLink,
    receipt: &ObservedReceiptLink,
) -> LiveFeedLink {
    let feed_root = domain_hash(
        "PQ-WITHDRAWAL-LIVE-FEED-LINK",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(config.monero_height as i128),
            HashPart::Int(config.l2_height as i128),
            HashPart::Str(payload_root),
            HashPart::Str(&quorum.link_root),
            HashPart::Str(&receipt.link_root),
        ],
        32,
    );
    LiveFeedLink {
        feed_id: id_root("live-feed", &feed_root),
        lane,
        source_height: config.monero_height,
        l2_height: config.l2_height,
        payload_root: payload_root.to_string(),
        watcher_quorum_root: quorum.link_root.clone(),
        receipt_link_root: receipt.link_root.clone(),
        feed_root,
    }
}

fn upgrade_fence(config: &Config, current_authority_root: &str) -> UpgradeAuthorityFence {
    let proposed_authority_root = label_root("proposed-authority", "next-pq-authority-set");
    let pq_upgrade_signature_root = label_root("upgrade-signatures", "timelock-signatures");
    let watcher_veto_root = label_root("watcher-veto", "empty-veto-root");
    let activation_height = config.l2_height + config.upgrade_fence_delay_blocks;
    let fence_active = true;
    let fence_root = domain_hash(
        "PQ-WITHDRAWAL-UPGRADE-AUTHORITY-FENCE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(current_authority_root),
            HashPart::Str(&proposed_authority_root),
            HashPart::Int(activation_height as i128),
            HashPart::Int(config.upgrade_fence_delay_blocks as i128),
            HashPart::Str(&pq_upgrade_signature_root),
            HashPart::Str(&watcher_veto_root),
            HashPart::Str(if fence_active { "active" } else { "inactive" }),
        ],
        32,
    );
    UpgradeAuthorityFence {
        fence_id: id_root("upgrade-fence", &fence_root),
        current_authority_root: current_authority_root.to_string(),
        proposed_authority_root,
        activation_height,
        delay_blocks: config.upgrade_fence_delay_blocks,
        pq_upgrade_signature_root,
        watcher_veto_root,
        fence_active,
        fence_root,
    }
}

fn mismatch(
    kind: BlockerKind,
    expected_root: String,
    observed_root: String,
    evidence_root: String,
    blocks_release: bool,
) -> MismatchRecord {
    let mismatch_root = domain_hash(
        "PQ-WITHDRAWAL-MISMATCH-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(&expected_root),
            HashPart::Str(&observed_root),
            HashPart::Str(&evidence_root),
            HashPart::Str(if blocks_release { "blocks" } else { "observed" }),
        ],
        32,
    );
    MismatchRecord {
        mismatch_id: id_root("mismatch", &mismatch_root),
        kind,
        expected_root,
        observed_root,
        evidence_root,
        blocks_release,
        mismatch_root,
    }
}

fn release_hold(
    config: &Config,
    held_claim_root: String,
    hold_reason_root: String,
    authority_epoch: &AuthorityEpoch,
    quorum: &WatcherQuorumLink,
    receipt: &ObservedReceiptLink,
    release_allowed: bool,
) -> ReleaseHold {
    let held_until_l2_height = config.l2_height + config.release_hold_blocks;
    let hold_root = domain_hash(
        "PQ-WITHDRAWAL-RELEASE-HOLD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&held_claim_root),
            HashPart::Str(&hold_reason_root),
            HashPart::Int(held_until_l2_height as i128),
            HashPart::Str(&authority_epoch.epoch_root),
            HashPart::Str(&quorum.link_root),
            HashPart::Str(&receipt.link_root),
            HashPart::Str(if release_allowed { "release" } else { "hold" }),
        ],
        32,
    );
    ReleaseHold {
        hold_id: id_root("release-hold", &hold_root),
        held_claim_root,
        hold_reason_root,
        held_until_l2_height,
        release_authority_root: authority_epoch.epoch_root.clone(),
        watcher_quorum_root: quorum.link_root.clone(),
        observed_receipt_root: receipt.link_root.clone(),
        release_allowed,
        hold_root,
    }
}

fn fail_closed_blocker(
    kind: BlockerKind,
    source_root: String,
    reason_root: String,
    authority_epoch: u64,
    blocks_release: bool,
) -> FailClosedAuthorityBlocker {
    let blocker_root = domain_hash(
        "PQ-WITHDRAWAL-FAIL-CLOSED-AUTHORITY-BLOCKER",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(&source_root),
            HashPart::Str(&reason_root),
            HashPart::Int(authority_epoch as i128),
            HashPart::Str(if blocks_release { "blocks" } else { "observes" }),
        ],
        32,
    );
    FailClosedAuthorityBlocker {
        blocker_id: id_root("fail-closed-blocker", &blocker_root),
        kind,
        source_root,
        reason_root,
        authority_epoch,
        blocks_release,
        blocker_root,
    }
}

fn json_record<T: Serialize>(record: &T) -> Value {
    match serde_json::to_value(record) {
        Ok(value) => value,
        Err(error) => json!({
            "serialization_error": error.to_string(),
        }),
    }
}

fn vector_root<T: Serialize>(label: &str, records: &[T]) -> String {
    merkle_records(label, records.iter().map(json_record).collect())
}

fn label_root(label: &str, value: &str) -> String {
    domain_hash(
        "PQ-WITHDRAWAL-AUTHORITY-RECOVERY-BINDING-LABEL",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn id_root(label: &str, root: &str) -> String {
    domain_hash(
        "PQ-WITHDRAWAL-AUTHORITY-RECOVERY-BINDING-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(root),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "PQ-WITHDRAWAL-AUTHORITY-RECOVERY-BINDING-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn merkle_records(label: &str, records: Vec<Value>) -> String {
    merkle_root(
        label,
        &records
            .iter()
            .map(|record| HashPart::Json(record))
            .collect::<Vec<_>>(),
    )
}
