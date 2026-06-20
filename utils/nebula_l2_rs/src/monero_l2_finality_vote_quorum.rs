use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2FinalityVoteQuorumResult<T> = Result<T, String>;

pub const MONERO_L2_FINALITY_VOTE_QUORUM_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-finality-vote-quorum-v1";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_QUORUM_ID: &str =
    "monero-l2-finality-vote-quorum-devnet";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_HEIGHT: u64 = 24_000;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_PRIMARY_PQ_SCHEME: &str = "ML-DSA-87";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_BACKUP_PQ_SCHEME: &str = "SLH-DSA-SHAKE-192s";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_AGGREGATE_SCHEME: &str =
    "weighted-roots-only-pq-finality-certificate-v1";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_MONERO_ANCHOR_SCHEME: &str =
    "monero-header-and-txset-anchor-commitment-v1";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_FAST_EXIT_SCHEME: &str =
    "fast-exit-settlement-certificate-v1";
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MIN_CONFIRMATIONS: u64 = 24;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_STRONG_CONFIRMATIONS: u64 = 40;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_REORG_GRACE_BLOCKS: u64 = 12;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_FAST_EXIT_QUORUM_BPS: u64 = 8_000;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_EMERGENCY_QUORUM_BPS: u64 = 9_000;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MIN_WATCHERS: u64 = 3;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MAX_ANCHOR_LAG: u64 = 8;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_CERTIFICATE_TTL_BLOCKS: u64 = 96;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_FINALITY_VOTE_QUORUM_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherRole {
    BridgeWatcher,
    HeaderObserver,
    ExitLiquidityGuard,
    ContractSettlementGuard,
    ReorgSentinel,
    EmergencySigner,
}

impl WatcherRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeWatcher => "bridge_watcher",
            Self::HeaderObserver => "header_observer",
            Self::ExitLiquidityGuard => "exit_liquidity_guard",
            Self::ContractSettlementGuard => "contract_settlement_guard",
            Self::ReorgSentinel => "reorg_sentinel",
            Self::EmergencySigner => "emergency_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherStatus {
    Pending,
    Active,
    Degraded,
    Jailed,
    Retired,
}

impl WatcherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Jailed => "jailed",
            Self::Retired => "retired",
        }
    }

    pub fn can_vote(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteIntent {
    Observe,
    FastExit,
    DefiSettlement,
    TokenMintBurn,
    ContractCommit,
    EmergencyFreeze,
}

impl VoteIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::FastExit => "fast_exit",
            Self::DefiSettlement => "defi_settlement",
            Self::TokenMintBurn => "token_mint_burn",
            Self::ContractCommit => "contract_commit",
            Self::EmergencyFreeze => "emergency_freeze",
        }
    }

    pub fn requires_fast_quorum(self) -> bool {
        matches!(
            self,
            Self::FastExit | Self::DefiSettlement | Self::TokenMintBurn | Self::ContractCommit
        )
    }

    pub fn requires_emergency_quorum(self) -> bool {
        matches!(self, Self::EmergencyFreeze)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorConfidence {
    Untrusted,
    Observed,
    SafeDepth,
    StrongDepth,
    Final,
}

impl AnchorConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Observed => "observed",
            Self::SafeDepth => "safe_depth",
            Self::StrongDepth => "strong_depth",
            Self::Final => "final",
        }
    }

    pub fn score_bps(self) -> u64 {
        match self {
            Self::Untrusted => 0,
            Self::Observed => 3_000,
            Self::SafeDepth => 7_000,
            Self::StrongDepth => 9_000,
            Self::Final => 10_000,
        }
    }

    pub fn supports_certificate(self) -> bool {
        matches!(self, Self::SafeDepth | Self::StrongDepth | Self::Final)
    }

    pub fn supports_fast_exit(self) -> bool {
        matches!(self, Self::StrongDepth | Self::Final)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteStatus {
    Submitted,
    Counted,
    Superseded,
    Rejected,
    Slashed,
}

impl VoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Prepared,
    ChallengeOpen,
    SettlementReady,
    Settled,
    Expired,
    Revoked,
}

impl CertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ChallengeOpen => "challenge_open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub asset_id: String,
    pub quorum_id: String,
    pub epoch_blocks: u64,
    pub min_monero_confirmations: u64,
    pub strong_monero_confirmations: u64,
    pub reorg_grace_blocks: u64,
    pub quorum_bps: u64,
    pub fast_exit_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub min_watchers: u64,
    pub max_anchor_lag: u64,
    pub certificate_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_ASSET_ID.to_string(),
            quorum_id: MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_QUORUM_ID.to_string(),
            epoch_blocks: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_EPOCH_BLOCKS,
            min_monero_confirmations: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MIN_CONFIRMATIONS,
            strong_monero_confirmations:
                MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_STRONG_CONFIRMATIONS,
            reorg_grace_blocks: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_REORG_GRACE_BLOCKS,
            quorum_bps: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_QUORUM_BPS,
            fast_exit_quorum_bps: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_FAST_EXIT_QUORUM_BPS,
            emergency_quorum_bps: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_EMERGENCY_QUORUM_BPS,
            min_watchers: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MIN_WATCHERS,
            max_anchor_lag: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MAX_ANCHOR_LAG,
            certificate_ttl_blocks: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_CERTIFICATE_TTL_BLOCKS,
            challenge_window_blocks: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_pq_security_bits: MONERO_L2_FINALITY_VOTE_QUORUM_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "network": self.network,
            "asset_id": self.asset_id,
            "quorum_id": self.quorum_id,
            "epoch_blocks": self.epoch_blocks,
            "min_monero_confirmations": self.min_monero_confirmations,
            "strong_monero_confirmations": self.strong_monero_confirmations,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "quorum_bps": self.quorum_bps,
            "fast_exit_quorum_bps": self.fast_exit_quorum_bps,
            "emergency_quorum_bps": self.emergency_quorum_bps,
            "min_watchers": self.min_watchers,
            "max_anchor_lag": self.max_anchor_lag,
            "certificate_ttl_blocks": self.certificate_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub watchers: u64,
    pub votes_submitted: u64,
    pub votes_counted: u64,
    pub votes_rejected: u64,
    pub epochs_certified: u64,
    pub fast_exit_certificates: u64,
    pub emergency_certificates: u64,
    pub total_counted_weight: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "watchers": self.watchers,
            "votes_submitted": self.votes_submitted,
            "votes_counted": self.votes_counted,
            "votes_rejected": self.votes_rejected,
            "epochs_certified": self.epochs_certified,
            "fast_exit_certificates": self.fast_exit_certificates,
            "emergency_certificates": self.emergency_certificates,
            "total_counted_weight": self.total_counted_weight,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Watcher {
    pub watcher_id: String,
    pub role: WatcherRole,
    pub status: WatcherStatus,
    pub weight: u64,
    pub pq_public_key_root: String,
    pub backup_pq_public_key_root: String,
    pub authorization_policy_root: String,
    pub joined_at_height: u64,
}

impl Watcher {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "pq_public_key_root": self.pq_public_key_root,
            "backup_pq_public_key_root": self.backup_pq_public_key_root,
            "authorization_policy_root": self.authorization_policy_root,
            "joined_at_height": self.joined_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroAnchor {
    pub anchor_id: String,
    pub network: String,
    pub monero_height: u64,
    pub observed_tip_height: u64,
    pub l2_epoch: u64,
    pub header_root: String,
    pub txset_root: String,
    pub output_commitment_root: String,
    pub nullifier_root: String,
    pub confirmations: u64,
    pub confidence: AnchorConfidence,
    pub first_seen_l2_height: u64,
}

impl MoneroAnchor {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "network": self.network,
            "monero_height": self.monero_height,
            "observed_tip_height": self.observed_tip_height,
            "l2_epoch": self.l2_epoch,
            "header_root": self.header_root,
            "txset_root": self.txset_root,
            "output_commitment_root": self.output_commitment_root,
            "nullifier_root": self.nullifier_root,
            "confirmations": self.confirmations,
            "confidence": self.confidence.as_str(),
            "first_seen_l2_height": self.first_seen_l2_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityVote {
    pub vote_id: String,
    pub watcher_id: String,
    pub epoch: u64,
    pub intent: VoteIntent,
    pub status: VoteStatus,
    pub weight: u64,
    pub anchor_id: String,
    pub anchor_confidence: AnchorConfidence,
    pub l2_state_root: String,
    pub bridge_event_root: String,
    pub private_exit_batch_root: String,
    pub private_defi_batch_root: String,
    pub private_contract_batch_root: String,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub backup_signature_root: String,
    pub submitted_at_height: u64,
}

impl FinalityVote {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "watcher_id": self.watcher_id,
            "epoch": self.epoch,
            "intent": self.intent.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "anchor_id": self.anchor_id,
            "anchor_confidence": self.anchor_confidence.as_str(),
            "l2_state_root": self.l2_state_root,
            "bridge_event_root": self.bridge_event_root,
            "private_exit_batch_root": self.private_exit_batch_root,
            "private_defi_batch_root": self.private_defi_batch_root,
            "private_contract_batch_root": self.private_contract_batch_root,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "backup_signature_root": self.backup_signature_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementCertificate {
    pub certificate_id: String,
    pub status: CertificateStatus,
    pub epoch: u64,
    pub intent: VoteIntent,
    pub anchor_id: String,
    pub anchor_confidence: AnchorConfidence,
    pub l2_state_root: String,
    pub vote_root: String,
    pub watcher_root: String,
    pub pq_authorization_root: String,
    pub settlement_payload_root: String,
    pub fast_exit_root: String,
    pub counted_weight: u64,
    pub total_active_weight: u64,
    pub quorum_bps: u64,
    pub counted_watchers: u64,
    pub issued_at_height: u64,
    pub challenge_ends_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "intent": self.intent.as_str(),
            "anchor_id": self.anchor_id,
            "anchor_confidence": self.anchor_confidence.as_str(),
            "l2_state_root": self.l2_state_root,
            "vote_root": self.vote_root,
            "watcher_root": self.watcher_root,
            "pq_authorization_root": self.pq_authorization_root,
            "settlement_payload_root": self.settlement_payload_root,
            "fast_exit_root": self.fast_exit_root,
            "counted_weight": self.counted_weight,
            "total_active_weight": self.total_active_weight,
            "quorum_bps": self.quorum_bps,
            "counted_watchers": self.counted_watchers,
            "issued_at_height": self.issued_at_height,
            "challenge_ends_at_height": self.challenge_ends_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteSubmission {
    pub watcher_id: String,
    pub epoch: u64,
    pub intent: VoteIntent,
    pub monero_height: u64,
    pub observed_tip_height: u64,
    pub header_root: String,
    pub txset_root: String,
    pub output_commitment_root: String,
    pub nullifier_root: String,
    pub l2_state_root: String,
    pub bridge_event_root: String,
    pub private_exit_batch_root: String,
    pub private_defi_batch_root: String,
    pub private_contract_batch_root: String,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub backup_signature_root: String,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub watchers: BTreeMap<String, Watcher>,
    pub anchors: BTreeMap<String, MoneroAnchor>,
    pub votes: BTreeMap<String, FinalityVote>,
    pub certificates: BTreeMap<String, SettlementCertificate>,
    pub epoch_votes: BTreeMap<u64, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            height: MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_HEIGHT,
            counters: Counters::default(),
            watchers: BTreeMap::new(),
            anchors: BTreeMap::new(),
            votes: BTreeMap::new(),
            certificates: BTreeMap::new(),
            epoch_votes: BTreeMap::new(),
        };
        state.add_devnet_watcher("watcher-alpha", WatcherRole::BridgeWatcher, 40);
        state.add_devnet_watcher("watcher-beta", WatcherRole::HeaderObserver, 30);
        state.add_devnet_watcher("watcher-gamma", WatcherRole::ExitLiquidityGuard, 20);
        state.add_devnet_watcher("watcher-delta", WatcherRole::ContractSettlementGuard, 10);
        state
    }

    pub fn submit_vote(
        &mut self,
        submission: VoteSubmission,
    ) -> MoneroL2FinalityVoteQuorumResult<FinalityVote> {
        self.validate_submission(&submission)?;
        let (watcher_weight, watcher_joined_at_height, watcher_status) = self
            .watchers
            .get(&submission.watcher_id)
            .map(|watcher| (watcher.weight, watcher.joined_at_height, watcher.status))
            .ok_or_else(|| "unknown watcher".to_string())?;
        if !watcher_status.can_vote() {
            return Err("watcher is not eligible to vote".to_string());
        }
        if watcher_weight == 0 {
            return Err("watcher has zero quorum weight".to_string());
        }
        if submission.submitted_at_height < watcher_joined_at_height {
            return Err("vote predates watcher activation".to_string());
        }

        let confirmations = submission
            .observed_tip_height
            .saturating_sub(submission.monero_height);
        let confidence = self.anchor_confidence(confirmations);
        if !confidence.supports_certificate() {
            return Err("monero anchor does not meet minimum finality depth".to_string());
        }
        if submission.intent.requires_fast_quorum() && !confidence.supports_fast_exit() {
            return Err("fast settlement requires strong Monero finality confidence".to_string());
        }
        if submission.observed_tip_height > submission.monero_height
            && submission.observed_tip_height - submission.monero_height
                > self.config.strong_monero_confirmations + self.config.max_anchor_lag
        {
            return Err("reported anchor lag exceeds configured freshness bound".to_string());
        }

        let anchor_id = anchor_id(
            &self.config.network,
            submission.monero_height,
            &submission.header_root,
            &submission.txset_root,
        );
        let anchor = MoneroAnchor {
            anchor_id: anchor_id.clone(),
            network: self.config.network.clone(),
            monero_height: submission.monero_height,
            observed_tip_height: submission.observed_tip_height,
            l2_epoch: submission.epoch,
            header_root: submission.header_root.clone(),
            txset_root: submission.txset_root.clone(),
            output_commitment_root: submission.output_commitment_root.clone(),
            nullifier_root: submission.nullifier_root.clone(),
            confirmations,
            confidence,
            first_seen_l2_height: submission.submitted_at_height,
        };
        self.anchors.entry(anchor_id.clone()).or_insert(anchor);

        let vote_id = vote_id(&submission, &anchor_id);
        if self.votes.contains_key(&vote_id) {
            return Err("duplicate vote".to_string());
        }
        if self
            .epoch_votes
            .get(&submission.epoch)
            .into_iter()
            .flatten()
            .filter_map(|id| self.votes.get(id))
            .any(|vote| {
                vote.watcher_id == submission.watcher_id
                    && vote.intent == submission.intent
                    && vote.status.counts_for_quorum()
            })
        {
            return Err(
                "watcher already submitted a counted vote for this epoch and intent".to_string(),
            );
        }

        let vote = FinalityVote {
            vote_id: vote_id.clone(),
            watcher_id: submission.watcher_id,
            epoch: submission.epoch,
            intent: submission.intent,
            status: VoteStatus::Counted,
            weight: watcher_weight,
            anchor_id,
            anchor_confidence: confidence,
            l2_state_root: submission.l2_state_root,
            bridge_event_root: submission.bridge_event_root,
            private_exit_batch_root: submission.private_exit_batch_root,
            private_defi_batch_root: submission.private_defi_batch_root,
            private_contract_batch_root: submission.private_contract_batch_root,
            pq_authorization_root: submission.pq_authorization_root,
            pq_signature_root: submission.pq_signature_root,
            backup_signature_root: submission.backup_signature_root,
            submitted_at_height: submission.submitted_at_height,
        };

        self.height = self.height.max(vote.submitted_at_height);
        self.counters.votes_submitted += 1;
        self.counters.votes_counted += 1;
        self.counters.total_counted_weight += vote.weight;
        self.epoch_votes
            .entry(vote.epoch)
            .or_default()
            .insert(vote_id.clone());
        self.votes.insert(vote_id, vote.clone());
        Ok(vote)
    }

    pub fn certify_epoch(
        &mut self,
        epoch: u64,
        intent: VoteIntent,
        settlement_payload_root: &str,
        fast_exit_root: &str,
        issued_at_height: u64,
    ) -> MoneroL2FinalityVoteQuorumResult<SettlementCertificate> {
        validate_root("settlement_payload_root", settlement_payload_root)?;
        validate_root("fast_exit_root", fast_exit_root)?;

        let votes = self.counted_votes_for(epoch, intent);
        if votes.len() < self.config.min_watchers as usize {
            return Err("not enough independent watchers for certificate".to_string());
        }

        let first = votes
            .first()
            .ok_or_else(|| "epoch has no counted votes".to_string())?;
        if !votes.iter().all(|vote| vote.anchor_id == first.anchor_id) {
            return Err("votes disagree on Monero anchor".to_string());
        }
        if !votes
            .iter()
            .all(|vote| vote.l2_state_root == first.l2_state_root)
        {
            return Err("votes disagree on L2 state root".to_string());
        }
        if !votes
            .iter()
            .all(|vote| vote.anchor_confidence.supports_certificate())
        {
            return Err("one or more counted votes lack Monero finality confidence".to_string());
        }
        if intent.requires_fast_quorum()
            && !votes
                .iter()
                .all(|vote| vote.anchor_confidence.supports_fast_exit())
        {
            return Err("fast exit certificate requires strong anchor confidence".to_string());
        }

        let counted_weight = votes.iter().map(|vote| vote.weight).sum::<u64>();
        let total_active_weight = self.total_active_weight();
        if total_active_weight == 0 {
            return Err("no active watcher weight".to_string());
        }
        let required_bps = self.required_quorum_bps(intent);
        if counted_weight.saturating_mul(MONERO_L2_FINALITY_VOTE_QUORUM_MAX_BPS)
            < total_active_weight.saturating_mul(required_bps)
        {
            return Err("counted vote weight is below quorum".to_string());
        }

        let vote_records = votes
            .iter()
            .map(|vote| vote.public_record())
            .collect::<Vec<_>>();
        let watcher_records = votes
            .iter()
            .filter_map(|vote| self.watchers.get(&vote.watcher_id))
            .map(Watcher::public_record)
            .collect::<Vec<_>>();
        let auth_records = votes
            .iter()
            .map(|vote| {
                json!({
                    "watcher_id": vote.watcher_id,
                    "pq_authorization_root": vote.pq_authorization_root,
                    "pq_signature_root": vote.pq_signature_root,
                    "backup_signature_root": vote.backup_signature_root,
                })
            })
            .collect::<Vec<_>>();

        let vote_root = merkle_root("MONERO-L2-FINALITY-VOTE-QUORUM-VOTES", &vote_records);
        let watcher_root = merkle_root("MONERO-L2-FINALITY-VOTE-QUORUM-WATCHERS", &watcher_records);
        let pq_authorization_root =
            merkle_root("MONERO-L2-FINALITY-VOTE-QUORUM-PQ-AUTH", &auth_records);
        let certificate_id = certificate_id(
            epoch,
            intent,
            &first.anchor_id,
            &first.l2_state_root,
            &vote_root,
            settlement_payload_root,
            fast_exit_root,
        );
        if self.certificates.contains_key(&certificate_id) {
            return Err("duplicate certificate".to_string());
        }

        let status = if intent.requires_fast_quorum() {
            CertificateStatus::SettlementReady
        } else {
            CertificateStatus::ChallengeOpen
        };
        let certificate = SettlementCertificate {
            certificate_id: certificate_id.clone(),
            status,
            epoch,
            intent,
            anchor_id: first.anchor_id.clone(),
            anchor_confidence: first.anchor_confidence,
            l2_state_root: first.l2_state_root.clone(),
            vote_root,
            watcher_root,
            pq_authorization_root,
            settlement_payload_root: settlement_payload_root.to_string(),
            fast_exit_root: fast_exit_root.to_string(),
            counted_weight,
            total_active_weight,
            quorum_bps: required_bps,
            counted_watchers: votes.len() as u64,
            issued_at_height,
            challenge_ends_at_height: issued_at_height + self.config.challenge_window_blocks,
            expires_at_height: issued_at_height + self.config.certificate_ttl_blocks,
        };

        self.height = self.height.max(issued_at_height);
        self.counters.epochs_certified += 1;
        if intent.requires_fast_quorum() {
            self.counters.fast_exit_certificates += 1;
        }
        if intent.requires_emergency_quorum() {
            self.counters.emergency_certificates += 1;
        }
        self.certificates
            .insert(certificate_id, certificate.clone());
        Ok(certificate)
    }

    pub fn public_record(&self) -> Value {
        let watcher_records = self
            .watchers
            .values()
            .map(Watcher::public_record)
            .collect::<Vec<_>>();
        let anchor_records = self
            .anchors
            .values()
            .map(MoneroAnchor::public_record)
            .collect::<Vec<_>>();
        let vote_records = self
            .votes
            .values()
            .map(FinalityVote::public_record)
            .collect::<Vec<_>>();
        let certificate_records = self
            .certificates
            .values()
            .map(SettlementCertificate::public_record)
            .collect::<Vec<_>>();

        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_FINALITY_VOTE_QUORUM_PROTOCOL_VERSION,
            "schema_version": MONERO_L2_FINALITY_VOTE_QUORUM_SCHEMA_VERSION,
            "hash_suite": MONERO_L2_FINALITY_VOTE_QUORUM_HASH_SUITE,
            "primary_pq_scheme": MONERO_L2_FINALITY_VOTE_QUORUM_PRIMARY_PQ_SCHEME,
            "backup_pq_scheme": MONERO_L2_FINALITY_VOTE_QUORUM_BACKUP_PQ_SCHEME,
            "aggregate_scheme": MONERO_L2_FINALITY_VOTE_QUORUM_AGGREGATE_SCHEME,
            "monero_anchor_scheme": MONERO_L2_FINALITY_VOTE_QUORUM_MONERO_ANCHOR_SCHEME,
            "fast_exit_scheme": MONERO_L2_FINALITY_VOTE_QUORUM_FAST_EXIT_SCHEME,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "watcher_root": merkle_root("MONERO-L2-FINALITY-VOTE-QUORUM-STATE-WATCHERS", &watcher_records),
            "anchor_root": merkle_root("MONERO-L2-FINALITY-VOTE-QUORUM-STATE-ANCHORS", &anchor_records),
            "vote_root": merkle_root("MONERO-L2-FINALITY-VOTE-QUORUM-STATE-VOTES", &vote_records),
            "certificate_root": merkle_root("MONERO-L2-FINALITY-VOTE-QUORUM-STATE-CERTIFICATES", &certificate_records),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-FINALITY-VOTE-QUORUM-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    fn add_devnet_watcher(&mut self, label: &str, role: WatcherRole, weight: u64) {
        let watcher_id = domain_hash(
            "MONERO-L2-FINALITY-VOTE-QUORUM-DEVNET-WATCHER-ID",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
            16,
        );
        let watcher = Watcher {
            watcher_id: watcher_id.clone(),
            role,
            status: WatcherStatus::Active,
            weight,
            pq_public_key_root: labeled_root("DEVNET-PQ-PUBLIC-KEY", label),
            backup_pq_public_key_root: labeled_root("DEVNET-BACKUP-PQ-PUBLIC-KEY", label),
            authorization_policy_root: labeled_root("DEVNET-AUTHORIZATION-POLICY", label),
            joined_at_height: MONERO_L2_FINALITY_VOTE_QUORUM_DEVNET_HEIGHT,
        };
        self.watchers.insert(watcher_id, watcher);
        self.counters.watchers = self.watchers.len() as u64;
    }

    fn validate_submission(
        &self,
        submission: &VoteSubmission,
    ) -> MoneroL2FinalityVoteQuorumResult<()> {
        if submission.epoch == 0 {
            return Err("epoch must be non-zero".to_string());
        }
        if submission.observed_tip_height < submission.monero_height {
            return Err("observed Monero tip is below anchor height".to_string());
        }
        validate_root("header_root", &submission.header_root)?;
        validate_root("txset_root", &submission.txset_root)?;
        validate_root("output_commitment_root", &submission.output_commitment_root)?;
        validate_root("nullifier_root", &submission.nullifier_root)?;
        validate_root("l2_state_root", &submission.l2_state_root)?;
        validate_root("bridge_event_root", &submission.bridge_event_root)?;
        validate_root(
            "private_exit_batch_root",
            &submission.private_exit_batch_root,
        )?;
        validate_root(
            "private_defi_batch_root",
            &submission.private_defi_batch_root,
        )?;
        validate_root(
            "private_contract_batch_root",
            &submission.private_contract_batch_root,
        )?;
        validate_root("pq_authorization_root", &submission.pq_authorization_root)?;
        validate_root("pq_signature_root", &submission.pq_signature_root)?;
        validate_root("backup_signature_root", &submission.backup_signature_root)?;
        Ok(())
    }

    fn anchor_confidence(&self, confirmations: u64) -> AnchorConfidence {
        if confirmations >= self.config.strong_monero_confirmations + self.config.reorg_grace_blocks
        {
            AnchorConfidence::Final
        } else if confirmations >= self.config.strong_monero_confirmations {
            AnchorConfidence::StrongDepth
        } else if confirmations >= self.config.min_monero_confirmations {
            AnchorConfidence::SafeDepth
        } else if confirmations > 0 {
            AnchorConfidence::Observed
        } else {
            AnchorConfidence::Untrusted
        }
    }

    fn required_quorum_bps(&self, intent: VoteIntent) -> u64 {
        if intent.requires_emergency_quorum() {
            self.config.emergency_quorum_bps
        } else if intent.requires_fast_quorum() {
            self.config.fast_exit_quorum_bps
        } else {
            self.config.quorum_bps
        }
    }

    fn total_active_weight(&self) -> u64 {
        self.watchers
            .values()
            .filter(|watcher| watcher.status.can_vote())
            .map(|watcher| watcher.weight)
            .sum()
    }

    fn counted_votes_for(&self, epoch: u64, intent: VoteIntent) -> Vec<FinalityVote> {
        self.epoch_votes
            .get(&epoch)
            .into_iter()
            .flatten()
            .filter_map(|vote_id| self.votes.get(vote_id))
            .filter(|vote| vote.intent == intent && vote.status.counts_for_quorum())
            .cloned()
            .collect()
    }
}

fn anchor_id(network: &str, monero_height: u64, header_root: &str, txset_root: &str) -> String {
    domain_hash(
        "MONERO-L2-FINALITY-VOTE-QUORUM-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(network),
            HashPart::Int(monero_height as i128),
            HashPart::Str(header_root),
            HashPart::Str(txset_root),
        ],
        32,
    )
}

fn vote_id(submission: &VoteSubmission, anchor_id: &str) -> String {
    domain_hash(
        "MONERO-L2-FINALITY-VOTE-QUORUM-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&submission.watcher_id),
            HashPart::Int(submission.epoch as i128),
            HashPart::Str(submission.intent.as_str()),
            HashPart::Str(anchor_id),
            HashPart::Str(&submission.l2_state_root),
            HashPart::Str(&submission.pq_authorization_root),
        ],
        32,
    )
}

fn certificate_id(
    epoch: u64,
    intent: VoteIntent,
    anchor_id: &str,
    l2_state_root: &str,
    vote_root: &str,
    settlement_payload_root: &str,
    fast_exit_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-FINALITY-VOTE-QUORUM-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(intent.as_str()),
            HashPart::Str(anchor_id),
            HashPart::Str(l2_state_root),
            HashPart::Str(vote_root),
            HashPart::Str(settlement_payload_root),
            HashPart::Str(fast_exit_root),
        ],
        32,
    )
}

fn labeled_root(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_L2_FINALITY_VOTE_QUORUM_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn validate_root(label: &str, value: &str) -> MoneroL2FinalityVoteQuorumResult<()> {
    if value.len() < 16 {
        return Err(format!("{label} must be a commitment root"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{label} must not contain whitespace"));
    }
    Ok(())
}
