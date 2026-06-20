use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateEventOracleSettlementRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_ORACLE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-private-event-oracle-settlement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_ORACLE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_426;
pub const DEFAULT_EPOCH: u64 = 42;
pub const DEFAULT_EVENT_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_CALLBACK_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 7;
pub const DEFAULT_MIN_ATTESTATION_WEIGHT: u64 = 5;
pub const DEFAULT_MAX_EVENT_BYTES: u64 = 32_768;
pub const DEFAULT_BASE_FEE_UNITS: u64 = 1_250;
pub const DEFAULT_CALLBACK_FEE_UNITS: u64 = 350;
pub const DEFAULT_REDACTION_UNITS: u64 = 16;
pub const DEFAULT_ACCESS_UNITS: u64 = 64;
pub const DEFAULT_SPONSOR_POOL_UNITS: u64 = 2_500_000;
pub const DEFAULT_SECURITY_BITS: u16 = 192;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventFeedKind {
    Price,
    Reserve,
    Bridge,
    Liquidation,
    Governance,
    Compliance,
    ContractSignal,
    Custom,
}

impl EventFeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Price => "price",
            Self::Reserve => "reserve",
            Self::Bridge => "bridge",
            Self::Liquidation => "liquidation",
            Self::Governance => "governance",
            Self::Compliance => "compliance",
            Self::ContractSignal => "contract_signal",
            Self::Custom => "custom",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::Bridge | Self::Liquidation => 95,
            Self::Reserve => 90,
            Self::Price => 80,
            Self::Governance => 72,
            Self::Compliance => 68,
            Self::ContractSignal => 64,
            Self::Custom => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedStatus {
    Draft,
    Active,
    Paused,
    Draining,
    Retired,
}

impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_events(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Encrypted,
    Queued,
    Attesting,
    QuorumReached,
    Settling,
    Settled,
    CallbackPending,
    CallbackDelivered,
    Redacted,
    Rejected,
    Expired,
}

impl EventStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Queued => "queued",
            Self::Attesting => "attesting",
            Self::QuorumReached => "quorum_reached",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::CallbackPending => "callback_pending",
            Self::CallbackDelivered => "callback_delivered",
            Self::Redacted => "redacted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::CallbackDelivered | Self::Redacted | Self::Rejected | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    Challenged,
    Retired,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Challenged => "challenged",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    CommitteeSigned,
    CallbackScheduled,
    Finalized,
    Disputed,
    Reversed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::CommitteeSigned => "committee_signed",
            Self::CallbackScheduled => "callback_scheduled",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackStatus {
    Pending,
    Delivered,
    Deferred,
    Failed,
    Expired,
}

impl CallbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Deferred => "deferred",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    Access,
    FeeSponsor,
    Redaction,
}

impl BudgetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::FeeSponsor => "fee_sponsor",
            Self::Redaction => "redaction",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub network: String,
    pub epoch: u64,
    pub event_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub callback_ttl_blocks: u64,
    pub min_committee_weight: u64,
    pub min_attestation_weight: u64,
    pub max_event_bytes: u64,
    pub base_fee_units: u64,
    pub callback_fee_units: u64,
    pub default_access_units: u64,
    pub default_redaction_units: u64,
    pub sponsor_pool_units: u64,
    pub pq_security_bits: u16,
    pub encryption_scheme: String,
    pub attestation_scheme: String,
    pub root_scheme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_ORACLE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            chain_id: CHAIN_ID.to_string(),
            network: "nebula-private-l2-devnet".to_string(),
            epoch: DEFAULT_EPOCH,
            event_ttl_blocks: DEFAULT_EVENT_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            callback_ttl_blocks: DEFAULT_CALLBACK_TTL_BLOCKS,
            min_committee_weight: DEFAULT_MIN_COMMITTEE_WEIGHT,
            min_attestation_weight: DEFAULT_MIN_ATTESTATION_WEIGHT,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            base_fee_units: DEFAULT_BASE_FEE_UNITS,
            callback_fee_units: DEFAULT_CALLBACK_FEE_UNITS,
            default_access_units: DEFAULT_ACCESS_UNITS,
            default_redaction_units: DEFAULT_REDACTION_UNITS,
            sponsor_pool_units: DEFAULT_SPONSOR_POOL_UNITS,
            pq_security_bits: DEFAULT_SECURITY_BITS,
            encryption_scheme: "ML-KEM-1024+XChaCha20-Poly1305-private-event-feed-v1".to_string(),
            attestation_scheme: "ML-DSA-87+SLH-DSA-SHAKE-192f-event-attestation-v1".to_string(),
            root_scheme: "SHAKE256-domain-separated-private-event-merkle-v1".to_string(),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version
            != PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_ORACLE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION
        {
            return Err("unexpected protocol version".to_string());
        }
        if self.chain_id.is_empty() {
            return Err("chain id is empty".to_string());
        }
        if self.min_committee_weight == 0 || self.min_attestation_weight == 0 {
            return Err("committee and attestation weights must be non-zero".to_string());
        }
        if self.min_attestation_weight > self.min_committee_weight {
            return Err("attestation threshold exceeds committee threshold".to_string());
        }
        if self.max_event_bytes == 0 {
            return Err("max event bytes must be non-zero".to_string());
        }
        if self.pq_security_bits < 128 {
            return Err("pq security bits below runtime floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "network": self.network,
            "epoch": self.epoch,
            "event_ttl_blocks": self.event_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "callback_ttl_blocks": self.callback_ttl_blocks,
            "min_committee_weight": self.min_committee_weight,
            "min_attestation_weight": self.min_attestation_weight,
            "max_event_bytes": self.max_event_bytes,
            "base_fee_units": self.base_fee_units,
            "callback_fee_units": self.callback_fee_units,
            "default_access_units": self.default_access_units,
            "default_redaction_units": self.default_redaction_units,
            "sponsor_pool_units": self.sponsor_pool_units,
            "pq_security_bits": self.pq_security_bits,
            "encryption_scheme": self.encryption_scheme,
            "attestation_scheme": self.attestation_scheme,
            "root_scheme": self.root_scheme,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:config",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEventFeed {
    pub feed_id: String,
    pub contract_id: String,
    pub kind: EventFeedKind,
    pub status: FeedStatus,
    pub committee_id: String,
    pub encryption_key_commitment: String,
    pub policy_commitment: String,
    pub access_budget_id: String,
    pub redaction_budget_id: String,
    pub sponsor_id: String,
    pub created_height: u64,
    pub priority: u64,
    pub event_count: u64,
    pub last_event_commitment: String,
    pub metadata_commitment: String,
}

impl EncryptedEventFeed {
    pub fn new(
        feed_id: impl Into<String>,
        contract_id: impl Into<String>,
        kind: EventFeedKind,
        committee_id: impl Into<String>,
        created_height: u64,
    ) -> Self {
        let feed_id = feed_id.into();
        let contract_id = contract_id.into();
        let committee_id = committee_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:feed-seed",
            &[
                HashPart::Str(&feed_id),
                HashPart::Str(&contract_id),
                HashPart::Str(&committee_id),
                HashPart::Str(kind.as_str()),
                HashPart::U64(created_height),
            ],
            32,
        );
        Self {
            access_budget_id: format!("access-{feed_id}"),
            redaction_budget_id: format!("redact-{feed_id}"),
            sponsor_id: format!("sponsor-{contract_id}"),
            encryption_key_commitment: domain_hash(
                "private-event-oracle-settlement:feed-key",
                &[HashPart::Str(&seed)],
                32,
            ),
            policy_commitment: domain_hash(
                "private-event-oracle-settlement:feed-policy",
                &[HashPart::Str(&seed), HashPart::Str(kind.as_str())],
                32,
            ),
            metadata_commitment: domain_hash(
                "private-event-oracle-settlement:feed-metadata",
                &[HashPart::Str(&seed)],
                32,
            ),
            last_event_commitment: domain_hash(
                "private-event-oracle-settlement:feed-empty-event",
                &[HashPart::Str(&seed)],
                32,
            ),
            feed_id,
            contract_id,
            kind,
            status: FeedStatus::Active,
            committee_id,
            created_height,
            priority: kind.default_priority(),
            event_count: 0,
        }
    }

    pub fn register_event(&mut self, event_commitment: &str) {
        self.event_count = self.event_count.saturating_add(1);
        self.last_event_commitment = event_commitment.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "contract_id": self.contract_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "committee_id": self.committee_id,
            "encryption_key_commitment": self.encryption_key_commitment,
            "policy_commitment": self.policy_commitment,
            "access_budget_id": self.access_budget_id,
            "redaction_budget_id": self.redaction_budget_id,
            "sponsor_id": self.sponsor_id,
            "created_height": self.created_height,
            "priority": self.priority,
            "event_count": self.event_count,
            "last_event_commitment": self.last_event_commitment,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:feed",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_id: String,
    pub pq_public_key_commitment: String,
    pub view_key_commitment: String,
    pub weight: u64,
    pub reliability_bps: u64,
    pub slashing_bond_units: u64,
}

impl CommitteeMember {
    pub fn new(member_id: impl Into<String>, operator_id: impl Into<String>, weight: u64) -> Self {
        let member_id = member_id.into();
        let operator_id = operator_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:member-seed",
            &[
                HashPart::Str(&member_id),
                HashPart::Str(&operator_id),
                HashPart::U64(weight),
            ],
            32,
        );
        Self {
            member_id,
            operator_id,
            pq_public_key_commitment: domain_hash(
                "private-event-oracle-settlement:member-pq-key",
                &[HashPart::Str(&seed)],
                32,
            ),
            view_key_commitment: domain_hash(
                "private-event-oracle-settlement:member-view-key",
                &[HashPart::Str(&seed)],
                32,
            ),
            weight,
            reliability_bps: 9_700,
            slashing_bond_units: 250_000 * weight.max(1),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_id": self.operator_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "view_key_commitment": self.view_key_commitment,
            "weight": self.weight,
            "reliability_bps": self.reliability_bps.min(MAX_BPS),
            "slashing_bond_units": self.slashing_bond_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSettlementCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub status: CommitteeStatus,
    pub members: Vec<CommitteeMember>,
    pub min_weight: u64,
    pub rotation_height: u64,
    pub transcript_root: String,
    pub aggregate_key_commitment: String,
}

impl OracleSettlementCommittee {
    pub fn new(
        committee_id: impl Into<String>,
        epoch: u64,
        members: Vec<CommitteeMember>,
        min_weight: u64,
        rotation_height: u64,
    ) -> Self {
        let committee_id = committee_id.into();
        let members_root = merkle_root(
            "private-event-oracle-settlement:committee-members",
            &members
                .iter()
                .map(CommitteeMember::public_record)
                .collect::<Vec<_>>(),
        );
        Self {
            aggregate_key_commitment: domain_hash(
                "private-event-oracle-settlement:committee-aggregate-key",
                &[HashPart::Str(&committee_id), HashPart::Str(&members_root)],
                32,
            ),
            transcript_root: domain_hash(
                "private-event-oracle-settlement:committee-transcript",
                &[
                    HashPart::Str(&committee_id),
                    HashPart::U64(epoch),
                    HashPart::Str(&members_root),
                ],
                32,
            ),
            committee_id,
            epoch,
            status: CommitteeStatus::Active,
            members,
            min_weight,
            rotation_height,
        }
    }

    pub fn total_weight(&self) -> u64 {
        self.members.iter().map(|member| member.weight).sum()
    }

    pub fn member_weight(&self, member_id: &str) -> u64 {
        self.members
            .iter()
            .find(|member| member.member_id == member_id)
            .map(|member| member.weight)
            .unwrap_or_default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "members": self.members.iter().map(CommitteeMember::public_record).collect::<Vec<_>>(),
            "min_weight": self.min_weight,
            "total_weight": self.total_weight(),
            "rotation_height": self.rotation_height,
            "transcript_root": self.transcript_root,
            "aggregate_key_commitment": self.aggregate_key_commitment,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:committee",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateEventRoot {
    pub root_id: String,
    pub feed_id: String,
    pub epoch: u64,
    pub height: u64,
    pub event_count: u64,
    pub encrypted_leaf_root: String,
    pub nullifier_root: String,
    pub access_log_root: String,
    pub redaction_root: String,
    pub settlement_root: String,
}

impl PrivateEventRoot {
    pub fn new(
        root_id: impl Into<String>,
        feed_id: impl Into<String>,
        epoch: u64,
        height: u64,
    ) -> Self {
        let root_id = root_id.into();
        let feed_id = feed_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:private-root-seed",
            &[
                HashPart::Str(&root_id),
                HashPart::Str(&feed_id),
                HashPart::U64(epoch),
                HashPart::U64(height),
            ],
            32,
        );
        Self {
            root_id,
            feed_id,
            epoch,
            height,
            event_count: 0,
            encrypted_leaf_root: domain_hash(
                "private-event-oracle-settlement:encrypted-leaf-root",
                &[HashPart::Str(&seed)],
                32,
            ),
            nullifier_root: domain_hash(
                "private-event-oracle-settlement:nullifier-root",
                &[HashPart::Str(&seed)],
                32,
            ),
            access_log_root: domain_hash(
                "private-event-oracle-settlement:access-log-root",
                &[HashPart::Str(&seed)],
                32,
            ),
            redaction_root: domain_hash(
                "private-event-oracle-settlement:redaction-root",
                &[HashPart::Str(&seed)],
                32,
            ),
            settlement_root: domain_hash(
                "private-event-oracle-settlement:settlement-root",
                &[HashPart::Str(&seed)],
                32,
            ),
        }
    }

    pub fn absorb_event(&mut self, event: &EncryptedPrivateEvent) {
        self.event_count = self.event_count.saturating_add(1);
        self.encrypted_leaf_root = domain_hash(
            "private-event-oracle-settlement:encrypted-leaf-root:update",
            &[
                HashPart::Str(&self.encrypted_leaf_root),
                HashPart::Str(&event.event_commitment),
            ],
            32,
        );
        self.nullifier_root = domain_hash(
            "private-event-oracle-settlement:nullifier-root:update",
            &[
                HashPart::Str(&self.nullifier_root),
                HashPart::Str(&event.nullifier_commitment),
            ],
            32,
        );
    }

    pub fn absorb_settlement(&mut self, settlement: &SettlementRecord) {
        self.settlement_root = domain_hash(
            "private-event-oracle-settlement:settlement-root:update",
            &[
                HashPart::Str(&self.settlement_root),
                HashPart::Str(&settlement.settlement_id),
                HashPart::Str(&settlement.result_commitment),
            ],
            32,
        );
    }

    pub fn absorb_redaction(&mut self, request: &RedactionBudget) {
        self.redaction_root = domain_hash(
            "private-event-oracle-settlement:redaction-root:update",
            &[
                HashPart::Str(&self.redaction_root),
                HashPart::Str(&request.budget_id),
                HashPart::U64(request.spent_units),
            ],
            32,
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "feed_id": self.feed_id,
            "epoch": self.epoch,
            "height": self.height,
            "event_count": self.event_count,
            "encrypted_leaf_root": self.encrypted_leaf_root,
            "nullifier_root": self.nullifier_root,
            "access_log_root": self.access_log_root,
            "redaction_root": self.redaction_root,
            "settlement_root": self.settlement_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:private-event-root",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPrivateEvent {
    pub event_id: String,
    pub feed_id: String,
    pub contract_id: String,
    pub status: EventStatus,
    pub sequence: u64,
    pub observed_height: u64,
    pub expires_height: u64,
    pub event_commitment: String,
    pub ciphertext_commitment: String,
    pub payload_size_bytes: u64,
    pub nullifier_commitment: String,
    pub access_tag_commitment: String,
    pub callback_selector_commitment: String,
    pub sponsor_id: String,
    pub private_root_id: String,
    pub priority: u64,
}

impl EncryptedPrivateEvent {
    pub fn new(
        event_id: impl Into<String>,
        feed: &EncryptedEventFeed,
        sequence: u64,
        observed_height: u64,
        config: &Config,
        private_root_id: impl Into<String>,
    ) -> Self {
        let event_id = event_id.into();
        let private_root_id = private_root_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:event-seed",
            &[
                HashPart::Str(&event_id),
                HashPart::Str(&feed.feed_id),
                HashPart::U64(sequence),
                HashPart::U64(observed_height),
            ],
            32,
        );
        Self {
            event_commitment: domain_hash(
                "private-event-oracle-settlement:event-commitment",
                &[HashPart::Str(&seed)],
                32,
            ),
            ciphertext_commitment: domain_hash(
                "private-event-oracle-settlement:event-ciphertext",
                &[
                    HashPart::Str(&seed),
                    HashPart::Str(&config.encryption_scheme),
                ],
                32,
            ),
            nullifier_commitment: domain_hash(
                "private-event-oracle-settlement:event-nullifier",
                &[HashPart::Str(&seed)],
                32,
            ),
            access_tag_commitment: domain_hash(
                "private-event-oracle-settlement:event-access-tag",
                &[HashPart::Str(&seed)],
                32,
            ),
            callback_selector_commitment: domain_hash(
                "private-event-oracle-settlement:event-callback-selector",
                &[HashPart::Str(&seed)],
                32,
            ),
            event_id,
            feed_id: feed.feed_id.clone(),
            contract_id: feed.contract_id.clone(),
            status: EventStatus::Encrypted,
            sequence,
            observed_height,
            expires_height: observed_height.saturating_add(config.event_ttl_blocks),
            payload_size_bytes: 2_048 + 128 * sequence,
            sponsor_id: feed.sponsor_id.clone(),
            private_root_id,
            priority: feed.priority,
        }
    }

    pub fn transition(&mut self, status: EventStatus) {
        if !self.status.terminal() {
            self.status = status;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "feed_id": self.feed_id,
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "sequence": self.sequence,
            "observed_height": self.observed_height,
            "expires_height": self.expires_height,
            "event_commitment": self.event_commitment,
            "ciphertext_commitment": self.ciphertext_commitment,
            "payload_size_bytes": self.payload_size_bytes,
            "nullifier_commitment": self.nullifier_commitment,
            "access_tag_commitment": self.access_tag_commitment,
            "callback_selector_commitment": self.callback_selector_commitment,
            "sponsor_id": self.sponsor_id,
            "private_root_id": self.private_root_id,
            "priority": self.priority,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:event",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqEventAttestation {
    pub attestation_id: String,
    pub event_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub status: AttestationStatus,
    pub weight: u64,
    pub observed_height: u64,
    pub result_commitment: String,
    pub signature_commitment: String,
    pub transcript_commitment: String,
    pub challenge_commitment: String,
}

impl PqEventAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        event: &EncryptedPrivateEvent,
        committee: &OracleSettlementCommittee,
        member_id: impl Into<String>,
        observed_height: u64,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let member_id = member_id.into();
        let weight = committee.member_weight(&member_id);
        let seed = domain_hash(
            "private-event-oracle-settlement:attestation-seed",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(&event.event_id),
                HashPart::Str(&committee.committee_id),
                HashPart::Str(&member_id),
                HashPart::U64(observed_height),
            ],
            32,
        );
        Self {
            attestation_id,
            event_id: event.event_id.clone(),
            committee_id: committee.committee_id.clone(),
            member_id,
            status: AttestationStatus::Accepted,
            weight,
            observed_height,
            result_commitment: domain_hash(
                "private-event-oracle-settlement:attestation-result",
                &[HashPart::Str(&seed), HashPart::Str(&event.event_commitment)],
                32,
            ),
            signature_commitment: domain_hash(
                "private-event-oracle-settlement:attestation-signature",
                &[
                    HashPart::Str(&seed),
                    HashPart::Str(&committee.aggregate_key_commitment),
                ],
                32,
            ),
            transcript_commitment: domain_hash(
                "private-event-oracle-settlement:attestation-transcript",
                &[
                    HashPart::Str(&seed),
                    HashPart::Str(&committee.transcript_root),
                ],
                32,
            ),
            challenge_commitment: domain_hash(
                "private-event-oracle-settlement:attestation-challenge",
                &[HashPart::Str(&seed)],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "event_id": self.event_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "status": self.status.as_str(),
            "weight": self.weight,
            "observed_height": self.observed_height,
            "result_commitment": self.result_commitment,
            "signature_commitment": self.signature_commitment,
            "transcript_commitment": self.transcript_commitment,
            "challenge_commitment": self.challenge_commitment,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:attestation",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub event_id: String,
    pub feed_id: String,
    pub committee_id: String,
    pub status: SettlementStatus,
    pub attestation_weight: u64,
    pub threshold_weight: u64,
    pub settled_height: u64,
    pub result_commitment: String,
    pub payout_commitment: String,
    pub callback_id: String,
    pub fee_sponsor_id: String,
}

impl SettlementRecord {
    pub fn new(
        settlement_id: impl Into<String>,
        event: &EncryptedPrivateEvent,
        committee_id: impl Into<String>,
        attestation_weight: u64,
        threshold_weight: u64,
        settled_height: u64,
    ) -> Self {
        let settlement_id = settlement_id.into();
        let committee_id = committee_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:settlement-seed",
            &[
                HashPart::Str(&settlement_id),
                HashPart::Str(&event.event_id),
                HashPart::Str(&committee_id),
                HashPart::U64(attestation_weight),
            ],
            32,
        );
        Self {
            callback_id: format!("callback-{}", event.event_id),
            fee_sponsor_id: event.sponsor_id.clone(),
            settlement_id,
            event_id: event.event_id.clone(),
            feed_id: event.feed_id.clone(),
            committee_id,
            status: SettlementStatus::CallbackScheduled,
            attestation_weight,
            threshold_weight,
            settled_height,
            result_commitment: domain_hash(
                "private-event-oracle-settlement:settlement-result",
                &[HashPart::Str(&seed), HashPart::Str(&event.event_commitment)],
                32,
            ),
            payout_commitment: domain_hash(
                "private-event-oracle-settlement:settlement-payout",
                &[HashPart::Str(&seed)],
                32,
            ),
        }
    }

    pub fn finalized(&self) -> bool {
        matches!(
            self.status,
            SettlementStatus::CallbackScheduled | SettlementStatus::Finalized
        ) && self.attestation_weight >= self.threshold_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "event_id": self.event_id,
            "feed_id": self.feed_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "attestation_weight": self.attestation_weight,
            "threshold_weight": self.threshold_weight,
            "settled_height": self.settled_height,
            "result_commitment": self.result_commitment,
            "payout_commitment": self.payout_commitment,
            "callback_id": self.callback_id,
            "fee_sponsor_id": self.fee_sponsor_id,
            "finalized": self.finalized(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:settlement",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackReceipt {
    pub callback_id: String,
    pub settlement_id: String,
    pub event_id: String,
    pub contract_id: String,
    pub status: CallbackStatus,
    pub scheduled_height: u64,
    pub delivered_height: Option<u64>,
    pub receipt_commitment: String,
    pub gas_commitment: String,
    pub return_data_commitment: String,
}

impl CallbackReceipt {
    pub fn new(
        callback_id: impl Into<String>,
        settlement: &SettlementRecord,
        event: &EncryptedPrivateEvent,
        scheduled_height: u64,
    ) -> Self {
        let callback_id = callback_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:callback-seed",
            &[
                HashPart::Str(&callback_id),
                HashPart::Str(&settlement.settlement_id),
                HashPart::Str(&event.event_id),
                HashPart::U64(scheduled_height),
            ],
            32,
        );
        Self {
            callback_id,
            settlement_id: settlement.settlement_id.clone(),
            event_id: event.event_id.clone(),
            contract_id: event.contract_id.clone(),
            status: CallbackStatus::Delivered,
            scheduled_height,
            delivered_height: Some(scheduled_height.saturating_add(2)),
            receipt_commitment: domain_hash(
                "private-event-oracle-settlement:callback-receipt",
                &[
                    HashPart::Str(&seed),
                    HashPart::Str(&settlement.result_commitment),
                ],
                32,
            ),
            gas_commitment: domain_hash(
                "private-event-oracle-settlement:callback-gas",
                &[HashPart::Str(&seed)],
                32,
            ),
            return_data_commitment: domain_hash(
                "private-event-oracle-settlement:callback-return-data",
                &[HashPart::Str(&seed)],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "callback_id": self.callback_id,
            "settlement_id": self.settlement_id,
            "event_id": self.event_id,
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "scheduled_height": self.scheduled_height,
            "delivered_height": self.delivered_height,
            "receipt_commitment": self.receipt_commitment,
            "gas_commitment": self.gas_commitment,
            "return_data_commitment": self.return_data_commitment,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:callback",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessBudget {
    pub budget_id: String,
    pub feed_id: String,
    pub grantee_commitment: String,
    pub total_units: u64,
    pub spent_units: u64,
    pub expires_height: u64,
    pub policy_commitment: String,
}

impl AccessBudget {
    pub fn new(
        budget_id: impl Into<String>,
        feed_id: impl Into<String>,
        total_units: u64,
        expires_height: u64,
    ) -> Self {
        let budget_id = budget_id.into();
        let feed_id = feed_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:access-budget-seed",
            &[
                HashPart::Str(&budget_id),
                HashPart::Str(&feed_id),
                HashPart::U64(total_units),
            ],
            32,
        );
        Self {
            budget_id,
            feed_id,
            grantee_commitment: domain_hash(
                "private-event-oracle-settlement:access-grantee",
                &[HashPart::Str(&seed)],
                32,
            ),
            total_units,
            spent_units: 0,
            expires_height,
            policy_commitment: domain_hash(
                "private-event-oracle-settlement:access-policy",
                &[HashPart::Str(&seed)],
                32,
            ),
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.spent_units)
    }

    pub fn spend(&mut self, units: u64) -> Result<()> {
        if self.remaining_units() < units {
            return Err(format!("access budget {} exhausted", self.budget_id));
        }
        self.spent_units = self.spent_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "kind": BudgetKind::Access.as_str(),
            "feed_id": self.feed_id,
            "grantee_commitment": self.grantee_commitment,
            "total_units": self.total_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "expires_height": self.expires_height,
            "policy_commitment": self.policy_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsor {
    pub sponsor_id: String,
    pub contract_id: String,
    pub total_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub fee_asset_id: String,
    pub policy_commitment: String,
}

impl FeeSponsor {
    pub fn new(
        sponsor_id: impl Into<String>,
        contract_id: impl Into<String>,
        total_units: u64,
    ) -> Self {
        let sponsor_id = sponsor_id.into();
        let contract_id = contract_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:fee-sponsor-seed",
            &[
                HashPart::Str(&sponsor_id),
                HashPart::Str(&contract_id),
                HashPart::U64(total_units),
            ],
            32,
        );
        Self {
            sponsor_id,
            contract_id,
            total_units,
            reserved_units: 0,
            spent_units: 0,
            fee_asset_id: "dxmr".to_string(),
            policy_commitment: domain_hash(
                "private-event-oracle-settlement:fee-sponsor-policy",
                &[HashPart::Str(&seed)],
                32,
            ),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve(&mut self, units: u64) -> Result<()> {
        if self.available_units() < units {
            return Err(format!("fee sponsor {} exhausted", self.sponsor_id));
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn settle_reserved(&mut self, units: u64) {
        let paid = units.min(self.reserved_units);
        self.reserved_units = self.reserved_units.saturating_sub(paid);
        self.spent_units = self.spent_units.saturating_add(paid);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "kind": BudgetKind::FeeSponsor.as_str(),
            "contract_id": self.contract_id,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "fee_asset_id": self.fee_asset_id,
            "policy_commitment": self.policy_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub feed_id: String,
    pub reviewer_commitment: String,
    pub total_units: u64,
    pub spent_units: u64,
    pub disclosure_root: String,
    pub policy_commitment: String,
}

impl RedactionBudget {
    pub fn new(budget_id: impl Into<String>, feed_id: impl Into<String>, total_units: u64) -> Self {
        let budget_id = budget_id.into();
        let feed_id = feed_id.into();
        let seed = domain_hash(
            "private-event-oracle-settlement:redaction-budget-seed",
            &[
                HashPart::Str(&budget_id),
                HashPart::Str(&feed_id),
                HashPart::U64(total_units),
            ],
            32,
        );
        Self {
            budget_id,
            feed_id,
            reviewer_commitment: domain_hash(
                "private-event-oracle-settlement:redaction-reviewer",
                &[HashPart::Str(&seed)],
                32,
            ),
            total_units,
            spent_units: 0,
            disclosure_root: domain_hash(
                "private-event-oracle-settlement:redaction-disclosure-root",
                &[HashPart::Str(&seed)],
                32,
            ),
            policy_commitment: domain_hash(
                "private-event-oracle-settlement:redaction-policy",
                &[HashPart::Str(&seed)],
                32,
            ),
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.spent_units)
    }

    pub fn redact(&mut self, event_id: &str, units: u64) -> Result<()> {
        if self.remaining_units() < units {
            return Err(format!("redaction budget {} exhausted", self.budget_id));
        }
        self.spent_units = self.spent_units.saturating_add(units);
        self.disclosure_root = domain_hash(
            "private-event-oracle-settlement:redaction-disclosure-root:update",
            &[
                HashPart::Str(&self.disclosure_root),
                HashPart::Str(event_id),
                HashPart::U64(units),
            ],
            32,
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "kind": BudgetKind::Redaction.as_str(),
            "feed_id": self.feed_id,
            "reviewer_commitment": self.reviewer_commitment,
            "total_units": self.total_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "disclosure_root": self.disclosure_root,
            "policy_commitment": self.policy_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub label: String,
    pub committee_count: u64,
    pub accepted_attestations: u64,
    pub rejected_attestations: u64,
    pub sponsored_fee_units: u64,
    pub delivered_callbacks: u64,
    pub redactions_served: u64,
    pub latest_height: u64,
    pub reputation_bps: u64,
}

impl OperatorSummary {
    pub fn new(
        operator_id: impl Into<String>,
        label: impl Into<String>,
        latest_height: u64,
    ) -> Self {
        Self {
            operator_id: operator_id.into(),
            label: label.into(),
            committee_count: 0,
            accepted_attestations: 0,
            rejected_attestations: 0,
            sponsored_fee_units: 0,
            delivered_callbacks: 0,
            redactions_served: 0,
            latest_height,
            reputation_bps: 9_600,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "label": self.label,
            "committee_count": self.committee_count,
            "accepted_attestations": self.accepted_attestations,
            "rejected_attestations": self.rejected_attestations,
            "sponsored_fee_units": self.sponsored_fee_units,
            "delivered_callbacks": self.delivered_callbacks,
            "redactions_served": self.redactions_served,
            "latest_height": self.latest_height,
            "reputation_bps": self.reputation_bps.min(MAX_BPS),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub feeds: u64,
    pub committees: u64,
    pub committee_members: u64,
    pub private_roots: u64,
    pub encrypted_events: u64,
    pub accepted_attestations: u64,
    pub rejected_attestations: u64,
    pub settlements: u64,
    pub callbacks: u64,
    pub delivered_callbacks: u64,
    pub access_budgets: u64,
    pub fee_sponsors: u64,
    pub redaction_budgets: u64,
    pub redacted_events: u64,
    pub total_fee_units_reserved: u64,
    pub total_fee_units_spent: u64,
    pub total_access_units_spent: u64,
    pub total_redaction_units_spent: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "feeds": self.feeds,
            "committees": self.committees,
            "committee_members": self.committee_members,
            "private_roots": self.private_roots,
            "encrypted_events": self.encrypted_events,
            "accepted_attestations": self.accepted_attestations,
            "rejected_attestations": self.rejected_attestations,
            "settlements": self.settlements,
            "callbacks": self.callbacks,
            "delivered_callbacks": self.delivered_callbacks,
            "access_budgets": self.access_budgets,
            "fee_sponsors": self.fee_sponsors,
            "redaction_budgets": self.redaction_budgets,
            "redacted_events": self.redacted_events,
            "total_fee_units_reserved": self.total_fee_units_reserved,
            "total_fee_units_spent": self.total_fee_units_spent,
            "total_access_units_spent": self.total_access_units_spent,
            "total_redaction_units_spent": self.total_redaction_units_spent,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "private-event-oracle-settlement:counters",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub feeds_root: String,
    pub committees_root: String,
    pub private_event_roots_root: String,
    pub encrypted_events_root: String,
    pub attestations_root: String,
    pub settlements_root: String,
    pub callbacks_root: String,
    pub access_budgets_root: String,
    pub fee_sponsors_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "feeds_root": self.feeds_root,
            "committees_root": self.committees_root,
            "private_event_roots_root": self.private_event_roots_root,
            "encrypted_events_root": self.encrypted_events_root,
            "attestations_root": self.attestations_root,
            "settlements_root": self.settlements_root,
            "callbacks_root": self.callbacks_root,
            "access_budgets_root": self.access_budgets_root,
            "fee_sponsors_root": self.fee_sponsors_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub feeds: BTreeMap<String, EncryptedEventFeed>,
    pub committees: BTreeMap<String, OracleSettlementCommittee>,
    pub private_event_roots: BTreeMap<String, PrivateEventRoot>,
    pub encrypted_events: BTreeMap<String, EncryptedPrivateEvent>,
    pub attestations: BTreeMap<String, PqEventAttestation>,
    pub settlements: BTreeMap<String, SettlementRecord>,
    pub callbacks: BTreeMap<String, CallbackReceipt>,
    pub access_budgets: BTreeMap<String, AccessBudget>,
    pub fee_sponsors: BTreeMap<String, FeeSponsor>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        let mut state = Self {
            config,
            height,
            feeds: BTreeMap::new(),
            committees: BTreeMap::new(),
            private_event_roots: BTreeMap::new(),
            encrypted_events: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            callbacks: BTreeMap::new(),
            access_budgets: BTreeMap::new(),
            fee_sponsors: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn add_committee(&mut self, committee: OracleSettlementCommittee) {
        for member in &committee.members {
            let summary = self
                .operator_summaries
                .entry(member.operator_id.clone())
                .or_insert_with(|| {
                    OperatorSummary::new(
                        member.operator_id.clone(),
                        format!("operator {}", member.operator_id),
                        self.height,
                    )
                });
            summary.committee_count = summary.committee_count.saturating_add(1);
            summary.latest_height = self.height;
        }
        self.committees
            .insert(committee.committee_id.clone(), committee);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn add_feed(&mut self, feed: EncryptedEventFeed) {
        let access_budget = AccessBudget::new(
            feed.access_budget_id.clone(),
            feed.feed_id.clone(),
            self.config.default_access_units,
            self.height.saturating_add(self.config.event_ttl_blocks),
        );
        let redaction_budget = RedactionBudget::new(
            feed.redaction_budget_id.clone(),
            feed.feed_id.clone(),
            self.config.default_redaction_units,
        );
        let fee_sponsor = FeeSponsor::new(
            feed.sponsor_id.clone(),
            feed.contract_id.clone(),
            self.config.sponsor_pool_units,
        );
        self.access_budgets
            .insert(access_budget.budget_id.clone(), access_budget);
        self.redaction_budgets
            .insert(redaction_budget.budget_id.clone(), redaction_budget);
        self.fee_sponsors
            .entry(fee_sponsor.sponsor_id.clone())
            .or_insert(fee_sponsor);
        self.feeds.insert(feed.feed_id.clone(), feed);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn add_private_root(&mut self, root: PrivateEventRoot) {
        self.private_event_roots.insert(root.root_id.clone(), root);
        self.refresh_counters();
        self.refresh_roots();
    }

    pub fn ingest_event(&mut self, mut event: EncryptedPrivateEvent) -> Result<()> {
        self.config.validate()?;
        if event.payload_size_bytes > self.config.max_event_bytes {
            return Err(format!("event {} exceeds max event bytes", event.event_id));
        }
        let feed = self
            .feeds
            .get_mut(&event.feed_id)
            .ok_or_else(|| format!("unknown feed {}", event.feed_id))?;
        if !feed.status.accepts_events() {
            return Err(format!("feed {} does not accept events", feed.feed_id));
        }
        let access = self
            .access_budgets
            .get_mut(&feed.access_budget_id)
            .ok_or_else(|| format!("missing access budget {}", feed.access_budget_id))?;
        access.spend(1)?;
        self.counters.total_access_units_spent =
            self.counters.total_access_units_spent.saturating_add(1);
        let sponsor = self
            .fee_sponsors
            .get_mut(&event.sponsor_id)
            .ok_or_else(|| format!("missing sponsor {}", event.sponsor_id))?;
        let reserve_units = self
            .config
            .base_fee_units
            .saturating_add(self.config.callback_fee_units);
        sponsor.reserve(reserve_units)?;
        self.counters.total_fee_units_reserved = self
            .counters
            .total_fee_units_reserved
            .saturating_add(reserve_units);
        event.transition(EventStatus::Queued);
        feed.register_event(&event.event_commitment);
        if let Some(root) = self.private_event_roots.get_mut(&event.private_root_id) {
            root.absorb_event(&event);
        }
        self.encrypted_events.insert(event.event_id.clone(), event);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_attestation(&mut self, attestation: PqEventAttestation) -> Result<()> {
        if !self.encrypted_events.contains_key(&attestation.event_id) {
            return Err(format!("unknown event {}", attestation.event_id));
        }
        if !self.committees.contains_key(&attestation.committee_id) {
            return Err(format!("unknown committee {}", attestation.committee_id));
        }
        if attestation.status.counts_for_quorum() {
            if let Some(event) = self.encrypted_events.get_mut(&attestation.event_id) {
                event.transition(EventStatus::Attesting);
            }
            if let Some(summary) = self.operator_summary_for_member(&attestation.member_id) {
                summary.accepted_attestations = summary.accepted_attestations.saturating_add(1);
                summary.latest_height = self.height;
            }
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn settle_event(&mut self, event_id: &str) -> Result<SettlementRecord> {
        let event = self
            .encrypted_events
            .get(event_id)
            .cloned()
            .ok_or_else(|| format!("unknown event {event_id}"))?;
        let feed = self
            .feeds
            .get(&event.feed_id)
            .ok_or_else(|| format!("unknown feed {}", event.feed_id))?;
        let committee = self
            .committees
            .get(&feed.committee_id)
            .ok_or_else(|| format!("unknown committee {}", feed.committee_id))?;
        let attestation_weight = self.attestation_weight(event_id, &committee.committee_id);
        if attestation_weight < self.config.min_attestation_weight {
            return Err(format!(
                "event {event_id} has insufficient attestation weight {attestation_weight}"
            ));
        }
        let settlement = SettlementRecord::new(
            format!("settlement-{event_id}"),
            &event,
            committee.committee_id.clone(),
            attestation_weight,
            self.config.min_attestation_weight,
            self.height.saturating_add(1),
        );
        if let Some(root) = self.private_event_roots.get_mut(&event.private_root_id) {
            root.absorb_settlement(&settlement);
        }
        if let Some(stored_event) = self.encrypted_events.get_mut(event_id) {
            stored_event.transition(EventStatus::CallbackPending);
        }
        if let Some(sponsor) = self.fee_sponsors.get_mut(&event.sponsor_id) {
            let fee_units = self
                .config
                .base_fee_units
                .saturating_add(self.config.callback_fee_units);
            sponsor.settle_reserved(fee_units);
            self.counters.total_fee_units_spent = self
                .counters
                .total_fee_units_spent
                .saturating_add(fee_units);
            if let Some(summary) = self.operator_summaries.values_mut().next() {
                summary.sponsored_fee_units = summary.sponsored_fee_units.saturating_add(fee_units);
            }
        }
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        self.refresh_counters();
        self.refresh_roots();
        Ok(settlement)
    }

    pub fn deliver_callback(&mut self, settlement_id: &str) -> Result<CallbackReceipt> {
        let settlement = self
            .settlements
            .get(settlement_id)
            .cloned()
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        let event = self
            .encrypted_events
            .get(&settlement.event_id)
            .cloned()
            .ok_or_else(|| format!("unknown event {}", settlement.event_id))?;
        let receipt = CallbackReceipt::new(
            settlement.callback_id.clone(),
            &settlement,
            &event,
            self.height.saturating_add(2),
        );
        if let Some(stored_event) = self.encrypted_events.get_mut(&event.event_id) {
            stored_event.transition(EventStatus::CallbackDelivered);
        }
        if let Some(summary) = self.operator_summaries.values_mut().next() {
            summary.delivered_callbacks = summary.delivered_callbacks.saturating_add(1);
        }
        self.callbacks
            .insert(receipt.callback_id.clone(), receipt.clone());
        self.refresh_counters();
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn redact_event(&mut self, event_id: &str, units: u64) -> Result<()> {
        let event = self
            .encrypted_events
            .get_mut(event_id)
            .ok_or_else(|| format!("unknown event {event_id}"))?;
        let feed = self
            .feeds
            .get(&event.feed_id)
            .ok_or_else(|| format!("unknown feed {}", event.feed_id))?;
        let redaction = self
            .redaction_budgets
            .get_mut(&feed.redaction_budget_id)
            .ok_or_else(|| format!("missing redaction budget {}", feed.redaction_budget_id))?;
        redaction.redact(event_id, units)?;
        event.transition(EventStatus::Redacted);
        if let Some(root) = self.private_event_roots.get_mut(&event.private_root_id) {
            root.absorb_redaction(redaction);
        }
        self.counters.total_redaction_units_spent = self
            .counters
            .total_redaction_units_spent
            .saturating_add(units);
        if let Some(summary) = self.operator_summaries.values_mut().next() {
            summary.redactions_served = summary.redactions_served.saturating_add(1);
        }
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn attestation_weight(&self, event_id: &str, committee_id: &str) -> u64 {
        let mut seen_members = BTreeSet::new();
        self.attestations
            .values()
            .filter(|attestation| {
                attestation.event_id == event_id
                    && attestation.committee_id == committee_id
                    && attestation.status.counts_for_quorum()
                    && seen_members.insert(attestation.member_id.clone())
            })
            .map(|attestation| attestation.weight)
            .sum()
    }

    pub fn event_attestation_ids(&self, event_id: &str) -> Vec<String> {
        self.attestations
            .values()
            .filter(|attestation| attestation.event_id == event_id)
            .map(|attestation| attestation.attestation_id.clone())
            .collect()
    }

    pub fn settlement_for_event(&self, event_id: &str) -> Option<&SettlementRecord> {
        self.settlements
            .values()
            .find(|settlement| settlement.event_id == event_id)
    }

    pub fn callback_for_event(&self, event_id: &str) -> Option<&CallbackReceipt> {
        self.callbacks
            .values()
            .find(|callback| callback.event_id == event_id)
    }

    pub fn refresh_counters(&mut self) {
        self.counters.feeds = self.feeds.len() as u64;
        self.counters.committees = self.committees.len() as u64;
        self.counters.committee_members = self
            .committees
            .values()
            .map(|committee| committee.members.len() as u64)
            .sum();
        self.counters.private_roots = self.private_event_roots.len() as u64;
        self.counters.encrypted_events = self.encrypted_events.len() as u64;
        self.counters.accepted_attestations = self
            .attestations
            .values()
            .filter(|attestation| attestation.status.counts_for_quorum())
            .count() as u64;
        self.counters.rejected_attestations = self
            .attestations
            .values()
            .filter(|attestation| attestation.status == AttestationStatus::Rejected)
            .count() as u64;
        self.counters.settlements = self.settlements.len() as u64;
        self.counters.callbacks = self.callbacks.len() as u64;
        self.counters.delivered_callbacks = self
            .callbacks
            .values()
            .filter(|callback| callback.status == CallbackStatus::Delivered)
            .count() as u64;
        self.counters.access_budgets = self.access_budgets.len() as u64;
        self.counters.fee_sponsors = self.fee_sponsors.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.redacted_events = self
            .encrypted_events
            .values()
            .filter(|event| event.status == EventStatus::Redacted)
            .count() as u64;
    }

    pub fn refresh_roots(&mut self) {
        let config_root = self.config.root();
        let feeds_root = merkle_root(
            "private-event-oracle-settlement:feeds",
            &self
                .feeds
                .values()
                .map(EncryptedEventFeed::public_record)
                .collect::<Vec<_>>(),
        );
        let committees_root = merkle_root(
            "private-event-oracle-settlement:committees",
            &self
                .committees
                .values()
                .map(OracleSettlementCommittee::public_record)
                .collect::<Vec<_>>(),
        );
        let private_event_roots_root = merkle_root(
            "private-event-oracle-settlement:private-event-roots",
            &self
                .private_event_roots
                .values()
                .map(PrivateEventRoot::public_record)
                .collect::<Vec<_>>(),
        );
        let encrypted_events_root = merkle_root(
            "private-event-oracle-settlement:encrypted-events",
            &self
                .encrypted_events
                .values()
                .map(EncryptedPrivateEvent::public_record)
                .collect::<Vec<_>>(),
        );
        let attestations_root = merkle_root(
            "private-event-oracle-settlement:attestations",
            &self
                .attestations
                .values()
                .map(PqEventAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let settlements_root = merkle_root(
            "private-event-oracle-settlement:settlements",
            &self
                .settlements
                .values()
                .map(SettlementRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let callbacks_root = merkle_root(
            "private-event-oracle-settlement:callbacks",
            &self
                .callbacks
                .values()
                .map(CallbackReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let access_budgets_root = merkle_root(
            "private-event-oracle-settlement:access-budgets",
            &self
                .access_budgets
                .values()
                .map(AccessBudget::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_sponsors_root = merkle_root(
            "private-event-oracle-settlement:fee-sponsors",
            &self
                .fee_sponsors
                .values()
                .map(FeeSponsor::public_record)
                .collect::<Vec<_>>(),
        );
        let redaction_budgets_root = merkle_root(
            "private-event-oracle-settlement:redaction-budgets",
            &self
                .redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect::<Vec<_>>(),
        );
        let operator_summaries_root = merkle_root(
            "private-event-oracle-settlement:operator-summaries",
            &self
                .operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect::<Vec<_>>(),
        );
        let counters_root = self.counters.root();
        let state_root = domain_hash(
            "private-event-oracle-settlement:state-root",
            &[
                HashPart::Str(
                    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_ORACLE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION,
                ),
                HashPart::U64(self.height),
                HashPart::Str(&config_root),
                HashPart::Str(&feeds_root),
                HashPart::Str(&committees_root),
                HashPart::Str(&private_event_roots_root),
                HashPart::Str(&encrypted_events_root),
                HashPart::Str(&attestations_root),
                HashPart::Str(&settlements_root),
                HashPart::Str(&callbacks_root),
                HashPart::Str(&access_budgets_root),
                HashPart::Str(&fee_sponsors_root),
                HashPart::Str(&redaction_budgets_root),
                HashPart::Str(&operator_summaries_root),
                HashPart::Str(&counters_root),
            ],
            32,
        );
        self.roots = Roots {
            config_root,
            feeds_root,
            committees_root,
            private_event_roots_root,
            encrypted_events_root,
            attestations_root,
            settlements_root,
            callbacks_root,
            access_budgets_root,
            fee_sponsors_root,
            redaction_budgets_root,
            operator_summaries_root,
            counters_root,
            state_root,
        };
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version":
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_ORACLE_SETTLEMENT_RUNTIME_PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "feeds": self.feeds.values().map(EncryptedEventFeed::public_record).collect::<Vec<_>>(),
            "committees": self.committees.values().map(OracleSettlementCommittee::public_record).collect::<Vec<_>>(),
            "private_event_roots": self.private_event_roots.values().map(PrivateEventRoot::public_record).collect::<Vec<_>>(),
            "encrypted_events": self.encrypted_events.values().map(EncryptedPrivateEvent::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqEventAttestation::public_record).collect::<Vec<_>>(),
            "settlements": self.settlements.values().map(SettlementRecord::public_record).collect::<Vec<_>>(),
            "callbacks": self.callbacks.values().map(CallbackReceipt::public_record).collect::<Vec<_>>(),
            "access_budgets": self.access_budgets.values().map(AccessBudget::public_record).collect::<Vec<_>>(),
            "fee_sponsors": self.fee_sponsors.values().map(FeeSponsor::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn operator_summary_for_member(&mut self, member_id: &str) -> Option<&mut OperatorSummary> {
        let operator_id = self
            .committees
            .values()
            .flat_map(|committee| committee.members.iter())
            .find(|member| member.member_id == member_id)
            .map(|member| member.operator_id.clone())?;
        self.operator_summaries.get_mut(&operator_id)
    }

    fn seed_devnet(&mut self) {
        let committee = OracleSettlementCommittee::new(
            "committee-oracle-alpha",
            self.config.epoch,
            vec![
                CommitteeMember::new("member-alpha-1", "operator-alpha", 3),
                CommitteeMember::new("member-alpha-2", "operator-beta", 2),
                CommitteeMember::new("member-alpha-3", "operator-gamma", 2),
                CommitteeMember::new("member-alpha-4", "operator-delta", 1),
            ],
            self.config.min_committee_weight,
            self.height.saturating_add(360),
        );
        self.add_committee(committee.clone());

        let feed_a = EncryptedEventFeed::new(
            "feed-wxmr-reserve",
            "contract-confidential-reserve-vault",
            EventFeedKind::Reserve,
            committee.committee_id.clone(),
            self.height,
        );
        let feed_b = EncryptedEventFeed::new(
            "feed-bridge-risk",
            "contract-private-bridge-risk",
            EventFeedKind::Bridge,
            committee.committee_id.clone(),
            self.height.saturating_add(1),
        );
        self.add_feed(feed_a.clone());
        self.add_feed(feed_b.clone());

        let root_a = PrivateEventRoot::new(
            "root-wxmr-reserve-42",
            feed_a.feed_id.clone(),
            self.config.epoch,
            self.height,
        );
        let root_b = PrivateEventRoot::new(
            "root-bridge-risk-42",
            feed_b.feed_id.clone(),
            self.config.epoch,
            self.height,
        );
        self.add_private_root(root_a.clone());
        self.add_private_root(root_b.clone());

        let event_a = EncryptedPrivateEvent::new(
            "event-reserve-threshold-001",
            &feed_a,
            1,
            self.height.saturating_add(4),
            &self.config,
            root_a.root_id.clone(),
        );
        let event_b = EncryptedPrivateEvent::new(
            "event-bridge-latency-002",
            &feed_b,
            2,
            self.height.saturating_add(5),
            &self.config,
            root_b.root_id.clone(),
        );
        let event_c = EncryptedPrivateEvent::new(
            "event-bridge-callback-003",
            &feed_b,
            3,
            self.height.saturating_add(6),
            &self.config,
            root_b.root_id.clone(),
        );
        self.ingest_event(event_a.clone()).expect("devnet event a");
        self.ingest_event(event_b.clone()).expect("devnet event b");
        self.ingest_event(event_c.clone()).expect("devnet event c");

        for event in [&event_a, &event_b, &event_c] {
            for member in committee.members.iter().take(3) {
                let attestation = PqEventAttestation::new(
                    format!("attestation-{}-{}", event.event_id, member.member_id),
                    event,
                    &committee,
                    member.member_id.clone(),
                    self.height.saturating_add(8),
                );
                self.submit_attestation(attestation)
                    .expect("devnet attestation");
            }
            let settlement = self
                .settle_event(&event.event_id)
                .expect("devnet settlement");
            self.deliver_callback(&settlement.settlement_id)
                .expect("devnet callback");
        }
        self.redact_event(&event_b.event_id, 2)
            .expect("devnet redaction");
        self.refresh_counters();
        self.refresh_roots();
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
