use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateCrossDomainNonceSettlementResult<T> = Result<T, String>;

pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION: &str =
    "nebula-private-cross-domain-nonce-settlement-v1";
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEVNET_HEIGHT: u64 = 2_816;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-cross-domain-nonce";
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_NULLIFIER_SUITE: &str =
    "private-cross-domain-nullifier-set-v1";
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 12;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_PRIVACY_SET: u64 = 512;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 1_500_000;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_MAX_FEE_UNITS: u64 = 30_000;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_MAX_LIVE_NONCES: usize = 2_048;
pub const PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_MAX_RECEIPTS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceDomainKind {
    MoneroExit,
    PrivateContract,
    TokenBridge,
    ProofBatch,
    OracleSettlement,
    WalletSession,
    GovernanceAction,
}

impl NonceDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero_exit",
            Self::PrivateContract => "private_contract",
            Self::TokenBridge => "token_bridge",
            Self::ProofBatch => "proof_batch",
            Self::OracleSettlement => "oracle_settlement",
            Self::WalletSession => "wallet_session",
            Self::GovernanceAction => "governance_action",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::MoneroExit => 95,
            Self::TokenBridge => 90,
            Self::PrivateContract => 84,
            Self::ProofBatch => 76,
            Self::OracleSettlement => 72,
            Self::GovernanceAction => 68,
            Self::WalletSession => 56,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceStatus {
    Reserved,
    Bound,
    Settled,
    Expired,
    Challenged,
    Slashed,
}

impl NonceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Bound => "bound",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Reserved | Self::Bound | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    PendingFinality,
    Finalized,
    Replayed,
    Rejected,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingFinality => "pending_finality",
            Self::Finalized => "finalized",
            Self::Replayed => "replayed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceChallengeKind {
    ReplayNullifier,
    InvalidDomainBinding,
    MissingPqAuthorization,
    PrematureFinality,
    SponsorOverspend,
    PrivacySetTooSmall,
}

impl NonceChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayNullifier => "replay_nullifier",
            Self::InvalidDomainBinding => "invalid_domain_binding",
            Self::MissingPqAuthorization => "missing_pq_authorization",
            Self::PrematureFinality => "premature_finality",
            Self::SponsorOverspend => "sponsor_overspend",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossDomainNonceSettlementConfig {
    pub nonce_ttl_blocks: u64,
    pub finality_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub default_sponsor_budget_units: u64,
    pub max_fee_units: u64,
    pub max_live_nonces: usize,
    pub max_receipts: usize,
    pub require_dual_pq_authorization: bool,
}

impl PrivateCrossDomainNonceSettlementConfig {
    pub fn devnet() -> Self {
        Self {
            nonce_ttl_blocks: PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_TTL_BLOCKS,
            finality_delay_blocks:
                PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_FINALITY_DELAY_BLOCKS,
            challenge_window_blocks:
                PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_PRIVACY_SET,
            default_sponsor_budget_units:
                PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_fee_units: PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_MAX_FEE_UNITS,
            max_live_nonces: PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_MAX_LIVE_NONCES,
            max_receipts: PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEFAULT_MAX_RECEIPTS,
            require_dual_pq_authorization: true,
        }
    }

    pub fn validate(&self) -> PrivateCrossDomainNonceSettlementResult<()> {
        if self.nonce_ttl_blocks == 0
            || self.finality_delay_blocks == 0
            || self.challenge_window_blocks == 0
        {
            return Err("nonce settlement windows must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.default_sponsor_budget_units == 0
            || self.max_fee_units == 0
        {
            return Err("nonce settlement budget and privacy floors must be positive".to_string());
        }
        if self.max_live_nonces == 0 || self.max_receipts == 0 {
            return Err("nonce settlement capacity limits must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_domain_nonce_settlement_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "nonce_ttl_blocks": self.nonce_ttl_blocks,
            "finality_delay_blocks": self.finality_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "max_fee_units": self.max_fee_units,
            "max_live_nonces": self.max_live_nonces,
            "max_receipts": self.max_receipts,
            "require_dual_pq_authorization": self.require_dual_pq_authorization,
        })
    }

    pub fn state_root(&self) -> String {
        nonce_json_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateNonceReservation {
    pub nonce_id: String,
    pub domain_kind: NonceDomainKind,
    pub account_commitment: String,
    pub source_domain_root: String,
    pub destination_domain_root: String,
    pub nonce_commitment: String,
    pub nullifier: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub fee_cap_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: NonceStatus,
}

impl PrivateNonceReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain_kind: NonceDomainKind,
        account_commitment: &str,
        source_domain_root: &str,
        destination_domain_root: &str,
        nonce_commitment: &str,
        nullifier: &str,
        pq_authorization_root: &str,
        privacy_set_size: u64,
        fee_cap_units: u64,
        created_at_height: u64,
        config: &PrivateCrossDomainNonceSettlementConfig,
    ) -> PrivateCrossDomainNonceSettlementResult<Self> {
        if account_commitment.is_empty()
            || source_domain_root.is_empty()
            || destination_domain_root.is_empty()
            || nonce_commitment.is_empty()
            || nullifier.is_empty()
            || pq_authorization_root.is_empty()
        {
            return Err("nonce reservation commitments cannot be empty".to_string());
        }
        if privacy_set_size < config.min_privacy_set_size {
            return Err("nonce reservation privacy set below floor".to_string());
        }
        if fee_cap_units == 0 || fee_cap_units > config.max_fee_units {
            return Err("nonce reservation fee cap invalid".to_string());
        }
        let expires_at_height = created_at_height.saturating_add(config.nonce_ttl_blocks);
        let nonce_id = nonce_id(
            domain_kind,
            account_commitment,
            source_domain_root,
            destination_domain_root,
            nonce_commitment,
            nullifier,
            created_at_height,
        );
        Ok(Self {
            nonce_id,
            domain_kind,
            account_commitment: account_commitment.to_string(),
            source_domain_root: source_domain_root.to_string(),
            destination_domain_root: destination_domain_root.to_string(),
            nonce_commitment: nonce_commitment.to_string(),
            nullifier: nullifier.to_string(),
            pq_authorization_root: pq_authorization_root.to_string(),
            privacy_set_size,
            fee_cap_units,
            created_at_height,
            expires_at_height,
            status: NonceStatus::Reserved,
        })
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn validate(
        &self,
        config: &PrivateCrossDomainNonceSettlementConfig,
    ) -> PrivateCrossDomainNonceSettlementResult<()> {
        if self.nonce_id.is_empty()
            || self.account_commitment.is_empty()
            || self.source_domain_root.is_empty()
            || self.destination_domain_root.is_empty()
            || self.nonce_commitment.is_empty()
            || self.nullifier.is_empty()
            || self.pq_authorization_root.is_empty()
        {
            return Err("nonce reservation identifiers cannot be empty".to_string());
        }
        if self.created_at_height >= self.expires_at_height {
            return Err("nonce reservation ttl invalid".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("nonce reservation privacy set below floor".to_string());
        }
        if self.fee_cap_units == 0 || self.fee_cap_units > config.max_fee_units {
            return Err("nonce reservation fee cap invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_nonce_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "nonce_id": self.nonce_id,
            "domain_kind": self.domain_kind.as_str(),
            "account_commitment": self.account_commitment,
            "source_domain_root": self.source_domain_root,
            "destination_domain_root": self.destination_domain_root,
            "nonce_commitment": self.nonce_commitment,
            "nullifier": self.nullifier,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "fee_cap_units": self.fee_cap_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        nonce_json_root("NONCE-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainBindingReceipt {
    pub binding_id: String,
    pub nonce_id: String,
    pub route_root: String,
    pub l2_batch_root: String,
    pub monero_context_root: String,
    pub contract_context_root: String,
    pub bound_at_height: u64,
    pub expected_finality_height: u64,
}

impl DomainBindingReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nonce: &PrivateNonceReservation,
        route_root: &str,
        l2_batch_root: &str,
        monero_context_root: &str,
        contract_context_root: &str,
        bound_at_height: u64,
        config: &PrivateCrossDomainNonceSettlementConfig,
    ) -> PrivateCrossDomainNonceSettlementResult<Self> {
        if route_root.is_empty()
            || l2_batch_root.is_empty()
            || monero_context_root.is_empty()
            || contract_context_root.is_empty()
        {
            return Err("domain binding roots cannot be empty".to_string());
        }
        let expected_finality_height = bound_at_height.saturating_add(config.finality_delay_blocks);
        let binding_id = nonce_hash(
            "DOMAIN-BINDING-ID",
            &[
                HashPart::Str(&nonce.nonce_id),
                HashPart::Str(route_root),
                HashPart::Str(l2_batch_root),
                HashPart::Int(bound_at_height as i128),
            ],
        );
        Ok(Self {
            binding_id,
            nonce_id: nonce.nonce_id.clone(),
            route_root: route_root.to_string(),
            l2_batch_root: l2_batch_root.to_string(),
            monero_context_root: monero_context_root.to_string(),
            contract_context_root: contract_context_root.to_string(),
            bound_at_height,
            expected_finality_height,
        })
    }

    pub fn validate(&self) -> PrivateCrossDomainNonceSettlementResult<()> {
        if self.binding_id.is_empty()
            || self.nonce_id.is_empty()
            || self.route_root.is_empty()
            || self.l2_batch_root.is_empty()
            || self.monero_context_root.is_empty()
            || self.contract_context_root.is_empty()
        {
            return Err("domain binding receipt identifiers cannot be empty".to_string());
        }
        if self.bound_at_height >= self.expected_finality_height {
            return Err("domain binding finality height invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "domain_binding_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "binding_id": self.binding_id,
            "nonce_id": self.nonce_id,
            "route_root": self.route_root,
            "l2_batch_root": self.l2_batch_root,
            "monero_context_root": self.monero_context_root,
            "contract_context_root": self.contract_context_root,
            "bound_at_height": self.bound_at_height,
            "expected_finality_height": self.expected_finality_height,
        })
    }

    pub fn state_root(&self) -> String {
        nonce_json_root("DOMAIN-BINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceSettlementReceipt {
    pub receipt_id: String,
    pub nonce_id: String,
    pub binding_id: String,
    pub settlement_root: String,
    pub fee_paid_units: u64,
    pub settled_at_height: u64,
    pub status: SettlementReceiptStatus,
}

impl NonceSettlementReceipt {
    pub fn new(
        nonce_id: &str,
        binding_id: &str,
        settlement_root: &str,
        fee_paid_units: u64,
        settled_at_height: u64,
    ) -> PrivateCrossDomainNonceSettlementResult<Self> {
        if nonce_id.is_empty() || binding_id.is_empty() || settlement_root.is_empty() {
            return Err("settlement receipt identifiers cannot be empty".to_string());
        }
        if fee_paid_units == 0 {
            return Err("settlement fee must be positive".to_string());
        }
        let receipt_id = nonce_hash(
            "SETTLEMENT-RECEIPT-ID",
            &[
                HashPart::Str(nonce_id),
                HashPart::Str(binding_id),
                HashPart::Str(settlement_root),
                HashPart::Int(settled_at_height as i128),
            ],
        );
        Ok(Self {
            receipt_id,
            nonce_id: nonce_id.to_string(),
            binding_id: binding_id.to_string(),
            settlement_root: settlement_root.to_string(),
            fee_paid_units,
            settled_at_height,
            status: SettlementReceiptStatus::PendingFinality,
        })
    }

    pub fn validate(&self) -> PrivateCrossDomainNonceSettlementResult<()> {
        if self.receipt_id.is_empty()
            || self.nonce_id.is_empty()
            || self.binding_id.is_empty()
            || self.settlement_root.is_empty()
        {
            return Err("settlement receipt identifiers cannot be empty".to_string());
        }
        if self.fee_paid_units == 0 {
            return Err("settlement receipt fee invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nonce_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "nonce_id": self.nonce_id,
            "binding_id": self.binding_id,
            "settlement_root": self.settlement_root,
            "fee_paid_units": self.fee_paid_units,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        nonce_json_root("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeNonceSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeNonceSponsor {
    pub fn new(
        sponsor_commitment: &str,
        asset_id: &str,
        budget_units: u64,
        policy_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateCrossDomainNonceSettlementResult<Self> {
        if sponsor_commitment.is_empty() || asset_id.is_empty() || policy_root.is_empty() {
            return Err("nonce sponsor identifiers cannot be empty".to_string());
        }
        if budget_units == 0 || created_at_height >= expires_at_height {
            return Err("nonce sponsor budget or ttl invalid".to_string());
        }
        let sponsor_id = nonce_hash(
            "LOW-FEE-SPONSOR-ID",
            &[
                HashPart::Str(sponsor_commitment),
                HashPart::Str(asset_id),
                HashPart::Str(policy_root),
                HashPart::Int(created_at_height as i128),
            ],
        );
        Ok(Self {
            sponsor_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            asset_id: asset_id.to_string(),
            budget_units,
            spent_units: 0,
            policy_root: policy_root.to_string(),
            created_at_height,
            expires_at_height,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateCrossDomainNonceSettlementResult<()> {
        if self.sponsor_id.is_empty()
            || self.sponsor_commitment.is_empty()
            || self.asset_id.is_empty()
            || self.policy_root.is_empty()
        {
            return Err("nonce sponsor identifiers cannot be empty".to_string());
        }
        if self.budget_units == 0 || self.spent_units > self.budget_units {
            return Err("nonce sponsor budget invalid".to_string());
        }
        if self.created_at_height >= self.expires_at_height {
            return Err("nonce sponsor ttl invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_nonce_sponsor",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "policy_root": self.policy_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        nonce_json_root("LOW-FEE-SPONSOR", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceChallengeEvidence {
    pub challenge_id: String,
    pub challenge_kind: NonceChallengeKind,
    pub subject_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub bond_units: u64,
    pub slashing_ready: bool,
}

impl NonceChallengeEvidence {
    pub fn new(
        challenge_kind: NonceChallengeKind,
        subject_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        opened_at_height: u64,
        bond_units: u64,
    ) -> PrivateCrossDomainNonceSettlementResult<Self> {
        if subject_id.is_empty() || challenger_commitment.is_empty() || evidence_root.is_empty() {
            return Err("nonce challenge identifiers cannot be empty".to_string());
        }
        if bond_units == 0 {
            return Err("nonce challenge bond must be positive".to_string());
        }
        let challenge_id = nonce_hash(
            "NONCE-CHALLENGE-ID",
            &[
                HashPart::Str(challenge_kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(challenger_commitment),
                HashPart::Str(evidence_root),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Ok(Self {
            challenge_id,
            challenge_kind,
            subject_id: subject_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_at_height,
            bond_units,
            slashing_ready: false,
        })
    }

    pub fn validate(&self) -> PrivateCrossDomainNonceSettlementResult<()> {
        if self.challenge_id.is_empty()
            || self.subject_id.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("nonce challenge identifiers cannot be empty".to_string());
        }
        if self.bond_units == 0 {
            return Err("nonce challenge bond invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nonce_challenge_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "subject_id": self.subject_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "bond_units": self.bond_units,
            "slashing_ready": self.slashing_ready,
        })
    }

    pub fn state_root(&self) -> String {
        nonce_json_root("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossDomainNonceSettlementRoots {
    pub config_root: String,
    pub nonce_root: String,
    pub binding_root: String,
    pub receipt_root: String,
    pub sponsor_root: String,
    pub challenge_root: String,
    pub spent_nullifier_root: String,
}

impl PrivateCrossDomainNonceSettlementRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_domain_nonce_settlement_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "nonce_root": self.nonce_root,
            "binding_root": self.binding_root,
            "receipt_root": self.receipt_root,
            "sponsor_root": self.sponsor_root,
            "challenge_root": self.challenge_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossDomainNonceSettlementCounters {
    pub nonce_count: u64,
    pub live_nonce_count: u64,
    pub binding_count: u64,
    pub receipt_count: u64,
    pub finalized_receipt_count: u64,
    pub sponsor_count: u64,
    pub challenge_count: u64,
    pub spent_nullifier_count: u64,
    pub sponsor_available_units: u64,
}

impl PrivateCrossDomainNonceSettlementCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_domain_nonce_settlement_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "nonce_count": self.nonce_count,
            "live_nonce_count": self.live_nonce_count,
            "binding_count": self.binding_count,
            "receipt_count": self.receipt_count,
            "finalized_receipt_count": self.finalized_receipt_count,
            "sponsor_count": self.sponsor_count,
            "challenge_count": self.challenge_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "sponsor_available_units": self.sponsor_available_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossDomainNonceSettlementState {
    pub height: u64,
    pub config: PrivateCrossDomainNonceSettlementConfig,
    pub nonces: BTreeMap<String, PrivateNonceReservation>,
    pub bindings: BTreeMap<String, DomainBindingReceipt>,
    pub receipts: BTreeMap<String, NonceSettlementReceipt>,
    pub sponsors: BTreeMap<String, LowFeeNonceSponsor>,
    pub challenges: BTreeMap<String, NonceChallengeEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl PrivateCrossDomainNonceSettlementState {
    pub fn new(height: u64, config: PrivateCrossDomainNonceSettlementConfig) -> Self {
        Self {
            height,
            config,
            nonces: BTreeMap::new(),
            bindings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> PrivateCrossDomainNonceSettlementResult<Self> {
        let config = PrivateCrossDomainNonceSettlementConfig::devnet();
        let mut state = Self::new(PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_DEVNET_HEIGHT, config);
        let sponsor = LowFeeNonceSponsor::new(
            "sponsor:devnet-cross-domain-nonces",
            "wxmr-devnet",
            state.config.default_sponsor_budget_units,
            "policy:cross-domain-nonce-sponsor",
            state.height,
            state.height.saturating_add(state.config.nonce_ttl_blocks),
        )?;
        state.insert_sponsor(sponsor)?;
        let nonce = PrivateNonceReservation::new(
            NonceDomainKind::MoneroExit,
            "account:shielded:alice",
            "domain:monero-exit",
            "domain:private-contract",
            "nonce:alice:monero-exit:0",
            "nullifier:alice:monero-exit:0",
            "pq-auth:alice:cross-domain",
            state.config.min_privacy_set_size.saturating_mul(2),
            12_000,
            state.height,
            &state.config,
        )?;
        let nonce_id = state.insert_nonce(nonce)?;
        let binding = {
            let nonce = state
                .nonces
                .get(&nonce_id)
                .cloned()
                .ok_or_else(|| "devnet nonce missing after insert".to_string())?;
            DomainBindingReceipt::new(
                &nonce,
                "route:monero-exit-to-contract",
                "l2-batch:devnet:nonce-settlement",
                "monero-context:exit-output",
                "contract-context:private-vault",
                state.height.saturating_add(1),
                &state.config,
            )?
        };
        let binding_id = state.bind_nonce(binding)?;
        let receipt = NonceSettlementReceipt::new(
            &nonce_id,
            &binding_id,
            "settlement:private-vault-credit",
            12_000,
            state
                .height
                .saturating_add(state.config.finality_delay_blocks + 2),
        )?;
        state.insert_receipt(receipt)?;
        let challenge = NonceChallengeEvidence::new(
            NonceChallengeKind::ReplayNullifier,
            &nonce_id,
            "watcher:nonce-replay",
            "evidence:nonce-replay",
            state.height.saturating_add(3),
            50_000,
        )?;
        state.insert_challenge(challenge)?;
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(
        &mut self,
        next_height: u64,
    ) -> PrivateCrossDomainNonceSettlementResult<()> {
        if next_height < self.height {
            return Err("cross-domain nonce settlement height cannot decrease".to_string());
        }
        self.height = next_height;
        self.expire_stale_records();
        Ok(())
    }

    pub fn insert_nonce(
        &mut self,
        nonce: PrivateNonceReservation,
    ) -> PrivateCrossDomainNonceSettlementResult<String> {
        if self.nonces.len() >= self.config.max_live_nonces
            && !self.nonces.contains_key(&nonce.nonce_id)
        {
            return Err("cross-domain nonce capacity exceeded".to_string());
        }
        nonce.validate(&self.config)?;
        if self.spent_nullifiers.contains(&nonce.nullifier) {
            return Err("nonce nullifier already spent".to_string());
        }
        if self.nonces.contains_key(&nonce.nonce_id) {
            return Err("duplicate nonce reservation".to_string());
        }
        let id = nonce.nonce_id.clone();
        self.nonces.insert(id.clone(), nonce);
        Ok(id)
    }

    pub fn bind_nonce(
        &mut self,
        binding: DomainBindingReceipt,
    ) -> PrivateCrossDomainNonceSettlementResult<String> {
        binding.validate()?;
        let nonce = self
            .nonces
            .get_mut(&binding.nonce_id)
            .ok_or_else(|| "binding references unknown nonce".to_string())?;
        if nonce.expired_at(self.height) {
            return Err("cannot bind expired nonce".to_string());
        }
        nonce.status = NonceStatus::Bound;
        let id = binding.binding_id.clone();
        self.bindings.insert(id.clone(), binding);
        Ok(id)
    }

    pub fn insert_receipt(
        &mut self,
        receipt: NonceSettlementReceipt,
    ) -> PrivateCrossDomainNonceSettlementResult<String> {
        if self.receipts.len() >= self.config.max_receipts
            && !self.receipts.contains_key(&receipt.receipt_id)
        {
            return Err("cross-domain receipt capacity exceeded".to_string());
        }
        receipt.validate()?;
        if !self.bindings.contains_key(&receipt.binding_id) {
            return Err("receipt references unknown binding".to_string());
        }
        let nonce = self
            .nonces
            .get_mut(&receipt.nonce_id)
            .ok_or_else(|| "receipt references unknown nonce".to_string())?;
        if self.spent_nullifiers.contains(&nonce.nullifier) {
            return Err("receipt would replay spent nullifier".to_string());
        }
        self.spent_nullifiers.insert(nonce.nullifier.clone());
        nonce.status = NonceStatus::Settled;
        let id = receipt.receipt_id.clone();
        self.receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: LowFeeNonceSponsor,
    ) -> PrivateCrossDomainNonceSettlementResult<String> {
        sponsor.validate()?;
        if self.sponsors.contains_key(&sponsor.sponsor_id) {
            return Err("duplicate nonce sponsor".to_string());
        }
        let id = sponsor.sponsor_id.clone();
        self.sponsors.insert(id.clone(), sponsor);
        Ok(id)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: NonceChallengeEvidence,
    ) -> PrivateCrossDomainNonceSettlementResult<String> {
        challenge.validate()?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("duplicate nonce challenge".to_string());
        }
        let id = challenge.challenge_id.clone();
        if let Some(nonce) = self.nonces.get_mut(&challenge.subject_id) {
            nonce.status = NonceStatus::Challenged;
        }
        self.challenges.insert(id.clone(), challenge);
        Ok(id)
    }

    pub fn roots(&self) -> PrivateCrossDomainNonceSettlementRoots {
        PrivateCrossDomainNonceSettlementRoots {
            config_root: self.config.state_root(),
            nonce_root: value_root(
                "PRIVATE-XDOMAIN-NONCES",
                self.nonces
                    .values()
                    .map(PrivateNonceReservation::public_record),
            ),
            binding_root: value_root(
                "PRIVATE-XDOMAIN-BINDINGS",
                self.bindings
                    .values()
                    .map(DomainBindingReceipt::public_record),
            ),
            receipt_root: value_root(
                "PRIVATE-XDOMAIN-RECEIPTS",
                self.receipts
                    .values()
                    .map(NonceSettlementReceipt::public_record),
            ),
            sponsor_root: value_root(
                "PRIVATE-XDOMAIN-SPONSORS",
                self.sponsors
                    .values()
                    .map(LowFeeNonceSponsor::public_record),
            ),
            challenge_root: value_root(
                "PRIVATE-XDOMAIN-CHALLENGES",
                self.challenges
                    .values()
                    .map(NonceChallengeEvidence::public_record),
            ),
            spent_nullifier_root: string_set_root("PRIVATE-XDOMAIN-SPENT", &self.spent_nullifiers),
        }
    }

    pub fn counters(&self) -> PrivateCrossDomainNonceSettlementCounters {
        PrivateCrossDomainNonceSettlementCounters {
            nonce_count: self.nonces.len() as u64,
            live_nonce_count: self
                .nonces
                .values()
                .filter(|nonce| nonce.status.live())
                .count() as u64,
            binding_count: self.bindings.len() as u64,
            receipt_count: self.receipts.len() as u64,
            finalized_receipt_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.status == SettlementReceiptStatus::Finalized)
                .count() as u64,
            sponsor_count: self.sponsors.len() as u64,
            challenge_count: self.challenges.len() as u64,
            spent_nullifier_count: self.spent_nullifiers.len() as u64,
            sponsor_available_units: self
                .sponsors
                .values()
                .filter(|sponsor| !sponsor.expired_at(self.height))
                .map(LowFeeNonceSponsor::available_units)
                .sum(),
        }
    }

    pub fn live_nonce_ids(&self) -> Vec<String> {
        self.nonces
            .values()
            .filter(|nonce| nonce.status.live())
            .map(|nonce| nonce.nonce_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| !challenge.slashing_ready)
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        private_cross_domain_nonce_settlement_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_domain_nonce_settlement_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PROTOCOL_VERSION,
            "schema_version": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_SCHEMA_VERSION,
            "height": self.height,
            "hash_suite": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_HASH_SUITE,
            "pq_auth_suite": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_PQ_AUTH_SUITE,
            "nullifier_suite": PRIVATE_CROSS_DOMAIN_NONCE_SETTLEMENT_NULLIFIER_SUITE,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_nonce_ids": self.live_nonce_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
        })
    }

    pub fn validate(&self) -> PrivateCrossDomainNonceSettlementResult<()> {
        self.config.validate()?;
        if self.nonces.len() > self.config.max_live_nonces {
            return Err("nonce settlement nonce capacity exceeded".to_string());
        }
        if self.receipts.len() > self.config.max_receipts {
            return Err("nonce settlement receipt capacity exceeded".to_string());
        }
        for nonce in self.nonces.values() {
            nonce.validate(&self.config)?;
        }
        for binding in self.bindings.values() {
            binding.validate()?;
            if !self.nonces.contains_key(&binding.nonce_id) {
                return Err("binding references missing nonce".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.nonces.contains_key(&receipt.nonce_id)
                || !self.bindings.contains_key(&receipt.binding_id)
            {
                return Err("receipt references missing nonce or binding".to_string());
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(())
    }

    fn expire_stale_records(&mut self) {
        for nonce in self.nonces.values_mut() {
            if nonce.expired_at(self.height) && nonce.status.live() {
                nonce.status = NonceStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> PrivateCrossDomainNonceSettlementResult<PrivateCrossDomainNonceSettlementState> {
    PrivateCrossDomainNonceSettlementState::devnet()
}

pub fn private_cross_domain_nonce_settlement_state_root_from_record(record: &Value) -> String {
    nonce_json_root("STATE", record)
}

pub fn nonce_id(
    domain_kind: NonceDomainKind,
    account_commitment: &str,
    source_domain_root: &str,
    destination_domain_root: &str,
    nonce_commitment: &str,
    nullifier: &str,
    height: u64,
) -> String {
    nonce_hash(
        "NONCE-ID",
        &[
            HashPart::Str(domain_kind.as_str()),
            HashPart::Str(account_commitment),
            HashPart::Str(source_domain_root),
            HashPart::Str(destination_domain_root),
            HashPart::Str(nonce_commitment),
            HashPart::Str(nullifier),
            HashPart::Int(height as i128),
        ],
    )
}

fn value_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &values.into_iter().collect::<Vec<_>>())
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn nonce_json_root(domain: &str, value: &Value) -> String {
    nonce_hash(domain, &[HashPart::Json(value)])
}

fn nonce_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-DOMAIN-NONCE-SETTLEMENT:{domain}"),
        parts,
        32,
    )
}
