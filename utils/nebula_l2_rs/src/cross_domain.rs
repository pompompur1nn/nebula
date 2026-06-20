use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type CrossDomainResult<T> = Result<T, String>;

pub const CROSS_DOMAIN_PROTOCOL_VERSION: &str = "nebula-cross-domain-v1";
pub const CROSS_DOMAIN_DEFAULT_PACKET_TTL_BLOCKS: u64 = 24;
pub const CROSS_DOMAIN_DEFAULT_ACK_TTL_BLOCKS: u64 = 12;
pub const CROSS_DOMAIN_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 96;
pub const CROSS_DOMAIN_DEFAULT_LIQUIDITY_TTL_BLOCKS: u64 = 18;
pub const CROSS_DOMAIN_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const CROSS_DOMAIN_DEFAULT_MAX_PACKET_BYTES: u64 = 64 * 1024;
pub const CROSS_DOMAIN_DEFAULT_MAX_RETRY_COUNT: u64 = 3;
pub const CROSS_DOMAIN_DEFAULT_MAX_ROUTE_RISK_BPS: u64 = 2_500;
pub const CROSS_DOMAIN_DEFAULT_PRIVATE_SURCHARGE_BPS: u64 = 50;
pub const CROSS_DOMAIN_MAX_BPS: u64 = 10_000;
pub const CROSS_DOMAIN_STATUS_ACTIVE: &str = "active";
pub const CROSS_DOMAIN_STATUS_PAUSED: &str = "paused";
pub const CROSS_DOMAIN_STATUS_QUEUED: &str = "queued";
pub const CROSS_DOMAIN_STATUS_SEALED: &str = "sealed";
pub const CROSS_DOMAIN_STATUS_SENT: &str = "sent";
pub const CROSS_DOMAIN_STATUS_ACKED: &str = "acked";
pub const CROSS_DOMAIN_STATUS_SETTLED: &str = "settled";
pub const CROSS_DOMAIN_STATUS_EXPIRED: &str = "expired";
pub const CROSS_DOMAIN_STATUS_REJECTED: &str = "rejected";
pub const CROSS_DOMAIN_STATUS_QUARANTINED: &str = "quarantined";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrossDomainEndpointKind {
    Monero,
    L2,
    Contract,
    TokenRegistry,
    PrivacyPool,
    Oracle,
    ProverMarket,
    ExternalSettlement,
}

impl CrossDomainEndpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monero => "monero",
            Self::L2 => "l2",
            Self::Contract => "contract",
            Self::TokenRegistry => "token_registry",
            Self::PrivacyPool => "privacy_pool",
            Self::Oracle => "oracle",
            Self::ProverMarket => "prover_market",
            Self::ExternalSettlement => "external_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrossDomainRouteKind {
    Deposit,
    Withdrawal,
    ContractCall,
    TokenTransfer,
    LiquidityRebalance,
    OracleUpdate,
    ProofDelivery,
    GovernanceAction,
    Custom,
}

impl CrossDomainRouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::OracleUpdate => "oracle_update",
            Self::ProofDelivery => "proof_delivery",
            Self::GovernanceAction => "governance_action",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrossDomainMessageKind {
    MoneroDeposit,
    MoneroWithdrawal,
    PrivateTransfer,
    PrivateSwap,
    PublicSwap,
    ContractInvocation,
    TokenMint,
    TokenBurn,
    OraclePrice,
    ProofReceipt,
    GovernanceNotice,
}

impl CrossDomainMessageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroDeposit => "monero_deposit",
            Self::MoneroWithdrawal => "monero_withdrawal",
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::PublicSwap => "public_swap",
            Self::ContractInvocation => "contract_invocation",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::OraclePrice => "oracle_price",
            Self::ProofReceipt => "proof_receipt",
            Self::GovernanceNotice => "governance_notice",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrossDomainVisibility {
    Public,
    CommitmentOnly,
    Encrypted,
    Shielded,
}

impl CrossDomainVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::CommitmentOnly => "commitment_only",
            Self::Encrypted => "encrypted",
            Self::Shielded => "shielded",
        }
    }

    pub fn privacy_surcharge_bps(self) -> u64 {
        match self {
            Self::Public => 0,
            Self::CommitmentOnly => 10,
            Self::Encrypted => CROSS_DOMAIN_DEFAULT_PRIVATE_SURCHARGE_BPS,
            Self::Shielded => CROSS_DOMAIN_DEFAULT_PRIVATE_SURCHARGE_BPS.saturating_mul(2),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrossDomainProofKind {
    MoneroFinality,
    L2Inclusion,
    ContractExecution,
    PrivacyMembership,
    NullifierNonReplay,
    LiquidityReserve,
    OracleAttestation,
    ProverReceipt,
}

impl CrossDomainProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroFinality => "monero_finality",
            Self::L2Inclusion => "l2_inclusion",
            Self::ContractExecution => "contract_execution",
            Self::PrivacyMembership => "privacy_membership",
            Self::NullifierNonReplay => "nullifier_non_replay",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::OracleAttestation => "oracle_attestation",
            Self::ProverReceipt => "prover_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrossDomainRiskLevel {
    Low,
    Watch,
    Elevated,
    Critical,
}

impl CrossDomainRiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }

    pub fn risk_bps(self) -> u64 {
        match self {
            Self::Low => 100,
            Self::Watch => 500,
            Self::Elevated => 1_500,
            Self::Critical => 7_500,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainEndpoint {
    pub endpoint_id: String,
    pub label: String,
    pub endpoint_kind: CrossDomainEndpointKind,
    pub network: String,
    pub address_commitment: String,
    pub capability_root: String,
    pub proof_root: String,
    pub max_message_bytes: u64,
    pub finality_depth_blocks: u64,
    pub risk_level: CrossDomainRiskLevel,
    pub status: String,
}

impl CrossDomainEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        endpoint_kind: CrossDomainEndpointKind,
        network: impl Into<String>,
        address_hint: impl Into<String>,
        capabilities: &[String],
        proof_root: impl Into<String>,
        max_message_bytes: u64,
        finality_depth_blocks: u64,
        risk_level: CrossDomainRiskLevel,
    ) -> CrossDomainResult<Self> {
        let label = normalize_label(label.into());
        let network = normalize_label(network.into());
        let address_hint = address_hint.into();
        let proof_root = proof_root.into();
        ensure_non_empty(&label, "cross-domain endpoint label")?;
        ensure_non_empty(&network, "cross-domain endpoint network")?;
        ensure_non_empty(&address_hint, "cross-domain endpoint address")?;
        ensure_non_empty(&proof_root, "cross-domain endpoint proof root")?;
        ensure_positive(max_message_bytes, "cross-domain endpoint max bytes")?;
        ensure_positive(
            finality_depth_blocks,
            "cross-domain endpoint finality depth",
        )?;
        let capability_root =
            cross_domain_string_set_root("CROSS-DOMAIN-ENDPOINT-CAP", capabilities);
        let address_commitment =
            cross_domain_string_root("CROSS-DOMAIN-ENDPOINT-ADDRESS", &address_hint);
        let endpoint_id = cross_domain_endpoint_id(
            &label,
            endpoint_kind,
            &network,
            &address_commitment,
            &capability_root,
        );
        Ok(Self {
            endpoint_id,
            label,
            endpoint_kind,
            network,
            address_commitment,
            capability_root,
            proof_root,
            max_message_bytes,
            finality_depth_blocks,
            risk_level,
            status: CROSS_DOMAIN_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_endpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "label": self.label,
            "endpoint_kind": self.endpoint_kind.as_str(),
            "network": self.network,
            "address_commitment": self.address_commitment,
            "capability_root": self.capability_root,
            "proof_root": self.proof_root,
            "max_message_bytes": self.max_message_bytes,
            "finality_depth_blocks": self.finality_depth_blocks,
            "risk_level": self.risk_level.as_str(),
            "risk_bps": self.risk_level.risk_bps(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainRoute {
    pub route_id: String,
    pub label: String,
    pub route_kind: CrossDomainRouteKind,
    pub source_endpoint_id: String,
    pub destination_endpoint_id: String,
    pub fee_asset_id: String,
    pub base_fee_units: u64,
    pub per_byte_fee_units: u64,
    pub max_payload_bytes: u64,
    pub max_risk_bps: u64,
    pub privacy_required: bool,
    pub proof_requirement_root: String,
    pub status: String,
}

impl CrossDomainRoute {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        route_kind: CrossDomainRouteKind,
        source_endpoint_id: impl Into<String>,
        destination_endpoint_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        base_fee_units: u64,
        per_byte_fee_units: u64,
        max_payload_bytes: u64,
        max_risk_bps: u64,
        privacy_required: bool,
        proof_kinds: &[CrossDomainProofKind],
    ) -> CrossDomainResult<Self> {
        let label = normalize_label(label.into());
        let source_endpoint_id = source_endpoint_id.into();
        let destination_endpoint_id = destination_endpoint_id.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&label, "cross-domain route label")?;
        ensure_non_empty(&source_endpoint_id, "cross-domain route source")?;
        ensure_non_empty(&destination_endpoint_id, "cross-domain route destination")?;
        ensure_non_empty(&fee_asset_id, "cross-domain route fee asset")?;
        ensure_positive(max_payload_bytes, "cross-domain route max payload bytes")?;
        ensure_bps(max_risk_bps, "cross-domain route max risk")?;
        let proof_labels = proof_kinds
            .iter()
            .map(|proof| proof.as_str().to_string())
            .collect::<Vec<_>>();
        let proof_requirement_root =
            cross_domain_string_set_root("CROSS-DOMAIN-ROUTE-PROOF-REQ", &proof_labels);
        let route_id = cross_domain_route_id(
            &label,
            route_kind,
            &source_endpoint_id,
            &destination_endpoint_id,
            &fee_asset_id,
            &proof_requirement_root,
        );
        Ok(Self {
            route_id,
            label,
            route_kind,
            source_endpoint_id,
            destination_endpoint_id,
            fee_asset_id,
            base_fee_units,
            per_byte_fee_units,
            max_payload_bytes,
            max_risk_bps,
            privacy_required,
            proof_requirement_root,
            status: CROSS_DOMAIN_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn quote_units(&self, payload_bytes: u64, visibility: CrossDomainVisibility) -> u64 {
        let raw = self
            .base_fee_units
            .saturating_add(payload_bytes.saturating_mul(self.per_byte_fee_units));
        raw.saturating_add(mul_bps(raw, visibility.privacy_surcharge_bps()))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_route",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "route_id": self.route_id,
            "label": self.label,
            "route_kind": self.route_kind.as_str(),
            "source_endpoint_id": self.source_endpoint_id,
            "destination_endpoint_id": self.destination_endpoint_id,
            "fee_asset_id": self.fee_asset_id,
            "base_fee_units": self.base_fee_units,
            "per_byte_fee_units": self.per_byte_fee_units,
            "max_payload_bytes": self.max_payload_bytes,
            "max_risk_bps": self.max_risk_bps,
            "privacy_required": self.privacy_required,
            "proof_requirement_root": self.proof_requirement_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainRetryPolicy {
    pub policy_id: String,
    pub route_id: String,
    pub max_retries: u64,
    pub first_retry_after_blocks: u64,
    pub backoff_multiplier_bps: u64,
    pub dead_letter_after_blocks: u64,
    pub low_fee_retry_credit_units: u64,
    pub status: String,
}

impl CrossDomainRetryPolicy {
    pub fn new(
        route_id: impl Into<String>,
        max_retries: u64,
        first_retry_after_blocks: u64,
        backoff_multiplier_bps: u64,
        dead_letter_after_blocks: u64,
        low_fee_retry_credit_units: u64,
    ) -> CrossDomainResult<Self> {
        let route_id = route_id.into();
        ensure_non_empty(&route_id, "cross-domain retry policy route")?;
        ensure_positive(first_retry_after_blocks, "cross-domain first retry")?;
        ensure_positive(dead_letter_after_blocks, "cross-domain dead letter")?;
        let policy_id = cross_domain_retry_policy_id(
            &route_id,
            max_retries,
            first_retry_after_blocks,
            backoff_multiplier_bps,
            dead_letter_after_blocks,
        );
        Ok(Self {
            policy_id,
            route_id,
            max_retries,
            first_retry_after_blocks,
            backoff_multiplier_bps,
            dead_letter_after_blocks,
            low_fee_retry_credit_units,
            status: CROSS_DOMAIN_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn retry_height(&self, submitted_at_height: u64, retry_count: u64) -> u64 {
        let mut delay = self.first_retry_after_blocks;
        for _ in 0..retry_count {
            delay = delay.saturating_add(mul_bps(delay, self.backoff_multiplier_bps));
        }
        submitted_at_height.saturating_add(delay)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_retry_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "route_id": self.route_id,
            "max_retries": self.max_retries,
            "first_retry_after_blocks": self.first_retry_after_blocks,
            "backoff_multiplier_bps": self.backoff_multiplier_bps,
            "dead_letter_after_blocks": self.dead_letter_after_blocks,
            "low_fee_retry_credit_units": self.low_fee_retry_credit_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainFeeQuote {
    pub quote_id: String,
    pub route_id: String,
    pub fee_asset_id: String,
    pub payload_bytes: u64,
    pub base_fee_units: u64,
    pub privacy_surcharge_units: u64,
    pub risk_surcharge_units: u64,
    pub low_fee_credit_units: u64,
    pub total_fee_units: u64,
    pub expires_at_height: u64,
    pub quote_root: String,
}

impl CrossDomainFeeQuote {
    pub fn new(
        route: &CrossDomainRoute,
        payload_bytes: u64,
        visibility: CrossDomainVisibility,
        risk_level: CrossDomainRiskLevel,
        low_fee_credit_units: u64,
        height: u64,
    ) -> Self {
        let base_fee_units = route
            .base_fee_units
            .saturating_add(payload_bytes.saturating_mul(route.per_byte_fee_units));
        let privacy_surcharge_units = mul_bps(base_fee_units, visibility.privacy_surcharge_bps());
        let risk_surcharge_units = mul_bps(base_fee_units, risk_level.risk_bps());
        let total_fee_units = base_fee_units
            .saturating_add(privacy_surcharge_units)
            .saturating_add(risk_surcharge_units)
            .saturating_sub(low_fee_credit_units);
        let quote_root = cross_domain_payload_root(
            "CROSS-DOMAIN-FEE-QUOTE-CONTENT",
            &json!({
                "route_id": route.route_id,
                "payload_bytes": payload_bytes,
                "visibility": visibility.as_str(),
                "risk": risk_level.as_str(),
                "low_fee_credit_units": low_fee_credit_units,
                "total_fee_units": total_fee_units,
            }),
        );
        let quote_id =
            cross_domain_fee_quote_id(&route.route_id, payload_bytes, height, &quote_root);
        Self {
            quote_id,
            route_id: route.route_id.clone(),
            fee_asset_id: route.fee_asset_id.clone(),
            payload_bytes,
            base_fee_units,
            privacy_surcharge_units,
            risk_surcharge_units,
            low_fee_credit_units,
            total_fee_units,
            expires_at_height: height.saturating_add(CROSS_DOMAIN_DEFAULT_ACK_TTL_BLOCKS),
            quote_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_fee_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "route_id": self.route_id,
            "fee_asset_id": self.fee_asset_id,
            "payload_bytes": self.payload_bytes,
            "base_fee_units": self.base_fee_units,
            "privacy_surcharge_units": self.privacy_surcharge_units,
            "risk_surcharge_units": self.risk_surcharge_units,
            "low_fee_credit_units": self.low_fee_credit_units,
            "total_fee_units": self.total_fee_units,
            "expires_at_height": self.expires_at_height,
            "quote_root": self.quote_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainPrivacyEnvelope {
    pub envelope_id: String,
    pub visibility: CrossDomainVisibility,
    pub sender_commitment: String,
    pub recipient_commitment: String,
    pub route_hint_root: String,
    pub encrypted_payload_root: String,
    pub disclosure_policy_root: String,
    pub view_tag_root: String,
    pub proof_root: String,
}

impl CrossDomainPrivacyEnvelope {
    pub fn new(
        visibility: CrossDomainVisibility,
        sender_hint: &str,
        recipient_hint: &str,
        route_hints: &[String],
        payload: &Value,
        disclosure_policy: &Value,
        view_tag: &str,
        proof: &Value,
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(sender_hint, "cross-domain sender hint")?;
        ensure_non_empty(recipient_hint, "cross-domain recipient hint")?;
        let sender_commitment = cross_domain_string_root("CROSS-DOMAIN-SENDER", sender_hint);
        let recipient_commitment =
            cross_domain_string_root("CROSS-DOMAIN-RECIPIENT", recipient_hint);
        let route_hint_root = cross_domain_string_set_root("CROSS-DOMAIN-ROUTE-HINT", route_hints);
        let encrypted_payload_root =
            cross_domain_payload_root("CROSS-DOMAIN-ENCRYPTED-PAYLOAD", payload);
        let disclosure_policy_root =
            cross_domain_payload_root("CROSS-DOMAIN-DISCLOSURE-POLICY", disclosure_policy);
        let view_tag_root = cross_domain_string_root("CROSS-DOMAIN-VIEW-TAG", view_tag);
        let proof_root = cross_domain_payload_root("CROSS-DOMAIN-PRIVACY-PROOF", proof);
        let envelope_id = cross_domain_privacy_envelope_id(
            visibility,
            &sender_commitment,
            &recipient_commitment,
            &encrypted_payload_root,
            &proof_root,
        );
        Ok(Self {
            envelope_id,
            visibility,
            sender_commitment,
            recipient_commitment,
            route_hint_root,
            encrypted_payload_root,
            disclosure_policy_root,
            view_tag_root,
            proof_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_privacy_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "visibility": self.visibility.as_str(),
            "sender_commitment": self.sender_commitment,
            "recipient_commitment": self.recipient_commitment,
            "route_hint_root": self.route_hint_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "view_tag_root": self.view_tag_root,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainMessage {
    pub message_id: String,
    pub route_id: String,
    pub message_kind: CrossDomainMessageKind,
    pub visibility: CrossDomainVisibility,
    pub sender_commitment: String,
    pub recipient_commitment: String,
    pub payload_root: String,
    pub metadata_root: String,
    pub privacy_envelope_id: String,
    pub fee_quote_id: String,
    pub nonce: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl CrossDomainMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route: &CrossDomainRoute,
        message_kind: CrossDomainMessageKind,
        visibility: CrossDomainVisibility,
        privacy_envelope: &CrossDomainPrivacyEnvelope,
        fee_quote: &CrossDomainFeeQuote,
        payload: &Value,
        metadata: &Value,
        nonce: u64,
        height: u64,
    ) -> CrossDomainResult<Self> {
        if route.status != CROSS_DOMAIN_STATUS_ACTIVE {
            return Err("cross-domain route is not active".to_string());
        }
        if route.privacy_required && visibility == CrossDomainVisibility::Public {
            return Err("cross-domain route requires private visibility".to_string());
        }
        let payload_root = cross_domain_payload_root("CROSS-DOMAIN-MESSAGE-PAYLOAD", payload);
        let metadata_root = cross_domain_payload_root("CROSS-DOMAIN-MESSAGE-METADATA", metadata);
        let message_id = cross_domain_message_id(
            &route.route_id,
            message_kind,
            visibility,
            &privacy_envelope.sender_commitment,
            &privacy_envelope.recipient_commitment,
            &payload_root,
            nonce,
        );
        Ok(Self {
            message_id,
            route_id: route.route_id.clone(),
            message_kind,
            visibility,
            sender_commitment: privacy_envelope.sender_commitment.clone(),
            recipient_commitment: privacy_envelope.recipient_commitment.clone(),
            payload_root,
            metadata_root,
            privacy_envelope_id: privacy_envelope.envelope_id.clone(),
            fee_quote_id: fee_quote.quote_id.clone(),
            nonce,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(CROSS_DOMAIN_DEFAULT_PACKET_TTL_BLOCKS),
            status: CROSS_DOMAIN_STATUS_QUEUED.to_string(),
        })
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_message",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "message_id": self.message_id,
            "route_id": self.route_id,
            "message_kind": self.message_kind.as_str(),
            "visibility": self.visibility.as_str(),
            "sender_commitment": self.sender_commitment,
            "recipient_commitment": self.recipient_commitment,
            "payload_root": self.payload_root,
            "metadata_root": self.metadata_root,
            "privacy_envelope_id": self.privacy_envelope_id,
            "fee_quote_id": self.fee_quote_id,
            "nonce": self.nonce,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainProofBundle {
    pub proof_bundle_id: String,
    pub message_id: String,
    pub proof_kind_root: String,
    pub public_input_root: String,
    pub verifier_key_root: String,
    pub recursive_accumulator_root: String,
    pub attestation_root: String,
    pub proof_bytes: u64,
    pub status: String,
}

impl CrossDomainProofBundle {
    pub fn new(
        message_id: &str,
        proof_kinds: &[CrossDomainProofKind],
        public_inputs: &Value,
        verifier_key_root: &str,
        recursive_accumulator_root: &str,
        attestations: &[String],
        proof_bytes: u64,
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(message_id, "cross-domain proof bundle message")?;
        ensure_non_empty(verifier_key_root, "cross-domain verifier key root")?;
        ensure_non_empty(
            recursive_accumulator_root,
            "cross-domain recursive accumulator root",
        )?;
        ensure_positive(proof_bytes, "cross-domain proof bytes")?;
        let proof_kind_labels = proof_kinds
            .iter()
            .map(|proof| proof.as_str().to_string())
            .collect::<Vec<_>>();
        let proof_kind_root =
            cross_domain_string_set_root("CROSS-DOMAIN-PROOF-KIND", &proof_kind_labels);
        let public_input_root =
            cross_domain_payload_root("CROSS-DOMAIN-PROOF-PUBLIC-INPUT", public_inputs);
        let attestation_root =
            cross_domain_string_set_root("CROSS-DOMAIN-PROOF-ATTESTATION", attestations);
        let proof_bundle_id = cross_domain_proof_bundle_id(
            message_id,
            &proof_kind_root,
            &public_input_root,
            verifier_key_root,
            recursive_accumulator_root,
        );
        Ok(Self {
            proof_bundle_id,
            message_id: message_id.to_string(),
            proof_kind_root,
            public_input_root,
            verifier_key_root: verifier_key_root.to_string(),
            recursive_accumulator_root: recursive_accumulator_root.to_string(),
            attestation_root,
            proof_bytes,
            status: CROSS_DOMAIN_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_proof_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "proof_bundle_id": self.proof_bundle_id,
            "message_id": self.message_id,
            "proof_kind_root": self.proof_kind_root,
            "public_input_root": self.public_input_root,
            "verifier_key_root": self.verifier_key_root,
            "recursive_accumulator_root": self.recursive_accumulator_root,
            "attestation_root": self.attestation_root,
            "proof_bytes": self.proof_bytes,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainPacket {
    pub packet_id: String,
    pub route_id: String,
    pub source_endpoint_id: String,
    pub destination_endpoint_id: String,
    pub message_root: String,
    pub message_count: u64,
    pub payload_bytes: u64,
    pub proof_bundle_root: String,
    pub replay_guard_root: String,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub retry_count: u64,
    pub status: String,
}

impl CrossDomainPacket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route: &CrossDomainRoute,
        messages: &[CrossDomainMessage],
        proof_bundles: &[CrossDomainProofBundle],
        replay_guard_root: &str,
        payload_bytes: u64,
        height: u64,
    ) -> CrossDomainResult<Self> {
        if messages.is_empty() {
            return Err("cross-domain packet requires at least one message".to_string());
        }
        if payload_bytes > route.max_payload_bytes {
            return Err("cross-domain packet exceeds route payload limit".to_string());
        }
        ensure_non_empty(replay_guard_root, "cross-domain replay guard root")?;
        let message_root = cross_domain_message_root(messages);
        let proof_bundle_root = cross_domain_proof_bundle_root(proof_bundles);
        let packet_id = cross_domain_packet_id(
            &route.route_id,
            &message_root,
            &proof_bundle_root,
            replay_guard_root,
            height,
        );
        Ok(Self {
            packet_id,
            route_id: route.route_id.clone(),
            source_endpoint_id: route.source_endpoint_id.clone(),
            destination_endpoint_id: route.destination_endpoint_id.clone(),
            message_root,
            message_count: messages.len() as u64,
            payload_bytes,
            proof_bundle_root,
            replay_guard_root: replay_guard_root.to_string(),
            sealed_at_height: height,
            expires_at_height: height.saturating_add(CROSS_DOMAIN_DEFAULT_PACKET_TTL_BLOCKS),
            retry_count: 0,
            status: CROSS_DOMAIN_STATUS_SEALED.to_string(),
        })
    }

    pub fn mark_sent(&mut self) {
        self.status = CROSS_DOMAIN_STATUS_SENT.to_string();
    }

    pub fn mark_expired(&mut self) {
        self.status = CROSS_DOMAIN_STATUS_EXPIRED.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_packet",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "route_id": self.route_id,
            "source_endpoint_id": self.source_endpoint_id,
            "destination_endpoint_id": self.destination_endpoint_id,
            "message_root": self.message_root,
            "message_count": self.message_count,
            "payload_bytes": self.payload_bytes,
            "proof_bundle_root": self.proof_bundle_root,
            "replay_guard_root": self.replay_guard_root,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "retry_count": self.retry_count,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainReplayGuard {
    pub replay_guard_id: String,
    pub route_id: String,
    pub message_id: String,
    pub nullifier_root: String,
    pub nonce: u64,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl CrossDomainReplayGuard {
    pub fn new(
        route_id: &str,
        message: &CrossDomainMessage,
        height: u64,
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(route_id, "cross-domain replay guard route")?;
        let nullifier_root = cross_domain_payload_root(
            "CROSS-DOMAIN-REPLAY-NULLIFIER",
            &json!({
                "message_id": message.message_id,
                "route_id": route_id,
                "nonce": message.nonce,
                "sender": message.sender_commitment,
            }),
        );
        let replay_guard_id =
            cross_domain_replay_guard_id(route_id, &message.message_id, &nullifier_root, height);
        Ok(Self {
            replay_guard_id,
            route_id: route_id.to_string(),
            message_id: message.message_id.clone(),
            nullifier_root,
            nonce: message.nonce,
            first_seen_height: height,
            expires_at_height: height.saturating_add(CROSS_DOMAIN_DEFAULT_REPLAY_WINDOW_BLOCKS),
            status: CROSS_DOMAIN_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_replay_guard",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "replay_guard_id": self.replay_guard_id,
            "route_id": self.route_id,
            "message_id": self.message_id,
            "nullifier_root": self.nullifier_root,
            "nonce": self.nonce,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainAck {
    pub ack_id: String,
    pub packet_id: String,
    pub destination_endpoint_id: String,
    pub finality_witness_id: String,
    pub receipt_root: String,
    pub acked_at_height: u64,
    pub challenge_until_height: u64,
    pub status: String,
}

impl CrossDomainAck {
    pub fn new(
        packet: &CrossDomainPacket,
        finality_witness_id: &str,
        receipt: &Value,
        height: u64,
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(finality_witness_id, "cross-domain ack witness")?;
        let receipt_root = cross_domain_payload_root("CROSS-DOMAIN-ACK-RECEIPT", receipt);
        let ack_id = cross_domain_ack_id(
            &packet.packet_id,
            finality_witness_id,
            &receipt_root,
            height,
        );
        Ok(Self {
            ack_id,
            packet_id: packet.packet_id.clone(),
            destination_endpoint_id: packet.destination_endpoint_id.clone(),
            finality_witness_id: finality_witness_id.to_string(),
            receipt_root,
            acked_at_height: height,
            challenge_until_height: height.saturating_add(CROSS_DOMAIN_DEFAULT_ACK_TTL_BLOCKS),
            status: CROSS_DOMAIN_STATUS_ACKED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_ack",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "ack_id": self.ack_id,
            "packet_id": self.packet_id,
            "destination_endpoint_id": self.destination_endpoint_id,
            "finality_witness_id": self.finality_witness_id,
            "receipt_root": self.receipt_root,
            "acked_at_height": self.acked_at_height,
            "challenge_until_height": self.challenge_until_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainFinalityWitness {
    pub witness_id: String,
    pub endpoint_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub finality_depth_blocks: u64,
    pub observed_height: u64,
    pub finalized_height: u64,
    pub attestation_root: String,
    pub status: String,
}

impl CrossDomainFinalityWitness {
    pub fn new(
        endpoint: &CrossDomainEndpoint,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        observed_height: u64,
        attestations: &[String],
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(subject_kind, "cross-domain finality subject kind")?;
        ensure_non_empty(subject_id, "cross-domain finality subject id")?;
        ensure_non_empty(subject_root, "cross-domain finality subject root")?;
        let attestation_root =
            cross_domain_string_set_root("CROSS-DOMAIN-FINALITY-ATTESTATION", attestations);
        let finalized_height = observed_height.saturating_add(endpoint.finality_depth_blocks);
        let witness_id = cross_domain_finality_witness_id(
            &endpoint.endpoint_id,
            subject_kind,
            subject_id,
            subject_root,
            observed_height,
        );
        Ok(Self {
            witness_id,
            endpoint_id: endpoint.endpoint_id.clone(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            finality_depth_blocks: endpoint.finality_depth_blocks,
            observed_height,
            finalized_height,
            attestation_root,
            status: CROSS_DOMAIN_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_finality_witness",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "witness_id": self.witness_id,
            "endpoint_id": self.endpoint_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "finality_depth_blocks": self.finality_depth_blocks,
            "observed_height": self.observed_height,
            "finalized_height": self.finalized_height,
            "attestation_root": self.attestation_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainLiquidityReservation {
    pub reservation_id: String,
    pub route_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub fee_asset_id: String,
    pub fee_units: u64,
    pub reserve_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl CrossDomainLiquidityReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: &str,
        owner_hint: &str,
        asset_id: &str,
        amount_units: u64,
        fee_asset_id: &str,
        fee_units: u64,
        reserve_context: &Value,
        height: u64,
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(route_id, "cross-domain liquidity route")?;
        ensure_non_empty(owner_hint, "cross-domain liquidity owner")?;
        ensure_non_empty(asset_id, "cross-domain liquidity asset")?;
        ensure_positive(amount_units, "cross-domain liquidity amount")?;
        ensure_non_empty(fee_asset_id, "cross-domain liquidity fee asset")?;
        let owner_commitment = cross_domain_string_root("CROSS-DOMAIN-LIQUIDITY-OWNER", owner_hint);
        let reserve_root =
            cross_domain_payload_root("CROSS-DOMAIN-LIQUIDITY-RESERVE", reserve_context);
        let reservation_id = cross_domain_liquidity_reservation_id(
            route_id,
            &owner_commitment,
            asset_id,
            amount_units,
            &reserve_root,
            height,
        );
        Ok(Self {
            reservation_id,
            route_id: route_id.to_string(),
            owner_commitment,
            asset_id: asset_id.to_string(),
            amount_units,
            fee_asset_id: fee_asset_id.to_string(),
            fee_units,
            reserve_root,
            created_at_height: height,
            expires_at_height: height.saturating_add(CROSS_DOMAIN_DEFAULT_LIQUIDITY_TTL_BLOCKS),
            status: CROSS_DOMAIN_STATUS_QUEUED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_liquidity_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "route_id": self.route_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "fee_asset_id": self.fee_asset_id,
            "fee_units": self.fee_units,
            "reserve_root": self.reserve_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainSettlementIntent {
    pub intent_id: String,
    pub packet_id: String,
    pub route_id: String,
    pub reservation_id: String,
    pub source_asset_id: String,
    pub destination_asset_id: String,
    pub amount_bucket: u64,
    pub settlement_context_root: String,
    pub expected_finality_height: u64,
    pub status: String,
}

impl CrossDomainSettlementIntent {
    pub fn new(
        packet: &CrossDomainPacket,
        reservation_id: &str,
        source_asset_id: &str,
        destination_asset_id: &str,
        amount_units: u64,
        context: &Value,
        expected_finality_height: u64,
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(reservation_id, "cross-domain settlement reservation")?;
        ensure_non_empty(source_asset_id, "cross-domain settlement source asset")?;
        ensure_non_empty(
            destination_asset_id,
            "cross-domain settlement destination asset",
        )?;
        ensure_positive(amount_units, "cross-domain settlement amount")?;
        let amount_bucket = cross_domain_amount_bucket(amount_units);
        let settlement_context_root =
            cross_domain_payload_root("CROSS-DOMAIN-SETTLEMENT-CONTEXT", context);
        let intent_id = cross_domain_settlement_intent_id(
            &packet.packet_id,
            reservation_id,
            source_asset_id,
            destination_asset_id,
            amount_bucket,
            &settlement_context_root,
        );
        Ok(Self {
            intent_id,
            packet_id: packet.packet_id.clone(),
            route_id: packet.route_id.clone(),
            reservation_id: reservation_id.to_string(),
            source_asset_id: source_asset_id.to_string(),
            destination_asset_id: destination_asset_id.to_string(),
            amount_bucket,
            settlement_context_root,
            expected_finality_height,
            status: CROSS_DOMAIN_STATUS_QUEUED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_settlement_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "packet_id": self.packet_id,
            "route_id": self.route_id,
            "reservation_id": self.reservation_id,
            "source_asset_id": self.source_asset_id,
            "destination_asset_id": self.destination_asset_id,
            "amount_bucket": self.amount_bucket,
            "settlement_context_root": self.settlement_context_root,
            "expected_finality_height": self.expected_finality_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainSettlementReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub ack_id: String,
    pub finality_witness_id: String,
    pub outcome_root: String,
    pub fee_quote_id: String,
    pub settled_fee_units: u64,
    pub settled_at_height: u64,
    pub status: String,
}

impl CrossDomainSettlementReceipt {
    pub fn new(
        intent: &CrossDomainSettlementIntent,
        ack_id: &str,
        finality_witness_id: &str,
        outcome: &Value,
        fee_quote_id: &str,
        settled_fee_units: u64,
        height: u64,
    ) -> CrossDomainResult<Self> {
        ensure_non_empty(ack_id, "cross-domain settlement ack")?;
        ensure_non_empty(finality_witness_id, "cross-domain settlement witness")?;
        ensure_non_empty(fee_quote_id, "cross-domain settlement fee quote")?;
        let outcome_root = cross_domain_payload_root("CROSS-DOMAIN-SETTLEMENT-OUTCOME", outcome);
        let receipt_id =
            cross_domain_settlement_receipt_id(&intent.intent_id, ack_id, &outcome_root, height);
        Ok(Self {
            receipt_id,
            intent_id: intent.intent_id.clone(),
            ack_id: ack_id.to_string(),
            finality_witness_id: finality_witness_id.to_string(),
            outcome_root,
            fee_quote_id: fee_quote_id.to_string(),
            settled_fee_units,
            settled_at_height: height,
            status: CROSS_DOMAIN_STATUS_SETTLED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "ack_id": self.ack_id,
            "finality_witness_id": self.finality_witness_id,
            "outcome_root": self.outcome_root,
            "fee_quote_id": self.fee_quote_id,
            "settled_fee_units": self.settled_fee_units,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainRouteHealth {
    pub health_id: String,
    pub route_id: String,
    pub height: u64,
    pub pending_packets: u64,
    pub expired_packets: u64,
    pub acked_packets: u64,
    pub unsettled_intents: u64,
    pub replay_guard_count: u64,
    pub risk_bps: u64,
    pub status: String,
}

impl CrossDomainRouteHealth {
    pub fn new(
        route_id: &str,
        height: u64,
        pending_packets: u64,
        expired_packets: u64,
        acked_packets: u64,
        unsettled_intents: u64,
        replay_guard_count: u64,
    ) -> Self {
        let denominator = pending_packets
            .saturating_add(expired_packets)
            .saturating_add(acked_packets)
            .max(1);
        let risk_bps = ratio_bps(
            expired_packets.saturating_add(unsettled_intents),
            denominator,
        );
        let status = if risk_bps >= 5_000 {
            CROSS_DOMAIN_STATUS_QUARANTINED
        } else if risk_bps >= CROSS_DOMAIN_DEFAULT_MAX_ROUTE_RISK_BPS {
            CROSS_DOMAIN_STATUS_PAUSED
        } else {
            CROSS_DOMAIN_STATUS_ACTIVE
        }
        .to_string();
        let health_id = cross_domain_route_health_id(route_id, height, risk_bps);
        Self {
            health_id,
            route_id: route_id.to_string(),
            height,
            pending_packets,
            expired_packets,
            acked_packets,
            unsettled_intents,
            replay_guard_count,
            risk_bps,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_domain_route_health",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "health_id": self.health_id,
            "route_id": self.route_id,
            "height": self.height,
            "pending_packets": self.pending_packets,
            "expired_packets": self.expired_packets,
            "acked_packets": self.acked_packets,
            "unsettled_intents": self.unsettled_intents,
            "replay_guard_count": self.replay_guard_count,
            "risk_bps": self.risk_bps,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossDomainState {
    pub height: u64,
    pub nonce: u64,
    pub endpoints: BTreeMap<String, CrossDomainEndpoint>,
    pub routes: BTreeMap<String, CrossDomainRoute>,
    pub retry_policies: BTreeMap<String, CrossDomainRetryPolicy>,
    pub fee_quotes: BTreeMap<String, CrossDomainFeeQuote>,
    pub privacy_envelopes: BTreeMap<String, CrossDomainPrivacyEnvelope>,
    pub messages: BTreeMap<String, CrossDomainMessage>,
    pub proof_bundles: BTreeMap<String, CrossDomainProofBundle>,
    pub packets: BTreeMap<String, CrossDomainPacket>,
    pub replay_guards: BTreeMap<String, CrossDomainReplayGuard>,
    pub acknowledgements: BTreeMap<String, CrossDomainAck>,
    pub finality_witnesses: BTreeMap<String, CrossDomainFinalityWitness>,
    pub liquidity_reservations: BTreeMap<String, CrossDomainLiquidityReservation>,
    pub settlement_intents: BTreeMap<String, CrossDomainSettlementIntent>,
    pub settlement_receipts: BTreeMap<String, CrossDomainSettlementReceipt>,
    pub route_health: BTreeMap<String, CrossDomainRouteHealth>,
}

impl CrossDomainState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> CrossDomainResult<Self> {
        let mut state = Self::new();
        state.height = 1;

        let monero = CrossDomainEndpoint::new(
            "monero-devnet",
            CrossDomainEndpointKind::Monero,
            "monero-devnet",
            "devnet-monero-bridge-wallet",
            &[
                "deposit_observation".to_string(),
                "withdrawal_release".to_string(),
                "reserve_report".to_string(),
            ],
            &cross_domain_string_root("CROSS-DOMAIN-DEVNET-ENDPOINT-PROOF", "monero"),
            CROSS_DOMAIN_DEFAULT_MAX_PACKET_BYTES,
            10,
            CrossDomainRiskLevel::Watch,
        )?;
        let l2 = CrossDomainEndpoint::new(
            "nebula-l2",
            CrossDomainEndpointKind::L2,
            "nebula-l2-devnet",
            "devnet-l2-state-root",
            &[
                "fast_finality".to_string(),
                "private_mempool".to_string(),
                "contract_execution".to_string(),
            ],
            &cross_domain_string_root("CROSS-DOMAIN-DEVNET-ENDPOINT-PROOF", "l2"),
            CROSS_DOMAIN_DEFAULT_MAX_PACKET_BYTES,
            2,
            CrossDomainRiskLevel::Low,
        )?;
        let privacy = CrossDomainEndpoint::new(
            "privacy-pool",
            CrossDomainEndpointKind::PrivacyPool,
            "nebula-l2-devnet",
            "devnet-privacy-pool-root",
            &[
                "membership".to_string(),
                "selective_disclosure".to_string(),
                "nullifier_registry".to_string(),
            ],
            &cross_domain_string_root("CROSS-DOMAIN-DEVNET-ENDPOINT-PROOF", "privacy"),
            CROSS_DOMAIN_DEFAULT_MAX_PACKET_BYTES / 2,
            2,
            CrossDomainRiskLevel::Low,
        )?;
        let contract = CrossDomainEndpoint::new(
            "contract-vm",
            CrossDomainEndpointKind::Contract,
            "nebula-l2-devnet",
            "devnet-contract-vm-root",
            &[
                "wasm_call".to_string(),
                "host_receipt".to_string(),
                "storage_overlay".to_string(),
            ],
            &cross_domain_string_root("CROSS-DOMAIN-DEVNET-ENDPOINT-PROOF", "contract"),
            CROSS_DOMAIN_DEFAULT_MAX_PACKET_BYTES / 2,
            2,
            CrossDomainRiskLevel::Watch,
        )?;

        let monero_id = state.insert_endpoint(monero)?;
        let l2_id = state.insert_endpoint(l2)?;
        let privacy_id = state.insert_endpoint(privacy)?;
        let contract_id = state.insert_endpoint(contract)?;

        let deposit_route = CrossDomainRoute::new(
            "monero deposit to l2",
            CrossDomainRouteKind::Deposit,
            &monero_id,
            &l2_id,
            CROSS_DOMAIN_DEFAULT_FEE_ASSET_ID,
            5,
            1,
            16 * 1024,
            2_500,
            false,
            &[
                CrossDomainProofKind::MoneroFinality,
                CrossDomainProofKind::L2Inclusion,
            ],
        )?;
        let withdrawal_route = CrossDomainRoute::new(
            "private l2 withdrawal to monero",
            CrossDomainRouteKind::Withdrawal,
            &privacy_id,
            &monero_id,
            CROSS_DOMAIN_DEFAULT_FEE_ASSET_ID,
            8,
            1,
            32 * 1024,
            2_500,
            true,
            &[
                CrossDomainProofKind::PrivacyMembership,
                CrossDomainProofKind::NullifierNonReplay,
                CrossDomainProofKind::LiquidityReserve,
            ],
        )?;
        let contract_route = CrossDomainRoute::new(
            "private contract call",
            CrossDomainRouteKind::ContractCall,
            &privacy_id,
            &contract_id,
            CROSS_DOMAIN_DEFAULT_FEE_ASSET_ID,
            6,
            2,
            24 * 1024,
            3_000,
            true,
            &[
                CrossDomainProofKind::PrivacyMembership,
                CrossDomainProofKind::ContractExecution,
            ],
        )?;
        let deposit_route_id = state.insert_route(deposit_route)?;
        let withdrawal_route_id = state.insert_route(withdrawal_route)?;
        let contract_route_id = state.insert_route(contract_route)?;

        for route_id in [
            deposit_route_id.clone(),
            withdrawal_route_id.clone(),
            contract_route_id.clone(),
        ] {
            let policy = CrossDomainRetryPolicy::new(
                route_id,
                CROSS_DOMAIN_DEFAULT_MAX_RETRY_COUNT,
                2,
                1_000,
                CROSS_DOMAIN_DEFAULT_PACKET_TTL_BLOCKS,
                2,
            )?;
            state.insert_retry_policy(policy)?;
        }

        let deposit = state.enqueue_message(
            &deposit_route_id,
            CrossDomainMessageKind::MoneroDeposit,
            CrossDomainVisibility::CommitmentOnly,
            "devnet-monero-depositor",
            "devnet-l2-recipient",
            &json!({"txid": "devnet-monero-deposit-0", "amount_bucket": 100_000}),
            &json!({"source": "monero_watch", "purpose": "mint_wxmr"}),
            &["monero_deposit".to_string()],
            1,
        )?;
        let withdrawal = state.enqueue_message(
            &withdrawal_route_id,
            CrossDomainMessageKind::MoneroWithdrawal,
            CrossDomainVisibility::Shielded,
            "devnet-private-note-owner",
            "devnet-monero-withdrawal-recipient",
            &json!({"nullifier": "devnet-nullifier-0", "amount_bucket": 100_000}),
            &json!({"source": "privacy_pool", "purpose": "release_xmr"}),
            &["private_withdrawal".to_string(), "low_fee".to_string()],
            4,
        )?;
        let contract_call = state.enqueue_message(
            &contract_route_id,
            CrossDomainMessageKind::ContractInvocation,
            CrossDomainVisibility::Encrypted,
            "devnet-defi-user",
            "devnet-amm-contract",
            &json!({"method": "swap_exact_in", "asset_pair": "wxmr/usdd"}),
            &json!({"source": "private_orderflow", "purpose": "defi"}),
            &["private_defi".to_string()],
            3,
        )?;

        state.attach_proof_bundle(
            &deposit.message_id,
            &[
                CrossDomainProofKind::MoneroFinality,
                CrossDomainProofKind::L2Inclusion,
            ],
            &json!({"deposit_event_root": deposit.payload_root}),
            "devnet-monero-verifier-key",
            "devnet-recursive-root-0",
            &["observer-a".to_string(), "observer-b".to_string()],
            2_048,
        )?;
        state.attach_proof_bundle(
            &withdrawal.message_id,
            &[
                CrossDomainProofKind::PrivacyMembership,
                CrossDomainProofKind::NullifierNonReplay,
                CrossDomainProofKind::LiquidityReserve,
            ],
            &json!({"withdrawal_event_root": withdrawal.payload_root}),
            "devnet-withdrawal-verifier-key",
            "devnet-recursive-root-1",
            &[
                "privacy-auditor-a".to_string(),
                "privacy-auditor-b".to_string(),
            ],
            4_096,
        )?;
        state.attach_proof_bundle(
            &contract_call.message_id,
            &[
                CrossDomainProofKind::PrivacyMembership,
                CrossDomainProofKind::ContractExecution,
            ],
            &json!({"contract_call_root": contract_call.payload_root}),
            "devnet-contract-verifier-key",
            "devnet-recursive-root-2",
            &["vm-attestor-a".to_string(), "vm-attestor-b".to_string()],
            3_072,
        )?;

        let reservation = state.reserve_liquidity(
            &withdrawal_route_id,
            "devnet-withdrawal-owner",
            "wxmr-devnet",
            100_000,
            CROSS_DOMAIN_DEFAULT_FEE_ASSET_ID,
            4,
            &json!({"reserve_lane": "delayed_release", "bucket": "100k"}),
        )?;
        let packet = state.seal_packet(
            &withdrawal_route_id,
            &[withdrawal.message_id.clone()],
            8_192,
        )?;
        let witness = state.observe_finality(
            &monero_id,
            "monero_withdrawal_packet",
            &packet.packet_id,
            &packet.packet_id,
            &[
                "monero-observer-a".to_string(),
                "monero-observer-b".to_string(),
            ],
        )?;
        let ack = state.ack_packet(
            &packet.packet_id,
            &witness.witness_id,
            &json!({"monero_release": "devnet-release-tx-0"}),
        )?;
        let intent = state.create_settlement_intent(
            &packet.packet_id,
            &reservation.reservation_id,
            "wxmr-devnet",
            "xmr-devnet",
            100_000,
            &json!({"monero_release_root": ack.receipt_root}),
            witness.finalized_height,
        )?;
        state.settle_intent(
            &intent.intent_id,
            &ack.ack_id,
            &witness.witness_id,
            &json!({"released": true, "route": "privacy_pool_to_monero"}),
            &withdrawal.fee_quote_id,
            7,
        )?;

        state.refresh_route_health();
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for message in self.messages.values_mut() {
            if message.is_expired(height) && message.status == CROSS_DOMAIN_STATUS_QUEUED {
                message.status = CROSS_DOMAIN_STATUS_EXPIRED.to_string();
            }
        }
        for packet in self.packets.values_mut() {
            if height > packet.expires_at_height
                && packet.status != CROSS_DOMAIN_STATUS_ACKED
                && packet.status != CROSS_DOMAIN_STATUS_SETTLED
            {
                packet.mark_expired();
            }
        }
        for reservation in self.liquidity_reservations.values_mut() {
            if height > reservation.expires_at_height
                && reservation.status == CROSS_DOMAIN_STATUS_QUEUED
            {
                reservation.status = CROSS_DOMAIN_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_endpoint(&mut self, endpoint: CrossDomainEndpoint) -> CrossDomainResult<String> {
        if self
            .endpoints
            .values()
            .any(|existing| existing.label == endpoint.label)
        {
            return Err("cross-domain endpoint label already exists".to_string());
        }
        let endpoint_id = endpoint.endpoint_id.clone();
        self.endpoints.insert(endpoint_id.clone(), endpoint);
        Ok(endpoint_id)
    }

    pub fn insert_route(&mut self, route: CrossDomainRoute) -> CrossDomainResult<String> {
        if !self.endpoints.contains_key(&route.source_endpoint_id)
            || !self.endpoints.contains_key(&route.destination_endpoint_id)
        {
            return Err("cross-domain route endpoint missing".to_string());
        }
        let route_id = route.route_id.clone();
        self.routes.insert(route_id.clone(), route);
        Ok(route_id)
    }

    pub fn insert_retry_policy(
        &mut self,
        policy: CrossDomainRetryPolicy,
    ) -> CrossDomainResult<String> {
        if !self.routes.contains_key(&policy.route_id) {
            return Err("cross-domain retry policy route missing".to_string());
        }
        let policy_id = policy.policy_id.clone();
        self.retry_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_message(
        &mut self,
        route_id: &str,
        message_kind: CrossDomainMessageKind,
        visibility: CrossDomainVisibility,
        sender_hint: &str,
        recipient_hint: &str,
        payload: &Value,
        metadata: &Value,
        route_hints: &[String],
        low_fee_credit_units: u64,
    ) -> CrossDomainResult<CrossDomainMessage> {
        let route = self
            .routes
            .get(route_id)
            .cloned()
            .ok_or_else(|| "cross-domain route missing".to_string())?;
        let payload_bytes = json_size(payload);
        if payload_bytes > route.max_payload_bytes {
            return Err("cross-domain message payload exceeds route limit".to_string());
        }
        let source = self
            .endpoints
            .get(&route.source_endpoint_id)
            .ok_or_else(|| "cross-domain source endpoint missing".to_string())?;
        let destination = self
            .endpoints
            .get(&route.destination_endpoint_id)
            .ok_or_else(|| "cross-domain destination endpoint missing".to_string())?;
        let risk_level = if source.risk_level.risk_bps() >= destination.risk_level.risk_bps() {
            source.risk_level
        } else {
            destination.risk_level
        };
        if risk_level.risk_bps() > route.max_risk_bps {
            return Err("cross-domain route risk limit exceeded".to_string());
        }
        let envelope = CrossDomainPrivacyEnvelope::new(
            visibility,
            sender_hint,
            recipient_hint,
            route_hints,
            payload,
            metadata,
            "devnet-view-tag",
            &json!({"proof": "privacy-envelope-root-only"}),
        )?;
        let quote = CrossDomainFeeQuote::new(
            &route,
            payload_bytes,
            visibility,
            risk_level,
            low_fee_credit_units,
            self.height,
        );
        let nonce = self.next_nonce();
        let message = CrossDomainMessage::new(
            &route,
            message_kind,
            visibility,
            &envelope,
            &quote,
            payload,
            metadata,
            nonce,
            self.height,
        )?;
        self.privacy_envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        self.fee_quotes.insert(quote.quote_id.clone(), quote);
        self.messages
            .insert(message.message_id.clone(), message.clone());
        Ok(message)
    }

    pub fn attach_proof_bundle(
        &mut self,
        message_id: &str,
        proof_kinds: &[CrossDomainProofKind],
        public_inputs: &Value,
        verifier_key_root: &str,
        recursive_accumulator_root: &str,
        attestations: &[String],
        proof_bytes: u64,
    ) -> CrossDomainResult<CrossDomainProofBundle> {
        if !self.messages.contains_key(message_id) {
            return Err("cross-domain proof references missing message".to_string());
        }
        let bundle = CrossDomainProofBundle::new(
            message_id,
            proof_kinds,
            public_inputs,
            verifier_key_root,
            recursive_accumulator_root,
            attestations,
            proof_bytes,
        )?;
        self.proof_bundles
            .insert(bundle.proof_bundle_id.clone(), bundle.clone());
        Ok(bundle)
    }

    pub fn reserve_liquidity(
        &mut self,
        route_id: &str,
        owner_hint: &str,
        asset_id: &str,
        amount_units: u64,
        fee_asset_id: &str,
        fee_units: u64,
        reserve_context: &Value,
    ) -> CrossDomainResult<CrossDomainLiquidityReservation> {
        if !self.routes.contains_key(route_id) {
            return Err("cross-domain liquidity route missing".to_string());
        }
        let reservation = CrossDomainLiquidityReservation::new(
            route_id,
            owner_hint,
            asset_id,
            amount_units,
            fee_asset_id,
            fee_units,
            reserve_context,
            self.height,
        )?;
        self.liquidity_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        Ok(reservation)
    }

    pub fn seal_packet(
        &mut self,
        route_id: &str,
        message_ids: &[String],
        payload_bytes: u64,
    ) -> CrossDomainResult<CrossDomainPacket> {
        let route = self
            .routes
            .get(route_id)
            .cloned()
            .ok_or_else(|| "cross-domain packet route missing".to_string())?;
        let mut messages = Vec::new();
        let mut replay_guards = Vec::new();
        for message_id in message_ids {
            let message = self
                .messages
                .get(message_id)
                .cloned()
                .ok_or_else(|| "cross-domain packet message missing".to_string())?;
            if message.route_id != route_id {
                return Err("cross-domain packet message route mismatch".to_string());
            }
            let guard = CrossDomainReplayGuard::new(route_id, &message, self.height)?;
            replay_guards.push(guard.clone());
            self.replay_guards
                .insert(guard.replay_guard_id.clone(), guard);
            messages.push(message);
        }
        let proof_bundles = self
            .proof_bundles
            .values()
            .filter(|bundle| {
                message_ids
                    .iter()
                    .any(|message_id| message_id == &bundle.message_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let replay_guard_root = cross_domain_replay_guard_root(&replay_guards);
        let mut packet = CrossDomainPacket::new(
            &route,
            &messages,
            &proof_bundles,
            &replay_guard_root,
            payload_bytes,
            self.height,
        )?;
        packet.mark_sent();
        for message in messages {
            if let Some(stored) = self.messages.get_mut(&message.message_id) {
                stored.status = CROSS_DOMAIN_STATUS_SENT.to_string();
            }
        }
        self.packets
            .insert(packet.packet_id.clone(), packet.clone());
        Ok(packet)
    }

    pub fn observe_finality(
        &mut self,
        endpoint_id: &str,
        subject_kind: &str,
        subject_id: &str,
        subject_root_hint: &str,
        attestations: &[String],
    ) -> CrossDomainResult<CrossDomainFinalityWitness> {
        let endpoint = self
            .endpoints
            .get(endpoint_id)
            .cloned()
            .ok_or_else(|| "cross-domain finality endpoint missing".to_string())?;
        let subject_root =
            cross_domain_string_root("CROSS-DOMAIN-FINALITY-SUBJECT", subject_root_hint);
        let witness = CrossDomainFinalityWitness::new(
            &endpoint,
            subject_kind,
            subject_id,
            &subject_root,
            self.height,
            attestations,
        )?;
        self.finality_witnesses
            .insert(witness.witness_id.clone(), witness.clone());
        Ok(witness)
    }

    pub fn ack_packet(
        &mut self,
        packet_id: &str,
        finality_witness_id: &str,
        receipt: &Value,
    ) -> CrossDomainResult<CrossDomainAck> {
        let packet = self
            .packets
            .get(packet_id)
            .cloned()
            .ok_or_else(|| "cross-domain ack packet missing".to_string())?;
        if !self.finality_witnesses.contains_key(finality_witness_id) {
            return Err("cross-domain ack witness missing".to_string());
        }
        let ack = CrossDomainAck::new(&packet, finality_witness_id, receipt, self.height)?;
        if let Some(stored) = self.packets.get_mut(packet_id) {
            stored.status = CROSS_DOMAIN_STATUS_ACKED.to_string();
        }
        self.acknowledgements
            .insert(ack.ack_id.clone(), ack.clone());
        Ok(ack)
    }

    pub fn create_settlement_intent(
        &mut self,
        packet_id: &str,
        reservation_id: &str,
        source_asset_id: &str,
        destination_asset_id: &str,
        amount_units: u64,
        context: &Value,
        expected_finality_height: u64,
    ) -> CrossDomainResult<CrossDomainSettlementIntent> {
        let packet = self
            .packets
            .get(packet_id)
            .cloned()
            .ok_or_else(|| "cross-domain settlement packet missing".to_string())?;
        if !self.liquidity_reservations.contains_key(reservation_id) {
            return Err("cross-domain settlement reservation missing".to_string());
        }
        let intent = CrossDomainSettlementIntent::new(
            &packet,
            reservation_id,
            source_asset_id,
            destination_asset_id,
            amount_units,
            context,
            expected_finality_height,
        )?;
        self.settlement_intents
            .insert(intent.intent_id.clone(), intent.clone());
        Ok(intent)
    }

    pub fn settle_intent(
        &mut self,
        intent_id: &str,
        ack_id: &str,
        finality_witness_id: &str,
        outcome: &Value,
        fee_quote_id: &str,
        settled_fee_units: u64,
    ) -> CrossDomainResult<CrossDomainSettlementReceipt> {
        let intent = self
            .settlement_intents
            .get(intent_id)
            .cloned()
            .ok_or_else(|| "cross-domain settlement intent missing".to_string())?;
        if !self.acknowledgements.contains_key(ack_id) {
            return Err("cross-domain settlement ack missing".to_string());
        }
        if !self.finality_witnesses.contains_key(finality_witness_id) {
            return Err("cross-domain settlement witness missing".to_string());
        }
        if !self.fee_quotes.contains_key(fee_quote_id) {
            return Err("cross-domain settlement fee quote missing".to_string());
        }
        let receipt = CrossDomainSettlementReceipt::new(
            &intent,
            ack_id,
            finality_witness_id,
            outcome,
            fee_quote_id,
            settled_fee_units,
            self.height,
        )?;
        if let Some(stored) = self.settlement_intents.get_mut(intent_id) {
            stored.status = CROSS_DOMAIN_STATUS_SETTLED.to_string();
        }
        if let Some(reservation) = self.liquidity_reservations.get_mut(&intent.reservation_id) {
            reservation.status = CROSS_DOMAIN_STATUS_SETTLED.to_string();
        }
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn refresh_route_health(&mut self) -> Vec<CrossDomainRouteHealth> {
        let mut records = Vec::new();
        for route_id in self.routes.keys().cloned().collect::<Vec<_>>() {
            let pending_packets = self
                .packets
                .values()
                .filter(|packet| {
                    packet.route_id == route_id
                        && matches!(
                            packet.status.as_str(),
                            CROSS_DOMAIN_STATUS_SEALED | CROSS_DOMAIN_STATUS_SENT
                        )
                })
                .count() as u64;
            let expired_packets = self
                .packets
                .values()
                .filter(|packet| {
                    packet.route_id == route_id && packet.status == CROSS_DOMAIN_STATUS_EXPIRED
                })
                .count() as u64;
            let acked_packets = self
                .packets
                .values()
                .filter(|packet| {
                    packet.route_id == route_id
                        && matches!(
                            packet.status.as_str(),
                            CROSS_DOMAIN_STATUS_ACKED | CROSS_DOMAIN_STATUS_SETTLED
                        )
                })
                .count() as u64;
            let unsettled_intents = self
                .settlement_intents
                .values()
                .filter(|intent| {
                    intent.route_id == route_id && intent.status != CROSS_DOMAIN_STATUS_SETTLED
                })
                .count() as u64;
            let replay_guard_count = self
                .replay_guards
                .values()
                .filter(|guard| guard.route_id == route_id)
                .count() as u64;
            let health = CrossDomainRouteHealth::new(
                &route_id,
                self.height,
                pending_packets,
                expired_packets,
                acked_packets,
                unsettled_intents,
                replay_guard_count,
            );
            if let Some(route) = self.routes.get_mut(&route_id) {
                route.status = health.status.clone();
            }
            self.route_health
                .insert(health.health_id.clone(), health.clone());
            records.push(health);
        }
        records
    }

    pub fn endpoint_root(&self) -> String {
        cross_domain_endpoint_root(&self.endpoints.values().cloned().collect::<Vec<_>>())
    }

    pub fn route_root(&self) -> String {
        cross_domain_route_root(&self.routes.values().cloned().collect::<Vec<_>>())
    }

    pub fn retry_policy_root(&self) -> String {
        cross_domain_retry_policy_root(&self.retry_policies.values().cloned().collect::<Vec<_>>())
    }

    pub fn fee_quote_root(&self) -> String {
        cross_domain_fee_quote_root(&self.fee_quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn privacy_envelope_root(&self) -> String {
        cross_domain_privacy_envelope_root(
            &self.privacy_envelopes.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn message_root(&self) -> String {
        cross_domain_message_root(&self.messages.values().cloned().collect::<Vec<_>>())
    }

    pub fn proof_bundle_root(&self) -> String {
        cross_domain_proof_bundle_root(&self.proof_bundles.values().cloned().collect::<Vec<_>>())
    }

    pub fn packet_root(&self) -> String {
        cross_domain_packet_root(&self.packets.values().cloned().collect::<Vec<_>>())
    }

    pub fn replay_guard_root(&self) -> String {
        cross_domain_replay_guard_root(&self.replay_guards.values().cloned().collect::<Vec<_>>())
    }

    pub fn acknowledgement_root(&self) -> String {
        cross_domain_ack_root(&self.acknowledgements.values().cloned().collect::<Vec<_>>())
    }

    pub fn finality_witness_root(&self) -> String {
        cross_domain_finality_witness_root(
            &self
                .finality_witnesses
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidity_reservation_root(&self) -> String {
        cross_domain_liquidity_reservation_root(
            &self
                .liquidity_reservations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_intent_root(&self) -> String {
        cross_domain_settlement_intent_root(
            &self
                .settlement_intents
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        cross_domain_settlement_receipt_root(
            &self
                .settlement_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn route_health_root(&self) -> String {
        cross_domain_route_health_root(&self.route_health.values().cloned().collect::<Vec<_>>())
    }

    pub fn state_root(&self) -> String {
        cross_domain_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("cross-domain state public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "cross_domain_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_DOMAIN_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "endpoint_root": self.endpoint_root(),
            "route_root": self.route_root(),
            "retry_policy_root": self.retry_policy_root(),
            "fee_quote_root": self.fee_quote_root(),
            "privacy_envelope_root": self.privacy_envelope_root(),
            "message_root": self.message_root(),
            "proof_bundle_root": self.proof_bundle_root(),
            "packet_root": self.packet_root(),
            "replay_guard_root": self.replay_guard_root(),
            "acknowledgement_root": self.acknowledgement_root(),
            "finality_witness_root": self.finality_witness_root(),
            "liquidity_reservation_root": self.liquidity_reservation_root(),
            "settlement_intent_root": self.settlement_intent_root(),
            "settlement_receipt_root": self.settlement_receipt_root(),
            "route_health_root": self.route_health_root(),
            "endpoint_count": self.endpoints.len() as u64,
            "route_count": self.routes.len() as u64,
            "message_count": self.messages.len() as u64,
            "packet_count": self.packets.len() as u64,
            "replay_guard_count": self.replay_guards.len() as u64,
            "settlement_receipt_count": self.settlement_receipts.len() as u64,
            "active_route_count": self.routes.values().filter(|route| route.status == CROSS_DOMAIN_STATUS_ACTIVE).count() as u64,
        })
    }
}

pub fn cross_domain_endpoint_id(
    label: &str,
    endpoint_kind: CrossDomainEndpointKind,
    network: &str,
    address_commitment: &str,
    capability_root: &str,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-ENDPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(endpoint_kind.as_str()),
            HashPart::Str(network),
            HashPart::Str(address_commitment),
            HashPart::Str(capability_root),
        ],
        32,
    )
}

pub fn cross_domain_route_id(
    label: &str,
    route_kind: CrossDomainRouteKind,
    source_endpoint_id: &str,
    destination_endpoint_id: &str,
    fee_asset_id: &str,
    proof_requirement_root: &str,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(route_kind.as_str()),
            HashPart::Str(source_endpoint_id),
            HashPart::Str(destination_endpoint_id),
            HashPart::Str(fee_asset_id),
            HashPart::Str(proof_requirement_root),
        ],
        32,
    )
}

pub fn cross_domain_retry_policy_id(
    route_id: &str,
    max_retries: u64,
    first_retry_after_blocks: u64,
    backoff_multiplier_bps: u64,
    dead_letter_after_blocks: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-RETRY-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Int(max_retries as i128),
            HashPart::Int(first_retry_after_blocks as i128),
            HashPart::Int(backoff_multiplier_bps as i128),
            HashPart::Int(dead_letter_after_blocks as i128),
        ],
        32,
    )
}

pub fn cross_domain_fee_quote_id(
    route_id: &str,
    payload_bytes: u64,
    height: u64,
    quote_root: &str,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-FEE-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Int(payload_bytes as i128),
            HashPart::Int(height as i128),
            HashPart::Str(quote_root),
        ],
        32,
    )
}

pub fn cross_domain_privacy_envelope_id(
    visibility: CrossDomainVisibility,
    sender_commitment: &str,
    recipient_commitment: &str,
    encrypted_payload_root: &str,
    proof_root: &str,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-PRIVACY-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(visibility.as_str()),
            HashPart::Str(sender_commitment),
            HashPart::Str(recipient_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn cross_domain_message_id(
    route_id: &str,
    message_kind: CrossDomainMessageKind,
    visibility: CrossDomainVisibility,
    sender_commitment: &str,
    recipient_commitment: &str,
    payload_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-MESSAGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(message_kind.as_str()),
            HashPart::Str(visibility.as_str()),
            HashPart::Str(sender_commitment),
            HashPart::Str(recipient_commitment),
            HashPart::Str(payload_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn cross_domain_proof_bundle_id(
    message_id: &str,
    proof_kind_root: &str,
    public_input_root: &str,
    verifier_key_root: &str,
    recursive_accumulator_root: &str,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-PROOF-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(message_id),
            HashPart::Str(proof_kind_root),
            HashPart::Str(public_input_root),
            HashPart::Str(verifier_key_root),
            HashPart::Str(recursive_accumulator_root),
        ],
        32,
    )
}

pub fn cross_domain_packet_id(
    route_id: &str,
    message_root: &str,
    proof_bundle_root: &str,
    replay_guard_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(message_root),
            HashPart::Str(proof_bundle_root),
            HashPart::Str(replay_guard_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn cross_domain_replay_guard_id(
    route_id: &str,
    message_id: &str,
    nullifier_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-REPLAY-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(message_id),
            HashPart::Str(nullifier_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn cross_domain_ack_id(
    packet_id: &str,
    finality_witness_id: &str,
    receipt_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-ACK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(finality_witness_id),
            HashPart::Str(receipt_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn cross_domain_finality_witness_id(
    endpoint_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    observed_height: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-FINALITY-WITNESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(endpoint_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(observed_height as i128),
        ],
        32,
    )
}

pub fn cross_domain_liquidity_reservation_id(
    route_id: &str,
    owner_commitment: &str,
    asset_id: &str,
    amount_units: u64,
    reserve_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-LIQUIDITY-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Str(reserve_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn cross_domain_settlement_intent_id(
    packet_id: &str,
    reservation_id: &str,
    source_asset_id: &str,
    destination_asset_id: &str,
    amount_bucket: u64,
    settlement_context_root: &str,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-SETTLEMENT-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(reservation_id),
            HashPart::Str(source_asset_id),
            HashPart::Str(destination_asset_id),
            HashPart::Int(amount_bucket as i128),
            HashPart::Str(settlement_context_root),
        ],
        32,
    )
}

pub fn cross_domain_settlement_receipt_id(
    intent_id: &str,
    ack_id: &str,
    outcome_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "CROSS-DOMAIN-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(ack_id),
            HashPart::Str(outcome_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn cross_domain_route_health_id(route_id: &str, height: u64, risk_bps: u64) -> String {
    domain_hash(
        "CROSS-DOMAIN-ROUTE-HEALTH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Int(height as i128),
            HashPart::Int(risk_bps as i128),
        ],
        32,
    )
}

pub fn cross_domain_state_root_from_record(record: &Value) -> String {
    cross_domain_payload_root("CROSS-DOMAIN-STATE-ROOT", record)
}

pub fn cross_domain_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn cross_domain_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn cross_domain_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn cross_domain_amount_bucket(amount_units: u64) -> u64 {
    match amount_units {
        0..=999 => 1_000,
        1_000..=9_999 => 10_000,
        10_000..=99_999 => 100_000,
        100_000..=999_999 => 1_000_000,
        _ => 10_000_000,
    }
}

pub fn cross_domain_endpoint_root(values: &[CrossDomainEndpoint]) -> String {
    merkle_root(
        "CROSS-DOMAIN-ENDPOINT",
        &values
            .iter()
            .map(CrossDomainEndpoint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_route_root(values: &[CrossDomainRoute]) -> String {
    merkle_root(
        "CROSS-DOMAIN-ROUTE",
        &values
            .iter()
            .map(CrossDomainRoute::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_retry_policy_root(values: &[CrossDomainRetryPolicy]) -> String {
    merkle_root(
        "CROSS-DOMAIN-RETRY-POLICY",
        &values
            .iter()
            .map(CrossDomainRetryPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_fee_quote_root(values: &[CrossDomainFeeQuote]) -> String {
    merkle_root(
        "CROSS-DOMAIN-FEE-QUOTE",
        &values
            .iter()
            .map(CrossDomainFeeQuote::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_privacy_envelope_root(values: &[CrossDomainPrivacyEnvelope]) -> String {
    merkle_root(
        "CROSS-DOMAIN-PRIVACY-ENVELOPE",
        &values
            .iter()
            .map(CrossDomainPrivacyEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_message_root(values: &[CrossDomainMessage]) -> String {
    merkle_root(
        "CROSS-DOMAIN-MESSAGE",
        &values
            .iter()
            .map(CrossDomainMessage::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_proof_bundle_root(values: &[CrossDomainProofBundle]) -> String {
    merkle_root(
        "CROSS-DOMAIN-PROOF-BUNDLE",
        &values
            .iter()
            .map(CrossDomainProofBundle::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_packet_root(values: &[CrossDomainPacket]) -> String {
    merkle_root(
        "CROSS-DOMAIN-PACKET",
        &values
            .iter()
            .map(CrossDomainPacket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_replay_guard_root(values: &[CrossDomainReplayGuard]) -> String {
    merkle_root(
        "CROSS-DOMAIN-REPLAY-GUARD",
        &values
            .iter()
            .map(CrossDomainReplayGuard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_ack_root(values: &[CrossDomainAck]) -> String {
    merkle_root(
        "CROSS-DOMAIN-ACK",
        &values
            .iter()
            .map(CrossDomainAck::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_finality_witness_root(values: &[CrossDomainFinalityWitness]) -> String {
    merkle_root(
        "CROSS-DOMAIN-FINALITY-WITNESS",
        &values
            .iter()
            .map(CrossDomainFinalityWitness::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_liquidity_reservation_root(
    values: &[CrossDomainLiquidityReservation],
) -> String {
    merkle_root(
        "CROSS-DOMAIN-LIQUIDITY-RESERVATION",
        &values
            .iter()
            .map(CrossDomainLiquidityReservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_settlement_intent_root(values: &[CrossDomainSettlementIntent]) -> String {
    merkle_root(
        "CROSS-DOMAIN-SETTLEMENT-INTENT",
        &values
            .iter()
            .map(CrossDomainSettlementIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_settlement_receipt_root(values: &[CrossDomainSettlementReceipt]) -> String {
    merkle_root(
        "CROSS-DOMAIN-SETTLEMENT-RECEIPT",
        &values
            .iter()
            .map(CrossDomainSettlementReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn cross_domain_route_health_root(values: &[CrossDomainRouteHealth]) -> String {
    merkle_root(
        "CROSS-DOMAIN-ROUTE-HEALTH",
        &values
            .iter()
            .map(CrossDomainRouteHealth::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return CROSS_DOMAIN_MAX_BPS;
    }
    numerator
        .saturating_mul(CROSS_DOMAIN_MAX_BPS)
        .saturating_div(denominator)
        .min(CROSS_DOMAIN_MAX_BPS)
}

pub fn mul_bps(value: u64, bps: u64) -> u64 {
    value
        .saturating_mul(bps)
        .saturating_div(CROSS_DOMAIN_MAX_BPS)
}

fn json_size(value: &Value) -> u64 {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .unwrap_or(0)
}

fn normalize_label(value: String) -> String {
    value.trim().replace(' ', "-").to_ascii_lowercase()
}

fn ensure_non_empty(value: &str, field: &str) -> CrossDomainResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> CrossDomainResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, field: &str) -> CrossDomainResult<()> {
    if value > CROSS_DOMAIN_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}
